//! Binary packer for assembling packed executables.
//!
//! This module handles combining the stub executable, compressed assets,
//! manifest, and footer into a self-contained `.smolmachine` package.
//! See [`crate::format`] for the binary format specification.

use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::assets::{crc32_file_range, crc32_reader_range, AssetCollector};
use crate::format::{PackFooter, PackManifest, FOOTER_SIZE, SIDECAR_EXTENSION};
use crate::Result;

/// Maximum allowed manifest size (16 MiB) to prevent malicious/corrupt sidecars
/// from causing excessive memory allocation.
const MAX_MANIFEST_SIZE: u64 = 16 * 1024 * 1024;

fn artifact_parent(output: &Path) -> &Path {
    output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn prepare_artifact_parent(parent: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    let mut missing = Vec::new();
    #[cfg(unix)]
    {
        let mut directory = parent;
        while !directory.try_exists()? {
            missing.push(directory);
            directory = artifact_parent(directory);
        }
    }
    fs::create_dir_all(parent)?;
    #[cfg(unix)]
    for directory in missing {
        // Persist newly created ancestors too, not just the final file's name.
        File::open(directory)?.sync_all()?;
        File::open(artifact_parent(directory))?.sync_all()?;
    }
    Ok(())
}

fn publish_artifact(
    temporary: tempfile::TempPath,
    output: &Path,
    sync_parent: impl FnOnce(&Path) -> std::io::Result<()>,
) -> std::io::Result<()> {
    temporary
        .persist_noclobber(output)
        .map_err(|error| error.error)?;
    let parent = artifact_parent(output);
    // The contents were synced before publication. Persist the new directory
    // entry too; an error here must not be acknowledged as durable success.
    sync_parent(parent)
}

struct DigestWriter<W> {
    inner: W,
    sha256: Option<DigestWorker>,
    digest_error: Option<std::io::Error>,
}

struct DigestWorker {
    sender: Option<std::sync::mpsc::SyncSender<Vec<u8>>>,
    worker: Option<std::thread::JoinHandle<Sha256>>,
}

impl DigestWorker {
    fn spawn() -> std::io::Result<Self> {
        let (sender, receiver) = std::sync::mpsc::sync_channel::<Vec<u8>>(2);
        let worker = std::thread::Builder::new()
            .name("checkpoint-sha256".into())
            .spawn(move || {
                let mut digest = Sha256::new();
                for bytes in receiver {
                    digest.update(&bytes);
                }
                digest
            })?;
        Ok(Self {
            sender: Some(sender),
            worker: Some(worker),
        })
    }

    fn update(&self, bytes: &[u8]) -> std::io::Result<()> {
        // Two queued chunks, one producer chunk, and one consumer chunk bound
        // additional payload memory to 4 MiB, irrespective of artifact size.
        for chunk in bytes.chunks(1024 * 1024) {
            self.sender
                .as_ref()
                .expect("live digest sender")
                .send(chunk.to_vec())
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "checkpoint digest worker stopped",
                    )
                })?;
        }
        Ok(())
    }

    fn finish(mut self) -> std::io::Result<String> {
        drop(self.sender.take());
        let digest = self
            .worker
            .take()
            .expect("live digest worker")
            .join()
            .map_err(|_| std::io::Error::other("checkpoint digest worker failed"))?;
        Ok(format!("{:x}", digest.finalize()))
    }
}

impl Drop for DigestWorker {
    fn drop(&mut self) {
        drop(self.sender.take());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl<W: Write> Write for DigestWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if let Some(error) = &self.digest_error {
            return Err(std::io::Error::new(error.kind(), error.to_string()));
        }
        let written = self.inner.write(bytes)?;
        if let Some(digest) = &mut self.sha256 {
            // Once the file accepted bytes, report that progress accurately.
            // A digest failure poisons subsequent writes and flush/publication.
            if let Err(error) = digest.update(&bytes[..written]) {
                self.digest_error = Some(error);
            }
        }
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if let Some(error) = &self.digest_error {
            return Err(std::io::Error::new(error.kind(), error.to_string()));
        }
        self.inner.flush()
    }
}

/// A digest produced by this process while writing an artifact, never supplied
/// by an upload, a cache key, or an on-disk marker. The descriptor pins its inode.
pub struct PackedArtifactIdentity {
    file: File,
    digest: String,
    #[cfg(unix)]
    identity: PackedInode,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PackedInode {
    dev: u64,
    ino: u64,
    len: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

#[cfg(unix)]
impl PackedInode {
    fn of(file: &File) -> std::io::Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let meta = file.metadata()?;
        Ok(Self {
            dev: meta.dev(),
            ino: meta.ino(),
            len: meta.len(),
            modified: (meta.mtime(), meta.mtime_nsec()),
            changed: (meta.ctime(), meta.ctime_nsec()),
        })
    }
}

impl PackedArtifactIdentity {
    /// Conservative, request-local reuse: both the pinned descriptor and the
    /// current path must still name the exact bytes written by the packer.
    pub(crate) fn digest_for(&self, path: &Path) -> Option<&str> {
        #[cfg(unix)]
        {
            let current = File::open(path).ok()?;
            (PackedInode::of(&self.file).ok()? == self.identity
                && PackedInode::of(&current).ok()? == self.identity)
                .then_some(self.digest.as_str())
        }
        #[cfg(not(unix))]
        {
            let _ = (path, &self.file, &self.digest);
            None
        }
    }
}

struct ChecksummedWriter<W> {
    inner: W,
    hasher: crc32fast::Hasher,
    bytes: u64,
}

impl<W> ChecksummedWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: crc32fast::Hasher::new(),
            bytes: 0,
        }
    }
}

impl<W: Write> Write for ChecksummedWriter<W> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let count = self.inner.write(data)?;
        self.hasher.update(&data[..count]);
        self.bytes += count as u64;
        Ok(count)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Binary packer for creating self-contained executables.
pub struct Packer {
    stub_path: Option<std::path::PathBuf>,
    manifest: PackManifest,
    asset_collector: Option<AssetCollector>,
    direct_artifact_io: bool,
}

/// Error type for try_pack_embedded_macho (internal).
#[cfg(target_os = "macos")]
enum PackedEmbeddedError {
    /// Not a valid Mach-O with required section, return Packer to try append mode.
    NotMachO(Box<Packer>),
    /// Other pack error.
    PackError(crate::PackError),
}

impl Packer {
    /// Create a new packer with the given manifest.
    pub fn new(manifest: PackManifest) -> Self {
        Self {
            stub_path: None,
            manifest,
            asset_collector: None,
            direct_artifact_io: false,
        }
    }

    /// Prefer bounded direct writes for bulk artifacts on Linux; other hosts
    /// and unsupported filesystems retain buffered writes and final syncing.
    pub fn with_direct_artifact_io(mut self) -> Self {
        self.direct_artifact_io = true;
        self
    }

    /// Set the path to the stub executable.
    pub fn with_stub(mut self, stub_path: impl AsRef<Path>) -> Self {
        self.stub_path = Some(stub_path.as_ref().to_path_buf());
        self
    }

    /// Set the asset collector and update manifest with its inventory.
    pub fn with_assets(mut self, collector: AssetCollector) -> Self {
        // Update manifest with the collector's inventory
        self.manifest.assets = collector.inventory().clone();
        self.asset_collector = Some(collector);
        self
    }

    /// Set the asset collector without updating the manifest.
    ///
    /// Use this when the manifest already has the correct asset inventory
    /// (e.g., when it was set from a different collector that was consumed).
    pub fn with_asset_collector(mut self, collector: AssetCollector) -> Self {
        self.asset_collector = Some(collector);
        self
    }

    /// Get a mutable reference to the manifest.
    pub fn manifest_mut(&mut self) -> &mut PackManifest {
        &mut self.manifest
    }

    /// Pack everything into the output file using sidecar format.
    ///
    /// Creates two files:
    /// 1. `output` - Stub executable (pure Mach-O, signable)
    /// 2. `output.smolmachine` - Compressed assets + manifest + footer
    ///
    /// This keeps the binary as a pure Mach-O executable that can be
    /// properly code-signed on macOS.
    pub fn pack(self, output: impl AsRef<Path>) -> Result<PackedInfo> {
        let output = output.as_ref();
        let temp_dir = tempfile::tempdir()?;

        // Get stub executable
        let stub_path = self
            .stub_path
            .as_ref()
            .ok_or_else(|| crate::PackError::AssetNotFound("stub executable".to_string()))?;

        // 1. Copy stub executable to output (libs are appended later, after signing)
        let stub_data = fs::read(stub_path)?;
        let stub_size = stub_data.len() as u64;
        fs::write(output, &stub_data)?;

        // Make executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(output)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(output, perms)?;
        }

        // 3. Build sidecar file with: assets (no libs) + manifest + footer
        let sidecar_path = sidecar_path_for(output);
        let mut sidecar_file = File::create(&sidecar_path)?;

        // 3a. Write compressed assets (excludes lib/ — those are embedded in the stub)
        let assets_temp = temp_dir.path().join("assets.tar.zst");
        let assets_size = if let Some(collector) = &self.asset_collector {
            collector.compress(&assets_temp, true)?
        } else {
            let empty_file = File::create(&assets_temp)?;
            let encoder = zstd::stream::Encoder::new(empty_file, 1)?;
            let tar_builder = tar::Builder::new(encoder);
            let encoder = tar_builder.into_inner()?;
            encoder.finish()?;
            fs::metadata(&assets_temp)?.len()
        };

        let mut assets_file = File::open(&assets_temp)?;
        std::io::copy(&mut assets_file, &mut sidecar_file)?;

        // 3b. Write manifest JSON
        let manifest_offset = assets_size;
        let manifest_json = self.manifest.to_json()?;
        let manifest_size = manifest_json.len() as u64;
        sidecar_file.write_all(&manifest_json)?;

        // 3c. Calculate checksum of assets + manifest
        sidecar_file.flush()?;
        drop(sidecar_file);
        let checksum_size = assets_size + manifest_size;
        let checksum = crc32_file_range(&sidecar_path, 0, checksum_size)?;

        // 3d. Write footer to sidecar
        let footer = PackFooter {
            stub_size: 0,     // Not used in sidecar mode
            assets_offset: 0, // Assets start at beginning of sidecar
            assets_size,
            manifest_offset,
            manifest_size,
            checksum,
        };

        let mut sidecar_file = fs::OpenOptions::new().append(true).open(&sidecar_path)?;
        sidecar_file.write_all(&footer.to_bytes())?;

        let sidecar_total = assets_size + manifest_size + FOOTER_SIZE as u64;
        let total_size = stub_size + sidecar_total;

        Ok(PackedInfo {
            stub_size,
            assets_size,
            manifest_size,
            total_size,
            checksum,
            sidecar_path: Some(sidecar_path),
        })
    }

    /// Pack a standalone artifact containing assets, manifest, and footer.
    ///
    /// Unlike [`Self::pack`], this writes no launcher stub and includes runtime
    /// libraries in the compressed assets. It is used for portable checkpoints,
    /// which are consumed by an installed smolvm rather than executed directly.
    pub fn pack_artifact(self, output: impl AsRef<Path>) -> Result<PackedInfo> {
        self.pack_artifact_inner(output.as_ref(), false, None)
            .map(|(info, _)| info)
    }

    /// Compute the complete artifact digest, including its footer, as it is
    /// written. Other pack callers pay no SHA-256 cost.
    pub fn pack_artifact_with_identity(
        self,
        output: impl AsRef<Path>,
    ) -> Result<(PackedInfo, PackedArtifactIdentity)> {
        self.pack_artifact_inner(output.as_ref(), true, None)
            .map(|(info, identity)| (info, identity.expect("digest requested")))
    }

    /// Pack immutable streamed RAM alongside staged checkpoint assets.
    /// The runtime must confirm complete output before the artifact is published.
    /// This does not retain a separate mappable prepared-memory backing.
    pub fn pack_checkpoint_stream(
        self,
        output: impl AsRef<Path>,
        stream: &mut crate::checkpoint_stream::CheckpointStream<'_>,
    ) -> Result<PackedInfo> {
        if self.asset_collector.is_none() {
            return Err(crate::PackError::AssetNotFound(
                "streamed checkpoint staging".into(),
            ));
        }
        self.pack_artifact_inner(output.as_ref(), false, Some(stream))
            .map(|(info, _)| info)
    }

    fn pack_artifact_inner(
        self,
        output: &Path,
        compute_digest: bool,
        stream: Option<&mut crate::checkpoint_stream::CheckpointStream<'_>>,
    ) -> Result<(PackedInfo, Option<PackedArtifactIdentity>)> {
        let parent = artifact_parent(output);
        prepare_artifact_parent(parent)?;
        let temp = tempfile::NamedTempFile::new_in(parent)?;
        let temp_path = temp.into_temp_path();
        let artifact = ChecksummedWriter::new(DigestWriter {
            inner: crate::artifact_writer::ArtifactWriter::create(
                &temp_path,
                self.direct_artifact_io,
            )?,
            sha256: compute_digest.then(DigestWorker::spawn).transpose()?,
            digest_error: None,
        });
        let mut artifact = if let Some(collector) = &self.asset_collector {
            if let Some(stream) = stream {
                collector.compress_checkpoint_to(artifact, stream)?
            } else {
                collector.compress_to(artifact, false)?
            }
        } else {
            let encoder = zstd::stream::Encoder::new(artifact, 1)?;
            let tar_builder = tar::Builder::new(encoder);
            let encoder = tar_builder.into_inner()?;
            encoder.finish()?
        };
        let assets_size = artifact.bytes;
        let manifest_json = self.manifest.to_json()?;
        let manifest_offset = assets_size;
        let manifest_size = manifest_json.len() as u64;
        artifact.write_all(&manifest_json)?;
        artifact.flush()?;
        let checksum = artifact.hasher.finalize();
        let mut artifact = artifact.inner;
        let footer = PackFooter {
            stub_size: 0,
            assets_offset: 0,
            assets_size,
            manifest_offset,
            manifest_size,
            checksum,
        };
        artifact.write_all(&footer.to_bytes())?;
        artifact.flush()?;
        let file = artifact.inner.finish()?;
        file.sync_all()?;
        let digest = artifact.sha256.map(DigestWorker::finish).transpose()?;

        publish_artifact(temp_path, output, |parent| {
            #[cfg(unix)]
            File::open(parent)?.sync_all()?;
            #[cfg(not(unix))]
            let _ = parent;
            Ok(())
        })?;
        let identity = digest
            .map(|digest| {
                Ok::<_, std::io::Error>(PackedArtifactIdentity {
                    #[cfg(unix)]
                    identity: PackedInode::of(&file)?,
                    file,
                    digest,
                })
            })
            .transpose()?;
        Ok((
            PackedInfo {
                stub_size: 0,
                assets_size,
                manifest_size,
                total_size: assets_size + manifest_size + FOOTER_SIZE as u64,
                checksum,
                sidecar_path: Some(output.to_path_buf()),
            },
            identity,
        ))
    }

    /// Pack everything into a single executable file (embedded format).
    ///
    /// On macOS, this uses Mach-O section manipulation to embed assets inside
    /// the `__SMOLVM,__smolvm` section, allowing proper code signing.
    ///
    /// On other platforms, this appends assets to the binary (simpler but
    /// not signable on macOS).
    pub fn pack_embedded(self, output: impl AsRef<Path>) -> Result<PackedInfo> {
        #[cfg(target_os = "macos")]
        {
            // Try Mach-O section mode first
            match self.try_pack_embedded_macho(output.as_ref()) {
                Ok(info) => Ok(info),
                Err(PackedEmbeddedError::NotMachO(packer)) => {
                    // Not a valid Mach-O, fall back to append mode
                    packer.pack_embedded_append(output)
                }
                Err(PackedEmbeddedError::PackError(e)) => Err(e),
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            self.pack_embedded_append(output)
        }
    }

    /// Try to pack using Mach-O section manipulation.
    ///
    /// Returns NotMachO with self if the stub isn't a valid Mach-O with
    /// the required __smolvm section, allowing fallback to append mode.
    #[cfg(target_os = "macos")]
    fn try_pack_embedded_macho(
        self,
        output: &Path,
    ) -> std::result::Result<PackedInfo, PackedEmbeddedError> {
        use crate::macho::MachoFile;

        // Get stub path
        let stub_path = match self.stub_path.as_ref() {
            Some(p) => p,
            None => {
                return Err(PackedEmbeddedError::PackError(
                    crate::PackError::AssetNotFound("stub executable".to_string()),
                ))
            }
        };

        // Read stub data
        let stub_data = match fs::read(stub_path) {
            Ok(data) => data,
            Err(e) => return Err(PackedEmbeddedError::PackError(e.into())),
        };

        // Try to parse as Mach-O
        let macho = match MachoFile::parse(&stub_data) {
            Ok(m) => m,
            Err(_) => return Err(PackedEmbeddedError::NotMachO(Box::new(self))), // Not a Mach-O, fall back
        };

        // Check for __smolvm section
        if macho.find_section("__SMOLVM", "__smolvm").is_none() {
            return Err(PackedEmbeddedError::NotMachO(Box::new(self))); // No section, fall back
        }

        // Valid Mach-O with section, proceed with Mach-O packing
        match self.pack_embedded_macho_inner(output, stub_data, macho) {
            Ok(info) => Ok(info),
            Err(e) => Err(PackedEmbeddedError::PackError(e)),
        }
    }

    /// Pack using Mach-O section manipulation (macOS), inner implementation.
    ///
    /// This writes assets to the `__SMOLVM,__smolvm` section, keeping the
    /// binary as a valid Mach-O that can be properly code-signed.
    #[cfg(target_os = "macos")]
    fn pack_embedded_macho_inner(
        self,
        output: &Path,
        stub_data: Vec<u8>,
        mut macho: crate::macho::MachoFile,
    ) -> Result<PackedInfo> {
        use crate::format::{SectionHeader, SECTION_HEADER_SIZE};

        let stub_size = stub_data.len() as u64;
        let temp_dir = tempfile::tempdir()?;

        // Compress assets
        let assets_temp = temp_dir.path().join("assets.tar.zst");
        let assets_size = if let Some(collector) = &self.asset_collector {
            collector.compress(&assets_temp, false)? // include libs in single-file mode
        } else {
            let empty_file = File::create(&assets_temp)?;
            let encoder = zstd::stream::Encoder::new(empty_file, 1)?;
            let tar_builder = tar::Builder::new(encoder);
            let encoder = tar_builder.into_inner()?;
            encoder.finish()?;
            fs::metadata(&assets_temp)?.len()
        };

        // Serialize manifest
        let manifest_json = self.manifest.to_json()?;
        let manifest_size = manifest_json.len() as u32;

        // Calculate checksum of manifest + assets
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&manifest_json);
        let assets_data = fs::read(&assets_temp)?;
        hasher.update(&assets_data);
        let checksum = hasher.finalize();

        // Build section data: header + manifest + assets
        let header = SectionHeader {
            manifest_size,
            assets_size,
            checksum,
        };

        let mut section_data =
            Vec::with_capacity(SECTION_HEADER_SIZE + manifest_json.len() + assets_data.len());
        section_data.extend_from_slice(&header.to_bytes());
        section_data.extend_from_slice(&manifest_json);
        section_data.extend_from_slice(&assets_data);

        // Write section data to Mach-O
        macho
            .write_section("__SMOLVM", "__smolvm", &section_data)
            .map_err(|e| crate::PackError::Signing(format!("failed to write section: {}", e)))?;

        // Sign the binary with adhoc signature
        macho
            .sign_adhoc()
            .map_err(|e| crate::PackError::Signing(format!("failed to sign: {}", e)))?;

        // Write output
        let output_data = macho.write();
        let total_size = output_data.len() as u64;
        fs::write(output, &output_data)?;

        // Make executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(output)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(output, perms)?;
        }

        Ok(PackedInfo {
            stub_size,
            assets_size,
            manifest_size: manifest_size as u64,
            total_size,
            checksum,
            sidecar_path: None,
        })
    }

    /// Pack by appending assets to binary.
    ///
    /// This is the fallback method on macOS (when stub isn't a valid Mach-O)
    /// and the default method on other platforms.
    fn pack_embedded_append(self, output: impl AsRef<Path>) -> Result<PackedInfo> {
        let output = output.as_ref();
        let temp_dir = tempfile::tempdir()?;

        // Get stub executable
        let stub_path = self
            .stub_path
            .as_ref()
            .ok_or_else(|| crate::PackError::AssetNotFound("stub executable".to_string()))?;

        // 1. Copy stub executable to output
        let stub_data = fs::read(stub_path)?;
        let stub_size = stub_data.len() as u64;
        let mut output_file = File::create(output)?;
        output_file.write_all(&stub_data)?;

        // 2. Compress and append assets
        let assets_temp = temp_dir.path().join("assets.tar.zst");
        let assets_size = if let Some(collector) = &self.asset_collector {
            collector.compress(&assets_temp, false)? // include libs in append mode
        } else {
            let empty_file = File::create(&assets_temp)?;
            let encoder = zstd::stream::Encoder::new(empty_file, 1)?;
            let tar_builder = tar::Builder::new(encoder);
            let encoder = tar_builder.into_inner()?;
            encoder.finish()?;
            fs::metadata(&assets_temp)?.len()
        };

        let assets_offset = stub_size; // Assets start right after stub
        let mut assets_file = File::open(&assets_temp)?;
        std::io::copy(&mut assets_file, &mut output_file)?;

        // 3. Append manifest JSON
        let manifest_offset = stub_size + assets_size;
        let manifest_json = self.manifest.to_json()?;
        let manifest_size = manifest_json.len() as u64;
        output_file.write_all(&manifest_json)?;

        // 4. Calculate checksum of assets + manifest
        output_file.flush()?;
        drop(output_file);
        let checksum_size = assets_size + manifest_size;
        let checksum = crc32_file_range(output, assets_offset, checksum_size)?;

        // 5. Append footer
        let footer = PackFooter {
            stub_size,
            assets_offset, // Non-zero indicates embedded mode
            assets_size,
            manifest_offset,
            manifest_size,
            checksum,
        };

        let mut output_file = fs::OpenOptions::new().append(true).open(output)?;
        output_file.write_all(&footer.to_bytes())?;

        // Make executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(output)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(output, perms)?;
        }

        let total_size = stub_size + assets_size + manifest_size + FOOTER_SIZE as u64;

        Ok(PackedInfo {
            stub_size,
            assets_size,
            manifest_size,
            total_size,
            checksum,
            sidecar_path: None, // No sidecar in embedded mode
        })
    }
}

/// Append compressed runtime libraries to a packed binary.
///
/// Call this AFTER code signing — the SMOLLIBS footer must be the last
/// bytes of the file so `extract_libs_from_binary()` can find it.
pub fn embed_libs_in_binary(binary_path: &Path, staging_dir: &Path) -> Result<()> {
    use crate::format::LibsFooter;

    let lib_dir = staging_dir.join("lib");
    if !lib_dir.exists() {
        return Ok(()); // No libs to embed
    }

    // Check if there are actual library files
    let has_libs = fs::read_dir(&lib_dir)?
        .filter_map(|e| e.ok())
        .any(|e| e.path().is_file());
    if !has_libs {
        return Ok(());
    }

    let temp_dir = tempfile::tempdir()?;
    let libs_temp = temp_dir.path().join("libs.tar.zst");

    // Compress libs
    let output_file = File::create(&libs_temp)?;
    let encoder = zstd::stream::Encoder::new(output_file, crate::assets::ZSTD_LEVEL)
        .map_err(|e| crate::PackError::Compression(e.to_string()))?;
    let mut tar_builder = tar::Builder::new(encoder);
    tar_builder
        .append_dir_all("lib", &lib_dir)
        .map_err(|e| crate::PackError::Tar(e.to_string()))?;
    let encoder = tar_builder
        .into_inner()
        .map_err(|e| crate::PackError::Tar(e.to_string()))?;
    encoder
        .finish()
        .map_err(|e| crate::PackError::Compression(e.to_string()))?;

    let libs_size = fs::metadata(&libs_temp)?.len();
    let binary_size = fs::metadata(binary_path)?.len();

    // Append libs blob + footer
    let mut output_file = fs::OpenOptions::new().append(true).open(binary_path)?;
    let mut libs_file = File::open(&libs_temp)?;
    std::io::copy(&mut libs_file, &mut output_file)?;

    let libs_footer = LibsFooter {
        libs_offset: binary_size,
        libs_size,
    };
    output_file.write_all(&libs_footer.to_bytes())?;

    Ok(())
}

/// Get the sidecar path for a packed binary.
pub fn sidecar_path_for(binary_path: impl AsRef<Path>) -> PathBuf {
    let mut path = binary_path.as_ref().to_path_buf();
    let filename = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    path.set_file_name(format!("{}{}", filename, SIDECAR_EXTENSION));
    path
}

/// Information about a packed binary.
#[derive(Debug, Clone)]
pub struct PackedInfo {
    /// Size of stub executable.
    pub stub_size: u64,
    /// Size of compressed assets.
    pub assets_size: u64,
    /// Size of manifest JSON.
    pub manifest_size: u64,
    /// Total size (binary + sidecar).
    pub total_size: u64,
    /// CRC32 checksum of assets.
    pub checksum: u32,
    /// Path to sidecar file (if using sidecar mode).
    pub sidecar_path: Option<PathBuf>,
}

/// Read footer from a sidecar file.
///
/// Validates structural bounds: footer-derived sizes must be consistent with
/// the actual file size and within safe limits.
pub fn read_footer_from_sidecar(sidecar_path: impl AsRef<Path>) -> Result<PackFooter> {
    let mut file = File::open(sidecar_path.as_ref())?;
    read_footer_from_file(&mut file)
}

/// Read and bounds-check the footer of an already-open sidecar.
pub fn read_footer_from_file(file: &mut File) -> Result<PackFooter> {
    let file_size = file.metadata()?.len();

    if file_size < FOOTER_SIZE as u64 {
        return Err(crate::PackError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "sidecar file too small to contain footer",
        )));
    }

    file.seek(SeekFrom::End(-(FOOTER_SIZE as i64)))?;
    let mut footer_bytes = [0u8; FOOTER_SIZE];
    file.read_exact(&mut footer_bytes)?;

    let footer = PackFooter::from_bytes(&footer_bytes)?;

    // Validate footer-derived sizes against actual file size
    validate_footer_bounds(&footer, file_size)?;

    Ok(footer)
}

/// Read manifest from a sidecar file.
pub fn read_manifest_from_sidecar(sidecar_path: impl AsRef<Path>) -> Result<PackManifest> {
    let footer = read_footer_from_sidecar(sidecar_path.as_ref())?;

    let mut file = File::open(sidecar_path.as_ref())?;
    file.seek(SeekFrom::Start(footer.manifest_offset))?;

    let mut manifest_bytes = vec![0u8; footer.manifest_size as usize];
    file.read_exact(&mut manifest_bytes)?;

    PackManifest::from_json(&manifest_bytes)
}

/// Read footer from a packed binary (deprecated - use sidecar instead).
pub fn read_footer(path: impl AsRef<Path>) -> Result<PackFooter> {
    // Try sidecar first
    let sidecar = sidecar_path_for(path.as_ref());
    if sidecar.exists() {
        return read_footer_from_sidecar(&sidecar);
    }

    // Fall back to embedded (v1 format)
    let mut file = File::open(path.as_ref())?;
    let file_size = file.metadata()?.len();

    if file_size < FOOTER_SIZE as u64 {
        return Err(crate::PackError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file too small to contain footer",
        )));
    }

    file.seek(SeekFrom::End(-(FOOTER_SIZE as i64)))?;
    let mut footer_bytes = [0u8; FOOTER_SIZE];
    file.read_exact(&mut footer_bytes)?;

    PackFooter::from_bytes(&footer_bytes)
}

/// Read manifest from a packed binary (deprecated - use sidecar instead).
pub fn read_manifest(path: impl AsRef<Path>) -> Result<PackManifest> {
    // Try sidecar first
    let sidecar = sidecar_path_for(path.as_ref());
    if sidecar.exists() {
        return read_manifest_from_sidecar(&sidecar);
    }

    // Fall back to embedded (v1 format)
    let footer = read_footer(path.as_ref())?;

    let mut file = File::open(path.as_ref())?;
    file.seek(SeekFrom::Start(footer.manifest_offset))?;

    let mut manifest_bytes = vec![0u8; footer.manifest_size as usize];
    file.read_exact(&mut manifest_bytes)?;

    PackManifest::from_json(&manifest_bytes)
}

/// Check if a packed binary uses sidecar mode.
pub fn is_sidecar_mode(footer: &PackFooter) -> bool {
    footer.assets_offset == 0
}

/// Verify checksum of a packed binary.
pub fn verify_checksum(path: impl AsRef<Path>) -> Result<bool> {
    let footer = read_footer(path.as_ref())?;

    if is_sidecar_mode(&footer) {
        // Sidecar mode: checksum is of assets + manifest (not the footer)
        let sidecar = sidecar_path_for(path.as_ref());
        if !sidecar.exists() {
            return Ok(false);
        }
        let checksum_size = footer.assets_size + footer.manifest_size;
        let actual = crc32_file_range(&sidecar, 0, checksum_size)?;
        Ok(actual == footer.checksum)
    } else {
        // Embedded mode: checksum is of assets + manifest
        let checksum_size = footer.assets_size + footer.manifest_size;
        let actual = crc32_file_range(path.as_ref(), footer.assets_offset, checksum_size)?;
        Ok(actual == footer.checksum)
    }
}

/// Verify checksum of a sidecar file.
///
/// Computes CRC32 over the assets + manifest region and compares to the
/// checksum stored in the footer.
pub fn verify_sidecar_checksum(
    sidecar_path: impl AsRef<Path>,
    footer: &PackFooter,
) -> Result<bool> {
    let mut file = File::open(sidecar_path.as_ref())?;
    verify_sidecar_checksum_file(&mut file, footer)
}

/// [`verify_sidecar_checksum`] over an already-open sidecar descriptor.
pub fn verify_sidecar_checksum_file(file: &mut File, footer: &PackFooter) -> Result<bool> {
    let checksum_size = footer
        .assets_size
        .checked_add(footer.manifest_size)
        .ok_or_else(|| {
            crate::PackError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "assets_size + manifest_size overflow",
            ))
        })?;
    let actual = crc32_reader_range(file, 0, checksum_size)?;
    Ok(actual == footer.checksum)
}

/// Validate that footer-derived sizes are consistent with the actual file size.
fn validate_footer_bounds(footer: &PackFooter, file_size: u64) -> Result<()> {
    // Cap manifest size to prevent excessive memory allocation
    if footer.manifest_size > MAX_MANIFEST_SIZE {
        return Err(crate::PackError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "manifest size ({} bytes) exceeds maximum ({} bytes)",
                footer.manifest_size, MAX_MANIFEST_SIZE
            ),
        )));
    }

    // Verify that assets + manifest + footer fit within the file
    let content_end = footer
        .assets_size
        .checked_add(footer.manifest_size)
        .and_then(|s| s.checked_add(FOOTER_SIZE as u64));

    match content_end {
        Some(end) if end <= file_size => {}
        _ => {
            return Err(crate::PackError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "footer sizes exceed file size (corrupt or truncated sidecar)",
            )));
        }
    }

    // In sidecar mode (assets_offset == 0), the layout is:
    //   [assets_blob | manifest_json | footer]
    // so manifest_offset MUST equal assets_size.  If it doesn't, the
    // manifest bytes that read_manifest_from_sidecar parses could differ
    // from the region covered by the checksum (0..assets_size+manifest_size),
    // creating a trust gap between verified and parsed data.
    if footer.assets_offset == 0 && footer.manifest_offset != footer.assets_size {
        return Err(crate::PackError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "sidecar manifest_offset ({}) does not match assets_size ({}): corrupt footer",
                footer.manifest_offset, footer.assets_size
            ),
        )));
    }

    // Verify manifest_offset + manifest_size doesn't exceed the pre-footer region
    let manifest_end = footer
        .manifest_offset
        .checked_add(footer.manifest_size)
        .and_then(|end| end.checked_add(FOOTER_SIZE as u64));

    match manifest_end {
        Some(end) if end <= file_size => {}
        _ => {
            return Err(crate::PackError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "manifest offset/size exceeds file bounds",
            )));
        }
    }

    Ok(())
}

/// Extract assets from a packed binary to a directory.
pub fn extract_assets(packed_path: impl AsRef<Path>, output_dir: impl AsRef<Path>) -> Result<()> {
    let footer = read_footer(packed_path.as_ref())?;

    if is_sidecar_mode(&footer) {
        // Sidecar mode: read from .smolmachine file
        let sidecar = sidecar_path_for(packed_path.as_ref());
        crate::assets::decompress_assets_from_file(&sidecar, output_dir.as_ref())?;
    } else {
        // Embedded mode: read from the binary itself
        let mut file = File::open(packed_path.as_ref())?;
        file.seek(SeekFrom::Start(footer.assets_offset))?;

        // Read compressed assets
        let mut compressed = vec![0u8; footer.assets_size as usize];
        file.read_exact(&mut compressed)?;

        // Decompress
        crate::assets::decompress_assets(&compressed, output_dir.as_ref())?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn artifact_parent_accepts_bare_names_and_creates_nested_directories() {
        assert_eq!(
            artifact_parent(Path::new("saved.smolcheckpoint")),
            Path::new(".")
        );
        let directory = tempfile::tempdir().unwrap();
        let nested = directory.path().join("new").join("checkpoints");
        prepare_artifact_parent(&nested).unwrap();
        assert!(nested.is_dir());
        prepare_artifact_parent(&nested).unwrap();
        let file = nested.join("file");
        fs::write(&file, b"not a directory").unwrap();
        assert!(prepare_artifact_parent(&file.join("child")).is_err());
    }

    #[test]
    fn artifact_publication_syncs_the_published_name() {
        let directory = tempfile::tempdir().unwrap();
        let mut temporary = tempfile::NamedTempFile::new_in(directory.path()).unwrap();
        temporary.write_all(b"checkpoint").unwrap();
        temporary.as_file().sync_all().unwrap();
        let output = directory.path().join("saved.smolcheckpoint");
        let mut synced = false;
        publish_artifact(temporary.into_temp_path(), &output, |parent| {
            assert_eq!(parent, directory.path());
            assert_eq!(fs::read(&output)?, b"checkpoint");
            #[cfg(unix)]
            File::open(parent)?.sync_all()?;
            synced = true;
            Ok(())
        })
        .unwrap();
        assert!(synced);
    }

    #[test]
    fn artifact_publication_does_not_hide_directory_sync_failure() {
        let directory = tempfile::tempdir().unwrap();
        let temporary = tempfile::NamedTempFile::new_in(directory.path()).unwrap();
        let output = directory.path().join("saved.smolcheckpoint");
        let error = publish_artifact(temporary.into_temp_path(), &output, |_| {
            Err(std::io::Error::other("directory sync failed"))
        })
        .unwrap_err();
        assert_eq!(error.to_string(), "directory sync failed");
        // Published bytes may be recoverable, but durability was not promised.
        assert!(output.is_file());
    }

    #[test]
    fn artifact_publication_never_overwrites_an_existing_checkpoint() {
        let directory = tempfile::tempdir().unwrap();
        let temporary = tempfile::NamedTempFile::new_in(directory.path()).unwrap();
        let output = directory.path().join("saved.smolcheckpoint");
        fs::write(&output, b"original").unwrap();
        assert!(publish_artifact(temporary.into_temp_path(), &output, |_| {
            panic!("failed publication must not reach the directory sync")
        })
        .is_err());
        assert_eq!(fs::read(&output).unwrap(), b"original");
    }

    #[test]
    fn test_pack_and_read() {
        let temp_dir = tempfile::tempdir().unwrap();

        // Create a dummy stub
        let stub_path = temp_dir.path().join("stub");
        let mut stub_file = File::create(&stub_path).unwrap();
        stub_file.write_all(b"#!/bin/sh\necho stub").unwrap();

        // Create manifest
        let manifest = PackManifest::new(
            "alpine:latest".to_string(),
            "sha256:abc123".to_string(),
            "linux/arm64".to_string(),
            "darwin/arm64".to_string(),
        );

        // Pack
        let output_path = temp_dir.path().join("packed");
        let packer = Packer::new(manifest).with_stub(&stub_path);
        let info = packer.pack(&output_path).unwrap();

        assert!(info.stub_size > 0);
        assert!(info.total_size > info.stub_size);

        // Verify sidecar file exists
        let sidecar = sidecar_path_for(&output_path);
        assert!(sidecar.exists());

        // Read back - sidecar mode has stub_size=0 in footer
        let footer = read_footer(&output_path).unwrap();
        assert_eq!(footer.stub_size, 0); // Sidecar mode doesn't track stub size in footer
        assert_eq!(footer.assets_offset, 0); // Sidecar mode indicator

        let manifest = read_manifest(&output_path).unwrap();
        assert_eq!(manifest.image, "alpine:latest");

        // Verify checksum
        assert!(verify_checksum(&output_path).unwrap());
    }

    #[test]
    fn test_pack_with_assets() {
        let temp_dir = tempfile::tempdir().unwrap();

        // Create a dummy stub
        let stub_path = temp_dir.path().join("stub");
        fs::write(&stub_path, b"#!/bin/sh\necho stub").unwrap();

        // Create staging directory with a test file
        let staging = temp_dir.path().join("staging");
        let mut collector = AssetCollector::new(staging).unwrap();

        // Add a fake layer
        collector
            .add_layer("sha256:abc123def456", b"layer content")
            .unwrap();

        // Create manifest
        let manifest = PackManifest::new(
            "test:latest".to_string(),
            "sha256:test".to_string(),
            "linux/arm64".to_string(),
            "darwin/arm64".to_string(),
        );

        // Pack with assets
        let output_path = temp_dir.path().join("packed");
        let packer = Packer::new(manifest)
            .with_stub(&stub_path)
            .with_assets(collector);
        packer.pack(&output_path).unwrap();

        // Verify we can read the manifest with layer info
        let manifest = read_manifest(&output_path).unwrap();
        assert_eq!(manifest.assets.layers.len(), 1);
        assert_eq!(manifest.assets.layers[0].digest, "sha256:abc123def456");

        // Extract and verify assets
        let extract_dir = temp_dir.path().join("extracted");
        extract_assets(&output_path, &extract_dir).unwrap();

        let layer_file = extract_dir.join("layers/abc123def456.tar");
        assert!(layer_file.exists());
        assert_eq!(fs::read_to_string(&layer_file).unwrap(), "layer content");
    }

    #[test]
    fn test_pack_embedded() {
        let temp_dir = tempfile::tempdir().unwrap();

        // Create a dummy stub
        let stub_path = temp_dir.path().join("stub");
        fs::write(&stub_path, b"#!/bin/sh\necho stub").unwrap();

        // Create manifest
        let manifest = PackManifest::new(
            "alpine:latest".to_string(),
            "sha256:abc123".to_string(),
            "linux/arm64".to_string(),
            "darwin/arm64".to_string(),
        );

        // Pack embedded (single file)
        let output_path = temp_dir.path().join("packed-single");
        let packer = Packer::new(manifest).with_stub(&stub_path);
        let info = packer.pack_embedded(&output_path).unwrap();

        // Should have no sidecar
        assert!(info.sidecar_path.is_none());
        assert!(info.stub_size > 0);
        assert!(info.total_size > info.stub_size);

        // Sidecar file should NOT exist
        let sidecar = sidecar_path_for(&output_path);
        assert!(!sidecar.exists());

        // Output file should contain everything
        let output_size = fs::metadata(&output_path).unwrap().len();
        assert_eq!(output_size, info.total_size);

        // Read back - embedded mode has non-zero assets_offset
        let footer = read_footer(&output_path).unwrap();
        assert!(footer.assets_offset > 0); // Embedded mode indicator
        assert_eq!(footer.stub_size, info.stub_size);

        let manifest = read_manifest(&output_path).unwrap();
        assert_eq!(manifest.image, "alpine:latest");

        // Verify checksum
        assert!(verify_checksum(&output_path).unwrap());
    }

    #[test]
    fn test_pack_embedded_with_assets() {
        let temp_dir = tempfile::tempdir().unwrap();

        // Create a dummy stub
        let stub_path = temp_dir.path().join("stub");
        fs::write(&stub_path, b"#!/bin/sh\necho stub").unwrap();

        // Create staging directory with a test file
        let staging = temp_dir.path().join("staging");
        let mut collector = AssetCollector::new(staging).unwrap();

        // Add a fake layer. The digest must be at least 12 characters after
        // `sha256:` and valid hex — it is used as a filesystem path, so
        // `add_layer` rejects anything else (see 680ba8d9).
        collector
            .add_layer("sha256:abcdef123456", b"embedded layer content")
            .unwrap();

        // Create manifest
        let manifest = PackManifest::new(
            "test:embedded".to_string(),
            "sha256:test".to_string(),
            "linux/arm64".to_string(),
            "darwin/arm64".to_string(),
        );

        // Pack embedded with assets
        let output_path = temp_dir.path().join("packed-embedded");
        let packer = Packer::new(manifest)
            .with_stub(&stub_path)
            .with_assets(collector);
        packer.pack_embedded(&output_path).unwrap();

        // Verify we can read the manifest with layer info
        let manifest = read_manifest(&output_path).unwrap();
        assert_eq!(manifest.assets.layers.len(), 1);
        assert_eq!(manifest.assets.layers[0].digest, "sha256:abcdef123456");

        // Verify footer indicates embedded mode
        let footer = read_footer(&output_path).unwrap();
        assert!(footer.assets_offset > 0);
        assert!(!is_sidecar_mode(&footer));

        // Extract and verify assets
        let extract_dir = temp_dir.path().join("extracted");
        extract_assets(&output_path, &extract_dir).unwrap();

        let layer_file = extract_dir.join("layers/abcdef123456.tar"); // First 12 chars
        assert!(layer_file.exists());
        assert_eq!(
            fs::read_to_string(&layer_file).unwrap(),
            "embedded layer content"
        );
    }

    #[test]
    fn test_pack_standalone_artifact_roundtrip_and_no_clobber() {
        let temp_dir = tempfile::tempdir().unwrap();
        let staging = temp_dir.path().join("staging");
        let collector = AssetCollector::new(staging.clone()).unwrap();
        fs::create_dir(staging.join("checkpoint")).unwrap();
        fs::write(staging.join("checkpoint/memory.bin"), b"guest memory").unwrap();

        let manifest = PackManifest::new(
            "vm://saved".to_string(),
            "none".to_string(),
            "linux/amd64".to_string(),
            "linux/amd64".to_string(),
        );
        let output = temp_dir.path().join("saved.smolcheckpoint");
        let info = Packer::new(manifest)
            .with_asset_collector(collector)
            .pack_artifact(&output)
            .unwrap();
        assert_eq!(info.stub_size, 0);
        assert_eq!(info.sidecar_path.as_deref(), Some(output.as_path()));
        let footer = read_footer_from_sidecar(&output).unwrap();
        assert!(verify_sidecar_checksum(&output, &footer).unwrap());
        assert_eq!(
            read_manifest_from_sidecar(&output).unwrap().image,
            "vm://saved"
        );

        let extracted = temp_dir.path().join("extracted");
        crate::extract::extract_sidecar(&output, &extracted, &footer, false, false).unwrap();
        assert_eq!(
            fs::read(extracted.join("checkpoint/memory.bin")).unwrap(),
            b"guest memory"
        );

        let second = AssetCollector::new(temp_dir.path().join("second")).unwrap();
        let manifest = PackManifest::new(
            "vm://replacement".to_string(),
            "none".to_string(),
            "linux/amd64".to_string(),
            "linux/amd64".to_string(),
        );
        assert!(Packer::new(manifest)
            .with_asset_collector(second)
            .pack_artifact(&output)
            .is_err());
        assert_eq!(
            read_manifest_from_sidecar(&output).unwrap().image,
            "vm://saved"
        );
    }

    #[test]
    fn checksummed_writer_tracks_only_successful_short_writes() {
        struct ShortWriter(Vec<u8>);
        impl Write for ShortWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if self.0.len() == 6 {
                    return Err(std::io::Error::other("injected write failure"));
                }
                let count = bytes.len().min(3);
                self.0.extend_from_slice(&bytes[..count]);
                Ok(count)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut writer = ChecksummedWriter::new(ShortWriter(Vec::new()));
        assert!(writer.write_all(b"123456789").is_err());
        assert_eq!(writer.bytes, 6);
        assert_eq!(writer.hasher.finalize(), crc32fast::hash(b"123456"));
        assert_eq!(writer.inner.0, b"123456");

        let mut writer = DigestWriter {
            inner: ShortWriter(Vec::new()),
            sha256: Some(DigestWorker::spawn().unwrap()),
            digest_error: None,
        };
        assert!(writer.write_all(b"123456789").is_err());
        assert_eq!(writer.inner.0, b"123456");
        assert_eq!(
            writer.sha256.take().unwrap().finish().unwrap(),
            format!("{:x}", Sha256::digest(b"123456"))
        );
    }

    #[test]
    fn failed_digest_worker_cannot_publish_a_digest() {
        let (sender, receiver) = std::sync::mpsc::sync_channel(2);
        drop(receiver);
        let worker = std::thread::spawn(|| -> Sha256 { panic!("test digest worker failure") });
        let digest = DigestWorker {
            sender: Some(sender),
            worker: Some(worker),
        };
        assert!(digest.update(b"bytes").is_err());
        assert!(digest.finish().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn direct_artifact_keeps_exact_footer_checksum_and_digest() {
        let temp = tempfile::tempdir().unwrap();
        let output = temp.path().join("direct.smolcheckpoint");
        let manifest = PackManifest::new(
            "vm://saved".into(),
            "none".into(),
            "linux/amd64".into(),
            "linux/amd64".into(),
        );
        let (info, identity) = Packer::new(manifest)
            .with_direct_artifact_io()
            .pack_artifact_with_identity(&output)
            .unwrap();
        let bytes = fs::read(&output).unwrap();
        assert_eq!(info.total_size, bytes.len() as u64);
        let expected = format!("{:x}", Sha256::digest(&bytes));
        assert_eq!(identity.digest_for(&output), Some(expected.as_str()));
        assert!(
            verify_sidecar_checksum(&output, &read_footer_from_sidecar(&output).unwrap()).unwrap()
        );
    }

    #[cfg(unix)]
    #[test]
    fn packed_identity_covers_footer_and_rejects_changed_inputs() {
        let temp = tempfile::tempdir().unwrap();
        let output = temp.path().join("local.smolcheckpoint");
        let manifest = PackManifest::new(
            "vm://saved".into(),
            "none".into(),
            "linux/amd64".into(),
            "linux/amd64".into(),
        );
        let (info, identity) = Packer::new(manifest)
            .pack_artifact_with_identity(&output)
            .unwrap();
        let bytes = fs::read(&output).unwrap();
        let expected = format!("{:x}", Sha256::digest(&bytes));
        assert_eq!(identity.digest_for(&output), Some(expected.as_str()));
        assert_eq!(info.total_size, bytes.len() as u64);
        assert!(
            verify_sidecar_checksum(&output, &read_footer_from_sidecar(&output).unwrap()).unwrap()
        );
        // A downloaded/copied file has no local provenance, even when equal.
        let copy = temp.path().join("download.smolcheckpoint");
        fs::write(&copy, &bytes).unwrap();
        assert!(identity.digest_for(&copy).is_none());
        // A replacement at the original name cannot inherit its proof.
        fs::rename(&copy, &output).unwrap();
        assert!(identity.digest_for(&output).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn packed_identity_rejects_same_length_mutation_with_restored_mtime() {
        let temp = tempfile::tempdir().unwrap();
        let output = temp.path().join("local.smolcheckpoint");
        let manifest = PackManifest::new(
            "vm://saved".into(),
            "none".into(),
            "linux/amd64".into(),
            "linux/amd64".into(),
        );
        let (_, identity) = Packer::new(manifest)
            .pack_artifact_with_identity(&output)
            .unwrap();
        let modified = fs::metadata(&output).unwrap().modified().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let mut bytes = fs::read(&output).unwrap();
        bytes[0] ^= 1;
        fs::write(&output, bytes).unwrap();
        File::options()
            .write(true)
            .open(&output)
            .unwrap()
            .set_modified(modified)
            .unwrap();
        assert!(identity.digest_for(&output).is_none());
    }

    #[test]
    fn standalone_artifact_without_assets_roundtrips() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("empty.smolcheckpoint");
        let manifest = PackManifest::new(
            "vm://empty".into(),
            "none".into(),
            "linux/amd64".into(),
            "linux/amd64".into(),
        );
        let info = Packer::new(manifest).pack_artifact(&output).unwrap();
        let footer = read_footer_from_sidecar(&output).unwrap();
        assert_eq!(info.total_size, fs::metadata(&output).unwrap().len());
        assert!(verify_sidecar_checksum(&output, &footer).unwrap());
        crate::extract::extract_sidecar(
            &output,
            &directory.path().join("out"),
            &footer,
            false,
            false,
        )
        .unwrap();
    }

    #[test]
    fn test_sidecar_checksum_verification() {
        let temp_dir = tempfile::tempdir().unwrap();

        // Create a dummy stub
        let stub_path = temp_dir.path().join("stub");
        fs::write(&stub_path, b"#!/bin/sh\necho stub").unwrap();

        let manifest = PackManifest::new(
            "alpine:latest".to_string(),
            "sha256:abc123".to_string(),
            "linux/arm64".to_string(),
            "darwin/arm64".to_string(),
        );

        // Pack sidecar mode
        let output_path = temp_dir.path().join("packed");
        let packer = Packer::new(manifest).with_stub(&stub_path);
        packer.pack(&output_path).unwrap();

        let sidecar = sidecar_path_for(&output_path);
        let footer = read_footer_from_sidecar(&sidecar).unwrap();

        // Valid sidecar should pass
        assert!(verify_sidecar_checksum(&sidecar, &footer).unwrap());

        // Corrupt the sidecar by flipping a byte in the assets region
        let mut data = fs::read(&sidecar).unwrap();
        if !data.is_empty() {
            data[0] ^= 0xFF;
        }
        fs::write(&sidecar, &data).unwrap();

        // Corrupted sidecar should fail checksum
        assert!(!verify_sidecar_checksum(&sidecar, &footer).unwrap());
    }

    #[test]
    fn test_footer_bounds_reject_oversized_manifest() {
        let temp_dir = tempfile::tempdir().unwrap();
        let sidecar = temp_dir.path().join("bad.smolmachine");

        // Craft a footer with manifest_size exceeding the 16 MiB cap
        let footer = PackFooter {
            stub_size: 0,
            assets_offset: 0,
            assets_size: 100,
            manifest_offset: 100,
            manifest_size: 32 * 1024 * 1024, // 32 MiB — exceeds cap
            checksum: 0,
        };

        // Write a minimal sidecar: some bytes + footer
        let footer_bytes = footer.to_bytes();
        let mut data = vec![0u8; 200]; // some dummy content
        data.extend_from_slice(&footer_bytes);
        fs::write(&sidecar, &data).unwrap();

        let result = read_footer_from_sidecar(&sidecar);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("exceeds maximum"), "got: {}", err_msg);
    }

    #[test]
    fn test_footer_bounds_reject_manifest_offset_mismatch() {
        let temp_dir = tempfile::tempdir().unwrap();
        let sidecar = temp_dir.path().join("mismatch.smolmachine");

        // In sidecar mode (assets_offset=0), manifest_offset must == assets_size.
        // Craft a footer where manifest_offset points elsewhere.
        let footer = PackFooter {
            stub_size: 0,
            assets_offset: 0, // sidecar mode
            assets_size: 100,
            manifest_offset: 50, // should be 100 — points into assets region
            manifest_size: 50,
            checksum: 0,
        };

        let footer_bytes = footer.to_bytes();
        // File needs: 100 (assets) + 50 (manifest) + 64 (footer) = 214 bytes
        let mut data = vec![0u8; 150];
        data.extend_from_slice(&footer_bytes);
        fs::write(&sidecar, &data).unwrap();

        let result = read_footer_from_sidecar(&sidecar);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("manifest_offset") && err_msg.contains("does not match"),
            "got: {}",
            err_msg
        );
    }

    #[test]
    fn test_sidecar_vs_embedded_mode_detection() {
        let temp_dir = tempfile::tempdir().unwrap();

        // Create a dummy stub
        let stub_path = temp_dir.path().join("stub");
        fs::write(&stub_path, b"#!/bin/sh\necho stub").unwrap();

        let manifest = PackManifest::new(
            "test:latest".to_string(),
            "sha256:test".to_string(),
            "linux/arm64".to_string(),
            "darwin/arm64".to_string(),
        );

        // Pack sidecar mode
        let sidecar_output = temp_dir.path().join("sidecar-mode");
        let packer = Packer::new(manifest.clone()).with_stub(&stub_path);
        packer.pack(&sidecar_output).unwrap();

        // Pack embedded mode
        let embedded_output = temp_dir.path().join("embedded-mode");
        let packer = Packer::new(manifest).with_stub(&stub_path);
        packer.pack_embedded(&embedded_output).unwrap();

        // Verify mode detection
        let sidecar_footer = read_footer(&sidecar_output).unwrap();
        let embedded_footer = read_footer(&embedded_output).unwrap();

        assert!(is_sidecar_mode(&sidecar_footer));
        assert!(!is_sidecar_mode(&embedded_footer));

        // Both should have valid checksums
        assert!(verify_checksum(&sidecar_output).unwrap());
        assert!(verify_checksum(&embedded_output).unwrap());
    }
}
