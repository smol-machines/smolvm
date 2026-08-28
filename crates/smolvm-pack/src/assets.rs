//! Asset collection and compression for packed binaries.
//!
//! This module handles discovering and packaging runtime assets:
//! - Runtime libraries (libkrun, libkrunfw)
//! - Agent rootfs
//! - OCI image layers

use std::fs::{self, File};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::format::{AssetEntry, AssetInventory, LayerEntry};
use crate::{PackError, Result};

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug)]
struct SparseExtent {
    offset: u64,
    len: u64,
}

/// Return the allocated byte ranges of an APFS sparse file.
///
/// The `tar` crate intentionally disables its `SEEK_DATA`/`SEEK_HOLE` path on
/// macOS, so its otherwise sparse-aware builder expands holes into a dense tar
/// stream. Checkpoint RAM and disk images can be tens of GiB logically while
/// containing only a few MiB of allocated pages; preserve those extents using
/// the GNU sparse-tar representation that the same crate already restores.
#[cfg(target_os = "macos")]
fn macos_sparse_extents(file: &mut File) -> std::io::Result<Option<Vec<SparseExtent>>> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;

    let metadata = file.metadata()?;
    let logical_len = metadata.len();
    if logical_len == 0 || metadata.blocks().saturating_mul(512) >= logical_len {
        return Ok(None);
    }

    let mut extents = Vec::new();
    let mut offset = 0_u64;
    while offset < logical_len {
        let seek_offset = i64::try_from(offset).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "sparse file offset exceeds the host off_t range",
            )
        })?;
        let data_offset = unsafe { libc::lseek(file.as_raw_fd(), seek_offset, libc::SEEK_DATA) };
        if data_offset < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENXIO) {
                break;
            }
            // A filesystem without sparse-seek support is still valid; let the
            // ordinary tar path copy it densely rather than failing a pack.
            if error.raw_os_error() == Some(libc::EINVAL) {
                file.seek(SeekFrom::Start(0))?;
                return Ok(None);
            }
            return Err(error);
        }
        let data = data_offset as u64;
        if data >= logical_len {
            break;
        }

        let hole = unsafe { libc::lseek(file.as_raw_fd(), data_offset, libc::SEEK_HOLE) };
        if hole < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let hole = (hole as u64).min(logical_len);
        if hole <= data {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "sparse extent did not advance",
            ));
        }
        extents.push(SparseExtent {
            offset: data,
            len: hole - data,
        });
        offset = hole;
    }
    file.seek(SeekFrom::Start(0))?;

    let allocated = extents.iter().map(|extent| extent.len).sum::<u64>();
    if allocated >= logical_len {
        return Ok(None);
    }
    // A zero-length final entry carries a trailing hole's logical endpoint in
    // old-GNU sparse tar. Without it extraction would truncate the file at the
    // end of the final allocated extent.
    if extents
        .last()
        .is_none_or(|extent| extent.offset + extent.len < logical_len)
    {
        extents.push(SparseExtent {
            offset: logical_len,
            len: 0,
        });
    }
    Ok(Some(extents))
}

#[cfg(target_os = "macos")]
fn append_macos_sparse_file<W: Write>(
    builder: &mut tar::Builder<W>,
    source: &Path,
    archive_path: &Path,
) -> std::io::Result<bool> {
    let mut file = File::open(source)?;
    let metadata = file.metadata()?;
    let Some(extents) = macos_sparse_extents(&mut file)? else {
        return Ok(false);
    };
    let stored_len = extents.iter().try_fold(0_u64, |total, extent| {
        total.checked_add(extent.len).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "sparse archive payload is too large",
            )
        })
    })?;

    let mut header = tar::Header::new_gnu();
    // Old-GNU sparse headers have a short path field. Let the ordinary tar
    // builder emit its long-name extension rather than making an unrelated
    // sparse asset with a long path un-packable.
    if header.set_path(archive_path).is_err() {
        return Ok(false);
    }
    header.set_metadata(&metadata);
    header.set_entry_type(tar::EntryType::GNUSparse);
    header.set_size(stored_len);
    let first_header_entries = {
        let gnu = header.as_gnu_mut().expect("new GNU header");
        gnu.set_real_size(metadata.len());
        let slots_len = gnu.sparse.len();
        for (extent, slot) in extents.iter().zip(gnu.sparse.iter_mut()) {
            slot.set_offset(extent.offset);
            slot.set_length(extent.len);
        }
        gnu.set_is_extended(extents.len() > slots_len);
        slots_len
    };
    header.set_cksum();
    builder.get_mut().write_all(header.as_bytes())?;

    let remaining = &extents[first_header_entries.min(extents.len())..];
    for (index, chunk) in remaining.chunks(21).enumerate() {
        let mut extended = tar::GnuExtSparseHeader::new();
        for (extent, slot) in chunk.iter().zip(extended.sparse_mut().iter_mut()) {
            slot.set_offset(extent.offset);
            slot.set_length(extent.len);
        }
        extended.set_is_extended((index + 1) * 21 < remaining.len());
        builder.get_mut().write_all(extended.as_bytes())?;
    }

    for extent in &extents {
        if extent.len == 0 {
            continue;
        }
        file.seek(SeekFrom::Start(extent.offset))?;
        let copied = std::io::copy(&mut (&file).take(extent.len), builder.get_mut())?;
        if copied != extent.len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "sparse file changed while it was archived",
            ));
        }
    }
    let padding = (512 - stored_len % 512) % 512;
    if padding != 0 {
        builder
            .get_mut()
            .write_all(&[0_u8; 512][..padding as usize])?;
    }
    Ok(true)
}

#[cfg(target_os = "macos")]
fn append_macos_tree<W: Write>(
    builder: &mut tar::Builder<W>,
    source: &Path,
    archive_path: &Path,
) -> Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    if metadata.is_dir() {
        builder
            .append_dir(archive_path, source)
            .map_err(|error| PackError::Tar(error.to_string()))?;
        let mut entries = fs::read_dir(source)?.collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            append_macos_tree(
                builder,
                &entry.path(),
                &archive_path.join(entry.file_name()),
            )?;
        }
    } else if metadata.is_file() && append_macos_sparse_file(builder, source, archive_path)? {
        // The sparse entry was written directly above.
    } else {
        builder
            .append_path_with_name(source, archive_path)
            .map_err(|error| PackError::Tar(error.to_string()))?;
    }
    Ok(())
}

/// Convert a digest string to a filename for layer tars.
///
/// Strips an optional `sha256:` prefix and uses the full remaining digest hex.
/// Returns an error if the digest portion is shorter than 12 characters.
fn digest_to_filename(digest: &str) -> Result<String> {
    let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
    if hex.len() < 12 {
        return Err(PackError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "digest too short for filename: '{}' ({} chars, need 12)",
                digest,
                hex.len()
            ),
        )));
    }
    // The filename becomes `layers/{hex}.tar` joined onto the staging dir, so
    // the digest MUST be pure hex — otherwise a malicious `.smolmachine` with a
    // digest like `sha256:../../evil` would write the layer bytes outside the
    // staging root (path traversal). A real content digest is always hex.
    if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(PackError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("digest is not valid hex: '{}'", digest),
        )));
    }
    Ok(format!("{}.tar", hex))
}

/// Compression level for zstd (3 = zstd default, fast with good ratio).
/// Level 19 was ~100x slower for only ~10% better compression.
pub const ZSTD_LEVEL: i32 = 3;

/// Find a pre-formatted disk template by filename.
///
/// Searches in order:
/// 1. `~/.smolvm/{filename}` (installed location)
/// 2. Next to the current executable (development)
///
/// Each location is checked for the plain file first and then for a `.zst`
/// sibling, which is expanded on demand by [`materialize_template`]. Releases
/// ship only the compressed form; the plain file is still honored so existing
/// installs and development trees keep working untouched.
pub fn find_existing_template(filename: &str) -> Option<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    if let Some(home) = dirs::home_dir() {
        roots.push(home.join(".smolvm"));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            roots.push(dir.to_path_buf());
        }
    }

    for root in &roots {
        let plain = root.join(filename);
        if plain.exists() {
            return Some(plain);
        }
    }
    for root in &roots {
        let compressed = root.join(format!("{filename}.zst"));
        if compressed.exists() {
            match expand_template(&compressed, filename) {
                Ok(path) => return Some(path),
                Err(e) => {
                    // Falling through would report the template as simply
                    // missing, which hides the real cause (usually no space or
                    // no writable location).
                    eprintln!("warning: could not expand {}: {e}", compressed.display());
                }
            }
        }
    }
    None
}

/// Expand `compressed` into a sparse file and return the expanded path.
///
/// Written next to the archive when that directory is writable, otherwise into
/// the user cache — the read-only case is the normal one for Nix and any other
/// immutable store. The result is reused on later runs: the plain-file lookup
/// above finds it first, so expansion happens once per install.
fn expand_template(compressed: &Path, filename: &str) -> std::io::Result<PathBuf> {
    let beside = compressed.parent().map(|d| d.join(filename));
    let cached = dirs::cache_dir().map(|c| c.join("smolvm").join(filename));

    let mut last_err = None;
    for dest in [beside, cached].into_iter().flatten() {
        if dest.exists() {
            return Ok(dest);
        }
        if let Some(parent) = dest.parent() {
            if fs::create_dir_all(parent).is_err() {
                continue;
            }
        }
        match materialize_template(compressed, &dest) {
            Ok(()) => return Ok(dest),
            Err(e) => {
                // A partial file would be mistaken for a good template by the
                // plain-file lookup, so remove it before trying the next root.
                let _ = fs::remove_file(&dest);
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        std::io::Error::other("no writable location to expand the disk template")
    }))
}

/// Decompress `src` into `dest`, writing only the non-zero regions.
///
/// The template is ~20 GiB logical and a few MiB of real data. Expanding it
/// with a plain copy would write every zero, so the zero runs are skipped and
/// left as holes — the same shape the file has when built. Decompression goes
/// to a temporary file that is renamed into place only on success, so a crash
/// or a full disk cannot leave a truncated template behind for the next run to
/// treat as valid.
fn materialize_template(src: &Path, dest: &Path) -> std::io::Result<()> {
    let tmp = dest.with_extension("partial");
    let _ = fs::remove_file(&tmp);
    let result = decompress_sparse(src, &tmp);
    if result.is_ok() {
        if let Err(e) = fs::rename(&tmp, dest) {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
        return Ok(());
    }
    // Leave nothing behind on failure: a stray scratch file wastes space, and a
    // renamed partial would be picked up as a valid template by the next run.
    let _ = fs::remove_file(&tmp);
    result
}

/// Stream `src` into `dest`, skipping the zero runs so they stay holes.
fn decompress_sparse(src: &Path, dest: &Path) -> std::io::Result<()> {
    use std::io::Read as _;

    let file = File::create(dest)?;
    // On Windows/NTFS, File::create makes a non-sparse file: seeking past the
    // zero runs and set_len-ing to the full 20 GiB would allocate and zero-fill
    // the whole gap, ballooning the template to its full logical size on disk.
    // Mark it sparse first so only the written extents consume space — matching
    // the implicit sparse behavior the seek/set_len path already gets on ext4
    // and APFS.
    #[cfg(windows)]
    crate::extract::mark_file_sparse(&file)?;
    let mut out = std::io::BufWriter::new(file);

    let mut decoder = zstd::Decoder::new(File::open(src)?)?;
    let mut buf = vec![0u8; 512 * 1024];
    let mut offset: u64 = 0;
    loop {
        let mut filled = 0;
        // Fill the whole buffer so the zero test sees full chunks rather than
        // whatever short reads the decoder happens to produce.
        while filled < buf.len() {
            match decoder.read(&mut buf[filled..])? {
                0 => break,
                n => filled += n,
            }
        }
        if filled == 0 {
            break;
        }
        let chunk = &buf[..filled];
        if chunk.iter().any(|&b| b != 0) {
            out.seek(SeekFrom::Start(offset))?;
            out.write_all(chunk)?;
        }
        offset += filled as u64;
    }
    out.flush()?;
    let file = out.into_inner().map_err(|e| e.into_error())?;
    // Trailing zeros are never written, so set the length explicitly to give the
    // file its full logical size with the tail left as a hole.
    file.set_len(offset)?;
    file.sync_all()?;
    Ok(())
}

/// Asset collector for gathering runtime components.
pub struct AssetCollector {
    staging_dir: PathBuf,
    inventory: AssetInventory,
}

impl AssetCollector {
    /// Create a new asset collector with a staging directory.
    pub fn new(staging_dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&staging_dir)?;
        fs::create_dir_all(staging_dir.join("layers"))?;

        Ok(Self {
            staging_dir,
            inventory: AssetInventory {
                libraries: Vec::new(),
                agent_rootfs: AssetEntry {
                    path: "agent-rootfs.tar".to_string(),
                    size: 0,
                },
                layers: Vec::new(),
                storage_template: None,
                storage_logical_size: None,
                overlay_template: None,
                overlay_logical_size: None,
            },
        })
    }

    /// Get the staging directory path.
    pub fn staging_dir(&self) -> &Path {
        &self.staging_dir
    }

    /// Discover and copy runtime libraries from the given lib directory.
    ///
    /// Always copies:
    /// - libkrun.dylib / libkrun.so — VM runtime
    /// - libkrunfw.5.dylib / libkrunfw.so.5 — kernel firmware
    ///
    /// Copies when present (GPU passthrough for `gpu = true` guests):
    /// - macOS: libvirglrenderer.1.dylib, libMoltenVK.dylib, libepoxy.0.dylib
    /// - Linux: libvirglrenderer.so.1, libepoxy.so.0, virgl_render_server binary
    ///
    /// GPU Vulkan ICDs (ANV, RADV) are hardware-specific and cannot be bundled.
    /// When GPU libs are bundled, loading them adds ~3ms overhead even for non-GPU
    /// workloads (lib load is unavoidable; virglrenderer init is deferred to GPU use).
    pub fn collect_libraries(&mut self, lib_dir: &Path) -> Result<()> {
        fs::create_dir_all(self.staging_dir.join("lib"))?;

        let lib_names = if cfg!(target_os = "macos") {
            vec!["libkrun.dylib", "libkrunfw.5.dylib"]
        } else if cfg!(target_os = "windows") {
            // Must match smolvm's loader (util::libkrun_filename): WHP uses the
            // Windows DLL names, not the Linux .so names.
            vec!["krun.dll", "libkrunfw.dll"]
        } else {
            vec!["libkrun.so", "libkrunfw.so.5"]
        };

        for name in lib_names {
            let src = lib_dir.join(name);
            if !src.exists() {
                return Err(PackError::AssetNotFound(format!(
                    "library not found: {}",
                    src.display()
                )));
            }

            let dst = self.staging_dir.join("lib").join(name);
            fs::copy(&src, &dst)?;

            let metadata = fs::metadata(&dst)?;
            self.inventory.libraries.push(AssetEntry {
                path: format!("lib/{}", name),
                size: metadata.len(),
            });
        }

        // On macOS, bundle GPU rendering libraries when present in the lib dir.
        // The virglrenderer chain (Venus/Vulkan) enables hardware-accelerated GPU
        // passthrough for guests using virtio-gpu. All paths use @loader_path so
        // they resolve relative to where libkrun.dylib is loaded from.
        #[cfg(target_os = "macos")]
        {
            let gpu_libs = [
                "libvirglrenderer.1.dylib",
                "libMoltenVK.dylib",
                "libepoxy.0.dylib",
            ];
            for name in &gpu_libs {
                let src = lib_dir.join(name);
                if src.exists() {
                    let dst = self.staging_dir.join("lib").join(name);
                    fs::copy(&src, &dst)?;
                    let metadata = fs::metadata(&dst)?;
                    self.inventory.libraries.push(AssetEntry {
                        path: format!("lib/{}", name),
                        size: metadata.len(),
                    });
                }
            }
        }

        // On Linux, bundle GPU rendering libraries and render server when present.
        // virglrenderer + epoxy enable Venus/Vulkan via virtio-gpu.
        // virgl_render_server is the subprocess libkrun spawns during Venus init.
        // GPU Vulkan ICDs (ANV, RADV) are hardware-specific and cannot be bundled.
        #[cfg(target_os = "linux")]
        {
            let gpu_libs = ["libvirglrenderer.so.1", "libepoxy.so.0"];
            for name in &gpu_libs {
                let src = lib_dir.join(name);
                if src.exists() {
                    let dst = self.staging_dir.join("lib").join(name);
                    fs::copy(&src, &dst)?;
                    let metadata = fs::metadata(&dst)?;
                    self.inventory.libraries.push(AssetEntry {
                        path: format!("lib/{}", name),
                        size: metadata.len(),
                    });
                }
            }
            let server_src = lib_dir.join("virgl_render_server");
            if server_src.exists() {
                let server_dst = self.staging_dir.join("lib").join("virgl_render_server");
                fs::copy(&server_src, &server_dst)?;
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&server_dst, fs::Permissions::from_mode(0o755))?;
                let metadata = fs::metadata(&server_dst)?;
                self.inventory.libraries.push(AssetEntry {
                    path: "lib/virgl_render_server".to_string(),
                    size: metadata.len(),
                });
            }
        }

        Ok(())
    }

    /// Copy the agent rootfs directory and create a tarball.
    pub fn collect_agent_rootfs(&mut self, rootfs_dir: &Path) -> Result<()> {
        if !rootfs_dir.exists() {
            return Err(PackError::AssetNotFound(format!(
                "agent rootfs not found: {}",
                rootfs_dir.display()
            )));
        }

        let tar_path = self.staging_dir.join("agent-rootfs.tar");
        let tar_file = File::create(&tar_path)?;
        let mut tar_builder = tar::Builder::new(BufWriter::new(tar_file));

        // Don't follow symlinks - preserve them as-is
        tar_builder.follow_symlinks(false);

        // The agent-rootfs directory doubles as the virtiofs mount the host
        // writes its per-boot readiness markers into (`.smolvm-ready.<hash>`,
        // see `AGENT_READY_MARKER`). Those are host-side runtime artifacts, not
        // part of the guest init system, and they accumulate across boots — and
        // a VM that ran under per-VM-uid isolation leaves them owned by a
        // foreign uid with mode 0600, unreadable to the packer. `append_dir_all`
        // over the whole directory then hard-failed the entire pack with an
        // opaque "tar error: Permission denied". Walk the top level instead,
        // skip the markers, and name the offending path on any real I/O error.
        let mut entries: Vec<fs::DirEntry> =
            fs::read_dir(rootfs_dir)?.collect::<std::io::Result<_>>()?;
        // Deterministic ordering so the tar (and its hash) is reproducible.
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let name = entry.file_name();
            if name
                .to_string_lossy()
                .starts_with(smolvm_protocol::AGENT_READY_MARKER)
            {
                continue;
            }
            let path = entry.path();
            let tar_err = |e: std::io::Error| PackError::Tar(format!("{}: {e}", path.display()));
            if entry.file_type()?.is_dir() {
                tar_builder.append_dir_all(&name, &path).map_err(tar_err)?;
            } else {
                // Regular file or symlink (follow_symlinks(false) archives the
                // link itself rather than its target).
                tar_builder
                    .append_path_with_name(&path, &name)
                    .map_err(tar_err)?;
            }
        }

        tar_builder
            .finish()
            .map_err(|e| PackError::Tar(e.to_string()))?;

        let metadata = fs::metadata(&tar_path)?;
        self.inventory.agent_rootfs = AssetEntry {
            path: "agent-rootfs.tar".to_string(),
            size: metadata.len(),
        };

        Ok(())
    }

    /// Add an OCI layer tarball.
    pub fn add_layer(&mut self, digest: &str, layer_data: &[u8]) -> Result<()> {
        let filename = digest_to_filename(digest)?;
        let path = format!("layers/{}", filename);

        let dst = self.staging_dir.join(&path);
        fs::write(&dst, layer_data)?;

        self.inventory.layers.push(LayerEntry {
            digest: digest.to_string(),
            path,
            size: layer_data.len() as u64,
        });

        Ok(())
    }

    /// Total bytes of the layer tars registered so far.
    ///
    /// From-vm packs record this as the manifest's `image_size` so the run-time
    /// storage auto-sizer accounts for the layers — essential when the guest
    /// unpacks staged tars onto the storage disk itself.
    pub fn staged_layer_bytes(&self) -> u64 {
        self.inventory.layers.iter().map(|l| l.size).sum()
    }

    /// Get the staging path where a layer file should be written.
    ///
    /// Call this before streaming the layer to get the destination path,
    /// then call `register_layer()` after writing to register it in the inventory.
    pub fn layer_staging_path(&self, digest: &str) -> PathBuf {
        let filename = digest_to_filename(digest)
            .expect("layer digest must be sha256:<hex> with at least 12 hex chars");
        self.staging_dir.join(format!("layers/{}", filename))
    }

    /// Register a layer that was already written to its staging path.
    ///
    /// Use after streaming a layer directly to `layer_staging_path()`.
    pub fn register_layer(&mut self, digest: &str) -> Result<()> {
        let filename = digest_to_filename(digest)?;
        let path = format!("layers/{}", filename);
        let dst = self.staging_dir.join(&path);

        let metadata = fs::metadata(&dst)?;
        self.inventory.layers.push(LayerEntry {
            digest: digest.to_string(),
            path,
            size: metadata.len(),
        });

        Ok(())
    }

    /// Add an OCI layer from a file path.
    pub fn add_layer_from_file(&mut self, digest: &str, layer_path: &Path) -> Result<()> {
        let filename = digest_to_filename(digest)?;
        let path = format!("layers/{}", filename);

        let dst = self.staging_dir.join(&path);
        fs::copy(layer_path, &dst)?;

        let metadata = fs::metadata(&dst)?;
        self.inventory.layers.push(LayerEntry {
            digest: digest.to_string(),
            path,
            size: metadata.len(),
        });

        Ok(())
    }

    /// Create and collect a pre-formatted ext4 storage template.
    ///
    /// Creates a small sparse ext4 disk image that can be used as a template
    /// for the storage disk at runtime. This eliminates the need for mkfs.ext4
    /// on first boot and improves reliability.
    ///
    /// Tries in order:
    /// 1. Copy an existing pre-formatted template from `~/.smolvm/` or next to the exe
    /// 2. Format a new one with `mkfs.ext4` (requires e2fsprogs)
    ///
    /// The template is a 512MB sparse file (actual size ~100KB when empty).
    pub fn create_storage_template(&mut self) -> Result<()> {
        use std::io::{Seek, SeekFrom, Write};
        use std::process::Command;

        const TEMPLATE_SIZE: u64 = 512 * 1024 * 1024; // 512MB virtual size
        const TEMPLATE_NAME: &str = "storage.ext4";

        let template_path = self.staging_dir.join(TEMPLATE_NAME);

        // Try to copy from an existing pre-formatted template first.
        // This avoids requiring e2fsprogs on the build machine.
        if let Some(existing) = find_existing_template("storage-template.ext4") {
            // Hole-preserving copy: the shipped storage-template.ext4 is a large
            // (multi-GiB) sparse file, and a plain fs::copy densifies it into its
            // full logical size of zeros on some Linux filesystems/mounts —
            // ballooning the staging dir and failing pack builds with ENOSPC.
            crate::extract::sparse_copy(&existing, &template_path)?;
            let metadata = fs::metadata(&template_path)?;
            self.inventory.storage_template = Some(AssetEntry {
                path: TEMPLATE_NAME.to_string(),
                size: metadata.len(),
            });
            return Ok(());
        }

        // No pre-formatted template found — create one with mkfs.ext4.

        // Create sparse file
        let mut file = File::create(&template_path)?;
        // On Windows/NTFS, File::create makes a dense file; seeking past the end
        // and writing a tail byte would allocate every intermediate block.
        #[cfg(windows)]
        crate::extract::mark_file_sparse(&file)?;
        file.seek(SeekFrom::Start(TEMPLATE_SIZE - 1))?;
        file.write_all(&[0])?;
        file.sync_all()?;
        drop(file);

        // Find mkfs.ext4
        let mkfs_paths = [
            "/opt/homebrew/opt/e2fsprogs/sbin/mkfs.ext4",
            "/usr/local/opt/e2fsprogs/sbin/mkfs.ext4",
            "/opt/homebrew/sbin/mkfs.ext4",
            "/usr/local/sbin/mkfs.ext4",
            "/sbin/mkfs.ext4",
            "/usr/sbin/mkfs.ext4",
            "mkfs.ext4",
        ];

        let mkfs_path = mkfs_paths
            .iter()
            .find(|p| {
                if p.contains('/') {
                    std::path::Path::new(p).exists()
                } else {
                    Command::new(p).arg("--version").output().is_ok()
                }
            })
            .ok_or_else(|| {
                // Windows has no host mkfs.ext4, so point the user at the
                // guest-VM recipe for staging a template (the agent rootfs has
                // e2fsprogs). On Unix the fix is just installing e2fsprogs.
                #[cfg(windows)]
                let msg = "storage-template.ext4 not found, and Windows has no host \
                     mkfs.ext4 to create one. Format a small template inside a guest VM \
                     once and place it next to smolvm.exe (or in %USERPROFILE%\\.smolvm\\):\n  \
                     smolvm machine create --name mktmpl --volume <dir>:/out\n  \
                     smolvm machine start --name mktmpl\n  \
                     smolvm machine exec --name mktmpl -- /bin/busybox sh -c \
                     \"truncate -s 512M /out/storage-template.ext4 && \
                     mkfs.ext4 -F -q -m 0 /out/storage-template.ext4\"\n  \
                     smolvm machine delete --name mktmpl --force\n  \
                     then copy <dir>\\storage-template.ext4 next to smolvm.exe";
                #[cfg(not(windows))]
                let msg = "mkfs.ext4 not found. Install e2fsprogs or place a pre-formatted \
                     storage-template.ext4 in ~/.smolvm/";
                PackError::AssetNotFound(msg.into())
            })?;

        // Format with ext4
        // Reset SIGCHLD to default before spawning to avoid issues after agent stop
        #[cfg(unix)]
        unsafe {
            libc::signal(libc::SIGCHLD, libc::SIG_DFL);
        }

        let mut child = Command::new(mkfs_path)
            .args([
                "-F", // Force (don't ask)
                "-q", // Quiet
                "-m", "0", // No reserved blocks
                "-L", "smolvm", // Label
            ])
            .arg(&template_path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| PackError::AssetNotFound(format!("failed to spawn mkfs.ext4: {}", e)))?;

        let status = child.wait().map_err(|e| {
            PackError::AssetNotFound(format!("failed to wait for mkfs.ext4: {}", e))
        })?;

        if !status.success() {
            return Err(PackError::AssetNotFound(
                "mkfs.ext4 failed to format storage template".into(),
            ));
        }

        // Get actual file size (sparse, so much smaller than 512MB)
        let metadata = fs::metadata(&template_path)?;
        self.inventory.storage_template = Some(AssetEntry {
            path: TEMPLATE_NAME.to_string(),
            size: metadata.len(),
        });

        Ok(())
    }

    /// Add an overlay disk template from an existing VM.
    ///
    /// Copies the VM's overlay disk (overlay.raw) to the staging directory as
    /// `overlay.raw`, stripping trailing sparse holes so only actual data bytes
    /// enter the tar/zstd pipeline.  For a typical 10 GiB overlay with ~50 MB
    /// of real ext4 data this reduces pack time by ~100x.
    ///
    /// The original full size is recorded in `overlay_logical_size` so that
    /// the extraction path can restore the sparse skeleton with `ftruncate`.
    pub fn add_overlay_template(&mut self, path: &Path) -> Result<()> {
        if !path.exists() {
            return Err(PackError::AssetNotFound(format!(
                "overlay disk not found: {}",
                path.display()
            )));
        }

        const OVERLAY_NAME: &str = "overlay.raw";
        let dst = self.staging_dir.join(OVERLAY_NAME);

        let (logical_size, truncated_size) = sparse_copy_overlay(path, &dst)?;

        self.inventory.overlay_template = Some(AssetEntry {
            path: OVERLAY_NAME.to_string(),
            size: truncated_size,
        });

        // Record the original full disk size so extract can restore it.
        if logical_size > truncated_size {
            self.inventory.overlay_logical_size = Some(logical_size);
        }

        Ok(())
    }

    /// Add a stopped VM's persistent storage disk as the VM-mode template.
    /// Trailing sparse space is stripped for packing and its original logical
    /// size is recorded so cold-create can normalize one safe COW base.
    pub fn add_vm_storage_template(&mut self, path: &Path) -> Result<()> {
        if !path.exists() {
            return Err(PackError::AssetNotFound(format!(
                "storage disk not found: {}",
                path.display()
            )));
        }

        const STORAGE_NAME: &str = "storage.ext4";
        let dst = self.staging_dir.join(STORAGE_NAME);
        let (logical_size, truncated_size) = sparse_copy_overlay(path, &dst)?;
        self.inventory.storage_template = Some(AssetEntry {
            path: STORAGE_NAME.to_string(),
            size: truncated_size,
        });
        self.inventory.storage_logical_size = Some(logical_size);
        Ok(())
    }

    /// Get the current asset inventory.
    pub fn inventory(&self) -> &AssetInventory {
        &self.inventory
    }

    /// Consume the collector and return the final inventory.
    pub fn into_inventory(self) -> AssetInventory {
        self.inventory
    }

    /// Compress staged assets into a single zstd-compressed tarball.
    ///
    /// When `exclude_libs` is true, the `lib/` directory is excluded
    /// (two-file mode: libs are embedded in the stub binary instead).
    /// When false, everything is included (single-file mode).
    pub fn compress(&self, output: &Path, exclude_libs: bool) -> Result<u64> {
        let output_file = File::create(output)?;
        let encoder = zstd::stream::Encoder::new(output_file, ZSTD_LEVEL)
            .map_err(|e| PackError::Compression(e.to_string()))?;
        let mut tar_builder = tar::Builder::new(encoder);

        // Sort entries for deterministic tar ordering (consistent checksums)
        let mut entries: Vec<_> = fs::read_dir(&self.staging_dir)?
            .filter_map(|e| e.ok())
            .collect();
        entries.sort_by_key(|e| e.file_name());

        for entry in entries {
            let name = entry.file_name();
            if exclude_libs && name == "lib" {
                continue; // libs go in the stub, not the sidecar
            }
            let path = entry.path();
            #[cfg(target_os = "macos")]
            append_macos_tree(&mut tar_builder, &path, Path::new(&name))?;
            #[cfg(not(target_os = "macos"))]
            {
                if path.is_dir() {
                    tar_builder
                        .append_dir_all(name.to_string_lossy().as_ref(), &path)
                        .map_err(|e| PackError::Tar(e.to_string()))?;
                } else {
                    tar_builder
                        .append_path_with_name(&path, name.to_string_lossy().as_ref())
                        .map_err(|e| PackError::Tar(e.to_string()))?;
                }
            }
        }

        let encoder = tar_builder
            .into_inner()
            .map_err(|e| PackError::Tar(e.to_string()))?;
        encoder
            .finish()
            .map_err(|e| PackError::Compression(e.to_string()))?;

        let metadata = fs::metadata(output)?;
        Ok(metadata.len())
    }
}

// =============================================================================
// Sparse-aware overlay copy
// =============================================================================

/// Copy a sparse overlay disk to `dst`, stripping trailing zeros.
///
/// Scans backwards from the end of the source to find the last non-zero byte,
/// then copies only bytes `[0, last_nonzero+1]` to `dst`, skipping zero
/// chunks in the forward pass.
///
/// `SEEK_DATA`/`SEEK_HOLE` is avoided because APFS reports zero-fill extents
/// (efficiently stored but containing zeros) as "data", making lseek-based
/// hole detection return the full file size even when 90%+ is zeros.
/// Content scanning works correctly on both APFS and Linux ext4/xfs.
///
/// Returns the original full (logical) size so the caller can record it for
/// the extraction side to restore the sparse skeleton via `ftruncate`.
/// Returns `(logical_size, truncated_size)`.
fn sparse_copy_overlay(src: &Path, dst: &Path) -> std::io::Result<(u64, u64)> {
    let mut src_file = File::open(src)?;
    let logical_size = src_file.metadata()?.len();

    // Scan backwards to find the last non-zero byte (= safe truncation point).
    // On APFS, zero-fill regions are served from page cache without disk I/O,
    // so even scanning 8+ GiB of trailing zeros takes only ~100–200 ms.
    let truncated_size = find_last_data_byte(&mut src_file, logical_size)?;

    // Create destination as a sparse skeleton; keep the handle for writing.
    let mut dst_file = File::create(dst)?;
    // On Windows/NTFS, File::create makes a non-sparse file: set_len-ing to the
    // (large) truncated size and then writing a chunk at a high offset would
    // zero-fill/allocate the entire gap, ballooning a ~50 MB overlay to ~10 GiB
    // of real disk. Mark it sparse first so only written extents consume space —
    // matching the implicit sparse behavior of Unix filesystems.
    #[cfg(windows)]
    crate::extract::mark_file_sparse(&dst_file)?;
    dst_file.set_len(truncated_size)?;

    if truncated_size == 0 {
        return Ok((logical_size, 0));
    }

    // Forward copy: read [0, truncated_size) in 512 KiB chunks,
    // writing only non-zero chunks (zero chunks remain as holes).
    src_file.seek(SeekFrom::Start(0))?;
    let mut buf = vec![0u8; 512 * 1024];
    let mut offset: u64 = 0;

    while offset < truncated_size {
        let to_read = (truncated_size - offset).min(buf.len() as u64) as usize;
        let n = src_file.read(&mut buf[..to_read])?;
        if n == 0 {
            break;
        }
        let chunk = &buf[..n];
        if chunk.iter().any(|&b| b != 0) {
            dst_file.seek(SeekFrom::Start(offset))?;
            dst_file.write_all(chunk)?;
        }
        offset += n as u64;
    }

    Ok((logical_size, truncated_size))
}

/// Find the truncation point: offset of the last non-zero byte + 1.
///
/// Reads the file backwards in 1 MiB chunks until a non-zero byte is found.
/// Returns 0 if the entire file is zeros.
fn find_last_data_byte(file: &mut File, logical_size: u64) -> std::io::Result<u64> {
    if logical_size == 0 {
        return Ok(0);
    }

    const CHUNK: u64 = 1024 * 1024; // 1 MiB scan chunk
    let mut buf = vec![0u8; CHUNK as usize];
    let mut pos = logical_size;

    while pos > 0 {
        let chunk_start = pos.saturating_sub(CHUNK);
        let chunk_size = (pos - chunk_start) as usize;

        file.seek(SeekFrom::Start(chunk_start))?;
        let n = file.read(&mut buf[..chunk_size])?;
        if n == 0 {
            break;
        }

        // Scan backwards for the last non-zero byte in this chunk.
        for i in (0..n).rev() {
            if buf[i] != 0 {
                return Ok(chunk_start + i as u64 + 1);
            }
        }

        pos = chunk_start;
    }

    Ok(0) // Entire file is zeros
}

/// Decompress a zstd-compressed assets blob.
pub fn decompress_assets(compressed: &[u8], output_dir: &Path) -> Result<()> {
    fs::create_dir_all(output_dir)?;

    let decoder = zstd::stream::Decoder::new(compressed)
        .map_err(|e| PackError::Compression(e.to_string()))?;
    let mut archive = tar::Archive::new(decoder);

    archive
        .unpack(output_dir)
        .map_err(|e| PackError::Tar(e.to_string()))?;

    Ok(())
}

/// Decompress assets from a file.
pub fn decompress_assets_from_file(compressed_path: &Path, output_dir: &Path) -> Result<()> {
    fs::create_dir_all(output_dir)?;

    let file = File::open(compressed_path)?;
    let decoder =
        zstd::stream::Decoder::new(file).map_err(|e| PackError::Compression(e.to_string()))?;
    let mut archive = tar::Archive::new(decoder);

    archive
        .unpack(output_dir)
        .map_err(|e| PackError::Tar(e.to_string()))?;

    Ok(())
}

/// Calculate CRC32 checksum of data.
pub fn crc32(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}

/// Calculate CRC32 checksum of a file.
pub fn crc32_file(path: &Path) -> Result<u32> {
    let mut file = File::open(path)?;
    let mut hasher = crc32fast::Hasher::new();

    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    Ok(hasher.finalize())
}

/// Calculate CRC32 checksum of multiple sections of a file.
pub fn crc32_file_range(path: &Path, offset: u64, size: u64) -> Result<u32> {
    use std::io::{Seek, SeekFrom};

    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(offset))?;

    let mut hasher = crc32fast::Hasher::new();
    let mut remaining = size;
    let mut buf = [0u8; 64 * 1024];

    while remaining > 0 {
        let to_read = remaining.min(buf.len() as u64) as usize;
        let n = file.read(&mut buf[..to_read])?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        remaining -= n as u64;
    }

    Ok(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_to_filename_rejects_path_traversal() {
        // A valid hex digest is accepted.
        assert_eq!(
            digest_to_filename("sha256:abcdef012345").unwrap(),
            "abcdef012345.tar"
        );
        // Non-hex / traversal digests are rejected before becoming a path.
        for bad in [
            "sha256:../../../../etc/evil",
            "sha256:..%2f..%2fevil",
            "sha256:abc/def/ghij",
            "sha256:abcdefabcdeZ",
        ] {
            assert!(
                digest_to_filename(bad).is_err(),
                "should reject non-hex digest: {bad}"
            );
        }
    }

    #[test]
    fn test_find_last_data_byte_all_zero() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        fs::write(temp.path(), vec![0u8; 4096]).unwrap();
        let mut file = File::open(temp.path()).unwrap();
        assert_eq!(find_last_data_byte(&mut file, 4096).unwrap(), 0);
    }

    #[test]
    fn test_find_last_data_byte_trailing_zeros() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        let mut data = vec![0u8; 4100];
        data[99] = 0xAB; // non-zero at 99, then 4000 trailing zeros
        fs::write(temp.path(), &data).unwrap();
        let mut file = File::open(temp.path()).unwrap();
        assert_eq!(find_last_data_byte(&mut file, 4100).unwrap(), 100);
    }

    #[test]
    fn test_find_last_data_byte_nonzero_at_end() {
        // Boundary: no trailing zeros — function must return full length.
        let temp = tempfile::NamedTempFile::new().unwrap();
        let mut data = vec![0u8; 1024];
        data[1023] = 1;
        fs::write(temp.path(), &data).unwrap();
        let mut file = File::open(temp.path()).unwrap();
        assert_eq!(find_last_data_byte(&mut file, 1024).unwrap(), 1024);
    }

    #[test]
    fn test_sparse_copy_overlay_all_zero() {
        // All-zero source: truncated_size=0, early exit before forward copy.
        let temp_dir = tempfile::tempdir().unwrap();
        let src = temp_dir.path().join("src.raw");
        let dst = temp_dir.path().join("dst.raw");
        fs::write(&src, vec![0u8; 8192]).unwrap();

        let (logical, truncated) = sparse_copy_overlay(&src, &dst).unwrap();
        assert_eq!(logical, 8192);
        assert_eq!(truncated, 0);
        assert_eq!(fs::metadata(&dst).unwrap().len(), 0);
    }

    #[test]
    fn test_sparse_copy_overlay_trailing_zeros_and_interior_holes() {
        // Verifies: trailing zeros are stripped, sizes are returned, interior
        // holes (zero chunks in the forward pass) are preserved in the copy.
        let temp_dir = tempfile::tempdir().unwrap();
        let src = temp_dir.path().join("src.raw");
        let dst = temp_dir.path().join("dst.raw");

        let mut data = vec![0u8; 8192];
        data[0] = 0x01; // non-zero at start
        data[511] = 0xFF; // last non-zero byte; trailing 7680 bytes are zeros
        fs::write(&src, &data).unwrap();

        let (logical, truncated) = sparse_copy_overlay(&src, &dst).unwrap();
        assert_eq!(logical, 8192);
        assert_eq!(truncated, 512);

        let dst_data = fs::read(&dst).unwrap();
        assert_eq!(dst_data[0], 0x01);
        assert_eq!(dst_data[511], 0xFF);
        assert_eq!(dst_data[256], 0x00); // interior zero is preserved
    }

    #[test]
    fn vm_storage_template_preserves_logical_size_without_packing_the_tail() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("storage.raw");
        let mut file = File::create(&source).unwrap();
        file.write_all(b"docker-layer").unwrap();
        file.set_len(4 * 1024 * 1024).unwrap();

        let staging = temp.path().join("staging");
        let mut collector = AssetCollector::new(staging.clone()).unwrap();
        collector.add_vm_storage_template(&source).unwrap();
        let inventory = collector.inventory();
        let template = inventory.storage_template.as_ref().unwrap();

        assert_eq!(template.path, "storage.ext4");
        assert_eq!(inventory.storage_logical_size, Some(4 * 1024 * 1024));
        assert_eq!(
            fs::metadata(staging.join(&template.path)).unwrap().len(),
            template.size
        );
        assert!(template.size < 4 * 1024 * 1024);
        assert_eq!(
            fs::read(staging.join(&template.path)).unwrap(),
            b"docker-layer"
        );
    }

    #[test]
    fn test_crc32_basic() {
        let data = b"hello world";
        let checksum = crc32(data);
        assert_eq!(checksum, 0x0D4A_1185); // Known CRC32 value
    }

    #[test]
    fn test_crc32_empty() {
        let data = b"";
        let checksum = crc32(data);
        assert_eq!(checksum, 0); // CRC32 of empty data is 0
    }

    #[test]
    fn test_asset_collector_staging() {
        let temp_dir = tempfile::tempdir().unwrap();
        let staging = temp_dir.path().join("staging");

        let _collector = AssetCollector::new(staging.clone()).unwrap();

        // lib/ is only created when collect_libraries() is called
        assert!(!staging.join("lib").exists());
        assert!(staging.join("layers").exists());
    }

    #[test]
    fn collect_agent_rootfs_excludes_ready_markers() {
        // The agent-rootfs dir doubles as the host's per-boot readiness-marker
        // mount (`.smolvm-ready.<hash>`). Those markers must never be packed
        // into the guest image — and on a host that ran uid-isolated VMs they
        // can be foreign-owned/unreadable, which used to hard-fail the whole
        // pack ("tar error: Permission denied"). Verify they're skipped while
        // real rootfs content is preserved.
        let temp = tempfile::tempdir().unwrap();
        let rootfs = temp.path().join("rootfs");
        fs::create_dir_all(rootfs.join("bin")).unwrap();
        fs::create_dir_all(rootfs.join("etc")).unwrap();
        fs::write(rootfs.join("bin/sh"), b"#!/bin/sh\n").unwrap();
        fs::write(rootfs.join("etc/hostname"), b"vm\n").unwrap();
        fs::write(rootfs.join("init"), b"agent").unwrap();
        fs::write(
            rootfs.join(format!("{}.deadbeef", smolvm_protocol::AGENT_READY_MARKER)),
            b"1",
        )
        .unwrap();
        fs::write(
            rootfs.join(format!("{}.cafef00d", smolvm_protocol::AGENT_READY_MARKER)),
            b"1",
        )
        .unwrap();

        let staging = temp.path().join("staging");
        let mut collector = AssetCollector::new(staging.clone()).unwrap();
        collector.collect_agent_rootfs(&rootfs).unwrap();

        let tar_path = staging.join("agent-rootfs.tar");
        let names: Vec<String> = tar::Archive::new(File::open(&tar_path).unwrap())
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
            .collect();

        assert!(
            names.iter().any(|n| n.ends_with("bin/sh")),
            "real rootfs file missing from pack: {names:?}"
        );
        assert!(
            names.iter().any(|n| n.ends_with("etc/hostname")),
            "real rootfs file missing from pack: {names:?}"
        );
        assert!(
            names.iter().any(|n| n.ends_with("init")),
            "top-level agent binary missing from pack: {names:?}"
        );
        assert!(
            !names.iter().any(|n| n.contains(".smolvm-ready")),
            "readiness marker leaked into the pack: {names:?}"
        );
    }

    #[test]
    fn test_compression_roundtrip() {
        let temp_dir = tempfile::tempdir().unwrap();
        let staging = temp_dir.path().join("staging");
        let output = temp_dir.path().join("output");

        // Create a file in staging
        fs::create_dir_all(&staging).unwrap();
        let test_file = staging.join("test.txt");
        fs::write(&test_file, b"hello world").unwrap();

        // Create collector and compress
        let collector = AssetCollector::new(staging).unwrap();
        let compressed = temp_dir.path().join("assets.tar.zst");
        collector.compress(&compressed, false).unwrap();

        // Decompress and verify
        decompress_assets_from_file(&compressed, &output).unwrap();
        let restored = output.join("test.txt");
        assert!(restored.exists());
        assert_eq!(fs::read_to_string(&restored).unwrap(), "hello world");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn compression_preserves_sparse_files_on_macos() {
        use std::os::unix::fs::MetadataExt;

        const LOGICAL_SIZE: u64 = 64 * 1024 * 1024;
        let temp_dir = tempfile::tempdir().unwrap();
        let staging = temp_dir.path().join("staging");
        let collector = AssetCollector::new(staging.clone()).unwrap();
        let checkpoint = staging.join("checkpoint");
        fs::create_dir_all(&checkpoint).unwrap();
        let memory = checkpoint.join("memory.bin");
        let mut file = File::create(&memory).unwrap();
        file.set_len(LOGICAL_SIZE).unwrap();
        file.seek(SeekFrom::Start(4096)).unwrap();
        file.write_all(&[0xA5; 4096]).unwrap();
        file.seek(SeekFrom::Start(32 * 1024 * 1024)).unwrap();
        file.write_all(&[0x5A; 4096]).unwrap();
        file.sync_all().unwrap();

        let compressed = temp_dir.path().join("assets.tar.zst");
        collector.compress(&compressed, false).unwrap();
        assert!(
            fs::metadata(&compressed).unwrap().len() < 1024 * 1024,
            "sparse holes were expanded into the compressed archive"
        );

        let output = temp_dir.path().join("output");
        decompress_assets_from_file(&compressed, &output).unwrap();
        let restored = output.join("checkpoint/memory.bin");
        let metadata = fs::metadata(&restored).unwrap();
        assert_eq!(metadata.len(), LOGICAL_SIZE);
        assert!(metadata.blocks() * 512 < LOGICAL_SIZE / 4);
        let mut restored = File::open(restored).unwrap();
        let mut page = [0_u8; 4096];
        restored.seek(SeekFrom::Start(4096)).unwrap();
        restored.read_exact(&mut page).unwrap();
        assert_eq!(page, [0xA5; 4096]);
        restored.seek(SeekFrom::Start(32 * 1024 * 1024)).unwrap();
        restored.read_exact(&mut page).unwrap();
        assert_eq!(page, [0x5A; 4096]);
        restored.seek(SeekFrom::End(-1)).unwrap();
        restored.read_exact(&mut page[..1]).unwrap();
        assert_eq!(page[0], 0);
    }
}

/// Expanding a compressed disk template back into a sparse file.
#[cfg(test)]
mod template_expand_tests {
    use super::*;

    /// Build a template-shaped file: a little real data, a large hole, a tail.
    /// Sized at 64 MiB: APFS does not report holes for files much smaller than
    /// this regardless of how they are written, so a smaller fixture would fail
    /// the sparseness assertion even for a correct implementation.
    fn template_bytes() -> Vec<u8> {
        let mut v = vec![0u8; 64 * 1024 * 1024];
        v[..4096].copy_from_slice(&[0xABu8; 4096]);
        let tail = v.len() - 16;
        v[tail..].copy_from_slice(&[0xCDu8; 16]);
        v
    }

    fn compress_to(path: &Path, data: &[u8]) {
        let out = File::create(path).expect("create zst");
        let mut enc = zstd::Encoder::new(out, 3).expect("encoder");
        enc.write_all(data).expect("write");
        enc.finish().expect("finish");
    }

    #[test]
    fn expansion_reproduces_the_original_bytes() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let src = tmp.path().join("t.ext4.zst");
        let dest = tmp.path().join("t.ext4");
        let data = template_bytes();
        compress_to(&src, &data);

        materialize_template(&src, &dest).expect("materialize");

        assert_eq!(fs::read(&dest).expect("read"), data);
    }

    /// The point of the exercise: the hole must not be written out.
    #[cfg(unix)]
    #[test]
    fn the_hole_is_left_unallocated() {
        use std::os::unix::fs::MetadataExt;
        let tmp = tempfile::tempdir().expect("tempdir");
        let src = tmp.path().join("t.ext4.zst");
        let dest = tmp.path().join("t.ext4");
        let data = template_bytes();
        compress_to(&src, &data);

        materialize_template(&src, &dest).expect("materialize");

        let meta = fs::metadata(&dest).expect("stat");
        assert_eq!(meta.len(), data.len() as u64, "logical size must match");
        let dense = data.len() as u64 / 512;
        assert!(
            meta.blocks() < dense / 4,
            "expected a sparse file, got {} blocks vs {dense} if dense",
            meta.blocks()
        );
    }

    /// The same guarantee on Windows/NTFS, where holes exist only after the file
    /// is explicitly marked sparse — the plain seek/set_len path leaves it dense.
    /// `GetCompressedFileSizeW` reports the bytes actually allocated on disk, so a
    /// sparse expansion reads far below the logical size while a dense one matches
    /// it. Cross-compilation cannot exercise this; it needs a native Windows run.
    #[cfg(windows)]
    #[test]
    fn the_hole_is_left_unallocated() {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::GetCompressedFileSizeW;

        let tmp = tempfile::tempdir().expect("tempdir");
        let src = tmp.path().join("t.ext4.zst");
        let dest = tmp.path().join("t.ext4");
        let data = template_bytes();
        compress_to(&src, &data);

        materialize_template(&src, &dest).expect("materialize");

        assert_eq!(
            fs::metadata(&dest).expect("stat").len(),
            data.len() as u64,
            "logical size must match"
        );

        let wide: Vec<u16> = dest.as_os_str().encode_wide().chain([0]).collect();
        let mut high: u32 = 0;
        // SAFETY: `wide` is a valid NUL-terminated path; `high` is a valid out ptr.
        let low = unsafe { GetCompressedFileSizeW(wide.as_ptr(), &mut high) };
        assert_ne!(low, u32::MAX, "GetCompressedFileSizeW failed");
        let on_disk = ((high as u64) << 32) | low as u64;
        assert!(
            on_disk < data.len() as u64 / 4,
            "expected a sparse file, got {on_disk} bytes on disk vs {} logical",
            data.len()
        );
    }

    /// A file that is entirely zeros still has to come back at full length.
    #[test]
    fn an_all_zero_template_keeps_its_length() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let src = tmp.path().join("z.ext4.zst");
        let dest = tmp.path().join("z.ext4");
        let data = vec![0u8; 4 * 1024 * 1024];
        compress_to(&src, &data);

        materialize_template(&src, &dest).expect("materialize");

        assert_eq!(fs::metadata(&dest).expect("stat").len(), data.len() as u64);
        assert!(fs::read(&dest).expect("read").iter().all(|&b| b == 0));
    }

    /// End-to-end discovery: a `.zst` beside the executable is found and
    /// expanded, exercising the same `current_exe()` branch a real install uses.
    /// The filename is unique so parallel tests cannot collide, and both the
    /// archive and its expansion are removed afterwards.
    #[test]
    fn a_zst_beside_the_executable_is_discovered_and_expanded() {
        let exe = std::env::current_exe().expect("current_exe");
        let dir = exe.parent().expect("exe dir");
        let name = format!("discovery-probe-{}.ext4", std::process::id());
        let zst = dir.join(format!("{name}.zst"));
        let expanded = dir.join(&name);
        let _ = fs::remove_file(&zst);
        let _ = fs::remove_file(&expanded);

        let data = template_bytes();
        compress_to(&zst, &data);

        let found = find_existing_template(&name);

        let cleanup = || {
            let _ = fs::remove_file(&zst);
            let _ = fs::remove_file(&expanded);
        };
        let Some(path) = found else {
            cleanup();
            panic!("compressed template beside the executable was not found");
        };
        let got = fs::read(&path).expect("read expanded");
        cleanup();
        assert_eq!(got, data, "expanded template must match the original");
    }

    /// A truncated archive must not leave a half-written file behind, or the
    /// plain-file lookup would treat the debris as a valid template.
    #[test]
    fn a_corrupt_archive_leaves_no_partial_file() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let src = tmp.path().join("bad.ext4.zst");
        let dest = tmp.path().join("bad.ext4");
        let data = template_bytes();
        compress_to(&src, &data);
        // Lop off the end so decompression fails partway.
        let whole = fs::read(&src).expect("read zst");
        fs::write(&src, &whole[..whole.len() / 2]).expect("truncate");

        assert!(materialize_template(&src, &dest).is_err());
        assert!(!dest.exists(), "no template should be left behind");
        assert!(
            !dest.with_extension("partial").exists(),
            "no scratch file should be left behind"
        );
    }
}
