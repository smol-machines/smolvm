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

/// Convert a digest string to a short filename for layer tars.
///
/// Expects `sha256:<64-hex-chars>` format. Returns error if the digest
/// portion (after prefix strip) is shorter than 12 characters.
fn digest_to_filename(digest: &str) -> Result<String> {
    let short = digest.strip_prefix("sha256:").unwrap_or(digest);
    if short.len() < 12 {
        return Err(PackError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "digest too short for filename: '{}' ({} chars, need 12)",
                digest,
                short.len()
            ),
        )));
    }
    Ok(format!("{}.tar", &short[..12]))
}

/// Compression level for zstd (3 = zstd default, fast with good ratio).
/// Level 19 was ~100x slower for only ~10% better compression.
pub const ZSTD_LEVEL: i32 = 3;

/// Find a pre-formatted disk template by filename.
///
/// Searches in order:
/// 1. `~/.smolvm/{filename}` (installed location)
/// 2. Next to the current executable (development)
fn find_existing_template(filename: &str) -> Option<PathBuf> {
    if let Some(home) = dirs::home_dir() {
        let path = home.join(".smolvm").join(filename);
        if path.exists() {
            return Some(path);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let path = dir.join(filename);
            if path.exists() {
                return Some(path);
            }
        }
    }
    None
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

        // Add all files from rootfs directory
        tar_builder
            .append_dir_all(".", rootfs_dir)
            .map_err(|e| PackError::Tar(e.to_string()))?;

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
            fs::copy(&existing, &template_path)?;
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
                PackError::AssetNotFound(
                    "mkfs.ext4 not found. Install e2fsprogs or place a pre-formatted \
                     storage-template.ext4 in ~/.smolvm/"
                        .into(),
                )
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
}
