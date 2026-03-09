//! Asset collection and compression for packed binaries.
//!
//! This module handles discovering and packaging runtime assets:
//! - Runtime libraries (libkrun, libkrunfw)
//! - Agent rootfs
//! - OCI image layers

use std::fs::{self, File};
use std::io::{BufWriter, Read};
use std::path::{Path, PathBuf};

use crate::format::{AssetEntry, AssetInventory, LayerEntry};
use crate::{PackError, Result};

/// Compression level for zstd (19 = high compression).
pub const ZSTD_LEVEL: i32 = 19;

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
        fs::create_dir_all(staging_dir.join("lib"))?;
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
            },
        })
    }

    /// Get the staging directory path.
    pub fn staging_dir(&self) -> &Path {
        &self.staging_dir
    }

    /// Discover and copy runtime libraries from the given lib directory.
    ///
    /// Looks for:
    /// - libkrun.dylib (macOS) or libkrun.so (Linux)
    /// - libkrunfw.5.dylib (macOS) or libkrunfw.so.5 (Linux)
    pub fn collect_libraries(&mut self, lib_dir: &Path) -> Result<()> {
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
        // Create filename from digest (remove sha256: prefix)
        let short_digest = digest.strip_prefix("sha256:").unwrap_or(digest);
        let filename = format!("{}.tar", &short_digest[..12]);
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

    /// Add an OCI layer from a file path.
    pub fn add_layer_from_file(&mut self, digest: &str, layer_path: &Path) -> Result<()> {
        let short_digest = digest.strip_prefix("sha256:").unwrap_or(digest);
        let filename = format!("{}.tar", &short_digest[..12]);
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
    /// Copies the VM's overlay disk (overlay.raw) to the staging directory
    /// as `overlay.raw`. This preserves the VM's persistent rootfs state
    /// for use in packed VM-mode binaries.
    pub fn add_overlay_template(&mut self, path: &Path) -> Result<()> {
        if !path.exists() {
            return Err(PackError::AssetNotFound(format!(
                "overlay disk not found: {}",
                path.display()
            )));
        }

        const OVERLAY_NAME: &str = "overlay.raw";
        let dst = self.staging_dir.join(OVERLAY_NAME);
        fs::copy(path, &dst)?;

        let metadata = fs::metadata(&dst)?;
        self.inventory.overlay_template = Some(AssetEntry {
            path: OVERLAY_NAME.to_string(),
            size: metadata.len(),
        });

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

    /// Compress all staged assets into a single zstd-compressed tarball.
    pub fn compress(&self, output: &Path) -> Result<u64> {
        let output_file = File::create(output)?;
        let encoder = zstd::stream::Encoder::new(output_file, ZSTD_LEVEL)
            .map_err(|e| PackError::Compression(e.to_string()))?;
        let mut tar_builder = tar::Builder::new(encoder);

        // Add all files from staging directory
        tar_builder
            .append_dir_all(".", &self.staging_dir)
            .map_err(|e| PackError::Tar(e.to_string()))?;

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

        assert!(staging.join("lib").exists());
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
        collector.compress(&compressed).unwrap();

        // Decompress and verify
        decompress_assets_from_file(&compressed, &output).unwrap();
        let restored = output.join("test.txt");
        assert!(restored.exists());
        assert_eq!(fs::read_to_string(&restored).unwrap(), "hello world");
    }
}
