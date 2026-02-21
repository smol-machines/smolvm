//! Persistent storage management.
//!
//! This module provides [`StorageDisk`] for managing persistent storage.
//! Each VM (default or named) gets its own sparse ext4 disk image that stores
//! OCI layers, container overlays, and cached manifests.
//!
//! # Storage Locations
//!
//! - Default VM: `~/Library/Application Support/smolvm/storage.raw` (macOS)
//! - Named VMs: `~/Library/Caches/smolvm/vms/{name}/storage.raw` (macOS)
//!
//! # Architecture
//!
//! The storage disk is a sparse raw disk image formatted with ext4.
//! It's mounted inside the agent VM which handles OCI layer extraction
//! and overlay filesystem management.

use crate::error::{Error, Result};
use crate::platform::Os;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Default size for the shared storage disk (20 GB sparse).
pub const DEFAULT_STORAGE_SIZE_GB: u64 = 20;

/// Storage disk filename.
pub const STORAGE_DISK_FILENAME: &str = "storage.raw";

/// Common search paths for e2fsprogs tools (mkfs.ext4, e2fsck, resize2fs).
const E2FSPROGS_PATH_PREFIXES: &[&str] = &[
    "/opt/homebrew/opt/e2fsprogs/sbin", // macOS ARM (Homebrew)
    "/usr/local/opt/e2fsprogs/sbin",    // macOS Intel (Homebrew)
    "/opt/homebrew/sbin",               // macOS ARM (Homebrew alt)
    "/usr/local/sbin",                  // macOS Intel (Homebrew alt)
    "/sbin",                            // Linux
    "/usr/sbin",                        // Linux alt
];

/// Find an e2fsprogs tool by name (e.g., "mkfs.ext4", "e2fsck", "resize2fs").
///
/// Searches common installation paths, then falls back to PATH lookup.
fn find_e2fsprogs_tool(name: &str) -> Option<String> {
    // Check known paths first
    for prefix in E2FSPROGS_PATH_PREFIXES {
        let path = format!("{}/{}", prefix, name);
        if std::path::Path::new(&path).exists() {
            return Some(path);
        }
    }

    // Fall back to PATH lookup
    if std::process::Command::new(name)
        .arg("--version")
        .output()
        .is_ok()
    {
        return Some(name.to_string());
    }

    None
}

/// Disk format version info (stored at `/.smolvm/version.json` in ext4 disk).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskVersion {
    /// Format version (currently: 1).
    pub format_version: u32,

    /// Timestamp when the disk was created.
    pub created_at: String,

    /// Digest of the base rootfs image.
    pub base_digest: String,

    /// smolvm version that created this disk.
    pub smolvm_version: String,
}

impl DiskVersion {
    /// Current format version.
    pub const CURRENT_VERSION: u32 = 1;

    /// Create a new disk version with current settings.
    pub fn new(base_digest: impl Into<String>) -> Self {
        Self {
            format_version: Self::CURRENT_VERSION,
            created_at: crate::util::current_timestamp(),
            base_digest: base_digest.into(),
            smolvm_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// Check if this version is compatible with the current smolvm.
    pub fn is_compatible(&self) -> bool {
        self.format_version <= Self::CURRENT_VERSION
    }
}

/// Shared storage disk for OCI layers.
///
/// This is a sparse raw disk image that the helper VM mounts to store
/// OCI image layers and overlay filesystems.
///
/// # Directory Structure (inside ext4)
///
/// ```text
/// /
/// ├── .smolvm_formatted    # Marker file
/// ├── layers/              # Extracted OCI layers (content-addressed)
/// │   └── sha256:{digest}/ # Each layer as a directory
/// ├── configs/             # OCI image configs
/// │   └── {digest}.json
/// ├── overlays/            # Workload overlay directories
/// │   └── {workload_id}/
/// │       ├── upper/       # Writable layer
/// │       ├── work/        # Overlay work directory
/// │       └── merged/      # Mount point (optional)
/// └── manifests/           # Cached image manifests
///     └── {image_ref}.json
/// ```
#[derive(Debug, Clone)]
pub struct StorageDisk {
    /// Path to the disk image file.
    path: PathBuf,
    /// Size in bytes.
    size_bytes: u64,
}

impl StorageDisk {
    /// Get the default path for the storage disk.
    ///
    /// On macOS: `~/Library/Application Support/smolvm/storage.raw`
    /// On Linux: `~/.local/share/smolvm/storage.raw`
    pub fn default_path() -> Result<PathBuf> {
        let data_dir = dirs::data_local_dir()
            .or_else(dirs::data_dir)
            .ok_or_else(|| Error::storage("resolve path", "could not determine data directory"))?;

        let smolvm_dir = data_dir.join("smolvm");
        Ok(smolvm_dir.join(STORAGE_DISK_FILENAME))
    }

    /// Open or create the storage disk at the default location.
    pub fn open_or_create() -> Result<Self> {
        let path = Self::default_path()?;
        Self::open_or_create_at(&path, DEFAULT_STORAGE_SIZE_GB)
    }

    /// Open or create the storage disk at the default location with a custom size.
    pub fn open_or_create_with_size(size_gb: u64) -> Result<Self> {
        let path = Self::default_path()?;
        Self::open_or_create_at(&path, size_gb)
    }

    /// Open or create the storage disk at a custom path.
    pub fn open_or_create_at(path: &Path, size_gb: u64) -> Result<Self> {
        // Validate size
        if size_gb == 0 {
            return Err(Error::config(
                "validate storage size",
                "disk size must be greater than 0 GB",
            ));
        }

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let size_bytes = size_gb * 1024 * 1024 * 1024;

        if path.exists() {
            // Open existing disk
            let metadata = std::fs::metadata(path)?;
            Ok(Self {
                path: path.to_path_buf(),
                size_bytes: metadata.len(),
            })
        } else {
            // Create sparse disk image
            Self::create_sparse(path, size_bytes)?;
            Ok(Self {
                path: path.to_path_buf(),
                size_bytes,
            })
        }
    }

    /// Create a sparse disk image.
    ///
    /// # Panics
    ///
    /// Panics if `size_bytes` is 0 (would cause underflow).
    fn create_sparse(path: &Path, size_bytes: u64) -> Result<()> {
        use std::fs::OpenOptions;
        use std::io::{Seek, SeekFrom, Write};

        // Guard against zero-size disk (would underflow in seek)
        assert!(size_bytes > 0, "disk size must be greater than 0");

        tracing::info!(path = %path.display(), size_gb = size_bytes / (1024*1024*1024), "creating sparse storage disk");

        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;

        // Seek to end and write a single byte to create sparse file
        file.seek(SeekFrom::Start(size_bytes - 1))?;
        file.write_all(&[0])?;
        file.sync_all()?;

        Ok(())
    }

    /// Pre-format the disk with ext4 on the host.
    ///
    /// This tries multiple approaches in order:
    /// 1. Copy from pre-formatted template (no dependencies, fastest)
    /// 2. Format with mkfs.ext4 (requires e2fsprogs)
    ///
    /// The template approach eliminates the e2fsprogs dependency for end users.
    pub fn ensure_formatted(&self) -> Result<()> {
        if !self.needs_format() {
            tracing::debug!(path = %self.path.display(), "disk already formatted");
            return Ok(());
        }

        // Try to copy from pre-formatted template first (no dependencies)
        if let Some(template_path) = Self::find_storage_template() {
            return self.copy_from_template(&template_path);
        }

        // Fall back to formatting with mkfs.ext4
        self.format_with_mkfs()
    }

    /// Find the pre-formatted storage template.
    ///
    /// Searches in order:
    /// 1. ~/.smolvm/storage-template.ext4 (installed location)
    /// 2. Next to the current executable (development)
    fn find_storage_template() -> Option<PathBuf> {
        const TEMPLATE_FILENAME: &str = "storage-template.ext4";

        // Check ~/.smolvm/ (installed location)
        if let Some(home) = dirs::home_dir() {
            let installed_path = home.join(".smolvm").join(TEMPLATE_FILENAME);
            if installed_path.exists() {
                tracing::debug!(path = %installed_path.display(), "found storage template");
                return Some(installed_path);
            }
        }

        // Check next to the current executable (development/testing)
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                let dev_path = exe_dir.join(TEMPLATE_FILENAME);
                if dev_path.exists() {
                    tracing::debug!(path = %dev_path.display(), "found storage template (dev)");
                    return Some(dev_path);
                }
            }
        }

        None
    }

    /// Copy the storage disk from a pre-formatted template.
    fn copy_from_template(&self, template_path: &Path) -> Result<()> {
        tracing::info!(
            template = %template_path.display(),
            target = %self.path.display(),
            "copying storage from template"
        );

        // Ensure parent directory exists
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::storage("create directory", e.to_string()))?;
        }

        // Copy the template file
        std::fs::copy(template_path, &self.path)
            .map_err(|e| Error::storage("copy template", e.to_string()))?;

        // Resize to the desired size (template is 512MB, we want 20GB)
        // This just extends the sparse file - doesn't use actual disk space
        use std::io::{Seek, SeekFrom, Write};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&self.path)
            .map_err(|e| Error::storage("open for resize", e.to_string()))?;

        file.seek(SeekFrom::Start(self.size_bytes - 1))
            .map_err(|e| Error::storage("seek for resize", e.to_string()))?;
        file.write_all(&[0])
            .map_err(|e| Error::storage("extend storage", e.to_string()))?;
        file.sync_all()
            .map_err(|e| Error::storage("sync storage", e.to_string()))?;

        // Filesystem resize happens inside the VM (guest runs resize2fs on boot).

        // Mark as formatted
        self.mark_formatted()?;

        tracing::info!(path = %self.path.display(), "storage copied from template");
        Ok(())
    }

    /// Format the disk using mkfs.ext4 (fallback when no template available).
    ///
    /// This is only used if the pre-formatted storage template is missing.
    /// Requires e2fsprogs to be installed on the host.
    fn format_with_mkfs(&self) -> Result<()> {
        tracing::info!(path = %self.path.display(), "formatting disk with mkfs.ext4");

        let mkfs_path = find_e2fsprogs_tool("mkfs.ext4").ok_or_else(|| {
            let hint = if Os::current().is_macos() {
                "On macOS, install with: brew install e2fsprogs"
            } else {
                "On Linux, install with: apt install e2fsprogs (or equivalent for your distro)"
            };
            Error::storage(
                "find mkfs.ext4",
                format!(
                    "mkfs.ext4 not found - required for storage disk formatting.\n  {}\n  \
                     After installing, run your smolvm command again.",
                    hint
                ),
            )
        })?;

        let path_str = self.path.to_str().ok_or_else(|| {
            Error::storage("validate path", "disk path contains invalid characters")
        })?;

        // Format with ext4 (-F = force, -q = quiet, -m 0 = no reserved blocks)
        let output = std::process::Command::new(mkfs_path)
            .args(["-F", "-q", "-m", "0", "-L", "smolvm", path_str])
            .output()
            .map_err(|e| Error::storage("run mkfs.ext4", e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::storage("format with mkfs.ext4", stderr.to_string()));
        }

        // Mark as formatted
        self.mark_formatted()?;

        tracing::info!(path = %self.path.display(), "disk formatted successfully");
        Ok(())
    }

    /// Get the path to the disk image.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Get the disk size in bytes.
    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    /// Get the disk size in GB.
    pub fn size_gb(&self) -> u64 {
        self.size_bytes / (1024 * 1024 * 1024)
    }

    /// Check if the disk needs to be formatted.
    ///
    /// This checks for a marker file that's created after formatting.
    /// Also validates that the disk appears to be valid ext4.
    pub fn needs_format(&self) -> bool {
        let marker_path = self.marker_path();

        // If marker doesn't exist, needs format
        if !marker_path.exists() {
            return true;
        }

        // If disk doesn't exist, needs format (and delete stale marker)
        if !self.path.exists() {
            let _ = std::fs::remove_file(&marker_path);
            return true;
        }

        // Validate disk appears to be ext4 (detect corruption)
        if !self.appears_valid_ext4() {
            tracing::warn!(
                path = %self.path.display(),
                "storage disk appears corrupt, will recreate"
            );
            // Delete corrupt disk and marker so we start fresh
            let _ = std::fs::remove_file(&self.path);
            let _ = std::fs::remove_file(&marker_path);
            return true;
        }

        false
    }

    /// Check if the disk file appears to be a valid ext4 filesystem.
    ///
    /// Uses the `file` command to check the magic bytes.
    /// This helps detect corrupted disks that would cause mount failures.
    fn appears_valid_ext4(&self) -> bool {
        // Use `file` command to check filesystem type
        let output = std::process::Command::new("file")
            .arg("-b") // Brief output
            .arg(&self.path)
            .output();

        match output {
            Ok(output) if output.status.success() => {
                let desc = String::from_utf8_lossy(&output.stdout);
                // Valid ext4 should contain "ext4 filesystem" or similar
                let is_ext4 =
                    desc.contains("ext4") || desc.contains("ext2") || desc.contains("ext3");
                if !is_ext4 {
                    tracing::debug!(
                        path = %self.path.display(),
                        file_type = %desc.trim(),
                        "storage disk is not ext4"
                    );
                }
                is_ext4
            }
            _ => {
                // If file command fails, assume it's okay (don't block on missing `file` command)
                tracing::debug!(path = %self.path.display(), "could not verify disk type, assuming valid");
                true
            }
        }
    }

    /// Mark the disk as formatted.
    ///
    /// This creates a marker file next to the disk image.
    pub fn mark_formatted(&self) -> Result<()> {
        let marker_path = self.marker_path();
        std::fs::write(&marker_path, "1")?;
        Ok(())
    }

    /// Get the path to the format marker file.
    fn marker_path(&self) -> PathBuf {
        self.path.with_extension("formatted")
    }

    /// Delete the storage disk and its marker.
    pub fn delete(&self) -> Result<()> {
        if self.path.exists() {
            std::fs::remove_file(&self.path)?;
        }
        let marker = self.marker_path();
        if marker.exists() {
            std::fs::remove_file(&marker)?;
        }
        Ok(())
    }
}

// ============================================================================
// Overlay Disk
// ============================================================================

/// Default size for the rootfs overlay disk (2 GB sparse).
pub const DEFAULT_OVERLAY_SIZE_GB: u64 = 2;

/// Overlay disk filename.
pub const OVERLAY_DISK_FILENAME: &str = "overlay.raw";

/// Persistent rootfs overlay disk.
///
/// A sparse ext4 disk image used as the upper layer of an overlayfs
/// on top of the initramfs. Changes to the root filesystem (e.g.,
/// `apk add git`) persist across VM reboots.
///
/// The overlay is set up by the agent's `setup_persistent_rootfs()`
/// function early in boot, before the vsock listener starts.
#[derive(Debug, Clone)]
pub struct OverlayDisk {
    /// Path to the disk image file.
    path: PathBuf,
    /// Size in bytes.
    #[allow(dead_code)]
    size_bytes: u64,
}

impl OverlayDisk {
    /// Open or create the overlay disk at a custom path.
    pub fn open_or_create_at(path: &Path, size_gb: u64) -> Result<Self> {
        if size_gb == 0 {
            return Err(Error::config(
                "validate overlay size",
                "disk size must be greater than 0 GB",
            ));
        }

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let size_bytes = size_gb * 1024 * 1024 * 1024;

        if path.exists() {
            let metadata = std::fs::metadata(path)?;
            Ok(Self {
                path: path.to_path_buf(),
                size_bytes: metadata.len(),
            })
        } else {
            // Create sparse disk image
            Self::create_sparse(path, size_bytes)?;
            Ok(Self {
                path: path.to_path_buf(),
                size_bytes,
            })
        }
    }

    /// Create a sparse disk image.
    fn create_sparse(path: &Path, size_bytes: u64) -> Result<()> {
        use std::fs::OpenOptions;
        use std::io::{Seek, SeekFrom, Write};

        assert!(size_bytes > 0, "disk size must be greater than 0");

        tracing::info!(
            path = %path.display(),
            size_gb = size_bytes / (1024 * 1024 * 1024),
            "creating sparse overlay disk"
        );

        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        file.seek(SeekFrom::Start(size_bytes - 1))?;
        file.write_all(&[0])?;
        file.sync_all()?;

        Ok(())
    }

    /// Pre-format the overlay disk with ext4 on the host.
    ///
    /// Tries template copy first (fast, no dependencies), then falls back
    /// to mkfs.ext4 (requires e2fsprogs).
    pub fn ensure_formatted(&self) -> Result<()> {
        if !self.needs_format() {
            tracing::debug!(path = %self.path.display(), "overlay disk already formatted");
            return Ok(());
        }

        // Try to copy from pre-formatted template first (no dependencies)
        if let Some(template_path) = Self::find_overlay_template() {
            return self.copy_from_template(&template_path);
        }

        // Fall back to formatting with mkfs.ext4
        self.format_with_mkfs()
    }

    /// Find the pre-formatted overlay template.
    ///
    /// Searches in order:
    /// 1. ~/.smolvm/overlay-template.ext4 (installed location)
    /// 2. Next to the current executable (development)
    fn find_overlay_template() -> Option<PathBuf> {
        const TEMPLATE_FILENAME: &str = "overlay-template.ext4";

        // Check ~/.smolvm/ (installed location)
        if let Some(home) = dirs::home_dir() {
            let installed_path = home.join(".smolvm").join(TEMPLATE_FILENAME);
            if installed_path.exists() {
                tracing::debug!(path = %installed_path.display(), "found overlay template");
                return Some(installed_path);
            }
        }

        // Check next to the current executable (development/testing)
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                let dev_path = exe_dir.join(TEMPLATE_FILENAME);
                if dev_path.exists() {
                    tracing::debug!(path = %dev_path.display(), "found overlay template (dev)");
                    return Some(dev_path);
                }
            }
        }

        None
    }

    /// Copy the overlay disk from a pre-formatted template.
    fn copy_from_template(&self, template_path: &Path) -> Result<()> {
        tracing::info!(
            template = %template_path.display(),
            target = %self.path.display(),
            "copying overlay from template"
        );

        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::storage("create directory", e.to_string()))?;
        }

        std::fs::copy(template_path, &self.path)
            .map_err(|e| Error::storage("copy overlay template", e.to_string()))?;

        // Resize to the desired size (template may be smaller)
        use std::io::{Seek, SeekFrom, Write};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&self.path)
            .map_err(|e| Error::storage("open overlay for resize", e.to_string()))?;

        file.seek(SeekFrom::Start(self.size_bytes - 1))
            .map_err(|e| Error::storage("seek overlay for resize", e.to_string()))?;
        file.write_all(&[0])
            .map_err(|e| Error::storage("extend overlay", e.to_string()))?;
        file.sync_all()
            .map_err(|e| Error::storage("sync overlay", e.to_string()))?;

        self.mark_formatted()?;

        tracing::info!(path = %self.path.display(), "overlay copied from template");
        Ok(())
    }

    /// Format the disk using mkfs.ext4.
    fn format_with_mkfs(&self) -> Result<()> {
        tracing::info!(path = %self.path.display(), "formatting overlay disk with mkfs.ext4");

        let mkfs_path = find_e2fsprogs_tool("mkfs.ext4").ok_or_else(|| {
            let hint = if crate::platform::Os::current().is_macos() {
                "On macOS, install with: brew install e2fsprogs"
            } else {
                "On Linux, install with: apt install e2fsprogs (or equivalent)"
            };
            Error::storage(
                "find mkfs.ext4",
                format!(
                    "mkfs.ext4 not found - required for overlay disk formatting.\n  {}",
                    hint
                ),
            )
        })?;

        let path_str = self.path.to_str().ok_or_else(|| {
            Error::storage(
                "validate path",
                "overlay disk path contains invalid characters",
            )
        })?;

        let output = std::process::Command::new(mkfs_path)
            .args(["-F", "-q", "-m", "0", "-L", "smolvm-overlay", path_str])
            .output()
            .map_err(|e| Error::storage("run mkfs.ext4", e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::storage(
                "format overlay with mkfs.ext4",
                stderr.to_string(),
            ));
        }

        self.mark_formatted()?;

        tracing::info!(path = %self.path.display(), "overlay disk formatted successfully");
        Ok(())
    }

    /// Get the path to the disk image.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Check if the disk needs to be formatted.
    fn needs_format(&self) -> bool {
        let marker_path = self.marker_path();
        if !marker_path.exists() {
            return true;
        }
        if !self.path.exists() {
            let _ = std::fs::remove_file(&marker_path);
            return true;
        }

        // Validate disk appears to be ext4 (detect corruption)
        if !self.appears_valid_ext4() {
            tracing::warn!(
                path = %self.path.display(),
                "overlay disk appears corrupt, will reformat"
            );
            let _ = std::fs::remove_file(&self.path);
            let _ = std::fs::remove_file(&marker_path);
            return true;
        }

        false
    }

    /// Check if the disk file appears to be a valid ext4 filesystem.
    fn appears_valid_ext4(&self) -> bool {
        let output = std::process::Command::new("file")
            .arg("-b")
            .arg(&self.path)
            .output();

        match output {
            Ok(output) if output.status.success() => {
                let desc = String::from_utf8_lossy(&output.stdout);
                desc.contains("ext4") || desc.contains("ext2") || desc.contains("ext3")
            }
            _ => true, // If `file` command unavailable, assume valid
        }
    }

    /// Mark the disk as formatted.
    fn mark_formatted(&self) -> Result<()> {
        std::fs::write(self.marker_path(), "1")?;
        Ok(())
    }

    /// Get the path to the format marker file.
    fn marker_path(&self) -> PathBuf {
        self.path.with_extension("formatted")
    }

    /// Delete the overlay disk and its marker.
    pub fn delete(&self) -> Result<()> {
        if self.path.exists() {
            std::fs::remove_file(&self.path)?;
        }
        let marker = self.marker_path();
        if marker.exists() {
            std::fs::remove_file(&marker)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disk_version_compatibility() {
        // Important for migration safety
        let version = DiskVersion::new("sha256:abc123");
        assert!(version.is_compatible());

        let future_version = DiskVersion {
            format_version: 999,
            created_at: "0".to_string(),
            base_digest: "sha256:abc123".to_string(),
            smolvm_version: "99.0.0".to_string(),
        };
        assert!(!future_version.is_compatible());
    }

    #[test]
    fn test_disk_version_serialization() {
        let version = DiskVersion::new("sha256:abc123");
        let json = serde_json::to_string(&version).unwrap();
        let deserialized: DiskVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.format_version, version.format_version);
        assert_eq!(deserialized.base_digest, version.base_digest);
    }

    #[test]
    fn test_storage_disk_create_and_delete() {
        let temp_dir = std::env::temp_dir().join("smolvm_test_basic");
        std::fs::create_dir_all(&temp_dir).unwrap();
        let disk_path = temp_dir.join("test_storage.raw");

        // Clean up any existing file
        let _ = std::fs::remove_file(&disk_path);
        let _ = std::fs::remove_file(disk_path.with_extension("formatted"));

        // Create a small disk for testing (1 GB)
        let disk = StorageDisk::open_or_create_at(&disk_path, 1).unwrap();

        assert!(disk_path.exists());
        assert_eq!(disk.size_gb(), 1);
        assert!(disk.needs_format());

        // Write ext4 magic bytes so the disk appears valid
        // ext4 superblock is at offset 1024, magic (0xEF53) is at offset 56 within superblock
        write_ext4_magic(&disk_path);

        // Mark as formatted
        disk.mark_formatted().unwrap();
        assert!(!disk.needs_format()); // Should pass now that disk has ext4 magic

        // Delete disk
        disk.delete().unwrap();
        assert!(!disk_path.exists());

        // Clean up temp dir
        let _ = std::fs::remove_dir(&temp_dir);
    }

    #[test]
    fn test_corruption_detection() {
        let temp_dir = std::env::temp_dir().join("smolvm_test_corrupt");
        std::fs::create_dir_all(&temp_dir).unwrap();
        let disk_path = temp_dir.join("corrupt_storage.raw");
        let marker_path = disk_path.with_extension("formatted");

        // Clean up any existing files
        let _ = std::fs::remove_file(&disk_path);
        let _ = std::fs::remove_file(&marker_path);

        // Create disk and mark as formatted (simulating previous successful run)
        let disk = StorageDisk::open_or_create_at(&disk_path, 1).unwrap();
        write_ext4_magic(&disk_path);
        disk.mark_formatted().unwrap();

        // Verify it's recognized as valid
        assert!(!disk.needs_format());
        assert!(disk.appears_valid_ext4());

        // Now corrupt the disk by zeroing the magic bytes
        corrupt_ext4_magic(&disk_path);

        // Create a new disk handle to check corruption detection
        let disk2 = StorageDisk::open_or_create_at(&disk_path, 1).unwrap();

        // Should detect corruption and need reformatting
        assert!(!disk2.appears_valid_ext4());
        assert!(disk2.needs_format()); // This should delete the corrupt disk

        // Verify corrupt disk was deleted
        assert!(!disk_path.exists());
        assert!(!marker_path.exists());

        // Clean up temp dir
        let _ = std::fs::remove_dir(&temp_dir);
    }

    /// Write ext4 magic bytes to make `file` command recognize it as ext4.
    /// ext4 superblock is at offset 1024, magic number 0xEF53 is at offset 56.
    fn write_ext4_magic(path: &std::path::Path) {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = std::fs::OpenOptions::new().write(true).open(path).unwrap();

        // Seek to superblock magic offset (1024 + 56 = 1080)
        file.seek(SeekFrom::Start(1080)).unwrap();
        // Write ext4 magic: 0xEF53 (little-endian: 0x53, 0xEF)
        file.write_all(&[0x53, 0xEF]).unwrap();
        file.sync_all().unwrap();
    }

    /// Corrupt the ext4 magic bytes by zeroing them.
    fn corrupt_ext4_magic(path: &std::path::Path) {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = std::fs::OpenOptions::new().write(true).open(path).unwrap();

        // Seek to superblock magic offset and zero it
        file.seek(SeekFrom::Start(1080)).unwrap();
        file.write_all(&[0x00, 0x00]).unwrap();
        file.sync_all().unwrap();
    }

    #[test]
    fn test_overlay_disk_create_and_delete() {
        let temp_dir = std::env::temp_dir().join("smolvm_test_overlay");
        std::fs::create_dir_all(&temp_dir).unwrap();
        let disk_path = temp_dir.join("test_overlay.raw");

        // Clean up any existing file
        let _ = std::fs::remove_file(&disk_path);
        let _ = std::fs::remove_file(disk_path.with_extension("formatted"));

        // Create overlay disk (1 GB for testing)
        let disk = OverlayDisk::open_or_create_at(&disk_path, 1).unwrap();

        assert!(disk_path.exists());
        assert!(disk.needs_format());

        // Write ext4 magic so appears_valid_ext4() passes
        write_ext4_magic(&disk_path);

        // Mark as formatted
        disk.mark_formatted().unwrap();
        assert!(!disk.needs_format());

        // Delete disk
        disk.delete().unwrap();
        assert!(!disk_path.exists());

        // Clean up temp dir
        let _ = std::fs::remove_dir(&temp_dir);
    }

    #[test]
    fn test_overlay_disk_zero_size_rejected() {
        let temp_dir = std::env::temp_dir().join("smolvm_test_overlay_zero");
        let disk_path = temp_dir.join("zero_overlay.raw");
        assert!(OverlayDisk::open_or_create_at(&disk_path, 0).is_err());
    }

    #[test]
    fn test_overlay_disk_ensure_formatted() {
        // Skip if mkfs.ext4 is not available (CI without e2fsprogs)
        if find_e2fsprogs_tool("mkfs.ext4").is_none() {
            eprintln!("skipping test_overlay_disk_ensure_formatted: mkfs.ext4 not found");
            return;
        }

        let temp_dir = std::env::temp_dir().join("smolvm_test_overlay_fmt");
        std::fs::create_dir_all(&temp_dir).unwrap();
        let disk_path = temp_dir.join("fmt_overlay.raw");

        // Clean up any existing files
        let _ = std::fs::remove_file(&disk_path);
        let _ = std::fs::remove_file(disk_path.with_extension("formatted"));

        // Create overlay disk (1 GB sparse)
        let disk = OverlayDisk::open_or_create_at(&disk_path, 1).unwrap();
        assert!(disk.needs_format());

        // Format it — this calls mkfs.ext4 for real
        disk.ensure_formatted().unwrap();
        assert!(!disk.needs_format());

        // Calling ensure_formatted again should be a no-op
        disk.ensure_formatted().unwrap();

        // Clean up
        disk.delete().unwrap();
        assert!(!disk_path.exists());
        let _ = std::fs::remove_dir(&temp_dir);
    }
}
