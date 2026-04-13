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

use crate::data::consts::BYTES_PER_GIB;
pub use crate::data::disk::{DiskType, Overlay, Storage};
pub use crate::data::storage::{
    DEFAULT_OVERLAY_SIZE_GIB, DEFAULT_STORAGE_SIZE_GIB, OVERLAY_DISK_FILENAME,
    STORAGE_DISK_FILENAME,
};
use crate::disk_utils;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

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

/// Shared disk implementation for storage and overlay disks.
#[derive(Debug, Clone)]
pub struct VmDisk<K> {
    path: PathBuf,
    size_bytes: u64,
    _kind: PhantomData<K>,
}

impl<K: DiskType> VmDisk<K> {
    /// Get the default path for the disk.
    pub fn default_path() -> Result<PathBuf> {
        let data_dir = dirs::data_local_dir()
            .or_else(dirs::data_dir)
            .ok_or_else(|| {
                Error::storage(
                    format!("resolve {} path", K::NAME),
                    "could not determine data directory",
                )
            })?;

        Ok(data_dir.join("smolvm").join(K::DEFAULT_FILENAME))
    }

    /// Open or create the disk of the default size at the default location.
    pub fn open_or_create() -> Result<Self> {
        let path = Self::default_path()?;
        Self::open_or_create_at(&path, K::DEFAULT_SIZE_GIB)
    }

    /// Open or create the disk of the custom size at a custom path.
    pub fn open_or_create_at(path: &Path, size_gb: u64) -> Result<Self> {
        if size_gb == 0 {
            return Err(Error::config(
                format!("validate {} size", K::NAME),
                "disk size must be greater than 0 GiB",
            ));
        }

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let size_bytes = size_gb * BYTES_PER_GIB;

        if path.exists() {
            let metadata = std::fs::metadata(path)?;
            Ok(Self {
                path: path.to_path_buf(),
                size_bytes: metadata.len(),
                _kind: PhantomData,
            })
        } else {
            disk_utils::create_sparse_disk::<K>(path, size_bytes)?;
            Ok(Self {
                path: path.to_path_buf(),
                size_bytes,
                _kind: PhantomData,
            })
        }
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
            tracing::debug!(
                path = %self.path.display(),
                disk_type = K::NAME,
                "disk already formatted"
            );
            return Ok(());
        }

        if let Some(template_path) = Self::template_path() {
            disk_utils::copy_disk_from_template::<K>(&self.path, self.size_bytes, &template_path)?;
        } else {
            disk_utils::format_disk_with_mkfs::<K>(&self.path)?;
        }

        self.mark_formatted()
    }

    /// Get the path to the disk image.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Get the disk size in bytes.
    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    /// Get the disk size in GiB.
    pub fn size_gib(&self) -> u64 {
        self.size_bytes / BYTES_PER_GIB
    }

    /// Check if the disk needs to be formatted.
    ///
    /// Fast path: if the format marker and the disk file both exist, the disk
    /// was formatted successfully, so skip the expensive `file` command check.
    pub fn needs_format(&self) -> bool {
        if !self.disk_marker_path().exists() {
            return true;
        }

        if !self.path.exists() {
            let marker_path = self.disk_marker_path();
            if let Err(error) = std::fs::remove_file(&marker_path) {
                tracing::warn!(
                    path = %marker_path.display(),
                    disk_type = K::NAME,
                    %error,
                    "failed to remove stale disk marker"
                );
            }
            return true;
        }

        false
    }

    /// Mark a disk as formatted by creating its marker file.
    pub fn mark_formatted(&self) -> Result<()> {
        std::fs::write(self.disk_marker_path(), "1")?;
        Ok(())
    }

    /// Delete a disk image and its marker file.
    pub fn delete(&self) -> Result<()> {
        if self.path.exists() {
            std::fs::remove_file(&self.path)?;
        }

        let marker_path = self.disk_marker_path();
        if marker_path.exists() {
            std::fs::remove_file(marker_path)?;
        }
        Ok(())
    }

    /// Find a pre-formatted disk template.
    ///
    /// Searches in order:
    /// 1. `~/.smolvm/{filename}` (installed location)
    /// 2. Next to the current executable (development)
    fn template_path() -> Option<PathBuf> {
        if let Some(home) = dirs::home_dir() {
            let installed_path = home.join(".smolvm").join(K::TEMPLATE_FILENAME);
            if installed_path.exists() {
                tracing::debug!(
                    path = %installed_path.display(),
                    disk_type = K::NAME,
                    "found disk template"
                );
                return Some(installed_path);
            }
        }

        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                let dev_path = exe_dir.join(K::TEMPLATE_FILENAME);
                if dev_path.exists() {
                    tracing::debug!(
                        path = %dev_path.display(),
                        disk_type = K::NAME,
                        "found disk template (dev)"
                    );
                    return Some(dev_path);
                }
            }
        }

        None
    }

    /// Get the path to the format marker file for a disk.
    fn disk_marker_path(&self) -> PathBuf {
        self.path.with_extension("formatted")
    }
}

impl VmDisk<Storage> {
    /// Open or create the storage disk at the default location with a custom size.
    pub fn open_or_create_with_size(size_gb: u64) -> Result<Self> {
        let path = Self::default_path()?;
        Self::open_or_create_at(&path, size_gb)
    }
}

// ============================================================================
// Storage Disk
// ============================================================================

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
pub type StorageDisk = VmDisk<Storage>;

// ============================================================================
// Overlay Disk
// ============================================================================

/// Persistent rootfs overlay disk.
///
/// A sparse ext4 disk image used as the upper layer of an overlayfs
/// on top of the initramfs. Changes to the root filesystem (e.g.,
/// `apk add git`) persist across VM reboots.
///
/// The overlay is set up by the agent's `setup_persistent_rootfs()`
/// function early in boot, before the vsock listener starts.
pub type OverlayDisk = VmDisk<Overlay>;

/// Expand a disk image at an arbitrary path for a specific disk type.
pub fn expand_disk<D: DiskType>(path: &Path, new_size_gb: u64) -> Result<()> {
    disk_utils::expand_sparse_disk::<D>(path, new_size_gb)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disk_version_compatibility() {
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

        let _ = std::fs::remove_file(&disk_path);
        let _ = std::fs::remove_file(disk_path.with_extension("formatted"));

        let disk = StorageDisk::open_or_create_at(&disk_path, 1).unwrap();

        assert!(disk_path.exists());
        assert_eq!(disk.size_gib(), 1);
        assert!(disk.needs_format());

        write_ext4_magic(&disk_path);

        disk.mark_formatted().unwrap();
        assert!(!disk.needs_format());

        disk.delete().unwrap();
        assert!(!disk_path.exists());

        let _ = std::fs::remove_dir(&temp_dir);
    }

    #[test]
    fn test_default_paths_use_expected_filenames() {
        assert_eq!(
            StorageDisk::default_path().unwrap().file_name().unwrap(),
            STORAGE_DISK_FILENAME
        );
        assert_eq!(
            OverlayDisk::default_path().unwrap().file_name().unwrap(),
            OVERLAY_DISK_FILENAME
        );
    }

    #[test]
    fn test_corruption_detection() {
        let temp_dir = std::env::temp_dir().join("smolvm_test_corrupt");
        std::fs::create_dir_all(&temp_dir).unwrap();
        let disk_path = temp_dir.join("corrupt_storage.raw");
        let marker_path = disk_path.with_extension("formatted");

        let _ = std::fs::remove_file(&disk_path);
        let _ = std::fs::remove_file(&marker_path);

        let disk = StorageDisk::open_or_create_at(&disk_path, 1).unwrap();
        write_ext4_magic(&disk_path);
        disk.mark_formatted().unwrap();

        assert!(!disk.needs_format());
        assert!(disk_appears_valid_ext4(&disk_path));

        corrupt_ext4_magic(&disk_path);

        assert!(!disk_appears_valid_ext4(&disk_path));

        let disk2 = StorageDisk::open_or_create_at(&disk_path, 1).unwrap();
        assert!(!disk2.needs_format());

        let _ = std::fs::remove_file(&disk_path);
        assert!(disk2.needs_format());
        assert!(!marker_path.exists());

        let _ = std::fs::remove_dir(&temp_dir);
    }

    #[test]
    fn test_overlay_disk_create_and_delete() {
        let temp_dir = std::env::temp_dir().join("smolvm_test_overlay");
        std::fs::create_dir_all(&temp_dir).unwrap();
        let disk_path = temp_dir.join("test_overlay.raw");

        let _ = std::fs::remove_file(&disk_path);
        let _ = std::fs::remove_file(disk_path.with_extension("formatted"));

        let disk = OverlayDisk::open_or_create_at(&disk_path, 1).unwrap();

        assert!(disk_path.exists());
        assert!(disk.needs_format());

        write_ext4_magic(&disk_path);

        disk.mark_formatted().unwrap();
        assert!(!disk.needs_format());

        disk.delete().unwrap();
        assert!(!disk_path.exists());

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
        if disk_utils::find_e2fsprogs_tool("mkfs.ext4").is_none() {
            eprintln!("skipping test_overlay_disk_ensure_formatted: mkfs.ext4 not found");
            return;
        }

        let temp_dir = std::env::temp_dir().join("smolvm_test_overlay_fmt");
        std::fs::create_dir_all(&temp_dir).unwrap();
        let disk_path = temp_dir.join("fmt_overlay.raw");

        let _ = std::fs::remove_file(&disk_path);
        let _ = std::fs::remove_file(disk_path.with_extension("formatted"));

        let disk = OverlayDisk::open_or_create_at(&disk_path, 1).unwrap();
        assert!(disk.needs_format());

        disk.ensure_formatted().unwrap();
        assert!(!disk.needs_format());

        disk.ensure_formatted().unwrap();

        disk.delete().unwrap();
        assert!(!disk_path.exists());
        let _ = std::fs::remove_dir(&temp_dir);
    }

    #[test]
    fn test_typed_expand_updates_cached_size() {
        let temp_dir = std::env::temp_dir().join("smolvm_test_typed_expand");
        std::fs::create_dir_all(&temp_dir).unwrap();
        let disk_path = temp_dir.join("typed_expand_test.raw");

        let _ = std::fs::remove_file(&disk_path);

        let _disk = StorageDisk::open_or_create_at(&disk_path, 1).unwrap();
        expand_disk::<Storage>(&disk_path, 2).unwrap();

        let disk = StorageDisk::open_or_create_at(&disk_path, 2).unwrap();
        assert_eq!(disk.size_gib(), 2);
        let metadata = std::fs::metadata(&disk_path).unwrap();
        assert_eq!(metadata.len(), 2 * BYTES_PER_GIB);

        let _ = std::fs::remove_file(&disk_path);
        let _ = std::fs::remove_dir(&temp_dir);
    }

    #[test]
    fn test_expand_disk_basic() {
        let temp_dir = std::env::temp_dir().join("smolvm_test_expand");
        std::fs::create_dir_all(&temp_dir).unwrap();
        let disk_path = temp_dir.join("expand_test.raw");

        let _ = std::fs::remove_file(&disk_path);

        let initial_size = BYTES_PER_GIB;
        disk_utils::create_sparse_disk::<Storage>(&disk_path, initial_size).unwrap();

        let metadata = std::fs::metadata(&disk_path).unwrap();
        assert_eq!(metadata.len(), initial_size);

        expand_disk::<Storage>(&disk_path, 2).unwrap();

        let metadata = std::fs::metadata(&disk_path).unwrap();
        assert_eq!(metadata.len(), 2 * BYTES_PER_GIB);

        let _ = std::fs::remove_file(&disk_path);
        let _ = std::fs::remove_dir(&temp_dir);
    }

    #[test]
    fn test_expand_disk_reject_shrink() {
        let temp_dir = std::env::temp_dir().join("smolvm_test_shrink");
        std::fs::create_dir_all(&temp_dir).unwrap();
        let disk_path = temp_dir.join("shrink_test.raw");

        let _ = std::fs::remove_file(&disk_path);

        let initial_size = 10 * BYTES_PER_GIB;
        disk_utils::create_sparse_disk::<Storage>(&disk_path, initial_size).unwrap();

        let result = expand_disk::<Storage>(&disk_path, 5);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("must be larger"));

        let metadata = std::fs::metadata(&disk_path).unwrap();
        assert_eq!(metadata.len(), initial_size);

        let _ = std::fs::remove_file(&disk_path);
        let _ = std::fs::remove_dir(&temp_dir);
    }

    #[test]
    fn test_expand_disk_same_size_rejected() {
        let temp_dir = std::env::temp_dir().join("smolvm_test_same");
        std::fs::create_dir_all(&temp_dir).unwrap();
        let disk_path = temp_dir.join("same_test.raw");

        let _ = std::fs::remove_file(&disk_path);

        let initial_size = 10 * BYTES_PER_GIB;
        disk_utils::create_sparse_disk::<Storage>(&disk_path, initial_size).unwrap();

        let result = expand_disk::<Storage>(&disk_path, 10);
        assert!(result.is_err());

        let _ = std::fs::remove_file(&disk_path);
        let _ = std::fs::remove_dir(&temp_dir);
    }

    /// Write ext4 magic bytes to make `file` command recognize it as ext4.
    /// ext4 superblock is at offset 1024, magic number 0xEF53 is at offset 56.
    fn write_ext4_magic(path: &std::path::Path) {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = std::fs::OpenOptions::new().write(true).open(path).unwrap();

        file.seek(SeekFrom::Start(1080)).unwrap();
        file.write_all(&[0x53, 0xEF]).unwrap();
        file.sync_all().unwrap();
    }

    /// Corrupt the ext4 magic bytes by zeroing them.
    fn corrupt_ext4_magic(path: &std::path::Path) {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = std::fs::OpenOptions::new().write(true).open(path).unwrap();

        file.seek(SeekFrom::Start(1080)).unwrap();
        file.write_all(&[0x00, 0x00]).unwrap();
        file.sync_all().unwrap();
    }

    /// Check if a disk file appears to be a valid ext4 filesystem.
    fn disk_appears_valid_ext4(disk_path: &Path) -> bool {
        let output = std::process::Command::new("file")
            .arg("-b")
            .arg(disk_path)
            .output();

        match output {
            Ok(output) if output.status.success() => {
                let desc = String::from_utf8_lossy(&output.stdout);
                let is_ext4 =
                    desc.contains("ext4") || desc.contains("ext2") || desc.contains("ext3");
                if !is_ext4 {
                    tracing::debug!(
                        path = %disk_path.display(),
                        file_type = %desc.trim(),
                        "disk is not ext4"
                    );
                }
                is_ext4
            }
            _ => {
                tracing::debug!(path = %disk_path.display(), "could not verify disk type, assuming valid");
                true
            }
        }
    }
}
