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

// ============================================================================
// Shared ext4 disk operations
// ============================================================================

/// Create a sparse disk image file.
fn create_sparse_disk(path: &Path, size_bytes: u64, label: &str) -> Result<()> {
    use std::fs::OpenOptions;
    use std::io::{Seek, SeekFrom, Write};

    assert!(size_bytes > 0, "disk size must be greater than 0");

    tracing::info!(path = %path.display(), size_gb = size_bytes / (1024*1024*1024), "creating sparse {} disk", label);

    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.seek(SeekFrom::Start(size_bytes - 1))?;
    file.write_all(&[0])?;

    Ok(())
}

/// Find a pre-formatted disk template by filename.
///
/// Searches in order:
/// 1. `~/.smolvm/{filename}` (installed location)
/// 2. Next to the current executable (development)
fn find_disk_template(template_filename: &str) -> Option<PathBuf> {
    if let Some(home) = dirs::home_dir() {
        let installed_path = home.join(".smolvm").join(template_filename);
        if installed_path.exists() {
            tracing::debug!(path = %installed_path.display(), "found disk template");
            return Some(installed_path);
        }
    }

    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let dev_path = exe_dir.join(template_filename);
            if dev_path.exists() {
                tracing::debug!(path = %dev_path.display(), "found disk template (dev)");
                return Some(dev_path);
            }
        }
    }

    None
}

/// Copy a disk from a pre-formatted template, resizing to target size.
///
/// On macOS, uses `clonefile()` for instant APFS copy-on-write cloning.
/// On Linux, falls back to `fs::copy` (which uses `copy_file_range` for
/// sparse-aware copying on supported filesystems).
fn copy_disk_from_template(
    disk_path: &Path,
    size_bytes: u64,
    template_path: &Path,
    label: &str,
) -> Result<()> {
    tracing::info!(
        template = %template_path.display(),
        target = %disk_path.display(),
        "copying {} from template", label
    );

    if let Some(parent) = disk_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::storage("create directory", e.to_string()))?;
    }

    clone_or_copy_file(template_path, disk_path)?;

    // Resize to the desired size (template may be smaller than target)
    use std::io::{Seek, SeekFrom, Write};
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(disk_path)
        .map_err(|e| Error::storage("open for resize", e.to_string()))?;

    file.seek(SeekFrom::Start(size_bytes - 1))
        .map_err(|e| Error::storage("seek for resize", e.to_string()))?;
    file.write_all(&[0])
        .map_err(|e| Error::storage("extend disk", e.to_string()))?;

    // Filesystem resize happens inside the VM (guest runs resize2fs on boot).

    mark_disk_formatted(disk_path)?;

    tracing::info!(path = %disk_path.display(), "{} copied from template", label);
    Ok(())
}

/// Clone a file using platform-optimal method.
///
/// - macOS: `clonefile()` for instant APFS copy-on-write (falls back to `fs::copy`)
/// - Linux: `fs::copy` (uses `copy_file_range` for sparse-aware copy)
fn clone_or_copy_file(src: &Path, dst: &Path) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        use std::ffi::CString;

        // clonefile(2) requires the destination to not exist
        if dst.exists() {
            let _ = std::fs::remove_file(dst);
        }

        let src_c = CString::new(src.to_string_lossy().as_bytes())
            .map_err(|e| Error::storage("clonefile src path", e.to_string()))?;
        let dst_c = CString::new(dst.to_string_lossy().as_bytes())
            .map_err(|e| Error::storage("clonefile dst path", e.to_string()))?;

        // clonefile(2): instant APFS copy-on-write clone
        let ret = unsafe { libc::clonefile(src_c.as_ptr(), dst_c.as_ptr(), 0) };
        if ret == 0 {
            tracing::debug!(src = %src.display(), dst = %dst.display(), "clonefile succeeded");
            return Ok(());
        }

        // Fall back to regular copy if clonefile fails (e.g., non-APFS filesystem)
        tracing::debug!(
            src = %src.display(),
            errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
            "clonefile failed, falling back to fs::copy"
        );
    }

    std::fs::copy(src, dst).map_err(|e| Error::storage("copy template", e.to_string()))?;
    Ok(())
}

/// Format a disk with mkfs.ext4 (requires e2fsprogs).
fn format_disk_with_mkfs(disk_path: &Path, volume_label: &str, label: &str) -> Result<()> {
    tracing::info!(path = %disk_path.display(), "formatting {} disk with mkfs.ext4", label);

    let mkfs_path = find_e2fsprogs_tool("mkfs.ext4").ok_or_else(|| {
        let hint = if Os::current().is_macos() {
            "On macOS, install with: brew install e2fsprogs"
        } else {
            "On Linux, install with: apt install e2fsprogs (or equivalent)"
        };
        Error::storage(
            "find mkfs.ext4",
            format!(
                "mkfs.ext4 not found - required for {} disk formatting.\n  {}",
                label, hint
            ),
        )
    })?;

    let path_str = disk_path
        .to_str()
        .ok_or_else(|| Error::storage("validate path", "disk path contains invalid characters"))?;

    let output = std::process::Command::new(mkfs_path)
        .args([
            "-F",
            "-q",
            "-m",
            "0",
            "-O",
            "^has_journal",
            "-L",
            volume_label,
            path_str,
        ])
        .output()
        .map_err(|e| Error::storage("run mkfs.ext4", e.to_string()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::storage("format with mkfs.ext4", stderr.to_string()));
    }

    mark_disk_formatted(disk_path)?;

    tracing::info!(path = %disk_path.display(), "{} disk formatted successfully", label);
    Ok(())
}

/// Check if a disk file appears to be a valid ext4 filesystem.
/// Used in tests; removed from hot path to avoid spawning `file` command on every start.
#[cfg(test)]
fn disk_appears_valid_ext4(disk_path: &Path) -> bool {
    let output = std::process::Command::new("file")
        .arg("-b")
        .arg(disk_path)
        .output();

    match output {
        Ok(output) if output.status.success() => {
            let desc = String::from_utf8_lossy(&output.stdout);
            let is_ext4 = desc.contains("ext4") || desc.contains("ext2") || desc.contains("ext3");
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

/// Check if a disk needs to be formatted.
///
/// Fast path: if the format marker AND the disk file both exist, the disk
/// was formatted successfully — skip the expensive `file` command validation.
/// The marker is only created after successful mkfs.ext4 completion.
fn disk_needs_format(disk_path: &Path, _label: &str) -> bool {
    let marker_path = disk_marker_path(disk_path);

    if !marker_path.exists() {
        return true;
    }

    if !disk_path.exists() {
        // Marker exists but disk is gone — stale marker
        let _ = std::fs::remove_file(&marker_path);
        return true;
    }

    // Both marker and disk exist — disk was formatted successfully.
    // Skip spawning `file` command (~10ms) on every restart.
    false
}

/// Get the path to the format marker file for a disk.
fn disk_marker_path(disk_path: &Path) -> PathBuf {
    disk_path.with_extension("formatted")
}

/// Mark a disk as formatted by creating its marker file.
fn mark_disk_formatted(disk_path: &Path) -> Result<()> {
    std::fs::write(disk_marker_path(disk_path), "1")?;
    Ok(())
}

/// Delete a disk image and its marker file.
fn delete_disk_and_marker(disk_path: &Path) -> Result<()> {
    if disk_path.exists() {
        std::fs::remove_file(disk_path)?;
    }
    let marker = disk_marker_path(disk_path);
    if marker.exists() {
        std::fs::remove_file(&marker)?;
    }
    Ok(())
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

    fn create_sparse(path: &Path, size_bytes: u64) -> Result<()> {
        create_sparse_disk(path, size_bytes, "storage")
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
        if let Some(template_path) = find_disk_template("storage-template.ext4") {
            return copy_disk_from_template(&self.path, self.size_bytes, &template_path, "storage");
        }
        format_disk_with_mkfs(&self.path, "smolvm", "storage")
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
    pub fn needs_format(&self) -> bool {
        disk_needs_format(&self.path, "storage")
    }

    /// Mark the disk as formatted.
    pub fn mark_formatted(&self) -> Result<()> {
        mark_disk_formatted(&self.path)
    }

    /// Delete the storage disk and its marker.
    pub fn delete(&self) -> Result<()> {
        delete_disk_and_marker(&self.path)
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

    fn create_sparse(path: &Path, size_bytes: u64) -> Result<()> {
        create_sparse_disk(path, size_bytes, "overlay")
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
        if let Some(template_path) = find_disk_template("overlay-template.ext4") {
            return copy_disk_from_template(&self.path, self.size_bytes, &template_path, "overlay");
        }
        format_disk_with_mkfs(&self.path, "smolvm-overlay", "overlay")
    }

    /// Get the path to the disk image.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Check if the disk needs to be formatted.
    fn needs_format(&self) -> bool {
        disk_needs_format(&self.path, "overlay")
    }

    /// Delete the overlay disk and its marker.
    pub fn delete(&self) -> Result<()> {
        delete_disk_and_marker(&self.path)
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
        assert!(disk_appears_valid_ext4(&disk_path));

        // Now corrupt the disk by zeroing the magic bytes
        corrupt_ext4_magic(&disk_path);

        // disk_appears_valid_ext4 catches corruption via `file` command
        assert!(!disk_appears_valid_ext4(&disk_path));

        // But needs_format trusts the marker file for performance (avoids
        // spawning `file` on every start). Marker + disk present = no reformat.
        let disk2 = StorageDisk::open_or_create_at(&disk_path, 1).unwrap();
        assert!(!disk2.needs_format());

        // Stale marker (disk deleted) should be detected
        let _ = std::fs::remove_file(&disk_path);
        assert!(disk2.needs_format());
        // Stale marker should be cleaned up
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

        // Write ext4 magic so disk_appears_valid_ext4() passes
        write_ext4_magic(&disk_path);

        // Mark as formatted
        mark_disk_formatted(&disk_path).unwrap();
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
