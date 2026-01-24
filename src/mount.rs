//! Host mount handling.
//!
//! This module provides utilities for managing host directory mounts
//! into guest VMs using virtiofs.
//!
//! Phase 0: Basic types and validation.
//! Phase 1: Full virtiofs integration with the guest agent.

use crate::api::types::{MountInfo, MountSpec};
use crate::error::{Error, Result};
use crate::vm::config::HostMount;
use std::path::{Path, PathBuf};

/// Canonical mount binding representation.
///
/// This is the internal representation used throughout the codebase.
/// Use the conversion methods to transform to/from API and storage formats.
///
/// # Examples
///
/// ```ignore
/// use smolvm::mount::MountBinding;
///
/// // Create from API spec (validates paths exist)
/// let binding = MountBinding::new("/host/path", "/guest/path", true)?;
///
/// // Convert to database tuple
/// let (source, target, ro) = binding.to_tuple();
///
/// // Convert to agent binding with virtiofs tag
/// let (tag, target, ro) = binding.to_agent_binding(0);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountBinding {
    /// Canonicalized host path.
    pub source: PathBuf,
    /// Target path in guest.
    pub target: PathBuf,
    /// Read-only mount.
    pub read_only: bool,
}

impl MountBinding {
    /// Create a new mount binding with full validation.
    ///
    /// Validates:
    /// - Source path is absolute
    /// - Target path is absolute
    /// - Source exists and is a directory
    /// - Source is canonicalized
    pub fn new(
        source: impl Into<PathBuf>,
        target: impl Into<PathBuf>,
        read_only: bool,
    ) -> Result<Self> {
        let source = source.into();
        let target = target.into();

        // Validate source is absolute
        if !source.is_absolute() {
            return Err(Error::Mount(format!(
                "source must be absolute: {}",
                source.display()
            )));
        }

        // Validate target is absolute
        if !target.is_absolute() {
            return Err(Error::Mount(format!(
                "target must be absolute: {}",
                target.display()
            )));
        }

        // Validate source exists
        if !source.exists() {
            return Err(Error::Mount(format!(
                "source does not exist: {}",
                source.display()
            )));
        }

        // Validate source is a directory
        if !source.is_dir() {
            return Err(Error::Mount(format!(
                "source must be a directory (virtiofs limitation): {}",
                source.display()
            )));
        }

        // Canonicalize source path
        let source = source.canonicalize().map_err(|e| {
            Error::Mount(format!(
                "failed to canonicalize source '{}': {}",
                source.display(),
                e
            ))
        })?;

        Ok(Self {
            source,
            target,
            read_only,
        })
    }

    /// Create without validation (for loading from database).
    ///
    /// Use this only when loading persisted mounts that were previously validated.
    pub fn from_stored(source: String, target: String, read_only: bool) -> Self {
        Self {
            source: PathBuf::from(source),
            target: PathBuf::from(target),
            read_only,
        }
    }

    /// Convert to database storage tuple format.
    pub fn to_tuple(&self) -> (String, String, bool) {
        (
            self.source.to_string_lossy().to_string(),
            self.target.to_string_lossy().to_string(),
            self.read_only,
        )
    }

    /// Convert to agent binding with virtiofs tag.
    ///
    /// Returns (virtiofs_tag, target_path, read_only).
    pub fn to_agent_binding(&self, index: usize) -> (String, String, bool) {
        (
            format!("smolvm{}", index),
            self.target.to_string_lossy().to_string(),
            self.read_only,
        )
    }

    /// Convert to MountInfo for API responses.
    pub fn to_mount_info(&self, index: usize) -> MountInfo {
        MountInfo {
            tag: format!("smolvm{}", index),
            source: self.source.to_string_lossy().to_string(),
            target: self.target.to_string_lossy().to_string(),
            readonly: self.read_only,
        }
    }
}

// Conversion from API MountSpec
impl TryFrom<&MountSpec> for MountBinding {
    type Error = Error;

    fn try_from(spec: &MountSpec) -> Result<Self> {
        MountBinding::new(&spec.source, &spec.target, spec.readonly)
    }
}

// Conversion to API MountSpec
impl From<&MountBinding> for MountSpec {
    fn from(m: &MountBinding) -> Self {
        MountSpec {
            source: m.source.to_string_lossy().to_string(),
            target: m.target.to_string_lossy().to_string(),
            readonly: m.read_only,
        }
    }
}

// Conversion to HostMount (for AgentManager)
impl From<&MountBinding> for HostMount {
    fn from(m: &MountBinding) -> Self {
        if m.read_only {
            HostMount::new(&m.source, &m.target)
        } else {
            HostMount::new_writable(&m.source, &m.target)
        }
    }
}

/// Validate a host mount configuration.
///
/// Checks that:
/// - Source path exists on the host
/// - Source path is absolute
/// - Source path is a directory (not a file)
/// - Target path is absolute
pub fn validate_mount(mount: &HostMount) -> Result<()> {
    // Source must be absolute
    if !mount.source.is_absolute() {
        return Err(Error::InvalidMountPath(format!(
            "source path must be absolute: {}",
            mount.source.display()
        )));
    }

    // Target must be absolute
    if !mount.target.is_absolute() {
        return Err(Error::InvalidMountPath(format!(
            "target path must be absolute: {}",
            mount.target.display()
        )));
    }

    // Source must exist
    if !mount.source.exists() {
        return Err(Error::MountSourceNotFound {
            path: mount.source.clone(),
        });
    }

    // Source must be a directory (virtiofs doesn't support single file mounts)
    if mount.source.is_file() {
        return Err(Error::InvalidMountPath(format!(
            "cannot mount single file '{}': virtiofs only supports directory mounts. \
             Mount the parent directory instead (e.g., -v {}:/mnt/data)",
            mount.source.display(),
            mount.source.parent().unwrap_or(&mount.source).display()
        )));
    }

    Ok(())
}

/// Parse a mount specification string.
///
/// Format: `host_path:guest_path[:ro]`
///
/// - `host_path` - Path on the host filesystem
/// - `guest_path` - Path inside the guest VM
/// - `ro` - Optional, makes the mount read-only (default is writable)
///
/// Note: Per DESIGN.md, mounts should be read-only by default, but for CLI
/// compatibility with Docker-style `-v`, we default to writable unless `:ro`
/// is specified.
pub fn parse_mount_spec(spec: &str) -> Result<HostMount> {
    let parts: Vec<&str> = spec.split(':').collect();

    match parts.as_slice() {
        [source, target] => Ok(HostMount::new_writable(source, target)),
        [source, target, "ro"] => Ok(HostMount::new(source, target)),
        [source, target, "rw"] => Ok(HostMount::new_writable(source, target)),
        _ => Err(Error::InvalidMountPath(format!(
            "invalid mount spec: {} (expected host:guest[:ro|:rw])",
            spec
        ))),
    }
}

/// Check if a path is safe to mount (not a sensitive system path).
///
/// This is a basic check to prevent accidentally mounting sensitive directories.
pub fn is_safe_mount_source(path: &Path) -> bool {
    let path_str = path.to_string_lossy();

    // Block obvious sensitive paths
    const BLOCKED_PATHS: &[&str] = &[
        "/", "/etc", "/var", "/usr", "/bin", "/sbin", "/lib", "/System", "/Library", "/private",
    ];

    for blocked in BLOCKED_PATHS {
        if path_str == *blocked || path_str.starts_with(&format!("{}/", blocked)) {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // === Mount Spec Parsing ===

    #[test]
    fn test_parse_mount_spec_basic() {
        let mount = parse_mount_spec("/host/path:/guest/path").unwrap();
        assert_eq!(mount.source, PathBuf::from("/host/path"));
        assert_eq!(mount.target, PathBuf::from("/guest/path"));
        assert!(!mount.read_only); // Default writable for CLI compat
    }

    #[test]
    fn test_parse_mount_spec_read_only() {
        let mount = parse_mount_spec("/host/path:/guest/path:ro").unwrap();
        assert!(mount.read_only);
    }

    #[test]
    fn test_parse_mount_spec_explicit_rw() {
        let mount = parse_mount_spec("/host/path:/guest/path:rw").unwrap();
        assert!(!mount.read_only);
    }

    #[test]
    fn test_parse_mount_spec_invalid() {
        assert!(parse_mount_spec("/only/one/path").is_err());
        assert!(parse_mount_spec("").is_err());
        assert!(parse_mount_spec("/a:/b:/c:/d").is_err());
    }

    // === Edge Cases ===

    #[test]
    fn test_parse_mount_spec_paths_with_spaces() {
        let mount = parse_mount_spec("/path/with spaces:/guest/path").unwrap();
        assert_eq!(mount.source, PathBuf::from("/path/with spaces"));
        assert_eq!(mount.target, PathBuf::from("/guest/path"));
    }

    #[test]
    fn test_parse_mount_spec_invalid_mode() {
        // Invalid mode should fail
        let result = parse_mount_spec("/host:/guest:invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_mount_spec_too_many_colons() {
        // Too many parts should fail
        let result = parse_mount_spec("/a:/b:ro:extra");
        assert!(result.is_err());
    }

    // === Mount Validation ===

    #[test]
    fn test_validate_mount_relative_source() {
        let mount = HostMount::new("relative/path", "/guest/path");
        let result = validate_mount(&mount);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("absolute"));
    }

    #[test]
    fn test_validate_mount_relative_target() {
        let mount = HostMount::new("/host/path", "relative/path");
        let result = validate_mount(&mount);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("absolute"));
    }

    #[test]
    fn test_validate_mount_nonexistent_source() {
        let mount = HostMount::new("/nonexistent/path/12345abcde", "/guest/path");
        let result = validate_mount(&mount);
        assert!(matches!(result, Err(Error::MountSourceNotFound { .. })));
    }

    #[test]
    fn test_validate_mount_existing_source() {
        // /tmp should exist on all Unix systems
        let mount = HostMount::new("/tmp", "/guest/tmp");
        let result = validate_mount(&mount);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_mount_rejects_single_file() {
        // Create a temp file
        let temp_file = std::env::temp_dir().join("smolvm_test_file.txt");
        std::fs::write(&temp_file, "test").unwrap();

        let mount = HostMount::new(temp_file.to_str().unwrap(), "/guest/file.txt");
        let result = validate_mount(&mount);

        // Cleanup
        let _ = std::fs::remove_file(&temp_file);

        // Should fail with helpful error
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("single file"),
            "Error should mention single file"
        );
        assert!(
            err_msg.contains("directory"),
            "Error should suggest directory mount"
        );
    }

    // === Safe Mount Source Checks ===

    #[test]
    fn test_is_safe_mount_source() {
        // Blocked system paths
        assert!(!is_safe_mount_source(Path::new("/")));
        assert!(!is_safe_mount_source(Path::new("/etc")));
        assert!(!is_safe_mount_source(Path::new("/etc/passwd")));
        assert!(!is_safe_mount_source(Path::new("/System")));
        assert!(!is_safe_mount_source(Path::new("/var")));
        assert!(!is_safe_mount_source(Path::new("/usr")));
        assert!(!is_safe_mount_source(Path::new("/bin")));
        assert!(!is_safe_mount_source(Path::new("/sbin")));
        assert!(!is_safe_mount_source(Path::new("/lib")));

        // Safe user paths
        assert!(is_safe_mount_source(Path::new("/home/user/project")));
        assert!(is_safe_mount_source(Path::new("/Users/someone/code")));
        assert!(is_safe_mount_source(Path::new("/tmp/test")));
        assert!(is_safe_mount_source(Path::new("/opt/myapp")));
    }

    #[test]
    fn test_is_safe_mount_source_subdirectories() {
        // Subdirectories of blocked paths should also be blocked
        assert!(!is_safe_mount_source(Path::new("/etc/nginx")));
        assert!(!is_safe_mount_source(Path::new("/var/log")));
        assert!(!is_safe_mount_source(Path::new("/usr/local")));
    }
}
