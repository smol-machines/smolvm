//! Host mount handling.
//!
//! This module provides utilities for managing host directory mounts
//! into guest VMs using virtiofs.

use crate::api::types::{MountInfo, MountSpec};
use crate::data::storage::HostMount;
use crate::error::{Error, Result};
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
            return Err(Error::mount(
                "validate source",
                format!("path must be absolute: {}", source.display()),
            ));
        }

        // Validate target is absolute
        if !target.is_absolute() {
            return Err(Error::mount(
                "validate target",
                format!("path must be absolute: {}", target.display()),
            ));
        }

        // Validate source exists
        if !source.exists() {
            return Err(Error::mount(
                "validate source",
                format!("path does not exist: {}", source.display()),
            ));
        }

        // Validate source is a directory
        if !source.is_dir() {
            return Err(Error::mount(
                "validate source",
                format!(
                    "path must be a directory (virtiofs limitation): {}",
                    source.display()
                ),
            ));
        }

        // Canonicalize source path
        let source = source.canonicalize().map_err(|e| {
            Error::mount(
                "canonicalize source",
                format!("'{}': {}", source.display(), e),
            )
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
            crate::agent::mount_tag(index),
            self.target.to_string_lossy().to_string(),
            self.read_only,
        )
    }

    /// Convert to MountInfo for API responses.
    pub fn to_mount_info(&self, index: usize) -> MountInfo {
        MountInfo {
            tag: crate::agent::mount_tag(index),
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
        let mount = HostMount::parse("/tmp:/guest/path").unwrap();
        assert_eq!(mount.source, PathBuf::from("/tmp").canonicalize().unwrap());
        assert_eq!(mount.target, PathBuf::from("/guest/path"));
        assert!(!mount.read_only); // Default writable for CLI compat
    }

    #[test]
    fn test_parse_mount_spec_read_only() {
        let mount = HostMount::parse("/tmp:/guest/path:ro").unwrap();
        assert!(mount.read_only);
    }

    #[test]
    fn test_parse_mount_spec_explicit_rw() {
        let mount = HostMount::parse("/tmp:/guest/path:rw").unwrap();
        assert!(!mount.read_only);
    }

    #[test]
    fn test_parse_mount_spec_invalid() {
        assert!(HostMount::parse("/only/one/path").is_err());
        assert!(HostMount::parse("").is_err());
        assert!(HostMount::parse("/a:/b:/c:/d").is_err());
    }

    // === Edge Cases ===

    #[test]
    fn test_parse_mount_spec_paths_with_spaces() {
        let temp_dir = std::env::temp_dir().join("smolvm mount with spaces");
        std::fs::create_dir_all(&temp_dir).unwrap();

        let spec = format!("{}:/guest/path", temp_dir.display());
        let mount = HostMount::parse(&spec).unwrap();

        assert_eq!(mount.source, temp_dir.canonicalize().unwrap());
        assert_eq!(mount.target, PathBuf::from("/guest/path"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_parse_mount_spec_invalid_mode() {
        // Invalid mode should fail
        let result = HostMount::parse("/host:/guest:invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_mount_spec_too_many_colons() {
        // Too many parts should fail
        let result = HostMount::parse("/a:/b:ro:extra");
        assert!(result.is_err());
    }

    // === Mount Validation ===

    #[test]
    fn test_validate_mount_relative_source() {
        let mount = HostMount::new("relative/path", "/guest/path");
        let result = mount.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("absolute"));
    }

    #[test]
    fn test_validate_mount_relative_target() {
        let mount = HostMount::new("/host/path", "relative/path");
        let result = mount.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("absolute"));
    }

    #[test]
    fn test_validate_mount_nonexistent_source() {
        let mount = HostMount::new("/nonexistent/path/12345abcde", "/guest/path");
        let result = mount.validate();
        assert!(matches!(result, Err(Error::MountSourceNotFound { .. })));
    }

    #[test]
    fn test_validate_mount_existing_source() {
        // /tmp should exist on all Unix systems
        let mount = HostMount::new("/tmp", "/guest/tmp");
        let result = mount.validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_mount_rejects_single_file() {
        // Create a temp file
        let temp_file = std::env::temp_dir().join("smolvm_test_file.txt");
        std::fs::write(&temp_file, "test").unwrap();

        let mount = HostMount::new(temp_file.to_str().unwrap(), "/guest/file.txt");
        let result = mount.validate();

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
        // (path, expected_safe, description)
        let cases = [
            // Blocked system paths
            ("/", false, "root"),
            ("/etc", false, "etc"),
            ("/etc/passwd", false, "etc file"),
            ("/etc/nginx", false, "etc subdir"),
            ("/System", false, "System"),
            ("/var", false, "var"),
            ("/var/log", false, "var subdir"),
            ("/usr", false, "usr"),
            ("/usr/local", false, "usr subdir"),
            ("/bin", false, "bin"),
            ("/sbin", false, "sbin"),
            ("/lib", false, "lib"),
            // Safe user paths
            ("/home/user/project", true, "home dir"),
            ("/Users/someone/code", true, "Users dir"),
            ("/tmp/test", true, "tmp"),
            ("/opt/myapp", true, "opt"),
        ];

        for (path, expected, desc) in cases {
            assert_eq!(
                is_safe_mount_source(Path::new(path)),
                expected,
                "{} ({}) should be {}",
                path,
                desc,
                if expected { "safe" } else { "blocked" }
            );
        }
    }
}
