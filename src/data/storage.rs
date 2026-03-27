use crate::data::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Default size for the rootfs overlay disk (10 GiB sparse).
///
/// This is a sparse file — only actually-written data consumes host disk space.
/// 10 GiB provides headroom for package installation (`apk add`, `pip install`, etc.)
/// without hitting "No space left on device" during typical development workflows.
pub const DEFAULT_OVERLAY_SIZE_GIB: u64 = 10;

/// Default size for the shared storage disk (20 GiB sparse).
pub const DEFAULT_STORAGE_SIZE_GIB: u64 = 20;

/// Overlay disk filename.
pub const OVERLAY_DISK_FILENAME: &str = "overlay.raw";

/// Storage disk filename.
pub const STORAGE_DISK_FILENAME: &str = "storage.raw";

/// Host directory mount.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostMount {
    /// Path on the host.
    pub source: PathBuf,

    /// Path inside the guest.
    pub target: PathBuf,

    /// Read-only mount (default: true per DESIGN.md).
    pub read_only: bool,
}

impl HostMount {
    /// Protected host paths that must never be mounted into the guest.
    const ILLEGAL_SOURCE_MOUNT_PATH: &[&str] = &[
        "/", "/etc", "/var", "/usr", "/bin", "/sbin", "/lib", "/System", "/Library", "/private",
    ];

    /// Create a host mount with an explicit read-only flag.
    pub fn new(
        source: impl Into<PathBuf>,
        target: impl Into<PathBuf>,
        read_only: bool,
    ) -> Result<Self> {
        let mut mount = Self {
            source: source.into(),
            target: target.into(),
            read_only,
        };
        Self::validate(&mount)?;
        mount.source = mount.source.canonicalize().map_err(|e| {
            Error::mount(
                "canonicalize host path",
                format!("'{}': {}", mount.source.display(), e),
            )
        })?;
        Ok(mount)
    }

    /// Parse a mount specification (`host_path:guest_path[:ro|:rw]`).
    ///
    /// If no mode is provided, the mount defaults to writable.
    /// The source path is validated, required to be a directory, and canonicalized.
    fn _parse(spec: &str) -> Result<Self> {
        let parts: Vec<&str> = spec.split(':').collect();

        match parts.as_slice() {
            [source, target] => Self::new(source, target, false),
            [source, target, "ro"] => Self::new(source, target, true),
            [source, target, "rw"] => Self::new(source, target, false),
            _ => Err(Error::invalid_mount_path(format!(
                "invalid format '{}' (expected host:guest[:ro|:rw])",
                spec
            ))),
        }
    }

    /// Parse multiple mount specifications.
    pub fn parse(specs: &[String]) -> Result<Vec<Self>> {
        specs.iter().map(|spec| Self::_parse(spec)).collect()
    }

    fn validate(mount: &Self) -> Result<()> {
        if !mount.source.exists() {
            return Err(Error::MountSourceNotFound {
                path: mount.source.clone(),
            });
        }

        if !mount.source.is_dir() {
            return Err(Error::mount(
                "validate host path",
                format!(
                    "source path on host must be a directory (virtiofs limitation): {}",
                    mount.source.display()
                ),
            ));
        }

        let source = mount.source.to_string_lossy();
        for illegal_path in Self::ILLEGAL_SOURCE_MOUNT_PATH {
            if source == *illegal_path || source.starts_with(&format!("{}/", illegal_path)) {
                return Err(Error::mount(
                    "validate host path",
                    format!(
                        "source path on host is a protected system path and cannot be mounted: {}",
                        mount.source.display()
                    ),
                ));
            }
        }

        if !mount.target.is_absolute() {
            return Err(Error::mount(
                "validate guest path",
                format!(
                    "target path on guest should be an absolute directory: {}",
                    mount.target.display()
                ),
            ));
        }

        Ok(())
    }

    /// Generate a virtiofs mount tag for a given index.
    ///
    /// Mount tags follow the format "smolvm0", "smolvm1", etc. and are used
    /// consistently across the host launcher, API handlers, and guest agent.
    pub fn mount_tag(index: usize) -> String {
        format!("smolvm{}", index)
    }

    /// Create without validation (for loading from database).
    ///
    /// Use this only when loading persisted mounts that were previously validated.
    pub fn from_storage_tuple(source: String, target: String, read_only: bool) -> Self {
        Self {
            source: PathBuf::from(source),
            target: PathBuf::from(target),
            read_only,
        }
    }

    /// Convert this mount to tuple format for persistence.
    pub fn to_storage_tuple(&self) -> (String, String, bool) {
        (
            self.source.to_string_lossy().to_string(),
            self.target.to_string_lossy().to_string(),
            self.read_only,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn parse_one(spec: &str) -> HostMount {
        HostMount::parse(&[spec.to_string()]).unwrap().remove(0)
    }

    #[test]
    fn test_new_mount_rejects_illegal_source_mount_path() {
        for path in ["/", "/etc", "/var/log"] {
            let result = HostMount::new(path, "/guest/path", true);
            assert!(result.is_err(), "{} should be rejected", path);
            let err_msg = result.unwrap_err().to_string();
            assert!(
                err_msg.contains("protected system path"),
                "Error should explain why {} is blocked, got: {}",
                path,
                err_msg
            );
            assert!(
                err_msg.contains("cannot be mounted"),
                "Error should explain that {} cannot be mounted, got: {}",
                path,
                err_msg
            );
        }
    }

    #[test]
    fn test_parse_mount_spec_basic() {
        let mount = parse_one("/tmp:/guest/path");
        assert_eq!(mount.source, PathBuf::from("/tmp").canonicalize().unwrap());
        assert_eq!(mount.target, PathBuf::from("/guest/path"));
        assert!(!mount.read_only);
    }

    #[test]
    fn test_parse_mount_spec_read_only() {
        let mount = parse_one("/tmp:/guest/path:ro");
        assert!(mount.read_only);
    }

    #[test]
    fn test_parse_mount_spec_explicit_rw() {
        let mount = parse_one("/tmp:/guest/path:rw");
        assert!(!mount.read_only);
    }

    #[test]
    fn test_parse_mount_spec_invalid() {
        assert!(HostMount::parse(&["/only/one/path".to_string()]).is_err());
        assert!(HostMount::parse(&["".to_string()]).is_err());
        assert!(HostMount::parse(&["/a:/b:/c:/d".to_string()]).is_err());
    }

    #[test]
    fn test_parse_mount_spec_paths_with_spaces() {
        let temp_dir = std::env::current_dir()
            .unwrap()
            .join("target")
            .join("smolvm mount with spaces");
        std::fs::create_dir_all(&temp_dir).unwrap();

        let spec = format!("{}:/guest/path", temp_dir.display());
        let mount = parse_one(&spec);

        assert_eq!(mount.source, temp_dir.canonicalize().unwrap());
        assert_eq!(mount.target, PathBuf::from("/guest/path"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_parse_mount_spec_invalid_mode() {
        let result = HostMount::parse(&["/host:/guest:invalid".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_mount_spec_too_many_colons() {
        let result = HostMount::parse(&["/a:/b:ro:extra".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn test_new_mount_nonexistent_source() {
        let result = HostMount::new("/nonexistent/path/12345abcde", "/guest/path", true);
        assert!(matches!(result, Err(Error::MountSourceNotFound { .. })));
    }

    #[test]
    fn test_new_mount_disallows_relative_target() {
        let result = HostMount::new("/tmp", "relative/path", true);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("absolute"),
            "Error should explain that guest target paths must be absolute"
        );
    }

    #[test]
    fn test_new_mount_existing_source() {
        let result = HostMount::new("/tmp", "/guest/tmp", true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_new_mount_rejects_single_file() {
        let temp_file = std::env::temp_dir().join("smolvm_test_file.txt");
        std::fs::write(&temp_file, "test").unwrap();

        let result = HostMount::new(temp_file.to_str().unwrap(), "/guest/file.txt", true);

        let _ = std::fs::remove_file(&temp_file);

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("directory"),
            "Error should suggest directory mount"
        );
        assert!(
            err_msg.contains("virtiofs limitation"),
            "Error should explain the virtiofs directory requirement"
        );
    }
}
