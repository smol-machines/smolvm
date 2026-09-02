use crate::data::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

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
    #[cfg(target_os = "macos")]
    const ILLEGAL_SOURCE_MOUNT_PATH: &[(&str, bool)] = &[
        ("/", false),
        ("/private/var", false),
        ("/private/var/run", true),
        ("/private/var/log", true),
        ("/private/etc", true),
        ("/usr", true),
        ("/bin", true),
        ("/sbin", true),
        ("/lib", true),
        ("/System", true),
        ("/Library", true),
    ];

    /// Protected host paths that must never be mounted into the guest.
    #[cfg(target_os = "linux")]
    const ILLEGAL_SOURCE_MOUNT_PATH: &[(&str, bool)] = &[
        ("/", false),
        ("/var", false),
        ("/var/run", true),
        ("/var/log", true),
        ("/etc", true),
        ("/boot", true),
        ("/usr", true),
        ("/bin", true),
        ("/sbin", true),
        ("/lib", true),
        ("/proc", true),
        ("/sys", true),
        ("/dev", true),
        ("/run", true),
    ];

    /// Protected host paths that must never be mounted into the guest (Windows).
    #[cfg(target_os = "windows")]
    const ILLEGAL_SOURCE_MOUNT_PATH: &[(&str, bool)] = &[
        ("C:\\", false),
        ("C:\\Windows", true),
        ("C:\\Program Files", true),
        ("C:\\Program Files (x86)", true),
        ("C:\\ProgramData", true),
    ];

    /// Create a host mount with an explicit read-only flag.
    pub fn new(
        source: impl Into<PathBuf>,
        target: impl Into<PathBuf>,
        read_only: bool,
    ) -> Result<Self> {
        Self::new_with_system_mounts(source, target, read_only, false)
    }

    /// Create a host mount, optionally permitting selected host system trees.
    ///
    /// The opt-in is deliberately narrow: only configuration and log trees may
    /// be exposed, they must be read-only, and they must appear below `/host`
    /// in the guest. Virtual kernel filesystems and executable system trees
    /// remain blocked even for trusted callers.
    pub fn new_with_system_mounts(
        source: impl Into<PathBuf>,
        target: impl Into<PathBuf>,
        read_only: bool,
        allow_system_mounts: bool,
    ) -> Result<Self> {
        let mut mount = Self {
            source: source.into(),
            target: target.into(),
            read_only,
        };

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

        mount.source = mount.source.canonicalize().map_err(|e| {
            Error::mount(
                "canonicalize host path",
                format!("'{}': {}", mount.source.display(), e),
            )
        })?;
        if allow_system_mounts {
            Self::validate_with_system_mounts(&mount, true)?;
        } else {
            Self::validate(&mount)?;
        }
        Ok(mount)
    }

    /// Parse a mount specification (`host_path:guest_path[:ro|:rw]`).
    ///
    /// If no mode is provided, the mount defaults to writable.
    /// The source path is validated, required to be a directory, and canonicalized.
    fn _parse(spec: &str, allow_system_mounts: bool) -> Result<Self> {
        // Parse from the right so a Windows host path keeps its drive-letter
        // colon (e.g. `C:\data:/data:ro`). The guest path is a Unix path with no
        // colon, and the optional trailing mode is `ro`/`rw`; everything before
        // the guest path is the host source.
        let (rest, read_only) = match spec.rsplit_once(':') {
            Some((head, "ro")) => (head, true),
            Some((head, "rw")) => (head, false),
            _ => (spec, false),
        };
        match rest.rsplit_once(':') {
            Some((source, target)) if !source.is_empty() && !target.is_empty() => {
                Self::new_with_system_mounts(source, target, read_only, allow_system_mounts)
            }
            _ => Err(Error::invalid_mount_path(format!(
                "invalid format '{}' (expected host:guest[:ro|:rw])",
                spec
            ))),
        }
    }

    /// Parse multiple mount specifications.
    pub fn parse(specs: &[String]) -> Result<Vec<Self>> {
        Self::parse_with_system_mounts(specs, false)
    }

    /// Parse mounts for a trusted local caller that explicitly opted into
    /// read-only host system configuration/log mounts.
    pub fn parse_with_system_mounts(
        specs: &[String],
        allow_system_mounts: bool,
    ) -> Result<Vec<Self>> {
        let mounts: Vec<Self> = specs
            .iter()
            .map(|spec| Self::_parse(spec, allow_system_mounts))
            .collect::<Result<_>>()?;
        Self::ensure_unique_targets(&mounts)?;
        Ok(mounts)
    }

    /// Reject duplicate guest targets. Silently letting a later mount shadow an
    /// earlier one at the same guest path (second-wins) hides a likely mistake
    /// and makes the effective mount ambiguous. Enforced on both the CLI (`-v`)
    /// and the HTTP create paths so they behave identically.
    pub fn ensure_unique_targets(mounts: &[Self]) -> Result<()> {
        let mut seen = std::collections::HashSet::new();
        for m in mounts {
            if !seen.insert(&m.target) {
                return Err(Error::mount(
                    "validate mounts",
                    format!(
                        "duplicate mount target: {} is specified more than once",
                        m.target.display()
                    ),
                ));
            }
        }
        Ok(())
    }

    fn validate(mount: &Self) -> Result<()> {
        Self::validate_with_system_mounts(mount, false)
    }

    fn validate_with_system_mounts(mount: &Self, allow_system_mounts: bool) -> Result<()> {
        for (illegal_path, block_subtree) in Self::ILLEGAL_SOURCE_MOUNT_PATH {
            let illegal_path = Path::new(illegal_path);
            if mount.source == illegal_path
                || (*block_subtree && mount.source.starts_with(illegal_path))
            {
                if allow_system_mounts && Self::trusted_system_source(&mount.source) {
                    if !mount.read_only {
                        return Err(Error::mount(
                            "validate host path",
                            format!(
                                "system mount must be read-only; add ':ro' to the volume: {}",
                                mount.source.display()
                            ),
                        ));
                    }
                    if !Self::target_is_below_host(&mount.target) {
                        return Err(Error::mount(
                            "validate guest path",
                            format!(
                                "system mount target must be /host or below it (for example /host/etc): {}",
                                mount.target.display()
                            ),
                        ));
                    }
                    continue;
                }
                return Err(Error::mount(
                    "validate host path",
                    format!(
                        "source path on host is a protected system path and cannot be mounted: {}",
                        mount.source.display()
                    ),
                ));
            }
        }

        // Guest paths are always Linux paths; check Linux-absolute (leading '/')
        // rather than `Path::is_absolute()`, which is host-platform-specific and
        // wrongly rejects "/data" on Windows (where absolute means `C:\...`).
        let target_is_absolute = mount.target.to_str().is_some_and(|t| t.starts_with('/'));
        if !target_is_absolute {
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

    fn target_is_below_host(target: &Path) -> bool {
        use std::path::Component;

        let mut components = target.components();
        if components.next() != Some(Component::RootDir)
            || components.next() != Some(Component::Normal("host".as_ref()))
        {
            return false;
        }

        components.all(|component| matches!(component, Component::Normal(_)))
    }

    #[cfg(target_os = "linux")]
    fn trusted_system_source(source: &Path) -> bool {
        source == Path::new("/etc")
            || source.starts_with("/etc")
            || source == Path::new("/var/log")
            || source.starts_with("/var/log")
    }

    #[cfg(target_os = "macos")]
    fn trusted_system_source(source: &Path) -> bool {
        // `/etc` and `/var/log` canonicalize below `/private` on macOS.
        source == Path::new("/private/etc")
            || source.starts_with("/private/etc")
            || source == Path::new("/private/var/log")
            || source.starts_with("/private/var/log")
    }

    #[cfg(target_os = "windows")]
    fn trusted_system_source(_source: &Path) -> bool {
        // The initial capability is intentionally scoped to Unix `/etc` and
        // `/var/log` semantics. Add Windows trees only with equivalent QA.
        false
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

    #[test]
    fn parse_rejects_duplicate_target() {
        // Sources must exist (HostMount::_parse validates source presence),
        // so use real temp directories.
        let base = std::env::temp_dir();
        let a = base.join("smolvm_dup_a");
        let b = base.join("smolvm_dup_b");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let (a, b) = (a.to_string_lossy(), b.to_string_lossy());

        let err = HostMount::parse(&[format!("{a}:/app"), format!("{b}:/app")]).unwrap_err();
        assert!(
            err.to_string().contains("duplicate mount target"),
            "expected duplicate-target error, got: {err}"
        );
        // Distinct targets are fine.
        assert!(HostMount::parse(&[format!("{a}:/app"), format!("{b}:/data")]).is_ok());
    }

    #[test]
    fn ensure_unique_targets_guards_the_http_path() {
        // The HTTP create handler builds HostMounts via TryFrom (which does not
        // dedup) and relies on this helper for the same duplicate-target guard
        // the CLI gets through parse(). Exercise it directly on that collection.
        let base = std::env::temp_dir();
        let a = base.join("smolvm_dup_http_a");
        let b = base.join("smolvm_dup_http_b");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let dup = vec![
            HostMount::new(&a, "/data", true).unwrap(),
            HostMount::new(&b, "/data", true).unwrap(),
        ];
        assert!(HostMount::ensure_unique_targets(&dup)
            .unwrap_err()
            .to_string()
            .contains("duplicate mount target"));
        let ok = vec![
            HostMount::new(&a, "/data", true).unwrap(),
            HostMount::new(&b, "/logs", true).unwrap(),
        ];
        assert!(HostMount::ensure_unique_targets(&ok).is_ok());
    }

    fn parse_one(spec: &str) -> HostMount {
        HostMount::parse(&[spec.to_string()]).unwrap().remove(0)
    }

    #[test]
    fn test_new_mount_rejects_illegal_source_mount_path() {
        for path in ["/", "/etc", "/var", "/var/run", "/var/log"] {
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

    #[cfg(target_os = "linux")]
    #[test]
    fn trusted_system_mounts_require_all_three_guards() {
        let etc = vec!["/etc:/host/etc:ro".to_string()];

        let default_err = HostMount::parse(&etc).unwrap_err().to_string();
        assert!(default_err.contains("protected system path"));

        let mounts = HostMount::parse_with_system_mounts(&etc, true).unwrap();
        assert_eq!(mounts.len(), 1);
        assert!(mounts[0].read_only);
        assert_eq!(mounts[0].target, PathBuf::from("/host/etc"));

        let writable =
            HostMount::parse_with_system_mounts(&["/etc:/host/etc:rw".to_string()], true)
                .unwrap_err()
                .to_string();
        assert!(writable.contains("must be read-only"));

        let wrong_target = HostMount::parse_with_system_mounts(&["/etc:/etc:ro".to_string()], true)
            .unwrap_err()
            .to_string();
        assert!(wrong_target.contains("must be /host or below"));

        let traversal_target =
            HostMount::parse_with_system_mounts(&["/etc:/host/../etc:ro".to_string()], true)
                .unwrap_err()
                .to_string();
        assert!(traversal_target.contains("must be /host or below"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn trusted_system_mounts_accept_canonical_macos_etc() {
        let mounts =
            HostMount::parse_with_system_mounts(&["/etc:/host/etc:ro".to_string()], true).unwrap();
        assert_eq!(mounts[0].source, PathBuf::from("/private/etc"));
        assert_eq!(mounts[0].target, PathBuf::from("/host/etc"));
        assert!(mounts[0].read_only);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn trusted_system_mounts_allow_logs_but_not_kernel_or_executable_trees() {
        assert!(HostMount::parse_with_system_mounts(
            &["/var/log:/host/var/log:ro".to_string()],
            true,
        )
        .is_ok());

        for source in ["/proc", "/sys", "/dev", "/usr"] {
            let spec = format!("{source}:/host{source}:ro");
            let err = HostMount::parse_with_system_mounts(&[spec], true)
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("protected system path"),
                "{source} should remain protected, got: {err}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_validate_rejects_boot_subtree() {
        // `/boot` holds the kernel and bootloader config; mounting it read-write
        // into a guest that scribbles on it can leave the host unbootable, so it
        // belongs alongside the other protected system paths. Exercise `validate`
        // directly so the assertion holds where `/boot` is absent (e.g. CI
        // containers), which `HostMount::new` would otherwise reject earlier as
        // not-found.
        for path in ["/boot", "/boot/grub"] {
            let mount = HostMount {
                source: PathBuf::from(path),
                target: PathBuf::from("/guest/path"),
                read_only: true,
            };
            let err = HostMount::validate(&mount).unwrap_err().to_string();
            assert!(
                err.contains("protected system path"),
                "{path} should be blocked as a protected path, got: {err}"
            );
        }
    }

    #[test]
    fn test_new_mount_allows_safe_source_under_var() {
        let temp_dir = std::env::temp_dir().join("smolvm-safe-var-path");
        std::fs::create_dir_all(&temp_dir).unwrap();

        let result = HostMount::new(&temp_dir, "/guest/path", true);

        let _ = std::fs::remove_dir_all(&temp_dir);

        assert!(
            result.is_ok(),
            "safe paths under the OS temp directory should remain mountable"
        );
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
