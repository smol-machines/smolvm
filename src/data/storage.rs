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
    /// Create a new read-only host mount.
    pub fn new(source: impl Into<PathBuf>, target: impl Into<PathBuf>) -> Self {
        Self {
            source: source.into(),
            target: target.into(),
            read_only: true,
        }
    }

    /// Make this mount writable.
    pub fn writable(mut self) -> Self {
        self.read_only = false;
        self
    }

    /// Create a writable mount directly.
    pub fn new_writable(source: impl Into<PathBuf>, target: impl Into<PathBuf>) -> Self {
        Self {
            source: source.into(),
            target: target.into(),
            read_only: false,
        }
    }

    /// Parse a mount specification (`host_path:guest_path[:ro|:rw]`).
    ///
    /// If no mode is provided, the mount defaults to writable.
    /// The source path is validated, required to be a directory, and canonicalized.
    pub fn parse(spec: &str) -> Result<Self> {
        let parts: Vec<&str> = spec.split(':').collect();

        let mut mount = match parts.as_slice() {
            [source, target] => Self::new_writable(source, target),
            [source, target, "ro"] => Self::new(source, target),
            [source, target, "rw"] => Self::new_writable(source, target),
            _ => {
                return Err(Error::invalid_mount_path(format!(
                    "invalid format '{}' (expected host:guest[:ro|:rw])",
                    spec
                )))
            }
        };

        if !mount.source.exists() {
            return Err(Error::mount(
                "validate host path",
                format!("path does not exist: {}", mount.source.display()),
            ));
        }

        if !mount.source.is_dir() {
            return Err(Error::mount(
                "validate host path",
                format!(
                    "path must be a directory (virtiofs limitation): {}",
                    mount.source.display()
                ),
            ));
        }

        mount.source = mount.source.canonicalize().map_err(|e| {
            Error::mount("canonicalize host path", format!("'{}': {}", parts[0], e))
        })?;

        Ok(mount)
    }

    /// Parse multiple mount specifications.
    pub fn parse_many(specs: &[String]) -> Result<Vec<Self>> {
        specs.iter().map(|spec| Self::parse(spec)).collect()
    }

    /// Validate that the mount uses absolute paths and a directory source.
    pub fn validate(&self) -> Result<()> {
        if !self.source.is_absolute() {
            return Err(Error::invalid_mount_path(format!(
                "source path must be absolute: {}",
                self.source.display()
            )));
        }

        if !self.target.is_absolute() {
            return Err(Error::invalid_mount_path(format!(
                "target path must be absolute: {}",
                self.target.display()
            )));
        }

        if !self.source.exists() {
            return Err(Error::MountSourceNotFound {
                path: self.source.clone(),
            });
        }

        if self.source.is_file() {
            return Err(Error::invalid_mount_path(format!(
                "cannot mount single file '{}': virtiofs only supports directory mounts. \
                 Mount the parent directory instead (e.g., -v {}:/mnt/data)",
                self.source.display(),
                self.source.parent().unwrap_or(&self.source).display()
            )));
        }

        Ok(())
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
