//! Shared path configuration for embedded SDK adapters.

use crate::{Error, Result};
use std::path::PathBuf;
use std::sync::{OnceLock, RwLock};

/// Paths supplied by an embedded SDK adapter.
#[derive(Debug, Clone, Default)]
pub struct EmbeddedPaths {
    /// Directory containing bundled native libraries such as libkrun/libkrunfw.
    pub lib_dir: Option<PathBuf>,
    /// Helper executable used to spawn the hidden `_boot-vm` subprocess.
    pub boot_bin: Option<PathBuf>,
    /// Optional override for the agent rootfs path.
    pub rootfs_path: Option<PathBuf>,
}

static EMBEDDED_PATHS: OnceLock<RwLock<EmbeddedPaths>> = OnceLock::new();

fn paths_lock() -> &'static RwLock<EmbeddedPaths> {
    EMBEDDED_PATHS.get_or_init(|| RwLock::new(EmbeddedPaths::default()))
}

fn normalize_path(path: PathBuf) -> Result<PathBuf> {
    if !path.exists() {
        return Err(Error::config(
            "configure embedded paths",
            format!("path does not exist: {}", path.display()),
        ));
    }

    Ok(path.canonicalize().unwrap_or(path))
}

/// Merge explicit embedded SDK paths into the shared runtime configuration.
pub fn configure_paths(paths: EmbeddedPaths) -> Result<()> {
    let mut configured = paths_lock()
        .write()
        .map_err(|e| Error::agent("embedded paths", e.to_string()))?;

    if let Some(lib_dir) = paths.lib_dir {
        configured.lib_dir = Some(normalize_path(lib_dir)?);
    }
    if let Some(boot_bin) = paths.boot_bin {
        configured.boot_bin = Some(normalize_path(boot_bin)?);
    }
    if let Some(rootfs_path) = paths.rootfs_path {
        configured.rootfs_path = Some(normalize_path(rootfs_path)?);
    }

    Ok(())
}

/// Snapshot the current embedded SDK path configuration.
pub fn configured_paths() -> Result<EmbeddedPaths> {
    let configured = paths_lock()
        .read()
        .map_err(|e| Error::agent("embedded paths", e.to_string()))?;
    Ok(configured.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_temp_dir(label: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "smolvm-embedded-paths-{}-{}-{}",
            label,
            std::process::id(),
            unique
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn configure_paths_merges_updates() {
        let lib_dir = unique_temp_dir("lib");
        let boot_bin = lib_dir.join("smolvm");
        std::fs::write(&boot_bin, b"#!/bin/sh\n").unwrap();

        configure_paths(EmbeddedPaths {
            lib_dir: Some(lib_dir.clone()),
            boot_bin: None,
            rootfs_path: None,
        })
        .unwrap();
        configure_paths(EmbeddedPaths {
            lib_dir: None,
            boot_bin: Some(boot_bin.clone()),
            rootfs_path: None,
        })
        .unwrap();

        let configured = configured_paths().unwrap();
        assert_eq!(configured.lib_dir, Some(lib_dir.canonicalize().unwrap()));
        assert_eq!(configured.boot_bin, Some(boot_bin.canonicalize().unwrap()));
        assert!(configured.rootfs_path.is_none());
    }

    #[test]
    fn configure_paths_rejects_missing_paths() {
        let err = configure_paths(EmbeddedPaths {
            lib_dir: Some(std::env::temp_dir().join("smolvm-missing-lib-dir")),
            boot_bin: None,
            rootfs_path: None,
        })
        .unwrap_err();

        assert!(err.to_string().contains("path does not exist"));
    }
}
