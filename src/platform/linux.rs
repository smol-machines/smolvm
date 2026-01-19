//! Linux-specific platform implementations.
//!
//! This module provides Linux implementations for VM execution.
//! On Linux, virtiofs devices are auto-mounted by the kernel, so no
//! wrapper script is needed.

use crate::error::{Error, Result};
use crate::platform::traits::{RosettaSupport, VmExecutor};
use std::ffi::CString;
use std::path::Path;

/// Linux VM executor implementation.
///
/// On Linux, virtiofs devices are automatically mounted by the kernel,
/// so this executor doesn't need to wrap commands with a mount script.
pub struct LinuxExecutor;

impl VmExecutor for LinuxExecutor {
    fn requires_mount_wrapper(&self) -> bool {
        false
    }

    fn build_exec_command(
        &self,
        command: &Option<Vec<String>>,
        _mounts: &[(String, String)], // Ignored on Linux - kernel handles virtiofs
        _rootfs: &Path,
    ) -> Result<(CString, Vec<*const libc::c_char>, Vec<CString>)> {
        // Linux doesn't need mount wrapper; execute command directly
        let default_cmd = vec!["/bin/sh".to_string()];
        let cmd = command.as_ref().unwrap_or(&default_cmd);

        if cmd.is_empty() {
            return Err(Error::vm_creation("command cannot be empty"));
        }

        let exec_path =
            CString::new(cmd[0].as_str()).map_err(|_| Error::vm_creation("invalid command path"))?;

        // Skip argv[0] - libkrun/init.krun handles it via KRUN_INIT
        let cstrings: Vec<CString> = cmd
            .iter()
            .skip(1)
            .map(|s| CString::new(s.as_str()))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| Error::vm_creation("invalid command argument"))?;

        let mut argv: Vec<*const libc::c_char> = cstrings.iter().map(|s| s.as_ptr()).collect();
        argv.push(std::ptr::null());

        Ok((exec_path, argv, cstrings))
    }

    fn tool_search_paths(&self) -> &'static [&'static str] {
        &[
            "/sbin",
            "/usr/sbin",
            "/usr/local/sbin",
        ]
    }

    fn dylib_extension(&self) -> &'static str {
        "so"
    }

    fn library_search_paths(&self) -> &'static [&'static str] {
        &[
            "/usr/lib",
            "/usr/local/lib",
            "/usr/lib64",
            "/usr/local/lib64",
            "/usr/lib/x86_64-linux-gnu",
            "/usr/lib/aarch64-linux-gnu",
        ]
    }
}

/// Linux Rosetta support (stub - always unavailable).
///
/// Rosetta 2 is a macOS-only feature, so this implementation
/// always returns false for availability checks.
pub struct LinuxRosetta;

impl RosettaSupport for LinuxRosetta {
    fn is_available(&self) -> bool {
        false
    }

    fn runtime_path(&self) -> Option<&'static str> {
        None
    }
}

/// Get the Rosetta support instance for Linux.
pub fn rosetta_support() -> LinuxRosetta {
    LinuxRosetta
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_linux_executor_no_mount_wrapper() {
        let executor = LinuxExecutor;
        assert!(!executor.requires_mount_wrapper());
    }

    #[test]
    fn test_linux_dylib_extension() {
        let executor = LinuxExecutor;
        assert_eq!(executor.dylib_extension(), "so");
    }

    #[test]
    fn test_linux_rosetta_unavailable() {
        let rosetta = LinuxRosetta;
        assert!(!rosetta.is_available());
        assert!(rosetta.runtime_path().is_none());
    }

    #[test]
    fn test_rosetta_needs_rosetta() {
        let rosetta = LinuxRosetta;
        // The needs_rosetta logic is in the trait default impl
        assert!(rosetta.needs_rosetta("linux/amd64"));
        assert!(!rosetta.needs_rosetta("linux/arm64"));
    }

    #[test]
    fn test_linux_ignores_mounts_in_exec_command() {
        let executor = LinuxExecutor;
        let tmp = TempDir::new().unwrap();
        let cmd = Some(vec!["/bin/echo".to_string(), "hello".to_string()]);
        // Linux should ignore mounts - kernel handles virtiofs automatically
        let mounts = vec![
            ("smolvm0".to_string(), "/data".to_string()),
        ];

        let (exec_path, _argv, cstrings) = executor
            .build_exec_command(&cmd, &mounts, tmp.path())
            .unwrap();

        // Should return direct command, ignoring mounts
        assert_eq!(exec_path.to_str().unwrap(), "/bin/echo");
        assert_eq!(cstrings.len(), 1);
        assert_eq!(cstrings[0].to_str().unwrap(), "hello");

        // No mount script should be created
        let script_path = tmp.path().join("tmp/smolvm-mount.sh");
        assert!(!script_path.exists(), "Linux should not create mount script");
    }
}
