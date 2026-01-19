//! Platform behavior traits.
//!
//! These traits define platform-specific behaviors that differ between
//! macOS and Linux, particularly around VM execution and Rosetta support.

use crate::error::Result;
use std::ffi::CString;
use std::path::Path;

/// Trait for platform-specific VM execution behaviors.
///
/// This abstracts over differences in how VMs are executed on different
/// platforms, particularly around virtiofs mount handling.
///
/// On macOS, virtiofs devices must be explicitly mounted by the guest
/// using a wrapper script. On Linux, the kernel auto-mounts them.
pub trait VmExecutor: Send + Sync {
    /// Whether this platform requires explicit virtiofs mount commands.
    ///
    /// Returns `true` on macOS where virtiofs devices need manual mounting,
    /// `false` on Linux where the kernel handles it automatically.
    fn requires_mount_wrapper(&self) -> bool;

    /// Build the execution command, optionally wrapping with mount script.
    ///
    /// # Arguments
    ///
    /// * `command` - The user's command to execute (None defaults to /bin/sh)
    /// * `mounts` - List of (virtiofs_tag, guest_path) tuples for virtiofs mounts
    /// * `rootfs` - Path to the rootfs directory on the host
    ///
    /// # Returns
    ///
    /// Tuple of (exec_path, argv_pointers, cstrings_to_keep_alive).
    /// The cstrings must be kept alive for the duration of the argv usage.
    ///
    /// Note: libkrun expects argv to contain only arguments (not argv[0]),
    /// as it passes exec_path via KRUN_INIT environment variable.
    fn build_exec_command(
        &self,
        command: &Option<Vec<String>>,
        mounts: &[(String, String)],
        rootfs: &Path,
    ) -> Result<(CString, Vec<*const libc::c_char>, Vec<CString>)>;

    /// Get platform-specific paths for finding system tools.
    ///
    /// Returns paths where tools like `mkfs.ext4` might be found.
    /// On macOS this includes Homebrew paths, on Linux standard system paths.
    fn tool_search_paths(&self) -> &'static [&'static str];

    /// Get the dynamic library extension for this platform.
    ///
    /// Returns "dylib" on macOS, "so" on Linux.
    fn dylib_extension(&self) -> &'static str;

    /// Get common library search paths for this platform.
    ///
    /// Used for finding libraries like libkrun at runtime.
    fn library_search_paths(&self) -> &'static [&'static str];
}

/// Trait for Rosetta 2 support detection and configuration.
///
/// Rosetta 2 allows running x86_64 binaries on Apple Silicon Macs.
/// This trait provides a uniform interface that returns "not available"
/// on platforms where Rosetta doesn't exist.
pub trait RosettaSupport {
    /// Check if Rosetta 2 is available on this system.
    ///
    /// Returns `true` only on Apple Silicon Macs with Rosetta installed.
    fn is_available(&self) -> bool;

    /// Get the path to the Rosetta runtime directory.
    ///
    /// Returns `Some("/Library/Apple/usr/libexec/oah")` if Rosetta is available,
    /// `None` otherwise.
    fn runtime_path(&self) -> Option<&'static str>;

    /// Check if the given platform string requires Rosetta.
    ///
    /// Returns `true` for x86_64/amd64 platforms when running on ARM.
    fn needs_rosetta(&self, platform: &str) -> bool {
        let platform_lower = platform.to_lowercase();
        platform_lower.contains("amd64")
            || platform_lower.contains("x86_64")
            || platform_lower.contains("x86-64")
    }
}
