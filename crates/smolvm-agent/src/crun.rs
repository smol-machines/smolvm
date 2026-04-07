//! Crun OCI runtime command builder.
//!
//! This module provides a consistent interface for invoking crun commands
//! with the correct configuration (cgroup-manager, etc.).

use std::path::Path;
use std::process::{Command, Stdio};

use crate::paths;

/// Builder for crun commands with consistent configuration.
///
/// This ensures all crun invocations use the same cgroup-manager setting
/// and other common options.
pub struct CrunCommand {
    cmd: Command,
}

impl CrunCommand {
    /// Create a new crun command with standard configuration.
    ///
    /// Uses `--root` to store container state on the persistent storage disk
    /// instead of the default `/run/crun`, which may not be writable when the
    /// rootfs is an overlayfs with an initramfs lower layer.
    fn new() -> Self {
        let mut cmd = Command::new(paths::CRUN_PATH);
        cmd.args(["--root", paths::CRUN_ROOT_DIR]);
        cmd.args(["--cgroup-manager", paths::CRUN_CGROUP_MANAGER]);
        Self { cmd }
    }

    /// Run a container: `crun run --bundle <path> <id>`
    ///
    /// This creates, starts, waits, and deletes the container in one operation.
    pub fn run(bundle_dir: &Path, container_id: &str) -> Self {
        let mut c = Self::new();
        c.cmd.args([
            "run",
            "--bundle",
            &bundle_dir.to_string_lossy(),
            container_id,
        ]);
        c
    }

    /// Kill a container: `crun kill <id> <signal>`
    pub fn kill(container_id: &str, signal: &str) -> Self {
        let mut c = Self::new();
        c.cmd.args(["kill", container_id, signal]);
        c
    }

    /// Delete a container: `crun delete [-f] <id>`
    pub fn delete(container_id: &str, force: bool) -> Self {
        let mut c = Self::new();
        if force {
            c.cmd.args(["delete", "-f", container_id]);
        } else {
            c.cmd.args(["delete", container_id]);
        }
        c
    }

    /// Set stdin to null.
    pub fn stdin_null(mut self) -> Self {
        self.cmd.stdin(Stdio::null());
        self
    }

    /// Set stdin to piped.
    pub fn stdin_piped(mut self) -> Self {
        self.cmd.stdin(Stdio::piped());
        self
    }

    /// Set stdin from a raw fd (e.g., PTY slave).
    ///
    /// # Safety
    /// The fd must be a valid open file descriptor. Ownership is transferred.
    #[cfg(unix)]
    pub unsafe fn stdin_from_fd(mut self, fd: std::os::unix::io::RawFd) -> Self {
        use std::os::unix::io::FromRawFd;
        self.cmd.stdin(Stdio::from_raw_fd(fd));
        self
    }

    /// Set stdout from a raw fd (e.g., PTY slave).
    ///
    /// # Safety
    /// The fd must be a valid open file descriptor. Ownership is transferred.
    #[cfg(unix)]
    pub unsafe fn stdout_from_fd(mut self, fd: std::os::unix::io::RawFd) -> Self {
        use std::os::unix::io::FromRawFd;
        self.cmd.stdout(Stdio::from_raw_fd(fd));
        self
    }

    /// Set stderr from a raw fd (e.g., PTY slave).
    ///
    /// # Safety
    /// The fd must be a valid open file descriptor. Ownership is transferred.
    #[cfg(unix)]
    pub unsafe fn stderr_from_fd(mut self, fd: std::os::unix::io::RawFd) -> Self {
        use std::os::unix::io::FromRawFd;
        self.cmd.stderr(Stdio::from_raw_fd(fd));
        self
    }

    /// Capture stdout.
    pub fn stdout_piped(mut self) -> Self {
        self.cmd.stdout(Stdio::piped());
        self
    }

    /// Capture stderr.
    pub fn stderr_piped(mut self) -> Self {
        self.cmd.stderr(Stdio::piped());
        self
    }

    /// Capture both stdout and stderr.
    pub fn capture_output(self) -> Self {
        self.stdout_piped().stderr_piped()
    }

    /// Spawn the command.
    pub fn spawn(mut self) -> std::io::Result<std::process::Child> {
        self.cmd.spawn()
    }

    /// Run and wait for status.
    pub fn status(mut self) -> std::io::Result<std::process::ExitStatus> {
        self.cmd.status()
    }
}
