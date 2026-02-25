//! Crun OCI runtime command builder.
//!
//! This module provides a consistent interface for invoking crun commands
//! with the correct configuration (cgroup-manager, etc.).

use std::path::Path;
use std::process::{Command, Stdio};

use crate::paths;

/// Default PATH for container execution.
///
/// This is passed explicitly when using `crun exec --env` because crun doesn't
/// preserve the container's PATH for command lookup when custom env vars are set.
pub const DEFAULT_CONTAINER_PATH: &str =
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Ensure PATH is included in environment variables for crun exec.
///
/// When crun exec is called with `--env`, it doesn't search PATH for executables
/// unless PATH is explicitly set. This function ensures PATH is always present.
fn ensure_path_in_env(env: &[(String, String)]) -> Vec<(String, String)> {
    let has_path = env.iter().any(|(k, _)| k == "PATH");
    if has_path {
        env.to_vec()
    } else {
        let mut result = env.to_vec();
        result.push(("PATH".to_string(), DEFAULT_CONTAINER_PATH.to_string()));
        result
    }
}

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

    /// Create a container: `crun create --bundle <path> <id>`
    ///
    /// This puts the container in "created" state, ready for `crun start`.
    /// Stdio is null because capturing pipes can block when child processes
    /// inherit file descriptors.
    pub fn create(bundle_dir: &Path, container_id: &str) -> Self {
        let mut c = Self::new();
        c.cmd.args([
            "create",
            "--bundle",
            &bundle_dir.to_string_lossy(),
            container_id,
        ]);
        c.cmd.stdin(Stdio::null());
        c.cmd.stdout(Stdio::null());
        c.cmd.stderr(Stdio::null());
        c
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

    /// Start a container: `crun start <id>`
    pub fn start(container_id: &str) -> Self {
        let mut c = Self::new();
        c.cmd.args(["start", container_id]);
        c
    }

    /// Execute a command in a running container.
    ///
    /// Supports optional working directory and TTY allocation.
    /// Automatically ensures PATH is set if not provided, because crun doesn't
    /// search PATH for executables when `--env` is used.
    pub fn exec(
        container_id: &str,
        env: &[(String, String)],
        command: &[String],
        workdir: Option<&str>,
        tty: bool,
    ) -> Self {
        let mut c = Self::new();
        c.cmd.arg("exec");
        if tty {
            c.cmd.arg("--tty");
        }
        // Ensure PATH is set for command lookup
        let env_with_path = ensure_path_in_env(env);
        for (key, value) in &env_with_path {
            c.cmd.arg("--env").arg(format!("{}={}", key, value));
        }
        if let Some(wd) = workdir {
            c.cmd.args(["--cwd", wd]);
        }
        c.cmd.arg(container_id).args(command);
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

    /// Get container state: `crun state <id>`
    pub fn state(container_id: &str) -> Self {
        let mut c = Self::new();
        c.cmd.args(["state", container_id]);
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

    /// Discard both stdout and stderr.
    pub fn discard_output(mut self) -> Self {
        self.cmd.stdout(Stdio::null());
        self.cmd.stderr(Stdio::null());
        self
    }

    /// Spawn the command.
    pub fn spawn(mut self) -> std::io::Result<std::process::Child> {
        self.cmd.spawn()
    }

    /// Run and wait for output.
    pub fn output(mut self) -> std::io::Result<std::process::Output> {
        self.cmd.output()
    }

    /// Run and wait for status.
    pub fn status(mut self) -> std::io::Result<std::process::ExitStatus> {
        self.cmd.status()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_container_path_value() {
        assert!(DEFAULT_CONTAINER_PATH.contains("/usr/bin"));
        assert!(DEFAULT_CONTAINER_PATH.contains("/bin"));
    }

    #[test]
    fn test_ensure_path_in_env_adds_path_when_missing() {
        let env = vec![("HOME".to_string(), "/root".to_string())];
        let result = ensure_path_in_env(&env);
        assert_eq!(result.len(), 2);
        assert!(result
            .iter()
            .any(|(k, v)| k == "PATH" && v == DEFAULT_CONTAINER_PATH));
    }

    #[test]
    fn test_ensure_path_in_env_preserves_existing_path() {
        let custom_path = "/custom/bin:/other/bin";
        let env = vec![("PATH".to_string(), custom_path.to_string())];
        let result = ensure_path_in_env(&env);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], ("PATH".to_string(), custom_path.to_string()));
    }

    #[test]
    fn test_ensure_path_in_env_empty_input() {
        let env: Vec<(String, String)> = vec![];
        let result = ensure_path_in_env(&env);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "PATH");
    }

    #[test]
    fn test_ensure_path_in_env_case_sensitive() {
        // "path" (lowercase) should not be treated as PATH
        let env = vec![("path".to_string(), "/lowercase".to_string())];
        let result = ensure_path_in_env(&env);
        assert_eq!(result.len(), 2);
        assert!(result.iter().any(|(k, _)| k == "PATH"));
    }
}
