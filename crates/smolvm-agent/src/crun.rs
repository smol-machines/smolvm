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
    /// Trailing positional arguments (e.g. the container id for `crun run`, or
    /// the container id followed by the command for `crun exec`). Appended at
    /// the very end in `spawn`/`output`/`status` so options added later (e.g.
    /// `--console-socket` via `console_socket()`) still land before them.
    pending_positionals: Vec<String>,
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
        Self {
            cmd,
            pending_positionals: Vec::new(),
        }
    }

    /// Create a container: `crun create --bundle <path> <id>`
    ///
    /// This puts the container in "created" state, ready for `crun start`.
    /// Stdio defaults to null because capturing pipes can block when child
    /// processes inherit file descriptors.
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

    /// Run a container: `crun run [options] --bundle <path> <id>`
    ///
    /// Creates, starts, waits, and deletes the container in one operation.
    /// The container id is deferred so later builder calls (e.g.
    /// `console_socket`) can still insert options before the positional.
    pub fn run(bundle_dir: &Path, container_id: &str) -> Self {
        let mut c = Self::new();
        c.cmd
            .args(["run", "--bundle", &bundle_dir.to_string_lossy()]);
        c.pending_positionals = vec![container_id.to_string()];
        c
    }

    /// Run a container detached: `crun run --detach --bundle <path> <id>`
    ///
    /// Returns immediately after the container process is started. The container
    /// continues running independently. Use `crun state` to check status.
    pub fn run_detach(bundle_dir: &Path, container_id: &str) -> Self {
        let mut c = Self::new();
        c.cmd.args([
            "run",
            "--detach",
            "--bundle",
            &bundle_dir.to_string_lossy(),
            container_id,
        ]);
        c.cmd.stdin(Stdio::null());
        c.cmd.stdout(Stdio::null());
        c.cmd.stderr(Stdio::null());
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
    ///
    /// The container id and command are deferred (see `pending_positionals`) so
    /// later builder calls — notably `console_socket()` for the interactive TTY
    /// path — still insert their options before the positional arguments.
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
        c.pending_positionals = std::iter::once(container_id.to_string())
            .chain(command.iter().cloned())
            .collect();
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

    /// List all containers: `crun list -f json`
    ///
    /// Returns all containers in a single invocation, much faster than
    /// calling `crun state` per container during reconciliation.
    pub fn list() -> Self {
        let mut c = Self::new();
        c.cmd.args(["list", "-f", "json"]);
        c
    }

    /// Pass `--console-socket <path>` to the crun subcommand.
    ///
    /// With `process.terminal = true` in the OCI spec, crun will connect to
    /// this AF_UNIX socket and send the container's PTY master fd via
    /// `SCM_RIGHTS`. The caller must be listening on `path` before the crun
    /// process starts.
    pub fn console_socket(mut self, path: &Path) -> Self {
        self.cmd.args(["--console-socket", &path.to_string_lossy()]);
        self
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

    /// Append any deferred positional arguments right before the command is
    /// launched, so options added by the caller (e.g. `--console-socket`) land
    /// before them.
    fn apply_pending(&mut self) {
        for arg in std::mem::take(&mut self.pending_positionals) {
            self.cmd.arg(arg);
        }
    }

    /// Spawn the command.
    pub fn spawn(mut self) -> std::io::Result<std::process::Child> {
        self.apply_pending();
        self.cmd.spawn()
    }

    /// Run and wait for output.
    pub fn output(mut self) -> std::io::Result<std::process::Output> {
        self.apply_pending();
        self.cmd.output()
    }

    /// Run and wait for status.
    pub fn status(mut self) -> std::io::Result<std::process::ExitStatus> {
        self.apply_pending();
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
