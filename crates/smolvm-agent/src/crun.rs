//! Crun OCI runtime command builder.
//!
//! This module provides a consistent interface for invoking crun commands
//! with the correct configuration (cgroup-manager, etc.).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

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

/// Compose the environment used for an exec that joins a workload container.
///
/// Kept public within the agent so the restored-container namespace path and
/// ordinary `crun exec` receive the same PATH, CUDA, and Vulkan additions.
/// `container_id` identifies the container being joined: the Vulkan step only
/// pins a driver the container can actually see, so it has to know which one.
pub(crate) fn augmented_exec_env(
    env: &[(String, String)],
    container_id: &str,
) -> Vec<(String, String)> {
    crate::vulkan::augment_exec_env(
        crate::cuda::augment_exec_env(ensure_path_in_env(env)),
        container_id,
    )
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

/// Unique pid file for one foreground `crun exec` invocation.
///
/// The PID of the `crun` client is not the PID of the workload in the
/// container. Keeping the pid file alive until the wait completes lets timeout
/// and disconnect cleanup signal the workload itself, then removes the runtime
/// artifact on every return path.
pub struct ExecPidFile {
    path: PathBuf,
}

impl ExecPidFile {
    pub fn new() -> std::io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(1);

        std::fs::create_dir_all(paths::CONTAINERS_RUN_DIR)?;
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = Path::new(paths::CONTAINERS_RUN_DIR)
            .join(format!("exec-{}-{sequence}.pid", std::process::id()));
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Signal the actual container workload recorded by crun. Returns false
    /// when crun did not create a valid pid file, in which case killing the
    /// foreground crun child remains the caller's fallback.
    pub fn kill_workload(&self) -> bool {
        let Some(pid) = read_pid_file(&self.path) else {
            return false;
        };
        // PID 1 is never a valid foreground exec target and must not be
        // signalled if a corrupt pid file is encountered.
        if pid <= 1 {
            return false;
        }
        kill_process_tree(pid)
    }
}

impl Drop for ExecPidFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn read_pid_file(path: &Path) -> Option<libc::pid_t> {
    std::fs::read_to_string(path)
        .ok()?
        .trim()
        .parse::<libc::pid_t>()
        .ok()
}

/// Stop a foreground exec process, discover its descendants while it can no
/// longer create more, then kill the entire tree. Killing only the pid crun
/// records leaks background children such as `sh -c 'worker & wait'`, which can
/// keep GPU memory, ports, and files live after the client has timed out.
fn kill_process_tree(root: libc::pid_t) -> bool {
    // SAFETY: `root` came from crun's pid file and was validated above.
    if unsafe { libc::kill(root, libc::SIGSTOP) } != 0 {
        return false;
    }

    let mut descendants = Vec::new();
    let mut pending = vec![root];
    let mut seen = std::collections::HashSet::from([root]);
    while let Some(pid) = pending.pop() {
        for child in process_children(pid) {
            if !seen.insert(child) {
                continue;
            }
            // Stop each child before walking its own children. Once every
            // discovered process is stopped, the tree is stable.
            unsafe {
                libc::kill(child, libc::SIGSTOP);
            }
            descendants.push(child);
            pending.push(child);
        }
    }

    // Children first avoids leaving work running after its parent disappears.
    for pid in descendants.into_iter().rev() {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
    }
    unsafe { libc::kill(root, libc::SIGKILL) == 0 }
}

fn process_children(pid: libc::pid_t) -> Vec<libc::pid_t> {
    std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children"))
        .unwrap_or_default()
        .split_whitespace()
        .filter_map(|child| child.parse().ok())
        .filter(|child| *child > 1)
        .collect()
}

/// Where crun records its own diagnostics for a [`CrunCommand::create`].
///
/// `crun create` hands its stdout and stderr to the container process, so the
/// builder cannot capture them to find out why a create failed. `--log` is the
/// one channel that carries crun's errors without touching container stdio.
pub fn create_log_path(container_id: &str) -> PathBuf {
    // Part of the id reaches here from a machine name, so it is reduced to
    // characters that cannot walk out of the run directory.
    let stem: String = container_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    Path::new(paths::CONTAINERS_RUN_DIR).join(format!("create-{stem}.log"))
}

/// Read back and remove the diagnostics crun recorded for a failed create.
/// Empty when crun logged nothing, so callers should fall back to stderr.
pub fn take_create_log(container_id: &str) -> String {
    let path = create_log_path(container_id);
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    let _ = std::fs::remove_file(&path);
    text.trim().to_string()
}

/// Best available explanation for a failed create: crun's log, its stderr when
/// the log is empty, and failing both the exit status -- which at least
/// distinguishes a rejected config from a crun that died on a signal.
pub fn create_failure_reason(container_id: &str, output: &std::process::Output) -> String {
    let logged = take_create_log(container_id);
    if !logged.is_empty() {
        return logged;
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stderr = stderr.trim();
    if !stderr.is_empty() {
        return stderr.to_string();
    }
    format!("crun {} and reported nothing", output.status)
}

impl CrunCommand {
    /// Create a new crun command with standard configuration.
    ///
    /// Uses `--root` to store container state on the persistent storage disk
    /// instead of the default `/run/crun`, which may not be writable when the
    /// rootfs is an overlayfs with an initramfs lower layer.
    fn new() -> Self {
        Self::new_with_cgroup(paths::CRUN_CGROUP_MANAGER)
    }

    /// Like [`new`](Self::new) but with an explicit cgroup manager. Pods pass
    /// `"cgroupfs"` (after delegating a writable cgroup2) so crun creates a
    /// per-container cgroup and enforces resource limits; everything else uses
    /// the `disabled` default (libkrun mounts cgroup2 read-only by default).
    fn new_with_cgroup(manager: &str) -> Self {
        let mut cmd = Command::new(paths::CRUN_PATH);
        cmd.args(["--root", paths::CRUN_ROOT_DIR]);
        cmd.args(["--cgroup-manager", manager]);
        Self {
            cmd,
            pending_positionals: Vec::new(),
        }
    }

    /// Create a container: `crun create --bundle <path> <id>`
    ///
    /// This puts the container in "created" state, ready for `crun start`.
    /// Stdio is null because the created container inherits it: capturing the
    /// pipes would make `output()` block until the container itself exits.
    /// crun's own diagnostics therefore go to [`create_log_path`], which a
    /// failed create reads back with [`take_create_log`].
    pub fn create(bundle_dir: &Path, container_id: &str) -> Self {
        let log_path = create_log_path(container_id);
        // A stale log from an earlier attempt would be misreported as this
        // one's reason, and crun refuses to start if it cannot open the file.
        let log_ready = std::fs::create_dir_all(paths::CONTAINERS_RUN_DIR).is_ok()
            && match std::fs::remove_file(&log_path) {
                Ok(()) => true,
                Err(e) => e.kind() == std::io::ErrorKind::NotFound,
            };
        let mut c = Self::new();
        if log_ready {
            c.cmd.args(["--log", &log_path.to_string_lossy()]);
        }
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
        Self::run_managed(bundle_dir, container_id, paths::CRUN_CGROUP_MANAGER)
    }

    /// [`run`](Self::run) with the cgroupfs manager, so crun creates a
    /// per-container cgroup and enforces the spec's resource limits (memory/
    /// pids → OOM). Only safe once cgroup2 is writable and delegated.
    pub fn run_cgroupfs(bundle_dir: &Path, container_id: &str) -> Self {
        Self::run_managed(bundle_dir, container_id, "cgroupfs")
    }

    fn run_managed(bundle_dir: &Path, container_id: &str, manager: &str) -> Self {
        let mut c = Self::new_with_cgroup(manager);
        c.cmd
            .args(["run", "--bundle", &bundle_dir.to_string_lossy()]);
        c.pending_positionals = vec![container_id.to_string()];
        c
    }

    /// Run a container with its console handed back over a socket:
    /// `crun run --bundle <path> --console-socket <sock> <id>`.
    ///
    /// crun creates the container's PTY and sends its master fd to `console_socket`
    /// (via SCM_RIGHTS), instead of relaying through crun's own stdio. This is the
    /// only way the agent can own the real console — and therefore drive window
    /// size / resize, which crun does not propagate in stdio-relay mode. crun's own
    /// stdio is unused, so it's nulled.
    pub fn run_with_console(bundle_dir: &Path, container_id: &str, console_socket: &Path) -> Self {
        Self::run_with_console_managed(
            bundle_dir,
            container_id,
            console_socket,
            paths::CRUN_CGROUP_MANAGER,
        )
    }

    /// [`run_with_console`](Self::run_with_console) with the cgroupfs manager
    /// (pod containers; see [`run_cgroupfs`](Self::run_cgroupfs)).
    pub fn run_with_console_cgroupfs(
        bundle_dir: &Path,
        container_id: &str,
        console_socket: &Path,
    ) -> Self {
        Self::run_with_console_managed(bundle_dir, container_id, console_socket, "cgroupfs")
    }

    fn run_with_console_managed(
        bundle_dir: &Path,
        container_id: &str,
        console_socket: &Path,
        manager: &str,
    ) -> Self {
        let mut c = Self::new_with_cgroup(manager);
        c.cmd.args([
            "run",
            "--bundle",
            &bundle_dir.to_string_lossy(),
            "--console-socket",
            &console_socket.to_string_lossy(),
            container_id,
        ]);
        c.cmd.stdin(Stdio::null());
        c.cmd.stdout(Stdio::null());
        // Pipe stderr so the caller can surface crun's reason if the console
        // handshake fails (and it falls back to a stdio PTY).
        c.cmd.stderr(Stdio::piped());
        c
    }

    /// `crun exec --tty --console-socket <sock> [--env ...] [--cwd <wd>] <id> <cmd...>`.
    /// The TTY counterpart to [`Self::exec`] that takes the console over a socket
    /// so the agent owns the real PTY master (for resize). crun's stdio is nulled.
    pub fn exec_with_console(
        container_id: &str,
        env: &[(String, String)],
        command: &[String],
        workdir: Option<&str>,
        console_socket: &Path,
    ) -> Self {
        let mut c = Self::new();
        c.cmd.arg("exec").arg("--tty");
        c.cmd.arg("--console-socket").arg(console_socket);
        let env_with_path = augmented_exec_env(env, container_id);
        for (key, value) in &env_with_path {
            c.cmd.arg("--env").arg(format!("{}={}", key, value));
        }
        if let Some(wd) = workdir {
            c.cmd.args(["--cwd", wd]);
        }
        // Defer the container id + command so `.user()` (and any later option)
        // can still insert flags before the positionals in `spawn`.
        c.pending_positionals = std::iter::once(container_id.to_string())
            .chain(command.iter().cloned())
            .collect();
        c.cmd.stdin(Stdio::null());
        c.cmd.stdout(Stdio::null());
        c.cmd.stderr(Stdio::piped());
        c
    }

    /// Run the exec/run as `--user UID[:GID]`. No-op when `user` is None. Used so
    /// `crun exec` honours the container's configured user (image `config.User` /
    /// CRI RunAsUser) — without it, exec defaults to uid 0.
    ///
    /// NOTE: crun's `--user` CLI flag accepts only a NUMERIC uid[:gid]; a username
    /// is rejected with "invalid USERSPEC specified" (unlike the OCI runtime
    /// spec's `process.user`, which `crun run` resolves). Callers must pass an
    /// already-resolved numeric spec — see `oci::resolve_exec_user_spec` (#632).
    /// Inserted before the deferred positional arguments.
    pub fn user(mut self, user: Option<&str>) -> Self {
        if let Some(u) = user.filter(|s| !s.is_empty()) {
            self.cmd.arg("--user").arg(u);
        }
        self
    }

    /// Ask crun to record the PID of the process launched inside the
    /// container. This is valid for foreground and detached `exec` commands.
    pub fn pid_file(mut self, path: &Path) -> Self {
        self.cmd.arg("--pid-file").arg(path);
        self
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
        // Ensure PATH is set for command lookup; forward CUDA zero-copy opt-in.
        let env_with_path = augmented_exec_env(env, container_id);
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

    /// Execute a command DETACHED inside a running container:
    /// `crun exec --detach <id> <cmd…>`. crun starts the process in the
    /// container's namespaces and returns immediately; the process keeps
    /// running as a child of the container's PID 1 (smolvm's child reaper)
    /// for the machine's lifetime — this is how a background exec (a dev
    /// server, an agent) survives across foreground execs, sharing the
    /// container view every other exec sees. Stdio is detached (no pipes to
    /// wait on), so the caller does not block.
    pub fn exec_detached(
        container_id: &str,
        env: &[(String, String)],
        command: &[String],
        workdir: Option<&str>,
        pid_file: Option<&Path>,
    ) -> Self {
        let mut c = Self::new();
        c.cmd.arg("exec").arg("--detach");
        if let Some(pf) = pid_file {
            // crun writes the detached process's PID here so the caller can
            // report it back (the run-background contract returns a PID).
            c.cmd.arg("--pid-file").arg(pf);
        }
        let env_with_path = augmented_exec_env(env, container_id);
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

    /// Execute a command in a running container from a full OCI Process spec:
    /// `crun exec --process <file> <id>`. Unlike the flag-based [`Self::exec`],
    /// this honors every field of the process — notably `user.additionalGids`
    /// (CRI SupplementalGroups), which crun exec has no flag for. Non-TTY
    /// (piped) stdio; the process file must set `terminal: false`.
    pub fn exec_with_process(container_id: &str, process_file: &Path) -> Self {
        let mut c = Self::new();
        c.cmd.arg("exec").arg("--process").arg(process_file);
        c.pending_positionals = vec![container_id.to_string()];
        c
    }

    /// Kill a container: `crun kill <id> <signal>`
    pub fn kill(container_id: &str, signal: &str) -> Self {
        let mut c = Self::new();
        c.cmd.args(["kill", container_id, signal]);
        c
    }

    /// Kill every process in a container: `crun kill --all <id> <signal>`
    ///
    /// Used by the pod-container path (`PodSignal { all: true }`). May fail
    /// when no per-container cgroup exists (cgroup manager is disabled);
    /// callers fall back to signalling the process tree directly.
    pub fn kill_all(container_id: &str, signal: &str) -> Self {
        let mut c = Self::new();
        c.cmd.args(["kill", "--all", container_id, signal]);
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

    #[test]
    fn read_pid_file_rejects_invalid_content() {
        let path =
            std::env::temp_dir().join(format!("smolvm-crun-pid-test-{}", std::process::id()));
        std::fs::write(&path, "not-a-pid\n").unwrap();
        assert_eq!(read_pid_file(&path), None);
        std::fs::write(&path, "4242\n").unwrap();
        assert_eq!(read_pid_file(&path), Some(4242));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn workload_cleanup_kills_background_descendants() {
        let mut shell = std::process::Command::new("/bin/sh")
            .args(["-c", "sleep 60 & wait"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let root = shell.id() as libc::pid_t;
        let mut children = Vec::new();
        for _ in 0..50 {
            children = process_children(root);
            if !children.is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(
            !children.is_empty(),
            "shell did not start its background child"
        );
        assert!(kill_process_tree(root));
        shell.wait().unwrap();
        for child in children {
            for _ in 0..50 {
                if !Path::new(&format!("/proc/{child}")).exists() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            assert!(
                !Path::new(&format!("/proc/{child}")).exists(),
                "background child {child} survived cleanup"
            );
        }
    }
}
