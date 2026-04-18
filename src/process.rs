//! Process management utilities.
//!
//! This module provides utilities for managing child processes,
//! including signal handling and graceful shutdown.

use std::os::fd::IntoRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};

/// Flag indicating whether SIGCHLD handler has been installed.
static SIGCHLD_HANDLER_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Default timeout for graceful shutdown before SIGKILL.
pub const DEFAULT_STOP_TIMEOUT: Duration = Duration::from_secs(10);

/// Default timeout for SIGKILL to take effect.
pub const SIGKILL_WAIT: Duration = Duration::from_millis(50);

/// Aggressive poll interval for fast process shutdown and agent readiness.
pub const FAST_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Number of aggressive polls before backing off to slower intervals.
pub const FAST_POLL_COUNT: u32 = 10;

/// Exit code returned when the actual exit status cannot be determined.
/// This happens when a process is confirmed dead but waitpid() fails to
/// retrieve the exit status (e.g., process was reaped by another handler).
pub const UNKNOWN_EXIT_CODE: i32 = -1;

/// Install a SIGCHLD handler to automatically reap zombie child processes.
///
/// This function installs a signal handler that calls waitpid(-1, WNOHANG) to
/// reap any terminated child processes, preventing zombie accumulation.
///
/// The handler is only installed once; subsequent calls are no-ops.
///
/// # Safety
///
/// This function installs a signal handler which must be async-signal-safe.
/// The handler only calls waitpid() which is safe.
pub fn install_sigchld_handler() {
    // Only install once
    if SIGCHLD_HANDLER_INSTALLED.swap(true, Ordering::SeqCst) {
        return;
    }

    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = sigchld_handler as *const () as usize;
        sa.sa_flags = libc::SA_RESTART | libc::SA_NOCLDSTOP;
        libc::sigemptyset(&mut sa.sa_mask);

        if libc::sigaction(libc::SIGCHLD, &sa, std::ptr::null_mut()) != 0 {
            // Failed to install handler, reset flag
            SIGCHLD_HANDLER_INSTALLED.store(false, Ordering::SeqCst);
            tracing::warn!("failed to install SIGCHLD handler");
        } else {
            tracing::debug!("installed SIGCHLD handler for zombie reaping");
        }
    }
}

/// SIGCHLD signal handler that reaps zombie children.
///
/// This handler is async-signal-safe as it only calls waitpid().
extern "C" fn sigchld_handler(_sig: libc::c_int) {
    // Reap all terminated children (non-blocking)
    // Loop until no more children to reap
    loop {
        let result = unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) };
        if result <= 0 {
            // No more children to reap (0) or error (-1)
            break;
        }
        // Successfully reaped a child, continue to check for more
    }
}

/// Check if a process is alive.
///
/// Returns true if the process exists and is running.
pub fn is_alive(pid: libc::pid_t) -> bool {
    unsafe { libc::kill(pid, 0) == 0 }
}

/// Wait for a process to exit (non-blocking check).
///
/// Returns `Some(exit_code)` if the process has exited, `None` if still running.
/// Handles EINTR by retrying the waitpid call.
pub fn try_wait(pid: libc::pid_t) -> Option<i32> {
    loop {
        let mut status: libc::c_int = 0;
        let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };

        if result == pid {
            // Process exited
            let exit_code = if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else if libc::WIFSIGNALED(status) {
                128 + libc::WTERMSIG(status)
            } else {
                -1
            };
            return Some(exit_code);
        } else if result < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                // EINTR - interrupted by signal, retry
                continue;
            }
            // ECHILD: not our child (e.g., session-leader reparented to init).
            // Return None so callers fall back to is_alive() (kill -0) polling.
            return None;
        } else {
            // Still running
            return None;
        }
    }
}

/// Wait for a process to exit (blocking).
///
/// Returns the exit code. Handles EINTR by retrying the waitpid call.
pub fn wait(pid: libc::pid_t) -> i32 {
    loop {
        let mut status: libc::c_int = 0;
        let result = unsafe { libc::waitpid(pid, &mut status, 0) };

        if result < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                // EINTR - interrupted by signal, retry
                continue;
            }
            return -1;
        }

        return if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else if libc::WIFSIGNALED(status) {
            128 + libc::WTERMSIG(status)
        } else {
            -1
        };
    }
}

/// Send SIGTERM to a process.
///
/// Returns true if the signal was sent successfully.
pub fn terminate(pid: libc::pid_t) -> bool {
    unsafe { libc::kill(pid, libc::SIGTERM) == 0 }
}

/// Send SIGKILL to a process.
///
/// Returns true if the signal was sent successfully.
pub fn kill(pid: libc::pid_t) -> bool {
    unsafe { libc::kill(pid, libc::SIGKILL) == 0 }
}

/// Get the start time of a process (seconds since epoch).
///
/// Used alongside PID to create a stable process identity that survives
/// PID reuse. If the process at a given PID has a different start time
/// than expected, it's a different process (PID was recycled).
#[cfg(target_os = "macos")]
pub fn process_start_time(pid: libc::pid_t) -> Option<u64> {
    // Use proc_pidinfo(PROC_PIDTBSDINFO) — the modern macOS API for
    // process information, which has stable struct layouts.
    extern "C" {
        fn proc_pidinfo(
            pid: libc::c_int,
            flavor: libc::c_int,
            arg: u64,
            buffer: *mut libc::c_void,
            buffersize: libc::c_int,
        ) -> libc::c_int;
    }

    const PROC_PIDTBSDINFO: libc::c_int = 3;

    /// Subset of `struct proc_bsdinfo` from <libproc.h>.
    #[repr(C)]
    struct ProcBsdInfo {
        pbi_flags: u32,
        pbi_status: u32,
        pbi_xstatus: u32,
        pbi_pid: u32,
        pbi_ppid: u32,
        pbi_uid: u32,
        pbi_gid: u32,
        pbi_ruid: u32,
        pbi_rgid: u32,
        pbi_svuid: u32,
        pbi_svgid: u32,
        _rfu_1: u32,
        pbi_comm: [u8; 16], // MAXCOMLEN
        pbi_name: [u8; 32], // 2 * MAXCOMLEN
        pbi_nfiles: u32,
        pbi_pgid: u32,
        pbi_pjobc: u32,
        e_tdev: u32,
        e_tpgid: u32,
        pbi_nice: i32,
        pbi_start_tvsec: u64,
        pbi_start_tvusec: u64,
    }

    let mut info: ProcBsdInfo = unsafe { std::mem::zeroed() };
    let ret = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDTBSDINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            std::mem::size_of::<ProcBsdInfo>() as libc::c_int,
        )
    };
    if ret > 0 {
        let usec = info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec;
        // proc_pidinfo can return a zeroed struct for session-leader children
        // (e.g., VM processes that called setsid()). Treat 0 as unavailable.
        if usec > 0 {
            Some(usec)
        } else {
            None
        }
    } else {
        None
    }
}

/// Get the start time of a process (clock ticks since boot from /proc/pid/stat field 22).
#[cfg(target_os = "linux")]
pub fn process_start_time(pid: libc::pid_t) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    // Format: pid (comm) state ppid ... starttime ...
    // comm can contain spaces and parentheses, so find the last ')' first.
    let after_comm = stat.rfind(')')? + 2;
    let fields: Vec<&str> = stat.get(after_comm..)?.split_whitespace().collect();
    // After ") ", fields are: state(0) ppid(1) ... starttime(19)
    fields.get(19)?.parse::<u64>().ok()
}

/// Get the start time of a process (stub for unsupported platforms).
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn process_start_time(_pid: libc::pid_t) -> Option<u64> {
    None
}

/// Backward-compatible start time comparison.
///
/// Handles the transition from seconds to microseconds on macOS: old records
/// stored seconds (~10^9), new code returns microseconds (~10^15). Values below
/// 10^12 are treated as seconds and compared at second granularity.
fn start_time_matches(actual: u64, expected: u64) -> bool {
    if actual == expected {
        return true;
    }
    // Backward compat: old macOS records stored seconds, new code uses microseconds.
    // Seconds-epoch values are < 10^12; microsecond values are > 10^15.
    if expected < 1_000_000_000_000 && actual >= 1_000_000_000_000 {
        return actual / 1_000_000 == expected;
    }
    false
}

/// Check if a PID belongs to our process by verifying start time.
///
/// If `expected_start_time` is None (legacy records), falls back to PID-only check.
/// Use [`is_our_process_strict`] for signal/kill paths where false positives are dangerous.
pub fn is_our_process(pid: libc::pid_t, expected_start_time: Option<u64>) -> bool {
    if !is_alive(pid) {
        return false;
    }
    if let Some(expected) = expected_start_time {
        match process_start_time(pid) {
            Some(actual) => start_time_matches(actual, expected),
            None => false,
        }
    } else {
        // Legacy record without start time — assume ours for status checks
        true
    }
}

/// Strict version of [`is_our_process`] for signal/kill paths.
///
/// Returns `false` when start time is missing (legacy records) rather than
/// assuming the PID is ours. Prevents accidentally signaling an unrelated
/// process that reused the same PID.
pub fn is_our_process_strict(pid: libc::pid_t, expected_start_time: Option<u64>) -> bool {
    if !is_alive(pid) {
        return false;
    }
    match expected_start_time {
        Some(expected) => match process_start_time(pid) {
            Some(actual) => start_time_matches(actual, expected),
            None => false,
        },
        None => {
            tracing::warn!(
                pid,
                "refusing to verify process without start time (legacy record)"
            );
            false
        }
    }
}

/// Send SIGTERM only if the PID still belongs to our process.
///
/// Uses strict verification — refuses to signal without start time.
pub fn terminate_verified(pid: libc::pid_t, start_time: Option<u64>) -> bool {
    if is_our_process_strict(pid, start_time) {
        terminate(pid)
    } else {
        false
    }
}

/// Send SIGKILL only if the PID still belongs to our process.
///
/// Uses strict verification — refuses to signal without start time.
pub fn kill_verified(pid: libc::pid_t, start_time: Option<u64>) -> bool {
    if is_our_process_strict(pid, start_time) {
        kill(pid)
    } else {
        false
    }
}

/// Gracefully stop a process.
///
/// 1. Sends SIGTERM
/// 2. Waits up to `timeout` for graceful exit
/// 3. If still running and `force` is true, sends SIGKILL
///
/// Returns `Ok(exit_code)` on success, `Err` if timeout without force.
pub fn stop_process(pid: libc::pid_t, timeout: Duration, force: bool) -> Result<i32> {
    // Check if already dead
    if !is_alive(pid) {
        // Try to reap zombie
        if let Some(code) = try_wait(pid) {
            return Ok(code);
        }
        return Ok(0);
    }

    // Send SIGTERM
    if !terminate(pid) {
        // Process already dead - signal couldn't be sent.
        // Try to get exit code; if unavailable (e.g., already reaped), use unknown.
        return Ok(try_wait(pid).unwrap_or(UNKNOWN_EXIT_CODE));
    }

    // Wait for graceful exit
    let start = Instant::now();
    let poll_interval = Duration::from_millis(100);

    while start.elapsed() < timeout {
        if let Some(code) = try_wait(pid) {
            return Ok(code);
        }

        if !is_alive(pid) {
            // Process died during wait - get exit code or return unknown.
            return Ok(try_wait(pid).unwrap_or(UNKNOWN_EXIT_CODE));
        }

        std::thread::sleep(poll_interval);
    }

    // Timeout reached
    if force {
        tracing::debug!(pid = pid, "SIGTERM timeout, sending SIGKILL");
        kill(pid);

        // Wait for SIGKILL to take effect
        std::thread::sleep(SIGKILL_WAIT);

        // Reap the process
        Ok(wait(pid))
    } else {
        Err(Error::agent(
            "stop process",
            format!("timeout waiting for process {} to stop", pid),
        ))
    }
}

/// Optimized process stop with aggressive polling for fast response.
///
/// This version uses a two-phase polling strategy:
/// 1. Aggressive polling (10ms intervals) for the first 100ms
/// 2. Backs off to 100ms intervals for the remainder
///
/// This minimizes latency for processes that exit quickly while
/// still being efficient for slower shutdowns.
pub fn stop_process_fast(pid: libc::pid_t, timeout: Duration, force: bool) -> Result<i32> {
    // Check if already dead
    if !is_alive(pid) {
        if let Some(code) = try_wait(pid) {
            return Ok(code);
        }
        return Ok(0);
    }

    // Send SIGTERM
    if !terminate(pid) {
        return Ok(try_wait(pid).unwrap_or(UNKNOWN_EXIT_CODE));
    }

    // Two-phase polling: aggressive first, then back off
    let start = Instant::now();
    let mut poll_count: u32 = 0;

    while start.elapsed() < timeout {
        // Check immediately, then poll
        if let Some(code) = try_wait(pid) {
            return Ok(code);
        }

        if !is_alive(pid) {
            return Ok(try_wait(pid).unwrap_or(UNKNOWN_EXIT_CODE));
        }

        // Aggressive polling for first ~100ms, then back off
        let poll_interval = if poll_count < FAST_POLL_COUNT {
            FAST_POLL_INTERVAL // 10ms
        } else {
            Duration::from_millis(100)
        };
        poll_count += 1;

        std::thread::sleep(poll_interval);
    }

    // Timeout reached
    if force {
        tracing::debug!(pid = pid, "SIGTERM timeout, sending SIGKILL");
        kill(pid);

        // Brief wait then poll for exit
        std::thread::sleep(SIGKILL_WAIT);
        Ok(try_wait(pid).unwrap_or_else(|| wait(pid)))
    } else {
        Err(Error::agent(
            "stop process",
            format!("timeout waiting for process {} to stop", pid),
        ))
    }
}

/// Default SIGTERM timeout for VM processes (3 seconds).
///
/// Generous to accommodate guest shutdown + Hypervisor.framework teardown.
pub const VM_SIGTERM_TIMEOUT: Duration = Duration::from_secs(3);

/// Default SIGKILL timeout for VM processes (3 seconds).
///
/// On macOS, Hypervisor.framework VMs can be in uninterruptible kernel state
/// (`hv_vcpu_run`). Even SIGKILL may take 1-3 seconds while the kernel tears
/// down VM resources. This timeout must be long enough for that cleanup.
pub const VM_SIGKILL_TIMEOUT: Duration = Duration::from_secs(3);

/// Stop a VM process with Hypervisor-aware timeouts.
///
/// Two-phase shutdown:
/// 1. SIGTERM → poll up to `sigterm_timeout` with early exit
/// 2. If still alive: SIGKILL → poll up to `sigkill_timeout` with early exit
///
/// Callers must verify process identity BEFORE calling this function.
///
/// Returns `Ok(exit_code)` if the process exited, `Err` if still alive.
pub fn stop_vm_process(
    pid: libc::pid_t,
    sigterm_timeout: Duration,
    sigkill_timeout: Duration,
) -> Result<i32> {
    if !is_alive(pid) {
        return Ok(try_wait(pid).unwrap_or(UNKNOWN_EXIT_CODE));
    }

    // Phase 1: SIGTERM + poll
    if !terminate(pid) {
        return Ok(try_wait(pid).unwrap_or(UNKNOWN_EXIT_CODE));
    }

    if let Some(code) = poll_for_exit(pid, sigterm_timeout) {
        return Ok(code);
    }

    // Phase 2: SIGKILL + poll
    tracing::debug!(pid, "SIGTERM timeout, sending SIGKILL");
    kill(pid);

    if let Some(code) = poll_for_exit(pid, sigkill_timeout) {
        return Ok(code);
    }

    Err(Error::agent(
        "stop vm process",
        format!("process {} still alive after SIGTERM+SIGKILL", pid),
    ))
}

/// Poll for process exit with aggressive-then-backoff strategy.
///
/// Returns `Some(exit_code)` if the process exits within the timeout.
fn poll_for_exit(pid: libc::pid_t, timeout: Duration) -> Option<i32> {
    let start = Instant::now();
    let mut poll_count: u32 = 0;

    while start.elapsed() < timeout {
        if let Some(code) = try_wait(pid) {
            return Some(code);
        }
        if !is_alive(pid) {
            return Some(try_wait(pid).unwrap_or(UNKNOWN_EXIT_CODE));
        }

        let interval = if poll_count < FAST_POLL_COUNT {
            FAST_POLL_INTERVAL
        } else {
            Duration::from_millis(100)
        };
        poll_count += 1;
        std::thread::sleep(interval);
    }
    None
}

/// Result of a fork operation.
#[derive(Debug)]
pub enum ForkResult {
    /// This is the parent process. Contains the child's PID.
    Parent(libc::pid_t),
    /// This is the child process.
    Child,
}

/// Fork a child process that becomes a session leader.
///
/// This function provides a safe interface to fork a child process and
/// have it call `setsid()` to become a session leader. This is commonly
/// used to detach VM processes from the parent's session so they survive
/// if the parent is killed.
///
/// # Arguments
///
/// * `child_fn` - A closure to run in the child process. The closure must
///   never return - it should either call `std::process::exit()` or exec
///   another program.
///
/// # Returns
///
/// * `Ok(pid)` - The child's PID if this is the parent process
/// * `Err` - If the fork failed
///
/// # Example
///
/// ```ignore
/// let child_pid = fork_session_leader(|| {
///     // This runs in the child process as a session leader
///     launch_vm(...);
///     std::process::exit(0);
/// })?;
/// ```
pub fn fork_session_leader<F>(child_fn: F) -> Result<libc::pid_t>
where
    F: FnOnce(),
{
    // SAFETY: fork() creates a new process. The child inherits the parent's
    // memory space as copy-on-write. We must be careful not to:
    // - Hold any locks across fork (we don't)
    // - Use async-signal-unsafe functions in the child before exec
    //
    // The child immediately calls setsid() and then the user-provided closure,
    // which is expected to exec or exit.
    let pid = unsafe { libc::fork() };

    match pid {
        -1 => {
            // Fork failed
            let err = std::io::Error::last_os_error();
            Err(Error::vm_creation(format!("fork failed: {}", err)))
        }
        0 => {
            // Child process
            //
            // SAFETY: setsid() is safe to call immediately after fork.
            // It creates a new session and makes this process the session leader,
            // detaching it from the parent's controlling terminal.
            unsafe {
                libc::setsid();
            }

            // Close inherited file descriptors to prevent holding parent's
            // database locks, sockets, and other resources. Keep stdin(0),
            // stdout(1), stderr(2) for error output during child setup.
            // The child opens fresh fds for everything it needs.
            unsafe {
                #[cfg(target_os = "linux")]
                {
                    // Use close_range() (Linux 5.9+) for O(1) fd closure instead
                    // of iterating through potentially 500K+ fds one at a time.
                    let ret = libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32);
                    if ret != 0 {
                        // Fallback for older kernels
                        let max_fd = libc::getdtablesize();
                        for fd in 3..max_fd {
                            libc::close(fd);
                        }
                    }
                }
                #[cfg(not(target_os = "linux"))]
                {
                    // macOS: no close_range syscall, but getdtablesize() is
                    // typically small (e.g. 1024) so iteration is fast.
                    let max_fd = libc::getdtablesize();
                    for fd in 3..max_fd {
                        libc::close(fd);
                    }
                }
            }

            // Run the user-provided closure
            child_fn();

            // If the closure returns (it shouldn't), exit with error
            //
            // SAFETY: _exit() is safe in the child after fork. We use _exit()
            // instead of exit() to avoid running atexit handlers and flushing
            // stdio buffers that were inherited from the parent.
            unsafe {
                libc::_exit(1);
            }
        }
        child_pid => {
            // Parent process
            Ok(child_pid)
        }
    }
}

/// Redirect stdin, stdout, and stderr to `/dev/null`.
///
/// Call this in a forked child process before launching a long-running
/// background task (e.g. a VM via `krun_start_enter`). Without this,
/// the child inherits the parent's terminal file descriptors and libkrun's
/// internal threads may read from stdin or set terminal attributes,
/// stealing keystrokes from the user's shell.
///
/// Must be called **after** any `eprintln!()` diagnostics that need the
/// real stderr, but **before** the point of no return (`krun_start_enter`).
pub fn detach_stdio() {
    unsafe {
        let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if devnull >= 0 {
            libc::dup2(devnull, 0); // stdin
            libc::dup2(devnull, 1); // stdout
            libc::dup2(devnull, 2); // stderr
            if devnull > 2 {
                libc::close(devnull);
            }
        }
    }
}

/// Redirect stdin/stdout to `/dev/null` and stderr to a log file.
///
/// This keeps background children detached from the user's terminal while
/// preserving boot-time diagnostics for later inspection.
pub fn detach_stdio_to_stderr_file(path: &std::path::Path) -> std::io::Result<()> {
    let stderr_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    let stderr_fd = stderr_file.into_raw_fd();

    unsafe {
        let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if devnull < 0 {
            libc::close(stderr_fd);
            return Err(std::io::Error::last_os_error());
        }

        libc::dup2(devnull, 0); // stdin
        libc::dup2(devnull, 1); // stdout
        libc::dup2(stderr_fd, 2); // stderr

        if devnull > 2 {
            libc::close(devnull);
        }
        if stderr_fd > 2 {
            libc::close(stderr_fd);
        }
    }

    Ok(())
}

/// Exit the current process immediately without cleanup.
///
/// This is a safe wrapper around `libc::_exit()` for use in forked child
/// processes. It avoids running atexit handlers and flushing stdio buffers
/// that were inherited from the parent.
///
/// # Safety
///
/// This function never returns. It should only be called in a forked child
/// process after fork() to avoid double-flushing stdio buffers.
pub fn exit_child(code: i32) -> ! {
    // SAFETY: _exit() is safe in a forked child process. Using _exit() instead
    // of exit() ensures we don't run atexit handlers or flush stdio buffers
    // that were inherited from the parent process.
    unsafe {
        libc::_exit(code);
    }
}

/// A handle to a running child process.
///
/// Provides methods to check status, stop, and kill the process.
#[derive(Debug)]
pub struct ChildProcess {
    pid: libc::pid_t,
    /// Start time captured at creation for PID reuse detection.
    start_time: Option<u64>,
    exit_code: Option<i32>,
}

impl ChildProcess {
    /// Create a new child process handle, capturing start time immediately.
    pub fn new(pid: libc::pid_t) -> Self {
        Self {
            pid,
            start_time: process_start_time(pid),
            exit_code: None,
        }
    }

    /// Get the process ID.
    pub fn pid(&self) -> libc::pid_t {
        self.pid
    }

    /// Get the start time captured when this handle was created.
    pub fn start_time(&self) -> Option<u64> {
        self.start_time
    }

    /// Check if the process is still running.
    pub fn is_running(&mut self) -> bool {
        if self.exit_code.is_some() {
            return false;
        }

        if let Some(code) = try_wait(self.pid) {
            self.exit_code = Some(code);
            false
        } else {
            is_alive(self.pid)
        }
    }

    /// Get the exit code if the process has exited.
    pub fn exit_code(&mut self) -> Option<i32> {
        if self.exit_code.is_none() {
            self.exit_code = try_wait(self.pid);
        }
        self.exit_code
    }

    /// Wait for the process to exit (blocking).
    pub fn wait(&mut self) -> i32 {
        if let Some(code) = self.exit_code {
            return code;
        }

        let code = wait(self.pid);
        self.exit_code = Some(code);
        code
    }

    /// Send SIGTERM to the process.
    pub fn terminate(&self) -> bool {
        terminate(self.pid)
    }

    /// Send SIGKILL to the process.
    pub fn kill(&self) -> bool {
        kill(self.pid)
    }

    /// Gracefully stop the process.
    ///
    /// Sends SIGTERM, waits for `timeout`, then SIGKILL if `force` is true.
    pub fn stop(&mut self, timeout: Duration, force: bool) -> Result<i32> {
        if let Some(code) = self.exit_code {
            return Ok(code);
        }

        let code = stop_process(self.pid, timeout, force)?;
        self.exit_code = Some(code);
        Ok(code)
    }
}

// ============================================================================
// SIGINT guard — kill a VM child process on Ctrl+C
// ============================================================================

/// PID for the SIGINT handler to kill on Ctrl+C.
/// Set by [`SigintGuard::new`], cleared on drop/disarm.
static SIGINT_CHILD_PID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

/// RAII guard that ensures a VM child process is killed on Ctrl+C.
///
/// Without this, SIGINT terminates the parent immediately (default handler)
/// without running Rust destructors, so [`AgentManager::drop`] never fires
/// and the `setsid()`-detached VM child is orphaned.
///
/// The signal handler only calls `kill()` and `_exit()` (async-signal-safe).
pub struct SigintGuard(());

impl SigintGuard {
    /// Install a SIGINT handler that will SIGTERM+SIGKILL the given PID.
    pub fn new(pid: libc::pid_t) -> Self {
        SIGINT_CHILD_PID.store(pid, Ordering::SeqCst);
        unsafe {
            libc::signal(
                libc::SIGINT,
                sigint_kill_handler as *const () as libc::sighandler_t,
            );
        }
        Self(())
    }

    /// Disarm the guard: clear the PID, restore default handler, skip Drop.
    ///
    /// Use when transitioning to a phase with its own SIGINT handling
    /// (e.g., interactive exec).
    pub fn disarm(self) {
        SIGINT_CHILD_PID.store(0, Ordering::SeqCst);
        unsafe {
            libc::signal(libc::SIGINT, libc::SIG_DFL);
        }
        std::mem::forget(self);
    }
}

impl Drop for SigintGuard {
    fn drop(&mut self) {
        SIGINT_CHILD_PID.store(0, Ordering::SeqCst);
        unsafe {
            libc::signal(libc::SIGINT, libc::SIG_DFL);
        }
    }
}

/// SIGINT handler: SIGTERM the child, brief busy-wait, escalate to SIGKILL, then _exit.
///
/// SAFETY: Only calls `kill()` and `_exit()`, both async-signal-safe.
extern "C" fn sigint_kill_handler(_sig: libc::c_int) {
    let pid = SIGINT_CHILD_PID.load(Ordering::SeqCst);
    if pid > 0 {
        unsafe {
            libc::kill(pid, libc::SIGTERM);
            for _ in 0..10 {
                if libc::kill(pid, 0) != 0 {
                    break;
                }
            }
            if libc::kill(pid, 0) == 0 {
                libc::kill(pid, libc::SIGKILL);
            }
        }
    }
    unsafe {
        libc::_exit(128 + libc::SIGINT);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_alive_self() {
        // Current process should be alive
        let pid = unsafe { libc::getpid() };
        assert!(is_alive(pid));
    }

    #[test]
    fn test_is_alive_nonexistent() {
        // PID 99999999 is unlikely to exist
        assert!(!is_alive(99999999));
    }

    #[test]
    fn test_process_start_time_self() {
        let pid = unsafe { libc::getpid() };
        let start_time = process_start_time(pid);
        // On macOS and Linux this should return Some; on other platforms None
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        assert!(
            start_time.is_some(),
            "should get start time on this platform"
        );
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        assert!(start_time.is_none());
    }

    #[test]
    fn test_process_start_time_nonexistent() {
        assert!(process_start_time(99999999).is_none());
    }

    #[test]
    fn test_is_our_process_self() {
        let pid = unsafe { libc::getpid() };
        let start_time = process_start_time(pid);
        assert!(is_our_process(pid, start_time));
    }

    #[test]
    fn test_is_our_process_wrong_start_time() {
        let pid = unsafe { libc::getpid() };
        // A start time far in the future should not match
        assert!(!is_our_process(pid, Some(u64::MAX)));
    }

    #[test]
    fn test_is_our_process_nonexistent() {
        assert!(!is_our_process(99999999, None));
        assert!(!is_our_process(99999999, Some(12345)));
    }

    #[test]
    fn test_is_our_process_strict_requires_start_time() {
        let pid = unsafe { libc::getpid() };
        // Strict refuses to verify without start time
        assert!(!is_our_process_strict(pid, None));
        // But works with valid start time
        let start_time = process_start_time(pid);
        if start_time.is_some() {
            assert!(is_our_process_strict(pid, start_time));
        }
    }

    #[test]
    fn test_start_time_matches_exact() {
        assert!(start_time_matches(12345, 12345));
        assert!(!start_time_matches(12345, 12346));
    }

    #[test]
    fn test_start_time_matches_backward_compat() {
        // Old record stored seconds (1_700_000_000), new code returns microseconds
        let old_seconds = 1_700_000_000u64;
        let new_micros = old_seconds * 1_000_000 + 500_000; // same second, different usec
        assert!(start_time_matches(new_micros, old_seconds));

        // Different second should not match
        assert!(!start_time_matches(new_micros, old_seconds + 1));
    }
}
