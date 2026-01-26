//! Process management utilities.
//!
//! This module provides utilities for managing child processes,
//! including signal handling and graceful shutdown.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};

/// Flag indicating whether SIGCHLD handler has been installed.
static SIGCHLD_HANDLER_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Default timeout for graceful shutdown before SIGKILL.
pub const DEFAULT_STOP_TIMEOUT: Duration = Duration::from_secs(10);

/// Default timeout for SIGKILL to take effect.
pub const SIGKILL_WAIT: Duration = Duration::from_millis(500);

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
pub fn try_wait(pid: libc::pid_t) -> Option<i32> {
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
        Some(exit_code)
    } else if result < 0 {
        // Error (process doesn't exist or not our child)
        Some(-1)
    } else {
        // Still running
        None
    }
}

/// Wait for a process to exit (blocking).
///
/// Returns the exit code.
pub fn wait(pid: libc::pid_t) -> i32 {
    let mut status: libc::c_int = 0;
    let result = unsafe { libc::waitpid(pid, &mut status, 0) };

    if result < 0 {
        return -1;
    }

    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        -1
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
        Err(Error::vm_creation(format!(
            "timeout waiting for process {} to stop",
            pid
        )))
    }
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
    exit_code: Option<i32>,
}

impl ChildProcess {
    /// Create a new child process handle.
    pub fn new(pid: libc::pid_t) -> Self {
        Self {
            pid,
            exit_code: None,
        }
    }

    /// Get the process ID.
    pub fn pid(&self) -> libc::pid_t {
        self.pid
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
}
