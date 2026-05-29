//! Process execution utilities for the smolvm agent.
//!
//! This module provides common helpers for spawning and managing child processes,
//! including timeout handling and output capture.

use std::io::Read;
use std::process::Child;
use std::time::{Duration, Instant};

/// Exit code used when a command is killed due to timeout.
pub const TIMEOUT_EXIT_CODE: i32 = 124;

/// Per-stream output cap for non-interactive exec. Vec<u8> is base64-encoded
/// in JSON frames (4/3 expansion). Two streams at this cap must fit within the
/// 32 MB frame limit with room for JSON overhead:
///   11 MiB × 2 × 4/3 ≈ 29.3 MiB encoded + ~2.7 MiB JSON headroom.
pub const MAX_EXEC_OUTPUT: usize = 11 * 1024 * 1024;

/// Maximum time to wait for reader threads to finish after the child is killed.
/// Guards against pathological cases where an inherited fd keeps a pipe open.
const READER_JOIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Captured output from a child process.
#[derive(Debug, Default)]
pub struct ChildOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Result of waiting for a child process.
#[derive(Debug)]
pub enum WaitResult {
    /// Process completed with the given exit code.
    Completed { exit_code: i32, output: ChildOutput },
    /// Process was killed due to timeout.
    TimedOut {
        output: ChildOutput,
        timeout_ms: u64,
    },
    /// Process was killed because the requesting client disconnected.
    /// Used to free the accept loop when the client gives up mid-exec.
    ClientDisconnected { output: ChildOutput },
}

/// Check whether the peer on `fd` has closed the connection.
///
/// Uses `recv(MSG_PEEK | MSG_DONTWAIT)` which is more reliable than `poll()`
/// on vsock — vsock's poll implementation doesn't always propagate POLLHUP
/// when the peer closes, but a zero-length peek is the canonical way to
/// detect half-closed sockets.
///
/// Returns `true` if the peer has closed OR the socket is in an error state.
/// Returns `false` if the socket is still alive OR we can't determine (fail
/// open — a bogus fd shouldn't cause us to kill a healthy child).
#[cfg(target_os = "linux")]
pub fn is_peer_closed(fd: std::os::unix::io::RawFd) -> bool {
    if fd < 0 {
        return false;
    }
    let mut buf = [0u8; 1];
    // SAFETY: buf is a valid write target, MSG_PEEK doesn't consume data.
    let rc = unsafe {
        libc::recv(
            fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    if rc == 0 {
        // Peer performed orderly shutdown (FIN received).
        return true;
    }
    if rc < 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        // EAGAIN/EWOULDBLOCK = no data but connection alive → peer still there.
        // Any other error (ECONNRESET, ENOTCONN, EBADF, etc.) → peer gone.
        return !matches!(errno, libc::EAGAIN | libc::EWOULDBLOCK);
    }
    // rc > 0: there's data in the buffer — connection is alive.
    false
}

#[cfg(not(target_os = "linux"))]
pub fn is_peer_closed(_fd: std::os::unix::io::RawFd) -> bool {
    false
}

/// Capture stdout and stderr from a child process.
///
/// Reads raw bytes — preserves binary output (image bytes, tarballs, etc.)
/// that `read_to_string` would truncate at the first non-UTF-8 byte.
///
/// # Safety note
///
/// Call this only AFTER the process has already exited (or been killed).
/// If the process is still running and has filled the pipe buffer (~64 KB on
/// Linux), reading blocks until the process exits — which it cannot do while
/// the pipe is full.  Prefer `spawn_pipe_drains` + `join_pipe_drains` when
/// the process is still running.
pub fn capture_child_output(child: &mut Child) -> ChildOutput {
    let mut output = ChildOutput::default();

    if let Some(mut stdout) = child.stdout.take() {
        let _ = stdout.read_to_end(&mut output.stdout);
    }
    if let Some(mut stderr) = child.stderr.take() {
        let _ = stderr.read_to_end(&mut output.stderr);
    }

    output
}

/// Start background threads that drain the child's stdout and stderr pipes.
///
/// This must be called BEFORE the wait loop so the pipes are continuously
/// drained while the process runs.  If a process fills the ~64 KB Linux pipe
/// buffer and nobody is reading, its next `write(2)` blocks and the process
/// can never exit — a classic pipe-deadlock.
///
/// Returns `(stdout_drain, stderr_drain)` join handles.  Call
/// `join_pipe_drains` to collect the output after the process has exited.
pub fn spawn_pipe_drains(
    child: &mut Child,
) -> (
    Option<std::thread::JoinHandle<Vec<u8>>>,
    Option<std::thread::JoinHandle<Vec<u8>>>,
) {
    let stdout_handle = child.stdout.take().map(|mut pipe| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = pipe.read_to_end(&mut buf);
            buf
        })
    });
    let stderr_handle = child.stderr.take().map(|mut pipe| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = pipe.read_to_end(&mut buf);
            buf
        })
    });
    (stdout_handle, stderr_handle)
}

/// Collect output from pipe-drain threads started by `spawn_pipe_drains`.
pub fn join_pipe_drains(
    stdout_handle: Option<std::thread::JoinHandle<Vec<u8>>>,
    stderr_handle: Option<std::thread::JoinHandle<Vec<u8>>>,
) -> ChildOutput {
    ChildOutput {
        stdout: stdout_handle
            .and_then(|h| h.join().ok())
            .unwrap_or_default(),
        stderr: stderr_handle
            .and_then(|h| h.join().ok())
            .unwrap_or_default(),
    }
}

/// Wait for a child process with optional timeout.
///
/// If timeout_ms is Some, the process will be killed after the timeout
/// and WaitResult::TimedOut will be returned.
///
/// The poll_interval_ms parameter controls how often we check for completion
/// (default: 10ms).
///
/// Handles EINTR (interrupted system call) by retrying the wait.
pub fn wait_with_timeout(
    child: &mut Child,
    timeout_ms: Option<u64>,
    poll_interval_ms: Option<u64>,
) -> std::io::Result<WaitResult> {
    let poll_interval = Duration::from_millis(poll_interval_ms.unwrap_or(10));
    let deadline = timeout_ms.map(|ms| Instant::now() + Duration::from_millis(ms));

    // Drain pipes in background threads so they never fill up and deadlock the child.
    let (stdout_drain, stderr_drain) = spawn_pipe_drains(child);

    loop {
        match try_wait_with_eintr(child) {
            Ok(Some(status)) => {
                // Process completed — join drains to get full output.
                let output = join_pipe_drains(stdout_drain, stderr_drain);
                let exit_code = status.code().unwrap_or(-1);
                return Ok(WaitResult::Completed { exit_code, output });
            }
            Ok(None) => {
                // Still running - check timeout
                if let Some(deadline) = deadline {
                    if Instant::now() >= deadline {
                        // Kill the process
                        let _ = child.kill();
                        let _ = child.wait();

                        // Collect any partial output from the drain threads.
                        let output = join_pipe_drains(stdout_drain, stderr_drain);

                        return Ok(WaitResult::TimedOut {
                            output,
                            timeout_ms: timeout_ms.unwrap_or(0),
                        });
                    }
                }

                // Sleep before checking again
                std::thread::sleep(poll_interval);
            }
            Err(e) => return Err(e),
        }
    }
}

/// Try to wait for a child process, handling EINTR by retrying.
///
/// EINTR can occur when a signal is delivered during the wait syscall.
/// This is not a real error - we should just retry the wait.
fn try_wait_with_eintr(child: &mut Child) -> std::io::Result<Option<std::process::ExitStatus>> {
    loop {
        match child.try_wait() {
            Ok(status) => return Ok(status),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                // EINTR - signal interrupted the syscall, retry
                continue;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Wait for a child process with timeout and custom timeout handler.
///
/// The on_timeout callback is called when the process times out, before
/// killing it. This allows for custom cleanup (e.g., killing containers).
///
/// Handles EINTR (interrupted system call) by retrying the wait.
pub fn wait_with_timeout_and_cleanup<F>(
    child: &mut Child,
    timeout_ms: Option<u64>,
    on_timeout: F,
) -> std::io::Result<WaitResult>
where
    F: FnOnce(),
{
    wait_with_timeout_cleanup_and_liveness(child, timeout_ms, None, on_timeout)
}

/// Wait for a child process, killing it if the timeout expires OR if the
/// requesting client disconnects (indicated by `client_fd`, which is polled
/// each iteration).
///
/// Stdout and stderr are drained concurrently in background threads to prevent
/// pipe deadlock: if the child writes more than the OS pipe buffer (~64KB),
/// it blocks on write() while the agent blocks waiting for exit — neither side
/// makes progress. The background threads consume pipe data continuously,
/// preventing backpressure from stalling the child.
///
/// The client-disconnect check is the short-term mitigation for BUG-12/20:
/// when the host-side exec client is SIGTERM'd or times out, the agent's
/// accept loop was left blocked on the still-running child. Now we kill the
/// child as soon as we detect the peer has closed the connection, freeing
/// the accept loop for the next request.
pub fn wait_with_timeout_cleanup_and_liveness<F>(
    child: &mut Child,
    timeout_ms: Option<u64>,
    client_fd: Option<std::os::unix::io::RawFd>,
    on_timeout: F,
) -> std::io::Result<WaitResult>
where
    F: FnOnce(),
{
    use std::sync::mpsc;

    const CHUNK_SIZE: usize = 64 * 1024;

    // Drain stdout/stderr in background threads BEFORE waiting for exit.
    // Threads send chunks via channels so the parent accumulates data
    // incrementally. On timeout/disconnect, already-received chunks are
    // preserved even if the reader thread is still blocked on a pipe that
    // hasn't reached EOF (e.g., background process inherited stdio).
    let (stdout_tx, stdout_rx) = mpsc::channel::<Vec<u8>>();
    let (stderr_tx, stderr_rx) = mpsc::channel::<Vec<u8>>();

    let stdout_handle = child.stdout.take().and_then(|mut out| {
        std::thread::Builder::new()
            .name("crun-stdout".into())
            .spawn(move || {
                let mut total = 0usize;
                loop {
                    let mut chunk = vec![0u8; CHUNK_SIZE];
                    match out.read(&mut chunk) {
                        Ok(0) => break, // EOF
                        Ok(n) => {
                            total += n;
                            chunk.truncate(n);
                            if stdout_tx.send(chunk).is_err() {
                                break; // receiver dropped
                            }
                            if total >= MAX_EXEC_OUTPUT {
                                break; // cap reached
                            }
                        }
                        Err(_) => break,
                    }
                }
            })
            .ok()
    });

    let stderr_handle = child.stderr.take().and_then(|mut err| {
        std::thread::Builder::new()
            .name("crun-stderr".into())
            .spawn(move || {
                let mut total = 0usize;
                loop {
                    let mut chunk = vec![0u8; CHUNK_SIZE];
                    match err.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => {
                            total += n;
                            chunk.truncate(n);
                            if stderr_tx.send(chunk).is_err() {
                                break;
                            }
                            if total >= MAX_EXEC_OUTPUT {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            })
            .ok()
    });

    // Accumulated output — grows as reader threads send chunks.
    let mut stdout_buf = Vec::new();
    let mut stderr_buf = Vec::new();

    let poll_interval = Duration::from_millis(10);
    let deadline = timeout_ms.map(|ms| Instant::now() + Duration::from_millis(ms));

    // Drain any available chunks from the channels into local buffers.
    let drain_channels = |stdout_rx: &mpsc::Receiver<Vec<u8>>,
                          stderr_rx: &mpsc::Receiver<Vec<u8>>,
                          stdout_buf: &mut Vec<u8>,
                          stderr_buf: &mut Vec<u8>| {
        for chunk in stdout_rx.try_iter() {
            stdout_buf.extend_from_slice(&chunk);
        }
        for chunk in stderr_rx.try_iter() {
            stderr_buf.extend_from_slice(&chunk);
        }
    };

    loop {
        // Drain available chunks each iteration so local buffers stay current.
        drain_channels(&stdout_rx, &stderr_rx, &mut stdout_buf, &mut stderr_buf);

        match try_wait_with_eintr(child) {
            Ok(Some(status)) => {
                // Child exited — give reader threads a bounded window to finish.
                // After the child dies, pipe write ends close and readers see EOF.
                // Use is_finished() on handles to detect completion without consuming
                // chunks (try_recv as a probe races and can drop data).
                let join_deadline = Instant::now() + READER_JOIN_TIMEOUT;
                while Instant::now() < join_deadline {
                    drain_channels(&stdout_rx, &stderr_rx, &mut stdout_buf, &mut stderr_buf);
                    let stdout_done = stdout_handle.as_ref().map_or(true, |h| h.is_finished());
                    let stderr_done = stderr_handle.as_ref().map_or(true, |h| h.is_finished());
                    if stdout_done && stderr_done {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                // Final drain after threads are done (or timed out).
                drain_channels(&stdout_rx, &stderr_rx, &mut stdout_buf, &mut stderr_buf);
                let exit_code = status.code().unwrap_or(-1);
                return Ok(WaitResult::Completed {
                    exit_code,
                    output: ChildOutput {
                        stdout: stdout_buf,
                        stderr: stderr_buf,
                    },
                });
            }
            Ok(None) => {
                if let Some(fd) = client_fd {
                    if is_peer_closed(fd) {
                        let _ = child.kill();
                        let _ = child.wait();
                        drain_channels(&stdout_rx, &stderr_rx, &mut stdout_buf, &mut stderr_buf);
                        return Ok(WaitResult::ClientDisconnected {
                            output: ChildOutput {
                                stdout: stdout_buf,
                                stderr: stderr_buf,
                            },
                        });
                    }
                }

                if let Some(deadline) = deadline {
                    if Instant::now() >= deadline {
                        on_timeout();
                        let _ = child.kill();
                        let _ = child.wait();
                        drain_channels(&stdout_rx, &stderr_rx, &mut stdout_buf, &mut stderr_buf);
                        return Ok(WaitResult::TimedOut {
                            output: ChildOutput {
                                stdout: stdout_buf,
                                stderr: stderr_buf,
                            },
                            timeout_ms: timeout_ms.unwrap_or(0),
                        });
                    }
                }

                std::thread::sleep(poll_interval);
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    #[test]
    fn test_timeout_exit_code_value() {
        // Matches the standard timeout command exit code
        assert_eq!(TIMEOUT_EXIT_CODE, 124);
    }

    #[test]
    fn test_child_output_default() {
        let output = ChildOutput::default();
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }

    #[test]
    fn test_capture_child_output_stdout() {
        let mut child = Command::new("echo")
            .arg("hello world")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();

        child.wait().unwrap();
        let output = capture_child_output(&mut child);

        assert!(output
            .stdout
            .windows(b"hello world".len())
            .any(|w| w == b"hello world"));
        assert!(output.stderr.is_empty());
    }

    #[test]
    fn test_capture_child_output_stderr() {
        let mut child = Command::new("sh")
            .args(["-c", "echo error >&2"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();

        child.wait().unwrap();
        let output = capture_child_output(&mut child);

        assert!(output.stdout.is_empty());
        assert!(output.stderr.windows(b"error".len()).any(|w| w == b"error"));
    }

    #[test]
    fn test_wait_completes_success() {
        let mut child = Command::new("echo")
            .arg("hello")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();

        let result = wait_with_timeout(&mut child, Some(5000), None).unwrap();

        match result {
            WaitResult::Completed { exit_code, output } => {
                assert_eq!(exit_code, 0);
                assert!(output.stdout.windows(b"hello".len()).any(|w| w == b"hello"));
            }
            WaitResult::TimedOut { .. } => panic!("unexpected timeout"),
            WaitResult::ClientDisconnected { .. } => panic!("unexpected client disconnect"),
        }
    }

    #[test]
    fn test_wait_completes_with_nonzero_exit() {
        let mut child = Command::new("sh")
            .args(["-c", "exit 42"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();

        let result = wait_with_timeout(&mut child, Some(5000), None).unwrap();

        match result {
            WaitResult::Completed { exit_code, .. } => {
                assert_eq!(exit_code, 42);
            }
            WaitResult::TimedOut { .. } => panic!("unexpected timeout"),
            WaitResult::ClientDisconnected { .. } => panic!("unexpected client disconnect"),
        }
    }

    #[test]
    fn test_wait_no_timeout() {
        // With timeout_ms = None, should wait indefinitely (process completes quickly)
        let mut child = Command::new("echo")
            .arg("quick")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();

        let result = wait_with_timeout(&mut child, None, None).unwrap();

        match result {
            WaitResult::Completed { exit_code, output } => {
                assert_eq!(exit_code, 0);
                assert!(output.stdout.windows(b"quick".len()).any(|w| w == b"quick"));
            }
            WaitResult::TimedOut { .. } => panic!("unexpected timeout"),
            WaitResult::ClientDisconnected { .. } => panic!("unexpected client disconnect"),
        }
    }

    #[test]
    fn test_wait_timeout() {
        let mut child = Command::new("sleep")
            .arg("10")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();

        let result = wait_with_timeout(&mut child, Some(50), None).unwrap();

        match result {
            WaitResult::TimedOut { timeout_ms, .. } => {
                assert_eq!(timeout_ms, 50);
            }
            WaitResult::Completed { .. } => panic!("expected timeout"),
            WaitResult::ClientDisconnected { .. } => panic!("unexpected client disconnect"),
        }
    }

    #[test]
    fn test_wait_custom_poll_interval() {
        let mut child = Command::new("echo")
            .arg("fast")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();

        // Use a custom poll interval of 1ms
        let result = wait_with_timeout(&mut child, Some(5000), Some(1)).unwrap();

        assert!(matches!(result, WaitResult::Completed { .. }));
    }

    #[test]
    fn test_wait_with_cleanup_calls_callback() {
        let callback_called = Arc::new(AtomicBool::new(false));
        let callback_called_clone = callback_called.clone();

        let mut child = Command::new("sleep")
            .arg("10")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();

        let result = wait_with_timeout_and_cleanup(&mut child, Some(50), || {
            callback_called_clone.store(true, Ordering::SeqCst);
        })
        .unwrap();

        assert!(matches!(result, WaitResult::TimedOut { .. }));
        assert!(
            callback_called.load(Ordering::SeqCst),
            "cleanup callback should be called"
        );
    }

    #[test]
    fn test_wait_with_cleanup_no_callback_on_success() {
        let callback_called = Arc::new(AtomicBool::new(false));
        let callback_called_clone = callback_called.clone();

        let mut child = Command::new("echo")
            .arg("done")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();

        let result = wait_with_timeout_and_cleanup(&mut child, Some(5000), || {
            callback_called_clone.store(true, Ordering::SeqCst);
        })
        .unwrap();

        assert!(matches!(result, WaitResult::Completed { .. }));
        assert!(
            !callback_called.load(Ordering::SeqCst),
            "cleanup callback should not be called on success"
        );
    }
}
