//! Process execution utilities for the smolvm agent.
//!
//! This module provides common helpers for spawning and managing child processes,
//! including timeout handling and output capture.

use std::io::Read;
use std::process::Child;
use std::time::{Duration, Instant};

const CONTAINER_INIT_ARG: &str = "container-init";

/// Whether this agent invocation is the image-independent init process used by
/// a persistent workload container.
pub fn container_init_requested() -> bool {
    std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new(CONTAINER_INIT_ARG))
}

/// Run a minimal PID-1 reaper for a persistent workload container.
///
/// Foreground execs can create background descendants. When timeout cleanup
/// kills that process tree, the descendants are reparented to container PID 1.
/// A passive keepalive such as `tail -f /dev/null` never waits for them and
/// therefore leaks zombies across execs. Block the relevant signals and use
/// `sigwait`, which closes the usual reap-before-sleep race without requiring
/// an async signal handler.
#[cfg(target_os = "linux")]
pub fn run_container_init() -> i32 {
    let mut signals = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    unsafe {
        libc::sigemptyset(&mut signals);
        libc::sigaddset(&mut signals, libc::SIGCHLD);
        libc::sigaddset(&mut signals, libc::SIGTERM);
        libc::sigaddset(&mut signals, libc::SIGINT);
    }
    if unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &signals, std::ptr::null_mut()) } != 0 {
        return 1;
    }

    loop {
        loop {
            let mut status = 0;
            let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
            if pid <= 0 {
                break;
            }
        }

        let mut signal = 0;
        if unsafe { libc::sigwait(&signals, &mut signal) } != 0 {
            return 1;
        }
        if signal == libc::SIGTERM || signal == libc::SIGINT {
            return 0;
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn run_container_init() -> i32 {
    1
}

/// Exit code used when a command is killed due to timeout.
pub const TIMEOUT_EXIT_CODE: i32 = 124;

/// Map a process exit status to a numeric exit code.
///
/// Normal exit → the process's exit code. Terminated by a signal (where
/// `ExitStatus::code()` is `None`) → `128 + signal`, matching shell
/// convention (SIGINT → 130, SIGTERM → 143), so callers and scripts can
/// distinguish a signal kill from a normal exit instead of seeing an
/// opaque 255.
pub fn exit_code_from_status(status: &std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    if let Some(code) = status.code() {
        code
    } else if let Some(sig) = status.signal() {
        128 + sig
    } else {
        -1
    }
}

/// Per-stream output cap for non-interactive exec. Vec<u8> is base64-encoded
/// in JSON frames (4/3 expansion). Two streams at this cap must fit within the
/// 32 MB frame limit with room for JSON overhead:
///   11 MiB × 2 × 4/3 ≈ 29.3 MiB encoded + ~2.7 MiB JSON headroom.
pub const MAX_EXEC_OUTPUT: usize = 11 * 1024 * 1024;

/// How long an exec that exited waits for the rest of its output. A process it
/// left running in the background (`sh -c 'server &'`) can hold the output
/// pipe open for as long as it lives; the reply goes out without waiting for it.
pub(crate) const READER_JOIN_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a killed exec waits for output still in flight before replying.
/// Every process holding the output pipe was killed with the command, so the
/// pipe normally closes at once; this only bounds the reply if one survived.
pub(crate) const KILLED_OUTPUT_GRACE: Duration = Duration::from_millis(500);

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

/// Kill `child` and every process descended from it, then reap `child`.
///
/// A command run in an image container is not the agent's child: the agent
/// spawns `crun exec` (or a namespace-entering helper) and the command is that
/// helper's child. Killing only the direct child orphans the command, which
/// keeps running in the container after its client disconnected or its timeout
/// passed. The agent's PID namespace contains the container's, so the whole
/// tree is visible in `/proc`.
///
/// Processes that left the tree are killed too when they still write to the
/// command's output: a child that double-forked or was re-parented holds the
/// pipe open, so the exec could not finish and would keep running after the
/// command was declared dead. Only the command's own output pipes count (ones
/// this process reads), never an inherited stdout other processes share.
pub fn kill_child_tree(child: &mut Child) {
    kill_tree(child, false);
}

/// [`kill_child_tree`] plus the child's process group, for a command spawned as
/// the leader of its own session.
pub fn kill_child_group_tree(child: &mut Child) {
    kill_tree(child, true);
}

fn kill_tree(child: &mut Child, group: bool) {
    #[cfg(target_os = "linux")]
    {
        let root = child.id();
        // Read before anything dies: the pipes go away with the child's fds.
        let pipes = own_output_pipes(root);
        freeze_and_kill(|| {
            let mut pids = live_descendants(root);
            pids.extend(pipe_writers(&pipes));
            pids
        });
        if group {
            // SAFETY: plain signal delivery. The child is not reaped yet, so
            // its pid still names its process group.
            unsafe { libc::killpg(root as libc::pid_t, libc::SIGKILL) };
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = group;
    let _ = child.kill();
    let _ = child.wait();
}

/// SIGKILL every process `scan` finds (never this one).
///
/// The set is frozen first: once an intermediate process dies its children are
/// re-parented and no longer look like descendants, and a live process could
/// fork between a walk and the kill. So SIGSTOP everything found, re-walk until
/// no new process appears (a stopped process cannot fork), then SIGKILL the
/// whole set. Bounded, so a fork bomb cannot pin the agent.
#[cfg(target_os = "linux")]
fn freeze_and_kill(mut scan: impl FnMut() -> Vec<u32>) {
    let me = std::process::id();
    let mut frozen = std::collections::BTreeSet::new();
    for _ in 0..32 {
        let fresh: Vec<u32> = scan()
            .into_iter()
            .filter(|pid| *pid != me && !frozen.contains(pid))
            .collect();
        if fresh.is_empty() {
            break;
        }
        for pid in fresh {
            // SAFETY: plain signal delivery to a PID read from /proc.
            unsafe { libc::kill(pid as libc::pid_t, libc::SIGSTOP) };
            frozen.insert(pid);
        }
    }
    for pid in frozen {
        // SAFETY: as above. A stopped process still dies on SIGKILL.
        unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
    }
}

/// Live (non-zombie) descendants of `root`, read from `/proc`.
#[cfg(target_os = "linux")]
fn live_descendants(root: u32) -> Vec<u32> {
    let mut children: std::collections::HashMap<u32, Vec<u32>> = Default::default();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            continue;
        };
        if let Some((state, ppid)) = parse_stat_state_ppid(&stat) {
            if state != 'Z' {
                children.entry(ppid).or_default().push(pid);
            }
        }
    }
    let mut found = Vec::new();
    let mut queue = vec![root];
    while let Some(pid) = queue.pop() {
        if let Some(kids) = children.get(&pid) {
            for &kid in kids {
                found.push(kid);
                queue.push(kid);
            }
        }
    }
    found
}

/// The pipes `pid` writes its stdout and stderr to that this process holds only
/// the read end of: the output pipes of a command this process spawned. A pipe
/// this process also writes (its own stdout handed down) is shared with other
/// processes, so it is left out.
#[cfg(target_os = "linux")]
fn own_output_pipes(pid: u32) -> Vec<String> {
    let mine = open_pipes(std::process::id());
    let ours = |link: &str| {
        mine.iter()
            .any(|(l, mode)| l == link && *mode == libc::O_RDONLY)
            && !mine
                .iter()
                .any(|(l, mode)| l == link && *mode != libc::O_RDONLY)
    };
    let mut pipes = Vec::new();
    for fd in [1, 2] {
        let Ok(link) = std::fs::read_link(format!("/proc/{pid}/fd/{fd}")) else {
            continue;
        };
        let link = link.to_string_lossy().into_owned();
        if link.starts_with("pipe:[") && ours(&link) && !pipes.contains(&link) {
            pipes.push(link);
        }
    }
    pipes
}

/// Every process other than this one that has one of `pipes` open for writing.
#[cfg(target_os = "linux")]
fn pipe_writers(pipes: &[String]) -> Vec<u32> {
    if pipes.is_empty() {
        return Vec::new();
    }
    let me = std::process::id();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
        .filter(|pid| *pid != me)
        .filter(|pid| {
            open_pipes(*pid)
                .iter()
                .any(|(link, mode)| *mode != libc::O_RDONLY && pipes.contains(link))
        })
        .collect()
}

/// `(pipe:[inode], access mode)` for every pipe `pid` has open.
#[cfg(target_os = "linux")]
fn open_pipes(pid: u32) -> Vec<(String, i32)> {
    let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for fd in fds.flatten() {
        let Ok(link) = std::fs::read_link(fd.path()) else {
            continue;
        };
        let link = link.to_string_lossy();
        if !link.starts_with("pipe:[") {
            continue;
        }
        let name = fd.file_name();
        let Some(mode) =
            std::fs::read_to_string(format!("/proc/{pid}/fdinfo/{}", name.to_string_lossy()))
                .ok()
                .and_then(|info| fdinfo_access_mode(&info))
        else {
            continue;
        };
        out.push((link.into_owned(), mode));
    }
    out
}

/// The access mode (`O_RDONLY`, `O_WRONLY`, `O_RDWR`) from a fdinfo file,
/// whose `flags:` line is octal.
#[cfg(target_os = "linux")]
fn fdinfo_access_mode(info: &str) -> Option<i32> {
    let flags = info.lines().find_map(|l| l.strip_prefix("flags:"))?.trim();
    Some(i32::from_str_radix(flags, 8).ok()? & libc::O_ACCMODE)
}

/// `(state, ppid)` from a `/proc/<pid>/stat` line. The command name is in
/// parentheses and may itself contain spaces or `)`, so fields are read after
/// the LAST `)`.
fn parse_stat_state_ppid(stat: &str) -> Option<(char, u32)> {
    let rest = stat.get(stat.rfind(')')? + 1..)?;
    let mut fields = rest.split_whitespace();
    let state = fields.next()?.chars().next()?;
    let ppid = fields.next()?.parse().ok()?;
    Some((state, ppid))
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
        // EAGAIN = no data but connection alive → peer still there. (EWOULDBLOCK
        // is the same value as EAGAIN on Linux.) Any other error (ECONNRESET,
        // ENOTCONN, EBADF, etc.) → peer gone.
        return !matches!(errno, libc::EAGAIN);
    }
    // rc > 0: there's data in the buffer — connection is alive.
    false
}

#[cfg(not(target_os = "linux"))]
pub fn is_peer_closed(_fd: std::os::unix::io::RawFd) -> bool {
    false
}

/// Receive `rx` into `buf` until its sender is gone or `deadline` passes.
pub(crate) fn drain_until_closed(
    rx: &std::sync::mpsc::Receiver<Vec<u8>>,
    buf: &mut Vec<u8>,
    deadline: Instant,
) {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(remaining) {
            Ok(chunk) => buf.extend_from_slice(&chunk),
            Err(_) => {
                // Disconnected (reader finished) or out of time: take whatever
                // arrived meanwhile and stop.
                buf.extend(rx.try_iter().flatten());
                return;
            }
        }
    }
}

/// Read `pipe` to EOF on a thread of its own and throw the bytes away.
///
/// For a command's output pipe after its reply went out: a process the command
/// left running in the background may still hold the pipe, and with no reader
/// its next write would kill it with SIGPIPE.
pub(crate) fn drain_in_background<P>(pipe: Option<P>)
where
    P: std::io::Read + std::os::unix::io::AsRawFd + Send + 'static,
{
    let Some(mut pipe) = pipe else {
        return;
    };
    // A session may have read it non-blocking.
    let fd = pipe.as_raw_fd();
    // SAFETY: fcntl on an fd this function owns.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags >= 0 && flags & libc::O_NONBLOCK != 0 {
            libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK);
        }
    }
    let _ = std::thread::Builder::new()
        .name("exec-drain".into())
        .spawn(move || {
            let mut buf = [0u8; 16 * 1024];
            loop {
                match pipe.read(&mut buf) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
        });
}

/// Wakes a waiter when a child exits: a pidfd that polls readable on exit.
/// Without one (a kernel older than 5.3), waiting is a plain sleep.
pub(crate) struct ExitSignal(#[cfg(target_os = "linux")] Option<std::os::fd::OwnedFd>);

impl ExitSignal {
    #[cfg(target_os = "linux")]
    pub(crate) fn open(child: &Child) -> Self {
        use std::os::fd::FromRawFd;
        // SAFETY: pidfd_open takes a pid and flags and returns a new fd or -1.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id() as libc::pid_t, 0) };
        // SAFETY: a non-negative return is a fresh fd this process owns.
        Self((fd >= 0).then(|| unsafe { std::os::fd::OwnedFd::from_raw_fd(fd as i32) }))
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn open(_child: &Child) -> Self {
        Self()
    }

    /// The pidfd, for callers that wait on it alongside other fds. It
    /// becomes readable when the child exits. `None` without pidfd support.
    pub(crate) fn raw_fd(&self) -> Option<std::os::fd::RawFd> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            self.0.as_ref().map(|fd| fd.as_raw_fd())
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }

    /// Return after `timeout`, or sooner if the child exits.
    pub(crate) fn wait(&self, timeout: Duration) {
        #[cfg(target_os = "linux")]
        if let Some(fd) = &self.0 {
            use std::os::fd::AsRawFd;
            let mut pollfd = libc::pollfd {
                fd: fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let ms = timeout.as_millis().clamp(1, i32::MAX as u128) as i32;
            // SAFETY: one valid pollfd. An EINTR or error only ends this wait
            // early; the caller checks the child again either way.
            unsafe { libc::poll(&mut pollfd, 1, ms) };
            return;
        }
        std::thread::sleep(timeout);
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
    on_abort: F,
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

    let _stdout_reader = child.stdout.take().and_then(|mut out| {
        std::thread::Builder::new()
            .name("crun-stdout".into())
            .spawn(move || {
                let mut total = 0usize;
                let mut attached = true;
                loop {
                    let mut chunk = vec![0u8; CHUNK_SIZE];
                    match out.read(&mut chunk) {
                        Ok(0) => break, // EOF
                        // The caller replied: keep the pipe drained so a
                        // process still writing to it is not killed by SIGPIPE.
                        Ok(_) if !attached => {}
                        Ok(n) => {
                            total += n;
                            chunk.truncate(n);
                            if stdout_tx.send(chunk).is_err() {
                                attached = false;
                                continue;
                            }
                            // Stop only once past the cap, so output of exactly
                            // the cap is not mistaken for truncated output.
                            if total > MAX_EXEC_OUTPUT {
                                break;
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(_) => break,
                    }
                }
            })
            .ok()
    });

    let _stderr_reader = child.stderr.take().and_then(|mut err| {
        std::thread::Builder::new()
            .name("crun-stderr".into())
            .spawn(move || {
                let mut total = 0usize;
                let mut attached = true;
                loop {
                    let mut chunk = vec![0u8; CHUNK_SIZE];
                    match err.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(_) if !attached => {}
                        Ok(n) => {
                            total += n;
                            chunk.truncate(n);
                            if stderr_tx.send(chunk).is_err() {
                                attached = false;
                                continue;
                            }
                            if total > MAX_EXEC_OUTPUT {
                                break;
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
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
    // Wakes the loop the moment the child exits, rather than at the next tick.
    let exit_signal = ExitSignal::open(child);

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
                // After the child dies, pipe write ends close and readers see EOF;
                // a reader's channel disconnects as soon as it returns, so wait on
                // that instead of polling. A background process still holding a
                // pipe keeps its reader open until the deadline, as before.
                let join_deadline = Instant::now() + READER_JOIN_TIMEOUT;
                drain_until_closed(&stdout_rx, &mut stdout_buf, join_deadline);
                drain_until_closed(&stderr_rx, &mut stderr_buf, join_deadline);
                let exit_code = exit_code_from_status(&status);
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
                        on_abort();
                        kill_child_tree(child);
                        let grace = Instant::now() + KILLED_OUTPUT_GRACE;
                        drain_until_closed(&stdout_rx, &mut stdout_buf, grace);
                        drain_until_closed(&stderr_rx, &mut stderr_buf, grace);
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
                        on_abort();
                        kill_child_tree(child);
                        let grace = Instant::now() + KILLED_OUTPUT_GRACE;
                        drain_until_closed(&stdout_rx, &mut stdout_buf, grace);
                        drain_until_closed(&stderr_rx, &mut stderr_buf, grace);
                        return Ok(WaitResult::TimedOut {
                            output: ChildOutput {
                                stdout: stdout_buf,
                                stderr: stderr_buf,
                            },
                            timeout_ms: timeout_ms.unwrap_or(0),
                        });
                    }
                }

                let tick = deadline.map_or(poll_interval, |deadline| {
                    deadline
                        .saturating_duration_since(Instant::now())
                        .min(poll_interval)
                });
                exit_signal.wait(tick);
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_parsing_survives_odd_command_names() {
        let stat = "4242 (weird) name)) S 17 4242 4242 0 -1 4194560 0 0";
        assert_eq!(parse_stat_state_ppid(stat), Some(('S', 17)));
        assert_eq!(parse_stat_state_ppid("7 (sh) Z 1 7"), Some(('Z', 1)));
        assert_eq!(parse_stat_state_ppid("garbage"), None);
    }

    // The case that motivated it: the command is a GRANDCHILD (crun exec ->
    // command -> its own children). Killing only the direct child used to leave
    // the rest running.
    #[cfg(target_os = "linux")]
    #[test]
    fn kill_child_tree_kills_grandchildren() {
        let mut child = std::process::Command::new("sh")
            .args(["-c", "sh -c 'sleep 30 & sleep 30 & wait' & wait"])
            .spawn()
            .unwrap();
        // Let the tree form.
        let mut tree = Vec::new();
        for _ in 0..50 {
            tree = live_descendants(child.id());
            if tree.len() >= 3 {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(tree.len() >= 3, "expected sh + two sleeps, got {tree:?}");
        kill_child_tree(&mut child);
        std::thread::sleep(Duration::from_millis(100));
        for pid in tree {
            let alive = std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .ok()
                .and_then(|s| parse_stat_state_ppid(&s))
                .is_some_and(|(state, _)| state != 'Z');
            assert!(!alive, "descendant {pid} survived");
        }
    }

    /// Spawn `sh -c <script>` with piped output and read the PID it prints first.
    #[cfg(target_os = "linux")]
    fn spawn_printing_pid(script: &str) -> (std::process::Child, u32) {
        use std::io::Read as _;
        let mut child = std::process::Command::new("sh")
            .args(["-c", script])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let out = child.stdout.as_mut().unwrap();
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        while out.read(&mut byte).unwrap() == 1 && byte[0] != b'\n' {
            line.push(byte[0]);
        }
        let pid = String::from_utf8(line).unwrap().trim().parse().unwrap();
        (child, pid)
    }

    #[cfg(target_os = "linux")]
    fn is_live(pid: u32) -> bool {
        std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|s| parse_stat_state_ppid(&s))
            .is_some_and(|(state, _)| state != 'Z')
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn kill_child_tree_kills_a_reparented_process_still_writing_the_output() {
        // The subshell exits, so the writer is no longer a descendant.
        let (mut child, writer) =
            spawn_printing_pid("(sh -c 'echo $$; exec sleep 30' &); exec sleep 30");
        assert!(is_live(writer));
        kill_child_tree(&mut child);
        std::thread::sleep(Duration::from_millis(100));
        let survived = is_live(writer);
        if survived {
            // SAFETY: plain signal delivery to the PID the test started.
            unsafe { libc::kill(writer as libc::pid_t, libc::SIGKILL) };
        }
        assert!(!survived, "writer {writer} survived");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn kill_child_tree_spares_writers_of_a_pipe_this_process_also_writes() {
        use std::os::fd::{FromRawFd, OwnedFd};
        // A pipe this process holds both ends of stands for its own stdout
        // handed down: other processes write to it too, so they are not the
        // command's to kill.
        let mut fds = [0; 2];
        // SAFETY: fds is a valid two-int array.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: both fds were just created and are owned here.
        let (_read, write) =
            unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        let mut bystander = std::process::Command::new("sleep")
            .arg("30")
            .stdout(std::process::Stdio::from(write.try_clone().unwrap()))
            .spawn()
            .unwrap();
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .stdout(std::process::Stdio::from(write.try_clone().unwrap()))
            .spawn()
            .unwrap();
        kill_child_tree(&mut child);
        std::thread::sleep(Duration::from_millis(100));
        let spared = is_live(bystander.id());
        let _ = bystander.kill();
        let _ = bystander.wait();
        assert!(spared, "a writer of a shared pipe was killed");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn timed_out_wait_kills_a_reparented_writer_and_answers_on_time() {
        let (mut child, writer) =
            spawn_printing_pid("(sh -c 'echo $$; exec sleep 30' &); exec sleep 30");
        let started = Instant::now();
        let result =
            wait_with_timeout_cleanup_and_liveness(&mut child, Some(300), None, || {}).unwrap();
        let elapsed = started.elapsed();
        std::thread::sleep(Duration::from_millis(100));
        let survived = is_live(writer);
        if survived {
            // SAFETY: plain signal delivery to the PID the test started.
            unsafe { libc::kill(writer as libc::pid_t, libc::SIGKILL) };
        }
        assert!(matches!(result, WaitResult::TimedOut { .. }));
        assert!(elapsed < Duration::from_secs(2), "took {elapsed:?}");
        assert!(!survived, "writer {writer} survived the timeout");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn finished_wait_leaves_a_background_writer_alive_and_drained() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("finished");
        let mut child = std::process::Command::new("sh")
            .args([
                "-c",
                &format!(
                    "echo hi; (sleep 6; echo late; sleep 0.5; echo later; touch '{}') &",
                    marker.display()
                ),
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        match wait_with_timeout_cleanup_and_liveness(&mut child, None, None, || {}).unwrap() {
            WaitResult::Completed { exit_code, output } => {
                assert_eq!(exit_code, 0);
                assert_eq!(output.stdout, b"hi\n");
            }
            _ => panic!("expected the command to complete"),
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while !marker.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            marker.exists(),
            "the background job died writing to the drained pipe"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fdinfo_access_mode_reads_the_octal_flags() {
        assert_eq!(
            fdinfo_access_mode("pos:\t0\nflags:\t02000001\nmnt_id:\t15\n"),
            Some(libc::O_WRONLY)
        );
        assert_eq!(
            fdinfo_access_mode("flags:\t0100000\n"),
            Some(libc::O_RDONLY)
        );
        assert_eq!(fdinfo_access_mode("pos:\t0\n"), None);
    }

    // A command that exits at once used to wait out a 10 ms poll tick, plus
    // another while its output readers finished.
    #[cfg(target_os = "linux")]
    #[test]
    fn quick_command_returns_without_a_poll_tick() {
        let mut best = Duration::MAX;
        for _ in 0..20 {
            let mut child = std::process::Command::new("true")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let started = Instant::now();
            let result =
                wait_with_timeout_cleanup_and_liveness(&mut child, None, None, || {}).unwrap();
            best = best.min(started.elapsed());
            assert!(matches!(result, WaitResult::Completed { exit_code: 0, .. }));
        }
        assert!(
            best < Duration::from_millis(8),
            "fastest wait took {best:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn output_is_complete_when_the_child_exits() {
        let mut child = std::process::Command::new("sh")
            .args(["-c", "head -c 300000 /dev/zero; echo err >&2"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        match wait_with_timeout_cleanup_and_liveness(&mut child, Some(10_000), None, || {}).unwrap()
        {
            WaitResult::Completed { output, .. } => {
                assert_eq!(output.stdout.len(), 300_000);
                assert_eq!(output.stderr, b"err\n");
            }
            _ => panic!("expected the command to complete"),
        }
    }

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
}
