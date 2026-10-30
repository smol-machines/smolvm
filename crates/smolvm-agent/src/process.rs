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

const EXEC_AS_ARG: &str = "exec-as";

/// Whether this agent invocation is the credential helper a command entering a
/// snapshot-restored container runs through (see [`exec_as_args`]).
pub fn exec_as_requested() -> bool {
    std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new(EXEC_AS_ARG))
}

/// The arguments that make `exe` (this agent binary) become `command` as
/// `uid:gid` holding `groups`: `exe exec-as UID GID GROUPS -- command...`, with
/// GROUPS comma-separated (`-` for none).
///
/// `nsenter --setgid` drops every supplementary group (it calls
/// `setgroups(0, NULL)` itself), so a command that enters a container through
/// nsenter cannot keep its user's groups that way. nsenter enters the
/// namespaces as root and runs this helper instead, which sets the groups,
/// then the gid, then the uid, and execs the command, as `initgroups` and a
/// login do.
pub fn exec_as_args(
    exe: &str,
    uid: u32,
    gid: u32,
    groups: &[u32],
    command: &[String],
) -> Vec<String> {
    let groups = if groups.is_empty() {
        "-".to_string()
    } else {
        groups
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",")
    };
    let mut args = vec![
        exe.to_string(),
        EXEC_AS_ARG.to_string(),
        uid.to_string(),
        gid.to_string(),
        groups,
        "--".to_string(),
    ];
    args.extend(command.iter().cloned());
    args
}

/// What an `exec-as` invocation asks for.
#[derive(Debug, PartialEq, Eq)]
struct ExecAs<'a> {
    uid: u32,
    gid: u32,
    groups: Vec<u32>,
    command: &'a [String],
}

/// Parse [`exec_as_args`] (without the executable) back into an [`ExecAs`].
fn parse_exec_as(args: &[String]) -> Result<ExecAs<'_>, String> {
    let [arg, uid, gid, groups, sep, command @ ..] = args else {
        return Err("usage: exec-as UID GID GROUPS -- COMMAND...".to_string());
    };
    if arg != EXEC_AS_ARG || sep != "--" || command.is_empty() {
        return Err("usage: exec-as UID GID GROUPS -- COMMAND...".to_string());
    }
    let id = |value: &str| {
        value
            .parse::<u32>()
            .map_err(|_| format!("exec-as: invalid id '{value}'"))
    };
    let groups = if groups == "-" {
        Vec::new()
    } else {
        groups.split(',').map(id).collect::<Result<_, _>>()?
    };
    Ok(ExecAs {
        uid: id(uid)?,
        gid: id(gid)?,
        groups,
        command,
    })
}

/// Entry point for `smolvm-agent exec-as`: set the credentials, then exec the
/// command (searching `PATH`). Returns only on failure, with the shell's exit
/// codes: 127 for a command that does not exist, 126 otherwise.
#[cfg(target_os = "linux")]
pub fn run_exec_as() -> i32 {
    use std::os::unix::process::CommandExt as _;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let ExecAs {
        uid,
        gid,
        groups,
        command,
    } = match parse_exec_as(&args) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("smolvm: {error}");
            return 126;
        }
    };
    let groups: Vec<libc::gid_t> = groups.into_iter().map(|g| g as libc::gid_t).collect();
    // SAFETY: plain credential syscalls on this single-threaded process; the
    // pointer and length describe `groups`, which outlives the call.
    unsafe {
        if libc::setgroups(groups.len(), groups.as_ptr()) != 0 {
            eprintln!("smolvm: setgroups: {}", std::io::Error::last_os_error());
            return 126;
        }
        if libc::setgid(gid) != 0 {
            eprintln!("smolvm: setgid {gid}: {}", std::io::Error::last_os_error());
            return 126;
        }
        if libc::setuid(uid) != 0 {
            eprintln!("smolvm: setuid {uid}: {}", std::io::Error::last_os_error());
            return 126;
        }
    }
    let error = std::process::Command::new(&command[0])
        .args(&command[1..])
        .exec();
    eprintln!("smolvm: exec {}: {error}", command[0]);
    if error.kind() == std::io::ErrorKind::NotFound {
        127
    } else {
        126
    }
}

#[cfg(not(target_os = "linux"))]
pub fn run_exec_as() -> i32 {
    126
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
/// Kill `child` and every process descended from it, then reap `child`.
///
/// A command run in an image container is not the agent's child: the agent
/// spawns `crun exec` (or a namespace-entering helper) and the command is that
/// helper's child. Killing only the direct child orphans the command, which
/// keeps running in the container after its client disconnected or its timeout
/// passed. The agent's PID namespace contains the container's, so the whole
/// tree is visible in `/proc`.
pub fn kill_child_tree(child: &mut Child) {
    #[cfg(target_os = "linux")]
    kill_descendants(child.id());
    let _ = child.kill();
    let _ = child.wait();
}

/// SIGKILL every live descendant of `root`.
///
/// The tree is frozen first: once an intermediate process dies its children are
/// re-parented and no longer look like descendants, and a live process could
/// fork between a walk and the kill. So SIGSTOP everything found, re-walk until
/// no new process appears (a stopped process cannot fork), then SIGKILL the
/// whole set. Bounded, so a fork bomb cannot pin the agent.
#[cfg(target_os = "linux")]
fn kill_descendants(root: u32) {
    let mut frozen = std::collections::BTreeSet::new();
    for _ in 0..32 {
        let fresh: Vec<u32> = live_descendants(root)
            .into_iter()
            .filter(|pid| !frozen.contains(pid))
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
fn drain_until_closed(
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

    let _stderr_reader = child.stderr.take().and_then(|mut err| {
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
                        on_abort();
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
    fn exec_as_round_trips_the_user_its_groups_and_the_command() {
        let command = vec!["sh".to_string(), "-c".to_string(), "id -G".to_string()];
        let args = exec_as_args("/proc/self/fd/7", 1001, 1001, &[1001, 27, 123], &command);
        assert_eq!(
            args,
            [
                "/proc/self/fd/7",
                "exec-as",
                "1001",
                "1001",
                "1001,27,123",
                "--",
                "sh",
                "-c",
                "id -G"
            ]
        );
        assert_eq!(
            parse_exec_as(&args[1..]).unwrap(),
            ExecAs {
                uid: 1001,
                gid: 1001,
                groups: vec![1001, 27, 123],
                command: command.as_slice(),
            }
        );

        // No groups at all is spelled `-` and parses back to none.
        let args = exec_as_args("exe", 0, 0, &[], &command);
        assert_eq!(args[4], "-");
        assert!(parse_exec_as(&args[1..]).unwrap().groups.is_empty());
    }

    #[test]
    fn exec_as_refuses_malformed_arguments() {
        let parse = |args: &[&str]| {
            let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
            parse_exec_as(&args).map(|_| ())
        };
        assert!(parse(&["exec-as", "1001", "1001", "-", "--"]).is_err());
        assert!(parse(&["exec-as", "1001", "1001", "-", "sh"]).is_err());
        assert!(parse(&["exec-as", "runner", "1001", "-", "--", "sh"]).is_err());
        assert!(parse(&["exec-as", "1001", "1001", "27,x", "--", "sh"]).is_err());
        assert!(parse(&["exec-as", "1001", "1001", "-", "--", "sh"]).is_ok());
    }

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
