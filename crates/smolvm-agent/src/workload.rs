//! A machine's detached workload: where its output goes and how it is stopped.
//!
//! Output. A detached workload's stdout and stderr are a pipe the agent drains
//! into a bounded queue, and a sender thread writes that queue to the host over
//! the [`ports::WORKLOAD_LOGS`] vsock port, where the boot process appends it to
//! the machine's `workload.log`. The workload never waits on the host: a full
//! queue drops output (and says how much once the host catches up), and a lost
//! connection, as after a restore or a branch, is simply dialled again.
//!
//! Stop. Each launched workload is remembered with its stop signal and timeout.
//! On shutdown the agent signals every live one, waits for them to exit for at
//! most their timeout, kills what is left, and only then quiesces storage, so a
//! workload gets to save its state before the machine goes away.

use smolvm_protocol::{guest_env, ports};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// Chunks of output waiting for the host before newer output is dropped.
const LOG_QUEUE_CHUNKS: usize = 128;
/// Largest chunk read from a workload's output pipe.
const LOG_CHUNK_BYTES: usize = 16 * 1024;
/// Wait between attempts to reach the host's log listener.
const LOG_RECONNECT_DELAY: Duration = Duration::from_secs(1);
/// A write the host has not taken within this long counts as a lost connection.
const LOG_SEND_TIMEOUT: Duration = Duration::from_secs(5);
/// How often a stop checks whether the signalled workloads have exited.
const STOP_POLL: Duration = Duration::from_millis(50);

/// Output bytes dropped because the queue to the host was full.
static DROPPED_BYTES: AtomicU64 = AtomicU64::new(0);

/// The queue to the log sender, created on first use when the host asked for
/// workload logs; `None` when it did not.
fn log_queue() -> Option<&'static SyncSender<Vec<u8>>> {
    static QUEUE: OnceLock<Option<SyncSender<Vec<u8>>>> = OnceLock::new();
    QUEUE
        .get_or_init(|| {
            if std::env::var(guest_env::WORKLOAD_LOGS).as_deref() != Ok(guest_env::VALUE_ON) {
                return None;
            }
            let (tx, rx) = mpsc::sync_channel(LOG_QUEUE_CHUNKS);
            match std::thread::Builder::new()
                .name("workload-log-send".into())
                .spawn(move || send_logs(rx))
            {
                Ok(_) => Some(tx),
                Err(e) => {
                    warn!(error = %e, "could not start the workload log sender; output is discarded");
                    None
                }
            }
        })
        .as_ref()
}

/// Whether workload output reaches the host.
pub fn logs_enabled() -> bool {
    log_queue().is_some()
}

/// The write end of a pipe whose output is forwarded to the host's workload
/// log, to hand to a workload as both stdout and stderr; `None` when workload
/// logs are off, in which case the caller discards the output as before.
pub fn output_pipe() -> Option<OwnedFd> {
    let queue = log_queue()?.clone();
    let mut fds = [0; 2];
    // SAFETY: pipe2 writes two descriptors into the array on success.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        warn!(error = %std::io::Error::last_os_error(), "could not create the workload output pipe");
        return None;
    }
    // SAFETY: both descriptors were just created and are owned only here.
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    let spawned = std::thread::Builder::new()
        .name("workload-log-read".into())
        .spawn(move || drain_output(std::fs::File::from(read), queue));
    if let Err(e) = spawned {
        warn!(error = %e, "could not start the workload output reader");
        return None;
    }
    Some(write)
}

/// Move a workload's output into the queue until every writer has closed the
/// pipe. Never blocks on the host: output that does not fit is counted and
/// dropped.
fn drain_output(mut pipe: std::fs::File, queue: SyncSender<Vec<u8>>) {
    let mut buffer = vec![0u8; LOG_CHUNK_BYTES];
    loop {
        let read = match pipe.read(&mut buffer) {
            Ok(0) => return,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                warn!(error = %e, "reading workload output failed");
                return;
            }
        };
        match queue.try_send(buffer[..read].to_vec()) {
            Ok(()) => {}
            Err(TrySendError::Full(chunk)) => {
                DROPPED_BYTES.fetch_add(chunk.len() as u64, Ordering::Relaxed);
            }
            Err(TrySendError::Disconnected(_)) => return,
        }
    }
}

/// Write queued output to the host, dialling it again whenever the connection
/// is lost.
fn send_logs(queue: Receiver<Vec<u8>>) {
    let mut connection: Option<crate::vsock::VsockStream> = None;
    for chunk in queue {
        // A chunk is retried once on a fresh connection, so the one in flight
        // when a restore cut the old connection is not lost.
        for _ in 0..2 {
            if connection.is_none() {
                connection = connect_to_host();
            }
            let Some(stream) = connection.as_mut() else {
                break;
            };
            let dropped = DROPPED_BYTES.swap(0, Ordering::Relaxed);
            let notice = (dropped > 0)
                .then(|| format!("[smolvm: {dropped} bytes of workload output dropped]\n"));
            let sent = notice
                .as_deref()
                .map_or(Ok(()), |notice| stream.write_all(notice.as_bytes()))
                .and_then(|()| stream.write_all(&chunk));
            match sent {
                Ok(()) => break,
                Err(_) => {
                    DROPPED_BYTES.fetch_add(dropped, Ordering::Relaxed);
                    connection = None;
                }
            }
        }
        if connection.is_none() {
            DROPPED_BYTES.fetch_add(chunk.len() as u64, Ordering::Relaxed);
            std::thread::sleep(LOG_RECONNECT_DELAY);
        }
    }
}

fn connect_to_host() -> Option<crate::vsock::VsockStream> {
    let stream = crate::vsock::connect(ports::WORKLOAD_LOGS).ok()?;
    let timeout = libc::timeval {
        tv_sec: LOG_SEND_TIMEOUT.as_secs() as _,
        tv_usec: 0,
    };
    // SAFETY: setsockopt reads `timeout` for the duration of the call only.
    unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            &timeout as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }
    Some(stream)
}

/// What a stop signals: the workload process itself, or the init of a
/// container whose init is the workload.
#[derive(Clone, Debug)]
pub enum StopTarget {
    Process(crate::CrunProcessIdentity),
    Container(String),
}

impl StopTarget {
    /// The target's pid while it is running.
    fn alive(&self) -> Option<u32> {
        match self {
            StopTarget::Process(identity) => {
                let stat = std::fs::read_to_string(format!("/proc/{}/stat", identity.pid)).ok()?;
                crate::validate_crun_process_identity(*identity, &stat)
            }
            StopTarget::Container(id) => crate::crun_container_pid(id),
        }
    }
}

struct Workload {
    target: StopTarget,
    signal: i32,
    timeout: Duration,
}

static WORKLOADS: Mutex<Vec<Workload>> = Mutex::new(Vec::new());
static STOPPING: AtomicBool = AtomicBool::new(false);

/// Remember a launched workload so a shutdown stops it gracefully.
pub fn register(target: StopTarget, signal: i32, timeout: Duration) {
    let mut workloads = WORKLOADS.lock().unwrap_or_else(|e| e.into_inner());
    workloads.retain(|workload| workload.target.alive().is_some());
    workloads.push(Workload {
        target,
        signal,
        timeout,
    });
}

/// Whether a shutdown has begun stopping the workloads, so a workload exiting
/// now is being stopped rather than ending on its own.
pub fn stopping() -> bool {
    STOPPING.load(Ordering::SeqCst)
}

/// Signal every live workload, wait for them to exit for at most their
/// timeouts (or `timeout_override`), then kill whatever is still running.
pub fn stop_all(timeout_override: Option<Duration>) {
    STOPPING.store(true, Ordering::SeqCst);
    let workloads = std::mem::take(&mut *WORKLOADS.lock().unwrap_or_else(|e| e.into_inner()));
    stop(
        workloads
            .into_iter()
            .map(|workload| Workload {
                timeout: timeout_override.unwrap_or(workload.timeout),
                ..workload
            })
            .collect(),
        |pid, signal| {
            // SAFETY: kill takes no pointers; the pid was just validated as
            // the workload's.
            unsafe { libc::kill(pid as libc::pid_t, signal) };
        },
    );
}

fn stop(workloads: Vec<Workload>, send: impl Fn(u32, i32)) {
    let started = Instant::now();
    let mut waiting = Vec::new();
    for workload in workloads {
        let Some(pid) = workload.target.alive() else {
            continue;
        };
        if workload.timeout.is_zero() {
            send(pid, libc::SIGKILL);
            continue;
        }
        info!(
            pid,
            signal = workload.signal,
            timeout_secs = workload.timeout.as_secs(),
            "stopping the workload"
        );
        send(pid, workload.signal);
        waiting.push(workload);
    }
    while !waiting.is_empty() {
        waiting.retain(|workload| match workload.target.alive() {
            None => false,
            Some(pid) if started.elapsed() >= workload.timeout => {
                warn!(
                    pid,
                    timeout_secs = workload.timeout.as_secs(),
                    "workload did not exit after its stop signal; killing it"
                );
                send(pid, libc::SIGKILL);
                false
            }
            Some(_) => true,
        });
        if !waiting.is_empty() {
            std::thread::sleep(STOP_POLL);
        }
    }
    let elapsed = started.elapsed();
    if elapsed > STOP_POLL {
        info!(elapsed_ms = elapsed.as_millis(), "workloads stopped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn identity(child: &std::process::Child) -> crate::CrunProcessIdentity {
        let stat = std::fs::read_to_string(format!("/proc/{}/stat", child.id())).unwrap();
        crate::CrunProcessIdentity {
            pid: child.id(),
            start_time: crate::proc_stat_start_time(&stat).unwrap(),
        }
    }

    fn workload(child: &std::process::Child, timeout: Duration) -> Workload {
        Workload {
            target: StopTarget::Process(identity(child)),
            signal: libc::SIGTERM,
            timeout,
        }
    }

    fn reap_in_background(mut child: std::process::Child) {
        std::thread::spawn(move || {
            let _ = child.wait();
        });
    }

    fn kill(pid: u32, signal: i32) {
        unsafe { libc::kill(pid as libc::pid_t, signal) };
    }

    #[test]
    fn a_workload_that_handles_its_stop_signal_gets_to_finish() {
        let marker = tempfile::NamedTempFile::new().unwrap();
        let path = marker.path().to_path_buf();
        let child = Command::new("sh")
            .arg("-c")
            .arg(format!(
                "trap 'sleep 0.3; echo saved > {}; exit 0' TERM; while :; do sleep 0.05; done",
                path.display()
            ))
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_millis(200));
        let started = Instant::now();
        let target = workload(&child, Duration::from_secs(5));
        reap_in_background(child);
        stop(vec![target], kill);
        assert_eq!(std::fs::read_to_string(&path).unwrap().trim(), "saved");
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_workload_that_ignores_its_stop_signal_is_killed_at_the_timeout() {
        let child = Command::new("sh")
            .arg("-c")
            .arg("trap '' TERM; while :; do sleep 0.05; done")
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_millis(200));
        let target = workload(&child, Duration::from_millis(400));
        let probe = target.target.clone();
        reap_in_background(child);
        let started = Instant::now();
        stop(vec![target], kill);
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_millis(400), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(3), "{elapsed:?}");
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(probe.alive(), None);
    }

    #[test]
    fn a_zero_timeout_kills_without_waiting() {
        let child = Command::new("sh")
            .arg("-c")
            .arg("trap '' TERM; while :; do sleep 0.05; done")
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let target = workload(&child, Duration::ZERO);
        let probe = target.target.clone();
        reap_in_background(child);
        let started = Instant::now();
        stop(vec![target], kill);
        assert!(started.elapsed() < Duration::from_millis(200));
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(probe.alive(), None);
    }
}
