//! smolvm-managed shared CUDA daemon.
//!
//! One process holding a single GPU context, serving every CUDA VM's proxied
//! connection (see [`crate::cuda_host`]'s proxy path). Because all connections
//! live in this one process, they share the device primary context — which is
//! what lets a forked VM clone reconnect and reuse its golden's device memory.
//!
//! Lifecycle is lazy and self-managing: the first CUDA VM that needs the daemon
//! calls [`ensure_running`], which spawns `smolvm _cuda-daemon <socket>` if the
//! socket isn't already live. The daemon then persists across VMs (it is not
//! tied to any single VM's boot subprocess) until the host shuts down.

use crate::platform::uds::UdsListener;
use smolvm_cuda::host::{serve, Backend, CpuBackend, GpuBackend};
use std::io;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Control-socket path for the shared daemon, under the smolvm data dir (so the
/// daemon and every boot subprocess agree on one location).
pub fn socket_path() -> PathBuf {
    let root = std::env::var_os("SMOLVM_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("smolvm"));
    root.join("cuda-daemon.sock")
}

/// True if a daemon is already listening on `sock` (a probe connect succeeds).
fn is_alive(sock: &Path) -> bool {
    UnixStream::connect(sock).is_ok()
}

/// How long the daemon may sit with ZERO open connections before it exits and
/// releases the GPU context. `None` (env set to `0`) disables the timeout.
///
/// Counting *open connections* (not activity) is what makes this fork-safe: a
/// frozen golden keeps its proxied connection open, so it counts as active and
/// never trips the timeout even while paused. The daemon only exits once every
/// VM — golden and clones — has disconnected.
fn idle_timeout() -> Option<Duration> {
    let secs = std::env::var("SMOLVM_CUDA_DAEMON_IDLE_SECS")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(300);
    (secs > 0).then(|| Duration::from_secs(secs))
}

/// Exit the process once `active` has been 0 for `timeout`. Polls slowly (the
/// timeout is coarse) and resets the idle clock whenever a connection is live.
fn spawn_idle_watchdog(active: Arc<AtomicUsize>, timeout: Duration) {
    thread::Builder::new()
        .name("cuda-daemon-idle".into())
        .spawn(move || {
            let mut idle_since = Instant::now();
            loop {
                thread::sleep(Duration::from_secs(5));
                if active.load(Ordering::SeqCst) > 0 {
                    idle_since = Instant::now();
                } else if idle_since.elapsed() >= timeout {
                    tracing::info!(
                        timeout_secs = timeout.as_secs(),
                        "shared CUDA daemon idle with no connections — exiting"
                    );
                    std::process::exit(0);
                }
            }
        })
        .ok();
}

/// Run the daemon body: bind `sock` and serve every connection in its own
/// thread against a fresh backend — all in this process, so they share one GPU
/// context. Returns only on listener failure; otherwise exits via the idle
/// watchdog (or runs until the host shuts down when the timeout is disabled).
pub fn run(sock: &Path) -> io::Result<()> {
    if let Some(parent) = sock.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::remove_file(sock); // caller serialized us; clear any stale node
    let listener = UdsListener::bind(sock)?;
    tracing::info!(socket = %sock.display(), "shared CUDA daemon listening");
    let active = Arc::new(AtomicUsize::new(0));
    // Optional network transport (P1): also accept CUDA-RPC over TCP so a remote,
    // GPU-less client (e.g. a Mac running the shim with SMOLVM_CUDA_RPC=tcp:HOST:PORT)
    // can drive this GPU. Trusted single-tenant only — NO TLS/auth yet; that is the
    // hosted-service layer, intentionally deferred. Bind e.g. `0.0.0.0:7001`.
    let tcp_addr = std::env::var("SMOLVM_CUDA_DAEMON_TCP").ok();
    if let Some(ref addr) = tcp_addr {
        match std::net::TcpListener::bind(addr) {
            Ok(tcp) => {
                tracing::info!(%addr, "CUDA daemon ALSO listening on TCP (network transport)");
                let active_tcp = active.clone();
                thread::Builder::new()
                    .name("cuda-daemon-tcp".into())
                    .spawn(move || {
                        for stream in tcp.incoming() {
                            match stream {
                                Ok(s) => {
                                    let _ = s.set_nodelay(true); // low-latency RPC
                                    spawn_serve(s, &active_tcp);
                                }
                                Err(e) => {
                                    tracing::debug!(error = %e, "CUDA daemon TCP accept error")
                                }
                            }
                        }
                    })
                    .ok();
            }
            Err(e) => tracing::warn!(%addr, error = %e, "CUDA daemon TCP bind failed"),
        }
    }
    // A network daemon should persist even with no client yet, so only run the
    // idle watchdog when there is no TCP listener holding the door open.
    if tcp_addr.is_none() {
        if let Some(timeout) = idle_timeout() {
            spawn_idle_watchdog(active.clone(), timeout);
        }
    }
    for stream in listener.incoming() {
        match stream {
            // Count the connection open for the whole serve loop so a frozen golden
            // (idle but connected) keeps the daemon alive for its clones.
            Ok(stream) => spawn_serve(stream, &active),
            Err(e) => tracing::debug!(error = %e, "CUDA daemon accept error"),
        }
    }
    Ok(())
}

/// Serve one accepted connection on its own thread with a fresh backend, counting
/// it against `active` for the idle watchdog. Generic over the stream type so the
/// local UDS listener and the optional TCP listener share one path.
fn spawn_serve<S>(stream: S, active: &Arc<AtomicUsize>)
where
    S: std::io::Read + std::io::Write + Send + 'static,
{
    let guard = ConnGuard::new(active);
    thread::Builder::new()
        .name("cuda-daemon-conn".into())
        .spawn(move || {
            let _guard = guard;
            let mut backend = make_backend();
            if let Err(e) = serve(stream, backend.as_mut()) {
                tracing::debug!(error = %e, "CUDA daemon connection ended");
            }
        })
        .ok();
}

/// Keeps the daemon's open-connection count accurate: +1 on construction, -1 on
/// drop (whether the serve thread finished or never started).
struct ConnGuard(Arc<AtomicUsize>);

impl ConnGuard {
    fn new(active: &Arc<AtomicUsize>) -> Self {
        active.fetch_add(1, Ordering::SeqCst);
        ConnGuard(active.clone())
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn make_backend() -> Box<dyn Backend> {
    match GpuBackend::load() {
        Ok(gpu) => {
            tracing::info!("cuda-daemon: GPU driver backend ready");
            Box::new(gpu)
        }
        Err(e) => {
            tracing::info!("cuda-daemon: no GPU driver ({e}) — CPU emulation backend");
            Box::<CpuBackend>::default()
        }
    }
}

/// Ensure the shared daemon is running and return its socket path. Serialized by
/// an exclusive lock on `<socket>.lock` so concurrent CUDA VMs can't spawn two
/// daemons (a second would bind-fail and exit, but the lock avoids the churn and
/// the stale-socket-removal race).
pub fn ensure_running() -> io::Result<PathBuf> {
    let sock = socket_path();
    if let Some(parent) = sock.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _guard = FileLock::acquire(&sock.with_extension("lock"))?;
    if is_alive(&sock) {
        return Ok(sock);
    }
    let _ = std::fs::remove_file(&sock); // stale node from a dead daemon
    use std::os::unix::process::CommandExt;
    let exe = std::env::current_exe()?;
    // Dev diagnostic: SMOLVM_CUDA_DAEMON_STDERR=<path> captures the daemon's
    // stderr (fork-isolation traces, backend selection) instead of dropping it.
    let stderr = match std::env::var_os("SMOLVM_CUDA_DAEMON_STDERR") {
        Some(p) => std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&p)
            .map(Stdio::from)
            .unwrap_or_else(|_| Stdio::null()),
        None => Stdio::null(),
    };
    Command::new(exe)
        .args(["_cuda-daemon", &sock.to_string_lossy()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr)
        // Own process group so the daemon outlives the VM that first spawned it.
        .process_group(0)
        .spawn()?;
    for _ in 0..200 {
        if is_alive(&sock) {
            return Ok(sock);
        }
        thread::sleep(Duration::from_millis(25));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "shared CUDA daemon did not come up",
    ))
}

/// Minimal RAII `flock(LOCK_EX)` guard on a lock file.
struct FileLock(std::fs::File);

impl FileLock {
    fn acquire(path: &Path) -> io::Result<Self> {
        use std::os::unix::io::AsRawFd;
        let f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(path)?;
        let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(FileLock(f))
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}
