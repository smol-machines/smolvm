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
use std::thread;
use std::time::Duration;

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

/// Run the daemon body: bind `sock` and serve every connection in its own
/// thread against a fresh backend — all in this process, so they share one GPU
/// context. Never returns under normal operation.
pub fn run(sock: &Path) -> io::Result<()> {
    if let Some(parent) = sock.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::remove_file(sock); // caller serialized us; clear any stale node
    let listener = UdsListener::bind(sock)?;
    tracing::info!(socket = %sock.display(), "shared CUDA daemon listening");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::Builder::new()
                    .name("cuda-daemon-conn".into())
                    .spawn(move || {
                        let mut backend = make_backend();
                        if let Err(e) = serve(stream, backend.as_mut()) {
                            tracing::debug!(error = %e, "CUDA daemon connection ended");
                        }
                    })
                    .ok();
            }
            Err(e) => tracing::debug!(error = %e, "CUDA daemon accept error"),
        }
    }
    Ok(())
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
    Command::new(exe)
        .args(["_cuda-daemon", &sock.to_string_lossy()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
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
