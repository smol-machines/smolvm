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
use std::sync::{Arc, Mutex, OnceLock};
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

/// Reap dead clone-worker children so they don't accumulate as zombies. The
/// daemon forks a worker per clone; the reconnect path reaps a worker only if
/// that clone reconnects (see route_clone_connection), but a worker that dies
/// at teardown — including the teardown SIGSEGV — with no reconnect was never
/// waited on and became a zombie. Over a long run these fill the process table
/// (observed: 288 `<defunct>` after ~42 fork cycles), risking PID exhaustion
/// and fork failures that slow clone startup. A background reaper drains all
/// exited children; it coexists with the targeted reconnect reap (whichever
/// waits first wins; the other simply sees the child already gone).
#[cfg(unix)]
fn spawn_child_reaper() {
    thread::Builder::new()
        .name("cuda-daemon-reaper".into())
        .spawn(|| loop {
            // Drain every exited child without blocking.
            loop {
                let mut status: libc::c_int = 0;
                // SAFETY: WNOHANG waitpid(-1) on our own children; never blocks.
                let r = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
                // 0 = children exist but none exited yet; <=0 (incl. -1/ECHILD
                // when there are no children) = nothing to reap right now.
                if r <= 0 {
                    break;
                }
            }
            thread::sleep(Duration::from_secs(2));
        })
        .ok();
}

#[cfg(not(unix))]
fn spawn_child_reaper() {}

/// Sweep clone-worker processes left behind by a PRIOR daemon that died without
/// reaping them (crash or SIGKILL — neither runs the clean-shutdown handler).
/// Called at startup ONLY when no live daemon answers the socket, so any process
/// still running `_cuda-clone-worker` is orphaned and is pinning a GPU context;
/// killing it lets the next golden's CUDA init proceed cleanly. Identifies
/// workers by argv (NUL-separated `/proc/<pid>/cmdline`) rather than a registry,
/// so it catches workers from a daemon instance that is already gone.
#[cfg(unix)]
fn reap_orphan_workers() {
    let me = std::process::id();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return;
    };
    let mut killed = 0u32;
    for ent in entries.flatten() {
        let name = ent.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<i32>().ok()) else {
            continue;
        };
        if pid as u32 == me {
            continue;
        }
        let Ok(cmdline) = std::fs::read(ent.path().join("cmdline")) else {
            continue;
        };
        if cmdline
            .split(|&b| b == 0)
            .any(|arg| arg == b"_cuda-clone-worker")
        {
            // SAFETY: kill(pid, SIGKILL) on a process we identified by argv as an
            // orphaned clone worker; the daemon that parented it is already gone.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
            killed += 1;
        }
    }
    if killed > 0 {
        tracing::warn!(
            count = killed,
            "swept orphaned clone-worker(s) from a dead prior daemon"
        );
        // Let the driver release the killed workers' GPU contexts before we serve.
        thread::sleep(Duration::from_millis(500));
    }
}

/// Install a clean-shutdown handler for SIGTERM/SIGINT: unlink the control
/// socket and SIGKILL our own process group (this daemon + its clone workers),
/// so a `pkill`/`kill` of the daemon never leaves GPU-pinning workers or a stale
/// socket node behind. Without this a killed daemon orphaned its workers and the
/// next golden's CUDA init stalled on their lingering context.
#[cfg(unix)]
fn install_shutdown_handler(sock: &Path) {
    use std::os::unix::ffi::OsStrExt;
    static SOCK_C: std::sync::OnceLock<std::ffi::CString> = std::sync::OnceLock::new();
    let _ = SOCK_C.set(std::ffi::CString::new(sock.as_os_str().as_bytes()).unwrap_or_default());
    unsafe extern "C" fn on_term(_sig: libc::c_int) {
        // async-signal-safe only: OnceLock::get (atomic load) + unlink + getpgrp
        // + getpid + kill + _exit.
        if let Some(c) = SOCK_C.get() {
            unsafe {
                libc::unlink(c.as_ptr());
            }
        }
        // Only group-kill when we actually lead our own group — never nuke the
        // shell/ssh that launched us if setpgid(0, 0) did not take.
        if unsafe { libc::getpgrp() } == unsafe { libc::getpid() } {
            unsafe {
                libc::kill(0, libc::SIGKILL);
            }
        }
        unsafe {
            libc::_exit(0);
        }
    }
    for sig in [libc::SIGTERM, libc::SIGINT] {
        // SAFETY: installing a handler that only unlinks + group-kills + _exits.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_term as *const () as usize;
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
}

/// Run the daemon body: bind `sock` and serve every connection in its own
/// thread against a fresh backend — all in this process, so they share one GPU
/// context. Returns only on listener failure; otherwise exits via the idle
/// watchdog (or runs until the host shuts down when the timeout is disabled).
/// Fatal-signal backtrace: the daemon and its clone workers host large unsafe
/// surfaces (the CUDA driver itself, raw-pointer translation, IPC mappings). A
/// SIGSEGV/SIGABRT/SIGBUS here previously died SILENTLY — a daemon segfault
/// under concurrent 7B vLLM engines left a 933-byte log and no evidence. The
/// handler writes the signal and a native backtrace to stderr (async-signal-
/// unsafe in principle, but we are crashing anyway — best-effort output beats
/// none) and then re-raises with the default action so wait() sees the truth.
#[cfg(unix)]
pub(crate) fn install_crash_handler(role: &'static str) {
    static ROLE: std::sync::OnceLock<&'static str> = std::sync::OnceLock::new();
    let _ = ROLE.set(role);
    unsafe extern "C" fn on_fatal(sig: libc::c_int) {
        use std::sync::atomic::{AtomicBool, Ordering};
        // A fault raised while already handling one (the capture itself
        // faulted — e.g. the original crash was inside malloc and the
        // allocating Backtrace deadlocked or re-crashed) must not recurse:
        // go straight to the default action so the process dies and dumps.
        static IN_HANDLER: AtomicBool = AtomicBool::new(false);
        if IN_HANDLER.swap(true, Ordering::SeqCst) {
            unsafe {
                libc::signal(sig, libc::SIG_DFL);
                libc::raise(sig);
            }
            return;
        }
        // If the capture deadlocks (malloc lock held by the faulting thread),
        // SIGALRM's default action ends the process instead of wedging the
        // worker forever ("FATAL signal 11; backtrace:" with no frames).
        unsafe { libc::alarm(5) };
        let role = ROLE.get().copied().unwrap_or("cuda-proc");
        eprintln!("[{role}] FATAL signal {sig}; backtrace:");
        smolvm_cuda::host::op_ring_dump();
        eprintln!("{}", std::backtrace::Backtrace::force_capture());
        unsafe {
            libc::signal(sig, libc::SIG_DFL);
            libc::raise(sig);
        }
    }
    // A stack-overflow SIGSEGV cannot run its handler on the overflowed
    // stack; SA_ONSTACK only helps if an alternate stack is registered on
    // the thread. Best-effort: register one for this (installing) thread.
    unsafe {
        static mut ALT_STACK: [u8; 256 * 1024] = [0; 256 * 1024];
        let ss = libc::stack_t {
            ss_sp: std::ptr::addr_of_mut!(ALT_STACK) as *mut libc::c_void,
            ss_flags: 0,
            ss_size: 256 * 1024,
        };
        libc::sigaltstack(&ss, std::ptr::null_mut());
    }
    for sig in [libc::SIGSEGV, libc::SIGABRT, libc::SIGBUS, libc::SIGILL] {
        // SAFETY: installing a handler that only formats + re-raises.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_fatal as *const () as usize;
            sa.sa_flags = libc::SA_ONSTACK;
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
}

/// Serve the shared CUDA daemon on `sock` (spawned as `smolvm _cuda-daemon`).
pub fn run(sock: &Path) -> io::Result<()> {
    #[cfg(unix)]
    install_crash_handler("cuda-daemon");
    // Become our own process-group leader so a clean-shutdown signal can take the
    // whole group (this daemon + its clone workers) down together without ever
    // touching the shell/ssh session that launched us. The `ensure_running` spawn
    // path already sets this at fork; this also covers a direct `_cuda-daemon &`.
    // SAFETY: setpgid(0, 0) on self; harmless best-effort (ignore EPERM if we are
    // already a session leader).
    #[cfg(unix)]
    unsafe {
        libc::setpgid(0, 0);
    }
    if let Some(parent) = sock.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // Refuse to double-bind: a live daemon on this socket already owns the GPU.
    // Clobbering its socket node would orphan it (still holding the GPU context)
    // and split state across two daemons — the "new golden hangs forever" bug.
    if is_alive(sock) {
        tracing::warn!(socket = %sock.display(),
            "a CUDA daemon already owns this socket; not starting a second one");
        return Ok(());
    }
    // No live daemon answered, but a prior one may have died (crash / SIGKILL)
    // without reaping its clone-worker children. Those workers still pin the GPU
    // context, so the next golden's CUDA init stalls on it. Sweep them before we
    // bind — this is the self-heal for stale post-fork daemon/IPC state.
    #[cfg(unix)]
    reap_orphan_workers();
    // Drop any stale socket node, then arm the clean-shutdown handler (unlink the
    // socket + take the process group down on SIGTERM/SIGINT) so a `pkill` of the
    // daemon never leaks workers or a stale socket node.
    let _ = std::fs::remove_file(sock);
    #[cfg(unix)]
    install_shutdown_handler(sock);
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
                                                                 // Path 3: a REMOTE isolating fork clone (its VM
                                                                 // proxies here over TCP) gets a worker process
                                                                 // exactly like a local one — the golden's memory
                                                                 // and the clone worker both live on THIS GPU
                                                                 // host; only the RPC crosses the network.
                                    #[cfg(unix)]
                                    {
                                        use std::os::unix::io::AsRawFd;
                                        // Clone-marked connections (preamble from the
                                        // remote clone VM's proxy) route to a worker or
                                        // are rejected; a golden's reconnect (token, no
                                        // preamble) falls through to in-daemon serving.
                                        let rdir = consume_ring_dir_preamble(s.as_raw_fd());
                                        if route_clone_connection(
                                            s.as_raw_fd(),
                                            rdir.as_deref(),
                                            None,
                                        ) {
                                            drop(s); // worker owns it / rejected
                                            continue;
                                        }
                                    }
                                    spawn_serve(s, &active_tcp, None, None);
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
    spawn_child_reaper();
    for stream in listener.incoming() {
        match stream {
            // Count the connection open for the whole serve loop so a frozen golden
            // (idle but connected) keeps the daemon alive for its clones.
            Ok(stream) => {
                // Path 3 (M1): an isolating fork clone (its VM's proxy sends a
                // clone preamble) is served in its own worker PROCESS (own
                // context/UVA) so it can hold memory at the golden's exact VAs.
                // A GOLDEN's reconnect — same lineage token, NO preamble —
                // falls through and resumes in-daemon: routing it to a worker
                // would silently serve it a reconstructed COPY of its memory.
                // Only fires under SMOLVM_CUDA_FORK_WORKERS; otherwise legacy.
                #[cfg(unix)]
                let (guest_ram, ring_dir) = {
                    use std::os::unix::io::AsRawFd;
                    let ram = consume_ram_preamble(stream.as_raw_fd());
                    let rdir = consume_ring_dir_preamble(stream.as_raw_fd());
                    let procmem = consume_procmem_preamble(stream.as_raw_fd());
                    if route_clone_connection(stream.as_raw_fd(), rdir.as_deref(), procmem) {
                        drop(stream); // worker owns it / rejected
                        continue;
                    }
                    (ram, rdir)
                };
                #[cfg(not(unix))]
                let (guest_ram, ring_dir) = (None, None::<String>);
                spawn_serve(stream, &active, guest_ram, ring_dir);
            }
            Err(e) => tracing::debug!(error = %e, "CUDA daemon accept error"),
        }
    }
    Ok(())
}

/// Serve one accepted connection on its own thread with a fresh backend, counting
/// it against `active` for the idle watchdog. Generic over the stream type so the
/// local UDS listener and the optional TCP listener share one path.
/// `guest_ram`: daemon-local mappings of the VM's guest RAM (from the RAM
/// preamble) — installing them enables the ring transport + zero-copy GPA
/// memcpys for this connection.
fn spawn_serve<S>(
    stream: S,
    active: &Arc<AtomicUsize>,
    guest_ram: Option<Vec<(u64, u64, u64)>>,
    ring_dir: Option<String>,
) where
    S: std::io::Read + std::io::Write + Send + 'static,
{
    let guard = ConnGuard::new(active);
    thread::Builder::new()
        .name("cuda-daemon-conn".into())
        .spawn(move || {
            let _guard = guard;
            let mut backend = make_backend();
            if let Some(regions) = guest_ram {
                tracing::info!(
                    count = regions.len(),
                    "guest-RAM mapped: zero-copy + rings enabled"
                );
                backend.set_guest_ram(regions);
            }
            smolvm_cuda::host::ring_dir_set(ring_dir);
            if let Err(e) = serve(stream, backend.as_mut()) {
                tracing::debug!(error = %e, "CUDA daemon connection ended");
            }
        })
        .ok();
}

/// Consume a fork-CLONE proc-mem advertisement (`SMVGPVM1`) if present: the
/// clone proxy sends `(pid, gpa, host_va, len)` for its LIVE private (COW) guest
/// RAM after its clone preamble, so the worker can pread/pwrite /proc/<pid>/mem
/// (a memfd map would be STALE golden bytes). Peek-based; `None` on any old proxy
/// or golden connection (leaves the bytes untouched for the RPC serve loop).
/// A fork clone's live-RAM advert: its pid + (gpa, host_va, len) regions.
type ProcMemAdvert = (u32, Vec<(u64, u64, u64)>);

/// Serialize a proc-mem advert into the worker env value (see `procmem_from_env`).
fn procmem_to_env(pid: u32, regions: &[(u64, u64, u64)]) -> String {
    let mut out = pid.to_string();
    for (g, h, l) in regions {
        out.push_str(&format!(";{g},{h},{l}"));
    }
    out
}

/// Parse the `SMOLVM_CUDA_CLONE_PROCMEM` worker env back into a proc-mem advert.
fn procmem_from_env() -> Option<ProcMemAdvert> {
    let v = std::env::var("SMOLVM_CUDA_CLONE_PROCMEM").ok()?;
    let mut it = v.split(';');
    let pid: u32 = it.next()?.parse().ok()?;
    let mut regions = Vec::new();
    for part in it {
        let mut c = part.split(',');
        let g: u64 = c.next()?.parse().ok()?;
        let h: u64 = c.next()?.parse().ok()?;
        let l: u64 = c.next()?.parse().ok()?;
        regions.push((g, h, l));
    }
    (!regions.is_empty()).then_some((pid, regions))
}

fn consume_procmem_preamble(fd: std::os::unix::io::RawFd) -> Option<ProcMemAdvert> {
    let mut hdr = [0u8; 20];
    let mut n = 0isize;
    for _ in 0..200 {
        n = unsafe {
            libc::recv(
                fd,
                hdr.as_mut_ptr() as *mut libc::c_void,
                hdr.len(),
                libc::MSG_PEEK,
            )
        };
        if n >= 8 && &hdr[..8] != b"SMVGPVM1" {
            return None; // not ours; leave the bytes untouched
        }
        if n >= 20 || n == 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    if n < 20 || &hdr[..8] != b"SMVGPVM1" {
        return None;
    }
    let pid = u32::from_le_bytes(hdr[8..12].try_into().unwrap());
    let count = u32::from_le_bytes(hdr[12..16].try_into().unwrap()) as usize;
    if count == 0 || count > 64 {
        return None;
    }
    let total = 20 + count * 24;
    let mut buf = vec![0u8; total];
    let mut got = 0usize;
    while got < total {
        let r = unsafe {
            libc::recv(
                fd,
                buf[got..].as_mut_ptr() as *mut libc::c_void,
                total - got,
                0,
            )
        };
        if r <= 0 {
            return None;
        }
        got += r as usize;
    }
    let mut regions = Vec::with_capacity(count);
    for i in 0..count {
        let o = 20 + i * 24;
        let gpa = u64::from_le_bytes(buf[o..o + 8].try_into().unwrap());
        let hva = u64::from_le_bytes(buf[o + 8..o + 16].try_into().unwrap());
        let len = u64::from_le_bytes(buf[o + 16..o + 24].try_into().unwrap());
        if len == 0 {
            return None;
        }
        regions.push((gpa, hva, len));
    }
    Some((pid, regions))
}

/// Consume a guest-RAM advertisement preamble if present (peek-based; absent on
/// old proxies and non-memfd VMs). Maps the advertised regions of
/// `/proc/<pid>/fd/<memfd>` MAP_SHARED into THIS process and returns them as
/// `(gpa, daemon_va, len)` for `Backend::set_guest_ram`. Mappings are leaked
/// (VM-lifetime; bounded by connections-with-adverts). Same-uid access only —
/// exactly the trust boundary the daemon already has with its VMs.
/// Consume a ring-dir advertisement (`SMVRDIR1` + u16 len + host path) if
/// present. Returns the HOST directory backing the VM's dax ring mount, which
/// `RingSetupFile` on this connection resolves file names against.
#[cfg(unix)]
fn consume_ring_dir_preamble(fd: std::os::unix::io::RawFd) -> Option<String> {
    let mut hdr = [0u8; 10];
    let mut n: isize = 0;
    // SAFETY: MSG_PEEK of the fixed header on a valid fd; loop because proxied
    // bytes can arrive in pieces.
    for _ in 0..200 {
        n = unsafe {
            libc::recv(
                fd,
                hdr.as_mut_ptr() as *mut libc::c_void,
                hdr.len(),
                libc::MSG_PEEK,
            )
        };
        if n >= 8 && &hdr[..8] != b"SMVRDIR1" {
            return None; // not ours; leave the bytes untouched
        }
        if n >= 10 || n == 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    if n < 10 || &hdr[..8] != b"SMVRDIR1" {
        return None;
    }
    let len = u16::from_le_bytes(hdr[8..10].try_into().unwrap()) as usize;
    if len == 0 || len > 512 {
        return None;
    }
    let total = 10 + len;
    let mut buf = vec![0u8; total];
    let mut got = 0usize;
    while got < total {
        // SAFETY: plain recv into our buffer.
        let r = unsafe {
            libc::recv(
                fd,
                buf[got..].as_mut_ptr() as *mut libc::c_void,
                total - got,
                0,
            )
        };
        if r <= 0 {
            return None;
        }
        got += r as usize;
    }
    String::from_utf8(buf[10..].to_vec()).ok()
}

#[cfg(unix)]
fn consume_ram_preamble(fd: std::os::unix::io::RawFd) -> Option<Vec<(u64, u64, u64)>> {
    let mut hdr = [0u8; 20];
    // SAFETY: MSG_PEEK of the fixed header on a valid fd; loops like
    // peek_clone_token because proxied bytes can arrive in pieces.
    let mut n: isize = 0;
    for _ in 0..200 {
        n = unsafe {
            libc::recv(
                fd,
                hdr.as_mut_ptr() as *mut libc::c_void,
                hdr.len(),
                libc::MSG_PEEK,
            )
        };
        if n >= 8 && &hdr[..8] != b"SMVGRAM2" {
            return None; // not ours; leave the bytes untouched
        }
        if n >= 20 || n == 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    if n < 20 || &hdr[..8] != b"SMVGRAM2" {
        return None;
    }
    let pid = u32::from_le_bytes(hdr[8..12].try_into().unwrap());
    let count = u32::from_le_bytes(hdr[12..16].try_into().unwrap()) as usize;
    if count == 0 || count > 64 {
        return None;
    }
    let total = 20 + count * 28;
    let mut buf = vec![0u8; total];
    let mut got = 0usize;
    while got < total {
        // SAFETY: plain recv consuming the preamble we just validated.
        let r = unsafe {
            libc::recv(
                fd,
                buf[got..].as_mut_ptr() as *mut libc::c_void,
                total - got,
                0,
            )
        };
        if r <= 0 {
            return None;
        }
        got += r as usize;
    }
    // One memfd PER REGION (libkrun's layout): open each via /proc and map
    // MAP_SHARED at the advertised offset.
    let mut files: std::collections::HashMap<u32, std::fs::File> = std::collections::HashMap::new();
    let mut regions = Vec::with_capacity(count);
    for i in 0..count {
        let o = 20 + i * 28;
        let gpa = u64::from_le_bytes(buf[o..o + 8].try_into().unwrap());
        let fd_no = u32::from_le_bytes(buf[o + 8..o + 12].try_into().unwrap());
        let off = u64::from_le_bytes(buf[o + 12..o + 20].try_into().unwrap());
        let len = u64::from_le_bytes(buf[o + 20..o + 28].try_into().unwrap());
        if len == 0 || off % 4096 != 0 {
            return None;
        }
        use std::os::unix::io::AsRawFd as _;
        let file = match files.entry(fd_no) {
            std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::hash_map::Entry::Vacant(v) => {
                let f = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(format!("/proc/{pid}/fd/{fd_no}"))
                    .ok()?;
                v.insert(f)
            }
        };
        // SAFETY: MAP_SHARED of the VM's guest-RAM memfd at the advertised
        // offset; failure aborts the whole advert. Mappings are leaked
        // (VM-lifetime; bounded by connections that advertise).
        let va = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                off as i64,
            )
        };
        if va == libc::MAP_FAILED {
            tracing::warn!(pid, fd_no, off, len, "guest-RAM mmap failed; sockets only");
            return None;
        }
        regions.push((gpa, va as u64, len));
    }
    Some(regions)
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

/// Staged golden handle state retained for late-attached channels:
/// (module images, function metadata, streams, events).
type SeedHandles = (
    Vec<(u64, Vec<u8>)>,
    Vec<smolvm_cuda::host::FuncMeta>,
    Vec<(u64, u64)>,
    Vec<(u64, u64)>,
);

/// Path 3 (M1): serve one isolating fork-clone connection in THIS separate worker
/// process. A per-clone process has its own CUDA primary context and thus its own
/// UVA space, so it can place memory at the golden's exact virtual addresses
/// (address-preserving isolation — no per-op pointer translation). The daemon
/// spawns us with the accepted connection's fd (see the clone routing in
/// `spawn_serve`). M2 (golden-state reconstruction) and M3 (module/graph rebuild)
/// hook in before the serve loop; establishing the process boundary comes first.
pub fn run_clone_worker(fd: std::os::unix::io::RawFd) -> io::Result<()> {
    use std::os::unix::io::FromRawFd;
    install_crash_handler("cuda-clone-worker");
    // File-ring transport (per-worker: one worker == one clone VM == one dir).
    smolvm_cuda::host::ring_dir_set(std::env::var("SMOLVM_CUDA_CLONE_RING_DIR").ok());
    let mut backend = make_backend();
    // Our own primary context (separate process ⇒ own UVA), so we can place memory
    // at the golden's exact VAs.
    let _ = backend.init();
    // Reconstruct on the GOLDEN's GPU: the exported physical lives there.
    let clone_dev: i32 = std::env::var("SMOLVM_CUDA_CLONE_DEVICE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let _ = backend.primary_ctx_retain(clone_dev);
    // Clone transport: consume the proc-mem advert (SMVGPVM1) the clone proxy
    // sent right after its clone preamble, so D2H/H2D reach the clone's LIVE
    // guest RAM via /proc/<pid>/mem instead of the ring-copy fallback.
    if let Some((pid, regions)) = procmem_from_env() {
        let n = regions.len();
        if backend.set_guest_ram_procmem(pid, regions) {
            tracing::info!(
                pid,
                count = n,
                "cuda clone-worker: proc-mem live-RAM transport enabled"
            );
        } else {
            tracing::warn!(
                pid,
                "cuda clone-worker: proc-mem unavailable; ring-copy fallback"
            );
        }
    }
    // Seed state for late-attached guest channels (see the attach listener
    // below): each attached channel serves on its own thread, and every
    // translation table is thread-local — new threads must be seeded with
    // clones of what the main serving thread installed.
    let mut seed_vmm: Option<std::collections::HashMap<u64, u64>> = None;
    let mut seed_handles: Option<SeedHandles> = None;
    // M2: reconstruct the golden's memory at its exact VAs from the layout the
    // daemon passed (SMOLVM_CUDA_CLONE_LAYOUT) + the golden's physical exported to
    // fds 4.. — BEFORE serving, so the clone's inherited pointers are valid verbatim.
    if let Ok(layout) = std::env::var("SMOLVM_CUDA_CLONE_LAYOUT") {
        let (n, vmm_trans) = reconstruct_golden_memory(backend.as_mut(), &layout, clone_dev);
        tracing::info!(
            maps = n,
            vmm_handles = vmm_trans.len(),
            "cuda clone-worker: reconstructed golden memory at its VAs"
        );
        seed_vmm = Some(vmm_trans.clone());
        // The clone unmaps/releases inherited chunks by their GOLDEN handle
        // values (torch expandable_segments trims segments under pressure);
        // untranslated, cuMemRelease segfaults on the foreign-context handle.
        smolvm_cuda::host::set_vmm_trans(vmm_trans);
        // Barrier: VMM reconstruction must fully settle before the clone runs, or a
        // later cuModuleLoadData surfaces a sticky async fault from the copies.
        if let Err(e) = backend.ctx_synchronize() {
            tracing::warn!(e, "clone-worker: sync after memory reconstruction failed");
        }
    }
    // M3a: STAGE the golden's modules/functions for LAZY reload in OUR context
    // (reloading all up front stalls serving ~2s and breaks the clone connection)
    // + recreate streams/events, then install the translation so the clone's
    // inherited kernel launches resolve (each module reloads on first use).
    if let Ok(modpath) = std::env::var("SMOLVM_CUDA_CLONE_MODULES") {
        let (mod_images, func_meta, streams, events, graphs, lib_handles) =
            reconstruct_golden_modules(backend.as_mut(), &modpath);
        let (nm, nf, ns, ne, ng, nlh) = (
            mod_images.len(),
            func_meta.len(),
            streams.len(),
            events.len(),
            graphs.len(),
            lib_handles.len(),
        );
        // Retained for attached-channel threads (module images are the bulk —
        // tens of MB per worker; the price of correct late channels).
        seed_handles = Some((
            mod_images.clone(),
            func_meta.clone(),
            streams.clone(),
            events.clone(),
        ));
        smolvm_cuda::host::set_handle_trans(mod_images, func_meta, streams, events);
        // Re-create the golden's top-level cuBLAS/cuBLASLt/cuDNN handles in
        // THIS process and map the clone's inherited values to them — library
        // handles are process-local, so a pre-fork handle would otherwise fail
        // the clone's first post-fork library call.
        let nseeded = smolvm_cuda::host::replay_lib_handles(backend.as_mut(), &lib_handles);
        // M3b: rebuild the golden's captured CUDA graphs in THIS context, now
        // that modules can lazily reload and memory is reconstructed (kernel-arg
        // pointers reference the golden VAs, valid here). Maps the clone's
        // inherited graph/exec handles to the worker's rebuilt reals.
        let nrebuilt = smolvm_cuda::host::rebuild_clone_graphs(backend.as_mut(), graphs);
        let _ = std::fs::remove_file(&modpath);
        // P3b: pre-warm NOW (module reloads + graph re-capture into the
        // process-wide registries), while the guest VM is still resuming —
        // serving sessions adopt the results instead of doing this work on
        // the guest's first CUDA call.
        smolvm_cuda::host::prewarm_clone_worker(backend.as_mut());
        tracing::info!(
            modules = nm,
            functions = nf,
            streams = ns,
            events = ne,
            graphs = ng,
            graphs_rebuilt = nrebuilt,
            lib_handles = nlh,
            lib_handles_seeded = nseeded,
            "cuda clone-worker: staged modules for lazy reload + remapped handles"
        );
    }
    // Late-attached guest channels: the guest dials fresh daemon connections
    // after the fork (first-ever cuBLAS init inside a clone does exactly
    // this); the daemon forwards each such fd over the control channel and we
    // serve it on its own thread, seeded with the same translation state.
    if let Some(ctrl) = std::env::var("SMOLVM_CUDA_CLONE_CTRL")
        .ok()
        .and_then(|v| v.parse::<std::os::unix::io::RawFd>().ok())
    {
        let seed_alloc = smolvm_cuda::host::worker_alloc_trans_snapshot();
        let seed = std::sync::Arc::new((seed_vmm, seed_handles, seed_alloc));
        std::thread::spawn(move || loop {
            match recv_fd(ctrl) {
                Ok(nfd) => {
                    let seed = seed.clone();
                    std::thread::spawn(move || serve_attached_channel(nfd, clone_dev, &seed));
                }
                Err(e) => {
                    tracing::info!(error = %e, "clone-worker: control channel closed");
                    break;
                }
            }
        });
    }
    // The handed-off connection may be a local UDS (VM on this host) or a TCP
    // socket (remote client driving this GPU host) — wrap by actual domain.
    // (getsockname is portable unix; SO_DOMAIN would be Linux-only.)
    let mut addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: plain getsockname on a valid fd with a correctly-sized out buffer.
    unsafe {
        libc::getsockname(fd, &mut addr as *mut _ as *mut libc::sockaddr, &mut len);
    }
    let domain = libc::c_int::from(addr.ss_family);
    tracing::info!(
        fd,
        tcp = domain != libc::AF_UNIX,
        "cuda clone-worker: serving in its own context / UVA space"
    );
    if domain == libc::AF_UNIX {
        // SAFETY: the daemon handed us sole ownership of the accepted fd.
        let stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
        serve(stream, backend.as_mut())
    } else {
        // SAFETY: as above; a TCP connection from the daemon's network listener.
        let stream = unsafe { std::net::TcpStream::from_raw_fd(fd) };
        let _ = stream.set_nodelay(true);
        serve(stream, backend.as_mut())
    }
}

/// Serve one late-attached guest channel inside the clone worker. Own backend
/// handle, same primary context (same UVA space), thread-local translation
/// tables seeded from the main serving thread's snapshot so golden handles and
/// translated allocations resolve identically on this channel.
#[cfg(unix)]
#[allow(clippy::type_complexity)]
fn serve_attached_channel(
    fd: std::os::unix::io::RawFd,
    dev: i32,
    seed: &(
        Option<std::collections::HashMap<u64, u64>>,
        Option<SeedHandles>,
        Vec<(u64, u64, u64)>,
    ),
) {
    use std::os::unix::io::FromRawFd;
    let mut backend = make_backend();
    let _ = backend.init();
    let _ = backend.primary_ctx_retain(dev);
    if let Some((pid, regions)) = procmem_from_env() {
        backend.set_guest_ram_procmem(pid, regions);
    }
    // File-ring transport: attached channels serve on their own threads, and
    // the ring dir is per-worker (thread-local install per serve thread).
    smolvm_cuda::host::ring_dir_set(std::env::var("SMOLVM_CUDA_CLONE_RING_DIR").ok());
    let (vmm, handles, alloc) = seed;
    if let Some(v) = vmm {
        smolvm_cuda::host::set_vmm_trans(v.clone());
    }
    if let Some((m, f, s, e)) = handles {
        smolvm_cuda::host::set_handle_trans(m.clone(), f.clone(), s.clone(), e.clone());
    }
    if !alloc.is_empty() {
        smolvm_cuda::host::set_worker_alloc_trans(alloc.clone());
    }
    let mut addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: plain getsockname on a valid fd with a correctly-sized out buffer.
    unsafe {
        libc::getsockname(fd, &mut addr as *mut _ as *mut libc::sockaddr, &mut len);
    }
    let domain = libc::c_int::from(addr.ss_family);
    tracing::info!(
        fd,
        tcp = domain != libc::AF_UNIX,
        "cuda clone-worker: serving attached channel"
    );
    let r = if domain == libc::AF_UNIX {
        // SAFETY: recv_fd handed us sole ownership of the received fd.
        let stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
        smolvm_cuda::host::serve(stream, backend.as_mut())
    } else {
        // SAFETY: as above; a TCP connection forwarded by the daemon.
        let stream = unsafe { std::net::TcpStream::from_raw_fd(fd) };
        let _ = stream.set_nodelay(true);
        smolvm_cuda::host::serve(stream, backend.as_mut())
    };
    if let Err(e) = r {
        tracing::info!(error = %e, fd, "clone-worker: attached channel ended");
    }
}

/// IPC-import a golden physical from `fd`, retrying on transient failure with a
/// ctx_synchronize between attempts. Defense-in-depth: the deterministic e=999
/// import failure was the CLOEXEC fd handoff (fixed in spawn_clone_worker); this
/// guards the remaining first-import-in-fresh-context warm-up window.
#[cfg(unix)]
fn import_with_retry(b: &mut dyn Backend, fd: i32) -> Result<u64, i32> {
    let mut last = 0;
    for attempt in 0..5 {
        match b.mem_import_handle(fd) {
            Ok(h) => {
                if attempt > 0 {
                    tracing::info!(fd, attempt, "M2: import succeeded on retry");
                }
                return Ok(h);
            }
            Err(e) => {
                last = e;
                let _ = b.ctx_synchronize();
            }
        }
    }
    Err(last)
}

/// M2: rebuild the golden's VMM layout in THIS worker's context at the golden's
/// EXACT VAs. `layout` = `"resv=va:size,…|maps=va:size:fdidx:loaded:ghandle,…"` (hex);
/// each map's physical was exported by the daemon to fd `4 + fdidx`. We import +
/// map at the same VA — address-preserving, so inherited pointers and rebuilt
/// graphs are valid verbatim. (Weights are shared here; private-mutable copy for
/// full isolation is the next refinement.)
///
/// Also returns the golden-handle → worker-handle map (from `ghandle`): the
/// clone's torch later unmaps/releases inherited chunks by their GOLDEN handle
/// values, and cuMemRelease on a foreign-context handle SEGFAULTS the worker.
#[cfg(unix)]
fn reconstruct_golden_memory(
    b: &mut dyn Backend,
    layout: &str,
    device: i32,
) -> (usize, std::collections::HashMap<u64, u64>) {
    let mut vmm_trans = std::collections::HashMap::new();
    let (mut resv_s, mut maps_s, mut aregions_s, mut allocs_s) = ("", "", "", "");
    let mut astage: Option<i32> = None;
    for part in layout.split('|') {
        if let Some(r) = part.strip_prefix("resv=") {
            resv_s = r;
        }
        if let Some(m) = part.strip_prefix("maps=") {
            maps_s = m;
        }
        if let Some(a) = part.strip_prefix("astage=") {
            astage = a.parse().ok();
        }
        if let Some(a) = part.strip_prefix("aregions=") {
            aregions_s = a;
        }
        if let Some(a) = part.strip_prefix("allocs=") {
            allocs_s = a;
        }
    }
    let hx = |s: &str| u64::from_str_radix(s, 16).ok();
    for e in resv_s.split(',').filter(|s| !s.is_empty()) {
        if let Some((va, size)) = e.split_once(':') {
            if let (Some(va), Some(size)) = (hx(va), hx(size)) {
                if let Err(e) = b.mem_address_reserve_fixed(size, 0, va) {
                    tracing::warn!(e, va, "M2: reserve-fixed failed");
                }
            }
        }
    }
    let share_weights = smolvm_cuda::host::path3_share_weights_enabled();
    let (mut count, mut shared) = (0, 0);
    for e in maps_s.split(',').filter(|s| !s.is_empty()) {
        let f: Vec<&str> = e.split(':').collect();
        if f.len() < 3 {
            continue;
        }
        let (Some(va), Some(size), Ok(idx)) = (hx(f[0]), hx(f[1]), f[2].parse::<i32>()) else {
            continue;
        };
        // 4th field (loaded) marks a fully-H2D-covered weight range; 5th is the
        // golden's handle value for this chunk (hex).
        let loaded = f.get(3).map(|s| *s == "1").unwrap_or(false);
        let golden_h = f.get(4).and_then(|s| hx(s));

        // DENSITY (opt-in, SMOLVM_CUDA_FORK_SHARE_WEIGHTS): a loaded weight range is
        // read-only during frozen-base fine-tuning (LoRA freezes the base; only the
        // clone's PRIVATE adapters train), so SHARE the golden's physical at its VA —
        // every clone imports the same physical, so one weight set lives in VRAM.
        // Mapped READ-WRITE: unsloth's fix_untrained_tokens writes the embedding at
        // trainer setup, and that write is identical across clones (same base → same
        // fix), so sharing stays correct for this use case (verified by each clone
        // still learning its distinct task). On ANY share failure, fall through to a
        // private copy — never leave the VA unmapped (a hole faults the clone).
        if share_weights && loaded {
            let mut ok = false;
            if let Ok(gh) = import_with_retry(b, 4 + idx) {
                if b.mem_map(va, size, 0, gh).is_ok() {
                    // Sharing the golden's frozen base READ-WRITE across clones
                    // is only correct when the base is never written post-fork.
                    // Unsloth writes the embedding via a KERNEL (undetectable by
                    // the COW path, which only catches explicit mem ops), so at
                    // N>=3 concurrent clones those writes race on the shared
                    // physical and corrupt every sibling (loss=nan). Copy-mode
                    // (the DEFAULT, no --share-weights) is correct at all N.
                    // SMOLVM_CUDA_SHARE_RO=1 maps read-only so a base write
                    // faults loudly instead of corrupting silently (diagnostic;
                    // currently SIGSEGVs on base-writing workloads — the proper
                    // fix is to private-copy only the written ranges).
                    let set = if std::env::var("SMOLVM_CUDA_SHARE_RO").as_deref() == Ok("1") {
                        b.mem_set_access_ro(va, size, device)
                    } else {
                        b.mem_set_access(va, size, device)
                    };
                    if set.is_ok() {
                        ok = true;
                    } else {
                        let _ = b.mem_unmap(va, size); // roll back for the fallback
                    }
                }
                match (ok, golden_h) {
                    // Keep gh held and record golden→worker: the clone later
                    // releases this chunk by the GOLDEN's handle value.
                    (true, Some(g)) => {
                        vmm_trans.insert(g, gh);
                    }
                    // Legacy layout (no handle field) or failure: the va mapping
                    // holds its own ref, so drop ours.
                    _ => {
                        let _ = b.mem_release(gh);
                    }
                }
            }
            if ok {
                shared += 1;
                count += 1;
                continue;
            }
            tracing::warn!(idx, "M2-share: share failed → private-copy fallback");
            // fall through to the private path (va stays reserved + unmapped)
        }
        // Private-mutable, address-preserving: map a PRIVATE physical at the golden
        // VA, then copy the golden's bytes in via a temp mapping of the imported
        // physical. Reads see the golden's data; writes hit the clone's own copy,
        // so a clone can't corrupt the frozen golden.
        let priv_h = match b.mem_create(size, device) {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(e, "M2: private create failed");
                continue;
            }
        };
        if let Err(e) = b.mem_map(va, size, 0, priv_h) {
            tracing::warn!(e, va, "M2: private map failed");
            continue;
        }
        // priv_h stays held (never released here): the clone releases this chunk
        // post-fork by the GOLDEN's handle value, translated to priv_h.
        if let Some(g) = golden_h {
            vmm_trans.insert(g, priv_h);
        }
        if let Err(e) = b.mem_set_access(va, size, device) {
            tracing::warn!(e, va, "M2: private set_access failed");
        }
        match import_with_retry(b, 4 + idx) {
            Ok(gh) => {
                if let Ok(tmp) = b.mem_address_reserve(size, 0) {
                    match b.mem_map(tmp, size, 0, gh) {
                        Ok(()) => {
                            if let Err(e) = b.mem_set_access(tmp, size, device) {
                                tracing::warn!(e, "M2: temp set_access failed");
                            }
                            if let Err(e) = b.memcpy_dtod(va, tmp, size) {
                                tracing::warn!(e, va, tmp, "M2: dtod copy failed");
                            }
                            // The copy must finish before we unmap the temp source,
                            // or the in-flight copy faults on unmapped memory.
                            let _ = b.ctx_synchronize();
                            let _ = b.mem_unmap(tmp, size);
                        }
                        Err(e) => tracing::warn!(e, tmp, "M2: temp map failed"),
                    }
                    let _ = b.mem_address_free(tmp, size);
                }
                let _ = b.mem_release(gh);
            }
            Err(e) => tracing::warn!(e, idx, "M2: import failed"),
        }
        count += 1;
    }
    if share_weights {
        tracing::info!(shared, private = count - shared, "M2: shared weight ranges");
    }
    // Non-VMM golden allocations (`cudaMalloc` — a plain-torch golden keeps ALL
    // its tensors here): copy each from the daemon's staged export into a fresh
    // private buffer and record a POINTER TRANSLATION, exactly like the
    // in-daemon isolate path. cudaMalloc VAs can't be address-preserved — they
    // collide with the worker's own host mappings (cuMemAddressReserve treats
    // the address as a hint) — but every op already translates through
    // `dptr_trans`, so translated copies are equivalent.
    if let (Some(sidx), false) = (astage, aregions_s.is_empty()) {
        let regions: Vec<(u64, u64, u64)> = aregions_s
            .split(',')
            .filter(|e| !e.is_empty())
            .filter_map(|e| {
                let f: Vec<&str> = e.split(':').collect();
                match (
                    hx(f[0]),
                    f.get(1).and_then(|v| hx(v)),
                    f.get(2).and_then(|v| hx(v)),
                ) {
                    (Some(b0), Some(sz), Some(off)) => Some((b0, sz, off)),
                    _ => None,
                }
            })
            .collect();
        let allocs: Vec<(u64, u64)> = allocs_s
            .split(',')
            .filter(|e| !e.is_empty())
            .filter_map(|e| {
                let (d, sz) = e.split_once(':')?;
                Some((hx(d)?, hx(sz)?))
            })
            .collect();
        // VA guard: reserve every golden non-VMM span at its exact address so
        // fresh allocations in this worker can never land inside one. The
        // session's dptr translation is RANGE-based — an untranslated fresh
        // pointer inside a golden range gets rewritten into the staged copy
        // (silent corruption) or past its end (async illegal address that
        // poisons the context: e=700 on every later op — found via QA-1l,
        // first-ever cuBLAS init inside a clone).
        for &(b0, sz, _) in &regions {
            if let Err(e) = b.mem_address_reserve_fixed(sz, 0, b0) {
                tracing::warn!(e, va = b0, size = sz, "M2-alloc: VA guard reserve failed");
            }
        }
        let total: u64 = regions.iter().map(|r| r.1).sum();
        let mut trans: Vec<(u64, u64, u64)> = Vec::new();
        match import_with_retry(b, 4 + sidx) {
            Ok(sh) => {
                if let Ok(tmp) = b.mem_address_reserve(total, 0) {
                    if b.mem_map(tmp, total, 0, sh).is_ok() {
                        let _ = b.mem_set_access(tmp, total, device);
                        for &(d, sz) in &allocs {
                            // Staging offset: region offset + intra-region delta.
                            let Some(&(base, _, off)) =
                                regions.iter().find(|&&(b0, rs, _)| d >= b0 && d < b0 + rs)
                            else {
                                continue;
                            };
                            let cdptr = match b.mem_alloc(sz) {
                                Ok(c) => c,
                                Err(e) => {
                                    tracing::warn!(e, d, "M2-alloc: copy alloc failed");
                                    continue;
                                }
                            };
                            if let Err(e) = b.memcpy_dtod(cdptr, tmp + off + (d - base), sz) {
                                tracing::warn!(e, d, "M2-alloc: dtod failed");
                            }
                            trans.push((d, sz, cdptr));
                        }
                        let _ = b.ctx_synchronize();
                        let _ = b.mem_unmap(tmp, total);
                    } else {
                        tracing::warn!("M2-alloc: staging map failed");
                    }
                    let _ = b.mem_address_free(tmp, total);
                }
                let _ = b.mem_release(sh);
            }
            Err(e) => tracing::warn!(e, "M2-alloc: staging import failed"),
        }
        tracing::info!(
            copies = trans.len(),
            of = allocs.len(),
            bytes = total,
            "M2-alloc: private translated copies of the golden's non-VMM allocations"
        );
        count += trans.len();
        smolvm_cuda::host::set_worker_alloc_trans(trans);
    }
    (count, vmm_trans)
}

/// M3a: parse the golden's module IMAGES + function METADATA (for LAZY reload in
/// THIS worker at first use — reloading ~400 modules up front stalls the clone
/// ~2s and breaks its connection) and RECREATE its streams/events now (few,
/// cheap). Returns `(mod_images, func_meta, streams, events)`. Reads the blob the
/// daemon wrote (path in `SMOLVM_CUDA_CLONE_MODULES`):
/// `[u32 nmods]([u64 h][u32 len][image])* [u32 nfuncs]([u64 fn][u64 mod][u32 len][name])*
///  [u32 nstreams]([u64 h][u32 flags])* [u32 nevents]([u64 h][u32 flags])*`.
#[cfg(unix)]
#[allow(clippy::type_complexity)]
fn reconstruct_golden_modules(
    b: &mut dyn Backend,
    path: &str,
) -> (
    Vec<(u64, Vec<u8>)>,
    Vec<smolvm_cuda::host::FuncMeta>,
    Vec<(u64, u64)>,
    Vec<(u64, u64)>,
    Vec<(u64, u64, smolvm_cuda::host::GraphSer)>,
    Vec<(u8, u16, u64, Vec<u8>)>,
) {
    let mut mod_images = Vec::new();
    let mut func_meta = Vec::new();
    let mut stream_trans = Vec::new();
    let mut event_trans = Vec::new();
    let mut graphs: Vec<(u64, u64, smolvm_cuda::host::GraphSer)> = Vec::new();
    let mut lib_handles: Vec<(u8, u16, u64, Vec<u8>)> = Vec::new();
    let Ok(buf) = std::fs::read(path) else {
        return (
            mod_images,
            func_meta,
            stream_trans,
            event_trans,
            graphs,
            lib_handles,
        );
    };
    let mut p = 0usize;
    macro_rules! need {
        ($n:expr) => {
            if p + $n > buf.len() {
                return (
                    mod_images,
                    func_meta,
                    stream_trans,
                    event_trans,
                    graphs,
                    lib_handles,
                );
            }
        };
    }
    macro_rules! ru32 {
        () => {{
            need!(4);
            let v = u32::from_le_bytes(buf[p..p + 4].try_into().unwrap());
            p += 4;
            v
        }};
    }
    macro_rules! ru64 {
        () => {{
            need!(8);
            let v = u64::from_le_bytes(buf[p..p + 8].try_into().unwrap());
            p += 8;
            v
        }};
    }
    // Modules: just STAGE the images (reloaded lazily on first use in the worker).
    let nmods = ru32!();
    for _ in 0..nmods {
        let gh = ru64!();
        let ilen = ru32!() as usize;
        need!(ilen);
        mod_images.push((gh, buf[p..p + ilen].to_vec()));
        p += ilen;
    }
    // Functions: stage golden fn → (golden module, name); resolved lazily.
    let nfuncs = ru32!();
    for _ in 0..nfuncs {
        let gf = ru64!();
        let gm = ru64!();
        let nlen = ru32!() as usize;
        need!(nlen);
        let name = String::from_utf8_lossy(&buf[p..p + nlen]).into_owned();
        p += nlen;
        let nattrs = ru32!();
        let mut attrs = Vec::with_capacity(nattrs as usize);
        for _ in 0..nattrs {
            let a = ru32!() as i32;
            let v = ru32!() as i32;
            attrs.push((a, v));
        }
        func_meta.push((gf, gm, name, attrs));
    }
    // Streams + events: recreate each with its golden create flags in OUR context,
    // mapping the golden's inherited raw handle → our own (same M3a pattern).
    let nstreams = ru32!();
    for _ in 0..nstreams {
        let gs = ru64!();
        let flags = ru32!();
        match b.stream_create(flags) {
            Ok(ws) => stream_trans.push((gs, ws)),
            Err(e) => tracing::warn!(e, "M3a: stream recreate failed"),
        }
    }
    let nevents = ru32!();
    for _ in 0..nevents {
        let ge = ru64!();
        let flags = ru32!();
        match b.event_create(flags) {
            Ok(we) => event_trans.push((ge, we)),
            Err(e) => tracing::warn!(e, "M3a: event recreate failed"),
        }
    }
    // M3b: parse captured graphs (rebuilt later, after set_handle_trans). Absent
    // in older blobs → the `p < buf.len()` guard leaves `graphs` empty.
    if p < buf.len() {
        let ngraphs = ru32!();
        for _ in 0..ngraphs {
            let graph_vh = ru64!();
            let exec_vh = ru64!();
            let nnodes = ru32!();
            let mut nodes = Vec::with_capacity(nnodes as usize);
            for _ in 0..nnodes {
                let func = ru64!();
                let mut d = [0u32; 7];
                for v in d.iter_mut() {
                    *v = ru32!();
                }
                let nparams = ru32!();
                let mut params = Vec::with_capacity(nparams as usize);
                for _ in 0..nparams {
                    let plen = ru32!() as usize;
                    need!(plen);
                    params.push(buf[p..p + plen].to_vec());
                    p += plen;
                }
                nodes.push(smolvm_cuda::host::GraphKernelNode {
                    func,
                    grid: [d[0], d[1], d[2]],
                    block: [d[3], d[4], d[5]],
                    shared_mem: d[6],
                    params,
                });
            }
            let nedges = ru32!();
            let mut edges = Vec::with_capacity(nedges as usize);
            for _ in 0..nedges {
                let f = ru32!();
                let t = ru32!();
                edges.push((f, t));
            }
            graphs.push((
                graph_vh,
                exec_vh,
                smolvm_cuda::host::GraphSer { nodes, edges },
            ));
        }
    }
    // Library-handle creates to replay in this worker (absent in older blobs).
    if p < buf.len() {
        let nlh = ru32!();
        for _ in 0..nlh {
            need!(1);
            let lib = buf[p];
            p += 1;
            need!(2);
            let func = u16::from_le_bytes(buf[p..p + 2].try_into().unwrap());
            p += 2;
            let h = ru64!();
            let alen = ru32!() as usize;
            need!(alen);
            let args = buf[p..p + alen].to_vec();
            p += alen;
            lib_handles.push((lib, func, h, args));
        }
    }
    // P3b: capture-replay op-logs (absent in older blobs). Installed into a
    // thread-local for the serving session to drain and replay lazily.
    let mut noplogs = 0usize;
    if p < buf.len() {
        let ng = ru32!();
        let mut oplogs: Vec<(u64, u64, Vec<Vec<u8>>)> = Vec::with_capacity(ng as usize);
        for _ in 0..ng {
            let graph_vh = ru64!();
            let exec_vh = ru64!();
            let nops = ru32!();
            let mut ops = Vec::with_capacity(nops as usize);
            for _ in 0..nops {
                let olen = ru32!() as usize;
                need!(olen);
                ops.push(buf[p..p + olen].to_vec());
                p += olen;
            }
            oplogs.push((graph_vh, exec_vh, ops));
        }
        noplogs = oplogs.len();
        smolvm_cuda::host::set_worker_graph_oplogs(oplogs);
    }
    tracing::info!(
        nmods,
        nfuncs,
        nstreams,
        nevents,
        ngraphs = graphs.len(),
        noplogs,
        streams = stream_trans.len(),
        events = event_trans.len(),
        lib_handles = lib_handles.len(),
        "M3a: staged golden modules/functions for lazy reload + recreated streams/events"
    );
    (
        mod_images,
        func_meta,
        stream_trans,
        event_trans,
        graphs,
        lib_handles,
    )
}

/// Strip a fork-clone connection preamble (magic + clone id) if present,
/// returning the clone id. The preamble is sent by a CLONE VM's proxy before
/// any RPC frames (see `cuda_host::proxy_to_daemon`); the GOLDEN's connections
/// never carry it. Must run on every accepted connection REGARDLESS of routing
/// mode — an unconsumed preamble would corrupt the frame stream. Non-preamble
/// connections are left untouched (peek only).
#[cfg(unix)]
fn consume_clone_preamble(fd: std::os::unix::io::RawFd) -> Option<(u64, u8)> {
    let mut buf = [0u8; 17];
    // Same buffered-in-pieces caveat as peek_clone_token: retry the peek
    // briefly so a slow proxy write can't make us misread the magic.
    let mut n: isize = 0;
    for _ in 0..200 {
        n = unsafe {
            libc::recv(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                libc::MSG_PEEK,
            )
        };
        // Enough to decide: 8 bytes tells us magic-or-not; 16 is the full
        // preamble. A legit first frame is ≥ 5 bytes, so a short non-magic
        // prefix resolves as soon as the magic mismatches.
        if n >= 8 && buf[..(n as usize).min(8)] != smolvm_cuda::proto::CLONE_PREAMBLE_MAGIC {
            return None;
        }
        if n >= 17 || n == 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    if n < 17 || buf[..8] != smolvm_cuda::proto::CLONE_PREAMBLE_MAGIC {
        return None;
    }
    // Consume exactly the 17 preamble bytes, leaving the RPC stream intact.
    // SAFETY: plain recv on a valid fd; MSG_WAITALL for the already-peeked bytes.
    let c = unsafe {
        libc::recv(
            fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            17,
            libc::MSG_WAITALL,
        )
    };
    if c != 17 {
        return None;
    }
    Some((u64::from_le_bytes(buf[8..16].try_into().unwrap()), buf[16]))
}

/// Live clone workers keyed by (lineage token, clone id) → (worker pid,
/// control fd). New connections from a clone whose worker is STILL ALIVE are
/// ATTACHED to that worker over the control fd (SCM_RIGHTS) — guests open
/// fresh daemon channels after the fork (first-ever cuBLAS init inside a
/// clone does), and a fresh worker would re-reconstruct from the golden and
/// silently DISCARD the clone's accumulated GPU state. Dead entries are
/// replaced (worker crash → a fresh worker is the best recovery available).
#[cfg(unix)]
type CloneWorkerEntry = (u32, std::os::unix::io::RawFd);
#[cfg(unix)]
fn clone_worker_registry() -> &'static Mutex<std::collections::HashMap<(u64, u64), CloneWorkerEntry>>
{
    static REG: OnceLock<Mutex<std::collections::HashMap<(u64, u64), CloneWorkerEntry>>> =
        OnceLock::new();
    REG.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

/// Route one just-accepted connection: strip the clone preamble (always), and
/// when it marks an isolating fork clone, spawn/refuse its worker. Returns
/// `true` when the connection was consumed (routed or rejected); `false` means
/// the caller serves it normally — including a GOLDEN's own reconnect, whose
/// token-bearing Init WITHOUT the preamble must resume in-daemon (a worker
/// would silently serve it a reconstructed COPY of its memory).
#[cfg(unix)]
fn route_clone_connection(
    fd: std::os::unix::io::RawFd,
    ring_dir: Option<&str>,
    procmem: Option<ProcMemAdvert>,
) -> bool {
    let Some((clone_id, flags)) = consume_clone_preamble(fd) else {
        return false;
    };
    let share_weights = flags & 1 != 0;
    // Warm dial (flag bit 1): the clone VM's proxy dials at STARTUP so worker
    // spawn (CUDA init + memory reconstruction + module/graph pre-warm) runs
    // concurrent with guest resume instead of on the guest's first CUDA call.
    // No Init ever arrives on this connection — it parks as the worker's idle
    // primary channel. The golden token is inferred from the registered
    // layouts (unambiguous with one golden; otherwise skip and let the real
    // channel spawn with its true token).
    if flags & 2 != 0 {
        let mut reg = clone_worker_registry().lock().unwrap();
        let live = reg.iter().find_map(|(&(_, cid), &(pid, ctrl))| {
            // SAFETY: kill(pid, 0) — pure liveness probe, no signal delivered.
            (cid == clone_id && unsafe { libc::kill(pid as i32, 0) } == 0).then_some((pid, ctrl))
        });
        if let Some((_pid, ctrl)) = live {
            // Worker already up (a real channel won the race): park there.
            let _ = send_fd(ctrl, fd);
            return true;
        }
        let tokens = smolvm_cuda::host::layout_tokens();
        let [token] = tokens[..] else {
            tracing::info!(
                clone_id,
                goldens = tokens.len(),
                "warm dial: cannot infer golden token; deferring spawn to first real channel"
            );
            return false;
        };
        match spawn_clone_worker(fd, token, share_weights, ring_dir, procmem.clone()) {
            Ok((pid, ctrl)) => {
                reg.insert((token, clone_id), (pid, ctrl));
                tracing::info!(
                    token,
                    clone_id,
                    worker_pid = pid,
                    "warm dial: spawned clone worker ahead of first CUDA call"
                );
                return true;
            }
            Err(e) => {
                tracing::warn!(error = %e, token, clone_id, "warm dial: worker spawn failed");
                return false;
            }
        }
    }
    let Some(token) = peek_clone_token(fd) else {
        // A clone VM's connection whose Init carries no lineage token. The
        // guest treats CUDA state as process-global, so if this clone already
        // has a live worker, the channel MUST serve there: a cuBLAS handle
        // created through an in-daemon session is invisible to the worker's
        // sessions (vh-miss → NOT_INITIALIZED on the compute channel). Only
        // when no worker exists is in-daemon serving correct (genuinely
        // fresh post-fork work before any isolating resume).
        let reg = clone_worker_registry().lock().unwrap();
        let live = reg.iter().find_map(|(&(_, cid), &(pid, ctrl))| {
            // SAFETY: kill(pid, 0) — pure liveness probe, no signal delivered.
            (cid == clone_id && unsafe { libc::kill(pid as i32, 0) } == 0).then_some((pid, ctrl))
        });
        if let Some((pid, ctrl)) = live {
            match send_fd(ctrl, fd) {
                Ok(()) => {
                    tracing::info!(
                        clone_id,
                        worker_pid = pid,
                        "attached token-less clone channel to its live worker"
                    );
                    return true; // worker owns an in-flight dup; caller drops its copy
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        clone_id,
                        worker_pid = pid,
                        "token-less channel attach failed; serving in-daemon"
                    );
                }
            }
        }
        return false;
    };
    let mut reg = clone_worker_registry().lock().unwrap();
    if let Some(&(pid, ctrl)) = reg.get(&(token, clone_id)) {
        // Reap first: an exited worker stays a ZOMBIE (the daemon is its parent
        // and nothing waits on it), and kill(pid, 0) reports zombies as alive —
        // without this, one worker death makes every reconnect of that clone
        // rejected forever (observed as a 54/s reconnect storm on H100).
        // Reaping also surfaces HOW it died, which nothing logged before.
        let mut status: libc::c_int = 0;
        // SAFETY: WNOHANG waitpid on our own child; no blocking, no signals.
        let r = unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) };
        if r == pid as i32 {
            let (code, sig) = (
                libc::WEXITSTATUS(status),
                if libc::WIFSIGNALED(status) {
                    libc::WTERMSIG(status)
                } else {
                    0
                },
            );
            tracing::warn!(
                token,
                clone_id,
                worker_pid = pid,
                exit_code = code,
                signal = sig,
                "clone worker had exited; reaped — spawning a fresh worker for the reconnect"
            );
        }
        // SAFETY: kill(pid, 0) — pure liveness probe, no signal delivered.
        else if unsafe { libc::kill(pid as i32, 0) } == 0 {
            // The clone opened ANOTHER channel (guests dial fresh connections
            // post-fork — e.g. first cuBLAS init). Hand the fd to the live
            // worker so the channel serves in the clone's context; a fresh
            // worker would silently reset the clone's GPU state, and serving
            // in-daemon would split the guest across two UVA spaces.
            match send_fd(ctrl, fd) {
                Ok(()) => {
                    tracing::info!(
                        token,
                        clone_id,
                        worker_pid = pid,
                        "attached new clone channel to its live worker"
                    );
                    return true; // worker owns an in-flight dup; caller drops its copy
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        token,
                        clone_id,
                        worker_pid = pid,
                        "channel attach to live worker failed; rejecting the connection"
                    );
                    return true; // consumed: caller drops the stream (fail fast)
                }
            }
        }
        reg.remove(&(token, clone_id));
        // SAFETY: control fd of a dead/reaped worker.
        unsafe { libc::close(ctrl) };
    }
    // A warm-dial worker may be registered under an INFERRED token. A clone
    // has exactly one golden lineage, so any live worker for this clone_id is
    // the right one — attach rather than spawning a duplicate (which would
    // split the clone's CUDA state across two processes).
    let live = reg.iter().find_map(|(&(t, cid), &(pid, ctrl))| {
        // SAFETY: kill(pid, 0) — pure liveness probe, no signal delivered.
        (cid == clone_id && t != token && unsafe { libc::kill(pid as i32, 0) } == 0)
            .then_some((pid, ctrl))
    });
    if let Some((pid, ctrl)) = live {
        match send_fd(ctrl, fd) {
            Ok(()) => {
                tracing::info!(
                    token,
                    clone_id,
                    worker_pid = pid,
                    "attached tokened clone channel to its (warm-spawned) live worker"
                );
                return true;
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    token,
                    clone_id,
                    worker_pid = pid,
                    "attach to warm worker failed; spawning fresh"
                );
            }
        }
    }
    match spawn_clone_worker(fd, token, share_weights, ring_dir, procmem.clone()) {
        Ok((pid, ctrl)) => {
            reg.insert((token, clone_id), (pid, ctrl));
            tracing::info!(
                token,
                clone_id,
                worker_pid = pid,
                share_weights,
                "routed isolating clone to a worker process"
            );
        }
        Err(e) => {
            // REJECT rather than serve in-process: this IS an isolating clone
            // (preamble matched), and the legacy shared path can't serve it —
            // its inherited pointers are garbage in a fresh context, so the
            // guest would wedge mid-training. Closing makes it fail fast.
            tracing::warn!(error = %e, token, "clone-worker spawn failed; rejecting the clone connection");
        }
    }
    true
}

/// SCM_RIGHTS-send one fd over a control socketpair (one data byte as payload).
#[cfg(unix)]
fn send_fd(chan: std::os::unix::io::RawFd, fd: std::os::unix::io::RawFd) -> io::Result<()> {
    let mut data = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr() as *mut libc::c_void,
        iov_len: 1,
    };
    // SAFETY: standard sendmsg with a single SCM_RIGHTS cmsg over buffers that
    // outlive the call; CMSG_* macros compute the layout.
    unsafe {
        let mut cmsgbuf = [0u8; 32];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsgbuf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = libc::CMSG_SPACE(4) as _;
        let c = libc::CMSG_FIRSTHDR(&msg);
        (*c).cmsg_level = libc::SOL_SOCKET;
        (*c).cmsg_type = libc::SCM_RIGHTS;
        (*c).cmsg_len = libc::CMSG_LEN(4) as _;
        std::ptr::copy_nonoverlapping(&fd as *const i32 as *const u8, libc::CMSG_DATA(c), 4);
        if libc::sendmsg(chan, &msg, 0) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Blocking receive of one SCM_RIGHTS fd; `Err` on close/garbage ends the
/// worker's attach listener.
#[cfg(unix)]
fn recv_fd(chan: std::os::unix::io::RawFd) -> io::Result<std::os::unix::io::RawFd> {
    let mut data = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr() as *mut libc::c_void,
        iov_len: 1,
    };
    // SAFETY: standard recvmsg with room for one SCM_RIGHTS cmsg; buffers
    // outlive the call.
    unsafe {
        let mut cmsgbuf = [0u8; 32];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsgbuf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = libc::CMSG_SPACE(4) as _;
        let n = libc::recvmsg(chan, &mut msg, 0);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "control channel closed",
            ));
        }
        let c = libc::CMSG_FIRSTHDR(&msg);
        if c.is_null() || (*c).cmsg_type != libc::SCM_RIGHTS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "control message without an fd",
            ));
        }
        let mut fd: i32 = -1;
        std::ptr::copy_nonoverlapping(libc::CMSG_DATA(c), &mut fd as *mut i32 as *mut u8, 4);
        Ok(fd)
    }
}

/// Path 3 (M1): peek a just-accepted connection's first message; true iff it's an
/// isolating fork-clone Init (`op == Init`, `resume_token != 0`) that should be
/// served in a dedicated worker process. `MSG_PEEK` leaves the bytes on the
/// socket so the worker reads them fresh. Gated behind `SMOLVM_CUDA_FORK_WORKERS` (unset
/// = legacy shared-context path) so partial Path-3 wiring can't disturb serving.
#[cfg(unix)]
fn peek_clone_token(fd: std::os::unix::io::RawFd) -> Option<u64> {
    if std::env::var_os("SMOLVM_CUDA_FORK_WORKERS").is_none()
        || std::env::var_os("SMOLVM_CUDA_FORK_ISOLATE").is_none()
    {
        return None;
    }
    // framing: [u32 le len][op][proto_hash u64][resume_token u64]
    let mut buf = [0u8; 21];
    // The connection is often proxied (guest vsock → per-VM cuda_host proxy →
    // daemon unix socket), so the 21-byte Init can arrive in pieces AFTER accept.
    // A one-shot peek that saw a short read here would MISROUTE the isolating
    // clone to the legacy shared-context path (which fails for expandable_segments
    // → CUDA_ERROR_UNKNOWN, esp. at larger models). Retry the non-consuming peek
    // until the full header is buffered (or the peer closes / we time out ~1s).
    let mut n: isize = 0;
    for _ in 0..200 {
        n = unsafe {
            libc::recv(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                libc::MSG_PEEK,
            )
        };
        if n >= 21 || n == 0 {
            break; // full header buffered, or peer closed
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    if n < 21 || buf[4] != 0x01 {
        tracing::warn!(
            n,
            op = buf[4],
            "peek_clone_token: not routed (short read / non-Init)"
        );
        return None;
    }
    let token = u64::from_le_bytes(buf[13..21].try_into().unwrap());
    (token != 0).then_some(token)
}

/// Fork-time share-safety check: D2H the chunk and confirm every recorded
/// upload segment still hashes to its H2D-time CRC. Any mismatch (or D2H
/// failure) → not shareable.
#[cfg(unix)]
fn verify_chunk_content(b: &mut dyn Backend, ch: &smolvm_cuda::host::HandoffChunk) -> bool {
    match b.memcpy_dtoh(ch.va, ch.size, 0) {
        Ok(bytes) => ch.segs.iter().all(|&(s, e, crc)| {
            crc != 0
                && e as usize <= bytes.len()
                && smolvm_cuda::host::fnv64(&bytes[s as usize..e as usize]) == crc
        }),
        Err(e) => {
            tracing::warn!(e, va = ch.va, "M2-share: verify D2H failed → private");
            false
        }
    }
}

/// Stage private copies of the golden's non-VMM (`cudaMalloc`) allocations into
/// one exportable physical the worker can import. Regions are
/// granularity-aligned merged spans of the allocations' VAs; each allocation's
/// bytes are copied at `region_off + (dptr - region_base)` so the worker can
/// blit whole regions back to the golden's exact VAs. Returns the export fd.
#[cfg(unix)]
fn stage_alloc_copies(
    b: &mut dyn smolvm_cuda::host::Backend,
    device: i32,
    allocs: &[(u64, u64, bool)],
    regions: &[(u64, u64)], // (base, end)
    total: u64,
) -> Result<i32, String> {
    let h = b
        .mem_create_exportable(total, device)
        .map_err(|e| format!("stage create: {e}"))?;
    let tmp = match b.mem_address_reserve(total, 0) {
        Ok(t) => t,
        Err(e) => {
            let _ = b.mem_release(h);
            return Err(format!("stage reserve: {e}"));
        }
    };
    let mut copy = || -> Result<(), String> {
        b.mem_map(tmp, total, 0, h)
            .map_err(|e| format!("stage map: {e}"))?;
        b.mem_set_access(tmp, total, device)
            .map_err(|e| format!("stage access: {e}"))?;
        for &(d, sz, _) in allocs {
            // Locate the containing region and its offset into the staging chunk.
            let mut off = 0u64;
            for &(base, end) in regions {
                if d >= base && d < end {
                    b.memcpy_dtod(tmp + off + (d - base), d, sz)
                        .map_err(|e| format!("stage dtod {d:#x}: {e}"))?;
                    break;
                }
                off += end - base;
            }
        }
        let _ = b.ctx_synchronize();
        Ok(())
    };
    let res = copy();
    let _ = b.mem_unmap(tmp, total);
    let _ = b.mem_address_free(tmp, total);
    match res.and_then(|()| {
        b.mem_export_handle(h)
            .map_err(|e| format!("stage export: {e}"))
    }) {
        Ok(fd) => {
            // The fd holds its own driver reference; drop ours.
            let _ = b.mem_release(h);
            Ok(fd)
        }
        Err(e) => {
            let _ = b.mem_release(h);
            Err(e)
        }
    }
}

/// Path 3 (M1): hand the accepted connection to a fresh worker PROCESS (its own
/// CUDA context, hence its own UVA — so it can place memory at the golden's exact
/// VAs). `dup2` the socket fd onto fd 3 in the child (clears CLOEXEC) and exec
/// `smolvm _cuda-clone-worker 3`; the daemon then drops its own copy.
#[cfg(unix)]
fn spawn_clone_worker(
    conn_fd: std::os::unix::io::RawFd,
    token: u64,
    share_weights: bool,
    ring_dir: Option<&str>,
    procmem: Option<ProcMemAdvert>,
) -> io::Result<(u32, std::os::unix::io::RawFd)> {
    use std::os::unix::process::CommandExt;
    // Gather the golden's VMM layout (reservations + maps→physical handle).
    let (resvs, maps, golden_dev) = smolvm_cuda::host::layout_handoff_snapshot(token)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no golden layout for token"))?;
    // Export each map's physical to a POSIX fd (in the golden's shared context) and
    // build the layout string the worker parses
    // ("resv=va:size,…|maps=va:size:fdidx:loaded:ghandle,…"; loaded=1 → shareable
    // weight; ghandle = the golden's
    // handle value, so the worker can translate the clone's inherited
    // MemRelease/MemMap handles to its own).
    let mut backend = make_backend();
    backend
        .init()
        .map_err(|e| io::Error::other(format!("worker-export init: {e}")))?;
    backend
        .primary_ctx_retain(golden_dev)
        .map_err(|e| io::Error::other(format!("ctx retain: {e}")))?;
    // Commit the golden's pending device work so its writes are visible in the
    // physical the clone will IPC-import (the golden runs on another thread of the
    // shared primary context).
    let _ = backend.ctx_synchronize();
    let mut layout = String::from("resv=");
    for (va, size) in &resvs {
        layout.push_str(&format!("{va:x}:{size:x},"));
    }
    layout.push_str("|maps=");
    let mut export_fds: Vec<i32> = Vec::new();
    for ch in &maps {
        if let Ok(efd) = backend.mem_export_handle(ch.handle) {
            let idx = export_fds.len();
            export_fds.push(efd);
            // Share-safety: a candidate chunk is shared only if its device
            // content still equals what the H2Ds uploaded (any kernel write —
            // e.g. LoRA adapters placed in freed weight space — must keep the
            // chunk private or clone writes leak through the shared physical).
            // Verified once per frozen golden; verdict cached.
            let safe = match (ch.candidate, ch.verified) {
                (false, _) => false,
                (true, Some(v)) => v,
                (true, None) => {
                    let v = verify_chunk_content(backend.as_mut(), ch);
                    smolvm_cuda::host::layout_set_share_verdict(token, ch.va, v);
                    v
                }
            };
            let ld = u8::from(safe);
            layout.push_str(&format!(
                "{:x}:{:x}:{}:{}:{:x},",
                ch.va, ch.size, idx, ld, ch.ghandle
            ));
        }
    }
    // Non-VMM golden memory: a plain-torch golden (no expandable_segments) keeps
    // every tensor in cudaMalloc'd blocks that never enter the VMM layout, so a
    // worker-mode clone would lose them all (illegal address on first touch —
    // the maps above only cover VMM). Stage private copies for the worker.
    if let Some(allocs) = smolvm_cuda::host::alloc_handoff_snapshot(token) {
        if !allocs.is_empty() {
            let gran = backend
                .mem_get_allocation_granularity(golden_dev, 0)
                .unwrap_or(1 << 21)
                .max(1 << 16);
            let mut spans: Vec<(u64, u64)> = allocs
                .iter()
                .map(|&(d, sz, _)| (d & !(gran - 1), (d + sz + gran - 1) & !(gran - 1)))
                .collect();
            spans.sort_unstable();
            let mut regions: Vec<(u64, u64)> = Vec::new();
            for (b0, e0) in spans {
                match regions.last_mut() {
                    Some((_, e)) if b0 <= *e => *e = (*e).max(e0),
                    _ => regions.push((b0, e0)),
                }
            }
            let total: u64 = regions.iter().map(|&(b0, e0)| e0 - b0).sum();
            match stage_alloc_copies(backend.as_mut(), golden_dev, &allocs, &regions, total) {
                Ok(efd) => {
                    let idx = export_fds.len();
                    export_fds.push(efd);
                    layout.push_str(&format!("|astage={idx}|aregions="));
                    let mut off = 0u64;
                    for &(b0, e0) in &regions {
                        layout.push_str(&format!("{:x}:{:x}:{:x},", b0, e0 - b0, off));
                        off += e0 - b0;
                    }
                    layout.push_str("|allocs=");
                    for &(d, sz, _) in &allocs {
                        layout.push_str(&format!("{d:x}:{sz:x},"));
                    }
                    tracing::info!(
                        allocs = allocs.len(),
                        regions = regions.len(),
                        bytes = total,
                        "staged the golden's non-VMM allocations for the worker"
                    );
                }
                Err(e) => tracing::warn!(
                    e,
                    "failed to stage non-VMM golden allocations; the clone will fault on pre-fork tensors"
                ),
            }
        }
    }
    // M3a: serialize the golden's modules (images) + functions to a temp file for
    // the worker to reload + remap. Images are MB-scale, so a file, not env.
    let mut modpath: Option<String> = None;
    if let Some((modules, funcs, streams, events, graphs, lib_handles)) =
        smolvm_cuda::host::module_handoff_snapshot(token)
    {
        tracing::info!(
            modules = modules.len(),
            funcs = funcs.len(),
            streams = streams.len(),
            events = events.len(),
            graphs = graphs.len(),
            lib_handles = lib_handles.len(),
            "M3a: gathered golden modules/functions/streams/events"
        );
        let mut blob = Vec::new();
        blob.extend_from_slice(&(modules.len() as u32).to_le_bytes());
        for (h, img) in &modules {
            blob.extend_from_slice(&h.to_le_bytes());
            blob.extend_from_slice(&(img.len() as u32).to_le_bytes());
            blob.extend_from_slice(img);
        }
        blob.extend_from_slice(&(funcs.len() as u32).to_le_bytes());
        for (h, m, n, attrs) in &funcs {
            blob.extend_from_slice(&h.to_le_bytes());
            blob.extend_from_slice(&m.to_le_bytes());
            blob.extend_from_slice(&(n.len() as u32).to_le_bytes());
            blob.extend_from_slice(n.as_bytes());
            // Per-function attribute replays ([i32 attr][i32 value] each) —
            // e.g. FlashAttention's MaxDynamicSharedMemorySize opt-in.
            blob.extend_from_slice(&(attrs.len() as u32).to_le_bytes());
            for &(a, v) in attrs {
                blob.extend_from_slice(&a.to_le_bytes());
                blob.extend_from_slice(&v.to_le_bytes());
            }
        }
        // Streams + events: [u64 golden handle][u32 create flags] each.
        blob.extend_from_slice(&(streams.len() as u32).to_le_bytes());
        for (h, flags) in &streams {
            blob.extend_from_slice(&h.to_le_bytes());
            blob.extend_from_slice(&flags.to_le_bytes());
        }
        blob.extend_from_slice(&(events.len() as u32).to_le_bytes());
        for (h, flags) in &events {
            blob.extend_from_slice(&h.to_le_bytes());
            blob.extend_from_slice(&flags.to_le_bytes());
        }
        // M3b: captured graphs. Per graph: [u64 graph_vh][u64 exec_vh]
        //   [u32 nnodes]([u64 func][u32*3 grid][u32*3 block][u32 shmem]
        //                [u32 nparams]([u32 len][bytes])* )*
        //   [u32 nedges]([u32 from][u32 to])*
        blob.extend_from_slice(&(graphs.len() as u32).to_le_bytes());
        for (graph_vh, exec_vh, g) in &graphs {
            blob.extend_from_slice(&graph_vh.to_le_bytes());
            blob.extend_from_slice(&exec_vh.to_le_bytes());
            blob.extend_from_slice(&(g.nodes.len() as u32).to_le_bytes());
            for nd in &g.nodes {
                blob.extend_from_slice(&nd.func.to_le_bytes());
                for x in nd.grid.iter().chain(nd.block.iter()) {
                    blob.extend_from_slice(&x.to_le_bytes());
                }
                blob.extend_from_slice(&nd.shared_mem.to_le_bytes());
                blob.extend_from_slice(&(nd.params.len() as u32).to_le_bytes());
                for p in &nd.params {
                    blob.extend_from_slice(&(p.len() as u32).to_le_bytes());
                    blob.extend_from_slice(p);
                }
            }
            blob.extend_from_slice(&(g.edges.len() as u32).to_le_bytes());
            for &(f, t) in &g.edges {
                blob.extend_from_slice(&f.to_le_bytes());
                blob.extend_from_slice(&t.to_le_bytes());
            }
        }
        // Library-handle creates for the worker to replay:
        //   [u32 n]([u8 lib][u16 func][u64 handle][u32 len][args])*
        blob.extend_from_slice(&(lib_handles.len() as u32).to_le_bytes());
        for (lib, func, h, args) in &lib_handles {
            blob.push(*lib);
            blob.extend_from_slice(&func.to_le_bytes());
            blob.extend_from_slice(&h.to_le_bytes());
            blob.extend_from_slice(&(args.len() as u32).to_le_bytes());
            blob.extend_from_slice(args);
        }
        // P3b: capture-replay op-logs. Per graph:
        //   [u64 graph_vh][u64 exec_vh][u32 nops]([u32 len][op bytes])*
        let oplogs = smolvm_cuda::host::graph_oplogs_snapshot(token);
        blob.extend_from_slice(&(oplogs.len() as u32).to_le_bytes());
        for (graph_vh, exec_vh, ops) in &oplogs {
            blob.extend_from_slice(&graph_vh.to_le_bytes());
            blob.extend_from_slice(&exec_vh.to_le_bytes());
            blob.extend_from_slice(&(ops.len() as u32).to_le_bytes());
            for op in ops {
                blob.extend_from_slice(&(op.len() as u32).to_le_bytes());
                blob.extend_from_slice(op);
            }
        }
        let _ = std::fs::create_dir_all("/tmp/smolvm");
        // Unique per SPAWN, not per (token, conn_fd): fd numbers are reused as
        // soon as the daemon closes a spawned worker's copy, so two clones forked
        // near-simultaneously collide on the same path — and each worker deletes
        // its blob after staging, leaving the second worker 0 modules (its kernel
        // launches then use raw golden handles → SIGSEGV in cuLaunchKernel).
        static SPAWN_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = SPAWN_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mp = format!("/tmp/smolvm/clone-mods-{token}-{seq}.bin");
        if std::fs::write(&mp, &blob).is_ok() {
            modpath = Some(mp);
        }
    }
    // Control channel for late-attached guest channels: the daemon keeps sp[0]
    // and SCM_RIGHTS-sends each additional connection fd from the same clone;
    // the worker inherits sp[1] and serves every received fd in-process.
    let mut sp = [0i32; 2];
    // SAFETY: plain socketpair; fds checked below.
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sp.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // Lift the child end above the dup2 target range (3..4+nexports) so the
    // fd shuffle in pre_exec can't clobber it before it's dup2'd into place.
    // SAFETY: F_DUPFD to >=64 on an fd we own; original closed right after.
    let ctrl_child = unsafe { libc::fcntl(sp[1], libc::F_DUPFD, 64) };
    // SAFETY: closing our original child-end copy.
    unsafe { libc::close(sp[1]) };
    if ctrl_child < 0 {
        // SAFETY: closing the parent end we created above.
        unsafe { libc::close(sp[0]) };
        return Err(io::Error::last_os_error());
    }
    let ctrl_slot = 4 + export_fds.len() as i32;
    let exe = std::env::current_exe()?;
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("_cuda-clone-worker").arg("3");
    cmd.env("SMOLVM_CUDA_CLONE_LAYOUT", layout);
    cmd.env("SMOLVM_CUDA_CLONE_DEVICE", golden_dev.to_string());
    cmd.env("SMOLVM_CUDA_CLONE_CTRL", ctrl_slot.to_string());
    // Clone live-RAM transport: hand the worker our (pid, gpa, host_va, len) so
    // it can pread/pwrite /proc/<pid>/mem for D2H/H2D instead of ring-copying.
    if let Some((pid, regions)) = &procmem {
        cmd.env("SMOLVM_CUDA_CLONE_PROCMEM", procmem_to_env(*pid, regions));
    }
    if let Some(rd) = ring_dir {
        // File-ring transport: the worker resolves RingSetupFile names
        // against the clone VM's advertised host ring dir.
        cmd.env("SMOLVM_CUDA_CLONE_RING_DIR", rd);
    }
    // Per-fork density: this fork asked for --share-weights (preamble flag), so
    // the worker's reconstruction shares the golden's loaded weight physicals
    // instead of copying them. The daemon-wide env remains the global default;
    // the worker inherits it, so the flag only ever ADDS sharing.
    if share_weights {
        cmd.env("SMOLVM_CUDA_FORK_SHARE_WEIGHTS", "1");
    }
    if let Some(mp) = &modpath {
        cmd.env("SMOLVM_CUDA_CLONE_MODULES", mp);
    }
    // Parent copies of the exported-physical fds, to close once the child has
    // forked (it inherits its own set). Every open export fd holds a DRIVER
    // REFERENCE on the golden's physical allocation — leaking them in the
    // daemon pins the golden's VRAM long after the golden is torn down and its
    // session reclaimed (found: two dead goldens left ~3.2 GB resident).
    let parent_fds = export_fds.clone();
    // SAFETY: dup2 in the forked child (async-signal-safe); fds were inherited at
    // fork. Connection → fd 3; each exported physical → fd 4+idx.
    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(conn_fd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            for (i, efd) in export_fds.iter().enumerate() {
                if libc::dup2(*efd, 4 + i as i32) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            // The export fds from cuMemExportToShareableHandle are O_CLOEXEC. dup2 to
            // a DIFFERENT fd clears CLOEXEC, but dup2(fd, fd) — when an export fd
            // already sits at its destination (commonly the first, fd 4) — is a
            // no-op that does NOT clear it, so that fd would be closed on exec and
            // the worker's import fails e=999 (a region left uninitialized → a later
            // read of a weight there faults). Clear CLOEXEC on every handed-off fd.
            if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            for i in 0..export_fds.len() as i32 {
                if libc::fcntl(4 + i, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if libc::dup2(ctrl_child, ctrl_slot) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(ctrl_slot, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let spawned = cmd.spawn().map(|child| child.id());
    // The child (if any) forked with its own copies; drop ours either way so
    // the golden's physicals can actually be released at teardown.
    for efd in parent_fds {
        // SAFETY: fds we created via mem_export_handle and no longer use.
        unsafe { libc::close(efd) };
    }
    // SAFETY: the child inherited its own copy of the control child-end.
    unsafe { libc::close(ctrl_child) };
    match spawned {
        Ok(pid) => Ok((pid, sp[0])),
        Err(e) => {
            // SAFETY: no worker took ownership; close the parent control end.
            unsafe { libc::close(sp[0]) };
            Err(e)
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
