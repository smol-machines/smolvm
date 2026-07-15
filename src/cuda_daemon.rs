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
            Ok(stream) => {
                // Path 3 (M1): an isolating fork clone is served in its own worker
                // PROCESS (own context/UVA) so it can hold memory at the golden's
                // exact VAs. Only fires under SMOLVM_CUDA_PATH3; otherwise legacy.
                #[cfg(unix)]
                {
                    use std::os::unix::io::AsRawFd;
                    let fd = stream.as_raw_fd();
                    if let Some(token) = peek_clone_token(fd) {
                        match spawn_clone_worker(fd, token) {
                            Ok(()) => {
                                tracing::info!(token, "routed isolating clone to a worker process");
                                drop(stream); // the worker owns the connection now
                                continue;
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "clone-worker spawn failed; serving in-process");
                            }
                        }
                    }
                }
                spawn_serve(stream, &active);
            }
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

/// Path 3 (M1): serve one isolating fork-clone connection in THIS separate worker
/// process. A per-clone process has its own CUDA primary context and thus its own
/// UVA space, so it can place memory at the golden's exact virtual addresses
/// (address-preserving isolation — no per-op pointer translation). The daemon
/// spawns us with the accepted connection's fd (see the clone routing in
/// `spawn_serve`). M2 (golden-state reconstruction) and M3 (module/graph rebuild)
/// hook in before the serve loop; establishing the process boundary comes first.
pub fn run_clone_worker(fd: std::os::unix::io::RawFd) -> io::Result<()> {
    use std::os::unix::io::FromRawFd;
    let mut backend = make_backend();
    // Our own primary context (separate process ⇒ own UVA), so we can place memory
    // at the golden's exact VAs.
    let _ = backend.init();
    let _ = backend.primary_ctx_retain(0);
    // M2: reconstruct the golden's memory at its exact VAs from the layout the
    // daemon passed (SMOLVM_CUDA_CLONE_LAYOUT) + the golden's physical exported to
    // fds 4.. — BEFORE serving, so the clone's inherited pointers are valid verbatim.
    if let Ok(layout) = std::env::var("SMOLVM_CUDA_CLONE_LAYOUT") {
        let n = reconstruct_golden_memory(backend.as_mut(), &layout);
        tracing::info!(
            maps = n,
            "cuda clone-worker: reconstructed golden memory at its VAs"
        );
        // Barrier: VMM reconstruction must fully settle before the clone runs, or a
        // later cuModuleLoadData surfaces a sticky async fault from the copies.
        if let Err(e) = backend.ctx_synchronize() {
            tracing::warn!(e, "clone-worker: sync after memory reconstruction failed");
        }
    }
    // M3a: reload the golden's modules + re-resolve its functions in OUR context,
    // and install the golden→worker handle translation so the clone's inherited
    // kernel launches (raw CUfunction from the golden's context) resolve correctly.
    if let Ok(modpath) = std::env::var("SMOLVM_CUDA_CLONE_MODULES") {
        let (funcs, mods, streams, events) = reconstruct_golden_modules(backend.as_mut(), &modpath);
        let (nf, ns, ne) = (funcs.len(), streams.len(), events.len());
        smolvm_cuda::host::set_handle_trans(funcs, mods, streams, events);
        let _ = std::fs::remove_file(&modpath);
        tracing::info!(
            functions = nf,
            streams = ns,
            events = ne,
            "cuda clone-worker: reloaded golden modules + remapped handles"
        );
    }
    // SAFETY: the daemon handed us sole ownership of the accepted connection fd.
    let stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
    tracing::info!(
        fd,
        "cuda clone-worker: serving in its own context / UVA space"
    );
    serve(stream, backend.as_mut())
}

/// M2: rebuild the golden's VMM layout in THIS worker's context at the golden's
/// EXACT VAs. `layout` = `"resv=va:size,…|maps=va:size:fdidx,…"` (hex); each map's
/// physical was exported by the daemon to fd `4 + fdidx`. We import + map at the
/// same VA — address-preserving, so inherited pointers and rebuilt graphs are
/// valid verbatim. (Weights are shared here; private-mutable copy for full
/// isolation is the next refinement.)
#[cfg(unix)]
fn reconstruct_golden_memory(b: &mut dyn Backend, layout: &str) -> usize {
    let (mut resv_s, mut maps_s) = ("", "");
    for part in layout.split('|') {
        if let Some(r) = part.strip_prefix("resv=") {
            resv_s = r;
        }
        if let Some(m) = part.strip_prefix("maps=") {
            maps_s = m;
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
    let mut count = 0;
    for e in maps_s.split(',').filter(|s| !s.is_empty()) {
        let f: Vec<&str> = e.split(':').collect();
        if f.len() != 3 {
            continue;
        }
        let (Some(va), Some(size), Ok(idx)) = (hx(f[0]), hx(f[1]), f[2].parse::<i32>()) else {
            continue;
        };
        // Private-mutable, address-preserving: map a PRIVATE physical at the golden
        // VA, then copy the golden's bytes in via a temp mapping of the imported
        // physical. Reads see the golden's data; writes hit the clone's own copy,
        // so a clone can't corrupt the frozen golden.
        let priv_h = match b.mem_create(size, 0) {
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
        if let Err(e) = b.mem_set_access(va, size, 0) {
            tracing::warn!(e, va, "M2: private set_access failed");
        }
        match b.mem_import_handle(4 + idx) {
            Ok(gh) => {
                if let Ok(tmp) = b.mem_address_reserve(size, 0) {
                    match b.mem_map(tmp, size, 0, gh) {
                        Ok(()) => {
                            if let Err(e) = b.mem_set_access(tmp, size, 0) {
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
    count
}

/// M3a: reload the golden's modules + re-resolve its functions in THIS worker's
/// context, returning golden→worker handle maps `(functions, modules)`. Reads the
/// binary blob the daemon wrote (path in `SMOLVM_CUDA_CLONE_MODULES`):
/// `[u32 nmods]( [u64 handle][u32 len][image] )* [u32 nfuncs]( [u64 fn][u64 mod][u32 len][name] )*`.
#[cfg(unix)]
#[allow(clippy::type_complexity)]
fn reconstruct_golden_modules(
    b: &mut dyn Backend,
    path: &str,
) -> (
    Vec<(u64, u64)>,
    Vec<(u64, u64)>,
    Vec<(u64, u64)>,
    Vec<(u64, u64)>,
) {
    let mut func_trans = Vec::new();
    let mut mod_trans = Vec::new();
    let mut stream_trans = Vec::new();
    let mut event_trans = Vec::new();
    let Ok(buf) = std::fs::read(path) else {
        return (func_trans, mod_trans, stream_trans, event_trans);
    };
    let mut p = 0usize;
    macro_rules! need {
        ($n:expr) => {
            if p + $n > buf.len() {
                return (func_trans, mod_trans, stream_trans, event_trans);
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
    let mut g2w: std::collections::HashMap<u64, u64> = std::collections::HashMap::new();
    let nmods = ru32!();
    for _ in 0..nmods {
        let gh = ru64!();
        let ilen = ru32!() as usize;
        need!(ilen);
        let img = buf[p..p + ilen].to_vec();
        p += ilen;
        // Null-terminate: cuModuleLoadData treats a PTX image as a C string, so the
        // stored bytes need a trailing NUL the raw blob may lack.
        let mut img = img;
        if img.last() != Some(&0) {
            img.push(0);
        }
        match b.module_load_data(&img) {
            Ok(wh) => {
                g2w.insert(gh, wh);
                mod_trans.push((gh, wh));
            }
            Err(e) => tracing::warn!(e, ilen, "M3a: module reload failed"),
        }
    }
    let nfuncs = ru32!();
    for _ in 0..nfuncs {
        let gf = ru64!();
        let gm = ru64!();
        let nlen = ru32!() as usize;
        need!(nlen);
        let name = String::from_utf8_lossy(&buf[p..p + nlen]).into_owned();
        p += nlen;
        match g2w.get(&gm) {
            Some(&wm) => match b.module_get_function(wm, &name) {
                Ok(wf) => func_trans.push((gf, wf)),
                Err(e) => tracing::warn!(name, e, "M3a: re-resolve function failed"),
            },
            None => tracing::warn!(gm, "M3a: function's module not reloaded"),
        }
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
    tracing::info!(
        nmods,
        nfuncs,
        nstreams,
        nevents,
        mods = mod_trans.len(),
        funcs = func_trans.len(),
        streams = stream_trans.len(),
        events = event_trans.len(),
        "M3a: reconstruct_golden_modules"
    );
    (func_trans, mod_trans, stream_trans, event_trans)
}

/// Path 3 (M1): peek a just-accepted connection's first message; true iff it's an
/// isolating fork-clone Init (`op == Init`, `resume_token != 0`) that should be
/// served in a dedicated worker process. `MSG_PEEK` leaves the bytes on the
/// socket so the worker reads them fresh. Gated behind `SMOLVM_CUDA_PATH3` (unset
/// = legacy shared-context path) so partial Path-3 wiring can't disturb serving.
#[cfg(unix)]
fn peek_clone_token(fd: std::os::unix::io::RawFd) -> Option<u64> {
    if std::env::var_os("SMOLVM_CUDA_PATH3").is_none()
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

/// Path 3 (M1): hand the accepted connection to a fresh worker PROCESS (its own
/// CUDA context, hence its own UVA — so it can place memory at the golden's exact
/// VAs). `dup2` the socket fd onto fd 3 in the child (clears CLOEXEC) and exec
/// `smolvm _cuda-clone-worker 3`; the daemon then drops its own copy.
#[cfg(unix)]
fn spawn_clone_worker(conn_fd: std::os::unix::io::RawFd, token: u64) -> io::Result<()> {
    use std::os::unix::process::CommandExt;
    // Gather the golden's VMM layout (reservations + maps→physical handle).
    let (resvs, maps) = smolvm_cuda::host::layout_handoff_snapshot(token)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no golden layout for token"))?;
    // Export each map's physical to a POSIX fd (in the golden's shared context) and
    // build the layout string the worker parses ("resv=va:size,…|maps=va:size:fdidx,…").
    let mut backend = make_backend();
    backend
        .init()
        .map_err(|e| io::Error::other(format!("worker-export init: {e}")))?;
    backend
        .primary_ctx_retain(0)
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
    for (va, size, handle) in &maps {
        if let Ok(efd) = backend.mem_export_handle(*handle) {
            let idx = export_fds.len();
            export_fds.push(efd);
            layout.push_str(&format!("{va:x}:{size:x}:{idx},"));
        }
    }
    // M3a: serialize the golden's modules (images) + functions to a temp file for
    // the worker to reload + remap. Images are MB-scale, so a file, not env.
    let mut modpath: Option<String> = None;
    if let Some((modules, funcs, streams, events)) =
        smolvm_cuda::host::module_handoff_snapshot(token)
    {
        tracing::info!(
            modules = modules.len(),
            funcs = funcs.len(),
            streams = streams.len(),
            events = events.len(),
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
        for (h, m, n) in &funcs {
            blob.extend_from_slice(&h.to_le_bytes());
            blob.extend_from_slice(&m.to_le_bytes());
            blob.extend_from_slice(&(n.len() as u32).to_le_bytes());
            blob.extend_from_slice(n.as_bytes());
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
        let _ = std::fs::create_dir_all("/tmp/smolvm");
        let mp = format!("/tmp/smolvm/clone-mods-{token}-{conn_fd}.bin");
        if std::fs::write(&mp, &blob).is_ok() {
            modpath = Some(mp);
        }
    }
    let exe = std::env::current_exe()?;
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("_cuda-clone-worker").arg("3");
    cmd.env("SMOLVM_CUDA_CLONE_LAYOUT", layout);
    if let Some(mp) = &modpath {
        cmd.env("SMOLVM_CUDA_CLONE_MODULES", mp);
    }
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
            Ok(())
        });
    }
    cmd.spawn().map(|_| ())
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
