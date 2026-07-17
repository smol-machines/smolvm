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
                                        if route_clone_connection(s.as_raw_fd()) {
                                            drop(s); // worker owns it / rejected
                                            continue;
                                        }
                                    }
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
                // Path 3 (M1): an isolating fork clone (its VM's proxy sends a
                // clone preamble) is served in its own worker PROCESS (own
                // context/UVA) so it can hold memory at the golden's exact VAs.
                // A GOLDEN's reconnect — same lineage token, NO preamble —
                // falls through and resumes in-daemon: routing it to a worker
                // would silently serve it a reconstructed COPY of its memory.
                // Only fires under SMOLVM_CUDA_FORK_WORKERS; otherwise legacy.
                #[cfg(unix)]
                {
                    use std::os::unix::io::AsRawFd;
                    if route_clone_connection(stream.as_raw_fd()) {
                        drop(stream); // worker owns it / rejected
                        continue;
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
        let (n, vmm_trans) = reconstruct_golden_memory(backend.as_mut(), &layout);
        tracing::info!(
            maps = n,
            vmm_handles = vmm_trans.len(),
            "cuda clone-worker: reconstructed golden memory at its VAs"
        );
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
        let (mod_images, func_meta, streams, events, graphs) =
            reconstruct_golden_modules(backend.as_mut(), &modpath);
        let (nm, nf, ns, ne, ng) = (
            mod_images.len(),
            func_meta.len(),
            streams.len(),
            events.len(),
            graphs.len(),
        );
        smolvm_cuda::host::set_handle_trans(mod_images, func_meta, streams, events);
        // M3b: rebuild the golden's captured CUDA graphs in THIS context, now
        // that modules can lazily reload and memory is reconstructed (kernel-arg
        // pointers reference the golden VAs, valid here). Maps the clone's
        // inherited graph/exec handles to the worker's rebuilt reals.
        let nrebuilt = smolvm_cuda::host::rebuild_clone_graphs(backend.as_mut(), graphs);
        let _ = std::fs::remove_file(&modpath);
        tracing::info!(
            modules = nm,
            functions = nf,
            streams = ns,
            events = ne,
            graphs = ng,
            graphs_rebuilt = nrebuilt,
            "cuda clone-worker: staged modules for lazy reload + remapped handles"
        );
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
) -> (usize, std::collections::HashMap<u64, u64>) {
    let mut vmm_trans = std::collections::HashMap::new();
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
                    if b.mem_set_access(va, size, 0).is_ok() {
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
        // priv_h stays held (never released here): the clone releases this chunk
        // post-fork by the GOLDEN's handle value, translated to priv_h.
        if let Some(g) = golden_h {
            vmm_trans.insert(g, priv_h);
        }
        if let Err(e) = b.mem_set_access(va, size, 0) {
            tracing::warn!(e, va, "M2: private set_access failed");
        }
        match import_with_retry(b, 4 + idx) {
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
    if share_weights {
        tracing::info!(shared, private = count - shared, "M2: shared weight ranges");
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
    Vec<(u64, u64, String)>,
    Vec<(u64, u64)>,
    Vec<(u64, u64)>,
    Vec<(u64, u64, smolvm_cuda::host::GraphSer)>,
) {
    let mut mod_images = Vec::new();
    let mut func_meta = Vec::new();
    let mut stream_trans = Vec::new();
    let mut event_trans = Vec::new();
    let mut graphs: Vec<(u64, u64, smolvm_cuda::host::GraphSer)> = Vec::new();
    let Ok(buf) = std::fs::read(path) else {
        return (mod_images, func_meta, stream_trans, event_trans, graphs);
    };
    let mut p = 0usize;
    macro_rules! need {
        ($n:expr) => {
            if p + $n > buf.len() {
                return (mod_images, func_meta, stream_trans, event_trans, graphs);
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
        func_meta.push((gf, gm, name));
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
    tracing::info!(
        nmods,
        nfuncs,
        nstreams,
        nevents,
        ngraphs = graphs.len(),
        streams = stream_trans.len(),
        events = event_trans.len(),
        "M3a: staged golden modules/functions for lazy reload + recreated streams/events"
    );
    (mod_images, func_meta, stream_trans, event_trans, graphs)
}

/// Strip a fork-clone connection preamble (magic + clone id) if present,
/// returning the clone id. The preamble is sent by a CLONE VM's proxy before
/// any RPC frames (see `cuda_host::proxy_to_daemon`); the GOLDEN's connections
/// never carry it. Must run on every accepted connection REGARDLESS of routing
/// mode — an unconsumed preamble would corrupt the frame stream. Non-preamble
/// connections are left untouched (peek only).
#[cfg(unix)]
fn consume_clone_preamble(fd: std::os::unix::io::RawFd) -> Option<u64> {
    let mut buf = [0u8; 16];
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
        if n >= 16 || n == 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    if n < 16 || buf[..8] != smolvm_cuda::proto::CLONE_PREAMBLE_MAGIC {
        return None;
    }
    // Consume exactly the 16 preamble bytes, leaving the RPC stream intact.
    // SAFETY: plain recv on a valid fd; MSG_WAITALL for the already-peeked bytes.
    let c = unsafe {
        libc::recv(
            fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            16,
            libc::MSG_WAITALL,
        )
    };
    if c != 16 {
        return None;
    }
    Some(u64::from_le_bytes(buf[8..16].try_into().unwrap()))
}

/// Live clone workers keyed by (lineage token, clone id) → worker pid. A
/// reconnect from a clone whose worker is STILL ALIVE is rejected loudly: a
/// fresh worker would re-reconstruct from the golden and silently DISCARD the
/// clone's accumulated GPU state (its training progress). Dead entries are
/// replaced (worker crash → a fresh worker is the best recovery available).
#[cfg(unix)]
fn clone_worker_registry() -> &'static Mutex<std::collections::HashMap<(u64, u64), u32>> {
    static REG: OnceLock<Mutex<std::collections::HashMap<(u64, u64), u32>>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

/// Route one just-accepted connection: strip the clone preamble (always), and
/// when it marks an isolating fork clone, spawn/refuse its worker. Returns
/// `true` when the connection was consumed (routed or rejected); `false` means
/// the caller serves it normally — including a GOLDEN's own reconnect, whose
/// token-bearing Init WITHOUT the preamble must resume in-daemon (a worker
/// would silently serve it a reconstructed COPY of its memory).
#[cfg(unix)]
fn route_clone_connection(fd: std::os::unix::io::RawFd) -> bool {
    let Some(clone_id) = consume_clone_preamble(fd) else {
        return false;
    };
    let Some(token) = peek_clone_token(fd) else {
        // A clone VM's connection whose Init carries no lineage token: fresh
        // post-fork work (new guest process), served in-daemon like any new
        // session.
        return false;
    };
    let mut reg = clone_worker_registry().lock().unwrap();
    if let Some(&pid) = reg.get(&(token, clone_id)) {
        // SAFETY: kill(pid, 0) — pure liveness probe, no signal delivered.
        if unsafe { libc::kill(pid as i32, 0) } == 0 {
            tracing::warn!(
                token,
                clone_id,
                worker_pid = pid,
                "clone reconnected while its worker is still alive; rejecting — \
                 a fresh worker would silently reset the clone's GPU state"
            );
            return true; // consumed: caller drops the stream (fail fast)
        }
        reg.remove(&(token, clone_id));
    }
    match spawn_clone_worker(fd, token) {
        Ok(pid) => {
            reg.insert((token, clone_id), pid);
            tracing::info!(
                token,
                clone_id,
                worker_pid = pid,
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

/// Path 3 (M1): hand the accepted connection to a fresh worker PROCESS (its own
/// CUDA context, hence its own UVA — so it can place memory at the golden's exact
/// VAs). `dup2` the socket fd onto fd 3 in the child (clears CLOEXEC) and exec
/// `smolvm _cuda-clone-worker 3`; the daemon then drops its own copy.
#[cfg(unix)]
fn spawn_clone_worker(conn_fd: std::os::unix::io::RawFd, token: u64) -> io::Result<u32> {
    use std::os::unix::process::CommandExt;
    // Gather the golden's VMM layout (reservations + maps→physical handle).
    let (resvs, maps) = smolvm_cuda::host::layout_handoff_snapshot(token)
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
                ch.va, ch.size, idx, ld, ch.handle
            ));
        }
    }
    // M3a: serialize the golden's modules (images) + functions to a temp file for
    // the worker to reload + remap. Images are MB-scale, so a file, not env.
    let mut modpath: Option<String> = None;
    if let Some((modules, funcs, streams, events, graphs)) =
        smolvm_cuda::host::module_handoff_snapshot(token)
    {
        tracing::info!(
            modules = modules.len(),
            funcs = funcs.len(),
            streams = streams.len(),
            events = events.len(),
            graphs = graphs.len(),
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
    let exe = std::env::current_exe()?;
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("_cuda-clone-worker").arg("3");
    cmd.env("SMOLVM_CUDA_CLONE_LAYOUT", layout);
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
    spawned
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
