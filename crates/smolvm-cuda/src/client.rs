//! Guest-side CUDA-RPC client: marshal `cu*` calls over a byte stream.
//!
//! Transport-agnostic — it takes any [`Read`]/[`Write`], so the guest binary
//! supplies an `AF_VSOCK` stream while tests supply an in-memory pipe. Each
//! method does one request→response round-trip and surfaces a non-zero
//! `CUresult` as [`CudaRpcError::Cuda`].

use crate::proto::{decode_response, encode_request, read_msg, write_msg, Op, Request, Response};
use std::io::{self, Read, Write};

/// A client-side failure: transport error, a CUDA error code from the host, or
/// a protocol mismatch (host returned the wrong response shape).
#[derive(Debug)]
pub enum CudaRpcError {
    Io(io::Error),
    /// Non-zero `CUresult` returned by the host driver.
    Cuda(i32),
    Protocol(&'static str),
}

impl std::fmt::Display for CudaRpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CudaRpcError::Io(e) => write!(f, "cuda-rpc io: {e}"),
            CudaRpcError::Cuda(c) => write!(f, "CUDA error {c}"),
            CudaRpcError::Protocol(m) => write!(f, "cuda-rpc protocol: {m}"),
        }
    }
}
impl std::error::Error for CudaRpcError {}
impl From<io::Error> for CudaRpcError {
    fn from(e: io::Error) -> Self {
        CudaRpcError::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, CudaRpcError>;

/// Debug profiling (`SMOLVM_CUDA_COUNT_SYNC=1`): tally synchronous round-trips
/// per op, dumped to stderr every 4096 calls, to show what still serializes an
/// asynchronously-pipelined workload. For `LibCall` the tally key includes the
/// library id and function index.
fn sync_key(req: &Request, op: Op) -> String {
    match req {
        Request::LibCall { lib, func, .. } => format!("LibCall(lib={lib},func={func})"),
        Request::ModuleGetFunction { name, .. } => format!("ModuleGetFunction({name})"),
        Request::FuncGetParamInfo { function } => format!("FuncGetParamInfo(fid={function})"),
        Request::ModuleLoadData { image } => format!("ModuleLoadData(len={})", image.len()),
        _ => format!("{op:?}"),
    }
}

/// Tally one sync round-trip: count AND total wall time per op class, dumped
/// every 4096 calls ranked by TIME (counts alone pointed at high-frequency
/// cheap ops; the gap hides in where the microseconds actually go).
fn count_sync_key(key: &str, dur: std::time::Duration) {
    use std::collections::HashMap;
    use std::sync::Mutex;
    #[allow(clippy::type_complexity)]
    static COUNTS: Mutex<Option<HashMap<String, (u64, u128)>>> = Mutex::new(None);
    let mut g = COUNTS.lock().unwrap();
    let m = g.get_or_insert_with(HashMap::new);
    let e = m.entry(key.to_string()).or_insert((0, 0));
    e.0 += 1;
    e.1 += dur.as_micros();
    let total: u64 = m.values().map(|(n, _)| n).sum();
    if total.is_multiple_of(4096) {
        let mut v: Vec<_> = m.iter().collect();
        v.sort_by_key(|b| std::cmp::Reverse(b.1 .1));
        eprintln!("[sync-times after {total}]");
        for (k, (n, us)) in v.iter().take(12) {
            eprintln!("  {:>9.1}ms {n:>7}x  {k}", *us as f64 / 1000.0);
        }
    }
}

/// C-ABI hooks into another shim's connection in the same process, resolved
/// via `dlsym`. The driver shim (`libcuda.so.1`) routes its traffic through
/// the runtime shim's connection with these, so the host sees ONE
/// program-ordered pipeline instead of two independently flushed queues (two
/// queues let the host execute work out of guest program order — fatal once
/// CUDA-graph capture records the misorder).
#[derive(Clone, Copy)]
pub struct Bridge {
    /// Append one encoded request to the shared pipeline, fire-and-forget.
    /// Nonzero return = transport failure (op-level failures surface later as
    /// sticky asynchronous errors on the owning connection).
    pub quiet: unsafe extern "C" fn(req: *const u8, len: usize) -> i32,
    /// Send one encoded request, receive its response payload (status still
    /// in-band). Returns the response length; -1 = transport failure; any
    /// other negative = `cap` too small, retry with `-ret` bytes and an empty
    /// request to fetch the stashed response.
    pub call: unsafe extern "C" fn(req: *const u8, len: usize, resp: *mut u8, cap: usize) -> isize,
    /// Settle the shared pipeline (fence); returns the first collected
    /// quiet-failure status, 0 if none.
    pub drain: unsafe extern "C" fn() -> i32,
}

/// Debug bisection (`SMOLVM_CUDA_SYNC_OPS=LaunchKernel,LibCall1,LibCall4:10`):
/// force the named op kinds — optionally narrowed to a library id and
/// function index for `LibCall` — to synchronous round-trips while the rest
/// stay deferred, to isolate which deferred class corrupts a failing workload.
fn sync_forced(req: &Request, op: Op) -> bool {
    use std::sync::OnceLock;
    static SET: OnceLock<Vec<String>> = OnceLock::new();
    let set = SET.get_or_init(|| {
        std::env::var("SMOLVM_CUDA_SYNC_OPS")
            .unwrap_or_default()
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.trim().to_ascii_lowercase())
            .collect()
    });
    if set.is_empty() {
        return false;
    }
    let kind = format!("{op:?}").to_ascii_lowercase();
    if set.contains(&kind) {
        return true;
    }
    if let Request::LibCall { lib, func, .. } = req {
        return set.contains(&format!("libcall{lib}"))
            || set.contains(&format!("libcall{lib}:{func}"));
    }
    false
}

/// Bench/diagnostic: `SMOLVM_CUDA_RTT_DELAY_US` sleeps this many microseconds
/// per host round-trip, modeling a remote server's network RTT. Batched
/// deferred work pays it once per fence (as a real network would), so the
/// resulting throughput-vs-latency curve shows how tolerant each mode is of
/// distance. Read once (env lookups aren't free on the hot path).
fn rtt_tax() {
    use std::sync::atomic::{AtomicI64, Ordering};
    static US: AtomicI64 = AtomicI64::new(-1);
    let mut v = US.load(Ordering::Relaxed);
    if v == -1 {
        v = std::env::var("SMOLVM_CUDA_RTT_DELAY_US")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        US.store(v, Ordering::Relaxed);
    }
    if v > 0 {
        std::thread::sleep(std::time::Duration::from_micros(v as u64));
    }
}

/// Round-trip one encoded request over a [`Bridge`], growing the response
/// buffer when the callee reports it too small (the callee stashes the
/// response; an empty request fetches the stash).
fn bridge_call_vec(b: &Bridge, req: &[u8]) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; 4096];
    let mut ret = unsafe { (b.call)(req.as_ptr(), req.len(), buf.as_mut_ptr(), buf.len()) };
    if ret < -1 {
        buf = vec![0u8; (-ret) as usize];
        ret = unsafe { (b.call)(std::ptr::null(), 0, buf.as_mut_ptr(), buf.len()) };
    }
    if ret >= 0 {
        buf.truncate(ret as usize);
        Ok(buf)
    } else {
        Err(CudaRpcError::Protocol("bridge call failed"))
    }
}

/// Shared-memory ring transport state (in-VM fast path; see `crate::ring`).
pub struct ClientRing {
    /// Guest→host requests (this side produces).
    req: crate::ring::Ring,
    /// Host→guest completions (this side consumes).
    resp: crate::ring::Ring,
    /// Guest VAs of the bounce pages: staging for oversized traffic in both
    /// directions (requests chunk guest→host, responses spill host→guest —
    /// never simultaneously, the queue is strictly request-then-response).
    bounce: Vec<*mut u8>,
    page_size: usize,
}

// SAFETY: raw pointers reference process-owned pinned pages; the shim holds
// the client behind a mutex.
unsafe impl Send for ClientRing {}

/// A CUDA Driver-API client over one connection to the host server.
pub struct Client<S> {
    stream: S,
    /// Shared-memory ring transport, when negotiated (in-VM fast path).
    ring: Option<ClientRing>,
    /// When set, this client owns no connection: every request rides another
    /// shim's connection through these hooks (see [`Bridge`]).
    bridge: Option<Bridge>,
    /// Count of quiet (fire-and-forget) requests since the last fence. Quiet
    /// requests produce no responses; a fence settles them all at once.
    deferred: usize,
    /// First non-zero status collected from a deferred response — surfaced at
    /// the next launch/synchronize, mirroring CUDA's asynchronous ("sticky")
    /// error reporting.
    sticky: i32,
    /// Kill-switch: `SMOLVM_CUDA_ASYNC=0` restores strict per-call round-trips.
    defer_enabled: bool,
    /// Sync-elision: true when NO op that could enqueue device work has been
    /// issued since the last successful synchronize. `clean_all` means a
    /// context-wide sync established it (covers every stream); otherwise only
    /// `clean_stream` is known settled. bnb-style workloads synchronize the
    /// same stream dozens of times per training step with no work in between
    /// — each elided sync saves a full host round-trip.
    clean: bool,
    clean_all: bool,
    clean_stream: u64,
    /// Framed-but-unsent deferred requests. Batching them into one write turns
    /// a launch storm's thousand syscalls into a handful; flushed before any
    /// read (a response can only exist for a request the host has seen).
    wbuf: Vec<u8>,
    /// Replay journal: every quiet request "sent" since the last response we
    /// received (encoded payloads, send order). A VM-fork clone inherits a
    /// transport that swallows writes without erroring — ring records land in
    /// cloned pages no host reads, vsock writes buffer into a dead socket — so
    /// quiet ops issued before the first blocking call are silently lost. The
    /// host serves strictly in order, so ANY received response proves every
    /// prior request was consumed (journal clears); on reconnect the journal
    /// replays the unproven suffix. Bounded by MAX_DEFERRED (drain fences).
    journal: Vec<Vec<u8>>,
}

/// Outstanding-response cap. Responses are ~8 bytes, so even the smallest
/// socket buffer holds far more than this; the cap just bounds how much work
/// can race ahead of an error being noticed.
const MAX_DEFERRED: usize = 512;
/// Flush the deferred-write buffer beyond this size even without a sync point,
/// so bulk H2D byte-shipping doesn't accumulate unbounded copies in memory.
const WBUF_FLUSH: usize = 256 * 1024;

impl<S: Read + Write> Client<S> {
    pub fn new(stream: S) -> Self {
        Client {
            stream,
            ring: None,
            bridge: None,
            deferred: 0,
            sticky: 0,
            defer_enabled: std::env::var("SMOLVM_CUDA_ASYNC").as_deref() != Ok("0"),
            clean: false,
            clean_all: false,
            clean_stream: 0,
            wbuf: Vec::new(),
            journal: Vec::new(),
        }
    }

    /// A client that owns no connection: every request rides another shim's
    /// connection via `bridge`. `stream` is never read or written.
    pub fn new_bridged(stream: S, bridge: Bridge) -> Self {
        let mut c = Self::new(stream);
        c.bridge = Some(bridge);
        c
    }

    pub fn is_bridged(&self) -> bool {
        self.bridge.is_some()
    }

    /// Negotiate the shared-memory ring transport (in-VM fast path). `req`,
    /// `resp` and `bounce` are (page VAs, page GPAs) of zeroed, mlocked,
    /// page-aligned guest allocations. On Ok the connection switches: the
    /// socket carries only doorbell bytes from here on.
    #[allow(clippy::type_complexity)]
    pub fn ring_setup(
        &mut self,
        page_size: usize,
        req: (Vec<*mut u8>, Vec<u64>),
        resp: (Vec<*mut u8>, Vec<u64>),
        bounce: (Vec<*mut u8>, Vec<u64>),
    ) -> Result<()> {
        self.call(
            &Request::RingSetup {
                page_size: page_size as u32,
                req_pages: req.1,
                resp_pages: resp.1,
                bounce_pages: bounce.1,
            },
            Op::RingSetup,
        )?;
        // SAFETY: pages are owned by the shim and stay mapped + resident for
        // the process lifetime (mlocked, never freed).
        self.ring = Some(ClientRing {
            req: unsafe { crate::ring::Ring::from_pages(req.0, page_size) },
            resp: unsafe { crate::ring::Ring::from_pages(resp.0, page_size) },
            bounce: bounce.0,
            page_size,
        });
        Ok(())
    }

    /// File-backed ring setup (DAX clone transport): the caller mmap'd
    /// `fname` (inside the guest's dax ring mount) MAP_SHARED and hands the
    /// page pointers here; the host mmaps the same file through the dir its
    /// proxy advertised. Layout: req pages, then resp, then bounce.
    pub fn ring_setup_file(
        &mut self,
        page_size: usize,
        fname: &str,
        req: Vec<*mut u8>,
        resp: Vec<*mut u8>,
        bounce: Vec<*mut u8>,
    ) -> Result<()> {
        self.call(
            &Request::RingSetupFile {
                page_size: page_size as u32,
                req_n: req.len() as u32,
                resp_n: resp.len() as u32,
                bounce_n: bounce.len() as u32,
                fname: fname.as_bytes().to_vec(),
            },
            Op::RingSetupFile,
        )?;
        // SAFETY: the file mapping is owned by the shim and stays mapped for
        // the process lifetime (never munmap'd).
        self.ring = Some(ClientRing {
            req: unsafe { crate::ring::Ring::from_pages(req, page_size) },
            resp: unsafe { crate::ring::Ring::from_pages(resp, page_size) },
            bounce,
            page_size,
        });
        Ok(())
    }

    pub fn is_ring(&self) -> bool {
        self.ring.is_some()
    }

    /// Push one frame (socket-payload bytes: QUIET/FENCE prefix included) to
    /// the request ring. Oversized frames chunk through the bounce pages:
    /// each chunk record is acked by the host before the pages are reused,
    /// except the last — the caller's own response wait covers it, so every
    /// oversized frame MUST be a sync op (quiet callers upgrade to sync).
    fn ring_push(&mut self, frame: &[u8]) -> Result<()> {
        use crate::ring::{INLINE_MAX, LEN_INDIRECT};
        if frame.len() <= INLINE_MAX {
            let ring = self.ring.as_ref().expect("ring transport");
            while !ring.req.try_push(frame, 0) {
                std::hint::spin_loop(); // host drains continuously
            }
            if ring.req.take_parked() {
                self.stream.write_all(&[1u8])?;
                self.stream.flush()?;
            }
            return Ok(());
        }
        let (bounce_cap, page_size) = {
            let ring = self.ring.as_ref().expect("ring transport");
            (ring.bounce.len() * ring.page_size, ring.page_size)
        };
        let total = frame.len();
        let mut off = 0;
        while off < total {
            let chunk = (total - off).min(bounce_cap);
            {
                let ring = self.ring.as_ref().expect("ring transport");
                for (i, piece) in frame[off..off + chunk].chunks(page_size).enumerate() {
                    // SAFETY: bounce pages are live shim allocations of
                    // page_size bytes each; piece fits by construction.
                    unsafe {
                        std::ptr::copy_nonoverlapping(piece.as_ptr(), ring.bounce[i], piece.len());
                    }
                }
                let mut rec = [0u8; 16];
                rec[..8].copy_from_slice(&(total as u64).to_le_bytes());
                rec[8..].copy_from_slice(&(chunk as u64).to_le_bytes());
                while !ring.req.try_push(&rec, LEN_INDIRECT) {
                    std::hint::spin_loop();
                }
                if ring.req.take_parked() {
                    self.stream.write_all(&[1u8])?;
                    self.stream.flush()?;
                }
            }
            off += chunk;
            if off < total {
                // Host acks each non-final chunk once copied out; the final
                // chunk is covered by the operation's own response.
                let _ack = self.ring_pop_response()?;
            }
        }
        Ok(())
    }

    /// Await exactly one completion record: spin briefly, then park and block
    /// on a doorbell byte.
    fn ring_pop_response(&mut self) -> Result<Vec<u8>> {
        use crate::ring::LEN_INDIRECT;
        loop {
            {
                let ring = self.ring.as_ref().expect("ring transport");
                let mut popped = ring.resp.try_pop();
                if popped.is_none() {
                    for _ in 0..20_000 {
                        popped = ring.resp.try_pop();
                        if popped.is_some() {
                            break;
                        }
                        std::hint::spin_loop();
                    }
                }
                if let Some((payload, flags)) = popped {
                    if flags & LEN_INDIRECT == 0 {
                        return Ok(payload);
                    }
                    // Oversized response: [total][chunk] records, each chunk
                    // staged in the bounce pages; we post a continue record
                    // after copying each non-final chunk out.
                    let mut hdr = payload;
                    let mut buf: Vec<u8> = Vec::new();
                    loop {
                        if hdr.len() < 16 {
                            return Err(CudaRpcError::Protocol("ring: short indirect"));
                        }
                        let total = u64::from_le_bytes(hdr[..8].try_into().unwrap()) as usize;
                        let chunk = u64::from_le_bytes(hdr[8..16].try_into().unwrap()) as usize;
                        if chunk > ring.bounce.len() * ring.page_size {
                            return Err(CudaRpcError::Protocol("ring: bounce overrun"));
                        }
                        let mut left = chunk;
                        for &page in &ring.bounce {
                            if left == 0 {
                                break;
                            }
                            let take = left.min(ring.page_size);
                            // SAFETY: bounce pages are live shim allocations.
                            unsafe {
                                buf.extend_from_slice(std::slice::from_raw_parts(
                                    page as *const u8,
                                    take,
                                ));
                            }
                            left -= take;
                        }
                        if buf.len() >= total {
                            return Ok(buf);
                        }
                        // More chunks: tell the host the pages are free.
                        while !ring.req.try_push(&[0xFF; 16], LEN_INDIRECT) {
                            std::hint::spin_loop();
                        }
                        hdr = loop {
                            if let Some((p, f)) = ring.resp.try_pop() {
                                if f & LEN_INDIRECT == 0 {
                                    return Err(CudaRpcError::Protocol("ring: expected chunk"));
                                }
                                break p;
                            }
                            std::hint::spin_loop();
                        };
                    }
                }
                if ring.resp.park() {
                    continue; // record landed while parking
                }
            }
            // Blocked: wait for the host's doorbell byte on the socket.
            let mut byte = [0u8; 1];
            match self.stream.read(&mut byte) {
                Ok(0) => return Err(CudaRpcError::Protocol("host closed ring connection")),
                Ok(_) => {}
                Err(e) => return Err(e.into()),
            }
            self.ring.as_ref().expect("ring transport").resp.unpark();
        }
    }

    /// One sync round-trip over the rings.
    fn ring_roundtrip(&mut self, frame: &[u8]) -> Result<Vec<u8>> {
        self.ring_push(frame)?;
        rtt_tax();
        let resp = self.ring_pop_response()?;
        // In-order serving: this response proves every earlier request was
        // consumed by the host — the replay journal can forget them.
        self.journal.clear();
        Ok(resp)
    }

    /// Send everything buffered by deferred calls.
    fn flush_wbuf(&mut self) -> Result<()> {
        if !self.wbuf.is_empty() {
            self.stream.write_all(&self.wbuf)?;
            self.stream.flush()?;
            self.wbuf.clear();
        }
        Ok(())
    }

    /// Force every op to a synchronous round-trip (disable the deferred
    /// pipeline). Used by the driver shim: it shares one guest program-order
    /// stream with the runtime shim's connection, and two independently
    /// flushed deferred queues would let the host execute their work out of
    /// program order (fatal once CUDA-graph capture records the misorder).
    pub fn set_defer_enabled(&mut self, on: bool) {
        self.defer_enabled = on;
    }

    /// Take this client's replay journal — every quiet request not yet proven
    /// consumed by a host response — plus the sticky status, clearing both. On
    /// a VM-fork clone the inherited transport swallows writes without erroring
    /// (ring records land in cloned pages no host reads; vsock writes buffer
    /// into a dead socket), so these requests may never have reached the host:
    /// they must replay on the reconnected client or the work (e.g. torch's
    /// queued launches before a `.item()`) is silently dropped and later reads
    /// return stale data. Fork points are quiescent (the golden synchronizes
    /// before gating), so an empty journal is the common case and replay of a
    /// host-side-executed op cannot arise there.
    pub fn take_journal(&mut self) -> (Vec<Vec<u8>>, i32) {
        let sticky = std::mem::take(&mut self.sticky);
        self.deferred = 0;
        self.wbuf.clear(); // superseded: the journal holds sent AND unsent
        (std::mem::take(&mut self.journal), sticky)
    }

    /// Replay a journal taken from a prior (dead) client, in order, on this
    /// fresh connection (after `init` — and ring setup, if any — so the ops
    /// re-enter the new pipeline exactly like first-time sends and are
    /// re-journaled for a possible second reconnect). The requests reference
    /// handles that stay valid across the reconnect (shared primary context /
    /// Init handoff / clone-worker translation tables).
    pub fn replay_journal(&mut self, ops: Vec<Vec<u8>>, sticky: i32) -> Result<()> {
        if self.sticky == 0 {
            self.sticky = sticky;
        }
        for payload in ops {
            self.enqueue_quiet(payload)?;
        }
        Ok(())
    }

    /// Settle all fire-and-forget work with a single fence round-trip: quiet
    /// requests produce no per-op responses (each response read costs a guest
    /// wake-up on vsock), so one fence reply carries the first failure among
    /// them.
    pub fn drain(&mut self) -> Result<()> {
        if self.ring.is_some() {
            if self.deferred == 0 {
                return Ok(());
            }
            self.deferred = 0;
            let resp = self.ring_roundtrip(&[crate::proto::FENCE_OP])?;
            if resp.len() >= 4 {
                let status = i32::from_le_bytes(resp[..4].try_into().unwrap());
                if status != 0 && self.sticky == 0 {
                    self.sticky = status;
                }
            }
            return Ok(());
        }
        if let Some(b) = self.bridge {
            let st = unsafe { (b.drain)() };
            if st != 0 && self.sticky == 0 {
                self.sticky = st;
            }
            return Ok(());
        }
        if self.deferred == 0 {
            return self.flush_wbuf();
        }
        self.deferred = 0;
        self.wbuf.extend_from_slice(&1u32.to_le_bytes());
        self.wbuf.push(crate::proto::FENCE_OP);
        self.flush_wbuf()?;
        rtt_tax();
        let payload =
            read_msg(&mut self.stream)?.ok_or(CudaRpcError::Protocol("host closed mid-fence"))?;
        self.journal.clear(); // fence response → all prior consumed
        if payload.len() >= 4 {
            let status = i32::from_le_bytes(payload[..4].try_into().unwrap());
            if status != 0 && self.sticky == 0 {
                if std::env::var_os("SMOLVM_CUDA_TRACE_STICKY").is_some() {
                    eprintln!("[sticky] fence collected {status}");
                }
                self.sticky = status;
            }
        }
        Ok(())
    }

    /// Take (and clear) the sticky asynchronous error, if any. Non-blocking:
    /// reports failures already collected by a past drain, the way
    /// `cudaGetLastError` reports asynchronous errors observed so far.
    pub fn take_sticky(&mut self) -> i32 {
        std::mem::take(&mut self.sticky)
    }

    /// Send `req` without waiting for its (status-only) response. Ordering is
    /// preserved — the host serves one request at a time in arrival order — so
    /// the deferred work is complete by the time any later round-trip returns.
    /// Fails fast if an earlier deferred op already failed (sticky).
    fn call_deferred(&mut self, req: &Request, op: Op) -> Result<()> {
        self.call_deferred_kind(req, op, false)
    }

    fn call_deferred_kind(&mut self, req: &Request, op: Op, _is_libcall: bool) -> Result<()> {
        self.clean = false; // deferred work dirties the pipeline
        if !self.defer_enabled || sync_forced(req, op) {
            return self.call(req, op).map(|_| ());
        }
        if let Some(b) = self.bridge {
            // Push into the owning connection's pipeline NOW — buffering here
            // would re-create the two-queue reorder the bridge exists to kill.
            if self.sticky != 0 {
                return Err(CudaRpcError::Cuda(std::mem::take(&mut self.sticky)));
            }
            let payload = encode_request(req);
            let rc = unsafe { (b.quiet)(payload.as_ptr(), payload.len()) };
            if rc != 0 {
                return Err(CudaRpcError::Cuda(rc));
            }
            return Ok(());
        }
        self.enqueue_quiet(encode_request(req))
    }

    /// Enqueue one quiet (fire-and-forget) request payload on the active
    /// transport, journaling it for replay-on-reconnect. The journal append
    /// comes FIRST so a payload whose transport write fails is still replayed
    /// after the reconnect that failure triggers.
    fn enqueue_quiet(&mut self, payload: Vec<u8>) -> Result<()> {
        if self.deferred >= MAX_DEFERRED {
            self.drain()?;
        }
        if self.sticky != 0 {
            return Err(CudaRpcError::Cuda(std::mem::take(&mut self.sticky)));
        }
        if self.ring.is_some() {
            if payload.len() < crate::ring::INLINE_MAX {
                let mut frame = Vec::with_capacity(payload.len() + 1);
                frame.push(crate::proto::QUIET_PREFIX);
                frame.extend_from_slice(&payload);
                self.journal.push(payload);
                self.deferred += 1;
                // A transport error here (e.g. a fork clone's first op hitting
                // the dead inherited ring/doorbell) is NOT a failure of the op:
                // it is already journaled, so the reconnect the next blocking
                // call triggers will replay it in order. Erroring here instead
                // made the guest wrapper fail the op spuriously (seen as a
                // bogus CUBLAS_STATUS_NOT_INITIALIZED on the clone's first
                // post-fork matmul). A persistent transport failure still
                // surfaces loudly at the next blocking round-trip.
                let _ = self.ring_push(&frame);
            } else {
                // Oversized quiet frames go indirect, which needs the staging
                // buffer alive until consumption — round-trip instead and
                // fold a failure into the sticky slot. (Synchronous: no
                // journal entry needed, the response itself proves delivery.)
                let resp = self.ring_roundtrip(&payload)?;
                if resp.len() >= 4 {
                    let st = i32::from_le_bytes(resp[..4].try_into().unwrap());
                    if st != 0 && self.sticky == 0 {
                        self.sticky = st;
                    }
                }
            }
            return Ok(());
        }
        // Frame into the batch buffer as a QUIET request (no response) — one
        // write syscall per sync point (or per WBUF_FLUSH bytes), and one
        // fence reply per drain instead of one reply per request.
        self.wbuf
            .extend_from_slice(&((payload.len() + 1) as u32).to_le_bytes());
        self.wbuf.push(crate::proto::QUIET_PREFIX);
        self.wbuf.extend_from_slice(&payload);
        self.journal.push(payload);
        self.deferred += 1;
        if self.wbuf.len() >= WBUF_FLUSH {
            // Swallow a transport error: the ops are journaled (see the ring
            // branch above) and replay after the reconnect the next blocking
            // call triggers.
            let _ = self.flush_wbuf();
        }
        Ok(())
    }

    /// Fire-and-forget `LibCall` for library functions with no output
    /// parameters (GEMMs, conv/batch-norm executes, stream setters): the call
    /// reports optimistic success and a real failure surfaces as a sticky
    /// asynchronous error, like a failed kernel launch.
    pub fn lib_call_deferred(&mut self, lib: u8, func: u16, args: Vec<u8>) -> Result<()> {
        self.call_deferred_kind(&Request::LibCall { lib, func, args }, Op::LibCall, true)
    }

    fn call(&mut self, req: &Request, op: Op) -> Result<Response> {
        // Sync-elision bookkeeping: only ops that can leave PENDING device
        // work dirty the pipeline. Pure queries return existing state, and
        // the blocking transfer forms complete before the host responds —
        // after either, a stream with nothing else outstanding is still
        // settled. Everything not whitelisted dirties (conservative).
        match op {
            Op::StreamSynchronize
            | Op::CtxSynchronize
            | Op::EventSynchronize
            | Op::DeviceGetCount
            | Op::DeviceGetName
            | Op::DeviceTotalMem
            | Op::DriverGetVersion
            | Op::DeviceGetAttribute
            | Op::DeviceGetUuid
            | Op::ModuleGetFunction
            | Op::FuncGetParamInfo
            | Op::FuncGetAttribute
            | Op::MemAlloc
            | Op::MemFree
            | Op::MemGetInfo
            | Op::MemcpyDtoH
            | Op::MemcpyShmDtoH
            | Op::MemcpyGpaDtoH
            | Op::StreamQuery
            | Op::EventQuery
            | Op::EventCreate
            | Op::EventDestroy
            | Op::EventElapsedTime
            | Op::StreamCaptureInfo => {}
            _ => self.clean = false,
        }
        static TALLY: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        let tally = *TALLY.get_or_init(|| std::env::var_os("SMOLVM_CUDA_COUNT_SYNC").is_some());
        let t0 = tally.then(std::time::Instant::now);
        let payload = if self.ring.is_some() {
            self.ring_roundtrip(&encode_request(req))?
        } else if let Some(b) = self.bridge {
            bridge_call_vec(&b, &encode_request(req))?
        } else {
            // Flush, don't fence: the host serves in arrival order, so this
            // request's response already proves every deferred request before
            // it was consumed. A fence here would double the RTT of every
            // sync op under deferred load just to surface quiet failures a
            // little earlier — they still surface at explicit sync points
            // (drain) and the MAX_DEFERRED backstop.
            self.flush_wbuf()?;
            write_msg(&mut self.stream, &encode_request(req))?;
            rtt_tax();
            let p = read_msg(&mut self.stream)?
                .ok_or(CudaRpcError::Protocol("host closed mid-call"))?;
            self.journal.clear(); // response received → all prior consumed
            p
        };
        let (status, resp) = decode_response(op, &payload)?;
        if let Some(t0) = t0 {
            count_sync_key(&sync_key(req, op), t0.elapsed());
        }
        if status != 0 {
            return Err(CudaRpcError::Cuda(status));
        }
        Ok(resp)
    }

    /// Serve a bridged peer: append one pre-encoded request to this
    /// connection's deferred pipeline, preserving arrival order. In strict
    /// mode (`SMOLVM_CUDA_ASYNC=0`) the request round-trips instead and a
    /// failure status is collected as this connection's sticky error.
    pub fn raw_quiet(&mut self, payload: &[u8]) -> Result<()> {
        self.clean = false; // bridged driver-shim work dirties the pipeline
        if !self.defer_enabled {
            let resp = self.raw_call(payload)?;
            if resp.len() >= 4 {
                let st = i32::from_le_bytes(resp[..4].try_into().unwrap());
                if st != 0 && self.sticky == 0 {
                    self.sticky = st;
                }
            }
            return Ok(());
        }
        self.enqueue_quiet(payload.to_vec())
    }

    /// Serve a bridged peer: one pre-encoded synchronous round-trip. Returns
    /// the raw response payload — the status stays in-band for the peer to
    /// decode, so nothing is lost to error mapping.
    pub fn raw_call(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        self.clean = false; // bridged driver-shim work dirties the pipeline
        static TALLY_RAW: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        if *TALLY_RAW.get_or_init(|| std::env::var_os("SMOLVM_CUDA_COUNT_SYNC").is_some()) {
            let t0 = std::time::Instant::now();
            let r = self.raw_call_inner(payload);
            let key = format!("Bridged(0x{:02x})", payload.first().copied().unwrap_or(0));
            count_sync_key(&key, t0.elapsed());
            return r;
        }
        self.raw_call_inner(payload)
    }

    fn raw_call_inner(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        if self.ring.is_some() {
            return self.ring_roundtrip(payload);
        }
        // Flush, don't fence — see `call`.
        self.flush_wbuf()?;
        write_msg(&mut self.stream, payload)?;
        rtt_tax();
        let p =
            read_msg(&mut self.stream)?.ok_or(CudaRpcError::Protocol("host closed mid-call"))?;
        self.journal.clear(); // response received → all prior consumed
        Ok(p)
    }

    /// Run the connect handshake, adopting `resume_token`'s (frozen) session
    /// handle map if non-zero. Returns this session's own lineage token, to be
    /// replayed as `resume_token` when a fork clone reconnects.
    pub fn init(&mut self, resume_token: u64) -> Result<u64> {
        match self.call(
            &Request::Init {
                proto_hash: crate::PROTO_HASH,
                resume_token,
            },
            Op::Init,
        )? {
            Response::Handle(token) => Ok(token),
            // Older host that replies Ok carries no token; treat as no handoff.
            _ => Ok(0),
        }
    }

    pub fn device_get_count(&mut self) -> Result<i32> {
        match self.call(&Request::DeviceGetCount, Op::DeviceGetCount)? {
            Response::Count(n) => Ok(n),
            _ => Err(CudaRpcError::Protocol("expected Count")),
        }
    }

    pub fn device_get_name(&mut self, device: i32) -> Result<String> {
        match self.call(&Request::DeviceGetName { device }, Op::DeviceGetName)? {
            Response::Name(s) => Ok(s),
            _ => Err(CudaRpcError::Protocol("expected Name")),
        }
    }

    pub fn device_total_mem(&mut self, device: i32) -> Result<u64> {
        match self.call(&Request::DeviceTotalMem { device }, Op::DeviceTotalMem)? {
            Response::Bytes(v) => Ok(v),
            _ => Err(CudaRpcError::Protocol("expected Bytes")),
        }
    }

    pub fn ctx_create(&mut self, device: i32) -> Result<u64> {
        match self.call(&Request::CtxCreate { device }, Op::CtxCreate)? {
            Response::Handle(h) => Ok(h),
            _ => Err(CudaRpcError::Protocol("expected Handle")),
        }
    }

    pub fn ctx_destroy(&mut self, ctx: u64) -> Result<()> {
        self.call(&Request::CtxDestroy { ctx }, Op::CtxDestroy)
            .map(|_| ())
    }

    pub fn module_load_data(&mut self, image: &[u8]) -> Result<u64> {
        // Dedup: offer the image BY CONTENT HASH first (LibCall 6/1). A HIT
        // loads the server's cached copy — the bytes never cross the wire
        // again (engine loads re-ship hundreds of MB of identical fatbins per
        // replica otherwise). MISS or an old server → full send below, which
        // also populates the server cache.
        if image.len() >= 64 {
            let mut blob = Vec::with_capacity(32);
            blob.extend_from_slice(&crate::host::fnv64(image).to_le_bytes());
            blob.extend_from_slice(&(image.len() as u64).to_le_bytes());
            blob.extend_from_slice(&image[..8]);
            blob.extend_from_slice(&image[image.len() - 8..]);
            if let Ok((0, out)) = self.lib_call(6, 1, blob) {
                if out.len() == 8 {
                    return Ok(u64::from_le_bytes(out.try_into().unwrap()));
                }
            }
        }
        match self.call(
            &Request::ModuleLoadData {
                image: image.to_vec(),
            },
            Op::ModuleLoadData,
        )? {
            Response::Handle(h) => Ok(h),
            _ => Err(CudaRpcError::Protocol("expected Handle")),
        }
    }

    pub fn module_get_function(&mut self, module: u64, name: &str) -> Result<u64> {
        match self.call(
            &Request::ModuleGetFunction {
                module,
                name: name.to_string(),
            },
            Op::ModuleGetFunction,
        )? {
            Response::Handle(h) => Ok(h),
            _ => Err(CudaRpcError::Protocol("expected Handle")),
        }
    }

    pub fn mem_alloc(&mut self, bytes: u64) -> Result<u64> {
        match self.call(&Request::MemAlloc { bytes }, Op::MemAlloc)? {
            Response::Dptr(d) => Ok(d),
            _ => Err(CudaRpcError::Protocol("expected Dptr")),
        }
    }

    pub fn mem_free(&mut self, dptr: u64) -> Result<()> {
        // Deferred: status-only, and callers ignore free failures anyway.
        self.call_deferred(&Request::MemFree { dptr }, Op::MemFree)
    }

    pub fn memcpy_htod(&mut self, dptr: u64, data: &[u8], stream: u64) -> Result<()> {
        // Deferred: the bytes are copied into the request, so the caller may
        // reuse its buffer immediately — synchronous-memcpy semantics hold.
        self.call_deferred(
            &Request::MemcpyHtoD {
                dptr,
                stream,
                data: data.to_vec(),
            },
            Op::MemcpyHtoD,
        )
    }

    pub fn memcpy_dtoh(&mut self, dptr: u64, bytes: u64, stream: u64) -> Result<Vec<u8>> {
        match self.call(
            &Request::MemcpyDtoH {
                dptr,
                bytes,
                stream,
            },
            Op::MemcpyDtoH,
        )? {
            Response::Data(d) => Ok(d),
            _ => Err(CudaRpcError::Protocol("expected Data")),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn launch_kernel(
        &mut self,
        function: u64,
        grid: [u32; 3],
        block: [u32; 3],
        shared_bytes: u32,
        stream: u64,
        params: &[Vec<u8>],
    ) -> Result<()> {
        // Deferred: kernel launches are asynchronous by CUDA contract; launch
        // failures surface at the next synchronize (or as a sticky error),
        // exactly like a real asynchronous launch error.
        self.call_deferred(
            &Request::LaunchKernel {
                function,
                grid,
                block,
                shared_bytes,
                stream,
                params: params.to_vec(),
            },
            Op::LaunchKernel,
        )
    }

    /// Exchange the serving thread's stream-capture interaction mode; returns
    /// the previous mode. Sync: the caller's next op must see the new mode.
    pub fn thread_exchange_capture_mode(&mut self, mode: i32) -> Result<i32> {
        match self.call(
            &Request::ThreadExchangeCaptureMode { mode },
            Op::ThreadExchangeCaptureMode,
        )? {
            Response::Count(old) => Ok(old),
            _ => Err(CudaRpcError::Protocol("expected Count")),
        }
    }

    pub fn stream_begin_capture(&mut self, stream: u64, mode: i32) -> Result<()> {
        self.call(
            &Request::StreamBeginCapture { stream, mode },
            Op::StreamBeginCapture,
        )
        .map(|_| ())
    }

    /// Fire-and-forget begin-capture: the host starts capture when this drains,
    /// and subsequent (also-deferred) launches record in order. Saves a host
    /// round-trip per captured graph (coldstart over a network).
    pub fn stream_begin_capture_deferred(&mut self, stream: u64, mode: i32) -> Result<()> {
        self.call_deferred(
            &Request::StreamBeginCapture { stream, mode },
            Op::StreamBeginCapture,
        )
    }

    /// Fire-and-forget end-capture: the guest supplies a virtual graph handle
    /// it minted; the host maps it to the real captured graph when it drains.
    pub fn stream_end_capture_deferred(&mut self, stream: u64, graph_vh: u64) -> Result<()> {
        self.call_deferred(
            &Request::StreamEndCapture { stream, graph_vh },
            Op::StreamEndCapture,
        )
    }

    /// `(capture_status, capture_id)` straight from the host driver.
    pub fn stream_capture_info(&mut self, stream: u64) -> Result<(u64, u64)> {
        match self.call(
            &Request::StreamCaptureInfo { stream },
            Op::StreamCaptureInfo,
        )? {
            Response::Pair(a, b) => Ok((a, b)),
            _ => Err(CudaRpcError::Protocol("expected Pair")),
        }
    }

    /// Fire-and-forget instantiate: `graph` is a virtual graph handle; the
    /// guest supplies a virtual exec handle the host maps to the real exec.
    pub fn graph_instantiate_deferred(&mut self, graph: u64, exec_vh: u64) -> Result<()> {
        self.call_deferred(
            &Request::GraphInstantiate { graph, exec_vh },
            Op::GraphInstantiate,
        )
    }

    /// Replay an instantiated graph — the hot path (one message replays every
    /// captured kernel), so it pipelines like a kernel launch.
    pub fn graph_launch(&mut self, graph_exec: u64, stream: u64) -> Result<()> {
        self.call_deferred(
            &Request::GraphLaunch { graph_exec, stream },
            Op::GraphLaunch,
        )
    }

    /// Node count of a captured graph (count-only query; PyTorch uses it to
    /// warn about empty captures).
    pub fn graph_get_node_count(&mut self, graph: u64) -> Result<u64> {
        match self.call(&Request::GraphGetNodes { graph }, Op::GraphGetNodes)? {
            Response::Bytes(n) => Ok(n),
            _ => Err(CudaRpcError::Protocol("expected Bytes")),
        }
    }

    pub fn graph_exec_destroy(&mut self, graph_exec: u64) -> Result<()> {
        self.call_deferred(
            &Request::GraphExecDestroy { graph_exec },
            Op::GraphExecDestroy,
        )
    }

    pub fn graph_destroy(&mut self, graph: u64) -> Result<()> {
        self.call_deferred(&Request::GraphDestroy { graph }, Op::GraphDestroy)
    }

    /// Stream-ordered memset: capture-safe (recorded into an active graph).
    pub fn memset_d8_async(&mut self, dptr: u64, value: u8, bytes: u64, stream: u64) -> Result<()> {
        self.call_deferred(
            &Request::MemsetD8Async {
                dptr,
                value,
                bytes,
                stream,
            },
            Op::MemsetD8Async,
        )
    }

    /// Stream-ordered device copy: capture-safe.
    pub fn memcpy_dtod_async(&mut self, dst: u64, src: u64, bytes: u64, stream: u64) -> Result<()> {
        self.call_deferred(
            &Request::MemcpyDtoDAsync {
                dst,
                src,
                bytes,
                stream,
            },
            Op::MemcpyDtoDAsync,
        )
    }

    pub fn ctx_synchronize(&mut self) -> Result<()> {
        // Clean-pipeline elision: nothing was issued since a context-wide
        // sync completed, so there is nothing to wait for — skip the trip.
        if self.clean && self.clean_all && self.sticky == 0 {
            return Ok(());
        }
        // Settle fire-and-forget work first: a quiet op's failure lives in the
        // HOST's sticky slot and only a fence reports it — and synchronize is
        // exactly CUDA's contract point for surfacing asynchronous errors.
        // Without this, a failed quiet launch (e.g. an inherited CUDA graph a
        // fork clone couldn't rebuild) returns success + stale data.
        self.drain()?;
        self.call(&Request::CtxSynchronize, Op::CtxSynchronize)?;
        self.clean = true;
        self.clean_all = true;
        // Surface any asynchronous failure collected by the drain, the way
        // cudaDeviceSynchronize reports errors from earlier async work.
        match self.take_sticky() {
            0 => Ok(()),
            code => Err(CudaRpcError::Cuda(code)),
        }
    }

    pub fn driver_get_version(&mut self) -> Result<i32> {
        match self.call(&Request::DriverGetVersion, Op::DriverGetVersion)? {
            Response::Count(v) => Ok(v),
            _ => Err(CudaRpcError::Protocol("expected Count")),
        }
    }

    pub fn device_get_attribute(&mut self, attrib: i32, device: i32) -> Result<i32> {
        match self.call(
            &Request::DeviceGetAttribute { attrib, device },
            Op::DeviceGetAttribute,
        )? {
            Response::Count(v) => Ok(v),
            _ => Err(CudaRpcError::Protocol("expected Count")),
        }
    }

    pub fn device_get_uuid(&mut self, device: i32) -> Result<[u8; 16]> {
        match self.call(&Request::DeviceGetUuid { device }, Op::DeviceGetUuid)? {
            Response::Data(d) if d.len() == 16 => {
                let mut uuid = [0u8; 16];
                uuid.copy_from_slice(&d);
                Ok(uuid)
            }
            _ => Err(CudaRpcError::Protocol("expected 16-byte Data")),
        }
    }

    pub fn primary_ctx_retain(&mut self, device: i32) -> Result<u64> {
        match self.call(&Request::PrimaryCtxRetain { device }, Op::PrimaryCtxRetain)? {
            Response::Handle(h) => Ok(h),
            _ => Err(CudaRpcError::Protocol("expected Handle")),
        }
    }

    pub fn primary_ctx_release(&mut self, device: i32) -> Result<()> {
        self.call(
            &Request::PrimaryCtxRelease { device },
            Op::PrimaryCtxRelease,
        )
        .map(|_| ())
    }

    pub fn module_unload(&mut self, module: u64) -> Result<()> {
        self.call(&Request::ModuleUnload { module }, Op::ModuleUnload)
            .map(|_| ())
    }

    /// Per-parameter byte sizes of the kernel's arguments, in declaration order.
    /// Set a `CUfunction_attribute` on the host function (round-trip: the caller
    /// — Triton — checks the status to decide whether the kernel can run).
    pub fn func_get_attribute(&mut self, function: u64, attrib: i32) -> Result<i32> {
        match self.call(
            &Request::FuncGetAttribute { function, attrib },
            Op::FuncGetAttribute,
        )? {
            Response::Count(v) => Ok(v),
            _ => Err(CudaRpcError::Protocol("expected Count")),
        }
    }

    pub fn func_set_attribute(&mut self, function: u64, attrib: i32, value: i32) -> Result<()> {
        self.call(
            &Request::FuncSetAttribute {
                function,
                attrib,
                value,
            },
            Op::FuncSetAttribute,
        )
        .map(|_| ())
    }

    pub fn func_get_param_info(&mut self, function: u64) -> Result<Vec<u32>> {
        match self.call(
            &Request::FuncGetParamInfo { function },
            Op::FuncGetParamInfo,
        )? {
            Response::Data(d) if d.len() % 4 == 0 => Ok(d
                .chunks_exact(4)
                .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
                .collect()),
            _ => Err(CudaRpcError::Protocol("expected u32-array Data")),
        }
    }

    pub fn memcpy_dtod(&mut self, dst: u64, src: u64, bytes: u64) -> Result<()> {
        self.call(&Request::MemcpyDtoD { dst, src, bytes }, Op::MemcpyDtoD)
            .map(|_| ())
    }

    pub fn memset_d8(&mut self, dptr: u64, value: u8, bytes: u64) -> Result<()> {
        // Deferred: status-only device-side work, same contract as a launch.
        self.call_deferred(&Request::MemsetD8 { dptr, value, bytes }, Op::MemsetD8)
    }

    /// Returns `(free, total)` device memory in bytes.
    pub fn mem_get_info(&mut self) -> Result<(u64, u64)> {
        match self.call(&Request::MemGetInfo, Op::MemGetInfo)? {
            Response::Pair(free, total) => Ok((free, total)),
            _ => Err(CudaRpcError::Protocol("expected Pair")),
        }
    }

    pub fn stream_create(&mut self, flags: u32) -> Result<u64> {
        match self.call(&Request::StreamCreate { flags }, Op::StreamCreate)? {
            Response::Handle(h) => Ok(h),
            _ => Err(CudaRpcError::Protocol("expected Handle")),
        }
    }

    pub fn stream_destroy(&mut self, stream: u64) -> Result<()> {
        self.call(&Request::StreamDestroy { stream }, Op::StreamDestroy)
            .map(|_| ())
    }

    pub fn stream_synchronize(&mut self, stream: u64) -> Result<()> {
        // Clean-pipeline elision: no device work was issued since the last
        // successful sync whose scope covers this stream (same stream, or a
        // context-wide sync). bnb-heavy steps repeat this dozens of times.
        if self.clean && self.sticky == 0 && (self.clean_all || self.clean_stream == stream) {
            return Ok(());
        }
        self.drain()?; // see ctx_synchronize: fences surface quiet failures
        self.call(
            &Request::StreamSynchronize { stream },
            Op::StreamSynchronize,
        )?;
        self.clean = true;
        self.clean_all = false;
        self.clean_stream = stream;
        match self.take_sticky() {
            0 => Ok(()),
            code => Err(CudaRpcError::Cuda(code)),
        }
    }

    /// Raw `cuStreamQuery` code: 0 complete, 600 not ready.
    pub fn stream_query(&mut self, stream: u64) -> Result<i32> {
        match self.call(&Request::StreamQuery { stream }, Op::StreamQuery)? {
            Response::Count(code) => Ok(code),
            _ => Err(CudaRpcError::Protocol("expected Count")),
        }
    }

    /// Deferred like a launch: a stream-ordered dependency edge whose failure
    /// surfaces at the next fence, exactly like an async launch error.
    pub fn stream_wait_event(&mut self, stream: u64, event: u64, flags: u32) -> Result<()> {
        self.call_deferred(
            &Request::StreamWaitEvent {
                stream,
                event,
                flags,
            },
            Op::StreamWaitEvent,
        )
    }

    /// Raw `cuEventQuery` code: 0 complete, 600 not ready.
    pub fn event_query(&mut self, event: u64) -> Result<i32> {
        match self.call(&Request::EventQuery { event }, Op::EventQuery)? {
            Response::Count(code) => Ok(code),
            _ => Err(CudaRpcError::Protocol("expected Count")),
        }
    }

    pub fn event_create(&mut self, flags: u32) -> Result<u64> {
        match self.call(&Request::EventCreate { flags }, Op::EventCreate)? {
            Response::Handle(h) => Ok(h),
            _ => Err(CudaRpcError::Protocol("expected Handle")),
        }
    }

    pub fn event_destroy(&mut self, event: u64) -> Result<()> {
        // No return value: fire-and-forget. torch's allocator churns events
        // (~2,500 destroys/short run); a sync round-trip each was pure tax.
        // Ordered in the pipeline, so it runs after every prior use of `event`.
        self.call_deferred_kind(&Request::EventDestroy { event }, Op::EventDestroy, false)
    }

    pub fn event_record(&mut self, event: u64, stream: u64) -> Result<()> {
        // No return value (also graph-capturable): fire-and-forget. It flushes
        // before any sync that reads the event (EventQuery/Synchronize/
        // ElapsedTime), so the record is always ordered before its reader.
        self.call_deferred_kind(
            &Request::EventRecord { event, stream },
            Op::EventRecord,
            false,
        )
    }

    pub fn event_synchronize(&mut self, event: u64) -> Result<()> {
        self.call(&Request::EventSynchronize { event }, Op::EventSynchronize)
            .map(|_| ())
    }

    pub fn event_elapsed_time(&mut self, start: u64, end: u64) -> Result<f32> {
        match self.call(
            &Request::EventElapsedTime { start, end },
            Op::EventElapsedTime,
        )? {
            Response::Millis(ms) => Ok(ms),
            _ => Err(CudaRpcError::Protocol("expected Millis")),
        }
    }

    /// `(nvcomp_status, temp_bytes)` — nvcomp status is the library's own code.
    pub fn nvcomp_deflate_temp_size(
        &mut self,
        num_chunks: u64,
        max_uncompressed_chunk_bytes: u64,
        max_total_uncompressed_bytes: u64,
    ) -> Result<(i32, u64)> {
        match self.call(
            &Request::NvcompDeflateTempSize {
                num_chunks,
                max_uncompressed_chunk_bytes,
                max_total_uncompressed_bytes,
            },
            Op::NvcompDeflateTempSize,
        )? {
            Response::Pair(st, tb) => Ok((st as i32, tb)),
            _ => Err(CudaRpcError::Protocol("expected Pair")),
        }
    }

    /// Returns the nvcomp status code.
    #[allow(clippy::too_many_arguments)]
    pub fn nvcomp_deflate_decompress(
        &mut self,
        device_compressed_ptrs: u64,
        device_compressed_bytes: u64,
        device_uncompressed_bytes: u64,
        device_actual_uncompressed_bytes: u64,
        batch_size: u64,
        device_temp: u64,
        temp_bytes: u64,
        device_uncompressed_ptrs: u64,
        device_statuses: u64,
        stream: u64,
    ) -> Result<i32> {
        match self.call(
            &Request::NvcompDeflateDecompress {
                device_compressed_ptrs,
                device_compressed_bytes,
                device_uncompressed_bytes,
                device_actual_uncompressed_bytes,
                batch_size,
                device_temp,
                temp_bytes,
                device_uncompressed_ptrs,
                device_statuses,
                stream,
            },
            Op::NvcompDeflateDecompress,
        )? {
            Response::Count(st) => Ok(st),
            _ => Err(CudaRpcError::Protocol("expected Count")),
        }
    }

    pub fn cublas_create(&mut self) -> Result<u64> {
        match self.call(&Request::CublasCreate, Op::CublasCreate)? {
            Response::Handle(h) => Ok(h),
            _ => Err(CudaRpcError::Protocol("expected Handle")),
        }
    }

    pub fn cublas_destroy(&mut self, handle: u64) -> Result<()> {
        self.call(&Request::CublasDestroy { handle }, Op::CublasDestroy)
            .map(|_| ())
    }

    pub fn cublas_set_stream(&mut self, handle: u64, stream: u64) -> Result<()> {
        self.call(
            &Request::CublasSetStream { handle, stream },
            Op::CublasSetStream,
        )
        .map(|_| ())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn cublas_sgemm(
        &mut self,
        handle: u64,
        transa: u32,
        transb: u32,
        m: i32,
        n: i32,
        k: i32,
        alpha: f32,
        a: u64,
        lda: i32,
        b: u64,
        ldb: i32,
        beta: f32,
        c: u64,
        ldc: i32,
    ) -> Result<()> {
        self.call(
            &Request::CublasSgemm {
                handle,
                transa,
                transb,
                m,
                n,
                k,
                alpha_bits: alpha.to_bits(),
                a,
                lda,
                b,
                ldb,
                beta_bits: beta.to_bits(),
                c,
                ldc,
            },
            Op::CublasSgemm,
        )
        .map(|_| ())
    }

    /// Generic forward-to-host-lib call. Returns `(library_status, outputs)`.
    pub fn lib_call(&mut self, lib: u8, func: u16, args: Vec<u8>) -> Result<(i32, Vec<u8>)> {
        match self.call(&Request::LibCall { lib, func, args }, Op::LibCall)? {
            Response::LibResult(status, out) => Ok((status, out)),
            _ => Err(CudaRpcError::Protocol("expected LibResult")),
        }
    }

    // ---- VMM (torch expandable-segments) — sync control-plane ops ----
    pub fn mem_address_reserve(&mut self, size: u64, align: u64) -> Result<u64> {
        match self.call(
            &Request::MemAddressReserve { size, align },
            Op::MemAddressReserve,
        )? {
            Response::Dptr(va) => Ok(va),
            _ => Err(CudaRpcError::Protocol("expected Dptr")),
        }
    }
    pub fn mem_create(&mut self, size: u64, device: i32) -> Result<u64> {
        match self.call(&Request::MemCreate { size, device }, Op::MemCreate)? {
            Response::Handle(h) => Ok(h),
            _ => Err(CudaRpcError::Protocol("expected Handle")),
        }
    }
    /// Fire-and-forget create under a guest-minted virtual handle: the burst
    /// path for allocation-heavy phases (model load) — create/map/setAccess
    /// pipeline with no per-chunk round trip. A failure (e.g. OOM) surfaces as
    /// a sticky asynchronous error at the next blocking call.
    pub fn mem_create_vh(&mut self, size: u64, device: i32, handle_vh: u64) -> Result<()> {
        self.call_deferred(
            &Request::MemCreateVh {
                size,
                device,
                handle_vh,
            },
            Op::MemCreateVh,
        )
    }
    pub fn mem_map_quiet(&mut self, va: u64, size: u64, offset: u64, handle: u64) -> Result<()> {
        self.call_deferred(
            &Request::MemMap {
                va,
                size,
                offset,
                handle,
            },
            Op::MemMap,
        )
    }
    pub fn mem_set_access_quiet(&mut self, va: u64, size: u64, device: i32) -> Result<()> {
        self.call_deferred(
            &Request::MemSetAccess { va, size, device },
            Op::MemSetAccess,
        )
    }
    pub fn mem_release_quiet(&mut self, handle: u64) -> Result<()> {
        self.call_deferred(&Request::MemRelease { handle }, Op::MemRelease)
    }
    /// Pin this session to host GPU `device` (guest device 0 maps to it; the
    /// guest sees exactly one device). Sent right after `init` when the VM is
    /// launched with `SMOLVM_CUDA_DEVICE=<n>`.
    pub fn set_device_base(&mut self, device: i32) -> Result<()> {
        self.call_deferred(&Request::SetDeviceBase { device }, Op::SetDeviceBase)
    }
    pub fn mem_map(&mut self, va: u64, size: u64, offset: u64, handle: u64) -> Result<()> {
        self.call(
            &Request::MemMap {
                va,
                size,
                offset,
                handle,
            },
            Op::MemMap,
        )
        .map(|_| ())
    }
    pub fn mem_set_access(&mut self, va: u64, size: u64, device: i32) -> Result<()> {
        self.call(
            &Request::MemSetAccess { va, size, device },
            Op::MemSetAccess,
        )
        .map(|_| ())
    }
    pub fn mem_unmap(&mut self, va: u64, size: u64) -> Result<()> {
        self.call(&Request::MemUnmap { va, size }, Op::MemUnmap)
            .map(|_| ())
    }
    pub fn mem_release(&mut self, handle: u64) -> Result<()> {
        self.call(&Request::MemRelease { handle }, Op::MemRelease)
            .map(|_| ())
    }
    pub fn mem_address_free(&mut self, va: u64, size: u64) -> Result<()> {
        self.call(&Request::MemAddressFree { va, size }, Op::MemAddressFree)
            .map(|_| ())
    }
    pub fn mem_get_allocation_granularity(&mut self, device: i32, flags: u32) -> Result<u64> {
        match self.call(
            &Request::MemGetAllocationGranularity { device, flags },
            Op::MemGetAllocationGranularity,
        )? {
            Response::Bytes(g) => Ok(g),
            _ => Err(CudaRpcError::Protocol("expected Bytes")),
        }
    }

    /// Zero-copy H2D via the shared region (data already written at `offset`).
    pub fn memcpy_shm_htod(
        &mut self,
        dptr: u64,
        offset: u64,
        size: u64,
        stream: u64,
    ) -> Result<()> {
        self.call(
            &Request::MemcpyShmHtoD {
                dptr,
                offset,
                size,
                stream,
            },
            Op::MemcpyShmHtoD,
        )
        .map(|_| ())
    }

    /// Zero-copy D2H via the shared region (host writes into `offset`).
    pub fn memcpy_shm_dtoh(
        &mut self,
        offset: u64,
        dptr: u64,
        size: u64,
        stream: u64,
    ) -> Result<()> {
        self.call(
            &Request::MemcpyShmDtoH {
                offset,
                dptr,
                size,
                stream,
            },
            Op::MemcpyShmDtoH,
        )
        .map(|_| ())
    }

    /// Zero-copy H2D from guest RAM: the host gathers `segments` (guest-physical)
    /// and DMAs to `dptr`.
    pub fn memcpy_gpa_htod(
        &mut self,
        dptr: u64,
        segments: Vec<(u64, u64)>,
        stream: u64,
    ) -> Result<()> {
        self.call(
            &Request::MemcpyGpaHtoD {
                dptr,
                stream,
                segments,
            },
            Op::MemcpyGpaHtoD,
        )
        .map(|_| ())
    }

    /// Zero-copy D2H to guest RAM: the host DMAs from `dptr` and scatters into
    /// `segments` (guest-physical).
    pub fn memcpy_gpa_dtoh(
        &mut self,
        dptr: u64,
        segments: Vec<(u64, u64)>,
        stream: u64,
    ) -> Result<()> {
        self.call(
            &Request::MemcpyGpaDtoH {
                dptr,
                stream,
                segments,
            },
            Op::MemcpyGpaDtoH,
        )
        .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::QUIET_PREFIX;
    use std::sync::Mutex;

    /// What the fake bridge callee observed / will serve.
    static QUIET_LOG: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());
    static PENDING: Mutex<Option<Vec<u8>>> = Mutex::new(None);
    static RESPONSE: Mutex<Vec<u8>> = Mutex::new(Vec::new());

    unsafe extern "C" fn fake_quiet(req: *const u8, len: usize) -> i32 {
        let bytes = unsafe { std::slice::from_raw_parts(req, len) }.to_vec();
        QUIET_LOG.lock().unwrap().push(bytes);
        0
    }
    unsafe extern "C" fn fake_call(
        req: *const u8,
        _len: usize,
        resp: *mut u8,
        cap: usize,
    ) -> isize {
        let payload = if req.is_null() {
            PENDING.lock().unwrap().take().expect("no stashed response")
        } else {
            RESPONSE.lock().unwrap().clone()
        };
        if payload.len() > cap {
            let n = payload.len() as isize;
            *PENDING.lock().unwrap() = Some(payload);
            return -n;
        }
        unsafe { std::ptr::copy_nonoverlapping(payload.as_ptr(), resp, payload.len()) };
        payload.len() as isize
    }
    unsafe extern "C" fn fake_drain() -> i32 {
        7 // pretend a quiet failure was collected
    }

    fn bridge() -> Bridge {
        Bridge {
            quiet: fake_quiet,
            call: fake_call,
            drain: fake_drain,
        }
    }

    /// io::Empty satisfies Client<S>'s bounds; a bridged client never touches it.
    fn client() -> Client<std::io::Cursor<Vec<u8>>> {
        Client::new_bridged(std::io::Cursor::new(Vec::new()), bridge())
    }

    #[test]
    fn bridged_deferred_ops_push_immediately() {
        QUIET_LOG.lock().unwrap().clear();
        let mut c = client();
        c.set_defer_enabled(true);
        c.mem_free(0xAB).unwrap();
        let log = QUIET_LOG.lock().unwrap();
        assert_eq!(log.len(), 1, "quiet op must reach the bridge at call time");
        assert_eq!(log[0], encode_request(&Request::MemFree { dptr: 0xAB }));
    }

    #[test]
    fn bridged_call_retries_oversized_response() {
        // Encoded Count response for DeviceGetCount, padded past the caller's
        // first 4 KiB buffer to force the stash-and-retry path.
        let mut resp = 0i32.to_le_bytes().to_vec(); // status 0
        resp.extend_from_slice(&3i32.to_le_bytes()); // count 3
        resp.resize(8192, 0);
        *RESPONSE.lock().unwrap() = resp;
        let mut c = client();
        assert_eq!(c.device_get_count().unwrap(), 3);
        assert!(PENDING.lock().unwrap().is_none(), "stash must be consumed");
    }

    #[test]
    fn bridged_drain_collects_sticky() {
        let mut c = client();
        c.drain().unwrap();
        assert_eq!(c.take_sticky(), 7);
    }

    #[test]
    fn raw_quiet_frames_like_call_deferred() {
        // Serving side: raw_quiet must produce the same wire framing as a
        // native deferred call, so bridged traffic is indistinguishable.
        let mut direct: Client<std::io::Cursor<Vec<u8>>> =
            Client::new(std::io::Cursor::new(Vec::new()));
        direct.set_defer_enabled(true);
        let payload = encode_request(&Request::MemFree { dptr: 0xCD });
        direct.raw_quiet(&payload).unwrap();
        let mut expect = ((payload.len() + 1) as u32).to_le_bytes().to_vec();
        expect.push(QUIET_PREFIX);
        expect.extend_from_slice(&payload);
        assert_eq!(direct.wbuf, expect);
    }
}
