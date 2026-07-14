//! Host-side CUDA-RPC server: dispatch decoded [`Request`]s to a [`Backend`].
//!
//! The dispatch layer ([`serve`]) owns opaque→raw handle tables for modules,
//! functions and contexts, so the guest only ever sees host-minted ids and
//! cannot forge a host pointer; an unknown id is rejected with
//! `CUDA_ERROR_INVALID_HANDLE`. Device pointers (`CUdeviceptr`) pass through by
//! value because kernel launch parameters embed them — exactly as the Driver
//! API works.
//!
//! Two backends ship: [`GpuBackend`] (the real driver via `nvcuda.dll` /
//! `libcuda.so.1`) and [`CpuBackend`] (emulates a known test kernel so the full
//! protocol + transport can be exercised on a host with no NVIDIA GPU).

use crate::proto::{decode_request, encode_response, read_msg, write_msg, Request, Response};
use std::collections::HashMap;
use std::io::{Read, Write};

/// `Ok(value)` or `Err(CUresult)` — a non-zero CUDA error code.
pub type CuResult<T> = Result<T, i32>;

/// `CUDA_ERROR_INVALID_HANDLE`.
pub const CUDA_ERROR_INVALID_HANDLE: i32 = 400;
/// Bit-63 marks a guest-minted virtual handle (see `raw_graph`, cublas vh).
const VHANDLE_TAG: u64 = 1 << 63;
/// `CUDA_ERROR_NOT_FOUND`.
pub const CUDA_ERROR_NOT_FOUND: i32 = 500;
pub const CUDA_ERROR_NOT_SUPPORTED: i32 = 801;

/// A CUDA Driver-API implementation. Handles returned here are the backend's
/// own raw values (e.g. real `CUmodule` pointers); [`serve`] hides them behind
/// opaque ids before they reach the guest.
pub trait Backend: Send {
    fn init(&mut self) -> CuResult<()>;
    /// Begin a session on this connection and return its lineage token (0 if
    /// the backend has no handoff support). `resume_token` is 0 for a fresh
    /// session, or a token from a prior `begin_session` whose (frozen) library
    /// handle map this connection should adopt — the mechanism a forked VM
    /// clone uses to keep its parent's cuBLAS/cuDNN descriptors valid.
    fn begin_session(&mut self, _resume_token: u64) -> u64 {
        0
    }
    fn device_get_count(&mut self) -> CuResult<i32>;
    fn device_get_name(&mut self, device: i32) -> CuResult<String>;
    fn device_total_mem(&mut self, device: i32) -> CuResult<u64>;
    fn driver_get_version(&mut self) -> CuResult<i32>;
    fn device_get_attribute(&mut self, attrib: i32, device: i32) -> CuResult<i32>;
    fn device_get_uuid(&mut self, device: i32) -> CuResult<[u8; 16]>;
    fn ctx_create(&mut self, device: i32) -> CuResult<u64>;
    fn ctx_destroy(&mut self, ctx: u64) -> CuResult<()>;
    fn primary_ctx_retain(&mut self, device: i32) -> CuResult<u64>;
    fn primary_ctx_release(&mut self, device: i32) -> CuResult<()>;
    fn module_load_data(&mut self, image: &[u8]) -> CuResult<u64>;
    fn module_get_function(&mut self, module: u64, name: &str) -> CuResult<u64>;
    fn module_unload(&mut self, module: u64) -> CuResult<()>;
    /// Per-parameter byte sizes of the kernel's arguments, in declaration order.
    fn func_get_param_info(&mut self, function: u64) -> CuResult<Vec<u32>>;
    /// Set a `CUfunction_attribute` (e.g. raise max dynamic shared memory).
    fn func_set_attribute(&mut self, function: u64, attrib: i32, value: i32) -> CuResult<()>;
    /// Read a `CUfunction_attribute`; default 0 (CPU backend has no kernels).
    fn func_get_attribute(&mut self, _function: u64, _attrib: i32) -> CuResult<i32> {
        Ok(0)
    }
    fn mem_alloc(&mut self, bytes: u64) -> CuResult<u64>;
    fn mem_free(&mut self, dptr: u64) -> CuResult<()>;
    /// Copy with stream ordering: prior work on `stream` (0 = legacy default)
    /// must complete first. Torch's pool streams are created non-blocking, so
    /// a NULL-stream copy does NOT order against them — dropping `stream`
    /// makes a `cudaMemcpyAsync` overwrite buffers still-running kernels read.
    fn memcpy_htod(&mut self, dptr: u64, data: &[u8], stream: u64) -> CuResult<()>;
    /// See `memcpy_htod` for the `stream` contract.
    fn memcpy_dtoh(&mut self, dptr: u64, bytes: u64, stream: u64) -> CuResult<Vec<u8>>;
    fn memcpy_dtod(&mut self, dst: u64, src: u64, bytes: u64) -> CuResult<()>;
    fn memset_d8(&mut self, dptr: u64, value: u8, bytes: u64) -> CuResult<()>;
    fn mem_get_info(&mut self) -> CuResult<(u64, u64)>;
    fn launch_kernel(
        &mut self,
        function: u64,
        grid: [u32; 3],
        block: [u32; 3],
        shared_bytes: u32,
        stream: u64,
        params: &[Vec<u8>],
    ) -> CuResult<()>;
    fn ctx_synchronize(&mut self) -> CuResult<()>;
    fn stream_create(&mut self, flags: u32) -> CuResult<u64>;
    /// Begin capturing `stream`'s work into a CUDA graph (mode per
    /// `cudaStreamCaptureMode`).
    fn stream_begin_capture(&mut self, stream: u64, mode: i32) -> CuResult<()>;
    /// Exchange this (serving) thread's capture interaction mode; returns the
    /// previous mode. Lets a guest run capture-unsafe calls (allocator growth)
    /// under `cudaStreamCaptureModeRelaxed` exactly like PyTorch does natively.
    fn thread_exchange_capture_mode(&mut self, mode: i32) -> CuResult<i32>;
    /// Raw `cuStreamQuery` code as a value (0 complete, 600 not ready) — not
    /// an error, so it rides the response body.
    fn stream_query(&mut self, stream: u64) -> CuResult<i32>;
    /// `cuStreamWaitEvent`: make `stream` wait for `event`.
    fn stream_wait_event(&mut self, stream: u64, event: u64, flags: u32) -> CuResult<()>;
    /// Raw `cuEventQuery` code as a value (0 complete, 600 not ready).
    fn event_query(&mut self, event: u64) -> CuResult<i32>;
    /// End capture; returns the raw `cudaGraph_t`.
    fn stream_end_capture(&mut self, stream: u64) -> CuResult<u64>;
    /// `(capture_status, capture_id)` for `stream`.
    fn stream_capture_info(&mut self, stream: u64) -> CuResult<(u64, u64)>;
    /// Instantiate a captured graph; returns the raw `cudaGraphExec_t`.
    fn graph_instantiate(&mut self, graph: u64) -> CuResult<u64>;
    /// Replay an instantiated graph on `stream`.
    fn graph_launch(&mut self, graph_exec: u64, stream: u64) -> CuResult<()>;
    /// Rewrite `exec`'s node params so device pointers baked in at capture are
    /// translated through `trans` to a fork clone's private copies (Path 2).
    /// Default: no-op (a backend without graph support has nothing to patch).
    fn graph_exec_patch(
        &mut self,
        _exec: u64,
        _graph: u64,
        _trans: &[(u64, u64, u64)],
    ) -> CuResult<()> {
        Ok(())
    }
    fn graph_exec_destroy(&mut self, graph_exec: u64) -> CuResult<()>;
    fn graph_destroy(&mut self, graph: u64) -> CuResult<()>;
    /// Number of nodes in a captured graph (PyTorch warns on empty graphs).
    fn graph_get_node_count(&mut self, graph: u64) -> CuResult<u64>;
    /// Stream-ordered memset (capture-safe; the sync form would invalidate an
    /// active capture).
    fn memset_d8_async(&mut self, dptr: u64, value: u8, bytes: u64, stream: u64) -> CuResult<()>;
    /// Stream-ordered device-to-device copy (capture-safe).
    fn memcpy_dtod_async(&mut self, dst: u64, src: u64, bytes: u64, stream: u64) -> CuResult<()>;
    fn stream_destroy(&mut self, stream: u64) -> CuResult<()>;
    fn stream_synchronize(&mut self, stream: u64) -> CuResult<()>;
    fn event_create(&mut self, flags: u32) -> CuResult<u64>;
    fn event_destroy(&mut self, event: u64) -> CuResult<()>;
    fn event_record(&mut self, event: u64, stream: u64) -> CuResult<()>;
    fn event_synchronize(&mut self, event: u64) -> CuResult<()>;
    fn event_elapsed_time(&mut self, start: u64, end: u64) -> CuResult<f32>;

    // ---- forward-to-host-lib: nvcomp batched Deflate ----
    // Return the library's own `nvcompStatus_t` (0 = success) rather than a
    // CUresult; the transport status stays 0 and the shim surfaces this verbatim.
    /// `(nvcomp_status, temp_bytes)`.
    fn nvcomp_deflate_temp_size(
        &mut self,
        num_chunks: u64,
        max_uncompressed_chunk_bytes: u64,
        max_total_uncompressed_bytes: u64,
    ) -> CuResult<(i32, u64)>;
    #[allow(clippy::too_many_arguments)]
    fn nvcomp_deflate_decompress(
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
    ) -> CuResult<i32>;

    // ---- forward-to-host-lib: cuBLAS ----
    /// Returns the backend's raw `cublasHandle_t`.
    fn cublas_create(&mut self) -> CuResult<u64>;
    fn cublas_destroy(&mut self, handle: u64) -> CuResult<()>;
    fn cublas_set_stream(&mut self, handle: u64, stream: u64) -> CuResult<()>;
    #[allow(clippy::too_many_arguments)]
    fn cublas_sgemm(
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
    ) -> CuResult<()>;

    /// Generic forward-to-host-lib dispatch (code-generated per function).
    /// `streams` is the session's stream table (wire id → raw host stream) for
    /// resolving `cudaStream_t` parameters. Returns `(library_status,
    /// serialized_outputs)`. Default: unsupported.
    fn lib_call(
        &mut self,
        _lib: u8,
        _func: u16,
        _args: &[u8],
        _streams: &HashMap<u64, u64>,
    ) -> CuResult<(i32, Vec<u8>)> {
        Err(CUDA_ERROR_NOT_FOUND)
    }

    /// Zero-copy H2D: DMA `size` bytes from shared-region `offset` to `dptr`.
    /// Default: no shared region → caller must fall back to byte-shipping.
    fn memcpy_shm_htod(
        &mut self,
        _dptr: u64,
        _offset: u64,
        _size: u64,
        _stream: u64,
    ) -> CuResult<()> {
        Err(CUDA_ERROR_NOT_FOUND)
    }
    /// Zero-copy D2H: DMA `size` bytes from `dptr` to shared-region `offset`.
    fn memcpy_shm_dtoh(
        &mut self,
        _offset: u64,
        _dptr: u64,
        _size: u64,
        _stream: u64,
    ) -> CuResult<()> {
        Err(CUDA_ERROR_NOT_FOUND)
    }

    /// Provide the host mappings of guest RAM (`gpa_start, host_va, len` triples)
    /// so `memcpy_gpa_*` can read guest memory directly. Set once per connection
    /// by the embedder. Guest RAM is usually split around the 4 GiB PCI hole.
    fn set_guest_ram(&mut self, _regions: Vec<(u64, u64, u64)>) {}
    /// Zero-copy H2D from guest RAM: gather `segments` and DMA to `dptr`.
    fn memcpy_gpa_htod(
        &mut self,
        _dptr: u64,
        _segments: &[(u64, u64)],
        _stream: u64,
    ) -> CuResult<()> {
        Err(CUDA_ERROR_NOT_FOUND)
    }
    /// Zero-copy D2H to guest RAM: DMA from `dptr` and scatter into `segments`.
    fn memcpy_gpa_dtoh(
        &mut self,
        _dptr: u64,
        _segments: &[(u64, u64)],
        _stream: u64,
    ) -> CuResult<()> {
        Err(CUDA_ERROR_NOT_FOUND)
    }
    /// Host virtual address of `len` bytes at guest-physical `gpa`, when the
    /// embedder mapped guest RAM (in-VM only). Rings need long-lived page
    /// mappings, unlike the per-call `memcpy_gpa_*` segment reads.
    fn gpa_to_hva(&mut self, _gpa: u64, _len: u64) -> Option<u64> {
        None
    }
    // VMM (torch expandable-segments allocator). Defaults: unsupported.
    fn mem_address_reserve(&mut self, _size: u64, _align: u64) -> CuResult<u64> {
        Err(CUDA_ERROR_NOT_SUPPORTED)
    }
    fn mem_create(&mut self, _size: u64, _device: i32) -> CuResult<u64> {
        Err(CUDA_ERROR_NOT_SUPPORTED)
    }
    fn mem_map(&mut self, _va: u64, _size: u64, _offset: u64, _handle: u64) -> CuResult<()> {
        Err(CUDA_ERROR_NOT_SUPPORTED)
    }
    fn mem_set_access(&mut self, _va: u64, _size: u64, _device: i32) -> CuResult<()> {
        Err(CUDA_ERROR_NOT_SUPPORTED)
    }
    fn mem_unmap(&mut self, _va: u64, _size: u64) -> CuResult<()> {
        Err(CUDA_ERROR_NOT_SUPPORTED)
    }
    fn mem_release(&mut self, _handle: u64) -> CuResult<()> {
        Err(CUDA_ERROR_NOT_SUPPORTED)
    }
    fn mem_address_free(&mut self, _va: u64, _size: u64) -> CuResult<()> {
        Err(CUDA_ERROR_NOT_SUPPORTED)
    }
    fn mem_get_allocation_granularity(&mut self, _device: i32, _flags: u32) -> CuResult<u64> {
        Err(CUDA_ERROR_NOT_SUPPORTED)
    }
    // Path 3 address-preserving isolation primitives. Defaults: unsupported.
    fn mem_address_reserve_fixed(&mut self, _size: u64, _align: u64, _fixed: u64) -> CuResult<u64> {
        Err(CUDA_ERROR_NOT_SUPPORTED)
    }
    fn mem_create_exportable(&mut self, _size: u64, _device: i32) -> CuResult<u64> {
        Err(CUDA_ERROR_NOT_SUPPORTED)
    }
    fn mem_export_handle(&mut self, _handle: u64) -> CuResult<i32> {
        Err(CUDA_ERROR_NOT_SUPPORTED)
    }
    fn mem_import_handle(&mut self, _fd: i32) -> CuResult<u64> {
        Err(CUDA_ERROR_NOT_SUPPORTED)
    }
}

/// Per-connection opaque→raw handle translation. Ids are dense and monotonic so
/// a stale/forged id from the guest never aliases a live resource.
#[derive(Default)]
struct Session {
    next_id: u64,
    modules: HashMap<u64, u64>,
    functions: HashMap<u64, u64>,
    contexts: HashMap<u64, u64>,
    streams: HashMap<u64, u64>,
    events: HashMap<u64, u64>,
    cublas_handles: HashMap<u64, u64>,
    /// Guest-minted virtual graph/exec handles → real (bit-63 tagged). Lets
    /// EndCapture / GraphInstantiate be fire-and-forget: the guest invents the
    /// handle, the host maps it when it materializes the real one. Shared via
    /// [`GRAPH_HANDOFF`] so a fork clone inherits a snapshot of its parent's
    /// captured graphs (the reals are context-scoped, valid across connections).
    graph_vhandles: std::sync::Arc<std::sync::Mutex<HashMap<u64, u64>>>,
    /// Real graph/exec handles THIS session created (not inherited). Only these
    /// are destroyed on reclaim — mirrors `owned_modules`, so a clone dropping
    /// never frees a graph its (still-live) parent handed it.
    owned_graph_reals: std::collections::HashSet<u64>,
    /// Live resources this connection created, reclaimed when it ends —
    /// a guest that dies mid-run must not leak GPU memory (device
    /// allocations are the multi-GB hazard; modules/streams/events are
    /// hygiene). Raw backend handles.
    owned_dptrs: HashMap<u64, u64>, // dptr → size (also the quota ledger)
    /// VMM state for reclaim: physical handles → size (quota ledger too),
    /// live mappings (va → size), and address reservations (va → size).
    owned_vmm_handles: HashMap<u64, u64>,
    owned_vmm_maps: HashMap<u64, u64>,
    owned_vmm_reservations: HashMap<u64, u64>,
    owned_modules: std::collections::HashSet<u64>,
    owned_streams: std::collections::HashSet<u64>,
    owned_events: std::collections::HashSet<u64>,
    primary_retains: u32,
    /// This session's live device allocations (dptr → size), shared via
    /// [`DPTR_HANDOFF`] so a fork clone in isolation mode can enumerate the
    /// parent's buffers and give itself private copies. Mirrors `owned_dptrs`.
    alloc_table: std::sync::Arc<std::sync::Mutex<HashMap<u64, (u64, bool)>>>,
    /// This session's live VMM-mapped ranges (mapped-va → size), shared via
    /// [`VMM_HANDOFF`] so a fork clone copies them privately. Torch's default
    /// `expandable_segments` allocator serves the whole pool from VMM
    /// (`cuMemCreate`/`cuMemMap`), whose memory never lands in `alloc_table` —
    /// without this the fork misses the entire model (0 copies). Always copied,
    /// never shared: an expandable segment mixes weights and activations, so it
    /// can't be shared read-only like a discrete weight buffer.
    vmm_ranges: std::sync::Arc<VmmRanges>,
    /// Fork-isolation pointer map: `(parent_base, size, private_copy_base)`.
    /// Empty unless this session is an isolating clone. Every inherited dptr the
    /// guest sends is rewritten through these ranges to the clone's own copy, so
    /// two clones of one golden write disjoint VRAM instead of colliding.
    dptr_trans: Vec<(u64, u64, u64)>,
    /// Parent lineage token whose allocations must be copied privately on the
    /// first `PrimaryCtxRetain` (when a context is finally current). 0 = none.
    pending_isolate: u64,
    /// Inherited read-only (weight) buffers this isolating clone SHARES with its
    /// parent: `(base, size)`. Shared until the clone writes one, at which point
    /// it's copied-on-write into `dptr_trans` and dropped from here. Lets clones
    /// share gigabytes of weights while still isolating anything they mutate.
    shared_ranges: Vec<(u64, u64)>,
    /// Per-clone patched graph execs: inherited exec (real) → this clone's own
    /// exec (real) with node pointers translated to its private copies. Freed via
    /// `owned_graph_reals` on teardown. Empty for non-isolating sessions.
    clone_graph_execs: HashMap<u64, u64>,
}

/// Free everything a finished connection still owns. Failures are ignored —
/// the driver may already have reclaimed (context destruction, device reset).
fn reclaim_session(sess: &mut Session, b: &mut dyn Backend) {
    for (d, _size) in std::mem::take(&mut sess.owned_dptrs) {
        let _ = b.mem_free(d);
    }
    // VMM teardown order: unmap, release physical, free reservations.
    for (va, size) in std::mem::take(&mut sess.owned_vmm_maps) {
        let _ = b.mem_unmap(va, size);
    }
    for (h, _size) in std::mem::take(&mut sess.owned_vmm_handles) {
        let _ = b.mem_release(h);
    }
    for (va, size) in std::mem::take(&mut sess.owned_vmm_reservations) {
        let _ = b.mem_address_free(va, size);
    }
    for m in std::mem::take(&mut sess.owned_modules) {
        let _ = b.module_unload(m);
    }
    for st in std::mem::take(&mut sess.owned_streams) {
        let _ = b.stream_destroy(st);
    }
    for e in std::mem::take(&mut sess.owned_events) {
        let _ = b.event_destroy(e);
    }
    for real in std::mem::take(&mut sess.owned_graph_reals) {
        // Only reals this session created — never a graph inherited from a
        // still-live parent (those stay in the shared map, owned by the parent).
        // Exec vs graph is unknown here; try exec destroy first, then graph
        // destroy — the wrong one errors harmlessly.
        let _ = b
            .graph_exec_destroy(real)
            .or_else(|_| b.graph_destroy(real));
    }
    for _ in 0..std::mem::take(&mut sess.primary_retains) {
        let _ = b.primary_ctx_release(0);
    }
}

impl Session {
    fn mint(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }
}

/// Registry of live sessions' `graph_vhandles` maps, keyed by the lineage token
/// [`Backend::begin_session`] returns. `Weak` refs so a session's entry
/// evaporates when its connection closes. Parallels the cuBLAS `HANDOFF` in
/// `host::gpu`, but lives here because graph vhandles are session state (the
/// generic dispatch owns them, not the concrete GPU backend). A fork clone
/// resuming a parent token adopts a snapshot of the parent's captured graphs.
type GraphVhMap = std::sync::Mutex<HashMap<u64, u64>>;
static GRAPH_HANDOFF: std::sync::Mutex<Option<HashMap<u64, std::sync::Weak<GraphVhMap>>>> =
    std::sync::Mutex::new(None);

/// Maps an instantiated graph exec (real handle) → its source graph template
/// (real handle). Populated at GraphInstantiate; lets an isolating fork clone
/// re-instantiate + patch an inherited exec (Path 2 graph-mode isolation).
/// Real handles are context-global, so one process-wide map serves all sessions.
static EXEC_TEMPLATES: std::sync::Mutex<Option<HashMap<u64, u64>>> = std::sync::Mutex::new(None);

fn exec_template_register(exec: u64, graph: u64) {
    EXEC_TEMPLATES
        .lock()
        .unwrap()
        .get_or_insert_with(HashMap::new)
        .insert(exec, graph);
}

fn exec_template_lookup(exec: u64) -> Option<u64> {
    EXEC_TEMPLATES.lock().unwrap().as_ref()?.get(&exec).copied()
}

/// Graph templates an isolating clone may need to re-instantiate. PyTorch/vLLM
/// destroy the cuGraph right after instantiating its exec, so we keep templates
/// alive (leaking them — acceptable on the opt-in isolation path) so a clone can
/// re-instantiate + patch them later.
static TEMPLATE_GRAPHS: std::sync::Mutex<Option<std::collections::HashSet<u64>>> =
    std::sync::Mutex::new(None);

fn template_graph_mark(graph: u64) {
    TEMPLATE_GRAPHS
        .lock()
        .unwrap()
        .get_or_insert_with(std::collections::HashSet::new)
        .insert(graph);
}

fn template_graph_is(graph: u64) -> bool {
    TEMPLATE_GRAPHS
        .lock()
        .unwrap()
        .as_ref()
        .is_some_and(|s| s.contains(&graph))
}

/// Copy `resume_token`'s captured-graph map into `dst`, then register `dst`
/// under `my_token` (the same token the backend minted for cuBLAS handoff, so
/// both handle families share one lineage). The reals are context-scoped host
/// handles valid in the shared primary context, so copying vh→real is enough.
fn graph_handoff_register(dst: &std::sync::Arc<GraphVhMap>, resume_token: u64, my_token: u64) {
    let mut reg = GRAPH_HANDOFF.lock().unwrap();
    let reg = reg.get_or_insert_with(HashMap::new);
    if resume_token != 0 {
        if let Some(parent) = reg.get(&resume_token).and_then(|w| w.upgrade()) {
            *dst.lock().unwrap() = parent.lock().unwrap().clone();
        }
    }
    reg.retain(|_, w| w.strong_count() > 0);
    reg.insert(my_token, std::sync::Arc::downgrade(dst));
}

/// Opt-in (`SMOLVM_CUDA_FORK_ISOLATE=1`): fork clones get PRIVATE copies of the
/// golden's device memory instead of sharing it. Independent serving (two clones
/// running different requests) needs this; the default shared-memory fork is for
/// "resume the golden's exact work" (checkpoint/continue), which this would break.
fn fork_isolate_enabled() -> bool {
    std::env::var_os("SMOLVM_CUDA_FORK_ISOLATE").is_some()
}

/// P0 transport-viability instrumentation. Counts every dispatched CUDA RPC so we
/// can derive calls-per-token (the number that decides whether CUDA-over-network
/// survives WAN round-trips). `SMOLVM_CUDA_RPC_STATS=1` logs the running count with
/// a wall-clock stamp every 2000 calls; `SMOLVM_CUDA_RPC_DELAY_US=<n>` injects `n`
/// microseconds of latency per call to model network RTT. Both cached so a normal
/// run pays only one relaxed atomic add.
static RPC_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// Subset of RPCs that actually block the client on a reply (non-quiet responses +
/// fences). This — not the raw RPC count — is what a network RTT multiplies, since
/// quiet/fire-and-forget requests pipeline.
static ROUNDTRIP_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
fn rpc_stats_enabled() -> bool {
    static S: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *S.get_or_init(|| std::env::var_os("SMOLVM_CUDA_RPC_STATS").is_some())
}
fn rpc_delay_us() -> u64 {
    static D: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *D.get_or_init(|| {
        std::env::var("SMOLVM_CUDA_RPC_DELAY_US")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    })
}
/// Models network round-trip time: `SMOLVM_CUDA_RTT_US` microseconds of latency
/// added at each BLOCKING round-trip (fence / non-quiet response) only — quiet
/// fire-and-forget requests are untouched, exactly as a real network would leave
/// pipelined sends overlapped. Lets us confirm the P0 latency model on a live
/// workload over the existing transport, without netem.
fn rtt_us() -> u64 {
    static R: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *R.get_or_init(|| {
        std::env::var("SMOLVM_CUDA_RTT_US")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    })
}

/// Let an isolating clone launch an INHERITED cudagraph by re-instantiating it and
/// translating its node pointers to the clone's private copies (Path 2). ON by
/// default: `graph_exec_patch` now translates device pointers embedded in by-value
/// kernel-arg structs (vLLM's attention/sampling kernels), not just standalone
/// 8-byte args, so graph-mode isolation is correct (verified: opt-350m, shared
/// weights, two concurrent clones on different prompts, all token-exact). Opt out
/// with `SMOLVM_CUDA_FORK_GRAPH_PATCH=0` to fall back to fail-loud (e.g. to bisect a
/// suspected regression).
fn graph_patch_enabled() -> bool {
    !matches!(
        std::env::var("SMOLVM_CUDA_FORK_GRAPH_PATCH").as_deref(),
        Ok("0")
    )
}

/// Diagnostic: patch the golden's exec IN PLACE instead of re-instantiating, to
/// tell whether the re-instantiation or the patching is what breaks graph mode.
/// Single-clone only (mutates the shared exec).
fn graph_inplace_enabled() -> bool {
    std::env::var_os("SMOLVM_CUDA_GRAPH_INPLACE").is_some()
}

/// Registry of live sessions' allocation tables, keyed by lineage token, so an
/// isolating clone can enumerate its parent's device buffers to copy them.
/// `Weak` so a session's entry evaporates when its connection closes. Parallels
/// [`GRAPH_HANDOFF`].
/// dptr → (size, loaded). `loaded` = written via a host-to-device copy, i.e. a
/// weight/constant streamed in at load time. Such buffers are read-only during
/// inference, so clones SHARE them (M4) instead of each copying gigabytes of
/// weights; only the un-loaded buffers (KV cache, activations) get private copies.
type AllocTable = std::sync::Mutex<HashMap<u64, (u64, bool)>>;
/// VMM-mapped ranges (mapped-va → size), handed off to fork clones. Parallels
/// [`AllocTable`] but for the CUDA VMM path (see [`Session::vmm_ranges`]).
type VmmRanges = std::sync::Mutex<HashMap<u64, u64>>;
static DPTR_HANDOFF: std::sync::Mutex<Option<HashMap<u64, std::sync::Weak<AllocTable>>>> =
    std::sync::Mutex::new(None);

fn dptr_handoff_register(table: &std::sync::Arc<AllocTable>, my_token: u64) {
    let mut reg = DPTR_HANDOFF.lock().unwrap();
    let reg = reg.get_or_insert_with(HashMap::new);
    reg.retain(|_, w| w.strong_count() > 0);
    reg.insert(my_token, std::sync::Arc::downgrade(table));
}

/// Snapshot of `token`'s current `(dptr, size, loaded)` allocations, or `None`
/// if that lineage is gone.
fn dptr_handoff_snapshot(token: u64) -> Option<Vec<(u64, u64, bool)>> {
    let reg = DPTR_HANDOFF.lock().unwrap();
    if std::env::var_os("SMOLVM_CUDA_FORK_DEBUG").is_some() {
        // Show which tokens hold how many live allocations — reveals whether the
        // weight-bearing session's token differs from the one the clone resumes.
        let dump: Vec<(u64, usize)> = reg
            .as_ref()
            .map(|m| {
                m.iter()
                    .map(|(&t, w)| (t, w.upgrade().map(|a| a.lock().unwrap().len()).unwrap_or(0)))
                    .collect()
            })
            .unwrap_or_default();
        eprintln!("[fork-debug] snapshot(token={token}) registry tokens->allocs = {dump:?}");
    }
    let table = reg.as_ref()?.get(&token)?.upgrade()?;
    let snap = table
        .lock()
        .unwrap()
        .iter()
        .map(|(&d, &(s, l))| (d, s, l))
        .collect();
    Some(snap)
}

/// Registry of live sessions' VMM-mapped ranges, keyed by lineage token — the
/// VMM counterpart of [`DPTR_HANDOFF`]. Torch/Unsloth `expandable_segments`
/// memory lives here (never in `alloc_table`), so a fork clone must copy these
/// too or it inherits the golden's raw VMM addresses untranslated.
static VMM_HANDOFF: std::sync::Mutex<Option<HashMap<u64, std::sync::Weak<VmmRanges>>>> =
    std::sync::Mutex::new(None);

fn vmm_handoff_register(ranges: &std::sync::Arc<VmmRanges>, my_token: u64) {
    let mut reg = VMM_HANDOFF.lock().unwrap();
    let reg = reg.get_or_insert_with(HashMap::new);
    reg.retain(|_, w| w.strong_count() > 0);
    reg.insert(my_token, std::sync::Arc::downgrade(ranges));
}

/// Snapshot of `token`'s VMM-mapped `(va, size)` ranges, or `None` if gone.
fn vmm_handoff_snapshot(token: u64) -> Option<Vec<(u64, u64)>> {
    let reg = VMM_HANDOFF.lock().unwrap();
    let ranges = reg.as_ref()?.get(&token)?.upgrade()?;
    let snap = ranges
        .lock()
        .unwrap()
        .iter()
        .map(|(&v, &s)| (v, s))
        .collect();
    Some(snap)
}

/// Mark the allocation containing `dptr` as loaded (H2D-written → read-only
/// weight). Called on every host-to-device copy on the golden.
fn mark_loaded(table: &AllocTable, dptr: u64) {
    let mut t = table.lock().unwrap();
    if let Some(v) = t.get_mut(&dptr) {
        v.1 = true;
        return;
    }
    for (&base, v) in t.iter_mut() {
        if dptr >= base && dptr < base + v.0 {
            v.1 = true;
            return;
        }
    }
}

/// Copy-on-write a shared (inherited read-only) buffer that this clone is about
/// to WRITE, so the write hits a private copy instead of the parent's buffer.
/// Moves it from `shared_ranges` into `dptr_trans`. No-op if `dptr` isn't shared.
fn cow_one(sess: &mut Session, b: &mut dyn Backend, dptr: u64) {
    let Some(i) = sess
        .shared_ranges
        .iter()
        .position(|&(base, size)| dptr >= base && dptr < base + size)
    else {
        return;
    };
    let (base, size) = sess.shared_ranges.swap_remove(i);
    if let Ok(cdptr) = b.mem_alloc(size) {
        let _ = b.memcpy_dtod(cdptr, base, size);
        sess.dptr_trans.push((base, size, cdptr));
        sess.owned_dptrs.insert(cdptr, size);
        sess.alloc_table
            .lock()
            .unwrap()
            .insert(cdptr, (size, false));
        gpu::set_lib_trans(&sess.dptr_trans); // keep the cuBLAS/cuDNN map current
    }
}

/// COW any shared buffer this request WRITES (host-to-device copies, memset,
/// device-to-device destination). Kernel outputs are undetectable, but the only
/// shared buffers are H2D-loaded weights, which kernels only read.
fn cow_written(sess: &mut Session, b: &mut dyn Backend, req: &Request) {
    if sess.shared_ranges.is_empty() {
        return;
    }
    match req {
        Request::MemcpyHtoD { dptr, .. }
        | Request::MemsetD8 { dptr, .. }
        | Request::MemsetD8Async { dptr, .. }
        | Request::MemcpyShmHtoD { dptr, .. }
        | Request::MemcpyGpaHtoD { dptr, .. } => cow_one(sess, b, *dptr),
        Request::MemcpyDtoD { dst, .. } | Request::MemcpyDtoDAsync { dst, .. } => {
            cow_one(sess, b, *dst)
        }
        _ => {}
    }
}

/// Rewrite a guest device pointer through the clone's private-copy ranges. A
/// pointer inside an inherited allocation `[base, base+size)` maps to the same
/// offset in the clone's copy; everything else (fresh post-fork allocations,
/// non-isolating sessions) passes through untouched.
fn xlat(trans: &[(u64, u64, u64)], p: u64) -> u64 {
    if p == 0 {
        return 0;
    }
    for &(base, size, copy) in trans {
        if p >= base && p < base + size {
            return copy + (p - base);
        }
    }
    p
}

/// Rewrite every inherited device pointer in a memory-op request to the clone's
/// private copy. No-op when `trans` is empty (the common, non-isolating path).
fn translate_dptrs(trans: &[(u64, u64, u64)], req: Request) -> Request {
    if trans.is_empty() {
        return req;
    }
    match req {
        Request::MemcpyHtoD { dptr, stream, data } => Request::MemcpyHtoD {
            dptr: xlat(trans, dptr),
            stream,
            data,
        },
        Request::MemcpyDtoH {
            dptr,
            bytes,
            stream,
        } => Request::MemcpyDtoH {
            dptr: xlat(trans, dptr),
            bytes,
            stream,
        },
        Request::MemcpyDtoD { dst, src, bytes } => Request::MemcpyDtoD {
            dst: xlat(trans, dst),
            src: xlat(trans, src),
            bytes,
        },
        Request::MemcpyDtoDAsync {
            dst,
            src,
            bytes,
            stream,
        } => Request::MemcpyDtoDAsync {
            dst: xlat(trans, dst),
            src: xlat(trans, src),
            bytes,
            stream,
        },
        Request::MemsetD8 { dptr, value, bytes } => Request::MemsetD8 {
            dptr: xlat(trans, dptr),
            value,
            bytes,
        },
        Request::MemsetD8Async {
            dptr,
            value,
            bytes,
            stream,
        } => Request::MemsetD8Async {
            dptr: xlat(trans, dptr),
            value,
            bytes,
            stream,
        },
        Request::MemcpyShmHtoD {
            dptr,
            offset,
            size,
            stream,
        } => Request::MemcpyShmHtoD {
            dptr: xlat(trans, dptr),
            offset,
            size,
            stream,
        },
        Request::MemcpyShmDtoH {
            offset,
            dptr,
            size,
            stream,
        } => Request::MemcpyShmDtoH {
            offset,
            dptr: xlat(trans, dptr),
            size,
            stream,
        },
        Request::MemcpyGpaHtoD {
            dptr,
            segments,
            stream,
        } => Request::MemcpyGpaHtoD {
            dptr: xlat(trans, dptr),
            segments,
            stream,
        },
        Request::MemcpyGpaDtoH {
            dptr,
            segments,
            stream,
        } => Request::MemcpyGpaDtoH {
            dptr: xlat(trans, dptr),
            segments,
            stream,
        },
        Request::MemFree { dptr } => Request::MemFree {
            dptr: xlat(trans, dptr),
        },
        Request::LaunchKernel {
            function,
            grid,
            block,
            shared_bytes,
            stream,
            mut params,
        } => {
            // A kernel's pointer arguments are device addresses embedded in the
            // per-arg byte buffers. CUDA doesn't tell us which args are pointers,
            // so scan each arg's 8-byte-aligned windows and remap any value that
            // lands inside an inherited allocation. Each arg is its own buffer, so
            // a standalone pointer arg is a clean 8-byte read; non-pointer scalars
            // essentially never fall inside a live device-address range.
            for p in params.iter_mut() {
                let mut off = 0;
                while off + 8 <= p.len() {
                    let v = u64::from_le_bytes(p[off..off + 8].try_into().unwrap());
                    let t = xlat(trans, v);
                    if t != v {
                        p[off..off + 8].copy_from_slice(&t.to_le_bytes());
                    }
                    off += 8;
                }
            }
            Request::LaunchKernel {
                function,
                grid,
                block,
                shared_bytes,
                stream,
                params,
            }
        }
        Request::CublasSgemm {
            handle,
            transa,
            transb,
            m,
            n,
            k,
            alpha_bits,
            a,
            lda,
            b,
            ldb,
            beta_bits,
            c,
            ldc,
        } => Request::CublasSgemm {
            handle,
            transa,
            transb,
            m,
            n,
            k,
            alpha_bits,
            a: xlat(trans, a),
            lda,
            b: xlat(trans, b),
            ldb,
            beta_bits,
            c: xlat(trans, c),
            ldc,
        },
        // LibCall (cuBLAS/cuDNN) device-pointer args are translated TYPED in the
        // generated dispatch via `gpu::dptr_resolve` (a byte-scan of the packed,
        // mixed-width arg buffer would mis-align and corrupt scalars), driven by
        // the thread-local map that `dispatch` keeps in sync — see `set_lib_trans`.
        other => other,
    }
}

/// Serve one CUDA-RPC connection to completion (until the peer closes). Each
/// request is dispatched to `backend`; returns on clean EOF.
pub fn serve<S: Read + Write>(stream: S, backend: &mut dyn Backend) -> std::io::Result<()> {
    let mut sess = Session::default();
    let r = serve_inner(stream, backend, &mut sess);
    // The connection is over (guest exit, crash, or transport error): free
    // everything it still owns so a dead client can't hold GPU memory.
    reclaim_session(&mut sess, backend);
    r
}

fn serve_inner<S: Read + Write>(
    mut stream: S,
    backend: &mut dyn Backend,
    sess: &mut Session,
) -> std::io::Result<()> {
    // First failure among quiet (fire-and-forget) requests since the last
    // fence. Quiet requests get no response at all — the client collects
    // failures with one Fence round-trip instead of reading N per-op replies,
    // which on vsock cost a guest wake-up each.
    let mut quiet_sticky: i32 = 0;
    while let Some(payload) = read_msg(&mut stream)? {
        match payload.first() {
            // Quiet wrapper: execute the inner request, reply with nothing.
            Some(&crate::proto::QUIET_PREFIX) => {
                let req = decode_request(&payload[1..])?;
                if std::env::var_os("SMOLVM_CUDA_HOST_OPLOG").is_some() {
                    eprintln!("[op~] 0x{:02x} len={}", payload[1], payload.len());
                }
                let (status, _) = dispatch(sess, backend, req);
                if status != 0 && std::env::var_os("SMOLVM_CUDA_HOST_OPLOG").is_some() {
                    eprintln!("[op~!] status={status}");
                }
                if status != 0 && quiet_sticky == 0 {
                    quiet_sticky = status;
                }
            }
            // Fence: report (and clear) the sticky quiet failure.
            Some(&crate::proto::FENCE_OP) if payload.len() == 1 => {
                ROUNDTRIP_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let rtt = rtt_us();
                if rtt > 0 {
                    std::thread::sleep(std::time::Duration::from_micros(rtt));
                }
                let st = std::mem::take(&mut quiet_sticky);
                write_msg(&mut stream, &encode_response(st, &Response::Ok))?;
            }
            _ => {
                let req = decode_request(&payload)?;
                if std::env::var_os("SMOLVM_CUDA_HOST_OPLOG").is_some() {
                    eprintln!("[op] 0x{:02x} len={}", payload[0], payload.len());
                }
                // Transport upgrade: switch this connection to shared-memory
                // rings and never return to socket framing (the socket then
                // carries only doorbell bytes).
                if let Request::RingSetup {
                    page_size,
                    req_pages,
                    resp_pages,
                    bounce_pages,
                } = req
                {
                    match HostRings::map(backend, page_size, &req_pages, &resp_pages, &bounce_pages)
                    {
                        Ok(rings) => {
                            write_msg(&mut stream, &encode_response(0, &Response::Ok))?;
                            return serve_rings(stream, backend, sess, quiet_sticky, rings);
                            // (session reclaimed by `serve` on return)
                        }
                        Err(code) => {
                            write_msg(&mut stream, &encode_response(code, &Response::Ok))?;
                            continue;
                        }
                    }
                }
                ROUNDTRIP_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let rtt = rtt_us();
                if rtt > 0 {
                    std::thread::sleep(std::time::Duration::from_micros(rtt));
                }
                let (status, resp) = dispatch(sess, backend, req);
                if status != 0 && std::env::var_os("SMOLVM_CUDA_HOST_OPLOG").is_some() {
                    eprintln!("[op!] status={status}");
                }
                let out = encode_response(status, &resp);
                write_msg(&mut stream, &out)?;
            }
        }
    }
    Ok(())
}

/// Host mappings of the guest's rings + bounce buffer.
struct HostRings {
    req: crate::ring::Ring,
    resp: crate::ring::Ring,
    /// Bounce pages (host VAs) for responses too large for an inline record.
    bounce: Vec<*mut u8>,
    page_size: usize,
}

impl HostRings {
    fn map(
        backend: &mut dyn Backend,
        page_size: u32,
        req_pages: &[u64],
        resp_pages: &[u64],
        bounce_pages: &[u64],
    ) -> Result<HostRings, i32> {
        let ps = page_size as usize;
        if ps < crate::ring::HEADER_SIZE + crate::ring::RECORD_SIZE
            || req_pages.is_empty()
            || resp_pages.is_empty()
        {
            return Err(1); // CUDA_ERROR_INVALID_VALUE
        }
        let mut map_all = |gpas: &[u64]| -> Result<Vec<*mut u8>, i32> {
            gpas.iter()
                .map(|&gpa| {
                    backend
                        .gpa_to_hva(gpa, page_size as u64)
                        .map(|hva| hva as *mut u8)
                        .ok_or(CUDA_ERROR_NOT_SUPPORTED)
                })
                .collect()
        };
        let req = map_all(req_pages)?;
        let resp = map_all(resp_pages)?;
        let bounce = map_all(bounce_pages)?;
        // SAFETY: pages are backed by mapped guest RAM for the VM's lifetime.
        Ok(HostRings {
            req: unsafe { crate::ring::Ring::from_pages(req, ps) },
            resp: unsafe { crate::ring::Ring::from_pages(resp, ps) },
            bounce,
            page_size: ps,
        })
    }

    /// Copy an oversized response into the bounce buffer. Returns false when
    /// it doesn't fit (protocol error surfaced to the guest as a status).
    fn write_bounce(&self, bytes: &[u8]) -> bool {
        if bytes.len() > self.bounce.len() * self.page_size {
            return false;
        }
        for (i, chunk) in bytes.chunks(self.page_size).enumerate() {
            // SAFETY: chunk fits within bounce page i (checked above).
            unsafe {
                std::ptr::copy_nonoverlapping(chunk.as_ptr(), self.bounce[i], chunk.len());
            }
        }
        true
    }
}

/// Ring-mode serve loop: requests pop from the guest's request ring,
/// responses push to the completion ring; the socket carries doorbells only.
fn serve_rings<S: Read + Write>(
    mut stream: S,
    backend: &mut dyn Backend,
    sess: &mut Session,
    mut quiet_sticky: i32,
    rings: HostRings,
) -> std::io::Result<()> {
    use crate::ring::LEN_INDIRECT;
    let oplog = std::env::var_os("SMOLVM_CUDA_HOST_OPLOG").is_some();
    // Reassembly buffer for oversized frames arriving as bounce chunks.
    let mut pending: Vec<u8> = Vec::new();
    // Push one response. Oversized ones chunk through the bounce pages: the
    // guest posts a continue record (16×0xFF, LEN_INDIRECT) on the request
    // ring after copying each non-final chunk out — unambiguous because a
    // blocked guest can't send anything else. Doorbell on park either way.
    fn respond<S: Read + Write>(
        rings: &HostRings,
        stream: &mut S,
        bytes: &[u8],
    ) -> std::io::Result<()> {
        let kick = |stream: &mut S| -> std::io::Result<()> {
            if rings_take_parked(rings) {
                stream.write_all(&[1u8])?;
                stream.flush()?;
            }
            Ok(())
        };
        fn rings_take_parked(rings: &HostRings) -> bool {
            rings.resp.take_parked()
        }
        if bytes.len() <= crate::ring::INLINE_MAX {
            while !rings.resp.try_push(bytes, 0) {
                std::hint::spin_loop(); // guest drains sync responses promptly
            }
            return kick(stream);
        }
        let cap = rings.bounce.len() * rings.page_size;
        let total = bytes.len();
        let mut off = 0;
        while off < total {
            let chunk = (total - off).min(cap);
            if !rings.write_bounce(&bytes[off..off + chunk]) {
                return Err(std::io::Error::other("ring: bounce write failed"));
            }
            let mut hdr = [0u8; 16];
            hdr[..8].copy_from_slice(&(total as u64).to_le_bytes());
            hdr[8..].copy_from_slice(&(chunk as u64).to_le_bytes());
            while !rings.resp.try_push(&hdr, LEN_INDIRECT) {
                std::hint::spin_loop();
            }
            kick(stream)?;
            off += chunk;
            if off < total {
                // Await the guest's continue record before refilling.
                loop {
                    if let Some((p, f)) = rings.req.try_pop() {
                        if f & LEN_INDIRECT != 0 && p == [0xFF; 16] {
                            break;
                        }
                        return Err(std::io::Error::other("ring: expected continue"));
                    }
                    std::hint::spin_loop();
                }
            }
        }
        Ok(())
    }
    loop {
        let (payload, flags) = match rings.req.try_pop() {
            Some(rec) => rec,
            None => {
                // Adaptive wait: spin briefly, then park and block on a
                // doorbell byte from the guest.
                let mut found = None;
                for _ in 0..20_000 {
                    if let Some(rec) = rings.req.try_pop() {
                        found = Some(rec);
                        break;
                    }
                    std::hint::spin_loop();
                }
                match found {
                    Some(rec) => rec,
                    None => {
                        if !rings.req.park() {
                            let mut byte = [0u8; 1];
                            match stream.read(&mut byte) {
                                Ok(0) => return Ok(()), // guest closed
                                Ok(_) => {}
                                Err(e) => return Err(e),
                            }
                            rings.req.unpark();
                        }
                        continue;
                    }
                }
            }
        };
        // Oversized frame: chunks arrive through the bounce pages. Every
        // non-final chunk is acked (so the guest can refill the pages); the
        // final chunk completes the frame, which dispatches below and whose
        // own response closes the exchange.
        let frame: Vec<u8> = if flags & LEN_INDIRECT != 0 {
            if payload.len() < 16 {
                return Err(std::io::Error::other("ring: short chunk record"));
            }
            let total = u64::from_le_bytes(payload[..8].try_into().unwrap()) as usize;
            let chunk = u64::from_le_bytes(payload[8..16].try_into().unwrap()) as usize;
            if total > crate::proto::MAX_MSG || chunk > rings.bounce.len() * rings.page_size {
                return Err(std::io::Error::other("ring: oversized chunk"));
            }
            let mut left = chunk;
            for &page in &rings.bounce {
                if left == 0 {
                    break;
                }
                let take = left.min(rings.page_size);
                // SAFETY: bounce pages are mapped guest RAM.
                unsafe {
                    pending.extend_from_slice(std::slice::from_raw_parts(page, take));
                }
                left -= take;
            }
            if pending.len() < total {
                // Ack the chunk so the guest may refill the bounce pages.
                respond(&rings, &mut stream, &encode_response(0, &Response::Ok))?;
                continue;
            }
            std::mem::take(&mut pending)
        } else {
            payload
        };
        match frame.first() {
            Some(&crate::proto::QUIET_PREFIX) => {
                let req = match decode_request(&frame[1..]) {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!(
                            "[ring-dbg] malformed QUIET frame len={} head={:02x?}",
                            frame.len(),
                            &frame[..frame.len().min(12)]
                        );
                        return Err(e);
                    }
                };
                if oplog {
                    eprintln!("[op~] 0x{:02x} len={}", frame[1], frame.len());
                }
                let (status, _) = dispatch(sess, backend, req);
                if status != 0 {
                    if oplog {
                        eprintln!("[op~!] status={status}");
                    }
                    if quiet_sticky == 0 {
                        quiet_sticky = status;
                    }
                }
            }
            Some(&crate::proto::FENCE_OP) if frame.len() == 1 => {
                let st = std::mem::take(&mut quiet_sticky);
                respond(&rings, &mut stream, &encode_response(st, &Response::Ok))?;
            }
            _ => {
                let req = match decode_request(&frame) {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!(
                            "[ring-dbg] malformed frame len={} head={:02x?}",
                            frame.len(),
                            &frame[..frame.len().min(12)]
                        );
                        return Err(e);
                    }
                };
                if oplog {
                    eprintln!("[op] 0x{:02x} len={}", frame[0], frame.len());
                }
                let (status, resp) = dispatch(sess, backend, req);
                if status != 0 && oplog {
                    eprintln!("[op!] status={status}");
                }
                respond(&rings, &mut stream, &encode_response(status, &resp))?;
            }
        }
    }
}

/// Per-connection VRAM budget (`SMOLVM_CUDA_VRAM_LIMIT_MB`), read per
/// allocation: rare calls, and staying uncached keeps it adjustable and
/// test-deterministic.
fn vram_limit() -> u64 {
    std::env::var("SMOLVM_CUDA_VRAM_LIMIT_MB")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(|mb| mb * 1024 * 1024)
        .unwrap_or(u64::MAX)
}

fn dispatch(sess: &mut Session, b: &mut dyn Backend, req: Request) -> (i32, Response) {
    // P0 transport-viability: count every RPC; optionally inject per-call latency
    // to model network RTT, and periodically log the count vs wall-clock so
    // calls/sec (and thus calls-per-token) can be derived.
    let rpc_n = RPC_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    let delay = rpc_delay_us();
    if delay > 0 {
        std::thread::sleep(std::time::Duration::from_micros(delay));
    }
    if rpc_stats_enabled() && rpc_n.is_multiple_of(2000) {
        let wall = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        let rt = ROUNDTRIP_COUNT.load(std::sync::atomic::Ordering::Relaxed);
        eprintln!("[rpc-stats] count={rpc_n} roundtrips={rt} wall={wall:.6}");
    }
    // Translate an opaque id to the backend's raw handle, or error.
    fn raw(map: &HashMap<u64, u64>, id: u64) -> CuResult<u64> {
        map.get(&id).copied().ok_or(CUDA_ERROR_INVALID_HANDLE)
    }
    // Translate an opaque stream id: 0 is the default stream (passes through),
    // anything else must be a live minted id.
    fn raw_stream(sess: &Session, stream: u64) -> CuResult<u64> {
        // Streams are raw host pointers on the wire (see StreamCreate below);
        // the table only translates ids minted by pre-raw-stream guests.
        if stream == 0 {
            Ok(0)
        } else {
            Ok(sess.streams.get(&stream).copied().unwrap_or(stream))
        }
    }
    // Modules and functions are raw host handles on the wire (like streams):
    // the real CUmodule/CUfunction is context-scoped and every connection
    // retains the same device primary context, so a handle minted on one
    // connection stays valid on another (this is what lets a forked VM clone
    // reconnect and keep using its parent's loaded modules). The tables only
    // translate ids minted by pre-raw guests; a raw value passes through.
    fn raw_module(sess: &Session, m: u64) -> u64 {
        sess.modules.get(&m).copied().unwrap_or(m)
    }
    fn raw_fn_h(sess: &Session, f: u64) -> u64 {
        sess.functions.get(&f).copied().unwrap_or(f)
    }
    fn raw_graph(sess: &Session, h: u64) -> u64 {
        // Virtual graph/exec handle → real; untagged values pass through.
        if h & VHANDLE_TAG != 0 {
            sess.graph_vhandles
                .lock()
                .unwrap()
                .get(&h)
                .copied()
                .unwrap_or(0)
        } else {
            h
        }
    }
    fn raw_event(sess: &Session, event: u64) -> CuResult<u64> {
        // Same raw-on-the-wire convention as streams.
        Ok(sess.events.get(&event).copied().unwrap_or(event))
    }
    // Copy-on-write any shared weight buffer this request writes, then rewrite
    // inherited device pointers to this clone's private copies (both no-ops
    // unless this is an isolating clone).
    cow_written(sess, b, &req);
    let req = translate_dptrs(&sess.dptr_trans, req);
    let r: CuResult<Response> = (|| match req {
        Request::Init {
            proto_hash,
            resume_token,
        } => {
            if proto_hash != crate::PROTO_HASH {
                eprintln!(
                    "[smolvm-cuda] PROTOCOL MISMATCH: client wire hash {:016x} != server {:016x} \
                     — the guest shim and host server were built from different source. \
                     Rebuild and restage both. Refusing the connection to avoid corruption.",
                    proto_hash,
                    crate::PROTO_HASH
                );
                // CUDA_ERROR_NOT_SUPPORTED — surfaced at cuInit, loud and early.
                Err(CUDA_ERROR_NOT_SUPPORTED)
            } else {
                // Adopt the parent's handle map if resuming, and hand back this
                // session's token so a later fork-clone can resume from us. The
                // backend hands off its cuBLAS/cuDNN descriptors; mirror that for
                // the session-level captured-graph map under the same token.
                let token = b.begin_session(resume_token);
                graph_handoff_register(&sess.graph_vhandles, resume_token, token);
                dptr_handoff_register(&sess.alloc_table, token);
                vmm_handoff_register(&sess.vmm_ranges, token);
                // Isolation-mode clone: defer copying the parent's buffers until
                // the first PrimaryCtxRetain, when a context is actually current.
                if resume_token != 0 && fork_isolate_enabled() {
                    sess.pending_isolate = resume_token;
                }
                b.init().map(|_| Response::Handle(token))
            }
        }
        Request::DeviceGetCount => b.device_get_count().map(Response::Count),
        Request::DeviceGetName { device } => b.device_get_name(device).map(Response::Name),
        Request::DeviceTotalMem { device } => b.device_total_mem(device).map(Response::Bytes),
        Request::DriverGetVersion => b.driver_get_version().map(Response::Count),
        Request::DeviceGetAttribute { attrib, device } => {
            b.device_get_attribute(attrib, device).map(Response::Count)
        }
        Request::DeviceGetUuid { device } => b
            .device_get_uuid(device)
            .map(|u| Response::Data(u.to_vec())),
        Request::CtxCreate { device } => {
            let raw = b.ctx_create(device)?;
            let id = sess.mint();
            sess.contexts.insert(id, raw);
            Ok(Response::Handle(id))
        }
        Request::CtxDestroy { ctx } => {
            let raw = raw(&sess.contexts, ctx)?;
            b.ctx_destroy(raw)?;
            sess.contexts.remove(&ctx);
            Ok(Response::Ok)
        }
        Request::PrimaryCtxRetain { device } => {
            let raw = b.primary_ctx_retain(device)?;
            sess.primary_retains += 1;
            let id = sess.mint();
            sess.contexts.insert(id, raw);
            // Copy-on-fork (isolation mode): now that the primary context is
            // current on this thread, give this clone private copies of the
            // parent's device buffers and record the pointer translation, so its
            // inherited dptrs resolve to disjoint VRAM from sibling clones.
            if sess.pending_isolate != 0 {
                let parent = std::mem::take(&mut sess.pending_isolate);
                // SMOLVM_CUDA_FORK_COPY_ALL forces every buffer private (weights
                // too) — maximal isolation at N× the VRAM. Default shares the
                // read-only weights (copy-on-write) so clones fit alongside the golden.
                let copy_all = std::env::var_os("SMOLVM_CUDA_FORK_COPY_ALL").is_some();
                let (mut copied, mut shared, mut cbytes, mut sbytes) = (0u64, 0u64, 0u64, 0u64);
                if let Some(allocs) = dptr_handoff_snapshot(parent) {
                    for (gdptr, size, loaded) in allocs {
                        if loaded && !copy_all {
                            // Weight/constant: share the parent's copy (read in
                            // place, no translation). Copied-on-write only if the
                            // clone actually writes it (see `cow_written`).
                            sess.shared_ranges.push((gdptr, size));
                            shared += 1;
                            sbytes += size;
                            continue;
                        }
                        if let Ok(cdptr) = b.mem_alloc(size) {
                            let _ = b.memcpy_dtod(cdptr, gdptr, size);
                            sess.dptr_trans.push((gdptr, size, cdptr));
                            sess.owned_dptrs.insert(cdptr, size);
                            sess.alloc_table
                                .lock()
                                .unwrap()
                                .insert(cdptr, (size, false));
                            copied += 1;
                            cbytes += size;
                        }
                    }
                }
                // VMM-mapped ranges (torch's expandable_segments pool) never
                // enter alloc_table, so copy each privately here — ALWAYS, since
                // an expandable segment mixes weights + activations and can't be
                // shared read-only. Without this a clone inherits the golden's
                // raw VMM addresses untranslated (the 0-copies bug).
                if let Some(vmm) = vmm_handoff_snapshot(parent) {
                    for (gva, size) in vmm {
                        if let Ok(cdptr) = b.mem_alloc(size) {
                            let _ = b.memcpy_dtod(cdptr, gva, size);
                            sess.dptr_trans.push((gva, size, cdptr));
                            sess.owned_dptrs.insert(cdptr, size);
                            sess.alloc_table
                                .lock()
                                .unwrap()
                                .insert(cdptr, (size, false));
                            copied += 1;
                            cbytes += size;
                        }
                    }
                }
                gpu::set_lib_trans(&sess.dptr_trans); // forwarded-lib pointer map
                eprintln!(
                    "[cuda-fork-isolate] clone resumed token {parent}: {copied} private copies \
                     ({cbytes} B), {shared} shared read-only ({sbytes} B)"
                );
                if std::env::var_os("SMOLVM_CUDA_GRAPH_DEBUG").is_some() {
                    // Scan the copied buffers for 8-byte values that fall inside a
                    // golden allocation range: those are DEVICE-STORED POINTERS that
                    // node-arg translation can't reach. fp16/fp32 data almost never
                    // forms a 0x7f..-class address, so any hits are real.
                    let mut ranges: Vec<(u64, u64)> = sess
                        .dptr_trans
                        .iter()
                        .map(|&(b, s, _)| (b, b + s))
                        .collect();
                    ranges.extend(sess.shared_ranges.iter().map(|&(b, s)| (b, b + s)));
                    let copies: Vec<(u64, u64)> =
                        sess.dptr_trans.iter().map(|&(_, s, c)| (c, s)).collect();
                    let (mut found, mut sample) = (0u64, Vec::new());
                    for (cptr, size) in copies {
                        if let Ok(bytes) = b.memcpy_dtoh(cptr, size, 0) {
                            for ch in bytes.chunks_exact(8) {
                                let v = u64::from_ne_bytes(ch.try_into().unwrap());
                                if ranges.iter().any(|&(lo, hi)| v >= lo && v < hi) {
                                    found += 1;
                                    if sample.len() < 6 {
                                        sample.push(v);
                                    }
                                }
                            }
                        }
                    }
                    eprintln!(
                        "[cuda-fork-isolate] DEVICE-STORED golden pointers in copies: {found} (e.g. {sample:#x?})"
                    );
                }
            }
            Ok(Response::Handle(id))
        }
        Request::PrimaryCtxRelease { device } => {
            sess.primary_retains = sess.primary_retains.saturating_sub(1);
            b.primary_ctx_release(device).map(|_| Response::Ok)
        }
        Request::ModuleLoadData { image } => {
            // Return the raw CUmodule as the wire handle (context-scoped, so it
            // survives a fork-clone reconnect). Still tracked for reclaim.
            let raw = b.module_load_data(&image)?;
            sess.owned_modules.insert(raw);
            Ok(Response::Handle(raw))
        }
        Request::ModuleGetFunction { module, name } => {
            let raw_mod = raw_module(sess, module);
            // Raw CUfunction on the wire: valid across connections in the shared
            // primary context, so a forked clone keeps its parent's functions.
            let raw_fn = b.module_get_function(raw_mod, &name)?;
            Ok(Response::Handle(raw_fn))
        }
        Request::ModuleUnload { module } => {
            let raw_mod = raw_module(sess, module);
            b.module_unload(raw_mod)?;
            sess.owned_modules.remove(&raw_mod);
            sess.modules.remove(&module);
            Ok(Response::Ok)
        }
        Request::FuncGetParamInfo { function } => {
            let raw_fn = raw_fn_h(sess, function);
            let sizes = b.func_get_param_info(raw_fn)?;
            let mut out = Vec::with_capacity(sizes.len() * 4);
            for s in sizes {
                out.extend_from_slice(&s.to_le_bytes());
            }
            Ok(Response::Data(out))
        }
        Request::FuncSetAttribute {
            function,
            attrib,
            value,
        } => {
            let raw_fn = raw_fn_h(sess, function);
            b.func_set_attribute(raw_fn, attrib, value)
                .map(|_| Response::Ok)
        }
        Request::FuncGetAttribute { function, attrib } => {
            let raw_fn = raw_fn_h(sess, function);
            b.func_get_attribute(raw_fn, attrib).map(Response::Count)
        }
        Request::MemAlloc { bytes } => {
            // Per-connection VRAM quota (SMOLVM_CUDA_VRAM_LIMIT_MB on the
            // host): a guest may not allocate past its budget — the CUDA-
            // native failure (out of memory) surfaces to the app.
            let limit = vram_limit();
            let used: u64 = sess.owned_dptrs.values().sum::<u64>()
                + sess.owned_vmm_handles.values().sum::<u64>();
            if used.saturating_add(bytes) > limit {
                return Err(2); // CUDA_ERROR_OUT_OF_MEMORY
            }
            b.mem_alloc(bytes).map(|d| {
                sess.owned_dptrs.insert(d, bytes);
                sess.alloc_table.lock().unwrap().insert(d, (bytes, false));
                Response::Dptr(d)
            })
        }
        Request::MemFree { dptr } => {
            // `dptr` is already translated to the clone's copy (if inherited).
            sess.owned_dptrs.remove(&dptr);
            sess.alloc_table.lock().unwrap().remove(&dptr);
            // (removal returns the freed size to the quota ledger)
            b.mem_free(dptr).map(|_| Response::Ok)
        }
        Request::MemcpyHtoD { dptr, stream, data } => {
            mark_loaded(&sess.alloc_table, dptr); // H2D write → weight/read-only
            b.memcpy_htod(dptr, &data, raw_stream(sess, stream)?)
                .map(|_| Response::Ok)
        }
        Request::MemcpyDtoH {
            dptr,
            bytes,
            stream,
        } => b
            .memcpy_dtoh(dptr, bytes, raw_stream(sess, stream)?)
            .map(Response::Data),
        Request::MemcpyDtoD { dst, src, bytes } => {
            b.memcpy_dtod(dst, src, bytes).map(|_| Response::Ok)
        }
        Request::MemsetD8 { dptr, value, bytes } => {
            b.memset_d8(dptr, value, bytes).map(|_| Response::Ok)
        }
        Request::MemGetInfo => b.mem_get_info().map(|(f, t)| Response::Pair(f, t)),
        Request::LaunchKernel {
            function,
            grid,
            block,
            shared_bytes,
            stream,
            params,
        } => {
            let raw_fn = raw_fn_h(sess, function);
            let raw_str = raw_stream(sess, stream)?;
            b.launch_kernel(raw_fn, grid, block, shared_bytes, raw_str, &params)
                .map(|_| Response::Ok)
        }
        Request::CtxSynchronize => b.ctx_synchronize().map(|_| Response::Ok),
        // Streams hand back the RAW host pointer, not a session-minted id.
        // Streams are context-scoped and every connection retains the same
        // device primary context — but one guest process holds SEPARATE
        // connections (runtime shim + driver shim), so a per-session id minted
        // on one is garbage on the other: torch's capture stream (runtime)
        // fed to a Triton kernel launch (driver) came back INVALID_HANDLE.
        // Raw pointers are valid on every connection, like device pointers.
        Request::StreamCreate { flags } => b.stream_create(flags).map(|st| {
            sess.owned_streams.insert(st);
            Response::Handle(st)
        }),
        Request::StreamBeginCapture { stream, mode } => {
            let raw = raw_stream(sess, stream)?;
            b.stream_begin_capture(raw, mode).map(|_| Response::Ok)
        }
        Request::ThreadExchangeCaptureMode { mode } => {
            b.thread_exchange_capture_mode(mode).map(Response::Count)
        }
        Request::StreamEndCapture { stream, graph_vh } => {
            let raw = raw_stream(sess, stream)?;
            let g = b.stream_end_capture(raw)?;
            if graph_vh & VHANDLE_TAG != 0 {
                sess.graph_vhandles.lock().unwrap().insert(graph_vh, g);
                sess.owned_graph_reals.insert(g);
            }
            Ok(Response::Handle(g))
        }
        Request::StreamCaptureInfo { stream } => {
            let raw = raw_stream(sess, stream)?;
            b.stream_capture_info(raw)
                .map(|(st, id)| Response::Pair(st, id))
        }
        Request::GraphInstantiate { graph, exec_vh } => {
            let real_graph = raw_graph(sess, graph);
            let e = b.graph_instantiate(real_graph)?;
            exec_template_register(e, real_graph); // for Path 2 clone re-instantiation
            if fork_isolate_enabled() {
                template_graph_mark(real_graph); // keep it alive for clones
            }
            if exec_vh & VHANDLE_TAG != 0 {
                sess.graph_vhandles.lock().unwrap().insert(exec_vh, e);
                sess.owned_graph_reals.insert(e);
            }
            Ok(Response::Handle(e))
        }
        Request::GraphLaunch { graph_exec, stream } => {
            let real = raw_graph(sess, graph_exec);
            // Fork isolation + an INHERITED cudagraph: the graph baked in the
            // golden's device addresses at capture time, so replaying it verbatim
            // would write the golden's / a sibling's memory. A graph the clone
            // captured itself (owned_graph_reals) is already correct; eager mode
            // has no graphs, so this branch never fires there.
            let inherited_isolated =
                !sess.dptr_trans.is_empty() && !sess.owned_graph_reals.contains(&real);
            if inherited_isolated && !graph_patch_enabled() {
                // Only when explicitly disabled (SMOLVM_CUDA_FORK_GRAPH_PATCH=0):
                // fail loud rather than launch an inherited graph verbatim.
                eprintln!(
                    "[cuda-fork-isolate] graph patch disabled (SMOLVM_CUDA_FORK_GRAPH_PATCH=0); \
                     refusing to launch an inherited CUDA graph in an isolated clone. \
                     Unset the var to use the graph-patch path, or run with enforce_eager."
                );
                return Err(CUDA_ERROR_NOT_SUPPORTED);
            }
            // Diagnostic: patch the golden's exec IN PLACE (no re-instantiate).
            if inherited_isolated && graph_inplace_enabled() {
                if let Some(template) = exec_template_lookup(real) {
                    if !sess.clone_graph_execs.contains_key(&real) {
                        b.graph_exec_patch(real, template, &sess.dptr_trans)?;
                        sess.clone_graph_execs.insert(real, real); // patch once
                    }
                }
                let raw = raw_stream(sess, stream)?;
                return b.graph_launch(real, raw).map(|_| Response::Ok);
            }
            // Path 2: re-instantiate the template and translate its node pointers
            // (including those embedded in by-value kernel-arg structs) to this
            // clone's private copies.
            let launch = if inherited_isolated {
                match sess.clone_graph_execs.get(&real).copied() {
                    Some(patched) => patched,
                    None => {
                        let template = exec_template_lookup(real).ok_or_else(|| {
                            eprintln!(
                                "[cuda-fork-isolate] inherited graph exec {real:#x} has no known \
                                 template; refusing to launch (would corrupt across clones)"
                            );
                            CUDA_ERROR_NOT_SUPPORTED
                        })?;
                        let dbg = std::env::var_os("SMOLVM_CUDA_GRAPH_DEBUG").is_some();
                        let patched = b.graph_instantiate(template).inspect_err(|e| {
                            if dbg {
                                eprintln!(
                                    "[gpatch] reinstantiate template {template:#x} FAILED: {e}"
                                )
                            }
                        })?;
                        b.graph_exec_patch(patched, template, &sess.dptr_trans)
                            .inspect_err(|e| {
                                if dbg {
                                    eprintln!("[gpatch] patch exec {patched:#x} FAILED: {e}")
                                }
                            })?;
                        sess.clone_graph_execs.insert(real, patched);
                        sess.owned_graph_reals.insert(patched);
                        patched
                    }
                }
            } else {
                real
            };
            let raw = raw_stream(sess, stream)?;
            b.graph_launch(launch, raw).map(|_| Response::Ok)
        }
        Request::GraphExecDestroy { graph_exec } => {
            let real = raw_graph(sess, graph_exec);
            sess.graph_vhandles.lock().unwrap().remove(&graph_exec);
            // Only free if we created it; an inherited exec belongs to the
            // still-live parent (or a sibling clone) and must not be freed here.
            if sess.owned_graph_reals.remove(&real) {
                b.graph_exec_destroy(real).map(|_| Response::Ok)
            } else {
                Ok(Response::Ok)
            }
        }
        Request::GraphDestroy { graph } => {
            let real = raw_graph(sess, graph);
            sess.graph_vhandles.lock().unwrap().remove(&graph);
            let owned = sess.owned_graph_reals.remove(&real);
            if template_graph_is(real) {
                // Keep the template alive so isolating clones can still
                // re-instantiate + patch it (Path 2). Leaks the cuGraph.
                Ok(Response::Ok)
            } else if owned {
                b.graph_destroy(real).map(|_| Response::Ok)
            } else {
                Ok(Response::Ok)
            }
        }
        Request::GraphGetNodes { graph } => b.graph_get_node_count(graph).map(Response::Bytes),
        Request::MemsetD8Async {
            dptr,
            value,
            bytes,
            stream,
        } => {
            let raw = raw_stream(sess, stream)?;
            b.memset_d8_async(dptr, value, bytes, raw)
                .map(|_| Response::Ok)
        }
        Request::MemcpyDtoDAsync {
            dst,
            src,
            bytes,
            stream,
        } => {
            let raw = raw_stream(sess, stream)?;
            b.memcpy_dtod_async(dst, src, bytes, raw)
                .map(|_| Response::Ok)
        }
        Request::StreamDestroy { stream } => {
            let raw = raw_stream(sess, stream)?;
            b.stream_destroy(raw)?;
            sess.owned_streams.remove(&raw);
            sess.streams.remove(&stream);
            Ok(Response::Ok)
        }
        Request::StreamSynchronize { stream } => {
            let raw = raw_stream(sess, stream)?;
            b.stream_synchronize(raw).map(|_| Response::Ok)
        }
        Request::StreamQuery { stream } => {
            let raw = raw_stream(sess, stream)?;
            b.stream_query(raw).map(Response::Count)
        }
        Request::StreamWaitEvent {
            stream,
            event,
            flags,
        } => {
            let raw_s = raw_stream(sess, stream)?;
            let raw_e = raw_event(sess, event)?;
            b.stream_wait_event(raw_s, raw_e, flags)
                .map(|_| Response::Ok)
        }
        // Events are raw host pointers on the wire, same as streams (see
        // StreamCreate): context-scoped, and one guest process talks over
        // several connections that must all understand the same handle.
        Request::EventCreate { flags } => b.event_create(flags).map(|e| {
            sess.owned_events.insert(e);
            Response::Handle(e)
        }),
        Request::EventDestroy { event } => {
            let raw = raw_event(sess, event)?;
            b.event_destroy(raw)?;
            sess.owned_events.remove(&raw);
            sess.events.remove(&event);
            Ok(Response::Ok)
        }
        Request::EventRecord { event, stream } => {
            let raw_ev = raw_event(sess, event)?;
            let raw_str = raw_stream(sess, stream)?;
            b.event_record(raw_ev, raw_str).map(|_| Response::Ok)
        }
        Request::EventSynchronize { event } => {
            let raw_ev = raw_event(sess, event)?;
            b.event_synchronize(raw_ev).map(|_| Response::Ok)
        }
        Request::EventQuery { event } => {
            let raw_ev = raw_event(sess, event)?;
            b.event_query(raw_ev).map(Response::Count)
        }
        Request::EventElapsedTime { start, end } => {
            let raw_start = raw_event(sess, start)?;
            let raw_end = raw_event(sess, end)?;
            b.event_elapsed_time(raw_start, raw_end)
                .map(Response::Millis)
        }
        Request::NvcompDeflateTempSize {
            num_chunks,
            max_uncompressed_chunk_bytes,
            max_total_uncompressed_bytes,
        } => b
            .nvcomp_deflate_temp_size(
                num_chunks,
                max_uncompressed_chunk_bytes,
                max_total_uncompressed_bytes,
            )
            .map(|(st, tb)| Response::Pair(st as u64, tb)),
        Request::NvcompDeflateDecompress {
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
        } => {
            let raw_str = raw_stream(sess, stream)?;
            b.nvcomp_deflate_decompress(
                device_compressed_ptrs,
                device_compressed_bytes,
                device_uncompressed_bytes,
                device_actual_uncompressed_bytes,
                batch_size,
                device_temp,
                temp_bytes,
                device_uncompressed_ptrs,
                device_statuses,
                raw_str,
            )
            .map(Response::Count)
        }
        Request::CublasCreate => {
            let raw = b.cublas_create()?;
            let id = sess.mint();
            sess.cublas_handles.insert(id, raw);
            Ok(Response::Handle(id))
        }
        Request::CublasDestroy { handle } => {
            let raw = raw(&sess.cublas_handles, handle)?;
            b.cublas_destroy(raw)?;
            sess.cublas_handles.remove(&handle);
            Ok(Response::Ok)
        }
        Request::CublasSetStream { handle, stream } => {
            let raw_h = raw(&sess.cublas_handles, handle)?;
            let raw_s = raw_stream(sess, stream)?;
            b.cublas_set_stream(raw_h, raw_s).map(|_| Response::Ok)
        }
        Request::CublasSgemm {
            handle,
            transa,
            transb,
            m,
            n,
            k,
            alpha_bits,
            a,
            lda,
            b: bmat,
            ldb,
            beta_bits,
            c,
            ldc,
        } => {
            let raw_h = raw(&sess.cublas_handles, handle)?;
            b.cublas_sgemm(
                raw_h,
                transa,
                transb,
                m,
                n,
                k,
                f32::from_bits(alpha_bits),
                a,
                lda,
                bmat,
                ldb,
                f32::from_bits(beta_bits),
                c,
                ldc,
            )
            .map(|_| Response::Ok)
        }
        Request::LibCall { lib, func, args } => b
            .lib_call(lib, func, &args, &sess.streams)
            .map(|(status, out)| Response::LibResult(status, out)),
        Request::MemcpyShmHtoD {
            dptr,
            offset,
            size,
            stream,
        } => {
            mark_loaded(&sess.alloc_table, dptr);
            b.memcpy_shm_htod(dptr, offset, size, raw_stream(sess, stream)?)
                .map(|_| Response::Ok)
        }
        Request::MemcpyShmDtoH {
            offset,
            dptr,
            size,
            stream,
        } => b
            .memcpy_shm_dtoh(offset, dptr, size, raw_stream(sess, stream)?)
            .map(|_| Response::Ok),
        Request::MemcpyGpaHtoD {
            dptr,
            stream,
            segments,
        } => {
            mark_loaded(&sess.alloc_table, dptr);
            b.memcpy_gpa_htod(dptr, &segments, raw_stream(sess, stream)?)
                .map(|_| Response::Ok)
        }
        Request::MemcpyGpaDtoH {
            dptr,
            stream,
            segments,
        } => b
            .memcpy_gpa_dtoh(dptr, &segments, raw_stream(sess, stream)?)
            .map(|_| Response::Ok),
        // Handled by the serve loop (transport concern, not a backend op);
        // reaching dispatch means the transport doesn't support rings.
        Request::RingSetup { .. } => Err(CUDA_ERROR_NOT_SUPPORTED),
        Request::MemAddressReserve { size, align } => {
            b.mem_address_reserve(size, align).map(|va| {
                sess.owned_vmm_reservations.insert(va, size);
                Response::Dptr(va)
            })
        }
        Request::MemCreate { size, device } => {
            let limit = vram_limit();
            let used: u64 = sess.owned_dptrs.values().sum::<u64>()
                + sess.owned_vmm_handles.values().sum::<u64>();
            if used.saturating_add(size) > limit {
                return Err(2); // CUDA_ERROR_OUT_OF_MEMORY
            }
            b.mem_create(size, device).map(|h| {
                sess.owned_vmm_handles.insert(h, size);
                Response::Handle(h)
            })
        }
        Request::MemMap {
            va,
            size,
            offset,
            handle,
        } => b.mem_map(va, size, offset, handle).map(|_| {
            sess.owned_vmm_maps.insert(va, size);
            sess.vmm_ranges.lock().unwrap().insert(va, size);
            Response::Ok
        }),
        Request::MemSetAccess { va, size, device } => {
            b.mem_set_access(va, size, device).map(|_| Response::Ok)
        }
        Request::MemUnmap { va, size } => {
            sess.owned_vmm_maps.remove(&va);
            sess.vmm_ranges.lock().unwrap().remove(&va);
            b.mem_unmap(va, size).map(|_| Response::Ok)
        }
        Request::MemRelease { handle } => {
            sess.owned_vmm_handles.remove(&handle);
            b.mem_release(handle).map(|_| Response::Ok)
        }
        Request::MemAddressFree { va, size } => {
            sess.owned_vmm_reservations.remove(&va);
            b.mem_address_free(va, size).map(|_| Response::Ok)
        }
        Request::MemGetAllocationGranularity { device, flags } => b
            .mem_get_allocation_granularity(device, flags)
            .map(Response::Bytes),
    })();
    match r {
        Ok(resp) => (0, resp),
        Err(code) => (code, Response::Ok),
    }
}

// ===========================================================================
// CPU emulation backend (for GPU-less verification of the full RPC path)
// ===========================================================================

/// Emulates a small, known set of kernels so the protocol + transport can be
/// exercised end-to-end without an NVIDIA GPU. Device memory is a bump-allocated
/// host buffer keyed by fake `CUdeviceptr`. Recognizes the `vecadd(a,b,c,n)`
/// test kernel by name; unknown kernels return `CUDA_ERROR_NOT_FOUND`.
pub struct CpuBackend {
    next_dptr: u64,
    mem: HashMap<u64, Vec<u8>>,
    fn_names: HashMap<u64, String>,
    next_handle: u64,
    /// Guest-RAM mappings, same shape as the GPU backend's — lets the ring
    /// transport (and its tests) run without a GPU.
    guest_ram: Vec<(u64, u64, u64)>,
}

impl Default for CpuBackend {
    fn default() -> Self {
        CpuBackend {
            next_dptr: 0x1_0000_0000, // distinct from small handle ids
            mem: HashMap::new(),
            fn_names: HashMap::new(),
            next_handle: 1,
            guest_ram: Vec::new(),
        }
    }
}

impl CpuBackend {
    fn handle(&mut self) -> u64 {
        let h = self.next_handle;
        self.next_handle += 1;
        h
    }
}

fn read_u64(p: &[u8]) -> Option<u64> {
    Some(u64::from_le_bytes(p.get(..8)?.try_into().ok()?))
}
fn read_u32(p: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(p.get(..4)?.try_into().ok()?))
}

impl Backend for CpuBackend {
    fn init(&mut self) -> CuResult<()> {
        Ok(())
    }
    fn set_guest_ram(&mut self, regions: Vec<(u64, u64, u64)>) {
        self.guest_ram = regions;
    }
    fn gpa_to_hva(&mut self, gpa: u64, len: u64) -> Option<u64> {
        self.guest_ram.iter().find_map(|&(gs, hva, rlen)| {
            (gpa >= gs && gpa.checked_add(len)? <= gs + rlen).then(|| hva + (gpa - gs))
        })
    }
    fn device_get_count(&mut self) -> CuResult<i32> {
        Ok(1)
    }
    fn device_get_name(&mut self, _device: i32) -> CuResult<String> {
        Ok("smolvm CPU emulation device".into())
    }
    fn device_total_mem(&mut self, _device: i32) -> CuResult<u64> {
        Ok(1 << 30)
    }
    fn driver_get_version(&mut self) -> CuResult<i32> {
        Ok(13000)
    }
    fn device_get_attribute(&mut self, attrib: i32, _device: i32) -> CuResult<i32> {
        // Plausible values for the attributes real programs commonly probe
        // (CUdevice_attribute numeric ids from cuda.h).
        Ok(match attrib {
            1 => 1024,       // MAX_THREADS_PER_BLOCK
            2..=4 => 1024,   // MAX_BLOCK_DIM_X/Y/Z
            5 => 2147483647, // MAX_GRID_DIM_X
            6 | 7 => 65535,  // MAX_GRID_DIM_Y/Z
            8 => 49152,      // MAX_SHARED_MEMORY_PER_BLOCK
            10 => 32,        // WARP_SIZE
            16 => 1,         // MULTIPROCESSOR_COUNT
            75 => 8,         // COMPUTE_CAPABILITY_MAJOR
            76 => 6,         // COMPUTE_CAPABILITY_MINOR
            _ => 1,
        })
    }
    fn device_get_uuid(&mut self, _device: i32) -> CuResult<[u8; 16]> {
        Ok(*b"smolvm-cpu-emul\0")
    }
    fn ctx_create(&mut self, _device: i32) -> CuResult<u64> {
        Ok(self.handle())
    }
    fn ctx_destroy(&mut self, _ctx: u64) -> CuResult<()> {
        Ok(())
    }
    fn primary_ctx_retain(&mut self, _device: i32) -> CuResult<u64> {
        Ok(self.handle())
    }
    fn primary_ctx_release(&mut self, _device: i32) -> CuResult<()> {
        Ok(())
    }
    fn module_load_data(&mut self, _image: &[u8]) -> CuResult<u64> {
        Ok(self.handle())
    }
    fn module_get_function(&mut self, _module: u64, name: &str) -> CuResult<u64> {
        let h = self.handle();
        self.fn_names.insert(h, name.to_string());
        Ok(h)
    }
    fn module_unload(&mut self, _module: u64) -> CuResult<()> {
        Ok(())
    }
    fn func_get_param_info(&mut self, function: u64) -> CuResult<Vec<u32>> {
        let name = self
            .fn_names
            .get(&function)
            .ok_or(CUDA_ERROR_INVALID_HANDLE)?;
        match name.as_str() {
            // vecadd(const float* a, const float* b, float* c, int n)
            "vecadd" => Ok(vec![8, 8, 8, 4]),
            _ => Err(CUDA_ERROR_NOT_FOUND),
        }
    }
    fn func_set_attribute(&mut self, _function: u64, _attrib: i32, _value: i32) -> CuResult<()> {
        // CPU emulation has no shared-memory limits to raise.
        Ok(())
    }
    fn mem_alloc(&mut self, bytes: u64) -> CuResult<u64> {
        let dptr = self.next_dptr;
        self.next_dptr += bytes.max(1);
        self.mem.insert(dptr, vec![0u8; bytes as usize]);
        Ok(dptr)
    }
    fn mem_free(&mut self, dptr: u64) -> CuResult<()> {
        self.mem
            .remove(&dptr)
            .map(|_| ())
            .ok_or(CUDA_ERROR_INVALID_HANDLE)
    }
    fn memcpy_htod(&mut self, dptr: u64, data: &[u8], _stream: u64) -> CuResult<()> {
        let buf = self.mem.get_mut(&dptr).ok_or(CUDA_ERROR_INVALID_HANDLE)?;
        if data.len() > buf.len() {
            return Err(CUDA_ERROR_INVALID_HANDLE);
        }
        buf[..data.len()].copy_from_slice(data);
        Ok(())
    }
    fn memcpy_dtoh(&mut self, dptr: u64, bytes: u64, _stream: u64) -> CuResult<Vec<u8>> {
        let buf = self.mem.get(&dptr).ok_or(CUDA_ERROR_INVALID_HANDLE)?;
        let n = bytes as usize;
        if n > buf.len() {
            return Err(CUDA_ERROR_INVALID_HANDLE);
        }
        Ok(buf[..n].to_vec())
    }
    fn memcpy_dtod(&mut self, dst: u64, src: u64, bytes: u64) -> CuResult<()> {
        let n = bytes as usize;
        let data = {
            let s = self.mem.get(&src).ok_or(CUDA_ERROR_INVALID_HANDLE)?;
            if n > s.len() {
                return Err(CUDA_ERROR_INVALID_HANDLE);
            }
            s[..n].to_vec()
        };
        let d = self.mem.get_mut(&dst).ok_or(CUDA_ERROR_INVALID_HANDLE)?;
        if n > d.len() {
            return Err(CUDA_ERROR_INVALID_HANDLE);
        }
        d[..n].copy_from_slice(&data);
        Ok(())
    }
    fn memset_d8(&mut self, dptr: u64, value: u8, bytes: u64) -> CuResult<()> {
        let buf = self.mem.get_mut(&dptr).ok_or(CUDA_ERROR_INVALID_HANDLE)?;
        let n = bytes as usize;
        if n > buf.len() {
            return Err(CUDA_ERROR_INVALID_HANDLE);
        }
        buf[..n].fill(value);
        Ok(())
    }
    fn mem_get_info(&mut self) -> CuResult<(u64, u64)> {
        Ok((1 << 29, 1 << 30))
    }
    fn launch_kernel(
        &mut self,
        function: u64,
        _grid: [u32; 3],
        _block: [u32; 3],
        _shared_bytes: u32,
        _stream: u64,
        params: &[Vec<u8>],
    ) -> CuResult<()> {
        let name = self
            .fn_names
            .get(&function)
            .cloned()
            .ok_or(CUDA_ERROR_INVALID_HANDLE)?;
        match name.as_str() {
            // vecadd(const float* a, const float* b, float* c, int n): c[i]=a[i]+b[i]
            "vecadd" => {
                if params.len() != 4 {
                    return Err(CUDA_ERROR_NOT_FOUND);
                }
                let a = read_u64(&params[0]).ok_or(CUDA_ERROR_NOT_FOUND)?;
                let b = read_u64(&params[1]).ok_or(CUDA_ERROR_NOT_FOUND)?;
                let c = read_u64(&params[2]).ok_or(CUDA_ERROR_NOT_FOUND)?;
                let n = read_u32(&params[3]).ok_or(CUDA_ERROR_NOT_FOUND)? as usize;
                let av = self.mem.get(&a).ok_or(CUDA_ERROR_INVALID_HANDLE)?.clone();
                let bv = self.mem.get(&b).ok_or(CUDA_ERROR_INVALID_HANDLE)?.clone();
                let out = self.mem.get_mut(&c).ok_or(CUDA_ERROR_INVALID_HANDLE)?;
                for i in 0..n {
                    let x = f32::from_le_bytes(av[i * 4..i * 4 + 4].try_into().unwrap());
                    let y = f32::from_le_bytes(bv[i * 4..i * 4 + 4].try_into().unwrap());
                    out[i * 4..i * 4 + 4].copy_from_slice(&(x + y).to_le_bytes());
                }
                Ok(())
            }
            _ => Err(CUDA_ERROR_NOT_FOUND),
        }
    }
    fn ctx_synchronize(&mut self) -> CuResult<()> {
        Ok(())
    }
    // Streams and events are inert in emulation: every operation completes
    // synchronously, so create/destroy mint handles and the rest are no-ops.
    fn stream_create(&mut self, _flags: u32) -> CuResult<u64> {
        Ok(self.handle())
    }
    fn stream_begin_capture(&mut self, _stream: u64, _mode: i32) -> CuResult<()> {
        Err(CUDA_ERROR_NOT_SUPPORTED)
    }
    fn thread_exchange_capture_mode(&mut self, mode: i32) -> CuResult<i32> {
        // No capture machinery in CPU emulation; echo the mode back.
        Ok(mode)
    }
    fn stream_query(&mut self, _stream: u64) -> CuResult<i32> {
        Ok(0) // everything executes synchronously
    }
    fn stream_wait_event(&mut self, _stream: u64, _event: u64, _flags: u32) -> CuResult<()> {
        Ok(()) // in-order execution: the dependency already holds
    }
    fn event_query(&mut self, _event: u64) -> CuResult<i32> {
        Ok(0)
    }
    fn stream_end_capture(&mut self, _stream: u64) -> CuResult<u64> {
        Err(CUDA_ERROR_NOT_SUPPORTED)
    }
    fn stream_capture_info(&mut self, _stream: u64) -> CuResult<(u64, u64)> {
        Ok((0, 0)) // cudaStreamCaptureStatusNone
    }
    fn graph_instantiate(&mut self, _graph: u64) -> CuResult<u64> {
        Err(CUDA_ERROR_NOT_SUPPORTED)
    }
    fn graph_launch(&mut self, _graph_exec: u64, _stream: u64) -> CuResult<()> {
        Err(CUDA_ERROR_NOT_SUPPORTED)
    }
    fn graph_exec_destroy(&mut self, _graph_exec: u64) -> CuResult<()> {
        Err(CUDA_ERROR_NOT_SUPPORTED)
    }
    fn graph_destroy(&mut self, _graph: u64) -> CuResult<()> {
        Err(CUDA_ERROR_NOT_SUPPORTED)
    }
    fn graph_get_node_count(&mut self, _graph: u64) -> CuResult<u64> {
        Err(CUDA_ERROR_NOT_SUPPORTED)
    }
    fn memset_d8_async(&mut self, dptr: u64, value: u8, bytes: u64, _stream: u64) -> CuResult<()> {
        self.memset_d8(dptr, value, bytes)
    }
    fn memcpy_dtod_async(&mut self, dst: u64, src: u64, bytes: u64, _stream: u64) -> CuResult<()> {
        self.memcpy_dtod(dst, src, bytes)
    }
    fn stream_destroy(&mut self, _stream: u64) -> CuResult<()> {
        Ok(())
    }
    fn stream_synchronize(&mut self, _stream: u64) -> CuResult<()> {
        Ok(())
    }
    fn event_create(&mut self, _flags: u32) -> CuResult<u64> {
        Ok(self.handle())
    }
    fn event_destroy(&mut self, _event: u64) -> CuResult<()> {
        Ok(())
    }
    fn event_record(&mut self, _event: u64, _stream: u64) -> CuResult<()> {
        Ok(())
    }
    fn event_synchronize(&mut self, _event: u64) -> CuResult<()> {
        Ok(())
    }
    fn event_elapsed_time(&mut self, _start: u64, _end: u64) -> CuResult<f32> {
        Ok(0.0)
    }
    fn nvcomp_deflate_temp_size(&mut self, _n: u64, _m: u64, _t: u64) -> CuResult<(i32, u64)> {
        Err(CUDA_ERROR_NOT_FOUND) // no nvcomp under CPU emulation
    }
    fn nvcomp_deflate_decompress(
        &mut self,
        _a: u64,
        _b: u64,
        _c: u64,
        _d: u64,
        _e: u64,
        _f: u64,
        _g: u64,
        _h: u64,
        _i: u64,
        _j: u64,
    ) -> CuResult<i32> {
        Err(CUDA_ERROR_NOT_FOUND)
    }
    fn cublas_create(&mut self) -> CuResult<u64> {
        Err(CUDA_ERROR_NOT_FOUND)
    }
    fn cublas_destroy(&mut self, _handle: u64) -> CuResult<()> {
        Err(CUDA_ERROR_NOT_FOUND)
    }
    fn cublas_set_stream(&mut self, _handle: u64, _stream: u64) -> CuResult<()> {
        Err(CUDA_ERROR_NOT_FOUND)
    }
    fn cublas_sgemm(
        &mut self,
        _handle: u64,
        _transa: u32,
        _transb: u32,
        _m: i32,
        _n: i32,
        _k: i32,
        _alpha: f32,
        _a: u64,
        _lda: i32,
        _b: u64,
        _ldb: i32,
        _beta: f32,
        _c: u64,
        _ldc: i32,
    ) -> CuResult<()> {
        Err(CUDA_ERROR_NOT_FOUND)
    }
}

#[cfg(feature = "gpu")]
mod gpu;
#[cfg(feature = "gpu")]
pub use gpu::GpuBackend;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Client;
    use std::io::{Read, Write};

    // Drive the CPU backend through the full encode→dispatch→decode path.
    #[test]
    fn cpu_backend_vecadd_via_dispatch() {
        let mut sess = Session::default();
        let mut b = CpuBackend::default();
        // module + function
        let (_, m) = dispatch(&mut sess, &mut b, Request::ModuleLoadData { image: vec![] });
        let module = match m {
            Response::Handle(h) => h,
            _ => panic!(),
        };
        let (_, f) = dispatch(
            &mut sess,
            &mut b,
            Request::ModuleGetFunction {
                module,
                name: "vecadd".into(),
            },
        );
        let function = match f {
            Response::Handle(h) => h,
            _ => panic!(),
        };
        // alloc a, b, c (4 floats)
        let alloc = |sess: &mut Session, b: &mut CpuBackend| -> u64 {
            match dispatch(sess, b, Request::MemAlloc { bytes: 16 }).1 {
                Response::Dptr(d) => d,
                _ => panic!(),
            }
        };
        let da = alloc(&mut sess, &mut b);
        let db = alloc(&mut sess, &mut b);
        let dc = alloc(&mut sess, &mut b);
        let a: Vec<u8> = [1f32, 2., 3., 4.]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        let bb: Vec<u8> = [10f32, 20., 30., 40.]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        dispatch(
            &mut sess,
            &mut b,
            Request::MemcpyHtoD {
                dptr: da,
                stream: 0,
                data: a,
            },
        );
        dispatch(
            &mut sess,
            &mut b,
            Request::MemcpyHtoD {
                dptr: db,
                stream: 0,
                data: bb,
            },
        );
        let params = vec![
            da.to_le_bytes().to_vec(),
            db.to_le_bytes().to_vec(),
            dc.to_le_bytes().to_vec(),
            4u32.to_le_bytes().to_vec(),
        ];
        let (st, _) = dispatch(
            &mut sess,
            &mut b,
            Request::LaunchKernel {
                function,
                grid: [1, 1, 1],
                block: [4, 1, 1],
                shared_bytes: 0,
                stream: 0,
                params,
            },
        );
        assert_eq!(st, 0);
        let out = match dispatch(
            &mut sess,
            &mut b,
            Request::MemcpyDtoH {
                dptr: dc,
                bytes: 16,
                stream: 0,
            },
        )
        .1
        {
            Response::Data(d) => d,
            _ => panic!(),
        };
        let c: Vec<f32> = out
            .chunks(4)
            .map(|p| f32::from_le_bytes(p.try_into().unwrap()))
            .collect();
        assert_eq!(c, vec![11., 22., 33., 44.]);
    }

    #[test]
    fn unknown_handle_rejected() {
        let mut sess = Session::default();
        let mut b = CpuBackend::default();
        // function id 999 was never minted
        let (st, _) = dispatch(
            &mut sess,
            &mut b,
            Request::LaunchKernel {
                function: 999,
                grid: [1, 1, 1],
                block: [1, 1, 1],
                shared_bytes: 0,
                stream: 0,
                params: vec![],
            },
        );
        assert_eq!(st, CUDA_ERROR_INVALID_HANDLE);
    }

    // Full client↔serve round-trip over an in-process socketpair-like channel.
    #[test]
    fn client_serve_roundtrip() {
        use std::sync::mpsc::{Receiver, Sender};
        // A duplex stream built from two mpsc byte channels.
        struct Chan {
            tx: Sender<u8>,
            rx: Receiver<u8>,
        }
        impl Write for Chan {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                for &x in buf {
                    self.tx
                        .send(x)
                        .map_err(|_| std::io::ErrorKind::BrokenPipe)?;
                }
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl Read for Chan {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                // Block for at least one byte, then drain what's buffered.
                if buf.is_empty() {
                    return Ok(0);
                }
                let mut n = match self.rx.recv() {
                    Ok(b) => {
                        buf[0] = b;
                        1
                    }
                    Err(_) => return Ok(0), // EOF
                };
                while n < buf.len() {
                    match self.rx.try_recv() {
                        Ok(b) => {
                            buf[n] = b;
                            n += 1;
                        }
                        Err(_) => break,
                    }
                }
                Ok(n)
            }
        }
        let (c2s_tx, c2s_rx) = std::sync::mpsc::channel();
        let (s2c_tx, s2c_rx) = std::sync::mpsc::channel();
        let server_side = Chan {
            tx: s2c_tx,
            rx: c2s_rx,
        };
        let client_side = Chan {
            tx: c2s_tx,
            rx: s2c_rx,
        };

        let server = std::thread::spawn(move || {
            let mut b = CpuBackend::default();
            let _ = serve(server_side, &mut b);
        });

        let mut cli = Client::new(client_side);
        cli.init(0).unwrap();
        assert_eq!(cli.device_get_count().unwrap(), 1);
        let module = cli.module_load_data(b"<ptx>").unwrap();
        let func = cli.module_get_function(module, "vecadd").unwrap();
        let n = 8usize;
        let da = cli.mem_alloc((n * 4) as u64).unwrap();
        let db = cli.mem_alloc((n * 4) as u64).unwrap();
        let dc = cli.mem_alloc((n * 4) as u64).unwrap();
        let a: Vec<u8> = (0..n).flat_map(|i| (i as f32).to_le_bytes()).collect();
        let bb: Vec<u8> = (0..n)
            .flat_map(|i| ((2 * i) as f32).to_le_bytes())
            .collect();
        cli.memcpy_htod(da, &a, 0).unwrap();
        cli.memcpy_htod(db, &bb, 0).unwrap();
        cli.launch_kernel(
            func,
            [1, 1, 1],
            [n as u32, 1, 1],
            0,
            0,
            &[
                da.to_le_bytes().to_vec(),
                db.to_le_bytes().to_vec(),
                dc.to_le_bytes().to_vec(),
                (n as u32).to_le_bytes().to_vec(),
            ],
        )
        .unwrap();
        cli.ctx_synchronize().unwrap();
        let out = cli.memcpy_dtoh(dc, (n * 4) as u64, 0).unwrap();
        let c: Vec<f32> = out
            .chunks(4)
            .map(|p| f32::from_le_bytes(p.try_into().unwrap()))
            .collect();
        let expect: Vec<f32> = (0..n).map(|i| (3 * i) as f32).collect();
        assert_eq!(c, expect);
        drop(cli); // closes client_side → server sees EOF
        server.join().unwrap();
    }
    // Ring transport end-to-end: handshake over the socket, then requests
    // (inline quiet, indirect oversized, fence) through shared memory with
    // bounce-buffer responses — no GPU, no VM.
    #[test]
    fn ring_transport_end_to_end() {
        use std::sync::atomic::AtomicUsize;
        use std::sync::mpsc::{Receiver, Sender};
        struct Chan {
            tx: Sender<u8>,
            rx: Receiver<u8>,
        }
        impl Write for Chan {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                for &x in buf {
                    self.tx
                        .send(x)
                        .map_err(|_| std::io::ErrorKind::BrokenPipe)?;
                }
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl Read for Chan {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if buf.is_empty() {
                    return Ok(0);
                }
                match self.rx.recv() {
                    Ok(b) => {
                        buf[0] = b;
                        Ok(1)
                    }
                    Err(_) => Ok(0), // EOF
                }
            }
        }

        // In-process fake guest RAM: identity-mapped (GPA == host VA), so
        // any heap address — ring pages and indirect staging buffers alike —
        // resolves. The aligned ring pages are leaked so both threads may
        // hold pointers.
        const PAGES: usize = 64;
        const PAGE: usize = 4096;
        let _ = AtomicUsize::new(0); // (kept import happy on older toolchains)
        let layout = std::alloc::Layout::from_size_align(PAGES * PAGE, PAGE).unwrap();
        // SAFETY: fresh allocation, zeroed, intentionally leaked.
        let hva = unsafe {
            let p = std::alloc::alloc_zeroed(layout);
            assert!(!p.is_null());
            p as usize
        };

        let (c2s_tx, c2s_rx) = std::sync::mpsc::channel();
        let (s2c_tx, s2c_rx) = std::sync::mpsc::channel();
        let server_side = Chan {
            tx: s2c_tx,
            rx: c2s_rx,
        };
        let client_side = Chan {
            tx: c2s_tx,
            rx: s2c_rx,
        };
        let server = std::thread::spawn(move || {
            let mut b = CpuBackend::default();
            b.set_guest_ram(vec![(0, 0, u64::MAX / 2)]); // identity: hva == gpa
            let r = serve(server_side, &mut b);
            eprintln!("[test] serve exited: {r:?}");
        });

        let mut cli = Client::new(client_side);
        cli.init(0).unwrap();
        let vas = |r: std::ops::Range<usize>| -> Vec<*mut u8> {
            r.map(|i| (hva + i * PAGE) as *mut u8).collect()
        };
        let gpas = |r: std::ops::Range<usize>| -> Vec<u64> {
            r.map(|i| (hva + i * PAGE) as u64).collect()
        };
        cli.ring_setup(
            PAGE,
            (vas(0..8), gpas(0..8)),
            (vas(8..16), gpas(8..16)),
            (vas(16..24), gpas(16..24)),
        )
        .unwrap();
        assert!(cli.is_ring());

        // Sync op over the ring (inline both ways).
        assert_eq!(cli.device_get_count().unwrap(), 1);
        let d = cli.mem_alloc(8192).unwrap();
        // Deferred quiet op, inline record.
        cli.memcpy_htod(d, &[9u8; 64], 0).unwrap();
        // Fence over the ring settles it.
        cli.drain().unwrap();
        assert_eq!(cli.take_sticky(), 0);
        // Oversized write: multi-chunk through the 32 KiB bounce staging.
        let big: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let d2 = cli.mem_alloc(big.len() as u64).unwrap();
        cli.memcpy_htod(d2, &big, 0).unwrap();
        // Oversized read: response spills through the same bounce pages.
        let back = cli.memcpy_dtoh(d2, big.len() as u64, 0).unwrap();
        assert_eq!(back, big);
        drop(cli);
        server.join().unwrap();
    }
    // A connection may not allocate past SMOLVM_CUDA_VRAM_LIMIT_MB; freeing
    // returns budget. (Env is process-global; restored at the end so
    // parallel tests never see the 1 MB cap on their own allocations.)
    #[test]
    fn vram_quota_enforced() {
        std::env::set_var("SMOLVM_CUDA_VRAM_LIMIT_MB", "1");
        let mut sess = Session::default();
        let mut b = CpuBackend::default();
        let mb = 1024 * 1024;
        let (st, r) = dispatch(&mut sess, &mut b, Request::MemAlloc { bytes: mb / 2 });
        assert_eq!(st, 0);
        let d1 = match r {
            Response::Dptr(d) => d,
            _ => unreachable!(),
        };
        // Second half-MB fits exactly; a byte more must fail with OOM(2).
        let (st, _) = dispatch(&mut sess, &mut b, Request::MemAlloc { bytes: mb / 2 });
        assert_eq!(st, 0);
        let (st, _) = dispatch(&mut sess, &mut b, Request::MemAlloc { bytes: 1 });
        assert_eq!(st, 2, "over-quota alloc must report OUT_OF_MEMORY");
        // Freeing restores budget.
        let (st, _) = dispatch(&mut sess, &mut b, Request::MemFree { dptr: d1 });
        assert_eq!(st, 0);
        let (st, _) = dispatch(&mut sess, &mut b, Request::MemAlloc { bytes: mb / 4 });
        assert_eq!(st, 0);
        std::env::remove_var("SMOLVM_CUDA_VRAM_LIMIT_MB");
    }
    // Modules and functions are raw host handles on the wire, so a handle minted
    // on one connection resolves on another (both retain the same primary
    // context). This is what lets a forked VM clone reconnect on a fresh session
    // and keep launching the parent's kernels instead of getting INVALID_HANDLE.
    #[test]
    fn function_handle_survives_across_sessions() {
        let mut backend = CpuBackend::default();
        // Session A loads a module and resolves a function.
        let mut sess_a = Session::default();
        let (st, r) = dispatch(
            &mut sess_a,
            &mut backend,
            Request::ModuleLoadData {
                image: vec![0u8; 8],
            },
        );
        assert_eq!(st, 0);
        let module = match r {
            Response::Handle(h) => h,
            _ => unreachable!("module load returns a handle"),
        };
        let (st, r) = dispatch(
            &mut sess_a,
            &mut backend,
            Request::ModuleGetFunction {
                module,
                name: "vecadd".into(),
            },
        );
        assert_eq!(st, 0);
        let function = match r {
            Response::Handle(h) => h,
            _ => unreachable!("get-function returns a handle"),
        };
        // Session B is a brand-new session (the clone's fresh connection). It
        // never loaded the module, yet resolving A's function must succeed —
        // pre-raw-handle code returned INVALID_HANDLE here.
        let mut sess_b = Session::default();
        assert!(
            sess_b.functions.is_empty(),
            "clone session starts with no local function ids"
        );
        let (st, r) = dispatch(
            &mut sess_b,
            &mut backend,
            Request::FuncGetParamInfo { function },
        );
        assert_eq!(
            st, 0,
            "function from another session must resolve, not fault"
        );
        match r {
            Response::Data(d) => assert_eq!(
                d,
                [8u32, 8, 8, 4]
                    .iter()
                    .flat_map(|s| s.to_le_bytes())
                    .collect::<Vec<u8>>(),
                "resolved the right function's param layout"
            ),
            other => panic!("expected param data, got {other:?}"),
        }
    }

    #[test]
    fn graph_handoff_copies_parent_captures_to_clone() {
        use std::sync::{Arc, Mutex};
        // High, distinctive tokens so this test can't collide with any token
        // minted through `dispatch` (CpuBackend hands out 0) in the shared
        // GRAPH_HANDOFF registry.
        let vh = VHANDLE_TAG | 0x0000_0000_0000_0007;
        let real_exec = 0xDEAD_BEEF_u64;

        // Parent captured a graph (vh → real) and registered under its token.
        let parent: Arc<GraphVhMap> = Arc::new(Mutex::new(HashMap::new()));
        parent.lock().unwrap().insert(vh, real_exec);
        graph_handoff_register(&parent, 0, 0xA1A1_0000_0000_0001);

        // Clone resumes the parent's token: it must inherit the vh → real entry
        // so a GraphLaunch of the guest's (unchanged) virtual handle resolves.
        let clone: Arc<GraphVhMap> = Arc::new(Mutex::new(HashMap::new()));
        graph_handoff_register(&clone, 0xA1A1_0000_0000_0001, 0xA1A1_0000_0000_0002);
        assert_eq!(
            clone.lock().unwrap().get(&vh).copied(),
            Some(real_exec),
            "clone must inherit the parent's captured-graph handle"
        );

        // Resuming a token whose session is gone yields an empty map, not a fault.
        let orphan: Arc<GraphVhMap> = Arc::new(Mutex::new(HashMap::new()));
        graph_handoff_register(&orphan, 0xDEAD_0000_0000_9999, 0xA1A1_0000_0000_0003);
        assert!(
            orphan.lock().unwrap().is_empty(),
            "a dead lineage token hands off nothing"
        );
    }
    // The connect handshake rejects a client whose wire fingerprint differs
    // (stale shim/server), so protocol skew fails loudly instead of decoding
    // the wrong bytes and corrupting silently.
    #[test]
    fn init_rejects_proto_mismatch() {
        let mut sess = Session::default();
        let mut b = CpuBackend::default();
        let (st, _) = dispatch(
            &mut sess,
            &mut b,
            Request::Init {
                proto_hash: crate::PROTO_HASH,
                resume_token: 0,
            },
        );
        assert_eq!(st, 0, "matching proto hash must connect");
        let (st, _) = dispatch(
            &mut sess,
            &mut b,
            Request::Init {
                proto_hash: crate::PROTO_HASH ^ 0x1,
                resume_token: 0,
            },
        );
        assert_eq!(
            st, CUDA_ERROR_NOT_SUPPORTED,
            "mismatched proto hash must be rejected"
        );
    }
}
