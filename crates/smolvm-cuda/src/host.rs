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

use crate::proto::{
    decode_request, encode_request, encode_response, read_msg, write_msg, Request, Response,
};
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

/// M3b: one KERNEL node of a captured CUDA graph, in a portable form. `func` is
/// the golden's `CUfunction` (re-resolved in the worker); `params` are the raw
/// bytes of each kernel argument in declaration order (address-preserving fork
/// keeps device pointers valid verbatim, so they are copied, not translated).
#[derive(Clone)]
pub struct GraphKernelNode {
    pub func: u64,
    pub grid: [u32; 3],
    pub block: [u32; 3],
    pub shared_mem: u32,
    pub params: Vec<Vec<u8>>,
}

/// M3b: a captured CUDA graph reduced to kernel nodes + dependency edges, so a
/// clone worker can rebuild it in its own context. `edges` are `(from, to)`
/// indices into `nodes` (from runs before to).
#[derive(Clone, Default)]
pub struct GraphSer {
    pub nodes: Vec<GraphKernelNode>,
    pub edges: Vec<(u32, u32)>,
}

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
    /// M3b: introspect a captured graph into a portable, rebuildable form so a
    /// Path-3 clone worker can reconstruct it in its OWN context (the golden's
    /// CUgraph/CUgraphExec are context-scoped and invalid there). Returns `None`
    /// if the graph contains any non-KERNEL node (unsupported — the caller then
    /// keeps the golden's exec, which fails loud rather than mis-executing).
    /// Address-preserving fork means kernel-arg bytes are captured verbatim;
    /// only each node's `func` is golden-scoped and re-resolved in the worker.
    fn graph_introspect(&mut self, _graph: u64) -> CuResult<Option<GraphSer>> {
        Ok(None)
    }
    /// M3b: rebuild `ser` as a NEW CUDA graph in THIS context, mapping every
    /// node's golden `func` handle through `funcs` (golden CUfunction → this
    /// context's reloaded function). Returns the new `cudaGraph_t`.
    fn graph_rebuild(&mut self, _ser: &GraphSer, _funcs: &HashMap<u64, u64>) -> CuResult<u64> {
        Err(CUDA_ERROR_NOT_SUPPORTED)
    }
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

    /// Alias an inherited raw library-handle value (the GOLDEN process's
    /// pointer, e.g. what cublasLtCreate returned there) to `real`, a handle
    /// created in THIS process — so a clone's calls on the inherited value
    /// resolve to a live handle instead of a foreign pointer. Default: no-op.
    fn lib_handle_alias(&mut self, _golden: u64, _real: u64) {}

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
    /// Fork-CLONE variant: `regions` are the clone's own (gpa, host_va, len);
    /// the backend reaches its LIVE pages through /proc/<pid>/mem. Default no-op.
    fn set_guest_ram_procmem(&mut self, _pid: u32, _regions: Vec<(u64, u64, u64)>) -> bool {
        false
    }
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
    /// Like `mem_set_access` but READ-ONLY (CU_MEM_ACCESS_FLAGS_PROT_READ). Used
    /// for `--share-weights` clones so a kernel that writes the shared frozen
    /// base faults loudly instead of silently corrupting every sibling clone
    /// that maps the same physical (the N>=3 concurrent-training nan).
    fn mem_set_access_ro(&mut self, _va: u64, _size: u64, _device: i32) -> CuResult<()> {
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
    /// Guest-minted VMM virtual handle → real handle (burst-path creates:
    /// `MemCreateVh` is fire-and-forget, so the guest never sees the real).
    vmm_vhandles: HashMap<u64, u64>,
    /// Host GPU this session is pinned to (guest device 0 maps here; the
    /// guest sees exactly one device). (0, false) = unpinned legacy behavior.
    device_base: i32,
    device_pinned: bool,
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
    /// Path 3: this session's VMM layout (reservations + maps→physical handle),
    /// handed off so a clone worker reconstructs memory at the golden's VAs (M2).
    golden_layout: std::sync::Arc<LayoutCell>,
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
    /// P3b capture-replay recording. `Some((capture stream vh, recorded op
    /// payloads))` while a stream capture is active on this session. Every
    /// capturable op (kernel launch, library call, async memset/memcpy, event
    /// op) issued during the window is recorded verbatim (wire bytes) so a
    /// clone can RE-CAPTURE the same sequence in its own context — the robust
    /// alternative to node-by-node graph rebuild, which can't reconstruct
    /// library-API (cuBLAS) kernels or non-kernel nodes.
    capture_rec: Option<(u64, Vec<Vec<u8>>)>,
    /// Worker-side (clone) inherited capture-replay logs, keyed by the golden's
    /// exec vhandle: the ordered op payloads to re-capture on first launch.
    /// Drained from the layout at clone resume.
    clone_graph_oplogs: HashMap<u64, Vec<Vec<u8>>>,
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
        if worker_module_take(m) {
            let _ = b.module_unload(m);
        }
    }
    for st in std::mem::take(&mut sess.owned_streams) {
        if worker_handle_take(&WORKER_STREAMS, st) {
            let _ = b.stream_destroy(st);
        }
    }
    for e in std::mem::take(&mut sess.owned_events) {
        if worker_handle_take(&WORKER_EVENTS, e) {
            let _ = b.event_destroy(e);
        }
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

/// Path 3 (address-preserving per-clone-process isolation) mode. When set, the
/// golden's VMM physical is created IPC-exportable so a clone worker process can
/// share/copy it at the golden's exact VA. Off = legacy shared-context path.
fn path3_enabled() -> bool {
    std::env::var_os("SMOLVM_CUDA_FORK_WORKERS").is_some()
}

/// Path 3 density opt-in: a clone worker SHARES the golden's loaded (weight)
/// VMM ranges read-only (IPC-import without copy) instead of privately copying
/// them. Off by default (the proven path privately copies every range —
/// correct + isolated but N copies of the weights).
pub fn path3_share_weights_enabled() -> bool {
    std::env::var_os("SMOLVM_CUDA_FORK_SHARE_WEIGHTS").is_some()
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

/// P3b capture-replay: record the golden's capture-window ops and re-capture
/// them in a clone at first launch (with an eager warmup pass so library
/// handles bind their streams/workspaces outside the capture window). ON by
/// default: a worker-process clone can never launch the golden's exec
/// verbatim (the CUgraphExec is process-local), and node rebuild can't
/// reproduce library-emitted kernels — replay is the only correct path.
/// `SMOLVM_CUDA_CLONE_GRAPH_REPLAY=0` disables (falls back to node
/// rebuild/patch, known-broken for library graphs).
fn clone_graph_replay_enabled() -> bool {
    !matches!(
        std::env::var("SMOLVM_CUDA_CLONE_GRAPH_REPLAY").as_deref(),
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
/// Path 3: the golden's VMM layout, handed off (via [`LAYOUT_HANDOFF`]) so a clone
/// worker process reconstructs memory at the golden's EXACT VAs (M2). Reservations
/// (va→size) it re-reserves; maps (va→(size, physical handle)) whose handle the
/// daemon exports to an fd for the clone to IPC-import/copy at that VA.
/// Per-chunk H2D upload record for the share-safety verdict (see
/// `GoldenLayout::maps`). `segs` = sorted, disjoint, chunk-relative
/// `(start, end, crc)` of every uploaded range (`crc == 0` marks a segment
/// whose bytes weren't dispatch-visible — shm/GPA H2D — and therefore can
/// never be verified). `verified` caches the fork-time content check.
#[derive(Default, Clone)]
struct ChunkCover {
    size: u64,
    handle: u64,
    /// The GUEST-visible handle value for this chunk (differs from `handle`
    /// when the guest created it under a burst virtual handle): what the
    /// clone's inherited MemMap/MemRelease carry, so the worker's translation
    /// table must be keyed by it.
    ghandle: u64,
    segs: Vec<(u64, u64, u64)>,
    verified: Option<bool>,
}

impl ChunkCover {
    /// Upload segments tile the chunk exactly and every segment is verifiable.
    fn covered_exactly(&self) -> bool {
        let mut expect = 0;
        for &(s, e, crc) in &self.segs {
            if s != expect || crc == 0 {
                return false;
            }
            expect = e;
        }
        expect == self.size
    }
}

#[derive(Default)]
struct GoldenLayout {
    reservations: HashMap<u64, u64>,
    /// va → per-chunk H2D coverage + share verdict. A chunk is a share
    /// CANDIDATE only if its recorded upload segments tile it exactly; it is
    /// share-SAFE only once the daemon verifies (at fork time) that its device
    /// content still equals what the H2Ds uploaded, byte for byte. Coverage
    /// alone is NOT enough: under `expandable_segments` torch frees weight
    /// bytes and reuses them for MUTABLE tensors (proven: LoRA adapters inside
    /// fully H2D-covered chunks — the bitsandbytes optimizer then writes the
    /// shared physical and the update leaks into every later fork; also RMS
    /// LayerNorm activations packed into partial chunks). A kernel write
    /// changes content → CRC mismatch → the chunk degrades to private.
    maps: HashMap<u64, ChunkCover>,
    /// M3a: golden module handle → module image bytes (to reload in the worker).
    modules: HashMap<u64, Vec<u8>>,
    /// M3a: golden function handle → (module handle, name) — the worker re-resolves
    /// it in its reloaded module and remaps the inherited raw CUfunction handle.
    functions: HashMap<u64, (u64, String)>,
    /// Function attributes the golden set (`cuFuncSetAttribute`) — chiefly
    /// FlashAttention's MaxDynamicSharedMemorySize opt-in, applied once at
    /// library import. Per-context state: a worker's re-resolved function
    /// reverts to the 48KB default and every large-smem launch fails with
    /// "invalid argument" until these are replayed.
    func_attrs: HashMap<u64, Vec<(i32, i32)>>,
    /// M3a: golden stream handle → create flags (the worker recreates + remaps).
    streams: HashMap<u64, u32>,
    /// M3a: golden event handle → create flags (the worker recreates + remaps).
    events: HashMap<u64, u32>,
    /// M3b: captured CUDA graphs to rebuild in a clone worker. Each entry is
    /// `(guest virtual graph handle, guest virtual exec handle, portable graph)`,
    /// recorded at the golden's `GraphInstantiate` under Path 3. The worker
    /// rebuilds the graph in its own context and maps both virtual handles to
    /// its rebuilt reals, so the clone's inherited `GraphLaunch` resolves.
    graphs: Vec<(u64, u64, GraphSer)>,
    /// P3b: capture-replay op-logs, `(graph_vh, exec_vh, ordered op payloads)`.
    /// The worker re-captures the recorded ops in its own context instead of
    /// rebuilding nodes — the only path that reproduces cuBLAS-kernel and
    /// non-kernel graph nodes. Preferred over `graphs` when present for an exec.
    graph_oplogs: Vec<(u64, u64, Vec<Vec<u8>>)>,
    /// P3b: capture recordings finished (EndCapture) but not yet instantiated,
    /// keyed by graph_vh; moved into `graph_oplogs` with the exec_vh at
    /// GraphInstantiate.
    pending_oplogs: HashMap<u64, Vec<Vec<u8>>>,
    /// Top-level library handles (cuBLAS/cuBLASLt/cuDNN contexts) the golden
    /// created, as `(lib, func, guest handle value, create args)`. Library
    /// handles are process-local; a clone worker replays each create in ITS
    /// process and maps the inherited value to its own handle — otherwise the
    /// clone's first post-fork cuBLASLt call on a pre-fork handle fails
    /// CUBLAS_STATUS_NOT_INITIALIZED (or worse, dereferences a foreign
    /// pointer). Only context-level creates are recorded; descriptors are
    /// transient and recreated by the workload itself.
    lib_handles: Vec<(u8, u16, u64, Vec<u8>)>,
    /// Host GPU the golden is pinned to — clones must reconstruct on it.
    device_base: i32,
}
type LayoutCell = std::sync::Mutex<GoldenLayout>;
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
/// Worker-mode handoff: the golden's live non-VMM (`cudaMalloc`) allocations,
/// read from the daemon-process registry. The daemon stages private copies of
/// these for a clone worker — a plain-torch golden (no expandable_segments)
/// keeps ALL its tensors here, and without the staging a worker-mode clone
/// faults on its first touch of any pre-fork buffer.
pub fn alloc_handoff_snapshot(token: u64) -> Option<Vec<(u64, u64, bool)>> {
    dptr_handoff_snapshot(token)
}

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

/// Path 3 (M2): the golden's VMM layout, keyed by lineage token, so the daemon
/// can gather it (reservations + maps→handle) when spawning a clone worker.
static LAYOUT_HANDOFF: std::sync::Mutex<Option<HashMap<u64, std::sync::Weak<LayoutCell>>>> =
    std::sync::Mutex::new(None);

fn layout_handoff_register(l: &std::sync::Arc<LayoutCell>, my_token: u64) {
    let mut reg = LAYOUT_HANDOFF.lock().unwrap();
    let reg = reg.get_or_insert_with(HashMap::new);
    reg.retain(|_, w| w.strong_count() > 0);
    reg.insert(my_token, std::sync::Arc::downgrade(l));
}

/// The live layout registered under `token`, for a resuming sibling channel to
/// SHARE (same guest process → one layout; see the Init handler).
fn layout_handoff_adopt(token: u64) -> Option<std::sync::Arc<LayoutCell>> {
    LAYOUT_HANDOFF
        .lock()
        .unwrap()
        .as_ref()?
        .get(&token)?
        .upgrade()
}

/// One VMM chunk in the fork handoff (see [`layout_handoff_snapshot`]).
pub struct HandoffChunk {
    pub va: u64,
    pub size: u64,
    pub handle: u64,
    /// Guest-visible handle value (a burst virtual handle, or `handle` when
    /// the guest created it synchronously) — the clone's inherited ops carry
    /// this, so the worker's translation table is keyed by it.
    pub ghandle: u64,
    /// Upload segments tile the chunk exactly (share CANDIDATE — safe to share
    /// only after fork-time content verification against `segs`).
    pub candidate: bool,
    /// Chunk-relative `(start, end, crc)` upload segments (crc from [`fnv64`]).
    pub segs: Vec<(u64, u64, u64)>,
    /// Cached fork-time content-verification verdict (golden frozen → stable).
    pub verified: Option<bool>,
}

/// `(reservations: [(va,size)], chunks)` for `token`'s golden.
#[allow(clippy::type_complexity)]
pub fn layout_handoff_snapshot(token: u64) -> Option<(Vec<(u64, u64)>, Vec<HandoffChunk>, i32)> {
    let reg = LAYOUT_HANDOFF.lock().unwrap();
    let l = reg.as_ref()?.get(&token)?.upgrade()?;
    let g = l.lock().unwrap();
    let resvs = g.reservations.iter().map(|(&v, &s)| (v, s)).collect();
    let maps = g
        .maps
        .iter()
        .map(|(&va, c)| HandoffChunk {
            va,
            size: c.size,
            handle: c.handle,
            ghandle: c.ghandle,
            candidate: c.covered_exactly(),
            segs: c.segs.clone(),
            verified: c.verified,
        })
        .collect();
    Some((resvs, maps, g.device_base))
}

/// Cache the fork-time content-verification verdict for `va` in `token`'s
/// golden layout, so later forks of the (frozen) golden skip the D2H+CRC pass.
pub fn layout_set_share_verdict(token: u64, va: u64, ok: bool) {
    let reg = LAYOUT_HANDOFF.lock().unwrap();
    let Some(l) = reg
        .as_ref()
        .and_then(|r| r.get(&token))
        .and_then(|w| w.upgrade())
    else {
        return;
    };
    let mut g = l.lock().unwrap();
    if let Some(c) = g.maps.get_mut(&va) {
        c.verified = Some(ok);
    }
}

/// M3a: golden handle-reconstruction snapshot for `token`'s golden —
/// `(modules: [(handle, image)], functions: [(handle, module, name)],
///   streams: [(handle, flags)], events: [(handle, flags)])`. The worker
/// reloads modules / re-resolves functions / recreates streams+events, then
/// remaps the clone's inherited raw handles to its own.
#[allow(clippy::type_complexity)]
pub fn module_handoff_snapshot(
    token: u64,
) -> Option<(
    Vec<(u64, Vec<u8>)>,
    Vec<FuncMeta>,
    Vec<(u64, u32)>,
    Vec<(u64, u32)>,
    Vec<(u64, u64, GraphSer)>,
    Vec<(u8, u16, u64, Vec<u8>)>,
)> {
    let reg = LAYOUT_HANDOFF.lock().unwrap();
    let l = reg.as_ref()?.get(&token)?.upgrade()?;
    let g = l.lock().unwrap();
    let modules = g.modules.iter().map(|(&h, i)| (h, i.clone())).collect();
    let funcs = g
        .functions
        .iter()
        .map(|(&h, (m, n))| {
            (
                h,
                *m,
                n.clone(),
                g.func_attrs.get(&h).cloned().unwrap_or_default(),
            )
        })
        .collect();
    let streams = g.streams.iter().map(|(&h, &f)| (h, f)).collect();
    let events = g.events.iter().map(|(&h, &f)| (h, f)).collect();
    let graphs = g.graphs.clone();
    let lib_handles = g.lib_handles.clone();
    Some((modules, funcs, streams, events, graphs, lib_handles))
}

/// P3b: capture-replay op-logs, `(graph_vh, exec_vh, ordered op payloads)`.
type GraphOplogs = Vec<(u64, u64, Vec<Vec<u8>>)>;

/// Live golden-layout tokens WITH fork content (staged modules / VMM maps /
/// library handles). Every guest channel's session registers a layout, but
/// only the golden's real one carries content — filtering to those makes the
/// eager warm-dial token inference unambiguous in the single-golden case.
pub fn layout_tokens() -> Vec<u64> {
    let reg = LAYOUT_HANDOFF.lock().unwrap();
    let Some(r) = reg.as_ref() else {
        return Vec::new();
    };
    // One golden's layout Arc is registered under EVERY channel token that
    // shares it — dedupe by Arc identity, keeping the smallest token per
    // distinct layout so the result is deterministic.
    let mut seen: Vec<(*const std::sync::Mutex<GoldenLayout>, u64)> = Vec::new();
    for (&t, w) in r.iter() {
        let Some(l) = w.upgrade() else { continue };
        let has_content = {
            let g = l.lock().unwrap();
            !g.modules.is_empty() || !g.maps.is_empty() || !g.lib_handles.is_empty()
        };
        if !has_content {
            continue;
        }
        let p = std::sync::Arc::as_ptr(&l);
        match seen.iter_mut().find(|(sp, _)| *sp == p) {
            Some((_, st)) => *st = (*st).min(t),
            None => seen.push((p, t)),
        }
    }
    seen.into_iter().map(|(_, t)| t).collect()
}

/// P3b: snapshot the golden's capture-replay op-logs for a clone worker,
/// `(graph_vh, exec_vh, ordered op payloads)`. Separate from
/// [`module_handoff_snapshot`] so its 6-tuple stays stable.
pub fn graph_oplogs_snapshot(token: u64) -> GraphOplogs {
    let reg = LAYOUT_HANDOFF.lock().unwrap();
    match reg
        .as_ref()
        .and_then(|r| r.get(&token))
        .and_then(|w| w.upgrade())
    {
        Some(l) => l.lock().unwrap().graph_oplogs.clone(),
        None => Vec::new(),
    }
}

/// P3b worker: install inherited capture-replay logs for this clone. Drained
/// into the serving session at clone resume; replayed lazily at first launch.
pub fn set_worker_graph_oplogs(v: GraphOplogs) {
    WORKER_GRAPH_OPLOGS.with(|r| *r.borrow_mut() = v);
}

thread_local! {
    static WORKER_GRAPH_OPLOGS: std::cell::RefCell<GraphOplogs> =
        const { std::cell::RefCell::new(Vec::new()) };
}

fn take_worker_graph_oplogs() -> GraphOplogs {
    WORKER_GRAPH_OPLOGS.with(|r| std::mem::take(&mut *r.borrow_mut()))
}

fn worker_graph_oplogs_peek() -> GraphOplogs {
    WORKER_GRAPH_OPLOGS.with(|r| r.borrow().clone())
}

/// P3b: pre-warm a clone worker at SPAWN, before any guest channel attaches —
/// eagerly reload every staged golden module and re-capture every inherited
/// graph into the process-wide registries. Serving sessions then ADOPT the
/// results at resume instead of paying reload/re-capture on the guest's first
/// CUDA call. Must run on the worker main thread AFTER module staging and
/// lib-handle replay (their thread-locals seed the scratch session).
/// Opt out: SMOLVM_CUDA_PREREPLAY=0.
pub fn prewarm_clone_worker(b: &mut dyn Backend) {
    if std::env::var("SMOLVM_CUDA_PREREPLAY").as_deref() == Ok("0") {
        return;
    }
    let t0 = std::time::Instant::now();
    let mods: Vec<u64> = MOD_IMAGES.with(|m| m.borrow().keys().copied().collect());
    let nmods = mods.len();
    for g in mods {
        let _ = xlat_mod(b, g);
    }
    let t_mods = t0.elapsed().as_millis();
    // Scratch session: replay dispatch needs pointer translation for
    // alloc-table clones (VMM clones are address-preserved / identity).
    let mut sess = Session {
        dptr_trans: worker_alloc_trans_snapshot(),
        ..Session::default()
    };
    gpu::set_lib_trans(&sess.dptr_trans);
    let oplogs = worker_graph_oplogs_peek();
    let (mut ok, mut failed) = (0u32, 0u32);
    for (_graph_vh, exec_vh, ops) in oplogs {
        if replayed_exec_get(exec_vh).is_some() {
            continue;
        }
        sess.clone_graph_oplogs.insert(exec_vh, ops);
        match replay_capture_graph(&mut sess, b, exec_vh) {
            Ok(exec) => {
                replayed_exec_put(exec_vh, exec);
                ok += 1;
            }
            Err(e) => {
                eprintln!("[p3b] spawn pre-replay exec {exec_vh:#x} failed st={e}");
                failed += 1;
            }
        }
    }
    eprintln!(
        "[p3b] spawn pre-warm: {nmods} module(s) in {t_mods} ms, {ok} graph(s) re-captured \
         ({failed} deferred) in {} ms total",
        t0.elapsed().as_millis()
    );
}

/// Replay the golden's top-level library-handle creates in THIS worker's
/// process. cuBLAS/cuDNN creates carry the guest-minted id in their args, so
/// the generated dispatch installs id→worker-handle itself; cuBLASLt returns a
/// raw pointer, so the golden's value is aliased to the worker's new handle
/// via [`Backend::lib_handle_alias`]. Returns how many creates succeeded.
pub fn replay_lib_handles(b: &mut dyn Backend, handles: &[(u8, u16, u64, Vec<u8>)]) -> usize {
    let empty = HashMap::new();
    let mut n = 0;
    for (lib, func, golden, args) in handles {
        match b.lib_call(*lib, *func, args, &empty) {
            Ok((0, out)) => {
                if *lib == 4 && out.len() >= 8 {
                    let real = u64::from_le_bytes(out[..8].try_into().unwrap());
                    b.lib_handle_alias(*golden, real);
                }
                n += 1;
            }
            Ok((st, _)) => {
                eprintln!("[lib-seed] create lib={lib} func={func} failed: status={st}")
            }
            Err(e) => eprintln!("[lib-seed] create lib={lib} func={func} failed: e={e}"),
        }
    }
    n
}

// M3a: per-worker (thread-local) translation of the golden's inherited raw
// module/function handles → this worker's reloaded ones. LAZY: a real model has
// ~400 modules; reloading them ALL synchronously before serving stalls the clone
// worker ~2s, and the clone's connection breaks during that silent window. So we
// hold the source images/metadata here and reload each module (and re-resolve
// each function) on FIRST USE at the raw_module/raw_fn_h choke points. Empty
// (identity) unless a Path-3 clone worker installed it via `set_handle_trans`.
type HandleMap = std::cell::RefCell<HashMap<u64, u64>>;
type ImageMap = std::cell::RefCell<HashMap<u64, Vec<u8>>>;
type MetaMap = std::cell::RefCell<HashMap<u64, (u64, String, Vec<(i32, i32)>)>>;
thread_local! {
    static FUNC_TRANS: HandleMap = std::cell::RefCell::new(HashMap::new());
    static MOD_TRANS: HandleMap = std::cell::RefCell::new(HashMap::new());
    static STREAM_TRANS: HandleMap = std::cell::RefCell::new(HashMap::new());
    static EVENT_TRANS: HandleMap = std::cell::RefCell::new(HashMap::new());
    // Lazy sources: golden module handle → image; golden fn handle → (module, name).
    static MOD_IMAGES: ImageMap = std::cell::RefCell::new(HashMap::new());
    static FUNC_META: MetaMap = std::cell::RefCell::new(HashMap::new());
    // M2: golden VMM physical handle → THIS worker's handle backing the same VA.
    // `None` = not a clone worker (raw passthrough). The clone frees inherited
    // chunks by their GOLDEN handle values; passing one raw into cuMemRelease in
    // the worker's context SEGFAULTS the driver (SEGV_MAPERR inside cuMemRelease).
    static VMM_TRANS: std::cell::RefCell<Option<HashMap<u64, u64>>> =
        const { std::cell::RefCell::new(None) };
    // M3b: guest virtual graph/exec handle → THIS worker's rebuilt graph/exec.
    // A clone forked at a graph-capture point inherits the guest's virtual
    // handles; the golden's reals are context-scoped, so `raw_graph` remaps them
    // to the worker's rebuilt reals here.
    static GRAPH_TRANS: HandleMap = std::cell::RefCell::new(HashMap::new());
}

/// Install a clone worker's golden→worker VMM physical-handle map (M2). Until
/// installed, MemMap/MemRelease pass handles through raw (daemon/golden path).
pub fn set_vmm_trans(map: HashMap<u64, u64>) {
    VMM_TRANS.with(|m| *m.borrow_mut() = Some(map));
}

/// Worker-mode: private copies of the golden's non-VMM (`cudaMalloc`)
/// allocations, made during reconstruction — `(golden_dptr, size, copy)`.
/// Process-global and NON-draining: every serving thread's isolate session
/// adopts the same translations at clone resume. This was a drained
/// thread_local, which made clone survival a scheduling lottery — a channel
/// served on any thread other than the one that staged the copies (or after
/// the spawn pre-warm's scratch session drained them) resumed with ZERO
/// translations, and its first kernel launch dereferenced untranslated golden
/// addresses (the intermittent one-dead-clone-per-fork bug: "unknown error"
/// or a worker SIGSEGV). No session takes ownership of the copies — they must
/// outlive every channel and are reclaimed when the worker process exits.
static WORKER_ALLOC_TRANS: std::sync::Mutex<Vec<(u64, u64, u64)>> =
    std::sync::Mutex::new(Vec::new());

pub fn set_worker_alloc_trans(v: Vec<(u64, u64, u64)>) {
    *WORKER_ALLOC_TRANS.lock().unwrap() = v;
}

/// Non-draining copy of the worker's staged alloc translations; used both to
/// seed late-attached channels and by every isolate session at clone resume.
pub fn worker_alloc_trans_snapshot() -> Vec<(u64, u64, u64)> {
    WORKER_ALLOC_TRANS.lock().unwrap().clone()
}

/// M3b: rebuild the golden's captured graphs in THIS worker's context and map
/// each `(graph_vh, exec_vh)` to the rebuilt reals, so the clone's inherited
/// `GraphLaunch` resolves. Kernel-node graphs only; a rebuild/instantiate
/// failure is logged and skipped (that graph's launch then fails loud). Returns
/// the number rebuilt. Call AFTER `set_handle_trans` (needs module reload) and
/// AFTER memory reconstruction (kernel-arg pointers reference golden VAs).
pub fn rebuild_clone_graphs(b: &mut dyn Backend, graphs: Vec<(u64, u64, GraphSer)>) -> usize {
    let mut n = 0;
    for (graph_vh, exec_vh, ser) in graphs {
        // Resolve each golden CUfunction to this worker's reloaded function.
        let mut funcs: HashMap<u64, u64> = HashMap::new();
        for node in &ser.nodes {
            if let std::collections::hash_map::Entry::Vacant(e) = funcs.entry(node.func) {
                let w = xlat_func(b, node.func);
                e.insert(w);
            }
        }
        // A func that resolved to 0 (reload failed) or back to its golden handle
        // (not in FUNC_META — e.g. cuBLAS kernels bound via the CUDA-12 library
        // API, which we don't track) is a FOREIGN-context handle. Passing it to
        // cuGraphAddKernelNode makes the driver dereference it -> SIGSEGV, which
        // crash-loops the worker. Skip the whole graph instead: the clone's
        // GraphLaunch then fails loud rather than taking down the process.
        let unresolved = funcs.iter().filter(|(g, w)| **w == 0 || *g == *w).count();
        if unresolved > 0 {
            eprintln!(
                "[graph-rebuild] skipping graph vh={graph_vh:#x}: {unresolved}/{} kernel funcs \
                 unresolved (not in FUNC_META); leaving inherited exec in place",
                funcs.len()
            );
            continue;
        }
        match b.graph_rebuild(&ser, &funcs) {
            Ok(wgraph) => match b.graph_instantiate(wgraph) {
                Ok(wexec) => {
                    GRAPH_TRANS.with(|m| {
                        let mut m = m.borrow_mut();
                        m.insert(graph_vh, wgraph);
                        m.insert(exec_vh, wexec);
                    });
                    n += 1;
                }
                Err(e) => eprintln!("[graph-rebuild] instantiate failed: e={e}"),
            },
            Err(e) => eprintln!("[graph-rebuild] rebuild failed: e={e}"),
        }
    }
    n
}

/// Install a clone worker's golden→worker handle reconstruction. Modules are
/// reloaded / functions re-resolved LAZILY from `mod_images` / `func_meta` at
/// first use; streams/events are already-recreated golden→worker maps (eager,
/// few). Clears any prior worker's caches.
/// One staged golden function: `(golden handle, golden module, name, attribute
/// replays)` — see [`module_handoff_snapshot`].
pub type FuncMeta = (u64, u64, String, Vec<(i32, i32)>);

pub fn set_handle_trans(
    mod_images: Vec<(u64, Vec<u8>)>,
    func_meta: Vec<FuncMeta>,
    streams: Vec<(u64, u64)>,
    events: Vec<(u64, u64)>,
) {
    fn put_h(cell: &'static std::thread::LocalKey<HandleMap>, v: Vec<(u64, u64)>) {
        cell.with(|m| {
            let mut m = m.borrow_mut();
            m.clear();
            m.extend(v);
        });
    }
    MOD_TRANS.with(|m| m.borrow_mut().clear());
    FUNC_TRANS.with(|m| m.borrow_mut().clear());
    MOD_IMAGES.with(|m| {
        let mut m = m.borrow_mut();
        m.clear();
        m.extend(mod_images.iter().cloned());
    });
    FUNC_META.with(|m| {
        let mut m = m.borrow_mut();
        m.clear();
        m.extend(
            func_meta
                .iter()
                .cloned()
                .map(|(f, gm, n, a)| (f, (gm, n, a))),
        );
    });
    // Process-global copies too, so a channel served on a thread that was
    // never seeded still lazy-resolves instead of leaking golden handles.
    *MOD_IMAGES_GLOBAL.lock().unwrap() = Some(mod_images.into_iter().collect());
    *FUNC_META_GLOBAL.lock().unwrap() = Some(
        func_meta
            .into_iter()
            .map(|(f, gm, n, a)| (f, (gm, n, a)))
            .collect(),
    );
    *STREAM_TRANS_GLOBAL.lock().unwrap() = Some(streams.iter().copied().collect());
    *EVENT_TRANS_GLOBAL.lock().unwrap() = Some(events.iter().copied().collect());
    put_h(&STREAM_TRANS, streams);
    put_h(&EVENT_TRANS, events);
}

/// Lazily reload the golden module `golden` in THIS worker's context (once),
/// caching golden→worker. Identity for a non-clone / unknown handle.
fn xlat_mod(b: &mut dyn Backend, golden: u64) -> u64 {
    if let Some(w) = MOD_TRANS.with(|m| m.borrow().get(&golden).copied()) {
        return w;
    }
    // Process-global registry: a module some OTHER thread already reloaded
    // (pre-warm on the resume thread, or a sibling channel's lazy load) is
    // reused, not loaded again — CUmodule handles are context-wide; only the
    // mapping was thread-local, which silently duplicated every module per
    // serve thread that touched it.
    if let Some(w) = MOD_TRANS_GLOBAL
        .lock()
        .unwrap()
        .as_ref()
        .and_then(|m| m.get(&golden).copied())
    {
        MOD_TRANS.with(|m| {
            m.borrow_mut().insert(golden, w);
        });
        return w;
    }
    let image = MOD_IMAGES
        .with(|m| m.borrow().get(&golden).cloned())
        .or_else(|| {
            // Unseeded thread: fall back to the process-global copy rather
            // than returning the golden handle (foreign-handle deref hazard).
            MOD_IMAGES_GLOBAL
                .lock()
                .unwrap()
                .as_ref()
                .and_then(|m| m.get(&golden).cloned())
        });
    let Some(mut image) = image else {
        return golden;
    };
    // Binary images (ELF cubin / fatbin) must reload BYTE-IDENTICAL to what the
    // golden loaded — appending anything diverges from the proven-loadable bytes
    // (sm90 fatbins failed 209 with a spurious trailing byte). Only PTX, which
    // cuModuleLoadData reads as a C string, needs a trailing NUL.
    let is_elf = image.starts_with(&[0x7f, b'E', b'L', b'F']);
    let is_fatbin = image.len() >= 4
        && u32::from_le_bytes([image[0], image[1], image[2], image[3]]) == 0xba55ed50;
    if !is_elf && !is_fatbin && image.last() != Some(&0) {
        image.push(0);
    }
    match b.module_load_data(&image) {
        Ok(w) => {
            MOD_TRANS.with(|m| {
                m.borrow_mut().insert(golden, w);
            });
            MOD_TRANS_GLOBAL
                .lock()
                .unwrap()
                .get_or_insert_with(HashMap::new)
                .insert(golden, w);
            worker_module_register(w);
            w
        }
        Err(e) => {
            static RELOAD_FAILS: std::sync::atomic::AtomicU64 =
                std::sync::atomic::AtomicU64::new(0);
            let n = RELOAD_FAILS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if n < 8 {
                let head: Vec<String> = image.iter().take(12).map(|b| format!("{b:02x}")).collect();
                eprintln!(
                    "[M3a-lazy] module reload failed: e={e} len={} elf={is_elf} fatbin={is_fatbin} head={}",
                    image.len(),
                    head.join("")
                );
                if std::env::var_os("SMOLVM_CUDA_DUMP_FAILMOD").is_some() {
                    let p = format!("/tmp/smolvm/failmod-{golden:x}.bin");
                    let _ = std::fs::write(&p, &image);
                    // Context health right after the failed load: a poisoned
                    // (sticky-fault) context errors on sync/alloc too; a healthy
                    // one pins the failure on cuModuleLoadData itself.
                    let sync = b.ctx_synchronize().err();
                    let alloc = match b.mem_alloc(1 << 20) {
                        Ok(d) => {
                            let _ = b.mem_free(d);
                            None
                        }
                        Err(e) => Some(e),
                    };
                    eprintln!(
                        "[M3a-lazy] dumped {p}; post-fail probes: sync_err={sync:?} alloc_err={alloc:?}"
                    );
                }
            } else if n == 8 {
                eprintln!("[M3a-lazy] module reload failing repeatedly (e={e}); further reports suppressed");
            }
            // NULL, not the golden handle: the driver rejects a NULL module with
            // a clean error, but DEREFERENCES a foreign-context handle (SIGSEGV
            // in cuModuleGetFunction — seen when a sticky fault poisoned reloads).
            0
        }
    }
}

/// Lazily re-resolve the golden function `golden` (loading its module first if
/// needed), caching golden→worker. Identity for a non-clone / unknown handle.
fn xlat_func(b: &mut dyn Backend, golden: u64) -> u64 {
    if let Some(w) = FUNC_TRANS.with(|m| m.borrow().get(&golden).copied()) {
        return w;
    }
    let meta = FUNC_META
        .with(|m| m.borrow().get(&golden).cloned())
        .or_else(|| {
            // Unseeded thread: process-global fallback (see MOD_IMAGES_GLOBAL) —
            // returning the golden handle here launched foreign functions
            // ("invalid argument") on channels served by unseeded threads.
            FUNC_META_GLOBAL
                .lock()
                .unwrap()
                .as_ref()
                .and_then(|m| m.get(&golden).cloned())
        });
    let Some((gm, name, attrs)) = meta else {
        return golden;
    };
    let wm = xlat_mod(b, gm);
    if wm == 0 {
        return 0; // module reload failed; a NULL function errors cleanly
    }
    match b.module_get_function(wm, &name) {
        Ok(w) => {
            // Re-apply the golden's per-function attributes in THIS context —
            // without FlashAttention's MaxDynamicSharedMemorySize opt-in, its
            // decode kernels launch with >48KB smem and fail "invalid argument".
            for &(a, v) in &attrs {
                if let Err(e) = b.func_set_attribute(w, a, v) {
                    eprintln!("[M3a-lazy] func attr replay failed: name={name} attr={a} e={e}");
                }
            }
            FUNC_TRANS.with(|m| {
                m.borrow_mut().insert(golden, w);
            });
            w
        }
        Err(e) => {
            eprintln!("[M3a-lazy] function re-resolve failed: name={name} e={e}");
            // NULL, not the golden handle (see xlat_mod): fail with a clean
            // driver error rather than a foreign-handle dereference.
            0
        }
    }
}
// Per-connection host ring directory for file-backed rings, advertised by
// the per-VM proxy at connect (SMVRDIR1 preamble) and installed by the
// serving thread before entering `serve`. Thread-local: one serve thread per
// connection.
thread_local! {
    static RING_DIR: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// Install (or clear) the file-ring host directory for THIS serve thread.
pub fn ring_dir_set(dir: Option<String>) {
    RING_DIR.with(|r| *r.borrow_mut() = dir);
}

#[cfg(unix)]
fn ring_dir_get() -> Option<String> {
    RING_DIR.with(|r| r.borrow().clone())
}

fn xlat_stream(h: u64) -> u64 {
    // Thread-local first (P3b replay overrides are deliberately per-thread),
    // then the process-global map for channels served on unseeded threads.
    if let Some(w) = STREAM_TRANS.with(|m| m.borrow().get(&h).copied()) {
        return w;
    }
    STREAM_TRANS_GLOBAL
        .lock()
        .unwrap()
        .as_ref()
        .and_then(|m| m.get(&h).copied())
        .unwrap_or(h)
}
/// P3b: temporarily redirect a golden stream to a private replay stream.
/// Returns the previous mapping so the caller can restore it.
fn stream_trans_override(golden: u64, private: u64) -> Option<u64> {
    STREAM_TRANS.with(|m| m.borrow_mut().insert(golden, private))
}
fn stream_trans_restore(golden: u64, prev: Option<u64>) {
    STREAM_TRANS.with(|m| {
        let mut b = m.borrow_mut();
        match prev {
            Some(p) => {
                b.insert(golden, p);
            }
            None => {
                b.remove(&golden);
            }
        }
    });
}
fn xlat_event(h: u64) -> u64 {
    if let Some(w) = EVENT_TRANS.with(|m| m.borrow().get(&h).copied()) {
        return w;
    }
    EVENT_TRANS_GLOBAL
        .lock()
        .unwrap()
        .as_ref()
        .and_then(|m| m.get(&h).copied())
        .unwrap_or(h)
}

/// Path 3: record this H2D's coverage (+ content CRC) into every golden VMM
/// chunk it overlaps (see `GoldenLayout.maps`). No-op unless Path 3 is
/// tracking a golden layout.
fn mark_loaded_vmm(layout: &LayoutCell, dptr: u64, nbytes: u64, data: Option<&[u8]>) {
    let end = dptr.saturating_add(nbytes);
    let mut g = layout.lock().unwrap();
    for (&base, c) in g.maps.iter_mut() {
        let (abs_s, abs_e) = (dptr.max(base), end.min(base + c.size));
        if abs_s >= abs_e {
            continue;
        }
        // CRC the PER-CHUNK SLICE of the payload: one H2D spans many chunks,
        // and each chunk must record the hash of its own bytes (crc 0 =
        // unverifiable → never shared; used when bytes aren't dispatch-visible).
        let crc = data.map_or(0, |d| {
            fnv64(&d[(abs_s - dptr) as usize..(abs_e - dptr) as usize])
        });
        let (s, e) = (abs_s - base, abs_e - base);
        // An overlapping re-upload invalidates the prior segment's CRC for its
        // surviving bytes, so overlapped segments are dropped whole
        // (conservative: lost coverage → the chunk stays private).
        c.segs.retain(|&(a, b, _)| b <= s || a >= e);
        c.segs.push((s, e, crc));
        c.segs.sort_unstable();
        c.verified = None;
    }
}

/// FNV-1a 64-bit content hash (0 remapped to 1 — segment CRC 0 means
/// "unverifiable", reserved for uploads whose bytes dispatch can't see).
/// Process-wide module-image cache key: content hash + length + first/last
/// bytes (the extra fields guard fnv collisions — a wrong module would be a
/// silent catastrophe).
#[derive(PartialEq, Eq, Hash, Clone)]
struct ModuleCacheKey {
    fnv: u64,
    len: u64,
    head: [u8; 8],
    tail: [u8; 8],
}

fn module_cache() -> &'static std::sync::Mutex<HashMap<ModuleCacheKey, std::sync::Arc<Vec<u8>>>> {
    static C: std::sync::OnceLock<
        std::sync::Mutex<HashMap<ModuleCacheKey, std::sync::Arc<Vec<u8>>>>,
    > = std::sync::OnceLock::new();
    C.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

fn module_cache_budget() -> u64 {
    static B: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *B.get_or_init(|| {
        std::env::var("SMOLVM_CUDA_MODCACHE_MB")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(2048u64)
            * 1024
            * 1024
    })
}

fn module_cache_put(image: &[u8]) {
    if image.len() < 64 {
        return;
    }
    let mut c = module_cache().lock().unwrap();
    let used: u64 = c.values().map(|v| v.len() as u64).sum();
    if used + image.len() as u64 > module_cache_budget() {
        return; // over budget: first-come wins; the big early fatbins matter most
    }
    let key = ModuleCacheKey {
        fnv: fnv64(image),
        len: image.len() as u64,
        head: image[..8].try_into().unwrap(),
        tail: image[image.len() - 8..].try_into().unwrap(),
    };
    c.entry(key)
        .or_insert_with(|| std::sync::Arc::new(image.to_vec()));
}

fn module_cache_get(key: &ModuleCacheKey) -> Option<std::sync::Arc<Vec<u8>>> {
    module_cache().lock().unwrap().get(key).cloned()
}

pub fn fnv64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h.max(1)
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
        sort_trans(&mut sess.dptr_trans); // xlat binary-searches by base
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
/// Translate one inherited device pointer through the (base-sorted) table.
/// Binary search: this runs per 8-byte window of every kernel-param blob on
/// the serve thread — a linear scan here was O(windows x table) per launch,
/// a tax only clones paid (goldens have an empty table).
fn xlat(trans: &[(u64, u64, u64)], p: u64) -> u64 {
    if p == 0 || trans.is_empty() {
        return p;
    }
    let i = trans.partition_point(|&(base, _, _)| base <= p);
    if i > 0 {
        let (base, size, copy) = trans[i - 1];
        if p < base + size {
            return copy + (p - base);
        }
    }
    p
}

/// Keep `dptr_trans` base-sorted (see [`xlat`]). Call after any append.
fn sort_trans(trans: &mut [(u64, u64, u64)]) {
    trans.sort_unstable_by_key(|t| t.0);
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

/// Oplog helper: for LibCall payloads, decode "(lib,func)" for attribution.
fn libcall_tag(p: &[u8]) -> String {
    if p.first() == Some(&0xA0) && p.len() >= 4 {
        let lib = p[1];
        let func = u16::from_le_bytes([p[2], p[3]]);
        format!(" lib={lib} func={func}")
    } else {
        String::new()
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
                    eprintln!(
                        "[op~] p{} 0x{:02x} len={}{}",
                        std::process::id(),
                        payload[1],
                        payload.len(),
                        libcall_tag(&payload[1..])
                    );
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
                    eprintln!(
                        "[op] p{} 0x{:02x} len={}{}",
                        std::process::id(),
                        payload[0],
                        payload.len(),
                        libcall_tag(&payload)
                    );
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
                // File-backed rings (DAX clone transport): the rings live in a
                // file inside the host dir the per-VM proxy advertised; guest
                // and host mmap the same page-cache pages (coherent), which is
                // how a COW clone gets ring speed without guest-RAM visibility.
                if let Request::RingSetupFile {
                    page_size,
                    req_n,
                    resp_n,
                    bounce_n,
                    fname,
                } = req
                {
                    #[cfg(unix)]
                    let mapped = HostRings::map_file(page_size, req_n, resp_n, bounce_n, &fname);
                    #[cfg(not(unix))]
                    let mapped: Result<HostRings, i32> = {
                        let _ = (page_size, req_n, resp_n, bounce_n, &fname);
                        Err(801)
                    };
                    match mapped {
                        Ok(rings) => {
                            write_msg(&mut stream, &encode_response(0, &Response::Ok))?;
                            eprintln!(
                                "[ring-file] file rings active ({req_n}/{resp_n}/{bounce_n} pages)"
                            );
                            return serve_rings(stream, backend, sess, quiet_sticky, rings);
                        }
                        Err(code) => {
                            eprintln!("[ring-file] setup rejected code={code}");
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

    /// File-backed variant (DAX clone rings): mmap `fname` (a bare name inside
    /// the per-connection advertised ring dir) MAP_SHARED and slice it into
    /// req/resp/bounce page lists. The guest mmaps the SAME file through its
    /// dax mount, so both sides touch the same host page-cache pages.
    #[cfg(unix)]
    fn map_file(
        page_size: u32,
        req_n: u32,
        resp_n: u32,
        bounce_n: u32,
        fname: &[u8],
    ) -> Result<HostRings, i32> {
        let ps = page_size as usize;
        if ps < crate::ring::HEADER_SIZE + crate::ring::RECORD_SIZE
            || req_n == 0
            || resp_n == 0
            || req_n > 1024
            || resp_n > 1024
            || bounce_n > 4096
        {
            return Err(1);
        }
        let Some(dir) = ring_dir_get() else {
            return Err(801); // no advert on this connection -> not supported
        };
        let name = std::str::from_utf8(fname).map_err(|_| 1)?;
        // Bare names only: the guest must not traverse out of the ring dir.
        if name.is_empty() || name.contains('/') || name.contains("..") {
            return Err(1);
        }
        let total = (req_n + resp_n + bounce_n) as usize * ps;
        let path = std::path::Path::new(&dir).join(name);
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|_| 1)?;
        if f.metadata()
            .map(|m| (m.len() as usize) < total)
            .unwrap_or(true)
        {
            return Err(1);
        }
        // SAFETY: mapping a regular file we just validated, MAP_SHARED so the
        // guest's dax view and ours are the same physical pages.
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                total,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                std::os::unix::io::AsRawFd::as_raw_fd(&f),
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(1);
        }
        let pages = |start: usize, n: usize| -> Vec<*mut u8> {
            (0..n)
                .map(|i| (base as usize + (start + i) * ps) as *mut u8)
                .collect()
        };
        let req = pages(0, req_n as usize);
        let resp = pages(req_n as usize, resp_n as usize);
        let bounce = pages((req_n + resp_n) as usize, bounce_n as usize);
        // The mapping (and an O_RDWR fd via the mmap ref) lives for the
        // connection; the file itself can be unlinked by either side later.
        // SAFETY: pages are backed by the shared file mapping for the
        // connection's lifetime (never munmap'd until process exit).
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
    // Phase profiler (SMOLVM_CUDA_HOST_PROF=1): where the serve thread's wall
    // time goes — idle (waiting on the guest), frame decode, dispatch (the
    // CUDA call), respond. Dumped every 8192 ops so the per-learner gap can
    // be attributed to guest-bound vs host-bound vs GPU-bound time.
    struct Prof {
        on: bool,
        idle: u128,
        decode: u128,
        exec: u128,
        resp: u128,
        ops: u64,
    }
    impl Prof {
        fn dump_maybe(&mut self) {
            if self.on && self.ops.is_multiple_of(8192) && self.ops > 0 {
                eprintln!(
                    "[serve-prof] ops={} idle={}ms decode={}ms exec={}ms respond={}ms",
                    self.ops,
                    self.idle / 1000,
                    self.decode / 1000,
                    self.exec / 1000,
                    self.resp / 1000
                );
            }
        }
    }
    let mut prof = Prof {
        on: std::env::var_os("SMOLVM_CUDA_HOST_PROF").is_some(),
        idle: 0,
        decode: 0,
        exec: 0,
        resp: 0,
        ops: 0,
    };
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
        let t_idle = std::time::Instant::now();
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
        if prof.on {
            prof.idle += t_idle.elapsed().as_micros();
        }
        let t_dec = std::time::Instant::now();
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
                    eprintln!(
                        "[op~] p{} 0x{:02x} len={}{}",
                        std::process::id(),
                        frame[1],
                        frame.len(),
                        libcall_tag(&frame[1..])
                    );
                }
                if prof.on {
                    prof.decode += t_dec.elapsed().as_micros();
                }
                let t_exec = std::time::Instant::now();
                let (status, _) = dispatch(sess, backend, req);
                if prof.on {
                    prof.exec += t_exec.elapsed().as_micros();
                    prof.ops += 1;
                    prof.dump_maybe();
                }
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
                    eprintln!(
                        "[op] p{} 0x{:02x} len={}{}",
                        std::process::id(),
                        frame[0],
                        frame.len(),
                        libcall_tag(&frame)
                    );
                }
                if prof.on {
                    prof.decode += t_dec.elapsed().as_micros();
                }
                let t_exec = std::time::Instant::now();
                let (status, resp) = dispatch(sess, backend, req);
                if prof.on {
                    prof.exec += t_exec.elapsed().as_micros();
                }
                if status != 0 && oplog {
                    eprintln!("[op!] status={status}");
                }
                let t_resp = std::time::Instant::now();
                respond(&rings, &mut stream, &encode_response(status, &resp))?;
                if prof.on {
                    prof.resp += t_resp.elapsed().as_micros();
                    prof.ops += 1;
                    prof.dump_maybe();
                }
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

/// Debug op trace (`SMOLVM_CUDA_OPTRACE=<path>`): appends one line per traced
/// memory/launch op with pid + post-translation params + status, so a fork
/// investigation can see exactly which PROCESS executed which op on which
/// address. Off (None) unless the env var is set.
fn optrace_summary(req: &Request) -> Option<String> {
    static PATH: std::sync::OnceLock<Option<std::path::PathBuf>> = std::sync::OnceLock::new();
    PATH.get_or_init(|| std::env::var_os("SMOLVM_CUDA_OPTRACE").map(Into::into))
        .as_ref()?;
    Some(match req {
        Request::MemAlloc { bytes } => format!("MemAlloc bytes={bytes:#x}"),
        Request::MemFree { dptr } => format!("MemFree dptr={dptr:#x}"),
        Request::MemcpyHtoD { dptr, data, .. } => {
            format!("HtoD dptr={dptr:#x} len={:#x}", data.len())
        }
        Request::MemcpyDtoH { dptr, bytes, .. } => format!("DtoH dptr={dptr:#x} len={bytes:#x}"),
        Request::MemcpyShmHtoD { dptr, size, .. } => {
            format!("ShmHtoD dptr={dptr:#x} len={size:#x}")
        }
        Request::MemcpyShmDtoH { dptr, size, .. } => {
            format!("ShmDtoH dptr={dptr:#x} len={size:#x}")
        }
        Request::MemcpyGpaHtoD { dptr, segments, .. } => {
            let len: u64 = segments.iter().map(|(_, l)| l).sum();
            format!("GpaHtoD dptr={dptr:#x} len={len:#x}")
        }
        Request::MemcpyGpaDtoH { dptr, segments, .. } => {
            let len: u64 = segments.iter().map(|(_, l)| l).sum();
            format!("GpaDtoH dptr={dptr:#x} len={len:#x}")
        }
        Request::MemcpyDtoD { dst, src, bytes } => {
            format!("DtoD dst={dst:#x} src={src:#x} len={bytes:#x}")
        }
        Request::MemcpyDtoDAsync {
            dst, src, bytes, ..
        } => format!("DtoDAsync dst={dst:#x} src={src:#x} len={bytes:#x}"),
        Request::MemsetD8 { dptr, value, bytes } => {
            format!("MemsetD8 dptr={dptr:#x} v={value} len={bytes:#x}")
        }
        Request::MemsetD8Async {
            dptr, value, bytes, ..
        } => format!("MemsetD8Async dptr={dptr:#x} v={value} len={bytes:#x}"),
        Request::LaunchKernel {
            function,
            grid,
            block,
            shared_bytes,
            params,
            ..
        } => {
            let args: Vec<String> = params
                .iter()
                .take(10)
                .map(|a| {
                    if a.len() >= 8 {
                        format!("{:#x}", u64::from_le_bytes(a[..8].try_into().unwrap()))
                    } else {
                        format!("<{}b>", a.len())
                    }
                })
                .collect();
            format!(
                "Launch fn={function:#x} grid={grid:?} block={block:?} smem={shared_bytes:#x} np={} args=[{}]",
                params.len(),
                args.join(" ")
            )
        }
        Request::GraphLaunch { graph_exec, .. } => format!("GraphLaunch exec={graph_exec:#x}"),
        Request::LibCall { lib, func, args } => {
            format!("LibCall lib={lib} func={func} alen={}", args.len())
        }
        Request::MemAddressReserve { size, .. } => format!("VmmReserve size={size:#x}"),
        Request::MemCreate { size, .. } => format!("VmmCreate size={size:#x}"),
        Request::MemCreateVh {
            size, handle_vh, ..
        } => {
            format!("VmmCreateVh size={size:#x} vh={handle_vh:#x}")
        }
        Request::MemMap {
            va, size, handle, ..
        } => {
            format!("VmmMap va={va:#x} size={size:#x} h={handle:#x}")
        }
        Request::MemSetAccess { va, size, .. } => format!("VmmAccess va={va:#x} size={size:#x}"),
        Request::MemUnmap { va, size } => format!("VmmUnmap va={va:#x} size={size:#x}"),
        Request::MemRelease { handle } => format!("VmmRelease h={handle:#x}"),
        Request::ModuleLoadData { image } => {
            let n = image.len();
            let head: Vec<String> = image.iter().take(4).map(|b| format!("{b:02x}")).collect();
            format!("ModuleLoadData len={n:#x} head={}", head.join(""))
        }
        // Catch-all: op byte only (re-encoding is debug-run-only cost), so a
        // failing op outside the detailed set above still shows up.
        other => format!(
            "Op0x{:02x}",
            encode_request(other).first().copied().unwrap_or(0)
        ),
    })
}

fn op_ring() -> &'static std::sync::Mutex<std::collections::VecDeque<String>> {
    static R: std::sync::OnceLock<std::sync::Mutex<std::collections::VecDeque<String>>> =
        std::sync::OnceLock::new();
    R.get_or_init(|| std::sync::Mutex::new(std::collections::VecDeque::with_capacity(80)))
}

fn op_ring_push(line: String) {
    if let Ok(mut r) = op_ring().try_lock() {
        if r.len() >= 64 {
            r.pop_front();
        }
        r.push_back(line);
    }
}

pub fn op_ring_dump() {
    if let Ok(r) = op_ring().try_lock() {
        eprintln!(
            "[op-ring] last {} ops before crash (oldest first):",
            r.len()
        );
        for (i, l) in r.iter().enumerate() {
            eprintln!("  [{i:02}] {l}");
        }
    }
}

fn optrace_write(line: &str, status: i32) {
    if std::env::var_os("SMOLVM_CUDA_OPTRACE").is_some() {
        op_ring_push(format!("{line} st={status}"));
    }
}

/// P3b: which requests belong INSIDE a capture window and must be recorded for
/// clone re-capture. Work-issuing ops only — handle bookkeeping (create/destroy)
/// and queries stay out of the graph. `CublasSetStream` is included so a
/// replayed GEMM lands on the re-capture stream.
fn is_capturable(req: &Request) -> bool {
    matches!(
        req,
        Request::LaunchKernel { .. }
            | Request::LibCall { .. }
            | Request::MemsetD8Async { .. }
            | Request::MemcpyDtoDAsync { .. }
            | Request::EventRecord { .. }
            | Request::StreamWaitEvent { .. }
    )
}

/// P3b: execs this worker process has already re-captured, keyed by the
/// inherited exec vhandle. Clone workers serve several sessions (one per
/// guest channel) that each adopt the same oplogs at resume — the registry
/// makes the re-capture happen once per process, with later sessions just
/// adopting the finished exec.
static REPLAYED_EXECS: std::sync::Mutex<Option<HashMap<u64, u64>>> = std::sync::Mutex::new(None);

/// Process-global golden-module → reloaded-module map (see `xlat_mod`). Safe
/// as a process global: golden handles are raw host pointers (unique), and a
/// clone worker owns exactly one CUDA context.
static MOD_TRANS_GLOBAL: std::sync::Mutex<Option<HashMap<u64, u64>>> = std::sync::Mutex::new(None);

/// Handles of modules THIS worker process loaded into ITS OWN context, across
/// every channel. A `ModuleUnload` whose resolved handle is NOT in here is a
/// module the worker never created — a golden-/foreign-context module the clone
/// inherited via COW guest RAM (or one already freed) — and `cuModuleUnload`
/// would deref a pointer valid only in another context, SIGSEGV-ing the driver.
/// Process-global (not per-session) so a module loaded on one channel unloads
/// correctly from another (no leak) while foreign handles are never touched.
static WORKER_MODULES: std::sync::Mutex<Option<std::collections::HashSet<u64>>> =
    std::sync::Mutex::new(None);
/// Streams and events this worker created in its OWN context — same rationale as
/// WORKER_MODULES: `cuStreamDestroy`/`cuEventDestroy` on a golden-/foreign-context
/// handle the clone inherited via COW would deref a pointer valid only in another
/// context. Process-global so a create on one channel destroys correctly from
/// another (no leak) while foreign handles are skipped.
static WORKER_STREAMS: std::sync::Mutex<Option<std::collections::HashSet<u64>>> =
    std::sync::Mutex::new(None);
static WORKER_EVENTS: std::sync::Mutex<Option<std::collections::HashSet<u64>>> =
    std::sync::Mutex::new(None);

/// Record a handle this worker just created in its own context.
fn worker_handle_register(reg: &std::sync::Mutex<Option<std::collections::HashSet<u64>>>, h: u64) {
    reg.lock()
        .unwrap()
        .get_or_insert_with(std::collections::HashSet::new)
        .insert(h);
}

/// Claim `h` for destroy: true (and forgets it, so a double-destroy is a safe
/// no-op) iff this worker created it; false for a foreign/inherited/already-freed
/// handle, which must NOT be passed to the driver's destroy call.
fn worker_handle_take(
    reg: &std::sync::Mutex<Option<std::collections::HashSet<u64>>>,
    h: u64,
) -> bool {
    reg.lock()
        .unwrap()
        .as_mut()
        .map(|s| s.remove(&h))
        .unwrap_or(false)
}

fn worker_module_register(raw: u64) {
    worker_handle_register(&WORKER_MODULES, raw);
}
fn worker_module_take(raw: u64) -> bool {
    worker_handle_take(&WORKER_MODULES, raw)
}

/// Process-global copies of the lazy-resolve INPUTS (module images + function
/// metadata). The thread-local copies are seeded per serving thread; a channel
/// served on an unseeded thread previously fell through the lazy paths and
/// passed RAW GOLDEN HANDLES to the driver — launch-time "invalid argument"
/// at best, a SIGSEGV inside `cuModuleGetFunction` (foreign-handle deref) at
/// worst: the intermittent per-clone worker crash loop.
static MOD_IMAGES_GLOBAL: std::sync::Mutex<Option<HashMap<u64, Vec<u8>>>> =
    std::sync::Mutex::new(None);
#[allow(clippy::type_complexity)]
static FUNC_META_GLOBAL: std::sync::Mutex<Option<HashMap<u64, (u64, String, Vec<(i32, i32)>)>>> =
    std::sync::Mutex::new(None);
/// Golden→worker stream/event maps, process-global fallbacks for unseeded
/// serving threads (thread-locals stay authoritative — P3b replay overrides
/// stream mappings per-thread on purpose).
static STREAM_TRANS_GLOBAL: std::sync::Mutex<Option<HashMap<u64, u64>>> =
    std::sync::Mutex::new(None);
static EVENT_TRANS_GLOBAL: std::sync::Mutex<Option<HashMap<u64, u64>>> =
    std::sync::Mutex::new(None);

fn replayed_exec_get(exec_vh: u64) -> Option<u64> {
    REPLAYED_EXECS
        .lock()
        .unwrap()
        .as_ref()
        .and_then(|m| m.get(&exec_vh).copied())
}

fn replayed_exec_put(exec_vh: u64, exec: u64) {
    REPLAYED_EXECS
        .lock()
        .unwrap()
        .get_or_insert_with(HashMap::new)
        .insert(exec_vh, exec);
}

/// P3b: adopt a finished re-capture into this session so `raw_graph` resolves
/// the inherited vhandle to the clone-owned exec from now on.
fn adopt_replayed_exec(sess: &mut Session, exec_vh: u64, exec: u64) {
    sess.graph_vhandles.lock().unwrap().insert(exec_vh, exec);
    sess.owned_graph_reals.insert(exec);
}

/// P3b: rebuild an inherited graph by RE-CAPTURING its recorded op sequence in
/// this clone's context. Begins capture on the clone's remapped copy of the
/// golden's capture stream, re-dispatches each recorded op (so `dispatch`'s
/// pointer/handle translation applies verbatim), ends capture, and instantiates.
/// Returns the clone-owned exec. Errors bubble so the caller can fall back.
fn replay_capture_graph(sess: &mut Session, b: &mut dyn Backend, exec_vh: u64) -> CuResult<u64> {
    fn op_tag(req: &Request) -> &'static str {
        match req {
            Request::LaunchKernel { .. } => "LaunchKernel",
            Request::LibCall { .. } => "LibCall",
            Request::MemsetD8Async { .. } => "MemsetD8Async",
            Request::MemcpyDtoDAsync { .. } => "MemcpyDtoDAsync",
            Request::EventRecord { .. } => "EventRecord",
            Request::StreamWaitEvent { .. } => "StreamWaitEvent",
            _ => "other",
        }
    }
    fn op_stream(req: &Request) -> Option<u64> {
        match req {
            Request::LaunchKernel { stream, .. }
            | Request::MemsetD8Async { stream, .. }
            | Request::MemcpyDtoDAsync { stream, .. }
            | Request::EventRecord { stream, .. }
            | Request::StreamWaitEvent { stream, .. } => Some(*stream),
            _ => None,
        }
    }
    let ops = sess
        .clone_graph_oplogs
        .get(&exec_vh)
        .cloned()
        .ok_or(CUDA_ERROR_INVALID_HANDLE)?;
    // Collect every stream the recorded ops touch (as GOLDEN raw values — the
    // same key both raw_stream and the lib-arg stream_resolve translate by).
    let mut kinds: HashMap<&'static str, u32> = HashMap::new();
    let mut golden_streams: Vec<u64> = Vec::new();
    for op in &ops {
        if let Ok(req) = crate::proto::decode_request(op) {
            *kinds.entry(op_tag(&req)).or_insert(0) += 1;
            if let Some(s) = op_stream(&req) {
                if s != 0 {
                    let g = sess.streams.get(&s).copied().unwrap_or(s);
                    if !golden_streams.contains(&g) {
                        golden_streams.push(g);
                    }
                }
            }
        }
    }
    // PRIVATE replay stream: capturing on the clone's live remapped stream
    // races the guest's own traffic arriving on other channels — concurrent
    // guest ops get absorbed into (or collide with) the capture, corrupting
    // both. All recorded streams are redirected onto one private stream for
    // the replay (linearizing a multi-stream DAG is dependency-safe, it only
    // serializes intra-graph parallelism), then the overrides are restored.
    let private = b.stream_create(0)?;
    let saved: Vec<(u64, Option<u64>)> = golden_streams
        .iter()
        .map(|&g| (g, stream_trans_override(g, private)))
        .collect();
    eprintln!(
        "[p3b] replay exec {exec_vh:#x}: {} ops {kinds:?}, {} stream(s) -> private {private:#x}",
        ops.len(),
        golden_streams.len()
    );
    let restore = |saved: &[(u64, Option<u64>)]| {
        for &(g, prev) in saved {
            stream_trans_restore(g, prev);
        }
    };
    // WARMUP eager pass (on the private stream): binds every library handle's
    // stream/workspace outside the capture window (cuBLAS workspace cudaMalloc
    // during capture is the classic NOT_INITIALIZED source). Results land in
    // the clone's own buffers, which the guest overwrites before real use.
    if std::env::var("SMOLVM_CUDA_P3B_WARMUP").as_deref() != Ok("0") {
        for (i, op) in ops.iter().enumerate() {
            let req = match crate::proto::decode_request(op) {
                Ok(r) => r,
                Err(_) => {
                    restore(&saved);
                    let _ = b.stream_destroy(private);
                    return Err(CUDA_ERROR_INVALID_HANDLE);
                }
            };
            let tag = op_tag(&req);
            let (st, _) = dispatch(sess, b, req);
            if st != 0 {
                eprintln!("[p3b] WARMUP op {i}/{} {tag} failed st={st}", ops.len());
                restore(&saved);
                let _ = b.stream_destroy(private);
                return Err(st);
            }
        }
        if let Err(e) = b.ctx_synchronize() {
            eprintln!("[p3b] WARMUP ctx_synchronize failed st={e}");
            restore(&saved);
            let _ = b.stream_destroy(private);
            return Err(e);
        }
    }
    // RELAXED (2): the re-issued library calls may touch capture-unsafe APIs.
    if let Err(e) = b.stream_begin_capture(private, 2) {
        eprintln!("[p3b] begin_capture(private={private:#x}) failed st={e}");
        restore(&saved);
        let _ = b.stream_destroy(private);
        return Err(e);
    }
    for (i, op) in ops.iter().enumerate() {
        let req = match crate::proto::decode_request(op) {
            Ok(r) => r,
            Err(_) => {
                let _ = b.stream_end_capture(private);
                restore(&saved);
                let _ = b.stream_destroy(private);
                return Err(CUDA_ERROR_INVALID_HANDLE);
            }
        };
        let tag = op_tag(&req);
        let (st, _) = dispatch(sess, b, req);
        if st != 0 {
            eprintln!("[p3b] CAPTURE op {i}/{} {tag} failed st={st}", ops.len());
            // Abort the capture cleanly before bubbling — a dangling capture
            // poisons the stream for every later op.
            let _ = b.stream_end_capture(private);
            restore(&saved);
            let _ = b.stream_destroy(private);
            return Err(st);
        }
    }
    let ended = b.stream_end_capture(private);
    restore(&saved);
    let graph = match ended {
        Ok(g) => g,
        Err(e) => {
            eprintln!("[p3b] end_capture failed st={e}");
            let _ = b.stream_destroy(private);
            return Err(e);
        }
    };
    let _ = b.stream_destroy(private);
    let exec = match b.graph_instantiate(graph) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("[p3b] instantiate failed st={e}");
            let _ = b.graph_destroy(graph);
            return Err(e);
        }
    };
    let _ = b.graph_destroy(graph); // the exec is what we launch; graph is scratch
    eprintln!("[p3b] replay exec {exec_vh:#x}: re-captured OK -> new exec {exec:#x}");
    Ok(exec)
}

fn dispatch(sess: &mut Session, b: &mut dyn Backend, req: Request) -> (i32, Response) {
    // P3b capture-replay recording: while a capture is active on this session,
    // append each capturable op's wire bytes so a clone can re-capture the same
    // sequence in its own context (see StreamBeginCapture / GraphInstantiate).
    if sess.capture_rec.is_some() && is_capturable(&req) {
        let bytes = crate::proto::encode_request(&req);
        if let Some((_, log)) = sess.capture_rec.as_mut() {
            log.push(bytes);
        }
    }
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
    // Map a guest device index through the session's pin (guest 0 → host N).
    fn dev(sess: &Session, device: i32) -> i32 {
        if sess.device_pinned {
            sess.device_base + device
        } else {
            device
        }
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
            // Path 3 (M3a pattern): translate a clone's inherited golden stream
            // to its own recreated stream; identity otherwise.
            Ok(xlat_stream(
                sess.streams.get(&stream).copied().unwrap_or(stream),
            ))
        }
    }
    // Modules and functions are raw host handles on the wire (like streams):
    // the real CUmodule/CUfunction is context-scoped and every connection
    // retains the same device primary context, so a handle minted on one
    // connection stays valid on another (this is what lets a forked VM clone
    // reconnect and keep using its parent's loaded modules). The tables only
    // translate ids minted by pre-raw guests; a raw value passes through.
    fn raw_module(sess: &Session, b: &mut dyn Backend, m: u64) -> u64 {
        // Path 3 (M3a): a clone worker lazily reloads + translates the golden's
        // inherited raw module handle to its own; identity otherwise.
        xlat_mod(b, sess.modules.get(&m).copied().unwrap_or(m))
    }
    fn raw_fn_h(sess: &Session, b: &mut dyn Backend, f: u64) -> u64 {
        xlat_func(b, sess.functions.get(&f).copied().unwrap_or(f))
    }
    fn raw_graph(sess: &Session, h: u64) -> u64 {
        // Virtual graph/exec handle → real; untagged values pass through.
        if h & VHANDLE_TAG == 0 {
            return h;
        }
        // M3b (Path 3): a clone worker rebuilds inherited graphs in ITS OWN
        // context; GRAPH_TRANS holds those worker-local reals. It must win over
        // the session map, which — via the handoff registry — still carries the
        // GOLDEN's real handles for the same virtual handle (a foreign-context
        // exec that silently no-ops or faults if launched here).
        if let Some(r) = GRAPH_TRANS.with(|m| m.borrow().get(&h).copied()) {
            return r;
        }
        sess.graph_vhandles
            .lock()
            .unwrap()
            .get(&h)
            .copied()
            .unwrap_or(0)
    }
    fn raw_event(sess: &Session, event: u64) -> CuResult<u64> {
        // Same raw-on-the-wire convention as streams.
        Ok(xlat_event(
            sess.events.get(&event).copied().unwrap_or(event),
        ))
    }
    // Copy-on-write any shared weight buffer this request writes, then rewrite
    // inherited device pointers to this clone's private copies (both no-ops
    // unless this is an isolating clone).
    cow_written(sess, b, &req);
    let req = translate_dptrs(&sess.dptr_trans, req);
    let trace = optrace_summary(&req);
    if let Some(_l) = &trace {
        optrace_write(&format!("BEGIN {_l}"), -999);
    }
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
                // A resuming channel belongs to the SAME guest process as its
                // parent, and GoldenLayout is process-scoped fork-handoff
                // metadata (modules, upload coverage, library-handle creates).
                // SHARE the parent's layout instead of registering a fresh one,
                // or records split across channels: a cuBLAS handle created on
                // one channel is then missing from the layout the fork stages,
                // and every clone's replay lacks it (vh-miss →
                // NOT_INITIALIZED on the clone's first GEMM).
                if resume_token != 0 {
                    if let Some(parent) = layout_handoff_adopt(resume_token) {
                        sess.golden_layout = parent;
                    }
                }
                layout_handoff_register(&sess.golden_layout, token);
                // Isolation-mode clone: defer copying the parent's buffers until
                // the first PrimaryCtxRetain, when a context is actually current.
                if resume_token != 0 && fork_isolate_enabled() {
                    sess.pending_isolate = resume_token;
                }
                b.init().map(|_| Response::Handle(token))
            }
        }
        Request::DeviceGetCount => {
            if sess.device_pinned {
                // Pinned sessions see exactly one device (their pin).
                return Ok(Response::Count(1));
            }
            b.device_get_count().map(Response::Count)
        }
        Request::DeviceGetName { device } => {
            b.device_get_name(dev(sess, device)).map(Response::Name)
        }
        Request::DeviceTotalMem { device } => {
            b.device_total_mem(dev(sess, device)).map(Response::Bytes)
        }
        Request::DriverGetVersion => b.driver_get_version().map(Response::Count),
        Request::DeviceGetAttribute { attrib, device } => b
            .device_get_attribute(attrib, dev(sess, device))
            .map(Response::Count),
        Request::DeviceGetUuid { device } => b
            .device_get_uuid(dev(sess, device))
            .map(|u| Response::Data(u.to_vec())),
        Request::CtxCreate { device } => {
            let raw = b.ctx_create(dev(sess, device))?;
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
            let device = dev(sess, device);
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
                // In a clone WORKER (layout env set), reconstruction already
                // placed/copied everything; the in-daemon copy branches below
                // must not run. They originally no-op'd because the worker's
                // handoff registries were empty — but a LATE-ATTACHED channel
                // Inits after the primary session re-registered the clone's
                // own ranges under the same token, and copying those would
                // snapshot live clone state into stale "private copies"
                // (VMM ranges are address-preserved in workers: translating
                // them is wrong even when the copy succeeds).
                let in_worker = std::env::var_os("SMOLVM_CUDA_CLONE_LAYOUT").is_some();
                let (mut copied, mut shared, mut cbytes, mut sbytes) = (0u64, 0u64, 0u64, 0u64);
                if let Some(allocs) = dptr_handoff_snapshot(parent).filter(|_| !in_worker) {
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
                if let Some(vmm) = vmm_handoff_snapshot(parent).filter(|_| !in_worker) {
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
                // Worker-mode: reconstruction already made private copies of the
                // golden's non-VMM allocations (the daemon-process registries
                // above are empty in a worker) — adopt them into this session's
                // translation exactly like the copies made in-daemon. Adoption
                // is non-draining and ownerless: every channel's session needs
                // the same translations (the guest launches kernels on more
                // than one channel), and no session may free the copies on
                // close — they live until the worker process exits.
                for (gdptr, size, cdptr) in worker_alloc_trans_snapshot() {
                    sess.dptr_trans.push((gdptr, size, cdptr));
                    sess.alloc_table
                        .lock()
                        .unwrap()
                        .insert(cdptr, (size, false));
                    copied += 1;
                    cbytes += size;
                }
                sort_trans(&mut sess.dptr_trans); // xlat binary-searches by base
                gpu::set_lib_trans(&sess.dptr_trans); // forwarded-lib pointer map
                                                      // P3b: adopt inherited capture-replay logs, keyed by exec_vh —
                                                      // replayed lazily at the clone's first GraphLaunch.
                for (graph_vh, exec_vh, ops) in take_worker_graph_oplogs() {
                    eprintln!(
                        "[p3b] clone adopted oplog: graph {graph_vh:#x} exec {exec_vh:#x} ({} ops)",
                        ops.len()
                    );
                    sess.clone_graph_oplogs.insert(exec_vh, ops);
                }
                eprintln!(
                    "[cuda-fork-isolate] clone resumed token {parent}: {copied} private copies \
                     ({cbytes} B), {shared} shared read-only ({sbytes} B)"
                );
                // P3b PRE-WARM (opt out: SMOLVM_CUDA_PREREPLAY=0). Two stages,
                // both moving one-time clone costs off the first-request path:
                // (1) eagerly reload every staged golden module — first-touch
                // kernel launches (prefill, eager ops) stop paying per-module
                // reload stalls; (2) re-capture every inherited graph now
                // rather than lazily at first launch. Failures are left for
                // the lazy paths to retry; later sessions adopt from the
                // registry.
                if std::env::var("SMOLVM_CUDA_PREREPLAY").as_deref() != Ok("0") {
                    let mods: Vec<u64> = MOD_IMAGES.with(|m| m.borrow().keys().copied().collect());
                    if !mods.is_empty() {
                        let t0 = std::time::Instant::now();
                        let mut loaded = 0u32;
                        for g in mods {
                            if xlat_mod(b, g) != g {
                                loaded += 1;
                            }
                        }
                        eprintln!(
                            "[p3b] pre-warm: {loaded} module(s) ready in {} ms",
                            t0.elapsed().as_millis()
                        );
                    }
                }
                if !sess.clone_graph_oplogs.is_empty()
                    && std::env::var("SMOLVM_CUDA_PREREPLAY").as_deref() != Ok("0")
                {
                    let t0 = std::time::Instant::now();
                    let execs: Vec<u64> = sess.clone_graph_oplogs.keys().copied().collect();
                    let (mut fresh, mut adopted, mut deferred) = (0u32, 0u32, 0u32);
                    for exec_vh in execs {
                        if let Some(exec) = replayed_exec_get(exec_vh) {
                            adopt_replayed_exec(sess, exec_vh, exec);
                            adopted += 1;
                            continue;
                        }
                        match replay_capture_graph(sess, b, exec_vh) {
                            Ok(exec) => {
                                replayed_exec_put(exec_vh, exec);
                                adopt_replayed_exec(sess, exec_vh, exec);
                                fresh += 1;
                            }
                            Err(e) => {
                                eprintln!(
                                    "[p3b] pre-replay exec {exec_vh:#x} failed st={e}; \
                                     left for lazy retry"
                                );
                                deferred += 1;
                            }
                        }
                    }
                    eprintln!(
                        "[p3b] pre-replay: {fresh} re-captured, {adopted} adopted, \
                         {deferred} deferred in {} ms",
                        t0.elapsed().as_millis()
                    );
                }
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
            let device = dev(sess, device);
            sess.primary_retains = sess.primary_retains.saturating_sub(1);
            b.primary_ctx_release(device).map(|_| Response::Ok)
        }
        Request::ModuleLoadData { image } => {
            // Return the raw CUmodule as the wire handle (context-scoped, so it
            // survives a fork-clone reconnect). Still tracked for reclaim.
            if let Some(p) = std::env::var_os("SMOLVM_CUDA_DUMP_LOADING") {
                let _ = std::fs::write(&p, &image);
            }
            let raw = b.module_load_data(&image)?;
            worker_module_register(raw);
            sess.owned_modules.insert(raw);
            // Feed the process-wide image cache so later replicas can load by
            // hash without re-shipping the bytes (LibCall 6/1).
            module_cache_put(&image);
            // M3a: keep the image so a Path-3 clone worker can reload the module in
            // its own context and remap this inherited handle.
            if path3_enabled() {
                sess.golden_layout
                    .lock()
                    .unwrap()
                    .modules
                    .insert(raw, image.clone());
            }
            Ok(Response::Handle(raw))
        }
        Request::ModuleGetFunction { module, name } => {
            let raw_mod = raw_module(sess, b, module);
            // Raw CUfunction on the wire: valid across connections in the shared
            // primary context, so a forked clone keeps its parent's functions.
            let raw_fn = b.module_get_function(raw_mod, &name)?;
            if path3_enabled() {
                sess.golden_layout
                    .lock()
                    .unwrap()
                    .functions
                    .insert(raw_fn, (raw_mod, name.clone()));
            }
            Ok(Response::Handle(raw_fn))
        }
        Request::ModuleUnload { module } => {
            let raw_mod = raw_module(sess, b, module);
            // Only unload a module THIS worker created (WORKER_MODULES). A handle
            // it doesn't own is a foreign/golden-context module inherited via COW
            // (or already freed); cuModuleUnload would deref it in the wrong
            // context and SIGSEGV the driver. Skipping is correct — the worker
            // never allocated it, and its own modules are freed on ctx teardown.
            if worker_module_take(raw_mod) {
                b.module_unload(raw_mod)?;
            }
            sess.owned_modules.remove(&raw_mod);
            sess.modules.remove(&module);
            Ok(Response::Ok)
        }
        Request::FuncGetParamInfo { function } => {
            let raw_fn = raw_fn_h(sess, b, function);
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
            let raw_fn = raw_fn_h(sess, b, function);
            if path3_enabled() {
                sess.golden_layout
                    .lock()
                    .unwrap()
                    .func_attrs
                    .entry(raw_fn)
                    .or_default()
                    .push((attrib, value));
            }
            b.func_set_attribute(raw_fn, attrib, value)
                .map(|_| Response::Ok)
        }
        Request::FuncGetAttribute { function, attrib } => {
            let raw_fn = raw_fn_h(sess, b, function);
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
            if path3_enabled() {
                mark_loaded_vmm(&sess.golden_layout, dptr, data.len() as u64, Some(&data));
            }
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
            let raw_fn = raw_fn_h(sess, b, function);
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
            worker_handle_register(&WORKER_STREAMS, st);
            if path3_enabled() {
                sess.golden_layout.lock().unwrap().streams.insert(st, flags);
            }
            Response::Handle(st)
        }),
        Request::StreamBeginCapture { stream, mode } => {
            let raw = raw_stream(sess, stream)?;
            // P3b: start recording capturable ops for clone re-capture. Only the
            // golden records (path3 enabled, not itself a clone); a clone that
            // captures its own graph needs no replay log.
            if clone_graph_replay_enabled() && path3_enabled() && sess.dptr_trans.is_empty() {
                sess.capture_rec = Some((stream, Vec::new()));
            }
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
            // P3b: park the recorded op-log under graph_vh until GraphInstantiate
            // associates it with an exec_vh (what the clone launches).
            if let Some((_, log)) = sess.capture_rec.take() {
                if !log.is_empty() {
                    eprintln!(
                        "[p3b] golden recorded {} ops for graph {graph_vh:#x}",
                        log.len()
                    );
                    sess.golden_layout
                        .lock()
                        .unwrap()
                        .pending_oplogs
                        .insert(graph_vh, log);
                }
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
            // M3b (Path 3): record the graph in portable form so a clone worker
            // can rebuild it in its own context (the golden's CUgraph/exec are
            // context-scoped). Only kernel-node graphs serialize; anything else
            // returns None and simply isn't recorded (the clone then fails loud
            // on launch rather than mis-executing an unsupported graph).
            if path3_enabled() {
                let mut layout = sess.golden_layout.lock().unwrap();
                // P3b preferred: promote the parked capture-replay log (keyed by
                // graph_vh) to a `(graph_vh, exec_vh, log)` entry.
                if let Some(log) = layout.pending_oplogs.remove(&graph) {
                    eprintln!(
                        "[p3b] promoted oplog: graph {graph:#x} -> exec {exec_vh:#x} ({} ops)",
                        log.len()
                    );
                    layout.graph_oplogs.push((graph, exec_vh, log));
                }
                // Node-rebuild fallback (kernel-only graphs): kept for clones
                // whose exec has no oplog.
                if let Ok(Some(ser)) = b.graph_introspect(real_graph) {
                    layout.graphs.push((graph, exec_vh, ser));
                }
            }
            if exec_vh & VHANDLE_TAG != 0 {
                sess.graph_vhandles.lock().unwrap().insert(exec_vh, e);
                sess.owned_graph_reals.insert(e);
            }
            Ok(Response::Handle(e))
        }
        Request::GraphLaunch { graph_exec, stream } => {
            // P3b: an inherited exec with a capture-replay log re-captures the
            // recorded ops in THIS clone's context (translating every pointer /
            // handle through the normal dispatch path) instead of rebuilding
            // nodes — the only path that reproduces cuBLAS-kernel and non-kernel
            // graph nodes. Built once, then launched like a clone-owned graph.
            // Normally satisfied by pre-replay at resume; this is the lazy
            // fallback (and retry path for deferred pre-replays).
            if clone_graph_replay_enabled()
                && !sess
                    .owned_graph_reals
                    .contains(&raw_graph(sess, graph_exec))
            {
                // Registry FIRST, independent of this session's oplog stash:
                // spawn pre-warm re-captures on the worker main thread, while
                // the resumed session may serve on an attached channel whose
                // thread-local oplogs were never seeded — the registry is the
                // process-wide truth. Empty outside clone workers, so this is
                // a no-op for golden/daemon sessions.
                if let Some(exec) = replayed_exec_get(graph_exec) {
                    adopt_replayed_exec(sess, graph_exec, exec);
                    let raw = raw_stream(sess, stream)?;
                    return b.graph_launch(exec, raw).map(|_| Response::Ok);
                }
            }
            if clone_graph_replay_enabled()
                && !sess
                    .owned_graph_reals
                    .contains(&raw_graph(sess, graph_exec))
                && sess.clone_graph_oplogs.contains_key(&graph_exec)
            {
                match replay_capture_graph(sess, b, graph_exec) {
                    Ok(exec) => {
                        replayed_exec_put(graph_exec, exec);
                        adopt_replayed_exec(sess, graph_exec, exec);
                        let raw = raw_stream(sess, stream)?;
                        return b.graph_launch(exec, raw).map(|_| Response::Ok);
                    }
                    Err(e) => {
                        eprintln!(
                            "[p3b] capture-replay failed for exec {graph_exec:#x}: e={e}; \
                                   falling back to node rebuild"
                        );
                        // fall through to the node-rebuild / patch paths below
                    }
                }
            }
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
            // Only destroy a stream THIS worker created; a foreign/inherited handle
            // would SIGSEGV cuStreamDestroy in the wrong context (see WORKER_MODULES).
            if worker_handle_take(&WORKER_STREAMS, raw) {
                b.stream_destroy(raw)?;
            }
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
            worker_handle_register(&WORKER_EVENTS, e);
            if path3_enabled() {
                sess.golden_layout.lock().unwrap().events.insert(e, flags);
            }
            Response::Handle(e)
        }),
        Request::EventDestroy { event } => {
            let raw = raw_event(sess, event)?;
            if worker_handle_take(&WORKER_EVENTS, raw) {
                b.event_destroy(raw)?;
            }
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
        Request::LibCall { lib, func, args } => {
            // lib 6 / func 1: module load BY CONTENT HASH — served here (needs
            // session state), not in the backend. Blob:
            // [u64 fnv][u64 len][first 8 bytes][last 8 bytes]. HIT → load the
            // cached image (same bookkeeping as ModuleLoadData) and return the
            // 8-byte handle; MISS → (0, empty) and the client falls back to a
            // full ModuleLoadData. Engine loads re-ship hundreds of MB of
            // identical fatbins per replica without this.
            if lib == 6 && func == 1 && args.len() >= 32 {
                let key = ModuleCacheKey {
                    fnv: u64::from_le_bytes(args[0..8].try_into().unwrap()),
                    len: u64::from_le_bytes(args[8..16].try_into().unwrap()),
                    head: args[16..24].try_into().unwrap(),
                    tail: args[24..32].try_into().unwrap(),
                };
                if let Some(image) = module_cache_get(&key) {
                    let raw = b.module_load_data(&image)?;
                    worker_module_register(raw);
                    sess.owned_modules.insert(raw);
                    if path3_enabled() {
                        sess.golden_layout
                            .lock()
                            .unwrap()
                            .modules
                            .insert(raw, image.to_vec());
                    }
                    return Ok(Response::LibResult(0, raw.to_le_bytes().to_vec()));
                }
                return Ok(Response::LibResult(0, Vec::new()));
            }
            // lib 6 / func 2: classify a pointer — reply [2] iff the session
            // knows it as device memory (cudaMalloc table, VMM ranges, clone
            // translations/shared ranges). The guest cudart shim can't see
            // driver-VMM allocations (torch expandable_segments), so its
            // cudaPointerGetAttributes mis-reported them as unregistered and
            // vLLM's CUDA-graph capture (`weak_ref_tensor`) refused them.
            if lib == 6 && func == 2 && args.len() >= 8 {
                let p = u64::from_le_bytes(args[0..8].try_into().unwrap());
                let in_alloc = sess
                    .alloc_table
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|(&b0, &(sz, _))| p >= b0 && p < b0 + sz);
                let dev = in_alloc
                    || sess
                        .owned_dptrs
                        .iter()
                        .any(|(&b0, &sz)| p >= b0 && p < b0 + sz)
                    || sess
                        .vmm_ranges
                        .lock()
                        .unwrap()
                        .iter()
                        .any(|(&b0, &sz)| p >= b0 && p < b0 + sz)
                    || sess
                        .dptr_trans
                        .iter()
                        .any(|&(b0, sz, _)| p >= b0 && p < b0 + sz)
                    || sess
                        .shared_ranges
                        .iter()
                        .any(|&(b0, sz)| p >= b0 && p < b0 + sz);
                return Ok(Response::LibResult(0, vec![if dev { 2 } else { 0 }]));
            }
            let r = b.lib_call(lib, func, &args, &sess.streams);
            // Path 3: record top-level library-context creates so a clone
            // worker can replay them in ITS process (library handles are
            // process-local; see GoldenLayout::lib_handles). The guest value
            // is the minted vhandle id (cuBLAS/cuDNN pass it in args) or the
            // returned raw pointer (cuBLASLt returns it in the output).
            if path3_enabled() {
                if let Ok((0, ref out)) = r {
                    let recorded = match (lib, func) {
                        // cublasCreate_v2 / cudnnCreate: guest-minted id leads args.
                        (1, 0) | (2, 0) if args.len() >= 8 => {
                            Some(u64::from_le_bytes(args[..8].try_into().unwrap()))
                        }
                        // cublasLtCreate: raw host pointer returned to the guest.
                        (4, 11) if out.len() >= 8 => {
                            Some(u64::from_le_bytes(out[..8].try_into().unwrap()))
                        }
                        _ => None,
                    };
                    if let Some(h) = recorded {
                        if std::env::var_os("SMOLVM_CUDA_LIB_SEED_DEBUG").is_some() {
                            eprintln!("[lib-rec] lib={lib} func={func} h={h:#x}");
                        }
                        sess.golden_layout.lock().unwrap().lib_handles.push((
                            lib,
                            func,
                            h,
                            args.clone(),
                        ));
                    }
                }
            }
            r.map(|(status, out)| Response::LibResult(status, out))
        }
        Request::MemcpyShmHtoD {
            dptr,
            offset,
            size,
            stream,
        } => {
            mark_loaded(&sess.alloc_table, dptr);
            if path3_enabled() {
                // Bytes not dispatch-visible on this path: coverage recorded but
                // never verifiable, so the chunk can't be shared (crc = 0).
                mark_loaded_vmm(&sess.golden_layout, dptr, size, None);
            }
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
            if path3_enabled() {
                let n: u64 = segments.iter().map(|&(_, len)| len).sum();
                mark_loaded_vmm(&sess.golden_layout, dptr, n, None); // see ShmHtoD
            }
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
        Request::RingSetup { .. } | Request::RingSetupFile { .. } => Err(CUDA_ERROR_NOT_SUPPORTED),
        Request::MemAddressReserve { size, align } => {
            b.mem_address_reserve(size, align).map(|va| {
                sess.owned_vmm_reservations.insert(va, size);
                sess.golden_layout
                    .lock()
                    .unwrap()
                    .reservations
                    .insert(va, size);
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
            // Path 3: create the physical IPC-exportable so a clone worker process
            // can import it and place it at the golden's exact VA (M2).
            let device = dev(sess, device);
            let created = if path3_enabled() {
                b.mem_create_exportable(size, device)
            } else {
                b.mem_create(size, device)
            };
            created.map(|h| {
                sess.owned_vmm_handles.insert(h, size);
                Response::Handle(h)
            })
        }
        Request::MemCreateVh {
            size,
            device,
            handle_vh,
        } => {
            let limit = vram_limit();
            let used: u64 = sess.owned_dptrs.values().sum::<u64>()
                + sess.owned_vmm_handles.values().sum::<u64>();
            if used.saturating_add(size) > limit {
                return Err(2); // CUDA_ERROR_OUT_OF_MEMORY (surfaces via sticky)
            }
            let device = dev(sess, device);
            let created = if path3_enabled() {
                b.mem_create_exportable(size, device)
            } else {
                b.mem_create(size, device)
            };
            created.map(|h| {
                sess.owned_vmm_handles.insert(h, size);
                sess.vmm_vhandles.insert(handle_vh, h);
                Response::Ok
            })
        }
        Request::MemMap {
            va,
            size,
            offset,
            handle,
        } => {
            // The guest-visible value: a burst virtual handle, or (legacy) the
            // raw real. Recorded as the chunk's ghandle so a clone's inherited
            // ops (which carry this value) translate in the worker.
            let ghandle = handle;
            // Burst create: resolve the session's minted virtual handle.
            let handle = sess.vmm_vhandles.get(&handle).copied().unwrap_or(handle);
            // Path 3 worker: an inherited golden handle must map via the worker's
            // own physical (raw golden values are invalid in this context).
            let handle = VMM_TRANS
                .with(|m| m.borrow().as_ref().and_then(|t| t.get(&handle).copied()))
                .unwrap_or(handle);
            b.mem_map(va, size, offset, handle).map(|_| {
                sess.owned_vmm_maps.insert(va, size);
                sess.vmm_ranges.lock().unwrap().insert(va, size);
                // Path 3 (M2): record va→(size, physical handle) so the daemon can
                // export this physical to an fd for a clone worker to import at `va`.
                // coverage starts at 0 bytes; H2Ds accumulate it (see mark_loaded_vmm).
                sess.golden_layout.lock().unwrap().maps.insert(
                    va,
                    ChunkCover {
                        size,
                        handle,
                        ghandle,
                        ..ChunkCover::default()
                    },
                );
                Response::Ok
            })
        }
        Request::MemSetAccess { va, size, device } => b
            .mem_set_access(va, size, dev(sess, device))
            .map(|_| Response::Ok),
        Request::MemUnmap { va, size } => {
            sess.owned_vmm_maps.remove(&va);
            sess.vmm_ranges.lock().unwrap().remove(&va);
            sess.golden_layout.lock().unwrap().maps.remove(&va);
            b.mem_unmap(va, size).map(|_| Response::Ok)
        }
        Request::MemRelease { handle } => {
            // Burst create: resolve (and retire) the session's virtual handle.
            let handle = sess.vmm_vhandles.remove(&handle).unwrap_or(handle);
            let created_here = sess.owned_vmm_handles.remove(&handle).is_some();
            // Path 3 worker: translate an inherited golden handle to the worker
            // handle backing that chunk (consumed: releasing twice is a no-op).
            // A handle neither translated nor created in this process is a stale
            // golden value we can't resolve — dropped, NOT passed to the driver
            // (cuMemRelease on a foreign-context handle segfaults, not errors).
            let resolved = VMM_TRANS.with(|m| match m.borrow_mut().as_mut() {
                Some(t) => match t.remove(&handle) {
                    Some(w) => Some(Some(w)),
                    None if created_here => Some(Some(handle)),
                    None => Some(None),
                },
                None => None,
            });
            match resolved {
                Some(Some(h)) => b.mem_release(h).map(|_| Response::Ok),
                Some(None) => {
                    eprintln!("[M2] MemRelease: unknown inherited handle {handle:#x} → no-op");
                    Ok(Response::Ok)
                }
                None => b.mem_release(handle).map(|_| Response::Ok),
            }
        }
        Request::SetDeviceBase { device } => {
            sess.device_base = device;
            sess.device_pinned = true;
            sess.golden_layout.lock().unwrap().device_base = device;
            Ok(Response::Ok)
        }
        Request::MemAddressFree { va, size } => {
            sess.owned_vmm_reservations.remove(&va);
            sess.golden_layout.lock().unwrap().reservations.remove(&va);
            b.mem_address_free(va, size).map(|_| Response::Ok)
        }
        Request::MemGetAllocationGranularity { device, flags } => b
            .mem_get_allocation_granularity(dev(sess, device), flags)
            .map(Response::Bytes),
    })();
    let (status, resp) = match r {
        Ok(resp) => (0, resp),
        Err(code) => (code, Response::Ok),
    };
    if let Some(mut line) = trace {
        if let Response::LibResult(lst, _) = &resp {
            line.push_str(&format!(" lib_st={lst}"));
        }
        optrace_write(&line, status);
    }
    (status, resp)
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
