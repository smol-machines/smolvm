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
/// `CUDA_ERROR_NOT_FOUND`.
pub const CUDA_ERROR_NOT_FOUND: i32 = 500;
pub const CUDA_ERROR_NOT_SUPPORTED: i32 = 801;

/// A CUDA Driver-API implementation. Handles returned here are the backend's
/// own raw values (e.g. real `CUmodule` pointers); [`serve`] hides them behind
/// opaque ids before they reach the guest.
pub trait Backend: Send {
    fn init(&mut self) -> CuResult<()>;
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
    /// Live resources this connection created, reclaimed when it ends —
    /// a guest that dies mid-run must not leak GPU memory (device
    /// allocations are the multi-GB hazard; modules/streams/events are
    /// hygiene). Raw backend handles.
    owned_dptrs: HashMap<u64, u64>, // dptr → size (also the quota ledger)
    owned_modules: std::collections::HashSet<u64>,
    owned_streams: std::collections::HashSet<u64>,
    owned_events: std::collections::HashSet<u64>,
    primary_retains: u32,
}

/// Free everything a finished connection still owns. Failures are ignored —
/// the driver may already have reclaimed (context destruction, device reset).
fn reclaim_session(sess: &mut Session, b: &mut dyn Backend) {
    for (d, _size) in std::mem::take(&mut sess.owned_dptrs) {
        let _ = b.mem_free(d);
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

fn dispatch(sess: &mut Session, b: &mut dyn Backend, req: Request) -> (i32, Response) {
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
    fn raw_event(sess: &Session, event: u64) -> CuResult<u64> {
        // Same raw-on-the-wire convention as streams.
        Ok(sess.events.get(&event).copied().unwrap_or(event))
    }
    let r: CuResult<Response> = (|| match req {
        Request::Init => b.init().map(|_| Response::Ok),
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
            Ok(Response::Handle(id))
        }
        Request::PrimaryCtxRelease { device } => {
            sess.primary_retains = sess.primary_retains.saturating_sub(1);
            b.primary_ctx_release(device).map(|_| Response::Ok)
        }
        Request::ModuleLoadData { image } => {
            let raw = b.module_load_data(&image)?;
            sess.owned_modules.insert(raw);
            let id = sess.mint();
            sess.modules.insert(id, raw);
            Ok(Response::Handle(id))
        }
        Request::ModuleGetFunction { module, name } => {
            let raw_mod = raw(&sess.modules, module)?;
            let raw_fn = b.module_get_function(raw_mod, &name)?;
            let id = sess.mint();
            sess.functions.insert(id, raw_fn);
            Ok(Response::Handle(id))
        }
        Request::ModuleUnload { module } => {
            let raw_mod = raw(&sess.modules, module)?;
            b.module_unload(raw_mod)?;
            sess.owned_modules.remove(&raw_mod);
            sess.modules.remove(&module);
            Ok(Response::Ok)
        }
        Request::FuncGetParamInfo { function } => {
            let raw_fn = raw(&sess.functions, function)?;
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
            let raw_fn = raw(&sess.functions, function)?;
            b.func_set_attribute(raw_fn, attrib, value)
                .map(|_| Response::Ok)
        }
        Request::MemAlloc { bytes } => {
            // Per-connection VRAM quota (SMOLVM_CUDA_VRAM_LIMIT_MB on the
            // host): a guest may not allocate past its budget — the CUDA-
            // native failure (out of memory) surfaces to the app.
            // Read per call (allocations are rare): also keeps the limit
            // adjustable and test-deterministic, unlike a process cache.
            let limit = std::env::var("SMOLVM_CUDA_VRAM_LIMIT_MB")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .map(|mb| mb * 1024 * 1024)
                .unwrap_or(u64::MAX);
            let used: u64 = sess.owned_dptrs.values().sum();
            if used.saturating_add(bytes) > limit {
                return Err(2); // CUDA_ERROR_OUT_OF_MEMORY
            }
            b.mem_alloc(bytes).map(|d| {
                sess.owned_dptrs.insert(d, bytes);
                Response::Dptr(d)
            })
        }
        Request::MemFree { dptr } => {
            sess.owned_dptrs.remove(&dptr);
            // (removal returns the freed size to the quota ledger)
            b.mem_free(dptr).map(|_| Response::Ok)
        }
        Request::MemcpyHtoD { dptr, stream, data } => b
            .memcpy_htod(dptr, &data, raw_stream(sess, stream)?)
            .map(|_| Response::Ok),
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
            let raw_fn = raw(&sess.functions, function)?;
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
        Request::StreamEndCapture { stream } => {
            let raw = raw_stream(sess, stream)?;
            b.stream_end_capture(raw).map(Response::Handle)
        }
        Request::StreamCaptureInfo { stream } => {
            let raw = raw_stream(sess, stream)?;
            b.stream_capture_info(raw)
                .map(|(st, id)| Response::Pair(st, id))
        }
        Request::GraphInstantiate { graph } => b.graph_instantiate(graph).map(Response::Handle),
        Request::GraphLaunch { graph_exec, stream } => {
            let raw = raw_stream(sess, stream)?;
            b.graph_launch(graph_exec, raw).map(|_| Response::Ok)
        }
        Request::GraphExecDestroy { graph_exec } => {
            b.graph_exec_destroy(graph_exec).map(|_| Response::Ok)
        }
        Request::GraphDestroy { graph } => b.graph_destroy(graph).map(|_| Response::Ok),
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
        } => b
            .memcpy_shm_htod(dptr, offset, size, raw_stream(sess, stream)?)
            .map(|_| Response::Ok),
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
        } => b
            .memcpy_gpa_htod(dptr, &segments, raw_stream(sess, stream)?)
            .map(|_| Response::Ok),
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
        cli.init().unwrap();
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
        cli.init().unwrap();
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
}
