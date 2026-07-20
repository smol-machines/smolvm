//! Wire protocol for CUDA Driver-API remoting over a byte stream (vsock).
//!
//! Framing: every message is a `u32` little-endian length followed by the
//! payload. A request payload is a `u8` opcode then its args; a response payload
//! is an `i32` status (`CUresult`, LE) then return data (present only when
//! `status == 0`). The codec is zero-dependency and transport-agnostic: it
//! operates on any [`Read`]/[`Write`], so the host (AF_UNIX) and guest
//! (AF_VSOCK) share one definition.
//!
//! Handle model: modules, functions and contexts are referred to by opaque
//! `u64` ids minted by the host (so the guest can never forge a host pointer).
//! Device pointers (`CUdeviceptr`) are passed by their real value, because a
//! kernel's launch parameters embed the device address by value — that is how
//! the CUDA Driver API itself works.

use std::io::{self, Read, Write};

/// Maximum accepted message payload (256 MiB) — bounds a hostile/length field.
pub const MAX_MSG: usize = 256 * 1024 * 1024;

/// First byte of a *quiet* request frame: the server executes the wrapped
/// request (encoded normally after this byte) and sends **no response**; the
/// first failing status is held until the next [`FENCE_OP`]. Chosen outside
/// the [`Op`] value space.
pub const QUIET_PREFIX: u8 = 0x7F;
/// Single-byte fence request: replies with (and clears) the first failing
/// status among quiet requests since the previous fence.
pub const FENCE_OP: u8 = 0x7E;

/// Connection preamble a FORK-CLONE VM's proxy sends before any RPC frames:
/// these 8 magic bytes followed by an 8-byte per-clone id (le) and a 1-byte
/// flags field (bit 0: share the golden's loaded weights instead of copying —
/// the per-fork `--share-weights` surface). Lets the
/// daemon distinguish a clone's connection (route to its isolating worker
/// process) from the GOLDEN's own reconnect carrying the same lineage token
/// (must resume in-daemon — a worker would silently serve it a reconstructed
/// COPY of its memory). The first 4 bytes decode as a length far beyond
/// [`MAX_MSG`], so the preamble can never be confused with a legit frame.
pub const CLONE_PREAMBLE_MAGIC: [u8; 8] = *b"SMVCLN\x02\x00";

/// Request opcodes. Stable wire values — append only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Op {
    Init = 0x01,
    DeviceGetCount = 0x02,
    DeviceGetName = 0x03,
    DeviceTotalMem = 0x04,
    DriverGetVersion = 0x05,
    DeviceGetAttribute = 0x06,
    DeviceGetUuid = 0x07,
    CtxCreate = 0x10,
    CtxDestroy = 0x11,
    PrimaryCtxRetain = 0x12,
    PrimaryCtxRelease = 0x13,
    ModuleLoadData = 0x20,
    ModuleGetFunction = 0x21,
    ModuleUnload = 0x22,
    FuncGetParamInfo = 0x23,
    FuncSetAttribute = 0x24,
    FuncGetAttribute = 0x25,
    MemAlloc = 0x30,
    MemFree = 0x31,
    MemcpyHtoD = 0x32,
    MemcpyDtoH = 0x33,
    MemcpyDtoD = 0x34,
    MemsetD8 = 0x35,
    MemGetInfo = 0x36,
    LaunchKernel = 0x40,
    CtxSynchronize = 0x50,
    StreamCreate = 0x60,
    StreamDestroy = 0x61,
    StreamSynchronize = 0x62,
    StreamQuery = 0x63,
    EventCreate = 0x70,
    EventDestroy = 0x71,
    EventRecord = 0x72,
    EventSynchronize = 0x73,
    EventElapsedTime = 0x74,
    StreamWaitEvent = 0x75,
    EventQuery = 0x76,
    // CUDA graphs: capture forwarded to the host driver (which records the
    // stream's work into a graph), replayed with a single GraphLaunch.
    StreamBeginCapture = 0xC0,
    StreamEndCapture = 0xC1,
    GraphInstantiate = 0xC2,
    GraphLaunch = 0xC3,
    GraphExecDestroy = 0xC4,
    GraphDestroy = 0xC5,
    StreamCaptureInfo = 0xC6,
    // Stream-ordered variants (capture-safe: the sync forms would invalidate
    // an active capture and cannot be recorded into a graph).
    MemsetD8Async = 0xC7,
    MemcpyDtoDAsync = 0xC8,
    GraphGetNodes = 0xC9,
    ThreadExchangeCaptureMode = 0xCA,
    // nvcomp (forward-to-host-lib): batched Deflate decompression. Device-pointer
    // args are real host device addresses, forwarded by value.
    NvcompDeflateTempSize = 0x80,
    NvcompDeflateDecompress = 0x81,
    // cuBLAS (forward-to-host-lib). Handles are host-minted opaque ids; device
    // pointers pass by value.
    CublasCreate = 0x90,
    CublasDestroy = 0x91,
    CublasSetStream = 0x92,
    CublasSgemm = 0x93,
    /// Generic forward-to-host-lib call: `(lib, func, args)` → `(status, out)`.
    /// The wire is library-agnostic; per-function (de)serialization is
    /// code-generated (see `smolvm-cuda-codegen`). This is how the cuBLAS/cuDNN
    /// surface scales without a new opcode per function.
    LibCall = 0xA0,
    /// Zero-copy memcpy via the shared-memory channel: the payload is an
    /// `(offset, size)` descriptor into the shared region, not the bytes.
    MemcpyShmHtoD = 0xB0,
    MemcpyShmDtoH = 0xB1,
    /// Zero-copy memcpy via guest RAM the host maps: the payload is a list of
    /// `(guest_physical_addr, len)` segments, not the bytes. The host reads
    /// guest memory directly (one DMA if contiguous, gather otherwise).
    MemcpyGpaHtoD = 0xB2,
    MemcpyGpaDtoH = 0xB3,
    /// Switch this connection to shared-memory rings (see `crate::ring`):
    /// the payload names the guest-physical pages of the request ring, the
    /// completion ring, and a bounce buffer for oversized responses. After
    /// the host acks, the socket carries only doorbell bytes.
    RingSetup = 0xD0,
    RingSetupFile = 0xD1,
    // CUDA VMM (virtual memory management) — torch's expandable-segments
    // allocator. Control-plane ops, all synchronous.
    MemAddressReserve = 0xE0,
    MemCreate = 0xE1,
    MemMap = 0xE2,
    MemSetAccess = 0xE3,
    MemUnmap = 0xE4,
    MemRelease = 0xE5,
    MemAddressFree = 0xE6,
    MemGetAllocationGranularity = 0xE7,
    /// VMM create under a GUEST-MINTED virtual handle — quiet-eligible, so an
    /// allocation burst (model load) pipelines create/map/setAccess with no
    /// per-chunk round trip.
    MemCreateVh = 0xE8,
    /// Pin this session to a host GPU: guest device 0 maps to host device N
    /// and the guest sees exactly one device (CUDA_VISIBLE_DEVICES-style).
    SetDeviceBase = 0xE9,
}

impl Op {
    pub fn from_u8(v: u8) -> Option<Op> {
        Some(match v {
            0x01 => Op::Init,
            0x02 => Op::DeviceGetCount,
            0x03 => Op::DeviceGetName,
            0x04 => Op::DeviceTotalMem,
            0x05 => Op::DriverGetVersion,
            0x06 => Op::DeviceGetAttribute,
            0x07 => Op::DeviceGetUuid,
            0x10 => Op::CtxCreate,
            0x11 => Op::CtxDestroy,
            0x12 => Op::PrimaryCtxRetain,
            0x13 => Op::PrimaryCtxRelease,
            0x20 => Op::ModuleLoadData,
            0x21 => Op::ModuleGetFunction,
            0x22 => Op::ModuleUnload,
            0x23 => Op::FuncGetParamInfo,
            0x24 => Op::FuncSetAttribute,
            0x25 => Op::FuncGetAttribute,
            0x30 => Op::MemAlloc,
            0x31 => Op::MemFree,
            0x32 => Op::MemcpyHtoD,
            0x33 => Op::MemcpyDtoH,
            0x34 => Op::MemcpyDtoD,
            0x35 => Op::MemsetD8,
            0x36 => Op::MemGetInfo,
            0x40 => Op::LaunchKernel,
            0x50 => Op::CtxSynchronize,
            0xC0 => Op::StreamBeginCapture,
            0xC1 => Op::StreamEndCapture,
            0xC2 => Op::GraphInstantiate,
            0xC3 => Op::GraphLaunch,
            0xC4 => Op::GraphExecDestroy,
            0xC5 => Op::GraphDestroy,
            0xC6 => Op::StreamCaptureInfo,
            0xC7 => Op::MemsetD8Async,
            0xC8 => Op::MemcpyDtoDAsync,
            0xC9 => Op::GraphGetNodes,
            0xCA => Op::ThreadExchangeCaptureMode,
            0x60 => Op::StreamCreate,
            0x61 => Op::StreamDestroy,
            0x62 => Op::StreamSynchronize,
            0x63 => Op::StreamQuery,
            0x70 => Op::EventCreate,
            0x71 => Op::EventDestroy,
            0x72 => Op::EventRecord,
            0x73 => Op::EventSynchronize,
            0x74 => Op::EventElapsedTime,
            0x75 => Op::StreamWaitEvent,
            0x76 => Op::EventQuery,
            0x80 => Op::NvcompDeflateTempSize,
            0x81 => Op::NvcompDeflateDecompress,
            0x90 => Op::CublasCreate,
            0x91 => Op::CublasDestroy,
            0x92 => Op::CublasSetStream,
            0x93 => Op::CublasSgemm,
            0xA0 => Op::LibCall,
            0xB0 => Op::MemcpyShmHtoD,
            0xB1 => Op::MemcpyShmDtoH,
            0xB2 => Op::MemcpyGpaHtoD,
            0xB3 => Op::MemcpyGpaDtoH,
            0xD0 => Op::RingSetup,
            0xD1 => Op::RingSetupFile,
            0xE0 => Op::MemAddressReserve,
            0xE1 => Op::MemCreate,
            0xE8 => Op::MemCreateVh,
            0xE9 => Op::SetDeviceBase,
            0xE2 => Op::MemMap,
            0xE3 => Op::MemSetAccess,
            0xE4 => Op::MemUnmap,
            0xE5 => Op::MemRelease,
            0xE6 => Op::MemAddressFree,
            0xE7 => Op::MemGetAllocationGranularity,
            _ => return None,
        })
    }
}

/// A decoded request. Handles are opaque ids; device pointers are real values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Connect handshake. `proto_hash` is the client's wire fingerprint
    /// (`crate::PROTO_HASH`); the host rejects a mismatch (stale binary).
    /// `resume_token` is 0 for a fresh session, or a token returned by a prior
    /// `Init` to adopt that (frozen) session's library handle map — this is how
    /// a forked VM clone reconnects and keeps using its parent's cuBLAS/cuDNN
    /// descriptors. The response's `Handle` carries this session's own token.
    Init {
        proto_hash: u64,
        resume_token: u64,
    },
    DeviceGetCount,
    DeviceGetName {
        device: i32,
    },
    DeviceTotalMem {
        device: i32,
    },
    DriverGetVersion,
    DeviceGetAttribute {
        attrib: i32,
        device: i32,
    },
    DeviceGetUuid {
        device: i32,
    },
    CtxCreate {
        device: i32,
    },
    CtxDestroy {
        ctx: u64,
    },
    PrimaryCtxRetain {
        device: i32,
    },
    PrimaryCtxRelease {
        device: i32,
    },
    ModuleLoadData {
        image: Vec<u8>,
    },
    ModuleGetFunction {
        module: u64,
        name: String,
    },
    ModuleUnload {
        module: u64,
    },
    /// Per-parameter byte sizes of `function`'s kernel arguments, in declaration
    /// order — what a generic client needs to serialize `kernelParams` blobs.
    FuncGetParamInfo {
        function: u64,
    },
    /// Raise/set a `CUfunction_attribute` on the host function — chiefly
    /// `CU_FUNC_ATTRIBUTE_MAX_DYNAMIC_SHARED_SIZE_BYTES`, which Triton/vLLM
    /// kernels needing >48 KiB shared memory must opt into before launching, or
    /// the launch fails with `INVALID_VALUE`.
    FuncSetAttribute {
        function: u64,
        attrib: i32,
        value: i32,
    },
    /// Read a `CUfunction_attribute` (max-threads, num-regs, shared/local
    /// bytes, ptx/binary version) — forwarded so `cudaFuncGetAttributes`
    /// returns real values instead of fakes (num_regs=0 divides by zero in
    /// occupancy math).
    FuncGetAttribute {
        function: u64,
        attrib: i32,
    },
    MemAlloc {
        bytes: u64,
    },
    MemFree {
        dptr: u64,
    },
    MemcpyHtoD {
        dptr: u64,
        /// Stream whose prior work must complete before the copy (0 = legacy
        /// default). Guest `cudaMemcpyAsync` semantics: the copy is ordered
        /// within this stream, and torch's pool streams are non-blocking, so
        /// a NULL-stream copy would NOT wait for them.
        stream: u64,
        data: Vec<u8>,
    },
    MemcpyDtoH {
        dptr: u64,
        bytes: u64,
        /// See `MemcpyHtoD::stream`.
        stream: u64,
    },
    MemcpyDtoD {
        dst: u64,
        src: u64,
        bytes: u64,
    },
    MemsetD8 {
        dptr: u64,
        value: u8,
        bytes: u64,
    },
    MemGetInfo,
    /// Launch `function` with the given geometry. `params` is one byte-blob per
    /// kernel argument, in order — the host rebuilds the `void*[]` the Driver
    /// API expects by pointing at local copies of each blob. `stream` is an
    /// opaque stream id (0 = the default stream).
    LaunchKernel {
        function: u64,
        grid: [u32; 3],
        block: [u32; 3],
        shared_bytes: u32,
        stream: u64,
        params: Vec<Vec<u8>>,
    },
    CtxSynchronize,
    StreamBeginCapture {
        stream: u64,
        mode: i32,
    },
    StreamEndCapture {
        stream: u64,
        /// Guest-minted virtual graph handle (bit-63 tagged). The host maps it
        /// to the real captured graph so EndCapture can be fire-and-forget.
        graph_vh: u64,
    },
    GraphInstantiate {
        graph: u64,
        /// Guest-minted virtual exec handle; host maps it to the real
        /// instantiated exec so GraphInstantiate can be fire-and-forget.
        exec_vh: u64,
    },
    GraphLaunch {
        graph_exec: u64,
        stream: u64,
    },
    GraphExecDestroy {
        graph_exec: u64,
    },
    GraphDestroy {
        graph: u64,
    },
    StreamCaptureInfo {
        stream: u64,
    },
    GraphGetNodes {
        graph: u64,
    },
    /// `cuThreadExchangeStreamCaptureMode` on the serving thread. PyTorch's
    /// allocator wraps its capture-time `cudaMalloc` in a thread-local
    /// relaxed-mode guard; each connection is served by one host thread, so
    /// forwarding the exchange preserves the per-thread semantics. Returns the
    /// previous mode.
    ThreadExchangeCaptureMode {
        mode: i32,
    },
    MemsetD8Async {
        dptr: u64,
        value: u8,
        bytes: u64,
        stream: u64,
    },
    MemcpyDtoDAsync {
        dst: u64,
        src: u64,
        bytes: u64,
        stream: u64,
    },
    StreamCreate {
        flags: u32,
    },
    StreamDestroy {
        stream: u64,
    },
    StreamSynchronize {
        stream: u64,
    },
    /// `cuStreamQuery`: 0 = all work complete, 600 = not ready (raw code in
    /// the Count response; the guest surfaces it as its own return).
    StreamQuery {
        stream: u64,
    },
    /// Make `stream` wait for `event` — the cross-stream ordering edge. Once
    /// work really runs on side streams (and graph capture records these as
    /// graph dependencies), dropping it means racy replays.
    StreamWaitEvent {
        stream: u64,
        event: u64,
        flags: u32,
    },
    /// `cuEventQuery`: 0 = complete, 600 = not ready. PyTorch's allocator
    /// polls this to decide when freed blocks are safe to reuse.
    EventQuery {
        event: u64,
    },
    EventCreate {
        flags: u32,
    },
    EventDestroy {
        event: u64,
    },
    /// Record `event` on `stream` (0 = the default stream).
    EventRecord {
        event: u64,
        stream: u64,
    },
    EventSynchronize {
        event: u64,
    },
    EventElapsedTime {
        start: u64,
        end: u64,
    },
    /// `nvcompBatchedDeflateDecompressGetTempSizeEx` — all host scalars.
    NvcompDeflateTempSize {
        num_chunks: u64,
        max_uncompressed_chunk_bytes: u64,
        max_total_uncompressed_bytes: u64,
    },
    /// `nvcompBatchedDeflateDecompressAsync` — every pointer is a host device
    /// address (or 0 for the optional out-params), forwarded by value.
    NvcompDeflateDecompress {
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
    },
    CublasCreate,
    CublasDestroy {
        handle: u64,
    },
    CublasSetStream {
        handle: u64,
        stream: u64,
    },
    /// `cublasSgemm` (column-major). `alpha`/`beta` carried as f32 bits.
    CublasSgemm {
        handle: u64,
        transa: u32,
        transb: u32,
        m: i32,
        n: i32,
        k: i32,
        alpha_bits: u32,
        a: u64,
        lda: i32,
        b: u64,
        ldb: i32,
        beta_bits: u32,
        c: u64,
        ldc: i32,
    },
    /// Generic library call; `args` is the code-generated arg blob.
    LibCall {
        lib: u8,
        func: u16,
        args: Vec<u8>,
    },
    /// Zero-copy H2D: copy `size` bytes from shared-region `offset` to `dptr`.
    MemcpyShmHtoD {
        dptr: u64,
        offset: u64,
        size: u64,
        /// See `MemcpyHtoD::stream`.
        stream: u64,
    },
    /// Zero-copy D2H: copy `size` bytes from `dptr` to shared-region `offset`.
    MemcpyShmDtoH {
        offset: u64,
        dptr: u64,
        size: u64,
        /// See `MemcpyHtoD::stream`.
        stream: u64,
    },
    /// Zero-copy H2D from guest RAM: gather `segments` (each `(gpa, len)`, in
    /// buffer order) and copy to `dptr`.
    MemcpyGpaHtoD {
        dptr: u64,
        /// See `MemcpyHtoD::stream`.
        stream: u64,
        segments: Vec<(u64, u64)>,
    },
    /// Zero-copy D2H to guest RAM: copy from `dptr` and scatter into `segments`.
    MemcpyGpaDtoH {
        dptr: u64,
        /// See `MemcpyHtoD::stream`.
        stream: u64,
        segments: Vec<(u64, u64)>,
    },
    /// Switch to shared-memory rings. Page lists are guest-physical addresses
    /// of `page_size`-sized pages; `bounce` receives responses too large for
    /// an inline completion record.
    RingSetup {
        page_size: u32,
        req_pages: Vec<u64>,
        resp_pages: Vec<u64>,
        bounce_pages: Vec<u64>,
    },
    /// Like [`Request::RingSetup`] but the rings live in a FILE inside a host
    /// directory the per-VM proxy advertised at connect (DAX-backed clone
    /// rings — clone guest RAM is COW-private, but a fresh MAP_SHARED mmap of
    /// a dax-mount file is host-coherent). `fname` is a bare file name (no
    /// separators); the file holds `req_n` + `resp_n` + `bounce_n` contiguous
    /// pages of `page_size`.
    RingSetupFile {
        page_size: u32,
        req_n: u32,
        resp_n: u32,
        bounce_n: u32,
        fname: Vec<u8>,
    },
    /// VMM: reserve a virtual address range (no backing).
    MemAddressReserve {
        size: u64,
        align: u64,
    },
    /// VMM: create a physical allocation on `device`.
    MemCreate {
        size: u64,
        device: i32,
    },
    /// VMM: create a physical allocation on `device` under `handle_vh`, a
    /// guest-minted bit-63-tagged virtual handle later ops resolve (fire-and-
    /// forget: the guest never needs the real handle value).
    MemCreateVh {
        size: u64,
        device: i32,
        handle_vh: u64,
    },
    /// Pin the session's device mapping (see [`Op::SetDeviceBase`]).
    SetDeviceBase {
        device: i32,
    },
    /// VMM: back `va` with `handle` at `offset`.
    MemMap {
        va: u64,
        size: u64,
        offset: u64,
        handle: u64,
    },
    /// VMM: grant `device` read/write access to the mapped range.
    MemSetAccess {
        va: u64,
        size: u64,
        device: i32,
    },
    MemUnmap {
        va: u64,
        size: u64,
    },
    MemRelease {
        handle: u64,
    },
    MemAddressFree {
        va: u64,
        size: u64,
    },
    MemGetAllocationGranularity {
        device: i32,
        flags: u32,
    },
}

/// A decoded successful response body (the `status == 0` payload).
#[derive(Debug, Clone, PartialEq)]
pub enum Response {
    /// No return value beyond status (Init, CtxDestroy, MemFree, Memcpy*, Launch, Sync).
    Ok,
    Count(i32),
    Name(String),
    Bytes(u64),
    Handle(u64),
    Dptr(u64),
    Data(Vec<u8>),
    /// Two u64s (MemGetInfo: free, total).
    Pair(u64, u64),
    /// Milliseconds (EventElapsedTime). f32 bits on the wire.
    Millis(f32),
    /// Generic library-call result: library status + serialized output params.
    LibResult(i32, Vec<u8>),
}

// ---- low-level primitives -------------------------------------------------

fn w_u8(b: &mut Vec<u8>, v: u8) {
    b.push(v);
}
fn w_i32(b: &mut Vec<u8>, v: i32) {
    b.extend_from_slice(&v.to_le_bytes());
}
fn w_u32(b: &mut Vec<u8>, v: u32) {
    b.extend_from_slice(&v.to_le_bytes());
}
fn w_u64(b: &mut Vec<u8>, v: u64) {
    b.extend_from_slice(&v.to_le_bytes());
}
fn w_bytes(b: &mut Vec<u8>, v: &[u8]) {
    w_u64(b, v.len() as u64);
    b.extend_from_slice(v);
}
fn w_str(b: &mut Vec<u8>, v: &str) {
    w_bytes(b, v.as_bytes());
}

/// Cursor-based reader over an in-memory payload. Every accessor is
/// bounds-checked so a malformed/hostile message yields `InvalidData`, never a
/// panic.
pub(crate) struct Cur<'a> {
    b: &'a [u8],
    p: usize,
}
impl<'a> Cur<'a> {
    pub(crate) fn new(b: &'a [u8]) -> Self {
        Cur { b, p: 0 }
    }
    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        let end = self.p.checked_add(n).ok_or_else(bad)?;
        if end > self.b.len() {
            return Err(bad());
        }
        let s = &self.b[self.p..end];
        self.p = end;
        Ok(s)
    }
    fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn i32(&mut self) -> io::Result<i32> {
        Ok(i32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub(crate) fn u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub(crate) fn u64(&mut self) -> io::Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn bytes(&mut self) -> io::Result<Vec<u8>> {
        let n = self.u64()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    fn string(&mut self) -> io::Result<String> {
        let v = self.bytes()?;
        String::from_utf8(v).map_err(|_| bad())
    }
}

fn bad() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "malformed cuda-rpc message")
}

// ---- framing --------------------------------------------------------------

/// Write a length-prefixed payload as a **single** write.
///
/// Framing the length and payload into one buffer (rather than two `write_all`
/// calls) matters for latency: on a request/response protocol, a length-then-
/// payload pair triggers the classic write-write-read Nagle + delayed-ACK stall
/// (~40 ms/round-trip on TCP), and even on vsock it halves the syscall count.
/// One write per message is the single biggest per-call latency win.
pub fn write_msg<W: Write>(w: &mut W, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_MSG {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "message too large",
        ));
    }
    let len = (payload.len() as u32).to_le_bytes();
    // Small messages (control calls, launches): coalesce header+payload into one
    // write so the write-write-read Nagle/delayed-ACK stall can't happen; the
    // copy is negligible. Large messages (bulk memcpy): write the 4-byte header
    // then the payload directly — a large payload already fills segments (no
    // stall), and skipping the copy is a real bandwidth win for H2D/D2H.
    const COALESCE_MAX: usize = 64 * 1024;
    if payload.len() <= COALESCE_MAX {
        let mut framed = Vec::with_capacity(4 + payload.len());
        framed.extend_from_slice(&len);
        framed.extend_from_slice(payload);
        w.write_all(&framed)?;
    } else {
        w.write_all(&len)?;
        w.write_all(payload)?;
    }
    w.flush()
}

/// Read a length-prefixed payload. Returns `None` on a clean EOF at a frame
/// boundary (peer closed), `Err` on a truncated/oversized frame.
pub fn read_msg<R: Read>(r: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let n = u32::from_le_bytes(len) as usize;
    if n > MAX_MSG {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message too large",
        ));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)?;
    Ok(Some(buf))
}

// ---- request encode/decode ------------------------------------------------

pub fn encode_request(req: &Request) -> Vec<u8> {
    let mut b = Vec::new();
    match req {
        Request::Init {
            proto_hash,
            resume_token,
        } => {
            w_u8(&mut b, Op::Init as u8);
            w_u64(&mut b, *proto_hash);
            w_u64(&mut b, *resume_token);
        }
        Request::DeviceGetCount => w_u8(&mut b, Op::DeviceGetCount as u8),
        Request::DeviceGetName { device } => {
            w_u8(&mut b, Op::DeviceGetName as u8);
            w_i32(&mut b, *device);
        }
        Request::DeviceTotalMem { device } => {
            w_u8(&mut b, Op::DeviceTotalMem as u8);
            w_i32(&mut b, *device);
        }
        Request::DriverGetVersion => w_u8(&mut b, Op::DriverGetVersion as u8),
        Request::DeviceGetAttribute { attrib, device } => {
            w_u8(&mut b, Op::DeviceGetAttribute as u8);
            w_i32(&mut b, *attrib);
            w_i32(&mut b, *device);
        }
        Request::DeviceGetUuid { device } => {
            w_u8(&mut b, Op::DeviceGetUuid as u8);
            w_i32(&mut b, *device);
        }
        Request::CtxCreate { device } => {
            w_u8(&mut b, Op::CtxCreate as u8);
            w_i32(&mut b, *device);
        }
        Request::CtxDestroy { ctx } => {
            w_u8(&mut b, Op::CtxDestroy as u8);
            w_u64(&mut b, *ctx);
        }
        Request::PrimaryCtxRetain { device } => {
            w_u8(&mut b, Op::PrimaryCtxRetain as u8);
            w_i32(&mut b, *device);
        }
        Request::PrimaryCtxRelease { device } => {
            w_u8(&mut b, Op::PrimaryCtxRelease as u8);
            w_i32(&mut b, *device);
        }
        Request::ModuleLoadData { image } => {
            w_u8(&mut b, Op::ModuleLoadData as u8);
            w_bytes(&mut b, image);
        }
        Request::ModuleGetFunction { module, name } => {
            w_u8(&mut b, Op::ModuleGetFunction as u8);
            w_u64(&mut b, *module);
            w_str(&mut b, name);
        }
        Request::ModuleUnload { module } => {
            w_u8(&mut b, Op::ModuleUnload as u8);
            w_u64(&mut b, *module);
        }
        Request::FuncGetParamInfo { function } => {
            w_u8(&mut b, Op::FuncGetParamInfo as u8);
            w_u64(&mut b, *function);
        }
        Request::FuncGetAttribute { function, attrib } => {
            w_u8(&mut b, Op::FuncGetAttribute as u8);
            w_u64(&mut b, *function);
            w_i32(&mut b, *attrib);
        }
        Request::FuncSetAttribute {
            function,
            attrib,
            value,
        } => {
            w_u8(&mut b, Op::FuncSetAttribute as u8);
            w_u64(&mut b, *function);
            w_i32(&mut b, *attrib);
            w_i32(&mut b, *value);
        }
        Request::MemAlloc { bytes } => {
            w_u8(&mut b, Op::MemAlloc as u8);
            w_u64(&mut b, *bytes);
        }
        Request::MemFree { dptr } => {
            w_u8(&mut b, Op::MemFree as u8);
            w_u64(&mut b, *dptr);
        }
        Request::MemcpyHtoD { dptr, stream, data } => {
            w_u8(&mut b, Op::MemcpyHtoD as u8);
            w_u64(&mut b, *dptr);
            w_u64(&mut b, *stream);
            w_bytes(&mut b, data);
        }
        Request::MemcpyDtoH {
            dptr,
            bytes,
            stream,
        } => {
            w_u8(&mut b, Op::MemcpyDtoH as u8);
            w_u64(&mut b, *dptr);
            w_u64(&mut b, *bytes);
            w_u64(&mut b, *stream);
        }
        Request::MemcpyDtoD { dst, src, bytes } => {
            w_u8(&mut b, Op::MemcpyDtoD as u8);
            w_u64(&mut b, *dst);
            w_u64(&mut b, *src);
            w_u64(&mut b, *bytes);
        }
        Request::MemsetD8 { dptr, value, bytes } => {
            w_u8(&mut b, Op::MemsetD8 as u8);
            w_u64(&mut b, *dptr);
            w_u8(&mut b, *value);
            w_u64(&mut b, *bytes);
        }
        Request::MemGetInfo => w_u8(&mut b, Op::MemGetInfo as u8),
        Request::LaunchKernel {
            function,
            grid,
            block,
            shared_bytes,
            stream,
            params,
        } => {
            w_u8(&mut b, Op::LaunchKernel as u8);
            w_u64(&mut b, *function);
            for v in grid {
                w_u32(&mut b, *v);
            }
            for v in block {
                w_u32(&mut b, *v);
            }
            w_u32(&mut b, *shared_bytes);
            w_u64(&mut b, *stream);
            w_u32(&mut b, params.len() as u32);
            for p in params {
                w_bytes(&mut b, p);
            }
        }
        Request::CtxSynchronize => w_u8(&mut b, Op::CtxSynchronize as u8),
        Request::StreamBeginCapture { stream, mode } => {
            w_u8(&mut b, Op::StreamBeginCapture as u8);
            w_u64(&mut b, *stream);
            w_i32(&mut b, *mode);
        }
        Request::StreamEndCapture { stream, graph_vh } => {
            w_u8(&mut b, Op::StreamEndCapture as u8);
            w_u64(&mut b, *stream);
            w_u64(&mut b, *graph_vh);
        }
        Request::GraphInstantiate { graph, exec_vh } => {
            w_u8(&mut b, Op::GraphInstantiate as u8);
            w_u64(&mut b, *graph);
            w_u64(&mut b, *exec_vh);
        }
        Request::GraphLaunch { graph_exec, stream } => {
            w_u8(&mut b, Op::GraphLaunch as u8);
            w_u64(&mut b, *graph_exec);
            w_u64(&mut b, *stream);
        }
        Request::GraphExecDestroy { graph_exec } => {
            w_u8(&mut b, Op::GraphExecDestroy as u8);
            w_u64(&mut b, *graph_exec);
        }
        Request::GraphDestroy { graph } => {
            w_u8(&mut b, Op::GraphDestroy as u8);
            w_u64(&mut b, *graph);
        }
        Request::StreamCaptureInfo { stream } => {
            w_u8(&mut b, Op::StreamCaptureInfo as u8);
            w_u64(&mut b, *stream);
        }
        Request::GraphGetNodes { graph } => {
            w_u8(&mut b, Op::GraphGetNodes as u8);
            w_u64(&mut b, *graph);
        }
        Request::ThreadExchangeCaptureMode { mode } => {
            w_u8(&mut b, Op::ThreadExchangeCaptureMode as u8);
            w_i32(&mut b, *mode);
        }
        Request::MemsetD8Async {
            dptr,
            value,
            bytes,
            stream,
        } => {
            w_u8(&mut b, Op::MemsetD8Async as u8);
            w_u64(&mut b, *dptr);
            w_u8(&mut b, *value);
            w_u64(&mut b, *bytes);
            w_u64(&mut b, *stream);
        }
        Request::MemcpyDtoDAsync {
            dst,
            src,
            bytes,
            stream,
        } => {
            w_u8(&mut b, Op::MemcpyDtoDAsync as u8);
            w_u64(&mut b, *dst);
            w_u64(&mut b, *src);
            w_u64(&mut b, *bytes);
            w_u64(&mut b, *stream);
        }
        Request::StreamCreate { flags } => {
            w_u8(&mut b, Op::StreamCreate as u8);
            w_u32(&mut b, *flags);
        }
        Request::StreamDestroy { stream } => {
            w_u8(&mut b, Op::StreamDestroy as u8);
            w_u64(&mut b, *stream);
        }
        Request::StreamSynchronize { stream } => {
            w_u8(&mut b, Op::StreamSynchronize as u8);
            w_u64(&mut b, *stream);
        }
        Request::StreamQuery { stream } => {
            w_u8(&mut b, Op::StreamQuery as u8);
            w_u64(&mut b, *stream);
        }
        Request::StreamWaitEvent {
            stream,
            event,
            flags,
        } => {
            w_u8(&mut b, Op::StreamWaitEvent as u8);
            w_u64(&mut b, *stream);
            w_u64(&mut b, *event);
            w_u32(&mut b, *flags);
        }
        Request::EventQuery { event } => {
            w_u8(&mut b, Op::EventQuery as u8);
            w_u64(&mut b, *event);
        }
        Request::EventCreate { flags } => {
            w_u8(&mut b, Op::EventCreate as u8);
            w_u32(&mut b, *flags);
        }
        Request::EventDestroy { event } => {
            w_u8(&mut b, Op::EventDestroy as u8);
            w_u64(&mut b, *event);
        }
        Request::EventRecord { event, stream } => {
            w_u8(&mut b, Op::EventRecord as u8);
            w_u64(&mut b, *event);
            w_u64(&mut b, *stream);
        }
        Request::EventSynchronize { event } => {
            w_u8(&mut b, Op::EventSynchronize as u8);
            w_u64(&mut b, *event);
        }
        Request::EventElapsedTime { start, end } => {
            w_u8(&mut b, Op::EventElapsedTime as u8);
            w_u64(&mut b, *start);
            w_u64(&mut b, *end);
        }
        Request::NvcompDeflateTempSize {
            num_chunks,
            max_uncompressed_chunk_bytes,
            max_total_uncompressed_bytes,
        } => {
            w_u8(&mut b, Op::NvcompDeflateTempSize as u8);
            w_u64(&mut b, *num_chunks);
            w_u64(&mut b, *max_uncompressed_chunk_bytes);
            w_u64(&mut b, *max_total_uncompressed_bytes);
        }
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
            w_u8(&mut b, Op::NvcompDeflateDecompress as u8);
            for v in [
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
            ] {
                w_u64(&mut b, *v);
            }
        }
        Request::CublasCreate => w_u8(&mut b, Op::CublasCreate as u8),
        Request::CublasDestroy { handle } => {
            w_u8(&mut b, Op::CublasDestroy as u8);
            w_u64(&mut b, *handle);
        }
        Request::CublasSetStream { handle, stream } => {
            w_u8(&mut b, Op::CublasSetStream as u8);
            w_u64(&mut b, *handle);
            w_u64(&mut b, *stream);
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
            w_u8(&mut b, Op::CublasSgemm as u8);
            w_u64(&mut b, *handle);
            w_u32(&mut b, *transa);
            w_u32(&mut b, *transb);
            w_i32(&mut b, *m);
            w_i32(&mut b, *n);
            w_i32(&mut b, *k);
            w_u32(&mut b, *alpha_bits);
            w_u64(&mut b, *a);
            w_i32(&mut b, *lda);
            w_u64(&mut b, *bmat);
            w_i32(&mut b, *ldb);
            w_u32(&mut b, *beta_bits);
            w_u64(&mut b, *c);
            w_i32(&mut b, *ldc);
        }
        Request::LibCall { lib, func, args } => {
            w_u8(&mut b, Op::LibCall as u8);
            w_u8(&mut b, *lib);
            w_u32(&mut b, *func as u32);
            w_bytes(&mut b, args);
        }
        Request::MemcpyShmHtoD {
            dptr,
            offset,
            size,
            stream,
        } => {
            w_u8(&mut b, Op::MemcpyShmHtoD as u8);
            w_u64(&mut b, *dptr);
            w_u64(&mut b, *offset);
            w_u64(&mut b, *size);
            w_u64(&mut b, *stream);
        }
        Request::MemcpyShmDtoH {
            offset,
            dptr,
            size,
            stream,
        } => {
            w_u8(&mut b, Op::MemcpyShmDtoH as u8);
            w_u64(&mut b, *offset);
            w_u64(&mut b, *dptr);
            w_u64(&mut b, *size);
            w_u64(&mut b, *stream);
        }
        Request::MemcpyGpaHtoD {
            dptr,
            stream,
            segments,
        } => {
            w_u8(&mut b, Op::MemcpyGpaHtoD as u8);
            w_u64(&mut b, *dptr);
            w_u64(&mut b, *stream);
            w_gpa_segments(&mut b, segments);
        }
        Request::MemcpyGpaDtoH {
            dptr,
            stream,
            segments,
        } => {
            w_u8(&mut b, Op::MemcpyGpaDtoH as u8);
            w_u64(&mut b, *dptr);
            w_u64(&mut b, *stream);
            w_gpa_segments(&mut b, segments);
        }
        Request::RingSetup {
            page_size,
            req_pages,
            resp_pages,
            bounce_pages,
        } => {
            w_u8(&mut b, Op::RingSetup as u8);
            w_u32(&mut b, *page_size);
            for pages in [req_pages, resp_pages, bounce_pages] {
                w_u32(&mut b, pages.len() as u32);
                for gpa in pages {
                    w_u64(&mut b, *gpa);
                }
            }
        }
        Request::RingSetupFile {
            page_size,
            req_n,
            resp_n,
            bounce_n,
            fname,
        } => {
            w_u8(&mut b, Op::RingSetupFile as u8);
            w_u32(&mut b, *page_size);
            w_u32(&mut b, *req_n);
            w_u32(&mut b, *resp_n);
            w_u32(&mut b, *bounce_n);
            w_bytes(&mut b, fname);
        }
        Request::MemAddressReserve { size, align } => {
            w_u8(&mut b, Op::MemAddressReserve as u8);
            w_u64(&mut b, *size);
            w_u64(&mut b, *align);
        }
        Request::MemCreate { size, device } => {
            w_u8(&mut b, Op::MemCreate as u8);
            w_u64(&mut b, *size);
            w_i32(&mut b, *device);
        }
        Request::MemCreateVh {
            size,
            device,
            handle_vh,
        } => {
            w_u8(&mut b, Op::MemCreateVh as u8);
            w_u64(&mut b, *size);
            w_i32(&mut b, *device);
            w_u64(&mut b, *handle_vh);
        }
        Request::SetDeviceBase { device } => {
            w_u8(&mut b, Op::SetDeviceBase as u8);
            w_i32(&mut b, *device);
        }
        Request::MemMap {
            va,
            size,
            offset,
            handle,
        } => {
            w_u8(&mut b, Op::MemMap as u8);
            w_u64(&mut b, *va);
            w_u64(&mut b, *size);
            w_u64(&mut b, *offset);
            w_u64(&mut b, *handle);
        }
        Request::MemSetAccess { va, size, device } => {
            w_u8(&mut b, Op::MemSetAccess as u8);
            w_u64(&mut b, *va);
            w_u64(&mut b, *size);
            w_i32(&mut b, *device);
        }
        Request::MemUnmap { va, size } => {
            w_u8(&mut b, Op::MemUnmap as u8);
            w_u64(&mut b, *va);
            w_u64(&mut b, *size);
        }
        Request::MemRelease { handle } => {
            w_u8(&mut b, Op::MemRelease as u8);
            w_u64(&mut b, *handle);
        }
        Request::MemAddressFree { va, size } => {
            w_u8(&mut b, Op::MemAddressFree as u8);
            w_u64(&mut b, *va);
            w_u64(&mut b, *size);
        }
        Request::MemGetAllocationGranularity { device, flags } => {
            w_u8(&mut b, Op::MemGetAllocationGranularity as u8);
            w_i32(&mut b, *device);
            w_u32(&mut b, *flags);
        }
    }
    b
}

fn w_gpa_segments(b: &mut Vec<u8>, segs: &[(u64, u64)]) {
    w_u32(b, segs.len() as u32);
    for (gpa, len) in segs {
        w_u64(b, *gpa);
        w_u64(b, *len);
    }
}

pub fn decode_request(payload: &[u8]) -> io::Result<Request> {
    let mut c = Cur::new(payload);
    let op = Op::from_u8(c.u8()?).ok_or_else(bad)?;
    Ok(match op {
        // Decode Init leniently so a *shorter* Init from an older shim still
        // yields a Request rather than a decode error. A stale shim would
        // otherwise have its whole connection dropped as a "malformed message",
        // hiding the real cause; decoding here lets the proto_hash check reject
        // it *loudly* ("PROTOCOL MISMATCH … rebuild and restage both"). Missing
        // fields default to 0 — proto_hash is never 0 in practice, so an Init too
        // short to even carry a hash still mismatches and is rejected.
        Op::Init => Request::Init {
            proto_hash: c.u64().unwrap_or(0),
            resume_token: c.u64().unwrap_or(0),
        },
        Op::DeviceGetCount => Request::DeviceGetCount,
        Op::DeviceGetName => Request::DeviceGetName { device: c.i32()? },
        Op::DeviceTotalMem => Request::DeviceTotalMem { device: c.i32()? },
        Op::DriverGetVersion => Request::DriverGetVersion,
        Op::DeviceGetAttribute => Request::DeviceGetAttribute {
            attrib: c.i32()?,
            device: c.i32()?,
        },
        Op::DeviceGetUuid => Request::DeviceGetUuid { device: c.i32()? },
        Op::CtxCreate => Request::CtxCreate { device: c.i32()? },
        Op::CtxDestroy => Request::CtxDestroy { ctx: c.u64()? },
        Op::PrimaryCtxRetain => Request::PrimaryCtxRetain { device: c.i32()? },
        Op::PrimaryCtxRelease => Request::PrimaryCtxRelease { device: c.i32()? },
        Op::ModuleLoadData => Request::ModuleLoadData { image: c.bytes()? },
        Op::ModuleGetFunction => Request::ModuleGetFunction {
            module: c.u64()?,
            name: c.string()?,
        },
        Op::ModuleUnload => Request::ModuleUnload { module: c.u64()? },
        Op::FuncGetParamInfo => Request::FuncGetParamInfo { function: c.u64()? },
        Op::FuncSetAttribute => Request::FuncSetAttribute {
            function: c.u64()?,
            attrib: c.i32()?,
            value: c.i32()?,
        },
        Op::FuncGetAttribute => Request::FuncGetAttribute {
            function: c.u64()?,
            attrib: c.i32()?,
        },
        Op::MemAlloc => Request::MemAlloc { bytes: c.u64()? },
        Op::MemFree => Request::MemFree { dptr: c.u64()? },
        Op::MemcpyHtoD => Request::MemcpyHtoD {
            dptr: c.u64()?,
            stream: c.u64()?,
            data: c.bytes()?,
        },
        Op::MemcpyDtoH => Request::MemcpyDtoH {
            dptr: c.u64()?,
            bytes: c.u64()?,
            stream: c.u64()?,
        },
        Op::MemcpyDtoD => Request::MemcpyDtoD {
            dst: c.u64()?,
            src: c.u64()?,
            bytes: c.u64()?,
        },
        Op::MemsetD8 => Request::MemsetD8 {
            dptr: c.u64()?,
            value: c.u8()?,
            bytes: c.u64()?,
        },
        Op::MemGetInfo => Request::MemGetInfo,
        Op::LaunchKernel => {
            let function = c.u64()?;
            let grid = [c.u32()?, c.u32()?, c.u32()?];
            let block = [c.u32()?, c.u32()?, c.u32()?];
            let shared_bytes = c.u32()?;
            let stream = c.u64()?;
            let n = c.u32()? as usize;
            let mut params = Vec::with_capacity(n);
            for _ in 0..n {
                params.push(c.bytes()?);
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
        Op::CtxSynchronize => Request::CtxSynchronize,
        Op::StreamBeginCapture => Request::StreamBeginCapture {
            stream: c.u64()?,
            mode: c.i32()?,
        },
        Op::StreamEndCapture => Request::StreamEndCapture {
            stream: c.u64()?,
            graph_vh: c.u64()?,
        },
        Op::GraphInstantiate => Request::GraphInstantiate {
            graph: c.u64()?,
            exec_vh: c.u64()?,
        },
        Op::GraphLaunch => Request::GraphLaunch {
            graph_exec: c.u64()?,
            stream: c.u64()?,
        },
        Op::GraphExecDestroy => Request::GraphExecDestroy {
            graph_exec: c.u64()?,
        },
        Op::GraphDestroy => Request::GraphDestroy { graph: c.u64()? },
        Op::StreamCaptureInfo => Request::StreamCaptureInfo { stream: c.u64()? },
        Op::GraphGetNodes => Request::GraphGetNodes { graph: c.u64()? },
        Op::ThreadExchangeCaptureMode => Request::ThreadExchangeCaptureMode { mode: c.i32()? },
        Op::MemsetD8Async => Request::MemsetD8Async {
            dptr: c.u64()?,
            value: c.u8()?,
            bytes: c.u64()?,
            stream: c.u64()?,
        },
        Op::MemcpyDtoDAsync => Request::MemcpyDtoDAsync {
            dst: c.u64()?,
            src: c.u64()?,
            bytes: c.u64()?,
            stream: c.u64()?,
        },
        Op::StreamCreate => Request::StreamCreate { flags: c.u32()? },
        Op::StreamDestroy => Request::StreamDestroy { stream: c.u64()? },
        Op::StreamSynchronize => Request::StreamSynchronize { stream: c.u64()? },
        Op::StreamQuery => Request::StreamQuery { stream: c.u64()? },
        Op::StreamWaitEvent => Request::StreamWaitEvent {
            stream: c.u64()?,
            event: c.u64()?,
            flags: c.u32()?,
        },
        Op::EventQuery => Request::EventQuery { event: c.u64()? },
        Op::EventCreate => Request::EventCreate { flags: c.u32()? },
        Op::EventDestroy => Request::EventDestroy { event: c.u64()? },
        Op::EventRecord => Request::EventRecord {
            event: c.u64()?,
            stream: c.u64()?,
        },
        Op::EventSynchronize => Request::EventSynchronize { event: c.u64()? },
        Op::EventElapsedTime => Request::EventElapsedTime {
            start: c.u64()?,
            end: c.u64()?,
        },
        Op::NvcompDeflateTempSize => Request::NvcompDeflateTempSize {
            num_chunks: c.u64()?,
            max_uncompressed_chunk_bytes: c.u64()?,
            max_total_uncompressed_bytes: c.u64()?,
        },
        Op::NvcompDeflateDecompress => Request::NvcompDeflateDecompress {
            device_compressed_ptrs: c.u64()?,
            device_compressed_bytes: c.u64()?,
            device_uncompressed_bytes: c.u64()?,
            device_actual_uncompressed_bytes: c.u64()?,
            batch_size: c.u64()?,
            device_temp: c.u64()?,
            temp_bytes: c.u64()?,
            device_uncompressed_ptrs: c.u64()?,
            device_statuses: c.u64()?,
            stream: c.u64()?,
        },
        Op::CublasCreate => Request::CublasCreate,
        Op::CublasDestroy => Request::CublasDestroy { handle: c.u64()? },
        Op::CublasSetStream => Request::CublasSetStream {
            handle: c.u64()?,
            stream: c.u64()?,
        },
        Op::CublasSgemm => Request::CublasSgemm {
            handle: c.u64()?,
            transa: c.u32()?,
            transb: c.u32()?,
            m: c.i32()?,
            n: c.i32()?,
            k: c.i32()?,
            alpha_bits: c.u32()?,
            a: c.u64()?,
            lda: c.i32()?,
            b: c.u64()?,
            ldb: c.i32()?,
            beta_bits: c.u32()?,
            c: c.u64()?,
            ldc: c.i32()?,
        },
        Op::LibCall => Request::LibCall {
            lib: c.u8()?,
            func: c.u32()? as u16,
            args: c.bytes()?,
        },
        Op::MemcpyShmHtoD => Request::MemcpyShmHtoD {
            dptr: c.u64()?,
            offset: c.u64()?,
            size: c.u64()?,
            stream: c.u64()?,
        },
        Op::MemcpyShmDtoH => Request::MemcpyShmDtoH {
            offset: c.u64()?,
            dptr: c.u64()?,
            size: c.u64()?,
            stream: c.u64()?,
        },
        Op::MemcpyGpaHtoD => Request::MemcpyGpaHtoD {
            dptr: c.u64()?,
            stream: c.u64()?,
            segments: r_gpa_segments(&mut c)?,
        },
        Op::MemcpyGpaDtoH => Request::MemcpyGpaDtoH {
            dptr: c.u64()?,
            stream: c.u64()?,
            segments: r_gpa_segments(&mut c)?,
        },
        Op::RingSetup => {
            let page_size = c.u32()?;
            let mut lists = [const { Vec::new() }; 3];
            for list in lists.iter_mut() {
                let n = c.u32()? as usize;
                list.reserve(n.min(1 << 16));
                for _ in 0..n {
                    list.push(c.u64()?);
                }
            }
            let [req_pages, resp_pages, bounce_pages] = lists;
            Request::RingSetup {
                page_size,
                req_pages,
                resp_pages,
                bounce_pages,
            }
        }
        Op::RingSetupFile => Request::RingSetupFile {
            page_size: c.u32()?,
            req_n: c.u32()?,
            resp_n: c.u32()?,
            bounce_n: c.u32()?,
            fname: c.bytes()?,
        },
        Op::MemAddressReserve => Request::MemAddressReserve {
            size: c.u64()?,
            align: c.u64()?,
        },
        Op::MemCreate => Request::MemCreate {
            size: c.u64()?,
            device: c.i32()?,
        },
        Op::MemCreateVh => Request::MemCreateVh {
            size: c.u64()?,
            device: c.i32()?,
            handle_vh: c.u64()?,
        },
        Op::SetDeviceBase => Request::SetDeviceBase { device: c.i32()? },
        Op::MemMap => Request::MemMap {
            va: c.u64()?,
            size: c.u64()?,
            offset: c.u64()?,
            handle: c.u64()?,
        },
        Op::MemSetAccess => Request::MemSetAccess {
            va: c.u64()?,
            size: c.u64()?,
            device: c.i32()?,
        },
        Op::MemUnmap => Request::MemUnmap {
            va: c.u64()?,
            size: c.u64()?,
        },
        Op::MemRelease => Request::MemRelease { handle: c.u64()? },
        Op::MemAddressFree => Request::MemAddressFree {
            va: c.u64()?,
            size: c.u64()?,
        },
        Op::MemGetAllocationGranularity => Request::MemGetAllocationGranularity {
            device: c.i32()?,
            flags: c.u32()?,
        },
    })
}

fn r_gpa_segments(c: &mut Cur) -> io::Result<Vec<(u64, u64)>> {
    let n = c.u32()? as usize;
    let mut segs = Vec::with_capacity(n.min(1 << 20));
    for _ in 0..n {
        segs.push((c.u64()?, c.u64()?));
    }
    Ok(segs)
}

// ---- response encode/decode -----------------------------------------------

/// Encode a response: `i32 status` then, only when `status == 0`, the body.
pub fn encode_response(status: i32, resp: &Response) -> Vec<u8> {
    let mut b = Vec::new();
    w_i32(&mut b, status);
    if status == 0 {
        match resp {
            Response::Ok => {}
            Response::Count(v) => w_i32(&mut b, *v),
            Response::Name(s) => w_str(&mut b, s),
            Response::Bytes(v) | Response::Handle(v) | Response::Dptr(v) => w_u64(&mut b, *v),
            Response::Data(d) => w_bytes(&mut b, d),
            Response::Pair(a, z) => {
                w_u64(&mut b, *a);
                w_u64(&mut b, *z);
            }
            Response::Millis(ms) => w_u32(&mut b, ms.to_bits()),
            Response::LibResult(status, out) => {
                w_i32(&mut b, *status);
                w_bytes(&mut b, out);
            }
        }
    }
    b
}

/// Decode a response for `op`. Returns `(status, body)`; `body` is `Response::Ok`
/// when status != 0 (error — no body on the wire).
pub fn decode_response(op: Op, payload: &[u8]) -> io::Result<(i32, Response)> {
    let mut c = Cur::new(payload);
    let status = c.i32()?;
    if status != 0 {
        return Ok((status, Response::Ok));
    }
    let body = match op {
        Op::DeviceGetCount
        | Op::DriverGetVersion
        | Op::DeviceGetAttribute
        | Op::ThreadExchangeCaptureMode
        | Op::StreamQuery
        | Op::EventQuery
        | Op::FuncGetAttribute => Response::Count(c.i32()?),
        Op::DeviceGetName => Response::Name(c.string()?),
        Op::DeviceTotalMem => Response::Bytes(c.u64()?),
        // Init hands back this session's lineage token (for fork-clone handoff).
        Op::Init => Response::Handle(c.u64()?),
        Op::CtxCreate | Op::PrimaryCtxRetain => Response::Handle(c.u64()?),
        Op::ModuleLoadData | Op::ModuleGetFunction => Response::Handle(c.u64()?),
        Op::StreamCreate | Op::EventCreate => Response::Handle(c.u64()?),
        Op::StreamEndCapture | Op::GraphInstantiate => Response::Handle(c.u64()?),
        Op::GraphGetNodes => Response::Bytes(c.u64()?),
        Op::StreamCaptureInfo => Response::Pair(c.u64()?, c.u64()?),
        Op::MemAlloc => Response::Dptr(c.u64()?),
        Op::MemcpyDtoH | Op::DeviceGetUuid | Op::FuncGetParamInfo => Response::Data(c.bytes()?),
        Op::MemGetInfo => Response::Pair(c.u64()?, c.u64()?),
        // nvcomp calls carry their own nvcompStatus in the body (transport
        // status stays 0): TempSize -> (status, temp_bytes); Decompress -> status.
        Op::NvcompDeflateTempSize => Response::Pair(c.u64()?, c.u64()?),
        Op::NvcompDeflateDecompress => Response::Count(c.i32()?),
        Op::CublasCreate => Response::Handle(c.u64()?),
        Op::LibCall => Response::LibResult(c.i32()?, c.bytes()?),
        Op::EventElapsedTime => Response::Millis(f32::from_bits(c.u32()?)),
        Op::StreamBeginCapture
        | Op::GraphLaunch
        | Op::GraphExecDestroy
        | Op::GraphDestroy
        | Op::MemsetD8Async
        | Op::MemcpyDtoDAsync
        | Op::CtxDestroy
        | Op::PrimaryCtxRelease
        | Op::ModuleUnload
        | Op::FuncSetAttribute
        | Op::MemFree
        | Op::MemcpyHtoD
        | Op::MemcpyDtoD
        | Op::MemsetD8
        | Op::LaunchKernel
        | Op::CtxSynchronize
        | Op::StreamDestroy
        | Op::StreamSynchronize
        | Op::StreamWaitEvent
        | Op::EventDestroy
        | Op::EventRecord
        | Op::EventSynchronize
        | Op::CublasDestroy
        | Op::CublasSetStream
        | Op::CublasSgemm
        | Op::MemcpyShmHtoD
        | Op::MemcpyShmDtoH
        | Op::MemcpyGpaHtoD
        | Op::MemcpyGpaDtoH
        | Op::RingSetup
        | Op::RingSetupFile
        | Op::MemMap
        | Op::MemSetAccess
        | Op::MemUnmap
        | Op::MemRelease
        | Op::MemAddressFree
        | Op::MemCreateVh
        | Op::SetDeviceBase => Response::Ok,
        Op::MemAddressReserve => Response::Dptr(c.u64()?),
        Op::MemCreate => Response::Handle(c.u64()?),
        Op::MemGetAllocationGranularity => Response::Bytes(c.u64()?),
    };
    Ok((status, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(req: Request) {
        let enc = encode_request(&req);
        let dec = decode_request(&enc).expect("decode");
        assert_eq!(req, dec);
    }

    #[test]
    fn request_roundtrips() {
        roundtrip(Request::Init {
            proto_hash: 0xdeadbeef,
            resume_token: 0x1234,
        });
        roundtrip(Request::DeviceGetCount);
        roundtrip(Request::DeviceGetName { device: 3 });
        roundtrip(Request::DeviceTotalMem { device: 0 });
        roundtrip(Request::CtxCreate { device: 1 });
        roundtrip(Request::CtxDestroy { ctx: 0xdead_beef });
        roundtrip(Request::ModuleLoadData {
            image: b".version 7.0\n".to_vec(),
        });
        roundtrip(Request::ModuleGetFunction {
            module: 42,
            name: "vecadd".into(),
        });
        roundtrip(Request::MemAlloc { bytes: 4096 });
        roundtrip(Request::MemFree { dptr: 0x7f00_0000 });
        roundtrip(Request::MemcpyHtoD {
            dptr: 0x7f00_0000,
            stream: 0x7001,
            data: vec![1, 2, 3, 4],
        });
        roundtrip(Request::MemcpyDtoH {
            dptr: 0x7f00_0000,
            bytes: 16,
            stream: 0x7001,
        });
        roundtrip(Request::LaunchKernel {
            function: 7,
            grid: [4, 1, 1],
            block: [256, 1, 1],
            shared_bytes: 0,
            stream: 0,
            params: vec![
                0x1000u64.to_le_bytes().to_vec(),
                0x2000u64.to_le_bytes().to_vec(),
                1024u32.to_le_bytes().to_vec(),
            ],
        });
        roundtrip(Request::CtxSynchronize);
    }

    // A stale shim sends a shorter Init (older wire format). It must still
    // *decode* — with missing fields defaulting to 0 — so the host's proto_hash
    // check can reject it loudly, rather than the frame failing to decode and
    // the connection being silently dropped as "malformed" (which hid the real
    // version-skew cause during the torch bring-up debugging).
    #[test]
    fn short_init_decodes_for_loud_rejection() {
        // Full-length Init (current format).
        let full = decode_request(&encode_request(&Request::Init {
            proto_hash: 0xabcd,
            resume_token: 7,
        }))
        .expect("full Init decodes");
        assert_eq!(
            full,
            Request::Init {
                proto_hash: 0xabcd,
                resume_token: 7
            }
        );

        // Older shim: op + proto_hash only (no resume_token) → resume_token = 0.
        let mut short = vec![Op::Init as u8];
        short.extend_from_slice(&0xabcdu64.to_le_bytes());
        assert_eq!(
            decode_request(&short).expect("short Init still decodes"),
            Request::Init {
                proto_hash: 0xabcd,
                resume_token: 0
            }
        );

        // Pre-handshake shim: just the op byte → proto_hash = 0 (never a real
        // hash, so it will mismatch and be rejected loudly).
        assert_eq!(
            decode_request(&[Op::Init as u8]).expect("bare Init still decodes"),
            Request::Init {
                proto_hash: 0,
                resume_token: 0
            }
        );
    }

    #[test]
    fn extended_request_roundtrips() {
        roundtrip(Request::DriverGetVersion);
        roundtrip(Request::DeviceGetAttribute {
            attrib: 75,
            device: 0,
        });
        roundtrip(Request::DeviceGetUuid { device: 0 });
        roundtrip(Request::PrimaryCtxRetain { device: 0 });
        roundtrip(Request::PrimaryCtxRelease { device: 0 });
        roundtrip(Request::ModuleUnload { module: 7 });
        roundtrip(Request::FuncGetParamInfo { function: 9 });
        roundtrip(Request::FuncSetAttribute {
            function: 9,
            attrib: 8,
            value: 73728,
        });
        roundtrip(Request::MemcpyDtoD {
            dst: 0x2000,
            src: 0x1000,
            bytes: 64,
        });
        roundtrip(Request::MemsetD8 {
            dptr: 0x1000,
            value: 0xAB,
            bytes: 128,
        });
        roundtrip(Request::MemGetInfo);
        roundtrip(Request::StreamCreate { flags: 1 });
        roundtrip(Request::StreamDestroy { stream: 3 });
        roundtrip(Request::StreamSynchronize { stream: 3 });
        roundtrip(Request::EventCreate { flags: 0 });
        roundtrip(Request::EventDestroy { event: 4 });
        roundtrip(Request::EventRecord {
            event: 4,
            stream: 0,
        });
        roundtrip(Request::EventSynchronize { event: 4 });
        roundtrip(Request::EventElapsedTime { start: 4, end: 5 });
        roundtrip(Request::StreamQuery { stream: 3 });
        roundtrip(Request::StreamWaitEvent {
            stream: 3,
            event: 4,
            flags: 0,
        });
        roundtrip(Request::EventQuery { event: 4 });
        roundtrip(Request::ThreadExchangeCaptureMode { mode: 2 });
    }

    #[test]
    fn extended_response_roundtrips() {
        for (op, resp) in [
            (Op::DriverGetVersion, Response::Count(13000)),
            (Op::DeviceGetAttribute, Response::Count(1024)),
            (Op::DeviceGetUuid, Response::Data(vec![0u8; 16])),
            (Op::PrimaryCtxRetain, Response::Handle(11)),
            (
                Op::FuncGetParamInfo,
                Response::Data(vec![8, 0, 0, 0, 4, 0, 0, 0]),
            ),
            (Op::MemGetInfo, Response::Pair(6 << 30, 8 << 30)),
            (Op::StreamCreate, Response::Handle(21)),
            (Op::EventCreate, Response::Handle(22)),
            (Op::EventElapsedTime, Response::Millis(1.25)),
            (Op::ModuleUnload, Response::Ok),
            (Op::MemsetD8, Response::Ok),
        ] {
            let enc = encode_response(0, &resp);
            let (status, dec) = decode_response(op, &enc).expect("decode");
            assert_eq!(status, 0);
            assert_eq!(dec, resp);
        }
    }

    #[test]
    fn response_roundtrips() {
        for (op, resp) in [
            (Op::DeviceGetCount, Response::Count(2)),
            (
                Op::DeviceGetName,
                Response::Name("NVIDIA GeForce RTX 3070".into()),
            ),
            (Op::DeviceTotalMem, Response::Bytes(8 << 30)),
            (Op::CtxCreate, Response::Handle(99)),
            (Op::ModuleLoadData, Response::Handle(1)),
            (Op::MemAlloc, Response::Dptr(0x7f00_0000)),
            (Op::MemcpyDtoH, Response::Data(vec![9, 8, 7])),
            (Op::CtxSynchronize, Response::Ok),
        ] {
            let enc = encode_response(0, &resp);
            let (status, dec) = decode_response(op, &enc).expect("decode");
            assert_eq!(status, 0);
            assert_eq!(dec, resp);
        }
    }

    #[test]
    fn error_response_has_no_body() {
        let enc = encode_response(700, &Response::Handle(123)); // CUDA_ERROR_*
        let (status, body) = decode_response(Op::ModuleLoadData, &enc).unwrap();
        assert_eq!(status, 700);
        assert_eq!(body, Response::Ok); // body omitted on error
        assert_eq!(enc.len(), 4); // status only
    }

    #[test]
    fn framing_roundtrip_and_eof() {
        let mut buf = Vec::new();
        let payload = encode_request(&Request::DeviceGetCount);
        write_msg(&mut buf, &payload).unwrap();
        let mut cur = std::io::Cursor::new(buf);
        let got = read_msg(&mut cur).unwrap().expect("frame");
        assert_eq!(got, payload);
        // clean EOF at boundary
        assert!(read_msg(&mut cur).unwrap().is_none());
    }

    #[test]
    fn truncated_message_is_error_not_panic() {
        // opcode says ModuleGetFunction but payload is truncated mid-string
        let mut b = vec![Op::ModuleGetFunction as u8];
        b.extend_from_slice(&7u64.to_le_bytes()); // module
        b.extend_from_slice(&100u64.to_le_bytes()); // claims 100-byte name…
        b.extend_from_slice(b"short"); // …but only 5 bytes follow
        assert!(decode_request(&b).is_err());
    }
}
