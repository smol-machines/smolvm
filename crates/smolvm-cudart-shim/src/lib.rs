//! Drop-in `libcudart.so.11.0` for smolvm guests: the CUDA **Runtime API**,
//! implemented by lowering each call to the public CUDA **Driver API** and
//! remoting that over smolvm's CUDA vsock RPC to the host GPU.
//!
//! Why this exists: NVIDIA's own `libcudart` bootstraps through a private,
//! undocumented driver interface (`cuGetExportTable` with an internal UUID),
//! which a black-box `libcuda` shim cannot provide — so Runtime-API programs
//! (anything `nvcc`-compiled, and frameworks on top) cannot run on the Driver-
//! API shim alone. This library replaces `libcudart` instead of the driver:
//! every `cuda*` / `__cuda*` entry point a program links is served here by
//! lowering to public Driver-API calls (`cuModuleLoadData`, `cuLaunchKernel`,
//! `cuMemAlloc`, …) that the existing host CUDA server already executes on the
//! real GPU. No host-side changes; it reuses the Driver-API RPC wholesale.
//!
//! Interpose it with `LD_PRELOAD=/path/libcudart.so.11.0` (or stage it ahead of
//! the program's own copy on `LD_LIBRARY_PATH`). Transport is selected by
//! `SMOLVM_CUDA_RPC` exactly as the libcuda shim: unset/`vsock` (in-guest),
//! `tcp:HOST:PORT`, or `unix:/path` (host-side testing).
//!
//! Semantics: work executes synchronously on the host, so `*Async` calls and
//! streams collapse to ordered-and-complete (permitted — an implementation may
//! be more synchronous than requested). Device pointers are the host's real
//! `CUdeviceptr` values, opaque to the guest; pinned host memory
//! (`cudaHostAlloc`) is plain guest RAM (the "pinned" property is a host-only
//! optimization that does not cross the boundary). Kernel launch reconstructs
//! `kernelParams` from per-argument sizes the host reports via
//! `cuFuncGetParamInfo` (needs a CUDA 12.4+ host driver).

#![allow(clippy::not_unsafe_ptr_arg_deref)]
#![allow(non_snake_case)]

use smolvm_cuda::client::{Client, CudaRpcError};
use smolvm_cuda::proto::Request;
mod cublas_stubs;
use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{c_char, c_int, c_uint, c_void, CStr};
use std::io::{Read, Write};
use std::sync::Mutex;

// ---- cudaError_t codes we produce locally -----------------------------------

const CUDA_SUCCESS: c_int = 0;
const CUDA_ERROR_INVALID_VALUE: c_int = 1;
const CUDA_ERROR_MEMORY_ALLOCATION: c_int = 2;
const CUDA_ERROR_INITIALIZATION: c_int = 3;
const CUDA_ERROR_INVALID_SYMBOL: c_int = 13;
const CUDA_ERROR_INVALID_DEVICE_POINTER: c_int = 17;
const CUDA_ERROR_INVALID_RESOURCE_HANDLE: c_int = 400;
const CUDA_ERROR_ILLEGAL_STATE: c_int = 401;
const CUDA_ERROR_NO_DEVICE: c_int = 100;
const CUDA_ERROR_NOT_SUPPORTED: c_int = 801;
const CUDA_ERROR_UNKNOWN: c_int = 999;

// cudaMemcpyKind
const MEMCPY_HTOH: c_int = 0;
const MEMCPY_HTOD: c_int = 1;
const MEMCPY_DTOH: c_int = 2;
const MEMCPY_DTOD: c_int = 3;
const MEMCPY_DEFAULT: c_int = 4;

/// A `dim3` passed by value across the C ABI (three unsigned ints).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Dim3 {
    x: c_uint,
    y: c_uint,
    z: c_uint,
}

// ---- transport (mirrors smolvm-cuda-shim) -----------------------------------

enum Stream {
    #[cfg(target_os = "linux")]
    Vsock(vsock::VsockStream),
    Tcp(std::net::TcpStream),
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixStream),
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            #[cfg(target_os = "linux")]
            Stream::Vsock(s) => s.read(buf),
            Stream::Tcp(s) => s.read(buf),
            #[cfg(unix)]
            Stream::Unix(s) => s.read(buf),
        }
    }
}
impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            #[cfg(target_os = "linux")]
            Stream::Vsock(s) => s.write(buf),
            Stream::Tcp(s) => s.write(buf),
            #[cfg(unix)]
            Stream::Unix(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            #[cfg(target_os = "linux")]
            Stream::Vsock(s) => s.flush(),
            Stream::Tcp(s) => s.flush(),
            #[cfg(unix)]
            Stream::Unix(s) => s.flush(),
        }
    }
}

#[cfg(unix)]
impl Stream {
    fn raw_fd(&self) -> std::os::unix::io::RawFd {
        use std::os::unix::io::AsRawFd;
        match self {
            #[cfg(target_os = "linux")]
            Stream::Vsock(s) => s.as_raw_fd(),
            Stream::Tcp(s) => s.as_raw_fd(),
            Stream::Unix(s) => s.as_raw_fd(),
        }
    }
}

/// Best-effort liveness of the host connection via a non-blocking, non-consuming
/// `MSG_PEEK`. A VM-fork clone inherits a socket whose host peer is gone; the
/// guest kernel resets it, so the peek sees EOF/ECONNRESET and we know to
/// reconnect. Returns `true` when the connection is usable (data pending, or
/// simply no data yet), `false` on a clean close or fatal socket error. Peeking
/// is safe in shared-memory-ring mode too: pending doorbell bytes read as
/// "alive" and stay queued for the real read.
#[cfg(unix)]
fn conn_alive(fd: std::os::unix::io::RawFd) -> bool {
    let mut b = [0u8; 1];
    let n = unsafe {
        libc::recv(
            fd,
            b.as_mut_ptr() as *mut libc::c_void,
            1,
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    if n > 0 {
        true
    } else if n == 0 {
        false // orderly shutdown by the peer
    } else {
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        e == libc::EAGAIN || e == libc::EWOULDBLOCK
    }
}

fn connect() -> Result<Stream, c_int> {
    let spec = std::env::var("SMOLVM_CUDA_RPC").unwrap_or_default();
    if let Some(addr) = spec.strip_prefix("tcp:") {
        return std::net::TcpStream::connect(addr)
            .map(|s| {
                let _ = s.set_nodelay(true); // low-latency request/response
                Stream::Tcp(s)
            })
            .map_err(|_| CUDA_ERROR_NO_DEVICE);
    }
    #[cfg(unix)]
    if let Some(path) = spec.strip_prefix("unix:") {
        return std::os::unix::net::UnixStream::connect(path)
            .map(Stream::Unix)
            .map_err(|_| CUDA_ERROR_NO_DEVICE);
    }
    #[cfg(target_os = "linux")]
    {
        const HOST_CID: u32 = 2;
        const CUDA_PORT: u32 = 7000;
        vsock::VsockStream::connect_with_cid_port(HOST_CID, CUDA_PORT)
            .map(Stream::Vsock)
            .map_err(|_| CUDA_ERROR_NO_DEVICE)
    }
    #[cfg(not(target_os = "linux"))]
    Err(CUDA_ERROR_NO_DEVICE)
}

// ---- global state -----------------------------------------------------------

/// A registered kernel: its host-side driver function id and the byte size of
/// each `__global__` parameter, in declaration order.
struct FuncRec {
    fid: u64,
    param_sizes: Vec<u32>,
}

/// A CUDA 12+ runtime library lowered to the existing Driver-API module RPCs.
/// Kernel handles minted from the library are tracked so unload invalidates
/// them just like the native runtime does.
struct LibraryRec {
    module: u64,
    device: i32,
    kernels: Vec<usize>,
    globals: Vec<u64>,
}

#[derive(Clone)]
struct SymbolRec {
    module: u64,
    name: String,
    address: u64,
}

#[derive(Clone)]
struct StaticFuncRec {
    fatbin: usize,
    name: String,
}

#[derive(Clone)]
struct StaticSymbolRec {
    fatbin: usize,
    name: String,
}

struct ShimState {
    client: Client<Stream>,
    initialized: bool,
    /// `__cudaRegisterFatBinary` handle (the pointer we minted) → driver module id.
    modules: HashMap<(i32, usize), u64>,
    /// `__cudaRegisterFunction` host stub pointer → resolved kernel.
    funcs: HashMap<(i32, usize), FuncRec>,
    /// `cudaLibrary_t` virtual handle → loaded driver module and its kernels.
    libraries: HashMap<usize, LibraryRec>,
    /// Runtime host-symbol address → module/name for driver global lookup.
    symbols: HashMap<(i32, usize), SymbolRec>,
    /// Host pinned-memory allocations (guest RAM) → layout, for cudaFreeHost.
    host_allocs: HashMap<usize, std::alloc::Layout>,
    /// CPU-visible mapped-host range → daemon GPU-visible pointer. The two
    /// virtual addresses differ across the remoting boundary.
    host_device_ptrs: std::collections::BTreeMap<u64, (u64, u64)>,
    driver_host_allocs: std::collections::HashSet<u64>,
    /// Live device allocations, base → size. Range-queried (not exact-match):
    /// PyTorch's caching allocator suballocates, so tensor data pointers are
    /// interior to a cudaMalloc'd block — `cudaPointerGetAttributes` on one
    /// must still report Device or torch's `getDeviceFromPtr` throws.
    dev_allocs: std::collections::BTreeMap<u64, (u64, i32)>,
    /// Active CUDA graph captures keyed by root stream. Multiple relaxed-mode
    /// captures may coexist in one process. Root-stream queries stay local;
    /// side streams use the host capture ID to find the matching local record.
    captures: HashMap<u64, CaptureRecord>,
    /// Virtual captured graph handle → exact node count returned alongside the
    /// synchronous EndCapture response. This makes GraphGetNodes a local,
    /// truthful query rather than one extra RTT per graph.
    graph_node_counts: HashMap<u64, usize>,
    /// Same-flag raw events provisioned in one host round trip. Frameworks
    /// create/destroy events at very high frequency; keeping a small local
    /// handle reserve removes synchronous creation RTTs without changing event
    /// ordering, query, or destruction semantics.
    event_spares: HashMap<(i32, u32), Vec<u64>>,
    stream_devices: HashMap<u64, i32>,
    event_devices: HashMap<u64, i32>,
    /// PID that opened `client`. If the process forks (or a snapshotted VM is
    /// restored as a clone), the inherited socket fd + ring mapping belong to
    /// the parent and are dead here; a mismatch triggers a transparent
    /// reconnect. The registries above survive because every connection retains
    /// the same device primary context, so their raw module / function / device
    /// handles stay valid across the new connection.
    conn_pid: i32,
    /// Lineage token the host assigned this session. Inherited by a fork clone
    /// (it lives in this CoW guest memory), so on reconnect the clone replays it
    /// as the resume token and the host seeds the clone's fresh connection with
    /// the parent's cuBLAS/cuDNN handle map. 0 = host has no handoff support.
    conn_token: u64,
    /// Raw fd of `client`'s socket, for the pre-call liveness peek. A VM-fork
    /// clone (same pid, so the pid check can't fire) inherits a dead socket;
    /// the peek catches it and triggers a reconnect. -1 = no fd / skip.
    conn_fd: i32,
    /// Set when an op just hit a transport error: the peek can miss a freshly
    /// severed connection (the kernel hasn't processed the reset yet on the
    /// first post-fork call), so `with_client_retrying` forces an unconditional
    /// reconnect on its retry instead of trusting the peek.
    force_reconnect: bool,
    /// Primary-context handles retained on this host connection, keyed by the
    /// guest-visible device ordinal, plus the device currently bound on the
    /// single host serving thread.
    primary_ctx: HashMap<i32, u64>,
    bound_device: Option<i32>,
    /// Exact context currently bound on the daemon's single serving thread.
    /// Driver and runtime calls share this connection, so a device ordinal
    /// alone cannot describe an explicit driver context.
    bound_context: Option<u64>,
    /// Driver API's intended current context. Runtime calls temporarily bind a
    /// primary context; the next bridged driver call restores this one first.
    bridge_context: Option<u64>,
}

#[derive(Clone, Copy)]
struct CaptureRecord {
    local_id: u64,
    host_id: Option<u64>,
}

static STATE: Mutex<Option<ShimState>> = Mutex::new(None);
// Native libcudart only records static fatbins during ELF initialization and
// materializes a module when one of its kernels/globals is first used. Keep the
// same split here: registration must not connect to the host or upload hundreds
// of unused modules in tokenizer/controller processes that merely import torch.
static STATIC_MODULES: Mutex<Option<HashMap<usize, Vec<u8>>>> = Mutex::new(None);
static STATIC_FUNCS: Mutex<Option<HashMap<usize, StaticFuncRec>>> = Mutex::new(None);
static STATIC_SYMBOLS: Mutex<Option<HashMap<usize, StaticSymbolRec>>> = Mutex::new(None);

thread_local! {
    /// `__cudaPushCallConfiguration` stash, popped by `__cudaPopCallConfiguration`.
    static CALL_CONFIG: RefCell<Vec<(Dim3, Dim3, usize, u64)>> = const { RefCell::new(Vec::new()) };
    /// Last error, for cudaGetLastError / cudaPeekAtLastError.
    static LAST_ERROR: std::cell::Cell<c_int> = const { std::cell::Cell::new(CUDA_SUCCESS) };
    /// Set by `map_err` when the failure was TRANSPORT (Io/Protocol), i.e. the
    /// op never reached the host. `retry_transport_c` consults this to decide
    /// that one forced-reconnect retry runs the op exactly once.
    static TRANSPORT_ERR: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// CUDA runtime device selection is thread-local. The shared RPC connection
    /// rebinds its host context before serving each calling thread.
    static CURRENT_DEVICE: std::cell::Cell<c_int> = const { std::cell::Cell::new(0) };
}

fn set_last(code: c_int) -> c_int {
    if code != CUDA_SUCCESS {
        if std::env::var_os("SMOLVM_CUDA_SHIM_TRACE").is_some() {
            let bt = std::backtrace::Backtrace::force_capture().to_string();
            let frames: Vec<&str> = bt.lines().take(16).collect();
            eprintln!("[shim-err] code={code} frames:\n{}", frames.join("\n"));
        }
        LAST_ERROR.with(|e| e.set(code));
    }
    code
}

/// Map a Driver-API `CUresult`/transport failure to a `cudaError_t`.
fn map_err(e: CudaRpcError) -> c_int {
    match e {
        CudaRpcError::Cuda(code) => match code {
            0 => CUDA_SUCCESS,
            1 => CUDA_ERROR_INVALID_VALUE,
            2 => CUDA_ERROR_MEMORY_ALLOCATION,
            200 | 218 => CUDA_ERROR_INVALID_VALUE, // invalid image / PTX
            400 => CUDA_ERROR_INVALID_RESOURCE_HANDLE,
            801 => CUDA_ERROR_NOT_SUPPORTED,
            // Driver and Runtime capture failures intentionally use the same
            // numeric range. Preserve them so frameworks can distinguish an
            // invalidated capture from a transport or unknown device failure.
            900..=910 => code,
            other => {
                if std::env::var_os("SMOLVM_CUDA_SHIM_TRACE").is_some() {
                    eprintln!("[map-err] unmapped driver code {other}");
                }
                CUDA_ERROR_UNKNOWN
            }
        },
        CudaRpcError::Io(_) | CudaRpcError::Protocol(_) => {
            if std::env::var_os("SMOLVM_CUDA_SHIM_TRACE").is_some() {
                eprintln!("[map-err] transport: {e}");
            }
            TRANSPORT_ERR.with(|t| t.set(true));
            CUDA_ERROR_UNKNOWN
        }
    }
}

fn map_symbol_err(e: CudaRpcError) -> c_int {
    match e {
        CudaRpcError::Cuda(500) => CUDA_ERROR_INVALID_SYMBOL,
        other => map_err(other),
    }
}

/// Run `f`, and if it failed because the TRANSPORT died (not a device error),
/// force a reconnect (which replays the quiet-op journal) and run it once
/// more. A VM-fork clone's first ops race the reconnect: the pre-call
/// liveness peek can miss the dead inherited channel (the guest pid is
/// unchanged, the socket reset may not have surfaced, and ring writes vanish
/// into cloned pages no host reads), so the op dies with a transport error
/// the host never saw — safe to rerun exactly once.
fn retry_transport_c(f: impl Fn() -> c_int) -> c_int {
    TRANSPORT_ERR.with(|t| t.set(false));
    let rc = f();
    if rc != CUDA_SUCCESS && TRANSPORT_ERR.with(|t| t.get()) {
        mark_force_reconnect();
        TRANSPORT_ERR.with(|t| t.set(false));
        return f();
    }
    rc
}

/// Lazily connect and bring up a primary context, then run `f` against the
/// client. The first call performs `cuInit` + `cuDevicePrimaryCtxRetain(0)`
/// (which the host binds current on its serving thread), matching how the CUDA
/// runtime brings up its device on first use.
/// Cross-shim ordering hook, dlsym'd by the driver shim (`libcuda.so.1`).
/// The two shims hold separate connections to the host, i.e. two ordering
/// domains for one guest program-order stream; the driver shim fences this
/// connection before each of its own ops so runtime-issued work (deferred in
/// the pipeline) executes first. No-op before the runtime connection exists.
#[no_mangle]
pub extern "C" fn smolvm_cudart_fence() {
    if let Ok(mut guard) = STATE.lock() {
        if let Some(st) = guard.as_mut() {
            let _ = st.client.drain();
        }
    }
}

fn tensor_publish_sync(client: &mut Client<Stream>) -> Result<(), CudaRpcError> {
    client.drain()?;
    let request = smolvm_cuda::proto::encode_request(&smolvm_cuda::proto::Request::CtxSynchronize);
    let response = client.raw_call(&request)?;
    if response.len() < 4 {
        return Err(CudaRpcError::Protocol("short forced synchronize response"));
    }
    let status = i32::from_le_bytes(response[..4].try_into().unwrap());
    if status != 0 {
        return Err(CudaRpcError::Cuda(status));
    }
    match client.take_sticky() {
        0 => Ok(()),
        status => Err(CudaRpcError::Cuda(status)),
    }
}

/// Publish selected CUDA tensors to smolvm's managed rollout consumer without
/// serializing a checkpoint through guest RAM or disk. This is intentionally a
/// smolvm-specific ABI rather than an implementation of generic CUDA IPC.
///
/// On success, `token_len` receives the opaque token length and `token` receives
/// those bytes. `token_capacity` must be at least 64 bytes; smaller buffers are
/// rejected before any allocation is published.
#[no_mangle]
pub extern "C" fn smolvm_cuda_publish_tensor_bundle(
    manifest: *const u8,
    manifest_len: usize,
    dptrs: *const u64,
    sizes: *const u64,
    count: usize,
    token: *mut u8,
    token_capacity: usize,
    token_len: *mut usize,
) -> c_int {
    if manifest_len > 1 << 20
        || count == 0
        || count > 65_536
        || (manifest_len != 0 && manifest.is_null())
        || dptrs.is_null()
        || sizes.is_null()
        || token.is_null()
        || token_capacity < 64
        || token_len.is_null()
    {
        return set_last(CUDA_ERROR_INVALID_VALUE);
    }
    // SAFETY: the caller promises readable arrays of `count` u64s and a
    // readable manifest of `manifest_len` bytes for the duration of this call.
    let manifest = if manifest_len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(manifest, manifest_len) }.to_vec()
    };
    let dptrs = unsafe { std::slice::from_raw_parts(dptrs, count) };
    let sizes = unsafe { std::slice::from_raw_parts(sizes, count) };
    if dptrs
        .iter()
        .zip(sizes)
        .any(|(&dptr, &size)| dptr == 0 || size == 0)
    {
        return set_last(CUDA_ERROR_INVALID_VALUE);
    }
    // Quiesce framework-owned streams before the host copies their tensors.
    // This idempotent preflight is also the clone-boundary reconnect barrier:
    // the first post-restore call can race the inherited socket reset, so use
    // the transport-safe retry path before the deliberately at-most-once
    // publication request.
    let trace = std::env::var_os("SMOLVM_CUDA_SHIM_TRACE").is_some();
    if trace {
        eprintln!("[tensor-publish] reconnect/sync preflight");
    }
    if let Err(error) = with_client_retrying(tensor_publish_sync) {
        return set_last(error);
    }
    if trace {
        eprintln!("[tensor-publish] preflight complete; sending publication");
    }
    let tensors = dptrs.iter().copied().zip(sizes.iter().copied()).collect();
    // Publication is not retried implicitly: once the host has accepted a
    // bundle, a lost reply may leave a short-lived orphan that its TTL reaps;
    // replaying here would publish duplicate driver references.
    let published = with_client(|client| client.publish_tensor_bundle(manifest, tensors));
    let published = match published {
        Ok(published) => published,
        Err(error) => return set_last(error),
    };
    if trace {
        eprintln!("[tensor-publish] publication accepted");
    }
    // SAFETY: token_len was validated non-null above.
    unsafe { token_len.write(published.len()) };
    if published.len() > token_capacity {
        return set_last(CUDA_ERROR_INVALID_VALUE);
    }
    // SAFETY: the caller supplied at least `token_capacity` writable bytes.
    unsafe { std::ptr::copy_nonoverlapping(published.as_ptr(), token, published.len()) };
    CUDA_SUCCESS
}

// ---- driver-shim bridge -------------------------------------------------------
// The driver shim (`libcuda.so.1`) dlsym-resolves these three and routes ALL
// its traffic through this connection, giving the host one program-ordered
// pipeline for both shims (see smolvm-cuda's `client::Bridge`). Op statuses
// stay in-band in the response payload — nothing is lost to error mapping.

/// A response too large for the caller's buffer, parked until the caller
/// retries with a big-enough one (null request = fetch).
static BRIDGE_PENDING: Mutex<Option<Vec<u8>>> = Mutex::new(None);

fn set_bound_context(state: &mut ShimState, context: u64) {
    state.bound_context = Some(context);
    state.bound_device = state
        .primary_ctx
        .iter()
        .find_map(|(&device, &candidate)| (candidate == context).then_some(device));
}

/// Restore the driver API's current context after any intervening runtime API
/// call. Both APIs share one daemon connection, so this must happen while the
/// same state lock also protects the following driver request.
fn prepare_bridge_context(state: &mut ShimState) -> Result<(), c_int> {
    if let Some(context) = state.bridge_context {
        if state.bound_context != Some(context) {
            state.client.ctx_set_current(context).map_err(map_err)?;
            set_bound_context(state, context);
        }
    }
    Ok(())
}

fn response_succeeded(payload: &[u8]) -> bool {
    payload
        .get(..4)
        .map(|status| i32::from_le_bytes(status.try_into().unwrap()) == 0)
        .unwrap_or(false)
}

fn response_handle(payload: &[u8]) -> Option<u64> {
    response_succeeded(payload)
        .then(|| payload.get(4..12))
        .flatten()
        .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
}

/// Mirror context-changing driver requests so later bridged operations can be
/// rebound after a runtime call temporarily selected another device/context.
fn finish_bridge_context(state: &mut ShimState, request: &Request, payload: &[u8]) {
    if !response_succeeded(payload) {
        return;
    }
    match request {
        Request::CtxSetCurrent { ctx } => {
            state.bridge_context = Some(*ctx);
            set_bound_context(state, *ctx);
        }
        Request::CtxCreate { device } | Request::PrimaryCtxRetain { device } => {
            if let Some(context) = response_handle(payload) {
                if matches!(request, Request::PrimaryCtxRetain { .. }) {
                    state.primary_ctx.entry(*device).or_insert(context);
                }
                state.bridge_context = Some(context);
                set_bound_context(state, context);
            }
        }
        Request::CtxDestroy { ctx } if state.bridge_context == Some(*ctx) => {
            state.bridge_context = Some(0);
            set_bound_context(state, 0);
        }
        Request::PrimaryCtxRelease { device }
            if state
                .primary_ctx
                .get(device)
                .is_some_and(|context| state.bridge_context == Some(*context)) =>
        {
            state.bridge_context = None;
            state.bound_context = None;
            state.bound_device = None;
        }
        _ => {}
    }
}

fn bridge_raw_quiet(bytes: &[u8]) -> Result<(), c_int> {
    let request = smolvm_cuda::proto::decode_request(bytes).ok();
    with_client_state(false, |state| {
        prepare_bridge_context(state)?;
        state.client.raw_quiet(bytes).map_err(map_err)?;
        // CtxSetCurrent is ordered but response-free. Mirror its virtual
        // context immediately so the next bridged Driver call does not restore
        // the context that preceded this queued bind.
        if let Some(Request::CtxSetCurrent { ctx }) = request {
            state.bridge_context = Some(ctx);
            set_bound_context(state, ctx);
        }
        Ok(())
    })
}

fn bridge_raw_call(bytes: &[u8]) -> Result<Vec<u8>, c_int> {
    let request = smolvm_cuda::proto::decode_request(bytes).ok();
    with_client_state(false, |state| {
        prepare_bridge_context(state)?;
        let payload = state.client.raw_call(bytes).map_err(map_err)?;
        if let Some(request) = request.as_ref() {
            finish_bridge_context(state, request, &payload);
        }
        Ok(payload)
    })
}

/// Fire-and-forget: append one encoded request to the shared pipeline.
/// Nonzero = transport failure.
#[no_mangle]
pub extern "C" fn smolvm_cudart_bridge_quiet(req: *const u8, len: usize) -> i32 {
    if req.is_null() {
        return 1;
    }
    let bytes = unsafe { std::slice::from_raw_parts(req, len) };
    // Transport-classified retry (see retry_transport_c): a fork clone's
    // bridged op racing the reconnect never reached the host — rerun once.
    TRANSPORT_ERR.with(|t| t.set(false));
    match bridge_raw_quiet(bytes) {
        Ok(()) => 0,
        Err(_) if TRANSPORT_ERR.with(|t| t.get()) => {
            mark_force_reconnect();
            TRANSPORT_ERR.with(|t| t.set(false));
            match bridge_raw_quiet(bytes) {
                Ok(()) => 0,
                Err(_) => 999,
            }
        }
        Err(_) => 999,
    }
}

/// Synchronous round-trip: send one encoded request, write the response
/// payload into `resp`. Returns the response length; -1 = transport failure;
/// other negatives = `cap` too small, retry with `-ret` capacity and a null
/// request to collect the stashed response.
#[no_mangle]
pub extern "C" fn smolvm_cudart_bridge_call(
    req: *const u8,
    req_len: usize,
    resp: *mut u8,
    cap: usize,
) -> isize {
    let payload = if req.is_null() {
        match BRIDGE_PENDING.lock().map(|mut g| g.take()) {
            Ok(Some(p)) => p,
            _ => return -1,
        }
    } else {
        let bytes = unsafe { std::slice::from_raw_parts(req, req_len) };
        TRANSPORT_ERR.with(|t| t.set(false));
        match bridge_raw_call(bytes) {
            Ok(p) => p,
            Err(_) if TRANSPORT_ERR.with(|t| t.get()) => {
                mark_force_reconnect();
                TRANSPORT_ERR.with(|t| t.set(false));
                match bridge_raw_call(bytes) {
                    Ok(p) => p,
                    Err(_) => return -1,
                }
            }
            Err(_) => return -1,
        }
    };
    if payload.len() > cap {
        let n = payload.len() as isize;
        match BRIDGE_PENDING.lock() {
            Ok(mut g) => {
                *g = Some(payload);
                -n
            }
            Err(_) => -1,
        }
    } else {
        unsafe { std::ptr::copy_nonoverlapping(payload.as_ptr(), resp, payload.len()) };
        payload.len() as isize
    }
}

/// Fence the shared pipeline; returns (and consumes) the first collected
/// quiet-failure status, so the bridged caller can surface it.
#[no_mangle]
pub extern "C" fn smolvm_cudart_bridge_drain() -> i32 {
    with_client(|c| {
        c.drain()?;
        Ok(c.take_sticky())
    })
    .unwrap_or(999)
}

/// Allocate one ring region: pinned pages + their per-page GPAs.
fn ring_alloc_pages(pages: usize) -> Option<(Vec<*mut u8>, Vec<u64>)> {
    const PAGE: usize = 4096;
    let base = guestmem::alloc(pages * PAGE)? as usize;
    // Zero (also faults every page in before pagemap reads).
    unsafe { std::ptr::write_bytes(base as *mut u8, 0, pages * PAGE) };
    let segs = guestmem::segments(base, pages * PAGE, false)?;
    let mut gpas = Vec::with_capacity(pages);
    for (gpa, len) in segs {
        let mut off = 0;
        while off < len {
            gpas.push(gpa + off);
            off += PAGE as u64;
        }
    }
    if gpas.len() != pages {
        return None;
    }
    Some((
        (0..pages).map(|i| (base + i * PAGE) as *mut u8).collect(),
        gpas,
    ))
}

/// Try to switch `client` to the shared-memory ring transport. Failure is
/// fine — the connection simply stays on the socket.
fn ring_try_setup(client: &mut Client<Stream>) {
    const PAGE: usize = 4096;
    let trace = std::env::var_os("SMOLVM_CUDA_SHIM_TRACE").is_some();
    let Some(req) = ring_alloc_pages(32) else {
        if trace {
            eprintln!("[ring] no pinned pages (zerocopy off?) — socket mode");
        }
        return;
    };
    let (Some(resp), Some(bounce)) = (ring_alloc_pages(8), ring_alloc_pages(64)) else {
        return;
    };
    match client.ring_setup(PAGE, req, resp, bounce) {
        Ok(()) => {
            if trace {
                eprintln!("[ring] shared-memory rings active");
            }
        }
        Err(e) => {
            if trace {
                eprintln!("[ring] setup rejected ({e}) — socket mode");
            }
        }
    }
}

/// File-backed ring fallback (DAX clone transport). When the GPA ring is
/// rejected (clones: their COW RAM is invisible to the daemon), create a
/// uniquely-named file on the dax ring mount, mmap it MAP_SHARED (a FRESH
/// mapping — inherited dax mappings die across fork, fresh ones are
/// host-coherent), and negotiate `RingSetupFile`. Failure is fine — socket
/// mode continues.
#[cfg(target_os = "linux")]
fn ring_try_setup_file(client: &mut Client<Stream>) {
    const PAGE: usize = 4096;
    const REQ_N: usize = 32;
    const RESP_N: usize = 8;
    const BOUNCE_N: usize = 64;
    let trace = std::env::var_os("SMOLVM_CUDA_SHIM_TRACE").is_some();
    let dir = std::env::var("SMOLVM_CUDA_RING_DIR").unwrap_or_else(|_| "/opt/smolvm-ring".into());
    if !std::path::Path::new(&dir).is_dir() {
        if trace {
            eprintln!("[ring-file] no ring dir {dir} — socket mode");
        }
        return;
    }
    // Unique per (process, attempt): a clone shares the golden's ring dir, so
    // names must never collide with the golden's (or a sibling's) live file.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // SAFETY: plain clock read into a local.
    let t: i64 = unsafe {
        let mut ts: libc::timespec = std::mem::zeroed();
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
        ts.tv_nsec as i64 ^ (ts.tv_sec as i64) << 20
    };
    let fname = format!("ring-{}-{}-{}.bin", std::process::id(), seq, t as u64);
    let path = format!("{dir}/{fname}");
    let total = (REQ_N + RESP_N + BOUNCE_N) * PAGE;
    let Ok(f) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
    else {
        if trace {
            eprintln!("[ring-file] create {path} failed — socket mode");
        }
        return;
    };
    if f.set_len(total as u64).is_err() {
        let _ = std::fs::remove_file(&path);
        return;
    }
    // SAFETY: fresh mmap of a regular file on the dax mount; pages stay
    // mapped for the process lifetime.
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
        let _ = std::fs::remove_file(&path);
        if trace {
            eprintln!("[ring-file] mmap failed — socket mode");
        }
        return;
    }
    // Zero the ring headers so producer/consumer indices start clean.
    // SAFETY: base..base+total is our fresh mapping.
    unsafe { std::ptr::write_bytes(base as *mut u8, 0, total) };
    let pages = |start: usize, n: usize| -> Vec<*mut u8> {
        (0..n)
            .map(|i| (base as usize + (start + i) * PAGE) as *mut u8)
            .collect()
    };
    match client.ring_setup_file(
        PAGE,
        &fname,
        (base.cast(), total),
        pages(0, REQ_N),
        pages(REQ_N, RESP_N),
        pages(REQ_N + RESP_N, BOUNCE_N),
    ) {
        Ok(()) => {
            // Both sides have mapped the inode now; keeping a directory entry
            // would accumulate one visible tmpfs file per process/reconnect.
            let _ = std::fs::remove_file(&path);
            if trace {
                eprintln!("[ring-file] file-backed rings active ({fname})");
            }
        }
        Err(e) => {
            // SAFETY: unmapping the mapping we created above.
            unsafe { libc::munmap(base, total) };
            let _ = std::fs::remove_file(&path);
            if trace {
                eprintln!("[ring-file] setup rejected ({e}) — socket mode");
            }
        }
    }
}

/// Open a fresh transport, run the init handshake (adopting `resume_token`'s
/// session handle map if non-zero), retain device 0's primary context, and
/// (best-effort) set up the shared-memory rings. Used for the first connection
/// and to re-establish one after a fork/clone. Returns the client and the
/// lineage token the host assigned this session.
/// Bound a socket's blocking reads (0 = restore fully blocking). Used only
/// around bring-up: a connection that is ACCEPTED but never answered (e.g. the
/// CUDA host service isn't actually up behind the port) must fail cuInit in
/// seconds, not hang the first torch import forever.
#[cfg(unix)]
fn set_recv_timeout(fd: i32, secs: i64) {
    let tv = libc::timeval {
        tv_sec: secs,
        tv_usec: 0,
    };
    // SAFETY: plain setsockopt on our own connected socket fd.
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }
}

fn bring_up_client(resume_token: u64) -> Result<(Client<Stream>, u64, i32, u64), c_int> {
    let stream = connect()?;
    #[cfg(target_os = "linux")]
    let try_ring = matches!(stream, Stream::Vsock(_))
        && std::env::var("SMOLVM_CUDA_RING").as_deref() != Ok("0");
    #[cfg(not(target_os = "linux"))]
    let try_ring = false;
    // Capture the socket fd for the liveness check before `Client` takes the
    // stream. Rings keep this same socket (for doorbells), so it stays valid.
    #[cfg(unix)]
    let fd = stream.raw_fd();
    #[cfg(not(unix))]
    let fd = -1;
    let trace = std::env::var_os("SHIM_TRACE").is_some();
    if trace {
        eprintln!("[shim] bring_up: connected fd={fd}");
    }
    // A fork clone's reconnect handshake waits for its worker's full golden
    // reconstruction (chunk imports + copies + module staging) — give it real
    // headroom; a fresh session's handshake stays tight.
    #[cfg(unix)]
    set_recv_timeout(fd, if resume_token != 0 { 90 } else { 60 });
    let mut client = Client::new(stream);
    let token = client.init(resume_token).map_err(|e| {
        if trace {
            eprintln!("[shim] bring_up: init FAILED {e:?}");
        }
        CUDA_ERROR_INITIALIZATION
    })?;
    // Per-machine GPU pin: guest device 0 maps to host device N and the guest
    // sees exactly one device. Sent before any device query or ctx retain.
    if let Some(d) = std::env::var("SMOLVM_CUDA_DEVICE")
        .ok()
        .and_then(|v| v.parse::<i32>().ok())
    {
        let _ = client.set_device_base(d);
    }
    if trace {
        eprintln!("[shim] bring_up: init ok token={token}");
    }
    let primary_ctx = client.primary_ctx_retain(0).map_err(|e| {
        if trace {
            eprintln!("[shim] bring_up: primary_ctx_retain FAILED {e:?}");
        }
        CUDA_ERROR_INITIALIZATION
    })?;
    if trace {
        eprintln!("[shim] bring_up: primary_ctx_retain ok");
    }
    if try_ring {
        ring_try_setup(&mut client); // best-effort; socket mode on failure
        #[cfg(target_os = "linux")]
        if !client.is_ring() {
            // GPA rings rejected (clone COW RAM is daemon-invisible): try the
            // DAX file-ring transport instead.
            ring_try_setup_file(&mut client);
        }
    }
    // Bring-up answered: restore fully blocking reads (steady-state ops may
    // legitimately wait longer than the handshake bound).
    #[cfg(unix)]
    set_recv_timeout(fd, 0);
    if trace {
        eprintln!("[shim] bring_up: complete");
    }
    Ok((client, token, fd, primary_ctx))
}

fn with_client_state<T>(
    bind_runtime_context: bool,
    f: impl FnOnce(&mut ShimState) -> Result<T, c_int>,
) -> Result<T, c_int> {
    let mut guard = STATE.lock().map_err(|_| CUDA_ERROR_UNKNOWN)?;
    let pid = unsafe { libc::getpid() };
    match guard.as_mut() {
        None => {
            let (client, token, fd, primary_ctx) = bring_up_client(0)?;
            *guard = Some(ShimState {
                client,
                initialized: true,
                modules: HashMap::new(),
                funcs: HashMap::new(),
                libraries: HashMap::new(),
                symbols: HashMap::new(),
                host_allocs: HashMap::new(),
                host_device_ptrs: std::collections::BTreeMap::new(),
                driver_host_allocs: std::collections::HashSet::new(),
                dev_allocs: std::collections::BTreeMap::new(),
                captures: HashMap::new(),
                graph_node_counts: HashMap::new(),
                event_spares: HashMap::new(),
                stream_devices: HashMap::new(),
                event_devices: HashMap::new(),
                conn_pid: pid,
                conn_token: token,
                conn_fd: fd,
                force_reconnect: false,
                primary_ctx: HashMap::from([(0, primary_ctx)]),
                bound_device: Some(0),
                bound_context: Some(primary_ctx),
                bridge_context: None,
            });
        }
        // We forked and the inherited connection is dead — either an in-guest
        // process fork (pid changes) or a snapshotted VM restored as a clone
        // (pid is preserved, so the socket peek is what catches it). Either way
        // re-establish in place, resuming the parent's lineage token so the host
        // seeds this connection with the parent's library handle map. The
        // registries stay valid: the reconnected session retains the same device
        // primary context.
        Some(st) => {
            let forked = st.conn_pid != pid;
            #[cfg(unix)]
            let severed = st.conn_fd >= 0 && !conn_alive(st.conn_fd);
            #[cfg(not(unix))]
            let severed = false;
            let forced = st.force_reconnect;
            if forked || severed || forced {
                if std::env::var_os("SHIM_TRACE").is_some() {
                    eprintln!(
                        "[shim] reconnect (forked={forked} severed={severed} forced={forced}) resume_token={}",
                        st.conn_token
                    );
                }
                // Carry every quiet op not yet PROVEN consumed (no host response
                // received since it was sent) across the reconnect. A fork
                // clone's inherited transport swallows writes without erroring —
                // ring records go into cloned pages no host reads — so ops
                // "sent" pre-reconnect (e.g. torch's queued launches before the
                // first sync) would otherwise be silently lost, leaving reads
                // stale and compute wrong.
                let (journal, sticky) = st.client.take_journal();
                let (mut client, token, fd, primary_ctx) = bring_up_client(st.conn_token)?;
                if let Err(e) = client.replay_journal(journal, sticky) {
                    if std::env::var_os("SHIM_TRACE").is_some() {
                        eprintln!("[shim] journal replay failed: {e:?}");
                    }
                    return Err(map_err(e));
                }
                st.client = client;
                st.conn_token = token;
                st.conn_pid = pid;
                st.conn_fd = fd;
                st.force_reconnect = false;
                st.primary_ctx.clear();
                st.primary_ctx.insert(0, primary_ctx);
                st.bound_device = Some(0);
                st.bound_context = Some(primary_ctx);
                st.bridge_context = None;
                st.captures.clear(); // in-flight captures belonged to the parent
                                     // The old session owns and reclaims unused provisioned events;
                                     // none of its raw handles may be issued after reconnect/fork.
                st.event_spares.clear();
            }
        }
    }
    let st = guard.as_mut().ok_or(CUDA_ERROR_INITIALIZATION)?;
    debug_assert!(st.initialized);
    if bind_runtime_context {
        let desired = CURRENT_DEVICE.with(|device| device.get());
        let ctx = match st.primary_ctx.get(&desired).copied() {
            Some(ctx) => ctx,
            None => {
                let ctx = st.client.primary_ctx_retain(desired).map_err(map_err)?;
                st.primary_ctx.insert(desired, ctx);
                ctx
            }
        };
        if st.bound_context != Some(ctx) {
            st.client.ctx_set_current(ctx).map_err(map_err)?;
        }
        st.bound_device = Some(desired);
        st.bound_context = Some(ctx);
    }
    f(st)
}

fn with_client<T>(
    f: impl FnOnce(&mut Client<Stream>) -> Result<T, CudaRpcError>,
) -> Result<T, c_int> {
    with_client_state(true, |state| f(&mut state.client).map_err(map_err))
}

/// Like [`with_client`], but transparently retries once on a transport error.
/// After a VM-fork the clone's inherited connection is dead, but the pre-call
/// liveness peek can miss it on the very first call (the kernel hasn't surfaced
/// the reset yet) — so that call fails with a transport error (`999`). This
/// forces a reconnect and reruns `f`, which then reads from the reconnected
/// (shared-context) session. For ops safe to rerun after a TRANSPORT failure
/// (reads, syncs, queries, and sync library calls): the failure means the op
/// never reached the host, so the retry runs it exactly once. Takes `Fn` (not
/// `FnOnce`) precisely so it can run twice — closures clone their args per
/// attempt.
/// Debug (`SMOLVM_CUDA_SHIM_TRACE=1`): print which generated library wrapper
/// swallowed an error into its c_int return, with the mapped code.
fn lib_err_trace(lib: u8, func: u16, code: c_int) {
    if std::env::var_os("SMOLVM_CUDA_SHIM_TRACE").is_some() {
        eprintln!("[lib-err] lib={lib} func={func} code={code}");
    }
}

fn with_client_retrying<T>(
    f: impl Fn(&mut Client<Stream>) -> Result<T, CudaRpcError>,
) -> Result<T, c_int> {
    TRANSPORT_ERR.with(|t| t.set(false));
    match with_client(&f) {
        // Retry only when the failure was TRANSPORT (op never reached the
        // host) — retrying on any CUDA_ERROR_UNKNOWN would re-run ops the
        // device may have executed (unmapped driver codes also map to 999).
        Err(e) if TRANSPORT_ERR.with(|t| t.get()) => {
            let _ = e;
            mark_force_reconnect();
            TRANSPORT_ERR.with(|t| t.set(false));
            with_client(&f)
        }
        other => other,
    }
}

/// Run `f` with the full state (client + registries) under the lock.
fn with_state<T>(f: impl FnOnce(&mut ShimState) -> Result<T, c_int>) -> Result<T, c_int> {
    with_client_state(true, f)
}

fn with_client_on_device<T>(
    device: i32,
    f: impl FnOnce(&mut Client<Stream>) -> Result<T, CudaRpcError>,
) -> Result<T, c_int> {
    let previous = CURRENT_DEVICE.with(|current| current.replace(device));
    if let Ok(mut state) = STATE.lock() {
        if let Some(state) = state.as_mut() {
            state.bound_device = None;
            state.bound_context = None;
        }
    }
    let result = with_client(f);
    CURRENT_DEVICE.with(|current| current.set(previous));
    result
}

fn with_state_on_device<T>(
    device: i32,
    f: impl FnOnce(&mut ShimState) -> Result<T, c_int>,
) -> Result<T, c_int> {
    let previous = CURRENT_DEVICE.with(|current| current.replace(device));
    if let Ok(mut state) = STATE.lock() {
        if let Some(state) = state.as_mut() {
            state.bound_device = None;
            state.bound_context = None;
        }
    }
    let result = with_state(f);
    CURRENT_DEVICE.with(|current| current.set(previous));
    result
}

fn stream_device(stream: *mut c_void) -> i32 {
    if stream.is_null() {
        return CURRENT_DEVICE.with(|current| current.get());
    }
    STATE
        .lock()
        .ok()
        .and_then(|state| {
            state
                .as_ref()
                .and_then(|state| state.stream_devices.get(&(stream as u64)).copied())
        })
        .unwrap_or_else(|| CURRENT_DEVICE.with(|current| current.get()))
}

fn event_device(event: *mut c_void) -> i32 {
    STATE
        .lock()
        .ok()
        .and_then(|state| {
            state
                .as_ref()
                .and_then(|state| state.event_devices.get(&(event as u64)).copied())
        })
        .unwrap_or_else(|| CURRENT_DEVICE.with(|current| current.get()))
}

fn function_device(function: *const c_void) -> i32 {
    STATE
        .lock()
        .ok()
        .and_then(|state| {
            state.as_ref().and_then(|state| {
                state.funcs.iter().find_map(|(&(device, handle), record)| {
                    (handle == function as usize || record.fid == function as u64).then_some(device)
                })
            })
        })
        .unwrap_or_else(|| CURRENT_DEVICE.with(|current| current.get()))
}

unsafe fn out<T>(p: *mut T, v: T) -> c_int {
    if p.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    unsafe { p.write(v) };
    CUDA_SUCCESS
}

// ---- device / init ----------------------------------------------------------

#[no_mangle]
pub extern "C" fn cudaGetDeviceCount(count: *mut c_int) -> c_int {
    set_last(match cached_device_count() {
        Ok(n) => unsafe { out(count, n) },
        Err(e) => {
            // A CUDA program treats "0 devices" as recoverable; surface the count.
            unsafe { out(count, 0) };
            e
        }
    })
}

fn cached_device_count() -> Result<c_int, c_int> {
    use std::sync::atomic::{AtomicI32, Ordering};
    static DEVICE_COUNT: AtomicI32 = AtomicI32::new(-1);
    let cached = DEVICE_COUNT.load(Ordering::Relaxed);
    if cached >= 0 {
        return Ok(cached);
    }
    let count = with_client_retrying(|client| client.device_get_count())?;
    DEVICE_COUNT.store(count, Ordering::Relaxed);
    Ok(count)
}

#[no_mangle]
pub extern "C" fn cudaSetDevice(device: c_int) -> c_int {
    if device < 0 {
        return set_last(CUDA_ERROR_INVALID_VALUE);
    }
    let count = match cached_device_count() {
        Ok(count) => count,
        Err(error) => return set_last(error),
    };
    if device >= count {
        return set_last(CUDA_ERROR_INVALID_VALUE);
    }
    let previous = CURRENT_DEVICE.with(|current| current.replace(device));
    match with_client(|_| Ok(())) {
        Ok(()) => set_last(CUDA_SUCCESS),
        Err(error) => {
            CURRENT_DEVICE.with(|current| current.set(previous));
            set_last(error)
        }
    }
}

#[no_mangle]
pub extern "C" fn cudaGetDevice(device: *mut c_int) -> c_int {
    set_last(unsafe { out(device, CURRENT_DEVICE.with(|current| current.get())) })
}

#[no_mangle]
pub extern "C" fn cudaDeviceSynchronize() -> c_int {
    set_last(match with_client_retrying(|c| c.ctx_synchronize()) {
        Ok(()) => CUDA_SUCCESS,
        Err(e) => e,
    })
}

/// Context / device limits (stack size, printf FIFO, malloc heap, …).
/// Mirror `cuCtxGetLimit` / `cuCtxSetLimit` in the driver shim: report a generous
/// stack-size default on get, accept any set. Conda PyTorch (`libtorch_cuda.so`)
/// version-requires `cudaDeviceSetLimit@libcudart.so.12` at import time; without
/// this export, bind-mount staging of the shim over a real cudart fails the
/// dynamic linker before any CUDA call runs.
#[no_mangle]
pub extern "C" fn cudaDeviceGetLimit(pvalue: *mut usize, _limit: c_int) -> c_int {
    if pvalue.is_null() {
        return set_last(CUDA_ERROR_INVALID_VALUE);
    }
    // Match driver-shim stack-size default (Triton / launcher setup reads this).
    unsafe { *pvalue = 8 * 1024 * 1024 };
    set_last(CUDA_SUCCESS)
}

#[no_mangle]
pub extern "C" fn cudaDeviceSetLimit(_limit: c_int, _value: usize) -> c_int {
    set_last(CUDA_SUCCESS)
}

/// The CUDA surface this shim advertises (mirrors the cuda-shim's
/// `shim_cuda_version`): `SMOLVM_CUDA_ADVERTISE` overrides, default 12.4.
/// Never report the HOST's real driver/runtime version — guest libraries
/// negotiate entry points for whatever they see, and the shim only fully
/// provides the cu12 surface (a leaked 13000 sent cuBLASLt down cu13 paths
/// that ended in 209 NO_BINARY_FOR_GPU on sm90).
fn advertised_cuda_version() -> c_int {
    static V: std::sync::OnceLock<c_int> = std::sync::OnceLock::new();
    *V.get_or_init(|| {
        std::env::var("SMOLVM_CUDA_ADVERTISE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(12040)
    })
}

#[no_mangle]
pub extern "C" fn cudaDriverGetVersion(version: *mut c_int) -> c_int {
    set_last(unsafe { out(version, advertised_cuda_version()) })
}

#[no_mangle]
pub extern "C" fn cudaRuntimeGetVersion(version: *mut c_int) -> c_int {
    set_last(unsafe { out(version, advertised_cuda_version()) })
}

// ---- memory -----------------------------------------------------------------

#[no_mangle]
pub extern "C" fn cudaMalloc(dev_ptr: *mut *mut c_void, size: usize) -> c_int {
    set_last(retry_transport_c(|| {
        match with_state(|s| {
            let d = s.client.mem_alloc(size as u64).map_err(map_err)?;
            s.dev_allocs.insert(
                d,
                (size as u64, CURRENT_DEVICE.with(|current| current.get())),
            );
            Ok(d)
        }) {
            Ok(d) => unsafe { out(dev_ptr, d as *mut c_void) },
            Err(e) => e,
        }
    }))
}

/// `cudaMallocManaged` — unified memory the CPU and GPU both access by the same
/// pointer. Through API remoting to a discrete GPU that cannot page-fault into
/// guest RAM, that is unserviceable: a guest-CPU dereference of a real host
/// device address reads garbage. So by default we FAIL (writing a NULL
/// out-pointer), turning silent corruption into an immediate, obvious crash —
/// this is exactly bitsandbytes' *paged* optimizer path (`get_paged` wraps the
/// pointer as a host numpy array). `SMOLVM_CUDA_MANAGED=device` restores the
/// old device-backed behavior for workloads that only ever touch the pointer
/// on the GPU (never on the CPU); use it only when you know that holds.
#[no_mangle]
pub extern "C" fn cudaMallocManaged(
    dev_ptr: *mut *mut c_void,
    size: usize,
    _flags: c_uint,
) -> c_int {
    if std::env::var("SMOLVM_CUDA_MANAGED").as_deref() == Ok("device") {
        return cudaMalloc(dev_ptr, size);
    }
    if !dev_ptr.is_null() {
        unsafe { *dev_ptr = std::ptr::null_mut() };
    }
    // cudaErrorNotSupported: host-coherent managed memory can't cross the
    // forwarding boundary. (SMOLVM_CUDA_MANAGED=device to override.)
    set_last(801)
}

/// Managed-memory prefetch hint: nothing to do, our "managed" memory is
/// always device-resident.
#[no_mangle]
pub extern "C" fn cudaMemPrefetchAsync(
    _dev_ptr: *const c_void,
    _count: usize,
    _dst_device: c_int,
    _stream: *mut c_void,
) -> c_int {
    CUDA_SUCCESS
}

/// Is `p` inside any live device allocation (base ≤ p < base+size)?
fn dev_device(allocs: &std::collections::BTreeMap<u64, (u64, i32)>, p: u64) -> Option<i32> {
    allocs
        .range(..=p)
        .next_back()
        .and_then(|(base, (size, device))| (p < base + size).then_some(*device))
}

fn dev_contains(allocs: &std::collections::BTreeMap<u64, (u64, i32)>, p: u64) -> bool {
    dev_device(allocs, p).is_some()
}

#[no_mangle]
pub extern "C" fn cudaFree(dev_ptr: *mut c_void) -> c_int {
    if dev_ptr.is_null() {
        return set_last(CUDA_SUCCESS); // cudaFree(NULL) is a no-op
    }
    set_last(retry_transport_c(|| {
        match with_state(|s| {
            s.client.mem_free(dev_ptr as u64).map_err(map_err)?;
            s.dev_allocs.remove(&(dev_ptr as u64));
            Ok(())
        }) {
            Ok(()) => CUDA_SUCCESS,
            Err(e) => e,
        }
    }))
}

#[no_mangle]
pub extern "C" fn cudaHostAlloc(ptr: *mut *mut c_void, size: usize, flags: c_uint) -> c_int {
    cuda_host_malloc(ptr, size.max(1), flags)
}

#[no_mangle]
pub extern "C" fn cudaMallocHost(ptr: *mut *mut c_void, size: usize) -> c_int {
    cuda_host_malloc(ptr, size.max(1), 0)
}

// ---- shared-memory zero-copy staging ----------------------------------------
// When SMOLVM_CUDA_SHM is set, `cudaMallocHost`/`cudaHostAlloc` bump-allocate
// from a region the host also maps, so a memcpy on that buffer ships only an
// offset (see do_memcpy). Falls back to plain host memory when the region is
// absent or exhausted.

use std::sync::atomic::AtomicU64;
// Every use of the bare `Ordering` name in this file sits on a Linux-only
// path, so importing it unconditionally warns on a macOS dev host.
#[cfg(target_os = "linux")]
use std::sync::atomic::Ordering;

static SHM_NEXT: AtomicU64 = AtomicU64::new(0);

#[cfg(target_os = "linux")]
fn shm_region() -> Option<&'static smolvm_cuda::shm::ShmRegion> {
    smolvm_cuda::shm::get_or_create()
}
#[cfg(not(target_os = "linux"))]
fn shm_region() -> Option<&'static ()> {
    None
}

// ---- guest-RAM zero-copy (microVM) ------------------------------------------
// When SMOLVM_CUDA_ZEROCOPY is set, `cudaMallocHost`/`cudaHostAlloc` return a
// page-aligned, mlocked buffer whose guest-physical frames we read from
// /proc/self/pagemap. A memcpy on that buffer then ships the guest-physical
// segment list, and the host (which maps guest RAM via krun_get_guest_ram)
// reads it directly. Requires the guest process to have CAP_SYS_ADMIN so
// pagemap exposes real frame numbers (microVM workloads typically run as root).

#[cfg(target_os = "linux")]
mod guestmem {
    use std::os::unix::fs::FileExt;
    use std::sync::Mutex;

    const PAGE: usize = 4096;

    struct Pinned {
        base: usize,
        size: usize,         // mmap length (page-rounded)
        page_gpas: Vec<u64>, // guest-physical base of each page
    }
    static PINNED: Mutex<Vec<Pinned>> = Mutex::new(Vec::new());

    fn enabled() -> bool {
        std::env::var_os("SMOLVM_CUDA_ZEROCOPY").is_some()
    }

    /// Allocate a page-aligned, mlocked buffer and record its guest-physical
    /// frames. `None` (fall back to byte-shipping) if disabled or unavailable.
    pub fn alloc(size: usize) -> Option<*mut u8> {
        if !enabled() || size == 0 {
            return None;
        }
        let npages = size.div_ceil(PAGE);
        let len = npages * PAGE;
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return None;
        }
        let base = p as usize;
        // Pin (present + non-migratable) and fault every page in.
        if unsafe { libc::mlock(p, len) } != 0 {
            unsafe { libc::munmap(p, len) };
            return None;
        }
        for i in 0..npages {
            unsafe { (p as *mut u8).add(i * PAGE).write_volatile(0) };
        }
        match read_gpas(base, npages) {
            Some(page_gpas) => {
                PINNED.lock().unwrap().push(Pinned {
                    base,
                    size: len,
                    page_gpas,
                });
                Some(p as *mut u8)
            }
            None => {
                unsafe { libc::munmap(p, len) };
                None // pagemap unavailable (no CAP_SYS_ADMIN) → caller falls back
            }
        }
    }

    fn trace() -> bool {
        std::env::var_os("SMOLVM_CUDA_ZC_TRACE").is_some()
    }

    fn read_gpas(base: usize, npages: usize) -> Option<Vec<u64>> {
        let f = match std::fs::File::open("/proc/self/pagemap") {
            Ok(f) => f,
            Err(e) => {
                if trace() {
                    eprintln!("[zc] open pagemap failed: {e}");
                }
                return None;
            }
        };
        let mut gpas = Vec::with_capacity(npages);
        for i in 0..npages {
            let va = base + i * PAGE;
            let mut buf = [0u8; 8];
            f.read_exact_at(&mut buf, (va / PAGE) as u64 * 8).ok()?;
            let entry = u64::from_le_bytes(buf);
            if entry & (1 << 63) == 0 {
                if trace() {
                    eprintln!("[zc] page {i} not present (entry={entry:#x})");
                }
                return None;
            }
            let pfn = entry & ((1u64 << 55) - 1);
            if pfn == 0 {
                if trace() {
                    eprintln!("[zc] pagemap PFN hidden (need CAP_SYS_ADMIN); entry={entry:#x}");
                }
                return None;
            }
            gpas.push(pfn * PAGE as u64);
        }
        if trace() {
            eprintln!("[zc] pagemap OK: {npages} pages, gpa[0]={:#x}", gpas[0]);
        }
        Some(gpas)
    }

    /// Coalesced `(gpa, len)` segments for `[ptr, ptr+len)`. Fast path: a
    /// registered pinned buffer (precomputed frames). Fallback (opt-in via
    /// SMOLVM_CUDA_ZEROCOPY): on-demand /proc/self/pagemap translation of an
    /// arbitrary (pageable) source range, so a pageable H2D also gets the
    /// zero-copy GPA path instead of slow byte-shipping through the ring.
    pub fn segments(ptr: usize, len: usize, writable: bool) -> Option<Vec<(u64, u64)>> {
        if len == 0 {
            return None;
        }
        let hit = {
            let reg = PINNED.lock().unwrap();
            reg.iter()
                .find(|b| ptr >= b.base && ptr + len <= b.base + b.size)
                .map(|buf| {
                    let mut segs: Vec<(u64, u64)> = Vec::new();
                    let mut cur = ptr - buf.base;
                    let end = cur + len;
                    while cur < end {
                        let page_gpa = buf.page_gpas[cur / PAGE];
                        let in_page = cur % PAGE;
                        let chunk = (PAGE - in_page).min(end - cur);
                        let gpa = page_gpa + in_page as u64;
                        match segs.last_mut() {
                            Some(last) if last.0 + last.1 == gpa => last.1 += chunk as u64,
                            _ => segs.push((gpa, chunk as u64)),
                        }
                        cur += chunk;
                    }
                    segs
                })
        };
        if let Some(segs) = hit {
            return Some(segs);
        }
        if !enabled() {
            return None;
        }
        segments_pagemap(ptr, len, writable)
    }

    /// On-demand GPA segments for an arbitrary source range via pagemap.
    fn segments_pagemap(ptr: usize, len: usize, writable: bool) -> Option<Vec<(u64, u64)>> {
        let first_page = ptr & !(PAGE - 1);
        let last_page = (ptr + len - 1) & !(PAGE - 1);
        let npages = (last_page - first_page) / PAGE + 1;
        // Fault every page in so pagemap reports a present frame (the H2D reads
        // these bytes anyway); a no-op for already-present real data.
        for i in 0..npages {
            let pp = (first_page + i * PAGE) as *mut u8;
            unsafe {
                let b = std::ptr::read_volatile(pp);
                // A D2H destination may be an unwritten (shared read-only ZERO)
                // page; the host writing its GPA would corrupt the shared zero
                // page guest-wide. Force a PRIVATE, writable frame first (COW)
                // without changing content. H2D sources stay read-only (they can
                // be read-only mmap file pages) so we never write-fault those.
                if writable {
                    std::ptr::write_volatile(pp, b);
                }
            }
        }
        let gpas = read_gpas_bulk(first_page, npages)?;
        let mut segs: Vec<(u64, u64)> = Vec::new();
        let mut cur = ptr;
        let end = ptr + len;
        while cur < end {
            let pidx = (cur - first_page) / PAGE;
            let in_page = (cur & (PAGE - 1)) as u64;
            let chunk = ((PAGE - (cur & (PAGE - 1))).min(end - cur)) as u64;
            let gpa = gpas[pidx] + in_page;
            match segs.last_mut() {
                Some(last) if last.0 + last.1 == gpa => last.1 += chunk,
                _ => segs.push((gpa, chunk)),
            }
            cur += chunk as usize;
        }
        Some(segs)
    }

    /// Bulk pagemap read: one pread of the whole VA range's entries.
    fn read_gpas_bulk(base: usize, npages: usize) -> Option<Vec<u64>> {
        let f = std::fs::File::open("/proc/self/pagemap").ok()?;
        let mut raw = vec![0u8; npages * 8];
        f.read_exact_at(&mut raw, (base / PAGE) as u64 * 8).ok()?;
        let mut gpas = Vec::with_capacity(npages);
        for i in 0..npages {
            let entry = u64::from_le_bytes(raw[i * 8..i * 8 + 8].try_into().unwrap());
            if entry & (1 << 63) == 0 {
                return None;
            }
            let pfn = entry & ((1u64 << 55) - 1);
            if pfn == 0 {
                return None;
            }
            gpas.push(pfn * PAGE as u64);
        }
        Some(gpas)
    }

    pub fn is_pinned(ptr: usize) -> bool {
        let reg = PINNED.lock().unwrap();
        reg.iter().any(|b| ptr >= b.base && ptr < b.base + b.size)
    }

    pub fn device_gpa(ptr: usize) -> Option<u64> {
        let reg = PINNED.lock().unwrap();
        let allocation = reg
            .iter()
            .find(|allocation| ptr >= allocation.base && ptr < allocation.base + allocation.size)?;
        if allocation
            .page_gpas
            .windows(2)
            .any(|pair| pair[1] != pair[0] + PAGE as u64)
        {
            return None;
        }
        let offset = ptr - allocation.base;
        Some(allocation.page_gpas[offset / PAGE] + (offset % PAGE) as u64)
    }

    pub fn free(ptr: usize) -> bool {
        let mut reg = PINNED.lock().unwrap();
        if let Some(i) = reg.iter().position(|b| b.base == ptr) {
            let b = reg.remove(i);
            unsafe { libc::munmap(b.base as *mut libc::c_void, b.size) };
            true
        } else {
            false
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod guestmem {
    pub fn alloc(_: usize) -> Option<*mut u8> {
        None
    }
    pub fn segments(_: usize, _: usize, _: bool) -> Option<Vec<(u64, u64)>> {
        None
    }
    pub fn is_pinned(_: usize) -> bool {
        false
    }
    pub fn device_gpa(_: usize) -> Option<u64> {
        None
    }
    pub fn free(_: usize) -> bool {
        false
    }
}

/// Bump-allocate `size` bytes (256-aligned: ggml asserts host buffers hit
/// TENSOR_ALIGNMENT, and 256 also matches cudaHostAlloc's real alignment).
#[allow(clippy::needless_return)] // `return` is load-bearing across the cfg arms
fn shm_alloc(size: usize) -> Option<*mut u8> {
    #[cfg(target_os = "linux")]
    {
        let r = shm_region()?;
        let sz = (size as u64 + 255) & !255;
        let off = SHM_NEXT.fetch_add(sz, Ordering::Relaxed);
        if off + sz > r.len() as u64 {
            return None; // region exhausted → caller falls back
        }
        return Some(unsafe { r.base().add(off as usize) });
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = size;
        None
    }
}

/// If `ptr` lies within the shared region, return its offset.
fn shm_offset(ptr: *const c_void) -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let r = shm_region()?;
        let base = r.base() as usize;
        let p = ptr as usize;
        if p >= base && p < base + r.len() {
            return Some((p - base) as u64);
        }
        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = ptr;
        None
    }
}

fn mapped_host_source(pointer: *const c_void) -> Option<(u8, u64)> {
    shm_offset(pointer)
        .map(|offset| (0, offset))
        .or_else(|| guestmem::device_gpa(pointer as usize).map(|gpa| (1, gpa)))
}

#[cfg(target_os = "linux")]
fn driver_mapped_host_allocate(
    size: usize,
    flags: c_uint,
) -> Option<Result<(*mut u8, u64), c_int>> {
    extern "C" {
        fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    }
    type Allocate = extern "C" fn(*mut *mut c_void, usize, c_uint) -> c_int;
    type DevicePointer = extern "C" fn(*mut u64, *mut c_void, c_uint) -> c_int;
    type Free = extern "C" fn(*mut c_void) -> c_int;
    static API: std::sync::OnceLock<Option<(usize, usize, usize)>> = std::sync::OnceLock::new();
    let &(allocate, device_pointer, free) = API
        .get_or_init(|| unsafe {
            let allocate = dlsym(std::ptr::null_mut(), c"cuMemHostAlloc".as_ptr()) as usize;
            let device_pointer = dlsym(
                std::ptr::null_mut(),
                c"cuMemHostGetDevicePointer_v2".as_ptr(),
            ) as usize;
            let free = dlsym(std::ptr::null_mut(), c"cuMemFreeHost".as_ptr()) as usize;
            (allocate != 0 && device_pointer != 0 && free != 0).then_some((
                allocate,
                device_pointer,
                free,
            ))
        })
        .as_ref()?;
    let allocate: Allocate = unsafe { std::mem::transmute(allocate) };
    let device_pointer: DevicePointer = unsafe { std::mem::transmute(device_pointer) };
    let free: Free = unsafe { std::mem::transmute(free) };
    let mut host = std::ptr::null_mut();
    let status = allocate(&mut host, size, flags);
    if status != 0 {
        return Some(Err(status));
    }
    let mut device = 0u64;
    let status = device_pointer(&mut device, host, 0);
    if status != 0 {
        free(host);
        return Some(Err(status));
    }
    Some(Ok((host.cast(), device)))
}

#[cfg(not(target_os = "linux"))]
fn driver_mapped_host_allocate(
    _size: usize,
    _flags: c_uint,
) -> Option<Result<(*mut u8, u64), c_int>> {
    None
}

#[cfg(target_os = "linux")]
fn driver_mapped_host_free(pointer: *mut c_void) -> c_int {
    unsafe {
        let free = libc::dlsym(libc::RTLD_DEFAULT, c"cuMemFreeHost".as_ptr()) as usize;
        if free == 0 {
            return 801;
        }
        let free: extern "C" fn(*mut c_void) -> c_int = std::mem::transmute(free);
        free(pointer)
    }
}

#[cfg(not(target_os = "linux"))]
fn driver_mapped_host_free(_pointer: *mut c_void) -> c_int {
    801
}

fn register_mapped_host(pointer: *mut u8, size: usize, flags: c_uint) -> Result<(), c_int> {
    if flags & 2 == 0 {
        return Ok(());
    }
    let (source, address) = mapped_host_source(pointer.cast()).ok_or(801)?;
    with_state(|state| {
        let device_pointer = state
            .client
            .host_get_device_pointer(source, address)
            .map_err(map_err)?;
        state
            .host_device_ptrs
            .insert(pointer as u64, (size as u64, device_pointer));
        Ok(())
    })
}

fn cuda_host_malloc(ptr: *mut *mut c_void, size: usize, flags: c_uint) -> c_int {
    if flags & 2 != 0 {
        if let Some(result) = driver_mapped_host_allocate(size, flags) {
            match result {
                Ok((host, device)) => {
                    let tracked = with_state(|state| {
                        state
                            .host_device_ptrs
                            .insert(host as u64, (size as u64, device));
                        state.driver_host_allocs.insert(host as u64);
                        Ok(())
                    });
                    if let Err(code) = tracked {
                        driver_mapped_host_free(host.cast());
                        return set_last(code);
                    }
                    return set_last(unsafe { out(ptr, host.cast()) });
                }
                Err(code) if !matches!(code, 1 | 2 | 801) => return set_last(code),
                Err(_) => {}
            }
        }
    }
    // Zero-copy backings, in order of preference: guest-RAM (microVM) then the
    // same-host shared region. Either lets a memcpy skip shipping the bytes.
    if let Some(mem) = guestmem::alloc(size) {
        return match register_mapped_host(mem, size, flags) {
            Ok(()) => set_last(unsafe { out(ptr, mem as *mut c_void) }),
            Err(code) => {
                guestmem::free(mem as usize);
                set_last(code)
            }
        };
    }
    if let Some(mem) = shm_alloc(size) {
        return match register_mapped_host(mem, size, flags) {
            Ok(()) => set_last(unsafe { out(ptr, mem as *mut c_void) }),
            Err(code) => set_last(code),
        };
    }
    let layout = match std::alloc::Layout::from_size_align(size, 256) {
        Ok(l) => l,
        Err(_) => return set_last(CUDA_ERROR_INVALID_VALUE),
    };
    let mem = unsafe { std::alloc::alloc(layout) };
    if mem.is_null() {
        return set_last(CUDA_ERROR_MEMORY_ALLOCATION);
    }
    let tracked = with_state(|s| {
        s.host_allocs.insert(mem as usize, layout);
        Ok(())
    });
    if let Err(error) = tracked {
        unsafe { std::alloc::dealloc(mem, layout) };
        return set_last(error);
    }
    if let Err(error) = register_mapped_host(mem, size, flags) {
        if let Ok(mut state) = STATE.lock() {
            if let Some(state) = state.as_mut() {
                state.host_allocs.remove(&(mem as usize));
            }
        }
        unsafe { std::alloc::dealloc(mem, layout) };
        return set_last(error);
    }
    set_last(unsafe { out(ptr, mem as *mut c_void) })
}

#[no_mangle]
pub extern "C" fn cudaFreeHost(ptr: *mut c_void) -> c_int {
    if ptr.is_null() {
        return set_last(CUDA_SUCCESS);
    }
    let mut driver_allocation = false;
    if let Ok(mut state) = STATE.lock() {
        if let Some(state) = state.as_mut() {
            state.host_device_ptrs.remove(&(ptr as u64));
            driver_allocation = state.driver_host_allocs.remove(&(ptr as u64));
        }
    }
    if driver_allocation {
        return set_last(driver_mapped_host_free(ptr));
    }
    // Guest-RAM pinned buffers: munmap + unpin.
    if guestmem::free(ptr as usize) {
        return set_last(CUDA_SUCCESS);
    }
    // Shared-region allocations are bump-allocated; freeing is a no-op.
    if shm_offset(ptr as *const c_void).is_some() {
        return set_last(CUDA_SUCCESS);
    }
    set_last(
        match with_state(|s| Ok(s.host_allocs.remove(&(ptr as usize)))) {
            Ok(Some(layout)) => {
                unsafe { std::alloc::dealloc(ptr as *mut u8, layout) };
                CUDA_SUCCESS
            }
            Ok(None) => CUDA_ERROR_INVALID_VALUE,
            Err(e) => e,
        },
    )
}

/// Classify a pointer that may have been allocated through either the runtime
/// or driver API. NCCL allocates through libcuda and later calls runtime
/// `cudaMemcpyDefault`; relying only on libcudart's local allocation table
/// misclassifies both device pointers as host memory and dereferences GPU VAs.
fn pointer_is_device(s: &mut ShimState, pointer: *const c_void) -> bool {
    if pointer.is_null() {
        return false;
    }
    if dev_contains(&s.dev_allocs, pointer as u64) {
        return true;
    }
    let is_device = s
        .client
        .lib_call(6, 2, (pointer as u64).to_le_bytes().to_vec())
        .map(|(status, output)| status == 0 && output.first() == Some(&2))
        .unwrap_or(false);
    if is_device {
        // The exact pointer is enough to avoid repeating the control-plane
        // query for NCCL's small setup copies; the daemon remains authoritative
        // for other interior pointers whose allocation extent is unknown here.
        s.dev_allocs
            .entry(pointer as u64)
            .or_insert((1, CURRENT_DEVICE.with(|d| d.get())));
    }
    is_device
}

fn mapped_host_device_pointer(state: &ShimState, pointer: u64) -> Option<u64> {
    let (&base, &(bytes, device_base)) = state.host_device_ptrs.range(..=pointer).next_back()?;
    (pointer < base.saturating_add(bytes)).then(|| device_base + (pointer - base))
}

fn patch_mapped_host_pointers(state: &ShimState, bytes: &mut [u8]) -> usize {
    let mut replacements = 0;
    let mut offset = 0;
    while offset + 8 <= bytes.len() {
        let value = u64::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap());
        if let Some(mapped) = mapped_host_device_pointer(state, value) {
            bytes[offset..offset + 8].copy_from_slice(&mapped.to_ne_bytes());
            replacements += 1;
        }
        offset += 8;
    }
    replacements
}

/// Driver launches from libraries with embedded cudart still pass through the
/// libcuda shim. Let it patch mapped-host addresses using this runtime-owned
/// allocation table before forwarding a packed kernel argument buffer.
#[no_mangle]
pub extern "C" fn smolvm_cudart_translate_host_pointers(bytes: *mut u8, len: usize) -> usize {
    if bytes.is_null() || len > 16 * 1024 * 1024 {
        return 0;
    }
    let Ok(state) = STATE.lock() else {
        return 0;
    };
    let Some(state) = state.as_ref() else {
        return 0;
    };
    let bytes = unsafe { std::slice::from_raw_parts_mut(bytes, len) };
    patch_mapped_host_pointers(state, bytes)
}

/// Resolve `cudaMemcpyDefault` to a concrete direction from local and
/// daemon-owned allocations.
fn resolve_kind(s: &mut ShimState, dst: *const c_void, src: *const c_void, kind: c_int) -> c_int {
    if kind != MEMCPY_DEFAULT {
        return kind;
    }
    let dst_dev = pointer_is_device(s, dst);
    let src_dev = pointer_is_device(s, src);
    match (src_dev, dst_dev) {
        (false, true) => MEMCPY_HTOD,
        (true, false) => MEMCPY_DTOH,
        (true, true) => MEMCPY_DTOD,
        (false, false) => MEMCPY_HTOH,
    }
}

fn do_memcpy(dst: *mut c_void, src: *const c_void, n: usize, kind: c_int, stream: u64) -> c_int {
    let dbg = std::env::var_os("SMOLVM_CUDA_TRACE_MEMCPY").is_some();
    let mut r = do_memcpy_inner(dst, src, n, kind, stream);
    // A transport error means the copy never reached the host (e.g. a VM-fork
    // clone's inherited connection is dead and the pre-call peek missed it on
    // this first call). Force a reconnect and retry once — the copy is safe to
    // repeat because it didn't run.
    if r == CUDA_ERROR_UNKNOWN {
        mark_force_reconnect();
        r = do_memcpy_inner(dst, src, n, kind, stream);
    }
    if dbg {
        eprintln!("[memcpy] src={src:p} dst={dst:p} kind={kind} n={n} stream={stream:#x} -> {r}");
    }
    r
}

/// Force the next `with_client` to rebuild the connection (used after a
/// transport error whose op is safe to retry).
fn mark_force_reconnect() {
    if let Ok(mut guard) = STATE.lock() {
        if let Some(st) = guard.as_mut() {
            st.force_reconnect = true;
        }
    }
}

fn do_memcpy_inner(
    dst: *mut c_void,
    src: *const c_void,
    n: usize,
    kind: c_int,
    stream: u64,
) -> c_int {
    with_state(|s| {
        let kind = resolve_kind(s, dst, src, kind);
        match kind {
            MEMCPY_HTOH => {
                if n > 0 && (dst.is_null() || src.is_null()) {
                    return Err(CUDA_ERROR_INVALID_VALUE);
                }
                unsafe { std::ptr::copy(src as *const u8, dst as *mut u8, n) };
                Ok(())
            }
            MEMCPY_HTOD => {
                // Zero-copy from a pinned guest buffer: ship guest-physical
                // segments; the host reads guest RAM directly. Fall back to
                // byte-shipping if the host can't serve it (no mapping).
                if let Some(segs) = guestmem::segments(src as usize, n, false) {
                    if s.client.memcpy_gpa_htod(dst as u64, segs, stream).is_ok() {
                        return Ok(());
                    }
                }
                // Zero-copy from the same-host shared region: ship the offset.
                if let Some(off) = shm_offset(src) {
                    return s
                        .client
                        .memcpy_shm_htod(dst as u64, off, n as u64, stream)
                        .map_err(map_err);
                }
                // Chunk: one frame must stay far below the transport's
                // 256 MiB message cap (a 272 MiB embedding tensor here killed
                // the connection). Host-synchronous copies chunk safely.
                let original = unsafe { std::slice::from_raw_parts(src as *const u8, n) };
                let mut translated = Vec::new();
                let data = if n <= 1024 * 1024 && !s.host_device_ptrs.is_empty() {
                    translated.extend_from_slice(original);
                    patch_mapped_host_pointers(s, &mut translated);
                    translated.as_slice()
                } else {
                    original
                };
                const CHUNK: usize = 64 * 1024 * 1024;
                for (i, piece) in data.chunks(CHUNK).enumerate() {
                    s.client
                        .memcpy_htod(dst as u64 + (i * CHUNK) as u64, piece, stream)
                        .map_err(map_err)?;
                }
                Ok(())
            }
            MEMCPY_DTOH => {
                // Fast-fail latch: in a fork clone the worker has no map of
                // THIS VM's guest RAM, so every GPA copy fails NOT_FOUND —
                // at ~8.5 ms per doomed attempt that was 23% of a training
                // step. One failure disables the GPA path for this process;
                // the bounce fallback below serves everything after.
                static GPA_D2H_DEAD: std::sync::atomic::AtomicBool =
                    std::sync::atomic::AtomicBool::new(false);
                if !GPA_D2H_DEAD.load(std::sync::atomic::Ordering::Relaxed) {
                    if let Some(segs) = guestmem::segments(dst as usize, n, true) {
                        match s.client.memcpy_gpa_dtoh(src as u64, segs, stream) {
                            Ok(()) => return Ok(()),
                            Err(_) => {
                                GPA_D2H_DEAD.store(true, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                    }
                }
                if let Some(off) = shm_offset(dst) {
                    // Host writes straight into the shared region at `off`.
                    return s
                        .client
                        .memcpy_shm_dtoh(off, src as u64, n as u64, stream)
                        .map_err(map_err);
                }
                const CHUNK: usize = 64 * 1024 * 1024; // see H2D: stay under the frame cap
                let mut off = 0;
                while off < n {
                    let c = (n - off).min(CHUNK);
                    let data = s
                        .client
                        .memcpy_dtoh(src as u64 + off as u64, c as u64, stream)
                        .map_err(map_err)?;
                    if data.len() != c {
                        return Err(CUDA_ERROR_UNKNOWN);
                    }
                    unsafe {
                        std::ptr::copy_nonoverlapping(data.as_ptr(), (dst as *mut u8).add(off), c)
                    };
                    off += c;
                }
                Ok(())
            }
            MEMCPY_DTOD => s
                .client
                .memcpy_dtod(dst as u64, src as u64, n as u64)
                .map_err(map_err),
            _ => Err(CUDA_ERROR_INVALID_VALUE),
        }
    })
    .err()
    .unwrap_or(CUDA_SUCCESS)
}

#[no_mangle]
pub extern "C" fn cudaMemcpy(dst: *mut c_void, src: *const c_void, n: usize, kind: c_int) -> c_int {
    set_last(retry_transport_c(|| do_memcpy(dst, src, n, kind, 0)))
}

/// Runtime-API 2D copy. The wire protocol currently exposes linear copies, so
/// preserve CUDA's pitched-memory semantics by lowering each logical row to a
/// linear copy. Contiguous layouts retain the one-RPC fast path.
#[no_mangle]
pub extern "C" fn cudaMemcpy2D(
    dst: *mut c_void,
    dpitch: usize,
    src: *const c_void,
    spitch: usize,
    width: usize,
    height: usize,
    kind: c_int,
) -> c_int {
    if width == 0 || height == 0 {
        return set_last(CUDA_SUCCESS);
    }
    if dst.is_null() || src.is_null() || width > dpitch || width > spitch {
        return set_last(CUDA_ERROR_INVALID_VALUE);
    }
    if dpitch == width && spitch == width {
        let Some(bytes) = width.checked_mul(height) else {
            return set_last(CUDA_ERROR_INVALID_VALUE);
        };
        return cudaMemcpy(dst, src, bytes, kind);
    }
    for row in 0..height {
        let Some(dst_off) = row.checked_mul(dpitch) else {
            return set_last(CUDA_ERROR_INVALID_VALUE);
        };
        let Some(src_off) = row.checked_mul(spitch) else {
            return set_last(CUDA_ERROR_INVALID_VALUE);
        };
        let row_dst = (dst as *mut u8).wrapping_add(dst_off).cast();
        let row_src = (src as *const u8).wrapping_add(src_off).cast();
        let rc = do_memcpy(row_dst, row_src, width, kind, 0);
        if rc != CUDA_SUCCESS {
            return set_last(rc);
        }
    }
    set_last(CUDA_SUCCESS)
}

#[no_mangle]
pub extern "C" fn cudaMemcpyAsync(
    dst: *mut c_void,
    src: *const c_void,
    n: usize,
    kind: c_int,
    stream: *mut c_void,
) -> c_int {
    // Device-to-device goes through the stream-ordered driver call: it
    // pipelines like a launch and — critically — records into an active graph
    // capture instead of invalidating it (the sync form is capture-unsafe).
    let resolved = with_state(|s| Ok(resolve_kind(s, dst, src, kind))).unwrap_or(kind);
    if std::env::var_os("SMOLVM_CUDA_TRACE_MEMCPY").is_some() {
        eprintln!(
            "[memcpy-async] src={src:p} dst={dst:p} requested={kind} resolved={resolved} n={n} stream={stream:p}"
        );
    }
    if resolved == MEMCPY_DTOD {
        return set_last(
            match with_client(|c| {
                c.memcpy_dtod_async(dst as u64, src as u64, n as u64, stream as u64)
            }) {
                Ok(()) => CUDA_SUCCESS,
                Err(e) => e,
            },
        );
    }
    // Other kinds complete before returning (the CUDA API permits a more
    // synchronous implementation), but the host orders the copy after prior
    // work on `stream` first — torch's non-blocking pool streams don't order
    // against the NULL-stream copy the host uses, so dropping the stream let
    // a copy overwrite buffers that still-running kernels were reading.
    set_last(retry_transport_c(|| {
        do_memcpy(dst, src, n, kind, stream as u64)
    }))
}

#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn cudaMemcpy2DAsync(
    dst: *mut c_void,
    dpitch: usize,
    src: *const c_void,
    spitch: usize,
    width: usize,
    height: usize,
    kind: c_int,
    stream: *mut c_void,
) -> c_int {
    if width == 0 || height == 0 {
        return set_last(CUDA_SUCCESS);
    }
    if dst.is_null() || src.is_null() || width > dpitch || width > spitch {
        return set_last(CUDA_ERROR_INVALID_VALUE);
    }
    if dpitch == width && spitch == width {
        let Some(bytes) = width.checked_mul(height) else {
            return set_last(CUDA_ERROR_INVALID_VALUE);
        };
        return cudaMemcpyAsync(dst, src, bytes, kind, stream);
    }
    for row in 0..height {
        let Some(dst_off) = row.checked_mul(dpitch) else {
            return set_last(CUDA_ERROR_INVALID_VALUE);
        };
        let Some(src_off) = row.checked_mul(spitch) else {
            return set_last(CUDA_ERROR_INVALID_VALUE);
        };
        let row_dst = (dst as *mut u8).wrapping_add(dst_off).cast();
        let row_src = (src as *const u8).wrapping_add(src_off).cast();
        let rc = cudaMemcpyAsync(row_dst, row_src, width, kind, stream);
        if rc != CUDA_SUCCESS {
            return set_last(rc);
        }
    }
    set_last(CUDA_SUCCESS)
}

#[no_mangle]
pub extern "C" fn cudaMemset(dev_ptr: *mut c_void, value: c_int, count: usize) -> c_int {
    set_last(
        match with_client(|c| c.memset_d8(dev_ptr as u64, value as u8, count as u64)) {
            Ok(()) => CUDA_SUCCESS,
            Err(e) => e,
        },
    )
}

#[no_mangle]
pub extern "C" fn cudaMemsetAsync(
    dev_ptr: *mut c_void,
    value: c_int,
    count: usize,
    stream: *mut c_void,
) -> c_int {
    // Stream-ordered driver call: pipelines, and records into an active graph
    // capture instead of invalidating it.
    set_last(
        match with_client(|c| {
            c.memset_d8_async(dev_ptr as u64, value as u8, count as u64, stream as u64)
        }) {
            Ok(()) => CUDA_SUCCESS,
            Err(e) => e,
        },
    )
}

// ---- streams ----------------------------------------------------------------

#[no_mangle]
pub extern "C" fn cudaStreamCreate(stream: *mut *mut c_void) -> c_int {
    let device = CURRENT_DEVICE.with(|current| current.get());
    set_last(
        match with_state(|state| {
            let handle = state.client.stream_create(0).map_err(map_err)?;
            state.stream_devices.insert(handle, device);
            Ok(handle)
        }) {
            Ok(h) => unsafe { out(stream, h as *mut c_void) },
            Err(e) => e,
        },
    )
}

#[no_mangle]
pub extern "C" fn cudaStreamCreateWithFlags(stream: *mut *mut c_void, flags: c_uint) -> c_int {
    let device = CURRENT_DEVICE.with(|current| current.get());
    set_last(
        match with_state(|state| {
            let handle = state.client.stream_create(flags).map_err(map_err)?;
            state.stream_devices.insert(handle, device);
            Ok(handle)
        }) {
            Ok(h) => unsafe { out(stream, h as *mut c_void) },
            Err(e) => e,
        },
    )
}

#[no_mangle]
pub extern "C" fn cudaStreamDestroy(stream: *mut c_void) -> c_int {
    if stream.is_null() {
        return set_last(CUDA_SUCCESS); // destroying the default stream is a no-op
    }
    let device = stream_device(stream);
    set_last(
        match with_state_on_device(device, |state| {
            state
                .client
                .stream_destroy(stream as u64)
                .map_err(map_err)?;
            state.stream_devices.remove(&(stream as u64));
            Ok(())
        }) {
            Ok(()) => CUDA_SUCCESS,
            Err(e) => e,
        },
    )
}

#[no_mangle]
pub extern "C" fn cudaStreamSynchronize(stream: *mut c_void) -> c_int {
    set_last(
        match with_client_on_device(stream_device(stream), |c| {
            c.stream_synchronize(stream as u64)
        }) {
            Ok(()) => CUDA_SUCCESS,
            Err(e) => e,
        },
    )
}

/// `cudaLaunchHostFunc` — a host callback that must run AFTER all prior work on
/// `stream`. The deferred pipeline means that prior work may not have executed
/// host-side yet, so we synchronize the stream first; invoking the callback
/// immediately (as the old stub did) let it observe stale GPU results.
#[no_mangle]
pub extern "C" fn cudaLaunchHostFunc(
    stream: *mut c_void,
    func: Option<unsafe extern "C" fn(*mut c_void)>,
    user_data: *mut c_void,
) -> c_int {
    let rc = with_client_retrying(|c| c.stream_synchronize(stream as u64));
    if let Err(e) = rc {
        return set_last(e);
    }
    if let Some(f) = func {
        unsafe { f(user_data) };
    }
    CUDA_SUCCESS
}

// ---- device queries, events, stream/mempool surface (PyTorch runtime API) ----
//
// Most of this is forward-to-host or no-op: the host serves every connection on
// one thread in call order, so stream/event ordering is implicit and query
// APIs (stream/event "ready?", capture status) can answer synchronously.

// CUdevice_attribute values used to assemble cudaDeviceProp.
const A_MAX_THREADS_PER_BLOCK: i32 = 1;
const A_MAX_BLOCK_DIM_X: i32 = 2;
const A_MAX_BLOCK_DIM_Y: i32 = 3;
const A_MAX_BLOCK_DIM_Z: i32 = 4;
const A_MAX_GRID_DIM_X: i32 = 5;
const A_MAX_GRID_DIM_Y: i32 = 6;
const A_MAX_GRID_DIM_Z: i32 = 7;
const A_MAX_SHMEM_PER_BLOCK: i32 = 8;
const A_TOTAL_CONST_MEM: i32 = 9;
const A_WARP_SIZE: i32 = 10;
const A_MAX_REGS_PER_BLOCK: i32 = 12;
const A_CLOCK_RATE: i32 = 13;
const A_MP_COUNT: i32 = 16;
const A_KERNEL_EXEC_TIMEOUT: i32 = 17;
const A_CONCURRENT_KERNELS: i32 = 31;
const A_PCI_BUS_ID: i32 = 33;
const A_PCI_DEVICE_ID: i32 = 34;
const A_MEMORY_CLOCK_RATE: i32 = 36;
const A_MEMORY_BUS_WIDTH: i32 = 37;
const A_L2_CACHE_SIZE: i32 = 38;
const A_MAX_THREADS_PER_MP: i32 = 39;
const A_ASYNC_ENGINE_COUNT: i32 = 40;
const A_PCI_DOMAIN_ID: i32 = 50;
const A_COMPUTE_MAJOR: i32 = 75;
const A_COMPUTE_MINOR: i32 = 76;
const A_MAX_SHMEM_PER_MP: i32 = 81;
const A_MAX_REGS_PER_MP: i32 = 82;
const A_MANAGED_MEMORY: i32 = 83;
const A_CONCURRENT_MANAGED_ACCESS: i32 = 89;
const A_COMPUTE_PREEMPTION: i32 = 90;
const A_COOPERATIVE_LAUNCH: i32 = 95;
const A_COOPERATIVE_MULTI_DEVICE: i32 = 96;
const A_SINGLE_TO_DOUBLE_PERF: i32 = 87;
const A_MAX_SHMEM_PER_BLOCK_OPTIN: i32 = 97;
const A_HOST_REGISTER_SUPPORTED: i32 = 99;
const A_SPARSE_CUDA_ARRAY: i32 = 112;
const A_READ_ONLY_HOST_REGISTER: i32 = 113;
const A_MAX_BLOCKS_PER_MP: i32 = 106;
const A_MAX_PERSISTING_L2: i32 = 108;
const A_MAX_ACCESS_POLICY_WINDOW: i32 = 109;
const A_RESERVED_SHMEM_PER_BLOCK: i32 = 111;
const A_TIMELINE_SEMAPHORE: i32 = 114;

/// Immutable per-(device, attribute) cache (see cudaDeviceGetAttribute).
static DEV_ATTRS: Mutex<Option<HashMap<(c_int, c_int), c_int>>> = Mutex::new(None);
fn dev_attr_cached(device: c_int, attr: c_int) -> Option<c_int> {
    DEV_ATTRS
        .lock()
        .ok()?
        .get_or_insert_with(HashMap::new)
        .get(&(device, attr))
        .copied()
}
fn dev_attr_store(device: c_int, attr: c_int, v: c_int) {
    if let Ok(mut g) = DEV_ATTRS.lock() {
        g.get_or_insert_with(HashMap::new).insert((device, attr), v);
    }
}

#[no_mangle]
pub extern "C" fn cudaDeviceGetAttribute(value: *mut c_int, attr: c_int, device: c_int) -> c_int {
    // Device attributes are immutable — memoize to spare a host round-trip on
    // every repeat (torch queries them thousands of times; a remote server's
    // network RTT makes each one expensive).
    if let Some(v) = dev_attr_cached(device, attr) {
        return set_last(unsafe { out(value, v) });
    }
    set_last(
        match with_client(|c| c.device_get_attribute(attr, device)) {
            Ok(v) => {
                dev_attr_store(device, attr, v);
                unsafe { out(value, v) }
            }
            Err(e) => e,
        },
    )
}

#[no_mangle]
pub extern "C" fn cudaMemGetInfo(free: *mut usize, total: *mut usize) -> c_int {
    set_last(match with_client_retrying(|c| c.mem_get_info()) {
        Ok((f, t)) => unsafe {
            let _ = out(free, f as usize);
            out(total, t as usize)
        },
        Err(e) => e,
    })
}

/// `cudaDeviceProp`, the exact CUDA 12.x layout (1032 bytes). Offsets verified
/// against the real bundled `libcudart.so.12` filling the struct on this
/// machine, and pinned by the compile-time assertions below — a missing field
/// silently shifts everything after it (that bug has bitten twice: uuid, and a
/// mis-sized texture block that landed the tail up to 76 bytes off).
#[repr(C)]
struct CudaDeviceProp {
    name: [u8; 256],
    uuid: [u8; 16],
    luid: [u8; 8],
    luid_device_node_mask: c_uint,
    total_global_mem: usize,
    shared_mem_per_block: usize,
    regs_per_block: c_int,
    warp_size: c_int,
    mem_pitch: usize,
    max_threads_per_block: c_int,
    max_threads_dim: [c_int; 3],
    max_grid_size: [c_int; 3],
    clock_rate: c_int,
    total_const_mem: usize,
    major: c_int,
    minor: c_int,
    texture_alignment: usize,
    texture_pitch_alignment: usize,
    device_overlap: c_int,
    multi_processor_count: c_int,
    kernel_exec_timeout_enabled: c_int,
    integrated: c_int,
    can_map_host_memory: c_int,
    compute_mode: c_int,
    _tex_surf: [c_int; 40], // maxTexture*/maxSurface* block (unused, left zero)
    surface_alignment: usize,
    concurrent_kernels: c_int,
    ecc_enabled: c_int,
    pci_bus_id: c_int,
    pci_device_id: c_int,
    pci_domain_id: c_int,
    tcc_driver: c_int,
    async_engine_count: c_int,
    unified_addressing: c_int,
    memory_clock_rate: c_int,
    memory_bus_width: c_int,
    l2_cache_size: c_int,
    persisting_l2_cache_max_size: c_int,
    max_threads_per_multiprocessor: c_int,
    stream_priorities_supported: c_int,
    global_l1_cache_supported: c_int,
    local_l1_cache_supported: c_int,
    shared_mem_per_multiprocessor: usize,
    regs_per_multiprocessor: c_int,
    managed_memory: c_int,
    is_multi_gpu_board: c_int,
    multi_gpu_board_group_id: c_int,
    host_native_atomic_supported: c_int,
    single_to_double_precision_perf_ratio: c_int,
    pageable_memory_access: c_int,
    concurrent_managed_access: c_int,
    compute_preemption_supported: c_int,
    can_use_host_pointer_for_registered_mem: c_int,
    cooperative_launch: c_int,
    cooperative_multi_device_launch: c_int,
    shared_mem_per_block_optin: usize,
    pageable_memory_access_uses_host_page_tables: c_int,
    direct_managed_mem_access_from_host: c_int,
    max_blocks_per_multiprocessor: c_int,
    access_policy_max_window_size: c_int,
    reserved_shared_mem_per_block: usize,
    host_register_supported: c_int,
    sparse_cuda_array_supported: c_int,
    host_register_read_only_supported: c_int,
    timeline_semaphore_interop_supported: c_int,
    memory_pools_supported: c_int,
    gpu_direct_rdma_supported: c_int,
    gpu_direct_rdma_flush_writes_options: c_uint,
    gpu_direct_rdma_writes_ordering: c_int,
    memory_pool_supported_handle_types: c_uint,
    deferred_mapping_cuda_array_supported: c_int,
    ipc_event_supported: c_int,
    cluster_launch: c_int,
    unified_function_pointers: c_int,
    _reserved: [c_int; 63],
}

// Anchor offsets measured from the real 12.4 cudart on this machine; a layout
// drift fails the build instead of shipping a silently shifted struct.
const _: () = {
    assert!(std::mem::offset_of!(CudaDeviceProp, clock_rate) == 348);
    assert!(std::mem::offset_of!(CudaDeviceProp, multi_processor_count) == 388);
    assert!(std::mem::offset_of!(CudaDeviceProp, _tex_surf) == 408);
    assert!(std::mem::offset_of!(CudaDeviceProp, memory_clock_rate) == 608);
    assert!(std::mem::offset_of!(CudaDeviceProp, max_threads_per_multiprocessor) == 624);
    assert!(std::mem::offset_of!(CudaDeviceProp, regs_per_multiprocessor) == 648);
    assert!(std::mem::offset_of!(CudaDeviceProp, shared_mem_per_block_optin) == 696);
    assert!(std::mem::offset_of!(CudaDeviceProp, reserved_shared_mem_per_block) == 720);
    assert!(std::mem::size_of::<CudaDeviceProp>() == 1032);
};

/// CUDA 13 entry point: 13.x renamed the symbol back from `_v2` AND changed
/// the struct (1008 bytes, clock-rate fields removed, everything after
/// `canMapHostMemory` shifted). Callers compiled against 13.x land here;
/// 12.x callers keep `_v2` and its layout. Offsets measured from the 13.3
/// headers (scratchpad probe), values fetched like the 12.x path.
#[no_mangle]
pub extern "C" fn cudaGetDeviceProperties(prop: *mut c_void, device: c_int) -> c_int {
    if prop.is_null() {
        return set_last(CUDA_ERROR_INVALID_VALUE);
    }
    unsafe { std::ptr::write_bytes(prop as *mut u8, 0, 1008) };
    set_last(
        with_state(|s| {
            let a = |s: &mut ShimState, attr: i32, dflt: i32| {
                s.client.device_get_attribute(attr, device).unwrap_or(dflt)
            };
            let name = s.client.device_get_name(device).unwrap_or_default();
            let uuid = s.client.device_get_uuid(device).unwrap_or([0; 16]);
            let total = s.client.device_total_mem(device).unwrap_or(0);
            let base = prop as *mut u8;
            let wi = |off: usize, v: i32| unsafe { base.add(off).cast::<i32>().write_unaligned(v) };
            let wu = |off: usize, v: u64| unsafe { base.add(off).cast::<u64>().write_unaligned(v) };
            let nb = name.as_bytes();
            let n = nb.len().min(255);
            unsafe {
                std::ptr::copy_nonoverlapping(nb.as_ptr(), base, n);
                std::ptr::copy_nonoverlapping(uuid.as_ptr(), base.add(256), 16);
            }
            wu(288, total); // totalGlobalMem
            wu(296, a(s, A_MAX_SHMEM_PER_BLOCK, 49152) as u64);
            wi(304, a(s, A_MAX_REGS_PER_BLOCK, 65536));
            wi(308, a(s, A_WARP_SIZE, 32));
            wu(312, 2147483647); // memPitch
            wi(320, a(s, A_MAX_THREADS_PER_BLOCK, 1024));
            wi(324, a(s, A_MAX_BLOCK_DIM_X, 1024));
            wi(328, a(s, A_MAX_BLOCK_DIM_Y, 1024));
            wi(332, a(s, A_MAX_BLOCK_DIM_Z, 64));
            wi(336, a(s, A_MAX_GRID_DIM_X, 2147483647));
            wi(340, a(s, A_MAX_GRID_DIM_Y, 65535));
            wi(344, a(s, A_MAX_GRID_DIM_Z, 65535));
            wu(352, a(s, A_TOTAL_CONST_MEM, 65536) as u64);
            wi(360, a(s, A_COMPUTE_MAJOR, 8));
            wi(364, a(s, A_COMPUTE_MINOR, 6));
            wu(368, 512); // textureAlignment
            wu(376, 32); // texturePitchAlignment
            wi(384, a(s, A_MP_COUNT, 1));
            wi(392, 1); // canMapHostMemory
            wi(560, a(s, A_CONCURRENT_KERNELS, 1));
            wi(584, a(s, A_ASYNC_ENGINE_COUNT, 2));
            wi(588, 1); // unifiedAddressing
            wi(592, a(s, A_MEMORY_BUS_WIDTH, 0));
            wi(596, a(s, A_L2_CACHE_SIZE, 0));
            wi(600, a(s, A_MAX_PERSISTING_L2, 0));
            wi(604, a(s, A_MAX_THREADS_PER_MP, 1536));
            wi(608, 1); // streamPrioritiesSupported
            wi(612, 1); // globalL1CacheSupported
            wi(616, 1); // localL1CacheSupported
            wu(624, a(s, A_MAX_SHMEM_PER_MP, 102400) as u64);
            wi(632, a(s, A_MAX_REGS_PER_MP, 65536));
            wi(636, a(s, A_MANAGED_MEMORY, 1));
            wi(656, a(s, A_CONCURRENT_MANAGED_ACCESS, 1));
            wi(660, a(s, A_COMPUTE_PREEMPTION, 1));
            wi(668, a(s, A_COOPERATIVE_LAUNCH, 1));
            wu(672, a(s, A_MAX_SHMEM_PER_BLOCK_OPTIN, 101376) as u64);
            wi(688, a(s, A_MAX_BLOCKS_PER_MP, 16));
            wi(692, a(s, A_MAX_ACCESS_POLICY_WINDOW, 0));
            wu(696, a(s, A_RESERVED_SHMEM_PER_BLOCK, 0) as u64);
            wi(704, a(s, A_HOST_REGISTER_SUPPORTED, 1));
            Ok(())
        })
        .err()
        .unwrap_or(CUDA_SUCCESS),
    )
}

/// Device-flag scheduling hints have no effect through forwarding.
#[no_mangle]
pub extern "C" fn cudaSetDeviceFlags(_flags: c_uint) -> c_int {
    CUDA_SUCCESS
}

/// Whole-graph exec update. The host driver checks topology compatibility and
/// patches the executable graph in place; error-node handles remain host-local,
/// so only the portable result enum is returned to the guest.
#[no_mangle]
pub extern "C" fn cudaGraphExecUpdate(
    exec: *mut c_void,
    graph: *mut c_void,
    result_info: *mut c_void,
) -> c_int {
    if result_info.is_null() {
        return set_last(CUDA_ERROR_INVALID_VALUE);
    }
    set_last(
        match with_client_retrying(|c| c.graph_exec_update(exec as u64, graph as u64)) {
            Ok(result) => {
                // cudaGraphExecUpdateResultInfo { i32 result; pad; ptr; ptr }.
                // Raw host graph-node pointers cannot cross the transport.
                unsafe {
                    std::ptr::write_bytes(result_info as *mut u8, 0, 24);
                    (result_info as *mut c_int).write(result);
                }
                if result == 0 {
                    CUDA_SUCCESS
                } else {
                    910 // cudaErrorGraphExecUpdateFailure
                }
            }
            Err(error) => error,
        },
    )
}

/// Cooperative launches need grid-wide sync the transport can't fake; the
/// caller sees NotSupported and picks a non-cooperative path.
#[no_mangle]
pub extern "C" fn cudaLaunchCooperativeKernel(
    _func: *const c_void,
    _grid: Dim3,
    _block: Dim3,
    _args: *mut *mut c_void,
    _shared: usize,
    _stream: *mut c_void,
) -> c_int {
    set_last(801) // cudaErrorNotSupported
}

#[no_mangle]
pub extern "C" fn cublasGetStatusString(_status: c_int) -> *const c_char {
    c"cublas status (forwarded by smolvm)".as_ptr()
}

#[no_mangle]
pub extern "C" fn cudaGetDeviceProperties_v2(prop: *mut c_void, device: c_int) -> c_int {
    if prop.is_null() {
        return set_last(CUDA_ERROR_INVALID_VALUE);
    }
    // Zero the caller's whole 12.x cudaDeviceProp (~1032 bytes) first, then fill
    // the prefix fields we know. Trailing fields stay a defined zero.
    unsafe { std::ptr::write_bytes(prop as *mut u8, 0, 1032) };
    set_last(
        with_state(|s| {
            let a = |s: &mut ShimState, attr: i32, dflt: i32| {
                s.client.device_get_attribute(attr, device).unwrap_or(dflt)
            };
            let name = s.client.device_get_name(device).unwrap_or_default();
            let uuid = s.client.device_get_uuid(device).unwrap_or([0; 16]);
            let total = s.client.device_total_mem(device).unwrap_or(0);
            let major = a(s, A_COMPUTE_MAJOR, 8);
            let minor = a(s, A_COMPUTE_MINOR, 6);
            let mp = a(s, A_MP_COUNT, 1);
            let max_tpb = a(s, A_MAX_THREADS_PER_BLOCK, 1024);
            let warp = a(s, A_WARP_SIZE, 32);
            let shmem_blk = a(s, A_MAX_SHMEM_PER_BLOCK, 49152);
            let regs_blk = a(s, A_MAX_REGS_PER_BLOCK, 65536);
            let max_tpm = a(s, A_MAX_THREADS_PER_MP, 1536);
            let shmem_mp = a(s, A_MAX_SHMEM_PER_MP, 102400);
            let regs_mp = a(s, A_MAX_REGS_PER_MP, 65536);
            let const_mem = a(s, A_TOTAL_CONST_MEM, 65536);
            let (bx, by, bz) = (
                a(s, A_MAX_BLOCK_DIM_X, 1024),
                a(s, A_MAX_BLOCK_DIM_Y, 1024),
                a(s, A_MAX_BLOCK_DIM_Z, 64),
            );
            let (gx, gy, gz) = (
                a(s, A_MAX_GRID_DIM_X, 2147483647),
                a(s, A_MAX_GRID_DIM_Y, 65535),
                a(s, A_MAX_GRID_DIM_Z, 65535),
            );
            let clock = a(s, A_CLOCK_RATE, 0);
            let mem_clock = a(s, A_MEMORY_CLOCK_RATE, 0);
            let bus_width = a(s, A_MEMORY_BUS_WIDTH, 0);
            let l2 = a(s, A_L2_CACHE_SIZE, 0);
            let persist_l2 = a(s, A_MAX_PERSISTING_L2, 0);
            let engines = a(s, A_ASYNC_ENGINE_COUNT, 2);
            let timeout = a(s, A_KERNEL_EXEC_TIMEOUT, 0);
            let shmem_optin = a(s, A_MAX_SHMEM_PER_BLOCK_OPTIN, shmem_mp);
            let reserved_shmem = a(s, A_RESERVED_SHMEM_PER_BLOCK, 0);
            let max_blocks_mp = a(s, A_MAX_BLOCKS_PER_MP, 16);
            let access_window = a(s, A_MAX_ACCESS_POLICY_WINDOW, 0);
            let (pci_bus, pci_dev, pci_dom) = (
                a(s, A_PCI_BUS_ID, 0),
                a(s, A_PCI_DEVICE_ID, 0),
                a(s, A_PCI_DOMAIN_ID, 0),
            );
            // SAFETY: `prop` points at a caller-provided cudaDeviceProp we zeroed.
            let p = unsafe { &mut *(prop as *mut CudaDeviceProp) };
            let nb = name.as_bytes();
            let n = nb.len().min(255);
            p.name[..n].copy_from_slice(&nb[..n]);
            p.uuid = uuid;
            p.total_global_mem = total as usize;
            p.shared_mem_per_block = shmem_blk as usize;
            p.regs_per_block = regs_blk;
            p.warp_size = warp;
            p.mem_pitch = 2147483647;
            p.max_threads_per_block = max_tpb;
            p.max_threads_dim = [bx, by, bz];
            p.max_grid_size = [gx, gy, gz];
            p.clock_rate = clock;
            p.total_const_mem = const_mem as usize;
            p.major = major;
            p.minor = minor;
            p.texture_alignment = 512;
            p.texture_pitch_alignment = 32;
            p.device_overlap = (engines > 0) as c_int;
            p.multi_processor_count = mp;
            p.kernel_exec_timeout_enabled = timeout;
            p.can_map_host_memory = 1;
            p.surface_alignment = 512;
            p.concurrent_kernels = a(s, A_CONCURRENT_KERNELS, 1);
            p.pci_bus_id = pci_bus;
            p.pci_device_id = pci_dev;
            p.pci_domain_id = pci_dom;
            p.async_engine_count = engines;
            p.unified_addressing = 1;
            p.memory_clock_rate = mem_clock;
            p.memory_bus_width = bus_width;
            p.l2_cache_size = l2;
            p.persisting_l2_cache_max_size = persist_l2;
            p.max_threads_per_multiprocessor = max_tpm;
            p.stream_priorities_supported = 1;
            p.global_l1_cache_supported = 1;
            p.local_l1_cache_supported = 1;
            p.shared_mem_per_multiprocessor = shmem_mp as usize;
            p.regs_per_multiprocessor = regs_mp;
            p.managed_memory = a(s, A_MANAGED_MEMORY, 1);
            p.single_to_double_precision_perf_ratio = a(s, A_SINGLE_TO_DOUBLE_PERF, 32);
            p.concurrent_managed_access = a(s, A_CONCURRENT_MANAGED_ACCESS, 1);
            p.compute_preemption_supported = a(s, A_COMPUTE_PREEMPTION, 1);
            p.cooperative_launch = a(s, A_COOPERATIVE_LAUNCH, 1);
            p.cooperative_multi_device_launch = a(s, A_COOPERATIVE_MULTI_DEVICE, 1);
            p.shared_mem_per_block_optin = shmem_optin as usize;
            p.max_blocks_per_multiprocessor = max_blocks_mp;
            p.access_policy_max_window_size = access_window;
            p.reserved_shared_mem_per_block = reserved_shmem as usize;
            p.host_register_supported = a(s, A_HOST_REGISTER_SUPPORTED, 1);
            p.timeline_semaphore_interop_supported = a(s, A_TIMELINE_SEMAPHORE, 1);
            p.sparse_cuda_array_supported = a(s, A_SPARSE_CUDA_ARRAY, 0);
            p.host_register_read_only_supported = a(s, A_READ_ONLY_HOST_REGISTER, 0);
            // Deliberately NOT mirrored from the host GPU: capabilities that
            // would steer callers onto paths forwarding can't honor. Pageable /
            // registered host memory is guest RAM the host GPU can't reach by
            // that pointer, mempools + IPC events are stubbed.
            // (pageable_memory_access, can_use_host_pointer_for_registered_mem,
            //  memory_pools_supported, memory_pool_supported_handle_types,
            //  ipc_event_supported stay 0.)
            Ok(())
        })
        .err()
        .unwrap_or(CUDA_SUCCESS),
    )
}

// ---- events (forward to host) -----------------------------------------------

const EVENT_CREATE_BATCH_SIZE: u32 = 64;

fn event_create_cached(event: *mut *mut c_void, flags: c_uint) -> c_int {
    if event.is_null() {
        return set_last(CUDA_ERROR_INVALID_VALUE);
    }
    set_last(
        match with_state(|st| {
            let device = CURRENT_DEVICE.with(|current| current.get());
            let key = (device, flags);
            if let Some(handle) = st.event_spares.get_mut(&key).and_then(Vec::pop) {
                st.event_devices.insert(handle, device);
                return Ok(handle);
            }

            let mut handles = st
                .client
                .event_create_batch(flags, EVENT_CREATE_BATCH_SIZE)
                .map_err(map_err)?;
            let handle = handles.pop().ok_or(CUDA_ERROR_UNKNOWN)?;
            for &spare in &handles {
                st.event_devices.insert(spare, device);
            }
            st.event_spares.entry(key).or_default().extend(handles);
            st.event_devices.insert(handle, device);
            Ok(handle)
        }) {
            Ok(handle) => unsafe { out(event, handle as *mut c_void) },
            Err(code) => code,
        },
    )
}

#[no_mangle]
pub extern "C" fn cudaEventCreate(event: *mut *mut c_void) -> c_int {
    event_create_cached(event, 0)
}
#[no_mangle]
pub extern "C" fn cudaEventCreateWithFlags(event: *mut *mut c_void, flags: c_uint) -> c_int {
    event_create_cached(event, flags)
}
#[no_mangle]
pub extern "C" fn cudaEventDestroy(event: *mut c_void) -> c_int {
    let device = event_device(event);
    set_last(
        match with_state_on_device(device, |state| {
            state.client.event_destroy(event as u64).map_err(map_err)?;
            state.event_devices.remove(&(event as u64));
            Ok(())
        }) {
            Ok(()) => CUDA_SUCCESS,
            Err(e) => e,
        },
    )
}
#[no_mangle]
pub extern "C" fn cudaEventRecord(event: *mut c_void, stream: *mut c_void) -> c_int {
    let device = if stream.is_null() {
        event_device(event)
    } else {
        stream_device(stream)
    };
    set_last(
        match with_client_on_device(device, |c| c.event_record(event as u64, stream as u64)) {
            Ok(()) => CUDA_SUCCESS,
            Err(e) => e,
        },
    )
}
#[no_mangle]
pub extern "C" fn cudaEventRecordWithFlags(
    event: *mut c_void,
    stream: *mut c_void,
    _flags: c_uint,
) -> c_int {
    cudaEventRecord(event, stream)
}
#[no_mangle]
pub extern "C" fn cudaEventSynchronize(event: *mut c_void) -> c_int {
    set_last(
        match with_client_on_device(event_device(event), |c| c.event_synchronize(event as u64)) {
            Ok(()) => CUDA_SUCCESS,
            Err(e) => e,
        },
    )
}
#[no_mangle]
pub extern "C" fn cudaEventQuery(event: *mut c_void) -> c_int {
    // Must be honest: PyTorch's allocator polls this to decide when freed
    // blocks are safe to reuse. Always answering "complete" caused premature
    // reuse (ILLEGAL_ADDRESS) once work really ran on side streams. NotReady
    // (600) latches into last-error exactly like real cudart; torch clears it.
    set_last(
        match with_client_on_device(event_device(event), |c| c.event_query(event as u64)) {
            Ok(code) => code,
            Err(e) => e,
        },
    )
}
#[no_mangle]
pub extern "C" fn cudaEventElapsedTime(
    ms: *mut f32,
    start: *mut c_void,
    end: *mut c_void,
) -> c_int {
    set_last(
        match with_client(|c| c.event_elapsed_time(start as u64, end as u64)) {
            Ok(t) => unsafe { out(ms, t) },
            Err(e) => e,
        },
    )
}

// ---- streams: priorities, capture queries, callbacks ------------------------

#[no_mangle]
pub extern "C" fn cudaStreamCreateWithPriority(
    stream: *mut *mut c_void,
    flags: c_uint,
    _priority: c_int,
) -> c_int {
    let device = CURRENT_DEVICE.with(|current| current.get());
    set_last(
        match with_state(|state| {
            let handle = state.client.stream_create(flags).map_err(map_err)?;
            state.stream_devices.insert(handle, device);
            Ok(handle)
        }) {
            Ok(h) => unsafe { out(stream, h as *mut c_void) },
            Err(e) => e,
        },
    )
}
#[no_mangle]
pub extern "C" fn cudaStreamWaitEvent(
    stream: *mut c_void,
    event: *mut c_void,
    flags: c_uint,
) -> c_int {
    // A real cross-stream ordering edge now that work runs on side streams
    // (and a graph dependency during capture) — dropping it made replays racy
    // (ILLEGAL_ADDRESS). Deferred like a launch.
    set_last(
        match with_client_on_device(stream_device(stream), |c| {
            c.stream_wait_event(stream as u64, event as u64, flags)
        }) {
            Ok(()) => CUDA_SUCCESS,
            Err(e) => e,
        },
    )
}
#[no_mangle]
pub extern "C" fn cudaStreamQuery(stream: *mut c_void) -> c_int {
    // Honest completion status (0 or 600-NotReady), same as cudaEventQuery.
    set_last(
        match with_client_on_device(stream_device(stream), |c| c.stream_query(stream as u64)) {
            Ok(code) => code,
            Err(e) => e,
        },
    )
}
// ---- CUDA graphs -------------------------------------------------------------
// Capture happens on the HOST driver: Begin/End forward, and every launch /
// stream-ordered op issued in between lands on the capturing host stream and is
// recorded (not executed) by the real driver. Replay is a single GraphLaunch
// message for the whole graph — the antidote to per-launch round-trips in
// launch-bound inference. The hot capture-status queries answer from the
// guest-side `capture` field, costing nothing outside capture and on the root
// stream. Queries for side streams participating through event edges go to the
// host driver; treating them as inactive leaves a forked capture branch
// unjoined and breaks segmented graph implementations that track side-stream
// forks.

/// cudaStreamCaptureStatusNone.
const CAPTURE_NONE: c_int = 0;
/// cudaStreamCaptureStatusActive.
const CAPTURE_ACTIVE: c_int = 1;

fn local_capture_info(captures: &HashMap<u64, CaptureRecord>, stream: u64) -> Option<(c_int, u64)> {
    if let Some(record) = captures.get(&stream) {
        Some((CAPTURE_ACTIVE, record.local_id))
    } else if captures.is_empty() {
        Some((CAPTURE_NONE, 0))
    } else {
        None
    }
}

fn capture_info_for_stream(s: &mut ShimState, stream: u64) -> Result<(c_int, u64), c_int> {
    if let Some(info) = local_capture_info(&s.captures, stream) {
        return Ok(info);
    }

    // CUDA owns side-stream participation: event edges can join a non-root
    // stream to one of several active captures. Ask the host which capture it
    // joined, then translate the host's ID to the process-local ID frameworks
    // use to correlate allocator state.
    let (status, side_host_id) = s.client.stream_capture_info(stream).map_err(map_err)?;
    if status as c_int != CAPTURE_ACTIVE {
        return Ok((status as c_int, 0));
    }
    if let Some(record) = s
        .captures
        .values()
        .find(|record| record.host_id == Some(side_host_id))
    {
        return Ok((CAPTURE_ACTIVE, record.local_id));
    }

    // BeginCapture is pipelined, so host IDs are populated lazily only when a
    // side-stream query needs them. This keeps the common root-only path at
    // zero RTT while correctly disambiguating concurrent capture DAGs.
    let unresolved: Vec<u64> = s
        .captures
        .iter()
        .filter_map(|(&root, record)| record.host_id.is_none().then_some(root))
        .collect();
    for root in unresolved {
        let (root_status, root_host_id) = s.client.stream_capture_info(root).map_err(map_err)?;
        if root_status as c_int == CAPTURE_ACTIVE {
            if let Some(record) = s.captures.get_mut(&root) {
                record.host_id = Some(root_host_id);
                if root_host_id == side_host_id {
                    return Ok((CAPTURE_ACTIVE, record.local_id));
                }
            }
        }
    }

    // A capture started outside this runtime shim can still be reported by the
    // host. Its host ID is already stable, so expose it rather than claiming the
    // stream is inactive or attaching it to the wrong local capture.
    Ok((CAPTURE_ACTIVE, side_host_id))
}

#[no_mangle]
pub extern "C" fn cudaStreamBeginCapture(stream: *mut c_void, mode: c_int) -> c_int {
    set_last(
        match with_state(|s| {
            let stream = stream as u64;
            if s.captures.contains_key(&stream) {
                return Err(CUDA_ERROR_ILLEGAL_STATE);
            }
            // Fire-and-forget: the host starts capture when this drains, and
            // the (also-deferred) launches record in order. The capture id is
            // torch-visible only (its allocator correlates via the local
            // GetCaptureInfo queries; the host tracks capture by stream), so
            // mint it locally. This saves a host round-trip per captured graph;
            // EndCapture remains synchronous because it reports invalidation.
            if s.captures.is_empty() {
                s.client
                    .stream_begin_capture_deferred(stream, mode)
                    .map_err(map_err)?;
            } else {
                // Concurrent captures are uncommon and need host validation;
                // keep only the first/root-only capture on the zero-RTT path.
                s.client
                    .stream_begin_capture(stream, mode)
                    .map_err(map_err)?;
            }
            static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
            let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            s.captures.insert(
                stream,
                CaptureRecord {
                    local_id: id,
                    host_id: None,
                },
            );
            Ok(())
        }) {
            Ok(()) => CUDA_SUCCESS,
            Err(e) => e,
        },
    )
}

#[no_mangle]
pub extern "C" fn cudaStreamEndCapture(stream: *mut c_void, graph: *mut *mut c_void) -> c_int {
    if graph.is_null() {
        return set_last(CUDA_ERROR_INVALID_VALUE);
    }
    unsafe { *graph = std::ptr::null_mut() };
    set_last(
        match with_state(|s| {
            // Mint a virtual graph handle; the host maps it to the real graph.
            // EndCapture is a validation boundary: it must synchronously report
            // an invalidated capture and leave `graph` null, matching libcudart.
            let vh = alloc_vhandle();
            let node_count = s
                .client
                .stream_end_capture(stream as u64, vh)
                .map_err(map_err)?;
            s.captures.remove(&(stream as u64));
            s.graph_node_counts.insert(vh, node_count as usize);
            Ok(vh)
        }) {
            Ok(g) => unsafe { out(graph, g as *mut c_void) },
            Err(e) => {
                let _ = with_state(|s| {
                    s.captures.remove(&(stream as u64));
                    Ok(())
                });
                e
            }
        },
    )
}

#[no_mangle]
pub extern "C" fn cudaStreamIsCapturing(stream: *mut c_void, status: *mut c_int) -> c_int {
    if status.is_null() {
        return set_last(CUDA_ERROR_INVALID_VALUE);
    }
    set_last(
        match with_state(|s| capture_info_for_stream(s, stream as u64)) {
            Ok((capture_status, _)) => unsafe { out(status, capture_status) },
            Err(error) => error,
        },
    )
}

#[no_mangle]
pub extern "C" fn cudaStreamGetCaptureInfo_v2(
    stream: *mut c_void,
    status: *mut c_int,
    id: *mut u64,
    graph: *mut *mut c_void,
    deps: *mut *mut *const c_void,
    num_deps: *mut usize,
) -> c_int {
    if status.is_null() {
        return set_last(CUDA_ERROR_INVALID_VALUE);
    }
    let (st, cid) = match with_state(|s| capture_info_for_stream(s, stream as u64)) {
        Ok(info) => info,
        Err(error) => return set_last(error),
    };
    unsafe {
        let _ = out(status, st);
        if !id.is_null() {
            let _ = out(id, cid);
        }
        if !graph.is_null() {
            let _ = out(graph, std::ptr::null_mut());
        }
        if !deps.is_null() {
            let _ = out(deps, std::ptr::null_mut());
        }
        if !num_deps.is_null() {
            let _ = out(num_deps, 0usize);
        }
    }
    set_last(CUDA_SUCCESS)
}

#[no_mangle]
pub extern "C" fn cudaGraphInstantiate(
    graph_exec: *mut *mut c_void,
    graph: *mut c_void,
    _error_node: *mut *mut c_void,
    _log_buffer: *mut c_char,
    _buffer_size: usize,
) -> c_int {
    cudaGraphInstantiateWithFlags(graph_exec, graph, 0)
}

#[no_mangle]
pub extern "C" fn cudaGraphInstantiateWithFlags(
    graph_exec: *mut *mut c_void,
    graph: *mut c_void,
    _flags: u64,
) -> c_int {
    if graph_exec.is_null() {
        return set_last(CUDA_ERROR_INVALID_VALUE);
    }
    set_last(
        match with_client(|c| {
            // Mint a virtual exec handle; the host maps it after validating the
            // graph. Instantiation errors are synchronous in libcudart.
            let exec_vh = alloc_vhandle();
            c.graph_instantiate(graph as u64, exec_vh)?;
            Ok(exec_vh)
        }) {
            Ok(e) => unsafe { out(graph_exec, e as *mut c_void) },
            Err(e) => e,
        },
    )
}

#[no_mangle]
pub extern "C" fn cudaGraphLaunch(graph_exec: *mut c_void, stream: *mut c_void) -> c_int {
    // The whole point: one pipelined message replays every captured kernel.
    set_last(
        match with_client(|c| c.graph_launch(graph_exec as u64, stream as u64)) {
            Ok(()) => CUDA_SUCCESS,
            Err(e) => e,
        },
    )
}

/// Count-only node query (`nodes == NULL`): PyTorch uses it to warn about
/// empty captures. Filling a caller-provided node array is not supported.
#[no_mangle]
pub extern "C" fn cudaGraphGetNodes(
    graph: *mut c_void,
    nodes: *mut *mut c_void,
    num_nodes: *mut usize,
) -> c_int {
    if num_nodes.is_null() {
        return set_last(CUDA_ERROR_INVALID_VALUE);
    }
    if !nodes.is_null() {
        return set_last(CUDA_ERROR_INVALID_VALUE);
    }
    set_last(
        match with_state(|s| {
            s.graph_node_counts
                .get(&(graph as u64))
                .copied()
                .ok_or(CUDA_ERROR_INVALID_RESOURCE_HANDLE)
        }) {
            Ok(count) => unsafe { out(num_nodes, count) },
            Err(error) => error,
        },
    )
}

#[no_mangle]
pub extern "C" fn cudaGraphExecDestroy(graph_exec: *mut c_void) -> c_int {
    set_last(
        match with_client(|c| c.graph_exec_destroy(graph_exec as u64)) {
            Ok(()) => CUDA_SUCCESS,
            Err(e) => e,
        },
    )
}

#[no_mangle]
pub extern "C" fn cudaGraphDestroy(graph: *mut c_void) -> c_int {
    set_last(
        match with_state(|s| {
            s.graph_node_counts.remove(&(graph as u64));
            s.client.graph_destroy(graph as u64).map_err(map_err)
        }) {
            Ok(()) => CUDA_SUCCESS,
            Err(e) => e,
        },
    )
}

/// Manual graph-build APIs. Conda `libtorch_cuda.so` version-requires these at
/// import; stream-capture (Begin/EndCapture) is the path we actually forward.
/// Return NotSupported so callers that poke the builder API fall back.
fn graph_add_node_unsupported(p_graph_node: *mut *mut c_void) -> c_int {
    if !p_graph_node.is_null() {
        unsafe { *p_graph_node = std::ptr::null_mut() };
    }
    set_last(CUDA_ERROR_NOT_SUPPORTED)
}

#[no_mangle]
pub extern "C" fn cudaGraphAddEmptyNode(
    p_graph_node: *mut *mut c_void,
    _graph: *mut c_void,
    _deps: *const *const c_void,
    _num_deps: usize,
) -> c_int {
    graph_add_node_unsupported(p_graph_node)
}

#[no_mangle]
pub extern "C" fn cudaGraphAddNode(
    p_graph_node: *mut *mut c_void,
    _graph: *mut c_void,
    _deps: *const *const c_void,
    _dependency_data: *const c_void,
    _num_deps: usize,
    _node_params: *mut c_void,
) -> c_int {
    graph_add_node_unsupported(p_graph_node)
}

#[no_mangle]
pub extern "C" fn cudaGraphNodeGetType(_node: *mut c_void, node_type: *mut c_int) -> c_int {
    if !node_type.is_null() {
        unsafe { *node_type = 0 };
    }
    set_last(CUDA_ERROR_NOT_SUPPORTED)
}

#[no_mangle]
pub extern "C" fn cudaGraphConditionalHandleCreate(
    handle_out: *mut u64,
    _graph: *mut c_void,
    _default_launch_value: c_uint,
    _flags: c_uint,
) -> c_int {
    if !handle_out.is_null() {
        unsafe { *handle_out = 0 };
    }
    set_last(CUDA_ERROR_NOT_SUPPORTED)
}

/// Capturing into a caller-provided graph carries dependency-edge semantics
/// that `cudaStreamBeginCapture` cannot represent, so reject it explicitly.
#[no_mangle]
pub extern "C" fn cudaStreamBeginCaptureToGraph(
    _stream: *mut c_void,
    _graph: *mut c_void,
    _dependencies: *const *const c_void,
    _dependency_data: *const c_void,
    _num_dependencies: usize,
    _mode: c_int,
) -> c_int {
    set_last(CUDA_ERROR_NOT_SUPPORTED)
}

#[no_mangle]
pub extern "C" fn cudaGraphAddKernelNode(
    p_graph_node: *mut *mut c_void,
    _graph: *mut c_void,
    _deps: *const *const c_void,
    _num_deps: usize,
    _node_params: *const c_void,
) -> c_int {
    graph_add_node_unsupported(p_graph_node)
}

#[no_mangle]
pub extern "C" fn cudaGraphAddHostNode(
    p_graph_node: *mut *mut c_void,
    _graph: *mut c_void,
    _deps: *const *const c_void,
    _num_deps: usize,
    _node_params: *const c_void,
) -> c_int {
    graph_add_node_unsupported(p_graph_node)
}

#[no_mangle]
pub extern "C" fn cudaGraphAddEventRecordNode(
    p_graph_node: *mut *mut c_void,
    _graph: *mut c_void,
    _deps: *const *const c_void,
    _num_deps: usize,
    _event: *mut c_void,
) -> c_int {
    graph_add_node_unsupported(p_graph_node)
}

#[no_mangle]
pub extern "C" fn cudaGraphAddEventWaitNode(
    p_graph_node: *mut *mut c_void,
    _graph: *mut c_void,
    _deps: *const *const c_void,
    _num_deps: usize,
    _event: *mut c_void,
) -> c_int {
    graph_add_node_unsupported(p_graph_node)
}

/// User-object retain: no-op success. Needed so conda torch links; stream-capture
/// workloads we care about don't depend on real user-object refcounting.
#[no_mangle]
pub extern "C" fn cudaGraphRetainUserObject(
    _graph: *mut c_void,
    _object: *mut c_void,
    _count: c_uint,
    _flags: c_uint,
) -> c_int {
    set_last(CUDA_SUCCESS)
}

#[no_mangle]
pub extern "C" fn cudaUserObjectCreate(
    object_out: *mut *mut c_void,
    _ptr: *mut c_void,
    _destroy: *mut c_void,
    _initial_refcount: c_uint,
    _flags: c_uint,
) -> c_int {
    // Sentinel non-null handle so callers that only stash the pointer succeed.
    set_last(unsafe { out(object_out, std::ptr::without_provenance_mut(1)) })
}

#[no_mangle]
pub extern "C" fn cudaStreamUpdateCaptureDependencies(
    _stream: *mut c_void,
    _dependencies: *mut *mut c_void,
    _num_dependencies: usize,
    _flags: c_uint,
) -> c_int {
    // Capture dependency edges are tracked host-side during Begin/EndCapture;
    // accepting this as a no-op keeps conda torch linking and avoids aborting
    // a capture that already flows through our deferred path.
    set_last(CUDA_SUCCESS)
}

#[no_mangle]
pub extern "C" fn cudaThreadExchangeStreamCaptureMode(mode: *mut c_int) -> c_int {
    // PyTorch's allocator wraps capture-time cudaMalloc in a relaxed-mode
    // guard via this call. The per-thread mode must take effect on the HOST
    // thread that will execute the malloc — each connection is served by one
    // host thread, so forwarding maps the semantics exactly. A no-op here
    // leaves the host thread in global mode and the malloc fails with 900
    // (cudaErrorStreamCaptureUnsupported), invalidating the capture.
    if mode.is_null() {
        return set_last(CUDA_ERROR_INVALID_VALUE);
    }
    let new_mode = unsafe { *mode };
    set_last(
        match with_client(|c| c.thread_exchange_capture_mode(new_mode)) {
            Ok(old) => {
                unsafe { *mode = old };
                CUDA_SUCCESS
            }
            Err(e) => e,
        },
    )
}
/// `cudaStreamCallback_t` = `void (*)(cudaStream_t, cudaError_t, void*)`.
type StreamCallback = unsafe extern "C" fn(*mut c_void, c_int, *mut c_void);
#[no_mangle]
pub extern "C" fn cudaStreamAddCallback(
    stream: *mut c_void,
    callback: Option<StreamCallback>,
    user_data: *mut c_void,
    _flags: c_uint,
) -> c_int {
    // The callback must run after all prior work on `stream`. Under the
    // deferred pipeline that work may not have executed host-side yet, so
    // synchronize first — invoking it immediately let it observe stale results.
    if let Err(e) = with_client_retrying(|c| c.stream_synchronize(stream as u64)) {
        return set_last(e);
    }
    if let Some(cb) = callback {
        unsafe { cb(stream, CUDA_SUCCESS, user_data) };
    }
    set_last(CUDA_SUCCESS)
}
#[no_mangle]
pub extern "C" fn cudaDeviceGetStreamPriorityRange(
    least: *mut c_int,
    greatest: *mut c_int,
) -> c_int {
    unsafe {
        if !least.is_null() {
            let _ = out(least, 0);
        }
        if !greatest.is_null() {
            let _ = out(greatest, 0);
        }
    }
    set_last(CUDA_SUCCESS)
}

// ---- async malloc / mempool (map to sync alloc; pool stubs) ------------------

#[no_mangle]
pub extern "C" fn cudaMallocAsync(
    dev_ptr: *mut *mut c_void,
    size: usize,
    _stream: *mut c_void,
) -> c_int {
    cudaMalloc(dev_ptr, size)
}
#[no_mangle]
pub extern "C" fn cudaFreeAsync(dev_ptr: *mut c_void, _stream: *mut c_void) -> c_int {
    cudaFree(dev_ptr)
}
#[no_mangle]
pub extern "C" fn cudaDeviceGetDefaultMemPool(pool: *mut *mut c_void, _device: c_int) -> c_int {
    // No pool support; hand back a sentinel so callers that only stash it are ok.
    set_last(unsafe { out(pool, std::ptr::without_provenance_mut(1)) })
}
#[no_mangle]
pub extern "C" fn cudaMemPoolSetAttribute(
    _pool: *mut c_void,
    _attr: c_int,
    _value: *mut c_void,
) -> c_int {
    set_last(CUDA_SUCCESS)
}
#[no_mangle]
pub extern "C" fn cudaMemPoolGetAttribute(
    _pool: *mut c_void,
    _attr: c_int,
    value: *mut c_void,
) -> c_int {
    // Every mempool attribute is an 8-byte value (thresholds are u64, the
    // bool/used/reserved counters are i64). Write a defined 0 rather than
    // leaving the caller's buffer as stack garbage.
    if !value.is_null() {
        unsafe { (value as *mut u64).write_unaligned(0) };
    }
    set_last(CUDA_SUCCESS)
}
#[no_mangle]
pub extern "C" fn cudaMemPoolSetAccess(
    _pool: *mut c_void,
    _desc: *const c_void,
    _count: usize,
) -> c_int {
    set_last(CUDA_SUCCESS)
}
#[no_mangle]
pub extern "C" fn cudaMemPoolTrimTo(_pool: *mut c_void, _min_bytes_to_keep: usize) -> c_int {
    set_last(CUDA_SUCCESS)
}

// ---- pointer / func attributes, occupancy, host register, peer, misc --------

/// `cudaPointerAttributes` (CUDA 12.x): `{ int type; int device; void* devPtr;
/// void* hostPtr; }`.
#[repr(C)]
struct CudaPointerAttributes {
    memory_type: c_int,
    device: c_int,
    device_pointer: *mut c_void,
    host_pointer: *mut c_void,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct CudaIpcHandle {
    reserved: [u8; 64],
}
#[no_mangle]
pub extern "C" fn cudaPointerGetAttributes(attr: *mut c_void, ptr: *const c_void) -> c_int {
    if attr.is_null() {
        return set_last(CUDA_ERROR_INVALID_VALUE);
    }
    // cudaMemoryTypeDevice=2 for our device allocations, Host=1 only for
    // buffers from cudaMallocHost/cudaHostAlloc (zero-copy, shm or plain), and
    // Unregistered=0 for everything else — real cudart reports plain memory as
    // unregistered, and PyTorch's `is_pinned()` relies on that: reporting Host
    // for arbitrary pointers made `pin_memory()` a silent no-op, so pinned
    // transfers never reached the zero-copy path.
    let tracked_device = with_state(|s| Ok(dev_device(&s.dev_allocs, ptr as u64))).unwrap_or(None);
    let is_dev = tracked_device.is_some()
        // Driver-VMM allocations (torch expandable_segments) never enter this
        // shim's tables — ask the server, which knows every session range
        // (LibCall 6/2 → [2] iff device). Without this, CUDA-graph capture
        // (vLLM `weak_ref_tensor`) saw device tensors as "unregistered host".
        || with_state(|s| {
            Ok(s.client
                .lib_call(6, 2, (ptr as u64).to_le_bytes().to_vec())
                .map(|(st, out)| st == 0 && out.first() == Some(&2))
                .unwrap_or(false))
        })
        .unwrap_or(false);
    let is_pinned_host = !is_dev
        && (guestmem::is_pinned(ptr as usize)
            || shm_offset(ptr).is_some()
            || with_state(|s| {
                Ok(s.host_allocs
                    .iter()
                    .any(|(b, l)| ptr as usize >= *b && (ptr as usize) < b + l.size()))
            })
            .unwrap_or(false));
    // SAFETY: caller-provided cudaPointerAttributes.
    let a = unsafe { &mut *(attr as *mut CudaPointerAttributes) };
    a.memory_type = if is_dev {
        2
    } else if is_pinned_host {
        1
    } else {
        0
    };
    a.device = tracked_device.unwrap_or_else(|| CURRENT_DEVICE.with(|current| current.get()));
    a.device_pointer = if is_dev {
        ptr as *mut c_void
    } else {
        std::ptr::null_mut()
    };
    a.host_pointer = if is_pinned_host {
        ptr as *mut c_void
    } else {
        std::ptr::null_mut()
    };
    set_last(CUDA_SUCCESS)
}
#[no_mangle]
pub extern "C" fn cudaFuncGetAttributes(attr: *mut c_void, func: *const c_void) -> c_int {
    if attr.is_null() {
        return set_last(CUDA_ERROR_INVALID_VALUE);
    }
    // cudaFuncAttributes: sharedSizeBytes, constSizeBytes, localSizeBytes
    // (size_t @ 0/8/16) then maxThreadsPerBlock, numRegs, ptxVersion,
    // binaryVersion (i32 @ 24/28/32/36). Forward the real values — the old
    // fixed fakes (numRegs=0) divided by zero in occupancy math.
    unsafe { std::ptr::write_bytes(attr as *mut u8, 0, 72) };
    // Kernel attributes are immutable — memoize the packed 72-byte blob per
    // function (torch may query per-launch; each miss is 7 host round-trips).
    type FuncAttrsCache = HashMap<(i32, usize), [u8; 72]>;
    static FUNC_ATTRS: Mutex<Option<FuncAttrsCache>> = Mutex::new(None);
    let device = function_device(func);
    if let Ok(mut g) = FUNC_ATTRS.lock() {
        if let Some(blob) = g
            .get_or_insert_with(HashMap::new)
            .get(&(device, func as usize))
        {
            unsafe { std::ptr::copy_nonoverlapping(blob.as_ptr(), attr as *mut u8, 72) };
            return set_last(CUDA_SUCCESS);
        }
    }
    // CUfunction_attribute: MAX_THREADS_PER_BLOCK=0, SHARED=1, CONST=2,
    // LOCAL=3, NUM_REGS=4, PTX_VERSION=5, BINARY_VERSION=6.
    let r = with_state_on_device(device, |s| {
        let (fid, _) = ensure_registered_func(s, func as usize).inspect_err(|code| {
            if std::env::var_os("SMOLVM_CUDA_SHIM_TRACE").is_some() {
                let known: Vec<_> = s
                    .funcs
                    .keys()
                    .filter(|(_, handle)| *handle == func as usize)
                    .copied()
                    .collect();
                eprintln!(
                    "[func-attrs] resolve failed code={code} device={device} func={func:p} known={known:?}"
                );
            }
        })?;
        let get = |s: &mut ShimState, a: i32| s.client.func_get_attribute(fid, a).unwrap_or(0);
        let shared = get(s, 1);
        let cst = get(s, 2);
        let local = get(s, 3);
        let max_tpb = get(s, 0);
        let num_regs = get(s, 4);
        let ptx = get(s, 5);
        let bin = get(s, 6);
        unsafe {
            let base = attr as *mut u8;
            (base as *mut usize).write_unaligned(shared.max(0) as usize);
            (base.add(8) as *mut usize).write_unaligned(cst.max(0) as usize);
            (base.add(16) as *mut usize).write_unaligned(local.max(0) as usize);
            let ints = base.add(24) as *mut c_int;
            *ints = if max_tpb > 0 { max_tpb } else { 1024 };
            *ints.add(1) = if num_regs > 0 { num_regs } else { 1 }; // never 0 (occupancy div)
            *ints.add(2) = if ptx > 0 { ptx } else { 86 };
            *ints.add(3) = if bin > 0 { bin } else { 86 };
        }
        Ok(())
    });
    if r.is_ok() {
        if let Ok(mut g) = FUNC_ATTRS.lock() {
            let mut blob = [0u8; 72];
            unsafe { std::ptr::copy_nonoverlapping(attr as *const u8, blob.as_mut_ptr(), 72) };
            g.get_or_insert_with(HashMap::new)
                .insert((device, func as usize), blob);
        }
    }
    set_last(r.err().unwrap_or(CUDA_SUCCESS))
}
/// Forward the shared-memory opt-in (`cudaFuncAttributeMaxDynamicSharedMemorySize`
/// = 8, matching the driver's `CU_FUNC_ATTRIBUTE_MAX_DYNAMIC_SHARED_SIZE_BYTES`)
/// to the host function. FlashAttention/cutlass kernels needing >48 KiB shared
/// memory raise it here before launching, or the launch fails with INVALID_VALUE.
/// The runtime and driver enum values coincide, so `attr` passes through.
#[no_mangle]
pub extern "C" fn cudaFuncSetAttribute(func: *const c_void, attr: c_int, value: c_int) -> c_int {
    // Kernels re-assert the same attribute before every launch (FlashAttention
    // raises the shared-memory cap each call) — skip repeats, each was a sync
    // round-trip.
    type AppliedAttributes = HashMap<(i32, usize, c_int), c_int>;
    static APPLIED: Mutex<Option<AppliedAttributes>> = Mutex::new(None);
    let device = function_device(func);
    if APPLIED
        .lock()
        .unwrap()
        .get_or_insert_with(HashMap::new)
        .get(&(device, func as usize, attr))
        == Some(&value)
    {
        return CUDA_SUCCESS;
    }
    let r = with_state_on_device(device, |s| {
        let (fid, _) = ensure_registered_func(s, func as usize).inspect_err(|code| {
            if std::env::var_os("SMOLVM_CUDA_SHIM_TRACE").is_some() {
                let known: Vec<_> = s
                    .funcs
                    .keys()
                    .filter(|(_, handle)| *handle == func as usize)
                    .copied()
                    .collect();
                eprintln!(
                    "[func-attr-set] resolve failed code={code} device={device} func={func:p} known={known:?}"
                );
            }
        })?;
        s.client
            .func_set_attribute(fid, attr, value)
            .map_err(map_err)
    });
    if r.is_ok() {
        APPLIED
            .lock()
            .unwrap()
            .get_or_insert_with(HashMap::new)
            .insert((device, func as usize, attr), value);
    }
    set_last(r.err().unwrap_or(CUDA_SUCCESS))
}

/// Resolve a statically registered kernel symbol to a runtime function
/// handle. Return the daemon's real CUfunction so callers may use the result
/// with either Runtime or Driver launch APIs, as NCCL does.
#[no_mangle]
pub extern "C" fn cudaGetFuncBySymbol(function: *mut *mut c_void, symbol: *const c_void) -> c_int {
    if function.is_null() || symbol.is_null() {
        return set_last(CUDA_ERROR_INVALID_VALUE);
    }
    let device = function_device(symbol);
    let result = with_state_on_device(device, |state| {
        ensure_registered_func(state, symbol as usize).map(|(function, _)| function)
    });
    match result {
        Ok(resolved) => {
            unsafe { *function = resolved as *mut c_void };
            set_last(CUDA_SUCCESS)
        }
        Err(code) => set_last(code),
    }
}

#[no_mangle]
pub extern "C" fn cudaOccupancyMaxActiveBlocksPerMultiprocessorWithFlags(
    num_blocks: *mut c_int,
    _func: *const c_void,
    block_size: c_int,
    _dynamic_smem: usize,
    _flags: c_uint,
) -> c_int {
    // Coarse estimate: 2048 threads/SM cap divided by the block size, ≥1.
    let bs = block_size.max(1);
    set_last(unsafe { out(num_blocks, (2048 / bs).clamp(1, 32)) })
}

// ---- CUDA 13 surface --------------------------------------------------------
// CUDA 13 renamed several `_v2` entry points back to their base names and cu13
// wheels (torch 2.11+cu130) bind these from libcudart.so.13 / libcublas*.so.13.

#[no_mangle]
pub extern "C" fn cudaStreamGetCaptureInfo(
    stream: *mut c_void,
    status: *mut c_int,
    id: *mut u64,
    graph: *mut *mut c_void,
    deps: *mut *mut *const c_void,
    edge_data: *mut *const c_void,
    num_deps: *mut usize,
) -> c_int {
    // CUDA 13 added the edge-data output before `numDependencies`; current
    // cuda-python bindings call this seven-argument ABI.
    if !edge_data.is_null() && deps.is_null() {
        return set_last(CUDA_ERROR_INVALID_VALUE);
    }
    if !edge_data.is_null() {
        unsafe { *edge_data = std::ptr::null() };
    }
    cudaStreamGetCaptureInfo_v2(stream, status, id, graph, deps, num_deps)
}

#[no_mangle]
pub extern "C" fn cudaOccupancyMaxActiveBlocksPerMultiprocessor(
    num_blocks: *mut c_int,
    func: *const c_void,
    block_size: c_int,
    dynamic_smem: usize,
) -> c_int {
    cudaOccupancyMaxActiveBlocksPerMultiprocessorWithFlags(
        num_blocks,
        func,
        block_size,
        dynamic_smem,
        0,
    )
}

#[no_mangle]
pub extern "C" fn cudaOccupancyMaxActiveClusters(
    num_clusters: *mut c_int,
    func: *const c_void,
    launch_config: *const c_void,
) -> c_int {
    if num_clusters.is_null() || func.is_null() || launch_config.is_null() {
        return set_last(CUDA_ERROR_INVALID_VALUE);
    }
    // Cluster launch attributes are not yet carried by cudaLaunchKernelExC.
    // Reporting a fabricated occupancy could make a caller select a launch
    // configuration the runtime cannot preserve, so fail explicitly.
    unsafe { *num_clusters = 0 };
    set_last(CUDA_ERROR_NOT_SUPPORTED)
}

#[no_mangle]
pub extern "C" fn cublasLtGetVersion() -> usize {
    130000
}

/// CUDA 12+ Library API, lowered to the module/function RPC surface already
/// used by nvcc's runtime registration hooks.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn cudaLibraryLoadData(
    library: *mut *mut c_void,
    code: *const c_void,
    _jit_options: *const c_int,
    _jit_option_values: *mut *mut c_void,
    num_jit_options: c_uint,
    _library_options: *const c_int,
    _library_option_values: *mut *mut c_void,
    num_library_options: c_uint,
) -> c_int {
    if library.is_null() || code.is_null() {
        return set_last(CUDA_ERROR_INVALID_VALUE);
    }
    unsafe { *library = std::ptr::null_mut() };
    // Options affect linking/loading semantics. Silently ignoring them could
    // load a different program, so only the unadorned form is supported.
    if num_jit_options != 0 || num_library_options != 0 {
        return set_last(CUDA_ERROR_NOT_SUPPORTED);
    }
    let len = match unsafe { module_image_len(code) } {
        Ok(len) => len,
        Err(e) => return set_last(e),
    };
    let blob = unsafe { std::slice::from_raw_parts(code.cast::<u8>(), len) }.to_vec();
    set_last(
        match with_state(|s| {
            let module = s.client.module_load_data(&blob).map_err(map_err)?;
            let handle = alloc_vhandle() as usize;
            s.libraries.insert(
                handle,
                LibraryRec {
                    module,
                    device: CURRENT_DEVICE.with(|current| current.get()),
                    kernels: Vec::new(),
                    globals: Vec::new(),
                },
            );
            Ok(handle)
        }) {
            Ok(handle) => unsafe { out(library, handle as *mut c_void) },
            Err(e) => e,
        },
    )
}

#[no_mangle]
pub extern "C" fn cudaLibraryGetKernel(
    kernel: *mut *mut c_void,
    library: *mut c_void,
    name: *const c_char,
) -> c_int {
    if kernel.is_null() || library.is_null() || name.is_null() {
        return set_last(CUDA_ERROR_INVALID_VALUE);
    }
    unsafe { *kernel = std::ptr::null_mut() };
    let name = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(name) => name.to_owned(),
        Err(_) => return set_last(CUDA_ERROR_INVALID_VALUE),
    };
    set_last(
        match with_state(|s| {
            let rec = s
                .libraries
                .get(&(library as usize))
                .ok_or(CUDA_ERROR_INVALID_RESOURCE_HANDLE)?;
            let device = CURRENT_DEVICE.with(|current| current.get());
            if rec.device != device {
                return Err(CUDA_ERROR_INVALID_RESOURCE_HANDLE);
            }
            let module = rec.module;
            let fid = s
                .client
                .module_get_function(module, &name)
                .map_err(map_err)?;
            let param_sizes = s.client.func_get_param_info(fid).map_err(map_err)?;
            let handle = alloc_vhandle() as usize;
            let device = CURRENT_DEVICE.with(|current| current.get());
            s.funcs
                .insert((device, handle), FuncRec { fid, param_sizes });
            s.libraries
                .get_mut(&(library as usize))
                .expect("library validated above")
                .kernels
                .push(handle);
            Ok(handle)
        }) {
            Ok(handle) => unsafe { out(kernel, handle as *mut c_void) },
            Err(e) => e,
        },
    )
}

#[no_mangle]
pub extern "C" fn cudaLibraryGetGlobal(
    dptr: *mut *mut c_void,
    bytes: *mut usize,
    library: *mut c_void,
    name: *const c_char,
) -> c_int {
    if dptr.is_null() || bytes.is_null() || library.is_null() || name.is_null() {
        return set_last(CUDA_ERROR_INVALID_VALUE);
    }
    unsafe {
        *dptr = std::ptr::null_mut();
        *bytes = 0;
    }
    let name = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(name) => name.to_owned(),
        Err(_) => return set_last(CUDA_ERROR_INVALID_VALUE),
    };
    set_last(
        match with_state(|s| {
            let rec = s
                .libraries
                .get(&(library as usize))
                .ok_or(CUDA_ERROR_INVALID_RESOURCE_HANDLE)?;
            let device = CURRENT_DEVICE.with(|current| current.get());
            if rec.device != device {
                return Err(CUDA_ERROR_INVALID_RESOURCE_HANDLE);
            }
            let module = rec.module;
            let (address, size) = s
                .client
                .module_get_global(module, &name)
                .map_err(map_symbol_err)?;
            s.dev_allocs.insert(
                address,
                (size, CURRENT_DEVICE.with(|current| current.get())),
            );
            let globals = &mut s
                .libraries
                .get_mut(&(library as usize))
                .expect("library validated above")
                .globals;
            if !globals.contains(&address) {
                globals.push(address);
            }
            Ok((address, size))
        }) {
            Ok((address, size)) => unsafe {
                *bytes = size as usize;
                out(dptr, address as *mut c_void)
            },
            Err(e) => e,
        },
    )
}

#[no_mangle]
pub extern "C" fn cudaKernelSetAttributeForDevice(
    kernel: *mut c_void,
    attr: c_int,
    value: c_int,
    device: c_int,
) -> c_int {
    let count = match with_client_retrying(|client| client.device_get_count()) {
        Ok(count) => count,
        Err(error) => return set_last(error),
    };
    if device < 0 || device >= count {
        return set_last(10); // cudaErrorInvalidDevice
    }
    let previous = CURRENT_DEVICE.with(|current| current.replace(device));
    let result = cudaFuncSetAttribute(kernel, attr, value);
    CURRENT_DEVICE.with(|current| current.set(previous));
    result
}

#[no_mangle]
pub extern "C" fn cudaLibraryUnload(library: *mut c_void) -> c_int {
    if library.is_null() {
        return set_last(CUDA_ERROR_INVALID_VALUE);
    }
    set_last(
        match with_state(|s| {
            let module = s
                .libraries
                .get(&(library as usize))
                .ok_or(CUDA_ERROR_INVALID_RESOURCE_HANDLE)?
                .module;
            s.client.module_unload(module).map_err(map_err)?;
            let rec = s
                .libraries
                .remove(&(library as usize))
                .expect("library validated above");
            for kernel in rec.kernels {
                s.funcs.retain(|(_, handle), _| *handle != kernel);
            }
            for global in rec.globals {
                s.dev_allocs.remove(&global);
            }
            Ok(())
        }) {
            Ok(()) => CUDA_SUCCESS,
            Err(e) => e,
        },
    )
}

/// Driver entry-point lookup (cudart 13): resolve `symbol` from the staged
/// driver shim (`libcuda.so.1`) so callers get the same interposed surface as
/// direct linking. Missing symbols report `SymbolNotFound` via `driver_status`
/// with a success return, per the cudart contract.
/// Pre-12.5 entry point (no cudaVersion arg). torch 2.7's `libtorch_cuda.so`
/// links this symbol directly at load time, so it must be exported even though
/// the versioned variant carries the real logic.
#[no_mangle]
pub extern "C" fn cudaGetDriverEntryPoint(
    symbol: *const c_char,
    func_ptr: *mut *mut c_void,
    flags: u64,
    driver_status: *mut c_int,
) -> c_int {
    cudaGetDriverEntryPointByVersion(symbol, func_ptr, 12040, flags, driver_status)
}

#[no_mangle]
pub extern "C" fn cudaGetDriverEntryPointByVersion(
    symbol: *const c_char,
    func_ptr: *mut *mut c_void,
    _cuda_version: c_uint,
    _flags: u64,
    driver_status: *mut c_int,
) -> c_int {
    extern "C" {
        fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void;
        fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    }
    const RTLD_NOW: c_int = 2;
    const RTLD_GLOBAL: c_int = 0x100;
    const ENTRY_POINT_SUCCESS: c_int = 0;
    const ENTRY_POINT_SYMBOL_NOT_FOUND: c_int = 1;
    if symbol.is_null() || func_ptr.is_null() {
        return set_last(CUDA_ERROR_INVALID_VALUE);
    }
    let symbol_name = unsafe { CStr::from_ptr(symbol) };
    let found = if driver_entrypoint_supported(symbol_name) {
        unsafe {
            let lib = dlopen(c"libcuda.so.1".as_ptr(), RTLD_NOW | RTLD_GLOBAL);
            if lib.is_null() {
                std::ptr::null_mut()
            } else {
                dlsym(lib, symbol)
            }
        }
    } else {
        std::ptr::null_mut()
    };
    unsafe {
        *func_ptr = found;
        if !driver_status.is_null() {
            *driver_status = if found.is_null() {
                ENTRY_POINT_SYMBOL_NOT_FOUND
            } else {
                ENTRY_POINT_SUCCESS
            };
        }
    }
    set_last(CUDA_SUCCESS)
}

/// CUDA VMM itself is forwarded, but exporting its generic allocation handles
/// across guest processes is not.  `cuMemCreate` is the standard capability
/// probe used by NCCL before selecting its CUMEM transport; exposing it through
/// the runtime lookup would advertise a transport that later fails at handle
/// export.  Direct Driver API users retain the supported, process-local VMM
/// surface through libcuda/cuGetProcAddress.
fn driver_entrypoint_supported(symbol: &CStr) -> bool {
    symbol.to_bytes() != b"cuMemCreate"
}

#[no_mangle]
pub extern "C" fn cudaGetSymbolAddress(dev_ptr: *mut *mut c_void, symbol: *const c_void) -> c_int {
    if dev_ptr.is_null() {
        return set_last(CUDA_ERROR_INVALID_VALUE);
    }
    unsafe { *dev_ptr = std::ptr::null_mut() };
    set_last(match resolve_symbol(symbol) {
        Ok((address, _)) => unsafe { out(dev_ptr, address as *mut c_void) },
        Err(e) => e,
    })
}

#[no_mangle]
pub extern "C" fn cudaMemcpyToSymbol(
    symbol: *const c_void,
    src: *const c_void,
    count: usize,
    offset: usize,
    kind: c_int,
) -> c_int {
    let address = match symbol_range(symbol, offset, count) {
        Ok(address) => address,
        Err(e) => return set_last(e),
    };
    set_last(do_memcpy(address as *mut c_void, src, count, kind, 0))
}

#[no_mangle]
pub extern "C" fn cudaMemcpyFromSymbol(
    dst: *mut c_void,
    symbol: *const c_void,
    count: usize,
    offset: usize,
    kind: c_int,
) -> c_int {
    let address = match symbol_range(symbol, offset, count) {
        Ok(address) => address,
        Err(e) => return set_last(e),
    };
    set_last(do_memcpy(dst, address as *const c_void, count, kind, 0))
}

#[no_mangle]
pub extern "C" fn cudaMemcpyToSymbolAsync(
    symbol: *const c_void,
    src: *const c_void,
    count: usize,
    offset: usize,
    kind: c_int,
    stream: *mut c_void,
) -> c_int {
    let address = match symbol_range(symbol, offset, count) {
        Ok(address) => address,
        Err(e) => return set_last(e),
    };
    cudaMemcpyAsync(address as *mut c_void, src, count, kind, stream)
}

#[no_mangle]
pub extern "C" fn cudaMemcpyFromSymbolAsync(
    dst: *mut c_void,
    symbol: *const c_void,
    count: usize,
    offset: usize,
    kind: c_int,
    stream: *mut c_void,
) -> c_int {
    let address = match symbol_range(symbol, offset, count) {
        Ok(address) => address,
        Err(e) => return set_last(e),
    };
    cudaMemcpyAsync(dst, address as *const c_void, count, kind, stream)
}

#[no_mangle]
pub extern "C" fn cudaGetSymbolSize(size: *mut usize, symbol: *const c_void) -> c_int {
    if size.is_null() {
        return set_last(CUDA_ERROR_INVALID_VALUE);
    }
    unsafe { *size = 0 };
    set_last(match resolve_symbol(symbol) {
        Ok((_, bytes)) => unsafe { out(size, bytes as usize) },
        Err(e) => e,
    })
}

fn resolve_symbol(symbol: *const c_void) -> Result<(u64, u64), c_int> {
    if symbol.is_null() {
        return Err(CUDA_ERROR_INVALID_SYMBOL);
    }
    with_state(|s| {
        let key = (
            CURRENT_DEVICE.with(|current| current.get()),
            symbol as usize,
        );
        if !s.symbols.contains_key(&key) {
            let source = STATIC_SYMBOLS
                .lock()
                .map_err(|_| CUDA_ERROR_UNKNOWN)?
                .as_ref()
                .and_then(|symbols| symbols.get(&key.1))
                .cloned()
                .ok_or(CUDA_ERROR_INVALID_SYMBOL)?;
            let module = ensure_static_module(s, source.fatbin)?;
            let (address, size) = s
                .client
                .module_get_global(module, &source.name)
                .map_err(map_symbol_err)?;
            s.dev_allocs.insert(address, (size, key.0));
            s.symbols.insert(
                key,
                SymbolRec {
                    module,
                    name: source.name,
                    address,
                },
            );
            return Ok((address, size));
        }
        let rec = s.symbols.get(&key).cloned().expect("checked above");
        let result = s
            .client
            .module_get_global(rec.module, &rec.name)
            .map_err(map_symbol_err)?;
        if rec.address != result.0 {
            s.dev_allocs.remove(&rec.address);
        }
        s.dev_allocs.insert(result.0, (result.1, key.0));
        if let Some(stored) = s.symbols.get_mut(&key) {
            stored.address = result.0;
        }
        Ok(result)
    })
}

fn symbol_range(symbol: *const c_void, offset: usize, count: usize) -> Result<u64, c_int> {
    let (address, bytes) = resolve_symbol(symbol)?;
    let end = offset.checked_add(count).ok_or(CUDA_ERROR_INVALID_VALUE)?;
    if end as u64 > bytes {
        return Err(CUDA_ERROR_INVALID_VALUE);
    }
    address
        .checked_add(offset as u64)
        .ok_or(CUDA_ERROR_INVALID_VALUE)
}

#[no_mangle]
pub extern "C" fn cudaGraphNodeGetDependencies(
    _node: *mut c_void,
    deps: *mut *mut c_void,
    num_deps: *mut usize,
) -> c_int {
    unsafe {
        if !num_deps.is_null() {
            if !deps.is_null() && *num_deps > 0 {
                // No dependency introspection over the wire; report none.
            }
            *num_deps = 0;
        }
    }
    set_last(CUDA_SUCCESS)
}
#[no_mangle]
pub extern "C" fn cudaHostRegister(_ptr: *mut c_void, _size: usize, _flags: c_uint) -> c_int {
    set_last(CUDA_SUCCESS)
}
#[no_mangle]
pub extern "C" fn cudaHostUnregister(_ptr: *mut c_void) -> c_int {
    set_last(CUDA_SUCCESS)
}
#[no_mangle]
pub extern "C" fn cudaHostGetDevicePointer(
    p_device: *mut *mut c_void,
    host: *mut c_void,
    _flags: c_uint,
) -> c_int {
    if p_device.is_null() || host.is_null() {
        return set_last(CUDA_ERROR_INVALID_VALUE);
    }
    if let Ok(state) = STATE.lock() {
        if let Some(pointer) = state
            .as_ref()
            .and_then(|state| mapped_host_device_pointer(state, host as u64))
        {
            return set_last(unsafe { out(p_device, pointer as *mut c_void) });
        }
    }
    let source = mapped_host_source(host);
    let Some((source, address)) = source else {
        return set_last(801);
    };
    set_last(
        match with_client_retrying(|client| client.host_get_device_pointer(source, address)) {
            Ok(pointer) => unsafe { out(p_device, pointer as *mut c_void) },
            Err(error) => error,
        },
    )
}
#[no_mangle]
pub extern "C" fn cudaDeviceCanAccessPeer(can: *mut c_int, device: c_int, peer: c_int) -> c_int {
    set_last(
        match with_client_retrying(|client| client.device_can_access_peer(device, peer)) {
            Ok(value) => unsafe { out(can, value) },
            Err(error) => error,
        },
    )
}
#[no_mangle]
pub extern "C" fn cudaDeviceEnablePeerAccess(peer: c_int, flags: c_uint) -> c_int {
    set_last(
        match with_client(|client| client.device_enable_peer_access(peer, flags)) {
            Ok(()) => CUDA_SUCCESS,
            Err(error) => error,
        },
    )
}
#[no_mangle]
pub extern "C" fn cudaDeviceDisablePeerAccess(peer: c_int) -> c_int {
    set_last(
        match with_client(|client| client.device_disable_peer_access(peer)) {
            Ok(()) => CUDA_SUCCESS,
            Err(error) => error,
        },
    )
}
#[no_mangle]
pub extern "C" fn cudaMemcpyPeerAsync(
    dst: *mut c_void,
    dst_device: c_int,
    src: *const c_void,
    src_device: c_int,
    count: usize,
    stream: *mut c_void,
) -> c_int {
    if (dst.is_null() || src.is_null()) && count != 0 {
        return set_last(CUDA_ERROR_INVALID_VALUE);
    }
    set_last(
        match with_client(|client| {
            client.memcpy_peer_async(
                dst as u64,
                dst_device,
                src as u64,
                src_device,
                count as u64,
                stream as u64,
            )
        }) {
            Ok(()) => CUDA_SUCCESS,
            Err(error) => error,
        },
    )
}
#[no_mangle]
pub extern "C" fn cudaIpcGetMemHandle(handle: *mut CudaIpcHandle, dptr: *mut c_void) -> c_int {
    if handle.is_null() || dptr.is_null() {
        return set_last(CUDA_ERROR_INVALID_VALUE);
    }
    set_last(
        match with_client_retrying(|client| client.ipc_get_mem_handle(dptr as u64)) {
            Ok(bytes) => {
                unsafe { (*handle).reserved.copy_from_slice(&bytes) };
                CUDA_SUCCESS
            }
            Err(error) => error,
        },
    )
}
#[no_mangle]
pub extern "C" fn cudaIpcOpenMemHandle(
    dptr: *mut *mut c_void,
    handle: CudaIpcHandle,
    flags: c_uint,
) -> c_int {
    if dptr.is_null() {
        return set_last(CUDA_ERROR_INVALID_VALUE);
    }
    set_last(
        match with_state(|state| {
            let pointer = state
                .client
                .ipc_open_mem_handle(handle.reserved.to_vec(), flags)
                .map_err(map_err)?;
            state
                .dev_allocs
                .insert(pointer, (1, CURRENT_DEVICE.with(|current| current.get())));
            Ok(pointer)
        }) {
            Ok(pointer) => unsafe { out(dptr, pointer as *mut c_void) },
            Err(error) => error,
        },
    )
}
#[no_mangle]
pub extern "C" fn cudaIpcCloseMemHandle(dptr: *mut c_void) -> c_int {
    if dptr.is_null() {
        return set_last(CUDA_ERROR_INVALID_VALUE);
    }
    set_last(
        match with_state(|state| {
            state
                .client
                .ipc_close_mem_handle(dptr as u64)
                .map_err(map_err)?;
            state.dev_allocs.remove(&(dptr as u64));
            Ok(())
        }) {
            Ok(()) => CUDA_SUCCESS,
            Err(error) => error,
        },
    )
}
#[no_mangle]
pub extern "C" fn cudaIpcGetEventHandle(handle: *mut CudaIpcHandle, event: *mut c_void) -> c_int {
    if handle.is_null() || event.is_null() {
        return set_last(CUDA_ERROR_INVALID_VALUE);
    }
    set_last(
        match with_client_retrying(|client| client.ipc_get_event_handle(event as u64)) {
            Ok(bytes) => {
                unsafe { (*handle).reserved.copy_from_slice(&bytes) };
                CUDA_SUCCESS
            }
            Err(error) => error,
        },
    )
}
#[no_mangle]
pub extern "C" fn cudaIpcOpenEventHandle(event: *mut *mut c_void, handle: CudaIpcHandle) -> c_int {
    if event.is_null() {
        return set_last(CUDA_ERROR_INVALID_VALUE);
    }
    set_last(
        match with_client_retrying(|client| client.ipc_open_event_handle(handle.reserved.to_vec()))
        {
            Ok(raw) => unsafe { out(event, raw as *mut c_void) },
            Err(error) => error,
        },
    )
}
#[no_mangle]
pub extern "C" fn cudaDeviceGetPCIBusId(buf: *mut c_char, len: c_int, device: c_int) -> c_int {
    if buf.is_null() || len <= 0 {
        return set_last(CUDA_ERROR_INVALID_VALUE);
    }
    let id = match with_client_retrying(|client| client.device_get_pci_bus_id(device)) {
        Ok(id) => id,
        Err(error) => return set_last(error),
    };
    let bytes = id.as_bytes();
    let count = (len as usize - 1).min(bytes.len());
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr().cast::<c_char>(), buf, count);
        *buf.add(count) = 0;
    }
    set_last(CUDA_SUCCESS)
}

#[no_mangle]
pub extern "C" fn cudaDeviceGetByPCIBusId(device: *mut c_int, pci_bus_id: *const c_char) -> c_int {
    if device.is_null() || pci_bus_id.is_null() {
        return set_last(CUDA_ERROR_INVALID_VALUE);
    }
    let requested = unsafe { CStr::from_ptr(pci_bus_id) }.to_bytes();
    let requested = match std::str::from_utf8(requested) {
        Ok(requested) => requested,
        Err(_) => return set_last(CUDA_ERROR_INVALID_VALUE),
    };
    set_last(
        match with_client_retrying(|client| client.device_get_by_pci_bus_id(requested)) {
            Ok(ordinal) => unsafe { out(device, ordinal) },
            Err(error) => error,
        },
    )
}

// ---- kernel registration + launch -------------------------------------------

fn ensure_static_module(s: &mut ShimState, fatbin: usize) -> Result<u64, c_int> {
    let key = (CURRENT_DEVICE.with(|current| current.get()), fatbin);
    if let Some(&module) = s.modules.get(&key) {
        return Ok(module);
    }
    let blob = STATIC_MODULES
        .lock()
        .map_err(|_| CUDA_ERROR_UNKNOWN)?
        .as_ref()
        .and_then(|modules| modules.get(&fatbin))
        .cloned()
        .ok_or(CUDA_ERROR_INVALID_RESOURCE_HANDLE)?;
    let module = s.client.module_load_data(&blob).map_err(map_err)?;
    s.modules.insert(key, module);
    Ok(module)
}

fn ensure_registered_func(s: &mut ShimState, key: usize) -> Result<(u64, Vec<u32>), c_int> {
    let device_key = (CURRENT_DEVICE.with(|current| current.get()), key);
    if let Some(rec) = s.funcs.get(&device_key) {
        return Ok((rec.fid, rec.param_sizes.clone()));
    }
    // cudaGetFuncBySymbol returns the already-resolved daemon CUfunction. A
    // subsequent Runtime launch may hand that value back instead of the
    // original registration stub.
    let current_device = device_key.0;
    if let Some(record) = s.funcs.iter().find_map(|(&(device, _), record)| {
        (device == current_device && record.fid == key as u64).then_some(record)
    }) {
        return Ok((record.fid, record.param_sizes.clone()));
    }
    let source = STATIC_FUNCS
        .lock()
        .map_err(|_| CUDA_ERROR_UNKNOWN)?
        .as_ref()
        .and_then(|funcs| funcs.get(&key))
        .cloned()
        .ok_or(CUDA_ERROR_INVALID_DEVICE_POINTER)?;
    let module = ensure_static_module(s, source.fatbin).inspect_err(|code| {
        if std::env::var_os("SMOLVM_CUDA_SHIM_TRACE").is_some() {
            eprintln!(
                "[func-resolve] module failed code={code} device={} fatbin={:#x} name={}",
                device_key.0, source.fatbin, source.name
            );
        }
    })?;
    let fid = s
        .client
        .module_get_function(module, &source.name)
        .map_err(map_err)
        .inspect_err(|code| {
            if std::env::var_os("SMOLVM_CUDA_SHIM_TRACE").is_some() {
                eprintln!(
                    "[func-resolve] function failed code={code} device={} module={module:#x} name={}",
                    device_key.0, source.name
                );
            }
        })?;
    let param_sizes = s.client.func_get_param_info(fid).map_err(map_err)?;
    s.funcs.insert(
        device_key,
        FuncRec {
            fid,
            param_sizes: param_sizes.clone(),
        },
    );
    Ok((fid, param_sizes))
}

/// `__fatBinC_Wrapper_t`: what `__cudaRegisterFatBinary` receives. `data` points
/// at the fatbin container (its own header carries the length).
#[repr(C)]
struct FatBinWrapper {
    magic: c_int,
    version: c_int,
    data: *const c_void,
    filename_or_fatbins: *const c_void,
}

/// Byte length of a CUDA module/library image handed to a pointer-only API.
/// Fatbins carry a byte count, cubins are ELF, and PTX is NUL-terminated.
unsafe fn module_image_len(image: *const c_void) -> Result<usize, c_int> {
    // NCCL 2.26's all-architecture v2 fatbin is about 193 MiB. Keep the bound
    // high enough for a real vendor module while still rejecting corrupt
    // headers before they turn into an unbounded guest-memory read.
    const MAX_FATBIN_BYTES: usize = 512 * 1024 * 1024;
    const MAX_OTHER_IMAGE_BYTES: usize = 128 * 1024 * 1024;
    if image.is_null() {
        return Err(CUDA_ERROR_INVALID_VALUE);
    }
    let p = image as *const u8;
    let magic = unsafe { std::slice::from_raw_parts(p, 4) };
    if magic == [0x50, 0xED, 0x55, 0xBA] {
        let chain = std::env::var_os("SMOLVM_CUDA_FATBIN_CHAIN").is_some();
        let mut total = 0usize;
        loop {
            let q = unsafe { p.add(total) };
            if unsafe { std::slice::from_raw_parts(q, 4) } != [0x50, 0xED, 0x55, 0xBA] {
                break;
            }
            let header_size = u16::from_le_bytes(unsafe { *(q.add(6) as *const [u8; 2]) }) as usize;
            let fat_size = u64::from_le_bytes(unsafe { *(q.add(8) as *const [u8; 8]) }) as usize;
            let Some(next) = header_size
                .checked_add(fat_size)
                .and_then(|n| total.checked_add(n))
            else {
                return Err(CUDA_ERROR_INVALID_VALUE);
            };
            if header_size == 0 || fat_size == 0 || next > MAX_FATBIN_BYTES {
                break;
            }
            total = next;
            if !chain {
                break;
            }
        }
        return (total > 0).then_some(total).ok_or(CUDA_ERROR_INVALID_VALUE);
    }
    if magic == [0x7F, b'E', b'L', b'F'] {
        // CUDA cubins are little-endian ELF64. Include the furthest file-backed
        // segment/section, rather than assuming the header tables are last.
        if unsafe { *p.add(4) } != 2 || unsafe { *p.add(5) } != 1 {
            return Err(CUDA_ERROR_INVALID_VALUE);
        }
        let to_usize = |value: u64| usize::try_from(value).map_err(|_| CUDA_ERROR_INVALID_VALUE);
        let phoff = to_usize(u64::from_le_bytes(unsafe {
            *(p.add(0x20) as *const [u8; 8])
        }))?;
        let phsize = u16::from_le_bytes(unsafe { *(p.add(0x36) as *const [u8; 2]) }) as usize;
        let phnum = u16::from_le_bytes(unsafe { *(p.add(0x38) as *const [u8; 2]) }) as usize;
        let shoff = to_usize(u64::from_le_bytes(unsafe {
            *(p.add(0x28) as *const [u8; 8])
        }))?;
        let shsize = u16::from_le_bytes(unsafe { *(p.add(0x3A) as *const [u8; 2]) }) as usize;
        let shnum = u16::from_le_bytes(unsafe { *(p.add(0x3C) as *const [u8; 2]) }) as usize;
        if (phnum > 0 && phsize < 56) || (shnum > 0 && shsize < 64) {
            return Err(CUDA_ERROR_INVALID_VALUE);
        }
        let mut end = 64usize;
        end = end.max(
            phsize
                .checked_mul(phnum)
                .and_then(|n| phoff.checked_add(n))
                .ok_or(CUDA_ERROR_INVALID_VALUE)?,
        );
        end = end.max(
            shsize
                .checked_mul(shnum)
                .and_then(|n| shoff.checked_add(n))
                .ok_or(CUDA_ERROR_INVALID_VALUE)?,
        );
        if end > MAX_OTHER_IMAGE_BYTES {
            return Err(CUDA_ERROR_INVALID_VALUE);
        }
        for index in 0..phnum {
            let entry = unsafe { p.add(phoff + index * phsize) };
            let offset = to_usize(u64::from_le_bytes(unsafe {
                *(entry.add(8) as *const [u8; 8])
            }))?;
            let size = to_usize(u64::from_le_bytes(unsafe {
                *(entry.add(32) as *const [u8; 8])
            }))?;
            let segment_end = offset
                .checked_add(size)
                .filter(|end| *end <= MAX_OTHER_IMAGE_BYTES)
                .ok_or(CUDA_ERROR_INVALID_VALUE)?;
            end = end.max(segment_end);
        }
        for index in 0..shnum {
            let entry = unsafe { p.add(shoff + index * shsize) };
            let section_type = u32::from_le_bytes(unsafe { *(entry.add(4) as *const [u8; 4]) });
            if section_type == 8 {
                continue; // SHT_NOBITS occupies no bytes in the cubin image.
            }
            let offset = to_usize(u64::from_le_bytes(unsafe {
                *(entry.add(24) as *const [u8; 8])
            }))?;
            let size = to_usize(u64::from_le_bytes(unsafe {
                *(entry.add(32) as *const [u8; 8])
            }))?;
            let section_end = offset
                .checked_add(size)
                .filter(|end| *end <= MAX_OTHER_IMAGE_BYTES)
                .ok_or(CUDA_ERROR_INVALID_VALUE)?;
            end = end.max(section_end);
        }
        return Ok(end);
    }
    for len in 0..MAX_OTHER_IMAGE_BYTES {
        if unsafe { *p.add(len) } == 0 {
            return Ok(len + 1);
        }
    }
    Err(CUDA_ERROR_INVALID_VALUE)
}

#[no_mangle]
pub extern "C" fn __cudaRegisterFatBinary(fat_cubin: *mut c_void) -> *mut *mut c_void {
    // Mint a stable handle the app hands back to Register/Unregister. Preserve
    // the image locally; the first kernel/global use uploads it to the host.
    let handle = Box::into_raw(Box::new(0u8)) as *mut *mut c_void;
    if fat_cubin.is_null() {
        return handle;
    }
    let wrapper = fat_cubin as *const FatBinWrapper;
    let data = unsafe { (*wrapper).data };
    let len = match unsafe { module_image_len(data) } {
        Ok(len) => len,
        Err(code) => {
            if std::env::var_os("SMOLVM_CUDA_SHIM_TRACE").is_some() {
                let version = unsafe { (*wrapper).version };
                let alternatives = unsafe { (*wrapper).filename_or_fatbins };
                let head = if data.is_null() {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(data.cast::<u8>(), 16) }.to_vec()
                };
                eprintln!(
                    "[fatbin-register] rejected code={code} version={version} data={data:p} alternatives={alternatives:p} handle={handle:p} head={head:02x?}"
                );
            }
            return handle;
        }
    };
    let blob = unsafe { std::slice::from_raw_parts(data as *const u8, len) }.to_vec();
    if let Ok(mut modules) = STATIC_MODULES.lock() {
        modules
            .get_or_insert_with(HashMap::new)
            .insert(handle as usize, blob);
    }
    handle
}

#[no_mangle]
pub extern "C" fn __cudaRegisterFatBinaryEnd(_handle: *mut *mut c_void) {}

/// Called by some CUDA-compiled modules (e.g. torchvision's `_C.so`) during
/// their static init. The real runtime returns `char` 1 (module usable); we do
/// the same — registration proper happens via `__cudaRegisterFunction`.
#[no_mangle]
pub extern "C" fn __cudaInitModule(_fat_cubin_handle: *mut *mut c_void) -> c_char {
    1
}

#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn __cudaRegisterFunction(
    fat_cubin_handle: *mut *mut c_void,
    host_fun: *const c_char,
    _device_fun: *mut c_char,
    device_name: *const c_char,
    _thread_limit: c_int,
    _tid: *mut c_void,
    _bid: *mut c_void,
    _b_dim: *mut c_void,
    _g_dim: *mut c_void,
    _w_size: *mut c_void,
) {
    if device_name.is_null() {
        return;
    }
    let name = match unsafe { CStr::from_ptr(device_name) }.to_str() {
        Ok(n) => n.to_string(),
        Err(_) => return,
    };
    if let Ok(mut funcs) = STATIC_FUNCS.lock() {
        funcs.get_or_insert_with(HashMap::new).insert(
            host_fun as usize,
            StaticFuncRec {
                fatbin: fat_cubin_handle as usize,
                name,
            },
        );
    }
}

#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn __cudaRegisterVar(
    fat_cubin_handle: *mut *mut c_void,
    host_var: *mut c_char,
    device_address: *mut c_char,
    device_name: *const c_char,
    _ext: c_int,
    _size: usize,
    _constant: c_int,
    _global: c_int,
) {
    if host_var.is_null() {
        return;
    }
    let name_ptr = if !device_name.is_null() {
        device_name
    } else {
        device_address.cast_const()
    };
    if name_ptr.is_null() {
        return;
    }
    let name = match unsafe { CStr::from_ptr(name_ptr) }.to_str() {
        Ok(name) => name.to_owned(),
        Err(_) => return,
    };
    if let Ok(mut symbols) = STATIC_SYMBOLS.lock() {
        symbols.get_or_insert_with(HashMap::new).insert(
            host_var as usize,
            StaticSymbolRec {
                fatbin: fat_cubin_handle as usize,
                name,
            },
        );
    }
}

#[no_mangle]
pub extern "C" fn __cudaUnregisterFatBinary(handle: *mut *mut c_void) {
    let fatbin = handle as usize;
    if let Ok(mut modules) = STATIC_MODULES.lock() {
        if let Some(modules) = modules.as_mut() {
            modules.remove(&fatbin);
        }
    }
    let function_keys = STATIC_FUNCS
        .lock()
        .ok()
        .and_then(|mut funcs| {
            let funcs = funcs.as_mut()?;
            let keys: Vec<usize> = funcs
                .iter()
                .filter_map(|(&key, rec)| (rec.fatbin == fatbin).then_some(key))
                .collect();
            for key in &keys {
                funcs.remove(key);
            }
            Some(keys)
        })
        .unwrap_or_default();
    let symbol_keys = STATIC_SYMBOLS
        .lock()
        .ok()
        .and_then(|mut symbols| {
            let symbols = symbols.as_mut()?;
            let keys: Vec<usize> = symbols
                .iter()
                .filter_map(|(&key, rec)| (rec.fatbin == fatbin).then_some(key))
                .collect();
            for key in &keys {
                symbols.remove(key);
            }
            Some(keys)
        })
        .unwrap_or_default();
    // Do not create a CUDA connection during ELF teardown. Unload only when
    // this process actually materialized the module earlier.
    if let Ok(mut state) = STATE.lock() {
        if let Some(s) = state.as_mut() {
            for key in function_keys {
                s.funcs.retain(|(_, handle), _| *handle != key);
            }
            for key in symbol_keys {
                let device_keys: Vec<(i32, usize)> = s
                    .symbols
                    .keys()
                    .filter(|(_, handle)| *handle == key)
                    .copied()
                    .collect();
                for device_key in device_keys {
                    let Some(symbol) = s.symbols.remove(&device_key) else {
                        continue;
                    };
                    s.dev_allocs.remove(&symbol.address);
                }
            }
            let module_keys: Vec<(i32, usize)> = s
                .modules
                .keys()
                .filter(|(_, registered)| *registered == fatbin)
                .copied()
                .collect();
            for module_key in module_keys {
                let Some(module) = s.modules.remove(&module_key) else {
                    continue;
                };
                let global_addresses: Vec<u64> = s
                    .symbols
                    .values()
                    .filter(|symbol| symbol.module == module)
                    .map(|symbol| symbol.address)
                    .collect();
                s.symbols.retain(|_, symbol| symbol.module != module);
                for address in global_addresses {
                    s.dev_allocs.remove(&address);
                }
                let _ = s.client.module_unload(module);
            }
        }
    }
    if !handle.is_null() {
        unsafe { drop(Box::from_raw(handle as *mut u8)) };
    }
}

#[no_mangle]
pub extern "C" fn __cudaPushCallConfiguration(
    grid: Dim3,
    block: Dim3,
    shared_mem: usize,
    stream: *mut c_void,
) -> c_int {
    CALL_CONFIG.with(|c| {
        c.borrow_mut()
            .push((grid, block, shared_mem, stream as u64))
    });
    CUDA_SUCCESS
}

#[no_mangle]
pub extern "C" fn __cudaPopCallConfiguration(
    grid: *mut Dim3,
    block: *mut Dim3,
    shared_mem: *mut usize,
    stream: *mut *mut c_void,
) -> c_int {
    CALL_CONFIG.with(|c| {
        let cfg = c.borrow_mut().pop();
        match cfg {
            Some((g, b, sh, st)) => unsafe {
                if !grid.is_null() {
                    *grid = g;
                }
                if !block.is_null() {
                    *block = b;
                }
                if !shared_mem.is_null() {
                    *shared_mem = sh;
                }
                if !stream.is_null() {
                    *stream = st as *mut c_void;
                }
                CUDA_SUCCESS
            },
            None => CUDA_ERROR_INVALID_VALUE,
        }
    })
}

#[no_mangle]
pub extern "C" fn cudaLaunchKernel(
    func: *const c_void,
    grid: Dim3,
    block: Dim3,
    args: *mut *mut c_void,
    shared_mem: usize,
    stream: *mut c_void,
) -> c_int {
    set_last(retry_transport_c(|| {
        do_launch(
            func,
            [grid.x, grid.y, grid.z],
            [block.x, block.y, block.z],
            shared_mem,
            stream as u64,
            args,
        )
    }))
}

/// Shared launch path for both `cudaLaunchKernel` and `cudaLaunchKernelExC`:
/// look up the registered function, gather its argument blobs, forward.
/// Call through `retry_transport_c` — a fork clone's first launch can race
/// the reconnect and die with a transport error the host never saw.
/// Guest-side hot-path profiler (SMOLVM_CUDA_SHIM_PROF=1): accumulated ns
/// spent inside do_launch (marshal + enqueue, excluding torch/python), dumped
/// every 8192 launches — separates OUR per-op cost from the framework's.
fn shim_prof_launch(dur: std::time::Duration) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NS: AtomicU64 = AtomicU64::new(0);
    static N: AtomicU64 = AtomicU64::new(0);
    let ns = NS.fetch_add(dur.as_nanos() as u64, Ordering::Relaxed) + dur.as_nanos() as u64;
    let n = N.fetch_add(1, Ordering::Relaxed) + 1;
    if n.is_multiple_of(8192) {
        eprintln!(
            "[shim-prof] launches={n} total={}ms avg={}ns",
            ns / 1_000_000,
            ns / n
        );
    }
}

fn do_launch(
    func: *const c_void,
    grid: [u32; 3],
    block: [u32; 3],
    shared_mem: usize,
    stream: u64,
    args: *mut *mut c_void,
) -> c_int {
    static PROF: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    if *PROF.get_or_init(|| std::env::var_os("SMOLVM_CUDA_SHIM_PROF").is_some()) {
        let t0 = std::time::Instant::now();
        let rc = do_launch_inner(func, grid, block, shared_mem, stream, args);
        shim_prof_launch(t0.elapsed());
        return rc;
    }
    do_launch_inner(func, grid, block, shared_mem, stream, args)
}

fn do_launch_inner(
    func: *const c_void,
    grid: [u32; 3],
    block: [u32; 3],
    shared_mem: usize,
    stream: u64,
    args: *mut *mut c_void,
) -> c_int {
    // Debug bisection: drop launches entirely to isolate marshaling cost.
    // Cached: an env walk per launch cost measurable ns on the hot path.
    static NOOP: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    if *NOOP.get_or_init(|| std::env::var_os("SMOLVM_CUDA_NOOP_LAUNCH").is_some()) {
        return CUDA_SUCCESS;
    }
    let device = if stream == 0 {
        function_device(func)
    } else {
        stream_device(stream as *mut c_void)
    };
    with_state_on_device(device, |s| {
        let (fid, sizes) = ensure_registered_func(s, func as usize)?;
        // Reconstruct one byte-blob per kernel argument from `args[i]`.
        let mut params: Vec<Vec<u8>> = if sizes.is_empty() {
            Vec::new()
        } else if args.is_null() {
            return Err(CUDA_ERROR_INVALID_VALUE);
        } else {
            let ptrs = unsafe { std::slice::from_raw_parts(args, sizes.len()) };
            sizes
                .iter()
                .zip(ptrs)
                .map(|(&sz, &p)| {
                    unsafe { std::slice::from_raw_parts(p as *const u8, sz as usize) }.to_vec()
                })
                .collect()
        };
        for parameter in &mut params {
            patch_mapped_host_pointers(s, parameter);
        }
        s.client
            .launch_kernel(fid, grid, block, shared_mem as u32, stream, &params)
            .map_err(map_err)
    })
    .err()
    .unwrap_or(CUDA_SUCCESS)
}

/// `cudaLaunchConfig_t` (CUDA 12): grid/block dims, dynamic shared bytes, stream,
/// then an attribute array we ignore (cluster dims etc. are not forwarded).
#[repr(C)]
struct CudaLaunchConfig {
    grid_dim: Dim3,
    block_dim: Dim3,
    dynamic_smem_bytes: usize,
    stream: *mut c_void,
    attrs: *mut c_void,
    num_attrs: c_uint,
}

#[no_mangle]
pub extern "C" fn cudaLaunchKernelExC(
    config: *const c_void,
    func: *const c_void,
    args: *mut *mut c_void,
) -> c_int {
    if config.is_null() {
        return set_last(CUDA_ERROR_INVALID_VALUE);
    }
    // SAFETY: caller passes a valid cudaLaunchConfig_t.
    let c = unsafe { &*(config as *const CudaLaunchConfig) };
    set_last(retry_transport_c(|| {
        do_launch(
            func,
            [c.grid_dim.x, c.grid_dim.y, c.grid_dim.z],
            [c.block_dim.x, c.block_dim.y, c.block_dim.z],
            c.dynamic_smem_bytes,
            c.stream as u64,
            args,
        )
    }))
}

// CUDA 12.0+ launch path. nvcc-generated stubs resolve a "kernel handle" via
// __cudaGetKernel(&handle, hostFun) once, then launch through __cudaLaunchKernel.
// We use the host stub pointer itself as the handle, so both reduce to the same
// funcs-table lookup as the classic cudaLaunchKernel.

#[no_mangle]
pub extern "C" fn __cudaGetKernel(kernel: *mut *const c_void, host_fun: *const c_void) -> c_int {
    if kernel.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    unsafe { *kernel = host_fun };
    CUDA_SUCCESS
}

#[no_mangle]
pub extern "C" fn __cudaLaunchKernel(
    kernel: *const c_void,
    grid: Dim3,
    block: Dim3,
    args: *mut *mut c_void,
    shared_mem: usize,
    stream: *mut c_void,
) -> c_int {
    // The handle is the host stub pointer (see __cudaGetKernel).
    cudaLaunchKernel(kernel, grid, block, args, shared_mem, stream)
}

/// Per-thread-default-stream variant (compiled with `--default-stream per-thread`).
#[no_mangle]
pub extern "C" fn __cudaLaunchKernel_ptsz(
    kernel: *const c_void,
    grid: Dim3,
    block: Dim3,
    args: *mut *mut c_void,
    shared_mem: usize,
    stream: *mut c_void,
) -> c_int {
    cudaLaunchKernel(kernel, grid, block, args, shared_mem, stream)
}

// ---- errors -----------------------------------------------------------------

#[no_mangle]
pub extern "C" fn cudaGetLastError() -> c_int {
    merge_sticky_async_error();
    LAST_ERROR.with(|e| {
        let v = e.get();
        e.set(CUDA_SUCCESS);
        if v != CUDA_SUCCESS && std::env::var_os("SMOLVM_CUDA_SHIM_TRACE").is_some() {
            eprintln!("[cuda-get-last-error] returning {v}");
        }
        v
    })
}

#[no_mangle]
pub extern "C" fn cudaPeekAtLastError() -> c_int {
    merge_sticky_async_error();
    LAST_ERROR.with(|e| e.get())
}

/// Fold any sticky asynchronous-pipeline error (a deferred launch/memcpy that
/// failed on the host) into the thread's last-error slot. Non-blocking: it
/// only reports failures already observed, matching how `cudaGetLastError`
/// reports asynchronous errors "seen so far" without synchronizing.
fn merge_sticky_async_error() {
    let _ = with_state(|s| {
        let code = s.client.take_sticky();
        if code != 0 {
            if std::env::var_os("SMOLVM_CUDA_SHIM_TRACE").is_some() {
                eprintln!("[cuda-sticky-error] collected driver status {code}");
            }
            set_last(map_err(CudaRpcError::Cuda(code)));
        }
        Ok(())
    });
}

#[no_mangle]
pub extern "C" fn cudaGetErrorString(error: c_int) -> *const c_char {
    let s: &CStr = match error {
        CUDA_SUCCESS => c"no error",
        CUDA_ERROR_INVALID_VALUE => c"invalid argument",
        CUDA_ERROR_MEMORY_ALLOCATION => c"out of memory",
        CUDA_ERROR_INITIALIZATION => c"initialization error",
        CUDA_ERROR_INVALID_DEVICE_POINTER => c"invalid device pointer",
        CUDA_ERROR_INVALID_RESOURCE_HANDLE => c"invalid resource handle",
        CUDA_ERROR_NO_DEVICE => c"no CUDA-capable device is detected",
        _ => c"unknown error",
    };
    s.as_ptr()
}

// ---- nvcomp (forward-to-host-lib) -------------------------------------------
// nvcomp is a dynamic library the workload links (e.g. shadowfax). Interposing
// its API here means its statically-linked cudart never runs in the guest — the
// real nvcomp runs host-side on the shared context. Device-pointer args are
// real host device addresses, forwarded by value; the stream is our handle
// (translated host-side).

#[no_mangle]
pub extern "C" fn nvcompBatchedDeflateDecompressGetTempSizeEx(
    num_chunks: usize,
    max_uncompressed_chunk_bytes: usize,
    temp_bytes: *mut usize,
    max_total_uncompressed_bytes: usize,
) -> c_int {
    match with_client(|c| {
        c.nvcomp_deflate_temp_size(
            num_chunks as u64,
            max_uncompressed_chunk_bytes as u64,
            max_total_uncompressed_bytes as u64,
        )
    }) {
        Ok((status, tb)) => {
            if !temp_bytes.is_null() {
                unsafe { *temp_bytes = tb as usize };
            }
            status
        }
        // Transport/CUDA-layer failure before nvcomp ran → generic nvcomp error.
        Err(_) => 1,
    }
}

#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn nvcompBatchedDeflateDecompressAsync(
    device_compressed_ptrs: *const *const c_void,
    device_compressed_bytes: *const usize,
    device_uncompressed_bytes: *const usize,
    device_actual_uncompressed_bytes: *mut usize,
    batch_size: usize,
    device_temp: *mut c_void,
    temp_bytes: usize,
    device_uncompressed_ptrs: *const *mut c_void,
    device_statuses: *mut c_int,
    stream: *mut c_void,
) -> c_int {
    // On success return nvcomp's own status; on a transport/CUDA-layer failure
    // before nvcomp ran, report a generic nvcomp error (1).
    with_client(|c| {
        c.nvcomp_deflate_decompress(
            device_compressed_ptrs as u64,
            device_compressed_bytes as u64,
            device_uncompressed_bytes as u64,
            device_actual_uncompressed_bytes as u64,
            batch_size as u64,
            device_temp as u64,
            temp_bytes as u64,
            device_uncompressed_ptrs as u64,
            device_statuses as u64,
            stream as u64,
        )
    })
    .unwrap_or(1)
}

#[no_mangle]
pub extern "C" fn cudaGetErrorName(error: c_int) -> *const c_char {
    let s: &CStr = match error {
        CUDA_SUCCESS => c"cudaSuccess",
        CUDA_ERROR_INVALID_VALUE => c"cudaErrorInvalidValue",
        CUDA_ERROR_MEMORY_ALLOCATION => c"cudaErrorMemoryAllocation",
        CUDA_ERROR_INITIALIZATION => c"cudaErrorInitializationError",
        _ => c"cudaErrorUnknown",
    };
    s.as_ptr()
}

/// Code-generated cuBLAS forwarding stubs over the generic `LibCall` transport.
/// Regenerate with `smolvm-cuda-codegen`; do not edit by hand.
mod gen_cublas {
    #![allow(non_snake_case, clippy::unnecessary_cast, unused_mut, dead_code)]
    use super::{c_int, c_void, with_client, with_client_retrying};
    include!("generated/cublas_guest.rs");
}

/// Code-generated cuDNN forwarding stubs. Regenerate with `smolvm-cuda-codegen`.
mod gen_cudnn {
    #![allow(non_snake_case, clippy::unnecessary_cast, unused_mut, dead_code)]
    use super::{c_int, c_void, with_client, with_client_retrying};
    include!("generated/cudnn_guest.rs");
}

// ---- cuDNN v8 backend (graph) API — PyTorch's convolution path --------------
// Forwarded via the generic LibCall transport under a dedicated lib id. Opaque
// descriptors + device pointers passing through are the server's real host
// pointers, so attribute arrays ship as raw bytes sized by the attribute type.
const LIB_CUDNN_BACKEND: u8 = 3;

/// Guest-assigned virtual descriptor ids (bit 63 tags them; host userspace
/// pointers and device VAs never set it). Lets create calls fire-and-forget:
/// we invent the id, the host maps it to the real descriptor it creates.
pub(crate) fn alloc_vhandle() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new((1 << 63) | 1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// Byte size of one `cudnnBackendAttributeType_t` element (must match host).
fn cudnn_be_elem_size(t: c_int) -> usize {
    match t {
        0 | 3 | 5 | 6 | 15 => 8, // HANDLE, INT64, DOUBLE, VOID_PTR, BACKEND_DESCRIPTOR
        2 | 24 => 1,             // BOOLEAN, CHAR
        26 => 16,                // FRACTION
        _ => 4,                  // DATA_TYPE / enums / FLOAT / INT32 / ...
    }
}

#[no_mangle]
pub extern "C" fn cudnnBackendCreateDescriptor(
    descriptor_type: c_int,
    descriptor: *mut *mut c_void,
) -> c_int {
    if descriptor.is_null() {
        return 2000; // CUDNN_STATUS_BAD_PARAM
    }
    // Fire-and-forget: hand back a virtual id now; the host materializes the
    // descriptor and maps the id. A creation failure surfaces on the next
    // synchronous call touching it (Finalize/GetAttribute).
    let vh = alloc_vhandle();
    let mut a = descriptor_type.to_le_bytes().to_vec();
    a.extend_from_slice(&vh.to_le_bytes());
    match with_client(|c| c.lib_call_deferred(LIB_CUDNN_BACKEND, 0, a)) {
        Ok(()) => {
            unsafe { *descriptor = vh as *mut c_void };
            0
        }
        Err(_) => 1,
    }
}

#[no_mangle]
pub extern "C" fn cudnnBackendDestroyDescriptor(descriptor: *mut c_void) -> c_int {
    let a = (descriptor as u64).to_le_bytes().to_vec();
    match with_client(|c| c.lib_call_deferred(LIB_CUDNN_BACKEND, 1, a)) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[no_mangle]
pub extern "C" fn cudnnBackendSetAttribute(
    descriptor: *mut c_void,
    attribute_name: c_int,
    attribute_type: c_int,
    element_count: i64,
    array_of_elements: *const c_void,
) -> c_int {
    let n = (element_count.max(0) as usize) * cudnn_be_elem_size(attribute_type);
    let mut a = Vec::with_capacity(24 + n);
    a.extend_from_slice(&(descriptor as u64).to_le_bytes());
    a.extend_from_slice(&attribute_name.to_le_bytes());
    a.extend_from_slice(&attribute_type.to_le_bytes());
    a.extend_from_slice(&element_count.to_le_bytes());
    if n > 0 && !array_of_elements.is_null() {
        a.extend_from_slice(unsafe {
            std::slice::from_raw_parts(array_of_elements as *const u8, n)
        });
    }
    match with_client(|c| c.lib_call_deferred(LIB_CUDNN_BACKEND, 2, a)) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[no_mangle]
pub extern "C" fn cudnnBackendGetAttribute(
    descriptor: *mut c_void,
    attribute_name: c_int,
    attribute_type: c_int,
    requested_element_count: i64,
    element_count: *mut i64,
    array_of_elements: *mut c_void,
) -> c_int {
    let cap = (requested_element_count.max(0) as usize) * cudnn_be_elem_size(attribute_type);
    let mut a = Vec::with_capacity(24 + cap);
    a.extend_from_slice(&(descriptor as u64).to_le_bytes());
    a.extend_from_slice(&attribute_name.to_le_bytes());
    a.extend_from_slice(&attribute_type.to_le_bytes());
    a.extend_from_slice(&requested_element_count.to_le_bytes());
    // Seed with current contents: descriptor-array gets pass pre-created handles.
    if cap > 0 && !array_of_elements.is_null() {
        a.extend_from_slice(unsafe {
            std::slice::from_raw_parts(array_of_elements as *const u8, cap)
        });
    }
    match with_client_retrying(|c| c.lib_call(LIB_CUDNN_BACKEND, 3, a.clone())) {
        Ok((0, out)) if out.len() >= 8 => {
            let cnt = i64::from_le_bytes(out[..8].try_into().unwrap());
            if !element_count.is_null() {
                unsafe { *element_count = cnt };
            }
            let bytes = &out[8..];
            if !array_of_elements.is_null() && !bytes.is_empty() {
                let cap =
                    (requested_element_count.max(0) as usize) * cudnn_be_elem_size(attribute_type);
                let n = bytes.len().min(cap);
                // Descriptor arrays are populated *in place*: the returned
                // pointers are the caller's own descriptors, so keep the ids
                // the caller passed (they may be virtual) instead of the real
                // host pointers the server sees.
                const TYPE_BACKEND_DESCRIPTOR: c_int = 15;
                if attribute_type != TYPE_BACKEND_DESCRIPTOR {
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            bytes.as_ptr(),
                            array_of_elements as *mut u8,
                            n,
                        )
                    };
                }
            }
            0
        }
        Ok((st, _)) => st,
        Err(_) => 1,
    }
}

#[no_mangle]
pub extern "C" fn cudnnBackendFinalize(descriptor: *mut c_void) -> c_int {
    let a = (descriptor as u64).to_le_bytes().to_vec();
    match with_client_retrying(|c| c.lib_call(LIB_CUDNN_BACKEND, 4, a.clone())) {
        Ok((st, _)) => st,
        Err(_) => 1,
    }
}

#[no_mangle]
pub extern "C" fn cudnnBackendExecute(
    handle: *mut c_void,
    execution_plan: *mut c_void,
    variant_pack: *mut c_void,
) -> c_int {
    let mut a = Vec::with_capacity(24);
    a.extend_from_slice(&(handle as u64).to_le_bytes());
    a.extend_from_slice(&(execution_plan as u64).to_le_bytes());
    a.extend_from_slice(&(variant_pack as u64).to_le_bytes());
    match with_client(|c| c.lib_call_deferred(LIB_CUDNN_BACKEND, 5, a)) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

// ---- cuBLASLt matmul API — PyTorch's linear-layer path -----------------------
// Forwarded via the generic LibCall transport. Descriptors, layouts, preferences
// and device pointers are the server's real host pointers (opaque handles here);
// the opaque 64-byte algo blob and attribute buffers ship as raw bytes. The
// "light handle" is the connection's cuBLAS handle, which torch reuses for Lt.
const LIB_CUBLASLT: u8 = 4;
const CUBLAS_STATUS_SUCCESS: c_int = 0;
const CUBLAS_STATUS_NOT_INITIALIZED: c_int = 1;

// ---- cuBLASLt descriptor fast path -------------------------------------------
// torch builds desc + layouts + preference around EVERY Linear matmul; sync
// round-trips here dominated eager decode (125k of 184k). Creates are
// fire-and-forget with guest-minted virtual ids (bit-63-tagged, host maps
// them), Set/Destroy defer, and AlgoGetHeuristic memoizes on the CONTENT of
// the descriptors (ids change every step; the shapes repeat).
/// Live Lt handle → content fingerprint (create args + every attr write).
static LT_FP: Mutex<Option<HashMap<u64, Vec<u8>>>> = Mutex::new(None);
/// Heuristic memo entry: (status, out blob).
type LtHeurEntry = (c_int, Vec<u8>);
/// Heuristic memo: concatenated fingerprints + request → result.
static LT_HEUR_MEMO: Mutex<Option<HashMap<Vec<u8>, LtHeurEntry>>> = Mutex::new(None);

fn lt_mint(create_args: &[u8]) -> u64 {
    // Share the process-wide virtual-handle counter (alloc_vhandle) — a
    // second counter minted colliding ids and clobbered the host's map.
    let id = alloc_vhandle();
    let mut g = LT_FP.lock().unwrap();
    g.get_or_insert_with(HashMap::new)
        .insert(id, create_args.to_vec());
    id
}

fn lt_fp_append(handle: u64, attr: c_int, buf: &[u8]) {
    let mut g = LT_FP.lock().unwrap();
    if let Some(fp) = g.get_or_insert_with(HashMap::new).get_mut(&handle) {
        fp.extend_from_slice(&attr.to_le_bytes());
        fp.extend_from_slice(&(buf.len() as u32).to_le_bytes());
        fp.extend_from_slice(buf);
    }
}

fn lt_fp_of(handle: u64) -> Vec<u8> {
    let mut g = LT_FP.lock().unwrap();
    g.get_or_insert_with(HashMap::new)
        .get(&handle)
        .cloned()
        .unwrap_or_else(|| handle.to_le_bytes().to_vec())
}

fn lt_fp_drop(handle: u64) {
    let mut g = LT_FP.lock().unwrap();
    g.get_or_insert_with(HashMap::new).remove(&handle);
}
/// sizeof(cublasLtMatmulHeuristicResult_t): algo[64]+workspaceSize(8)+state(4)
/// +wavesCount(4)+reserved[4](16). Must match the host.
const LT_HEUR_RESULT_SZ: usize = 96;

#[no_mangle]
pub extern "C" fn cublasLtCreate(light_handle: *mut *mut c_void) -> c_int {
    if light_handle.is_null() {
        return CUBLAS_STATUS_NOT_INITIALIZED;
    }
    match with_client_retrying(|c| c.lib_call(LIB_CUBLASLT, 11, Vec::new())) {
        Ok((0, out)) if out.len() >= 8 => {
            unsafe {
                *light_handle = u64::from_le_bytes(out[..8].try_into().unwrap()) as *mut c_void
            };
            CUBLAS_STATUS_SUCCESS
        }
        Ok((st, _)) => st,
        Err(_) => CUBLAS_STATUS_NOT_INITIALIZED,
    }
}

#[no_mangle]
pub extern "C" fn cublasLtDestroy(light_handle: *mut c_void) -> c_int {
    let a = (light_handle as u64).to_le_bytes().to_vec();
    match with_client_retrying(|c| c.lib_call(LIB_CUBLASLT, 12, a.clone())) {
        Ok((st, _)) => st,
        Err(_) => CUBLAS_STATUS_NOT_INITIALIZED,
    }
}

#[no_mangle]
pub extern "C" fn cublasLtMatmulDescCreate(
    matmul_desc: *mut *mut c_void,
    compute_type: c_int,
    scale_type: c_int,
) -> c_int {
    if matmul_desc.is_null() {
        return CUBLAS_STATUS_NOT_INITIALIZED;
    }
    let mut a = Vec::with_capacity(16);
    a.extend_from_slice(&compute_type.to_le_bytes());
    a.extend_from_slice(&scale_type.to_le_bytes());
    let vh = lt_mint(&a);
    a.extend_from_slice(&vh.to_le_bytes());
    match with_client(|c| c.lib_call_deferred(LIB_CUBLASLT, 0, a)) {
        Ok(()) => {
            unsafe { *matmul_desc = vh as *mut c_void };
            CUBLAS_STATUS_SUCCESS
        }
        Err(_) => CUBLAS_STATUS_NOT_INITIALIZED,
    }
}

#[no_mangle]
pub extern "C" fn cublasLtMatmulDescDestroy(matmul_desc: *mut c_void) -> c_int {
    lt_fp_drop(matmul_desc as u64);
    let a = (matmul_desc as u64).to_le_bytes().to_vec();
    match with_client(|c| c.lib_call_deferred(LIB_CUBLASLT, 1, a)) {
        Ok(()) => CUBLAS_STATUS_SUCCESS,
        Err(_) => CUBLAS_STATUS_NOT_INITIALIZED,
    }
}

/// Pack an opaque descriptor/layout/preference SetAttribute call: the attribute
/// buffer forwards verbatim (device pointers inside it stay coherent).
fn lt_set_attr(
    func: u16,
    handle: *mut c_void,
    attr: c_int,
    buf: *const c_void,
    size: usize,
) -> c_int {
    let mut a = Vec::with_capacity(12 + size);
    a.extend_from_slice(&(handle as u64).to_le_bytes());
    a.extend_from_slice(&attr.to_le_bytes());
    let bytes: &[u8] = if size > 0 && !buf.is_null() {
        unsafe { std::slice::from_raw_parts(buf as *const u8, size) }
    } else {
        &[]
    };
    a.extend_from_slice(bytes);
    lt_fp_append(handle as u64, attr, bytes);
    match with_client(|c| c.lib_call_deferred(LIB_CUBLASLT, func, a)) {
        Ok(()) => CUBLAS_STATUS_SUCCESS,
        Err(_) => CUBLAS_STATUS_NOT_INITIALIZED,
    }
}

#[no_mangle]
pub extern "C" fn cublasLtMatmulDescSetAttribute(
    matmul_desc: *mut c_void,
    attr: c_int,
    buf: *const c_void,
    size_in_bytes: usize,
) -> c_int {
    lt_set_attr(2, matmul_desc, attr, buf, size_in_bytes)
}

#[no_mangle]
pub extern "C" fn cublasLtMatrixLayoutCreate(
    mat_layout: *mut *mut c_void,
    data_type: c_int,
    rows: u64,
    cols: u64,
    ld: i64,
) -> c_int {
    if mat_layout.is_null() {
        return CUBLAS_STATUS_NOT_INITIALIZED;
    }
    let mut a = Vec::with_capacity(36);
    a.extend_from_slice(&data_type.to_le_bytes());
    a.extend_from_slice(&rows.to_le_bytes());
    a.extend_from_slice(&cols.to_le_bytes());
    a.extend_from_slice(&ld.to_le_bytes());
    let vh = lt_mint(&a);
    a.extend_from_slice(&vh.to_le_bytes());
    match with_client(|c| c.lib_call_deferred(LIB_CUBLASLT, 3, a)) {
        Ok(()) => {
            unsafe { *mat_layout = vh as *mut c_void };
            CUBLAS_STATUS_SUCCESS
        }
        Err(_) => CUBLAS_STATUS_NOT_INITIALIZED,
    }
}

#[no_mangle]
pub extern "C" fn cublasLtMatrixLayoutDestroy(mat_layout: *mut c_void) -> c_int {
    lt_fp_drop(mat_layout as u64);
    let a = (mat_layout as u64).to_le_bytes().to_vec();
    match with_client(|c| c.lib_call_deferred(LIB_CUBLASLT, 4, a)) {
        Ok(()) => CUBLAS_STATUS_SUCCESS,
        Err(_) => CUBLAS_STATUS_NOT_INITIALIZED,
    }
}

#[no_mangle]
pub extern "C" fn cublasLtMatrixLayoutSetAttribute(
    mat_layout: *mut c_void,
    attr: c_int,
    buf: *const c_void,
    size_in_bytes: usize,
) -> c_int {
    lt_set_attr(5, mat_layout, attr, buf, size_in_bytes)
}

#[no_mangle]
pub extern "C" fn cublasLtMatmulPreferenceCreate(pref: *mut *mut c_void) -> c_int {
    if pref.is_null() {
        return CUBLAS_STATUS_NOT_INITIALIZED;
    }
    let vh = lt_mint(&[]);
    match with_client(|c| c.lib_call_deferred(LIB_CUBLASLT, 6, vh.to_le_bytes().to_vec())) {
        Ok(()) => {
            unsafe { *pref = vh as *mut c_void };
            CUBLAS_STATUS_SUCCESS
        }
        Err(_) => CUBLAS_STATUS_NOT_INITIALIZED,
    }
}

#[no_mangle]
pub extern "C" fn cublasLtMatmulPreferenceDestroy(pref: *mut c_void) -> c_int {
    lt_fp_drop(pref as u64);
    let a = (pref as u64).to_le_bytes().to_vec();
    match with_client(|c| c.lib_call_deferred(LIB_CUBLASLT, 7, a)) {
        Ok(()) => CUBLAS_STATUS_SUCCESS,
        Err(_) => CUBLAS_STATUS_NOT_INITIALIZED,
    }
}

#[no_mangle]
pub extern "C" fn cublasLtMatmulPreferenceSetAttribute(
    pref: *mut c_void,
    attr: c_int,
    buf: *const c_void,
    size_in_bytes: usize,
) -> c_int {
    lt_set_attr(8, pref, attr, buf, size_in_bytes)
}

#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn cublasLtMatmulAlgoGetHeuristic(
    light_handle: *mut c_void,
    operation_desc: *mut c_void,
    a_desc: *mut c_void,
    b_desc: *mut c_void,
    c_desc: *mut c_void,
    d_desc: *mut c_void,
    preference: *mut c_void,
    requested_algo_count: c_int,
    heuristic_results_array: *mut c_void,
    return_algo_count: *mut c_int,
) -> c_int {
    // Memo key: the CONTENT of every descriptor (ids change per step; the
    // shapes repeat every decode step, so this hits ~always after warmup).
    let mut key = Vec::new();
    for h in [operation_desc, a_desc, b_desc, c_desc, d_desc, preference] {
        let fp = lt_fp_of(h as u64);
        key.extend_from_slice(&(fp.len() as u32).to_le_bytes());
        key.extend_from_slice(&fp);
    }
    key.extend_from_slice(&requested_algo_count.to_le_bytes());
    if let Some((st, out)) = LT_HEUR_MEMO
        .lock()
        .unwrap()
        .get_or_insert_with(HashMap::new)
        .get(&key)
        .cloned()
    {
        if st == 0 && out.len() >= 8 {
            let count = i64::from_le_bytes(out[..8].try_into().unwrap()).max(0) as usize;
            if !return_algo_count.is_null() {
                unsafe { *return_algo_count = count as c_int };
            }
            let bytes = &out[8..];
            if !heuristic_results_array.is_null() {
                let n = bytes.len().min(count * LT_HEUR_RESULT_SZ);
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        bytes.as_ptr(),
                        heuristic_results_array as *mut u8,
                        n,
                    )
                };
            }
            return CUBLAS_STATUS_SUCCESS;
        }
        return st;
    }
    let mut a = Vec::with_capacity(60);
    a.extend_from_slice(&(light_handle as u64).to_le_bytes());
    a.extend_from_slice(&(operation_desc as u64).to_le_bytes());
    a.extend_from_slice(&(a_desc as u64).to_le_bytes());
    a.extend_from_slice(&(b_desc as u64).to_le_bytes());
    a.extend_from_slice(&(c_desc as u64).to_le_bytes());
    a.extend_from_slice(&(d_desc as u64).to_le_bytes());
    a.extend_from_slice(&(preference as u64).to_le_bytes());
    a.extend_from_slice(&requested_algo_count.to_le_bytes());
    match with_client_retrying(|c| c.lib_call(LIB_CUBLASLT, 9, a.clone())) {
        Ok((0, out)) if out.len() >= 8 => {
            LT_HEUR_MEMO
                .lock()
                .unwrap()
                .get_or_insert_with(HashMap::new)
                .insert(key, (0, out.clone()));
            let count = i64::from_le_bytes(out[..8].try_into().unwrap()).max(0) as usize;
            if !return_algo_count.is_null() {
                unsafe { *return_algo_count = count as c_int };
            }
            let bytes = &out[8..];
            if !heuristic_results_array.is_null() {
                let n = bytes.len().min(count * LT_HEUR_RESULT_SZ);
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        bytes.as_ptr(),
                        heuristic_results_array as *mut u8,
                        n,
                    )
                };
            }
            CUBLAS_STATUS_SUCCESS
        }
        Ok((st, _)) => st,
        Err(_) => CUBLAS_STATUS_NOT_INITIALIZED,
    }
}

#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn cublasLtMatmul(
    light_handle: *mut c_void,
    compute_desc: *mut c_void,
    alpha: *const c_void,
    a: *const c_void,
    a_desc: *mut c_void,
    b: *const c_void,
    b_desc: *mut c_void,
    beta: *const c_void,
    c: *const c_void,
    c_desc: *mut c_void,
    d: *mut c_void,
    d_desc: *mut c_void,
    algo: *const c_void,
    workspace: *mut c_void,
    workspace_size_in_bytes: usize,
    stream: *mut c_void,
) -> c_int {
    // alpha/beta are host scalars sized by the desc's scale type (≤16 bytes for
    // any real/complex type); forward a fixed 16-byte window so either fits.
    let read16 = |p: *const c_void| -> [u8; 16] {
        let mut v = [0u8; 16];
        if !p.is_null() {
            unsafe { std::ptr::copy_nonoverlapping(p as *const u8, v.as_mut_ptr(), 16) };
        }
        v
    };
    let algo_bytes = {
        let mut v = [0u8; 64];
        if !algo.is_null() {
            unsafe { std::ptr::copy_nonoverlapping(algo as *const u8, v.as_mut_ptr(), 64) };
        }
        v
    };
    let mut buf = Vec::with_capacity(208);
    buf.extend_from_slice(&(light_handle as u64).to_le_bytes());
    buf.extend_from_slice(&(compute_desc as u64).to_le_bytes());
    buf.extend_from_slice(&read16(alpha));
    buf.extend_from_slice(&(a as u64).to_le_bytes());
    buf.extend_from_slice(&(a_desc as u64).to_le_bytes());
    buf.extend_from_slice(&(b as u64).to_le_bytes());
    buf.extend_from_slice(&(b_desc as u64).to_le_bytes());
    buf.extend_from_slice(&read16(beta));
    buf.extend_from_slice(&(c as u64).to_le_bytes());
    buf.extend_from_slice(&(c_desc as u64).to_le_bytes());
    buf.extend_from_slice(&(d as u64).to_le_bytes());
    buf.extend_from_slice(&(d_desc as u64).to_le_bytes());
    buf.extend_from_slice(&algo_bytes);
    buf.extend_from_slice(&(if algo.is_null() { 0u64 } else { 1u64 }).to_le_bytes());
    buf.extend_from_slice(&(workspace as u64).to_le_bytes());
    buf.extend_from_slice(&(workspace_size_in_bytes as u64).to_le_bytes());
    buf.extend_from_slice(&(stream as u64).to_le_bytes());
    match with_client(|c| c.lib_call_deferred(LIB_CUBLASLT, 10, buf)) {
        Ok(()) => CUBLAS_STATUS_SUCCESS,
        Err(_) => CUBLAS_STATUS_NOT_INITIALIZED,
    }
}

// ---- Legacy cuDNN batch-norm (Ex) + N-D descriptor — BatchNorm2d path --------
// Forwarded via the generic LibCall transport. Descriptors and device pointers
// are the server's real host pointers; alpha/beta are float scalars, epsilon and
// the averaging factor are doubles, and the N-D descriptor's dim/stride arrays
// forward as raw i32s.
const LIB_CUDNN_BN: u8 = 5;

/// A valid, static message pointer for `cudnnGetErrorString`. The real function
/// returns `const char*`; torch dereferences it when formatting errors, so a
/// stub that returned an int caused a segfault. The exact text is cosmetic.
#[no_mangle]
pub extern "C" fn cudnnGetErrorString(_status: c_int) -> *const c_char {
    c"cudnn status (forwarded by smolvm)".as_ptr()
}

/// Read a host float behind a `*const c_void` (cuDNN alpha/beta), 0.0 if null.
fn bn_f32(p: *const c_void) -> f32 {
    if p.is_null() {
        0.0
    } else {
        unsafe { *(p as *const f32) }
    }
}

#[no_mangle]
pub extern "C" fn cudnnSetTensorNdDescriptor(
    tensor_desc: *mut c_void,
    data_type: c_int,
    nb_dims: c_int,
    dim_a: *const c_int,
    stride_a: *const c_int,
) -> c_int {
    let n = nb_dims.max(0) as usize;
    let mut a = Vec::with_capacity(16 + n * 8);
    a.extend_from_slice(&(tensor_desc as u64).to_le_bytes());
    a.extend_from_slice(&data_type.to_le_bytes());
    a.extend_from_slice(&nb_dims.to_le_bytes());
    // Record this descriptor\'s content fingerprint (everything after the
    // handle) so pure size queries over it can be memoized soundly — the
    // handle value alone is reusable across different shapes.
    record_desc_fingerprint(tensor_desc as u64, &a[8..]);
    for arr in [dim_a, stride_a] {
        for i in 0..n {
            let v = if arr.is_null() {
                0
            } else {
                unsafe { *arr.add(i) }
            };
            a.extend_from_slice(&v.to_le_bytes());
        }
    }
    match with_client(|c| c.lib_call_deferred(LIB_CUDNN_BN, 0, a)) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn cudnnBatchNormalizationForwardInference(
    handle: *mut c_void,
    mode: c_int,
    alpha: *const c_void,
    beta: *const c_void,
    x_desc: *mut c_void,
    x: *const c_void,
    y_desc: *mut c_void,
    y: *mut c_void,
    bn_desc: *mut c_void,
    bn_scale: *const c_void,
    bn_bias: *const c_void,
    est_mean: *const c_void,
    est_var: *const c_void,
    epsilon: f64,
) -> c_int {
    let mut a = Vec::with_capacity(96);
    a.extend_from_slice(&(handle as u64).to_le_bytes());
    a.extend_from_slice(&mode.to_le_bytes());
    a.extend_from_slice(&bn_f32(alpha).to_le_bytes());
    a.extend_from_slice(&bn_f32(beta).to_le_bytes());
    for p in [
        x_desc as u64,
        x as u64,
        y_desc as u64,
        y as u64,
        bn_desc as u64,
        bn_scale as u64,
        bn_bias as u64,
        est_mean as u64,
        est_var as u64,
    ] {
        a.extend_from_slice(&p.to_le_bytes());
    }
    a.extend_from_slice(&epsilon.to_le_bytes());
    match with_client(|c| c.lib_call_deferred(LIB_CUDNN_BN, 2, a)) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn cudnnBatchNormalizationForwardTrainingEx(
    handle: *mut c_void,
    mode: c_int,
    bn_ops: c_int,
    alpha: *const c_void,
    beta: *const c_void,
    x_desc: *mut c_void,
    x: *const c_void,
    z_desc: *mut c_void,
    z: *const c_void,
    y_desc: *mut c_void,
    y: *mut c_void,
    bn_desc: *mut c_void,
    bn_scale: *const c_void,
    bn_bias: *const c_void,
    factor: f64,
    run_mean: *mut c_void,
    run_var: *mut c_void,
    epsilon: f64,
    save_mean: *mut c_void,
    save_ivar: *mut c_void,
    act_desc: *mut c_void,
    workspace: *mut c_void,
    ws_size: usize,
    reserve: *mut c_void,
    reserve_size: usize,
) -> c_int {
    let mut a = Vec::with_capacity(200);
    a.extend_from_slice(&(handle as u64).to_le_bytes());
    a.extend_from_slice(&mode.to_le_bytes());
    a.extend_from_slice(&bn_ops.to_le_bytes());
    a.extend_from_slice(&bn_f32(alpha).to_le_bytes());
    a.extend_from_slice(&bn_f32(beta).to_le_bytes());
    for p in [
        x_desc as u64,
        x as u64,
        z_desc as u64,
        z as u64,
        y_desc as u64,
        y as u64,
        bn_desc as u64,
        bn_scale as u64,
        bn_bias as u64,
    ] {
        a.extend_from_slice(&p.to_le_bytes());
    }
    a.extend_from_slice(&factor.to_le_bytes());
    a.extend_from_slice(&(run_mean as u64).to_le_bytes());
    a.extend_from_slice(&(run_var as u64).to_le_bytes());
    a.extend_from_slice(&epsilon.to_le_bytes());
    for p in [
        save_mean as u64,
        save_ivar as u64,
        act_desc as u64,
        workspace as u64,
    ] {
        a.extend_from_slice(&p.to_le_bytes());
    }
    a.extend_from_slice(&(ws_size as u64).to_le_bytes());
    a.extend_from_slice(&(reserve as u64).to_le_bytes());
    a.extend_from_slice(&(reserve_size as u64).to_le_bytes());
    match with_client(|c| c.lib_call_deferred(LIB_CUDNN_BN, 3, a)) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn cudnnBatchNormalizationBackwardEx(
    handle: *mut c_void,
    mode: c_int,
    bn_ops: c_int,
    alpha_d: *const c_void,
    beta_d: *const c_void,
    alpha_p: *const c_void,
    beta_p: *const c_void,
    x_desc: *mut c_void,
    x: *const c_void,
    y_desc: *mut c_void,
    y: *const c_void,
    dy_desc: *mut c_void,
    dy: *const c_void,
    dz_desc: *mut c_void,
    dz: *mut c_void,
    dx_desc: *mut c_void,
    dx: *mut c_void,
    d_bn_desc: *mut c_void,
    bn_scale: *const c_void,
    bn_bias: *const c_void,
    d_bn_scale: *mut c_void,
    d_bn_bias: *mut c_void,
    epsilon: f64,
    saved_mean: *const c_void,
    saved_ivar: *const c_void,
    act_desc: *mut c_void,
    workspace: *mut c_void,
    ws_size: usize,
    reserve: *mut c_void,
    reserve_size: usize,
) -> c_int {
    let mut a = Vec::with_capacity(256);
    a.extend_from_slice(&(handle as u64).to_le_bytes());
    a.extend_from_slice(&mode.to_le_bytes());
    a.extend_from_slice(&bn_ops.to_le_bytes());
    a.extend_from_slice(&bn_f32(alpha_d).to_le_bytes());
    a.extend_from_slice(&bn_f32(beta_d).to_le_bytes());
    a.extend_from_slice(&bn_f32(alpha_p).to_le_bytes());
    a.extend_from_slice(&bn_f32(beta_p).to_le_bytes());
    for p in [
        x_desc as u64,
        x as u64,
        y_desc as u64,
        y as u64,
        dy_desc as u64,
        dy as u64,
        dz_desc as u64,
        dz as u64,
        dx_desc as u64,
        dx as u64,
        d_bn_desc as u64,
        bn_scale as u64,
        bn_bias as u64,
        d_bn_scale as u64,
        d_bn_bias as u64,
    ] {
        a.extend_from_slice(&p.to_le_bytes());
    }
    a.extend_from_slice(&epsilon.to_le_bytes());
    for p in [
        saved_mean as u64,
        saved_ivar as u64,
        act_desc as u64,
        workspace as u64,
    ] {
        a.extend_from_slice(&p.to_le_bytes());
    }
    a.extend_from_slice(&(ws_size as u64).to_le_bytes());
    a.extend_from_slice(&(reserve as u64).to_le_bytes());
    a.extend_from_slice(&(reserve_size as u64).to_le_bytes());
    match with_client(|c| c.lib_call_deferred(LIB_CUDNN_BN, 4, a)) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

/// Tensor-descriptor content fingerprints (dtype + dims + strides from the
/// last `cudnnSetTensorNdDescriptor`), keyed by handle value. A handle alone
/// is not a stable identity — destroy/create can reuse the address — so size
/// memoization keys on these contents instead.
static DESC_FP: Mutex<Option<HashMap<u64, Vec<u8>>>> = Mutex::new(None);

fn record_desc_fingerprint(desc: u64, contents: &[u8]) {
    if let Ok(mut g) = DESC_FP.lock() {
        g.get_or_insert_with(HashMap::new)
            .insert(desc, contents.to_vec());
    }
}

/// Rewrite a BN size-query arg blob into a content-addressed memo key: every
/// descriptor handle is replaced by its recorded fingerprint. `None` (do not
/// cache) if any non-null descriptor has no fingerprint on record.
fn bn_memo_key(func: u16, args: &[u8]) -> Option<Vec<u8>> {
    // Layouts (see the three Get*Size wrappers): handle u64, mode i32, ops i32,
    // then only u64 descriptor handles (5/7 for the workspace queries, act+x
    // for the reserve query). The leading cudnn handle is identity-stable.
    if args.len() < 16 || !(args.len() - 16).is_multiple_of(8) {
        return None;
    }
    let fps = DESC_FP.lock().ok()?;
    let fps = fps.as_ref()?;
    let mut key = Vec::with_capacity(args.len() * 4);
    key.extend_from_slice(&func.to_le_bytes());
    key.extend_from_slice(&args[..16]);
    for chunk in args[16..].as_chunks::<8>().0 {
        let h = u64::from_le_bytes(*chunk);
        if h == 0 {
            key.push(0);
            continue;
        }
        let fp = fps.get(&h)?; // unknown descriptor → uncacheable
        key.extend_from_slice(&(fp.len() as u32).to_le_bytes());
        key.extend_from_slice(fp);
    }
    Some(key)
}

/// Shared tail for the three `Get...Size` queries: forward the packed args and
/// write the returned `size_t` through `size_out`. Memoized on the descriptor
/// *contents* (not handles): the sizes are pure functions of those contents,
/// and PyTorch re-queries them on every batch-norm invocation (~150 sync
/// round-trips per ResNet training step without the cache).
fn bn_size_call(func: u16, args: Vec<u8>, size_out: *mut usize) -> c_int {
    static MEMO: Mutex<Option<HashMap<Vec<u8>, usize>>> = Mutex::new(None);
    let key = bn_memo_key(func, &args);
    if let Some(k) = &key {
        if let Ok(mut g) = MEMO.lock() {
            if let Some(sz) = g.get_or_insert_with(HashMap::new).get(k) {
                if !size_out.is_null() {
                    unsafe { *size_out = *sz };
                }
                return 0;
            }
        }
    }
    match with_client_retrying(|c| c.lib_call(LIB_CUDNN_BN, func, args.clone())) {
        Ok((0, out)) if out.len() >= 8 => {
            let sz = u64::from_le_bytes(out[..8].try_into().unwrap()) as usize;
            if !size_out.is_null() {
                unsafe { *size_out = sz };
            }
            if let Some(k) = key {
                if let Ok(mut g) = MEMO.lock() {
                    g.get_or_insert_with(HashMap::new).insert(k, sz);
                }
            }
            0
        }
        Ok((st, _)) => st,
        Err(_) => 1,
    }
}

#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn cudnnGetBatchNormalizationForwardTrainingExWorkspaceSize(
    handle: *mut c_void,
    mode: c_int,
    bn_ops: c_int,
    x_desc: *mut c_void,
    z_desc: *mut c_void,
    y_desc: *mut c_void,
    bn_desc: *mut c_void,
    act_desc: *mut c_void,
    size_out: *mut usize,
) -> c_int {
    let mut a = Vec::with_capacity(56);
    a.extend_from_slice(&(handle as u64).to_le_bytes());
    a.extend_from_slice(&mode.to_le_bytes());
    a.extend_from_slice(&bn_ops.to_le_bytes());
    for p in [
        x_desc as u64,
        z_desc as u64,
        y_desc as u64,
        bn_desc as u64,
        act_desc as u64,
    ] {
        a.extend_from_slice(&p.to_le_bytes());
    }
    bn_size_call(5, a, size_out)
}

#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn cudnnGetBatchNormalizationBackwardExWorkspaceSize(
    handle: *mut c_void,
    mode: c_int,
    bn_ops: c_int,
    x_desc: *mut c_void,
    y_desc: *mut c_void,
    dy_desc: *mut c_void,
    dz_desc: *mut c_void,
    dx_desc: *mut c_void,
    d_bn_desc: *mut c_void,
    act_desc: *mut c_void,
    size_out: *mut usize,
) -> c_int {
    let mut a = Vec::with_capacity(64);
    a.extend_from_slice(&(handle as u64).to_le_bytes());
    a.extend_from_slice(&mode.to_le_bytes());
    a.extend_from_slice(&bn_ops.to_le_bytes());
    for p in [
        x_desc as u64,
        y_desc as u64,
        dy_desc as u64,
        dz_desc as u64,
        dx_desc as u64,
        d_bn_desc as u64,
        act_desc as u64,
    ] {
        a.extend_from_slice(&p.to_le_bytes());
    }
    bn_size_call(6, a, size_out)
}

#[no_mangle]
pub extern "C" fn cudnnGetBatchNormalizationTrainingExReserveSpaceSize(
    handle: *mut c_void,
    mode: c_int,
    bn_ops: c_int,
    act_desc: *mut c_void,
    x_desc: *mut c_void,
    size_out: *mut usize,
) -> c_int {
    let mut a = Vec::with_capacity(40);
    a.extend_from_slice(&(handle as u64).to_le_bytes());
    a.extend_from_slice(&mode.to_le_bytes());
    a.extend_from_slice(&bn_ops.to_le_bytes());
    a.extend_from_slice(&(act_desc as u64).to_le_bytes());
    a.extend_from_slice(&(x_desc as u64).to_le_bytes());
    bn_size_call(7, a, size_out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_info_stays_local_for_independent_roots() {
        let mut captures = HashMap::new();
        assert_eq!(local_capture_info(&captures, 22), Some((CAPTURE_NONE, 0)));
        captures.insert(
            11,
            CaptureRecord {
                local_id: 77,
                host_id: None,
            },
        );
        captures.insert(
            22,
            CaptureRecord {
                local_id: 88,
                host_id: None,
            },
        );
        assert_eq!(
            local_capture_info(&captures, 11),
            Some((CAPTURE_ACTIVE, 77))
        );
        assert_eq!(
            local_capture_info(&captures, 22),
            Some((CAPTURE_ACTIVE, 88))
        );
    }

    #[test]
    fn unrelated_side_stream_stays_outside_capture() {
        let captures = HashMap::from([(
            11,
            CaptureRecord {
                local_id: 77,
                host_id: None,
            },
        )]);
        assert_eq!(local_capture_info(&captures, 22), None);
    }

    #[test]
    fn capture_errors_preserve_runtime_codes() {
        for code in 900..=910 {
            assert_eq!(map_err(CudaRpcError::Cuda(code)), code);
        }
    }

    #[test]
    fn module_image_lengths_cover_ptx_fatbin_and_elf() {
        let ptx = b".version 7.0\0";
        assert_eq!(
            unsafe { module_image_len(ptx.as_ptr().cast()) },
            Ok(ptx.len())
        );

        let mut fatbin = [0u8; 32];
        fatbin[..4].copy_from_slice(&0xBA55_ED50u32.to_le_bytes());
        fatbin[6..8].copy_from_slice(&16u16.to_le_bytes());
        fatbin[8..16].copy_from_slice(&16u64.to_le_bytes());
        assert_eq!(unsafe { module_image_len(fatbin.as_ptr().cast()) }, Ok(32));

        let mut elf = [0u8; 256];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2; // ELFCLASS64
        elf[5] = 1; // ELFDATA2LSB
        elf[0x20..0x28].copy_from_slice(&64u64.to_le_bytes());
        elf[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
        elf[0x38..0x3a].copy_from_slice(&2u16.to_le_bytes());
        elf[0x28..0x30].copy_from_slice(&128u64.to_le_bytes());
        elf[0x3a..0x3c].copy_from_slice(&64u16.to_le_bytes());
        elf[0x3c..0x3e].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(unsafe { module_image_len(elf.as_ptr().cast()) }, Ok(256));

        let mut oversized_elf = [0u8; 64];
        oversized_elf[..4].copy_from_slice(b"\x7fELF");
        oversized_elf[4] = 2;
        oversized_elf[5] = 1;
        oversized_elf[0x20..0x28].copy_from_slice(&(128u64 * 1024 * 1024).to_le_bytes());
        oversized_elf[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
        oversized_elf[0x38..0x3a].copy_from_slice(&1u16.to_le_bytes());
        assert_eq!(
            unsafe { module_image_len(oversized_elf.as_ptr().cast()) },
            Err(CUDA_ERROR_INVALID_VALUE)
        );
    }

    #[test]
    fn static_registration_stays_local_until_first_use() {
        let ptx = b".version 7.0\n.entry lazy_test() { ret; }\0";
        let wrapper = FatBinWrapper {
            magic: 0x4662_43b1_u32 as c_int,
            version: 1,
            data: ptx.as_ptr().cast(),
            filename_or_fatbins: std::ptr::null(),
        };
        let handle = __cudaRegisterFatBinary((&wrapper as *const FatBinWrapper).cast_mut().cast());
        let host_stub = std::ptr::dangling::<c_char>();
        __cudaRegisterFunction(
            handle,
            host_stub,
            std::ptr::null_mut(),
            c"lazy_test".as_ptr(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );

        assert!(STATIC_MODULES
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|modules| modules.contains_key(&(handle as usize))));
        assert!(STATIC_FUNCS
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|funcs| funcs.contains_key(&(host_stub as usize))));
        assert!(STATE.lock().unwrap().is_none());

        __cudaUnregisterFatBinary(handle);
        assert!(!STATIC_MODULES
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|modules| modules.contains_key(&(handle as usize))));
        assert!(!STATIC_FUNCS
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|funcs| funcs.contains_key(&(host_stub as usize))));
    }

    #[test]
    fn unsupported_graph_builders_clear_outputs() {
        let mut node = std::ptr::dangling_mut::<c_void>();
        assert_eq!(
            cudaGraphAddEmptyNode(&mut node, std::ptr::null_mut(), std::ptr::null(), 0),
            CUDA_ERROR_NOT_SUPPORTED
        );
        assert!(node.is_null());

        let mut node_type = 123;
        assert_eq!(
            cudaGraphNodeGetType(std::ptr::null_mut(), &mut node_type),
            CUDA_ERROR_NOT_SUPPORTED
        );
        assert_eq!(node_type, 0);

        let mut generic_node = std::ptr::dangling_mut::<c_void>();
        assert_eq!(
            cudaGraphAddNode(
                &mut generic_node,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
            ),
            CUDA_ERROR_NOT_SUPPORTED
        );
        assert!(generic_node.is_null());

        let mut clusters = 99;
        assert_eq!(
            cudaOccupancyMaxActiveClusters(
                &mut clusters,
                std::ptr::dangling(),
                std::ptr::dangling(),
            ),
            CUDA_ERROR_NOT_SUPPORTED
        );
        assert_eq!(clusters, 0);
    }

    #[test]
    fn library_options_fail_without_connecting() {
        let mut library = std::ptr::dangling_mut::<c_void>();
        let code = b".version 7.0\0";
        assert_eq!(
            cudaLibraryLoadData(
                &mut library,
                code.as_ptr().cast(),
                std::ptr::null(),
                std::ptr::null_mut(),
                1,
                std::ptr::null(),
                std::ptr::null_mut(),
                0,
            ),
            CUDA_ERROR_NOT_SUPPORTED
        );
        assert!(library.is_null());
    }

    #[test]
    fn pci_bus_lookup_rejects_invalid_pointers_without_connecting() {
        let mut device = -1;
        assert_eq!(
            cudaDeviceGetByPCIBusId(&mut device, std::ptr::null()),
            CUDA_ERROR_INVALID_VALUE
        );
        assert_eq!(
            cudaDeviceGetByPCIBusId(std::ptr::null_mut(), c"0000:01:00.0".as_ptr()),
            CUDA_ERROR_INVALID_VALUE
        );
    }

    #[test]
    fn runtime_lookup_does_not_advertise_cross_process_vmm() {
        assert!(!driver_entrypoint_supported(c"cuMemCreate"));
        assert!(driver_entrypoint_supported(c"cuMemAlloc_v2"));
    }
}
