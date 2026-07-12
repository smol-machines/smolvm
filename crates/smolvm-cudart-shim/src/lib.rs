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
mod cublas_stubs;
use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{c_char, c_int, c_uint, c_void, CStr, CString};
use std::io::{Read, Write};
use std::sync::Mutex;

// ---- cudaError_t codes we produce locally -----------------------------------

const CUDA_SUCCESS: c_int = 0;
const CUDA_ERROR_INVALID_VALUE: c_int = 1;
const CUDA_ERROR_MEMORY_ALLOCATION: c_int = 2;
const CUDA_ERROR_INITIALIZATION: c_int = 3;
const CUDA_ERROR_INVALID_DEVICE_POINTER: c_int = 17;
const CUDA_ERROR_INVALID_RESOURCE_HANDLE: c_int = 400;
const CUDA_ERROR_NO_DEVICE: c_int = 100;
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

struct ShimState {
    client: Client<Stream>,
    initialized: bool,
    /// `__cudaRegisterFatBinary` handle (the pointer we minted) → driver module id.
    modules: HashMap<usize, u64>,
    /// `__cudaRegisterFunction` host stub pointer → resolved kernel.
    funcs: HashMap<usize, FuncRec>,
    /// Host pinned-memory allocations (guest RAM) → layout, for cudaFreeHost.
    host_allocs: HashMap<usize, std::alloc::Layout>,
    /// Live device allocations, base → size. Range-queried (not exact-match):
    /// PyTorch's caching allocator suballocates, so tensor data pointers are
    /// interior to a cudaMalloc'd block — `cudaPointerGetAttributes` on one
    /// must still report Device or torch's `getDeviceFromPtr` throws.
    dev_allocs: std::collections::BTreeMap<u64, u64>,
    /// Active CUDA graph capture, `(stream_handle, capture_id)`. Kept
    /// guest-side so the per-launch hot queries (`cudaStreamIsCapturing`,
    /// `cudaStreamGetCaptureInfo` — PyTorch's allocator calls them constantly)
    /// answer locally instead of round-tripping.
    capture: Option<(u64, u64)>,
}

static STATE: Mutex<Option<ShimState>> = Mutex::new(None);

thread_local! {
    /// `__cudaPushCallConfiguration` stash, popped by `__cudaPopCallConfiguration`.
    static CALL_CONFIG: RefCell<Vec<(Dim3, Dim3, usize, u64)>> = const { RefCell::new(Vec::new()) };
    /// Last error, for cudaGetLastError / cudaPeekAtLastError.
    static LAST_ERROR: std::cell::Cell<c_int> = const { std::cell::Cell::new(CUDA_SUCCESS) };
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
            CUDA_ERROR_UNKNOWN
        }
    }
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

// ---- driver-shim bridge -------------------------------------------------------
// The driver shim (`libcuda.so.1`) dlsym-resolves these three and routes ALL
// its traffic through this connection, giving the host one program-ordered
// pipeline for both shims (see smolvm-cuda's `client::Bridge`). Op statuses
// stay in-band in the response payload — nothing is lost to error mapping.

/// A response too large for the caller's buffer, parked until the caller
/// retries with a big-enough one (null request = fetch).
static BRIDGE_PENDING: Mutex<Option<Vec<u8>>> = Mutex::new(None);

/// Fire-and-forget: append one encoded request to the shared pipeline.
/// Nonzero = transport failure.
#[no_mangle]
pub extern "C" fn smolvm_cudart_bridge_quiet(req: *const u8, len: usize) -> i32 {
    if req.is_null() {
        return 1;
    }
    let bytes = unsafe { std::slice::from_raw_parts(req, len) };
    match with_client(|c| c.raw_quiet(bytes)) {
        Ok(()) => 0,
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
        match with_client(|c| c.raw_call(bytes)) {
            Ok(p) => p,
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
    let segs = guestmem::segments(base, pages * PAGE)?;
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

fn with_client<T>(
    f: impl FnOnce(&mut Client<Stream>) -> Result<T, CudaRpcError>,
) -> Result<T, c_int> {
    let mut guard = STATE.lock().map_err(|_| CUDA_ERROR_UNKNOWN)?;
    if guard.is_none() {
        let stream = connect()?;
        #[cfg(target_os = "linux")]
        let try_ring = matches!(stream, Stream::Vsock(_))
            && std::env::var("SMOLVM_CUDA_RING").as_deref() != Ok("0");
        #[cfg(not(target_os = "linux"))]
        let try_ring = false;
        let mut client = Client::new(stream);
        client.init().map_err(|_| CUDA_ERROR_INITIALIZATION)?;
        let _ = client
            .primary_ctx_retain(0)
            .map_err(|_| CUDA_ERROR_INITIALIZATION)?;
        if try_ring {
            ring_try_setup(&mut client); // best-effort; socket mode on failure
        }
        *guard = Some(ShimState {
            client,
            initialized: true,
            modules: HashMap::new(),
            funcs: HashMap::new(),
            host_allocs: HashMap::new(),
            dev_allocs: std::collections::BTreeMap::new(),
            capture: None,
        });
    }
    let st = guard.as_mut().ok_or(CUDA_ERROR_INITIALIZATION)?;
    debug_assert!(st.initialized);
    // SAFETY-free: split the borrow so `f` gets the client while we keep the lock.
    let client = &mut st.client;
    f(client).map_err(map_err)
}

/// Run `f` with the full state (client + registries) under the lock.
fn with_state<T>(f: impl FnOnce(&mut ShimState) -> Result<T, c_int>) -> Result<T, c_int> {
    // Ensure init first (reuses with_client's bring-up), then re-lock.
    with_client(|_| Ok(()))?;
    let mut guard = STATE.lock().map_err(|_| CUDA_ERROR_UNKNOWN)?;
    let st = guard.as_mut().ok_or(CUDA_ERROR_INITIALIZATION)?;
    f(st)
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
    set_last(match with_client(|c| c.device_get_count()) {
        Ok(n) => unsafe { out(count, n) },
        Err(e) => {
            // A CUDA program treats "0 devices" as recoverable; surface the count.
            unsafe { out(count, 0) };
            e
        }
    })
}

#[no_mangle]
pub extern "C" fn cudaSetDevice(device: c_int) -> c_int {
    // Single-device model: only device 0 exists.
    set_last(if device == 0 {
        CUDA_SUCCESS
    } else {
        CUDA_ERROR_INVALID_VALUE
    })
}

#[no_mangle]
pub extern "C" fn cudaGetDevice(device: *mut c_int) -> c_int {
    set_last(unsafe { out(device, 0) })
}

#[no_mangle]
pub extern "C" fn cudaDeviceSynchronize() -> c_int {
    set_last(match with_client(|c| c.ctx_synchronize()) {
        Ok(()) => CUDA_SUCCESS,
        Err(e) => e,
    })
}

#[no_mangle]
pub extern "C" fn cudaDriverGetVersion(version: *mut c_int) -> c_int {
    static CACHED: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);
    let c = CACHED.load(std::sync::atomic::Ordering::Relaxed);
    if c != 0 {
        return set_last(unsafe { out(version, c) });
    }
    set_last(match with_client(|c| c.driver_get_version()) {
        Ok(v) => {
            CACHED.store(v, std::sync::atomic::Ordering::Relaxed);
            unsafe { out(version, v) }
        }
        Err(e) => e,
    })
}

#[no_mangle]
pub extern "C" fn cudaRuntimeGetVersion(version: *mut c_int) -> c_int {
    set_last(unsafe { out(version, 12040) })
}

// ---- memory -----------------------------------------------------------------

#[no_mangle]
pub extern "C" fn cudaMalloc(dev_ptr: *mut *mut c_void, size: usize) -> c_int {
    set_last(
        match with_state(|s| {
            let d = s.client.mem_alloc(size as u64).map_err(map_err)?;
            s.dev_allocs.insert(d, size as u64);
            Ok(d)
        }) {
            Ok(d) => unsafe { out(dev_ptr, d as *mut c_void) },
            Err(e) => e,
        },
    )
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
fn dev_contains(allocs: &std::collections::BTreeMap<u64, u64>, p: u64) -> bool {
    allocs
        .range(..=p)
        .next_back()
        .is_some_and(|(base, size)| p < base + size)
}

#[no_mangle]
pub extern "C" fn cudaFree(dev_ptr: *mut c_void) -> c_int {
    if dev_ptr.is_null() {
        return set_last(CUDA_SUCCESS); // cudaFree(NULL) is a no-op
    }
    set_last(
        match with_state(|s| {
            s.client.mem_free(dev_ptr as u64).map_err(map_err)?;
            s.dev_allocs.remove(&(dev_ptr as u64));
            Ok(())
        }) {
            Ok(()) => CUDA_SUCCESS,
            Err(e) => e,
        },
    )
}

#[no_mangle]
pub extern "C" fn cudaHostAlloc(ptr: *mut *mut c_void, size: usize, _flags: c_uint) -> c_int {
    cuda_host_malloc(ptr, size.max(1))
}

#[no_mangle]
pub extern "C" fn cudaMallocHost(ptr: *mut *mut c_void, size: usize) -> c_int {
    cuda_host_malloc(ptr, size.max(1))
}

// ---- shared-memory zero-copy staging ----------------------------------------
// When SMOLVM_CUDA_SHM is set, `cudaMallocHost`/`cudaHostAlloc` bump-allocate
// from a region the host also maps, so a memcpy on that buffer ships only an
// offset (see do_memcpy). Falls back to plain host memory when the region is
// absent or exhausted.

use std::sync::atomic::{AtomicU64, Ordering};

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

    /// Coalesced `(gpa, len)` segments for `[ptr, ptr+len)` if it lies wholly in
    /// a pinned buffer.
    pub fn segments(ptr: usize, len: usize) -> Option<Vec<(u64, u64)>> {
        if len == 0 {
            return None;
        }
        let reg = PINNED.lock().unwrap();
        let buf = reg
            .iter()
            .find(|b| ptr >= b.base && ptr + len <= b.base + b.size)?;
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
        Some(segs)
    }

    pub fn is_pinned(ptr: usize) -> bool {
        let reg = PINNED.lock().unwrap();
        reg.iter().any(|b| ptr >= b.base && ptr < b.base + b.size)
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
    pub fn segments(_: usize, _: usize) -> Option<Vec<(u64, u64)>> {
        None
    }
    pub fn is_pinned(_: usize) -> bool {
        false
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

fn cuda_host_malloc(ptr: *mut *mut c_void, size: usize) -> c_int {
    // Zero-copy backings, in order of preference: guest-RAM (microVM) then the
    // same-host shared region. Either lets a memcpy skip shipping the bytes.
    if let Some(mem) = guestmem::alloc(size) {
        return set_last(unsafe { out(ptr, mem as *mut c_void) });
    }
    if let Some(mem) = shm_alloc(size) {
        return set_last(unsafe { out(ptr, mem as *mut c_void) });
    }
    let layout = match std::alloc::Layout::from_size_align(size, 256) {
        Ok(l) => l,
        Err(_) => return set_last(CUDA_ERROR_INVALID_VALUE),
    };
    let mem = unsafe { std::alloc::alloc(layout) };
    if mem.is_null() {
        return set_last(CUDA_ERROR_MEMORY_ALLOCATION);
    }
    set_last(
        match with_state(|s| {
            s.host_allocs.insert(mem as usize, layout);
            Ok(())
        }) {
            Ok(()) => unsafe { out(ptr, mem as *mut c_void) },
            Err(e) => {
                unsafe { std::alloc::dealloc(mem, layout) };
                e
            }
        },
    )
}

#[no_mangle]
pub extern "C" fn cudaFreeHost(ptr: *mut c_void) -> c_int {
    if ptr.is_null() {
        return set_last(CUDA_SUCCESS);
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

/// Resolve `cudaMemcpyDefault` to a concrete direction from tracked allocations.
fn resolve_kind(s: &ShimState, dst: *const c_void, src: *const c_void, kind: c_int) -> c_int {
    if kind != MEMCPY_DEFAULT {
        return kind;
    }
    let dst_dev = dev_contains(&s.dev_allocs, dst as u64);
    let src_dev = dev_contains(&s.dev_allocs, src as u64);
    match (src_dev, dst_dev) {
        (false, true) => MEMCPY_HTOD,
        (true, false) => MEMCPY_DTOH,
        (true, true) => MEMCPY_DTOD,
        (false, false) => MEMCPY_HTOH,
    }
}

fn do_memcpy(dst: *mut c_void, src: *const c_void, n: usize, kind: c_int, stream: u64) -> c_int {
    let dbg = std::env::var_os("SMOLVM_CUDA_TRACE_MEMCPY").is_some();
    let r = do_memcpy_inner(dst, src, n, kind, stream);
    if dbg && r != CUDA_SUCCESS {
        eprintln!("[memcpy-err] kind={kind} n={n} -> {r}");
    }
    r
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
                if let Some(segs) = guestmem::segments(src as usize, n) {
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
                let data = unsafe { std::slice::from_raw_parts(src as *const u8, n) };
                const CHUNK: usize = 64 * 1024 * 1024;
                for (i, piece) in data.chunks(CHUNK).enumerate() {
                    s.client
                        .memcpy_htod(dst as u64 + (i * CHUNK) as u64, piece, stream)
                        .map_err(map_err)?;
                }
                Ok(())
            }
            MEMCPY_DTOH => {
                if let Some(segs) = guestmem::segments(dst as usize, n) {
                    if s.client.memcpy_gpa_dtoh(src as u64, segs, stream).is_ok() {
                        return Ok(());
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
    set_last(do_memcpy(dst, src, n, kind, 0))
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
    set_last(do_memcpy(dst, src, n, kind, stream as u64))
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
    set_last(match with_client(|c| c.stream_create(0)) {
        Ok(h) => unsafe { out(stream, h as *mut c_void) },
        Err(e) => e,
    })
}

#[no_mangle]
pub extern "C" fn cudaStreamCreateWithFlags(stream: *mut *mut c_void, flags: c_uint) -> c_int {
    set_last(match with_client(|c| c.stream_create(flags)) {
        Ok(h) => unsafe { out(stream, h as *mut c_void) },
        Err(e) => e,
    })
}

#[no_mangle]
pub extern "C" fn cudaStreamDestroy(stream: *mut c_void) -> c_int {
    if stream.is_null() {
        return set_last(CUDA_SUCCESS); // destroying the default stream is a no-op
    }
    set_last(match with_client(|c| c.stream_destroy(stream as u64)) {
        Ok(()) => CUDA_SUCCESS,
        Err(e) => e,
    })
}

#[no_mangle]
pub extern "C" fn cudaStreamSynchronize(stream: *mut c_void) -> c_int {
    set_last(match with_client(|c| c.stream_synchronize(stream as u64)) {
        Ok(()) => CUDA_SUCCESS,
        Err(e) => e,
    })
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
    let rc = with_client(|c| c.stream_synchronize(stream as u64));
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
    set_last(match with_client(|c| c.mem_get_info()) {
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

/// Whole-graph exec update: report "update failed" — ggml (and torch) fall
/// back to destroying and re-instantiating the graph, which we forward.
#[no_mangle]
pub extern "C" fn cudaGraphExecUpdate(
    _exec: *mut c_void,
    _graph: *mut c_void,
    result_info: *mut c_void,
) -> c_int {
    if !result_info.is_null() {
        // cudaGraphExecUpdateResultInfo { result, errorNode, errorFromNode }
        unsafe { std::ptr::write_bytes(result_info as *mut u8, 0, 24) };
    }
    910 // cudaErrorGraphExecUpdateFailure
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

#[no_mangle]
pub extern "C" fn cudaEventCreate(event: *mut *mut c_void) -> c_int {
    set_last(match with_client(|c| c.event_create(0)) {
        Ok(h) => unsafe { out(event, h as *mut c_void) },
        Err(e) => e,
    })
}
#[no_mangle]
pub extern "C" fn cudaEventCreateWithFlags(event: *mut *mut c_void, flags: c_uint) -> c_int {
    set_last(match with_client(|c| c.event_create(flags)) {
        Ok(h) => unsafe { out(event, h as *mut c_void) },
        Err(e) => e,
    })
}
#[no_mangle]
pub extern "C" fn cudaEventDestroy(event: *mut c_void) -> c_int {
    set_last(match with_client(|c| c.event_destroy(event as u64)) {
        Ok(()) => CUDA_SUCCESS,
        Err(e) => e,
    })
}
#[no_mangle]
pub extern "C" fn cudaEventRecord(event: *mut c_void, stream: *mut c_void) -> c_int {
    set_last(
        match with_client(|c| c.event_record(event as u64, stream as u64)) {
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
    set_last(match with_client(|c| c.event_synchronize(event as u64)) {
        Ok(()) => CUDA_SUCCESS,
        Err(e) => e,
    })
}
#[no_mangle]
pub extern "C" fn cudaEventQuery(event: *mut c_void) -> c_int {
    // Must be honest: PyTorch's allocator polls this to decide when freed
    // blocks are safe to reuse. Always answering "complete" caused premature
    // reuse (ILLEGAL_ADDRESS) once work really ran on side streams. NotReady
    // (600) latches into last-error exactly like real cudart; torch clears it.
    set_last(match with_client(|c| c.event_query(event as u64)) {
        Ok(code) => code,
        Err(e) => e,
    })
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
    set_last(match with_client(|c| c.stream_create(flags)) {
        Ok(h) => unsafe { out(stream, h as *mut c_void) },
        Err(e) => e,
    })
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
        match with_client(|c| c.stream_wait_event(stream as u64, event as u64, flags)) {
            Ok(()) => CUDA_SUCCESS,
            Err(e) => e,
        },
    )
}
#[no_mangle]
pub extern "C" fn cudaStreamQuery(stream: *mut c_void) -> c_int {
    // Honest completion status (0 or 600-NotReady), same as cudaEventQuery.
    set_last(match with_client(|c| c.stream_query(stream as u64)) {
        Ok(code) => code,
        Err(e) => e,
    })
}
// ---- CUDA graphs -------------------------------------------------------------
// Capture happens on the HOST driver: Begin/End forward, and every launch /
// stream-ordered op issued in between lands on the capturing host stream and is
// recorded (not executed) by the real driver. Replay is a single GraphLaunch
// message for the whole graph — the antidote to per-launch round-trips in
// launch-bound inference. The hot capture-status queries answer from the
// guest-side `capture` field, costing nothing outside capture.

/// cudaStreamCaptureStatusActive.
const CAPTURE_ACTIVE: c_int = 1;

#[no_mangle]
pub extern "C" fn cudaStreamBeginCapture(stream: *mut c_void, mode: c_int) -> c_int {
    set_last(
        match with_state(|s| {
            s.client
                .stream_begin_capture(stream as u64, mode)
                .map_err(map_err)?;
            // The capture id is torch-visible only (its allocator correlates
            // capture state through the local GetCaptureInfo queries); the
            // host tracks capture by stream, not id. So mint it locally
            // instead of round-tripping cuStreamGetCaptureInfo — that saved
            // one host RTT per captured graph (vLLM captures ~1400, dominating
            // coldstart over a network).
            static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
            let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            s.capture = Some((stream as u64, id));
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
    set_last(
        match with_state(|s| {
            let g = s
                .client
                .stream_end_capture(stream as u64)
                .map_err(map_err)?;
            s.capture = None;
            Ok(g)
        }) {
            Ok(g) => unsafe { out(graph, g as *mut c_void) },
            Err(e) => {
                let _ = with_state(|s| {
                    s.capture = None;
                    Ok(())
                });
                e
            }
        },
    )
}

#[no_mangle]
pub extern "C" fn cudaStreamIsCapturing(stream: *mut c_void, status: *mut c_int) -> c_int {
    let active = with_state(|s| Ok(matches!(s.capture, Some((cs, _)) if cs == stream as u64)))
        .unwrap_or(false);
    set_last(unsafe { out(status, if active { CAPTURE_ACTIVE } else { 0 }) })
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
    let cap = with_state(|s| Ok(s.capture)).unwrap_or(None);
    let (st, cid) = match cap {
        Some((cs, cid)) if cs == stream as u64 => (CAPTURE_ACTIVE, cid),
        _ => (0, 0),
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
    set_last(match with_client(|c| c.graph_instantiate(graph as u64)) {
        Ok(e) => unsafe { out(graph_exec, e as *mut c_void) },
        Err(e) => e,
    })
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
    _graph: *mut c_void,
    nodes: *mut *mut c_void,
    num_nodes: *mut usize,
) -> c_int {
    if num_nodes.is_null() {
        return set_last(CUDA_ERROR_INVALID_VALUE);
    }
    // The real node list is never requested (nodes != NULL is rejected below);
    // torch calls this only with nodes = NULL to check for an EMPTY graph and
    // warn. A captured decode graph is never empty, so answer the count query
    // locally with a non-zero value instead of a host round-trip — fetching
    // the true count cost one RTT per captured graph (~1400), dominating
    // coldstart over a network. (This can only suppress a cosmetic empty-graph
    // warning, never cause wrong behavior — unlike the fake-data stubs that
    // were replaced with real values.)
    if !nodes.is_null() {
        return set_last(CUDA_ERROR_INVALID_VALUE);
    }
    set_last(unsafe { out(num_nodes, 1usize) })
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
    set_last(match with_client(|c| c.graph_destroy(graph as u64)) {
        Ok(()) => CUDA_SUCCESS,
        Err(e) => e,
    })
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
    if let Err(e) = with_client(|c| c.stream_synchronize(stream as u64)) {
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
    let is_dev = with_state(|s| Ok(dev_contains(&s.dev_allocs, ptr as u64))).unwrap_or(false);
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
    a.device = 0;
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
    static FUNC_ATTRS: Mutex<Option<HashMap<usize, [u8; 72]>>> = Mutex::new(None);
    if let Ok(mut g) = FUNC_ATTRS.lock() {
        if let Some(blob) = g.get_or_insert_with(HashMap::new).get(&(func as usize)) {
            unsafe { std::ptr::copy_nonoverlapping(blob.as_ptr(), attr as *mut u8, 72) };
            return set_last(CUDA_SUCCESS);
        }
    }
    // CUfunction_attribute: MAX_THREADS_PER_BLOCK=0, SHARED=1, CONST=2,
    // LOCAL=3, NUM_REGS=4, PTX_VERSION=5, BINARY_VERSION=6.
    let r = with_state(|s| {
        let fid = s
            .funcs
            .get(&(func as usize))
            .ok_or(CUDA_ERROR_INVALID_DEVICE_POINTER)?
            .fid;
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
                .insert(func as usize, blob);
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
    static APPLIED: Mutex<Option<HashMap<(usize, c_int), c_int>>> = Mutex::new(None);
    if APPLIED
        .lock()
        .unwrap()
        .get_or_insert_with(HashMap::new)
        .get(&(func as usize, attr))
        == Some(&value)
    {
        return CUDA_SUCCESS;
    }
    let r = with_state(|s| {
        let fid = s
            .funcs
            .get(&(func as usize))
            .ok_or(CUDA_ERROR_INVALID_DEVICE_POINTER)?
            .fid;
        s.client
            .func_set_attribute(fid, attr, value)
            .map_err(map_err)
    });
    if r.is_ok() {
        APPLIED
            .lock()
            .unwrap()
            .get_or_insert_with(HashMap::new)
            .insert((func as usize, attr), value);
    }
    set_last(r.err().unwrap_or(CUDA_SUCCESS))
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
    // Unified-addressing convention: device VA == host VA. Correct for the
    // memcpy path (the host recognizes guest-RAM addresses and DMAs them).
    // KNOWN LIMITATION: a mapped host pointer passed as a KERNEL ARG can't be
    // dereferenced by the host GPU (a guest VA isn't device-addressable) — that
    // needs true unified memory we don't have. No validated workload does this;
    // those that would should use explicit cudaMemcpy instead.
    set_last(unsafe { out(p_device, host) })
}
#[no_mangle]
pub extern "C" fn cudaDeviceCanAccessPeer(can: *mut c_int, _device: c_int, _peer: c_int) -> c_int {
    set_last(unsafe { out(can, 0) }) // single device
}
#[no_mangle]
pub extern "C" fn cudaDeviceEnablePeerAccess(_peer: c_int, _flags: c_uint) -> c_int {
    set_last(CUDA_SUCCESS)
}
#[no_mangle]
pub extern "C" fn cudaDeviceGetPCIBusId(buf: *mut c_char, len: c_int, _device: c_int) -> c_int {
    let id = b"0000:01:00.0\0";
    if !buf.is_null() && len > 0 {
        let n = (len as usize - 1).min(id.len() - 1);
        unsafe { std::ptr::copy_nonoverlapping(id.as_ptr() as *const c_char, buf, n) };
        unsafe { *buf.add(n) = 0 };
    }
    set_last(CUDA_SUCCESS)
}

// ---- kernel registration + launch -------------------------------------------

/// `__fatBinC_Wrapper_t`: what `__cudaRegisterFatBinary` receives. `data` points
/// at the fatbin container (its own header carries the length).
#[repr(C)]
struct FatBinWrapper {
    magic: c_int,
    version: c_int,
    data: *const c_void,
    filename_or_fatbins: *const c_void,
}

/// Length of a fatbin container from its header (magic `0xBA55ED50`,
/// u16 version, u16 headerSize, u64 fatSize).
unsafe fn fatbin_len(data: *const c_void) -> Option<usize> {
    if data.is_null() {
        return None;
    }
    let p = data as *const u8;
    let magic = u32::from_le_bytes(unsafe { *(p as *const [u8; 4]) });
    if magic != 0xBA55_ED50 {
        return None;
    }
    let header_size = u16::from_le_bytes(unsafe { *(p.add(6) as *const [u8; 2]) }) as usize;
    let fat_size = u64::from_le_bytes(unsafe { *(p.add(8) as *const [u8; 8]) }) as usize;
    Some(header_size + fat_size)
}

#[no_mangle]
pub extern "C" fn __cudaRegisterFatBinary(fat_cubin: *mut c_void) -> *mut *mut c_void {
    // Mint a stable handle the app hands back to Register/Unregister; map it to
    // the driver module we load from the embedded fatbin.
    let handle = Box::into_raw(Box::new(0u8)) as *mut *mut c_void;
    if fat_cubin.is_null() {
        return handle;
    }
    let wrapper = fat_cubin as *const FatBinWrapper;
    let data = unsafe { (*wrapper).data };
    let Some(len) = (unsafe { fatbin_len(data) }) else {
        return handle;
    };
    let blob = unsafe { std::slice::from_raw_parts(data as *const u8, len) }.to_vec();
    let _ = with_state(|s| {
        match s.client.module_load_data(&blob) {
            Ok(module) => {
                s.modules.insert(handle as usize, module);
            }
            Err(e) => return Err(map_err(e)),
        }
        Ok(())
    });
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
    let _ = with_state(|s| {
        let module = *s
            .modules
            .get(&(fat_cubin_handle as usize))
            .ok_or(CUDA_ERROR_INVALID_RESOURCE_HANDLE)?;
        let cname = CString::new(name.clone()).map_err(|_| CUDA_ERROR_INVALID_VALUE)?;
        let fid = s
            .client
            .module_get_function(module, cname.to_str().unwrap())
            .map_err(map_err)?;
        let param_sizes = s.client.func_get_param_info(fid).map_err(map_err)?;
        s.funcs
            .insert(host_fun as usize, FuncRec { fid, param_sizes });
        Ok(())
    });
}

#[no_mangle]
pub extern "C" fn __cudaUnregisterFatBinary(handle: *mut *mut c_void) {
    let _ = with_state(|s| {
        if let Some(module) = s.modules.remove(&(handle as usize)) {
            let _ = s.client.module_unload(module);
        }
        Ok(())
    });
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
    set_last(do_launch(
        func,
        [grid.x, grid.y, grid.z],
        [block.x, block.y, block.z],
        shared_mem,
        stream as u64,
        args,
    ))
}

/// Shared launch path for both `cudaLaunchKernel` and `cudaLaunchKernelExC`:
/// look up the registered function, gather its argument blobs, forward.
fn do_launch(
    func: *const c_void,
    grid: [u32; 3],
    block: [u32; 3],
    shared_mem: usize,
    stream: u64,
    args: *mut *mut c_void,
) -> c_int {
    // Debug bisection: drop launches entirely to isolate marshaling cost.
    if std::env::var_os("SMOLVM_CUDA_NOOP_LAUNCH").is_some() {
        return CUDA_SUCCESS;
    }
    with_state(|s| {
        let rec = s
            .funcs
            .get(&(func as usize))
            .ok_or(CUDA_ERROR_INVALID_DEVICE_POINTER)?;
        let fid = rec.fid;
        let sizes = rec.param_sizes.clone();
        // Reconstruct one byte-blob per kernel argument from `args[i]`.
        let params: Vec<Vec<u8>> = if sizes.is_empty() {
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
    set_last(do_launch(
        func,
        [c.grid_dim.x, c.grid_dim.y, c.grid_dim.z],
        [c.block_dim.x, c.block_dim.y, c.block_dim.z],
        c.dynamic_smem_bytes,
        c.stream as u64,
        args,
    ))
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
    use super::{c_int, c_void, with_client};
    include!("generated/cublas_guest.rs");
}

/// Code-generated cuDNN forwarding stubs. Regenerate with `smolvm-cuda-codegen`.
mod gen_cudnn {
    #![allow(non_snake_case, clippy::unnecessary_cast, unused_mut, dead_code)]
    use super::{c_int, c_void, with_client};
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
    match with_client(|c| c.lib_call(LIB_CUDNN_BACKEND, 3, a)) {
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
    match with_client(|c| c.lib_call(LIB_CUDNN_BACKEND, 4, a)) {
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
    match with_client(|c| c.lib_call(LIB_CUBLASLT, 11, Vec::new())) {
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
    match with_client(|c| c.lib_call(LIB_CUBLASLT, 12, a)) {
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
    match with_client(|c| c.lib_call(LIB_CUBLASLT, 9, a)) {
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
    for chunk in args[16..].chunks_exact(8) {
        let h = u64::from_le_bytes(chunk.try_into().unwrap());
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
    match with_client(|c| c.lib_call(LIB_CUDNN_BN, func, args)) {
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
