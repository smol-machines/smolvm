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
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
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
    /// Live device allocations, to classify pointers for cudaMemcpyDefault.
    dev_allocs: HashSet<u64>,
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
            _ => CUDA_ERROR_UNKNOWN,
        },
        CudaRpcError::Io(_) | CudaRpcError::Protocol(_) => CUDA_ERROR_UNKNOWN,
    }
}

/// Lazily connect and bring up a primary context, then run `f` against the
/// client. The first call performs `cuInit` + `cuDevicePrimaryCtxRetain(0)`
/// (which the host binds current on its serving thread), matching how the CUDA
/// runtime brings up its device on first use.
fn with_client<T>(
    f: impl FnOnce(&mut Client<Stream>) -> Result<T, CudaRpcError>,
) -> Result<T, c_int> {
    let mut guard = STATE.lock().map_err(|_| CUDA_ERROR_UNKNOWN)?;
    if guard.is_none() {
        let stream = connect()?;
        let mut client = Client::new(stream);
        client.init().map_err(|_| CUDA_ERROR_INITIALIZATION)?;
        let _ = client
            .primary_ctx_retain(0)
            .map_err(|_| CUDA_ERROR_INITIALIZATION)?;
        *guard = Some(ShimState {
            client,
            initialized: true,
            modules: HashMap::new(),
            funcs: HashMap::new(),
            host_allocs: HashMap::new(),
            dev_allocs: HashSet::new(),
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
    set_last(match with_client(|c| c.driver_get_version()) {
        Ok(v) => unsafe { out(version, v) },
        Err(e) => e,
    })
}

#[no_mangle]
pub extern "C" fn cudaRuntimeGetVersion(version: *mut c_int) -> c_int {
    set_last(unsafe { out(version, 11080) })
}

// ---- memory -----------------------------------------------------------------

#[no_mangle]
pub extern "C" fn cudaMalloc(dev_ptr: *mut *mut c_void, size: usize) -> c_int {
    set_last(
        match with_state(|s| {
            let d = s.client.mem_alloc(size as u64).map_err(map_err)?;
            s.dev_allocs.insert(d);
            Ok(d)
        }) {
            Ok(d) => unsafe { out(dev_ptr, d as *mut c_void) },
            Err(e) => e,
        },
    )
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

/// Bump-allocate `size` bytes (16-aligned) from the shared region.
#[allow(clippy::needless_return)] // `return` is load-bearing across the cfg arms
fn shm_alloc(size: usize) -> Option<*mut u8> {
    #[cfg(target_os = "linux")]
    {
        let r = shm_region()?;
        let sz = (size as u64 + 15) & !15;
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
    let layout = match std::alloc::Layout::from_size_align(size, 16) {
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
    let dst_dev = s.dev_allocs.contains(&(dst as u64));
    let src_dev = s.dev_allocs.contains(&(src as u64));
    match (src_dev, dst_dev) {
        (false, true) => MEMCPY_HTOD,
        (true, false) => MEMCPY_DTOH,
        (true, true) => MEMCPY_DTOD,
        (false, false) => MEMCPY_HTOH,
    }
}

fn do_memcpy(dst: *mut c_void, src: *const c_void, n: usize, kind: c_int) -> c_int {
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
                    if s.client.memcpy_gpa_htod(dst as u64, segs).is_ok() {
                        return Ok(());
                    }
                }
                // Zero-copy from the same-host shared region: ship the offset.
                if let Some(off) = shm_offset(src) {
                    return s
                        .client
                        .memcpy_shm_htod(dst as u64, off, n as u64)
                        .map_err(map_err);
                }
                let data = unsafe { std::slice::from_raw_parts(src as *const u8, n) };
                s.client.memcpy_htod(dst as u64, data).map_err(map_err)
            }
            MEMCPY_DTOH => {
                if let Some(segs) = guestmem::segments(dst as usize, n) {
                    if s.client.memcpy_gpa_dtoh(src as u64, segs).is_ok() {
                        return Ok(());
                    }
                }
                if let Some(off) = shm_offset(dst) {
                    // Host writes straight into the shared region at `off`.
                    return s
                        .client
                        .memcpy_shm_dtoh(off, src as u64, n as u64)
                        .map_err(map_err);
                }
                let data = s
                    .client
                    .memcpy_dtoh(src as u64, n as u64)
                    .map_err(map_err)?;
                if data.len() != n {
                    return Err(CUDA_ERROR_UNKNOWN);
                }
                unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), dst as *mut u8, n) };
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
    set_last(do_memcpy(dst, src, n, kind))
}

#[no_mangle]
pub extern "C" fn cudaMemcpyAsync(
    dst: *mut c_void,
    src: *const c_void,
    n: usize,
    kind: c_int,
    _stream: *mut c_void,
) -> c_int {
    // Executed synchronously; ordering within a stream is preserved because all
    // work runs on the host's single serving thread in call order.
    set_last(do_memcpy(dst, src, n, kind))
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
    _stream: *mut c_void,
) -> c_int {
    cudaMemset(dev_ptr, value, count)
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
    set_last(
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
                .launch_kernel(
                    fid,
                    [grid.x, grid.y, grid.z],
                    [block.x, block.y, block.z],
                    shared_mem as u32,
                    stream as u64,
                    &params,
                )
                .map_err(map_err)
        })
        .err()
        .unwrap_or(CUDA_SUCCESS),
    )
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
    LAST_ERROR.with(|e| {
        let v = e.get();
        e.set(CUDA_SUCCESS);
        v
    })
}

#[no_mangle]
pub extern "C" fn cudaPeekAtLastError() -> c_int {
    LAST_ERROR.with(|e| e.get())
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
