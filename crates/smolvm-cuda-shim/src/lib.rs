//! Drop-in `libcuda.so.1` for smolvm guests: the CUDA Driver API C ABI,
//! implemented by marshaling every call over smolvm's CUDA RPC to the host.
//!
//! Install this library at `/usr/lib/libcuda.so.1` inside a guest (or point
//! `LD_LIBRARY_PATH` at it) and unmodified Driver-API programs — including the
//! CUDA runtime's dlopen of the driver — run their GPU work on the host GPU
//! with no code changes.
//!
//! Transport is chosen by `SMOLVM_CUDA_RPC`:
//!   * unset / `vsock` — AF_VSOCK to host CID 2, port 7000 (production, in-guest)
//!   * `tcp:HOST:PORT` — TCP (host-side testing against a loopback server)
//!   * `unix:/path`    — AF_UNIX (host-side testing against the real cuda.sock)
//!
//! Semantics notes:
//!   * Handles returned to the app (contexts, modules, functions, streams,
//!     events) are the server's opaque ids cast to pointers — never host
//!     addresses.
//!   * Everything executes synchronously on the host; the `*Async` entry points
//!     complete before returning, which the CUDA API permits (an implementation
//!     may be more synchronous than requested). Stream/event query entry points
//!     therefore always report "complete".
//!   * The context-current APIs are process-global, not per-thread. Programs
//!     that juggle distinct contexts on different threads concurrently are out
//!     of scope for this shim.
//!   * `cuLaunchKernel` serializes `kernelParams` using per-parameter sizes the
//!     host extracts from the loaded module (`cuFuncGetParamInfo`, CUDA 12.4+).

// These are C ABI entry points: the caller is C code holding the CUDA Driver
// API contract (valid pointers or NULL, checked where the API allows NULL).
// Marking them `unsafe fn` would not change what C callers can do.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use smolvm_cuda::client::{Client, CudaRpcError};
use std::collections::HashMap;
use std::ffi::{c_char, c_int, c_uint, c_void, CStr};
use std::io::{Read, Write};
use std::sync::Mutex;

// ---- CUresult codes the shim produces locally -------------------------------

const CUDA_SUCCESS: c_int = 0;
const CUDA_ERROR_INVALID_VALUE: c_int = 1;
const CUDA_ERROR_NOT_INITIALIZED: c_int = 3;
const CUDA_ERROR_NO_DEVICE: c_int = 100;
const CUDA_ERROR_INVALID_CONTEXT: c_int = 201;
const CUDA_ERROR_NOT_FOUND: c_int = 500;
const CUDA_ERROR_NOT_SUPPORTED: c_int = 801;
const CUDA_ERROR_UNKNOWN: c_int = 999;

/// The CUDA version this shim reports for its own API surface.
const SHIM_CUDA_VERSION: c_int = 12040;

// ---- transport ---------------------------------------------------------------

/// One concrete byte stream to the host CUDA server.
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
            .map(Stream::Tcp)
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
        // smolvm's reserved CUDA port on the host CID (smolvm_protocol::ports::CUDA).
        const HOST_CID: u32 = 2;
        const CUDA_PORT: u32 = 7000;
        vsock::VsockStream::connect_with_cid_port(HOST_CID, CUDA_PORT)
            .map(Stream::Vsock)
            .map_err(|_| CUDA_ERROR_NO_DEVICE)
    }
    #[cfg(not(target_os = "linux"))]
    Err(CUDA_ERROR_NO_DEVICE)
}

// ---- global state -------------------------------------------------------------

struct ShimState {
    client: Client<Stream>,
    /// Kernel-argument byte sizes per function handle, fetched once per function.
    param_sizes: HashMap<u64, Vec<u32>>,
    /// Primary-context handle per device (retain is refcounted host-side; the
    /// app-visible handle stays stable per device as the real driver's does).
    primary_ctx: HashMap<i32, u64>,
    /// Process-global "current context" stack (bottom = cuCtxSetCurrent slot).
    ctx_stack: Vec<u64>,
}

static STATE: Mutex<Option<ShimState>> = Mutex::new(None);

/// Run `f` against the connected client, translating errors to `CUresult`.
fn with_state<T>(f: impl FnOnce(&mut ShimState) -> Result<T, CudaRpcError>) -> Result<T, c_int> {
    let mut guard = match STATE.lock() {
        Ok(g) => g,
        Err(_) => return Err(CUDA_ERROR_UNKNOWN),
    };
    let state = guard.as_mut().ok_or(CUDA_ERROR_NOT_INITIALIZED)?;
    f(state).map_err(|e| match e {
        CudaRpcError::Cuda(code) => code as c_int,
        CudaRpcError::Io(_) | CudaRpcError::Protocol(_) => CUDA_ERROR_UNKNOWN,
    })
}

/// Fold a `Result<CUresult-able>` into the C return convention.
fn ret(r: Result<(), c_int>) -> c_int {
    match r {
        Ok(()) => CUDA_SUCCESS,
        Err(code) => code,
    }
}

/// Write `v` through an out-pointer, guarding NULL.
unsafe fn out<T>(p: *mut T, v: T) -> Result<(), c_int> {
    if p.is_null() {
        return Err(CUDA_ERROR_INVALID_VALUE);
    }
    unsafe { p.write(v) };
    Ok(())
}

// ---- init / device ------------------------------------------------------------

#[no_mangle]
pub extern "C" fn cuInit(_flags: c_uint) -> c_int {
    let mut guard = match STATE.lock() {
        Ok(g) => g,
        Err(_) => return CUDA_ERROR_UNKNOWN,
    };
    if guard.is_some() {
        return CUDA_SUCCESS; // idempotent, like the real driver
    }
    let stream = match connect() {
        Ok(s) => s,
        Err(code) => return code,
    };
    let mut client = Client::new(stream);
    if let Err(e) = client.init() {
        return match e {
            CudaRpcError::Cuda(code) => code as c_int,
            _ => CUDA_ERROR_NO_DEVICE,
        };
    }
    *guard = Some(ShimState {
        client,
        param_sizes: HashMap::new(),
        primary_ctx: HashMap::new(),
        ctx_stack: Vec::new(),
    });
    CUDA_SUCCESS
}

#[no_mangle]
pub extern "C" fn cuDriverGetVersion(version: *mut c_int) -> c_int {
    // Queryable before cuInit, per the driver's contract.
    if STATE.lock().map(|g| g.is_some()).unwrap_or(false) {
        ret(with_state(|s| s.client.driver_get_version()).and_then(|v| unsafe { out(version, v) }))
    } else {
        ret(unsafe { out(version, SHIM_CUDA_VERSION) })
    }
}

#[no_mangle]
pub extern "C" fn cuDeviceGetCount(count: *mut c_int) -> c_int {
    ret(with_state(|s| s.client.device_get_count()).and_then(|v| unsafe { out(count, v) }))
}

#[no_mangle]
pub extern "C" fn cuDeviceGet(device: *mut c_int, ordinal: c_int) -> c_int {
    // CUdevice is the ordinal itself in this ABI.
    match with_state(|s| s.client.device_get_count()) {
        Ok(n) if ordinal >= 0 && ordinal < n => ret(unsafe { out(device, ordinal) }),
        Ok(_) => CUDA_ERROR_INVALID_VALUE,
        Err(code) => code,
    }
}

#[no_mangle]
pub extern "C" fn cuDeviceGetName(name: *mut c_char, len: c_int, device: c_int) -> c_int {
    if name.is_null() || len <= 0 {
        return CUDA_ERROR_INVALID_VALUE;
    }
    match with_state(|s| s.client.device_get_name(device)) {
        Ok(n) => {
            let bytes = n.as_bytes();
            let copy = bytes.len().min(len as usize - 1);
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), name as *mut u8, copy);
                *name.add(copy) = 0;
            }
            CUDA_SUCCESS
        }
        Err(code) => code,
    }
}

#[no_mangle]
pub extern "C" fn cuDeviceTotalMem_v2(bytes: *mut usize, device: c_int) -> c_int {
    ret(with_state(|s| s.client.device_total_mem(device))
        .and_then(|v| unsafe { out(bytes, v as usize) }))
}

#[no_mangle]
pub extern "C" fn cuDeviceGetAttribute(pi: *mut c_int, attrib: c_int, device: c_int) -> c_int {
    ret(
        with_state(|s| s.client.device_get_attribute(attrib, device))
            .and_then(|v| unsafe { out(pi, v) }),
    )
}

#[no_mangle]
pub extern "C" fn cuDeviceGetUuid(uuid: *mut u8, device: c_int) -> c_int {
    if uuid.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    match with_state(|s| s.client.device_get_uuid(device)) {
        Ok(u) => {
            unsafe { std::ptr::copy_nonoverlapping(u.as_ptr(), uuid, 16) };
            CUDA_SUCCESS
        }
        Err(code) => code,
    }
}

#[no_mangle]
pub extern "C" fn cuDeviceGetUuid_v2(uuid: *mut u8, device: c_int) -> c_int {
    cuDeviceGetUuid(uuid, device)
}

// ---- contexts -------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn cuCtxCreate_v2(pctx: *mut *mut c_void, _flags: c_uint, device: c_int) -> c_int {
    match with_state(|s| s.client.ctx_create(device)) {
        Ok(h) => {
            let r = ret(unsafe { out(pctx, h as *mut c_void) });
            if r == CUDA_SUCCESS {
                if let Ok(mut g) = STATE.lock() {
                    if let Some(s) = g.as_mut() {
                        // cuCtxCreate makes the new context current (pushes it).
                        s.ctx_stack.push(h);
                    }
                }
            }
            r
        }
        Err(code) => code,
    }
}

#[no_mangle]
pub extern "C" fn cuCtxDestroy_v2(ctx: *mut c_void) -> c_int {
    let h = ctx as u64;
    let r = ret(with_state(|s| s.client.ctx_destroy(h)));
    if r == CUDA_SUCCESS {
        if let Ok(mut g) = STATE.lock() {
            if let Some(s) = g.as_mut() {
                s.ctx_stack.retain(|&c| c != h);
            }
        }
    }
    r
}

#[no_mangle]
pub extern "C" fn cuCtxSetCurrent(ctx: *mut c_void) -> c_int {
    match STATE.lock() {
        Ok(mut g) => match g.as_mut() {
            Some(s) => {
                s.ctx_stack.pop();
                if !ctx.is_null() {
                    s.ctx_stack.push(ctx as u64);
                }
                CUDA_SUCCESS
            }
            None => CUDA_ERROR_NOT_INITIALIZED,
        },
        Err(_) => CUDA_ERROR_UNKNOWN,
    }
}

#[no_mangle]
pub extern "C" fn cuCtxGetCurrent(pctx: *mut *mut c_void) -> c_int {
    match STATE.lock() {
        Ok(g) => match g.as_ref() {
            Some(s) => {
                let cur = s.ctx_stack.last().copied().unwrap_or(0);
                ret(unsafe { out(pctx, cur as *mut c_void) })
            }
            None => CUDA_ERROR_NOT_INITIALIZED,
        },
        Err(_) => CUDA_ERROR_UNKNOWN,
    }
}

#[no_mangle]
pub extern "C" fn cuCtxPushCurrent_v2(ctx: *mut c_void) -> c_int {
    if ctx.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    match STATE.lock() {
        Ok(mut g) => match g.as_mut() {
            Some(s) => {
                s.ctx_stack.push(ctx as u64);
                CUDA_SUCCESS
            }
            None => CUDA_ERROR_NOT_INITIALIZED,
        },
        Err(_) => CUDA_ERROR_UNKNOWN,
    }
}

#[no_mangle]
pub extern "C" fn cuCtxPopCurrent_v2(pctx: *mut *mut c_void) -> c_int {
    match STATE.lock() {
        Ok(mut g) => match g.as_mut() {
            Some(s) => match s.ctx_stack.pop() {
                Some(h) => {
                    if !pctx.is_null() {
                        unsafe { *pctx = h as *mut c_void };
                    }
                    CUDA_SUCCESS
                }
                None => CUDA_ERROR_INVALID_CONTEXT,
            },
            None => CUDA_ERROR_NOT_INITIALIZED,
        },
        Err(_) => CUDA_ERROR_UNKNOWN,
    }
}

#[no_mangle]
pub extern "C" fn cuCtxGetDevice(device: *mut c_int) -> c_int {
    // Single-device model: the current context always belongs to device 0.
    match STATE.lock() {
        Ok(g) => match g.as_ref() {
            Some(s) if !s.ctx_stack.is_empty() => ret(unsafe { out(device, 0) }),
            Some(_) => CUDA_ERROR_INVALID_CONTEXT,
            None => CUDA_ERROR_NOT_INITIALIZED,
        },
        Err(_) => CUDA_ERROR_UNKNOWN,
    }
}

#[no_mangle]
pub extern "C" fn cuCtxSynchronize() -> c_int {
    ret(with_state(|s| s.client.ctx_synchronize()))
}

#[no_mangle]
pub extern "C" fn cuDevicePrimaryCtxRetain(pctx: *mut *mut c_void, device: c_int) -> c_int {
    let r = with_state(|s| {
        if let Some(&h) = s.primary_ctx.get(&device) {
            return Ok(h);
        }
        let h = s.client.primary_ctx_retain(device)?;
        s.primary_ctx.insert(device, h);
        Ok(h)
    });
    match r {
        Ok(h) => ret(unsafe { out(pctx, h as *mut c_void) }),
        Err(code) => code,
    }
}

#[no_mangle]
pub extern "C" fn cuDevicePrimaryCtxRelease_v2(device: c_int) -> c_int {
    ret(with_state(|s| s.client.primary_ctx_release(device)))
}

#[no_mangle]
pub extern "C" fn cuDevicePrimaryCtxRelease(device: c_int) -> c_int {
    cuDevicePrimaryCtxRelease_v2(device)
}

#[no_mangle]
pub extern "C" fn cuDevicePrimaryCtxSetFlags_v2(_device: c_int, _flags: c_uint) -> c_int {
    CUDA_SUCCESS // flags are advisory; the host context uses defaults
}

#[no_mangle]
pub extern "C" fn cuDevicePrimaryCtxGetState(
    device: c_int,
    flags: *mut c_uint,
    active: *mut c_int,
) -> c_int {
    let is_active = match STATE.lock() {
        Ok(g) => match g.as_ref() {
            Some(s) => s.primary_ctx.contains_key(&device),
            None => return CUDA_ERROR_NOT_INITIALIZED,
        },
        Err(_) => return CUDA_ERROR_UNKNOWN,
    };
    if !flags.is_null() {
        unsafe { *flags = 0 };
    }
    if !active.is_null() {
        unsafe { *active = is_active as c_int };
    }
    CUDA_SUCCESS
}

// ---- modules --------------------------------------------------------------------

/// Byte length of a module image the app handed us as a bare pointer.
///
/// The Driver API infers the length from the image itself; the RPC needs it
/// explicit. PTX is NUL-terminated text; cubins are ELF; nvcc embeddings are
/// fatbin containers with a size field in the header.
unsafe fn module_image_len(image: *const c_void) -> Result<usize, c_int> {
    if image.is_null() {
        return Err(CUDA_ERROR_INVALID_VALUE);
    }
    let p = image as *const u8;
    let magic = unsafe { std::slice::from_raw_parts(p, 4) };
    // Fatbin container: u32 magic, u16 version, u16 headerSize, u64 fatSize.
    if magic == [0x50, 0xED, 0x55, 0xBA] {
        let header_size = u16::from_le_bytes(unsafe { *(p.add(6) as *const [u8; 2]) }) as usize;
        let fat_size = u64::from_le_bytes(unsafe { *(p.add(8) as *const [u8; 8]) }) as usize;
        return Ok(header_size + fat_size);
    }
    // ELF (cubin): total = e_shoff + e_shnum * e_shentsize (sections are last).
    if magic == [0x7F, b'E', b'L', b'F'] {
        let e_shoff = u64::from_le_bytes(unsafe { *(p.add(0x28) as *const [u8; 8]) }) as usize;
        let e_shentsize = u16::from_le_bytes(unsafe { *(p.add(0x3A) as *const [u8; 2]) }) as usize;
        let e_shnum = u16::from_le_bytes(unsafe { *(p.add(0x3C) as *const [u8; 2]) }) as usize;
        return Ok(e_shoff + e_shentsize * e_shnum);
    }
    // PTX text: NUL-terminated.
    Ok(unsafe { CStr::from_ptr(image as *const c_char) }
        .to_bytes()
        .len()
        + 1)
}

#[no_mangle]
pub extern "C" fn cuModuleLoadData(module: *mut *mut c_void, image: *const c_void) -> c_int {
    let len = match unsafe { module_image_len(image) } {
        Ok(l) => l,
        Err(code) => return code,
    };
    let bytes = unsafe { std::slice::from_raw_parts(image as *const u8, len) };
    match with_state(|s| s.client.module_load_data(bytes)) {
        Ok(h) => ret(unsafe { out(module, h as *mut c_void) }),
        Err(code) => code,
    }
}

#[no_mangle]
pub extern "C" fn cuModuleLoadDataEx(
    module: *mut *mut c_void,
    image: *const c_void,
    _num_options: c_uint,
    _options: *mut c_void,
    _option_values: *mut *mut c_void,
) -> c_int {
    // JIT options are tuning hints; the host driver applies its defaults.
    cuModuleLoadData(module, image)
}

#[no_mangle]
pub extern "C" fn cuModuleLoadFatBinary(module: *mut *mut c_void, fatbin: *const c_void) -> c_int {
    cuModuleLoadData(module, fatbin)
}

#[no_mangle]
pub extern "C" fn cuModuleLoad(module: *mut *mut c_void, fname: *const c_char) -> c_int {
    if fname.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    let path = match unsafe { CStr::from_ptr(fname) }.to_str() {
        Ok(p) => p,
        Err(_) => return CUDA_ERROR_INVALID_VALUE,
    };
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => return CUDA_ERROR_NOT_FOUND,
    };
    match with_state(|s| s.client.module_load_data(&bytes)) {
        Ok(h) => ret(unsafe { out(module, h as *mut c_void) }),
        Err(code) => code,
    }
}

#[no_mangle]
pub extern "C" fn cuModuleGetFunction(
    func: *mut *mut c_void,
    module: *mut c_void,
    name: *const c_char,
) -> c_int {
    if name.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    let fn_name = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(n) => n.to_string(),
        Err(_) => return CUDA_ERROR_INVALID_VALUE,
    };
    match with_state(|s| s.client.module_get_function(module as u64, &fn_name)) {
        Ok(h) => ret(unsafe { out(func, h as *mut c_void) }),
        Err(code) => code,
    }
}

#[no_mangle]
pub extern "C" fn cuModuleUnload(module: *mut c_void) -> c_int {
    ret(with_state(|s| s.client.module_unload(module as u64)))
}

// ---- memory ---------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn cuMemAlloc_v2(dptr: *mut u64, bytes: usize) -> c_int {
    match with_state(|s| s.client.mem_alloc(bytes as u64)) {
        Ok(d) => ret(unsafe { out(dptr, d) }),
        Err(code) => code,
    }
}

#[no_mangle]
pub extern "C" fn cuMemFree_v2(dptr: u64) -> c_int {
    ret(with_state(|s| s.client.mem_free(dptr)))
}

#[no_mangle]
pub extern "C" fn cuMemcpyHtoD_v2(dptr: u64, src: *const c_void, bytes: usize) -> c_int {
    if src.is_null() && bytes > 0 {
        return CUDA_ERROR_INVALID_VALUE;
    }
    let data = unsafe { std::slice::from_raw_parts(src as *const u8, bytes) };
    ret(with_state(|s| s.client.memcpy_htod(dptr, data)))
}

#[no_mangle]
pub extern "C" fn cuMemcpyDtoH_v2(dst: *mut c_void, dptr: u64, bytes: usize) -> c_int {
    if dst.is_null() && bytes > 0 {
        return CUDA_ERROR_INVALID_VALUE;
    }
    match with_state(|s| s.client.memcpy_dtoh(dptr, bytes as u64)) {
        Ok(data) => {
            if data.len() != bytes {
                return CUDA_ERROR_UNKNOWN;
            }
            unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), dst as *mut u8, bytes) };
            CUDA_SUCCESS
        }
        Err(code) => code,
    }
}

#[no_mangle]
pub extern "C" fn cuMemcpyDtoD_v2(dst: u64, src: u64, bytes: usize) -> c_int {
    ret(with_state(|s| s.client.memcpy_dtod(dst, src, bytes as u64)))
}

#[no_mangle]
pub extern "C" fn cuMemsetD8_v2(dptr: u64, value: u8, n: usize) -> c_int {
    ret(with_state(|s| s.client.memset_d8(dptr, value, n as u64)))
}

#[no_mangle]
pub extern "C" fn cuMemGetInfo_v2(free: *mut usize, total: *mut usize) -> c_int {
    match with_state(|s| s.client.mem_get_info()) {
        Ok((f, t)) => {
            if !free.is_null() {
                unsafe { *free = f as usize };
            }
            if !total.is_null() {
                unsafe { *total = t as usize };
            }
            CUDA_SUCCESS
        }
        Err(code) => code,
    }
}

// The *Async variants complete synchronously — permitted by the API contract
// (an implementation may be more synchronous than requested).

#[no_mangle]
pub extern "C" fn cuMemcpyHtoDAsync_v2(
    dptr: u64,
    src: *const c_void,
    bytes: usize,
    _stream: *mut c_void,
) -> c_int {
    cuMemcpyHtoD_v2(dptr, src, bytes)
}

#[no_mangle]
pub extern "C" fn cuMemcpyDtoHAsync_v2(
    dst: *mut c_void,
    dptr: u64,
    bytes: usize,
    _stream: *mut c_void,
) -> c_int {
    cuMemcpyDtoH_v2(dst, dptr, bytes)
}

#[no_mangle]
pub extern "C" fn cuMemcpyDtoDAsync_v2(
    dst: u64,
    src: u64,
    bytes: usize,
    _stream: *mut c_void,
) -> c_int {
    cuMemcpyDtoD_v2(dst, src, bytes)
}

// ---- kernel launch ----------------------------------------------------------------

#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn cuLaunchKernel(
    func: *mut c_void,
    grid_x: c_uint,
    grid_y: c_uint,
    grid_z: c_uint,
    block_x: c_uint,
    block_y: c_uint,
    block_z: c_uint,
    shared_bytes: c_uint,
    stream: *mut c_void,
    kernel_params: *mut *mut c_void,
    extra: *mut *mut c_void,
) -> c_int {
    let fh = func as u64;
    // Argument sizes come from the host's view of the loaded module; fetch once
    // per function and cache.
    let sizes = match with_state(|s| {
        if let Some(sz) = s.param_sizes.get(&fh) {
            return Ok(sz.clone());
        }
        let sz = s.client.func_get_param_info(fh)?;
        s.param_sizes.insert(fh, sz.clone());
        Ok(sz)
    }) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let params: Vec<Vec<u8>> = if sizes.is_empty() {
        Vec::new()
    } else {
        if kernel_params.is_null() {
            // The `extra` buffer-pointer convention is not implemented.
            return if extra.is_null() {
                CUDA_ERROR_INVALID_VALUE
            } else {
                CUDA_ERROR_NOT_SUPPORTED
            };
        }
        let ptrs = unsafe { std::slice::from_raw_parts(kernel_params, sizes.len()) };
        sizes
            .iter()
            .zip(ptrs)
            .map(|(&sz, &p)| {
                unsafe { std::slice::from_raw_parts(p as *const u8, sz as usize) }.to_vec()
            })
            .collect()
    };
    ret(with_state(|s| {
        s.client.launch_kernel(
            fh,
            [grid_x, grid_y, grid_z],
            [block_x, block_y, block_z],
            shared_bytes,
            stream as u64,
            &params,
        )
    }))
}

// ---- streams / events ----------------------------------------------------------------

#[no_mangle]
pub extern "C" fn cuStreamCreate(stream: *mut *mut c_void, flags: c_uint) -> c_int {
    match with_state(|s| s.client.stream_create(flags)) {
        Ok(h) => ret(unsafe { out(stream, h as *mut c_void) }),
        Err(code) => code,
    }
}

#[no_mangle]
pub extern "C" fn cuStreamDestroy_v2(stream: *mut c_void) -> c_int {
    ret(with_state(|s| s.client.stream_destroy(stream as u64)))
}

#[no_mangle]
pub extern "C" fn cuStreamSynchronize(stream: *mut c_void) -> c_int {
    ret(with_state(|s| s.client.stream_synchronize(stream as u64)))
}

#[no_mangle]
pub extern "C" fn cuStreamQuery(_stream: *mut c_void) -> c_int {
    CUDA_SUCCESS // all work completes synchronously
}

#[no_mangle]
pub extern "C" fn cuStreamWaitEvent(
    _stream: *mut c_void,
    _event: *mut c_void,
    _flags: c_uint,
) -> c_int {
    CUDA_SUCCESS // recorded events are already complete
}

#[no_mangle]
pub extern "C" fn cuEventCreate(event: *mut *mut c_void, flags: c_uint) -> c_int {
    match with_state(|s| s.client.event_create(flags)) {
        Ok(h) => ret(unsafe { out(event, h as *mut c_void) }),
        Err(code) => code,
    }
}

#[no_mangle]
pub extern "C" fn cuEventDestroy_v2(event: *mut c_void) -> c_int {
    ret(with_state(|s| s.client.event_destroy(event as u64)))
}

#[no_mangle]
pub extern "C" fn cuEventRecord(event: *mut c_void, stream: *mut c_void) -> c_int {
    ret(with_state(|s| {
        s.client.event_record(event as u64, stream as u64)
    }))
}

#[no_mangle]
pub extern "C" fn cuEventSynchronize(event: *mut c_void) -> c_int {
    ret(with_state(|s| s.client.event_synchronize(event as u64)))
}

#[no_mangle]
pub extern "C" fn cuEventQuery(_event: *mut c_void) -> c_int {
    CUDA_SUCCESS
}

#[no_mangle]
pub extern "C" fn cuEventElapsedTime(ms: *mut f32, start: *mut c_void, end: *mut c_void) -> c_int {
    match with_state(|s| s.client.event_elapsed_time(start as u64, end as u64)) {
        Ok(v) => ret(unsafe { out(ms, v) }),
        Err(code) => code,
    }
}

// ---- error strings -------------------------------------------------------------------

fn error_name(code: c_int) -> &'static CStr {
    match code {
        CUDA_SUCCESS => c"CUDA_SUCCESS",
        CUDA_ERROR_INVALID_VALUE => c"CUDA_ERROR_INVALID_VALUE",
        CUDA_ERROR_NOT_INITIALIZED => c"CUDA_ERROR_NOT_INITIALIZED",
        CUDA_ERROR_NO_DEVICE => c"CUDA_ERROR_NO_DEVICE",
        CUDA_ERROR_INVALID_CONTEXT => c"CUDA_ERROR_INVALID_CONTEXT",
        200 => c"CUDA_ERROR_INVALID_IMAGE",
        218 => c"CUDA_ERROR_INVALID_PTX",
        400 => c"CUDA_ERROR_INVALID_HANDLE",
        CUDA_ERROR_NOT_FOUND => c"CUDA_ERROR_NOT_FOUND",
        700 => c"CUDA_ERROR_ILLEGAL_ADDRESS",
        701 => c"CUDA_ERROR_LAUNCH_OUT_OF_RESOURCES",
        719 => c"CUDA_ERROR_LAUNCH_FAILED",
        CUDA_ERROR_NOT_SUPPORTED => c"CUDA_ERROR_NOT_SUPPORTED",
        _ => c"CUDA_ERROR_UNKNOWN",
    }
}

#[no_mangle]
pub extern "C" fn cuGetErrorName(code: c_int, pstr: *mut *const c_char) -> c_int {
    ret(unsafe { out(pstr, error_name(code).as_ptr()) })
}

#[no_mangle]
pub extern "C" fn cuGetErrorString(code: c_int, pstr: *mut *const c_char) -> c_int {
    // Name doubles as description; apps only ever print it.
    cuGetErrorName(code, pstr)
}

// ---- cuGetProcAddress ------------------------------------------------------------------

/// The modern CUDA runtime resolves nearly every driver entry point through
/// this table rather than dlsym, so it must cover everything we export.
fn proc_table(name: &str) -> Option<*mut c_void> {
    macro_rules! table {
        ($($sym:literal => $f:expr),+ $(,)?) => {
            match name {
                $($sym => Some($f as *mut c_void),)+
                _ => None,
            }
        };
    }
    table! {
        "cuInit" => cuInit,
        "cuDriverGetVersion" => cuDriverGetVersion,
        "cuDeviceGetCount" => cuDeviceGetCount,
        "cuDeviceGet" => cuDeviceGet,
        "cuDeviceGetName" => cuDeviceGetName,
        "cuDeviceTotalMem" => cuDeviceTotalMem_v2,
        "cuDeviceGetAttribute" => cuDeviceGetAttribute,
        "cuDeviceGetUuid" => cuDeviceGetUuid,
        "cuCtxCreate" => cuCtxCreate_v2,
        "cuCtxDestroy" => cuCtxDestroy_v2,
        "cuCtxSetCurrent" => cuCtxSetCurrent,
        "cuCtxGetCurrent" => cuCtxGetCurrent,
        "cuCtxPushCurrent" => cuCtxPushCurrent_v2,
        "cuCtxPopCurrent" => cuCtxPopCurrent_v2,
        "cuCtxGetDevice" => cuCtxGetDevice,
        "cuCtxSynchronize" => cuCtxSynchronize,
        "cuDevicePrimaryCtxRetain" => cuDevicePrimaryCtxRetain,
        "cuDevicePrimaryCtxRelease" => cuDevicePrimaryCtxRelease_v2,
        "cuDevicePrimaryCtxSetFlags" => cuDevicePrimaryCtxSetFlags_v2,
        "cuDevicePrimaryCtxGetState" => cuDevicePrimaryCtxGetState,
        "cuModuleLoad" => cuModuleLoad,
        "cuModuleLoadData" => cuModuleLoadData,
        "cuModuleLoadDataEx" => cuModuleLoadDataEx,
        "cuModuleLoadFatBinary" => cuModuleLoadFatBinary,
        "cuModuleGetFunction" => cuModuleGetFunction,
        "cuModuleUnload" => cuModuleUnload,
        "cuMemAlloc" => cuMemAlloc_v2,
        "cuMemFree" => cuMemFree_v2,
        "cuMemcpyHtoD" => cuMemcpyHtoD_v2,
        "cuMemcpyDtoH" => cuMemcpyDtoH_v2,
        "cuMemcpyDtoD" => cuMemcpyDtoD_v2,
        "cuMemcpyHtoDAsync" => cuMemcpyHtoDAsync_v2,
        "cuMemcpyDtoHAsync" => cuMemcpyDtoHAsync_v2,
        "cuMemcpyDtoDAsync" => cuMemcpyDtoDAsync_v2,
        "cuMemsetD8" => cuMemsetD8_v2,
        "cuMemGetInfo" => cuMemGetInfo_v2,
        "cuLaunchKernel" => cuLaunchKernel,
        "cuStreamCreate" => cuStreamCreate,
        "cuStreamDestroy" => cuStreamDestroy_v2,
        "cuStreamSynchronize" => cuStreamSynchronize,
        "cuStreamQuery" => cuStreamQuery,
        "cuStreamWaitEvent" => cuStreamWaitEvent,
        "cuEventCreate" => cuEventCreate,
        "cuEventDestroy" => cuEventDestroy_v2,
        "cuEventRecord" => cuEventRecord,
        "cuEventSynchronize" => cuEventSynchronize,
        "cuEventQuery" => cuEventQuery,
        "cuEventElapsedTime" => cuEventElapsedTime,
        "cuGetErrorName" => cuGetErrorName,
        "cuGetErrorString" => cuGetErrorString,
        "cuGetProcAddress" => cuGetProcAddress_v2,
    }
}

#[no_mangle]
pub extern "C" fn cuGetProcAddress_v2(
    symbol: *const c_char,
    pfn: *mut *mut c_void,
    _cuda_version: c_int,
    _flags: u64,
    symbol_status: *mut c_int,
) -> c_int {
    if symbol.is_null() || pfn.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    let name = match unsafe { CStr::from_ptr(symbol) }.to_str() {
        Ok(n) => n,
        Err(_) => return CUDA_ERROR_INVALID_VALUE,
    };
    // Strip any explicit version suffix: the table serves one implementation
    // per entry point regardless of the requested revision.
    let base = name.trim_end_matches("_v3").trim_end_matches("_v2");
    match proc_table(base) {
        Some(f) => {
            unsafe { *pfn = f };
            if !symbol_status.is_null() {
                unsafe { *symbol_status = 0 }; // CU_GET_PROC_ADDRESS_SUCCESS
            }
            CUDA_SUCCESS
        }
        None => {
            unsafe { *pfn = std::ptr::null_mut() };
            if !symbol_status.is_null() {
                unsafe { *symbol_status = 1 }; // CU_GET_PROC_ADDRESS_SYMBOL_NOT_FOUND
            }
            CUDA_ERROR_NOT_FOUND
        }
    }
}

#[no_mangle]
pub extern "C" fn cuGetProcAddress(
    symbol: *const c_char,
    pfn: *mut *mut c_void,
    cuda_version: c_int,
    flags: u64,
) -> c_int {
    cuGetProcAddress_v2(symbol, pfn, cuda_version, flags, std::ptr::null_mut())
}
