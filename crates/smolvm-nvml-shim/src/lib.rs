//! Guest-side `libnvidia-ml.so.1` drop-in.
//!
//! CUDA frameworks — vLLM in particular — detect the GPU and read its memory,
//! compute capability, name and UUID through **NVML**, not the CUDA driver or
//! runtime. smolvm remotes the CUDA driver + runtime but not NVML, so without
//! this shim such frameworks see "no CUDA platform" and refuse to run.
//!
//! This implements the small NVML surface they touch and answers it from the
//! remoted CUDA driver: our `libcuda.so.1` is already loaded in the process, so
//! its `cuDeviceGet*`/`cuMemGetInfo` are resolvable at runtime via
//! `dlsym(RTLD_DEFAULT, …)`. Everything degrades to a static fallback when the
//! driver isn't reachable, so the library is safe to load unconditionally.
//!
//! Drop it in where the loader looks for `libnvidia-ml.so.1`.

// These are C ABI entry points: the caller owns the pointers and the contract is
// the NVML one, so marking each `unsafe` would only obscure the ABI. Matches the
// other `smolvm-*-shim` crates.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::os::raw::{c_char, c_int, c_uint, c_ulonglong};

// ---- nvmlReturn_t ------------------------------------------------------------
const NVML_SUCCESS: c_int = 0;
const NVML_ERROR_INVALID_ARGUMENT: c_int = 2;

// ---- CUdevice attribute ids (driver API) ------------------------------------
const CU_ATTR_CC_MAJOR: c_int = 75;
const CU_ATTR_CC_MINOR: c_int = 76;

// ---- CUDA driver resolution (from the already-loaded libcuda.so.1) -----------

/// Resolve a NUL-terminated CUDA Driver symbol from any library loaded in the
/// process (our LD_PRELOADed `libcuda.so.1`). `None` if CUDA isn't present.
///
/// The shim is only ever loaded by a Linux guest, but the workspace is
/// cross-compiled, so the non-Unix build resolves nothing and every NVML query
/// then falls back to its static answer.
#[cfg(unix)]
unsafe fn cu_sym(name: &std::ffi::CStr) -> Option<*mut std::ffi::c_void> {
    let p = libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr());
    if p.is_null() {
        None
    } else {
        Some(p)
    }
}

#[cfg(not(unix))]
unsafe fn cu_sym(_name: &std::ffi::CStr) -> Option<*mut std::ffi::c_void> {
    None
}

fn cu_init() {
    unsafe {
        if let Some(f) = cu_sym(c"cuInit") {
            let f: extern "C" fn(c_uint) -> c_int = std::mem::transmute(f);
            let _ = f(0);
        }
    }
}

/// The driver's CUdevice for ordinal `ord` (an int handle, usually == ord).
unsafe fn cu_device(ord: c_int) -> Option<c_int> {
    let f = cu_sym(c"cuDeviceGet")?;
    let f: extern "C" fn(*mut c_int, c_int) -> c_int = std::mem::transmute(f);
    let mut dev: c_int = 0;
    (f(&mut dev, ord) == 0).then_some(dev)
}

/// Number of visible CUDA devices, or 1 if the driver can't be asked (we only
/// ever expose the single remoted GPU anyway).
fn cu_device_count() -> u32 {
    unsafe {
        if let Some(f) = cu_sym(c"cuDeviceGetCount") {
            let f: extern "C" fn(*mut c_int) -> c_int = std::mem::transmute(f);
            let mut n: c_int = 0;
            if f(&mut n) == 0 && n > 0 {
                return n as u32;
            }
        }
    }
    1
}

fn cu_device_name(ord: c_int) -> Option<String> {
    unsafe {
        let dev = cu_device(ord)?;
        let f = cu_sym(c"cuDeviceGetName")?;
        let f: extern "C" fn(*mut c_char, c_int, c_int) -> c_int = std::mem::transmute(f);
        let mut buf = [0i8; 256];
        (f(buf.as_mut_ptr(), buf.len() as c_int, dev) == 0).then(|| {
            let cstr = std::ffi::CStr::from_ptr(buf.as_ptr());
            cstr.to_string_lossy().into_owned()
        })
    }
}

fn cu_total_mem(ord: c_int) -> Option<u64> {
    unsafe {
        let dev = cu_device(ord)?;
        // cuDeviceTotalMem_v2 takes no context (device query only).
        let f = cu_sym(c"cuDeviceTotalMem_v2").or_else(|| cu_sym(c"cuDeviceTotalMem"))?;
        let f: extern "C" fn(*mut usize, c_int) -> c_int = std::mem::transmute(f);
        let mut bytes: usize = 0;
        (f(&mut bytes, dev) == 0 && bytes > 0).then_some(bytes as u64)
    }
}

/// (free, total) from the current context if one exists; `None` otherwise.
fn cu_mem_get_info() -> Option<(u64, u64)> {
    unsafe {
        let f = cu_sym(c"cuMemGetInfo_v2").or_else(|| cu_sym(c"cuMemGetInfo"))?;
        let f: extern "C" fn(*mut usize, *mut usize) -> c_int = std::mem::transmute(f);
        let (mut free, mut total): (usize, usize) = (0, 0);
        (f(&mut free, &mut total) == 0 && total > 0).then_some((free as u64, total as u64))
    }
}

fn cu_compute_capability(ord: c_int) -> Option<(c_int, c_int)> {
    unsafe {
        let dev = cu_device(ord)?;
        let f = cu_sym(c"cuDeviceGetAttribute")?;
        let f: extern "C" fn(*mut c_int, c_int, c_int) -> c_int = std::mem::transmute(f);
        let (mut maj, mut min): (c_int, c_int) = (0, 0);
        let ok = f(&mut maj, CU_ATTR_CC_MAJOR, dev) == 0
            && f(&mut min, CU_ATTR_CC_MINOR, dev) == 0
            && maj > 0;
        ok.then_some((maj, min))
    }
}

// ---- helpers ----------------------------------------------------------------

/// Encode an ordinal as a non-null opaque `nvmlDevice_t` (ordinal + 1) and back.
fn handle_of(ord: u32) -> *mut std::ffi::c_void {
    (ord as usize + 1) as *mut std::ffi::c_void
}
fn ord_of(handle: *mut std::ffi::c_void) -> c_int {
    (handle as usize).wrapping_sub(1) as c_int
}

/// Copy `s` into the caller's C buffer, NUL-terminated and length-bounded.
unsafe fn write_cstr(dst: *mut c_char, len: c_uint, s: &str) {
    if dst.is_null() || len == 0 {
        return;
    }
    let cap = len as usize - 1;
    let bytes = s.as_bytes();
    let n = bytes.len().min(cap);
    std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, dst, n);
    *dst.add(n) = 0;
}

// ---- nvmlMemory_t ------------------------------------------------------------
#[repr(C)]
pub struct NvmlMemory {
    pub total: c_ulonglong,
    pub free: c_ulonglong,
    pub used: c_ulonglong,
}

// ---- NVML API ----------------------------------------------------------------
// Return NVML_SUCCESS broadly: these are queried during device discovery, and a
// framework that gets an error concludes "no GPU". Multiple symbol versions are
// exported because pynvml resolves whichever the header it was built against
// names (`_v2`, plain, etc.).

#[no_mangle]
pub extern "C" fn nvmlInit_v2() -> c_int {
    cu_init();
    NVML_SUCCESS
}
#[no_mangle]
pub extern "C" fn nvmlInit() -> c_int {
    cu_init();
    NVML_SUCCESS
}
#[no_mangle]
pub extern "C" fn nvmlInitWithFlags(_flags: c_uint) -> c_int {
    cu_init();
    NVML_SUCCESS
}
#[no_mangle]
pub extern "C" fn nvmlShutdown() -> c_int {
    NVML_SUCCESS
}

#[no_mangle]
pub extern "C" fn nvmlDeviceGetCount_v2(count: *mut c_uint) -> c_int {
    if count.is_null() {
        return NVML_ERROR_INVALID_ARGUMENT;
    }
    unsafe { *count = cu_device_count() }
    NVML_SUCCESS
}
#[no_mangle]
pub extern "C" fn nvmlDeviceGetCount(count: *mut c_uint) -> c_int {
    nvmlDeviceGetCount_v2(count)
}

#[no_mangle]
pub extern "C" fn nvmlDeviceGetHandleByIndex_v2(
    index: c_uint,
    device: *mut *mut std::ffi::c_void,
) -> c_int {
    if device.is_null() || index >= cu_device_count() {
        return NVML_ERROR_INVALID_ARGUMENT;
    }
    unsafe { *device = handle_of(index) }
    NVML_SUCCESS
}
#[no_mangle]
pub extern "C" fn nvmlDeviceGetHandleByIndex(
    index: c_uint,
    device: *mut *mut std::ffi::c_void,
) -> c_int {
    nvmlDeviceGetHandleByIndex_v2(index, device)
}

#[no_mangle]
pub extern "C" fn nvmlDeviceGetName(
    device: *mut std::ffi::c_void,
    name: *mut c_char,
    length: c_uint,
) -> c_int {
    let s = cu_device_name(ord_of(device)).unwrap_or_else(|| "NVIDIA GPU".to_string());
    unsafe { write_cstr(name, length, &s) }
    NVML_SUCCESS
}

#[no_mangle]
pub extern "C" fn nvmlDeviceGetMemoryInfo(
    device: *mut std::ffi::c_void,
    memory: *mut NvmlMemory,
) -> c_int {
    if memory.is_null() {
        return NVML_ERROR_INVALID_ARGUMENT;
    }
    let ord = ord_of(device);
    // Prefer live (free,total) from the current context; else total from the
    // device query with a conservative free estimate.
    let (free, total) = cu_mem_get_info().unwrap_or_else(|| {
        let total = cu_total_mem(ord).unwrap_or(8 * 1024 * 1024 * 1024);
        (total, total)
    });
    unsafe {
        (*memory).total = total;
        (*memory).free = free;
        (*memory).used = total.saturating_sub(free);
    }
    NVML_SUCCESS
}
// v2 memory struct adds reserved fields after {total,free,used}; the first three
// match, so the same writer is ABI-safe for callers that pass the larger struct.
#[no_mangle]
pub extern "C" fn nvmlDeviceGetMemoryInfo_v2(
    device: *mut std::ffi::c_void,
    memory: *mut NvmlMemory,
) -> c_int {
    nvmlDeviceGetMemoryInfo(device, memory)
}

#[no_mangle]
pub extern "C" fn nvmlDeviceGetCudaComputeCapability(
    device: *mut std::ffi::c_void,
    major: *mut c_int,
    minor: *mut c_int,
) -> c_int {
    if major.is_null() || minor.is_null() {
        return NVML_ERROR_INVALID_ARGUMENT;
    }
    let (maj, min) = cu_compute_capability(ord_of(device)).unwrap_or((8, 0));
    unsafe {
        *major = maj;
        *minor = min;
    }
    NVML_SUCCESS
}

#[no_mangle]
pub extern "C" fn nvmlDeviceGetUUID(
    _device: *mut std::ffi::c_void,
    uuid: *mut c_char,
    length: c_uint,
) -> c_int {
    // A stable, well-formed GPU UUID. Frameworks key caches/logs on it but don't
    // require it to match real hardware for a single-GPU remoted device.
    unsafe { write_cstr(uuid, length, "GPU-00000000-0000-0000-0000-000000000000") }
    NVML_SUCCESS
}

#[no_mangle]
pub extern "C" fn nvmlDeviceGetP2PStatus(
    _device1: *mut std::ffi::c_void,
    _device2: *mut std::ffi::c_void,
    _p2p_index: c_int,
    p2p_status: *mut c_int,
) -> c_int {
    if p2p_status.is_null() {
        return NVML_ERROR_INVALID_ARGUMENT;
    }
    unsafe { *p2p_status = 0 } // NVML_P2P_STATUS_OK
    NVML_SUCCESS
}

// ---- torch c10 DriverAPI surface --------------------------------------------
// torch's expandable-segments support (c10/cuda/driver_api.cpp) dlopens NVML
// and eagerly asserts its whole symbol table; a single missing name aborts
// engine startup (vLLM: "Can't find nvmlDeviceGetHandleByPciBusId_v2").
// NvLink/fabric queries honestly report NOT_SUPPORTED — the remoted view is a
// single GPU with no NvLink topology.

const NVML_ERROR_NOT_SUPPORTED: c_int = 3;

#[no_mangle]
pub extern "C" fn nvmlDeviceGetHandleByPciBusId_v2(
    _pci_bus_id: *const c_char,
    device: *mut *mut std::ffi::c_void,
) -> c_int {
    // The guest sees exactly one device; every bus id resolves to it.
    if device.is_null() {
        return NVML_ERROR_INVALID_ARGUMENT;
    }
    unsafe { *device = handle_of(0) }
    NVML_SUCCESS
}

#[no_mangle]
pub extern "C" fn nvmlDeviceGetHandleByPciBusId(
    pci_bus_id: *const c_char,
    device: *mut *mut std::ffi::c_void,
) -> c_int {
    nvmlDeviceGetHandleByPciBusId_v2(pci_bus_id, device)
}

#[no_mangle]
pub extern "C" fn nvmlDeviceGetNvLinkRemoteDeviceType(
    _device: *mut std::ffi::c_void,
    _link: c_uint,
    _dev_type: *mut c_int,
) -> c_int {
    NVML_ERROR_NOT_SUPPORTED
}

#[no_mangle]
pub extern "C" fn nvmlDeviceGetNvLinkRemotePciInfo_v2(
    _device: *mut std::ffi::c_void,
    _link: c_uint,
    _pci: *mut std::ffi::c_void,
) -> c_int {
    NVML_ERROR_NOT_SUPPORTED
}

#[no_mangle]
pub extern "C" fn nvmlDeviceGetComputeRunningProcesses(
    _device: *mut std::ffi::c_void,
    info_count: *mut c_uint,
    _infos: *mut std::ffi::c_void,
) -> c_int {
    // No process visibility across the remoting boundary; report none.
    if info_count.is_null() {
        return NVML_ERROR_INVALID_ARGUMENT;
    }
    unsafe { *info_count = 0 }
    NVML_SUCCESS
}

#[no_mangle]
pub extern "C" fn nvmlSystemGetCudaDriverVersion_v2(version: *mut c_int) -> c_int {
    if version.is_null() {
        return NVML_ERROR_INVALID_ARGUMENT;
    }
    let mut v: c_int = 0;
    let ok = unsafe {
        match cu_sym(c"cuDriverGetVersion") {
            Some(f) => {
                let f: extern "C" fn(*mut c_int) -> c_int = std::mem::transmute(f);
                f(&mut v) == 0 && v > 0
            }
            None => false,
        }
    };
    if !ok {
        v = 13020;
    }
    unsafe { *version = v }
    NVML_SUCCESS
}

#[no_mangle]
pub extern "C" fn nvmlSystemGetCudaDriverVersion(version: *mut c_int) -> c_int {
    nvmlSystemGetCudaDriverVersion_v2(version)
}

#[no_mangle]
pub extern "C" fn nvmlDeviceGetGpuFabricInfoV(
    _device: *mut std::ffi::c_void,
    _info: *mut std::ffi::c_void,
) -> c_int {
    NVML_ERROR_NOT_SUPPORTED
}

#[no_mangle]
pub extern "C" fn nvmlErrorString(_result: c_int) -> *const c_char {
    c"Success".as_ptr()
}
