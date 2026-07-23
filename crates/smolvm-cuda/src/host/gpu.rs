//! Real CUDA Driver-API backend via `dlopen` of the driver library
//! (`nvcuda.dll` on Windows, `libcuda.so.1` on Linux). No CUDA toolkit needed —
//! the `cu*` signatures are declared by hand. The same calls were proven on an
//! RTX 3070; this wraps them behind the [`Backend`] trait.
//!
//! Context affinity: the CUDA context becomes current on the thread that calls
//! `cuCtxCreate`. The host runs one [`serve`](super::serve) loop per connection
//! on a single thread, and `ctx_create` is invoked on that thread, so all later
//! calls on the connection see the right current context.

use super::{Backend, CuResult};
use libloading::{Library, Symbol};
use std::ffi::{c_void, CStr, CString};
use std::os::raw::{c_char, c_int, c_uint};

#[cfg(windows)]
const CUDA_LIB: &str = "nvcuda.dll";
#[cfg(target_os = "linux")]
const CUDA_LIB: &str = "libcuda.so.1";
#[cfg(target_os = "macos")]
const CUDA_LIB: &str = "libcuda.dylib"; // not expected to exist; macOS has no CUDA

type CuResultCode = c_int;

/// Hand-declared driver entry points. Stored as `'static` fn pointers; `_lib`
/// keeps the library mapped for as long as the backend lives.
pub struct GpuBackend {
    _lib: Library,
    init: unsafe extern "C" fn(c_uint) -> CuResultCode,
    device_get_count: unsafe extern "C" fn(*mut c_int) -> CuResultCode,
    device_get_name: unsafe extern "C" fn(*mut c_char, c_int, c_int) -> CuResultCode,
    device_total_mem: unsafe extern "C" fn(*mut usize, c_int) -> CuResultCode,
    driver_get_version: unsafe extern "C" fn(*mut c_int) -> CuResultCode,
    device_get_attribute: unsafe extern "C" fn(*mut c_int, c_int, c_int) -> CuResultCode,
    device_get_uuid: unsafe extern "C" fn(*mut u8, c_int) -> CuResultCode,
    ctx_create: unsafe extern "C" fn(*mut *mut c_void, c_uint, c_int) -> CuResultCode,
    ctx_destroy: unsafe extern "C" fn(*mut c_void) -> CuResultCode,
    ctx_set_current: unsafe extern "C" fn(*mut c_void) -> CuResultCode,
    ctx_get_current: unsafe extern "C" fn(*mut *mut c_void) -> CuResultCode,
    primary_ctx_retain: unsafe extern "C" fn(*mut *mut c_void, c_int) -> CuResultCode,
    primary_ctx_release: unsafe extern "C" fn(c_int) -> CuResultCode,
    module_load_data: unsafe extern "C" fn(*mut *mut c_void, *const c_void) -> CuResultCode,
    module_get_function:
        unsafe extern "C" fn(*mut *mut c_void, *mut c_void, *const c_char) -> CuResultCode,
    module_unload: unsafe extern "C" fn(*mut c_void) -> CuResultCode,
    /// `cuFuncGetParamInfo` — CUDA 12.4+. `None` on older drivers, where
    /// [`Backend::func_get_param_info`] reports `CUDA_ERROR_NOT_SUPPORTED`.
    func_get_param_info:
        Option<unsafe extern "C" fn(*mut c_void, usize, *mut usize, *mut usize) -> CuResultCode>,
    func_set_attribute: unsafe extern "C" fn(*mut c_void, c_int, c_int) -> CuResultCode,
    func_get_attribute: unsafe extern "C" fn(*mut c_int, c_int, *mut c_void) -> CuResultCode,
    mem_alloc: unsafe extern "C" fn(*mut u64, usize) -> CuResultCode,
    mem_free: unsafe extern "C" fn(u64) -> CuResultCode,
    memcpy_htod: unsafe extern "C" fn(u64, *const c_void, usize) -> CuResultCode,
    memcpy_dtoh: unsafe extern "C" fn(*mut c_void, u64, usize) -> CuResultCode,
    memcpy_dtod: unsafe extern "C" fn(u64, u64, usize) -> CuResultCode,
    memset_d8: unsafe extern "C" fn(u64, u8, usize) -> CuResultCode,
    mem_get_info: unsafe extern "C" fn(*mut usize, *mut usize) -> CuResultCode,
    /// `cuMemHostRegister_v2` / `cuMemHostUnregister` — pin a host range into the
    /// context so DMAs from it run at full (pinned) bandwidth instead of the
    /// ~3 GB/s pageable path. `None` on very old drivers. Used to pin guest RAM
    /// for zero-copy. Registration needs a current context, so it happens lazily
    /// on the first zero-copy transfer, not at `set_guest_ram`.
    mem_host_register: Option<unsafe extern "C" fn(*mut c_void, usize, c_uint) -> CuResultCode>,
    mem_host_unregister: Option<unsafe extern "C" fn(*mut c_void) -> CuResultCode>,
    /// `cuMemAllocHost_v2` / `cuMemFreeHost` — allocate pinned host memory, used
    /// for the gather/scatter staging buffer on heavily-fragmented zero-copy
    /// transfers. `None` on very old drivers (then the fragmented path DMAs each
    /// segment directly).
    mem_host_alloc: Option<unsafe extern "C" fn(*mut *mut c_void, usize) -> CuResultCode>,
    mem_free_host: Option<unsafe extern "C" fn(*mut c_void) -> CuResultCode>,
    #[allow(clippy::type_complexity)]
    launch_kernel: unsafe extern "C" fn(
        *mut c_void,
        c_uint,
        c_uint,
        c_uint,
        c_uint,
        c_uint,
        c_uint,
        c_uint,
        *mut c_void,
        *mut *mut c_void,
        *mut *mut c_void,
    ) -> CuResultCode,
    ctx_synchronize: unsafe extern "C" fn() -> CuResultCode,
    stream_create: unsafe extern "C" fn(*mut *mut c_void, c_uint) -> CuResultCode,
    // CUDA graphs (capture on the real driver; replay = one launch).
    stream_begin_capture: unsafe extern "C" fn(*mut c_void, c_int) -> CuResultCode,
    thread_exchange_capture_mode: unsafe extern "C" fn(*mut c_int) -> CuResultCode,
    stream_end_capture: unsafe extern "C" fn(*mut c_void, *mut *mut c_void) -> CuResultCode,
    stream_get_capture_info:
        unsafe extern "C" fn(*mut c_void, *mut c_int, *mut u64) -> CuResultCode,
    graph_instantiate_with_flags:
        unsafe extern "C" fn(*mut *mut c_void, *mut c_void, u64) -> CuResultCode,
    graph_launch: unsafe extern "C" fn(*mut c_void, *mut c_void) -> CuResultCode,
    graph_exec_destroy: unsafe extern "C" fn(*mut c_void) -> CuResultCode,
    graph_destroy: unsafe extern "C" fn(*mut c_void) -> CuResultCode,
    graph_get_nodes:
        unsafe extern "C" fn(*mut c_void, *mut *mut c_void, *mut usize) -> CuResultCode,
    // M3b: graph rebuild in a fresh context (Path 3) — create + add kernel nodes
    // + wire dependencies, then instantiate.
    graph_create: unsafe extern "C" fn(*mut *mut c_void, c_uint) -> CuResultCode,
    graph_add_kernel_node: unsafe extern "C" fn(
        *mut *mut c_void,   // out node
        *mut c_void,        // graph
        *const *mut c_void, // deps
        usize,              // numDeps
        *const KernelNodeParams,
    ) -> CuResultCode,
    graph_node_get_dependencies:
        unsafe extern "C" fn(*mut c_void, *mut *mut c_void, *mut usize) -> CuResultCode,
    graph_add_dependencies: unsafe extern "C" fn(
        *mut c_void,        // graph
        *const *mut c_void, // from[]
        *const *mut c_void, // to[]
        usize,              // count
    ) -> CuResultCode,
    // Graph-node introspection + exec node-param setters — used to patch a fork
    // clone's inherited cudagraph so its baked-in device pointers hit the clone's
    // private copies (Path 2 of the fork-isolation design).
    graph_node_get_type: unsafe extern "C" fn(*mut c_void, *mut c_int) -> CuResultCode,
    graph_kernel_node_get_params:
        unsafe extern "C" fn(*mut c_void, *mut KernelNodeParams) -> CuResultCode,
    graph_exec_kernel_node_set_params:
        unsafe extern "C" fn(*mut c_void, *mut c_void, *const KernelNodeParams) -> CuResultCode,
    graph_memset_node_get_params:
        unsafe extern "C" fn(*mut c_void, *mut MemsetNodeParams) -> CuResultCode,
    graph_exec_memset_node_set_params: unsafe extern "C" fn(
        *mut c_void,
        *mut c_void,
        *const MemsetNodeParams,
        *mut c_void,
    ) -> CuResultCode,
    graph_memcpy_node_get_params: unsafe extern "C" fn(*mut c_void, *mut Memcpy3D) -> CuResultCode,
    graph_exec_memcpy_node_set_params: unsafe extern "C" fn(
        *mut c_void,
        *mut c_void,
        *const Memcpy3D,
        *mut c_void,
    ) -> CuResultCode,
    memset_d8_async: unsafe extern "C" fn(u64, u8, usize, *mut c_void) -> CuResultCode,
    memcpy_dtod_async: unsafe extern "C" fn(u64, u64, usize, *mut c_void) -> CuResultCode,
    stream_destroy: unsafe extern "C" fn(*mut c_void) -> CuResultCode,
    stream_synchronize: unsafe extern "C" fn(*mut c_void) -> CuResultCode,
    stream_query: unsafe extern "C" fn(*mut c_void) -> CuResultCode,
    stream_wait_event: unsafe extern "C" fn(*mut c_void, *mut c_void, c_uint) -> CuResultCode,
    // VMM (all optional: pre-Pascal drivers lack them; ops report NOT_SUPPORTED)
    vmm_address_reserve:
        Option<unsafe extern "C" fn(*mut u64, usize, usize, u64, u64) -> CuResultCode>,
    vmm_create: Option<unsafe extern "C" fn(*mut u64, usize, *const VmmProp, u64) -> CuResultCode>,
    vmm_map: Option<unsafe extern "C" fn(u64, usize, usize, u64, u64) -> CuResultCode>,
    vmm_set_access:
        Option<unsafe extern "C" fn(u64, usize, *const VmmAccessDesc, usize) -> CuResultCode>,
    vmm_unmap: Option<unsafe extern "C" fn(u64, usize) -> CuResultCode>,
    vmm_release: Option<unsafe extern "C" fn(u64) -> CuResultCode>,
    vmm_address_free: Option<unsafe extern "C" fn(u64, usize) -> CuResultCode>,
    // IPC (Path 3 address-preserving isolation): export a physical handle to a
    // POSIX fd (golden) and import it back (clone), so a clone process shares the
    // golden's weight physical at the golden's VA. `cuMemExportToShareableHandle`
    // / `cuMemImportFromShareableHandle`.
    vmm_export: Option<unsafe extern "C" fn(*mut c_int, u64, c_int, u64) -> CuResultCode>,
    vmm_import: Option<unsafe extern "C" fn(*mut u64, *mut c_void, c_int) -> CuResultCode>,
    vmm_granularity:
        Option<unsafe extern "C" fn(*mut usize, *const VmmProp, c_uint) -> CuResultCode>,
    event_query: unsafe extern "C" fn(*mut c_void) -> CuResultCode,
    event_create: unsafe extern "C" fn(*mut *mut c_void, c_uint) -> CuResultCode,
    event_destroy: unsafe extern "C" fn(*mut c_void) -> CuResultCode,
    event_record: unsafe extern "C" fn(*mut c_void, *mut c_void) -> CuResultCode,
    event_synchronize: unsafe extern "C" fn(*mut c_void) -> CuResultCode,
    event_elapsed_time: unsafe extern "C" fn(*mut f32, *mut c_void, *mut c_void) -> CuResultCode,
    /// Real nvcomp, dlopened on demand from `SMOLVM_NVCOMP_LIB`. Kept in an
    /// `Option` because most workloads never touch it. Runs on the same primary
    /// context as everything else, so forwarded device pointers are valid.
    nvcomp: Option<Nvcomp>,
    /// Real cuBLAS, dlopened on demand from `SMOLVM_CUBLAS_LIB` (default
    /// `libcublas.so`). Runs on the same primary context.
    cublas: Option<Cublas>,
    /// Code-generated dispatch tables (library id → handlers), loaded on first use.
    cublas_gen: Option<gen_cublas::GenLib>,
    cudnn_gen: Option<gen_cudnn::GenLib>,
    /// cuDNN v8 backend (graph) API forwarder — PyTorch's convolution path.
    cudnn_backend: Option<CudnnBackend>,
    /// cuBLASLt matmul forwarder — PyTorch's `cublasLtMatmul` linear-layer path.
    cublaslt: Option<CublasLt>,
    /// Legacy cuDNN batch-norm (Ex) forwarder — PyTorch's `BatchNorm2d` path.
    cudnn_bn: Option<CudnnBn>,
    /// Guest-assigned virtual handle (bit 63 set) → real host descriptor
    /// pointer. Lets the guest fire-and-forget descriptor creation: it invents
    /// the id, the host materializes and maps it, and every later reference is
    /// translated here. Real pointers (bit 63 clear) pass through untouched.
    ///
    /// Behind `Arc<Mutex>` so a fork clone's reconnecting session can adopt a
    /// snapshot of its (frozen) parent's map — the descriptors are real host
    /// pointers valid in the shared primary context, so copying the id→pointer
    /// pairs is enough. Lock cost is negligible: every access already sits
    /// behind a guest round-trip.
    vhandles: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<u64, u64>>>,
    /// Host mappings of guest RAM, each `(gpa_start, host_va, len)`, for
    /// zero-copy `memcpy_gpa_*` (via `krun_get_guest_ram`). Empty outside a
    /// microVM / on older libkrun. Guest RAM is usually split into a low and a
    /// high region around the 4 GiB PCI hole.
    guest_ram: Vec<(u64, u64, u64)>,
    /// Fork-CLONE transport: private COW guest RAM cannot be memfd-mapped, so
    /// `guest_ram` holds the CLONE's own (gpa, host_va, len) and we read/write its
    /// LIVE pages through this open /proc/<pid>/mem. Correct on COW-diverged pages
    /// and race-free vs the socket bounce path. `None` for the golden (memfd map).
    #[cfg(unix)]
    proc_mem: Option<std::fs::File>,
    /// Clone proc-mem regions (gpa, CLONE host_va, len), resolved for pread/pwrite
    /// of /proc/<pid>/mem. Kept SEPARATE from `guest_ram` because these host VAs
    /// live in the CLONE's address space and must NEVER be dereferenced by the
    /// daemon's ring / zero-copy paths (which assume guest_ram is mapped HERE).
    #[cfg(unix)]
    proc_mem_regions: Vec<(u64, u64, u64)>,
    /// Guest-RAM host ranges `(host_va, len)` this backend pinned via
    /// `cuMemHostRegister` (to unregister on drop). Excludes ranges another
    /// connection already owns. Empty until the first zero-copy transfer.
    registered: Vec<(u64, u64)>,
    /// Whether lazy guest-RAM pinning has been attempted (once per backend).
    guest_ram_pin_tried: bool,
    /// Reusable pinned host staging buffer `(addr, capacity)` for the gather /
    /// scatter path on fragmented zero-copy transfers. Held as an address (not a
    /// pointer) so the backend stays `Send`; 0 until first needed, grown on
    /// demand, freed on drop.
    staging: (usize, usize),
}

/// Above this segment count, a fragmented zero-copy transfer gathers into one
/// pinned staging buffer and issues a single DMA instead of one DMA per segment
/// — past here the per-DMA launch overhead of thousands of tiny copies costs
/// more than a single host-side gather plus one big transfer.
const ZC_DIRECT_MAX_SEGMENTS: usize = 16;

/// Code-generated forward-to-host-lib dispatch (see `smolvm-cuda-codegen`).
/// Each `include!`d module exposes a `GenLib` with `load()` + `dispatch()`.
mod gen_cublas {
    #![allow(non_snake_case, clippy::unnecessary_cast, unused_mut, dead_code)]
    use super::*;
    include!("../generated/cublas_host.rs");
}
mod gen_cudnn {
    #![allow(non_snake_case, clippy::unnecessary_cast, unused_mut, dead_code)]
    use super::*;
    include!("../generated/cudnn_host.rs");
}

/// Library ids on the `LibCall` wire (must match the generated `LIB_ID`).
const LIB_CUBLAS: u8 = 1;
const LIB_CUDNN: u8 = 2;
/// cuDNN v8 backend (graph) API — hand-marshaled, not codegen (opaque
/// descriptors + typed attribute arrays).
const LIB_CUDNN_BACKEND: u8 = 3;
const LIB_CUBLASLT: u8 = 4;
const LIB_CUDNN_BN: u8 = 5;
/// Driver-API extras forwarded over the generic LibCall transport (no proto
/// change needed): func 0 = cuTensorMapEncodeTiled (Hopper TMA descriptors).
const LIB_DRIVER_TMA: u8 = 6;

/// Hand-declared cuBLAS entry points (subset). `cublasStatus_t` is an enum (i32).
struct Cublas {
    _lib: Library,
    create: unsafe extern "C" fn(*mut *mut c_void) -> c_int,
    destroy: unsafe extern "C" fn(*mut c_void) -> c_int,
    set_stream: unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int,
    #[allow(clippy::type_complexity)]
    sgemm: unsafe extern "C" fn(
        *mut c_void, // handle
        c_int,       // transa
        c_int,       // transb
        c_int,
        c_int,
        c_int, // m,n,k
        *const f32,
        *const f32,
        c_int, // alpha, A, lda
        *const f32,
        c_int, // B, ldb
        *const f32,
        *mut f32,
        c_int, // beta, C, ldc
    ) -> c_int,
}

/// Open a host CUDA library with auto-discovery: an env override wins, then
/// the plain soname (dlopen's ldconfig search), then the usual CUDA install
/// prefixes. Removes the need to export `SMOLVM_*_LIB` on typical hosts, where
/// the toolkit lives under `/opt/cuda` or `/usr/local/cuda` without ldconfig
/// entries.
pub(super) fn open_host_lib(env_var: &str, sonames: &[&str]) -> Result<Library, String> {
    if let Ok(path) = std::env::var(env_var) {
        // SAFETY: loading a user-designated shared library.
        return unsafe { Library::new(&path).map_err(|e| format!("load {path}: {e}")) };
    }
    const PREFIXES: &[&str] = &[
        "", // plain soname: dlopen's own ldconfig search
        "/opt/cuda/lib64/",
        "/usr/local/cuda/lib64/",
        "/usr/lib/x86_64-linux-gnu/",
        "/usr/lib64/",
        "/usr/lib/",
    ];
    let mut last_err = String::new();
    for soname in sonames {
        for prefix in PREFIXES {
            let cand = format!("{prefix}{soname}");
            // SAFETY: probing well-known system library locations.
            match unsafe { Library::new(&cand) } {
                Ok(lib) => return Ok(lib),
                Err(e) => last_err = format!("load {cand}: {e}"),
            }
        }
    }
    Err(format!(
        "{last_err} (set {env_var} to the library path if it lives elsewhere)"
    ))
}

impl Cublas {
    fn load() -> Result<Cublas, String> {
        unsafe {
            let lib = open_host_lib(
                "SMOLVM_CUBLAS_LIB",
                &["libcublas.so", "libcublas.so.13", "libcublas.so.12"],
            )?;
            let c = Cublas {
                create: sym(&lib, b"cublasCreate_v2\0")?,
                destroy: sym(&lib, b"cublasDestroy_v2\0")?,
                set_stream: sym(&lib, b"cublasSetStream_v2\0")?,
                sgemm: sym(&lib, b"cublasSgemm_v2\0")?,
                _lib: lib,
            };
            Ok(c)
        }
    }
}

/// Hand-declared nvcomp batched Deflate entry points (uniform batched ABI).
struct Nvcomp {
    _lib: Library,
    temp_size: unsafe extern "C" fn(usize, usize, *mut usize, usize) -> c_int,
    #[allow(clippy::type_complexity)]
    decompress: unsafe extern "C" fn(
        *const *const c_void, // device_compressed_ptrs
        *const usize,         // device_compressed_bytes
        *const usize,         // device_uncompressed_bytes
        *mut usize,           // device_actual_uncompressed_bytes (nullable)
        usize,                // batch_size
        *mut c_void,          // device_temp
        usize,                // temp_bytes
        *const *mut c_void,   // device_uncompressed_ptrs
        *mut c_int,           // device_statuses (nullable)
        *mut c_void,          // stream (CUstream)
    ) -> c_int,
}

impl Nvcomp {
    fn load() -> Result<Nvcomp, String> {
        let path = std::env::var("SMOLVM_NVCOMP_LIB")
            .map_err(|_| "SMOLVM_NVCOMP_LIB not set".to_string())?;
        unsafe {
            let lib = Library::new(&path).map_err(|e| format!("load {path}: {e}"))?;
            let n = Nvcomp {
                temp_size: sym(&lib, b"nvcompBatchedDeflateDecompressGetTempSizeEx\0")?,
                decompress: sym(&lib, b"nvcompBatchedDeflateDecompressAsync\0")?,
                _lib: lib,
            };
            Ok(n)
        }
    }
}

unsafe fn sym<T>(lib: &Library, name: &[u8]) -> Result<T, String> {
    let s: Symbol<T> = lib
        .get(name)
        .map_err(|e| format!("symbol {}: {e}", String::from_utf8_lossy(name)))?;
    // Transmute the borrowed Symbol into a bare fn pointer; `_lib` in the
    // struct keeps the library loaded for the pointer's whole lifetime.
    Ok(std::ptr::read(&s as *const Symbol<T> as *const T))
}

/// Resolve `primary`, falling back to `fallback` — for entry points whose
/// canonical name gained a `_v2` suffix in a later CUDA release.
unsafe fn sym2<T>(lib: &Library, primary: &[u8], fallback: &[u8]) -> Result<T, String> {
    sym(lib, primary).or_else(|_| sym(lib, fallback))
}

impl GpuBackend {
    /// Load the driver and resolve every entry point. Returns the library name
    /// + error string on failure so the caller can fall back (e.g. to CPU).
    pub fn load() -> Result<GpuBackend, String> {
        unsafe {
            let lib = Library::new(CUDA_LIB).map_err(|e| format!("load {CUDA_LIB}: {e}"))?;
            let b = GpuBackend {
                init: sym(&lib, b"cuInit\0")?,
                device_get_count: sym(&lib, b"cuDeviceGetCount\0")?,
                device_get_name: sym(&lib, b"cuDeviceGetName\0")?,
                device_total_mem: sym(&lib, b"cuDeviceTotalMem_v2\0")?,
                driver_get_version: sym(&lib, b"cuDriverGetVersion\0")?,
                device_get_attribute: sym(&lib, b"cuDeviceGetAttribute\0")?,
                device_get_uuid: sym2(&lib, b"cuDeviceGetUuid_v2\0", b"cuDeviceGetUuid\0")?,
                ctx_create: sym(&lib, b"cuCtxCreate_v2\0")?,
                ctx_destroy: sym(&lib, b"cuCtxDestroy_v2\0")?,
                ctx_set_current: sym(&lib, b"cuCtxSetCurrent\0")?,
                ctx_get_current: sym(&lib, b"cuCtxGetCurrent\0")?,
                primary_ctx_retain: sym(&lib, b"cuDevicePrimaryCtxRetain\0")?,
                primary_ctx_release: sym2(
                    &lib,
                    b"cuDevicePrimaryCtxRelease_v2\0",
                    b"cuDevicePrimaryCtxRelease\0",
                )?,
                module_load_data: sym(&lib, b"cuModuleLoadData\0")?,
                module_get_function: sym(&lib, b"cuModuleGetFunction\0")?,
                module_unload: sym(&lib, b"cuModuleUnload\0")?,
                func_get_param_info: sym(&lib, b"cuFuncGetParamInfo\0").ok(),
                func_set_attribute: sym(&lib, b"cuFuncSetAttribute\0")?,
                func_get_attribute: sym(&lib, b"cuFuncGetAttribute\0")?,
                mem_alloc: sym(&lib, b"cuMemAlloc_v2\0")?,
                mem_free: sym(&lib, b"cuMemFree_v2\0")?,
                memcpy_htod: sym(&lib, b"cuMemcpyHtoD_v2\0")?,
                memcpy_dtoh: sym(&lib, b"cuMemcpyDtoH_v2\0")?,
                memcpy_dtod: sym(&lib, b"cuMemcpyDtoD_v2\0")?,
                memset_d8: sym(&lib, b"cuMemsetD8_v2\0")?,
                mem_get_info: sym(&lib, b"cuMemGetInfo_v2\0")?,
                mem_host_register: sym(&lib, b"cuMemHostRegister_v2\0").ok(),
                mem_host_unregister: sym(&lib, b"cuMemHostUnregister\0").ok(),
                mem_host_alloc: sym(&lib, b"cuMemAllocHost_v2\0").ok(),
                mem_free_host: sym(&lib, b"cuMemFreeHost\0").ok(),
                launch_kernel: sym(&lib, b"cuLaunchKernel\0")?,
                ctx_synchronize: sym(&lib, b"cuCtxSynchronize\0")?,
                stream_create: sym(&lib, b"cuStreamCreate\0")?,
                stream_begin_capture: sym2(
                    &lib,
                    b"cuStreamBeginCapture_v2\0",
                    b"cuStreamBeginCapture\0",
                )?,
                thread_exchange_capture_mode: sym(&lib, b"cuThreadExchangeStreamCaptureMode\0")?,
                stream_end_capture: sym(&lib, b"cuStreamEndCapture\0")?,
                stream_get_capture_info: sym2(
                    &lib,
                    b"cuStreamGetCaptureInfo\0",
                    b"cuStreamGetCaptureInfo_v2\0",
                )?,
                graph_instantiate_with_flags: sym(&lib, b"cuGraphInstantiateWithFlags\0")?,
                graph_launch: sym(&lib, b"cuGraphLaunch\0")?,
                graph_exec_destroy: sym(&lib, b"cuGraphExecDestroy\0")?,
                graph_destroy: sym(&lib, b"cuGraphDestroy\0")?,
                graph_get_nodes: sym(&lib, b"cuGraphGetNodes\0")?,
                graph_create: sym(&lib, b"cuGraphCreate\0")?,
                graph_add_kernel_node: sym(&lib, b"cuGraphAddKernelNode_v2\0")?,
                graph_node_get_dependencies: sym(&lib, b"cuGraphNodeGetDependencies\0")?,
                graph_add_dependencies: sym(&lib, b"cuGraphAddDependencies\0")?,
                graph_node_get_type: sym(&lib, b"cuGraphNodeGetType\0")?,
                graph_kernel_node_get_params: sym(&lib, b"cuGraphKernelNodeGetParams_v2\0")?,
                graph_exec_kernel_node_set_params: sym(
                    &lib,
                    b"cuGraphExecKernelNodeSetParams_v2\0",
                )?,
                graph_memset_node_get_params: sym(&lib, b"cuGraphMemsetNodeGetParams\0")?,
                graph_exec_memset_node_set_params: sym(&lib, b"cuGraphExecMemsetNodeSetParams\0")?,
                graph_memcpy_node_get_params: sym(&lib, b"cuGraphMemcpyNodeGetParams\0")?,
                graph_exec_memcpy_node_set_params: sym(&lib, b"cuGraphExecMemcpyNodeSetParams\0")?,
                memset_d8_async: sym(&lib, b"cuMemsetD8Async\0")?,
                memcpy_dtod_async: sym2(&lib, b"cuMemcpyDtoDAsync_v2\0", b"cuMemcpyDtoDAsync\0")?,
                stream_destroy: sym2(&lib, b"cuStreamDestroy_v2\0", b"cuStreamDestroy\0")?,
                stream_synchronize: sym(&lib, b"cuStreamSynchronize\0")?,
                stream_query: sym(&lib, b"cuStreamQuery\0")?,
                stream_wait_event: sym(&lib, b"cuStreamWaitEvent\0")?,
                vmm_address_reserve: sym(&lib, b"cuMemAddressReserve\0").ok(),
                vmm_create: sym(&lib, b"cuMemCreate\0").ok(),
                vmm_map: sym(&lib, b"cuMemMap\0").ok(),
                vmm_set_access: sym(&lib, b"cuMemSetAccess\0").ok(),
                vmm_unmap: sym(&lib, b"cuMemUnmap\0").ok(),
                vmm_release: sym(&lib, b"cuMemRelease\0").ok(),
                vmm_address_free: sym(&lib, b"cuMemAddressFree\0").ok(),
                vmm_export: sym(&lib, b"cuMemExportToShareableHandle\0").ok(),
                vmm_import: sym(&lib, b"cuMemImportFromShareableHandle\0").ok(),
                vmm_granularity: sym(&lib, b"cuMemGetAllocationGranularity\0").ok(),
                event_query: sym(&lib, b"cuEventQuery\0")?,
                event_create: sym(&lib, b"cuEventCreate\0")?,
                event_destroy: sym2(&lib, b"cuEventDestroy_v2\0", b"cuEventDestroy\0")?,
                event_record: sym(&lib, b"cuEventRecord\0")?,
                event_synchronize: sym(&lib, b"cuEventSynchronize\0")?,
                event_elapsed_time: sym(&lib, b"cuEventElapsedTime\0")?,
                nvcomp: None,
                cublas: None,
                cublas_gen: None,
                cudnn_gen: None,
                cudnn_backend: None,
                vhandles: if std::env::var_os("SMOLVM_CUDA_CLONE_LAYOUT").is_some() {
                    // Clone worker: every channel serves the SAME guest, so
                    // all backend instances share ONE handle map. Per-channel
                    // snapshot adoption loses handles created after the
                    // snapshot (guest creates a cuBLAS handle on one channel,
                    // GEMMs flow on another → vh-miss → NOT_INITIALIZED).
                    static WORKER_VHANDLES: std::sync::OnceLock<
                        std::sync::Arc<std::sync::Mutex<std::collections::HashMap<u64, u64>>>,
                    > = std::sync::OnceLock::new();
                    WORKER_VHANDLES
                        .get_or_init(|| {
                            std::sync::Arc::new(std::sync::Mutex::new(
                                std::collections::HashMap::new(),
                            ))
                        })
                        .clone()
                } else {
                    std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()))
                },
                cublaslt: None,
                cudnn_bn: None,
                guest_ram: Vec::new(),
                #[cfg(unix)]
                proc_mem: None,
                #[cfg(unix)]
                proc_mem_regions: Vec::new(),
                registered: Vec::new(),
                guest_ram_pin_tried: false,
                staging: (0, 0),
                _lib: lib,
            };
            Ok(b)
        }
    }
}

/// Map a raw `CUresult`: 0 → `Ok`, else the code as `Err`.
fn chk(code: CuResultCode) -> CuResult<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(code)
    }
}

/// Registry of live sessions' `vhandles` maps, keyed by lineage token. Holds
/// `Weak` refs so a session's entry evaporates when its connection closes; a
/// fork clone resuming a dead token just starts with an empty map. Lets a
/// clone's fresh connection adopt a snapshot of its (frozen) parent's handle
/// map — see [`GpuBackend::begin_session`].
type VhMap = std::sync::Mutex<std::collections::HashMap<u64, u64>>;
static HANDOFF: std::sync::Mutex<Option<std::collections::HashMap<u64, std::sync::Weak<VhMap>>>> =
    std::sync::Mutex::new(None);

fn next_lineage_token() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// Adopt `resume_token`'s (frozen) descriptor map into `dst`, then register
/// `dst` under a fresh token and return it. The parent's entries are real host
/// pointers valid in the shared primary context, so copying id→pointer pairs is
/// enough for a fork clone to keep using them. Closed sessions' entries (dead
/// `Weak`s) are pruned on the way through.
fn handoff_register(dst: &std::sync::Arc<VhMap>, resume_token: u64) -> u64 {
    let mut reg = HANDOFF.lock().unwrap();
    let reg = reg.get_or_insert_with(std::collections::HashMap::new);
    if resume_token != 0 {
        if let Some(parent) = reg.get(&resume_token).and_then(|w| w.upgrade()) {
            // ptr_eq guard: in a clone worker every backend shares ONE map
            // (see the WORKER_VHANDLES init) — self-adoption would deadlock
            // on the same mutex and is a no-op anyway.
            if !std::sync::Arc::ptr_eq(&parent, dst) {
                *dst.lock().unwrap() = parent.lock().unwrap().clone();
            }
        }
    }
    let token = next_lineage_token();
    reg.retain(|_, w| w.strong_count() > 0);
    reg.insert(token, std::sync::Arc::downgrade(dst));
    token
}

impl Backend for GpuBackend {
    fn init(&mut self) -> CuResult<()> {
        unsafe { chk((self.init)(0)) }
    }
    fn begin_session(&mut self, resume_token: u64) -> u64 {
        handoff_register(&self.vhandles, resume_token)
    }
    fn device_get_count(&mut self) -> CuResult<i32> {
        let mut n = 0;
        unsafe { chk((self.device_get_count)(&mut n))? };
        Ok(n)
    }
    fn device_get_name(&mut self, device: i32) -> CuResult<String> {
        let mut buf = [0i8; 256];
        unsafe {
            chk((self.device_get_name)(
                buf.as_mut_ptr() as *mut c_char,
                256,
                device,
            ))?
        };
        let name = unsafe { CStr::from_ptr(buf.as_ptr() as *const c_char) }
            .to_string_lossy()
            .into_owned();
        Ok(name)
    }
    fn device_total_mem(&mut self, device: i32) -> CuResult<u64> {
        let mut bytes: usize = 0;
        unsafe { chk((self.device_total_mem)(&mut bytes, device))? };
        Ok(bytes as u64)
    }
    fn driver_get_version(&mut self) -> CuResult<i32> {
        let mut v = 0;
        unsafe { chk((self.driver_get_version)(&mut v))? };
        Ok(v)
    }
    fn device_get_attribute(&mut self, attrib: i32, device: i32) -> CuResult<i32> {
        let mut v = 0;
        unsafe { chk((self.device_get_attribute)(&mut v, attrib, device))? };
        Ok(v)
    }
    fn device_get_uuid(&mut self, device: i32) -> CuResult<[u8; 16]> {
        let mut uuid = [0u8; 16];
        unsafe { chk((self.device_get_uuid)(uuid.as_mut_ptr(), device))? };
        Ok(uuid)
    }
    fn ctx_create(&mut self, device: i32) -> CuResult<u64> {
        let mut ctx: *mut c_void = std::ptr::null_mut();
        unsafe { chk((self.ctx_create)(&mut ctx, 0, device))? };
        Ok(ctx as u64)
    }
    fn ctx_destroy(&mut self, ctx: u64) -> CuResult<()> {
        unsafe { chk((self.ctx_destroy)(ctx as *mut c_void)) }
    }
    fn primary_ctx_retain(&mut self, device: i32) -> CuResult<u64> {
        let mut ctx: *mut c_void = std::ptr::null_mut();
        unsafe { chk((self.primary_ctx_retain)(&mut ctx, device))? };
        // Unlike cuCtxCreate, retain does not bind the context to the calling
        // thread — bind it here so every later call on this connection's
        // serving thread (module load, alloc, launch) has a current context.
        unsafe { chk((self.ctx_set_current)(ctx))? };
        Ok(ctx as u64)
    }
    fn primary_ctx_release(&mut self, device: i32) -> CuResult<()> {
        unsafe { chk((self.primary_ctx_release)(device)) }
    }
    fn module_load_data(&mut self, image: &[u8]) -> CuResult<u64> {
        // cuModuleLoadData reads a NUL-terminated PTX string or a cubin blob.
        // Ensure a trailing NUL so PTX text is well-formed for the JIT.
        let mut buf = image.to_vec();
        if !buf.ends_with(&[0]) {
            buf.push(0);
        }
        let mut module: *mut c_void = std::ptr::null_mut();
        let code = unsafe { (self.module_load_data)(&mut module, buf.as_ptr() as *const c_void) };
        if code != 0 {
            // Debug: keep failing images for cuobjdump post-mortem.
            if let Some(dir) = std::env::var_os("SMOLVM_CUDA_DUMP_BAD_MODULES") {
                let n = buf.len();
                let path = std::path::Path::new(&dir).join(format!("badmod-{code}-{n}.bin"));
                let _ = std::fs::write(path, &buf);
            }
            return Err(code);
        }
        Ok(module as u64)
    }
    fn module_get_function(&mut self, module: u64, name: &str) -> CuResult<u64> {
        let cname = CString::new(name).map_err(|_| super::CUDA_ERROR_NOT_FOUND)?;
        let mut func: *mut c_void = std::ptr::null_mut();
        unsafe {
            chk((self.module_get_function)(
                &mut func,
                module as *mut c_void,
                cname.as_ptr(),
            ))?
        };
        Ok(func as u64)
    }
    fn module_unload(&mut self, module: u64) -> CuResult<()> {
        unsafe { chk((self.module_unload)(module as *mut c_void)) }
    }
    fn func_get_param_info(&mut self, function: u64) -> CuResult<Vec<u32>> {
        // CUDA 12.4+. Walk parameter indices until INVALID_VALUE marks the end.
        const CUDA_ERROR_INVALID_VALUE: i32 = 1;
        const CUDA_ERROR_NOT_SUPPORTED: i32 = 801;
        let f = self.func_get_param_info.ok_or(CUDA_ERROR_NOT_SUPPORTED)?;
        let mut sizes = Vec::new();
        for i in 0.. {
            let (mut offset, mut size): (usize, usize) = (0, 0);
            let code = unsafe { f(function as *mut c_void, i, &mut offset, &mut size) };
            match code {
                0 => sizes.push(size as u32),
                CUDA_ERROR_INVALID_VALUE => break,
                other => return Err(other),
            }
        }
        Ok(sizes)
    }
    fn func_set_attribute(&mut self, function: u64, attrib: i32, value: i32) -> CuResult<()> {
        unsafe {
            chk((self.func_set_attribute)(
                function as *mut c_void,
                attrib,
                value,
            ))
        }
    }
    fn func_get_attribute(&mut self, function: u64, attrib: i32) -> CuResult<i32> {
        let mut v = 0;
        unsafe {
            chk((self.func_get_attribute)(
                &mut v,
                attrib,
                function as *mut c_void,
            ))?
        };
        Ok(v)
    }
    fn mem_alloc(&mut self, bytes: u64) -> CuResult<u64> {
        let mut dptr: u64 = 0;
        unsafe { chk((self.mem_alloc)(&mut dptr, bytes as usize))? };
        Ok(dptr)
    }
    fn mem_free(&mut self, dptr: u64) -> CuResult<()> {
        unsafe { chk((self.mem_free)(dptr)) }
    }
    fn memcpy_htod(&mut self, dptr: u64, data: &[u8], stream: u64) -> CuResult<()> {
        self.wait_stream(stream)?;
        unsafe {
            chk((self.memcpy_htod)(
                dptr,
                data.as_ptr() as *const c_void,
                data.len(),
            ))
        }
    }
    fn memcpy_dtoh(&mut self, dptr: u64, bytes: u64, stream: u64) -> CuResult<Vec<u8>> {
        self.wait_stream(stream)?;
        let mut out = vec![0u8; bytes as usize];
        unsafe {
            chk((self.memcpy_dtoh)(
                out.as_mut_ptr() as *mut c_void,
                dptr,
                bytes as usize,
            ))?
        };
        Ok(out)
    }
    fn memcpy_dtod(&mut self, dst: u64, src: u64, bytes: u64) -> CuResult<()> {
        unsafe { chk((self.memcpy_dtod)(dst, src, bytes as usize)) }
    }
    fn memset_d8(&mut self, dptr: u64, value: u8, bytes: u64) -> CuResult<()> {
        unsafe { chk((self.memset_d8)(dptr, value, bytes as usize)) }
    }
    fn mem_get_info(&mut self) -> CuResult<(u64, u64)> {
        let (mut free, mut total): (usize, usize) = (0, 0);
        unsafe { chk((self.mem_get_info)(&mut free, &mut total))? };
        Ok((free as u64, total as u64))
    }

    // The shared-memory data channel is Linux-only (`crate::shm`); on other
    // platforms these fall back to the trait's not-supported default.
    #[cfg(target_os = "linux")]
    fn memcpy_shm_htod(&mut self, dptr: u64, offset: u64, size: u64, stream: u64) -> CuResult<()> {
        // Read straight from the shared region (no bytes over the socket) and
        // DMA to the GPU — one copy instead of three.
        self.wait_stream(stream)?;
        let region = crate::shm::get_or_create().ok_or(super::CUDA_ERROR_NOT_FOUND)?;
        let src = region
            .checked(offset, size)
            .ok_or(super::CUDA_ERROR_INVALID_HANDLE)?;
        unsafe {
            chk((self.memcpy_htod)(
                dptr,
                src as *const c_void,
                size as usize,
            ))
        }
    }
    #[cfg(target_os = "linux")]
    fn memcpy_shm_dtoh(&mut self, offset: u64, dptr: u64, size: u64, stream: u64) -> CuResult<()> {
        self.wait_stream(stream)?;
        let region = crate::shm::get_or_create().ok_or(super::CUDA_ERROR_NOT_FOUND)?;
        let dst = region
            .checked(offset, size)
            .ok_or(super::CUDA_ERROR_INVALID_HANDLE)?;
        unsafe { chk((self.memcpy_dtoh)(dst as *mut c_void, dptr, size as usize)) }
    }

    fn set_guest_ram(&mut self, regions: Vec<(u64, u64, u64)>) {
        self.guest_ram = regions;
    }

    #[cfg(unix)]
    fn set_guest_ram_procmem(&mut self, pid: u32, regions: Vec<(u64, u64, u64)>) -> bool {
        // Only install the clone regions if we can actually open its /proc/mem.
        // Their host VAs live in the CLONE's address space, so without proc_mem
        // the normal GPA path would deref foreign pointers — leave guest_ram
        // empty on failure so memcpy_gpa returns NOT_FOUND and the shim falls
        // back to the (safe) ring-copy path instead.
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(format!("/proc/{pid}/mem"))
        {
            Ok(f) => {
                self.proc_mem = Some(f);
                self.proc_mem_regions = regions;
                true
            }
            Err(e) => {
                eprintln!(
                    "clone-worker: /proc/{pid}/mem open failed ({e}); proc-mem off, ring copy"
                );
                false
            }
        }
    }

    fn gpa_to_hva(&mut self, gpa: u64, len: u64) -> Option<u64> {
        self.guest_ram.iter().find_map(|&(gs, hva, rlen)| {
            (gpa >= gs && gpa.checked_add(len)? <= gs + rlen).then(|| hva + (gpa - gs))
        })
    }

    fn mem_address_reserve(&mut self, size: u64, align: u64) -> CuResult<u64> {
        let f = self
            .vmm_address_reserve
            .ok_or(super::CUDA_ERROR_NOT_SUPPORTED)?;
        let mut va = 0u64;
        unsafe { chk(f(&mut va, size as usize, align as usize, 0, 0))? };
        Ok(va)
    }
    fn mem_create(&mut self, size: u64, device: i32) -> CuResult<u64> {
        let f = self.vmm_create.ok_or(super::CUDA_ERROR_NOT_SUPPORTED)?;
        let prop = vmm_prop(device);
        let mut h = 0u64;
        unsafe { chk(f(&mut h, size as usize, &prop, 0))? };
        Ok(h)
    }
    fn mem_map(&mut self, va: u64, size: u64, offset: u64, handle: u64) -> CuResult<()> {
        let f = self.vmm_map.ok_or(super::CUDA_ERROR_NOT_SUPPORTED)?;
        unsafe { chk(f(va, size as usize, offset as usize, handle, 0)) }
    }
    fn mem_set_access(&mut self, va: u64, size: u64, device: i32) -> CuResult<()> {
        let f = self.vmm_set_access.ok_or(super::CUDA_ERROR_NOT_SUPPORTED)?;
        let desc = VmmAccessDesc {
            location_type: 1,
            location_id: device,
            flags: 3,
        };
        unsafe { chk(f(va, size as usize, &desc, 1)) }
    }
    fn mem_set_access_ro(&mut self, va: u64, size: u64, device: i32) -> CuResult<()> {
        let f = self.vmm_set_access.ok_or(super::CUDA_ERROR_NOT_SUPPORTED)?;
        let desc = VmmAccessDesc {
            location_type: 1,
            location_id: device,
            flags: 1, // CU_MEM_ACCESS_FLAGS_PROT_READ
        };
        unsafe { chk(f(va, size as usize, &desc, 1)) }
    }
    fn mem_unmap(&mut self, va: u64, size: u64) -> CuResult<()> {
        let f = self.vmm_unmap.ok_or(super::CUDA_ERROR_NOT_SUPPORTED)?;
        unsafe { chk(f(va, size as usize)) }
    }
    fn mem_release(&mut self, handle: u64) -> CuResult<()> {
        let f = self.vmm_release.ok_or(super::CUDA_ERROR_NOT_SUPPORTED)?;
        unsafe { chk(f(handle)) }
    }
    fn mem_address_free(&mut self, va: u64, size: u64) -> CuResult<()> {
        let f = self
            .vmm_address_free
            .ok_or(super::CUDA_ERROR_NOT_SUPPORTED)?;
        unsafe { chk(f(va, size as usize)) }
    }
    // ---- Path 3 address-preserving isolation primitives ----
    /// Reserve a VA at a FIXED address (`cuMemAddressReserve` addr hint), so a
    /// clone process can place memory at the golden's exact virtual address.
    fn mem_address_reserve_fixed(&mut self, size: u64, align: u64, fixed: u64) -> CuResult<u64> {
        let f = self
            .vmm_address_reserve
            .ok_or(super::CUDA_ERROR_NOT_SUPPORTED)?;
        let mut va = 0u64;
        unsafe { chk(f(&mut va, size as usize, align as usize, fixed, 0))? };
        Ok(va)
    }
    /// `cuMemCreate` with POSIX-fd handle type requested, so the physical can be
    /// IPC-exported to a clone process.
    fn mem_create_exportable(&mut self, size: u64, device: i32) -> CuResult<u64> {
        let f = self.vmm_create.ok_or(super::CUDA_ERROR_NOT_SUPPORTED)?;
        let mut prop = vmm_prop(device);
        prop.requested_handle_types = 1; // CU_MEM_HANDLE_TYPE_POSIX_FILE_DESCRIPTOR
        let mut h = 0u64;
        unsafe { chk(f(&mut h, size as usize, &prop, 0))? };
        Ok(h)
    }
    /// Export a physical handle to a POSIX fd (`cuMemExportToShareableHandle`).
    fn mem_export_handle(&mut self, handle: u64) -> CuResult<i32> {
        let f = self.vmm_export.ok_or(super::CUDA_ERROR_NOT_SUPPORTED)?;
        let mut fd: c_int = -1;
        unsafe { chk(f(&mut fd, handle, 1, 0))? }; // 1 = POSIX_FILE_DESCRIPTOR
        Ok(fd as i32)
    }
    /// Import a physical handle from a POSIX fd (`cuMemImportFromShareableHandle`).
    /// The fd's int value is passed as the `osHandle` pointer, per the CUDA ABI.
    fn mem_import_handle(&mut self, fd: i32) -> CuResult<u64> {
        let f = self.vmm_import.ok_or(super::CUDA_ERROR_NOT_SUPPORTED)?;
        let mut h = 0u64;
        unsafe { chk(f(&mut h, fd as usize as *mut c_void, 1))? };
        Ok(h)
    }
    fn mem_get_allocation_granularity(&mut self, device: i32, flags: u32) -> CuResult<u64> {
        let f = self
            .vmm_granularity
            .ok_or(super::CUDA_ERROR_NOT_SUPPORTED)?;
        let prop = vmm_prop(device);
        let mut g = 0usize;
        unsafe { chk(f(&mut g, &prop, flags))? };
        Ok(g as u64)
    }

    fn memcpy_gpa_htod(&mut self, dptr: u64, segments: &[(u64, u64)], stream: u64) -> CuResult<()> {
        #[cfg(unix)]
        if self.proc_mem.is_some() {
            self.wait_stream(stream)?;
            return self.gpa_procmem(dptr, segments, false);
        }
        if self.guest_ram.is_empty() {
            return Err(super::CUDA_ERROR_NOT_FOUND);
        }
        self.wait_stream(stream)?;
        self.ensure_guest_ram_pinned();
        zc_trace_segments("H2D", segments);
        // Few segments: DMA each straight from its guest-RAM host mapping to the
        // right device offset — no staging copy. The common contiguous case is a
        // single big DMA at full pinned bandwidth.
        if segments.len() <= ZC_DIRECT_MAX_SEGMENTS {
            let mut off = 0u64;
            for &(gpa, len) in segments {
                let src = self.gpa_to_host(gpa, len)?;
                unsafe {
                    chk((self.memcpy_htod)(
                        dptr + off,
                        src as *const c_void,
                        len as usize,
                    ))?
                };
                off += len;
            }
            return Ok(());
        }
        // Heavily fragmented: gather into one pinned staging buffer and issue a
        // single DMA, avoiding thousands of tiny per-segment transfers.
        let total: u64 = segments.iter().map(|(_, l)| *l).sum();
        if let Some(stg) = self.ensure_staging(total as usize) {
            let mut off = 0usize;
            for &(gpa, len) in segments {
                let src = self.gpa_to_host(gpa, len)?;
                unsafe { std::ptr::copy_nonoverlapping(src, stg.add(off), len as usize) };
                off += len as usize;
            }
            return unsafe {
                chk((self.memcpy_htod)(
                    dptr,
                    stg as *const c_void,
                    total as usize,
                ))
            };
        }
        // No staging available → fall back to direct per-segment DMA.
        let mut off = 0u64;
        for &(gpa, len) in segments {
            let src = self.gpa_to_host(gpa, len)?;
            unsafe {
                chk((self.memcpy_htod)(
                    dptr + off,
                    src as *const c_void,
                    len as usize,
                ))?
            };
            off += len;
        }
        Ok(())
    }

    fn memcpy_gpa_dtoh(&mut self, dptr: u64, segments: &[(u64, u64)], stream: u64) -> CuResult<()> {
        #[cfg(unix)]
        if self.proc_mem.is_some() {
            self.wait_stream(stream)?;
            return self.gpa_procmem(dptr, segments, true);
        }
        if self.guest_ram.is_empty() {
            return Err(super::CUDA_ERROR_NOT_FOUND);
        }
        self.wait_stream(stream)?;
        self.ensure_guest_ram_pinned();
        zc_trace_segments("D2H", segments);
        if segments.len() <= ZC_DIRECT_MAX_SEGMENTS {
            let mut off = 0u64;
            for &(gpa, len) in segments {
                let dst = self.gpa_to_host(gpa, len)?;
                unsafe {
                    chk((self.memcpy_dtoh)(
                        dst as *mut c_void,
                        dptr + off,
                        len as usize,
                    ))?
                };
                off += len;
            }
            return Ok(());
        }
        // Heavily fragmented: one DMA into pinned staging, then scatter to the
        // guest segments.
        let total: u64 = segments.iter().map(|(_, l)| *l).sum();
        if let Some(stg) = self.ensure_staging(total as usize) {
            unsafe { chk((self.memcpy_dtoh)(stg as *mut c_void, dptr, total as usize))? };
            let mut off = 0usize;
            for &(gpa, len) in segments {
                let dst = self.gpa_to_host(gpa, len)?;
                unsafe {
                    std::ptr::copy_nonoverlapping(stg.add(off) as *const u8, dst, len as usize)
                };
                off += len as usize;
            }
            return Ok(());
        }
        let mut off = 0u64;
        for &(gpa, len) in segments {
            let dst = self.gpa_to_host(gpa, len)?;
            unsafe {
                chk((self.memcpy_dtoh)(
                    dst as *mut c_void,
                    dptr + off,
                    len as usize,
                ))?
            };
            off += len;
        }
        Ok(())
    }
    fn launch_kernel(
        &mut self,
        function: u64,
        grid: [u32; 3],
        block: [u32; 3],
        shared_bytes: u32,
        stream: u64,
        params: &[Vec<u8>],
    ) -> CuResult<()> {
        // The Driver API wants `void* kernelParams[]`, each pointing at one
        // argument's value. Point at each param blob in place (CUDA only reads).
        let mut ptrs: Vec<*mut c_void> = params.iter().map(|p| p.as_ptr() as *mut c_void).collect();
        let params_ptr = if ptrs.is_empty() {
            std::ptr::null_mut()
        } else {
            ptrs.as_mut_ptr()
        };
        unsafe {
            chk((self.launch_kernel)(
                function as *mut c_void,
                grid[0],
                grid[1],
                grid[2],
                block[0],
                block[1],
                block[2],
                shared_bytes,
                stream as *mut c_void,
                params_ptr,
                std::ptr::null_mut(),
            ))
        }
    }
    fn ctx_synchronize(&mut self) -> CuResult<()> {
        unsafe { chk((self.ctx_synchronize)()) }
    }
    fn stream_create(&mut self, flags: u32) -> CuResult<u64> {
        let mut s: *mut c_void = std::ptr::null_mut();
        unsafe { chk((self.stream_create)(&mut s, flags))? };
        if std::env::var_os("SMOLVM_CUDA_HOST_OPLOG").is_some() {
            eprintln!("[strm] host created {:#x}", s as u64);
        }
        Ok(s as u64)
    }
    fn thread_exchange_capture_mode(&mut self, mode: i32) -> CuResult<i32> {
        let mut m: c_int = mode;
        unsafe { chk((self.thread_exchange_capture_mode)(&mut m))? };
        Ok(m)
    }
    fn stream_begin_capture(&mut self, stream: u64, mode: i32) -> CuResult<()> {
        unsafe { chk((self.stream_begin_capture)(stream as *mut c_void, mode)) }
    }
    fn stream_end_capture(&mut self, stream: u64) -> CuResult<u64> {
        let mut g: *mut c_void = std::ptr::null_mut();
        unsafe { chk((self.stream_end_capture)(stream as *mut c_void, &mut g))? };
        Ok(g as u64)
    }
    fn stream_capture_info(&mut self, stream: u64) -> CuResult<(u64, u64)> {
        let mut status: c_int = 0;
        let mut id: u64 = 0;
        unsafe {
            chk((self.stream_get_capture_info)(
                stream as *mut c_void,
                &mut status,
                &mut id,
            ))?
        };
        Ok((status as u64, id))
    }
    fn graph_instantiate(&mut self, graph: u64) -> CuResult<u64> {
        let mut e: *mut c_void = std::ptr::null_mut();
        unsafe {
            chk((self.graph_instantiate_with_flags)(
                &mut e,
                graph as *mut c_void,
                0,
            ))?
        };
        Ok(e as u64)
    }
    fn graph_launch(&mut self, graph_exec: u64, stream: u64) -> CuResult<()> {
        unsafe {
            chk((self.graph_launch)(
                graph_exec as *mut c_void,
                stream as *mut c_void,
            ))
        }
    }
    fn graph_exec_patch(
        &mut self,
        exec: u64,
        graph: u64,
        trans: &[(u64, u64, u64)],
    ) -> CuResult<()> {
        // Enumerate the graph's nodes and rewrite each node's device-pointer
        // params through `trans`, so a fork clone's inherited cudagraph writes its
        // OWN private copies instead of the golden's memory (Path 2).
        let mut count: usize = 0;
        unsafe {
            chk((self.graph_get_nodes)(
                graph as *mut c_void,
                std::ptr::null_mut(),
                &mut count,
            ))?
        };
        if count == 0 {
            return Ok(());
        }
        let mut nodes: Vec<*mut c_void> = vec![std::ptr::null_mut(); count];
        unsafe {
            chk((self.graph_get_nodes)(
                graph as *mut c_void,
                nodes.as_mut_ptr(),
                &mut count,
            ))?
        };
        let dbg = std::env::var_os("SMOLVM_CUDA_GRAPH_DEBUG").is_some();
        // Diagnostic: rewrite translated pointers to a definitely-unmapped address
        // instead of the real copy. If the patched exec is what actually runs, the
        // clone must crash with an illegal access; if it keeps producing the same
        // garbage without crashing, the patched exec is NOT the one being launched.
        let poison = std::env::var_os("SMOLVM_CUDA_GRAPH_POISON").is_some();
        const POISON: u64 = 0x0000_dead_dead_0000;
        if dbg {
            eprintln!("[gpatch] graph {graph:#x} exec {exec:#x}: {count} nodes");
        }
        let mut type_hist: std::collections::HashMap<c_int, u32> = std::collections::HashMap::new();
        // Diagnostic: find the MISSED pointer class. Scan every kernel param's raw
        // bytes (8-aligned) for values that look like device VAs but are NOT in any
        // trans range. Under full-copy (COPY_ALL=1) every mutable buffer is in trans,
        // so any hit here is a pointer we fail to translate — keyed by param size to
        // reveal struct-embedded pointers (size != 8) vs plain missed 8-byte args.
        const VA_LO: u64 = 0x10_0000_0000; // 64 GiB
        const VA_HI: u64 = 0x1_0000_0000_0000; // 256 TiB
        let mut missed_by_size: std::collections::HashMap<usize, u32> =
            std::collections::HashMap::new();
        let mut missed_examples: Vec<(usize, u64)> = Vec::new();
        for &node in nodes.iter().take(count) {
            let mut ty: c_int = -1;
            unsafe { chk((self.graph_node_get_type)(node, &mut ty))? };
            *type_hist.entry(ty).or_insert(0) += 1;
            match ty {
                0 => {
                    // KERNEL node: translate 8-byte pointer args (sized via the
                    // function's param info; args are stored as pointers-to-values).
                    let mut kp: KernelNodeParams = unsafe { std::mem::zeroed() };
                    unsafe { chk((self.graph_kernel_node_get_params)(node, &mut kp))? };
                    if kp.kernel_params.is_null() {
                        // Args packed via `extra` (CU_LAUNCH_PARAM_BUFFER_*): an opaque
                        // blob we don't parse, so we can't translate any device
                        // pointers inside it. Fail loud rather than launch with the
                        // golden's addresses (silent cross-clone corruption). opt-350m
                        // never hits this; a model that does must use enforce_eager.
                        eprintln!(
                            "[gpatch] kernel node {:#x} packs args via `extra` (untranslatable); \
                             refusing to launch this inherited graph in an isolated clone. \
                             Use enforce_eager for this model.",
                            kp.func as u64
                        );
                        return Err(super::CUDA_ERROR_NOT_SUPPORTED);
                    }
                    let sizes = self.func_get_param_info(kp.func as u64)?;
                    // Copy EVERY arg value (full size, 8-byte-aligned) into our own
                    // buffer, translating 8-byte pointers, and point the new
                    // kernelParams entirely into it — never reuse the driver's
                    // returned arg pointers.
                    let mut offsets = Vec::with_capacity(sizes.len());
                    let mut total = 0usize;
                    for &sz in &sizes {
                        total = total.next_multiple_of(8);
                        offsets.push(total);
                        total += sz as usize;
                    }
                    let mut buf = vec![0u8; total.max(8)];
                    let mut changed = false;
                    for (i, &sz) in sizes.iter().enumerate() {
                        let sz = sz as usize;
                        let argptr = unsafe { *kp.kernel_params.add(i) } as *const u8;
                        if argptr.is_null() || sz == 0 {
                            continue;
                        }
                        let o = offsets[i];
                        unsafe {
                            std::ptr::copy_nonoverlapping(argptr, buf.as_mut_ptr().add(o), sz);
                        }
                        // Translate EVERY 8-byte-aligned device pointer embedded in
                        // this param, not just standalone 8-byte pointer args. vLLM's
                        // attention/sampling kernels pass large by-value structs (e.g.
                        // 360 B) that embed many device pointers; those must be
                        // redirected to the clone's private copies too. A window is
                        // rewritten only when its value lands inside a known golden
                        // allocation range (`xlat_range` returns a different address),
                        // so shared read-only weights and scalar fields are untouched.
                        let mut w = 0usize;
                        while w + 8 <= sz {
                            let v = u64::from_ne_bytes(buf[o + w..o + w + 8].try_into().unwrap());
                            let t = xlat_range(trans, v);
                            if t != v {
                                let nw = if poison { POISON } else { t };
                                buf[o + w..o + w + 8].copy_from_slice(&nw.to_ne_bytes());
                                changed = true;
                            } else if dbg && (VA_LO..VA_HI).contains(&v) {
                                *missed_by_size.entry(sz).or_insert(0) += 1;
                                if missed_examples.len() < 12 {
                                    missed_examples.push((sz, v));
                                }
                            }
                            w += 8;
                        }
                    }
                    if !changed {
                        continue;
                    }
                    let new_ptrs: Vec<*mut c_void> = offsets
                        .iter()
                        .map(|&o| unsafe { buf.as_mut_ptr().add(o) } as *mut c_void)
                        .collect();
                    let mut kp2 = kp;
                    kp2.kernel_params = new_ptrs.as_ptr() as *mut *mut c_void;
                    let rc = unsafe {
                        (self.graph_exec_kernel_node_set_params)(exec as *mut c_void, node, &kp2)
                    };
                    if dbg || rc != 0 {
                        eprintln!(
                            "[gpatch] KERNEL func={:#x} nargs={} extra_null={} rc={rc}",
                            kp.func as u64,
                            sizes.len(),
                            kp.extra.is_null()
                        );
                    }
                    chk(rc)?;
                }
                2 => {
                    // MEMSET node: translate the destination.
                    let mut mp: MemsetNodeParams = unsafe { std::mem::zeroed() };
                    unsafe { chk((self.graph_memset_node_get_params)(node, &mut mp))? };
                    let t = xlat_range(trans, mp.dst);
                    if t != mp.dst {
                        mp.dst = if poison { POISON } else { t };
                        let mut ctx: *mut c_void = std::ptr::null_mut();
                        unsafe { chk((self.ctx_get_current)(&mut ctx))? };
                        unsafe {
                            chk((self.graph_exec_memset_node_set_params)(
                                exec as *mut c_void,
                                node,
                                &mp,
                                ctx,
                            ))?
                        };
                    }
                }
                1 => {
                    // MEMCPY node: translate src/dst device pointers.
                    let mut cp: Memcpy3D = unsafe { std::mem::zeroed() };
                    unsafe { chk((self.graph_memcpy_node_get_params)(node, &mut cp))? };
                    let (ns, nd) = (
                        xlat_range(trans, cp.src_device),
                        xlat_range(trans, cp.dst_device),
                    );
                    if ns != cp.src_device || nd != cp.dst_device {
                        cp.src_device = if poison && ns != cp.src_device {
                            POISON
                        } else {
                            ns
                        };
                        cp.dst_device = if poison && nd != cp.dst_device {
                            POISON
                        } else {
                            nd
                        };
                        let mut ctx: *mut c_void = std::ptr::null_mut();
                        unsafe { chk((self.ctx_get_current)(&mut ctx))? };
                        let rc = unsafe {
                            (self.graph_exec_memcpy_node_set_params)(
                                exec as *mut c_void,
                                node,
                                &cp,
                                ctx,
                            )
                        };
                        if dbg || rc != 0 {
                            eprintln!("[gpatch] MEMCPY src->{ns:#x} dst->{nd:#x} rc={rc}");
                        }
                        chk(rc)?;
                    }
                }
                // Host(3), empty(5), wait-event(6), event-record(7), ext-sema
                // signal(8)/wait(9): carry no device pointers we must translate.
                3 | 5 | 6 | 7 | 8 | 9 => {}
                // Child-graph(4), mem-alloc(10)/free(11), batch-mem-op(12) and any
                // future type CAN reference device memory we don't yet translate.
                // Fail loud rather than replay the golden's addresses (silent
                // corruption); the clone should fall back to enforce_eager.
                other => {
                    eprintln!(
                        "[gpatch] unsupported graph node type {other} in an isolated clone's \
                         inherited graph; refusing to launch (would corrupt across clones). \
                         Use enforce_eager for this model."
                    );
                    return Err(super::CUDA_ERROR_NOT_SUPPORTED);
                }
            }
        }
        if dbg {
            eprintln!("[gpatch] node types (type:count): {type_hist:?}");
            if missed_by_size.is_empty() {
                eprintln!(
                    "[gpatch] MISSED-CLASS scan: 0 untranslated device-VA values in kernel params"
                );
            } else {
                let mut sizes: Vec<(usize, u32)> = missed_by_size.into_iter().collect();
                sizes.sort_unstable();
                eprintln!(
                    "[gpatch] MISSED-CLASS scan: untranslated device-VA values by param size {sizes:?}; examples (size,val) {:#x?}",
                    &missed_examples[..missed_examples.len().min(12)]
                );
            }
        }
        Ok(())
    }
    fn graph_exec_destroy(&mut self, graph_exec: u64) -> CuResult<()> {
        unsafe { chk((self.graph_exec_destroy)(graph_exec as *mut c_void)) }
    }
    fn graph_destroy(&mut self, graph: u64) -> CuResult<()> {
        unsafe { chk((self.graph_destroy)(graph as *mut c_void)) }
    }
    fn graph_get_node_count(&mut self, graph: u64) -> CuResult<u64> {
        let mut n: usize = 0;
        unsafe {
            chk((self.graph_get_nodes)(
                graph as *mut c_void,
                std::ptr::null_mut(),
                &mut n,
            ))?
        };
        Ok(n as u64)
    }
    fn graph_introspect(&mut self, graph: u64) -> CuResult<Option<super::GraphSer>> {
        // Enumerate the golden graph's nodes.
        let mut count: usize = 0;
        unsafe {
            chk((self.graph_get_nodes)(
                graph as *mut c_void,
                std::ptr::null_mut(),
                &mut count,
            ))?
        };
        if count == 0 {
            // A working captured graph that reports zero nodes is OPAQUE, not
            // empty — torch.compile(reduce-overhead)'s cudagraph trees hide
            // their kernels from cuGraphGetNodes. Rebuilding it would produce a
            // genuinely empty graph whose replay silently returns wrong data
            // (stale/zero outputs); skipping keeps the inherited exec, which
            // fails loud in the clone instead.
            return Ok(None);
        }
        let mut nodes: Vec<*mut c_void> = vec![std::ptr::null_mut(); count];
        unsafe {
            chk((self.graph_get_nodes)(
                graph as *mut c_void,
                nodes.as_mut_ptr(),
                &mut count,
            ))?
        };
        // Node pointer -> index, for turning dependency edges into indices.
        let idx: std::collections::HashMap<usize, u32> = nodes
            .iter()
            .take(count)
            .enumerate()
            .map(|(i, &n)| (n as usize, i as u32))
            .collect();
        let mut out = super::GraphSer::default();
        for &node in nodes.iter().take(count) {
            let mut ty: c_int = -1;
            unsafe { chk((self.graph_node_get_type)(node, &mut ty))? };
            if ty != 0 {
                // Non-KERNEL node (memcpy/memset/child-graph/event/...). Rebuild
                // isn't implemented for these yet; bail so the caller keeps the
                // golden's exec (which fails loud) rather than a wrong graph.
                return Ok(None);
            }
            let mut kp: KernelNodeParams = unsafe { std::mem::zeroed() };
            unsafe { chk((self.graph_kernel_node_get_params)(node, &mut kp))? };
            if kp.kernel_params.is_null() {
                // Args packed via `extra` — opaque, can't serialize. Bail.
                return Ok(None);
            }
            let sizes = self.func_get_param_info(kp.func as u64)?;
            let mut params: Vec<Vec<u8>> = Vec::with_capacity(sizes.len());
            for (i, &sz) in sizes.iter().enumerate() {
                let sz = sz as usize;
                let argptr = unsafe { *kp.kernel_params.add(i) } as *const u8;
                if argptr.is_null() || sz == 0 {
                    params.push(Vec::new());
                    continue;
                }
                let mut v = vec![0u8; sz];
                unsafe { std::ptr::copy_nonoverlapping(argptr, v.as_mut_ptr(), sz) };
                params.push(v);
            }
            out.nodes.push(super::GraphKernelNode {
                func: kp.func as u64,
                grid: [kp.grid_x, kp.grid_y, kp.grid_z],
                block: [kp.block_x, kp.block_y, kp.block_z],
                shared_mem: kp.shared_mem_bytes,
                params,
            });
        }
        // Dependency edges: for each node, its predecessors -> (pred, node).
        for (&node, to) in nodes.iter().take(count).zip(0u32..) {
            let mut dn: usize = 0;
            unsafe {
                chk((self.graph_node_get_dependencies)(
                    node,
                    std::ptr::null_mut(),
                    &mut dn,
                ))?
            };
            if dn == 0 {
                continue;
            }
            let mut deps: Vec<*mut c_void> = vec![std::ptr::null_mut(); dn];
            unsafe {
                chk((self.graph_node_get_dependencies)(
                    node,
                    deps.as_mut_ptr(),
                    &mut dn,
                ))?
            };
            for &d in deps.iter().take(dn) {
                if let Some(&from) = idx.get(&(d as usize)) {
                    out.edges.push((from, to));
                }
            }
        }
        Ok(Some(out))
    }
    fn graph_rebuild(
        &mut self,
        ser: &super::GraphSer,
        funcs: &std::collections::HashMap<u64, u64>,
    ) -> CuResult<u64> {
        let mut graph: *mut c_void = std::ptr::null_mut();
        unsafe { chk((self.graph_create)(&mut graph, 0))? };
        let mut new_nodes: Vec<*mut c_void> = Vec::with_capacity(ser.nodes.len());
        for n in &ser.nodes {
            // Keep each arg's bytes alive for the add call; kernel_params points
            // at them. Addresses are preserved across the fork, so the bytes
            // (which may embed device pointers) are used verbatim.
            let bufs = n.params.clone();
            let mut argp: Vec<*mut c_void> = bufs
                .iter()
                .map(|b| {
                    if b.is_empty() {
                        std::ptr::null_mut()
                    } else {
                        b.as_ptr() as *mut c_void
                    }
                })
                .collect();
            let func = funcs.get(&n.func).copied().unwrap_or(n.func);
            let kp = KernelNodeParams {
                func: func as *mut c_void,
                grid_x: n.grid[0],
                grid_y: n.grid[1],
                grid_z: n.grid[2],
                block_x: n.block[0],
                block_y: n.block[1],
                block_z: n.block[2],
                shared_mem_bytes: n.shared_mem,
                kernel_params: if argp.is_empty() {
                    std::ptr::null_mut()
                } else {
                    argp.as_mut_ptr()
                },
                extra: std::ptr::null_mut(),
                kern: std::ptr::null_mut(),
                ctx: std::ptr::null_mut(),
            };
            let mut node: *mut c_void = std::ptr::null_mut();
            unsafe {
                chk((self.graph_add_kernel_node)(
                    &mut node,
                    graph,
                    std::ptr::null(),
                    0,
                    &kp,
                ))?
            };
            new_nodes.push(node);
        }
        if !ser.edges.is_empty() {
            let from: Vec<*mut c_void> = ser
                .edges
                .iter()
                .map(|&(f, _)| new_nodes[f as usize])
                .collect();
            let to: Vec<*mut c_void> = ser
                .edges
                .iter()
                .map(|&(_, t)| new_nodes[t as usize])
                .collect();
            unsafe {
                chk((self.graph_add_dependencies)(
                    graph,
                    from.as_ptr(),
                    to.as_ptr(),
                    from.len(),
                ))?
            };
        }
        Ok(graph as u64)
    }
    fn memset_d8_async(&mut self, dptr: u64, value: u8, bytes: u64, stream: u64) -> CuResult<()> {
        unsafe {
            chk((self.memset_d8_async)(
                dptr,
                value,
                bytes as usize,
                stream as *mut c_void,
            ))
        }
    }
    fn memcpy_dtod_async(&mut self, dst: u64, src: u64, bytes: u64, stream: u64) -> CuResult<()> {
        unsafe {
            chk((self.memcpy_dtod_async)(
                dst,
                src,
                bytes as usize,
                stream as *mut c_void,
            ))
        }
    }
    fn stream_destroy(&mut self, stream: u64) -> CuResult<()> {
        unsafe { chk((self.stream_destroy)(stream as *mut c_void)) }
    }
    fn stream_query(&mut self, stream: u64) -> CuResult<i32> {
        // 600 (NOT_READY) is a status, not an error — return the raw code.
        Ok(unsafe { (self.stream_query)(stream as *mut c_void) })
    }
    fn stream_wait_event(&mut self, stream: u64, event: u64, flags: u32) -> CuResult<()> {
        unsafe {
            chk((self.stream_wait_event)(
                stream as *mut c_void,
                event as *mut c_void,
                flags,
            ))
        }
    }
    fn event_query(&mut self, event: u64) -> CuResult<i32> {
        Ok(unsafe { (self.event_query)(event as *mut c_void) })
    }
    fn stream_synchronize(&mut self, stream: u64) -> CuResult<()> {
        unsafe { chk((self.stream_synchronize)(stream as *mut c_void)) }
    }
    fn event_create(&mut self, flags: u32) -> CuResult<u64> {
        let mut e: *mut c_void = std::ptr::null_mut();
        unsafe { chk((self.event_create)(&mut e, flags))? };
        Ok(e as u64)
    }
    fn event_destroy(&mut self, event: u64) -> CuResult<()> {
        unsafe { chk((self.event_destroy)(event as *mut c_void)) }
    }
    fn event_record(&mut self, event: u64, stream: u64) -> CuResult<()> {
        unsafe {
            chk((self.event_record)(
                event as *mut c_void,
                stream as *mut c_void,
            ))
        }
    }
    fn event_synchronize(&mut self, event: u64) -> CuResult<()> {
        unsafe { chk((self.event_synchronize)(event as *mut c_void)) }
    }
    fn event_elapsed_time(&mut self, start: u64, end: u64) -> CuResult<f32> {
        let mut ms: f32 = 0.0;
        unsafe {
            chk((self.event_elapsed_time)(
                &mut ms,
                start as *mut c_void,
                end as *mut c_void,
            ))?
        };
        Ok(ms)
    }

    fn nvcomp_deflate_temp_size(
        &mut self,
        num_chunks: u64,
        max_uncompressed_chunk_bytes: u64,
        max_total_uncompressed_bytes: u64,
    ) -> CuResult<(i32, u64)> {
        let nv = self.ensure_nvcomp()?;
        let mut temp: usize = 0;
        let st = unsafe {
            (nv.temp_size)(
                num_chunks as usize,
                max_uncompressed_chunk_bytes as usize,
                &mut temp,
                max_total_uncompressed_bytes as usize,
            )
        };
        Ok((st, temp as u64))
    }

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
    ) -> CuResult<i32> {
        let nv = self.ensure_nvcomp()?;
        if std::env::var_os("SMOLVM_CUDA_HOST_TRACE").is_some() {
            eprintln!(
                "cuda-host: nvcompDecompress batch={batch_size} temp_bytes={temp_bytes} \
                 comp_ptrs={device_compressed_ptrs:#x} uncomp_ptrs={device_uncompressed_ptrs:#x} \
                 stream={stream:#x} — calling real nvcomp"
            );
        }
        // Every pointer is already a real host device address in this process's
        // primary context; pass them straight to real nvcomp.
        let st = unsafe {
            (nv.decompress)(
                device_compressed_ptrs as *const *const c_void,
                device_compressed_bytes as *const usize,
                device_uncompressed_bytes as *const usize,
                device_actual_uncompressed_bytes as *mut usize,
                batch_size as usize,
                device_temp as *mut c_void,
                temp_bytes as usize,
                device_uncompressed_ptrs as *const *mut c_void,
                device_statuses as *mut c_int,
                stream as *mut c_void,
            )
        };
        if std::env::var_os("SMOLVM_CUDA_HOST_TRACE").is_some() {
            eprintln!("cuda-host: nvcompDecompress returned status={st}");
        }
        Ok(st)
    }

    fn cublas_create(&mut self) -> CuResult<u64> {
        let cb = self.ensure_cublas()?;
        let mut h: *mut c_void = std::ptr::null_mut();
        let st = unsafe { (cb.create)(&mut h) };
        if st != 0 {
            return Err(st);
        }
        Ok(h as u64)
    }
    fn cublas_destroy(&mut self, handle: u64) -> CuResult<()> {
        let cb = self.ensure_cublas()?;
        chk_cublas(unsafe { (cb.destroy)(handle as *mut c_void) })
    }
    fn cublas_set_stream(&mut self, handle: u64, stream: u64) -> CuResult<()> {
        let cb = self.ensure_cublas()?;
        chk_cublas(unsafe { (cb.set_stream)(handle as *mut c_void, stream as *mut c_void) })
    }
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
    ) -> CuResult<()> {
        let cb = self.ensure_cublas()?;
        // alpha/beta are host scalars (default cuBLAS pointer mode); the matrix
        // pointers are real device addresses in this process's primary context.
        chk_cublas(unsafe {
            (cb.sgemm)(
                handle as *mut c_void,
                transa as c_int,
                transb as c_int,
                m,
                n,
                k,
                &alpha,
                a as *const f32,
                lda,
                b as *const f32,
                ldb,
                &beta,
                c as *mut f32,
                ldc,
            )
        })
    }

    fn lib_call(
        &mut self,
        lib: u8,
        func: u16,
        args: &[u8],
        streams: &std::collections::HashMap<u64, u64>,
    ) -> CuResult<(i32, Vec<u8>)> {
        self.gen_lib_call(lib, func, args, streams)
    }
    fn lib_handle_alias(&mut self, golden: u64, real: u64) {
        self.vhandles.lock().unwrap().insert(golden, real);
    }
}

/// cuBLAS status: 0 = `CUBLAS_STATUS_SUCCESS`, else the code as `Err`.
fn chk_cublas(st: c_int) -> CuResult<()> {
    if st == 0 {
        Ok(())
    } else {
        Err(st)
    }
}

/// Byte size of one element of a `cudnnBackendAttributeType_t`. PyTorch's conv
/// graph uses handles/pointers (8), enums/int32/float (4), int64/double (8),
/// bool/char (1). Everything else defaults to a 4-byte enum.
fn cudnn_elem_size(attr_type: i32) -> usize {
    match attr_type {
        0 | 3 | 5 | 6 | 15 => 8, // HANDLE, INT64, DOUBLE, VOID_PTR, BACKEND_DESCRIPTOR
        2 | 24 => 1,             // BOOLEAN, CHAR
        26 => 16,                // FRACTION
        _ => 4,                  // DATA_TYPE / enums / FLOAT / INT32 / ...
    }
}

/// The 6-function cuDNN v8 **backend (graph) API** PyTorch uses for convolution.
/// Descriptors and device pointers passing through are the server's real host
/// pointers (opaque to the guest), so attribute arrays forward as raw bytes.
struct CudnnBackend {
    _lib: Library,
    create: unsafe extern "C" fn(c_int, *mut *mut c_void) -> c_int,
    destroy: unsafe extern "C" fn(*mut c_void) -> c_int,
    set_attr: unsafe extern "C" fn(*mut c_void, c_int, c_int, i64, *const c_void) -> c_int,
    get_attr: unsafe extern "C" fn(*mut c_void, c_int, c_int, i64, *mut i64, *mut c_void) -> c_int,
    finalize: unsafe extern "C" fn(*mut c_void) -> c_int,
    execute: unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> c_int,
}

impl CudnnBackend {
    fn load() -> Result<CudnnBackend, String> {
        unsafe {
            let lib = open_host_lib(
                "SMOLVM_CUDNN_LIB",
                &["libcudnn.so", "libcudnn.so.9", "libcudnn.so.8"],
            )?;
            let b = CudnnBackend {
                create: sym(&lib, b"cudnnBackendCreateDescriptor\0")?,
                destroy: sym(&lib, b"cudnnBackendDestroyDescriptor\0")?,
                set_attr: sym(&lib, b"cudnnBackendSetAttribute\0")?,
                get_attr: sym(&lib, b"cudnnBackendGetAttribute\0")?,
                finalize: sym(&lib, b"cudnnBackendFinalize\0")?,
                execute: sym(&lib, b"cudnnBackendExecute\0")?,
                _lib: lib,
            };
            Ok(b)
        }
    }

    /// `func` selects the entry point; `args` is the hand-packed little-endian
    /// argument blob (see the guest shim). Returns `(cudnnStatus, out_bytes)`.
    /// Descriptor handles may be guest-assigned virtual ids (`vh`); attribute
    /// arrays of type `CUDNN_TYPE_BACKEND_DESCRIPTOR` embed handles and are
    /// translated element-wise.
    fn dispatch(
        &self,
        func: u16,
        args: &[u8],
        vh: &mut std::collections::HashMap<u64, u64>,
    ) -> (i32, Vec<u8>) {
        /// `cudnnBackendAttributeType_t` values whose 8-byte elements are
        /// handles the guest may know only by virtual id: HANDLE(0) — the
        /// cudnnHandle_t itself — and BACKEND_DESCRIPTOR(15). VOID_PTR(6)
        /// elements are device pointers (untagged), translated harmlessly.
        fn handle_bearing(ty: i32) -> bool {
            matches!(ty, 0 | 6 | 15)
        }
        let rd_u64 = |a: &[u8], o: usize| u64::from_le_bytes(a[o..o + 8].try_into().unwrap());
        let rd_i32 = |a: &[u8], o: usize| i32::from_le_bytes(a[o..o + 4].try_into().unwrap());
        let rd_i64 = |a: &[u8], o: usize| i64::from_le_bytes(a[o..o + 8].try_into().unwrap());
        match func {
            0 => {
                // create(type[, virtual-id]) -> handle. With a virtual id the
                // guest fired-and-forgot: map it and reply with the real
                // pointer (ignored by a pipelining guest, used by an old one).
                let ty = rd_i32(args, 0);
                let mut desc: *mut c_void = std::ptr::null_mut();
                let st = unsafe { (self.create)(ty, &mut desc) };
                if st == 0 && args.len() >= 12 {
                    let id = rd_u64(args, 4);
                    if id & VHANDLE_TAG != 0 {
                        vh.insert(id, desc as u64);
                    }
                }
                (st, (desc as u64).to_le_bytes().to_vec())
            }
            1 => {
                let id = rd_u64(args, 0);
                let desc = vh_resolve(vh, id) as *mut c_void;
                if id & VHANDLE_TAG != 0 {
                    vh.remove(&id);
                }
                (unsafe { (self.destroy)(desc) }, Vec::new())
            }
            2 => {
                // set_attr(desc, name, type, count, elements...)
                let desc = vh_resolve(vh, rd_u64(args, 0)) as *mut c_void;
                let name = rd_i32(args, 8);
                let ty = rd_i32(args, 12);
                let count = rd_i64(args, 16);
                let mut elems = args[24..].to_vec();
                if handle_bearing(ty) {
                    for chunk in elems.chunks_exact_mut(8) {
                        let h = u64::from_le_bytes(chunk.try_into().unwrap());
                        // VOID_PTR(6) = device pointer (fork-translate); HANDLE(0)
                        // / BACKEND_DESCRIPTOR(15) = opaque handle (vh_resolve).
                        let r = if ty == 6 {
                            dptr_resolve(h)
                        } else {
                            vh_resolve(vh, h)
                        };
                        chunk.copy_from_slice(&r.to_le_bytes());
                    }
                }
                let st = unsafe { (self.set_attr)(desc, name, ty, count, elems.as_ptr().cast()) };
                (st, Vec::new())
            }
            3 => {
                // get_attr(desc, name, type, requestedCount, input_bytes) -> count + bytes.
                // For descriptor-array attributes the caller pre-creates the
                // descriptors and passes their handles in; cuDNN populates them
                // in place. So seed the buffer with the forwarded input
                // (translated — the guest may pass virtual ids).
                let desc = vh_resolve(vh, rd_u64(args, 0)) as *mut c_void;
                let name = rd_i32(args, 8);
                let ty = rd_i32(args, 12);
                let req = rd_i64(args, 16);
                let cap = (req.max(0) as usize) * cudnn_elem_size(ty);
                let input = &args[24..];
                let mut buf = vec![0u8; cap];
                let seed = input.len().min(cap);
                buf[..seed].copy_from_slice(&input[..seed]);
                if handle_bearing(ty) {
                    for chunk in buf[..seed].chunks_exact_mut(8) {
                        let h = u64::from_le_bytes(chunk.try_into().unwrap());
                        let r = if ty == 6 {
                            dptr_resolve(h)
                        } else {
                            vh_resolve(vh, h)
                        };
                        chunk.copy_from_slice(&r.to_le_bytes());
                    }
                }
                let mut count: i64 = 0;
                let ptr = if cap == 0 {
                    std::ptr::null_mut()
                } else {
                    buf.as_mut_ptr().cast()
                };
                let st = unsafe { (self.get_attr)(desc, name, ty, req, &mut count, ptr) };
                let n = (count.max(0) as usize) * cudnn_elem_size(ty);
                let mut out = count.to_le_bytes().to_vec();
                out.extend_from_slice(&buf[..n.min(buf.len())]);
                (st, out)
            }
            4 => {
                let desc = vh_resolve(vh, rd_u64(args, 0)) as *mut c_void;
                (unsafe { (self.finalize)(desc) }, Vec::new())
            }
            5 => {
                // execute(handle, plan, variantPack)
                let handle = vh_resolve(vh, rd_u64(args, 0)) as *mut c_void;
                let plan = vh_resolve(vh, rd_u64(args, 8)) as *mut c_void;
                let vpack = vh_resolve(vh, rd_u64(args, 16)) as *mut c_void;
                (unsafe { (self.execute)(handle, plan, vpack) }, Vec::new())
            }
            _ => (super::CUDA_ERROR_NOT_FOUND, Vec::new()),
        }
    }
}

/// The 11-function cuBLASLt matmul API PyTorch uses for linear layers.
/// Descriptors, layouts, preferences and device pointers passing through are the
/// server's real host pointers (opaque to the guest); scalars, attribute buffers
/// and the opaque algo blob forward as raw little-endian bytes. The "light
/// handle" is the connection's real cuBLAS handle (torch reuses it), forwarded as
/// a handle just like every other pointer.
struct CublasLt {
    _lib: Library,
    matmul: unsafe extern "C" fn(
        *mut c_void,
        *mut c_void,
        *const c_void,
        *const c_void,
        *mut c_void,
        *const c_void,
        *mut c_void,
        *const c_void,
        *const c_void,
        *mut c_void,
        *mut c_void,
        *mut c_void,
        *const c_void,
        *mut c_void,
        usize,
        *mut c_void,
    ) -> c_int,
    algo_get_heuristic: unsafe extern "C" fn(
        *mut c_void,
        *mut c_void,
        *mut c_void,
        *mut c_void,
        *mut c_void,
        *mut c_void,
        *mut c_void,
        c_int,
        *mut c_void,
        *mut c_int,
    ) -> c_int,
    desc_create: unsafe extern "C" fn(*mut *mut c_void, c_int, c_int) -> c_int,
    desc_destroy: unsafe extern "C" fn(*mut c_void) -> c_int,
    desc_set_attr: unsafe extern "C" fn(*mut c_void, c_int, *const c_void, usize) -> c_int,
    layout_create: unsafe extern "C" fn(*mut *mut c_void, c_int, u64, u64, i64) -> c_int,
    layout_destroy: unsafe extern "C" fn(*mut c_void) -> c_int,
    layout_set_attr: unsafe extern "C" fn(*mut c_void, c_int, *const c_void, usize) -> c_int,
    pref_create: unsafe extern "C" fn(*mut *mut c_void) -> c_int,
    pref_destroy: unsafe extern "C" fn(*mut c_void) -> c_int,
    pref_set_attr: unsafe extern "C" fn(*mut c_void, c_int, *const c_void, usize) -> c_int,
    // Standalone callers (not PyTorch, which reuses the cuBLAS handle) create a
    // dedicated cuBLASLt handle.
    lt_create: unsafe extern "C" fn(*mut *mut c_void) -> c_int,
    lt_destroy: unsafe extern "C" fn(*mut c_void) -> c_int,
}

impl CublasLt {
    fn load() -> Result<CublasLt, String> {
        // cuBLASLt ships in its own soname; fall back to the cuBLAS path's dir.
        unsafe {
            let lib = open_host_lib(
                "SMOLVM_CUBLASLT_LIB",
                &["libcublasLt.so", "libcublasLt.so.13", "libcublasLt.so.12"],
            )?;
            let b = CublasLt {
                matmul: sym(&lib, b"cublasLtMatmul\0")?,
                algo_get_heuristic: sym(&lib, b"cublasLtMatmulAlgoGetHeuristic\0")?,
                desc_create: sym(&lib, b"cublasLtMatmulDescCreate\0")?,
                desc_destroy: sym(&lib, b"cublasLtMatmulDescDestroy\0")?,
                desc_set_attr: sym(&lib, b"cublasLtMatmulDescSetAttribute\0")?,
                layout_create: sym(&lib, b"cublasLtMatrixLayoutCreate\0")?,
                layout_destroy: sym(&lib, b"cublasLtMatrixLayoutDestroy\0")?,
                layout_set_attr: sym(&lib, b"cublasLtMatrixLayoutSetAttribute\0")?,
                pref_create: sym(&lib, b"cublasLtMatmulPreferenceCreate\0")?,
                pref_destroy: sym(&lib, b"cublasLtMatmulPreferenceDestroy\0")?,
                pref_set_attr: sym(&lib, b"cublasLtMatmulPreferenceSetAttribute\0")?,
                lt_create: sym(&lib, b"cublasLtCreate\0")?,
                lt_destroy: sym(&lib, b"cublasLtDestroy\0")?,
                _lib: lib,
            };
            Ok(b)
        }
    }

    /// `func` selects the entry point; `args` is the hand-packed little-endian
    /// argument blob (see the guest shim). Returns `(cublasStatus, out_bytes)`.
    fn dispatch(
        &self,
        func: u16,
        args: &[u8],
        vh: &mut std::collections::HashMap<u64, u64>,
        streams: &std::collections::HashMap<u64, u64>,
    ) -> (i32, Vec<u8>) {
        // Fire-and-forget creates append a guest-minted virtual id after the
        // regular args; register it so later (deferred) calls resolve.
        fn register_vh(
            vh: &mut std::collections::HashMap<u64, u64>,
            args: &[u8],
            fixed: usize,
            real: u64,
        ) {
            if args.len() >= fixed + 8 {
                let id = u64::from_le_bytes(args[fixed..fixed + 8].try_into().unwrap());
                if id & VHANDLE_TAG != 0 {
                    vh.insert(id, real);
                }
            }
        }
        // sizeof(cublasLtMatmulHeuristicResult_t): algo[64] + workspaceSize(8)
        // + state(4) + wavesCount(4) + reserved[4](16) = 96 bytes.
        const HEUR_RESULT_SZ: usize = 96;
        let rd_u64 = |o: usize| u64::from_le_bytes(args[o..o + 8].try_into().unwrap());
        let rd_i64 = |o: usize| i64::from_le_bytes(args[o..o + 8].try_into().unwrap());
        let rd_i32 = |o: usize| i32::from_le_bytes(args[o..o + 4].try_into().unwrap());
        match func {
            0 => {
                // desc_create(computeType, scaleType) -> handle
                let compute = rd_i32(0);
                let scale = rd_i32(4);
                let mut d: *mut c_void = std::ptr::null_mut();
                let st = unsafe { (self.desc_create)(&mut d, compute, scale) };
                register_vh(vh, args, 8, d as u64);
                (st, (d as u64).to_le_bytes().to_vec())
            }
            1 => {
                let id = rd_u64(0);
                let real = vh_resolve(vh, id);
                vh.remove(&id);
                (
                    unsafe { (self.desc_destroy)(real as *mut c_void) },
                    Vec::new(),
                )
            }
            2 => {
                // desc_set_attr(desc, attr, buf, size)
                let desc = vh_resolve(vh, rd_u64(0)) as *mut c_void;
                let attr = rd_i32(8);
                let buf = &args[12..];
                let st =
                    unsafe { (self.desc_set_attr)(desc, attr, buf.as_ptr().cast(), buf.len()) };
                (st, Vec::new())
            }
            3 => {
                // layout_create(type, rows, cols, ld) -> handle
                let ty = rd_i32(0);
                let rows = rd_u64(4);
                let cols = rd_u64(12);
                let ld = rd_i64(20);
                let mut l: *mut c_void = std::ptr::null_mut();
                let st = unsafe { (self.layout_create)(&mut l, ty, rows, cols, ld) };
                register_vh(vh, args, 28, l as u64);
                (st, (l as u64).to_le_bytes().to_vec())
            }
            4 => {
                let id = rd_u64(0);
                let real = vh_resolve(vh, id);
                vh.remove(&id);
                (
                    unsafe { (self.layout_destroy)(real as *mut c_void) },
                    Vec::new(),
                )
            }
            5 => {
                let layout = vh_resolve(vh, rd_u64(0)) as *mut c_void;
                let attr = rd_i32(8);
                let buf = &args[12..];
                let st =
                    unsafe { (self.layout_set_attr)(layout, attr, buf.as_ptr().cast(), buf.len()) };
                (st, Vec::new())
            }
            6 => {
                // pref_create() -> handle
                let mut p: *mut c_void = std::ptr::null_mut();
                let st = unsafe { (self.pref_create)(&mut p) };
                register_vh(vh, args, 0, p as u64);
                (st, (p as u64).to_le_bytes().to_vec())
            }
            7 => {
                let id = rd_u64(0);
                let real = vh_resolve(vh, id);
                vh.remove(&id);
                (
                    unsafe { (self.pref_destroy)(real as *mut c_void) },
                    Vec::new(),
                )
            }
            8 => {
                let pref = vh_resolve(vh, rd_u64(0)) as *mut c_void;
                let attr = rd_i32(8);
                let buf = &args[12..];
                let st =
                    unsafe { (self.pref_set_attr)(pref, attr, buf.as_ptr().cast(), buf.len()) };
                (st, Vec::new())
            }
            9 => {
                // algo_get_heuristic(light, opDesc, A, B, C, D, pref, requested)
                //   -> returnCount + returnCount * heuristicResult structs.
                let light = vh_resolve(vh, rd_u64(0)) as *mut c_void;
                let op = vh_resolve(vh, rd_u64(8)) as *mut c_void;
                let a = vh_resolve(vh, rd_u64(16)) as *mut c_void;
                let b = vh_resolve(vh, rd_u64(24)) as *mut c_void;
                let c = vh_resolve(vh, rd_u64(32)) as *mut c_void;
                let d = vh_resolve(vh, rd_u64(40)) as *mut c_void;
                let pref = vh_resolve(vh, rd_u64(48)) as *mut c_void;
                let requested = rd_i32(56).max(0);
                let mut results = vec![0u8; requested as usize * HEUR_RESULT_SZ];
                let mut count: c_int = 0;
                let st = unsafe {
                    (self.algo_get_heuristic)(
                        light,
                        op,
                        a,
                        b,
                        c,
                        d,
                        pref,
                        requested,
                        results.as_mut_ptr().cast(),
                        &mut count,
                    )
                };
                let n = (count.max(0) as usize) * HEUR_RESULT_SZ;
                let mut out = (count as i64).to_le_bytes().to_vec();
                out.extend_from_slice(&results[..n.min(results.len())]);
                (st, out)
            }
            10 => {
                // matmul(light, desc, alpha[16], A, Adesc, B, Bdesc, beta[16],
                //   C, Cdesc, D, Ddesc, algo[64], workspace, wsSize, stream)
                let light = vh_resolve(vh, rd_u64(0)) as *mut c_void;
                let desc = vh_resolve(vh, rd_u64(8)) as *mut c_void;
                let alpha = &args[16..32];
                // A/B/C/D and the workspace are device pointers — translate them
                // through the fork-isolation map so a clone's matmul hits its
                // private copies (untranslated for normal sessions).
                let a = dptr_resolve(rd_u64(32)) as *mut c_void;
                let adesc = vh_resolve(vh, rd_u64(40)) as *mut c_void;
                let b = dptr_resolve(rd_u64(48)) as *mut c_void;
                let bdesc = vh_resolve(vh, rd_u64(56)) as *mut c_void;
                let beta = &args[64..80];
                let c = dptr_resolve(rd_u64(80)) as *mut c_void;
                let cdesc = vh_resolve(vh, rd_u64(88)) as *mut c_void;
                let dd = dptr_resolve(rd_u64(96)) as *mut c_void;
                let ddesc = vh_resolve(vh, rd_u64(104)) as *mut c_void;
                let algo = &args[112..176];
                let algo_present = rd_u64(176) != 0;
                let workspace = dptr_resolve(rd_u64(184)) as *mut c_void;
                let ws_size = rd_u64(192) as usize;
                // Session-minted stream id → real host stream (see stream_resolve).
                let stream = stream_resolve(streams, rd_u64(200)) as *mut c_void;
                let algo_ptr = if algo_present {
                    algo.as_ptr().cast()
                } else {
                    std::ptr::null()
                };
                let st = unsafe {
                    (self.matmul)(
                        light,
                        desc,
                        alpha.as_ptr().cast(),
                        a,
                        adesc,
                        b,
                        bdesc,
                        beta.as_ptr().cast(),
                        c,
                        cdesc,
                        dd,
                        ddesc,
                        algo_ptr,
                        workspace,
                        ws_size,
                        stream,
                    )
                };
                (st, Vec::new())
            }
            11 => {
                let mut h: *mut c_void = std::ptr::null_mut();
                let st = unsafe { (self.lt_create)(&mut h) };
                (st, (h as u64).to_le_bytes().to_vec())
            }
            12 => (
                unsafe { (self.lt_destroy)(rd_u64(0) as *mut c_void) },
                Vec::new(),
            ),
            _ => (super::CUDA_ERROR_NOT_FOUND, Vec::new()),
        }
    }
}

/// The tag bit marking a guest-assigned virtual handle. Host userspace
/// pointers and CUDA device VAs never have bit 63 set, so tagged values are
/// unambiguous on the wire.
const VHANDLE_TAG: u64 = 1 << 63;

/// Resolve a possibly-virtual handle against the map: tagged values must be
/// mapped (0 → guaranteed invalid-handle error from the library), real
/// pointers pass through.
fn vh_resolve(map: &std::collections::HashMap<u64, u64>, h: u64) -> u64 {
    if h & VHANDLE_TAG != 0 {
        let r = map.get(&h).copied().unwrap_or(0);
        if r == 0 {
            // A tagged id with no mapping resolves to NULL and the library
            // call fails (cuBLAS: NOT_INITIALIZED). Always-log: this is a
            // bug signature, not a hot path.
            eprintln!(
                "[vh-miss] pid={} tagged handle {h:#x} unmapped (map has {} entries)",
                std::process::id(),
                map.len()
            );
        }
        r
    } else {
        // Untagged values are usually real host pointers and pass through —
        // EXCEPT an inherited raw library handle in a fork-clone worker
        // (cuBLASLt returns raw pointers to the guest), which the worker
        // aliased to its own re-created handle at staging. Identity when
        // absent, so the common case costs one map miss.
        map.get(&h).copied().unwrap_or(h)
    }
}

/// Resolve a wire `cudaStream_t` against the session stream table. Streams are
/// session-minted small ids (see `StreamCreate` in host.rs), so passing one
/// straight to a real library would be read as a pointer and crash it. 0 (the
/// default stream) and unmapped values (the legacy 0x1/0x2 stream constants)
/// pass through.
fn stream_resolve(map: &std::collections::HashMap<u64, u64>, s: u64) -> u64 {
    if s == 0 {
        0
    } else {
        // Clone workers additionally remap the GOLDEN's raw stream to their own
        // re-created stream (M3a stream_trans) — without this, a raw-stream
        // guest's cublasSetStream(golden ptr) dereferences a foreign heap
        // pointer inside libcuda (SIGSEGV in cuStreamGetGreenCtx). Identity on
        // non-clone sessions, so the common case is one thread-local miss.
        super::xlat_stream(map.get(&s).copied().unwrap_or(s))
    }
}

// Fork-isolation pointer translation for forwarded library calls (cuBLAS/cuDNN).
// The generated `dispatch` reads each DevPtr arg through `dptr_resolve`, so a
// clone's inherited device pointers hit its private copies — TYPED at the exact
// arg offset, unlike the byte-scan used for opaque kernel args. Kept in a
// thread-local (one serve thread per connection) so the generated code needs no
// extra parameter; `host::dispatch` refreshes it whenever the map changes.
thread_local! {
    static LIB_TRANS: std::cell::RefCell<Vec<(u64, u64, u64)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Install this connection's `(base, size, copy)` translation ranges for the
/// generated library dispatch. No-op cost when empty (the common case).
pub(super) fn set_lib_trans(trans: &[(u64, u64, u64)]) {
    LIB_TRANS.with(|c| {
        let mut v = c.borrow_mut();
        v.clear();
        v.extend_from_slice(trans);
    });
}

/// Translate a device pointer arg of a forwarded library call to the clone's
/// private copy; untranslated pointers (weights, fresh allocations) pass through.
pub(super) fn dptr_resolve(p: u64) -> u64 {
    if p == 0 {
        return 0;
    }
    LIB_TRANS.with(|c| {
        for &(base, size, copy) in c.borrow().iter() {
            if p >= base && p < base + size {
                return copy + (p - base);
            }
        }
        p
    })
}

/// Little-endian cursor over a hand-packed argument blob (host side of the
/// batchnorm forwarder). Mirrors the guest shim's packing exactly.
struct Cur<'a> {
    b: &'a [u8],
    p: usize,
    /// Virtual-handle map for resolving guest-assigned descriptor ids in
    /// [`Cur::ptr`]. Device pointers and real host pointers pass through
    /// (bit 63 clear).
    vh: &'a std::collections::HashMap<u64, u64>,
}
impl Cur<'_> {
    fn take(&mut self, n: usize) -> &[u8] {
        let s = &self.b[self.p..self.p + n];
        self.p += n;
        s
    }
    fn i32(&mut self) -> i32 {
        i32::from_le_bytes(self.take(4).try_into().unwrap())
    }
    fn u64(&mut self) -> u64 {
        u64::from_le_bytes(self.take(8).try_into().unwrap())
    }
    fn f32(&mut self) -> f32 {
        f32::from_le_bytes(self.take(4).try_into().unwrap())
    }
    fn f64(&mut self) -> f64 {
        f64::from_le_bytes(self.take(8).try_into().unwrap())
    }
    fn ptr(&mut self) -> *mut c_void {
        vh_resolve(self.vh, self.u64()) as *mut c_void
    }
}

/// The legacy cuDNN **batch-norm (Ex) + N-D tensor descriptor** API PyTorch uses
/// for `BatchNorm2d`. Tensor/activation descriptors and device pointers are the
/// server's real host pointers; alpha/beta are float scalars, epsilon/factor are
/// doubles, and the N-D descriptor's dim/stride arrays forward as raw i32s.
#[allow(clippy::type_complexity)]
struct CudnnBn {
    _lib: Library,
    set_nd: unsafe extern "C" fn(*mut c_void, c_int, c_int, *const c_int, *const c_int) -> c_int,
    derive_bn: unsafe extern "C" fn(*mut c_void, *mut c_void, c_int) -> c_int,
    fwd_infer: unsafe extern "C" fn(
        *mut c_void,
        c_int,
        *const c_void,
        *const c_void,
        *mut c_void,
        *const c_void,
        *mut c_void,
        *mut c_void,
        *mut c_void,
        *const c_void,
        *const c_void,
        *const c_void,
        *const c_void,
        f64,
    ) -> c_int,
    fwd_train_ex: unsafe extern "C" fn(
        *mut c_void,
        c_int,
        c_int,
        *const c_void,
        *const c_void,
        *mut c_void,
        *const c_void,
        *mut c_void,
        *const c_void,
        *mut c_void,
        *mut c_void,
        *mut c_void,
        *const c_void,
        *const c_void,
        f64,
        *mut c_void,
        *mut c_void,
        f64,
        *mut c_void,
        *mut c_void,
        *mut c_void,
        *mut c_void,
        usize,
        *mut c_void,
        usize,
    ) -> c_int,
    bwd_ex: unsafe extern "C" fn(
        *mut c_void,
        c_int,
        c_int,
        *const c_void,
        *const c_void,
        *const c_void,
        *const c_void,
        *mut c_void,
        *const c_void,
        *mut c_void,
        *const c_void,
        *mut c_void,
        *const c_void,
        *mut c_void,
        *mut c_void,
        *mut c_void,
        *mut c_void,
        *const c_void,
        *const c_void,
        *const c_void,
        *mut c_void,
        *mut c_void,
        f64,
        *const c_void,
        *const c_void,
        *mut c_void,
        *mut c_void,
        usize,
        *mut c_void,
        usize,
    ) -> c_int,
    ws_train: unsafe extern "C" fn(
        *mut c_void,
        c_int,
        c_int,
        *mut c_void,
        *mut c_void,
        *mut c_void,
        *mut c_void,
        *mut c_void,
        *mut usize,
    ) -> c_int,
    ws_bwd: unsafe extern "C" fn(
        *mut c_void,
        c_int,
        c_int,
        *mut c_void,
        *mut c_void,
        *mut c_void,
        *mut c_void,
        *mut c_void,
        *mut c_void,
        *mut c_void,
        *mut usize,
    ) -> c_int,
    reserve: unsafe extern "C" fn(
        *mut c_void,
        c_int,
        c_int,
        *mut c_void,
        *mut c_void,
        *mut usize,
    ) -> c_int,
}

impl CudnnBn {
    fn load() -> Result<CudnnBn, String> {
        unsafe {
            let lib = open_host_lib(
                "SMOLVM_CUDNN_LIB",
                &["libcudnn.so", "libcudnn.so.9", "libcudnn.so.8"],
            )?;
            let b = CudnnBn {
                set_nd: sym(&lib, b"cudnnSetTensorNdDescriptor\0")?,
                derive_bn: sym(&lib, b"cudnnDeriveBNTensorDescriptor\0")?,
                fwd_infer: sym(&lib, b"cudnnBatchNormalizationForwardInference\0")?,
                fwd_train_ex: sym(&lib, b"cudnnBatchNormalizationForwardTrainingEx\0")?,
                bwd_ex: sym(&lib, b"cudnnBatchNormalizationBackwardEx\0")?,
                ws_train: sym(
                    &lib,
                    b"cudnnGetBatchNormalizationForwardTrainingExWorkspaceSize\0",
                )?,
                ws_bwd: sym(&lib, b"cudnnGetBatchNormalizationBackwardExWorkspaceSize\0")?,
                reserve: sym(
                    &lib,
                    b"cudnnGetBatchNormalizationTrainingExReserveSpaceSize\0",
                )?,
                _lib: lib,
            };
            Ok(b)
        }
    }

    fn dispatch(
        &self,
        func: u16,
        args: &[u8],
        vh: &std::collections::HashMap<u64, u64>,
    ) -> (i32, Vec<u8>) {
        let mut c = Cur { b: args, p: 0, vh };
        match func {
            0 => {
                // set_nd(desc, dataType, nbDims, dimA[], strideA[])
                let desc = c.ptr();
                let dtype = c.i32();
                let nb = c.i32();
                let n = nb.max(0) as usize;
                let dims: Vec<c_int> = (0..n).map(|_| c.i32()).collect();
                let strides: Vec<c_int> = (0..n).map(|_| c.i32()).collect();
                let st = unsafe { (self.set_nd)(desc, dtype, nb, dims.as_ptr(), strides.as_ptr()) };
                (st, Vec::new())
            }
            1 => {
                let derived = c.ptr();
                let xdesc = c.ptr();
                let mode = c.i32();
                (
                    unsafe { (self.derive_bn)(derived, xdesc, mode) },
                    Vec::new(),
                )
            }
            2 => {
                let handle = c.ptr();
                let mode = c.i32();
                let alpha = c.f32();
                let beta = c.f32();
                let xdesc = c.ptr();
                let x = c.ptr();
                let ydesc = c.ptr();
                let y = c.ptr();
                let bndesc = c.ptr();
                let scale = c.ptr();
                let bias = c.ptr();
                let mean = c.ptr();
                let var = c.ptr();
                let eps = c.f64();
                let st = unsafe {
                    (self.fwd_infer)(
                        handle,
                        mode,
                        (&alpha as *const f32).cast(),
                        (&beta as *const f32).cast(),
                        xdesc,
                        x.cast_const(),
                        ydesc,
                        y,
                        bndesc,
                        scale.cast_const(),
                        bias.cast_const(),
                        mean.cast_const(),
                        var.cast_const(),
                        eps,
                    )
                };
                (st, Vec::new())
            }
            3 => {
                let handle = c.ptr();
                let mode = c.i32();
                let bn_ops = c.i32();
                let alpha = c.f32();
                let beta = c.f32();
                let xdesc = c.ptr();
                let x = c.ptr();
                let zdesc = c.ptr();
                let z = c.ptr();
                let ydesc = c.ptr();
                let y = c.ptr();
                let bndesc = c.ptr();
                let scale = c.ptr();
                let bias = c.ptr();
                let factor = c.f64();
                let run_mean = c.ptr();
                let run_var = c.ptr();
                let eps = c.f64();
                let save_mean = c.ptr();
                let save_ivar = c.ptr();
                let act = c.ptr();
                let ws = c.ptr();
                let ws_sz = c.u64() as usize;
                let rs = c.ptr();
                let rs_sz = c.u64() as usize;
                let st = unsafe {
                    (self.fwd_train_ex)(
                        handle,
                        mode,
                        bn_ops,
                        (&alpha as *const f32).cast(),
                        (&beta as *const f32).cast(),
                        xdesc,
                        x.cast_const(),
                        zdesc,
                        z.cast_const(),
                        ydesc,
                        y,
                        bndesc,
                        scale.cast_const(),
                        bias.cast_const(),
                        factor,
                        run_mean,
                        run_var,
                        eps,
                        save_mean,
                        save_ivar,
                        act,
                        ws,
                        ws_sz,
                        rs,
                        rs_sz,
                    )
                };
                (st, Vec::new())
            }
            4 => {
                let handle = c.ptr();
                let mode = c.i32();
                let bn_ops = c.i32();
                let alpha_d = c.f32();
                let beta_d = c.f32();
                let alpha_p = c.f32();
                let beta_p = c.f32();
                let xdesc = c.ptr();
                let x = c.ptr();
                let ydesc = c.ptr();
                let y = c.ptr();
                let dydesc = c.ptr();
                let dy = c.ptr();
                let dzdesc = c.ptr();
                let dz = c.ptr();
                let dxdesc = c.ptr();
                let dx = c.ptr();
                let dbndesc = c.ptr();
                let scale = c.ptr();
                let bias = c.ptr();
                let dscale = c.ptr();
                let dbias = c.ptr();
                let eps = c.f64();
                let save_mean = c.ptr();
                let save_ivar = c.ptr();
                let act = c.ptr();
                let ws = c.ptr();
                let ws_sz = c.u64() as usize;
                let rs = c.ptr();
                let rs_sz = c.u64() as usize;
                let st = unsafe {
                    (self.bwd_ex)(
                        handle,
                        mode,
                        bn_ops,
                        (&alpha_d as *const f32).cast(),
                        (&beta_d as *const f32).cast(),
                        (&alpha_p as *const f32).cast(),
                        (&beta_p as *const f32).cast(),
                        xdesc,
                        x.cast_const(),
                        ydesc,
                        y.cast_const(),
                        dydesc,
                        dy.cast_const(),
                        dzdesc,
                        dz,
                        dxdesc,
                        dx,
                        dbndesc,
                        scale.cast_const(),
                        bias.cast_const(),
                        dscale,
                        dbias,
                        eps,
                        save_mean.cast_const(),
                        save_ivar.cast_const(),
                        act,
                        ws,
                        ws_sz,
                        rs,
                        rs_sz,
                    )
                };
                (st, Vec::new())
            }
            5 => {
                let handle = c.ptr();
                let mode = c.i32();
                let bn_ops = c.i32();
                let xdesc = c.ptr();
                let zdesc = c.ptr();
                let ydesc = c.ptr();
                let bndesc = c.ptr();
                let act = c.ptr();
                let mut size: usize = 0;
                let st = unsafe {
                    (self.ws_train)(
                        handle, mode, bn_ops, xdesc, zdesc, ydesc, bndesc, act, &mut size,
                    )
                };
                (st, (size as u64).to_le_bytes().to_vec())
            }
            6 => {
                let handle = c.ptr();
                let mode = c.i32();
                let bn_ops = c.i32();
                let xdesc = c.ptr();
                let ydesc = c.ptr();
                let dydesc = c.ptr();
                let dzdesc = c.ptr();
                let dxdesc = c.ptr();
                let bndesc = c.ptr();
                let act = c.ptr();
                let mut size: usize = 0;
                let st = unsafe {
                    (self.ws_bwd)(
                        handle, mode, bn_ops, xdesc, ydesc, dydesc, dzdesc, dxdesc, bndesc, act,
                        &mut size,
                    )
                };
                (st, (size as u64).to_le_bytes().to_vec())
            }
            7 => {
                let handle = c.ptr();
                let mode = c.i32();
                let bn_ops = c.i32();
                let act = c.ptr();
                let xdesc = c.ptr();
                let mut size: usize = 0;
                let st = unsafe { (self.reserve)(handle, mode, bn_ops, act, xdesc, &mut size) };
                (st, (size as u64).to_le_bytes().to_vec())
            }
            _ => (super::CUDA_ERROR_NOT_FOUND, Vec::new()),
        }
    }
}

impl Drop for GpuBackend {
    fn drop(&mut self) {
        // Release any guest-RAM pins this backend took so the next connection can
        // re-register them. Safe to call at drop: the context is still alive.
        if let Some(unreg) = self.mem_host_unregister {
            for &(hva, _) in &self.registered {
                // SAFETY: we registered exactly this host range earlier.
                unsafe {
                    unreg(hva as *mut c_void);
                }
            }
        }
        let (addr, _) = self.staging;
        if addr != 0 {
            if let Some(free) = self.mem_free_host {
                // SAFETY: `addr` came from cuMemAllocHost and is freed once.
                unsafe { free(addr as *mut c_void) };
            }
        }
    }
}

/// `CUDA_KERNEL_NODE_PARAMS_v2` — a graph kernel node's launch config (CUDA 12+;
/// torch captures kernels through the v2 API, so we use v2 get/set with the extra
/// `kern`/`ctx` tail). We read it to translate a fork clone's inherited pointer
/// args, then set it on the exec. Fields are read by the driver via FFI.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
pub struct KernelNodeParams {
    func: *mut c_void,
    grid_x: c_uint,
    grid_y: c_uint,
    grid_z: c_uint,
    block_x: c_uint,
    block_y: c_uint,
    block_z: c_uint,
    shared_mem_bytes: c_uint,
    kernel_params: *mut *mut c_void,
    extra: *mut *mut c_void,
    kern: *mut c_void, // v2: CUkernel
    ctx: *mut c_void,  // v2: CUcontext
}

/// `CUDA_MEMSET_NODE_PARAMS` — a graph memset node's target + fill.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
pub struct MemsetNodeParams {
    dst: u64,
    pitch: usize,
    value: c_uint,
    element_size: c_uint,
    width: usize,
    height: usize,
}

/// `CUDA_MEMCPY3D` — a graph memcpy node's descriptor. We translate the src/dst
/// device pointers; host-memory copies leave those 0 (pass through).
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
pub struct Memcpy3D {
    src_x: usize,
    src_y: usize,
    src_z: usize,
    src_lod: usize,
    src_mem_type: c_uint,
    src_host: *const c_void,
    src_device: u64,
    src_array: *mut c_void,
    reserved0: *mut c_void,
    src_pitch: usize,
    src_height: usize,
    dst_x: usize,
    dst_y: usize,
    dst_z: usize,
    dst_lod: usize,
    dst_mem_type: c_uint,
    dst_host: *mut c_void,
    dst_device: u64,
    dst_array: *mut c_void,
    reserved1: *mut c_void,
    dst_pitch: usize,
    dst_height: usize,
    width: usize,
    height: usize,
    depth: usize,
}

/// Translate a device pointer through a clone's `(base, size, copy)` ranges
/// (mirrors `host::xlat`); untranslated pointers pass through.
fn xlat_range(trans: &[(u64, u64, u64)], p: u64) -> u64 {
    if p == 0 {
        return p;
    }
    for &(base, size, copy) in trans {
        if p >= base && p < base + size {
            return copy + (p - base);
        }
    }
    p
}

/// `CUmemAllocationProp` prefix we populate: pinned device memory on one
/// device, no export handles. Zeroed tail keeps future fields defined.
#[repr(C)]
pub struct VmmProp {
    type_: c_int, // CU_MEM_ALLOCATION_TYPE_PINNED = 1
    requested_handle_types: c_int,
    location_type: c_int, // CU_MEM_LOCATION_TYPE_DEVICE = 1
    location_id: c_int,
    win32_handle_meta: *mut c_void,
    alloc_flags: [u8; 8],
}

/// `CUmemAccessDesc`: device location + RW flags.
#[repr(C)]
pub struct VmmAccessDesc {
    location_type: c_int,
    location_id: c_int,
    flags: c_int, // CU_MEM_ACCESS_FLAGS_PROT_READWRITE = 3
}

fn vmm_prop(device: i32) -> VmmProp {
    VmmProp {
        type_: 1,
        requested_handle_types: 0,
        location_type: 1,
        location_id: device,
        win32_handle_meta: std::ptr::null_mut(),
        alloc_flags: [0; 8],
    }
}

impl GpuBackend {
    /// CLONE transport: move `total` bytes between the GPU (`dptr`) and the
    /// clone's LIVE guest RAM via /proc/<pid>/mem + pinned staging. `to_guest`:
    /// D2H (GPU -> pwrite guest); else H2D (pread guest -> GPU).
    #[cfg(unix)]
    fn gpa_procmem(&mut self, dptr: u64, segments: &[(u64, u64)], to_guest: bool) -> CuResult<()> {
        let total: u64 = segments.iter().map(|(_, l)| *l).sum();
        if total == 0 {
            return Ok(());
        }
        let stg = self
            .ensure_staging(total as usize)
            .ok_or(super::CUDA_ERROR_NOT_FOUND)?;
        let memfd = {
            use std::os::unix::io::AsRawFd as _;
            self.proc_mem
                .as_ref()
                .ok_or(super::CUDA_ERROR_NOT_FOUND)?
                .as_raw_fd()
        };
        let dtoh = self.memcpy_dtoh;
        let htod = self.memcpy_htod;
        // Resolve each segment's clone host VA (immutable read of guest_ram).
        let mut resolved: Vec<(u64, u64, u64)> = Vec::with_capacity(segments.len());
        let mut off = 0u64;
        for &(gpa, len) in segments {
            let hva = self
                .proc_mem_regions
                .iter()
                .find_map(|&(gs, h, rl)| {
                    (gpa >= gs && gpa.checked_add(len)? <= gs + rl).then(|| h + (gpa - gs))
                })
                .ok_or(super::CUDA_ERROR_INVALID_HANDLE)?;
            resolved.push((hva, off, len));
            off += len;
        }
        if to_guest {
            // D2H: one DMA GPU -> staging, then pwrite each segment into the clone.
            unsafe { chk(dtoh(stg as *mut c_void, dptr, total as usize))? };
            for (hva, o, len) in resolved {
                let r = unsafe {
                    libc::pwrite(
                        memfd,
                        stg.add(o as usize) as *const c_void,
                        len as usize,
                        hva as i64,
                    )
                };
                if r < 0 || r as u64 != len {
                    return Err(super::CUDA_ERROR_INVALID_HANDLE);
                }
            }
        } else {
            // H2D: pread each segment from the clone into staging, then one DMA.
            for (hva, o, len) in resolved {
                let r = unsafe {
                    libc::pread(
                        memfd,
                        stg.add(o as usize) as *mut c_void,
                        len as usize,
                        hva as i64,
                    )
                };
                if r < 0 || r as u64 != len {
                    return Err(super::CUDA_ERROR_INVALID_HANDLE);
                }
            }
            unsafe { chk(htod(dptr, stg as *const c_void, total as usize))? };
        }
        Ok(())
    }

    /// Order a blocking copy after prior work on `stream`. Torch creates its
    /// pool streams non-blocking, so the NULL-stream blocking `cuMemcpy*` our
    /// copies use does NOT wait for them — without this wait, a stream-ordered
    /// `cudaMemcpyAsync` from the guest could overwrite (or read) memory that
    /// kernels still running on `stream` are using.
    fn wait_stream(&mut self, stream: u64) -> CuResult<()> {
        if stream == 0 {
            return Ok(()); // legacy default stream: blocking copies already order
        }
        unsafe { chk((self.stream_synchronize)(stream as *mut c_void)) }
    }

    /// Pin the guest-RAM host mappings into the current CUDA context on the first
    /// zero-copy transfer, so subsequent DMAs from guest RAM run at full pinned
    /// bandwidth (~9 GB/s) instead of the ~3 GB/s pageable path. Best-effort and
    /// one-shot: a driver without the API, memory that can't be pinned, or a
    /// range another connection already owns just leaves that region pageable.
    /// Requires a current context, which exists by the time a transfer happens.
    fn ensure_guest_ram_pinned(&mut self) {
        if self.guest_ram_pin_tried {
            return;
        }
        self.guest_ram_pin_tried = true;
        let Some(reg) = self.mem_host_register else {
            zc_trace("[zc-host] driver lacks cuMemHostRegister — pageable DMA");
            return;
        };
        for &(_, hva, len) in &self.guest_ram {
            // SAFETY: [hva, hva+len) is a live host mapping of guest RAM.
            let rc = unsafe { reg(hva as *mut c_void, len as usize, 0) };
            match rc {
                0 => {
                    self.registered.push((hva, len));
                    zc_trace(&format!(
                        "[zc-host] pinned guest RAM hva={hva:#x} len={len}"
                    ));
                }
                // CUDA_ERROR_HOST_MEMORY_ALREADY_REGISTERED: another connection
                // owns this pin — leave it, but don't unregister it on drop.
                712 => zc_trace(&format!("[zc-host] guest RAM hva={hva:#x} already pinned")),
                _ => zc_trace(&format!(
                    "[zc-host] pin guest RAM hva={hva:#x} len={len} failed rc={rc} (pageable)"
                )),
            }
        }
    }

    /// A pinned host staging buffer of at least `size` bytes, grown on demand and
    /// reused across transfers. `None` if the driver lacks `cuMemAllocHost` or the
    /// allocation fails (the caller then DMAs each segment directly).
    fn ensure_staging(&mut self, size: usize) -> Option<*mut u8> {
        let (addr, cap) = self.staging;
        if addr != 0 && cap >= size {
            return Some(addr as *mut u8);
        }
        let alloc = self.mem_host_alloc?;
        if addr != 0 {
            if let Some(free) = self.mem_free_host {
                // SAFETY: `addr` came from a prior cuMemAllocHost.
                unsafe { free(addr as *mut c_void) };
            }
            self.staging = (0, 0);
        }
        let mut p: *mut c_void = std::ptr::null_mut();
        // SAFETY: valid out-pointer; a current context exists during a transfer.
        let rc = unsafe { alloc(&mut p, size) };
        if rc != 0 || p.is_null() {
            return None;
        }
        self.staging = (p as usize, size);
        Some(p as *mut u8)
    }

    /// Translate a guest-physical range `[gpa, gpa+len)` to a host pointer,
    /// finding the RAM region that contains it. The whole range must lie in one
    /// region (guest buffers are page-pinned and never straddle the PCI hole).
    fn gpa_to_host(&self, gpa: u64, len: u64) -> CuResult<*mut u8> {
        let end = gpa
            .checked_add(len)
            .ok_or(super::CUDA_ERROR_INVALID_HANDLE)?;
        for &(start, hva, rlen) in &self.guest_ram {
            if gpa >= start && end <= start + rlen {
                return Ok((hva + (gpa - start)) as *mut u8);
            }
        }
        Err(super::CUDA_ERROR_INVALID_HANDLE)
    }

    /// Load real nvcomp on first use (from `SMOLVM_NVCOMP_LIB`).
    fn ensure_nvcomp(&mut self) -> CuResult<&Nvcomp> {
        if self.nvcomp.is_none() {
            match Nvcomp::load() {
                Ok(n) => self.nvcomp = Some(n),
                Err(e) => {
                    tracing_note(&e);
                    return Err(super::CUDA_ERROR_NOT_FOUND);
                }
            }
        }
        Ok(self.nvcomp.as_ref().unwrap())
    }
    /// Load real cuBLAS on first use (from `SMOLVM_CUBLAS_LIB`).
    fn ensure_cublas(&mut self) -> CuResult<&Cublas> {
        if self.cublas.is_none() {
            match Cublas::load() {
                Ok(c) => self.cublas = Some(c),
                Err(e) => {
                    tracing_note(&e);
                    return Err(super::CUDA_ERROR_NOT_FOUND);
                }
            }
        }
        Ok(self.cublas.as_ref().unwrap())
    }

    /// Dispatch a generic `LibCall` to the code-generated handler for `lib`.
    fn gen_lib_call(
        &mut self,
        lib: u8,
        func: u16,
        args: &[u8],
        streams: &std::collections::HashMap<u64, u64>,
    ) -> CuResult<(i32, Vec<u8>)> {
        match lib {
            LIB_DRIVER_TMA => {
                // cuTensorMapEncodeTiled: 152-byte blob (see the guest shim),
                // reply = the 128-byte CUtensorMap. The global address goes
                // through the clone translation like every other device
                // pointer; the descriptor embeds the RESOLVED address, so
                // clone kernels using it touch their own memory.
                if func != 0 || args.len() < 152 {
                    return Err(1); // CUDA_ERROR_INVALID_VALUE
                }
                type EncodeTiled = unsafe extern "C" fn(
                    *mut u8,
                    c_int,
                    u32,
                    *mut c_void,
                    *const u64,
                    *const u64,
                    *const u32,
                    *const u32,
                    c_int,
                    c_int,
                    c_int,
                    c_int,
                ) -> c_int;
                let f: EncodeTiled = unsafe {
                    sym(&self._lib, b"cuTensorMapEncodeTiled\0")
                        .map_err(|_| super::CUDA_ERROR_NOT_SUPPORTED)?
                };
                let rd_u32 = |o: usize| u32::from_le_bytes(args[o..o + 4].try_into().unwrap());
                let rd_u64 = |o: usize| u64::from_le_bytes(args[o..o + 8].try_into().unwrap());
                let dtype = rd_u32(0) as c_int;
                let rank = rd_u32(4).min(5);
                let gaddr = dptr_resolve(rd_u64(8));
                let mut gdim = [0u64; 5];
                let mut gstr = [0u64; 5];
                let mut bdim = [0u32; 5];
                let mut estr = [0u32; 5];
                for i in 0..5 {
                    gdim[i] = rd_u64(16 + i * 8);
                    gstr[i] = rd_u64(56 + i * 8);
                    bdim[i] = rd_u32(96 + i * 4);
                    estr[i] = rd_u32(116 + i * 4);
                }
                let mut map = [0u8; 128];
                // SAFETY: real driver entry point with in-range arrays; the
                // descriptor out-buffer is exactly CUtensorMap-sized.
                let st = unsafe {
                    f(
                        map.as_mut_ptr(),
                        dtype,
                        rank,
                        gaddr as *mut c_void,
                        gdim.as_ptr(),
                        gstr.as_ptr(),
                        bdim.as_ptr(),
                        estr.as_ptr(),
                        rd_u32(136) as c_int,
                        rd_u32(140) as c_int,
                        rd_u32(144) as c_int,
                        rd_u32(148) as c_int,
                    )
                };
                Ok((st, if st == 0 { map.to_vec() } else { Vec::new() }))
            }
            LIB_CUBLAS => {
                if self.cublas_gen.is_none() {
                    match gen_cublas::GenLib::load() {
                        Ok(g) => self.cublas_gen = Some(g),
                        Err(e) => {
                            tracing_note(&e);
                            return Err(super::CUDA_ERROR_NOT_FOUND);
                        }
                    }
                }
                let mut vh = self.vhandles.lock().unwrap();
                Ok(self
                    .cublas_gen
                    .as_ref()
                    .unwrap()
                    .dispatch(func, args, &mut vh, streams))
            }
            LIB_CUDNN => {
                if self.cudnn_gen.is_none() {
                    match gen_cudnn::GenLib::load() {
                        Ok(g) => self.cudnn_gen = Some(g),
                        Err(e) => {
                            tracing_note(&e);
                            return Err(super::CUDA_ERROR_NOT_FOUND);
                        }
                    }
                }
                let mut vh = self.vhandles.lock().unwrap();
                Ok(self
                    .cudnn_gen
                    .as_ref()
                    .unwrap()
                    .dispatch(func, args, &mut vh, streams))
            }
            LIB_CUDNN_BACKEND => {
                if self.cudnn_backend.is_none() {
                    match CudnnBackend::load() {
                        Ok(b) => self.cudnn_backend = Some(b),
                        Err(e) => {
                            tracing_note(&e);
                            return Err(super::CUDA_ERROR_NOT_FOUND);
                        }
                    }
                }
                let mut vh = self.vhandles.lock().unwrap();
                Ok(self
                    .cudnn_backend
                    .as_ref()
                    .unwrap()
                    .dispatch(func, args, &mut vh))
            }
            LIB_CUBLASLT => {
                if self.cublaslt.is_none() {
                    match CublasLt::load() {
                        Ok(b) => self.cublaslt = Some(b),
                        Err(e) => {
                            tracing_note(&e);
                            return Err(super::CUDA_ERROR_NOT_FOUND);
                        }
                    }
                }
                let mut vh = self.vhandles.lock().unwrap();
                Ok(self
                    .cublaslt
                    .as_ref()
                    .unwrap()
                    .dispatch(func, args, &mut vh, streams))
            }
            LIB_CUDNN_BN => {
                if self.cudnn_bn.is_none() {
                    match CudnnBn::load() {
                        Ok(b) => self.cudnn_bn = Some(b),
                        Err(e) => {
                            tracing_note(&e);
                            return Err(super::CUDA_ERROR_NOT_FOUND);
                        }
                    }
                }
                let vh = self.vhandles.lock().unwrap();
                Ok(self.cudnn_bn.as_ref().unwrap().dispatch(func, args, &vh))
            }
            _ => Err(super::CUDA_ERROR_NOT_FOUND),
        }
    }
}

fn tracing_note(msg: &str) {
    eprintln!("cuda-host: nvcomp unavailable: {msg}");
}

/// Emit a host-side zero-copy trace line. Goes to the file named by
/// `SMOLVM_CUDA_HOST_TRACE_FILE` if set (the boot subprocess silences stderr),
/// else to stderr when `SMOLVM_CUDA_HOST_TRACE` is set.
pub(crate) fn zc_trace(msg: &str) {
    if let Some(path) = std::env::var_os("SMOLVM_CUDA_HOST_TRACE_FILE") {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            let _ = writeln!(f, "{msg}");
        }
    } else if std::env::var_os("SMOLVM_CUDA_HOST_TRACE").is_some() {
        eprintln!("{msg}");
    }
}

fn zc_trace_enabled() -> bool {
    std::env::var_os("SMOLVM_CUDA_HOST_TRACE_FILE").is_some()
        || std::env::var_os("SMOLVM_CUDA_HOST_TRACE").is_some()
}

/// Trace guest-RAM zero-copy transfers: direction, total bytes, and how many
/// physical segments the buffer coalesced to (1 = physically contiguous → a
/// single DMA).
fn zc_trace_segments(dir: &str, segments: &[(u64, u64)]) {
    if zc_trace_enabled() {
        let total: u64 = segments.iter().map(|(_, l)| *l).sum();
        zc_trace(&format!(
            "[zc-host] {dir} gpa memcpy: {total} bytes in {} segment(s)",
            segments.len()
        ));
    }
}

#[cfg(test)]
mod handoff_tests {
    use super::handoff_register;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    fn map(pairs: &[(u64, u64)]) -> Arc<Mutex<HashMap<u64, u64>>> {
        Arc::new(Mutex::new(pairs.iter().copied().collect()))
    }

    // A fork clone (fresh, empty handle map) resuming its parent's token adopts
    // the parent's live descriptor map — the mechanism that keeps a clone's
    // cuBLAS/cuDNN handles valid after it reconnects.
    #[test]
    fn clone_adopts_parent_handle_map() {
        // Parent registers (fresh), then creates a descriptor after the fact —
        // the clone must see it because the registry holds the live map.
        let parent = map(&[]);
        let ptoken = handoff_register(&parent, 0);
        assert_ne!(ptoken, 0, "a session gets a non-zero lineage token");
        parent.lock().unwrap().insert(1 << 63, 0xdead_beef);

        let clone = map(&[]);
        let ctoken = handoff_register(&clone, ptoken);
        assert_ne!(ctoken, ptoken, "the clone gets its own token");
        assert_eq!(
            clone.lock().unwrap().get(&(1 << 63)).copied(),
            Some(0xdead_beef),
            "clone adopted the parent's descriptor"
        );

        // The clone's own later descriptors do not leak back into the parent.
        clone.lock().unwrap().insert((1 << 63) | 2, 0x1234);
        assert!(
            !parent.lock().unwrap().contains_key(&((1 << 63) | 2)),
            "clone and parent maps are independent copies"
        );
    }

    // Resuming a token whose session has closed (its map dropped) is not an
    // error — the clone simply starts empty instead of faulting.
    #[test]
    fn resuming_a_dead_token_is_harmless() {
        let dead_token = {
            let gone = map(&[(1 << 63, 7)]);
            handoff_register(&gone, 0)
            // `gone` drops here; the registry's Weak can no longer upgrade.
        };
        let clone = map(&[]);
        let t = handoff_register(&clone, dead_token);
        assert_ne!(t, 0);
        assert!(
            clone.lock().unwrap().is_empty(),
            "no parent to adopt → empty map, no panic"
        );
    }
}
