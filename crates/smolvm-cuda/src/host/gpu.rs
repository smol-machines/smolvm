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
    ctx_create: unsafe extern "C" fn(*mut *mut c_void, c_uint, c_int) -> CuResultCode,
    ctx_destroy: unsafe extern "C" fn(*mut c_void) -> CuResultCode,
    module_load_data: unsafe extern "C" fn(*mut *mut c_void, *const c_void) -> CuResultCode,
    module_get_function:
        unsafe extern "C" fn(*mut *mut c_void, *mut c_void, *const c_char) -> CuResultCode,
    mem_alloc: unsafe extern "C" fn(*mut u64, usize) -> CuResultCode,
    mem_free: unsafe extern "C" fn(u64) -> CuResultCode,
    memcpy_htod: unsafe extern "C" fn(u64, *const c_void, usize) -> CuResultCode,
    memcpy_dtoh: unsafe extern "C" fn(*mut c_void, u64, usize) -> CuResultCode,
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
}

unsafe fn sym<T>(lib: &Library, name: &[u8]) -> Result<T, String> {
    let s: Symbol<T> = lib
        .get(name)
        .map_err(|e| format!("symbol {}: {e}", String::from_utf8_lossy(name)))?;
    // Transmute the borrowed Symbol into a bare fn pointer; `_lib` in the
    // struct keeps the library loaded for the pointer's whole lifetime.
    Ok(std::ptr::read(&s as *const Symbol<T> as *const T))
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
                ctx_create: sym(&lib, b"cuCtxCreate_v2\0")?,
                ctx_destroy: sym(&lib, b"cuCtxDestroy_v2\0")?,
                module_load_data: sym(&lib, b"cuModuleLoadData\0")?,
                module_get_function: sym(&lib, b"cuModuleGetFunction\0")?,
                mem_alloc: sym(&lib, b"cuMemAlloc_v2\0")?,
                mem_free: sym(&lib, b"cuMemFree_v2\0")?,
                memcpy_htod: sym(&lib, b"cuMemcpyHtoD_v2\0")?,
                memcpy_dtoh: sym(&lib, b"cuMemcpyDtoH_v2\0")?,
                launch_kernel: sym(&lib, b"cuLaunchKernel\0")?,
                ctx_synchronize: sym(&lib, b"cuCtxSynchronize\0")?,
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

impl Backend for GpuBackend {
    fn init(&mut self) -> CuResult<()> {
        unsafe { chk((self.init)(0)) }
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
    fn ctx_create(&mut self, device: i32) -> CuResult<u64> {
        let mut ctx: *mut c_void = std::ptr::null_mut();
        unsafe { chk((self.ctx_create)(&mut ctx, 0, device))? };
        Ok(ctx as u64)
    }
    fn ctx_destroy(&mut self, ctx: u64) -> CuResult<()> {
        unsafe { chk((self.ctx_destroy)(ctx as *mut c_void)) }
    }
    fn module_load_data(&mut self, image: &[u8]) -> CuResult<u64> {
        // cuModuleLoadData reads a NUL-terminated PTX string or a cubin blob.
        // Ensure a trailing NUL so PTX text is well-formed for the JIT.
        let mut buf = image.to_vec();
        if !buf.ends_with(&[0]) {
            buf.push(0);
        }
        let mut module: *mut c_void = std::ptr::null_mut();
        unsafe {
            chk((self.module_load_data)(
                &mut module,
                buf.as_ptr() as *const c_void,
            ))?
        };
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
    fn mem_alloc(&mut self, bytes: u64) -> CuResult<u64> {
        let mut dptr: u64 = 0;
        unsafe { chk((self.mem_alloc)(&mut dptr, bytes as usize))? };
        Ok(dptr)
    }
    fn mem_free(&mut self, dptr: u64) -> CuResult<()> {
        unsafe { chk((self.mem_free)(dptr)) }
    }
    fn memcpy_htod(&mut self, dptr: u64, data: &[u8]) -> CuResult<()> {
        unsafe {
            chk((self.memcpy_htod)(
                dptr,
                data.as_ptr() as *const c_void,
                data.len(),
            ))
        }
    }
    fn memcpy_dtoh(&mut self, dptr: u64, bytes: u64) -> CuResult<Vec<u8>> {
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
}
