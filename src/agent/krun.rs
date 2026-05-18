//! Runtime loader for libkrun.
//!
//! smolvm loads libkrun explicitly instead of relying on ELF/Mach-O
//! load-time linking. This lets packed Linux stubs start on hosts that do not
//! already have libkrun installed; packed mode can then extract bundled
//! libraries and load them from the cache.

use crate::util::{libkrun_filename, libkrunfw_filename};
use std::ffi::{CStr, CString};
use std::path::Path;

/// Function pointers loaded from libkrun.
///
/// Required symbols are loaded eagerly. Optional symbols are exposed as
/// `Option` so callers can report feature-specific errors.
#[allow(missing_docs)]
pub struct KrunFunctions {
    _handle: *mut libc::c_void,
    _fw_handle: *mut libc::c_void,
    pub set_log_level: unsafe extern "C" fn(u32) -> i32,
    pub create_ctx: unsafe extern "C" fn() -> i32,
    pub free_ctx: unsafe extern "C" fn(u32),
    pub set_vm_config: unsafe extern "C" fn(u32, u8, u32) -> i32,
    pub set_root: unsafe extern "C" fn(u32, *const libc::c_char) -> i32,
    pub set_workdir: unsafe extern "C" fn(u32, *const libc::c_char) -> i32,
    pub set_exec: unsafe extern "C" fn(
        u32,
        *const libc::c_char,
        *const *const libc::c_char,
        *const *const libc::c_char,
    ) -> i32,
    pub set_port_map: unsafe extern "C" fn(u32, *const *const libc::c_char) -> i32,
    pub add_disk2:
        unsafe extern "C" fn(u32, *const libc::c_char, *const libc::c_char, u32, bool) -> i32,
    pub add_vsock_port2: unsafe extern "C" fn(u32, u32, *const libc::c_char, bool) -> i32,
    pub add_virtiofs: unsafe extern "C" fn(u32, *const libc::c_char, *const libc::c_char) -> i32,
    pub start_enter: unsafe extern "C" fn(u32) -> i32,
    pub disable_implicit_vsock: unsafe extern "C" fn(u32) -> i32,
    pub add_vsock: unsafe extern "C" fn(u32, u32) -> i32,
    pub set_console_output: unsafe extern "C" fn(u32, *const libc::c_char) -> i32,
    pub set_control_socket: Option<unsafe extern "C" fn(u32, *const libc::c_char) -> i32>,
    pub set_egress_policy: Option<unsafe extern "C" fn(u32, *const *const libc::c_char) -> i32>,
    pub add_net_unixstream: Option<
        unsafe extern "C" fn(u32, *const libc::c_char, libc::c_int, *mut u8, u32, u32) -> i32,
    >,
    pub get_egress_handle: Option<unsafe extern "C" fn(u32) -> *mut libc::c_void>,
    pub set_gpu_options2: Option<unsafe extern "C" fn(u32, u32, u64) -> i32>,
}

impl KrunFunctions {
    /// Load libkrun from the given library directory.
    ///
    /// libkrunfw is preloaded with `RTLD_GLOBAL` because libkrun may resolve it
    /// later by soname.
    ///
    /// # Safety
    ///
    /// Caller must ensure `lib_dir` contains compatible libkrun/libkrunfw
    /// libraries for the current host.
    pub unsafe fn load(lib_dir: &Path) -> Result<Self, String> {
        #[cfg(target_os = "linux")]
        preload_linux_gpu_dependencies(lib_dir);

        let fw_lib_path = lib_dir.join(libkrunfw_filename());
        let fw_lib_path_c = CString::new(fw_lib_path.to_string_lossy().as_bytes())
            .map_err(|_| "invalid library path")?;

        let fw_handle = libc::dlopen(fw_lib_path_c.as_ptr(), libc::RTLD_NOW | libc::RTLD_GLOBAL);
        if fw_handle.is_null() {
            return Err(format!(
                "failed to load {}: {}",
                fw_lib_path.display(),
                dlerror_message()
            ));
        }

        let lib_path = lib_dir.join(libkrun_filename());
        let lib_path_c = CString::new(lib_path.to_string_lossy().as_bytes())
            .map_err(|_| "invalid library path")?;

        let handle = libc::dlopen(lib_path_c.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL);
        if handle.is_null() {
            let err = dlerror_message();
            libc::dlclose(fw_handle);
            return Err(format!("failed to load {}: {}", lib_path.display(), err));
        }

        macro_rules! load_sym {
            ($name:ident) => {{
                let sym_name = CString::new(stringify!($name)).expect("symbol name is static");
                let sym = libc::dlsym(handle, sym_name.as_ptr());
                if sym.is_null() {
                    libc::dlclose(handle);
                    libc::dlclose(fw_handle);
                    return Err(format!("symbol not found: {}", stringify!($name)));
                }
                #[allow(clippy::missing_transmute_annotations)]
                std::mem::transmute(sym)
            }};
        }

        macro_rules! load_optional_sym {
            ($name:literal) => {{
                let sym_name = CString::new($name).expect("symbol name is static");
                let sym = libc::dlsym(handle, sym_name.as_ptr());
                if sym.is_null() {
                    None
                } else {
                    #[allow(clippy::missing_transmute_annotations)]
                    Some(std::mem::transmute(sym))
                }
            }};
        }

        Ok(Self {
            _handle: handle,
            _fw_handle: fw_handle,
            set_log_level: load_sym!(krun_set_log_level),
            create_ctx: load_sym!(krun_create_ctx),
            free_ctx: load_sym!(krun_free_ctx),
            set_vm_config: load_sym!(krun_set_vm_config),
            set_root: load_sym!(krun_set_root),
            set_workdir: load_sym!(krun_set_workdir),
            set_exec: load_sym!(krun_set_exec),
            set_port_map: load_sym!(krun_set_port_map),
            add_disk2: load_sym!(krun_add_disk2),
            add_vsock_port2: load_sym!(krun_add_vsock_port2),
            add_virtiofs: load_sym!(krun_add_virtiofs),
            start_enter: load_sym!(krun_start_enter),
            disable_implicit_vsock: load_sym!(krun_disable_implicit_vsock),
            add_vsock: load_sym!(krun_add_vsock),
            set_console_output: load_sym!(krun_set_console_output),
            set_control_socket: load_optional_sym!("krun_set_control_socket"),
            set_egress_policy: load_optional_sym!("krun_set_egress_policy"),
            add_net_unixstream: load_optional_sym!("krun_add_net_unixstream"),
            get_egress_handle: load_optional_sym!("krun_get_egress_handle"),
            set_gpu_options2: load_optional_sym!("krun_set_gpu_options2"),
        })
    }
}

impl Drop for KrunFunctions {
    fn drop(&mut self) {
        unsafe {
            libc::dlclose(self._handle);
            // Keep libkrunfw resident for any libkrun-owned references.
        }
    }
}

fn dlerror_message() -> String {
    unsafe {
        let err = libc::dlerror();
        if err.is_null() {
            "unknown error".to_string()
        } else {
            CStr::from_ptr(err).to_string_lossy().to_string()
        }
    }
}

#[cfg(target_os = "linux")]
fn preload_linux_gpu_dependencies(lib_dir: &Path) {
    for lib_name in &["libepoxy.so.0", "libvirglrenderer.so.1"] {
        let path = lib_dir.join(lib_name);
        if path.exists() {
            dlopen_global(&path);
        }
    }

    let server = lib_dir.join("virgl_render_server");
    if server.exists() && std::env::var("VIRGL_RENDER_SERVER_PATH").is_err() {
        if let Some(s) = server.to_str() {
            #[allow(deprecated)]
            std::env::set_var("VIRGL_RENDER_SERVER_PATH", s);
        }
    }
}

#[cfg(target_os = "linux")]
fn dlopen_global(path: &Path) -> bool {
    let Ok(path_c) = CString::new(path.to_string_lossy().as_bytes()) else {
        return false;
    };

    unsafe {
        let handle = libc::dlopen(path_c.as_ptr(), libc::RTLD_NOW | libc::RTLD_GLOBAL);
        if handle.is_null() {
            tracing::warn!(
                path = %path.display(),
                error = %dlerror_message(),
                "failed to preload library"
            );
            return false;
        }
    }

    true
}
