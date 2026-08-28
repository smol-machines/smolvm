//! Runtime loader for libkrun.
//!
//! smolvm loads libkrun explicitly instead of relying on ELF/Mach-O
//! load-time linking. This lets packed Linux stubs start on hosts that do not
//! already have libkrun installed; packed mode can then extract bundled
//! libraries and load them from the cache.

use crate::util::{libkrun_filename, libkrunfw_filename};
use std::path::{Path, PathBuf};

/// Function pointers loaded from libkrun.
///
/// Required symbols are loaded eagerly. Optional symbols are exposed as
/// `Option` so callers can report feature-specific errors.
#[allow(missing_docs)]
pub struct KrunFunctions {
    // Keep the loaded libraries resident for the lifetime of the function
    // table: the raw symbol pointers below borrow from these. `libloading`
    // unloads (dlclose / FreeLibrary) on drop, so these must outlive the fns.
    _handle: libloading::Library,
    // Wrapped in `Option` so `Drop` can `take()` and `forget()` it, keeping
    // libkrunfw resident (never unloaded) for any libkrun-owned references.
    _fw_handle: Option<libloading::Library>,
    // Retained so feature-specific preflights can validate the exact libkrun
    // that supplied the function table rather than searching the host again.
    _lib_dir: PathBuf,
    pub set_log_level: unsafe extern "C" fn(u32) -> i32,
    pub create_ctx: unsafe extern "C" fn() -> i32,
    pub free_ctx: unsafe extern "C" fn(u32),
    pub set_vm_config: unsafe extern "C" fn(u32, u8, u32) -> i32,
    pub set_cpu_template: unsafe extern "C" fn(u32, u32) -> i32,
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
    pub add_virtiofs3: Option<
        unsafe extern "C" fn(u32, *const libc::c_char, *const libc::c_char, u64, bool) -> i32,
    >,
    pub start_enter: unsafe extern "C" fn(u32) -> i32,
    pub get_last_error: Option<unsafe extern "C" fn() -> *const libc::c_char>,
    pub add_vsock: unsafe extern "C" fn(u32, u32) -> i32,
    /// Add a virtio-console device (the upstream replacement for the removed
    /// `krun_set_console_output`). Unix: input/output/err file descriptors.
    pub add_virtio_console_default:
        unsafe extern "C" fn(u32, libc::c_int, libc::c_int, libc::c_int) -> i32,
    pub set_egress_policy: Option<
        unsafe extern "C" fn(
            u32,
            *const *const libc::c_char,
            *const *const libc::c_char,
            *const *const libc::c_char,
        ) -> i32,
    >,
    pub add_net_unixstream: Option<
        unsafe extern "C" fn(u32, *const libc::c_char, libc::c_int, *mut u8, u32, u32) -> i32,
    >,
    pub get_egress_handle: Option<unsafe extern "C" fn(u32) -> *mut libc::c_void>,
    pub set_gpu_options2: Option<unsafe extern "C" fn(u32, u32, u64) -> i32>,
    /// Add a virtio-gpu scanout (display) of the given width/height.
    ///
    /// Without at least one display the device reports `num_scanouts = 0`, the
    /// guest virtio-gpu driver creates no connector, and `/dev/dri/card0` is a
    /// render node only — so DRM compositors (Hyprland, GNOME, KDE) refuse to
    /// start with "not a KMS device". `None` on libkrun builds predating the API.
    pub add_display: Option<unsafe extern "C" fn(u32, u32, u32) -> i32>,
    /// Register a host display backend that consumes scanout frames.
    ///
    /// `krun_add_display` only *describes* a display. Without a backend
    /// libkrun installs a no-op whose `configure_scanout`/`alloc_frame`/
    /// `present_frame` all fail, so the guest's first page flip never
    /// completes and a compositor blocks on it forever. `None` on libkrun
    /// builds predating the API.
    pub set_display_backend: Option<unsafe extern "C" fn(u32, *const libc::c_void, usize) -> i32>,
    /// Registers a virtio-input device from a config vtable and an event
    /// provider vtable; present only in libkrun builds with the input feature.
    pub add_input_device: Option<
        unsafe extern "C" fn(u32, *const libc::c_void, usize, *const libc::c_void, usize) -> i32,
    >,
    /// Retrieve guest RAM regions (`gpa_start, host_va, len` triples) for
    /// zero-copy CUDA transfers. `None` on libkrun builds that predate the API.
    pub get_guest_ram: Option<unsafe extern "C" fn(u32, *mut u64, u32, *mut u64) -> i32>,
    /// Register a Unix control socket for the VM (pause/resume/checkpoint/restore).
    pub set_control_socket: Option<unsafe extern "C" fn(u32, *const libc::c_char) -> i32>,
    /// Boot the VM as a fork clone from a snapshot directory (CoW-map a golden
    /// VM's RAM + restore state instead of cold-booting).
    pub set_snapshot: Option<unsafe extern "C" fn(u32, *const libc::c_char) -> i32>,
    /// Create a qcow2 copy-on-write overlay backed by an existing disk image
    /// (used for fork-clone block disks). Pure filesystem op; takes no ctx.
    pub create_disk_overlay:
        Option<unsafe extern "C" fn(*const libc::c_char, *const libc::c_char, u32) -> i32>,
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
        // libkrunfw must be loaded with RTLD_GLOBAL on Unix so libkrun can
        // resolve it later by soname; `libloading` only exposes that via the
        // os-specific `Library::open`. On Windows there is no RTLD_GLOBAL
        // concept, so a plain `Library::new` is used.
        let fw_handle = load_library_global(&fw_lib_path)
            .map_err(|e| format!("failed to load {}: {}", fw_lib_path.display(), e))?;

        let lib_path = lib_dir.join(libkrun_filename());
        // RTLD_LAZY (not RTLD_NOW) on Unix: a single libkrun built with the GPU
        // feature references virglrenderer, but on Linux that NEEDED entry is
        // stripped at package time so a host without virglrenderer can still
        // load it. Lazy binding defers the virgl symbols until the GPU path
        // actually calls them; preload_linux_gpu_dependencies() loads
        // virglrenderer first when a GPU host has it. Non-GPU hosts never bind
        // those symbols.
        let handle = libloading::Library::new(&lib_path)
            .map_err(|e| format!("failed to load {}: {}", lib_path.display(), e))?;

        macro_rules! load_sym {
            ($name:ident) => {{
                let sym: libloading::Symbol<*mut std::ffi::c_void> = handle
                    .get(concat!(stringify!($name), "\0").as_bytes())
                    .map_err(|_| format!("symbol not found: {}", stringify!($name)))?;
                // The raw pointer outlives the `Symbol` borrow; the backing
                // `Library` is kept resident in `_handle`/`_fw_handle`.
                #[allow(clippy::missing_transmute_annotations)]
                std::mem::transmute(*sym)
            }};
        }

        macro_rules! load_optional_sym {
            ($name:literal) => {{
                match handle.get::<*mut std::ffi::c_void>(concat!($name, "\0").as_bytes()) {
                    Ok(sym) =>
                    {
                        #[allow(clippy::missing_transmute_annotations)]
                        Some(std::mem::transmute(*sym))
                    }
                    Err(_) => None,
                }
            }};
        }

        // Resolve all symbols (borrowing `handle`) before moving the libraries
        // into the struct, so the moves don't conflict with the borrows.
        let set_log_level = load_sym!(krun_set_log_level);
        let create_ctx = load_sym!(krun_create_ctx);
        let free_ctx = load_sym!(krun_free_ctx);
        let set_vm_config = load_sym!(krun_set_vm_config);
        let set_cpu_template = load_sym!(krun_set_cpu_template);
        let set_workdir = load_sym!(krun_set_workdir);
        let set_exec = load_sym!(krun_set_exec);
        let set_port_map = load_sym!(krun_set_port_map);
        let add_disk2 = load_sym!(krun_add_disk2);
        let add_vsock_port2 = load_sym!(krun_add_vsock_port2);
        let add_virtiofs = load_sym!(krun_add_virtiofs);
        let add_virtiofs3 = load_optional_sym!("krun_add_virtiofs3");
        let start_enter = load_sym!(krun_start_enter);
        let get_last_error = load_optional_sym!("krun_get_last_error");
        let add_vsock = load_sym!(krun_add_vsock);
        let add_virtio_console_default = load_sym!(krun_add_virtio_console_default);
        let set_egress_policy = load_optional_sym!("krun_set_egress_policy");
        let add_net_unixstream = load_optional_sym!("krun_add_net_unixstream");
        let get_egress_handle = load_optional_sym!("krun_get_egress_handle");
        let set_gpu_options2 = load_optional_sym!("krun_set_gpu_options2");
        let add_display = load_optional_sym!("krun_add_display");
        let set_display_backend = load_optional_sym!("krun_set_display_backend");
        let add_input_device = load_optional_sym!("krun_add_input_device");
        let get_guest_ram = load_optional_sym!("krun_get_guest_ram");
        let set_control_socket = load_optional_sym!("krun_set_control_socket");
        let set_snapshot = load_optional_sym!("krun_set_snapshot");
        let create_disk_overlay = load_optional_sym!("krun_create_disk_overlay");

        Ok(Self {
            _handle: handle,
            _fw_handle: Some(fw_handle),
            _lib_dir: lib_dir.to_path_buf(),
            set_log_level,
            create_ctx,
            free_ctx,
            set_vm_config,
            set_cpu_template,
            set_workdir,
            set_exec,
            set_port_map,
            add_disk2,
            add_vsock_port2,
            add_virtiofs,
            add_virtiofs3,
            start_enter,
            get_last_error,
            add_vsock,
            add_virtio_console_default,
            set_egress_policy,
            add_net_unixstream,
            get_egress_handle,
            set_gpu_options2,
            add_display,
            set_display_backend,
            add_input_device,
            get_guest_ram,
            set_control_socket,
            set_snapshot,
            create_disk_overlay,
        })
    }
}

impl KrunFunctions {
    /// Copy libkrun's thread-local diagnostic before another FFI call can
    /// replace it. Older compatible libraries simply return no detail.
    pub fn last_error_message(&self) -> Option<String> {
        let get_last_error = self.get_last_error?;
        // SAFETY: libkrun owns a NUL-terminated thread-local string whose
        // lifetime extends until the next error update; copy it immediately.
        let ptr = unsafe { get_last_error() };
        if ptr.is_null() {
            return None;
        }
        Some(
            unsafe { std::ffi::CStr::from_ptr(ptr) }
                .to_string_lossy()
                .into_owned(),
        )
    }

    /// Validate the optional host libraries needed by libkrun's Vulkan path.
    ///
    /// Linux release artifacts deliberately remove libkrun's hard
    /// `libvirglrenderer.so.1` dependency so CPU- and CUDA-only machines still
    /// boot on hosts without a Vulkan stack. That makes the dependency lazy,
    /// but calling `krun_set_gpu_options2` with an absent or ABI-incompatible
    /// virglrenderer would otherwise terminate the VMM at symbol resolution.
    /// Resolve the entire libkrun object with `RTLD_NOW` first and return an
    /// actionable error while the caller can still abort cleanly.
    pub fn ensure_gpu_runtime(&self) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            ensure_linux_gpu_dependencies(&self._lib_dir)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(())
        }
    }

    /// Redirect the guest console output to `path`, using the upstream
    /// virtio-console API (the replacement for the removed
    /// `krun_set_console_output`). Returns libkrun's rc, or a negative value if
    /// the file can't be opened.
    ///
    /// The opened fds are intentionally leaked: a console device's fds must stay
    /// valid for the VM's lifetime, and `krun_start_enter` runs the VM in this
    /// process, so the process owns them until it exits.
    ///
    /// # Safety
    /// `ctx` must be a valid libkrun context that has not yet been started.
    #[cfg(unix)]
    pub unsafe fn console_output_to_file(&self, ctx: u32, path: &Path) -> i32 {
        use std::os::fd::IntoRawFd;
        let Ok(out) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        else {
            return -1;
        };
        let out_fd = out.into_raw_fd();
        // Console input comes from /dev/null (the agent talks over vsock, not the
        // console); output and stderr both go to the log file.
        let null_fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
        unsafe { (self.add_virtio_console_default)(ctx, null_fd, out_fd, out_fd) }
    }

    /// Windows stub: the virtio-console redirection relies on POSIX file
    /// descriptors passed to libkrun. The Windows libkrun ABI/console wiring is
    /// not implemented here, so this is a no-op that reports failure.
    ///
    /// # Safety
    /// `unsafe` only to match the Unix signature (which dereferences libkrun
    /// function pointers). This stub touches nothing and is always sound to call.
    #[cfg(not(unix))]
    pub unsafe fn console_output_to_file(&self, _ctx: u32, _path: &Path) -> i32 {
        -1
    }
}

// libkrun's `_handle` is unloaded automatically when `KrunFunctions` is
// dropped (libloading calls dlclose / FreeLibrary). libkrunfw (`_fw_handle`)
// is intentionally kept resident for any libkrun-owned references, so we leak
// it rather than letting it unload.
impl Drop for KrunFunctions {
    fn drop(&mut self) {
        // Leak libkrunfw rather than unloading it: libkrun may still hold
        // references resolved against it. `_handle` (libkrun itself) is dropped
        // normally, unloading it.
        if let Some(fw) = self._fw_handle.take() {
            std::mem::forget(fw);
        }
    }
}

/// Load a dynamic library with global symbol visibility where the platform
/// supports it (RTLD_GLOBAL on Unix). On Windows there is no equivalent flag,
/// so a normal load is performed.
unsafe fn load_library_global(path: &Path) -> Result<libloading::Library, String> {
    #[cfg(unix)]
    {
        use libloading::os::unix::{Library, RTLD_GLOBAL, RTLD_NOW};
        Library::open(Some(path), RTLD_NOW | RTLD_GLOBAL)
            .map(Into::into)
            .map_err(|e| e.to_string())
    }
    #[cfg(not(unix))]
    {
        libloading::Library::new(path).map_err(|e| e.to_string())
    }
}

#[cfg(target_os = "linux")]
fn dlerror_message() -> String {
    unsafe {
        let err = libc::dlerror();
        if err.is_null() {
            "unknown error".to_string()
        } else {
            std::ffi::CStr::from_ptr(err).to_string_lossy().to_string()
        }
    }
}

#[cfg(target_os = "linux")]
fn preload_linux_gpu_dependencies(lib_dir: &Path) {
    for lib_name in &["libepoxy.so.0", "libvirglrenderer.so.1"] {
        let path = lib_dir.join(lib_name);
        let loaded = if path.exists() {
            dlopen_global(&path)
        } else {
            // Not bundled: try the host's copy by soname. A GPU host has
            // virglrenderer (and its X11/DRM/Mesa chain) installed system-wide;
            // loading it RTLD_GLOBAL here lets libkrun's lazily-bound virgl
            // symbols resolve when the GPU path runs. Best-effort — on a non-GPU
            // host it simply isn't found, which is fine: those symbols are never
            // called, and the libkrun NEEDED entry was stripped at package time.
            dlopen_global_soname(lib_name)
        };
        if let Err(error) = loaded {
            tracing::debug!(library = lib_name, %error, "optional GPU dependency unavailable");
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
fn ensure_linux_gpu_dependencies(lib_dir: &Path) -> Result<(), String> {
    // Epoxy is commonly a transitive virglrenderer dependency. Preload a
    // bundled copy when present, but let virglrenderer's own loader diagnose a
    // missing system copy so statically-linked builds remain valid.
    let epoxy = lib_dir.join("libepoxy.so.0");
    if epoxy.exists() {
        dlopen_global(&epoxy).map_err(linux_gpu_runtime_error)?;
    } else {
        let _ = dlopen_global_soname("libepoxy.so.0");
    }

    let virgl = lib_dir.join("libvirglrenderer.so.1");
    if virgl.exists() {
        dlopen_global(&virgl).map_err(linux_gpu_runtime_error)?;
    } else {
        dlopen_global_soname("libvirglrenderer.so.1").map_err(linux_gpu_runtime_error)?;
    }

    // Force every lazy undefined symbol in this exact libkrun to resolve now.
    // This catches an installed virglrenderer with the wrong ABI (the observed
    // failure was a missing `virgl_set_debug_callback`) before the first GPU
    // FFI call can make the dynamic linker abort the VMM process.
    dlopen_now(&lib_dir.join(libkrun_filename())).map_err(linux_gpu_runtime_error)
}

#[cfg(target_os = "linux")]
fn linux_gpu_runtime_error(detail: String) -> String {
    format!(
        "Linux Vulkan GPU support (--gpu) requires a compatible \
         libvirglrenderer.so.1 and host Vulkan driver. Install virglrenderer \
         plus your Mesa/Vulkan driver (Debian/Ubuntu: `apt install \
         virglrenderer0 mesa-vulkan-drivers`; Arch: `pacman -S virglrenderer`): {detail}"
    )
}

#[cfg(target_os = "linux")]
fn dlopen_global(path: &Path) -> Result<(), String> {
    use std::ffi::CString;
    let path_c = CString::new(path.to_string_lossy().as_bytes())
        .map_err(|_| format!("library path contains NUL: {}", path.display()))?;

    unsafe {
        libc::dlerror();
        let handle = libc::dlopen(path_c.as_ptr(), libc::RTLD_NOW | libc::RTLD_GLOBAL);
        if handle.is_null() {
            return Err(format!(
                "failed to load {}: {}",
                path.display(),
                dlerror_message()
            ));
        }
    }

    Ok(())
}

/// Load a library by soname (no path), letting the dynamic loader search the
/// host's standard library directories. Used to pick up a GPU host's
/// system-installed virglrenderer when it isn't bundled. Best-effort: on a
/// non-GPU host the library is absent, which is expected and not an error.
#[cfg(target_os = "linux")]
fn dlopen_global_soname(soname: &str) -> Result<(), String> {
    use std::ffi::CString;
    let soname_c = CString::new(soname).map_err(|_| format!("invalid library name: {soname}"))?;
    unsafe {
        libc::dlerror();
        let handle = libc::dlopen(soname_c.as_ptr(), libc::RTLD_NOW | libc::RTLD_GLOBAL);
        if handle.is_null() {
            Err(format!("failed to load {soname}: {}", dlerror_message()))
        } else {
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
fn dlopen_now(path: &Path) -> Result<(), String> {
    use std::ffi::CString;
    let path_c = CString::new(path.to_string_lossy().as_bytes())
        .map_err(|_| format!("library path contains NUL: {}", path.display()))?;
    unsafe {
        libc::dlerror();
        let handle = libc::dlopen(path_c.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL);
        if handle.is_null() {
            Err(format!(
                "{} is incompatible with the installed Vulkan stack: {}",
                path.display(),
                dlerror_message()
            ))
        } else {
            // `KrunFunctions` retains the original libkrun handle. Balance only
            // this validation reference; the object and resolved symbols remain
            // resident through `_handle`.
            libc::dlclose(handle);
            Ok(())
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod linux_gpu_tests {
    use super::linux_gpu_runtime_error;

    #[test]
    fn gpu_runtime_error_is_actionable() {
        let error = linux_gpu_runtime_error("undefined symbol: virgl_example".to_string());
        assert!(error.contains("--gpu"));
        assert!(error.contains("libvirglrenderer.so.1"));
        assert!(error.contains("apt install"));
        assert!(error.contains("pacman -S"));
        assert!(error.contains("virgl_example"));
    }
}
