//! Dynamic (dlopen-based) libkrun launcher for packed/sidecar mode.
//!
//! This module provides a `KrunFunctions` struct that loads libkrun via `dlopen`
//! at runtime, enabling the main smolvm binary to boot VMs using libraries
//! extracted from a `.smolmachine` sidecar file.
//!
//! The static FFI path in `launcher.rs` remains untouched for normal operations.

use smolvm_protocol::ports;
use std::ffi::{CStr, CString};
use std::path::Path;

use super::VmResources;

// TSI (Transparent Socket Impersonation) feature flags
const KRUN_TSI_HIJACK_INET: u32 = 1 << 0;

/// Function pointers for libkrun, loaded via dlopen.
///
/// This struct parallels the `extern "C"` declarations in `launcher.rs`
/// but loads them dynamically so we can use libkrun from extracted sidecar assets.
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
}

impl KrunFunctions {
    /// Load libkrun from the given library directory via dlopen.
    ///
    /// Preloads libkrunfw with `RTLD_GLOBAL` so libkrun can find it.
    ///
    /// # Safety
    ///
    /// Caller must ensure `lib_dir` contains valid libkrun and libkrunfw libraries.
    pub unsafe fn load(lib_dir: &Path) -> Result<Self, String> {
        // Platform-specific library names
        #[cfg(target_os = "macos")]
        let (fw_lib_name, lib_name) = ("libkrunfw.5.dylib", "libkrun.dylib");
        #[cfg(target_os = "linux")]
        let (fw_lib_name, lib_name) = ("libkrunfw.so.5", "libkrun.so");

        // Preload libkrunfw with RTLD_GLOBAL so libkrun can find it
        let fw_lib_path = lib_dir.join(fw_lib_name);
        let fw_lib_path_c = CString::new(fw_lib_path.to_string_lossy().as_bytes())
            .map_err(|_| "invalid library path")?;

        let fw_handle = libc::dlopen(fw_lib_path_c.as_ptr(), libc::RTLD_NOW | libc::RTLD_GLOBAL);
        if fw_handle.is_null() {
            let err = libc::dlerror();
            let err_msg = if err.is_null() {
                "unknown error".to_string()
            } else {
                CStr::from_ptr(err).to_string_lossy().to_string()
            };
            return Err(format!(
                "failed to load {}: {}",
                fw_lib_path.display(),
                err_msg
            ));
        }

        // Load libkrun
        let lib_path = lib_dir.join(lib_name);
        let lib_path_c = CString::new(lib_path.to_string_lossy().as_bytes())
            .map_err(|_| "invalid library path")?;

        let handle = libc::dlopen(lib_path_c.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL);
        if handle.is_null() {
            let err = libc::dlerror();
            let err_msg = if err.is_null() {
                "unknown error".to_string()
            } else {
                CStr::from_ptr(err).to_string_lossy().to_string()
            };
            return Err(format!(
                "failed to load {}: {}",
                lib_path.display(),
                err_msg
            ));
        }

        macro_rules! load_sym {
            ($name:ident) => {{
                let sym_name = CString::new(stringify!($name)).expect("symbol name is static");
                let sym = libc::dlsym(handle, sym_name.as_ptr());
                if sym.is_null() {
                    libc::dlclose(handle);
                    return Err(format!("symbol not found: {}", stringify!($name)));
                }
                #[allow(clippy::missing_transmute_annotations)]
                std::mem::transmute(sym)
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
        })
    }
}

impl Drop for KrunFunctions {
    fn drop(&mut self) {
        unsafe {
            libc::dlclose(self._handle);
            // Note: _fw_handle intentionally not closed — it needs to stay loaded
        }
    }
}

/// Volume mount for packed binaries.
#[derive(Debug, Clone)]
pub struct PackedMount {
    /// Virtiofs tag (e.g., "smolvm0").
    pub tag: String,
    /// Host source path (passed to `krun_add_virtiofs`).
    pub host_path: String,
    /// Guest mount path (passed to agent via `SMOLVM_MOUNT_*` env).
    pub guest_path: String,
    /// Whether the mount is read-only.
    pub read_only: bool,
}

/// Configuration for launching a packed VM.
pub struct PackedLaunchConfig<'a> {
    /// Path to agent rootfs directory.
    pub rootfs_path: &'a Path,
    /// Path to storage disk.
    pub storage_path: &'a Path,
    /// Path to vsock Unix socket.
    pub vsock_socket: &'a Path,
    /// Path to layers directory (for virtiofs).
    pub layers_dir: &'a Path,
    /// Volume mounts.
    pub mounts: &'a [PackedMount],
    /// Port mappings (host, guest).
    pub port_mappings: &'a [(u16, u16)],
    /// VM resources.
    pub resources: VmResources,
    /// Debug logging.
    pub debug: bool,
}

/// Launch VM using dynamically loaded libkrun (for packed/sidecar mode).
///
/// This mirrors the setup logic in `launcher.rs:launch_agent_vm()` but calls
/// through `KrunFunctions` instead of static `extern "C"` symbols.
///
/// # Safety
///
/// Must be called in a forked child process. Never returns on success.
pub fn launch_agent_vm_dynamic(
    krun: &KrunFunctions,
    config: &PackedLaunchConfig,
) -> Result<(), String> {
    // Raise file descriptor limits
    raise_fd_limits();

    // Set library path so libkrun can find libkrunfw
    let lib_dir = config
        .rootfs_path
        .parent()
        .unwrap_or(Path::new("."))
        .join("lib");
    #[cfg(target_os = "macos")]
    {
        let lib_path = lib_dir.to_string_lossy();
        unsafe { std::env::set_var("DYLD_LIBRARY_PATH", lib_path.as_ref()) };
    }
    #[cfg(target_os = "linux")]
    {
        let lib_path = lib_dir.to_string_lossy();
        unsafe { std::env::set_var("LD_LIBRARY_PATH", lib_path.as_ref()) };
    }

    // SAFETY: Each FFI call below is individually wrapped in unsafe.
    // All CString/pointer construction is safe Rust outside the unsafe blocks.

    // Set log level
    let log_level = if config.debug { 3 } else { 0 };
    // SAFETY: set_log_level is a valid function pointer loaded from libkrun
    unsafe { (krun.set_log_level)(log_level) };

    // Create VM context
    // SAFETY: create_ctx is a valid function pointer loaded from libkrun
    let ctx = unsafe { (krun.create_ctx)() };
    if ctx < 0 {
        return Err("krun_create_ctx failed".to_string());
    }
    let ctx = ctx as u32;

    // Helper: clean up context on error (string message)
    macro_rules! free_ctx_on_err {
        ($msg:expr) => {{
            // SAFETY: ctx is a valid context from krun_create_ctx
            unsafe { (krun.free_ctx)(ctx) };
            return Err($msg.to_string());
        }};
    }

    // Helper: evaluate a fallible expression, freeing ctx if it fails.
    // Replaces bare `?` which would leak the libkrun context.
    macro_rules! try_or_free_ctx {
        ($expr:expr, $msg:expr) => {
            match $expr {
                Ok(val) => val,
                Err(_) => free_ctx_on_err!($msg),
            }
        };
    }

    // Set VM config
    // SAFETY: ctx is valid, cpus and mem are primitive values
    if unsafe { (krun.set_vm_config)(ctx, config.resources.cpus, config.resources.mem) } < 0 {
        free_ctx_on_err!("krun_set_vm_config failed");
    }

    // Set root filesystem
    let root = try_or_free_ctx!(
        path_to_cstring(config.rootfs_path),
        "rootfs path contains null byte"
    );
    // SAFETY: ctx is valid, root.as_ptr() is a valid null-terminated C string
    if unsafe { (krun.set_root)(ctx, root.as_ptr()) } < 0 {
        free_ctx_on_err!("krun_set_root failed");
    }

    // Configure TSI networking
    // SAFETY: ctx is valid
    if unsafe { (krun.disable_implicit_vsock)(ctx) } < 0 {
        free_ctx_on_err!("krun_disable_implicit_vsock failed");
    }

    if config.resources.network || !config.port_mappings.is_empty() {
        // SAFETY: ctx is valid, KRUN_TSI_HIJACK_INET is a valid flag
        if unsafe { (krun.add_vsock)(ctx, KRUN_TSI_HIJACK_INET) } < 0 {
            free_ctx_on_err!("krun_add_vsock with TSI failed");
        }

        // Set port mappings
        let port_cstrings: Vec<CString> = config
            .port_mappings
            .iter()
            .map(|(host, guest)| {
                CString::new(format!("{}:{}", host, guest))
                    .expect("port mapping cannot contain null bytes")
            })
            .collect();
        let mut port_ptrs: Vec<*const libc::c_char> =
            port_cstrings.iter().map(|s| s.as_ptr()).collect();
        port_ptrs.push(std::ptr::null());

        // SAFETY: ctx is valid, port_ptrs is a null-terminated array of valid C strings
        if unsafe { (krun.set_port_map)(ctx, port_ptrs.as_ptr()) } < 0 {
            free_ctx_on_err!("krun_set_port_map failed");
        }
    } else {
        // Control-only vsock, no network
        // SAFETY: ctx is valid
        if unsafe { (krun.add_vsock)(ctx, 0) } < 0 {
            free_ctx_on_err!("krun_add_vsock failed");
        }
    }

    // Add storage disk
    let block_id = cstr("storage");
    let disk_path = try_or_free_ctx!(
        path_to_cstring(config.storage_path),
        "storage path contains null byte"
    );
    // SAFETY: ctx is valid, block_id and disk_path are valid C strings
    if unsafe { (krun.add_disk2)(ctx, block_id.as_ptr(), disk_path.as_ptr(), 0, false) } < 0 {
        free_ctx_on_err!("krun_add_disk2 failed");
    }

    // Add vsock port for control channel
    let socket_path = try_or_free_ctx!(
        path_to_cstring(config.vsock_socket),
        "vsock socket path contains null byte"
    );
    // SAFETY: ctx is valid, socket_path is a valid C string
    if unsafe { (krun.add_vsock_port2)(ctx, ports::AGENT_CONTROL, socket_path.as_ptr(), true) } < 0
    {
        free_ctx_on_err!("krun_add_vsock_port2 failed");
    }

    // Set working directory
    let workdir = cstr("/");
    // SAFETY: ctx is valid, workdir is a valid C string
    unsafe { (krun.set_workdir)(ctx, workdir.as_ptr()) };

    // Build environment (all safe Rust)
    let mut env_strings = vec![
        cstr("HOME=/root"),
        cstr("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
        cstr("TERM=xterm-256color"),
    ];

    // Tell agent about packed layers mount
    if config.layers_dir.exists() {
        env_strings.push(cstr("SMOLVM_PACKED_LAYERS=smolvm_layers:/packed_layers"));
    }

    // Pass mount info to the agent via environment
    for (i, mount) in config.mounts.iter().enumerate() {
        let ro_flag = if mount.read_only { "ro" } else { "rw" };
        let env_val = format!(
            "SMOLVM_MOUNT_{}={}:{}:{}",
            i, mount.tag, mount.guest_path, ro_flag
        );
        if let Ok(cstr) = CString::new(env_val) {
            env_strings.push(cstr);
        }
    }

    if !config.mounts.is_empty() {
        if let Ok(cstr) = CString::new(format!("SMOLVM_MOUNT_COUNT={}", config.mounts.len())) {
            env_strings.push(cstr);
        }
    }

    let mut envp: Vec<*const libc::c_char> = env_strings.iter().map(|s| s.as_ptr()).collect();
    envp.push(std::ptr::null());

    // Set exec command (MUST be before add_virtiofs)
    let exec_path = cstr("/sbin/init");
    let argv_strings = [cstr("/sbin/init")];
    let mut argv: Vec<*const libc::c_char> = argv_strings.iter().map(|s| s.as_ptr()).collect();
    argv.push(std::ptr::null());

    // SAFETY: ctx is valid, all pointers are valid null-terminated C strings/arrays
    if unsafe { (krun.set_exec)(ctx, exec_path.as_ptr(), argv.as_ptr(), envp.as_ptr()) } < 0 {
        free_ctx_on_err!("krun_set_exec failed");
    }

    // Add virtiofs mount for packed layers (AFTER set_exec)
    if config.layers_dir.exists() {
        let layers_tag = cstr("smolvm_layers");
        let layers_path = try_or_free_ctx!(
            path_to_cstring(config.layers_dir),
            "layers dir path contains null byte"
        );
        // SAFETY: ctx is valid, tag and path are valid C strings
        if unsafe { (krun.add_virtiofs)(ctx, layers_tag.as_ptr(), layers_path.as_ptr()) } < 0 {
            free_ctx_on_err!("krun_add_virtiofs failed for packed layers");
        }
    }

    // Add user-specified virtiofs mounts
    for mount in config.mounts.iter() {
        let tag = try_or_free_ctx!(
            CString::new(mount.tag.as_str()),
            "mount tag contains null byte"
        );
        let host_path = try_or_free_ctx!(
            CString::new(mount.host_path.as_str()),
            "mount path contains null byte"
        );

        // SAFETY: ctx is valid, tag and host_path are valid C strings
        if unsafe { (krun.add_virtiofs)(ctx, tag.as_ptr(), host_path.as_ptr()) } < 0 {
            free_ctx_on_err!(format!(
                "krun_add_virtiofs failed for '{}' - requested mount cannot be attached",
                mount.tag
            ));
        }
    }

    // Start VM (never returns on success)
    // SAFETY: ctx is valid, all configuration has been set
    let ret = unsafe { (krun.start_enter)(ctx) };

    // If we get here, something went wrong — free the context before returning
    // SAFETY: ctx is a valid context from krun_create_ctx
    unsafe { (krun.free_ctx)(ctx) };
    Err(format!("krun_start_enter returned: {}", ret))
}

/// Create a CString from a static string that is known not to contain NUL bytes.
fn cstr(s: &str) -> CString {
    CString::new(s).expect("string literal must not contain NUL bytes")
}

/// Convert a Path to a CString.
fn path_to_cstring(path: &Path) -> Result<CString, String> {
    CString::new(path.to_string_lossy().as_bytes())
        .map_err(|_| "path contains null byte".to_string())
}

/// Raise file descriptor limits (required by libkrun).
fn raise_fd_limits() {
    unsafe {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };

        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) == 0 {
            limit.rlim_cur = limit.rlim_max;
            libc::setrlimit(libc::RLIMIT_NOFILE, &limit);
        }
    }
}
