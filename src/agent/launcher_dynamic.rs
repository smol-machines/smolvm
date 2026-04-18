//! Dynamic (dlopen-based) libkrun launcher for packed/sidecar mode.
//!
//! This module provides a `KrunFunctions` struct that loads libkrun via `dlopen`
//! at runtime, enabling the main smolvm binary to boot VMs using libraries
//! extracted from a `.smolmachine` sidecar file.
//!
//! The static FFI path in `launcher.rs` remains untouched for normal operations.

use crate::network::backend::{COMPAT_NET_FEATURES, TSI_FEATURE_HIJACK_INET};
use crate::network::{plan_launch_network, EffectiveNetworkBackend};
use crate::util::{libkrun_filename, libkrunfw_filename};
use smolvm_network::{guest_env, start_virtio_network, GuestNetworkConfig, VirtioNetworkRuntime};
use smolvm_protocol::ports;
use std::ffi::{CStr, CString};
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};

use super::VmResources;

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
    pub set_egress_policy: Option<unsafe extern "C" fn(u32, *const *const libc::c_char) -> i32>,
    pub add_net_unixstream: Option<
        unsafe extern "C" fn(u32, *const libc::c_char, libc::c_int, *mut u8, u32, u32) -> i32,
    >,
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
        let fw_lib_name = libkrunfw_filename();
        let lib_name = libkrun_filename();

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
            set_egress_policy: {
                let sym_name =
                    CString::new("krun_set_egress_policy").expect("symbol name is static");
                let sym = libc::dlsym(handle, sym_name.as_ptr());
                if sym.is_null() {
                    None
                } else {
                    #[allow(clippy::missing_transmute_annotations)]
                    Some(std::mem::transmute(sym))
                }
            },
            add_net_unixstream: {
                let sym_name =
                    CString::new("krun_add_net_unixstream").expect("symbol name is static");
                let sym = libc::dlsym(handle, sym_name.as_ptr());
                if sym.is_null() {
                    None
                } else {
                    #[allow(clippy::missing_transmute_annotations)]
                    Some(std::mem::transmute(sym))
                }
            },
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
    /// Path to overlay disk (VM mode only, mounted as /dev/vdb).
    pub overlay_path: Option<&'a Path>,
    /// Path to redirect VM console output (prevents libkrun from putting
    /// the inherited terminal into raw mode).
    pub console_log: PathBuf,
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
    crate::network::validate_requested_network_backend(
        &config.resources,
        None,
        config.port_mappings.len(),
    )
    .map_err(|e| e.to_string())?;

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
    if unsafe { (krun.set_vm_config)(ctx, config.resources.cpus, config.resources.memory_mib) } < 0
    {
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

    let network_plan = plan_launch_network(&config.resources, None, config.port_mappings.len());
    if let Some(reason) = network_plan.fallback_reason {
        tracing::warn!(reason = %reason.user_message(), "network backend fell back to TSI");
    }

    let mut virtio_network_runtime: Option<VirtioNetworkRuntime> = None;
    let guest_network = match network_plan.backend {
        EffectiveNetworkBackend::None => {
            if unsafe { (krun.disable_implicit_vsock)(ctx) } < 0 {
                free_ctx_on_err!("krun_disable_implicit_vsock failed");
            }
            if unsafe { (krun.add_vsock)(ctx, 0) } < 0 {
                free_ctx_on_err!("krun_add_vsock failed");
            }
            tracing::debug!("configured vsock without guest networking");
            None
        }
        EffectiveNetworkBackend::Tsi => {
            if unsafe { (krun.disable_implicit_vsock)(ctx) } < 0 {
                free_ctx_on_err!("krun_disable_implicit_vsock failed");
            }
            if unsafe { (krun.add_vsock)(ctx, TSI_FEATURE_HIJACK_INET) } < 0 {
                free_ctx_on_err!("krun_add_vsock with TSI failed");
            }

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

            if unsafe { (krun.set_port_map)(ctx, port_ptrs.as_ptr()) } < 0 {
                free_ctx_on_err!("krun_set_port_map failed");
            }

            if let Some(ref cidrs) = config.resources.allowed_cidrs {
                if !cidrs.is_empty() {
                    let set_egress = krun.set_egress_policy.ok_or_else(|| {
                        "libkrun does not support egress policy (krun_set_egress_policy not found). \
                         Update libkrun or remove --allow-cidr flags."
                            .to_string()
                    })?;

                    let mut all_cidrs = cidrs.clone();
                    crate::data::network::ensure_dns_in_cidrs(&mut all_cidrs);

                    let cidr_cstrings: Vec<CString> = all_cidrs
                        .iter()
                        .map(|c| CString::new(c.as_str()).expect("CIDR cannot contain null bytes"))
                        .collect();
                    let mut cidr_ptrs: Vec<*const libc::c_char> =
                        cidr_cstrings.iter().map(|s| s.as_ptr()).collect();
                    cidr_ptrs.push(std::ptr::null());

                    if unsafe { (set_egress)(ctx, cidr_ptrs.as_ptr()) } < 0 {
                        free_ctx_on_err!("krun_set_egress_policy failed");
                    }
                }
            }

            tracing::info!("network backend: tsi");
            None
        }
        EffectiveNetworkBackend::VirtioNet => {
            let add_net_unixstream = krun.add_net_unixstream.ok_or_else(|| {
                "libkrun does not expose krun_add_net_unixstream; update libkrun or use --net-backend tsi"
                    .to_string()
            })?;
            let guest_network = GuestNetworkConfig::default();
            let mut guest_mac = guest_network.guest_mac;
            let (host_fd, guest_fd) =
                create_unix_stream_pair().map_err(|e| format!("socketpair failed: {e}"))?;

            let runtime = match start_virtio_network(host_fd, guest_network) {
                Ok(runtime) => runtime,
                Err(err) => {
                    // SAFETY: guest_fd was created by socketpair above and not moved elsewhere.
                    unsafe { libc::close(guest_fd) };
                    return Err(format!("failed to start virtio network runtime: {err}"));
                }
            };

            if unsafe {
                (add_net_unixstream)(
                    ctx,
                    std::ptr::null(),
                    guest_fd,
                    guest_mac.as_mut_ptr(),
                    COMPAT_NET_FEATURES,
                    0,
                )
            } < 0
            {
                // SAFETY: guest_fd was created by socketpair above and not moved elsewhere.
                unsafe { libc::close(guest_fd) };
                free_ctx_on_err!("krun_add_net_unixstream failed");
            }

            virtio_network_runtime = Some(runtime);

            tracing::info!("network backend: virtio-net");
            Some(guest_network)
        }
    };

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

    // Add overlay disk as 2nd disk (/dev/vdb) for VM mode
    if let Some(overlay) = config.overlay_path {
        let overlay_id = cstr("overlay");
        let overlay_disk =
            try_or_free_ctx!(path_to_cstring(overlay), "overlay path contains null byte");
        // SAFETY: ctx is valid, overlay_id and overlay_disk are valid C strings
        if unsafe { (krun.add_disk2)(ctx, overlay_id.as_ptr(), overlay_disk.as_ptr(), 0, false) }
            < 0
        {
            free_ctx_on_err!("krun_add_disk2 failed for overlay disk");
        }
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

    // Redirect console output to a log file so libkrun doesn't put the
    // inherited terminal into raw mode (which would break terminal echo
    // if the child is killed before exit observers can restore it).
    let console_path = try_or_free_ctx!(
        path_to_cstring(&config.console_log),
        "console log path contains null byte"
    );
    // SAFETY: ctx is valid, console_path is a valid null-terminated C string
    if unsafe { (krun.set_console_output)(ctx, console_path.as_ptr()) } < 0 {
        tracing::warn!("failed to set console output");
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

    if let Some(network) = guest_network {
        env_strings.push(cstr(&format!(
            "{}={}",
            guest_env::BACKEND,
            guest_env::BACKEND_VIRTIO_NET
        )));
        env_strings.push(cstr(&format!(
            "{}={}",
            guest_env::GUEST_IP,
            network.guest_ip
        )));
        env_strings.push(cstr(&format!(
            "{}={}",
            guest_env::GATEWAY,
            network.gateway_ip
        )));
        env_strings.push(cstr(&format!(
            "{}={}",
            guest_env::PREFIX_LEN,
            network.prefix_len
        )));
        env_strings.push(cstr(&format!(
            "{}={}",
            guest_env::GUEST_MAC,
            format_mac(network.guest_mac)
        )));
        env_strings.push(cstr(&format!("{}={}", guest_env::DNS, network.dns_server)));
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
    drop(virtio_network_runtime);
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

fn create_unix_stream_pair() -> std::io::Result<(RawFd, RawFd)> {
    let mut fds = [0; 2];
    // SAFETY: `socketpair` initializes both descriptors on success.
    let result = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    if result < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((fds[0], fds[1]))
}

fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
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
