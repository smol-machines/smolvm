//! Agent VM launcher.
//!
//! This module provides the low-level VM launching functionality.
//! All setup is done in the child process after fork, where
//! DYLD_LIBRARY_PATH is still available for dlopen.

use crate::data::consts::{ENV_SMOLVM_KRUN_LOG_LEVEL, ENV_SMOLVM_LIB_DIR};
use crate::data::storage::HostMount;
use crate::error::{Error, Result};
use crate::storage::{OverlayDisk, StorageDisk};
use crate::util::libkrunfw_filename;

use smolvm_protocol::ports;
use std::ffi::{CStr, CString};
use std::path::{Path, PathBuf};

use super::{PortMapping, VmResources};

/// Disks to attach to the agent VM.
pub struct VmDisks<'a> {
    /// Storage disk for OCI layers (/dev/vda in guest).
    pub storage: &'a StorageDisk,
    /// Optional overlay disk for persistent rootfs (/dev/vdb in guest).
    pub overlay: Option<&'a OverlayDisk>,
}

// FFI bindings to libkrun
extern "C" {
    fn krun_set_log_level(level: u32) -> i32;
    fn krun_create_ctx() -> i32;
    fn krun_free_ctx(ctx: u32);
    fn krun_set_vm_config(ctx: u32, num_vcpus: u8, ram_mib: u32) -> i32;
    fn krun_set_root(ctx: u32, root_path: *const libc::c_char) -> i32;
    fn krun_set_workdir(ctx: u32, workdir: *const libc::c_char) -> i32;
    fn krun_set_exec(
        ctx: u32,
        exec_path: *const libc::c_char,
        argv: *const *const libc::c_char,
        envp: *const *const libc::c_char,
    ) -> i32;
    fn krun_add_disk2(
        ctx: u32,
        block_id: *const libc::c_char,
        disk_path: *const libc::c_char,
        disk_format: u32,
        read_only: bool,
    ) -> i32;
    fn krun_add_vsock_port2(
        ctx: u32,
        port: u32,
        filepath: *const libc::c_char,
        listen: bool,
    ) -> i32;
    fn krun_set_console_output(ctx: u32, filepath: *const libc::c_char) -> i32;
    fn krun_set_port_map(ctx: u32, port_map: *const *const libc::c_char) -> i32;
    fn krun_add_virtiofs(ctx: u32, tag: *const libc::c_char, path: *const libc::c_char) -> i32;
    fn krun_start_enter(ctx: u32) -> i32;
    fn krun_disable_implicit_vsock(ctx: u32) -> i32;
    fn krun_add_vsock(ctx: u32, tsi_features: u32) -> i32;
}

// TSI (Transparent Socket Impersonation) feature flags
const KRUN_TSI_HIJACK_INET: u32 = 1 << 0;

/// Find the directory containing libkrunfw by checking explicit overrides and
/// paths relative to the current executable.
///
/// Checks:
/// - `$SMOLVM_LIB_DIR` (explicit override for embedded runtimes)
/// - `<exe_dir>/lib/` (distribution layout)
/// - `<exe_dir>/../lib/` (alternative layout)
/// - `<exe_dir>/../../lib/linux-<arch>/` (source tree dev builds)
pub fn find_lib_dir() -> Option<PathBuf> {
    let lib_name = libkrunfw_filename();
    if let Ok(explicit_dir) = std::env::var(ENV_SMOLVM_LIB_DIR) {
        let path = PathBuf::from(explicit_dir);
        if path.join(lib_name).exists() {
            return path.canonicalize().ok().or(Some(path));
        }

        tracing::warn!(
            path = %path.display(),
            lib = lib_name,
            "{} does not contain the expected libkrunfw library", ENV_SMOLVM_LIB_DIR
        );
    }

    let exe = std::env::current_exe().ok()?;
    let exe_dir = exe.parent()?;

    let candidates = [
        exe_dir.join("lib"),
        exe_dir.join("../lib"),
        exe_dir.join("../../lib"),
        exe_dir.join(format!("../../lib/linux-{}", std::env::consts::ARCH)),
    ];

    for dir in &candidates {
        if dir.join(lib_name).exists() {
            return dir.canonicalize().ok();
        }
    }

    None
}

/// Preload libkrunfw with `RTLD_GLOBAL` so libkrun's internal `dlopen("libkrunfw.so.5")` finds it.
///
/// Setting `LD_LIBRARY_PATH` via `std::env::set_var` is insufficient because glibc caches
/// library search paths at process startup and `dlopen()` never re-reads the environment.
/// Instead, we load libkrunfw ourselves with `RTLD_GLOBAL`, which makes it visible to all
/// subsequent `dlopen()` calls by soname — matching how `launcher_dynamic.rs` handles this.
///
/// This is a no-op if libkrunfw is not found in any candidate directory (e.g., it's already
/// in a system library path).
fn preload_libkrunfw() {
    let Some(lib_dir) = find_lib_dir() else {
        return;
    };

    let lib_path = lib_dir.join(libkrunfw_filename());
    let Ok(lib_path_c) = CString::new(lib_path.to_string_lossy().as_bytes()) else {
        return;
    };

    unsafe {
        let handle = libc::dlopen(lib_path_c.as_ptr(), libc::RTLD_NOW | libc::RTLD_GLOBAL);
        if handle.is_null() {
            let err = libc::dlerror();
            let err_msg = if err.is_null() {
                "unknown error".to_string()
            } else {
                CStr::from_ptr(err).to_string_lossy().to_string()
            };
            tracing::warn!(path = %lib_path.display(), error = %err_msg, "failed to preload libkrunfw");
        }
        // Intentionally leak the handle — libkrunfw must stay loaded for libkrun to use it.
    }
}

/// Launch the agent VM (call in the forked child process).
///
/// This function sets up and starts the VM in a single call.
/// It should be called in the child process after fork, where
/// DYLD_LIBRARY_PATH is still available for dlopen to find libkrunfw.
///
/// Optional features for VM launch (SSH agent, DNS filtering, etc.).
///
/// Groups optional capabilities that don't affect core VM operation.
/// New features should be added here rather than as additional parameters
/// on manager/launcher functions.
#[derive(Debug, Clone, Default)]
pub struct LaunchFeatures {
    /// Host SSH agent socket path for forwarding into the guest.
    pub ssh_agent_socket: Option<std::path::PathBuf>,
    /// Hostnames for DNS filtering. When set, the host starts a DNS filter
    /// listener and the guest agent proxies DNS queries through it.
    pub dns_filter_hosts: Option<Vec<String>>,
}

/// Configuration for launching an agent VM.
pub struct LaunchConfig<'a> {
    /// Path to the agent rootfs directory.
    pub rootfs_path: &'a Path,
    /// Storage and overlay disk handles.
    pub disks: &'a VmDisks<'a>,
    /// Path to the vsock Unix socket for the control channel.
    pub vsock_socket: &'a Path,
    /// Optional path to write console output.
    pub console_log: Option<&'a Path>,
    /// Host directory mounts to expose to the guest.
    pub mounts: &'a [HostMount],
    /// Port mappings (host:guest).
    pub port_mappings: &'a [PortMapping],
    /// VM resources (CPU, memory, network, disk sizes).
    pub resources: VmResources,
    /// Host SSH agent socket path for forwarding into the guest.
    pub ssh_agent_socket: Option<&'a Path>,
    /// Host DNS filter socket path. When set, the guest DNS proxy forwards
    /// queries over vsock to this socket for filtering.
    pub dns_filter_socket: Option<&'a Path>,
}

/// Launch the agent VM using libkrun.
///
/// This function never returns on success.
pub fn launch_agent_vm(config: &LaunchConfig<'_>) -> Result<()> {
    let LaunchConfig {
        rootfs_path,
        disks,
        vsock_socket,
        console_log,
        mounts,
        port_mappings,
        resources,
        ssh_agent_socket,
        dns_filter_socket,
    } = config;
    // Raise file descriptor limits
    raise_fd_limits();

    // Preload libkrunfw so libkrun's internal dlopen can find it
    preload_libkrunfw();

    unsafe {
        // Set log level (0 = off, 1 = error, 2 = warn, 3 = info, 4 = debug)
        // Enable debug logging to trace vsock timing issues
        let log_level = std::env::var(ENV_SMOLVM_KRUN_LOG_LEVEL)
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        krun_set_log_level(log_level);

        // Create VM context
        let ctx = krun_create_ctx();
        if ctx < 0 {
            return Err(Error::agent("create vm context", "krun_create_ctx failed"));
        }
        let ctx = ctx as u32;

        // Set VM config
        if krun_set_vm_config(ctx, resources.cpus, resources.memory_mib) < 0 {
            krun_free_ctx(ctx);
            return Err(Error::agent("configure vm", "krun_set_vm_config failed"));
        }

        // Helper: evaluate a fallible expression, freeing ctx if it fails.
        // Replaces bare `?` which would leak the libkrun context.
        macro_rules! try_or_free_ctx {
            ($expr:expr, $op:expr, $msg:expr) => {
                match $expr {
                    Ok(val) => val,
                    Err(_) => {
                        krun_free_ctx(ctx);
                        return Err(Error::agent($op, $msg));
                    }
                }
            };
        }

        // Set root filesystem
        let root = try_or_free_ctx!(
            path_to_cstring(rootfs_path),
            "set rootfs",
            "path contains null byte"
        );
        if krun_set_root(ctx, root.as_ptr()) < 0 {
            krun_free_ctx(ctx);
            return Err(Error::agent("set rootfs", "krun_set_root failed"));
        }

        // Configure TSI (Transparent Socket Impersonation) networking.
        // TSI allows the guest to access the network via the host's network stack
        // by intercepting socket system calls and proxying them through vsock.
        //
        // Note: TSI supports TCP/UDP but not raw sockets (e.g., ICMP/ping).
        //
        // We must explicitly disable the implicit vsock and add our own vsock
        // to control whether network access is enabled or disabled.
        // Without this, libkrun's implicit vsock uses heuristics that may
        // inadvertently enable network access.

        // Always disable implicit vsock to take explicit control
        if krun_disable_implicit_vsock(ctx) < 0 {
            krun_free_ctx(ctx);
            return Err(Error::agent(
                "configure vsock",
                "krun_disable_implicit_vsock failed",
            ));
        }

        let has_egress_policy = resources
            .allowed_cidrs
            .as_ref()
            .is_some_and(|c| !c.is_empty());
        if resources.network || !port_mappings.is_empty() || has_egress_policy {
            // Add vsock with TSI HIJACK_INET flag to enable network access
            if krun_add_vsock(ctx, KRUN_TSI_HIJACK_INET) < 0 {
                krun_free_ctx(ctx);
                return Err(Error::agent(
                    "configure vsock",
                    "krun_add_vsock with TSI failed",
                ));
            }

            // Set port mappings for TCP port forwarding
            let port_cstrings: Vec<CString> = port_mappings
                .iter()
                .map(|p| {
                    CString::new(format!("{}:{}", p.host, p.guest))
                        .expect("port mapping format cannot contain null bytes")
                })
                .collect();
            let mut port_ptrs: Vec<*const libc::c_char> =
                port_cstrings.iter().map(|s| s.as_ptr()).collect();
            port_ptrs.push(std::ptr::null()); // Null-terminate the array

            if krun_set_port_map(ctx, port_ptrs.as_ptr()) < 0 {
                krun_free_ctx(ctx);
                return Err(Error::agent("set port mapping", "krun_set_port_map failed"));
            }

            // Set egress policy (CIDR-based filtering) if specified.
            // Resolved via dlsym at runtime for backwards compatibility.
            if let Some(ref cidrs) = resources.allowed_cidrs {
                type SetEgressPolicyFn =
                    unsafe extern "C" fn(u32, *const *const libc::c_char) -> i32;

                let sym_name =
                    CString::new("krun_set_egress_policy").expect("symbol name is static");
                let sym = libc::dlsym(libc::RTLD_DEFAULT, sym_name.as_ptr());
                if sym.is_null() {
                    krun_free_ctx(ctx);
                    return Err(Error::agent(
                        "set egress policy",
                        "libkrun does not support egress policy (krun_set_egress_policy not found). \
                         Update libkrun or remove --allow-cidr flags.",
                    ));
                }
                #[allow(clippy::missing_transmute_annotations)]
                let set_egress: SetEgressPolicyFn = std::mem::transmute(sym);

                let mut all_cidrs = cidrs.clone();
                crate::data::network::ensure_dns_in_cidrs(&mut all_cidrs);

                let cidr_cstrings: Vec<CString> = all_cidrs
                    .iter()
                    .map(|c| CString::new(c.as_str()).expect("CIDR cannot contain null bytes"))
                    .collect();
                let mut cidr_ptrs: Vec<*const libc::c_char> =
                    cidr_cstrings.iter().map(|s| s.as_ptr()).collect();
                cidr_ptrs.push(std::ptr::null());

                if set_egress(ctx, cidr_ptrs.as_ptr()) < 0 {
                    krun_free_ctx(ctx);
                    return Err(Error::agent(
                        "set egress policy",
                        "krun_set_egress_policy failed",
                    ));
                }

                tracing::debug!(
                    cidr_count = all_cidrs.len(),
                    "configured egress policy with CIDR filtering"
                );
            }

            tracing::debug!(
                network = resources.network,
                port_count = port_mappings.len(),
                "configured TSI networking with HIJACK_INET"
            );
        } else {
            // Add vsock without TSI features - this is needed for the control
            // channel but doesn't enable network interception.
            // Using 0 for tsi_features means no network interception.
            if krun_add_vsock(ctx, 0) < 0 {
                krun_free_ctx(ctx);
                return Err(Error::agent("configure vsock", "krun_add_vsock failed"));
            }

            tracing::debug!("configured vsock without TSI networking");
        }

        // Add storage disk (critical - VM needs storage to function)
        // This is the first disk → /dev/vda in guest
        let block_id = cstr("storage");
        let disk_path = try_or_free_ctx!(
            path_to_cstring(disks.storage.path()),
            "add storage disk",
            "path contains null byte"
        );
        if krun_add_disk2(ctx, block_id.as_ptr(), disk_path.as_ptr(), 0, false) < 0 {
            krun_free_ctx(ctx);
            return Err(Error::agent(
                "add storage disk",
                "krun_add_disk2 failed - VM cannot function without storage",
            ));
        }

        // Add overlay disk for persistent rootfs changes (optional)
        // This is the second disk → /dev/vdb in guest
        if let Some(overlay) = disks.overlay {
            let overlay_id = cstr("overlay");
            let overlay_path = try_or_free_ctx!(
                path_to_cstring(overlay.path()),
                "add overlay disk",
                "path contains null byte"
            );
            if krun_add_disk2(ctx, overlay_id.as_ptr(), overlay_path.as_ptr(), 0, false) < 0 {
                krun_free_ctx(ctx);
                return Err(Error::agent(
                    "add overlay disk",
                    "krun_add_disk2 failed for rootfs overlay",
                ));
            }
        }

        // Add vsock port for control channel (critical - host-guest communication)
        let socket_path = try_or_free_ctx!(
            path_to_cstring(vsock_socket),
            "add vsock port",
            "path contains null byte"
        );
        if krun_add_vsock_port2(ctx, ports::AGENT_CONTROL, socket_path.as_ptr(), true) < 0 {
            krun_free_ctx(ctx);
            return Err(Error::agent(
                "add vsock port",
                "krun_add_vsock_port2 failed - control channel required for host-guest communication",
            ));
        }

        // Add vsock port for SSH agent forwarding (optional)
        if let Some(ssh_socket) = ssh_agent_socket {
            let ssh_path = try_or_free_ctx!(
                path_to_cstring(ssh_socket),
                "add ssh agent vsock port",
                "path contains null byte"
            );
            // listen=false: guest connects out to this port, host receives via Unix socket
            if krun_add_vsock_port2(ctx, ports::SSH_AGENT, ssh_path.as_ptr(), false) < 0 {
                tracing::warn!("failed to add SSH agent vsock port — SSH forwarding disabled");
            } else {
                tracing::info!(
                    "SSH agent forwarding enabled on vsock port {}",
                    ports::SSH_AGENT
                );
            }
        }

        // Add vsock port for DNS filter proxy (optional)
        if let Some(dns_socket) = dns_filter_socket {
            let dns_path = try_or_free_ctx!(
                path_to_cstring(dns_socket),
                "add dns filter vsock port",
                "path contains null byte"
            );
            // listen=false: guest connects out to this port, host listens via Unix socket
            if krun_add_vsock_port2(ctx, ports::DNS_FILTER, dns_path.as_ptr(), false) < 0 {
                tracing::warn!("failed to add DNS filter vsock port — DNS filtering disabled");
            } else {
                tracing::info!("DNS filtering enabled on vsock port {}", ports::DNS_FILTER);
            }
        }

        // Set console output if specified
        if let Some(log_path) = console_log {
            let console_path = try_or_free_ctx!(
                path_to_cstring(log_path),
                "set console output",
                "path contains null byte"
            );
            if krun_set_console_output(ctx, console_path.as_ptr()) < 0 {
                tracing::warn!("failed to set console output");
            }
        }

        // Add virtiofs mounts
        // Each mount gets a tag like "smolvm0", "smolvm1", etc.
        // The guest must mount these manually (or via the agent)
        for (i, mount) in mounts.iter().enumerate() {
            let mount_tag = HostMount::mount_tag(i);
            let tag = try_or_free_ctx!(
                CString::new(mount_tag.clone()),
                "configure mount",
                "mount tag contains null byte"
            );
            let host_path = try_or_free_ctx!(
                path_to_cstring(&mount.source),
                "configure mount",
                "mount path contains null byte"
            );

            tracing::debug!(
                tag = %mount_tag,
                host = %mount.source.display(),
                guest = %mount.target.display(),
                read_only = mount.read_only,
                "adding virtiofs mount"
            );

            if krun_add_virtiofs(ctx, tag.as_ptr(), host_path.as_ptr()) < 0 {
                krun_free_ctx(ctx);
                return Err(Error::agent(
                    "add virtiofs mount",
                    format!(
                        "krun_add_virtiofs failed for '{}' - requested mount cannot be attached",
                        mount.source.display()
                    ),
                ));
            }
        }

        // Set working directory
        let workdir = cstr("/");
        krun_set_workdir(ctx, workdir.as_ptr());

        // Build environment
        let mut env_strings = vec![
            cstr("HOME=/root"),
            cstr("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
            cstr("TERM=xterm-256color"),
        ];

        // Pass mount info to the agent via environment
        // Format: SMOLVM_MOUNT_0=tag:guest_path:ro
        for (i, mount) in mounts.iter().enumerate() {
            let mount_tag = HostMount::mount_tag(i);
            let ro_flag = if mount.read_only { "ro" } else { "rw" };
            let env_val = format!(
                "SMOLVM_MOUNT_{}={}:{}:{}",
                i,
                mount_tag,
                mount.target.display(),
                ro_flag
            );
            if let Ok(cstr) = CString::new(env_val) {
                env_strings.push(cstr);
            }
        }

        // Pass mount count
        if !mounts.is_empty() {
            if let Ok(cstr) = CString::new(format!("SMOLVM_MOUNT_COUNT={}", mounts.len())) {
                env_strings.push(cstr);
            }
        }

        // Tell the agent to start SSH agent forwarding bridge
        if ssh_agent_socket.is_some() {
            env_strings.push(cstr("SMOLVM_SSH_AGENT=1"));
        }

        // Tell the agent to start DNS filtering proxy
        if dns_filter_socket.is_some() {
            env_strings.push(cstr("SMOLVM_DNS_FILTER=1"));
        }

        let mut envp: Vec<*const libc::c_char> = env_strings.iter().map(|s| s.as_ptr()).collect();
        envp.push(std::ptr::null());

        // Set exec command (/sbin/init)
        let exec_path = cstr("/sbin/init");
        let argv_strings = [cstr("/sbin/init")];
        let mut argv: Vec<*const libc::c_char> = argv_strings.iter().map(|s| s.as_ptr()).collect();
        argv.push(std::ptr::null());

        if krun_set_exec(ctx, exec_path.as_ptr(), argv.as_ptr(), envp.as_ptr()) < 0 {
            krun_free_ctx(ctx);
            return Err(Error::agent("set exec command", "krun_set_exec failed"));
        }

        // Start VM (this replaces the process on success)
        let ret = krun_start_enter(ctx);

        // If we get here, something went wrong — free the context before returning
        krun_free_ctx(ctx);
        Err(Error::agent(
            "start vm",
            format!("krun_start_enter returned: {}", ret),
        ))
    }
}

/// Create a CString from a static string that is known not to contain NUL bytes.
fn cstr(s: &str) -> CString {
    CString::new(s).expect("string literal must not contain NUL bytes")
}

/// Convert a Path to a CString.
fn path_to_cstring(path: &Path) -> Result<CString> {
    CString::new(path.to_string_lossy().as_bytes())
        .map_err(|_| Error::agent("convert path", "path contains null byte"))
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
