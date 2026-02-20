//! Agent VM launcher.
//!
//! This module provides the low-level VM launching functionality.
//! All setup is done in the child process after fork, where
//! DYLD_LIBRARY_PATH is still available for dlopen.

use crate::error::{Error, Result};
use crate::storage::{OverlayDisk, StorageDisk};
use crate::vm::config::HostMount;
use smolvm_protocol::ports;
use std::ffi::CString;
use std::path::Path;

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
    fn krun_set_egress_policy(ctx: u32, cidrs: *const *const libc::c_char) -> i32;
    fn krun_add_virtiofs(ctx: u32, tag: *const libc::c_char, path: *const libc::c_char) -> i32;
    fn krun_start_enter(ctx: u32) -> i32;
    fn krun_disable_implicit_vsock(ctx: u32) -> i32;
    fn krun_add_vsock(ctx: u32, tsi_features: u32) -> i32;
}

// TSI (Transparent Socket Impersonation) feature flags
const KRUN_TSI_HIJACK_INET: u32 = 1 << 0;

/// Launch the agent VM (call in the forked child process).
///
/// This function sets up and starts the VM in a single call.
/// It should be called in the child process after fork, where
/// DYLD_LIBRARY_PATH is still available for dlopen to find libkrunfw.
///
/// This function never returns on success.
pub fn launch_agent_vm(
    rootfs_path: &Path,
    disks: &VmDisks<'_>,
    vsock_socket: &Path,
    console_log: Option<&Path>,
    mounts: &[HostMount],
    port_mappings: &[PortMapping],
    resources: VmResources,
) -> Result<()> {
    // Raise file descriptor limits
    raise_fd_limits();

    unsafe {
        // Set log level (0 = off, 1 = error, 2 = warn, 3 = info, 4 = debug)
        // Enable debug logging to trace vsock timing issues
        let log_level = std::env::var("SMOLVM_KRUN_LOG_LEVEL")
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
        if krun_set_vm_config(ctx, resources.cpus, resources.mem) < 0 {
            krun_free_ctx(ctx);
            return Err(Error::agent("configure vm", "krun_set_vm_config failed"));
        }

        // Set root filesystem
        let root = path_to_cstring(rootfs_path)?;
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

        let has_egress_policy = !resources.allow_cidrs.is_empty();
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

            // Set egress policy if CIDRs are specified
            if has_egress_policy {
                let cidr_cstrings: Vec<CString> = resources
                    .allow_cidrs
                    .iter()
                    .map(|c| CString::new(c.as_str()).expect("CIDR cannot contain null bytes"))
                    .collect();
                let mut cidr_ptrs: Vec<*const libc::c_char> =
                    cidr_cstrings.iter().map(|s| s.as_ptr()).collect();
                cidr_ptrs.push(std::ptr::null());

                if krun_set_egress_policy(ctx, cidr_ptrs.as_ptr()) < 0 {
                    krun_free_ctx(ctx);
                    return Err(Error::agent(
                        "set egress policy",
                        "krun_set_egress_policy failed",
                    ));
                }

                tracing::debug!(
                    cidr_count = resources.allow_cidrs.len(),
                    "configured egress policy"
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
        let block_id = CString::new("storage").expect("static string");
        let disk_path = path_to_cstring(disks.storage.path())?;
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
            let overlay_id = CString::new("overlay").expect("static string");
            let overlay_path = path_to_cstring(overlay.path())?;
            if krun_add_disk2(ctx, overlay_id.as_ptr(), overlay_path.as_ptr(), 0, false) < 0 {
                krun_free_ctx(ctx);
                return Err(Error::agent(
                    "add overlay disk",
                    "krun_add_disk2 failed for rootfs overlay",
                ));
            }
        }

        // Add vsock port for control channel (critical - host-guest communication)
        let socket_path = path_to_cstring(vsock_socket)?;
        if krun_add_vsock_port2(ctx, ports::AGENT_CONTROL, socket_path.as_ptr(), true) < 0 {
            krun_free_ctx(ctx);
            return Err(Error::agent(
                "add vsock port",
                "krun_add_vsock_port2 failed - control channel required for host-guest communication",
            ));
        }

        // Set console output if specified
        if let Some(log_path) = console_log {
            let console_path = path_to_cstring(log_path)?;
            if krun_set_console_output(ctx, console_path.as_ptr()) < 0 {
                tracing::warn!("failed to set console output");
            }
        }

        // Add virtiofs mounts
        // Each mount gets a tag like "smolvm0", "smolvm1", etc.
        // The guest must mount these manually (or via the agent)
        for (i, mount) in mounts.iter().enumerate() {
            let tag = CString::new(crate::agent::mount_tag(i))
                .map_err(|_| Error::agent("configure mount", "invalid mount tag"))?;
            let host_path = path_to_cstring(&mount.source)?;

            tracing::debug!(
                tag = %crate::agent::mount_tag(i),
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
        let workdir = CString::new("/").expect("static string");
        krun_set_workdir(ctx, workdir.as_ptr());

        // Build environment
        let mut env_strings = vec![
            CString::new("HOME=/root").expect("static string"),
            CString::new("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
                .expect("static string"),
            CString::new("TERM=xterm-256color").expect("static string"),
        ];

        // Pass mount info to the agent via environment
        // Format: SMOLVM_MOUNT_0=tag:guest_path:ro
        for (i, mount) in mounts.iter().enumerate() {
            let ro_flag = if mount.read_only { "ro" } else { "rw" };
            let env_val = format!(
                "SMOLVM_MOUNT_{}=smolvm{}:{}:{}",
                i,
                i,
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

        let mut envp: Vec<*const libc::c_char> = env_strings.iter().map(|s| s.as_ptr()).collect();
        envp.push(std::ptr::null());

        // Set exec command (/sbin/init)
        let exec_path = CString::new("/sbin/init").expect("static string");
        let argv_strings = [CString::new("/sbin/init").expect("static string")];
        let mut argv: Vec<*const libc::c_char> = argv_strings.iter().map(|s| s.as_ptr()).collect();
        argv.push(std::ptr::null());

        if krun_set_exec(ctx, exec_path.as_ptr(), argv.as_ptr(), envp.as_ptr()) < 0 {
            krun_free_ctx(ctx);
            return Err(Error::agent("set exec command", "krun_set_exec failed"));
        }

        // Start VM (this replaces the process on success)
        tracing::info!("starting agent VM");
        let ret = krun_start_enter(ctx);

        // If we get here, something went wrong
        Err(Error::agent(
            "start vm",
            format!("krun_start_enter returned: {}", ret),
        ))
    }
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
