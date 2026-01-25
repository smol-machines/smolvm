//! Agent VM launcher.
//!
//! This module provides the low-level VM launching functionality.
//! All setup is done in the child process after fork, where
//! DYLD_LIBRARY_PATH is still available for dlopen.

use crate::error::{Error, Result};
use smolvm_protocol::ports;
use crate::storage::StorageDisk;
use crate::vm::config::HostMount;
use std::ffi::CString;
use std::path::Path;

use super::{PortMapping, VmResources};

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
}

/// Launch the agent VM (call in the forked child process).
///
/// This function sets up and starts the VM in a single call.
/// It should be called in the child process after fork, where
/// DYLD_LIBRARY_PATH is still available for dlopen to find libkrunfw.
///
/// This function never returns on success.
pub fn launch_agent_vm(
    rootfs_path: &Path,
    storage_disk: &StorageDisk,
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
            return Err(Error::AgentError("failed to create libkrun context".into()));
        }
        let ctx = ctx as u32;

        // Set VM config
        if krun_set_vm_config(ctx, resources.cpus, resources.mem) < 0 {
            krun_free_ctx(ctx);
            return Err(Error::AgentError("failed to set VM config".into()));
        }

        // Set root filesystem
        let root = path_to_cstring(rootfs_path)?;
        if krun_set_root(ctx, root.as_ptr()) < 0 {
            krun_free_ctx(ctx);
            return Err(Error::AgentError("failed to set root filesystem".into()));
        }

        // Set port map for TCP port forwarding (only if there are mappings)
        // Note: Only call krun_set_port_map if we have actual mappings.
        // An empty port map might interfere with TSI networking.
        if !port_mappings.is_empty() {
            let port_cstrings: Vec<CString> = port_mappings
                .iter()
                .map(|p| CString::new(format!("{}:{}", p.host, p.guest)).unwrap())
                .collect();
            let mut port_ptrs: Vec<*const libc::c_char> =
                port_cstrings.iter().map(|s| s.as_ptr()).collect();
            port_ptrs.push(std::ptr::null()); // Null-terminate the array

            if krun_set_port_map(ctx, port_ptrs.as_ptr()) < 0 {
                krun_free_ctx(ctx);
                return Err(Error::AgentError("failed to set port map".into()));
            }

            tracing::debug!(
                port_count = port_mappings.len(),
                "configured port forwarding"
            );
        }

        // Add storage disk
        let block_id = CString::new("storage").unwrap();
        let disk_path = path_to_cstring(storage_disk.path())?;
        if krun_add_disk2(ctx, block_id.as_ptr(), disk_path.as_ptr(), 0, false) < 0 {
            tracing::warn!("failed to add storage disk");
        }

        // Add vsock port for control channel (host listens)
        let socket_path = path_to_cstring(vsock_socket)?;
        if krun_add_vsock_port2(ctx, ports::AGENT_CONTROL, socket_path.as_ptr(), true) < 0 {
            tracing::warn!("failed to add vsock port");
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
            let tag = CString::new(format!("smolvm{}", i))
                .map_err(|_| Error::AgentError("invalid mount tag".into()))?;
            let host_path = path_to_cstring(&mount.source)?;

            tracing::debug!(
                tag = %format!("smolvm{}", i),
                host = %mount.source.display(),
                guest = %mount.target.display(),
                read_only = mount.read_only,
                "adding virtiofs mount"
            );

            if krun_add_virtiofs(ctx, tag.as_ptr(), host_path.as_ptr()) < 0 {
                tracing::warn!(
                    host = %mount.source.display(),
                    "failed to add virtiofs mount"
                );
            }
        }

        // Set working directory
        let workdir = CString::new("/").unwrap();
        krun_set_workdir(ctx, workdir.as_ptr());

        // Build environment
        let mut env_strings = vec![
            CString::new("HOME=/root").unwrap(),
            CString::new("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
                .unwrap(),
            CString::new("TERM=xterm-256color").unwrap(),
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
        let exec_path = CString::new("/sbin/init").unwrap();
        let argv_strings = [CString::new("/sbin/init").unwrap()];
        let mut argv: Vec<*const libc::c_char> = argv_strings.iter().map(|s| s.as_ptr()).collect();
        argv.push(std::ptr::null());

        if krun_set_exec(ctx, exec_path.as_ptr(), argv.as_ptr(), envp.as_ptr()) < 0 {
            krun_free_ctx(ctx);
            return Err(Error::AgentError("failed to set exec command".into()));
        }

        // Start VM (this replaces the process on success)
        tracing::info!("starting agent VM");
        let ret = krun_start_enter(ctx);

        // If we get here, something went wrong
        Err(Error::AgentError(format!(
            "krun_start_enter returned: {}",
            ret
        )))
    }
}

/// Convert a Path to a CString.
fn path_to_cstring(path: &Path) -> Result<CString> {
    CString::new(path.to_string_lossy().as_bytes())
        .map_err(|_| Error::AgentError("path contains null byte".into()))
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
