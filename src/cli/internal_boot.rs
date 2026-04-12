//! Internal boot subprocess for the API server.
//!
//! This command is NOT for direct user invocation. It's spawned by the API
//! server to launch a VM in a fresh single-threaded process, avoiding the
//! macOS fork-in-multithreaded-process issue.
//!
//! Usage: smolvm _boot-vm <config-path>

use smolvm::agent::boot_config::BootConfig;
use smolvm::agent::{launch_agent_vm, LaunchConfig, VmDisks};
use std::path::PathBuf;

/// Run the boot subprocess.
///
/// Reads the boot config from the given path, sets up libkrun, and calls
/// `krun_start_enter` which blocks forever (or until the VM exits).
pub fn run(config_path: PathBuf) -> smolvm::Result<()> {
    // Become a session leader (detach from parent's terminal session)
    unsafe {
        libc::setsid();
    }

    // Read boot config
    let config_data = std::fs::read(&config_path)
        .map_err(|e| smolvm::Error::agent("read boot config", e.to_string()))?;
    let config: BootConfig = serde_json::from_slice(&config_data)
        .map_err(|e| smolvm::Error::agent("parse boot config", e.to_string()))?;

    // Clean up the config file — it's no longer needed
    let _ = std::fs::remove_file(&config_path);

    // Redirect stdio. When SMOLVM_GPU_DEBUG=1, keep stderr pointed at a
    // debug log file so virglrenderer/MoltenVK errors are captured.
    if std::env::var_os("SMOLVM_GPU_DEBUG").is_some() {
        if let Some(ref log) = config.console_log {
            let debug_path = log.with_file_name("gpu-debug.log");
            if let Ok(cpath) = std::ffi::CString::new(debug_path.to_string_lossy().as_bytes()) {
                unsafe {
                    let fd = libc::open(
                        cpath.as_ptr(),
                        libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
                        0o644,
                    );
                    if fd >= 0 {
                        libc::dup2(fd, 2);
                        libc::close(fd);
                    }
                }
            }
        }
        // Detach stdin/stdout only — keep stderr for debug
        unsafe {
            let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
            if devnull >= 0 {
                libc::dup2(devnull, 0);
                libc::dup2(devnull, 1);
                libc::close(devnull);
            }
        }
    } else {
        smolvm::process::detach_stdio();
    }

    // Close ALL inherited file descriptors from the parent (server).
    // Without this, the subprocess holds database locks, network sockets, etc.
    // that can interfere with libkrun's operation. Keep stdin/stdout/stderr (0-2)
    // which now point to /dev/null.
    unsafe {
        let max_fd = libc::getdtablesize();
        for fd in 3..max_fd {
            libc::close(fd);
        }
    }

    // Open storage and overlay disks
    let storage_disk = match smolvm::storage::StorageDisk::open_or_create_at(
        &config.storage_disk_path,
        config.storage_size_gb,
    ) {
        Ok(d) => d,
        Err(e) => {
            let _ = std::fs::write(
                &config.startup_error_log,
                format!("failed to open storage disk: {}", e),
            );
            smolvm::process::exit_child(1);
        }
    };

    let overlay_disk = match smolvm::storage::OverlayDisk::open_or_create_at(
        &config.overlay_disk_path,
        config.overlay_size_gb,
    ) {
        Ok(d) => d,
        Err(e) => {
            let _ = std::fs::write(
                &config.startup_error_log,
                format!("failed to open overlay disk: {}", e),
            );
            smolvm::process::exit_child(1);
        }
    };

    // Launch the VM (never returns on success)
    let disks = VmDisks {
        storage: &storage_disk,
        overlay: Some(&overlay_disk),
    };

    // Start DNS filter listener if configured
    let dns_filter_socket_path = if let Some(ref hosts) = config.dns_filter_hosts {
        if !hosts.is_empty() {
            let socket_path = config
                .vsock_socket
                .parent()
                .unwrap_or(std::path::Path::new("/tmp"))
                .join("dns-filter.sock");
            if let Err(e) = smolvm::dns_filter_listener::start(&socket_path, hosts.clone()) {
                tracing::warn!(error = %e, "failed to start DNS filter listener");
                None
            } else {
                Some(socket_path)
            }
        } else {
            None
        }
    } else {
        None
    };

    let result = launch_agent_vm(&LaunchConfig {
        rootfs_path: &config.rootfs_path,
        disks: &disks,
        vsock_socket: &config.vsock_socket,
        console_log: config.console_log.as_deref(),
        mounts: &config.mounts,
        port_mappings: &config.ports,
        resources: config.resources,
        ssh_agent_socket: config.ssh_agent_socket.as_deref(),
        dns_filter_socket: dns_filter_socket_path.as_deref(),
    });

    // If we get here, launch_agent_vm returned (should only happen on error)
    if let Err(ref e) = result {
        let _ = std::fs::write(&config.startup_error_log, e.to_string());
    }

    smolvm::process::exit_child(1);
}
