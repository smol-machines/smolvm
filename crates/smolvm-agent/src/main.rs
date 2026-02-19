//! smolvm guest agent.
//!
//! This agent runs inside smolvm VMs and handles:
//! - OCI image pulling via crane
//! - Layer extraction and storage management
//! - Overlay filesystem preparation for workloads
//! - Command execution with optional interactive/TTY support
//!
//! Communication is via vsock on port 6000.

use smolvm_protocol::{
    error_codes, ports, AgentRequest, AgentResponse, ContainerInfo, RegistryAuth, LAYER_CHUNK_SIZE,
    PROTOCOL_VERSION,
};
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::process::{Child, Command, Stdio};
use tracing::{debug, error, info, warn};

mod container;
mod crun;
mod oci;
mod paths;
mod process;
#[cfg(target_os = "linux")]
mod pty;
mod retry;
mod storage;
mod vsock;

// ============================================================================
// Configuration Constants
// ============================================================================

/// Initial buffer size for reading requests from the vsock socket.
const REQUEST_BUFFER_SIZE: usize = 64 * 1024; // 64KB

/// Maximum allowed message size to prevent DoS via memory exhaustion.
const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024; // 16MB

/// Buffer size for streaming stdout/stderr in interactive mode.
const IO_BUFFER_SIZE: usize = 4096;

/// Default poll timeout in milliseconds for interactive I/O loop.
const INTERACTIVE_POLL_TIMEOUT_MS: i32 = 100;

/// Timeout for network connectivity test operations.
/// Used in diagnostics/troubleshooting functions.
const NETWORK_TEST_TIMEOUT_SECS: u64 = 10;

/// Poll interval for checking process completion in VM exec.
const PROCESS_POLL_INTERVAL_MS: u64 = 10;

/// Get system uptime in milliseconds (for timing relative to boot).
fn uptime_ms() -> u64 {
    if let Ok(contents) = std::fs::read_to_string("/proc/uptime") {
        if let Some(uptime_str) = contents.split_whitespace().next() {
            if let Ok(uptime_secs) = uptime_str.parse::<f64>() {
                return (uptime_secs * 1000.0) as u64;
            }
        }
    }
    0
}

fn main() {
    // Quick --version check (used by init script to detect rootfs updates)
    if std::env::args().any(|a| a == "--version") {
        println!("{}", env!("CARGO_PKG_VERSION"));
        std::process::exit(0);
    }

    // CRITICAL: Mount essential filesystems FIRST, before anything else.
    // When running as init (PID 1), we need these for the system to function.
    // This must happen before logging (which needs /dev for output).
    mount_essential_filesystems();

    // Set up persistent rootfs overlay (if /dev/vdb exists).
    // This does overlayfs + pivot_root before anything else touches the filesystem.
    setup_persistent_rootfs();

    // CRITICAL: Create vsock listener IMMEDIATELY after mounts.
    // This must happen before logging setup to minimize time to listener ready.
    // The kernel boots in ~30ms and host connects immediately after.
    let listener = match vsock::listen(ports::AGENT_CONTROL) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("smolvm-agent: FAILED to create vsock listener: {}", e);
            std::process::exit(1);
        }
    };

    let start_uptime = uptime_ms();

    // Initialize logging (after vsock listener is ready)
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("smolvm_agent=warn".parse().expect("valid directive")),
        )
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        uptime_ms = start_uptime,
        "smolvm-agent started, vsock listener already ready"
    );

    // Set up signal handlers for graceful shutdown (sync before exit)
    setup_signal_handlers();

    // Mount storage disk (moved from init script for faster vsock availability)
    let t0 = uptime_ms();
    mount_storage_disk();
    info!(duration_ms = uptime_ms() - t0, "storage disk mounted");

    // Now do initialization - the vsock listener is already accepting at kernel level
    let t0 = uptime_ms();
    if let Err(e) = storage::init() {
        error!(error = %e, "failed to initialize storage");
        std::process::exit(1);
    }
    info!(duration_ms = uptime_ms() - t0, "storage initialized");

    // Initialize packed layers support (if SMOLVM_PACKED_LAYERS env var is set)
    let t0 = uptime_ms();
    if let Some(packed_dir) = storage::get_packed_layers_dir() {
        info!(
            duration_ms = uptime_ms() - t0,
            packed_dir = %packed_dir.display(),
            "packed layers initialized"
        );
    }

    // Load and reconcile container registry
    let t0 = uptime_ms();
    if let Err(e) = container::REGISTRY.load() {
        warn!(error = %e, "failed to load container registry, starting fresh");
    }
    if let Err(e) = container::REGISTRY.reconcile() {
        warn!(error = %e, "failed to reconcile container registry");
    }
    info!(duration_ms = uptime_ms() - t0, "registry reconciled");

    info!(
        total_startup_ms = uptime_ms() - start_uptime,
        uptime_ms = uptime_ms(),
        "agent startup complete, entering accept loop"
    );

    // Start accepting connections (listener already bound)
    if let Err(e) = run_server_with_listener(listener) {
        error!(error = %e, "server error");
        std::process::exit(1);
    }
}

/// Helper to create a CString from a static str.
/// Used by boot functions that call libc mount/mknod/pivot_root.
#[cfg(target_os = "linux")]
fn cstr(s: &str) -> std::ffi::CString {
    std::ffi::CString::new(s).expect("static string without null bytes")
}

/// Mount essential filesystems (proc, sysfs, devtmpfs).
/// This must be done first when running as init (PID 1).
/// Uses direct syscalls to avoid any overhead.
#[cfg(target_os = "linux")]
fn mount_essential_filesystems() {
    // Mount proc
    let _ = std::fs::create_dir_all("/proc");
    // SAFETY: libc::mount with valid CString pointers for proc filesystem
    unsafe {
        libc::mount(
            cstr("proc").as_ptr(),
            cstr("/proc").as_ptr(),
            cstr("proc").as_ptr(),
            0,
            std::ptr::null(),
        );
    }

    // Mount sysfs
    let _ = std::fs::create_dir_all("/sys");
    // SAFETY: libc::mount with valid CString pointers for sysfs
    unsafe {
        libc::mount(
            cstr("sysfs").as_ptr(),
            cstr("/sys").as_ptr(),
            cstr("sysfs").as_ptr(),
            0,
            std::ptr::null(),
        );
    }

    // Mount devtmpfs
    let _ = std::fs::create_dir_all("/dev");
    // SAFETY: libc::mount with valid CString pointers for devtmpfs
    unsafe {
        libc::mount(
            cstr("devtmpfs").as_ptr(),
            cstr("/dev").as_ptr(),
            cstr("devtmpfs").as_ptr(),
            0,
            std::ptr::null(),
        );
    }

    // Set up loopback interface (non-blocking, best effort)
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if fd >= 0 {
            // This would require more complex ioctl calls, skip for now
            // The networking will be set up by TSI anyway
            libc::close(fd);
        }
    }
}

/// Stub for non-Linux platforms (agent only runs on Linux inside VM).
#[cfg(not(target_os = "linux"))]
fn mount_essential_filesystems() {
    // No-op on non-Linux platforms
}

/// Set up persistent rootfs overlay using overlayfs on /dev/vdb.
///
/// If /dev/vdb exists (overlay disk attached by host), this function:
/// 1. Mounts /dev/vdb as ext4 (formats on first boot)
/// 2. Creates overlayfs with initramfs as lower layer, /dev/vdb as upper
/// 3. Moves /proc, /sys, /dev into the new root
/// 4. Calls pivot_root to switch to the overlayfs root
///
/// After pivot_root, the old initramfs stays at /oldroot (needed as
/// overlay lower layer). All subsequent writes go through overlayfs
/// and are persisted to /dev/vdb.
///
/// If /dev/vdb doesn't exist, this is a no-op (backward compatible).
#[cfg(target_os = "linux")]
fn setup_persistent_rootfs() {
    use std::path::Path;

    const OVERLAY_DEVICE: &str = "/dev/vdb";
    const OVERLAY_MOUNT: &str = "/mnt/overlay";
    const NEWROOT: &str = "/mnt/newroot";

    // Make root mount private — required for mount --move and pivot_root.
    // libkrun's init.c sets MS_SHARED; we override with MS_PRIVATE.
    let root = cstr("/");
    // SAFETY: mount with MS_PRIVATE|MS_REC on root, no filesystem type
    unsafe {
        libc::mount(
            std::ptr::null(),
            root.as_ptr(),
            std::ptr::null(),
            libc::MS_PRIVATE | libc::MS_REC,
            std::ptr::null(),
        );
    }

    // If overlay device doesn't exist, no overlay disk attached — skip.
    // On devtmpfs, the kernel creates /dev/vdb automatically when libkrun
    // attaches a second virtio-blk disk. No mknod needed.
    if !Path::new(OVERLAY_DEVICE).exists() {
        tracing::debug!("no overlay device, skipping");
        return;
    }
    tracing::debug!("overlay device found, setting up overlayfs");

    let _ = std::fs::create_dir_all(OVERLAY_MOUNT);

    // Try to mount overlay disk (should be pre-formatted ext4)
    let dev = cstr(OVERLAY_DEVICE);
    let mnt = cstr(OVERLAY_MOUNT);
    let ext4 = cstr("ext4");
    // SAFETY: mount /dev/vdb as ext4 at /mnt/overlay
    let mounted = unsafe {
        libc::mount(
            dev.as_ptr(),
            mnt.as_ptr(),
            ext4.as_ptr(),
            0,
            std::ptr::null(),
        ) == 0
    };

    if !mounted {
        tracing::debug!("formatting overlay disk on first boot");
        // First boot — format the disk
        let _ = std::process::Command::new("mkfs.ext4")
            .args(["-F", "-q", "-L", "smolvm-overlay", OVERLAY_DEVICE])
            .status();

        let dev = cstr(OVERLAY_DEVICE);
        let mnt = cstr(OVERLAY_MOUNT);
        let ext4 = cstr("ext4");
        // SAFETY: retry mount after formatting
        if unsafe {
            libc::mount(
                dev.as_ptr(),
                mnt.as_ptr(),
                ext4.as_ptr(),
                0,
                std::ptr::null(),
            )
        } != 0
        {
            eprintln!("smolvm-agent: failed to mount overlay disk after formatting");
            return;
        }
    }

    // Create overlay directories
    let _ = std::fs::create_dir_all(format!("{}/upper", OVERLAY_MOUNT));
    let _ = std::fs::create_dir_all(format!("{}/work", OVERLAY_MOUNT));
    let _ = std::fs::create_dir_all(NEWROOT);

    // Mount overlayfs: initramfs (lower, read-only) + persistent disk (upper)
    let overlay_src = cstr("overlay");
    let newroot = cstr(NEWROOT);
    let overlay_type = cstr("overlay");
    let overlay_opts = cstr(&format!(
        "lowerdir=/,upperdir={}/upper,workdir={}/work",
        OVERLAY_MOUNT, OVERLAY_MOUNT
    ));
    // SAFETY: mount overlayfs with the specified options
    let result = unsafe {
        libc::mount(
            overlay_src.as_ptr(),
            newroot.as_ptr(),
            overlay_type.as_ptr(),
            0,
            overlay_opts.as_ptr() as *const libc::c_void,
        )
    };
    if result != 0 {
        let err = std::io::Error::last_os_error();
        eprintln!("smolvm-agent: failed to mount overlayfs: {}", err);
        return;
    }
    tracing::debug!("overlayfs mounted, doing pivot_root");

    // Create mount point directories in new root and move special mounts
    for dir in &["proc", "sys", "dev"] {
        let _ = std::fs::create_dir_all(format!("{}/{}", NEWROOT, dir));
        let src = cstr(&format!("/{}", dir));
        let dst = cstr(&format!("{}/{}", NEWROOT, dir));
        // SAFETY: mount --move for each special filesystem
        unsafe {
            libc::mount(
                src.as_ptr(),
                dst.as_ptr(),
                std::ptr::null(),
                libc::MS_MOVE,
                std::ptr::null(),
            );
        }
    }

    // Prepare for pivot_root
    let _ = std::fs::create_dir_all(format!("{}/oldroot", NEWROOT));

    if std::env::set_current_dir(NEWROOT).is_err() {
        eprintln!("smolvm-agent: failed to chdir to new root");
        return;
    }

    // pivot_root — switch to overlayed root.
    // Old root stays at /oldroot (needed as overlay lower layer, ~44MB RAM).
    let dot = cstr(".");
    let oldroot = cstr("oldroot");
    // SAFETY: pivot_root syscall with valid path arguments
    let result = unsafe { libc::syscall(libc::SYS_pivot_root, dot.as_ptr(), oldroot.as_ptr()) };
    if result != 0 {
        let err = std::io::Error::last_os_error();
        eprintln!("smolvm-agent: pivot_root failed: {}", err);
        return;
    }
    tracing::debug!("pivot_root done");

    // Set working directory to new root
    let _ = std::env::set_current_dir("/");
}

/// Stub for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
fn setup_persistent_rootfs() {
    // No-op on non-Linux platforms
}

/// Sync filesystem caches before shutdown.
/// This prevents ext4 corruption when the VM is terminated.
#[cfg(target_os = "linux")]
fn sync_and_unmount_storage() {
    info!("syncing filesystems before shutdown");

    // Sync all filesystem caches to disk
    // SAFETY: sync() is always safe to call
    unsafe {
        libc::sync();
    }

    // Note: We don't unmount /storage here because:
    // 1. The overlay filesystem uses /storage/layers and /storage/overlays
    // 2. Unmounting /storage while overlay is active causes issues
    // 3. The sync() call ensures all pending writes are flushed to disk
    // 4. When the VM terminates, the kernel will clean up mounts
}

/// Stub for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
fn sync_and_unmount_storage() {
    // No-op on non-Linux platforms
}

/// Set up signal handlers to sync filesystem on SIGTERM/SIGINT.
/// This prevents ext4 corruption when the VM is forcefully stopped.
#[cfg(target_os = "linux")]
fn setup_signal_handlers() {
    // SAFETY: Signal handler that calls sync() - sync is async-signal-safe
    unsafe extern "C" fn handle_term_signal(_sig: libc::c_int) {
        // sync() is async-signal-safe, so we can call it from a signal handler
        libc::sync();
        // Exit cleanly
        libc::_exit(0);
    }

    // SAFETY: Setting up signal handlers with valid function pointer
    unsafe {
        // Handle SIGTERM (sent by VM stop)
        libc::signal(
            libc::SIGTERM,
            handle_term_signal as *const () as libc::sighandler_t,
        );
        // Handle SIGINT (Ctrl+C, if attached to console)
        libc::signal(
            libc::SIGINT,
            handle_term_signal as *const () as libc::sighandler_t,
        );
    }
}

/// Stub for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
fn setup_signal_handlers() {
    // No-op on non-Linux platforms
}

/// Mount the storage disk at /storage.
/// This is done by the agent (instead of init script) to allow vsock listener
/// to be created first, reducing cold start latency.
fn mount_storage_disk() {
    use std::process::Command;

    const STORAGE_DEVICE: &str = "/dev/vda";
    const STORAGE_MOUNT: &str = "/storage";

    // Create mount point if needed
    let _ = std::fs::create_dir_all(STORAGE_MOUNT);

    // Check if device exists
    if !std::path::Path::new(STORAGE_DEVICE).exists() {
        // Try to create device node
        let _ = Command::new("mknod")
            .args([STORAGE_DEVICE, "b", "253", "0"])
            .status();
    }

    // Check if already mounted
    if std::path::Path::new(STORAGE_MOUNT).join("layers").exists() {
        debug!("storage already mounted");
        return;
    }

    // Try to mount (disk should be pre-formatted by host)
    let mount_result = Command::new("mount")
        .args([STORAGE_DEVICE, STORAGE_MOUNT])
        .status();

    let create_dirs = || {
        let dirs = [
            "layers",
            "configs",
            "manifests",
            "overlays",
            "containers/run",
            "containers/logs",
            "containers/exit",
        ];
        for dir in dirs {
            let _ = std::fs::create_dir_all(std::path::Path::new(STORAGE_MOUNT).join(dir));
        }
    };

    // Expand the ext4 filesystem to fill the block device. The host creates
    // storage from a 512MB template then extends the sparse file to 20GB, but
    // the ext4 superblock still thinks the FS is 512MB. resize2fs fixes this.
    // Safe to call even when the FS already spans the device (instant no-op).
    let resize_fs = || {
        let _ = Command::new("resize2fs").arg(STORAGE_DEVICE).output(); // output() to suppress stdout/stderr
    };

    match mount_result {
        Ok(status) if status.success() => {
            debug!("storage disk mounted successfully");
            resize_fs();
            create_dirs();
        }
        _ => {
            // Mount failed - try fsck to repair filesystem first
            warn!("mount failed, attempting filesystem repair with fsck");
            let fsck_result = Command::new("fsck.ext4")
                .args(["-y", "-f", STORAGE_DEVICE])
                .status();

            match fsck_result {
                Ok(status) if status.success() || status.code() == Some(1) => {
                    // fsck succeeded (0) or fixed errors (1) - try mounting again
                    info!("fsck completed, attempting mount");
                    let mount_after_fsck = Command::new("mount")
                        .args([STORAGE_DEVICE, STORAGE_MOUNT])
                        .status();

                    if let Ok(status) = mount_after_fsck {
                        if status.success() {
                            info!("storage disk mounted after fsck repair");
                            resize_fs();
                            create_dirs();
                            return;
                        }
                    }
                    // Mount still failed after fsck, need to format
                    warn!("mount failed after fsck, formatting storage disk");
                }
                _ => {
                    // fsck failed - disk might be unformatted (first boot)
                    info!("fsck failed, assuming first boot - formatting storage disk");
                }
            }

            // Format as last resort (mkfs creates the FS at full device size,
            // no resize needed)
            let _ = Command::new("mkfs.ext4")
                .args(["-F", "-q", STORAGE_DEVICE])
                .status();
            let _ = Command::new("mount")
                .args([STORAGE_DEVICE, STORAGE_MOUNT])
                .status();
            create_dirs();
        }
    }
}

/// Run the vsock server with a pre-created listener.
/// The listener is created early (before initialization) to ensure the kernel
/// has a listener ready when the host connects.
fn run_server_with_listener(
    listener: vsock::VsockListener,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut first_connection = true;
    let listen_start = uptime_ms();

    info!(uptime_ms = uptime_ms(), "entering vsock accept loop");

    loop {
        match listener.accept() {
            Ok(mut stream) => {
                if first_connection {
                    info!(
                        wait_for_first_connection_ms = uptime_ms() - listen_start,
                        uptime_ms = uptime_ms(),
                        "first connection accepted"
                    );
                    first_connection = false;
                }
                info!("accepted connection");

                if let Err(e) = handle_connection(&mut stream) {
                    warn!(error = %e, "connection error");
                }
            }
            Err(e) => {
                warn!(error = %e, "accept error");
            }
        }
    }
}

/// Handle a single connection.
fn handle_connection(stream: &mut impl ReadWrite) -> Result<(), Box<dyn std::error::Error>> {
    let mut buf = vec![0u8; REQUEST_BUFFER_SIZE];

    loop {
        // Read length header
        let mut header = [0u8; 4];
        match stream.read_exact(&mut header) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                debug!("connection closed");
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        }

        let len = u32::from_be_bytes(header) as usize;

        // Validate message size to prevent DoS via memory exhaustion
        if len > MAX_MESSAGE_SIZE {
            warn!(
                len = len,
                max = MAX_MESSAGE_SIZE,
                "message too large, rejecting"
            );
            send_response(
                stream,
                &AgentResponse::error(
                    format!("message size {} exceeds maximum {}", len, MAX_MESSAGE_SIZE),
                    error_codes::MESSAGE_TOO_LARGE,
                ),
            )?;
            continue;
        }

        if len > buf.len() {
            buf.resize(len, 0);
        }

        // Read payload
        stream.read_exact(&mut buf[..len])?;

        // Parse request
        let request: AgentRequest = match serde_json::from_slice(&buf[..len]) {
            Ok(req) => req,
            Err(e) => {
                warn!(error = %e, "invalid request");
                send_response(
                    stream,
                    &AgentResponse::error(
                        format!("invalid request: {}", e),
                        error_codes::INVALID_REQUEST,
                    ),
                )?;
                continue;
            }
        };

        debug!(?request, "received request");

        // Check if this is an interactive run request
        if let AgentRequest::Run {
            interactive: true, ..
        }
        | AgentRequest::Run { tty: true, .. } = &request
        {
            // Handle interactive session
            handle_interactive_run(stream, request)?;
            continue;
        }

        // Check if this is an interactive VM exec request
        if let AgentRequest::VmExec {
            interactive: true, ..
        }
        | AgentRequest::VmExec { tty: true, .. } = &request
        {
            // Handle interactive VM exec session
            handle_interactive_vm_exec(stream, request)?;
            continue;
        }

        // Check if this is an interactive container exec request
        if let AgentRequest::Exec {
            interactive: true, ..
        }
        | AgentRequest::Exec { tty: true, .. } = &request
        {
            // Handle interactive container exec session
            handle_interactive_container_exec(stream, request)?;
            continue;
        }

        // Handle Pull with progress streaming
        if let AgentRequest::Pull {
            ref image,
            ref platform,
            ref auth,
        } = request
        {
            handle_streaming_pull(stream, image, platform.as_deref(), auth.as_ref())?;
            continue;
        }

        // Handle ExportLayer with chunked streaming
        if let AgentRequest::ExportLayer {
            ref image_digest,
            layer_index,
        } = request
        {
            handle_streaming_export_layer(stream, image_digest, layer_index)?;
            continue;
        }

        // Handle regular request
        let response = handle_request(request);
        send_response(stream, &response)?;

        // Check for shutdown
        if matches!(response, AgentResponse::Ok { .. }) {
            if let AgentResponse::Ok { data: Some(ref d) } = response {
                if d.get("shutdown").and_then(|v| v.as_bool()) == Some(true) {
                    info!("shutdown requested");
                    return Ok(());
                }
            }
        }
    }
}

/// Handle a single non-interactive request.
fn handle_request(request: AgentRequest) -> AgentResponse {
    match request {
        AgentRequest::Ping => AgentResponse::Pong {
            version: PROTOCOL_VERSION,
        },

        // Pull is handled separately in handle_streaming_pull for progress streaming
        AgentRequest::Pull { .. } => unreachable!("Pull handled before match"),

        AgentRequest::Query { image } => handle_query(&image),

        AgentRequest::ListImages => handle_list_images(),

        AgentRequest::GarbageCollect { dry_run } => handle_gc(dry_run),

        AgentRequest::PrepareOverlay { image, workload_id } => {
            handle_prepare_overlay(&image, &workload_id)
        }

        AgentRequest::CleanupOverlay { workload_id } => handle_cleanup_overlay(&workload_id),

        AgentRequest::FormatStorage => handle_format_storage(),

        AgentRequest::StorageStatus => handle_storage_status(),

        AgentRequest::NetworkTest { url } => {
            info!(url = %url, "testing network connectivity directly from agent");

            // Extract host:port for TCP test from URL
            let tcp_target = extract_host_port(&url).unwrap_or_else(|| "1.1.1.1:80".to_string());

            // Test 1: Pure syscall TCP connect test (bypass C library)
            let syscall_result = test_tcp_syscall(&tcp_target);

            // Test 2: Try wget (busybox/musl)
            let wget_result = match std::process::Command::new("wget")
                .args(["-q", "-O-", "-T", "10", &url])
                .output()
            {
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    serde_json::json!({
                        "tool": "wget",
                        "success": output.status.success(),
                        "exit_code": output.status.code(),
                        "stdout_len": output.stdout.len(),
                        "stderr": stderr,
                    })
                }
                Err(e) => serde_json::json!({
                    "tool": "wget",
                    "error": format!("{}", e),
                }),
            };

            // Test 3: Try crane (Go static binary) - fetch manifest
            let crane_result = match std::process::Command::new("crane")
                .args(["manifest", "alpine:latest"])
                .env("HOME", "/root")
                .output()
            {
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    serde_json::json!({
                        "tool": "crane",
                        "success": output.status.success(),
                        "exit_code": output.status.code(),
                        "stdout_len": output.stdout.len(),
                        "stderr": stderr,
                    })
                }
                Err(e) => serde_json::json!({
                    "tool": "crane",
                    "error": format!("{}", e),
                }),
            };

            AgentResponse::Ok {
                data: Some(serde_json::json!({
                    "syscall_tcp": syscall_result,
                    "wget": wget_result,
                    "crane": crane_result,
                })),
            }
        }

        AgentRequest::Shutdown => {
            info!("shutdown requested");
            // Sync filesystem before shutdown to prevent corruption
            sync_and_unmount_storage();
            AgentResponse::Ok {
                data: Some(serde_json::json!({"shutdown": true})),
            }
        }

        // VM-level exec (direct command execution in VM, not container)
        AgentRequest::VmExec {
            command,
            env,
            workdir,
            timeout_ms,
            interactive: false,
            tty: false,
        } => handle_vm_exec(&command, &env, workdir.as_deref(), timeout_ms),

        AgentRequest::VmExec { .. } => {
            // Interactive mode should be handled by handle_interactive_vm_exec
            AgentResponse::error(
                "interactive VM exec not handled here",
                error_codes::INTERNAL_ERROR,
            )
        }

        AgentRequest::Run {
            image,
            command,
            env,
            workdir,
            mounts,
            timeout_ms,
            interactive: false,
            tty: false,
        } => handle_run(
            &image,
            &command,
            &env,
            workdir.as_deref(),
            &mounts,
            timeout_ms,
        ),

        AgentRequest::Run { .. } => {
            // Interactive mode should be handled by handle_interactive_run
            AgentResponse::error(
                "interactive mode not handled here",
                error_codes::INTERNAL_ERROR,
            )
        }

        AgentRequest::Stdin { .. } | AgentRequest::Resize { .. } => AgentResponse::error(
            "stdin/resize only valid during interactive session",
            error_codes::INVALID_REQUEST,
        ),

        // Container lifecycle
        AgentRequest::CreateContainer {
            image,
            command,
            env,
            workdir,
            mounts,
        } => handle_create_container(&image, &command, &env, workdir.as_deref(), &mounts),

        AgentRequest::StartContainer { container_id } => handle_start_container(&container_id),

        AgentRequest::StopContainer {
            container_id,
            timeout_secs,
        } => handle_stop_container(&container_id, timeout_secs.unwrap_or(10)),

        AgentRequest::DeleteContainer {
            container_id,
            force,
        } => handle_delete_container(&container_id, force),

        AgentRequest::ListContainers => handle_list_containers(),

        AgentRequest::Exec {
            container_id,
            command,
            env,
            workdir,
            timeout_ms,
            interactive: false,
            tty: false,
        } => handle_exec(
            &container_id,
            &command,
            &env,
            workdir.as_deref(),
            timeout_ms,
        ),

        AgentRequest::Exec { .. } => {
            // Interactive mode should be handled by handle_interactive_container_exec
            AgentResponse::error(
                "interactive container exec not handled here",
                error_codes::INTERNAL_ERROR,
            )
        }

        AgentRequest::ExportLayer { .. } => {
            // Streaming export is handled by handle_streaming_export_layer
            AgentResponse::error("export layer not handled here", error_codes::INTERNAL_ERROR)
        }
    }
}

/// Handle an interactive run session with streaming I/O.
fn handle_interactive_run(
    stream: &mut impl ReadWrite,
    request: AgentRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    let (image, command, env, workdir, mounts, timeout_ms, tty) = match request {
        AgentRequest::Run {
            image,
            command,
            env,
            workdir,
            mounts,
            timeout_ms,
            tty,
            ..
        } => (image, command, env, workdir, mounts, timeout_ms, tty),
        _ => {
            send_response(
                stream,
                &AgentResponse::error("expected Run request", error_codes::INVALID_REQUEST),
            )?;
            return Ok(());
        }
    };

    info!(image = %image, command = ?command, tty = tty, "starting interactive run");

    // Prepare the overlay and get the rootfs path
    let rootfs = match storage::prepare_for_run(&image) {
        Ok(path) => path,
        Err(e) => {
            send_response(stream, &AgentResponse::from_err(e, error_codes::RUN_FAILED))?;
            return Ok(());
        }
    };

    // Setup virtiofs mounts at staging area (crun will bind-mount them via OCI spec)
    if let Err(e) = storage::setup_mounts(&rootfs, &mounts) {
        send_response(
            stream,
            &AgentResponse::from_err(e, error_codes::MOUNT_FAILED),
        )?;
        return Ok(());
    }

    // Spawn the command with crun
    let mut child = match spawn_interactive_command(
        &rootfs,
        &command,
        &env,
        workdir.as_deref(),
        &mounts,
        tty,
    ) {
        Ok(child) => child,
        Err(e) => {
            send_response(
                stream,
                &AgentResponse::from_err(e, error_codes::SPAWN_FAILED),
            )?;
            return Ok(());
        }
    };

    // Send Started response
    send_response(stream, &AgentResponse::Started)?;

    // Run the interactive I/O loop
    let exit_code = run_interactive_loop(stream, &mut child, timeout_ms)?;

    // Send Exited response
    send_response(stream, &AgentResponse::Exited { exit_code })?;

    Ok(())
}

/// Spawn a command for interactive execution using crun OCI runtime.
fn spawn_interactive_command(
    rootfs: &str,
    command: &[String],
    env: &[(String, String)],
    workdir: Option<&str>,
    mounts: &[(String, String, bool)],
    _tty: bool,
) -> Result<Child, Box<dyn std::error::Error>> {
    use std::path::Path;

    if command.is_empty() {
        return Err("empty command".into());
    }

    // Compute bundle path from rootfs path
    // rootfs = /storage/overlays/{id}/merged
    // bundle = /storage/overlays/{id}/bundle
    let rootfs_path = Path::new(rootfs);
    let overlay_root = rootfs_path
        .parent()
        .ok_or("invalid rootfs path: no parent")?;
    let bundle_path = overlay_root.join("bundle");

    if !bundle_path.exists() {
        return Err(format!("bundle directory not found: {}", bundle_path.display()).into());
    }

    // Generate OCI spec for this command
    let workdir_str = workdir.unwrap_or("/");
    let mut spec = oci::OciSpec::new(command, env, workdir_str, false);

    // Add virtiofs bind mounts to OCI spec
    for (tag, container_path, read_only) in mounts {
        let virtiofs_mount = Path::new(paths::VIRTIOFS_MOUNT_ROOT).join(tag);
        spec.add_bind_mount(
            &virtiofs_mount.to_string_lossy(),
            container_path,
            *read_only,
        );
    }

    // Write config.json to bundle
    spec.write_to(&bundle_path)
        .map_err(|e| format!("failed to write OCI spec: {}", e))?;

    // Generate unique container ID
    let container_id = oci::generate_container_id();

    // TODO: For TTY mode, use --console-socket to receive PTY master FD

    info!(
        command = ?command,
        container_id = %container_id,
        bundle = %bundle_path.display(),
        mounts = mounts.len(),
        "spawning interactive container with crun"
    );

    // Build and spawn crun run command with stdio piped for interactive mode
    let child = crun::CrunCommand::run(&bundle_path, &container_id)
        .stdin_piped()
        .capture_output()
        .spawn()?;

    Ok(child)
}

/// Run the interactive I/O loop using poll() for efficient I/O multiplexing.
fn run_interactive_loop(
    stream: &mut impl ReadWrite,
    child: &mut Child,
    timeout_ms: Option<u64>,
) -> Result<i32, Box<dyn std::error::Error>> {
    use std::io::Read as _;
    use std::time::{Duration, Instant};

    let start = Instant::now();
    let deadline = timeout_ms.map(|ms| start + Duration::from_millis(ms));

    // Get handles to child's stdio
    let mut child_stdout = child.stdout.take();
    let mut child_stderr = child.stderr.take();
    let mut child_stdin = child.stdin.take();

    // Set non-blocking mode on stdout/stderr
    if let Some(ref stdout) = child_stdout {
        if !set_nonblocking(stdout.as_raw_fd()) {
            warn!("failed to set stdout to non-blocking mode");
        }
    }
    if let Some(ref stderr) = child_stderr {
        if !set_nonblocking(stderr.as_raw_fd()) {
            warn!("failed to set stderr to non-blocking mode");
        }
    }

    let mut stdout_buf = [0u8; IO_BUFFER_SIZE];
    let mut stderr_buf = [0u8; IO_BUFFER_SIZE];

    loop {
        // Check if child has exited
        if let Some(status) = child.try_wait()? {
            // Drain any remaining output
            drain_remaining_output(
                stream,
                &mut child_stdout,
                &mut child_stderr,
                &mut stdout_buf,
                &mut stderr_buf,
            )?;
            return Ok(status.code().unwrap_or(-1));
        }

        // Check timeout
        if let Some(deadline) = deadline {
            if Instant::now() >= deadline {
                warn!("interactive command timed out, killing process");
                if let Err(e) = child.kill() {
                    warn!(error = %e, "failed to kill timed out process");
                }
                // Wait to reap the process and avoid zombies
                if let Err(e) = child.wait() {
                    warn!(error = %e, "failed to wait for killed process");
                }
                return Ok(124); // Timeout exit code
            }
        }

        // Calculate poll timeout: either remaining time until deadline, or 100ms default
        let poll_timeout_ms = match deadline {
            Some(dl) => {
                let remaining = dl.saturating_duration_since(Instant::now());
                // Cap at 100ms to periodically check child exit status
                remaining
                    .as_millis()
                    .min(INTERACTIVE_POLL_TIMEOUT_MS as u128) as i32
            }
            None => INTERACTIVE_POLL_TIMEOUT_MS,
        };

        // Build poll fds array for stdout, stderr, and vsock stream
        let stdout_fd = child_stdout.as_ref().map(|s| s.as_raw_fd()).unwrap_or(-1);
        let stderr_fd = child_stderr.as_ref().map(|s| s.as_raw_fd()).unwrap_or(-1);
        let stream_fd = stream.as_raw_fd();

        let mut poll_fds = [
            libc::pollfd {
                fd: stdout_fd,
                events: if stdout_fd >= 0 { libc::POLLIN } else { 0 },
                revents: 0,
            },
            libc::pollfd {
                fd: stderr_fd,
                events: if stderr_fd >= 0 { libc::POLLIN } else { 0 },
                revents: 0,
            },
            libc::pollfd {
                fd: stream_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];

        // Wait for I/O or timeout using poll()
        let poll_result = unsafe { libc::poll(poll_fds.as_mut_ptr(), 3, poll_timeout_ms) };

        if poll_result < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::Interrupted {
                debug!(error = %err, "poll error");
            }
            continue;
        }

        // Read available stdout
        if poll_fds[0].revents & libc::POLLIN != 0 {
            if let Some(ref mut stdout) = child_stdout {
                loop {
                    match stdout.read(&mut stdout_buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            send_response(
                                stream,
                                &AgentResponse::Stdout {
                                    data: stdout_buf[..n].to_vec(),
                                },
                            )?;
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) => {
                            debug!(error = %e, "stdout read error");
                            break;
                        }
                    }
                }
            }
        }

        // Read available stderr
        if poll_fds[1].revents & libc::POLLIN != 0 {
            if let Some(ref mut stderr) = child_stderr {
                loop {
                    match stderr.read(&mut stderr_buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            send_response(
                                stream,
                                &AgentResponse::Stderr {
                                    data: stderr_buf[..n].to_vec(),
                                },
                            )?;
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) => {
                            debug!(error = %e, "stderr read error");
                            break;
                        }
                    }
                }
            }
        }

        // Read incoming request from host (stdin data, resize) — only when
        // poll confirms data is available, then use blocking read_exact which
        // is safe because the data is already in the kernel buffer.
        if poll_fds[2].revents & libc::POLLIN != 0 {
            let mut header = [0u8; 4];
            stream.read_exact(&mut header)?;
            let len = u32::from_be_bytes(header) as usize;
            if len > MAX_MESSAGE_SIZE {
                return Err(format!("message too large: {} bytes", len).into());
            }
            let mut buf = vec![0u8; len];
            stream.read_exact(&mut buf)?;
            let request: AgentRequest = serde_json::from_slice(&buf)?;

            match request {
                AgentRequest::Stdin { data } => {
                    if data.is_empty() {
                        drop(child_stdin.take());
                    } else if let Some(ref mut stdin) = child_stdin {
                        let _ = stdin.write_all(&data);
                        let _ = stdin.flush();
                    }
                }
                AgentRequest::Resize { cols, rows } => {
                    debug!(cols, rows, "resize requested (no PTY in pipe mode)");
                }
                _ => {
                    warn!("unexpected request during interactive session");
                }
            }
        }
    }
}

/// Run the interactive I/O loop for PTY-based sessions.
///
/// Unlike `run_interactive_loop`, this polls a single PTY master fd
/// (PTY merges stdout and stderr) and supports terminal resize.
#[cfg(target_os = "linux")]
fn run_interactive_loop_pty(
    stream: &mut impl ReadWrite,
    child: &mut Child,
    pty_master: pty::PtyMaster,
    timeout_ms: Option<u64>,
) -> Result<i32, Box<dyn std::error::Error>> {
    use std::time::{Duration, Instant};

    let start = Instant::now();
    let deadline = timeout_ms.map(|ms| start + Duration::from_millis(ms));

    // Set the master fd to non-blocking so we can poll it.
    if !set_nonblocking(pty_master.as_raw_fd()) {
        warn!("failed to set PTY master to non-blocking mode");
    }

    let mut buf = [0u8; IO_BUFFER_SIZE];

    loop {
        // Check if child has exited.
        if let Some(status) = child.try_wait()? {
            // Drain remaining PTY output.
            loop {
                match pty_master.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        send_response(
                            stream,
                            &AgentResponse::Stdout {
                                data: buf[..n].to_vec(),
                            },
                        )?;
                    }
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.raw_os_error() == Some(libc::EIO) =>
                    {
                        // EIO is expected when the slave side is closed.
                        break;
                    }
                    Err(_) => break,
                }
            }
            return Ok(status.code().unwrap_or(-1));
        }

        // Check timeout.
        if let Some(deadline) = deadline {
            if Instant::now() >= deadline {
                warn!("interactive PTY command timed out, killing process");
                if let Err(e) = child.kill() {
                    warn!(error = %e, "failed to kill timed out process");
                }
                if let Err(e) = child.wait() {
                    warn!(error = %e, "failed to wait for killed process");
                }
                return Ok(124);
            }
        }

        // Poll the PTY master fd for readable data.
        let poll_timeout_ms = match deadline {
            Some(dl) => {
                let remaining = dl.saturating_duration_since(Instant::now());
                remaining
                    .as_millis()
                    .min(INTERACTIVE_POLL_TIMEOUT_MS as u128) as i32
            }
            None => INTERACTIVE_POLL_TIMEOUT_MS,
        };

        // Poll PTY master and vsock stream for readable data.
        let stream_fd = stream.as_raw_fd();
        let mut poll_fds = [
            libc::pollfd {
                fd: pty_master.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: stream_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];

        let poll_result = unsafe { libc::poll(poll_fds.as_mut_ptr(), 2, poll_timeout_ms) };

        if poll_result < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::Interrupted {
                debug!(error = %err, "poll error on PTY master");
            }
            continue;
        }

        // Read available data from PTY master.
        if poll_fds[0].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            loop {
                match pty_master.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        send_response(
                            stream,
                            &AgentResponse::Stdout {
                                data: buf[..n].to_vec(),
                            },
                        )?;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) if e.raw_os_error() == Some(libc::EIO) => {
                        // Slave side closed — child is exiting.
                        break;
                    }
                    Err(e) => {
                        debug!(error = %e, "PTY master read error");
                        break;
                    }
                }
            }
        }

        // Read incoming request from host — only when poll confirms data
        // is available, then use blocking read_exact (safe, data is buffered).
        if poll_fds[1].revents & libc::POLLIN != 0 {
            let mut header = [0u8; 4];
            stream.read_exact(&mut header)?;
            let len = u32::from_be_bytes(header) as usize;
            if len > MAX_MESSAGE_SIZE {
                return Err(format!("message too large: {} bytes", len).into());
            }
            let mut msg_buf = vec![0u8; len];
            stream.read_exact(&mut msg_buf)?;
            let request: AgentRequest = serde_json::from_slice(&msg_buf)?;

            match request {
                AgentRequest::Stdin { data } => {
                    // For PTY, empty stdin is not EOF (Ctrl+D is a byte).
                    if !data.is_empty() {
                        let _ = pty_master.write_all(&data);
                    }
                }
                AgentRequest::Resize { cols, rows } => {
                    if let Err(e) = pty_master.set_window_size(cols, rows) {
                        debug!(error = %e, cols, rows, "failed to set PTY window size");
                    }
                }
                _ => {
                    warn!("unexpected request during interactive PTY session");
                }
            }
        }
    }
}

/// Drain any remaining output from stdout/stderr after child exits.
fn drain_remaining_output(
    stream: &mut impl Write,
    child_stdout: &mut Option<std::process::ChildStdout>,
    child_stderr: &mut Option<std::process::ChildStderr>,
    stdout_buf: &mut [u8],
    stderr_buf: &mut [u8],
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Read as _;

    if let Some(ref mut stdout) = child_stdout {
        loop {
            match stdout.read(stdout_buf) {
                Ok(0) => break,
                Ok(n) => {
                    send_response(
                        stream,
                        &AgentResponse::Stdout {
                            data: stdout_buf[..n].to_vec(),
                        },
                    )?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
    }
    if let Some(ref mut stderr) = child_stderr {
        loop {
            match stderr.read(stderr_buf) {
                Ok(0) => break,
                Ok(n) => {
                    send_response(
                        stream,
                        &AgentResponse::Stderr {
                            data: stderr_buf[..n].to_vec(),
                        },
                    )?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
    }
    Ok(())
}

/// Set a file descriptor to non-blocking mode.
///
/// Returns true if successful, false if fcntl() failed.
fn set_nonblocking(fd: i32) -> bool {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 {
            debug!(fd, "fcntl(F_GETFL) failed");
            return false;
        }
        let result = libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        if result < 0 {
            debug!(fd, "fcntl(F_SETFL, O_NONBLOCK) failed");
            return false;
        }
        true
    }
}

/// Extract host:port from a URL for TCP connection testing.
///
/// Supports URLs like:
/// - `http://example.com` -> `example.com:80`
/// - `https://example.com` -> `example.com:443`
/// - `http://example.com:8080` -> `example.com:8080`
/// - `example.com:80` -> `example.com:80`
fn extract_host_port(url: &str) -> Option<String> {
    // Remove protocol prefix if present
    let without_proto = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);

    // Extract host (remove path)
    let host_port = without_proto.split('/').next()?;

    // If no port, add default based on protocol
    if host_port.contains(':') {
        Some(host_port.to_string())
    } else if url.starts_with("https://") {
        Some(format!("{}:443", host_port))
    } else {
        Some(format!("{}:80", host_port))
    }
}

/// Test TCP connection using pure syscalls (bypass C library).
/// Connects to the specified target and sends HTTP GET request.
///
/// # Arguments
/// * `target` - Host:port to connect to (e.g., "1.1.1.1:80", "example.com:443")
fn test_tcp_syscall(target: &str) -> serde_json::Value {
    use std::io::{Read as _, Write as _};
    use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
    use std::time::Duration;

    info!(target = %target, "testing TCP with pure Rust std::net");

    // Resolve the target to socket address
    let addr: SocketAddr = match target.to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(addr) => addr,
            None => {
                return serde_json::json!({
                    "success": false,
                    "error": "could not resolve target address",
                    "target": target,
                });
            }
        },
        Err(e) => {
            return serde_json::json!({
                "success": false,
                "error": format!("failed to resolve {}: {}", target, e),
                "target": target,
            });
        }
    };

    // Extract host for HTTP Host header
    let host = target.split(':').next().unwrap_or(target);

    let connect_result =
        match TcpStream::connect_timeout(&addr, Duration::from_secs(NETWORK_TEST_TIMEOUT_SECS)) {
            Ok(mut stream) => {
                // Try to set timeouts
                let _ =
                    stream.set_read_timeout(Some(Duration::from_secs(NETWORK_TEST_TIMEOUT_SECS)));
                let _ =
                    stream.set_write_timeout(Some(Duration::from_secs(NETWORK_TEST_TIMEOUT_SECS)));

                // Send a simple HTTP request
                let request = format!("GET / HTTP/1.0\r\nHost: {}\r\n\r\n", host);
                match stream.write_all(request.as_bytes()) {
                    Ok(_) => {
                        // Try to read the response
                        let mut response = vec![0u8; 1024];
                        match stream.read(&mut response) {
                            Ok(n) => {
                                let response_str =
                                    String::from_utf8_lossy(&response[..n.min(200)]).to_string();
                                serde_json::json!({
                                    "success": true,
                                    "connected": true,
                                    "sent_request": true,
                                    "received_bytes": n,
                                    "response_preview": response_str,
                                })
                            }
                            Err(e) => {
                                serde_json::json!({
                                    "success": false,
                                    "connected": true,
                                    "sent_request": true,
                                    "read_error": format!("{}", e),
                                    "read_error_kind": format!("{:?}", e.kind()),
                                })
                            }
                        }
                    }
                    Err(e) => {
                        serde_json::json!({
                            "success": false,
                            "connected": true,
                            "write_error": format!("{}", e),
                        })
                    }
                }
            }
            Err(e) => {
                // Get more details about the error
                let raw_os_error = e.raw_os_error();
                serde_json::json!({
                    "success": false,
                    "connected": false,
                    "error": format!("{}", e),
                    "error_kind": format!("{:?}", e.kind()),
                    "raw_os_error": raw_os_error,
                })
            }
        };

    // Also test socket syscall and lseek behavior using safe nix APIs
    #[cfg(target_os = "linux")]
    let socket_test = {
        use nix::sys::socket::{socket, AddressFamily, SockFlag, SockType};
        use nix::unistd::{lseek, Whence};
        use std::os::fd::AsRawFd;

        match socket(
            AddressFamily::Inet,
            SockType::Stream,
            SockFlag::empty(),
            None,
        ) {
            Ok(fd) => {
                let raw_fd = fd.as_raw_fd();

                // Test lseek on the socket - this should return ESPIPE (29) for normal sockets
                let (lseek_result, lseek_errno) = match lseek(raw_fd, 0, Whence::SeekCur) {
                    Ok(offset) => (offset, None),
                    Err(e) => (-1, Some((e as i32, e.desc().to_string()))),
                };

                // fd is automatically closed when OwnedFd drops
                serde_json::json!({
                    "socket_created": true,
                    "fd": raw_fd,
                    "sock_type": libc::SOCK_STREAM,  // We know we created SOCK_STREAM
                    "lseek_result": lseek_result,
                    "lseek_errno": lseek_errno.map(|(e, s)| serde_json::json!({"code": e, "str": s})),
                    "expected_errno_espipe": 29,  // ESPIPE = 29 on Linux
                })
            }
            Err(e) => {
                serde_json::json!({
                    "socket_created": false,
                    "errno": e as i32,
                    "errno_str": e.desc().to_string(),
                })
            }
        }
    };

    #[cfg(not(target_os = "linux"))]
    let socket_test = serde_json::json!({
        "skipped": true,
        "reason": "socket test only available on Linux"
    });

    // Test 3: Try nc (netcat) if available
    let nc_result = match std::process::Command::new("nc")
        .args(["-w", "5", "1.1.1.1", "80"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(mut child) => {
            // Send HTTP request via stdin
            if let Some(ref mut stdin) = child.stdin {
                let _ = stdin.write_all(b"GET / HTTP/1.0\r\nHost: 1.1.1.1\r\n\r\n");
            }
            drop(child.stdin.take());

            match child.wait_with_output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    serde_json::json!({
                        "tool": "nc",
                        "success": output.status.success(),
                        "exit_code": output.status.code(),
                        "stdout_preview": stdout.chars().take(200).collect::<String>(),
                        "stderr": stderr.to_string(),
                    })
                }
                Err(e) => serde_json::json!({
                    "tool": "nc",
                    "error": format!("wait error: {}", e),
                }),
            }
        }
        Err(e) => serde_json::json!({
            "tool": "nc",
            "error": format!("spawn error: {}", e),
        }),
    };

    // Test 4: Try curl if available
    let curl_result = match std::process::Command::new("curl")
        .args([
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--connect-timeout",
            "10",
            "http://1.1.1.1",
        ])
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            serde_json::json!({
                "tool": "curl",
                "success": output.status.success(),
                "exit_code": output.status.code(),
                "http_code": stdout,
                "stderr": stderr,
            })
        }
        Err(e) => serde_json::json!({
            "tool": "curl",
            "error": format!("{}", e),
        }),
    };

    serde_json::json!({
        "rust_std_net": connect_result,
        "raw_socket": socket_test,
        "nc": nc_result,
        "curl": curl_result,
    })
}

/// Handle command execution request (non-interactive).
fn handle_run(
    image: &str,
    command: &[String],
    env: &[(String, String)],
    workdir: Option<&str>,
    mounts: &[(String, String, bool)],
    timeout_ms: Option<u64>,
) -> AgentResponse {
    info!(image = %image, command = ?command, mounts = ?mounts, timeout_ms = ?timeout_ms, "running command");

    match storage::run_command(image, command, env, workdir, mounts, timeout_ms) {
        Ok(result) => AgentResponse::Completed {
            exit_code: result.exit_code,
            stdout: result.stdout,
            stderr: result.stderr,
        },
        Err(e) => AgentResponse::from_err(e, error_codes::RUN_FAILED),
    }
}

/// Handle image pull request with progress streaming.
fn handle_streaming_pull<S: Read + Write>(
    stream: &mut S,
    image: &str,
    platform: Option<&str>,
    auth: Option<&RegistryAuth>,
) -> Result<(), Box<dyn std::error::Error>> {
    info!(
        image = %image,
        ?platform,
        has_auth = auth.is_some(),
        "pulling image with progress"
    );

    // Create a progress callback that sends updates over the stream
    let progress_callback = |current: usize, total: usize, layer: &str| {
        let percent = if total > 0 {
            ((current as f64 / total as f64) * 100.0) as u8
        } else {
            0
        };
        let response = AgentResponse::Progress {
            message: format!("Pulling layer {}/{}", current, total),
            percent: Some(percent),
            layer: Some(layer.to_string()),
        };
        // Ignore errors from progress updates - non-critical
        let _ = send_response(stream, &response);
    };

    let response = AgentResponse::from_result(
        storage::pull_image_with_progress_and_auth(image, platform, auth, progress_callback),
        error_codes::PULL_FAILED,
    );

    send_response(stream, &response)
}

/// Handle image query request.
fn handle_query(image: &str) -> AgentResponse {
    match storage::query_image(image) {
        Ok(Some(info)) => AgentResponse::ok_with_data(info),
        Ok(None) => AgentResponse::error(
            format!("image not found: {}", image),
            error_codes::NOT_FOUND,
        ),
        Err(e) => AgentResponse::from_err(e, error_codes::QUERY_FAILED),
    }
}

/// Handle list images request.
fn handle_list_images() -> AgentResponse {
    AgentResponse::from_result(storage::list_images(), error_codes::LIST_FAILED)
}

/// Handle garbage collection request.
fn handle_gc(dry_run: bool) -> AgentResponse {
    match storage::garbage_collect(dry_run) {
        Ok(freed) => AgentResponse::ok_with_data(serde_json::json!({
            "freed_bytes": freed,
            "dry_run": dry_run,
        })),
        Err(e) => AgentResponse::from_err(e, error_codes::GC_FAILED),
    }
}

/// Handle overlay preparation request.
fn handle_prepare_overlay(image: &str, workload_id: &str) -> AgentResponse {
    info!(image = %image, workload_id = %workload_id, "preparing overlay");
    AgentResponse::from_result(
        storage::prepare_overlay(image, workload_id),
        error_codes::OVERLAY_FAILED,
    )
}

/// Handle overlay cleanup request.
fn handle_cleanup_overlay(workload_id: &str) -> AgentResponse {
    info!(workload_id = %workload_id, "cleaning up overlay");
    match storage::cleanup_overlay(workload_id) {
        Ok(_) => AgentResponse::ok(None),
        Err(e) => AgentResponse::from_err(e, error_codes::CLEANUP_FAILED),
    }
}

/// Handle storage format request.
fn handle_format_storage() -> AgentResponse {
    info!("formatting storage");
    match storage::format() {
        Ok(_) => AgentResponse::ok(None),
        Err(e) => AgentResponse::from_err(e, error_codes::FORMAT_FAILED),
    }
}

/// Handle export layer request with chunked streaming.
///
/// Reads the layer tar file and sends it in LAYER_CHUNK_SIZE chunks,
/// each as a separate LayerData response. This avoids hitting MAX_FRAME_SIZE
/// for large layers.
fn handle_streaming_export_layer(
    stream: &mut impl Write,
    image_digest: &str,
    layer_index: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    info!(image_digest = %image_digest, layer_index = layer_index, "exporting layer (chunked)");

    // Export layer to tar file
    let tar_path = match storage::export_layer(image_digest, layer_index) {
        Ok(path) => path,
        Err(e) => {
            send_response(
                stream,
                &AgentResponse::from_err(e, error_codes::EXPORT_FAILED),
            )?;
            return Ok(());
        }
    };

    // Verify layer exists
    if let Err(e) = storage::get_layer_digest(image_digest, layer_index) {
        let _ = std::fs::remove_file(&tar_path);
        send_response(
            stream,
            &AgentResponse::from_err(e, error_codes::EXPORT_FAILED),
        )?;
        return Ok(());
    }

    // Open tar file for streaming
    let mut file = match std::fs::File::open(&tar_path) {
        Ok(f) => f,
        Err(e) => {
            let _ = std::fs::remove_file(&tar_path);
            send_response(
                stream,
                &AgentResponse::error(
                    format!("failed to open tar file: {}", e),
                    error_codes::EXPORT_FAILED,
                ),
            )?;
            return Ok(());
        }
    };

    // Stream in chunks. Read ahead one chunk so we can mark the last
    // data-carrying frame with done=true, avoiding an empty final frame.
    let mut buf = vec![0u8; LAYER_CHUNK_SIZE];
    let mut pending = match file.read(&mut buf) {
        Ok(n) => n,
        Err(e) => {
            let _ = std::fs::remove_file(&tar_path);
            send_response(
                stream,
                &AgentResponse::error(
                    format!("failed to read tar file: {}", e),
                    error_codes::EXPORT_FAILED,
                ),
            )?;
            return Ok(());
        }
    };

    loop {
        // Read the next chunk to determine if `pending` is the last one.
        let mut next_buf = vec![0u8; LAYER_CHUNK_SIZE];
        let next_n = match file.read(&mut next_buf) {
            Ok(n) => n,
            Err(e) => {
                let _ = std::fs::remove_file(&tar_path);
                send_response(
                    stream,
                    &AgentResponse::error(
                        format!("failed to read tar file: {}", e),
                        error_codes::EXPORT_FAILED,
                    ),
                )?;
                return Ok(());
            }
        };

        let done = next_n == 0;
        send_response(
            stream,
            &AgentResponse::LayerData {
                data: buf[..pending].to_vec(),
                done,
            },
        )?;

        if done {
            break;
        }

        // Swap buffers: next becomes pending.
        std::mem::swap(&mut buf, &mut next_buf);
        pending = next_n;
    }

    // Clean up temp file
    let _ = std::fs::remove_file(&tar_path);

    Ok(())
}

/// Handle storage status request.
fn handle_storage_status() -> AgentResponse {
    AgentResponse::from_result(storage::status(), error_codes::STATUS_FAILED)
}

// ============================================================================
// VM-Level Exec Handlers (Direct Execution in VM)
// ============================================================================

/// Handle VM-level exec (non-interactive).
/// Executes command directly in the VM's rootfs without any container isolation.
fn handle_vm_exec(
    command: &[String],
    env: &[(String, String)],
    workdir: Option<&str>,
    timeout_ms: Option<u64>,
) -> AgentResponse {
    info!(command = ?command, "executing directly in VM");

    if command.is_empty() {
        return AgentResponse::error("command cannot be empty", error_codes::INVALID_REQUEST);
    }

    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..]);

    // Set environment variables
    for (key, value) in env {
        cmd.env(key, value);
    }

    // Set working directory
    if let Some(wd) = workdir {
        cmd.current_dir(wd);
    }

    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    // Spawn the command
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            return AgentResponse::error(
                format!("failed to spawn command: {}", e),
                error_codes::SPAWN_FAILED,
            );
        }
    };

    // Handle timeout
    let deadline =
        timeout_ms.map(|ms| std::time::Instant::now() + std::time::Duration::from_millis(ms));

    loop {
        // Check if process has exited
        match child.try_wait() {
            Ok(Some(status)) => {
                // Process exited, collect output
                let mut stdout = String::new();
                let mut stderr = String::new();

                if let Some(mut out) = child.stdout.take() {
                    let _ = out.read_to_string(&mut stdout);
                }
                if let Some(mut err) = child.stderr.take() {
                    let _ = err.read_to_string(&mut stderr);
                }

                return AgentResponse::Completed {
                    exit_code: status.code().unwrap_or(-1),
                    stdout,
                    stderr,
                };
            }
            Ok(None) => {
                // Still running, check timeout
                if let Some(deadline) = deadline {
                    if std::time::Instant::now() >= deadline {
                        // Timeout - kill process
                        warn!("VM exec command timed out, killing process");
                        if let Err(e) = child.kill() {
                            warn!(error = %e, "failed to kill timed out process");
                        }
                        // Wait to reap the process and avoid zombies
                        if let Err(e) = child.wait() {
                            warn!(error = %e, "failed to wait for killed process");
                        }
                        return AgentResponse::Completed {
                            exit_code: 124, // Standard timeout exit code
                            stdout: String::new(),
                            stderr: "command timed out".to_string(),
                        };
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(PROCESS_POLL_INTERVAL_MS));
            }
            Err(e) => {
                return AgentResponse::error(
                    format!("failed to check process status: {}", e),
                    error_codes::WAIT_FAILED,
                );
            }
        }
    }
}

/// Handle interactive VM-level exec with streaming I/O.
fn handle_interactive_vm_exec(
    stream: &mut impl ReadWrite,
    request: AgentRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    let (command, env, workdir, timeout_ms, tty) = match request {
        AgentRequest::VmExec {
            command,
            env,
            workdir,
            timeout_ms,
            tty,
            ..
        } => (command, env, workdir, timeout_ms, tty),
        _ => {
            send_response(
                stream,
                &AgentResponse::error("expected VmExec request", error_codes::INVALID_REQUEST),
            )?;
            return Ok(());
        }
    };

    info!(command = ?command, tty = tty, "starting interactive VM exec");

    if command.is_empty() {
        send_response(
            stream,
            &AgentResponse::error("command cannot be empty", error_codes::INVALID_REQUEST),
        )?;
        return Ok(());
    }

    // Spawn the command directly
    let (mut child, pty_master) =
        match spawn_direct_interactive_command(&command, &env, workdir.as_deref(), tty) {
            Ok(result) => result,
            Err(e) => {
                send_response(
                    stream,
                    &AgentResponse::from_err(e, error_codes::SPAWN_FAILED),
                )?;
                return Ok(());
            }
        };

    // Send Started response
    send_response(stream, &AgentResponse::Started)?;

    // Run the appropriate interactive I/O loop
    let exit_code = match pty_master {
        #[cfg(target_os = "linux")]
        Some(pty) => run_interactive_loop_pty(stream, &mut child, pty, timeout_ms)?,
        _ => run_interactive_loop(stream, &mut child, timeout_ms)?,
    };

    // Send Exited response
    send_response(stream, &AgentResponse::Exited { exit_code })?;

    Ok(())
}

/// Spawn a command directly in the VM for interactive execution.
///
/// When `tty` is true, allocates a PTY pair and attaches the slave side
/// to the child process. Returns the child and an optional `PtyMaster`.
#[cfg(target_os = "linux")]
fn spawn_direct_interactive_command(
    command: &[String],
    env: &[(String, String)],
    workdir: Option<&str>,
    tty: bool,
) -> Result<(Child, Option<pty::PtyMaster>), Box<dyn std::error::Error>> {
    use std::os::unix::io::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::process::CommandExt;

    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..]);

    for (key, value) in env {
        cmd.env(key, value);
    }
    if let Some(wd) = workdir {
        cmd.current_dir(wd);
    }

    if tty {
        // Allocate a PTY pair with default 80x24 size (host will send Resize).
        let (pty_master, slave_fd) = pty::open_pty(80, 24)?;
        let slave_raw = slave_fd.as_raw_fd();

        // Set up stdio from the slave fd. We dup because Stdio::from_raw_fd
        // takes ownership and we need the fd for all three handles + pre_exec.
        // SAFETY: slave_fd is a valid open fd from openpty.
        unsafe {
            cmd.stdin(Stdio::from_raw_fd(libc::dup(slave_raw)));
            cmd.stdout(Stdio::from_raw_fd(libc::dup(slave_raw)));
            cmd.stderr(Stdio::from_raw_fd(libc::dup(slave_raw)));
        }

        // SAFETY: pre_exec closure calls only async-signal-safe functions.
        unsafe {
            cmd.pre_exec(pty::slave_pre_exec(slave_raw));
        }

        let child = cmd.spawn()?;

        // Close the slave fd in the parent — the child has its own copies.
        drop(slave_fd);

        Ok((child, Some(pty_master)))
    } else {
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let child = cmd.spawn()?;
        Ok((child, None))
    }
}

/// Stub for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
fn spawn_direct_interactive_command(
    command: &[String],
    env: &[(String, String)],
    workdir: Option<&str>,
    _tty: bool,
) -> Result<(Child, Option<()>), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..]);

    for (key, value) in env {
        cmd.env(key, value);
    }
    if let Some(wd) = workdir {
        cmd.current_dir(wd);
    }

    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let child = cmd.spawn()?;
    Ok((child, None))
}

// ============================================================================
// Container Lifecycle Handlers
// ============================================================================

fn handle_create_container(
    image: &str,
    command: &[String],
    env: &[(String, String)],
    workdir: Option<&str>,
    mounts: &[(String, String, bool)],
) -> AgentResponse {
    info!(image = %image, command = ?command, "creating container");

    match container::create_container(image, command, env, workdir, mounts) {
        Ok(info) => {
            // Also start the container immediately
            if let Err(e) = container::start_container(&info.id) {
                warn!(error = %e, "failed to start container after create");
                return AgentResponse::error(
                    format!("container created but failed to start: {}", e),
                    error_codes::START_FAILED,
                );
            }

            let container_info = ContainerInfo {
                id: info.id,
                image: info.image,
                state: "running".to_string(),
                created_at: info.created_at,
                command: info.command,
            };

            AgentResponse::ok_with_data(container_info)
        }
        Err(e) => AgentResponse::from_err(e, error_codes::CREATE_FAILED),
    }
}

fn handle_start_container(container_id: &str) -> AgentResponse {
    info!(container_id = %container_id, "starting container");
    match container::start_container(container_id) {
        Ok(()) => AgentResponse::ok(None),
        Err(e) => AgentResponse::from_err(e, error_codes::START_FAILED),
    }
}

fn handle_stop_container(container_id: &str, timeout_secs: u64) -> AgentResponse {
    info!(container_id = %container_id, timeout_secs = timeout_secs, "stopping container");
    match container::stop_container(container_id, timeout_secs) {
        Ok(()) => AgentResponse::ok(None),
        Err(e) => AgentResponse::from_err(e, error_codes::STOP_FAILED),
    }
}

fn handle_delete_container(container_id: &str, force: bool) -> AgentResponse {
    info!(container_id = %container_id, force = force, "deleting container");
    match container::delete_container(container_id, force) {
        Ok(()) => AgentResponse::ok(None),
        Err(e) => AgentResponse::from_err(e, error_codes::DELETE_FAILED),
    }
}

fn handle_list_containers() -> AgentResponse {
    let containers = container::list_containers();
    let infos: Vec<ContainerInfo> = containers
        .into_iter()
        .map(|c| ContainerInfo {
            id: c.id,
            image: c.image,
            state: c.state.to_string(),
            created_at: c.created_at,
            command: c.command,
        })
        .collect();

    AgentResponse::ok_with_data(infos)
}

fn handle_exec(
    container_id: &str,
    command: &[String],
    env: &[(String, String)],
    workdir: Option<&str>,
    timeout_ms: Option<u64>,
) -> AgentResponse {
    info!(container_id = %container_id, command = ?command, "executing in container");

    match container::exec_in_container(container_id, command, env, workdir, timeout_ms) {
        Ok(result) => AgentResponse::Completed {
            exit_code: result.exit_code,
            stdout: result.stdout,
            stderr: result.stderr,
        },
        Err(e) => AgentResponse::from_err(e, error_codes::EXEC_FAILED),
    }
}

/// Handle interactive container exec with streaming I/O.
fn handle_interactive_container_exec(
    stream: &mut impl ReadWrite,
    request: AgentRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    let (container_id, command, env, workdir, timeout_ms, tty) = match request {
        AgentRequest::Exec {
            container_id,
            command,
            env,
            workdir,
            timeout_ms,
            tty,
            ..
        } => (container_id, command, env, workdir, timeout_ms, tty),
        _ => {
            send_response(
                stream,
                &AgentResponse::error("expected Exec request", error_codes::INVALID_REQUEST),
            )?;
            return Ok(());
        }
    };

    info!(container_id = %container_id, command = ?command, tty = tty, "starting interactive container exec");

    // Spawn the interactive exec process
    let mut child = match container::spawn_interactive_exec(
        &container_id,
        &command,
        &env,
        workdir.as_deref(),
        tty,
    ) {
        Ok(child) => child,
        Err(e) => {
            send_response(
                stream,
                &AgentResponse::from_err(e, error_codes::EXEC_FAILED),
            )?;
            return Ok(());
        }
    };

    // Send Started response
    send_response(stream, &AgentResponse::Started)?;

    // Run the interactive I/O loop
    let exit_code = run_interactive_loop(stream, &mut child, timeout_ms)?;

    // Send Exited response
    send_response(stream, &AgentResponse::Exited { exit_code })?;

    Ok(())
}

/// Send a response to the client.
fn send_response(
    stream: &mut impl Write,
    response: &AgentResponse,
) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_vec(response)?;
    let len = json.len() as u32;

    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(&json)?;
    stream.flush()?;

    debug!(?response, "sent response");
    Ok(())
}

/// Trait for read+write streams with raw fd access.
trait ReadWrite: Read + Write + AsRawFd {}
impl<T: Read + Write + AsRawFd> ReadWrite for T {}
