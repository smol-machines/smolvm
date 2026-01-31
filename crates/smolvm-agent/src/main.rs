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
    ports, AgentRequest, AgentResponse, ContainerInfo, RegistryAuth, PROTOCOL_VERSION,
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
    // CRITICAL: Mount essential filesystems FIRST, before anything else.
    // When running as init (PID 1), we need these for the system to function.
    // This must happen before logging (which needs /dev for output).
    mount_essential_filesystems();

    // CRITICAL: Create vsock listener IMMEDIATELY after mounts.
    // This must happen before logging setup to minimize time to listener ready.
    // The kernel boots in ~30ms and host connects immediately after.
    let listener = match vsock::listen(ports::AGENT_CONTROL) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("failed to create vsock listener: {}", e);
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

/// Mount essential filesystems (proc, sysfs, devtmpfs).
/// This must be done first when running as init (PID 1).
/// Uses direct syscalls to avoid any overhead.
#[cfg(target_os = "linux")]
fn mount_essential_filesystems() {
    use std::ffi::CString;

    // Helper to create CString from static str (safe: no null bytes in literals)
    fn cstr(s: &str) -> CString {
        CString::new(s).expect("static string without null bytes")
    }

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

    match mount_result {
        Ok(status) if status.success() => {
            debug!("storage disk mounted successfully");
            // Create directory structure
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
        }
        _ => {
            // Mount failed - try formatting first (first boot)
            warn!("mount failed, attempting to format storage disk");
            let _ = Command::new("mkfs.ext4")
                .args(["-F", "-q", STORAGE_DEVICE])
                .status();
            let _ = Command::new("mount")
                .args([STORAGE_DEVICE, STORAGE_MOUNT])
                .status();
            // Create directory structure
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
                &AgentResponse::Error {
                    message: format!("message size {} exceeds maximum {}", len, MAX_MESSAGE_SIZE),
                    code: Some("MESSAGE_TOO_LARGE".to_string()),
                },
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
                    &AgentResponse::Error {
                        message: format!("invalid request: {}", e),
                        code: Some("INVALID_REQUEST".to_string()),
                    },
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

        AgentRequest::Pull {
            image,
            platform,
            auth,
        } => handle_pull(&image, platform.as_deref(), auth.as_ref()),

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
            AgentResponse::Error {
                message: "interactive VM exec not handled here".into(),
                code: Some("INTERNAL_ERROR".into()),
            }
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
            AgentResponse::Error {
                message: "interactive mode not handled here".into(),
                code: Some("INTERNAL_ERROR".into()),
            }
        }

        AgentRequest::Stdin { .. } | AgentRequest::Resize { .. } => AgentResponse::Error {
            message: "stdin/resize only valid during interactive session".into(),
            code: Some("INVALID_REQUEST".into()),
        },

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
            AgentResponse::Error {
                message: "interactive container exec not handled here".into(),
                code: Some("INTERNAL_ERROR".into()),
            }
        }

        AgentRequest::ExportLayer {
            image_digest,
            layer_index,
        } => handle_export_layer(&image_digest, layer_index),
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
                &AgentResponse::Error {
                    message: "expected Run request".into(),
                    code: Some("INVALID_REQUEST".into()),
                },
            )?;
            return Ok(());
        }
    };

    info!(image = %image, command = ?command, tty = tty, "starting interactive run");

    // Prepare the overlay and get the rootfs path
    let rootfs = match storage::prepare_for_run(&image) {
        Ok(path) => path,
        Err(e) => {
            send_response(
                stream,
                &AgentResponse::Error {
                    message: e.to_string(),
                    code: Some("RUN_FAILED".into()),
                },
            )?;
            return Ok(());
        }
    };

    // Setup virtiofs mounts at staging area (crun will bind-mount them via OCI spec)
    if let Err(e) = storage::setup_mounts(&rootfs, &mounts) {
        send_response(
            stream,
            &AgentResponse::Error {
                message: e.to_string(),
                code: Some("MOUNT_FAILED".into()),
            },
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
                &AgentResponse::Error {
                    message: e.to_string(),
                    code: Some("SPAWN_FAILED".into()),
                },
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

        // Build poll fds array for stdout and stderr
        let stdout_fd = child_stdout.as_ref().map(|s| s.as_raw_fd()).unwrap_or(-1);
        let stderr_fd = child_stderr.as_ref().map(|s| s.as_raw_fd()).unwrap_or(-1);

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
        ];

        // Wait for I/O or timeout using poll()
        let nfds = if stdout_fd >= 0 && stderr_fd >= 0 {
            2
        } else if stdout_fd >= 0 || stderr_fd >= 0 {
            // Only one fd is valid, adjust nfds
            if stdout_fd >= 0 {
                1
            } else {
                2
            }
        } else {
            0
        };

        if nfds > 0 {
            let poll_result =
                unsafe { libc::poll(poll_fds.as_mut_ptr(), nfds as libc::nfds_t, poll_timeout_ms) };

            if poll_result < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() != std::io::ErrorKind::Interrupted {
                    debug!(error = %err, "poll error");
                }
                // On EINTR, just continue the loop
                continue;
            }
        } else {
            // No fds to poll, just sleep briefly to avoid busy-loop
            std::thread::sleep(Duration::from_millis(poll_timeout_ms as u64));
        }

        // Read available stdout if poll indicated data ready (or always try in non-blocking mode)
        if let Some(ref mut stdout) = child_stdout {
            loop {
                match stdout.read(&mut stdout_buf) {
                    Ok(0) => break, // EOF
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

        // Read available stderr
        if let Some(ref mut stderr) = child_stderr {
            loop {
                match stderr.read(&mut stderr_buf) {
                    Ok(0) => break, // EOF
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

        // Check for incoming stdin data (non-blocking read from vsock)
        // Try to read a request (with timeout)
        if let Some(request) = try_read_request(stream)? {
            match request {
                AgentRequest::Stdin { data } => {
                    if let Some(ref mut stdin) = child_stdin {
                        let _ = stdin.write_all(&data);
                        let _ = stdin.flush();
                    }
                }
                AgentRequest::Resize { cols, rows } => {
                    // TODO: Implement PTY resize using TIOCSWINSZ
                    debug!(cols, rows, "resize requested (not implemented)");
                }
                _ => {
                    warn!("unexpected request during interactive session");
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

/// Try to read a request with a very short timeout.
fn try_read_request(
    _stream: &mut impl ReadWrite,
) -> Result<Option<AgentRequest>, Box<dyn std::error::Error>> {
    // For now, use a simple non-blocking approach
    // In a production implementation, we'd use poll/select

    // This is a simplified version - we'll check if data is available
    // by trying to peek or using non-blocking read

    // For the initial implementation, we'll skip stdin forwarding
    // and just focus on output streaming
    Ok(None)
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

    let connect_result = match TcpStream::connect_timeout(&addr, Duration::from_secs(10)) {
        Ok(mut stream) => {
            // Try to set timeouts
            let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));

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
        Err(e) => AgentResponse::Error {
            message: e.to_string(),
            code: Some("RUN_FAILED".to_string()),
        },
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

    let response = match storage::pull_image_with_progress_and_auth(
        image,
        platform,
        auth,
        progress_callback,
    ) {
        Ok(info) => match serde_json::to_value(info) {
            Ok(data) => AgentResponse::Ok { data: Some(data) },
            Err(e) => AgentResponse::Error {
                message: format!("failed to serialize image info: {}", e),
                code: Some("SERIALIZATION_ERROR".to_string()),
            },
        },
        Err(e) => AgentResponse::Error {
            message: e.to_string(),
            code: Some("PULL_FAILED".to_string()),
        },
    };

    send_response(stream, &response)
}

/// Handle image pull request (legacy, no progress).
#[allow(dead_code)]
fn handle_pull(image: &str, platform: Option<&str>, auth: Option<&RegistryAuth>) -> AgentResponse {
    info!(
        image = %image,
        ?platform,
        has_auth = auth.is_some(),
        "pulling image"
    );

    match storage::pull_image_with_auth(image, platform, auth) {
        Ok(info) => match serde_json::to_value(info) {
            Ok(data) => AgentResponse::Ok { data: Some(data) },
            Err(e) => AgentResponse::Error {
                message: format!("failed to serialize image info: {}", e),
                code: Some("SERIALIZATION_ERROR".to_string()),
            },
        },
        Err(e) => AgentResponse::Error {
            message: e.to_string(),
            code: Some("PULL_FAILED".to_string()),
        },
    }
}

/// Handle image query request.
fn handle_query(image: &str) -> AgentResponse {
    match storage::query_image(image) {
        Ok(Some(info)) => match serde_json::to_value(info) {
            Ok(data) => AgentResponse::Ok { data: Some(data) },
            Err(e) => AgentResponse::Error {
                message: format!("failed to serialize image info: {}", e),
                code: Some("SERIALIZATION_ERROR".to_string()),
            },
        },
        Ok(None) => AgentResponse::Error {
            message: format!("image not found: {}", image),
            code: Some("NOT_FOUND".to_string()),
        },
        Err(e) => AgentResponse::Error {
            message: e.to_string(),
            code: Some("QUERY_FAILED".to_string()),
        },
    }
}

/// Handle list images request.
fn handle_list_images() -> AgentResponse {
    match storage::list_images() {
        Ok(images) => match serde_json::to_value(images) {
            Ok(data) => AgentResponse::Ok { data: Some(data) },
            Err(e) => AgentResponse::Error {
                message: format!("failed to serialize image list: {}", e),
                code: Some("SERIALIZATION_ERROR".to_string()),
            },
        },
        Err(e) => AgentResponse::Error {
            message: e.to_string(),
            code: Some("LIST_FAILED".to_string()),
        },
    }
}

/// Handle garbage collection request.
fn handle_gc(dry_run: bool) -> AgentResponse {
    match storage::garbage_collect(dry_run) {
        Ok(freed) => AgentResponse::Ok {
            data: Some(serde_json::json!({
                "freed_bytes": freed,
                "dry_run": dry_run,
            })),
        },
        Err(e) => AgentResponse::Error {
            message: e.to_string(),
            code: Some("GC_FAILED".to_string()),
        },
    }
}

/// Handle overlay preparation request.
fn handle_prepare_overlay(image: &str, workload_id: &str) -> AgentResponse {
    info!(image = %image, workload_id = %workload_id, "preparing overlay");

    match storage::prepare_overlay(image, workload_id) {
        Ok(info) => match serde_json::to_value(info) {
            Ok(data) => AgentResponse::Ok { data: Some(data) },
            Err(e) => AgentResponse::Error {
                message: format!("failed to serialize overlay info: {}", e),
                code: Some("SERIALIZATION_ERROR".to_string()),
            },
        },
        Err(e) => AgentResponse::Error {
            message: e.to_string(),
            code: Some("OVERLAY_FAILED".to_string()),
        },
    }
}

/// Handle overlay cleanup request.
fn handle_cleanup_overlay(workload_id: &str) -> AgentResponse {
    info!(workload_id = %workload_id, "cleaning up overlay");

    match storage::cleanup_overlay(workload_id) {
        Ok(_) => AgentResponse::Ok { data: None },
        Err(e) => AgentResponse::Error {
            message: e.to_string(),
            code: Some("CLEANUP_FAILED".to_string()),
        },
    }
}

/// Handle storage format request.
fn handle_format_storage() -> AgentResponse {
    info!("formatting storage");

    match storage::format() {
        Ok(_) => AgentResponse::Ok { data: None },
        Err(e) => AgentResponse::Error {
            message: e.to_string(),
            code: Some("FORMAT_FAILED".to_string()),
        },
    }
}

/// Handle export layer request.
/// Returns the layer data as base64 encoded tar.
fn handle_export_layer(image_digest: &str, layer_index: usize) -> AgentResponse {
    info!(image_digest = %image_digest, layer_index = layer_index, "exporting layer");

    // Export layer to tar file
    let tar_path = match storage::export_layer(image_digest, layer_index) {
        Ok(path) => path,
        Err(e) => {
            return AgentResponse::Error {
                message: e.to_string(),
                code: Some("EXPORT_FAILED".to_string()),
            };
        }
    };

    // Get layer digest for metadata (verifies the layer exists)
    let _layer_digest = match storage::get_layer_digest(image_digest, layer_index) {
        Ok(d) => d,
        Err(e) => {
            return AgentResponse::Error {
                message: e.to_string(),
                code: Some("EXPORT_FAILED".to_string()),
            };
        }
    };

    // Read the tar file
    let tar_data = match std::fs::read(&tar_path) {
        Ok(data) => data,
        Err(e) => {
            return AgentResponse::Error {
                message: format!("failed to read tar file: {}", e),
                code: Some("EXPORT_FAILED".to_string()),
            };
        }
    };

    // Clean up temp file
    let _ = std::fs::remove_file(&tar_path);

    // Return layer data
    AgentResponse::LayerData {
        data: tar_data,
        done: true,
    }
}

/// Handle storage status request.
fn handle_storage_status() -> AgentResponse {
    match storage::status() {
        Ok(status) => match serde_json::to_value(status) {
            Ok(data) => AgentResponse::Ok { data: Some(data) },
            Err(e) => AgentResponse::Error {
                message: format!("failed to serialize storage status: {}", e),
                code: Some("SERIALIZATION_ERROR".to_string()),
            },
        },
        Err(e) => AgentResponse::Error {
            message: e.to_string(),
            code: Some("STATUS_FAILED".to_string()),
        },
    }
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
        return AgentResponse::Error {
            message: "command cannot be empty".into(),
            code: Some("INVALID_REQUEST".into()),
        };
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
            return AgentResponse::Error {
                message: format!("failed to spawn command: {}", e),
                code: Some("SPAWN_FAILED".into()),
            };
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
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(e) => {
                return AgentResponse::Error {
                    message: format!("failed to check process status: {}", e),
                    code: Some("WAIT_FAILED".into()),
                };
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
                &AgentResponse::Error {
                    message: "expected VmExec request".into(),
                    code: Some("INVALID_REQUEST".into()),
                },
            )?;
            return Ok(());
        }
    };

    info!(command = ?command, tty = tty, "starting interactive VM exec");

    if command.is_empty() {
        send_response(
            stream,
            &AgentResponse::Error {
                message: "command cannot be empty".into(),
                code: Some("INVALID_REQUEST".into()),
            },
        )?;
        return Ok(());
    }

    // Spawn the command directly
    let mut child = match spawn_direct_interactive_command(&command, &env, workdir.as_deref(), tty)
    {
        Ok(child) => child,
        Err(e) => {
            send_response(
                stream,
                &AgentResponse::Error {
                    message: e.to_string(),
                    code: Some("SPAWN_FAILED".into()),
                },
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

/// Spawn a command directly in the VM for interactive execution.
fn spawn_direct_interactive_command(
    command: &[String],
    env: &[(String, String)],
    workdir: Option<&str>,
    tty: bool,
) -> Result<Child, Box<dyn std::error::Error>> {
    if tty {
        // For TTY mode, we need to use a PTY
        // TODO: For TTY mode, use --console-socket or similar
        // For now, fall back to pipe-based I/O
        warn!("TTY mode requested but not fully supported for direct VM exec, using pipes");
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

    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let child = cmd.spawn()?;
    Ok(child)
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
                return AgentResponse::Error {
                    message: format!("container created but failed to start: {}", e),
                    code: Some("START_FAILED".to_string()),
                };
            }

            let container_info = ContainerInfo {
                id: info.id,
                image: info.image,
                state: "running".to_string(),
                created_at: info.created_at,
                command: info.command,
            };

            match serde_json::to_value(container_info) {
                Ok(data) => AgentResponse::Ok { data: Some(data) },
                Err(e) => AgentResponse::Error {
                    message: format!("failed to serialize container info: {}", e),
                    code: Some("SERIALIZATION_ERROR".to_string()),
                },
            }
        }
        Err(e) => AgentResponse::Error {
            message: e.to_string(),
            code: Some("CREATE_FAILED".to_string()),
        },
    }
}

fn handle_start_container(container_id: &str) -> AgentResponse {
    info!(container_id = %container_id, "starting container");

    match container::start_container(container_id) {
        Ok(()) => AgentResponse::Ok { data: None },
        Err(e) => AgentResponse::Error {
            message: e.to_string(),
            code: Some("START_FAILED".to_string()),
        },
    }
}

fn handle_stop_container(container_id: &str, timeout_secs: u64) -> AgentResponse {
    info!(container_id = %container_id, timeout_secs = timeout_secs, "stopping container");

    match container::stop_container(container_id, timeout_secs) {
        Ok(()) => AgentResponse::Ok { data: None },
        Err(e) => AgentResponse::Error {
            message: e.to_string(),
            code: Some("STOP_FAILED".to_string()),
        },
    }
}

fn handle_delete_container(container_id: &str, force: bool) -> AgentResponse {
    info!(container_id = %container_id, force = force, "deleting container");

    match container::delete_container(container_id, force) {
        Ok(()) => AgentResponse::Ok { data: None },
        Err(e) => AgentResponse::Error {
            message: e.to_string(),
            code: Some("DELETE_FAILED".to_string()),
        },
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

    match serde_json::to_value(infos) {
        Ok(data) => AgentResponse::Ok { data: Some(data) },
        Err(e) => AgentResponse::Error {
            message: format!("failed to serialize container list: {}", e),
            code: Some("SERIALIZATION_ERROR".to_string()),
        },
    }
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
        Err(e) => AgentResponse::Error {
            message: e.to_string(),
            code: Some("EXEC_FAILED".to_string()),
        },
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
                &AgentResponse::Error {
                    message: "expected Exec request".into(),
                    code: Some("INVALID_REQUEST".into()),
                },
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
                &AgentResponse::Error {
                    message: e.to_string(),
                    code: Some("EXEC_FAILED".into()),
                },
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

/// Trait for read+write streams.
trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}
