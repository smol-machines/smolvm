//! smolvm guest agent.
//!
//! This agent runs inside smolvm VMs and handles:
//! - OCI image pulling via crane
//! - Layer extraction and storage management
//! - Overlay filesystem preparation for workloads
//! - Command execution with optional interactive/TTY support
//!
//! Communication is via vsock on port 6000.

use smolvm_protocol::{ports, AgentRequest, AgentResponse, ContainerInfo, PROTOCOL_VERSION};
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::process::{Child, Command, Stdio};
use tracing::{debug, error, info, warn};

mod container;
mod oci;
mod storage;
mod vsock;

fn main() {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("smolvm_agent=debug".parse().unwrap()),
        )
        .init();

    info!(version = env!("CARGO_PKG_VERSION"), "starting smolvm-agent");

    // Initialize storage
    if let Err(e) = storage::init() {
        error!(error = %e, "failed to initialize storage");
        std::process::exit(1);
    }

    // Start vsock server
    if let Err(e) = run_server() {
        error!(error = %e, "server error");
        std::process::exit(1);
    }
}

/// Run the vsock server.
fn run_server() -> Result<(), Box<dyn std::error::Error>> {
    let listener = vsock::listen(ports::AGENT_CONTROL)?;
    info!(port = ports::AGENT_CONTROL, "listening on vsock");

    loop {
        match listener.accept() {
            Ok(mut stream) => {
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
    let mut buf = vec![0u8; 64 * 1024]; // 64KB buffer

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

        AgentRequest::Pull { image, platform } => handle_pull(&image, platform.as_deref()),

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

            // Test 1: Pure syscall TCP connect test (bypass C library)
            let syscall_result = test_tcp_syscall();

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

        // Container lifecycle (Phase 2/3)
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
        } => handle_exec(
            &container_id,
            &command,
            &env,
            workdir.as_deref(),
            timeout_ms,
        ),
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

/// Path to crun binary.
const CRUN_PATH: &str = "/usr/bin/crun";

/// Directory where virtiofs mounts are staged.
const VIRTIOFS_MOUNT_ROOT: &str = "/mnt/virtiofs";

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
        let virtiofs_mount = Path::new(VIRTIOFS_MOUNT_ROOT).join(tag);
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

    // Build crun run command
    let mut cmd = Command::new(CRUN_PATH);
    cmd.args([
        "run",
        "--bundle",
        &bundle_path.to_string_lossy(),
        &container_id,
    ]);

    // Setup stdio for interactive mode
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    // TODO: For TTY mode, use --console-socket to receive PTY master FD

    info!(
        command = ?command,
        container_id = %container_id,
        bundle = %bundle_path.display(),
        mounts = mounts.len(),
        "spawning interactive container with crun"
    );
    let child = cmd.spawn()?;

    Ok(child)
}

/// Run the interactive I/O loop.
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
        set_nonblocking(stdout.as_raw_fd());
    }
    if let Some(ref stderr) = child_stderr {
        set_nonblocking(stderr.as_raw_fd());
    }

    let mut stdout_buf = [0u8; 4096];
    let mut stderr_buf = [0u8; 4096];

    loop {
        // Check if child has exited
        match child.try_wait()? {
            Some(status) => {
                // Drain any remaining output
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
                            Err(_) => break,
                        }
                    }
                }
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
                            Err(_) => break,
                        }
                    }
                }
                return Ok(status.code().unwrap_or(-1));
            }
            None => {}
        }

        // Check timeout
        if let Some(deadline) = deadline {
            if Instant::now() >= deadline {
                warn!("interactive command timed out");
                let _ = child.kill();
                let _ = child.wait();
                return Ok(124); // Timeout exit code
            }
        }

        // Read available stdout
        if let Some(ref mut stdout) = child_stdout {
            match stdout.read(&mut stdout_buf) {
                Ok(0) => {} // EOF
                Ok(n) => {
                    send_response(
                        stream,
                        &AgentResponse::Stdout {
                            data: stdout_buf[..n].to_vec(),
                        },
                    )?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    debug!(error = %e, "stdout read error");
                }
            }
        }

        // Read available stderr
        if let Some(ref mut stderr) = child_stderr {
            match stderr.read(&mut stderr_buf) {
                Ok(0) => {} // EOF
                Ok(n) => {
                    send_response(
                        stream,
                        &AgentResponse::Stderr {
                            data: stderr_buf[..n].to_vec(),
                        },
                    )?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    debug!(error = %e, "stderr read error");
                }
            }
        }

        // Check for incoming stdin data (non-blocking read from vsock)
        // This requires the stream to support non-blocking or using poll/select
        // For now, we use a simple polling approach with short timeout

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

        // Small sleep to prevent busy-waiting
        std::thread::sleep(Duration::from_millis(10));
    }
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
fn set_nonblocking(fd: i32) {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
}

/// Test TCP connection using pure syscalls (bypass C library).
/// Connects to 1.1.1.1:80 and sends HTTP GET request.
fn test_tcp_syscall() -> serde_json::Value {
    use std::io::{Read as _, Write as _};
    use std::net::{SocketAddr, TcpStream};
    use std::time::Duration;

    info!("testing TCP with pure Rust std::net");

    // Test 1: Try to create a TCP connection to 1.1.1.1:80
    let addr: SocketAddr = "1.1.1.1:80".parse().unwrap();

    let connect_result = match TcpStream::connect_timeout(&addr, Duration::from_secs(10)) {
        Ok(mut stream) => {
            // Try to set timeouts
            let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));

            // Send a simple HTTP request
            let request = "GET / HTTP/1.0\r\nHost: 1.1.1.1\r\n\r\n";
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

    // Also test raw socket() syscall and lseek behavior
    let socket_test = unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            serde_json::json!({
                "socket_created": false,
                "errno": err.raw_os_error().unwrap_or(-1),
                "errno_str": err.to_string(),
            })
        } else {
            // Get socket type info
            let mut sock_type: libc::c_int = 0;
            let mut sock_type_len: libc::socklen_t =
                std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                &mut sock_type as *mut _ as *mut libc::c_void,
                &mut sock_type_len,
            );

            // Test lseek on the socket - this should return ESPIPE (29) for normal sockets
            let lseek_result = libc::lseek(fd, 0, libc::SEEK_CUR);
            let lseek_errno = if lseek_result < 0 {
                let err = std::io::Error::last_os_error();
                Some((err.raw_os_error().unwrap_or(-1), err.to_string()))
            } else {
                None
            };

            libc::close(fd);
            serde_json::json!({
                "socket_created": true,
                "fd": fd,
                "sock_type": sock_type,
                "lseek_result": lseek_result,
                "lseek_errno": lseek_errno.map(|(e, s)| serde_json::json!({"code": e, "str": s})),
                "expected_errno_espipe": 29,  // ESPIPE = 29 on Linux
            })
        }
    };

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

/// Handle image pull request.
fn handle_pull(image: &str, platform: Option<&str>) -> AgentResponse {
    info!(image = %image, ?platform, "pulling image");

    match storage::pull_image(image, platform) {
        Ok(info) => AgentResponse::Ok {
            data: Some(serde_json::to_value(info).unwrap()),
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
        Ok(Some(info)) => AgentResponse::Ok {
            data: Some(serde_json::to_value(info).unwrap()),
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
        Ok(images) => AgentResponse::Ok {
            data: Some(serde_json::to_value(images).unwrap()),
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
        Ok(info) => AgentResponse::Ok {
            data: Some(serde_json::to_value(info).unwrap()),
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

/// Handle storage status request.
fn handle_storage_status() -> AgentResponse {
    match storage::status() {
        Ok(status) => AgentResponse::Ok {
            data: Some(serde_json::to_value(status).unwrap()),
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
                        let _ = child.kill();
                        let _ = child.wait();
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
// Container Lifecycle Handlers (Phase 2/3)
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

            AgentResponse::Ok {
                data: Some(
                    serde_json::to_value(ContainerInfo {
                        id: info.id,
                        image: info.image,
                        state: "running".to_string(),
                        created_at: info.created_at,
                        command: info.command,
                    })
                    .unwrap(),
                ),
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

    AgentResponse::Ok {
        data: Some(serde_json::to_value(infos).unwrap()),
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
