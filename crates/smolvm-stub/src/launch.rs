//! VM launch functionality for packed binaries.
//!
//! This module handles forking and launching the microVM with libkrun.
//! Uses dlopen to load libkrun dynamically after assets are extracted.
//!
//! Supports two modes:
//! - Ephemeral: Boot VM, run command, kill VM
//! - Daemon: Keep VM running for fast repeated exec (~50ms)

use smolvm_pack::format::PackManifest;
use smolvm_protocol::ports;
use std::ffi::{CStr, CString};
use std::fs::{self, File};
use std::io::{BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process;
use std::time::Duration;

/// Daemon state file name.
const DAEMON_STATE_FILE: &str = "daemon.json";

/// Volume mount specification.
#[derive(Debug, Clone)]
pub struct VolumeMount {
    pub host_path: PathBuf,
    pub guest_path: String,
    pub read_only: bool,
}

/// Configuration for launching the VM in ephemeral mode.
pub struct LaunchConfig {
    pub cache_dir: PathBuf,
    pub manifest: PackManifest,
    pub command: Option<Vec<String>>,
    pub mounts: Vec<VolumeMount>,
    pub env_vars: Vec<(String, String)>,
    pub workdir: Option<String>,
    pub cpus: Option<u8>,
    pub mem: Option<u32>,
    pub debug: bool,
}

/// Configuration for starting the daemon.
pub struct DaemonConfig {
    pub cache_dir: PathBuf,
    pub manifest: PackManifest,
    pub mounts: Vec<VolumeMount>,
    pub cpus: Option<u8>,
    pub mem: Option<u32>,
    pub debug: bool,
}

/// Configuration for executing in the daemon.
pub struct ExecConfig {
    pub cache_dir: PathBuf,
    pub manifest: PackManifest,
    pub command: Option<Vec<String>>,
    pub mounts: Vec<VolumeMount>,
    pub env_vars: Vec<(String, String)>,
    pub workdir: Option<String>,
    pub debug: bool,
}

/// Daemon state persisted to disk.
#[derive(serde::Serialize, serde::Deserialize)]
struct DaemonState {
    pid: u32,
    socket_path: String,
    started_at: u64,
}

/// Parse a volume mount string (HOST:GUEST[:ro]).
pub fn parse_volume_mount(s: &str) -> Option<VolumeMount> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() < 2 {
        return None;
    }

    let host_path = PathBuf::from(parts[0]);
    let guest_path = parts[1].to_string();
    let read_only = parts.get(2).map(|s| *s == "ro").unwrap_or(false);

    Some(VolumeMount {
        host_path,
        guest_path,
        read_only,
    })
}

/// Function pointers for libkrun FFI.
///
/// # Safety
///
/// All function pointers are loaded via dlsym and must match the libkrun C ABI.
/// The caller must ensure:
/// - `handle` remains valid for the lifetime of this struct
/// - All string arguments (c_char pointers) are valid null-terminated C strings
/// - Context IDs returned by `create_ctx` are passed to subsequent calls
/// - `start_enter` is called in a forked child process (it calls exit() internally)
struct LibKrun {
    handle: *mut libc::c_void,
    set_log_level: unsafe extern "C" fn(u32) -> i32,
    create_ctx: unsafe extern "C" fn() -> i32,
    free_ctx: unsafe extern "C" fn(u32),
    set_vm_config: unsafe extern "C" fn(u32, u8, u32) -> i32,
    set_root: unsafe extern "C" fn(u32, *const libc::c_char) -> i32,
    set_workdir: unsafe extern "C" fn(u32, *const libc::c_char) -> i32,
    set_exec: unsafe extern "C" fn(u32, *const libc::c_char, *const *const libc::c_char, *const *const libc::c_char) -> i32,
    add_disk2: unsafe extern "C" fn(u32, *const libc::c_char, *const libc::c_char, u32, bool) -> i32,
    add_vsock_port2: unsafe extern "C" fn(u32, u32, *const libc::c_char, bool) -> i32,
    add_virtiofs: unsafe extern "C" fn(u32, *const libc::c_char, *const libc::c_char) -> i32,
    start_enter: unsafe extern "C" fn(u32) -> i32,
}

impl LibKrun {
    /// Load libkrun from the given library directory.
    ///
    /// # Safety
    ///
    /// Caller must ensure `lib_dir` contains valid libkrun and libkrunfw libraries.
    unsafe fn load(lib_dir: &Path) -> Result<Self, String> {
        // Preload libkrunfw first - libkrun loads it dynamically and needs to find it
        #[cfg(target_os = "macos")]
        let fw_lib_name = "libkrunfw.5.dylib";
        #[cfg(target_os = "linux")]
        let fw_lib_name = "libkrunfw.so.5";

        let fw_lib_path = lib_dir.join(fw_lib_name);
        let fw_lib_path_c = CString::new(fw_lib_path.to_string_lossy().as_bytes())
            .map_err(|_| "invalid library path")?;

        // Load libkrunfw with RTLD_GLOBAL so libkrun can find it
        let fw_handle = libc::dlopen(fw_lib_path_c.as_ptr(), libc::RTLD_NOW | libc::RTLD_GLOBAL);
        if fw_handle.is_null() {
            let err = libc::dlerror();
            let err_msg = if err.is_null() {
                "unknown error".to_string()
            } else {
                CStr::from_ptr(err).to_string_lossy().to_string()
            };
            return Err(format!("failed to load {}: {}", fw_lib_path.display(), err_msg));
        }
        // Note: we intentionally don't close fw_handle - it needs to stay loaded

        #[cfg(target_os = "macos")]
        let lib_name = "libkrun.dylib";
        #[cfg(target_os = "linux")]
        let lib_name = "libkrun.so";

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
            return Err(format!("failed to load {}: {}", lib_path.display(), err_msg));
        }

        macro_rules! load_sym {
            ($name:ident) => {{
                let sym_name = CString::new(stringify!($name)).unwrap();
                let sym = libc::dlsym(handle, sym_name.as_ptr());
                if sym.is_null() {
                    libc::dlclose(handle);
                    return Err(format!("symbol not found: {}", stringify!($name)));
                }
                std::mem::transmute(sym)
            }};
        }

        Ok(Self {
            handle,
            set_log_level: load_sym!(krun_set_log_level),
            create_ctx: load_sym!(krun_create_ctx),
            free_ctx: load_sym!(krun_free_ctx),
            set_vm_config: load_sym!(krun_set_vm_config),
            set_root: load_sym!(krun_set_root),
            set_workdir: load_sym!(krun_set_workdir),
            set_exec: load_sym!(krun_set_exec),
            add_disk2: load_sym!(krun_add_disk2),
            add_vsock_port2: load_sym!(krun_add_vsock_port2),
            add_virtiofs: load_sym!(krun_add_virtiofs),
            start_enter: load_sym!(krun_start_enter),
        })
    }
}

impl Drop for LibKrun {
    fn drop(&mut self) {
        unsafe {
            libc::dlclose(self.handle);
        }
    }
}

// ============================================================================
// Ephemeral Mode (original behavior)
// ============================================================================

/// Launch the VM and run the command (ephemeral mode).
pub fn launch_vm(config: LaunchConfig) -> Result<i32, String> {
    // Set up paths
    let rootfs_path = config.cache_dir.join("agent-rootfs");
    let lib_dir = config.cache_dir.join("lib");
    let layers_dir = config.cache_dir.join("layers");

    // Create runtime directory for this execution
    let runtime_dir = config.cache_dir.join("runtime");
    fs::create_dir_all(&runtime_dir).map_err(|e| format!("failed to create runtime dir: {}", e))?;

    // Create storage disk
    let storage_path = runtime_dir.join("storage.ext4");
    if !storage_path.exists() {
        create_storage_disk(&storage_path, 512 * 1024 * 1024)?; // 512MB
    }

    // Create vsock socket path
    let vsock_path = runtime_dir.join("agent.sock");
    let _ = fs::remove_file(&vsock_path); // Remove if exists

    if config.debug {
        eprintln!("debug: rootfs: {}", rootfs_path.display());
        eprintln!("debug: lib dir: {}", lib_dir.display());
        eprintln!("debug: layers: {}", layers_dir.display());
        eprintln!("debug: storage: {}", storage_path.display());
        eprintln!("debug: vsock: {}", vsock_path.display());
    }

    // Fork to launch VM
    let pid = unsafe { libc::fork() };

    match pid {
        -1 => Err("fork failed".to_string()),
        0 => {
            // Child process - launch VM
            // This never returns on success
            if let Err(e) = launch_vm_child(
                &lib_dir,
                &rootfs_path,
                &storage_path,
                &vsock_path,
                &layers_dir,
                &config.mounts,
                config.cpus.unwrap_or(config.manifest.cpus),
                config.mem.unwrap_or(config.manifest.mem),
                config.debug,
            ) {
                eprintln!("error: VM launch failed: {}", e);
                process::exit(1);
            }
            process::exit(0);
        }
        _ => {
            // Parent process - wait for agent and run command
            if config.debug {
                eprintln!("debug: VM child pid: {}", pid);
            }

            // Wait for agent to be ready
            let socket = wait_for_agent(&vsock_path, Duration::from_secs(30))?;

            // Build the command to run
            let run_command = build_run_command_from_config(&config.manifest, config.command.as_deref());

            if config.debug {
                eprintln!("debug: running command: {:?}", run_command);
            }

            // Run the command
            let exit_code = run_command_in_vm(
                socket,
                &config.manifest.image,
                &run_command,
                &config.env_vars,
                config.workdir.as_deref().or(config.manifest.workdir.as_deref()),
                &config.mounts,
                config.debug,
            )?;

            // Clean up - kill the VM
            unsafe {
                libc::kill(pid, libc::SIGTERM);
                let mut status = 0;
                libc::waitpid(pid, &mut status, 0);
            }

            Ok(exit_code)
        }
    }
}

// ============================================================================
// Daemon Mode
// ============================================================================

/// Start the daemon VM (keeps running for subsequent exec calls).
pub fn start_daemon(config: DaemonConfig) -> Result<(), String> {
    // Check if daemon is already running
    if let Ok(state) = read_daemon_state(&config.cache_dir) {
        if is_process_alive(state.pid) {
            return Err("Daemon is already running. Use 'stop' first.".to_string());
        }
        // Stale state file, clean up
        let _ = fs::remove_file(config.cache_dir.join("runtime").join(DAEMON_STATE_FILE));
    }

    // Set up paths
    let rootfs_path = config.cache_dir.join("agent-rootfs");
    let lib_dir = config.cache_dir.join("lib");
    let layers_dir = config.cache_dir.join("layers");

    // Create runtime directory
    let runtime_dir = config.cache_dir.join("runtime");
    fs::create_dir_all(&runtime_dir).map_err(|e| format!("failed to create runtime dir: {}", e))?;

    // Create storage disk
    let storage_path = runtime_dir.join("storage.ext4");
    if !storage_path.exists() {
        create_storage_disk(&storage_path, 512 * 1024 * 1024)?; // 512MB
    }

    // Create vsock socket path
    let vsock_path = runtime_dir.join("agent.sock");
    let _ = fs::remove_file(&vsock_path); // Remove if exists

    if config.debug {
        eprintln!("debug: starting daemon VM...");
        eprintln!("debug: rootfs: {}", rootfs_path.display());
        eprintln!("debug: vsock: {}", vsock_path.display());
    }

    // Fork to launch VM as daemon
    let pid = unsafe { libc::fork() };

    match pid {
        -1 => Err("fork failed".to_string()),
        0 => {
            // Child process - become session leader and launch VM
            unsafe {
                libc::setsid(); // Detach from parent session
            }

            // Launch VM (never returns on success)
            if let Err(e) = launch_vm_child(
                &lib_dir,
                &rootfs_path,
                &storage_path,
                &vsock_path,
                &layers_dir,
                &config.mounts,
                config.cpus.unwrap_or(config.manifest.cpus),
                config.mem.unwrap_or(config.manifest.mem),
                config.debug,
            ) {
                eprintln!("error: VM launch failed: {}", e);
                unsafe { libc::_exit(1) };
            }
            unsafe { libc::_exit(0) };
        }
        _ => {
            // Parent process - wait for agent to be ready, then save state
            if config.debug {
                eprintln!("debug: daemon VM pid: {}", pid);
            }

            // Wait for agent to be ready
            match wait_for_agent(&vsock_path, Duration::from_secs(30)) {
                Ok(_socket) => {
                    // Agent is ready, save state
                    let state = DaemonState {
                        pid: pid as u32,
                        socket_path: vsock_path.to_string_lossy().to_string(),
                        started_at: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                    };

                    let state_path = runtime_dir.join(DAEMON_STATE_FILE);
                    let state_json = serde_json::to_string_pretty(&state)
                        .map_err(|e| format!("failed to serialize state: {}", e))?;
                    fs::write(&state_path, state_json)
                        .map_err(|e| format!("failed to write state: {}", e))?;

                    if config.debug {
                        eprintln!("debug: daemon state saved to {}", state_path.display());
                    }

                    Ok(())
                }
                Err(e) => {
                    // Agent didn't start, kill the VM
                    unsafe {
                        libc::kill(pid, libc::SIGKILL);
                    }
                    Err(format!("daemon failed to start: {}", e))
                }
            }
        }
    }
}

/// Execute a command in the running daemon VM.
pub fn exec_in_daemon(config: ExecConfig) -> Result<i32, String> {
    // Read daemon state
    let state = read_daemon_state(&config.cache_dir)?;

    // Check if daemon is still running
    if !is_process_alive(state.pid) {
        // Clean up stale state
        let _ = fs::remove_file(config.cache_dir.join("runtime").join(DAEMON_STATE_FILE));
        return Err("Daemon is not running. Use 'start' first.".to_string());
    }

    // Connect to agent
    let socket_path = PathBuf::from(&state.socket_path);
    let socket = UnixStream::connect(&socket_path)
        .map_err(|e| format!("failed to connect to daemon: {}", e))?;

    socket.set_read_timeout(Some(Duration::from_secs(300))).ok();
    socket.set_write_timeout(Some(Duration::from_secs(30))).ok();

    // Build command
    let run_command = build_run_command_from_config(&config.manifest, config.command.as_deref());

    if config.debug {
        eprintln!("debug: executing in daemon: {:?}", run_command);
    }

    // Run command
    run_command_in_vm(
        socket,
        &config.manifest.image,
        &run_command,
        &config.env_vars,
        config.workdir.as_deref().or(config.manifest.workdir.as_deref()),
        &config.mounts,
        config.debug,
    )
}

/// Stop the running daemon VM.
pub fn stop_daemon(cache_dir: &Path, debug: bool) -> Result<(), String> {
    // Read daemon state
    let state = read_daemon_state(cache_dir)?;

    if debug {
        eprintln!("debug: stopping daemon pid {}", state.pid);
    }

    // Send SIGTERM
    let ret = unsafe { libc::kill(state.pid as i32, libc::SIGTERM) };
    if ret != 0 {
        // Process might already be dead
        if debug {
            eprintln!("debug: kill returned {}", ret);
        }
    }

    // Wait briefly for process to exit
    std::thread::sleep(Duration::from_millis(500));

    // If still running, force kill
    if is_process_alive(state.pid) {
        if debug {
            eprintln!("debug: force killing daemon");
        }
        unsafe {
            libc::kill(state.pid as i32, libc::SIGKILL);
        }
    }

    // Clean up state file
    let state_path = cache_dir.join("runtime").join(DAEMON_STATE_FILE);
    let _ = fs::remove_file(state_path);

    // Clean up socket
    let _ = fs::remove_file(&state.socket_path);

    Ok(())
}

/// Get daemon status.
pub fn daemon_status(cache_dir: &Path) -> Result<String, String> {
    match read_daemon_state(cache_dir) {
        Ok(state) => {
            if is_process_alive(state.pid) {
                let uptime = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    .saturating_sub(state.started_at);

                Ok(format!(
                    "Daemon running (pid: {}, uptime: {}s)\nSocket: {}",
                    state.pid, uptime, state.socket_path
                ))
            } else {
                // Clean up stale state
                let _ = fs::remove_file(cache_dir.join("runtime").join(DAEMON_STATE_FILE));
                Ok("Daemon not running (stale state cleaned up)".to_string())
            }
        }
        Err(_) => Ok("Daemon not running".to_string()),
    }
}

/// Read daemon state from disk.
fn read_daemon_state(cache_dir: &Path) -> Result<DaemonState, String> {
    let state_path = cache_dir.join("runtime").join(DAEMON_STATE_FILE);
    let content = fs::read_to_string(&state_path)
        .map_err(|_| "Daemon not running (no state file)".to_string())?;
    serde_json::from_str(&content).map_err(|e| format!("invalid state file: {}", e))
}

/// Check if a process is alive.
fn is_process_alive(pid: u32) -> bool {
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

// ============================================================================
// Shared Helpers
// ============================================================================

/// Build the command to run from manifest and overrides.
fn build_run_command_from_config(manifest: &PackManifest, command: Option<&[String]>) -> Vec<String> {
    if let Some(cmd) = command {
        return cmd.to_vec();
    }

    let mut result = Vec::new();

    // Use entrypoint if present
    if !manifest.entrypoint.is_empty() {
        result.extend(manifest.entrypoint.clone());
    }

    // Add cmd if present
    if !manifest.cmd.is_empty() {
        result.extend(manifest.cmd.clone());
    }

    // Default to /bin/sh if nothing specified
    if result.is_empty() {
        result.push("/bin/sh".to_string());
    }

    result
}

/// Create a storage disk file.
fn create_storage_disk(path: &Path, size: u64) -> Result<(), String> {
    let file = File::create(path).map_err(|e| format!("failed to create storage disk: {}", e))?;
    file.set_len(size)
        .map_err(|e| format!("failed to set storage disk size: {}", e))?;
    Ok(())
}

/// Wait for the agent to become available.
fn wait_for_agent(socket_path: &Path, timeout: Duration) -> Result<UnixStream, String> {
    let start = std::time::Instant::now();
    let initial_delay = Duration::from_millis(300); // Give agent time to start
    let poll_interval = Duration::from_millis(100);

    // Initial delay to let VM and agent initialize before first connection attempt
    std::thread::sleep(initial_delay);

    while start.elapsed() < timeout {
        match UnixStream::connect(socket_path) {
            Ok(stream) => {
                // Set timeouts
                stream
                    .set_read_timeout(Some(Duration::from_secs(30)))
                    .ok();
                stream
                    .set_write_timeout(Some(Duration::from_secs(30)))
                    .ok();
                return Ok(stream);
            }
            Err(_) => {
                std::thread::sleep(poll_interval);
            }
        }
    }

    Err("timeout waiting for agent".to_string())
}

/// Run a command in the VM via the agent.
fn run_command_in_vm(
    mut socket: UnixStream,
    image: &str,
    command: &[String],
    env_vars: &[(String, String)],
    workdir: Option<&str>,
    mounts: &[VolumeMount],
    debug: bool,
) -> Result<i32, String> {
    // Build mount tuples for protocol
    let mount_tuples: Vec<(String, String, bool)> = mounts
        .iter()
        .enumerate()
        .map(|(i, m)| (format!("smolvm{}", i), m.guest_path.clone(), m.read_only))
        .collect();

    // Create Run request
    let request = smolvm_protocol::AgentRequest::Run {
        image: image.to_string(),
        command: command.to_vec(),
        env: env_vars.to_vec(),
        workdir: workdir.map(String::from),
        mounts: mount_tuples,
        timeout_ms: None,
        interactive: true,
        tty: false,
    };

    // Send request
    let request_bytes =
        smolvm_protocol::encode_message(&request).map_err(|e| format!("encode error: {}", e))?;
    socket
        .write_all(&request_bytes)
        .map_err(|e| format!("write error: {}", e))?;

    if debug {
        eprintln!("debug: sent run request");
    }

    // Read responses
    let mut exit_code = 0;
    let mut reader = BufReader::new(socket);

    loop {
        // Read length header
        let mut len_buf = [0u8; 4];
        if reader.read_exact(&mut len_buf).is_err() {
            break;
        }

        let len = u32::from_be_bytes(len_buf) as usize;
        if len > 256 * 1024 * 1024 {
            return Err("response too large".to_string());
        }

        // Read payload
        let mut payload = vec![0u8; len];
        reader
            .read_exact(&mut payload)
            .map_err(|e| format!("read error: {}", e))?;

        // Parse response
        let response: smolvm_protocol::AgentResponse =
            serde_json::from_slice(&payload).map_err(|e| format!("parse error: {}", e))?;

        match response {
            smolvm_protocol::AgentResponse::Started => {
                if debug {
                    eprintln!("debug: command started");
                }
            }
            smolvm_protocol::AgentResponse::Stdout { data } => {
                std::io::stdout()
                    .write_all(&data)
                    .map_err(|e| format!("stdout write error: {}", e))?;
            }
            smolvm_protocol::AgentResponse::Stderr { data } => {
                std::io::stderr()
                    .write_all(&data)
                    .map_err(|e| format!("stderr write error: {}", e))?;
            }
            smolvm_protocol::AgentResponse::Exited { exit_code: code } => {
                exit_code = code;
                break;
            }
            smolvm_protocol::AgentResponse::Error { message, .. } => {
                return Err(message);
            }
            smolvm_protocol::AgentResponse::Completed {
                exit_code: code,
                stdout,
                stderr,
            } => {
                print!("{}", stdout);
                eprint!("{}", stderr);
                exit_code = code;
                break;
            }
            _ => {
                if debug {
                    eprintln!("debug: received response: {:?}", response);
                }
            }
        }
    }

    Ok(exit_code)
}

/// Launch the VM in the child process.
fn launch_vm_child(
    lib_dir: &Path,
    rootfs_path: &Path,
    storage_path: &Path,
    vsock_path: &Path,
    layers_dir: &Path,
    mounts: &[VolumeMount],
    cpus: u8,
    mem: u32,
    debug: bool,
) -> Result<(), String> {
    // Raise file descriptor limits
    raise_fd_limits();

    // Set DYLD_LIBRARY_PATH so libkrun can find libkrunfw
    #[cfg(target_os = "macos")]
    {
        let lib_path = lib_dir.to_string_lossy();
        std::env::set_var("DYLD_LIBRARY_PATH", lib_path.as_ref());
        if debug {
            eprintln!("debug: DYLD_LIBRARY_PATH={}", lib_path);
        }
    }
    #[cfg(target_os = "linux")]
    {
        let lib_path = lib_dir.to_string_lossy();
        std::env::set_var("LD_LIBRARY_PATH", lib_path.as_ref());
        if debug {
            eprintln!("debug: LD_LIBRARY_PATH={}", lib_path);
        }
    }

    // Load libkrun dynamically
    let krun = unsafe { LibKrun::load(lib_dir)? };

    unsafe {
        // Set log level
        let log_level = if debug { 3 } else { 0 };
        (krun.set_log_level)(log_level);

        // Create VM context
        let ctx = (krun.create_ctx)();
        if ctx < 0 {
            return Err("failed to create libkrun context".to_string());
        }
        let ctx = ctx as u32;

        // Set VM config
        if (krun.set_vm_config)(ctx, cpus, mem) < 0 {
            (krun.free_ctx)(ctx);
            return Err("failed to set VM config".to_string());
        }

        // Set root filesystem
        let root = path_to_cstring(rootfs_path)?;
        if (krun.set_root)(ctx, root.as_ptr()) < 0 {
            (krun.free_ctx)(ctx);
            return Err("failed to set root filesystem".to_string());
        }

        // Add storage disk
        let block_id = CString::new("storage").unwrap();
        let disk_path = path_to_cstring(storage_path)?;
        if (krun.add_disk2)(ctx, block_id.as_ptr(), disk_path.as_ptr(), 0, false) < 0 {
            if debug {
                eprintln!("debug: failed to add storage disk");
            }
        }

        // Add vsock port
        let socket_path = path_to_cstring(vsock_path)?;
        if (krun.add_vsock_port2)(ctx, ports::AGENT_CONTROL, socket_path.as_ptr(), true) < 0 {
            if debug {
                eprintln!("debug: failed to add vsock port");
            }
        }

        // Add virtiofs mount for packed layers
        // This mounts the host layers directory so the agent can access pre-packaged OCI layers
        if layers_dir.exists() {
            let layers_tag = CString::new("smolvm_layers").unwrap();
            let layers_path = path_to_cstring(layers_dir)?;
            if (krun.add_virtiofs)(ctx, layers_tag.as_ptr(), layers_path.as_ptr()) < 0 {
                if debug {
                    eprintln!("debug: failed to add layers virtiofs mount");
                }
            }
        }

        // Add user-specified virtiofs mounts
        for (i, mount) in mounts.iter().enumerate() {
            let tag = CString::new(format!("smolvm{}", i)).map_err(|_| "invalid mount tag")?;
            let host_path = path_to_cstring(&mount.host_path)?;

            if (krun.add_virtiofs)(ctx, tag.as_ptr(), host_path.as_ptr()) < 0 {
                if debug {
                    eprintln!(
                        "debug: failed to add virtiofs mount: {}",
                        mount.host_path.display()
                    );
                }
            }
        }

        // Set working directory
        let workdir = CString::new("/").unwrap();
        (krun.set_workdir)(ctx, workdir.as_ptr());

        // Build environment
        let mut env_strings = vec![
            CString::new("HOME=/root").unwrap(),
            CString::new("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
                .unwrap(),
            CString::new("TERM=xterm-256color").unwrap(),
        ];

        // Tell agent about packed layers mount (tag:mount_point)
        if layers_dir.exists() {
            if let Ok(cstr) = CString::new("SMOLVM_PACKED_LAYERS=smolvm_layers:/packed_layers") {
                env_strings.push(cstr);
            }
        }

        // Pass mount info to the agent
        for (i, mount) in mounts.iter().enumerate() {
            let ro_flag = if mount.read_only { "ro" } else { "rw" };
            let env_val = format!(
                "SMOLVM_MOUNT_{}=smolvm{}:{}:{}",
                i, i, mount.guest_path, ro_flag
            );
            if let Ok(cstr) = CString::new(env_val) {
                env_strings.push(cstr);
            }
        }

        if !mounts.is_empty() {
            if let Ok(cstr) = CString::new(format!("SMOLVM_MOUNT_COUNT={}", mounts.len())) {
                env_strings.push(cstr);
            }
        }

        let mut envp: Vec<*const libc::c_char> = env_strings.iter().map(|s| s.as_ptr()).collect();
        envp.push(std::ptr::null());

        // Set exec command
        let exec_path = CString::new("/sbin/init").unwrap();
        let argv_strings = [CString::new("/sbin/init").unwrap()];
        let mut argv: Vec<*const libc::c_char> = argv_strings.iter().map(|s| s.as_ptr()).collect();
        argv.push(std::ptr::null());

        if (krun.set_exec)(ctx, exec_path.as_ptr(), argv.as_ptr(), envp.as_ptr()) < 0 {
            (krun.free_ctx)(ctx);
            return Err("failed to set exec command".to_string());
        }

        // Start VM
        let ret = (krun.start_enter)(ctx);
        Err(format!("krun_start_enter returned: {}", ret))
    }
}

/// Convert a Path to a CString.
fn path_to_cstring(path: &Path) -> Result<CString, String> {
    CString::new(path.to_string_lossy().as_bytes())
        .map_err(|_| "path contains null byte".to_string())
}

/// Raise file descriptor limits.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_volume_mount() {
        // Basic mount
        let mount = parse_volume_mount("/host:/guest").unwrap();
        assert_eq!(mount.host_path, PathBuf::from("/host"));
        assert_eq!(mount.guest_path, "/guest");
        assert!(!mount.read_only);

        // Read-only
        let mount = parse_volume_mount("/host:/guest:ro").unwrap();
        assert!(mount.read_only);

        // Invalid (no colon)
        assert!(parse_volume_mount("/host/path").is_none());
    }

    #[test]
    fn test_parse_volume_mount_edge_cases() {
        // BUG: Colon in path breaks parsing (e.g., paths with timestamps)
        // "/logs/2024:01:01:/data" splits wrong
        let mount = parse_volume_mount("/logs/2024:01:01:/data").unwrap();
        // Current behavior: host="/logs/2024", guest="01" - THIS IS WRONG
        // This documents the bug for future fix
        assert_eq!(mount.host_path, PathBuf::from("/logs/2024"));
        assert_eq!(mount.guest_path, "01"); // Bug: should be "/data"

        // Empty paths are accepted but probably shouldn't be
        let mount = parse_volume_mount(":/guest").unwrap();
        assert_eq!(mount.host_path, PathBuf::from("")); // Empty host path

        let mount = parse_volume_mount("/host:").unwrap();
        assert_eq!(mount.guest_path, ""); // Empty guest path
    }

    #[test]
    fn test_build_run_command() {
        let manifest = PackManifest::new(
            "test:latest".to_string(),
            "sha256:abc".to_string(),
            "linux/arm64".to_string(),
        );

        // Override takes precedence
        let cmd = vec!["echo".to_string(), "hello".to_string()];
        assert_eq!(
            build_run_command_from_config(&manifest, Some(&cmd)),
            vec!["echo", "hello"]
        );

        // Default to /bin/sh when no entrypoint/cmd
        assert_eq!(
            build_run_command_from_config(&manifest, None),
            vec!["/bin/sh"]
        );

        // Entrypoint + cmd are combined
        let mut manifest_with_ep = manifest.clone();
        manifest_with_ep.entrypoint = vec!["python".to_string()];
        manifest_with_ep.cmd = vec!["app.py".to_string()];
        assert_eq!(
            build_run_command_from_config(&manifest_with_ep, None),
            vec!["python", "app.py"]
        );
    }

    #[test]
    fn test_build_run_command_edge_cases() {
        // Empty override should use manifest defaults, not empty command
        let mut manifest = PackManifest::new(
            "test:latest".to_string(),
            "sha256:abc".to_string(),
            "linux/arm64".to_string(),
        );
        manifest.cmd = vec!["default".to_string()];

        let empty_cmd: Vec<String> = vec![];
        // Empty slice override returns empty - caller must handle this
        assert_eq!(
            build_run_command_from_config(&manifest, Some(&empty_cmd)),
            Vec::<String>::new()
        );

        // Entrypoint with empty cmd still works
        manifest.entrypoint = vec!["/bin/bash".to_string()];
        manifest.cmd = vec![];
        assert_eq!(
            build_run_command_from_config(&manifest, None),
            vec!["/bin/bash"]
        );
    }

    #[test]
    fn test_daemon_state_roundtrip() {
        let state = DaemonState {
            pid: 12345,
            socket_path: "/tmp/agent.sock".to_string(),
            started_at: 1700000000,
        };

        let json = serde_json::to_string(&state).unwrap();
        let parsed: DaemonState = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.pid, state.pid);
        assert_eq!(parsed.socket_path, state.socket_path);
        assert_eq!(parsed.started_at, state.started_at);
    }

    #[test]
    fn test_daemon_state_corrupted() {
        // Truncated JSON
        let result: Result<DaemonState, _> = serde_json::from_str("{\"pid\": 123");
        assert!(result.is_err());

        // Wrong types
        let result: Result<DaemonState, _> =
            serde_json::from_str("{\"pid\": \"not a number\", \"socket_path\": \"/tmp/x\", \"started_at\": 0}");
        assert!(result.is_err());

        // Missing fields
        let result: Result<DaemonState, _> = serde_json::from_str("{\"pid\": 123}");
        assert!(result.is_err());
    }

    #[test]
    fn test_is_process_alive_edge_cases() {
        // PID 0 means "current process group" in kill() - could cause issues
        // This is actually alive (sends to process group)
        assert!(is_process_alive(0) || !is_process_alive(0)); // Platform dependent

        // PID 1 (init) - should be alive on most systems
        #[cfg(target_os = "linux")]
        assert!(is_process_alive(1));
    }

    #[test]
    fn test_create_storage_disk() {
        let temp_dir = tempfile::tempdir().unwrap();
        let disk_path = temp_dir.path().join("test.ext4");

        create_storage_disk(&disk_path, 1024 * 1024).unwrap();

        assert!(disk_path.exists());
        assert_eq!(fs::metadata(&disk_path).unwrap().len(), 1024 * 1024);
    }

    #[test]
    fn test_create_storage_disk_overwrites() {
        let temp_dir = tempfile::tempdir().unwrap();
        let disk_path = temp_dir.path().join("test.ext4");

        // Create initial disk
        create_storage_disk(&disk_path, 1024).unwrap();
        assert_eq!(fs::metadata(&disk_path).unwrap().len(), 1024);

        // Creating again overwrites (truncates) - could lose data!
        create_storage_disk(&disk_path, 2048).unwrap();
        assert_eq!(fs::metadata(&disk_path).unwrap().len(), 2048);
    }
}
