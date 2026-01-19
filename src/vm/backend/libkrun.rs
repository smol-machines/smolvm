//! libkrun backend implementation.
//!
//! This module provides VM creation and management using libkrun,
//! which uses Hypervisor.framework on macOS and KVM on Linux.

use std::ffi::CString;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::platform::{self, VmExecutor};
use crate::vm::config::{NetworkPolicy, RootfsSource, VmConfig};
use crate::vm::state::{ExitReason, VmState};
use crate::vm::{VmBackend, VmHandle, VmId};

// FFI bindings to libkrun
// Linking is handled by build.rs
// Note: Some functions are declared but not yet used - allow dead_code for FFI completeness
#[allow(dead_code)]
extern "C" {
    // Logging
    fn krun_set_log_level(level: u32) -> i32;

    // Context management
    fn krun_create_ctx() -> i32;
    fn krun_free_ctx(ctx: u32);

    // VM configuration
    fn krun_set_vm_config(ctx: u32, num_vcpus: u8, ram_mib: u32) -> i32;

    // Root filesystem
    fn krun_set_root(ctx: u32, root_path: *const libc::c_char) -> i32;

    // Working directory
    fn krun_set_workdir(ctx: u32, workdir: *const libc::c_char) -> i32;

    // Execution
    fn krun_set_exec(
        ctx: u32,
        exec_path: *const libc::c_char,
        argv: *const *const libc::c_char,
        envp: *const *const libc::c_char,
    ) -> i32;

    // Filesystem sharing (virtiofs)
    fn krun_add_virtiofs(ctx: u32, tag: *const libc::c_char, path: *const libc::c_char) -> i32;

    // Networking
    fn krun_set_port_map(ctx: u32, port_map: *const *const libc::c_char) -> i32;

    // Block devices (virtio-blk)
    // format: 0 = Raw, 1 = Qcow2
    fn krun_add_disk2(
        ctx: u32,
        block_id: *const libc::c_char,
        disk_path: *const libc::c_char,
        disk_format: u32,
        read_only: bool,
    ) -> i32;

    // Disk-based root filesystem (boots from virtiofs then switches to block device)
    fn krun_set_root_disk_remount(
        ctx: u32,
        device: *const libc::c_char,
        fstype: *const libc::c_char,
        options: *const libc::c_char,
    ) -> i32;

    // vsock ports for host-guest communication
    fn krun_add_vsock_port(ctx: u32, port: u32, filepath: *const libc::c_char) -> i32;
    fn krun_add_vsock_port2(
        ctx: u32,
        port: u32,
        filepath: *const libc::c_char,
        listen: bool,
    ) -> i32;

    // Console output redirection
    fn krun_set_console_output(ctx: u32, filepath: *const libc::c_char) -> i32;

    // Console setup - adds virtio console connected to given file descriptors
    fn krun_add_virtio_console_default(
        ctx: u32,
        input_fd: libc::c_int,
        output_fd: libc::c_int,
        error_fd: libc::c_int,
    ) -> i32;

    // Serial console - legacy serial device
    fn krun_add_serial_console_default(
        ctx: u32,
        input_fd: libc::c_int,
        output_fd: libc::c_int,
    ) -> i32;

    // Set kernel console parameter (e.g., "hvc0" for virtio console)
    fn krun_set_kernel_console(ctx: u32, console: *const libc::c_char) -> i32;

    // Start VM (blocks until exit)
    fn krun_start_enter(ctx: u32) -> i32;
}

/// libkrun backend for VM creation.
pub struct LibkrunBackend {
    /// Whether libkrun appears to be available.
    available: bool,
}

impl LibkrunBackend {
    /// Create a new libkrun backend.
    pub fn new() -> Result<Self> {
        // For now, assume libkrun is available if we're on a supported platform.
        // A more robust check would try to load the library dynamically.
        Ok(Self { available: true })
    }
}

impl VmBackend for LibkrunBackend {
    fn name(&self) -> &'static str {
        "libkrun"
    }

    fn is_available(&self) -> bool {
        self.available
    }

    fn create(&self, config: VmConfig) -> Result<Box<dyn VmHandle>> {
        LibkrunVm::create(config).map(|vm| Box::new(vm) as Box<dyn VmHandle>)
    }
}

/// A VM instance managed by libkrun.
pub struct LibkrunVm {
    id: VmId,
    state: VmState,
    exit_reason: Option<ExitReason>,
    /// Child process running the VM.
    child: Option<crate::process::ChildProcess>,
}

impl LibkrunVm {
    /// Create and start a VM with the given configuration.
    fn create(config: VmConfig) -> Result<Self> {
        let id = config.id.clone();

        // Resolve rootfs to a path
        let rootfs_path = resolve_rootfs(&config.rootfs)?;

        // Inject init.krun into rootfs (required by libkrunfw kernel)
        inject_init_krun(&rootfs_path)?;

        // Setup DNS if network egress is enabled
        if let NetworkPolicy::Egress { dns } = &config.network {
            setup_dns(&rootfs_path, dns.map(|ip| ip.to_string()).as_deref())?;
        }

        let mut vm = Self {
            id,
            state: VmState::Created,
            exit_reason: None,
            child: None,
        };

        // Execute VM (this blocks until VM exits)
        vm.state = VmState::Booting;
        let result = vm.exec_vm(&rootfs_path, &config);

        match result {
            Ok(code) => {
                vm.state = VmState::Stopped;
                vm.exit_reason = Some(ExitReason::exited(code));
            }
            Err(e) => {
                vm.state = VmState::Failed {
                    reason: e.to_string(),
                };
                vm.exit_reason = Some(ExitReason::vm_crash(e.to_string()));
            }
        }

        Ok(vm)
    }

    /// Execute the VM using libkrun FFI.
    fn exec_vm(&mut self, rootfs_path: &Path, config: &VmConfig) -> Result<i32> {
        // Raise file descriptor limits (required by libkrun)
        set_rlimits();

        // Check if we're running in a real TTY (reserved for future TTY support)
        let _is_tty = unsafe { libc::isatty(libc::STDIN_FILENO) == 1 };

        unsafe {
            // Initialize libkrun logging (0 = off, 1 = error, 2 = warn, 3 = info, 4 = debug)
            // Use 0 (off) in production - smolvm has its own logging via tracing
            krun_set_log_level(0);

            // Create VM context
            let ctx = krun_create_ctx();
            if ctx < 0 {
                return Err(Error::vm_creation("failed to create libkrun context"));
            }
            let ctx = ctx as u32;

            // Set VM resources
            if krun_set_vm_config(ctx, config.resources.cpus, config.resources.memory_mib) < 0 {
                krun_free_ctx(ctx);
                return Err(Error::vm_creation("failed to set VM config"));
            }

            // Set root filesystem
            let root = path_to_cstring(rootfs_path)?;
            tracing::debug!("[libkrun] rootfs_path: {:?}", rootfs_path);
            tracing::debug!("[libkrun] root CString: {:?}", root);
            let ret = krun_set_root(ctx, root.as_ptr());
            tracing::debug!("[libkrun] krun_set_root returned: {}", ret);
            if ret < 0 {
                krun_free_ctx(ctx);
                return Err(Error::vm_creation("failed to set root filesystem"));
            }

            // Set empty port map (required by libkrun)
            let empty_ports: Vec<*const libc::c_char> = vec![std::ptr::null()];
            if krun_set_port_map(ctx, empty_ports.as_ptr()) < 0 {
                krun_free_ctx(ctx);
                return Err(Error::vm_creation("failed to set port map"));
            }

            // Note: libkrun's implicit console connects stdin/stdout/stderr automatically.
            // In libkrun 1.15.x, krun_add_virtio_console_default is not available.
            // Console output should work via the implicit console mechanism.

            // Set working directory if specified
            if let Some(ref wd) = config.workdir {
                let workdir = path_to_cstring(wd)?;
                if krun_set_workdir(ctx, workdir.as_ptr()) < 0 {
                    tracing::warn!(workdir = %wd.display(), "failed to set workdir");
                }
            }

            // Build environment with defaults
            let (envp, _env_cstrings) = build_env_args(&config.env, &self.id)?;

            // Build mounts list for wrapper script: (tag, guest_path)
            let mount_specs: Vec<(String, String)> = config
                .mounts
                .iter()
                .enumerate()
                .map(|(i, m)| {
                    (
                        format!("smolvm{}", i),
                        m.target.to_string_lossy().to_string(),
                    )
                })
                .collect();

            // Build exec command using platform-specific executor
            // On macOS, this wraps the command with a mount script for virtiofs
            // On Linux, the kernel handles virtiofs mounting automatically
            let executor = platform::vm_executor();
            let (exec_path, argv, _argv_cstrings) =
                executor.build_exec_command(&config.command, &mount_specs, rootfs_path)?;

            tracing::debug!("[libkrun] exec_path: {:?}", exec_path);
            tracing::debug!("[libkrun] command: {:?}", config.command);
            tracing::debug!("[libkrun] argv count (excluding null): {}", argv.len() - 1);
            tracing::debug!("[libkrun] argv_cstrings: {:?}", _argv_cstrings);

            let ret = krun_set_exec(ctx, exec_path.as_ptr(), argv.as_ptr(), envp.as_ptr());
            tracing::debug!("[libkrun] krun_set_exec returned: {}", ret);
            if ret < 0 {
                krun_free_ctx(ctx);
                return Err(Error::vm_creation("failed to set exec command"));
            }

            // Add virtiofs mounts for host directories
            for (i, mount) in config.mounts.iter().enumerate() {
                let tag = CString::new(format!("smolvm{}", i))
                    .map_err(|_| Error::mount("invalid mount tag"))?;
                let path = path_to_cstring(&mount.source)?;

                if krun_add_virtiofs(ctx, tag.as_ptr(), path.as_ptr()) < 0 {
                    tracing::warn!(
                        "failed to add virtiofs mount: {} -> {}",
                        mount.source.display(),
                        mount.target.display()
                    );
                }
            }

            // Add block devices
            for disk in &config.disks {
                let block_id = CString::new(disk.block_id.as_str())
                    .map_err(|_| Error::vm_creation("invalid block_id"))?;
                let disk_path = path_to_cstring(&disk.path)?;
                let format = disk.format as u32;

                if krun_add_disk2(
                    ctx,
                    block_id.as_ptr(),
                    disk_path.as_ptr(),
                    format,
                    disk.read_only,
                ) < 0
                {
                    tracing::warn!(
                        "failed to add disk: {} ({})",
                        disk.block_id,
                        disk.path.display()
                    );
                } else {
                    tracing::debug!(
                        block_id = %disk.block_id,
                        path = %disk.path.display(),
                        "added block device"
                    );
                }
            }

            // Add vsock ports
            for vsock in &config.vsock_ports {
                let socket_path = path_to_cstring(&vsock.socket_path)?;

                let ret = krun_add_vsock_port2(ctx, vsock.port, socket_path.as_ptr(), vsock.listen);
                if ret < 0 {
                    tracing::warn!(
                        "failed to add vsock port {}: {}",
                        vsock.port,
                        vsock.socket_path.display()
                    );
                } else {
                    tracing::debug!(
                        port = vsock.port,
                        socket = %vsock.socket_path.display(),
                        listen = vsock.listen,
                        "added vsock port"
                    );
                }
            }

            // Set console output if specified
            if let Some(ref log_path) = config.console_log {
                let console_path = path_to_cstring(log_path)?;
                if krun_set_console_output(ctx, console_path.as_ptr()) < 0 {
                    tracing::warn!("failed to set console output: {}", log_path.display());
                } else {
                    tracing::debug!(path = %log_path.display(), "console output enabled");
                }
            }

            // Update state to running
            self.state = VmState::Running;

            // Fork before starting VM because krun_start_enter calls exit() directly
            // The child runs the VM, parent waits and returns the exit code
            tracing::info!(vm_id = %self.id, "starting VM");

            let pid = libc::fork();
            if pid < 0 {
                return Err(Error::vm_creation("fork failed"));
            } else if pid == 0 {
                // Child process: run the VM
                // This will call exit() when the VM exits
                krun_start_enter(ctx);
                // If we get here, something went wrong
                libc::_exit(1);
            } else {
                // Parent process: store child process and wait
                self.child = Some(crate::process::ChildProcess::new(pid));

                let exit_code = self.child.as_mut().unwrap().wait();

                // Clear child reference after exit
                self.child = None;

                Ok(exit_code)
            }
        }
    }
}

/// Raise file descriptor limits (required by libkrun).
fn set_rlimits() {
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

impl VmHandle for LibkrunVm {
    fn id(&self) -> &VmId {
        &self.id
    }

    fn state(&self) -> VmState {
        self.state.clone()
    }

    fn wait(&mut self) -> Result<ExitReason> {
        // VM already exited since krun_start_enter blocks
        self.exit_reason
            .clone()
            .ok_or_else(|| Error::VmNotFound(self.id.0.clone()))
    }

    fn stop(&mut self) -> Result<()> {
        if let Some(ref mut child) = self.child {
            if child.is_running() {
                tracing::info!(pid = child.pid(), "stopping VM with SIGTERM");
                child.stop(crate::process::DEFAULT_STOP_TIMEOUT, true)?;
                self.state = VmState::Stopped;
            }
        }
        Ok(())
    }

    fn kill(&mut self) -> Result<()> {
        if let Some(ref child) = self.child {
            if crate::process::is_alive(child.pid()) {
                tracing::info!(pid = child.pid(), "killing VM with SIGKILL");
                crate::process::kill(child.pid());
            }
        }
        self.state = VmState::Stopped;
        Ok(())
    }
}

// Helper functions

/// Resolve a rootfs source to an actual path.
fn resolve_rootfs(source: &RootfsSource) -> Result<PathBuf> {
    match source {
        RootfsSource::Path { path } => {
            if path.exists() {
                Ok(path.clone())
            } else {
                Err(Error::RootfsNotFound { path: path.clone() })
            }
        }
    }
}

/// Setup DNS configuration in the rootfs.
fn setup_dns(rootfs: &Path, dns: Option<&str>) -> Result<()> {
    let resolv_path = rootfs.join("etc/resolv.conf");

    // Only write if etc directory exists
    if let Some(parent) = resolv_path.parent() {
        if parent.exists() {
            let content = format!("nameserver {}\n", dns.unwrap_or("1.1.1.1"));
            std::fs::write(&resolv_path, content)?;
            tracing::debug!("wrote DNS config to {:?}", resolv_path);
        }
    }

    Ok(())
}

/// Inject init.krun into the rootfs.
///
/// libkrunfw's kernel is built without initramfs support, so it expects
/// /init.krun to be present in the virtiofs root filesystem.
fn inject_init_krun(rootfs: &Path) -> Result<()> {
    let target = rootfs.join("init.krun");
    tracing::debug!("[libkrun] inject_init_krun: target = {:?}", target);

    // Check if init.krun already exists
    if target.exists() {
        tracing::debug!("[libkrun] init.krun already present in rootfs");
        tracing::debug!("init.krun already present in rootfs");
        return Ok(());
    }

    // Look for init.krun in standard locations
    let sources = [
        // User's local smolvm data directory (macOS: ~/Library/Application Support)
        dirs::data_local_dir().map(|d| d.join("smolvm/init.krun")),
        // XDG data home (Linux: ~/.local/share, works on macOS too)
        dirs::home_dir().map(|d| d.join(".local/share/smolvm/init.krun")),
        // System-wide location
        Some(PathBuf::from("/usr/local/share/smolvm/init.krun")),
        // Homebrew location
        Some(PathBuf::from("/opt/homebrew/share/smolvm/init.krun")),
    ];

    for source in sources.into_iter().flatten() {
        tracing::debug!("[libkrun] checking for init.krun at {:?}", source);
        if source.exists() {
            tracing::debug!(
                "[libkrun] found init.krun at {:?}, copying to {:?}",
                source,
                target
            );
            std::fs::copy(&source, &target).map_err(|e| {
                Error::vm_creation(format!("failed to copy init.krun to rootfs: {}", e))
            })?;
            // Make executable
            let perms = std::fs::Permissions::from_mode(0o755);
            std::fs::set_permissions(&target, perms)?;
            tracing::debug!("[libkrun] successfully injected init.krun");
            tracing::debug!("injected init.krun from {:?} to {:?}", source, target);
            return Ok(());
        }
    }

    Err(Error::vm_creation(
        "init.krun not found. Please install smolvm-init or build from source. \
         See https://github.com/smolvm/smolvm#init-krun for details.",
    ))
}

/// Convert a Path to a CString.
fn path_to_cstring(path: &Path) -> Result<CString> {
    CString::new(path.to_string_lossy().as_bytes())
        .map_err(|_| Error::vm_creation("path contains null byte"))
}

/// Build exec arguments for libkrun (test helper).
///
/// libkrun passes exec_path as KRUN_INIT env var, and argv is appended to the
/// kernel cmdline after " -- ". init.krun replaces argv[0] with KRUN_INIT.
/// Therefore, argv should NOT include the command name (argv[0]) - only the
/// arguments starting from argv[1].
///
/// Note: Production code uses `platform::vm_executor().build_exec_command()` instead.
#[cfg(test)]
fn build_exec_args(
    command: &Option<Vec<String>>,
) -> Result<(CString, Vec<*const libc::c_char>, Vec<CString>)> {
    let default_cmd = vec!["/bin/sh".to_string()];
    let cmd = command.as_ref().unwrap_or(&default_cmd);

    if cmd.is_empty() {
        return Err(Error::vm_creation("command cannot be empty"));
    }

    let exec_path =
        CString::new(cmd[0].as_str()).map_err(|_| Error::vm_creation("invalid command path"))?;

    // Do NOT include argv[0] - libkrun/init.krun handles it via KRUN_INIT.
    // Only pass arguments (cmd[1..]).
    let cstrings: Vec<CString> = cmd
        .iter()
        .skip(1) // Skip argv[0], it's passed via exec_path/KRUN_INIT
        .map(|s| CString::new(s.as_str()))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| Error::vm_creation("invalid command argument"))?;

    let mut argv: Vec<*const libc::c_char> = cstrings.iter().map(|s| s.as_ptr()).collect();
    argv.push(std::ptr::null());

    Ok((exec_path, argv, cstrings))
}

/// Build environment variables for libkrun.
fn build_env_args(
    env: &[(String, String)],
    vm_id: &VmId,
) -> Result<(Vec<*const libc::c_char>, Vec<CString>)> {
    let mut cstrings: Vec<CString> = Vec::new();

    // Add default environment variables
    cstrings.push(
        CString::new(format!("HOSTNAME={}", vm_id.as_str()))
            .map_err(|_| Error::vm_creation("invalid hostname"))?,
    );
    cstrings.push(CString::new("HOME=/root").map_err(|_| Error::vm_creation("invalid HOME"))?);
    cstrings.push(
        CString::new("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
            .map_err(|_| Error::vm_creation("invalid PATH"))?,
    );
    cstrings
        .push(CString::new("TERM=xterm-256color").map_err(|_| Error::vm_creation("invalid TERM"))?);

    // Add user-provided environment variables
    for (k, v) in env {
        cstrings.push(
            CString::new(format!("{}={}", k, v))
                .map_err(|_| Error::vm_creation("invalid environment variable"))?,
        );
    }

    let mut envp: Vec<*const libc::c_char> = cstrings.iter().map(|s| s.as_ptr()).collect();
    envp.push(std::ptr::null());

    Ok((envp, cstrings))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_exec_args_default() {
        let (exec_path, argv, _) = build_exec_args(&None).unwrap();
        assert_eq!(exec_path.to_str().unwrap(), "/bin/sh");
        // argv should NOT include argv[0] - only the arguments after it
        // For default "/bin/sh" with no args: argv = [null]
        assert_eq!(argv.len(), 1); // just [null]
    }

    #[test]
    fn test_build_exec_args_custom() {
        let cmd = Some(vec![
            "/bin/echo".to_string(),
            "hello".to_string(),
            "world".to_string(),
        ]);
        let (exec_path, argv, _) = build_exec_args(&cmd).unwrap();
        assert_eq!(exec_path.to_str().unwrap(), "/bin/echo");
        // argv should NOT include argv[0] - only ["hello", "world", null]
        assert_eq!(argv.len(), 3); // ["hello", "world", null]
    }

    #[test]
    fn test_build_exec_args_empty() {
        let cmd = Some(vec![]);
        let result = build_exec_args(&cmd);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_env_args() {
        let env = vec![
            ("FOO".to_string(), "bar".to_string()),
            ("BAZ".to_string(), "qux".to_string()),
        ];
        let vm_id = VmId::new("test-vm");
        let (envp, cstrings) = build_env_args(&env, &vm_id).unwrap();
        // 4 defaults (HOSTNAME, HOME, PATH, TERM) + 2 user vars + null
        assert_eq!(cstrings.len(), 6);
        assert_eq!(envp.len(), 7);
        assert_eq!(cstrings[0].to_str().unwrap(), "HOSTNAME=test-vm");
        assert_eq!(cstrings[1].to_str().unwrap(), "HOME=/root");
        assert!(cstrings[2].to_str().unwrap().starts_with("PATH="));
        assert!(cstrings[3].to_str().unwrap().starts_with("TERM="));
        assert_eq!(cstrings[4].to_str().unwrap(), "FOO=bar");
        assert_eq!(cstrings[5].to_str().unwrap(), "BAZ=qux");
    }

    #[test]
    fn test_build_env_args_empty() {
        let env: Vec<(String, String)> = vec![];
        let vm_id = VmId::new("test-vm");
        let (envp, cstrings) = build_env_args(&env, &vm_id).unwrap();
        // 4 defaults (HOSTNAME, HOME, PATH, TERM) + null
        assert_eq!(cstrings.len(), 4);
        assert_eq!(envp.len(), 5);
    }

    #[test]
    fn test_path_to_cstring() {
        let path = Path::new("/some/path");
        let cstring = path_to_cstring(path).unwrap();
        assert_eq!(cstring.to_str().unwrap(), "/some/path");
    }
}
