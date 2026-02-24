//! Agent VM lifecycle management.
//!
//! The AgentManager is responsible for starting and stopping the agent VM,
//! which runs the smolvm-agent for OCI image management and command execution.

use crate::error::{Error, Result};
use crate::process::{self, ChildProcess};
use crate::storage::{OverlayDisk, StorageDisk};
use parking_lot::Mutex;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::launcher::{self, launch_agent_vm};
use super::{HostMount, PortMapping, VmResources};

// ============================================================================
// Configuration Constants
// ============================================================================

/// Timeout for the agent to become ready after starting.
const AGENT_READY_TIMEOUT: Duration = Duration::from_secs(30);

// Re-use shared polling constants from process module.
use crate::process::{FAST_POLL_COUNT, FAST_POLL_INTERVAL};

/// Timeout for agent to stop gracefully before force kill.
/// Reduced from 5s - VMs typically exit within 100ms after shutdown signal.
const AGENT_STOP_TIMEOUT: Duration = Duration::from_secs(2);

/// Timeout when waiting for agent to stop.
const WAIT_FOR_STOP_TIMEOUT: Duration = Duration::from_secs(10);

/// State of the agent VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentState {
    /// Agent is not running.
    Stopped,
    /// Agent is starting up.
    Starting,
    /// Agent is running and ready.
    Running,
    /// Agent is shutting down.
    Stopping,
}

impl std::fmt::Display for AgentState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentState::Stopped => write!(f, "stopped"),
            AgentState::Starting => write!(f, "starting"),
            AgentState::Running => write!(f, "running"),
            AgentState::Stopping => write!(f, "stopping"),
        }
    }
}

/// Get the Docker config directory path.
///
/// Checks DOCKER_CONFIG environment variable first, then falls back to ~/.docker/
pub fn docker_config_dir() -> Option<PathBuf> {
    // Check DOCKER_CONFIG env var first
    if let Ok(docker_config) = std::env::var("DOCKER_CONFIG") {
        let path = PathBuf::from(docker_config);
        if path.exists() {
            return Some(path);
        }
        tracing::debug!(
            path = %path.display(),
            "DOCKER_CONFIG path does not exist"
        );
    }

    // Fall back to ~/.docker/
    if let Some(home) = dirs::home_dir() {
        let docker_dir = home.join(".docker");
        if docker_dir.exists() {
            return Some(docker_dir);
        }
    }

    None
}

/// Create a HostMount for Docker config directory.
///
/// Returns Some(mount) if the Docker config directory exists,
/// None otherwise.
pub fn docker_config_mount() -> Option<HostMount> {
    let docker_dir = docker_config_dir()?;

    tracing::info!(
        path = %docker_dir.display(),
        "mounting Docker config directory"
    );

    // Mount to /root/.docker which is where crane looks by default
    // Use read-only mount to prevent modification
    Some(HostMount {
        source: docker_dir,
        target: PathBuf::from("/root/.docker"),
        read_only: true,
    })
}

/// Internal state shared between threads.
struct AgentInner {
    state: AgentState,
    /// Child process (if running).
    child: Option<ChildProcess>,
    /// Currently configured mounts.
    mounts: Vec<HostMount>,
    /// Currently configured port mappings.
    ports: Vec<PortMapping>,
    /// Currently configured VM resources.
    resources: VmResources,
    /// If true, the agent has been detached and should not be stopped on drop.
    detached: bool,
}

/// Get the data directory for a named VM.
///
/// Returns `~/.cache/smolvm/vms/{name}/` (macOS) or equivalent on other platforms.
/// This is the canonical location for a VM's storage disk, overlay disk, and socket.
pub fn vm_data_dir(name: &str) -> PathBuf {
    dirs::cache_dir()
        .or_else(dirs::data_local_dir)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("smolvm")
        .join("vms")
        .join(name)
}

/// Agent VM manager.
///
/// Manages the lifecycle of the agent VM which handles OCI image operations
/// and command execution.
///
/// Each named VM gets its own agent with isolated paths:
/// - Anonymous: `~/.cache/smolvm/agent.sock`
/// - Named "foo": `~/.cache/smolvm/vms/foo/agent.sock`
pub struct AgentManager {
    /// Optional VM name (None for anonymous/default agent).
    name: Option<String>,
    /// Path to the agent rootfs.
    rootfs_path: PathBuf,
    /// Storage disk for OCI layers.
    storage_disk: StorageDisk,
    /// Overlay disk for persistent rootfs changes.
    overlay_disk: OverlayDisk,
    /// vsock socket path for control channel.
    vsock_socket: PathBuf,
    /// PID file path for tracking the VM process across CLI invocations.
    pid_file: PathBuf,
    /// Console log path (optional).
    console_log: Option<PathBuf>,
    /// Internal state.
    inner: Arc<Mutex<AgentInner>>,
}

impl AgentManager {
    /// Create a new agent manager for an anonymous (default) agent.
    ///
    /// # Arguments
    ///
    /// * `rootfs_path` - Path to the agent VM rootfs
    /// * `storage_disk` - Storage disk for OCI layers
    /// * `overlay_disk` - Overlay disk for persistent rootfs changes
    pub fn new(
        rootfs_path: impl Into<PathBuf>,
        storage_disk: StorageDisk,
        overlay_disk: OverlayDisk,
    ) -> Result<Self> {
        Self::new_internal(None, rootfs_path.into(), storage_disk, overlay_disk)
    }

    /// Create a new agent manager for a named VM.
    ///
    /// Each named VM gets isolated paths for socket, storage, and logs.
    pub fn new_named(
        name: impl Into<String>,
        rootfs_path: impl Into<PathBuf>,
        storage_disk: StorageDisk,
        overlay_disk: OverlayDisk,
    ) -> Result<Self> {
        Self::new_internal(
            Some(name.into()),
            rootfs_path.into(),
            storage_disk,
            overlay_disk,
        )
    }

    /// Internal constructor.
    fn new_internal(
        name: Option<String>,
        rootfs_path: PathBuf,
        storage_disk: StorageDisk,
        overlay_disk: OverlayDisk,
    ) -> Result<Self> {
        // Create runtime directory for sockets
        let runtime_dir = dirs::runtime_dir()
            .or_else(dirs::cache_dir)
            .unwrap_or_else(|| PathBuf::from("/tmp"));

        // Named VMs get their own subdirectory
        let smolvm_runtime = if let Some(ref vm_name) = name {
            runtime_dir.join("smolvm").join("vms").join(vm_name)
        } else {
            runtime_dir.join("smolvm")
        };
        std::fs::create_dir_all(&smolvm_runtime)?;

        let vsock_socket = smolvm_runtime.join("agent.sock");
        let pid_file = smolvm_runtime.join("agent.pid");
        let console_log = Some(smolvm_runtime.join("agent-console.log"));

        Ok(Self {
            name,
            rootfs_path,
            storage_disk,
            overlay_disk,
            vsock_socket,
            pid_file,
            console_log,
            inner: Arc::new(Mutex::new(AgentInner {
                state: AgentState::Stopped,
                child: None,
                mounts: Vec::new(),
                ports: Vec::new(),
                resources: VmResources::default(),
                detached: false,
            })),
        })
    }

    /// Get the default (anonymous) agent manager.
    ///
    /// Uses default paths for rootfs and storage.
    /// `storage_gb` and `overlay_gb` override the default disk sizes (20 GiB / 2 GiB).
    pub fn new_default_with_sizes(
        storage_gb: Option<u64>,
        overlay_gb: Option<u64>,
    ) -> Result<Self> {
        let rootfs_path = Self::default_rootfs_path()?;
        let sg = storage_gb.unwrap_or(crate::storage::DEFAULT_STORAGE_SIZE_GB);
        let og = overlay_gb.unwrap_or(crate::storage::DEFAULT_OVERLAY_SIZE_GB);

        let storage_disk = StorageDisk::open_or_create_with_size(sg)?;

        // Overlay disk lives next to the storage disk
        let overlay_path = storage_disk
            .path()
            .parent()
            .unwrap_or_else(|| Path::new("/tmp"))
            .join(crate::storage::OVERLAY_DISK_FILENAME);
        let overlay_disk = OverlayDisk::open_or_create_at(&overlay_path, og)?;

        Self::new(rootfs_path, storage_disk, overlay_disk)
    }

    /// Get the default (anonymous) agent manager with default sizes.
    pub fn new_default() -> Result<Self> {
        Self::new_default_with_sizes(None, None)
    }

    /// Get an agent manager for a named VM.
    ///
    /// Each named VM gets its own isolated storage and socket.
    /// `storage_gb` and `overlay_gb` override the default disk sizes (20 GiB / 2 GiB).
    pub fn for_vm_with_sizes(
        name: impl Into<String>,
        storage_gb: Option<u64>,
        overlay_gb: Option<u64>,
    ) -> Result<Self> {
        let name = name.into();
        let rootfs_path = Self::default_rootfs_path()?;
        let sg = storage_gb.unwrap_or(crate::storage::DEFAULT_STORAGE_SIZE_GB);
        let og = overlay_gb.unwrap_or(crate::storage::DEFAULT_OVERLAY_SIZE_GB);

        // Named VMs get their own storage disk
        let storage_dir = vm_data_dir(&name);
        std::fs::create_dir_all(&storage_dir)?;

        let storage_path = storage_dir.join(crate::storage::STORAGE_DISK_FILENAME);
        let storage_disk = StorageDisk::open_or_create_at(&storage_path, sg)?;

        let overlay_path = storage_dir.join(crate::storage::OVERLAY_DISK_FILENAME);
        let overlay_disk = OverlayDisk::open_or_create_at(&overlay_path, og)?;

        Self::new_named(name, rootfs_path, storage_disk, overlay_disk)
    }

    /// Get an agent manager for a named VM with default sizes.
    pub fn for_vm(name: impl Into<String>) -> Result<Self> {
        Self::for_vm_with_sizes(name, None, None)
    }

    /// Get the VM name if this is a named agent.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Get the default path for the agent rootfs.
    ///
    /// Checks `SMOLVM_AGENT_ROOTFS` env var first, then falls back to the
    /// platform data directory (`~/.local/share/smolvm/agent-rootfs` on Linux,
    /// `~/Library/Application Support/smolvm/agent-rootfs` on macOS).
    pub fn default_rootfs_path() -> Result<PathBuf> {
        if let Ok(path) = std::env::var("SMOLVM_AGENT_ROOTFS") {
            return Ok(PathBuf::from(path));
        }

        let data_dir = dirs::data_local_dir()
            .or_else(dirs::data_dir)
            .ok_or_else(|| Error::storage("resolve path", "could not determine data directory"))?;

        Ok(data_dir.join("smolvm").join("agent-rootfs"))
    }

    /// Get the current state of the agent.
    pub fn state(&self) -> AgentState {
        self.inner.lock().state
    }

    /// Check if the agent is running.
    pub fn is_running(&self) -> bool {
        self.state() == AgentState::Running
    }

    /// If cached state is Running but the process is not actually alive,
    /// reset to Stopped so that start paths can proceed. This handles the
    /// case where a VM crashed without going through `stop()`.
    fn reset_stale_running_state(&self) {
        let mut inner = self.inner.lock();
        if inner.state == AgentState::Running && !self.is_process_alive_inner(&inner) {
            tracing::info!("resetting stale Running state to Stopped (VM process is dead)");
            inner.state = AgentState::Stopped;
            inner.child = None;
        }
    }

    /// Return consistent (state, pid) for API status responses.
    ///
    /// Clears the PID when effective state is `Stopped`, so clients never
    /// see a stale PID paired with a stopped state.
    pub fn effective_status(&self) -> (AgentState, Option<i32>) {
        let inner = self.inner.lock();
        let state = if inner.state == AgentState::Running && !self.is_process_alive_inner(&inner) {
            AgentState::Stopped
        } else {
            inner.state
        };
        let pid = if state == AgentState::Stopped {
            None
        } else {
            inner.child.as_ref().map(|c| c.pid())
        };
        (state, pid)
    }

    /// Get the vsock socket path.
    pub fn vsock_socket(&self) -> &Path {
        &self.vsock_socket
    }

    /// Get the console log path.
    pub fn console_log(&self) -> Option<&Path> {
        self.console_log.as_deref()
    }

    /// Check if an agent is already running (socket exists + responds to ping).
    ///
    /// Returns Some(()) if agent is running and reachable, None otherwise.
    /// This also updates the internal state to Running if successful.
    pub fn try_connect_existing(&self) -> Option<()> {
        self.try_connect_existing_with_pid(None)
    }

    /// Try to reconnect to an existing agent with a known PID.
    ///
    /// If the PID is provided and the process is alive, sets the child process.
    /// Falls back to reading the PID file if no PID is provided.
    /// Returns Some(()) if agent is running and reachable, None otherwise.
    pub fn try_connect_existing_with_pid(&self, pid: Option<i32>) -> Option<()> {
        self.try_connect_existing_with_pid_and_start_time(pid, None)
    }

    /// Try to reconnect to an existing agent with a known PID and expected start time.
    ///
    /// The `expected_start_time` is the start time stored when the VM was originally
    /// launched. If provided, it is used to verify the PID hasn't been recycled by the OS.
    pub fn try_connect_existing_with_pid_and_start_time(
        &self,
        pid: Option<i32>,
        expected_start_time: Option<u64>,
    ) -> Option<()> {
        if !self.vsock_socket.exists() {
            return None;
        }

        // Resolve PID and start time.
        // If caller provides expected_start_time, use it (DB source of truth).
        // Otherwise fall back to PID file which stores both PID and start time.
        let (effective_pid, pid_start_time) = if let Some(p) = pid {
            (
                Some(p),
                expected_start_time.or_else(|| {
                    // Caller didn't provide start time — try PID file as fallback
                    self.read_pid_file_with_start_time()
                        .and_then(|(file_pid, st)| if file_pid == p { st } else { None })
                }),
            )
        } else {
            match self.read_pid_file_with_start_time() {
                Some((p, st)) => (Some(p), st),
                None => (None, None),
            }
        };

        // Try to ping the agent
        if let Ok(mut client) = super::AgentClient::connect(&self.vsock_socket) {
            if client.ping().is_ok() {
                // Update internal state to reflect running
                let mut inner = self.inner.lock();
                inner.state = AgentState::Running;
                // Only store child PID if identity is verified via start time.
                // Without verification, stop() could signal the wrong process.
                if let Some(p) = effective_pid {
                    if process::is_our_process_strict(p, pid_start_time) {
                        inner.child = Some(ChildProcess::new(p));
                    } else {
                        tracing::debug!(
                            pid = p,
                            "skipping child PID storage: identity not verified"
                        );
                    }
                }
                return Some(());
            }
        }

        None
    }

    /// Read PID and start time from the PID file.
    fn read_pid_file_with_start_time(&self) -> Option<(i32, Option<u64>)> {
        let content = std::fs::read_to_string(&self.pid_file).ok()?;
        let mut lines = content.lines();
        let pid = lines.next()?.trim().parse::<i32>().ok()?;
        let start_time = lines.next().and_then(|s| s.trim().parse::<u64>().ok());
        Some((pid, start_time))
    }

    /// Get the child PID if known.
    pub fn child_pid(&self) -> Option<i32> {
        self.inner.lock().child.as_ref().map(|c| c.pid())
    }

    /// Check if the VM process is actually alive using start-time-aware
    /// verification.
    ///
    /// Checks in-memory child handle first, then falls back to PID file.
    /// Returns `false` when neither source provides a PID (fail-closed).
    /// Uses `is_our_process` (lenient) so that a live process without
    /// start-time data is assumed to be ours rather than silently ignored.
    pub fn is_process_alive(&self) -> bool {
        let inner = self.inner.lock();
        self.is_process_alive_inner(&inner)
    }

    /// Inner liveness check that accepts a lock guard to avoid double-locking.
    fn is_process_alive_inner(&self, inner: &AgentInner) -> bool {
        // Try in-memory child handle first (has stored start time)
        if let Some(child) = inner.child.as_ref() {
            return crate::process::is_our_process(child.pid(), child.start_time());
        }

        // Fall back to PID file (covers orphan/reconnect paths)
        if let Some((pid, start_time)) = self.read_pid_file_with_start_time() {
            return crate::process::is_our_process(pid, start_time);
        }

        // No PID source — fail closed
        false
    }

    /// Connect to the running agent and return a client.
    ///
    /// Uses retry logic to handle transient connection failures.
    pub fn connect(&self) -> crate::error::Result<super::AgentClient> {
        super::AgentClient::connect_with_retry(&self.vsock_socket)
    }

    /// Get the currently configured mounts.
    pub fn mounts(&self) -> Vec<HostMount> {
        self.inner.lock().mounts.clone()
    }

    /// Check if the given mounts match the currently running agent's mounts.
    pub fn mounts_match(&self, mounts: &[HostMount]) -> bool {
        let inner = self.inner.lock();
        inner.mounts == mounts
    }

    /// Check if the given resources match the currently running agent's resources.
    pub fn resources_match(&self, resources: VmResources) -> bool {
        let inner = self.inner.lock();
        inner.resources == resources
    }

    /// Check if the given port mappings match the currently running agent's ports.
    pub fn ports_match(&self, ports: &[PortMapping]) -> bool {
        let inner = self.inner.lock();
        inner.ports == ports
    }

    /// Ensure the agent is running with the specified mounts.
    ///
    /// If the agent is running with different mounts, it will be restarted.
    pub fn ensure_running_with_mounts(&self, mounts: Vec<HostMount>) -> Result<()> {
        self.ensure_running_with_full_config(mounts, Vec::new(), VmResources::default())
    }

    /// Ensure the agent is running with the specified mounts and resources.
    ///
    /// If the agent is running with different mounts or resources, it will be restarted.
    pub fn ensure_running_with_config(
        &self,
        mounts: Vec<HostMount>,
        resources: VmResources,
    ) -> Result<()> {
        self.ensure_running_with_full_config(mounts, Vec::new(), resources)
    }

    /// Ensure the agent is running with the specified mounts, ports, and resources.
    ///
    /// If the agent is running with different configuration, it will be restarted.
    pub fn ensure_running_with_full_config(
        &self,
        mounts: Vec<HostMount>,
        ports: Vec<PortMapping>,
        resources: VmResources,
    ) -> Result<()> {
        // Check if agent is already running with the same configuration
        if self.try_connect_existing().is_some()
            && self.mounts_match(&mounts)
            && self.ports_match(&ports)
            && self.resources_match(resources)
        {
            return Ok(());
        }

        // If running with different config, we need to restart
        let needs_restart = {
            let inner = self.inner.lock();
            inner.state == AgentState::Running
                && (inner.mounts != mounts || inner.ports != ports || inner.resources != resources)
        };

        if needs_restart {
            tracing::info!("restarting agent VM due to configuration change");
            self.stop()?;
        } else {
            // try_connect_existing failed but state may still be Running (crashed VM).
            // Reset to Stopped so start_with_full_config can proceed.
            self.reset_stale_running_state();
        }

        // Start with new config
        self.start_with_full_config(mounts, ports, resources)
    }

    /// Ensure the agent is running.
    ///
    /// If the agent is not running, this starts it.
    /// If the agent is already running, this is a no-op.
    pub fn ensure_running(&self) -> Result<()> {
        // First, check if an agent is already running (from a previous invocation)
        if self.try_connect_existing().is_some() {
            return Ok(());
        }

        // try_connect_existing failed — if state is stale Running (crashed VM),
        // reset to Stopped so we can start fresh.
        self.reset_stale_running_state();

        // Check internal state
        let state = self.state();

        match state {
            AgentState::Running => Ok(()), // shouldn't reach here after reset, but safe
            AgentState::Starting => self.wait_for_ready(),
            AgentState::Stopped => self.start(),
            AgentState::Stopping => {
                self.wait_for_stop()?;
                self.start()
            }
        }
    }

    /// Start the agent VM.
    pub fn start(&self) -> Result<()> {
        self.start_with_full_config(Vec::new(), Vec::new(), VmResources::default())
    }

    /// Start the agent VM with specified mounts.
    pub fn start_with_mounts(&self, mounts: Vec<HostMount>) -> Result<()> {
        self.start_with_full_config(mounts, Vec::new(), VmResources::default())
    }

    /// Start the agent VM with specified mounts and resources.
    pub fn start_with_config(&self, mounts: Vec<HostMount>, resources: VmResources) -> Result<()> {
        self.start_with_full_config(mounts, Vec::new(), resources)
    }

    /// Start the agent VM with specified mounts, ports, and resources.
    pub fn start_with_full_config(
        &self,
        mounts: Vec<HostMount>,
        ports: Vec<PortMapping>,
        resources: VmResources,
    ) -> Result<()> {
        // Check and update state
        {
            let mut inner = self.inner.lock();
            if inner.state != AgentState::Stopped {
                return Err(Error::agent(
                    "start agent",
                    "agent already starting or running",
                ));
            }
            inner.state = AgentState::Starting;
            inner.mounts = mounts.clone();
            inner.ports = ports.clone();
            inner.resources = resources;
        }

        tracing::info!(
            rootfs = %self.rootfs_path.display(),
            storage = %self.storage_disk.path().display(),
            socket = %self.vsock_socket.display(),
            mount_count = mounts.len(),
            "starting agent VM"
        );

        // Check KVM availability on Linux before attempting to start VM
        #[cfg(target_os = "linux")]
        {
            if let Err(e) = crate::platform::linux::check_kvm_available() {
                let mut inner = self.inner.lock();
                inner.state = AgentState::Stopped;
                return Err(e);
            }
        }

        // Validate rootfs exists
        if !self.rootfs_path.exists() {
            let mut inner = self.inner.lock();
            inner.state = AgentState::Stopped;
            return Err(Error::agent(
                "verify rootfs",
                format!("agent rootfs not found: {}", self.rootfs_path.display()),
            ));
        }

        // Pre-format storage disk on host (much faster than in-VM formatting)
        // This tries: 1) copy from template (no deps), 2) mkfs.ext4 (requires e2fsprogs)
        // If both fail, VM can still format the disk but it may be slower or timeout.
        if let Err(e) = self.storage_disk.ensure_formatted() {
            tracing::warn!(
                error = %e,
                "failed to pre-format disk on host, will attempt format in VM. \
                For faster startup, install storage template or e2fsprogs"
            );
        }

        // Pre-format overlay disk for persistent rootfs
        if let Err(e) = self.overlay_disk.ensure_formatted() {
            tracing::warn!(
                error = %e,
                "failed to pre-format overlay disk on host, will format in VM on first boot"
            );
        }

        // Install SIGCHLD handler to automatically reap zombie children.
        // This must be done AFTER ensure_formatted() because the handler
        // reaps all children, which interferes with Command::output().
        crate::process::install_sigchld_handler();

        // Clean up old socket
        if let Err(e) = std::fs::remove_file(&self.vsock_socket) {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::debug!(error = %e, path = %self.vsock_socket.display(), "failed to remove old socket");
            }
        }

        // Clone paths for the child process (owned copies)
        let rootfs_path = self.rootfs_path.clone();
        let storage_disk_path = self.storage_disk.path().to_path_buf();
        let overlay_disk_path = self.overlay_disk.path().to_path_buf();
        let vsock_socket = self.vsock_socket.clone();
        let console_log = self.console_log.clone();
        let storage_size_gb = resources
            .storage_gb
            .unwrap_or(crate::storage::DEFAULT_STORAGE_SIZE_GB);
        let overlay_size_gb = resources
            .overlay_gb
            .unwrap_or(crate::storage::DEFAULT_OVERLAY_SIZE_GB);

        // Fork child process using the safe abstraction.
        // The child becomes a session leader (detached from parent's session)
        // so the VM survives if the parent process is killed.
        let child_pid = match process::fork_session_leader(move || {
            // Inherited file descriptors (including database locks) are closed
            // by fork_session_leader before this closure runs.

            // All libkrun setup happens here in the child, same as the regular run path.
            // This ensures DYLD_LIBRARY_PATH is still available (inherited from parent).

            // Re-create StorageDisk in child (we only have the path)
            let storage_disk = match crate::storage::StorageDisk::open_or_create_at(
                &storage_disk_path,
                storage_size_gb,
            ) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("failed to open storage disk: {}", e);
                    process::exit_child(1);
                }
            };

            // Re-create OverlayDisk in child
            let overlay_disk = match crate::storage::OverlayDisk::open_or_create_at(
                &overlay_disk_path,
                overlay_size_gb,
            ) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("failed to open overlay disk: {}", e);
                    process::exit_child(1);
                }
            };

            // Detach from parent's terminal before launching the VM.
            // Without this, libkrun's threads inherit stdin and steal
            // keystrokes from the user's shell.
            process::detach_stdio();

            // Launch the agent VM (never returns on success)
            let disks = launcher::VmDisks {
                storage: &storage_disk,
                overlay: Some(&overlay_disk),
            };
            let result = launch_agent_vm(
                &rootfs_path,
                &disks,
                &vsock_socket,
                console_log.as_deref(),
                &mounts,
                &ports,
                resources,
            );

            // If we get here, something went wrong (stderr is /dev/null,
            // but the error is also logged to console.log)
            let _ = result;

            process::exit_child(1);
        }) {
            Ok(pid) => pid,
            Err(e) => {
                let mut inner = self.inner.lock();
                inner.state = AgentState::Stopped;
                return Err(Error::agent("fork process", e.to_string()));
            }
        };

        // Parent process continues here
        tracing::debug!(pid = child_pid, "forked agent VM process");

        // Store child process
        {
            let mut inner = self.inner.lock();
            inner.child = Some(ChildProcess::new(child_pid));
        }

        // Write PID file so future CLI invocations can find this process.
        // Include start time on second line for PID reuse detection.
        let pid_content = match process::process_start_time(child_pid) {
            Some(t) => format!("{}\n{}", child_pid, t),
            None => child_pid.to_string(),
        };
        if let Err(e) = std::fs::write(&self.pid_file, pid_content) {
            tracing::warn!(error = %e, "failed to write PID file");
        }

        // Wait for the agent to be ready
        match self.wait_for_ready() {
            Ok(_) => {
                let mut inner = self.inner.lock();
                inner.state = AgentState::Running;
                tracing::info!(pid = child_pid, "agent VM is ready");
                Ok(())
            }
            Err(e) => {
                // Kill child if startup failed
                process::terminate(child_pid);
                let mut inner = self.inner.lock();
                inner.state = AgentState::Stopped;
                inner.child = None;
                Err(e)
            }
        }
    }

    /// Verify identity of a VM process and kill it.
    ///
    /// Uses two methods to confirm the PID belongs to our VM:
    /// 1. **Vsock shutdown** — if the guest agent acknowledges, it's our VM
    /// 2. **PID start-time** — strict comparison guards against PID reuse
    ///
    /// If either method confirms identity, sends SIGTERM (then SIGKILL on timeout).
    /// Returns `Ok(())` if the process is confirmed dead, `Err` if still alive
    /// or identity could not be verified.
    fn stop_vm_process(&self, pid: libc::pid_t, start_time: Option<u64>) -> Result<()> {
        let shutdown_acked = if let Ok(mut client) = super::AgentClient::connect(&self.vsock_socket)
        {
            client.shutdown().is_ok()
        } else {
            false
        };

        let identity_verified = process::is_our_process_strict(pid, start_time);

        if identity_verified || shutdown_acked {
            if !identity_verified {
                tracing::debug!(
                    pid,
                    "PID identity not verified (session-leader child), \
                     but shutdown was acknowledged over vsock"
                );
            }
            let _ = process::stop_process_fast(pid, AGENT_STOP_TIMEOUT, true);
        } else {
            tracing::warn!(
                pid,
                "skipping kill: PID identity not verified and vsock shutdown failed"
            );
        }

        if process::is_alive(pid) {
            Err(Error::agent(
                "stop agent",
                format!("process {} still alive after stop attempts", pid),
            ))
        } else {
            Ok(())
        }
    }

    /// Remove PID file and vsock socket marker files.
    ///
    /// Only call after the VM process is confirmed dead.
    fn cleanup_marker_files(&self) {
        for path in [&self.pid_file, &self.vsock_socket] {
            if let Err(e) = std::fs::remove_file(path) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::debug!(error = %e, path = %path.display(), "failed to remove marker file");
                }
            }
        }
    }

    /// Stop the agent VM.
    pub fn stop(&self) -> Result<()> {
        let state = {
            let inner = self.inner.lock();
            inner.state
        };

        if state == AgentState::Stopped {
            // Even if internal state is Stopped, check PID file for orphan processes
            // from previous CLI invocations that weren't properly cleaned up.
            if let Some((pid, start_time)) = self.read_pid_file_with_start_time() {
                if let Err(e) = self.stop_vm_process(pid, start_time) {
                    tracing::warn!(
                        pid,
                        "orphan process still alive, preserving PID/socket files"
                    );
                    return Err(e);
                }
                self.cleanup_marker_files();
            }
            return Ok(());
        }

        {
            let mut inner = self.inner.lock();
            inner.state = AgentState::Stopping;
        }

        tracing::info!("stopping agent VM");

        // Get the child PID and start time — try in-memory first, then PID file.
        // The PID file fallback is critical for anonymous VMs where a fresh
        // AgentManager doesn't know the PID from a previous CLI invocation.
        let (child_pid, pid_start_time) = {
            let inner = self.inner.lock();
            if let Some(child) = inner.child.as_ref() {
                // Use the start time captured when the child handle was created,
                // not recomputed from the PID (which would be self-fulfilling
                // if the PID was recycled by the OS).
                (Some(child.pid()), child.start_time())
            } else {
                match self.read_pid_file_with_start_time() {
                    Some((pid, start_time)) => (Some(pid), start_time),
                    None => (None, None),
                }
            }
        };

        if let Some(pid) = child_pid {
            if let Err(e) = self.stop_vm_process(pid, pid_start_time) {
                // Revert to Running — don't lie about state or delete markers
                {
                    let mut inner = self.inner.lock();
                    inner.state = AgentState::Running;
                }
                return Err(e);
            }
        }

        // Defense in depth: sync host's view of the disk files
        // This catches any writes that made it to the host buffer but weren't flushed
        // Combined with agent-side sync(), this provides robust data integrity
        for (label, path) in [
            ("storage", self.storage_disk.path()),
            ("overlay", self.overlay_disk.path()),
        ] {
            if let Ok(file) = std::fs::File::open(path) {
                if file.sync_all().is_ok() {
                    tracing::debug!("{} disk synced to host", label);
                }
            }
        }

        // Clean up — safe now that process is confirmed dead
        {
            let mut inner = self.inner.lock();
            inner.state = AgentState::Stopped;
            inner.child = None;
        }

        self.cleanup_marker_files();

        Ok(())
    }

    /// Wait for the agent to be ready.
    fn wait_for_ready(&self) -> Result<()> {
        let timeout = AGENT_READY_TIMEOUT;
        let start = Instant::now();

        tracing::debug!("waiting for agent to be ready");

        // Track timing for each phase
        let mut socket_appeared_at: Option<Duration> = None;
        let mut first_connect_at: Option<Duration> = None;
        let mut poll_count: u32 = 0;

        while start.elapsed() < timeout {
            // Use aggressive polling at first, then back off
            let poll_interval = if poll_count < FAST_POLL_COUNT {
                FAST_POLL_INTERVAL // 10ms
            } else {
                Duration::from_millis(100) // Back off to 100ms
            };
            poll_count += 1;
            // Check if child process is still alive
            {
                let mut inner = self.inner.lock();
                if let Some(ref mut child) = inner.child {
                    if !child.is_running() {
                        // Child exited
                        return Err(Error::agent(
                            "monitor agent",
                            "agent process exited during startup",
                        ));
                    }
                }
            }

            // Try to connect to vsock socket
            if self.vsock_socket.exists() {
                // Log when socket first appears
                if socket_appeared_at.is_none() {
                    let elapsed = start.elapsed();
                    socket_appeared_at = Some(elapsed);
                    tracing::debug!(elapsed_ms = elapsed.as_millis(), "vsock socket appeared");
                }

                match UnixStream::connect(&self.vsock_socket) {
                    Ok(stream) => {
                        drop(stream);

                        // Log when first connect succeeds
                        if first_connect_at.is_none() {
                            let elapsed = start.elapsed();
                            first_connect_at = Some(elapsed);
                            tracing::debug!(
                                elapsed_ms = elapsed.as_millis(),
                                "vsock first connect succeeded"
                            );
                        }

                        // Try to ping
                        match super::AgentClient::connect(&self.vsock_socket) {
                            Ok(mut client) => {
                                if client.ping().is_ok() {
                                    let total = start.elapsed();
                                    tracing::info!(
                                        total_ms = total.as_millis(),
                                        socket_wait_ms =
                                            socket_appeared_at.map(|d| d.as_millis()).unwrap_or(0),
                                        connect_wait_ms =
                                            first_connect_at.map(|d| d.as_millis()).unwrap_or(0),
                                        "agent ready - timing breakdown"
                                    );
                                    return Ok(());
                                }
                            }
                            Err(e) => {
                                tracing::trace!("ping failed: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::trace!("connect failed: {}", e);
                    }
                }
            }

            std::thread::sleep(poll_interval);
        }

        Err(Error::agent(
            "wait for ready",
            format!(
                "agent did not become ready within {} seconds",
                timeout.as_secs()
            ),
        ))
    }

    /// Wait for the agent to stop.
    fn wait_for_stop(&self) -> Result<()> {
        let timeout = WAIT_FOR_STOP_TIMEOUT;
        let start = Instant::now();

        while start.elapsed() < timeout {
            if self.state() == AgentState::Stopped {
                return Ok(());
            }
            std::thread::sleep(FAST_POLL_INTERVAL);
        }

        Err(Error::agent(
            "shutdown agent",
            "timeout waiting for agent to stop",
        ))
    }

    /// Check if agent process is still running.
    pub fn check_alive(&self) -> bool {
        let mut inner = self.inner.lock();

        if let Some(ref mut child) = inner.child {
            child.is_running()
        } else {
            false
        }
    }

    /// Detach the agent manager, preventing cleanup on drop.
    ///
    /// Call this when you want the agent VM to continue running after
    /// this manager instance is dropped (e.g., for persistent VMs).
    ///
    /// This is preferred over `std::mem::forget` because:
    /// - Intent is explicit and documented
    /// - Other resources (non-child-process) are still properly cleaned up
    /// - The manager can still be used after detaching
    pub fn detach(&self) {
        let mut inner = self.inner.lock();
        inner.detached = true;
        tracing::debug!("agent manager detached, VM will continue running");
    }

    /// Check if the agent manager has been detached.
    pub fn is_detached(&self) -> bool {
        let inner = self.inner.lock();
        inner.detached
    }
}

impl Drop for AgentManager {
    fn drop(&mut self) {
        // Check if detached before attempting cleanup
        let detached = self.inner.lock().detached;

        if !detached {
            if let Err(e) = self.stop() {
                tracing::debug!(error = %e, "failed to stop agent in drop");
            }
        }
    }
}
