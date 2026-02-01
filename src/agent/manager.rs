//! Agent VM lifecycle management.
//!
//! The AgentManager is responsible for starting and stopping the agent VM,
//! which runs the smolvm-agent for OCI image management and command execution.

use crate::error::{Error, Result};
use crate::process::{self, ChildProcess};
use crate::storage::StorageDisk;
use parking_lot::Mutex;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::launcher::launch_agent_vm;
use super::{HostMount, PortMapping, VmResources};

// ============================================================================
// Configuration Constants
// ============================================================================

/// Timeout for the agent to become ready after starting.
const AGENT_READY_TIMEOUT: Duration = Duration::from_secs(30);

/// Poll interval when waiting for agent readiness.
/// Use aggressive polling initially to reduce cold start latency.
const AGENT_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Number of aggressive poll attempts before backing off.
/// At 10ms intervals, this covers ~100ms of aggressive polling.
const AGGRESSIVE_POLL_COUNT: u32 = 10;

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
    /// vsock socket path for control channel.
    vsock_socket: PathBuf,
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
    pub fn new(rootfs_path: impl Into<PathBuf>, storage_disk: StorageDisk) -> Result<Self> {
        Self::new_internal(None, rootfs_path.into(), storage_disk)
    }

    /// Create a new agent manager for a named VM.
    ///
    /// Each named VM gets isolated paths for socket, storage, and logs.
    pub fn new_named(
        name: impl Into<String>,
        rootfs_path: impl Into<PathBuf>,
        storage_disk: StorageDisk,
    ) -> Result<Self> {
        Self::new_internal(Some(name.into()), rootfs_path.into(), storage_disk)
    }

    /// Internal constructor.
    fn new_internal(
        name: Option<String>,
        rootfs_path: PathBuf,
        storage_disk: StorageDisk,
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
        let console_log = Some(smolvm_runtime.join("agent-console.log"));

        Ok(Self {
            name,
            rootfs_path,
            storage_disk,
            vsock_socket,
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
    pub fn new_default() -> Result<Self> {
        let rootfs_path = Self::default_rootfs_path()?;
        let storage_disk = StorageDisk::open_or_create()?;

        Self::new(rootfs_path, storage_disk)
    }

    /// Get an agent manager for a named VM.
    ///
    /// Each named VM gets its own isolated storage and socket.
    pub fn for_vm(name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        let rootfs_path = Self::default_rootfs_path()?;

        // Named VMs get their own storage disk
        let storage_dir = dirs::cache_dir()
            .or_else(dirs::data_local_dir)
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("smolvm")
            .join("vms")
            .join(&name);
        std::fs::create_dir_all(&storage_dir)?;

        let storage_path = storage_dir.join("storage.img");
        let storage_disk =
            StorageDisk::open_or_create_at(&storage_path, crate::storage::DEFAULT_STORAGE_SIZE_GB)?;

        Self::new_named(name, rootfs_path, storage_disk)
    }

    /// Get the VM name if this is a named agent.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Get the default path for the agent rootfs.
    pub fn default_rootfs_path() -> Result<PathBuf> {
        let data_dir = dirs::data_local_dir()
            .or_else(dirs::data_dir)
            .ok_or_else(|| Error::Storage("could not determine data directory".into()))?;

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
    /// Returns Some(()) if agent is running and reachable, None otherwise.
    pub fn try_connect_existing_with_pid(&self, pid: Option<i32>) -> Option<()> {
        if !self.vsock_socket.exists() {
            return None;
        }

        // Try to ping the agent
        if let Ok(mut client) = super::AgentClient::connect(&self.vsock_socket) {
            if client.ping().is_ok() {
                // Update internal state to reflect running
                let mut inner = self.inner.lock();
                inner.state = AgentState::Running;
                // Set the child process if PID is known and process is alive
                if let Some(p) = pid {
                    if process::is_alive(p) {
                        inner.child = Some(ChildProcess::new(p));
                    }
                }
                return Some(());
            }
        }

        None
    }

    /// Get the child PID if known.
    pub fn child_pid(&self) -> Option<i32> {
        self.inner.lock().child.as_ref().map(|c| c.pid())
    }

    /// Connect to the running agent and return a client.
    pub fn connect(&self) -> crate::error::Result<super::AgentClient> {
        super::AgentClient::connect(&self.vsock_socket)
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

        // Otherwise, check internal state
        let state = self.state();

        match state {
            AgentState::Running => Ok(()),
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
                return Err(Error::AgentError(
                    "agent already starting or running".into(),
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
            return Err(Error::AgentError(format!(
                "agent rootfs not found: {}",
                self.rootfs_path.display()
            )));
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

        // Install SIGCHLD handler to automatically reap zombie children.
        // This must be done AFTER ensure_formatted() because the handler
        // reaps all children, which interferes with Command::output().
        crate::process::install_sigchld_handler();

        // Clean up old socket
        let _ = std::fs::remove_file(&self.vsock_socket);

        // Clone paths for the child process (owned copies)
        let rootfs_path = self.rootfs_path.clone();
        let storage_disk_path = self.storage_disk.path().to_path_buf();
        let vsock_socket = self.vsock_socket.clone();
        let console_log = self.console_log.clone();

        // Fork child process using the safe abstraction.
        // The child becomes a session leader (detached from parent's session)
        // so the VM survives if the parent process is killed.
        let child_pid = match process::fork_session_leader(move || {
            // NOTE: Database file descriptors are handled by the caller closing
            // the database before fork and reopening after. This avoids the
            // fragile approach of closing fds in a range.

            // All libkrun setup happens here in the child, same as the regular run path.
            // This ensures DYLD_LIBRARY_PATH is still available (inherited from parent).

            // Re-create StorageDisk in child (we only have the path)
            let storage_disk = match crate::storage::StorageDisk::open_or_create_at(
                &storage_disk_path,
                crate::storage::DEFAULT_STORAGE_SIZE_GB,
            ) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("failed to open storage disk: {}", e);
                    process::exit_child(1);
                }
            };

            // Launch the agent VM (never returns on success)
            let result = launch_agent_vm(
                &rootfs_path,
                &storage_disk,
                &vsock_socket,
                console_log.as_deref(),
                &mounts,
                &ports,
                resources,
            );

            // If we get here, something went wrong
            if let Err(e) = result {
                eprintln!("agent VM failed to start: {}", e);
            }

            process::exit_child(1);
        }) {
            Ok(pid) => pid,
            Err(e) => {
                let mut inner = self.inner.lock();
                inner.state = AgentState::Stopped;
                return Err(Error::AgentError(format!("fork failed: {}", e)));
            }
        };

        // Parent process continues here
        tracing::debug!(pid = child_pid, "forked agent VM process");

        // Store child process
        {
            let mut inner = self.inner.lock();
            inner.child = Some(ChildProcess::new(child_pid));
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

    /// Stop the agent VM.
    pub fn stop(&self) -> Result<()> {
        let state = {
            let inner = self.inner.lock();
            inner.state
        };

        if state == AgentState::Stopped {
            return Ok(());
        }

        {
            let mut inner = self.inner.lock();
            inner.state = AgentState::Stopping;
        }

        tracing::info!("stopping agent VM");

        // Get the child PID first so we can check if it exits quickly
        let child_pid = {
            let inner = self.inner.lock();
            inner.child.as_ref().map(|c| c.pid())
        };

        // Try graceful shutdown via vsock (fire-and-forget, don't wait for response)
        if let Ok(mut client) = super::AgentClient::connect(&self.vsock_socket) {
            let _ = client.shutdown();
        }

        if let Some(pid) = child_pid {
            // Use optimized stop with aggressive polling for fast response
            let _ = process::stop_process_fast(pid, AGENT_STOP_TIMEOUT, true);
        }

        // Clean up
        {
            let mut inner = self.inner.lock();
            inner.state = AgentState::Stopped;
            inner.child = None;
        }

        // Remove socket
        let _ = std::fs::remove_file(&self.vsock_socket);

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
            let poll_interval = if poll_count < AGGRESSIVE_POLL_COUNT {
                AGENT_POLL_INTERVAL // 10ms
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
                        return Err(Error::AgentError(
                            "agent process exited during startup".into(),
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

        Err(Error::AgentError(format!(
            "agent did not become ready within {} seconds",
            timeout.as_secs()
        )))
    }

    /// Wait for the agent to stop.
    fn wait_for_stop(&self) -> Result<()> {
        let timeout = WAIT_FOR_STOP_TIMEOUT;
        let start = Instant::now();

        while start.elapsed() < timeout {
            if self.state() == AgentState::Stopped {
                return Ok(());
            }
            std::thread::sleep(AGENT_POLL_INTERVAL);
        }

        Err(Error::AgentError(
            "timeout waiting for agent to stop".into(),
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
            // Best-effort cleanup
            let _ = self.stop();
        }
    }
}
