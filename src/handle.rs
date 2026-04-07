//! Runtime VM handle.
//!
//! `VmHandle` owns the host-side VM process manager and lazily creates the
//! guest-agent client the first time an agent operation is requested. This keeps
//! VM lifecycle ownership in one place while exposing only the agent operations
//! the control layer and CLI are expected to use.

use crate::error::Result;
use crate::internal::agent::{AgentClient, AgentManager, ExecEvent, RunConfig};
use smolvm_protocol::{ImageInfo, StorageStatus};
use std::time::Duration;

/// Handle to a running VM process.
///
/// The handle is intentionally narrower than [`AgentClient`]. It exposes
/// selected guest-agent operations while retaining ownership of the
/// [`AgentManager`] that supervises the host-side VM process.
pub struct VmHandle {
    /// Host-side process manager for this VM.
    pub(crate) manager: AgentManager,
    /// Lazily initialized guest-agent client.
    client: Option<AgentClient>,
    /// Whether this handle started the VM instead of reconnecting to it.
    freshly_started: bool,
}

/// Extra options for an interactive OCI image run.
#[derive(Debug, Clone, Copy)]
pub struct RunInteractiveOptions {
    /// Timeout for command execution.
    pub timeout: Option<Duration>,
    /// Whether to allocate a TTY.
    pub tty: bool,
}

impl VmHandle {
    /// Construct a handle from an already-created process manager.
    ///
    /// `client` may be `None`; agent operations will connect to the guest lazily
    /// through [`Self::client_mut`].
    pub(crate) fn new(
        manager: AgentManager,
        freshly_started: bool,
        client: Option<AgentClient>,
    ) -> Self {
        Self {
            manager,
            freshly_started,
            client,
        }
    }

    /// Returns `true` if this handle booted the VM instead of reconnecting.
    pub fn freshly_started(&self) -> bool {
        self.freshly_started
    }

    /// Return the cached agent client, connecting to the guest if needed.
    fn client_mut(&mut self) -> Result<&mut AgentClient> {
        if self.client.is_none() {
            self.client = Some(AgentClient::connect_with_retry(
                self.manager.vsock_socket(),
            )?);
        }
        Ok(self.client.as_mut().expect("client initialized"))
    }

    /// Pull an OCI image inside the VM and report progress through `on_progress`.
    pub fn pull_with_registry_config_and_progress<F: FnMut(usize, usize, &str)>(
        &mut self,
        image: &str,
        oci_platform: Option<&str>,
        on_progress: F,
    ) -> Result<ImageInfo> {
        self.client_mut()?
            .pull_with_registry_config_and_progress(image, oci_platform, on_progress)
    }

    /// Run a non-interactive command directly in the VM guest.
    ///
    /// The handle API borrows command configuration for caller ergonomics; the
    /// values are cloned at the agent-client boundary because the protocol
    /// request owns its payload.
    pub fn vm_exec(
        &mut self,
        command: &[String],
        env: &[(String, String)],
        workdir: Option<&str>,
        timeout: Option<Duration>,
    ) -> Result<(i32, String, String)> {
        self.client_mut()?.vm_exec(
            command.to_vec(),
            env.to_vec(),
            workdir.map(str::to_string),
            timeout,
        )
    }

    /// Run an interactive command directly in the VM guest.
    pub fn vm_exec_interactive(
        &mut self,
        command: &[String],
        env: &[(String, String)],
        workdir: Option<&str>,
        timeout: Option<Duration>,
        tty: bool,
    ) -> Result<i32> {
        self.client_mut()?.vm_exec_interactive(
            command.to_vec(),
            env.to_vec(),
            workdir.map(str::to_string),
            timeout,
            tty,
        )
    }

    /// Start a background command directly in the VM guest and return its PID.
    pub fn vm_exec_background(
        &mut self,
        command: &[String],
        env: &[(String, String)],
        workdir: Option<&str>,
    ) -> Result<u32> {
        self.client_mut()?.vm_exec_background(
            command.to_vec(),
            env.to_vec(),
            workdir.map(str::to_string),
        )
    }

    /// Run a command in the VM guest and return structured streaming events.
    pub fn vm_exec_streaming(
        &mut self,
        command: &[String],
        env: &[(String, String)],
        workdir: Option<&str>,
        timeout: Option<Duration>,
    ) -> Result<Vec<ExecEvent>> {
        self.client_mut()?.vm_exec_streaming(
            command.to_vec(),
            env.to_vec(),
            workdir.map(str::to_string),
            timeout,
        )
    }

    /// Run an OCI image command with mount bindings and an optional timeout.
    pub fn run_with_mounts_and_timeout(
        &mut self,
        image: &str,
        command: &[String],
        env: &[(String, String)],
        workdir: Option<&str>,
        mounts: &[(String, String, bool)],
        timeout: Option<Duration>,
    ) -> Result<(i32, String, String)> {
        self.client_mut()?.run_with_mounts_and_timeout(
            image,
            command.to_vec(),
            env.to_vec(),
            workdir.map(str::to_string),
            mounts.to_vec(),
            timeout,
        )
    }

    /// Run an OCI image command interactively.
    pub fn run_interactive(
        &mut self,
        image: &str,
        command: &[String],
        env: &[(String, String)],
        workdir: Option<&str>,
        mounts: &[(String, String, bool)],
        options: RunInteractiveOptions,
    ) -> Result<i32> {
        let config = RunConfig::new(image, command.to_vec())
            .with_env(env.to_vec())
            .with_workdir(workdir.map(str::to_string))
            .with_mounts(mounts.to_vec())
            .with_timeout(options.timeout)
            .with_tty(options.tty);
        self.client_mut()?.run_interactive(config)
    }

    /// Write bytes to a path inside the VM guest.
    pub fn write_file(&mut self, path: &str, data: &[u8], mode: Option<u32>) -> Result<()> {
        self.client_mut()?.write_file(path, data, mode)
    }

    /// Read bytes from a path inside the VM guest.
    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>> {
        self.client_mut()?.read_file(path)
    }

    /// Ask the guest agent to run its network diagnostic against `url`.
    pub fn network_test(&mut self, url: &str) -> Result<serde_json::Value> {
        self.client_mut()?.network_test(url)
    }

    /// Return storage usage information reported by the guest agent.
    pub fn storage_status(&mut self) -> Result<StorageStatus> {
        self.client_mut()?.storage_status()
    }

    /// List OCI images available inside the VM.
    pub fn list_images(&mut self) -> Result<Vec<ImageInfo>> {
        self.client_mut()?.list_images()
    }

    /// Run image/container garbage collection inside the VM.
    pub fn garbage_collect(&mut self, dry_run: bool) -> Result<u64> {
        self.client_mut()?.garbage_collect(dry_run)
    }

    /// Detach the VM process so it survives after this handle is dropped.
    pub fn detach(self) {
        self.manager.detach();
    }

    /// Stop the VM process gracefully.
    pub fn stop(self) -> Result<()> {
        self.manager.stop()
    }

    /// Kill the VM process immediately.
    pub fn kill(self) {
        self.manager.kill();
    }

    /// Get the guest agent vsock socket path.
    pub fn vsock_socket(&self) -> &std::path::Path {
        self.manager.vsock_socket()
    }

    /// Get the child PID if available.
    pub fn child_pid(&self) -> Option<i32> {
        self.manager.child_pid()
    }

    /// Get the VM storage disk path.
    pub fn storage_path(&self) -> std::path::PathBuf {
        self.manager.storage_path().to_path_buf()
    }

    /// Get the VM overlay disk path.
    pub fn overlay_path(&self) -> std::path::PathBuf {
        self.manager.overlay_path().to_path_buf()
    }
}
