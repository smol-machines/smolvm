//! Runtime VM handle for embedded SDK backends.

use crate::agent::{AgentClient, AgentManager, RunConfig};
use crate::config::VmRecord;
use crate::Result;
use smolvm_protocol::ImageInfo;

/// Handle to a running VM process.
pub struct VmHandle {
    manager: AgentManager,
    client: Option<AgentClient>,
}

// SAFETY: The embedded runtime stores `VmHandle` behind a mutex and only moves
// it into blocking worker threads. `AgentManager` guards its mutable state
// internally, and `AgentClient` owns a Unix stream that is safe to move between
// threads when access is serialized by the handle mutex.
unsafe impl Send for VmHandle {}

impl VmHandle {
    /// Construct a handle from an already-created process manager.
    pub fn new(manager: AgentManager, client: Option<AgentClient>) -> Self {
        Self { manager, client }
    }

    /// Get the child PID if known.
    pub fn child_pid(&self) -> Option<i32> {
        self.manager.child_pid()
    }

    /// Check whether the VM process is alive.
    pub fn is_process_alive(&self) -> bool {
        self.manager.is_process_alive()
    }

    /// Return the agent manager state as a string.
    pub fn state(&self) -> String {
        self.manager.state().to_string()
    }

    /// Where the VM's agent listens, for opening a dedicated connection.
    pub fn agent_socket(&self) -> std::path::PathBuf {
        self.manager.vsock_socket().to_path_buf()
    }

    fn client_mut(&mut self) -> Result<&mut AgentClient> {
        if self.client.is_none() {
            self.client = Some(self.manager.connect()?);
        }
        Ok(self.client.as_mut().expect("client initialized"))
    }

    /// Run a prebuilt [`RunConfig`] over the cached connection, for callers
    /// that have already decided the image and overlay.
    pub fn run_config(&mut self, config: RunConfig) -> Result<(i32, Vec<u8>, Vec<u8>)> {
        self.client_mut()?.run_non_interactive(config)
    }

    /// Point this connection's file operations at `target`; see
    /// [`AgentClient::use_target`].
    pub fn use_target(&mut self, target: crate::agent::WorkloadTarget) -> Result<()> {
        self.client_mut()?.use_target(target)
    }

    /// Pull an OCI image into the VM storage for `platform` (`os/arch`), or for
    /// the guest's own architecture when `None`. A machine keeps one platform
    /// per reference, so every pull of its image passes
    /// [`VmRecord::image_platform`].
    pub fn pull_image(&mut self, image: &str, platform: Option<&str>) -> Result<ImageInfo> {
        let mut options = crate::agent::PullOptions::new().use_registry_config(true);
        if let Some(platform) = platform {
            options = options.oci_platform(platform);
        }
        self.client_mut()?.pull(image, options)
    }

    /// List cached OCI images in the VM storage.
    pub fn list_images(&mut self) -> Result<Vec<ImageInfo>> {
        self.client_mut()?.list_images()
    }

    /// Prepare the saved machine using the CLI's initialization semantics.
    /// The runtime owns the startup lock and commits init_completed only after
    /// every command succeeds, so another client cannot attach halfway through.
    pub(crate) fn initialize_machine(&mut self, name: &str, record: &VmRecord) -> Result<()> {
        let packed = record.source_smolmachine.is_some()
            || record
                .image
                .as_deref()
                .is_some_and(crate::data::image_source::is_local_ref);
        let image_info = if packed {
            None
        } else if let Some(image) = record.image.as_deref() {
            Some(self.pull_image(image, record.image_platform())?)
        } else {
            None
        };
        let env = crate::secrets::record_env_with_secrets(record)?;
        crate::cli::vm_common::run_init_commands_captured(
            self.client_mut()?,
            &record.init,
            crate::cli::vm_common::InitRunContext {
                image: record.image.as_deref(),
                image_info: image_info.as_ref(),
                env: &env,
                workdir: record.workdir.as_deref(),
                record_mounts: &record.mounts,
                overlay_id: name,
            },
        )
    }

    /// Pull and launch an image machine's persistent workload before the SDK
    /// reports create/start complete.
    pub fn launch_image_workload(&mut self, name: &str, record: &VmRecord) -> Result<()> {
        let Some(image) = record.image.as_deref() else {
            return Ok(());
        };
        if !record.init_completed {
            self.pull_image(image, record.image_platform())?;
        }
        let client = self.client_mut()?;
        let env = crate::secrets::record_env_with_secrets(record)?;
        crate::workload::launch_image_workload(client, name, record, env)?;
        Ok(())
    }

    /// Write a file into the VM.
    pub fn write_file(&mut self, path: &str, data: &[u8], mode: Option<u32>) -> Result<()> {
        self.client_mut()?.write_file(path, data, mode)
    }

    /// Read a file from the VM.
    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>> {
        self.client_mut()?.read_file(path)
    }

    /// Copy every guest-local staged mount back to its host source.
    pub fn sync_staged_mounts(&mut self, record: &crate::config::VmRecord) -> Result<()> {
        crate::staged_mount::sync_with_manager(record, &self.manager)
    }

    /// Stop the VM and drop the cached agent client.
    pub fn stop(&mut self) -> Result<()> {
        self.stop_with_timeout(None)
    }

    /// [`stop`](Self::stop), giving the workload `stop_timeout` to exit after
    /// its stop signal instead of the timeout it was launched with.
    pub fn stop_with_timeout(&mut self, stop_timeout: Option<std::time::Duration>) -> Result<()> {
        self.client = None;
        match stop_timeout {
            Some(stop_timeout) => self.manager.stop_with_timeout(stop_timeout),
            None => self.manager.stop(),
        }
    }

    /// Stop a VM whose guest is paused (a frozen branch base): its agent
    /// cannot answer a shutdown request, so the VMM is ended directly.
    #[cfg(unix)]
    pub fn stop_paused(&mut self) -> Result<()> {
        self.client = None;
        self.manager.stop_paused()
    }

    /// Let a CLI-started VM outlive the process that launched it.
    pub fn detach(self) {
        self.manager.detach();
    }
}
