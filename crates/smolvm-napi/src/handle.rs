//! Runtime VM handle for the NAPI backend.
//!
//! This is a crate-local transplant of the control-layer handle idea: keep
//! process ownership and the lazy agent connection together, without exposing
//! the whole `AgentClient` surface through `NapiMachine`.

use std::time::Duration;

use smolvm::agent::{AgentClient, AgentManager, ExecEvent};
use smolvm::Result;
use smolvm_protocol::ImageInfo;

/// Handle to a running VM process.
pub(crate) struct VmHandle {
    manager: AgentManager,
    client: Option<AgentClient>,
}

// SAFETY: The NAPI runtime stores `VmHandle` behind a mutex and only moves it
// into blocking worker threads. `AgentManager` guards its mutable state
// internally, and `AgentClient` owns a Unix stream that is safe to move between
// threads when access is serialized by the handle mutex.
unsafe impl Send for VmHandle {}

impl VmHandle {
    /// Construct a handle from an already-created process manager.
    pub(crate) fn new(manager: AgentManager, client: Option<AgentClient>) -> Self {
        Self { manager, client }
    }

    /// Get the child PID if known.
    pub(crate) fn child_pid(&self) -> Option<i32> {
        self.manager.child_pid()
    }

    /// Check whether the VM process is alive.
    pub(crate) fn is_process_alive(&self) -> bool {
        self.manager.is_process_alive()
    }

    /// Return the agent manager state as a string.
    pub(crate) fn state(&self) -> String {
        self.manager.state().to_string()
    }

    fn client_mut(&mut self) -> Result<&mut AgentClient> {
        if self.client.is_none() {
            self.client = Some(self.manager.connect()?);
        }
        Ok(self.client.as_mut().expect("client initialized"))
    }

    /// Execute a command directly in the VM.
    pub(crate) fn exec(
        &mut self,
        command: Vec<String>,
        env: Vec<(String, String)>,
        workdir: Option<String>,
        timeout: Option<Duration>,
    ) -> Result<(i32, String, String)> {
        self.client_mut()?.vm_exec(command, env, workdir, timeout)
    }

    /// Pull an OCI image and run a command inside it.
    pub(crate) fn run(
        &mut self,
        image: &str,
        command: Vec<String>,
        env: Vec<(String, String)>,
        workdir: Option<String>,
        timeout: Option<Duration>,
    ) -> Result<(i32, String, String)> {
        let client = self.client_mut()?;
        client.pull_with_registry_config(image)?;
        client.run_with_mounts_and_timeout(image, command, env, workdir, Vec::new(), timeout)
    }

    /// Pull an OCI image into the VM storage.
    pub(crate) fn pull_image(&mut self, image: &str) -> Result<ImageInfo> {
        self.client_mut()?.pull_with_registry_config(image)
    }

    /// List cached OCI images in the VM storage.
    pub(crate) fn list_images(&mut self) -> Result<Vec<ImageInfo>> {
        self.client_mut()?.list_images()
    }

    /// Write a file into the VM.
    pub(crate) fn write_file(&mut self, path: &str, data: &[u8], mode: Option<u32>) -> Result<()> {
        self.client_mut()?.write_file(path, data, mode)
    }

    /// Read a file from the VM.
    pub(crate) fn read_file(&mut self, path: &str) -> Result<Vec<u8>> {
        self.client_mut()?.read_file(path)
    }

    /// Execute a command with streaming stdout/stderr events.
    pub(crate) fn exec_streaming(
        &mut self,
        command: Vec<String>,
        env: Vec<(String, String)>,
        workdir: Option<String>,
        timeout: Option<Duration>,
    ) -> Result<Vec<ExecEvent>> {
        self.client_mut()?
            .vm_exec_streaming(command, env, workdir, timeout)
    }

    /// Stop the VM and drop the cached agent client.
    pub(crate) fn stop(&mut self) -> Result<()> {
        self.client = None;
        self.manager.stop()
    }
}
