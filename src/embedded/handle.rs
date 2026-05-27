//! Runtime VM handle for embedded SDK backends.

use std::time::Duration;

use crate::agent::{AgentClient, AgentManager, ExecEvent, RunConfig};
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

    fn client_mut(&mut self) -> Result<&mut AgentClient> {
        if self.client.is_none() {
            self.client = Some(self.manager.connect()?);
        }
        Ok(self.client.as_mut().expect("client initialized"))
    }

    /// Execute a command directly in the VM.
    pub fn exec(
        &mut self,
        command: Vec<String>,
        env: Vec<(String, String)>,
        workdir: Option<String>,
        timeout: Option<Duration>,
    ) -> Result<(i32, Vec<u8>, Vec<u8>)> {
        self.client_mut()?.vm_exec(command, env, workdir, timeout)
    }

    /// Pull an OCI image and run a command inside it.
    ///
    /// Returns `(exit_code, stdout_bytes, stderr_bytes)`. Bytes are raw
    /// to preserve binary output.
    pub fn run(
        &mut self,
        image: &str,
        command: Vec<String>,
        env: Vec<(String, String)>,
        workdir: Option<String>,
        timeout: Option<Duration>,
    ) -> Result<(i32, Vec<u8>, Vec<u8>)> {
        let client = self.client_mut()?;
        client.pull_with_registry_config(image)?;
        let config = RunConfig::new(image, command)
            .with_env(env)
            .with_workdir(workdir)
            .with_timeout(timeout);
        client.run_non_interactive(config)
    }

    /// Pull an OCI image into the VM storage.
    pub fn pull_image(&mut self, image: &str) -> Result<ImageInfo> {
        self.client_mut()?.pull_with_registry_config(image)
    }

    /// List cached OCI images in the VM storage.
    pub fn list_images(&mut self) -> Result<Vec<ImageInfo>> {
        self.client_mut()?.list_images()
    }

    /// Write a file into the VM.
    pub fn write_file(&mut self, path: &str, data: &[u8], mode: Option<u32>) -> Result<()> {
        self.client_mut()?.write_file(path, data, mode)
    }

    /// Read a file from the VM.
    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>> {
        self.client_mut()?.read_file(path)
    }

    /// Execute a command with streaming stdout/stderr events.
    pub fn exec_streaming(
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
    pub fn stop(&mut self) -> Result<()> {
        self.client = None;
        self.manager.stop()
    }
}
