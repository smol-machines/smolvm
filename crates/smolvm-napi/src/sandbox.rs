//! NapiSandbox — the main NAPI class wrapping AgentManager + AgentClient.
//!
//! All blocking operations (start, exec, pull, stop) run on tokio's blocking
//! thread pool to avoid blocking Node's event loop. The AgentManager and
//! AgentClient are wrapped in Arc<Mutex<>> for safe cross-thread access.

use std::sync::{Arc, Mutex};

use napi_derive::napi;

use smolvm::agent::{AgentClient, AgentManager, HostMount, PortMapping, VmResources};

use crate::error::IntoNapiResult;
use crate::types::*;

/// Wrapper to make AgentManager sendable across threads.
/// AgentManager contains Arc<Mutex<AgentInner>> + PathBuf fields, all Send.
struct ManagerWrapper(AgentManager);

// SAFETY: AgentManager's fields are all Send (Arc<Mutex<_>>, PathBuf, String, Option<PathBuf>).
// The internal Mutex synchronizes all mutable state.
unsafe impl Send for ManagerWrapper {}
unsafe impl Sync for ManagerWrapper {}

#[napi]
pub struct NapiSandbox {
    name: String,
    manager: Arc<ManagerWrapper>,
    client: Arc<Mutex<Option<AgentClient>>>,
    mounts: Vec<HostMount>,
    ports: Vec<PortMapping>,
    resources: VmResources,
}

#[napi]
impl NapiSandbox {
    /// Create a new sandbox. Does not start the VM yet — call `start()`.
    #[napi(constructor)]
    pub fn new(config: SandboxConfig) -> napi::Result<Self> {
        let mounts: Vec<HostMount> = config
            .mounts
            .as_ref()
            .map(|ms| ms.iter().map(HostMount::from).collect())
            .unwrap_or_default();

        let ports: Vec<PortMapping> = config
            .ports
            .as_ref()
            .map(|ps| ps.iter().map(PortMapping::from).collect())
            .unwrap_or_default();

        let resources = config
            .resources
            .as_ref()
            .map(|r| r.to_vm_resources())
            .unwrap_or_default();

        let manager = AgentManager::for_vm_with_sizes(
            &config.name,
            resources.storage_gb,
            resources.overlay_gb,
        )
        .into_napi()?;

        Ok(Self {
            name: config.name,
            manager: Arc::new(ManagerWrapper(manager)),
            client: Arc::new(Mutex::new(None)),
            mounts,
            ports,
            resources,
        })
    }

    /// Connect to an already-running VM by name.
    ///
    /// Returns an error if no running VM is found with the given name.
    #[napi(factory)]
    pub fn connect(name: String) -> napi::Result<Self> {
        let manager = AgentManager::for_vm(&name).into_napi()?;

        let connected = manager.try_connect_existing().is_some();
        if !connected {
            return Err(napi::Error::from_reason(format!(
                "[NOT_FOUND] No running VM found with name '{}'",
                name
            )));
        }

        let client = manager.connect().into_napi()?;

        Ok(Self {
            name,
            manager: Arc::new(ManagerWrapper(manager)),
            client: Arc::new(Mutex::new(Some(client))),
            mounts: Vec::new(),
            ports: Vec::new(),
            resources: VmResources::default(),
        })
    }

    /// Get the sandbox name.
    #[napi(getter)]
    pub fn name(&self) -> String {
        self.name.clone()
    }

    /// Get the child PID if the VM is running.
    #[napi(getter)]
    pub fn pid(&self) -> Option<i32> {
        self.manager.0.child_pid()
    }

    /// Check if the VM process is currently running.
    #[napi(getter)]
    pub fn is_running(&self) -> bool {
        self.manager.0.is_running()
    }

    /// Get the current sandbox state: "stopped", "starting", "running", or "stopping".
    #[napi]
    pub fn state(&self) -> String {
        self.manager.0.state().to_string()
    }

    /// Start the sandbox VM. Boots via fork + libkrun, waits for agent ready,
    /// then connects the vsock client.
    #[napi]
    pub async fn start(&self) -> napi::Result<()> {
        let manager = self.manager.clone();
        let mounts = self.mounts.clone();
        let ports = self.ports.clone();
        let resources = self.resources;

        tokio::task::spawn_blocking(move || {
            manager
                .0
                .ensure_running_with_full_config(mounts, ports, resources)
        })
        .await
        .map_err(|e| napi::Error::from_reason(format!("Task join error: {}", e)))?
        .into_napi()?;

        // Ensure we have a client connection
        let needs_connect = {
            let guard = self
                .client
                .lock()
                .map_err(|e| napi::Error::from_reason(format!("Client lock poisoned: {}", e)))?;
            guard.is_none()
        };

        if needs_connect {
            let manager = self.manager.clone();
            let new_client = tokio::task::spawn_blocking(move || manager.0.connect())
                .await
                .map_err(|e| napi::Error::from_reason(format!("Task join error: {}", e)))?
                .into_napi()?;

            let mut guard = self
                .client
                .lock()
                .map_err(|e| napi::Error::from_reason(format!("Client lock poisoned: {}", e)))?;
            *guard = Some(new_client);
        }

        Ok(())
    }

    /// Execute a command directly in the VM (not in a container).
    #[napi]
    pub async fn exec(
        &self,
        command: Vec<String>,
        options: Option<ExecOptions>,
    ) -> napi::Result<ExecResult> {
        let (env, workdir, timeout) = parse_exec_options(&options);
        let client = self.client.clone();

        let result = tokio::task::spawn_blocking(move || {
            let mut guard = client
                .lock()
                .map_err(|e| napi::Error::from_reason(format!("Client lock poisoned: {}", e)))?;
            let c = guard.as_mut().ok_or_else(|| {
                napi::Error::from_reason("Sandbox not started. Call start() first.")
            })?;
            c.vm_exec(command, env, workdir, timeout).into_napi()
        })
        .await
        .map_err(|e| napi::Error::from_reason(format!("Task join error: {}", e)))??;

        Ok(ExecResult {
            exit_code: result.0,
            stdout: result.1,
            stderr: result.2,
        })
    }

    /// Pull an OCI image and run a command inside it.
    ///
    /// This pulls the image (if not already cached), creates an overlay rootfs,
    /// runs the command inside it, and cleans up. Equivalent to `smolvm run`.
    #[napi]
    pub async fn run(
        &self,
        image: String,
        command: Vec<String>,
        options: Option<ExecOptions>,
    ) -> napi::Result<ExecResult> {
        let (env, workdir, timeout) = parse_exec_options(&options);

        // Pull the image first
        let client = self.client.clone();
        let image_for_pull = image.clone();
        tokio::task::spawn_blocking(move || {
            let mut guard = client
                .lock()
                .map_err(|e| napi::Error::from_reason(format!("Client lock poisoned: {}", e)))?;
            let c = guard.as_mut().ok_or_else(|| {
                napi::Error::from_reason("Sandbox not started. Call start() first.")
            })?;
            c.pull_with_registry_config(&image_for_pull).into_napi()
        })
        .await
        .map_err(|e| napi::Error::from_reason(format!("Task join error: {}", e)))??;

        // Run the command in the image's rootfs via the agent protocol
        let client = self.client.clone();
        let result = tokio::task::spawn_blocking(move || {
            let mut guard = client
                .lock()
                .map_err(|e| napi::Error::from_reason(format!("Client lock poisoned: {}", e)))?;
            let c = guard.as_mut().ok_or_else(|| {
                napi::Error::from_reason("Sandbox not started. Call start() first.")
            })?;
            c.run_with_mounts_and_timeout(&image, command, env, workdir, Vec::new(), timeout)
                .into_napi()
        })
        .await
        .map_err(|e| napi::Error::from_reason(format!("Task join error: {}", e)))??;

        Ok(ExecResult {
            exit_code: result.0,
            stdout: result.1,
            stderr: result.2,
        })
    }

    /// Pull an OCI image into the sandbox's storage.
    #[napi]
    pub async fn pull_image(&self, image: String) -> napi::Result<ImageInfo> {
        let client = self.client.clone();

        let info = tokio::task::spawn_blocking(move || {
            let mut guard = client
                .lock()
                .map_err(|e| napi::Error::from_reason(format!("Client lock poisoned: {}", e)))?;
            let c = guard.as_mut().ok_or_else(|| {
                napi::Error::from_reason("Sandbox not started. Call start() first.")
            })?;
            c.pull_with_registry_config(&image).into_napi()
        })
        .await
        .map_err(|e| napi::Error::from_reason(format!("Task join error: {}", e)))??;

        Ok(ImageInfo::from(info))
    }

    /// List all cached OCI images in the sandbox's storage.
    #[napi]
    pub async fn list_images(&self) -> napi::Result<Vec<ImageInfo>> {
        let client = self.client.clone();

        let images = tokio::task::spawn_blocking(move || {
            let mut guard = client
                .lock()
                .map_err(|e| napi::Error::from_reason(format!("Client lock poisoned: {}", e)))?;
            let c = guard.as_mut().ok_or_else(|| {
                napi::Error::from_reason("Sandbox not started. Call start() first.")
            })?;
            c.list_images().into_napi()
        })
        .await
        .map_err(|e| napi::Error::from_reason(format!("Task join error: {}", e)))??;

        Ok(images.into_iter().map(ImageInfo::from).collect())
    }

    /// Stop the sandbox VM gracefully.
    #[napi]
    pub async fn stop(&self) -> napi::Result<()> {
        // Drop the client first
        {
            let mut guard = self
                .client
                .lock()
                .map_err(|e| napi::Error::from_reason(format!("Client lock poisoned: {}", e)))?;
            *guard = None;
        }

        let manager = self.manager.clone();
        tokio::task::spawn_blocking(move || manager.0.stop().into_napi())
            .await
            .map_err(|e| napi::Error::from_reason(format!("Task join error: {}", e)))?
    }

    /// Stop the sandbox and clean up all storage (disks, config).
    #[napi]
    pub async fn delete(&self) -> napi::Result<()> {
        self.stop().await?;

        let data_dir = smolvm::agent::vm_data_dir(&self.name);
        if data_dir.exists() {
            std::fs::remove_dir_all(&data_dir).map_err(|e| {
                napi::Error::from_reason(format!(
                    "Failed to delete VM data at {}: {}",
                    data_dir.display(),
                    e
                ))
            })?;
        }

        Ok(())
    }
}
