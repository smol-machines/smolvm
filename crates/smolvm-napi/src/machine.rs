//! NapiMachine — the main NAPI class wrapping AgentManager + AgentClient.
//!
//! All blocking operations (start, exec, pull, stop) run on tokio's blocking
//! thread pool to avoid blocking Node's event loop. The AgentManager and
//! AgentClient are wrapped in Arc<Mutex<>> for safe cross-thread access.
//!
//! Lifecycle operations (new, stop, delete) now persist to SmolvmDb via the
//! control layer, fixing the bug where SDK-created VMs were invisible to CLI/API.

use std::sync::{Arc, Mutex};

use napi_derive::napi;

use smolvm::agent::{AgentClient, AgentManager, HostMount, VmResources};
use smolvm::data::network::PortMapping;
use smolvm::data::vm::{MicroVm, VmSpec};
use smolvm::db::SmolvmDb;

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
pub struct NapiMachine {
    name: String,
    manager: Arc<ManagerWrapper>,
    client: Arc<Mutex<Option<AgentClient>>>,
    mounts: Vec<HostMount>,
    ports: Vec<PortMapping>,
    resources: VmResources,
}

#[napi]
impl NapiMachine {
    /// Create a new machine. Does not start the VM yet — call `start()`.
    ///
    /// Persists the VM to SmolvmDb so it's visible to CLI (`smolvm machine ls`)
    /// and the HTTP API.
    #[napi(constructor)]
    pub fn new(config: MachineConfig) -> napi::Result<Self> {
        let mounts: Vec<HostMount> = config
            .mounts
            .as_ref()
            .map(|ms| {
                ms.iter()
                    .map(HostMount::try_from)
                    .collect::<smolvm::Result<_>>()
            })
            .transpose()
            .into_napi()?
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

        // Persist to DB via control layer (fixes SDK visibility bug)
        let vm = MicroVm {
            name: config.name.clone(),
            spec: VmSpec {
                resources,
                mounts: mounts.clone(),
                ports: ports.clone(),
                image: None,
                entrypoint: Vec::new(),
                cmd: Vec::new(),
                env: Vec::new(),
                workdir: None,
                init: Vec::new(),
            },
            status: None,
        };

        let db = SmolvmDb::open().into_napi()?;
        smolvm::control::create_vm(&db, vm).into_napi()?;

        // Create AgentManager for runtime operations
        let manager = AgentManager::for_vm_with_sizes(
            &config.name,
            resources.storage_gib,
            resources.overlay_gib,
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
        // Verify VM exists in DB
        let db = SmolvmDb::open().into_napi()?;
        let vm = smolvm::control::get_vm(&db, &name).into_napi()?;

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
            mounts: vm.spec.mounts,
            ports: vm.spec.ports,
            resources: vm.spec.resources,
        })
    }

    /// Get the machine name.
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

    /// Get the current machine state: "stopped", "starting", "running", or "stopping".
    #[napi]
    pub fn state(&self) -> String {
        self.manager.0.state().to_string()
    }

    /// Start the machine VM. Boots via fork + libkrun, waits for agent ready,
    /// then connects the vsock client.
    ///
    /// Persists Running state to SmolvmDb.
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

        // Persist running state to DB
        let name = self.name.clone();
        let pid = self.manager.0.child_pid();
        tokio::task::spawn_blocking(move || {
            if let Ok(db) = SmolvmDb::open() {
                let pid_start_time = pid.and_then(smolvm::process::process_start_time);
                let _ = db.update_vm(&name, |r| {
                    r.state = smolvm::config::RecordState::Running;
                    r.pid = pid;
                    r.pid_start_time = pid_start_time;
                });
            }
        })
        .await
        .map_err(|e| napi::Error::from_reason(format!("Task join error: {}", e)))?;

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
                napi::Error::from_reason("Machine not started. Call start() first.")
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
                napi::Error::from_reason("Machine not started. Call start() first.")
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
                napi::Error::from_reason("Machine not started. Call start() first.")
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

    /// Pull an OCI image into the machine's storage.
    #[napi]
    pub async fn pull_image(&self, image: String) -> napi::Result<ImageInfo> {
        let client = self.client.clone();

        let info = tokio::task::spawn_blocking(move || {
            let mut guard = client
                .lock()
                .map_err(|e| napi::Error::from_reason(format!("Client lock poisoned: {}", e)))?;
            let c = guard.as_mut().ok_or_else(|| {
                napi::Error::from_reason("Machine not started. Call start() first.")
            })?;
            c.pull_with_registry_config(&image).into_napi()
        })
        .await
        .map_err(|e| napi::Error::from_reason(format!("Task join error: {}", e)))??;

        Ok(ImageInfo::from(info))
    }

    /// List all cached OCI images in the machine's storage.
    #[napi]
    pub async fn list_images(&self) -> napi::Result<Vec<ImageInfo>> {
        let client = self.client.clone();

        let images = tokio::task::spawn_blocking(move || {
            let mut guard = client
                .lock()
                .map_err(|e| napi::Error::from_reason(format!("Client lock poisoned: {}", e)))?;
            let c = guard.as_mut().ok_or_else(|| {
                napi::Error::from_reason("Machine not started. Call start() first.")
            })?;
            c.list_images().into_napi()
        })
        .await
        .map_err(|e| napi::Error::from_reason(format!("Task join error: {}", e)))??;

        Ok(images.into_iter().map(ImageInfo::from).collect())
    }

    /// Stop the machine VM gracefully.
    ///
    /// Persists Stopped state to SmolvmDb.
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
            .map_err(|e| napi::Error::from_reason(format!("Task join error: {}", e)))??;

        // Persist stopped state to DB
        let name = self.name.clone();
        tokio::task::spawn_blocking(move || {
            if let Ok(db) = SmolvmDb::open() {
                let _ = db.update_vm(&name, |r| {
                    r.state = smolvm::config::RecordState::Stopped;
                    r.pid = None;
                    r.pid_start_time = None;
                });
            }
        })
        .await
        .map_err(|e| napi::Error::from_reason(format!("Task join error: {}", e)))?;

        Ok(())
    }

    /// Stop the machine and clean up all storage (disks, config, DB record).
    #[napi]
    pub async fn delete(&self) -> napi::Result<()> {
        self.stop().await?;

        // Delete via control layer (removes DB record + data directory)
        let name = self.name.clone();
        tokio::task::spawn_blocking(move || {
            if let Ok(db) = SmolvmDb::open() {
                let _ = smolvm::control::delete_vm(&db, &name, true);
            }
        })
        .await
        .map_err(|e| napi::Error::from_reason(format!("Task join error: {}", e)))?;

        Ok(())
    }
}
