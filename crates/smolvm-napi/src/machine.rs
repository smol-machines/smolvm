//! NapiMachine — the main NAPI class for embedded Machine operations.
//!
//! All blocking operations run on tokio's blocking thread pool. VM process
//! handles live in a process-local runtime registry so multiple JS objects and
//! worker threads coordinate through the same cached handle per machine name.

use napi::bindgen_prelude::Buffer;
use napi_derive::napi;

use crate::error::IntoNapiResult;
use crate::types::*;
use smolvm::embedded::{runtime, MachineSpec};

fn join_error(err: tokio::task::JoinError) -> napi::Error {
    napi::Error::from_reason(format!("Task join error: {}", err))
}

#[napi]
pub struct NapiMachine {
    name: String,
}

#[napi]
impl NapiMachine {
    /// Create a new machine. Does not start the VM yet — call `start()`.
    #[napi(constructor)]
    pub fn new(config: MachineConfig) -> napi::Result<Self> {
        let mounts = config
            .mounts
            .as_ref()
            .map(|ms| {
                ms.iter()
                    .map(smolvm::agent::HostMount::try_from)
                    .collect::<smolvm::Result<_>>()
            })
            .transpose()
            .into_napi()?
            .unwrap_or_default();

        let ports = config
            .ports
            .as_ref()
            .map(|ps| {
                ps.iter()
                    .map(smolvm::data::network::PortMapping::from)
                    .collect()
            })
            .unwrap_or_default();

        let resources = config
            .resources
            .as_ref()
            .map(|r| r.to_vm_resources())
            .unwrap_or_default();

        let spec = MachineSpec {
            name: config.name.clone(),
            mounts,
            ports,
            resources,
            persistent: config.persistent.unwrap_or(false),
        };

        runtime().into_napi()?.create_machine(spec).into_napi()?;

        Ok(Self { name: config.name })
    }

    /// Connect to an already-running VM by name.
    ///
    /// Returns an error if no running VM is found with the given name.
    #[napi(factory)]
    pub fn connect(name: String) -> napi::Result<Self> {
        runtime().into_napi()?.connect_machine(&name).into_napi()?;
        Ok(Self { name })
    }

    /// Get the machine name.
    #[napi(getter)]
    pub fn name(&self) -> String {
        self.name.clone()
    }

    /// Get the child PID if the VM is running.
    #[napi(getter)]
    pub fn pid(&self) -> Option<i32> {
        runtime().ok().and_then(|runtime| runtime.pid(&self.name))
    }

    /// Check if the VM process is currently running.
    #[napi(getter)]
    pub fn is_running(&self) -> bool {
        runtime()
            .map(|runtime| runtime.is_running(&self.name))
            .unwrap_or(false)
    }

    /// Get the current machine state: "stopped", "starting", "running", or "stopping".
    #[napi]
    pub fn state(&self) -> String {
        runtime()
            .map(|runtime| runtime.state(&self.name))
            .unwrap_or_else(|_| "stopped".to_string())
    }

    /// Start the machine VM. Boots via fork + libkrun, waits for agent ready,
    /// then connects the vsock client.
    #[napi]
    pub async fn start(&self) -> napi::Result<()> {
        let runtime = runtime().into_napi()?;
        let name = self.name.clone();
        tokio::task::spawn_blocking(move || runtime.start_machine(&name))
            .await
            .map_err(join_error)?
            .into_napi()
    }

    /// Execute a command directly in the VM (not in a container).
    #[napi]
    pub async fn exec(
        &self,
        command: Vec<String>,
        options: Option<ExecOptions>,
    ) -> napi::Result<ExecResult> {
        let runtime = runtime().into_napi()?;
        let name = self.name.clone();
        let (env, workdir, timeout) = parse_exec_options(options);

        let result = tokio::task::spawn_blocking(move || {
            runtime.exec(&name, command, env, workdir, timeout)
        })
        .await
        .map_err(join_error)?
        .into_napi()?;

        Ok(ExecResult {
            exit_code: result.0,
            stdout: String::from_utf8_lossy(&result.1).into_owned(),
            stderr: String::from_utf8_lossy(&result.2).into_owned(),
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
        let runtime = runtime().into_napi()?;
        let name = self.name.clone();
        let (env, workdir, timeout) = parse_exec_options(options);

        let result = tokio::task::spawn_blocking(move || {
            runtime.run(&name, &image, command, env, workdir, timeout)
        })
        .await
        .map_err(join_error)?
        .into_napi()?;

        Ok(ExecResult {
            exit_code: result.0,
            stdout: String::from_utf8_lossy(&result.1).into_owned(),
            stderr: String::from_utf8_lossy(&result.2).into_owned(),
        })
    }

    /// Pull an OCI image into the machine's storage.
    #[napi]
    pub async fn pull_image(&self, image: String) -> napi::Result<ImageInfo> {
        let runtime = runtime().into_napi()?;
        let name = self.name.clone();

        let info = tokio::task::spawn_blocking(move || runtime.pull_image(&name, &image))
            .await
            .map_err(join_error)?
            .into_napi()?;

        Ok(ImageInfo::from(info))
    }

    /// List all cached OCI images in the machine's storage.
    #[napi]
    pub async fn list_images(&self) -> napi::Result<Vec<ImageInfo>> {
        let runtime = runtime().into_napi()?;
        let name = self.name.clone();

        let images = tokio::task::spawn_blocking(move || runtime.list_images(&name))
            .await
            .map_err(join_error)?
            .into_napi()?;

        Ok(images.into_iter().map(ImageInfo::from).collect())
    }

    /// Write a file into the running VM.
    #[napi]
    pub async fn write_file(
        &self,
        path: String,
        data: Buffer,
        options: Option<FileWriteOptions>,
    ) -> napi::Result<()> {
        let runtime = runtime().into_napi()?;
        let name = self.name.clone();
        let mode = options.and_then(|opts| opts.mode);
        let data = data.to_vec();

        tokio::task::spawn_blocking(move || runtime.write_file(&name, &path, data, mode))
            .await
            .map_err(join_error)?
            .into_napi()
    }

    /// Read a file from the running VM.
    #[napi]
    pub async fn read_file(&self, path: String) -> napi::Result<Buffer> {
        let runtime = runtime().into_napi()?;
        let name = self.name.clone();

        let data = tokio::task::spawn_blocking(move || runtime.read_file(&name, &path))
            .await
            .map_err(join_error)?
            .into_napi()?;

        Ok(data.into())
    }

    /// Execute a command and return streaming stdout/stderr/exit events.
    #[napi]
    pub async fn exec_streaming(
        &self,
        command: Vec<String>,
        options: Option<ExecOptions>,
    ) -> napi::Result<Vec<ExecStreamEvent>> {
        let runtime = runtime().into_napi()?;
        let name = self.name.clone();
        let (env, workdir, timeout) = parse_exec_options(options);

        let events = tokio::task::spawn_blocking(move || {
            runtime.exec_streaming(&name, command, env, workdir, timeout)
        })
        .await
        .map_err(join_error)?
        .into_napi()?;

        Ok(events.into_iter().map(ExecStreamEvent::from).collect())
    }

    /// Stop the machine VM gracefully.
    #[napi]
    pub async fn stop(&self) -> napi::Result<()> {
        let runtime = runtime().into_napi()?;
        let name = self.name.clone();
        tokio::task::spawn_blocking(move || runtime.stop_machine(&name))
            .await
            .map_err(join_error)?
            .into_napi()
    }

    /// Stop the machine and clean up all storage (disks, config).
    #[napi]
    pub async fn delete(&self) -> napi::Result<()> {
        let runtime = runtime().into_napi()?;
        let name = self.name.clone();
        tokio::task::spawn_blocking(move || runtime.delete_machine(&name))
            .await
            .map_err(join_error)?
            .into_napi()
    }
}
