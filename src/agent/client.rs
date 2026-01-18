//! vsock client for communicating with the smolvm-agent.
//!
//! This module provides a client for sending requests to the agent
//! and receiving responses.

use crate::error::{Error, Result};
use smolvm_protocol::{
    encode_message, AgentRequest, AgentResponse, ContainerInfo, ImageInfo, OverlayInfo,
    StorageStatus,
};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

/// Client for communicating with the smolvm-agent.
pub struct AgentClient {
    stream: UnixStream,
}

impl AgentClient {
    /// Connect to the agent via Unix socket.
    ///
    /// # Arguments
    ///
    /// * `socket_path` - Path to the vsock Unix socket
    pub fn connect(socket_path: impl AsRef<Path>) -> Result<Self> {
        let stream = UnixStream::connect(socket_path.as_ref())
            .map_err(|e| Error::AgentError(format!("failed to connect to agent: {}", e)))?;

        // Set timeouts
        stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

        Ok(Self { stream })
    }

    /// Send a request and receive a response.
    fn request(&mut self, req: &AgentRequest) -> Result<AgentResponse> {
        // Encode and send request
        let data = encode_message(req).map_err(|e| Error::AgentError(e.to_string()))?;
        self.stream
            .write_all(&data)
            .map_err(|e| Error::AgentError(format!("write failed: {}", e)))?;

        // Read response
        self.read_response()
    }

    /// Read a response from the stream.
    fn read_response(&mut self) -> Result<AgentResponse> {
        // Read length header
        let mut header = [0u8; 4];
        self.stream
            .read_exact(&mut header)
            .map_err(|e| Error::AgentError(format!("read header failed: {}", e)))?;

        let len = u32::from_be_bytes(header) as usize;

        // Read payload
        let mut buf = vec![0u8; len];
        self.stream
            .read_exact(&mut buf)
            .map_err(|e| Error::AgentError(format!("read payload failed: {}", e)))?;

        // Parse response
        serde_json::from_slice(&buf).map_err(|e| Error::AgentError(format!("parse failed: {}", e)))
    }

    /// Ping the helper daemon.
    pub fn ping(&mut self) -> Result<u32> {
        let resp = self.request(&AgentRequest::Ping)?;

        match resp {
            AgentResponse::Pong { version } => Ok(version),
            AgentResponse::Error { message, .. } => Err(Error::AgentError(message)),
            _ => Err(Error::AgentError("unexpected response".into())),
        }
    }

    /// Pull an OCI image.
    ///
    /// # Arguments
    ///
    /// * `image` - Image reference (e.g., "alpine:latest")
    /// * `platform` - Optional platform (e.g., "linux/arm64")
    pub fn pull(&mut self, image: &str, platform: Option<&str>) -> Result<ImageInfo> {
        let resp = self.request(&AgentRequest::Pull {
            image: image.to_string(),
            platform: platform.map(String::from),
        })?;

        match resp {
            AgentResponse::Ok { data: Some(data) } => {
                serde_json::from_value(data).map_err(|e| Error::AgentError(e.to_string()))
            }
            AgentResponse::Error { message, .. } => Err(Error::AgentError(message)),
            _ => Err(Error::AgentError("unexpected response".into())),
        }
    }

    /// Query if an image exists locally.
    pub fn query(&mut self, image: &str) -> Result<Option<ImageInfo>> {
        let resp = self.request(&AgentRequest::Query {
            image: image.to_string(),
        })?;

        match resp {
            AgentResponse::Ok { data: Some(data) } => {
                let info: ImageInfo =
                    serde_json::from_value(data).map_err(|e| Error::AgentError(e.to_string()))?;
                Ok(Some(info))
            }
            AgentResponse::Error { code, .. } if code.as_deref() == Some("NOT_FOUND") => Ok(None),
            AgentResponse::Error { message, .. } => Err(Error::AgentError(message)),
            _ => Err(Error::AgentError("unexpected response".into())),
        }
    }

    /// List all cached images.
    pub fn list_images(&mut self) -> Result<Vec<ImageInfo>> {
        let resp = self.request(&AgentRequest::ListImages)?;

        match resp {
            AgentResponse::Ok { data: Some(data) } => {
                serde_json::from_value(data).map_err(|e| Error::AgentError(e.to_string()))
            }
            AgentResponse::Error { message, .. } => Err(Error::AgentError(message)),
            _ => Err(Error::AgentError("unexpected response".into())),
        }
    }

    /// Run garbage collection.
    ///
    /// # Arguments
    ///
    /// * `dry_run` - If true, only report what would be deleted
    pub fn garbage_collect(&mut self, dry_run: bool) -> Result<u64> {
        let resp = self.request(&AgentRequest::GarbageCollect { dry_run })?;

        match resp {
            AgentResponse::Ok { data: Some(data) } => {
                let freed = data["freed_bytes"].as_u64().unwrap_or(0);
                Ok(freed)
            }
            AgentResponse::Error { message, .. } => Err(Error::AgentError(message)),
            _ => Err(Error::AgentError("unexpected response".into())),
        }
    }

    /// Prepare an overlay filesystem for a workload.
    ///
    /// # Arguments
    ///
    /// * `image` - Image reference
    /// * `workload_id` - Unique workload identifier
    pub fn prepare_overlay(&mut self, image: &str, workload_id: &str) -> Result<OverlayInfo> {
        let resp = self.request(&AgentRequest::PrepareOverlay {
            image: image.to_string(),
            workload_id: workload_id.to_string(),
        })?;

        match resp {
            AgentResponse::Ok { data: Some(data) } => {
                serde_json::from_value(data).map_err(|e| Error::AgentError(e.to_string()))
            }
            AgentResponse::Error { message, .. } => Err(Error::AgentError(message)),
            _ => Err(Error::AgentError("unexpected response".into())),
        }
    }

    /// Clean up an overlay filesystem.
    pub fn cleanup_overlay(&mut self, workload_id: &str) -> Result<()> {
        let resp = self.request(&AgentRequest::CleanupOverlay {
            workload_id: workload_id.to_string(),
        })?;

        match resp {
            AgentResponse::Ok { .. } => Ok(()),
            AgentResponse::Error { message, .. } => Err(Error::AgentError(message)),
            _ => Err(Error::AgentError("unexpected response".into())),
        }
    }

    /// Format the storage disk.
    pub fn format_storage(&mut self) -> Result<()> {
        let resp = self.request(&AgentRequest::FormatStorage)?;

        match resp {
            AgentResponse::Ok { .. } => Ok(()),
            AgentResponse::Error { message, .. } => Err(Error::AgentError(message)),
            _ => Err(Error::AgentError("unexpected response".into())),
        }
    }

    /// Get storage status.
    pub fn storage_status(&mut self) -> Result<StorageStatus> {
        let resp = self.request(&AgentRequest::StorageStatus)?;

        match resp {
            AgentResponse::Ok { data: Some(data) } => {
                serde_json::from_value(data).map_err(|e| Error::AgentError(e.to_string()))
            }
            AgentResponse::Error { message, .. } => Err(Error::AgentError(message)),
            _ => Err(Error::AgentError("unexpected response".into())),
        }
    }

    /// Test network connectivity directly from the agent (not via chroot).
    /// Used to debug TSI networking.
    pub fn network_test(&mut self, url: &str) -> Result<serde_json::Value> {
        let resp = self.request(&AgentRequest::NetworkTest {
            url: url.to_string(),
        })?;

        match resp {
            AgentResponse::Ok { data: Some(data) } => Ok(data),
            AgentResponse::Error { message, .. } => Err(Error::AgentError(message)),
            _ => Err(Error::AgentError("unexpected response".into())),
        }
    }

    /// Request agent shutdown.
    pub fn shutdown(&mut self) -> Result<()> {
        let resp = self.request(&AgentRequest::Shutdown)?;

        match resp {
            AgentResponse::Ok { .. } => Ok(()),
            AgentResponse::Error { message, .. } => Err(Error::AgentError(message)),
            _ => Err(Error::AgentError("unexpected response".into())),
        }
    }

    // ========================================================================
    // VM-Level Exec (Direct Execution in VM)
    // ========================================================================

    /// Execute a command directly in the VM (not in a container).
    ///
    /// This runs the command in the agent's Alpine rootfs without any
    /// container isolation. Useful for VM-level operations and debugging.
    ///
    /// # Arguments
    ///
    /// * `command` - Command and arguments
    /// * `env` - Environment variables
    /// * `workdir` - Working directory in the VM
    /// * `timeout` - Optional timeout duration
    ///
    /// # Returns
    ///
    /// A tuple of (exit_code, stdout, stderr)
    pub fn vm_exec(
        &mut self,
        command: Vec<String>,
        env: Vec<(String, String)>,
        workdir: Option<String>,
        timeout: Option<Duration>,
    ) -> Result<(i32, String, String)> {
        // Set socket read timeout based on command timeout (with buffer for response)
        let socket_timeout = match timeout {
            Some(t) => t + Duration::from_secs(5),
            None => Duration::from_secs(3600),
        };
        self.stream.set_read_timeout(Some(socket_timeout)).ok();

        let timeout_ms = timeout.map(|t| t.as_millis() as u64);

        let resp = self.request(&AgentRequest::VmExec {
            command,
            env,
            workdir,
            timeout_ms,
            interactive: false,
            tty: false,
        })?;

        // Reset timeout
        self.stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .ok();

        match resp {
            AgentResponse::Completed {
                exit_code,
                stdout,
                stderr,
            } => Ok((exit_code, stdout, stderr)),
            AgentResponse::Error { message, .. } => Err(Error::AgentError(message)),
            _ => Err(Error::AgentError("unexpected response".into())),
        }
    }

    /// Execute a command directly in the VM with interactive I/O.
    ///
    /// This method streams output directly to stdout/stderr and forwards stdin.
    /// It blocks until the command exits.
    ///
    /// # Arguments
    ///
    /// * `command` - Command and arguments
    /// * `env` - Environment variables
    /// * `workdir` - Working directory in the VM
    /// * `timeout` - Optional timeout duration
    /// * `tty` - Whether to allocate a PTY
    ///
    /// # Returns
    ///
    /// The exit code of the command
    pub fn vm_exec_interactive(
        &mut self,
        command: Vec<String>,
        env: Vec<(String, String)>,
        workdir: Option<String>,
        timeout: Option<Duration>,
        tty: bool,
    ) -> Result<i32> {
        use std::io::{stderr, stdout, Write};

        // Set long socket timeout for interactive sessions
        self.stream
            .set_read_timeout(Some(Duration::from_secs(3600)))
            .ok();

        let timeout_ms = timeout.map(|t| t.as_millis() as u64);

        // Send the vm_exec request with interactive mode
        self.send(&AgentRequest::VmExec {
            command,
            env,
            workdir,
            timeout_ms,
            interactive: true,
            tty,
        })?;

        // Wait for Started response
        let started = self.receive()?;
        match started {
            AgentResponse::Started => {}
            AgentResponse::Error { message, .. } => {
                return Err(Error::AgentError(message));
            }
            _ => {
                return Err(Error::AgentError("expected Started response".into()));
            }
        }

        // Stream I/O until we get an Exited response
        loop {
            let resp = self.receive()?;
            match resp {
                AgentResponse::Stdout { data } => {
                    stdout().write_all(&data)?;
                    stdout().flush()?;
                }
                AgentResponse::Stderr { data } => {
                    stderr().write_all(&data)?;
                    stderr().flush()?;
                }
                AgentResponse::Exited { exit_code } => {
                    return Ok(exit_code);
                }
                AgentResponse::Error { message, .. } => {
                    return Err(Error::AgentError(message));
                }
                _ => {
                    // Ignore unexpected responses
                    tracing::warn!("unexpected response during interactive VM exec session");
                }
            }
        }
    }

    /// Run a command in an image's rootfs.
    ///
    /// # Arguments
    ///
    /// * `image` - Image reference (must be pulled first)
    /// * `command` - Command and arguments
    /// * `env` - Environment variables
    /// * `workdir` - Working directory inside the rootfs
    ///
    /// # Returns
    ///
    /// A tuple of (exit_code, stdout, stderr)
    pub fn run(
        &mut self,
        image: &str,
        command: Vec<String>,
        env: Vec<(String, String)>,
        workdir: Option<String>,
    ) -> Result<(i32, String, String)> {
        self.run_with_mounts(image, command, env, workdir, Vec::new())
    }

    /// Run a command in an image's rootfs with volume mounts.
    ///
    /// # Arguments
    ///
    /// * `image` - Image reference (must be pulled first)
    /// * `command` - Command and arguments
    /// * `env` - Environment variables
    /// * `workdir` - Working directory inside the rootfs
    /// * `mounts` - Volume mounts as (virtiofs_tag, container_path, read_only)
    ///
    /// # Returns
    ///
    /// A tuple of (exit_code, stdout, stderr)
    pub fn run_with_mounts(
        &mut self,
        image: &str,
        command: Vec<String>,
        env: Vec<(String, String)>,
        workdir: Option<String>,
        mounts: Vec<(String, String, bool)>,
    ) -> Result<(i32, String, String)> {
        self.run_with_mounts_and_timeout(image, command, env, workdir, mounts, None)
    }

    /// Run a command in an image's rootfs with volume mounts and optional timeout.
    ///
    /// # Arguments
    ///
    /// * `image` - Image reference (must be pulled first)
    /// * `command` - Command and arguments
    /// * `env` - Environment variables
    /// * `workdir` - Working directory inside the rootfs
    /// * `mounts` - Volume mounts as (virtiofs_tag, container_path, read_only)
    /// * `timeout` - Optional timeout duration. If exceeded, command is killed with exit code 124.
    ///
    /// # Returns
    ///
    /// A tuple of (exit_code, stdout, stderr)
    pub fn run_with_mounts_and_timeout(
        &mut self,
        image: &str,
        command: Vec<String>,
        env: Vec<(String, String)>,
        workdir: Option<String>,
        mounts: Vec<(String, String, bool)>,
        timeout: Option<Duration>,
    ) -> Result<(i32, String, String)> {
        // Set socket read timeout based on command timeout (with buffer for response)
        let socket_timeout = match timeout {
            Some(t) => t + Duration::from_secs(5), // Add buffer for response
            None => Duration::from_secs(3600),     // Default 1 hour
        };
        self.stream.set_read_timeout(Some(socket_timeout)).ok();

        // Convert timeout to milliseconds for protocol
        let timeout_ms = timeout.map(|t| t.as_millis() as u64);

        let resp = self.request(&AgentRequest::Run {
            image: image.to_string(),
            command,
            env,
            workdir,
            mounts,
            timeout_ms,
            interactive: false,
            tty: false,
        })?;

        // Reset timeout
        self.stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .ok();

        match resp {
            AgentResponse::Completed {
                exit_code,
                stdout,
                stderr,
            } => Ok((exit_code, stdout, stderr)),
            AgentResponse::Error { message, .. } => Err(Error::AgentError(message)),
            _ => Err(Error::AgentError("unexpected response".into())),
        }
    }

    /// Run a command interactively with streaming I/O.
    ///
    /// This method streams output directly to stdout/stderr and forwards stdin.
    /// It blocks until the command exits.
    ///
    /// # Arguments
    ///
    /// * `image` - Image reference (must be pulled first)
    /// * `command` - Command and arguments
    /// * `env` - Environment variables
    /// * `workdir` - Working directory inside the rootfs
    /// * `mounts` - Volume mounts as (virtiofs_tag, container_path, read_only)
    /// * `timeout` - Optional timeout duration
    /// * `tty` - Whether to allocate a PTY
    ///
    /// # Returns
    ///
    /// The exit code of the command
    pub fn run_interactive(
        &mut self,
        image: &str,
        command: Vec<String>,
        env: Vec<(String, String)>,
        workdir: Option<String>,
        mounts: Vec<(String, String, bool)>,
        timeout: Option<Duration>,
        tty: bool,
    ) -> Result<i32> {
        use std::io::{stderr, stdout, Write};

        // Set long socket timeout for interactive sessions
        self.stream
            .set_read_timeout(Some(Duration::from_secs(3600)))
            .ok();

        // Convert timeout to milliseconds for protocol
        let timeout_ms = timeout.map(|t| t.as_millis() as u64);

        // Send the run request with interactive mode
        self.send(&AgentRequest::Run {
            image: image.to_string(),
            command,
            env,
            workdir,
            mounts,
            timeout_ms,
            interactive: true,
            tty,
        })?;

        // Wait for Started response
        let started = self.receive()?;
        match started {
            AgentResponse::Started => {}
            AgentResponse::Error { message, .. } => {
                return Err(Error::AgentError(message));
            }
            _ => {
                return Err(Error::AgentError("expected Started response".into()));
            }
        }

        // Stream I/O until we get an Exited response
        loop {
            let resp = self.receive()?;
            match resp {
                AgentResponse::Stdout { data } => {
                    stdout().write_all(&data)?;
                    stdout().flush()?;
                }
                AgentResponse::Stderr { data } => {
                    stderr().write_all(&data)?;
                    stderr().flush()?;
                }
                AgentResponse::Exited { exit_code } => {
                    return Ok(exit_code);
                }
                AgentResponse::Error { message, .. } => {
                    return Err(Error::AgentError(message));
                }
                _ => {
                    // Ignore unexpected responses
                    tracing::warn!("unexpected response during interactive session");
                }
            }
        }
    }

    /// Send stdin data to a running interactive command.
    pub fn send_stdin(&mut self, data: &[u8]) -> Result<()> {
        self.send(&AgentRequest::Stdin {
            data: data.to_vec(),
        })
    }

    /// Send a window resize event to a running interactive command.
    pub fn send_resize(&mut self, cols: u16, rows: u16) -> Result<()> {
        self.send(&AgentRequest::Resize { cols, rows })
    }

    // ========================================================================
    // Container Lifecycle (Phase 2/3)
    // ========================================================================

    /// Create a long-running container from an image.
    ///
    /// The container is created and started, ready for exec.
    ///
    /// # Arguments
    ///
    /// * `image` - Image reference (must be pulled first)
    /// * `command` - Command to run (e.g., ["sleep", "infinity"])
    /// * `env` - Environment variables
    /// * `workdir` - Working directory inside the container
    /// * `mounts` - Volume mounts as (virtiofs_tag, container_path, read_only)
    ///
    /// # Returns
    ///
    /// ContainerInfo with the container ID
    pub fn create_container(
        &mut self,
        image: &str,
        command: Vec<String>,
        env: Vec<(String, String)>,
        workdir: Option<String>,
        mounts: Vec<(String, String, bool)>,
    ) -> Result<ContainerInfo> {
        let resp = self.request(&AgentRequest::CreateContainer {
            image: image.to_string(),
            command,
            env,
            workdir,
            mounts,
        })?;

        match resp {
            AgentResponse::Ok { data: Some(data) } => {
                serde_json::from_value(data).map_err(|e| Error::AgentError(e.to_string()))
            }
            AgentResponse::Error { message, .. } => Err(Error::AgentError(message)),
            _ => Err(Error::AgentError("unexpected response".into())),
        }
    }

    /// Start a created container.
    pub fn start_container(&mut self, container_id: &str) -> Result<()> {
        let resp = self.request(&AgentRequest::StartContainer {
            container_id: container_id.to_string(),
        })?;

        match resp {
            AgentResponse::Ok { .. } => Ok(()),
            AgentResponse::Error { message, .. } => Err(Error::AgentError(message)),
            _ => Err(Error::AgentError("unexpected response".into())),
        }
    }

    /// Stop a running container.
    ///
    /// # Arguments
    ///
    /// * `container_id` - Container ID (full or prefix)
    /// * `timeout_secs` - Timeout before force kill (default: 10)
    pub fn stop_container(&mut self, container_id: &str, timeout_secs: Option<u64>) -> Result<()> {
        let resp = self.request(&AgentRequest::StopContainer {
            container_id: container_id.to_string(),
            timeout_secs,
        })?;

        match resp {
            AgentResponse::Ok { .. } => Ok(()),
            AgentResponse::Error { message, .. } => Err(Error::AgentError(message)),
            _ => Err(Error::AgentError("unexpected response".into())),
        }
    }

    /// Delete a container.
    ///
    /// # Arguments
    ///
    /// * `container_id` - Container ID (full or prefix)
    /// * `force` - Force delete even if running
    pub fn delete_container(&mut self, container_id: &str, force: bool) -> Result<()> {
        let resp = self.request(&AgentRequest::DeleteContainer {
            container_id: container_id.to_string(),
            force,
        })?;

        match resp {
            AgentResponse::Ok { .. } => Ok(()),
            AgentResponse::Error { message, .. } => Err(Error::AgentError(message)),
            _ => Err(Error::AgentError("unexpected response".into())),
        }
    }

    /// List all containers.
    pub fn list_containers(&mut self) -> Result<Vec<ContainerInfo>> {
        let resp = self.request(&AgentRequest::ListContainers)?;

        match resp {
            AgentResponse::Ok { data: Some(data) } => {
                serde_json::from_value(data).map_err(|e| Error::AgentError(e.to_string()))
            }
            AgentResponse::Ok { data: None } => Ok(Vec::new()),
            AgentResponse::Error { message, .. } => Err(Error::AgentError(message)),
            _ => Err(Error::AgentError("unexpected response".into())),
        }
    }

    /// Execute a command in a running container.
    ///
    /// Unlike `run`, this executes in an existing container created with `create_container`.
    ///
    /// # Arguments
    ///
    /// * `container_id` - Container ID (full or prefix)
    /// * `command` - Command and arguments to execute
    /// * `env` - Environment variables for this exec
    /// * `workdir` - Working directory for this exec
    /// * `timeout` - Optional timeout duration
    ///
    /// # Returns
    ///
    /// A tuple of (exit_code, stdout, stderr)
    pub fn exec(
        &mut self,
        container_id: &str,
        command: Vec<String>,
        env: Vec<(String, String)>,
        workdir: Option<String>,
        timeout: Option<Duration>,
    ) -> Result<(i32, String, String)> {
        // Set socket read timeout based on command timeout (with buffer for response)
        let socket_timeout = match timeout {
            Some(t) => t + Duration::from_secs(5),
            None => Duration::from_secs(3600),
        };
        self.stream.set_read_timeout(Some(socket_timeout)).ok();

        let timeout_ms = timeout.map(|t| t.as_millis() as u64);

        let resp = self.request(&AgentRequest::Exec {
            container_id: container_id.to_string(),
            command,
            env,
            workdir,
            timeout_ms,
        })?;

        // Reset timeout
        self.stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .ok();

        match resp {
            AgentResponse::Completed {
                exit_code,
                stdout,
                stderr,
            } => Ok((exit_code, stdout, stderr)),
            AgentResponse::Error { message, .. } => Err(Error::AgentError(message)),
            _ => Err(Error::AgentError("unexpected response".into())),
        }
    }

    /// Low-level send without waiting for response.
    fn send(&mut self, request: &AgentRequest) -> Result<()> {
        let json = serde_json::to_vec(request)
            .map_err(|e| Error::AgentError(format!("serialize error: {}", e)))?;
        let len = json.len() as u32;

        self.stream.write_all(&len.to_be_bytes())?;
        self.stream.write_all(&json)?;
        self.stream.flush()?;

        Ok(())
    }

    /// Low-level receive a single response.
    fn receive(&mut self) -> Result<AgentResponse> {
        let mut header = [0u8; 4];
        self.stream.read_exact(&mut header)?;
        let len = u32::from_be_bytes(header) as usize;

        let mut buf = vec![0u8; len];
        self.stream.read_exact(&mut buf)?;

        let resp: AgentResponse = serde_json::from_slice(&buf)
            .map_err(|e| Error::AgentError(format!("deserialize error: {}", e)))?;
        Ok(resp)
    }
}
