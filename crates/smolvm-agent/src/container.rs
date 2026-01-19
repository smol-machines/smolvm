//! Container registry for tracking long-running containers.
//!
//! This module provides container lifecycle management using crun OCI runtime.
//! Containers can be created, started, exec'd into, and deleted.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

use crate::oci::{generate_container_id, OciSpec};
use crate::storage;

/// Error type for container operations (reuses storage error).
pub use crate::storage::StorageError;

/// Path to crun binary.
const CRUN_PATH: &str = "/usr/bin/crun";

/// Storage root path.
const STORAGE_ROOT: &str = "/storage";

/// Directory for overlay filesystems.
const OVERLAYS_DIR: &str = "overlays";

/// Container state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerState {
    /// Container has been created but not started.
    Created,
    /// Container is running.
    Running,
    /// Container has stopped.
    Stopped,
}

impl std::fmt::Display for ContainerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContainerState::Created => write!(f, "created"),
            ContainerState::Running => write!(f, "running"),
            ContainerState::Stopped => write!(f, "stopped"),
        }
    }
}

/// Information about a container.
#[derive(Debug, Clone)]
pub struct ContainerInfo {
    /// Unique container ID.
    pub id: String,
    /// Image the container was created from.
    pub image: String,
    /// Path to the OCI bundle directory.
    #[allow(dead_code)] // Stored for debugging and potential future use
    pub bundle_path: PathBuf,
    /// Current container state.
    pub state: ContainerState,
    /// Creation timestamp (Unix epoch seconds).
    pub created_at: u64,
    /// Command the container is running.
    pub command: Vec<String>,
}

/// Global container registry.
pub struct ContainerRegistry {
    containers: RwLock<HashMap<String, ContainerInfo>>,
}

impl ContainerRegistry {
    /// Create a new empty container registry.
    pub fn new() -> Self {
        Self {
            containers: RwLock::new(HashMap::new()),
        }
    }

    /// Register a new container.
    pub fn register(&self, info: ContainerInfo) {
        let mut containers = self.containers.write().unwrap_or_else(|e| e.into_inner());
        info!(container_id = %info.id, image = %info.image, "registered container");
        containers.insert(info.id.clone(), info);
    }

    /// Unregister a container.
    pub fn unregister(&self, id: &str) -> Option<ContainerInfo> {
        let mut containers = self.containers.write().unwrap_or_else(|e| e.into_inner());
        let removed = containers.remove(id);
        if removed.is_some() {
            info!(container_id = %id, "unregistered container");
        }
        removed
    }

    /// Get a container by ID.
    #[allow(dead_code)] // Used in tests
    pub fn get(&self, id: &str) -> Option<ContainerInfo> {
        let containers = self.containers.read().unwrap_or_else(|e| e.into_inner());
        containers.get(id).cloned()
    }

    /// Update container state.
    pub fn update_state(&self, id: &str, state: ContainerState) {
        let mut containers = self.containers.write().unwrap_or_else(|e| e.into_inner());
        if let Some(info) = containers.get_mut(id) {
            info.state = state;
            debug!(container_id = %id, state = %state, "updated container state");
        }
    }

    /// List all containers.
    pub fn list(&self) -> Vec<ContainerInfo> {
        let containers = self.containers.read().unwrap_or_else(|e| e.into_inner());
        containers.values().cloned().collect()
    }

    /// Find container by ID prefix (for short IDs).
    pub fn find_by_prefix(&self, prefix: &str) -> Option<ContainerInfo> {
        let containers = self.containers.read().unwrap_or_else(|e| e.into_inner());

        // First try exact match
        if let Some(info) = containers.get(prefix) {
            return Some(info.clone());
        }

        // Then try prefix match
        let matches: Vec<_> = containers
            .iter()
            .filter(|(id, _)| id.starts_with(prefix))
            .collect();

        if matches.len() == 1 {
            return Some(matches[0].1.clone());
        }

        None
    }
}

impl Default for ContainerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// Global registry instance
lazy_static::lazy_static! {
    /// Global container registry.
    pub static ref REGISTRY: ContainerRegistry = ContainerRegistry::new();
}

/// Result of running a command in a container.
pub struct ExecResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Create a long-running container and start it immediately.
///
/// This creates the overlay, OCI bundle, and calls `crun run --detach`.
/// The container starts running immediately in the background.
pub fn create_container(
    image: &str,
    command: &[String],
    env: &[(String, String)],
    workdir: Option<&str>,
    mounts: &[(String, String, bool)],
) -> Result<ContainerInfo, StorageError> {
    // Generate unique container ID
    let container_id = generate_container_id();

    // Use container ID as workload ID for unique overlay
    let workload_id = format!("container-{}", &container_id);

    // Prepare overlay filesystem
    let overlay = storage::prepare_overlay(image, &workload_id)?;

    // Setup volume mounts
    storage::setup_mounts(&overlay.rootfs_path, mounts)?;

    // Get bundle path
    let overlay_root = Path::new(STORAGE_ROOT)
        .join(OVERLAYS_DIR)
        .join(&workload_id);
    let bundle_path = overlay_root.join("bundle");

    // Create OCI spec
    let workdir_str = workdir.unwrap_or("/");
    let mut spec = OciSpec::new(command, env, workdir_str, false);

    // Add bind mounts for virtiofs volumes
    for (tag, container_path, read_only) in mounts {
        let virtiofs_mount = Path::new("/mnt/virtiofs").join(tag);
        spec.add_bind_mount(
            &virtiofs_mount.to_string_lossy(),
            container_path,
            *read_only,
        );
    }

    // Write config.json
    spec.write_to(&bundle_path)
        .map_err(|e| StorageError::new(format!("failed to write OCI spec: {}", e)))?;

    // Create and start the container with crun run --detach
    // Using spawn() with null stdio to avoid blocking on pipe EOF
    info!(container_id = %container_id, bundle = %bundle_path.display(), "creating container");

    let mut child = Command::new(CRUN_PATH)
        .args([
            "run",
            "--detach",
            "--bundle",
            &bundle_path.to_string_lossy(),
            &container_id,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| StorageError::new(format!("failed to spawn crun: {}", e)))?;

    // Wait for crun to complete (should be fast with --detach)
    let status = child
        .wait()
        .map_err(|e| StorageError::new(format!("failed to wait for crun: {}", e)))?;

    if !status.success() {
        let mut stderr = String::new();
        if let Some(mut err) = child.stderr.take() {
            use std::io::Read as _;
            let _ = err.read_to_string(&mut stderr);
        }
        return Err(StorageError::new(format!("crun run failed: {}", stderr)));
    }

    // Get current timestamp
    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let info = ContainerInfo {
        id: container_id,
        image: image.to_string(),
        bundle_path,
        state: ContainerState::Running, // Container starts immediately
        created_at,
        command: command.to_vec(),
    };

    // Register in global registry
    REGISTRY.register(info.clone());

    Ok(info)
}

/// Start a container.
///
/// Since containers are started immediately upon creation with `crun run --detach`,
/// this function checks if the container is running and returns success if so.
/// For stopped containers, it attempts to restart by recreating the container.
pub fn start_container(container_id: &str) -> Result<(), StorageError> {
    // Find container
    let info = REGISTRY
        .find_by_prefix(container_id)
        .ok_or_else(|| StorageError::new(format!("container not found: {}", container_id)))?;

    // Check actual state from crun
    if let Ok(state) = get_crun_state(&info.id) {
        if state == "running" {
            info!(container_id = %info.id, "container already running");
            REGISTRY.update_state(&info.id, ContainerState::Running);
            return Ok(());
        }
    }

    // Container is not running - we can't restart it with crun start since we used run --detach
    // The user needs to delete and recreate the container
    Err(StorageError::new(format!(
        "container {} is not running. Use 'container rm' and 'container create' to restart.",
        info.id
    )))
}

/// Execute a command in a running container.
pub fn exec_in_container(
    container_id: &str,
    command: &[String],
    env: &[(String, String)],
    workdir: Option<&str>,
    timeout_ms: Option<u64>,
) -> Result<ExecResult, StorageError> {
    use std::io::Read as _;
    use std::time::{Duration, Instant};

    // Find container
    let info = REGISTRY
        .find_by_prefix(container_id)
        .ok_or_else(|| StorageError::new(format!("container not found: {}", container_id)))?;

    // Check container is running
    let state = get_crun_state(&info.id)?;
    if state != "running" {
        return Err(StorageError::new(format!(
            "container {} is not running (state: {})",
            info.id, state
        )));
    }

    info!(
        container_id = %info.id,
        command = ?command,
        "executing command in container"
    );

    // Build crun exec command
    let mut cmd = Command::new(CRUN_PATH);
    cmd.arg("exec");

    // Add environment variables
    for (key, value) in env {
        cmd.args(["--env", &format!("{}={}", key, value)]);
    }

    // Add working directory
    if let Some(wd) = workdir {
        cmd.args(["--cwd", wd]);
    }

    // Add container ID and command
    cmd.arg(&info.id);
    cmd.args(command);

    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    // Spawn the exec
    let mut child = cmd
        .spawn()
        .map_err(|e| StorageError::new(format!("failed to spawn crun exec: {}", e)))?;

    let start = Instant::now();
    let deadline = timeout_ms.map(|ms| start + Duration::from_millis(ms));

    // Poll for completion with timeout
    loop {
        match child.try_wait()? {
            Some(status) => {
                let mut stdout = String::new();
                let mut stderr = String::new();

                if let Some(mut out) = child.stdout.take() {
                    let _ = out.read_to_string(&mut stdout);
                }
                if let Some(mut err) = child.stderr.take() {
                    let _ = err.read_to_string(&mut stderr);
                }

                let exit_code = status.code().unwrap_or(-1);
                debug!(
                    container_id = %info.id,
                    exit_code = exit_code,
                    "exec completed"
                );

                return Ok(ExecResult {
                    exit_code,
                    stdout,
                    stderr,
                });
            }
            None => {
                if let Some(deadline) = deadline {
                    if Instant::now() >= deadline {
                        warn!(container_id = %info.id, "exec timed out");
                        let _ = child.kill();
                        let _ = child.wait();

                        return Ok(ExecResult {
                            exit_code: 124, // Timeout exit code
                            stdout: String::new(),
                            stderr: format!("exec timed out after {}ms", timeout_ms.unwrap_or(0)),
                        });
                    }
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

/// Stop a running container.
pub fn stop_container(container_id: &str, timeout_secs: u64) -> Result<(), StorageError> {
    let info = REGISTRY
        .find_by_prefix(container_id)
        .ok_or_else(|| StorageError::new(format!("container not found: {}", container_id)))?;

    info!(container_id = %info.id, timeout_secs = timeout_secs, "stopping container");

    // Send SIGTERM first
    let _ = Command::new(CRUN_PATH)
        .args(["kill", &info.id, "SIGTERM"])
        .status();

    // Wait for container to stop
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(timeout_secs);

    while start.elapsed() < timeout {
        if let Ok(state) = get_crun_state(&info.id) {
            if state == "stopped" {
                REGISTRY.update_state(&info.id, ContainerState::Stopped);
                return Ok(());
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    // Force kill if still running
    warn!(container_id = %info.id, "container didn't stop gracefully, force killing");
    let _ = Command::new(CRUN_PATH)
        .args(["kill", &info.id, "SIGKILL"])
        .status();

    REGISTRY.update_state(&info.id, ContainerState::Stopped);

    Ok(())
}

/// Delete a container (must be stopped).
pub fn delete_container(container_id: &str, force: bool) -> Result<(), StorageError> {
    let info = REGISTRY
        .find_by_prefix(container_id)
        .ok_or_else(|| StorageError::new(format!("container not found: {}", container_id)))?;

    // Check if running
    if let Ok(state) = get_crun_state(&info.id) {
        if state == "running" {
            if force {
                stop_container(&info.id, 5)?;
            } else {
                return Err(StorageError::new(format!(
                    "container {} is still running, stop it first or use force",
                    info.id
                )));
            }
        }
    }

    info!(container_id = %info.id, "deleting container");

    // Delete with crun
    let mut cmd = Command::new(CRUN_PATH);
    cmd.args(["delete"]);
    if force {
        cmd.arg("-f");
    }
    cmd.arg(&info.id);

    let output = cmd
        .output()
        .map_err(|e| StorageError::new(format!("failed to run crun delete: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Ignore "does not exist" errors
        if !stderr.contains("does not exist") {
            warn!(container_id = %info.id, error = %stderr, "crun delete warning");
        }
    }

    // Clean up overlay
    let workload_id = format!("container-{}", &info.id);
    if let Err(e) = storage::cleanup_overlay(&workload_id) {
        warn!(container_id = %info.id, error = %e, "failed to cleanup overlay");
    }

    // Unregister from registry
    REGISTRY.unregister(&info.id);

    Ok(())
}

/// List all containers with their current state.
pub fn list_containers() -> Vec<ContainerInfo> {
    let mut containers = REGISTRY.list();

    // Update states from crun
    for container in &mut containers {
        if let Ok(state) = get_crun_state(&container.id) {
            container.state = match state.as_str() {
                "running" => ContainerState::Running,
                "stopped" | "exited" => ContainerState::Stopped,
                "created" => ContainerState::Created,
                _ => container.state,
            };
        }
    }

    containers
}

/// Get container state from crun.
fn get_crun_state(container_id: &str) -> Result<String, StorageError> {
    let output = Command::new(CRUN_PATH)
        .args(["state", container_id])
        .output()
        .map_err(|e| StorageError::new(format!("failed to run crun state: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(StorageError::new(format!("crun state failed: {}", stderr)));
    }

    let state_json: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| StorageError::new(format!("failed to parse crun state: {}", e)))?;

    state_json["status"]
        .as_str()
        .map(String::from)
        .ok_or_else(|| StorageError("missing status in crun state".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_basic() {
        let registry = ContainerRegistry::new();

        let info = ContainerInfo {
            id: "test-123".to_string(),
            image: "alpine:latest".to_string(),
            bundle_path: PathBuf::from("/tmp/bundle"),
            state: ContainerState::Created,
            created_at: 12345,
            command: vec!["sleep".to_string(), "infinity".to_string()],
        };

        registry.register(info.clone());

        assert!(registry.get("test-123").is_some());
        assert!(registry.get("nonexistent").is_none());

        registry.update_state("test-123", ContainerState::Running);
        assert_eq!(
            registry.get("test-123").unwrap().state,
            ContainerState::Running
        );

        registry.unregister("test-123");
        assert!(registry.get("test-123").is_none());
    }

    #[test]
    fn test_find_by_prefix() {
        let registry = ContainerRegistry::new();

        let info = ContainerInfo {
            id: "smolvm-abc123def456".to_string(),
            image: "alpine:latest".to_string(),
            bundle_path: PathBuf::from("/tmp/bundle"),
            state: ContainerState::Running,
            created_at: 12345,
            command: vec!["sh".to_string()],
        };

        registry.register(info);

        // Exact match
        assert!(registry.find_by_prefix("smolvm-abc123def456").is_some());

        // Prefix match
        assert!(registry.find_by_prefix("smolvm-abc").is_some());

        // No match
        assert!(registry.find_by_prefix("xyz").is_none());
    }
}
