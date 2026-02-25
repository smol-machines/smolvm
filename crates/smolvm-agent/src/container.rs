//! Container registry for tracking long-running containers.
//!
//! This module provides container lifecycle management using crun OCI runtime.
//! Containers can be created, started, exec'd into, and deleted.
//!
//! The registry is persisted to disk at `/storage/containers/registry.json`
//! and reconciled with actual container state on agent startup.
//!
//! ## State Versioning
//!
//! The registry includes version information to:
//! - Detect stale state after crashes or unexpected restarts
//! - Enable future schema migrations
//! - Track when state was last modified

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::crun::CrunCommand;
use crate::oci::{generate_container_id, OciSpec};
use crate::paths;
use crate::process::{wait_with_timeout, WaitResult, TIMEOUT_EXIT_CODE};
use crate::storage;

/// Error type for container operations (reuses storage error).
pub use crate::storage::StorageError;

// ============================================================================
// Timeout Configuration Constants
// ============================================================================

/// Timeout for crun create/start operations in milliseconds.
/// 10 seconds is generous for container creation which should be quick.
const CRUN_OPERATION_TIMEOUT_MS: u64 = 10_000;

/// Poll interval for checking crun operation completion.
const CRUN_POLL_INTERVAL_MS: u64 = 100;

/// Retry interval when waiting for registry lock acquisition.
const LOCK_RETRY_INTERVAL_MS: u64 = 10;

/// Poll interval when checking if a container has stopped.
const CONTAINER_STOP_POLL_INTERVAL_MS: u64 = 100;

/// Current schema version for the registry file format.
///
/// Increment this when making breaking changes to the registry format.
/// The registry loader will handle migrations when loading older versions.
const REGISTRY_SCHEMA_VERSION: u32 = 1;

/// Persisted registry state with version information.
///
/// This wrapper provides:
/// - Schema versioning for future migrations
/// - Timestamp tracking for staleness detection
/// - Atomic state updates
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RegistryState {
    /// Schema version for migration support.
    #[serde(default = "default_schema_version")]
    version: u32,

    /// Unix timestamp when registry was last modified.
    #[serde(default)]
    last_modified: u64,

    /// Unique instance ID to detect state from different agent runs.
    /// Generated on agent startup and persisted with each save.
    #[serde(default)]
    instance_id: u64,

    /// The actual container data.
    containers: HashMap<String, ContainerInfo>,
}

fn default_schema_version() -> u32 {
    1
}

/// Get current Unix timestamp in seconds.
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Generate a unique instance ID for this agent run.
fn generate_instance_id() -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    current_timestamp().hash(&mut hasher);
    std::process::id().hash(&mut hasher);
    hasher.finish()
}

/// RAII guard for registry file lock.
///
/// Acquires an exclusive lock on the registry lock file when created,
/// releases it when dropped.
struct RegistryLock {
    _file: File,
}

impl RegistryLock {
    /// Acquire an exclusive lock on the registry, with timeout.
    fn acquire() -> Result<Self, StorageError> {
        // Ensure lock directory exists
        if let Some(parent) = Path::new(paths::REGISTRY_LOCK_PATH).parent() {
            fs::create_dir_all(parent)
                .map_err(|e| StorageError::new(format!("failed to create lock dir: {}", e)))?;
        }

        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(paths::REGISTRY_LOCK_PATH)
            .map_err(|e| StorageError::new(format!("failed to open lock file: {}", e)))?;

        let fd = file.as_raw_fd();
        let start = Instant::now();
        let timeout = Duration::from_millis(paths::REGISTRY_LOCK_TIMEOUT_MS);

        loop {
            // Try non-blocking lock
            let result = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };

            if result == 0 {
                // Lock acquired
                debug!("acquired registry lock");
                return Ok(Self { _file: file });
            }

            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::WouldBlock {
                return Err(StorageError::new(format!(
                    "failed to acquire lock: {}",
                    err
                )));
            }

            // Check timeout
            if start.elapsed() >= timeout {
                return Err(StorageError::new(format!(
                    "timeout acquiring registry lock after {}ms",
                    paths::REGISTRY_LOCK_TIMEOUT_MS
                )));
            }

            // Wait a bit and retry
            std::thread::sleep(Duration::from_millis(LOCK_RETRY_INTERVAL_MS));
        }
    }
}

impl Drop for RegistryLock {
    fn drop(&mut self) {
        debug!("released registry lock");
        // Lock is automatically released when file is closed
    }
}

/// Container state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerInfo {
    /// Unique container ID.
    pub id: String,
    /// Image the container was created from.
    pub image: String,
    /// Path to the OCI bundle directory.
    pub bundle_path: PathBuf,
    /// Current container state.
    pub state: ContainerState,
    /// Creation timestamp (Unix epoch seconds).
    pub created_at: u64,
    /// Command the container is running.
    pub command: Vec<String>,

    /// Path to the container PID file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid_file: Option<PathBuf>,
    /// Path to the exit code file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_file: Option<PathBuf>,
    /// Path to the container log file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_file: Option<PathBuf>,
    /// Path to the attach socket.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attach_socket: Option<PathBuf>,
}

/// Global container registry.
pub struct ContainerRegistry {
    containers: RwLock<HashMap<String, ContainerInfo>>,
    /// Instance ID for this agent run, used to detect stale state.
    instance_id: u64,
}

impl ContainerRegistry {
    /// Create a new empty container registry.
    pub fn new() -> Self {
        Self {
            containers: RwLock::new(HashMap::new()),
            instance_id: generate_instance_id(),
        }
    }

    /// Register a new container.
    pub fn register(&self, info: ContainerInfo) {
        let mut containers = self.containers.write();
        info!(container_id = %info.id, image = %info.image, "registered container");
        containers.insert(info.id.clone(), info);
    }

    /// Unregister a container.
    pub fn unregister(&self, id: &str) -> Option<ContainerInfo> {
        let mut containers = self.containers.write();
        let removed = containers.remove(id);
        if removed.is_some() {
            info!(container_id = %id, "unregistered container");
        }
        removed
    }

    /// Get a container by ID.
    #[allow(dead_code)] // Used in tests
    pub fn get(&self, id: &str) -> Option<ContainerInfo> {
        let containers = self.containers.read();
        containers.get(id).cloned()
    }

    /// Update container state.
    pub fn update_state(&self, id: &str, state: ContainerState) {
        let mut containers = self.containers.write();
        if let Some(info) = containers.get_mut(id) {
            info.state = state;
            debug!(container_id = %id, state = %state, "updated container state");
        }
    }

    /// List all containers.
    pub fn list(&self) -> Vec<ContainerInfo> {
        let containers = self.containers.read();
        containers.values().cloned().collect()
    }

    /// Find container by ID prefix (for short IDs).
    pub fn find_by_prefix(&self, prefix: &str) -> Option<ContainerInfo> {
        let containers = self.containers.read();

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

    /// Persist the registry to disk.
    ///
    /// Uses file locking to prevent concurrent writes and atomic file
    /// replacement to prevent partial writes.
    ///
    /// The registry is saved with version information for future migrations
    /// and staleness detection.
    pub fn persist(&self) -> Result<(), StorageError> {
        // Acquire exclusive lock
        let _lock = RegistryLock::acquire()?;

        let containers = self.containers.read();

        // Ensure parent directory exists
        if let Some(parent) = Path::new(paths::REGISTRY_PATH).parent() {
            fs::create_dir_all(parent)
                .map_err(|e| StorageError::new(format!("failed to create registry dir: {}", e)))?;
        }

        // Create versioned state for persistence
        let state = RegistryState {
            version: REGISTRY_SCHEMA_VERSION,
            last_modified: current_timestamp(),
            instance_id: self.instance_id,
            containers: containers.clone(),
        };

        let json = serde_json::to_string_pretty(&state)
            .map_err(|e| StorageError::new(format!("failed to serialize registry: {}", e)))?;

        // Write to temp file first (atomic write pattern)
        let temp_path = format!("{}.tmp", paths::REGISTRY_PATH);
        {
            let mut file = File::create(&temp_path)
                .map_err(|e| StorageError::new(format!("failed to create temp registry: {}", e)))?;
            file.write_all(json.as_bytes())
                .map_err(|e| StorageError::new(format!("failed to write temp registry: {}", e)))?;
            file.sync_all()
                .map_err(|e| StorageError::new(format!("failed to sync temp registry: {}", e)))?;
        }

        // Atomic rename
        fs::rename(&temp_path, paths::REGISTRY_PATH)
            .map_err(|e| StorageError::new(format!("failed to rename registry: {}", e)))?;

        debug!(
            path = paths::REGISTRY_PATH,
            count = containers.len(),
            version = REGISTRY_SCHEMA_VERSION,
            instance_id = self.instance_id,
            "persisted registry"
        );
        Ok(())
    }

    /// Load the registry from disk.
    ///
    /// Uses file locking to prevent reading while another process is writing.
    /// Handles migration from older registry formats automatically.
    /// If the registry is corrupted, backs it up and starts fresh.
    pub fn load(&self) -> Result<(), StorageError> {
        let path = Path::new(paths::REGISTRY_PATH);
        if !path.exists() {
            debug!(
                path = paths::REGISTRY_PATH,
                "registry file not found, starting fresh"
            );
            return Ok(());
        }

        // Acquire lock to ensure we don't read during a write
        let _lock = RegistryLock::acquire()?;

        let json = match fs::read_to_string(path) {
            Ok(j) => j,
            Err(e) => {
                warn!(error = %e, "failed to read registry file, starting fresh");
                return Ok(());
            }
        };

        // Try to parse as new versioned format first
        if let Ok(state) = serde_json::from_str::<RegistryState>(&json) {
            let mut containers = self.containers.write();
            *containers = state.containers;

            // Check for stale state (different instance)
            if state.instance_id != 0 && state.instance_id != self.instance_id {
                let age_secs = current_timestamp().saturating_sub(state.last_modified);
                info!(
                    path = paths::REGISTRY_PATH,
                    count = containers.len(),
                    version = state.version,
                    old_instance_id = state.instance_id,
                    new_instance_id = self.instance_id,
                    age_secs = age_secs,
                    "loaded registry from previous instance (will reconcile)"
                );
            } else {
                info!(
                    path = paths::REGISTRY_PATH,
                    count = containers.len(),
                    version = state.version,
                    "loaded registry from disk"
                );
            }
            return Ok(());
        }

        // Fall back to old format (just HashMap) for migration
        match serde_json::from_str::<HashMap<String, ContainerInfo>>(&json) {
            Ok(loaded) => {
                let mut containers = self.containers.write();
                *containers = loaded;
                info!(
                    path = paths::REGISTRY_PATH,
                    count = containers.len(),
                    "migrated registry from old format"
                );
                // Persist immediately in new format
                drop(containers);
                drop(_lock);
                if let Err(e) = self.persist() {
                    warn!(error = %e, "failed to persist migrated registry");
                }
            }
            Err(e) => {
                // Registry is corrupted - back it up and start fresh
                warn!(error = %e, "registry file corrupted, backing up and starting fresh");
                self.backup_corrupted_registry()?;
            }
        }

        Ok(())
    }

    /// Back up a corrupted registry file for later analysis.
    fn backup_corrupted_registry(&self) -> Result<(), StorageError> {
        let backup_path = format!(
            "{}.corrupted.{}",
            paths::REGISTRY_PATH,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        );

        if let Err(e) = fs::rename(paths::REGISTRY_PATH, &backup_path) {
            warn!(error = %e, backup_path = %backup_path, "failed to backup corrupted registry");
            // Try to just remove it
            let _ = fs::remove_file(paths::REGISTRY_PATH);
        } else {
            info!(backup_path = %backup_path, "backed up corrupted registry");
        }

        Ok(())
    }

    /// Reconcile the registry with actual container state.
    ///
    /// This checks each registered container against `crun state`,
    /// updating or removing entries that don't match reality.
    pub fn reconcile(&self) -> Result<(), StorageError> {
        let container_ids: Vec<String> = {
            let containers = self.containers.read();
            containers.keys().cloned().collect()
        };

        let mut to_remove = Vec::new();
        let mut to_update = Vec::new();

        for id in container_ids {
            // Check crun state
            let crun_state = get_crun_state(&id);
            let exit_code = read_exit_code(&id);

            match crun_state {
                Ok(state) => {
                    let new_state = match state.as_str() {
                        "running" => ContainerState::Running,
                        "stopped" | "exited" => ContainerState::Stopped,
                        "created" => ContainerState::Created,
                        _ => {
                            warn!(container_id = %id, state = %state, "unknown crun state");
                            ContainerState::Stopped
                        }
                    };
                    to_update.push((id.clone(), new_state));
                    debug!(container_id = %id, state = %state, "reconciled container");
                }
                Err(_) => {
                    // Container doesn't exist in crun
                    if exit_code.is_some() {
                        // Container exited, mark as stopped
                        to_update.push((id.clone(), ContainerState::Stopped));
                        debug!(container_id = %id, exit_code = ?exit_code, "container exited");
                    } else {
                        // Container doesn't exist at all, remove from registry
                        to_remove.push(id.clone());
                        warn!(container_id = %id, "container not found in crun, removing from registry");
                    }
                }
            }
        }

        // Apply updates
        {
            let mut containers = self.containers.write();
            for (id, state) in to_update {
                if let Some(info) = containers.get_mut(&id) {
                    info.state = state;
                }
            }
            for id in to_remove {
                containers.remove(&id);
            }
        }

        // Persist changes
        self.persist()?;

        info!("registry reconciliation complete");
        Ok(())
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

/// Validate container creation parameters.
///
/// Returns an error with a descriptive message if validation fails.
fn validate_container_params(
    image: &str,
    command: &[String],
    workdir: Option<&str>,
) -> Result<(), StorageError> {
    // Validate image reference using comprehensive validation
    crate::oci::validate_image_reference(image).map_err(StorageError::new)?;

    // Validate command is not empty
    if command.is_empty() {
        return Err(StorageError::new(
            "command cannot be empty: specify at least one command to run",
        ));
    }

    // Validate first command element is not empty
    if command[0].is_empty() {
        return Err(StorageError::new("command cannot start with empty string"));
    }

    // Validate workdir if provided
    if let Some(wd) = workdir {
        if wd.is_empty() {
            return Err(StorageError::new("workdir cannot be empty string"));
        }
        if !wd.starts_with('/') {
            return Err(StorageError::new(format!(
                "workdir must be an absolute path, got: '{}'",
                wd
            )));
        }
    }

    Ok(())
}

/// Validate environment variables (wrapper for oci::validate_env_vars).
fn validate_env_vars(env: &[(String, String)]) -> Result<(), StorageError> {
    crate::oci::validate_env_vars(env).map_err(StorageError::new)
}

/// Validate exec parameters.
fn validate_exec_params(command: &[String]) -> Result<(), StorageError> {
    if command.is_empty() {
        return Err(StorageError::new(
            "exec command cannot be empty: specify at least one command to run",
        ));
    }
    if command[0].is_empty() {
        return Err(StorageError::new(
            "exec command cannot start with empty string",
        ));
    }
    Ok(())
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
    // Validate inputs before proceeding
    validate_container_params(image, command, workdir)?;
    validate_env_vars(env)?;

    // Generate unique container ID
    let container_id = generate_container_id();

    // Use container ID as workload ID for unique overlay
    let workload_id = format!("container-{}", &container_id);

    // Prepare overlay filesystem
    let overlay = storage::prepare_overlay(image, &workload_id)?;

    // Setup volume mounts
    storage::setup_mounts(&overlay.rootfs_path, mounts)?;

    // Get bundle path
    let bundle_path = paths::bundle_dir(&workload_id);

    // Create OCI spec
    let workdir_str = workdir.unwrap_or("/");
    let mut spec = OciSpec::new(command, env, workdir_str, false);

    // Add bind mounts for virtiofs volumes
    for (tag, container_path, read_only) in mounts {
        let virtiofs_mount = Path::new(paths::VIRTIOFS_MOUNT_ROOT).join(tag);
        spec.add_bind_mount(
            &virtiofs_mount.to_string_lossy(),
            container_path,
            *read_only,
        );
    }

    // Write config.json
    spec.write_to(&bundle_path)
        .map_err(|e| StorageError::new(format!("failed to write OCI spec: {}", e)))?;

    // Create the container with crun create (does NOT start it)
    // This puts the container in "created" state, ready for `crun start`
    info!(
        container_id = %container_id,
        bundle = %bundle_path.display(),
        "creating container with crun"
    );

    // Verify rootfs exists and has content before calling crun
    let rootfs_path = bundle_path.join("rootfs");
    if rootfs_path.is_symlink() {
        if let Ok(target) = std::fs::read_link(&rootfs_path) {
            let resolved = bundle_path.join(&target);
            let entry_count = std::fs::read_dir(&resolved)
                .map(|entries| entries.count())
                .unwrap_or(0);
            debug!(
                rootfs_symlink = %rootfs_path.display(),
                target = %target.display(),
                resolved = %resolved.display(),
                entry_count = entry_count,
                "rootfs check before crun create"
            );
            if entry_count == 0 {
                return Err(StorageError::new(format!(
                    "rootfs is empty at {} (symlink to {})",
                    rootfs_path.display(),
                    resolved.display()
                )));
            }
        }
    }

    // Use spawn with timeout - don't capture stdout/stderr as pipes can block
    // when child processes inherit fds
    let mut child = CrunCommand::create(&bundle_path, &container_id)
        .spawn()
        .map_err(|e| StorageError::new(format!("failed to spawn crun create: {}", e)))?;

    // Wait with timeout for crun create
    let timeout = Duration::from_millis(CRUN_OPERATION_TIMEOUT_MS);
    let start = Instant::now();
    let poll_interval = Duration::from_millis(CRUN_POLL_INTERVAL_MS);

    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                break status;
            }
            Ok(None) => {
                // Still running - check timeout
                if start.elapsed() >= timeout {
                    // Kill the hung process
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(StorageError::new(
                        "crun create timed out after 10 seconds - this may indicate a cgroup or namespace issue"
                    ));
                }
                std::thread::sleep(poll_interval);
            }
            Err(e) => {
                return Err(StorageError::new(format!(
                    "failed to wait for crun create: {}",
                    e
                )));
            }
        }
    };

    debug!(
        exit_code = status.code(),
        elapsed_ms = start.elapsed().as_millis(),
        "crun create completed"
    );

    if !status.success() {
        // If crun failed, try to get error from crun state
        let state_output = CrunCommand::state(&container_id).output();
        let state_info = state_output
            .map(|o| String::from_utf8_lossy(&o.stderr).to_string())
            .unwrap_or_default();
        return Err(StorageError::new(format!(
            "crun create failed with exit code {:?}: {}",
            status.code(),
            state_info
        )));
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
        state: ContainerState::Created, // Container is created but NOT running
        created_at,
        command: command.to_vec(),
        // Runtime state fields (populated when container is started)
        pid_file: None,
        exit_file: None,
        log_file: None,
        attach_socket: None,
    };

    // Register in global registry and persist
    REGISTRY.register(info.clone());
    if let Err(e) = REGISTRY.persist() {
        warn!(error = %e, "failed to persist registry after create");
    }

    Ok(info)
}

/// Start a container.
///
/// This calls `crun start` to start the container.
/// For stopped containers, it cleans up stale state and recreates before starting.
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

    info!(container_id = %info.id, state = ?info.state, "starting container");

    match info.state {
        ContainerState::Running => {
            // Already running (shouldn't reach here due to check above)
            return Ok(());
        }
        ContainerState::Created => {
            // Container is in created state, call crun start with timeout handling
            let mut child = CrunCommand::start(&info.id)
                .stdin_null()
                .stderr_piped()
                .spawn()
                .map_err(|e| StorageError::new(format!("failed to spawn crun start: {}", e)))?;

            let result = wait_with_timeout(&mut child, Some(CRUN_OPERATION_TIMEOUT_MS), None)
                .map_err(|e| StorageError::new(format!("failed to wait for crun start: {}", e)))?;

            match result {
                WaitResult::Completed { exit_code, output } => {
                    if exit_code != 0 {
                        warn!(
                            container_id = %info.id,
                            exit_code = exit_code,
                            error = %output.stderr,
                            "crun start failed, cleaning up"
                        );
                        let _ = CrunCommand::delete(&info.id, true).output();
                        return Err(StorageError::new(format!(
                            "crun start failed (exit {}): {}",
                            exit_code, output.stderr
                        )));
                    }
                }
                WaitResult::TimedOut { output, timeout_ms } => {
                    warn!(
                        container_id = %info.id,
                        timeout_ms = timeout_ms,
                        error = %output.stderr,
                        "crun start timed out, cleaning up"
                    );
                    let _ = CrunCommand::delete(&info.id, true).output();
                    return Err(StorageError::new(format!(
                        "crun start timed out after {}ms: {}",
                        timeout_ms, output.stderr
                    )));
                }
            }

            REGISTRY.update_state(&info.id, ContainerState::Running);
            info!(container_id = %info.id, "container started with crun start");
        }
        ContainerState::Stopped => {
            // Container was stopped - need to recreate and start it
            info!(container_id = %info.id, "container stopped, recreating");

            // Delete stale crun state
            if let Ok(output) = CrunCommand::delete(&info.id, true).output() {
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    debug!(container_id = %info.id, error = %stderr, "crun delete returned error (may be expected)");
                }
            }

            // Check if overlay is still mounted, remount if necessary
            let workload_id = format!("container-{}", &info.id);
            let merged_path = PathBuf::from(paths::STORAGE_ROOT)
                .join("overlays")
                .join(&workload_id)
                .join("merged");

            if !is_overlay_mounted(&merged_path) {
                info!(container_id = %info.id, "overlay not mounted, remounting");

                // Re-prepare the overlay using the stored image
                match storage::prepare_overlay(&info.image, &workload_id) {
                    Ok(overlay) => {
                        debug!(container_id = %info.id, rootfs = %overlay.rootfs_path, "overlay remounted");
                    }
                    Err(e) => {
                        return Err(StorageError::new(format!(
                            "failed to remount overlay for restart: {}",
                            e
                        )));
                    }
                }
            } else {
                debug!(container_id = %info.id, "overlay still mounted, reusing");
            }

            // Verify bundle and rootfs exist
            let rootfs_path = info.bundle_path.join("rootfs");
            if !rootfs_path.exists() {
                return Err(StorageError::new(format!(
                    "rootfs not found at {} - bundle may be corrupted",
                    rootfs_path.display()
                )));
            }

            // Recreate the container using spawn + timeout pattern (same as create_container)
            info!(container_id = %info.id, bundle = %info.bundle_path.display(), "recreating container");

            let mut child = CrunCommand::create(&info.bundle_path, &info.id)
                .spawn()
                .map_err(|e| StorageError::new(format!("failed to spawn crun create: {}", e)))?;

            // Wait with timeout for crun create
            let timeout = Duration::from_millis(CRUN_OPERATION_TIMEOUT_MS);
            let start = Instant::now();
            let poll_interval = Duration::from_millis(CRUN_POLL_INTERVAL_MS);

            let status = loop {
                match child.try_wait() {
                    Ok(Some(status)) => break status,
                    Ok(None) => {
                        if start.elapsed() >= timeout {
                            let _ = child.kill();
                            let _ = child.wait();
                            return Err(StorageError::new(
                                "crun create timed out on restart - this may indicate a cgroup or namespace issue"
                            ));
                        }
                        std::thread::sleep(poll_interval);
                    }
                    Err(e) => {
                        return Err(StorageError::new(format!(
                            "failed to wait for crun create: {}",
                            e
                        )));
                    }
                }
            };

            if !status.success() {
                return Err(StorageError::new(format!(
                    "crun create failed on restart with exit code {:?}",
                    status.code()
                )));
            }

            debug!(container_id = %info.id, "container recreated, now starting");

            // Now start it directly with crun start (also use spawn + timeout)
            let mut child = CrunCommand::start(&info.id)
                .stdin_null()
                .discard_output()
                .spawn()
                .map_err(|e| StorageError::new(format!("failed to spawn crun start: {}", e)))?;

            let start = Instant::now();
            let status = loop {
                match child.try_wait() {
                    Ok(Some(status)) => break status,
                    Ok(None) => {
                        if start.elapsed() >= timeout {
                            let _ = child.kill();
                            let _ = child.wait();
                            // Cleanup stale container
                            let _ = CrunCommand::delete(&info.id, true).output();
                            return Err(StorageError::new("crun start timed out on restart"));
                        }
                        std::thread::sleep(poll_interval);
                    }
                    Err(e) => {
                        return Err(StorageError::new(format!(
                            "failed to wait for crun start: {}",
                            e
                        )));
                    }
                }
            };

            if !status.success() {
                warn!(container_id = %info.id, exit_code = ?status.code(), "crun start failed after recreate");
                let _ = CrunCommand::delete(&info.id, true).output();
                return Err(StorageError::new(format!(
                    "crun start failed with exit code {:?}",
                    status.code()
                )));
            }

            REGISTRY.update_state(&info.id, ContainerState::Running);
            info!(container_id = %info.id, "container restarted");
        }
    }

    // Persist registry changes
    if let Err(e) = REGISTRY.persist() {
        warn!(error = %e, "failed to persist registry after start");
    }

    info!(container_id = %info.id, "container started");
    Ok(())
}

/// Execute a command in a running container.
pub fn exec_in_container(
    container_id: &str,
    command: &[String],
    env: &[(String, String)],
    workdir: Option<&str>,
    timeout_ms: Option<u64>,
) -> Result<ExecResult, StorageError> {
    // Validate inputs
    validate_exec_params(command)?;
    validate_env_vars(env)?;

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

    let mut child = CrunCommand::exec(&info.id, env, command, workdir, false)
        .capture_output()
        .spawn()
        .map_err(|e| StorageError::new(format!("failed to spawn crun exec: {}", e)))?;

    let result = wait_with_timeout(&mut child, timeout_ms, None)?;
    convert_wait_result_to_exec(&info.id, result)
}

/// Convert WaitResult to ExecResult.
fn convert_wait_result_to_exec(
    container_id: &str,
    result: WaitResult,
) -> Result<ExecResult, StorageError> {
    match result {
        WaitResult::Completed { exit_code, output } => {
            debug!(
                container_id = %container_id,
                exit_code = exit_code,
                "exec completed"
            );
            Ok(ExecResult {
                exit_code,
                stdout: output.stdout,
                stderr: output.stderr,
            })
        }
        WaitResult::TimedOut { output, timeout_ms } => {
            warn!(container_id = %container_id, "exec timed out");
            Ok(ExecResult {
                exit_code: TIMEOUT_EXIT_CODE,
                stdout: output.stdout,
                stderr: format!("{}\nexec timed out after {}ms", output.stderr, timeout_ms),
            })
        }
    }
}

/// Spawn an interactive exec in a running container.
///
/// Returns a Child process that the caller can use to handle I/O streaming.
/// The caller is responsible for managing stdin/stdout/stderr and waiting for exit.
pub fn spawn_interactive_exec(
    container_id: &str,
    command: &[String],
    env: &[(String, String)],
    workdir: Option<&str>,
    tty: bool,
) -> Result<std::process::Child, StorageError> {
    // Validate command
    validate_exec_params(command)?;

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
        tty = tty,
        "spawning interactive exec in container"
    );

    // Spawn crun exec with piped stdio for streaming
    let child = CrunCommand::exec(&info.id, env, command, workdir, tty)
        .stdin_piped()
        .capture_output()
        .spawn()
        .map_err(|e| StorageError::new(format!("failed to spawn crun exec: {}", e)))?;

    debug!(container_id = %info.id, "interactive exec spawned");

    Ok(child)
}

/// Stop a running container.
pub fn stop_container(container_id: &str, timeout_secs: u64) -> Result<(), StorageError> {
    let info = REGISTRY
        .find_by_prefix(container_id)
        .ok_or_else(|| StorageError::new(format!("container not found: {}", container_id)))?;

    info!(container_id = %info.id, timeout_secs = timeout_secs, "stopping container");

    // Send SIGTERM first
    let _ = CrunCommand::kill(&info.id, "SIGTERM").status();

    // Wait for container to stop
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(timeout_secs);

    while start.elapsed() < timeout {
        if let Ok(state) = get_crun_state(&info.id) {
            if state == "stopped" {
                REGISTRY.update_state(&info.id, ContainerState::Stopped);
                if let Err(e) = REGISTRY.persist() {
                    warn!(error = %e, "failed to persist registry after stop");
                }
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(CONTAINER_STOP_POLL_INTERVAL_MS));
    }

    // Force kill if still running
    warn!(container_id = %info.id, "container didn't stop gracefully, force killing");
    let _ = CrunCommand::kill(&info.id, "SIGKILL").status();

    REGISTRY.update_state(&info.id, ContainerState::Stopped);

    // Persist registry changes
    if let Err(e) = REGISTRY.persist() {
        warn!(error = %e, "failed to persist registry after stop");
    }

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
    let output = CrunCommand::delete(&info.id, force)
        .output()
        .map_err(|e| StorageError::new(format!("failed to run crun delete: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Ignore "does not exist" errors
        if !stderr.contains("does not exist") {
            warn!(container_id = %info.id, error = %stderr, "crun delete warning");
        }
    }

    // Clean up container runtime state (pid files, logs, exit files)
    cleanup_container_state(&info.id);

    // Clean up overlay
    let workload_id = format!("container-{}", &info.id);
    if let Err(e) = storage::cleanup_overlay(&workload_id) {
        warn!(container_id = %info.id, error = %e, "failed to cleanup overlay");
    }

    // Unregister from registry and persist
    REGISTRY.unregister(&info.id);
    if let Err(e) = REGISTRY.persist() {
        warn!(error = %e, "failed to persist registry after delete");
    }

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

/// Check if the overlay is mounted at the given path.
fn is_overlay_mounted(merged_path: &Path) -> bool {
    paths::is_mount_point(merged_path)
}

/// Get container state from crun.
fn get_crun_state(container_id: &str) -> Result<String, StorageError> {
    let output = CrunCommand::state(container_id)
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
        .ok_or_else(|| StorageError::MissingField {
            context: "crun state".into(),
            field: "status".into(),
        })
}

/// Read exit code from the exit file for a container.
fn read_exit_code(container_id: &str) -> Option<i32> {
    let exit_path = paths::container_exit_path(container_id);
    match fs::read_to_string(&exit_path) {
        Ok(content) => content.trim().parse().ok(),
        Err(_) => None,
    }
}

/// Clean up container runtime state (pid files, logs, exit files).
fn cleanup_container_state(container_id: &str) {
    // Remove run directory (contains pidfile, etc.)
    let run_dir = paths::container_run_dir(container_id);
    if run_dir.exists() {
        if let Err(e) = fs::remove_dir_all(&run_dir) {
            warn!(container_id = %container_id, error = %e, "failed to remove run directory");
        }
    }

    // Remove log file
    let log_path = paths::container_log_path(container_id);
    if log_path.exists() {
        if let Err(e) = fs::remove_file(&log_path) {
            warn!(container_id = %container_id, error = %e, "failed to remove log file");
        }
    }

    // Remove exit file
    let exit_path = paths::container_exit_path(container_id);
    if exit_path.exists() {
        if let Err(e) = fs::remove_file(&exit_path) {
            warn!(container_id = %container_id, error = %e, "failed to remove exit file");
        }
    }

    debug!(container_id = %container_id, "cleaned up container state");
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
            pid_file: None,
            exit_file: None,
            log_file: None,
            attach_socket: None,
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
            pid_file: None,
            exit_file: None,
            log_file: None,
            attach_socket: None,
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
