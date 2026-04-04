//! Machine lifecycle handlers.
//!
//! These handlers manage persistent machines via the shared database,
//! accessible to both API and CLI commands.
//!
//! ## Limitations
//!
//! ### Name Length Limit
//!
//! Machine names are limited to 40 characters due to Unix domain socket path
//! length limits (~104 bytes on macOS). The full socket path is:
//!
//! ```text
//! ~/Library/Caches/smolvm/vms/{name}/agent.sock
//! ```
//!
//! With a typical macOS home directory path of ~30 chars, a name of 40 chars
//! results in a socket path of ~90 chars, leaving some margin.
//!
//! Recommended: Use short, descriptive names (e.g., "dev-vm", "test-1").

use axum::{
    extract::{Path, State},
    Json,
};
use std::sync::Arc;
use std::time::Duration;

use crate::agent::{AgentManager, HostMount};
use crate::api::error::ApiError;
use crate::api::state::{ApiState, MachineEntry};
use crate::api::types::{
    ApiErrorResponse, CreateMachineRequest, DeleteResponse, EnvVar, ExecResponse,
    ListMachinesResponse, MachineExecRequest, MachineInfo, MountSpec, PortSpec,
    ResizeMachineRequest, ResourceSpec,
};
use crate::api::validation::validate_command;
use crate::api::validation::validate_resource_name;
use crate::config::{RecordState, RestartConfig, VmRecord};

/// Maximum machine name length.
///
/// This is limited to 40 characters to ensure the Unix domain socket path
/// (~/Library/Caches/smolvm/vms/{name}/agent.sock) stays under the 104-byte
/// limit on macOS. With a typical home directory path of ~30 chars, a name
/// of 40 chars results in a socket path of ~90 chars, leaving some margin.
const MAX_NAME_LENGTH: usize = 40;

/// Resolve the actual machine state, using vsock as a fallback.
///
/// `VmRecord::actual_state()` checks PID liveness, but on macOS the
/// session-leader VM process may not be visible via `kill(pid, 0)`.
/// When the DB says Running but the PID check says Stopped, probe
/// the agent socket to determine the real state.
fn resolve_machine_state(name: &str, record: &VmRecord) -> RecordState {
    let state = record.actual_state();

    if record.state == RecordState::Running && state == RecordState::Stopped {
        if let Ok(manager) = AgentManager::for_vm(name) {
            if let Ok(mut client) =
                crate::agent::AgentClient::connect_with_short_timeout(manager.vsock_socket())
            {
                if client.ping().is_ok() {
                    return RecordState::Running;
                }
            }
        }
    }

    state
}

/// Convert VmRecord to MachineInfo (pure mapping, no I/O).
fn record_to_info(name: &str, record: &VmRecord) -> MachineInfo {
    let actual_state = resolve_machine_state(name, record);
    // Clear stale PID when the process is not actually running, so clients
    // never see state=stopped paired with a PID.
    let pid = if actual_state == RecordState::Stopped {
        None
    } else {
        record.pid
    };
    MachineInfo {
        name: name.to_string(),
        state: actual_state.to_string(),
        cpus: record.cpus,
        mem: record.mem,
        pid,
        mounts: record
            .mounts
            .iter()
            .enumerate()
            .map(
                |(i, (source, target, readonly))| crate::api::types::MountInfo {
                    tag: crate::data::storage::HostMount::mount_tag(i),
                    source: source.clone(),
                    target: target.clone(),
                    readonly: *readonly,
                },
            )
            .collect(),
        ports: record
            .ports
            .iter()
            .map(|(host, guest)| crate::api::types::PortSpec {
                host: *host,
                guest: *guest,
            })
            .collect(),
        network: record.network,
        storage_gb: record.storage_gb,
        overlay_gb: record.overlay_gb,
        created_at: record.created_at.clone(),
    }
}

/// Build a MachineEntry from a VmRecord and AgentManager.
///
/// Used by `start_machine` to register a machine in ApiState after boot
/// or during registry repair. Centralizes the record→entry conversion
/// so the two branches don't drift.
fn machine_entry_from_record(record: &VmRecord, manager: AgentManager) -> MachineEntry {
    let mounts = record
        .mounts
        .iter()
        .map(|(s, t, ro)| MountSpec {
            source: s.clone(),
            target: t.clone(),
            readonly: *ro,
        })
        .collect();
    let ports = record
        .ports
        .iter()
        .map(|(h, g)| PortSpec {
            host: *h,
            guest: *g,
        })
        .collect();
    MachineEntry {
        manager,
        mounts,
        ports,
        resources: crate::api::state::vm_resources_to_spec(record.vm_resources()),
        restart: record.restart.clone(),
        network: record.network,
    }
}

/// Attempt graceful shutdown, then force-terminate if still running.
///
/// Uses verified signals to prevent killing an unrelated process if the
/// PID was recycled by the OS. Returns true if the process is confirmed
/// dead (or was never running), false if it may still be alive.
fn shutdown_machine_process(name: &str, pid: Option<i32>, pid_start_time: Option<u64>) -> bool {
    // Try graceful shutdown via vsock first.
    // If vsock connects, this confirms the process is our VM (identity verification).
    let manager = AgentManager::for_vm(name).ok();
    let mut vsock_confirmed = false;
    if let Some(ref manager) = manager {
        if let Ok(mut client) = crate::agent::AgentClient::connect(manager.vsock_socket()) {
            vsock_confirmed = true;
            let _ = client.shutdown();
        }
    }

    // PID-based signal handling.
    if let Some(pid) = pid {
        // Identity check: vsock acknowledgement OR strict PID start-time match.
        // We intentionally do NOT use the lenient is_our_process() here because
        // it treats any alive PID as "ours" when start_time is None — which risks
        // killing an unrelated process if the OS reused the PID.
        let identity_ok =
            vsock_confirmed || crate::process::is_our_process_strict(pid, pid_start_time);

        if identity_ok {
            let _ = crate::process::stop_vm_process(
                pid,
                crate::process::VM_SIGTERM_TIMEOUT,
                crate::process::VM_SIGKILL_TIMEOUT,
            );
        } else {
            tracing::debug!(pid, name, "PID already dead");
        }

        // Post-check: verify the process is actually gone.
        if crate::process::is_alive(pid) {
            tracing::warn!(pid, name, "process still alive after shutdown attempts");
            return false;
        }
    } else {
        // No PID available — check if VM is still reachable via vsock.
        if let Some(ref manager) = manager {
            if let Ok(mut client) = crate::agent::AgentClient::connect(manager.vsock_socket()) {
                if client.ping().is_ok() {
                    tracing::warn!(name, "VM still reachable via vsock but no PID to signal");
                    return false;
                }
            }
        }
    }

    true
}

/// Create a new machine.
#[utoipa::path(
    post,
    path = "/api/v1/machines",
    tag = "Machines",
    request_body = CreateMachineRequest,
    responses(
        (status = 200, description = "Machine created", body = MachineInfo),
        (status = 400, description = "Invalid request", body = ApiErrorResponse),
        (status = 409, description = "Machine already exists", body = ApiErrorResponse)
    )
)]
pub async fn create_machine(
    State(state): State<Arc<ApiState>>,
    Json(req): Json<CreateMachineRequest>,
) -> Result<Json<MachineInfo>, ApiError> {
    use crate::api::state::{MachineRegistration, ReservationGuard};
    // Validate name format
    validate_resource_name(&req.name, "machine", MAX_NAME_LENGTH)?;

    // Validate mount paths
    for mount_spec in &req.mounts {
        HostMount::try_from(mount_spec).map_err(|e| ApiError::BadRequest(e.to_string()))?;
    }

    let name = req.name.clone();

    // Reserve the name atomically (prevents concurrent creation)
    let guard = ReservationGuard::new(&state, name.clone())?;

    // Create manager (does not boot the VM)
    let manager = tokio::task::spawn_blocking({
        let name = name.clone();
        let storage_gb = req.storage_gb;
        let overlay_gb = req.overlay_gb;
        move || {
            AgentManager::for_vm_with_sizes(&name, storage_gb, overlay_gb)
                .map_err(|e| ApiError::internal(format!("failed to create agent manager: {}", e)))
        }
    })
    .await
    .map_err(|e| ApiError::internal(format!("task error: {}", e)))??;

    let resources = ResourceSpec {
        cpus: Some(req.cpus),
        memory_mb: Some(req.mem),
        network: Some(req.network),
        storage_gb: req.storage_gb,
        overlay_gb: req.overlay_gb,
        allowed_cidrs: req.allowed_cidrs.clone(),
    };

    // Complete registration: persists to DB + registers in ApiState
    guard.complete(MachineRegistration {
        manager,
        mounts: req.mounts.clone(),
        ports: req.ports.clone(),
        resources: resources.clone(),
        restart: RestartConfig::default(),
        network: req.network,
    })?;

    // Fetch the persisted record for the response
    let db = state.db();
    let record = db
        .get_vm(&name)
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::internal("machine disappeared after creation".to_string()))?;

    Ok(Json(record_to_info(&name, &record)))
}

/// List all machines.
#[utoipa::path(
    get,
    path = "/api/v1/machines",
    tag = "Machines",
    responses(
        (status = 200, description = "List of machines", body = ListMachinesResponse),
        (status = 500, description = "Database error", body = ApiErrorResponse)
    )
)]
pub async fn list_machines(
    State(state): State<Arc<ApiState>>,
) -> Result<Json<ListMachinesResponse>, ApiError> {
    let db = state.db();
    let vms = db.list_vms().map_err(ApiError::database)?;

    let machines: Vec<MachineInfo> = vms
        .iter()
        .map(|(name, record)| record_to_info(name, record))
        .collect();

    Ok(Json(ListMachinesResponse { machines }))
}

/// Get machine status.
#[utoipa::path(
    get,
    path = "/api/v1/machines/{name}",
    tag = "Machines",
    params(
        ("name" = String, Path, description = "Machine name")
    ),
    responses(
        (status = 200, description = "Machine details", body = MachineInfo),
        (status = 404, description = "Machine not found", body = ApiErrorResponse)
    )
)]
pub async fn get_machine(
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
) -> Result<Json<MachineInfo>, ApiError> {
    let db = state.db();
    let record = db
        .get_vm(&name)
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::NotFound(format!("machine '{}' not found", name)))?;

    Ok(Json(record_to_info(&name, &record)))
}

/// Start a machine.
#[utoipa::path(
    post,
    path = "/api/v1/machines/{name}/start",
    tag = "Machines",
    params(
        ("name" = String, Path, description = "Machine name")
    ),
    responses(
        (status = 200, description = "Machine started", body = MachineInfo),
        (status = 404, description = "Machine not found", body = ApiErrorResponse),
        (status = 500, description = "Failed to start", body = ApiErrorResponse)
    )
)]
pub async fn start_machine(
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
) -> Result<Json<MachineInfo>, ApiError> {
    // Get VM record from database
    let db = state.db();
    let record = db
        .get_vm(&name)
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::NotFound(format!("machine '{}' not found", name)))?;

    // Check state — if already running, ensure it's in the registry
    let actual_state = record.actual_state();
    if actual_state == RecordState::Running {
        if !state.machine_exists(&name) {
            // Running in DB but not in registry (startup recovery case).
            let name_for_repair = name.clone();
            let storage_gb = record.storage_gb;
            let overlay_gb = record.overlay_gb;
            let manager = tokio::task::spawn_blocking(move || {
                AgentManager::for_vm_with_sizes(&name_for_repair, storage_gb, overlay_gb)
            })
            .await
            .map_err(|e| ApiError::internal(format!("task error: {}", e)))?
            .map_err(|e| {
                ApiError::internal(format!(
                    "machine '{}' is running but registry repair failed: {}",
                    name, e
                ))
            })?;

            state.insert_machine(&name, machine_entry_from_record(&record, manager));
        }
        return Ok(Json(record_to_info(&name, &record)));
    }

    let mounts = record.host_mounts();
    let ports = record.port_mappings();
    let resources = record.vm_resources();

    // Start agent VM in blocking task.
    // Uses subprocess launch to avoid macOS fork-in-multithreaded-process issue.
    let name_clone = name.clone();
    let storage_gb = record.storage_gb;
    let overlay_gb = record.overlay_gb;
    let (manager, pid) = tokio::task::spawn_blocking(move || {
        let manager = AgentManager::for_vm_with_sizes(&name_clone, storage_gb, overlay_gb)
            .map_err(|e| format!("failed to create agent manager: {}", e))?;

        let _ = manager
            .ensure_running_via_subprocess(mounts, ports, resources, None)
            .map_err(|e| format!("failed to start machine: {}", e))?;

        let pid = manager.child_pid();
        Ok::<_, String>((manager, pid))
    })
    .await
    .map_err(|e| ApiError::internal(format!("task error: {}", e)))?
    .map_err(ApiError::internal)?;

    // Register in ApiState so exec/run/container endpoints can find it
    state.insert_machine(&name, machine_entry_from_record(&record, manager));

    // Capture start time for PID verification
    let pid_start_time = pid.and_then(crate::process::process_start_time);

    // Persist state to database
    let record = db
        .update_vm(&name, |r| {
            r.state = RecordState::Running;
            r.pid = pid;
            r.pid_start_time = pid_start_time;
        })
        .map_err(ApiError::database)?
        .ok_or_else(|| {
            ApiError::NotFound(format!(
                "machine '{}' disappeared from database during start",
                name
            ))
        })?;

    // Build response directly with state=running. We just confirmed the VM
    // is running (wait_for_ready passed), so we bypass actual_state() which
    // may falsely report "stopped" on macOS due to setsid/session-leader
    // PID visibility issues.
    let mut info = record_to_info(&name, &record);
    info.state = "running".to_string();
    info.pid = pid;
    Ok(Json(info))
}

/// Stop a machine.
#[utoipa::path(
    post,
    path = "/api/v1/machines/{name}/stop",
    tag = "Machines",
    params(
        ("name" = String, Path, description = "Machine name")
    ),
    responses(
        (status = 200, description = "Machine stopped", body = MachineInfo),
        (status = 404, description = "Machine not found", body = ApiErrorResponse),
        (status = 500, description = "Failed to stop", body = ApiErrorResponse)
    )
)]
pub async fn stop_machine(
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
) -> Result<Json<MachineInfo>, ApiError> {
    // Get VM record from database
    let db = state.db();
    let record = db
        .get_vm(&name)
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::NotFound(format!("machine '{}' not found", name)))?;

    // Check state
    let actual_state = record.actual_state();
    if actual_state != RecordState::Running {
        // Already stopped, just return current info
        return Ok(Json(record_to_info(&name, &record)));
    }

    // Get PID and start time from database record - this is the source of truth
    let pid = record.pid;
    let pid_start_time = record.pid_start_time;

    // Stop VM in blocking task
    let name_clone = name.clone();
    let stopped = tokio::task::spawn_blocking(move || {
        shutdown_machine_process(&name_clone, pid, pid_start_time)
    })
    .await
    .map_err(|e| ApiError::internal(format!("task error: {}", e)))?;

    if !stopped {
        return Err(ApiError::Internal(format!(
            "machine '{}' process may still be running after stop attempt",
            name
        )));
    }

    // Persist state to database and get updated record — only after confirmed stop
    let record = db
        .update_vm(&name, |r| {
            r.state = RecordState::Stopped;
            r.pid = None;
            r.pid_start_time = None;
        })
        .map_err(ApiError::database)?
        .ok_or_else(|| {
            ApiError::NotFound(format!(
                "machine '{}' disappeared from database during stop",
                name
            ))
        })?;

    Ok(Json(record_to_info(&name, &record)))
}

/// Delete a machine.
#[utoipa::path(
    delete,
    path = "/api/v1/machines/{name}",
    tag = "Machines",
    params(
        ("name" = String, Path, description = "Machine name")
    ),
    responses(
        (status = 200, description = "Machine deleted", body = DeleteResponse),
        (status = 404, description = "Machine not found", body = ApiErrorResponse),
        (status = 500, description = "Failed to delete", body = ApiErrorResponse)
    )
)]
pub async fn delete_machine(
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
) -> Result<Json<DeleteResponse>, ApiError> {
    let db = state.db();

    // Check if VM exists and get its state
    let record = db
        .get_vm(&name)
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::NotFound(format!("machine '{}' not found", name)))?;

    // Get PID and start time from database record
    let pid = record.pid;
    let pid_start_time = record.pid_start_time;

    // Stop if running (in blocking task)
    let name_clone = name.clone();
    let stopped = tokio::task::spawn_blocking(move || {
        shutdown_machine_process(&name_clone, pid, pid_start_time)
    })
    .await
    .map_err(|e| ApiError::internal(format!("task error: {}", e)))?;

    if !stopped {
        return Err(ApiError::Internal(format!(
            "machine '{}' process (pid {}) is still alive after shutdown; not removing",
            name,
            pid.map(|p| p.to_string())
                .unwrap_or_else(|| "unknown".into()),
        )));
    }

    // Remove from registry (in-memory + database)
    match state.remove_machine(&name) {
        Ok(_) => {}
        Err(ApiError::NotFound(_)) => {
            // Machine exists in DB but not in registry (startup recovery case).
            // Remove directly from DB.
            let removed = db.remove_vm(&name).map_err(ApiError::database)?;
            if removed.is_none() {
                return Err(ApiError::NotFound(format!("machine '{}' not found", name)));
            }
        }
        Err(e) => return Err(e),
    }

    Ok(Json(DeleteResponse { deleted: name }))
}

/// Execute a command in a machine.
#[utoipa::path(
    post,
    path = "/api/v1/machines/{name}/exec",
    tag = "Machines",
    params(
        ("name" = String, Path, description = "Machine name")
    ),
    request_body = MachineExecRequest,
    responses(
        (status = 200, description = "Command executed", body = ExecResponse),
        (status = 400, description = "Invalid request", body = ApiErrorResponse),
        (status = 404, description = "Machine not found", body = ApiErrorResponse),
        (status = 409, description = "Machine not running", body = ApiErrorResponse),
        (status = 500, description = "Execution failed", body = ApiErrorResponse)
    )
)]
pub async fn exec_machine(
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
    Json(req): Json<MachineExecRequest>,
) -> Result<Json<ExecResponse>, ApiError> {
    validate_command(&req.command)?;

    // Check if VM exists
    let db = state.db();
    if db.get_vm(&name).map_err(ApiError::database)?.is_none() {
        return Err(ApiError::NotFound(format!("machine '{}' not found", name)));
    }

    let name_clone = name.clone();
    let command = req.command.clone();
    let env = EnvVar::to_tuples(&req.env);
    let workdir = req.workdir.clone();
    let timeout = req.timeout_secs.map(Duration::from_secs);

    let result = tokio::task::spawn_blocking(move || {
        // Get manager and check if running
        let manager = AgentManager::for_vm(&name_clone)
            .map_err(|e| crate::Error::agent("create agent manager", e.to_string()))?;

        if manager.try_connect_existing().is_none() {
            return Err(crate::Error::InvalidState {
                expected: "running".into(),
                actual: "stopped".into(),
            });
        }

        // Execute command
        let mut client = manager
            .connect()
            .map_err(|e| crate::Error::agent("connect", e.to_string()))?;
        let (exit_code, stdout, stderr) = client
            .vm_exec(command, env, workdir, timeout)
            .map_err(|e| crate::Error::agent("exec", e.to_string()))?;

        // Keep VM running (persistent)
        manager.detach();

        Ok(ExecResponse {
            exit_code,
            stdout,
            stderr,
        })
    })
    .await
    .map_err(|e| ApiError::internal(format!("task error: {}", e)))?;

    result.map(Json).map_err(ApiError::from)
}

/// Resize a machine's disk resources.
#[utoipa::path(
    post,
    path = "/api/v1/machines/{name}/resize",
    tag = "Machines",
    params(
        ("name" = String, Path, description = "Machine name")
    ),
    request_body = ResizeMachineRequest,
    responses(
        (status = 200, description = "Machine resized", body = MachineInfo),
        (status = 400, description = "Invalid request", body = ApiErrorResponse),
        (status = 404, description = "Machine not found", body = ApiErrorResponse),
        (status = 409, description = "Machine is running", body = ApiErrorResponse),
        (status = 500, description = "Resize failed", body = ApiErrorResponse)
    )
)]
pub async fn resize_machine(
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
    Json(req): Json<ResizeMachineRequest>,
) -> Result<Json<MachineInfo>, ApiError> {
    let db = state.db();

    let record = db
        .get_vm(&name)
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::NotFound(format!("machine '{}' not found", name)))?
        .clone();

    let actual_state = record.actual_state();
    match actual_state {
        RecordState::Stopped | RecordState::Created => {}
        _ => {
            return Err(ApiError::Conflict(format!(
                "machine '{}' must be stopped before resizing. Current state: {:?}",
                name, actual_state
            )));
        }
    }

    let current_storage_gb = record
        .storage_gb
        .unwrap_or(crate::storage::DEFAULT_STORAGE_SIZE_GIB);
    let current_overlay_gb = record
        .overlay_gb
        .unwrap_or(crate::storage::DEFAULT_OVERLAY_SIZE_GIB);

    if req.storage_gb.unwrap_or(current_storage_gb) < current_storage_gb {
        return Err(ApiError::BadRequest(format!(
            "storageGb cannot be smaller than current size ({} GiB)",
            current_storage_gb
        )));
    }
    if req.overlay_gb.unwrap_or(current_overlay_gb) < current_overlay_gb {
        return Err(ApiError::BadRequest(format!(
            "overlayGb cannot be smaller than current size ({} GiB)",
            current_overlay_gb
        )));
    }

    if req.storage_gb.is_none() && req.overlay_gb.is_none() {
        return Err(ApiError::BadRequest(
            "at least one of storageGb or overlayGb must be specified".into(),
        ));
    }

    let manager = crate::agent::AgentManager::for_vm(&name)
        .map_err(|e| ApiError::internal(format!("failed to get agent manager: {}", e)))?;

    if let Some(storage_gb) = req.storage_gb {
        if storage_gb > current_storage_gb {
            let storage_path = manager.storage_path();
            crate::storage::expand_disk(storage_path, storage_gb, "storage")
                .map_err(|e| ApiError::internal(format!("failed to expand storage: {}", e)))?;
        }
    }

    if let Some(overlay_gb) = req.overlay_gb {
        if overlay_gb > current_overlay_gb {
            let overlay_path = manager.overlay_path();
            crate::storage::expand_disk(overlay_path, overlay_gb, "overlay")
                .map_err(|e| ApiError::internal(format!("failed to expand overlay: {}", e)))?;
        }
    }

    let record = db
        .update_vm(&name, |r| {
            if let Some(s) = req.storage_gb {
                r.storage_gb = Some(s);
            }
            if let Some(o) = req.overlay_gb {
                r.overlay_gb = Some(o);
            }
        })
        .map_err(ApiError::database)?
        .ok_or_else(|| {
            ApiError::NotFound(format!("machine '{}' disappeared during resize", name))
        })?;

    Ok(Json(record_to_info(&name, &record)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::SmolvmDb;
    use tempfile::TempDir;

    #[test]
    fn test_record_to_info() {
        let record = VmRecord::new(
            "test-vm".to_string(),
            2,
            1024,
            vec![
                ("/host/path".to_string(), "/guest/path".to_string(), false),
                ("/host/ro".to_string(), "/guest/ro".to_string(), true),
            ],
            vec![(8080, 80), (3000, 3000)],
            false,
        );

        let info = record_to_info("test-vm", &record);

        assert_eq!(info.name, "test-vm");
        assert_eq!(info.state, "created");
        assert_eq!(info.cpus, 2);
        assert_eq!(info.mem, 1024);
        assert_eq!(info.mounts.len(), 2);
        assert_eq!(info.ports.len(), 2);
        assert!(!info.network);
        assert!(info.pid.is_none());
    }

    #[test]
    fn test_record_to_info_with_running_state() {
        let mut record = VmRecord::new("running-vm".to_string(), 1, 512, vec![], vec![], false);
        record.state = RecordState::Running;
        record.pid = Some(12345);

        let info = record_to_info("running-vm", &record);

        assert_eq!(info.name, "running-vm");
        // Note: actual_state() checks if process is alive, which won't be true in test
        // So it will show as "stopped" even though record state is Running
        assert_eq!(info.cpus, 1);
        assert_eq!(info.mem, 512);
        assert_eq!(info.mounts.len(), 0);
        assert_eq!(info.ports.len(), 0);
    }

    #[test]
    fn test_record_to_info_default_values() {
        let record = VmRecord::new("minimal-vm".to_string(), 1, 512, vec![], vec![], false);

        let info = record_to_info("minimal-vm", &record);

        assert_eq!(info.name, "minimal-vm");
        assert_eq!(info.state, "created");
        assert_eq!(info.cpus, 1);
        assert_eq!(info.mem, 512);
        assert_eq!(info.mounts.len(), 0);
        assert_eq!(info.ports.len(), 0);
        assert!(!info.network);
        assert!(info.pid.is_none());
        assert!(!info.created_at.is_empty());
    }

    #[test]
    fn test_record_to_info_with_network() {
        let record = VmRecord::new("network-vm".to_string(), 1, 512, vec![], vec![], true);

        let info = record_to_info("network-vm", &record);

        assert_eq!(info.name, "network-vm");
        assert!(info.network);
    }

    /// Helper to create a test database and API state.
    #[allow(dead_code)]
    fn setup_test_state() -> (TempDir, Arc<ApiState>) {
        let dir = TempDir::new().expect("failed to create temp dir");
        let db_path = dir.path().join("test.redb");
        let db = SmolvmDb::open_at(&db_path).expect("failed to open test db");
        let state = Arc::new(ApiState::with_db(db));
        (dir, state)
    }

    #[tokio::test]
    async fn test_resize_validation_shrink_storage_rejected() {
        let (_dir, state) = setup_test_state();
        let db = state.db();
        create_test_vm(db, "test-vm", Some(20), Some(5));

        let req = ResizeMachineRequest {
            storage_gb: Some(10),
            overlay_gb: None,
        };
        let result = resize_machine(State(state), Path("test-vm".to_string()), Json(req)).await;
        assert!(matches!(result.unwrap_err(), ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn test_resize_validation_no_params_rejected() {
        let (_dir, state) = setup_test_state();
        let db = state.db();
        create_test_vm(db, "test-vm", Some(20), Some(5));

        let req = ResizeMachineRequest {
            storage_gb: None,
            overlay_gb: None,
        };
        let result = resize_machine(State(state), Path("test-vm".to_string()), Json(req)).await;
        assert!(matches!(result.unwrap_err(), ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn test_resize_not_found() {
        let (_dir, state) = setup_test_state();
        let req = ResizeMachineRequest {
            storage_gb: Some(30),
            overlay_gb: None,
        };
        let result = resize_machine(State(state), Path("nonexistent".to_string()), Json(req)).await;
        assert!(matches!(result.unwrap_err(), ApiError::NotFound(_)));
    }

    /// Helper to create a VM record in the database.
    fn create_test_vm(db: &SmolvmDb, name: &str, storage_gb: Option<u64>, overlay_gb: Option<u64>) {
        let mut record = VmRecord::new(name.to_string(), 1, 512, vec![], vec![], false);
        record.storage_gb = storage_gb;
        record.overlay_gb = overlay_gb;
        db.insert_vm(name, &record)
            .expect("failed to insert test vm");
    }
}
