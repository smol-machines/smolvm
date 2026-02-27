//! MicroVM lifecycle handlers.
//!
//! These handlers manage persistent microVMs via the shared database,
//! accessible to both API and CLI commands.
//!
//! ## Limitations
//!
//! ### Name Length Limit
//!
//! MicroVM names are limited to 40 characters due to Unix domain socket path
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

use crate::agent::AgentManager;
use crate::api::error::ApiError;
use crate::api::state::ApiState;
use crate::api::types::{
    ApiErrorResponse, CreateMicrovmRequest, DeleteResponse, EnvVar, ExecResponse,
    ListMicrovmsResponse, MicrovmExecRequest, MicrovmInfo,
};
use crate::api::validation::{validate_command, validate_resource_name};
use crate::config::{RecordState, VmRecord};
use crate::mount::MountBinding;

/// Maximum microvm name length.
///
/// This is limited to 40 characters to ensure the Unix domain socket path
/// (~/Library/Caches/smolvm/vms/{name}/agent.sock) stays under the 104-byte
/// limit on macOS. With a typical home directory path of ~30 chars, a name
/// of 40 chars results in a socket path of ~90 chars, leaving some margin.
const MAX_NAME_LENGTH: usize = 40;

/// Convert VmRecord to MicrovmInfo.
fn record_to_info(name: &str, record: &VmRecord) -> MicrovmInfo {
    let actual_state = record.actual_state();
    // Clear stale PID when the process is not actually running, so clients
    // never see state=stopped paired with a PID.
    let pid = if actual_state == RecordState::Stopped {
        None
    } else {
        record.pid
    };
    MicrovmInfo {
        name: name.to_string(),
        state: actual_state.to_string(),
        cpus: record.cpus,
        mem: record.mem,
        pid,
        mounts: record.mounts.len(),
        ports: record.ports.len(),
        network: record.network,
        created_at: record.created_at.clone(),
    }
}

/// Attempt graceful shutdown, then force-terminate if still running.
///
/// Uses verified signals to prevent killing an unrelated process if the
/// PID was recycled by the OS. Returns true if the process is confirmed
/// dead (or was never running), false if it may still be alive.
fn shutdown_microvm_process(name: &str, pid: Option<i32>, pid_start_time: Option<u64>) -> bool {
    // Try graceful shutdown via vsock first.
    let manager = AgentManager::for_vm(name).ok();
    if let Some(ref manager) = manager {
        if let Ok(mut client) = crate::agent::AgentClient::connect(manager.vsock_socket()) {
            let _ = client.shutdown();
        }
    }

    // PID-based signal handling with start-time verification.
    if let Some(pid) = pid {
        crate::process::terminate_verified(pid, pid_start_time);
        std::thread::sleep(std::time::Duration::from_millis(100));
        if crate::process::is_our_process_strict(pid, pid_start_time) {
            crate::process::kill_verified(pid, pid_start_time);
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        // Post-check: verify the process is actually gone.
        if crate::process::is_alive(pid) {
            tracing::warn!(pid, name, "process still alive after shutdown attempts");
            return false;
        }
    } else {
        // No PID available — check if VM is still reachable via vsock.
        // Without a PID we can't signal, but we can detect if it's still running.
        if let Some(ref manager) = manager {
            if let Ok(mut client) = crate::agent::AgentClient::connect(manager.vsock_socket()) {
                if client.ping().is_ok() {
                    tracing::warn!(name, "VM still reachable via vsock but no PID to signal");
                    return false;
                }
            }
        } else {
            // Neither PID nor vsock manager available — cannot verify shutdown
            tracing::warn!(
                name,
                "no PID and no vsock manager: cannot verify VM shutdown"
            );
            return false;
        }
    }

    true
}

/// Create a new microvm.
#[utoipa::path(
    post,
    path = "/api/v1/microvms",
    tag = "MicroVMs",
    request_body = CreateMicrovmRequest,
    responses(
        (status = 200, description = "MicroVM created", body = MicrovmInfo),
        (status = 400, description = "Invalid request", body = ApiErrorResponse),
        (status = 409, description = "MicroVM already exists", body = ApiErrorResponse)
    )
)]
pub async fn create_microvm(
    State(state): State<Arc<ApiState>>,
    Json(req): Json<CreateMicrovmRequest>,
) -> Result<Json<MicrovmInfo>, ApiError> {
    // Validate name format
    validate_resource_name(&req.name, "microvm", MAX_NAME_LENGTH)?;

    let name = req.name.clone();
    let cpus = req.cpus;
    let mem = req.mem;

    // Validate and convert mounts to storage format
    let mut mounts: Vec<(String, String, bool)> = Vec::with_capacity(req.mounts.len());
    for mount_spec in &req.mounts {
        // Validate mount paths (checks: absolute paths, source exists, source is directory)
        let binding =
            MountBinding::new(&mount_spec.source, &mount_spec.target, mount_spec.readonly)
                .map_err(|e| ApiError::BadRequest(e.to_string()))?;
        mounts.push(binding.to_tuple());
    }

    // Convert ports to storage format
    let ports: Vec<(u16, u16)> = req.ports.iter().map(|p| (p.host, p.guest)).collect();

    // Create record with requested network setting
    let mut record = VmRecord::new(name.clone(), cpus, mem, mounts, ports, req.network);
    record.storage_gb = req.storage_gb;
    record.overlay_gb = req.overlay_gb;

    // Use atomic insert to detect conflicts
    let db = state.db();
    match db.insert_vm_if_not_exists(&name, &record) {
        Ok(true) => Ok(Json(record_to_info(&name, &record))),
        Ok(false) => Err(ApiError::Conflict(format!(
            "microvm '{}' already exists",
            name
        ))),
        Err(e) => Err(ApiError::database(e)),
    }
}

/// List all microvms.
#[utoipa::path(
    get,
    path = "/api/v1/microvms",
    tag = "MicroVMs",
    responses(
        (status = 200, description = "List of microvms", body = ListMicrovmsResponse),
        (status = 500, description = "Database error", body = ApiErrorResponse)
    )
)]
pub async fn list_microvms(
    State(state): State<Arc<ApiState>>,
) -> Result<Json<ListMicrovmsResponse>, ApiError> {
    let db = state.db();
    let vms = db.list_vms().map_err(ApiError::database)?;

    let microvms: Vec<MicrovmInfo> = vms
        .iter()
        .map(|(name, record)| record_to_info(name, record))
        .collect();

    Ok(Json(ListMicrovmsResponse { microvms }))
}

/// Get microvm status.
#[utoipa::path(
    get,
    path = "/api/v1/microvms/{name}",
    tag = "MicroVMs",
    params(
        ("name" = String, Path, description = "MicroVM name")
    ),
    responses(
        (status = 200, description = "MicroVM details", body = MicrovmInfo),
        (status = 404, description = "MicroVM not found", body = ApiErrorResponse)
    )
)]
pub async fn get_microvm(
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
) -> Result<Json<MicrovmInfo>, ApiError> {
    let db = state.db();
    let record = db
        .get_vm(&name)
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::NotFound(format!("microvm '{}' not found", name)))?;

    Ok(Json(record_to_info(&name, &record)))
}

/// Start a microvm.
#[utoipa::path(
    post,
    path = "/api/v1/microvms/{name}/start",
    tag = "MicroVMs",
    params(
        ("name" = String, Path, description = "MicroVM name")
    ),
    responses(
        (status = 200, description = "MicroVM started", body = MicrovmInfo),
        (status = 404, description = "MicroVM not found", body = ApiErrorResponse),
        (status = 500, description = "Failed to start", body = ApiErrorResponse)
    )
)]
pub async fn start_microvm(
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
) -> Result<Json<MicrovmInfo>, ApiError> {
    // Get VM record from database
    let db = state.db();
    let record = db
        .get_vm(&name)
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::NotFound(format!("microvm '{}' not found", name)))?;

    // Check state
    let actual_state = record.actual_state();
    if actual_state == RecordState::Running {
        // Already running, just return current info
        return Ok(Json(record_to_info(&name, &record)));
    }

    let mounts = record.host_mounts();
    let ports = record.port_mappings();
    let resources = record.vm_resources();

    // Start agent VM in blocking task.
    // Child process closes inherited fds, so DB stays open for concurrent requests.
    let name_clone = name.clone();
    let storage_gb = record.storage_gb;
    let overlay_gb = record.overlay_gb;
    let pid = tokio::task::spawn_blocking(move || {
        let manager = AgentManager::for_vm_with_sizes(&name_clone, storage_gb, overlay_gb)
            .map_err(|e| format!("failed to create agent manager: {}", e))?;

        let _ = manager
            .ensure_running_with_full_config(mounts, ports, resources)
            .map_err(|e| format!("failed to start microvm: {}", e))?;

        let pid = manager.child_pid();
        manager.detach();
        Ok::<_, String>(pid)
    })
    .await
    .map_err(|e| ApiError::internal(format!("task error: {}", e)))?
    .map_err(ApiError::internal)?;

    // Capture start time for PID verification
    let pid_start_time = pid.and_then(crate::process::process_start_time);

    // Persist state to database
    let updated = db
        .update_vm(&name, |r| {
            r.state = RecordState::Running;
            r.pid = pid;
            r.pid_start_time = pid_start_time;
        })
        .map_err(ApiError::database)?;
    if updated.is_none() {
        return Err(ApiError::NotFound(format!(
            "microvm '{}' disappeared from database during start",
            name
        )));
    }

    // Return updated record
    let record = db
        .get_vm(&name)
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::NotFound(format!("microvm '{}' not found", name)))?;

    Ok(Json(record_to_info(&name, &record)))
}

/// Stop a microvm.
#[utoipa::path(
    post,
    path = "/api/v1/microvms/{name}/stop",
    tag = "MicroVMs",
    params(
        ("name" = String, Path, description = "MicroVM name")
    ),
    responses(
        (status = 200, description = "MicroVM stopped", body = MicrovmInfo),
        (status = 404, description = "MicroVM not found", body = ApiErrorResponse),
        (status = 500, description = "Failed to stop", body = ApiErrorResponse)
    )
)]
pub async fn stop_microvm(
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
) -> Result<Json<MicrovmInfo>, ApiError> {
    // Get VM record from database
    let db = state.db();
    let record = db
        .get_vm(&name)
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::NotFound(format!("microvm '{}' not found", name)))?;

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
        shutdown_microvm_process(&name_clone, pid, pid_start_time)
    })
    .await
    .map_err(|e| ApiError::internal(format!("task error: {}", e)))?;

    if !stopped {
        return Err(ApiError::Internal(format!(
            "microvm '{}' process may still be running after stop attempt",
            name
        )));
    }

    // Persist state to database — only after confirmed stop
    let updated = db
        .update_vm(&name, |r| {
            r.state = RecordState::Stopped;
            r.pid = None;
            r.pid_start_time = None;
        })
        .map_err(ApiError::database)?;
    if updated.is_none() {
        return Err(ApiError::NotFound(format!(
            "microvm '{}' disappeared from database during stop",
            name
        )));
    }

    // Get updated record
    let record = db
        .get_vm(&name)
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::NotFound(format!("microvm '{}' not found", name)))?;

    Ok(Json(record_to_info(&name, &record)))
}

/// Delete a microvm.
#[utoipa::path(
    delete,
    path = "/api/v1/microvms/{name}",
    tag = "MicroVMs",
    params(
        ("name" = String, Path, description = "MicroVM name")
    ),
    responses(
        (status = 200, description = "MicroVM deleted", body = DeleteResponse),
        (status = 404, description = "MicroVM not found", body = ApiErrorResponse),
        (status = 500, description = "Failed to delete", body = ApiErrorResponse)
    )
)]
pub async fn delete_microvm(
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
) -> Result<Json<DeleteResponse>, ApiError> {
    let db = state.db();

    // Check if VM exists and get its state
    let record = db
        .get_vm(&name)
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::NotFound(format!("microvm '{}' not found", name)))?;

    // Get PID and start time from database record
    let pid = record.pid;
    let pid_start_time = record.pid_start_time;

    // Stop if running (in blocking task)
    let name_clone = name.clone();
    let stopped = tokio::task::spawn_blocking(move || {
        shutdown_microvm_process(&name_clone, pid, pid_start_time)
    })
    .await
    .map_err(|e| ApiError::internal(format!("task error: {}", e)))?;

    if !stopped {
        return Err(ApiError::Internal(format!(
            "microvm '{}' process (pid {}) is still alive after shutdown; not removing",
            name,
            pid.map(|p| p.to_string())
                .unwrap_or_else(|| "unknown".into()),
        )));
    }

    // Remove from database — safe now that process is confirmed dead
    let removed = db.remove_vm(&name).map_err(ApiError::database)?;
    if removed.is_none() {
        return Err(ApiError::NotFound(format!(
            "microvm '{}' was already removed",
            name
        )));
    }

    Ok(Json(DeleteResponse { deleted: name }))
}

/// Execute a command in a microvm.
#[utoipa::path(
    post,
    path = "/api/v1/microvms/{name}/exec",
    tag = "MicroVMs",
    params(
        ("name" = String, Path, description = "MicroVM name")
    ),
    request_body = MicrovmExecRequest,
    responses(
        (status = 200, description = "Command executed", body = ExecResponse),
        (status = 400, description = "Invalid request", body = ApiErrorResponse),
        (status = 404, description = "MicroVM not found", body = ApiErrorResponse),
        (status = 409, description = "MicroVM not running", body = ApiErrorResponse),
        (status = 500, description = "Execution failed", body = ApiErrorResponse)
    )
)]
pub async fn exec_microvm(
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
    Json(req): Json<MicrovmExecRequest>,
) -> Result<Json<ExecResponse>, ApiError> {
    validate_command(&req.command)?;

    // Check if VM exists
    let db = state.db();
    if db.get_vm(&name).map_err(ApiError::database)?.is_none() {
        return Err(ApiError::NotFound(format!("microvm '{}' not found", name)));
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

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(info.mounts, 2);
        assert_eq!(info.ports, 2);
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
        assert_eq!(info.mounts, 0);
        assert_eq!(info.ports, 0);
    }

    #[test]
    fn test_record_to_info_default_values() {
        let record = VmRecord::new("minimal-vm".to_string(), 1, 512, vec![], vec![], false);

        let info = record_to_info("minimal-vm", &record);

        assert_eq!(info.name, "minimal-vm");
        assert_eq!(info.state, "created");
        assert_eq!(info.cpus, 1);
        assert_eq!(info.mem, 512);
        assert_eq!(info.mounts, 0);
        assert_eq!(info.ports, 0);
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
}
