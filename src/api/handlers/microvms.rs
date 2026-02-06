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
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::agent::{AgentManager, HostMount, PortMapping, VmResources};
use crate::api::error::ApiError;
use crate::api::state::{ApiState, DbCloseGuard};
use crate::api::types::{
    ApiErrorResponse, CreateMicrovmRequest, DeleteResponse, ExecResponse, ListMicrovmsResponse,
    MicrovmExecRequest, MicrovmInfo,
};
use crate::api::validation::validate_resource_name;
use crate::config::{RecordState, VmRecord};
use crate::mount::MountBinding;

/// Maximum microvm name length.
///
/// This is limited to 40 characters to ensure the Unix domain socket path
/// (~/Library/Caches/smolvm/vms/{name}/agent.sock) stays under the 104-byte
/// limit on macOS. With a typical home directory path of ~30 chars, a name
/// of 40 chars results in a socket path of ~90 chars, leaving some margin.
const MAX_NAME_LENGTH: usize = 40;

/// Validate a microvm name.
///
/// Rules:
/// - Length: 1-40 characters
/// - Allowed characters: alphanumeric, hyphen (-), underscore (_)
/// - Must start with a letter or digit
/// - Cannot end with a hyphen
/// - No consecutive hyphens
/// - No path separators (/, \)
fn validate_microvm_name(name: &str) -> Result<(), ApiError> {
    validate_resource_name(name, "microvm", MAX_NAME_LENGTH)
}

/// Convert VmRecord to MicrovmInfo.
fn record_to_info(name: &str, record: &VmRecord) -> MicrovmInfo {
    let actual_state = record.actual_state();
    MicrovmInfo {
        name: name.to_string(),
        state: actual_state.to_string(),
        cpus: record.cpus,
        mem: record.mem,
        pid: record.pid,
        mounts: record.mounts.len(),
        ports: record.ports.len(),
        network: record.network,
        created_at: record.created_at.clone(),
    }
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
    validate_microvm_name(&req.name)?;

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
    let record = VmRecord::new(name.clone(), cpus, mem, mounts, ports, req.network);

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

    // Convert stored mounts to HostMount
    let mounts: Vec<HostMount> = record
        .mounts
        .iter()
        .map(|(host, guest, ro)| HostMount {
            source: PathBuf::from(host),
            target: PathBuf::from(guest),
            read_only: *ro,
        })
        .collect();

    // Convert stored ports to PortMapping
    let ports: Vec<PortMapping> = record
        .ports
        .iter()
        .map(|(host, guest)| PortMapping::new(*host, *guest))
        .collect();

    let resources = VmResources {
        cpus: record.cpus,
        mem: record.mem,
        network: record.network,
    };

    // Start agent VM in blocking task.
    // DbCloseGuard ensures the database fd is not inherited by the forked child.
    let name_clone = name.clone();
    let pid = {
        let _db_guard = DbCloseGuard::new(&state);
        tokio::task::spawn_blocking(move || {
            let manager = AgentManager::for_vm(&name_clone)
                .map_err(|e| format!("failed to create agent manager: {}", e))?;

            manager
                .ensure_running_with_full_config(mounts, ports, resources)
                .map_err(|e| format!("failed to start microvm: {}", e))?;

            let pid = manager.child_pid();
            manager.detach();
            Ok::<_, String>(pid)
        })
        .await
        .map_err(|e| ApiError::internal(format!("task error: {}", e)))?
        .map_err(ApiError::internal)?
    };
    // Guard dropped — DB reopened

    // Update state in database (after fork, DB is safe to use)
    if let Err(e) = db.update_vm(&name, |r| {
        r.state = RecordState::Running;
        r.pid = pid;
    }) {
        tracing::warn!(error = %e, "failed to persist microvm state");
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

    // Get PID from database record - this is the source of truth
    let pid = record.pid;

    // Stop VM in blocking task
    let name_clone = name.clone();
    let db_clone = db.clone();
    tokio::task::spawn_blocking(move || {
        // First try graceful shutdown via vsock
        if let Ok(manager) = AgentManager::for_vm(&name_clone) {
            // manager.stop() won't work because it creates a new manager without the child
            // But we can use it to get the vsock socket path and try graceful shutdown
            if let Ok(mut client) = crate::agent::AgentClient::connect(manager.vsock_socket()) {
                let _ = client.shutdown();
            }
        }

        // Terminate the process using PID from database
        if let Some(pid) = pid {
            crate::process::terminate(pid);
            // Give it a moment to exit gracefully
            std::thread::sleep(std::time::Duration::from_millis(100));
            // Force kill if still running
            if crate::process::is_alive(pid) {
                crate::process::kill(pid);
            }
        }

        // Update state in database
        if let Err(e) = db_clone.update_vm(&name_clone, |r| {
            r.state = RecordState::Stopped;
            r.pid = None;
        }) {
            tracing::warn!(error = %e, "failed to persist microvm state");
        }
    })
    .await
    .map_err(|e| ApiError::internal(format!("task error: {}", e)))?;

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

    // Get PID from database record
    let pid = record.pid;

    // Stop if running (in blocking task)
    let name_clone = name.clone();
    tokio::task::spawn_blocking(move || {
        // First try graceful shutdown via vsock
        if let Ok(manager) = AgentManager::for_vm(&name_clone) {
            if let Ok(mut client) = crate::agent::AgentClient::connect(manager.vsock_socket()) {
                let _ = client.shutdown();
            }
        }

        // Terminate the process using PID from database
        if let Some(pid) = pid {
            crate::process::terminate(pid);
            // Give it a moment to exit gracefully
            std::thread::sleep(std::time::Duration::from_millis(100));
            // Force kill if still running
            if crate::process::is_alive(pid) {
                crate::process::kill(pid);
            }
        }
    })
    .await
    .map_err(|e| ApiError::internal(format!("task error: {}", e)))?;

    // Remove from database
    db.remove_vm(&name).map_err(ApiError::database)?;

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
    if req.command.is_empty() {
        return Err(ApiError::BadRequest("command cannot be empty".into()));
    }

    // Check if VM exists
    let db = state.db();
    if db.get_vm(&name).map_err(ApiError::database)?.is_none() {
        return Err(ApiError::NotFound(format!("microvm '{}' not found", name)));
    }

    let name_clone = name.clone();
    let command = req.command.clone();
    let env: Vec<(String, String)> = req
        .env
        .iter()
        .map(|e| (e.name.clone(), e.value.clone()))
        .collect();
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
    fn test_validate_microvm_name() {
        // Valid names
        let valid = [
            "test",
            "my-vm",
            "my_vm",
            "test123",
            "123test",
            "a",
            "test-vm-123",
            "TEST_VM",
            &"a".repeat(40), // max length
        ];
        for name in valid {
            assert!(
                validate_microvm_name(name).is_ok(),
                "expected '{}' to be valid",
                name
            );
        }

        // Invalid names
        let invalid = [
            ("", "empty"),
            (&"a".repeat(41), "too long"),
            ("-test", "starts with hyphen"),
            ("_test", "starts with underscore"),
            ("test-", "ends with hyphen"),
            ("test--vm", "consecutive hyphens"),
            ("test/vm", "forward slash"),
            ("test\\vm", "backslash"),
            ("test vm", "space"),
            ("test@vm", "at sign"),
            ("../test", "path traversal"),
        ];
        for (name, desc) in invalid {
            assert!(
                validate_microvm_name(name).is_err(),
                "expected '{}' ({}) to be invalid",
                name,
                desc
            );
        }
    }

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

    #[test]
    fn test_validate_microvm_name_special_characters() {
        // Underscore is allowed
        assert!(validate_microvm_name("test_vm").is_ok());
        assert!(validate_microvm_name("test_vm_123").is_ok());

        // Dot is not allowed
        assert!(validate_microvm_name("test.vm").is_err());

        // Colon is not allowed
        assert!(validate_microvm_name("test:vm").is_err());

        // Hash is not allowed
        assert!(validate_microvm_name("test#vm").is_err());
    }

    #[test]
    fn test_validate_microvm_name_boundary_conditions() {
        // Single character (minimum valid)
        assert!(validate_microvm_name("a").is_ok());
        assert!(validate_microvm_name("1").is_ok());

        // 40 characters (maximum valid - limited for Unix socket path length)
        assert!(validate_microvm_name(&"a".repeat(40)).is_ok());

        // 41 characters (too long)
        assert!(validate_microvm_name(&"a".repeat(41)).is_err());
    }
}
