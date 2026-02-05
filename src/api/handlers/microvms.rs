//! MicroVM lifecycle handlers.
//!
//! These handlers manage persistent microVMs via the shared database,
//! accessible to both API and CLI commands.
//!
//! ## Limitations
//!
//! ### Name Length Limit
//!
//! MicroVM names are limited to 64 characters. However, due to Unix domain
//! socket path length limits (~104 bytes on macOS), very long names may cause
//! issues. The full socket path is:
//!
//! ```text
//! ~/Library/Caches/smolvm/vms/{name}/agent.sock
//! ```
//!
//! With a typical macOS home directory path, names should be kept under ~40
//! characters to avoid socket path length issues. The API will accept longer
//! names but VM startup may fail silently.
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
use crate::api::state::ApiState;
use crate::api::types::{
    CreateMicrovmRequest, ExecResponse, ListMicrovmsResponse, MicrovmExecRequest, MicrovmInfo,
};
use crate::config::{RecordState, VmRecord};

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
/// - Length: 1-64 characters
/// - Allowed characters: alphanumeric, hyphen (-), underscore (_)
/// - Must start with a letter or digit
/// - Cannot end with a hyphen
/// - No consecutive hyphens
/// - No path separators (/, \)
fn validate_microvm_name(name: &str) -> Result<(), ApiError> {
    let first_char = name
        .chars()
        .next()
        .ok_or_else(|| ApiError::BadRequest("microvm name cannot be empty".into()))?;

    if name.len() > MAX_NAME_LENGTH {
        return Err(ApiError::BadRequest(format!(
            "microvm name too long: {} characters (max {})",
            name.len(),
            MAX_NAME_LENGTH
        )));
    }

    if !first_char.is_ascii_alphanumeric() {
        return Err(ApiError::BadRequest(
            "microvm name must start with a letter or digit".into(),
        ));
    }

    let last_char = name.chars().last().expect("non-empty string has last char");
    if last_char == '-' {
        return Err(ApiError::BadRequest(
            "microvm name cannot end with a hyphen".into(),
        ));
    }

    let mut prev_was_hyphen = false;
    for c in name.chars() {
        if c == '-' {
            if prev_was_hyphen {
                return Err(ApiError::BadRequest(
                    "microvm name cannot contain consecutive hyphens".into(),
                ));
            }
            prev_was_hyphen = true;
        } else {
            prev_was_hyphen = false;
        }

        if !c.is_ascii_alphanumeric() && c != '-' && c != '_' {
            if c == '/' || c == '\\' {
                return Err(ApiError::BadRequest(
                    "microvm name cannot contain path separators".into(),
                ));
            }
            return Err(ApiError::BadRequest(format!(
                "microvm name contains invalid character: '{}'",
                c
            )));
        }
    }

    Ok(())
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
        created_at: record.created_at.clone(),
    }
}

/// POST /api/v1/microvms - Create a new microvm.
pub async fn create_microvm(
    State(state): State<Arc<ApiState>>,
    Json(req): Json<CreateMicrovmRequest>,
) -> Result<Json<MicrovmInfo>, ApiError> {
    // Validate name format
    validate_microvm_name(&req.name)?;

    let name = req.name.clone();
    let cpus = req.cpus;
    let mem = req.mem;

    // Convert mounts to storage format
    let mounts: Vec<(String, String, bool)> = req
        .mounts
        .iter()
        .map(|m| (m.source.clone(), m.target.clone(), m.readonly))
        .collect();

    // Convert ports to storage format
    let ports: Vec<(u16, u16)> = req.ports.iter().map(|p| (p.host, p.guest)).collect();

    // Create record (enable network by default for API-created microvms)
    let record = VmRecord::new(name.clone(), cpus, mem, mounts, ports, true);

    // Use atomic insert to detect conflicts
    let db = state.db();
    match db.insert_vm_if_not_exists(&name, &record) {
        Ok(true) => Ok(Json(record_to_info(&name, &record))),
        Ok(false) => Err(ApiError::Conflict(format!(
            "microvm '{}' already exists",
            name
        ))),
        Err(e) => Err(ApiError::Internal(format!("database error: {}", e))),
    }
}

/// GET /api/v1/microvms - List all microvms.
pub async fn list_microvms(
    State(state): State<Arc<ApiState>>,
) -> Result<Json<ListMicrovmsResponse>, ApiError> {
    let db = state.db();
    let vms = db
        .list_vms()
        .map_err(|e| ApiError::Internal(format!("database error: {}", e)))?;

    let microvms: Vec<MicrovmInfo> = vms
        .iter()
        .map(|(name, record)| record_to_info(name, record))
        .collect();

    Ok(Json(ListMicrovmsResponse { microvms }))
}

/// GET /api/v1/microvms/:name - Get microvm status.
pub async fn get_microvm(
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
) -> Result<Json<MicrovmInfo>, ApiError> {
    let db = state.db();
    let record = db
        .get_vm(&name)
        .map_err(|e| ApiError::Internal(format!("database error: {}", e)))?
        .ok_or_else(|| ApiError::NotFound(format!("microvm '{}' not found", name)))?;

    Ok(Json(record_to_info(&name, &record)))
}

/// POST /api/v1/microvms/:name/start - Start a microvm.
pub async fn start_microvm(
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
) -> Result<Json<MicrovmInfo>, ApiError> {
    // Get VM record from database
    let db = state.db();
    let record = db
        .get_vm(&name)
        .map_err(|e| ApiError::Internal(format!("database error: {}", e)))?
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

    // Start agent VM in blocking task
    let name_clone = name.clone();
    let db_clone = db.clone();
    let result = tokio::task::spawn_blocking(move || {
        let manager = AgentManager::for_vm(&name_clone)
            .map_err(|e| format!("failed to create agent manager: {}", e))?;

        manager
            .ensure_running_with_full_config(mounts, ports, resources)
            .map_err(|e| format!("failed to start microvm: {}", e))?;

        // Update state in database
        let pid = manager.child_pid();
        let _ = db_clone.update_vm(&name_clone, |r| {
            r.state = RecordState::Running;
            r.pid = pid;
        });

        // Keep VM running (persistent)
        manager.detach();

        // Get updated record
        db_clone
            .get_vm(&name_clone)
            .map_err(|e| format!("database error: {}", e))
    })
    .await
    .map_err(|e| ApiError::Internal(format!("task error: {}", e)))?;

    match result {
        Ok(Some(record)) => Ok(Json(record_to_info(&name, &record))),
        Ok(None) => Err(ApiError::NotFound(format!("microvm '{}' not found", name))),
        Err(e) => Err(ApiError::Internal(e)),
    }
}

/// POST /api/v1/microvms/:name/stop - Stop a microvm.
pub async fn stop_microvm(
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
) -> Result<Json<MicrovmInfo>, ApiError> {
    // Get VM record from database
    let db = state.db();
    let record = db
        .get_vm(&name)
        .map_err(|e| ApiError::Internal(format!("database error: {}", e)))?
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
        let _ = db_clone.update_vm(&name_clone, |r| {
            r.state = RecordState::Stopped;
            r.pid = None;
        });
    })
    .await
    .map_err(|e| ApiError::Internal(format!("task error: {}", e)))?;

    // Get updated record
    let record = db
        .get_vm(&name)
        .map_err(|e| ApiError::Internal(format!("database error: {}", e)))?
        .ok_or_else(|| ApiError::NotFound(format!("microvm '{}' not found", name)))?;

    Ok(Json(record_to_info(&name, &record)))
}

/// DELETE /api/v1/microvms/:name - Delete a microvm.
pub async fn delete_microvm(
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let db = state.db();

    // Check if VM exists and get its state
    let record = db
        .get_vm(&name)
        .map_err(|e| ApiError::Internal(format!("database error: {}", e)))?
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
    .map_err(|e| ApiError::Internal(format!("task error: {}", e)))?;

    // Remove from database
    db.remove_vm(&name)
        .map_err(|e| ApiError::Internal(format!("database error: {}", e)))?;

    Ok(Json(serde_json::json!({
        "deleted": name
    })))
}

/// POST /api/v1/microvms/:name/exec - Execute a command in a microvm.
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
    if db
        .get_vm(&name)
        .map_err(|e| ApiError::Internal(format!("database error: {}", e)))?
        .is_none()
    {
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
            .map_err(|e| format!("failed to create agent manager: {}", e))?;

        if manager.try_connect_existing().is_none() {
            return Err(format!("microvm '{}' is not running", name_clone));
        }

        // Execute command
        let mut client = manager
            .connect()
            .map_err(|e| format!("connect error: {}", e))?;
        let (exit_code, stdout, stderr) = client
            .vm_exec(command, env, workdir, timeout)
            .map_err(|e| format!("exec error: {}", e))?;

        // Keep VM running (persistent)
        manager.detach();

        Ok(ExecResponse {
            exit_code,
            stdout,
            stderr,
        })
    })
    .await
    .map_err(|e| ApiError::Internal(format!("task error: {}", e)))?;

    result.map(Json).map_err(|e: String| {
        if e.contains("not running") {
            ApiError::Conflict(e)
        } else {
            ApiError::Internal(e)
        }
    })
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
        assert!(info.pid.is_none());
        assert!(!info.created_at.is_empty());
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
