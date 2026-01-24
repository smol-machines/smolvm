//! Sandbox lifecycle handlers.

use axum::{
    extract::{Path, State},
    Json,
};
use std::sync::Arc;

use crate::agent::AgentManager;
use crate::api::error::ApiError;
use crate::api::state::{
    mount_spec_to_host_mount, port_spec_to_mapping, resource_spec_to_vm_resources,
    restart_spec_to_config, ApiState, ReservationGuard,
};
use crate::api::types::{
    CreateSandboxRequest, ListSandboxesResponse, MountInfo, MountSpec, ResourceSpec, SandboxInfo,
};
use crate::config::RecordState;

/// Minimum sandbox name length.
const MIN_NAME_LENGTH: usize = 1;

/// Maximum sandbox name length.
const MAX_NAME_LENGTH: usize = 64;

/// Convert MountSpec list to MountInfo list with virtiofs tags.
fn mounts_to_info(mounts: &[MountSpec]) -> Vec<MountInfo> {
    mounts
        .iter()
        .enumerate()
        .map(|(i, m)| MountInfo {
            tag: format!("smolvm{}", i),
            source: m.source.clone(),
            target: m.target.clone(),
            readonly: m.readonly,
        })
        .collect()
}

/// Validate a sandbox name.
///
/// Rules:
/// - Length: 1-64 characters
/// - Allowed characters: alphanumeric, hyphen (-), underscore (_)
/// - Must start with a letter or digit
/// - Cannot end with a hyphen
/// - No consecutive hyphens
/// - No path separators (/, \)
fn validate_sandbox_name(name: &str) -> Result<(), ApiError> {
    // Check length
    if name.len() < MIN_NAME_LENGTH {
        return Err(ApiError::BadRequest("sandbox name cannot be empty".into()));
    }
    if name.len() > MAX_NAME_LENGTH {
        return Err(ApiError::BadRequest(format!(
            "sandbox name too long: {} characters (max {})",
            name.len(),
            MAX_NAME_LENGTH
        )));
    }

    // Check first character (must be alphanumeric)
    let first_char = name.chars().next().unwrap();
    if !first_char.is_ascii_alphanumeric() {
        return Err(ApiError::BadRequest(
            "sandbox name must start with a letter or digit".into(),
        ));
    }

    // Check last character (cannot be hyphen)
    let last_char = name.chars().last().unwrap();
    if last_char == '-' {
        return Err(ApiError::BadRequest(
            "sandbox name cannot end with a hyphen".into(),
        ));
    }

    // Check all characters and patterns
    let mut prev_was_hyphen = false;
    for c in name.chars() {
        if c == '-' {
            if prev_was_hyphen {
                return Err(ApiError::BadRequest(
                    "sandbox name cannot contain consecutive hyphens".into(),
                ));
            }
            prev_was_hyphen = true;
        } else {
            prev_was_hyphen = false;
        }

        // Check character whitelist
        if !c.is_ascii_alphanumeric() && c != '-' && c != '_' {
            if c == '/' || c == '\\' {
                return Err(ApiError::BadRequest(
                    "sandbox name cannot contain path separators".into(),
                ));
            }
            return Err(ApiError::BadRequest(format!(
                "sandbox name contains invalid character: '{}'",
                c
            )));
        }
    }

    Ok(())
}

/// POST /api/v1/sandboxes - Create a new sandbox.
pub async fn create_sandbox(
    State(state): State<Arc<ApiState>>,
    Json(req): Json<CreateSandboxRequest>,
) -> Result<Json<SandboxInfo>, ApiError> {
    // Validate name format
    validate_sandbox_name(&req.name)?;

    // Validate mounts
    let _mounts_result: Result<Vec<_>, _> = req
        .mounts
        .iter()
        .map(mount_spec_to_host_mount)
        .collect();
    _mounts_result.map_err(|e| ApiError::BadRequest(e.to_string()))?;

    let resources = req.resources.clone().unwrap_or(ResourceSpec {
        cpus: None,
        memory_mb: None,
    });

    // Parse restart configuration
    let restart_config = restart_spec_to_config(req.restart.as_ref());

    // Reserve name with RAII guard - automatically released on any error or panic
    let guard = ReservationGuard::new(&state, req.name.clone())?;

    // Create AgentManager in blocking task
    let name = guard.name().to_string();
    let manager_result = tokio::task::spawn_blocking(move || AgentManager::for_vm(&name)).await;

    // Handle manager creation result - guard auto-releases on error return
    let manager = match manager_result {
        Ok(Ok(m)) => m,
        Ok(Err(e)) => return Err(ApiError::Internal(e.to_string())),
        Err(e) => return Err(ApiError::Internal(e.to_string())),
    };

    // Get state for response before completing registration
    let agent_state = format!("{:?}", manager.state()).to_lowercase();
    let pid = manager.child_pid();

    // Complete registration - consumes the guard
    guard.complete(
        manager,
        req.mounts.clone(),
        req.ports.clone(),
        resources.clone(),
        restart_config,
    )?;

    Ok(Json(SandboxInfo {
        name: req.name.clone(),
        state: agent_state,
        pid,
        mounts: mounts_to_info(&req.mounts),
        ports: req.ports,
        resources,
        restart_count: None,
    }))
}

/// GET /api/v1/sandboxes - List all sandboxes.
pub async fn list_sandboxes(
    State(state): State<Arc<ApiState>>,
) -> Json<ListSandboxesResponse> {
    let sandboxes = state.list_sandboxes();
    Json(ListSandboxesResponse { sandboxes })
}

/// GET /api/v1/sandboxes/:id - Get sandbox status.
pub async fn get_sandbox(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
) -> Result<Json<SandboxInfo>, ApiError> {
    let entry = state.get_sandbox(&id)?;
    let entry = entry.lock();

    let agent_state = format!("{:?}", entry.manager.state()).to_lowercase();
    let pid = entry.manager.child_pid();
    let restart_count = if entry.restart.restart_count > 0 {
        Some(entry.restart.restart_count)
    } else {
        None
    };

    Ok(Json(SandboxInfo {
        name: id,
        state: agent_state,
        pid,
        mounts: mounts_to_info(&entry.mounts),
        ports: entry.ports.clone(),
        resources: entry.resources.clone(),
        restart_count,
    }))
}

/// POST /api/v1/sandboxes/:id/start - Start a sandbox.
pub async fn start_sandbox(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
) -> Result<Json<SandboxInfo>, ApiError> {
    let entry = state.get_sandbox(&id)?;

    // Get configuration from entry
    let (mounts, ports, resources, mounts_spec, ports_spec, resources_spec) = {
        let entry = entry.lock();
        let mounts_result: Result<Vec<_>, _> = entry
            .mounts
            .iter()
            .map(mount_spec_to_host_mount)
            .collect();
        let mounts = mounts_result.map_err(|e| ApiError::Internal(e.to_string()))?;
        let ports: Vec<_> = entry.ports.iter().map(port_spec_to_mapping).collect();
        let resources = resource_spec_to_vm_resources(&entry.resources);
        (
            mounts,
            ports,
            resources,
            entry.mounts.clone(),
            entry.ports.clone(),
            entry.resources.clone(),
        )
    };

    // Clear user_stopped flag since user is explicitly starting
    state.mark_user_stopped(&id, false);

    // Close database before forking to prevent child from inheriting the fd lock
    state.close_db_temporarily();

    // Start the sandbox in a blocking task (this forks)
    let entry_clone = entry.clone();
    let start_result = tokio::task::spawn_blocking(move || {
        let entry = entry_clone.lock();
        entry
            .manager
            .ensure_running_with_full_config(mounts, ports, resources)
    })
    .await?;

    // Reopen database after fork completes
    state.reopen_db().map_err(|e| ApiError::Internal(e.to_string()))?;

    // Now check the start result
    start_result.map_err(|e| ApiError::Internal(e.to_string()))?;

    // Get updated state and persist
    let (agent_state, pid) = {
        let entry = entry.lock();
        let agent_state = format!("{:?}", entry.manager.state()).to_lowercase();
        let pid = entry.manager.child_pid();
        (agent_state, pid)
    };

    // Reset restart count on successful user-initiated start
    state.reset_restart_count(&id);

    // Persist state to config
    state.update_sandbox_state(&id, RecordState::Running, pid);

    Ok(Json(SandboxInfo {
        name: id,
        state: agent_state,
        pid,
        mounts: mounts_to_info(&mounts_spec),
        ports: ports_spec,
        resources: resources_spec,
        restart_count: None, // Just reset
    }))
}

/// POST /api/v1/sandboxes/:id/stop - Stop a sandbox.
pub async fn stop_sandbox(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
) -> Result<Json<SandboxInfo>, ApiError> {
    let entry = state.get_sandbox(&id)?;

    // Get config for response
    let (mounts_spec, ports_spec, resources_spec, restart_count) = {
        let entry = entry.lock();
        (
            entry.mounts.clone(),
            entry.ports.clone(),
            entry.resources.clone(),
            if entry.restart.restart_count > 0 {
                Some(entry.restart.restart_count)
            } else {
                None
            },
        )
    };

    // Mark as user-stopped before stopping (prevents auto-restart)
    state.mark_user_stopped(&id, true);

    // Stop the sandbox in a blocking task
    let entry_clone = entry.clone();
    tokio::task::spawn_blocking(move || {
        let entry = entry_clone.lock();
        entry.manager.stop()
    })
    .await?
    .map_err(|e| ApiError::Internal(e.to_string()))?;

    // Get updated state and persist
    let (agent_state, pid) = {
        let entry = entry.lock();
        let agent_state = format!("{:?}", entry.manager.state()).to_lowercase();
        let pid = entry.manager.child_pid();
        (agent_state, pid)
    };

    // Persist state to config
    state.update_sandbox_state(&id, RecordState::Stopped, None);

    Ok(Json(SandboxInfo {
        name: id,
        state: agent_state,
        pid,
        mounts: mounts_to_info(&mounts_spec),
        ports: ports_spec,
        resources: resources_spec,
        restart_count,
    }))
}

/// DELETE /api/v1/sandboxes/:id - Delete a sandbox.
pub async fn delete_sandbox(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let entry = state.remove_sandbox(&id)?;

    // Stop the sandbox if running
    tokio::task::spawn_blocking(move || {
        let entry = entry.lock();
        let _ = entry.manager.stop();
    })
    .await?;

    Ok(Json(serde_json::json!({
        "deleted": id
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_sandbox_name_valid() {
        // Valid names
        assert!(validate_sandbox_name("test").is_ok());
        assert!(validate_sandbox_name("my-sandbox").is_ok());
        assert!(validate_sandbox_name("my_sandbox").is_ok());
        assert!(validate_sandbox_name("test123").is_ok());
        assert!(validate_sandbox_name("123test").is_ok());
        assert!(validate_sandbox_name("a").is_ok());
        assert!(validate_sandbox_name("test-sandbox-123").is_ok());
        assert!(validate_sandbox_name("TEST_SANDBOX").is_ok());
        assert!(validate_sandbox_name("a".repeat(64).as_str()).is_ok());
    }

    #[test]
    fn test_validate_sandbox_name_empty() {
        let err = validate_sandbox_name("").unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn test_validate_sandbox_name_too_long() {
        let long_name = "a".repeat(65);
        let err = validate_sandbox_name(&long_name).unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn test_validate_sandbox_name_invalid_first_char() {
        assert!(validate_sandbox_name("-test").is_err());
        assert!(validate_sandbox_name("_test").is_err());
        assert!(validate_sandbox_name(".test").is_err());
    }

    #[test]
    fn test_validate_sandbox_name_invalid_last_char() {
        assert!(validate_sandbox_name("test-").is_err());
    }

    #[test]
    fn test_validate_sandbox_name_consecutive_hyphens() {
        assert!(validate_sandbox_name("test--sandbox").is_err());
        assert!(validate_sandbox_name("a---b").is_err());
    }

    #[test]
    fn test_validate_sandbox_name_path_separators() {
        assert!(validate_sandbox_name("test/sandbox").is_err());
        assert!(validate_sandbox_name("test\\sandbox").is_err());
        assert!(validate_sandbox_name("../test").is_err());
    }

    #[test]
    fn test_validate_sandbox_name_invalid_chars() {
        assert!(validate_sandbox_name("test sandbox").is_err()); // space
        assert!(validate_sandbox_name("test@sandbox").is_err());
        assert!(validate_sandbox_name("test!sandbox").is_err());
        assert!(validate_sandbox_name("test$sandbox").is_err());
        assert!(validate_sandbox_name("test.sandbox").is_err()); // dot not allowed
        assert!(validate_sandbox_name("test:sandbox").is_err());
    }
}
