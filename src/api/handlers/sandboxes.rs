//! Sandbox lifecycle handlers.

use axum::{
    extract::{Path, Query, State},
    Json,
};
use std::sync::Arc;

use crate::agent::AgentManager;
use crate::api::error::ApiError;
use crate::api::state::{
    mount_spec_to_host_mount, port_spec_to_mapping, resource_spec_to_vm_resources,
    restart_spec_to_config, ApiState, DbCloseGuard, ReservationGuard, SandboxRegistration,
};
use crate::api::types::{
    ApiErrorResponse, CreateSandboxRequest, DeleteQuery, DeleteResponse, ListSandboxesResponse,
    MountInfo, MountSpec, ResourceSpec, SandboxInfo,
};
use crate::config::RecordState;

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
    // Check length and get first/last chars safely
    let first_char = name
        .chars()
        .next()
        .ok_or_else(|| ApiError::BadRequest("sandbox name cannot be empty".into()))?;

    if name.len() > MAX_NAME_LENGTH {
        return Err(ApiError::BadRequest(format!(
            "sandbox name too long: {} characters (max {})",
            name.len(),
            MAX_NAME_LENGTH
        )));
    }

    // Check first character (must be alphanumeric)
    if !first_char.is_ascii_alphanumeric() {
        return Err(ApiError::BadRequest(
            "sandbox name must start with a letter or digit".into(),
        ));
    }

    // Check last character (cannot be hyphen)
    // Safe to unwrap: we know string is non-empty from first_char check
    let last_char = name.chars().last().expect("non-empty string has last char");
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

/// Create a new sandbox.
#[utoipa::path(
    post,
    path = "/api/v1/sandboxes",
    tag = "Sandboxes",
    request_body = CreateSandboxRequest,
    responses(
        (status = 200, description = "Sandbox created", body = SandboxInfo),
        (status = 400, description = "Invalid request", body = ApiErrorResponse),
        (status = 409, description = "Sandbox already exists", body = ApiErrorResponse)
    )
)]
pub async fn create_sandbox(
    State(state): State<Arc<ApiState>>,
    Json(req): Json<CreateSandboxRequest>,
) -> Result<Json<SandboxInfo>, ApiError> {
    // Validate name format
    validate_sandbox_name(&req.name)?;

    // Validate mounts
    let _mounts_result: Result<Vec<_>, _> =
        req.mounts.iter().map(mount_spec_to_host_mount).collect();
    _mounts_result.map_err(|e| ApiError::BadRequest(e.to_string()))?;

    let resources = req.resources.clone().unwrap_or(ResourceSpec {
        cpus: None,
        memory_mb: None,
        network: None,
    });

    // Get network setting from resources (default to false)
    let network = resources.network.unwrap_or(false);

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
    guard.complete(SandboxRegistration {
        manager,
        mounts: req.mounts.clone(),
        ports: req.ports.clone(),
        resources: resources.clone(),
        restart: restart_config,
        network,
    })?;

    Ok(Json(SandboxInfo {
        name: req.name.clone(),
        state: agent_state,
        pid,
        mounts: mounts_to_info(&req.mounts),
        ports: req.ports,
        resources,
        network,
        restart_count: None,
    }))
}

/// List all sandboxes.
#[utoipa::path(
    get,
    path = "/api/v1/sandboxes",
    tag = "Sandboxes",
    responses(
        (status = 200, description = "List of sandboxes", body = ListSandboxesResponse)
    )
)]
pub async fn list_sandboxes(State(state): State<Arc<ApiState>>) -> Json<ListSandboxesResponse> {
    let sandboxes = state.list_sandboxes();
    Json(ListSandboxesResponse { sandboxes })
}

/// Get sandbox status.
#[utoipa::path(
    get,
    path = "/api/v1/sandboxes/{id}",
    tag = "Sandboxes",
    params(
        ("id" = String, Path, description = "Sandbox name")
    ),
    responses(
        (status = 200, description = "Sandbox details", body = SandboxInfo),
        (status = 404, description = "Sandbox not found", body = ApiErrorResponse)
    )
)]
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
        network: entry.network,
        restart_count,
    }))
}

/// Start a sandbox.
#[utoipa::path(
    post,
    path = "/api/v1/sandboxes/{id}/start",
    tag = "Sandboxes",
    params(
        ("id" = String, Path, description = "Sandbox name")
    ),
    responses(
        (status = 200, description = "Sandbox started", body = SandboxInfo),
        (status = 404, description = "Sandbox not found", body = ApiErrorResponse),
        (status = 500, description = "Failed to start", body = ApiErrorResponse)
    )
)]
pub async fn start_sandbox(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
) -> Result<Json<SandboxInfo>, ApiError> {
    let entry = state.get_sandbox(&id)?;

    // Get configuration from entry
    let (mounts, ports, resources, mounts_spec, ports_spec, resources_spec, network) = {
        let entry = entry.lock();
        let mounts_result: Result<Vec<_>, _> =
            entry.mounts.iter().map(mount_spec_to_host_mount).collect();
        let mounts = mounts_result.map_err(|e| ApiError::Internal(e.to_string()))?;
        let ports: Vec<_> = entry.ports.iter().map(port_spec_to_mapping).collect();
        let resources = resource_spec_to_vm_resources(&entry.resources, entry.network);
        (
            mounts,
            ports,
            resources,
            entry.mounts.clone(),
            entry.ports.clone(),
            entry.resources.clone(),
            entry.network,
        )
    };

    // Clear user_stopped flag since user is explicitly starting
    state.mark_user_stopped(&id, false);

    // Start the sandbox in a blocking task (this forks).
    // Use DbCloseGuard to ensure DB is reopened even if cancelled/panicked.
    let start_result = {
        let _db_guard = DbCloseGuard::new(&state);

        let entry_clone = entry.clone();
        tokio::task::spawn_blocking(move || {
            let entry = entry_clone.lock();
            entry
                .manager
                .ensure_running_with_full_config(mounts, ports, resources)
        })
        .await
        // Guard dropped here, DB reopened (even on cancellation)
    };

    // Check the task join result, then the start result
    let start_result = start_result?;
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
        network,
        restart_count: None, // Just reset
    }))
}

/// Stop a sandbox.
#[utoipa::path(
    post,
    path = "/api/v1/sandboxes/{id}/stop",
    tag = "Sandboxes",
    params(
        ("id" = String, Path, description = "Sandbox name")
    ),
    responses(
        (status = 200, description = "Sandbox stopped", body = SandboxInfo),
        (status = 404, description = "Sandbox not found", body = ApiErrorResponse),
        (status = 500, description = "Failed to stop", body = ApiErrorResponse)
    )
)]
pub async fn stop_sandbox(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
) -> Result<Json<SandboxInfo>, ApiError> {
    let entry = state.get_sandbox(&id)?;

    // Get config for response
    let (mounts_spec, ports_spec, resources_spec, network, restart_count) = {
        let entry = entry.lock();
        (
            entry.mounts.clone(),
            entry.ports.clone(),
            entry.resources.clone(),
            entry.network,
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
        network,
        restart_count,
    }))
}

/// Delete a sandbox.
#[utoipa::path(
    delete,
    path = "/api/v1/sandboxes/{id}",
    tag = "Sandboxes",
    params(
        ("id" = String, Path, description = "Sandbox name"),
        ("force" = Option<bool>, Query, description = "Force delete even if VM is still running")
    ),
    responses(
        (status = 200, description = "Sandbox deleted", body = DeleteResponse),
        (status = 404, description = "Sandbox not found", body = ApiErrorResponse),
        (status = 409, description = "VM still running, use force=true", body = ApiErrorResponse)
    )
)]
pub async fn delete_sandbox(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
    Query(query): Query<DeleteQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // First, get the entry and stop the sandbox (before removing from registry).
    let entry = state.get_sandbox(&id)?;

    // Stop the sandbox if running
    let entry_clone = entry.clone();
    let stop_result = tokio::task::spawn_blocking(move || {
        let entry = entry_clone.lock();
        entry.manager.stop()
    })
    .await?;

    // Handle stop errors
    if let Err(ref e) = stop_result {
        // Check if VM is actually still running
        let still_running = {
            let entry = entry.lock();
            entry.manager.is_running()
        };

        if still_running && !query.force {
            // VM is still running and force not specified - refuse to orphan it
            return Err(ApiError::Conflict(format!(
                "failed to stop sandbox '{}': {}. VM is still running. \
                 Use ?force=true to delete anyway (will orphan the VM process)",
                id, e
            )));
        }

        // Either VM is not running, or force=true - proceed with warning
        tracing::warn!(
            sandbox = %id,
            error = %e,
            still_running = still_running,
            force = query.force,
            "stop failed during delete, proceeding with removal"
        );
    }

    // Now remove from registry and database
    state.remove_sandbox(&id)?;

    Ok(Json(serde_json::json!({
        "deleted": id
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_sandbox_name() {
        // Valid names
        let valid = [
            "test",
            "my-sandbox",
            "my_sandbox",
            "test123",
            "123test",
            "a",
            "test-sandbox-123",
            "TEST_SANDBOX",
            &"a".repeat(64),
        ];
        for name in valid {
            assert!(
                validate_sandbox_name(name).is_ok(),
                "expected '{}' to be valid",
                name
            );
        }

        // Invalid names
        let invalid = [
            ("", "empty"),
            (&"a".repeat(65), "too long"),
            ("-test", "starts with hyphen"),
            ("_test", "starts with underscore"),
            (".test", "starts with dot"),
            ("test-", "ends with hyphen"),
            ("test--sandbox", "consecutive hyphens"),
            ("test/sandbox", "forward slash"),
            ("test\\sandbox", "backslash"),
            ("../test", "path traversal"),
            ("test sandbox", "space"),
            ("test@sandbox", "at sign"),
            ("test.sandbox", "dot"),
        ];
        for (name, desc) in invalid {
            assert!(
                validate_sandbox_name(name).is_err(),
                "expected '{}' ({}) to be invalid",
                name,
                desc
            );
        }
    }
}
