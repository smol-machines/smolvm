//! Sandbox lifecycle handlers.

use axum::{
    extract::{Path, Query, State},
    Json,
};
use std::sync::Arc;

use crate::agent::{AgentManager, HostMount};
use crate::api::error::{classify_ensure_running_error, ApiError};
use crate::api::state::{
    ensure_sandbox_running, restart_spec_to_config, ApiState, ReservationGuard, SandboxRegistration,
};
use crate::api::types::{
    ApiErrorResponse, CreateSandboxRequest, DeleteQuery, DeleteResponse, ListSandboxesResponse,
    MountInfo, MountSpec, ResourceSpec, SandboxInfo,
};
use crate::api::validation::validate_resource_name;
use crate::config::RecordState;

/// Maximum sandbox name length.
/// Socket path is ~/Library/Caches/smolvm/vms/{name}/agent.sock — a name
/// of 40 chars results in a socket path of ~90 chars, leaving some margin.
const MAX_NAME_LENGTH: usize = 40;

/// Convert MountSpec list to MountInfo list with virtiofs tags.
pub(crate) fn mounts_to_info(mounts: &[MountSpec]) -> Vec<MountInfo> {
    mounts
        .iter()
        .enumerate()
        .map(|(i, m)| MountInfo {
            tag: crate::agent::mount_tag(i),
            source: m.source.clone(),
            target: m.target.clone(),
            readonly: m.readonly,
        })
        .collect()
}

/// Build a SandboxInfo from a locked SandboxEntry.
pub(crate) fn sandbox_entry_to_info(
    name: String,
    entry: &crate::api::state::SandboxEntry,
) -> SandboxInfo {
    let (effective_state, pid) = entry.manager.effective_status();
    SandboxInfo {
        name,
        state: effective_state.to_string(),
        pid,
        mounts: mounts_to_info(&entry.mounts),
        ports: entry.ports.clone(),
        resources: entry.resources.clone(),
        network: entry.network,
        restart_count: if entry.restart.restart_count > 0 {
            Some(entry.restart.restart_count)
        } else {
            None
        },
    }
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
    validate_resource_name(&req.name, "sandbox", MAX_NAME_LENGTH)?;

    // Validate mounts
    let mounts_result: Result<Vec<_>, _> = req.mounts.iter().map(HostMount::try_from).collect();
    mounts_result.map_err(|e| ApiError::BadRequest(e.to_string()))?;

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
        Ok(Err(e)) => return Err(ApiError::internal(e)),
        Err(e) => return Err(ApiError::internal(e)),
    };

    // Get state for response before completing registration
    let agent_state = manager.state().to_string();
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
    Ok(Json(sandbox_entry_to_info(id, &entry)))
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

    // Snapshot configuration for response
    let (mounts_spec, ports_spec, resources_spec, network) = {
        let entry = entry.lock();
        (
            entry.mounts.clone(),
            entry.ports.clone(),
            entry.resources.clone(),
            entry.network,
        )
    };

    // Clear user_stopped flag since user is explicitly starting
    state.mark_user_stopped(&id, false);

    // Start sandbox (child process closes inherited fds, so DB stays open).
    ensure_sandbox_running(&entry)
        .await
        .map_err(classify_ensure_running_error)?;

    // Get updated state and persist
    let (agent_state, pid) = {
        let entry = entry.lock();
        let agent_state = entry.manager.state().to_string();
        let pid = entry.manager.child_pid();
        (agent_state, pid)
    };

    // Reset restart count on successful user-initiated start
    state.reset_restart_count(&id);

    // Persist state to config
    state
        .update_sandbox_state(&id, RecordState::Running, pid)
        .map_err(ApiError::database)?;

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
    let stop_result = tokio::task::spawn_blocking(move || {
        let entry = entry_clone.lock();
        entry.manager.stop()
    })
    .await?;

    if let Err(e) = stop_result {
        // Roll back user_stopped so the supervisor can still restart if configured
        state.mark_user_stopped(&id, false);
        return Err(ApiError::internal(e));
    }

    // Get updated state and persist
    let (agent_state, pid) = {
        let entry = entry.lock();
        let agent_state = entry.manager.state().to_string();
        let pid = entry.manager.child_pid();
        (agent_state, pid)
    };

    // Persist state to config
    state
        .update_sandbox_state(&id, RecordState::Stopped, None)
        .map_err(ApiError::database)?;

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
) -> Result<Json<DeleteResponse>, ApiError> {
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
        // Check if VM process is actually still alive using start-time-aware
        // verification across both child handle and PID file.
        let still_running = {
            let entry = entry.lock();
            entry.manager.is_process_alive()
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

    Ok(Json(DeleteResponse { deleted: id }))
}
