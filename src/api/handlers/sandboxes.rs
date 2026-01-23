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
    ApiState,
};
use crate::api::types::{
    CreateSandboxRequest, ListSandboxesResponse, MountInfo, MountSpec, ResourceSpec, SandboxInfo,
};
use crate::config::RecordState;

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

/// POST /api/v1/sandboxes - Create a new sandbox.
pub async fn create_sandbox(
    State(state): State<Arc<ApiState>>,
    Json(req): Json<CreateSandboxRequest>,
) -> Result<Json<SandboxInfo>, ApiError> {
    // Validate name
    if req.name.is_empty() {
        return Err(ApiError::BadRequest("sandbox name cannot be empty".into()));
    }
    if req.name.contains('/') || req.name.contains('\\') {
        return Err(ApiError::BadRequest(
            "sandbox name cannot contain path separators".into(),
        ));
    }

    // Check if already exists
    if state.sandbox_exists(&req.name) {
        return Err(ApiError::Conflict(format!(
            "sandbox '{}' already exists",
            req.name
        )));
    }

    // Convert specs
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

    let name = req.name.clone();

    // Create AgentManager in blocking task
    let manager = tokio::task::spawn_blocking(move || AgentManager::for_vm(&name))
        .await?
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    // Get state for response
    let agent_state = format!("{:?}", manager.state()).to_lowercase();
    let pid = manager.child_pid();

    // Register sandbox
    state.register_sandbox(
        req.name.clone(),
        manager,
        req.mounts.clone(),
        req.ports.clone(),
        resources.clone(),
    )?;

    Ok(Json(SandboxInfo {
        name: req.name.clone(),
        state: agent_state,
        pid,
        mounts: mounts_to_info(&req.mounts),
        ports: req.ports,
        resources,
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

    Ok(Json(SandboxInfo {
        name: id,
        state: agent_state,
        pid,
        mounts: mounts_to_info(&entry.mounts),
        ports: entry.ports.clone(),
        resources: entry.resources.clone(),
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

    // Persist state to config
    state.update_sandbox_state(&id, RecordState::Running, pid);

    Ok(Json(SandboxInfo {
        name: id,
        state: agent_state,
        pid,
        mounts: mounts_to_info(&mounts_spec),
        ports: ports_spec,
        resources: resources_spec,
    }))
}

/// POST /api/v1/sandboxes/:id/stop - Stop a sandbox.
pub async fn stop_sandbox(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
) -> Result<Json<SandboxInfo>, ApiError> {
    let entry = state.get_sandbox(&id)?;

    // Get config for response
    let (mounts_spec, ports_spec, resources_spec) = {
        let entry = entry.lock();
        (
            entry.mounts.clone(),
            entry.ports.clone(),
            entry.resources.clone(),
        )
    };

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
