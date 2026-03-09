//! Container management handlers.

use axum::{
    extract::{Path, State},
    Json,
};
use std::sync::Arc;
use std::time::Duration;

use crate::api::error::{classify_ensure_running_error, ApiError};
use crate::api::state::{ensure_running_and_persist, with_sandbox_client, ApiState};
use crate::api::types::{
    ApiErrorResponse, ContainerExecRequest, ContainerInfo, CreateContainerRequest,
    DeleteContainerRequest, DeleteResponse, EnvVar, ExecResponse, ListContainersResponse,
    StartResponse, StopContainerRequest, StopResponse,
};
use crate::api::validation::validate_command;
use crate::DEFAULT_IDLE_CMD;

/// Create a container in a sandbox.
#[utoipa::path(
    post,
    path = "/api/v1/sandboxes/{id}/containers",
    tag = "Containers",
    params(
        ("id" = String, Path, description = "Sandbox name")
    ),
    request_body = CreateContainerRequest,
    responses(
        (status = 200, description = "Container created", body = ContainerInfo),
        (status = 404, description = "Sandbox not found", body = ApiErrorResponse),
        (status = 500, description = "Failed to create container", body = ApiErrorResponse)
    )
)]
pub async fn create_container(
    State(state): State<Arc<ApiState>>,
    Path(sandbox_id): Path<String>,
    Json(req): Json<CreateContainerRequest>,
) -> Result<Json<ContainerInfo>, ApiError> {
    let entry = state.get_sandbox(&sandbox_id)?;

    // Ensure sandbox is running and persist state to DB
    ensure_running_and_persist(&state, &sandbox_id, &entry)
        .await
        .map_err(classify_ensure_running_error)?;

    // Prepare parameters
    let image = req.image.clone();
    let command = if req.command.is_empty() {
        DEFAULT_IDLE_CMD.iter().map(|s| s.to_string()).collect()
    } else {
        req.command.clone()
    };
    let env = EnvVar::to_tuples(&req.env);
    let workdir = req.workdir.clone();
    let mounts: Vec<(String, String, bool)> = req
        .mounts
        .iter()
        .map(|m| (m.source.clone(), m.target.clone(), m.readonly))
        .collect();

    let container_info = with_sandbox_client(&entry, move |c| {
        c.create_container(&image, command, env, workdir, mounts)
    })
    .await?;

    Ok(Json(ContainerInfo {
        id: container_info.id,
        image: container_info.image,
        state: container_info.state,
        created_at: container_info.created_at,
        command: container_info.command,
    }))
}

/// List containers in a sandbox.
#[utoipa::path(
    get,
    path = "/api/v1/sandboxes/{id}/containers",
    tag = "Containers",
    params(
        ("id" = String, Path, description = "Sandbox name")
    ),
    responses(
        (status = 200, description = "List of containers", body = ListContainersResponse),
        (status = 404, description = "Sandbox not found", body = ApiErrorResponse)
    )
)]
pub async fn list_containers(
    State(state): State<Arc<ApiState>>,
    Path(sandbox_id): Path<String>,
) -> Result<Json<ListContainersResponse>, ApiError> {
    let entry = state.get_sandbox(&sandbox_id)?;

    // Check if sandbox VM is actually alive, return empty list if not
    {
        let entry = entry.lock();
        if !entry.manager.is_process_alive() {
            return Ok(Json(ListContainersResponse {
                containers: Vec::new(),
            }));
        }
    }

    let containers = with_sandbox_client(&entry, |c| c.list_containers()).await?;

    let containers = containers
        .into_iter()
        .map(|c| ContainerInfo {
            id: c.id,
            image: c.image,
            state: c.state,
            created_at: c.created_at,
            command: c.command,
        })
        .collect();

    Ok(Json(ListContainersResponse { containers }))
}

/// Start a container.
#[utoipa::path(
    post,
    path = "/api/v1/sandboxes/{id}/containers/{cid}/start",
    tag = "Containers",
    params(
        ("id" = String, Path, description = "Sandbox name"),
        ("cid" = String, Path, description = "Container ID")
    ),
    responses(
        (status = 200, description = "Container started", body = StartResponse),
        (status = 404, description = "Sandbox or container not found", body = ApiErrorResponse),
        (status = 500, description = "Failed to start container", body = ApiErrorResponse)
    )
)]
pub async fn start_container(
    State(state): State<Arc<ApiState>>,
    Path((sandbox_id, container_id)): Path<(String, String)>,
) -> Result<Json<StartResponse>, ApiError> {
    let entry = state.get_sandbox(&sandbox_id)?;

    let container_id_response = container_id.clone();
    with_sandbox_client(&entry, move |c| c.start_container(&container_id)).await?;
    Ok(Json(StartResponse {
        started: container_id_response,
    }))
}

/// Stop a container.
#[utoipa::path(
    post,
    path = "/api/v1/sandboxes/{id}/containers/{cid}/stop",
    tag = "Containers",
    params(
        ("id" = String, Path, description = "Sandbox name"),
        ("cid" = String, Path, description = "Container ID")
    ),
    request_body = StopContainerRequest,
    responses(
        (status = 200, description = "Container stopped", body = StopResponse),
        (status = 404, description = "Sandbox or container not found", body = ApiErrorResponse),
        (status = 500, description = "Failed to stop container", body = ApiErrorResponse)
    )
)]
pub async fn stop_container(
    State(state): State<Arc<ApiState>>,
    Path((sandbox_id, container_id)): Path<(String, String)>,
    Json(req): Json<StopContainerRequest>,
) -> Result<Json<StopResponse>, ApiError> {
    let entry = state.get_sandbox(&sandbox_id)?;

    let timeout_secs = req.timeout_secs;

    let container_id_response = container_id.clone();
    with_sandbox_client(&entry, move |c| {
        c.stop_container(&container_id, timeout_secs)
    })
    .await?;
    Ok(Json(StopResponse {
        stopped: container_id_response,
    }))
}

/// Delete a container.
#[utoipa::path(
    delete,
    path = "/api/v1/sandboxes/{id}/containers/{cid}",
    tag = "Containers",
    params(
        ("id" = String, Path, description = "Sandbox name"),
        ("cid" = String, Path, description = "Container ID")
    ),
    request_body = DeleteContainerRequest,
    responses(
        (status = 200, description = "Container deleted", body = DeleteResponse),
        (status = 404, description = "Sandbox or container not found", body = ApiErrorResponse),
        (status = 500, description = "Failed to delete container", body = ApiErrorResponse)
    )
)]
pub async fn delete_container(
    State(state): State<Arc<ApiState>>,
    Path((sandbox_id, container_id)): Path<(String, String)>,
    Json(req): Json<DeleteContainerRequest>,
) -> Result<Json<DeleteResponse>, ApiError> {
    let entry = state.get_sandbox(&sandbox_id)?;

    let force = req.force;

    let container_id_response = container_id.clone();
    with_sandbox_client(&entry, move |c| c.delete_container(&container_id, force)).await?;
    Ok(Json(DeleteResponse {
        deleted: container_id_response,
    }))
}

/// Execute a command in a container.
#[utoipa::path(
    post,
    path = "/api/v1/sandboxes/{id}/containers/{cid}/exec",
    tag = "Containers",
    params(
        ("id" = String, Path, description = "Sandbox name"),
        ("cid" = String, Path, description = "Container ID")
    ),
    request_body = ContainerExecRequest,
    responses(
        (status = 200, description = "Command executed", body = ExecResponse),
        (status = 400, description = "Invalid request", body = ApiErrorResponse),
        (status = 404, description = "Sandbox or container not found", body = ApiErrorResponse),
        (status = 500, description = "Execution failed", body = ApiErrorResponse)
    )
)]
pub async fn exec_in_container(
    State(state): State<Arc<ApiState>>,
    Path((sandbox_id, container_id)): Path<(String, String)>,
    Json(req): Json<ContainerExecRequest>,
) -> Result<Json<ExecResponse>, ApiError> {
    validate_command(&req.command)?;

    let entry = state.get_sandbox(&sandbox_id)?;

    // Prepare parameters
    let command = req.command.clone();
    let env = EnvVar::to_tuples(&req.env);
    let workdir = req.workdir.clone();
    let timeout = req.timeout_secs.map(Duration::from_secs);

    let (exit_code, stdout, stderr) = with_sandbox_client(&entry, move |c| {
        c.exec(&container_id, command, env, workdir, timeout)
    })
    .await?;

    Ok(Json(ExecResponse {
        exit_code,
        stdout,
        stderr,
    }))
}
