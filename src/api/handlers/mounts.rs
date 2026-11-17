//! Attached mounts: host directories mounted into a running machine until it
//! stops (see [`crate::attach`]).

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;
use utoipa::IntoParams;

use crate::api::error::ApiError;
use crate::api::state::ApiState;
use crate::api::types::{ApiErrorResponse, MountSpec};
use crate::config::{RecordState, VmRecord};
use crate::data::storage::HostMount;

/// Which attached mount to remove.
#[derive(Debug, Deserialize, IntoParams)]
pub struct DetachMountQuery {
    /// Guest path the directory is mounted at.
    pub target: String,
}

fn spec(mount: crate::attach::AttachedMount) -> MountSpec {
    MountSpec {
        source: mount.source,
        target: mount.target,
        readonly: mount.read_only,
        staged: false,
    }
}

fn attach_error(e: crate::Error) -> ApiError {
    match e {
        crate::Error::Config { .. } => ApiError::BadRequest(e.to_string()),
        other => ApiError::from(other),
    }
}

async fn record(state: &ApiState, name: &str) -> Result<VmRecord, ApiError> {
    state
        .lookup_vm(name)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("machine '{name}' not found")))
}

fn require_running(record: &VmRecord, name: &str) -> Result<(), ApiError> {
    if record.actual_state() == RecordState::Running {
        Ok(())
    } else {
        Err(ApiError::Conflict(format!(
            "machine '{name}' is not running; set mounts on a stopped machine with update"
        )))
    }
}

/// List the host directories mounted into a running machine since it started.
#[utoipa::path(
    get,
    path = "/api/v1/machines/{name}/mounts",
    tag = "Machines",
    params(("name" = String, Path, description = "Machine name")),
    responses(
        (status = 200, description = "Directories mounted while the machine runs; none when it is stopped", body = Vec<MountSpec>),
        (status = 404, description = "Machine not found", body = ApiErrorResponse)
    )
)]
pub async fn list_mounts(
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
) -> Result<Json<Vec<MountSpec>>, ApiError> {
    if record(&state, &name).await?.actual_state() != RecordState::Running {
        return Ok(Json(Vec::new()));
    }
    let mounts = tokio::task::spawn_blocking(move || crate::attach::list(&name))
        .await
        .map_err(|e| ApiError::internal(format!("list mounts task failed: {e}")))?
        .map_err(attach_error)?;
    Ok(Json(mounts.into_iter().map(spec).collect()))
}

/// Mount a host directory into a running machine without restarting it. The
/// mount lasts until the machine stops; set it with update to keep it.
#[utoipa::path(
    post,
    path = "/api/v1/machines/{name}/mounts",
    tag = "Machines",
    params(("name" = String, Path, description = "Machine name")),
    request_body = MountSpec,
    responses(
        (status = 200, description = "Mounted", body = MountSpec),
        (status = 400, description = "Invalid mount, or one already at that path", body = ApiErrorResponse),
        (status = 404, description = "Machine not found", body = ApiErrorResponse),
        (status = 409, description = "Machine is not running", body = ApiErrorResponse)
    )
)]
pub async fn attach_mount(
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
    Json(req): Json<MountSpec>,
) -> Result<Json<MountSpec>, ApiError> {
    if req.staged {
        return Err(ApiError::BadRequest(
            "a staged mount is copied in at boot and cannot be attached to a running machine"
                .to_string(),
        ));
    }
    // The same validation a create's mounts get.
    let mount = HostMount::try_from(&req).map_err(|e| ApiError::BadRequest(e.to_string()))?;
    // Under the lifecycle lock, so a stop cannot land between the check and
    // the attach.
    let guard = state.lifecycle_lock(&name).lock_owned().await;
    let record = record(&state, &name).await?;
    require_running(&record, &name)?;
    let boot_targets: Vec<String> = record.mounts.iter().map(|m| m.1.clone()).collect();
    let attached = tokio::task::spawn_blocking(move || {
        let _guard = guard;
        crate::attach::attach(
            &name,
            &mount.source,
            &mount.target,
            mount.read_only,
            &boot_targets,
        )
    })
    .await
    .map_err(|e| ApiError::internal(format!("attach mount task failed: {e}")))?
    .map_err(attach_error)?;
    Ok(Json(spec(attached)))
}

/// Unmount a directory mounted into a running machine with `POST .../mounts`.
#[utoipa::path(
    delete,
    path = "/api/v1/machines/{name}/mounts",
    tag = "Machines",
    params(("name" = String, Path, description = "Machine name"), DetachMountQuery),
    responses(
        (status = 200, description = "Unmounted", body = MountSpec),
        (status = 400, description = "Nothing attached at that path", body = ApiErrorResponse),
        (status = 404, description = "Machine not found", body = ApiErrorResponse),
        (status = 409, description = "Machine is not running", body = ApiErrorResponse)
    )
)]
pub async fn detach_mount(
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
    Query(query): Query<DetachMountQuery>,
) -> Result<Json<MountSpec>, ApiError> {
    let guard = state.lifecycle_lock(&name).lock_owned().await;
    require_running(&record(&state, &name).await?, &name)?;
    let detached = tokio::task::spawn_blocking(move || {
        let _guard = guard;
        crate::attach::detach(&name, std::path::Path::new(&query.target))
    })
    .await
    .map_err(|e| ApiError::internal(format!("detach mount task failed: {e}")))?
    .map_err(attach_error)?;
    Ok(Json(spec(detached)))
}
