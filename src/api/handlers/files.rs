//! File I/O handlers — upload and download files to/from a running machine.

use axum::{
    body::Bytes,
    extract::{Path, State},
    Json,
};
use serde::Serialize;
use std::sync::Arc;
use utoipa::ToSchema;

use crate::api::error::{classify_ensure_running_error, ApiError};
use crate::api::state::{ensure_running_and_persist, with_machine_client_traced, ApiState};
use crate::api::TraceId;

/// Response from file upload.
#[derive(Debug, Serialize, ToSchema)]
pub struct FileUploadResponse {
    /// Path where the file was written.
    pub path: String,
    /// Size of the file in bytes.
    pub size: u64,
}

/// Upload a file to a machine.
///
/// Writes the request body as a file at the specified path inside the VM.
/// Creates parent directories automatically.
#[utoipa::path(
    put,
    path = "/api/v1/machines/{id}/files/{path}",
    tag = "Files",
    params(
        ("id" = String, Path, description = "Machine name"),
        ("path" = String, Path, description = "File path inside the VM (e.g., workspace/script.py)")
    ),
    request_body(content = Vec<u8>, content_type = "application/octet-stream"),
    responses(
        (status = 200, description = "File uploaded", body = FileUploadResponse),
        (status = 404, description = "Machine not found"),
        (status = 500, description = "Write failed")
    )
)]
pub async fn upload_file(
    State(state): State<Arc<ApiState>>,
    Path((id, file_path)): Path<(String, String)>,
    trace_id: Option<axum::Extension<TraceId>>,
    body: Bytes,
) -> Result<Json<FileUploadResponse>, ApiError> {
    let tid = trace_id.map(|t| t.0 .0.clone());
    let entry = state.get_machine(&id)?;
    ensure_running_and_persist(&state, &id, &entry)
        .await
        .map_err(classify_ensure_running_error)?;

    let machine_image = state.lookup_vm(&id).await?.and_then(|r| r.image);

    let file_path = file_path.trim_start_matches('/');
    let guest_path = format!("/{}", file_path);
    let size = body.len() as u64;

    let overlay_id = id.clone();
    with_machine_client_traced(&entry, tid, move |c| {
        // For image machines, mount the per-machine persistent container overlay
        // (same id exec uses) so the file lands INSIDE the container, not the
        // read-only agent base. Pull the image first if it isn't present yet.
        if let Some(ref image) = machine_image {
            if c.query(image)?.is_none() {
                c.pull_with_registry_config(image)?;
            }
            // Activate the per-machine container overlay so the file op targets
            // the image container, not the read-only agent base. `prepare_overlay`
            // mounts but doesn't make it the active fs for write_file/read_file;
            // a no-op container run (same path exec takes) does.
            c.run_non_interactive(
                crate::agent::RunConfig::new(image.clone(), vec!["/bin/true".to_string()])
                    .with_persistent_overlay(Some(overlay_id.clone())),
            )?;
        }
        c.write_file(&guest_path, &body, None)
    })
    .await?;

    Ok(Json(FileUploadResponse {
        path: format!("/{}", file_path),
        size,
    }))
}

/// Download a file from a machine.
///
/// Returns the file contents as a raw byte stream.
#[utoipa::path(
    get,
    path = "/api/v1/machines/{id}/files/{path}",
    tag = "Files",
    params(
        ("id" = String, Path, description = "Machine name"),
        ("path" = String, Path, description = "File path inside the VM")
    ),
    responses(
        (status = 200, description = "File contents", content_type = "application/octet-stream"),
        (status = 404, description = "Machine or file not found"),
        (status = 500, description = "Read failed")
    )
)]
pub async fn download_file(
    State(state): State<Arc<ApiState>>,
    Path((id, file_path)): Path<(String, String)>,
    trace_id: Option<axum::Extension<TraceId>>,
) -> Result<Bytes, ApiError> {
    let tid = trace_id.map(|t| t.0 .0.clone());
    let entry = state.get_machine(&id)?;
    ensure_running_and_persist(&state, &id, &entry)
        .await
        .map_err(classify_ensure_running_error)?;

    let machine_image = state.lookup_vm(&id).await?.and_then(|r| r.image);

    let file_path = file_path.trim_start_matches('/');
    let guest_path = format!("/{}", file_path);

    let overlay_id = id.clone();
    let data = with_machine_client_traced(&entry, tid, move |c| {
        // Read from inside the container overlay for image machines (matching
        // upload + exec), not the agent base.
        if let Some(ref image) = machine_image {
            if c.query(image)?.is_none() {
                c.pull_with_registry_config(image)?;
            }
            // Activate the per-machine container overlay so the file op targets
            // the image container, not the read-only agent base. `prepare_overlay`
            // mounts but doesn't make it the active fs for write_file/read_file;
            // a no-op container run (same path exec takes) does.
            c.run_non_interactive(
                crate::agent::RunConfig::new(image.clone(), vec!["/bin/true".to_string()])
                    .with_persistent_overlay(Some(overlay_id.clone())),
            )?;
        }
        c.read_file(&guest_path)
    })
    .await?;

    Ok(Bytes::from(data))
}
