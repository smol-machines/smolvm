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
use crate::api::state::{ensure_running_and_persist, with_machine_client, ApiState};

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
    body: Bytes,
) -> Result<Json<FileUploadResponse>, ApiError> {
    let entry = state.get_machine(&id)?;
    ensure_running_and_persist(&state, &id, &entry)
        .await
        .map_err(classify_ensure_running_error)?;

    let guest_path = format!("/{}", file_path);
    let size = body.len() as u64;

    with_machine_client(&entry, move |c| c.write_file(&guest_path, &body, None)).await?;

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
) -> Result<Bytes, ApiError> {
    let entry = state.get_machine(&id)?;
    ensure_running_and_persist(&state, &id, &entry)
        .await
        .map_err(classify_ensure_running_error)?;

    let guest_path = format!("/{}", file_path);

    let data = with_machine_client(&entry, move |c| c.read_file(&guest_path)).await?;

    Ok(Bytes::from(data))
}
