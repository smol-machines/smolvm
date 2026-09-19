//! File I/O handlers — upload and download files to/from a running machine.

use axum::http::header::CONTENT_TYPE;
use axum::response::IntoResponse;
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

/// Download a file, or list a directory, from a machine.
///
/// A file returns its contents as a raw byte stream. A directory returns its
/// entries as JSON, so a caller exploring a tree does not have to know in
/// advance which paths are files, and does not have to guess names and eat a
/// 404 for each miss.
#[utoipa::path(
    get,
    path = "/api/v1/machines/{id}/files/{path}",
    tag = "Files",
    params(
        ("id" = String, Path, description = "Machine name"),
        ("path" = String, Path, description = "File or directory path inside the VM")
    ),
    responses(
        (status = 200, description = "File contents (application/octet-stream) or, for a directory, an `entries` array of name/kind/size (application/json)"),
        (status = 404, description = "Machine or path not found"),
        (status = 500, description = "Read failed")
    )
)]
pub async fn download_file(
    State(state): State<Arc<ApiState>>,
    Path((id, file_path)): Path<(String, String)>,
    trace_id: Option<axum::Extension<TraceId>>,
) -> Result<axum::response::Response, ApiError> {
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
        // Asking for a directory returns its listing rather than an error: a
        // caller exploring a tree should not have to know in advance which
        // paths are files, and guessing names costs a request per miss.
        match c.read_file(&guest_path) {
            Ok(bytes) => Ok(FilePayload::File(bytes)),
            Err(e) if is_directory_error(&e.to_string()) => {
                let entries = c.list_directory(&guest_path)?;
                Ok(FilePayload::Directory(entries))
            }
            Err(e) => Err(e),
        }
    })
    .await?;

    match data {
        FilePayload::File(bytes) => Ok((
            [(CONTENT_TYPE, "application/octet-stream")],
            Bytes::from(bytes),
        )
            .into_response()),
        FilePayload::Directory(entries) => {
            let body = serde_json::to_vec(&serde_json::json!({ "entries": entries }))
                .map_err(|e| ApiError::internal(format!("serialize directory listing: {e}")))?;
            Ok(([(CONTENT_TYPE, "application/json")], Bytes::from(body)).into_response())
        }
    }
}

/// What a path turned out to be: file bytes, or the entries of a directory.
enum FilePayload {
    File(Vec<u8>),
    Directory(Vec<smolvm_protocol::DirectoryEntry>),
}

/// Whether a guest read failed because the path is a directory.
///
/// The agent refuses a non-regular file before it starts streaming and names a
/// directory specifically, so match that. `os error 21` (EISDIR) covers a
/// kernel message that reached the caller untranslated. Deliberately NOT
/// matching the agent's generic "not a regular file", which also covers
/// sockets, fifos and devices: retrying those as a listing would replace one
/// confusing error with another.
fn is_directory_error(message: &str) -> bool {
    let lowered = message.to_ascii_lowercase();
    lowered.contains("is a directory") || lowered.contains("os error 21")
}

#[cfg(test)]
mod directory_listing_tests {
    use super::*;

    /// The guest read fails with the OS message, so the fallback keys on that.
    /// Getting this wrong turns a directory request back into a hard error.
    #[test]
    fn a_directory_read_is_recognised_from_the_os_message() {
        assert!(is_directory_error("read file /workspace: Is a directory"));
        assert!(is_directory_error(
            "failed to read /root/workspace/skills: is a directory: /root/workspace/skills"
        ));
        assert!(is_directory_error("agent: os error 21"));
    }

    /// A missing path must stay a 404 rather than being retried as a listing,
    /// and an unrelated failure must not be swallowed either.
    #[test]
    fn other_failures_are_not_mistaken_for_a_directory() {
        assert!(!is_directory_error("No such file or directory"));
        assert!(!is_directory_error("os error 2"));
        assert!(!is_directory_error("permission denied"));
        assert!(!is_directory_error("connection reset"));
        assert!(
            !is_directory_error("not a regular file: /run/docker.sock"),
            "a socket must not be retried as a listing"
        );
    }
}
