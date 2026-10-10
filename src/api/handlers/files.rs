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

/// The machine's image and the persistent overlay its container runs on.
///
/// A fork clone's inherited overlay lives under its golden's id, which is how
/// exec resolves it (`RunConfig::in_machine`). Keying file ops by the clone's
/// own name mounted a fresh, empty overlay the running workload never sees, so
/// uploads to a fork silently vanished and downloads missed the fork's files.
async fn image_and_overlay_owner(
    state: &ApiState,
    id: &str,
) -> Result<(Option<String>, String), ApiError> {
    let record = state.lookup_vm(id).await?;
    let overlay_owner = match &record {
        Some(record) => crate::workload::persistent_overlay_owner_with_lineage(
            id,
            record.golden.as_deref(),
            record.fork_overlay_owner.as_deref(),
        ),
        None => id.to_string(),
    };
    Ok((record.and_then(|record| record.image), overlay_owner))
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
    headers: axum::http::HeaderMap,
    body: axum::body::Body,
) -> Result<Json<FileUploadResponse>, ApiError> {
    let tid = trace_id.map(|t| t.0 .0.clone());
    let limit = crate::api::MAX_FILE_UPLOAD_BYTES as u64;
    let too_large =
        || ApiError::PayloadTooLarge(format!("file exceeds the {} MiB upload limit", limit >> 20));
    let declared = headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|len| len > limit) {
        return Err(too_large());
    }
    let entry = state.get_machine(&id)?;
    ensure_running_and_persist(&state, &id, &entry)
        .await
        .map_err(classify_ensure_running_error)?;

    let (machine_image, overlay_id) = image_and_overlay_owner(&state, &id).await?;

    let file_path = file_path.trim_start_matches('/');
    let guest_path = format!("/{}", file_path);

    // A large body of known size is written into the guest as it arrives,
    // so the upload costs one pass over the network, not that plus a second
    // pass from memory once it has all arrived. Anything else is read whole.
    let source = match declared {
        Some(len) if len > smolvm_protocol::FILE_WRITE_SINGLE_SHOT_MAX as u64 => {
            UploadSource::Streamed(len, BodyReader::spawn(body, len))
        }
        _ => UploadSource::Whole(axum::body::to_bytes(body, limit as usize).await.map_err(
            |e| {
                if e.to_string().contains("length limit") {
                    too_large()
                } else {
                    ApiError::BadRequest(format!("upload body did not arrive in full: {e}"))
                }
            },
        )?),
    };
    let size = match &source {
        UploadSource::Streamed(len, _) => *len,
        UploadSource::Whole(bytes) => bytes.len() as u64,
    };

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
        match source {
            // The agent stages a streamed file and renames it into place only
            // once all of it is written, so a body that stops short leaves
            // nothing at the path.
            UploadSource::Streamed(len, reader) => {
                c.write_file_from_reader(&guest_path, reader, len, None)
            }
            UploadSource::Whole(bytes) => c.write_file(&guest_path, &bytes, None),
        }
    })
    .await?;

    Ok(Json(FileUploadResponse {
        path: format!("/{}", file_path),
        size,
    }))
}

enum UploadSource {
    Streamed(u64, BodyReader),
    Whole(Bytes),
}

/// A request body read synchronously, as the agent client reads its source,
/// while a task feeds it the chunks as they arrive.
struct BodyReader {
    chunks: tokio::sync::mpsc::Receiver<std::io::Result<Bytes>>,
    current: Bytes,
    /// Bytes still owed by the declared length.
    remaining: u64,
}

impl BodyReader {
    fn spawn(body: axum::body::Body, len: u64) -> Self {
        use futures_util::StreamExt;
        // A few chunks of slack keep the network and the guest writes
        // overlapping without holding the body in memory.
        let (tx, chunks) = tokio::sync::mpsc::channel(8);
        tokio::spawn(async move {
            let mut stream = body.into_data_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|e| std::io::Error::other(e.to_string()));
                let failed = chunk.is_err();
                if tx.send(chunk).await.is_err() || failed {
                    return;
                }
            }
        });
        Self {
            chunks,
            current: Bytes::new(),
            remaining: len,
        }
    }
}

impl std::io::Read for BodyReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() || self.remaining == 0 {
            return Ok(0);
        }
        while self.current.is_empty() {
            match self.chunks.blocking_recv() {
                Some(chunk) => self.current = chunk?,
                None if self.remaining == 0 => return Ok(0),
                // A body that ends before its declared length must fail the
                // write, never finish a short file.
                None => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        format!("upload ended {} bytes short", self.remaining),
                    ))
                }
            }
        }
        let n = buf
            .len()
            .min(self.current.len())
            .min(self.remaining as usize);
        self.remaining -= n as u64;
        buf[..n].copy_from_slice(&self.current[..n]);
        self.current = self.current.slice(n..);
        Ok(n)
    }
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

    let (machine_image, overlay_id) = image_and_overlay_owner(&state, &id).await?;

    let file_path = file_path.trim_start_matches('/');
    let guest_path = format!("/{}", file_path);

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

#[cfg(test)]
mod body_reader_tests {
    use super::BodyReader;
    use std::io::Read;

    fn body(chunks: Vec<Result<&'static [u8], std::io::Error>>) -> axum::body::Body {
        axum::body::Body::from_stream(futures_util::stream::iter(chunks))
    }

    /// A body that delivers its declared length reads back whole.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_whole_body_reads_back_in_full() {
        let reader = BodyReader::spawn(body(vec![Ok(b"hello "), Ok(b"world")]), 11);
        let out = tokio::task::spawn_blocking(move || {
            let mut out = Vec::new();
            let mut reader = reader;
            reader.read_to_end(&mut out).map(|_| out)
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(out, b"hello world");
    }

    /// A producer's final chunk can be larger than the declared remainder.
    /// A synchronous reader must never hand more than the advertised bytes
    /// to the guest, even when an upstream body is malformed.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_body_reader_stops_at_the_declared_size() {
        let reader = BodyReader::spawn(body(vec![Ok(b"hello world")]), 5);
        let out = tokio::task::spawn_blocking(move || {
            let mut reader = reader;
            let mut out = Vec::new();
            reader.read_to_end(&mut out).map(|_| out)
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(out, b"hello");
    }

    /// A body that stops before its declared length is an error, so the
    /// write fails instead of finishing a short file.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_body_that_ends_short_is_an_error() {
        let reader = BodyReader::spawn(body(vec![Ok(b"hello")]), 11);
        let error = tokio::task::spawn_blocking(move || {
            let mut out = Vec::new();
            let mut reader = reader;
            reader.read_to_end(&mut out)
        })
        .await
        .unwrap()
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    /// A body the client breaks off is an error too.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_broken_body_is_an_error() {
        let reader = BodyReader::spawn(
            body(vec![
                Ok(b"hello"),
                Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "gone",
                )),
            ]),
            11,
        );
        let result = tokio::task::spawn_blocking(move || {
            let mut out = Vec::new();
            let mut reader = reader;
            reader.read_to_end(&mut out)
        })
        .await
        .unwrap();
        assert!(result.is_err());
    }
}
