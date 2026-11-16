//! Directory metadata without an exec, shell, or recursive archive download.

use std::collections::HashSet;
use std::path::Path as HostPath;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use smolvm_protocol::{AgentRequest, AgentResponse, DirectoryEntry};

use super::util::{ApiError, ApiResult};
use super::Engine;

const MAX_LISTING: usize = 8 << 20;

/// Metadata for one container directory; file contents are never included.
#[derive(Debug, Serialize, Deserialize)]
pub struct Directory {
    /// Canonical container ID, even when the request used a name.
    pub id: String,
    /// Absolute guest path requested by the caller.
    pub path: String,
    /// Immediate children only. Links are reported without following them.
    pub entries: Vec<DirectoryEntry>,
}

#[derive(Deserialize)]
pub(super) struct ListQuery {
    path: String,
}

fn validate_path(path: &str) -> Result<(), String> {
    if !path.starts_with('/') || path.contains('\0') {
        return Err("Enter an absolute container path without NUL characters.".into());
    }
    Ok(())
}

fn validate_entries(entries: &[DirectoryEntry]) -> Result<(), String> {
    let mut names = HashSet::new();
    for entry in entries {
        if entry.name.is_empty()
            || matches!(entry.name.as_str(), "." | "..")
            || entry.name.contains(['/', '\0'])
            || !names.insert(&entry.name)
        {
            return Err("The agent returned an invalid directory entry.".into());
        }
    }
    Ok(())
}

fn entries(reply: AgentResponse) -> ApiResult<Vec<DirectoryEntry>> {
    match reply {
        AgentResponse::Ok { data: Some(data) } => {
            let entries: Vec<DirectoryEntry> = serde_json::from_value(data["entries"].clone())
                .map_err(|e| ApiError::internal(format!("read directory metadata: {e}")))?;
            validate_entries(&entries).map_err(ApiError::internal)?;
            Ok(entries)
        }
        AgentResponse::Error { message, code } => Err(if code.as_deref() == Some("NOT_FOUND") {
            ApiError::not_found(message)
        } else {
            ApiError::internal(message)
        }),
        _ => Err(ApiError::internal(
            "The agent returned no directory metadata.",
        )),
    }
}

/// Smol extension to the Docker API. Uses the same namespace and temporary
/// machine lifetime as `docker cp`, including for stopped containers.
pub(super) async fn list(
    State(engine): State<Arc<Engine>>,
    Path(id): Path<String>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<Directory>> {
    validate_path(&q.path).map_err(ApiError::bad_request)?;
    let c = engine
        .find_container(&id)
        .ok_or_else(|| ApiError::no_such_container(&id))?;
    if matches!(c.record().state.status.as_str(), "removing" | "dead") {
        return Err(ApiError::conflict(
            "This container's filesystem is unavailable.",
        ));
    }
    let machine = super::archive::files_machine(&engine, &c).await?;
    let reply = tokio::time::timeout(
        Duration::from_secs(30),
        super::runtime::request(
            &machine.socket,
            &AgentRequest::ListDirectory {
                path: q.path.clone(),
                target: Some(super::archive::target(&c)),
            },
        ),
    )
    .await;
    machine.finish().await;
    let reply = reply
        .map_err(|_| ApiError::internal("Directory listing timed out."))?
        .map_err(|e| ApiError::internal(format!("list directory: {e}")))?;
    let listing = Directory {
        id: c.id(),
        path: q.path,
        entries: entries(reply)?,
    };
    let size = serde_json::to_vec(&listing)
        .map_err(|e| ApiError::internal(e.to_string()))?
        .len();
    if size > MAX_LISTING {
        return Err(ApiError::internal(
            "Directory metadata exceeds 8 MiB; choose a smaller directory.",
        ));
    }
    Ok(Json(listing))
}

/// List immediate children through an explicitly selected Smol Docker socket.
/// Does not consult Docker environment variables or start the container command.
pub async fn list_directory(
    socket: &HostPath,
    container: &str,
    path: &str,
) -> crate::Result<Directory> {
    let error = |message: String| crate::Error::agent("list container files", message);
    validate_path(path).map_err(|message| crate::Error::config("list container files", message))?;
    if !super::util::valid_container_name(container) {
        return Err(crate::Error::config(
            "list container files",
            "Enter a container name or ID.",
        ));
    }
    let client = reqwest::Client::builder()
        .unix_socket(socket)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|e| error(e.to_string()))?;
    let mut url = reqwest::Url::parse("http://localhost/containers/").expect("static URL");
    url.path_segments_mut()
        .expect("HTTP URL")
        .pop_if_empty()
        .extend([container, "smol", "files"]);
    url.query_pairs_mut().append_pair("path", path);
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|e| error(format!("Cannot read the Smol container filesystem: {e}")))?;
    let status = response.status();
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| error(e.to_string()))? {
        if bytes.len().saturating_add(chunk.len()) > MAX_LISTING {
            return Err(error("Directory metadata exceeds 8 MiB.".into()));
        }
        bytes.extend_from_slice(&chunk);
    }
    if !status.is_success() {
        let message = serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|v| v["message"].as_str().map(str::to_owned))
            .unwrap_or_else(|| format!("The engine returned HTTP {status}."));
        return Err(match status.as_u16() {
            404 => crate::Error::agent_not_found("list container files", message),
            409 => crate::Error::agent_conflict("list container files", message),
            403 => crate::Error::agent_forbidden("list container files", message),
            400 => crate::Error::config("list container files", message),
            _ => error(message),
        });
    }
    let listing: Directory = serde_json::from_slice(&bytes)
        .map_err(|e| error(format!("Invalid directory response: {e}")))?;
    let canonical = listing.id.len() == 64 && listing.id.bytes().all(|b| b.is_ascii_hexdigit());
    let exact_id = container.len() == 64 && container.bytes().all(|b| b.is_ascii_hexdigit());
    if !canonical || listing.path != path || (exact_id && listing.id != container) {
        return Err(error(
            "The engine returned a different container or directory.".into(),
        ));
    }
    validate_entries(&listing.entries).map_err(error)?;
    Ok(listing)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn serve_one(
        body: Vec<u8>,
        status: &str,
    ) -> (
        tempfile::TempDir,
        std::path::PathBuf,
        tokio::task::JoinHandle<String>,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("files.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let header = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let task = tokio::spawn(async move {
            let (mut stream, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
                .await
                .unwrap()
                .unwrap();
            let mut request = Vec::new();
            loop {
                let byte = stream.read_u8().await.unwrap();
                request.push(byte);
                assert!(request.len() < 8192);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            stream.write_all(header.as_bytes()).await.unwrap();
            let _ = stream.write_all(&body).await;
            String::from_utf8(request).unwrap()
        });
        (dir, socket, task)
    }

    #[tokio::test]
    async fn client_encodes_literal_paths_and_checks_response_identity() {
        let id = "a".repeat(64);
        let path = "/a &?#+%/\n雪";
        let body =
            serde_json::to_vec(&serde_json::json!({"id":id,"path":path,"entries":[]})).unwrap();
        let (_dir, socket, server) = serve_one(body, "200 OK").await;
        let listing = list_directory(&socket, &id, path).await.unwrap();
        assert_eq!(listing.path, path);
        let request = server.await.unwrap();
        let target = request
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap();
        let url = reqwest::Url::parse(&format!("http://localhost{target}")).unwrap();
        assert_eq!(url.path(), format!("/containers/{id}/smol/files"));
        assert_eq!(
            url.query_pairs().collect::<Vec<_>>(),
            [("path".into(), path.into())]
        );
        for (returned_id, returned_path) in [("b".repeat(64), path), (id.clone(), "/other")] {
            let body = serde_json::to_vec(
                &serde_json::json!({"id":returned_id,"path":returned_path,"entries":[]}),
            )
            .unwrap();
            let (_dir, socket, server) = serve_one(body, "200 OK").await;
            assert!(list_directory(&socket, &id, path)
                .await
                .unwrap_err()
                .to_string()
                .contains("different container or directory"));
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn client_bounds_metadata_and_preserves_engine_errors() {
        let id = "a".repeat(64);
        let (_dir, socket, server) = serve_one(vec![b' '; MAX_LISTING + 1], "200 OK").await;
        assert!(list_directory(&socket, &id, "/")
            .await
            .unwrap_err()
            .to_string()
            .contains("exceeds 8 MiB"));
        server.await.unwrap();
        let (_dir, socket, server) = serve_one(
            br#"{"message":"folder is missing"}"#.to_vec(),
            "404 Not Found",
        )
        .await;
        let error = list_directory(&socket, &id, "/").await.unwrap_err();
        assert_eq!(error.code(), "NOT_FOUND");
        assert!(error.to_string().contains("folder is missing"));
        server.await.unwrap();
    }

    #[test]
    fn metadata_does_not_interpret_names_or_accept_invalid_children() {
        let reply = |name: &str| AgentResponse::Ok {
            data: Some(serde_json::json!({"entries":[{"name":name,"kind":"symlink","size":0}]})),
        };
        let name = "a ; $(true)\n.txt";
        assert_eq!(entries(reply(name)).unwrap()[0].name, name);
        for name in ["", ".", "..", "a/b", "nul\0"] {
            assert!(entries(reply(name)).is_err());
        }
        assert!(entries(AgentResponse::Ok {
            data: Some(serde_json::json!({}))
        })
        .is_err());
        assert_eq!(
            entries(AgentResponse::Error {
                message: "missing".into(),
                code: Some("NOT_FOUND".into())
            })
            .unwrap_err()
            .status,
            axum::http::StatusCode::NOT_FOUND
        );
    }
}
