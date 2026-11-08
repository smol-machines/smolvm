//! `docker cp`: tar archives in and out of a container's filesystem.
//!
//! A running container's files are reached through its agent. A container
//! that is not running gets its machine booted for the copy and stopped
//! again, except an upload before the first start, which is kept on the
//! host and unpacked as the container starts.

use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use smolvm_protocol::{AgentRequest, AgentResponse, WorkloadTarget};

use super::containers::Container;
use super::util::{ApiError, ApiResult};
use super::Engine;

type Q = Query<std::collections::HashMap<String, String>>;

/// Largest archive accepted in one upload.
const MAX_UPLOAD: usize = 4 << 30;

fn path_param(q: &std::collections::HashMap<String, String>) -> ApiResult<String> {
    let path = q
        .get("path")
        .filter(|p| !p.is_empty())
        .ok_or_else(|| ApiError::bad_request("path is required"))?;
    Ok(if path.starts_with('/') {
        path.clone()
    } else {
        format!("/{path}")
    })
}

/// A machine to talk to for the container's files: its own when it runs,
/// otherwise one booted for this copy, which [`FilesMachine::finish`] stops
/// again. A booted one holds the container's lifecycle lock, so a start
/// waits for the copy instead of racing the stop.
struct FilesMachine {
    socket: std::path::PathBuf,
    temporary: Option<(Arc<Engine>, String, tokio::sync::OwnedMutexGuard<()>)>,
}

impl FilesMachine {
    async fn finish(mut self) {
        if let Some((engine, machine, guard)) = self.temporary.take() {
            super::containers::stop_machine(&engine, &machine, Some(std::time::Duration::ZERO))
                .await;
            drop(guard);
        }
    }
}

impl Drop for FilesMachine {
    fn drop(&mut self) {
        // An error path that never reached `finish` still stops the machine.
        if let Some((engine, machine, guard)) = self.temporary.take() {
            tokio::spawn(async move {
                super::containers::stop_machine(&engine, &machine, Some(std::time::Duration::ZERO))
                    .await;
                drop(guard);
            });
        }
    }
}

async fn files_machine(engine: &Arc<Engine>, c: &Arc<Container>) -> ApiResult<FilesMachine> {
    if let Some(socket) = c.socket() {
        return Ok(FilesMachine {
            socket,
            temporary: None,
        });
    }
    let guard = c.op_lock().await;
    if let Some(socket) = c.socket() {
        return Ok(FilesMachine {
            socket,
            temporary: None,
        });
    }
    let record = c.record();
    let e = engine.clone();
    let machine = record.machine.clone();
    let pull_ref = record.pull_ref.clone();
    let socket = tokio::task::spawn_blocking(move || -> crate::Result<std::path::PathBuf> {
        let started = crate::embedded::control::start_vm(&e.db, &machine)?;
        let handle = started.handle;
        let socket = handle.agent_socket();
        let mut client = crate::agent::AgentClient::connect_with_retry(&socket)?;
        if client.query(&pull_ref)?.is_none() {
            client.pull_with_registry_config(&pull_ref)?;
        }
        handle.detach();
        Ok(socket)
    })
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?
    .map_err(|e| ApiError::internal(format!("boot the container's machine: {e}")))?;
    Ok(FilesMachine {
        socket,
        temporary: Some((engine.clone(), record.machine, guard)),
    })
}

fn target(c: &Container) -> WorkloadTarget {
    let record = c.record();
    WorkloadTarget::Container {
        image: record.pull_ref.clone(),
        overlay_id: super::containers::overlay_id(&record),
    }
}

/// What `path` is in the container: `(kind, size)`, or `None` when absent.
async fn stat(
    socket: &std::path::Path,
    target: &WorkloadTarget,
    path: &str,
) -> ApiResult<Option<(String, u64)>> {
    if path == "/" {
        return Ok(Some(("dir".into(), 0)));
    }
    let p = std::path::Path::new(path);
    let parent = p
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "/".into());
    let name = p
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let reply = super::runtime::request(
        socket,
        &AgentRequest::ListDirectory {
            path: parent,
            target: Some(target.clone()),
        },
    )
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    let entries = match reply {
        AgentResponse::Ok { data: Some(data) } => data,
        _ => return Ok(None),
    };
    let list = entries.get("entries").cloned().unwrap_or(entries.clone());
    let entries: Vec<smolvm_protocol::DirectoryEntry> =
        serde_json::from_value(list).unwrap_or_default();
    Ok(entries
        .into_iter()
        .find(|e| e.name == name)
        .map(|e| (e.kind, e.size)))
}

fn stat_header(path: &str, kind: &str, size: u64) -> HeaderValue {
    use base64::Engine as _;
    // Go's os.FileMode bits: ModeDir is 1<<31, ModeSymlink 1<<27.
    let mode: u64 = match kind {
        "dir" => (1 << 31) | 0o755,
        "symlink" => (1 << 27) | 0o777,
        _ => 0o644,
    };
    let name = std::path::Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "/".into());
    let json = serde_json::json!({
        "name": name, "size": size, "mode": mode,
        "mtime": super::util::now_rfc3339(), "linkTarget": "",
    });
    HeaderValue::from_str(&base64::engine::general_purpose::STANDARD.encode(json.to_string()))
        .unwrap_or_else(|_| HeaderValue::from_static(""))
}

fn no_such_path(path: &str) -> ApiError {
    ApiError::not_found(format!("Could not find the file {path} in container"))
}

/// `HEAD /containers/{id}/archive`.
pub(crate) async fn head_archive(
    State(engine): State<Arc<Engine>>,
    Path(id): Path<String>,
    Query(q): Q,
) -> ApiResult<Response> {
    let c = engine
        .find_container(&id)
        .ok_or_else(|| ApiError::no_such_container(&id))?;
    let path = path_param(&q)?;
    let machine = files_machine(&engine, &c).await?;
    let found = stat(&machine.socket, &target(&c), &path).await;
    machine.finish().await;
    let (kind, size) = found?.ok_or_else(|| no_such_path(&path))?;
    let mut r = StatusCode::OK.into_response();
    r.headers_mut().insert(
        "X-Docker-Container-Path-Stat",
        stat_header(&path, &kind, size),
    );
    Ok(r)
}

/// `GET /containers/{id}/archive`: a tar of the path, its own name at the top.
pub(crate) async fn get_archive(
    State(engine): State<Arc<Engine>>,
    Path(id): Path<String>,
    Query(q): Q,
) -> ApiResult<Response> {
    let c = engine
        .find_container(&id)
        .ok_or_else(|| ApiError::no_such_container(&id))?;
    let path = path_param(&q)?;
    let machine = files_machine(&engine, &c).await?;
    let target = target(&c);
    let (kind, size) = stat(&machine.socket, &target, &path)
        .await?
        .ok_or_else(|| no_such_path(&path))?;
    let name = std::path::Path::new(&path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| ".".into());
    let request = if kind == "dir" {
        AgentRequest::ArchiveDirectory {
            path: path.clone(),
            target: Some(target),
        }
    } else {
        AgentRequest::FileRead {
            path: path.clone(),
            target: Some(target),
        }
    };
    let (mut reader, mut writer) = super::runtime::connect(&machine.socket)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    writer
        .send(&request)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let mut data = Vec::new();
    loop {
        match reader
            .recv()
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?
        {
            AgentResponse::DataChunk { data: chunk, done } => {
                data.extend_from_slice(&chunk);
                if done {
                    break;
                }
            }
            AgentResponse::Error { message, .. } => {
                return Err(ApiError::internal(format!("read {path}: {message}")))
            }
            _ => {}
        }
    }
    machine.finish().await;
    let tar = tokio::task::spawn_blocking(move || {
        if kind == "dir" {
            prefix_archive(&data, &name)
        } else {
            single_file_archive(&name, &data)
        }
    })
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?
    .map_err(|e| ApiError::internal(format!("build archive: {e}")))?;
    let mut r = Response::new(Body::from(tar));
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-tar"),
    );
    r.headers_mut().insert(
        "X-Docker-Container-Path-Stat",
        stat_header(&path, "file", size),
    );
    Ok(r)
}

/// The entries of `tar` (a directory's contents) under `prefix/`.
fn prefix_archive(tar_bytes: &[u8], prefix: &str) -> std::io::Result<Vec<u8>> {
    let mut out = tar::Builder::new(Vec::new());
    let mut top = tar::Header::new_gnu();
    top.set_entry_type(tar::EntryType::Directory);
    top.set_mode(0o755);
    top.set_size(0);
    top.set_mtime(now_secs());
    out.append_data(&mut top, format!("{prefix}/"), std::io::empty())?;
    let mut archive = tar::Archive::new(tar_bytes);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_string_lossy().into_owned();
        let path = path.trim_start_matches("./");
        if path.is_empty() || path == "." {
            continue;
        }
        let mut header = entry.header().clone();
        let full = format!("{prefix}/{path}");
        match header.entry_type() {
            tar::EntryType::Symlink | tar::EntryType::Link => {
                let link = entry
                    .link_name()?
                    .map(|l| l.to_string_lossy().into_owned())
                    .unwrap_or_default();
                out.append_link(&mut header, &full, link)?;
            }
            _ => out.append_data(&mut header, &full, &mut entry)?,
        }
    }
    out.into_inner()
}

fn single_file_archive(name: &str, data: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut out = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    header.set_mtime(now_secs());
    header.set_entry_type(tar::EntryType::Regular);
    out.append_data(&mut header, name, data)?;
    out.into_inner()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `PUT /containers/{id}/archive`: unpack the body (a tar) at `path`.
pub(crate) async fn put_archive(
    State(engine): State<Arc<Engine>>,
    Path(id): Path<String>,
    Query(q): Q,
    body: Body,
) -> ApiResult<Response> {
    let c = engine
        .find_container(&id)
        .ok_or_else(|| ApiError::no_such_container(&id))?;
    let path = path_param(&q)?;
    let bytes: Bytes = axum::body::to_bytes(body, MAX_UPLOAD)
        .await
        .map_err(|e| ApiError::bad_request(format!("read archive: {e}")))?;
    let record = c.record();
    // Before the first start the overlay may not exist yet: keep the archive
    // and unpack it as the container starts.
    if !c.is_running() && record.state.status == "created" {
        let dir = engine.store.container_dir(&record.id).join("archives");
        std::fs::create_dir_all(&dir).map_err(|e| ApiError::internal(e.to_string()))?;
        let file = dir.join(format!("{}.tar", super::util::new_id()));
        std::fs::write(&file, &bytes).map_err(|e| ApiError::internal(e.to_string()))?;
        c.update(&engine, |r| {
            r.pending_archives
                .push((file.to_string_lossy().into_owned(), path.clone()))
        });
        return Ok(StatusCode::OK.into_response());
    }
    let machine = files_machine(&engine, &c).await?;
    let unpacked = unpack(&machine.socket, &record, &bytes, &path).await;
    machine.finish().await;
    unpacked?;
    Ok(StatusCode::OK.into_response())
}

/// Upload `tar` into the machine and unpack it at `destination` of the
/// container's root filesystem.
pub(crate) async fn unpack(
    socket: &std::path::Path,
    record: &super::containers::ContainerRecord,
    tar: &[u8],
    destination: &str,
) -> ApiResult<()> {
    let guest = format!("/storage/engine-archives/{}.tar", super::util::new_id());
    upload(socket, &guest, tar).await?;
    let reply = super::runtime::request(
        socket,
        &AgentRequest::ContainerArchive {
            image: record.pull_ref.clone(),
            overlay_id: super::containers::overlay_id(record),
            archive: guest,
            destination: destination.to_string(),
        },
    )
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    match super::runtime::error_text(&reply) {
        Some(e) => Err(ApiError::internal(format!("extract archive: {e}"))),
        None => Ok(()),
    }
}

/// Write `data` to `path` in the machine (not the container).
async fn upload(socket: &std::path::Path, path: &str, data: &[u8]) -> ApiResult<()> {
    let err = |e: std::io::Error| ApiError::internal(format!("upload archive: {e}"));
    let (mut reader, mut writer) = super::runtime::connect(socket).await.map_err(err)?;
    let expect_ok = |reply: AgentResponse| match reply {
        AgentResponse::Ok { .. } => Ok(()),
        other => Err(ApiError::internal(format!(
            "upload archive: {}",
            super::runtime::error_text(&other).unwrap_or_else(|| format!("{other:?}"))
        ))),
    };
    writer
        .send(&AgentRequest::FileWriteBegin {
            path: path.to_string(),
            mode: Some(0o600),
            uid: None,
            gid: None,
            total_size: data.len() as u64,
            target: Some(WorkloadTarget::Vm),
        })
        .await
        .map_err(err)?;
    expect_ok(reader.recv().await.map_err(err)?)?;
    let chunks: Vec<&[u8]> = if data.is_empty() {
        vec![&[][..]]
    } else {
        data.chunks(smolvm_protocol::FILE_WRITE_CHUNK_SIZE)
            .collect()
    };
    let last = chunks.len() - 1;
    for (i, chunk) in chunks.into_iter().enumerate() {
        writer
            .send(&AgentRequest::FileWriteChunk {
                data: chunk.to_vec(),
                done: i == last,
            })
            .await
            .map_err(err)?;
        let mut reply = reader.recv().await.map_err(err)?;
        while matches!(reply, AgentResponse::Progress { .. }) {
            reply = reader.recv().await.map_err(err)?;
        }
        expect_ok(reply)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_directory_archive_gets_its_name_at_the_top() {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(2);
        h.set_mode(0o644);
        b.append_data(&mut h, "./a.txt", &b"hi"[..]).unwrap();
        let inner = b.into_inner().unwrap();
        let out = prefix_archive(&inner, "etc").unwrap();
        let mut names = Vec::new();
        for e in tar::Archive::new(&out[..]).entries().unwrap() {
            names.push(e.unwrap().path().unwrap().to_string_lossy().into_owned());
        }
        assert_eq!(names, ["etc/", "etc/a.txt"]);
    }
}
