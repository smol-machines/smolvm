//! `docker cp`: tar archives in and out of a container's filesystem.
//!
//! A running container's files are reached through its agent. A container
//! that is not running gets its machine booted for the copy and stopped
//! again. A stopped container gets its configured mount namespace without
//! executing its command, so uploads are visible immediately.

use std::io::{Read as _, Write as _};
use std::sync::Arc;

mod transfer;

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use smolvm_protocol::{AgentRequest, AgentResponse, PathMetadata, WorkloadTarget};

use super::containers::Container;
use super::util::{ApiError, ApiResult};
use super::Engine;

type Q = Query<std::collections::HashMap<String, String>>;

/// Largest archive accepted in one upload.
const MAX_UPLOAD: u64 = 4 << 30;

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

/// Docker distinguishes copying a directory from copying its contents (`dir/.`).
/// Guest paths use `/` on every host; `Path::file_name` would erase the final dot.
fn archive_basename(path: &str) -> Option<&str> {
    path.trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
}

/// A machine to talk to for the container's files: its own when it runs,
/// otherwise one booted for this copy, which [`FilesMachine::finish`] stops
/// again. A booted one holds the container's lifecycle lock, so a start
/// waits for the copy instead of racing the stop.
pub(super) struct FilesMachine {
    pub(super) socket: std::path::PathBuf,
    temporary: Option<Temporary>,
    operation: Option<tokio::sync::OwnedMutexGuard<()>>,
    session: Option<FilesSession>,
    shares: Option<(Arc<Engine>, super::containers::ContainerRecord)>,
}

struct Temporary {
    engine: Arc<Engine>,
    machine: String,
    _vm: tokio::sync::OwnedMutexGuard<()>,
    _op: tokio::sync::OwnedMutexGuard<()>,
}

struct FilesSession {
    overlay_id: String,
    id: String,
    reader: super::runtime::AgentReader,
    writer: super::runtime::AgentWriter,
}

async fn end_session(mut session: FilesSession) {
    let request = AgentRequest::ContainerEndFiles {
        overlay_id: session.overlay_id,
        id: session.id,
    };
    match tokio::time::timeout(std::time::Duration::from_secs(5), async {
        session.writer.send(&request).await?;
        session.reader.recv().await
    })
    .await
    {
        Ok(Ok(AgentResponse::Ok { .. })) => {}
        reply => tracing::warn!(
            ?reply,
            "could not release the container inspection namespace"
        ),
    }
}

async fn finish_files(
    session: Option<FilesSession>,
    temporary: Option<Temporary>,
    shares: Option<(Arc<Engine>, super::containers::ContainerRecord)>,
    _operation: Option<tokio::sync::OwnedMutexGuard<()>>,
) {
    if let Some(session) = session {
        end_session(session).await;
    }
    if let Some((engine, record)) = shares {
        super::containers::release_guest_shares(&engine, &record).await;
    }
    if let Some(t) = temporary {
        super::containers::stop_machine(&t.engine, &t.machine, Some(std::time::Duration::ZERO))
            .await;
    }
}

impl FilesMachine {
    pub(super) async fn finish(mut self) {
        finish_files(
            self.session.take(),
            self.temporary.take(),
            self.shares.take(),
            self.operation.take(),
        )
        .await;
    }
}

impl Drop for FilesMachine {
    fn drop(&mut self) {
        if self.session.is_some() || self.temporary.is_some() || self.shares.is_some() {
            tokio::spawn(finish_files(
                self.session.take(),
                self.temporary.take(),
                self.shares.take(),
                self.operation.take(),
            ));
        }
    }
}

async fn begin_session(
    engine: &Engine,
    record: &super::containers::ContainerRecord,
    socket: &std::path::Path,
) -> ApiResult<FilesSession> {
    let request =
        AgentRequest::ContainerBeginFiles(Box::new(super::containers::start_spec(engine, record)));
    let (mut reader, mut writer) = super::runtime::connect(socket)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let reply = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        writer.send(&request).await?;
        reader.recv().await
    })
    .await
    .map_err(|_| ApiError::internal("container filesystem preparation timed out"))?
    .map_err(|e| {
        ApiError::internal(format!(
            "prepare container files: {e}; ensure the guest agent supports ContainerBeginFiles"
        ))
    })?;
    match reply {
        AgentResponse::Ok { data: Some(data) } => {
            let id = data["id"]
                .as_str()
                .filter(|id| {
                    !id.is_empty()
                        && id.len() <= 200
                        && id
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
                })
                .ok_or_else(|| {
                    ApiError::internal("the guest returned an invalid inspection identity")
                })?;
            Ok(FilesSession {
                overlay_id: super::containers::overlay_id(record),
                id: id.into(),
                reader,
                writer,
            })
        }
        AgentResponse::Error { message, .. } => Err(ApiError::internal(format!(
            "prepare container files: {message}"
        ))),
        _ => Err(ApiError::internal(
            "the guest returned no inspection identity",
        )),
    }
}

// Migrate archives queued by older engines. New uploads are applied immediately.
async fn unpack_pending(engine: &Engine, c: &Container, socket: &std::path::Path) -> ApiResult<()> {
    let record = c.record();
    for (file, destination) in &record.pending_archives {
        unpack(socket, &record, std::path::Path::new(file), destination).await?;
        c.update(engine, |r| {
            r.pending_archives
                .retain(|p| p != &(file.clone(), destination.clone()))
        });
        let _ = tokio::fs::remove_file(file).await;
    }
    Ok(())
}

/// Apply legacy queued uploads in the configured namespace before first start.
/// The caller already holds the container lifecycle lock.
pub(super) async fn apply_pending(
    engine: &Engine,
    c: &Container,
    socket: &std::path::Path,
) -> ApiResult<()> {
    if c.record().pending_archives.is_empty() {
        return Ok(());
    }
    let session = begin_session(engine, &c.record(), socket).await?;
    let result = unpack_pending(engine, c, socket).await;
    end_session(session).await;
    result
}

pub(super) async fn files_machine(
    engine: &Arc<Engine>,
    c: &Arc<Container>,
) -> ApiResult<FilesMachine> {
    let mut machine = open_files_machine(engine, c).await?;
    if !c.is_running() {
        machine.session = Some(begin_session(engine, &c.record(), &machine.socket).await?);
    }
    unpack_pending(engine, c, &machine.socket).await?;
    Ok(machine)
}

async fn open_files_machine(engine: &Arc<Engine>, c: &Arc<Container>) -> ApiResult<FilesMachine> {
    let guard = c.op_lock().await;
    if let Some(socket) = c.socket() {
        return Ok(FilesMachine {
            socket,
            temporary: None,
            operation: Some(guard),
            session: None,
            shares: None,
        });
    }
    // A container that shares another's network has its files in that
    // container's machine, which only that container boots.
    let record = c.record();
    if let Some(host) = record.network_host().map(str::to_string) {
        let mut machine = FilesMachine {
            socket: std::path::PathBuf::new(),
            temporary: None,
            operation: Some(guard),
            session: None,
            shares: Some((engine.clone(), record.clone())),
        };
        machine.socket = super::containers::guest_machine(engine, &record, &host).await?;
        return Ok(machine);
    }
    // A machine still shutting down after its command exited must be down
    // before it boots again.
    let vm = c.vm.clone().lock_owned().await;
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
        operation: None,
        session: None,
        shares: None,
        temporary: Some(Temporary {
            engine: engine.clone(),
            machine: record.machine,
            _vm: vm,
            _op: guard,
        }),
    })
}

pub(super) fn target(c: &Container) -> WorkloadTarget {
    let record = c.record();
    WorkloadTarget::Container {
        image: record.pull_ref.clone(),
        overlay_id: super::containers::overlay_id(&record),
    }
}

/// Read guest metadata without scanning the parent or inventing host permissions.
async fn stat(
    socket: &std::path::Path,
    target: &WorkloadTarget,
    path: &str,
) -> ApiResult<Option<PathMetadata>> {
    let reply = super::runtime::request(
        socket,
        &AgentRequest::StatPath {
            path: path.into(),
            target: Some(target.clone()),
        },
    )
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    match reply {
        AgentResponse::Ok { data: Some(data) } => serde_json::from_value(data)
            .map(Some)
            .map_err(|e| ApiError::internal(format!("invalid guest metadata: {e}"))),
        AgentResponse::Error { code, .. }
            if code.as_deref() == Some(smolvm_protocol::error_codes::NOT_FOUND) =>
        {
            Ok(None)
        }
        AgentResponse::Error { message, .. } => Err(ApiError::internal(message)),
        _ => Err(ApiError::internal("guest did not return path metadata")),
    }
}

fn stat_header(path: &str, metadata: &PathMetadata) -> HeaderValue {
    use base64::Engine as _;
    // Go's FileMode stores type and special permission bits above the low nine.
    let mut mode = (metadata.mode & 0o777) as u64;
    mode |= match metadata.kind.as_str() {
        "dir" => 1 << 31,
        "symlink" => 1 << 27,
        "file" => 0,
        _ => 1 << 19, // ModeIrregular, never report a device as an ordinary file.
    };
    for (posix, go) in [(0o4000, 1 << 23), (0o2000, 1 << 22), (0o1000, 1 << 20)] {
        if metadata.mode & posix != 0 {
            mode |= go;
        }
    }
    let epoch = std::time::UNIX_EPOCH;
    let time = if metadata.modified_secs >= 0 {
        epoch.checked_add(std::time::Duration::from_secs(
            metadata.modified_secs as u64,
        ))
    } else {
        epoch.checked_sub(std::time::Duration::from_secs(
            metadata.modified_secs.unsigned_abs(),
        ))
    }
    .and_then(|t| {
        t.checked_add(std::time::Duration::from_nanos(
            metadata.modified_nanos.into(),
        ))
    });
    let json = serde_json::json!({
        "name": archive_basename(path).unwrap_or("/"), "size": metadata.size, "mode": mode,
        "mtime": super::util::rfc3339(time.unwrap_or(epoch)), "linkTarget": metadata.resolved_link_target,
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
    let metadata = found?.ok_or_else(|| no_such_path(&path))?;
    let mut r = StatusCode::OK.into_response();
    r.headers_mut().insert(
        "X-Docker-Container-Path-Stat",
        stat_header(&path, &metadata),
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
    let metadata = stat(&machine.socket, &target, &path)
        .await?
        .ok_or_else(|| no_such_path(&path))?;
    let name = archive_basename(&path).unwrap_or(".").to_owned();
    if metadata.kind == "symlink" {
        // Copy the link itself; Docker's -L resolves linkTarget with another request.
        let bytes = single_file_archive(std::io::empty(), Vec::new(), &name, &metadata)
            .map_err(|e| ApiError::internal(e.to_string()))?;
        machine.finish().await;
        let mut response = Response::new(Body::from(bytes));
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-tar"),
        );
        response.headers_mut().insert(
            "X-Docker-Container-Path-Stat",
            stat_header(&path, &metadata),
        );
        return Ok(response);
    }
    if metadata.kind != "file" && metadata.kind != "dir" {
        return Err(ApiError::bad_request(
            "only regular files, directories and symbolic links can be copied",
        ));
    }
    let request = if metadata.kind == "dir" {
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
    // Fail before HTTP headers when the guest refuses the read. Later failures
    // remain body errors, so Docker and Studio cannot report a truncated copy as complete.
    let first = reader
        .recv()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    if let AgentResponse::Error { message, .. } = &first {
        return Err(ApiError::internal(format!("read {path}: {message}")));
    }
    let (input, incoming) = transfer::channel();
    let (output, outgoing) = transfer::channel();
    let disconnected = output.clone();
    tokio::spawn(async move {
        let _writer = writer;
        let mut first = Some(first);
        loop {
            let reply = if let Some(first) = first.take() {
                Ok(first)
            } else {
                tokio::select! {
                    _ = disconnected.closed() => break,
                    _ = input.closed() => break,
                    reply = reader.recv() => reply,
                }
            };
            let (chunk, done) = match reply {
                Ok(AgentResponse::DataChunk { data, done }) => (Ok(data.into()), done),
                Ok(AgentResponse::Progress { .. }) => continue,
                Ok(AgentResponse::Error { message, .. }) => {
                    (Err(std::io::Error::other(message)), true)
                }
                Ok(other) => (
                    Err(std::io::Error::other(format!(
                        "unexpected archive response: {other:?}"
                    ))),
                    true,
                ),
                Err(error) => (Err(error), true),
            };
            tokio::select! {
                _ = disconnected.closed() => break,
                sent = input.send(chunk) => if sent.is_err() { break; },
            }
            if done {
                break;
            }
        }
        drop(input);
        drop(reader);
        drop(_writer);
        machine.finish().await;
    });
    let directory = metadata.kind == "dir";
    let archive_metadata = metadata.clone();
    tokio::task::spawn_blocking(move || {
        let source = transfer::Reader::new(incoming);
        let destination = transfer::Writer::new(output.clone());
        let result = if directory {
            prefix_archive(source, destination, &name)
        } else {
            single_file_archive(source, destination, &name, &archive_metadata)
        }
        .and_then(|mut writer| writer.flush());
        if let Err(error) = result {
            let _ = output.blocking_send(Err(error));
        }
    });
    let mut r = Response::new(Body::from_stream(
        tokio_stream::wrappers::ReceiverStream::new(outgoing),
    ));
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-tar"),
    );
    r.headers_mut().insert(
        "X-Docker-Container-Path-Stat",
        stat_header(&path, &metadata),
    );
    Ok(r)
}

/// The entries of `tar` (a directory's contents) under `prefix/`.
fn prefix_archive<R: std::io::Read, W: std::io::Write>(
    source: R,
    destination: W,
    prefix: &str,
) -> std::io::Result<W> {
    let mut out = tar::Builder::new(transfer::AbortWriter::new(destination));
    let result = (|| {
        let mut top = tar::Header::new_gnu();
        top.set_entry_type(tar::EntryType::Directory);
        top.set_mode(0o755);
        top.set_size(0);
        top.set_mtime(now_secs());
        let mut top_written = false;
        let mut archive = tar::Archive::new(source);
        for entry in archive.entries()? {
            let mut entry = entry?;
            let path = entry.path()?.to_string_lossy().into_owned();
            let path = path.trim_start_matches("./");
            let root = path.is_empty() || path == ".";
            if root && entry.header().entry_type().is_dir() {
                top = entry.header().clone();
                top.set_size(0);
                out.append_data(&mut top, format!("{prefix}/"), std::io::empty())?;
                top_written = true;
                continue;
            }
            if !top_written {
                out.append_data(&mut top, format!("{prefix}/"), std::io::empty())?;
                top_written = true;
            }
            if root {
                continue;
            }
            let mut header = entry.header().clone();
            if header.entry_type().is_gnu_sparse() {
                // Entry reads expand GNU sparse data to its logical byte stream;
                // retaining the packed size/map would corrupt the rewritten tar.
                header.set_entry_type(tar::EntryType::Regular);
                header.set_size(entry.size());
            }
            let full = format!("{prefix}/{path}");
            match header.entry_type() {
                tar::EntryType::Symlink | tar::EntryType::Link => {
                    let mut link = entry
                        .link_name()?
                        .map(|l| l.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    if header.entry_type().is_hard_link() {
                        let relative = std::path::Path::new(&link);
                        if relative.components().any(|c| {
                            !matches!(
                                c,
                                std::path::Component::Normal(_) | std::path::Component::CurDir
                            )
                        }) {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "hard link escapes directory archive",
                            ));
                        }
                        link = format!("{prefix}/{}", link.trim_start_matches("./"));
                    }
                    out.append_link(&mut header, &full, link)?;
                }
                _ => out.append_data(&mut header, &full, &mut entry)?,
            }
        }
        if !top_written {
            out.append_data(&mut top, format!("{prefix}/"), std::io::empty())?;
        }
        // A tar footer is not the end of the transport: the guest can still fail
        // while finishing its helper. Consume that final result before success.
        std::io::copy(&mut archive.into_inner(), &mut std::io::sink())?;
        Ok(())
    })();
    finish_archive(out, result)
}

fn single_file_archive<R: std::io::Read, W: std::io::Write>(
    mut source: R,
    destination: W,
    name: &str,
    metadata: &PathMetadata,
) -> std::io::Result<W> {
    let mut out = tar::Builder::new(transfer::AbortWriter::new(destination));
    let result = (|| {
        let mut header = tar::Header::new_gnu();
        header.set_mode(metadata.mode);
        header.set_uid(metadata.uid.into());
        header.set_gid(metadata.gid.into());
        header.set_mtime(metadata.modified_secs.max(0) as u64);
        if metadata.modified_secs < 0 || metadata.modified_nanos != 0 {
            let nanos =
                metadata.modified_secs as i128 * 1_000_000_000 + metadata.modified_nanos as i128;
            let sign = if nanos < 0 { "-" } else { "" };
            let nanos = nanos.unsigned_abs();
            let time = format!(
                "{sign}{}.{:09}",
                nanos / 1_000_000_000,
                nanos % 1_000_000_000
            );
            out.append_pax_extensions([("mtime", time.as_bytes())])?;
        }
        if metadata.kind == "symlink" {
            header.set_size(0);
            header.set_entry_type(tar::EntryType::Symlink);
            out.append_link(&mut header, name, &metadata.link_target)?;
            return Ok(());
        }
        header.set_size(metadata.size);
        header.set_entry_type(tar::EntryType::Regular);
        let mut limited = source.by_ref().take(metadata.size);
        out.append_data(&mut header, name, &mut limited)?;
        if limited.limit() != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "file became shorter during download",
            ));
        }
        if source.read(&mut [0u8])? != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "file became longer during download",
            ));
        }
        Ok(())
    })();
    finish_archive(out, result)
}

fn finish_archive<W: std::io::Write>(
    mut archive: tar::Builder<transfer::AbortWriter<W>>,
    result: std::io::Result<()>,
) -> std::io::Result<W> {
    if let Err(error) = result {
        archive.get_mut().abort();
        return Err(error);
    }
    archive.into_inner().map(transfer::AbortWriter::into_inner)
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
    let staging = crate::data::image_source::archive_staging_dir()
        .map_err(|e| ApiError::internal(format!("stage archive: {e}")))?;
    let archive = staging.path().join("upload.tar");
    stage_upload(body, &archive, MAX_UPLOAD).await?;
    let machine = files_machine(&engine, &c).await?;
    let record = c.record();
    let unpacked = unpack(&machine.socket, &record, &archive, &path).await;
    machine.finish().await;
    unpacked?;
    Ok(StatusCode::OK.into_response())
}

/// Receive the complete bounded upload before changing any guest files.
async fn stage_upload(body: Body, path: &std::path::Path, limit: u64) -> ApiResult<()> {
    use tokio::io::AsyncWriteExt as _;
    use tokio_stream::StreamExt as _;
    let file = tokio::fs::File::create(path)
        .await
        .map_err(|e| ApiError::internal(format!("stage archive: {e}")))?;
    // HTTP frames can be tiny; coalesce them before scheduling filesystem writes.
    let mut file = tokio::io::BufWriter::with_capacity(1024 * 1024, file);
    let mut stream = body.into_data_stream();
    let mut total = 0u64;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| ApiError::bad_request(format!("read archive: {e}")))?;
        total = total
            .checked_add(chunk.len() as u64)
            .filter(|total| *total <= limit)
            .ok_or_else(|| {
                ApiError::bad_request(format!("archive exceeds the {limit}-byte upload limit"))
            })?;
        file.write_all(&chunk)
            .await
            .map_err(|e| ApiError::internal(format!("stage archive: {e}")))?;
    }
    file.flush()
        .await
        .map_err(|e| ApiError::internal(format!("stage archive: {e}")))?;
    Ok(())
}

/// Upload `tar` into the machine and unpack it at `destination` of the
/// container's root filesystem.
pub(crate) async fn unpack(
    socket: &std::path::Path,
    record: &super::containers::ContainerRecord,
    tar: &std::path::Path,
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
            image_source: record.image_source(),
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
async fn upload(socket: &std::path::Path, path: &str, source: &std::path::Path) -> ApiResult<()> {
    use tokio::io::AsyncReadExt as _;
    let err = |e: std::io::Error| ApiError::internal(format!("upload archive: {e}"));
    let mut file = tokio::fs::File::open(source).await.map_err(err)?;
    let size = file.metadata().await.map_err(err)?.len();
    if size > MAX_UPLOAD {
        return Err(ApiError::bad_request("archive exceeds the upload limit"));
    }
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
            total_size: size,
            target: Some(WorkloadTarget::Vm),
        })
        .await
        .map_err(err)?;
    expect_ok(reader.recv().await.map_err(err)?)?;
    let mut remaining = size;
    loop {
        let mut chunk =
            vec![0u8; remaining.min(smolvm_protocol::FILE_WRITE_CHUNK_SIZE as u64) as usize];
        file.read_exact(&mut chunk).await.map_err(err)?;
        remaining -= chunk.len() as u64;
        if remaining == 0 && file.read(&mut [0u8]).await.map_err(err)? != 0 {
            return Err(ApiError::bad_request(
                "staged archive changed during upload",
            ));
        }
        writer
            .send(&AgentRequest::FileWriteChunk {
                data: chunk,
                done: remaining == 0,
            })
            .await
            .map_err(err)?;
        let mut reply = reader.recv().await.map_err(err)?;
        while matches!(reply, AgentResponse::Progress { .. }) {
            reply = reader.recv().await.map_err(err)?;
        }
        expect_ok(reply)?;
        if remaining == 0 {
            break;
        }
    }
    Ok(())
}

/// Write what the container changed against its image to `out`, as one
/// image layer (`docker commit`).
pub(crate) async fn container_diff(
    engine: &Arc<Engine>,
    c: &Arc<Container>,
    out: &std::path::Path,
) -> ApiResult<()> {
    use tokio::io::AsyncWriteExt as _;
    let machine = files_machine(engine, c).await?;
    let overlay_id = super::containers::overlay_id(&c.record());
    let (mut reader, mut writer) = super::runtime::connect(&machine.socket)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    writer
        .send(&AgentRequest::ContainerDiff { overlay_id })
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let mut file = tokio::fs::File::create(out)
        .await
        .map_err(|e| ApiError::internal(format!("write the layer: {e}")))?;
    loop {
        match reader
            .recv()
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?
        {
            AgentResponse::DataChunk { data, done } => {
                file.write_all(&data)
                    .await
                    .map_err(|e| ApiError::internal(format!("write the layer: {e}")))?;
                if done {
                    break;
                }
            }
            AgentResponse::Error { message, .. } => {
                return Err(ApiError::internal(format!(
                    "read the container's changes: {message}"
                )))
            }
            _ => {}
        }
    }
    file.flush()
        .await
        .map_err(|e| ApiError::internal(format!("write the layer: {e}")))?;
    machine.finish().await;
    Ok(())
}

/// `GET /containers/{id}/export`: the container's whole filesystem as a tar,
/// streamed as the guest produces it.
pub(crate) async fn export(
    State(engine): State<Arc<Engine>>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    let c = engine
        .find_container(&id)
        .ok_or_else(|| ApiError::no_such_container(&id))?;
    let machine = files_machine(&engine, &c).await?;
    let (mut reader, mut writer) = super::runtime::connect(&machine.socket)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    writer
        .send(&AgentRequest::ArchiveDirectory {
            path: "/".into(),
            target: Some(target(&c)),
        })
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let (tx, rx) = tokio::sync::mpsc::channel::<std::io::Result<axum::body::Bytes>>(8);
    tokio::spawn(async move {
        loop {
            match reader.recv().await {
                Ok(AgentResponse::DataChunk { data, done }) => {
                    if !data.is_empty() && tx.send(Ok(data.into())).await.is_err() {
                        break;
                    }
                    if done {
                        break;
                    }
                }
                Ok(AgentResponse::Error { message, .. }) => {
                    let _ = tx.send(Err(std::io::Error::other(message))).await;
                    break;
                }
                Ok(_) => {}
                Err(e) => {
                    let _ = tx.send(Err(e)).await;
                    break;
                }
            }
        }
        machine.finish().await;
    });
    let mut r = Response::new(Body::from_stream(
        tokio_stream::wrappers::ReceiverStream::new(rx),
    ));
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-tar"),
    );
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_metadata(size: u64) -> PathMetadata {
        PathMetadata {
            kind: "file".into(),
            size,
            mode: 0o751,
            uid: 1234,
            gid: 2345,
            modified_secs: 1_600_000_000,
            modified_nanos: 0,
            link_target: String::new(),
            resolved_link_target: String::new(),
        }
    }

    #[test]
    fn individual_archives_preserve_guest_metadata_and_symbolic_links() {
        use base64::Engine as _;
        let name = "café 雪\nscript";
        let mut metadata = file_metadata(7);
        metadata.mode = 0o6751;
        metadata.modified_nanos = 123_456_789;
        let bytes = single_file_archive(&b"payload"[..], Vec::new(), name, &metadata).unwrap();
        let mut tar = tar::Archive::new(&bytes[..]);
        let mut entries = tar.entries().unwrap();
        let mut file = entries.next().unwrap().unwrap();
        assert_eq!(file.path().unwrap().to_str(), Some(name));
        assert_eq!(file.header().mode().unwrap(), 0o6751);
        assert_eq!(file.header().uid().unwrap(), 1234);
        assert_eq!(file.header().gid().unwrap(), 2345);
        let extensions: Vec<_> = file
            .pax_extensions()
            .unwrap()
            .unwrap()
            .map(|item| {
                let item = item.unwrap();
                (
                    item.key().unwrap().to_owned(),
                    item.value().unwrap().to_owned(),
                )
            })
            .collect();
        assert!(extensions.contains(&("mtime".into(), "1600000000.123456789".into())));
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "payload");
        assert!(entries.next().is_none());
        let encoded = stat_header("/app/script", &metadata);
        let stat: serde_json::Value = serde_json::from_slice(
            &base64::engine::general_purpose::STANDARD
                .decode(encoded.as_bytes())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(stat["mode"], 0o751 | (1 << 23) | (1 << 22));
        assert_eq!(stat["mtime"], "2020-09-13T12:26:40.123456789Z");

        metadata.kind = "symlink".into();
        metadata.link_target = "missing 雪\nfile".into();
        let bytes = single_file_archive(std::io::empty(), Vec::new(), "link", &metadata).unwrap();
        let mut tar = tar::Archive::new(&bytes[..]);
        let link = tar.entries().unwrap().next().unwrap().unwrap();
        assert!(link.header().entry_type().is_symlink());
        assert_eq!(link.size(), 0);
        assert_eq!(
            link.link_name().unwrap().unwrap().to_str(),
            Some(metadata.link_target.as_str())
        );
    }

    #[test]
    fn directory_contents_keep_the_trailing_dot_in_metadata_and_archive() {
        use base64::Engine as _;
        let mut input = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(2);
        header.set_mode(0o751);
        input
            .append_data(&mut header, "./file", &b"hi"[..])
            .unwrap();
        let input = input.into_inner().unwrap();
        for (path, name, copied_file) in [
            ("/app/project", "project", "project/file"),
            ("/app/project/", "project", "project/file"),
            ("/app/project/.", ".", "file"),
            ("/app/project/./", ".", "file"),
            ("/.", ".", "file"),
        ] {
            let stat = stat_header(
                path,
                &PathMetadata {
                    kind: "dir".into(),
                    ..file_metadata(0)
                },
            );
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(stat.as_bytes())
                .unwrap();
            let stat: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
            assert_eq!(stat["name"], name, "{path}");
            let output =
                prefix_archive(&input[..], Vec::new(), archive_basename(path).unwrap()).unwrap();
            let destination = tempfile::tempdir().unwrap();
            tar::Archive::new(&output[..])
                .unpack(destination.path())
                .unwrap();
            assert_eq!(
                std::fs::read(destination.path().join(copied_file)).unwrap(),
                b"hi"
            );
        }
    }

    #[test]
    fn a_directory_archive_gets_its_name_at_the_top() {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(2);
        h.set_mode(0o644);
        b.append_data(&mut h, "./a.txt", &b"hi"[..]).unwrap();
        let inner = b.into_inner().unwrap();
        let out = prefix_archive(&inner[..], Vec::new(), "etc").unwrap();
        let mut names = Vec::new();
        for e in tar::Archive::new(&out[..]).entries().unwrap() {
            names.push(e.unwrap().path().unwrap().to_string_lossy().into_owned());
        }
        assert_eq!(names, ["etc/", "etc/a.txt"]);
    }

    #[test]
    fn rewriting_directory_archive_preserves_root_mode_and_link_targets() {
        let mut input = tar::Builder::new(Vec::new());
        let mut root = tar::Header::new_gnu();
        root.set_mode(0o700);
        root.set_size(0);
        root.set_entry_type(tar::EntryType::Directory);
        input.append_data(&mut root, ".", std::io::empty()).unwrap();
        let mut file = tar::Header::new_gnu();
        file.set_mode(0o640);
        file.set_size(3);
        input.append_data(&mut file, "./data", &b"abc"[..]).unwrap();
        for (kind, name, target) in [
            (tar::EntryType::Link, "hard", "./data"),
            (tar::EntryType::Symlink, "symbolic", "data"),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(kind);
            header.set_size(0);
            header.set_mode(0o777);
            input.append_link(&mut header, name, target).unwrap();
        }
        let input = input.into_inner().unwrap();
        let output = prefix_archive(&input[..], Vec::new(), "private").unwrap();
        let mut archive = tar::Archive::new(&output[..]);
        let mut entries = archive.entries().unwrap();
        let root = entries.next().unwrap().unwrap();
        assert_eq!(root.header().mode().unwrap(), 0o700);
        assert_eq!(
            root.path().unwrap().as_ref(),
            std::path::Path::new("private/")
        );
        entries.next().unwrap().unwrap();
        assert_eq!(
            entries
                .next()
                .unwrap()
                .unwrap()
                .link_name()
                .unwrap()
                .unwrap()
                .as_ref(),
            std::path::Path::new("private/data")
        );
        assert_eq!(
            entries
                .next()
                .unwrap()
                .unwrap()
                .link_name()
                .unwrap()
                .unwrap()
                .as_ref(),
            std::path::Path::new("data")
        );
        assert!(entries.next().is_none());
    }

    #[test]
    fn rewriting_sparse_archive_uses_logical_size_and_regular_header() {
        let mut input = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::GNUSparse);
        header.set_size(3);
        header.set_mode(0o600);
        let sparse = header.as_gnu_mut().unwrap();
        sparse.set_real_size(32768);
        sparse.sparse[0].set_offset(8192);
        sparse.sparse[0].set_length(3);
        sparse.sparse[1].set_offset(32768);
        sparse.sparse[1].set_length(0);
        input
            .append_data(&mut header, "sparse", &b"abc"[..])
            .unwrap();
        let input = input.into_inner().unwrap();
        let output = prefix_archive(&input[..], Vec::new(), "app").unwrap();
        let mut archive = tar::Archive::new(&output[..]);
        let mut entries = archive.entries().unwrap();
        entries.next().unwrap().unwrap();
        let mut file = entries.next().unwrap().unwrap();
        assert!(file.header().entry_type().is_file());
        assert_eq!(file.header().size().unwrap(), 32768);
        let mut actual = Vec::new();
        file.read_to_end(&mut actual).unwrap();
        let mut expected = vec![0; 32768];
        expected[8192..8195].copy_from_slice(b"abc");
        assert_eq!(actual, expected);
        assert!(entries.next().is_none());
    }
    #[test]
    fn changed_file_size_never_finishes_a_successful_archive() {
        for (bytes, expected) in [(&b"short"[..], 50), (&b"too long"[..], 2)] {
            let mut output = Vec::new();
            assert!(
                single_file_archive(bytes, &mut output, "file.txt", &file_metadata(expected))
                    .is_err()
            );
            assert!(
                !output.ends_with(&[0u8; 1024]),
                "failed copy acquired a tar footer"
            );
        }
    }

    struct FailsAtEnd(std::io::Cursor<Vec<u8>>);
    impl std::io::Read for FailsAtEnd {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let count = self.0.read(buf)?;
            if count == 0 && !buf.is_empty() {
                return Err(std::io::Error::other("guest failed after tar footer"));
            }
            Ok(count)
        }
    }

    #[test]
    fn directory_transport_failure_after_tar_footer_is_not_hidden() {
        let bytes =
            single_file_archive(&b"payload"[..], Vec::new(), "file", &file_metadata(7)).unwrap();
        let mut output = Vec::new();
        let error = prefix_archive(FailsAtEnd(std::io::Cursor::new(bytes)), &mut output, "app")
            .unwrap_err();
        assert!(error.to_string().contains("guest failed"));
        assert!(
            !output.ends_with(&[0u8; 1024]),
            "failure must not emit a successful footer"
        );
    }

    #[tokio::test]
    async fn streamed_directory_preserves_file_bytes_and_literal_names() {
        let literal = "a ; $(false) &?#+%\n雪.txt";
        let payload = vec![0x93; 512 * 1024 + 13];
        let archive = single_file_archive(
            &payload[..],
            Vec::new(),
            literal,
            &file_metadata(payload.len() as u64),
        )
        .unwrap();
        let (tx, rx) = transfer::channel();
        let (out, mut downloaded) = transfer::channel();
        let producer = tokio::spawn(async move {
            for chunk in archive.chunks(4097) {
                tx.send(Ok(chunk.to_vec().into())).await.unwrap();
            }
        });
        let transform = tokio::task::spawn_blocking(move || {
            prefix_archive(transfer::Reader::new(rx), transfer::Writer::new(out), "app")
                .unwrap()
                .flush()
                .unwrap();
        });
        let mut bytes = Vec::new();
        while let Some(chunk) = downloaded.recv().await {
            bytes.extend_from_slice(&chunk.unwrap());
        }
        producer.await.unwrap();
        transform.await.unwrap();
        let mut tar = tar::Archive::new(&bytes[..]);
        let mut entries = tar.entries().unwrap();
        assert_eq!(
            entries.next().unwrap().unwrap().path().unwrap().to_str(),
            Some("app/")
        );
        let mut file = entries.next().unwrap().unwrap();
        assert_eq!(
            file.path().unwrap().to_str(),
            Some(format!("app/{literal}").as_str())
        );
        let mut read = Vec::new();
        file.read_to_end(&mut read).unwrap();
        assert_eq!(read, payload);
        assert!(entries.next().is_none());
    }

    #[tokio::test]
    async fn upload_limit_and_transport_errors_are_rejected_while_staging() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("upload.tar");
        let chunks = || {
            vec![
                Ok::<_, std::io::Error>(axum::body::Bytes::from_static(b"12345")),
                Ok(axum::body::Bytes::from_static(b"67890")),
            ]
        };
        stage_upload(Body::from_stream(tokio_stream::iter(chunks())), &path, 10)
            .await
            .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"1234567890");
        let error = stage_upload(Body::from_stream(tokio_stream::iter(chunks())), &path, 9)
            .await
            .unwrap_err();
        assert!(error.message.contains("upload limit"));
        let failed = vec![
            Ok(axum::body::Bytes::from_static(b"partial")),
            Err(std::io::Error::other("connection interrupted")),
        ];
        assert!(
            stage_upload(Body::from_stream(tokio_stream::iter(failed)), &path, 100)
                .await
                .is_err()
        );
    }
}
