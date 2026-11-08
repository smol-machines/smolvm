//! Exec sessions: commands the node owns (see [`crate::api::exec_sessions`]).
//!
//! - `POST   /machines/{id}/execs`                start (idempotent on `execId`)
//! - `GET    /machines/{id}/execs`                list
//! - `GET    /machines/{id}/execs/{exec}`         read output `after` an offset
//! - `POST   /machines/{id}/execs/{exec}/stdin`   one sequenced stdin frame
//! - `POST   /machines/{id}/execs/{exec}/resize`  resize the terminal
//! - `DELETE /machines/{id}/execs/{exec}`         kill (if running) and forget
//! - `GET    /machines/{id}/execs/{exec}/attach`  WebSocket: output, stdin, resize
//!
//! The attach WebSocket, for terminals. Server to client:
//! - text `{"type":"hello","execId","next","start","end","stdinApplied","state","tty"}`, first;
//! - binary output frames: one byte for the stream (1 stdout, 2 stderr), the
//!   chunk's offset as a big-endian u64, then the bytes;
//! - text `{"type":"lost","from","to"}` when the reader asked for output no
//!   longer held;
//! - text `{"type":"stdin","applied":N}` after each stdin frame, and
//!   `{"type":"error","message"}` for a frame that could not be applied;
//! - text `{"type":"exit","exitCode","error"}` last, then a normal close.
//!
//! Client to server:
//! - binary stdin frames: the frame's sequence number as a big-endian u64,
//!   then at most 64 KiB of bytes;
//! - text `{"type":"eof","seq":N}` (close stdin), `{"type":"resize","cols","rows"}`,
//!   `{"type":"ack","offset":N}` (the client holds every byte before N; the
//!   command may run at most one output window past it), `{"type":"terminate"}`
//!   (kill the command).
//!
//! A WebSocket that closes or drops without `terminate` only detaches: the
//! command keeps running, and a new attach with `?after=` the client's offset
//! resumes it.

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use futures_util::{SinkExt, StreamExt};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::Duration;

use crate::api::error::{classify_ensure_running_error, ApiError};
use crate::api::exec_sessions::{
    output_of, valid_exec_id, Batch, ExecSession, Exit, RegisterError, StdinError, MAX_STDIN_FRAME,
};
use crate::api::state::{ensure_running_and_persist, ApiState};
use crate::api::types::{
    ApiErrorResponse, CreateExecSessionRequest, ExecOutputChunk, ExecOutputGap, ExecResizeRequest,
    ExecSessionReadQuery, ExecSessionResponse, ExecStdinRequest, ExecStdinResponse,
    ListExecSessionsResponse,
};
use crate::api::validate_command;
use crate::api::TraceId;
use crate::data::storage::HostMount;

/// Default and largest output in one answer.
const DEFAULT_MAX_BYTES: usize = 4 * 1024 * 1024;
const MAX_MAX_BYTES: usize = 16 * 1024 * 1024;

/// Output sent per attach frame batch.
const ATTACH_READ_BYTES: usize = 256 * 1024;

/// Input events that may wait for the command to take them.
const INPUT_QUEUE_EVENTS: usize = 64;

/// How much longer than its timeout the node waits for a command's end before
/// it stops waiting for the guest (a wedged guest never reports it).
const HOST_DEADLINE_GRACE: Duration = Duration::from_secs(30);

fn fingerprint(req: &CreateExecSessionRequest, interactive: bool) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    req.command.hash(&mut h);
    for e in &req.env {
        e.name.hash(&mut h);
        e.value.hash(&mut h);
    }
    req.workdir.hash(&mut h);
    req.user.hash(&mut h);
    req.timeout_secs.hash(&mut h);
    req.stdin.hash(&mut h);
    req.tty.hash(&mut h);
    interactive.hash(&mut h);
    h.finish()
}

fn response(session: &ExecSession, batch: Batch) -> ExecSessionResponse {
    let state = match batch.state {
        crate::api::exec_sessions::SessionState::Starting => "starting",
        crate::api::exec_sessions::SessionState::Running => "running",
        crate::api::exec_sessions::SessionState::Exited => "exited",
    };
    ExecSessionResponse {
        exec_id: session.id.clone(),
        state: state.to_string(),
        done: batch.done,
        exit_code: batch.exit.as_ref().and_then(|e| e.code),
        error: batch.exit.as_ref().and_then(|e| e.error.clone()),
        output: batch
            .output
            .into_iter()
            .map(|p| ExecOutputChunk {
                stream: match p.stream {
                    crate::api::exec_sessions::OutputStream::Stdout => "stdout".into(),
                    crate::api::exec_sessions::OutputStream::Stderr => "stderr".into(),
                },
                offset: p.offset,
                data: p.data.to_vec(),
            })
            .collect(),
        next: batch.next,
        start: batch.start,
        end: batch.end,
        lost: batch.lost.map(|(from, to)| ExecOutputGap { from, to }),
        stdin_applied: batch.stdin_applied,
        tty: session.tty,
        interactive: session.interactive,
        created_at: session
            .created_at
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0),
    }
}

fn clamp_max(max: Option<usize>) -> usize {
    max.unwrap_or(DEFAULT_MAX_BYTES).clamp(1, MAX_MAX_BYTES)
}

fn beyond_end(after: u64, end: u64) -> ApiError {
    ApiError::BadRequest(format!(
        "offset {after} is beyond the end of the output ({end})"
    ))
}

/// Read after `after`, waiting up to `wait` for something new.
async fn read_waiting(
    session: &ExecSession,
    after: u64,
    wait: Option<u64>,
    max: usize,
) -> Result<Batch, ApiError> {
    // Acknowledge first: a command held back by its window must be able to
    // produce while this read waits.
    session.ack(after);
    if let Some(secs) = wait.filter(|s| *s > 0) {
        session.pace(after).await;
        session
            .wait_for_output(after, Duration::from_secs(secs))
            .await;
    }
    session
        .read(after, max, true)
        .map_err(|end| beyond_end(after, end))
}

fn not_found(id: &str, exec: &str) -> ApiError {
    ApiError::NotFound(format!(
        "exec '{exec}' not found on machine '{id}': it ended and was collected, was deleted, or the node restarted"
    ))
}

fn session_of(state: &ApiState, id: &str, exec: &str) -> Result<Arc<ExecSession>, ApiError> {
    state
        .exec_sessions()
        .get(id, exec)
        .ok_or_else(|| not_found(id, exec))
}

/// Start a command the node owns.
///
/// Answers once the command is running (or failed to start), with the output
/// from offset 0 after waiting up to `waitSecs`. A start whose `execId` the
/// node already has answers with that session, so a client may retry a start
/// whose answer it never got without running the command twice.
#[utoipa::path(
    post,
    path = "/api/v1/machines/{id}/execs",
    tag = "Execution",
    params(("id" = String, Path, description = "Machine name")),
    request_body = CreateExecSessionRequest,
    responses(
        (status = 201, description = "Started", body = ExecSessionResponse),
        (status = 200, description = "Already started by an earlier request with this execId", body = ExecSessionResponse),
        (status = 400, description = "Invalid request", body = ApiErrorResponse),
        (status = 404, description = "Machine not found", body = ApiErrorResponse),
        (status = 409, description = "The execId names a different or spent command, or the machine is not running and autoStart is false", body = ApiErrorResponse),
        (status = 503, description = "The node holds as many exec sessions as it may", body = ApiErrorResponse)
    )
)]
pub async fn create_exec_session(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
    trace_id: Option<axum::Extension<TraceId>>,
    Json(req): Json<CreateExecSessionRequest>,
) -> Result<(StatusCode, Json<ExecSessionResponse>), ApiError> {
    let tid = trace_id.map(|t| t.0 .0.clone());
    validate_command(&req.command)?;
    let exec_id = match &req.exec_id {
        Some(e) if !valid_exec_id(e) => {
            return Err(ApiError::BadRequest(
                "execId must be 8 to 64 of [A-Za-z0-9_-]".into(),
            ))
        }
        Some(e) => e.clone(),
        None => crate::api::exec_sessions::new_exec_id(),
    };
    let interactive = req.interactive || req.tty;
    let max = clamp_max(req.max_bytes);
    let entry = state.get_machine(&id)?;

    let (session, new) = state
        .exec_sessions()
        .register(
            &id,
            &exec_id,
            req.command.clone(),
            req.tty,
            interactive,
            fingerprint(&req, interactive),
        )
        .map_err(|e| match e {
            RegisterError::Mismatch => ApiError::Conflict(format!(
                "execId '{exec_id}' already names a different command on this machine"
            )),
            RegisterError::Spent => ApiError::Conflict(format!(
                "execId '{exec_id}' already ran on this machine and was collected"
            )),
            RegisterError::Full => {
                ApiError::Unavailable("this node holds as many exec sessions as it may".into())
            }
        })?;

    if !new {
        // A retried start: the first request may still be starting it.
        session.wait_started().await;
        let batch = read_waiting(&session, 0, req.wait_secs, max).await?;
        return Ok((StatusCode::OK, Json(response(&session, batch))));
    }

    let wait = req.wait_secs;
    if let Err(e) = start_session(&state, &id, &entry, &session, req, tid).await {
        state.exec_sessions().unregister(&id, &exec_id);
        return Err(e);
    }
    metrics::counter!("smolvm_exec_sessions_started_total").increment(1);
    let batch = read_waiting(&session, 0, wait, max).await?;
    Ok((StatusCode::CREATED, Json(response(&session, batch))))
}

/// Start the command of a session just registered: boot the machine if asked,
/// open a dedicated agent connection, and run the command on it in a task of
/// its own that outlives this request. Returns once the command runs, or with
/// the error that kept it from starting.
async fn start_session(
    state: &Arc<ApiState>,
    id: &str,
    entry: &Arc<parking_lot::Mutex<crate::api::state::MachineEntry>>,
    session: &Arc<ExecSession>,
    req: CreateExecSessionRequest,
    tid: Option<String>,
) -> Result<(), ApiError> {
    if req.auto_start {
        ensure_running_and_persist(state, id, entry)
            .await
            .map_err(classify_ensure_running_error)?;
    } else {
        crate::api::handlers::exec::require_running(entry).await?;
    }
    let machine_rec = state.lookup_vm(id).await?;
    let (env, workdir) = crate::api::handlers::machine_command_context(
        entry,
        machine_rec.as_ref(),
        &req.env,
        &req.secrets,
        req.workdir.clone(),
    )?;
    let machine_image = machine_rec.as_ref().and_then(|r| r.image.clone());
    let mounts_config = {
        let e = entry.lock();
        e.mounts
            .iter()
            .enumerate()
            .map(|(i, m)| (HostMount::mount_tag(i), m.target.clone(), m.readonly))
            .collect::<Vec<_>>()
    };

    let (in_tx, in_rx) = crate::agent::interactive_input(INPUT_QUEUE_EVENTS)
        .map_err(|e| ApiError::internal(format!("exec session input channel: {e}")))?;
    if req.tty {
        let _ = in_tx
            .send(crate::agent::InteractiveInput::Resize {
                cols: req.cols.unwrap_or(80),
                rows: req.rows.unwrap_or(24),
            })
            .await;
    }
    session.set_input(in_tx).await;

    let timeout = req.timeout_secs.map(Duration::from_secs);
    let plan = match machine_image {
        Some(image) => {
            let env_for_volumes = env.clone();
            Plan::Image(
                crate::agent::RunConfig::new(image, req.command.clone())
                    .with_env(env)
                    .with_workdir(workdir)
                    .with_user(req.user.clone())
                    .with_mounts(mounts_config)
                    .with_timeout(timeout)
                    .with_tty(req.tty)
                    .in_machine_opt(machine_rec.as_ref(), id, &env_for_volumes),
            )
        }
        None => Plan::Vm {
            command: req.command.clone(),
            env,
            workdir,
            timeout,
            tty: req.tty,
        },
    };
    let entry_owned = entry.clone();
    let started_rx = spawn_runner(
        session.clone(),
        move || {
            let entry = entry_owned.lock();
            let mut client = entry.manager.connect()?;
            if let Some(tid) = tid {
                client.set_trace_id(tid);
            }
            Ok(client)
        },
        plan,
        in_rx,
    );

    match started_rx.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(ApiError::internal("exec session ended before it started")),
    }

    // Input that came with the start, then (unless interactive) end of input.
    // In a task of its own: a command that reads its stdin slowly must not hold
    // up the start's answer. Sequenced frames wait behind it (same lock).
    {
        let session = session.clone();
        let stdin = req.stdin.map(String::into_bytes);
        tokio::spawn(async move { session.apply_initial_stdin(stdin).await });
    }

    // Backstop for a guest that never reports the end of a timed command.
    if let Some(timeout) = timeout {
        let session = session.clone();
        tokio::spawn(async move {
            tokio::time::sleep(timeout + HOST_DEADLINE_GRACE).await;
            if session.exit().is_none() {
                session
                    .kill_with(Exit {
                        code: Some(124),
                        error: Some(format!(
                            "command timed out after {} s (the machine did not report its end)",
                            timeout.as_secs()
                        )),
                    })
                    .await;
            }
        });
    }
    Ok(())
}

/// What a session runs.
enum Plan {
    /// A command in the VM itself.
    Vm {
        command: Vec<String>,
        env: Vec<(String, String)>,
        workdir: Option<String>,
        timeout: Option<Duration>,
        tty: bool,
    },
    /// A command in an image machine's container (the image is pulled first
    /// when the machine does not have it).
    Image(crate::agent::RunConfig),
}

/// Run a session's command in a task of its own, on the agent connection
/// `connect` opens. The receiver answers once the command runs, or with the
/// error that kept it from starting; the session records how it ended.
fn spawn_runner<C>(
    session: Arc<ExecSession>,
    connect: C,
    plan: Plan,
    input: crate::agent::InteractiveInputReceiver,
) -> tokio::sync::oneshot::Receiver<Result<(), ApiError>>
where
    C: FnOnce() -> crate::Result<crate::agent::AgentClient> + Send + 'static,
{
    let (started_tx, started_rx) = tokio::sync::oneshot::channel::<Result<(), ApiError>>();
    let started_tx = Arc::new(parking_lot::Mutex::new(Some(started_tx)));
    let on_start_tx = started_tx.clone();
    let run_session = session.clone();
    let start = std::time::Instant::now();
    tokio::spawn(async move {
        let result = tokio::task::spawn_blocking(move || -> crate::Result<i32> {
            let mut client = connect()?;
            let on_started = {
                let session = run_session.clone();
                move || {
                    session.mark_running();
                    if let Some(tx) = on_start_tx.lock().take() {
                        let _ = tx.send(Ok(()));
                    }
                }
            };
            let on_output = {
                let session = run_session.clone();
                move |o| {
                    let (stream, data) = output_of(o);
                    session.push_output(stream, data);
                }
            };
            match plan {
                Plan::Image(config) => {
                    if client.query(&config.image)?.is_none() {
                        client.pull_with_registry_config(&config.image)?;
                    }
                    client.run_session_io(config, input, on_started, on_output)
                }
                Plan::Vm {
                    command,
                    env,
                    workdir,
                    timeout,
                    tty,
                } => client.vm_exec_session_io(
                    command, env, workdir, timeout, tty, input, on_started, on_output,
                ),
            }
        })
        .await;
        metrics::histogram!("smolvm_exec_seconds").record(start.elapsed().as_secs_f64());
        let exit = match result {
            Ok(Ok(code)) => Exit {
                code: Some(code),
                error: None,
            },
            Ok(Err(e)) => {
                // Before the command ran, the error is the start's answer.
                if let Some(tx) = started_tx.lock().take() {
                    let _ = tx.send(Err(ApiError::from(e)));
                    session.finish(Exit {
                        code: None,
                        error: Some("the command did not start".into()),
                    });
                    return;
                }
                Exit {
                    code: None,
                    error: Some(format!("{e}")),
                }
            }
            Err(join) => Exit {
                code: None,
                error: Some(format!("exec session task failed: {join}")),
            },
        };
        if let Some(tx) = started_tx.lock().take() {
            let _ = tx.send(Err(ApiError::internal(
                exit.error
                    .clone()
                    .unwrap_or_else(|| "the command did not start".into()),
            )));
        }
        session.finish(exit);
    });
    started_rx
}

/// Read an exec session's output.
///
/// Returns the output after `after` (at most `max` bytes), waiting up to
/// `wait` seconds for some when there is none yet. `after` acknowledges every
/// byte before it. Read again with `after` = the answer's `next` until `done`.
#[utoipa::path(
    get,
    path = "/api/v1/machines/{id}/execs/{exec}",
    tag = "Execution",
    params(
        ("id" = String, Path, description = "Machine name"),
        ("exec" = String, Path, description = "Exec id"),
        ExecSessionReadQuery
    ),
    responses(
        (status = 200, description = "Output and state", body = ExecSessionResponse),
        (status = 400, description = "Offset beyond the end of the output", body = ApiErrorResponse),
        (status = 404, description = "No such exec on this machine", body = ApiErrorResponse)
    )
)]
pub async fn read_exec_session(
    State(state): State<Arc<ApiState>>,
    Path((id, exec)): Path<(String, String)>,
    Query(q): Query<ExecSessionReadQuery>,
) -> Result<Json<ExecSessionResponse>, ApiError> {
    let session = session_of(&state, &id, &exec)?;
    let batch = read_waiting(&session, q.after, q.wait, clamp_max(q.max)).await?;
    Ok(Json(response(&session, batch)))
}

/// List the exec sessions on a machine.
#[utoipa::path(
    get,
    path = "/api/v1/machines/{id}/execs",
    tag = "Execution",
    params(("id" = String, Path, description = "Machine name")),
    responses((status = 200, description = "Exec sessions", body = ListExecSessionsResponse))
)]
pub async fn list_exec_sessions(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
) -> Json<ListExecSessionsResponse> {
    Json(ListExecSessionsResponse {
        execs: state
            .exec_sessions()
            .list(&id)
            .iter()
            .map(|s| s.summary())
            .collect(),
    })
}

/// Write one sequenced stdin frame to an interactive exec session.
///
/// Answers with the last frame applied. A frame already applied is answered
/// without applying it again; a frame after a missing one is not applied, and
/// the answer's `stdinApplied` says where to resend from.
#[utoipa::path(
    post,
    path = "/api/v1/machines/{id}/execs/{exec}/stdin",
    tag = "Execution",
    params(
        ("id" = String, Path, description = "Machine name"),
        ("exec" = String, Path, description = "Exec id")
    ),
    request_body = ExecStdinRequest,
    responses(
        (status = 200, description = "The last frame applied", body = ExecStdinResponse),
        (status = 404, description = "No such exec on this machine", body = ApiErrorResponse),
        (status = 409, description = "Stdin is closed, or the session takes none", body = ApiErrorResponse),
        (status = 413, description = "Frame larger than 64 KiB", body = ApiErrorResponse),
        (status = 503, description = "The command did not take its input in time; nothing applied", body = ApiErrorResponse)
    )
)]
pub async fn exec_session_stdin(
    State(state): State<Arc<ApiState>>,
    Path((id, exec)): Path<(String, String)>,
    Json(req): Json<ExecStdinRequest>,
) -> Result<Json<ExecStdinResponse>, ApiError> {
    let session = session_of(&state, &id, &exec)?;
    match session.apply_stdin(req.seq, &req.data, req.eof).await {
        Ok(applied) | Err(StdinError::Gap { applied }) => Ok(Json(ExecStdinResponse {
            stdin_applied: applied,
        })),
        Err(e) => Err(stdin_error(e)),
    }
}

fn stdin_error(e: StdinError) -> ApiError {
    match e {
        StdinError::Closed { applied } => ApiError::Conflict(format!(
            "stdin is closed (last frame applied: {applied})"
        )),
        StdinError::Busy { applied } => ApiError::Unavailable(format!(
            "the command did not take its input within 30 s; nothing applied (last frame applied: {applied})"
        )),
        StdinError::TooLarge => ApiError::PayloadTooLarge(format!(
            "a stdin frame carries at most {MAX_STDIN_FRAME} bytes"
        )),
        StdinError::NotInteractive => {
            ApiError::Conflict("this exec takes no stdin (start it interactive)".into())
        }
        StdinError::Gap { applied } => ApiError::Conflict(format!(
            "a stdin frame is missing (last frame applied: {applied})"
        )),
    }
}

/// Resize an exec session's terminal.
#[utoipa::path(
    post,
    path = "/api/v1/machines/{id}/execs/{exec}/resize",
    tag = "Execution",
    params(
        ("id" = String, Path, description = "Machine name"),
        ("exec" = String, Path, description = "Exec id")
    ),
    request_body = ExecResizeRequest,
    responses(
        (status = 204, description = "Resized"),
        (status = 404, description = "No such exec on this machine", body = ApiErrorResponse),
        (status = 409, description = "The session has no terminal, or ended", body = ApiErrorResponse)
    )
)]
pub async fn resize_exec_session(
    State(state): State<Arc<ApiState>>,
    Path((id, exec)): Path<(String, String)>,
    Json(req): Json<ExecResizeRequest>,
) -> Result<StatusCode, ApiError> {
    let session = session_of(&state, &id, &exec)?;
    if session.resize(req.cols, req.rows).await {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::Conflict(
            "this exec has no terminal, or it ended".into(),
        ))
    }
}

/// Kill an exec session's command if it runs, and forget the session.
#[utoipa::path(
    delete,
    path = "/api/v1/machines/{id}/execs/{exec}",
    tag = "Execution",
    params(
        ("id" = String, Path, description = "Machine name"),
        ("exec" = String, Path, description = "Exec id")
    ),
    responses(
        (status = 204, description = "Deleted"),
        (status = 404, description = "No such exec on this machine", body = ApiErrorResponse)
    )
)]
pub async fn delete_exec_session(
    State(state): State<Arc<ApiState>>,
    Path((id, exec)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    if state.exec_sessions().remove(&id, &exec).await {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(not_found(&id, &exec))
    }
}

/// Query for attaching to an exec session.
#[derive(Debug, Default, serde::Deserialize)]
pub struct AttachQuery {
    /// Resume output from this offset (and acknowledge what precedes it).
    #[serde(default)]
    pub after: u64,
}

/// Attach to an exec session over a WebSocket (see the module docs).
pub async fn attach_exec_session(
    State(state): State<Arc<ApiState>>,
    Path((id, exec)): Path<(String, String)>,
    Query(q): Query<AttachQuery>,
    ws: WebSocketUpgrade,
) -> Result<axum::response::Response, ApiError> {
    let session = session_of(&state, &id, &exec)?;
    session
        .read(q.after, 0, false)
        .map_err(|end| beyond_end(q.after, end))?;
    session.ack(q.after);
    Ok(ws.on_upgrade(move |socket| attach(socket, session, q.after)))
}

fn text(v: serde_json::Value) -> Message {
    Message::Text(v.to_string().into())
}

fn output_frame(stream: u8, offset: u64, data: &[u8]) -> Message {
    let mut frame = Vec::with_capacity(9 + data.len());
    frame.push(stream);
    frame.extend_from_slice(&offset.to_be_bytes());
    frame.extend_from_slice(data);
    Message::Binary(frame.into())
}

async fn attach(socket: WebSocket, session: Arc<ExecSession>, after: u64) {
    let _attached = session.attach();
    let (mut ws_tx, mut ws_rx) = socket.split();
    // One writer: the output pump and the stdin acknowledgements share it.
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<Message>(16);
    let writer = tokio::spawn(async move {
        while let Some(msg) = out_rx.recv().await {
            let close = matches!(msg, Message::Close(_));
            if ws_tx.send(msg).await.is_err() || close {
                break;
            }
        }
        let _ = ws_tx.close().await;
    });

    let hello = match session.read(after, 0, false) {
        Ok(b) => b,
        Err(_) => return,
    };
    let _ = out_tx
        .send(text(serde_json::json!({
            "type": "hello",
            "execId": session.id,
            "next": after.max(hello.start),
            "start": hello.start,
            "end": hello.end,
            "stdinApplied": hello.stdin_applied,
            "state": format!("{:?}", hello.state).to_lowercase(),
            "tty": session.tty,
        })))
        .await;

    let pump = {
        let session = session.clone();
        let out_tx = out_tx.clone();
        async move {
            let mut pos = after;
            loop {
                let batch = match session.read(pos, ATTACH_READ_BYTES, false) {
                    Ok(b) => b,
                    Err(_) => return,
                };
                if let Some((from, to)) = batch.lost {
                    if out_tx
                        .send(text(
                            serde_json::json!({"type": "lost", "from": from, "to": to}),
                        ))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                for piece in &batch.output {
                    if out_tx
                        .send(output_frame(piece.stream.tag(), piece.offset, &piece.data))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                pos = batch.next;
                if batch.done {
                    let exit = batch.exit.unwrap_or(Exit {
                        code: None,
                        error: None,
                    });
                    let _ = out_tx
                        .send(text(serde_json::json!({
                            "type": "exit",
                            "exitCode": exit.code,
                            "error": exit.error,
                        })))
                        .await;
                    let _ = out_tx.send(Message::Close(None)).await;
                    return;
                }
                if batch.output.is_empty() {
                    session.wait_for_output(pos, Duration::from_secs(30)).await;
                }
            }
        }
    };

    let input = {
        let session = session.clone();
        let out_tx = out_tx.clone();
        async move {
            while let Some(Ok(msg)) = ws_rx.next().await {
                match msg {
                    Message::Binary(b) => {
                        if b.len() < 8 {
                            continue;
                        }
                        let seq = u64::from_be_bytes(b[..8].try_into().unwrap_or([0; 8]));
                        let reply = match session.apply_stdin(seq, &b[8..], false).await {
                            Ok(applied) | Err(StdinError::Gap { applied }) => {
                                serde_json::json!({"type": "stdin", "applied": applied})
                            }
                            Err(e) => serde_json::json!({
                                "type": "error",
                                "message": format!("{:?}", stdin_error(e)),
                            }),
                        };
                        if out_tx.send(text(reply)).await.is_err() {
                            return;
                        }
                    }
                    Message::Text(t) => {
                        let Ok(v) = serde_json::from_str::<serde_json::Value>(t.as_str()) else {
                            continue;
                        };
                        match v["type"].as_str() {
                            Some("ack") => {
                                if let Some(offset) = v["offset"].as_u64() {
                                    session.ack(offset);
                                }
                            }
                            Some("resize") => {
                                let cols = v["cols"].as_u64().unwrap_or(80) as u16;
                                let rows = v["rows"].as_u64().unwrap_or(24) as u16;
                                session.resize(cols, rows).await;
                            }
                            Some("eof") => {
                                let seq = v["seq"].as_u64().unwrap_or(0);
                                let reply = match session.apply_stdin(seq, &[], true).await {
                                    Ok(applied) | Err(StdinError::Gap { applied }) => {
                                        serde_json::json!({"type": "stdin", "applied": applied})
                                    }
                                    Err(e) => serde_json::json!({
                                        "type": "error",
                                        "message": format!("{:?}", stdin_error(e)),
                                    }),
                                };
                                if out_tx.send(text(reply)).await.is_err() {
                                    return;
                                }
                            }
                            Some("terminate") => {
                                session.kill("terminated by the client").await;
                            }
                            _ => {}
                        }
                    }
                    Message::Close(_) => return,
                    _ => {}
                }
            }
        }
    };

    // The pump ends at the exit (or a dead socket); the input loop when the
    // client goes. Either ends the attachment; the command itself goes on
    // unless it ended or was terminated.
    tokio::select! {
        _ = pump => {
            // Let the client's last acknowledgements and the close land.
            drop(out_tx);
            let _ = tokio::time::timeout(Duration::from_secs(5), writer).await;
        }
        _ = input => {
            drop(out_tx);
            let _ = tokio::time::timeout(Duration::from_secs(1), writer).await;
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    //! Sessions end to end but for the VM: the session runner, the agent
    //! client's session loop, and a stand-in guest running real processes.
    use super::*;
    use crate::agent::{test_guest::FakeGuest, AgentClient};
    use crate::api::exec_sessions::{ExecSessions, Limits, SessionState};
    use crate::platform::uds::UdsStream;
    use tokio_tungstenite::tungstenite::Message as Wire;

    async fn start(
        reg: &ExecSessions,
        id: &str,
        command: &[&str],
        interactive: bool,
        stdin: Option<&str>,
    ) -> (Arc<ExecSession>, FakeGuest) {
        let command: Vec<String> = command.iter().map(|s| s.to_string()).collect();
        let (session, new) = reg
            .register("m", id, command.clone(), false, interactive, 1)
            .unwrap();
        assert!(new);
        let (in_tx, in_rx) = crate::agent::interactive_input(INPUT_QUEUE_EVENTS).unwrap();
        session.set_input(in_tx).await;
        let (client_stream, guest_stream) = UdsStream::pair().unwrap();
        let guest = FakeGuest::spawn(guest_stream);
        let started = spawn_runner(
            session.clone(),
            move || Ok(AgentClient::from_stream(client_stream)),
            Plan::Vm {
                command,
                env: Vec::new(),
                workdir: None,
                timeout: None,
                tty: false,
            },
            in_rx,
        );
        started.await.unwrap().unwrap();
        let s = session.clone();
        let stdin = stdin.map(|s| s.as_bytes().to_vec());
        tokio::spawn(async move { s.apply_initial_stdin(stdin).await });
        (session, guest)
    }

    /// Poll like a client: advance to `next` until done.
    async fn drain(session: &ExecSession, mut after: u64) -> (Vec<u8>, Vec<u8>, Batch) {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        loop {
            let b = read_waiting(session, after, Some(5), 1024).await.unwrap();
            assert!(b.lost.is_none());
            for p in &b.output {
                match p.stream {
                    crate::api::exec_sessions::OutputStream::Stdout => {
                        out.extend_from_slice(&p.data)
                    }
                    crate::api::exec_sessions::OutputStream::Stderr => {
                        err.extend_from_slice(&p.data)
                    }
                }
            }
            after = b.next;
            if b.done {
                return (out, err, b);
            }
        }
    }

    #[tokio::test]
    async fn a_session_runs_to_its_exit_and_keeps_stdout_and_stderr_apart() {
        let reg = ExecSessions::with_limits(Limits::default());
        let (session, guest) = start(
            &reg,
            "exec-plain1",
            &[
                "sh",
                "-c",
                "head -c 100000 /dev/zero | tr '\\0' o; echo e >&2; exit 7",
            ],
            false,
            None,
        )
        .await;
        let (out, err, last) = drain(&session, 0).await;
        assert_eq!(out.len(), 100_000);
        assert!(out.iter().all(|&b| b == b'o'));
        assert_eq!(err, b"e\n");
        assert_eq!(last.exit.unwrap().code, Some(7));
        tokio::task::spawn_blocking(move || guest.finish())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn stdin_given_at_the_start_is_written_and_closed() {
        let reg = ExecSessions::with_limits(Limits::default());
        let (session, guest) = start(
            &reg,
            "exec-stdin1",
            &["sh", "-c", "wc -c"],
            false,
            Some("hello"),
        )
        .await;
        let (out, _, last) = drain(&session, 0).await;
        assert_eq!(String::from_utf8_lossy(&out).trim(), "5");
        assert_eq!(last.exit.unwrap().code, Some(0));
        tokio::task::spawn_blocking(move || guest.finish())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn resent_stdin_frames_reach_the_command_once() {
        let reg = ExecSessions::with_limits(Limits::default());
        let (session, guest) = start(&reg, "exec-cat0001", &["cat"], true, None).await;
        assert_eq!(session.apply_stdin(1, b"one ", false).await, Ok(1));
        assert_eq!(session.apply_stdin(1, b"one ", false).await, Ok(1));
        assert_eq!(session.apply_stdin(2, b"two", false).await, Ok(2));
        assert_eq!(session.apply_stdin(2, b"two", false).await, Ok(2));
        assert_eq!(session.apply_stdin(3, b"", true).await, Ok(3));
        let (out, _, last) = drain(&session, 0).await;
        assert_eq!(out, b"one two");
        assert_eq!(last.exit.unwrap().code, Some(0));
        tokio::task::spawn_blocking(move || guest.finish())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_killed_session_ends_with_the_reason() {
        let reg = ExecSessions::with_limits(Limits::default());
        let (session, guest) = start(&reg, "exec-sleep01", &["sleep", "30"], false, None).await;
        assert_eq!(session.state(), SessionState::Running);
        session.kill("deleted").await;
        let (_, _, last) = drain(&session, 0).await;
        assert_eq!(last.exit.unwrap().error.as_deref(), Some("deleted"));
        tokio::task::spawn_blocking(move || guest.finish())
            .await
            .unwrap();
    }

    /// A WebSocket attach dropped mid-session and resumed from the client's
    /// offset: every byte once, stdin resent across the switch applied once.
    #[tokio::test]
    async fn an_attach_resumed_after_a_drop_loses_and_repeats_nothing() {
        use axum::extract::ws::WebSocketUpgrade;
        use axum::{routing::get, Router};
        let reg = ExecSessions::with_limits(Limits::default());
        let (session, guest) = start(&reg, "exec-attach1", &["cat"], true, None).await;

        let app = {
            let session = session.clone();
            Router::new().route(
                "/attach",
                get(move |Query(q): Query<AttachQuery>, ws: WebSocketUpgrade| {
                    let session = session.clone();
                    async move { ws.on_upgrade(move |socket| attach(socket, session, q.after)) }
                }),
            )
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let stdin_frame = |seq: u64, data: &[u8]| {
            let mut f = seq.to_be_bytes().to_vec();
            f.extend_from_slice(data);
            Wire::Binary(f.into())
        };
        // Reads until `want` output bytes arrived; returns (bytes, next offset).
        async fn read_output<S>(
            ws: &mut S,
            mut next: u64,
            want: usize,
        ) -> (Vec<u8>, u64, Option<serde_json::Value>)
        where
            S: futures_util::Stream<Item = Result<Wire, tokio_tungstenite::tungstenite::Error>>
                + futures_util::Sink<Wire>
                + Unpin,
        {
            let mut got = Vec::new();
            loop {
                if got.len() >= want {
                    return (got, next, None);
                }
                let msg = tokio::time::timeout(Duration::from_secs(10), ws.next())
                    .await
                    .expect("output in time")
                    .expect("socket open")
                    .unwrap();
                match msg {
                    Wire::Binary(b) => {
                        let offset = u64::from_be_bytes(b[1..9].try_into().unwrap());
                        assert_eq!(offset, next, "output arrives in order, without gaps");
                        got.extend_from_slice(&b[9..]);
                        next += (b.len() - 9) as u64;
                        let _ = ws
                            .send(Wire::Text(
                                serde_json::json!({"type": "ack", "offset": next})
                                    .to_string()
                                    .into(),
                            ))
                            .await;
                    }
                    Wire::Text(t) => {
                        let v: serde_json::Value = serde_json::from_str(t.as_str()).unwrap();
                        if v["type"] == "exit" {
                            return (got, next, Some(v));
                        }
                    }
                    _ => {}
                }
            }
        }

        let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/attach?after=0"))
            .await
            .unwrap();
        ws.send(stdin_frame(1, b"alpha ")).await.unwrap();
        let (first, next, _) = read_output(&mut ws, 0, 6).await;
        assert_eq!(first, b"alpha ");
        // Frame 2 is sent, then the connection drops before its ack is seen.
        ws.send(stdin_frame(2, b"beta ")).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        drop(ws);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            session.state(),
            SessionState::Running,
            "a dropped attach only detaches"
        );

        let (mut ws, _) =
            tokio_tungstenite::connect_async(format!("ws://{addr}/attach?after={next}"))
                .await
                .unwrap();
        // The hello says which frames were applied; the client resends after it.
        let hello = loop {
            if let Some(Ok(Wire::Text(t))) = ws.next().await {
                let v: serde_json::Value = serde_json::from_str(t.as_str()).unwrap();
                if v["type"] == "hello" {
                    break v;
                }
            }
        };
        let applied = hello["stdinApplied"].as_u64().unwrap();
        assert!(applied >= 1);
        for (seq, data) in [(2u64, &b"beta "[..]), (3, &b"gamma"[..])] {
            if seq > applied {
                ws.send(stdin_frame(seq, data)).await.unwrap();
            }
        }
        // Resending an applied frame anyway changes nothing.
        ws.send(stdin_frame(2, b"beta ")).await.unwrap();
        ws.send(Wire::Text(
            serde_json::json!({"type": "eof", "seq": 4})
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
        let (rest, _, exit) = read_output(&mut ws, next, usize::MAX).await;
        assert_eq!([first, rest].concat(), b"alpha beta gamma");
        assert_eq!(exit.unwrap()["exitCode"], 0);
        tokio::task::spawn_blocking(move || guest.finish())
            .await
            .unwrap();
    }
}
