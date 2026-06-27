//! Command execution handlers.

use axum::{
    extract::{
        ws::{Message, WebSocketUpgrade},
        Path, Query, State,
    },
    response::sse::{Event, KeepAlive, Sse},
    Json,
};
use futures_util::{SinkExt, StreamExt};
use std::convert::Infallible;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::api::error::{classify_ensure_running_error, ApiError};
use crate::api::state::{ensure_running_and_persist, with_machine_client_traced, ApiState};
use crate::api::types::{
    ApiErrorResponse, EnvVar, ExecRequest, ExecResponse, LogsQuery, RunRequest,
};
use crate::api::validate_command;
use crate::api::TraceId;
use crate::data::consts::BYTES_PER_MIB;
use crate::data::storage::HostMount;
use tokio::sync::Semaphore;

/// Execute a command in a machine.
///
/// This executes directly in the VM (not in a container).
#[utoipa::path(
    post,
    path = "/api/v1/machines/{id}/exec",
    tag = "Execution",
    params(
        ("id" = String, Path, description = "Machine name")
    ),
    request_body = ExecRequest,
    responses(
        (status = 200, description = "Command executed", body = ExecResponse),
        (status = 400, description = "Invalid request", body = ApiErrorResponse),
        (status = 404, description = "Machine not found", body = ApiErrorResponse),
        (status = 500, description = "Execution failed", body = ApiErrorResponse)
    )
)]
pub async fn exec_command(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
    trace_id: Option<axum::Extension<TraceId>>,
    Json(req): Json<ExecRequest>,
) -> Result<Json<ExecResponse>, ApiError> {
    let tid = trace_id.map(|t| t.0 .0.clone());
    validate_command(&req.command)?;

    let entry = state.get_machine(&id)?;

    // Ensure machine is running and persist state to DB
    ensure_running_and_persist(&state, &id, &entry)
        .await
        .map_err(classify_ensure_running_error)?;

    // Resolve secrets ONCE, before the background/foreground split, so a
    // detached workload gets them too (a long-lived daemon usually needs its
    // credentials more than a one-shot exec does). Env precedence (low → high):
    // req.env (caller-plaintext) → record.secret_refs (persisted by a
    // TrustedLocal actor) → req.secrets (ad-hoc, Untrusted). Validation runs
    // before resolution so structural/scope violations surface as 400 without
    // the resolution audit firing.
    crate::api::handlers::validate_request_secrets(&req.secrets)?;
    let record_env = crate::api::handlers::record_secret_refs_env(&entry)?;
    let req_env = crate::api::handlers::resolve_request_secrets(&req.secrets)?;
    let mut env = EnvVar::to_tuples(&req.env);
    env.extend(crate::secrets::expose_into_env(record_env));
    env.extend(crate::secrets::expose_into_env(req_env));

    // Detached/background: spawn the process and return its PID immediately, so a
    // long-lived daemon (dev server, agent runner) keeps running after the
    // request returns. Image machines run it in their container (persistent
    // overlay); plain machines run it in the VM.
    if req.background {
        let command = req.command.clone();
        let workdir = req.workdir.clone();
        let machine_image = state.lookup_vm(&id).await?.and_then(|r| r.image);
        let pid = if let Some(image) = machine_image {
            let mounts_config = {
                let e = entry.lock();
                e.mounts
                    .iter()
                    .enumerate()
                    .map(|(i, m)| (HostMount::mount_tag(i), m.target.clone(), m.readonly))
                    .collect::<Vec<_>>()
            };
            let overlay_id = id.clone();
            with_machine_client_traced(&entry, tid, move |c| {
                if c.query(&image)?.is_none() {
                    c.pull_with_registry_config(&image)?;
                }
                let config = crate::agent::RunConfig::new(image, command)
                    .with_env(env)
                    .with_workdir(workdir)
                    .with_mounts(mounts_config)
                    .with_persistent_overlay(Some(overlay_id));
                c.run_background(config)
            })
            .await?
        } else {
            with_machine_client_traced(&entry, tid, move |c| {
                c.vm_exec_background(command, env, workdir)
            })
            .await?
        };
        return Ok(Json(ExecResponse {
            exit_code: 0,
            stdout: format!("pid={pid}\n"),
            stderr: String::new(),
        }));
    }

    // Secrets already resolved into `env` above (shared with the background
    // path); env precedence is req.env < record.secret_refs < req.secrets.
    let command = req.command.clone();
    let workdir = req.workdir.clone();
    let timeout = req.timeout_secs.map(Duration::from_secs);
    let stdin_data = req.stdin.clone();

    // Image-based machines exec INSIDE a container from their image, with a
    // per-machine persistent overlay so filesystem changes persist across exec
    // sessions. Without this, exec runs in the bare agent VM (no `python3`,
    // etc.) — the image is never entered. Plain machines exec in the VM
    // directly via `vm_exec`.
    let machine_image = state.lookup_vm(&id).await?.and_then(|r| r.image);

    let start = std::time::Instant::now();
    let (exit_code, stdout, stderr) = if let Some(image) = machine_image {
        let mounts_config = {
            let e = entry.lock();
            e.mounts
                .iter()
                .enumerate()
                .map(|(i, m)| (HostMount::mount_tag(i), m.target.clone(), m.readonly))
                .collect::<Vec<_>>()
        };
        let overlay_id = id.clone();
        let stdin_data = stdin_data.clone();
        with_machine_client_traced(&entry, tid, move |c| {
            // Pull only if the image isn't already present — avoids a registry
            // round-trip on every exec, and works once cached even on
            // network-restricted machines.
            if c.query(&image)?.is_none() {
                c.pull_with_registry_config(&image)?;
            }
            let config = crate::agent::RunConfig::new(image, command)
                .with_env(env)
                .with_workdir(workdir)
                .with_mounts(mounts_config)
                .with_timeout(timeout)
                .with_persistent_overlay(Some(overlay_id))
                .with_stdin(stdin_data);
            c.run_non_interactive(config)
        })
        .await?
    } else {
        with_machine_client_traced(&entry, tid, move |c| {
            c.vm_exec(command, env, workdir, timeout, stdin_data)
        })
        .await?
    };
    metrics::histogram!("smolvm_exec_seconds").record(start.elapsed().as_secs_f64());

    Ok(Json(ExecResponse {
        exit_code,
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
    }))
}

/// Execute a command with streaming output (Server-Sent Events).
///
/// Returns real-time stdout/stderr as SSE events. Useful for long-running
/// commands where buffering the entire output is impractical.
#[utoipa::path(
    post,
    path = "/api/v1/machines/{id}/exec/stream",
    tag = "Execution",
    params(
        ("id" = String, Path, description = "Machine name")
    ),
    request_body = ExecRequest,
    responses(
        (status = 200, description = "Streaming output (SSE)", content_type = "text/event-stream"),
        (status = 404, description = "Machine not found", body = ApiErrorResponse),
        (status = 500, description = "Execution failed", body = ApiErrorResponse)
    )
)]
pub async fn exec_stream(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
    trace_id: Option<axum::Extension<TraceId>>,
    Json(req): Json<ExecRequest>,
) -> Result<Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>>, ApiError> {
    let tid = trace_id.map(|t| t.0 .0.clone());
    validate_command(&req.command)?;

    let entry = state.get_machine(&id)?;
    ensure_running_and_persist(&state, &id, &entry)
        .await
        .map_err(classify_ensure_running_error)?;

    crate::api::handlers::validate_request_secrets(&req.secrets)?;
    let record_env = crate::api::handlers::record_secret_refs_env(&entry)?;
    let req_env = crate::api::handlers::resolve_request_secrets(&req.secrets)?;

    let command = req.command.clone();
    let mut env = EnvVar::to_tuples(&req.env);
    env.extend(crate::secrets::expose_into_env(record_env));
    env.extend(crate::secrets::expose_into_env(req_env));
    let workdir = req.workdir.clone();
    let timeout = req.timeout_secs.map(Duration::from_secs);

    // Image-based machines stream from a container in their image (persistent
    // overlay keyed by machine name); plain machines stream from the VM
    // directly. Without this, streaming exec on an image machine produces no
    // output (the agent-base streaming path doesn't enter the container).
    let machine_image = state.lookup_vm(&id).await?.and_then(|r| r.image);

    // Run streaming exec via the machine client (vsock is synchronous)
    let start = std::time::Instant::now();
    let events = if let Some(image) = machine_image {
        let mounts_config = {
            let e = entry.lock();
            e.mounts
                .iter()
                .enumerate()
                .map(|(i, m)| (HostMount::mount_tag(i), m.target.clone(), m.readonly))
                .collect::<Vec<_>>()
        };
        let overlay_id = id.clone();
        with_machine_client_traced(&entry, tid, move |c| {
            if c.query(&image)?.is_none() {
                c.pull_with_registry_config(&image)?;
            }
            let config = crate::agent::RunConfig::new(image, command)
                .with_env(env)
                .with_workdir(workdir)
                .with_mounts(mounts_config)
                .with_timeout(timeout)
                .with_persistent_overlay(Some(overlay_id));
            let mut evs = Vec::new();
            c.run_streaming_with(config, |e| evs.push(e))?;
            Ok(evs)
        })
        .await?
    } else {
        with_machine_client_traced(&entry, tid, move |c| {
            c.vm_exec_streaming(command, env, workdir, timeout)
        })
        .await?
    };
    metrics::histogram!("smolvm_exec_seconds").record(start.elapsed().as_secs_f64());

    // Convert events to SSE stream
    let stream = futures_util::stream::iter(events.into_iter().map(|event| {
        let sse_event = match event {
            crate::agent::ExecEvent::Stdout(data) => Event::default()
                .event("stdout")
                .data(String::from_utf8_lossy(&data)),
            crate::agent::ExecEvent::Stderr(data) => Event::default()
                .event("stderr")
                .data(String::from_utf8_lossy(&data)),
            crate::agent::ExecEvent::Exit(code) => Event::default()
                .event("exit")
                .data(format!("{{\"exitCode\":{}}}", code)),
            crate::agent::ExecEvent::Error(msg) => Event::default()
                .event("error")
                .data(format!("{{\"message\":\"{}\"}}", msg)),
        };
        Ok(sse_event)
    }));

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

/// Run a command in an image.
///
/// This creates a temporary overlay from the image and runs the command.
#[utoipa::path(
    post,
    path = "/api/v1/machines/{id}/run",
    tag = "Execution",
    params(
        ("id" = String, Path, description = "Machine name")
    ),
    request_body = RunRequest,
    responses(
        (status = 200, description = "Command executed", body = ExecResponse),
        (status = 400, description = "Invalid request", body = ApiErrorResponse),
        (status = 404, description = "Machine not found", body = ApiErrorResponse),
        (status = 500, description = "Execution failed", body = ApiErrorResponse)
    )
)]
pub async fn run_command(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
    trace_id: Option<axum::Extension<TraceId>>,
    Json(req): Json<RunRequest>,
) -> Result<Json<ExecResponse>, ApiError> {
    let tid = trace_id.map(|t| t.0 .0.clone());
    validate_command(&req.command)?;

    let entry = state.get_machine(&id)?;

    // Ensure machine is running and persist state to DB
    ensure_running_and_persist(&state, &id, &entry)
        .await
        .map_err(classify_ensure_running_error)?;

    crate::api::handlers::validate_request_secrets(&req.secrets)?;
    let record_env = crate::api::handlers::record_secret_refs_env(&entry)?;
    let req_env = crate::api::handlers::resolve_request_secrets(&req.secrets)?;

    let image = req.image.clone();
    let command = req.command.clone();
    let mut env = EnvVar::to_tuples(&req.env);
    env.extend(crate::secrets::expose_into_env(record_env));
    env.extend(crate::secrets::expose_into_env(req_env));
    let workdir = req.workdir.clone();
    let timeout = req.timeout_secs.map(Duration::from_secs);

    // Get mounts from machine config (converted to protocol format)
    let mounts_config = {
        let entry = entry.lock();
        entry
            .mounts
            .iter()
            .enumerate()
            .map(|(i, m)| {
                let tag = HostMount::mount_tag(i);
                (tag, m.target.clone(), m.readonly)
            })
            .collect::<Vec<_>>()
    };

    let start = std::time::Instant::now();
    let (exit_code, stdout, stderr) = with_machine_client_traced(&entry, tid, move |c| {
        let config = crate::agent::RunConfig::new(image, command)
            .with_env(env)
            .with_workdir(workdir)
            .with_mounts(mounts_config)
            .with_timeout(timeout);
        c.run_non_interactive(config)
    })
    .await?;
    metrics::histogram!("smolvm_exec_seconds").record(start.elapsed().as_secs_f64());

    Ok(Json(ExecResponse {
        exit_code,
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
    }))
}

/// Query parameters for an interactive PTY session.
#[derive(Debug, serde::Deserialize)]
pub struct InteractiveQuery {
    /// Program to run (single argv[0]); defaults to `/bin/sh`.
    pub cmd: Option<String>,
    /// Initial terminal width in columns.
    pub cols: Option<u16>,
    /// Initial terminal height in rows.
    pub rows: Option<u16>,
}

/// Interactive PTY session over a WebSocket.
///
/// The client connects a WebSocket; binary frames are forwarded to the
/// command's stdin and the PTY's output is sent back as binary frames. A JSON
/// text frame `{"type":"resize","cols":N,"rows":N}` resizes the terminal. When
/// the command exits, a final text frame `{"type":"exit","code":N}` is sent
/// before the socket closes.
///
/// Image machines run the program in their persistent-overlay container (the
/// same filesystem `exec` uses); plain machines run it directly in the VM.
pub async fn exec_interactive(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
    Query(q): Query<InteractiveQuery>,
    _trace_id: Option<axum::Extension<TraceId>>,
    ws: WebSocketUpgrade,
) -> Result<axum::response::Response, ApiError> {
    let entry = state.get_machine(&id)?;
    ensure_running_and_persist(&state, &id, &entry)
        .await
        .map_err(classify_ensure_running_error)?;

    let machine_image = state.lookup_vm(&id).await?.and_then(|r| r.image);

    let command = vec![q.cmd.clone().unwrap_or_else(|| "/bin/sh".to_string())];
    let init_size = (q.cols.unwrap_or(80), q.rows.unwrap_or(24));

    // Snapshot mounts now (used only for image runs) so the upgrade closure
    // doesn't need to re-lock the entry.
    let mounts_config = {
        let e = entry.lock();
        e.mounts
            .iter()
            .enumerate()
            .map(|(i, m)| (HostMount::mount_tag(i), m.target.clone(), m.readonly))
            .collect::<Vec<_>>()
    };

    Ok(ws.on_upgrade(move |socket| async move {
        let (mut ws_tx, mut ws_rx) = socket.split();

        // Input channel: WS task → blocking session (sync mpsc; session try_recv's it).
        let (in_tx, in_rx) = std::sync::mpsc::channel::<crate::agent::InteractiveInput>();
        // Output channel: blocking session → WS task (tokio mpsc; blocking_send from session).
        let (out_tx, mut out_rx) =
            tokio::sync::mpsc::channel::<crate::agent::InteractiveOutput>(256);

        // Seed the initial PTY size before any input.
        let _ = in_tx.send(crate::agent::InteractiveInput::Resize {
            cols: init_size.0,
            rows: init_size.1,
        });

        // Run the interactive session on a DEDICATED agent connection — NOT the
        // shared per-machine client. A PTY can outlive its usefulness (a client
        // that disconnects while a `sleep` or daemon keeps running), and holding
        // the shared client lock for the whole session would block every other
        // operation on that machine until the command exits. A fresh connection
        // also lets the agent kill the PTY child the moment we drop it on
        // disconnect. We lock the entry only briefly, to dial.
        let session_entry = entry.clone();
        let session = tokio::spawn(async move {
            let connect = { session_entry.lock().manager.connect() };
            let mut client = match connect {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(error = ?e, "pty: failed to open dedicated agent connection");
                    return -1;
                }
            };
            tokio::task::spawn_blocking(move || {
                let on_output = move |o| {
                    // If the WS side is gone, the receiver is dropped; ignore.
                    let _ = out_tx.blocking_send(o);
                };
                if let Some(image) = machine_image {
                    match client.query(&image) {
                        Ok(Some(_)) => {}
                        Ok(None) => {
                            if let Err(e) = client.pull_with_registry_config(&image) {
                                tracing::warn!(error = ?e, "pty: image pull failed");
                                return -1;
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = ?e, "pty: image query failed");
                            return -1;
                        }
                    }
                    let config = crate::agent::RunConfig::new(image, command)
                        .with_mounts(mounts_config)
                        .with_tty(true)
                        .with_persistent_overlay(Some(id));
                    client
                        .run_interactive_io(config, in_rx, on_output)
                        .unwrap_or_else(|e| {
                            tracing::warn!(error = ?e, "pty: interactive run failed");
                            -1
                        })
                } else {
                    client
                        .vm_exec_interactive_io(command, Vec::new(), None, true, in_rx, on_output)
                        .unwrap_or_else(|e| {
                            tracing::warn!(error = ?e, "pty: interactive vm_exec failed");
                            -1
                        })
                }
            })
            .await
            .unwrap_or(-1)
        });

        // Pump WS → session input. Dropping `in_tx` (when this task ends) signals
        // EOF to the session via channel disconnect.
        let input_pump = tokio::spawn(async move {
            while let Some(Ok(msg)) = ws_rx.next().await {
                match msg {
                    Message::Binary(b)
                        if in_tx
                            .send(crate::agent::InteractiveInput::Stdin(b.to_vec()))
                            .is_err() =>
                    {
                        break;
                    }
                    Message::Binary(_) => {}
                    Message::Text(t) => {
                        // Control frames are JSON; anything else is treated as raw stdin.
                        match serde_json::from_str::<serde_json::Value>(t.as_str()) {
                            Ok(v) if v["type"] == "resize" => {
                                let cols = v["cols"].as_u64().unwrap_or(80) as u16;
                                let rows = v["rows"].as_u64().unwrap_or(24) as u16;
                                let _ = in_tx
                                    .send(crate::agent::InteractiveInput::Resize { cols, rows });
                            }
                            Ok(v) if v["type"] == "stdin" => {
                                if let Some(d) = v["data"].as_str() {
                                    let _ = in_tx.send(crate::agent::InteractiveInput::Stdin(
                                        d.as_bytes().to_vec(),
                                    ));
                                }
                            }
                            _ => {
                                let _ = in_tx.send(crate::agent::InteractiveInput::Stdin(
                                    t.as_bytes().to_vec(),
                                ));
                            }
                        }
                    }
                    Message::Close(_) => {
                        let _ = in_tx.send(crate::agent::InteractiveInput::Eof);
                        break;
                    }
                    _ => {}
                }
            }
        });

        // Pump session output → WS. Ends when the session drops `out_tx` (command exit).
        while let Some(o) = out_rx.recv().await {
            let bytes = match o {
                crate::agent::InteractiveOutput::Stdout(d)
                | crate::agent::InteractiveOutput::Stderr(d) => d,
            };
            if ws_tx.send(Message::Binary(bytes.into())).await.is_err() {
                break;
            }
        }

        // Report the exit code and close. The session task returns the command's
        // exit code (or a sentinel: -1 on internal error, 130 on disconnect).
        let code = session.await.unwrap_or(-1);
        let _ = ws_tx
            .send(Message::Text(
                format!("{{\"type\":\"exit\",\"code\":{code}}}").into(),
            ))
            .await;
        let _ = ws_tx.send(Message::Close(None)).await;
        input_pump.abort();
    }))
}

/// Maximum number of concurrent log-follow SSE streams.
/// Each follower polls via `spawn_blocking` every 100ms, so capping concurrency
/// prevents blocking-pool saturation under high follower counts.
static LOG_FOLLOW_SEMAPHORE: std::sync::LazyLock<Semaphore> =
    std::sync::LazyLock::new(|| Semaphore::new(16));

/// Stream machine console logs via SSE.
#[utoipa::path(
    get,
    path = "/api/v1/machines/{id}/logs",
    tag = "Logs",
    params(
        ("id" = String, Path, description = "Machine name"),
        ("follow" = Option<bool>, Query, description = "Follow the logs (like tail -f)"),
        ("tail" = Option<usize>, Query, description = "Number of lines to show from the end")
    ),
    responses(
        (status = 200, description = "Log stream (SSE)", content_type = "text/event-stream"),
        (status = 404, description = "Machine or log file not found", body = ApiErrorResponse)
    )
)]
pub async fn stream_logs(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
    Query(query): Query<LogsQuery>,
) -> Result<Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>>, ApiError> {
    let entry = state.get_machine(&id)?;

    // Get console log path
    let log_path: PathBuf = {
        let entry = entry.lock();
        entry
            .manager
            .console_log()
            .ok_or_else(|| ApiError::NotFound("console log not configured".into()))?
            .to_path_buf()
    };

    // Check if file exists (blocking check is acceptable here since it's fast)
    let path_check = log_path.clone();
    let exists = tokio::task::spawn_blocking(move || path_check.exists())
        .await
        .map_err(ApiError::internal)?;

    if !exists {
        return Err(ApiError::NotFound(format!(
            "log file not found: {}",
            log_path.display()
        )));
    }

    let follow = query.follow;
    let tail = query.tail;
    let json_only = query.format.as_deref() == Some("json");

    // Validate tail value upfront
    const MAX_TAIL_LINES: usize = 10_000;
    if let Some(n) = tail {
        if n > MAX_TAIL_LINES {
            return Err(ApiError::BadRequest(format!(
                "tail value {} exceeds maximum of {}",
                n, MAX_TAIL_LINES,
            )));
        }
    }

    // Acquire a follow permit if the client wants to follow. This limits
    // concurrent long-lived polling streams to prevent blocking-pool saturation.
    // The permit is moved into the stream so it's held for the stream's lifetime.
    let follow_permit = if follow {
        Some(
            LOG_FOLLOW_SEMAPHORE
                .try_acquire()
                .map_err(|_| ApiError::Conflict("too many concurrent log followers".into()))?,
        )
    } else {
        None
    };

    // For tail, read last N lines upfront using spawn_blocking with bounded memory
    let (initial_lines, start_pos) = if let Some(n) = tail {
        let path = log_path.clone();
        tokio::task::spawn_blocking(move || read_last_n_lines_bounded(&path, n))
            .await
            .map_err(ApiError::internal)?
            .map_err(ApiError::internal)?
    } else {
        (Vec::new(), 0)
    };

    // Create the SSE stream
    let stream = async_stream::stream! {
        // Hold the follow permit for the stream's lifetime so it's released
        // when the client disconnects or the stream ends.
        let _permit = follow_permit;

        // Emit initial tail lines first
        for line in initial_lines {
            if json_only && serde_json::from_str::<serde_json::Value>(&line).is_err() {
                continue; // skip non-JSON lines in json mode
            }
            yield Ok(Event::default().data(line));
        }

        if tail.is_some() && !follow {
            return;
        }

        // For following or full read, poll the file for new content
        let mut pos = if tail.is_some() { start_pos } else { 0 };
        let mut partial_line = String::new();

        loop {
            // Read new content in spawn_blocking
            let path = log_path.clone();
            let current_pos = pos;

            let result = tokio::task::spawn_blocking(move || {
                read_from_position(&path, current_pos)
            })
            .await
            .unwrap_or_else(|e| Err(std::io::Error::other(e)));

            match result {
                Ok((new_data, new_pos)) => {
                    pos = new_pos;
                    if !new_data.is_empty() {
                        partial_line.push_str(&new_data);
                        // Yield complete lines
                        while let Some(newline_pos) = partial_line.find('\n') {
                            let line = partial_line[..newline_pos].trim_end_matches('\r').to_string();
                            partial_line = partial_line[newline_pos + 1..].to_string();
                            if json_only && serde_json::from_str::<serde_json::Value>(&line).is_err() {
                                continue; // skip non-JSON lines in json mode
                            }
                            yield Ok(Event::default().data(line));
                        }
                        // Flush partial line if it exceeds the safety cap
                        if partial_line.len() > MAX_PARTIAL_LINE {
                            yield Ok(Event::default().data(partial_line.clone()));
                            partial_line.clear();
                        }
                    }
                }
                Err(e) => {
                    yield Ok(Event::default().data(format!("error: {}", e)));
                    break;
                }
            }

            if !follow {
                // Yield any remaining partial line
                if !partial_line.is_empty() {
                    yield Ok(Event::default().data(partial_line.clone()));
                }
                break;
            }

            // Wait before polling again
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

/// Read the last N lines from a file using a bounded ring buffer.
/// Returns (lines, file_position_at_end) for follow mode.
fn read_last_n_lines_bounded(
    path: &std::path::Path,
    n: usize,
) -> std::io::Result<(Vec<String>, u64)> {
    use std::collections::VecDeque;

    let file = std::fs::File::open(path)?;
    let metadata = file.metadata()?;
    let file_len = metadata.len();

    // n == 0 means "no tail lines" — skip reading the file entirely
    if n == 0 {
        return Ok((Vec::new(), file_len));
    }

    let reader = BufReader::new(file);

    // Use a ring buffer to keep only the last N lines in memory
    let mut ring: VecDeque<String> = VecDeque::with_capacity(n + 1);

    for line in reader.lines() {
        let line = line?;
        if ring.len() == n {
            ring.pop_front();
        }
        ring.push_back(line);
    }

    Ok((ring.into_iter().collect(), file_len))
}

/// Maximum bytes to read per poll cycle (64 KiB).
/// Bounds memory usage per follower and prevents a single large write from
/// blocking the async runtime.
const MAX_READ_CHUNK: u64 = 64 * 1024;

/// Maximum size of the partial (incomplete) line buffer (1 MiB).
/// If a log produces data without newlines beyond this limit, the partial
/// buffer is flushed as-is to prevent unbounded memory growth.
const MAX_PARTIAL_LINE: usize = BYTES_PER_MIB as usize;

/// Read new content from a file starting at a given position.
/// Reads at most `MAX_READ_CHUNK` bytes per call.
fn read_from_position(path: &std::path::Path, pos: u64) -> std::io::Result<(String, u64)> {
    use std::io::Read as _;

    let mut file = std::fs::File::open(path)?;
    let metadata = file.metadata()?;
    let file_len = metadata.len();

    if pos >= file_len {
        // No new content
        return Ok((String::new(), pos));
    }

    file.seek(SeekFrom::Start(pos))?;
    let to_read = std::cmp::min(file_len - pos, MAX_READ_CHUNK) as usize;
    let mut buf = vec![0u8; to_read];
    file.read_exact(&mut buf)?;
    let new_pos = pos + to_read as u64;

    let text = String::from_utf8_lossy(&buf).into_owned();
    Ok((text, new_pos))
}
