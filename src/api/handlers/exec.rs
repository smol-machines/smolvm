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

/// Refuse, rather than boot, a machine that is not already running.
async fn require_running(
    entry: &std::sync::Arc<parking_lot::Mutex<crate::api::state::MachineEntry>>,
) -> Result<(), ApiError> {
    let entry = entry.clone();
    let running =
        tokio::task::spawn_blocking(move || entry.lock().manager.try_connect_existing().is_some())
            .await?;
    if running {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "machine is not running and autoStart is false".to_string(),
        ))
    }
}

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
        (status = 409, description = "Machine not running and autoStart is false", body = ApiErrorResponse),
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

    if req.auto_start {
        // Ensure machine is running and persist state to DB
        ensure_running_and_persist(&state, &id, &entry)
            .await
            .map_err(classify_ensure_running_error)?;
    } else {
        require_running(&entry).await?;
    }

    // Resolve secrets ONCE, before the background/foreground split, so a
    // detached workload gets them too (a long-lived daemon usually needs its
    // credentials more than a one-shot exec does). Env precedence (low → high):
    // req.env (caller-plaintext) → record.secret_refs (persisted by a
    // TrustedLocal actor) → req.secrets (ad-hoc, Untrusted). Validation runs
    // before resolution so structural/scope violations surface as 400 without
    // the resolution audit firing.
    crate::api::handlers::validate_request_secrets(&req.secrets)?;
    crate::api::handlers::validate_request_env(&req.env)?;
    let record_env = crate::api::handlers::record_secret_refs_env(&entry)?;
    let req_env = crate::api::handlers::resolve_request_secrets(&req.secrets)?;
    let mut env = EnvVar::to_tuples(&req.env);
    env.extend(record_env);
    env.extend(crate::secrets::expose_into_env(req_env));

    // Detached/background: spawn the process and return its PID immediately, so a
    // long-lived daemon (dev server, agent runner) keeps running after the
    // request returns. Image machines run it in their container (persistent
    // overlay); plain machines run it in the VM.
    if req.background {
        let command = req.command.clone();
        let workdir = req.workdir.clone();
        let user = req.user.clone();
        let machine_rec = state.lookup_vm(&id).await?;
        // An exec may be what establishes the workload container — the machine's
        // command exited, or the image's own default was short-lived — and that
        // container is where the mount lives, so the config has to target the
        // machine rather than merely reuse its overlay.
        let machine_for_run = machine_rec.clone();
        let machine_image = machine_rec.and_then(|r| r.image);
        let pid = if let Some(image) = machine_image {
            let mounts_config = {
                let e = entry.lock();
                e.mounts
                    .iter()
                    .enumerate()
                    .map(|(i, m)| (HostMount::mount_tag(i), m.target.clone(), m.readonly))
                    .collect::<Vec<_>>()
            };
            with_machine_client_traced(&entry, tid, move |c| {
                if c.query(&image)?.is_none() {
                    c.pull_with_registry_config(&image)?;
                }
                // The volumes are derived from the env the machine will see, so
                // keep a copy before the builder consumes it.
                let env_for_volumes = env.clone();
                let config = crate::agent::RunConfig::new(image, command)
                    .with_env(env)
                    .with_workdir(workdir)
                    .with_user(user)
                    .with_mounts(mounts_config)
                    .in_machine_opt(machine_for_run.as_ref(), &id, &env_for_volumes);
                c.run_background(config)
            })
            .await?
        } else {
            with_machine_client_traced(&entry, tid, move |c| {
                c.vm_exec_background(command, env, workdir)
            })
            .await?
        };
        let stdout = format!("pid={pid}\n");
        return Ok(Json(ExecResponse {
            exit_code: 0,
            stdout_b64: stdout.clone().into_bytes(),
            stdout,
            stderr_b64: Vec::new(),
            stderr: String::new(),
        }));
    }

    // Secrets already resolved into `env` above (shared with the background
    // path); env precedence is req.env < record.secret_refs < req.secrets.
    let command = req.command.clone();
    let workdir = req.workdir.clone();
    let user = req.user.clone();
    let timeout = req.timeout_secs.map(Duration::from_secs);
    let stdin_data = req.stdin.clone();

    // Image-based machines exec INSIDE a container from their image, with a
    // per-machine persistent overlay so filesystem changes persist across exec
    // sessions. Without this, exec runs in the bare agent VM (no `python3`,
    // etc.) — the image is never entered. Plain machines exec in the VM
    // directly via `vm_exec`.
    let machine_rec = state.lookup_vm(&id).await?;
    // An exec may be what establishes the workload container — the machine's
    // command exited, or the image's own default was short-lived — and that
    // container is where the mount lives, so the config has to target the
    // machine rather than merely reuse its overlay.
    let machine_for_run = machine_rec.clone();
    let machine_image = machine_rec.and_then(|r| r.image);

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
        // A fork clone's inherited overlay lives under the golden's id.
        let stdin_data = stdin_data.clone();
        with_machine_client_traced(&entry, tid, move |c| {
            // Pull only if the image isn't already present — avoids a registry
            // round-trip on every exec, and works once cached even on
            // network-restricted machines.
            if c.query(&image)?.is_none() {
                c.pull_with_registry_config(&image)?;
            }
            let env_for_volumes = env.clone();
            let config = crate::agent::RunConfig::new(image, command)
                .with_env(env)
                .with_workdir(workdir)
                .with_user(user)
                .with_mounts(mounts_config)
                .with_timeout(timeout)
                .in_machine_opt(machine_for_run.as_ref(), &id, &env_for_volumes)
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
        stdout_b64: stdout,
        stderr_b64: stderr,
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
        (status = 409, description = "Machine not running and autoStart is false", body = ApiErrorResponse),
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
    if req.auto_start {
        ensure_running_and_persist(&state, &id, &entry)
            .await
            .map_err(classify_ensure_running_error)?;
    } else {
        require_running(&entry).await?;
    }

    crate::api::handlers::validate_request_secrets(&req.secrets)?;
    crate::api::handlers::validate_request_env(&req.env)?;
    let record_env = crate::api::handlers::record_secret_refs_env(&entry)?;
    let req_env = crate::api::handlers::resolve_request_secrets(&req.secrets)?;

    let command = req.command.clone();
    let mut env = EnvVar::to_tuples(&req.env);
    env.extend(record_env);
    env.extend(crate::secrets::expose_into_env(req_env));
    let workdir = req.workdir.clone();
    let user = req.user.clone();
    let timeout = req.timeout_secs.map(Duration::from_secs);

    // Image-based machines stream from a container in their image (persistent
    // overlay keyed by machine name); plain machines stream from the VM
    // directly. Without this, streaming exec on an image machine produces no
    // output (the agent-base streaming path doesn't enter the container).
    let machine_rec = state.lookup_vm(&id).await?;
    // An exec may be what establishes the workload container — the machine's
    // command exited, or the image's own default was short-lived — and that
    // container is where the mount lives, so the config has to target the
    // machine rather than merely reuse its overlay.
    let machine_for_run = machine_rec.clone();
    let machine_image = machine_rec.and_then(|r| r.image);

    // Bridge the blocking, synchronous vsock streaming exec to an async SSE
    // stream: a spawned blocking task runs the exec and pushes each ExecEvent
    // into an unbounded channel AS IT ARRIVES; the SSE stream below yields
    // them live. Previously this collected every event into a Vec and only
    // built the SSE stream AFTER the command completed, so the "stream"
    // delivered nothing until exit — defeating streaming exec (F-16). The
    // per-session output cap is still enforced inside the agent client's
    // streaming collector (MAX_STREAMING_EXEC_OUTPUT), which emits a
    // truncation Error event and stops relaying.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<crate::agent::ExecEvent>();
    let err_tx = tx.clone();
    let entry_exec = entry.clone();
    let start = std::time::Instant::now();
    tokio::spawn(async move {
        let result = if let Some(image) = machine_image {
            let mounts_config = {
                let e = entry_exec.lock();
                e.mounts
                    .iter()
                    .enumerate()
                    .map(|(i, m)| (HostMount::mount_tag(i), m.target.clone(), m.readonly))
                    .collect::<Vec<_>>()
            };
            with_machine_client_traced(&entry_exec, tid, move |c| {
                if c.query(&image)?.is_none() {
                    c.pull_with_registry_config(&image)?;
                }
                // The volumes are derived from the env the machine will see, so
                // keep a copy before the builder consumes it.
                let env_for_volumes = env.clone();
                let config = crate::agent::RunConfig::new(image, command)
                    .with_env(env)
                    .with_workdir(workdir)
                    .with_user(user)
                    .with_mounts(mounts_config)
                    .with_timeout(timeout)
                    .in_machine_opt(machine_for_run.as_ref(), &id, &env_for_volumes);
                c.run_streaming_with(config, |e| {
                    let _ = tx.send(e);
                })
            })
            .await
        } else {
            with_machine_client_traced(&entry_exec, tid, move |c| {
                c.vm_exec_streaming_with(command, env, workdir, timeout, |e| {
                    let _ = tx.send(e);
                })
            })
            .await
        };
        metrics::histogram!("smolvm_exec_seconds").record(start.elapsed().as_secs_f64());
        // Setup/transport failures (image pull, vsock) can't become an HTTP
        // status once the SSE has begun, so surface them as a terminal error
        // event instead of silently ending the stream.
        if let Err(e) = result {
            let _ = err_tx.send(crate::agent::ExecEvent::Error(format!("{e:?}")));
        }
    });

    // Yield each event as an SSE frame the instant it lands in the channel.
    let stream = async_stream::stream! {
        while let Some(event) = rx.recv().await {
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
            yield Ok::<_, Infallible>(sse_event);
        }
    };

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
    crate::api::handlers::validate_request_env(&req.env)?;
    let record_env = crate::api::handlers::record_secret_refs_env(&entry)?;
    let req_env = crate::api::handlers::resolve_request_secrets(&req.secrets)?;

    let image = req.image.clone();
    let command = req.command.clone();
    let mut env = EnvVar::to_tuples(&req.env);
    env.extend(record_env);
    env.extend(crate::secrets::expose_into_env(req_env));
    let workdir = req.workdir.clone();
    let user = req.user.clone();
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
            .with_user(user)
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
        stdout_b64: stdout,
        stderr_b64: stderr,
    }))
}

/// Query parameters for an interactive session.
#[derive(Debug, serde::Deserialize)]
pub struct InteractiveQuery {
    /// Program to run (argv[0]); defaults to `/bin/sh`. Its arguments follow as
    /// repeated `arg` parameters, in order.
    pub cmd: Option<String>,
    /// Initial terminal width in columns (`tty=true` only).
    pub cols: Option<u16>,
    /// Initial terminal height in rows (`tty=true` only).
    pub rows: Option<u16>,
    /// Run the command on a PTY (the default). `tty=false` runs it on pipes
    /// instead: a byte stream in both directions with nothing between them and
    /// the command, no terminal line discipline, and stderr kept apart.
    pub tty: Option<bool>,
}

/// Largest piece of a WebSocket message forwarded to the command as one stdin
/// frame. The agent protocol carries stdin as JSON and bounds a frame, so a
/// large message is split rather than ending the session.
const STDIN_CHUNK_BYTES: usize = 64 * 1024;

/// Stdin events that may wait for the session to take them. Beyond this the
/// WebSocket is no longer read, which pushes back on the client.
const INPUT_QUEUE_EVENTS: usize = 64;

/// The command an interactive session runs: the program, then every `arg`
/// query parameter in the order given (an empty argument is an argument).
fn interactive_command(
    program: Option<String>,
    parameters: Vec<(String, String)>,
) -> Result<Vec<String>, ApiError> {
    let mut command = vec![program.unwrap_or_else(|| "/bin/sh".to_string())];
    if command[0].is_empty() {
        return Err(ApiError::BadRequest("command cannot be empty".into()));
    }
    command.extend(
        parameters
            .into_iter()
            .filter(|(name, _)| name == "arg")
            .map(|(_, value)| value),
    );
    validate_command(&command)?;
    Ok(command)
}

/// Interactive session over a WebSocket.
///
/// The client connects a WebSocket; binary frames are forwarded to the
/// command's stdin and its output is sent back as binary frames. A JSON text
/// frame `{"type":"resize","cols":N,"rows":N}` resizes the terminal. When the
/// command exits, a final text frame `{"type":"exit","code":N}` is sent before
/// the socket closes. Closing the socket ends the session, and the command is
/// killed.
///
/// Query parameters: `cmd` is the program and each `arg` one argument to it;
/// `tty` chooses between a PTY (the default, which merges stderr into stdout)
/// and pipes.
///
/// With `tty=false` stdin is written with backpressure and nothing is ever
/// dropped: the WebSocket is read only as fast as the command takes its input.
/// Standard output is the binary frames, byte for byte. Standard error is
/// reported as text frames `{"type":"stderr","data":"..."}` (lossily decoded
/// as UTF-8), so it never mixes into the stream.
///
/// Image machines run the program in their persistent-overlay container (the
/// same filesystem `exec` uses); plain machines run it directly in the VM.
pub async fn exec_interactive(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
    Query(q): Query<InteractiveQuery>,
    Query(parameters): Query<Vec<(String, String)>>,
    _trace_id: Option<axum::Extension<TraceId>>,
    ws: WebSocketUpgrade,
) -> Result<axum::response::Response, ApiError> {
    let command = interactive_command(q.cmd.clone(), parameters)?;
    let tty = q.tty.unwrap_or(true);

    let entry = state.get_machine(&id)?;
    ensure_running_and_persist(&state, &id, &entry)
        .await
        .map_err(classify_ensure_running_error)?;

    let machine_record = state.lookup_vm(&id).await?;
    let machine_image = machine_record.as_ref().and_then(|r| r.image.clone());
    // An interactive session may be what establishes the workload container,
    // and the mount lives there.
    let machine_for_run = machine_record.clone();
    // A terminal sees what an `exec` sees: the machine's own environment and
    // its resolved secret references. Without them a console shell ran with
    // neither, so a tool reading an API key from the environment found none.
    let mut env = machine_record
        .as_ref()
        .map(|record| record.env.clone())
        .unwrap_or_default();
    env.extend(crate::api::handlers::record_secret_refs_env(&entry)?);

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

    Ok(ws.on_upgrade(move |socket| {
        bridge_interactive(socket, tty, init_size, move |input, out_tx| {
            // Run the session on a DEDICATED agent connection — NOT the shared
            // per-machine client. A PTY can outlive its usefulness (a client
            // that disconnects while a `sleep` or daemon keeps running), and
            // holding the shared client lock for the whole session would block
            // every other operation on that machine until the command exits. A
            // fresh connection also lets the agent kill the child the moment we
            // drop it on disconnect. We lock the entry only briefly, to dial.
            async move {
                let connect = { entry.lock().manager.connect() };
                let mut client = match connect {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!(error = ?e, "interactive: failed to open dedicated agent connection");
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
                                    tracing::warn!(error = ?e, "interactive: image pull failed");
                                    return -1;
                                }
                            }
                            Err(e) => {
                                tracing::warn!(error = ?e, "interactive: image query failed");
                                return -1;
                            }
                        }
                        let config = crate::agent::RunConfig::new(image, command)
                            .with_env(env.clone())
                            .with_mounts(mounts_config)
                            .with_tty(tty)
                            .in_machine_opt(machine_for_run.as_ref(), &id, &env);
                        client
                            .run_interactive_io(config, input, on_output)
                            .unwrap_or_else(|e| {
                                tracing::warn!(error = ?e, "interactive: run failed");
                                -1
                            })
                    } else {
                        client
                            .vm_exec_interactive_io(command, env, None, tty, input, on_output)
                            .unwrap_or_else(|e| {
                                tracing::warn!(error = ?e, "interactive: vm exec failed");
                                -1
                            })
                    }
                })
                .await
                .unwrap_or(-1)
            }
        })
    }))
}

/// Carry one WebSocket to an interactive agent session and back.
///
/// `session` starts the session, given the receiving half of the input channel
/// and the sending half of the output channel, and returns the command's exit
/// code (or a sentinel: -1 on internal error, 130 on disconnect).
pub(crate) async fn bridge_interactive<S, F>(
    socket: axum::extract::ws::WebSocket,
    tty: bool,
    size: (u16, u16),
    session: S,
) where
    S: FnOnce(
        crate::agent::InteractiveInputReceiver,
        tokio::sync::mpsc::Sender<crate::agent::InteractiveOutput>,
    ) -> F,
    F: std::future::Future<Output = i32> + Send + 'static,
{
    use crate::agent::{InteractiveInput, InteractiveOutput};

    let (mut ws_tx, mut ws_rx) = socket.split();
    let exit_frame =
        |code: i32| Message::Text(format!("{{\"type\":\"exit\",\"code\":{code}}}").into());

    let (in_tx, in_rx) = match crate::agent::interactive_input(INPUT_QUEUE_EVENTS) {
        Ok(channel) => channel,
        Err(e) => {
            tracing::warn!(error = ?e, "interactive: could not create the input channel");
            let _ = ws_tx.send(exit_frame(-1)).await;
            let _ = ws_tx.send(Message::Close(None)).await;
            return;
        }
    };
    // Output channel: blocking session -> WS task (the session blocks in send).
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<InteractiveOutput>(256);

    // Seed the initial PTY size before any input.
    if tty {
        let _ = in_tx
            .send(InteractiveInput::Resize {
                cols: size.0,
                rows: size.1,
            })
            .await;
    }

    let session = tokio::spawn(session(in_rx, out_tx));

    // Pump WS -> session input. Dropping `in_tx` (when this task ends) tells the
    // session its peer is gone.
    let input_pump = tokio::spawn(async move {
        while let Some(Ok(msg)) = ws_rx.next().await {
            let sent = match msg {
                Message::Binary(b) => {
                    let mut sent = Ok(());
                    for chunk in b.chunks(STDIN_CHUNK_BYTES) {
                        sent = in_tx.send(InteractiveInput::Stdin(chunk.to_vec())).await;
                        if sent.is_err() {
                            break;
                        }
                    }
                    sent
                }
                Message::Text(t) => {
                    // Control frames are JSON; anything else is treated as raw stdin.
                    match serde_json::from_str::<serde_json::Value>(t.as_str()) {
                        Ok(v) if v["type"] == "resize" => {
                            if tty {
                                let cols = v["cols"].as_u64().unwrap_or(80) as u16;
                                let rows = v["rows"].as_u64().unwrap_or(24) as u16;
                                in_tx.send(InteractiveInput::Resize { cols, rows }).await
                            } else {
                                Ok(())
                            }
                        }
                        Ok(v) if v["type"] == "stdin" => match v["data"].as_str() {
                            Some(d) => {
                                in_tx
                                    .send(InteractiveInput::Stdin(d.as_bytes().to_vec()))
                                    .await
                            }
                            None => Ok(()),
                        },
                        _ => {
                            in_tx
                                .send(InteractiveInput::Stdin(t.as_bytes().to_vec()))
                                .await
                        }
                    }
                }
                Message::Close(_) => {
                    let _ = in_tx.send(InteractiveInput::Eof).await;
                    return;
                }
                _ => Ok(()),
            };
            if sent.is_err() {
                return;
            }
        }
    });

    // Pump session output -> WS. Ends when the session drops `out_tx` (command exit).
    while let Some(o) = out_rx.recv().await {
        let message = match o {
            InteractiveOutput::Stdout(d) => Message::Binary(d.into()),
            // A PTY has one output stream, which the agent reports as stdout. On
            // pipes stderr is a stream of its own and must not join the bytes.
            InteractiveOutput::Stderr(d) if tty => Message::Binary(d.into()),
            InteractiveOutput::Stderr(d) => Message::Text(
                serde_json::json!({"type": "stderr", "data": String::from_utf8_lossy(&d)})
                    .to_string()
                    .into(),
            ),
        };
        if ws_tx.send(message).await.is_err() {
            break;
        }
    }

    // Report the exit code and close.
    let code = session.await.unwrap_or(-1);
    let _ = ws_tx.send(exit_frame(code)).await;
    let _ = ws_tx.send(Message::Close(None)).await;
    input_pump.abort();
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
) -> Result<axum::response::Response, ApiError> {
    // get_machine only knows machines in the running map. Distinguish a real
    // typo (absent from the DB too) from a machine that exists but was never
    // started (present in the DB, no console log yet) so clients don't read a
    // created machine as "not found".
    let entry = match state.get_machine(&id) {
        Ok(e) => e,
        Err(_) => {
            let known = matches!(state.db().get_vm(&id), Ok(Some(_)));
            return Err(if known {
                ApiError::NotFound(format!(
                    "machine '{id}' has not been started yet — no logs available"
                ))
            } else {
                ApiError::NotFound(format!("machine '{id}' not found"))
            });
        }
    };

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
        // The machine is registered (get_machine succeeded above) but has no
        // console log yet — it was created and never started, or hasn't produced
        // output. Report that plainly instead of leaking the internal host log
        // path, and give the same not-started-shaped hint as the DB-miss branch
        // (which a created machine skips, since it's in the running map).
        return Err(ApiError::NotFound(format!(
            "machine '{id}' has no logs yet — it may not have been started"
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

    let stream = log_event_stream(
        log_path,
        follow,
        tail,
        start_pos,
        initial_lines,
        json_only,
        follow_permit,
    );

    use axum::response::IntoResponse as _;
    Ok((
        [
            (axum::http::header::CONTENT_TYPE, "text/event-stream"),
            (axum::http::header::CACHE_CONTROL, "no-cache"),
        ],
        axum::body::Body::from_stream(stream),
    )
        .into_response())
}

/// The console log at `log_path` as an SSE body: the `tail` lines already read
/// (`initial_lines`, ending at `start_pos`), then the file from there, to its
/// end or, with `follow`, as it grows.
fn log_event_stream(
    log_path: PathBuf,
    follow: bool,
    tail: Option<usize>,
    start_pos: u64,
    initial_lines: Vec<String>,
    json_only: bool,
    follow_permit: Option<tokio::sync::SemaphorePermit<'static>>,
) -> impl tokio_stream::Stream<Item = Result<axum::body::Bytes, Infallible>> {
    // One SSE event per line, as before, but many lines per write. Each write
    // reaches an HTTP/2 client as its own DATA frame, and a client that receives
    // too many small frames faster than it reads them (h2 counts them per
    // connection) closes the whole connection, failing everything else on it.
    async_stream::stream! {
        // Hold the follow permit for the stream's lifetime so it's released
        // when the client disconnects or the stream ends.
        let _permit = follow_permit;
        let mut batch = LogEvents::default();

        // Emit initial tail lines first
        for line in initial_lines {
            if json_only && serde_json::from_str::<serde_json::Value>(&line).is_err() {
                continue; // skip non-JSON lines in json mode
            }
            batch.push(&line);
            if batch.is_full() {
                yield Ok::<_, Infallible>(batch.take());
            }
        }
        if !batch.is_empty() {
            yield Ok(batch.take());
        }

        if tail.is_some() && !follow {
            return;
        }

        // For following or full read, poll the file for new content
        let mut pos = if tail.is_some() { start_pos } else { 0 };
        let mut partial_line = String::new();
        let mut last_write = tokio::time::Instant::now();

        loop {
            // Read new content in spawn_blocking
            let path = log_path.clone();
            let current_pos = pos;

            let result = tokio::task::spawn_blocking(move || {
                read_from_position(&path, current_pos)
            })
            .await
            .unwrap_or_else(|e| Err(std::io::Error::other(e)));

            let read_more = match result {
                Ok((new_data, new_pos)) => {
                    let advanced = new_pos > pos;
                    pos = new_pos;
                    if !new_data.is_empty() {
                        partial_line.push_str(&new_data);
                        // Queue complete lines
                        while let Some(newline_pos) = partial_line.find('\n') {
                            let line = partial_line[..newline_pos].trim_end_matches('\r').to_string();
                            partial_line = partial_line[newline_pos + 1..].to_string();
                            if json_only && serde_json::from_str::<serde_json::Value>(&line).is_err() {
                                continue; // skip non-JSON lines in json mode
                            }
                            batch.push(&line);
                        }
                        // Flush partial line if it exceeds the safety cap
                        if partial_line.len() > MAX_PARTIAL_LINE {
                            batch.push(&partial_line);
                            partial_line.clear();
                        }
                    }
                    advanced
                }
                Err(e) => {
                    batch.push(&format!("error: {}", e));
                    yield Ok(batch.take());
                    break;
                }
            };
            if !batch.is_empty() {
                yield Ok(batch.take());
                last_write = tokio::time::Instant::now();
            }

            if !follow {
                // A full read goes on to the end of the file, a chunk at a time.
                if read_more {
                    continue;
                }
                // Yield any remaining partial line
                if !partial_line.is_empty() {
                    batch.push(&partial_line);
                    yield Ok(batch.take());
                }
                break;
            }

            // Keep an idle follower's connection open, as SSE keep-alive did.
            if last_write.elapsed() >= LOG_KEEP_ALIVE {
                yield Ok(axum::body::Bytes::from_static(b":\n\n"));
                last_write = tokio::time::Instant::now();
            }

            // Wait before polling again
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

/// How long a followed log stream may go quiet before it sends a keep-alive
/// comment, the interval axum's SSE keep-alive used.
const LOG_KEEP_ALIVE: Duration = Duration::from_secs(15);

/// Log lines encoded as SSE events, written out together once they fill a
/// read's worth.
#[derive(Default)]
struct LogEvents(Vec<u8>);

impl LogEvents {
    /// Appends `line` as one SSE event, encoded exactly as axum's
    /// `Event::default().data(line)`: a `data: ` field per `\r`- or
    /// `\n`-delimited piece, then a blank line; an empty line is the blank line
    /// alone.
    fn push(&mut self, line: &str) {
        let out = &mut self.0;
        if !line.is_empty() {
            out.extend_from_slice(b"data: ");
            let bytes = line.as_bytes();
            let mut last = 0;
            let delimiters = bytes
                .iter()
                .enumerate()
                .filter(|(_, b)| matches!(b, b'\n' | b'\r'));
            for (delimiter, _) in delimiters {
                out.extend_from_slice(&bytes[last..=delimiter]);
                out.extend_from_slice(b"data: ");
                last = delimiter + 1;
            }
            out.extend_from_slice(&bytes[last..]);
            out.push(b'\n');
        }
        out.push(b'\n');
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn is_full(&self) -> bool {
        self.0.len() >= MAX_READ_CHUNK as usize
    }

    fn take(&mut self) -> axum::body::Bytes {
        axum::body::Bytes::from(std::mem::take(&mut self.0))
    }
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

#[cfg(all(test, unix))]
mod interactive_tests {
    //! The interactive WebSocket, end to end but for the VM: a real server and
    //! client, the handler's query parsing and bridge, the agent client's session
    //! loop, and a stand-in guest that runs the command as a real process on pipes.
    use super::*;
    use crate::agent::{test_guest::FakeGuest, AgentClient};
    use crate::platform::uds::UdsStream;
    use axum::{routing::get, Router};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio_tungstenite::{connect_async, tungstenite::Message as Wire};

    #[derive(Default)]
    struct Guests {
        resizes: std::sync::Mutex<Vec<Arc<AtomicUsize>>>,
    }

    /// Parses the same query as [`exec_interactive`] and bridges to a stand-in
    /// guest instead of a machine.
    async fn session(
        State(guests): State<Arc<Guests>>,
        Query(q): Query<InteractiveQuery>,
        Query(parameters): Query<Vec<(String, String)>>,
        ws: WebSocketUpgrade,
    ) -> Result<axum::response::Response, ApiError> {
        let command = interactive_command(q.cmd, parameters)?;
        let tty = q.tty.unwrap_or(true);
        let (client_stream, guest_stream) = UdsStream::pair().unwrap();
        let guest = FakeGuest::spawn(guest_stream);
        guests.resizes.lock().unwrap().push(guest.resizes.clone());
        Ok(ws.on_upgrade(move |socket| {
            bridge_interactive(socket, tty, (100, 40), move |input, out_tx| async move {
                let code = tokio::task::spawn_blocking(move || {
                    let on_output = move |o| {
                        let _ = out_tx.blocking_send(o);
                    };
                    AgentClient::from_stream(client_stream)
                        .vm_exec_interactive_io(command, Vec::new(), None, tty, input, on_output)
                        .unwrap_or(-1)
                })
                .await
                .unwrap_or(-1);
                let _ = tokio::task::spawn_blocking(move || guest.finish()).await;
                code
            })
        }))
    }

    async fn args(
        Query(q): Query<InteractiveQuery>,
        Query(parameters): Query<Vec<(String, String)>>,
    ) -> Result<Json<Vec<String>>, ApiError> {
        Ok(Json(interactive_command(q.cmd, parameters)?))
    }

    async fn server() -> (String, Arc<Guests>) {
        let guests = Arc::new(Guests::default());
        let app = Router::new()
            .route("/session", get(session))
            .route("/args", get(args))
            .with_state(guests.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (address.to_string(), guests)
    }

    type Client = tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >;

    async fn connect(address: &str, query: &str) -> Client {
        connect_async(format!("ws://{address}/session?{query}"))
            .await
            .expect("upgrade")
            .0
    }

    /// Everything the session sends until it says the command exited.
    struct Transcript {
        stdout: Vec<u8>,
        stderr: String,
        exit: Option<i64>,
    }

    async fn transcript(client: &mut Client) -> Transcript {
        let mut all = Transcript {
            stdout: Vec::new(),
            stderr: String::new(),
            exit: None,
        };
        while let Some(message) = tokio::time::timeout(Duration::from_secs(20), client.next())
            .await
            .expect("the session stalled")
        {
            match message.unwrap() {
                Wire::Binary(data) => all.stdout.extend(data.iter()),
                Wire::Text(text) => {
                    let frame: serde_json::Value = serde_json::from_str(text.as_str()).unwrap();
                    match frame["type"].as_str() {
                        Some("stderr") => all.stderr.push_str(frame["data"].as_str().unwrap()),
                        Some("exit") => all.exit = frame["code"].as_i64(),
                        other => panic!("unexpected frame type {other:?}"),
                    }
                }
                Wire::Close(_) => break,
                _ => {}
            }
        }
        all
    }

    /// Read binary frames until `count` bytes have arrived.
    async fn receive(client: &mut Client, count: usize) -> Vec<u8> {
        let mut received = Vec::new();
        while received.len() < count {
            match tokio::time::timeout(Duration::from_secs(20), client.next())
                .await
                .expect("the echo stalled")
                .expect("the session ended early")
                .unwrap()
            {
                Wire::Binary(data) => received.extend(data.iter()),
                Wire::Text(text) => panic!("unexpected text frame {text}"),
                _ => {}
            }
        }
        received
    }

    fn pattern(length: usize, seed: usize) -> Vec<u8> {
        (0..length).map(|i| ((seed + i) % 251) as u8).collect()
    }

    #[tokio::test]
    async fn arguments_arrive_in_order_and_empty_ones_count() {
        let (address, _) = server().await;
        let get = |query: &str| {
            let url = format!("http://{address}/args?{query}");
            async move { reqwest::get(url).await.unwrap() }
        };
        let answer = get("cmd=/bin/printf&arg=%25s-%25s&arg=a%20b&arg=&arg=c%26d")
            .await
            .json::<Vec<String>>()
            .await
            .unwrap();
        assert_eq!(answer, ["/bin/printf", "%s-%s", "a b", "", "c&d"]);
        // Without arguments the program is the whole command, and the default is a shell.
        let answer = get("cmd=/bin/cat")
            .await
            .json::<Vec<String>>()
            .await
            .unwrap();
        assert_eq!(answer, ["/bin/cat"]);
        let answer = get("cols=80").await.json::<Vec<String>>().await.unwrap();
        assert_eq!(answer, ["/bin/sh"]);
        assert_eq!(get("cmd=").await.status(), 400);
    }

    #[tokio::test]
    async fn the_command_runs_with_the_given_argument_vector() {
        let (address, _) = server().await;
        let mut client = connect(
            &address,
            "tty=false&cmd=/bin/sh&arg=-c&arg=printf%20%25s%20%22%241%7C%242%22&arg=x&arg=one%20two&arg=",
        )
        .await;
        let all = transcript(&mut client).await;
        assert_eq!(all.exit, Some(0));
        assert_eq!(String::from_utf8(all.stdout).unwrap(), "one two|");
    }

    #[tokio::test]
    async fn stdin_on_pipes_arrives_intact_whatever_its_size_and_pacing() {
        let (address, _) = server().await;
        let mut client = connect(&address, "tty=false&cmd=/bin/cat").await;

        // The message the terminal path delivered only 9,728 bytes of.
        let large = pattern(256 * 1024, 7);
        client
            .send(Wire::Binary(large.clone().into()))
            .await
            .unwrap();
        assert!(receive(&mut client, large.len()).await == large);

        // A burst that delivered less than a third of it.
        let mut burst = Vec::new();
        for i in 0..50 {
            let piece = pattern(1000, i);
            client
                .send(Wire::Binary(piece.clone().into()))
                .await
                .unwrap();
            burst.extend(piece);
        }
        assert!(receive(&mut client, burst.len()).await == burst);

        // Every byte value, including the ones a terminal treats specially.
        let all: Vec<u8> = (0..=255).collect();
        client.send(Wire::Binary(all.clone().into())).await.unwrap();
        assert_eq!(receive(&mut client, all.len()).await, all);

        client.close(None).await.unwrap();
    }

    #[tokio::test]
    async fn a_message_bigger_than_a_frame_is_split_rather_than_refused() {
        let (address, _) = server().await;
        let mut client = connect(&address, "tty=false&cmd=/bin/cat").await;
        let huge = pattern(3 * 1024 * 1024 + 5, 3);
        client
            .send(Wire::Binary(huge.clone().into()))
            .await
            .unwrap();
        assert!(receive(&mut client, huge.len()).await == huge);
        client.close(None).await.unwrap();
    }

    #[tokio::test]
    async fn an_echo_needs_no_help_from_the_guest_to_be_prompt() {
        // The session loop used to notice input only when its 100 ms poll timed
        // out, so an idle round trip took anywhere from 0 to 100 ms. The gaps are
        // jittered so no timer can phase-lock with the loop's.
        let (address, _) = server().await;
        let mut client = connect(&address, "tty=false&cmd=/bin/cat").await;
        let mut trips = Vec::new();
        for i in 0..30u64 {
            tokio::time::sleep(Duration::from_millis(20 + (i * 37) % 61)).await;
            let message = pattern(100, i as usize);
            let began = std::time::Instant::now();
            client
                .send(Wire::Binary(message.clone().into()))
                .await
                .unwrap();
            assert_eq!(receive(&mut client, message.len()).await, message);
            trips.push(began.elapsed());
        }
        trips.sort();
        eprintln!(
            "idle echo round trip over 30 messages: min {:?}, median {:?}, max {:?}",
            trips[0], trips[15], trips[29]
        );
        assert!(
            trips[15] < Duration::from_millis(40),
            "an idle round trip takes {:?} at the median; input waits for the poll timeout",
            trips[15]
        );
        client.close(None).await.unwrap();
    }

    #[tokio::test]
    async fn on_pipes_stderr_is_a_frame_of_its_own_and_the_exit_code_is_reported() {
        let (address, _) = server().await;
        let mut client = connect(
            &address,
            "tty=false&cmd=/bin/sh&arg=-c&arg=printf%20out%3B%20printf%20err%20%3E%262%3B%20exit%207",
        )
        .await;
        let all = transcript(&mut client).await;
        assert_eq!(all.stdout, b"out");
        assert_eq!(all.stderr, "err");
        assert_eq!(all.exit, Some(7));
    }

    #[tokio::test]
    async fn on_a_terminal_output_stays_one_stream_and_the_size_is_sent() {
        let (address, guests) = server().await;
        let mut client = connect(
            &address,
            "cmd=/bin/sh&arg=-c&arg=printf%20out%3B%20printf%20err%20%3E%262",
        )
        .await;
        let all = transcript(&mut client).await;
        // A PTY has one output stream, so stderr is not reported apart.
        assert_eq!(all.stderr, "");
        assert_eq!(all.stdout.len(), 6);
        assert_eq!(all.exit, Some(0));
        let mut piped = connect(&address, "tty=false&cmd=/bin/true").await;
        transcript(&mut piped).await;
        let resizes: Vec<_> = guests
            .resizes
            .lock()
            .unwrap()
            .iter()
            .map(|r| r.load(Ordering::SeqCst))
            .collect();
        assert_eq!(resizes, [1, 0], "only a terminal is told its size");
    }
}

#[cfg(test)]
mod log_stream_tests {
    use super::*;
    use futures_util::StreamExt;

    /// What axum's `Sse` writes for these lines, one `Event::default().data(line)` each.
    async fn axum_sse_bytes(lines: &[&str]) -> Vec<u8> {
        use axum::response::IntoResponse as _;
        let events: Vec<Result<Event, Infallible>> = lines
            .iter()
            .map(|line| Ok(Event::default().data(*line)))
            .collect();
        let response = Sse::new(futures_util::stream::iter(events)).into_response();
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec()
    }

    #[tokio::test]
    async fn log_events_are_encoded_as_axum_sse_encoded_them() {
        let lines = [
            "[    0.000000] Linux version 6.12",
            "",
            "carriage\rreturn inside",
            "data: looks like a field",
            "  leading spaces and ünïcode ✓",
            ":starts like a comment",
        ];
        let mut ours = LogEvents::default();
        for line in lines {
            ours.push(line);
        }
        assert_eq!(ours.take().to_vec(), axum_sse_bytes(&lines).await);
    }

    async fn read_all(
        stream: impl tokio_stream::Stream<Item = Result<axum::body::Bytes, Infallible>>,
    ) -> Vec<axum::body::Bytes> {
        let mut writes = Vec::new();
        let mut stream = std::pin::pin!(stream);
        while let Some(chunk) = stream.next().await {
            writes.push(chunk.unwrap());
        }
        writes
    }

    /// Splits an SSE body of single-field events back into their lines.
    fn lines_of(writes: &[axum::body::Bytes]) -> Vec<String> {
        let body: Vec<u8> = writes.iter().flat_map(|w| w.to_vec()).collect();
        String::from_utf8(body)
            .unwrap()
            .split("\n\n")
            .filter(|event| !event.is_empty())
            .map(|event| event.strip_prefix("data: ").unwrap().to_string())
            .collect()
    }

    #[tokio::test]
    async fn a_full_read_sends_the_whole_log_a_read_at_a_time() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("console.log");
        let lines: Vec<String> = (0..12_000)
            .map(|i| format!("[{i:>6}] console line {i}"))
            .collect();
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();
        let size = std::fs::metadata(&path).unwrap().len();
        assert!(size > 3 * MAX_READ_CHUNK, "the log must span several reads");

        let writes = read_all(log_event_stream(
            path,
            false,
            None,
            0,
            Vec::new(),
            false,
            None,
        ))
        .await;

        // Every line, past the first read's 64 KiB, which a full read used to stop at.
        assert_eq!(lines_of(&writes), lines);
        // A write per read of the file, not per line.
        assert!(
            writes.len() as u64 <= size / MAX_READ_CHUNK + 2,
            "{} writes for {} lines",
            writes.len(),
            lines.len()
        );
    }

    #[tokio::test]
    async fn a_tail_sends_only_its_lines_in_one_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("console.log");
        std::fs::write(&path, "one\ntwo\nthree\n").unwrap();
        let (initial, end) = read_last_n_lines_bounded(&path, 2).unwrap();

        let writes = read_all(log_event_stream(
            path,
            false,
            Some(2),
            end,
            initial,
            false,
            None,
        ))
        .await;

        assert_eq!(writes.len(), 1);
        assert_eq!(lines_of(&writes), ["two", "three"]);
    }
}
