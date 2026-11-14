//! `docker exec`: commands run inside a running container.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::Request;
use axum::response::Response;

use super::containers::Container;
use super::model::{ExecCreateRequest, ExecStartRequest};
use super::runtime::{Input, InputQueue};
use super::util::{ApiError, ApiResult};
use super::Engine;

/// One exec instance.
pub(crate) struct Exec {
    pub id: String,
    pub container_id: String,
    pub config: ExecCreateRequest,
    state: parking_lot::Mutex<ExecState>,
    input: InputQueue,
}

#[derive(Debug, Clone, Default)]
struct ExecState {
    running: bool,
    started: bool,
    exit_code: Option<i64>,
}

/// `POST /containers/{id}/exec`.
pub(crate) fn create(engine: &Engine, c: &Container, req: ExecCreateRequest) -> ApiResult<String> {
    if !c.is_running() {
        return Err(ApiError::conflict(format!(
            "container {} is not running",
            c.id()
        )));
    }
    if req.cmd.as_ref().is_none_or(|c| c.is_empty()) {
        return Err(ApiError::bad_request("No exec command specified"));
    }
    let id = super::util::new_id();
    let exec = Arc::new(Exec {
        id: id.clone(),
        container_id: c.id(),
        config: req,
        state: parking_lot::Mutex::new(ExecState::default()),
        input: InputQueue::default(),
    });
    persist(engine, &exec);
    engine.execs.lock().insert(id.clone(), exec);
    let record = c.record();
    let mut attrs = record.event_attributes();
    attrs.insert("execID".into(), id.clone());
    engine.events.emit(
        "container",
        format!(
            "exec_create: {}",
            exec_command(&engine.execs.lock()[&id].config).join(" ")
        ),
        &record.id,
        attrs,
    );
    Ok(id)
}

fn exec_command(config: &ExecCreateRequest) -> Vec<String> {
    config.cmd.clone().unwrap_or_default()
}

/// The agent request that runs `argv` in the running container `c`.
fn run_request(
    c: &Container,
    argv: Vec<String>,
    env: &[String],
    user: &str,
    workdir: &str,
    tty: bool,
) -> smolvm_protocol::AgentRequest {
    let record = c.record();
    let mut merged: Vec<(String, String)> = record
        .config
        .env
        .iter()
        .chain(env.iter())
        .filter_map(|e| {
            e.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect();
    // Later entries win.
    let mut seen = std::collections::HashSet::new();
    merged.reverse();
    merged.retain(|(k, _)| seen.insert(k.clone()));
    merged.reverse();
    let user = if user.is_empty() {
        record.config.user.clone()
    } else {
        user.to_string()
    };
    let workdir = if workdir.is_empty() {
        record.config.working_dir.clone()
    } else {
        workdir.to_string()
    };
    smolvm_protocol::AgentRequest::Run {
        image: record.pull_ref.clone(),
        command: argv,
        env: merged,
        workdir: (!workdir.is_empty()).then_some(workdir),
        user: (!user.is_empty()).then_some(user),
        mounts: Vec::new(),
        timeout_ms: None,
        interactive: true,
        tty,
        detached: false,
        unprivileged: false,
        persistent_overlay_id: Some(super::containers::overlay_id(&record)),
        stdin_data: None,
        background: false,
        s3_volumes: Vec::new(),
        stop_vm_on_exit: false,
        stop_signal: None,
        stop_timeout_secs: None,
    }
}

/// `POST /exec/{id}/start`.
pub(crate) async fn start(
    engine: &Arc<Engine>,
    exec: Arc<Exec>,
    body: ExecStartRequest,
    req: Request,
) -> ApiResult<Response> {
    let c = engine
        .find_container(&exec.container_id)
        .ok_or_else(|| ApiError::no_such_container(&exec.container_id))?;
    {
        let mut state = exec.state.lock();
        if state.started {
            return Err(ApiError::conflict(format!(
                "Exec command {} has already run",
                exec.id
            )));
        }
        state.started = true;
        state.running = true;
    }
    persist(engine, &exec);
    let socket = c
        .socket()
        .ok_or_else(|| ApiError::conflict(format!("container {} is not running", c.id())))?;
    let tty = exec.config.tty || body.tty;
    let request = run_request(
        &c,
        exec_command(&exec.config),
        &exec.config.env,
        &exec.config.user,
        &exec.config.working_dir,
        tty,
    );
    let started = async {
        let (mut reader, mut writer) = super::runtime::connect(&socket)
            .await
            .map_err(|e| format!("connect to container: {e}"))?;
        writer
            .send(&request)
            .await
            .map_err(|e| format!("start exec: {e}"))?;
        match reader
            .recv()
            .await
            .map_err(|e| format!("start exec: {e}"))?
        {
            smolvm_protocol::AgentResponse::Started => Ok((reader, writer)),
            other => {
                Err(super::runtime::error_text(&other).unwrap_or_else(|| format!("{other:?}")))
            }
        }
    }
    .await;
    let (reader, writer) = match started {
        Ok(rw) => rw,
        Err(message) => {
            // As Docker does: the session still opens, carries the error
            // text, and the exec ends with 126 (127 when nothing was found).
            let code = if message.contains("not found") || message.contains("no such file") {
                127
            } else {
                126
            };
            {
                let mut state = exec.state.lock();
                state.running = false;
                state.exit_code = Some(code);
            }
            persist(engine, &exec);
            let message = format!("OCI runtime exec failed: exec failed: {message}\r\n");
            if body.detach {
                return Err(ApiError::internal(message.trim_end().to_string()));
            }
            let content_type = if tty {
                super::stream::RAW
            } else {
                super::stream::MULTIPLEXED
            };
            let (response, session) = super::stream::hijack(req, content_type);
            tokio::spawn(async move {
                if let Some(session) = session.await {
                    let mut output = session.output;
                    let bytes = if tty {
                        message.into_bytes()
                    } else {
                        super::stream::frame(1, message.as_bytes())
                    };
                    let _ = output.write(bytes).await;
                    output.close().await;
                }
            });
            return Ok(response);
        }
    };
    let size = body
        .console_size
        .clone()
        .or(exec.config.console_size.clone());
    if let Some([h, w]) = size.as_deref() {
        exec.input.push(Input::Resize { cols: *w, rows: *h });
    }
    if !exec.config.attach_stdin {
        exec.input.push(Input::Eof);
    }
    let record = c.record();
    let mut attrs = record.event_attributes();
    attrs.insert("execID".into(), exec.id.clone());
    engine.events.emit(
        "container",
        format!("exec_start: {}", exec_command(&exec.config).join(" ")),
        &record.id,
        attrs.clone(),
    );

    let finish = {
        let engine = engine.clone();
        let exec = exec.clone();
        let container_id = record.id.clone();
        move |code: i64| {
            {
                let mut state = exec.state.lock();
                state.running = false;
                state.exit_code = Some(code);
            }
            persist(&engine, &exec);
            let mut attrs = attrs;
            attrs.insert("exitCode".into(), code.to_string());
            engine
                .events
                .emit("container", "exec_die", &container_id, attrs);
        }
    };

    if body.detach {
        let exec2 = exec.clone();
        tokio::spawn(async move {
            let exit = super::runtime::pump(reader, writer, &exec2.input, |_, _| {}).await;
            finish(exit.code);
        });
        return Ok(Response::new(axum::body::Body::empty()));
    }

    let content_type = if tty {
        super::stream::RAW
    } else {
        super::stream::MULTIPLEXED
    };
    let (response, session) = super::stream::hijack(req, content_type);
    let exec2 = exec.clone();
    tokio::spawn(async move {
        let Some(session) = session.await else {
            drop(writer);
            drop(reader);
            finish(130);
            return;
        };
        let super::stream::Session {
            input,
            mut output,
            _activity,
        } = session;
        if let Some(input) = input {
            if exec2.config.attach_stdin {
                let exec3 = exec2.clone();
                tokio::spawn(async move {
                    super::stream::read_input(input, |data| exec3.input.push(Input::Data(data)))
                        .await;
                    exec3.input.push(Input::Eof);
                });
            }
        }
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(u8, Vec<u8>)>();
        let pump = tokio::spawn({
            let exec2 = exec2.clone();
            async move {
                super::runtime::pump(reader, writer, &exec2.input, |stream, data| {
                    let _ = tx.send((stream, data));
                })
                .await
            }
        });
        let attach_out = exec2.config.attach_stdout || exec2.config.attach_stderr;
        while let Some((stream, data)) = rx.recv().await {
            if !attach_out {
                continue;
            }
            if stream == 1 && !exec2.config.attach_stdout && !tty {
                continue;
            }
            if stream == 2 && !exec2.config.attach_stderr && !tty {
                continue;
            }
            let bytes = if tty {
                data
            } else {
                super::stream::frame(stream, &data)
            };
            if !output.write(bytes).await {
                break;
            }
        }
        let exit = pump.await.unwrap_or(super::runtime::Exit {
            code: 137,
            oom: false,
        });
        finish(exit.code);
        output.close().await;
    });
    Ok(response)
}

/// `GET /exec/{id}/json`.
pub(crate) fn inspect(exec: &Exec) -> serde_json::Value {
    let state = exec.state.lock().clone();
    let cmd = exec_command(&exec.config);
    serde_json::json!({
        "ID": exec.id,
        "Running": state.running,
        "ExitCode": state.exit_code,
        "ProcessConfig": {
            "tty": exec.config.tty,
            "entrypoint": cmd.first().cloned().unwrap_or_default(),
            "arguments": cmd.iter().skip(1).cloned().collect::<Vec<_>>(),
            "privileged": exec.config.privileged,
            "user": exec.config.user,
        },
        "OpenStdin": exec.config.attach_stdin,
        "OpenStderr": exec.config.attach_stderr,
        "OpenStdout": exec.config.attach_stdout,
        "CanRemove": !state.running && state.started,
        "ContainerID": exec.container_id,
        "DetachKeys": "",
        "Pid": 0,
    })
}

/// `POST /exec/{id}/resize`.
pub(crate) fn resize(exec: &Exec, rows: u16, cols: u16) {
    exec.input.push(Input::Resize { cols, rows });
}

/// Run `argv` in the running container and return its exit code and
/// combined output, for health checks. Gives up after `timeout`.
pub(crate) async fn run_capture(
    _engine: &Arc<Engine>,
    c: &Arc<Container>,
    argv: &[String],
    timeout: Duration,
) -> ApiResult<(i64, String)> {
    let socket = c
        .socket()
        .ok_or_else(|| ApiError::conflict("container is not running"))?;
    let request = run_request(c, argv.to_vec(), &[], "", "", false);
    let run = async {
        let (mut reader, mut writer) = super::runtime::connect(&socket).await?;
        writer.send(&request).await?;
        writer
            .send(&smolvm_protocol::AgentRequest::Stdin { data: Vec::new() })
            .await?;
        let mut output = Vec::new();
        loop {
            match reader.recv().await? {
                smolvm_protocol::AgentResponse::Stdout { data }
                | smolvm_protocol::AgentResponse::Stderr { data } => {
                    if output.len() < 64 * 1024 {
                        output.extend_from_slice(&data);
                    }
                }
                smolvm_protocol::AgentResponse::Exited { exit_code, .. } => {
                    return Ok::<_, std::io::Error>((
                        exit_code as i64,
                        String::from_utf8_lossy(&output).into_owned(),
                    ));
                }
                smolvm_protocol::AgentResponse::Error { message, .. } => {
                    return Ok((-1, message));
                }
                _ => {}
            }
        }
    };
    match tokio::time::timeout(timeout, run).await {
        Ok(Ok(r)) => Ok(r),
        Ok(Err(e)) => Err(ApiError::internal(e.to_string())),
        Err(_) => Ok((
            -1,
            format!("Health check exceeded timeout ({}s)", timeout.as_secs_f64()),
        )),
    }
}

fn persist(engine: &Engine, exec: &Exec) {
    if let Err(error) = engine.store.save_object("execs", &exec.id, &inspect(exec)) {
        tracing::warn!(%error, "persist exec state");
    }
}
