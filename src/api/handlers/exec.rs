//! Command execution handlers.

use axum::{
    extract::{Path, Query, State},
    response::sse::{Event, KeepAlive, Sse},
    Json,
};
use std::convert::Infallible;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::api::error::{classify_ensure_running_error, ApiError};
use crate::api::state::{ensure_running_and_persist, with_sandbox_client, ApiState};
use crate::api::types::{
    ApiErrorResponse, EnvVar, ExecRequest, ExecResponse, LogsQuery, RunRequest,
};
use crate::api::validation::validate_command;
use tokio::sync::Semaphore;

/// Execute a command in a sandbox.
///
/// This executes directly in the VM (not in a container).
#[utoipa::path(
    post,
    path = "/api/v1/sandboxes/{id}/exec",
    tag = "Execution",
    params(
        ("id" = String, Path, description = "Sandbox name")
    ),
    request_body = ExecRequest,
    responses(
        (status = 200, description = "Command executed", body = ExecResponse),
        (status = 400, description = "Invalid request", body = ApiErrorResponse),
        (status = 404, description = "Sandbox not found", body = ApiErrorResponse),
        (status = 500, description = "Execution failed", body = ApiErrorResponse)
    )
)]
pub async fn exec_command(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
    Json(req): Json<ExecRequest>,
) -> Result<Json<ExecResponse>, ApiError> {
    validate_command(&req.command)?;

    let entry = state.get_sandbox(&id)?;

    // Ensure sandbox is running and persist state to DB
    ensure_running_and_persist(&state, &id, &entry)
        .await
        .map_err(classify_ensure_running_error)?;

    let command = req.command.clone();
    let env = EnvVar::to_tuples(&req.env);
    let workdir = req.workdir.clone();
    let timeout = req.timeout_secs.map(Duration::from_secs);

    let (exit_code, stdout, stderr) =
        with_sandbox_client(&entry, move |c| c.vm_exec(command, env, workdir, timeout)).await?;

    Ok(Json(ExecResponse {
        exit_code,
        stdout,
        stderr,
    }))
}

/// Run a command in an image.
///
/// This creates a temporary overlay from the image and runs the command.
#[utoipa::path(
    post,
    path = "/api/v1/sandboxes/{id}/run",
    tag = "Execution",
    params(
        ("id" = String, Path, description = "Sandbox name")
    ),
    request_body = RunRequest,
    responses(
        (status = 200, description = "Command executed", body = ExecResponse),
        (status = 400, description = "Invalid request", body = ApiErrorResponse),
        (status = 404, description = "Sandbox not found", body = ApiErrorResponse),
        (status = 500, description = "Execution failed", body = ApiErrorResponse)
    )
)]
pub async fn run_command(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
    Json(req): Json<RunRequest>,
) -> Result<Json<ExecResponse>, ApiError> {
    validate_command(&req.command)?;

    let entry = state.get_sandbox(&id)?;

    // Ensure sandbox is running and persist state to DB
    ensure_running_and_persist(&state, &id, &entry)
        .await
        .map_err(classify_ensure_running_error)?;

    let image = req.image.clone();
    let command = req.command.clone();
    let env = EnvVar::to_tuples(&req.env);
    let workdir = req.workdir.clone();
    let timeout = req.timeout_secs.map(Duration::from_secs);

    // Get mounts from sandbox config (converted to protocol format)
    let mounts_config = {
        let entry = entry.lock();
        entry
            .mounts
            .iter()
            .enumerate()
            .map(|(i, m)| {
                let tag = crate::agent::mount_tag(i);
                (tag, m.target.clone(), m.readonly)
            })
            .collect::<Vec<_>>()
    };

    let (exit_code, stdout, stderr) = with_sandbox_client(&entry, move |c| {
        c.run_with_mounts_and_timeout(&image, command, env, workdir, mounts_config, timeout)
    })
    .await?;

    Ok(Json(ExecResponse {
        exit_code,
        stdout,
        stderr,
    }))
}

/// Maximum number of concurrent log-follow SSE streams.
/// Each follower polls via `spawn_blocking` every 100ms, so capping concurrency
/// prevents blocking-pool saturation under high follower counts.
static LOG_FOLLOW_SEMAPHORE: std::sync::LazyLock<Semaphore> =
    std::sync::LazyLock::new(|| Semaphore::new(16));

/// Stream sandbox console logs via SSE.
#[utoipa::path(
    get,
    path = "/api/v1/sandboxes/{id}/logs",
    tag = "Logs",
    params(
        ("id" = String, Path, description = "Sandbox name"),
        ("follow" = Option<bool>, Query, description = "Follow the logs (like tail -f)"),
        ("tail" = Option<usize>, Query, description = "Number of lines to show from the end")
    ),
    responses(
        (status = 200, description = "Log stream (SSE)", content_type = "text/event-stream"),
        (status = 404, description = "Sandbox or log file not found", body = ApiErrorResponse)
    )
)]
pub async fn stream_logs(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
    Query(query): Query<LogsQuery>,
) -> Result<Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>>, ApiError> {
    let entry = state.get_sandbox(&id)?;

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
const MAX_PARTIAL_LINE: usize = 1024 * 1024;

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
