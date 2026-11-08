//! Talking to a container's agent: an async connection speaking the agent's
//! framed JSON protocol, the pump that carries a running container's I/O,
//! and commands run inside a running container.

use std::path::Path;

use smolvm_protocol::{AgentRequest, AgentResponse};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;

/// Largest response frame accepted from an agent.
const MAX_FRAME: usize = 64 << 20;

/// The reading half of an agent connection.
pub(crate) struct AgentReader(OwnedReadHalf);

/// The writing half of an agent connection.
pub(crate) struct AgentWriter(OwnedWriteHalf);

/// Open a connection to the agent listening on `socket`.
pub(crate) async fn connect(socket: &Path) -> std::io::Result<(AgentReader, AgentWriter)> {
    let stream = UnixStream::connect(socket).await?;
    let (r, w) = stream.into_split();
    Ok((AgentReader(r), AgentWriter(w)))
}

impl AgentWriter {
    pub(crate) async fn send(&mut self, request: &AgentRequest) -> std::io::Result<()> {
        let frame = smolvm_protocol::encode_message(request)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        self.0.write_all(&frame).await?;
        self.0.flush().await
    }
}

impl AgentReader {
    pub(crate) async fn recv(&mut self) -> std::io::Result<AgentResponse> {
        let mut header = [0u8; 4];
        self.0.read_exact(&mut header).await?;
        let len = u32::from_be_bytes(header) as usize;
        if len > MAX_FRAME {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("agent frame of {len} bytes is too large"),
            ));
        }
        let mut body = vec![0u8; len];
        self.0.read_exact(&mut body).await?;
        serde_json::from_slice(&body)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

/// Send one request on a fresh connection and return the agent's reply.
pub(crate) async fn request(
    socket: &Path,
    request: &AgentRequest,
) -> std::io::Result<AgentResponse> {
    let (mut r, mut w) = connect(socket).await?;
    w.send(request).await?;
    tokio::time::timeout(std::time::Duration::from_secs(30), r.recv())
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "agent did not answer"))?
}

/// The error text of an agent reply, if it is an error.
pub(crate) fn error_text(response: &AgentResponse) -> Option<String> {
    match response {
        AgentResponse::Error { message, .. } => Some(message.clone()),
        _ => None,
    }
}

/// One piece of a running process's output.
#[derive(Debug, Clone)]
pub(crate) enum Output {
    /// Bytes on stdout (1) or stderr (2).
    Data(u8, axum::body::Bytes),
    /// The process exited; no more output follows.
    End,
}

/// Input for a running process.
#[derive(Debug, Clone)]
pub(crate) enum Input {
    Data(Vec<u8>),
    /// Close the process's stdin.
    Eof,
    /// Resize its terminal.
    Resize {
        cols: u16,
        rows: u16,
    },
}

/// A queue of input for a container's process that outlives any one run, so
/// input written by a client attached before the start is not lost.
#[derive(Default)]
pub(crate) struct InputQueue {
    queue: parking_lot::Mutex<std::collections::VecDeque<Input>>,
    notify: tokio::sync::Notify,
}

impl InputQueue {
    pub(crate) fn push(&self, input: Input) {
        self.queue.lock().push_back(input);
        self.notify.notify_one();
    }

    pub(crate) async fn next(&self) -> Input {
        loop {
            let notified = self.notify.notified();
            if let Some(input) = self.queue.lock().pop_front() {
                return input;
            }
            notified.await;
        }
    }
}

impl Input {
    pub(crate) fn into_request(self) -> AgentRequest {
        match self {
            Input::Data(data) => AgentRequest::Stdin { data },
            Input::Eof => AgentRequest::Stdin { data: Vec::new() },
            Input::Resize { cols, rows } => AgentRequest::Resize { cols, rows },
        }
    }
}

/// How a process run through the agent ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Exit {
    pub code: i64,
    pub oom: bool,
}

/// Carry a started process's I/O until it exits: output goes to `on_output`,
/// input comes from `input`. An agent that goes away without reporting an
/// exit (the machine died) ends the process with 137.
pub(crate) async fn pump(
    mut reader: AgentReader,
    mut writer: AgentWriter,
    input: &InputQueue,
    mut on_output: impl FnMut(u8, Vec<u8>),
) -> Exit {
    let mut input_open = true;
    loop {
        tokio::select! {
            frame = reader.recv() => match frame {
                Ok(AgentResponse::Stdout { data }) => on_output(1, data),
                Ok(AgentResponse::Stderr { data }) => on_output(2, data),
                Ok(AgentResponse::Exited { exit_code, oom }) => {
                    return Exit { code: exit_code as i64, oom };
                }
                Ok(AgentResponse::Error { message, .. }) => {
                    on_output(2, format!("{message}\n").into_bytes());
                    return Exit { code: 126, oom: false };
                }
                Ok(_) => {}
                Err(_) => return Exit { code: 137, oom: false },
            },
            next = input.next(), if input_open => {
                if writer.send(&next.into_request()).await.is_err() {
                    input_open = false;
                }
            }
        }
    }
}
