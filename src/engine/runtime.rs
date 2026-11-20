//! Talking to a container's agent: an async connection speaking the agent's
//! negotiated framed protocol, the pump that carries a running container's I/O,
//! and commands run inside a running container.

use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use smolvm_protocol::{AgentRequest, AgentResponse};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;

/// Largest response frame accepted from an agent.
const MAX_FRAME: usize = 64 << 20;

/// The reading half of an agent connection.
pub(crate) struct AgentReader(OwnedReadHalf, Arc<AtomicBool>);

/// The writing half of an agent connection.
pub(crate) struct AgentWriter(OwnedWriteHalf, Arc<AtomicBool>);

/// Open a connection to the agent listening on `socket`.
pub(crate) async fn connect(socket: &Path) -> std::io::Result<(AgentReader, AgentWriter)> {
    let stream = UnixStream::connect(socket).await?;
    let (r, w) = stream.into_split();
    let binary = Arc::new(AtomicBool::new(false));
    Ok((AgentReader(r, binary.clone()), AgentWriter(w, binary)))
}

impl AgentWriter {
    pub(crate) async fn send(&mut self, request: &AgentRequest) -> std::io::Result<()> {
        let binary = if self.1.load(Ordering::Acquire) {
            smolvm_protocol::binary_stream::encode_request(request, None)?
        } else {
            None
        };
        let frame = if let Some(frame) = binary {
            frame
        } else {
            let mut envelope = smolvm_protocol::Envelope::new(request);
            envelope.binary_stream = Some(smolvm_protocol::binary_stream::VERSION);
            smolvm_protocol::encode_message(&envelope)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?
        };
        self.0.write_all(&frame).await?;
        self.0.flush().await
    }
}

impl AgentReader {
    pub(crate) async fn recv(&mut self) -> std::io::Result<AgentResponse> {
        self.recv_limited(MAX_FRAME).await
    }

    /// A caller with a bounded streaming protocol can impose a smaller limit.
    pub(crate) async fn recv_limited(&mut self, limit: usize) -> std::io::Result<AgentResponse> {
        let mut header = [0u8; 4];
        self.0.read_exact(&mut header).await?;
        let len = u32::from_be_bytes(header) as usize;
        if len == 0 || len > limit.min(MAX_FRAME) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("agent frame of {len} bytes is too large"),
            ));
        }
        let mut body = vec![0u8; len];
        self.0.read_exact(&mut body).await?;
        let (response, binary) = smolvm_protocol::binary_stream::decode_response(&body)?;
        if binary {
            self.1.store(true, Ordering::Release);
        }
        Ok(response)
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

/// Negotiate a raw app stream without buffering past the final response frame.
pub(crate) async fn app_connect(
    socket: &Path,
    overlay: &str,
    port: u16,
) -> super::util::ApiResult<UnixStream> {
    let (mut reader, mut writer) = connect(socket)
        .await
        .map_err(|e| super::util::ApiError::internal(e.to_string()))?;
    writer
        .send(&AgentRequest::ContainerPortConnect {
            overlay_id: overlay.into(),
            port,
        })
        .await
        .map_err(|e| super::util::ApiError::internal(e.to_string()))?;
    let reply = reader
        .recv()
        .await
        .map_err(|e| super::util::ApiError::internal(e.to_string()))?;
    super::app_ports::confirmed(reply)?;
    reader
        .0
        .reunite(writer.0)
        .map_err(|e| super::util::ApiError::internal(e.to_string()))
}

pub(crate) async fn listener_watch(socket: &Path) -> std::io::Result<UnixStream> {
    let (mut reader, mut writer) = connect(socket).await?;
    writer.send(&AgentRequest::WatchListeners).await?;
    match reader.recv().await? {
        AgentResponse::Ok { data: Some(data) } if data["protocol"] == "smol-listener-watch-v1" => {}
        AgentResponse::Error { code, .. }
            if code.as_deref() == Some(smolvm_protocol::error_codes::INVALID_REQUEST) =>
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Guest listener notifications require a newer runtime",
            ));
        }
        _ => {
            return Err(std::io::Error::other(
                "Guest did not confirm listener notifications",
            ))
        }
    }
    reader.0.reunite(writer.0).map_err(std::io::Error::other)
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

#[cfg(test)]
mod exec_io_tests;
mod input;
pub(crate) use input::{InputQueue, InputSender};

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

/// Streaming replies carry at most 64 KiB of output in current guests. Allow
/// room for the legacy JSON byte-array encoding while bounding frame allocation.
pub(crate) const STREAM_FRAME_LIMIT: usize = 512 * 1024;
const OUTPUT_CHUNK: usize = 64 * 1024;

async fn deliver<F, Fut>(on_output: &mut F, stream: u8, data: Vec<u8>)
where
    F: FnMut(u8, Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    if data.is_empty() {
        return;
    }
    if data.len() <= OUTPUT_CHUNK {
        on_output(stream, data).await;
    } else {
        for bytes in data.chunks(OUTPUT_CHUNK) {
            on_output(stream, bytes.to_vec()).await;
        }
    }
}

/// Carry an exec's I/O until the guest reports its exit. Output delivery is
/// awaited, so a slow client backpressures the guest instead of growing a queue.
/// A lost transport is an error, never an invented process exit status.
pub(crate) async fn pump<F, Fut>(
    mut reader: AgentReader,
    mut writer: AgentWriter,
    input: &InputQueue,
    mut on_output: F,
) -> std::io::Result<Exit>
where
    F: FnMut(u8, Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    // Input and output run concurrently: an echoing process or buildctl tunnel
    // must still receive stdin while delivery of earlier output is blocked.
    let forward = async {
        loop {
            let next = input.next().await;
            if writer.send(&next.into_request()).await.is_err() {
                // Exit can race stdin. Let the reader consume its actual status.
                std::future::pending::<()>().await;
            }
        }
    };
    let receive = async {
        loop {
            match reader.recv_limited(STREAM_FRAME_LIMIT).await? {
                AgentResponse::Stdout { data } => deliver(&mut on_output, 1, data).await,
                AgentResponse::Stderr { data } => deliver(&mut on_output, 2, data).await,
                AgentResponse::Exited { exit_code, oom } => {
                    return Ok(Exit {
                        code: exit_code as i64,
                        oom,
                    });
                }
                AgentResponse::Error { message, .. } => {
                    return Err(std::io::Error::other(message));
                }
                _ => {}
            }
        }
    };
    tokio::pin!(forward);
    tokio::select! {
        exit = receive => exit,
        _ = &mut forward => unreachable!("input forwarding never ends on its own"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn split_connection_negotiates_binary_and_keeps_legacy_peers_working() {
        for binary in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("agent.sock");
            let listener = tokio::net::UnixListener::bind(&path).unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let size = stream.read_u32().await.unwrap();
                let mut body = vec![0; size as usize];
                stream.read_exact(&mut body).await.unwrap();
                let request: smolvm_protocol::Envelope<AgentRequest> =
                    serde_json::from_slice(&body).unwrap();
                assert_eq!(request.binary_stream, Some(1));
                let mut response = smolvm_protocol::Envelope::new(AgentResponse::Started);
                if binary {
                    response.binary_stream = Some(1);
                }
                stream
                    .write_all(&smolvm_protocol::encode_message(&response).unwrap())
                    .await
                    .unwrap();
                let size = stream.read_u32().await.unwrap();
                let mut body = vec![0; size as usize];
                stream.read_exact(&mut body).await.unwrap();
                assert_eq!(body[0] == 0, binary);
                assert!(
                    matches!(smolvm_protocol::binary_stream::decode_request(&body).unwrap().body,
                    AgentRequest::Stdin { data } if data == [0, 255, 10])
                );
                let output = AgentResponse::Stderr {
                    data: vec![0, 255, 10],
                };
                let mut frame = Vec::new();
                if binary {
                    smolvm_protocol::binary_stream::write_response(&mut frame, &output).unwrap();
                } else {
                    frame = smolvm_protocol::encode_message(&output).unwrap();
                }
                for byte in frame {
                    stream.write_all(&[byte]).await.unwrap();
                }
            });
            let (mut reader, mut writer) = connect(&path).await.unwrap();
            writer.send(&AgentRequest::Ping).await.unwrap();
            assert!(matches!(
                reader.recv().await.unwrap(),
                AgentResponse::Started
            ));
            writer
                .send(&AgentRequest::Stdin {
                    data: vec![0, 255, 10],
                })
                .await
                .unwrap();
            assert!(
                matches!(reader.recv().await.unwrap(), AgentResponse::Stderr { data } if data == [0, 255, 10])
            );
            server.await.unwrap();
        }
    }
}
