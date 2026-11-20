//! Streams of the Docker API: multiplexed frames and hijacked connections.
//!
//! `attach` and `exec start` take over the HTTP connection. A client that
//! asks for an upgrade (`Connection: Upgrade`, `Upgrade: tcp`, which the
//! docker CLI, docker-py, dockerode and docker-java send) gets `101` and a raw
//! two-way stream. A client that does not gets a normal streaming response
//! carrying the output only.

use axum::body::{Body, Bytes};
use axum::extract::Request;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::Response;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Raw output of a process with a TTY.
pub(crate) const RAW: &str = "application/vnd.docker.raw-stream";
/// Output of a process without a TTY, framed per stream.
pub(crate) const MULTIPLEXED: &str = "application/vnd.docker.multiplexed-stream";

/// One frame of a multiplexed stream: `[stream, 0, 0, 0, len_be32]` + payload.
pub(crate) fn frame(stream: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + payload.len());
    out.extend_from_slice(&[stream, 0, 0, 0]);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Where a hijacked session's output goes.
pub(crate) enum Sink {
    Raw(
        Box<dyn AsyncWrite + Unpin + Send>,
        Option<super::supervisor::Peer>,
    ),
    Body(tokio::sync::mpsc::Sender<Result<Bytes, std::io::Error>>),
}

impl Sink {
    pub(crate) async fn closed(&mut self) {
        match self {
            Sink::Raw(_, Some(peer)) => peer.closed().await,
            Sink::Raw(_, None) => std::future::pending().await,
            Sink::Body(tx) => tx.closed().await,
        }
    }

    /// Write `bytes`; `false` once the client has gone.
    pub(crate) async fn write(&mut self, bytes: Vec<u8>) -> bool {
        match self {
            Sink::Raw(w, _) => w.write_all(&bytes).await.is_ok() && w.flush().await.is_ok(),
            Sink::Body(tx) => tx.send(Ok(Bytes::from(bytes))).await.is_ok(),
        }
    }

    pub(crate) async fn close(self) {
        if let Sink::Raw(mut w, _) = self {
            let _ = w.shutdown().await;
        }
    }
}

/// A hijacked session: the client's input (when it upgraded) and its output.
pub(crate) struct Session {
    pub(crate) _activity: Option<super::supervisor::ActivityGuard>,
    pub input: Option<Box<dyn AsyncRead + Unpin + Send>>,
    pub output: Sink,
}

/// Whether the client asked to upgrade the connection.
pub(crate) fn wants_upgrade(req: &Request) -> bool {
    let connection_upgrade = req
        .headers()
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| {
            v.split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
        });
    connection_upgrade && req.headers().contains_key(header::UPGRADE)
}

/// Take over `req`'s connection. Returns the response to send and a future
/// that resolves to the session once the client has it.
pub(crate) fn hijack(
    mut req: Request,
    content_type: &'static str,
) -> (
    Response,
    std::pin::Pin<Box<dyn std::future::Future<Output = Option<Session>> + Send>>,
) {
    let peer = req
        .extensions()
        .get::<axum::extract::ConnectInfo<super::supervisor::Peer>>()
        .map(|p| p.0.clone());
    let activity = req
        .extensions()
        .get::<std::sync::Arc<super::supervisor::Activity>>()
        .map(|a| a.hold());
    if wants_upgrade(&req) {
        let on_upgrade = hyper::upgrade::on(&mut req);
        let response = Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header(header::CONTENT_TYPE, content_type)
            .header(header::CONNECTION, "Upgrade")
            .header(header::UPGRADE, "tcp")
            .body(Body::empty())
            .expect("static response");
        let session = Box::pin(async move {
            let upgraded = on_upgrade.await.ok()?;
            let io = hyper_util::rt::TokioIo::new(upgraded);
            let (r, w) = tokio::io::split(io);
            Some(Session {
                _activity: activity,
                input: Some(Box::new(r) as Box<dyn AsyncRead + Unpin + Send>),
                output: Sink::Raw(Box::new(w), peer),
            })
        });
        (response, session)
    } else {
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(64);
        let body = Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(rx));
        let mut response = Response::new(body);
        response
            .headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
        let session = Box::pin(async move {
            Some(Session {
                _activity: activity,
                input: None,
                output: Sink::Body(tx),
            })
        });
        (response, session)
    }
}

/// The reader belongs to an execution, not its output attachment. A client
/// can close after writing buffered stdin: keep draining those accepted bytes
/// before EOF even if the output side has already noticed the disconnect.
/// The generation's closed signal cancels the reader when its process exits.
pub(crate) fn forward_input(
    input: Box<dyn AsyncRead + Unpin + Send>,
    sender: super::runtime::InputSender,
    close_stdin: bool,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(read_input(input, sender, close_stdin))
}

/// Await queue capacity before reading more socket data. This carries guest
/// backpressure all the way to the Docker client's write, without dropping bytes.
async fn read_input(
    mut input: Box<dyn AsyncRead + Unpin + Send>,
    sender: super::runtime::InputSender,
    close_stdin: bool,
) {
    use super::runtime::Input;
    let forward = async {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            match input.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if sender.send(Input::Data(buf[..n].to_vec())).await.is_err() {
                        return;
                    }
                }
            }
        }
        if close_stdin {
            let _ = sender.send(Input::Eof).await;
        }
    };
    tokio::select! {
        _ = sender.closed() => {},
        _ = forward => {},
    }
}

/// A streaming JSON-lines response body fed by the returned sender.
pub(crate) fn json_lines() -> (tokio::sync::mpsc::Sender<serde_json::Value>, Body) {
    let (tx, rx) = tokio::sync::mpsc::channel::<serde_json::Value>(64);
    let stream = tokio_stream::wrappers::ReceiverStream::new(rx).map(|v| {
        let mut line = serde_json::to_vec(&v).unwrap_or_default();
        line.push(b'\n');
        Ok::<_, std::io::Error>(Bytes::from(line))
    });
    (tx, Body::from_stream(stream))
}

use tokio_stream::StreamExt as _;

#[cfg(test)]
mod tests {
    use super::super::runtime::{Input, InputQueue};
    use super::*;
    use std::time::Duration;
    use tokio::time::timeout;

    #[tokio::test]
    async fn socket_input_backpressure_preserves_large_binary_stream_and_eof() {
        let queue = InputQueue::default();
        let (mut client, server) = tokio::io::duplex(1024);
        let data: Vec<u8> = (0..2 * 1024 * 1024).map(|n| (n % 251) as u8).collect();
        let sent = data.clone();
        let mut writer = tokio::spawn(async move {
            client.write_all(&sent).await.unwrap();
            client.shutdown().await.unwrap();
        });
        let mut reader = forward_input(Box::new(server), queue.sender(), true);
        assert!(timeout(Duration::from_millis(30), &mut writer)
            .await
            .is_err());
        let received = timeout(Duration::from_secs(5), async {
            let mut bytes = Vec::new();
            loop {
                match queue.next().await {
                    Input::Data(data) => bytes.extend(data),
                    Input::Eof => break bytes,
                    Input::Resize { .. } => panic!("unexpected resize"),
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(received, data);
        writer.await.unwrap();
        (&mut reader).await.unwrap();
    }

    #[tokio::test]
    async fn execution_end_releases_a_socket_reader_without_waiting_for_client_eof() {
        let queue = InputQueue::default();
        let (mut client, server) = tokio::io::duplex(1024);
        let mut reader = forward_input(Box::new(server), queue.sender(), true);
        queue.finish();
        timeout(Duration::from_secs(1), &mut reader)
            .await
            .unwrap()
            .unwrap();
        assert!(client.write_all(b"old execution").await.is_err());
        queue
            .sender()
            .send(Input::Data(b"new".to_vec()))
            .await
            .unwrap();
        assert!(matches!(queue.next().await, Input::Data(b) if b == b"new"));
    }

    #[tokio::test]
    async fn disconnect_drains_accepted_stdin_before_eof_even_after_output_detaches() {
        let queue = InputQueue::default();
        let (mut client, server) = tokio::io::duplex(512 * 1024);
        let data = vec![42; 512 * 1024];
        client.write_all(&data).await.unwrap();
        drop(client);
        let reader = forward_input(Box::new(server), queue.sender(), true);
        // The output attachment may observe full connection close first.
        // Its handle dropping must not truncate bytes already in the socket.
        drop(reader);
        let received = timeout(Duration::from_secs(5), async {
            let mut bytes = Vec::new();
            loop {
                match queue.next().await {
                    Input::Data(data) => bytes.extend(data),
                    Input::Eof => break bytes,
                    Input::Resize { .. } => panic!("unexpected resize"),
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(received, data);
    }

    #[test]
    fn frame_header_names_stream_and_length() {
        assert_eq!(frame(1, b"abc"), [1, 0, 0, 0, 0, 0, 0, 3, b'a', b'b', b'c']);
    }

    #[test]
    fn upgrade_needs_both_headers() {
        let req = Request::builder()
            .header("Connection", "Upgrade")
            .header("Upgrade", "tcp")
            .body(Body::empty())
            .unwrap();
        assert!(wants_upgrade(&req));
        let req = Request::builder()
            .header("Connection", "keep-alive")
            .body(Body::empty())
            .unwrap();
        assert!(!wants_upgrade(&req));
    }
}
