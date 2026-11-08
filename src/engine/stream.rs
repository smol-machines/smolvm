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
    Raw(Box<dyn AsyncWrite + Unpin + Send>),
    Body(tokio::sync::mpsc::Sender<Result<Bytes, std::io::Error>>),
}

impl Sink {
    /// Write `bytes`; `false` once the client has gone.
    pub(crate) async fn write(&mut self, bytes: Vec<u8>) -> bool {
        match self {
            Sink::Raw(w) => w.write_all(&bytes).await.is_ok() && w.flush().await.is_ok(),
            Sink::Body(tx) => tx.send(Ok(Bytes::from(bytes))).await.is_ok(),
        }
    }

    pub(crate) async fn close(self) {
        if let Sink::Raw(mut w) = self {
            let _ = w.shutdown().await;
        }
    }
}

/// A hijacked session: the client's input (when it upgraded) and its output.
pub(crate) struct Session {
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
                input: Some(Box::new(r) as Box<dyn AsyncRead + Unpin + Send>),
                output: Sink::Raw(Box::new(w)),
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
                input: None,
                output: Sink::Body(tx),
            })
        });
        (response, session)
    }
}

/// Read the client's input until it closes, handing each piece to `f`.
pub(crate) async fn read_input(
    mut input: Box<dyn AsyncRead + Unpin + Send>,
    mut f: impl FnMut(Vec<u8>),
) {
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        match input.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => f(buf[..n].to_vec()),
        }
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
    use super::*;

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
