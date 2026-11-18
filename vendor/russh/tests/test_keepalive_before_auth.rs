use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use russh::keys::{PrivateKey, PublicKeyOrCertificate};
use russh::{client, server};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

struct AcceptTestServerKey;

impl client::Handler for AcceptTestServerKey {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

struct TestServer;

impl server::Handler for TestServer {
    type Error = russh::Error;
}

/// Counts how many times the client session polls its socket for reading.
/// Every pass of the session loop polls the pending read once, so the count
/// tracks how often the loop wakes up.
struct CountingStream {
    inner: TcpStream,
    reads: Arc<AtomicUsize>,
}

impl AsyncRead for CountingStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for CountingStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Starts a server on a local port and connects a client to it with the
/// given config, counting the client's socket reads. The client completes key
/// exchange but does not authenticate.
async fn connect_unauthenticated(
    client_config: client::Config,
) -> (
    client::Handle<AcceptTestServerKey>,
    Arc<AtomicUsize>,
    tokio::task::JoinHandle<Result<(), russh::Error>>,
) {
    let mut server_config = server::Config::default();
    server_config.inactivity_timeout = None;
    server_config.keys.push(
        PrivateKey::random(&mut rand::rng(), russh::keys::ssh_key::Algorithm::Ed25519).unwrap(),
    );
    let server_config = Arc::new(server_config);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let running = server::run_stream(server_config, socket, TestServer)
            .await
            .unwrap();
        running.await
    });

    let reads = Arc::new(AtomicUsize::new(0));
    let stream = CountingStream {
        inner: TcpStream::connect(addr).await.unwrap(),
        reads: reads.clone(),
    };
    let session = client::connect_stream(Arc::new(client_config), stream, AcceptTestServerKey)
        .await
        .unwrap();
    (session, reads, server)
}

/// While the client waits before authenticating (e.g. for the user to type a
/// password), an elapsed keepalive timer must be re-armed rather than left
/// expired, or the session loop wakes up continuously and burns a CPU core.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keepalive_timer_does_not_spin_before_authentication() {
    let _ = env_logger::try_init();

    let keepalive_interval = Duration::from_millis(50);
    let (session, reads, server) = connect_unauthenticated(client::Config {
        keepalive_interval: Some(keepalive_interval),
        ..Default::default()
    })
    .await;

    // Key exchange is done but the client has not authenticated, so no
    // keepalives are sent. Let the timer elapse about ten times.
    let before = reads.load(Ordering::Relaxed);
    tokio::time::sleep(keepalive_interval * 10).await;
    let polls = reads.load(Ordering::Relaxed) - before;

    // A re-armed timer wakes the loop about once per interval; an expired one
    // wakes it as fast as the runtime can poll it.
    assert!(
        polls < 100,
        "session loop polled the socket {polls} times in {:?} before authentication",
        keepalive_interval * 10
    );

    drop(session);
    server.abort();
}

/// Elapsed keepalive timers are not activity: an idle client that has not
/// authenticated still hits its inactivity timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inactivity_timeout_applies_before_authentication() {
    let _ = env_logger::try_init();

    let (session, _, server) = connect_unauthenticated(client::Config {
        keepalive_interval: Some(Duration::from_millis(50)),
        inactivity_timeout: Some(Duration::from_millis(300)),
        ..Default::default()
    })
    .await;

    let result = tokio::time::timeout(Duration::from_secs(5), session)
        .await
        .expect("session did not end within 5s despite a 300ms inactivity timeout");
    assert!(
        matches!(result, Err(russh::Error::InactivityTimeout)),
        "unexpected session result: {result:?}"
    );

    server.abort();
}
