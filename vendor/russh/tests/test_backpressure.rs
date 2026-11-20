use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;

use futures::FutureExt;
use russh::keys::{PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::server::{self, Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelMsg, client};
use ssh_key::PrivateKey;
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, watch};
use tokio::time::{Duration, sleep, timeout};

pub const WINDOW_SIZE: usize = 8 * 2048;
pub const CHANNEL_BUFFER_SIZE: usize = 10;
const HANDLE_DATA_COUNT: usize = 64;

#[tokio::test]
async fn test_backpressure() -> Result<(), anyhow::Error> {
    env_logger::init();

    let addr = addr();
    let data = data();
    let (tx, rx) = watch::channel(());

    tokio::spawn(Server::run(addr, rx));

    // Wait until the server is started
    while TcpStream::connect(addr).is_err() {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    stream(addr, &data, tx).await?;

    Ok(())
}

#[tokio::test]
async fn server_handle_data_backpressures_when_client_stops_reading() -> Result<(), anyhow::Error> {
    let addr = addr();
    let (progress_tx, mut progress_rx) = mpsc::unbounded_channel();

    tokio::spawn(HandleBackpressureServer::run(addr, progress_tx));

    while TcpStream::connect(addr).is_err() {
        sleep(Duration::from_millis(10)).await;
    }

    let config = Arc::new(client::Config {
        window_size: WINDOW_SIZE as u32,
        channel_buffer_size: 1,
        ..Default::default()
    });
    let key = Arc::new(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());
    let mut session = russh::client::connect(config, addr, Client).await?;
    let mut channel = match session
        .authenticate_publickey(
            "user",
            PrivateKeyWithHashAlg::new(
                key,
                session.best_supported_rsa_hash().await.unwrap().flatten(),
            ),
        )
        .await
        .map(|x| x.success())
    {
        Ok(true) => session.channel_open_session().await?,
        Ok(false) => panic!("Authentication failed"),
        Err(err) => return Err(err.into()),
    };

    sleep(Duration::from_millis(100)).await;
    let mut accepted = 0;
    while progress_rx.try_recv().is_ok() {
        accepted += 1;
    }
    assert!(accepted < HANDLE_DATA_COUNT);

    let received = timeout(Duration::from_secs(5), async {
        let mut received = 0;
        while let Some(message) = channel.wait().await {
            match message {
                ChannelMsg::Data { data } => received += data.len(),
                ChannelMsg::Eof | ChannelMsg::Close => break,
                ChannelMsg::WindowAdjusted { .. } => {}
                other => panic!("unexpected message {other:?}"),
            }
        }
        received
    })
    .await?;

    assert_eq!(received, HANDLE_DATA_COUNT * WINDOW_SIZE);
    Ok(())
}

async fn stream(addr: SocketAddr, data: &[u8], tx: watch::Sender<()>) -> Result<(), anyhow::Error> {
    let config = Arc::new(client::Config::default());
    let key = Arc::new(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());

    let mut session = russh::client::connect(config, addr, Client).await?;
    let channel = match session
        .authenticate_publickey(
            "user",
            PrivateKeyWithHashAlg::new(
                key,
                session.best_supported_rsa_hash().await.unwrap().flatten(),
            ),
        )
        .await
        .map(|x| x.success())
    {
        Ok(true) => session.channel_open_session().await?,
        Ok(false) => panic!("Authentication failed"),
        Err(err) => return Err(err.into()),
    };

    let mut writer = channel.make_writer();

    // TCP listener will buffer one extra message
    for _ in 0..=CHANNEL_BUFFER_SIZE {
        assert!(writer.write(data).await.is_ok());
    }
    let pending_write = async { writer.write(data).await.unwrap() };
    sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(pending_write.now_or_never(), None);
    // Make space on the buffer
    tx.send(()).unwrap();
    assert!(writer.write(data).await.is_ok());

    Ok(())
}

fn data() -> Vec<u8> {
    let mut data = vec![0u8; WINDOW_SIZE]; // Check whether the window_size resizing works
    use rand::RngExt;
    rand::rng().fill(&mut data[..]);
    data
}

/// Find a unused local address to bind our server to
fn addr() -> SocketAddr {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
}

#[derive(Clone)]
struct Server {
    rx: Option<watch::Receiver<()>>,
}

impl Server {
    async fn run(addr: SocketAddr, rx: watch::Receiver<()>) {
        let config = Arc::new(server::Config {
            keys: vec![PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap()],
            window_size: WINDOW_SIZE as u32,
            channel_buffer_size: CHANNEL_BUFFER_SIZE,
            ..Default::default()
        });
        let mut sh = Server { rx: Some(rx) };

        sh.run_on_address(config, addr).await.unwrap();
    }
}

impl russh::server::Server for Server {
    type Handler = Self;

    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self::Handler {
        self.clone()
    }
}

impl russh::server::Handler for Server {
    type Error = anyhow::Error;

    async fn auth_publickey(
        &mut self,
        _: &str,
        _: server::VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        mut channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let mut rx = self.rx.take().unwrap();
        reply.accept().await;
        tokio::spawn(async move {
            while let Ok(_) = rx.changed().await {
                match channel.wait().await {
                    Some(ChannelMsg::Data { .. }) => (),
                    Some(ChannelMsg::Close) | None => break,
                    other => panic!("unexpected message {other:?}"),
                }
            }
        });

        Ok(())
    }
}

struct Client;

impl russh::client::Handler for Client {
    type Error = anyhow::Error;

    async fn check_server_key(&mut self, _: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

#[derive(Clone)]
struct HandleBackpressureServer {
    progress_tx: mpsc::UnboundedSender<usize>,
}

impl HandleBackpressureServer {
    async fn run(addr: SocketAddr, progress_tx: mpsc::UnboundedSender<usize>) {
        let config = Arc::new(server::Config {
            keys: vec![PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap()],
            event_buffer_size: 1,
            ..Default::default()
        });
        let mut server = Self { progress_tx };
        server.run_on_address(config, addr).await.unwrap();
    }
}

impl russh::server::Server for HandleBackpressureServer {
    type Handler = Self;

    fn new_client(&mut self, _: Option<SocketAddr>) -> Self::Handler {
        self.clone()
    }
}

impl russh::server::Handler for HandleBackpressureServer {
    type Error = anyhow::Error;

    async fn auth_publickey(
        &mut self,
        _: &str,
        _: server::VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let channel_id = channel.id();
        let handle = session.handle();
        let progress_tx = self.progress_tx.clone();
        reply.accept().await;
        tokio::spawn(async move {
            for index in 0..HANDLE_DATA_COUNT {
                if handle.data(channel_id, vec![0; WINDOW_SIZE]).await.is_err() {
                    return;
                }
                let _ = progress_tx.send(index);
            }
            let _ = handle.eof(channel_id).await;
        });
        Ok(())
    }
}
