use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use rand::Rng;
use russh::Channel;
use russh::client::{self, ChannelOpenHandle, Msg, Session};
use russh::keys::PublicKeyOrCertificate;
use russh::keys::key::PrivateKeyWithHashAlg;
use russh::server::{self, Auth, Server as _};
use ssh_key::PrivateKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

static DATA_SIZE: usize = 20_000_000;
static THREADS: usize = 16;

#[tokio::test(flavor = "multi_thread")]
async fn test_contention() -> Result<(), anyhow::Error> {
    env_logger::init();

    let ssh_addr = addr().await;
    let tcp_addr = addr().await;
    tokio::spawn(Server::run(ssh_addr, tcp_addr));

    while TcpStream::connect(ssh_addr).await.is_err() {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    let config = Arc::new(client::Config::default());
    let key = Arc::new(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());
    let mut data = vec![0u8; DATA_SIZE];
    rand::rng().fill_bytes(&mut data);

    let mut session =
        russh::client::connect(config, ssh_addr, Client(Bytes::from_static(data.leak()))).await?;
    if !session
        .authenticate_publickey(
            "user",
            PrivateKeyWithHashAlg::new(
                key,
                session.best_supported_rsa_hash().await.unwrap().flatten(),
            ),
        )
        .await?
        .success()
    {
        panic!("Authentication failed")
    };
    session
        .tcpip_forward("tcpip_forward", 12345)
        .await
        .expect("tcpip_forward failed");

    timeout(Duration::from_secs(30), async move {
        let mut jh_vec = vec![];
        for i in 1..=THREADS {
            let tcp_stream = TcpStream::connect(tcp_addr).await.unwrap();
            let (mut read_half, mut write_half) = tcp_stream.into_split();
            let jh = tokio::spawn(async move {
                let jh = tokio::spawn(async move {
                    write_half
                        .write_all(&(DATA_SIZE as u32).to_le_bytes()[..])
                        .await
                        .unwrap();
                });
                let mut buf = vec![0u8; DATA_SIZE];
                read_half.read_exact(&mut buf).await.unwrap();
                println!("Join handle #{i} finished");
                jh.abort();
            });
            jh_vec.push(jh);
            tokio::time::sleep(Duration::from_millis(10)).await; // Simulate delay between opening channels
        }
        for jh in jh_vec.into_iter() {
            jh.await.expect("Join handle panicked");
        }
    })
    .await
    .expect("Timeout waiting for test to finish.");

    Ok(())
}

async fn addr() -> SocketAddr {
    TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}

#[derive(Clone)]
struct Server(SocketAddr);

impl Server {
    async fn run(ssh_addr: SocketAddr, tcp_addr: SocketAddr) {
        let config = Arc::new(server::Config {
            keys: vec![PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap()],
            preferred: russh::Preferred {
                cipher: std::borrow::Cow::Borrowed(&[russh::cipher::CHACHA20_POLY1305]),
                ..Default::default()
            },
            ..Default::default()
        });
        let mut sh = Server(tcp_addr);

        sh.run_on_address(config, ssh_addr).await.unwrap();
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

    async fn tcpip_forward(
        &mut self,
        _address: &str,
        _port: &mut u32,
        session: &mut server::Session,
    ) -> Result<bool, Self::Error> {
        let tcp_addr = self.0;
        let handle = session.handle();
        tokio::spawn(async move {
            let listener = TcpListener::bind(tcp_addr).await.unwrap();
            while let Ok((mut stream, _)) = listener.accept().await {
                let handle = handle.clone();
                tokio::spawn(async move {
                    let channel = handle
                        .channel_open_forwarded_tcpip("tcpip_forward", 12345, "localhost", 23456)
                        .await
                        .unwrap();
                    copy_bidirectional(&mut stream, &mut channel.into_stream())
                        .await
                        .unwrap();
                });
            }
        });
        Ok(true)
    }
}

struct Client(Bytes);

impl russh::client::Handler for Client {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        _key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<Msg>,
        _connected_address: &str,
        _connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let bytes = self.0.clone();
        tokio::spawn(async move {
            let mut stream = channel.into_stream();
            let len = stream.read_u32_le().await.unwrap();
            stream.write_all(&bytes[..len as usize]).await.unwrap();
        });
        reply.accept().await;
        Ok(())
    }
}
