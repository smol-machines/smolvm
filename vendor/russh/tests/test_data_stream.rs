use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;

use russh::keys::{PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::server::{self, Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelMsg, client};
use ssh_key::PrivateKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const WINDOW_SIZE: u32 = 8 * 2048;

trait ChannelDataCopy {
    async fn copy_data_through_channel(
        &mut self,
        channel: Channel<client::Msg>,
        data: &[u8],
    ) -> anyhow::Result<Vec<u8>>;
}

struct ReaderAndWriter;

impl ChannelDataCopy for ReaderAndWriter {
    async fn copy_data_through_channel(
        &mut self,
        mut channel: Channel<client::Msg>,
        data: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let mut buf = Vec::<u8>::new();
        let mut writer = channel.make_writer_ext(Some(1));
        let mut reader = channel.make_reader();

        let (r0, r1) = tokio::join!(
            async {
                writer.write_all(data).await?;
                writer.shutdown().await?;

                Ok::<_, anyhow::Error>(())
            },
            reader.read_to_end(&mut buf)
        );

        r0?;
        let count = r1?;
        assert_eq!(data.len(), count);

        Ok(buf)
    }
}

struct ChannelHalves;

impl ChannelDataCopy for ChannelHalves {
    async fn copy_data_through_channel(
        &mut self,
        channel: Channel<client::Msg>,
        data: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let (mut read, write) = channel.split();
        let (r0, r1) = tokio::join!(
            async {
                write.extended_data(1, data).await?;
                write.eof().await?;

                Ok::<_, anyhow::Error>(())
            },
            async {
                let mut buf = Vec::<u8>::new();
                while let Some(msg) = read.wait().await {
                    match msg {
                        ChannelMsg::WindowAdjusted { .. } => {}
                        ChannelMsg::Data { data } => buf.extend(&*data),
                        ChannelMsg::Eof | ChannelMsg::Close => break,
                        msg => panic!("Got unexpected message: {msg:?}"),
                    }
                }
                Ok(buf)
            }
        );

        r0?;
        r1
    }
}

#[tokio::test]
async fn test_reader_and_writer() -> Result<(), anyhow::Error> {
    run_test(ReaderAndWriter).await
}

#[tokio::test]
async fn test_channel_halves() -> Result<(), anyhow::Error> {
    run_test(ChannelHalves).await
}

async fn run_test(test: impl ChannelDataCopy) -> Result<(), anyhow::Error> {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(env_logger::init);

    let addr = addr();
    let data = data();

    tokio::spawn(Server::run(addr));

    // Wait until the server is started
    while TcpStream::connect(addr).is_err() {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    stream(addr, &data, test).await?;

    Ok(())
}

async fn stream(
    addr: SocketAddr,
    data: &[u8],
    mut test: impl ChannelDataCopy,
) -> Result<(), anyhow::Error> {
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

    let buf = test.copy_data_through_channel(channel, data).await?;
    assert_eq!(data, buf);

    Ok(())
}

fn data() -> Vec<u8> {
    let mut data = vec![0u8; WINDOW_SIZE as usize * 2 + 7]; // Check whether the window_size resizing works
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
struct Server;

impl Server {
    async fn run(addr: SocketAddr) {
        let config = Arc::new(server::Config {
            keys: vec![PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap()],
            window_size: WINDOW_SIZE,
            ..Default::default()
        });
        let mut sh = Server {};

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
        reply.accept().await;
        tokio::spawn(async move {
            let (mut writer, mut reader) =
                (channel.make_writer(), channel.make_reader_ext(Some(1)));

            tokio::io::copy(&mut reader, &mut writer)
                .await
                .expect("Data transfer failed");

            writer.shutdown().await.expect("Shutdown failed");
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
