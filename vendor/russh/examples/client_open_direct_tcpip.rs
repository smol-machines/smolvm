use std::net::SocketAddr;
///
/// Run this example with:
/// cargo run --example client_open_direct_tcpip -- --private-key <private key path> --local-addr <addr:port> --forward-addr <addr:port> <host>
///
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use key::PrivateKeyWithHashAlg;
use log::info;
use russh::client::Config;
use russh::keys::*;
use russh::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    // CLI options are defined later in this file
    let cli = Cli::parse();

    info!("Connecting to server: {}:{}", cli.host, cli.port);
    info!("Key path: {:?}", cli.private_key);
    info!("OpenSSH Certificate path: {:?}", cli.openssh_certificate);

    let forward_addr: SocketAddr = cli.forward_addr.parse()?;
    let listener = TcpListener::bind(&cli.local_addr).await?;
    info!("listen on: {}", &cli.local_addr);

    // Session is a wrapper around a russh client, defined down below
    let mut ssh = Session::connect(
        cli.private_key,
        cli.openssh_certificate,
        cli.username.unwrap_or("root".to_string()),
        (cli.host.clone(), cli.port),
    )
    .await?;
    info!("Server: {}:{} Connected", cli.host, cli.port);

    let (socket, o_addr) = listener.accept().await?;
    info!("originator address: {o_addr}");
    ssh.call(socket, o_addr, forward_addr).await?;

    ssh.close().await?;

    Ok(())
}

struct Client {}

// More SSH event handlers
// can be defined in this trait
// In this example, we're only using Channel, so these aren't needed.
impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// This struct is a convenience wrapper
/// around a russh client
pub struct Session {
    session: client::Handle<Client>,
}

impl Session {
    async fn connect<P: AsRef<Path>, A: ToSocketAddrs>(
        key_path: P,
        openssh_cert_path: Option<P>,
        user: impl Into<String>,
        addrs: A,
    ) -> Result<Self> {
        let key_pair = load_secret_key(key_path, None)?;

        let config = Config {
            nodelay: true,
            ..Default::default()
        };

        // load ssh certificate
        let mut openssh_cert = None;
        if openssh_cert_path.is_some() {
            openssh_cert = Some(load_openssh_certificate(openssh_cert_path.unwrap())?);
        }

        let config = Arc::new(config);
        let sh = Client {};

        let mut session = client::connect(config, addrs, sh).await?;
        // use publickey authentication, with or without certificate
        if openssh_cert.is_none() {
            let auth_res = session
                .authenticate_publickey(
                    user,
                    PrivateKeyWithHashAlg::new(
                        Arc::new(key_pair),
                        session.best_supported_rsa_hash().await?.flatten(),
                    ),
                )
                .await?;

            if !auth_res.success() {
                anyhow::bail!("Authentication (with publickey) failed");
            }
        } else {
            let auth_res = session
                .authenticate_openssh_cert(user, Arc::new(key_pair), openssh_cert.unwrap())
                .await?;

            if !auth_res.success() {
                anyhow::bail!("Authentication (with publickey+cert) failed");
            }
        }

        Ok(Self { session })
    }

    async fn call(
        &mut self,
        mut stream: TcpStream,
        originator_addr: SocketAddr,
        forward_addr: SocketAddr,
    ) -> Result<()> {
        let mut channel = self
            .session
            .channel_open_direct_tcpip(
                forward_addr.ip().to_string(),
                forward_addr.port().into(),
                originator_addr.ip().to_string(),
                originator_addr.port().into(),
            )
            .await?;
        // There's an event available on the session channel
        let mut stream_closed = false;
        let mut buf = vec![0; 65536];
        loop {
            // Handle one of the possible events:
            tokio::select! {
                // There's socket input available from the client
                r = stream.read(&mut buf), if !stream_closed => {
                    match r {
                        Ok(0) => {
                            stream_closed = true;
                            channel.eof().await?;
                        },
                        // Send it to the server
                        Ok(n) => channel.data(&buf[..n]).await?,
                        Err(e) => return Err(e.into()),
                    };
                },
                // There's an event available on the session channel
                Some(msg) = channel.wait() => {
                    match msg {
                        // Write data to the client
                        ChannelMsg::Data { ref data } => {
                            stream.write_all(data).await?;
                        }
                        ChannelMsg::Eof => {
                            if !stream_closed {
                                channel.eof().await?;
                            }
                            break;
                        }
                        ChannelMsg::WindowAdjusted { new_size:_ }=> {
                            // Ignore this message type
                        }
                        _ => {todo!()}
                    }
                },
            }
        }
        Ok(())
    }

    async fn close(&mut self) -> Result<()> {
        self.session
            .disconnect(Disconnect::ByApplication, "", "English")
            .await?;
        Ok(())
    }
}

#[derive(clap::Parser)]
#[clap(trailing_var_arg = true)]
pub struct Cli {
    #[clap(index = 1)]
    host: String,

    #[clap(long, short, default_value_t = 22)]
    port: u16,

    #[clap(long, short = 'o')]
    openssh_certificate: Option<PathBuf>,

    #[clap(long, short)]
    username: Option<String>,

    #[clap(long, short = 'k')]
    private_key: PathBuf,

    #[clap(long, short = 'l')]
    local_addr: String,

    #[clap(long, short = 'f')]
    forward_addr: String,
}
