//! Regression test for <https://github.com/Eugeny/russh/issues/774>
#![cfg(unix)]

use std::io::Write;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::OwnedFd;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::keys::ssh_key::{self, LineEnding};
use russh::keys::{PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{ChannelMsg, client, server};
use tokio::process::{Child, Command};
use tokio::task::JoinHandle;

struct Client;

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

struct Server;

impl server::Handler for Server {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _key: server::VerifiedPublicKey<'_>,
    ) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _channel: russh::Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn agent_request(
        &mut self,
        _channel: russh::ChannelId,
        _session: &mut server::Session,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

async fn reply_is_channel_scoped(mut channel: russh::Channel<client::Msg>) -> bool {
    channel.agent_forward(true).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async move {
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Success) | Some(ChannelMsg::Failure) => return true,
                Some(_) => continue,
                None => return false,
            }
        }
    })
    .await
    .unwrap_or(false)
}

impl Server {
    async fn spawn_and_connect() -> (JoinHandle<()>, client::Handle<Client>) {
        let mut config = server::Config::default();
        config
            .keys
            .push(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());
        let config = Arc::new(config);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let _ = server::run_stream(config, socket, Server).await;
        });

        let mut handle = client::connect(Arc::new(client::Config::default()), addr, Client)
            .await
            .unwrap();
        let key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        handle
            .authenticate_publickey("user", PrivateKeyWithHashAlg::new(Arc::new(key), None))
            .await
            .unwrap();

        (server, handle)
    }
}

struct Sshd {
    listener: tokio::net::TcpListener,
    addr: SocketAddr,
    config_path: PathBuf,
    client_key: Arc<PrivateKey>,
    user: String,
    child: Mutex<Option<Child>>,
}

impl Sshd {
    async fn spawn(dir: &Path) -> Self {
        let host_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let client_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();

        let host_path = dir.join("host_key");
        std::fs::write(
            &host_path,
            host_key.to_openssh(LineEnding::LF).unwrap().as_bytes(),
        )
        .unwrap();
        std::fs::set_permissions(&host_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let authorized = dir.join("authorized_keys");
        std::fs::write(&authorized, client_key.public_key().to_openssh().unwrap()).unwrap();

        let config_path = dir.join("sshd_config");
        let mut config_file = std::fs::File::create(&config_path).unwrap();
        write!(
            config_file,
            "\
HostKey {host}
AuthorizedKeysFile {ak}
PasswordAuthentication no
PubkeyAuthentication yes
UsePAM no
StrictModes no
AllowAgentForwarding yes
",
            host = host_path.display(),
            ak = authorized.display(),
        )
        .unwrap();
        drop(config_file);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let user = String::from_utf8(Command::new("id").arg("-un").output().await.unwrap().stdout)
            .unwrap()
            .trim()
            .to_string();

        Sshd {
            listener,
            addr,
            config_path,
            client_key: Arc::new(client_key),
            user,
            child: Mutex::new(None),
        }
    }

    async fn connect(&self) -> client::Handle<Client> {
        let accept = async {
            let (socket, _) = self.listener.accept().await.unwrap();
            let socket = socket.into_std().unwrap();
            socket.set_nonblocking(false).unwrap();
            let stdout = socket.try_clone().unwrap();
            Command::new("/usr/sbin/sshd")
                .arg("-i")
                .arg("-f")
                .arg(&self.config_path)
                .stdin(Stdio::from(OwnedFd::from(socket)))
                .stdout(Stdio::from(OwnedFd::from(stdout)))
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .unwrap()
        };
        let connect = client::connect(Arc::new(client::Config::default()), self.addr, Client);
        let (child, handle) = tokio::join!(accept, connect);
        *self.child.lock().unwrap() = Some(child);

        let mut handle = handle.unwrap();
        handle
            .authenticate_publickey(
                self.user.clone(),
                PrivateKeyWithHashAlg::new(self.client_key.clone(), None),
            )
            .await
            .unwrap();
        handle
    }
}

#[tokio::test]
async fn russh_matches_openssh() {
    let dir = tempfile::tempdir().unwrap();
    let sshd = Sshd::spawn(dir.path()).await;
    let (_server, russh) = Server::spawn_and_connect().await;
    let openssh = sshd.connect().await;

    let russh_channel = russh.channel_open_session().await.unwrap();
    let openssh_channel = openssh.channel_open_session().await.unwrap();

    let (russh_scoped, openssh_scoped) = tokio::join!(
        reply_is_channel_scoped(russh_channel),
        reply_is_channel_scoped(openssh_channel),
    );
    assert!(
        openssh_scoped,
        "reference sshd did not reply on the channel"
    );
    assert_eq!(russh_scoped, openssh_scoped);
}
