#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // Allow unwraps, expects and panics in the test suite

use futures::Future;

use super::*;

#[cfg(feature = "flate2")]
mod compress {
    use std::borrow::Cow;
    use std::collections::HashMap;
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use keys::PrivateKeyWithHashAlg;
    use log::debug;
    use ssh_key::PrivateKey;

    use super::server::{Server as _, Session};
    use super::*;
    use crate::cert::PublicKeyOrCertificate;
    use crate::cipher::MAXIMUM_DECOMPRESSED_PACKET_LEN;
    use crate::server::Msg;

    const OVERSIZED_DEBUG_MESSAGE_LEN: usize = MAXIMUM_DECOMPRESSED_PACKET_LEN + 1024;

    #[tokio::test]
    async fn compress_local_test() {
        let _ = env_logger::try_init();

        let client_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let mut config = server::Config::default();
        config.preferred = preferred_zlib();
        config.inactivity_timeout = None; // Some(std::time::Duration::from_secs(3));
        config.auth_rejection_time = std::time::Duration::from_secs(3);
        config
            .keys
            .push(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());
        let config = Arc::new(config);
        let mut sh = Server {
            clients: Arc::new(Mutex::new(HashMap::new())),
            id: 0,
        };

        let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();

        tokio::spawn(async move {
            let (socket, _) = socket.accept().await.unwrap();
            let server = sh.new_client(socket.peer_addr().ok());
            server::run_stream(config, socket, server).await.unwrap();
        });

        let mut config = client::Config::default();
        config.preferred = preferred_zlib();
        let config = Arc::new(config);

        let mut session = client::connect(config, addr, Client {}).await.unwrap();
        let authenticated = session
            .authenticate_publickey(
                std::env::var("USER").unwrap_or("user".to_owned()),
                PrivateKeyWithHashAlg::new(
                    Arc::new(client_key),
                    session.best_supported_rsa_hash().await.unwrap().flatten(),
                ),
            )
            .await
            .unwrap()
            .success();
        assert!(authenticated);
        let mut channel = session.channel_open_session().await.unwrap();

        let data = &b"Hello, world!"[..];
        channel.data(data).await.unwrap();
        let msg = channel.wait().await.unwrap();
        match msg {
            ChannelMsg::Data { data: msg_data } => {
                assert_eq!(*data, *msg_data)
            }
            msg => panic!("Unexpected message {msg:?}"),
        }
    }

    #[test]
    fn oversized_debug_payload_can_stay_below_wire_cap() {
        let payload = vec![b'A'; OVERSIZED_DEBUG_MESSAGE_LEN];
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        encoder.write_all(&payload).unwrap();
        let compressed = encoder.finish().unwrap();

        assert!(
            compressed.len() < 256 * 1024,
            "attacker-crafted compressed payload should stay below the normal SSH wire cap"
        );
    }

    #[derive(Clone)]
    struct Server {
        clients: Arc<Mutex<HashMap<(usize, ChannelId), super::server::Handle>>>,
        id: usize,
    }

    impl server::Server for Server {
        type Handler = Self;
        fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
            let s = self.clone();
            self.id += 1;
            s
        }
    }

    impl server::Handler for Server {
        type Error = super::Error;

        async fn channel_open_session(
            &mut self,
            channel: Channel<Msg>,
            reply: server::ChannelOpenHandle,
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            {
                let mut clients = self.clients.lock().unwrap();
                clients.insert((self.id, channel.id()), session.handle());
            }
            reply.accept().await;
            Ok(())
        }
        async fn auth_publickey(
            &mut self,
            _: &str,
            _: server::VerifiedPublicKey<'_>,
        ) -> Result<server::Auth, Self::Error> {
            debug!("auth_publickey");
            Ok(server::Auth::Accept)
        }
        async fn data(
            &mut self,
            channel: ChannelId,
            data: &[u8],
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            debug!("server data = {:?}", std::str::from_utf8(data));
            session.data(channel, data.to_vec())?;
            Ok(())
        }
    }

    struct Client {}

    impl client::Handler for Client {
        type Error = super::Error;

        async fn check_server_key(
            &mut self,
            _server_public_key: &PublicKeyOrCertificate,
        ) -> Result<bool, Self::Error> {
            // println!("check_server_key: {:?}", server_public_key);
            Ok(true)
        }
    }

    fn preferred_zlib() -> Preferred {
        Preferred {
            host_key_certificates: Cow::Borrowed(&[]),
            compression: Cow::Borrowed(&[
                crate::compression::ZLIB,
                crate::compression::ZLIB_LEGACY,
                crate::compression::NONE,
            ]),
            ..Preferred::DEFAULT
        }
    }
}

mod channels {
    use keys::PrivateKeyWithHashAlg;
    use server::Session;
    use ssh_key::PrivateKey;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::cert::PublicKeyOrCertificate;

    use super::*;

    async fn test_session<RC, RS, CH, SH, F1, F2>(
        client_handler: CH,
        server_handler: SH,
        run_client: RC,
        run_server: RS,
    ) where
        RC: FnOnce(crate::client::Handle<CH>) -> F1 + Send + Sync + 'static,
        RS: FnOnce(crate::server::Handle) -> F2 + Send + Sync + 'static,
        F1: Future<Output = crate::client::Handle<CH>> + Send + Sync + 'static,
        F2: Future<Output = crate::server::Handle> + Send + Sync + 'static,
        CH: crate::client::Handler + Send + Sync + 'static,
        SH: crate::server::Handler + Send + Sync + 'static,
    {
        use std::sync::Arc;

        use crate::*;

        let _ = env_logger::try_init();

        let client_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let mut config = server::Config::default();
        config.inactivity_timeout = None;
        config.auth_rejection_time = std::time::Duration::from_secs(3);
        config
            .keys
            .push(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());
        let config = Arc::new(config);
        let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();

        let server_join = tokio::spawn(async move {
            let (socket, _) = socket.accept().await.unwrap();

            server::run_stream(config, socket, server_handler)
                .await
                .map_err(|_| ())
                .unwrap()
        });

        let client_join = tokio::spawn(async move {
            let config = Arc::new(client::Config::default());
            let mut session = client::connect(config, addr, client_handler)
                .await
                .map_err(|_| ())
                .unwrap();
            let authenticated = session
                .authenticate_publickey(
                    std::env::var("USER").unwrap_or("user".to_owned()),
                    PrivateKeyWithHashAlg::new(Arc::new(client_key), None),
                )
                .await
                .unwrap();
            assert!(authenticated.success());
            session
        });

        let (server_session, client_session) = tokio::join!(server_join, client_join);
        let client_handle = tokio::spawn(run_client(client_session.unwrap()));
        let server_handle = tokio::spawn(run_server(server_session.unwrap().handle()));

        let (server_session, client_session) = tokio::join!(server_handle, client_handle);
        assert!(server_session.is_ok());
        assert!(client_session.is_ok());
        drop(client_session);
        drop(server_session);
    }

    #[tokio::test]
    async fn test_server_channels() {
        #[derive(Debug)]
        struct Client {}

        impl client::Handler for Client {
            type Error = crate::Error;

            async fn check_server_key(
                &mut self,
                _server_public_key: &PublicKeyOrCertificate,
            ) -> Result<bool, Self::Error> {
                Ok(true)
            }

            async fn data(
                &mut self,
                channel: ChannelId,
                data: &[u8],
                session: &mut client::Session,
            ) -> Result<(), Self::Error> {
                assert_eq!(data, &b"hello world!"[..]);
                session.data(channel, b"hey there!".to_vec())?;
                Ok(())
            }
        }

        struct ServerHandle {
            did_auth: Option<tokio::sync::oneshot::Sender<()>>,
        }

        impl ServerHandle {
            fn get_auth_waiter(&mut self) -> tokio::sync::oneshot::Receiver<()> {
                let (tx, rx) = tokio::sync::oneshot::channel();
                self.did_auth = Some(tx);
                rx
            }
        }

        impl server::Handler for ServerHandle {
            type Error = crate::Error;

            async fn auth_publickey(
                &mut self,
                _: &str,
                _: server::VerifiedPublicKey<'_>,
            ) -> Result<server::Auth, Self::Error> {
                Ok(server::Auth::Accept)
            }
            async fn auth_succeeded(&mut self, _session: &mut Session) -> Result<(), Self::Error> {
                if let Some(a) = self.did_auth.take() {
                    a.send(()).unwrap();
                }
                Ok(())
            }
        }

        let mut sh = ServerHandle { did_auth: None };
        let a = sh.get_auth_waiter();
        test_session(
            Client {},
            sh,
            |c| async move { c },
            |s| async move {
                a.await.unwrap();
                let mut ch = s.channel_open_session().await.unwrap();
                ch.data(&b"hello world!"[..]).await.unwrap();

                let msg = ch.wait().await.unwrap();
                if let ChannelMsg::Data { data } = msg {
                    assert_eq!(&data[..], &b"hey there!"[..]);
                } else {
                    panic!("Unexpected message {msg:?}");
                }
                s
            },
        )
        .await;
    }

    #[tokio::test]
    async fn test_channel_streams() {
        #[derive(Debug)]
        struct Client {}

        impl client::Handler for Client {
            type Error = crate::Error;

            async fn check_server_key(
                &mut self,
                _server_public_key: &PublicKeyOrCertificate,
            ) -> Result<bool, Self::Error> {
                Ok(true)
            }
        }

        struct ServerHandle {
            channel: Option<tokio::sync::oneshot::Sender<Channel<server::Msg>>>,
        }

        impl ServerHandle {
            fn get_channel_waiter(
                &mut self,
            ) -> tokio::sync::oneshot::Receiver<Channel<server::Msg>> {
                let (tx, rx) = tokio::sync::oneshot::channel::<Channel<server::Msg>>();
                self.channel = Some(tx);
                rx
            }
        }

        impl server::Handler for ServerHandle {
            type Error = crate::Error;

            async fn auth_publickey(
                &mut self,
                _: &str,
                _: server::VerifiedPublicKey<'_>,
            ) -> Result<server::Auth, Self::Error> {
                Ok(server::Auth::Accept)
            }

            async fn channel_open_session(
                &mut self,
                channel: Channel<server::Msg>,
                reply: server::ChannelOpenHandle,
                _session: &mut server::Session,
            ) -> Result<(), Self::Error> {
                if let Some(a) = self.channel.take() {
                    println!("channel open session {a:?}");
                    a.send(channel).unwrap();
                }
                reply.accept().await;
                Ok(())
            }
        }

        let mut sh = ServerHandle { channel: None };
        let scw = sh.get_channel_waiter();

        test_session(
            Client {},
            sh,
            |client| async move {
                let ch = client.channel_open_session().await.unwrap();
                let mut stream = ch.into_stream();
                stream.write_all(&b"request"[..]).await.unwrap();

                let mut buf = Vec::new();
                stream.read_buf(&mut buf).await.unwrap();
                assert_eq!(&buf, &b"response"[..]);

                stream.write_all(&b"reply"[..]).await.unwrap();

                client
            },
            |server| async move {
                let channel = scw.await.unwrap();
                let mut stream = channel.into_stream();

                let mut buf = Vec::new();
                stream.read_buf(&mut buf).await.unwrap();
                assert_eq!(&buf, &b"request"[..]);

                stream.write_all(&b"response"[..]).await.unwrap();

                buf.clear();

                stream.read_buf(&mut buf).await.unwrap();
                assert_eq!(&buf, &b"reply"[..]);

                server
            },
        )
        .await;
    }

    #[tokio::test]
    async fn test_channel_objects() {
        #[derive(Debug)]
        struct Client {}

        impl client::Handler for Client {
            type Error = crate::Error;

            async fn check_server_key(
                &mut self,
                _server_public_key: &PublicKeyOrCertificate,
            ) -> Result<bool, Self::Error> {
                Ok(true)
            }
        }

        struct ServerHandle {}

        impl ServerHandle {}

        impl server::Handler for ServerHandle {
            type Error = crate::Error;

            async fn auth_publickey(
                &mut self,
                _: &str,
                _: server::VerifiedPublicKey<'_>,
            ) -> Result<server::Auth, Self::Error> {
                Ok(server::Auth::Accept)
            }

            async fn channel_open_session(
                &mut self,
                mut channel: Channel<server::Msg>,
                reply: server::ChannelOpenHandle,
                _session: &mut Session,
            ) -> Result<(), Self::Error> {
                reply.accept().await;
                tokio::spawn(async move {
                    while let Some(msg) = channel.wait().await {
                        match msg {
                            ChannelMsg::Data { data } => {
                                channel.data(&data[..]).await.unwrap();
                                channel.close().await.unwrap();
                                break;
                            }
                            _ => {}
                        }
                    }
                });
                Ok(())
            }
        }

        let sh = ServerHandle {};
        test_session(
            Client {},
            sh,
            |c| async move {
                let mut ch = c.channel_open_session().await.unwrap();
                ch.data(&b"hello world!"[..]).await.unwrap();

                let msg = ch.wait().await.unwrap();
                if let ChannelMsg::Data { data } = msg {
                    assert_eq!(&data[..], &b"hello world!"[..]);
                } else {
                    panic!("Unexpected message {msg:?}");
                }

                // After the server closes the channel, we should receive an
                // explicit Close message before the channel stream ends.
                let msg = ch.wait().await.unwrap();
                assert!(
                    matches!(msg, ChannelMsg::Close),
                    "expected Close, got {msg:?}"
                );
                assert!(ch.wait().await.is_none());
                c
            },
            |s| async move { s },
        )
        .await;
    }

    /// Verify that the server-side CHANNEL_CLOSE handler delivers
    /// `ChannelMsg::Close` before the channel stream ends.
    #[tokio::test]
    async fn test_server_receives_close_on_client_close() {
        #[derive(Debug)]
        struct Client {}

        impl client::Handler for Client {
            type Error = crate::Error;

            async fn check_server_key(
                &mut self,
                _server_public_key: &PublicKeyOrCertificate,
            ) -> Result<bool, Self::Error> {
                Ok(true)
            }
        }

        struct ServerHandle {
            channel: Option<tokio::sync::oneshot::Sender<Channel<server::Msg>>>,
        }

        impl server::Handler for ServerHandle {
            type Error = crate::Error;

            async fn auth_publickey(
                &mut self,
                _: &str,
                _: server::VerifiedPublicKey<'_>,
            ) -> Result<server::Auth, Self::Error> {
                Ok(server::Auth::Accept)
            }

            async fn channel_open_session(
                &mut self,
                channel: Channel<server::Msg>,
                reply: server::ChannelOpenHandle,
                _session: &mut server::Session,
            ) -> Result<(), Self::Error> {
                if let Some(tx) = self.channel.take() {
                    tx.send(channel).unwrap();
                }
                reply.accept().await;
                Ok(())
            }
        }

        let (tx, rx) = tokio::sync::oneshot::channel::<Channel<server::Msg>>();
        let sh = ServerHandle { channel: Some(tx) };

        test_session(
            Client {},
            sh,
            |c| async move {
                let ch = c.channel_open_session().await.unwrap();
                ch.close().await.unwrap();
                c
            },
            |s| async move {
                let mut ch = rx.await.unwrap();
                // The server should receive an explicit Close message
                // when the client closes the channel.
                let msg = ch.wait().await.unwrap();
                assert!(
                    matches!(msg, ChannelMsg::Close),
                    "expected Close, got {msg:?}"
                );
                assert!(ch.wait().await.is_none());
                s
            },
        )
        .await;
    }

    #[tokio::test]
    async fn test_channel_window_size() {
        #[derive(Debug)]
        struct Client {}

        impl client::Handler for Client {
            type Error = crate::Error;

            async fn check_server_key(
                &mut self,
                _server_public_key: &PublicKeyOrCertificate,
            ) -> Result<bool, Self::Error> {
                Ok(true)
            }
        }

        struct ServerHandle {
            channel: Option<tokio::sync::oneshot::Sender<Channel<server::Msg>>>,
        }

        impl ServerHandle {
            fn get_channel_waiter(
                &mut self,
            ) -> tokio::sync::oneshot::Receiver<Channel<server::Msg>> {
                let (tx, rx) = tokio::sync::oneshot::channel::<Channel<server::Msg>>();
                self.channel = Some(tx);
                rx
            }
        }

        impl server::Handler for ServerHandle {
            type Error = crate::Error;

            async fn auth_publickey(
                &mut self,
                _: &str,
                _: server::VerifiedPublicKey<'_>,
            ) -> Result<server::Auth, Self::Error> {
                Ok(server::Auth::Accept)
            }

            async fn channel_open_session(
                &mut self,
                channel: Channel<server::Msg>,
                reply: server::ChannelOpenHandle,
                _session: &mut server::Session,
            ) -> Result<(), Self::Error> {
                if let Some(a) = self.channel.take() {
                    println!("channel open session {a:?}");
                    a.send(channel).unwrap();
                }
                reply.accept().await;
                Ok(())
            }
        }

        let mut sh = ServerHandle { channel: None };
        let scw = sh.get_channel_waiter();

        test_session(
            Client {},
            sh,
            |client| async move {
                let ch = client.channel_open_session().await.unwrap();

                let mut writer_1 = ch.make_writer();
                let jh_1 = tokio::spawn(async move {
                    let buf = [1u8; 1024 * 64];
                    assert!(writer_1.write_all(&buf).await.is_ok());
                });
                let mut writer_2 = ch.make_writer();
                let jh_2 = tokio::spawn(async move {
                    let buf = [2u8; 1024 * 64];
                    assert!(writer_2.write_all(&buf).await.is_ok());
                });

                assert!(tokio::try_join!(jh_1, jh_2).is_ok());

                client
            },
            |server| async move {
                let mut channel = scw.await.unwrap();

                let mut total_data = 2 * 1024 * 64;
                while let Some(msg) = channel.wait().await {
                    match msg {
                        ChannelMsg::Data { data } => {
                            total_data -= data.len();
                            if total_data == 0 {
                                break;
                            }
                        }
                        _ => panic!("Unexpected message {msg:?}"),
                    }
                }

                server
            },
        )
        .await;
    }

    /// What a client sends in a pty-req is what the application on the server
    /// side must see: exactly those modes, with no padding behind them.
    #[tokio::test]
    async fn test_pty_req_modes_are_delivered_unpadded() {
        let modes = vec![(Pty::VINTR, 3), (Pty::VQUIT, 28)];
        assert_eq!(send_pty_req(modes.clone()).await, modes);
    }

    /// A mode list padded with TTY_OP_END entries -- the shape an application
    /// proxying a pty-req ends up holding -- must still produce a well formed
    /// request. The encoder skips those entries, so the length it declares for
    /// the modes string must not count them, or the receiver reads the rest of
    /// the packet as terminal modes and rejects it.
    #[tokio::test]
    async fn test_pty_req_with_padded_modes_is_well_formed() {
        let mut padded = vec![(Pty::VINTR, 3)];
        padded.resize(130, (Pty::TTY_OP_END, 0));
        assert_eq!(send_pty_req(padded).await, vec![(Pty::VINTR, 3)]);
    }

    /// Send one pty-req and return the modes the server side received.
    async fn send_pty_req(modes: Vec<(Pty, u32)>) -> Vec<(Pty, u32)> {
        struct Client {}

        impl client::Handler for Client {
            type Error = crate::Error;

            async fn check_server_key(
                &mut self,
                _server_public_key: &PublicKeyOrCertificate,
            ) -> Result<bool, Self::Error> {
                Ok(true)
            }
        }

        struct ServerHandle {
            seen: tokio::sync::mpsc::UnboundedSender<Vec<(Pty, u32)>>,
        }

        impl server::Handler for ServerHandle {
            type Error = crate::Error;

            async fn auth_publickey(
                &mut self,
                _: &str,
                _: server::VerifiedPublicKey<'_>,
            ) -> Result<server::Auth, Self::Error> {
                Ok(server::Auth::Accept)
            }

            async fn channel_open_session(
                &mut self,
                mut channel: Channel<server::Msg>,
                reply: server::ChannelOpenHandle,
                session: &mut Session,
            ) -> Result<(), Self::Error> {
                reply.accept().await;

                let seen = self.seen.clone();
                let handle = session.handle();
                let id = channel.id();
                tokio::spawn(async move {
                    while let Some(msg) = channel.wait().await {
                        if let ChannelMsg::RequestPty { terminal_modes, .. } = msg {
                            let _ = seen.send(terminal_modes);
                            // Answer, so the client knows we are done looking.
                            let _ = handle.channel_success(id).await;
                            break;
                        }
                    }
                });
                Ok(())
            }
        }

        let (seen, mut received) = tokio::sync::mpsc::unbounded_channel();
        test_session(
            Client {},
            ServerHandle { seen },
            move |client| async move {
                let mut channel = client.channel_open_session().await.unwrap();
                channel
                    .request_pty(true, "xterm", 80, 24, 0, 0, &modes)
                    .await
                    .unwrap();
                match channel.wait().await {
                    Some(ChannelMsg::Success) => (),
                    other => panic!("pty request was not accepted: {other:?}"),
                }
                client
            },
            |server| async move { server },
        )
        .await;

        received.try_recv().expect("server never saw the pty request")
    }
}

mod gex {
    use super::*;

    #[test]
    fn peer_request_accepts_rfc4419_minimum_when_server_can_choose_stronger_group() {
        let params = client::GexParams::from_peer_request(1024, 4097, 8192).unwrap();

        assert_eq!(params.min_group_size(), 1024);
        assert_eq!(params.preferred_group_size(), 4097);
        assert_eq!(params.max_group_size(), 8192);
    }

    #[test]
    fn local_client_config_still_rejects_minimum_below_2048() {
        let error = client::GexParams::for_client_config(1024, 4097, 8192).unwrap_err();

        assert!(matches!(error, Error::InvalidConfig(_)));
    }
}

mod server_kex_junk {
    use std::sync::Arc;

    use tokio::io::AsyncWriteExt;

    use super::server::Server as _;
    use super::*;

    #[tokio::test]
    async fn server_kex_junk_test() {
        let _ = env_logger::try_init();

        let config = server::Config::default();
        let config = Arc::new(config);
        let mut sh = Server {};

        let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();

        tokio::spawn(async move {
            let mut client_stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            client_stream
                .write_all(b"SSH-2.0-Client_1.0\r\n")
                .await
                .unwrap();
            // Unexpected message pre-kex
            client_stream.write_all(&[0, 0, 0, 2, 0, 99]).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        });

        let (socket, _) = socket.accept().await.unwrap();
        let server = sh.new_client(socket.peer_addr().ok());
        let rs = server::run_stream(config, socket, server).await.unwrap();

        // May not panic
        assert!(rs.await.is_err());
    }

    #[derive(Clone)]
    struct Server {}

    impl server::Server for Server {
        type Handler = Self;
        fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
            self.clone()
        }
    }

    impl server::Handler for Server {
        type Error = super::Error;
    }
}

pub(crate) mod raw_no_crypto {
    use std::borrow::Cow;
    use std::io;
    use std::sync::{Arc, Mutex, OnceLock};
    use std::time::Duration;

    use byteorder::{BigEndian, ByteOrder};
    use ssh_key::{Algorithm, PrivateKey};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    pub(crate) const MSG_SERVICE_REQUEST: u8 = 5;
    pub(crate) const MSG_SERVICE_ACCEPT: u8 = 6;
    pub(crate) const MSG_KEXINIT: u8 = 20;
    pub(crate) const MSG_NEWKEYS: u8 = 21;
    pub(crate) const MSG_USERAUTH_REQUEST: u8 = 50;
    pub(crate) const MSG_USERAUTH_FAILURE: u8 = 51;
    pub(crate) const MSG_USERAUTH_SUCCESS: u8 = 52;
    pub(crate) const MSG_CHANNEL_OPEN: u8 = 90;
    pub(crate) const MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
    pub(crate) const MSG_CHANNEL_REQUEST: u8 = 98;

    pub(crate) async fn raw_service_request_signal(
        build_payload: impl FnOnce(&mut Vec<u8>),
    ) -> ServerSignal {
        let mut stream = RawSession::connect().await;
        let mut payload = Vec::new();
        build_payload(&mut payload);
        stream.send_packet(&payload).await.unwrap();
        stream.result().await
    }

    pub(crate) async fn raw_auth_request_signal(
        build_payload: impl FnOnce(&mut Vec<u8>),
    ) -> ServerSignal {
        let mut stream = RawSession::connect().await;
        stream.service_request().await.unwrap();

        let mut payload = Vec::new();
        build_payload(&mut payload);
        stream.send_packet(&payload).await.unwrap();
        stream.result().await
    }

    pub(crate) async fn raw_kex_signal(build_payload: impl FnOnce(&mut Vec<u8>)) -> ServerSignal {
        let mut stream = RawSession::connect_without_kex().await;

        let mut payload = Vec::new();
        build_payload(&mut payload);
        stream.send_packet(&payload).await.unwrap();
        stream.result().await
    }

    pub(crate) async fn raw_channel_request_signal(
        build_payload: impl FnOnce(u32) -> Vec<u8>,
    ) -> ServerSignal {
        let mut stream = RawSession::connect().await;
        stream.auth_none().await.unwrap();
        let server_channel = stream.open_session().await.unwrap();
        stream
            .send_packet(&build_payload(server_channel))
            .await
            .unwrap();
        stream.result().await
    }

    pub(crate) struct RawSession {
        pub(crate) events: Arc<Mutex<Vec<&'static str>>>,
        pub(crate) stream: tokio::net::TcpStream,
        pub(crate) server_task: tokio::task::JoinHandle<Result<(), Error>>,
    }

    impl RawSession {
        pub(crate) async fn connect() -> Self {
            let mut stream = Self::connect_without_kex().await;
            raw_client_no_crypto_kex(&mut stream.stream).await.unwrap();
            stream
        }

        pub(crate) async fn connect_without_kex() -> Self {
            Self::connect_without_kex_with_config(no_crypto_server_config()).await
        }

        pub(crate) async fn connect_without_kex_with_config(
            config: Arc<server::Config>,
        ) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let events = Arc::new(Mutex::new(Vec::new()));
            let server_events = events.clone();
            let server_task = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                let running = server::run_stream(
                    config,
                    socket,
                    MalformedInputServer {
                        events: server_events,
                    },
                )
                .await
                .unwrap();
                running.await
            });

            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            stream.write_all(b"SSH-2.0-russh-test\r\n").await.unwrap();
            read_ssh_id(&mut stream).await.unwrap();
            let _server_kex = read_packet(&mut stream).await.unwrap();
            Self {
                events,
                stream,
                server_task,
            }
        }

        pub(crate) async fn service_request(&mut self) -> io::Result<()> {
            let mut service = Vec::new();
            service.push(MSG_SERVICE_REQUEST);
            encode_string(&mut service, b"ssh-userauth");
            self.send_packet(&service).await?;

            let accept = read_packet(&mut self.stream).await?;
            assert_eq!(accept.first(), Some(&MSG_SERVICE_ACCEPT));
            Ok(())
        }

        pub(crate) async fn auth_none(&mut self) -> io::Result<()> {
            self.service_request().await?;

            let mut auth = Vec::new();
            auth.push(MSG_USERAUTH_REQUEST);
            encode_string(&mut auth, b"test");
            encode_string(&mut auth, b"ssh-connection");
            encode_string(&mut auth, b"none");
            self.send_packet(&auth).await?;

            let success = read_packet(&mut self.stream).await?;
            assert_eq!(success.first(), Some(&MSG_USERAUTH_SUCCESS));
            Ok(())
        }

        pub(crate) async fn open_session(&mut self) -> io::Result<u32> {
            let mut open = Vec::new();
            open.push(MSG_CHANNEL_OPEN);
            encode_string(&mut open, b"session");
            push_u32(&mut open, 0);
            push_u32(&mut open, 1024 * 1024);
            push_u32(&mut open, 32 * 1024);
            self.send_packet(&open).await?;

            let confirmation = read_packet(&mut self.stream).await?;
            assert_eq!(confirmation.first(), Some(&MSG_CHANNEL_OPEN_CONFIRMATION));
            Ok(BigEndian::read_u32(&confirmation[5..9]))
        }

        pub(crate) async fn send_packet(&mut self, payload: &[u8]) -> io::Result<()> {
            self.stream.write_all(&ssh_packet(payload)).await?;
            self.stream.flush().await
        }

        pub(crate) async fn result(mut self) -> ServerSignal {
            let result =
                tokio::time::timeout(Duration::from_millis(200), &mut self.server_task).await;
            let events = self.events.lock().unwrap().clone();

            match result {
                Ok(Ok(Ok(()))) => ServerSignal::Closed { events },
                Ok(Ok(Err(_error))) => ServerSignal::ProtocolError { events },
                Ok(Err(join)) if join.is_panic() => ServerSignal::Panicked { events },
                Err(_) => {
                    self.server_task.abort();
                    ServerSignal::Survived { events }
                }
                _ => ServerSignal::Closed { events },
            }
        }
    }

    pub(crate) const MSG_IGNORE: u8 = 2;

    fn strict_kex_server_config() -> Arc<server::Config> {
        let mut config = server::Config::default();
        config.inactivity_timeout = None;
        config
            .keys
            .push(PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap());
        Arc::new(config)
    }

    /// KEXINIT advertising algorithms the default server config accepts, so
    /// that negotiation succeeds and the server waits for KEX_ECDH_INIT.
    fn real_kexinit_payload(kex_names: &[&str]) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.push(MSG_KEXINIT);
        payload.extend_from_slice(&[0; 16]);
        encode_name_list(&mut payload, kex_names);
        encode_name_list(&mut payload, &["ssh-ed25519"]);
        encode_name_list(&mut payload, &["aes256-ctr"]);
        encode_name_list(&mut payload, &["aes256-ctr"]);
        encode_name_list(&mut payload, &["hmac-sha2-256"]);
        encode_name_list(&mut payload, &["hmac-sha2-256"]);
        encode_name_list(&mut payload, &["none"]);
        encode_name_list(&mut payload, &["none"]);
        encode_name_list(&mut payload, &[]);
        encode_name_list(&mut payload, &[]);
        payload.push(0);
        push_u32(&mut payload, 0);
        payload
    }

    async fn ignore_during_initial_kex(kex_names: &[&str]) -> ServerSignal {
        let mut session = RawSession::connect_without_kex_with_config(strict_kex_server_config())
            .await;
        session
            .send_packet(&real_kexinit_payload(kex_names))
            .await
            .unwrap();
        session.send_packet(&[MSG_IGNORE]).await.unwrap();
        session.result().await
    }

    /// Strict kex forbids any non-KEX message during the initial exchange.
    #[tokio::test]
    async fn ignore_during_initial_strict_kex_is_rejected() {
        assert!(matches!(
            ignore_during_initial_kex(&["curve25519-sha256", "kex-strict-c-v00@openssh.com"]).await,
            ServerSignal::ProtocolError { .. }
        ));
    }

    /// ... and without it, SSH_MSG_IGNORE is still legal at any time.
    #[tokio::test]
    async fn ignore_during_initial_kex_is_allowed_without_strict_kex() {
        assert!(matches!(
            ignore_during_initial_kex(&["curve25519-sha256"]).await,
            ServerSignal::Survived { .. }
        ));
    }

    /// Server that did its initial exchange with the `none` kex but can also
    /// negotiate curve25519, so a rekey offering only curve25519 parks it
    /// waiting for a KEX_ECDH_INIT the raw client never sends.
    fn stalled_rekey_server_config() -> Arc<server::Config> {
        let mut config = server::Config::default();
        config.inactivity_timeout = None;
        config.preferred = Preferred {
            kex: Cow::Owned(vec![kex::NONE, kex::CURVE25519]),
            ..no_crypto_preferred()
        };
        config
            .keys
            .push(PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap());
        Arc::new(config)
    }

    /// Authenticate, then start a rekey and leave it hanging.
    async fn stalled_rekey_session() -> RawSession {
        let mut session =
            RawSession::connect_without_kex_with_config(stalled_rekey_server_config()).await;
        raw_client_no_crypto_kex(&mut session.stream).await.unwrap();
        session.auth_none().await.unwrap();
        session
            .send_packet(&kexinit_payload("curve25519-sha256"))
            .await
            .unwrap();
        let server_kexinit = read_packet(&mut session.stream).await.unwrap();
        assert_eq!(server_kexinit.first(), Some(&MSG_KEXINIT));
        session
    }

    /// A peer that starts a rekey and then sends channel traffic instead of
    /// finishing it is cut off before the request is looked at. RFC 4253 s7.1
    /// forbids non-transport messages after KEXINIT, and honouring them let a
    /// peer that never completes the rekey grow the reply queue without bound.
    #[tokio::test]
    async fn channel_open_after_peer_kexinit_during_rekey_is_rejected() {
        let mut session = stalled_rekey_session().await;
        let mut open = vec![MSG_CHANNEL_OPEN];
        open.extend(channel_open_payload(b"session"));
        session.send_packet(&open).await.unwrap();

        let signal = session.result().await;
        match signal {
            ServerSignal::ProtocolError { events } => assert_eq!(events, ["auth_none"]),
            other => panic!("expected a protocol error, got {other:?}"),
        }
    }

    /// ...while transport-layer messages are still fine mid-rekey, which also
    /// shows the stalled server above is parked, not broken.
    #[tokio::test]
    async fn ignore_after_peer_kexinit_during_rekey_is_allowed() {
        let mut session = stalled_rekey_session().await;
        session.send_packet(&[MSG_IGNORE]).await.unwrap();
        assert!(matches!(
            session.result().await,
            ServerSignal::Survived { .. }
        ));
    }

    fn no_crypto_server_config() -> Arc<server::Config> {
        let mut config = server::Config::default();
        config.inactivity_timeout = None;
        config.auth_rejection_time = Duration::from_millis(1);
        config.auth_rejection_time_initial = Some(Duration::from_millis(1));
        config.preferred = no_crypto_preferred();
        config
            .keys
            .push(PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap());
        Arc::new(config)
    }

    fn no_crypto_preferred() -> Preferred {
        Preferred {
            host_key_certificates: Cow::Borrowed(&[]),
            kex: Cow::Owned(vec![kex::NONE]),
            key: Cow::Owned(vec![Algorithm::Ed25519]),
            cipher: Cow::Owned(vec![cipher::NONE]),
            mac: Cow::Owned(vec![mac::NONE]),
            compression: Cow::Owned(vec![compression::NONE]),
        }
    }

    async fn raw_client_no_crypto_kex(stream: &mut tokio::net::TcpStream) -> io::Result<()> {
        stream
            .write_all(&ssh_packet(&kexinit_payload("none")))
            .await?;
        let newkeys = read_packet(stream).await?;
        assert_eq!(newkeys.first(), Some(&MSG_NEWKEYS));
        stream.write_all(&ssh_packet(&[MSG_NEWKEYS])).await?;
        stream.flush().await
    }

    pub(crate) fn pty_req_payload(server_channel: u32, terminal_modes: &[u8]) -> Vec<u8> {
        let mut payload = channel_request_payload(server_channel, b"pty-req");
        encode_string(&mut payload, b"xterm");
        push_u32(&mut payload, 80);
        push_u32(&mut payload, 24);
        push_u32(&mut payload, 0);
        push_u32(&mut payload, 0);
        encode_string(&mut payload, terminal_modes);
        payload
    }

    pub(crate) fn channel_open_payload(channel_type: &[u8]) -> Vec<u8> {
        let mut payload = Vec::new();
        encode_string(&mut payload, channel_type);
        push_u32(&mut payload, 0);
        push_u32(&mut payload, 1024 * 1024);
        push_u32(&mut payload, 32 * 1024);
        payload
    }

    pub(crate) fn channel_request_payload(server_channel: u32, request_type: &[u8]) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.push(MSG_CHANNEL_REQUEST);
        push_u32(&mut payload, server_channel);
        encode_string(&mut payload, request_type);
        payload.push(1);
        payload
    }

    pub(crate) fn kexinit_payload(kex_name: &str) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.push(MSG_KEXINIT);
        payload.extend_from_slice(&[0; 16]);
        encode_name_list(&mut payload, &[kex_name]);
        encode_name_list(&mut payload, &["ssh-ed25519"]);
        encode_name_list(&mut payload, &["none"]);
        encode_name_list(&mut payload, &["none"]);
        encode_name_list(&mut payload, &["none"]);
        encode_name_list(&mut payload, &["none"]);
        encode_name_list(&mut payload, &["none"]);
        encode_name_list(&mut payload, &["none"]);
        encode_name_list(&mut payload, &[]);
        encode_name_list(&mut payload, &[]);
        payload.push(0);
        push_u32(&mut payload, 0);
        payload
    }

    fn ssh_packet(payload: &[u8]) -> Vec<u8> {
        let mut padding_len = 8 - ((5 + payload.len()) % 8);
        if padding_len < 4 {
            padding_len += 8;
        }
        let packet_len = 1 + payload.len() + padding_len;
        let mut packet = Vec::with_capacity(4 + packet_len);
        push_u32(&mut packet, packet_len as u32);
        packet.push(padding_len as u8);
        packet.extend_from_slice(payload);
        packet.resize(packet.len() + padding_len, 0);
        packet
    }

    pub(crate) async fn read_packet(stream: &mut tokio::net::TcpStream) -> io::Result<Vec<u8>> {
        let mut len_buf = [0; 4];
        stream.read_exact(&mut len_buf).await?;
        let packet_len = BigEndian::read_u32(&len_buf) as usize;
        let mut packet = vec![0; packet_len];
        stream.read_exact(&mut packet).await?;
        let padding_len = packet[0] as usize;
        Ok(packet[1..packet.len() - padding_len].to_vec())
    }

    async fn read_ssh_id(stream: &mut tokio::net::TcpStream) -> io::Result<Vec<u8>> {
        let mut id = Vec::new();
        loop {
            let mut byte = [0];
            stream.read_exact(&mut byte).await?;
            id.push(byte[0]);
            if byte[0] == b'\n' {
                return Ok(id);
            }
        }
    }

    fn encode_name_list(buf: &mut Vec<u8>, names: &[&str]) {
        encode_string(buf, names.join(",").as_bytes());
    }

    pub(crate) fn encode_string(buf: &mut Vec<u8>, value: &[u8]) {
        push_u32(buf, value.len() as u32);
        buf.extend_from_slice(value);
    }

    pub(crate) fn push_u32(buf: &mut Vec<u8>, value: u32) {
        let mut bytes = [0; 4];
        BigEndian::write_u32(&mut bytes, value);
        buf.extend_from_slice(&bytes);
    }

    pub(crate) async fn timeout(
        future: impl Future<Output = ServerSignal>,
    ) -> Result<ServerSignal, tokio::time::error::Elapsed> {
        tokio::time::timeout(Duration::from_secs(3), future).await
    }

    pub(crate) async fn capture_panics<T>(future: impl Future<Output = T>) -> (T, bool) {
        static PANIC_HOOK_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

        let _guard = PANIC_HOOK_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap();
        let panicked = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let panicked_hook = panicked.clone();
        let previous_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |_| {
            panicked_hook.store(true, std::sync::atomic::Ordering::SeqCst);
        }));

        let result = future.await;

        std::panic::set_hook(previous_hook);
        (result, panicked.load(std::sync::atomic::Ordering::SeqCst))
    }

    #[derive(Debug)]
    pub(crate) enum ServerSignal {
        Closed { events: Vec<&'static str> },
        ProtocolError { events: Vec<&'static str> },
        Panicked { events: Vec<&'static str> },
        Survived { events: Vec<&'static str> },
    }

    impl ServerSignal {
        pub(crate) fn events(&self) -> &[&'static str] {
            match self {
                Self::Closed { events }
                | Self::ProtocolError { events }
                | Self::Panicked { events }
                | Self::Survived { events } => events,
            }
        }
    }

    pub(crate) fn assert_rejected(
        result: Result<ServerSignal, tokio::time::error::Elapsed>,
        message: &str,
    ) {
        assert!(
            matches!(
                result,
                Ok(ServerSignal::Closed { .. } | ServerSignal::ProtocolError { .. })
            ),
            "{message}: {result:?}; handler events: {:?}",
            result
                .as_ref()
                .ok()
                .map(ServerSignal::events)
                .unwrap_or(&[])
        );
    }

    #[derive(Clone)]
    struct MalformedInputServer {
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    impl MalformedInputServer {
        fn record(&self, event: &'static str) {
            self.events.lock().unwrap().push(event);
        }
    }

    impl server::Handler for MalformedInputServer {
        type Error = Error;

        async fn auth_none(&mut self, _user: &str) -> Result<server::Auth, Self::Error> {
            self.record("auth_none");
            Ok(server::Auth::Accept)
        }

        async fn auth_password(
            &mut self,
            _user: &str,
            _password: &str,
        ) -> Result<server::Auth, Self::Error> {
            self.record("auth_password");
            Ok(server::Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            })
        }

        async fn channel_open_session(
            &mut self,
            _channel: Channel<server::Msg>,
            reply: server::ChannelOpenHandle,
            _session: &mut server::Session,
        ) -> Result<(), Self::Error> {
            self.record("channel_open_session");
            reply.accept().await;
            Ok(())
        }

        async fn pty_request(
            &mut self,
            _channel: ChannelId,
            _term: &str,
            _col_width: u32,
            _row_height: u32,
            _pix_width: u32,
            _pix_height: u32,
            _modes: &[(Pty, u32)],
            _session: &mut server::Session,
        ) -> Result<(), Self::Error> {
            self.record("pty_request");
            Ok(())
        }

        async fn env_request(
            &mut self,
            _channel: ChannelId,
            _variable_name: &str,
            _variable_value: &str,
            _session: &mut server::Session,
        ) -> Result<(), Self::Error> {
            self.record("env_request");
            Ok(())
        }

        async fn exec_request(
            &mut self,
            _channel: ChannelId,
            _data: &[u8],
            _session: &mut server::Session,
        ) -> Result<(), Self::Error> {
            self.record("exec_request");
            Ok(())
        }

        async fn signal(
            &mut self,
            _channel: ChannelId,
            _signal: Sig,
            _session: &mut server::Session,
        ) -> Result<(), Self::Error> {
            self.record("signal");
            Ok(())
        }
    }
}

/// Integration test for FutureCertificate authentication flow
#[cfg(unix)]
mod future_certificate {
    use std::io::Write;
    use std::process::Stdio;
    use std::sync::Arc;

    use ssh_key::{PrivateKey, certificate};

    use crate::cert::PublicKeyOrCertificate;
    use crate::keys::agent::client::AgentClient;
    use crate::server::Session;
    use crate::{client, server};

    /// Helper to spawn an ssh-agent
    async fn spawn_agent() -> (tokio::process::Child, std::path::PathBuf, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let agent_path = dir.path().join("agent");
        let agent = tokio::process::Command::new("ssh-agent")
            .arg("-a")
            .arg(&agent_path)
            .arg("-D")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();

        // Wait for the socket to be created
        while agent_path.canonicalize().is_err() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        (agent, agent_path, dir)
    }

    /// Helper to create a test certificate
    fn create_test_cert(ca_key: &PrivateKey, user_key: &PrivateKey) -> ssh_key::Certificate {
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let valid_after = now - 3600;
        let valid_before = now + 86400 * 365;

        let mut builder = certificate::Builder::new_with_random_nonce(
            &mut rand::rng(),
            user_key.public_key(),
            valid_after,
            valid_before,
        )
        .unwrap();

        builder.serial(1).unwrap();
        builder.key_id("test-user-cert").unwrap();
        builder.cert_type(certificate::CertType::User).unwrap();
        builder.valid_principal("testuser").unwrap();
        builder.sign(ca_key).unwrap()
    }

    #[tokio::test]
    async fn test_future_certificate_auth_full_flow() {
        let _ = env_logger::try_init();

        // 1. Spawn ssh-agent
        let (mut agent, agent_path, dir) = spawn_agent().await;

        // 2. Create CA key and user key
        let ca_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let user_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();

        // 3. Create a certificate
        let cert = create_test_cert(&ca_key, &user_key);

        // 4. Write keys and certificate to temp files and add to agent
        let user_key_path = dir.path().join("user_key");
        let cert_path = dir.path().join("user_key-cert.pub");

        let mut f = std::fs::File::create(&user_key_path).unwrap();
        f.write_all(
            user_key
                .to_openssh(ssh_key::LineEnding::LF)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        std::fs::set_permissions(
            &user_key_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();

        let mut f = std::fs::File::create(&cert_path).unwrap();
        f.write_all(cert.to_openssh().unwrap().as_bytes()).unwrap();

        let status = tokio::process::Command::new("ssh-add")
            .arg(&user_key_path)
            .env("SSH_AUTH_SOCK", &agent_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .unwrap();
        assert!(status.success(), "ssh-add failed");

        // 5. Set up test server that accepts certificate auth
        let mut server_config = server::Config::default();
        server_config.inactivity_timeout = None;
        server_config.auth_rejection_time = std::time::Duration::from_secs(3);
        server_config
            .keys
            .push(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());
        let server_config = Arc::new(server_config);

        let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();

        // Server that accepts certificate auth
        let server_join = tokio::spawn(async move {
            let (socket, _) = socket.accept().await.unwrap();

            struct CertHandler;

            impl server::Handler for CertHandler {
                type Error = crate::Error;

                async fn auth_publickey_offered(
                    &mut self,
                    _user: &str,
                    _public_key: server::PublicKeyOffer<'_>,
                ) -> Result<server::Auth, Self::Error> {
                    // Accept the key/certificate for the probe
                    Ok(server::Auth::Accept)
                }

                async fn auth_openssh_certificate(
                    &mut self,
                    _user: &str,
                    cert: &ssh_key::Certificate,
                ) -> Result<server::Auth, Self::Error> {
                    // Validate the certificate is signed by our CA
                    // In a real server, you'd properly verify the CA signature
                    // For this test, just check the key_id matches
                    if cert.key_id() == "test-user-cert" {
                        Ok(server::Auth::Accept)
                    } else {
                        Ok(server::Auth::Reject {
                            proceed_with_methods: None,
                            partial_success: false,
                        })
                    }
                }

                async fn channel_open_session(
                    &mut self,
                    channel: crate::Channel<server::Msg>,
                    _reply: server::ChannelOpenHandle,
                    _session: &mut Session,
                ) -> Result<(), Self::Error> {
                    drop(channel);
                    Ok(())
                }
            }

            let handler = CertHandler;
            server::run_stream(server_config, socket, handler)
                .await
                .unwrap()
        });

        // 6. Connect as client using FutureCertificate auth with the agent
        let client_config = Arc::new(client::Config::default());

        struct TestClient;
        impl client::Handler for TestClient {
            type Error = crate::Error;

            async fn check_server_key(
                &mut self,
                _server_public_key: &PublicKeyOrCertificate,
            ) -> Result<bool, Self::Error> {
                Ok(true)
            }
        }

        let mut session = client::connect(client_config, addr, TestClient)
            .await
            .unwrap();

        // Connect to the agent
        let stream = tokio::net::UnixStream::connect(&agent_path).await.unwrap();
        let mut agent_client = AgentClient::connect(stream);

        // Authenticate using FutureCertificate (None for hash_alg since Ed25519 doesn't need it)
        let auth_result = session
            .authenticate_certificate_with("testuser", cert.clone(), None, &mut agent_client)
            .await
            .unwrap();

        // 7. Verify authentication succeeded
        assert!(
            auth_result.success(),
            "Certificate authentication should succeed"
        );

        // Clean up
        session
            .disconnect(crate::Disconnect::ByApplication, "", "")
            .await
            .unwrap();
        drop(session);
        server_join.abort();
        agent.kill().await.unwrap();
        agent.wait().await.unwrap();
    }
}

mod rekey_under_load {
    use std::sync::Arc;

    use keys::PrivateKeyWithHashAlg;
    use ssh_key::PrivateKey;

    use super::*;
    use crate::cert::PublicKeyOrCertificate;
    use crate::server::Session;

    struct Client;

    impl client::Handler for Client {
        type Error = crate::Error;

        async fn check_server_key(
            &mut self,
            _server_public_key: &PublicKeyOrCertificate,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    struct Echo;

    impl server::Handler for Echo {
        type Error = crate::Error;

        async fn auth_publickey(
            &mut self,
            _: &str,
            _: server::VerifiedPublicKey<'_>,
        ) -> Result<server::Auth, Self::Error> {
            Ok(server::Auth::Accept)
        }

        async fn channel_open_session(
            &mut self,
            _channel: Channel<server::Msg>,
            reply: server::ChannelOpenHandle,
            _session: &mut Session,
        ) -> Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }

        async fn data(
            &mut self,
            channel: ChannelId,
            data: &[u8],
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            session.data(channel, data.to_vec())?;
            Ok(())
        }
    }

    /// Server-initiated rekeys while the client streams data: the client's
    /// in-flight traffic (legal until it has seen the server's KEXINIT) is
    /// handled across each rekey with nothing lost or misordered.
    #[tokio::test]
    async fn client_traffic_in_flight_during_server_rekey_survives() {
        let _ = env_logger::try_init();

        let mut config = server::Config::default();
        config.inactivity_timeout = None;
        // Rekey every 64 KiB written: ~16 rekeys over the transfer below.
        config.limits = Limits::new(64 * 1024, 1 << 30, std::time::Duration::from_secs(3600));
        config
            .keys
            .push(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());
        let config = Arc::new(config);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            server::run_stream(config, socket, Echo).await.unwrap().await
        });

        let key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let mut session = client::connect(Arc::new(client::Config::default()), addr, Client)
            .await
            .unwrap();
        assert!(
            session
                .authenticate_publickey("user", PrivateKeyWithHashAlg::new(Arc::new(key), None))
                .await
                .unwrap()
                .success()
        );
        let mut channel = session.channel_open_session().await.unwrap();

        const CHUNK: usize = 4096;
        const CHUNKS: usize = 256;
        let payload: Vec<u8> = (0..CHUNK * CHUNKS).map(|i| (i % 251) as u8).collect();

        let writer = {
            let payload = payload.clone();
            let writer = channel.make_writer();
            tokio::spawn(async move {
                use tokio::io::AsyncWriteExt;
                let mut writer = writer;
                for chunk in payload.chunks(CHUNK) {
                    writer.write_all(chunk).await.unwrap();
                }
                writer.flush().await.unwrap();
            })
        };

        let mut server = server;
        let mut echoed = Vec::with_capacity(payload.len());
        let received = tokio::time::timeout(std::time::Duration::from_secs(30), async {
            while echoed.len() < payload.len() {
                match channel.wait().await {
                    Some(ChannelMsg::Data { data }) => echoed.extend_from_slice(&data),
                    Some(ChannelMsg::WindowAdjusted { .. }) => {}
                    other => {
                        let server = tokio::time::timeout(
                            std::time::Duration::from_secs(1),
                            &mut server,
                        )
                        .await;
                        panic!(
                            "unexpected channel message: {other:?} after {} bytes; server: {server:?}",
                            echoed.len()
                        );
                    }
                }
            }
        })
        .await;
        assert!(received.is_ok(), "echo did not complete");
        writer.await.unwrap();

        assert!(echoed == payload, "echoed data differs from what was sent");
    }
}
