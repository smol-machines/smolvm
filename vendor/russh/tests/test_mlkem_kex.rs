#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Integration tests for ML-KEM hybrid key exchange
//! https://datatracker.ietf.org/doc/draft-ietf-sshm-mlkem-hybrid-kex/

use std::borrow::Cow;
use std::sync::Arc;

use russh::keys::{PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::*;
use ssh_key::PrivateKey;

#[tokio::test]
async fn test_mlkem768x25519_handshake() {
    let _ = env_logger::try_init();

    let client_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();

    let mut server_config = server::Config::default();
    server_config.inactivity_timeout = None;
    server_config.auth_rejection_time = std::time::Duration::from_secs(3);
    server_config
        .keys
        .push(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());

    server_config.preferred = {
        let mut p = Preferred::default();
        p.kex = Cow::Borrowed(&[kex::MLKEM768X25519_SHA256]);
        p
    };

    let server_config = Arc::new(server_config);

    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();

    tokio::spawn(async move {
        let (socket, _) = socket.accept().await.unwrap();
        server::run_stream(server_config, socket, TestServer {})
            .await
            .unwrap();
    });

    let mut client_config = client::Config::default();
    client_config.preferred = {
        let mut p = Preferred::default();
        p.kex = Cow::Borrowed(&[kex::MLKEM768X25519_SHA256]);
        p
    };
    let client_config = Arc::new(client_config);

    let mut session = client::connect(client_config, addr, TestClient {})
        .await
        .unwrap();

    let authenticated = session
        .authenticate_publickey(
            std::env::var("USER").unwrap_or("user".to_owned()),
            PrivateKeyWithHashAlg::new(Arc::new(client_key), None),
        )
        .await
        .unwrap()
        .success();
    assert!(
        authenticated,
        "Authentication should succeed with ML-KEM KEX"
    );

    let mut channel = session.channel_open_session().await.unwrap();
    channel.data(&b"test data with mlkem"[..]).await.unwrap();

    let msg = channel.wait().await.unwrap();
    match msg {
        ChannelMsg::Data { data } => {
            assert_eq!(&*data, b"test data with mlkem");
        }
        msg => panic!("Unexpected message: {msg:?}"),
    }

    channel.eof().await.unwrap();
    session
        .disconnect(Disconnect::ByApplication, "", "")
        .await
        .unwrap();
}

#[tokio::test]
async fn test_mlkem768x25519_with_fallback() {
    let _ = env_logger::try_init();

    let client_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();

    let mut server_config = server::Config::default();
    server_config.inactivity_timeout = None;
    server_config.auth_rejection_time = std::time::Duration::from_secs(3);
    server_config
        .keys
        .push(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());

    server_config.preferred = {
        let mut p = Preferred::default();
        p.kex = Cow::Borrowed(&[kex::MLKEM768X25519_SHA256, kex::CURVE25519]);
        p
    };

    let server_config = Arc::new(server_config);

    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();

    tokio::spawn(async move {
        let (socket, _) = socket.accept().await.unwrap();
        server::run_stream(server_config, socket, TestServer {})
            .await
            .unwrap();
    });

    let mut client_config = client::Config::default();
    client_config.preferred = {
        let mut p = Preferred::default();
        p.kex = Cow::Borrowed(&[kex::MLKEM768X25519_SHA256, kex::CURVE25519]);
        p
    };
    let client_config = Arc::new(client_config);

    let mut session = client::connect(client_config, addr, TestClient {})
        .await
        .unwrap();

    let authenticated = session
        .authenticate_publickey(
            std::env::var("USER").unwrap_or("user".to_owned()),
            PrivateKeyWithHashAlg::new(Arc::new(client_key), None),
        )
        .await
        .unwrap()
        .success();
    assert!(
        authenticated,
        "Authentication should succeed with ML-KEM KEX and fallback"
    );

    let mut channel = session.channel_open_session().await.unwrap();
    channel.data(&b"test with fallback"[..]).await.unwrap();

    let msg = channel.wait().await.unwrap();
    match msg {
        ChannelMsg::Data { data } => {
            assert_eq!(&*data, b"test with fallback");
        }
        msg => panic!("Unexpected message: {msg:?}"),
    }

    channel.eof().await.unwrap();
    session
        .disconnect(Disconnect::ByApplication, "", "")
        .await
        .unwrap();
}

#[tokio::test]
async fn test_mlkem768x25519_rekey() {
    let _ = env_logger::try_init();

    let client_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();

    let mut server_config = server::Config::default();
    server_config.inactivity_timeout = None;
    server_config.auth_rejection_time = std::time::Duration::from_secs(3);
    server_config
        .keys
        .push(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());

    server_config.preferred = {
        let mut p = Preferred::default();
        p.kex = Cow::Borrowed(&[kex::MLKEM768X25519_SHA256]);
        p
    };

    let server_config = Arc::new(server_config);

    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();

    tokio::spawn(async move {
        let (socket, _) = socket.accept().await.unwrap();
        server::run_stream(server_config, socket, TestServer {})
            .await
            .unwrap();
    });

    let mut client_config = client::Config::default();
    client_config.preferred = {
        let mut p = Preferred::default();
        p.kex = Cow::Borrowed(&[kex::MLKEM768X25519_SHA256]);
        p
    };
    let client_config = Arc::new(client_config);

    let mut session = client::connect(client_config, addr, TestClient {})
        .await
        .unwrap();

    let authenticated = session
        .authenticate_publickey(
            std::env::var("USER").unwrap_or("user".to_owned()),
            PrivateKeyWithHashAlg::new(Arc::new(client_key), None),
        )
        .await
        .unwrap()
        .success();
    assert!(authenticated);

    let mut channel = session.channel_open_session().await.unwrap();
    channel.data(&b"before rekey"[..]).await.unwrap();

    let msg = channel.wait().await.unwrap();
    match msg {
        ChannelMsg::Data { data } => {
            assert_eq!(&*data, b"before rekey");
        }
        msg => panic!("Unexpected message before rekey: {msg:?}"),
    }

    session.rekey_soon().await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    channel.data(&b"after rekey"[..]).await.unwrap();

    let msg = channel.wait().await.unwrap();
    match msg {
        ChannelMsg::Data { data } => {
            assert_eq!(&*data, b"after rekey");
        }
        msg => panic!("Unexpected message after rekey: {msg:?}"),
    }

    channel.eof().await.unwrap();
    session
        .disconnect(Disconnect::ByApplication, "", "")
        .await
        .unwrap();
}

#[tokio::test]
async fn test_mlkem768x25519_multiple_channels() {
    let _ = env_logger::try_init();

    let client_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();

    let mut server_config = server::Config::default();
    server_config.inactivity_timeout = None;
    server_config.auth_rejection_time = std::time::Duration::from_secs(3);
    server_config
        .keys
        .push(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());

    server_config.preferred = {
        let mut p = Preferred::default();
        p.kex = Cow::Borrowed(&[kex::MLKEM768X25519_SHA256]);
        p
    };

    let server_config = Arc::new(server_config);

    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();

    tokio::spawn(async move {
        let (socket, _) = socket.accept().await.unwrap();
        server::run_stream(server_config, socket, TestServer {})
            .await
            .unwrap();
    });

    let mut client_config = client::Config::default();
    client_config.preferred = {
        let mut p = Preferred::default();
        p.kex = Cow::Borrowed(&[kex::MLKEM768X25519_SHA256]);
        p
    };
    let client_config = Arc::new(client_config);

    let mut session = client::connect(client_config, addr, TestClient {})
        .await
        .unwrap();

    let authenticated = session
        .authenticate_publickey(
            std::env::var("USER").unwrap_or("user".to_owned()),
            PrivateKeyWithHashAlg::new(Arc::new(client_key), None),
        )
        .await
        .unwrap()
        .success();
    assert!(authenticated);

    let mut channel1 = session.channel_open_session().await.unwrap();
    let mut channel2 = session.channel_open_session().await.unwrap();

    channel1.data(&b"channel 1 data"[..]).await.unwrap();
    channel2.data(&b"channel 2 data"[..]).await.unwrap();

    let msg1 = channel1.wait().await.unwrap();
    match msg1 {
        ChannelMsg::Data { data } => {
            assert_eq!(&*data, b"channel 1 data");
        }
        msg => panic!("Unexpected message on channel 1: {msg:?}"),
    }

    let msg2 = channel2.wait().await.unwrap();
    match msg2 {
        ChannelMsg::Data { data } => {
            assert_eq!(&*data, b"channel 2 data");
        }
        msg => panic!("Unexpected message on channel 2: {msg:?}"),
    }

    channel1.eof().await.unwrap();
    channel2.eof().await.unwrap();
    session
        .disconnect(Disconnect::ByApplication, "", "")
        .await
        .unwrap();
}

#[derive(Clone)]
struct TestServer {}

impl server::Handler for TestServer {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _public_key: server::VerifiedPublicKey<'_>,
    ) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        session.data(channel, data.to_vec())?;
        Ok(())
    }
}

struct TestClient {}

impl client::Handler for TestClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}
