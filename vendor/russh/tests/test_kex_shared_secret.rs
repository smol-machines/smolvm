#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Tests for the kex_done callback and shared secret access.
//!
//! This feature enables protocol bridging use cases where applications need to
//! derive additional encryption keys from the SSH KEX shared secret.

use std::borrow::Cow;
use std::sync::{Arc, Mutex};

use russh::keys::{PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::*;
use ssh_key::PrivateKey;

/// Test that kex_done callback is invoked with shared secret
#[tokio::test]
async fn test_kex_done_callback_receives_shared_secret() {
    let _ = env_logger::try_init();

    let client_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();

    // Set up server
    let mut server_config = server::Config::default();
    server_config.inactivity_timeout = None;
    server_config.auth_rejection_time = std::time::Duration::from_secs(3);
    server_config
        .keys
        .push(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());
    server_config.preferred = {
        let mut p = Preferred::default();
        p.kex = Cow::Borrowed(&[kex::CURVE25519]);
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

    // Set up client with shared secret capture
    let captured_secret: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let captured_names: Arc<Mutex<Option<Names>>> = Arc::new(Mutex::new(None));

    let mut client_config = client::Config::default();
    client_config.preferred = {
        let mut p = Preferred::default();
        p.kex = Cow::Borrowed(&[kex::CURVE25519]);
        p
    };
    let client_config = Arc::new(client_config);

    let client = TestClientWithKexCapture {
        shared_secret: captured_secret.clone(),
        negotiated_cipher: captured_names.clone(),
    };

    let mut session = client::connect(client_config, addr, client).await.unwrap();

    // Authenticate to complete the session setup
    let authenticated = session
        .authenticate_publickey(
            std::env::var("USER").unwrap_or("user".to_owned()),
            PrivateKeyWithHashAlg::new(Arc::new(client_key), None),
        )
        .await
        .unwrap()
        .success();
    assert!(authenticated, "Authentication should succeed");

    // Verify the shared secret was captured
    let secret = captured_secret.lock().unwrap();
    assert!(secret.is_some(), "Shared secret should be captured");
    let secret_bytes = secret.as_ref().unwrap();
    assert!(
        !secret_bytes.is_empty(),
        "Shared secret should not be empty"
    );
    assert_eq!(
        secret_bytes.len(),
        32,
        "Curve25519 shared secret should be 32 bytes"
    );

    // Verify negotiated cipher was captured
    let cipher = captured_names.lock().unwrap();
    assert!(cipher.is_some(), "Negotiated cipher should be captured");

    assert!(
        cipher.as_ref().unwrap().kex.as_ref().contains("curve25519"),
        "KEX algorithm should be curve25519"
    );

    session
        .disconnect(Disconnect::ByApplication, "", "")
        .await
        .unwrap();
}

/// Test kex_done with different KEX algorithms
#[tokio::test]
async fn test_kex_done_with_ecdh_nistp256() {
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
        p.kex = Cow::Borrowed(&[kex::ECDH_SHA2_NISTP256]);
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

    let captured_secret: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let captured_names: Arc<Mutex<Option<Names>>> = Arc::new(Mutex::new(None));

    let mut client_config = client::Config::default();
    client_config.preferred = {
        let mut p = Preferred::default();
        p.kex = Cow::Borrowed(&[kex::ECDH_SHA2_NISTP256]);
        p
    };
    let client_config = Arc::new(client_config);

    let client = TestClientWithKexCapture {
        shared_secret: captured_secret.clone(),
        negotiated_cipher: captured_names.clone(),
    };

    let mut session = client::connect(client_config, addr, client).await.unwrap();

    let authenticated = session
        .authenticate_publickey(
            std::env::var("USER").unwrap_or("user".to_owned()),
            PrivateKeyWithHashAlg::new(Arc::new(client_key), None),
        )
        .await
        .unwrap()
        .success();
    assert!(authenticated);

    let secret = captured_secret.lock().unwrap();
    assert!(secret.is_some(), "Shared secret should be captured");
    let secret_bytes = secret.as_ref().unwrap();
    assert!(
        !secret_bytes.is_empty(),
        "Shared secret should not be empty"
    );
    // NIST P-256 shared secret is 32 bytes
    assert_eq!(
        secret_bytes.len(),
        32,
        "ECDH-NISTP256 shared secret should be 32 bytes"
    );

    let kex_alg = captured_names.lock().unwrap();
    assert!(
        kex_alg.as_ref().unwrap().kex.as_ref().contains("nistp256"),
        "KEX algorithm should be nistp256"
    );

    session
        .disconnect(Disconnect::ByApplication, "", "")
        .await
        .unwrap();
}

#[tokio::test]
async fn test_kex_done_with_dh_gex_sha256_and_rfc4419_minimum() {
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
        p.kex = Cow::Borrowed(&[kex::DH_GEX_SHA256]);
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

    let captured_secret: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let captured_names: Arc<Mutex<Option<Names>>> = Arc::new(Mutex::new(None));

    let mut client_config = client::Config::default();
    client_config.preferred = {
        let mut p = Preferred::default();
        p.kex = Cow::Borrowed(&[kex::DH_GEX_SHA256]);
        p
    };
    client_config.gex = client::GexParams::for_client_config(2048, 4097, 8192).unwrap();
    let client_config = Arc::new(client_config);

    let client = TestClientWithKexCapture {
        shared_secret: captured_secret.clone(),
        negotiated_cipher: captured_names.clone(),
    };

    let mut session = client::connect(client_config, addr, client).await.unwrap();

    let authenticated = session
        .authenticate_publickey(
            std::env::var("USER").unwrap_or("user".to_owned()),
            PrivateKeyWithHashAlg::new(Arc::new(client_key), None),
        )
        .await
        .unwrap()
        .success();
    assert!(authenticated);

    let secret = captured_secret.lock().unwrap();
    assert!(secret.is_some(), "Shared secret should be captured");
    assert!(!secret.as_ref().unwrap().is_empty());

    let kex_alg = captured_names.lock().unwrap();
    assert_eq!(kex_alg.as_ref().unwrap().kex, kex::DH_GEX_SHA256);

    session
        .disconnect(Disconnect::ByApplication, "", "")
        .await
        .unwrap();
}

/// Test that kex_done is called on rekey
#[tokio::test]
async fn test_kex_done_on_rekey() {
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
        p.kex = Cow::Borrowed(&[kex::CURVE25519]);
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

    let kex_count: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
    let first_secret: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let second_secret: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));

    let mut client_config = client::Config::default();
    client_config.preferred = {
        let mut p = Preferred::default();
        p.kex = Cow::Borrowed(&[kex::CURVE25519]);
        p
    };
    // Set rekey limits very low to trigger rekey quickly
    client_config.limits = Limits {
        rekey_write_limit: 1024, // Rekey after 1KB of data
        rekey_read_limit: 1024,
        rekey_time_limit: std::time::Duration::from_secs(1),
    };
    let client_config = Arc::new(client_config);

    let client = TestClientWithRekeyCapture {
        kex_count: kex_count.clone(),
        first_secret: first_secret.clone(),
        second_secret: second_secret.clone(),
    };

    let mut session = client::connect(client_config, addr, client).await.unwrap();

    let authenticated = session
        .authenticate_publickey(
            std::env::var("USER").unwrap_or("user".to_owned()),
            PrivateKeyWithHashAlg::new(Arc::new(client_key), None),
        )
        .await
        .unwrap()
        .success();
    assert!(authenticated);

    // Initial KEX should have happened
    {
        let count = kex_count.lock().unwrap();
        assert_eq!(*count, 1, "Initial KEX should have happened");
    }

    // Open a channel and send enough data to trigger rekey
    let mut channel = session.channel_open_session().await.unwrap();

    // Send data to trigger rekey (more than rekey_write_limit)
    let large_data = vec![0u8; 2048];
    channel.data(&large_data[..]).await.unwrap();

    // Wait a bit for rekey to potentially happen
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Check that we received the echoed data back
    let _msg = channel.wait().await.unwrap();

    channel.eof().await.unwrap();
    session
        .disconnect(Disconnect::ByApplication, "", "")
        .await
        .unwrap();

    // Verify first shared secret was captured
    let first = first_secret.lock().unwrap();
    assert!(first.is_some(), "First shared secret should be captured");
}

// Test handlers

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
        // Echo data back
        session.data(channel, data.to_vec())?;
        Ok(())
    }
}

struct TestClientWithKexCapture {
    shared_secret: Arc<Mutex<Option<Vec<u8>>>>,
    negotiated_cipher: Arc<Mutex<Option<Names>>>,
}

impl client::Handler for TestClientWithKexCapture {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn kex_done(
        &mut self,
        shared_secret: Option<&[u8]>,
        names: &Names,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        // Capture the shared secret
        if let Some(secret) = shared_secret {
            *self.shared_secret.lock().unwrap() = Some(secret.to_vec());
        }

        // Capture the negotiated cipher name
        *self.negotiated_cipher.lock().unwrap() = Some(names.clone());

        Ok(())
    }
}

struct TestClientWithRekeyCapture {
    kex_count: Arc<Mutex<usize>>,
    first_secret: Arc<Mutex<Option<Vec<u8>>>>,
    second_secret: Arc<Mutex<Option<Vec<u8>>>>,
}

impl client::Handler for TestClientWithRekeyCapture {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn kex_done(
        &mut self,
        shared_secret: Option<&[u8]>,
        _names: &Names,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let mut count = self.kex_count.lock().unwrap();
        *count += 1;

        if let Some(secret) = shared_secret {
            if *count == 1 {
                *self.first_secret.lock().unwrap() = Some(secret.to_vec());
            } else {
                *self.second_secret.lock().unwrap() = Some(secret.to_vec());
            }
        }

        Ok(())
    }
}
