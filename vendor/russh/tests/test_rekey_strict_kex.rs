#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Test that strict key exchange is works during initial kex and rekey
//! kex.  This test ensures that strict_kex sequence number checking is
//! only applied to the initial key exchange, not to rekey operations.

use std::borrow::Cow;
use std::sync::Arc;

use russh::keys::{PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::*;
use ssh_key::PrivateKey;

#[tokio::test]
async fn test_rekey_with_strict_kex() {
    let _ = env_logger::try_init();

    // Generate keys
    let client_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();

    // Server config with strict kex enabled
    let mut server_config = server::Config::default();
    server_config.inactivity_timeout = None;
    server_config.auth_rejection_time = std::time::Duration::from_secs(3);
    server_config
        .keys
        .push(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());

    // Enable strict kex by including the strict kex extension
    server_config.preferred = {
        let mut p = Preferred::default();
        // Include the strict kex extension marker for server
        p.kex = Cow::Borrowed(&[kex::CURVE25519, kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER]);
        p
    };

    let server_config = Arc::new(server_config);

    // Setup server
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();

    tokio::spawn(async move {
        let (socket, _) = socket.accept().await.unwrap();
        server::run_stream(server_config, socket, TestServer {})
            .await
            .unwrap();
    });

    // Client config with strict kex enabled
    let mut client_config = client::Config::default();
    client_config.preferred = {
        let mut p = Preferred::default();
        // Include the strict kex extension marker for client
        p.kex = Cow::Borrowed(&[kex::CURVE25519, kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT]);
        p
    };
    let client_config = Arc::new(client_config);

    // Connect and authenticate
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

    // Open a channel and send some data
    let mut channel = session.channel_open_session().await.unwrap();
    channel.data(&b"before rekey"[..]).await.unwrap();

    // Wait for response
    let msg = channel.wait().await.unwrap();
    match msg {
        ChannelMsg::Data { data } => {
            assert_eq!(&*data, b"before rekey");
        }
        msg => panic!("Unexpected message before rekey: {msg:?}"),
    }

    session.rekey_soon().await.unwrap();

    // Give rekey time to complete
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Send data after rekey to ensure connection still works
    // If the rekey failed due to strict_kex violation, this would fail
    channel.data(&b"after rekey"[..]).await.unwrap();

    let msg = channel.wait().await.unwrap();
    match msg {
        ChannelMsg::Data { data } => {
            assert_eq!(&*data, b"after rekey");
        }
        msg => panic!("Unexpected message after rekey: {msg:?}"),
    }

    // Close the channel
    channel.eof().await.unwrap();
    session
        .disconnect(Disconnect::ByApplication, "", "")
        .await
        .unwrap();
}

#[derive(Clone)]
struct TestServer {}

// Insecure server that accepts any public key and echos back data it receives; ONLY FOR TESTS
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
        // Echo back the data
        session.data(channel, data.to_vec())?;
        Ok(())
    }
}

struct TestClient {}

// Insecure client that accept any server key; ONLY FOR TEST
impl client::Handler for TestClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}
