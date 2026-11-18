#![cfg(not(target_arch = "wasm32"))]
#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use russh::keys::agent::client::AgentClient;
use russh::keys::{Algorithm, PrivateKey, PublicKeyOrCertificate};
use russh::{Disconnect, client, server};
use signature::Verifier;
use ssh_encoding::Decode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const SSH_AGENT_SUCCESS: u8 = 6;
const SSH_AGENTC_EXTENSION: u8 = 27;

struct TestServer;

impl server::Handler for TestServer {
    type Error = russh::Error;
}

struct TestClient;

impl client::Handler for TestClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

#[tokio::test]
async fn agent_session_bind_uses_the_verified_initial_kex_tuple() {
    let server_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let server_public_key = server_key.public_key().clone();
    let mut server_config = server::Config::default();
    server_config.keys.push(server_key);
    let server_config = Arc::new(server_config);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        server::run_stream(server_config, stream, TestServer)
            .await
            .unwrap();
    });

    let handle = client::connect(Arc::new(client::Config::default()), address, TestClient)
        .await
        .unwrap();
    let binding = handle
        .agent_session_binding()
        .expect("a standard initial key exchange has an agent binding");

    for forwarding in [false, true] {
        let (agent_stream, mut fake_agent) = tokio::io::duplex(16 * 1024);
        let expected_key = server_public_key.clone();
        let agent = tokio::spawn(async move {
            let frame_len = fake_agent.read_u32().await.unwrap() as usize;
            let mut frame = vec![0; frame_len];
            fake_agent.read_exact(&mut frame).await.unwrap();
            let mut frame = frame.as_slice();

            assert_eq!(u8::decode(&mut frame).unwrap(), SSH_AGENTC_EXTENSION);
            assert_eq!(
                String::decode(&mut frame).unwrap(),
                "session-bind@openssh.com"
            );
            let host_key_blob = Vec::<u8>::decode(&mut frame).unwrap();
            let session_id = Vec::<u8>::decode(&mut frame).unwrap();
            let signature_blob = Vec::<u8>::decode(&mut frame).unwrap();
            assert_eq!(u8::decode(&mut frame).unwrap(), u8::from(forwarding));
            assert!(frame.is_empty());

            assert_eq!(host_key_blob, expected_key.to_bytes().unwrap());
            let mut signature_reader = signature_blob.as_slice();
            let signature = ssh_key::Signature::decode(&mut signature_reader).unwrap();
            assert!(signature_reader.is_empty());
            Verifier::verify(&expected_key, &session_id, &signature).unwrap();

            fake_agent
                .write_all(&[0, 0, 0, 1, SSH_AGENT_SUCCESS])
                .await
                .unwrap();
        });

        let mut client = AgentClient::connect(agent_stream);
        client.bind_session(binding, forwarding).await.unwrap();
        agent.await.unwrap();
    }

    handle
        .disconnect(Disconnect::ByApplication, "", "")
        .await
        .unwrap();
}
