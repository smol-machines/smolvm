use std::sync::Arc;
use std::time::Duration;

use russh::keys::{PrivateKey, PublicKeyOrCertificate};
use russh::{MethodKind, MethodSet, client, server};

struct AcceptTestServerKey;

impl client::Handler for AcceptTestServerKey {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

struct RemainingMethodsUserSwitchServer;

impl server::Handler for RemainingMethodsUserSwitchServer {
    type Error = russh::Error;

    async fn auth_none(&mut self, user: &str) -> Result<server::Auth, Self::Error> {
        if user == "alice" {
            Ok(server::Auth::Reject {
                proceed_with_methods: Some(MethodSet::from(&[MethodKind::Password][..])),
                partial_success: true,
            })
        } else {
            Ok(server::Auth::reject())
        }
    }
}

#[tokio::test]
async fn auth_does_not_carry_remaining_methods_across_username_change() {
    let mut server_config = server::Config::default();
    server_config.inactivity_timeout = None;
    server_config.auth_rejection_time = Duration::from_millis(1);
    server_config.auth_rejection_time_initial = Some(Duration::from_millis(1));
    server_config.keys.push(
        PrivateKey::random(&mut rand::rng(), russh::keys::ssh_key::Algorithm::Ed25519).unwrap(),
    );
    let server_config = Arc::new(server_config);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let running = server::run_stream(server_config, socket, RemainingMethodsUserSwitchServer)
            .await
            .unwrap();
        running.await
    });

    let mut session = client::connect(
        Arc::new(client::Config::default()),
        addr,
        AcceptTestServerKey,
    )
    .await
    .unwrap();

    let alice = session.authenticate_none("alice").await.unwrap();
    assert!(
        matches!(
            alice,
            client::AuthResult::Failure {
                ref remaining_methods,
                ..
            } if *remaining_methods == MethodSet::from(&[MethodKind::Password][..])
        ),
        "unexpected Alice auth result: {alice:?}"
    );

    let bob = session.authenticate_none("bob").await.unwrap();
    if let client::AuthResult::Failure {
        remaining_methods, ..
    } = bob
    {
        assert!(
            remaining_methods.contains(&MethodKind::PublicKey),
            "server reused Alice's narrowed remaining methods for Bob: {remaining_methods:?}"
        );
    }

    server.abort();
}
