//! Regression test catching <https://github.com/Eugeny/russh/issues/772>.
use std::sync::Arc;
use std::time::Duration;

use russh::keys::ssh_key::certificate::{Builder, CertType};
use russh::keys::{PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate, ssh_key};
use russh::{MethodKind, MethodSet, client, server};

struct AcceptServerKey;

impl client::Handler for AcceptServerKey {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

struct PartialSuccessServer;

impl server::Handler for PartialSuccessServer {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<server::Auth, Self::Error> {
        Ok(partial_success_reject())
    }

    async fn auth_password(
        &mut self,
        _user: &str,
        password: &str,
    ) -> Result<server::Auth, Self::Error> {
        if password == "wrong" {
            Ok(server::Auth::reject())
        } else {
            Ok(partial_success_reject())
        }
    }

    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        _public_key: server::PublicKeyOffer<'_>,
    ) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _public_key: server::VerifiedPublicKey<'_>,
    ) -> Result<server::Auth, Self::Error> {
        Ok(partial_success_reject())
    }

    async fn auth_keyboard_interactive(
        &mut self,
        _user: &str,
        _submethods: &str,
        response: Option<server::Response<'_>>,
    ) -> Result<server::Auth, Self::Error> {
        if response.is_some() {
            Ok(partial_success_reject())
        } else {
            Ok(server::Auth::Partial {
                name: "".into(),
                instructions: "".into(),
                prompts: vec![("token: ".into(), true)].into(),
            })
        }
    }
}

fn partial_success_reject() -> server::Auth {
    server::Auth::Reject {
        proceed_with_methods: Some(MethodSet::from(&[MethodKind::KeyboardInteractive][..])),
        partial_success: true,
    }
}

async fn connect() -> client::Handle<AcceptServerKey> {
    let mut server_config = server::Config::default();
    server_config.auth_rejection_time = Duration::from_millis(1);
    server_config.auth_rejection_time_initial = Some(Duration::from_millis(1));
    // A partial success must not count as a failed attempt: every test below
    // that sends a second request after a partial success relies on this.
    server_config.max_auth_attempts = 1;
    server_config
        .keys
        .push(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());
    let server_config = Arc::new(server_config);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let _ = server::run_stream(server_config, socket, PartialSuccessServer)
            .await
            .unwrap();
    });

    client::connect(Arc::new(client::Config::default()), addr, AcceptServerKey)
        .await
        .unwrap()
}

#[track_caller]
fn assert_partial_success(partial_success: bool, remaining_methods: &MethodSet) {
    assert!(
        remaining_methods.contains(&MethodKind::KeyboardInteractive),
        "server should advertise a continue method: {remaining_methods:?}",
    );
    assert!(
        partial_success,
        "handler returned Auth::Reject {{ partial_success: true }}, client got partial_success = \
            false"
    );
}

#[tokio::test]
async fn none() {
    let mut session = connect().await;
    let client::AuthResult::Failure {
        partial_success,
        remaining_methods,
    } = session.authenticate_none("alice").await.unwrap()
    else {
        panic!("expected AuthResult::Failure");
    };
    assert_partial_success(partial_success, &remaining_methods);
}

#[tokio::test]
async fn password() {
    let mut session = connect().await;
    let client::AuthResult::Failure {
        partial_success,
        remaining_methods,
    } = session
        .authenticate_password("alice", "hunter2")
        .await
        .unwrap()
    else {
        panic!("expected AuthResult::Failure");
    };
    assert_partial_success(partial_success, &remaining_methods);
}

#[tokio::test]
async fn publickey() {
    let mut session = connect().await;
    let key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
    let client::AuthResult::Failure {
        partial_success,
        remaining_methods,
    } = session
        .authenticate_publickey("alice", PrivateKeyWithHashAlg::new(Arc::new(key), None))
        .await
        .unwrap()
    else {
        panic!("expected AuthResult::Failure");
    };
    assert_partial_success(partial_success, &remaining_methods);
}

#[tokio::test]
async fn keyboard_interactive() {
    let mut session = connect().await;
    let start = session
        .authenticate_keyboard_interactive_start("alice", None::<String>)
        .await
        .unwrap();
    assert!(
        matches!(
            start,
            client::KeyboardInteractiveAuthResponse::InfoRequest { .. }
        ),
        "expected InfoRequest, got {start:?}",
    );
    let client::KeyboardInteractiveAuthResponse::Failure {
        partial_success,
        remaining_methods,
    } = session
        .authenticate_keyboard_interactive_respond(vec!["123456".to_string()])
        .await
        .unwrap()
    else {
        panic!("expected KeyboardInteractiveAuthResponse::Failure");
    };
    assert_partial_success(partial_success, &remaining_methods);
}

/// The flag describes only the request it answers: a plain rejection after a
/// partial success must not inherit it.
#[tokio::test]
async fn plain_rejection_after_partial_success() {
    let mut session = connect().await;
    let first = session.authenticate_password("alice", "ok").await.unwrap();
    assert!(
        matches!(
            first,
            client::AuthResult::Failure {
                partial_success: true,
                ..
            }
        ),
        "expected partial success, got {first:?}"
    );
    let second = session
        .authenticate_password("alice", "wrong")
        .await
        .unwrap();
    // An empty method set means the server disconnected instead of answering.
    assert!(
        matches!(
            second,
            client::AuthResult::Failure {
                partial_success: false,
                ref remaining_methods,
            } if !remaining_methods.is_empty()
        ),
        "stale partial_success leaked into a plain rejection: {second:?}"
    );
}

/// Rejections that never reach a handler (here: an expired certificate) must
/// not report a partial success left over from an earlier request.
#[tokio::test]
async fn handlerless_rejection_after_partial_success() {
    let mut session = connect().await;
    let first = session.authenticate_password("alice", "ok").await.unwrap();
    assert!(
        matches!(
            first,
            client::AuthResult::Failure {
                partial_success: true,
                ..
            }
        ),
        "expected partial success, got {first:?}"
    );

    let key = Arc::new(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());
    let ca = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
    let mut builder =
        Builder::new_with_random_nonce(&mut rand::rng(), key.public_key().clone(), 1, 2).unwrap();
    builder.cert_type(CertType::User).unwrap();
    builder.valid_principal("alice").unwrap();
    let expired_cert = builder.sign(&ca).unwrap();

    let second = session
        .authenticate_openssh_cert("alice", key, expired_cert)
        .await
        .unwrap();
    // An empty method set means the server disconnected instead of answering.
    assert!(
        matches!(
            second,
            client::AuthResult::Failure {
                partial_success: false,
                ref remaining_methods,
            } if !remaining_methods.is_empty()
        ),
        "expired cert reported as partial success: {second:?}"
    );
}
