//! A [`Signer`] that cannot produce a signature (an agent that does not hold
//! the key, a declined confirmation, a hardware key that was not touched)
//! must not leave the session stuck: the handle has to stay usable for the
//! authentication attempts that follow.
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use russh::keys::agent::AgentIdentity;
use russh::keys::agent::client::AgentClient;
use russh::keys::ssh_key::certificate::{Builder, CertType};
use russh::keys::{HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate, ssh_key};
use russh::{AgentAuthError, Signer, client, server};

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

/// Answers every public key probe with PK_OK (the default) and accepts every
/// verified signature; passwords are rejected (the default).
struct AcceptAnyKeyServer;

impl server::Handler for AcceptAnyKeyServer {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _public_key: server::VerifiedPublicKey<'_>,
    ) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }
}

#[derive(Debug)]
enum NoSignature {
    Refused,
    Send(russh::SendError),
}

impl From<russh::SendError> for NoSignature {
    fn from(e: russh::SendError) -> Self {
        Self::Send(e)
    }
}

/// Fails every signing request.
struct RefusingSigner;

impl Signer for RefusingSigner {
    type Error = NoSignature;

    async fn auth_sign(
        &mut self,
        _key: &AgentIdentity,
        _hash_alg: Option<HashAlg>,
        _to_sign: Vec<u8>,
    ) -> Result<Vec<u8>, Self::Error> {
        Err(NoSignature::Refused)
    }
}

fn random_key() -> Arc<PrivateKey> {
    Arc::new(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap())
}

async fn connect() -> client::Handle<AcceptServerKey> {
    let mut server_config = server::Config::default();
    server_config.inactivity_timeout = None;
    server_config.auth_rejection_time = Duration::from_millis(1);
    server_config.auth_rejection_time_initial = Some(Duration::from_millis(1));
    server_config
        .keys
        .push(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());
    let server_config = Arc::new(server_config);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let running = server::run_stream(server_config, socket, AcceptAnyKeyServer)
            .await
            .unwrap();
        running.await
    });

    client::connect(Arc::new(client::Config::default()), addr, AcceptServerKey)
        .await
        .unwrap()
}

/// What a client does after a signer failed, in the order Tabby does it. Each
/// step hung, or failed with `Inconsistent`, while the session was still
/// waiting for the signature that never came.
async fn assert_session_usable(
    session: &mut client::Handle<AcceptServerKey>,
    key: Arc<PrivateKey>,
) {
    tokio::time::timeout(Duration::from_secs(10), async {
        // Answered through a oneshot: the parked session dropped it.
        session
            .best_supported_rsa_hash()
            .await
            .expect("best_supported_rsa_hash() failed after the signer's failure");

        // Answered through the reply channel: the parked session never sent it.
        let password = session
            .authenticate_password("alice", "wrong")
            .await
            .unwrap();
        assert!(
            !password.success(),
            "unexpected password result: {password:?}"
        );

        // The key on disk, as Tabby's fallback. The server still gets a probe
        // and a signed request for it after the abandoned PK_OK.
        let result = session
            .authenticate_publickey("alice", PrivateKeyWithHashAlg::new(key, None))
            .await
            .unwrap();
        assert!(result.success(), "expected success, got {result:?}");
    })
    .await
    .expect("the session ignored everything sent after the signer's failure");
}

#[tokio::test]
async fn publickey_signer_failure_leaves_the_session_usable() {
    let mut session = connect().await;
    let key = random_key();

    let err = session
        .authenticate_publickey_with("alice", key.public_key().clone(), None, &mut RefusingSigner)
        .await
        .unwrap_err();
    assert!(
        matches!(err, NoSignature::Refused),
        "unexpected error: {err:?}"
    );

    assert_session_usable(&mut session, key).await;
}

#[tokio::test]
async fn certificate_signer_failure_leaves_the_session_usable() {
    let mut session = connect().await;
    let key = random_key();

    let ca = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut builder = Builder::new_with_random_nonce(
        &mut rand::rng(),
        key.public_key().clone(),
        now - 60,
        now + 60,
    )
    .unwrap();
    builder.cert_type(CertType::User).unwrap();
    builder.valid_principal("alice").unwrap();
    let cert = builder.sign(&ca).unwrap();

    let err = session
        .authenticate_certificate_with("alice", cert, None, &mut RefusingSigner)
        .await
        .unwrap_err();
    assert!(
        matches!(err, NoSignature::Refused),
        "unexpected error: {err:?}"
    );

    assert_session_usable(&mut session, key).await;
}

/// The case behind Eugeny/tabby#11743: the key offered through the agent is
/// one the agent does not hold, so the agent refuses to sign after the server
/// said PK_OK. Later attempts through the same agent have to work.
#[tokio::test]
async fn agent_without_the_key_leaves_the_session_usable() {
    let mut session = connect().await;
    let key = random_key();

    let (ours, agents) = tokio::io::duplex(64 * 1024);
    tokio::spawn(russh::keys::agent::server::serve(
        tokio_stream::once(Ok(agents)),
        (),
    ));
    let mut agent = AgentClient::connect(ours);

    let err = session
        .authenticate_publickey_with("alice", key.public_key().clone(), None, &mut agent)
        .await
        .unwrap_err();
    assert!(
        matches!(err, AgentAuthError::Key(russh::keys::Error::AgentFailure)),
        "unexpected error: {err:?}"
    );

    // Once the agent holds the key, the same attempt goes through.
    agent.add_identity(&key, &[]).await.unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        session.authenticate_publickey_with("alice", key.public_key().clone(), None, &mut agent),
    )
    .await
    .expect("the session ignored the attempt that followed the agent's failure")
    .unwrap();
    assert!(result.success(), "expected success, got {result:?}");
}
