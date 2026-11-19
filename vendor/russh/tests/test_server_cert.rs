#![cfg(not(target_arch = "wasm32"))]
use std::borrow::Cow;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use russh::keys::PublicKeyOrCertificate;
use russh::keys::ssh_key::certificate::{Builder, CertType};
use russh::keys::ssh_key::{self, Algorithm, HashAlg, PrivateKey};
use russh::*;
use tokio::net::TcpListener;

fn host_cert(
    subject: &PrivateKey,
    signing_ca: &PrivateKey,
    valid_after: u64,
    valid_before: u64,
) -> russh::keys::Certificate {
    let mut builder = Builder::new_with_random_nonce(
        &mut rand::rng(),
        subject.public_key().clone(),
        valid_after,
        valid_before,
    )
    .unwrap();
    builder.serial(42).unwrap();
    builder.key_id("test-server").unwrap();
    builder.cert_type(CertType::Host).unwrap();
    builder.valid_principal("localhost").unwrap();
    builder.sign(signing_ca).unwrap()
}

/// Spin up a server with `config` and connect a client that trusts
/// `trusted_ca` and advertises the certificate algorithm `cert_algo`.
/// Returns the connect result.
async fn serve_and_connect(
    config: server::Config,
    cert_algo: Algorithm,
    trusted_ca: &PrivateKey,
) -> Result<client::Handle<TestClient>, russh::Error> {
    let config = Arc::new(config);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let _ = server::run_stream(config, socket, TestServer {})
            .await
            .unwrap();
    });

    let mut client_config = client::Config::default();
    // Opt into host certificates: advertise the certificate algorithm.
    client_config.preferred.host_key_certificates = Cow::Owned(vec![cert_algo]);
    let client_config = Arc::new(client_config);

    let client = TestClient {
        ca_public_key: trusted_ca.public_key().clone(),
    };

    client::connect(client_config, addr, client).await
}

/// Spin up a server presenting a host certificate for `key_algo` signed by
/// `signing_ca`, and connect a client that trusts `trusted_ca` and advertises
/// the certificate algorithm `cert_algo`. Returns the connect result.
async fn connect_with_cert(
    key_algo: Algorithm,
    cert_algo: Algorithm,
    valid_after: u64,
    valid_before: u64,
    trusted_ca: &PrivateKey,
    signing_ca: &PrivateKey,
) -> Result<client::Handle<TestClient>, russh::Error> {
    let server_key = PrivateKey::random(&mut rand::rng(), key_algo).unwrap();
    let cert = host_cert(&server_key, signing_ca, valid_after, valid_before);

    let mut config = server::Config::default();
    config.keys.push(server_key);
    config.certificates.push(cert);

    serve_and_connect(config, cert_algo, trusted_ca).await
}

#[tokio::test]
async fn test_server_certificate_auth() {
    let _ = env_logger::try_init();

    let ca_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let session = connect_with_cert(
        Algorithm::Ed25519,
        Algorithm::Ed25519,
        now,
        now + 3600,
        &ca_key,
        &ca_key,
    )
    .await
    .unwrap();

    session
        .disconnect(Disconnect::ByApplication, "", "")
        .await
        .unwrap();
}

#[tokio::test]
async fn test_server_wrong_ca_certificate_auth() {
    let _ = env_logger::try_init();

    let ca_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let evil_ca_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if let Ok(session) = connect_with_cert(
        Algorithm::Ed25519,
        Algorithm::Ed25519,
        now,
        now + 3600,
        &ca_key,
        &evil_ca_key,
    )
    .await
    {
        session
            .disconnect(Disconnect::ByApplication, "", "")
            .await
            .unwrap();
        panic!("client connected to server with wrong ca in certificate");
    }
}

#[tokio::test]
async fn test_server_rsa_sha2_512_certificate_auth() {
    let _ = env_logger::try_init();

    let rsa = Algorithm::Rsa {
        hash: Some(HashAlg::Sha512),
    };
    let ca_key = PrivateKey::random(&mut rand::rng(), rsa.clone()).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let session = connect_with_cert(rsa.clone(), rsa, now, now + 3600, &ca_key, &ca_key)
        .await
        .unwrap();

    session
        .disconnect(Disconnect::ByApplication, "", "")
        .await
        .unwrap();
}

#[tokio::test]
async fn test_server_infinite_validity_certificate_auth() {
    let _ = env_logger::try_init();

    let ca_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();

    // A host cert with valid_after=0 and valid_before=u64::MAX (OpenSSH
    // "always valid" sentinels per PROTOCOL.certkeys), matching what
    // `ssh-keygen -s ca -h key.pub` generates without the -V flag.
    let session = connect_with_cert(
        Algorithm::Ed25519,
        Algorithm::Ed25519,
        0,
        u64::MAX,
        &ca_key,
        &ca_key,
    )
    .await
    .unwrap();

    session
        .disconnect(Disconnect::ByApplication, "", "")
        .await
        .unwrap();
}

/// Regression test: a certificate whose private key is absent from
/// `config.keys` must be skipped at presentation time (not only at
/// advertisement time), so a later certificate that does have its key
/// still works.
#[tokio::test]
async fn test_server_stale_certificate_is_skipped() {
    let _ = env_logger::try_init();

    let ca_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let stale_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let good_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();

    let mut config = server::Config::default();
    config
        .certificates
        .push(host_cert(&stale_key, &ca_key, 0, u64::MAX));
    config
        .certificates
        .push(host_cert(&good_key, &ca_key, 0, u64::MAX));
    config.keys.push(good_key);

    let session = serve_and_connect(config, Algorithm::Ed25519, &ca_key)
        .await
        .unwrap();

    session
        .disconnect(Disconnect::ByApplication, "", "")
        .await
        .unwrap();
}

struct TestServer {}

impl server::Handler for TestServer {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        _: &str,
        _: server::VerifiedPublicKey<'_>,
    ) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }
}

struct TestClient {
    ca_public_key: ssh_key::PublicKey,
}

impl client::Handler for TestClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        match server_public_key {
            PublicKeyOrCertificate::Certificate(cert) => {
                // Check that the certificate was signed by the trusted CA.
                let fingerprint = self.ca_public_key.fingerprint(HashAlg::Sha256);
                if let Err(e) = cert.validate([&fingerprint]) {
                    eprintln!("Host certificate signature verification failed: {e}");
                    return Ok(false);
                }

                // Check the certificate's validity period.
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                if now < cert.valid_after() || now > cert.valid_before() {
                    eprintln!("Host certificate is outside its validity period.");
                    return Ok(false);
                }

                // Check the certificate's valid principals.
                let target_hostname = "localhost";
                if !cert
                    .valid_principals()
                    .contains(&target_hostname.to_string())
                {
                    eprintln!("Host certificate is not valid for principal: {target_hostname}");
                    return Ok(false);
                }

                Ok(true)
            }
            PublicKeyOrCertificate::PublicKey { .. } => {
                // Certificate-only environment: reject plain host keys.
                eprintln!("Server presented a plain public key, not a certificate.");
                Ok(false)
            }
        }
    }
}
