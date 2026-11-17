//! mTLS for the fleet serve API (control↔node, increment 3 of the mTLS plan).
//!
//! In a fleet, the worker runs `smolvm serve` and is driven by the control
//! plane. That channel must be mutually authenticated: the node presents a
//! CA-signed **server** cert, and only a client presenting a CA-signed **client**
//! cert (the control plane) may connect. This module builds the rustls
//! `ServerConfig` that enforces `require_and_verify_client_cert`.
//!
//! **Client identity:** a CA signature alone does not say *which* client
//! connected. With `--mtls-client-cn` only a client certificate whose subject
//! CN matches gets the API; other CA-signed certificates are refused at the
//! handshake, or, with `--mtls-allow-peer-blobs`, admitted for the `/p2p/`
//! blob routes only (see [`ClientIdentityPolicy`]).
//!
//! **Fail-closed:** when `SMOLVM_SERVE_REQUIRE_MTLS=1` the serve API refuses to
//! start without TLS configured — it must never fall back to plain HTTP / the
//! interim bearer token when the deploy declared it should be mTLS-protected.
//! This is a DEDICATED opt-in, deliberately NOT keyed off `SMOLVM_PUBLISH_ADDR`
//! (which every worker sets for the published-port datapath — overloading it
//! would make plain-HTTP workers refuse to boot).

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum_server::accept::Accept;
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::WebPkiClientVerifier;
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, RootCertStore, ServerConfig,
    SignatureScheme,
};
use rustls_pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, UnixTime};

/// Env var holding the node's PEM **server** cert (signed by the node-CA).
const ENV_CERT: &str = "SMOLVM_SERVE_TLS_CERT";
/// Env var holding the node's PEM private key.
const ENV_KEY: &str = "SMOLVM_SERVE_TLS_KEY";
/// Env var holding the PEM node-CA cert used to verify the control's client cert.
const ENV_CLIENT_CA: &str = "SMOLVM_SERVE_TLS_CLIENT_CA";
/// Dedicated opt-in: the deploy declares this serve API MUST run mTLS. When set,
/// a missing/partial cert config is fatal (fail-closed) rather than a silent
/// fall-back to plain HTTP. NOT keyed off `SMOLVM_PUBLISH_ADDR` (see module doc).
const ENV_REQUIRE_MTLS: &str = "SMOLVM_SERVE_REQUIRE_MTLS";

/// True when the deploy has declared this serve API must be mTLS-protected.
pub fn require_mtls() -> bool {
    matches!(
        std::env::var(ENV_REQUIRE_MTLS).ok().as_deref(),
        Some("1") | Some("true")
    )
}

/// Loopback plain-HTTP address for the **local** node-agent when the main port
/// runs mTLS. mTLS locks the whole network port to CA-signed clients, but the
/// node's own agent polls `/capacity` locally over plain HTTP — so we open a
/// second door bound to loopback only (unreachable from the network). Defaults
/// to `127.0.0.1:<main_port + 1>`; override with `SMOLVM_SERVE_LOCAL_ADDR`.
/// Returns `None` only if an override is set but unparseable.
pub fn local_plain_addr(main: std::net::SocketAddr) -> Option<std::net::SocketAddr> {
    match std::env::var("SMOLVM_SERVE_LOCAL_ADDR")
        .ok()
        .filter(|v| !v.is_empty())
    {
        Some(v) => v.parse().ok(),
        None => Some(std::net::SocketAddr::from((
            std::net::Ipv4Addr::LOCALHOST,
            main.port().wrapping_add(1),
        ))),
    }
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// Which client certificates may use which part of the serve API.
///
/// With no `client_cn` (the default) every client certificate that chains to
/// the configured CA has full access, exactly as before this policy existed.
/// With a `client_cn`, only a certificate whose subject CN equals it has full
/// access. Other CA-signed certificates are refused at the handshake, unless
/// `allow_peer_blobs` is set, in which case they are admitted but limited to
/// the `/p2p/` blob routes that sibling hosts use to fetch cached layers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientIdentityPolicy {
    /// Required subject CN for full API access; `None` disables the check.
    pub client_cn: Option<String>,
    /// Admit other CA-signed certificates for the `/p2p/` routes only.
    pub allow_peer_blobs: bool,
}

impl ClientIdentityPolicy {
    /// True when a client presenting a certificate with subject CN `cn` may
    /// use every route.
    fn grants_full_access(&self, cn: Option<&str>) -> bool {
        match &self.client_cn {
            None => true,
            Some(expected) => cn == Some(expected.as_str()),
        }
    }
}

/// Resolved TLS settings for the serve listener.
#[derive(Clone, Debug)]
pub struct ServeTls {
    /// rustls config with the client-cert verifier installed.
    pub config: Arc<ServerConfig>,
    /// Identity policy applied per connection and per request.
    pub policy: Arc<ClientIdentityPolicy>,
}

/// Resolve the serve API's TLS posture from the environment.
///
/// - All three TLS env vars set ⇒ `Ok(Some(config))` (mTLS, client cert required).
/// - None set, mTLS not required ⇒ `Ok(None)` (plain HTTP, local/dev/non-mTLS worker).
/// - **`SMOLVM_SERVE_REQUIRE_MTLS` set but TLS not fully configured ⇒ `Err` (fail-closed).**
/// - A partial config (some but not all vars) ⇒ `Err` (misconfiguration).
/// - A client CN required by `policy` but no TLS configured ⇒ `Err`, so an
///   identity restriction is never silently dropped.
pub fn resolve_tls(policy: ClientIdentityPolicy) -> Result<Option<ServeTls>, String> {
    if policy.client_cn.as_deref().is_some_and(str::is_empty) {
        return Err("--mtls-client-cn must not be empty".to_string());
    }
    let cert = env_path(ENV_CERT);
    let key = env_path(ENV_KEY);
    let client_ca = env_path(ENV_CLIENT_CA);

    match (cert, key, client_ca) {
        (Some(cert), Some(key), Some(client_ca)) => {
            let config = build_server_config(&cert, &key, &client_ca, &policy)?;
            Ok(Some(ServeTls {
                config,
                policy: Arc::new(policy),
            }))
        }
        (None, None, None) => {
            if policy.client_cn.is_some() {
                Err(format!(
                    "--mtls-client-cn requires {ENV_CERT}, {ENV_KEY} and {ENV_CLIENT_CA} to be set"
                ))
            } else if require_mtls() {
                Err(format!(
                    "{ENV_REQUIRE_MTLS} is set but {ENV_CERT}/{ENV_KEY}/{ENV_CLIENT_CA} are unset — \
                     refusing to start without client-cert verification (fail-closed)"
                ))
            } else {
                Ok(None)
            }
        }
        _ => Err(format!(
            "incomplete serve TLS config: set all of {ENV_CERT}, {ENV_KEY}, {ENV_CLIENT_CA} (or none)"
        )),
    }
}

/// Build a rustls server config that requires + verifies a client cert chained
/// to the node-CA.
fn build_server_config(
    cert_path: &Path,
    key_path: &Path,
    client_ca_path: &Path,
    policy: &ClientIdentityPolicy,
) -> Result<Arc<ServerConfig>, String> {
    // Pin the ring provider explicitly rather than relying on a process-global
    // install — avoids ordering hazards if anything else touches rustls.
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    // Client-cert trust anchor: the node-CA. Only the control plane holds a
    // client cert signed by it.
    let mut roots = RootCertStore::empty();
    for ca in CertificateDer::pem_file_iter(client_ca_path)
        .map_err(|e| format!("read client CA {}: {e}", client_ca_path.display()))?
    {
        let ca = ca.map_err(|e| format!("parse client CA cert: {e}"))?;
        roots
            .add(ca)
            .map_err(|e| format!("add client CA to root store: {e}"))?;
    }
    if roots.is_empty() {
        return Err(format!(
            "client CA {} contained no certificates",
            client_ca_path.display()
        ));
    }
    let webpki = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|e| format!("build client-cert verifier: {e}"))?;
    // Without a required CN the stock verifier is used unchanged. With one,
    // wrap it so the handshake also checks the subject CN (unless other
    // CA-signed peers are admitted for the /p2p/ routes, in which case the
    // per-request middleware enforces the restriction).
    let verifier: Arc<dyn ClientCertVerifier> = match &policy.client_cn {
        Some(cn) if !policy.allow_peer_blobs => {
            Arc::new(CommonNameClientVerifier::new(webpki, cn.clone()))
        }
        _ => webpki,
    };

    // Our server identity (node server cert + key).
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert_path)
        .map_err(|e| format!("read server cert {}: {e}", cert_path.display()))?
        .collect::<Result<_, _>>()
        .map_err(|e| format!("parse server cert chain: {e}"))?;
    if certs.is_empty() {
        return Err(format!(
            "server cert {} contained no certificates",
            cert_path.display()
        ));
    }
    let key = PrivateKeyDer::from_pem_file(key_path)
        .map_err(|e| format!("read server key {}: {e}", key_path.display()))?;

    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("rustls protocol versions: {e}"))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|e| format!("install server cert/key: {e}"))?;
    // axum-server speaks h2 + http/1.1; advertise both via ALPN.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(Arc::new(config))
}

/// Subject common name of a DER certificate, or `None` when it cannot be
/// parsed or carries no UTF-8 CN.
fn subject_cn(cert: &CertificateDer<'_>) -> Option<String> {
    let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref()).ok()?;
    let cn = parsed
        .subject()
        .iter_common_name()
        .next()?
        .as_str()
        .ok()?
        .to_string();
    Some(cn)
}

/// Client-cert verifier that runs the WebPKI chain check and then requires the
/// end-entity certificate's subject CN to equal `expected_cn`.
#[derive(Debug)]
struct CommonNameClientVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    expected_cn: String,
}

impl CommonNameClientVerifier {
    fn new(inner: Arc<dyn ClientCertVerifier>, expected_cn: String) -> Self {
        Self { inner, expected_cn }
    }
}

impl ClientCertVerifier for CommonNameClientVerifier {
    fn offer_client_auth(&self) -> bool {
        self.inner.offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.inner.client_auth_mandatory()
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let verified = self
            .inner
            .verify_client_cert(end_entity, intermediates, now)?;
        match subject_cn(end_entity) {
            Some(cn) if cn == self.expected_cn => Ok(verified),
            cn => {
                tracing::warn!(
                    client_cn = cn.as_deref().unwrap_or("<none>"),
                    expected_cn = %self.expected_cn,
                    "rejected mTLS client certificate: subject CN does not match"
                );
                Err(rustls::Error::InvalidCertificate(
                    CertificateError::ApplicationVerificationFailure,
                ))
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        self.inner.requires_raw_public_keys()
    }
}

/// Identity of the mTLS client on a connection, attached to every request it
/// carries as a request extension.
#[derive(Debug, Clone)]
pub struct MtlsClientIdentity {
    /// Subject CN of the verified client certificate, if any.
    pub cn: Option<String>,
    /// Whether this client may use every route (otherwise `/p2p/` only).
    pub full_access: bool,
}

/// Acceptor that performs the rustls handshake and then tags the connection's
/// service with the client's [`MtlsClientIdentity`].
#[derive(Clone)]
pub struct IdentityAcceptor {
    inner: RustlsAcceptor,
    policy: Arc<ClientIdentityPolicy>,
}

impl IdentityAcceptor {
    pub fn new(tls: &ServeTls) -> Self {
        Self {
            inner: RustlsAcceptor::new(RustlsConfig::from_config(tls.config.clone())),
            policy: tls.policy.clone(),
        }
    }
}

type AcceptFuture<St, Sv> =
    Pin<Box<dyn Future<Output = std::io::Result<(St, Sv)>> + Send + 'static>>;

impl<S> Accept<tokio::net::TcpStream, S> for IdentityAcceptor
where
    S: Send + 'static,
{
    type Stream = <RustlsAcceptor as Accept<tokio::net::TcpStream, S>>::Stream;
    type Service = WithClientIdentity<S>;
    type Future = AcceptFuture<Self::Stream, Self::Service>;

    fn accept(&self, stream: tokio::net::TcpStream, service: S) -> Self::Future {
        let handshake = self.inner.accept(stream, service);
        let policy = self.policy.clone();
        Box::pin(async move {
            let (stream, service) = handshake.await?;
            let cn = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certs| certs.first())
                .and_then(subject_cn);
            let identity = MtlsClientIdentity {
                full_access: policy.grants_full_access(cn.as_deref()),
                cn,
            };
            Ok((
                stream,
                WithClientIdentity {
                    inner: service,
                    identity,
                },
            ))
        })
    }
}

/// Per-connection service wrapper that inserts the connection's
/// [`MtlsClientIdentity`] into every request's extensions.
#[derive(Clone)]
pub struct WithClientIdentity<S> {
    inner: S,
    identity: MtlsClientIdentity,
}

impl<S, B> tower::Service<axum::http::Request<B>> for WithClientIdentity<S>
where
    S: tower::Service<axum::http::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: axum::http::Request<B>) -> Self::Future {
        req.extensions_mut().insert(self.identity.clone());
        self.inner.call(req)
    }
}

/// Route prefix that admitted non-matching CA-signed peers may use.
const PEER_ROUTE_PREFIX: &str = "/p2p/";

/// Middleware for the mTLS listener: a client without full access may only
/// reach the `/p2p/` routes; everything else is `403`. A request with no
/// identity attached is refused (fail-closed).
pub async fn enforce_client_identity(req: Request, next: Next) -> Response {
    let allowed = match req.extensions().get::<MtlsClientIdentity>() {
        Some(id) if id.full_access => true,
        Some(_) => req.uri().path().starts_with(PEER_ROUTE_PREFIX),
        None => false,
    };
    if allowed {
        next.run(req).await
    } else {
        let cn = req
            .extensions()
            .get::<MtlsClientIdentity>()
            .and_then(|id| id.cn.as_deref())
            .unwrap_or("<none>");
        tracing::warn!(
            client_cn = cn,
            path = req.uri().path(),
            "refused request: client certificate is limited to peer blob routes"
        );
        (
            StatusCode::FORBIDDEN,
            "client certificate is not authorized for this route",
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // resolve_tls reads process env; these run serially via a shared guard to
    // avoid cross-test interference on the shared env vars.
    fn lock() -> std::sync::MutexGuard<'static, ()> {
        static L: std::sync::Mutex<()> = std::sync::Mutex::new(());
        L.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn clear() {
        for v in [ENV_CERT, ENV_KEY, ENV_CLIENT_CA, ENV_REQUIRE_MTLS] {
            std::env::remove_var(v);
        }
    }

    #[test]
    fn no_env_not_required_is_plain_http() {
        let _g = lock();
        clear();
        assert!(resolve_tls(ClientIdentityPolicy::default())
            .unwrap()
            .is_none());
    }

    #[test]
    fn require_mtls_without_tls_fails_closed() {
        let _g = lock();
        clear();
        std::env::set_var(ENV_REQUIRE_MTLS, "1");
        let err = resolve_tls(ClientIdentityPolicy::default()).unwrap_err();
        assert!(err.contains("fail-closed"), "{err}");
        clear();
    }

    #[test]
    fn local_plain_addr_defaults_to_loopback_port_plus_one() {
        let _g = lock();
        std::env::remove_var("SMOLVM_SERVE_LOCAL_ADDR");
        let main: std::net::SocketAddr = "0.0.0.0:8080".parse().unwrap();
        let local = local_plain_addr(main).unwrap();
        assert!(local.ip().is_loopback());
        assert_eq!(local.port(), 8081);
    }

    #[test]
    fn local_plain_addr_honors_override() {
        let _g = lock();
        std::env::set_var("SMOLVM_SERVE_LOCAL_ADDR", "127.0.0.1:9999");
        let local = local_plain_addr("0.0.0.0:8080".parse().unwrap()).unwrap();
        assert_eq!(local.port(), 9999);
        std::env::remove_var("SMOLVM_SERVE_LOCAL_ADDR");
    }

    #[test]
    fn publish_addr_alone_does_not_force_mtls() {
        // A worker sets SMOLVM_PUBLISH_ADDR for the datapath; that must NOT make
        // a plain-HTTP serve refuse to start.
        let _g = lock();
        clear();
        std::env::set_var("SMOLVM_PUBLISH_ADDR", "0.0.0.0");
        assert!(resolve_tls(ClientIdentityPolicy::default())
            .unwrap()
            .is_none());
        std::env::remove_var("SMOLVM_PUBLISH_ADDR");
    }

    #[test]
    fn partial_tls_config_is_rejected() {
        let _g = lock();
        clear();
        std::env::set_var(ENV_CERT, "/tmp/x.crt");
        let err = resolve_tls(ClientIdentityPolicy::default()).unwrap_err();
        assert!(err.contains("incomplete"), "{err}");
        clear();
    }

    // ---- client identity (subject CN) enforcement ----

    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    };

    struct Ca {
        cert: rcgen::Certificate,
        key: KeyPair,
    }

    struct Leaf {
        cert: rcgen::Certificate,
        key: KeyPair,
    }

    fn make_ca(name: &str) -> Ca {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        Ca { cert, key }
    }

    fn make_leaf(ca: &Ca, cn: &str) -> Leaf {
        let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.distinguished_name.push(DnType::CommonName, cn);
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &ca.cert, &ca.key).unwrap();
        Leaf { cert, key }
    }

    fn cn_verifier(ca: &Ca, expected: &str) -> CommonNameClientVerifier {
        let mut roots = RootCertStore::empty();
        roots.add(ca.cert.der().clone()).unwrap();
        let webpki = WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .unwrap();
        CommonNameClientVerifier::new(webpki, expected.to_string())
    }

    #[test]
    fn subject_cn_reads_common_name() {
        let ca = make_ca("test-ca");
        let leaf = make_leaf(&ca, "api-client");
        assert_eq!(subject_cn(leaf.cert.der()).as_deref(), Some("api-client"));
    }

    #[test]
    fn verifier_accepts_matching_cn() {
        let ca = make_ca("test-ca");
        let client = make_leaf(&ca, "api-client");
        let verifier = cn_verifier(&ca, "api-client");
        verifier
            .verify_client_cert(client.cert.der(), &[], UnixTime::now())
            .expect("matching CN must be accepted");
    }

    #[test]
    fn verifier_rejects_other_ca_signed_cn() {
        let ca = make_ca("test-ca");
        let other = make_leaf(&ca, "host-7");
        let verifier = cn_verifier(&ca, "api-client");
        let err = verifier
            .verify_client_cert(other.cert.der(), &[], UnixTime::now())
            .unwrap_err();
        assert!(
            matches!(
                err,
                rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
            ),
            "{err:?}"
        );
    }

    #[test]
    fn verifier_rejects_foreign_ca_even_with_matching_cn() {
        let ca = make_ca("test-ca");
        let foreign = make_ca("foreign-ca");
        let client = make_leaf(&foreign, "api-client");
        let verifier = cn_verifier(&ca, "api-client");
        let err = verifier
            .verify_client_cert(client.cert.der(), &[], UnixTime::now())
            .unwrap_err();
        assert!(
            !matches!(
                err,
                rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
            ),
            "foreign CA must fail chain verification, got {err:?}"
        );
    }

    #[test]
    fn policy_without_cn_grants_everyone_full_access() {
        let policy = ClientIdentityPolicy::default();
        assert!(policy.grants_full_access(Some("anything")));
        assert!(policy.grants_full_access(None));
        let policy = ClientIdentityPolicy {
            client_cn: Some("api-client".into()),
            allow_peer_blobs: true,
        };
        assert!(policy.grants_full_access(Some("api-client")));
        assert!(!policy.grants_full_access(Some("host-7")));
        assert!(!policy.grants_full_access(None));
    }

    #[test]
    fn client_cn_without_tls_is_rejected() {
        let _g = lock();
        clear();
        let err = resolve_tls(ClientIdentityPolicy {
            client_cn: Some("api-client".into()),
            allow_peer_blobs: false,
        })
        .unwrap_err();
        assert!(err.contains("--mtls-client-cn"), "{err}");
    }

    /// Certificates for an end-to-end serve test, written to a temp dir.
    struct Pki {
        dir: tempfile::TempDir,
        ca: Ca,
    }

    impl Pki {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let ca = make_ca("test-ca");
            let server = make_leaf(&ca, "server");
            std::fs::write(dir.path().join("ca.pem"), ca.cert.pem()).unwrap();
            std::fs::write(dir.path().join("server.pem"), server.cert.pem()).unwrap();
            std::fs::write(dir.path().join("server.key"), server.key.serialize_pem()).unwrap();
            Self { dir, ca }
        }

        fn serve_tls(&self, policy: ClientIdentityPolicy) -> ServeTls {
            let d = self.dir.path();
            let config = build_server_config(
                &d.join("server.pem"),
                &d.join("server.key"),
                &d.join("ca.pem"),
                &policy,
            )
            .unwrap();
            ServeTls {
                config,
                policy: Arc::new(policy),
            }
        }

        fn client(&self, issuer: &Ca, cn: &str, addr: std::net::SocketAddr) -> reqwest::Client {
            let leaf = make_leaf(issuer, cn);
            let identity_pem = format!("{}\n{}", leaf.cert.pem(), leaf.key.serialize_pem());
            reqwest::Client::builder()
                .use_rustls_tls()
                .tls_built_in_root_certs(false)
                .add_root_certificate(
                    reqwest::Certificate::from_pem(self.ca.cert.pem().as_bytes()).unwrap(),
                )
                .identity(reqwest::Identity::from_pem(identity_pem.as_bytes()).unwrap())
                .resolve("localhost", addr)
                .build()
                .unwrap()
        }
    }

    /// Start an mTLS listener with the production acceptor and middleware in
    /// front of a router exposing one API route and one peer blob route.
    async fn start_server(tls: ServeTls) -> (std::net::SocketAddr, axum_server::Handle) {
        use axum::routing::get;
        let app = axum::Router::new()
            .route("/api/v1/machines", get(|| async { "machines" }))
            .route("/p2p/blob/{digest}", get(|| async { "blob" }))
            .layer(axum::middleware::from_fn(enforce_client_identity));
        let handle = axum_server::Handle::new();
        let server = axum_server::bind("127.0.0.1:0".parse().unwrap())
            .acceptor(IdentityAcceptor::new(&tls))
            .handle(handle.clone());
        tokio::spawn(async move {
            let _ = server.serve(app.into_make_service()).await;
        });
        let addr = handle.listening().await.expect("server bound");
        (addr, handle)
    }

    async fn status(
        client: &reqwest::Client,
        addr: std::net::SocketAddr,
        path: &str,
    ) -> Option<u16> {
        client
            .get(format!("https://localhost:{}{path}", addr.port()))
            .send()
            .await
            .ok()
            .map(|r| r.status().as_u16())
    }

    #[tokio::test]
    async fn e2e_non_matching_client_refused_at_handshake() {
        let pki = Pki::new();
        let (addr, handle) = start_server(pki.serve_tls(ClientIdentityPolicy {
            client_cn: Some("api-client".into()),
            allow_peer_blobs: false,
        }))
        .await;

        let good = pki.client(&pki.ca, "api-client", addr);
        assert_eq!(status(&good, addr, "/api/v1/machines").await, Some(200));
        assert_eq!(status(&good, addr, "/p2p/blob/x").await, Some(200));

        let other = pki.client(&pki.ca, "host-7", addr);
        assert_eq!(status(&other, addr, "/api/v1/machines").await, None);
        assert_eq!(status(&other, addr, "/p2p/blob/x").await, None);

        let foreign = make_ca("foreign-ca");
        let stranger = pki.client(&foreign, "api-client", addr);
        assert_eq!(status(&stranger, addr, "/api/v1/machines").await, None);
        handle.shutdown();
    }

    #[tokio::test]
    async fn e2e_peer_blobs_limit_other_clients_to_p2p() {
        let pki = Pki::new();
        let (addr, handle) = start_server(pki.serve_tls(ClientIdentityPolicy {
            client_cn: Some("api-client".into()),
            allow_peer_blobs: true,
        }))
        .await;

        let good = pki.client(&pki.ca, "api-client", addr);
        assert_eq!(status(&good, addr, "/api/v1/machines").await, Some(200));

        let peer = pki.client(&pki.ca, "host-7", addr);
        assert_eq!(status(&peer, addr, "/p2p/blob/x").await, Some(200));
        assert_eq!(status(&peer, addr, "/api/v1/machines").await, Some(403));

        let foreign = make_ca("foreign-ca");
        let stranger = pki.client(&foreign, "host-7", addr);
        assert_eq!(status(&stranger, addr, "/p2p/blob/x").await, None);
        handle.shutdown();
    }

    #[tokio::test]
    async fn e2e_without_client_cn_any_ca_signed_client_has_full_access() {
        let pki = Pki::new();
        let (addr, handle) = start_server(pki.serve_tls(ClientIdentityPolicy::default())).await;

        let other = pki.client(&pki.ca, "host-7", addr);
        assert_eq!(status(&other, addr, "/api/v1/machines").await, Some(200));
        assert_eq!(status(&other, addr, "/p2p/blob/x").await, Some(200));
        handle.shutdown();
    }
}
