//! Secret egress broker: let a guest workload make authenticated outbound
//! requests without ever holding the real secret.
//!
//! Clean-room design. The problem it solves is the one smolvm's own secrets
//! doc calls out as the natural follow-up to env injection
//! (`docs/secrets.md`, "use without plaintext"): today a resolved secret is
//! injected as plaintext into the guest process environment, so anything root
//! in the guest — or the workload itself, if compromised — can read it from
//! `/proc/<pid>/environ`. The broker keeps the real value on the host and hands
//! the guest only a **placeholder**. When the guest makes an outbound HTTPS
//! request carrying that placeholder (typically in an `Authorization` header),
//! a host-side forward proxy MITMs the connection and swaps the placeholder for
//! the real value on the wire, so the credential reaches the upstream API but
//! never exists inside the VM.
//!
//! # Pieces
//!
//! - [`CaAuthority`] — a per-broker certificate authority. It generates one CA
//!   (whose cert is installed into the guest trust store) and mints a leaf
//!   certificate on demand for each host the guest connects to, so the proxy
//!   can terminate TLS transparently. The CA private key never leaves the host.
//! - [`SubstitutionTable`] — the placeholder↔secret registry. It generates
//!   high-entropy placeholders, hands them out for guest env injection, and
//!   rewrites outbound request bytes, replacing every placeholder with its real
//!   value. Real values live in [`crate::secrets::Secret`] (`Zeroizing`), never
//!   log, and never serialize.
//! - [`guest_env_with_placeholders`] — the injection boundary: given secrets
//!   resolved host-side, it returns the `(name, placeholder)` env the guest
//!   receives and registers the real values in the table.
//! - [`EgressBroker`] — the running proxy: [`EgressBroker::serve`] accepts guest
//!   `CONNECT` tunnels, mints a leaf per host, terminates TLS, rewrites the
//!   request head, and relays to the verified upstream.
//! - [`EgressBroker::guest_provisioning`] — the CA file + proxy/CA-bundle env
//!   the launch path installs so the guest routes through the broker.
//!
//! # Trust model
//!
//! This narrows the blast radius of a *guest* compromise; it does not defend
//! against a *host* compromise (the host holds every real value and the CA
//! key — same assumption as the existing secret store). The proxy must be the
//! guest's only egress path for the guarantee to hold: pair it with an egress
//! policy that allows outbound traffic *only* to the proxy address (smolvm
//! already supports CIDR/allow-host egress policy), so a workload cannot skip
//! the proxy and reach the internet directly with a placeholder that some other
//! endpoint might log.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::{Mutex, RwLock};
use ring::rand::{SecureRandom, SystemRandom};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::secrets::Secret;

/// Prefix on every generated placeholder. Distinctive and unlikely to collide
/// with real request content, so a whole-head substring replace is safe.
const PLACEHOLDER_PREFIX: &str = "smolvm-brokered-secret-";

/// Bytes of entropy in a placeholder (hex-encoded → 2× characters). 128 bits is
/// ample to make guessing or accidental collision infeasible.
const PLACEHOLDER_ENTROPY_BYTES: usize = 16;

/// Errors from broker setup and request handling.
#[derive(Debug)]
pub enum BrokerError {
    /// Certificate generation or signing failed.
    Cert(String),
    /// The proxied request head could not be parsed as HTTP/1.x.
    MalformedRequest(String),
}

impl std::fmt::Display for BrokerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BrokerError::Cert(e) => write!(f, "certificate error: {e}"),
            BrokerError::MalformedRequest(e) => write!(f, "malformed proxied request: {e}"),
        }
    }
}

impl std::error::Error for BrokerError {}

// ============================================================================
// Certificate authority
// ============================================================================

/// A minted leaf: PEM cert chain + PEM private key, ready to build a rustls
/// server config for one MITM'd host.
#[derive(Clone)]
pub struct LeafCert {
    /// Leaf certificate in PEM (single cert; the guest trusts the CA, so no
    /// chain is needed).
    pub cert_pem: String,
    /// Leaf private key in PKCS#8 PEM.
    pub key_pem: String,
}

impl std::fmt::Debug for LeafCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material.
        f.debug_struct("LeafCert").finish_non_exhaustive()
    }
}

/// Per-broker certificate authority.
///
/// Holds the CA in memory only (regenerated each run — the guest trusts it
/// freshly at boot, so there is nothing to persist and no long-lived key to
/// leak). Minting a leaf is cheap and lock-free.
pub struct CaAuthority {
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
    ca_cert_pem: String,
}

impl std::fmt::Debug for CaAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaAuthority").finish_non_exhaustive()
    }
}

impl CaAuthority {
    /// Generate a fresh CA. The returned authority can mint leaf certs and
    /// expose its CA cert PEM for installation into the guest trust store.
    pub fn generate() -> Result<Self, BrokerError> {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};

        let ca_key = KeyPair::generate().map_err(|e| BrokerError::Cert(e.to_string()))?;
        let mut params = CertificateParams::new(Vec::<String>::new())
            .map_err(|e| BrokerError::Cert(e.to_string()))?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params
            .distinguished_name
            .push(DnType::CommonName, "smolvm egress broker CA");

        // Self-sign to get the CA cert PEM the guest will trust, then move the
        // params + key into an Issuer for signing leaves.
        let ca_cert = params
            .self_signed(&ca_key)
            .map_err(|e| BrokerError::Cert(e.to_string()))?;
        let ca_cert_pem = ca_cert.pem();
        let issuer = rcgen::Issuer::new(params, ca_key);

        Ok(Self {
            issuer,
            ca_cert_pem,
        })
    }

    /// The CA certificate in PEM. Push this into the guest (e.g. via the agent
    /// `FileWrite` RPC to `/usr/local/share/ca-certificates/smolvm-broker.crt`
    /// followed by `update-ca-certificates`) so the guest trusts the leaves the
    /// proxy mints.
    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// Mint a leaf certificate valid for `host` (added as a SAN), signed by the
    /// CA. Called once per distinct upstream host the guest CONNECTs to.
    pub fn mint_leaf(&self, host: &str) -> Result<LeafCert, BrokerError> {
        use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose};

        let leaf_key = KeyPair::generate().map_err(|e| BrokerError::Cert(e.to_string()))?;
        let mut params = CertificateParams::new(vec![host.to_string()])
            .map_err(|e| BrokerError::Cert(e.to_string()))?;
        params.distinguished_name.push(DnType::CommonName, host);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        let leaf = params
            .signed_by(&leaf_key, &self.issuer)
            .map_err(|e| BrokerError::Cert(e.to_string()))?;

        Ok(LeafCert {
            cert_pem: leaf.pem(),
            key_pem: leaf_key.serialize_pem(),
        })
    }
}

// ============================================================================
// Substitution table
// ============================================================================

/// Registry mapping generated placeholders to real secret values.
///
/// Shared (via `Arc`) between the env-injection path (which registers entries)
/// and the proxy (which reads them to rewrite bytes). Real values are held as
/// [`Secret`] so they never log or serialize; the map itself has a redacting
/// `Debug`.
#[derive(Default)]
pub struct SubstitutionTable {
    inner: RwLock<Inner>,
}

#[derive(Default)]
struct Inner {
    /// placeholder → (secret name, real value). The name is for audit only.
    entries: HashMap<String, (String, Secret)>,
}

impl std::fmt::Debug for SubstitutionTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = self.inner.read().entries.len();
        f.debug_struct("SubstitutionTable")
            .field("entries", &n)
            .finish()
    }
}

impl SubstitutionTable {
    /// Create an empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Generate a fresh placeholder for a secret named `name`, register the real
    /// `value` under it, and return the placeholder to hand to the guest.
    pub fn register(&self, name: &str, value: Secret) -> String {
        let placeholder = generate_placeholder(&SystemRandom::new());
        self.inner
            .write()
            .entries
            .insert(placeholder.clone(), (name.to_string(), value));
        placeholder
    }

    /// Number of registered placeholders (test/telemetry).
    pub fn len(&self) -> usize {
        self.inner.read().entries.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Rewrite `head` (the request-line + headers block of an outbound HTTP
    /// request, as raw bytes) by replacing every registered placeholder with its
    /// real value. Returns the rewritten bytes and the number of substitutions
    /// made (for the audit log — the caller logs the *count* and secret names,
    /// never values).
    ///
    /// Placeholders are high-entropy opaque tokens, so a plain substring replace
    /// over the head is both correct (no false matches against real content) and
    /// sufficient. Only the head is rewritten: credentials live in headers, and
    /// rewriting a streamed body would require buffering it whole.
    pub fn rewrite_head(&self, head: &[u8]) -> (Vec<u8>, Vec<Substitution>) {
        let guard = self.inner.read();
        // Fast path: a head with no placeholder prefix at all can't match.
        if !contains_subslice(head, PLACEHOLDER_PREFIX.as_bytes()) {
            return (head.to_vec(), Vec::new());
        }

        let mut out = head.to_vec();
        let mut subs = Vec::new();
        for (placeholder, (name, value)) in guard.entries.iter() {
            let count =
                replace_all_in_place(&mut out, placeholder.as_bytes(), value.expose().as_bytes());
            if count > 0 {
                subs.push(Substitution {
                    secret_name: name.clone(),
                    count,
                });
            }
        }
        (out, subs)
    }
}

/// An audit record of one placeholder's substitution — safe to log (no value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Substitution {
    /// The secret's configured name.
    pub secret_name: String,
    /// How many times its placeholder appeared in the head.
    pub count: usize,
}

/// Build the guest-facing environment for a set of resolved secrets, replacing
/// each real value with a freshly-registered placeholder.
///
/// This is the broker's analogue of `secrets::expose_into_env`: same shape
/// (`Vec<(name, value)>` for the agent env), but the values that cross into the
/// guest are placeholders, not plaintext. The real values stay host-side in
/// `table`. Point the guest's `HTTPS_PROXY`/`HTTP_PROXY` at the broker so its
/// requests carry these placeholders back for substitution.
pub fn guest_env_with_placeholders(
    table: &SubstitutionTable,
    secrets: Vec<(String, Secret)>,
) -> Vec<(String, String)> {
    secrets
        .into_iter()
        .map(|(name, value)| {
            let placeholder = table.register(&name, value);
            (name, placeholder)
        })
        .collect()
}

// ============================================================================
// Per-connection MITM logic
// ============================================================================

/// A parsed CONNECT request target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectTarget {
    /// Upstream host.
    pub host: String,
    /// Upstream port.
    pub port: u16,
}

/// Parse the `CONNECT host:port HTTP/1.1` line a client sends to open a TLS
/// tunnel through a forward proxy. Returns the upstream the proxy must dial and
/// mint a leaf for.
pub fn parse_connect(request_line: &str) -> Result<ConnectTarget, BrokerError> {
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| BrokerError::MalformedRequest("empty request line".into()))?;
    if !method.eq_ignore_ascii_case("CONNECT") {
        return Err(BrokerError::MalformedRequest(format!(
            "expected CONNECT, got {method}"
        )));
    }
    let authority = parts
        .next()
        .ok_or_else(|| BrokerError::MalformedRequest("CONNECT missing authority".into()))?;
    let (host, port) = authority
        .rsplit_once(':')
        .ok_or_else(|| BrokerError::MalformedRequest("CONNECT authority missing port".into()))?;
    let port: u16 = port
        .parse()
        .map_err(|_| BrokerError::MalformedRequest(format!("invalid port {port}")))?;
    if host.is_empty() {
        return Err(BrokerError::MalformedRequest("CONNECT empty host".into()));
    }
    Ok(ConnectTarget {
        host: host.to_string(),
        port,
    })
}

/// Split a buffer into the HTTP head (through the terminating CRLF CRLF) and the
/// remaining body bytes. Returns `None` if the head is not yet complete.
pub fn split_head(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    find_subslice(buf, b"\r\n\r\n").map(|i| {
        let split = i + 4;
        (&buf[..split], &buf[split..])
    })
}

// ============================================================================
// Running MITM forward-proxy server
// ============================================================================

/// Largest HTTP head we will buffer before giving up (guards against a client
/// that never terminates its head).
const MAX_HEAD_BYTES: usize = 64 * 1024;

/// A running secret-substituting forward proxy.
///
/// Point a guest's `HTTPS_PROXY`/`HTTP_PROXY` at a listener served by
/// [`EgressBroker::serve`]. For each `CONNECT host:port` tunnel the guest opens,
/// the broker mints a leaf cert for `host` (trusted because the guest has the
/// broker CA installed), terminates the guest's TLS, rewrites the request head
/// to swap placeholders for real secret values, then relays to the real `host`
/// over a genuinely-verified upstream TLS connection. The credential reaches the
/// upstream API but never exists in plaintext inside the guest.
pub struct EgressBroker {
    ca: CaAuthority,
    table: Arc<SubstitutionTable>,
    upstream: Arc<ClientConfig>,
    /// Minted server configs, cached per host so a repeat connection reuses its
    /// leaf instead of re-signing.
    leaf_configs: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

impl std::fmt::Debug for EgressBroker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EgressBroker")
            .field("cached_leaves", &self.leaf_configs.lock().len())
            .field("registered_secrets", &self.table.len())
            .finish()
    }
}

impl EgressBroker {
    /// Build a broker that verifies upstream servers against the Mozilla webpki
    /// root set — the production configuration.
    pub fn new(ca: CaAuthority, table: Arc<SubstitutionTable>) -> Self {
        let mut roots = RootCertStore::empty();
        roots
            .roots
            .extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self::with_upstream_roots(ca, table, roots)
    }

    /// Build a broker that verifies upstream servers against a caller-supplied
    /// root store. Used by tests (trust a throwaway upstream CA) and by
    /// deployments that pin a private CA.
    pub fn with_upstream_roots(
        ca: CaAuthority,
        table: Arc<SubstitutionTable>,
        upstream_roots: RootCertStore,
    ) -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let upstream = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("ring provider supports the default protocol versions")
            .with_root_certificates(upstream_roots)
            .with_no_client_auth();
        Self {
            ca,
            table,
            upstream: Arc::new(upstream),
            leaf_configs: Mutex::new(HashMap::new()),
        }
    }

    /// The CA cert PEM to install into the guest trust store.
    pub fn ca_cert_pem(&self) -> &str {
        self.ca.ca_cert_pem()
    }

    /// The substitution table, so the env-injection path can register secrets.
    pub fn table(&self) -> &Arc<SubstitutionTable> {
        &self.table
    }

    /// Mint (or reuse) the TLS server config the proxy presents for `host`.
    fn server_config_for(&self, host: &str) -> Result<Arc<ServerConfig>, BrokerError> {
        if let Some(cfg) = self.leaf_configs.lock().get(host) {
            return Ok(Arc::clone(cfg));
        }
        let leaf = self.ca.mint_leaf(host)?;
        let certs: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(leaf.cert_pem.as_bytes())
                .collect::<Result<_, _>>()
                .map_err(|e| BrokerError::Cert(e.to_string()))?;
        let key = PrivateKeyDer::from_pem_slice(leaf.key_pem.as_bytes())
            .map_err(|e| BrokerError::Cert(e.to_string()))?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| BrokerError::Cert(e.to_string()))?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| BrokerError::Cert(e.to_string()))?;
        let arc = Arc::new(cfg);
        self.leaf_configs
            .lock()
            .insert(host.to_string(), Arc::clone(&arc));
        Ok(arc)
    }

    /// Accept and service tunnels until the listener errors fatally. Each
    /// connection is handled on its own task.
    pub async fn serve(self: Arc<Self>, listener: TcpListener) {
        loop {
            match listener.accept().await {
                Ok((tcp, _peer)) => {
                    let me = Arc::clone(&self);
                    tokio::spawn(async move {
                        if let Err(e) = me.handle(tcp).await {
                            tracing::debug!(error = %e, "broker connection ended");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "broker accept failed");
                    return;
                }
            }
        }
    }

    /// Service one client tunnel end to end.
    async fn handle(
        &self,
        mut tcp: TcpStream,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // 1. Read the plaintext CONNECT request the client sends to open a
        //    tunnel, and learn the upstream it wants.
        let mut buf = Vec::new();
        read_http_head(&mut tcp, &mut buf).await?;
        let head = std::str::from_utf8(&buf)
            .map_err(|_| BrokerError::MalformedRequest("non-UTF-8 CONNECT line".into()))?;
        let target = parse_connect(head.lines().next().unwrap_or_default())?;

        // 2. Accept the tunnel. Clients (curl, browsers, language HTTP stacks)
        //    wait for this 200 before starting their TLS handshake, so nothing
        //    of the handshake has been read into `buf`.
        tcp.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;

        // 3. Become the TLS server for `host` using a freshly-minted leaf.
        let acceptor = TlsAcceptor::from(self.server_config_for(&target.host)?);
        let client = acceptor.accept(tcp).await?;

        // 4. Dial the real upstream and verify its certificate for real.
        let upstream_tcp = TcpStream::connect((target.host.as_str(), target.port)).await?;
        let connector = TlsConnector::from(Arc::clone(&self.upstream));
        let sni = ServerName::try_from(target.host.clone())
            .map_err(|e| BrokerError::MalformedRequest(format!("invalid SNI host: {e}")))?;
        let upstream = connector.connect(sni, upstream_tcp).await?;

        // 5. Proxy the tunnel. Responses stream back verbatim (they never carry
        //    placeholders); every request head the client sends is rewritten, not
        //    just the first — a single CONNECT tunnel carries multiple requests
        //    under HTTP/1.1 keep-alive, and each must have its placeholders
        //    swapped for real secrets.
        let (mut client_r, mut client_w) = tokio::io::split(client);
        let (mut upstream_r, mut upstream_w) = tokio::io::split(upstream);
        let response_pump = tokio::spawn(async move {
            let _ = tokio::io::copy(&mut upstream_r, &mut client_w).await;
            // Propagate the upstream's EOF to the client. The read half is still
            // held by the request loop, so dropping this write half alone would
            // not close the tunnel — shut it down explicitly.
            let _ = client_w.shutdown().await;
        });
        let result =
            relay_requests(&self.table, &target.host, &mut client_r, &mut upstream_w).await;
        // Signal EOF upstream so it can finish the last response, then drain it.
        let _ = upstream_w.shutdown().await;
        let _ = response_pump.await;
        result?;
        Ok(())
    }
}

/// Guest-side path where the broker CA is written. Chosen under `/etc/smolvm`
/// so it is outside any workload-managed trust dir and stable across images.
pub const GUEST_CA_PATH: &str = "/etc/smolvm/broker-ca.crt";

/// Everything the launch path must push into the guest to route it through the
/// broker: the CA file to write, and the environment to set. Producing this as
/// concrete data (rather than performing the writes here) keeps the broker
/// independent of the agent RPC layer while giving the caller exactly what to
/// feed [`FileWrite`](crate) and the workload env vector.
#[derive(Debug, Clone)]
pub struct GuestProvisioning {
    /// Absolute guest path to write the CA cert to.
    pub ca_path: String,
    /// PEM bytes of the broker CA.
    pub ca_pem: Vec<u8>,
    /// File mode for the CA (world-readable; it is a public cert).
    pub ca_mode: u32,
    /// Environment to add to the workload: the proxy endpoint plus the standard
    /// CA-bundle variables pointed at [`Self::ca_path`], so common HTTP stacks
    /// (curl, Python requests, Node, Go) trust the minted leaves without having
    /// to run `update-ca-certificates` at boot.
    pub env: Vec<(String, String)>,
}

impl EgressBroker {
    /// Compute the guest provisioning for a broker reachable at `proxy_url`
    /// (e.g. `http://10.0.2.2:8080` for the guest→host gateway). The caller
    /// writes the CA via the agent `FileWrite` RPC and appends `env` to the
    /// workload environment. Pair with an egress policy that permits outbound
    /// traffic only to the proxy so the guest cannot bypass it.
    pub fn guest_provisioning(&self, proxy_url: &str) -> GuestProvisioning {
        let env = vec![
            ("HTTPS_PROXY".to_string(), proxy_url.to_string()),
            ("https_proxy".to_string(), proxy_url.to_string()),
            ("HTTP_PROXY".to_string(), proxy_url.to_string()),
            ("http_proxy".to_string(), proxy_url.to_string()),
            // CA-bundle env honored by the common client stacks.
            ("SSL_CERT_FILE".to_string(), GUEST_CA_PATH.to_string()),
            ("CURL_CA_BUNDLE".to_string(), GUEST_CA_PATH.to_string()),
            ("REQUESTS_CA_BUNDLE".to_string(), GUEST_CA_PATH.to_string()),
            ("NODE_EXTRA_CA_CERTS".to_string(), GUEST_CA_PATH.to_string()),
        ];
        GuestProvisioning {
            ca_path: GUEST_CA_PATH.to_string(),
            ca_pem: self.ca_cert_pem().as_bytes().to_vec(),
            ca_mode: 0o644,
            env,
        }
    }
}

/// Read from `s` into `buf` until `buf` contains a complete HTTP head
/// (terminated by CRLF CRLF). Extra bytes read past the terminator (the start
/// of the body) stay in `buf` for the caller to split off.
async fn read_http_head<S: AsyncReadExt + Unpin>(
    s: &mut S,
    buf: &mut Vec<u8>,
) -> std::io::Result<()> {
    let mut tmp = [0u8; 4096];
    loop {
        if contains_subslice(buf, b"\r\n\r\n") {
            return Ok(());
        }
        let n = s.read(&mut tmp).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed before the end of the HTTP head",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > MAX_HEAD_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "HTTP head exceeded the maximum size",
            ));
        }
    }
}

/// Proxy the request direction of a tunnel: read each HTTP request head the
/// client sends, rewrite its placeholders into real secrets, forward it plus its
/// body, and loop for the next request. A single CONNECT tunnel carries multiple
/// requests under keep-alive, so rewriting only the first head (and splicing the
/// rest) would leak placeholders unsubstituted on every subsequent request.
///
/// Body bytes are forwarded verbatim (credentials live in the head). The body is
/// framed by `Content-Length`; a chunked or otherwise unframed body means the
/// next head boundary can't be located, so the remainder is spliced through and
/// the loop ends (matching the original splice behavior for that uncommon case).
async fn relay_requests<R, W>(
    table: &SubstitutionTable,
    host: &str,
    client_r: &mut R,
    upstream_w: &mut W,
) -> std::io::Result<()>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        // Accumulate bytes until a full request head is buffered (or the client
        // cleanly ends the stream between requests).
        let head_end = loop {
            if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
                break pos + 4;
            }
            if buf.len() > MAX_HEAD_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "request head exceeded the maximum size",
                ));
            }
            let n = client_r.read(&mut tmp).await?;
            if n == 0 {
                if buf.is_empty() {
                    return Ok(());
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed before the end of a request head",
                ));
            }
            buf.extend_from_slice(&tmp[..n]);
        };

        let head = &buf[..head_end];
        let (rewritten, subs) = table.rewrite_head(head);
        for s in &subs {
            // Audit: name + count only — never the value.
            tracing::info!(
                secret = %s.secret_name,
                count = s.count,
                host = %host,
                "substituted brokered secret into an outbound request"
            );
        }
        let body_len = request_body_len(head);
        upstream_w.write_all(&rewritten).await?;
        buf.drain(..head_end);

        match body_len {
            Some(mut remaining) => {
                // Forward already-buffered body bytes first, then read the rest.
                let take = remaining.min(buf.len());
                if take > 0 {
                    upstream_w.write_all(&buf[..take]).await?;
                    buf.drain(..take);
                    remaining -= take;
                }
                while remaining > 0 {
                    let n = client_r.read(&mut tmp).await?;
                    if n == 0 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "connection closed before the end of a request body",
                        ));
                    }
                    let take = remaining.min(n);
                    upstream_w.write_all(&tmp[..take]).await?;
                    if n > take {
                        // Bytes past this body belong to the next request head.
                        buf.extend_from_slice(&tmp[take..n]);
                    }
                    remaining -= take;
                }
                upstream_w.flush().await?;
            }
            None => {
                // Unframed/chunked body: we can't find the next head boundary, so
                // splice the remainder through untouched and stop rewriting.
                upstream_w.write_all(&buf).await?;
                upstream_w.flush().await?;
                tokio::io::copy(client_r, upstream_w).await?;
                return Ok(());
            }
        }
    }
}

/// How many body bytes follow a request head: `Some(n)` for a `Content-Length`
/// body (or `Some(0)` when there is none), `None` when the framing is chunked or
/// otherwise not a plain length and the caller must splice the remainder.
fn request_body_len(head: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(head).ok()?;
    let mut content_length: Option<usize> = None;
    // Skip the request line; stop at the blank line ending the head.
    for line in text.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':')?;
        let name = name.trim();
        if name.eq_ignore_ascii_case("transfer-encoding") {
            // chunked (or any transfer-coding) — not a simple length.
            return None;
        }
        if name.eq_ignore_ascii_case("content-length") {
            content_length = Some(value.trim().parse::<usize>().ok()?);
        }
    }
    Some(content_length.unwrap_or(0))
}

// ============================================================================
// Byte helpers (no external dependency)
// ============================================================================

fn generate_placeholder(rng: &SystemRandom) -> String {
    let mut bytes = [0u8; PLACEHOLDER_ENTROPY_BYTES];
    // SystemRandom::fill only fails if the OS RNG is unavailable, which is
    // fatal for the whole process; treat a failure as unrecoverable rather than
    // handing out a low-entropy token.
    rng.fill(&mut bytes)
        .expect("system RNG unavailable while generating a broker placeholder");
    let mut s = String::with_capacity(PLACEHOLDER_PREFIX.len() + bytes.len() * 2);
    s.push_str(PLACEHOLDER_PREFIX);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Find the first index of `needle` in `haystack`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    find_subslice(haystack, needle).is_some()
}

/// Replace every non-overlapping occurrence of `from` with `to` in `buf`, in
/// place. Returns the number of replacements. `from` is never empty in practice
/// (it's a prefixed placeholder).
fn replace_all_in_place(buf: &mut Vec<u8>, from: &[u8], to: &[u8]) -> usize {
    if from.is_empty() {
        return 0;
    }
    let mut result = Vec::with_capacity(buf.len());
    let mut i = 0;
    let mut count = 0;
    while i < buf.len() {
        if i + from.len() <= buf.len() && &buf[i..i + from.len()] == from {
            result.extend_from_slice(to);
            i += from.len();
            count += 1;
        } else {
            result.push(buf[i]);
            i += 1;
        }
    }
    if count > 0 {
        *buf = result;
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build a real `Secret` through the crate's public resolution API (the
    // module exposes resolution, not a raw constructor): stash the value in a
    // uniquely-named env var, resolve a `from_env` ref against it, remove it.
    fn make_secret(value: &str) -> Secret {
        let key = format!("SMOLVM_BROKER_MK_{value}");
        std::env::set_var(&key, value);
        let mut refs = std::collections::BTreeMap::new();
        refs.insert("N".to_string(), crate::secrets::env_ref(&key));
        let out = crate::secrets::resolve_refs_to_env(
            &refs,
            crate::secrets::ResolutionScope::TrustedLocal,
        )
        .expect("resolve test secret");
        std::env::remove_var(&key);
        out.into_iter().next().unwrap().1
    }

    #[test]
    fn ca_generates_and_mints_valid_leaf() {
        let ca = CaAuthority::generate().expect("generate CA");
        assert!(ca.ca_cert_pem().contains("BEGIN CERTIFICATE"));

        let leaf = ca.mint_leaf("api.openai.com").expect("mint leaf");
        assert!(leaf.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(leaf.key_pem.contains("PRIVATE KEY"));

        // The leaf must be parseable and carry the host as a SAN.
        let der = pem_to_der(&leaf.cert_pem);
        let (_, parsed) = x509_parser::parse_x509_certificate(&der).expect("parse leaf");
        let sans: Vec<_> = parsed
            .subject_alternative_name()
            .ok()
            .flatten()
            .map(|ext| ext.value.general_names.clone())
            .unwrap_or_default();
        let has_host = sans.iter().any(|gn| {
            matches!(gn, x509_parser::extensions::GeneralName::DNSName(d) if *d == "api.openai.com")
        });
        assert!(has_host, "leaf SANs {sans:?} must include the host");
    }

    fn pem_to_der(pem: &str) -> Vec<u8> {
        let p = pem::parse(pem).expect("parse pem");
        p.into_contents()
    }

    #[test]
    fn placeholders_are_unique_and_prefixed() {
        let table = SubstitutionTable::new();
        let p1 = table.register("A", make_secret("secret-A"));
        let p2 = table.register("B", make_secret("secret-B"));
        assert!(p1.starts_with(PLACEHOLDER_PREFIX));
        assert!(p2.starts_with(PLACEHOLDER_PREFIX));
        assert_ne!(p1, p2);
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn rewrite_swaps_placeholder_for_real_value() {
        let table = SubstitutionTable::new();
        let placeholder = table.register("OPENAI_API_KEY", make_secret("sk-REALVALUE123"));

        let head = format!(
            "GET /v1/models HTTP/1.1\r\nHost: api.openai.com\r\nAuthorization: Bearer {placeholder}\r\n\r\n"
        );
        let (rewritten, subs) = table.rewrite_head(head.as_bytes());
        let text = String::from_utf8(rewritten).unwrap();

        assert!(text.contains("Bearer sk-REALVALUE123"));
        assert!(!text.contains(&placeholder), "placeholder must be gone");
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].secret_name, "OPENAI_API_KEY");
        assert_eq!(subs[0].count, 1);
    }

    #[test]
    fn rewrite_is_noop_without_placeholders() {
        let table = SubstitutionTable::new();
        table.register("K", make_secret("realval"));
        let head = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (out, subs) = table.rewrite_head(head);
        assert_eq!(out, head);
        assert!(subs.is_empty());
    }

    #[test]
    fn rewrite_handles_multiple_occurrences() {
        let table = SubstitutionTable::new();
        let p = table.register("TOK", make_secret("XYZ"));
        let head = format!("GET / HTTP/1.1\r\nA: {p}\r\nB: {p}\r\n\r\n");
        let (out, subs) = table.rewrite_head(head.as_bytes());
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text.matches("XYZ").count(), 2);
        assert_eq!(subs[0].count, 2);
    }

    #[test]
    fn guest_env_replaces_values_with_placeholders() {
        let table = SubstitutionTable::new();
        let env = guest_env_with_placeholders(
            &table,
            vec![
                ("OPENAI_API_KEY".to_string(), make_secret("sk-real")),
                ("DB_PASSWORD".to_string(), make_secret("hunter2")),
            ],
        );
        assert_eq!(env.len(), 2);
        for (name, value) in &env {
            assert!(
                value.starts_with(PLACEHOLDER_PREFIX),
                "{name} kept plaintext!"
            );
            assert_ne!(value, "sk-real");
            assert_ne!(value, "hunter2");
        }
        assert_eq!(table.len(), 2);

        // And a request carrying the injected placeholder resolves to the real
        // value host-side.
        let placeholder = &env[0].1;
        let head = format!("GET / HTTP/1.1\r\nAuthorization: Bearer {placeholder}\r\n\r\n");
        let (out, _) = table.rewrite_head(head.as_bytes());
        assert!(String::from_utf8(out).unwrap().contains("Bearer sk-real"));
    }

    #[test]
    fn parse_connect_extracts_host_and_port() {
        let t = parse_connect("CONNECT api.openai.com:443 HTTP/1.1").unwrap();
        assert_eq!(t.host, "api.openai.com");
        assert_eq!(t.port, 443);
    }

    #[test]
    fn parse_connect_rejects_non_connect() {
        assert!(parse_connect("GET / HTTP/1.1").is_err());
        assert!(parse_connect("CONNECT noport HTTP/1.1").is_err());
        assert!(parse_connect("CONNECT host:notaport HTTP/1.1").is_err());
    }

    #[test]
    fn split_head_separates_head_and_body() {
        let buf = b"GET / HTTP/1.1\r\nHost: x\r\n\r\nBODYBYTES";
        let (head, body) = split_head(buf).unwrap();
        assert!(head.ends_with(b"\r\n\r\n"));
        assert_eq!(body, b"BODYBYTES");
        // Incomplete head → None.
        assert!(split_head(b"GET / HTTP/1.1\r\nHost: x\r\n").is_none());
    }

    #[test]
    fn debug_never_leaks_secret_or_key() {
        let table = SubstitutionTable::new();
        table.register("K", make_secret("TOPSECRET"));
        let dbg = format!("{table:?}");
        assert!(!dbg.contains("TOPSECRET"));

        let ca = CaAuthority::generate().unwrap();
        let leaf = ca.mint_leaf("h").unwrap();
        assert!(!format!("{leaf:?}").contains("PRIVATE"));
        assert!(!format!("{ca:?}").contains("BEGIN"));
    }

    #[test]
    fn guest_provisioning_carries_ca_and_proxy_env() {
        let ca = CaAuthority::generate().unwrap();
        let table = Arc::new(SubstitutionTable::new());
        let broker = EgressBroker::new(ca, table);
        let prov = broker.guest_provisioning("http://10.0.2.2:8080");

        assert_eq!(prov.ca_path, GUEST_CA_PATH);
        assert!(prov.ca_pem.starts_with(b"-----BEGIN CERTIFICATE"));
        let env: std::collections::HashMap<_, _> = prov.env.into_iter().collect();
        assert_eq!(env["HTTPS_PROXY"], "http://10.0.2.2:8080");
        // CA-bundle vars point at the written CA so stacks trust minted leaves.
        assert_eq!(env["SSL_CERT_FILE"], GUEST_CA_PATH);
        assert_eq!(env["REQUESTS_CA_BUNDLE"], GUEST_CA_PATH);
        assert_eq!(env["NODE_EXTRA_CA_CERTS"], GUEST_CA_PATH);
    }

    /// Build a rustls `ServerConfig` from a minted leaf (used to stand up the
    /// mock upstream in the end-to-end test).
    fn server_config_from_leaf(leaf: &LeafCert) -> ServerConfig {
        let certs: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(leaf.cert_pem.as_bytes())
                .collect::<Result<_, _>>()
                .unwrap();
        let key = PrivateKeyDer::from_pem_slice(leaf.key_pem.as_bytes()).unwrap();
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap()
    }

    fn root_store_from_pem(ca_pem: &str) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        for c in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
            roots.add(c.unwrap()).unwrap();
        }
        roots
    }

    // A real end-to-end proof: a client sends a request bearing only the
    // placeholder through the running proxy to a live TLS upstream, and the
    // upstream observes the REAL secret on the wire while the placeholder never
    // reaches it. Exercises CONNECT handling, leaf minting, TLS termination,
    // head rewriting, verified upstream TLS, and relaying.
    #[tokio::test]
    async fn end_to_end_client_placeholder_becomes_real_secret_upstream() {
        // --- Mock upstream: its own CA + leaf for "localhost", records the
        //     Authorization header it receives. ---
        let upstream_ca = CaAuthority::generate().unwrap();
        let upstream_leaf = upstream_ca.mint_leaf("localhost").unwrap();
        let upstream_cfg = Arc::new(server_config_from_leaf(&upstream_leaf));
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = upstream_listener.local_addr().unwrap().port();
        let (seen_tx, seen_rx) = tokio::sync::oneshot::channel::<String>();
        tokio::spawn(async move {
            let (tcp, _) = upstream_listener.accept().await.unwrap();
            let mut tls = TlsAcceptor::from(upstream_cfg).accept(tcp).await.unwrap();
            let mut head = Vec::new();
            read_http_head(&mut tls, &mut head).await.unwrap();
            tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
            tls.flush().await.unwrap();
            let _ = seen_tx.send(String::from_utf8_lossy(&head).into_owned());
        });

        // --- Broker: trusts the upstream CA, MITMs the client. Guest env would
        //     carry the placeholder; here we register it directly. ---
        let broker_ca = CaAuthority::generate().unwrap();
        let table = Arc::new(SubstitutionTable::new());
        let placeholder = table.register("OPENAI_API_KEY", make_secret("sk-REAL-SECRET-123"));
        let broker = Arc::new(EgressBroker::with_upstream_roots(
            broker_ca,
            Arc::clone(&table),
            root_store_from_pem(upstream_ca.ca_cert_pem()),
        ));
        let broker_ca_pem = broker.ca_cert_pem().to_string();
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        tokio::spawn(Arc::clone(&broker).serve(proxy_listener));

        // --- Client: CONNECT through the proxy, TLS trusting the broker CA,
        //     then a request bearing only the placeholder. ---
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(
                format!("CONNECT localhost:{upstream_port} HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let mut connect_resp = Vec::new();
        read_http_head(&mut client, &mut connect_resp)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&connect_resp).contains("200"));

        let client_cfg =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(root_store_from_pem(&broker_ca_pem))
                .with_no_client_auth();
        let sni = ServerName::try_from("localhost").unwrap();
        let mut ctls = TlsConnector::from(Arc::new(client_cfg))
            .connect(sni, client)
            .await
            .unwrap();
        ctls.write_all(
            format!(
                "GET /v1/models HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {placeholder}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        ctls.flush().await.unwrap();
        let mut client_resp = Vec::new();
        let _ = ctls.read_to_end(&mut client_resp).await;

        // --- Proof: upstream saw the real secret, never the placeholder. ---
        let seen = tokio::time::timeout(std::time::Duration::from_secs(5), seen_rx)
            .await
            .expect("upstream did not receive a request in time")
            .unwrap();
        assert!(
            seen.contains("Authorization: Bearer sk-REAL-SECRET-123"),
            "upstream should receive the real secret; saw head:\n{seen}"
        );
        assert!(
            !seen.contains(&placeholder),
            "placeholder must never reach the upstream"
        );
        assert!(String::from_utf8_lossy(&client_resp).contains("200 OK"));
    }

    /// A single CONNECT tunnel carries more than one request under HTTP/1.1
    /// keep-alive (curl reusing a connection, requests.Session, Go/Node default
    /// clients). The broker rewrites only the first head and then splices the
    /// rest via copy_bidirectional, so a placeholder in the second request
    /// reaches the upstream unsubstituted.
    #[tokio::test]
    async fn keepalive_second_request_placeholder_is_not_substituted() {
        let upstream_ca = CaAuthority::generate().unwrap();
        let upstream_leaf = upstream_ca.mint_leaf("localhost").unwrap();
        let upstream_cfg = Arc::new(server_config_from_leaf(&upstream_leaf));
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = upstream_listener.local_addr().unwrap().port();
        let (seen_tx, seen_rx) = tokio::sync::oneshot::channel::<(String, String)>();
        tokio::spawn(async move {
            let (tcp, _) = upstream_listener.accept().await.unwrap();
            let mut tls = TlsAcceptor::from(upstream_cfg).accept(tcp).await.unwrap();
            let mut h1 = Vec::new();
            read_http_head(&mut tls, &mut h1).await.unwrap();
            tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            tls.flush().await.unwrap();
            let mut h2 = Vec::new();
            read_http_head(&mut tls, &mut h2).await.unwrap();
            tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            tls.flush().await.unwrap();
            let _ = seen_tx.send((
                String::from_utf8_lossy(&h1).into_owned(),
                String::from_utf8_lossy(&h2).into_owned(),
            ));
        });

        let broker_ca = CaAuthority::generate().unwrap();
        let table = Arc::new(SubstitutionTable::new());
        let placeholder = table.register("OPENAI_API_KEY", make_secret("sk-REAL-SECRET-123"));
        let broker = Arc::new(EgressBroker::with_upstream_roots(
            broker_ca,
            Arc::clone(&table),
            root_store_from_pem(upstream_ca.ca_cert_pem()),
        ));
        let broker_ca_pem = broker.ca_cert_pem().to_string();
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        tokio::spawn(Arc::clone(&broker).serve(proxy_listener));

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(
                format!("CONNECT localhost:{upstream_port} HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let mut connect_resp = Vec::new();
        read_http_head(&mut client, &mut connect_resp)
            .await
            .unwrap();

        let client_cfg =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(root_store_from_pem(&broker_ca_pem))
                .with_no_client_auth();
        let sni = ServerName::try_from("localhost").unwrap();
        let mut ctls = TlsConnector::from(Arc::new(client_cfg))
            .connect(sni, client)
            .await
            .unwrap();

        // Request 1 — establishes the tunnel and is the head the broker rewrites.
        ctls.write_all(
            format!("GET /a HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {placeholder}\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
        ctls.flush().await.unwrap();
        let mut r1 = Vec::new();
        read_http_head(&mut ctls, &mut r1).await.unwrap();

        // Request 2 — same TLS session, reused connection.
        ctls.write_all(
            format!("GET /b HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {placeholder}\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
        ctls.flush().await.unwrap();

        let (h1, h2) = tokio::time::timeout(std::time::Duration::from_secs(5), seen_rx)
            .await
            .expect("upstream did not receive both requests in time")
            .unwrap();

        assert!(
            h1.contains("sk-REAL-SECRET-123") && !h1.contains(&placeholder),
            "req1 should carry the real secret; upstream saw:\n{h1}"
        );
        assert!(
            h2.contains("sk-REAL-SECRET-123") && !h2.contains(&placeholder),
            "req2 on the keep-alive tunnel leaked the placeholder unsubstituted; upstream saw:\n{h2}"
        );
    }

    /// A framed request body (Content-Length) must be forwarded intact and the
    /// next request head on the same tunnel located after it — exercises the
    /// body-forwarding path of the request loop, not just bodyless GETs.
    #[tokio::test]
    async fn keepalive_request_body_is_forwarded_and_next_head_rewritten() {
        let upstream_ca = CaAuthority::generate().unwrap();
        let upstream_leaf = upstream_ca.mint_leaf("localhost").unwrap();
        let upstream_cfg = Arc::new(server_config_from_leaf(&upstream_leaf));
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = upstream_listener.local_addr().unwrap().port();
        let (seen_tx, seen_rx) = tokio::sync::oneshot::channel::<(String, String, String)>();
        tokio::spawn(async move {
            let (tcp, _) = upstream_listener.accept().await.unwrap();
            let mut tls = TlsAcceptor::from(upstream_cfg).accept(tcp).await.unwrap();
            // Request 1: head + a 5-byte "hello" body. read_http_head may pull
            // some body bytes past the head, so split and read the remainder.
            let mut b1 = Vec::new();
            read_http_head(&mut tls, &mut b1).await.unwrap();
            let (head1, leftover) = split_head(&b1).unwrap();
            let head1 = String::from_utf8_lossy(head1).into_owned();
            let mut body1 = leftover.to_vec();
            while body1.len() < 5 {
                let mut t = [0u8; 64];
                let n = tls.read(&mut t).await.unwrap();
                body1.extend_from_slice(&t[..n]);
            }
            tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            tls.flush().await.unwrap();
            // Request 2: bodyless.
            let mut b2 = Vec::new();
            read_http_head(&mut tls, &mut b2).await.unwrap();
            tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            tls.flush().await.unwrap();
            let _ = seen_tx.send((
                head1,
                String::from_utf8_lossy(&body1).into_owned(),
                String::from_utf8_lossy(&b2).into_owned(),
            ));
        });

        let broker_ca = CaAuthority::generate().unwrap();
        let table = Arc::new(SubstitutionTable::new());
        let placeholder = table.register("OPENAI_API_KEY", make_secret("sk-REAL-SECRET-123"));
        let broker = Arc::new(EgressBroker::with_upstream_roots(
            broker_ca,
            Arc::clone(&table),
            root_store_from_pem(upstream_ca.ca_cert_pem()),
        ));
        let broker_ca_pem = broker.ca_cert_pem().to_string();
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        tokio::spawn(Arc::clone(&broker).serve(proxy_listener));

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(
                format!("CONNECT localhost:{upstream_port} HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let mut connect_resp = Vec::new();
        read_http_head(&mut client, &mut connect_resp)
            .await
            .unwrap();

        let client_cfg =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(root_store_from_pem(&broker_ca_pem))
                .with_no_client_auth();
        let sni = ServerName::try_from("localhost").unwrap();
        let mut ctls = TlsConnector::from(Arc::new(client_cfg))
            .connect(sni, client)
            .await
            .unwrap();

        // Request 1 with a body.
        ctls.write_all(
            format!("POST /a HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {placeholder}\r\nContent-Length: 5\r\n\r\nhello")
                .as_bytes(),
        )
        .await
        .unwrap();
        ctls.flush().await.unwrap();
        let mut r1 = Vec::new();
        read_http_head(&mut ctls, &mut r1).await.unwrap();

        // Request 2 on the same tunnel.
        ctls.write_all(
            format!("GET /b HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {placeholder}\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
        ctls.flush().await.unwrap();

        let (head1, body1, head2) = tokio::time::timeout(std::time::Duration::from_secs(5), seen_rx)
            .await
            .expect("upstream did not receive both requests in time")
            .unwrap();

        assert!(head1.contains("sk-REAL-SECRET-123"), "req1 head:\n{head1}");
        assert_eq!(body1, "hello", "req1 body must be forwarded intact");
        assert!(
            head2.contains("sk-REAL-SECRET-123") && !head2.contains(&placeholder),
            "req2 head after a framed body must be rewritten; saw:\n{head2}"
        );
    }
}
