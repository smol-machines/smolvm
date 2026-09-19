//! Experimental, explicit HTTPS proxy. Only host-owned configuration may create
//! a broker. This is not a public fleet API or a machine-identity implementation.
//! Credentials never enter the guest; a revocable proxy capability does.

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    body::Incoming, header, server::conn::http1, service::service_fn, Method, Request, Response,
    StatusCode,
};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use std::{
    convert::Infallible,
    io::BufReader,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{net::TcpListener, sync::Semaphore};
use tokio_rustls::TlsAcceptor;
use zeroize::Zeroizing;

const REQUEST_LIMIT: usize = 1024 * 1024;
const RESPONSE_LIMIT: usize = 4 * 1024 * 1024;
const DEADLINE: Duration = Duration::from_secs(30);
type Reply = Response<Full<Bytes>>;

/// References only. Never deserialize this from a guest or an untrusted API.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: SocketAddr,
    /// Optional private host socket for Smol's backend-independent vsock mount.
    pub unix_socket: Option<PathBuf>,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    /// Contents are the proxy Basic password (username is `smol`). Read anew
    /// for every request, including requests inside an existing TLS connection.
    pub access_token_file: PathBuf,
    pub grants: Vec<Grant>,
    /// Extra upstream trust root, for private services and offline acceptance.
    /// Public WebPKI roots remain enabled. This never disables TLS verification.
    pub upstream_ca: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    /// Exact DNS hostname, with no wildcard, scheme or path.
    pub host: String,
    #[serde(default = "https_port")]
    pub port: u16,
    pub placeholder: String,
    /// Only Authorization and X-API-Key are currently supported.
    pub header: String,
    /// Explicit upstream operations. Read-only unless the administrator opts in.
    #[serde(default = "read_methods")]
    pub methods: Vec<String>,
    /// Plaintext read per authorized request. An external manager can rotate
    /// or remove this file; no resolved value is persisted by the broker.
    pub secret_file: Option<PathBuf>,
    /// Host broker environment only (e.g. populated by `dotenvx run`).
    /// Environment rotation requires restarting the broker.
    pub secret_env: Option<String>,
}

fn read_methods() -> Vec<String> {
    vec!["GET".into(), "HEAD".into()]
}

impl Grant {
    fn read_secret(&self) -> Result<Zeroizing<String>> {
        match (&self.secret_file, &self.secret_env) {
            (Some(path), None) => read_private(path),
            (None, Some(name)) if valid_env_name(name) => {
                let value = Zeroizing::new(
                    std::env::var(name)
                        .map_err(|_| anyhow::anyhow!("host credential environment unavailable"))?,
                );
                validate_value(&value)?;
                Ok(value)
            }
            _ => bail!("configure exactly one secret_file or valid secret_env"),
        }
    }
}

fn valid_env_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn validate_value(value: &str) -> Result<()> {
    if value.len() < 16 || value.len() > 8192 || value.bytes().any(|b| b.is_ascii_control()) {
        bail!("credential must contain 16..8192 non-control bytes");
    }
    Ok(())
}

fn https_port() -> u16 {
    443
}

fn read_private(path: &Path) -> Result<Zeroizing<String>> {
    use std::io::Read;
    if !path.is_absolute() {
        bail!("credential reference must be absolute");
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    // Refuse leaf symlinks atomically on Unix. Parent directories are owned
    // by the trusted administrator and must not be guest-writable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(not(unix))]
    if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
        bail!("credential reference is a symlink");
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        bail!("credential reference must be a regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("credential file must be private (0600 or 0400)");
        }
    }
    let mut value = Zeroizing::new(String::new());
    file.take(8193).read_to_string(&mut value)?;
    let trimmed = value.trim_end_matches(['\r', '\n']).to_owned();
    *value = trimmed;
    validate_value(&value)?;
    Ok(value)
}

pub struct Broker {
    config: Config,
    tls: TlsAcceptor,
    client: reqwest::Client,
    permits: Arc<Semaphore>,
}

impl Broker {
    pub fn new(config: Config) -> Result<Arc<Self>> {
        if !config.listen.ip().is_loopback() {
            bail!("experimental broker must listen on loopback");
        }
        #[cfg(not(unix))]
        if config.unix_socket.is_some() {
            bail!("Unix broker socket is unsupported on this platform");
        }
        if config.grants.is_empty() {
            bail!("at least one grant is required");
        }
        read_private(&config.access_token_file).context("invalid access-token reference")?;
        for (index, grant) in config.grants.iter().enumerate() {
            if grant.host.is_empty()
                || grant.host.len() > 253
                || grant.host.parse::<std::net::IpAddr>().is_ok()
                || grant.host.split('.').any(|label| {
                    label.is_empty()
                        || label.len() > 63
                        || label.starts_with('-')
                        || label.ends_with('-')
                        || !label
                            .bytes()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
                })
                || grant.port == 0
            {
                bail!("grant needs a canonical DNS hostname and nonzero port");
            }
            if !matches!(grant.header.as_str(), "authorization" | "x-api-key") {
                bail!("unsupported credential header");
            }
            if grant.methods.is_empty()
                || grant.methods.iter().any(|m| {
                    !matches!(
                        m.as_str(),
                        "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"
                    )
                })
            {
                bail!("grant methods must explicitly name supported HTTP operations");
            }
            if !grant.placeholder.starts_with("SMOL_PLACEHOLDER_")
                || grant.placeholder.len() < 24
                || !grant
                    .placeholder
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'_')
            {
                bail!("invalid placeholder");
            }
            if config.grants[..index].iter().any(|other| {
                other.host == grant.host && other.port == grant.port
                    || other.placeholder == grant.placeholder
            }) {
                bail!("duplicate destination or placeholder");
            }
            grant.read_secret().context("invalid secret reference")?;
        }
        let certs = rustls_pemfile::certs(&mut BufReader::new(std::fs::File::open(
            &config.certificate,
        )?))
        .collect::<std::io::Result<Vec<_>>>()?;
        // The private key is never written to the guest's CA directory.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if std::fs::metadata(&config.private_key)?.permissions().mode() & 0o077 != 0 {
                bail!("TLS private key must be private");
            }
        }
        let key = rustls_pemfile::private_key(&mut BufReader::new(std::fs::File::open(
            &config.private_key,
        )?))?
        .context("missing TLS private key")?;
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let mut client = reqwest::Client::builder()
            .use_rustls_tls()
            .no_proxy()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(DEADLINE)
            .connect_timeout(Duration::from_secs(10));
        if let Some(path) = &config.upstream_ca {
            client =
                client.add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(path)?)?);
        }
        Ok(Arc::new(Self {
            config,
            tls: TlsAcceptor::from(Arc::new(tls)),
            client: client.build()?,
            permits: Arc::new(Semaphore::new(32)),
        }))
    }

    pub fn listen_address(&self) -> SocketAddr {
        self.config.listen
    }

    pub fn unix_socket_path(&self) -> Option<&Path> {
        self.config.unix_socket.as_deref()
    }

    fn authorized(&self, presented: &str) -> bool {
        let Ok(token) = read_private(&self.config.access_token_file) else {
            return false;
        };
        // Avoid returning/logging either credential.
        let expected = Zeroizing::new(format!(
            "Basic {}",
            STANDARD.encode(format!("smol:{}", token.as_str()))
        ));
        constant_time_eq(expected.as_bytes(), presented.as_bytes())
    }

    /// Bounded connections and deadlines include idle clients and TLS setup.
    /// Dropping this future aborts all handlers (no detached secret holders).
    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> Result<()> {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            let (stream, _) = listener.accept().await?;
            let Ok(permit) = self.permits.clone().try_acquire_owned() else {
                // Close overload immediately, rather than queueing an accepted
                // socket outside the session deadline indefinitely.
                drop(stream);
                continue;
            };
            let broker = self.clone();
            tasks.spawn(async move {
                let _permit = permit;
                let _ = tokio::time::timeout(DEADLINE, broker.connection(stream)).await;
            });
            while tasks.try_join_next().is_some() {}
        }
    }

    #[cfg(unix)]
    pub async fn serve_unix(self: Arc<Self>, listener: tokio::net::UnixListener) -> Result<()> {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            let (stream, _) = listener.accept().await?;
            let Ok(permit) = self.permits.clone().try_acquire_owned() else {
                drop(stream);
                continue;
            };
            let broker = self.clone();
            tasks.spawn(async move {
                let _permit = permit;
                let _ = tokio::time::timeout(DEADLINE, broker.connection(stream)).await;
            });
            while tasks.try_join_next().is_some() {}
        }
    }

    async fn connection<S>(self: Arc<Self>, stream: S)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        // A oneshot transfers the upgrade to this connection task, so its
        // timeout and semaphore also cover the intercepted TLS session.
        let (send, receive) = tokio::sync::oneshot::channel();
        let sender = Arc::new(std::sync::Mutex::new(Some(send)));
        let broker = self.clone();
        let service = service_fn(move |mut request: Request<Incoming>| {
            let broker = broker.clone();
            let sender = sender.clone();
            async move {
                let auth = request
                    .headers()
                    .get(header::PROXY_AUTHORIZATION)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                let reply = if request
                    .headers()
                    .get_all(header::PROXY_AUTHORIZATION)
                    .iter()
                    .count()
                    != 1
                    || !broker.authorized(auth)
                {
                    response(
                        StatusCode::PROXY_AUTHENTICATION_REQUIRED,
                        "proxy authorization required",
                    )
                } else if request.method() != Method::CONNECT {
                    response(StatusCode::METHOD_NOT_ALLOWED, "HTTPS CONNECT required")
                } else if let Some(index) = broker
                    .config
                    .grants
                    .iter()
                    .position(|g| request.uri().to_string() == format!("{}:{}", g.host, g.port))
                {
                    let auth = Zeroizing::new(auth.to_owned());
                    let upgrade = hyper::upgrade::on(&mut request);
                    if let Some(send) = sender.lock().expect("upgrade sender poisoned").take() {
                        let _ = send.send((upgrade, index, auth));
                        response(StatusCode::OK, "")
                    } else {
                        response(StatusCode::BAD_REQUEST, "one tunnel per connection")
                    }
                } else {
                    response(StatusCode::FORBIDDEN, "destination not authorized")
                };
                Ok::<_, Infallible>(reply)
            }
        });
        if http1::Builder::new()
            .max_buf_size(32768)
            .serve_connection(TokioIo::new(stream), service)
            .with_upgrades()
            .await
            .is_err()
        {
            return;
        }
        let Ok((upgrade, index, auth)) = receive.await else {
            return;
        };
        let Ok(upgraded) = upgrade.await else {
            return;
        };
        let Ok(tls) = self.tls.accept(TokioIo::new(upgraded)).await else {
            return;
        };
        let broker = self.clone();
        let auth = Arc::new(auth);
        let service = service_fn(move |request| {
            let broker = broker.clone();
            let auth = auth.clone();
            async move {
                let reply = broker
                    .forward(index, auth.as_str(), request)
                    .await
                    .unwrap_or_else(|_| {
                        response(StatusCode::BAD_GATEWAY, "credential service unavailable")
                    });
                Ok::<_, Infallible>(reply)
            }
        });
        let _ = http1::Builder::new()
            .max_buf_size(32768)
            .serve_connection(TokioIo::new(tls), service)
            .await;
    }

    async fn forward(&self, index: usize, auth: &str, request: Request<Incoming>) -> Result<Reply> {
        if !self.authorized(auth) {
            return Ok(response(StatusCode::FORBIDDEN, "access revoked"));
        }
        let grant = &self.config.grants[index];
        if !grant.methods.iter().any(|m| m == request.method().as_str()) {
            return Ok(response(
                StatusCode::METHOD_NOT_ALLOWED,
                "operation not authorized",
            ));
        }
        let authority = if grant.port == 443 {
            grant.host.clone()
        } else {
            format!("{}:{}", grant.host, grant.port)
        };
        // Reject alternate request targets, duplicate Host, upgrades and encoded
        // bodies. No opaque tunnels, WebSockets, HTTP/2 or signing fallback.
        if request.uri().scheme().is_some()
            || request.uri().authority().is_some()
            || request.headers().get_all(header::HOST).iter().count() != 1
            || request
                .headers()
                .get(header::HOST)
                .and_then(|v| v.to_str().ok())
                != Some(authority.as_str())
            || request.method() == Method::CONNECT
            || request.headers().contains_key(header::UPGRADE)
            || request.headers().contains_key(header::CONTENT_ENCODING)
        {
            return Ok(response(
                StatusCode::BAD_REQUEST,
                "unsupported request or authority mismatch",
            ));
        }
        let (parts, body) = request.into_parts();
        let body = match Limited::new(body, REQUEST_LIMIT).collect().await {
            Ok(b) => b.to_bytes(),
            Err(_) => {
                return Ok(response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "request body refused",
                ))
            }
        };
        let target = parts
            .uri
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/");
        if target.contains("SMOL_PLACEHOLDER_") || contains(&body, b"SMOL_PLACEHOLDER_") {
            return Ok(response(
                StatusCode::FORBIDDEN,
                "credentials are supported only in configured headers",
            ));
        }
        let mut headers = parts.headers;
        if headers.get_all(grant.header.as_str()).iter().count() != 1 {
            return Ok(response(
                StatusCode::FORBIDDEN,
                "credential placeholder required",
            ));
        }
        let presented = headers
            .get(grant.header.as_str())
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let bearer = format!("Bearer {}", grant.placeholder);
        let prefix = if presented == grant.placeholder {
            ""
        } else if grant.header == "authorization" && presented == bearer {
            "Bearer "
        } else {
            return Ok(response(
                StatusCode::FORBIDDEN,
                "credential placeholder mismatch",
            ));
        };
        if headers.iter().any(|(name, value)| {
            name != grant.header.as_str() && contains(value.as_bytes(), b"SMOL_PLACEHOLDER_")
        }) {
            return Ok(response(
                StatusCode::FORBIDDEN,
                "placeholder in an unsupported header",
            ));
        }
        strip_hop_headers(&mut headers);
        headers.remove(header::HOST);
        headers.remove(header::CONTENT_LENGTH);
        headers.insert(
            header::ACCEPT_ENCODING,
            header::HeaderValue::from_static("identity"),
        );
        // Body collection yields to the runtime. An administrator may revoke
        // access while a client is uploading; recheck at the dispatch boundary.
        // Requests already dispatched upstream cannot be recalled.
        if !self.authorized(auth) {
            return Ok(response(StatusCode::FORBIDDEN, "access revoked"));
        }
        let secret = grant.read_secret()?;
        let mut value = header::HeaderValue::from_str(&format!("{prefix}{}", secret.as_str()))?;
        value.set_sensitive(true);
        headers.insert(
            header::HeaderName::from_bytes(grant.header.as_bytes())?,
            value,
        );
        let mut upstream = self
            .client
            .request(parts.method, format!("https://{authority}{target}"))
            .headers(headers)
            .body(body)
            .send()
            .await?;
        if upstream.headers().contains_key(header::CONTENT_ENCODING) {
            return Ok(response(
                StatusCode::BAD_GATEWAY,
                "encoded upstream response unsupported",
            ));
        }
        let status = upstream.status();
        let mut output_headers = upstream.headers().clone();
        let mut output = Vec::new();
        while let Some(chunk) = upstream.chunk().await? {
            if chunk.len() > RESPONSE_LIMIT - output.len() {
                return Ok(response(
                    StatusCode::BAD_GATEWAY,
                    "upstream response exceeds limit",
                ));
            }
            output.extend_from_slice(&chunk);
        }
        // Defense in depth against accidental plaintext reflection. Trusted
        // upstreams can still encode a secret; this is not a general DLP claim.
        if contains(&output, secret.as_bytes())
            || output_headers
                .values()
                .any(|v| contains(v.as_bytes(), secret.as_bytes()))
        {
            return Ok(response(
                StatusCode::BAD_GATEWAY,
                "upstream reflected a credential",
            ));
        }
        strip_hop_headers(&mut output_headers);
        output_headers.remove(header::CONTENT_LENGTH);
        output_headers.insert(
            header::CACHE_CONTROL,
            header::HeaderValue::from_static("no-store"),
        );
        let mut reply = Response::new(Full::new(Bytes::from(output)));
        *reply.status_mut() = status;
        *reply.headers_mut() = output_headers;
        Ok(reply)
    }
}

fn response(status: StatusCode, message: &'static str) -> Reply {
    let mut reply = Response::new(Full::new(Bytes::from_static(message.as_bytes())));
    *reply.status_mut() = status;
    reply.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    reply
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

fn strip_hop_headers(headers: &mut header::HeaderMap) {
    let named: Vec<String> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(',').map(|s| s.trim().to_owned()))
        .collect();
    for name in named {
        headers.remove(name);
    }
    for name in [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_source_is_explicit_and_environment_names_are_validated() {
        let mut grant = Grant {
            host: "example.com".into(),
            port: 443,
            placeholder: "SMOL_PLACEHOLDER_TEST_KEY".into(),
            header: "authorization".into(),
            methods: read_methods(),
            secret_file: None,
            secret_env: None,
        };
        assert!(grant.read_secret().is_err());
        grant.secret_env = Some("1INVALID".into());
        assert!(grant.read_secret().is_err());
        grant.secret_env = Some("SMOL_BROKER_UNIT_ABSENT_CREDENTIAL_0192".into());
        assert!(grant.read_secret().is_err());
        grant.secret_file = Some(PathBuf::from("/not-read"));
        assert!(grant.read_secret().is_err());
        assert!(valid_env_name("GITHUB_TOKEN"));
        assert!(!valid_env_name("GITHUB_TOKEN=secret"));
        assert!(!valid_env_name(""));
    }

    #[test]
    fn constant_time_comparison_matches_only_equal_values() {
        assert!(constant_time_eq(b"same", b"same"));
        assert!(!constant_time_eq(b"same", b"else"));
        assert!(!constant_time_eq(b"same", b"same-more"));
    }

    #[test]
    fn strips_all_connection_nominated_headers_and_proxy_credentials() {
        let mut headers = header::HeaderMap::new();
        headers.append("connection", "x-first".parse().unwrap());
        headers.append("connection", "x-second, keep-alive".parse().unwrap());
        for name in ["x-first", "x-second", "keep-alive", "proxy-authorization"] {
            headers.insert(name, "hidden".parse().unwrap());
        }
        headers.insert("x-end-to-end", "visible".parse().unwrap());
        strip_hop_headers(&mut headers);
        assert_eq!(headers.len(), 1);
        assert!(headers.contains_key("x-end-to-end"));
    }

    #[test]
    fn private_reference_is_bounded_and_revocable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        std::fs::write(&path, "synthetic-credential-value\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert!(read_private(&path).is_err());
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(
            read_private(&path).unwrap().as_str(),
            "synthetic-credential-value"
        );
        std::fs::write(&path, "x".repeat(8193)).unwrap();
        assert!(read_private(&path).is_err());
        std::fs::remove_file(&path).unwrap();
        assert!(read_private(&path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlink_and_non_regular_source() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(dir.path().join("missing"), &link).unwrap();
        assert!(read_private(&link).is_err());
        assert!(read_private(dir.path()).is_err());
    }
}
