//! Transparent HTTPS interceptor.
//!
//! The machine's network backend redirects HTTPS flows here (see
//! [`smolvm_protocol::intercept`]). For each flow the interceptor:
//!
//! 1. authenticates the preamble and learns the destination the guest dialed;
//! 2. peeks the TLS ClientHello for the server name;
//! 3. if some binding covers that host, terminates TLS with a leaf minted by
//!    the machine CA, serves HTTP/1.1, replaces the placeholder with the value
//!    the resolver returns, and forwards the request over a verified TLS
//!    connection to the destination IP the guest chose;
//! 4. otherwise splices the raw bytes to the destination untouched.
//!
//! Only the placeholder is replaced; the guest supplies `Bearer ` or any other
//! surrounding syntax. A placeholder anywhere other than an ordinary request
//! header is refused so it can never travel upstream unreplaced.

use crate::ca::MachineCa;
use crate::policy::{CredentialPolicy, PLACEHOLDER_PREFIX};
use crate::resolver::{CredentialRequest, CredentialResolver};
use crate::sni::{peek_client_hello, Peek, MAX_CLIENT_HELLO};
use anyhow::{Context, Result};
use bytes::Bytes;
use futures_util::TryStreamExt;
use http_body_util::{combinators::BoxBody, BodyExt, Full, Limited, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::{
    header, server::conn::http1, service::service_fn, Method, Request, Response, StatusCode,
};
use hyper_util::rt::TokioIo;
use smolvm_protocol::intercept::{
    connect_verdict, preamble_len, InterceptEndpoint, HEADER_LEN, TOKEN_LEN,
};
use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

/// Largest request body forwarded with substitution.
const REQUEST_LIMIT: usize = 8 * 1024 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_SESSIONS: usize = 256;
const MAX_CACHED_CLIENTS: usize = 64;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type Reply = Response<BoxBody<Bytes, BoxError>>;

/// Everything an interceptor needs besides the resolver.
pub struct InterceptorConfig {
    /// Machine identity handed to the resolver with every request.
    pub machine: String,
    pub policy: CredentialPolicy,
    /// Binding name → placeholder the guest was given.
    pub placeholders: BTreeMap<String, String>,
    pub ca: MachineCa,
    /// Extra PEM roots trusted for upstream connections, for private services.
    /// Public roots stay enabled.
    pub upstream_roots_pem: Vec<Vec<u8>>,
}

/// A running interceptor. Dropping it stops the listener and every session.
pub struct Interceptor {
    endpoint: InterceptEndpoint,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

struct State {
    machine: String,
    policy: CredentialPolicy,
    /// placeholder → binding name
    bindings_by_placeholder: HashMap<String, String>,
    ca: MachineCa,
    resolver: Arc<dyn CredentialResolver>,
    endpoint: InterceptEndpoint,
    leaves: Mutex<HashMap<String, Arc<rustls::ServerConfig>>>,
    clients: Mutex<HashMap<(String, SocketAddr), reqwest::Client>>,
    upstream_roots: Vec<reqwest::Certificate>,
    sessions: Arc<tokio::sync::Semaphore>,
}

impl Interceptor {
    /// Bind a loopback listener and start serving on a dedicated runtime.
    pub fn spawn(config: InterceptorConfig, resolver: Arc<dyn CredentialResolver>) -> Result<Self> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").context("bind interceptor")?;
        listener.set_nonblocking(true)?;
        let mut token = [0u8; TOKEN_LEN];
        getrandom::fill(&mut token).context("interceptor token")?;
        let endpoint = InterceptEndpoint {
            addr: listener.local_addr()?,
            token,
        };
        let upstream_roots = config
            .upstream_roots_pem
            .iter()
            .map(|pem| reqwest::Certificate::from_pem(pem).context("upstream root"))
            .collect::<Result<Vec<_>>>()?;
        let state = Arc::new(State {
            machine: config.machine,
            bindings_by_placeholder: config
                .placeholders
                .iter()
                .map(|(binding, placeholder)| (placeholder.clone(), binding.clone()))
                .collect(),
            policy: config.policy,
            ca: config.ca,
            resolver,
            endpoint,
            leaves: Mutex::new(HashMap::new()),
            clients: Mutex::new(HashMap::new()),
            upstream_roots,
            sessions: Arc::new(tokio::sync::Semaphore::new(MAX_SESSIONS)),
        });
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("smolvm-credentials")
            .enable_all()
            .build()
            .context("interceptor runtime")?;
        let thread = std::thread::Builder::new()
            .name("smolvm-credentials-listener".into())
            .spawn(move || {
                runtime.block_on(async move {
                    let listener = match TcpListener::from_std(listener) {
                        Ok(l) => l,
                        Err(e) => {
                            tracing::error!(error = %e, "credential interceptor listener");
                            return;
                        }
                    };
                    tokio::select! {
                        _ = accept_loop(state, listener) => {}
                        _ = shutdown_rx => {}
                    }
                });
                runtime.shutdown_timeout(Duration::from_secs(1));
            })
            .context("interceptor thread")?;
        Ok(Self {
            endpoint,
            shutdown: Some(shutdown_tx),
            thread: Some(thread),
        })
    }

    /// Where the network backend should redirect flows, and with which token.
    pub fn endpoint(&self) -> InterceptEndpoint {
        self.endpoint
    }
}

impl Drop for Interceptor {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

async fn accept_loop(state: Arc<State>, listener: TcpListener) {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                tracing::warn!(error = %e, "credential interceptor accept");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(permit) = state.sessions.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let state = state.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_flow(state, stream).await {
                tracing::debug!(error = %e, "credential interceptor flow ended");
            }
        });
    }
}

async fn handle_flow(state: Arc<State>, mut stream: TcpStream) -> Result<()> {
    let _ = stream.set_nodelay(true);
    let destination = tokio::time::timeout(HANDSHAKE_TIMEOUT, read_preamble(&state, &mut stream))
        .await
        .context("preamble timeout")??;

    // Reach the destination before the guest's connect completes, and report
    // the outcome, so an unreachable destination fails the guest's connect
    // (letting it try another address) instead of an established stream.
    let upstream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(destination))
        .await
        .unwrap_or_else(|_| Err(std::io::ErrorKind::TimedOut.into()));
    stream.write_all(&[connect_verdict(&upstream)]).await?;
    let upstream = upstream.context("upstream connect")?;

    let mut buffered = Vec::with_capacity(2048);
    let peek = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        loop {
            match peek_client_hello(&buffered) {
                Peek::Incomplete if buffered.len() < MAX_CLIENT_HELLO => {
                    let mut chunk = [0u8; 4096];
                    let n = stream.read(&mut chunk).await?;
                    if n == 0 {
                        return Ok::<_, anyhow::Error>(Peek::NoServerName);
                    }
                    buffered.extend_from_slice(&chunk[..n]);
                }
                Peek::Incomplete => return Ok(Peek::NoServerName),
                decided => return Ok(decided),
            }
        }
    })
    .await
    .context("client hello timeout")??;

    match peek {
        Peek::ServerName(host) if state.policy.bindings_for_host(&host).next().is_some() => {
            // The upstream client opens its own verified connection.
            drop(upstream);
            terminate(state, stream, buffered, host, destination).await
        }
        Peek::ServerName(_) | Peek::NoServerName | Peek::Incomplete => {
            passthrough(stream, upstream, buffered).await
        }
    }
}

async fn read_preamble(state: &State, stream: &mut TcpStream) -> Result<SocketAddr> {
    let mut header = [0u8; HEADER_LEN];
    stream.read_exact(&mut header).await?;
    let total = preamble_len(&header).context("preamble family")?;
    let mut full = header.to_vec();
    full.resize(total, 0);
    stream.read_exact(&mut full[HEADER_LEN..]).await?;
    Ok(state.endpoint.read_preamble(&full[..])?)
}

async fn passthrough(
    mut guest: TcpStream,
    mut upstream: TcpStream,
    buffered: Vec<u8>,
) -> Result<()> {
    let _ = upstream.set_nodelay(true);
    upstream.write_all(&buffered).await?;
    let _ = tokio::io::copy_bidirectional(&mut guest, &mut upstream).await;
    Ok(())
}

async fn terminate(
    state: Arc<State>,
    stream: TcpStream,
    buffered: Vec<u8>,
    host: String,
    destination: SocketAddr,
) -> Result<()> {
    let tls_config = state.leaf_config(&host)?;
    let tls = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        TlsAcceptor::from(tls_config).accept(Rewind::new(buffered, stream)),
    )
    .await
    .context("guest TLS handshake timeout")??;
    let host = Arc::new(host);
    let service = service_fn(move |request: Request<Incoming>| {
        let state = state.clone();
        let host = host.clone();
        async move {
            let reply = match state.forward(&host, destination, request).await {
                Ok(reply) => reply,
                Err(e) => {
                    tracing::warn!(machine = %state.machine, host = %host, error = %e, "credential forward failed");
                    text(
                        StatusCode::BAD_GATEWAY,
                        "smolvm credentials: upstream request failed",
                    )
                }
            };
            Ok::<_, std::convert::Infallible>(reply)
        }
    });
    http1::Builder::new()
        .keep_alive(true)
        .serve_connection(TokioIo::new(tls), service)
        .await
        .context("serve intercepted connection")?;
    Ok(())
}

impl State {
    fn leaf_config(&self, host: &str) -> Result<Arc<rustls::ServerConfig>> {
        if let Some(config) = self.leaves.lock().expect("leaf cache").get(host) {
            return Ok(config.clone());
        }
        let (chain, key) = self.ca.issue_leaf(host)?;
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let config = Arc::new(config);
        self.leaves
            .lock()
            .expect("leaf cache")
            .insert(host.to_string(), config.clone());
        Ok(config)
    }

    /// One upstream client per (host, address) so the connection is pinned to
    /// the IP the guest resolved — which the backend already admitted under the
    /// machine's egress policy — while the certificate is verified for `host`.
    fn client_for(&self, host: &str, destination: SocketAddr) -> Result<reqwest::Client> {
        let key = (host.to_string(), destination);
        let mut clients = self.clients.lock().expect("client cache");
        if let Some(client) = clients.get(&key) {
            return Ok(client.clone());
        }
        let mut builder = reqwest::Client::builder()
            .use_rustls_tls()
            .no_proxy()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .resolve(host, destination);
        for root in &self.upstream_roots {
            builder = builder.add_root_certificate(root.clone());
        }
        let client = builder.build().context("upstream client")?;
        if clients.len() >= MAX_CACHED_CLIENTS {
            clients.clear();
        }
        clients.insert(key, client.clone());
        Ok(client)
    }

    async fn forward(
        &self,
        host: &str,
        destination: SocketAddr,
        request: Request<Incoming>,
    ) -> Result<Reply> {
        let authority = if destination.port() == 443 {
            host.to_string()
        } else {
            format!("{host}:{}", destination.port())
        };
        if request.uri().scheme().is_some()
            || request.uri().authority().is_some()
            || request.method() == Method::CONNECT
            || request.headers().contains_key(header::UPGRADE)
        {
            return Ok(text(
                StatusCode::BAD_REQUEST,
                "smolvm credentials: only origin-form HTTP/1.1 requests are forwarded",
            ));
        }
        // The TCP destination fixes the port; the Host header only has to
        // name the same server the TLS handshake did.
        let host_header = request
            .headers()
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(host_without_port);
        if request.headers().get_all(header::HOST).iter().count() != 1
            || !host_header.is_some_and(|h| h.eq_ignore_ascii_case(host))
        {
            return Ok(text(
                StatusCode::BAD_REQUEST,
                "smolvm credentials: Host header must match the TLS server name",
            ));
        }

        let (parts, body) = request.into_parts();
        let target = parts
            .uri
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
        if target.contains(PLACEHOLDER_PREFIX) {
            return Ok(text(
                StatusCode::FORBIDDEN,
                "smolvm credentials: placeholders are substituted in request headers only",
            ));
        }
        let mut headers = parts.headers;
        let substitution = match find_placeholder(&headers) {
            Ok(found) => found,
            Err(reason) => return Ok(text(StatusCode::FORBIDDEN, reason)),
        };
        let body = match Limited::new(body, REQUEST_LIMIT).collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(_) => {
                return Ok(text(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "smolvm credentials: request body exceeds 8 MiB",
                ))
            }
        };
        if contains(&body, PLACEHOLDER_PREFIX.as_bytes()) {
            return Ok(text(
                StatusCode::FORBIDDEN,
                "smolvm credentials: placeholders are substituted in request headers only",
            ));
        }

        if let Some((header_name, placeholder)) = substitution {
            let Some(binding_name) = self.bindings_by_placeholder.get(&placeholder) else {
                return Ok(text(
                    StatusCode::FORBIDDEN,
                    "smolvm credentials: unknown placeholder",
                ));
            };
            let binding = self
                .policy
                .binding(binding_name)
                .context("binding vanished from policy")?;
            if !binding.allows_host(host) {
                return Ok(text(
                    StatusCode::FORBIDDEN,
                    "smolvm credentials: this credential is not allowed for this host",
                ));
            }
            if !binding.allows_method(parts.method.as_str()) {
                return Ok(text(
                    StatusCode::METHOD_NOT_ALLOWED,
                    "smolvm credentials: this credential is not allowed for this method",
                ));
            }
            let resolver = self.resolver.clone();
            let request_for_resolver = CredentialRequest {
                machine: self.machine.clone(),
                binding: binding_name.clone(),
                host: host.to_string(),
                port: destination.port(),
                method: parts.method.as_str().to_string(),
                path: target.clone(),
            };
            let resolved =
                tokio::task::spawn_blocking(move || resolver.resolve(&request_for_resolver))
                    .await
                    .context("resolver task")?;
            let secret = match resolved {
                Ok(secret) => secret,
                Err(e) => {
                    tracing::warn!(machine = %self.machine, binding = %binding_name, host, error = %e, "credential resolution failed");
                    return Ok(text(
                        StatusCode::BAD_GATEWAY,
                        "smolvm credentials: credential unavailable",
                    ));
                }
            };
            let current = headers
                .get(&header_name)
                .context("substituted header vanished")?
                .as_bytes()
                .to_vec();
            let replaced = replace_once(&current, placeholder.as_bytes(), secret.as_bytes());
            // Also refuses a value with CR, LF or other control bytes, which
            // could otherwise split the header.
            let Ok(mut value) = header::HeaderValue::from_bytes(&replaced) else {
                tracing::warn!(machine = %self.machine, binding = %binding_name, host, "credential value is not a valid header value");
                return Ok(text(
                    StatusCode::BAD_GATEWAY,
                    "smolvm credentials: credential unavailable",
                ));
            };
            value.set_sensitive(true);
            headers.insert(header_name, value);
        }

        strip_hop_headers(&mut headers);
        headers.remove(header::HOST);
        headers.remove(header::CONTENT_LENGTH);

        let client = self.client_for(host, destination)?;
        let upstream = client
            .request(parts.method, format!("https://{authority}{target}"))
            .headers(headers)
            .body(body)
            .send()
            .await?;

        let status = upstream.status();
        let mut response_headers = upstream.headers().clone();
        strip_hop_headers(&mut response_headers);
        let body = StreamBody::new(
            upstream
                .bytes_stream()
                .map_ok(Frame::data)
                .map_err(|e| Box::new(e) as BoxError),
        );
        let mut reply = Response::new(BodyExt::boxed(body));
        *reply.status_mut() = status;
        *reply.headers_mut() = response_headers;
        Ok(reply)
    }
}

/// Headers a placeholder may never appear in: they steer routing or framing.
const PROTECTED_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "upgrade",
    "proxy-authorization",
    "proxy-authenticate",
    "proxy-connection",
    "cookie",
];

/// Locate the single placeholder in the request headers.
///
/// Returns `Ok(None)` when no header carries one (the request is forwarded as
/// is), `Ok(Some((header, placeholder)))` for exactly one occurrence, and a
/// guest-facing reason when placeholders appear more than once or in a
/// protected header.
fn find_placeholder(
    headers: &header::HeaderMap,
) -> std::result::Result<Option<(header::HeaderName, String)>, &'static str> {
    let mut found: Option<(header::HeaderName, String)> = None;
    for (name, value) in headers.iter() {
        let bytes = value.as_bytes();
        let Some(start) = find(bytes, PLACEHOLDER_PREFIX.as_bytes()) else {
            continue;
        };
        if PROTECTED_HEADERS.contains(&name.as_str()) {
            return Err("smolvm credentials: placeholders are not substituted in routing or framing headers");
        }
        let end = start
            + bytes[start..]
                .iter()
                .take_while(|c| c.is_ascii_alphanumeric() || **c == b'_')
                .count();
        if find(&bytes[end..], PLACEHOLDER_PREFIX.as_bytes()).is_some() || found.is_some() {
            return Err("smolvm credentials: a request may carry one placeholder");
        }
        let placeholder = std::str::from_utf8(&bytes[start..end])
            .map_err(|_| "smolvm credentials: malformed placeholder")?
            .to_string();
        found = Some((name.clone(), placeholder));
    }
    Ok(found)
}

/// `Host` header value without an optional `:port` suffix.
fn host_without_port(value: &str) -> &str {
    match value.rsplit_once(':') {
        Some((name, port)) if !port.is_empty() && port.bytes().all(|c| c.is_ascii_digit()) => name,
        _ => value,
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    find(haystack, needle).is_some()
}

fn replace_once(value: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    match find(value, from) {
        Some(at) => {
            let mut out = Vec::with_capacity(value.len() - from.len() + to.len());
            out.extend_from_slice(&value[..at]);
            out.extend_from_slice(to);
            out.extend_from_slice(&value[at + from.len()..]);
            out
        }
        None => value.to_vec(),
    }
}

fn strip_hop_headers(headers: &mut header::HeaderMap) {
    let listed: Vec<String> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|s| s.trim().to_ascii_lowercase())
        .collect();
    for name in listed {
        if let Ok(name) = header::HeaderName::from_bytes(name.as_bytes()) {
            headers.remove(name);
        }
    }
    for name in [
        header::CONNECTION,
        header::TRANSFER_ENCODING,
        header::TE,
        header::TRAILER,
        header::UPGRADE,
        header::PROXY_AUTHENTICATE,
        header::PROXY_AUTHORIZATION,
    ] {
        headers.remove(name);
    }
    headers.remove("keep-alive");
    headers.remove("proxy-connection");
}

fn text(status: StatusCode, message: &'static str) -> Reply {
    let mut reply = Response::new(
        Full::new(Bytes::from_static(message.as_bytes()))
            .map_err(|never| match never {})
            .boxed(),
    );
    *reply.status_mut() = status;
    reply.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    reply.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    reply
}

/// Replays already-consumed bytes before reading from the inner stream.
struct Rewind<S> {
    prefix: Vec<u8>,
    offset: usize,
    inner: S,
}

impl<S> Rewind<S> {
    fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            offset: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Rewind<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.offset < self.prefix.len() {
            let n = buf.remaining().min(self.prefix.len() - self.offset);
            let offset = self.offset;
            buf.put_slice(&self.prefix[offset..offset + n]);
            self.offset += n;
            if self.offset == self.prefix.len() {
                self.prefix = Vec::new();
                self.offset = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Rewind<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{CredentialBinding, InjectionLocation, DEFAULT_METHODS};
    use crate::resolver::StaticResolver;
    use rustls::pki_types::ServerName;
    use tokio_rustls::TlsConnector;

    const CRED_HOST: &str = "api.credential.test";
    const OTHER_HOST: &str = "other.service.test";

    /// A TLS upstream serving both test hosts from one certificate. Records
    /// the Authorization header and path of every request it answers.
    struct Upstream {
        addr: SocketAddr,
        cert_pem: Vec<u8>,
        seen: Arc<Mutex<Vec<(String, String)>>>,
    }

    fn provider() -> Arc<rustls::crypto::CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    async fn start_upstream() -> Upstream {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert =
            rcgen::CertificateParams::new(vec![CRED_HOST.to_string(), OTHER_HOST.to_string()])
                .unwrap()
                .self_signed(&key)
                .unwrap();
        let cert_pem = cert.pem().into_bytes();
        let mut config = rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
            )
            .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                let recorded = recorded.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let service = service_fn(move |request: Request<Incoming>| {
                        let recorded = recorded.clone();
                        async move {
                            let auth = request
                                .headers()
                                .get(header::AUTHORIZATION)
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_string();
                            let path = request.uri().path().to_string();
                            recorded.lock().unwrap().push((auth, path.clone()));
                            Ok::<_, std::convert::Infallible>(text(StatusCode::OK, "upstream ok"))
                        }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), service)
                        .await;
                });
            }
        });
        Upstream {
            addr,
            cert_pem,
            seen,
        }
    }

    struct Fixture {
        upstream: Upstream,
        interceptor: Interceptor,
        placeholder: String,
        ca_pem: String,
    }

    async fn fixture() -> Fixture {
        fixture_with_secret("real-secret").await
    }

    async fn fixture_with_secret(secret: &str) -> Fixture {
        let upstream = start_upstream().await;
        let policy = CredentialPolicy {
            credentials: vec![CredentialBinding {
                name: "svc".into(),
                environment_variable: "SVC_TOKEN".into(),
                allowed_hosts: vec![CRED_HOST.into()],
                injection_location: InjectionLocation::default(),
                methods: DEFAULT_METHODS.iter().map(|m| m.to_string()).collect(),
            }],
        };
        let placeholders = crate::policy::generate_placeholders(&policy);
        let placeholder = placeholders["svc"].clone();
        let ca = MachineCa::generate("test-machine").unwrap();
        let ca_pem = ca.certificate_pem().to_string();
        let interceptor = Interceptor::spawn(
            InterceptorConfig {
                machine: "test-machine".into(),
                policy,
                placeholders,
                ca,
                upstream_roots_pem: vec![upstream.cert_pem.clone()],
            },
            Arc::new(StaticResolver::new().with("svc", secret)),
        )
        .unwrap();
        Fixture {
            upstream,
            interceptor,
            placeholder,
            ca_pem,
        }
    }

    fn client_config(trusted_pem: &[u8]) -> Arc<rustls::ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut &trusted_pem[..]) {
            roots.add(cert.unwrap()).unwrap();
        }
        Arc::new(
            rustls::ClientConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    }

    /// Dial the interceptor the way a backend would, then speak TLS+HTTP/1.1
    /// as the guest and return the raw response.
    async fn guest_request(
        f: &Fixture,
        trusted_pem: &[u8],
        sni: &str,
        request: &str,
    ) -> std::io::Result<String> {
        let mut tcp = TcpStream::connect(f.interceptor.endpoint().addr).await?;
        tcp.write_all(&f.interceptor.endpoint().preamble(f.upstream.addr))
            .await?;
        let mut verdict = [0xffu8; 1];
        tcp.read_exact(&mut verdict).await?;
        assert_eq!(verdict[0], 0, "interceptor could not reach the upstream");
        let connector = TlsConnector::from(client_config(trusted_pem));
        let name = ServerName::try_from(sni.to_string()).unwrap();
        let mut tls = connector.connect(name, tcp).await?;
        tls.write_all(request.as_bytes()).await?;
        let mut out = Vec::new();
        let _ = tls.read_to_end(&mut out).await;
        Ok(String::from_utf8_lossy(&out).into_owned())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn substitutes_the_placeholder_for_a_credential_host() {
        let f = fixture().await;
        let request = format!(
            "GET /v1/me HTTP/1.1\r\nHost: {CRED_HOST}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
            f.placeholder
        );
        let response = guest_request(&f, f.ca_pem.as_bytes(), CRED_HOST, &request)
            .await
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.ends_with("upstream ok"), "{response}");
        let seen = f.upstream.seen.lock().unwrap().clone();
        assert_eq!(
            seen,
            vec![("Bearer real-secret".to_string(), "/v1/me".to_string())]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn splices_other_hosts_through_untouched() {
        let f = fixture().await;
        let request = format!(
            "GET /raw HTTP/1.1\r\nHost: {OTHER_HOST}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
            f.placeholder
        );
        // Trusting only the upstream's own certificate proves the guest saw the
        // real server, not a leaf minted by the machine CA.
        let response = guest_request(&f, &f.upstream.cert_pem, OTHER_HOST, &request)
            .await
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        let seen = f.upstream.seen.lock().unwrap().clone();
        assert_eq!(seen[0].0, format!("Bearer {}", f.placeholder));
        assert_eq!(seen[0].1, "/raw");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refuses_unknown_placeholders_and_misplaced_ones() {
        let f = fixture().await;
        let request = format!(
            "GET /v1/me HTTP/1.1\r\nHost: {CRED_HOST}\r\nAuthorization: Bearer SMOL_PLACEHOLDER_FORGED_1\r\nConnection: close\r\n\r\n"
        );
        let response = guest_request(&f, f.ca_pem.as_bytes(), CRED_HOST, &request)
            .await
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");

        let request = format!(
            "GET /v1/me?key={} HTTP/1.1\r\nHost: {CRED_HOST}\r\nConnection: close\r\n\r\n",
            f.placeholder
        );
        let response = guest_request(&f, f.ca_pem.as_bytes(), CRED_HOST, &request)
            .await
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");
        assert!(f.upstream.seen.lock().unwrap().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refuses_a_value_that_would_split_the_header() {
        let f = fixture_with_secret("real\r\nX-Injected: 1").await;
        let request = format!(
            "GET /v1/me HTTP/1.1\r\nHost: {CRED_HOST}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
            f.placeholder
        );
        let response = guest_request(&f, f.ca_pem.as_bytes(), CRED_HOST, &request)
            .await
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 502"), "{response}");
        assert!(response.ends_with("credential unavailable"), "{response}");
        assert!(f.upstream.seen.lock().unwrap().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn forwards_requests_without_a_placeholder_as_is() {
        let f = fixture().await;
        let request =
            format!("GET /public HTTP/1.1\r\nHost: {CRED_HOST}\r\nConnection: close\r\n\r\n");
        let response = guest_request(&f, f.ca_pem.as_bytes(), CRED_HOST, &request)
            .await
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        let seen = f.upstream.seen.lock().unwrap().clone();
        assert_eq!(seen, vec![(String::new(), "/public".to_string())]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reports_an_unreachable_destination_before_the_guest_sends() {
        let f = fixture().await;
        // A port nothing listens on: the guest's connect must fail, not
        // succeed and then drop mid-handshake.
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let destination = closed.local_addr().unwrap();
        drop(closed);
        let mut tcp = TcpStream::connect(f.interceptor.endpoint().addr)
            .await
            .unwrap();
        tcp.write_all(&f.interceptor.endpoint().preamble(destination))
            .await
            .unwrap();
        let mut verdict = [0u8; 1];
        tcp.read_exact(&mut verdict).await.unwrap();
        assert_eq!(verdict[0], 111, "expected ECONNREFUSED");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drops_connections_with_a_bad_token() {
        let f = fixture().await;
        let mut forged = f.interceptor.endpoint();
        forged.token[0] ^= 0xff;
        let mut tcp = TcpStream::connect(forged.addr).await.unwrap();
        tcp.write_all(&forged.preamble(f.upstream.addr))
            .await
            .unwrap();
        let mut buf = [0u8; 8];
        let closed = matches!(tcp.read(&mut buf).await, Ok(0) | Err(_));
        assert!(
            closed,
            "interceptor kept a connection with a forged token open"
        );
        assert!(f.upstream.seen.lock().unwrap().is_empty());
    }

    #[test]
    fn placeholder_scan_rules() {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Bearer SMOL_PLACEHOLDER_A_1".parse().unwrap(),
        );
        let (name, placeholder) = find_placeholder(&headers).unwrap().unwrap();
        assert_eq!(name, header::AUTHORIZATION);
        assert_eq!(placeholder, "SMOL_PLACEHOLDER_A_1");

        headers.insert("x-api-key", "SMOL_PLACEHOLDER_B_2".parse().unwrap());
        assert!(find_placeholder(&headers).is_err());

        let mut headers = header::HeaderMap::new();
        headers.insert(header::HOST, "SMOL_PLACEHOLDER_A_1".parse().unwrap());
        assert!(find_placeholder(&headers).is_err());

        let mut headers = header::HeaderMap::new();
        headers.insert(header::ACCEPT, "application/json".parse().unwrap());
        assert!(find_placeholder(&headers).unwrap().is_none());
    }

    #[test]
    fn host_header_port_suffix_is_ignored() {
        assert_eq!(host_without_port("api.example.com:8443"), "api.example.com");
        assert_eq!(host_without_port("api.example.com"), "api.example.com");
        assert_eq!(host_without_port("[::1]:443"), "[::1]");
    }

    #[test]
    fn replace_once_keeps_surrounding_syntax() {
        assert_eq!(
            replace_once(
                b"Bearer SMOL_PLACEHOLDER_X_1 trailing",
                b"SMOL_PLACEHOLDER_X_1",
                b"real"
            ),
            b"Bearer real trailing".to_vec()
        );
    }
}
