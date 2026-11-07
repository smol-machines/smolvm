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
//!
//! With a [`GuestTunnel`], the interceptor also serves HTTPS the workload
//! routed through another interface than the machine's NIC (a Tailscale or
//! WireGuard TUN): the guest agent hands each such connection over a Unix
//! socket, and the upstream connection is opened back through the guest so it
//! takes the workload's route (see [`smolvm_protocol::intercept::tunnel`]).
//! TLS to the upstream is still made and verified here.

// The credential tunnel is Unix-only; elsewhere its plumbing is unused.
#![cfg_attr(not(unix), allow(dead_code))]

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
#[cfg(unix)]
use smolvm_protocol::intercept::{tunnel, VERDICT_CONNECTED};
use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::AtomicU64;
#[cfg(unix)]
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
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
    /// Serve HTTPS the guest routes through other interfaces too.
    pub guest_tunnel: Option<GuestTunnel>,
}

/// The host ends of the credential tunnel (see the module docs).
#[derive(Clone, Debug)]
pub struct GuestTunnel {
    /// Unix socket the interceptor listens on; the guest agent's redirected
    /// connections arrive here, each prefixed with its destination line.
    pub flows: PathBuf,
    /// Unix socket that reaches the guest agent's dial service; connecting
    /// and writing a destination line opens an upstream from inside the guest.
    pub dial: PathBuf,
    /// Private directory for the per-connection sockets the upstream HTTP
    /// client dials through the guest.
    pub relay_dir: PathBuf,
}

/// A connection the interceptor can relay: TCP, or a Unix socket into the guest.
trait Io: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Io for T {}

/// How a flow's upstream connection is opened.
#[derive(Clone, Copy)]
enum Route<'a> {
    /// From this host, to the destination the backend admitted.
    Direct,
    /// From inside the guest, through its dial service at this socket.
    Guest(&'a Path),
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
    guest_tunnel: Option<GuestTunnel>,
    relay_seq: AtomicU64,
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
            guest_tunnel: config.guest_tunnel.clone(),
            relay_seq: AtomicU64::new(0),
        });
        // Bind before the VM boots, so the guest's first redirected flow finds
        // the socket.
        #[cfg(unix)]
        let tunnel_listener = match &config.guest_tunnel {
            Some(tunnel) => {
                let _ = std::fs::remove_file(&tunnel.flows);
                let listener = std::os::unix::net::UnixListener::bind(&tunnel.flows)
                    .with_context(|| format!("bind {}", tunnel.flows.display()))?;
                listener.set_nonblocking(true)?;
                Some(listener)
            }
            None => None,
        };
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
                    #[cfg(unix)]
                    let tunnel = async {
                        match tunnel_listener.map(UnixListener::from_std) {
                            Some(Ok(listener)) => tunnel_accept_loop(state.clone(), listener).await,
                            Some(Err(e)) => {
                                tracing::error!(error = %e, "credential tunnel listener");
                                std::future::pending().await
                            }
                            None => std::future::pending().await,
                        }
                    };
                    #[cfg(not(unix))]
                    let tunnel = std::future::pending::<()>();
                    tokio::select! {
                        _ = accept_loop(state.clone(), listener) => {}
                        _ = tunnel => {}
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

#[cfg(unix)]
async fn tunnel_accept_loop(state: Arc<State>, listener: UnixListener) {
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(e) => {
                tracing::warn!(error = %e, "credential tunnel accept");
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
            if let Err(e) = handle_tunnel_flow(state, stream).await {
                tracing::debug!(error = %e, "credential tunnel flow ended");
            }
        });
    }
}

#[cfg(unix)]
/// A connection the guest agent redirected from another interface: its
/// upstream is opened back through the guest, along the workload's route.
async fn handle_tunnel_flow(state: Arc<State>, mut stream: UnixStream) -> Result<()> {
    let destination = tokio::time::timeout(HANDSHAKE_TIMEOUT, read_destination_line(&mut stream))
        .await
        .context("destination timeout")??;
    let tunnel = state
        .guest_tunnel
        .clone()
        .context("credential tunnel is not configured")?;
    // The guest's connect already completed against the agent, so a failed
    // upstream can only close the stream.
    let upstream = dial_guest(&tunnel.dial, destination)
        .await
        .context("upstream connect through the guest")?;
    serve_flow(
        state,
        stream,
        upstream,
        destination,
        Route::Guest(&tunnel.dial),
    )
    .await
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
    let _ = upstream.set_nodelay(true);
    serve_flow(state, stream, upstream, destination, Route::Direct).await
}

/// Terminate a credential host's TLS or splice anything else to `upstream`.
async fn serve_flow<S: Io, U: Io>(
    state: Arc<State>,
    mut stream: S,
    upstream: U,
    destination: SocketAddr,
    route: Route<'_>,
) -> Result<()> {
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
            terminate(state, stream, buffered, host, destination, route).await
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

#[cfg(unix)]
/// Read the credential tunnel's `IP:PORT\n` line without consuming more.
async fn read_destination_line<S: AsyncRead + Unpin>(stream: &mut S) -> Result<SocketAddr> {
    let mut line = Vec::with_capacity(tunnel::MAX_LINE);
    loop {
        let byte = stream.read_u8().await?;
        if byte == b'\n' {
            return Ok(tunnel::parse_destination(&line)?);
        }
        line.push(byte);
        if line.len() > tunnel::MAX_LINE {
            anyhow::bail!("credential tunnel destination line too long");
        }
    }
}

#[cfg(unix)]
/// Open `destination` from inside the guest through its dial service.
async fn dial_guest(dial: &Path, destination: SocketAddr) -> std::io::Result<UnixStream> {
    let connect = async {
        let mut stream = UnixStream::connect(dial).await?;
        stream
            .write_all(tunnel::destination_line(destination).as_bytes())
            .await?;
        match stream.read_u8().await? {
            VERDICT_CONNECTED => Ok(stream),
            errno => Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                format!("the guest could not reach {destination} (errno {errno})"),
            )),
        }
    };
    tokio::time::timeout(CONNECT_TIMEOUT + Duration::from_secs(5), connect)
        .await
        .unwrap_or_else(|_| Err(std::io::ErrorKind::TimedOut.into()))
}

/// A Unix socket whose every connection is relayed through the guest to one
/// destination, so the upstream HTTP client (which dials a socket path, not a
/// stream it is handed) reaches it along the guest's route. It lives as long
/// as the guest connection it serves.
struct GuestRelay {
    path: PathBuf,
    task: tokio::task::JoinHandle<()>,
}

#[cfg(unix)]
impl GuestRelay {
    fn bind(state: &State, dial: &Path, destination: SocketAddr) -> Result<Self> {
        let dir = &state
            .guest_tunnel
            .as_ref()
            .context("credential tunnel is not configured")?
            .relay_dir;
        let seq = state.relay_seq.fetch_add(1, Ordering::Relaxed);
        let path = dir.join(format!("cred-relay-{seq}.sock"));
        let _ = std::fs::remove_file(&path);
        let listener =
            UnixListener::bind(&path).with_context(|| format!("bind {}", path.display()))?;
        let dial = dial.to_path_buf();
        let task = tokio::spawn(async move {
            while let Ok((mut client, _)) = listener.accept().await {
                let dial = dial.clone();
                tokio::spawn(async move {
                    if let Ok(mut upstream) = dial_guest(&dial, destination).await {
                        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                    }
                });
            }
        });
        Ok(Self { path, task })
    }
}

#[cfg(unix)]
impl Drop for GuestRelay {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_file(&self.path);
    }
}

async fn passthrough<S: Io, U: Io>(mut guest: S, mut upstream: U, buffered: Vec<u8>) -> Result<()> {
    upstream.write_all(&buffered).await?;
    let _ = tokio::io::copy_bidirectional(&mut guest, &mut upstream).await;
    Ok(())
}

async fn terminate<S: Io>(
    state: Arc<State>,
    stream: S,
    buffered: Vec<u8>,
    host: String,
    destination: SocketAddr,
    route: Route<'_>,
) -> Result<()> {
    let tls_config = state.leaf_config(&host)?;
    let tls = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        TlsAcceptor::from(tls_config).accept(Rewind::new(buffered, stream)),
    )
    .await
    .context("guest TLS handshake timeout")??;
    // Through the guest, this connection gets a client of its own pinned to a
    // relay that dials the destination from inside the guest; the relay goes
    // away with the connection.
    let (relay, client) = match route {
        Route::Direct => (None, state.client_for(&host, destination)?),
        #[cfg(unix)]
        Route::Guest(dial) => {
            let relay = GuestRelay::bind(&state, dial, destination)?;
            let client = state.build_client(&host, Upstream::Unix(&relay.path))?;
            (Some(relay), client)
        }
        #[cfg(not(unix))]
        Route::Guest(_) => anyhow::bail!("the credential tunnel needs Unix sockets"),
    };
    let host = Arc::new(host);
    let service = service_fn(move |request: Request<Incoming>| {
        let state = state.clone();
        let host = host.clone();
        let client = client.clone();
        async move {
            let reply = match state.forward(&host, destination, &client, request).await {
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
    let served = http1::Builder::new()
        .keep_alive(true)
        .serve_connection(TokioIo::new(tls), service)
        .await
        .context("serve intercepted connection");
    drop(relay);
    served
}

/// Where an upstream client connects.
enum Upstream<'a> {
    /// The destination the guest resolved, directly from this host.
    Address(SocketAddr),
    /// A relay socket that reaches the destination through the guest.
    Unix(&'a Path),
}

impl State {
    /// Ask the resolver for `binding`'s value for this request. The inner
    /// `Err` is the reply to send the guest when it has none.
    async fn resolve(
        &self,
        binding: &str,
        host: &str,
        destination: SocketAddr,
        method: &str,
        path: &str,
    ) -> Result<std::result::Result<zeroize::Zeroizing<String>, Reply>> {
        let resolver = self.resolver.clone();
        let request = CredentialRequest {
            machine: self.machine.clone(),
            binding: binding.to_string(),
            host: host.to_string(),
            port: destination.port(),
            method: method.to_string(),
            path: path.to_string(),
        };
        let resolved = tokio::task::spawn_blocking(move || resolver.resolve(&request))
            .await
            .context("resolver task")?;
        Ok(resolved.map_err(|e| {
            tracing::warn!(machine = %self.machine, binding, host, error = %e, "credential resolution failed");
            text(
                StatusCode::BAD_GATEWAY,
                "smolvm credentials: credential unavailable",
            )
        }))
    }

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
        let client = self.build_client(host, Upstream::Address(destination))?;
        if clients.len() >= MAX_CACHED_CLIENTS {
            clients.clear();
        }
        clients.insert(key, client.clone());
        Ok(client)
    }

    /// An upstream client that verifies `host`'s certificate whatever it
    /// connects to.
    fn build_client(&self, host: &str, upstream: Upstream<'_>) -> Result<reqwest::Client> {
        let mut builder = reqwest::Client::builder()
            .use_rustls_tls()
            .no_proxy()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT);
        builder = match upstream {
            Upstream::Address(destination) => builder.resolve(host, destination),
            #[cfg(unix)]
            Upstream::Unix(path) => builder.unix_socket(path),
            #[cfg(not(unix))]
            Upstream::Unix(_) => anyhow::bail!("the credential tunnel needs Unix sockets"),
        };
        for root in &self.upstream_roots {
            builder = builder.add_root_certificate(root.clone());
        }
        builder.build().context("upstream client")
    }

    async fn forward(
        &self,
        host: &str,
        destination: SocketAddr,
        client: &reqwest::Client,
        request: Request<Incoming>,
    ) -> Result<Reply> {
        let authority = if destination.port() == 443 {
            host.to_string()
        } else {
            format!("{host}:{}", destination.port())
        };
        let websocket_upgrade = request
            .headers()
            .get(header::UPGRADE)
            .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"websocket"));
        if request.uri().scheme().is_some()
            || request.uri().authority().is_some()
            || request.method() == Method::CONNECT
            || (request.headers().contains_key(header::UPGRADE) && !websocket_upgrade)
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

        // WebSocket tunneling cannot use the HTTP forwarding client. Tell
        // clients with an HTTP fallback to retry that transport; never forward
        // the handshake or substitute its credential into an unsupported flow.
        if websocket_upgrade {
            let mut reply = text(
                StatusCode::UPGRADE_REQUIRED,
                "smolvm credentials: WebSocket forwarding is unavailable; use HTTP/1.1",
            );
            reply.headers_mut().insert(
                header::UPGRADE,
                header::HeaderValue::from_static("HTTP/1.1"),
            );
            return Ok(reply);
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
        let body_placeholder = match find_body_placeholder(&body) {
            Ok(found) => found,
            Err(reason) => return Ok(text(StatusCode::FORBIDDEN, reason)),
        };
        if substitution
            .as_ref()
            .zip(body_placeholder.as_ref())
            .is_some_and(|((_, header_placeholder), body_placeholder)| {
                header_placeholder != body_placeholder
            })
        {
            return Ok(text(
                StatusCode::FORBIDDEN,
                "smolvm credentials: a request may carry one placeholder",
            ));
        }
        let mut body = body.to_vec();
        if let Some(placeholder) = substitution
            .as_ref()
            .map(|(_, placeholder)| placeholder)
            .or(body_placeholder.as_ref())
        {
            let Some(binding_name) = self.bindings_by_placeholder.get(placeholder) else {
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
            if substitution.is_some() && !binding.injection_location.header {
                return Ok(text(
                    StatusCode::FORBIDDEN,
                    "smolvm credentials: header substitution is disabled for this binding",
                ));
            }
            if body_placeholder.is_some() {
                if !binding.injection_location.body {
                    return Ok(text(
                        StatusCode::FORBIDDEN,
                        "smolvm credentials: body substitution is disabled for this binding",
                    ));
                }
                if !headers.get(header::CONTENT_TYPE).is_some_and(|value| {
                    value.to_str().is_ok_and(|value| {
                        value.split(';').next().is_some_and(|mime| {
                            mime.trim()
                                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
                        })
                    })
                }) {
                    return Ok(text(
                        StatusCode::UNSUPPORTED_MEDIA_TYPE,
                        "smolvm credentials: body substitution requires a form body",
                    ));
                }
            }
            let secret = match self
                .resolve(
                    binding_name,
                    host,
                    destination,
                    parts.method.as_str(),
                    &target,
                )
                .await?
            {
                Ok(secret) => secret,
                Err(reply) => return Ok(reply),
            };
            if let Some((header_name, _)) = &substitution {
                let current = headers
                    .get(header_name)
                    .context("substituted header vanished")?
                    .as_bytes()
                    .to_vec();
                let replaced = replace_once(&current, placeholder.as_bytes(), secret.as_bytes());
                // Reject control bytes that could split the header.
                let Ok(mut value) = header::HeaderValue::from_bytes(&replaced) else {
                    tracing::warn!(machine = %self.machine, binding = %binding_name, host, "credential value is not a valid header value");
                    return Ok(text(
                        StatusCode::BAD_GATEWAY,
                        "smolvm credentials: credential unavailable",
                    ));
                };
                value.set_sensitive(true);
                headers.insert(header_name.clone(), value);
            }
            if body_placeholder.is_some() {
                let encoded = zeroize::Zeroizing::new(form_encode(secret.as_bytes()));
                body = replace_once(&body, placeholder.as_bytes(), encoded.as_bytes());
                if body.len() > REQUEST_LIMIT {
                    return Ok(text(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "smolvm credentials: substituted request body exceeds 8 MiB",
                    ));
                }
            }
        }

        // Header-setting bindings: the host supplies the whole value and it
        // replaces whatever the guest sent, placeholder or not.
        for binding in self.policy.header_bindings(host, parts.method.as_str()) {
            let header_name = binding
                .set_header
                .as_deref()
                .context("header binding without a header")?;
            let secret = match self
                .resolve(
                    &binding.name,
                    host,
                    destination,
                    parts.method.as_str(),
                    &target,
                )
                .await?
            {
                Ok(secret) => secret,
                Err(reply) => return Ok(reply),
            };
            let (Ok(name), Ok(mut value)) = (
                header::HeaderName::from_bytes(header_name.as_bytes()),
                header::HeaderValue::from_bytes(secret.as_bytes()),
            ) else {
                tracing::warn!(machine = %self.machine, binding = %binding.name, host, "credential value is not a valid header value");
                return Ok(text(
                    StatusCode::BAD_GATEWAY,
                    "smolvm credentials: credential unavailable",
                ));
            };
            value.set_sensitive(true);
            headers.insert(name, value);
        }

        strip_hop_headers(&mut headers);
        headers.remove(header::HOST);
        headers.remove(header::CONTENT_LENGTH);

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

use smolvm_protocol::credentials::PROTECTED_HEADERS;

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

/// Find the one literal placeholder in a form body, rejecting repeated tokens
/// before resolving anything or sending the request upstream.
fn find_body_placeholder(body: &[u8]) -> std::result::Result<Option<String>, &'static str> {
    let Some(start) = find(body, PLACEHOLDER_PREFIX.as_bytes()) else {
        return Ok(None);
    };
    let end = start
        + body[start..]
            .iter()
            .take_while(|c| c.is_ascii_alphanumeric() || **c == b'_')
            .count();
    if contains(&body[end..], PLACEHOLDER_PREFIX.as_bytes()) {
        return Err("smolvm credentials: a request may carry one placeholder");
    }
    let placeholder = std::str::from_utf8(&body[start..end])
        .map_err(|_| "smolvm credentials: malformed placeholder")?;
    Ok(Some(placeholder.to_string()))
}

/// Percent-encode the secret as one form field value: separators and control
/// characters in a credential must never become new fields in the request.
fn form_encode(secret: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(secret.len());
    for &byte in secret {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[(byte >> 4) as usize]));
            encoded.push(char::from(HEX[(byte & 0xf) as usize]));
        }
    }
    encoded
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
        bodies: Arc<Mutex<Vec<String>>>,
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
        let bodies = Arc::new(Mutex::new(Vec::new()));
        let recorded_bodies = bodies.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                let recorded = recorded.clone();
                let recorded_bodies = recorded_bodies.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let service = service_fn(move |request: Request<Incoming>| {
                        let recorded = recorded.clone();
                        let recorded_bodies = recorded_bodies.clone();
                        async move {
                            let auth = request
                                .headers()
                                .get(header::AUTHORIZATION)
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_string();
                            let path = request.uri().path().to_string();
                            let body = request.into_body().collect().await.unwrap().to_bytes();
                            recorded_bodies
                                .lock()
                                .unwrap()
                                .push(String::from_utf8_lossy(&body).into_owned());
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
            bodies,
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
        let policy = CredentialPolicy {
            credentials: vec![CredentialBinding {
                name: "svc".into(),
                environment_variable: "SVC_TOKEN".into(),
                allowed_hosts: vec![CRED_HOST.into()],
                injection_location: InjectionLocation::default(),
                methods: DEFAULT_METHODS.iter().map(|m| m.to_string()).collect(),
                set_header: None,
            }],
        };
        fixture_with_policy(policy, CRED_HOST, StaticResolver::new().with("svc", secret)).await
    }

    async fn fixture_with_policy(
        policy: CredentialPolicy,
        ca_subtree: &str,
        resolver: StaticResolver,
    ) -> Fixture {
        let upstream = start_upstream().await;
        let placeholders = crate::policy::generate_placeholders(&policy);
        let placeholder = placeholders.values().next().cloned().unwrap_or_default();
        let ca = MachineCa::generate("test-machine", &[ca_subtree.to_string()]).unwrap();
        let ca_pem = ca.certificate_pem().to_string();
        let interceptor = Interceptor::spawn(
            InterceptorConfig {
                machine: "test-machine".into(),
                policy,
                placeholders,
                ca,
                upstream_roots_pem: vec![upstream.cert_pem.clone()],
                guest_tunnel: None,
            },
            Arc::new(resolver),
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

    /// A wildcard binding that sets `Authorization` on GETs only.
    async fn header_fixture() -> Fixture {
        let policy = CredentialPolicy {
            credentials: vec![CredentialBinding {
                name: "git".into(),
                environment_variable: String::new(),
                allowed_hosts: vec!["*.credential.test".into()],
                injection_location: InjectionLocation::default(),
                methods: vec!["GET".into()],
                set_header: Some("authorization".into()),
            }],
        };
        fixture_with_policy(
            policy,
            "credential.test",
            StaticResolver::new().with("git", "Basic aW5qZWN0ZWQ="),
        )
        .await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sets_the_header_for_a_matching_host_replacing_the_guests() {
        let f = header_fixture().await;
        for guest_auth in ["Authorization: Bearer guest-chosen\r\n", ""] {
            let request = format!(
                "GET /repo.git/info/refs HTTP/1.1\r\nHost: {CRED_HOST}\r\n{guest_auth}Connection: close\r\n\r\n"
            );
            let response = guest_request(&f, f.ca_pem.as_bytes(), CRED_HOST, &request)
                .await
                .unwrap();
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        }
        let seen = f.upstream.seen.lock().unwrap().clone();
        assert_eq!(
            seen,
            vec![
                (
                    "Basic aW5qZWN0ZWQ=".to_string(),
                    "/repo.git/info/refs".to_string()
                ),
                (
                    "Basic aW5qZWN0ZWQ=".to_string(),
                    "/repo.git/info/refs".to_string()
                ),
            ]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sets_no_header_for_a_method_the_binding_does_not_allow() {
        let f = header_fixture().await;
        let request = format!(
            "POST /repo.git/git-receive-pack HTTP/1.1\r\nHost: {CRED_HOST}\r\nAuthorization: Bearer guest-chosen\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let response = guest_request(&f, f.ca_pem.as_bytes(), CRED_HOST, &request)
            .await
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        let seen = f.upstream.seen.lock().unwrap().clone();
        assert_eq!(seen[0].0, "Bearer guest-chosen");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unresolvable_header_value_fails_closed() {
        let policy = CredentialPolicy {
            credentials: vec![CredentialBinding {
                name: "git".into(),
                environment_variable: String::new(),
                allowed_hosts: vec![CRED_HOST.into()],
                injection_location: InjectionLocation::default(),
                methods: DEFAULT_METHODS.iter().map(|m| m.to_string()).collect(),
                set_header: Some("authorization".into()),
            }],
        };
        let f = fixture_with_policy(policy, CRED_HOST, StaticResolver::new()).await;
        let request = format!("GET / HTTP/1.1\r\nHost: {CRED_HOST}\r\nConnection: close\r\n\r\n");
        let response = guest_request(&f, f.ca_pem.as_bytes(), CRED_HOST, &request)
            .await
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 502"), "{response}");
        assert!(
            f.upstream.seen.lock().unwrap().is_empty(),
            "nothing reached upstream"
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

    /// The guest end of the credential tunnel: a dial service that, like the
    /// guest agent, reads a destination line, connects, answers a verdict and
    /// relays. Records every destination it was asked for.
    #[cfg(unix)]
    struct FakeGuest {
        dir: tempfile::TempDir,
        dials: Arc<Mutex<Vec<SocketAddr>>>,
    }

    #[cfg(unix)]
    impl FakeGuest {
        fn start() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let dial = UnixListener::bind(dir.path().join("dial.sock")).unwrap();
            let dials = Arc::new(Mutex::new(Vec::new()));
            let recorded = dials.clone();
            tokio::spawn(async move {
                while let Ok((mut host, _)) = dial.accept().await {
                    let recorded = recorded.clone();
                    tokio::spawn(async move {
                        let destination = read_destination_line(&mut host).await.unwrap();
                        recorded.lock().unwrap().push(destination);
                        let upstream = TcpStream::connect(destination).await;
                        host.write_all(&[connect_verdict(&upstream)]).await.unwrap();
                        if let Ok(mut upstream) = upstream {
                            let _ = tokio::io::copy_bidirectional(&mut host, &mut upstream).await;
                        }
                    });
                }
            });
            Self { dir, dials }
        }

        fn tunnel(&self) -> GuestTunnel {
            GuestTunnel {
                flows: self.dir.path().join("flows.sock"),
                dial: self.dir.path().join("dial.sock"),
                relay_dir: self.dir.path().to_path_buf(),
            }
        }
    }

    /// Like [`fixture`], with the credential tunnel's host ends served.
    #[cfg(unix)]
    async fn tunnel_fixture() -> (Fixture, FakeGuest) {
        let guest = FakeGuest::start();
        let upstream = start_upstream().await;
        let policy = CredentialPolicy {
            credentials: vec![CredentialBinding {
                name: "svc".into(),
                environment_variable: "SVC_TOKEN".into(),
                allowed_hosts: vec![CRED_HOST.into()],
                injection_location: InjectionLocation::default(),
                methods: DEFAULT_METHODS.iter().map(|m| m.to_string()).collect(),
                set_header: None,
            }],
        };
        let placeholders = crate::policy::generate_placeholders(&policy);
        let placeholder = placeholders.values().next().cloned().unwrap();
        let ca = MachineCa::generate("test-machine", &[CRED_HOST.to_string()]).unwrap();
        let ca_pem = ca.certificate_pem().to_string();
        let interceptor = Interceptor::spawn(
            InterceptorConfig {
                machine: "test-machine".into(),
                policy,
                placeholders,
                ca,
                upstream_roots_pem: vec![upstream.cert_pem.clone()],
                guest_tunnel: Some(guest.tunnel()),
            },
            Arc::new(StaticResolver::new().with("svc", "real-secret")),
        )
        .unwrap();
        let fixture = Fixture {
            upstream,
            interceptor,
            placeholder,
            ca_pem,
        };
        (fixture, guest)
    }

    /// Hand a connection over the tunnel the way the guest agent does, then
    /// speak TLS+HTTP/1.1 as the workload.
    #[cfg(unix)]
    async fn tunnel_request(
        f: &Fixture,
        guest: &FakeGuest,
        trusted_pem: &[u8],
        sni: &str,
        request: &str,
    ) -> std::io::Result<String> {
        let mut stream = UnixStream::connect(guest.tunnel().flows).await?;
        stream
            .write_all(tunnel::destination_line(f.upstream.addr).as_bytes())
            .await?;
        let connector = TlsConnector::from(client_config(trusted_pem));
        let name = ServerName::try_from(sni.to_string()).unwrap();
        let mut tls = connector.connect(name, stream).await?;
        tls.write_all(request.as_bytes()).await?;
        let mut out = Vec::new();
        let _ = tls.read_to_end(&mut out).await;
        Ok(String::from_utf8_lossy(&out).into_owned())
    }

    /// A workload that routes a credential host through a TUN (Tailscale,
    /// WireGuard) still gets the value substituted, and the upstream is dialed
    /// from inside the guest so it takes the workload's route.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn substitutes_through_the_tunnel_and_dials_upstream_from_the_guest() {
        let (f, guest) = tunnel_fixture().await;
        let request = format!(
            "GET /v1/me HTTP/1.1\r\nHost: {CRED_HOST}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
            f.placeholder
        );
        let response = tunnel_request(&f, &guest, f.ca_pem.as_bytes(), CRED_HOST, &request)
            .await
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert_eq!(
            f.upstream.seen.lock().unwrap().clone(),
            vec![("Bearer real-secret".to_string(), "/v1/me".to_string())]
        );
        let dials = guest.dials.lock().unwrap().clone();
        assert!(
            !dials.is_empty(),
            "the upstream was not dialed through the guest"
        );
        assert!(dials.iter().all(|d| *d == f.upstream.addr), "{dials:?}");
        // The per-connection relay socket goes away with the connection.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let leftover: Vec<_> = std::fs::read_dir(guest.dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with("cred-relay-"))
            .collect();
        assert!(leftover.is_empty(), "{leftover:?}");
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn splices_other_hosts_through_the_tunnel_untouched() {
        let (f, guest) = tunnel_fixture().await;
        let request = format!(
            "GET /raw HTTP/1.1\r\nHost: {OTHER_HOST}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
            f.placeholder
        );
        let response = tunnel_request(&f, &guest, &f.upstream.cert_pem, OTHER_HOST, &request)
            .await
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        let seen = f.upstream.seen.lock().unwrap().clone();
        assert_eq!(seen[0].0, format!("Bearer {}", f.placeholder));
        assert_eq!(guest.dials.lock().unwrap().clone(), vec![f.upstream.addr]);
    }

    /// When the guest cannot reach the destination, the flow closes; nothing
    /// is sent from the host instead.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unreachable_tunnel_destination_closes_the_flow() {
        let (f, guest) = tunnel_fixture().await;
        let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let unreachable = closed.local_addr().unwrap();
        drop(closed);
        let mut stream = UnixStream::connect(guest.tunnel().flows).await.unwrap();
        stream
            .write_all(tunnel::destination_line(unreachable).as_bytes())
            .await
            .unwrap();
        let mut out = Vec::new();
        let n = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut out))
            .await
            .expect("the flow was not closed")
            .unwrap_or(0);
        assert_eq!(n, 0);
        assert!(f.upstream.seen.lock().unwrap().is_empty());
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
    async fn oauth_form_body_substitution_is_explicit_scoped_and_encoded() {
        let mut policy = CredentialPolicy {
            credentials: vec![CredentialBinding {
                name: "refresh".into(),
                environment_variable: "REFRESH_TOKEN".into(),
                allowed_hosts: vec![CRED_HOST.into()],
                injection_location: InjectionLocation {
                    body: true,
                    ..InjectionLocation::default()
                },
                methods: vec!["POST".into()],
                set_header: None,
            }],
        };
        let secret = "token+with&separator=1";
        let f = fixture_with_policy(
            policy.clone(),
            CRED_HOST,
            StaticResolver::new().with("refresh", secret),
        )
        .await;
        let body = format!("grant_type=refresh_token&refresh_token={}", f.placeholder);
        let request = format!(
            "POST /token HTTP/1.1\r\nHost: {CRED_HOST}\r\nContent-Type: application/x-www-form-urlencoded; charset=utf-8\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            f.placeholder,
            body.len()
        );
        let response = guest_request(&f, f.ca_pem.as_bytes(), CRED_HOST, &request)
            .await
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert_eq!(
            f.upstream.seen.lock().unwrap()[0].0,
            format!("Bearer {secret}")
        );
        assert_eq!(
            f.upstream.bodies.lock().unwrap()[0],
            format!(
                "grant_type=refresh_token&refresh_token={}",
                form_encode(secret.as_bytes())
            )
        );

        policy.credentials[0].injection_location.body = false;
        let f = fixture_with_policy(
            policy,
            CRED_HOST,
            StaticResolver::new().with("refresh", secret),
        )
        .await;
        let body = format!("refresh_token={}", f.placeholder);
        let request = format!(
            "POST /token HTTP/1.1\r\nHost: {CRED_HOST}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let response = guest_request(&f, f.ca_pem.as_bytes(), CRED_HOST, &request)
            .await
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");
        assert!(f.upstream.seen.lock().unwrap().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn form_body_rejects_wrong_type_method_and_unknown_placeholder() {
        let policy = CredentialPolicy {
            credentials: vec![CredentialBinding {
                name: "refresh".into(),
                environment_variable: "REFRESH_TOKEN".into(),
                allowed_hosts: vec![CRED_HOST.into()],
                injection_location: InjectionLocation {
                    body: true,
                    ..InjectionLocation::default()
                },
                methods: vec!["POST".into()],
                set_header: None,
            }],
        };
        let f = fixture_with_policy(
            policy,
            CRED_HOST,
            StaticResolver::new().with("refresh", "real"),
        )
        .await;
        for (method, content_type, value, expected) in [
            ("POST", "application/json", f.placeholder.as_str(), "415"),
            (
                "GET",
                "application/x-www-form-urlencoded",
                f.placeholder.as_str(),
                "405",
            ),
            (
                "POST",
                "application/x-www-form-urlencoded",
                "SMOL_PLACEHOLDER_FORGED_1",
                "403",
            ),
        ] {
            let body = format!("refresh_token={value}");
            let request = format!(
                "{method} /token HTTP/1.1\r\nHost: {CRED_HOST}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let response = guest_request(&f, f.ca_pem.as_bytes(), CRED_HOST, &request)
                .await
                .unwrap();
            assert!(
                response.starts_with(&format!("HTTP/1.1 {expected}")),
                "{response}"
            );
        }
        assert!(f.upstream.seen.lock().unwrap().is_empty());
    }

    #[test]
    fn form_body_rejects_multiple_placeholders_and_encodes_field_separators() {
        assert!(
            find_body_placeholder(b"token=SMOL_PLACEHOLDER_A_1&other=SMOL_PLACEHOLDER_B_2")
                .is_err()
        );
        assert_eq!(form_encode(b"a+b&c=d\n"), "a%2Bb%26c%3Dd%0A");
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
    async fn websocket_upgrade_requests_get_http_fallback_without_leaking_credentials() {
        let f = fixture().await;
        let request = format!(
            "GET /v1/stream HTTP/1.1\r\nHost: {CRED_HOST}\r\nAuthorization: Bearer {}\r\nConnection: Upgrade, close\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
            f.placeholder
        );
        let response = guest_request(&f, f.ca_pem.as_bytes(), CRED_HOST, &request)
            .await
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 426"), "{response}");
        assert!(
            response
                .to_ascii_lowercase()
                .contains("upgrade: http/1.1\r\n"),
            "{response}"
        );
        assert!(!response.contains(&f.placeholder), "{response}");
        assert!(f.upstream.seen.lock().unwrap().is_empty());

        // The same client can retry over HTTP and still receive substitution.
        let request = format!(
            "GET /v1/stream HTTP/1.1\r\nHost: {CRED_HOST}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
            f.placeholder
        );
        let response = guest_request(&f, f.ca_pem.as_bytes(), CRED_HOST, &request)
            .await
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert_eq!(
            f.upstream.seen.lock().unwrap().as_slice(),
            &[("Bearer real-secret".to_string(), "/v1/stream".to_string())]
        );
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
