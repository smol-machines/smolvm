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
//! Bindings change while the machine runs ([`InterceptorControl`]). A host a
//! binding stops covering stays intercepted, nothing injected, for as long as
//! the interceptor runs, and its responses are still scrubbed of the values
//! sent there; a host a binding starts covering has the connections already
//! spliced to it ended before the change takes effect.
//!
//! Only the placeholder is replaced; the guest supplies `Bearer ` or any other
//! surrounding syntax. A placeholder anywhere other than an ordinary request
//! header is refused so it can never travel upstream unreplaced.
//!
//! Every response from a credential host is scrubbed of the values its
//! bindings carry (see [`crate::scrub`]), so a host that reflects a request's
//! credential cannot hand it to the guest. To keep that check complete,
//! requests ask for an uncompressed whole response: `Accept-Encoding` is set to
//! `identity` and range requests are dropped. A server that compresses anyway
//! has a gzip or deflate body decoded before the check; any other encoding is
//! refused.

use crate::ca::MachineCa;
use crate::policy::{CredentialPolicy, PLACEHOLDER_PREFIX};
use crate::resolver::{CredentialRequest, CredentialResolver, ResolveError};
use crate::scrub::{Scrubber, Secret, MAX_FORM_LEN};
use crate::sni::{peek_client_hello, Peek, MAX_CLIENT_HELLO};
use anyhow::{Context, Result};
use bytes::Bytes;
use futures_util::{Stream, StreamExt, TryStreamExt};
use http_body_util::{combinators::BoxBody, BodyExt, Full, Limited, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::{
    header, server::conn::http1, service::service_fn, Method, Request, Response, StatusCode,
};
use hyper_util::rt::TokioIo;
use smolvm_protocol::intercept::{
    connect_verdict, preamble_len, InterceptEndpoint, HEADER_LEN, TOKEN_LEN,
};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
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
/// Values remembered per binding for scrubbing: a rotated credential's old
/// value may still be stored upstream.
const MAX_REMEMBERED_VALUES: usize = 4;
/// Values kept for scrubbing on hosts their bindings no longer cover, across
/// every host, oldest dropped first. The hosts themselves are never dropped.
const MAX_RETIRED_VALUES: usize = 256;
/// Longest a change of bindings waits for the connections it ends (spliced to
/// a host it intercepts) to be gone before it is refused.
const SPLICE_END_WAIT: Duration = if cfg!(test) {
    Duration::from_millis(500)
} else {
    Duration::from_secs(2)
};
/// Largest compressed body decoded for scrubbing, from a server that ignored
/// `Accept-Encoding: identity`.
const ENCODED_LIMIT: usize = 64 * 1024 * 1024;
/// Largest body such a decode may produce.
const DECODED_LIMIT: u64 = 256 * 1024 * 1024;

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
    /// CAs added after boot for hosts the machine CA does not permit (each name-constrained to its own hosts); empty
    /// for a machine whose bindings never changed.
    pub extra_cas: Vec<MachineCa>,
    /// Extra PEM roots trusted for upstream connections, for private services.
    /// Public roots stay enabled.
    pub upstream_roots_pem: Vec<Vec<u8>>,
}

/// A running interceptor. Dropping it stops the listener and every session.
pub struct Interceptor {
    endpoint: InterceptEndpoint,
    state: Arc<State>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

/// The machine's bindings as they are now, swapped whole by [`Interceptor::update`] so every request reads one
/// consistent set. A request injects with the set it read; its response is checked for what that request carried
/// and for the values bound to its host now.
struct Bindings {
    policy: CredentialPolicy,
    /// placeholder → binding name
    by_placeholder: HashMap<String, String>,
    /// binding name → placeholder
    placeholders: BTreeMap<String, String>,
    /// The machine CA first, then those added for hosts it does not permit; a host's leaf is minted by the first that
    /// permits it.
    cas: Vec<Arc<MachineCa>>,
}

impl Bindings {
    fn new(
        policy: CredentialPolicy,
        placeholders: BTreeMap<String, String>,
        cas: Vec<Arc<MachineCa>>,
    ) -> Self {
        let by_placeholder = placeholders
            .iter()
            .map(|(binding, placeholder)| (placeholder.clone(), binding.clone()))
            .collect();
        Self {
            policy,
            by_placeholder,
            placeholders,
            cas,
        }
    }
}

/// What bindings that stopped covering a host leave there: the host may have stored a value sent to it and may hand
/// it back.
#[derive(Default)]
struct Retired {
    /// Host patterns, as bindings named them, that no binding covers any more. Kept while the interceptor runs: such
    /// a host stays intercepted (nothing injected, old placeholders refused, responses checked) and is never spliced.
    /// Bounded by the distinct host patterns ever bound on the machine.
    hosts: BTreeSet<String>,
    /// `(host pattern, value)` still scrubbed there, newest last, at most [`MAX_RETIRED_VALUES`].
    values: VecDeque<(String, zeroize::Zeroizing<String>)>,
}

impl Retired {
    /// Keep scrubbing `value` on `pattern`'s hosts; whether it is new there.
    fn add(&mut self, pattern: &str, value: &zeroize::Zeroizing<String>) -> bool {
        self.hosts.insert(pattern.to_string());
        if self.values.iter().any(|(p, v)| p == pattern && v == value) {
            return false;
        }
        if self.values.len() == MAX_RETIRED_VALUES {
            self.values.pop_front();
        }
        self.values.push_back((pattern.to_string(), value.clone()));
        true
    }

    fn covers(&self, host: &str) -> bool {
        self.hosts
            .iter()
            .any(|pattern| smolvm_protocol::credentials::host_matches(pattern, host))
    }
}

/// A flow spliced through untouched (no binding covered its host when it opened), which a change of bindings that
/// covers its host ends.
struct Splice {
    /// The server name its ClientHello gave, if any.
    host: Option<String>,
    cancel: tokio::sync::Notify,
    ended: Mutex<bool>,
    ended_signal: Condvar,
}

impl Splice {
    fn has_ended(&self) -> bool {
        *self.ended.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Wait until the flow is gone, at most `limit`; whether it is.
    fn wait_ended(&self, limit: Duration) -> bool {
        let ended = self.ended.lock().unwrap_or_else(|e| e.into_inner());
        let (ended, _) = self
            .ended_signal
            .wait_timeout_while(ended, limit, |ended| !*ended)
            .unwrap_or_else(|e| e.into_inner());
        *ended
    }
}

/// Marks its [`Splice`] ended when the flow's task lets go of it, sockets and all.
struct SpliceGuard(Arc<Splice>);

impl Drop for SpliceGuard {
    fn drop(&mut self) {
        *self.0.ended.lock().unwrap_or_else(|e| e.into_inner()) = true;
        self.0.ended_signal.notify_all();
    }
}

/// A scrubber shared by the responses it covers; `None` when there is nothing to look for.
type SharedScrubber = Option<Arc<Scrubber>>;

/// A value a request carried upstream, and the placeholder the guest knows it by.
struct Carried {
    value: zeroize::Zeroizing<String>,
    placeholder: Option<String>,
}

struct State {
    machine: String,
    bindings: std::sync::RwLock<Arc<Bindings>>,
    /// binding name → values it has resolved to in this process, newest last.
    /// An entry with no values is a binding that could not be resolved.
    resolved: Mutex<HashMap<String, Vec<zeroize::Zeroizing<String>>>>,
    /// What bindings that stopped covering a host left there.
    retired: Mutex<Retired>,
    /// Flows spliced through untouched and maybe still open. Held while a flow chooses between splicing and
    /// intercepting, and while a change of bindings picks the flows it ends.
    spliced: Mutex<Vec<Arc<Splice>>>,
    /// Host patterns a prepared change of bindings will cover: new connections to them wait for it to be committed
    /// or dropped rather than being spliced.
    pending: Mutex<Option<Vec<String>>>,
    /// Wakes connections waiting on a pending change once it is decided.
    pending_changed: tokio::sync::Notify,
    /// Connections waiting on a pending change now.
    held_flows: std::sync::atomic::AtomicUsize,
    /// host → the scrubber for what its bindings and retired values carry, and the epoch it was built at.
    scrubbers: Mutex<HashMap<String, (u64, SharedScrubber)>>,
    /// Run by a commit once the new bindings are visible, before it finishes: a test's gate.
    #[cfg(test)]
    after_swap: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// Grows whenever the values a response may need scrubbing of can have grown (bindings changed, a value
    /// resolved): a response being streamed rebuilds its scrubber when it moves.
    secrets_epoch: AtomicU64,
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
        let cas = std::iter::once(config.ca)
            .chain(config.extra_cas)
            .map(Arc::new)
            .collect();
        let state = Arc::new(State {
            machine: config.machine,
            bindings: std::sync::RwLock::new(Arc::new(Bindings::new(
                config.policy,
                config.placeholders,
                cas,
            ))),
            resolved: Mutex::new(HashMap::new()),
            retired: Mutex::new(Retired::default()),
            spliced: Mutex::new(Vec::new()),
            pending: Mutex::new(None),
            pending_changed: tokio::sync::Notify::new(),
            held_flows: std::sync::atomic::AtomicUsize::new(0),
            scrubbers: Mutex::new(HashMap::new()),
            #[cfg(test)]
            after_swap: Mutex::new(None),
            secrets_epoch: AtomicU64::new(0),
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
        let handle_state = state.clone();
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
            state: handle_state,
            shutdown: Some(shutdown_tx),
            thread: Some(thread),
        })
    }

    /// Where the network backend should redirect flows, and with which token.
    pub fn endpoint(&self) -> InterceptEndpoint {
        self.endpoint
    }

    /// Replace the bindings while the machine runs ([`InterceptorControl::update`]).
    pub fn update(
        &self,
        policy: CredentialPolicy,
        placeholders: BTreeMap<String, String>,
        extra_cas: Vec<MachineCa>,
    ) -> std::result::Result<(), String> {
        self.control().update(policy, placeholders, extra_cas)
    }

    /// A handle that changes this interceptor's bindings, for whoever serves the machine's control socket.
    pub fn control(&self) -> InterceptorControl {
        InterceptorControl {
            state: self.state.clone(),
        }
    }
}

/// Changes a running interceptor's bindings ([`Interceptor::control`]); outliving the interceptor changes nothing.
#[derive(Clone)]
pub struct InterceptorControl {
    state: Arc<State>,
}

impl InterceptorControl {
    /// Replace the bindings while the machine runs: [`Self::prepare`] then [`PreparedBindings::commit`]. Refused,
    /// the interceptor keeping its bindings, when a connection spliced to a host the new bindings cover does not
    /// end in time or another change is prepared.
    pub fn update(
        &self,
        policy: CredentialPolicy,
        placeholders: BTreeMap<String, String>,
        extra_cas: Vec<MachineCa>,
    ) -> std::result::Result<(), String> {
        self.prepare(&policy)?
            .commit(policy, placeholders, extra_cas);
        Ok(())
    }

    /// The first half of a change to `policy`: end every connection spliced through untouched to a host `policy`
    /// covers, and hold new connections to the hosts it covers that are not intercepted already until the change is
    /// committed or dropped, so none is spliced meanwhile (an intercepted host never goes back to being spliced).
    /// Waits, holding no lock, at most [`SPLICE_END_WAIT`]. Refused if a connection has not ended by then, since
    /// bindings never take effect on a host while an unchecked connection to it is open, and while another change
    /// is prepared: the interceptor then keeps its bindings, and the caller decides what that means for whatever it
    /// saved.
    pub fn prepare(
        &self,
        policy: &CredentialPolicy,
    ) -> std::result::Result<PreparedBindings, String> {
        let state = &self.state;
        let hosts: Vec<String> = policy
            .credentials
            .iter()
            .flat_map(|b| b.allowed_hosts.iter().cloned())
            .collect();
        let ending: Vec<Arc<Splice>> = {
            let mut spliced = state.spliced.lock().expect("spliced flows");
            let mut pending = state.pending.lock().expect("pending change");
            if pending.is_some() {
                return Err(
                    "another change of credential bindings is in progress; retry".to_string(),
                );
            }
            let held: Vec<String> = {
                let current = state.bindings();
                let retired = state.retired.lock().expect("retired values");
                hosts
                    .iter()
                    .filter(|pattern| {
                        !retired.hosts.contains(*pattern)
                            && !current
                                .policy
                                .credentials
                                .iter()
                                .any(|b| b.allowed_hosts.contains(pattern))
                    })
                    .cloned()
                    .collect()
            };
            *pending = Some(held);
            drop(pending);
            spliced.retain(|splice| !splice.has_ended());
            spliced
                .iter()
                .filter(|splice| {
                    splice.host.as_deref().is_some_and(|host| {
                        hosts.iter().any(|pattern| {
                            smolvm_protocol::credentials::host_matches(pattern, host)
                        })
                    })
                })
                .cloned()
                .collect()
        };
        // Dropped on refusal, which lets held connections go on as before.
        let prepared = PreparedBindings {
            state: state.clone(),
        };
        for splice in &ending {
            splice.cancel.notify_one();
        }
        let deadline = std::time::Instant::now() + SPLICE_END_WAIT;
        let lingering: Vec<&str> = ending
            .iter()
            .filter(|splice| {
                !splice.wait_ended(deadline.saturating_duration_since(std::time::Instant::now()))
            })
            .filter_map(|splice| splice.host.as_deref())
            .collect();
        if !lingering.is_empty() {
            tracing::warn!(machine = %state.machine, hosts = ?lingering, "connections to hosts the new bindings cover did not end in time; bindings not changed");
            return Err(format!(
                "connections opened before these bindings to hosts they cover ({}) did not close in time; the \
                 running machine keeps its current bindings, retry",
                lingering.join(", ")
            ));
        }
        Ok(prepared)
    }
}

/// A change of bindings whose spliced connections have ended ([`InterceptorControl::prepare`]), applied by
/// [`Self::commit`]. Dropped without that, it changes nothing and lets held connections go on.
pub struct PreparedBindings {
    state: Arc<State>,
}

impl PreparedBindings {
    /// Enforce `policy` from the next request on: a binding added is intercepted and substituted, one removed is
    /// not substituted any more and its values are dropped from what it may inject, while every host it covered
    /// stays intercepted with its responses still checked for those values. `extra_cas` are the CAs added for
    /// hosts the machine CA does not permit, all of them (the machine CA is kept).
    pub fn commit(
        self,
        policy: CredentialPolicy,
        placeholders: BTreeMap<String, String>,
        extra_cas: Vec<MachineCa>,
    ) {
        let state = &self.state;
        {
            let mut current = state.bindings.write().unwrap_or_else(|e| e.into_inner());
            let mut cas: Vec<Arc<MachineCa>> = current.cas.first().cloned().into_iter().collect();
            cas.extend(extra_cas.into_iter().map(Arc::new));
            // Before the swap: a flow that reads the new bindings finds a host they dropped already retired.
            state.retire(&current.policy, &policy);
            *current = Arc::new(Bindings::new(policy, placeholders, cas));
            // Before the new bindings are visible: no request reading them takes a scrubber built for the old ones.
            state.bump_secrets();
        }
        #[cfg(test)]
        if let Some(gate) = state.after_swap.lock().expect("commit gate").take() {
            gate();
        }
        // a host whose CA changed mints its leaf again
        state.leaves.lock().expect("leaf cache").clear();
        // Dropping `self` lets held connections decide under the new bindings.
    }
}

impl Drop for PreparedBindings {
    fn drop(&mut self) {
        *self.state.pending.lock().unwrap_or_else(|e| e.into_inner()) = None;
        self.state.pending_changed.notify_waiters();
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

    let host = match peek {
        Peek::ServerName(host) => Some(host),
        Peek::NoServerName | Peek::Incomplete => None,
    };
    // Chosen under the spliced-flow lock, which a change of bindings takes to pick the flows it ends: a flow
    // spliced here is one that change sees. A host a pending change will cover waits for it.
    let splice = loop {
        let notified = state.pending_changed.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        {
            let mut spliced = state.spliced.lock().expect("spliced flows");
            if !state.pending_covers(host.as_deref()) {
                break match &host {
                    Some(name) if state.intercepts(name) => None,
                    _ => {
                        spliced.retain(|splice| !splice.has_ended());
                        let splice = Arc::new(Splice {
                            host: host.clone(),
                            cancel: tokio::sync::Notify::new(),
                            ended: Mutex::new(false),
                            ended_signal: Condvar::new(),
                        });
                        spliced.push(splice.clone());
                        Some(SpliceGuard(splice))
                    }
                };
            }
        }
        // Decided within the change's own wait; checked again either way.
        state.held_flows.fetch_add(1, Ordering::AcqRel);
        let _ = tokio::time::timeout(SPLICE_END_WAIT * 2, notified).await;
        state.held_flows.fetch_sub(1, Ordering::AcqRel);
    };
    match (splice, host) {
        (None, Some(host)) => {
            // The upstream client opens its own verified connection.
            drop(upstream);
            terminate(state, stream, buffered, host, destination).await
        }
        (guard, _) => {
            let guard = guard.context("only a named host is intercepted")?;
            passthrough(stream, upstream, buffered, guard).await
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

/// Splice a flow through untouched until either side closes, or a change of bindings covering its host ends it.
/// Dropping `guard` with the sockets tells that change the flow is gone.
async fn passthrough(
    mut guest: TcpStream,
    mut upstream: TcpStream,
    buffered: Vec<u8>,
    guard: SpliceGuard,
) -> Result<()> {
    let splice = guard.0.clone();
    let relay = async {
        let _ = upstream.set_nodelay(true);
        upstream.write_all(&buffered).await?;
        let _ = tokio::io::copy_bidirectional(&mut guest, &mut upstream).await;
        Ok::<_, std::io::Error>(())
    };
    tokio::select! {
        relayed = relay => relayed?,
        () = splice.cancel.notified() => {
            tracing::info!(host = ?splice.host, "spliced connection ended: a binding now covers its host");
        }
    }
    drop(guest);
    drop(upstream);
    drop(guard);
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
    /// The bindings now: one consistent set for the caller to read.
    fn bindings(&self) -> Arc<Bindings> {
        self.bindings
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Keep every host a binding of `old` covers and its namesake in `new` does not intercepted, and scrubbed there
    /// of the values that binding resolved to; then forget the values of the bindings `new` drops.
    fn retire(&self, old: &CredentialPolicy, new: &CredentialPolicy) {
        let mut resolved = self.resolved.lock().expect("resolved values");
        let mut retired = self.retired.lock().expect("retired values");
        for binding in &old.credentials {
            let successor = new.binding(&binding.name);
            for host in &binding.allowed_hosts {
                if successor.is_some_and(|b| b.allowed_hosts.contains(host)) {
                    continue;
                }
                // Even with no value seen: one may be on its way there from a request in flight.
                retired.hosts.insert(host.clone());
                for value in resolved.get(&binding.name).into_iter().flatten() {
                    retired.add(host, value);
                }
            }
        }
        resolved.retain(|name, _| new.binding(name).is_some());
    }

    /// Whether a connection to `host` must wait for a pending change of bindings.
    fn pending_covers(&self, host: Option<&str>) -> bool {
        let pending = self.pending.lock().expect("pending change");
        match (pending.as_ref(), host) {
            (Some(hosts), Some(host)) => hosts
                .iter()
                .any(|pattern| smolvm_protocol::credentials::host_matches(pattern, host)),
            _ => false,
        }
    }

    /// Whether flows to `host` are intercepted rather than spliced: a binding covers it, or one did.
    fn intercepts(&self, host: &str) -> bool {
        self.bindings()
            .policy
            .bindings_for_host(host)
            .next()
            .is_some()
            || self.retired.lock().expect("retired values").covers(host)
    }

    fn bump_secrets(&self) {
        self.secrets_epoch.fetch_add(1, Ordering::AcqRel);
    }

    fn secrets_epoch(&self) -> u64 {
        self.secrets_epoch.load(Ordering::Acquire)
    }

    /// Ask the resolver for `binding`'s value for this request, `bindings`
    /// being the set the caller read. The inner `Err` is the reply to send
    /// the guest when it has none.
    async fn resolve(
        &self,
        bindings: &Bindings,
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
            .context("resolver task")?
            // Never sent, so never scrubbed: a longer value could outrun what a streamed response keeps to check.
            .and_then(|value| {
                crate::policy::check_credential_value(binding, &value)
                    .map(|()| value)
                    .map_err(ResolveError::Unavailable)
            });
        self.remember(bindings, binding, resolved.as_ref().ok());
        Ok(resolved.map_err(|e| {
            tracing::warn!(machine = %self.machine, binding, host, error = %e, "credential resolution failed");
            text(
                StatusCode::BAD_GATEWAY,
                "smolvm credentials: credential unavailable",
            )
        }))
    }

    /// Note what `binding` of `bindings` resolved to, or that it did not resolve. The bindings may have changed
    /// since the caller read them: the value is kept for the binding if it is still in force, and left with every
    /// host the binding covered and covers no more, so responses from there are still checked for it.
    fn remember(
        &self,
        bindings: &Bindings,
        binding: &str,
        value: Option<&zeroize::Zeroizing<String>>,
    ) {
        let current = self.bindings.read().unwrap_or_else(|e| e.into_inner());
        let successor = current.policy.binding(binding);
        let mut resolved = self.resolved.lock().expect("resolved values");
        let mut retired = self.retired.lock().expect("retired values");
        let mut grew = false;
        if successor.is_some() {
            let values = resolved.entry(binding.to_string()).or_default();
            if let Some(value) = value {
                if !values.iter().any(|known| known == value) {
                    if values.len() == MAX_REMEMBERED_VALUES {
                        values.remove(0);
                    }
                    values.push(value.clone());
                    grew = true;
                }
            }
        }
        if let (Some(value), Some(read)) = (value, bindings.policy.binding(binding)) {
            for host in &read.allowed_hosts {
                if !successor.is_some_and(|b| b.allowed_hosts.contains(host)) {
                    grew |= retired.add(host, value);
                }
            }
        }
        // Under the locks, so the epoch moves before the value is visible.
        if grew {
            self.bump_secrets();
        }
    }

    /// A scrubber for every value the bindings covering `host` may carry,
    /// resolving the ones this process has not seen yet. A guest that stored a
    /// value with one request could read it back with another that injects
    /// nothing, so every response from the host is checked. Also covered: the
    /// values the request being answered `carried`, whatever the bindings are
    /// now, and those left with the host by bindings that stopped covering it.
    /// The host's scrubber is built once per change of what it must find and
    /// shared by the requests it covers.
    async fn scrubber_for(
        &self,
        host: &str,
        destination: SocketAddr,
        method: &str,
        path: &str,
        carried: &[Carried],
    ) -> Result<Option<Arc<Scrubber>>> {
        let live = self.bindings();
        let unseen: Vec<String> = {
            let resolved = self.resolved.lock().expect("resolved values");
            live.policy
                .bindings_for_host(host)
                .filter(|b| !resolved.contains_key(&b.name))
                .map(|b| b.name.clone())
                .collect()
        };
        for binding in unseen {
            // Recorded either way by `resolve`; a failure only means there is
            // nothing of this binding's to look for.
            let _ = self
                .resolve(&live, &binding, host, destination, method, path)
                .await?;
        }
        // Read before what it tags: an entry is never older than its epoch.
        let epoch = self.secrets_epoch();
        let cached = self
            .scrubbers
            .lock()
            .expect("scrubber cache")
            .get(host)
            .filter(|(built, _)| *built == epoch)
            .map(|(_, scrubber)| scrubber.clone());
        let shared = match cached {
            Some(shared) => shared,
            None => {
                let mut secrets = self.host_secrets(host);
                let shared = build_scrubber(&secrets)?;
                secrets.clear();
                let mut cache = self.scrubbers.lock().expect("scrubber cache");
                if cache.len() >= MAX_CACHED_CLIENTS {
                    cache.clear();
                }
                cache.insert(host.to_string(), (epoch, shared.clone()));
                shared
            }
        };
        let covered = |value: &[u8]| shared.as_ref().is_some_and(|s| s.covers(value));
        if carried.iter().all(|c| covered(c.value.as_bytes())) {
            return Ok(shared);
        }
        // A value the request carried that the host's scrubber does not know (dropped since, or never kept).
        let mut secrets = self.host_secrets(host);
        secrets.extend(
            carried
                .iter()
                .map(|c| (c.value.clone(), c.placeholder.clone())),
        );
        build_scrubber(&secrets)
    }

    /// Every value a response from `host` is checked for, whatever request it answers, with the placeholder the
    /// guest knows it by: the current bindings' first, then those left by bindings that stopped covering it.
    fn host_secrets(&self, host: &str) -> Vec<(zeroize::Zeroizing<String>, Option<String>)> {
        let live = self.bindings();
        let resolved = self.resolved.lock().expect("resolved values");
        let retired = self.retired.lock().expect("retired values");
        let mut secrets: Vec<(zeroize::Zeroizing<String>, Option<String>)> = live
            .policy
            .bindings_for_host(host)
            .flat_map(|b| {
                // A header-setting binding's guest never holds a placeholder.
                let placeholder = b
                    .set_header
                    .is_none()
                    .then(|| live.placeholders.get(&b.name).cloned())
                    .flatten();
                resolved
                    .get(&b.name)
                    .into_iter()
                    .flatten()
                    .map(move |value| (value.clone(), placeholder.clone()))
            })
            .collect();
        // A value left by a binding that no longer covers the host has no placeholder the guest may still use.
        secrets.extend(
            retired
                .values
                .iter()
                .filter(|(pattern, _)| smolvm_protocol::credentials::host_matches(pattern, host))
                .map(|(_, value)| (value.clone(), None)),
        );
        secrets
    }

    fn leaf_config(&self, host: &str) -> Result<Arc<rustls::ServerConfig>> {
        if let Some(config) = self.leaves.lock().expect("leaf cache").get(host) {
            return Ok(config.clone());
        }
        let live = self.bindings();
        let ca = live
            .cas
            .iter()
            .find(|ca| ca.permits(host))
            .or(live.cas.first())
            .context("no machine CA")?;
        let (chain, key) = ca.issue_leaf(host)?;
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
        // A host the URL parser rewrites (`127.0.0.0x1` is 127.0.0.1) would
        // be dialled directly, skipping the pin to the admitted destination.
        let url = reqwest::Url::parse(&format!("https://{host}/")).context("upstream host")?;
        anyhow::ensure!(
            url.domain()
                .is_some_and(|name| name.eq_ignore_ascii_case(host)),
            "upstream host is not a DNS name"
        );
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
        self: &Arc<Self>,
        host: &str,
        destination: SocketAddr,
        request: Request<Incoming>,
    ) -> Result<Reply> {
        let live = self.bindings();
        // Values this request sends upstream: its response is checked for them whatever the bindings become.
        let mut carried: Vec<Carried> = Vec::new();
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
            let Some(binding_name) = live.by_placeholder.get(placeholder) else {
                return Ok(text(
                    StatusCode::FORBIDDEN,
                    "smolvm credentials: unknown placeholder",
                ));
            };
            let binding = live
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
                    &live,
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
            carried.push(Carried {
                value: secret,
                placeholder: Some(placeholder.clone()),
            });
        }

        // Header-setting bindings: the host supplies the whole value and it
        // replaces whatever the guest sent, placeholder or not.
        for binding in live.policy.header_bindings(host, parts.method.as_str()) {
            let header_name = binding
                .set_header
                .as_deref()
                .context("header binding without a header")?;
            let secret = match self
                .resolve(
                    &live,
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
            carried.push(Carried {
                value: secret,
                placeholder: None,
            });
        }

        strip_hop_headers(&mut headers);
        headers.remove(header::HOST);
        headers.remove(header::CONTENT_LENGTH);
        // The response is checked for credential values, which needs it whole
        // and readable: a partial range could carry a value in pieces too
        // short to match, and a compressed body hides it.
        headers.insert(
            header::ACCEPT_ENCODING,
            header::HeaderValue::from_static("identity"),
        );
        headers.remove(header::RANGE);
        headers.remove(header::IF_RANGE);
        let method = parts.method.clone();

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
        // Read before the scrubber is built: a value bound or resolved from here on moves the epoch, and the body
        // is checked for it too. Even a host with nothing to scrub yet is checked as its body arrives.
        let epoch = self.secrets_epoch();
        let scrubber = self
            .scrubber_for(host, destination, method.as_str(), &target, &carried)
            .await?;
        let has_body = method != Method::HEAD
            && status != StatusCode::NO_CONTENT
            && status != StatusCode::NOT_MODIFIED;
        let encodings: Vec<String> = response_headers
            .get_all(header::CONTENT_ENCODING)
            .iter()
            .flat_map(|v| v.to_str().unwrap_or("unreadable").split(','))
            .map(|e| e.trim().to_ascii_lowercase())
            .filter(|e| !e.is_empty() && e != "identity")
            .collect();
        let decode = match encodings.as_slice() {
            _ if !has_body => None,
            [] => None,
            [one] if matches!(one.as_str(), "gzip" | "x-gzip" | "deflate") => Some(one.clone()),
            _ => {
                tracing::warn!(machine = %self.machine, host, encodings = ?encodings, "credential host sent an encoding that cannot be checked; refused");
                return Ok(text(
                    StatusCode::BAD_GATEWAY,
                    "smolvm credentials: the response was compressed and could not be checked for credentials",
                ));
            }
        };
        let mut header_hits = 0;
        for value in response_headers.values_mut() {
            let Some(scrubber) = &scrubber else { break };
            if let Some(clean) = scrubber.scrub(value.as_bytes()) {
                header_hits += 1;
                *value = header::HeaderValue::from_bytes(&clean)
                    .unwrap_or_else(|_| header::HeaderValue::from_static("[smolvm-redacted]"));
            }
        }
        if header_hits > 0 {
            tracing::warn!(machine = %self.machine, host, count = header_hits, "credential value removed from response headers");
        }
        let body: BoxBody<Bytes, BoxError> = if let Some(encoding) = decode {
            // The server compressed despite being asked not to: decode the
            // whole body, scrub it, and send it uncompressed.
            let compressed = match Limited::new(
                StreamBody::new(upstream.bytes_stream().map_ok(Frame::data)),
                ENCODED_LIMIT,
            )
            .collect()
            .await
            {
                Ok(collected) => collected.to_bytes(),
                Err(_) => {
                    return Ok(text(
                        StatusCode::BAD_GATEWAY,
                        "smolvm credentials: the compressed response was too large to check for credentials",
                    ))
                }
            };
            let Ok(Ok(plain)) =
                tokio::task::spawn_blocking(move || decode_body(&encoding, &compressed)).await
            else {
                return Ok(text(
                    StatusCode::BAD_GATEWAY,
                    "smolvm credentials: the compressed response could not be decoded to check it for credentials",
                ));
            };
            // Values bound while the body was collected count too.
            let scrubber = if self.secrets_epoch() != epoch {
                self.scrubber_for(host, destination, method.as_str(), &target, &carried)
                    .await?
            } else {
                scrubber
            };
            let (clean, hits) = match &scrubber {
                Some(scrubber) => {
                    let mut clean = Vec::with_capacity(plain.len());
                    let (_, hits) = scrubber.scan(&plain, true, &mut clean);
                    (clean, hits)
                }
                None => (plain, 0),
            };
            if hits > 0 {
                tracing::warn!(machine = %self.machine, host, count = hits, "credential value removed from a response body");
            }
            response_headers.remove(header::CONTENT_ENCODING);
            response_headers.insert(
                header::CONTENT_LENGTH,
                header::HeaderValue::from(clean.len()),
            );
            BodyExt::boxed(
                Full::new(Bytes::from(clean))
                    .map_err(|never: std::convert::Infallible| match never {}),
            )
        } else if has_body {
            // Scrubbing changes the length, so the body goes out chunked.
            response_headers.remove(header::CONTENT_LENGTH);
            BodyExt::boxed(StreamBody::new(
                scrubbed(
                    upstream.bytes_stream(),
                    scrubber,
                    Rescrub {
                        state: self.clone(),
                        epoch,
                        host: host.to_string(),
                        destination,
                        method: method.to_string(),
                        path: target,
                        carried,
                    },
                )
                .map_ok(Frame::data),
            ))
        } else {
            BodyExt::boxed(
                Full::new(Bytes::new()).map_err(|never: std::convert::Infallible| match never {}),
            )
        };
        let mut reply = Response::new(body);
        *reply.status_mut() = status;
        *reply.headers_mut() = response_headers;
        Ok(reply)
    }
}

use smolvm_protocol::credentials::PROTECTED_HEADERS;

/// Decode a gzip or deflate body, refusing one that would grow past
/// [`DECODED_LIMIT`]. `deflate` is zlib-wrapped per the HTTP spec, but some
/// servers send it raw, so both are accepted.
fn decode_body(encoding: &str, compressed: &[u8]) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let read = |reader: &mut dyn Read| {
        let mut out = Vec::new();
        reader.take(DECODED_LIMIT + 1).read_to_end(&mut out)?;
        if out.len() as u64 > DECODED_LIMIT {
            return Err(std::io::Error::other("decoded body exceeds the limit"));
        }
        Ok(out)
    };
    match encoding {
        "deflate" => read(&mut flate2::read::ZlibDecoder::new(compressed))
            .or_else(|_| read(&mut flate2::read::DeflateDecoder::new(compressed))),
        _ => read(&mut flate2::read::GzDecoder::new(compressed)),
    }
}

/// A scrubber for `secrets` (value, placeholder), built outside every lock. An error fails the response it was for.
fn build_scrubber(
    secrets: &[(zeroize::Zeroizing<String>, Option<String>)],
) -> Result<SharedScrubber> {
    let secrets: Vec<Secret<'_>> = secrets
        .iter()
        .map(|(value, placeholder)| Secret {
            value: value.as_bytes(),
            placeholder: placeholder.as_deref(),
        })
        .collect();
    Ok(Scrubber::new(&secrets)
        .context("build the credential scrubber")?
        .map(Arc::new))
}

/// What a streamed response needs to rebuild its scrubber when the values it must be checked for grow while it
/// streams (a long poll, an event stream): the request it answers, and the epoch its scrubber was built at.
struct Rescrub {
    state: Arc<State>,
    epoch: u64,
    host: String,
    destination: SocketAddr,
    method: String,
    path: String,
    carried: Vec<Carried>,
}

/// `body` with every credential form `scrubber` knows replaced. Holds back the
/// tail of each chunk that could start a form the next chunk finishes. Before
/// each chunk is passed on, a scrubber built before a value was bound or
/// resolved is built again, so a value bound mid-response is scrubbed from the
/// rest of it, even one that began in bytes already passed on before it was
/// bound (see [`Scrubber::scan_after`]): the last input bytes passed on are kept
/// for that, as many as the longest form a value may take.
fn scrubbed<S>(
    body: S,
    scrubber: Option<Arc<Scrubber>>,
    rescrub: Rescrub,
) -> impl Stream<Item = std::result::Result<Bytes, BoxError>> + Send
where
    S: Stream<Item = reqwest::Result<Bytes>> + Send + Unpin + 'static,
{
    /// Input bytes passed on that are kept: a form begun in them can still be finished.
    const KEPT: usize = MAX_FORM_LEN - 1;
    /// Capacity a buffer keeps between chunks; a larger one is let go once drained.
    const SPARE: usize = 64 * 1024;
    struct Scan<S> {
        body: S,
        scrubber: Option<Arc<Scrubber>>,
        rescrub: Rescrub,
        carry: Vec<u8>,
        /// The last input bytes passed on, at most [`KEPT`] once trimmed.
        sent: Vec<u8>,
        hits: usize,
        done: bool,
    }
    impl<S> Scan<S> {
        /// Rebuild the scrubber if the values to look for may have grown.
        async fn refresh(&mut self) -> Result<()> {
            let now = self.rescrub.state.secrets_epoch();
            if now == self.rescrub.epoch {
                return Ok(());
            }
            let r = &self.rescrub;
            self.scrubber = r
                .state
                .scrubber_for(&r.host, r.destination, &r.method, &r.path, &r.carried)
                .await?;
            self.rescrub.epoch = now;
            Ok(())
        }

        /// What of the carried bytes may be passed on now, scrubbed by a scrubber that knows every value bound
        /// so far: rebuilt and scanned again if one was bound while scanning.
        async fn take(&mut self, last: bool) -> Result<Vec<u8>> {
            loop {
                self.refresh().await?;
                let mut out = Vec::with_capacity(self.carry.len());
                let (used, hits) = match &self.scrubber {
                    Some(scrubber) => scrubber.scan_after(&self.sent, &self.carry, last, &mut out),
                    None => {
                        out.extend_from_slice(&self.carry);
                        (self.carry.len(), 0)
                    }
                };
                if self.rescrub.state.secrets_epoch() != self.rescrub.epoch {
                    continue;
                }
                self.hits += hits;
                // Only the newest `KEPT` bytes passed on can still begin a form; trimmed in batches.
                let newest = &self.carry[used - used.min(KEPT)..used];
                if self.sent.len() + newest.len() > 2 * KEPT {
                    let keep = KEPT - newest.len();
                    self.sent
                        .drain(..self.sent.len() - self.sent.len().min(keep));
                }
                self.sent.extend_from_slice(newest);
                self.carry.drain(..used);
                if self.carry.capacity() > SPARE.max(2 * self.carry.len()) {
                    self.carry.shrink_to(SPARE.max(self.carry.len()));
                }
                return Ok(out);
            }
        }
    }
    futures_util::stream::unfold(
        Scan {
            body,
            scrubber,
            rescrub,
            carry: Vec::new(),
            sent: Vec::new(),
            hits: 0,
            done: false,
        },
        move |mut scan| async move {
            if scan.done {
                return None;
            }
            loop {
                let last = match scan.body.next().await {
                    Some(Ok(chunk)) => {
                        scan.carry.extend_from_slice(&chunk);
                        false
                    }
                    Some(Err(e)) => {
                        scan.done = true;
                        return Some((Err(Box::new(e) as BoxError), scan));
                    }
                    None => true,
                };
                let out = match scan.take(last).await {
                    Ok(out) => out,
                    Err(e) => {
                        scan.done = true;
                        return Some((Err(e.into()), scan));
                    }
                };
                if last {
                    scan.done = true;
                    scan.carry.clear();
                    if scan.hits > 0 {
                        tracing::warn!(machine = %scan.rescrub.state.machine, host = %scan.rescrub.host, count = scan.hits, "credential value removed from a response body");
                    }
                    if out.is_empty() {
                        return None;
                    }
                    return Some((Ok(Bytes::from(out)), scan));
                }
                if !out.is_empty() {
                    return Some((Ok(Bytes::from(out)), scan));
                }
            }
        },
    )
}

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
        held: Arc<Held>,
    }

    /// What the upstream keeps between requests, and the gate a held response waits at.
    #[derive(Default)]
    struct Held {
        /// The Authorization value `/store` saved, which `/read` hands back.
        stored: Mutex<String>,
        /// Signalled when a held response reaches its gate.
        arrived: tokio::sync::Notify,
        /// Released by the test to let a held response finish.
        gate: tokio::sync::Notify,
    }

    /// Bytes `/stream-read` sends before its gate: more than any scrubber holds back, so the guest sees them while
    /// the rest waits.
    const STREAM_LEAD: usize = 4096;

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
        let held = Arc::new(Held::default());
        let shared = held.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                let recorded = recorded.clone();
                let recorded_bodies = recorded_bodies.clone();
                let shared = shared.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let service = service_fn(move |request: Request<Incoming>| {
                        let recorded = recorded.clone();
                        let recorded_bodies = recorded_bodies.clone();
                        let held = shared.clone();
                        async move {
                            let get = |name: header::HeaderName| {
                                request
                                    .headers()
                                    .get(name)
                                    .and_then(|v| v.to_str().ok())
                                    .unwrap_or("")
                                    .to_string()
                            };
                            let auth = get(header::AUTHORIZATION);
                            let (encoding, range) =
                                (get(header::ACCEPT_ENCODING), get(header::RANGE));
                            let path = request.uri().path().to_string();
                            let body = request.into_body().collect().await.unwrap().to_bytes();
                            recorded_bodies
                                .lock()
                                .unwrap()
                                .push(String::from_utf8_lossy(&body).into_owned());
                            recorded.lock().unwrap().push((auth.clone(), path.clone()));
                            Ok::<_, std::convert::Infallible>(match path.as_str() {
                                // An httpbin-style echo, in the body and a header.
                                "/echo" => {
                                    let mut reply = text(StatusCode::OK, "");
                                    *reply.body_mut() = Full::new(Bytes::from(format!(
                                        "{{\"headers\":{{\"Authorization\":\"{auth}\",\"Accept-Encoding\":\"{encoding}\",\"Range\":\"{range}\"}}}}"
                                    )))
                                    .map_err(|never| match never {})
                                    .boxed();
                                    reply.headers_mut().insert(
                                        "x-echo",
                                        header::HeaderValue::from_str(&auth).unwrap(),
                                    );
                                    reply
                                }
                                "/echo-b64" => {
                                    use base64::Engine;
                                    let mut reply = text(StatusCode::OK, "");
                                    *reply.body_mut() = Full::new(Bytes::from(
                                        base64::engine::general_purpose::STANDARD
                                            .encode(format!("Authorization: {auth}; seen")),
                                    ))
                                    .map_err(|never| match never {})
                                    .boxed();
                                    reply
                                }
                                // A server that compresses whatever it is asked.
                                "/gzip" => {
                                    use std::io::Write;
                                    let mut gz = flate2::write::GzEncoder::new(
                                        Vec::new(),
                                        flate2::Compression::default(),
                                    );
                                    gz.write_all(format!("echo {auth}").as_bytes()).unwrap();
                                    let mut reply = text(StatusCode::OK, "");
                                    *reply.body_mut() =
                                        Full::new(Bytes::from(gz.finish().unwrap()))
                                            .map_err(|never| match never {})
                                            .boxed();
                                    reply.headers_mut().insert(
                                        header::CONTENT_ENCODING,
                                        header::HeaderValue::from_static("gzip"),
                                    );
                                    reply
                                }
                                "/brotli" => {
                                    let mut reply = text(StatusCode::OK, "pretend-brotli");
                                    reply.headers_mut().insert(
                                        header::CONTENT_ENCODING,
                                        header::HeaderValue::from_static("br"),
                                    );
                                    reply
                                }
                                // A service that keeps what it is sent and hands it back later.
                                "/store" => {
                                    *held.stored.lock().unwrap() = auth.clone();
                                    text(StatusCode::OK, "stored")
                                }
                                "/read" => {
                                    let mut reply = text(StatusCode::OK, "");
                                    let stored = held.stored.lock().unwrap().clone();
                                    *reply.body_mut() =
                                        Full::new(Bytes::from(format!("read {stored}")))
                                            .map_err(|never| match never {})
                                            .boxed();
                                    reply
                                }
                                // An echo that waits at the gate before answering.
                                "/gate-echo" => {
                                    held.arrived.notify_one();
                                    held.gate.notified().await;
                                    let mut reply = text(StatusCode::OK, "");
                                    *reply.body_mut() =
                                        Full::new(Bytes::from(format!("echo {auth}")))
                                            .map_err(|never| match never {})
                                            .boxed();
                                    reply
                                }
                                // A response that streams a lead, waits at the gate, then sends what is stored.
                                "/stream-read" => {
                                    let held = held.clone();
                                    let chunks = futures_util::stream::unfold(0u8, move |step| {
                                        let held = held.clone();
                                        async move {
                                            match step {
                                                0 => {
                                                    Some((Bytes::from(vec![b'.'; STREAM_LEAD]), 1))
                                                }
                                                1 => {
                                                    held.arrived.notify_one();
                                                    held.gate.notified().await;
                                                    let stored =
                                                        held.stored.lock().unwrap().clone();
                                                    Some((
                                                        Bytes::from(format!("stored {stored} end")),
                                                        2,
                                                    ))
                                                }
                                                _ => None,
                                            }
                                        }
                                    });
                                    let mut reply = text(StatusCode::OK, "");
                                    *reply.body_mut() = BodyExt::boxed(StreamBody::new(
                                        chunks.map(|chunk| Ok::<_, BoxError>(Frame::data(chunk))),
                                    ));
                                    reply
                                }
                                // `/stream-read` with what is stored split around the gate: its first half before.
                                "/stream-split" => {
                                    let held = held.clone();
                                    let stored = held.stored.lock().unwrap().clone();
                                    let (head, tail) = stored.split_at(stored.len() / 2);
                                    let (head, tail) = (head.to_string(), tail.to_string());
                                    let chunks = futures_util::stream::unfold(0u8, move |step| {
                                        let held = held.clone();
                                        let (head, tail) = (head.clone(), tail.clone());
                                        async move {
                                            match step {
                                                0 => {
                                                    let mut lead = vec![b'.'; STREAM_LEAD];
                                                    lead.extend_from_slice(head.as_bytes());
                                                    Some((Bytes::from(lead), 1))
                                                }
                                                1 => {
                                                    held.arrived.notify_one();
                                                    held.gate.notified().await;
                                                    Some((Bytes::from(format!("{tail} end")), 2))
                                                }
                                                _ => None,
                                            }
                                        }
                                    });
                                    let mut reply = text(StatusCode::OK, "");
                                    *reply.body_mut() = BodyExt::boxed(StreamBody::new(
                                        chunks.map(|chunk| Ok::<_, BoxError>(Frame::data(chunk))),
                                    ));
                                    reply
                                }
                                _ => text(StatusCode::OK, "upstream ok"),
                            })
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
            held,
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
                extra_cas: Vec::new(),
                upstream_roots_pem: vec![upstream.cert_pem.clone()],
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
        let mut tls = open_guest(f, trusted_pem, sni).await?;
        tls.write_all(request.as_bytes()).await?;
        let mut out = Vec::new();
        let _ = tls.read_to_end(&mut out).await;
        Ok(String::from_utf8_lossy(&out).into_owned())
    }

    type GuestTls = tokio_rustls::client::TlsStream<TcpStream>;

    /// A guest TLS connection through the interceptor, kept open for several requests.
    async fn open_guest(f: &Fixture, trusted_pem: &[u8], sni: &str) -> std::io::Result<GuestTls> {
        let mut tcp = TcpStream::connect(f.interceptor.endpoint().addr).await?;
        tcp.write_all(&f.interceptor.endpoint().preamble(f.upstream.addr))
            .await?;
        let mut verdict = [0xffu8; 1];
        tcp.read_exact(&mut verdict).await?;
        assert_eq!(verdict[0], 0, "interceptor could not reach the upstream");
        let connector = TlsConnector::from(client_config(trusted_pem));
        let name = ServerName::try_from(sni.to_string()).unwrap();
        connector.connect(name, tcp).await
    }

    /// Send `request` on an open connection and read one response off it, with its body as sent (chunked or not);
    /// whatever arrived if the connection fails or closes first.
    async fn exchange(tls: &mut GuestTls, request: &str) -> String {
        if tls.write_all(request.as_bytes()).await.is_err() {
            return String::new();
        }
        let mut out = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let text = String::from_utf8_lossy(&out).into_owned();
            if let Some((head, body)) = text.split_once("\r\n\r\n") {
                let head = head.to_ascii_lowercase();
                let length = head
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .and_then(|n| n.trim().parse::<usize>().ok());
                let complete = match length {
                    Some(length) => body.len() >= length,
                    None => body.ends_with("0\r\n\r\n"),
                };
                if complete {
                    return text;
                }
            }
            match tls.read(&mut chunk).await {
                Ok(0) | Err(_) => return text,
                Ok(n) => out.extend_from_slice(&chunk[..n]),
            }
        }
    }

    /// Change the fixture's bindings while it runs.
    fn rebind(
        f: &Fixture,
        policy: CredentialPolicy,
        placeholders: BTreeMap<String, String>,
        extra_cas: Vec<MachineCa>,
    ) {
        f.interceptor
            .update(policy, placeholders, extra_cas)
            .expect("bindings change");
    }

    fn bound(name: &str, host: &str) -> CredentialBinding {
        CredentialBinding {
            name: name.into(),
            environment_variable: format!("{}_TOKEN", name.to_ascii_uppercase()),
            allowed_hosts: vec![host.into()],
            injection_location: InjectionLocation::default(),
            methods: DEFAULT_METHODS.iter().map(|m| m.to_string()).collect(),
            set_header: None,
        }
    }

    /// Wait, at most ten seconds, until `ready` holds.
    async fn wait_until(ready: impl Fn() -> bool) {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !ready() {
            assert!(std::time::Instant::now() < deadline, "condition never held");
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    /// A spliced connection that never ends: what a change of bindings covering its host must wait for.
    fn stuck_splice(f: &Fixture, host: &str) -> Arc<Splice> {
        let splice = Arc::new(Splice {
            host: Some(host.to_string()),
            cancel: tokio::sync::Notify::new(),
            ended: Mutex::new(false),
            ended_signal: Condvar::new(),
        });
        f.interceptor
            .state
            .spliced
            .lock()
            .unwrap()
            .push(splice.clone());
        splice
    }

    /// A change whose spliced connection does not end in time is refused: the pending change is cleared, and a
    /// connection held for it meanwhile goes on under the old bindings (spliced to the real server).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_change_whose_spliced_connection_lingers_is_refused_and_releases_held_ones() {
        let f = fixture().await;
        let _stuck = stuck_splice(&f, OTHER_HOST);
        let grown = CredentialPolicy {
            credentials: vec![bound("svc", CRED_HOST), bound("other", OTHER_HOST)],
        };
        let placeholders = crate::policy::generate_placeholders(&grown);
        let control = f.interceptor.control();
        let change =
            tokio::task::spawn_blocking(move || control.update(grown, placeholders, Vec::new()));
        let state = f.interceptor.state.clone();
        wait_until(|| state.pending.lock().unwrap().is_some()).await;
        // opened while the change is pending, so held until it is decided
        let request =
            format!("GET /raw HTTP/1.1\r\nHost: {OTHER_HOST}\r\nConnection: close\r\n\r\n");
        let (response, refused) = tokio::join!(
            guest_request(&f, &f.upstream.cert_pem, OTHER_HOST, &request),
            async {
                wait_until(|| state.held_flows.load(Ordering::Acquire) == 1).await;
                change.await.unwrap()
            }
        );
        let why = refused.unwrap_err();
        assert!(why.contains(OTHER_HOST), "{why}");
        assert!(state.pending.lock().unwrap().is_none());
        assert_eq!(state.held_flows.load(Ordering::Acquire), 0);
        // spliced under the old bindings: the guest trusted only the real server, and nothing was substituted
        let response = response.unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(state.bindings().policy.binding("other").is_none());
        assert_eq!(
            f.upstream.seen.lock().unwrap().clone(),
            vec![(String::new(), "/raw".to_string())]
        );
    }

    /// A connection to a host a prepared change covers is held until the change is committed, then handled under
    /// the committed bindings; only one change is prepared at a time.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_connection_held_for_a_pending_change_is_handled_under_the_committed_bindings() {
        let policy = CredentialPolicy {
            credentials: vec![bound("svc", CRED_HOST)],
        };
        let resolver = StaticResolver::new()
            .with("svc", "real-secret")
            .with("other", "other-secret");
        let f = fixture_with_policy(policy, CRED_HOST, resolver).await;
        let grown = CredentialPolicy {
            credentials: vec![bound("svc", CRED_HOST), bound("other", OTHER_HOST)],
        };
        let mut placeholders = crate::policy::generate_placeholders(&grown);
        placeholders.insert("svc".into(), f.placeholder.clone());
        let other = placeholders["other"].clone();
        let extra = MachineCa::generate("test-machine", &[OTHER_HOST.to_string()]).unwrap();
        let trusted = format!("{}{}", f.ca_pem, extra.certificate_pem());
        let control = f.interceptor.control();
        let prepared = control.prepare(&grown).unwrap();
        assert!(
            control
                .prepare(&grown)
                .err()
                .is_some_and(|why| why.contains("in progress")),
            "a second change while one is pending"
        );
        let state = f.interceptor.state.clone();

        // a host the machine already intercepts is not held while the change is pending
        let kept = format!(
            "GET /v1/me HTTP/1.1\r\nHost: {CRED_HOST}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
            f.placeholder
        );
        let response = tokio::time::timeout(
            Duration::from_secs(5),
            guest_request(&f, f.ca_pem.as_bytes(), CRED_HOST, &kept),
        )
        .await
        .expect("an intercepted host was held for the change")
        .unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");

        let request = format!(
            "GET /v1/me HTTP/1.1\r\nHost: {OTHER_HOST}\r\nAuthorization: Bearer {other}\r\nConnection: close\r\n\r\n"
        );
        let (response, ()) = tokio::join!(
            guest_request(&f, trusted.as_bytes(), OTHER_HOST, &request),
            async {
                wait_until(|| state.held_flows.load(Ordering::Acquire) == 1).await;
                prepared.commit(grown, placeholders, vec![extra]);
            }
        );
        let response = response.unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(state.pending.lock().unwrap().is_none());
        assert!(f
            .upstream
            .seen
            .lock()
            .unwrap()
            .contains(&("Bearer other-secret".to_string(), "/v1/me".to_string())));
    }

    /// A value sent to a host whose binding is then removed stays scrubbed there: the host is kept intercepted, so
    /// a guest that trusts the real server too cannot be spliced through to read the stored value back.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_removed_bindings_host_stays_intercepted_and_scrubbed() {
        let f = fixture_with_secret("ghp_retiredsecret4321").await;
        let store = format!(
            "GET /store HTTP/1.1\r\nHost: {CRED_HOST}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
            f.placeholder
        );
        let response = guest_request(&f, f.ca_pem.as_bytes(), CRED_HOST, &store)
            .await
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");

        rebind(&f, CredentialPolicy::default(), BTreeMap::new(), Vec::new());
        let trusted = format!(
            "{}{}",
            f.ca_pem,
            String::from_utf8_lossy(&f.upstream.cert_pem)
        );
        let read = format!("GET /read HTTP/1.1\r\nHost: {CRED_HOST}\r\nConnection: close\r\n\r\n");
        let response = guest_request(&f, trusted.as_bytes(), CRED_HOST, &read)
            .await
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(
            !response_body(&response).contains("ghp_retiredsecret4321"),
            "{response}"
        );
        assert!(response.contains("[smolvm-redacted]"), "{response}");
        // nothing is injected there any more: the old placeholder is refused
        let reuse = format!(
            "GET /echo HTTP/1.1\r\nHost: {CRED_HOST}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
            f.placeholder
        );
        let response = guest_request(&f, trusted.as_bytes(), CRED_HOST, &reuse)
            .await
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");
    }

    #[test]
    fn retired_values_are_bounded_and_their_hosts_kept() {
        let mut retired = Retired::default();
        for i in 0..MAX_RETIRED_VALUES + 10 {
            let host = format!("h{}.credential.test", i % 3);
            assert!(retired.add(&host, &zeroize::Zeroizing::new(format!("value-{i:04}"))));
        }
        let newest = MAX_RETIRED_VALUES + 9;
        assert!(!retired.add(
            &format!("h{}.credential.test", newest % 3),
            &zeroize::Zeroizing::new(format!("value-{newest:04}"))
        ));
        assert_eq!(retired.values.len(), MAX_RETIRED_VALUES);
        assert!(!retired
            .values
            .iter()
            .any(|(_, v)| v.as_str() == "value-0000"));
        assert!(retired.covers("h0.credential.test") && retired.covers("H2.credential.test."));
        assert!(!retired.covers("h3.credential.test"));
    }

    /// A connection intercepted before its binding is removed keeps scrubbing the value it carried.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_open_connection_keeps_scrubbing_a_removed_binding() {
        let f = fixture_with_secret("ghp_keptopensecret1357").await;
        let mut tls = open_guest(&f, f.ca_pem.as_bytes(), CRED_HOST)
            .await
            .unwrap();
        let store = format!(
            "GET /store HTTP/1.1\r\nHost: {CRED_HOST}\r\nAuthorization: Bearer {}\r\n\r\n",
            f.placeholder
        );
        let response = exchange(&mut tls, &store).await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");

        rebind(&f, CredentialPolicy::default(), BTreeMap::new(), Vec::new());
        let read = format!("GET /read HTTP/1.1\r\nHost: {CRED_HOST}\r\n\r\n");
        let response = exchange(&mut tls, &read).await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(
            !response_body(&response).contains("ghp_keptopensecret1357"),
            "{response}"
        );
    }

    /// A raw connection spliced to a host before a binding covers it is ended when the binding takes effect: it
    /// could otherwise read back, unscrubbed, a value stored there through the binding.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_connection_spliced_before_its_host_is_bound_is_ended() {
        let policy = CredentialPolicy {
            credentials: vec![bound("svc", CRED_HOST)],
        };
        let resolver = StaticResolver::new()
            .with("svc", "real-secret")
            .with("other", "ghp_newlyboundsecret8642");
        let f = fixture_with_policy(policy, CRED_HOST, resolver).await;
        let mut spliced = open_guest(&f, &f.upstream.cert_pem, OTHER_HOST)
            .await
            .unwrap();
        let raw = format!("GET /raw HTTP/1.1\r\nHost: {OTHER_HOST}\r\n\r\n");
        let response = exchange(&mut spliced, &raw).await;
        assert!(response.starts_with("HTTP/1.1 200"), "spliced: {response}");

        let grown = CredentialPolicy {
            credentials: vec![bound("svc", CRED_HOST), bound("other", OTHER_HOST)],
        };
        let mut placeholders = crate::policy::generate_placeholders(&grown);
        placeholders.insert("svc".into(), f.placeholder.clone());
        let other = placeholders["other"].clone();
        let extra = MachineCa::generate("test-machine", &[OTHER_HOST.to_string()]).unwrap();
        let trusted = format!("{}{}", f.ca_pem, extra.certificate_pem());
        rebind(&f, grown, placeholders, vec![extra]);
        let store = format!(
            "GET /store HTTP/1.1\r\nHost: {OTHER_HOST}\r\nAuthorization: Bearer {other}\r\nConnection: close\r\n\r\n"
        );
        let response = guest_request(&f, trusted.as_bytes(), OTHER_HOST, &store)
            .await
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "store: {response}");

        let read = format!("GET /read HTTP/1.1\r\nHost: {OTHER_HOST}\r\n\r\n");
        let response = exchange(&mut spliced, &read).await;
        assert!(
            !response_body(&response).contains("ghp_newlyboundsecret8642"),
            "read back on the old connection: {response}"
        );
        assert!(response.is_empty(), "old connection still open: {response}");
    }

    /// A binding removed while a request it injected is upstream: the reply that echoes the value is scrubbed of it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_binding_removed_while_its_request_is_upstream_is_scrubbed_from_the_reply() {
        let f = fixture_with_secret("ghp_inflightsecret5678").await;
        let request = format!(
            "GET /gate-echo HTTP/1.1\r\nHost: {CRED_HOST}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
            f.placeholder
        );
        let (response, ()) = tokio::join!(
            guest_request(&f, f.ca_pem.as_bytes(), CRED_HOST, &request),
            async {
                f.upstream.held.arrived.notified().await;
                rebind(&f, CredentialPolicy::default(), BTreeMap::new(), Vec::new());
                f.upstream.held.gate.notify_one();
            }
        );
        let response = response.unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(
            !response_body(&response).contains("ghp_inflightsecret5678"),
            "{response}"
        );
        assert!(
            response_body(&response).starts_with("echo Bearer "),
            "{response}"
        );
    }

    /// A value bound while a response streams, whose first half the guest already has (the host's binding had no
    /// value, so nothing was held back): the second half, sent after the binding took effect, is replaced.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_rest_of_a_value_bound_mid_stream_is_scrubbed_though_its_start_was_sent() {
        const VALUE: &str = "ghp_straddlesecret1234";
        let (head, tail) = VALUE.split_at(VALUE.len() / 2);
        let policy = CredentialPolicy {
            credentials: vec![bound("svc", CRED_HOST)],
        };
        // `svc` resolves to nothing: the response starts with no scrubber at all
        let resolver = StaticResolver::new().with("other", VALUE);
        let f = fixture_with_policy(policy, CRED_HOST, resolver).await;
        *f.upstream.held.stored.lock().unwrap() = VALUE.to_string();
        let mut stream = open_guest(&f, f.ca_pem.as_bytes(), CRED_HOST)
            .await
            .unwrap();
        stream
            .write_all(
                format!(
                    "GET /stream-split HTTP/1.1\r\nHost: {CRED_HOST}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut received = Vec::new();
        let mut chunk = [0u8; 4096];
        while !response_body(&String::from_utf8_lossy(&received)).ends_with(head) {
            let n = stream.read(&mut chunk).await.unwrap();
            assert!(n > 0, "response ended early");
            received.extend_from_slice(&chunk[..n]);
        }

        let grown = CredentialPolicy {
            credentials: vec![bound("svc", CRED_HOST), bound("other", CRED_HOST)],
        };
        let placeholders = crate::policy::generate_placeholders(&grown);
        rebind(&f, grown, placeholders, Vec::new());
        f.upstream.held.gate.notify_one();
        let _ = stream.read_to_end(&mut received).await;
        let body = response_body(&String::from_utf8_lossy(&received));
        let rest = body
            .trim_start_matches('.')
            .strip_prefix(head)
            .unwrap_or(&body);
        assert!(rest.ends_with(" end"), "{rest}");
        assert!(!rest.contains(tail), "{rest}");
        assert!(!body.contains(VALUE), "{body}");
    }

    /// A value past the length limit is never sent, so it never needs scrubbing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_value_past_the_length_limit_is_refused() {
        let f =
            fixture_with_secret(&"v".repeat(crate::policy::MAX_CREDENTIAL_VALUE_BYTES + 1)).await;
        let request = format!(
            "GET /v1/me HTTP/1.1\r\nHost: {CRED_HOST}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
            f.placeholder
        );
        let response = guest_request(&f, f.ca_pem.as_bytes(), CRED_HOST, &request)
            .await
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 502"), "{response}");
        assert!(f.upstream.seen.lock().unwrap().is_empty());
    }

    /// A host gains a binding whose value is already resolved (it was bound to another host): from the moment the
    /// new bindings are visible, a response from the host is checked for that value, never by a scrubber built
    /// before the change.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_binding_is_scrubbed_for_as_soon_as_it_is_visible() {
        let policy = CredentialPolicy {
            credentials: vec![bound("svc", CRED_HOST), bound("other", OTHER_HOST)],
        };
        let resolver = StaticResolver::new()
            .with("svc", "real-secret")
            .with("other", "ghp_alreadyresolved9753");
        let f = fixture_with_policy(policy.clone(), CRED_HOST, resolver).await;
        let mut placeholders = crate::policy::generate_placeholders(&policy);
        placeholders.insert("svc".into(), f.placeholder.clone());
        let extra = MachineCa::generate("test-machine", &[OTHER_HOST.to_string()]).unwrap();
        let trusted = format!("{}{}", f.ca_pem, extra.certificate_pem());
        rebind(&f, policy, placeholders.clone(), vec![extra]);
        // `other`'s value is resolved and stored upstream, where `CRED_HOST` hands it back too
        let store = format!(
            "GET /store HTTP/1.1\r\nHost: {OTHER_HOST}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
            placeholders["other"]
        );
        let response = guest_request(&f, trusted.as_bytes(), OTHER_HOST, &store)
            .await
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        // builds and caches `CRED_HOST`'s scrubber, which has no business knowing `other`'s value yet
        let read = format!("GET /read HTTP/1.1\r\nHost: {CRED_HOST}\r\nConnection: close\r\n\r\n");
        let response = guest_request(&f, f.ca_pem.as_bytes(), CRED_HOST, &read)
            .await
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");

        // `other` now covers `CRED_HOST` too; the commit stops at its gate once the bindings are visible
        let mut wider = bound("other", OTHER_HOST);
        wider.allowed_hosts.push(CRED_HOST.into());
        let grown = CredentialPolicy {
            credentials: vec![bound("svc", CRED_HOST), wider],
        };
        let (reached_tx, reached_rx) = tokio::sync::oneshot::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        *f.interceptor.state.after_swap.lock().unwrap() = Some(Box::new(move || {
            let _ = reached_tx.send(());
            let _ = release_rx.recv();
        }));
        let control = f.interceptor.control();
        let extra_again = MachineCa::generate("test-machine", &[OTHER_HOST.to_string()]).unwrap();
        let commit = tokio::task::spawn_blocking(move || {
            control.update(grown, placeholders, vec![extra_again])
        });
        reached_rx.await.unwrap();
        let response = guest_request(&f, f.ca_pem.as_bytes(), CRED_HOST, &read)
            .await
            .unwrap();
        release_tx.send(()).unwrap();
        commit.await.unwrap().unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        let body = response_body(&response);
        assert!(!body.contains("ghp_alreadyresolved9753"), "{body}");
    }

    /// A value bound to a host while a response from it streams is scrubbed from the rest of that response.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_value_bound_while_a_response_streams_is_scrubbed_from_the_rest() {
        let policy = CredentialPolicy {
            credentials: vec![bound("svc", CRED_HOST)],
        };
        let resolver = StaticResolver::new()
            .with("svc", "real-secret")
            .with("other", "ghp_streamedsecret2468");
        let f = fixture_with_policy(policy, CRED_HOST, resolver).await;
        let mut stream = open_guest(&f, f.ca_pem.as_bytes(), CRED_HOST)
            .await
            .unwrap();
        stream
            .write_all(
                format!(
                    "GET /stream-read HTTP/1.1\r\nHost: {CRED_HOST}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        // the response is under way: its lead has reached the guest
        let mut received = Vec::new();
        let mut chunk = [0u8; 4096];
        while !received.windows(64).any(|w| w.iter().all(|b| *b == b'.')) {
            let n = stream.read(&mut chunk).await.unwrap();
            assert!(n > 0, "response ended early");
            received.extend_from_slice(&chunk[..n]);
        }

        let grown = CredentialPolicy {
            credentials: vec![bound("svc", CRED_HOST), bound("other", CRED_HOST)],
        };
        let mut placeholders = crate::policy::generate_placeholders(&grown);
        placeholders.insert("svc".into(), f.placeholder.clone());
        let other = placeholders["other"].clone();
        rebind(&f, grown, placeholders, Vec::new());
        let store = format!(
            "GET /store HTTP/1.1\r\nHost: {CRED_HOST}\r\nAuthorization: Bearer {other}\r\nConnection: close\r\n\r\n"
        );
        let response = guest_request(&f, f.ca_pem.as_bytes(), CRED_HOST, &store)
            .await
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "store: {response}");

        f.upstream.held.gate.notify_one();
        let _ = stream.read_to_end(&mut received).await;
        let body = response_body(&String::from_utf8_lossy(&received));
        let rest = body.trim_start_matches('.');
        assert!(rest.ends_with(" end"), "{rest}");
        assert!(!rest.contains("ghp_streamedsecret2468"), "{rest}");
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
        assert_eq!(response_body(&response), "upstream ok", "{response}");
        let seen = f.upstream.seen.lock().unwrap().clone();
        assert_eq!(
            seen,
            vec![("Bearer real-secret".to_string(), "/v1/me".to_string())]
        );
    }

    /// Bindings change while the machine runs (Capy adds and removes variables in place, 2026-11-18): a binding
    /// added is substituted from the next request, one removed is refused, and a binding for a host the machine CA does
    /// not permit is served by the CA added for it, which the guest trusts beside the first.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bindings_added_and_removed_live_take_effect_from_the_next_request() {
        let binding = |name: &str, var: &str, host: &str| CredentialBinding {
            name: name.into(),
            environment_variable: var.into(),
            allowed_hosts: vec![host.into()],
            injection_location: InjectionLocation::default(),
            methods: DEFAULT_METHODS.iter().map(|m| m.to_string()).collect(),
            set_header: None,
        };
        let policy = CredentialPolicy {
            credentials: vec![binding("svc", "SVC_TOKEN", CRED_HOST)],
        };
        let resolver = StaticResolver::new()
            .with("svc", "real-secret")
            .with("other", "other-secret");
        let f = fixture_with_policy(policy, CRED_HOST, resolver).await;
        let svc = f.placeholder.clone();
        let ask = |host: &str, placeholder: &str| {
            format!("GET /v1/me HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {placeholder}\r\nConnection: close\r\n\r\n")
        };

        // add `other` for a host the machine CA does not permit, with a CA of its own
        let grown = CredentialPolicy {
            credentials: vec![
                binding("svc", "SVC_TOKEN", CRED_HOST),
                binding("other", "OTHER_TOKEN", OTHER_HOST),
            ],
        };
        let mut placeholders = crate::policy::generate_placeholders(&grown);
        placeholders.insert("svc".into(), svc.clone());
        let other = placeholders["other"].clone();
        let extra = MachineCa::generate("test-machine", &[OTHER_HOST.to_string()]).unwrap();
        let trusted = format!("{}{}", f.ca_pem, extra.certificate_pem());
        rebind(&f, grown, placeholders.clone(), vec![extra]);
        let response = guest_request(&f, trusted.as_bytes(), OTHER_HOST, &ask(OTHER_HOST, &other))
            .await
            .unwrap();
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "added binding: {response}"
        );
        let response = guest_request(&f, trusted.as_bytes(), CRED_HOST, &ask(CRED_HOST, &svc))
            .await
            .unwrap();
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "kept binding: {response}"
        );

        // remove `svc`: its placeholder is refused from the next request
        let shrunk = CredentialPolicy {
            credentials: vec![binding("other", "OTHER_TOKEN", OTHER_HOST)],
        };
        placeholders.remove("svc");
        let extra_again = MachineCa::generate("test-machine", &[OTHER_HOST.to_string()]).unwrap();
        let trusted = format!("{}{}", f.ca_pem, extra_again.certificate_pem());
        rebind(&f, shrunk, placeholders, vec![extra_again]);
        let response = guest_request(&f, trusted.as_bytes(), OTHER_HOST, &ask(OTHER_HOST, &other))
            .await
            .unwrap();
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "remaining binding: {response}"
        );
        // the removed binding's host stays intercepted, so its responses are still checked, but its placeholder is
        // refused and never gets a value
        let removed = guest_request(&f, trusted.as_bytes(), CRED_HOST, &ask(CRED_HOST, &svc))
            .await
            .unwrap();
        assert!(
            removed.starts_with("HTTP/1.1 403"),
            "removed binding: {removed}"
        );
        let seen = f.upstream.seen.lock().unwrap().clone();
        assert!(
            seen.contains(&("Bearer other-secret".to_string(), "/v1/me".to_string())),
            "{seen:?}"
        );
        assert!(
            seen.contains(&("Bearer real-secret".to_string(), "/v1/me".to_string())),
            "{seen:?}"
        );
        // the removed binding's placeholder never reached a credential again
        assert_eq!(
            seen.iter()
                .filter(|(auth, _)| auth == "Bearer real-secret")
                .count(),
            1,
            "{seen:?}"
        );
    }

    #[test]
    fn a_ca_permits_its_hosts_and_their_subdomains_only() {
        let ca =
            MachineCa::generate("m", &["api.notion.com".into(), "*.example.com".into()]).unwrap();
        assert!(
            ca.permits("api.notion.com")
                && ca.permits("API.Notion.com.")
                && ca.permits("x.api.notion.com")
        );
        assert!(ca.permits("example.com") && ca.permits("a.example.com"));
        assert!(
            !ca.permits("notion.com")
                && !ca.permits("evilapi.notion.com.attacker.test")
                && !ca.permits("xexample.com")
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

    /// Body of a raw HTTP/1.1 response, chunked or not, or what of it has arrived.
    fn response_body(response: &str) -> String {
        let (head, body) = response.split_once("\r\n\r\n").unwrap_or((response, ""));
        if !head
            .to_ascii_lowercase()
            .contains("transfer-encoding: chunked")
        {
            return body.to_string();
        }
        let mut out = String::new();
        let mut rest = body;
        while let Some((size, after)) = rest.split_once("\r\n") {
            let size = usize::from_str_radix(size.trim(), 16).unwrap_or(0);
            if size == 0 {
                break;
            }
            // a response still arriving ends in part of a chunk
            if after.len() < size + 2 {
                out.push_str(&after[..size.min(after.len())]);
                break;
            }
            out.push_str(&after[..size]);
            rest = &after[size + 2..];
        }
        out
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_reflected_placeholder_value_comes_back_as_the_placeholder() {
        let f = fixture_with_secret("ghp_reflectedsecret0123").await;
        let request = format!(
            "GET /echo HTTP/1.1\r\nHost: {CRED_HOST}\r\nAuthorization: Bearer {}\r\nAccept-Encoding: gzip, br\r\nRange: bytes=0-9\r\nConnection: close\r\n\r\n",
            f.placeholder
        );
        let response = guest_request(&f, f.ca_pem.as_bytes(), CRED_HOST, &request)
            .await
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(!response.contains("ghp_reflectedsecret0123"), "{response}");
        let body = response_body(&response);
        assert!(
            body.contains(&format!("\"Authorization\":\"Bearer {}\"", f.placeholder)),
            "{body}"
        );
        // The upstream was asked for an uncompressed, whole response.
        assert!(body.contains("\"Accept-Encoding\":\"identity\""), "{body}");
        assert!(body.contains("\"Range\":\"\""), "{body}");
        assert!(
            response.to_ascii_lowercase().contains(&format!(
                "x-echo: bearer {}",
                f.placeholder.to_ascii_lowercase()
            )),
            "{response}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_reflected_header_value_is_redacted_even_base64_encoded() {
        let f = header_fixture().await;
        for path in ["/echo", "/echo-b64"] {
            let request =
                format!("GET {path} HTTP/1.1\r\nHost: {CRED_HOST}\r\nConnection: close\r\n\r\n");
            let response = guest_request(&f, f.ca_pem.as_bytes(), CRED_HOST, &request)
                .await
                .unwrap();
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
            assert!(!response.contains("aW5qZWN0ZWQ="), "{path}: {response}");
            assert!(response.contains("[smolvm-redacted]"), "{path}: {response}");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_value_stored_by_one_request_is_scrubbed_from_one_that_injects_nothing() {
        // Placeholder binding: a request without the placeholder injects
        // nothing, yet its response is still checked.
        let f = fixture_with_secret("ghp_storedsecret45678").await;
        let request = format!(
            "GET /echo HTTP/1.1\r\nHost: {CRED_HOST}\r\nAuthorization: ghp_storedsecret45678\r\nConnection: close\r\n\r\n"
        );
        let response = guest_request(&f, f.ca_pem.as_bytes(), CRED_HOST, &request)
            .await
            .unwrap();
        assert!(!response.contains("ghp_storedsecret45678"), "{response}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_gzip_response_sent_anyway_is_decoded_and_scrubbed() {
        let f = fixture_with_secret("ghp_gzippedsecret9876").await;
        let request = format!(
            "GET /gzip HTTP/1.1\r\nHost: {CRED_HOST}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
            f.placeholder
        );
        let response = guest_request(&f, f.ca_pem.as_bytes(), CRED_HOST, &request)
            .await
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(
            !response.to_ascii_lowercase().contains("content-encoding"),
            "{response}"
        );
        assert_eq!(
            response_body(&response),
            format!("echo Bearer {}", f.placeholder),
            "{response}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_encoding_that_cannot_be_checked_is_refused() {
        let f = fixture().await;
        let request =
            format!("GET /brotli HTTP/1.1\r\nHost: {CRED_HOST}\r\nConnection: close\r\n\r\n");
        let response = guest_request(&f, f.ca_pem.as_bytes(), CRED_HOST, &request)
            .await
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 502"), "{response}");
        assert!(!response.contains("pretend-brotli"), "{response}");
    }

    #[test]
    fn a_decompression_bomb_is_refused() {
        use std::io::Write;
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        let zeros = vec![0u8; 1 << 20];
        for _ in 0..(DECODED_LIMIT >> 20) + 1 {
            gz.write_all(&zeros).unwrap();
        }
        let bomb = gz.finish().unwrap();
        assert!(bomb.len() < ENCODED_LIMIT);
        assert!(decode_body("gzip", &bomb).is_err());
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(b"zlib-wrapped").unwrap();
        assert_eq!(
            decode_body("deflate", &z.finish().unwrap()).unwrap(),
            b"zlib-wrapped"
        );
        let mut raw =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        raw.write_all(b"raw deflate").unwrap();
        assert_eq!(
            decode_body("deflate", &raw.finish().unwrap()).unwrap(),
            b"raw deflate"
        );
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
