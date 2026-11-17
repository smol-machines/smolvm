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
//! Every response from a credential host is scrubbed of the values its
//! bindings carry (see [`crate::scrub`]), so a host that reflects a request's
//! credential cannot hand it to the guest. A host a binding stops covering
//! (the binding removed, or moved to other hosts) may still hold a value sent
//! to it, so for as long as the interceptor runs it keeps terminating that
//! host and scrubbing the values sent there, without injecting anything. To keep that check complete,
//! requests ask for an uncompressed whole response: `Accept-Encoding` is set to
//! `identity` and range requests are dropped. A server that compresses anyway
//! has a gzip or deflate body decoded before the check; any other encoding is
//! refused.

use crate::ca::MachineCa;
use crate::policy::{CredentialPolicy, PLACEHOLDER_PREFIX};
use crate::resolver::{CredentialRequest, CredentialResolver};
use crate::scrub::{Scrubber, Secret};
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
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, RwLock};
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
/// Longest a guest may leave a request body to a credential host idle: one
/// that stops sending is answered `408` rather than held open; one that keeps
/// sending, however slowly, is never cut off.
const BODY_IDLE_TIMEOUT: Duration = if cfg!(test) {
    Duration::from_millis(500)
} else {
    Duration::from_secs(60)
};
const MAX_CACHED_CLIENTS: usize = 64;
/// Values remembered per binding for scrubbing: a rotated credential's old
/// value may still be stored upstream.
const MAX_REMEMBERED_VALUES: usize = 4;
/// Values kept for scrubbing on hosts their bindings no longer cover, across
/// every host: the oldest value goes first. The hosts themselves are never
/// forgotten (see [`RetiredSet`]).
const MAX_RETIRED_VALUES: usize = 256;
/// Longest a change of bindings waits for a flow it ends (one spliced to a
/// host the change intercepts) to be gone before it takes effect.
const SPLICE_END_WAIT: Duration = Duration::from_secs(5);
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

/// Changes a running interceptor's bindings and CA. Cloneable; outlives
/// nothing: once the [`Interceptor`] is dropped, changes have no effect.
#[derive(Clone)]
pub struct InterceptorControl(Arc<State>);

/// The bindings an interceptor enforces, swapped as one value so a request
/// never sees one binding's policy beside another's placeholders.
struct Bindings {
    policy: CredentialPolicy,
    /// placeholder → binding name
    by_placeholder: HashMap<String, String>,
    /// binding name → placeholder
    placeholders: HashMap<String, String>,
    /// binding name → generation of the secret behind it: kept across a swap
    /// that keeps the binding's secret, new otherwise.
    generations: HashMap<String, u64>,
}

impl Bindings {
    fn new(
        policy: CredentialPolicy,
        placeholders: &BTreeMap<String, String>,
        generations: HashMap<String, u64>,
    ) -> Self {
        let placeholders: HashMap<String, String> = placeholders
            .iter()
            .filter(|(binding, _)| policy.binding(binding).is_some())
            .map(|(binding, placeholder)| (binding.clone(), placeholder.clone()))
            .collect();
        Self {
            by_placeholder: placeholders
                .iter()
                .map(|(binding, placeholder)| (placeholder.clone(), binding.clone()))
                .collect(),
            placeholders,
            generations,
            policy,
        }
    }

    /// Whether `name` is the very same binding in `self` and `other`: the
    /// same definition, placeholder and secret generation.
    fn same_binding(&self, other: &Bindings, name: &str) -> bool {
        self.policy.binding(name).is_some()
            && self.policy.binding(name) == other.policy.binding(name)
            && self.placeholders.get(name) == other.placeholders.get(name)
            && self.generations.get(name) == other.generations.get(name)
    }
}

/// Source of fresh secret generations, shared by every interceptor of the
/// process.
static NEXT_GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn fresh_generations(policy: &CredentialPolicy) -> HashMap<String, u64> {
    policy
        .credentials
        .iter()
        .map(|b| {
            (
                b.name.clone(),
                NEXT_GENERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            )
        })
        .collect()
}

/// What a binding has resolved to in this process, for scrubbing.
#[derive(Default)]
struct Remembered {
    /// The newest secret generation a resolution was made for. A binding
    /// whose secret was replaced since is resolved again before a response
    /// from its host is checked.
    generation: u64,
    /// Values seen, newest last, across generations: a rotated credential's
    /// old value may still be stored upstream. Empty for a binding that could
    /// not be resolved.
    values: Vec<zeroize::Zeroizing<String>>,
}

/// What bindings that stopped covering a host leave behind there: the host
/// may have stored a value sent to it, and may hand it back.
#[derive(Default)]
struct RetiredSet {
    /// Host patterns, as bindings named them, that values were sent to. Kept
    /// for as long as the interceptor runs: such a host stays terminated
    /// (its responses checked, nothing injected, old placeholders refused)
    /// and is never spliced through again. Bounded by the distinct host
    /// patterns ever bound on this machine.
    hosts: std::collections::BTreeSet<String>,
    /// `(host pattern, value)` still scrubbed there, newest last, at most
    /// [`MAX_RETIRED_VALUES`].
    values: VecDeque<(String, zeroize::Zeroizing<String>)>,
}

/// A flow spliced through untouched (its host was not intercepted when it
/// opened), which a change of bindings that intercepts its host ends.
struct Splice {
    /// The server name its ClientHello gave, if any.
    host: Option<String>,
    cancel: tokio::sync::Notify,
    ended: std::sync::Mutex<bool>,
    ended_signal: std::sync::Condvar,
}

impl Splice {
    fn end(&self) {
        self.cancel.notify_one();
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

/// Marks its [`Splice`] ended when the flow's task lets go of it.
struct SpliceGuard(Arc<Splice>);

impl Drop for SpliceGuard {
    fn drop(&mut self) {
        *self.0.ended.lock().unwrap_or_else(|e| e.into_inner()) = true;
        self.0.ended_signal.notify_all();
    }
}

struct State {
    machine: String,
    bindings: RwLock<Arc<Bindings>>,
    /// binding name → values it has resolved to in this process.
    resolved: Mutex<HashMap<String, Remembered>>,
    /// What bindings that stopped covering a host left behind there.
    retired: Mutex<RetiredSet>,
    /// Flows spliced through untouched, still open (ended ones are pruned).
    /// Held while a flow decides between splicing and terminating, and while
    /// bindings change, so no flow is spliced to a host the new bindings
    /// intercept.
    spliced: Mutex<Vec<Arc<Splice>>>,
    /// Grows whenever the values a response may need scrubbed of can have
    /// grown: bindings swapped, or a value resolved. A response being
    /// streamed rebuilds its scrubber when it changes.
    secrets_epoch: std::sync::atomic::AtomicU64,
    ca: RwLock<Arc<MachineCa>>,
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
            bindings: RwLock::new(Arc::new({
                let generations = fresh_generations(&config.policy);
                Bindings::new(config.policy, &config.placeholders, generations)
            })),
            resolved: Mutex::new(HashMap::new()),
            retired: Mutex::new(RetiredSet::default()),
            spliced: Mutex::new(Vec::new()),
            secrets_epoch: std::sync::atomic::AtomicU64::new(0),
            ca: RwLock::new(Arc::new(config.ca)),
            resolver,
            endpoint,
            leaves: Mutex::new(HashMap::new()),
            clients: Mutex::new(HashMap::new()),
            upstream_roots,
            sessions: Arc::new(tokio::sync::Semaphore::new(MAX_SESSIONS)),
        });
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let served = state.clone();
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
                        _ = accept_loop(served, listener) => {}
                        _ = shutdown_rx => {}
                    }
                });
                runtime.shutdown_timeout(Duration::from_secs(1));
            })
            .context("interceptor thread")?;
        Ok(Self {
            endpoint,
            state,
            shutdown: Some(shutdown_tx),
            thread: Some(thread),
        })
    }

    /// Where the network backend should redirect flows, and with which token.
    pub fn endpoint(&self) -> InterceptEndpoint {
        self.endpoint
    }

    /// A handle that changes this interceptor's bindings and CA while it runs.
    pub fn control(&self) -> InterceptorControl {
        InterceptorControl(self.state.clone())
    }
}

impl InterceptorControl {
    /// Enforce `policy` with `placeholders` from the next request on, every
    /// binding with a new secret. See [`Self::replace_bindings_keeping`].
    pub fn replace_bindings(
        &self,
        policy: CredentialPolicy,
        placeholders: &BTreeMap<String, String>,
    ) {
        self.replace_bindings_keeping(policy, placeholders, &[]);
    }

    /// Enforce `policy` with `placeholders` from the next request on. The
    /// bindings named in `kept` keep the secret they had (the caller kept
    /// their source and value); every other one has a new secret.
    ///
    /// A request in flight that resolved a binding's value is sent only if
    /// that binding is still the very same one (definition, placeholder and
    /// secret) once the value is in hand; otherwise it is refused with a
    /// `503` rather than sent with a value it was not checked against. A swap
    /// that leaves a request's binding alone (an unrelated addition, an
    /// identical re-send) does not disturb it. A caller that also changes
    /// the resolver's values must do both under the lock its resolver takes
    /// to read them, so no resolution sees one without the other. A host no
    /// binding allows any more is spliced through untouched on its next
    /// connection, and a placeholder whose binding is gone is refused —
    /// unless a value was sent to it: then it stays terminated, and its
    /// responses scrubbed of those values, while the interceptor runs.
    ///
    /// A connection spliced through untouched to a host these bindings now
    /// intercept (opened before a binding covered it) is ended before they
    /// take effect: no value is injected toward a host while a connection to
    /// it that nothing checks is open. One with no server name is ended when
    /// the change intercepts any new host.
    pub fn replace_bindings_keeping(
        &self,
        policy: CredentialPolicy,
        placeholders: &BTreeMap<String, String>,
        kept: &[String],
    ) {
        // A flow deciding to splice holds this: it decides either before the
        // swap (and is ended here if it must be) or after it.
        let mut spliced = self.0.spliced.lock().expect("spliced flows");
        let mut slot = self.0.bindings.write().unwrap_or_else(|e| e.into_inner());
        self.0.retire(&slot.policy, &policy);
        spliced.retain(|splice| !*splice.ended.lock().unwrap_or_else(|e| e.into_inner()));
        let new_host = policy
            .credentials
            .iter()
            .flat_map(|b| b.allowed_hosts.iter())
            .any(|host| {
                !slot
                    .policy
                    .credentials
                    .iter()
                    .any(|b| b.allowed_hosts.contains(host))
            });
        let ending: Vec<Arc<Splice>> = spliced
            .iter()
            .filter(|splice| match &splice.host {
                Some(host) => {
                    policy.bindings_for_host(host).next().is_some() || self.0.has_retired(host)
                }
                None => new_host,
            })
            .cloned()
            .collect();
        for splice in &ending {
            splice.end();
        }
        for splice in &ending {
            if !splice.wait_ended(SPLICE_END_WAIT) {
                tracing::warn!(machine = %self.0.machine, host = ?splice.host, "a spliced connection to a newly intercepted host did not end in time");
            }
        }
        let mut generations = fresh_generations(&policy);
        for name in kept {
            let same = slot.policy.binding(name) == policy.binding(name)
                && slot.placeholders.get(name) == placeholders.get(name);
            if let (true, Some(old)) = (same, slot.generations.get(name)) {
                generations.insert(name.clone(), *old);
            }
        }
        *slot = Arc::new(Bindings::new(policy, placeholders, generations));
        self.0.bump_secrets();
    }

    /// Sign leaves with `ca` from the next handshake on.
    pub fn replace_ca(&self, ca: MachineCa) {
        *self.0.ca.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(ca);
        self.0.leaves.lock().expect("leaf cache").clear();
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
    // Decided under the spliced-flow lock, which a change of bindings holds
    // while it swaps them: a flow spliced now is one that change ends if it
    // intercepts the flow's host.
    let splice = {
        let mut spliced = state.spliced.lock().expect("spliced flows");
        match &host {
            Some(name) if state.intercepts(name) => None,
            _ => {
                spliced.retain(|splice| !*splice.ended.lock().unwrap_or_else(|e| e.into_inner()));
                let splice = Arc::new(Splice {
                    host: host.clone(),
                    cancel: tokio::sync::Notify::new(),
                    ended: std::sync::Mutex::new(false),
                    ended_signal: std::sync::Condvar::new(),
                });
                spliced.push(splice.clone());
                Some(SpliceGuard(splice))
            }
        }
    };
    match (splice, host) {
        (Some(guard), _) => passthrough(stream, upstream, buffered, guard).await,
        (None, Some(host)) => {
            // The upstream client opens its own verified connection.
            drop(upstream);
            terminate(state, stream, buffered, host, destination).await
        }
        (None, None) => unreachable!("only a named host is terminated"),
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

/// Splice a flow through untouched until either side closes, or a change of
/// bindings intercepts its host and ends it. Dropping `guard` (with the
/// sockets) tells that change it is gone.
async fn passthrough(
    mut guest: TcpStream,
    mut upstream: TcpStream,
    buffered: Vec<u8>,
    guard: SpliceGuard,
) -> Result<()> {
    let splice = guard.0.clone();
    let spliced = async {
        let _ = upstream.set_nodelay(true);
        upstream.write_all(&buffered).await?;
        let _ = tokio::io::copy_bidirectional(&mut guest, &mut upstream).await;
        Ok::<_, std::io::Error>(())
    };
    tokio::select! {
        result = spliced => result?,
        () = splice.cancel.notified() => {
            tracing::info!(host = ?splice.host, "spliced connection ended: its host is now intercepted");
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
    /// Keep scrubbing, on every host a binding of `old` covered and its
    /// namesake in `new` does not, the values that binding resolved to here;
    /// and keep each such host intercepted for as long as this runs.
    fn retire(&self, old: &CredentialPolicy, new: &CredentialPolicy) {
        let resolved = self.resolved.lock().expect("resolved values");
        let mut retired = self.retired.lock().expect("retired values");
        for binding in &old.credentials {
            let Some(seen) = resolved.get(&binding.name).filter(|s| !s.values.is_empty()) else {
                continue;
            };
            let successor = new.binding(&binding.name);
            for host in &binding.allowed_hosts {
                if successor.is_some_and(|b| b.allowed_hosts.contains(host)) {
                    continue;
                }
                retired.hosts.insert(host.clone());
                for value in &seen.values {
                    if retired.values.iter().any(|(h, v)| h == host && v == value) {
                        continue;
                    }
                    if retired.values.len() == MAX_RETIRED_VALUES {
                        retired.values.pop_front();
                    }
                    retired.values.push_back((host.clone(), value.clone()));
                }
            }
        }
    }

    /// Whether `host` is one a binding sent values to and covers no more.
    fn has_retired(&self, host: &str) -> bool {
        self.retired
            .lock()
            .expect("retired values")
            .hosts
            .iter()
            .any(|pattern| smolvm_protocol::credentials::host_matches(pattern, host))
    }

    /// Whether flows to `host` are terminated here rather than spliced.
    fn intercepts(&self, host: &str) -> bool {
        self.bindings()
            .policy
            .bindings_for_host(host)
            .next()
            .is_some()
            || self.has_retired(host)
    }

    fn bump_secrets(&self) {
        self.secrets_epoch
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    }

    fn secrets_epoch(&self) -> u64 {
        self.secrets_epoch
            .load(std::sync::atomic::Ordering::Acquire)
    }

    fn bindings(&self) -> Arc<Bindings> {
        self.bindings
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Whether binding `name` of `seen` is still in force, unchanged. A value
    /// is resolved by binding name; checked after resolving, this proves the
    /// value belongs to the binding the request was checked against, not to
    /// a binding of the same name that replaced it meanwhile (the controller
    /// swaps bindings and the resolver's values as one step).
    fn binding_unchanged(&self, seen: &Arc<Bindings>, name: &str) -> bool {
        let now = self.bindings();
        Arc::ptr_eq(seen, &now) || seen.same_binding(&now, name)
    }

    fn ca(&self) -> Arc<MachineCa> {
        self.ca.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Ask the resolver for `binding`'s value for this request. The inner
    /// `Err` is the reply to send the guest when it has none.
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
            .context("resolver task")?;
        let generation = bindings.generations.get(binding).copied().unwrap_or(0);
        self.remember(binding, generation, resolved.as_ref().ok());
        Ok(resolved.map_err(|e| {
            tracing::warn!(machine = %self.machine, binding, host, error = %e, "credential resolution failed");
            text(
                StatusCode::BAD_GATEWAY,
                "smolvm credentials: credential unavailable",
            )
        }))
    }

    /// Note what `binding` resolved to under secret `generation`, or that it
    /// did not resolve.
    fn remember(&self, binding: &str, generation: u64, value: Option<&zeroize::Zeroizing<String>>) {
        let mut resolved = self.resolved.lock().expect("resolved values");
        let remembered = resolved.entry(binding.to_string()).or_default();
        // Generations only grow, so a resolution that finishes after a newer
        // one never makes the newer secret look unseen.
        remembered.generation = remembered.generation.max(generation);
        let values = &mut remembered.values;
        if let Some(value) = value {
            if !values.iter().any(|known| known == value) {
                if values.len() == MAX_REMEMBERED_VALUES {
                    values.remove(0);
                }
                values.push(value.clone());
                self.bump_secrets();
            }
        }
    }

    /// A scrubber for every value the bindings covering `host` may carry,
    /// resolving the ones this process has not seen yet. A guest that stored a
    /// value with one request could read it back with another that injects
    /// nothing, so every response from the host is checked.
    ///
    /// Both the bindings the request was checked against (`snapshot`) and the
    /// ones in force now count, and the values left with the host by bindings
    /// that stopped covering it: a value bound while a response is on its
    /// way is scrubbed from what is left of it.
    async fn scrubber_for(
        &self,
        snapshot: &Bindings,
        host: &str,
        destination: SocketAddr,
        method: &str,
        path: &str,
    ) -> Result<Option<Scrubber>> {
        let current = self.bindings();
        let views: [&Bindings; 2] = [snapshot, &current];
        for bindings in views {
            let unseen: Vec<String> = {
                let resolved = self.resolved.lock().expect("resolved values");
                bindings
                    .policy
                    .bindings_for_host(host)
                    .filter(|b| {
                        resolved.get(&b.name).is_none_or(|seen| {
                            bindings
                                .generations
                                .get(&b.name)
                                .is_some_and(|current| seen.generation < *current)
                        })
                    })
                    .map(|b| b.name.clone())
                    .collect()
            };
            for binding in unseen {
                // Recorded either way by `resolve`; a failure only means there
                // is nothing of this binding's to look for.
                let _ = self
                    .resolve(bindings, &binding, host, destination, method, path)
                    .await?;
            }
        }
        let resolved = self.resolved.lock().expect("resolved values");
        let retired = self.retired.lock().expect("retired values");
        let mut secrets: Vec<Secret<'_>> = Vec::new();
        for bindings in views {
            for b in bindings.policy.bindings_for_host(host) {
                // A header-setting binding's guest never holds a placeholder.
                let placeholder = b
                    .set_header
                    .is_none()
                    .then(|| bindings.placeholders.get(&b.name).map(String::as_str))
                    .flatten();
                secrets.extend(resolved.get(&b.name).into_iter().flat_map(|seen| {
                    seen.values.iter().map(move |value| Secret {
                        value: value.as_bytes(),
                        placeholder,
                    })
                }));
            }
        }
        // Values sent here under bindings that no longer cover the host have
        // no placeholder the guest could still use.
        secrets.extend(
            retired
                .values
                .iter()
                .filter(|(pattern, _)| smolvm_protocol::credentials::host_matches(pattern, host))
                .map(|(_, value)| Secret {
                    value: value.as_bytes(),
                    placeholder: None,
                }),
        );
        Ok(Scrubber::new(&secrets))
    }

    fn leaf_config(&self, host: &str) -> Result<Arc<rustls::ServerConfig>> {
        if let Some(config) = self.leaves.lock().expect("leaf cache").get(host) {
            return Ok(config.clone());
        }
        let (chain, key) = self.ca().issue_leaf(host)?;
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
        self: &Arc<Self>,
        host: &str,
        destination: SocketAddr,
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

        // One view of the bindings for the whole request, so a replacement
        // landing mid-request never pairs one policy with other placeholders.
        let bindings = self.bindings();
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
        let body = match read_body(body).await {
            Ok(body) => body,
            Err(reply) => return Ok(*reply),
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
            let Some(binding_name) = bindings.by_placeholder.get(placeholder) else {
                return Ok(text(
                    StatusCode::FORBIDDEN,
                    "smolvm credentials: unknown placeholder",
                ));
            };
            let binding = bindings
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
                    &bindings,
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
            if !self.binding_unchanged(&bindings, binding_name) {
                return Ok(bindings_changed());
            }
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
        for binding in bindings.policy.header_bindings(host, parts.method.as_str()) {
            let header_name = binding
                .set_header
                .as_deref()
                .context("header binding without a header")?;
            let secret = match self
                .resolve(
                    &bindings,
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
            if !self.binding_unchanged(&bindings, &binding.name) {
                return Ok(bindings_changed());
            }
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
        // Read before the scrubber is built: any value added from here on
        // shows as a newer epoch, and the body is checked for it too.
        let epoch = self.secrets_epoch();
        let scrubber = self
            .scrubber_for(&bindings, host, destination, method.as_str(), &target)
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
                self.scrubber_for(&bindings, host, destination, method.as_str(), &target)
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
                        snapshot: bindings.clone(),
                        epoch,
                        host: host.to_string(),
                        destination,
                        method: method.to_string(),
                        path: target.clone(),
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

/// What a streamed response needs to rebuild its scrubber when the values
/// it must be checked for change while it streams (a long poll, an event
/// stream): the request it answers, and the epoch its scrubber was built at.
struct Rescrub {
    state: Arc<State>,
    snapshot: Arc<Bindings>,
    epoch: u64,
    host: String,
    destination: SocketAddr,
    method: String,
    path: String,
}

/// `body` with every credential form `scrubber` knows replaced. Holds back the
/// tail of each chunk that could start a form the next chunk finishes. Before
/// each chunk, a scrubber built before a value was bound or resolved is built
/// again, so a value bound mid-response is scrubbed from the rest of it.
fn scrubbed<S>(
    body: S,
    scrubber: Option<Scrubber>,
    rescrub: Rescrub,
) -> impl Stream<Item = std::result::Result<Bytes, BoxError>> + Send
where
    S: Stream<Item = reqwest::Result<Bytes>> + Send + Unpin + 'static,
{
    struct Scan<S> {
        body: S,
        scrubber: Option<Arc<Scrubber>>,
        rescrub: Rescrub,
        carry: Vec<u8>,
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
                .scrubber_for(&r.snapshot, &r.host, r.destination, &r.method, &r.path)
                .await?
                .map(Arc::new);
            self.rescrub.epoch = now;
            Ok(())
        }

        fn scan(&mut self, last: bool) -> Vec<u8> {
            let mut out = Vec::with_capacity(self.carry.len());
            match &self.scrubber {
                Some(scrubber) => {
                    let (used, hits) = scrubber.scan(&self.carry, last, &mut out);
                    self.carry.drain(..used);
                    self.hits += hits;
                }
                None => out.append(&mut self.carry),
            }
            out
        }
    }
    futures_util::stream::unfold(
        Scan {
            body,
            scrubber: scrubber.map(Arc::new),
            rescrub,
            carry: Vec::new(),
            hits: 0,
            done: false,
        },
        move |mut scan| async move {
            if scan.done {
                return None;
            }
            loop {
                let next = scan.body.next().await;
                if let Err(e) = scan.refresh().await {
                    scan.done = true;
                    return Some((Err(e.into()), scan));
                }
                match next {
                    Some(Ok(chunk)) => {
                        scan.carry.extend_from_slice(&chunk);
                        let out = scan.scan(false);
                        if !out.is_empty() {
                            return Some((Ok(Bytes::from(out)), scan));
                        }
                    }
                    Some(Err(e)) => {
                        scan.done = true;
                        return Some((Err(Box::new(e) as BoxError), scan));
                    }
                    None => {
                        scan.done = true;
                        let out = scan.scan(true);
                        scan.carry.clear();
                        if scan.hits > 0 {
                            tracing::warn!(machine = %scan.rescrub.state.machine, host = %scan.rescrub.host, count = scan.hits, "credential value removed from a response body");
                        }
                        if out.is_empty() {
                            return None;
                        }
                        return Some((Ok(Bytes::from(out)), scan));
                    }
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

/// Buffer a request body of at most [`REQUEST_LIMIT`] bytes, giving up on one
/// that sends nothing for [`BODY_IDLE_TIMEOUT`].
async fn read_body(mut body: Incoming) -> std::result::Result<Bytes, Box<Reply>> {
    let mut buffered = Vec::new();
    loop {
        match tokio::time::timeout(BODY_IDLE_TIMEOUT, body.frame()).await {
            Err(_) => {
                return Err(Box::new(text(
                    StatusCode::REQUEST_TIMEOUT,
                    "smolvm credentials: request body stalled",
                )))
            }
            Ok(None) => return Ok(Bytes::from(buffered)),
            Ok(Some(Err(_))) => {
                return Err(Box::new(text(
                    StatusCode::BAD_REQUEST,
                    "smolvm credentials: request body could not be read",
                )))
            }
            Ok(Some(Ok(frame))) => {
                if let Ok(data) = frame.into_data() {
                    if buffered.len() + data.len() > REQUEST_LIMIT {
                        return Err(Box::new(text(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            "smolvm credentials: request body exceeds 8 MiB",
                        )));
                    }
                    buffered.extend_from_slice(&data);
                }
            }
        }
    }
}

/// The reply to a request whose bindings were replaced while it was being
/// handled: nothing was sent upstream, and a retry runs under the new ones.
fn bindings_changed() -> Reply {
    text(
        StatusCode::SERVICE_UNAVAILABLE,
        "smolvm credentials: credential bindings changed during the request; retry",
    )
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
                                // A response whose second half comes later and
                                // carries the value named in the path.
                                p if p.starts_with("/slow/") => {
                                    let value = p["/slow/".len()..].to_string();
                                    let parts = futures_util::stream::unfold(0u8, move |step| {
                                        let value = value.clone();
                                        async move {
                                            match step {
                                                0 => Some((
                                                    Ok::<_, BoxError>(Frame::data(
                                                        Bytes::from_static(b"start\n"),
                                                    )),
                                                    1,
                                                )),
                                                1 => {
                                                    tokio::time::sleep(Duration::from_millis(800))
                                                        .await;
                                                    Some((
                                                        Ok(Frame::data(Bytes::from(format!(
                                                            "late {value}\n"
                                                        )))),
                                                        2,
                                                    ))
                                                }
                                                _ => None,
                                            }
                                        }
                                    });
                                    let mut reply = text(StatusCode::OK, "");
                                    *reply.body_mut() = BodyExt::boxed(StreamBody::new(parts));
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
        assert_eq!(response_body(&response), "upstream ok", "{response}");
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

    /// Bindings and the CA change under a running interceptor: a kept
    /// binding keeps substituting with its placeholder, a new one substitutes
    /// on its own host under the new CA, and a removed one stops substituting
    /// from its next request.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn replaced_bindings_take_effect_on_the_next_request() {
        let binding = |name: &str, host: &str| CredentialBinding {
            name: name.into(),
            environment_variable: format!("{}_TOKEN", name.to_uppercase()),
            allowed_hosts: vec![host.into()],
            injection_location: InjectionLocation::default(),
            methods: DEFAULT_METHODS.iter().map(|m| m.to_string()).collect(),
            set_header: None,
        };
        let f = fixture_with_policy(
            CredentialPolicy {
                credentials: vec![binding("svc", CRED_HOST)],
            },
            CRED_HOST,
            StaticResolver::new()
                .with("svc", "svc-secret")
                .with("other", "other-secret"),
        )
        .await;
        let request = |host: &str, placeholder: &str| {
            format!(
                "GET /p HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {placeholder}\r\nConnection: close\r\n\r\n"
            )
        };
        let control = f.interceptor.control();
        let other_placeholder = crate::policy::generate_placeholder("other");
        let wider = MachineCa::generate(
            "test-machine",
            &[CRED_HOST.to_string(), OTHER_HOST.to_string()],
        )
        .unwrap();
        let wider_pem = wider.certificate_pem().to_string();
        control.replace_ca(wider);
        control.replace_bindings(
            CredentialPolicy {
                credentials: vec![binding("svc", CRED_HOST), binding("other", OTHER_HOST)],
            },
            &[
                ("svc".to_string(), f.placeholder.clone()),
                ("other".to_string(), other_placeholder.clone()),
            ]
            .into(),
        );
        let kept = guest_request(
            &f,
            wider_pem.as_bytes(),
            CRED_HOST,
            &request(CRED_HOST, &f.placeholder),
        )
        .await
        .unwrap();
        assert!(kept.starts_with("HTTP/1.1 200"), "{kept}");
        let added = guest_request(
            &f,
            wider_pem.as_bytes(),
            OTHER_HOST,
            &request(OTHER_HOST, &other_placeholder),
        )
        .await
        .unwrap();
        assert!(added.starts_with("HTTP/1.1 200"), "{added}");

        control.replace_bindings(
            CredentialPolicy {
                credentials: vec![binding("other", OTHER_HOST)],
            },
            &[("other".to_string(), other_placeholder.clone())].into(),
        );
        // A value was sent to the removed binding's host, so the host stays
        // terminated (to scrub it) and its placeholder is refused there.
        let removed = guest_request(
            &f,
            wider_pem.as_bytes(),
            CRED_HOST,
            &request(CRED_HOST, &f.placeholder),
        )
        .await
        .unwrap();
        assert!(removed.starts_with("HTTP/1.1 403"), "{removed}");
        assert!(removed.contains("unknown placeholder"), "{removed}");
        let seen = f.upstream.seen.lock().unwrap().clone();
        assert_eq!(
            seen.iter()
                .map(|(auth, _)| auth.as_str())
                .collect::<Vec<_>>(),
            ["Bearer svc-secret", "Bearer other-secret"]
        );
    }

    /// A resolver that holds every resolution until released, so a test can
    /// replace the bindings while a request is between check and send.
    struct GatedResolver {
        entered: std::sync::mpsc::SyncSender<()>,
        release: Mutex<std::sync::mpsc::Receiver<()>>,
    }

    impl CredentialResolver for GatedResolver {
        fn resolve(
            &self,
            _request: &CredentialRequest,
        ) -> std::result::Result<zeroize::Zeroizing<String>, crate::resolver::ResolveError>
        {
            let _ = self.entered.send(());
            let _ = self.release.lock().unwrap().recv();
            Ok(zeroize::Zeroizing::new("value-of-the-old-binding".into()))
        }
    }

    fn svc_policy() -> CredentialPolicy {
        CredentialPolicy {
            credentials: vec![CredentialBinding {
                name: "svc".into(),
                environment_variable: "SVC_TOKEN".into(),
                allowed_hosts: vec![CRED_HOST.into()],
                injection_location: InjectionLocation::default(),
                methods: DEFAULT_METHODS.iter().map(|m| m.to_string()).collect(),
                set_header: None,
            }],
        }
    }

    /// Run one request for `svc` whose resolution is held until `swap` has
    /// changed the bindings, and return the response.
    async fn request_across_a_swap(
        swap: impl FnOnce(&InterceptorControl, &CredentialPolicy, &BTreeMap<String, String>)
            + Send
            + 'static,
    ) -> (String, Fixture) {
        let upstream = start_upstream().await;
        let policy = svc_policy();
        let placeholders = crate::policy::generate_placeholders(&policy);
        let placeholder = placeholders["svc"].clone();
        let ca = MachineCa::generate(
            "test-machine",
            &[CRED_HOST.to_string(), OTHER_HOST.to_string()],
        )
        .unwrap();
        let ca_pem = ca.certificate_pem().to_string();
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let interceptor = Interceptor::spawn(
            InterceptorConfig {
                machine: "test-machine".into(),
                policy: policy.clone(),
                placeholders: placeholders.clone(),
                ca,
                upstream_roots_pem: vec![upstream.cert_pem.clone()],
            },
            Arc::new(GatedResolver {
                entered: entered_tx,
                release: Mutex::new(release_rx),
            }),
        )
        .unwrap();
        let f = Fixture {
            upstream,
            interceptor,
            placeholder: placeholder.clone(),
            ca_pem,
        };
        let control = f.interceptor.control();
        let swapper = std::thread::spawn(move || {
            entered_rx.recv().unwrap();
            swap(&control, &policy, &placeholders);
            release_tx.send(()).unwrap();
        });
        let request = format!(
            "GET /p HTTP/1.1\r\nHost: {CRED_HOST}\r\nAuthorization: Bearer {placeholder}\r\nConnection: close\r\n\r\n"
        );
        let response = guest_request(&f, f.ca_pem.as_bytes(), CRED_HOST, &request)
            .await
            .unwrap();
        swapper.join().unwrap();
        (response, f)
    }

    /// Bindings replaced while a request resolves its value refuse the
    /// request when its own binding changed: the value was resolved by name
    /// and may belong to the binding that replaced the one it was checked
    /// against.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_request_whose_bindings_change_while_it_resolves_is_refused() {
        let (response, f) = request_across_a_swap(|control, policy, placeholders| {
            // The same name, now bound elsewhere.
            let mut moved = policy.clone();
            moved.credentials[0].allowed_hosts = vec![OTHER_HOST.into()];
            control.replace_bindings(moved, placeholders);
        })
        .await;
        assert!(response.starts_with("HTTP/1.1 503"), "{response}");
        assert!(
            response.contains("changed during the request"),
            "{response}"
        );
        assert!(
            f.upstream.seen.lock().unwrap().is_empty(),
            "nothing went upstream"
        );

        // The same binding, but its secret was replaced (not kept).
        let (response, _f) = request_across_a_swap(|control, policy, placeholders| {
            control.replace_bindings(policy.clone(), placeholders);
        })
        .await;
        assert!(response.starts_with("HTTP/1.1 503"), "{response}");
    }

    /// A swap that leaves a request's own binding and its secret alone (an
    /// unrelated addition, an identical re-send) does not disturb it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_swap_that_keeps_the_requests_binding_lets_it_through() {
        let (response, f) = request_across_a_swap(|control, policy, placeholders| {
            let mut more = policy.clone();
            let mut other = more.credentials[0].clone();
            other.name = "other".into();
            other.environment_variable = "OTHER_TOKEN".into();
            other.allowed_hosts = vec![OTHER_HOST.into()];
            more.credentials.push(other);
            let mut placeholders = placeholders.clone();
            placeholders.insert("other".into(), crate::policy::generate_placeholder("other"));
            control.replace_bindings_keeping(more, &placeholders, &["svc".to_string()]);
        })
        .await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert_eq!(
            f.upstream.seen.lock().unwrap()[0].0,
            "Bearer value-of-the-old-binding"
        );
        let (response, _f) = request_across_a_swap(|control, policy, placeholders| {
            control.replace_bindings_keeping(policy.clone(), placeholders, &["svc".to_string()]);
        })
        .await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    }

    /// A body that keeps arriving, however slowly, is read whole; one that
    /// stops is answered `408`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn only_an_idle_request_body_times_out() {
        let f = fixture().await;
        let send = |gaps: Vec<u64>| {
            let endpoint = f.interceptor.endpoint();
            let upstream = f.upstream.addr;
            let ca_pem = f.ca_pem.clone();
            let placeholder = f.placeholder.clone();
            async move {
                let mut tcp = TcpStream::connect(endpoint.addr).await.unwrap();
                tcp.write_all(&endpoint.preamble(upstream)).await.unwrap();
                let mut verdict = [0u8; 1];
                tcp.read_exact(&mut verdict).await.unwrap();
                let connector = TlsConnector::from(client_config(ca_pem.as_bytes()));
                let mut tls = connector
                    .connect(ServerName::try_from(CRED_HOST.to_string()).unwrap(), tcp)
                    .await
                    .unwrap();
                let chunks = gaps.len() + 1;
                tls.write_all(
                    format!(
                        "POST /p HTTP/1.1\r\nHost: {CRED_HOST}\r\nAuthorization: Bearer {placeholder}\r\nContent-Length: {chunks}\r\nConnection: close\r\n\r\nx"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
                for gap in gaps {
                    tokio::time::sleep(Duration::from_millis(gap)).await;
                    if tls.write_all(b"x").await.is_err() {
                        break;
                    }
                }
                let mut out = Vec::new();
                let _ = tls.read_to_end(&mut out).await;
                String::from_utf8_lossy(&out).into_owned()
            }
        };
        // Four 300 ms gaps: longer than the idle limit in all, never idle.
        let slow = send(vec![300, 300, 300, 300]).await;
        assert!(slow.starts_with("HTTP/1.1 200"), "{slow}");
        let stalled = send(vec![900]).await;
        assert!(stalled.starts_with("HTTP/1.1 408"), "{stalled}");
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

    /// Body of a raw HTTP/1.1 response, chunked or not.
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

    /// A resolver whose value a test can rotate.
    struct RotatingResolver(Mutex<String>);

    impl CredentialResolver for RotatingResolver {
        fn resolve(
            &self,
            _request: &CredentialRequest,
        ) -> std::result::Result<zeroize::Zeroizing<String>, crate::resolver::ResolveError>
        {
            Ok(zeroize::Zeroizing::new(self.0.lock().unwrap().clone()))
        }
    }

    /// Bindings replaced with a new secret are looked up again before the
    /// next response from their host is checked, so a value supplied with the
    /// replacement is scrubbed even from a request that injects nothing, and
    /// the value before it still is.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_replaced_secret_is_scrubbed_before_any_request_injects_it() {
        let upstream = start_upstream().await;
        let policy = svc_policy();
        let placeholders = crate::policy::generate_placeholders(&policy);
        let ca = MachineCa::generate("test-machine", &[CRED_HOST.to_string()]).unwrap();
        let ca_pem = ca.certificate_pem().to_string();
        let resolver = Arc::new(RotatingResolver(Mutex::new("ghp_firstsecret1111".into())));
        let interceptor = Interceptor::spawn(
            InterceptorConfig {
                machine: "test-machine".into(),
                policy: policy.clone(),
                placeholders: placeholders.clone(),
                ca,
                upstream_roots_pem: vec![upstream.cert_pem.clone()],
            },
            resolver.clone(),
        )
        .unwrap();
        let f = Fixture {
            upstream,
            interceptor,
            placeholder: placeholders["svc"].clone(),
            ca_pem,
        };
        let echo = |value: &str| {
            format!(
                "GET /echo HTTP/1.1\r\nHost: {CRED_HOST}\r\nAuthorization: {value}\r\nConnection: close\r\n\r\n"
            )
        };
        let first = guest_request(
            &f,
            f.ca_pem.as_bytes(),
            CRED_HOST,
            &echo("ghp_firstsecret1111"),
        )
        .await
        .unwrap();
        assert!(!first.contains("ghp_firstsecret1111"), "{first}");

        *resolver.0.lock().unwrap() = "ghp_secondsecret2222".into();
        f.interceptor
            .control()
            .replace_bindings(policy, &placeholders);
        for value in ["ghp_secondsecret2222", "ghp_firstsecret1111"] {
            let response = guest_request(&f, f.ca_pem.as_bytes(), CRED_HOST, &echo(value))
                .await
                .unwrap();
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
            assert!(!response.contains(value), "{value}: {response}");
        }
    }

    /// A host a binding stops covering, because the binding was removed or
    /// moved to other hosts, may have stored a value sent to it: its responses
    /// are still scrubbed of that value. A host no value was ever sent to is
    /// relayed untouched again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_host_a_binding_left_is_still_scrubbed_of_what_it_was_sent() {
        let echo = |value: &str| {
            format!(
                "GET /echo HTTP/1.1\r\nHost: {CRED_HOST}\r\nAuthorization: {value}\r\nConnection: close\r\n\r\n"
            )
        };
        let moved = CredentialPolicy {
            credentials: vec![CredentialBinding {
                allowed_hosts: vec![OTHER_HOST.into()],
                ..svc_policy().credentials[0].clone()
            }],
        };
        for next in [CredentialPolicy::default(), moved] {
            let f = fixture_with_secret("ghp_retiredsecret4321").await;
            let sent = format!(
                "GET /echo HTTP/1.1\r\nHost: {CRED_HOST}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
                f.placeholder
            );
            let first = guest_request(&f, f.ca_pem.as_bytes(), CRED_HOST, &sent)
                .await
                .unwrap();
            assert!(first.starts_with("HTTP/1.1 200"), "{first}");
            let placeholders = crate::policy::generate_placeholders(&next);
            f.interceptor
                .control()
                .replace_bindings(next.clone(), &placeholders);
            // The guest stored the value upstream; reading it back finds it gone.
            let response = guest_request(
                &f,
                f.ca_pem.as_bytes(),
                CRED_HOST,
                &echo("ghp_retiredsecret4321"),
            )
            .await
            .unwrap();
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
            assert!(
                !response.contains("ghp_retiredsecret4321"),
                "{next:?}: {response}"
            );
            assert!(response.contains("[smolvm-redacted]"), "{response}");
            // Nothing is injected there any more.
            let refused = guest_request(&f, f.ca_pem.as_bytes(), CRED_HOST, &sent)
                .await
                .unwrap();
            assert!(!refused.starts_with("HTTP/1.1 200"), "{refused}");
        }

        // A binding that never resolved anything leaves its host to the guest.
        let f = fixture_with_secret("ghp_neversent00000").await;
        f.interceptor
            .control()
            .replace_bindings(CredentialPolicy::default(), &BTreeMap::new());
        assert!(
            guest_request(&f, f.ca_pem.as_bytes(), CRED_HOST, &echo("x"))
                .await
                .is_err(),
            "relayed untouched: the upstream's own certificate is not the machine CA"
        );
    }

    /// The values kept for hosts bindings left are bounded, but the hosts
    /// are not forgotten: one stays intercepted however many values came
    /// and went after it, never spliced through again.
    #[test]
    fn retired_values_are_bounded_and_their_hosts_kept() {
        let ca = MachineCa::generate("test-machine", &[CRED_HOST.to_string()]).unwrap();
        let policy = svc_policy();
        let placeholders = crate::policy::generate_placeholders(&policy);
        let interceptor = Interceptor::spawn(
            InterceptorConfig {
                machine: "test-machine".into(),
                policy: policy.clone(),
                placeholders: placeholders.clone(),
                ca,
                upstream_roots_pem: Vec::new(),
            },
            Arc::new(StaticResolver::new()),
        )
        .unwrap();
        let control = interceptor.control();
        let moved = |host: &str| CredentialPolicy {
            credentials: vec![CredentialBinding {
                allowed_hosts: vec![host.to_string()],
                ..policy.credentials[0].clone()
            }],
        };
        // The first host a value was sent to, then many values elsewhere.
        control.0.remember(
            "svc",
            u64::MAX,
            Some(&zeroize::Zeroizing::new("first-value-0000".into())),
        );
        control.replace_bindings(moved(OTHER_HOST), &placeholders);
        for round in 0..(MAX_RETIRED_VALUES * 2) {
            let value = zeroize::Zeroizing::new(format!("secret-value-{round:04}"));
            control.0.remember("svc", u64::MAX, Some(&value));
            control.replace_bindings(CredentialPolicy::default(), &BTreeMap::new());
            control.replace_bindings(moved(OTHER_HOST), &placeholders);
        }
        let retired = control.0.retired.lock().unwrap();
        assert_eq!(retired.values.len(), MAX_RETIRED_VALUES);
        assert!(!retired
            .values
            .iter()
            .any(|(_, v)| v.as_str() == "first-value-0000"));
        drop(retired);
        assert!(
            control.0.has_retired(CRED_HOST),
            "its values evicted, the first host is still intercepted"
        );
        assert!(control.0.intercepts(CRED_HOST));
    }

    /// A TLS connection spliced through untouched to a host no binding
    /// covered stays open until a binding covers that host: the change ends
    /// it before it takes effect, so nothing injected toward the host can be
    /// read back on a connection nothing checks. New connections to the host
    /// are intercepted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_spliced_connection_ends_before_its_host_is_intercepted() {
        let f = fixture().await;
        let mut tcp = TcpStream::connect(f.interceptor.endpoint().addr)
            .await
            .unwrap();
        tcp.write_all(&f.interceptor.endpoint().preamble(f.upstream.addr))
            .await
            .unwrap();
        let mut verdict = [0xffu8; 1];
        tcp.read_exact(&mut verdict).await.unwrap();
        // Spliced: only the upstream's own certificate is trusted.
        let connector = TlsConnector::from(client_config(&f.upstream.cert_pem));
        let name = ServerName::try_from(OTHER_HOST.to_string()).unwrap();
        let mut tls = connector.connect(name, tcp).await.unwrap();
        let request = format!("GET /public HTTP/1.1\r\nHost: {OTHER_HOST}\r\n\r\n");
        tls.write_all(request.as_bytes()).await.unwrap();
        let mut first = vec![0u8; 4096];
        let n = tls.read(&mut first).await.unwrap();
        assert!(String::from_utf8_lossy(&first[..n]).starts_with("HTTP/1.1 200"));

        let control = f.interceptor.control();
        let wider =
            MachineCa::generate("test-machine", &[CRED_HOST.into(), OTHER_HOST.into()]).unwrap();
        let wider_pem = wider.certificate_pem().to_string();
        control.replace_ca(wider);
        let other = CredentialPolicy {
            credentials: vec![CredentialBinding {
                name: "other".into(),
                allowed_hosts: vec![OTHER_HOST.into()],
                ..svc_policy().credentials[0].clone()
            }],
        };
        let placeholders = crate::policy::generate_placeholders(&other);
        tokio::task::spawn_blocking(move || control.replace_bindings(other, &placeholders))
            .await
            .unwrap();

        // The old connection is gone: nothing more comes back on it.
        let _ = tls.write_all(request.as_bytes()).await;
        let mut rest = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(5), tls.read_to_end(&mut rest))
            .await
            .expect("the spliced connection was closed");
        assert!(
            read.is_err() || !String::from_utf8_lossy(&rest).contains("HTTP/1.1"),
            "{rest:?}"
        );
        assert!(f
            .interceptor
            .state
            .spliced
            .lock()
            .unwrap()
            .iter()
            .all(|s| *s.ended.lock().unwrap()));
        // And a new one to the host is terminated with the machine CA.
        let fresh = guest_request(
            &f,
            wider_pem.as_bytes(),
            OTHER_HOST,
            &format!("GET /public HTTP/1.1\r\nHost: {OTHER_HOST}\r\nConnection: close\r\n\r\n"),
        )
        .await
        .unwrap();
        assert!(fresh.starts_with("HTTP/1.1 200"), "{fresh}");
    }

    /// A value bound while a response streams (a long poll, an event stream)
    /// is scrubbed from the rest of that response.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_value_bound_mid_response_is_scrubbed_from_the_rest() {
        let upstream = start_upstream().await;
        let policy = svc_policy();
        let placeholders = crate::policy::generate_placeholders(&policy);
        let ca = MachineCa::generate("test-machine", &[CRED_HOST.to_string()]).unwrap();
        let ca_pem = ca.certificate_pem().to_string();
        let resolver = Arc::new(RotatingResolver(Mutex::new("ghp_earlysecret1111".into())));
        let interceptor = Interceptor::spawn(
            InterceptorConfig {
                machine: "test-machine".into(),
                policy: policy.clone(),
                placeholders: placeholders.clone(),
                ca,
                upstream_roots_pem: vec![upstream.cert_pem.clone()],
            },
            resolver.clone(),
        )
        .unwrap();
        let f = Fixture {
            upstream,
            interceptor,
            placeholder: placeholders["svc"].clone(),
            ca_pem,
        };
        let late = "ghp_latesecret22222";
        let request =
            format!("GET /slow/{late} HTTP/1.1\r\nHost: {CRED_HOST}\r\nConnection: close\r\n\r\n");
        let control = f.interceptor.control();
        let (response, ()) = tokio::join!(
            guest_request(&f, f.ca_pem.as_bytes(), CRED_HOST, &request),
            async {
                // While the response waits for its second half, a new
                // secret is bound to the host.
                tokio::time::sleep(Duration::from_millis(300)).await;
                *resolver.0.lock().unwrap() = late.into();
                let (policy, placeholders) = (policy.clone(), placeholders.clone());
                tokio::task::spawn_blocking(move || {
                    control.replace_bindings(policy, &placeholders)
                })
                .await
                .unwrap();
            }
        );
        let response = response.unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.contains("start"), "{response}");
        assert!(!response.contains(late), "{response}");
        assert!(
            response.contains("[smolvm-redacted]") || response.contains(&f.placeholder),
            "{response}"
        );
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
