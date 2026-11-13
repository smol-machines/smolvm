//! The public adapter owns no workloads; each workload has one private supervisor.
//! Socket activation owns the public listener, so an idle adapter can disappear.

use std::os::fd::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::Request;
use axum::response::{IntoResponse, Response};
use hyper_util::rt::TokioIo;

use super::{
    util::{ApiError, ApiResult},
    Engine, EngineConfig,
};

const IDLE: Duration = Duration::from_secs(10);

pub(crate) struct Activity {
    active: AtomicUsize,
    last: parking_lot::Mutex<Instant>,
}
impl Default for Activity {
    fn default() -> Self {
        Self {
            active: AtomicUsize::new(0),
            last: parking_lot::Mutex::new(Instant::now()),
        }
    }
}
impl Activity {
    pub(crate) fn hold(self: &Arc<Self>) -> ActivityGuard {
        self.active.fetch_add(1, Ordering::SeqCst);
        ActivityGuard(self.clone())
    }
    fn idle(&self) -> bool {
        self.active.load(Ordering::SeqCst) == 0 && self.last.lock().elapsed() >= IDLE
    }
}
pub(crate) struct ActivityGuard(Arc<Activity>);
impl Drop for ActivityGuard {
    fn drop(&mut self) {
        *self.0.last.lock() = Instant::now();
        self.0.active.fetch_sub(1, Ordering::SeqCst);
    }
}
struct GuardedBody {
    inner: Body,
    _guard: ActivityGuard,
}
impl http_body::Body for GuardedBody {
    type Data = axum::body::Bytes;
    type Error = axum::Error;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        std::pin::Pin::new(&mut self.inner).poll_frame(cx)
    }
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

/// Kernel locks close on process death; PID files are never used as ownership proof.
pub(crate) async fn lock(path: PathBuf) -> std::io::Result<std::fs::File> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)?;
    loop {
        // SAFETY: flock borrows a live descriptor and retains no pointers.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(file);
        }
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::WouldBlock {
            return Err(e);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn worker_socket(config: &EngineConfig, id: &str) -> PathBuf {
    config
        .socket
        .parent()
        .unwrap_or(Path::new("."))
        .join(format!("w-{}.sock", &id[..24]))
}

async fn worker(engine: &Engine, id: &str) -> ApiResult<(tokio::net::UnixStream, std::fs::File)> {
    if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ApiError::bad_request("invalid container ID"));
    }
    let path = worker_socket(&engine.config, id);
    let spawn = lock(engine.config.root.join(format!("spawn-{id}.lock")))
        .await
        .map_err(internal)?;
    if let Ok(s) = tokio::net::UnixStream::connect(&path).await {
        return Ok((s, spawn));
    }
    use std::os::unix::process::CommandExt;
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(engine.store.container_dir(id).join("supervisor.log"))
        .map_err(internal)?;
    let mut cmd = std::process::Command::new(std::env::current_exe().map_err(internal)?);
    cmd.args(["engine", "supervise", "--id", id, "--socket"])
        .arg(&engine.config.socket)
        .arg("--root")
        .arg(&engine.config.root)
        .stdin(std::process::Stdio::null())
        .stdout(log.try_clone().map_err(internal)?)
        .stderr(log);
    // SAFETY: setsid is async-signal-safe and the child immediately execs.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn().map_err(internal)?;
    // Reap the child while this adapter exists; its lifetime is otherwise independent.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Ok(s) = tokio::net::UnixStream::connect(&path).await {
            std::thread::spawn(move || {
                let _ = child.wait();
            });
            return Ok((s, spawn));
        }
        if let Some(status) = child.try_wait().map_err(internal)? {
            return Err(ApiError::internal(format!(
                "workload supervisor exited: {status}"
            )));
        }
        if Instant::now() >= deadline {
            return Err(ApiError::internal(
                "workload supervisor did not become ready",
            ));
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
fn internal(e: impl std::fmt::Display) -> ApiError {
    ApiError::internal(e.to_string())
}

pub(crate) async fn forward(engine: &Engine, id: &str, mut req: Request) -> ApiResult<Response> {
    let (stream, spawn) = worker(engine, id).await?;
    let peer = req
        .extensions()
        .get::<axum::extract::ConnectInfo<Peer>>()
        .map(|p| p.0.clone());
    let upgrade = super::stream::wants_upgrade(&req).then(|| hyper::upgrade::on(&mut req));
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(internal)?;
    tokio::spawn(async move {
        let _ = connection.with_upgrades().await;
    });
    // The spawn/exit gate stays held until the supervisor has accepted this
    // connection; connection ownership then prevents an idle-exit race.
    let probe = Request::builder()
        .uri("/_ping")
        .body(Body::empty())
        .map_err(internal)?;
    let probe = sender.send_request(probe).await.map_err(internal)?;
    axum::body::to_bytes(Body::new(probe.into_body()), 64)
        .await
        .map_err(internal)?;
    drop(spawn);
    let mut response = sender.send_request(req).await.map_err(internal)?;
    if response.status() == axum::http::StatusCode::SWITCHING_PROTOCOLS {
        let backend = hyper::upgrade::on(&mut response);
        let activity = engine.activity.hold();
        tokio::spawn(async move {
            let _activity = activity;
            if let Some(frontend) = upgrade {
                if let (Ok(front), Ok(back)) = tokio::join!(frontend, backend) {
                    let (mut front, mut back) = (TokioIo::new(front), TokioIo::new(back));
                    tokio::select! {
                        _ = tokio::io::copy_bidirectional(&mut front, &mut back) => {},
                        _ = async { match peer { Some(p) => p.closed().await, None => std::future::pending().await } } => {},
                    }
                }
            }
        });
    }
    Ok(response.map(Body::new))
}

pub(crate) async fn dispatch(
    engine: Arc<Engine>,
    mut req: Request,
    next: axum::middleware::Next,
) -> Response {
    let guard = engine.activity.hold();
    req.extensions_mut().insert(engine.activity.clone());
    let result = dispatch_inner(&engine, req, next)
        .await
        .unwrap_or_else(IntoResponse::into_response);
    let (parts, body) = result.into_parts();
    Response::from_parts(
        parts,
        Body::new(GuardedBody {
            inner: body,
            _guard: guard,
        }),
    )
}

fn component(value: &str) -> ApiResult<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hi = bytes.get(i + 1).and_then(|b| (*b as char).to_digit(16));
            let lo = bytes.get(i + 2).and_then(|b| (*b as char).to_digit(16));
            let (Some(hi), Some(lo)) = (hi, lo) else {
                return Err(ApiError::bad_request("invalid escaped container name"));
            };
            decoded.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            decoded.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(decoded).map_err(|_| ApiError::bad_request("container name is not UTF-8"))
}

async fn dispatch_inner(
    engine: &Arc<Engine>,
    mut req: Request,
    next: axum::middleware::Next,
) -> ApiResult<Response> {
    engine.refresh().map_err(internal)?;
    if engine.owner.is_some() {
        return Ok(next.run(req).await);
    }
    let path = req.uri().path().to_string();
    let mut target = None;
    if let Some(rest) = path.strip_prefix("/containers/") {
        let id = rest.split('/').next().unwrap_or("");
        let collection = matches!(
            (req.method().as_str(), rest),
            ("POST", "create" | "prune") | ("GET", "json")
        );
        if !collection {
            let suffix = &rest[id.len()..];
            let name = component(id)?;
            let id = engine
                .find_container(&name)
                .ok_or_else(|| ApiError::no_such_container(&name))?
                .id();
            // Canonical IDs also avoid static route collisions for names such
            // as "create" when the supervisor receives DELETE /containers/{id}.
            let query = req
                .uri()
                .query()
                .map(|q| format!("?{q}"))
                .unwrap_or_default();
            *req.uri_mut() = format!("/containers/{id}{suffix}{query}")
                .parse()
                .map_err(internal)?;
            target = Some(id);
        }
    } else if let Some(rest) = path.strip_prefix("/exec/") {
        let id = rest.split('/').next().unwrap_or("");
        if id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()) {
            if let Ok(bytes) = std::fs::read(engine.store.object_path("execs", id)) {
                if let Ok(record) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                    if let Some(cid) = record["ContainerID"].as_str() {
                        if path.ends_with("/json") {
                            return Ok(axum::Json(record).into_response());
                        }
                        target = Some(cid.to_string());
                    }
                }
            }
        }
    } else if path == "/commit" {
        target = axum::extract::Query::<std::collections::HashMap<String, String>>::try_from_uri(
            req.uri(),
        )
        .ok()
        .and_then(|q| q.get("container").cloned())
        .and_then(|id| engine.find_container(&id))
        .map(|c| c.id());
    } else if path.starts_with("/networks/")
        && (path.ends_with("/connect") || path.ends_with("/disconnect"))
    {
        let (parts, body) = req.into_parts();
        let bytes = axum::body::to_bytes(body, 1 << 20)
            .await
            .map_err(internal)?;
        let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(internal)?;
        target = value["Container"]
            .as_str()
            .and_then(|id| engine.find_container(id))
            .map(|c| c.id());
        req = Request::from_parts(parts, Body::from(bytes));
    }
    if let Some(id) = target {
        return forward(engine, &id, req).await;
    }
    Ok(next.run(req).await)
}

/// Adopt the listener owned by the OS instead of unlinking its socket.
fn activated_listener() -> std::io::Result<Option<tokio::net::UnixListener>> {
    #[cfg(target_os = "linux")]
    let fd = {
        if std::env::var("LISTEN_PID").ok().as_deref() != Some(&std::process::id().to_string()) {
            return Ok(None);
        }
        if std::env::var("LISTEN_FDS").ok().as_deref() != Some("1") {
            return Err(std::io::Error::other("expected one activation socket"));
        }
        3
    };
    #[cfg(target_os = "macos")]
    let fd = {
        unsafe extern "C" {
            fn launch_activate_socket(
                name: *const libc::c_char,
                fds: *mut *mut libc::c_int,
                count: *mut libc::size_t,
            ) -> libc::c_int;
        }
        let mut fds = std::ptr::null_mut();
        let mut count = 0;
        // SAFETY: valid output pointers; launchd allocates the descriptor array.
        let result = unsafe { launch_activate_socket(c"Docker".as_ptr(), &mut fds, &mut count) };
        if result == libc::ESRCH || result == libc::ENOENT {
            return Ok(None);
        }
        if result != 0 {
            return Err(std::io::Error::from_raw_os_error(result));
        }
        if count != 1 {
            return Err(std::io::Error::other("expected one activation socket"));
        }
        // SAFETY: successful call returned exactly one descriptor and a malloc-owned array.
        unsafe {
            let fd = *fds;
            libc::free(fds.cast());
            fd
        }
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    return Ok(None);
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        // SAFETY: the service manager transferred this listener to this process.
        let socket = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
        socket.set_nonblocking(true)?;
        // Do not leak the activation listener into workload supervisors.
        unsafe {
            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        }
        Ok(Some(tokio::net::UnixListener::from_std(socket)?))
    }
}

pub(super) async fn serve(config: EngineConfig, owner: Option<String>) -> crate::Result<()> {
    std::fs::create_dir_all(&config.root)?;
    if owner
        .as_ref()
        .is_some_and(|id| id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err(crate::Error::config("supervisor", "invalid container ID"));
    }
    let role = owner.clone().unwrap_or_else(|| "adapter".into());
    let _singleton = lock(config.root.join(format!("{role}.lock"))).await?;
    let socket = owner
        .as_ref()
        .map(|id| worker_socket(&config, id))
        .unwrap_or_else(|| config.socket.clone());
    let activated = if owner.is_none() {
        activated_listener()?
    } else {
        None
    };
    let os_owned = activated.is_some();
    let listener = match activated {
        Some(l) => l,
        None => super::bind_socket(&socket)?,
    };
    let engine = Engine::open(config, owner)?;
    if engine.owner.is_some() {
        super::containers::recover(&engine).await;
        super::warm::spawn_reaper(&engine);
    } else {
        std::fs::write(
            engine.config.root.join("engine.pid"),
            std::process::id().to_string(),
        )?;
    }
    let app = super::api::router(engine.clone());
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let e = engine.clone();
    let exit_socket = socket.clone();
    let shutdown = async move {
        loop {
            tokio::select! {
                _ = term.recv() => return None,
                _ = tokio::signal::ctrl_c() => return None,
                _ = tokio::time::sleep(Duration::from_millis(200)) => {
                    let running = e.owner.as_deref().and_then(|id|e.find_container(id)).is_some_and(|c|c.is_running() || c.record().state.status=="restarting");
                    if !running && !super::warm::has_live_dependents(&e) && e.activity.idle() {
                        if let Some(id) = &e.owner {
                            if let Ok(gate) = lock(e.config.root.join(format!("spawn-{id}.lock"))).await {
                                let warm = e.clone();
                                if e.activity.idle() && tokio::task::spawn_blocking(move || super::warm::prepare_idle_exit(&warm)).await.unwrap_or(false) {
                                    let _ = std::fs::remove_file(&exit_socket);
                                    return Some(gate);
                                }
                            }
                        } else { return None; }
                    }
                }
            }
        }
    };
    // On an explicit stop, bound the drain: an events stream may never end.
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let listener = Connections {
        listener,
        activity: engine.owner.as_ref().map(|_| engine.activity.clone()),
    };
    let server = axum::serve(listener, app.into_make_service_with_connect_info::<Peer>())
        .with_graceful_shutdown(async {
            let _ = stopped.await;
        });
    let mut server = std::pin::pin!(std::future::IntoFuture::into_future(server));
    let _exit_gate = tokio::select! {
        result = &mut server => { result?; None },
        gate = shutdown => { let _ = stop.send(()); let _ = tokio::time::timeout(Duration::from_secs(5), &mut server).await; gate }
    };
    if engine.owner.is_some() {
        super::containers::shutdown_all(&engine).await;
        super::warm::shutdown(&engine).await;
    }
    if !os_owned {
        let _ = std::fs::remove_file(socket);
    }
    if engine.owner.is_none() {
        let _ = std::fs::remove_file(engine.config.root.join("engine.pid"));
    }
    Ok(())
}

// Private supervisor connections last for one forwarded request/stream. Counting
// them closes the gap between connecting and dispatching the first HTTP request.
struct Connections {
    listener: tokio::net::UnixListener,
    activity: Option<Arc<Activity>>,
}
struct Connection {
    stream: tokio::net::UnixStream,
    peer: Peer,
    _activity: Option<ActivityGuard>,
}
impl axum::serve::Listener for Connections {
    type Io = Connection;
    type Addr = tokio::net::unix::SocketAddr;
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.listener.accept().await {
                Ok((stream, addr)) => {
                    // SAFETY: duplicate a live Unix socket; ownership moves into File.
                    let fd = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
                    if fd < 0 {
                        tracing::warn!(error=%std::io::Error::last_os_error(), "duplicate client socket");
                        continue;
                    }
                    let peer = Peer(Arc::new(unsafe { std::fs::File::from_raw_fd(fd) }));
                    return (
                        Connection {
                            stream,
                            peer,
                            _activity: self.activity.as_ref().map(|a| a.hold()),
                        },
                        addr,
                    );
                }
                Err(error) => {
                    tracing::warn!(%error, "accept API connection");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }
    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}
impl tokio::io::AsyncRead for Connection {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}
impl tokio::io::AsyncWrite for Connection {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// A duplicate descriptor avoids FD-reuse races while observing a disconnected
/// Unix client; POLLHUP distinguishes full close from a stdin half-close.
#[derive(Clone)]
pub(crate) struct Peer(Arc<std::fs::File>);
impl Peer {
    fn is_closed(&self) -> bool {
        let mut poll = libc::pollfd {
            fd: self.0.as_raw_fd(),
            // Darwin reports a full disconnect on write readiness; read EOF
            // alone also occurs when a client only closes stdin.
            events: libc::POLLOUT,
            revents: 0,
        };
        // SAFETY: poll receives one initialized pollfd and does not retain it.
        unsafe {
            libc::poll(&mut poll, 1, 0);
        }
        poll.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0
    }
    pub(crate) async fn closed(&self) {
        while !self.is_closed() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}
impl axum::extract::connect_info::Connected<axum::serve::IncomingStream<'_, Connections>> for Peer {
    fn connect_info(stream: axum::serve::IncomingStream<'_, Connections>) -> Self {
        stream.io().peer.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stdin_half_close_does_not_discard_pending_output() {
        use std::os::fd::IntoRawFd;
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        let peer = Peer(Arc::new(unsafe {
            std::fs::File::from_raw_fd(a.into_raw_fd())
        }));
        assert!(!peer.is_closed());
        b.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(!peer.is_closed(), "stdin EOF must not cancel stdout");
        drop(b);
        assert!(
            peer.is_closed(),
            "a disconnected client must release the supervisor"
        );
    }
}
