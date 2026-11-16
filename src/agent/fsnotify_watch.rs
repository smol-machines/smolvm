//! Host → guest fsnotify propagation for `-v` mounts.
//!
//! virtiofs serves file *contents* to the guest, but it does not deliver
//! host-side change *notifications*. A file-watcher inside the guest (Vite,
//! webpack, nodemon, `inotifywait`) therefore never fires when a mounted file is
//! edited on the host — the classic reason "hot reload doesn't work in a
//! container on macOS". Because smolvm ships its own guest kernel (libkrunfw),
//! we can close this gap end to end:
//!
//! 1. This watcher runs on the host, watching each mounted source directory via
//!    the OS-native mechanism (FSEvents on macOS, inotify on Linux).
//! 2. For every change it maps the host path to the guest-side virtiofs path and
//!    sends it to the agent over a dedicated vsock connection
//!    ([`AgentRequest::FsNotify`]).
//! 3. The agent writes it to `/proc/smolvm-fsnotify` (a libkrunfw kernel patch),
//!    which fires the matching fsnotify event on the guest inode.
//!
//! Because the container's view of a `-v` mount is a bind of the same virtiofs
//! inode, a watcher inside the container wakes up exactly as if the change had
//! happened locally.
//!
//! The watcher is best-effort and follows the VM lifetime: pending changes are
//! bounded and coalesced, and a dropped agent connection is retried. A kernel
//! without the injection hook still serves mount reads. Dropping
//! [`FsNotifyWatcher`] stops the thread.

use crate::agent::AgentClient;
use crate::data::storage::HostMount;
#[cfg(all(test, unix))]
use notify::{Event, EventKind};
use notify::{RecursiveMode, Watcher};
use smolvm_protocol::{fsnotify_mask, FsNotifyEvent};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(test)]
use std::sync::mpsc;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;
#[cfg(test)]
use std::time::Instant;
use tracing::{debug, info, warn};

mod queue;
use queue::{EventQueue, Work};
mod reconcile;
use reconcile::{Change, Sink, Snapshot};

/// Whether host directories are watched at all. Setting SMOL_NO_HOT_RELOAD
/// disables it (e.g. very large trees, or privacy preference); the launcher
/// asks too, since a share may only keep negative entries while it is watched.
pub fn watching_enabled() -> bool {
    std::env::var_os("SMOL_NO_HOT_RELOAD").is_none()
}

/// Guest mountpoint root for virtiofs devices. MUST match the agent's
/// `paths::VIRTIOFS_MOUNT_ROOT` — the agent stages each `-v` device at
/// `<root>/smolvm{index}` and binds it into the container, so events fired on
/// that path reach the container's bind of the same inode.
const GUEST_VIRTIOFS_ROOT: &str = "/run/smolvm/virtiofs";

/// Watcher startup is independent of VM readiness. Poll in short increments so
/// a failed launch can tear down immediately instead of joining a sleeping
/// exponential-backoff thread.
const CONNECT_RETRY_INTERVAL: Duration = Duration::from_millis(50);
const MAX_BATCH_EVENTS: usize = 256;
const CONNECT_TIMEOUT: Duration = Duration::from_millis(250);

/// A single watched mount: host source directory → guest virtiofs staging base.
struct WatchTarget {
    host_source: PathBuf,
    /// e.g. `/run/smolvm/virtiofs/smolvm0`
    guest_base: String,
}

/// Propagates host file changes under `-v` mounts into the guest as fsnotify
/// events for the lifetime of the value. Drop to stop.
pub struct FsNotifyWatcher {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl FsNotifyWatcher {
    /// Start watching the source directory of every mount and replaying changes
    /// into the guest. `mounts` must be in the same order passed to VM start, so
    /// index `i` maps to virtiofs tag `smolvm{i}`.
    ///
    /// Returns `None` (non-fatal) when there is nothing to watch or the watcher
    /// thread can't be spawned — the mount still works, only live change
    /// notifications are unavailable.
    pub fn start(socket_path: PathBuf, mounts: &[HostMount]) -> Option<Self> {
        Self::start_tagged(
            socket_path,
            mounts
                .iter()
                .enumerate()
                // A staged mount intentionally has no live host/guest
                // coherence. Watching it would promise invalidations that the
                // guest-local working copy cannot observe.
                .filter(|(_, mount)| !mount.staged)
                .map(|(i, mount)| (mount.source.clone(), HostMount::mount_tag(i))),
        )
    }

    /// Start a watcher for launch paths that already resolved their virtiofs
    /// tags (notably packed/sidecar VMs).
    #[doc(hidden)]
    pub fn start_tagged(
        socket_path: PathBuf,
        mounts: impl IntoIterator<Item = (PathBuf, String)>,
    ) -> Option<Self> {
        Self::start_with(socket_path, mounts, false)
    }

    /// [`Self::start_tagged`] for a process forked from a multithreaded parent
    /// without exec. On macOS the native watcher (FSEvents) uses CoreFoundation,
    /// which the Objective-C runtime aborts in such a child, so changes are
    /// polled instead. Elsewhere this is the native watcher.
    #[doc(hidden)]
    pub fn start_tagged_after_fork(
        socket_path: PathBuf,
        mounts: impl IntoIterator<Item = (PathBuf, String)>,
    ) -> Option<Self> {
        Self::start_with(socket_path, mounts, cfg!(target_os = "macos"))
    }

    fn start_with(
        socket_path: PathBuf,
        mounts: impl IntoIterator<Item = (PathBuf, String)>,
        poll: bool,
    ) -> Option<Self> {
        if !watching_enabled() {
            return None;
        }

        // Only directories can be recursively watched; a file-target mount (rare)
        // is skipped. Read-only mounts are still watched: the host may edit them
        // (that is exactly the read-only-source hot-reload case).
        let targets: Vec<WatchTarget> = mounts
            .into_iter()
            .filter_map(|(source, tag)| {
                // FSEvents reports resolved paths (e.g. /private/var for
                // /var). Match the same directory even if the caller used an
                // alias; virtiofs holds that directory for the mount lifetime.
                let host_source = source.canonicalize().ok()?;
                host_source.is_dir().then_some(WatchTarget {
                    host_source,
                    guest_base: format!("{GUEST_VIRTIOFS_ROOT}/{tag}"),
                })
            })
            .collect();
        if targets.is_empty() {
            return None;
        }

        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = stop.clone();
        let handle = std::thread::Builder::new()
            .name("fsnotify-watch".into())
            .spawn(move || run_watch(socket_path, targets, stop_thread, poll))
            .ok()?;

        Some(Self {
            stop,
            handle: Some(handle),
        })
    }
}

impl Drop for FsNotifyWatcher {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Watcher thread body: owns the OS watcher + a dedicated agent connection.
/// How often the polling watcher (forked children on macOS) rescans.
const POLL_INTERVAL: Duration = Duration::from_secs(1);

struct StopOnExit(Option<Arc<AtomicBool>>);
impl Drop for StopOnExit {
    fn drop(&mut self) {
        if let Some(stop) = &self.0 {
            stop.store(true, Ordering::SeqCst);
        }
    }
}

fn run_watch(socket_path: PathBuf, targets: Vec<WatchTarget>, stop: Arc<AtomicBool>, poll: bool) {
    run_with_registration(socket_path, targets, stop, move |queue, targets, stop| {
        register_watches(queue, targets, stop, poll)
    });
}

/// Register mounts alongside delivery; native callbacks only mark dirty paths
/// and never wait for the guest or for recovery scans.
fn run_with_registration<R: Send>(
    socket_path: PathBuf,
    targets: Vec<WatchTarget>,
    stop: Arc<AtomicBool>,
    register: impl FnOnce(Arc<EventQueue>, &[WatchTarget], &Arc<AtomicBool>) -> Option<R> + Send,
) {
    let mut snapshot = match Snapshot::new() {
        Ok(snapshot) => snapshot,
        Err(error) => {
            warn!(%error,"cannot initialize host notification recovery");
            return;
        }
    };
    // Prime before installing OS watches, then reconcile once registration is
    // complete to cover changes between the baseline and watch installation.
    // This runs only on the watcher worker, never the VM launch thread.
    let roots = watched_roots(&targets);
    if let Err(error) = snapshot.reconcile(&roots, &stop, |_| true) {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        warn!(%error,"initial host notification snapshot was incomplete");
    }
    let rx = Arc::new(EventQueue::new(stop.clone()));

    std::thread::scope(|scope| {
        let registration = std::thread::Builder::new()
            .name("fsnotify-register".into())
            .spawn_scoped(scope, || {
                // Failed or panicked setup must also release the delivery
                // worker, including while it waits for a cold guest.
                let mut failed = StopOnExit(Some(stop.clone()));
                let watcher = register(rx.clone(), &targets, &stop);
                if watcher.is_some() {
                    failed.0.take();
                    rx.retry_all();
                }
                watcher
            });
        let registration = match registration {
            Ok(handle) => handle,
            Err(error) => {
                warn!(%error, "failed to start host watch registration");
                return;
            }
        };
        // Declared after the handle: on return or unwinding, unblock callbacks
        // before joining setup or destroying its returned OS watcher. The
        // registration thread exits after setup; its result owns the watcher
        // for the rest of this VM's lifetime.
        let _stop_on_exit = StopOnExit(Some(stop.clone()));
        run_delivery(&socket_path, &targets, &stop, &rx, &mut snapshot);
        drop(_stop_on_exit);
        if registration.join().is_err() {
            warn!("host watch registration panicked");
        }
    });
}

fn register_watches(
    queue: Arc<EventQueue>,
    targets: &[WatchTarget],
    stop: &Arc<AtomicBool>,
    poll: bool,
) -> Option<Box<dyn Watcher + Send>> {
    let handler = move |res| queue.push(res);
    let watcher: notify::Result<Box<dyn Watcher + Send>> = if poll {
        notify::PollWatcher::new(
            handler,
            notify::Config::default().with_poll_interval(POLL_INTERVAL),
        )
        .map(|w| Box::new(w) as Box<dyn Watcher + Send>)
    } else {
        notify::recommended_watcher(handler).map(|w| Box::new(w) as Box<dyn Watcher + Send>)
    };
    let mut watcher = match watcher {
        Ok(w) => w,
        Err(e) => {
            warn!(error = %e, "failed to create host fs watcher; hot-reload propagation disabled");
            return None;
        }
    };
    // If a backend panics in watch(), release its callback before unwinding
    // destroys the OS watcher and joins the callback thread.
    let mut failed = StopOnExit(Some(stop.clone()));

    for t in targets {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        if let Err(e) = watcher.watch(&t.host_source, RecursiveMode::Recursive) {
            warn!(path = %t.host_source.display(), error = %e, "failed to watch mount source");
        }
    }
    failed.0.take();
    Some(watcher)
}

fn run_delivery(
    socket_path: &Path,
    targets: &[WatchTarget],
    stop: &AtomicBool,
    rx: &EventQueue,
    snapshot: &mut Snapshot,
) {
    let Some(mut client) = connect_to_agent(socket_path, stop) else {
        return;
    };
    info!(
        mounts = targets.len(),
        "host→guest fsnotify delivery connected (hot-reload)"
    );
    let mut last_error = None;
    while !stop.load(Ordering::SeqCst) {
        let Some(work) = rx.take(Duration::from_millis(200)) else {
            continue;
        };
        let roots = match work {
            Work::All => watched_roots(targets),
            Work::Paths(paths) => paths
                .into_iter()
                .filter(|p| matching_target(p, targets).is_some())
                .collect(),
        };
        if roots.is_empty() {
            continue;
        }
        let sink = Delivery {
            client: &mut client,
            socket_path,
            targets,
            stop,
            batch: Vec::new(),
        };
        match snapshot.reconcile_sink(&roots, stop, sink) {
            Ok(()) => last_error = None,
            Err(error) => {
                if stop.load(Ordering::SeqCst) {
                    return;
                }
                let message = error.to_string();
                if last_error.as_ref() != Some(&message) {
                    warn!(%error,"host file reconciliation incomplete; retrying");
                    last_error = Some(message);
                }
                rx.retry_all();
                // Back off a failing filesystem/database while keeping teardown
                // responsive; permission errors never become synthetic deletes.
                for _ in 0..10 {
                    if stop.load(Ordering::SeqCst) {
                        return;
                    }
                    std::thread::sleep(CONNECT_RETRY_INTERVAL);
                }
            }
        }
    }
}

struct Delivery<'a> {
    client: &'a mut AgentClient,
    socket_path: &'a Path,
    targets: &'a [WatchTarget],
    stop: &'a AtomicBool,
    batch: Vec<FsNotifyEvent>,
}
impl Delivery<'_> {
    fn flush(&mut self) -> bool {
        if self.batch.is_empty() {
            return !self.stop.load(Ordering::SeqCst);
        }
        dedup(&mut self.batch);
        let success = deliver(self.client, &self.batch, self.socket_path, self.stop);
        self.batch.clear();
        success
    }
}
impl Sink for Delivery<'_> {
    fn emit(&mut self, change: Change) -> bool {
        for event in translate_change(change, self.targets) {
            self.batch.push(event);
            if self.batch.len() == MAX_BATCH_EVENTS && !self.flush() {
                return false;
            }
        }
        !self.stop.load(Ordering::SeqCst)
    }
    fn finish(&mut self) -> bool {
        self.flush()
    }
}

fn translate_change(change: Change, targets: &[WatchTarget]) -> Vec<FsNotifyEvent> {
    let (host_path, mask, removed) = match change {
        Change::Present {
            path,
            created,
            directory,
        } => {
            let mask = fsnotify_mask::FS_MODIFY
                | fsnotify_mask::FS_ATTRIB
                | if created { fsnotify_mask::FS_CREATE } else { 0 }
                | if directory {
                    fsnotify_mask::FS_ISDIR
                } else {
                    0
                };
            (path, mask, false)
        }
        Change::Removed { path, directory } => (
            path,
            fsnotify_mask::FS_DELETE
                | if directory {
                    fsnotify_mask::FS_ISDIR
                } else {
                    0
                },
            true,
        ),
    };
    let mut events = Vec::new();
    // Each virtiofs mount has its own guest inode/cache namespace, including
    // repeated or overlapping host sources. Every matching view must wake.
    for target in targets {
        let Ok(relative) = host_path.strip_prefix(&target.host_source) else {
            continue;
        };
        events.push(FsNotifyEvent {
            path: join_guest(&target.guest_base, relative),
            mask,
        });
        if removed {
            if let Some(parent) = relative.parent() {
                events.push(FsNotifyEvent {
                    path: join_guest(&target.guest_base, parent),
                    mask: fsnotify_mask::FS_MODIFY | fsnotify_mask::FS_ISDIR,
                });
            }
        }
    }
    events
}

fn watched_roots(targets: &[WatchTarget]) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    for target in targets {
        if roots
            .iter()
            .any(|root| target.host_source.starts_with(root))
        {
            continue;
        }
        roots.retain(|root| !root.starts_with(&target.host_source));
        roots.push(target.host_source.clone());
    }
    roots
}

fn connect_to_agent(socket_path: &Path, stop: &AtomicBool) -> Option<AgentClient> {
    let mut last_error = None;
    // A cold boot can spend more than ten seconds preparing disks before the
    // guest accepts connections. The VM process owns this watcher: only its
    // shutdown signal, not an arbitrary startup deadline, ends the watch.
    while !stop.load(Ordering::SeqCst) {
        match AgentClient::connect_for_sampling(socket_path, CONNECT_TIMEOUT) {
            Ok(client) => return Some(client),
            Err(error) => last_error = Some(error),
        }
        std::thread::sleep(CONNECT_RETRY_INTERVAL);
    }
    if let Some(error) = last_error {
        debug!(%error, "fsnotify watcher stopped before the agent became available");
    }
    None
}

fn deliver(
    client: &mut AgentClient,
    batch: &[FsNotifyEvent],
    socket_path: &Path,
    stop: &AtomicBool,
) -> bool {
    while !stop.load(Ordering::SeqCst) {
        match client.fsnotify(batch.to_vec()) {
            Ok(()) => return true,
            Err(error) => {
                debug!(%error, "fsnotify connection lost; reconnecting before replaying events");
                std::thread::sleep(CONNECT_RETRY_INTERVAL);
                let Some(next) = connect_to_agent(socket_path, stop) else {
                    return false;
                };
                *client = next;
            }
        }
    }
    false
}

fn matching_target<'a>(path: &Path, targets: &'a [WatchTarget]) -> Option<&'a WatchTarget> {
    targets
        .iter()
        .filter(|target| path.starts_with(&target.host_source))
        .max_by_key(|target| target.host_source.components().count())
}

/// Join a guest base path with a host-relative path, normalizing separators.
fn join_guest(base: &str, rel: &Path) -> String {
    // Host separators differ on Windows; guest paths always use '/'. Keep a
    // literal backslash in a Unix filename instead of replacing it globally.
    let mut path = String::with_capacity(base.len() + rel.as_os_str().len() + 1);
    path.push_str(base);
    for part in rel.components() {
        path.push('/');
        path.push_str(&part.as_os_str().to_string_lossy());
    }
    path
}

/// Sort + drop duplicate (path, mask) pairs produced within one burst.
/// One event per path, carrying every mask the batch had for it: the guest
/// fires all of them from a single write, and expires the entry once.
fn dedup(batch: &mut Vec<FsNotifyEvent>) {
    batch.sort_by(|a, b| a.path.cmp(&b.path));
    batch.dedup_by(|later, kept| {
        if later.path == kept.path {
            kept.mask |= later.mask;
            true
        } else {
            false
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn registration_can_fill_the_queue_before_finishing_without_blocking_delivery() {
        use smolvm_protocol::{encode_message, AgentRequest, AgentResponse, Envelope};
        use std::io::{Read, Write};
        use std::os::unix::net::UnixListener;

        struct OwnedWatch(Arc<AtomicBool>);
        impl Drop for OwnedWatch {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("agent.sock");
        let source = root.path().join("source");
        std::fs::create_dir(&source).unwrap();
        for index in 0..512 {
            std::fs::write(source.join(format!("file-{index}")), b"changed").unwrap();
        }
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let released = Arc::new(AtomicBool::new(false));
        let owned = released.clone();
        let (registered, complete) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            run_with_registration(
                socket,
                vec![WatchTarget {
                    host_source: source,
                    guest_base: "/run/smolvm/virtiofs/smolvm0".into(),
                }],
                stopped,
                move |queue, targets, _| {
                    // Models a backend's callback filling the queue before
                    // watch() can finish registering another mount.
                    for index in 0..512 {
                        let path = targets[0].host_source.join(format!("file-{index}"));
                        std::fs::write(&path, b"changed after baseline").unwrap();
                        queue.push(Ok(Event::new(EventKind::Any).add_path(path)));
                    }
                    registered.send(()).unwrap();
                    Some(OwnedWatch(owned))
                },
            );
        });
        // Own shutdown even if a socket assertion panics.
        let watcher = FsNotifyWatcher {
            stop,
            handle: Some(handle),
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut peer = loop {
            if let Ok((peer, _)) = listener.accept() {
                break peer;
            }
            assert!(Instant::now() < deadline, "registration blocked delivery");
            std::thread::sleep(Duration::from_millis(5));
        };
        peer.set_nonblocking(false).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut seen = std::collections::HashSet::new();
        while seen.len() < 512 {
            let mut header = [0; 4];
            peer.read_exact(&mut header).unwrap();
            let size = u32::from_be_bytes(header) as usize;
            assert!(size < 1024 * 1024);
            let mut frame = vec![0; size];
            peer.read_exact(&mut frame).unwrap();
            let request: Envelope<AgentRequest> = serde_json::from_slice(&frame).unwrap();
            let AgentRequest::FsNotify { events } = request.body else {
                panic!("unexpected request");
            };
            assert!(events.len() <= MAX_BATCH_EVENTS);
            seen.extend(events.into_iter().map(|event| event.path));
            peer.write_all(&encode_message(&AgentResponse::Ok { data: None }).unwrap())
                .unwrap();
        }
        complete.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(!released.load(Ordering::SeqCst));
        for index in 0..512 {
            assert!(seen.contains(&format!("/run/smolvm/virtiofs/smolvm0/file-{index}")));
        }
        drop(watcher);
        assert!(released.load(Ordering::SeqCst));
    }

    #[test]
    fn failed_registration_stops_delivery_waiting_for_an_absent_guest() {
        for panic in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let socket = root.path().join("absent.sock");
            let stop = Arc::new(AtomicBool::new(false));
            let stopped = stop.clone();
            let (finished, done) = mpsc::channel();
            let handle = std::thread::spawn(move || {
                run_with_registration(socket, vec![], stopped, move |_, _, _| {
                    assert!(!panic, "injected backend setup panic");
                    None::<()>
                });
                finished.send(()).unwrap();
            });
            let watcher = FsNotifyWatcher {
                stop,
                handle: Some(handle),
            };
            let result = done.recv_timeout(Duration::from_secs(2));
            drop(watcher);
            result.expect("failed setup left delivery running");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_cold_agent_can_become_ready_after_the_old_ten_second_limit() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("agent.sock");
        let stop = Arc::new(AtomicBool::new(false));
        let worker = {
            let socket = socket.clone();
            let stop = stop.clone();
            std::thread::spawn(move || connect_to_agent(&socket, &stop))
        };
        std::thread::sleep(Duration::from_millis(10_500));
        let waiting = !worker.is_finished();
        let listener = std::os::unix::net::UnixListener::bind(socket).unwrap();
        let connected = worker.join().unwrap();
        assert!(waiting, "watcher abandoned a VM that was still booting");
        assert!(connected.is_some());
        drop(listener);
    }

    #[cfg(unix)]
    #[test]
    fn a_lost_connection_replays_the_pending_events() {
        use smolvm_protocol::{encode_message, AgentRequest, AgentResponse, Envelope};
        use std::io::{Read, Write};
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("agent.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let mut client = AgentClient::connect(&socket).unwrap();
        let (peer, _) = listener.accept().unwrap();
        drop(peer); // A connection accepted before the guest was ready went away.
        let stop = Arc::new(AtomicBool::new(false));
        let server = {
            let stop = stop.clone();
            std::thread::spawn(move || {
                struct Stop(Arc<AtomicBool>);
                impl Drop for Stop {
                    fn drop(&mut self) {
                        self.0.store(true, Ordering::SeqCst);
                    }
                }
                let _stop = Stop(stop);
                listener.set_nonblocking(true).unwrap();
                let deadline = Instant::now() + Duration::from_secs(3);
                let mut peer = loop {
                    if let Ok((peer, _)) = listener.accept() {
                        break peer;
                    }
                    assert!(Instant::now() < deadline, "watcher did not reconnect");
                    std::thread::sleep(Duration::from_millis(5));
                };
                // BSD accepts inherit O_NONBLOCK from the listener.
                peer.set_nonblocking(false).unwrap();
                peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                let mut header = [0; 4];
                peer.read_exact(&mut header).unwrap();
                let mut frame = vec![0; u32::from_be_bytes(header) as usize];
                peer.read_exact(&mut frame).unwrap();
                let request: Envelope<AgentRequest> = serde_json::from_slice(&frame).unwrap();
                let AgentRequest::FsNotify { events } = request.body else {
                    panic!("expected fsnotify")
                };
                assert_eq!(events.len(), 1);
                assert_eq!(events[0].path, "/run/smolvm/virtiofs/smolvm0/first.tar");
                peer.write_all(&encode_message(&AgentResponse::Ok { data: None }).unwrap())
                    .unwrap();
            })
        };
        assert!(deliver(
            &mut client,
            &[FsNotifyEvent {
                path: "/run/smolvm/virtiofs/smolvm0/first.tar".into(),
                mask: fsnotify_mask::FS_CREATE,
            }],
            &socket,
            &stop
        ));
        server.join().unwrap();
    }

    #[test]
    fn an_agent_that_never_reads_has_a_bounded_notification_write() {
        let (stream, peer) = crate::platform::uds::UdsStream::pair().unwrap();
        stream.as_socket().set_send_buffer_size(4096).unwrap();
        peer.as_socket().set_recv_buffer_size(4096).unwrap();
        stream.set_write_timeout(Some(CONNECT_TIMEOUT)).unwrap();
        let mut client = AgentClient::from_stream(stream);
        let started = Instant::now();
        let error = client
            .fsnotify(vec![
                FsNotifyEvent {
                    path: format!("/run/smolvm/virtiofs/smolvm0/{}", "x".repeat(4000)),
                    mask: fsnotify_mask::FS_MODIFY,
                };
                MAX_BATCH_EVENTS
            ])
            .unwrap_err();
        assert!(error.to_string().contains("write progress"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn shutting_down_the_vm_cancels_waiting_for_its_agent() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("absent.sock");
        let stop = Arc::new(AtomicBool::new(false));
        let worker = {
            let stop = stop.clone();
            std::thread::spawn(move || connect_to_agent(&socket, &stop))
        };
        std::thread::sleep(Duration::from_millis(100));
        let start = Instant::now();
        stop.store(true, Ordering::SeqCst);
        assert!(worker.join().unwrap().is_none());
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    fn target() -> WatchTarget {
        WatchTarget {
            host_source: PathBuf::from("/host/project"),
            guest_base: "/run/smolvm/virtiofs/smolvm0".to_string(),
        }
    }

    #[test]
    fn join_guest_maps_relative_paths() {
        assert_eq!(
            join_guest(
                "/run/smolvm/virtiofs/smolvm0",
                &Path::new("src").join("app.js")
            ),
            "/run/smolvm/virtiofs/smolvm0/src/app.js"
        );
        assert_eq!(
            join_guest("/run/smolvm/virtiofs/smolvm0", Path::new("")),
            "/run/smolvm/virtiofs/smolvm0"
        );
    }

    #[test]
    fn dedup_collapses_duplicate_events() {
        let mut batch = vec![
            FsNotifyEvent {
                path: "/a".into(),
                mask: fsnotify_mask::FS_MODIFY,
            },
            FsNotifyEvent {
                path: "/a".into(),
                mask: fsnotify_mask::FS_MODIFY,
            },
        ];
        dedup(&mut batch);
        assert_eq!(batch.len(), 1);
    }

    #[test]
    fn dedup_merges_the_masks_of_one_path() {
        let mut batch = vec![
            FsNotifyEvent {
                path: "/a".into(),
                mask: fsnotify_mask::FS_CREATE,
            },
            FsNotifyEvent {
                path: "/b".into(),
                mask: fsnotify_mask::FS_MODIFY,
            },
            FsNotifyEvent {
                path: "/a".into(),
                mask: fsnotify_mask::FS_MODIFY,
            },
        ];
        dedup(&mut batch);
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].path, "/a");
        assert_eq!(
            batch[0].mask,
            fsnotify_mask::FS_CREATE | fsnotify_mask::FS_MODIFY
        );
    }

    #[test]
    fn nested_mounts_receive_changes_in_each_guest_view() {
        let targets = vec![
            WatchTarget {
                host_source: "/host/project/vendor".into(),
                guest_base: "/run/smolvm/virtiofs/smolvm1".into(),
            },
            target(),
        ];
        let events = translate_change(
            Change::Present {
                path: "/host/project/vendor/lib.js".into(),
                created: false,
                directory: false,
            },
            &targets,
        );
        assert_eq!(events.len(), 2);
        assert!(events
            .iter()
            .any(|e| e.path == "/run/smolvm/virtiofs/smolvm0/vendor/lib.js"));
        assert!(events
            .iter()
            .any(|e| e.path == "/run/smolvm/virtiofs/smolvm1/lib.js"));
        assert_eq!(
            watched_roots(&targets),
            vec![PathBuf::from("/host/project")]
        );
    }
    #[test]
    fn repeated_host_sources_receive_changes_in_each_guest_view() {
        let targets = vec![
            target(),
            WatchTarget {
                host_source: "/host/project".into(),
                guest_base: "/run/smolvm/virtiofs/smolvm1".into(),
            },
        ];
        let events = translate_change(
            Change::Present {
                path: "/host/project/app.js".into(),
                created: false,
                directory: false,
            },
            &targets,
        );
        assert_eq!(events.len(), 2);
        assert!(events
            .iter()
            .any(|e| e.path == "/run/smolvm/virtiofs/smolvm0/app.js"));
        assert!(events
            .iter()
            .any(|e| e.path == "/run/smolvm/virtiofs/smolvm1/app.js"));
        assert_eq!(
            watched_roots(&targets),
            vec![PathBuf::from("/host/project")]
        );
    }

    #[test]
    fn removed_names_invalidate_the_exact_entry_and_wake_the_parent() {
        let events = translate_change(
            Change::Removed {
                path: "/host/project/src/removed.js".into(),
                directory: false,
            },
            &[target()],
        );
        assert_eq!(events.len(), 2);
        assert_eq!(
            events[0].path,
            "/run/smolvm/virtiofs/smolvm0/src/removed.js"
        );
        assert_eq!(events[0].mask, fsnotify_mask::FS_DELETE);
        assert_eq!(events[1].path, "/run/smolvm/virtiofs/smolvm0/src");
    }
    #[test]
    fn changes_outside_the_mount_do_not_reach_the_guest() {
        assert!(translate_change(
            Change::Removed {
                path: "/outside/x".into(),
                directory: false
            },
            &[target()]
        )
        .is_empty());
    }
}
