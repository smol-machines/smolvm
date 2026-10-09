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
//! The watcher is best-effort and self-contained: if the kernel lacks the patch,
//! or the connection drops when the VM exits, propagation simply stops — the
//! mount still serves reads. Dropping [`FsNotifyWatcher`] stops the thread.

use crate::agent::AgentClient;
use crate::data::storage::HostMount;
use notify::{Event, EventKind, RecursiveMode, Watcher};
use smolvm_protocol::{fsnotify_mask, FsNotifyEvent};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Guest mountpoint root for virtiofs devices. MUST match the agent's
/// `paths::VIRTIOFS_MOUNT_ROOT` — the agent stages each `-v` device at
/// `<root>/smolvm{index}` and binds it into the container, so events fired on
/// that path reach the container's bind of the same inode.
const GUEST_VIRTIOFS_ROOT: &str = "/run/smolvm/virtiofs";

/// How long to coalesce a burst of change events before sending. An editor save
/// typically emits several events (write, close, attrib); batching de-dupes them
/// into one round-trip while keeping latency well under a human-perceptible
/// reload delay.
const COALESCE_WINDOW: Duration = Duration::from_millis(25);
/// Watcher startup is independent of VM readiness. Poll in short increments so
/// a failed launch can tear down immediately instead of joining a sleeping
/// exponential-backoff thread.
const CONNECT_RETRY_INTERVAL: Duration = Duration::from_millis(50);
const CONNECT_RETRY_LIMIT: usize = 200;

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
        // Opt-out escape hatch: setting SMOL_NO_HOT_RELOAD disables host FS
        // watching entirely (e.g. very large trees, or privacy preference).
        if std::env::var_os("SMOL_NO_HOT_RELOAD").is_some() {
            return None;
        }

        // Only directories can be recursively watched; a file-target mount (rare)
        // is skipped. Read-only mounts are still watched: the host may edit them
        // (that is exactly the read-only-source hot-reload case).
        let targets: Vec<WatchTarget> = mounts
            .into_iter()
            .filter(|(source, _)| source.is_dir())
            .map(|(host_source, tag)| WatchTarget {
                host_source,
                guest_base: format!("{GUEST_VIRTIOFS_ROOT}/{tag}"),
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

fn run_watch(socket_path: PathBuf, targets: Vec<WatchTarget>, stop: Arc<AtomicBool>, poll: bool) {
    let (tx, rx) = mpsc::channel::<notify::Result<Event>>();

    // The receiver is dropped only when this thread exits, so a send error
    // just means we're shutting down.
    let handler = move |res| {
        let _ = tx.send(res);
    };
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
            return;
        }
    };

    for t in &targets {
        if let Err(e) = watcher.watch(&t.host_source, RecursiveMode::Recursive) {
            warn!(path = %t.host_source.display(), error = %e, "failed to watch mount source");
        }
    }

    // A dedicated connection so injected events never interleave with the
    // command's own request/response stream on the primary connection.
    let mut client = match connect_to_agent(&socket_path, &stop) {
        Some(client) => client,
        None => return,
    };

    info!(
        mounts = targets.len(),
        "host→guest fsnotify propagation active (hot-reload)"
    );

    while !stop.load(Ordering::SeqCst) {
        // Block briefly so we notice `stop` without a busy loop.
        let first = match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(Ok(ev)) => ev,
            Ok(Err(_)) => continue, // watcher-level error event; ignore
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        };

        let mut batch = Vec::new();
        collect_events(&first, &targets, &mut batch);

        // Coalesce the rest of the burst (a save fans out into several events).
        let deadline = std::time::Instant::now() + COALESCE_WINDOW;
        while let Some(remaining) = deadline.checked_duration_since(std::time::Instant::now()) {
            match rx.recv_timeout(remaining) {
                Ok(Ok(ev)) => collect_events(&ev, &targets, &mut batch),
                Ok(Err(_)) => {}
                Err(_) => break,
            }
        }

        if batch.is_empty() {
            continue;
        }
        dedup(&mut batch);

        if let Err(e) = client.fsnotify(batch) {
            // The VM has almost certainly gone away (the command exited). Stop
            // quietly rather than spinning on a dead socket.
            debug!(error = %e, "fsnotify inject failed; stopping watcher");
            break;
        }
    }
}

fn connect_to_agent(socket_path: &Path, stop: &AtomicBool) -> Option<AgentClient> {
    let mut last_error = None;
    for _ in 0..CONNECT_RETRY_LIMIT {
        if stop.load(Ordering::SeqCst) {
            return None;
        }
        match AgentClient::connect(socket_path) {
            Ok(client) => return Some(client),
            Err(error) => last_error = Some(error),
        }
        std::thread::sleep(CONNECT_RETRY_INTERVAL);
    }
    if let Some(error) = last_error {
        debug!(%error, "fsnotify watcher could not connect to agent; disabled");
    }
    None
}

/// Maximum depth to inspect for recent file modifications when a directory event fires.
const MAX_DIR_SCAN_DEPTH: usize = 3;

/// Maximum number of recent child events to emit from a single directory event
/// to avoid flooding vsock if a large directory is touched.
const MAX_DIR_SCAN_EVENTS: usize = 64;

/// Time window within which a file's mtime is considered to match the event.
const RECENT_MTIME_WINDOW: Duration = Duration::from_secs(2);

/// Directories that should not be traversed during directory rescans.
fn is_ignored_dir(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | "node_modules"
            | "target"
            | "dist"
            | "build"
            | ".next"
            | ".cache"
            | ".turbo"
            | ".venv"
            | "__pycache__"
    )
}

/// Recursively find files within `dir` modified within `threshold`.
fn find_recent_files(
    dir: &Path,
    threshold: Duration,
    max_depth: usize,
    results: &mut Vec<PathBuf>,
) {
    if max_depth == 0 || results.len() >= MAX_DIR_SCAN_EVENTS {
        return;
    }

    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };

    let now = std::time::SystemTime::now();

    for entry in entries.flatten() {
        if results.len() >= MAX_DIR_SCAN_EVENTS {
            break;
        }

        let Ok(file_type) = entry.file_type() else {
            continue;
        };

        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();

        if file_type.is_dir() {
            if is_ignored_dir(&name_str) {
                continue;
            }
            find_recent_files(&entry.path(), threshold, max_depth - 1, results);
        } else if file_type.is_file() || file_type.is_symlink() {
            if let Ok(meta) = entry.metadata() {
                if let Ok(mtime) = meta.modified() {
                    let is_recent = if let Ok(elapsed) = now.duration_since(mtime) {
                        elapsed <= threshold
                    } else if let Ok(future) = mtime.duration_since(now) {
                        future <= threshold
                    } else {
                        false
                    };

                    if is_recent {
                        results.push(entry.path());
                    }
                }
            }
        }
    }
}

/// Translate one host event into guest-side [`FsNotifyEvent`]s, appended to `out`.
fn collect_events(event: &Event, targets: &[WatchTarget], out: &mut Vec<FsNotifyEvent>) {
    for host_path in &event.paths {
        let Some(t) = matching_target(host_path, targets) else {
            continue;
        };
        let Ok(rel) = host_path.strip_prefix(&t.host_source) else {
            continue;
        };

        if host_path.exists() {
            if host_path.is_dir() {
                // On macOS, FSEvents often notifies at the directory level rather
                // than reporting individual file changes. Scan the directory for
                // files modified within the coalesce window so file-level watchers
                // in the guest (e.g. Vite HMR, Webpack, Chokidar) receive events
                // for the actual changed files rather than only an anonymous
                // directory-level modification.
                let mut recent_files = Vec::new();
                find_recent_files(
                    host_path,
                    RECENT_MTIME_WINDOW,
                    MAX_DIR_SCAN_DEPTH,
                    &mut recent_files,
                );

                for child_path in recent_files {
                    if let Ok(child_rel) = child_path.strip_prefix(&t.host_source) {
                        out.push(FsNotifyEvent {
                            path: join_guest(&t.guest_base, child_rel),
                            mask: mask_for(&event.kind, &child_path),
                        });
                    }
                }

                // If this is a subdirectory (not the watched root itself), also
                // fire on the directory itself so directory-level watchers wake.
                if !rel.as_os_str().is_empty() {
                    out.push(FsNotifyEvent {
                        path: join_guest(&t.guest_base, rel),
                        mask: mask_for(&event.kind, host_path),
                    });
                }
            } else {
                // Regular file: fire directly on it. fsnotify_dentry() in the
                // guest propagates to the parent dir's watchers with the child
                // name, so both file- and dir-watches fire.
                out.push(FsNotifyEvent {
                    path: join_guest(&t.guest_base, rel),
                    mask: mask_for(&event.kind, host_path),
                });
            }
        } else if let Some(parent) = rel.parent() {
            // The guest may still cache the removed path. Send the exact name
            // so the kernel can expire that entry and preserve the filename in
            // directory-watch events, plus the surviving parent as a fallback
            // when the guest had never looked the path up.
            out.push(FsNotifyEvent {
                path: join_guest(&t.guest_base, rel),
                mask: fsnotify_mask::FS_DELETE,
            });
            out.push(FsNotifyEvent {
                path: join_guest(&t.guest_base, parent),
                mask: fsnotify_mask::FS_MODIFY | fsnotify_mask::FS_ISDIR,
            });
        }
    }
}

fn matching_target<'a>(path: &Path, targets: &'a [WatchTarget]) -> Option<&'a WatchTarget> {
    targets
        .iter()
        .filter(|target| path.starts_with(&target.host_source))
        .max_by_key(|target| target.host_source.components().count())
}

/// Join a guest base path with a host-relative path, normalizing separators.
fn join_guest(base: &str, rel: &Path) -> String {
    let rel = rel.to_string_lossy();
    if rel.is_empty() {
        base.to_string()
    } else {
        format!("{base}/{rel}")
    }
}

/// Map a notify [`EventKind`] to the closest `FS_*` mask.
fn mask_for(kind: &EventKind, path: &Path) -> u32 {
    use notify::event::ModifyKind;

    let base = match kind {
        EventKind::Create(_) => fsnotify_mask::FS_CREATE,
        EventKind::Modify(ModifyKind::Metadata(_)) => fsnotify_mask::FS_ATTRIB,
        // A rename whose destination exists reads as a create in the new dir.
        EventKind::Modify(ModifyKind::Name(_)) => fsnotify_mask::FS_CREATE,
        EventKind::Modify(_) => fsnotify_mask::FS_MODIFY,
        // Anything else that left the file present is treated as a content change
        // — the safe default that wakes content watchers.
        _ => fsnotify_mask::FS_MODIFY,
    };

    if path.is_dir() {
        base | fsnotify_mask::FS_ISDIR
    } else {
        base
    }
}

/// Sort + drop duplicate (path, mask) pairs produced within one burst.
fn dedup(batch: &mut Vec<FsNotifyEvent>) {
    batch.sort_by(|a, b| a.path.cmp(&b.path).then(a.mask.cmp(&b.mask)));
    batch.dedup_by(|a, b| a.path == b.path && a.mask == b.mask);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> WatchTarget {
        WatchTarget {
            host_source: PathBuf::from("/host/project"),
            guest_base: "/run/smolvm/virtiofs/smolvm0".to_string(),
        }
    }

    #[test]
    fn join_guest_maps_relative_paths() {
        assert_eq!(
            join_guest("/run/smolvm/virtiofs/smolvm0", Path::new("src/app.js")),
            "/run/smolvm/virtiofs/smolvm0/src/app.js"
        );
        assert_eq!(
            join_guest("/run/smolvm/virtiofs/smolvm0", Path::new("")),
            "/run/smolvm/virtiofs/smolvm0"
        );
    }

    #[test]
    fn deleted_path_expires_exact_name_and_wakes_parent() {
        let targets = vec![target()];
        let ev = Event {
            kind: EventKind::Remove(notify::event::RemoveKind::File),
            paths: vec![PathBuf::from("/host/project/src/gone.js")],
            attrs: Default::default(),
        };
        let mut out = Vec::new();
        collect_events(&ev, &targets, &mut out);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].path, "/run/smolvm/virtiofs/smolvm0/src/gone.js");
        assert_eq!(out[0].mask, fsnotify_mask::FS_DELETE);
        assert_eq!(out[1].path, "/run/smolvm/virtiofs/smolvm0/src");
        assert_eq!(
            out[1].mask & fsnotify_mask::FS_MODIFY,
            fsnotify_mask::FS_MODIFY
        );
    }

    #[test]
    fn path_outside_any_mount_is_ignored() {
        let targets = vec![target()];
        let ev = Event {
            kind: EventKind::Modify(notify::event::ModifyKind::Data(
                notify::event::DataChange::Any,
            )),
            paths: vec![PathBuf::from("/somewhere/else/x.js")],
            attrs: Default::default(),
        };
        let mut out = Vec::new();
        collect_events(&ev, &targets, &mut out);
        assert!(out.is_empty());
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
    fn nested_mount_uses_most_specific_target() {
        let targets = vec![
            WatchTarget {
                host_source: PathBuf::from("/host/project/vendor"),
                guest_base: "/run/smolvm/virtiofs/smolvm1".into(),
            },
            target(),
        ];
        let selected = matching_target(Path::new("/host/project/vendor/lib.js"), &targets)
            .expect("nested path should match");
        assert_eq!(selected.guest_base, "/run/smolvm/virtiofs/smolvm1");
    }

    #[test]
    fn directory_event_uncovers_recent_child_files() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let project_dir = temp_dir.path().to_path_buf();
        let src_dir = project_dir.join("src");
        std::fs::create_dir_all(&src_dir).expect("create src dir");
        let app_file = src_dir.join("app.js");
        std::fs::write(&app_file, "console.log('hello')").expect("write app.js");

        let targets = vec![WatchTarget {
            host_source: project_dir,
            guest_base: "/run/smolvm/virtiofs/smolvm0".into(),
        }];

        let ev = Event {
            kind: EventKind::Modify(notify::event::ModifyKind::Any),
            paths: vec![src_dir],
            attrs: Default::default(),
        };

        let mut out = Vec::new();
        collect_events(&ev, &targets, &mut out);

        // Should contain both the child file event (for Vite/Chokidar) and the directory event
        assert!(
            out.iter()
                .any(|e| e.path == "/run/smolvm/virtiofs/smolvm0/src/app.js"
                    && (e.mask & fsnotify_mask::FS_MODIFY) != 0
                    && (e.mask & fsnotify_mask::FS_ISDIR) == 0),
            "expected file-level event for app.js without FS_ISDIR, got: {out:?}"
        );
        assert!(
            out.iter()
                .any(|e| e.path == "/run/smolvm/virtiofs/smolvm0/src"
                    && (e.mask & fsnotify_mask::FS_ISDIR) != 0),
            "expected directory-level event for src with FS_ISDIR, got: {out:?}"
        );
    }

    #[test]
    fn root_directory_event_uncovers_recent_top_level_files() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let project_dir = temp_dir.path().to_path_buf();
        let config_file = project_dir.join("vite.config.ts");
        std::fs::write(&config_file, "export default {}").expect("write vite.config.ts");

        let targets = vec![WatchTarget {
            host_source: project_dir.clone(),
            guest_base: "/run/smolvm/virtiofs/smolvm0".into(),
        }];

        let ev = Event {
            kind: EventKind::Modify(notify::event::ModifyKind::Any),
            paths: vec![project_dir],
            attrs: Default::default(),
        };

        let mut out = Vec::new();
        collect_events(&ev, &targets, &mut out);

        assert!(
            out.iter()
                .any(|e| e.path == "/run/smolvm/virtiofs/smolvm0/vite.config.ts"
                    && (e.mask & fsnotify_mask::FS_MODIFY) != 0),
            "expected file-level event for top-level vite.config.ts, got: {out:?}"
        );
    }

    #[test]
    fn ignored_directories_are_skipped() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let project_dir = temp_dir.path().to_path_buf();
        let node_modules_dir = project_dir.join("node_modules").join("dep");
        std::fs::create_dir_all(&node_modules_dir).expect("create node_modules");
        let dep_file = node_modules_dir.join("index.js");
        std::fs::write(&dep_file, "module.exports = {}").expect("write dep index.js");

        let targets = vec![WatchTarget {
            host_source: project_dir.clone(),
            guest_base: "/run/smolvm/virtiofs/smolvm0".into(),
        }];

        let ev = Event {
            kind: EventKind::Modify(notify::event::ModifyKind::Any),
            paths: vec![project_dir],
            attrs: Default::default(),
        };

        let mut out = Vec::new();
        collect_events(&ev, &targets, &mut out);

        assert!(
            !out.iter().any(|e| e.path.contains("node_modules")),
            "expected node_modules files to be ignored, got: {out:?}"
        );
    }
}
