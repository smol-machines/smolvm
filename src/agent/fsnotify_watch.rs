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
const GUEST_VIRTIOFS_ROOT: &str = "/mnt/virtiofs";

/// How long to coalesce a burst of change events before sending. An editor save
/// typically emits several events (write, close, attrib); batching de-dupes them
/// into one round-trip while keeping latency well under a human-perceptible
/// reload delay.
const COALESCE_WINDOW: Duration = Duration::from_millis(25);

/// A single watched mount: host source directory → guest virtiofs staging base.
struct WatchTarget {
    host_source: PathBuf,
    /// e.g. `/mnt/virtiofs/smolvm0`
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
        // Opt-out escape hatch: setting SMOL_NO_HOT_RELOAD disables host FS
        // watching entirely (e.g. very large trees, or privacy preference).
        if std::env::var_os("SMOL_NO_HOT_RELOAD").is_some() {
            return None;
        }

        // Only directories can be recursively watched; a file-target mount (rare)
        // is skipped. Read-only mounts are still watched: the host may edit them
        // (that is exactly the read-only-source hot-reload case).
        let targets: Vec<WatchTarget> = mounts
            .iter()
            .enumerate()
            .filter(|(_, m)| m.source.is_dir())
            .map(|(i, m)| WatchTarget {
                host_source: m.source.clone(),
                guest_base: format!("{GUEST_VIRTIOFS_ROOT}/smolvm{i}"),
            })
            .collect();
        if targets.is_empty() {
            return None;
        }

        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = stop.clone();
        let handle = std::thread::Builder::new()
            .name("fsnotify-watch".into())
            .spawn(move || run_watch(socket_path, targets, stop_thread))
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
fn run_watch(socket_path: PathBuf, targets: Vec<WatchTarget>, stop: Arc<AtomicBool>) {
    let (tx, rx) = mpsc::channel::<notify::Result<Event>>();

    let mut watcher = match notify::recommended_watcher(move |res| {
        // The receiver is dropped only when this thread exits, so a send error
        // just means we're shutting down.
        let _ = tx.send(res);
    }) {
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
    let mut client = match AgentClient::connect_with_retry(&socket_path) {
        Ok(c) => c,
        Err(e) => {
            debug!(error = %e, "fsnotify watcher could not connect to agent; disabled");
            return;
        }
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

/// Translate one host event into guest-side [`FsNotifyEvent`]s, appended to `out`.
fn collect_events(event: &Event, targets: &[WatchTarget], out: &mut Vec<FsNotifyEvent>) {
    for host_path in &event.paths {
        let Some(t) = targets
            .iter()
            .find(|t| host_path.starts_with(&t.host_source))
        else {
            continue;
        };
        let Ok(rel) = host_path.strip_prefix(&t.host_source) else {
            continue;
        };
        // The watched root itself firing (empty rel) carries no useful child.
        if rel.as_os_str().is_empty() {
            continue;
        }

        if host_path.exists() {
            // Create/modify/attrib on an existing path: fire directly on it.
            // fsnotify_dentry() in the guest propagates to the parent dir's
            // watchers with the child name, so both file- and dir-watches fire.
            out.push(FsNotifyEvent {
                path: join_guest(&t.guest_base, rel),
                mask: mask_for(&event.kind, host_path),
            });
        } else if let Some(parent) = rel.parent() {
            // Deleted / moved away: the exact path no longer resolves in the
            // guest, so fire a MODIFY on the (still-present) parent directory.
            // Directory watchers re-scan and observe the removal.
            out.push(FsNotifyEvent {
                path: join_guest(&t.guest_base, parent),
                mask: fsnotify_mask::FS_MODIFY | fsnotify_mask::FS_ISDIR,
            });
        }
    }
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
            guest_base: "/mnt/virtiofs/smolvm0".to_string(),
        }
    }

    #[test]
    fn join_guest_maps_relative_paths() {
        assert_eq!(
            join_guest("/mnt/virtiofs/smolvm0", Path::new("src/app.js")),
            "/mnt/virtiofs/smolvm0/src/app.js"
        );
        assert_eq!(
            join_guest("/mnt/virtiofs/smolvm0", Path::new("")),
            "/mnt/virtiofs/smolvm0"
        );
    }

    #[test]
    fn deleted_path_fires_parent_dir_modify() {
        // A path that does not exist on disk maps to a MODIFY on its parent.
        let targets = vec![target()];
        let ev = Event {
            kind: EventKind::Remove(notify::event::RemoveKind::File),
            paths: vec![PathBuf::from("/host/project/src/gone.js")],
            attrs: Default::default(),
        };
        let mut out = Vec::new();
        collect_events(&ev, &targets, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].path, "/mnt/virtiofs/smolvm0/src");
        assert_eq!(
            out[0].mask & fsnotify_mask::FS_MODIFY,
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
}
