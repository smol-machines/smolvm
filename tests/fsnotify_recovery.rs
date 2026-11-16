//! Real host watcher and Unix-socket fault injection without booting a VM.
#![cfg(unix)]

use smolvm::agent::FsNotifyWatcher;
use smolvm_protocol::{encode_message, AgentRequest, AgentResponse, Envelope, FsNotifyEvent};
use std::collections::HashSet;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::{Duration, Instant};

fn accept(listener: &UnixListener) -> UnixStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                return stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "watcher did not connect");
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("accept watcher: {error}"),
        }
    }
}

fn request(peer: &mut UnixStream) -> Vec<FsNotifyEvent> {
    let mut header = [0; 4];
    peer.read_exact(&mut header).unwrap();
    let length = u32::from_be_bytes(header) as usize;
    assert!(length < 1024 * 1024, "unbounded notification frame");
    let mut frame = vec![0; length];
    peer.read_exact(&mut frame).unwrap();
    let message: Envelope<AgentRequest> = serde_json::from_slice(&frame).unwrap();
    let AgentRequest::FsNotify { events } = message.body else {
        panic!("unexpected request: {:?}", message.body)
    };
    assert!(events.len() <= 256, "unbounded notification batch");
    events
}

fn wait_for_notifications(peer: &mut UnixStream, source: &Path, tag: &str) {
    use std::sync::atomic::{AtomicBool, Ordering};
    let done = AtomicBool::new(false);
    let deadline = Instant::now() + Duration::from_secs(4);
    let expected = format!("/run/smolvm/virtiofs/{tag}/watch-ready");
    // An agent connection can precede registration of a later mount. Observe
    // actual delivery instead of treating socket acceptance as watch readiness.
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let mut revision = 0;
            while !done.load(Ordering::SeqCst) && Instant::now() < deadline {
                std::fs::write(source.join("watch-ready"), revision.to_string()).unwrap();
                revision += 1;
                std::thread::sleep(Duration::from_millis(25));
            }
        });
        loop {
            let events = request(peer);
            peer.write_all(&encode_message(&AgentResponse::Ok { data: None }).unwrap())
                .unwrap();
            if events.iter().any(|event| event.path == expected) {
                done.store(true, Ordering::SeqCst);
                break;
            }
            assert!(
                Instant::now() < deadline,
                "mount notifications never became ready"
            );
        }
    });
}

fn watcher(root: &Path, source: &Path, after_fork: bool) -> FsNotifyWatcher {
    if std::env::var_os("RUST_LOG").is_some() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .try_init();
    }
    let mounts = [(source.to_owned(), "smolvm0".into())];
    if after_fork {
        FsNotifyWatcher::start_tagged_after_fork(root.join("agent.sock"), mounts)
    } else {
        FsNotifyWatcher::start_tagged(root.join("agent.sock"), mounts)
    }
    .unwrap()
}

#[test]
fn an_immediate_edit_is_replayed_when_the_guest_has_not_booted_yet() {
    immediate_edit(false);
}

#[cfg(target_os = "macos")]
#[test]
fn polling_replays_an_immediate_edit_to_a_cold_guest() {
    immediate_edit(true);
}

fn immediate_edit(after_fork: bool) {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    std::fs::create_dir(&source).unwrap();
    for index in 0..10_000 {
        std::fs::write(source.join(format!("file-{index}")), b"before").unwrap();
    }
    // Choose the end of the OS directory order: an asynchronous initial scan
    // used to absorb this edit into its baseline and never tell the guest.
    let target = std::fs::read_dir(&source)
        .unwrap()
        .last()
        .unwrap()
        .unwrap()
        .path();
    let started = Instant::now();
    let watcher = watcher(root.path(), &source, after_fork);
    assert!(started.elapsed() < Duration::from_secs(10));
    std::fs::write(&target, b"after").unwrap();
    // Startup must finish without an agent socket or an acknowledgement.
    let listener = UnixListener::bind(root.path().join("agent.sock")).unwrap();
    let mut peer = accept(&listener);
    let expected = format!(
        "/run/smolvm/virtiofs/smolvm0/{}",
        target.file_name().unwrap().to_str().unwrap()
    );
    loop {
        let events = request(&mut peer);
        peer.write_all(&encode_message(&AgentResponse::Ok { data: None }).unwrap())
            .unwrap();
        if events.iter().any(|event| event.path == expected) {
            break;
        }
        assert!(started.elapsed() < Duration::from_secs(15));
    }
    drop(watcher);
}

#[test]
fn distinct_changes_survive_a_lost_agent_connection() {
    distinct_changes(false);
}

#[cfg(target_os = "macos")]
#[test]
fn polling_changes_survive_a_lost_agent_connection() {
    distinct_changes(true);
}

fn distinct_changes(after_fork: bool) {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    std::fs::create_dir(&source).unwrap();
    let listener = UnixListener::bind(root.path().join("agent.sock")).unwrap();
    let watcher = watcher(root.path(), &source, after_fork);
    let mut peer = accept(&listener);
    wait_for_notifications(&mut peer, &source, "smolvm0");
    std::fs::write(source.join("first"), b"pending").unwrap();
    assert!(!request(&mut peer).is_empty()); // Deliberately do not acknowledge.
    for index in 0..512 {
        std::fs::write(source.join(format!("file-{index}")), b"latest").unwrap();
    }
    std::thread::sleep(Duration::from_millis(150));
    drop(peer);
    let mut peer = accept(&listener);
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut seen = HashSet::new();
    loop {
        let events = request(&mut peer);
        seen.extend(events.into_iter().map(|event| event.path));
        peer.write_all(&encode_message(&AgentResponse::Ok { data: None }).unwrap())
            .unwrap();
        if seen.contains("/run/smolvm/virtiofs/smolvm0/first")
            && (0..512)
                .all(|index| seen.contains(&format!("/run/smolvm/virtiofs/smolvm0/file-{index}")))
        {
            break;
        }
        assert!(Instant::now() < deadline, "pending changes were lost");
    }
    drop(watcher);
}

#[test]
fn an_agent_that_never_answers_cannot_hold_up_watcher_shutdown() {
    unanswered_shutdown(false);
}

#[cfg(target_os = "macos")]
#[test]
fn an_agent_that_never_answers_cannot_hold_up_polling_shutdown() {
    unanswered_shutdown(true);
}

fn unanswered_shutdown(after_fork: bool) {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    std::fs::create_dir(&source).unwrap();
    let listener = UnixListener::bind(root.path().join("agent.sock")).unwrap();
    let watcher = watcher(root.path(), &source, after_fork);
    let mut peer = accept(&listener);
    wait_for_notifications(&mut peer, &source, "smolvm0");
    std::fs::write(source.join("first"), b"pending").unwrap();
    assert!(!request(&mut peer).is_empty());
    let stop = Instant::now();
    drop(watcher); // Keep the peer open, but never answer its pending RPC.
    assert!(stop.elapsed() < Duration::from_secs(3));
}

#[test]
fn a_full_host_queue_does_not_deadlock_the_os_watcher_destructor() {
    full_queue_shutdown(false);
}

#[cfg(target_os = "macos")]
#[test]
fn a_full_host_queue_does_not_deadlock_the_polling_watcher_destructor() {
    full_queue_shutdown(true);
}

fn full_queue_shutdown(after_fork: bool) {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    std::fs::create_dir(&source).unwrap();
    let watcher = watcher(root.path(), &source, after_fork);
    std::thread::sleep(Duration::from_millis(250));
    for index in 0..1024 {
        std::fs::write(source.join(format!("file-{index}")), b"pending").unwrap();
    }
    // Also let macOS's polling callback encounter the full queue.
    std::thread::sleep(Duration::from_millis(1250));
    let stop = Instant::now();
    drop(watcher);
    assert!(stop.elapsed() < Duration::from_secs(3));
}

#[test]
fn a_busy_first_mount_does_not_prevent_later_mounts_from_registering() {
    busy_mount_registration(false);
}

#[cfg(target_os = "macos")]
#[test]
fn polling_registers_later_mounts_while_the_first_mount_changes() {
    busy_mount_registration(true);
}

fn busy_mount_registration(after_fork: bool) {
    let root = tempfile::tempdir().unwrap();
    let sources: Vec<_> = (0..16)
        .map(|index| {
            let source = root.path().join(format!("mount-{index}"));
            std::fs::create_dir(&source).unwrap();
            source
        })
        .collect();
    let listener = UnixListener::bind(root.path().join("agent.sock")).unwrap();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            for index in 0..2048 {
                std::fs::write(sources[0].join(format!("file-{index}")), b"changed").unwrap();
            }
        });
        let mounts = sources
            .iter()
            .enumerate()
            .map(|(index, path)| (path.clone(), format!("smolvm{index}")));
        let watcher = if after_fork {
            FsNotifyWatcher::start_tagged_after_fork(root.path().join("agent.sock"), mounts)
        } else {
            FsNotifyWatcher::start_tagged(root.path().join("agent.sock"), mounts)
        }
        .unwrap();
        let mut peer = accept(&listener);
        wait_for_notifications(&mut peer, &sources[15], "smolvm15");
        wait_for_notifications(&mut peer, &sources[0], "smolvm0");
        let shutdown = Instant::now();
        drop(watcher);
        assert!(shutdown.elapsed() < Duration::from_secs(3));
    });
}

#[test]
fn a_disconnected_guest_recovers_a_large_burst_including_removed_names() {
    overflow_recovery(false);
}

#[cfg(target_os = "macos")]
#[test]
fn polling_recovers_a_large_burst_including_removed_names() {
    overflow_recovery(true);
}

fn overflow_recovery(after_fork: bool) {
    use smolvm_protocol::fsnotify_mask;
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    std::fs::create_dir(&source).unwrap();
    for index in 0..512 {
        std::fs::write(source.join(format!("remove-{index}")), b"before").unwrap();
        std::fs::write(source.join(format!("modify-{index}")), b"before").unwrap();
    }
    let listener = UnixListener::bind(root.path().join("agent.sock")).unwrap();
    let watcher = watcher(root.path(), &source, after_fork);
    let mut peer = accept(&listener);
    wait_for_notifications(&mut peer, &source, "smolvm0");
    std::fs::write(source.join("held"), b"pending").unwrap();
    // Hold the acknowledgement during the burst.
    assert!(!request(&mut peer).is_empty());
    // The unavailable guest cannot accept reconnects while the burst is being
    // written. Otherwise this mock queues connections that have already timed
    // out by accept(), and BSD rejects setting options on those dead sockets.
    drop(listener);
    for index in 0..20_000 {
        std::fs::write(source.join(format!("create-{index}")), b"new").unwrap();
    }
    for index in 0..512 {
        std::fs::remove_file(source.join(format!("remove-{index}"))).unwrap();
        std::fs::write(source.join(format!("modify-{index}")), b"after").unwrap();
    }
    drop(peer);
    std::fs::remove_file(root.path().join("agent.sock")).unwrap();
    let listener = UnixListener::bind(root.path().join("agent.sock")).unwrap();
    let mut peer = accept(&listener);
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut created = HashSet::new();
    let mut modified = HashSet::new();
    let mut removed = HashSet::new();
    while created.len() < 20_000 || modified.len() < 512 || removed.len() < 512 {
        for event in request(&mut peer) {
            let name = event.path.rsplit('/').next().unwrap();
            if name.starts_with("create-") && event.mask & fsnotify_mask::FS_CREATE != 0 {
                created.insert(name.to_owned());
            } else if name.starts_with("modify-") && event.mask & fsnotify_mask::FS_MODIFY != 0 {
                modified.insert(name.to_owned());
            } else if name.starts_with("remove-") && event.mask & fsnotify_mask::FS_DELETE != 0 {
                removed.insert(name.to_owned());
            }
        }
        peer.write_all(&encode_message(&AgentResponse::Ok { data: None }).unwrap())
            .unwrap();
        assert!(
            Instant::now() < deadline,
            "incomplete recovery: {} creates, {} modifies, {} removals",
            created.len(),
            modified.len(),
            removed.len()
        );
    }
    let shutdown = Instant::now();
    drop(watcher);
    assert!(shutdown.elapsed() < Duration::from_secs(3));
}
