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
    // Connecting happens after the host watch is registered.
    let mut peer = accept(&listener);
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
