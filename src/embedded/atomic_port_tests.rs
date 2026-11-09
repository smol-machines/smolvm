//! The control peer injects failures; runtimes, persistence and TCP listeners are real.
use super::*;
use smolvm_network::acceptor::{BoundTcpPorts, TcpAcceptorSet};
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::mpsc;
use std::time::Duration;

#[derive(Clone, Copy)]
enum Failure {
    Rejected,
    LostReply,
    Database,
}

fn request(listener: &UnixListener) -> (UnixStream, String) {
    let (mut stream, _) = listener.accept().unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut request = String::new();
    stream.read_to_string(&mut request).unwrap();
    (stream, request)
}

fn failed_publisher(failure: Failure, replace: bool) {
    let temp = tempfile::Builder::new()
        .prefix("smol-ports-")
        .tempdir_in("/tmp")
        .unwrap();
    std::env::set_var("SMOLVM_TEST_VM_CACHE_ROOT", temp.path());
    let name = "atomic-ports";
    let vm_dir = crate::agent::vm_data_dir(name);
    std::fs::create_dir_all(&vm_dir).unwrap();
    let db_path = temp.path().join("state.db");
    let db = SmolvmDb::open_at(&db_path).unwrap();
    let mut record = crate::VmRecord::new(name.into(), 1, 256, vec![], vec![], false);
    record.state = RecordState::Running;
    db.insert_vm(name, &record).unwrap();
    if matches!(failure, Failure::Database) {
        // Only A's update fails. B's publication must still commit.
        rusqlite::Connection::open(&db_path)
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER reject_a BEFORE UPDATE ON vms
                 WHEN json_extract(CAST(NEW.data AS TEXT), '$.ports[0][1]') = 8000
                 BEGIN SELECT RAISE(ABORT, 'injected database failure'); END;",
            )
            .unwrap();
    }

    let agent = UnixListener::bind(vm_dir.join("agent.sock")).unwrap();
    let (probe_tx, probe_rx) = mpsc::channel();
    let agent_thread = std::thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = agent.accept().unwrap();
            let mut len = [0; 4];
            stream.read_exact(&mut len).unwrap();
            let mut payload = vec![0; u32::from_be_bytes(len) as usize];
            stream.read_exact(&mut payload).unwrap();
            probe_tx.send(()).unwrap();
            stream
                .write_all(
                    &smolvm_protocol::encode_message(&smolvm_protocol::AgentResponse::Pong {
                        version: smolvm_protocol::PROTOCOL_VERSION,
                        capabilities: vec![],
                    })
                    .unwrap(),
                )
                .unwrap();
        }
    });
    let live = Arc::new(
        TcpAcceptorSet::start(BoundTcpPorts::bind(&[]).unwrap(), Box::new(|_| {})).unwrap(),
    );
    let ports = UnixListener::bind(vm_dir.join(smolvm_network::PORTS_SOCKET)).unwrap();
    let (allocated_tx, allocated_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let server_live = live.clone();
    let replacement = if replace {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        Some((listener.local_addr().unwrap().port(), 8001))
    } else {
        None
    };
    let server = std::thread::spawn(move || {
        let (mut first, req) = request(&ports);
        assert_eq!(req, "allocate 8000\n");
        let allocation = if matches!(failure, Failure::Rejected) {
            None
        } else {
            Some(server_live.publish_atomic(8000).unwrap())
        };
        allocated_tx.send(()).unwrap();
        release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        match failure {
            Failure::Rejected => first
                .write_all(b"error: injected allocation failure\n")
                .unwrap(),
            Failure::LostReply => {} // Bound, but the reply never reached A.
            Failure::Database => {
                let mapping = allocation.unwrap();
                writeln!(first, "ok {}:{}", mapping.host, mapping.guest).unwrap();
            }
        }
        drop(first);
        if !matches!(failure, Failure::Rejected) {
            let (mut rollback, req) = request(&ports);
            assert!(
                req.trim().is_empty(),
                "A must finish rollback before B mutates: {req}"
            );
            server_live.replace(&[]).unwrap();
            rollback.write_all(b"ok\n").unwrap();
        }
        let (mut second, req) = request(&ports);
        if let Some((host, guest)) = replacement {
            assert_eq!(req, format!("{host}:{guest}\n"));
            server_live
                .replace(&[smolvm_network::PortMapping::new(host, guest)])
                .unwrap();
            second.write_all(b"ok\n").unwrap();
        } else {
            assert_eq!(req, "allocate 8001\n");
            let mapping = server_live.publish_atomic(8001).unwrap();
            writeln!(second, "ok {}:{}", mapping.host, mapping.guest).unwrap();
        }
    });

    // Separate runtime instances AND independent SQLite connection pools.
    let a = EmbeddedRuntime::with_db(SmolvmDb::open_at(&db_path).unwrap());
    let b = EmbeddedRuntime::with_db(SmolvmDb::open_at(&db_path).unwrap());
    let publisher = std::thread::spawn(move || a.publish_atomic(name, 8000));
    allocated_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    probe_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let (started_tx, started_rx) = mpsc::channel();
    let other = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        if let Some((host, guest)) = replacement {
            b.set_ports(name, &[crate::data::network::PortMapping::new(host, guest)])?;
            Ok(host)
        } else {
            b.publish_atomic(name, 8001)
        }
    });
    started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    // B must not even read/probe its snapshot while A owns the transaction.
    assert!(probe_rx.recv_timeout(Duration::from_millis(200)).is_err());
    release_tx.send(()).unwrap();
    let error = publisher.join().unwrap().unwrap_err().to_string();
    match failure {
        Failure::Rejected => assert!(error.contains("injected allocation failure"), "{error}"),
        Failure::Database => assert!(error.contains("injected database failure"), "{error}"),
        Failure::LostReply => assert!(
            error.contains("invalid atomic port allocation reply"),
            "{error}"
        ),
    }
    let host = other.join().unwrap().unwrap();
    server.join().unwrap();
    agent_thread.join().unwrap();
    let saved = db.get_vm(name).unwrap().unwrap();
    assert_eq!(saved.ports, vec![(host, 8001)]);
    assert_eq!(
        live.mappings(),
        vec![smolvm_network::PortMapping::new(host, 8001)]
    );
    assert!(std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, host)).is_err());
}

#[test]
fn atomic_rejection_preserves_server_error_without_rollback() {
    if !crate::test_support::in_own_process!() {
        return;
    }
    failed_publisher(Failure::Rejected, false);
}

#[test]
fn atomic_lost_reply_rolls_back_before_another_runtime_publishes() {
    if !crate::test_support::in_own_process!() {
        return;
    }
    failed_publisher(Failure::LostReply, false);
}

#[test]
fn atomic_database_failure_rolls_back_before_another_runtime_publishes() {
    if !crate::test_support::in_own_process!() {
        return;
    }
    failed_publisher(Failure::Database, false);
}

#[test]
fn atomic_rollback_serializes_with_complete_set_replacement() {
    if !crate::test_support::in_own_process!() {
        return;
    }
    failed_publisher(Failure::LostReply, true);
}

#[test]
fn atomic_ports_lock_serializes_independent_processes() {
    if !crate::test_support::in_own_process!() {
        return;
    }
    if let Some(socket) = std::env::var_os("SMOLVM_TEST_PORT_LOCK_CHILD") {
        let mut peer = UnixStream::connect(socket).unwrap();
        peer.write_all(b"ready").unwrap();
        let _lock = crate::agent::lock_published_ports("cross-process").unwrap();
        peer.write_all(b"locked").unwrap();
        return;
    }
    let temp = tempfile::Builder::new()
        .prefix("smol-port-lock-")
        .tempdir_in("/tmp")
        .unwrap();
    std::env::set_var("SMOLVM_TEST_VM_CACHE_ROOT", temp.path());
    let socket = temp.path().join("peer.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let held = crate::agent::lock_published_ports("cross-process").unwrap();
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "embedded::runtime::atomic_port_tests::atomic_ports_lock_serializes_independent_processes",
            "--nocapture",
        ])
        .env("SMOLVM_TEST_PORT_LOCK_CHILD", &socket)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let (mut peer, _) = listener.accept().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut ready = [0; 5];
    peer.read_exact(&mut ready).unwrap();
    assert_eq!(&ready, b"ready");
    peer.set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let mut locked = [0; 6];
    let error = peer.read_exact(&mut locked).unwrap_err();
    assert!(matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));
    drop(held);
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    peer.read_exact(&mut locked).unwrap();
    assert_eq!(&locked, b"locked");
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
