use super::*;
fn origin() -> Origin {
    Origin {
        generation: 1,
        started_at: "2026-11-18T00:00:00Z".into(),
    }
}
use std::io::{Read, Write};
use std::sync::mpsc;
use std::time::{Duration, Instant};

fn execution() -> ExecutionId {
    "a".repeat(32).try_into().unwrap()
}
fn resume() -> Resume {
    Resume {
        execution: execution(),
        output_next: 1,
        input_next: 1,
    }
}
fn wait_for(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !predicate() {
        assert!(Instant::now() < deadline, "session condition timed out");
        std::thread::sleep(Duration::from_millis(1));
    }
}
fn process(script: &str, tty: bool) -> (Arc<Session>, mpsc::Receiver<i32>) {
    let command = vec!["sh".to_string(), "-c".into(), script.to_string()];
    let (done, receiver) = mpsc::channel();
    let session = Session::spawn(execution(), origin(), [0; 32], true, move |socket| {
        let (mut child, pty) =
            crate::spawn_direct_interactive_command(&command, &[], None, tty).unwrap();
        let mut wire = crate::WireStream::new(socket);
        wire.binary = true;
        crate::send_response(&mut wire, &AgentResponse::Started).unwrap();
        // A failed test cannot leave a child behind indefinitely.
        let code = match pty {
            Some(pty) => crate::run_interactive_loop_pty(&mut wire, &mut child, pty, Some(10_000)),
            None => crate::run_interactive_loop(&mut wire, &mut child, Some(10_000)),
        }
        .unwrap();
        let _ = crate::send_response(
            &mut wire,
            &AgentResponse::Exited {
                exit_code: code,
                oom: false,
            },
        );
        let _ = done.send(code);
    })
    .unwrap();
    (session, receiver)
}
fn attach(
    session: &Arc<Session>,
    resume: Resume,
) -> (
    UnixStream,
    std::thread::JoinHandle<stdio::Result<()>>,
    Snapshot,
) {
    let (client, server) = UnixStream::pair().unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let session = session.clone();
    let handler = std::thread::spawn(move || session.attach(server.as_raw_fd(), true, resume));
    let mut client = client;
    let snapshot = match event(&mut client) {
        Event::Attached { snapshot, .. } => snapshot,
        other => panic!("expected attachment: {other:?}"),
    };
    (client, handler, snapshot)
}
fn send(client: &mut UnixStream, control: Control) {
    let request = AgentRequest::ContainerSession { control };
    let bytes = binary_stream::encode_request(&request, None)
        .unwrap()
        .unwrap_or_else(|| smolvm_protocol::encode_message(&request).unwrap());
    client.write_all(&bytes).unwrap();
}
fn event(client: &mut UnixStream) -> Event {
    let mut header = [0; 4];
    client.read_exact(&mut header).unwrap();
    let mut bytes = vec![0; u32::from_be_bytes(header) as usize];
    client.read_exact(&mut bytes).unwrap();
    match binary_stream::decode_response(&bytes).unwrap().0 {
        AgentResponse::ContainerSession { event } => event,
        other => panic!("unexpected session response: {other:?}"),
    }
}
fn detach(client: UnixStream, handler: std::thread::JoinHandle<stdio::Result<()>>) {
    client.shutdown(std::net::Shutdown::Both).unwrap();
    drop(client);
    let result = handler.join().unwrap();
    assert!(result.is_err());
}

#[test]
fn pipe_and_pty_owners_survive_detach_and_lost_input_ack_without_duplicate_execution() {
    for tty in [false, true] {
        let prefix = if tty { "stty -echo -onlcr; " } else { "" };
        let (session, done) = process(&format!("{prefix}printf 'ready\\n'; read -r first; printf 'first=%s\\n' \"$first\"; read -r second; printf 'second=%s\\n' \"$second\"; exit 23"), tty);
        let (mut client, handler, _) = attach(&session, resume());
        let mut cursor = 1;
        let mut ready = Vec::new();
        while ready.len() < 6 {
            match event(&mut client) {
                Event::Output {
                    sequence, bytes, ..
                } => {
                    assert_eq!(sequence, cursor);
                    cursor += 1;
                    ready.extend(bytes);
                }
                other => panic!("unexpected readiness response: {other:?}"),
            }
        }
        assert_eq!(ready, b"ready\n");
        send(&mut client, Control::OutputAck { next: cursor });
        let input = Input::Data {
            bytes: b"one\n".to_vec(),
        };
        send(
            &mut client,
            Control::Input {
                sequence: 1,
                input: input.clone(),
            },
        );
        // The guest accepted the record; deliberately discard its ACK.
        wait_for(|| session.state.lock().input.next() == Some(2));
        detach(client, handler);
        assert!(session.state.lock().output.exit().is_none());
        let (mut client, handler, snapshot) = attach(
            &session,
            Resume {
                output_next: cursor,
                ..resume()
            },
        );
        assert_eq!(snapshot.input_next, 2);
        send(&mut client, Control::Input { sequence: 1, input });
        let mut output = Vec::new();
        loop {
            match event(&mut client) {
                Event::InputAck { next } => {
                    assert_eq!(next, 2);
                    break;
                }
                Event::Output {
                    sequence, bytes, ..
                } => {
                    assert_eq!(sequence, cursor);
                    cursor += 1;
                    output.extend(bytes);
                    send(&mut client, Control::OutputAck { next: cursor });
                }
                other => panic!("unexpected replay response: {other:?}"),
            }
        }
        send(
            &mut client,
            Control::Input {
                sequence: 2,
                input: Input::Data {
                    bytes: b"two\n".to_vec(),
                },
            },
        );
        loop {
            match event(&mut client) {
                Event::InputAck { next } => assert_eq!(next, 3),
                Event::Output {
                    sequence, bytes, ..
                } => {
                    assert_eq!(sequence, cursor);
                    cursor += 1;
                    output.extend(bytes); /* Exit can close the attachment before the final ACK. */
                }
                Event::Exited { exit } => {
                    assert_eq!(
                        exit,
                        Exit {
                            code: 23,
                            oom: false
                        }
                    );
                    break;
                }
                other => panic!("unexpected response: {other:?}"),
            }
        }
        assert_eq!(output, b"first=one\nsecond=two\n");
        handler.join().unwrap().unwrap();
        assert_eq!(done.recv_timeout(Duration::from_secs(5)).unwrap(), 23);
    }
}

#[test]
fn terminal_resize_and_explicit_eof_are_committed_and_real_exit_is_retained() {
    let (session, done) = process(
        "stty -echo -onlcr; printf 'ready\\n'; read -r line; stty size; cat; exit 7",
        true,
    );
    let (mut client, handler, _) = attach(&session, resume());
    assert!(matches!(event(&mut client), Event::Output { bytes, .. } if bytes == b"ready\n"));
    send(
        &mut client,
        Control::Input {
            sequence: 1,
            input: Input::Resize {
                cols: 123,
                rows: 45,
            },
        },
    );
    assert!(matches!(event(&mut client), Event::InputAck { next: 2 }));
    send(
        &mut client,
        Control::Input {
            sequence: 2,
            input: Input::Data {
                bytes: b"go\n".to_vec(),
            },
        },
    );
    let mut output = Vec::new();
    let mut acknowledged = false;
    while !acknowledged || !output.ends_with(b"45 123\n") {
        match event(&mut client) {
            Event::InputAck { next: 3 } => acknowledged = true,
            Event::Output { bytes, .. } => output.extend(bytes),
            other => panic!("unexpected terminal response: {other:?}"),
        }
    }
    send(
        &mut client,
        Control::Input {
            sequence: 3,
            input: Input::Eof {},
        },
    );
    loop {
        match event(&mut client) {
            Event::InputAck { next: 4 } => {}
            Event::Exited { exit } => {
                assert_eq!(exit.code, 7);
                break;
            }
            other => panic!("unexpected EOF response: {other:?}"),
        }
    }
    handler.join().unwrap().unwrap();
    assert_eq!(done.recv_timeout(Duration::from_secs(5)).unwrap(), 7);
    assert_eq!(session.state.lock().output.exit().unwrap().code, 7);
}

#[test]
fn detached_output_is_bounded_reports_a_gap_and_preserves_stderr_and_nonzero_exit() {
    let (session, done) = process(
        "head -c 4194304 /dev/zero; printf 'finished' >&2; exit 31",
        false,
    );
    assert_eq!(done.recv_timeout(Duration::from_secs(5)).unwrap(), 31);
    wait_for(|| session.state.lock().output.exit().is_some());
    assert!(
        session.state.lock().output.retained_bytes()
            <= smolvm_protocol::container_session::MAX_OUTPUT_BYTES
    );
    let (mut client, handler, snapshot) = attach(&session, resume());
    assert!(matches!(
        snapshot.reconcile(&resume()).unwrap().output,
        OutputResume::Gap { .. }
    ));
    let mut cursor = snapshot.output_first;
    let mut stderr = Vec::new();
    let mut total = 0;
    loop {
        match event(&mut client) {
            Event::Output {
                sequence,
                stream,
                bytes,
            } => {
                assert_eq!(sequence, cursor);
                cursor += 1;
                total += bytes.len();
                if stream == OutputStream::Stderr {
                    stderr.extend(bytes);
                }
            }
            Event::Exited { exit } => {
                assert_eq!(exit.code, 31);
                break;
            }
            other => panic!("unexpected detached output: {other:?}"),
        }
    }
    assert_eq!(stderr, b"finished");
    assert!(total <= smolvm_protocol::container_session::MAX_OUTPUT_BYTES);
    handler.join().unwrap().unwrap();
}

#[test]
fn a_partial_client_frame_detaches_without_eof_and_registry_never_forgets_a_live_execution() {
    let (session, done) = process("cat; exit 19", false);
    let registry = Registry::default();
    registry.0.lock().insert("overlay".into(), session.clone());
    let (mut client, handler, _) = attach(&session, resume());
    let (spare, _) = UnixStream::pair().unwrap();
    assert_eq!(
        session
            .attach(spare.as_raw_fd(), true, resume())
            .unwrap_err()
            .kind(),
        stdio::ErrorKind::WouldBlock
    );
    assert!(registry.forget("overlay", &execution()).is_err());
    assert!(registry
        .find("overlay", &"b".repeat(32).try_into().unwrap())
        .is_err());
    client.write_all(&[0, 0]).unwrap();
    detach(client, handler);
    let (mut client, handler, snapshot) = attach(&session, resume());
    assert_eq!(snapshot.input_next, 1);
    send(
        &mut client,
        Control::Input {
            sequence: 1,
            input: Input::Eof {},
        },
    );
    loop {
        match event(&mut client) {
            Event::InputAck { next: 2 } => {}
            Event::Exited { exit } => {
                assert_eq!(exit.code, 19);
                break;
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }
    handler.join().unwrap().unwrap();
    assert_eq!(done.recv_timeout(Duration::from_secs(5)).unwrap(), 19);
    registry.forget("overlay", &execution()).unwrap();
    registry.forget("overlay", &execution()).unwrap();
    assert!(registry.find("overlay", &execution()).is_err());
}

#[test]
fn attached_output_backpressure_releases_on_detach_without_killing_the_owner() {
    let (session, done) = process(
        "printf x; read -r go; head -c 4194304 /dev/zero; printf 'tail' >&2; exit 37",
        false,
    );
    let (mut client, handler, _) = attach(&session, resume());
    // Keep a one-byte record unacknowledged so the remaining capacity is not
    // an exact multiple of the process owner's output chunks.
    assert!(
        matches!(event(&mut client), Event::Output { sequence: 1, bytes, .. } if bytes == b"x")
    );
    send(
        &mut client,
        Control::Input {
            sequence: 1,
            input: Input::Data {
                bytes: b"go\n".to_vec(),
            },
        },
    );
    assert!(matches!(event(&mut client), Event::InputAck { next: 2 }));
    wait_for(|| {
        let state = session.state.lock();
        // A whole record must fit: pressure can begin before the byte limit
        // when the next read is larger than the remaining capacity.
        state.output.retained_bytes()
            > smolvm_protocol::container_session::MAX_OUTPUT_BYTES
                - smolvm_protocol::container_session::MAX_INPUT_BYTES
            || state.output.records_from(1).count()
                == smolvm_protocol::container_session::MAX_OUTPUT_RECORDS
    });
    assert!(matches!(
        done.recv_timeout(Duration::from_millis(100)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    {
        let state = session.state.lock();
        assert_eq!(state.output.first(), 1);
        assert!(
            state.output.retained_bytes() <= smolvm_protocol::container_session::MAX_OUTPUT_BYTES
        );
        assert!(
            state.output.records_from(1).count()
                <= smolvm_protocol::container_session::MAX_OUTPUT_RECORDS
        );
    }
    detach(client, handler);
    assert_eq!(done.recv_timeout(Duration::from_secs(5)).unwrap(), 37);
    wait_for(|| session.state.lock().output.exit().is_some());
    let (mut client, handler, snapshot) = attach(
        &session,
        Resume {
            input_next: 2,
            ..resume()
        },
    );
    assert!(snapshot.output_first > 1);
    let mut tail = Vec::new();
    loop {
        match event(&mut client) {
            Event::Output {
                stream: OutputStream::Stderr,
                bytes,
                ..
            } => tail.extend(bytes),
            Event::Output { .. } => {}
            Event::Exited { exit } => {
                assert_eq!(exit.code, 37);
                break;
            }
            other => panic!("unexpected backpressure response: {other:?}"),
        }
    }
    assert_eq!(tail, b"tail");
    handler.join().unwrap().unwrap();
}

#[test]
fn duplicate_start_is_idempotent_and_registry_capacity_never_evicts_live_sessions() {
    let spec = Box::new(smolvm_protocol::ContainerStartSpec {
        overlay_id: "overlay".into(),
        ..Default::default()
    });
    let fingerprint: [u8; 32] = Sha256::digest(serde_json::to_vec(&spec).unwrap()).into();
    let (release, wait) = mpsc::channel();
    let session = Session::spawn(execution(), origin(), fingerprint, true, move |_socket| {
        let _ = wait.recv_timeout(Duration::from_secs(5));
    })
    .unwrap();
    let registry = Registry::default();
    registry.0.lock().insert("overlay".into(), session.clone());
    assert!(Arc::ptr_eq(
        &registry.start(execution(), origin(), spec.clone()).unwrap(),
        &session
    ));
    let mut changed = spec.clone();
    changed.command.push("different".into());
    assert!(registry.start(execution(), origin(), changed).is_err());
    assert!(registry
        .start("b".repeat(32).try_into().unwrap(), origin(), spec)
        .is_err());
    for n in 1..MAX_SESSIONS {
        registry
            .0
            .lock()
            .insert(format!("reserved-{n}"), session.clone());
    }
    let spec = Box::new(smolvm_protocol::ContainerStartSpec {
        overlay_id: "another".into(),
        ..Default::default()
    });
    assert!(registry.start(execution(), origin(), spec).is_err());
    assert_eq!(registry.0.lock().len(), MAX_SESSIONS);
    assert!(registry.forget("overlay", &execution()).is_err());
    release.send(()).unwrap();
    wait_for(|| {
        let state = session.state.lock();
        state.owner_done && state.failure.is_some()
    });
    assert!(
        session.state.lock().output.exit().is_none(),
        "transport EOF is never a synthetic exit"
    );
    registry.forget("overlay", &execution()).unwrap();
}

#[test]
fn explicit_cancellation_reaps_only_its_owner_and_does_not_poison_other_sessions() {
    let (cancelled, first_done) = process("cat; exit 41", false);
    let (other, other_done) = process("cat; exit 43", false);
    let (client, handler, _) = attach(&cancelled, resume());
    detach(client, handler);
    cancelled.state.lock().cancelled = true;
    cancelled.owner_wake.signal();
    assert_eq!(
        first_done.recv_timeout(Duration::from_secs(5)).unwrap(),
        124
    );
    wait_for(|| cancelled.state.lock().owner_done);
    let registry = Registry::default();
    registry.0.lock().insert("cancelled".into(), cancelled);
    registry.forget("cancelled", &execution()).unwrap();
    assert!(matches!(
        other_done.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    let (mut client, handler, _) = attach(&other, resume());
    send(
        &mut client,
        Control::Input {
            sequence: 1,
            input: Input::Eof {},
        },
    );
    loop {
        if let Event::Exited { exit } = event(&mut client) {
            assert_eq!(exit.code, 43);
            break;
        }
    }
    handler.join().unwrap().unwrap();
    assert_eq!(other_done.recv_timeout(Duration::from_secs(5)).unwrap(), 43);
}

#[test]
fn inspection_preserves_live_owner_and_distinguishes_missing_from_replaced_execution() {
    let (session, done) = process("cat; exit 19", false);
    let registry = Registry::default();
    registry.0.lock().insert("overlay".into(), session.clone());
    wait_for(|| session.state.lock().ready);
    let before = registry.inspect("overlay").unwrap().unwrap();
    assert_eq!(before.origin, origin());
    assert_eq!(before.snapshot.execution, execution());
    assert!(!session.state.lock().attached);
    assert!(registry.inspect("missing").unwrap().is_none());
    assert_eq!(
        registry.find("missing", &execution()).err().unwrap().kind(),
        stdio::ErrorKind::NotFound
    );
    assert_eq!(
        registry
            .find("overlay", &"b".repeat(32).try_into().unwrap())
            .err()
            .unwrap()
            .kind(),
        stdio::ErrorKind::AlreadyExists
    );
    assert_eq!(registry.inspect("overlay").unwrap().unwrap(), before);
    let (mut client, handler, _) = attach(&session, resume());
    assert!(session.state.lock().attached);
    // Inspect must also be harmless while a legitimate attachment owns I/O.
    assert_eq!(registry.inspect("overlay").unwrap().unwrap(), before);
    send(
        &mut client,
        Control::Input {
            sequence: 1,
            input: Input::Eof {},
        },
    );
    loop {
        if let Event::Exited { exit } = event(&mut client) {
            assert_eq!(exit.code, 19);
            break;
        }
    }
    handler.join().unwrap().unwrap();
    assert_eq!(done.recv_timeout(Duration::from_secs(5)).unwrap(), 19);
    assert!(session.state.lock().input.stdin_closed());
    // A reconnect learns the actual EOF state, even after its original ACK
    // was lost. Merely inspecting must not consume or replace that state.
    let (mut client, server) = UnixStream::pair().unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let owner = session.clone();
    let handler = std::thread::spawn(move || owner.attach(server.as_raw_fd(), true, resume()));
    assert!(matches!(
        event(&mut client),
        Event::Attached {
            stdin_closed: true,
            ..
        }
    ));
    assert!(matches!(event(&mut client), Event::Exited { exit } if exit.code == 19));
    handler.join().unwrap().unwrap();
}

#[test]
fn completed_owner_rejects_nonadvancing_or_invalid_start_origins() {
    let (session, done) = process("exit 23", false);
    assert_eq!(done.recv_timeout(Duration::from_secs(5)).unwrap(), 23);
    wait_for(|| {
        let state = session.state.lock();
        state.output.exit().is_some() && state.owner_done
    });
    let registry = Registry::default();
    registry.0.lock().insert("overlay".into(), session.clone());
    let spec = Box::new(smolvm_protocol::ContainerStartSpec {
        overlay_id: "overlay".into(),
        ..Default::default()
    });
    for candidate in [
        Origin {
            generation: 0,
            ..origin()
        },
        origin(),
        Origin {
            generation: 2,
            started_at: String::new(),
        },
        Origin {
            generation: 2,
            started_at: "x".repeat(65),
        },
    ] {
        assert!(registry
            .start("b".repeat(32).try_into().unwrap(), candidate, spec.clone())
            .is_err());
        assert!(Arc::ptr_eq(
            &registry.find("overlay", &execution()).unwrap(),
            &session
        ));
    }
}
