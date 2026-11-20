use super::*;
mod recovery;
fn origin() -> Origin {
    Origin {
        generation: 1,
        started_at: "2026-11-18T00:00:00Z".into(),
    }
}
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

async fn request(stream: &mut UnixStream) -> AgentRequest {
    let size = stream.read_u32().await.unwrap();
    assert!(size < 131072);
    let mut bytes = vec![0; size as usize];
    stream.read_exact(&mut bytes).await.unwrap();
    smolvm_protocol::binary_stream::decode_request(&bytes)
        .unwrap()
        .body
}
async fn response(stream: &mut UnixStream, response: AgentResponse) {
    let mut bytes = Vec::new();
    if !smolvm_protocol::binary_stream::write_response(&mut bytes, &response).unwrap() {
        let mut envelope = smolvm_protocol::Envelope::new(response);
        envelope.binary_stream = Some(1);
        bytes = smolvm_protocol::encode_message(&envelope).unwrap();
    }
    stream.write_all(&bytes).await.unwrap();
}
async fn event(stream: &mut UnixStream, event: Event) {
    response(stream, AgentResponse::ContainerSession { event }).await;
}
async fn begin(listener: &UnixListener) -> (UnixStream, wire::ExecutionId) {
    let (mut stream, _) = listener.accept().await.unwrap();
    assert!(matches!(request(&mut stream).await, AgentRequest::Ping));
    response(
        &mut stream,
        AgentResponse::Pong {
            version: 1,
            capabilities: vec![wire::CAPABILITY.into()],
        },
    )
    .await;
    let execution = match request(&mut stream).await {
        AgentRequest::ContainerSession {
            control: Control::Start {
                execution, spec, ..
            },
        } => {
            assert_eq!(spec.overlay_id, "overlay");
            execution
        }
        other => panic!("unexpected start: {other:?}"),
    };
    event(
        &mut stream,
        Event::Attached {
            stdin_closed: false,
            snapshot: Snapshot {
                execution: execution.clone(),
                output_first: 1,
                output_next: 1,
                input_next: 1,
            },
        },
    )
    .await;
    (stream, execution)
}
fn spec() -> ContainerStartSpec {
    ContainerStartSpec {
        overlay_id: "overlay".into(),
        open_stdin: true,
        ..Default::default()
    }
}

#[tokio::test]
async fn startup_reconnect_reports_lost_output_before_delivering_retained_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("agent.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert!(matches!(request(&mut stream).await, AgentRequest::Ping));
        response(
            &mut stream,
            AgentResponse::Pong {
                version: 1,
                capabilities: vec![wire::CAPABILITY.into()],
            },
        )
        .await;
        let AgentRequest::ContainerSession {
            control: Control::Start { execution, .. },
        } = request(&mut stream).await
        else {
            panic!("expected start")
        };
        drop(stream); // The process starts, but its initial reply is lost.
        let (mut stream, _) = listener.accept().await.unwrap();
        let AgentRequest::ContainerSession {
            control: Control::Attach { resume, .. },
        } = request(&mut stream).await
        else {
            panic!("must attach, never start twice")
        };
        assert_eq!(resume.execution, execution);
        event(
            &mut stream,
            Event::Attached {
                stdin_closed: false,
                snapshot: Snapshot {
                    execution,
                    output_first: 3,
                    output_next: 4,
                    input_next: 1,
                },
            },
        )
        .await;
        event(
            &mut stream,
            Event::Output {
                sequence: 3,
                stream: wire::OutputStream::Stdout,
                bytes: b"retained".to_vec(),
            },
        )
        .await;
        event(
            &mut stream,
            Event::Exited {
                exit: wire::Exit {
                    code: 9,
                    oom: false,
                },
            },
        )
        .await;
    });
    let mut session = Session::new(socket, "overlay".into(), origin());
    session.start(spec()).await.unwrap();
    let observed = std::cell::RefCell::new(Vec::new());
    let exit = session
        .pump(
            &InputQueue::default(),
            |_, bytes| {
                observed
                    .borrow_mut()
                    .push(String::from_utf8(bytes).unwrap())
            },
            |notice| observed.borrow_mut().push(notice.to_owned()),
            |_| {},
            || true,
        )
        .await
        .unwrap();
    assert_eq!(exit.code, 9);
    let observed = observed.into_inner();
    assert_eq!(observed.len(), 2);
    assert!(observed[0].contains("1..3 were lost"), "{observed:?}");
    assert_eq!(observed[1], "retained");
    assert!(session.startup_notices.is_empty());
    server.await.unwrap();
}
async fn next_input(stream: &mut UnixStream) -> (u64, wire::Input) {
    loop {
        match request(stream).await {
            AgentRequest::ContainerSession {
                control: Control::Input { sequence, input },
            } => return (sequence, input),
            AgentRequest::ContainerSession {
                control: Control::OutputAck { .. },
            } => {}
            other => panic!("unexpected request: {other:?}"),
        }
    }
}

#[tokio::test]
async fn reconnect_reconciles_lost_ack_replays_output_once_and_preserves_real_exit() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("agent.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, execution) = begin(&listener).await;
        event(
            &mut stream,
            Event::Output {
                sequence: 1,
                stream: wire::OutputStream::Stdout,
                bytes: b"before".to_vec(),
            },
        )
        .await;
        let (sequence, input) = next_input(&mut stream).await;
        assert_eq!(sequence, 1);
        assert_eq!(
            input,
            wire::Input::Data {
                bytes: b"once".to_vec()
            }
        );
        event(
            &mut stream,
            Event::Output {
                sequence: 2,
                stream: wire::OutputStream::Stderr,
                bytes: b"committed".to_vec(),
            },
        )
        .await;
        drop(stream); // Deliberately lose InputAck, retaining the execution.
                      // A stale guest handler may take a moment to release its attachment.
        let (mut stream, _) = listener.accept().await.unwrap();
        assert!(matches!(
            request(&mut stream).await,
            AgentRequest::ContainerSession {
                control: Control::Attach { .. }
            }
        ));
        response(
            &mut stream,
            AgentResponse::error("still detaching", wire::BUSY),
        )
        .await;
        drop(stream);
        let (mut stream, _) = listener.accept().await.unwrap();
        let resume = match request(&mut stream).await {
            AgentRequest::ContainerSession {
                control: Control::Attach { overlay_id, resume },
            } => {
                assert_eq!(overlay_id, "overlay");
                resume
            }
            other => panic!("unexpected reconnect: {other:?}"),
        };
        assert_eq!(resume.execution, execution);
        assert_eq!(resume.input_next, 1);
        event(
            &mut stream,
            Event::Attached {
                stdin_closed: false,
                snapshot: Snapshot {
                    execution: execution.clone(),
                    output_first: 1,
                    output_next: 3,
                    input_next: 2,
                },
            },
        )
        .await;
        for (sequence, stream_id, bytes) in [
            (1, wire::OutputStream::Stdout, b"before".to_vec()),
            (2, wire::OutputStream::Stderr, b"committed".to_vec()),
        ] {
            if sequence >= resume.output_next {
                event(
                    &mut stream,
                    Event::Output {
                        sequence,
                        stream: stream_id,
                        bytes,
                    },
                )
                .await;
            }
        }
        assert_eq!(next_input(&mut stream).await, (2, wire::Input::Eof {}));
        event(&mut stream, Event::InputAck { next: 3 }).await;
        event(
            &mut stream,
            Event::Exited {
                exit: wire::Exit {
                    code: 23,
                    oom: false,
                },
            },
        )
        .await;
        drop(stream);
        let (mut stream, _) = listener.accept().await.unwrap();
        assert!(
            matches!(request(&mut stream).await, AgentRequest::ContainerSession { control: Control::Forget { execution: found, .. } } if found == execution)
        );
        response(&mut stream, AgentResponse::Ok { data: None }).await;
    });
    let mut session = Session::new(socket, "overlay".into(), origin());
    session.start(spec()).await.unwrap();
    let input = InputQueue::default();
    input
        .sender()
        .send(Input::Data(b"once".to_vec()))
        .await
        .unwrap();
    input.sender().send(Input::Eof).await.unwrap();
    let mut output = Vec::new();
    let mut notices = Vec::new();
    let exit = timeout(
        Duration::from_secs(3),
        session.pump(
            &input,
            |stream, bytes| output.push((stream, bytes)),
            |s| notices.push(s.to_string()),
            |_| {},
            || true,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        exit,
        Exit {
            code: 23,
            oom: false
        }
    );
    assert_eq!(
        output,
        vec![(1, b"before".to_vec()), (2, b"committed".to_vec())]
    );
    assert!(notices.is_empty(), "{notices:?}");
    session.forget().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn ambiguous_input_after_disconnect_is_reported_not_reexecuted() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("agent.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, execution) = begin(&listener).await;
        assert!(matches!(
            next_input(&mut stream).await,
            (1, wire::Input::Data { .. })
        ));
        drop(stream);
        let (mut stream, _) = listener.accept().await.unwrap();
        assert!(matches!(
            request(&mut stream).await,
            AgentRequest::ContainerSession {
                control: Control::Attach { .. }
            }
        ));
        event(
            &mut stream,
            Event::Attached {
                stdin_closed: false,
                snapshot: Snapshot {
                    execution,
                    output_first: 1,
                    output_next: 1,
                    input_next: 1,
                },
            },
        )
        .await;
        // The missing input may have executed before rollback. Only the next
        // user input is allowed; the earlier payload must never be replayed.
        assert_eq!(next_input(&mut stream).await, (1, wire::Input::Eof {}));
        event(&mut stream, Event::InputAck { next: 2 }).await;
        event(
            &mut stream,
            Event::Exited {
                exit: wire::Exit {
                    code: 7,
                    oom: false,
                },
            },
        )
        .await;
    });
    let mut session = Session::new(socket, "overlay".into(), origin());
    session.start(spec()).await.unwrap();
    let input = InputQueue::default();
    input
        .sender()
        .send(Input::Data(b"side effect".to_vec()))
        .await
        .unwrap();
    input.sender().send(Input::Eof).await.unwrap();
    let mut notices = Vec::new();
    let exit = timeout(
        Duration::from_secs(3),
        session.pump(
            &input,
            |_, _| {},
            |s| notices.push(s.to_string()),
            |_| {},
            || true,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(exit.code, 7);
    assert_eq!(notices.len(), 1);
    assert!(notices[0].contains("not replayed"));
    server.await.unwrap();
}

#[tokio::test]
async fn input_during_partial_output_header_does_not_discard_framing() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("agent.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let input = std::sync::Arc::new(InputQueue::default());
    let incoming = input.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = begin(&listener).await;
        let mut bytes = Vec::new();
        smolvm_protocol::binary_stream::write_response(
            &mut bytes,
            &AgentResponse::ContainerSession {
                event: Event::Output {
                    sequence: 1,
                    stream: wire::OutputStream::Stdout,
                    bytes: vec![0, 255, 1],
                },
            },
        )
        .unwrap();
        stream.write_all(&bytes[..1]).await.unwrap();
        incoming.resize(120, 40);
        assert_eq!(
            next_input(&mut stream).await,
            (
                1,
                wire::Input::Resize {
                    cols: 120,
                    rows: 40
                }
            )
        );
        stream.write_all(&bytes[1..]).await.unwrap();
        event(&mut stream, Event::InputAck { next: 2 }).await;
        event(
            &mut stream,
            Event::Exited {
                exit: wire::Exit {
                    code: 0,
                    oom: false,
                },
            },
        )
        .await;
    });
    let mut session = Session::new(socket, "overlay".into(), origin());
    session.start(spec()).await.unwrap();
    let mut output = Vec::new();
    let exit = timeout(
        Duration::from_secs(3),
        session.pump(
            &input,
            |_, bytes| output.extend(bytes),
            |_| {},
            |_| {},
            || true,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(exit.code, 0);
    assert_eq!(output, [0, 255, 1]);
    server.await.unwrap();
}

#[tokio::test]
async fn old_guest_is_rejected_before_start_and_dead_vm_is_not_a_fake_process_exit() {
    for supported in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("agent.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            if supported {
                let _ = begin(&listener).await;
            } else {
                let (mut stream, _) = listener.accept().await.unwrap();
                assert!(matches!(request(&mut stream).await, AgentRequest::Ping));
                response(
                    &mut stream,
                    AgentResponse::Pong {
                        version: 1,
                        capabilities: vec![],
                    },
                )
                .await;
                let mut byte = [0];
                assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
            }
        });
        let mut session = Session::new(socket, "overlay".into(), origin());
        if supported {
            session.start(spec()).await.unwrap();
            let error = session
                .pump(&InputQueue::default(), |_, _| {}, |_| {}, |_| {}, || false)
                .await
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::NotConnected);
        } else {
            assert_eq!(
                session.start(spec()).await.unwrap_err().kind(),
                io::ErrorKind::Unsupported
            );
            assert!(!session.requested);
            session.cancel_and_forget().await.unwrap();
        }
        server.await.unwrap();
    }
}

#[test]
fn host_rewind_reconciliation_never_replays_input_and_keeps_stdin_closed() {
    let mut session = Session::new(PathBuf::new(), "overlay".into(), origin());
    session.resume.output_next = 20;
    session.resume.input_next = 5;
    session.pending = Some(5);
    session.stdin_closed = true;
    let mut notices = Vec::new();
    session
        .reconcile(
            Snapshot {
                execution: session.resume.execution.clone(),
                output_first: 2,
                output_next: 4,
                input_next: 3,
            },
            &mut |s| notices.push(s.to_string()),
        )
        .unwrap();
    assert_eq!(session.resume.output_next, 4);
    assert_eq!(session.resume.input_next, 3);
    assert!(session.pending.is_none());
    assert!(session.stdin_closed);
    assert_eq!(notices.len(), 3);
    assert!(session
        .reconcile(
            Snapshot {
                execution: session.resume.execution.clone(),
                output_first: 2,
                output_next: 4,
                input_next: 4
            },
            &mut |_| {}
        )
        .is_err());
}

#[tokio::test]
async fn bounded_binary_stdin_and_output_progress_together_without_deadlock() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("agent.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = begin(&listener).await;
        for n in 1..=32u64 {
            let (sequence, input) = next_input(&mut stream).await;
            assert_eq!(sequence, n);
            let wire::Input::Data { bytes } = input else {
                panic!("expected binary stdin")
            };
            assert_eq!(bytes, vec![n as u8; wire::MAX_INPUT_BYTES]);
            event(
                &mut stream,
                Event::Output {
                    sequence: n,
                    stream: if n % 2 == 0 {
                        wire::OutputStream::Stderr
                    } else {
                        wire::OutputStream::Stdout
                    },
                    bytes,
                },
            )
            .await;
            event(&mut stream, Event::InputAck { next: n + 1 }).await;
        }
        assert_eq!(next_input(&mut stream).await, (33, wire::Input::Eof {}));
        event(&mut stream, Event::InputAck { next: 34 }).await;
        event(
            &mut stream,
            Event::Exited {
                exit: wire::Exit {
                    code: 0,
                    oom: false,
                },
            },
        )
        .await;
    });
    let mut session = Session::new(socket, "overlay".into(), origin());
    session.start(spec()).await.unwrap();
    let input = InputQueue::default();
    let sender = input.sender();
    let producer = tokio::spawn(async move {
        for n in 1..=32u8 {
            sender
                .send(Input::Data(vec![n; wire::MAX_INPUT_BYTES]))
                .await
                .unwrap();
        }
        sender.send(Input::Eof).await.unwrap();
    });
    let mut next = 1u8;
    let exit = timeout(
        Duration::from_secs(5),
        session.pump(
            &input,
            |stream, bytes| {
                assert_eq!(stream, if next.is_multiple_of(2) { 2 } else { 1 });
                assert_eq!(bytes, vec![next; wire::MAX_INPUT_BYTES]);
                next += 1;
            },
            |_| panic!("unexpected reconnect notice"),
            |_| {},
            || true,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(next, 33);
    assert_eq!(exit.code, 0);
    producer.await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn idle_session_sends_no_keepalives_and_does_not_poll_vm_liveness() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("agent.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let (observed, quiet) = tokio::sync::oneshot::channel();
    let (finish, finished) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = begin(&listener).await;
        let mut byte = [0];
        assert!(timeout(Duration::from_millis(80), stream.read(&mut byte))
            .await
            .is_err());
        observed.send(()).unwrap();
        let _ = finished.await;
    });
    let mut session = Session::new(socket, "overlay".into(), origin());
    session.start(spec()).await.unwrap();
    let input = InputQueue::default();
    let mut probes = 0;
    tokio::select! {
        result = session.pump(&input, |_,_| panic!("idle output"), |_| panic!("idle recovery"), |_| {}, || { probes += 1; true }) => panic!("idle session ended: {result:?}"),
        result = quiet => result.unwrap(),
    }
    assert_eq!(probes, 0);
    finish.send(()).unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn a_saved_session_reattaches_without_starting_another_command() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("agent.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let (connection, execution) = begin(&listener).await;
        drop(connection);
        let (mut connection, _) = listener.accept().await.unwrap();
        let resume = match request(&mut connection).await {
            AgentRequest::ContainerSession {
                control: Control::Attach { overlay_id, resume },
            } => {
                assert_eq!(overlay_id, "overlay");
                assert_eq!(resume.execution, execution);
                resume
            }
            other => panic!("saved execution must only attach: {other:?}"),
        };
        event(
            &mut connection,
            Event::Attached {
                stdin_closed: false,
                snapshot: Snapshot {
                    execution,
                    output_first: 1,
                    output_next: 1,
                    input_next: resume.input_next,
                },
            },
        )
        .await;
        event(
            &mut connection,
            Event::Exited {
                exit: wire::Exit {
                    code: 7,
                    oom: false,
                },
            },
        )
        .await;
    });
    let mut original = Session::new(socket.clone(), "overlay".into(), origin());
    original.start(spec()).await.unwrap();
    let bytes = serde_json::to_vec(&original.saved()).unwrap();
    drop(original);
    let saved = serde_json::from_slice(&bytes).unwrap();
    let mut restored = Session::from_saved(socket, "overlay".into(), saved)
        .await
        .unwrap();
    let exit = restored
        .pump(&InputQueue::default(), |_, _| {}, |_| {}, |_| {}, || true)
        .await
        .unwrap();
    assert_eq!(exit.code, 7);
    server.await.unwrap();
}

#[tokio::test]
async fn a_missing_saved_execution_is_never_replaced_with_a_new_start() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("agent.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let (connection, _) = begin(&listener).await;
        drop(connection);
        let (mut connection, _) = listener.accept().await.unwrap();
        assert!(matches!(
            request(&mut connection).await,
            AgentRequest::ContainerSession {
                control: Control::Attach { .. }
            }
        ));
        response(
            &mut connection,
            AgentResponse::Error {
                message: "saved execution no longer exists".into(),
                code: Some(wire::ABSENT.into()),
            },
        )
        .await;
        assert!(
            tokio::time::timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
    });
    let mut original = Session::new(socket.clone(), "overlay".into(), origin());
    original.start(spec()).await.unwrap();
    let saved = original.saved();
    drop(original);
    assert!(Session::from_saved(socket, "overlay".into(), saved)
        .await
        .is_err());
    server.await.unwrap();
}
