use super::*;

fn earlier() -> wire::ExecutionState {
    wire::ExecutionState {
        snapshot: Snapshot {
            execution: "a".repeat(32).try_into().unwrap(),
            output_first: 1,
            output_next: 2,
            input_next: 3,
        },
        origin: origin(),
        fingerprint: Sha256::digest(serde_json::to_vec(&spec()).unwrap()).into(),
    }
}

#[tokio::test]
async fn earlier_owner_recovers_with_real_exit_and_no_obsolete_stdin() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("agent.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, newer) = begin(&listener).await;
        assert!(
            matches!(request(&mut stream).await, AgentRequest::ContainerSession {
            control: Control::Input { sequence: 1, input: wire::Input::Data { bytes } }
        } if bytes == b"discarded-execution")
        );
        // This write's acknowledgement and the queued EOF belong to the newer
        // process. Neither may be delivered to the restored older process.
        drop(stream);
        let (mut stream, _) = listener.accept().await.unwrap();
        assert!(
            matches!(request(&mut stream).await, AgentRequest::ContainerSession {
            control: Control::Attach { resume, .. }
        } if resume.execution == newer)
        );
        response(
            &mut stream,
            AgentResponse::error("different owner", wire::CHANGED),
        )
        .await;
        drop(stream);
        let (mut stream, _) = listener.accept().await.unwrap();
        assert!(
            matches!(request(&mut stream).await, AgentRequest::ContainerSession {
            control: Control::Inspect { overlay_id }
        } if overlay_id == "overlay")
        );
        event(
            &mut stream,
            Event::State {
                state: Some(earlier()),
            },
        )
        .await;
        drop(stream);
        let (mut stream, _) = listener.accept().await.unwrap();
        assert!(
            matches!(request(&mut stream).await, AgentRequest::ContainerSession {
            control: Control::Attach { resume, .. }
        } if resume.execution == earlier().snapshot.execution && resume.input_next == 3)
        );
        event(
            &mut stream,
            Event::Attached {
                snapshot: earlier().snapshot,
                stdin_closed: false,
            },
        )
        .await;
        assert!(
            matches!(request(&mut stream).await, AgentRequest::ContainerSession {
            control: Control::Input { sequence: 3, input: wire::Input::Data { bytes } }
        } if bytes == b"fresh-input")
        );
        event(&mut stream, Event::InputAck { next: 4 }).await;
        event(
            &mut stream,
            Event::Output {
                sequence: 1,
                stream: wire::OutputStream::Stdout,
                bytes: b"restored-output".to_vec(),
            },
        )
        .await;
        event(
            &mut stream,
            Event::Exited {
                exit: wire::Exit {
                    code: 27,
                    oom: false,
                },
            },
        )
        .await;
    });
    let mut session = Session::new(
        socket,
        "overlay".into(),
        Origin {
            generation: 2,
            ..origin()
        },
    );
    session.start(spec()).await.unwrap();
    let input = InputQueue::default();
    let obsolete = input.sender();
    obsolete
        .send(Input::Data(b"discarded-execution".to_vec()))
        .await
        .unwrap();
    obsolete.send(Input::Eof).await.unwrap();
    let recovered = tokio::sync::Notify::new();
    let mut notices = Vec::new();
    let mut origins = Vec::new();
    let mut bytes = Vec::new();
    let pumping = session.pump(
        &input,
        |_, data| bytes.extend(data),
        |message| notices.push(message.to_owned()),
        |origin| {
            origins.push(origin.clone());
            recovered.notify_one();
        },
        || true,
    );
    let producer = async {
        recovered.notified().await;
        assert!(obsolete
            .send(Input::Data(b"stale-client".to_vec()))
            .await
            .is_err());
        input
            .sender()
            .send(Input::Data(b"fresh-input".to_vec()))
            .await
            .unwrap();
    };
    let (exit, ()) = timeout(Duration::from_secs(5), async {
        tokio::join!(pumping, producer)
    })
    .await
    .unwrap();
    assert_eq!(exit.unwrap().code, 27);
    assert_eq!(bytes, b"restored-output");
    assert_eq!(origins, [origin()]);
    assert!(notices
        .iter()
        .any(|message| message.contains("queued input was discarded")));
    assert_eq!(session.origin.generation, 1);
    server.await.unwrap();
}

#[tokio::test]
async fn unverifiable_owners_are_never_attached_or_cancelled() {
    for case in 0..5 {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("agent.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let mut state = earlier();
        match case {
            0 => state.origin.generation = 3,
            1 => state.origin.generation = 2,
            2 => state.fingerprint = [0; 32],
            3 => state.origin.started_at = "invalid timestamp".into(),
            _ => {}
        }
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            assert!(matches!(
                request(&mut stream).await,
                AgentRequest::ContainerSession {
                    control: Control::Inspect { .. }
                }
            ));
            event(
                &mut stream,
                Event::State {
                    state: (case != 4).then_some(state),
                },
            )
            .await;
            drop(stream);
            assert!(
                timeout(Duration::from_millis(50), listener.accept())
                    .await
                    .is_err(),
                "invalid owner received a follow-up operation"
            );
        });
        let mut session = Session::new(
            socket,
            "overlay".into(),
            Origin {
                generation: 2,
                ..origin()
            },
        );
        session.fingerprint = earlier().fingerprint;
        let error = session
            .recover_owner(
                &InputQueue::default(),
                &mut |_| panic!("notice on rejected owner"),
                &mut |_| panic!("adopted rejected owner"),
            )
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        if case == 4 {
            assert!(error.to_string().contains("does not contain"));
        }
        assert_eq!(session.origin.generation, 2);
        server.await.unwrap();
    }
}

#[tokio::test]
async fn owner_replacement_between_inspection_and_attach_does_not_change_host_ownership() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("agent.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert!(matches!(
            request(&mut stream).await,
            AgentRequest::ContainerSession {
                control: Control::Inspect { .. }
            }
        ));
        event(
            &mut stream,
            Event::State {
                state: Some(earlier()),
            },
        )
        .await;
        drop(stream);
        let (mut stream, _) = listener.accept().await.unwrap();
        assert!(
            matches!(request(&mut stream).await, AgentRequest::ContainerSession { control: Control::Attach { resume, .. } } if resume.execution == earlier().snapshot.execution)
        );
        response(
            &mut stream,
            AgentResponse::error("owner changed again", wire::CHANGED),
        )
        .await;
    });
    let mut session = Session::new(
        socket,
        "overlay".into(),
        Origin {
            generation: 2,
            ..origin()
        },
    );
    session.fingerprint = earlier().fingerprint;
    let previous = session.resume.clone();
    let error = session
        .recover_owner(&InputQueue::default(), &mut |_| {}, &mut |_| {
            panic!("replaced owner adopted")
        })
        .await
        .unwrap_err();
    assert!(owner_changed(&error));
    assert_eq!(session.resume, previous);
    assert_eq!(session.origin.generation, 2);
    server.await.unwrap();
}

#[tokio::test]
async fn same_execution_rewind_discards_old_eof_and_accepts_fresh_stdin() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("agent.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let (stream, execution) = begin(&listener).await;
        drop(stream);
        let (mut stream, _) = listener.accept().await.unwrap();
        assert!(
            matches!(request(&mut stream).await, AgentRequest::ContainerSession {
            control: Control::Attach { resume, .. }
        } if resume.execution == execution && resume.input_next == 3)
        );
        event(
            &mut stream,
            Event::Attached {
                snapshot: Snapshot {
                    execution,
                    output_first: 1,
                    output_next: 1,
                    input_next: 1,
                },
                stdin_closed: false,
            },
        )
        .await;
        let (sequence, input) = next_input(&mut stream).await;
        assert_eq!(sequence, 1);
        assert!(matches!(input, wire::Input::Data { bytes } if bytes == b"fresh"));
        event(&mut stream, Event::InputAck { next: 2 }).await;
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
    });
    let input = InputQueue::default();
    let old_sender = input.sender();
    old_sender
        .send(Input::Data(b"discarded".to_vec()))
        .await
        .unwrap();
    old_sender.eof();
    let mut session = Session::new(socket, "overlay".into(), origin());
    session.start(spec()).await.unwrap();
    // The host remembers acknowledged input/EOF after the checkpoint, while
    // the restored guest has open stdin and the original execution identity.
    session.resume.input_next = 3;
    session.resume.output_next = 4;
    session.stdin_closed = true;
    let recovered = tokio::sync::Notify::new();
    let producer = async {
        recovered.notified().await;
        assert!(old_sender
            .send(Input::Data(b"stale writer".to_vec()))
            .await
            .is_err());
        input
            .sender()
            .send(Input::Data(b"fresh".to_vec()))
            .await
            .unwrap();
    };
    let pump = session.pump(
        &input,
        |_, _| {},
        |message| {
            if message.starts_with("Queued input") {
                recovered.notify_one();
            }
        },
        |_| panic!("same execution must preserve its origin"),
        || true,
    );
    let (exit, ()) = timeout(Duration::from_secs(5), async {
        tokio::join!(pump, producer)
    })
    .await
    .unwrap();
    assert_eq!(exit.unwrap().code, 23);
    server.await.unwrap();
}
