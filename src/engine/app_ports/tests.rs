use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn fixture(root: &std::path::Path) -> (Arc<Engine>, Arc<Container>, std::path::PathBuf) {
    let engine = super::super::test_engine(root);
    let socket = root.join("guest.sock");
    let record: ContainerRecord = serde_json::from_value(serde_json::json!({
        "id":"a".repeat(64),"name":"web","created":"2026-11-18T00:00:00Z","image":"fixture","image_id":"fixture","pull_ref":"","machine":"fixture","agent_socket":socket,
        "config":{},"host_config":{},"host_config_raw":{},"networks":{},"path":"/web","args":[],"restart_count":0,"ports":[],"mounts":[],
        "state":{"status":"running","pid":123,"exit_code":0,"error":"","started_at":"2026-11-18T00:00:01Z","finished_at":"","oom_killed":false}
    })).unwrap();
    let container = Container::from_record(record);
    engine
        .containers
        .write()
        .insert(container.id(), container.clone());
    (engine, container, socket)
}

async fn read_request(stream: &mut tokio::net::UnixStream) -> AgentRequest {
    let n = stream.read_u32().await.unwrap();
    let mut bytes = vec![0; n as usize];
    stream.read_exact(&mut bytes).await.unwrap();
    smolvm_protocol::binary_stream::decode_request(&bytes)
        .unwrap()
        .body
}
async fn reply(stream: &mut tokio::net::UnixStream, response: &AgentResponse) {
    stream
        .write_all(&smolvm_protocol::encode_message(response).unwrap())
        .await
        .unwrap();
}

#[tokio::test]
async fn raw_upgrade_preserves_bytes_after_the_confirmation_frame() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("guest.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert!(
            matches!(read_request(&mut stream).await, AgentRequest::ContainerPortConnect { overlay_id, port:8080 } if overlay_id=="owned")
        );
        let mut bytes = smolvm_protocol::encode_message(&AgentResponse::Ok {
            data: Some(serde_json::json!({"protocol":"smol-app-tcp-v1"})),
        })
        .unwrap();
        bytes.extend_from_slice(b"response without a second frame");
        stream.write_all(&bytes).await.unwrap();
        let mut received = [0; 7];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"request");
    });
    let mut stream = super::super::runtime::app_connect(&path, "owned", 8080)
        .await
        .unwrap();
    let mut received = [0; 31];
    stream.read_exact(&mut received).await.unwrap();
    assert_eq!(&received, b"response without a second frame");
    stream.write_all(b"request").await.unwrap();
    peer.await.unwrap();
}

#[tokio::test]
async fn discovery_is_generation_pinned_and_rejects_invalid_guest_metadata() {
    let root = tempfile::tempdir().unwrap();
    let (engine, container, socket) = fixture(root.path());
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let guest = tokio::spawn(async move {
        for ports in [
            serde_json::json!([3000, 8080]),
            serde_json::json!([8080, 3000]),
        ] {
            let (mut stream, _) = listener.accept().await.unwrap();
            assert!(matches!(
                read_request(&mut stream).await,
                AgentRequest::ContainerPorts { .. }
            ));
            reply(
                &mut stream,
                &AgentResponse::Ok {
                    data: Some(serde_json::json!({"ports":ports})),
                },
            )
            .await;
        }
    });
    let result = list(State(engine.clone()), Path(container.id()))
        .await
        .unwrap()
        .0;
    assert_eq!(result.ports, vec![3000, 8080]);
    assert_eq!(result.started_at, container.record().state.started_at);
    assert!(list(State(engine.clone()), Path(container.id()))
        .await
        .is_err());
    guest.await.unwrap();
    container.update(&engine, |r| r.state.status = "paused".into());
    assert_eq!(
        list(State(engine), Path(container.id()))
            .await
            .err()
            .unwrap()
            .status,
        StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn stale_generation_and_missing_upgrade_never_open_agent_connections() {
    let root = tempfile::tempdir().unwrap();
    let (engine, container, _) = fixture(root.path());
    let request = Request::builder()
        .header(header::CONNECTION, "upgrade")
        .header(header::UPGRADE, "tcp")
        .body(axum::body::Body::empty())
        .unwrap();
    let error = connect(
        State(engine.clone()),
        Path((container.id(), 8080)),
        Query(Generation {
            started_at: "old-run".into(),
        }),
        request,
    )
    .await
    .unwrap_err();
    assert_eq!(error.status, StatusCode::CONFLICT);
    let request = Request::new(axum::body::Body::empty());
    let error = connect(
        State(engine),
        Path((container.id(), 8080)),
        Query(Generation {
            started_at: container.record().state.started_at,
        }),
        request,
    )
    .await
    .unwrap_err();
    assert_eq!(error.status, StatusCode::BAD_REQUEST);
}

#[test]
fn unsupported_guests_and_ambiguous_ok_responses_do_not_become_raw_streams() {
    assert_eq!(
        confirmed(AgentResponse::error(
            "unknown method",
            smolvm_protocol::error_codes::INVALID_REQUEST
        ))
        .unwrap_err()
        .status,
        StatusCode::NOT_IMPLEMENTED
    );
    assert!(confirmed(AgentResponse::Ok { data: None }).is_err());
    assert!(confirmed(AgentResponse::Ok {
        data: Some(serde_json::json!({"protocol":"something-else"}))
    })
    .is_err());
}

#[tokio::test]
async fn actual_http_upgrade_relays_eager_bytes_upload_and_response_after_half_close() {
    let root = tempfile::tempdir().unwrap();
    let (engine, container, path) = fixture(root.path());
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let guest = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert!(matches!(
            read_request(&mut stream).await,
            AgentRequest::ContainerPortConnect { port: 8080, .. }
        ));
        let mut start = smolvm_protocol::encode_message(&AgentResponse::Ok {
            data: Some(serde_json::json!({"protocol":"smol-app-tcp-v1"})),
        })
        .unwrap();
        start.extend_from_slice(b"hello");
        stream.write_all(&start).await.unwrap();
        let mut data = Vec::new();
        stream.read_to_end(&mut data).await.unwrap();
        assert_eq!(data, vec![0x42; 128 * 1024]);
        stream.write_all(b"finished after EOF").await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = axum::Router::new()
        .route(
            "/containers/{id}/smol/ports/{port}/connect",
            axum::routing::post(connect),
        )
        .with_state(engine);
    let api = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let socket = tokio::net::TcpStream::connect(address).await.unwrap();
    let (mut client, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(socket))
            .await
            .unwrap();
    let driver = tokio::spawn(async move { connection.with_upgrades().await.unwrap() });
    let request = Request::builder()
        .method("POST")
        .uri(format!(
            "/containers/{}/smol/ports/8080/connect?started_at={}",
            container.id(),
            container.record().state.started_at
        ))
        .header(header::HOST, "local-engine")
        .header(header::CONNECTION, "upgrade")
        .header(header::UPGRADE, "tcp")
        .body(axum::body::Body::empty())
        .unwrap();
    let mut response = tokio::time::timeout(Duration::from_secs(3), client.send_request(request))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
    let mut raw = hyper_util::rt::TokioIo::new(hyper::upgrade::on(&mut response).await.unwrap());
    let mut hello = [0; 5];
    raw.read_exact(&mut hello).await.unwrap();
    assert_eq!(&hello, b"hello");
    raw.write_all(&vec![0x42; 128 * 1024]).await.unwrap();
    raw.shutdown().await.unwrap();
    let mut tail = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), raw.read_to_end(&mut tail))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(tail, b"finished after EOF");
    guest.await.unwrap();
    driver.await.unwrap();
    api.abort();
}

#[tokio::test]
async fn container_restart_during_discovery_discards_the_old_guest_result() {
    let root = tempfile::tempdir().unwrap();
    let (engine, container, path) = fixture(root.path());
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let changed = container.clone();
    let state = engine.clone();
    let guest = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _ = read_request(&mut stream).await;
        changed.update(&state, |r| {
            r.state.started_at = "2026-11-18T00:00:02Z".into()
        });
        reply(
            &mut stream,
            &AgentResponse::Ok {
                data: Some(serde_json::json!({"ports":[8080]})),
            },
        )
        .await;
    });
    let error = list(State(engine), Path(container.id()))
        .await
        .err()
        .unwrap();
    assert_eq!(error.status, StatusCode::CONFLICT);
    guest.await.unwrap();
}

#[tokio::test]
async fn listener_watch_is_shared_by_vm_and_released_by_the_last_subscriber() {
    let root = tempfile::tempdir().unwrap();
    let (engine, container, socket) = fixture(root.path());
    engine.store.save_container(&container.record()).unwrap();
    let mut sibling = container.record();
    sibling.id = "b".repeat(64);
    sibling.name = "sibling".into();
    engine.store.save_container(&sibling).unwrap();
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let mut first = subscribe(&engine).unwrap();
    let mut second = subscribe(&engine).unwrap();
    let (mut guest, _) = tokio::time::timeout(std::time::Duration::from_secs(2), listener.accept())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        read_request(&mut guest).await,
        AgentRequest::WatchListeners
    ));
    // Combine the protocol response and first raw generation in one write.
    let mut response = smolvm_protocol::encode_message(&AgentResponse::Ok {
        data: Some(serde_json::json!({"protocol":"smol-listener-watch-v1"})),
    })
    .unwrap();
    response.extend_from_slice(&42u64.to_le_bytes());
    guest.write_all(&response).await.unwrap();
    for subscriber in [&mut first, &mut second] {
        tokio::time::timeout(std::time::Duration::from_secs(2), subscriber.changed())
            .await
            .unwrap()
            .unwrap();
    }
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
            .await
            .is_err(),
        "one VM opened multiple watcher connections"
    );
    drop(first);
    guest.write_all(&43u64.to_le_bytes()).await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), second.changed())
        .await
        .unwrap()
        .unwrap();
    drop(second);
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(2), guest.read(&mut [0]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert!(engine.app_listener_watch.lock().upgrade().is_none());
}

#[tokio::test]
async fn listener_watch_distinguishes_an_older_guest_from_a_transport_failure() {
    let root = tempfile::tempdir().unwrap();
    let socket = root.path().join("guest.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert!(matches!(
            read_request(&mut stream).await,
            AgentRequest::WatchListeners
        ));
        reply(
            &mut stream,
            &AgentResponse::error("unsupported", smolvm_protocol::error_codes::INVALID_REQUEST),
        )
        .await;
    });
    let error = super::super::runtime::listener_watch(&socket)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
    peer.await.unwrap();
}

async fn watch_peer(listener: &tokio::net::UnixListener) -> tokio::net::UnixStream {
    let (mut stream, _) = tokio::time::timeout(Duration::from_secs(3), listener.accept())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        read_request(&mut stream).await,
        AgentRequest::WatchListeners
    ));
    reply(
        &mut stream,
        &AgentResponse::ok_with_data(serde_json::json!({"protocol":"smol-listener-watch-v1"})),
    )
    .await;
    stream
}

#[tokio::test]
async fn listener_watch_reconnects_and_accepts_a_rewound_generation() {
    let root = tempfile::tempdir().unwrap();
    let (engine, container, socket) = fixture(root.path());
    engine.store.save_container(&container.record()).unwrap();
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let mut updates = subscribe(&engine).unwrap();
    let mut first = watch_peer(&listener).await;
    first.write_all(&1000u64.to_le_bytes()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), updates.changed())
        .await
        .unwrap()
        .unwrap();
    drop(first);
    // A lost stream invalidates discovery before the reconnect delay.
    tokio::time::timeout(Duration::from_secs(2), updates.changed())
        .await
        .unwrap()
        .unwrap();
    let mut restored = watch_peer(&listener).await;
    restored.write_all(&1u64.to_le_bytes()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), updates.changed())
        .await
        .unwrap()
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(150), updates.changed())
            .await
            .is_err(),
        "healthy idle observer woke without a guest event"
    );
    restored.write_all(&2u64.to_le_bytes()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), updates.changed())
        .await
        .unwrap()
        .unwrap();
    drop(updates);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), restored.read(&mut [0]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn a_replaced_guest_socket_retries_a_previously_unsupported_watcher() {
    let root = tempfile::tempdir().unwrap();
    let (engine, container, socket) = fixture(root.path());
    engine.store.save_container(&container.record()).unwrap();
    let original = tokio::net::UnixListener::bind(&socket).unwrap();
    let mut updates = subscribe(&engine).unwrap();
    let (mut guest, _) = tokio::time::timeout(Duration::from_secs(2), original.accept())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        read_request(&mut guest).await,
        AgentRequest::WatchListeners
    ));
    reply(
        &mut guest,
        &AgentResponse::error("unsupported", smolvm_protocol::error_codes::INVALID_REQUEST),
    )
    .await;
    tokio::time::timeout(Duration::from_secs(2), updates.changed())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), guest.read(&mut [0]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    // Keep the old bound inode alive so the replacement cannot reuse it.
    std::fs::remove_file(&socket).unwrap();
    let replacement = tokio::net::UnixListener::bind(&socket).unwrap();
    engine.events.emit(
        "container",
        "start",
        &container.id(),
        std::collections::BTreeMap::new(),
    );
    let mut guest = watch_peer(&replacement).await;
    guest.write_all(&1u64.to_le_bytes()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), updates.changed())
        .await
        .unwrap()
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), original.accept())
            .await
            .is_err()
    );
    drop(updates);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), guest.read(&mut [0]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}
