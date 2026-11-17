//! Docker statistics sampled from the container, never from its shared VM.

use super::containers::{Container, ContainerRecord};
use super::util::{ApiError, ApiResult};
use smolvm_protocol::{AgentRequest, AgentResponse, ContainerResourceUsage};

pub(crate) async fn sample(
    engine: &super::Engine,
    container: &Container,
) -> ApiResult<serde_json::Value> {
    let id = container.id();
    let record = if engine.owner.as_deref() == Some(id.as_str()) {
        container.record()
    } else {
        // A streaming adapter must see lifecycle writes made by a different
        // supervisor, including restart, stop and removal between samples.
        engine
            .store
            .load_container(&id)
            .map_err(|e| ApiError::internal(e.to_string()))?
            .ok_or_else(|| ApiError::no_such_container(&id))?
    };
    sample_record(&record).await
}

async fn sample_record(record: &ContainerRecord) -> ApiResult<serde_json::Value> {
    let mut usage = if matches!(record.state.status.as_str(), "running" | "paused") {
        let socket = record
            .agent_socket
            .as_ref()
            .ok_or_else(|| ApiError::internal("Container accounting is not available yet"))?;
        let request = AgentRequest::ContainerStats {
            overlay_id: super::containers::overlay_id(record),
        };
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            super::runtime::request(socket, &request),
        )
        .await
        .map_err(|_| ApiError::internal("Container accounting timed out"))?
        .map_err(|e| ApiError::internal(e.to_string()))?;
        match response {
            AgentResponse::Ok { data: Some(data) } => {
                serde_json::from_value::<ContainerResourceUsage>(data)
                    .map_err(|e| ApiError::internal(format!("Invalid container accounting: {e}")))?
            }
            other => {
                let message = super::runtime::error_text(&other)
                    .unwrap_or_else(|| "Guest did not return container accounting".into());
                let message = if message.contains("unknown variant `container_stats`") {
                    "This guest predates container accounting; statistics become available after its VM and workload supervisor are upgraded".into()
                } else {
                    message
                };
                return Err(ApiError::internal(message));
            }
        }
    } else {
        ContainerResourceUsage::default()
    };
    if record.host_config.memory > 0 && usage.memory_limit_bytes > 0 {
        usage.memory_limit_bytes = usage
            .memory_limit_bytes
            .min(record.host_config.memory as u64);
    }
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1) as u64;
    Ok(docker_sample(
        &record.id,
        &record.name,
        &usage,
        cpus,
        super::stats_clock::system_cpu_usage(cpus),
    ))
}

fn docker_sample(
    id: &str,
    name: &str,
    usage: &ContainerResourceUsage,
    cpus: u64,
    system: u64,
) -> serde_json::Value {
    let io: Vec<serde_json::Value> = usage.block_io.iter().flat_map(|device| {
        [("Read", device.read_bytes), ("Write", device.write_bytes)].map(|(operation, value)| {
            serde_json::json!({"major": device.major, "minor": device.minor, "op": operation, "value": value})
        })
    }).collect();
    serde_json::json!({
        "read": super::util::now_rfc3339(), "preread": super::util::ZERO_TIME,
        "id": id, "name": format!("/{name}"), "num_procs": usage.pids,
        "pids_stats": {"current": usage.pids},
        "cpu_stats": {
            "cpu_usage": {"total_usage": usage.cpu_usage_ns, "usage_in_kernelmode": usage.cpu_system_ns, "usage_in_usermode": usage.cpu_user_ns},
            "system_cpu_usage": system, "online_cpus": cpus,
            "throttling_data": {"periods": usage.cpu_periods, "throttled_periods": usage.cpu_throttled_periods, "throttled_time": usage.cpu_throttled_ns},
        },
        "precpu_stats": {
            "cpu_usage": {"total_usage": 0, "usage_in_kernelmode": 0, "usage_in_usermode": 0},
            "system_cpu_usage": 0, "online_cpus": cpus,
            "throttling_data": {"periods": 0, "throttled_periods": 0, "throttled_time": 0},
        },
        "memory_stats": {"usage": usage.memory_bytes, "limit": usage.memory_limit_bytes,
            "stats": {"rss": usage.anonymous_bytes, "cache": usage.file_bytes, "inactive_file": usage.inactive_file_bytes}},
        "blkio_stats": {"io_service_bytes_recursive": io},
        "networks": usage.networks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn running_record(socket: &std::path::Path) -> ContainerRecord {
        serde_json::from_value(serde_json::json!({
            "id": "a".repeat(64), "name": "owned", "created": super::super::util::ZERO_TIME,
            "image": "fixture", "image_id": "fixture", "pull_ref": "", "machine": "owned",
            "agent_socket": socket, "config": {}, "host_config": {}, "host_config_raw": {},
            "networks": {}, "path": "/bin/sleep", "args": [], "restart_count": 0, "ports": [], "mounts": [],
            "state": {"status": "running", "pid": std::process::id(), "exit_code": 0, "error": "",
                "started_at": super::super::util::ZERO_TIME, "finished_at": super::super::util::ZERO_TIME, "oom_killed": false}
        })).unwrap()
    }

    fn guest_response(
        socket: &std::path::Path,
        response: AgentResponse,
    ) -> tokio::task::JoinHandle<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::UnixListener::bind(socket).unwrap();
        tokio::spawn(async move {
            let (mut connection, _) = listener.accept().await.unwrap();
            let length = connection.read_u32().await.unwrap();
            let mut body = vec![0; length as usize];
            connection.read_exact(&mut body).await.unwrap();
            assert!(matches!(
                serde_json::from_slice::<AgentRequest>(&body).unwrap(),
                AgentRequest::ContainerStats { .. }
            ));
            connection
                .write_all(&smolvm_protocol::encode_message(&response).unwrap())
                .await
                .unwrap();
        })
    }

    #[tokio::test]
    async fn adapter_samples_guest_without_contacting_a_legacy_supervisor() {
        use tower::ServiceExt;
        let dir = tempfile::tempdir().unwrap();
        let engine = super::super::test_engine(dir.path());
        let socket = dir.path().join("guest.sock");
        let record = running_record(&socket);
        engine.store.save_container(&record).unwrap();
        // A live legacy supervisor would still serve VM counters; it must
        // not even receive a connection for this observational request.
        let worker =
            tokio::net::UnixListener::bind(dir.path().join(format!("w-{}.sock", &record.id[..24])))
                .unwrap();
        let guest = guest_response(
            &socket,
            AgentResponse::Ok {
                data: Some(
                    serde_json::to_value(ContainerResourceUsage {
                        pids: 7,
                        ..Default::default()
                    })
                    .unwrap(),
                ),
            },
        );
        let request = axum::http::Request::builder()
            .uri("/v1.51/containers/owned/stats?one-shot=true")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            super::super::api::router(engine).oneshot(request),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["pids_stats"]["current"], 7);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), worker.accept())
                .await
                .is_err()
        );
        guest.await.unwrap();
    }

    #[tokio::test]
    async fn samples_follow_durable_stop_restart_and_removal() {
        let dir = tempfile::tempdir().unwrap();
        let engine = super::super::test_engine(dir.path());
        let old = running_record(&dir.path().join("old.sock"));
        let container = Container::from_record(old.clone());
        let mut updated = old.clone();
        updated.state.status = "exited".into();
        engine.store.save_container(&updated).unwrap();
        assert_eq!(
            sample(&engine, &container).await.unwrap()["pids_stats"]["current"],
            0
        );
        let socket = dir.path().join("new.sock");
        updated.state.status = "running".into();
        updated.agent_socket = Some(socket.clone());
        engine.store.save_container(&updated).unwrap();
        let guest = guest_response(
            &socket,
            AgentResponse::Ok {
                data: Some(
                    serde_json::to_value(ContainerResourceUsage {
                        pids: 3,
                        ..Default::default()
                    })
                    .unwrap(),
                ),
            },
        );
        assert_eq!(
            sample(&engine, &container).await.unwrap()["pids_stats"]["current"],
            3
        );
        guest.await.unwrap();
        engine.store.remove_container(&old.id);
        assert_eq!(
            sample(&engine, &container).await.unwrap_err().status,
            axum::http::StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn legacy_guest_reports_upgrade_requirement_without_placeholder_counters() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("guest.sock");
        let guest = guest_response(
            &socket,
            AgentResponse::error(
                "invalid request: unknown variant `container_stats`, expected one of `ping`, `run`",
                smolvm_protocol::error_codes::INTERNAL_ERROR,
            ),
        );
        let error = sample_record(&running_record(&socket)).await.unwrap_err();
        assert_eq!(error.status, axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        assert!(error
            .message
            .contains("VM and workload supervisor are upgraded"));
        guest.await.unwrap();
    }

    #[tokio::test]
    async fn unavailable_guest_accounting_is_an_error_instead_of_vm_usage() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("agent.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let guest = tokio::spawn(async move {
            let (mut connection, _) = listener.accept().await.unwrap();
            let length = connection.read_u32().await.unwrap();
            let mut body = vec![0; length as usize];
            connection.read_exact(&mut body).await.unwrap();
            let response = AgentResponse::error(
                "container accounting unavailable; restart with an updated guest",
                smolvm_protocol::error_codes::INTERNAL_ERROR,
            );
            connection
                .write_all(&smolvm_protocol::encode_message(&response).unwrap())
                .await
                .unwrap();
        });
        let record = serde_json::from_value(serde_json::json!({
            "id": "a".repeat(64), "name": "owned", "created": super::super::util::ZERO_TIME,
            "image": "fixture", "image_id": "fixture", "pull_ref": "", "machine": "owned",
            "agent_socket": socket, "config": {}, "host_config": {}, "host_config_raw": {},
            "networks": {}, "path": "/bin/sleep", "args": [], "restart_count": 0, "ports": [], "mounts": [],
            "state": {"status": "running", "pid": std::process::id(), "exit_code": 0, "error": "",
                "started_at": super::super::util::ZERO_TIME, "finished_at": super::super::util::ZERO_TIME, "oom_killed": false}
        })).unwrap();
        let error = sample_record(&record).await.unwrap_err();
        assert!(error.message.contains("accounting unavailable"));
        assert_eq!(error.status, axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        guest.await.unwrap();
    }

    #[test]
    fn docker_receives_guest_counters_and_cache_adjustment_fields() {
        let usage = ContainerResourceUsage {
            cpu_usage_ns: 1_000_000_000,
            cpu_user_ns: 750_000_000,
            cpu_system_ns: 250_000_000,
            memory_bytes: 8192,
            inactive_file_bytes: 4096,
            memory_limit_bytes: 65536,
            pids: 3,
            block_io: vec![smolvm_protocol::ContainerBlockIo {
                major: 254,
                minor: 16,
                read_bytes: 4096,
                write_bytes: 8192,
            }],
            ..Default::default()
        };
        let out = docker_sample("id", "name", &usage, 16, 16_000_000_000);
        assert_eq!(
            out["cpu_stats"]["cpu_usage"]["usage_in_kernelmode"],
            250_000_000u64
        );
        assert_eq!(out["pids_stats"]["current"], 3);
        assert_eq!(
            out["memory_stats"]["usage"].as_u64().unwrap()
                - out["memory_stats"]["stats"]["inactive_file"]
                    .as_u64()
                    .unwrap(),
            4096
        );
        assert_eq!(
            out["blkio_stats"]["io_service_bytes_recursive"][1],
            serde_json::json!({"major":254,"minor":16,"op":"Write","value":8192})
        );
        assert_eq!(out["networks"], serde_json::json!({}));
    }
}
