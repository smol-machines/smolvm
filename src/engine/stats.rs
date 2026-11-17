//! Docker statistics sampled from the container, never from its shared VM.

use super::containers::Container;
use super::util::{ApiError, ApiResult};
use smolvm_protocol::{AgentRequest, AgentResponse, ContainerResourceUsage};

pub(crate) async fn sample(container: &Container) -> ApiResult<serde_json::Value> {
    let record = container.record();
    let mut usage = if container.is_running() {
        let socket = container
            .socket()
            .ok_or_else(|| ApiError::internal("Container accounting is not available yet"))?;
        let request = AgentRequest::ContainerStats {
            overlay_id: super::containers::overlay_id(&record),
        };
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            super::runtime::request(&socket, &request),
        )
        .await
        .map_err(|_| ApiError::internal("Container accounting timed out"))?
        .map_err(|e| ApiError::internal(e.to_string()))?;
        match response {
            AgentResponse::Ok { data: Some(data) } => serde_json::from_value::<ContainerResourceUsage>(data)
                .map_err(|e| ApiError::internal(format!("Invalid container accounting: {e}")))?,
            other => return Err(ApiError::internal(super::runtime::error_text(&other)
                .unwrap_or_else(|| "Guest did not return container accounting; update the guest and restart the container".into()))),
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
        let container = Container::from_record(record);
        let error = sample(&container).await.unwrap_err();
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
