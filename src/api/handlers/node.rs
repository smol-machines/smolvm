//! Node-level introspection endpoints.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{extract::State, Json};
use std::sync::Arc;

use crate::api::state::ApiState;
use crate::api::types::CapacityResponse;

/// Id minted once per serve process (pid + startup nanos — unique across a restart,
/// dependency-free). Constant for the process lifetime; a change tells the control
/// the serve restarted and wiped its warm pool. Lazily initialized on first read.
fn boot_id() -> &'static str {
    static BOOT_ID: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    BOOT_ID.get_or_init(|| {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("{}-{}", std::process::id(), nanos)
    })
}

/// Report live node capacity — current allocations + real utilization across
/// all running machines on this host.
///
/// Read-only and runtime-agnostic: it exposes only what the runtime knows
/// (allocated vs. used), leaving totals/reserved policy to the caller. A fleet
/// node-agent polls this over HTTP and forwards it to the control plane in its
/// heartbeat, which keeps the runtime itself free of any cloud coupling.
#[utoipa::path(
    get,
    path = "/capacity",
    tag = "Node",
    responses(
        (status = 200, description = "Live node capacity", body = CapacityResponse),
        (status = 503, description = "Main runtime stalled — node is unschedulable")
    )
)]
pub async fn capacity(State(state): State<Arc<ApiState>>) -> Response {
    // If the main runtime stopped heartbeating, the lifecycle path (boot/stop/
    // exec) is wedged even though this loopback door — on its own runtime — can
    // still answer. Report 503 so the node-agent's existing self-cordon drains
    // this node instead of the control scheduling onto a black hole. The agent
    // treats 503 like any poll failure and self-heals once heartbeats resume.
    if state.runtime_stalled() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "main runtime stalled; node unschedulable",
        )
            .into_response();
    }

    let (allocated_cpus, allocated_memory_mb) = state.allocated_resources();
    let (used_cpus, used_memory_mb, used_disk_gb) = state.real_utilization();

    Json(CapacityResponse {
        allocated_cpus,
        allocated_memory_mb,
        used_cpus,
        used_memory_mb,
        used_disk_gb,
        boot_id: boot_id().to_string(),
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::SmolvmDb;

    use axum::body::to_bytes;

    #[tokio::test]
    async fn capacity_reports_zero_on_an_idle_node() {
        let dir = tempfile::tempdir().unwrap();
        let db = SmolvmDb::open_at(&dir.path().join("test.db")).unwrap();
        let state = Arc::new(ApiState::with_db(db));
        // A fresh state has heartbeat 0 == "now", so it is not yet stalled.

        // No running machines → nothing allocated and nothing in use.
        let resp = capacity(State(state)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let cap: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(cap["allocated_cpus"], 0);
        assert_eq!(cap["allocated_memory_mb"], 0);
        assert_eq!(cap["used_cpus"], 0.0);
        assert_eq!(cap["used_memory_mb"], 0);
        assert_eq!(cap["used_disk_gb"], 0);
    }

    #[tokio::test]
    async fn capacity_returns_503_when_runtime_heartbeat_is_stale() {
        // Force an immediate stall window so the missing heartbeat counts as stalled.
        std::env::set_var("SMOLVM_RUNTIME_STALE_SECS", "1");
        let dir = tempfile::tempdir().unwrap();
        let db = SmolvmDb::open_at(&dir.path().join("test.db")).unwrap();
        let state = Arc::new(ApiState::with_db(db));

        // Let the 1s stall window elapse with no supervisor heartbeat.
        tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
        let resp = capacity(State(state.clone())).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

        // A heartbeat clears the stall and capacity answers 200 again.
        state.beat_runtime_heartbeat();
        let resp = capacity(State(state)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        std::env::remove_var("SMOLVM_RUNTIME_STALE_SECS");
    }
}
