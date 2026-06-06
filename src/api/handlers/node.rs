//! Node-level introspection endpoints.

use axum::{extract::State, Json};
use std::sync::Arc;

use crate::api::state::ApiState;
use crate::api::types::CapacityResponse;

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
        (status = 200, description = "Live node capacity", body = CapacityResponse)
    )
)]
pub async fn capacity(State(state): State<Arc<ApiState>>) -> Json<CapacityResponse> {
    let (allocated_cpus, allocated_memory_mb) = state.allocated_resources();
    let (used_cpus, used_memory_mb, used_disk_gb) = state.real_utilization();

    Json(CapacityResponse {
        allocated_cpus,
        allocated_memory_mb,
        used_cpus,
        used_memory_mb,
        used_disk_gb,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::SmolvmDb;

    #[tokio::test]
    async fn capacity_reports_zero_on_an_idle_node() {
        let dir = tempfile::tempdir().unwrap();
        let db = SmolvmDb::open_at(&dir.path().join("test.db")).unwrap();
        let state = Arc::new(ApiState::with_db(db));

        // No running machines → nothing allocated and nothing in use.
        let Json(cap) = capacity(State(state)).await;
        assert_eq!(cap.allocated_cpus, 0);
        assert_eq!(cap.allocated_memory_mb, 0);
        assert_eq!(cap.used_cpus, 0.0);
        assert_eq!(cap.used_memory_mb, 0);
        assert_eq!(cap.used_disk_gb, 0);
    }
}
