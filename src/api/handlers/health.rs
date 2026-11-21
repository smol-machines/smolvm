//! Health check endpoint.

use axum::http::StatusCode;
use axum::{extract::State, Json};
use std::sync::Arc;
use std::time::Duration;

use crate::api::state::ApiState;
use crate::api::types::{HealthResponse, MachineCountsResponse};

/// Deadline for the `/readyz` blocking-pool round-trip. Generous vs. a no-op task
/// on a healthy pool (microseconds); only a genuinely saturated pool misses it.
const READYZ_BUDGET: Duration = Duration::from_secs(2);

/// Server start time for uptime calculation.
static SERVER_START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

/// Record the server start time. Call once at startup.
pub fn mark_server_start() {
    let _ = SERVER_START.set(std::time::Instant::now());
}

/// Health check endpoint.
#[utoipa::path(
    get,
    path = "/health",
    tag = "Health",
    responses(
        (status = 200, description = "Server is healthy", body = HealthResponse)
    )
)]
pub async fn health(State(state): State<Arc<ApiState>>) -> Json<HealthResponse> {
    // Count from the authoritative DB (off-reactor), the same source `/machines`
    // reads. The in-memory machine map retains entries for VMs removed
    // out-of-band — an ephemeral cleanup or a CLI/other-process delete — which
    // made `/health.machines.total` report a stale count that diverged from
    // `/machines` and the DB (a monitoring/scheduling consumer then saw ghost
    // machines). Falls back to `None` if the DB read fails.
    let machines = state.list_vm_records().await.ok().map(|vms| {
        let total = vms.len();
        let running = vms.iter().filter(|(_, r)| r.process_can_run()).count();
        MachineCountsResponse { total, running }
    });
    let uptime = SERVER_START.get().map(|t| t.elapsed().as_secs());

    Json(HealthResponse {
        status: "ok",
        version: crate::VERSION,
        machines,
        uptime_seconds: uptime,
        nested_virt: state.nested_virt_allowed(),
        checkpoint_device_profiles: crate::portable_checkpoint::SUPPORTED_DEVICE_PROFILES.to_vec(),
        checkpoint_format_versions: vec![
            crate::portable_checkpoint::FORMAT_VERSION,
            crate::portable_checkpoint::HISTORY_FORMAT_VERSION,
            crate::portable_checkpoint::DELTA_FORMAT_VERSION,
        ],
    })
}

/// Readiness probe that exercises the **blocking pool** — the resource VM
/// start/exec/stop dispatch depends on.
///
/// `/health` is pure-async and keeps returning 200 even when the blocking pool is
/// exhausted, so the control's data-plane probe couldn't distinguish a wedged node
/// (start/exec timing out) from a healthy one, and never auto-cordoned it (the
/// 2026-07-05 worker-1 wedge). This round-trips a no-op `spawn_blocking` task under
/// a deadline: on a healthy pool it returns 200 in microseconds; if the pool can't
/// service it in [`READYZ_BUDGET`] the node is dispatch-wedged and it returns 503,
/// which the control treats as a data-plane failure and cordons.
#[utoipa::path(
    get,
    path = "/readyz",
    tag = "Health",
    responses(
        (status = 200, description = "Dispatch path (blocking pool) is responsive"),
        (status = 503, description = "Blocking pool saturated — node is dispatch-wedged")
    )
)]
pub async fn readyz() -> StatusCode {
    let probe = tokio::task::spawn_blocking(|| ());
    match tokio::time::timeout(READYZ_BUDGET, probe).await {
        Ok(Ok(())) => StatusCode::OK,
        // Timed out (pool saturated) or the task panicked/was cancelled — either way
        // the dispatch path is not servicing work; report unready.
        _ => StatusCode::SERVICE_UNAVAILABLE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn health_reports_image_archive_restore_support_without_starting_machines() {
        let root = tempfile::tempdir().unwrap();
        let db = crate::db::SmolvmDb::open_at(&root.path().join("machines.db")).unwrap();
        db.init_tables().unwrap();
        let state = Arc::new(ApiState::with_db(db));
        let Json(response) = health(State(state.clone())).await;
        let wire = serde_json::to_value(response).unwrap();
        let profiles = wire["checkpoint_device_profiles"].as_array().unwrap();
        assert!(profiles
            .iter()
            .any(|profile| profile == "smolvm-image-archive-v1"));
        assert!(profiles.iter().any(|profile| profile == "smolvm-basic-v1"));
        assert_eq!(wire["machines"]["total"], 0);
        assert!(wire["checkpoint_format_versions"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!(
                crate::portable_checkpoint::FORMAT_VERSION
            )));
        assert!(state.list_vm_records().await.unwrap().is_empty());
    }

    // On a healthy runtime the blocking-pool round-trip completes well inside the
    // budget, so readiness reports OK.
    #[tokio::test]
    async fn readyz_ok_when_pool_responsive() {
        assert_eq!(readyz().await, StatusCode::OK);
    }
}
