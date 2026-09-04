//! HTTP API server for smolvm.
//!
//! This module provides an HTTP API for managing machines, containers, and images
//! without CLI overhead.
//!
//! # Example
//!
//! ```bash
//! # Start the server on the default Unix socket
//! smolvm serve start
//!
//! # Or start the server on TCP explicitly
//! smolvm serve start --listen 127.0.0.1:8080
//!
//! # Create a machine
//! curl -X POST http://localhost:8080/api/v1/machines \
//!   -H "Content-Type: application/json" \
//!   -d '{"name": "test"}'
//! ```

pub mod admission;
#[cfg(target_os = "linux")]
pub(crate) mod device_handoff;
#[path = "errors.rs"]
pub mod error;
pub mod guest_rollout;
pub mod handlers;
pub mod pool_controller;
pub mod rollout;
pub mod state;
pub mod supervisor;
pub mod types;

use axum::{
    extract::{DefaultBodyLimit, Request},
    http::{HeaderValue, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::{delete, get, post, put},
    Router,
};
use std::sync::Arc;
use std::time::Duration;
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use self::error::ApiError;
use state::ApiState;

/// OpenAPI documentation for the smolvm API.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "smolvm API",
        version = "0.5.2",
        description = "smolvm API for managing machines and images.",
        license(name = "Apache-2.0", url = "https://www.apache.org/licenses/LICENSE-2.0")
    ),
    tags(
        (name = "Health", description = "Health check endpoints"),
        (name = "Node", description = "Node capacity introspection"),
        (name = "Machines", description = "Machine lifecycle management"),
        (name = "Pools", description = "Automatic held-fork worker pools"),
        (name = "Rollouts", description = "Framework-aware fused multi-policy rollout executors"),
        (name = "Execution", description = "Command execution in machines"),
        (name = "Logs", description = "Log streaming"),
        (name = "Images", description = "OCI image management"),
        (name = "Files", description = "File upload and download")
    ),
    paths(
        // Health
        handlers::health::health,
        // Node
        handlers::node::capacity,
        // Execution
        handlers::exec::exec_command,
        handlers::exec::exec_stream,
        handlers::exec::run_command,
        handlers::exec::stream_logs,
        // Files
        handlers::files::upload_file,
        handlers::files::download_file,
        // Images
        handlers::images::list_images,
        handlers::images::pull_image,
        // Machines
        handlers::machines::create_machine,
        handlers::machines::list_machines,
        handlers::machines::get_machine,
        handlers::machines::get_machine_egress_events,
        handlers::machines::start_machine,
        handlers::machines::branch_machine,
        handlers::machines::fork_machine,
        handlers::machines::release_held_fork,
        handlers::machines::stop_machine,
        handlers::machines::sync_machine,
        handlers::machines::delete_machine,
        handlers::machines::resize_machine,
        handlers::machines::export_machine,
        // Pools
        handlers::pools::create_pool,
        handlers::pools::list_pools,
        handlers::pools::get_pool,
        handlers::pools::resize_pool,
        handlers::pools::delete_pool,
        handlers::pools::acquire_lease,
        handlers::pools::acquire_lease_batch,
        handlers::pools::get_lease,
        handlers::pools::heartbeat_lease,
        handlers::pools::complete_lease,
        // Fused rollouts
        handlers::rollouts::create_executor,
        handlers::rollouts::list_executors,
        handlers::rollouts::get_executor,
        handlers::rollouts::delete_executor,
        handlers::rollouts::publish_policy,
        handlers::rollouts::publish_device_policy,
        handlers::rollouts::retire_policy,
        handlers::rollouts::generate,
        handlers::rollouts::generate_batch,
    ),
    components(schemas(
        // Request types
        types::CreateMachineRequest,
        types::RestartSpec,
        types::MountSpec,
        types::PortSpec,
        types::ResourceSpec,
        types::ExecRequest,
        types::RunRequest,
        types::EnvVar,
        types::PullImageRequest,
        types::DeleteQuery,
        types::LogsQuery,
        types::ResizeMachineRequest,
        types::ForkRequest,
        types::ForkReleaseRequest,
        types::ExportRequest,
        types::StartMachineQuery,
        types::CreateForkPoolRequest,
        types::DeleteForkPoolQuery,
        types::AcquireForkLeaseRequest,
        types::AcquireForkLeaseBatchRequest,
        types::RolloutLeaseAccess,
        types::ForkLeasePayloadFile,
        types::ResizeForkPoolRequest,
        rollout::CreateRolloutExecutorRequest,
        rollout::PublishRolloutPolicyRequest,
        rollout::PublishDeviceRolloutPolicyRequest,
        rollout::RolloutPrompt,
        rollout::RolloutSamplingParams,
        rollout::RolloutCohort,
        rollout::RolloutGenerateRequest,
        rollout::RolloutBatchRequest,
        // Response types
        types::HealthResponse,
        types::CapacityResponse,
        types::CudaDeviceCapacity,
        types::MachineInfo,
        types::EgressDenialInfo,
        types::EgressEventsResponse,
        types::MountInfo,
        types::ListMachinesResponse,
        types::ExecResponse,
        types::ExportResponse,
        types::ImageInfo,
        types::ListImagesResponse,
        types::PullImageResponse,
        types::StartResponse,
        types::StopResponse,
        types::DeleteResponse,
        types::ApiErrorResponse,
        types::ForkPoolInfo,
        types::ListForkPoolsResponse,
        types::ForkLeaseInfo,
        types::ForkLeaseBatchItemResponse,
        types::AcquireForkLeaseBatchResponse,
        rollout::RolloutExecutorInfo,
        rollout::RolloutPolicyInfo,
        rollout::RolloutCompletion,
        rollout::RolloutUsage,
        rollout::RolloutGenerateResponse,
        rollout::RolloutBatchItemResponse,
        rollout::RolloutBatchResponse,
    ))
)]
pub struct ApiDoc;

/// Default timeout for API requests (5 minutes).
/// Most operations (start, stop, exec) complete within this time.
/// Long-running operations like image pulls may need longer, but this
/// provides a reasonable upper bound for most requests.
const API_REQUEST_TIMEOUT_SECS: u64 = 300;

/// Body cap for the file-upload route. axum's 2 MiB default silently 413s larger
/// uploads before the handler runs; the control plane permits 100 MiB, so match
/// it here. The agent streams the write and enforces the true ceiling.
const MAX_FILE_UPLOAD_BYTES: usize = 100 * 1024 * 1024;
/// Bounded but large enough for cohorts of pre-tokenized RL prompts.
const MAX_ROLLOUT_REQUEST_BYTES: usize = 20 * 1024 * 1024;

/// Validate that an API command payload is not empty.
pub fn validate_command(cmd: &[String]) -> Result<(), ApiError> {
    if cmd.is_empty() {
        return Err(ApiError::BadRequest("command cannot be empty".into()));
    }
    Ok(())
}

/// Create the API router with all endpoints.
///
/// `cors_origins` specifies allowed CORS origins. If empty, defaults to
/// localhost:8080 and localhost:3000 (both http and 127.0.0.1 variants).
pub fn create_router(state: Arc<ApiState>, cors_origins: Vec<String>) -> Router {
    // Health check route. `/health` is liveness (pure-async, always answers);
    // `/readyz` is a dispatch-path readiness probe that exercises the blocking pool
    // so the control can detect — and cordon — a node whose start/exec are wedged
    // even while `/health` still returns 200.
    let health_route = Router::new()
        .route("/health", get(handlers::health::health))
        .route("/readyz", get(handlers::health::readyz));

    // Node capacity introspection (polled by a fleet node-agent over HTTP).
    let capacity_route = Router::new().route("/capacity", get(handlers::node::capacity));

    // Explicit, control-initiated node drain (decommission). Stops all VMs
    // cleanly. Control-only by construction (the listener is mTLS-gated; the
    // loopback door is localhost). See docs/lossless-serve-restart.md.
    let drain_route = Router::new().route("/drain", post(handlers::machines::drain_node));

    // Brokered P2P blob serving: hand a cached layer blob to a sibling node so a
    // create on another node can pull it from a peer instead of the registry.
    // Read-only, content-addressed, and mTLS-gated by the listener by
    // construction (like /drain, see the comment above). No request timeout:
    // blobs can be large.
    let p2p_route = Router::new().route("/p2p/blob/{digest}", get(handlers::p2p::serve_blob));

    // Control-initiated artifact pre-warm: pull a `.smolmachine` layer into this
    // node's blob cache before any machine needs it, so a create finds it warm
    // instead of racing a cold multi-hundred-MB download against a client's
    // readiness timeout. mTLS-gated by the listener like `/drain` and `/p2p`
    // above. No request timeout: the transfer is as large as a blob pull, and
    // it runs off the critical path where slowness costs nothing.
    let warm_route = Router::new().route("/artifacts/warm", post(handlers::prewarm::warm_artifact));

    // Long-lived streaming routes (no request timeout): SSE logs and the
    // interactive PTY WebSocket both outlive the 5-minute API timeout.
    let logs_route = Router::new()
        .route("/{id}/logs", get(handlers::exec::stream_logs))
        .route(
            "/{id}/checkpoint",
            post(handlers::machines::capture_portable_checkpoint)
                .put(handlers::machines::restore_portable_checkpoint),
        )
        .route(
            "/{id}/exec/interactive",
            get(handlers::exec::exec_interactive),
        );

    // Machine routes with timeout
    let machine_routes_with_timeout = Router::new()
        .route("/", post(handlers::machines::create_machine))
        .route("/", get(handlers::machines::list_machines))
        .route("/{id}", get(handlers::machines::get_machine))
        .route(
            "/{id}/egress-events",
            get(handlers::machines::get_machine_egress_events),
        )
        .route("/{id}/start", post(handlers::machines::start_machine))
        .route("/{id}/branches", post(handlers::machines::branch_machine))
        .route("/{id}/fork", post(handlers::machines::fork_machine))
        .route(
            "/{id}/branch-release",
            post(handlers::machines::release_held_fork),
        )
        .route(
            "/{id}/fork-release",
            post(handlers::machines::release_held_fork),
        )
        .route("/{id}/stop", post(handlers::machines::stop_machine))
        .route("/{id}/sync", post(handlers::machines::sync_machine))
        .route("/{id}/resize", post(handlers::machines::resize_machine))
        .route("/{id}/export", post(handlers::machines::export_machine))
        .route("/{id}", delete(handlers::machines::delete_machine))
        // Exec routes
        .route("/{id}/exec", post(handlers::exec::exec_command))
        .route("/{id}/exec/stream", post(handlers::exec::exec_stream))
        .route("/{id}/run", post(handlers::exec::run_command))
        // File I/O routes. The upload handler buffers the whole body (`body:
        // Bytes`), so without a raised limit axum's 2 MiB default rejects any
        // larger upload with a bare 413 "Failed to buffer the request body" —
        // the control plane already permits 100 MiB here, so match it (the agent
        // streams the write, so the real ceiling is FILE_TRANSFER_MAX_TOTAL).
        // Per-route so only uploads get the large cap; the agent enforces the
        // true maximum.
        .route(
            "/{id}/files/{*path}",
            put(handlers::files::upload_file).layer(DefaultBodyLimit::max(MAX_FILE_UPLOAD_BYTES)),
        )
        .route("/{id}/files/{*path}", get(handlers::files::download_file))
        // Image routes
        .route("/{id}/images", get(handlers::images::list_images))
        .route("/{id}/images/pull", post(handlers::images::pull_image))
        // Apply timeout only to these routes
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(API_REQUEST_TIMEOUT_SECS),
        ));

    // Machine routes
    let machine_routes = Router::new()
        .merge(logs_route)
        .merge(machine_routes_with_timeout);

    // Automatic pool operations are bounded by the same request timeout as
    // machine lifecycle calls. Pool fill and worker replacement happen in the
    // background controller, so create/delete themselves stay quick.
    let pool_routes = Router::new()
        .route("/", post(handlers::pools::create_pool))
        .route("/", get(handlers::pools::list_pools))
        .route("/{name}", get(handlers::pools::get_pool))
        .route("/{name}", delete(handlers::pools::delete_pool))
        .route("/{name}/size", put(handlers::pools::resize_pool))
        .route("/{name}/leases", post(handlers::pools::acquire_lease))
        .route(
            "/{name}/lease-batches",
            post(handlers::pools::acquire_lease_batch),
        )
        .route("/{name}/leases/{lease}", get(handlers::pools::get_lease))
        .route(
            "/{name}/leases/{lease}/heartbeat",
            post(handlers::pools::heartbeat_lease),
        )
        .route(
            "/{name}/leases/{lease}/complete",
            post(handlers::pools::complete_lease),
        )
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(API_REQUEST_TIMEOUT_SECS),
        ));

    // Volume provisioning (node-side storage for the control plane): create the
    // backing storage on THIS worker and return its host path. See
    // handlers::volumes.
    let volume_routes = Router::new()
        .route("/", post(handlers::volumes::provision_volume))
        .route("/{id}", delete(handlers::volumes::deprovision_volume));

    // Fused rollout handlers own their deadlines so cancelled clients abort the
    // backend HTTP request instead of inheriting the generic lifecycle timeout.
    let rollout_routes = Router::new()
        .route("/", post(handlers::rollouts::create_executor))
        .route("/", get(handlers::rollouts::list_executors))
        .route("/{name}", get(handlers::rollouts::get_executor))
        .route("/{name}", delete(handlers::rollouts::delete_executor))
        .route("/{name}/policies", post(handlers::rollouts::publish_policy))
        .route(
            "/{name}/device-policies",
            post(handlers::rollouts::publish_device_policy),
        )
        .route(
            "/{name}/policies/{policy}/{version}",
            delete(handlers::rollouts::retire_policy),
        )
        .route("/{name}/generate", post(handlers::rollouts::generate))
        .route("/{name}/batches", post(handlers::rollouts::generate_batch))
        .layer(DefaultBodyLimit::max(MAX_ROLLOUT_REQUEST_BYTES));

    // API v1 routes
    let api_v1 = Router::new()
        .nest("/machines", machine_routes)
        .nest("/pools", pool_routes)
        .nest("/rollout-executors", rollout_routes)
        .nest("/volumes", volume_routes);

    let cors = build_cors(cors_origins);

    // Prometheus metrics
    let metrics_route = Router::new().route("/metrics", get(serve_metrics));

    // Combine all routes
    Router::new()
        .merge(health_route)
        .merge(capacity_route)
        .merge(drain_route)
        .merge(p2p_route)
        .merge(warm_route)
        .merge(metrics_route)
        .nest("/api/v1", api_v1)
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .layer(middleware::from_fn(trace_id_middleware))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}

/// Build the shared CORS layer from the configured origins (falling back to the
/// localhost defaults). Shared by [`create_router`] and [`create_local_router`].
fn build_cors(cors_origins: Vec<String>) -> CorsLayer {
    let default_origins = || {
        vec![
            "http://localhost:8080"
                .parse()
                .expect("hardcoded CORS origin"),
            "http://127.0.0.1:8080"
                .parse()
                .expect("hardcoded CORS origin"),
            "http://localhost:3000"
                .parse()
                .expect("hardcoded CORS origin"),
            "http://127.0.0.1:3000"
                .parse()
                .expect("hardcoded CORS origin"),
        ]
    };
    let origins: Vec<axum::http::HeaderValue> = if cors_origins.is_empty() {
        default_origins()
    } else {
        let mut valid = Vec::new();
        for origin in &cors_origins {
            match origin.parse() {
                Ok(v) => valid.push(v),
                Err(e) => {
                    tracing::warn!(origin = %origin, error = %e, "invalid CORS origin, skipping");
                }
            }
        }
        if valid.is_empty() {
            tracing::warn!("no valid CORS origins provided, falling back to defaults");
            default_origins()
        } else {
            valid
        }
    };
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::DELETE,
        ])
        .allow_headers([axum::http::header::CONTENT_TYPE])
}

/// The router served on the plain-HTTP LOOPBACK door (fleet mode), as distinct
/// from the full [`create_router`] served on the mTLS network port.
///
/// The loopback door is unauthenticated by construction — anything that can
/// reach `127.0.0.1` on the node gets in. Serving the full router there exposed
/// the machine/file/exec API (`/api/v1/*`) to any local caller, and a crafted
/// registry reference (`127.0.0.1:<port>/...`) makes the node's OWN in-process
/// registry-pull client such a caller: it turns an attacker-supplied image ref
/// into unauthenticated reads/writes against `download_file` / `upload_file`.
///
/// The door's only legitimate job is liveness — a fleet node-agent polling
/// `/capacity` (plus `/health`/`/readyz`, and read-only `/metrics`). Restricting
/// it to exactly those routes closes the SSRF pivot without touching the mTLS
/// control path, which keeps the full API. Everything else 404s on loopback.
pub fn create_local_router(state: Arc<ApiState>, cors_origins: Vec<String>) -> Router {
    let cors = build_cors(cors_origins);
    Router::new()
        .route("/health", get(handlers::health::health))
        .route("/readyz", get(handlers::health::readyz))
        .route("/capacity", get(handlers::node::capacity))
        .route("/metrics", get(serve_metrics))
        .layer(middleware::from_fn(trace_id_middleware))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}

#[cfg(test)]
mod loopback_router_test {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    async fn status(router: axum::Router, method: &str, path: &str) -> StatusCode {
        router
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }

    // The loopback door must NOT expose the machine/file/exec API — that is the
    // SSRF pivot this router closes. Liveness routes must still answer.
    #[tokio::test]
    async fn loopback_router_excludes_machine_file_exec_api() {
        let dir = tempfile::TempDir::new().unwrap();
        let db = crate::db::SmolvmDb::open_at(&dir.path().join("t.db")).unwrap();
        let state = std::sync::Arc::new(crate::api::state::ApiState::with_db(db));
        let local = create_local_router(state.clone(), vec![]);

        // The attack surface — every one must be 404 (route absent) on loopback:
        for (m, p) in [
            ("GET", "/api/v1/machines"),
            ("GET", "/api/v1/machines/x/files/etc/passwd"),
            ("PUT", "/api/v1/machines/x/files/etc/cron.d/x"),
            ("POST", "/api/v1/machines/x/exec"),
            ("POST", "/api/v1/machines"),
        ] {
            assert_eq!(
                status(local.clone(), m, p).await,
                StatusCode::NOT_FOUND,
                "loopback door must NOT expose {m} {p}"
            );
        }
        // Liveness must still work (not 404) so the node-agent poll survives:
        assert_ne!(
            status(local.clone(), "GET", "/capacity").await,
            StatusCode::NOT_FOUND,
            "loopback /capacity must remain served"
        );
        assert_ne!(
            status(local.clone(), "GET", "/health").await,
            StatusCode::NOT_FOUND,
            "loopback /health must remain served"
        );

        // Sanity: the FULL router (mTLS port) still DOES expose the API.
        let full = create_router(state, vec![]);
        assert_ne!(
            status(full, "GET", "/api/v1/machines").await,
            StatusCode::NOT_FOUND,
            "full router must still expose the machine API on the mTLS port"
        );
    }
}

/// Install the global Prometheus metrics recorder.
/// Returns None if a recorder is already installed (e.g., in tests).
pub fn install_metrics_recorder() -> Option<metrics_exporter_prometheus::PrometheusHandle> {
    metrics_exporter_prometheus::PrometheusBuilder::new()
        .install_recorder()
        .ok()
}

/// Serve Prometheus metrics as text.
async fn serve_metrics() -> String {
    METRICS_HANDLE.get().map(|h| h.render()).unwrap_or_default()
}

/// Global handle to the Prometheus recorder, set once at startup.
/// Only accessed by serve.rs (startup) and serve_metrics (handler).
pub static METRICS_HANDLE: std::sync::OnceLock<metrics_exporter_prometheus::PrometheusHandle> =
    std::sync::OnceLock::new();

/// Normalize a request path for Prometheus labels.
/// Replaces machine IDs with `:id` to prevent cardinality explosion.
/// Pull the machine id out of `/api/v1/machines/<id>/...` so request logs can be
/// attributed to a specific machine. Metrics deliberately normalize this segment
/// away (cardinality), but logs need it: without it a failed start is an
/// anonymous 5xx and answering "why did this customer's machine fail" means
/// grepping journals on every worker by hand.
fn machine_id_from_path(path: &str) -> Option<&str> {
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() >= 5 && parts[1] == "api" && parts[3] == "machines" {
        return parts.get(4).copied().filter(|s| !s.is_empty());
    }
    None
}

fn normalize_metrics_path(path: &str) -> String {
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() >= 4
        && parts[1] == "api"
        && matches!(parts[3], "machines" | "pools" | "rollout-executors")
    {
        if let Some(id_pos) = parts.get(4) {
            if !id_pos.is_empty() {
                let mut normalized = parts[..4].to_vec();
                normalized.push(":id");
                normalized.extend_from_slice(&parts[5..]);
                if parts[3] == "rollout-executors"
                    && normalized.get(5) == Some(&"policies")
                    && normalized.len() >= 8
                {
                    normalized[6] = ":policy";
                    normalized[7] = ":version";
                }
                return normalized.join("/");
            }
        }
    }
    path.to_string()
}

/// Trace ID for correlating API requests to agent operations.
#[derive(Clone, Debug)]
pub struct TraceId(pub String);

/// Middleware that generates a unique trace ID for each request and returns it
/// in the `X-Trace-Id` response header.
async fn trace_id_middleware(mut req: Request, next: Next) -> Response {
    use std::sync::atomic::{AtomicU64, Ordering};
    use tracing::Instrument;

    static REQUEST_SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = REQUEST_SEQ.fetch_add(1, Ordering::Relaxed);
    let trace_id = format!("{:08x}{:08x}", seq, std::process::id());

    req.extensions_mut().insert(TraceId(trace_id.clone()));

    let method = req.method().to_string();
    // Normalize path to template to avoid cardinality explosion from machine IDs
    let path_template = normalize_metrics_path(req.uri().path());

    // Attach the machine id to the span so every line emitted while handling the
    // request — including the trace layer's response-failure log — is attributable.
    let machine = machine_id_from_path(req.uri().path())
        .unwrap_or("-")
        .to_string();
    let span = tracing::info_span!("request", trace_id = %trace_id, machine = %machine);
    let mut response = next.run(req).instrument(span).await;

    let status = response.status().as_u16().to_string();
    metrics::counter!("smolvm_api_requests_total", "method" => method, "status" => status, "path" => path_template).increment(1);

    if let Ok(val) = HeaderValue::from_str(&trace_id) {
        response.headers_mut().insert("x-trace-id", val);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::{machine_id_from_path, normalize_metrics_path, validate_command};

    #[test]
    fn machine_id_is_extracted_from_machine_routes() {
        assert_eq!(
            machine_id_from_path("/api/v1/machines/my-vm"),
            Some("my-vm")
        );
        assert_eq!(
            machine_id_from_path("/api/v1/machines/my-vm/start"),
            Some("my-vm")
        );
        assert_eq!(
            machine_id_from_path("/api/v1/machines/my-vm/exec"),
            Some("my-vm")
        );
    }

    #[test]
    fn non_machine_routes_have_no_machine_id() {
        assert_eq!(machine_id_from_path("/health"), None);
        assert_eq!(machine_id_from_path("/api/v1/machines"), None);
        assert_eq!(machine_id_from_path("/api/v1/machines/"), None);
    }

    #[test]
    fn metrics_paths_hide_rollout_and_pool_identifiers() {
        assert_eq!(
            normalize_metrics_path("/api/v1/pools/team-a/leases"),
            "/api/v1/pools/:id/leases"
        );
        assert_eq!(
            normalize_metrics_path("/api/v1/rollout-executors/qwen/policies/experiment-1/step-400"),
            "/api/v1/rollout-executors/:id/policies/:policy/:version"
        );
        assert_eq!(
            normalize_metrics_path("/api/v1/rollout-executors/qwen/generate"),
            "/api/v1/rollout-executors/:id/generate"
        );
    }

    #[test]
    fn test_validate_command() {
        assert!(validate_command(&[]).is_err());
        assert!(validate_command(&["echo".to_string()]).is_ok());
        assert!(validate_command(&["echo".to_string(), "hello".to_string()]).is_ok());
    }
}
