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

#[path = "errors.rs"]
pub mod error;
pub mod handlers;
pub mod state;
pub mod supervisor;
pub mod types;

use axum::{
    extract::Request,
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
        (name = "Machines", description = "Machine lifecycle management"),
        (name = "Execution", description = "Command execution in machines"),
        (name = "Logs", description = "Log streaming"),
        (name = "Images", description = "OCI image management"),
        (name = "Files", description = "File upload and download")
    ),
    paths(
        // Health
        handlers::health::health,
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
        handlers::machines::start_machine,
        handlers::machines::stop_machine,
        handlers::machines::delete_machine,
        handlers::machines::exec_machine,
        handlers::machines::resize_machine,
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
        types::MachineExecRequest,
        types::ResizeMachineRequest,
        // Response types
        types::HealthResponse,
        types::MachineInfo,
        types::MountInfo,
        types::ListMachinesResponse,
        types::ExecResponse,
        types::ImageInfo,
        types::ListImagesResponse,
        types::PullImageResponse,
        types::StartResponse,
        types::StopResponse,
        types::DeleteResponse,
        types::ApiErrorResponse,
    ))
)]
pub struct ApiDoc;

/// Default timeout for API requests (5 minutes).
/// Most operations (start, stop, exec) complete within this time.
/// Long-running operations like image pulls may need longer, but this
/// provides a reasonable upper bound for most requests.
const API_REQUEST_TIMEOUT_SECS: u64 = 300;

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
    // Health check route
    let health_route = Router::new().route("/health", get(handlers::health::health));

    // SSE logs route (no timeout - streams indefinitely)
    let logs_route = Router::new().route("/:id/logs", get(handlers::exec::stream_logs));

    // Machine routes with timeout
    let machine_routes_with_timeout = Router::new()
        .route("/", post(handlers::machines::create_machine))
        .route("/", get(handlers::machines::list_machines))
        .route("/:id", get(handlers::machines::get_machine))
        .route("/:id/start", post(handlers::machines::start_machine))
        .route("/:id/stop", post(handlers::machines::stop_machine))
        .route("/:id", delete(handlers::machines::delete_machine))
        // Exec routes
        .route("/:id/exec", post(handlers::exec::exec_command))
        .route("/:id/exec/stream", post(handlers::exec::exec_stream))
        .route("/:id/run", post(handlers::exec::run_command))
        // File I/O routes
        .route("/:id/files/*path", put(handlers::files::upload_file))
        .route("/:id/files/*path", get(handlers::files::download_file))
        // Image routes
        .route("/:id/images", get(handlers::images::list_images))
        .route("/:id/images/pull", post(handlers::images::pull_image))
        // Apply timeout only to these routes
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(API_REQUEST_TIMEOUT_SECS),
        ));

    // Machine routes
    let machine_routes = Router::new()
        .merge(logs_route)
        .merge(machine_routes_with_timeout);

    // API v1 routes
    let api_v1 = Router::new().nest("/machines", machine_routes);

    // CORS: Use configured origins, or default to localhost for security.
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

    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::DELETE,
        ])
        .allow_headers([axum::http::header::CONTENT_TYPE]);

    // Prometheus metrics
    let metrics_route = Router::new().route("/metrics", get(serve_metrics));

    // Combine all routes
    Router::new()
        .merge(health_route)
        .merge(metrics_route)
        .nest("/api/v1", api_v1)
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .layer(middleware::from_fn(trace_id_middleware))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
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
fn normalize_metrics_path(path: &str) -> String {
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() >= 4 && parts[1] == "api" && parts[3] == "machines" {
        if let Some(id_pos) = parts.get(4) {
            if !id_pos.is_empty() {
                let mut normalized = parts[..4].to_vec();
                normalized.push(":id");
                normalized.extend_from_slice(&parts[5..]);
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

    let span = tracing::info_span!("request", trace_id = %trace_id);
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
    use super::validate_command;

    #[test]
    fn test_validate_command() {
        assert!(validate_command(&[]).is_err());
        assert!(validate_command(&["echo".to_string()]).is_ok());
        assert!(validate_command(&["echo".to_string(), "hello".to_string()]).is_ok());
    }
}
