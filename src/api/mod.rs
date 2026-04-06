//! HTTP API server for smolvm.
//!
//! This module provides an HTTP API for managing machines, containers, and images
//! without CLI overhead.
//!
//! # Example
//!
//! ```bash
//! # Start the server
//! smolvm serve --listen 127.0.0.1:8080
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
pub mod validation;

use axum::{
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

use state::ApiState;

/// OpenAPI documentation for the smolvm API.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "smolvm API",
        version = "0.5.1",
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
        .route("/:id/run", post(handlers::exec::run_command))
        // File I/O routes
        .route("/:id/files/*path", put(handlers::files::upload_file))
        .route("/:id/files/*path", get(handlers::files::download_file))
        // Image routes
        .route("/:id/images", get(handlers::images::list_images))
        .route("/:id/images/pull", post(handlers::images::pull_image))
        // Apply timeout only to these routes
        .layer(TimeoutLayer::new(Duration::from_secs(
            API_REQUEST_TIMEOUT_SECS,
        )));

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

    // Combine all routes
    Router::new()
        .merge(health_route)
        .nest("/api/v1", api_v1)
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}
