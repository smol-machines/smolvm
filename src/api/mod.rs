//! HTTP API server for smolvm.
//!
//! This module provides an HTTP API for managing sandboxes, containers, and images
//! without CLI overhead.
//!
//! # Example
//!
//! ```bash
//! # Start the server
//! smolvm serve --listen 127.0.0.1:8080
//!
//! # Create a sandbox
//! curl -X POST http://localhost:8080/api/v1/sandboxes \
//!   -H "Content-Type: application/json" \
//!   -d '{"name": "test"}'
//! ```

pub mod error;
pub mod handlers;
pub mod state;
pub mod supervisor;
pub mod types;
pub mod validation;

use axum::{
    routing::{delete, get, post},
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
        version = "0.1.6",
        description = "OCI-native microVM runtime API for managing sandboxes, containers, images, and microvms.",
        license(name = "Apache-2.0", url = "https://www.apache.org/licenses/LICENSE-2.0")
    ),
    tags(
        (name = "Health", description = "Health check endpoints"),
        (name = "Sandboxes", description = "Sandbox lifecycle management"),
        (name = "Execution", description = "Command execution in sandboxes"),
        (name = "Logs", description = "Log streaming"),
        (name = "Containers", description = "Container management within sandboxes"),
        (name = "Images", description = "OCI image management"),
        (name = "MicroVMs", description = "Persistent microVM management")
    ),
    paths(
        // Health
        handlers::health::health,
        // Sandboxes
        handlers::sandboxes::create_sandbox,
        handlers::sandboxes::list_sandboxes,
        handlers::sandboxes::get_sandbox,
        handlers::sandboxes::start_sandbox,
        handlers::sandboxes::stop_sandbox,
        handlers::sandboxes::delete_sandbox,
        // Execution
        handlers::exec::exec_command,
        handlers::exec::run_command,
        handlers::exec::stream_logs,
        // Containers
        handlers::containers::create_container,
        handlers::containers::list_containers,
        handlers::containers::start_container,
        handlers::containers::stop_container,
        handlers::containers::delete_container,
        handlers::containers::exec_in_container,
        // Images
        handlers::images::list_images,
        handlers::images::pull_image,
        // MicroVMs
        handlers::microvms::create_microvm,
        handlers::microvms::list_microvms,
        handlers::microvms::get_microvm,
        handlers::microvms::start_microvm,
        handlers::microvms::stop_microvm,
        handlers::microvms::delete_microvm,
        handlers::microvms::exec_microvm,
    ),
    components(schemas(
        // Request types
        types::CreateSandboxRequest,
        types::RestartSpec,
        types::MountSpec,
        types::PortSpec,
        types::ResourceSpec,
        types::ExecRequest,
        types::RunRequest,
        types::EnvVar,
        types::CreateContainerRequest,
        types::ContainerMountSpec,
        types::ContainerExecRequest,
        types::StopContainerRequest,
        types::DeleteContainerRequest,
        types::PullImageRequest,
        types::DeleteQuery,
        types::LogsQuery,
        types::CreateMicrovmRequest,
        types::MicrovmExecRequest,
        // Response types
        types::HealthResponse,
        types::SandboxInfo,
        types::MountInfo,
        types::ListSandboxesResponse,
        types::ExecResponse,
        types::ContainerInfo,
        types::ListContainersResponse,
        types::ImageInfo,
        types::ListImagesResponse,
        types::PullImageResponse,
        types::MicrovmInfo,
        types::ListMicrovmsResponse,
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

    // Sandbox routes with timeout
    let sandbox_routes_with_timeout = Router::new()
        .route("/", post(handlers::sandboxes::create_sandbox))
        .route("/", get(handlers::sandboxes::list_sandboxes))
        .route("/:id", get(handlers::sandboxes::get_sandbox))
        .route("/:id/start", post(handlers::sandboxes::start_sandbox))
        .route("/:id/stop", post(handlers::sandboxes::stop_sandbox))
        .route("/:id", delete(handlers::sandboxes::delete_sandbox))
        // Exec routes
        .route("/:id/exec", post(handlers::exec::exec_command))
        .route("/:id/run", post(handlers::exec::run_command))
        // Container routes
        .route(
            "/:id/containers",
            post(handlers::containers::create_container),
        )
        .route(
            "/:id/containers",
            get(handlers::containers::list_containers),
        )
        .route(
            "/:id/containers/:cid/start",
            post(handlers::containers::start_container),
        )
        .route(
            "/:id/containers/:cid/stop",
            post(handlers::containers::stop_container),
        )
        .route(
            "/:id/containers/:cid",
            delete(handlers::containers::delete_container),
        )
        .route(
            "/:id/containers/:cid/exec",
            post(handlers::containers::exec_in_container),
        )
        // Image routes
        .route("/:id/images", get(handlers::images::list_images))
        .route("/:id/images/pull", post(handlers::images::pull_image))
        // Apply timeout only to these routes
        .layer(TimeoutLayer::new(Duration::from_secs(
            API_REQUEST_TIMEOUT_SECS,
        )));

    // Combine sandbox routes (with and without timeout)
    let sandbox_routes = Router::new()
        .merge(logs_route)
        .merge(sandbox_routes_with_timeout);

    // MicroVM routes
    let microvm_routes = Router::new()
        .route("/", post(handlers::microvms::create_microvm))
        .route("/", get(handlers::microvms::list_microvms))
        .route("/:name", get(handlers::microvms::get_microvm))
        .route("/:name/start", post(handlers::microvms::start_microvm))
        .route("/:name/stop", post(handlers::microvms::stop_microvm))
        .route("/:name", delete(handlers::microvms::delete_microvm))
        .route("/:name/exec", post(handlers::microvms::exec_microvm))
        .layer(TimeoutLayer::new(Duration::from_secs(
            API_REQUEST_TIMEOUT_SECS,
        )));

    // API v1 routes
    let api_v1 = Router::new()
        .nest("/sandboxes", sandbox_routes)
        .nest("/microvms", microvm_routes);

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
