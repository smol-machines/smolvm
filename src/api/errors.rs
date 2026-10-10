//! API error types with HTTP status mapping.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use std::fmt::Display;

/// API error type with HTTP status code mapping.
#[derive(Debug, Clone)]
pub enum ApiError {
    /// Missing or invalid authentication credentials (401).
    Unauthorized(String),
    /// Authenticated caller is not allowed to access this resource (403).
    Forbidden(String),
    /// Resource not found (404).
    NotFound(String),
    /// Conflict - resource already exists or invalid state (409).
    Conflict(String),
    /// A published host port could not be bound because it is already in use
    /// (409). Distinct from `Conflict` so the control plane can recognize this
    /// specific, retryable failure (reallocate a different port and retry)
    /// instead of treating it as a generic 500/409.
    PortConflict(String),
    /// A restored clone could not prove that its inherited machine identity was
    /// replaced. The clone has been torn down, so callers may safely retry.
    CloneIdentityRejuvenationFailed(String),
    /// Bad request - invalid input (400).
    BadRequest(String),
    /// The request body is larger than this route accepts (413).
    PayloadTooLarge(String),
    /// Durable refusal: retries of this operation cannot apply the resize.
    ResizeRejected {
        /// Request identity whose rejection has been persisted.
        operation_id: String,
        /// Machine incarnation to which the decision applies.
        runtime: crate::agent::live_resize::RuntimeIdentity,
        /// Reason the operation was refused before changing resources.
        message: String,
    },
    /// Request timeout (408).
    Timeout,
    /// Temporarily unavailable (503).
    Unavailable(String),
    /// Internal server error (500).
    Internal(String),
}

impl ApiError {
    /// Convert any displayable error to an internal API error.
    pub fn internal(err: impl Display) -> Self {
        Self::Internal(err.to_string())
    }

    /// Wrap a database-layer error with a consistent message prefix.
    pub fn database(err: impl Display) -> Self {
        Self::Internal(format!("database error: {}", err))
    }
}

/// JSON error response body.
#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    code: &'static str,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            ApiError::ResizeRejected {
                operation_id,
                runtime,
                message,
            } => {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(serde_json::json!({
                        "code": "RESIZE_REJECTED", "error": message,
                        "operationId": operation_id, "runtime": runtime,
                    })),
                )
                    .into_response();
            }
            ApiError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, "UNAUTHORIZED", msg),
            ApiError::Forbidden(msg) => (StatusCode::FORBIDDEN, "FORBIDDEN", msg),
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, "NOT_FOUND", msg),
            ApiError::Conflict(msg) => (StatusCode::CONFLICT, "CONFLICT", msg),
            ApiError::PortConflict(msg) => (StatusCode::CONFLICT, "PORT_IN_USE", msg),
            ApiError::CloneIdentityRejuvenationFailed(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "CLONE_IDENTITY_REJUVENATION_FAILED",
                msg,
            ),
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, "BAD_REQUEST", msg),
            ApiError::PayloadTooLarge(msg) => {
                (StatusCode::PAYLOAD_TOO_LARGE, "PAYLOAD_TOO_LARGE", msg)
            }
            ApiError::Timeout => (
                StatusCode::REQUEST_TIMEOUT,
                "TIMEOUT",
                "request timed out".to_string(),
            ),
            ApiError::Unavailable(msg) => (StatusCode::SERVICE_UNAVAILABLE, "UNAVAILABLE", msg),
            ApiError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", msg),
        };
        // The access log records only the status of a failed response; the
        // reason exists nowhere on the server unless it is logged here, inside
        // the request span that names the machine.
        match failure_log_level(status) {
            Some(tracing::Level::WARN) => {
                tracing::warn!(status = status.as_u16(), code, error = %message, "request unavailable")
            }
            Some(_) => {
                tracing::error!(status = status.as_u16(), code, error = %message, "request failed")
            }
            None => {}
        }

        let body = Json(ErrorResponse {
            error: message,
            code,
        });

        (status, body).into_response()
    }
}

/// Level at which a failed response's reason is logged: a server failure is
/// an error, a temporarily unavailable server a warning, and a client error is
/// the caller's to report.
fn failure_log_level(status: StatusCode) -> Option<tracing::Level> {
    if status == StatusCode::SERVICE_UNAVAILABLE {
        Some(tracing::Level::WARN)
    } else if status.is_server_error() {
        Some(tracing::Level::ERROR)
    } else {
        None
    }
}

impl From<crate::error::Error> for ApiError {
    fn from(err: crate::error::Error) -> Self {
        match &err {
            crate::error::Error::VmNotFound { name } => {
                ApiError::NotFound(format!("machine not found: {}", name))
            }
            crate::error::Error::InvalidState { expected, actual } => ApiError::Conflict(format!(
                "invalid state: expected {}, got {}",
                expected, actual
            )),
            // Handle structured Agent errors using kind for HTTP status mapping
            crate::error::Error::Agent { reason, kind, .. } => match kind {
                crate::error::AgentErrorKind::NotFound => ApiError::NotFound(reason.clone()),
                crate::error::AgentErrorKind::Conflict => ApiError::Conflict(reason.clone()),
                crate::error::AgentErrorKind::Forbidden => ApiError::Forbidden(reason.clone()),
                crate::error::AgentErrorKind::Other if is_invalid_image_archive(reason) => {
                    ApiError::BadRequest(reason.clone())
                }
                crate::error::AgentErrorKind::Other => ApiError::Internal(reason.clone()),
            },
            _ => ApiError::Internal(err.to_string()),
        }
    }
}

/// Whether a failure says the caller's image archive is not a container image:
/// empty or truncated (no `manifest.json`), not a tar at all, or corrupt gzip.
/// Retrying cannot help and only the caller can fix it, so it is a 400.
pub(crate) fn is_invalid_image_archive(message: &str) -> bool {
    [
        "manifest.json not found in tar",
        "archive/tar: invalid tar header",
        "invalid gzip header",
        "corrupt deflate stream",
    ]
    .iter()
    .any(|marker| message.contains(marker))
}

/// Classify errors from `ensure_machine_running` into proper HTTP status codes.
///
/// Mount validation errors are 400 (Bad Request), everything else uses the
/// standard `Error -> ApiError` mapping (500 for startup failures, etc.).
pub fn classify_ensure_running_error(err: crate::Error) -> ApiError {
    match &err {
        crate::Error::Mount { .. }
        | crate::Error::InvalidMountPath { .. }
        | crate::Error::MountSourceNotFound { .. } => {
            ApiError::BadRequest(format!("mount validation failed: {}", err))
        }
        _ => ApiError::from(err),
    }
}

impl From<tokio::task::JoinError> for ApiError {
    fn from(err: tokio::task::JoinError) -> Self {
        ApiError::Internal(format!("task failed: {}", err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    #[test]
    fn an_archive_that_is_not_a_container_image_is_the_callers_error() {
        for reason in [
            "crane export failed: Error: reading tarball from stdin: file manifest.json not found in tar (is the image a valid `docker save` / OCI archive?)",
            "crane export failed: Error: reading tarball from stdin: archive/tar: invalid tar header (is the image a valid `docker save` / OCI archive?)",
            "failed to decompress archive: invalid gzip header",
        ] {
            let err = crate::error::Error::agent("pull image", reason);
            assert!(matches!(ApiError::from(err), ApiError::BadRequest(_)), "{reason}");
        }
        let err =
            crate::error::Error::agent("pull image", "failed to spawn crane export: No such file");
        assert!(matches!(ApiError::from(err), ApiError::Internal(_)));
    }

    #[test]
    fn test_api_error_status_codes() {
        let cases = [
            (ApiError::Unauthorized("x".into()), StatusCode::UNAUTHORIZED),
            (ApiError::Forbidden("x".into()), StatusCode::FORBIDDEN),
            (ApiError::NotFound("x".into()), StatusCode::NOT_FOUND),
            (ApiError::Conflict("x".into()), StatusCode::CONFLICT),
            (
                ApiError::CloneIdentityRejuvenationFailed("x".into()),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (ApiError::BadRequest("x".into()), StatusCode::BAD_REQUEST),
            (
                ApiError::PayloadTooLarge("x".into()),
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
            (ApiError::Timeout, StatusCode::REQUEST_TIMEOUT),
            (
                ApiError::Unavailable("x".into()),
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                ApiError::Internal("x".into()),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(error.into_response().status(), expected);
        }
    }

    #[test]
    fn server_errors_log_their_reason() {
        use tracing::Level;
        let cases = [
            (ApiError::Internal("x".into()), Some(Level::ERROR)),
            (
                ApiError::CloneIdentityRejuvenationFailed("x".into()),
                Some(Level::ERROR),
            ),
            (ApiError::Unavailable("x".into()), Some(Level::WARN)),
            (ApiError::NotFound("x".into()), None),
            (ApiError::Conflict("x".into()), None),
            (ApiError::BadRequest("x".into()), None),
            (ApiError::Timeout, None),
        ];
        for (error, expected) in cases {
            let label = format!("{error:?}");
            let status = error.into_response().status();
            assert_eq!(failure_log_level(status), expected, "{label}");
        }
    }

    #[tokio::test]
    async fn resize_rejection_identifies_the_terminal_operation() {
        let runtime = crate::agent::live_resize::RuntimeIdentity {
            pid: 123,
            start_time: 456,
            boot_id: Some("boot-1".into()),
        };
        let response = ApiError::ResizeRejected {
            operation_id: "resize-1".into(),
            runtime: runtime.clone(),
            message: "memory must be aligned".into(),
        }
        .into_response();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let bytes = axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["code"], "RESIZE_REJECTED");
        assert_eq!(body["operationId"], "resize-1");
        assert_eq!(body["runtime"], serde_json::to_value(runtime).unwrap());
    }

    #[tokio::test]
    async fn clone_rejuvenation_failure_has_a_stable_public_code() {
        let response = ApiError::CloneIdentityRejuvenationFailed("identity reset failed".into())
            .into_response();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(body["code"], "CLONE_IDENTITY_REJUVENATION_FAILED");
        assert_eq!(body["error"], "identity reset failed");
    }

    #[test]
    fn test_agent_error_kind_mapping() {
        // NotFound kind -> NotFound
        let err = crate::error::Error::agent_not_found("lookup", "container not found");
        assert!(matches!(ApiError::from(err), ApiError::NotFound(_)));

        // Conflict kind -> Conflict
        let err = crate::error::Error::agent_conflict("create", "already exists");
        assert!(matches!(ApiError::from(err), ApiError::Conflict(_)));

        // Default (Other) kind -> Internal
        let err = crate::error::Error::agent("connect", "connection refused");
        assert!(matches!(ApiError::from(err), ApiError::Internal(_)));
    }
}
