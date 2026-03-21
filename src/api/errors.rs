//! API error types with HTTP status mapping.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use std::fmt::Display;

/// API error type with HTTP status code mapping.
#[derive(Debug)]
pub enum ApiError {
    /// Resource not found (404).
    NotFound(String),
    /// Conflict - resource already exists or invalid state (409).
    Conflict(String),
    /// Bad request - invalid input (400).
    BadRequest(String),
    /// Request timeout (408).
    Timeout,
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
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, "NOT_FOUND", msg),
            ApiError::Conflict(msg) => (StatusCode::CONFLICT, "CONFLICT", msg),
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, "BAD_REQUEST", msg),
            ApiError::Timeout => (
                StatusCode::REQUEST_TIMEOUT,
                "TIMEOUT",
                "request timed out".to_string(),
            ),
            ApiError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", msg),
        };

        let body = Json(ErrorResponse {
            error: message,
            code,
        });

        (status, body).into_response()
    }
}

impl From<crate::error::Error> for ApiError {
    fn from(err: crate::error::Error) -> Self {
        match &err {
            crate::error::Error::VmNotFound { name } => {
                ApiError::NotFound(format!("sandbox not found: {}", name))
            }
            crate::error::Error::InvalidState { expected, actual } => ApiError::Conflict(format!(
                "invalid state: expected {}, got {}",
                expected, actual
            )),
            // Handle structured Agent errors using kind for HTTP status mapping
            crate::error::Error::Agent { reason, kind, .. } => match kind {
                crate::error::AgentErrorKind::NotFound => ApiError::NotFound(reason.clone()),
                crate::error::AgentErrorKind::Conflict => ApiError::Conflict(reason.clone()),
                crate::error::AgentErrorKind::Other => ApiError::Internal(reason.clone()),
            },
            _ => ApiError::Internal(err.to_string()),
        }
    }
}

/// Classify errors from `ensure_sandbox_running` into proper HTTP status codes.
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
    fn test_api_error_status_codes() {
        let cases = [
            (ApiError::NotFound("x".into()), StatusCode::NOT_FOUND),
            (ApiError::Conflict("x".into()), StatusCode::CONFLICT),
            (ApiError::BadRequest("x".into()), StatusCode::BAD_REQUEST),
            (ApiError::Timeout, StatusCode::REQUEST_TIMEOUT),
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
