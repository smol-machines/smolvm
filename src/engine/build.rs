//! Image builds and loads, which the engine does not do yet.
//!
//! The engine runs images; it does not build them. Both build protocols a
//! client may use are answered with a clear error: the classic
//! `POST /build`, and BuildKit's, which the docker CLI (through buildx) and
//! Compose reach over `POST /session` and `POST /grpc`.

use axum::response::Response;

use super::util::{ApiError, ApiResult};

/// What every build endpoint answers.
pub(crate) const BUILD_UNSUPPORTED: &str = "the smolvm engine does not build images yet: \
build the image elsewhere and push it to a registry the engine can pull from";

/// `POST /build`. The build context is read to its end first: answering
/// while the client is still sending it would cut the connection, and the
/// client would show a broken pipe instead of this answer.
pub(crate) async fn build(body: axum::body::Body) -> ApiResult<Response> {
    use futures_util::StreamExt as _;
    let mut stream = body.into_data_stream();
    while let Some(chunk) = stream.next().await {
        if chunk.is_err() {
            break;
        }
    }
    Err(ApiError::not_implemented(BUILD_UNSUPPORTED))
}

/// `POST /build/prune`: there is no build cache to prune.
pub(crate) async fn build_prune() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({"CachesDeleted": [], "SpaceReclaimed": 0}))
}

/// `POST /session` and `POST /grpc`, BuildKit's entry points.
pub(crate) async fn session() -> ApiResult<Response> {
    Err(ApiError::not_implemented(BUILD_UNSUPPORTED))
}

/// `POST /images/load`.
pub(crate) async fn image_load() -> ApiResult<Response> {
    Err(ApiError::not_implemented(
        "the smolvm engine does not load image archives yet: push the image to a registry and pull it",
    ))
}
