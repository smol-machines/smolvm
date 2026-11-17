//! Legacy Docker build endpoints are not the native BuildKit protocol.
//! The engine registers a socket-activated remote Buildx builder instead;
//! its guest-local cache is owned by the persistent builder machine.

use axum::response::Response;

use super::util::{ApiError, ApiResult};

/// What every build endpoint answers.
pub(crate) const BUILD_UNSUPPORTED: &str = "configure the native builder with `smolvm engine`, \
then build with `docker buildx build --builder smol-builder`";

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

/// Legacy prune endpoint; native cache is pruned through `docker buildx prune`.
pub(crate) async fn build_prune() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({"CachesDeleted": [], "SpaceReclaimed": 0}))
}

/// `POST /session` and `POST /grpc`, BuildKit's entry points.
pub(crate) async fn session() -> ApiResult<Response> {
    Err(ApiError::not_implemented(BUILD_UNSUPPORTED))
}
