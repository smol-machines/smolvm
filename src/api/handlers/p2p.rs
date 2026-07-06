//! Brokered peer-to-peer blob serving.
//!
//! `GET /p2p/blob/{digest}` streams a content-addressed layer blob straight from
//! this node's local blob cache to a sibling fleet node, so a `create` on
//! another node can pull a hot `.smolmachine` layer from a peer instead of the
//! registry. Read-only and content-addressed.
//!
//! ## Security
//!
//! This endpoint is mTLS-gated by the serve listener by construction (like
//! `/drain`, see the router comment): only a client whose cert chains to the
//! fleet node-CA can reach it. It is NOT tenant-scoped, so on a multi-tenant
//! fleet it is a cross-tenant read oracle for private blobs, bounded only by
//! mTLS + sha256 digest entropy. See [`smolvm_registry::peer`] for the full
//! trust model and the scoped-token requirement before enabling P2P on a
//! multi-tenant fleet that hosts private artifacts.

use axum::{
    body::Body,
    extract::Path,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use smolvm_registry::BlobCache;
use tokio_util::io::ReaderStream;

use crate::api::error::ApiError;

/// Serve a cached layer blob by digest to a peer node.
///
/// Opens the default blob cache and delegates to [`serve_blob_from`], which does
/// the digest validation, lookup, and streaming.
pub async fn serve_blob(Path(digest): Path<String>) -> Result<Response, ApiError> {
    let cache = BlobCache::open_default()
        .map_err(|e| ApiError::internal(format!("open blob cache: {e}")))?;
    serve_blob_from(&cache, &digest).await
}

/// Validate the digest, look it up in `cache`, and stream it.
///
/// The digest is validated first — the path segment is attacker-influenced and
/// is used to build a cache filesystem path — then looked up: a miss is `404`, a
/// hit streams the file from disk. The body is streamed (never buffered) because
/// a `.smolmachine` layer can be hundreds of MB / multiple GB.
async fn serve_blob_from(cache: &BlobCache, digest: &str) -> Result<Response, ApiError> {
    // Reject a malformed / path-traversing digest before it is used to build any
    // cache path (mirrors the check `pull` runs before touching the cache).
    smolvm_registry::validate_digest(digest)
        .map_err(|e| ApiError::BadRequest(format!("invalid blob digest: {e}")))?;

    let Some(path) = cache.get(digest) else {
        return Err(ApiError::NotFound(format!("blob not cached: {digest}")));
    };

    let file = tokio::fs::File::open(&path)
        .await
        .map_err(|e| ApiError::internal(format!("open cached blob: {e}")))?;
    let len = file
        .metadata()
        .await
        .map(|m| m.len())
        .map_err(|e| ApiError::internal(format!("stat cached blob: {e}")))?;

    let body = Body::from_stream(ReaderStream::new(file));
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (header::CONTENT_LENGTH, len.to_string()),
        ],
        body,
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use sha2::{Digest, Sha256};

    fn temp_cache() -> (tempfile::TempDir, BlobCache) {
        let tmp = tempfile::tempdir().unwrap();
        let cache = BlobCache::open(tmp.path().to_path_buf(), 1024 * 1024).unwrap();
        (tmp, cache)
    }

    fn digest_of(data: &[u8]) -> String {
        format!("sha256:{}", hex::encode(Sha256::digest(data)))
    }

    #[tokio::test]
    async fn present_blob_streams_with_content_length() {
        let data = b"p2p-served-blob-bytes".to_vec();
        let digest = digest_of(&data);
        let (_tmp, cache) = temp_cache();
        cache.put(&digest, &data).unwrap();

        let resp = serve_blob_from(&cache, &digest)
            .await
            .expect("present blob must serve 200")
            .into_response();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok()),
            Some(data.len().to_string().as_str())
        );
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body.as_ref(), data.as_slice());
    }

    #[tokio::test]
    async fn absent_blob_is_404() {
        let (_tmp, cache) = temp_cache();
        let digest = digest_of(b"never-cached");
        let err = serve_blob_from(&cache, &digest)
            .await
            .expect_err("absent blob must be an error");
        assert!(matches!(err, ApiError::NotFound(_)));
    }

    #[tokio::test]
    async fn malformed_digest_is_400() {
        let (_tmp, cache) = temp_cache();

        // Malformed digest is rejected before any cache access.
        let err = serve_blob_from(&cache, "sha256:not-a-real-digest")
            .await
            .expect_err("malformed digest must be rejected");
        assert!(matches!(err, ApiError::BadRequest(_)));

        // A path-traversal attempt is likewise a 400, never a filesystem read.
        let err = serve_blob_from(&cache, "../../etc/passwd")
            .await
            .expect_err("path-traversal digest must be rejected");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }
}
