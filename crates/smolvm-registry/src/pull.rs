//! Pull a `.smolmachine` artifact from an OCI registry.
//!
//! The pull flow:
//! 1. Fetch the OCI manifest by tag or digest
//! 2. Parse the manifest to find the layer blob digest
//! 3. Check the local cache for the blob
//! 4. If not cached, try any brokered P2P peers, then stream from the registry,
//!    computing the digest while writing
//! 5. Verify the digest and adopt into cache

use crate::cache::BlobCache;
use crate::client::RegistryClient;
use crate::{OciManifest, RegistryError, Result, LAYER_MEDIA_TYPE};
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;

/// Result of a successful pull.
#[derive(Debug)]
pub struct PullResult {
    /// Path to the downloaded `.smolmachine` file.
    pub path: PathBuf,
    /// Digest of the layer blob.
    pub digest: String,
    /// Size of the layer blob in bytes.
    pub size: u64,
    /// Whether the blob was served from local cache.
    pub cached: bool,
}

/// Pull a `.smolmachine` artifact from the registry.
///
/// `repo` is the OCI repository path (e.g., "python-dev").
/// `reference` is the tag or digest (e.g., "latest" or "sha256:abc...").
/// If `output` is Some, the blob is copied there. Otherwise it's only cached.
///
/// `blob_peers` are optional brokered P2P peers (node base URLs, e.g.
/// `https://<addr>:<port>`) supplied by the control plane. On a cache miss the
/// layer blob is fetched from a peer's `GET /p2p/blob/<digest>` (over node→node
/// mTLS) before the registry. When `blob_peers` is empty the peer block is
/// skipped entirely and the registry path is byte-for-byte what it was before.
pub async fn pull(
    client: &RegistryClient,
    repo: &str,
    reference: &str,
    output: Option<&Path>,
    cache: &BlobCache,
    blob_peers: &[String],
) -> Result<PullResult> {
    // 1. Fetch the manifest, resolving a multi-platform index to this machine's
    //    host-platform entry (Docker-style fan-out). Shared with `inspect`.
    tracing::info!(repo = %repo, reference = %reference, "fetching manifest...");
    let manifest_bytes = client.get_manifest_resolved(repo, reference).await?;

    let manifest: OciManifest = serde_json::from_slice(&manifest_bytes)?;

    // 2. Find the smolmachine layer.
    let layer = manifest
        .layers
        .iter()
        .find(|l| l.media_type == LAYER_MEDIA_TYPE)
        .ok_or_else(|| {
            RegistryError::InvalidManifest(format!(
                "no layer with media type {} in manifest",
                LAYER_MEDIA_TYPE
            ))
        })?;

    let digest = &layer.digest;
    let size = layer.size;

    // Validate the digest format BEFORE it is used to build any cache filesystem
    // path. `BlobCache::blob_path` only does `digest.replace(':', "_")`, leaving
    // `/` and `..` intact, so an attacker-controlled manifest digest could
    // otherwise create a `.partial` file or touch atime outside the cache dir.
    crate::client::validate_digest(digest)?;

    // 3. Check cache.
    if let Some(cached_path) = cache.get(digest) {
        tracing::info!(digest = %digest, "blob found in cache");

        if let Some(out) = output {
            tokio::fs::copy(&cached_path, out).await?;
        }

        return Ok(PullResult {
            path: output.map(PathBuf::from).unwrap_or(cached_path),
            digest: digest.clone(),
            size,
            cached: true,
        });
    }

    // 4. Brokered P2P: try sibling nodes before hitting the registry. Inert when
    //    `blob_peers` is empty — the registry path below is then reached
    //    byte-for-byte as before. Peers arrive only from the control plane, and
    //    a node with no serve-TLS identity has no peer client, so this is also a
    //    no-op there.
    if !blob_peers.is_empty() {
        if let Some(peer_client) = crate::peer::peer_client() {
            if let Some(result) =
                crate::peer::fetch_blob_from_peers(peer_client, blob_peers, digest, output, cache)
                    .await
            {
                return Ok(result);
            }
            tracing::info!(digest = %digest, "no peer served the blob; falling back to registry");
        }
    }

    // 5. Stream blob from the registry to disk while computing + verifying the
    //    digest, then adopt into cache.
    tracing::info!(digest = %digest, size, "downloading blob...");

    let stream = client.pull_blob_stream(repo, digest).await?;
    let result = stream_verify_adopt(stream, digest, output, cache).await?;

    tracing::info!(digest = %digest, size = result.size, "pull complete");

    Ok(result)
}

/// Stream `stream` into the cache's `.partial` file for `digest`, hashing while
/// writing, verify the digest, adopt into the cache, and copy to `output` if
/// requested.
///
/// Shared by the registry pull path and the P2P peer-fetch path so a blob
/// obtained either way goes through identical digest verification and the same
/// LRU/size accounting ([`BlobCache::adopt`]). On a digest mismatch the
/// `.partial` is removed before returning the error. A mid-stream transport
/// error propagates as-is (leaving the `.partial`, which the next attempt
/// truncates via `File::create`), matching the original registry pull behavior.
pub(crate) async fn stream_verify_adopt<S>(
    stream: S,
    digest: &str,
    output: Option<&Path>,
    cache: &BlobCache,
) -> Result<PullResult>
where
    S: futures_util::Stream<Item = reqwest::Result<bytes::Bytes>>,
{
    let partial_path = cache.blob_path_for(digest).with_extension("partial");
    let mut file = tokio::fs::File::create(&partial_path).await?;
    let mut hasher = Sha256::new();
    let mut total_bytes: u64 = 0;

    let mut stream = std::pin::pin!(stream);
    while let Some(chunk_result) = stream.next().await {
        let chunk: bytes::Bytes = chunk_result.map_err(RegistryError::Http)?;
        hasher.update(&chunk);
        file.write_all(&chunk).await?;
        total_bytes += chunk.len() as u64;
    }
    file.flush().await?;
    drop(file);

    // Verify digest.
    let actual = format!("sha256:{}", hex::encode(hasher.finalize()));
    if actual != *digest {
        if let Err(e) = tokio::fs::remove_file(&partial_path).await {
            tracing::warn!(
                error = %e,
                path = %partial_path.display(),
                "failed to clean up partial blob after digest mismatch"
            );
        }
        return Err(RegistryError::DigestMismatch {
            expected: digest.to_string(),
            actual,
        });
    }

    // Adopt into cache (handles eviction + atomic rename).
    let cached_path = cache.adopt(digest, total_bytes)?;

    // Copy to output if requested.
    let result_path = if let Some(out) = output {
        tokio::fs::copy(&cached_path, out).await?;
        PathBuf::from(out)
    } else {
        cached_path
    };

    Ok(PullResult {
        path: result_path,
        digest: digest.to_string(),
        size: total_bytes,
        cached: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CONFIG_MEDIA_TYPE, MANIFEST_MEDIA_TYPE};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// With empty `blob_peers`, `pull` takes the registry path exactly as before:
    /// fetch the manifest, then stream the layer blob from `/v2/.../blobs/...`,
    /// verify, and adopt. No peer client is built or consulted.
    #[tokio::test]
    async fn empty_blob_peers_uses_registry_path() {
        use sha2::{Digest, Sha256};

        let data = b"registry-path-layer-bytes".to_vec();
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&data)));
        let config_digest =
            "sha256:1111111111111111111111111111111111111111111111111111111111111111";

        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": MANIFEST_MEDIA_TYPE,
            "config": { "mediaType": CONFIG_MEDIA_TYPE, "digest": config_digest, "size": 2 },
            "layers": [ { "mediaType": LAYER_MEDIA_TYPE, "digest": digest, "size": data.len() } ],
        });

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/myrepo/manifests/latest"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(serde_json::to_vec(&manifest).unwrap(), MANIFEST_MEDIA_TYPE),
            )
            .mount(&server)
            .await;
        // The layer blob endpoint must be hit exactly once on the registry path.
        Mock::given(method("GET"))
            .and(path(format!("/v2/myrepo/blobs/{digest}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(data.clone()))
            .expect(1)
            .mount(&server)
            .await;

        let tmp = tempfile::tempdir().unwrap();
        let cache = BlobCache::open(tmp.path().to_path_buf(), 1024 * 1024).unwrap();
        let client = RegistryClient::new(server.uri());

        let result = pull(&client, "myrepo", "latest", None, &cache, &[])
            .await
            .expect("registry pull must succeed");

        assert_eq!(result.digest, digest);
        assert_eq!(result.size, data.len() as u64);
        assert!(!result.cached);
        assert!(
            cache.get(&digest).is_some(),
            "blob must be adopted into cache"
        );
        // MockServer drop asserts the blob endpoint's expect(1) was satisfied.
    }
}
