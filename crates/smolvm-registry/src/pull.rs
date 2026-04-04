//! Pull a `.smolmachine` artifact from an OCI registry.
//!
//! The pull flow:
//! 1. Fetch the OCI manifest by tag or digest
//! 2. Parse the manifest to find the layer blob digest
//! 3. Check the local cache for the blob
//! 4. If not cached, stream the blob to disk while computing the digest
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
pub async fn pull(
    client: &RegistryClient,
    repo: &str,
    reference: &str,
    output: Option<&Path>,
    cache: &BlobCache,
) -> Result<PullResult> {
    // 1. Fetch manifest.
    tracing::info!(repo = %repo, reference = %reference, "fetching manifest...");
    let manifest_bytes = client.get_manifest(repo, reference).await?;
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

    // 4. Stream blob to disk while computing digest.
    tracing::info!(digest = %digest, size, "downloading blob...");

    let partial_path = cache.blob_path_for(digest).with_extension("partial");
    let mut file = tokio::fs::File::create(&partial_path).await?;
    let mut hasher = Sha256::new();
    let mut total_bytes: u64 = 0;

    let stream = client.pull_blob_stream(repo, digest).await?;
    let mut stream = std::pin::pin!(stream);

    while let Some(chunk_result) = stream.next().await {
        let chunk: bytes::Bytes = chunk_result.map_err(RegistryError::Http)?;
        hasher.update(&chunk);
        file.write_all(&chunk).await?;
        total_bytes += chunk.len() as u64;
    }
    file.flush().await?;
    drop(file);

    // 5. Verify digest.
    let actual = format!("sha256:{}", hex::encode(hasher.finalize()));
    if actual != *digest {
        let _ = tokio::fs::remove_file(&partial_path).await;
        return Err(RegistryError::DigestMismatch {
            expected: digest.to_string(),
            actual,
        });
    }

    // 6. Adopt into cache.
    let cached_path = cache.adopt(digest, total_bytes)?;

    // 7. Copy to output if requested.
    let result_path = if let Some(out) = output {
        tokio::fs::copy(&cached_path, out).await?;
        PathBuf::from(out)
    } else {
        cached_path
    };

    tracing::info!(digest = %digest, size = total_bytes, "pull complete");

    Ok(PullResult {
        path: result_path,
        digest: digest.clone(),
        size: total_bytes,
        cached: false,
    })
}
