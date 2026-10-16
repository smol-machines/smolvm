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
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
    pull_with_progress(
        client,
        repo,
        reference,
        output,
        cache,
        blob_peers,
        &mut |_, _| {},
    )
    .await
}

/// [`pull`], reporting download progress.
///
/// `on_progress` is called with `(bytes_on_disk, total_bytes)` as the layer
/// streams in, on every chunk — callers throttle their own rendering. It is not
/// called for a cache hit or a peer fetch, neither of which downloads from the
/// registry, and `bytes_on_disk` starts from the resume point when a retry
/// picks up a partial file rather than restarting at zero.
pub async fn pull_with_progress(
    client: &RegistryClient,
    repo: &str,
    reference: &str,
    output: Option<&Path>,
    cache: &BlobCache,
    blob_peers: &[String],
    on_progress: &mut (dyn FnMut(u64, u64) + Send),
) -> Result<PullResult> {
    // 1. Fetch the manifest, resolving a multi-platform index to this machine's
    //    host-platform entry (Docker-style fan-out). Shared with `inspect`.
    //    A manifest already fetched from this repo by digest cannot have changed,
    //    so it is reused without a registry round trip.
    let manifest_bytes = match cache.manifest_by_digest(client.base_url(), repo, reference) {
        Some(bytes) => {
            tracing::info!(repo = %repo, reference = %reference, "manifest found in cache");
            bytes
        }
        None => {
            tracing::info!(repo = %repo, reference = %reference, "fetching manifest...");
            let bytes = client.get_manifest_resolved(repo, reference).await?;
            if let Err(error) =
                cache.put_manifest_by_digest(client.base_url(), repo, reference, &bytes)
            {
                tracing::debug!(%error, "could not cache manifest");
            }
            bytes
        }
    };

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

    sweep_abandoned_partials_now_and_then(cache);

    // 3. Wait out any other pull of this blob, then check the cache: a pull that
    //    queued behind one fetching the same blob finds it cached here instead of
    //    streaming into the partial file the first one is about to rename away.
    let _download_lock = lock_blob_download(cache, digest).await?;
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

    // 5. Stream blob from the registry to disk, resuming and retrying a broken
    //    transfer, then verify the digest and adopt into cache.
    tracing::info!(digest = %digest, size, "downloading blob...");

    let result = download_blob(
        client,
        repo,
        digest,
        size,
        output,
        cache,
        RangedPlan::default(),
        on_progress,
    )
    .await?;

    tracing::info!(digest = %digest, size = result.size, "pull complete");

    Ok(result)
}

/// How long an abandoned partial download is kept for a retry to resume.
const ABANDONED_PARTIAL_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// How often a process sweeps abandoned partial downloads.
const PARTIAL_SWEEP_INTERVAL_SECS: u64 = 60 * 60;

/// Sweep the cache's abandoned partial downloads, at most once per interval
/// per process, from the pull path, so a long-running serve keeps its cache
/// clean without a separate timer. A failed sweep only logs.
fn sweep_abandoned_partials_now_and_then(cache: &BlobCache) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static LAST_SWEEP: AtomicU64 = AtomicU64::new(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let last = LAST_SWEEP.load(Ordering::Relaxed);
    if now.saturating_sub(last) < PARTIAL_SWEEP_INTERVAL_SECS
        || LAST_SWEEP
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
    {
        return;
    }
    if let Err(error) = cache.sweep_abandoned_partials(ABANDONED_PARTIAL_AGE) {
        tracing::warn!(%error, "could not sweep abandoned partial downloads");
    }
}

/// How often a pull waiting on another pull of the same blob checks again.
const DOWNLOAD_LOCK_POLL: Duration = Duration::from_millis(50);

/// Take the exclusive download lock for `digest`, waiting while another pull
/// (in this process or another one sharing the cache) holds it. Polls
/// `try_lock` rather than blocking so a waiting pull never parks a runtime
/// thread. The lock is released when the returned file is dropped, including
/// when the owning pull fails or is cancelled.
async fn lock_blob_download(cache: &BlobCache, digest: &str) -> Result<std::fs::File> {
    let file = cache.download_lock_file(digest)?;
    let mut waited = false;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(std::fs::TryLockError::WouldBlock) => {
                if !waited {
                    tracing::info!(digest = %digest, "waiting for another pull of this blob");
                    waited = true;
                }
                tokio::time::sleep(DOWNLOAD_LOCK_POLL).await;
            }
            Err(std::fs::TryLockError::Error(e)) => return Err(e.into()),
        }
    }
}

/// How a large blob is fetched over parallel ranged requests. The registry
/// streams each blob from object storage, where one stream runs at tens of
/// MB/s, so a multi-GiB layer waited most of a minute on a single GET.
#[derive(Clone, Copy, Debug)]
struct RangedPlan {
    /// Blobs smaller than this use one stream: ranged parts only pay off for
    /// large blobs.
    parallel_min_bytes: u64,
    /// Bytes per ranged request. Each part is held in memory while it is
    /// written, so `part_bytes * streams` bounds the buffering.
    part_bytes: u64,
    /// Ranged requests in flight at once.
    streams: usize,
}

impl Default for RangedPlan {
    fn default() -> Self {
        Self {
            parallel_min_bytes: 256 << 20,
            part_bytes: 16 << 20,
            streams: 16,
        }
    }
}

/// Extension of the file a ranged download fills before it is verified. It
/// ends in `partial`, so eviction skips it and the abandoned-partial sweep
/// removes it under the blob's download lock.
pub(crate) const RANGED_PARTIAL_EXTENSION: &str = "ranged.partial";

/// Download `digest` into the cache: as parallel ranged parts when the blob is
/// large and the registry serves ranges, otherwise (or when the ranged fetch
/// fails) as one resumable stream.
#[allow(clippy::too_many_arguments)]
async fn download_blob(
    client: &RegistryClient,
    repo: &str,
    digest: &str,
    size: u64,
    output: Option<&Path>,
    cache: &BlobCache,
    plan: RangedPlan,
    on_progress: &mut (dyn FnMut(u64, u64) + Send),
) -> Result<PullResult> {
    let partial_path = cache.blob_path_for(digest).with_extension("partial");
    // Parts land at their offsets in a file sized up front, so until the last
    // part arrives it has holes: it gets its own name, renamed to the resumable
    // partial only once it is the blob, so a cancelled ranged pull never leaves
    // a full-length file a single-stream resume would take as complete.
    let ranged_path = cache
        .blob_path_for(digest)
        .with_extension(RANGED_PARTIAL_EXTENSION);
    // A partial left by an interrupted single-stream pull is resumed by that
    // path rather than thrown away here.
    let resumable = tokio::fs::try_exists(&partial_path).await.unwrap_or(false);
    if size >= plan.parallel_min_bytes && !resumable {
        let started = std::time::Instant::now();
        match fetch_ranged(client, repo, digest, size, &ranged_path, plan, on_progress).await {
            Ok(true) => {
                let actual = hash_file(&ranged_path).await?;
                if actual != *digest {
                    discard_partial(&ranged_path).await;
                    return Err(RegistryError::DigestMismatch {
                        expected: digest.to_string(),
                        actual,
                    });
                }
                tracing::info!(
                    digest = %digest,
                    size,
                    streams = plan.streams,
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "blob downloaded in ranged parts"
                );
                tokio::fs::rename(&ranged_path, &partial_path).await?;
                return finish_download(digest, size, output, cache).await;
            }
            Ok(false) => {
                tracing::info!(digest = %digest, "registry does not serve ranges; using one stream");
            }
            Err(error) => {
                tracing::warn!(digest = %digest, %error, "ranged blob download failed; retrying as one stream");
                discard_partial(&ranged_path).await;
            }
        }
    }
    download_with_resume(client, repo, digest, size, output, cache, on_progress).await
}

/// Fetch the blob into `partial_path` as `plan.part_bytes` parts over
/// `plan.streams` concurrent ranged requests, each written in place.
///
/// The first part goes alone: it settles the registry token every other part
/// reuses, and a registry answering it with the whole blob (200) means ranges
/// are unsupported, reported as `Ok(false)` before any file is created.
async fn fetch_ranged(
    client: &RegistryClient,
    repo: &str,
    digest: &str,
    size: u64,
    partial_path: &Path,
    plan: RangedPlan,
    on_progress: &mut (dyn FnMut(u64, u64) + Send),
) -> Result<bool> {
    let parts: Vec<(u64, u64)> = (0..size)
        .step_by(plan.part_bytes as usize)
        .map(|start| (start, (start + plan.part_bytes).min(size) - 1))
        .collect();
    let Some(first) = fetch_part(client, repo, digest, parts[0]).await? else {
        return Ok(false);
    };
    let file = tokio::fs::File::create(partial_path).await?;
    file.set_len(size).await?;
    drop(file);
    write_part(partial_path, 0, &first).await?;
    let mut done = first.len() as u64;
    on_progress(done, size);

    let mut rest = futures_util::stream::iter(parts[1..].iter().copied())
        .map(|(start, end)| async move {
            let bytes = fetch_part(client, repo, digest, (start, end))
                .await?
                .ok_or_else(|| RegistryError::ApiError {
                    status: 200,
                    body: "registry stopped serving ranges mid-download".into(),
                })?;
            write_part(partial_path, start, &bytes).await?;
            Ok::<u64, RegistryError>(bytes.len() as u64)
        })
        .buffer_unordered(plan.streams);
    while let Some(written) = rest.next().await {
        done += written?;
        on_progress(done, size);
    }
    Ok(true)
}

/// One ranged part, retried with backoff on the faults a resume would retry.
async fn fetch_part(
    client: &RegistryClient,
    repo: &str,
    digest: &str,
    (start, end): (u64, u64),
) -> Result<Option<bytes::Bytes>> {
    let mut attempt = 1;
    loop {
        match client.pull_blob_range(repo, digest, start, end).await {
            Err(e) if attempt < MAX_ATTEMPTS && is_retryable(&e) => {
                tokio::time::sleep(RETRY_BACKOFF * 2u32.pow(attempt - 1)).await;
                attempt += 1;
            }
            other => return other,
        }
    }
}

/// Write `bytes` into `path` at `offset`.
async fn write_part(path: &Path, offset: u64, bytes: &[u8]) -> Result<()> {
    use tokio::io::AsyncSeekExt;
    let mut file = tokio::fs::OpenOptions::new().write(true).open(path).await?;
    file.seek(std::io::SeekFrom::Start(offset)).await?;
    file.write_all(bytes).await?;
    file.flush().await?;
    Ok(())
}

/// Attempts allowed for one blob (first try plus retries).
const MAX_ATTEMPTS: u32 = 5;

/// Delay before the first retry; doubles each attempt.
const RETRY_BACKOFF: Duration = Duration::from_millis(500);

/// Download `digest` into the cache, resuming a partial file across attempts.
///
/// Each attempt appends to `<digest>.partial` from wherever the last one stopped,
/// so a 90 MiB layer that breaks at 80 MiB resumes at 80 MiB instead of starting
/// over — the difference between converging and never finishing when a registry
/// drops long transfers. Retries are bounded and backed off, so a genuinely
/// broken blob fails in seconds with a real error instead of hammering the
/// registry forever (the retry storm that hid the original fault).
///
/// The digest is verified from the finished file rather than hashed incrementally
/// while streaming: resumed attempts would otherwise need the hasher state from a
/// previous attempt. Re-reading is cheap next to the transfer, and it verifies
/// exactly the bytes that landed on disk.
async fn download_with_resume(
    client: &RegistryClient,
    repo: &str,
    digest: &str,
    expected_size: u64,
    output: Option<&Path>,
    cache: &BlobCache,
    on_progress: &mut (dyn FnMut(u64, u64) + Send),
) -> Result<PullResult> {
    let partial_path = cache.blob_path_for(digest).with_extension("partial");

    for attempt in 1..=MAX_ATTEMPTS {
        // Resume from whatever a previous attempt left behind. A stale partial
        // from an earlier pull is fine: the digest check at the end rejects it,
        // and a mismatch clears it so the next pull starts clean.
        let mut have = tokio::fs::metadata(&partial_path)
            .await
            .map(|m| m.len())
            .unwrap_or(0);

        // A pull cancelled after its last byte landed but before it verified and
        // adopted the blob (its machine deleted mid-create) leaves a partial that
        // already holds the whole blob. Asking the registry for bytes past the
        // end gets a 416 on every later pull, so finish from disk instead: adopt
        // it when it is the blob, and start over when it is not.
        if expected_size > 0 && have >= expected_size {
            if have == expected_size && hash_file(&partial_path).await? == *digest {
                tracing::info!(digest = %digest, "adopting a complete partial left by an earlier pull");
                return finish_download(digest, have, output, cache).await;
            }
            discard_partial(&partial_path).await;
            have = 0;
        }

        match fetch_into_partial(
            client,
            repo,
            digest,
            have,
            expected_size,
            &partial_path,
            on_progress,
        )
        .await
        {
            Ok(written) => {
                let actual = hash_file(&partial_path).await?;
                if actual != *digest {
                    // Corrupt or mismatched bytes: remove them so a retry cannot
                    // resume onto a poisoned prefix, and fail — retrying the same
                    // content would only reproduce the mismatch.
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

                return finish_download(digest, written, output, cache).await;
            }
            // The registry refused the resume offset, so the partial does not
            // line up with the blob it serves: drop it and fetch from the start.
            Err(RegistryError::ApiError { status: 416, .. })
                if have > 0 && attempt < MAX_ATTEMPTS =>
            {
                tracing::warn!(
                    digest = %digest,
                    resumed_from = have,
                    "registry refused the resume offset; restarting the blob download"
                );
                discard_partial(&partial_path).await;
            }
            Err(e) if attempt < MAX_ATTEMPTS && is_retryable(&e) => {
                let backoff = RETRY_BACKOFF * 2u32.pow(attempt - 1);
                // Report what is actually on disk, not `have`: that was read
                // before the attempt, so a transfer that broke after gigabytes
                // logged `have_bytes=0` and read as "downloaded nothing" when
                // the next attempt in fact resumes from near the end.
                let on_disk = tokio::fs::metadata(&partial_path)
                    .await
                    .map(|m| m.len())
                    .unwrap_or(have);
                tracing::warn!(
                    digest = %digest,
                    attempt,
                    max_attempts = MAX_ATTEMPTS,
                    bytes_on_disk = on_disk,
                    resumed_from = have,
                    total_bytes = expected_size,
                    backoff_ms = backoff.as_millis(),
                    error = %e,
                    "blob download interrupted; resuming after backoff"
                );
                tokio::time::sleep(backoff).await;
            }
            Err(e) => return Err(e),
        }
    }

    unreachable!("loop returns on the final attempt")
}

/// Adopt a verified download into the cache and copy it to `output` if asked.
async fn finish_download(
    digest: &str,
    size: u64,
    output: Option<&Path>,
    cache: &BlobCache,
) -> Result<PullResult> {
    let cached_path = cache.adopt(digest, size)?;
    let path = if let Some(out) = output {
        tokio::fs::copy(&cached_path, out).await?;
        PathBuf::from(out)
    } else {
        cached_path
    };
    Ok(PullResult {
        path,
        digest: digest.to_string(),
        size,
        cached: false,
    })
}

/// Remove a partial download so the next attempt starts from zero.
async fn discard_partial(partial_path: &Path) {
    if let Err(e) = tokio::fs::remove_file(partial_path).await {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(error = %e, path = %partial_path.display(), "failed to remove partial blob");
        }
    }
}

/// One download attempt: append the blob to `partial_path` starting at `have`.
///
/// Returns the total bytes on disk when the body ends.
async fn fetch_into_partial(
    client: &RegistryClient,
    repo: &str,
    digest: &str,
    have: u64,
    expected_size: u64,
    partial_path: &Path,
    on_progress: &mut (dyn FnMut(u64, u64) + Send),
) -> Result<u64> {
    let (stream, resumed_at) = client.pull_blob_stream_from(repo, digest, have).await?;

    // `resumed_at == 0` with bytes already on disk means the registry ignored the
    // Range header and is resending the whole blob, so the partial must be
    // truncated — appending would produce a file with a duplicated prefix.
    let mut file = if resumed_at > 0 {
        tokio::fs::OpenOptions::new()
            .append(true)
            .open(partial_path)
            .await?
    } else {
        tokio::fs::File::create(partial_path).await?
    };

    let mut written = resumed_at;
    let mut stream = std::pin::pin!(stream);
    while let Some(chunk_result) = stream.next().await {
        let chunk: bytes::Bytes = chunk_result.map_err(RegistryError::Http)?;
        file.write_all(&chunk).await?;
        written += chunk.len() as u64;
        on_progress(written, expected_size);
    }
    file.flush().await?;
    drop(file);

    // A body that ends early is a truncated transfer, not a complete download.
    // Without this the short file would reach the digest check, mismatch, and be
    // deleted — throwing away bytes a resume could have kept.
    if expected_size > 0 && written < expected_size {
        return Err(RegistryError::DownloadStalled {
            digest: digest.to_string(),
            received: written,
            total: expected_size,
        });
    }

    Ok(written)
}

/// SHA-256 of a file on disk, read in chunks so a large layer is never buffered.
async fn hash_file(path: &Path) -> Result<String> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 128 * 1024];
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

/// Whether a failed attempt is worth resuming.
///
/// Transport faults and 5xx are transient — exactly the mid-transfer breakage
/// resume exists for. A missing blob, an auth failure, or a digest mismatch are
/// terminal: retrying re-fetches the same wrong answer and only delays the error
/// the caller needs to see.
fn is_retryable(err: &RegistryError) -> bool {
    match err {
        RegistryError::Http(e) => {
            e.is_timeout() || e.is_connect() || e.is_request() || e.is_body() || e.is_decode()
        }
        RegistryError::DownloadStalled { .. } => true,
        RegistryError::Io(_) => false,
        RegistryError::ApiError { status, .. } => *status >= 500,
        _ => false,
    }
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

    /// A second pull of the same repo by digest is served from the cache without
    /// asking the registry for the manifest again; a tag is always re-fetched, and
    /// the same digest under another repo still goes to the registry.
    #[tokio::test]
    async fn a_digest_pull_reuses_its_manifest_and_a_tag_pull_does_not() {
        use sha2::{Digest, Sha256};

        let data = b"digest-pinned-layer".to_vec();
        let layer = format!("sha256:{}", hex::encode(Sha256::digest(&data)));
        let manifest = serde_json::to_vec(&manifest_for(&layer, data.len())).unwrap();
        let pinned = format!("sha256:{}", hex::encode(Sha256::digest(&manifest)));

        let server = MockServer::start().await;
        for reference in [pinned.as_str(), "v1"] {
            Mock::given(method("GET"))
                .and(path(format!("/v2/myrepo/manifests/{reference}")))
                .respond_with(
                    ResponseTemplate::new(200).set_body_raw(manifest.clone(), MANIFEST_MEDIA_TYPE),
                )
                .expect(if reference == "v1" { 2 } else { 1 })
                .mount(&server)
                .await;
        }
        Mock::given(method("GET"))
            .and(path(format!("/v2/other/manifests/{pinned}")))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(manifest.clone(), MANIFEST_MEDIA_TYPE),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v2/myrepo/blobs/{layer}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(data.clone()))
            .expect(1)
            .mount(&server)
            .await;

        let tmp = tempfile::tempdir().unwrap();
        let cache = BlobCache::open(tmp.path().to_path_buf(), 1024 * 1024).unwrap();
        let client = RegistryClient::new(server.uri());

        for _ in 0..3 {
            let result = pull(&client, "myrepo", &pinned, None, &cache, &[])
                .await
                .unwrap();
            assert_eq!(result.digest, layer);
        }
        for _ in 0..2 {
            pull(&client, "myrepo", "v1", None, &cache, &[])
                .await
                .unwrap();
        }
        let other = pull(&client, "other", &pinned, None, &cache, &[])
            .await
            .unwrap();
        assert!(other.cached, "the layer blob itself is shared by digest");
        // MockServer drop asserts each manifest endpoint's expected hit count.
    }

    /// Build a manifest whose single layer declares `digest`/`size`.
    fn manifest_for(digest: &str, size: usize) -> serde_json::Value {
        serde_json::json!({
            "schemaVersion": 2,
            "mediaType": MANIFEST_MEDIA_TYPE,
            "config": {
                "mediaType": CONFIG_MEDIA_TYPE,
                "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "size": 2
            },
            "layers": [ { "mediaType": LAYER_MEDIA_TYPE, "digest": digest, "size": size } ],
        })
    }

    /// Two creates of one artifact at once on a node that has not cached it yet
    /// both pull its blob. They used to stream into the same `.partial` file, so
    /// whichever finished second failed with ENOENT once the first renamed it
    /// into the cache. Now the second waits for the first and is served from
    /// the cache, and the registry is asked for the blob once.
    #[tokio::test]
    async fn concurrent_pulls_of_one_blob_both_succeed_and_fetch_it_once() {
        use sha2::{Digest, Sha256};

        let data = vec![7u8; 256 * 1024];
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&data)));
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/myrepo/manifests/latest"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                serde_json::to_vec(&manifest_for(&digest, data.len())).unwrap(),
                MANIFEST_MEDIA_TYPE,
            ))
            .mount(&server)
            .await;
        // Slow enough that both pulls are past the cache check while the first
        // is still downloading.
        Mock::given(method("GET"))
            .and(path(format!("/v2/myrepo/blobs/{digest}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(data.clone())
                    .set_delay(Duration::from_millis(300)),
            )
            .expect(1)
            .mount(&server)
            .await;

        let tmp = tempfile::tempdir().unwrap();
        let cache = BlobCache::open(tmp.path().to_path_buf(), 16 * 1024 * 1024).unwrap();
        let client = RegistryClient::new(server.uri());

        let (a, b) = tokio::join!(
            pull(&client, "myrepo", "latest", None, &cache, &[]),
            pull(&client, "myrepo", "latest", None, &cache, &[]),
        );
        let (a, b) = (a.expect("first pull"), b.expect("second pull"));
        assert_eq!(
            [a.cached, b.cached].iter().filter(|c| **c).count(),
            1,
            "exactly one pull downloads; the other is served from the cache"
        );
        assert_eq!(tokio::fs::read(&a.path).await.unwrap(), data);
        assert_eq!(a.path, b.path);
    }

    /// A download reports progress while it streams: every callback carries the
    /// running byte count and the layer's declared total, counts never go
    /// backwards, and the last one reaches the full size. Without this a
    /// multi-gigabyte pull prints one line and then looks hung for minutes.
    #[tokio::test]
    async fn pull_reports_download_progress() {
        use sha2::{Digest, Sha256};

        let data = vec![7u8; 64 * 1024];
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&data)));

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/myrepo/manifests/latest"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                serde_json::to_vec(&manifest_for(&digest, data.len())).unwrap(),
                MANIFEST_MEDIA_TYPE,
            ))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v2/myrepo/blobs/{digest}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(data.clone()))
            .mount(&server)
            .await;

        let tmp = tempfile::tempdir().unwrap();
        let cache = BlobCache::open(tmp.path().to_path_buf(), 1024 * 1024).unwrap();
        let client = RegistryClient::new(server.uri());

        let mut seen: Vec<(u64, u64)> = Vec::new();
        let result = pull_with_progress(
            &client,
            "myrepo",
            "latest",
            None,
            &cache,
            &[],
            &mut |done, total| seen.push((done, total)),
        )
        .await
        .expect("pull must succeed");

        assert!(!seen.is_empty(), "progress must be reported at least once");
        assert!(
            seen.iter().all(|&(_, total)| total == data.len() as u64),
            "every callback carries the layer size declared in the manifest"
        );
        assert!(
            seen.windows(2).all(|w| w[0].0 <= w[1].0),
            "byte counts must never go backwards"
        );
        assert_eq!(
            seen.last().unwrap().0,
            data.len() as u64,
            "the final callback reaches the full size"
        );
        assert_eq!(result.size, data.len() as u64);
    }

    /// The incident behaviour: a transfer that dies mid-blob must RESUME from the
    /// bytes already on disk, not restart at zero.
    ///
    /// The registry here truncates the first response, then serves the remainder
    /// only to a ranged request. A client that restarts would keep receiving the
    /// same truncated prefix forever; one that resumes completes on the second
    /// attempt.
    #[tokio::test]
    async fn broken_transfer_resumes_instead_of_restarting() {
        use sha2::{Digest, Sha256};
        use wiremock::matchers::header_exists;

        let data: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&data)));
        let split = 1500;

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/myrepo/manifests/latest"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                serde_json::to_vec(&manifest_for(&digest, data.len())).unwrap(),
                MANIFEST_MEDIA_TYPE,
            ))
            .mount(&server)
            .await;

        // Registered first so it wins for ranged requests: serve the tail as 206.
        Mock::given(method("GET"))
            .and(path(format!("/v2/myrepo/blobs/{digest}")))
            .and(header_exists("range"))
            .respond_with(ResponseTemplate::new(206).set_body_bytes(data[split..].to_vec()))
            .expect(1)
            .mount(&server)
            .await;
        // Un-ranged first attempt: hand back a truncated body.
        Mock::given(method("GET"))
            .and(path(format!("/v2/myrepo/blobs/{digest}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(data[..split].to_vec()))
            .expect(1)
            .mount(&server)
            .await;

        let tmp = tempfile::tempdir().unwrap();
        let cache = BlobCache::open(tmp.path().to_path_buf(), 1024 * 1024).unwrap();
        let client = RegistryClient::new(server.uri());

        let result = pull(&client, "myrepo", "latest", None, &cache, &[])
            .await
            .expect("a truncated transfer must be resumed and completed");

        assert_eq!(
            result.size,
            data.len() as u64,
            "full blob must land on disk"
        );
        assert_eq!(result.digest, digest);
        let cached = cache.get(&digest).expect("blob must be adopted into cache");
        assert_eq!(
            tokio::fs::read(&cached).await.unwrap(),
            data,
            "resumed file must be byte-identical, not a duplicated prefix"
        );
        // Each expect(1) asserts the resume happened exactly once: one truncated
        // attempt, one ranged continuation.
    }

    /// Serve `data` under `myrepo:latest`; the blob endpoint answers 416 to a
    /// ranged request and the whole blob otherwise, each `expect`ed as given.
    async fn registry_refusing_ranges(
        data: &[u8],
        digest: &str,
        ranged: u64,
        whole: u64,
    ) -> MockServer {
        use wiremock::matchers::header_exists;
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/myrepo/manifests/latest"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                serde_json::to_vec(&manifest_for(digest, data.len())).unwrap(),
                MANIFEST_MEDIA_TYPE,
            ))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v2/myrepo/blobs/{digest}")))
            .and(header_exists("range"))
            .respond_with(ResponseTemplate::new(416))
            .expect(ranged)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v2/myrepo/blobs/{digest}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(data.to_vec()))
            .expect(whole)
            .mount(&server)
            .await;
        server
    }

    fn test_blob() -> (Vec<u8>, String) {
        use sha2::{Digest, Sha256};
        let data: Vec<u8> = (0..4096u32).map(|i| (i % 249) as u8).collect();
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&data)));
        (data, digest)
    }

    /// The incident: a pull cancelled after its last byte landed left a complete
    /// `.partial`, and every later pull of that blob asked for bytes past the
    /// end and failed with the registry's 416. The next pull must adopt it.
    #[tokio::test]
    async fn a_complete_partial_left_by_a_cancelled_pull_is_adopted() {
        let (data, digest) = test_blob();
        let server = registry_refusing_ranges(&data, &digest, 0, 0).await;
        let tmp = tempfile::tempdir().unwrap();
        let cache = BlobCache::open(tmp.path().to_path_buf(), 1024 * 1024).unwrap();
        let partial = cache.blob_path_for(&digest).with_extension("partial");
        std::fs::write(&partial, &data).unwrap();

        let result = pull(&client_for(&server), "myrepo", "latest", None, &cache, &[])
            .await
            .expect("a complete partial must be adopted, not resumed past its end");
        assert_eq!(result.size, data.len() as u64);
        assert_eq!(
            tokio::fs::read(cache.get(&digest).unwrap()).await.unwrap(),
            data
        );
        assert!(!partial.exists(), "the partial is renamed into the cache");
    }

    /// A full-size partial holding the wrong bytes is thrown away and the blob
    /// downloaded again from the start, rather than failing the pull.
    #[tokio::test]
    async fn a_full_size_partial_with_wrong_bytes_is_downloaded_again() {
        let (data, digest) = test_blob();
        let server = registry_refusing_ranges(&data, &digest, 0, 1).await;
        let tmp = tempfile::tempdir().unwrap();
        let cache = BlobCache::open(tmp.path().to_path_buf(), 1024 * 1024).unwrap();
        let partial = cache.blob_path_for(&digest).with_extension("partial");
        std::fs::write(&partial, vec![0u8; data.len()]).unwrap();

        let result = pull(&client_for(&server), "myrepo", "latest", None, &cache, &[])
            .await
            .expect("a wrong full-size partial must be replaced");
        assert_eq!(tokio::fs::read(&result.path).await.unwrap(), data);
    }

    /// A registry that refuses the resume offset gets asked for the whole blob
    /// on the next attempt instead of failing the pull.
    #[tokio::test]
    async fn a_refused_resume_restarts_the_download() {
        let (data, digest) = test_blob();
        let server = registry_refusing_ranges(&data, &digest, 1, 1).await;
        let tmp = tempfile::tempdir().unwrap();
        let cache = BlobCache::open(tmp.path().to_path_buf(), 1024 * 1024).unwrap();
        let partial = cache.blob_path_for(&digest).with_extension("partial");
        std::fs::write(&partial, &data[..100]).unwrap();

        let result = pull(&client_for(&server), "myrepo", "latest", None, &cache, &[])
            .await
            .expect("a 416 on resume must restart from zero");
        assert_eq!(tokio::fs::read(&result.path).await.unwrap(), data);
    }

    fn client_for(server: &MockServer) -> RegistryClient {
        RegistryClient::new(server.uri())
    }

    /// A terminal failure must NOT be retried. A missing blob is the same answer
    /// however many times it is asked for, and retrying only delays the error.
    #[tokio::test]
    async fn missing_blob_fails_without_retrying() {
        let digest = "sha256:2222222222222222222222222222222222222222222222222222222222222222";

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/myrepo/manifests/latest"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                serde_json::to_vec(&manifest_for(digest, 64)).unwrap(),
                MANIFEST_MEDIA_TYPE,
            ))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v2/myrepo/blobs/{digest}")))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&server)
            .await;

        let tmp = tempfile::tempdir().unwrap();
        let cache = BlobCache::open(tmp.path().to_path_buf(), 1024 * 1024).unwrap();
        let client = RegistryClient::new(server.uri());

        let err = pull(&client, "myrepo", "latest", None, &cache, &[])
            .await
            .expect_err("a missing blob must fail");
        assert!(
            matches!(err, RegistryError::BlobNotFound(_)),
            "expected BlobNotFound, got {err:?}"
        );
        // expect(1) asserts the blob endpoint was hit once, not MAX_ATTEMPTS times.
    }

    /// A registry that serves `data` honoring `Range: bytes=a-b` with a 206,
    /// failing the first `fail_first` ranged requests with a 503.
    struct RangeServer {
        data: Vec<u8>,
        fail_first: usize,
        seen: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl wiremock::Respond for RangeServer {
        fn respond(&self, req: &wiremock::Request) -> ResponseTemplate {
            let n = self.seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n < self.fail_first {
                return ResponseTemplate::new(503);
            }
            let Some(range) = req.headers.get("range").and_then(|v| v.to_str().ok()) else {
                return ResponseTemplate::new(200).set_body_bytes(self.data.clone());
            };
            let (a, b) = range.trim_start_matches("bytes=").split_once('-').unwrap();
            let a: usize = a.parse().unwrap();
            let b: usize = b.parse().unwrap_or(self.data.len() - 1);
            ResponseTemplate::new(206)
                .insert_header(
                    "content-range",
                    format!("bytes {a}-{b}/{}", self.data.len()).as_str(),
                )
                .set_body_bytes(self.data[a..=b].to_vec())
        }
    }

    fn small_plan() -> RangedPlan {
        RangedPlan {
            parallel_min_bytes: 1024,
            part_bytes: 300,
            streams: 4,
        }
    }

    async fn ranged_download(
        responder: impl wiremock::Respond + 'static,
        data: &[u8],
        digest: &str,
    ) -> (Result<PullResult>, BlobCache, tempfile::TempDir) {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/v2/myrepo/blobs/{digest}")))
            .respond_with(responder)
            .mount(&server)
            .await;
        let tmp = tempfile::tempdir().unwrap();
        let cache = BlobCache::open(tmp.path().to_path_buf(), 1024 * 1024).unwrap();
        let client = RegistryClient::new(server.uri());
        let mut progress = 0;
        let result = download_blob(
            &client,
            "myrepo",
            digest,
            data.len() as u64,
            None,
            &cache,
            small_plan(),
            &mut |done, _| progress = done,
        )
        .await;
        if result.is_ok() {
            assert_eq!(
                progress,
                data.len() as u64,
                "progress must reach the blob size"
            );
        }
        (result, cache, tmp)
    }

    /// A large blob arrives as many ranged parts written in place, and the file
    /// is byte-identical to the blob, including the short last part.
    #[tokio::test]
    async fn a_large_blob_downloads_in_ranged_parts() {
        let (data, digest) = test_blob();
        let seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let responder = RangeServer {
            data: data.clone(),
            fail_first: 0,
            seen: seen.clone(),
        };
        let (result, cache, _tmp) = ranged_download(responder, &data, &digest).await;
        result.expect("ranged download must succeed");
        let parts = data.len().div_ceil(300);
        assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), parts);
        let cached = cache.get(&digest).expect("blob must be adopted into cache");
        assert_eq!(tokio::fs::read(&cached).await.unwrap(), data);
    }

    /// A ranged pull cancelled midway leaves a full-length file with holes. It
    /// must not be taken for a resumable partial, and the next pull downloads
    /// the blob in parts again over it.
    #[tokio::test]
    async fn a_cancelled_ranged_pull_does_not_poison_the_next_one() {
        let (data, digest) = test_blob();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/v2/myrepo/blobs/{digest}")))
            .respond_with(RangeServer {
                data: data.clone(),
                fail_first: 0,
                seen: Default::default(),
            })
            .mount(&server)
            .await;
        let tmp = tempfile::tempdir().unwrap();
        let cache = BlobCache::open(tmp.path().to_path_buf(), 1024 * 1024).unwrap();
        let leftover = cache
            .blob_path_for(&digest)
            .with_extension(RANGED_PARTIAL_EXTENSION);
        std::fs::write(&leftover, vec![0u8; data.len()]).unwrap();

        let client = RegistryClient::new(server.uri());
        download_blob(
            &client,
            "myrepo",
            &digest,
            data.len() as u64,
            None,
            &cache,
            small_plan(),
            &mut |_, _| {},
        )
        .await
        .expect("the pull after a cancelled ranged pull must succeed");
        let cached = cache.get(&digest).unwrap();
        assert_eq!(tokio::fs::read(&cached).await.unwrap(), data);
        assert!(
            !leftover.exists(),
            "the ranged file is renamed into the cache"
        );
    }

    /// A part that fails transiently is retried on its own, not the whole blob.
    #[tokio::test]
    async fn a_failed_part_is_retried() {
        let (data, digest) = test_blob();
        let seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let responder = RangeServer {
            data: data.clone(),
            fail_first: 1,
            seen: seen.clone(),
        };
        let (result, cache, _tmp) = ranged_download(responder, &data, &digest).await;
        result.expect("a retried part must still complete the download");
        assert_eq!(
            seen.load(std::sync::atomic::Ordering::SeqCst),
            data.len().div_ceil(300) + 1
        );
        let cached = cache.get(&digest).unwrap();
        assert_eq!(tokio::fs::read(&cached).await.unwrap(), data);
    }

    /// A registry that ignores ranges is read once as a whole, not once per part.
    #[tokio::test]
    async fn a_registry_without_ranges_falls_back_to_one_stream() {
        let (data, digest) = test_blob();
        let (result, cache, _tmp) = ranged_download(
            ResponseTemplate::new(200).set_body_bytes(data.clone()),
            &data,
            &digest,
        )
        .await;
        result.expect("one stream must complete the download");
        let cached = cache.get(&digest).unwrap();
        assert_eq!(tokio::fs::read(&cached).await.unwrap(), data);
    }

    /// Parts that do not hash to the digest fail the pull and leave no partial
    /// behind for a later pull to resume onto.
    #[tokio::test]
    async fn ranged_parts_with_wrong_bytes_fail_the_digest_check() {
        let (data, _) = test_blob();
        let (_, other_digest) = {
            use sha2::{Digest, Sha256};
            let other = b"other".to_vec();
            (
                other.clone(),
                format!("sha256:{}", hex::encode(Sha256::digest(&other))),
            )
        };
        let responder = RangeServer {
            data: data.clone(),
            fail_first: 0,
            seen: Default::default(),
        };
        let (result, cache, _tmp) = ranged_download(responder, &data, &other_digest).await;
        assert!(matches!(result, Err(RegistryError::DigestMismatch { .. })));
        for ext in ["partial", RANGED_PARTIAL_EXTENSION] {
            let partial = cache.blob_path_for(&other_digest).with_extension(ext);
            assert!(!partial.exists(), "a mismatched {ext} must be removed");
        }
    }

    /// Retry classification: transient transport/5xx faults resume, terminal ones
    /// do not. This is what keeps a broken pull from becoming a retry storm.
    #[test]
    fn retry_classification_splits_transient_from_terminal() {
        assert!(is_retryable(&RegistryError::DownloadStalled {
            digest: "sha256:x".into(),
            received: 1,
            total: 2,
        }));
        assert!(is_retryable(&RegistryError::ApiError {
            status: 503,
            body: String::new(),
        }));
        assert!(!is_retryable(&RegistryError::ApiError {
            status: 404,
            body: String::new(),
        }));
        assert!(!is_retryable(&RegistryError::BlobNotFound("x".into())));
        assert!(!is_retryable(&RegistryError::DigestMismatch {
            expected: "a".into(),
            actual: "b".into(),
        }));
    }
}
