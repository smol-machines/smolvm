//! Download a cache disk base from its signed source URL.
//!
//! A base is the whole cache filesystem image (tens of GiB), and one HTTP
//! stream from object storage runs at a few hundred MB/s, so a cold create
//! waited minutes on a single GET. When the source answers ranged requests, the
//! base is fetched as fixed-size parts over several streams and written in
//! place; otherwise it falls back to one stream. Either way the caller gets the
//! file's SHA-256 to verify before the base appears under its name.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use sha2::Digest;
use tokio::io::AsyncWriteExt;

use crate::api::error::ApiError;

/// How a base is fetched. The defaults are for object storage over a data
/// center link; tests shrink them.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FetchPlan {
    /// Bases smaller than this use one stream: ranged parts only pay off for
    /// large files.
    pub parallel_min_bytes: u64,
    /// Bytes per ranged request. Each part is held in memory while it is
    /// written, so `part_bytes * streams` bounds the buffering.
    pub part_bytes: u64,
    /// Ranged requests in flight at once.
    pub streams: usize,
    /// Tries per part before the download fails.
    pub part_attempts: u32,
}

impl Default for FetchPlan {
    fn default() -> Self {
        Self {
            parallel_min_bytes: 256 << 20,
            part_bytes: 16 << 20,
            // From a GCE worker to object storage, 32 x 16 MiB parts ran at
            // about 2 GB/s against 120 MB/s for one stream.
            streams: 32,
            part_attempts: 3,
        }
    }
}

/// Download `url` into the new file `path` (which must not exist), refusing
/// anything larger than `max_bytes`, and return the file's SHA-256 as lowercase
/// hex.
pub(crate) async fn download(
    client: &reqwest::Client,
    url: &reqwest::Url,
    path: &std::path::Path,
    max_bytes: u64,
    plan: FetchPlan,
) -> Result<String, ApiError> {
    // One byte tells whether the source serves ranges, and how big the base is.
    let probe = client
        .get(url.clone())
        .header(reqwest::header::RANGE, "bytes=0-0")
        .send()
        .await
        .map_err(|e| ApiError::internal(format!("fetch cache base: {}", e.without_url())))?;
    let status = probe.status();
    if status == reqwest::StatusCode::PARTIAL_CONTENT {
        let total = content_range_total(&probe).ok_or_else(|| {
            ApiError::internal("cache base source answered a range without its size")
        })?;
        if total > max_bytes {
            return Err(ApiError::BadRequest(format!(
                "cache base exceeds {max_bytes} bytes"
            )));
        }
        if total >= plan.parallel_min_bytes {
            fetch_parts(client, url, path, total, plan).await?;
            return hash_file(path).await;
        }
        let full =
            client.get(url.clone()).send().await.map_err(|e| {
                ApiError::internal(format!("fetch cache base: {}", e.without_url()))
            })?;
        return stream_to_file(full, path, max_bytes).await;
    }
    if !status.is_success() {
        return Err(ApiError::BadRequest(format!(
            "cache base source url returned {status}"
        )));
    }
    // The source ignored the range and sent the whole base: keep it.
    stream_to_file(probe, path, max_bytes).await
}

/// The total size from a `Content-Range: bytes a-b/total` header.
fn content_range_total(response: &reqwest::Response) -> Option<u64> {
    response
        .headers()
        .get(reqwest::header::CONTENT_RANGE)?
        .to_str()
        .ok()?
        .rsplit_once('/')?
        .1
        .parse()
        .ok()
}

/// Write one full-body response to `path`, hashing as it arrives.
async fn stream_to_file(
    response: reqwest::Response,
    path: &std::path::Path,
    max_bytes: u64,
) -> Result<String, ApiError> {
    if !response.status().is_success() {
        return Err(ApiError::BadRequest(format!(
            "cache base source url returned {}",
            response.status()
        )));
    }
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .await
        .map_err(|e| ApiError::internal(format!("create {}: {e}", path.display())))?;
    let mut hasher = sha2::Sha256::new();
    let mut received = 0_u64;
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk
            .map_err(|e| ApiError::internal(format!("read cache base: {}", e.without_url())))?;
        received += chunk.len() as u64;
        if received > max_bytes {
            return Err(ApiError::BadRequest(format!(
                "cache base exceeds {max_bytes} bytes"
            )));
        }
        hasher.update(&chunk);
        file.write_all(&chunk)
            .await
            .map_err(|e| ApiError::internal(format!("write cache base: {e}")))?;
    }
    file.sync_all()
        .await
        .map_err(|e| ApiError::internal(format!("sync cache base: {e}")))?;
    Ok(format!("{:x}", hasher.finalize()))
}

/// Fill `path` with the `total` bytes of `url`, part by part over
/// `plan.streams` concurrent ranged requests.
async fn fetch_parts(
    client: &reqwest::Client,
    url: &reqwest::Url,
    path: &std::path::Path,
    total: u64,
    plan: FetchPlan,
) -> Result<(), ApiError> {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| ApiError::internal(format!("create {}: {e}", path.display())))?;
    file.set_len(total)
        .map_err(|e| ApiError::internal(format!("size {}: {e}", path.display())))?;
    let file = Arc::new(file);
    let parts = total.div_ceil(plan.part_bytes);
    let next = Arc::new(AtomicU64::new(0));
    let failed = Arc::new(AtomicBool::new(false));
    let mut workers = tokio::task::JoinSet::new();
    for _ in 0..plan.streams.max(1).min(parts as usize) {
        let (client, url, file, next, failed) = (
            client.clone(),
            url.clone(),
            file.clone(),
            next.clone(),
            failed.clone(),
        );
        workers.spawn(async move {
            loop {
                if failed.load(Ordering::Relaxed) {
                    return Ok(());
                }
                let part = next.fetch_add(1, Ordering::Relaxed);
                if part >= parts {
                    return Ok(());
                }
                let start = part * plan.part_bytes;
                let end = (start + plan.part_bytes).min(total) - 1;
                if let Err(error) = fetch_part(&client, &url, &file, start, end, plan).await {
                    failed.store(true, Ordering::Relaxed);
                    return Err(error);
                }
            }
        });
    }
    let mut first_error = None;
    while let Some(joined) = workers.join_next().await {
        let result =
            joined.map_err(|e| ApiError::internal(format!("cache base fetch task: {e}")))?;
        if let Err(error) = result {
            first_error.get_or_insert(error);
        }
    }
    if let Some(error) = first_error {
        return Err(error);
    }
    let file = file.clone();
    tokio::task::spawn_blocking(move || file.sync_all())
        .await
        .map_err(|e| ApiError::internal(format!("cache base sync task: {e}")))?
        .map_err(|e| ApiError::internal(format!("sync cache base: {e}")))
}

/// Fetch bytes `start..=end` and write them at `start`, retrying a part that
/// fails or comes back short.
async fn fetch_part(
    client: &reqwest::Client,
    url: &reqwest::Url,
    file: &Arc<std::fs::File>,
    start: u64,
    end: u64,
    plan: FetchPlan,
) -> Result<(), ApiError> {
    let want = end - start + 1;
    let mut last_error = String::new();
    for attempt in 1..=plan.part_attempts.max(1) {
        let result = async {
            let response = client
                .get(url.clone())
                .header(reqwest::header::RANGE, format!("bytes={start}-{end}"))
                .send()
                .await
                .map_err(|e| e.without_url().to_string())?;
            if response.status() != reqwest::StatusCode::PARTIAL_CONTENT {
                return Err(format!("range request returned {}", response.status()));
            }
            let body = response
                .bytes()
                .await
                .map_err(|e| e.without_url().to_string())?;
            if body.len() as u64 != want {
                return Err(format!("range returned {} of {want} bytes", body.len()));
            }
            Ok(body)
        }
        .await;
        match result {
            Ok(body) => {
                let file = file.clone();
                return tokio::task::spawn_blocking(move || write_at(&file, start, &body))
                    .await
                    .map_err(|e| ApiError::internal(format!("cache base write task: {e}")))?
                    .map_err(|e| ApiError::internal(format!("write cache base: {e}")));
            }
            Err(error) => {
                last_error = error;
                if attempt < plan.part_attempts {
                    tokio::time::sleep(Duration::from_millis(200 * u64::from(attempt))).await;
                }
            }
        }
    }
    Err(ApiError::internal(format!(
        "fetch cache base bytes {start}-{end}: {last_error}"
    )))
}

/// Write `bytes` at `offset` without a shared cursor, so parts can be written
/// concurrently.
fn write_at(file: &std::fs::File, offset: u64, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.write_all_at(bytes, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let mut written = 0;
        while written < bytes.len() {
            let count = file.seek_write(&bytes[written..], offset + written as u64)?;
            if count == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "cache base write returned zero bytes",
                ));
            }
            written += count;
        }
        Ok(())
    }
}

/// The SHA-256 of a whole file, as lowercase hex.
async fn hash_file(path: &std::path::Path) -> Result<String, ApiError> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let mut file = std::fs::File::open(&path)?;
        let mut hasher = sha2::Sha256::new();
        std::io::copy(&mut file, &mut hasher)?;
        Ok::<_, std::io::Error>(format!("{:x}", hasher.finalize()))
    })
    .await
    .map_err(|e| ApiError::internal(format!("cache base hash task: {e}")))?
    .map_err(|e| ApiError::internal(format!("hash cache base: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Serve `body` over HTTP. With `ranges`, answer `Range: bytes=a-b` with a
    /// 206 of exactly that slice; without, always send the whole body. Counts
    /// the requests it answered.
    async fn serve(body: Vec<u8>, ranges: bool) -> (reqwest::Url, Arc<AtomicU64>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = reqwest::Url::parse(&format!("http://{}/base", listener.local_addr().unwrap()))
            .unwrap();
        let body = Arc::new(body);
        let served = Arc::new(AtomicU64::new(0));
        let count = served.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let body = body.clone();
                let count = count.clone();
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    while !head.ends_with(b"\r\n\r\n") {
                        let Ok(byte) = socket.read_u8().await else {
                            return;
                        };
                        head.push(byte);
                    }
                    count.fetch_add(1, Ordering::Relaxed);
                    let head = String::from_utf8_lossy(&head).to_ascii_lowercase();
                    let range = head
                        .lines()
                        .find_map(|l| l.strip_prefix("range: bytes="))
                        .and_then(|r| r.trim().split_once('-'))
                        .and_then(|(a, b)| {
                            Some((a.parse::<usize>().ok()?, b.parse::<usize>().ok()?))
                        });
                    let response = match range {
                        Some((a, b)) if ranges => {
                            let b = b.min(body.len() - 1);
                            let mut r = format!(
                                "HTTP/1.1 206 Partial Content\r\ncontent-length: {}\r\ncontent-range: bytes {a}-{b}/{}\r\nconnection: close\r\n\r\n",
                                b - a + 1,
                                body.len()
                            )
                            .into_bytes();
                            r.extend_from_slice(&body[a..=b]);
                            r
                        }
                        _ => {
                            let mut r = format!(
                                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                                body.len()
                            )
                            .into_bytes();
                            r.extend_from_slice(&body);
                            r
                        }
                    };
                    let _ = socket.write_all(&response).await;
                });
            }
        });
        (url, served)
    }

    fn body(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 % 251) as u8).collect()
    }

    fn sha(bytes: &[u8]) -> String {
        format!("{:x}", sha2::Sha256::digest(bytes))
    }

    const SMALL_PLAN: FetchPlan = FetchPlan {
        parallel_min_bytes: 1000,
        part_bytes: 1000,
        streams: 4,
        part_attempts: 2,
    };

    #[tokio::test]
    async fn a_large_base_arrives_in_ranged_parts_byte_for_byte() {
        let data = body(10_500);
        let (url, served) = serve(data.clone(), true).await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("base.partial");
        let digest = download(&reqwest::Client::new(), &url, &path, 1 << 20, SMALL_PLAN)
            .await
            .unwrap();
        assert_eq!(digest, sha(&data));
        assert_eq!(std::fs::read(&path).unwrap(), data);
        // The probe plus eleven 1000-byte parts.
        assert_eq!(served.load(Ordering::Relaxed), 12);
    }

    #[tokio::test]
    async fn a_source_without_ranges_is_read_in_one_stream() {
        let data = body(10_500);
        let (url, served) = serve(data.clone(), false).await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("base.partial");
        let digest = download(&reqwest::Client::new(), &url, &path, 1 << 20, SMALL_PLAN)
            .await
            .unwrap();
        assert_eq!(digest, sha(&data));
        assert_eq!(std::fs::read(&path).unwrap(), data);
        assert_eq!(
            served.load(Ordering::Relaxed),
            1,
            "the probe already carried the base"
        );
    }

    #[tokio::test]
    async fn a_small_base_uses_one_stream_and_an_oversized_one_is_refused() {
        let data = body(600);
        let (url, served) = serve(data.clone(), true).await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("small.partial");
        let digest = download(&reqwest::Client::new(), &url, &path, 1 << 20, SMALL_PLAN)
            .await
            .unwrap();
        assert_eq!(digest, sha(&data));
        assert_eq!(served.load(Ordering::Relaxed), 2, "probe plus one full GET");

        let too_big = dir.path().join("big.partial");
        let refused = download(&reqwest::Client::new(), &url, &too_big, 500, SMALL_PLAN).await;
        assert!(matches!(refused, Err(ApiError::BadRequest(_))));
        assert!(!too_big.exists());
    }
}
