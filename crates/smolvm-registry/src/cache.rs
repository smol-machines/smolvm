//! Local blob cache for registry pulls.
//!
//! Content-addressed storage at `~/.cache/smolvm-registry/blobs/sha256/`.
//! Blobs are stored by their digest. LRU eviction keeps total size under a
//! configurable limit — default 5 GB, override with `SMOLVM_BLOB_CACHE_MAX_BYTES`.

use std::fs;
use std::path::{Path, PathBuf};

/// Default maximum blob-cache size when `SMOLVM_BLOB_CACHE_MAX_BYTES` is unset: 5 GB.
const DEFAULT_MAX_SIZE: u64 = 5 * 1024 * 1024 * 1024;

/// Resolve the blob-cache byte cap from `SMOLVM_BLOB_CACHE_MAX_BYTES`, falling
/// back to [`DEFAULT_MAX_SIZE`]. A fleet pulling multi-GB `.smolmachine`
/// artifacts should set this well above the largest artifact (bounded by disk)
/// so hot worlds are not re-pulled from the registry on every launch.
fn configured_max_size() -> u64 {
    parse_cache_limit(std::env::var("SMOLVM_BLOB_CACHE_MAX_BYTES").ok().as_deref())
}

/// Parse a byte-count cache limit, ignoring absent / unparseable / zero values.
/// Split out from `configured_max_size` so it is unit-testable without touching
/// the process-global environment.
fn parse_cache_limit(val: Option<&str>) -> u64 {
    val.and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_MAX_SIZE)
}

/// True if a cache-dir entry is an in-flight `.partial` download rather than a
/// finalized blob. A partial is being streamed by an active pull, so it must
/// never be counted toward the cache size or evicted — deleting one makes the
/// owning pull's `adopt` rename fail with ENOENT ("No such file or directory"),
/// which surfaces as `registry pull failed` on large artifacts (only large ones
/// push the cache over its cap and trigger eviction in the first place).
fn is_partial(path: &Path) -> bool {
    path.extension().and_then(|e| e.to_str()) == Some("partial")
}

/// Content-addressed blob cache.
pub struct BlobCache {
    root: PathBuf,
    max_size: u64,
}

impl BlobCache {
    /// Open or create a cache at the default location.
    pub fn open_default() -> std::io::Result<Self> {
        let cache_dir = dirs::cache_dir()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no cache dir"))?
            .join("smolvm-registry")
            .join("blobs");
        Self::open(cache_dir, configured_max_size())
    }

    /// Open or create a cache at a specific path with a size limit.
    pub fn open(root: PathBuf, max_size: u64) -> std::io::Result<Self> {
        fs::create_dir_all(&root)?;
        Ok(Self { root, max_size })
    }

    /// Look up a blob by digest. Returns the path if it exists.
    pub fn get(&self, digest: &str) -> Option<PathBuf> {
        let path = self.blob_path(digest);
        if path.exists() {
            // Touch atime for LRU tracking.
            let _ = filetime::set_file_atime(&path, filetime::FileTime::now());
            Some(path)
        } else {
            None
        }
    }

    /// Store a blob. Returns the path where it was written.
    ///
    /// If storing this blob would exceed `max_size`, evicts least-recently-accessed
    /// blobs first.
    pub fn put(&self, digest: &str, data: &[u8]) -> std::io::Result<PathBuf> {
        let path = self.blob_path(digest);
        if path.exists() {
            return Ok(path);
        }

        // Evict if needed.
        let current = self.total_size()?;
        if current + data.len() as u64 > self.max_size {
            self.evict_until(self.max_size.saturating_sub(data.len() as u64))?;
        }

        // Write atomically via temp file.
        let tmp = path.with_extension("partial");
        fs::write(&tmp, data)?;
        fs::rename(&tmp, &path)?;
        Ok(path)
    }

    /// Total size of all cached blobs in bytes.
    pub fn total_size(&self) -> std::io::Result<u64> {
        let mut total = 0u64;
        if self.root.exists() {
            for entry in fs::read_dir(&self.root)? {
                let entry = entry?;
                if entry.file_type()?.is_file() && !is_partial(&entry.path()) {
                    total += entry.metadata()?.len();
                }
            }
        }
        Ok(total)
    }

    /// Remove all cached blobs.
    pub fn prune_all(&self) -> std::io::Result<u64> {
        let mut freed = 0u64;
        if self.root.exists() {
            for entry in fs::read_dir(&self.root)? {
                let entry = entry?;
                if entry.file_type()?.is_file() {
                    freed += entry.metadata()?.len();
                    fs::remove_file(entry.path())?;
                }
            }
        }
        Ok(freed)
    }

    /// Evict least-recently-accessed blobs until total size is at or below `target`.
    fn evict_until(&self, target: u64) -> std::io::Result<()> {
        let mut entries: Vec<(PathBuf, u64, std::time::SystemTime)> = Vec::new();

        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            // Never evict in-flight `.partial` downloads — a concurrent pull is
            // actively writing them; deleting one breaks its adopt with ENOENT.
            if !entry.file_type()?.is_file() || is_partial(&entry.path()) {
                continue;
            }
            let meta = entry.metadata()?;
            let atime = meta.accessed().unwrap_or(std::time::UNIX_EPOCH);
            entries.push((entry.path(), meta.len(), atime));
        }

        // Sort by atime ascending (oldest first).
        entries.sort_by_key(|(_, _, atime)| *atime);

        let mut current = entries.iter().map(|(_, size, _)| size).sum::<u64>();

        for (path, size, _) in &entries {
            if current <= target {
                break;
            }
            tracing::debug!(path = %path.display(), size, "evicting cached blob");
            fs::remove_file(path)?;
            current -= size;
        }

        Ok(())
    }

    /// Return the cache path for a blob with this digest.
    ///
    /// Used by the pull flow to write directly to `path.with_extension("partial")`,
    /// then call [`adopt`] to finalize.
    pub fn blob_path_for(&self, digest: &str) -> PathBuf {
        self.blob_path(digest)
    }

    /// Adopt an externally-written partial file into the cache.
    ///
    /// Expects the file at `blob_path_for(digest).with_extension("partial")` to
    /// be fully written and digest-verified by the caller. Handles eviction if
    /// needed, then atomically renames the partial file into place.
    pub fn adopt(&self, digest: &str, size: u64) -> std::io::Result<PathBuf> {
        let path = self.blob_path(digest);
        let partial = path.with_extension("partial");

        if path.exists() {
            // Already cached (race condition protection).
            let _ = fs::remove_file(&partial);
            return Ok(path);
        }

        let current = self.total_size()?;
        if current + size > self.max_size {
            self.evict_until(self.max_size.saturating_sub(size))?;
        }

        fs::rename(&partial, &path)?;
        Ok(path)
    }

    /// Path for a blob with the given digest.
    fn blob_path(&self, digest: &str) -> PathBuf {
        // Store as flat files: "sha256:abc..." → "sha256_abc..."
        let filename = digest.replace(':', "_");
        self.root.join(filename)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_put_and_get() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = BlobCache::open(tmp.path().to_path_buf(), 1024 * 1024).unwrap();

        let digest = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let data = b"hello world";

        // Miss before put.
        assert!(cache.get(digest).is_none());

        // Put and get.
        let path = cache.put(digest, data).unwrap();
        assert!(path.exists());
        assert_eq!(fs::read(&path).unwrap(), data);

        // Hit after put.
        assert!(cache.get(digest).is_some());
    }

    #[test]
    fn test_put_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = BlobCache::open(tmp.path().to_path_buf(), 1024 * 1024).unwrap();

        let digest = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        cache.put(digest, b"data1").unwrap();
        // Second put with same digest doesn't overwrite.
        cache.put(digest, b"data2").unwrap();
        let path = cache.get(digest).unwrap();
        assert_eq!(fs::read(path).unwrap(), b"data1");
    }

    #[test]
    fn test_eviction() {
        let tmp = tempfile::tempdir().unwrap();
        // Tiny cache: 20 bytes max.
        let cache = BlobCache::open(tmp.path().to_path_buf(), 20).unwrap();

        let d1 = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        let d2 = "sha256:2222222222222222222222222222222222222222222222222222222222222222";

        cache.put(d1, &[0u8; 15]).unwrap();
        assert!(cache.get(d1).is_some());

        // This should trigger eviction of d1.
        cache.put(d2, &[0u8; 15]).unwrap();
        assert!(cache.get(d2).is_some());
        // d1 should have been evicted.
        assert!(cache.get(d1).is_none());
    }

    #[test]
    fn evict_does_not_delete_in_flight_partial() {
        // Regression (large-artifact "registry pull failed: No such file or
        // directory"): under cache pressure, a pull's eviction must not delete
        // ANOTHER concurrent pull's in-flight `.partial` download, nor its own.
        // Before the fix, `total_size`/`evict_until` counted and removed
        // `.partial` files, so the victim's `adopt` rename hit ENOENT. Only
        // large artifacts trip it because only they push the cache over its cap.
        let tmp = tempfile::tempdir().unwrap();
        let cache = BlobCache::open(tmp.path().to_path_buf(), 100).unwrap();

        let victim = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        let pulling = "sha256:2222222222222222222222222222222222222222222222222222222222222222";

        // A concurrent pull is mid-download: its large `.partial` is on disk.
        let victim_partial = cache.blob_path_for(victim).with_extension("partial");
        fs::write(&victim_partial, [0u8; 80]).unwrap();

        // This pull finishes streaming its own large blob and adopts it — which
        // triggers eviction because the cache dir now looks over-cap.
        let pulling_partial = cache.blob_path_for(pulling).with_extension("partial");
        fs::write(&pulling_partial, [0u8; 80]).unwrap();
        let adopted = cache
            .adopt(pulling, 80)
            .expect("adopt must not fail — its own .partial must survive eviction");

        assert!(adopted.exists(), "adopted blob missing after rename");
        assert!(
            victim_partial.exists(),
            "eviction deleted another concurrent pull's in-flight .partial (the ENOENT bug)"
        );
    }

    #[test]
    fn cache_limit_parses_env_or_defaults() {
        // Valid byte counts are honored.
        assert_eq!(
            parse_cache_limit(Some("10737418240")),
            10 * 1024 * 1024 * 1024
        );
        assert_eq!(parse_cache_limit(Some("  5000000000 ")), 5_000_000_000);
        // Absent / unparseable / zero fall back to the default.
        assert_eq!(parse_cache_limit(None), DEFAULT_MAX_SIZE);
        assert_eq!(parse_cache_limit(Some("garbage")), DEFAULT_MAX_SIZE);
        assert_eq!(parse_cache_limit(Some("0")), DEFAULT_MAX_SIZE);
    }

    #[test]
    fn test_prune_all() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = BlobCache::open(tmp.path().to_path_buf(), 1024 * 1024).unwrap();

        let d1 = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        cache.put(d1, b"test data").unwrap();
        assert!(cache.total_size().unwrap() > 0);

        let freed = cache.prune_all().unwrap();
        assert!(freed > 0);
        assert_eq!(cache.total_size().unwrap(), 0);
    }
}
