//! Local blob cache for registry pulls.
//!
//! Content-addressed storage at `~/.cache/smolvm-registry/blobs/sha256/`.
//! Blobs are stored by their digest, each with a zero-length `.used` sibling
//! that records when it was last read. LRU eviction keeps total size under a
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

/// True if a cache-dir entry is a `.used` recency marker rather than a blob.
///
/// Recency lives on a zero-length sibling instead of the blob's own inode
/// because a cache hit must not write to the blob at all: a hit used to set
/// the blob's atime for LRU, and on Linux every `utimensat` also moves the
/// inode's ctime. A machine create that pins a verified artifact by its exact
/// inode identity (device, inode, length, mtime, ctime) then sees "changed
/// while it was being verified" whenever another create of the same artifact
/// hits the cache mid-verification — a burst of creates from one pack failed
/// at random for that reason alone.
fn is_lru_marker(path: &Path) -> bool {
    path.extension().and_then(|e| e.to_str()) == Some(LRU_MARKER_EXT)
}

const LRU_MARKER_EXT: &str = "used";

fn lru_marker_path(blob: &Path) -> PathBuf {
    let mut name = blob.as_os_str().to_owned();
    name.push(".");
    name.push(LRU_MARKER_EXT);
    PathBuf::from(name)
}

/// Record that `blob` was just used. Writes only the marker, never the blob.
fn note_used(blob: &Path) {
    let marker = lru_marker_path(blob);
    let created = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&marker)
        .is_ok();
    if created {
        let _ = filetime::set_file_mtime(&marker, filetime::FileTime::now());
    }
}

/// When `blob` was last used: its marker's mtime, or for a blob cached before
/// markers existed, the atime the old scheme maintained.
fn last_used(blob: &Path, meta: &fs::Metadata) -> std::time::SystemTime {
    fs::metadata(lru_marker_path(blob))
        .and_then(|m| m.modified())
        .or_else(|_| meta.accessed())
        .unwrap_or(std::time::UNIX_EPOCH)
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
            note_used(&path);
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
                let path = entry.path();
                if entry.file_type()?.is_file() && !is_partial(&path) && !is_lru_marker(&path) {
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
            let path = entry.path();
            if !entry.file_type()?.is_file() || is_partial(&path) || is_lru_marker(&path) {
                continue;
            }
            let meta = entry.metadata()?;
            let used = last_used(&path, &meta);
            entries.push((path, meta.len(), used));
        }

        // Least recently used first.
        entries.sort_by_key(|(_, _, used)| *used);

        let mut current = entries.iter().map(|(_, size, _)| size).sum::<u64>();

        for (path, size, _) in &entries {
            if current <= target {
                break;
            }
            tracing::debug!(path = %path.display(), size, "evicting cached blob");
            fs::remove_file(path)?;
            let _ = fs::remove_file(lru_marker_path(path));
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

    /// A cache hit must not write to the blob's inode: the machine-create path
    /// pins a verified artifact by (dev, ino, len, mtime, ctime), and setting
    /// atime moves ctime on Linux, so a concurrent hit made verification fail.
    #[cfg(unix)]
    #[test]
    fn get_does_not_touch_the_blob_inode() {
        use std::os::unix::fs::MetadataExt;
        let tmp = tempfile::tempdir().unwrap();
        let cache = BlobCache::open(tmp.path().to_path_buf(), 1024 * 1024).unwrap();
        let digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        let path = cache.put(digest, b"payload").unwrap();
        // Coarse filesystems stamp whole seconds; make sure a touch would show.
        let old = filetime::FileTime::from_unix_time(1_600_000_000, 0);
        filetime::set_file_times(&path, old, old).unwrap();
        let before = fs::metadata(&path).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));

        for _ in 0..3 {
            assert_eq!(cache.get(digest).as_deref(), Some(path.as_path()));
        }

        let after = fs::metadata(&path).unwrap();
        assert_eq!(after.ino(), before.ino());
        assert_eq!(after.len(), before.len());
        assert_eq!(
            (after.mtime(), after.mtime_nsec()),
            (before.mtime(), before.mtime_nsec())
        );
        assert_eq!(
            (after.ctime(), after.ctime_nsec()),
            (before.ctime(), before.ctime_nsec())
        );
        assert_eq!(
            (after.atime(), after.atime_nsec()),
            (before.atime(), before.atime_nsec())
        );
        assert!(
            lru_marker_path(&path).exists(),
            "recency is recorded on the marker"
        );
    }

    /// The marker keeps LRU order: a blob that was read recently survives
    /// eviction ahead of one that was only written, and markers are neither
    /// counted toward the size nor evicted on their own.
    #[test]
    fn get_refreshes_recency_through_the_marker() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = BlobCache::open(tmp.path().to_path_buf(), 250).unwrap();
        let a = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let b = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let c = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let pa = cache.put(a, &[0u8; 100]).unwrap();
        let pb = cache.put(b, &[0u8; 100]).unwrap();
        // Pin distinct, ordered recency so the test does not depend on clock resolution.
        let t = |secs: i64| filetime::FileTime::from_unix_time(1_600_000_000 + secs, 0);
        filetime::set_file_times(&pa, t(1), t(1)).unwrap();
        filetime::set_file_times(&pb, t(2), t(2)).unwrap();
        cache.get(a).unwrap();
        filetime::set_file_mtime(lru_marker_path(&pa), t(3)).unwrap();
        assert_eq!(cache.total_size().unwrap(), 200, "markers do not count");

        cache.put(c, &[0u8; 100]).unwrap();

        assert!(cache.get(a).is_some(), "recently read blob survives");
        assert!(
            cache.get(b).is_none(),
            "least recently used blob is evicted"
        );
        assert!(!lru_marker_path(&pb).exists(), "its marker goes with it");
        assert!(cache.get(c).is_some());
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
