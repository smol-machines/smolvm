//! Keep the cache disk directory within a byte budget.
//!
//! A node's bases are a cache of versions the object store keeps: every
//! publish and every fetch of a new version leaves another base of tens of
//! GiB, and nothing used to remove one until its whole cache disk was deleted,
//! so workers filled up with versions nobody used any more. Before and after a
//! base is fetched or published, the least recently used bases are removed
//! until the bases fit the budget and the filesystem keeps its reserve free.
//! A base a machine here is attached to, one being fetched, and one used in
//! the last [`RECENT_USE_GRACE`] are never removed; a removed base that is
//! needed again is fetched from its source.

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, SystemTime};

use crate::api::state::ApiState;

/// How long after a base was last used it stays even over budget. A create
/// marks its base used when it resolves it, then saves the machine record that
/// attaches it; this covers that gap many times over.
pub(crate) const RECENT_USE_GRACE: Duration = Duration::from_secs(15 * 60);

/// Default share of the filesystem the bases may hold, as a divisor.
const DEFAULT_BUDGET_DIVISOR: u64 = 2;

/// Share of the filesystem kept free, as a divisor, whatever the bases hold:
/// the disk is shared with machines' own disks, which must never run out.
const RESERVE_DIVISOR: u64 = 10;

/// What the bases may hold and what the filesystem must keep free.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Budget {
    pub max_bytes: u64,
    pub reserve_bytes: u64,
}

impl Budget {
    /// The budget for a filesystem of `capacity` bytes, or `max_bytes` when
    /// configured. An unknown capacity leaves only a configured maximum.
    pub(crate) fn for_capacity(capacity: Option<u64>, max_bytes: Option<u64>) -> Self {
        Budget {
            max_bytes: max_bytes
                .or(capacity.map(|c| c / DEFAULT_BUDGET_DIVISOR))
                .unwrap_or(u64::MAX),
            reserve_bytes: capacity.map_or(0, |c| c / RESERVE_DIVISOR),
        }
    }
}

/// A base in the cache disk directory.
#[derive(Clone, Debug)]
pub(crate) struct Base {
    pub name: String,
    /// Bytes it occupies on disk, which for a sparse image is less than its length.
    pub bytes: u64,
    pub last_used: SystemTime,
}

/// The bases to remove, least recently used first, until the bases fit
/// `budget` and `available` bytes stay free. `keep` names bases that must stay.
pub(crate) fn choose_evictions(
    bases: &[Base],
    available: u64,
    budget: Budget,
    now: SystemTime,
    keep: impl Fn(&str) -> bool,
) -> Vec<String> {
    let mut held: u64 = bases.iter().map(|b| b.bytes).sum();
    let mut available = available;
    let fits =
        |held: u64, available: u64| held <= budget.max_bytes && available >= budget.reserve_bytes;
    if fits(held, available) {
        return Vec::new();
    }
    let mut candidates: Vec<&Base> = bases
        .iter()
        .filter(|b| !keep(&b.name))
        .filter(|b| now.duration_since(b.last_used).unwrap_or_default() >= RECENT_USE_GRACE)
        .collect();
    candidates.sort_by_key(|b| b.last_used);
    let mut chosen = Vec::new();
    for base in candidates {
        if fits(held, available) {
            break;
        }
        held -= base.bytes;
        available = available.saturating_add(base.bytes);
        chosen.push(base.name.clone());
    }
    chosen
}

/// Record that `base` was used now, in its access time: its modification time
/// is part of the identity its recorded digest is bound to. Best-effort.
pub(crate) fn mark_used(base: &Path) {
    let marked = std::fs::File::open(base)
        .and_then(|file| file.set_times(std::fs::FileTimes::new().set_accessed(SystemTime::now())));
    if let Err(e) = marked {
        tracing::debug!(base = %base.display(), error = %e, "could not mark a cache base used");
    }
}

/// The bases in `dir`: files a caller may name, skipping digests and partial
/// downloads, which start with a dot.
fn scan(dir: &Path) -> Vec<Base> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            crate::data::disk::validate_base_name(&name).ok()?;
            let meta = entry.metadata().ok()?;
            if !meta.is_file() {
                return None;
            }
            let modified = meta.modified().ok()?;
            let last_used = meta.accessed().map_or(modified, |a| a.max(modified));
            #[cfg(unix)]
            let bytes = std::os::unix::fs::MetadataExt::blocks(&meta).saturating_mul(512);
            #[cfg(not(unix))]
            let bytes = meta.len();
            Some(Base {
                name,
                bytes,
                last_used,
            })
        })
        .collect()
}

/// Capacity and free bytes of the filesystem holding `path` (unix).
fn filesystem_space(path: &Path) -> Option<(u64, u64)> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
        // SAFETY: valid NUL-terminated path; `stat` read only after success.
        unsafe {
            let mut stat: std::mem::MaybeUninit<libc::statvfs> = std::mem::MaybeUninit::uninit();
            if libc::statvfs(c.as_ptr(), stat.as_mut_ptr()) != 0 {
                return None;
            }
            let stat = stat.assume_init();
            #[allow(clippy::unnecessary_cast)]
            let frsize = stat.f_frsize as u64;
            #[allow(clippy::unnecessary_cast)]
            let total = (stat.f_blocks as u64).checked_mul(frsize)?;
            #[allow(clippy::unnecessary_cast)]
            let available = (stat.f_bavail as u64).checked_mul(frsize)?;
            (total > 0).then_some((total, available))
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// The bases machines on this server are attached to, by file name, with the
/// machine attached to each.
pub(crate) fn attached_bases(
    db: &crate::db::SmolvmDb,
) -> Result<HashMap<std::ffi::OsString, String>, crate::api::error::ApiError> {
    Ok(db
        .list_vms()
        .map_err(|e| crate::api::error::ApiError::internal(format!("list machines: {e}")))?
        .into_iter()
        .filter_map(|(name, record)| {
            let base = record.cache_disk?.base.file_name()?.to_os_string();
            Some((base, name))
        })
        .collect())
}

/// Remove least recently used bases until the cache disk directory fits its
/// budget. Best-effort: a failure here never fails the fetch or publish that
/// asked for room.
pub(crate) async fn make_room(state: &ApiState) {
    let Ok(dir) = state.cache_disk_dir() else {
        return;
    };
    let max_bytes = state.cache_disk_max_bytes();
    let db = state.db().clone();
    let swept = tokio::task::spawn_blocking(move || {
        let Some((capacity, available)) = filesystem_space(&dir) else {
            return;
        };
        let budget = Budget::for_capacity(Some(capacity), max_bytes);
        let bases = scan(&dir);
        let attached = match attached_bases(&db) {
            Ok(attached) => attached,
            Err(e) => {
                tracing::warn!(error = ?e, "could not list attached cache bases; removing none");
                return;
            }
        };
        let chosen = choose_evictions(&bases, available, budget, SystemTime::now(), |name| {
            attached.contains_key(std::ffi::OsStr::new(name))
        });
        for name in chosen {
            // A base being fetched stays; the fetch lock is held for the whole download.
            let lock = crate::api::handlers::machines::cache_base_fetch_lock(&name);
            let Ok(_fetching) = lock.try_lock() else {
                continue;
            };
            let base = bases.iter().find(|b| b.name == name);
            match crate::data::disk::remove_base(&dir.join(&name)) {
                Ok(()) => tracing::info!(
                    base = %name,
                    bytes = base.map_or(0, |b| b.bytes),
                    idle_s = base
                        .and_then(|b| SystemTime::now().duration_since(b.last_used).ok())
                        .map_or(0, |d| d.as_secs()),
                    "removed a least recently used cache base to stay within budget"
                ),
                Err(e) => tracing::warn!(base = %name, error = %e, "could not remove a cache base"),
            }
        }
    })
    .await;
    if let Err(e) = swept {
        tracing::warn!(error = %e, "cache base eviction task failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1 << 30;

    fn base(name: &str, gib: u64, idle_min: u64, now: SystemTime) -> Base {
        Base {
            name: name.to_string(),
            bytes: gib * GIB,
            last_used: now - Duration::from_secs(idle_min * 60),
        }
    }

    #[test]
    fn nothing_is_removed_while_the_bases_fit() {
        let now = SystemTime::now();
        let bases = [base("a", 10, 600, now), base("b", 10, 600, now)];
        let budget = Budget::for_capacity(Some(100 * GIB), None);
        assert!(choose_evictions(&bases, 50 * GIB, budget, now, |_| false).is_empty());
    }

    #[test]
    fn the_least_recently_used_go_first_until_the_bases_fit() {
        let now = SystemTime::now();
        let bases = [
            base("newest", 20, 30, now),
            base("oldest", 20, 900, now),
            base("middle", 20, 300, now),
        ];
        // 60 GiB held against a 50 GiB budget, plenty free: one removal fits.
        let budget = Budget::for_capacity(Some(100 * GIB), None);
        assert_eq!(
            choose_evictions(&bases, 40 * GIB, budget, now, |_| false),
            ["oldest"]
        );
    }

    #[test]
    fn a_full_filesystem_frees_its_reserve_even_under_budget() {
        let now = SystemTime::now();
        let bases = [base("old", 5, 900, now), base("older", 5, 1200, now)];
        // 10 GiB of bases is well under the 50 GiB budget, but machines' disks
        // left 4 GiB of the 10 GiB reserve free.
        let budget = Budget::for_capacity(Some(100 * GIB), None);
        assert_eq!(
            choose_evictions(&bases, 4 * GIB, budget, now, |_| false),
            ["older", "old"]
        );
    }

    #[test]
    fn attached_and_recently_used_bases_stay_over_budget() {
        let now = SystemTime::now();
        let bases = [
            base("attached", 40, 900, now),
            base("just-fetched", 40, 1, now),
            base("idle", 40, 600, now),
        ];
        let budget = Budget::for_capacity(Some(100 * GIB), None);
        assert_eq!(
            choose_evictions(&bases, 40 * GIB, budget, now, |name| name == "attached"),
            ["idle"],
            "only the idle, unattached base may go, even though the rest stay over budget"
        );
    }

    #[test]
    fn a_configured_maximum_replaces_the_share_of_the_disk() {
        assert_eq!(
            Budget::for_capacity(Some(1000 * GIB), Some(200 * GIB)),
            Budget {
                max_bytes: 200 * GIB,
                reserve_bytes: 100 * GIB
            }
        );
        assert_eq!(
            Budget::for_capacity(None, None),
            Budget {
                max_bytes: u64::MAX,
                reserve_bytes: 0
            }
        );
    }

    fn idle_base(dir: &Path, name: &str, idle: Duration) -> std::path::PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, vec![7u8; 64 << 10]).unwrap();
        let then = SystemTime::now() - idle;
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_times(
                std::fs::FileTimes::new()
                    .set_accessed(then)
                    .set_modified(then),
            )
            .unwrap();
        path
    }

    #[tokio::test]
    async fn over_budget_the_server_removes_only_idle_unattached_bases() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("cache-disks");
        std::fs::create_dir(&dir).unwrap();
        let idle = Duration::from_secs(6 * 3600);
        let old = idle_base(&dir, "cdisk-old-v1.qcow2", idle);
        crate::data::disk::record_base_digest(&old, &"ab".repeat(32));
        let attached = idle_base(&dir, "cdisk-attached-v1.qcow2", idle);
        let recent = idle_base(&dir, "cdisk-recent-v2.qcow2", Duration::from_secs(60));

        let db = crate::db::SmolvmDb::open_at(&root.path().join("smolvm.db")).unwrap();
        let mut record =
            crate::config::VmRecord::new("uses-cache".into(), 1, 512, vec![], vec![], false);
        record.cache_disk = Some(
            crate::data::disk::CacheDisk::parse(&format!("{}:/cache", attached.display())).unwrap(),
        );
        db.insert_vm("uses-cache", &record).unwrap();
        let state = ApiState::with_db(db);
        state.set_cache_disk_dir(Some(dir.clone()));
        state.set_cache_disk_max_bytes(Some(1));

        make_room(&state).await;

        assert!(!old.exists(), "the idle, unattached base is removed");
        assert!(
            !dir.join(".cdisk-old-v1.qcow2.sha256").exists(),
            "with its recorded digest"
        );
        assert!(attached.exists(), "a base a machine is attached to stays");
        assert!(recent.exists(), "a base used in the last minutes stays");
    }

    #[test]
    fn marking_a_base_used_keeps_its_recorded_digest() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cdisk-a-v1.qcow2");
        std::fs::write(&path, b"base").unwrap();
        let old = SystemTime::now() - Duration::from_secs(3600);
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_times(
                std::fs::FileTimes::new()
                    .set_accessed(old)
                    .set_modified(old),
            )
            .unwrap();
        crate::data::disk::record_base_digest(&path, &"ab".repeat(32));

        mark_used(&path);

        let scanned = scan(dir.path());
        assert_eq!(
            scanned.len(),
            1,
            "the digest sidecar is not a base: {scanned:?}"
        );
        assert!(
            SystemTime::now()
                .duration_since(scanned[0].last_used)
                .unwrap()
                < Duration::from_secs(60),
            "the use was recorded"
        );
        let cache =
            crate::data::disk::CacheDisk::in_dir(dir.path(), "cdisk-a-v1.qcow2", "/cache").unwrap();
        assert_eq!(
            cache.base_digest().unwrap(),
            "ab".repeat(32),
            "the recorded digest still describes the base"
        );
    }
}
