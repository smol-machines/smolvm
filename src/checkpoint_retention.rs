//! Keep the node's checkpoint store bounded.
//!
//! Every incremental capture publishes a checkpoint directory into the node's
//! store (see [`crate::checkpoint_delta`]), and nothing used to remove one: a
//! busy node held hundreds of published checkpoints and terabytes of objects
//! while its control plane knew of a dozen. This module forgets checkpoints and
//! reclaims the objects only they held.
//!
//! A checkpoint goes when the control plane asks ([`forget`]), or when it has
//! not been used for [`Policy::max_age`], or, oldest use first, while the store
//! is over its byte budget or the filesystem below its free reserve. Three
//! things keep one:
//!
//! - It is the checkpoint a machine here continues from (its checkpoint head),
//!   or a machine was created from its directory. The next capture of that
//!   machine is a delta of it. A forget asked for such a checkpoint is
//!   recorded, and it goes once nothing continues from it any more.
//! - It is in use: a capture deltas against it, or an import or restore reads
//!   it. Each holds the checkpoint's pin (a shared lock) for as long as it
//!   reads it, and a forget only proceeds holding the pin exclusively.
//! - It was used within [`Policy::grace`], which covers the gap between a
//!   restore and the machine record that names it as its head.
//!
//! Every published checkpoint holds a hard link to each object it needs, so
//! forgetting one never breaks another, including a delta's descendants: they
//! carry their own links to every object they share with it. A forgotten
//! checkpoint only costs a later delta its base: the capture then exports in
//! full, and a delta of it that arrives for restore is refused with a conflict
//! naming the base, which the control plane imports first.
//!
//! Objects whose last link is the store's own are removed afterwards by
//! [`crate::checkpoint_store::prune_in_batches`], which holds the store's
//! exclusive lock only for one batch at a time.

use crate::checkpoint_store as store;
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

/// Pins, one lock file per checkpoint id, also recording its last use.
const PINS: &str = "pins";
/// Forgets asked for while a checkpoint could not go yet.
const FORGET: &str = "forget";
/// Forgotten directories waiting to be deleted.
const TRASH: &str = "trash";

/// Default for how long an unused checkpoint is kept.
const DEFAULT_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);
/// Default for how long after its last use a checkpoint is never removed.
const DEFAULT_GRACE: Duration = Duration::from_secs(30 * 60);
/// Default share of the store's filesystem it may hold, as a divisor.
const DEFAULT_BUDGET_DIVISOR: u64 = 4;
/// Share of the filesystem kept free, as a divisor, whatever the store holds.
const RESERVE_DIVISOR: u64 = 10;
/// Objects examined per batch of a prune.
const PRUNE_BATCH: usize = 20_000;
/// Least time between two runs, however many captures ask for one.
const MIN_RUN_GAP: Duration = Duration::from_secs(60);
/// How often retention runs with no capture asking.
const RUN_INTERVAL: Duration = Duration::from_secs(60 * 60);
/// Interrupted imports leave staging directories; this old, they are dead.
const STALE_STAGING: Duration = Duration::from_secs(24 * 60 * 60);

/// Bytes the store's objects held after the last run, for `/capacity`.
static STORE_BYTES: AtomicU64 = AtomicU64::new(u64::MAX);

/// Disk space the node's checkpoint store held after the last retention run,
/// once one has run.
pub fn store_bytes() -> Option<u64> {
    let bytes = STORE_BYTES.load(Ordering::Relaxed);
    (bytes != u64::MAX).then_some(bytes)
}

fn published_dir(store: &Path) -> PathBuf {
    store.join("published")
}

fn materialized_record(store: &Path, id: &str) -> PathBuf {
    store.join("materialized").join(id)
}

// ---------------------------------------------------------------------------
// Pins

/// A shared hold on one stored checkpoint: while it is alive, the checkpoint
/// is not forgotten. Take it before looking the checkpoint up, so a forget that
/// ran first is seen as the checkpoint being absent.
#[derive(Debug)]
pub struct Pin {
    _file: File,
}

fn open_pin(path: &Path) -> io::Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

/// Whether `file` is still the file at `path`: a forget unlinks a pin it
/// holds, and a lock on the unlinked file protects nothing.
fn still_linked(file: &File, path: &Path) -> io::Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let held = file.metadata()?;
        match std::fs::symlink_metadata(path) {
            Ok(current) => Ok(held.dev() == current.dev() && held.ino() == current.ino()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (file, path);
        Ok(true)
    }
}

/// Pin checkpoint `id` in `store`, recording its use. `None` for an id that
/// is not a checkpoint id, which names nothing in the store.
pub fn pin(store: &Path, id: &str) -> io::Result<Option<Pin>> {
    if !store::is_checkpoint_id(id) {
        return Ok(None);
    }
    let dir = store.join(PINS);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(id);
    loop {
        let file = open_pin(&path)?;
        file.lock_shared()?;
        if still_linked(&file, &path)? {
            // Its modification time is the checkpoint's last use.
            let _ = file.set_modified(SystemTime::now());
            return Ok(Some(Pin { _file: file }));
        }
    }
}

/// The exclusive hold a forget needs, or `None` while something pins `id`.
fn try_claim(store: &Path, id: &str) -> io::Result<Option<(File, PathBuf)>> {
    let dir = store.join(PINS);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(id);
    loop {
        let file = open_pin(&path)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => return Ok(None),
            Err(std::fs::TryLockError::Error(error)) => return Err(error),
        }
        if still_linked(&file, &path)? {
            return Ok(Some((file, path)));
        }
    }
}

fn last_pinned(store: &Path, id: &str) -> Option<SystemTime> {
    std::fs::metadata(store.join(PINS).join(id))
        .and_then(|meta| meta.modified())
        .ok()
}

fn forget_requested(store: &Path, id: &str) -> bool {
    store.join(FORGET).join(id).exists()
}

fn request_forget(store: &Path, id: &str) -> io::Result<()> {
    let dir = store.join(FORGET);
    std::fs::create_dir_all(&dir)?;
    File::create(dir.join(id)).map(|_| ())
}

// ---------------------------------------------------------------------------
// What must stay

/// Checkpoints machines on this node continue from or were created from.
#[derive(Debug, Default, Clone)]
pub struct Keep {
    /// Checkpoint heads.
    pub ids: HashSet<String>,
    /// Published directory names a machine record points into.
    pub dirs: HashSet<OsString>,
}

impl Keep {
    /// What the machines in `db` need from `store`.
    pub fn from_db(db: &crate::db::SmolvmDb, store: &Path) -> crate::Result<Self> {
        Ok(Self::from_records(
            db.list_vms()?.into_iter().map(|(_, record)| record),
            store,
        ))
    }

    fn from_records(
        records: impl IntoIterator<Item = crate::config::VmRecord>,
        store: &Path,
    ) -> Self {
        let published = published_dir(store);
        let canonical = published.canonicalize().ok();
        let mut keep = Keep::default();
        for record in records {
            if let Some(head) = record.checkpoint_head {
                keep.ids.insert(head);
            }
            let paths = record
                .source_smolmachine
                .map(PathBuf::from)
                .into_iter()
                .chain(record.paused_checkpoint);
            for path in paths {
                for root in std::iter::once(&published).chain(canonical.as_ref()) {
                    if let Ok(rest) = path.strip_prefix(root) {
                        if let Some(first) = rest.components().next() {
                            keep.dirs.insert(first.as_os_str().to_os_string());
                        }
                    }
                }
            }
        }
        keep
    }

    fn keeps(&self, id: Option<&str>, dir: Option<&std::ffi::OsStr>) -> bool {
        id.is_some_and(|id| self.ids.contains(id)) || dir.is_some_and(|dir| self.dirs.contains(dir))
    }
}

// ---------------------------------------------------------------------------
// Forgetting

/// What [`forget`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Forgotten {
    /// The checkpoint is gone from the store.
    Removed,
    /// The store did not hold it.
    Absent,
    /// A machine continues from it, or something is reading it: it goes once
    /// that ends.
    Deferred,
}

/// The published directory a lineage record points to, by name, when it is
/// one of this store's.
fn record_dir(store: &Path, record: &store::LineageRecord) -> Option<OsString> {
    let path = Path::new(&record.path);
    let parent = path.parent()?;
    let published = published_dir(store);
    let ours = parent == published
        || published
            .canonicalize()
            .is_ok_and(|canonical| parent == canonical);
    ours.then(|| path.file_name().map(|name| name.to_os_string()))
        .flatten()
}

/// Move a published directory out of reach, then delete it. Renaming first
/// makes it disappear at once for every reader that looks it up after.
fn discard(store: &Path, name: &std::ffi::OsStr) -> io::Result<bool> {
    let source = published_dir(store).join(name);
    if !source.exists() {
        return Ok(false);
    }
    let trash = store.join(TRASH);
    std::fs::create_dir_all(&trash)?;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let mut target = name.to_os_string();
    target.push(format!(".{nanos}"));
    let target = trash.join(target);
    match std::fs::rename(&source, &target) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    }
    if let Err(error) = std::fs::remove_dir_all(&target) {
        // The next run empties the trash.
        tracing::warn!(path = %target.display(), %error, "could not delete a forgotten checkpoint");
    }
    Ok(true)
}

/// Forget checkpoint `id`: drop its lineage record and its published
/// directory, unless `keep` names it or it is pinned. Then the forget is
/// recorded, and a later [`run`] completes it once neither holds.
pub fn forget(store: &Path, id: &str, keep: &Keep) -> io::Result<Forgotten> {
    forget_inner(store, id, keep, true)
}

fn forget_inner(store: &Path, id: &str, keep: &Keep, remember: bool) -> io::Result<Forgotten> {
    if !store::is_checkpoint_id(id) {
        return Ok(Forgotten::Absent);
    }
    let Some((claim, pin_path)) = try_claim(store, id)? else {
        if remember {
            request_forget(store, id)?;
        }
        return Ok(Forgotten::Deferred);
    };
    let record = store::find_lineage(store, id)?;
    let mut dirs: Vec<OsString> = record
        .as_ref()
        .and_then(|record| record_dir(store, record))
        .into_iter()
        .collect();
    // An import publishes under the id itself.
    let imported = OsString::from(format!("{id}.checkpoint"));
    if !dirs.contains(&imported) && published_dir(store).join(&imported).exists() {
        dirs.push(imported);
    }
    if keep.ids.contains(id) || dirs.iter().any(|dir| keep.dirs.contains(dir)) {
        if remember {
            request_forget(store, id)?;
        }
        return Ok(Forgotten::Deferred);
    }
    // The record first: from here no capture or restore finds it, and a crash
    // leaves at worst an unrecorded directory, which ages out.
    let mut removed = store::remove_lineage(store, id)?;
    let _ = std::fs::remove_file(materialized_record(store, id));
    for dir in &dirs {
        removed |= discard(store, dir)?;
    }
    let _ = std::fs::remove_file(store.join(FORGET).join(id));
    // Unlinked while held, so a pin taken meanwhile sees it gone and retries.
    let _ = std::fs::remove_file(&pin_path);
    drop(claim);
    Ok(if removed {
        Forgotten::Removed
    } else {
        Forgotten::Absent
    })
}

// ---------------------------------------------------------------------------
// Selection

/// A published checkpoint, as retention sees it.
#[derive(Debug, Clone)]
pub struct Entry {
    /// Its directory under `published`.
    pub dir: OsString,
    /// Its checkpoint id, when the lineage index records it.
    pub id: Option<String>,
    /// When it was last captured, imported or pinned.
    pub last_used: SystemTime,
    /// A machine here continues from it or was created from it.
    pub keep: bool,
    /// The control plane asked for it to be forgotten.
    pub requested: bool,
}

/// Retention settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// Unused this long, a checkpoint goes; `None` keeps them however old.
    pub max_age: Option<Duration>,
    /// Used this recently, a checkpoint stays, even over budget.
    pub grace: Duration,
    /// Byte budget of the store's objects; `None` is a share of the filesystem.
    pub max_bytes: Option<u64>,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            max_age: Some(DEFAULT_MAX_AGE),
            grace: DEFAULT_GRACE,
            max_bytes: None,
        }
    }
}

fn env_secs(name: &str) -> Option<u64> {
    std::env::var(name).ok()?.trim().parse().ok()
}

impl Policy {
    /// The policy from the environment, or `None` when retention is off
    /// (`SMOLVM_CHECKPOINT_STORE_RETENTION=off`).
    ///
    /// - `SMOLVM_CHECKPOINT_STORE_MAX_AGE_SECS`: unused this long, a checkpoint
    ///   goes (default a day; `0` keeps them however old).
    /// - `SMOLVM_CHECKPOINT_STORE_GRACE_SECS`: used this recently, it stays
    ///   (default 30 minutes).
    /// - `SMOLVM_CHECKPOINT_STORE_MAX_BYTES`: the store's byte budget (default
    ///   a quarter of its filesystem).
    pub fn from_env() -> Option<Self> {
        if std::env::var("SMOLVM_CHECKPOINT_STORE_RETENTION")
            .is_ok_and(|value| matches!(value.trim(), "off" | "0" | "false"))
        {
            return None;
        }
        let defaults = Policy::default();
        Some(Policy {
            max_age: match env_secs("SMOLVM_CHECKPOINT_STORE_MAX_AGE_SECS") {
                Some(0) => None,
                Some(secs) => Some(Duration::from_secs(secs)),
                None => defaults.max_age,
            },
            grace: env_secs("SMOLVM_CHECKPOINT_STORE_GRACE_SECS")
                .map(Duration::from_secs)
                .unwrap_or(defaults.grace),
            max_bytes: env_secs("SMOLVM_CHECKPOINT_STORE_MAX_BYTES").filter(|&bytes| bytes > 0),
        })
    }
}

fn idle(entry: &Entry, now: SystemTime) -> Duration {
    now.duration_since(entry.last_used).unwrap_or_default()
}

/// Checkpoints to forget regardless of space: asked for, or unused longer than
/// the policy's maximum age. Kept ones never; recently used ones only when the
/// control plane asked.
pub fn expired(entries: &[Entry], policy: &Policy, now: SystemTime) -> Vec<usize> {
    entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| !entry.keep)
        .filter(|(_, entry)| {
            entry.requested
                || policy
                    .max_age
                    .is_some_and(|max| idle(entry, now) >= max.max(policy.grace))
        })
        .map(|(index, _)| index)
        .collect()
}

/// What the store may hold and what the filesystem must keep free.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    /// Most bytes the store's objects may occupy.
    pub max_bytes: u64,
    /// Least bytes the filesystem must keep available.
    pub reserve_bytes: u64,
}

impl Budget {
    /// The budget on a filesystem of `capacity` bytes, or `max_bytes` when
    /// configured. An unknown capacity leaves only a configured maximum.
    pub fn for_capacity(capacity: Option<u64>, max_bytes: Option<u64>) -> Self {
        Budget {
            max_bytes: max_bytes
                .or(capacity.map(|c| c / DEFAULT_BUDGET_DIVISOR))
                .unwrap_or(u64::MAX),
            reserve_bytes: capacity.map_or(0, |c| c / RESERVE_DIVISOR),
        }
    }

    fn fits(&self, held: u64, available: u64) -> bool {
        held <= self.max_bytes && available >= self.reserve_bytes
    }
}

/// Checkpoints to forget, least recently used first, until the store fits
/// `budget`: `held` is what its objects occupy, `available` what the
/// filesystem has free, and `reclaims` what forgetting an entry would free.
/// Kept entries and those used within the grace period stay.
pub fn over_budget(
    entries: &[Entry],
    held: u64,
    available: u64,
    budget: Budget,
    policy: &Policy,
    now: SystemTime,
    mut reclaims: impl FnMut(&Entry) -> u64,
) -> Vec<usize> {
    let (mut held, mut available) = (held, available);
    if budget.fits(held, available) {
        return Vec::new();
    }
    let mut candidates: Vec<usize> = (0..entries.len())
        .filter(|&index| !entries[index].keep && idle(&entries[index], now) >= policy.grace)
        .collect();
    candidates.sort_by_key(|&index| entries[index].last_used);
    let mut chosen = Vec::new();
    for index in candidates {
        if budget.fits(held, available) {
            break;
        }
        let bytes = reclaims(&entries[index]);
        held = held.saturating_sub(bytes);
        available = available.saturating_add(bytes);
        chosen.push(index);
    }
    chosen
}

// ---------------------------------------------------------------------------
// A run

fn modified(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path)
        .and_then(|meta| meta.modified())
        .ok()
}

/// The published checkpoints in `store`, and the ids of lineage records whose
/// directory is gone.
fn scan(store: &Path, keep: &Keep) -> io::Result<(Vec<Entry>, Vec<String>)> {
    let mut by_dir: HashMap<OsString, String> = HashMap::new();
    let mut dangling = Vec::new();
    for record in store::list_lineage(store)? {
        match record_dir(store, &record) {
            Some(dir) if published_dir(store).join(&dir).is_dir() => {
                by_dir.insert(dir, record.id);
            }
            _ => dangling.push(record.id),
        }
    }
    let mut entries = Vec::new();
    let listing = match std::fs::read_dir(published_dir(store)) {
        Ok(listing) => listing,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok((entries, dangling)),
        Err(error) => return Err(error),
    };
    for item in listing {
        let item = item?;
        let dir = item.file_name();
        if dir.to_string_lossy().starts_with('.') || !item.file_type()?.is_dir() {
            continue;
        }
        let id = by_dir.get(&dir).cloned().or_else(|| {
            // An import publishes under the id; one whose record was lost.
            dir.to_str()
                .and_then(|name| name.strip_suffix(".checkpoint"))
                .filter(|id| store::is_checkpoint_id(id))
                .map(str::to_string)
        });
        let path = item.path();
        let last_used = [
            modified(&path.join("checkpoint.json")),
            modified(&path),
            id.as_deref().and_then(|id| last_pinned(store, id)),
        ]
        .into_iter()
        .flatten()
        .max()
        .unwrap_or(SystemTime::UNIX_EPOCH);
        entries.push(Entry {
            keep: keep.keeps(id.as_deref(), Some(&dir)),
            requested: id.as_deref().is_some_and(|id| forget_requested(store, id)),
            dir,
            id,
            last_used,
        });
    }
    Ok((entries, dangling))
}

/// Remove what earlier runs and interrupted imports left: the trash, and
/// import staging older than a day.
fn sweep_leftovers(store: &Path) {
    if let Ok(listing) = std::fs::read_dir(store.join(TRASH)) {
        for item in listing.flatten() {
            let _ = std::fs::remove_dir_all(item.path());
        }
    }
    let now = SystemTime::now();
    if let Ok(listing) = std::fs::read_dir(store.join("staging")) {
        for item in listing.flatten() {
            let stale = item.file_name().to_string_lossy().starts_with(".import-")
                && modified(&item.path())
                    .is_some_and(|at| now.duration_since(at).unwrap_or_default() >= STALE_STAGING);
            if stale {
                let _ = std::fs::remove_dir_all(item.path());
            }
        }
    }
}

/// Drop forget requests and pins of ids the store no longer holds, once they
/// have been idle a day: a pin is only a lock and a use time, and a forget
/// asked for while an id was in use but never stored has nothing to finish.
fn sweep_stale_ids(store: &Path, held: &HashSet<&str>) {
    let now = SystemTime::now();
    for kind in [FORGET, PINS] {
        let Ok(listing) = std::fs::read_dir(store.join(kind)) else {
            continue;
        };
        for item in listing.flatten() {
            let name = item.file_name();
            let Some(id) = name.to_str() else { continue };
            let stale = modified(&item.path())
                .is_some_and(|at| now.duration_since(at).unwrap_or_default() >= STALE_STAGING);
            if held.contains(id) || !stale {
                continue;
            }
            if kind == PINS {
                // Only a pin nothing holds.
                if let Ok(Some((claim, path))) = try_claim(store, id) {
                    let _ = std::fs::remove_file(&path);
                    drop(claim);
                }
            } else {
                let _ = std::fs::remove_file(item.path());
            }
        }
    }
}

/// What one [`run`] did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    /// Published checkpoints before the run.
    pub checkpoints: usize,
    /// Checkpoints forgotten.
    pub forgotten: usize,
    /// Checkpoints chosen but in use, left for a later run.
    pub in_use: usize,
    /// Checkpoints kept because a machine here continues from them.
    pub kept: usize,
    /// Objects reclaimed.
    pub reclaimed_objects: u64,
    /// Disk space reclaimed.
    pub reclaimed_bytes: u64,
    /// Disk space the store's objects occupy after the run.
    pub held_bytes: u64,
}

fn forget_entry(store: &Path, entry: &Entry, keep: &Keep, report: &mut Report) -> io::Result<()> {
    let outcome = match entry.id.as_deref() {
        Some(id) => forget_inner(store, id, keep, false)?,
        // No id: nothing can look it up, and it is past its grace.
        None => {
            if discard(store, &entry.dir)? {
                Forgotten::Removed
            } else {
                Forgotten::Absent
            }
        }
    };
    match outcome {
        Forgotten::Removed => report.forgotten += 1,
        Forgotten::Deferred => report.in_use += 1,
        Forgotten::Absent => {}
    }
    Ok(())
}

/// Bring `store` within `policy`, keeping what `keep` names. Safe alongside
/// captures, imports and restores, in this process or another.
pub fn run(store: &Path, keep: &Keep, policy: &Policy) -> io::Result<Report> {
    let mut report = Report::default();
    if !store.is_dir() {
        return Ok(report);
    }
    sweep_leftovers(store);
    let now = SystemTime::now();
    let (entries, dangling) = scan(store, keep)?;
    report.checkpoints = entries.len();
    report.kept = entries.iter().filter(|entry| entry.keep).count();
    for id in &dangling {
        // Nothing to reclaim, but a record of nothing misleads a capture.
        forget_inner(store, id, keep, false)?;
    }
    let held: HashSet<&str> = entries
        .iter()
        .filter_map(|entry| entry.id.as_deref())
        .collect();
    sweep_stale_ids(store, &held);
    let mut gone: HashSet<usize> = HashSet::new();
    for index in expired(&entries, policy, now) {
        forget_entry(store, &entries[index], keep, &mut report)?;
        gone.insert(index);
    }
    let mut pruned = store::prune_in_batches(store, PRUNE_BATCH)?;
    report.reclaimed_objects += pruned.removed_objects;
    report.reclaimed_bytes += pruned.removed_bytes;
    let space = crate::api::cache_base_budget::filesystem_space(store);
    let budget = Budget::for_capacity(space.map(|(capacity, _)| capacity), policy.max_bytes);
    let available = space.map_or(u64::MAX, |(_, available)| available);
    let remaining: Vec<Entry> = entries
        .iter()
        .enumerate()
        .filter(|(index, _)| !gone.contains(index))
        .map(|(_, entry)| entry.clone())
        .collect();
    let chosen = over_budget(
        &remaining,
        pruned.kept_bytes,
        available,
        budget,
        policy,
        now,
        |entry| {
            store::exclusive_objects(&published_dir(store).join(&entry.dir))
                .map(|(_, bytes)| bytes)
                .unwrap_or(0)
        },
    );
    if !chosen.is_empty() {
        for index in chosen {
            forget_entry(store, &remaining[index], keep, &mut report)?;
        }
        pruned = store::prune_in_batches(store, PRUNE_BATCH)?;
        report.reclaimed_objects += pruned.removed_objects;
        report.reclaimed_bytes += pruned.removed_bytes;
    }
    report.held_bytes = pruned.kept_bytes;
    if !budget.fits(
        report.held_bytes,
        available.saturating_add(report.reclaimed_bytes),
    ) {
        tracing::warn!(
            held_bytes = report.held_bytes,
            max_bytes = budget.max_bytes,
            kept = report.kept,
            in_use = report.in_use,
            "checkpoint store is over budget with nothing left it may remove"
        );
    }
    Ok(report)
}

// ---------------------------------------------------------------------------
// Background

struct Trigger {
    requested: std::sync::Mutex<bool>,
    wake: std::sync::Condvar,
}

static TRIGGER: Trigger = Trigger {
    requested: std::sync::Mutex::new(false),
    wake: std::sync::Condvar::new(),
};

/// Ask the background task to run soon, as after a capture. A no-op when no
/// background task runs, as in the CLI.
pub fn request() {
    let mut requested = TRIGGER
        .requested
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    *requested = true;
    TRIGGER.wake.notify_one();
}

fn run_and_log(db: &crate::db::SmolvmDb, store: &Path, policy: &Policy) {
    let started = std::time::Instant::now();
    let keep = match Keep::from_db(db, store) {
        Ok(keep) => keep,
        Err(error) => {
            tracing::warn!(%error, "checkpoint retention: could not list machines; removing nothing");
            return;
        }
    };
    match run(store, &keep, policy) {
        Ok(report) => {
            STORE_BYTES.store(report.held_bytes, Ordering::Relaxed);
            metrics::gauge!("smolvm_checkpoint_store_bytes").set(report.held_bytes as f64);
            metrics::gauge!("smolvm_checkpoint_store_checkpoints")
                .set(report.checkpoints.saturating_sub(report.forgotten) as f64);
            metrics::counter!("smolvm_checkpoint_store_forgotten_total")
                .increment(report.forgotten as u64);
            metrics::counter!("smolvm_checkpoint_store_reclaimed_bytes_total")
                .increment(report.reclaimed_bytes);
            let fields = (
                report.checkpoints,
                report.forgotten,
                report.in_use,
                report.kept,
                report.reclaimed_objects,
                report.reclaimed_bytes,
                report.held_bytes,
                started.elapsed().as_millis() as u64,
            );
            if report.forgotten > 0 || report.reclaimed_objects > 0 {
                tracing::info!(
                    checkpoints = fields.0,
                    forgotten = fields.1,
                    in_use = fields.2,
                    kept = fields.3,
                    reclaimed_objects = fields.4,
                    reclaimed_bytes = fields.5,
                    held_bytes = fields.6,
                    elapsed_ms = fields.7,
                    "checkpoint store retention reclaimed space"
                );
            } else {
                tracing::debug!(
                    checkpoints = fields.0,
                    held_bytes = fields.6,
                    elapsed_ms = fields.7,
                    "checkpoint store retention: nothing to reclaim"
                );
            }
        }
        Err(error) => tracing::warn!(%error, "checkpoint store retention failed"),
    }
}

/// Run retention on the node store now and then on every [`request`], at most
/// once a minute, and hourly regardless, on a thread of its own. Does nothing
/// when the environment turns retention off.
pub fn start_background(db: crate::db::SmolvmDb) {
    let Some(policy) = Policy::from_env() else {
        tracing::info!("checkpoint store retention is off");
        return;
    };
    tracing::info!(?policy, "checkpoint store retention on");
    let spawned = std::thread::Builder::new()
        .name("checkpoint-retention".into())
        .spawn(move || {
            let store = crate::checkpoint_delta::node_store();
            loop {
                let started = std::time::Instant::now();
                run_and_log(&db, &store, &policy);
                if let Some(rest) = MIN_RUN_GAP.checked_sub(started.elapsed()) {
                    std::thread::sleep(rest);
                }
                let mut requested = TRIGGER
                    .requested
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                let deadline = std::time::Instant::now() + RUN_INTERVAL;
                while !*requested {
                    let Some(left) = deadline.checked_duration_since(std::time::Instant::now())
                    else {
                        break;
                    };
                    requested = TRIGGER
                        .wake
                        .wait_timeout(requested, left)
                        .unwrap_or_else(|error| error.into_inner())
                        .0;
                }
                *requested = false;
            }
        });
    if let Err(error) = spawned {
        tracing::warn!(%error, "could not start checkpoint store retention");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1 << 30;

    fn entry(dir: &str, idle_min: u64, now: SystemTime) -> Entry {
        Entry {
            dir: dir.into(),
            id: Some(dir.into()),
            last_used: now - Duration::from_secs(idle_min * 60),
            keep: false,
            requested: false,
        }
    }

    fn names(entries: &[Entry], chosen: Vec<usize>) -> Vec<String> {
        chosen
            .into_iter()
            .map(|index| entries[index].dir.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn age_expires_only_unkept_idle_checkpoints() {
        let now = SystemTime::now();
        let policy = Policy::default();
        let mut entries = vec![
            entry("old", 25 * 60, now),
            entry("young", 60, now),
            entry("old-head", 48 * 60, now),
            entry("asked", 1, now),
            entry("asked-head", 1, now),
        ];
        entries[2].keep = true;
        entries[3].requested = true;
        entries[4].requested = true;
        entries[4].keep = true;
        assert_eq!(
            names(&entries, expired(&entries, &policy, now)),
            ["old", "asked"]
        );
        // No maximum age keeps everything not asked for.
        let unbounded = Policy {
            max_age: None,
            ..policy
        };
        assert_eq!(
            names(&entries, expired(&entries, &unbounded, now)),
            ["asked"]
        );
        // A maximum age below the grace period is raised to it.
        let short = Policy {
            max_age: Some(Duration::from_secs(60)),
            ..policy
        };
        assert_eq!(
            names(&entries, expired(&entries, &short, now)),
            ["old", "young", "asked"]
        );
    }

    #[test]
    fn over_budget_removes_least_recently_used_until_it_fits() {
        let now = SystemTime::now();
        let policy = Policy::default();
        let mut entries = vec![
            entry("newest", 40, now),
            entry("oldest", 900, now),
            entry("head", 2000, now),
            entry("middle", 300, now),
            entry("in-grace", 5, now),
        ];
        entries[2].keep = true;
        let budget = Budget::for_capacity(Some(400 * GIB), None);
        assert_eq!(budget.max_bytes, 100 * GIB);
        let sizes = |entry: &Entry| match entry.dir.to_str().unwrap() {
            "oldest" => 10 * GIB,
            _ => 30 * GIB,
        };
        // Fits: nothing goes.
        assert!(over_budget(&entries, 90 * GIB, 200 * GIB, budget, &policy, now, sizes).is_empty());
        // 130 GiB held: the oldest frees 10, the middle 30, and then it fits.
        assert_eq!(
            names(
                &entries,
                over_budget(&entries, 130 * GIB, 200 * GIB, budget, &policy, now, sizes)
            ),
            ["oldest", "middle"]
        );
        // Far over: everything but the head and the recently used goes.
        assert_eq!(
            names(
                &entries,
                over_budget(&entries, 1000 * GIB, 200 * GIB, budget, &policy, now, sizes)
            ),
            ["oldest", "middle", "newest"]
        );
        // A full filesystem frees space even within the byte budget.
        assert_eq!(
            names(
                &entries,
                over_budget(&entries, 10 * GIB, 5 * GIB, budget, &policy, now, sizes)
            ),
            ["oldest", "middle"]
        );
    }

    #[test]
    fn budget_defaults_to_a_quarter_and_honours_a_configured_maximum() {
        assert_eq!(
            Budget::for_capacity(Some(1000), None),
            Budget {
                max_bytes: 250,
                reserve_bytes: 100
            }
        );
        assert_eq!(Budget::for_capacity(Some(1000), Some(7)).max_bytes, 7);
        assert_eq!(Budget::for_capacity(None, None).max_bytes, u64::MAX);
    }

    #[test]
    fn keep_names_heads_and_directories_machines_were_created_from() {
        let root = tempfile::tempdir().unwrap();
        let store = root.path();
        std::fs::create_dir_all(published_dir(store)).unwrap();
        let mut head = crate::config::VmRecord::new("a".into(), 1, 512, vec![], vec![], false);
        head.checkpoint_head = Some("h".repeat(32));
        let mut created = crate::config::VmRecord::new("b".into(), 1, 512, vec![], vec![], false);
        created.source_smolmachine = Some(
            published_dir(store)
                .join("vm-1.checkpoint")
                .to_string_lossy()
                .into_owned(),
        );
        let mut elsewhere = crate::config::VmRecord::new("c".into(), 1, 512, vec![], vec![], false);
        elsewhere.source_smolmachine = Some("/srv/app.smolmachine".into());
        let keep = Keep::from_records([head, created, elsewhere], store);
        assert!(keep.ids.contains(&"h".repeat(32)));
        assert_eq!(keep.dirs.len(), 1);
        assert!(keep.keeps(None, Some(std::ffi::OsStr::new("vm-1.checkpoint"))));
        assert!(!keep.keeps(Some("x"), Some(std::ffi::OsStr::new("vm-2.checkpoint"))));
    }

    fn published(store: &Path, id: &str, dir: &str) {
        let path = published_dir(store).join(dir);
        std::fs::create_dir_all(path.join("objects")).unwrap();
        std::fs::write(path.join("checkpoint.json"), b"{}").unwrap();
        store::record_lineage(
            store,
            &store::LineageRecord {
                id: id.into(),
                parent: None,
                machine: "vm".into(),
                created_at: "2026-10-24T00:00:00Z".into(),
                path: path.to_string_lossy().into_owned(),
            },
        )
        .unwrap();
    }

    #[test]
    fn forget_skips_pinned_and_kept_checkpoints_and_finishes_later() {
        let root = tempfile::tempdir().unwrap();
        let store = root.path();
        let (pinned, head, plain) = ("1".repeat(32), "2".repeat(32), "3".repeat(32));
        published(store, &pinned, "vm-1.checkpoint");
        published(store, &head, "vm-2.checkpoint");
        published(store, &plain, "vm-3.checkpoint");
        let keep = Keep {
            ids: [head.clone()].into(),
            ..Default::default()
        };

        let held = pin(store, &pinned).unwrap().unwrap();
        assert_eq!(forget(store, &pinned, &keep).unwrap(), Forgotten::Deferred);
        assert_eq!(forget(store, &head, &keep).unwrap(), Forgotten::Deferred);
        assert_eq!(forget(store, &plain, &keep).unwrap(), Forgotten::Removed);
        assert_eq!(forget(store, &plain, &keep).unwrap(), Forgotten::Absent);
        assert_eq!(forget(store, "../x", &keep).unwrap(), Forgotten::Absent);
        assert!(published_dir(store).join("vm-1.checkpoint").is_dir());
        assert!(published_dir(store).join("vm-2.checkpoint").is_dir());
        assert!(!published_dir(store).join("vm-3.checkpoint").exists());
        assert!(store::find_lineage(store, &plain).unwrap().is_none());

        // A run with the pin still held leaves both; the head stays while kept.
        let report = run(store, &keep, &Policy::default()).unwrap();
        assert_eq!((report.forgotten, report.in_use, report.kept), (0, 1, 1));
        drop(held);
        let report = run(store, &keep, &Policy::default()).unwrap();
        assert_eq!(report.forgotten, 1);
        assert!(!published_dir(store).join("vm-1.checkpoint").exists());
        // The machine moved on: its old head goes too.
        let report = run(store, &Keep::default(), &Policy::default()).unwrap();
        assert_eq!(report.forgotten, 1);
        assert!(!published_dir(store).join("vm-2.checkpoint").exists());
        assert_eq!(std::fs::read_dir(store.join(TRASH)).unwrap().count(), 0);
    }

    #[test]
    fn a_pin_taken_after_a_forget_sees_the_checkpoint_gone() {
        let root = tempfile::tempdir().unwrap();
        let store = root.path();
        let id = "4".repeat(32);
        published(store, &id, "vm-4.checkpoint");
        drop(pin(store, &id).unwrap());
        assert_eq!(
            forget(store, &id, &Keep::default()).unwrap(),
            Forgotten::Removed
        );
        let _pin = pin(store, &id).unwrap().unwrap();
        assert!(store::find_lineage(store, &id).unwrap().is_none());
        // And while it is held, the id cannot be forgotten again.
        assert_eq!(
            forget(store, &id, &Keep::default()).unwrap(),
            Forgotten::Deferred
        );
    }

    /// Capture `bytes` into `store` as checkpoint `id`, a child of `parent`,
    /// the way a node capture publishes and records one.
    #[cfg(unix)]
    fn capture(store: &Path, id: &str, parent: Option<&str>, bytes: &[u8]) {
        let staging = store.join("staging").join(format!(".checkpoint-{id}"));
        std::fs::create_dir_all(&staging).unwrap();
        let mut writer = store::Writer::new(store, &staging).unwrap();
        let file = writer
            .ingest(
                "checkpoint/memory.bin",
                bytes.len() as u64,
                0o600,
                &mut &*bytes,
            )
            .unwrap();
        let manifest = smolvm_pack::format::PackManifest::new(
            "vm://test".into(),
            "none".into(),
            "linux/amd64".into(),
            "linux/amd64".into(),
        );
        writer.finish(&staging, manifest, vec![file]).unwrap();
        drop(writer);
        let output = published_dir(store).join(format!("vm-{id}.checkpoint"));
        std::fs::create_dir_all(published_dir(store)).unwrap();
        store::publish(&staging, &output).unwrap();
        store::record_lineage(
            store,
            &store::LineageRecord {
                id: id.into(),
                parent: parent.map(str::to_string),
                machine: "vm".into(),
                created_at: "2026-10-24T00:00:00Z".into(),
                path: output.to_string_lossy().into_owned(),
            },
        )
        .unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn forgetting_ancestors_reclaims_their_objects_and_the_head_still_restores() {
        const MIB: usize = 1 << 20;
        let root = tempfile::tempdir().unwrap();
        let store = root.path().join("store");
        // Three generations of one machine: each keeps the first MiB and
        // rewrites the rest.
        let generation = |n: u8| {
            let mut bytes = vec![9u8; MIB];
            bytes.extend(vec![n; 3 * MIB]);
            bytes
        };
        let ids: Vec<String> = (1..=3).map(|n: u8| n.to_string().repeat(32)).collect();
        capture(&store, &ids[0], None, &generation(1));
        capture(&store, &ids[1], Some(&ids[0]), &generation(2));
        capture(&store, &ids[2], Some(&ids[1]), &generation(3));
        let before = store::prune_in_batches(&store, 2).unwrap();
        assert_eq!(before.removed_objects, 0);
        assert_eq!(
            before.kept_objects, 4,
            "one shared chunk and three of each generation's"
        );

        // The machine continues from the newest; its ancestors age out.
        let keep = Keep {
            ids: [ids[2].clone()].into(),
            ..Default::default()
        };
        let policy = Policy {
            max_age: Some(Duration::from_secs(1)),
            grace: Duration::ZERO,
            max_bytes: None,
        };
        std::thread::sleep(Duration::from_millis(1100));
        let report = run(&store, &keep, &policy).unwrap();
        assert_eq!(
            (report.checkpoints, report.forgotten, report.kept),
            (3, 2, 1)
        );
        assert_eq!(report.reclaimed_objects, 2);
        assert!(report.reclaimed_bytes > 0);
        assert!(report.held_bytes < before.kept_bytes);
        assert_eq!(
            report.held_bytes + report.reclaimed_bytes,
            before.kept_bytes
        );
        assert!(store::find_lineage(&store, &ids[0]).unwrap().is_none());
        assert!(store::find_lineage(&store, &ids[1]).unwrap().is_none());

        // The head holds a link to every object it needs, the shared one too.
        let head = published_dir(&store).join(format!("vm-{}.checkpoint", ids[2]));
        assert!(store::missing_objects(&head).unwrap().is_empty());
        let restored = root.path().join("restored");
        store::materialize(&head, &restored).unwrap();
        assert_eq!(
            std::fs::read(restored.join("checkpoint/memory.bin")).unwrap(),
            generation(3)
        );
        // Over a tiny byte budget the head still stays.
        let tight = Policy {
            max_bytes: Some(1),
            ..policy
        };
        let report = run(&store, &keep, &tight).unwrap();
        assert_eq!(report.forgotten, 0);
        assert!(head.is_dir());
        // Once nothing continues from it, it goes too, and the store empties.
        let report = run(&store, &Keep::default(), &policy).unwrap();
        assert_eq!(report.forgotten, 1);
        assert_eq!(report.held_bytes, 0);
    }

    #[test]
    fn a_run_keeps_young_checkpoints_and_clears_dangling_records() {
        let root = tempfile::tempdir().unwrap();
        let store = root.path();
        let (young, dangling) = ("5".repeat(32), "6".repeat(32));
        published(store, &young, "vm-5.checkpoint");
        published(store, &dangling, "vm-6.checkpoint");
        std::fs::remove_dir_all(published_dir(store).join("vm-6.checkpoint")).unwrap();
        let policy = Policy {
            max_age: Some(Duration::from_secs(1)),
            ..Policy::default()
        };
        let report = run(store, &Keep::default(), &policy).unwrap();
        assert_eq!((report.checkpoints, report.forgotten), (1, 0));
        assert!(published_dir(store).join("vm-5.checkpoint").is_dir());
        assert!(store::find_lineage(store, &dangling).unwrap().is_none());
        assert!(store::find_lineage(store, &young).unwrap().is_some());
    }
}
