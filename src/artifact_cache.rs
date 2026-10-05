//! Reference-safe lifecycle management for Linux artifact caches.
//!
//! A machine created from a shared `.smolmachine` owns a small `.pack-shared`
//! pointer in its data directory. That pointer is the durable lease for both the
//! extracted shared pack and any immutable COW disk bases derived from it. The
//! cache-wide flock in this module serializes lease publication with pruning;
//! machine creation remains concurrent because publishers take a shared lock.

use crate::agent::{
    shared_pack_cache_root, shared_pack_pointer_path, vm_cache_root, SHARED_PACK_POINTER,
};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const CACHE_LOCK_FILENAME: &str = ".artifact-cache.lock";
static POINTER_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// A validated machine reference to one shared artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedPackLease {
    /// Canonical `_shared/<checksum>` directory used by the machine.
    pub shared_dir: PathBuf,
    /// Full SHA-256 used to key immutable COW disk bases.
    pub artifact_sha256: String,
}

/// One unused artifact selected by reference-aware cache pruning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactCachePruneEntry {
    /// Artifact SHA-256, or `shared:<checksum>` for an old unidentifiable entry.
    pub artifact: String,
    /// Cache directories removed, or that would be removed in a dry run.
    pub paths: Vec<PathBuf>,
    /// Real allocated bytes occupied by the entry, including sparse-file blocks.
    pub allocated_bytes: u64,
}

/// Result of one reference-aware artifact cache prune.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactCachePruneReport {
    /// Unused artifact entries removed, or selected by a dry run.
    pub entries: Vec<ArtifactCachePruneEntry>,
    /// Artifact entries retained because at least one machine references them.
    pub referenced_entries: usize,
}

struct ArtifactCacheLock(fs::File);

/// Keep pruning and another publisher out while replacing a verified cache file.
pub(crate) struct CheckpointEntryLock {
    _entry: ArtifactCacheLock,
    _cache: ArtifactCacheLock,
}

pub(crate) fn lock_checkpoint_entry(shared_dir: &Path) -> io::Result<Option<CheckpointEntryLock>> {
    lock_checkpoint_entry_in(&vm_cache_root(), &shared_pack_cache_root(), shared_dir)
}

fn lock_checkpoint_entry_in(
    vm_root: &Path,
    root: &Path,
    shared_dir: &Path,
) -> io::Result<Option<CheckpointEntryLock>> {
    if shared_dir.parent() != Some(root) {
        return Ok(None);
    }
    let cache = lock_artifact_cache(vm_root, false)?;
    let shared = canonical_shared_dir(shared_dir, root)?;
    for directory in [root, shared.as_path()] {
        let metadata = fs::symlink_metadata(directory)?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Ok(None);
        }
    }
    let entry = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(shared.with_extension("lock"))?;
    if unsafe { libc::flock(entry.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // A cache miss is not an invitation to create an unverified extraction.
    if !smolvm_pack::extract::is_extracted(&shared) {
        return Ok(None);
    }
    read_artifact_digest(&shared)?;
    Ok(Some(CheckpointEntryLock {
        _entry: ArtifactCacheLock(entry),
        _cache: cache,
    }))
}

impl Drop for ArtifactCacheLock {
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

fn lock_artifact_cache(vm_root: &Path, exclusive: bool) -> io::Result<ArtifactCacheLock> {
    let file = open_artifact_cache_lock(vm_root)?;
    let operation = if exclusive {
        libc::LOCK_EX
    } else {
        libc::LOCK_SH
    };
    if unsafe { libc::flock(file.as_raw_fd(), operation) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ArtifactCacheLock(file))
}

/// Exclusive cache lock, or `None` while anyone else holds the lock.
fn try_lock_artifact_cache_exclusive(vm_root: &Path) -> io::Result<Option<ArtifactCacheLock>> {
    let file = open_artifact_cache_lock(vm_root)?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::WouldBlock {
            return Ok(None);
        }
        return Err(error);
    }
    Ok(Some(ArtifactCacheLock(file)))
}

fn open_artifact_cache_lock(vm_root: &Path) -> io::Result<fs::File> {
    fs::create_dir_all(vm_root)?;
    let path = vm_root.join(CACHE_LOCK_FILENAME);
    let file = fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    // Do not trust an older umask or manually-created lock file.
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn canonical_shared_dir(shared_dir: &Path, shared_root: &Path) -> io::Result<PathBuf> {
    if !shared_dir.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "shared pack pointer is not absolute: {}",
                shared_dir.display()
            ),
        ));
    }
    validate_real_cache_root(shared_root)?;
    let original_metadata = fs::symlink_metadata(shared_dir)?;
    if !original_metadata.file_type().is_dir() || original_metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "shared pack target is not a real directory: {}",
                shared_dir.display()
            ),
        ));
    }
    let root = shared_root.canonicalize().map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "canonicalize shared pack root {}: {error}",
                shared_root.display()
            ),
        )
    })?;
    let shared = shared_dir.canonicalize().map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("canonicalize shared pack {}: {error}", shared_dir.display()),
        )
    })?;
    let valid_name = shared
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| is_lower_hex(name, 8));
    if shared.parent() != Some(root.as_path()) || !valid_name {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "shared pack pointer escapes the cache root: {}",
                shared_dir.display()
            ),
        ));
    }
    Ok(shared)
}

fn read_artifact_digest(shared_dir: &Path) -> io::Result<String> {
    let marker = smolvm_pack::extract::shared_artifact_sha256_path(shared_dir);
    let metadata = fs::symlink_metadata(&marker)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "artifact SHA marker is not a regular file: {}",
                marker.display()
            ),
        ));
    }
    smolvm_pack::extract::read_shared_artifact_sha256(shared_dir)
}

fn atomic_publish_pointer(pointer: &Path, shared_dir: &Path) -> io::Result<()> {
    let parent = pointer.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("shared pack pointer has no parent: {}", pointer.display()),
        )
    })?;
    fs::create_dir_all(parent)?;
    let sequence = POINTER_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temp = parent.join(format!(
        ".{SHARED_PACK_POINTER}.tmp-{}-{sequence}",
        std::process::id()
    ));
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temp)?;
        writeln!(file, "{}", shared_dir.display())?;
        file.sync_all()?;
        fs::rename(&temp, pointer)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn read_lease_from_machine_dir(
    machine_dir: &Path,
    shared_root: &Path,
) -> io::Result<Option<SharedPackLease>> {
    let pointer = machine_dir.join(SHARED_PACK_POINTER);
    let metadata = match fs::symlink_metadata(&pointer) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "shared pack pointer is not a regular file: {}",
                pointer.display()
            ),
        ));
    }
    let raw = fs::read_to_string(&pointer)?;
    let target = raw.trim();
    if target.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("empty shared pack pointer: {}", pointer.display()),
        ));
    }
    let shared_dir = canonical_shared_dir(Path::new(target), shared_root)?;
    let artifact_sha256 = read_artifact_digest(&shared_dir)?;
    Ok(Some(SharedPackLease {
        shared_dir,
        artifact_sha256,
    }))
}

fn touch_lease(lease: &SharedPackLease) {
    let marker = smolvm_pack::extract::shared_artifact_sha256_path(&lease.shared_dir);
    if let Ok(file) = fs::OpenOptions::new().read(true).open(marker) {
        let _ = file.set_modified(SystemTime::now());
    }
}

/// Extract a shared pack and atomically publish the machine lease for it.
///
/// The lease is published while holding the cache's shared flock. An exclusive
/// prune therefore observes either no pointer and the pre-create cache state, or
/// the complete pointer plus its validated SHA marker—never the gap between them.
pub fn materialize_shared_pack_lease(
    sidecar_path: &Path,
    footer: &smolvm_pack::PackFooter,
    machine_layers_dir: &Path,
    debug: bool,
) -> io::Result<SharedPackLease> {
    materialize_shared_pack_lease_with_options(
        sidecar_path,
        footer,
        machine_layers_dir,
        debug,
        smolvm_pack::extract::SharedExtractOptions::default(),
    )
}

/// [`materialize_shared_pack_lease`] with the shortcuts a restore can take
/// (see [`smolvm_pack::extract::SharedExtractOptions`]).
pub fn materialize_shared_pack_lease_with_options(
    sidecar_path: &Path,
    footer: &smolvm_pack::PackFooter,
    machine_layers_dir: &Path,
    debug: bool,
    options: smolvm_pack::extract::SharedExtractOptions,
) -> io::Result<SharedPackLease> {
    let vm_root = vm_cache_root();
    let shared_root = shared_pack_cache_root();
    let _lock = lock_artifact_cache(&vm_root, false)?;
    let shared_dir = smolvm_pack::extract::extract_sidecar_shared_with_options(
        sidecar_path,
        &shared_root,
        footer,
        debug,
        options,
    )?;
    let shared_dir = canonical_shared_dir(&shared_dir, &shared_root)?;
    let artifact_sha256 = read_artifact_digest(&shared_dir)?;
    fs::create_dir_all(machine_layers_dir)?;
    atomic_publish_pointer(&shared_pack_pointer_path(machine_layers_dir), &shared_dir)?;
    let lease = SharedPackLease {
        shared_dir,
        artifact_sha256,
    };
    touch_lease(&lease);
    Ok(lease)
}

/// Publish capture-owned prepared state without racing explicit cache pruning.
pub fn retain_prepared_checkpoint(sidecar: &Path, prepared: &Path) -> io::Result<()> {
    retain_prepared_checkpoint_with_identity(sidecar, prepared, None)
}

/// Retain service-owned capture state with a digest produced by the packer.
pub fn retain_prepared_checkpoint_with_identity(
    sidecar: &Path,
    prepared: &Path,
    identity: Option<&smolvm_pack::packer::PackedArtifactIdentity>,
) -> io::Result<()> {
    let file = fs::symlink_metadata(sidecar)?;
    let parent = fs::metadata(
        sidecar
            .parent()
            .ok_or_else(|| io::Error::other("capture has no parent"))?,
    )?;
    if !file.is_file() || file.uid() != 0 || parent.uid() != 0 || parent.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "prepared retention requires a service-owned capture in a private directory",
        ));
    }
    let _lock = lock_artifact_cache(&vm_cache_root(), false)?;
    smolvm_pack::extract::retain_prepared_checkpoint_with_identity(
        sidecar,
        prepared,
        &shared_pack_cache_root(),
        identity,
    )
}

/// A prepared input pinned against cache pruning for the duration of import.
pub struct PreparedCheckpoint {
    /// Service-owned artifact retaining the capture's verified identity.
    pub path: PathBuf,
    _lock: ArtifactCacheLock,
}

/// Select prepared state only for the exact retained artifact, while excluding pruning.
pub fn open_prepared_checkpoint_for_sidecar(sidecar: &Path) -> io::Result<PreparedCheckpoint> {
    let lock = lock_artifact_cache(&vm_cache_root(), false)?;
    let reference = prepared_checkpoint_reference(sidecar)?;
    let key = reference
        .strip_prefix("checkpoint://")
        .expect("generated reference");
    let (crc, _) = key.split_once('-').expect("generated reference");
    let shared = shared_pack_cache_root().join(crc);
    if !smolvm_pack::extract::is_extracted(&shared) {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "prepared checkpoint unavailable",
        ));
    }
    Ok(PreparedCheckpoint {
        path: shared.with_extension("prepared.smolcheckpoint"),
        _lock: lock,
    })
}

/// Return the node-local reference for a retained capture, if still available.
pub fn prepared_checkpoint_reference(sidecar: &Path) -> io::Result<String> {
    let footer =
        smolvm_pack::packer::read_footer_from_sidecar(sidecar).map_err(io::Error::other)?;
    let shared = smolvm_pack::extract::shared_pack_dir(&shared_pack_cache_root(), footer.checksum);
    let digest = read_artifact_digest(&shared)?;
    let source = fs::metadata(sidecar)?;
    let retained = fs::metadata(shared.with_extension("prepared.smolcheckpoint"))?;
    if !retained.is_file() || source.dev() != retained.dev() || source.ino() != retained.ino() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "this capture has no retained prepared checkpoint",
        ));
    }
    Ok(format!("checkpoint://{:08x}-{digest}", footer.checksum))
}

/// Publish a cache alias while preserving verified local capture provenance.
pub fn link_checkpoint_artifact(
    source: &Path,
    destination: &Path,
    replace: bool,
) -> io::Result<()> {
    smolvm_pack::extract::link_checkpoint_artifact(
        source,
        destination,
        &shared_pack_cache_root(),
        replace,
    )
}

/// Finish a private transfer alias; stale identities retain full verification.
pub fn release_checkpoint_artifact_alias(artifact: &Path) {
    #[cfg(target_os = "linux")]
    let _ = smolvm_pack::extract::release_checkpoint_artifact_alias(
        artifact,
        &shared_pack_cache_root(),
    );
    #[cfg(not(target_os = "linux"))]
    let _ = artifact;
}

/// Pin a node-local capture through import so pruning cannot remove its inputs.
pub fn open_prepared_checkpoint(reference: &str) -> io::Result<PreparedCheckpoint> {
    let key = reference.strip_prefix("checkpoint://").unwrap_or("");
    let (crc, digest) = key.split_once('-').unwrap_or(("", ""));
    if crc.len() != 8
        || digest.len() != 64
        || !crc
            .bytes()
            .chain(digest.bytes())
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid prepared checkpoint reference",
        ));
    }
    let lock = lock_artifact_cache(&vm_cache_root(), false)?;
    let shared = shared_pack_cache_root().join(crc);
    if read_artifact_digest(&shared)? != digest {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "prepared checkpoint identity mismatch",
        ));
    }
    let path = shared.with_extension("prepared.smolcheckpoint");
    if !path.is_file() || !smolvm_pack::extract::is_extracted(&shared) {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "prepared checkpoint evicted; use the durable artifact",
        ));
    }
    Ok(PreparedCheckpoint { path, _lock: lock })
}

/// Copy a golden machine's shared artifact lease to a fork clone atomically.
///
/// Returns `None` when the golden uses a private extraction rather than the
/// Linux shared store. A malformed existing pointer is an error, not a fallback.
pub fn copy_shared_pack_lease(
    golden_layers_dir: &Path,
    clone_layers_dir: &Path,
) -> io::Result<Option<SharedPackLease>> {
    let vm_root = vm_cache_root();
    let shared_root = shared_pack_cache_root();
    copy_shared_pack_lease_in(&vm_root, &shared_root, golden_layers_dir, clone_layers_dir)
}

fn copy_shared_pack_lease_in(
    vm_root: &Path,
    shared_root: &Path,
    golden_layers_dir: &Path,
    clone_layers_dir: &Path,
) -> io::Result<Option<SharedPackLease>> {
    let _lock = lock_artifact_cache(vm_root, false)?;
    let golden_machine_dir = golden_layers_dir.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "golden pack dir has no parent")
    })?;
    let Some(lease) = read_lease_from_machine_dir(golden_machine_dir, shared_root)? else {
        return Ok(None);
    };
    fs::create_dir_all(clone_layers_dir)?;
    atomic_publish_pointer(
        &shared_pack_pointer_path(clone_layers_dir),
        &lease.shared_dir,
    )?;
    touch_lease(&lease);
    Ok(Some(lease))
}

pub(crate) fn validate_cow_lease(
    machine_dir: &Path,
    shared_dir: &Path,
    artifact_sha256: &str,
) -> io::Result<()> {
    validate_cow_lease_in(
        machine_dir,
        shared_dir,
        artifact_sha256,
        &shared_pack_cache_root(),
    )
}

fn validate_cow_lease_in(
    machine_dir: &Path,
    shared_dir: &Path,
    artifact_sha256: &str,
    shared_root: &Path,
) -> io::Result<()> {
    let lease = read_lease_from_machine_dir(machine_dir, shared_root)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "COW disk creation requires {}",
                machine_dir.join(SHARED_PACK_POINTER).display()
            ),
        )
    })?;
    let expected_shared = shared_dir.canonicalize()?;
    if lease.shared_dir != expected_shared || lease.artifact_sha256 != artifact_sha256 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "COW artifact does not match the machine's shared pack lease",
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct CacheCandidate {
    artifact: String,
    digest: Option<String>,
    shared_dirs: Vec<PathBuf>,
    cow_dirs: Vec<PathBuf>,
    metadata_files: Vec<PathBuf>,
    modified: SystemTime,
    allocated_bytes: u64,
}

impl CacheCandidate {
    fn new(artifact: String, digest: Option<String>) -> Self {
        Self {
            artifact,
            digest,
            shared_dirs: Vec::new(),
            cow_dirs: Vec::new(),
            metadata_files: Vec::new(),
            modified: UNIX_EPOCH,
            allocated_bytes: 0,
        }
    }

    fn visible_paths(&self) -> Vec<PathBuf> {
        self.shared_dirs
            .iter()
            .chain(self.cow_dirs.iter())
            .cloned()
            .collect()
    }
}

fn is_vm_dir_name(name: &str) -> bool {
    is_lower_hex(name, 16)
}

fn collect_machine_leases(
    vm_root: &Path,
    shared_root: &Path,
) -> io::Result<(HashSet<String>, HashSet<PathBuf>)> {
    let mut digests = HashSet::new();
    let mut shared_dirs = HashSet::new();
    let entries = match fs::read_dir(vm_root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok((digests, shared_dirs));
        }
        Err(error) => return Err(error),
    };
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !is_vm_dir_name(name) {
            continue;
        }
        let file_type = entry.file_type()?;
        if !file_type.is_dir() || file_type.is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "VM cache entry is not a real directory: {}",
                    entry.path().display()
                ),
            ));
        }
        if let Some(lease) = read_lease_from_machine_dir(&entry.path(), shared_root)? {
            digests.insert(lease.artifact_sha256);
            shared_dirs.insert(lease.shared_dir);
        }
    }
    Ok((digests, shared_dirs))
}

fn metadata_paths_for_shared(shared_dir: &Path) -> Vec<PathBuf> {
    let digest = smolvm_pack::extract::shared_artifact_sha256_path(shared_dir);
    vec![
        shared_dir.with_extension("lock"),
        digest.clone(),
        digest.with_extension("artifact-sha256.lock"),
        shared_dir.with_extension("artifact-source.json"),
        shared_dir.with_extension("prepared.smolcheckpoint"),
        smolvm_pack::extract::unsynced_marker_path(shared_dir),
    ]
}

/// Whether a restore in this boot is still writing `shared_dir`'s RAM back to
/// disk. A marker left by an earlier boot only means the data is suspect, and
/// such an extraction is extracted again on its next use, so it may go.
fn write_back_in_progress(shared_dir: &Path) -> bool {
    let marker = smolvm_pack::extract::unsynced_marker_path(shared_dir);
    marker.exists() && !smolvm_pack::extract::unsynced_before_this_boot(&marker)
}

fn allocated_usage(path: &Path) -> io::Result<u64> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    };
    let mut bytes = metadata.blocks().saturating_mul(512);
    if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
        for entry in fs::read_dir(path)? {
            bytes = bytes.saturating_add(allocated_usage(&entry?.path())?);
        }
    }
    Ok(bytes)
}

fn path_modified(path: &Path) -> io::Result<SystemTime> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.modified().unwrap_or(UNIX_EPOCH)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(UNIX_EPOCH),
        Err(error) => Err(error),
    }
}

fn add_candidate_path(candidate: &mut CacheCandidate, path: &Path) -> io::Result<()> {
    candidate.allocated_bytes = candidate
        .allocated_bytes
        .saturating_add(allocated_usage(path)?);
    candidate.modified = candidate.modified.max(path_modified(path)?);
    Ok(())
}

fn inventory_candidates(
    shared_root: &Path,
    cow_root: &Path,
    referenced_shared: &HashSet<PathBuf>,
) -> io::Result<HashMap<String, CacheCandidate>> {
    let mut candidates = HashMap::<String, CacheCandidate>::new();

    if shared_root.exists() {
        validate_real_cache_root(shared_root)?;
        for entry in fs::read_dir(shared_root)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if !is_lower_hex(name, 8) {
                continue;
            }
            let file_type = entry.file_type()?;
            if !file_type.is_dir() || file_type.is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "shared cache candidate is not a real directory: {}",
                        entry.path().display()
                    ),
                ));
            }
            let shared_dir = entry.path().canonicalize()?;
            let digest_result = read_artifact_digest(&shared_dir);
            let (key, digest) = match digest_result {
                Ok(digest) => (digest.clone(), Some(digest)),
                Err(error) if !referenced_shared.contains(&shared_dir) => {
                    tracing::warn!(
                        path = %shared_dir.display(),
                        error = %error,
                        "unreferenced legacy shared cache has no valid artifact SHA"
                    );
                    (format!("shared:{name}"), None)
                }
                Err(error) => return Err(error),
            };
            let candidate = candidates
                .entry(key.clone())
                .or_insert_with(|| CacheCandidate::new(key, digest));
            add_candidate_path(candidate, &shared_dir)?;
            candidate.shared_dirs.push(shared_dir.clone());
            for metadata_path in metadata_paths_for_shared(&shared_dir) {
                add_candidate_path(candidate, &metadata_path)?;
                candidate.metadata_files.push(metadata_path);
            }
        }
    }

    if cow_root.exists() {
        validate_real_cache_root(cow_root)?;
        for entry in fs::read_dir(cow_root)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if !is_lower_hex(name, 64) {
                continue;
            }
            let file_type = entry.file_type()?;
            if !file_type.is_dir() || file_type.is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "COW cache candidate is not a real directory: {}",
                        entry.path().display()
                    ),
                ));
            }
            let digest = name.to_string();
            let cow_dir = entry.path();
            let candidate = candidates
                .entry(digest.clone())
                .or_insert_with(|| CacheCandidate::new(digest.clone(), Some(digest.clone())));
            add_candidate_path(candidate, &cow_dir)?;
            candidate.cow_dirs.push(cow_dir);
        }
    }
    Ok(candidates)
}

fn validate_real_cache_root(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "artifact cache root is not a real directory: {}",
            path.display()
        ),
    ))
}

fn make_tree_owner_writable(path: &Path) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() {
        // `remove_dir_all` unlinks an in-tree symlink rather than traversing it.
        // Do not chmod or recurse through artifact-owned links.
        return Ok(());
    }
    if metadata.file_type().is_dir() {
        let mode = metadata.permissions().mode();
        fs::set_permissions(path, fs::Permissions::from_mode(mode | 0o700))?;
        for entry in fs::read_dir(path)? {
            make_tree_owner_writable(&entry?.path())?;
        }
    }
    Ok(())
}

fn remove_candidate(candidate: &CacheCandidate) -> io::Result<()> {
    for path in &candidate.cow_dirs {
        make_tree_owner_writable(path)?;
        fs::remove_dir_all(path)?;
    }
    for path in &candidate.shared_dirs {
        smolvm_pack::extract::force_detach_layers_volume(path);
        make_tree_owner_writable(path)?;
        fs::remove_dir_all(path)?;
    }
    for path in &candidate.metadata_files {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn prune_artifact_caches_in(
    vm_root: &Path,
    keep: usize,
    dry_run: bool,
) -> io::Result<ArtifactCachePruneReport> {
    let _lock = lock_artifact_cache(vm_root, true)?;
    let shared_root = vm_root.join("_shared");
    let cow_root = vm_root.join("_cow-bases");
    let (referenced_digests, referenced_shared) = collect_machine_leases(vm_root, &shared_root)?;
    // Finish the complete reference scan and candidate inventory before the
    // first mutation. Any malformed live pointer therefore fails closed.
    let candidates = inventory_candidates(&shared_root, &cow_root, &referenced_shared)?;
    let mut referenced_entries = 0usize;
    let mut unused = Vec::new();
    for candidate in candidates.into_values() {
        let referenced = candidate
            .digest
            .as_ref()
            .is_some_and(|digest| referenced_digests.contains(digest))
            || candidate
                .shared_dirs
                .iter()
                .any(|path| referenced_shared.contains(path));
        if referenced {
            referenced_entries += 1;
        } else {
            unused.push(candidate);
        }
    }
    unused.sort_by(|left, right| {
        right
            .modified
            .cmp(&left.modified)
            .then_with(|| left.artifact.cmp(&right.artifact))
    });

    let mut entries = Vec::new();
    for candidate in unused.into_iter().skip(keep) {
        if !dry_run {
            remove_candidate(&candidate)?;
        }
        entries.push(ArtifactCachePruneEntry {
            artifact: candidate.artifact.clone(),
            paths: candidate.visible_paths(),
            allocated_bytes: candidate.allocated_bytes,
        });
    }
    Ok(ArtifactCachePruneReport {
        entries,
        referenced_entries,
    })
}

/// Prune unreferenced Linux shared-pack and immutable COW-base caches.
///
/// `keep` applies only to unused artifacts; every artifact referenced by a
/// machine lease is retained in addition to that count. With `dry_run`, the
/// returned report describes the selection without changing the filesystem.
pub fn prune_artifact_caches(keep: usize, dry_run: bool) -> io::Result<ArtifactCachePruneReport> {
    prune_artifact_caches_in(&vm_cache_root(), keep, dry_run)
}

/// Bound the shared extractions no machine leases any more.
///
/// A restore extracts its checkpoint into the shared store, links what the
/// machine needs into the machine's own directory, and then drops the lease, so
/// nothing ever referenced the extraction again: every restored checkpoint
/// stayed on disk after its machines were deleted. The most recently used
/// extractions are worth keeping, because restoring the same checkpoint again
/// reuses one without extracting it, so this keeps those the restore cache
/// policy allows ([`crate::portable_checkpoint::RestoreCache`]) and removes the
/// rest. Prepared captures keep their own budget and are left alone.
///
/// Never waits: when another process holds the cache lock (an extraction in
/// progress), it returns `None` and a later call trims instead.
pub fn trim_unleased_shared_packs() -> io::Result<Option<ArtifactCachePruneReport>> {
    let policy = crate::portable_checkpoint::RestoreCache::default();
    trim_unleased_shared_packs_in(&vm_cache_root(), policy.entries, policy.max_bytes)
}

/// [`trim_unleased_shared_packs`] on a background thread, for request paths
/// that must not wait on removing gigabytes.
pub fn trim_unleased_shared_packs_soon() {
    let spawned = std::thread::Builder::new()
        .name("shared-pack-trim".into())
        .spawn(|| log_trim(trim_unleased_shared_packs()));
    if let Err(error) = spawned {
        tracing::warn!(%error, "could not start shared extraction trim");
    }
}

/// Log what a trim removed, or why it could not run.
pub fn log_trim(result: io::Result<Option<ArtifactCachePruneReport>>) {
    match result {
        Ok(Some(report)) if !report.entries.is_empty() => tracing::info!(
            removed = report.entries.len(),
            bytes = report
                .entries
                .iter()
                .map(|entry| entry.allocated_bytes)
                .sum::<u64>(),
            "trimmed unleased shared extractions"
        ),
        Ok(_) => {}
        Err(error) => tracing::warn!(%error, "could not trim unleased shared extractions"),
    }
}

fn trim_unleased_shared_packs_in(
    vm_root: &Path,
    keep: usize,
    max_bytes: u64,
) -> io::Result<Option<ArtifactCachePruneReport>> {
    let Some(_lock) = try_lock_artifact_cache_exclusive(vm_root)? else {
        return Ok(None);
    };
    let shared_root = vm_root.join("_shared");
    let (referenced_digests, referenced_shared) = collect_machine_leases(vm_root, &shared_root)?;
    let candidates = inventory_candidates(
        &shared_root,
        &vm_root.join("_cow-bases"),
        &referenced_shared,
    )?;
    let mut referenced_entries = 0usize;
    let mut unleased = Vec::new();
    for candidate in candidates.into_values() {
        let referenced = candidate
            .digest
            .as_ref()
            .is_some_and(|digest| referenced_digests.contains(digest))
            || candidate
                .shared_dirs
                .iter()
                .any(|path| referenced_shared.contains(path));
        let prepared = candidate
            .shared_dirs
            .iter()
            .any(|dir| dir.with_extension("prepared.smolcheckpoint").is_file());
        let writing_back = candidate
            .shared_dirs
            .iter()
            .any(|dir| write_back_in_progress(dir));
        if referenced {
            referenced_entries += 1;
        } else if !prepared && !writing_back {
            unleased.push(candidate);
        }
    }
    unleased.sort_by(|left, right| {
        right
            .modified
            .cmp(&left.modified)
            .then_with(|| left.artifact.cmp(&right.artifact))
    });
    let mut kept = 0usize;
    let mut kept_bytes = 0u64;
    let mut entries = Vec::new();
    for candidate in unleased {
        // Count only what removal frees: RAM still linked into a live restored
        // machine costs the cache nothing until that machine is deleted.
        let mut bytes = 0u64;
        for path in candidate
            .visible_paths()
            .iter()
            .chain(candidate.metadata_files.iter())
        {
            bytes = bytes.saturating_add(unshared_usage(path)?);
        }
        if kept < keep && bytes <= max_bytes.saturating_sub(kept_bytes) {
            kept += 1;
            kept_bytes += bytes;
            continue;
        }
        remove_candidate(&candidate)?;
        entries.push(ArtifactCachePruneEntry {
            artifact: candidate.artifact.clone(),
            paths: candidate.visible_paths(),
            allocated_bytes: candidate.allocated_bytes,
        });
    }
    Ok(Some(ArtifactCachePruneReport {
        entries,
        referenced_entries,
    }))
}

/// Allocated bytes under `path` held only by this tree: a file also linked
/// elsewhere frees nothing when the tree is removed.
fn unshared_usage(path: &Path) -> io::Result<u64> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    };
    let own = metadata.blocks().saturating_mul(512);
    if metadata.file_type().is_dir() {
        let mut bytes = own;
        for entry in fs::read_dir(path)? {
            bytes = bytes.saturating_add(unshared_usage(&entry?.path())?);
        }
        return Ok(bytes);
    }
    Ok(if metadata.nlink() > 1 { 0 } else { own })
}

/// Bound unused prepared state without removing inputs leased by machines.
pub fn prune_prepared_checkpoints(max_bytes: u64) -> io::Result<()> {
    prune_prepared_checkpoints_in(&vm_cache_root(), max_bytes)
}

fn prune_prepared_checkpoints_in(vm_root: &Path, max_bytes: u64) -> io::Result<()> {
    let _lock = lock_artifact_cache(vm_root, true)?;
    let shared = vm_root.join("_shared");
    let (digests, leases) = collect_machine_leases(vm_root, &shared)?;
    // Interrupted publication may leave metadata without a prepared tree.
    // The exclusive cache lock excludes captures and imports while reclaiming it.
    if shared.exists() {
        validate_real_cache_root(&shared)?;
        for entry in fs::read_dir(&shared)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(crc) = name
                .to_str()
                .and_then(|name| name.strip_suffix(".prepared.smolcheckpoint"))
            else {
                continue;
            };
            if is_lower_hex(crc, 8) && !shared.join(crc).exists() {
                for path in metadata_paths_for_shared(&shared.join(crc)) {
                    match fs::remove_file(path) {
                        Ok(()) => {}
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                        Err(error) => return Err(error),
                    }
                }
            }
        }
    }
    let candidates = inventory_candidates(&shared, &vm_root.join("_cow-bases"), &leases)?;
    let mut unused: Vec<_> = candidates
        .into_values()
        .filter(|candidate| {
            candidate
                .shared_dirs
                .iter()
                .any(|dir| dir.with_extension("prepared.smolcheckpoint").is_file())
                && !candidate
                    .digest
                    .as_ref()
                    .is_some_and(|digest| digests.contains(digest))
                && !candidate.shared_dirs.iter().any(|dir| leases.contains(dir))
        })
        .collect();
    unused.sort_by(|a, b| {
        b.modified
            .cmp(&a.modified)
            .then_with(|| a.artifact.cmp(&b.artifact))
    });
    let mut retained = 0_u64;
    for candidate in unused {
        if candidate.allocated_bytes <= max_bytes.saturating_sub(retained) {
            retained = retained.saturating_add(candidate.allocated_bytes);
        } else {
            remove_candidate(&candidate)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn machine_dir(root: &Path, suffix: &str) -> PathBuf {
        root.join(format!("00000000000000{suffix}"))
    }

    fn install_artifact(root: &Path, checksum: &str, digest: &str) -> (PathBuf, PathBuf) {
        let shared = root.join("_shared").join(checksum);
        fs::create_dir_all(shared.join("layers")).unwrap();
        fs::write(shared.join("layers/data"), b"shared").unwrap();
        fs::write(
            smolvm_pack::extract::shared_artifact_sha256_path(&shared),
            format!("{digest}\n"),
        )
        .unwrap();
        let cow = root.join("_cow-bases").join(digest).join("overlay-4096");
        fs::create_dir_all(&cow).unwrap();
        fs::write(cow.join("base.raw"), b"base").unwrap();
        fs::set_permissions(&cow, fs::Permissions::from_mode(0o555)).unwrap();
        (shared, root.join("_cow-bases").join(digest))
    }

    fn publish_test_lease(machine: &Path, shared: &Path) {
        fs::create_dir_all(machine.join("pack")).unwrap();
        atomic_publish_pointer(&machine.join(SHARED_PACK_POINTER), shared).unwrap();
    }

    #[test]
    #[ignore = "requires root to exercise service-owned promotion cache"]
    fn promotion_serializes_publishers_and_excludes_pruning() {
        use std::sync::mpsc;
        use std::time::Duration;
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("vms");
        let (shared, _) = install_artifact(&root, "deadbeef", DIGEST_A);
        fs::write(shared.join(".smolvm-extracted"), b"done").unwrap();
        let held = lock_checkpoint_entry_in(&root, &root.join("_shared"), &shared)
            .unwrap()
            .unwrap();
        std::thread::scope(|scope| {
            let (publisher_entered, published) = mpsc::channel();
            let (pruner_entered, pruned) = mpsc::channel();
            let root = &root;
            let shared = &shared;
            scope.spawn(move || {
                let _guard = lock_checkpoint_entry_in(root, &root.join("_shared"), shared)
                    .unwrap()
                    .unwrap();
                publisher_entered.send(()).unwrap();
            });
            scope.spawn(move || {
                let _guard = lock_artifact_cache(root, true).unwrap();
                pruner_entered.send(()).unwrap();
            });
            assert!(published.recv_timeout(Duration::from_millis(100)).is_err());
            assert!(pruned.recv_timeout(Duration::from_millis(100)).is_err());
            drop(held);
            published.recv_timeout(Duration::from_secs(5)).unwrap();
            pruned.recv_timeout(Duration::from_secs(5)).unwrap();
        });
    }

    #[test]
    #[ignore = "requires root to exercise service-owned promotion cache"]
    fn promotion_lock_refuses_incomplete_entries_and_symlinked_locks() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("vms");
        let (shared, _) = install_artifact(&root, "deadbeef", DIGEST_A);
        assert!(
            lock_checkpoint_entry_in(&root, &root.join("_shared"), &shared)
                .unwrap()
                .is_none()
        );
        fs::write(shared.join(".smolvm-extracted"), b"done").unwrap();
        fs::remove_file(shared.with_extension("lock")).unwrap();
        let outside = temp.path().join("outside");
        fs::write(&outside, b"unchanged").unwrap();
        std::os::unix::fs::symlink(&outside, shared.with_extension("lock")).unwrap();
        assert!(lock_checkpoint_entry_in(&root, &root.join("_shared"), &shared).is_err());
        assert_eq!(fs::read(outside).unwrap(), b"unchanged");
    }

    #[test]
    fn prepared_budget_evicts_only_unleased_prepared_entries() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("vms");
        let (prepared, cow) = install_artifact(&root, "deadbeef", DIGEST_A);
        let (ordinary, ordinary_cow) = install_artifact(&root, "12345678", DIGEST_B);
        fs::write(
            prepared.with_extension("prepared.smolcheckpoint"),
            b"artifact",
        )
        .unwrap();
        let machine = machine_dir(&root, "01");
        publish_test_lease(&machine, &prepared);
        prune_prepared_checkpoints_in(&root, 0).unwrap();
        assert!(prepared.exists() && cow.exists());
        fs::remove_dir_all(machine).unwrap();
        prune_prepared_checkpoints_in(&root, u64::MAX).unwrap();
        assert!(prepared.exists());
        prune_prepared_checkpoints_in(&root, 0).unwrap();
        assert!(!prepared.exists() && !cow.exists());
        assert!(!prepared.with_extension("prepared.smolcheckpoint").exists());
        assert!(ordinary.exists() && ordinary_cow.exists());
    }

    #[test]
    fn prepared_budget_waits_for_active_reader() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("vms");
        let (prepared, _) = install_artifact(&root, "deadbeef", DIGEST_A);
        fs::write(
            prepared.with_extension("prepared.smolcheckpoint"),
            b"artifact",
        )
        .unwrap();
        let pin = lock_artifact_cache(&root, false).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            let root = &root;
            scope.spawn(move || {
                prune_prepared_checkpoints_in(root, 0).unwrap();
                tx.send(()).unwrap();
            });
            assert!(rx
                .recv_timeout(std::time::Duration::from_millis(50))
                .is_err());
            assert!(prepared.exists());
            drop(pin);
            rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        });
        assert!(!prepared.exists());
    }

    #[test]
    fn prepared_budget_cleans_interrupted_publication() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("vms");
        let shared = root.join("_shared");
        fs::create_dir_all(&shared).unwrap();
        fs::write(shared.join("deadbeef.prepared.smolcheckpoint"), b"orphan").unwrap();
        fs::write(shared.join("deadbeef.artifact-sha256"), DIGEST_A).unwrap();
        prune_prepared_checkpoints_in(&root, u64::MAX).unwrap();
        assert!(!shared.join("deadbeef.prepared.smolcheckpoint").exists());
        assert!(!shared.join("deadbeef.artifact-sha256").exists());
    }

    /// Date every part of an artifact's cache entry, so trims order it.
    fn age_artifact(shared: &Path, digest: &str, seconds_ago: u64) {
        let when = SystemTime::now() - std::time::Duration::from_secs(seconds_ago);
        let root = shared.parent().unwrap().parent().unwrap();
        for path in [
            shared.to_path_buf(),
            smolvm_pack::extract::shared_artifact_sha256_path(shared),
            root.join("_cow-bases").join(digest),
        ] {
            fs::File::open(path).unwrap().set_modified(when).unwrap();
        }
    }

    #[test]
    fn trim_keeps_the_newest_unleased_extractions_and_every_leased_one() {
        const DIGEST_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        const DIGEST_D: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("vms");
        let (oldest, oldest_cow) = install_artifact(&root, "aaaaaaaa", DIGEST_A);
        let (middle, _) = install_artifact(&root, "bbbbbbbb", DIGEST_B);
        let (newest, _) = install_artifact(&root, "cccccccc", DIGEST_C);
        let (leased, leased_cow) = install_artifact(&root, "dddddddd", DIGEST_D);
        age_artifact(&oldest, DIGEST_A, 300);
        age_artifact(&middle, DIGEST_B, 200);
        age_artifact(&newest, DIGEST_C, 100);
        age_artifact(&leased, DIGEST_D, 400);
        publish_test_lease(&machine_dir(&root, "01"), &leased);

        let report = trim_unleased_shared_packs_in(&root, 2, u64::MAX)
            .unwrap()
            .unwrap();

        assert_eq!(report.referenced_entries, 1);
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.entries[0].artifact, DIGEST_A);
        assert!(!oldest.exists() && !oldest_cow.exists());
        assert!(!smolvm_pack::extract::shared_artifact_sha256_path(&oldest).exists());
        assert!(middle.exists() && newest.exists());
        assert!(leased.exists() && leased_cow.exists());
    }

    #[test]
    fn trim_budget_counts_only_what_removal_frees() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("vms");
        let (restored, _) = install_artifact(&root, "aaaaaaaa", DIGEST_A);
        let (older, _) = install_artifact(&root, "bbbbbbbb", DIGEST_B);
        let ram = vec![1u8; 1 << 20];
        fs::write(restored.join("memory.bin"), &ram).unwrap();
        fs::write(older.join("memory.bin"), &ram).unwrap();
        // A live restored machine still links the newer extraction's RAM.
        let machine = machine_dir(&root, "01");
        fs::create_dir_all(&machine).unwrap();
        fs::hard_link(restored.join("memory.bin"), machine.join("memory.bin")).unwrap();
        age_artifact(&restored, DIGEST_A, 100);
        age_artifact(&older, DIGEST_B, 200);

        trim_unleased_shared_packs_in(&root, 8, 512 * 1024)
            .unwrap()
            .unwrap();
        assert!(restored.exists(), "linked RAM frees nothing, so it fits");
        assert!(
            !older.exists(),
            "1 MiB held only by the cache exceeds the budget"
        );

        // Once the machine is gone its RAM is the cache's alone.
        fs::remove_dir_all(&machine).unwrap();
        trim_unleased_shared_packs_in(&root, 8, 512 * 1024)
            .unwrap()
            .unwrap();
        assert!(!restored.exists());
    }

    #[test]
    fn trim_leaves_prepared_captures_and_waits_for_no_one() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("vms");
        let (prepared, _) = install_artifact(&root, "aaaaaaaa", DIGEST_A);
        fs::write(prepared.with_extension("prepared.smolcheckpoint"), b"x").unwrap();
        let (unleased, _) = install_artifact(&root, "bbbbbbbb", DIGEST_B);

        let busy = lock_artifact_cache(&root, false).unwrap();
        assert!(trim_unleased_shared_packs_in(&root, 0, 0)
            .unwrap()
            .is_none());
        assert!(unleased.exists());
        drop(busy);

        trim_unleased_shared_packs_in(&root, 0, 0).unwrap().unwrap();
        assert!(prepared.exists());
        assert!(!unleased.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn trim_waits_for_a_ram_write_back_and_then_removes_its_marker() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("vms");
        let (writing, _) = install_artifact(&root, "aaaaaaaa", DIGEST_A);
        let marker = smolvm_pack::extract::unsynced_marker_path(&writing);
        smolvm_pack::extract::mark_unsynced(&marker).unwrap();

        trim_unleased_shared_packs_in(&root, 0, 0).unwrap().unwrap();
        assert!(
            writing.exists(),
            "an extraction still being written back stays"
        );

        smolvm_pack::extract::clear_unsynced(&marker).unwrap();
        fs::write(&marker, b"an earlier boot\n").unwrap();
        trim_unleased_shared_packs_in(&root, 0, 0).unwrap().unwrap();
        assert!(!writing.exists());
        assert!(!marker.exists(), "the marker goes with its extraction");
    }

    #[test]
    fn leases_protect_both_caches_until_the_last_machine_is_deleted() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("vms");
        let (shared, cow) = install_artifact(&root, "deadbeef", DIGEST_A);
        let first = machine_dir(&root, "01");
        let second = machine_dir(&root, "02");
        publish_test_lease(&first, &shared);
        publish_test_lease(&second, &shared);

        let report = prune_artifact_caches_in(&root, 0, false).unwrap();
        assert!(report.entries.is_empty());
        assert_eq!(report.referenced_entries, 1);
        fs::remove_dir_all(&first).unwrap();
        assert!(prune_artifact_caches_in(&root, 0, false)
            .unwrap()
            .entries
            .is_empty());
        assert!(shared.exists());
        assert!(cow.exists());

        fs::remove_dir_all(&second).unwrap();
        let report = prune_artifact_caches_in(&root, 0, false).unwrap();
        assert_eq!(report.entries.len(), 1);
        assert!(!shared.exists());
        assert!(!cow.exists());
        assert!(!smolvm_pack::extract::shared_artifact_sha256_path(&shared).exists());
    }

    #[test]
    fn malformed_live_pointer_fails_closed_before_any_removal() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("vms");
        let (shared, cow) = install_artifact(&root, "deadbeef", DIGEST_A);
        let machine = machine_dir(&root, "01");
        fs::create_dir_all(&machine).unwrap();
        fs::write(machine.join(SHARED_PACK_POINTER), "../../escape\n").unwrap();

        let error = prune_artifact_caches_in(&root, 0, false).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(shared.exists());
        assert!(cow.exists());
    }

    #[test]
    fn symlinked_digest_marker_fails_closed_for_a_live_lease() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("vms");
        let (shared, cow) = install_artifact(&root, "deadbeef", DIGEST_A);
        let marker = smolvm_pack::extract::shared_artifact_sha256_path(&shared);
        fs::remove_file(&marker).unwrap();
        let outside = temp.path().join("digest");
        fs::write(&outside, format!("{DIGEST_A}\n")).unwrap();
        std::os::unix::fs::symlink(&outside, &marker).unwrap();
        let machine = machine_dir(&root, "01");
        publish_test_lease(&machine, &shared);

        let error = prune_artifact_caches_in(&root, 0, false).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(shared.exists());
        assert!(cow.exists());
        assert_eq!(
            fs::read(&outside).unwrap(),
            format!("{DIGEST_A}\n").as_bytes()
        );
    }

    #[test]
    fn symlinked_cache_root_is_never_traversed() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("vms");
        fs::create_dir_all(&root).unwrap();
        let outside = temp.path().join("outside-cow");
        fs::create_dir_all(outside.join(DIGEST_A)).unwrap();
        fs::write(outside.join(DIGEST_A).join("keep"), b"outside").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("_cow-bases")).unwrap();

        let error = prune_artifact_caches_in(&root, 0, false).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            fs::read(outside.join(DIGEST_A).join("keep")).unwrap(),
            b"outside"
        );
    }

    #[test]
    fn dry_run_and_keep_apply_only_to_unused_artifacts() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("vms");
        let (shared_a, cow_a) = install_artifact(&root, "deadbeef", DIGEST_A);
        let (shared_b, cow_b) = install_artifact(&root, "cafebabe", DIGEST_B);
        fs::OpenOptions::new()
            .read(true)
            .open(smolvm_pack::extract::shared_artifact_sha256_path(&shared_b))
            .unwrap()
            .set_modified(SystemTime::now())
            .unwrap();

        let dry = prune_artifact_caches_in(&root, 1, true).unwrap();
        assert_eq!(dry.entries.len(), 1);
        assert_eq!(dry.entries[0].artifact, DIGEST_A);
        assert!(dry.entries[0].allocated_bytes > 0);
        assert!(shared_a.exists() && cow_a.exists());
        assert!(shared_b.exists() && cow_b.exists());

        let real = prune_artifact_caches_in(&root, 1, false).unwrap();
        assert_eq!(real.entries.len(), 1);
        assert!(!shared_a.exists() && !cow_a.exists());
        assert!(shared_b.exists() && cow_b.exists());
    }

    #[test]
    fn copy_lease_publishes_an_identical_clone_reference() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("vms");
        let shared_root = root.join("_shared");
        let (shared, _) = install_artifact(&root, "deadbeef", DIGEST_A);
        let golden = machine_dir(&root, "01");
        let clone = machine_dir(&root, "02");
        publish_test_lease(&golden, &shared);

        let lease = copy_shared_pack_lease_in(
            &root,
            &shared_root,
            &golden.join("pack"),
            &clone.join("pack"),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            read_lease_from_machine_dir(&clone, &shared_root)
                .unwrap()
                .unwrap(),
            lease
        );
    }

    #[test]
    fn cow_creation_requires_a_matching_machine_lease() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("vms");
        let shared_root = root.join("_shared");
        let (shared, _) = install_artifact(&root, "deadbeef", DIGEST_A);
        let machine = machine_dir(&root, "01");
        fs::create_dir_all(&machine).unwrap();

        let missing = validate_cow_lease_in(&machine, &shared, DIGEST_A, &shared_root).unwrap_err();
        assert_eq!(missing.kind(), io::ErrorKind::InvalidData);
        publish_test_lease(&machine, &shared);
        validate_cow_lease_in(&machine, &shared, DIGEST_A, &shared_root).unwrap();
        let mismatch =
            validate_cow_lease_in(&machine, &shared, DIGEST_B, &shared_root).unwrap_err();
        assert_eq!(mismatch.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn prune_waits_for_atomic_lease_publication() {
        use std::sync::mpsc;
        use std::time::Duration;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("vms");
        let (shared, cow) = install_artifact(&root, "deadbeef", DIGEST_A);
        let machine = machine_dir(&root, "01");
        let publisher = lock_artifact_cache(&root, false).unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let prune_root = root.clone();
        let worker = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let result = prune_artifact_caches_in(&prune_root, 0, false);
            done_tx.send(result).unwrap();
        });
        started_rx.recv().unwrap();
        assert!(matches!(
            done_rx.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));

        publish_test_lease(&machine, &shared);
        drop(publisher);
        let report = done_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap();
        worker.join().unwrap();
        assert!(report.entries.is_empty());
        assert!(shared.exists());
        assert!(cow.exists());
    }

    #[test]
    fn prune_unlinks_in_tree_symlinks_without_following_them() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("vms");
        let (shared, _) = install_artifact(&root, "deadbeef", DIGEST_A);
        let outside = temp.path().join("outside");
        fs::write(&outside, b"keep").unwrap();
        std::os::unix::fs::symlink(&outside, shared.join("layers/link")).unwrap();

        let report = prune_artifact_caches_in(&root, 0, false).unwrap();
        assert_eq!(report.entries.len(), 1);
        assert_eq!(fs::read(&outside).unwrap(), b"keep");
    }

    #[test]
    fn legacy_unreferenced_shared_entry_can_be_pruned_without_a_digest() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("vms");
        let shared = root.join("_shared/deadbeef");
        fs::create_dir_all(&shared).unwrap();
        fs::write(shared.join("old"), b"cache").unwrap();

        let report = prune_artifact_caches_in(&root, 0, false).unwrap();
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.entries[0].artifact, "shared:deadbeef");
        assert!(!shared.exists());
    }
}
#[test]
fn prepared_reference_rejects_paths_and_incomplete_digests() {
    for reference in [
        "checkpoint://../x",
        "checkpoint://12345678-x",
        "checkpoint://12345678/abc",
        "not-a-checkpoint",
    ] {
        assert!(open_prepared_checkpoint(reference).is_err());
    }
}

#[test]
fn prepared_retention_rejects_nonprivate_capture_directory() {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let artifact = dir.path().join("capture.smolcheckpoint");
    fs::write(&artifact, b"unchanged").unwrap();
    let error = retain_prepared_checkpoint(&artifact, dir.path()).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(fs::read(artifact).unwrap(), b"unchanged");
}
