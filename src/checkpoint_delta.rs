//! Incremental checkpoints for the node API.
//!
//! A capture goes through the node's content-addressed checkpoint store, so
//! only chunks the store has not seen are compressed and written. The file
//! handed to the caller holds the stored index and, when the machine was
//! restored from (or last captured to) a checkpoint this node still holds,
//! only the objects that checkpoint lacks: a delta that names its base by
//! lineage id and index digest.
//!
//! A restore imports the file into the store, completing a delta from its
//! base, and materializes the full payload once into the node's shared
//! extraction directory, reusing the base's materialization for every file
//! and chunk that did not change. Later restores of the same checkpoint reuse
//! that tree exactly like any extracted checkpoint.

use crate::checkpoint_store as store;
use crate::error::{Error, Result};
use std::path::{Path, PathBuf};

/// The node's checkpoint store.
pub fn node_store() -> PathBuf {
    crate::agent::vm_cache_root().join("checkpoint-store")
}

fn published_dir(store: &Path) -> PathBuf {
    store.join("published")
}

/// Where the materialized tree of checkpoint `id` is recorded.
///
/// Lineage records written before ids were checked may name anything, so a
/// path is only built for an id of the checkpoint form.
fn materialized_record(store: &Path, id: &str) -> Option<PathBuf> {
    store::is_checkpoint_id(id).then(|| store.join("materialized").join(id))
}

/// Materialized trees a restore can build over, whatever their lineage.
fn restore_bases(store: &Path) -> PathBuf {
    store.join("restore-bases")
}

/// How many trees [`restore_bases`] keeps; each costs a copy of its index.
const RESTORE_BASES_KEPT: usize = 128;

fn io(context: &'static str) -> impl Fn(std::io::Error) -> Error {
    move |error| Error::agent(context, error.to_string())
}

/// Result of an incremental capture.
#[derive(Debug, Clone)]
pub struct IncrementalCapture {
    /// The capture's own timings and pause.
    pub result: crate::portable_checkpoint::CaptureResult,
    /// Lineage id of the new checkpoint.
    pub id: String,
    /// The base the exported file is relative to, when it is a delta.
    pub base: Option<String>,
    /// What the export wrote.
    pub export: store::ExportStats,
    /// Time spent capturing into the store.
    pub store_elapsed: std::time::Duration,
    /// Time spent writing the transport file.
    pub export_elapsed: std::time::Duration,
}

/// Capture `name` into the node store and export it to `artifact`: a delta
/// against the checkpoint the machine continues from when this node holds it,
/// otherwise a complete chunked file. `force_full` exports a complete file
/// even when a base is held, so a caller can bound how long a chain of deltas
/// a restore must import; the capture still lands in the store and the next
/// one can be a delta of it.
pub fn capture(
    name: &str,
    artifact: &Path,
    force_full: bool,
    release_source: impl FnOnce(),
) -> Result<IncrementalCapture> {
    let store = node_store();
    let published = published_dir(&store);
    std::fs::create_dir_all(&published).map_err(io("create checkpoint store"))?;
    // The checkpoint this capture deltas against stays while it is read. The
    // caller holds the machine's lifecycle lock, so the head cannot move.
    let head = crate::db::SmolvmDb::open()
        .and_then(|db| db.get_vm(name))
        .ok()
        .flatten()
        .and_then(|record| record.checkpoint_head);
    let _base_pin = match head.as_deref() {
        Some(head) => {
            crate::checkpoint_retention::pin(&store, head).map_err(io("pin checkpoint base"))?
        }
        None => None,
    };
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let output = published.join(format!("{name}-{nanos}.checkpoint"));
    let started = std::time::Instant::now();
    let result =
        crate::portable_checkpoint::capture_to_store(name, &output, &store, release_source)?;
    let store_elapsed = started.elapsed();
    let manifest = store::read_manifest(&output).map_err(io("read stored checkpoint"))?;
    let lineage = manifest
        .checkpoint
        .as_ref()
        .and_then(|checkpoint| checkpoint.lineage.clone())
        .ok_or_else(|| Error::agent("incremental checkpoint", "capture recorded no lineage"))?;
    let base = match lineage.parent.as_deref() {
        Some(parent) if !force_full => held_checkpoint(&store, parent)?,
        _ => None,
    };
    let started = std::time::Instant::now();
    let export = store::export_chunked(&output, base.as_deref(), artifact, |manifest| {
        if let Some(checkpoint) = manifest.checkpoint.as_mut() {
            checkpoint.version = if checkpoint.base.is_some() {
                crate::portable_checkpoint::DELTA_FORMAT_VERSION
            } else {
                crate::portable_checkpoint::HISTORY_FORMAT_VERSION
            };
        }
    })
    .map_err(io("export checkpoint"))?;
    let export_elapsed = started.elapsed();
    tracing::info!(
        machine = name,
        id = %lineage.id,
        base = ?base.as_ref().and(lineage.parent.as_deref()),
        objects = export.objects,
        object_bytes = export.object_bytes,
        base_objects = export.base_objects,
        bytes = export.bytes,
        store_ms = store_elapsed.as_millis() as u64,
        export_ms = export_elapsed.as_millis() as u64,
        "incremental checkpoint exported"
    );
    crate::checkpoint_retention::request();
    Ok(IncrementalCapture {
        result,
        base: base.and(lineage.parent),
        id: lineage.id,
        export,
        store_elapsed,
        export_elapsed,
    })
}

/// The stored directory of checkpoint `id` on this node, if it is complete.
fn held_checkpoint(store: &Path, id: &str) -> Result<Option<PathBuf>> {
    let Some(record) = store::find_lineage(store, id).map_err(io("read checkpoint lineage"))?
    else {
        return Ok(None);
    };
    let path = PathBuf::from(record.path);
    if !path.join("checkpoint.json").is_file() {
        return Ok(None);
    }
    if !store::missing_objects(&path)
        .map_err(io("inspect stored checkpoint"))?
        .is_empty()
    {
        return Ok(None);
    }
    Ok(Some(path))
}

/// File inside a materialized tree holding the token its record repeats.
const MATERIALIZED_TOKEN: &str = ".smolvm-materialized";

/// The materialized tree recorded for checkpoint `id`, if it is still the
/// tree the record was written for. The tree lives at a path keyed by a
/// CRC32 that a file can choose, and is evicted and re-extracted there by
/// other restores; only the random token written into it at publication and
/// repeated in the record ties the two together.
fn materialized_tree(store: &Path, id: &str) -> Option<PathBuf> {
    let record = std::fs::read_to_string(materialized_record(store, id)?).ok()?;
    let mut lines = record.lines();
    let tree = PathBuf::from(lines.next()?.trim());
    let token = lines.next()?.trim();
    if token.is_empty() || !smolvm_pack::extract::is_extracted(&tree) {
        return None;
    }
    let marker = tree.join(MATERIALIZED_TOKEN);
    let metadata = std::fs::symlink_metadata(&marker).ok()?;
    if !metadata.is_file() || metadata.len() > 64 {
        return None;
    }
    (std::fs::read_to_string(&marker).ok()?.trim() == token).then_some(tree)
}

/// Write a fresh token into the tree at `partial`, replacing any file of that
/// name the checkpoint's index put there, and return it.
fn write_materialized_token(partial: &Path) -> std::io::Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|error| std::io::Error::other(error.to_string()))?;
    let token = hex::encode(bytes);
    let marker = partial.join(MATERIALIZED_TOKEN);
    match std::fs::remove_file(&marker) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    use std::io::Write;
    options.open(&marker)?.write_all(token.as_bytes())?;
    Ok(token)
}

/// Read-only files of the materialized tree of checkpoint `parent`, by inode,
/// so a capture of a machine restored from it skips re-reading its shared
/// disk bases. Empty when this node has no untouched tree of it.
#[cfg(unix)]
pub fn known_files_for(store: &Path, parent: &str) -> store::KnownFiles {
    let tree = materialized_tree(store, parent);
    let (Some(tree), Ok(Some(stored))) = (tree, held_checkpoint(store, parent)) else {
        return store::KnownFiles::default();
    };
    store::known_files(&stored, &tree).unwrap_or_default()
}

/// Windows captures still reuse cached chunks; inode-based disk reuse needs
/// Unix file identities and is unavailable there.
#[cfg(not(unix))]
pub fn known_files_for(_store: &Path, _parent: &str) -> store::KnownFiles {
    store::KnownFiles::default()
}

/// SHA-256 of the index a chunked checkpoint file carries, read without
/// unpacking its objects.
fn carried_index_digest(
    store: &Path,
    artifact: &Path,
    footer: &smolvm_pack::format::PackFooter,
) -> Result<String> {
    let staging_root = store.join("staging");
    std::fs::create_dir_all(&staging_root).map_err(io("create checkpoint staging"))?;
    let staging = tempfile::Builder::new()
        .prefix(".index-")
        .tempdir_in(&staging_root)
        .map_err(io("create checkpoint staging"))?;
    smolvm_pack::extract::extract_checkpoint_sidecar(
        artifact,
        staging.path(),
        footer,
        &[PathBuf::from("objects"), PathBuf::from("generations")],
        &[PathBuf::from("checkpoint.json")],
    )
    .map_err(io("read checkpoint index"))?;
    store::index_digest(staging.path()).map_err(io("read checkpoint index"))
}

/// Refuse to treat the stored `directory` as checkpoint `id` from a file
/// whose index digest is `carried`: ids are random per capture and say
/// nothing about content, so only an equal index means the same checkpoint.
fn ensure_same_checkpoint(id: &str, carried: &str, directory: &Path) -> Result<()> {
    let held = store::index_digest(directory).map_err(io("read stored checkpoint"))?;
    if held != carried {
        return Err(Error::agent_conflict(
            "restore checkpoint",
            format!("this node holds a different checkpoint with id {id}"),
        ));
    }
    Ok(())
}

/// How a chunked checkpoint file became available on this node.
#[derive(Debug, Clone, Default)]
pub struct Imported {
    /// Keeps the stored checkpoint from being forgotten while this is alive.
    pub pin: Option<std::sync::Arc<crate::checkpoint_retention::Pin>>,
    /// Lineage id of the checkpoint.
    pub id: String,
    /// The stored directory holding it.
    pub directory: PathBuf,
    /// Base it was completed from, for a delta.
    pub base: Option<String>,
    /// Objects linked from the base.
    pub base_objects: usize,
    /// The node already held it.
    pub already_held: bool,
}

/// Import a verified chunked checkpoint file into the node store. A delta's
/// base must already be held here with the exact index digest it names;
/// otherwise this fails with a conflict naming the base to import first.
pub fn import(artifact: &Path) -> Result<Option<Imported>> {
    let footer = smolvm_pack::packer::read_footer_from_sidecar(artifact)
        .map_err(|e| Error::agent("read checkpoint footer", e.to_string()))?;
    let manifest = smolvm_pack::packer::read_manifest_from_sidecar(artifact)
        .map_err(|e| Error::agent("read checkpoint manifest", e.to_string()))?;
    let Some(checkpoint) = manifest.checkpoint.as_ref() else {
        return Ok(None);
    };
    if checkpoint.payload != smolvm_pack::format::CheckpointLayout::Chunked {
        return Ok(None);
    }
    crate::portable_checkpoint::validate_compatibility(checkpoint)?;
    let id = checkpoint
        .lineage
        .as_ref()
        .map(|lineage| lineage.id.clone())
        .ok_or_else(|| Error::config("restore checkpoint", "chunked checkpoint has no id"))?;
    let store = node_store();
    std::fs::create_dir_all(&store).map_err(io("create checkpoint store"))?;
    // Pinned before it is looked up, so a forget either finished first or
    // waits for this restore.
    let pin = crate::checkpoint_retention::pin(&store, &id)
        .map_err(io("pin checkpoint"))?
        .map(std::sync::Arc::new);
    if let Some(directory) = held_checkpoint(&store, &id)? {
        // The id is the file's own claim; the held checkpoint stands in for
        // it only when the index the file carries is the one held.
        let carried = carried_index_digest(&store, artifact, &footer)?;
        ensure_same_checkpoint(&id, &carried, &directory)?;
        return Ok(Some(Imported {
            pin,
            id,
            directory,
            base: checkpoint.base.as_ref().map(|base| base.id.clone()),
            already_held: true,
            ..Default::default()
        }));
    }
    let mut _base_pin = None;
    let base = match checkpoint.base.as_ref() {
        Some(base) => {
            _base_pin = crate::checkpoint_retention::pin(&store, &base.id)
                .map_err(io("pin base checkpoint"))?;
            let Some(directory) = held_checkpoint(&store, &base.id)? else {
                return Err(Error::agent_conflict(
                    "restore checkpoint",
                    format!(
                        "this checkpoint is a delta of checkpoint {}, which this node does not hold; import it first",
                        base.id
                    ),
                ));
            };
            let digest = store::index_digest(&directory).map_err(io("read base checkpoint"))?;
            if digest != base.index_sha256 {
                return Err(Error::agent_conflict(
                    "restore checkpoint",
                    format!(
                        "base checkpoint {} on this node does not match the one this delta was captured against",
                        base.id
                    ),
                ));
            }
            Some((base.id.clone(), directory))
        }
        None => None,
    };
    let staging_root = store.join("staging");
    std::fs::create_dir_all(&staging_root).map_err(io("create checkpoint staging"))?;
    let staging = tempfile::Builder::new()
        .prefix(".import-")
        .tempdir_in(&staging_root)
        .map_err(io("create checkpoint staging"))?;
    let unpacked = staging.path().join("checkpoint");
    smolvm_pack::extract::unpack_checkpoint_history(artifact, &footer, &unpacked)
        .map_err(io("unpack checkpoint"))?;
    #[cfg(unix)]
    own_unpacked_checkpoint(&unpacked).map_err(io("take ownership of checkpoint"))?;
    let base_objects = match &base {
        Some((_, directory)) => {
            store::complete_from_base(&unpacked, directory).map_err(io("complete delta"))?
        }
        None => 0,
    };
    let missing = store::missing_objects(&unpacked).map_err(io("inspect checkpoint"))?;
    if !missing.is_empty() {
        return Err(Error::agent(
            "restore checkpoint",
            format!("checkpoint is missing {} object(s)", missing.len()),
        ));
    }
    let indexed_id = store::read_manifest(&unpacked)
        .map_err(io("read checkpoint index"))?
        .checkpoint
        .and_then(|checkpoint| checkpoint.lineage)
        .map(|lineage| lineage.id);
    if indexed_id.as_deref() != Some(id.as_str()) {
        return Err(Error::agent(
            "restore checkpoint",
            "the checkpoint's index names a different checkpoint id than its manifest",
        ));
    }
    let published = published_dir(&store);
    std::fs::create_dir_all(&published).map_err(io("create checkpoint store"))?;
    let directory = published.join(format!("{id}.checkpoint"));
    match store::publish(&unpacked, &directory) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let unpacked_digest =
                store::index_digest(&unpacked).map_err(io("read checkpoint index"))?;
            ensure_same_checkpoint(&id, &unpacked_digest, &directory)?;
        }
        Err(error) => return Err(io("publish checkpoint")(error)),
    }
    store::adopt_objects(&store, &directory).map_err(io("adopt checkpoint objects"))?;
    let lineage = checkpoint.lineage.clone().expect("checked above");
    store::record_lineage(
        &store,
        &store::LineageRecord {
            id: id.clone(),
            parent: lineage.parent,
            machine: lineage.machine,
            created_at: lineage.created_at,
            path: directory.to_string_lossy().into_owned(),
        },
    )
    .map_err(io("record checkpoint lineage"))?;
    Ok(Some(Imported {
        pin,
        id,
        directory,
        base_objects,
        base: base.map(|(id, _)| id),
        already_held: false,
    }))
}

/// `Some` once `shared` is extracted: the tree for a chunked `artifact`, or
/// `None` inside for a classic one, which takes the ordinary path.
fn already_prepared(artifact: &Path, shared: &Path) -> Result<Option<Option<PathBuf>>> {
    if !smolvm_pack::extract::is_extracted(shared) {
        return Ok(None);
    }
    let manifest = smolvm_pack::packer::read_manifest_from_sidecar(artifact)
        .map_err(|e| Error::agent("read checkpoint manifest", e.to_string()))?;
    let chunked = manifest
        .checkpoint
        .as_ref()
        .is_some_and(|c| c.payload == smolvm_pack::format::CheckpointLayout::Chunked);
    Ok(Some(chunked.then(|| shared.to_path_buf())))
}

/// Give this process the files of a checkpoint unpacked into its store.
///
/// Unpacking as root keeps the owners the archive recorded: the uid of
/// whatever captured it, a laptop user for a moved machine. The store is this
/// host's, and a lazily restored disk's VMM reads its objects through an
/// idmapped mount that maps only this process's ids, so a foreign owner left
/// them unreadable and the guest's disk stalled.
#[cfg(unix)]
fn own_unpacked_checkpoint(root: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.uid() != uid || metadata.gid() != gid {
            std::os::unix::fs::lchown(&path, Some(uid), Some(gid))?;
        }
        if metadata.is_dir() {
            for entry in std::fs::read_dir(&path)? {
                pending.push(entry?.path());
            }
        }
    }
    Ok(())
}

/// The lock the pack extractor holds while it extracts into `shared`.
fn lock_shared_extraction(shared: &Path) -> Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).write(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let lock = options
        .open(shared.with_extension("lock"))
        .map_err(io("open shared extraction lock"))?;
    lock.lock().map_err(io("lock shared extraction"))?;
    Ok(lock)
}

/// Make a chunked checkpoint file restorable through the ordinary extraction
/// path: import it, then materialize its full payload into the shared
/// extraction directory its footer names, reusing the closest held base's
/// materialization. Returns `None` for classic files.
pub fn prepare_restore(artifact: &Path) -> Result<Option<PathBuf>> {
    let footer = smolvm_pack::packer::read_footer_from_sidecar(artifact)
        .map_err(|e| Error::agent("read checkpoint footer", e.to_string()))?;
    let shared_root = crate::agent::shared_pack_cache_root();
    let shared = smolvm_pack::extract::shared_pack_dir(&shared_root, footer.checksum);
    if let Some(prepared) = already_prepared(artifact, &shared)? {
        return Ok(prepared);
    }
    std::fs::create_dir_all(&shared_root).map_err(io("create shared extraction root"))?;
    // Overlapping restores of one checkpoint share the partial directory
    // below and each cleared it on entry, removing the tree another was still
    // writing. The extractor's lock for this checksum makes them take turns;
    // the ones that waited find the tree published and reuse it.
    let _lock = lock_shared_extraction(&shared)?;
    if let Some(prepared) = already_prepared(artifact, &shared)? {
        return Ok(prepared);
    }
    let started = std::time::Instant::now();
    let Some(imported) = import(artifact)? else {
        return Ok(None);
    };
    let import_ms = started.elapsed().as_millis() as u64;
    let store = node_store();
    // The nearest ancestor this node has materialized and still holds.
    let mut base_tree = None;
    let mut _base_pin = None;
    let mut cursor = store::find_lineage(&store, &imported.id)
        .map_err(io("read checkpoint lineage"))?
        .and_then(|record| record.parent);
    for _ in 0..64 {
        let Some(id) = cursor else { break };
        let pinned =
            crate::checkpoint_retention::pin(&store, &id).map_err(io("pin checkpoint base"))?;
        if let (Some(tree), Some(stored)) = (
            materialized_tree(&store, &id),
            held_checkpoint(&store, &id)?,
        ) {
            base_tree = Some((stored, tree));
            _base_pin = pinned;
            break;
        }
        cursor = store::find_lineage(&store, &id)
            .map_err(io("read checkpoint lineage"))?
            .and_then(|record| record.parent);
    }
    // Without a held ancestor, the tree that shares the most chunks: a
    // branch of the same machine shares nearly all of its disks.
    let mut similarity = None;
    if base_tree.is_none() {
        match store::closest_base(
            &restore_bases(&store),
            &imported.directory,
            smolvm_pack::extract::is_extracted,
        ) {
            Ok(Some((entry, tree, score))) => {
                base_tree = Some((entry, tree));
                similarity = Some(score);
            }
            Ok(None) => {}
            Err(error) => tracing::warn!(%error, "could not look for a restore base"),
        }
    }
    let partial = shared_root.join(format!(
        ".{:08x}-materialize-{}",
        footer.checksum,
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&partial);
    let started = std::time::Instant::now();
    // RAM written below reaches the disk later, as for a deferred extraction.
    smolvm_pack::extract::mark_unsynced(&smolvm_pack::extract::unsynced_marker_path(&shared))
        .map_err(io("mark checkpoint memory unsynced"))?;
    // Lazy restores serve the machine's disks from the store as the guest
    // reads them, so the tree leaves them out.
    #[cfg(unix)]
    let lazy = crate::lazy_disk::enabled();
    #[cfg(not(unix))]
    let lazy = false;
    let skip = |path: &str| {
        #[cfg(unix)]
        return lazy && crate::lazy_disk::is_lazy_asset(path);
        #[cfg(not(unix))]
        return false;
    };
    let materialized = store::materialize_over_except(
        &imported.directory,
        &partial,
        base_tree.as_ref().map(|(s, t)| (s.as_path(), t.as_path())),
        &skip,
    );
    // A base is only a shortcut: if it fails, build the tree from the objects.
    let materialized = match materialized {
        Err(error) if base_tree.is_some() => {
            tracing::warn!(%error, "building over a restore base failed; materializing in full");
            let _ = std::fs::remove_dir_all(&partial);
            base_tree = None;
            store::materialize_over_except(&imported.directory, &partial, None, &skip)
        }
        other => other,
    };
    let stats = materialized.map_err(|error| {
        let _ = std::fs::remove_dir_all(&partial);
        Error::agent("materialize checkpoint", error.to_string())
    })?;
    #[cfg(unix)]
    {
        let recorded = std::fs::write(
            partial.join(crate::lazy_disk::TREE_SOURCE),
            imported.directory.as_os_str().as_encoded_bytes(),
        )
        .and_then(|()| match lazy {
            true => std::fs::write(partial.join(crate::lazy_disk::TREE_WITHOUT_DISKS), b"1\n"),
            false => Ok(()),
        });
        if let Err(error) = recorded {
            let _ = std::fs::remove_dir_all(&partial);
            return Err(io("record the checkpoint a restore tree came from")(error));
        }
    }
    let token = write_materialized_token(&partial).map_err(|error| {
        let _ = std::fs::remove_dir_all(&partial);
        io("mark materialized checkpoint")(error)
    })?;
    smolvm_pack::extract::mark_extracted(&partial).map_err(io("mark checkpoint extracted"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&partial, std::fs::Permissions::from_mode(0o700));
    }
    // The key is a CRC32 the file chooses, and the request may still be
    // refused after this returns. Record whose payload the entry holds before
    // it can be found, so another artifact with the same key is refused
    // rather than served this tree.
    smolvm_pack::extract::record_shared_artifact_sha256(artifact, &shared).map_err(|error| {
        let _ = std::fs::remove_dir_all(&partial);
        io("record materialized checkpoint")(error)
    })?;
    match std::fs::rename(&partial, &shared) {
        Ok(()) => {}
        Err(_) if smolvm_pack::extract::is_extracted(&shared) => {
            let _ = std::fs::remove_dir_all(&partial);
        }
        Err(error) => {
            let _ = std::fs::remove_dir_all(&partial);
            return Err(io("publish materialized checkpoint")(error));
        }
    }
    if let Some(record) = materialized_record(&store, &imported.id) {
        if let Some(parent) = record.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&record, format!("{}\n{token}\n", shared.to_string_lossy()));
    }
    if let Err(error) = store::remember_base(
        &restore_bases(&store),
        &imported.directory,
        &shared,
        RESTORE_BASES_KEPT,
    ) {
        tracing::warn!(%error, "could not keep the restored tree as a base");
    }
    tracing::info!(
        id = %imported.id,
        delta_base = ?imported.base,
        already_held = imported.already_held,
        base_objects = imported.base_objects,
        materialize_base = ?base_tree.as_ref().map(|(_, tree)| tree.display().to_string()),
        base_similarity = ?similarity,
        linked_files = stats.linked_files,
        linked_bytes = stats.linked_bytes,
        copied_chunks = stats.copied_chunks,
        written_chunks = stats.written_chunks,
        import_ms,
        materialize_ms = started.elapsed().as_millis() as u64,
        lazy_disks = lazy,
        "chunked checkpoint prepared for restore"
    );
    Ok(Some(shared))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_held_checkpoint_stands_in_only_for_the_same_index() {
        let held = tempfile::TempDir::new().unwrap();
        std::fs::write(held.path().join("checkpoint.json"), b"{\"genuine\":1}").unwrap();
        let same = store::index_digest(held.path()).unwrap();
        ensure_same_checkpoint("id", &same, held.path()).unwrap();

        let forged = tempfile::TempDir::new().unwrap();
        std::fs::write(forged.path().join("checkpoint.json"), b"{\"forged\":1}").unwrap();
        let other = store::index_digest(forged.path()).unwrap();
        let error = ensure_same_checkpoint("id", &other, held.path()).unwrap_err();
        assert!(
            error.to_string().contains("different checkpoint"),
            "{error}"
        );
    }

    #[test]
    fn a_record_names_only_the_tree_it_was_written_for() {
        const ID: &str = "0123456789abcdef0123456789abcdef";
        let root = tempfile::TempDir::new().unwrap();
        let store = root.path().join("store");
        let tree = root.path().join("_shared").join("0000beef");
        std::fs::create_dir_all(store.join("materialized")).unwrap();
        std::fs::create_dir_all(&tree).unwrap();
        let token = write_materialized_token(&tree).unwrap();
        smolvm_pack::extract::mark_extracted(&tree).unwrap();
        let record = materialized_record(&store, ID).unwrap();
        let write_record = |body: String| std::fs::write(&record, body).unwrap();

        write_record(format!("{}\n{token}\n", tree.display()));
        assert_eq!(materialized_tree(&store, ID), Some(tree.clone()));

        // A record from before tokens, or naming another token, is ignored.
        write_record(format!("{}\n", tree.display()));
        assert_eq!(materialized_tree(&store, ID), None);
        write_record(format!("{}\n{}\n", tree.display(), "f".repeat(32)));
        assert_eq!(materialized_tree(&store, ID), None);

        // The tree evicted and another extracted at the same path.
        write_record(format!("{}\n{token}\n", tree.display()));
        std::fs::remove_dir_all(&tree).unwrap();
        std::fs::create_dir_all(&tree).unwrap();
        smolvm_pack::extract::mark_extracted(&tree).unwrap();
        assert_eq!(materialized_tree(&store, ID), None);
        write_materialized_token(&tree).unwrap();
        assert_eq!(materialized_tree(&store, ID), None);
    }

    #[test]
    fn no_record_path_is_built_for_an_id_of_another_form() {
        let store = Path::new("/store");
        assert!(materialized_record(store, "/dev/zero").is_none());
        assert!(materialized_record(store, "../x").is_none());
        assert_eq!(
            materialized_record(store, "0123456789abcdef0123456789abcdef"),
            Some(store.join("materialized/0123456789abcdef0123456789abcdef"))
        );
    }
}
