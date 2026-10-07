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
fn materialized_record(store: &Path, id: &str) -> PathBuf {
    store.join("materialized").join(id)
}

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
/// otherwise a complete chunked file.
pub fn capture(
    name: &str,
    artifact: &Path,
    release_source: impl FnOnce(),
) -> Result<IncrementalCapture> {
    let store = node_store();
    let published = published_dir(&store);
    std::fs::create_dir_all(&published).map_err(io("create checkpoint store"))?;
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
        Some(parent) => held_checkpoint(&store, parent)?,
        None => None,
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

/// Read-only files of the materialized tree of checkpoint `parent`, by inode,
/// so a capture of a machine restored from it skips re-reading its shared
/// disk bases. Empty when this node has no untouched tree of it.
#[cfg(unix)]
pub fn known_files_for(store: &Path, parent: &str) -> store::KnownFiles {
    let tree = std::fs::read_to_string(materialized_record(store, parent))
        .ok()
        .map(|tree| PathBuf::from(tree.trim()))
        .filter(|tree| smolvm_pack::extract::is_extracted(tree));
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

/// How a chunked checkpoint file became available on this node.
#[derive(Debug, Clone, Default)]
pub struct Imported {
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
    if let Some(directory) = held_checkpoint(&store, &id)? {
        return Ok(Some(Imported {
            id,
            directory,
            base: checkpoint.base.as_ref().map(|base| base.id.clone()),
            already_held: true,
            ..Default::default()
        }));
    }
    let base = match checkpoint.base.as_ref() {
        Some(base) => {
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
    let published = published_dir(&store);
    std::fs::create_dir_all(&published).map_err(io("create checkpoint store"))?;
    let directory = published.join(format!("{id}.checkpoint"));
    match store::publish(&unpacked, &directory) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
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
        id,
        directory,
        base_objects,
        base: base.map(|(id, _)| id),
        already_held: false,
    }))
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
    if smolvm_pack::extract::is_extracted(&shared) {
        let manifest = smolvm_pack::packer::read_manifest_from_sidecar(artifact)
            .map_err(|e| Error::agent("read checkpoint manifest", e.to_string()))?;
        if manifest
            .checkpoint
            .as_ref()
            .is_some_and(|c| c.payload == smolvm_pack::format::CheckpointLayout::Chunked)
        {
            return Ok(Some(shared));
        }
        return Ok(None);
    }
    let started = std::time::Instant::now();
    let Some(imported) = import(artifact)? else {
        return Ok(None);
    };
    let import_ms = started.elapsed().as_millis() as u64;
    let store = node_store();
    // The nearest ancestor this node has materialized and still holds.
    let mut base_tree = None;
    let mut cursor = store::find_lineage(&store, &imported.id)
        .map_err(io("read checkpoint lineage"))?
        .and_then(|record| record.parent);
    for _ in 0..64 {
        let Some(id) = cursor else { break };
        if let (Ok(tree), Some(stored)) = (
            std::fs::read_to_string(materialized_record(&store, &id)),
            held_checkpoint(&store, &id)?,
        ) {
            let tree = PathBuf::from(tree.trim());
            if smolvm_pack::extract::is_extracted(&tree) {
                base_tree = Some((stored, tree));
                break;
            }
        }
        cursor = store::find_lineage(&store, &id)
            .map_err(io("read checkpoint lineage"))?
            .and_then(|record| record.parent);
    }
    std::fs::create_dir_all(&shared_root).map_err(io("create shared extraction root"))?;
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
    let stats = store::materialize_over(
        &imported.directory,
        &partial,
        base_tree.as_ref().map(|(s, t)| (s.as_path(), t.as_path())),
    )
    .map_err(|error| {
        let _ = std::fs::remove_dir_all(&partial);
        Error::agent("materialize checkpoint", error.to_string())
    })?;
    smolvm_pack::extract::mark_extracted(&partial).map_err(io("mark checkpoint extracted"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&partial, std::fs::Permissions::from_mode(0o700));
    }
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
    let record = materialized_record(&store, &imported.id);
    if let Some(parent) = record.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&record, shared.to_string_lossy().as_bytes());
    tracing::info!(
        id = %imported.id,
        delta_base = ?imported.base,
        already_held = imported.already_held,
        base_objects = imported.base_objects,
        materialize_base = ?base_tree.as_ref().map(|(_, tree)| tree.display().to_string()),
        linked_files = stats.linked_files,
        linked_bytes = stats.linked_bytes,
        copied_chunks = stats.copied_chunks,
        written_chunks = stats.written_chunks,
        import_ms,
        materialize_ms = started.elapsed().as_millis() as u64,
        "chunked checkpoint prepared for restore"
    );
    Ok(Some(shared))
}
