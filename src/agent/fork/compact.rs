//! Keeps a live-branch source's disk chain shallow.
//!
//! Every live branch freezes the source's active qcow2 into a generation layer and
//! stacks a fresh overlay on it, so a source branched many times would grow its
//! chain without bound. Once the chain reaches [`COMPACT_AT_DEPTH`], a background
//! job merges the source's generation layers into one base backed by the disk the
//! machine started from. The next branch then copies only what was written since
//! that job began onto the merged base, and the source and its new branch stack on
//! that short chain instead. Nothing is deleted: branches made earlier keep reading
//! the layers they were created on.

use super::{atomic_write_snapshot_file, qcow2_backing_name};
use crate::{Error, Result};
use imago::file::File as ImagoFile;
use imago::qcow2::Qcow2;
use imago::{
    FormatCreateBuilder, FormatDriverBuilder, Mapping, PermissiveImplicitOpenGate, Storage,
    StorageCreateOptions, SyncFormatAccess,
};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Chain depth at which a background merge starts. The hard refusal sits at
/// `MAX_FORK_DISK_CHAIN_DEPTH`; the gap is how many branches can land while the
/// merge runs.
pub(super) const COMPACT_AT_DEPTH: usize = 16;

/// Chain depth at which a branch merges before freezing the source when no merge
/// is ready or running. A process that exits right after branching, like the CLI,
/// never lets a background merge finish, so this keeps such sources under the limit.
pub(super) const SYNC_COMPACT_AT_DEPTH: usize = 24;

/// Bytes copied per read and write while merging.
const COPY_CHUNK: u64 = 4 << 20;

/// Disks with a merge running, so one source never runs two at once.
static IN_FLIGHT: Mutex<Option<HashSet<PathBuf>>> = Mutex::new(None);

/// Holds a disk's place in [`IN_FLIGHT`] until dropped.
struct Claim(PathBuf);

impl Claim {
    fn take(key: PathBuf) -> Option<Self> {
        let mut guard = IN_FLIGHT.lock().unwrap_or_else(|e| e.into_inner());
        guard
            .get_or_insert_with(HashSet::new)
            .insert(key.clone())
            .then_some(Claim(key))
    }
}

impl Drop for Claim {
    fn drop(&mut self) {
        let mut guard = IN_FLIGHT.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(set) = guard.as_mut() {
            set.remove(&self.0);
        }
    }
}

fn compact_err(context: &str, error: impl std::fmt::Display) -> Error {
    Error::agent("compact fork disk chain", format!("{context}: {error}"))
}

fn compact_dir(gdir: &Path) -> PathBuf {
    gdir.join("d").join("c")
}

fn marker_path(gdir: &Path, id: &str) -> PathBuf {
    compact_dir(gdir).join(format!("{id}.ready"))
}

fn is_qcow2(path: &Path) -> Result<bool> {
    use std::io::Read;
    let mut magic = [0_u8; 4];
    let mut file = std::fs::File::open(path).map_err(|e| compact_err("open layer", e))?;
    match file.read_exact(&mut magic) {
        Ok(()) => Ok(magic == *b"QFI\xfb"),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(compact_err("read layer", e)),
    }
}

/// The chain from `top` downward, each entry canonical, `top` first.
fn chain(top: &Path) -> Result<Vec<PathBuf>> {
    let mut layers = Vec::new();
    let mut current = top
        .canonicalize()
        .map_err(|e| compact_err("resolve layer", e))?;
    loop {
        if layers.contains(&current) {
            return Err(compact_err(
                "walk chain",
                format!("cycle at {}", current.display()),
            ));
        }
        layers.push(current.clone());
        if layers.len() > 4 * super::MAX_FORK_DISK_CHAIN_DEPTH {
            return Err(compact_err(
                "walk chain",
                "chain is deeper than any branch can make",
            ));
        }
        let Some(backing) = (if is_qcow2(&current)? {
            qcow2_backing_name(&current)?
        } else {
            None
        }) else {
            return Ok(layers);
        };
        let next = if backing.is_absolute() {
            backing
        } else {
            current
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(backing)
        };
        current = next
            .canonicalize()
            .map_err(|e| compact_err("resolve backing", e))?;
    }
}

/// A layer this module or a live branch wrote under the source's `d/`, which a
/// merge may fold. Anything else (the disk the machine started from, or backings
/// relocated from a restored checkpoint) is where a merge stops.
fn is_generation_layer(gdir_d: &Path, id: &str, layer: &Path) -> bool {
    if !layer.starts_with(gdir_d) {
        return false;
    }
    let Some(name) = layer.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let in_compact_dir = layer.parent().is_some_and(|p| p == gdir_d.join("c"));
    name == format!("{id}.base.qcow2")
        || name == format!("{id}.merged.qcow2")
        || (in_compact_dir && name.starts_with(&format!("{id}.")) && name.ends_with(".qcow2"))
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .map_err(|e| compact_err("start runtime", e))
}

fn open_readonly(path: &Path, with_backing: bool) -> Result<SyncFormatAccess<ImagoFile>> {
    let builder = Qcow2::<ImagoFile>::builder_path(path).data_file(None);
    let builder = if with_backing {
        builder
    } else {
        builder.backing(None)
    };
    let qcow = builder
        .open_sync(PermissiveImplicitOpenGate::default())
        .map_err(|e| compact_err(&format!("open {}", path.display()), e))?;
    SyncFormatAccess::new(qcow).map_err(|e| compact_err("wrap layer", e))
}

/// Create `out` as an empty qcow2 of `size` bytes backed by `backing`.
fn create_overlay(out: &Path, size: u64, backing: &Path) -> Result<()> {
    let format = if is_qcow2(backing)? { "qcow2" } else { "raw" };
    let backing = backing
        .to_str()
        .ok_or_else(|| compact_err("backing path", "not UTF-8"))?;
    runtime()?
        .block_on(async {
            let storage =
                ImagoFile::create_open(StorageCreateOptions::new().filename(out).size(0)).await?;
            Qcow2::<ImagoFile>::create_builder(storage)
                .size(size)
                .backing(backing.to_string(), format.to_string())
                .create()
                .await
        })
        .map_err(|e| compact_err(&format!("create {}", out.display()), e))
}

/// The guest ranges a layer itself defines (data, compressed data or an explicit
/// zero), as opposed to those it leaves to its backing.
fn defined_ranges(layer: &Path, size: u64, into: &mut Vec<(u64, u64)>) -> Result<()> {
    let access = open_readonly(layer, false)?;
    let mut offset = 0;
    while offset < size {
        let (mapping, length) = access
            .get_mapping_sync(offset, size - offset)
            .map_err(|e| compact_err("map layer", e))?;
        if length == 0 {
            break;
        }
        let defined = match mapping {
            Mapping::Raw { .. } | Mapping::Special { .. } => true,
            Mapping::Zero { explicit, .. } => explicit,
            Mapping::Eof { .. } => break,
            _ => true,
        };
        if defined {
            into.push((offset, offset + length));
        }
        offset += length;
    }
    Ok(())
}

fn coalesce(mut ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}

/// Write `out`, backed by `new_backing`, so it reads exactly as `top` does,
/// given that `new_backing` reads exactly as `stop` (a layer in `top`'s chain).
/// Only the ranges the layers above `stop` define are copied.
pub(super) fn merge_onto(top: &Path, stop: &Path, new_backing: &Path, out: &Path) -> Result<()> {
    let layers = chain(top)?;
    let stop = stop
        .canonicalize()
        .map_err(|e| compact_err("resolve stop", e))?;
    let above = layers
        .iter()
        .position(|layer| *layer == stop)
        .ok_or_else(|| compact_err("merge", format!("{} is not in the chain", stop.display())))?;
    let view = open_readonly(top, true)?;
    let size = view.size();
    let mut ranges = Vec::new();
    for layer in &layers[..above] {
        defined_ranges(layer, size, &mut ranges)?;
    }
    create_overlay(out, size, new_backing)?;
    let result = (|| {
        let qcow = Qcow2::<ImagoFile>::builder_path(out)
            .data_file(None)
            .write(true)
            .open_sync(PermissiveImplicitOpenGate::default())
            .map_err(|e| compact_err("open merged layer", e))?;
        let writer = SyncFormatAccess::new(qcow).map_err(|e| compact_err("wrap merged", e))?;
        let mut buffer = vec![0_u8; COPY_CHUNK as usize];
        for (start, end) in coalesce(ranges) {
            let mut offset = start;
            while offset < end {
                let length = (end - offset).min(COPY_CHUNK);
                let chunk = &mut buffer[..length as usize];
                view.read(&mut *chunk, offset)
                    .map_err(|e| compact_err("read chain", e))?;
                if chunk.iter().all(|byte| *byte == 0) {
                    writer
                        .write_zeroes(offset, length)
                        .map_err(|e| compact_err("write zeroes", e))?;
                } else {
                    writer
                        .write(&*chunk, offset)
                        .map_err(|e| compact_err("write data", e))?;
                }
                offset += length;
            }
        }
        writer.flush().map_err(|e| compact_err("flush merged", e))?;
        writer.sync().map_err(|e| compact_err("sync merged", e))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(out);
    }
    result
}

/// If a finished merge still covers part of `base`'s chain, write
/// `generation_dir/<id>.merged.qcow2` on it holding what was written since, and
/// return that path for the new overlays to stack on. Consumes the merge either way.
pub(super) fn adopt_compacted_base(
    gdir: &Path,
    id: &str,
    base: &Path,
    generation_dir: &Path,
) -> Result<Option<PathBuf>> {
    let marker = marker_path(gdir, id);
    let contents = match std::fs::read_to_string(&marker) {
        Ok(contents) => contents,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(compact_err("read merge marker", e)),
    };
    let _ = std::fs::remove_file(&marker);
    let mut lines = contents.lines();
    let (Some(compacted), Some(covers)) = (lines.next(), lines.next()) else {
        return Ok(None);
    };
    let (compacted, covers) = (Path::new(compacted), Path::new(covers));
    if !compacted.is_file() || !chain(base)?.iter().any(|layer| layer == covers) {
        return Ok(None);
    }
    let merged = generation_dir.join(format!("{id}.merged.qcow2"));
    merge_onto(base, covers, compacted, &merged)?;
    merged
        .canonicalize()
        .map(Some)
        .map_err(|e| compact_err("resolve merged layer", e))
}

/// Start a background merge of `base`'s generation layers when its chain is deep
/// and no merge for this disk is running or waiting to be adopted.
pub(super) fn maybe_start_compaction(
    gdir: &Path,
    id: &str,
    base: &Path,
    vm_ids: Option<(u32, u32)>,
) -> Result<()> {
    if !is_qcow2(base)? {
        return Ok(());
    }
    let layers = chain(base)?;
    if layers.len() <= COMPACT_AT_DEPTH || marker_path(gdir, id).is_file() {
        return Ok(());
    }
    let gdir_d = gdir
        .join("d")
        .canonicalize()
        .map_err(|e| compact_err("resolve d", e))?;
    let Some(root) = layers
        .iter()
        .find(|layer| !is_generation_layer(&gdir_d, id, layer))
    else {
        return Ok(());
    };
    let Some(claim) = Claim::take(gdir_d.join(id)) else {
        return Ok(());
    };
    let (gdir, id, top, root) = (
        gdir.to_path_buf(),
        id.to_string(),
        base.to_path_buf(),
        root.clone(),
    );
    std::thread::Builder::new()
        .name("fork-disk-compact".into())
        .spawn(move || {
            let _claim = claim;
            if let Err(error) = compact(&gdir, &id, &top, &root, vm_ids) {
                tracing::warn!(disk = %top.display(), %error, "could not compact a branch source's disk chain");
            }
        })
        .map_err(|e| compact_err("start merge", e))?;
    Ok(())
}

/// Merge before the source freezes when its chain is near the hard limit and no
/// merge is ready or running, so the branch about to happen adopts it. The source
/// keeps running meanwhile: every layer below its active disk is immutable.
pub(super) fn compact_if_near_limit(gdir: &Path, vm_ids: Option<(u32, u32)>) -> Result<()> {
    for (id, raw) in [
        ("storage", crate::data::storage::STORAGE_DISK_FILENAME),
        ("overlay", crate::data::storage::OVERLAY_DISK_FILENAME),
    ] {
        let (active, _) = crate::agent::resolve_disk_image(gdir, raw);
        if !active.is_file() || !is_qcow2(&active)? || marker_path(gdir, id).is_file() {
            continue;
        }
        let layers = chain(&active)?;
        if layers.len() <= SYNC_COMPACT_AT_DEPTH {
            continue;
        }
        let gdir_d = gdir
            .join("d")
            .canonicalize()
            .map_err(|e| compact_err("resolve d", e))?;
        let top = &layers[1];
        let Some(root) = layers[1..]
            .iter()
            .find(|layer| !is_generation_layer(&gdir_d, id, layer))
        else {
            continue;
        };
        if root == top {
            continue;
        }
        let Some(_claim) = Claim::take(gdir_d.join(id)) else {
            continue;
        };
        compact(gdir, id, top, root, vm_ids)?;
    }
    Ok(())
}

fn compact(
    gdir: &Path,
    id: &str,
    top: &Path,
    root: &Path,
    vm_ids: Option<(u32, u32)>,
) -> Result<()> {
    let started = std::time::Instant::now();
    let dir = compact_dir(gdir);
    std::fs::create_dir_all(&dir).map_err(|e| compact_err("create merge dir", e))?;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let partial = dir.join(format!("{id}.{stamp}.qcow2.partial"));
    let finished = dir.join(format!("{id}.{stamp}.qcow2"));
    merge_onto(top, root, root, &partial)?;
    std::fs::rename(&partial, &finished).map_err(|e| compact_err("publish merge", e))?;
    if let Some((uid, gid)) = vm_ids {
        #[cfg(target_os = "linux")]
        super::prepare_isolated_snapshot_permissions(&gdir.join("d"), &dir)
            .and_then(|()| crate::process::chown_tree(&dir, uid, gid))
            .map_err(|e| compact_err("hand merge to source VMM", e))?;
        #[cfg(not(target_os = "linux"))]
        let _ = (uid, gid);
    }
    let finished = finished
        .canonicalize()
        .map_err(|e| compact_err("resolve merge", e))?;
    let covers = top
        .canonicalize()
        .map_err(|e| compact_err("resolve merged top", e))?;
    atomic_write_snapshot_file(
        &marker_path(gdir, id),
        format!("{}\n{}\n", finished.display(), covers.display()).as_bytes(),
    )?;
    tracing::info!(
        disk = %covers.display(),
        elapsed_ms = started.elapsed().as_millis() as u64,
        "compacted a branch source's disk chain"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIZE: u64 = 8 << 20;
    const CLUSTER: u64 = 64 << 10;

    fn raw_root(dir: &Path) -> PathBuf {
        let path = dir.join("root.raw");
        let mut bytes = vec![0_u8; SIZE as usize];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = (i / CLUSTER as usize) as u8 | 1;
        }
        std::fs::write(&path, bytes).unwrap();
        path.canonicalize().unwrap()
    }

    fn writable(path: &Path) -> SyncFormatAccess<ImagoFile> {
        let qcow = Qcow2::<ImagoFile>::builder_path(path)
            .data_file(None)
            .write(true)
            .open_sync(PermissiveImplicitOpenGate::default())
            .unwrap();
        SyncFormatAccess::new(qcow).unwrap()
    }

    fn read_all(path: &Path) -> Vec<u8> {
        let access = open_readonly(path, true).unwrap();
        let mut bytes = vec![0_u8; access.size() as usize];
        access.read(&mut bytes[..], 0).unwrap();
        bytes
    }

    /// A stack of layers, each writing one cluster and zeroing another, the way a
    /// source branched many times leaves its disk.
    fn layered(dir: &Path, depth: usize) -> (PathBuf, Vec<PathBuf>) {
        let root = raw_root(dir);
        let mut below = root.clone();
        let mut layers = Vec::new();
        for n in 0..depth {
            let layer = dir.join(format!("l{n}.qcow2"));
            create_overlay(&layer, SIZE, &below).unwrap();
            let access = writable(&layer);
            let at = (n as u64 * 3 % (SIZE / CLUSTER)) * CLUSTER;
            access
                .write(&vec![0xA0 + n as u8; 4096][..], at + 512)
                .unwrap();
            access
                .write_zeroes(((n as u64 * 5 + 1) % (SIZE / CLUSTER)) * CLUSTER, CLUSTER)
                .unwrap();
            access.flush().unwrap();
            drop(access);
            below = layer.canonicalize().unwrap();
            layers.push(below.clone());
        }
        (root, layers)
    }

    #[test]
    fn a_merge_onto_the_root_reads_exactly_like_the_chain_it_replaces() {
        let dir = tempfile::tempdir().unwrap();
        let (root, layers) = layered(dir.path(), 20);
        let top = layers.last().unwrap();
        let merged = dir.path().join("merged.qcow2");
        merge_onto(top, &root, &root, &merged).unwrap();
        assert_eq!(read_all(&merged), read_all(top));
        assert_eq!(
            chain(&merged).unwrap().len(),
            2,
            "the merge sits directly on the root"
        );
    }

    #[test]
    fn adopting_a_merge_copies_only_what_was_written_since() {
        let dir = tempfile::tempdir().unwrap();
        let (root, layers) = layered(dir.path(), 20);
        // The background merge covered layer 15; layers 16..19 landed while it ran.
        let compacted = dir.path().join("compacted.qcow2");
        merge_onto(&layers[15], &root, &root, &compacted).unwrap();
        let top = layers.last().unwrap();
        let merged = dir.path().join("since.qcow2");
        merge_onto(top, &layers[15], &compacted, &merged).unwrap();
        assert_eq!(read_all(&merged), read_all(top));
        assert_eq!(chain(&merged).unwrap().len(), 3);
    }

    #[test]
    fn only_layers_written_under_d_are_folded() {
        let gdir_d = Path::new("/vms/m/d");
        assert!(is_generation_layer(
            gdir_d,
            "storage",
            Path::new("/vms/m/d/0123abcd/storage.base.qcow2")
        ));
        assert!(is_generation_layer(
            gdir_d,
            "storage",
            Path::new("/vms/m/d/0123abcd/storage.merged.qcow2")
        ));
        assert!(is_generation_layer(
            gdir_d,
            "storage",
            Path::new("/vms/m/d/c/storage.17.qcow2")
        ));
        assert!(!is_generation_layer(
            gdir_d,
            "storage",
            Path::new("/vms/m/d/0123abcd/.smolcheckpoint-storage-0.qcow2")
        ));
        assert!(!is_generation_layer(
            gdir_d,
            "storage",
            Path::new("/vms/m/storage.raw")
        ));
        assert!(!is_generation_layer(
            gdir_d,
            "overlay",
            Path::new("/vms/m/d/c/storage.17.qcow2")
        ));
    }

    #[test]
    fn overlapping_ranges_coalesce() {
        assert_eq!(
            coalesce(vec![(5, 9), (0, 2), (1, 4), (9, 10)]),
            vec![(0, 4), (5, 10)]
        );
    }
}
