//! Keeps a live-branch source's disk chain shallow.
//!
//! Every live branch freezes the source's active qcow2 into a generation layer and
//! stacks a fresh overlay on it, so a source branched many times would grow its
//! chain without bound. The newest generation stays writable until its branch
//! pivots the VMM onto the new overlay; every generation below it is immutable.
//! Once the chain reaches [`COMPACT_AT_DEPTH`], the newest immutable generation is
//! flattened: its content, and everything beneath it, is written into one new file
//! backed by the disk the machine started from, which then replaces it at the same
//! path by an atomic rename. Every chain that names that path reads the same bytes
//! through a short chain from then on, and nothing ever copies a layer a VMM can
//! still write. A process that already opened the old file keeps reading it, and
//! nothing a branch made earlier is deleted while a chain still reaches it.

use super::qcow2_backing_name;
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

/// A file that marks a merge as running to every process until dropped.
struct Busy(PathBuf);

impl Busy {
    fn announce(path: PathBuf) -> Result<Self> {
        std::fs::write(&path, b"").map_err(|e| compact_err("announce merge", e))?;
        Ok(Busy(path))
    }
}

impl Drop for Busy {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Holds a disk's place in [`IN_FLIGHT`] until dropped.
struct Claim(PathBuf);

impl Claim {
    fn take(key: PathBuf) -> Option<Self> {
        let mut guard = IN_FLIGHT.lock().unwrap_or_else(|e| e.into_inner());
        // Build the claim only once the key is ours: a `Claim` dropped here,
        // while `guard` still holds `IN_FLIGHT`, would relock it from its own
        // `Drop` and deadlock this thread and every later merge or layer GC.
        if guard.get_or_insert_with(HashSet::new).insert(key.clone()) {
            Some(Claim(key))
        } else {
            None
        }
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

/// The ranges of a raw image that hold data, from the filesystem's own
/// allocation map. A file system without one reports the whole file as data.
fn raw_data_ranges(path: &Path, size: u64, into: &mut Vec<(u64, u64)>) -> Result<()> {
    use std::os::unix::io::AsRawFd;
    let file = std::fs::File::open(path).map_err(|e| compact_err("open raw layer", e))?;
    let fd = file.as_raw_fd();
    let end = size.min(
        file.metadata()
            .map_err(|e| compact_err("stat raw", e))?
            .len(),
    );
    let mut offset: u64 = 0;
    while offset < end {
        // SAFETY: fd is open for the lifetime of `file`; lseek takes no pointers.
        let data = unsafe { libc::lseek(fd, offset as libc::off_t, libc::SEEK_DATA) };
        if data < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENXIO) {
                break;
            }
            into.push((offset, end));
            return Ok(());
        }
        // SAFETY: as above.
        let hole = unsafe { libc::lseek(fd, data, libc::SEEK_HOLE) };
        let hole = if hole < 0 {
            end
        } else {
            (hole as u64).min(end)
        };
        if hole <= data as u64 {
            break;
        }
        into.push((data as u64, hole));
        offset = hole;
    }
    Ok(())
}

/// Write `out` as one self-contained qcow2 that reads exactly as `top` does:
/// no backing file, so it can serve as a new base on its own. Only ranges some
/// layer of the chain holds are copied, and all-zero chunks are left
/// unallocated, so the result is no larger than the data it carries.
pub(crate) fn flatten_standalone(top: &Path, out: &Path) -> Result<()> {
    let layers = chain(top)?;
    let view = open_readonly(top, true)?;
    let size = view.size();
    let mut ranges = Vec::new();
    for layer in &layers {
        if is_qcow2(layer)? {
            defined_ranges(layer, size, &mut ranges)?;
        } else {
            raw_data_ranges(layer, size, &mut ranges)?;
        }
    }
    runtime()?
        .block_on(async {
            let storage =
                ImagoFile::create_open(StorageCreateOptions::new().filename(out).size(0)).await?;
            Qcow2::<ImagoFile>::create_builder(storage)
                .size(size)
                .create()
                .await
        })
        .map_err(|e| compact_err(&format!("create {}", out.display()), e))?;
    let result = (|| {
        let qcow = Qcow2::<ImagoFile>::builder_path(out)
            .data_file(None)
            .backing(None)
            .write(true)
            .open_sync(PermissiveImplicitOpenGate::default())
            .map_err(|e| compact_err("open flattened image", e))?;
        let writer = SyncFormatAccess::new(qcow).map_err(|e| compact_err("wrap flattened", e))?;
        let mut buffer = vec![0_u8; COPY_CHUNK as usize];
        for (start, end) in coalesce(ranges) {
            let mut offset = start;
            while offset < end {
                let length = (end - offset).min(COPY_CHUNK);
                let chunk = &mut buffer[..length as usize];
                view.read(&mut *chunk, offset)
                    .map_err(|e| compact_err("read chain", e))?;
                if chunk.iter().any(|byte| *byte != 0) {
                    writer
                        .write(&*chunk, offset)
                        .map_err(|e| compact_err("write data", e))?;
                }
                offset += length;
            }
        }
        writer
            .flush()
            .map_err(|e| compact_err("flush flattened", e))?;
        writer.sync().map_err(|e| compact_err("sync flattened", e))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(out);
    }
    result
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

/// The immutable layer to flatten in `live`'s chain and the layer it is flattened
/// onto, or `None` while the chain is no deeper than `threshold`.
///
/// `live` is the one layer a VMM may still write (the active disk, or the
/// generation a branch has just renamed it into), so the target is the layer
/// right beneath it: the newest generation whose branch has committed. It is
/// flattened onto the first layer of the chain that is not a generation.
fn flatten_target(
    gdir: &Path,
    id: &str,
    live: &Path,
    threshold: usize,
) -> Result<Option<(PathBuf, PathBuf)>> {
    if !is_qcow2(live)? {
        return Ok(None);
    }
    let layers = chain(live)?;
    if layers.len() <= threshold || layers.len() < 3 {
        return Ok(None);
    }
    let gdir_d = gdir
        .join("d")
        .canonicalize()
        .map_err(|e| compact_err("resolve d", e))?;
    let target = &layers[1];
    if !is_generation_layer(&gdir_d, id, target) {
        return Ok(None);
    }
    let Some(root) = layers[2..]
        .iter()
        .find(|layer| !is_generation_layer(&gdir_d, id, layer))
    else {
        return Ok(None);
    };
    // Already flat: the target sits directly on the root.
    if layers.get(2) == Some(root) {
        return Ok(None);
    }
    Ok(Some((target.clone(), root.clone())))
}

/// Flatten the newest immutable generation in the background when `live`'s
/// chain is deep and no flatten for this disk is running. Called once a branch
/// has renamed the active disk into `live`, which stays writable until the pivot.
pub(super) fn maybe_start_compaction(
    gdir: &Path,
    id: &str,
    live: &Path,
    vm_ids: Option<(u32, u32)>,
) -> Result<()> {
    let Some((target, root)) = flatten_target(gdir, id, live, COMPACT_AT_DEPTH)? else {
        return Ok(());
    };
    let gdir_d = gdir
        .join("d")
        .canonicalize()
        .map_err(|e| compact_err("resolve d", e))?;
    let Some(claim) = Claim::take(gdir_d.join(id)) else {
        return Ok(());
    };
    let (gdir, id) = (gdir.to_path_buf(), id.to_string());
    std::thread::Builder::new()
        .name("fork-disk-compact".into())
        .spawn(move || {
            let _claim = claim;
            if let Err(error) = flatten_in_place(&gdir, &id, &target, &root, vm_ids) {
                tracing::warn!(disk = %target.display(), %error, "could not flatten a branch source's disk chain");
            }
        })
        .map_err(|e| compact_err("start flatten", e))?;
    Ok(())
}

/// Flatten before the source freezes when its chain is near the hard limit and
/// no flatten is running, so a process that exits right after branching (the
/// CLI) still keeps the chain short. The source keeps running meanwhile: only
/// layers beneath its active disk are read.
pub(super) fn compact_if_near_limit(gdir: &Path, vm_ids: Option<(u32, u32)>) -> Result<()> {
    for (id, raw) in [
        ("storage", crate::data::storage::STORAGE_DISK_FILENAME),
        ("overlay", crate::data::storage::OVERLAY_DISK_FILENAME),
    ] {
        let (active, _) = crate::agent::resolve_disk_image(gdir, raw);
        if !active.is_file() {
            continue;
        }
        let Some((target, root)) = flatten_target(gdir, id, &active, SYNC_COMPACT_AT_DEPTH)? else {
            continue;
        };
        let gdir_d = gdir
            .join("d")
            .canonicalize()
            .map_err(|e| compact_err("resolve d", e))?;
        let Some(_claim) = Claim::take(gdir_d.join(id)) else {
            continue;
        };
        flatten_in_place(gdir, id, &target, &root, vm_ids)?;
    }
    Ok(())
}

/// Replace the immutable `target` with one file holding the same bytes, backed
/// directly by `root`: written beside it, given its owner and mode, synced, then
/// renamed over it. Readers that already opened `target` keep the old file.
fn flatten_in_place(
    gdir: &Path,
    id: &str,
    target: &Path,
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
    // Announce the flatten before reading any layer, so a collection in another
    // process keeps every layer from the first read on.
    let _busy = Busy::announce(dir.join(format!("{id}.{stamp}.busy")))?;
    let partial = target.with_file_name(format!(
        "{}.{stamp}.flatten.partial",
        target
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("layer")
    ));
    let result = (|| -> Result<()> {
        merge_onto(target, root, root, &partial)?;
        let meta = std::fs::metadata(target).map_err(|e| compact_err("stat target", e))?;
        std::fs::set_permissions(&partial, meta.permissions())
            .map_err(|e| compact_err("copy mode", e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if let Some((uid, gid)) = vm_ids.or(Some((meta.uid(), meta.gid()))) {
                let current =
                    std::fs::metadata(&partial).map_err(|e| compact_err("stat flat", e))?;
                if (current.uid(), current.gid()) != (uid, gid) {
                    std::os::unix::fs::chown(&partial, Some(uid), Some(gid))
                        .map_err(|e| compact_err("hand flat layer to its owner", e))?;
                }
            }
        }
        #[cfg(not(unix))]
        let _ = vm_ids;
        std::fs::rename(&partial, target).map_err(|e| compact_err("publish flat layer", e))?;
        if let Some(parent) = target.parent() {
            std::fs::File::open(parent)
                .and_then(|d| d.sync_all())
                .map_err(|e| compact_err("sync layer dir", e))?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&partial);
    }
    result?;
    tracing::info!(
        disk = %target.display(),
        elapsed_ms = started.elapsed().as_millis() as u64,
        "flattened a branch source's disk chain"
    );
    Ok(())
}

/// How long a merge may be in progress before its partial file is taken as left
/// behind by a process that died.
const STALE_PARTIAL: std::time::Duration = std::time::Duration::from_secs(3600);

/// Every disk layer some machine can still read: the chains under every machine's
/// active disks and every retained branch snapshot's recorded bases. `None` when
/// a chain cannot be read, which keeps everything.
fn reachable_layers(machine_dirs: &[PathBuf]) -> Option<HashSet<PathBuf>> {
    let mut reachable = HashSet::new();
    let mut walk = |top: &Path| -> Option<()> {
        reachable.extend(chain(top).ok()?);
        Some(())
    };
    for dir in machine_dirs {
        for raw in [
            crate::data::storage::STORAGE_DISK_FILENAME,
            crate::data::storage::OVERLAY_DISK_FILENAME,
        ] {
            let (active, _) = crate::agent::resolve_disk_image(dir, raw);
            if active.exists() {
                walk(&active)?;
            }
        }
        let Ok(snapshots) = std::fs::read_dir(dir.join("s")) else {
            continue;
        };
        for snapshot in snapshots.flatten() {
            let Ok(listing) = std::fs::read_to_string(snapshot.path().join("generation-disks.tsv"))
            else {
                continue;
            };
            for line in listing.lines() {
                if let Some(base) = line.split('\t').nth(1) {
                    walk(Path::new(base))?;
                }
            }
        }
    }
    Some(reachable)
}

/// Whether a merge for this source is running here or, judging by a fresh partial
/// file, in another process. A partial older than [`STALE_PARTIAL`] is removed.
fn merge_in_progress(gdir_d: &Path) -> bool {
    {
        let guard = IN_FLIGHT.lock().unwrap_or_else(|e| e.into_inner());
        if guard
            .as_ref()
            .is_some_and(|set| set.iter().any(|key| key.starts_with(gdir_d)))
        {
            return true;
        }
    }
    let Ok(entries) = std::fs::read_dir(gdir_d.join("c")) else {
        return false;
    };
    let mut running = false;
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.to_string_lossy();
        if !name.ends_with(".partial") && !name.ends_with(".busy") {
            continue;
        }
        let age = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|modified| modified.elapsed().ok());
        match age {
            Some(age) if age > STALE_PARTIAL => {
                let _ = std::fs::remove_file(&path);
            }
            _ => running = true,
        }
    }
    running
}

/// Delete the disk layers under `gdir/d` that no machine can read any more, given
/// the data directories of every machine on this host. Returns how many files went.
pub(super) fn collect_unreachable_layers(gdir: &Path, machine_dirs: &[PathBuf]) -> Result<usize> {
    let Ok(gdir_d) = gdir.join("d").canonicalize() else {
        return Ok(0);
    };
    if merge_in_progress(&gdir_d) {
        return Ok(0);
    }
    // A merge marker left by an earlier release names a merge nothing adopts
    // any more; drop it so the merged file goes once no chain reaches it.
    if let Ok(entries) = std::fs::read_dir(gdir_d.join("c")) {
        for entry in entries.flatten() {
            if entry.path().extension().and_then(|e| e.to_str()) == Some("ready") {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
    let Some(reachable) = reachable_layers(machine_dirs) else {
        tracing::debug!(gdir = %gdir.display(), "kept every disk layer: a chain could not be read");
        return Ok(0);
    };
    let mut removed = 0;
    let entries = std::fs::read_dir(&gdir_d).map_err(|e| compact_err("list layers", e))?;
    for entry in entries.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        let is_compact = dir.file_name().is_some_and(|n| n == "c");
        let is_generation = super::snapshot_generation_id(&dir).is_some();
        if !is_compact && !is_generation {
            continue;
        }
        removed += remove_unreachable_files(&dir, &reachable, is_compact)?;
        if is_generation {
            // Only succeeds once nothing in it is reachable.
            let _ = std::fs::remove_dir(&dir);
        }
    }
    if removed > 0 {
        tracing::info!(gdir = %gdir.display(), removed, "removed disk layers no machine reads");
    }
    Ok(removed)
}

fn remove_unreachable_files(
    dir: &Path,
    reachable: &HashSet<PathBuf>,
    layers_only: bool,
) -> Result<usize> {
    let mut removed = 0;
    let entries = std::fs::read_dir(dir).map_err(|e| compact_err("list layer dir", e))?;
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() {
            removed += remove_unreachable_files(&path, reachable, layers_only)?;
            let _ = std::fs::remove_dir(&path);
            continue;
        }
        // In the merge directory only finished layers go; markers and partials stay.
        if layers_only && path.extension().and_then(|e| e.to_str()) != Some("qcow2") {
            continue;
        }
        let canonical = path
            .canonicalize()
            .map_err(|e| compact_err("resolve layer", e))?;
        if !reachable.contains(&canonical) {
            std::fs::remove_file(&path).map_err(|e| compact_err("remove layer", e))?;
            removed += 1;
        }
    }
    Ok(removed)
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

    /// A machine dir laid out as live branching leaves it: a raw root, then one
    /// generation layer per branch under `d/<8 hex>/storage.base.qcow2`, each
    /// backed by the one before and each writing a cluster, then the live top.
    fn branched_machine(dir: &Path, generations: usize) -> (PathBuf, PathBuf, Vec<PathBuf>) {
        let gdir = dir.join("vm");
        std::fs::create_dir_all(gdir.join("d")).unwrap();
        let root = gdir.join("storage.raw");
        let mut bytes = vec![0_u8; SIZE as usize];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = (i / CLUSTER as usize) as u8 | 1;
        }
        std::fs::write(&root, bytes).unwrap();
        let mut below = root.canonicalize().unwrap();
        let mut gens = Vec::new();
        for n in 0..generations {
            let path = gdir
                .join("d")
                .join(format!("{n:08x}"))
                .join("storage.base.qcow2");
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            create_overlay(&path, SIZE, &below).unwrap();
            let access = writable(&path);
            let at = (n as u64 * 3 % (SIZE / CLUSTER)) * CLUSTER;
            access
                .write(&vec![0x40 + n as u8; 4096][..], at + 512)
                .unwrap();
            access.flush().unwrap();
            drop(access);
            below = path.canonicalize().unwrap();
            gens.push(below.clone());
        }
        let live = gdir.join("storage.qcow2");
        create_overlay(&live, SIZE, &below).unwrap();
        (gdir, live.canonicalize().unwrap(), gens)
    }

    /// The layer flattened is the one right beneath the writable top, onto the
    /// first layer that is not a generation; a shallow chain is left alone.
    #[test]
    fn the_newest_immutable_generation_is_the_flatten_target() {
        let dir = tempfile::tempdir().unwrap();
        let (gdir, live, gens) = branched_machine(dir.path(), 20);
        let (target, root) = flatten_target(&gdir, "storage", &live, COMPACT_AT_DEPTH)
            .unwrap()
            .unwrap();
        assert_eq!(&target, gens.last().unwrap(), "never the live layer itself");
        assert_eq!(root, gdir.join("storage.raw").canonicalize().unwrap());
        assert!(flatten_target(&gdir, "storage", &live, 64)
            .unwrap()
            .is_none());
    }

    /// Writes keep landing on the live layer while the layer beneath it is
    /// flattened, and none is lost: the chain afterwards is three files deep and
    /// reads the same as before, plus every write made meanwhile.
    #[test]
    fn writes_to_the_live_layer_during_a_flatten_are_never_lost() {
        let dir = tempfile::tempdir().unwrap();
        let (gdir, live, gens) = branched_machine(dir.path(), 20);
        let before = read_all(&live);
        let (target, root) = flatten_target(&gdir, "storage", &live, COMPACT_AT_DEPTH)
            .unwrap()
            .unwrap();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let writer = {
            let (live, stop) = (live.clone(), stop.clone());
            std::thread::spawn(move || {
                let access = writable(&live);
                let mut written = Vec::new();
                let mut n = 0_u64;
                while !stop.load(std::sync::atomic::Ordering::SeqCst) || n < 64 {
                    let at = (n % (SIZE / CLUSTER)) * CLUSTER + 1024;
                    let stamp = (n as u32).to_le_bytes();
                    access.write(&stamp[..], at).unwrap();
                    access.flush().unwrap();
                    written.push((at, stamp));
                    n += 1;
                }
                written
            })
        };
        flatten_in_place(&gdir, "storage", &target, &root, None).unwrap();
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let written = writer.join().unwrap();

        assert_eq!(
            chain(&live).unwrap().len(),
            3,
            "live, flattened layer, root"
        );
        let after = read_all(&live);
        let mut expected = before;
        for (at, stamp) in &written {
            expected[*at as usize..*at as usize + 4].copy_from_slice(stamp);
        }
        assert_eq!(
            after, expected,
            "every write made during the flatten survives"
        );
        assert_eq!(
            gens.last().unwrap(),
            &target,
            "the flattened file kept its path"
        );
    }

    /// A reader that opened the target before the flatten keeps the old file and
    /// reads the same bytes it always did.
    #[test]
    fn an_open_reader_keeps_the_file_it_opened() {
        let dir = tempfile::tempdir().unwrap();
        let (gdir, live, _) = branched_machine(dir.path(), 20);
        let (target, root) = flatten_target(&gdir, "storage", &live, COMPACT_AT_DEPTH)
            .unwrap()
            .unwrap();
        let opened = open_readonly(&target, true).unwrap();
        let mut old = vec![0_u8; opened.size() as usize];
        opened.read(&mut old[..], 0).unwrap();
        flatten_in_place(&gdir, "storage", &target, &root, None).unwrap();
        let mut again = vec![0_u8; opened.size() as usize];
        opened.read(&mut again[..], 0).unwrap();
        assert_eq!(again, old);
        assert_eq!(read_all(&target), old, "the new file reads the same");
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

    /// A layer goes once no machine's chain, retained snapshot or pending merge
    /// reaches it; everything something can still read stays.
    #[test]
    fn only_layers_nothing_reads_are_collected() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let branch = tmp.path().join("branch");
        for dir in [&source, &branch] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let root = source.join("storage.raw");
        std::fs::write(&root, vec![0_u8; SIZE as usize]).unwrap();
        let layer = |path: PathBuf, below: &Path| {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            create_overlay(&path, SIZE, below).unwrap();
            path.canonicalize().unwrap()
        };
        let a = layer(source.join("d/aaaaaaaa/storage.base.qcow2"), &root);
        let b = layer(source.join("d/bbbbbbbb/storage.base.qcow2"), &a);
        let compacted = layer(source.join("d/c/storage.1.qcow2"), &root);
        let merged = layer(source.join("d/cccccccc/storage.merged.qcow2"), &compacted);
        layer(source.join("storage.qcow2"), &merged);
        layer(branch.join("storage.qcow2"), &a);

        let both = [source.clone(), branch.clone()];
        assert_eq!(collect_unreachable_layers(&source, &both).unwrap(), 1);
        assert!(
            !b.exists() && !source.join("d/bbbbbbbb").exists(),
            "the orphaned generation goes"
        );
        for kept in [&a, &compacted, &merged, &root] {
            assert!(kept.exists(), "{} is still read", kept.display());
        }

        // A retained snapshot pins its recorded base even with no machine on it.
        let pinned = layer(source.join("d/dddddddd/storage.base.qcow2"), &a);
        std::fs::create_dir_all(source.join("s/dddddddd")).unwrap();
        std::fs::write(
            source.join("s/dddddddd/generation-disks.tsv"),
            format!("storage.raw\t{}\tqcow2\n", pinned.display()),
        )
        .unwrap();
        assert_eq!(collect_unreachable_layers(&source, &both).unwrap(), 0);
        assert!(pinned.exists());

        // An announced merge keeps everything too, before it has written a byte.
        std::fs::write(source.join("d/c/storage.3.busy"), b"").unwrap();
        assert_eq!(
            collect_unreachable_layers(&source, std::slice::from_ref(&source)).unwrap(),
            0
        );
        std::fs::remove_file(source.join("d/c/storage.3.busy")).unwrap();

        // A merge in progress keeps everything, whatever looks unreachable.
        std::fs::remove_dir_all(source.join("s")).unwrap();
        std::fs::write(source.join("d/c/storage.2.qcow2.partial"), b"").unwrap();
        assert_eq!(
            collect_unreachable_layers(&source, std::slice::from_ref(&source)).unwrap(),
            0
        );
        std::fs::remove_file(source.join("d/c/storage.2.qcow2.partial")).unwrap();

        // With the branch gone, the generation only it read goes as well.
        assert_eq!(
            collect_unreachable_layers(&source, std::slice::from_ref(&source)).unwrap(),
            2
        );
        assert!(!a.exists() && !pinned.exists());
        assert!(merged.exists() && compacted.exists());
    }

    /// A second claim on a disk whose merge is running is refused, and the
    /// refusal neither blocks the caller nor releases the first claim.
    #[test]
    fn a_second_claim_on_a_busy_disk_is_refused_without_blocking() {
        let key = PathBuf::from("/claim-test/d/storage");
        let first = Claim::take(key.clone()).expect("first claim");
        let (done, outcome) = std::sync::mpsc::channel();
        let contender = key.clone();
        std::thread::spawn(move || {
            let _ = done.send(Claim::take(contender).is_none());
        });
        let refused = outcome
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("a contended claim returns instead of deadlocking");
        assert!(refused, "the running merge keeps the disk");
        assert!(merge_in_progress(Path::new("/claim-test/d")));
        drop(first);
        assert!(
            Claim::take(key).is_some(),
            "the disk is free once the merge ends"
        );
    }

    #[test]
    fn overlapping_ranges_coalesce() {
        assert_eq!(
            coalesce(vec![(5, 9), (0, 2), (1, 4), (9, 10)]),
            vec![(0, 4), (5, 10)]
        );
    }
}
