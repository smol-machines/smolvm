//! Keeps a live-branch source's disk chain shallow.
//!
//! Every live branch freezes the source's active qcow2 into a generation layer and
//! stacks a fresh overlay on it, so a source branched many times would grow its
//! chain without bound. The newest generation stays writable until its branch
//! pivots the VMM onto the new overlay; every generation below it is immutable.
//! Once the chain reaches [`COMPACT_AT_DEPTH`], the newest immutable generation is
//! flattened: its content, and everything beneath it, is written into one new file
//! backed by the disk the machine started from, or standalone when that inherited
//! disk is itself deep, which then replaces it at the same path by an atomic
//! rename. A child may also flatten its ancestor's immutable generation. Every
//! chain that names that path reads the same bytes
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
use std::sync::{Condvar, Mutex};

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

/// Threads reading the chain while a flatten writes. A cloud disk serves one
/// sequential reader at a fraction of its throughput (256 MB/s against 2.1 GB/s
/// for sixteen on a worker's hyperdisk), and the chain's reads, not the writes,
/// set a flatten's pace. Each reader opens its own view of the chain.
const FLATTEN_READERS: usize = 16;

/// Disks with a merge running, so one source never runs two at once.
static IN_FLIGHT: Mutex<Option<HashSet<PathBuf>>> = Mutex::new(None);
static FINISHED: Condvar = Condvar::new();

/// A file that marks a merge as running to every process until dropped.
struct Busy(PathBuf);

impl Busy {
    fn announce(path: PathBuf) -> Result<Self> {
        std::fs::write(&path, std::process::id().to_string())
            .map_err(|e| compact_err("announce merge", e))?;
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

    fn wait(key: PathBuf) -> Self {
        let mut guard = IN_FLIGHT.lock().unwrap_or_else(|e| e.into_inner());
        while !guard.get_or_insert_with(HashSet::new).insert(key.clone()) {
            guard = FINISHED.wait(guard).unwrap_or_else(|e| e.into_inner());
        }
        Self(key)
    }
}

impl Drop for Claim {
    fn drop(&mut self) {
        let mut guard = IN_FLIGHT.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(set) = guard.as_mut() {
            set.remove(&self.0);
        }
        FINISHED.notify_all();
    }
}

fn lock_disk_gc(gdir: &Path, operation: libc::c_int) -> Result<Option<std::fs::File>> {
    use std::os::fd::AsRawFd;
    let parent = gdir
        .parent()
        .ok_or_else(|| compact_err("lock disk GC", "machine has no parent directory"))?;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(parent.join(".disk-chain-gc.lock"))
        .map_err(|error| compact_err("open disk GC lock", error))?;
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), operation) } == 0 {
            return Ok(Some(file));
        }
        let error = std::io::Error::last_os_error();
        match error.kind() {
            std::io::ErrorKind::Interrupted => continue,
            std::io::ErrorKind::WouldBlock => return Ok(None),
            _ => return Err(compact_err("lock disk GC", error)),
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

/// A layer this module or a live branch wrote under the source's `d/`, which may
/// be replaced in place. Other files may be read but must never be replaced.
fn is_generation_layer(gdir_d: &Path, id: &str, layer: &Path) -> bool {
    let Some(generation) = layer.parent() else {
        return false;
    };
    if generation.parent() != Some(gdir_d) {
        return false;
    }
    let Some(name) = layer.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    if generation.file_name().is_some_and(|name| name == "c") {
        name.starts_with(&format!("{id}.")) && name.ends_with(".qcow2")
    } else {
        super::snapshot_generation_id(generation).is_some()
            && (name == format!("{id}.base.qcow2") || name == format!("{id}.merged.qcow2"))
    }
}

fn generation_owner(id: &str, layer: &Path) -> Option<PathBuf> {
    let generation = layer.parent()?;
    let directory = generation.parent()?;
    if directory.file_name()? != "d"
        || !is_generation_layer(directory, id, layer)
        || (generation.file_name()? != "c" && super::snapshot_generation_id(generation).is_none())
    {
        return None;
    }
    Some(directory.parent()?.to_path_buf())
}

fn compaction_key(gdir: &Path, id: &str, target: &Path) -> PathBuf {
    generation_owner(id, target)
        .unwrap_or_else(|| gdir.to_path_buf())
        .join("d")
        .join(id)
}

fn disk_lock_path(owner: &Path, id: &str) -> PathBuf {
    let mut path = owner.as_os_str().to_os_string();
    path.push(format!(".compact-{id}.lock"));
    PathBuf::from(path)
}

pub(super) fn disk_lock_owner(path: &Path) -> Option<PathBuf> {
    let name = path.file_name()?.to_str()?;
    for (id, _) in super::FORK_DISK_ROLES {
        if let Some(owner) = name.strip_suffix(&format!(".compact-{id}.lock")) {
            if !owner.is_empty() {
                return Some(path.with_file_name(owner));
            }
        }
    }
    None
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
/// unallocated, so the result is no larger than the data it carries. Calls
/// `copied` after each chunk, so a caller can tell a long flatten from a
/// stuck one.
///
/// `out` holds its final bytes on return but is not yet durable: the caller
/// syncs it before relying on it surviving a crash. A publish reads the file
/// back for its hash and upload while that sync runs, rather than after it.
pub(crate) fn flatten_standalone(top: &Path, out: &Path, copied: &dyn Fn()) -> Result<()> {
    let ChainData { view, size, ranges } = chain_data(top)?;
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
    drop(view);
    let result = (|| {
        let qcow = Qcow2::<ImagoFile>::builder_path(out)
            .data_file(None)
            .backing(None)
            .write(true)
            .open_sync(PermissiveImplicitOpenGate::default())
            .map_err(|e| compact_err("open flattened image", e))?;
        let writer = SyncFormatAccess::new(qcow).map_err(|e| compact_err("wrap flattened", e))?;
        read_chain_parallel(top, coalesce(ranges), |offset, chunk| {
            if let Some(chunk) = chunk {
                writer
                    .write(chunk, offset)
                    .map_err(|e| compact_err("write data", e))?;
            }
            copied();
            Ok(())
        })?;
        writer
            .flush()
            .map_err(|e| compact_err("flush flattened", e))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(out);
    }
    result
}

/// Read `ranges` of `top`'s chain in [`COPY_CHUNK`] chunks with
/// [`FLATTEN_READERS`] threads, each over its own contiguous share, and hand
/// every chunk to `sink` on the calling thread, in no particular order:
/// `None` for an all-zero chunk, which a sparse copy leaves unallocated.
fn read_chain_parallel(
    top: &Path,
    ranges: Vec<(u64, u64)>,
    mut sink: impl FnMut(u64, Option<&[u8]>) -> Result<()>,
) -> Result<()> {
    let mut chunks = Vec::new();
    for (start, end) in ranges {
        let mut offset = start;
        while offset < end {
            let length = (end - offset).min(COPY_CHUNK);
            chunks.push((offset, length));
            offset += length;
        }
    }
    if chunks.is_empty() {
        return Ok(());
    }
    let layer_count = chain(top)?.len() as u64;
    let mut limits = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    let descriptor_budget =
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limits.as_mut_ptr()) } == 0 {
            unsafe { limits.assume_init() }.rlim_cur / 4
        } else {
            0
        };
    let readers = usize::try_from(descriptor_budget / layer_count)
        .unwrap_or(usize::MAX)
        .clamp(1, FLATTEN_READERS)
        .min(chunks.len());
    let per = chunks.len().div_ceil(readers);
    // Two chunks in hand per reader keeps every reader busy while the writer
    // drains, and bounds memory at a fixed number of chunks.
    let (send, receive) =
        std::sync::mpsc::sync_channel::<Result<(u64, Option<Vec<u8>>)>>(readers * 2);
    std::thread::scope(|scope| {
        for share in chunks.chunks(per) {
            let send = send.clone();
            scope.spawn(move || {
                let view = match open_readonly(top, true) {
                    Ok(view) => view,
                    Err(e) => {
                        let _ = send.send(Err(e));
                        return;
                    }
                };
                for &(offset, length) in share {
                    let mut chunk = vec![0_u8; length as usize];
                    let read = view
                        .read(&mut chunk[..], offset)
                        .map_err(|e| compact_err("read chain", e))
                        .map(|()| (offset, chunk.iter().any(|byte| *byte != 0).then_some(chunk)));
                    let failed = read.is_err();
                    // A closed channel means the writer stopped; so does this reader.
                    if send.send(read).is_err() || failed {
                        return;
                    }
                }
            });
        }
        drop(send);
        for received in receive {
            let (offset, chunk) = received?;
            sink(offset, chunk.as_deref())?;
        }
        Ok(())
    })
}

/// A read view of a whole chain, its size, and the ranges some layer of the
/// chain holds. Everything outside those ranges reads as zeros.
struct ChainData {
    view: SyncFormatAccess<ImagoFile>,
    size: u64,
    ranges: Vec<(u64, u64)>,
}

fn chain_data(top: &Path) -> Result<ChainData> {
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
    Ok(ChainData { view, size, ranges })
}

/// Write `out` as a sparse raw image that reads exactly as `top` does. Only
/// ranges some layer of the chain holds are read, and all-zero chunks stay
/// holes, so a mostly empty 20 GiB disk costs its data, not its size.
pub(crate) fn flatten_to_raw(top: &Path, out: &Path) -> Result<()> {
    use std::os::unix::fs::FileExt;
    let ChainData { view, size, ranges } = chain_data(top)?;
    let result = (|| {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(out)
            .map_err(|e| compact_err(&format!("create {}", out.display()), e))?;
        file.set_len(size)
            .map_err(|e| compact_err("size raw image", e))?;
        let mut buffer = vec![0_u8; COPY_CHUNK as usize];
        for (start, end) in coalesce(ranges) {
            let mut offset = start;
            while offset < end {
                let length = (end - offset).min(COPY_CHUNK);
                let chunk = &mut buffer[..length as usize];
                view.read(&mut *chunk, offset)
                    .map_err(|e| compact_err("read chain", e))?;
                if chunk.iter().any(|byte| *byte != 0) {
                    file.write_all_at(chunk, offset)
                        .map_err(|e| compact_err("write data", e))?;
                }
                offset += length;
            }
        }
        file.sync_all()
            .map_err(|e| compact_err("sync raw image", e))
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
/// below it: the nearest managed generation whose branch has committed. Frozen
/// ancestors' active disks are skipped, never replaced. A deep inherited root is
/// folded into a standalone target instead of retained.
fn flatten_target(
    gdir: &Path,
    id: &str,
    live: &Path,
    threshold: usize,
) -> Result<Option<(PathBuf, Option<PathBuf>)>> {
    if !is_qcow2(live)? {
        return Ok(None);
    }
    let layers = chain(live)?;
    if layers.len() <= threshold || layers.len() < 3 {
        return Ok(None);
    }
    let gdir_d = gdir
        .canonicalize()
        .map_err(|e| compact_err("resolve machine", e))?
        .join("d");
    let target = &layers[1];
    if !is_generation_layer(&gdir_d, id, target) {
        return Ok(layers[1..]
            .iter()
            .find(|layer| generation_owner(id, layer).is_some())
            .map(|target| (target.clone(), None)));
    }
    let Some(root) = layers[2..]
        .iter()
        .find(|layer| !is_generation_layer(&gdir_d, id, layer))
    else {
        return Ok(None);
    };
    let root_depth = layers.iter().position(|layer| layer == root).unwrap();
    if layers.len() - root_depth + 2 > COMPACT_AT_DEPTH {
        return Ok(Some((target.clone(), None)));
    }
    if layers.get(2) == Some(root) {
        return Ok(None);
    }
    Ok(Some((target.clone(), Some(root.clone()))))
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
    if matches!(flatten_target(gdir, id, live, COMPACT_AT_DEPTH), Ok(None)) {
        return Ok(());
    }
    let gc_guard = lock_disk_gc(gdir, libc::LOCK_SH)?;
    let Some((target, root)) = flatten_target(gdir, id, live, COMPACT_AT_DEPTH)? else {
        return Ok(());
    };
    let Some(claim) = Claim::take(compaction_key(gdir, id, &target)) else {
        return Ok(());
    };
    let (gdir, id) = (gdir.to_path_buf(), id.to_string());
    std::thread::Builder::new()
        .name("fork-disk-compact".into())
        .spawn(move || {
            let _gc_guard = gc_guard;
            let _claim = claim;
            if let Err(error) = flatten_in_place(&gdir, &id, &target, root.as_deref(), vm_ids) {
                tracing::warn!(disk = %target.display(), %error, "could not flatten a branch source's disk chain");
            }
        })
        .map_err(|e| compact_err("start flatten", e))?;
    Ok(())
}

/// Flatten before the source freezes when its chain is near the hard limit,
/// waiting for a running merge first. The source keeps running meanwhile: only
/// layers beneath its active disk are read.
pub(super) fn compact_if_near_limit(gdir: &Path, vm_ids: Option<(u32, u32)>) -> Result<()> {
    for (id, raw) in super::FORK_DISK_ROLES {
        let (active, _) = crate::agent::resolve_disk_image(gdir, raw);
        if !active.is_file() {
            continue;
        }
        if matches!(
            flatten_target(gdir, id, &active, SYNC_COMPACT_AT_DEPTH),
            Ok(None)
        ) {
            continue;
        }
        let _gc_guard = lock_disk_gc(gdir, libc::LOCK_SH)?;
        let Some((target, _)) = flatten_target(gdir, id, &active, SYNC_COMPACT_AT_DEPTH)? else {
            continue;
        };
        let _claim = Claim::wait(compaction_key(gdir, id, &target));
        let Some((target, root)) = flatten_target(gdir, id, &active, SYNC_COMPACT_AT_DEPTH)? else {
            continue;
        };
        flatten_in_place(gdir, id, &target, root.as_deref(), vm_ids)?;
    }
    Ok(())
}

/// Replace the immutable `target` with one file holding the same bytes, backed
/// directly by `root`, or standalone: given its owner and mode, synced, then
/// renamed over it. Readers that already opened `target` keep the old file.
fn flatten_in_place(
    gdir: &Path,
    id: &str,
    target: &Path,
    root: Option<&Path>,
    vm_ids: Option<(u32, u32)>,
) -> Result<()> {
    let started = std::time::Instant::now();
    let owner = generation_owner(id, target).unwrap_or_else(|| gdir.to_path_buf());
    let _gc_guard = lock_disk_gc(&owner, libc::LOCK_SH)?;
    let _disk_guard = super::ForkSourceLock::acquire_at(&disk_lock_path(&owner, id))?;
    let layers = chain(target)?;
    if layers.len() == 1 {
        return Ok(());
    }
    let root = root.filter(|root| layers.iter().any(|layer| layer == root));
    if root.is_some_and(|root| layers.get(1).is_some_and(|backing| backing == root)) {
        return Ok(());
    }
    let dir = compact_dir(&owner);
    std::fs::create_dir_all(&dir).map_err(|e| compact_err("create merge dir", e))?;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    // Announce the flatten before reading any layer, so a collection in another
    // process keeps every layer from the first read on.
    let _busy = Busy::announce(dir.join(format!("{id}.{}.{stamp}.busy", std::process::id())))?;
    let partial = target.with_file_name(format!(
        "{}.{}.{stamp}.flatten.partial",
        target
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("layer"),
        std::process::id(),
    ));
    let result = (|| -> Result<()> {
        match root {
            Some(root) => merge_onto(target, root, root, &partial)?,
            None => flatten_standalone(target, &partial, &|| {})?,
        }
        let meta = std::fs::metadata(target).map_err(|e| compact_err("stat target", e))?;
        std::fs::set_permissions(&partial, meta.permissions())
            .map_err(|e| compact_err("copy mode", e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let vm_ids = vm_ids.filter(|_| gdir.canonicalize().ok().as_ref() == Some(&owner));
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
        std::fs::File::open(&partial)
            .and_then(|file| file.sync_all())
            .map_err(|error| compact_err("sync flat layer and metadata", error))?;
        #[cfg(test)]
        pause_publication_for_qa(gdir, "before-rename");
        std::fs::rename(&partial, target).map_err(|e| compact_err("publish flat layer", e))?;
        #[cfg(test)]
        pause_publication_for_qa(gdir, "after-rename");
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
        previous_depth = layers.len() - 1,
        standalone = root.is_none(),
        elapsed_ms = started.elapsed().as_millis() as u64,
        "flattened a branch source's disk chain"
    );
    Ok(())
}

#[cfg(test)]
fn pause_publication_for_qa(directory: &Path, phase: &str) {
    if std::env::var("SMOLVM_COMPACTION_QA_MODE").as_deref() == Ok(phase) {
        std::fs::write(directory.join("ready-to-publish"), phase).unwrap();
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }
}

/// How long a merge may be in progress before its partial file is taken as left
/// behind by a process that died.
const STALE_PARTIAL: std::time::Duration = std::time::Duration::from_secs(3600);

/// Every disk layer some machine can still read: the chains under every machine's
/// active disks (cache disks included: their generations live under `d` like
/// the others) and every retained branch snapshot's recorded bases. `None` when
/// a chain cannot be read, which keeps everything.
fn reachable_layers(machine_dirs: &[PathBuf]) -> Option<HashSet<PathBuf>> {
    let mut reachable = HashSet::new();
    let mut walk = |top: &Path| -> Option<()> {
        reachable.extend(chain(top).ok()?);
        Some(())
    };
    for dir in machine_dirs {
        for (_, raw) in super::FORK_DISK_ROLES {
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
        if name.ends_with(".busy") {
            let dead = std::fs::read_to_string(&path)
                .ok()
                .and_then(|pid| pid.parse::<libc::pid_t>().ok())
                .filter(|pid| *pid > 0)
                .is_some_and(|pid| {
                    (unsafe { libc::kill(pid, 0) }) == -1
                        && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
                });
            if dead {
                let _ = std::fs::remove_file(&path);
                continue;
            }
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
/// The caller holds this machine's fork-source lock, preventing new generations
/// while reachability is scanned. Ancestor compaction can only shorten existing
/// paths, so scanning before taking the GC lock conservatively keeps extra layers
/// without blocking other machines' compactions during the scan.
pub(super) fn collect_unreachable_layers(gdir: &Path, machine_dirs: &[PathBuf]) -> Result<usize> {
    let Ok(gdir_d) = gdir.join("d").canonicalize() else {
        return Ok(0);
    };
    if merge_in_progress(&gdir_d) {
        return Ok(0);
    }
    let Some(reachable) = reachable_layers(machine_dirs) else {
        tracing::debug!(gdir = %gdir.display(), "kept every disk layer: a chain could not be read");
        return Ok(0);
    };
    let Some(_gc_guard) = lock_disk_gc(gdir, libc::LOCK_EX | libc::LOCK_NB)? else {
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

    struct TestProcess(std::process::Child);

    impl TestProcess {
        fn spawn(directory: &Path, mode: &str) -> Self {
            Self(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "agent::fork::compact::tests::compaction_process_helper",
                        "--nocapture",
                    ])
                    .env("SMOLVM_COMPACTION_QA_DIRECTORY", directory)
                    .env("SMOLVM_COMPACTION_QA_MODE", mode)
                    .stdout(std::process::Stdio::null())
                    .spawn()
                    .unwrap(),
            )
        }

        fn finish(&mut self) -> std::process::ExitStatus {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
            loop {
                if let Some(status) = self.0.try_wait().unwrap() {
                    return status;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "compaction process did not finish"
                );
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    }

    impl Drop for TestProcess {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn compaction_process_helper() {
        let Some(directory) = std::env::var_os("SMOLVM_COMPACTION_QA_DIRECTORY") else {
            return;
        };
        let directory = PathBuf::from(directory);
        match std::env::var("SMOLVM_COMPACTION_QA_MODE").unwrap().as_str() {
            "hold" => {
                let _gc_guard = lock_disk_gc(&directory, libc::LOCK_SH).unwrap();
                let _disk_guard = super::super::ForkSourceLock::acquire_at(&disk_lock_path(
                    &directory, "storage",
                ))
                .unwrap();
                let _busy = Busy::announce(directory.join("d/c/qa.busy")).unwrap();
                std::fs::write(directory.join("ready"), b"ready").unwrap();
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
            }
            "limited" => {
                let limit = libc::rlimit {
                    rlim_cur: 512 << 10,
                    rlim_max: 512 << 10,
                };
                unsafe {
                    libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
                    assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &limit), 0);
                }
                assert!(compact_if_near_limit(&directory, None).is_err());
            }
            "low-fd" => {
                let limit = libc::rlimit {
                    rlim_cur: 64,
                    rlim_max: 64,
                };
                assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
                compact_if_near_limit(&directory, None).unwrap();
            }
            "compact" | "before-rename" | "after-rename" => {
                compact_if_near_limit(&directory, None).unwrap()
            }
            #[cfg(target_os = "linux")]
            "enospc" => full_filesystem_qa(&directory),
            mode => panic!("unknown QA mode: {mode}"),
        }
    }

    #[cfg(target_os = "linux")]
    fn full_filesystem_qa(directory: &Path) {
        use std::io::Write;
        use std::os::unix::ffi::OsStrExt;
        assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNS) }, 0);
        assert_eq!(
            unsafe {
                libc::mount(
                    std::ptr::null(),
                    c"/".as_ptr(),
                    std::ptr::null(),
                    libc::MS_REC | libc::MS_PRIVATE,
                    std::ptr::null(),
                )
            },
            0
        );
        let mountpoint = directory.join("full-filesystem");
        std::fs::create_dir(&mountpoint).unwrap();
        let path = std::ffi::CString::new(mountpoint.as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe {
                libc::mount(
                    c"tmpfs".as_ptr(),
                    path.as_ptr(),
                    c"tmpfs".as_ptr(),
                    libc::MS_NOSUID | libc::MS_NODEV,
                    c"size=64m".as_ptr().cast(),
                )
            },
            0
        );
        let (source, live, _) = branched_machine(&mountpoint, 30);
        let before = read_all(&live);
        let depth = super::super::qcow2_backing_depth(&live).unwrap();
        let mut filler = std::fs::File::create(mountpoint.join("filler")).unwrap();
        let mut statistics = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        assert_eq!(
            unsafe { libc::statvfs(path.as_ptr(), statistics.as_mut_ptr()) },
            0
        );
        let statistics = unsafe { statistics.assume_init() };
        let mut remaining = (statistics.f_bavail * statistics.f_frsize).saturating_sub(256 << 10);
        let buffer = vec![0xA5_u8; 1 << 20];
        while remaining > 0 {
            let length = remaining.min(buffer.len() as u64) as usize;
            filler.write_all(&buffer[..length]).unwrap();
            remaining -= length as u64;
        }
        filler.sync_all().unwrap();
        let error = compact_if_near_limit(&source, None).unwrap_err();
        eprintln!("full-filesystem compaction failure: {error}");
        assert!(error.to_string().contains("os error 28"), "{error}");
        assert_eq!(super::super::qcow2_backing_depth(&live).unwrap(), depth);
        assert_eq!(read_all(&live), before);
        drop(filler);
        std::fs::remove_file(mountpoint.join("filler")).unwrap();
        compact_if_near_limit(&source, None).unwrap();
        assert_eq!(read_all(&live), before);
        assert!(super::super::qcow2_backing_depth(&live).unwrap() < COMPACT_AT_DEPTH);
    }

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
    fn flatten_to_raw_reads_exactly_as_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let (_, layers) = layered(dir.path(), 4);
        let top = layers.last().unwrap();
        let out = dir.path().join("flat.raw");

        flatten_to_raw(top, &out).unwrap();

        assert_eq!(std::fs::read(&out).unwrap(), read_all(top));
    }

    /// A publish flattens with many readers at once: the result must read exactly
    /// as the chain across every reader's share, chunk boundaries and all-zero
    /// spans, and stand alone.
    #[test]
    fn flatten_standalone_reads_exactly_as_the_chain_with_parallel_readers() {
        use std::os::unix::fs::FileExt;
        const SIZE: u64 = 50 * COPY_CHUNK;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root.raw");
        let file = std::fs::File::create(&root).unwrap();
        file.set_len(SIZE).unwrap();
        for chunk in 0..50u64 {
            // Chunks 20..30 stay zero; the rest each carry their own pattern.
            if !(20..30).contains(&chunk) {
                let fill = vec![chunk as u8 + 1; COPY_CHUNK as usize];
                file.write_all_at(&fill, chunk * COPY_CHUNK).unwrap();
            }
        }
        drop(file);
        let top = dir.path().join("top.qcow2");
        create_overlay(&top, SIZE, &root.canonicalize().unwrap()).unwrap();
        let access = writable(&top);
        access
            .write(&[0xEE; 8192][..], 3 * COPY_CHUNK - 4096)
            .unwrap();
        access.write(&[0x00; 65536][..], 7 * COPY_CHUNK).unwrap();
        access
            .write(&[0x5A; 4096][..], 25 * COPY_CHUNK + 12345)
            .unwrap();
        access.flush().unwrap();
        drop(access);
        let out = dir.path().join("flat.qcow2");
        let calls = std::sync::atomic::AtomicUsize::new(0);

        flatten_standalone(&top, &out, &|| {
            calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        })
        .unwrap();

        assert_eq!(read_all(&out), read_all(&top));
        assert!(
            qcow2_backing_name(&out).unwrap().is_none(),
            "the flattened image must stand alone"
        );
        // Holes in the base are never read: 40 written chunks, plus chunk 25,
        // which only the overlay wrote into.
        assert_eq!(calls.into_inner(), 41, "one progress call per chunk read");
        let failed = dir.path().join("missing.qcow2");
        assert!(flatten_standalone(&dir.path().join("absent.qcow2"), &failed, &|| {}).is_err());
        assert!(!failed.exists(), "a failed flatten leaves nothing behind");
    }

    #[test]
    fn flatten_to_raw_keeps_unwritten_space_as_holes() {
        use std::os::unix::fs::MetadataExt;
        const BIG: u64 = 256 << 20;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root.raw");
        std::fs::File::create(&root).unwrap().set_len(BIG).unwrap();
        let top = dir.path().join("top.qcow2");
        create_overlay(&top, BIG, &root.canonicalize().unwrap()).unwrap();
        let access = writable(&top);
        access.write(&[0xAB; 4096][..], 1 << 20).unwrap();
        access.write(&[0xCD; 4096][..], 200 << 20).unwrap();
        access.flush().unwrap();
        drop(access);
        let out = dir.path().join("flat.raw");

        flatten_to_raw(&top, &out).unwrap();

        let meta = std::fs::metadata(&out).unwrap();
        assert_eq!(meta.len(), BIG);
        assert!(
            meta.blocks() * 512 < 4 << 20,
            "8 KiB of data took {} bytes on disk",
            meta.blocks() * 512
        );
        assert_eq!(std::fs::read(&out).unwrap(), read_all(&top));
    }

    #[test]
    fn the_newest_immutable_generation_is_the_flatten_target() {
        let dir = tempfile::tempdir().unwrap();
        let (gdir, live, gens) = branched_machine(dir.path(), 20);
        let (target, root) = flatten_target(&gdir, "storage", &live, COMPACT_AT_DEPTH)
            .unwrap()
            .unwrap();
        assert_eq!(&target, gens.last().unwrap(), "never the live layer itself");
        assert_eq!(root, Some(gdir.join("storage.raw").canonicalize().unwrap()));
        assert!(flatten_target(&gdir, "storage", &live, 64)
            .unwrap()
            .is_none());
    }

    #[test]
    fn a_branch_inheriting_a_deep_golden_can_fork_again() {
        let dir = tempfile::tempdir().unwrap();
        let (parent, parent_live, generations) = branched_machine(&dir.path().join("parent"), 31);
        let child = dir.path().join("child");
        std::fs::create_dir_all(&child).unwrap();
        let child_live = child.join("storage.qcow2");
        create_overlay(&child_live, SIZE, generations.last().unwrap()).unwrap();
        let sibling = dir.path().join("sibling.qcow2");
        create_overlay(&sibling, SIZE, generations.last().unwrap()).unwrap();
        let expected = read_all(&child_live);
        let parent_expected = read_all(&parent_live);
        let existing_reader = open_readonly(&parent_live, true).unwrap();
        assert!(super::super::qcow2_backing_depth(&child_live).unwrap() >= 32);

        compact_if_near_limit(&child, None).unwrap();

        super::super::ensure_fork_disk_chain_is_bounded(&child).unwrap();
        assert!(chain(&child_live).unwrap().len() <= COMPACT_AT_DEPTH);
        assert_eq!(read_all(&child_live), expected);
        assert_eq!(read_all(&sibling), expected);
        assert_eq!(read_all(&parent_live), parent_expected);
        let mut existing_bytes = vec![0_u8; SIZE as usize];
        existing_reader.read(&mut existing_bytes, 0).unwrap();
        assert_eq!(existing_bytes, parent_expected);
        assert!(!merge_in_progress(&parent.join("d")));
    }

    #[test]
    fn a_failed_flatten_leaves_the_source_disk_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let (source, live, _) = branched_machine(dir.path(), 30);
        let before = read_all(&live);
        let depth = super::super::qcow2_backing_depth(&live).unwrap();
        std::fs::write(source.join("d/c"), b"not a directory").unwrap();
        assert!(compact_if_near_limit(&source, None).is_err());
        assert_eq!(super::super::qcow2_backing_depth(&live).unwrap(), depth);
        assert_eq!(read_all(&live), before);
    }

    #[test]
    fn a_local_generation_on_a_deep_inherited_base_becomes_standalone() {
        let dir = tempfile::tempdir().unwrap();
        let (_, _, generations) = branched_machine(&dir.path().join("parent"), 25);
        let child = dir.path().join("child");
        let target = child.join("d/00000001/storage.base.qcow2");
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        create_overlay(&target, SIZE, generations.last().unwrap()).unwrap();
        let live = child.join("storage.qcow2");
        create_overlay(&live, SIZE, &target).unwrap();
        let access = writable(&live);
        access.write(&[91_u8; 4096][..], 0).unwrap();
        access.flush().unwrap();
        let before = read_all(&live);
        compact_if_near_limit(&child, None).unwrap();
        assert!(qcow2_backing_name(&target).unwrap().is_none());
        assert_eq!(chain(&live).unwrap().len(), 2);
        assert_eq!(read_all(&live), before);
    }

    #[test]
    fn a_deep_fork_waits_for_a_merge_instead_of_hitting_the_limit() {
        let dir = tempfile::tempdir().unwrap();
        let (parent, live, _) = branched_machine(dir.path(), 30);
        let claim = Claim::take(parent.canonicalize().unwrap().join("d/storage")).unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let source = parent.clone();
        let worker = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            result_tx
                .send(compact_if_near_limit(&source, None))
                .unwrap();
        });
        started_rx.recv().unwrap();
        assert!(matches!(
            result_rx.recv_timeout(std::time::Duration::from_millis(100)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        drop(claim);
        result_rx
            .recv_timeout(std::time::Duration::from_secs(15))
            .unwrap()
            .unwrap();
        worker.join().unwrap();
        assert!(chain(&live).unwrap().len() < COMPACT_AT_DEPTH);
    }

    #[test]
    fn repeated_golden_job_golden_cycles_keep_disks_bounded_and_siblings_intact() {
        let dir = tempfile::tempdir().unwrap();
        let (mut source, _, _) = branched_machine(&dir.path().join("root"), 0);
        let mut siblings = Vec::new();
        let mut deepest = 0;
        for cycle in 0..12 {
            for step in 0..9 {
                compact_if_near_limit(&source, None).unwrap();
                super::super::ensure_fork_disk_chain_is_bounded(&source).unwrap();
                let live = source.join("storage.qcow2");
                let access = writable(&live);
                access
                    .write(&[cycle as u8 + 1; 4096][..], step * CLUSTER)
                    .unwrap();
                if step == 3 {
                    access.write_zeroes(CLUSTER * 20, CLUSTER).unwrap();
                }
                access.flush().unwrap();
                drop(access);
                let target = source.join(format!("d/{step:08x}/storage.base.qcow2"));
                std::fs::create_dir_all(target.parent().unwrap()).unwrap();
                std::fs::rename(&live, &target).unwrap();
                create_overlay(&live, SIZE, &target).unwrap();
                deepest = deepest.max(super::super::qcow2_backing_depth(&live).unwrap());
                assert!(deepest < super::super::MAX_FORK_DISK_CHAIN_DEPTH);
            }
            let base = source.join("d/00000008/storage.base.qcow2");
            let expected = read_all(&base);
            let sibling = dir.path().join(format!("sibling-{cycle}.qcow2"));
            create_overlay(&sibling, SIZE, &base).unwrap();
            siblings.push((sibling, expected));
            source = dir.path().join(format!("golden-{cycle}"));
            std::fs::create_dir_all(&source).unwrap();
            create_overlay(&source.join("storage.qcow2"), SIZE, &base).unwrap();
        }
        assert!(deepest >= SYNC_COMPACT_AT_DEPTH);
        for (sibling, expected) in siblings {
            assert_eq!(read_all(&sibling), expected);
        }
    }

    #[test]
    fn measured_depth_includes_cache_disks_and_does_not_truncate_at_32() {
        let dir = tempfile::tempdir().unwrap();
        let (source, live, _) = branched_machine(dir.path(), 35);
        let cache = source
            .join(crate::data::storage::CACHE_DISK_FILENAME)
            .with_extension("qcow2");
        create_overlay(&cache, SIZE, &live).unwrap();
        assert_eq!(
            super::super::disk_chain_depth_at(&source).unwrap(),
            Some(37)
        );
        let empty = dir.path().join("empty");
        std::fs::create_dir(&empty).unwrap();
        assert_eq!(super::super::disk_chain_depth_at(&empty).unwrap(), None);
        std::fs::write(empty.join("storage.raw"), [0_u8; 32]).unwrap();
        assert_eq!(super::super::disk_chain_depth_at(&empty).unwrap(), Some(0));
    }

    #[test]
    fn a_missing_backing_is_not_reported_as_zero_depth() {
        let dir = tempfile::tempdir().unwrap();
        let (source, _, generations) = branched_machine(dir.path(), 1);
        std::fs::remove_file(&generations[0]).unwrap();
        assert!(super::super::disk_chain_depth_at(&source).is_err());
    }

    #[test]
    fn arbitrary_inherited_layers_are_not_rewritten() {
        let dir = tempfile::tempdir().unwrap();
        let (_, layers) = layered(dir.path(), 30);
        let child = dir.path().join("child");
        std::fs::create_dir_all(&child).unwrap();
        let child_live = child.join("storage.qcow2");
        create_overlay(&child_live, SIZE, layers.last().unwrap()).unwrap();
        assert!(
            flatten_target(&child, "storage", &child_live, SYNC_COMPACT_AT_DEPTH)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn generations_behind_frozen_active_disks_compact_without_replacing_them() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let (_, mut live, _) = branched_machine(dir.path(), 24);
        let mut frozen = vec![(live.clone(), std::fs::metadata(&live).unwrap().ino())];
        let mut child = PathBuf::new();
        for index in 0..7 {
            child = dir.path().join(format!("frozen-{index}"));
            std::fs::create_dir(&child).unwrap();
            let next = child.join("storage.qcow2");
            create_overlay(&next, SIZE, &live).unwrap();
            frozen.push((next.clone(), std::fs::metadata(&next).unwrap().ino()));
            live = next;
        }
        let before = read_all(&live);
        assert_eq!(super::super::qcow2_backing_depth(&live).unwrap(), 32);
        compact_if_near_limit(&child, None).unwrap();
        assert_eq!(super::super::qcow2_backing_depth(&live).unwrap(), 8);
        assert_eq!(read_all(&live), before);
        for (disk, inode) in frozen {
            assert_eq!(std::fs::metadata(&disk).unwrap().ino(), inode);
        }
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
        flatten_in_place(&gdir, "storage", &target, root.as_deref(), None).unwrap();
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
        flatten_in_place(&gdir, "storage", &target, root.as_deref(), None).unwrap();
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
        for path in [
            "/vms/m/d/not-a-generation/storage.base.qcow2",
            "/vms/m/d/0123abcd/nested/storage.base.qcow2",
            "/vms/m/d/storage.base.qcow2",
            "/vms/m/d2/0123abcd/storage.base.qcow2",
        ] {
            assert!(
                !is_generation_layer(gdir_d, "storage", Path::new(path)),
                "{path}"
            );
        }
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

    /// A cache disk's generations are collected like the others: kept while a
    /// branch's cache chain reads them, never mistaken for orphans.
    #[test]
    fn a_cache_generation_a_branch_reads_is_kept() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let branch = tmp.path().join("branch");
        for dir in [&source, &branch] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let base = tmp.path().join("cdisk-v4.raw");
        std::fs::write(&base, vec![0_u8; SIZE as usize]).unwrap();
        let layer = |path: PathBuf, below: &Path| {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            create_overlay(&path, SIZE, below).unwrap();
            path.canonicalize().unwrap()
        };
        let generation = layer(source.join("d/aaaaaaaa/cache.base.qcow2"), &base);
        layer(source.join("cache.qcow2"), &generation);
        let below_branch = layer(source.join("d/bbbbbbbb/cache.base.qcow2"), &generation);
        layer(branch.join("cache.qcow2"), &below_branch);

        let both = [source.clone(), branch.clone()];
        assert_eq!(collect_unreachable_layers(&source, &both).unwrap(), 0);
        assert!(generation.exists() && below_branch.exists());

        // The source's own cache chain keeps its generation once the branch goes.
        assert_eq!(
            collect_unreachable_layers(&source, std::slice::from_ref(&source)).unwrap(),
            1
        );
        assert!(generation.exists() && !below_branch.exists());
        assert!(base.exists());
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

    #[test]
    fn an_all_zero_sparse_disk_flattens_without_readers() {
        let dir = tempfile::tempdir().unwrap();
        let raw = dir.path().join("empty.raw");
        std::fs::File::create(&raw).unwrap().set_len(SIZE).unwrap();
        let top = dir.path().join("top.qcow2");
        create_overlay(&top, SIZE, &raw).unwrap();
        let flat = dir.path().join("flat.qcow2");
        flatten_standalone(&top, &flat, &|| panic!("an empty disk needs no copying")).unwrap();
        assert_eq!(chain(&flat).unwrap().len(), 1);
        assert_eq!(read_all(&flat), vec![0_u8; SIZE as usize]);
    }

    #[test]
    fn child_identity_does_not_change_ancestor_disk_ownership_or_mode() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let (_, _, generations) = branched_machine(dir.path(), 30);
        let target = generations.last().unwrap();
        std::fs::set_permissions(target, std::fs::Permissions::from_mode(0o640)).unwrap();
        let before = std::fs::metadata(target).unwrap();
        let child = dir.path().join("child");
        std::fs::create_dir(&child).unwrap();
        create_overlay(&child.join("storage.qcow2"), SIZE, target).unwrap();
        compact_if_near_limit(
            &child,
            Some((
                before.uid().saturating_add(1),
                before.gid().saturating_add(1),
            )),
        )
        .unwrap();
        let after = std::fs::metadata(target).unwrap();
        assert_eq!(
            (after.uid(), after.gid(), after.mode()),
            (before.uid(), before.gid(), before.mode())
        );
    }

    #[test]
    fn a_failed_partial_write_keeps_the_old_disk_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let (source, live, _) = branched_machine(dir.path(), 30);
        let before = read_all(&live);
        let depth = super::super::qcow2_backing_depth(&live).unwrap();
        let mut worker = TestProcess::spawn(&source, "limited");
        assert!(worker.finish().success());
        assert_eq!(read_all(&live), before);
        assert_eq!(super::super::qcow2_backing_depth(&live).unwrap(), depth);
        assert!(!merge_in_progress(&source.join("d")));
        for generation in std::fs::read_dir(source.join("d")).unwrap().flatten() {
            for entry in std::fs::read_dir(generation.path()).unwrap().flatten() {
                assert!(!entry.file_name().to_string_lossy().ends_with(".partial"));
            }
        }
        compact_if_near_limit(&source, None).unwrap();
        assert_eq!(read_all(&live), before);
    }

    #[test]
    fn a_killed_process_releases_gc_and_disk_locks_and_stale_markers() {
        let dir = tempfile::tempdir().unwrap();
        let (source, live, _) = branched_machine(dir.path(), 30);
        let before = read_all(&live);
        std::fs::create_dir(source.join("d/c")).unwrap();
        let mut worker = TestProcess::spawn(&source, "hold");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !source.join("ready").exists() {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(lock_disk_gc(&source, libc::LOCK_EX | libc::LOCK_NB)
            .unwrap()
            .is_none());
        assert_eq!(
            collect_unreachable_layers(&source, std::slice::from_ref(&source)).unwrap(),
            0
        );
        worker.0.kill().unwrap();
        assert!(!worker.finish().success());
        assert!(!merge_in_progress(&source.join("d")));
        assert!(!source.join("d/c/qa.busy").exists());
        compact_if_near_limit(&source, None).unwrap();
        assert_eq!(read_all(&live), before);
    }

    #[test]
    fn separate_processes_compact_one_shared_ancestor_without_changing_children() {
        let dir = tempfile::tempdir().unwrap();
        let (source, _, generations) = branched_machine(dir.path(), 30);
        let mut workers = Vec::new();
        let mut children = Vec::new();
        for index in 0..4 {
            let child = dir.path().join(format!("child-{index}"));
            std::fs::create_dir(&child).unwrap();
            let disk = child.join("storage.qcow2");
            create_overlay(&disk, SIZE, generations.last().unwrap()).unwrap();
            let writer = writable(&disk);
            writer.write(&vec![index as u8; 4096], 0).unwrap();
            writer.flush().unwrap();
            drop(writer);
            children.push((disk.clone(), read_all(&disk)));
            workers.push(TestProcess::spawn(&child, "compact"));
        }
        for worker in &mut workers {
            assert!(worker.finish().success());
        }
        let mut machines = vec![source.clone()];
        machines.extend(
            children
                .iter()
                .map(|(disk, _)| disk.parent().unwrap().to_path_buf()),
        );
        collect_unreachable_layers(&source, &machines).unwrap();
        for (disk, before) in children {
            assert_eq!(read_all(&disk), before);
            assert!(super::super::qcow2_backing_depth(&disk).unwrap() < COMPACT_AT_DEPTH);
        }
    }

    #[test]
    fn disk_lock_cleanup_keeps_live_and_inflight_owners() {
        let dir = tempfile::tempdir().unwrap();
        let owner = dir.path().join("machine");
        std::fs::create_dir(&owner).unwrap();
        let path = disk_lock_path(&owner, "storage");
        let guard = super::super::ForkSourceLock::acquire_at(&path).unwrap();
        super::super::prune_orphaned_fork_source_locks_in(dir.path());
        assert!(path.exists());
        std::fs::remove_dir(&owner).unwrap();
        super::super::prune_orphaned_fork_source_locks_in(dir.path());
        assert!(path.exists());
        drop(guard);
        super::super::prune_orphaned_fork_source_locks_in(dir.path());
        assert!(!path.exists());
        assert!(disk_lock_owner(Path::new(".compact-storage.lock")).is_none());
        assert!(disk_lock_owner(Path::new("machine.compact-other.lock")).is_none());
        assert_ne!(
            disk_lock_path(Path::new("vm.one"), "storage"),
            disk_lock_path(Path::new("vm.two"), "storage")
        );
    }

    #[test]
    fn crashing_on_either_side_of_publication_keeps_data_and_retry_safe() {
        use std::os::unix::fs::MetadataExt;
        for phase in ["before-rename", "after-rename"] {
            let dir = tempfile::tempdir().unwrap();
            let (source, _, generations) = branched_machine(dir.path(), 30);
            let target = generations.last().unwrap();
            let inode = std::fs::metadata(target).unwrap().ino();
            let child = dir.path().join("child");
            std::fs::create_dir(&child).unwrap();
            let live = child.join("storage.qcow2");
            create_overlay(&live, SIZE, target).unwrap();
            let before = read_all(&live);
            let existing_reader = open_readonly(&live, true).unwrap();
            let mut worker = TestProcess::spawn(&child, phase);
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while !child.join("ready-to-publish").exists() {
                assert!(std::time::Instant::now() < deadline, "{phase}");
                assert!(worker.0.try_wait().unwrap().is_none(), "{phase}");
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            worker.0.kill().unwrap();
            assert!(!worker.finish().success());
            assert_eq!(
                std::fs::metadata(target).unwrap().ino() == inode,
                phase == "before-rename"
            );
            assert_eq!(read_all(&live), before);
            assert!(!merge_in_progress(&source.join("d")));
            let machines = [source.clone(), child.clone()];
            collect_unreachable_layers(&source, &machines).unwrap();
            compact_if_near_limit(&child, None).unwrap();
            collect_unreachable_layers(&source, &machines).unwrap();
            assert_eq!(read_all(&live), before);
            let mut existing = vec![0_u8; SIZE as usize];
            existing_reader.read(&mut existing, 0).unwrap();
            assert_eq!(existing, before);
            assert!(super::super::qcow2_backing_depth(&live).unwrap() < COMPACT_AT_DEPTH);
        }
    }

    #[test]
    fn inherited_flatten_respects_a_low_file_descriptor_limit() {
        let dir = tempfile::tempdir().unwrap();
        let (_, _, generations) = branched_machine(dir.path(), 30);
        let child = dir.path().join("child");
        std::fs::create_dir(&child).unwrap();
        let live = child.join("storage.qcow2");
        create_overlay(&live, SIZE, generations.last().unwrap()).unwrap();
        let before = read_all(&live);
        let mut worker = TestProcess::spawn(&child, "low-fd");
        assert!(worker.finish().success());
        assert_eq!(read_all(&live), before);
        assert!(super::super::qcow2_backing_depth(&live).unwrap() < COMPACT_AT_DEPTH);
    }

    #[test]
    fn shallow_sources_do_not_wait_for_other_machines_disk_gc() {
        let dir = tempfile::tempdir().unwrap();
        let (source, _, _) = branched_machine(dir.path(), 0);
        let gc_guard = lock_disk_gc(&source, libc::LOCK_EX).unwrap();
        let (completed, result) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            completed
                .send(compact_if_near_limit(&source, None))
                .unwrap();
        });
        let outcome = result.recv_timeout(std::time::Duration::from_secs(3));
        drop(gc_guard);
        worker.join().unwrap();
        outcome
            .expect("a shallow branch should not take the node GC lock")
            .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires root and a private mount namespace for actual ENOSPC"]
    fn a_full_filesystem_keeps_the_source_readable_and_can_retry() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let dir = tempfile::tempdir().unwrap();
        let mut worker = TestProcess::spawn(dir.path(), "enospc");
        assert!(worker.finish().success());
    }
}
