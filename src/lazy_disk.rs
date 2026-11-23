//! Restored disks served lazily from the node's checkpoint store.
//!
//! A restore normally writes every byte of a checkpoint's disks before the
//! machine boots: the chunked checkpoint is materialized into the shared
//! extraction, then each disk is copied into the machine. With lazy disks the
//! machine boots at once instead. Each disk file is created sparse with only
//! its first chunk (the image header) present, and `DISK.lazydisk` beside it
//! names the stored checkpoint holding the rest. The VMM (libkrun's lazy block
//! storage) fetches a chunk from the store the first time the guest touches
//! it, verifies it against its SHA-256, and keeps it in the disk file, which
//! it fills completely in the background. `DISK.present` records which chunks
//! the file holds.
//!
//! Until a disk is complete only its VMM may read it, so anything on the host
//! that reads or links a machine's disk files (a branch, a checkpoint capture,
//! an export) first calls [`settle`]. A VMM serving a lazy disk holds a shared
//! lock on its descriptor: while one does, `settle` waits for it to finish
//! filling; otherwise it takes the lock exclusively and fills the disk itself.
//! Either way the descriptor is then removed and the disk is an ordinary file.
//!
//! The descriptors sit in the machine's directory, which its VMM's uid may
//! write, so nothing privileged believes them about where to read from. The
//! stored checkpoint a machine's lazy disks read is recorded in the store,
//! root-only ([`record`]): the launcher mounts only that checkpoint for the
//! VMM, [`settle`] fills only from it, and retention keeps it while the
//! machine still has lazy disks ([`kept_checkpoints`]).

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::checkpoint_store::ChunkedFile;

/// Suffix of the descriptor that makes a disk lazy.
pub const DESCRIPTOR_SUFFIX: &str = ".lazydisk";
/// Suffix of the record of which chunks a lazy disk holds.
const PRESENT_SUFFIX: &str = ".present";
/// How long [`settle`] waits for a running machine's VMM to fill its disks.
const FILL_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// Threads filling a stopped machine's disk.
const FILL_THREADS: usize = 8;
/// Directory in the checkpoint store recording each lazy machine's checkpoint.
const RECORDS: &str = "lazy-disks";
/// Directory in the checkpoint store holding published checkpoints.
const PUBLISHED: &str = "published";

static ENABLED: AtomicBool = AtomicBool::new(false);

/// Serve restored disks lazily from now on (`serve start --lazy-disks`).
pub fn enable() {
    ENABLED.store(true, Ordering::Relaxed);
}

/// Whether restores serve their disks lazily.
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// `DISK.lazydisk`, read by libkrun. Fields libkrun does not know are refused
/// there, so this writes only those.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    version: u32,
    /// The stored checkpoint's `checkpoint.json`.
    index: PathBuf,
    /// The file within the index this disk is.
    file: String,
    /// The stored checkpoint's `objects/` directory.
    objects: PathBuf,
    /// The disk file itself, holding chunks as they become present.
    cache: PathBuf,
    /// Fill every chunk in the background.
    fill: bool,
}

fn suffixed(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

fn descriptor_path(disk: &Path) -> PathBuf {
    suffixed(disk, DESCRIPTOR_SUFFIX)
}

fn present_path(disk: &Path) -> PathBuf {
    suffixed(disk, PRESENT_SUFFIX)
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// File in a restore's shared extraction naming the stored checkpoint it was
/// materialized from, so an install can serve the disks from there instead.
pub const TREE_SOURCE: &str = ".lazy-source";
/// File in a shared extraction whose disks were left out of it.
pub const TREE_WITHOUT_DISKS: &str = ".lazy-disks-left-out";

/// Whether checkpoint asset `path` is a disk a restore can serve lazily. The
/// cache disk is rebased onto this host's base at install, so it is not.
pub fn is_lazy_asset(path: &str) -> bool {
    path.starts_with("checkpoint/disks/storage/") || path.starts_with("checkpoint/disks/overlay/")
}

/// The stored checkpoint shared extraction `tree` was materialized from.
pub fn tree_source(tree: &Path) -> Option<PathBuf> {
    let source = std::fs::read_to_string(tree.join(TREE_SOURCE)).ok()?;
    Some(PathBuf::from(source.trim_end()))
}

/// Which stored checkpoint a machine's lazy disks read, kept root-only.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    machine: PathBuf,
    checkpoint: PathBuf,
}

fn record_path(store: &Path, machine: &Path) -> io::Result<PathBuf> {
    let name = machine
        .file_name()
        .ok_or_else(|| invalid("machine directory has no name"))?;
    Ok(store.join(RECORDS).join(name))
}

/// Whether `checkpoint` is a checkpoint published in `store`.
fn is_published(store: &Path, checkpoint: &Path) -> bool {
    let (Ok(published), Ok(checkpoint)) = (
        store.join(PUBLISHED).canonicalize(),
        checkpoint.canonicalize(),
    ) else {
        return false;
    };
    checkpoint.parent() == Some(published.as_path()) && checkpoint.is_dir()
}

/// Record that the lazy disks of machine directory `machine` read the stored
/// checkpoint `checkpoint`, which must be published in `store`.
pub fn record(store: &Path, machine: &Path, checkpoint: &Path) -> io::Result<()> {
    if !is_published(store, checkpoint) {
        return Err(invalid(format!(
            "{} is not a published checkpoint",
            checkpoint.display()
        )));
    }
    let path = record_path(store, machine)?;
    std::fs::create_dir_all(path.parent().expect("record has a parent"))?;
    let body = serde_json::to_vec(&Record {
        machine: machine.canonicalize()?,
        checkpoint: checkpoint.to_path_buf(),
    })?;
    let partial = suffixed(&path, ".partial");
    std::fs::write(&partial, body)?;
    std::fs::rename(&partial, &path)
}

/// The stored checkpoint machine directory `machine`'s lazy disks may read,
/// when it has lazy disks and a record of it.
pub fn trusted_checkpoint(store: &Path, machine: &Path) -> Option<PathBuf> {
    if lazy_disks(machine).ok()?.is_empty() {
        return None;
    }
    let record: Record =
        serde_json::from_slice(&std::fs::read(record_path(store, machine).ok()?).ok()?).ok()?;
    (record.machine == machine.canonicalize().ok()? && is_published(store, &record.checkpoint))
        .then_some(record.checkpoint)
}

/// Names of the published checkpoints machines' lazy disks still read, for
/// retention to keep. Records of machines with no lazy disks left go.
pub fn kept_checkpoints(store: &Path) -> Vec<std::ffi::OsString> {
    let Ok(entries) = std::fs::read_dir(store.join(RECORDS)) else {
        return Vec::new();
    };
    let mut kept = Vec::new();
    for entry in entries.flatten() {
        let record: Option<Record> = std::fs::read(entry.path())
            .ok()
            .and_then(|body| serde_json::from_slice(&body).ok());
        let Some(record) = record else { continue };
        if lazy_disks(&record.machine).is_ok_and(|disks| !disks.is_empty()) {
            kept.extend(
                record
                    .checkpoint
                    .file_name()
                    .map(|name| name.to_os_string()),
            );
        } else {
            let _ = std::fs::remove_file(entry.path());
        }
    }
    kept
}

/// Whether `disk` is lazy.
pub fn is_lazy(disk: &Path) -> bool {
    descriptor_path(disk).is_file()
}

/// Create the lazy disk for file `file` of the stored checkpoint at `stored`
/// at `staged`: sized, sparse, with its first chunk present and recorded so.
/// [`publish`] makes it lazy once it is at its final path.
pub fn stage(stored: &Path, file: &str, staged: &Path) -> io::Result<()> {
    let chunked = ChunkedFile::open(stored, file)?;
    let disk = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(staged)?;
    disk.set_len(chunked.size())?;
    let mut present = vec![0u8; chunked.chunks()];
    if let Some(first) = present.first_mut() {
        if let Some(bytes) = chunked.read(0)? {
            use std::os::unix::fs::FileExt;
            disk.write_all_at(&bytes, 0)?;
        }
        *first = 1;
    }
    disk.sync_all()?;
    write_present(&present_path(staged), &present)
}

/// Move a staged lazy disk to `disk`, then write its descriptor naming file
/// `file` of the stored checkpoint at `stored`.
pub fn publish(stored: &Path, file: &str, staged: &Path, disk: &Path) -> io::Result<()> {
    std::fs::rename(present_path(staged), present_path(disk))?;
    std::fs::rename(staged, disk)?;
    let descriptor = Descriptor {
        version: 1,
        index: stored.join("checkpoint.json"),
        file: file.to_string(),
        objects: stored.join("objects"),
        cache: disk.to_path_buf(),
        fill: true,
    };
    let path = descriptor_path(disk);
    let partial = suffixed(&path, ".partial");
    std::fs::write(&partial, serde_json::to_vec(&descriptor)?)?;
    std::fs::rename(&partial, &path)
}

fn write_present(path: &Path, present: &[u8]) -> io::Result<()> {
    let partial = suffixed(path, ".partial");
    {
        use std::io::Write;
        let mut file = std::fs::File::create(&partial)?;
        file.write_all(present)?;
        file.sync_all()?;
    }
    std::fs::rename(&partial, path)
}

fn read_descriptor(disk: &Path) -> io::Result<Descriptor> {
    let path = descriptor_path(disk);
    serde_json::from_slice(&std::fs::read(&path)?)
        .map_err(|error| invalid(format!("{}: {error}", path.display())))
}

/// The stored checkpoint a descriptor names.
fn stored_dir(descriptor: &Descriptor) -> io::Result<&Path> {
    descriptor
        .index
        .parent()
        .ok_or_else(|| invalid("lazy disk index has no directory"))
}

/// The lazy disks in machine directory `dir`.
pub fn lazy_disks(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut disks = Vec::new();
    for entry in entries {
        let name = entry?.file_name();
        if let Some(disk) = name
            .to_str()
            .and_then(|n| n.strip_suffix(DESCRIPTOR_SUFFIX))
        {
            disks.push(dir.join(disk));
        }
    }
    disks.sort();
    Ok(disks)
}

/// Make every lazy disk in machine directory `dir` an ordinary, complete file:
/// wait for the VMM serving it to fill it, or fill it when none does.
pub fn settle(dir: &Path) -> crate::Result<()> {
    settle_in(&crate::checkpoint_delta::node_store(), dir)
}

fn settle_in(store: &Path, dir: &Path) -> crate::Result<()> {
    let failed = |e: io::Error| crate::Error::agent("complete lazy disk", e.to_string());
    let disks = lazy_disks(dir).map_err(failed)?;
    if disks.is_empty() {
        return Ok(());
    }
    let checkpoint = trusted_checkpoint(store, dir).ok_or_else(|| {
        crate::Error::agent(
            "complete lazy disk",
            format!(
                "{} has lazy disks but no record of their checkpoint",
                dir.display()
            ),
        )
    })?;
    for disk in disks {
        let started = Instant::now();
        let lock = std::fs::File::open(descriptor_path(&disk)).map_err(failed)?;
        let served = match lock.try_lock() {
            Ok(()) => false,
            Err(std::fs::TryLockError::WouldBlock) => true,
            Err(std::fs::TryLockError::Error(error)) => return Err(failed(error)),
        };
        let result = if served {
            wait_filled(&checkpoint, &disk, FILL_TIMEOUT)
        } else {
            fill(&checkpoint, &disk)
        };
        result.map_err(|error| {
            crate::Error::agent("complete lazy disk", format!("{}: {error}", disk.display()))
        })?;
        // Removed while still locked: a VMM starting now finds no descriptor
        // and opens the complete file as it is.
        finish(&disk).map_err(failed)?;
        drop(lock);
        tracing::info!(
            disk = %disk.display(),
            served,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "lazy disk completed"
        );
    }
    match std::fs::remove_file(record_path(store, dir).map_err(failed)?) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(failed(error)),
        _ => Ok(()),
    }
}

/// The file of `checkpoint` that `disk` is, by its descriptor. Its stored
/// checkpoint must be the one recorded for the machine.
fn chunked_file(checkpoint: &Path, disk: &Path) -> io::Result<ChunkedFile> {
    let descriptor = read_descriptor(disk)?;
    if stored_dir(&descriptor)? != checkpoint {
        return Err(invalid(
            "lazy disk names a checkpoint other than its machine's",
        ));
    }
    ChunkedFile::open(checkpoint, &descriptor.file)
}

/// Drop a complete disk's descriptor and presence record. A running VMM
/// keeps serving it from the file, which now holds every chunk.
fn finish(disk: &Path) -> io::Result<()> {
    std::fs::remove_file(descriptor_path(disk))?;
    match std::fs::remove_file(present_path(disk)) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

/// Whether the presence record says every chunk of a disk is present.
fn all_present(present: &[u8], chunks: usize) -> bool {
    present.len() == chunks && present.iter().all(|&p| p == 1)
}

/// Wait for a running VMM to record that it holds every chunk of `disk`.
fn wait_filled(checkpoint: &Path, disk: &Path, timeout: Duration) -> io::Result<()> {
    let chunks = chunked_file(checkpoint, disk)?.chunks();
    let deadline = Instant::now() + timeout;
    loop {
        if std::fs::read(present_path(disk)).is_ok_and(|p| all_present(&p, chunks)) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the machine did not finish filling its disk",
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// How long a chunk of a checkpoint still being imported is waited for.
const ARRIVAL_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// Chunk `index` of `chunked`, waiting for it while `checkpoint` is still
/// being imported. An import that failed will not bring it.
fn read_arriving(
    chunked: &ChunkedFile,
    index: usize,
    checkpoint: &Path,
) -> io::Result<Option<Vec<u8>>> {
    let deadline = Instant::now() + ARRIVAL_TIMEOUT;
    loop {
        match chunked.read(index) {
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    && crate::checkpoint_store::is_importing(checkpoint)
                    && !checkpoint
                        .join(crate::checkpoint_store::IMPORT_FAILED)
                        .exists()
                    && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(20));
            }
            other => return other,
        }
    }
}

/// Fill every chunk of `disk` its presence record lacks, from the store. No
/// VMM may have the disk open, one would hold chunks it has not recorded yet:
/// the caller holds the descriptor's lock exclusively.
fn fill(checkpoint: &Path, disk: &Path) -> io::Result<()> {
    let chunked = chunked_file(checkpoint, disk)?;
    let present = std::fs::read(present_path(disk))?;
    // A record that does not describe this file could claim chunks the file
    // lacks, or lose ones the guest wrote: neither can be repaired here.
    // A qcow2 layer the guest wrote may have grown past the checkpoint's
    // bytes; those are its own and are kept.
    if present.len() != chunked.chunks() || std::fs::metadata(disk)?.len() < chunked.size() {
        return Err(invalid("lazy disk presence record does not match the disk"));
    }
    if all_present(&present, chunked.chunks()) {
        return Ok(());
    }
    let file = std::fs::OpenOptions::new().write(true).open(disk)?;
    let missing: Vec<usize> = (0..chunked.chunks())
        .filter(|&i| present[i] != 1 && !chunked.is_zero(i))
        .collect();
    let next = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|scope| -> io::Result<()> {
        let workers: Vec<_> = (0..FILL_THREADS)
            .map(|_| {
                scope.spawn(|| -> io::Result<()> {
                    use std::os::unix::fs::FileExt;
                    loop {
                        let at = next.fetch_add(1, Ordering::Relaxed);
                        let Some(&chunk) = missing.get(at) else {
                            return Ok(());
                        };
                        if let Some(bytes) = read_arriving(&chunked, chunk, checkpoint)? {
                            file.write_all_at(&bytes, chunk as u64 * ChunkedFile::chunk_size())?;
                        }
                    }
                })
            })
            .collect();
        for worker in workers {
            worker
                .join()
                .map_err(|_| io::Error::other("lazy disk fill thread panicked"))??;
        }
        Ok(())
    })?;
    file.sync_all()?;
    write_present(&present_path(disk), &vec![1u8; chunked.chunks()])
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = "checkpoint/disks/storage/0";
    const MIB: usize = 1024 * 1024;

    /// A checkpoint published in `store` as `name`, holding `data` as its
    /// storage disk.
    fn publish_checkpoint(store: &Path, name: &str, data: &[u8]) -> PathBuf {
        let stored = store.join(PUBLISHED).join(name);
        std::fs::create_dir_all(&stored).unwrap();
        std::fs::create_dir_all(store.join("cache")).unwrap();
        let mut writer =
            crate::checkpoint_store::Writer::new(&store.join("cache"), &stored).unwrap();
        let file = writer
            .ingest(FILE, data.len() as u64, 0o600, &mut &*data)
            .unwrap();
        let manifest = smolvm_pack::format::PackManifest::new(
            "vm://test".into(),
            "none".into(),
            "linux/amd64".into(),
            "linux/amd64".into(),
        );
        writer.finish(&stored, manifest, vec![file]).unwrap();
        stored
    }

    /// Chunk `i` holds byte `i + 1`, except chunk 2, all zeros (no object).
    fn pattern(size: usize) -> Vec<u8> {
        let mut data = vec![0u8; size];
        for (i, chunk) in data.chunks_mut(MIB).enumerate() {
            if i != 2 {
                chunk.fill(i as u8 + 1);
            }
        }
        data
    }

    struct Setup {
        _root: tempfile::TempDir,
        store: PathBuf,
        stored: PathBuf,
        machine: PathBuf,
        disk: PathBuf,
    }

    /// A machine whose storage disk is lazy over a checkpoint holding `data`.
    fn lazy_machine(data: &[u8]) -> Setup {
        let root = tempfile::TempDir::new().unwrap();
        let store = root.path().join("store");
        let stored = publish_checkpoint(&store, "vm-a.checkpoint", data);
        let machine = root.path().join("vms").join("a");
        std::fs::create_dir_all(&machine).unwrap();
        let staged = machine.join(".staged");
        let disk = machine.join("storage.raw");
        stage(&stored, FILE, &staged).unwrap();
        record(&store, &machine, &stored).unwrap();
        publish(&stored, FILE, &staged, &disk).unwrap();
        Setup {
            _root: root,
            store,
            stored,
            machine,
            disk,
        }
    }

    #[test]
    fn a_staged_disk_holds_its_header_and_fills_to_the_checkpoint() {
        let data = pattern(4 * MIB + 4096);
        let m = lazy_machine(&data);

        assert!(is_lazy(&m.disk));
        assert_eq!(lazy_disks(&m.machine).unwrap(), vec![m.disk.clone()]);
        assert_eq!(
            trusted_checkpoint(&m.store, &m.machine),
            Some(m.stored.clone())
        );
        assert_eq!(kept_checkpoints(&m.store), vec!["vm-a.checkpoint"]);
        let partial = std::fs::read(&m.disk).unwrap();
        assert_eq!(partial.len(), data.len());
        assert_eq!(&partial[..MIB], &data[..MIB]);
        assert!(partial[MIB..].iter().all(|&b| b == 0));

        settle_in(&m.store, &m.machine).unwrap();
        assert!(!is_lazy(&m.disk));
        assert!(!present_path(&m.disk).exists());
        assert_eq!(std::fs::read(&m.disk).unwrap(), data);
        assert!(kept_checkpoints(&m.store).is_empty());
        assert!(!record_path(&m.store, &m.machine).unwrap().exists());
    }

    #[test]
    fn filling_keeps_chunks_the_guest_already_wrote() {
        let data = pattern(3 * MIB);
        let m = lazy_machine(&data);
        // What a VMM leaves: chunk 1 fetched then written by the guest.
        {
            use std::os::unix::fs::FileExt;
            let file = std::fs::OpenOptions::new()
                .write(true)
                .open(&m.disk)
                .unwrap();
            file.write_all_at(&[0xee; 16], MIB as u64).unwrap();
        }
        std::fs::write(present_path(&m.disk), [1, 1, 0]).unwrap();

        settle_in(&m.store, &m.machine).unwrap();
        let filled = std::fs::read(&m.disk).unwrap();
        assert_eq!(&filled[MIB..MIB + 16], &[0xee; 16]);
        assert_eq!(&filled[2 * MIB..], &data[2 * MIB..]);
    }

    #[test]
    fn a_disk_that_grew_past_its_checkpoint_keeps_the_growth() {
        let data = pattern(2 * MIB + 100);
        let m = lazy_machine(&data);
        {
            use std::os::unix::fs::FileExt;
            let file = std::fs::OpenOptions::new()
                .write(true)
                .open(&m.disk)
                .unwrap();
            file.write_all_at(b"grown", 5 * MIB as u64).unwrap();
        }
        settle_in(&m.store, &m.machine).unwrap();
        let filled = std::fs::read(&m.disk).unwrap();
        assert_eq!(&filled[..data.len()], &data[..]);
        assert_eq!(&filled[5 * MIB..], b"grown");
    }

    /// Take chunk 1's object out of `stored`, as if still on its way, and mark
    /// the checkpoint as being imported.
    fn hold_back_chunk_one(stored: &Path) -> (PathBuf, PathBuf) {
        let chunked = ChunkedFile::open(stored, FILE).unwrap();
        assert!(!chunked.is_zero(1));
        let index: serde_json::Value =
            serde_json::from_slice(&std::fs::read(stored.join("checkpoint.json")).unwrap())
                .unwrap();
        let hash = index["files"][0]["chunks"][1].as_str().unwrap().to_string();
        let object = stored.join("objects").join(&hash);
        let held = stored.join("held-object");
        std::fs::rename(&object, &held).unwrap();
        std::fs::write(stored.join(crate::checkpoint_store::IMPORTING), b"1\n").unwrap();
        (object, held)
    }

    #[test]
    fn filling_waits_for_a_chunk_still_being_imported() {
        let data = pattern(3 * MIB);
        let m = lazy_machine(&data);
        let (object, held) = hold_back_chunk_one(&m.stored);
        let arrives = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            std::fs::rename(held, object).unwrap();
        });
        settle_in(&m.store, &m.machine).unwrap();
        arrives.join().unwrap();
        assert_eq!(std::fs::read(&m.disk).unwrap(), data);
    }

    #[test]
    fn filling_stops_at_once_when_the_import_failed() {
        let m = lazy_machine(&pattern(3 * MIB));
        hold_back_chunk_one(&m.stored);
        std::fs::write(
            m.stored.join(crate::checkpoint_store::IMPORT_FAILED),
            b"1\n",
        )
        .unwrap();
        let started = Instant::now();
        assert!(settle_in(&m.store, &m.machine).is_err());
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(is_lazy(&m.disk));
    }

    #[test]
    fn a_damaged_presence_record_is_refused_not_guessed() {
        let m = lazy_machine(&pattern(2 * MIB));
        std::fs::write(present_path(&m.disk), [1]).unwrap();

        let error = settle_in(&m.store, &m.machine).unwrap_err();
        assert!(error.to_string().contains("does not match"), "{error}");
        assert!(is_lazy(&m.disk));
    }

    #[test]
    fn a_descriptor_pointed_at_another_checkpoint_is_not_followed() {
        let m = lazy_machine(&pattern(2 * MIB));
        // The machine's uid can rewrite its descriptor; another tenant's
        // checkpoint must not be copied into its disk.
        let other = publish_checkpoint(&m.store, "vm-b.checkpoint", &[0x42; 2 * MIB]);
        let mut descriptor = read_descriptor(&m.disk).unwrap();
        descriptor.index = other.join("checkpoint.json");
        descriptor.objects = other.join("objects");
        std::fs::write(
            descriptor_path(&m.disk),
            serde_json::to_vec(&descriptor).unwrap(),
        )
        .unwrap();

        let error = settle_in(&m.store, &m.machine).unwrap_err();
        assert!(error.to_string().contains("other than"), "{error}");
        assert!(std::fs::read(&m.disk).unwrap()[MIB..]
            .iter()
            .all(|&b| b == 0));
    }

    #[test]
    fn only_a_published_checkpoint_can_be_recorded() {
        let m = lazy_machine(&pattern(MIB));
        let elsewhere = m.machine.parent().unwrap().to_path_buf();
        assert!(record(&m.store, &m.machine, &elsewhere).is_err());
    }

    #[test]
    fn a_running_machine_is_waited_for_until_its_vmm_records_every_chunk() {
        let m = lazy_machine(&pattern(2 * MIB));

        // What a serving VMM holds.
        let vmm = std::fs::File::open(descriptor_path(&m.disk)).unwrap();
        vmm.lock_shared().unwrap();
        let error = wait_filled(&m.stored, &m.disk, Duration::from_millis(300)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        let waiting = {
            let (store, machine) = (m.store.clone(), m.machine.clone());
            std::thread::spawn(move || settle_in(&store, &machine))
        };
        std::thread::sleep(Duration::from_millis(300));
        // It waits on the VMM rather than filling underneath it.
        assert!(std::fs::read(&m.disk).unwrap()[MIB..]
            .iter()
            .all(|&b| b == 0));
        std::fs::write(present_path(&m.disk), [1, 1]).unwrap();
        waiting.join().unwrap().unwrap();
        assert!(!is_lazy(&m.disk));
    }
}
