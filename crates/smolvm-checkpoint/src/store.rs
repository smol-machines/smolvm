//! Content-addressed checkpoint directories. Each directory owns hard links to
//! every object it needs; deleting the cache or an older checkpoint cannot
//! invalidate a newer one. Export materializes a standalone pack on demand.

use serde::{Deserialize, Serialize};
use smolvm_pack::format::PackManifest;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::thread;

const CHUNK_SIZE: usize = 1024 * 1024;
const VERSION: u32 = 1;
const MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024 * 1024;
const INDEX: &str = "checkpoint.json";
/// Directory inside a stored checkpoint holding the indexes of the ancestor
/// generations it retains (see [`Writer::retain_generations`]).
pub const GENERATIONS: &str = "generations";
/// Directory inside a store recording where each checkpoint id was published.
const LINEAGE_DIR: &str = "lineage";
/// Upper bound on ancestor generations one checkpoint retains.
pub const MAX_RETAINED_GENERATIONS: usize = 256;
const CAPTURE_MARKER: &str = ".capture-owner";
const CAPTURE_MAGIC: &[u8] = b"smolvm-checkpoint-capture-v1\n";
const OBJECT_STAGING_PREFIX: &str = ".checkpoint-object-";

/// A file ingested by [`Writer`], ready to include in a checkpoint index.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredFile {
    path: String,
    size: u64,
    mode: u32,
    // None represents zeros, including a page that was nonzero previously.
    chunks: Vec<Option<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    version: u32,
    chunk_size: usize,
    manifest: PackManifest,
    files: Vec<StoredFile>,
}

/// Byte accounting for a capture; reused and zero bytes are logical sizes.
#[derive(Default, Debug)]
pub struct WriteStats {
    /// Compressed bytes stored as new objects.
    pub new_bytes: u64,
    /// Uncompressed bytes represented by new objects.
    pub new_logical_bytes: u64,
    /// Uncompressed bytes reused from verified existing objects.
    pub reused_bytes: u64,
    /// Zero-filled bytes represented without an object.
    pub zero_bytes: u64,
}

impl WriteStats {
    fn add(&mut self, other: &WriteStats) {
        self.new_bytes += other.new_bytes;
        self.new_logical_bytes += other.new_logical_bytes;
        self.reused_bytes += other.reused_bytes;
        self.zero_bytes += other.zero_bytes;
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn safe_relative(path: &str) -> bool {
    !path.is_empty()
        && Path::new(path)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref())
}

#[test]
fn checkpoint_hashes_match_existing_sha256_objects() {
    use sha2::{Digest, Sha256};
    let bytes: Vec<_> = (0..CHUNK_SIZE + 1)
        .map(|index| ((index * 73 + index / 127) & 255) as u8)
        .collect();
    for len in [0, 1, 55, 56, 63, 64, 65, 1024, CHUNK_SIZE, CHUNK_SIZE + 1] {
        assert_eq!(
            digest(&bytes[..len]),
            hex::encode(Sha256::digest(&bytes[..len]))
        );
    }
    assert_eq!(
        digest(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

/// Make a freshly written object durable enough to publish.
///
/// On macOS `File::sync_all` is `fcntl(F_FULLFSYNC)`: a flush of the whole
/// drive's write cache, not just this file. Measured on APFS it costs ~4.9 ms
/// per call, so a 1.5 GB incremental capture (~6,000 objects) spent ~30 s of
/// its 64 s doing device flushes one object at a time. A plain `fsync` (~0.2 ms)
/// gets the object's data and metadata to the drive, and [`Writer::finish`]
/// issues the one `F_FULLFSYNC` — through the index's `sync_all` — that pushes
/// the drive cache to stable storage for every object written before it. The
/// index is what makes objects reachable, so nothing can reference an object
/// that the final flush did not cover. Other platforms keep `sync_all`, where
/// it is already a per-file operation.
fn sync_object(file: &File) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::io::AsRawFd;
        if unsafe { libc::fsync(file.as_raw_fd()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        file.sync_all()
    }
}

fn decode_object(path: &Path, size: usize) -> io::Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > (CHUNK_SIZE + 128 * 1024) as u64
    {
        return Err(invalid("checkpoint object type or length mismatch"));
    }
    let mut bytes = Vec::with_capacity(size);
    let mut decoder = zstd::stream::read::Decoder::new(File::open(path)?)?;
    decoder.window_log_max(23)?;
    decoder.take(size as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() != size {
        return Err(invalid("checkpoint object checksum mismatch"));
    }
    Ok(bytes)
}

fn read_object(path: &Path, hash: &str, size: usize) -> io::Result<Vec<u8>> {
    let bytes = decode_object(path, size)?;
    if digest(&bytes) != hash {
        return Err(invalid("checkpoint object checksum mismatch"));
    }
    Ok(bytes)
}

/// Capture already computed the object key from `expected`. Exact byte
/// equality verifies the existing object against that same input without
/// hashing it twice. Restore has no trusted input and must use read_object.
fn verify_object_matches(path: &Path, expected: &[u8]) -> io::Result<()> {
    let bytes = decode_object(path, expected.len())?;
    if bytes != expected {
        return Err(invalid("checkpoint object checksum mismatch"));
    }
    Ok(())
}

/// A capture writes into a private staging directory and publishes it only
/// after the RAM stream, CPU/device state and disk snapshots have completed.
pub struct Writer {
    _lock: File,
    cache: std::path::PathBuf,
    objects: std::path::PathBuf,
    pool: Pool,
    /// Running byte accounting for this writer.
    pub stats: WriteStats,
}

impl Writer {
    /// Start a capture in an existing, empty, private staging directory.
    ///
    /// `cache` and `directory` must reside on the same filesystem so objects
    /// can be hard-linked. Keep both inaccessible to untrusted writers. Hold
    /// this writer until capture completes; drop it before calling [`prune`].
    pub fn new(cache: &Path, directory: &Path) -> io::Result<Self> {
        fs::create_dir_all(cache)?;
        let lock = cache_lock(cache, false)?;
        let mut marker = File::options()
            .write(true)
            .create_new(true)
            .open(directory.join(CAPTURE_MARKER))?;
        marker.write_all(CAPTURE_MAGIC)?;
        marker.sync_all()?;
        let cache = cache.join("objects");
        fs::create_dir_all(&cache)?;
        let objects = directory.join("objects");
        fs::create_dir(&objects)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if fs::metadata(&cache)?.dev() != fs::metadata(&objects)?.dev() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "checkpoint output and store must be on the same filesystem",
                ));
            }
        }
        let pool = Pool::start(&cache, &objects)?;
        Ok(Self {
            _lock: lock,
            cache,
            objects,
            pool,
            stats: WriteStats::default(),
        })
    }

    /// Read exactly `size` bytes under a safe relative path, reusing verified
    /// chunks from previous captures. The caller must supply a stable source.
    pub fn ingest(
        &mut self,
        path: &str,
        size: u64,
        mode: u32,
        source: &mut impl Read,
    ) -> io::Result<StoredFile> {
        if !safe_relative(path) || size > MAX_BYTES {
            return Err(invalid("invalid checkpoint file path or size"));
        }
        let mut remaining = size;
        let chunks = self.ingest_chunks(|buffer| {
            if remaining == 0 {
                return Ok(None);
            }
            let count = remaining.min(CHUNK_SIZE as u64) as usize;
            buffer.resize(count, 0);
            source.read_exact(buffer)?;
            remaining -= count as u64;
            Ok(Some(Job::Data))
        })?;
        Ok(StoredFile {
            path: path.into(),
            size,
            mode: mode & 0o777,
            chunks,
        })
    }

    /// Run one file's chunks through the worker pool. `next` fills the buffer
    /// it is handed with the next chunk in file order, or reports a hole, on
    /// this thread — which stays the only reader of the source — while the
    /// workers hash, compress, persist and link chunks concurrently; results
    /// are put back in file order here. At most `window` chunks are in flight,
    /// so the reader cannot run ahead of the workers into unbounded memory.
    /// The first error stops submission, but every chunk already in flight is
    /// still collected so no worker is left writing into an abandoned capture.
    fn ingest_chunks(
        &mut self,
        mut next: impl FnMut(&mut Vec<u8>) -> io::Result<Option<Job>>,
    ) -> io::Result<Vec<Option<String>>> {
        let window = self.pool.window;
        let (done, results) = mpsc::channel::<Done>();
        let mut pending: Vec<Option<Option<String>>> = Vec::new();
        let mut free: Vec<Vec<u8>> = Vec::new();
        let mut in_flight = 0usize;
        let mut failure: Option<io::Error> = None;
        loop {
            while failure.is_none() && in_flight < window {
                let mut buffer = free.pop().unwrap_or_default();
                buffer.clear();
                match next(&mut buffer) {
                    Ok(Some(Job::Hole(count))) => {
                        self.stats.zero_bytes += count as u64;
                        pending.push(Some(None));
                        free.push(buffer);
                    }
                    Ok(Some(Job::Data)) => {
                        let seq = pending.len();
                        pending.push(None);
                        if self.pool.submit(seq, buffer, done.clone()).is_err() {
                            failure = Some(io::Error::other("checkpoint worker pool stopped"));
                            break;
                        }
                        in_flight += 1;
                    }
                    Ok(None) => {
                        free.push(buffer);
                        break;
                    }
                    Err(error) => {
                        failure = Some(error);
                        break;
                    }
                }
            }
            if in_flight == 0 {
                break;
            }
            let Done { seq, bytes, result } = results
                .recv()
                .map_err(|_| io::Error::other("checkpoint worker exited"))?;
            in_flight -= 1;
            free.push(bytes);
            match result {
                Ok((hash, stats)) => {
                    self.stats.add(&stats);
                    pending[seq] = Some(hash);
                }
                Err(error) => {
                    if failure.is_none() {
                        failure = Some(error);
                    }
                    pending[seq] = Some(None);
                }
            }
        }
        if let Some(error) = failure {
            return Err(error);
        }
        Ok(pending
            .into_iter()
            .map(|slot| slot.expect("every submitted chunk resolved"))
            .collect())
    }

    /// Consume the libkrun stream before accepting its final success response.
    pub fn ingest_memory(
        &mut self,
        source: &mut impl Read,
        max_size: u64,
    ) -> io::Result<StoredFile> {
        let mut header = [0; 16];
        source.read_exact(&mut header)?;
        if &header[..8] != b"SMOLRAM1" {
            return Err(invalid("runtime does not support checkpoint RAM streaming"));
        }
        let size = u64::from_le_bytes(header[8..].try_into().unwrap());
        if size == 0 || size > max_size.min(MAX_BYTES) {
            return Err(invalid(
                "checkpoint RAM stream exceeds configured memory layout",
            ));
        }
        self.ingest("checkpoint/memory.bin", size, 0o600, source)
    }

    /// Ingest a stable directory tree. Symlinks and special files are rejected.
    pub fn ingest_tree(&mut self, root: &Path) -> io::Result<Vec<StoredFile>> {
        fn visit(
            writer: &mut Writer,
            root: &Path,
            dir: &Path,
            result: &mut Vec<StoredFile>,
        ) -> io::Result<()> {
            let mut entries = fs::read_dir(dir)?.collect::<io::Result<Vec<_>>>()?;
            entries.sort_by_key(|e| e.file_name());
            for entry in entries {
                let kind = entry.file_type()?;
                if kind.is_dir() {
                    visit(writer, root, &entry.path(), result)?;
                } else if kind.is_file() {
                    #[cfg(unix)]
                    let mode = {
                        use std::os::unix::fs::PermissionsExt;
                        entry.metadata()?.permissions().mode()
                    };
                    #[cfg(not(unix))]
                    let mode = 0o600;
                    let path = entry.path();
                    let relative = path
                        .strip_prefix(root)
                        .map_err(|_| invalid("checkpoint path escaped staging"))?;
                    let relative = relative
                        .to_str()
                        .ok_or_else(|| invalid("non-UTF8 checkpoint asset"))?;
                    result.push(writer.ingest_file(relative, mode, &mut File::open(&path)?)?);
                } else {
                    return Err(invalid("checkpoint staging contains a non-regular asset"));
                }
            }
            Ok(())
        }
        let mut files = Vec::new();
        visit(self, root, root, &mut files)?;
        Ok(files)
    }

    // Disk images and templates may be tens of GiB logically but mostly holes.
    // Preserve those holes without reading and scanning their logical zeros.
    fn ingest_file(&mut self, path: &str, mode: u32, source: &mut File) -> io::Result<StoredFile> {
        let size = source.metadata()?.len();
        if !safe_relative(path) || size > MAX_BYTES {
            return Err(invalid("invalid checkpoint asset"));
        }
        let mut offset = 0;
        #[cfg(unix)]
        let mut seek_sparse = true;
        let chunks = self.ingest_chunks(|buffer| {
            if offset >= size {
                return Ok(None);
            }
            let count = (size - offset).min(CHUNK_SIZE as u64);
            #[cfg(unix)]
            let hole = if seek_sparse {
                use std::os::fd::AsRawFd;
                let data = unsafe {
                    libc::lseek(source.as_raw_fd(), offset as libc::off_t, libc::SEEK_DATA)
                };
                if data >= 0 {
                    data as u64 >= offset + count
                } else {
                    let error = io::Error::last_os_error();
                    match error.raw_os_error() {
                        Some(libc::ENXIO) => true,
                        Some(libc::EINVAL) | Some(libc::ENOTSUP) => {
                            seek_sparse = false;
                            false
                        }
                        _ => return Err(error),
                    }
                }
            } else {
                false
            };
            #[cfg(not(unix))]
            let hole = false;
            let job = if hole {
                Job::Hole(count as usize)
            } else {
                buffer.resize(count as usize, 0);
                source.seek(SeekFrom::Start(offset))?;
                source.read_exact(buffer)?;
                Job::Data
            };
            offset += count;
            Ok(Some(job))
        })?;
        Ok(StoredFile {
            path: path.into(),
            size,
            mode: mode & 0o777,
            chunks,
        })
    }

    /// Write and sync the index in the same directory passed to [`Self::new`].
    ///
    /// Call once, only after every source operation has succeeded. Use
    /// [`publish`] afterwards to atomically expose the completed checkpoint.
    /// Failed staging directories belong to the caller and must be removed.
    pub fn finish(
        &mut self,
        directory: &Path,
        manifest: PackManifest,
        files: Vec<StoredFile>,
    ) -> io::Result<WriteStats> {
        let index = Index {
            version: VERSION,
            chunk_size: CHUNK_SIZE,
            manifest,
            files,
        };
        validate_index(&index)?;
        let mut file = File::options()
            .write(true)
            .create_new(true)
            .open(directory.join(INDEX))?;
        serde_json::to_writer(&mut file, &index)?;
        file.sync_all()?;
        File::open(&self.objects)?.sync_all()?;
        File::open(&self.cache)?.sync_all()?;
        File::open(directory)?.sync_all()?;
        Ok(std::mem::take(&mut self.stats))
    }
}

impl Writer {
    /// Retain `parent`'s generation, and every generation `parent` retains, in
    /// the checkpoint being written at `directory`: their indexes are copied
    /// under [`GENERATIONS`] and every object they reference is hard-linked
    /// into this checkpoint's `objects`, so any of them can be restored from
    /// this directory alone. Shared chunks cost nothing beyond the link — the
    /// history is stored as differences. Returns how many generations were
    /// retained; `limit` bounds the depth (newest first).
    pub fn retain_generations(
        &mut self,
        directory: &Path,
        parent: &Path,
        limit: usize,
    ) -> io::Result<usize> {
        self.retain_generations_from(directory, parent, None, limit)
    }

    /// [`retain_generations`](Self::retain_generations) starting at generation
    /// `start` within `source`'s history rather than at `source` itself — used
    /// when the parent's own directory is gone but another checkpoint in the
    /// store still retains it.
    pub fn retain_generations_from(
        &mut self,
        directory: &Path,
        source: &Path,
        start: Option<&str>,
        limit: usize,
    ) -> io::Result<usize> {
        let limit = limit.min(MAX_RETAINED_GENERATIONS);
        if limit == 0 {
            return Ok(0);
        }
        let mut sources: Vec<(String, std::path::PathBuf)> = Vec::new();
        let mut started = start.is_none();
        for generation in lineage_of(source)? {
            if !started {
                started = start == Some(generation.id.as_str());
                if !started {
                    continue;
                }
            }
            let path = if generation.retained {
                source.join(GENERATIONS).join(&generation.id).join(INDEX)
            } else {
                source.join(INDEX)
            };
            sources.push((generation.id, path));
        }
        if !started {
            return Err(invalid("start generation is not in the source's history"));
        }
        sources.truncate(limit);
        let parent_objects = source.join("objects");
        let generations = directory.join(GENERATIONS);
        let mut retained = 0;
        for (id, index_path) in sources {
            let index = read_index_from(&index_path)?;
            for hash in index.files.iter().flat_map(|f| f.chunks.iter().flatten()) {
                let destination = self.objects.join(hash);
                if destination.exists() {
                    continue;
                }
                let source = parent_objects.join(hash);
                let source = if source.is_file() {
                    source
                } else {
                    self.cache.join(hash)
                };
                match fs::hard_link(&source, &destination) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(e),
                }
            }
            let target = generations.join(&id);
            fs::create_dir_all(&target)?;
            fs::copy(&index_path, target.join(INDEX))?;
            retained += 1;
        }
        if retained > 0 {
            File::open(&generations)?.sync_all()?;
        }
        Ok(retained)
    }
}

/// One generation reachable from a stored checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Generation {
    /// Checkpoint id of this generation.
    pub id: String,
    /// Id of the generation it continues from, when known.
    pub parent: Option<String>,
    /// Machine the generation was captured from.
    pub machine: String,
    /// When it was published (RFC 3339).
    pub created_at: String,
    /// Bytes of actual data the generation describes (holes and zero chunks
    /// excluded), the figure a restore has to materialize.
    pub data_bytes: u64,
    /// `false` for the checkpoint's own generation, `true` for a retained ancestor.
    pub retained: bool,
}

fn generation_of(index: &Index, retained: bool) -> Option<Generation> {
    let lineage = index.manifest.checkpoint.as_ref()?.lineage.as_ref()?;
    Some(Generation {
        id: lineage.id.clone(),
        parent: lineage.parent.clone(),
        machine: lineage.machine.clone(),
        created_at: lineage.created_at.clone(),
        data_bytes: index.files.iter().map(data_size).sum(),
        retained,
    })
}

/// The checkpoint's own generation followed by the ancestors it retains,
/// newest first along the parent chain. A checkpoint written before lineage
/// was recorded yields an empty list.
pub fn lineage_of(directory: &Path) -> io::Result<Vec<Generation>> {
    let Some(own) = generation_of(&read_index(directory)?, false) else {
        return Ok(Vec::new());
    };
    let mut retained: HashMap<String, Generation> = HashMap::new();
    let generations = directory.join(GENERATIONS);
    if generations.is_dir() {
        for entry in fs::read_dir(&generations)? {
            let entry = entry?;
            let id = entry.file_name().to_string_lossy().into_owned();
            if !valid_generation_id(&id) || !entry.file_type()?.is_dir() {
                continue;
            }
            if let Some(generation) =
                generation_of(&read_index_from(&entry.path().join(INDEX))?, true)
            {
                if generation.id == id {
                    retained.insert(id, generation);
                }
            }
        }
    }
    let mut chain = vec![own];
    while let Some(parent) = chain.last().and_then(|g| g.parent.clone()) {
        match retained.remove(&parent) {
            Some(generation) => chain.push(generation),
            None => break,
        }
    }
    // Generations kept from an older lineage that this chain no longer links
    // to are still restorable; list them after the chain.
    let mut leftovers: Vec<Generation> = retained.into_values().collect();
    leftovers.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    chain.extend(leftovers);
    Ok(chain)
}

/// Resolve a user-supplied generation reference against `directory`: `~N`
/// (N generations back along the chain; `~0` is the checkpoint itself), a
/// full id, or an unambiguous id prefix of at least eight characters. Returns
/// `None` for the checkpoint's own generation and `Some(id)` for a retained
/// ancestor.
pub fn resolve_generation(directory: &Path, at: &str) -> io::Result<Option<String>> {
    resolve_in(&lineage_of(directory)?, at)
}

/// [`resolve_generation`] against an already-listed history (a directory's
/// [`lineage_of`], or a file's manifest history via [`generations_from_history`]).
pub fn resolve_in(lineage: &[Generation], at: &str) -> io::Result<Option<String>> {
    let at = at.trim();
    let generation = if let Some(depth) = at.strip_prefix('~') {
        let depth: usize = depth
            .parse()
            .map_err(|_| invalid("generation must be ~N, an id, or an id prefix"))?;
        lineage.get(depth).ok_or_else(|| {
            invalid(format!(
                "this checkpoint keeps {} earlier generation(s); ~{depth} is out of range",
                lineage.len().saturating_sub(1)
            ))
        })?
    } else {
        if at.len() < 8 || !at.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(invalid(
                "generation must be ~N, an id, or an id prefix of 8+ hex characters",
            ));
        }
        let at = at.to_ascii_lowercase();
        let mut matches = lineage.iter().filter(|g| g.id.starts_with(&at));
        let first = matches
            .next()
            .ok_or_else(|| invalid(format!("no generation matches {at}")))?;
        if matches.next().is_some() {
            return Err(invalid(format!("generation prefix {at} is ambiguous")));
        }
        first
    };
    Ok(generation.retained.then(|| generation.id.clone()))
}

/// The history a `Chunked` checkpoint file advertises in its manifest, in the
/// same shape as [`lineage_of`]: the file's own generation first.
pub fn generations_from_history(
    history: &[smolvm_pack::format::CheckpointGeneration],
) -> Vec<Generation> {
    history
        .iter()
        .enumerate()
        .map(|(index, generation)| Generation {
            id: generation.lineage.id.clone(),
            parent: generation.lineage.parent.clone(),
            machine: generation.lineage.machine.clone(),
            created_at: generation.lineage.created_at.clone(),
            data_bytes: generation.data_bytes,
            retained: index > 0,
        })
        .collect()
}

/// Export `directory` as ONE file that carries its history: the checkpoint's
/// index, the indexes of up to `limit` retained generations, and every object
/// any of them references, packed as a `Chunked` checkpoint. Restoring such a
/// file unpacks it into a directory checkpoint, so `--at` works on it exactly
/// as on the directory. `decorate` lets the caller stamp the outer manifest
/// (format version); the per-generation manifests inside are untouched.
///
/// Returns the file size and how many earlier generations it carries. With no
/// retained generations (or `limit == 0`) this is a plain [`export`].
pub fn export_with_history(
    directory: &Path,
    limit: usize,
    output: &Path,
    decorate: impl FnOnce(&mut PackManifest),
) -> io::Result<(u64, usize)> {
    let lineage = lineage_of(directory)?;
    let retained: Vec<&Generation> = lineage.iter().skip(1).take(limit).collect();
    if retained.is_empty() {
        return export(directory, output).map(|bytes| (bytes, 0));
    }
    if output.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "checkpoint output exists",
        ));
    }
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let temporary = tempfile::Builder::new()
        .prefix(".checkpoint-export-")
        .tempdir_in(parent)?;
    let staging = temporary.path().join("staging");
    fs::create_dir_all(staging.join("objects"))?;
    let own = read_index(directory)?;
    fs::copy(directory.join(INDEX), staging.join(INDEX))?;
    let mut hashes: HashSet<String> = HashSet::new();
    let mut indexes = vec![own];
    for generation in &retained {
        let source = directory.join(GENERATIONS).join(&generation.id);
        let target = staging.join(GENERATIONS).join(&generation.id);
        fs::create_dir_all(&target)?;
        fs::copy(source.join(INDEX), target.join(INDEX))?;
        indexes.push(read_index_from(&source.join(INDEX))?);
    }
    for index in &indexes {
        for hash in index.files.iter().flat_map(|f| f.chunks.iter().flatten()) {
            hashes.insert(hash.clone());
        }
    }
    let objects = directory.join("objects");
    for hash in &hashes {
        let source = objects.join(hash);
        let target = staging.join("objects").join(hash);
        if fs::hard_link(&source, &target).is_err() {
            fs::copy(&source, &target)?;
        }
    }
    let mut manifest = indexes.remove(0).manifest;
    {
        let checkpoint = manifest
            .checkpoint
            .as_mut()
            .ok_or_else(|| invalid("stored checkpoint has no live-state manifest"))?;
        checkpoint.payload = smolvm_pack::format::CheckpointLayout::Chunked;
        checkpoint.history = lineage
            .iter()
            .take(retained.len() + 1)
            .map(|generation| smolvm_pack::format::CheckpointGeneration {
                lineage: smolvm_pack::format::CheckpointLineage {
                    id: generation.id.clone(),
                    parent: generation.parent.clone(),
                    machine: generation.machine.clone(),
                    created_at: generation.created_at.clone(),
                },
                data_bytes: generation.data_bytes,
            })
            .collect();
    }
    decorate(&mut manifest);
    let collector =
        smolvm_pack::assets::AssetCollector::new(staging).map_err(|e| invalid(e.to_string()))?;
    let artifact = temporary.path().join("export.smolcheckpoint");
    let info = smolvm_pack::packer::Packer::new(manifest)
        .with_asset_collector(collector)
        .pack_artifact(&artifact)
        .map_err(|e| invalid(e.to_string()))?;
    File::open(&artifact)?.sync_all()?;
    publish(&artifact, output)?;
    Ok((info.total_size, retained.len()))
}

/// Where a checkpoint id was published within a store, so a later capture of
/// the same machine can find its parent and retain it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LineageRecord {
    /// Checkpoint id.
    pub id: String,
    /// Id of the checkpoint it continues from, when the source had one.
    #[serde(default)]
    pub parent: Option<String>,
    /// Machine it was captured from.
    pub machine: String,
    /// When it was published (RFC 3339).
    pub created_at: String,
    /// Published checkpoint directory (absolute).
    pub path: String,
}

/// Record a published checkpoint in the store's lineage index.
pub fn record_lineage(store: &Path, record: &LineageRecord) -> io::Result<()> {
    if !valid_generation_id(&record.id) {
        return Err(invalid("invalid checkpoint generation id"));
    }
    let dir = store.join(LINEAGE_DIR);
    fs::create_dir_all(&dir)?;
    let final_path = dir.join(format!("{}.json", record.id));
    let temp = dir.join(format!(".{}.json.tmp", record.id));
    {
        let mut file = File::create(&temp)?;
        serde_json::to_writer(&mut file, record)?;
        file.sync_all()?;
    }
    fs::rename(&temp, &final_path)?;
    File::open(&dir)?.sync_all()?;
    Ok(())
}

/// A checkpoint directory in `store` from which generation `id` can still be
/// retained: the checkpoint itself if its directory exists, else the newest
/// checkpoint that retains it. Returns the directory and whether `id` is that
/// directory's own generation.
pub fn find_generation_source(
    store: &Path,
    id: &str,
) -> io::Result<Option<(std::path::PathBuf, bool)>> {
    if let Some(record) = find_lineage(store, id)? {
        let path = std::path::PathBuf::from(&record.path);
        if path.join(INDEX).is_file() {
            return Ok(Some((path, true)));
        }
    }
    let mut records = list_lineage(store)?;
    records.reverse();
    for record in records {
        let path = std::path::PathBuf::from(&record.path);
        if path.join(GENERATIONS).join(id).join(INDEX).is_file() {
            return Ok(Some((path, false)));
        }
    }
    Ok(None)
}

/// Look up where a checkpoint id was published in `store`.
pub fn find_lineage(store: &Path, id: &str) -> io::Result<Option<LineageRecord>> {
    if !valid_generation_id(id) {
        return Ok(None);
    }
    let path = store.join(LINEAGE_DIR).join(format!("{id}.json"));
    match File::open(&path) {
        Ok(file) => Ok(Some(serde_json::from_reader(file)?)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Every checkpoint ever published into `store`, oldest first. Records whose
/// directory has since been deleted are included; callers check `path`.
pub fn list_lineage(store: &Path) -> io::Result<Vec<LineageRecord>> {
    let dir = store.join(LINEAGE_DIR);
    let mut records = Vec::new();
    if !dir.is_dir() {
        return Ok(records);
    }
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".json") || name.starts_with('.') {
            continue;
        }
        if let Ok(record) = serde_json::from_reader::<_, LineageRecord>(File::open(entry.path())?) {
            records.push(record);
        }
    }
    records.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
    Ok(records)
}

/// Bytes of a stored file backed by objects: every non-hole chunk, with the
/// final chunk counted at its real length.
fn data_size(file: &StoredFile) -> u64 {
    let chunks = file.chunks.len();
    file.chunks
        .iter()
        .enumerate()
        .filter(|(_, hash)| hash.is_some())
        .map(|(index, _)| {
            if index + 1 == chunks {
                file.size - index as u64 * CHUNK_SIZE as u64
            } else {
                CHUNK_SIZE as u64
            }
        })
        .sum()
}

/// One chunk of a file, as produced by the reading thread.
enum Job {
    /// A filesystem hole of this many bytes: recorded, never read or stored.
    Hole(usize),
    /// The reader filled the buffer it was handed with this chunk's bytes.
    Data,
}

struct Done {
    seq: usize,
    /// The chunk buffer, handed back so the reader can refill it instead of
    /// allocating a fresh megabyte per chunk.
    bytes: Vec<u8>,
    /// `None` when the chunk was all zero bytes.
    result: io::Result<(Option<String>, WriteStats)>,
}

type Submission = (usize, Vec<u8>, mpsc::Sender<Done>);

/// Worker threads that turn chunk bytes into store objects. Hashing and
/// compressing are most of a capture's cost and every chunk is independent of
/// every other, so they run across the machine's cores while a single reader
/// thread stays on the (serial) source. `SMOLVM_CHECKPOINT_THREADS` overrides
/// the worker count; `1` reproduces the serial behaviour.
struct Pool {
    jobs: Option<mpsc::SyncSender<Submission>>,
    workers: Vec<thread::JoinHandle<()>>,
    /// Chunks in flight per file: enough to keep every worker busy while the
    /// reader refills, small enough that buffers stay at a few dozen MiB.
    window: usize,
    inline_paths: (std::path::PathBuf, std::path::PathBuf),
    // Released only after Drop has joined every worker.
    _permit: WorkerPermit,
}

impl Pool {
    fn start(cache: &Path, objects: &Path) -> io::Result<Self> {
        Self::start_with_budget(cache, objects, process_worker_budget())
    }

    fn start_with_budget(
        cache: &Path,
        objects: &Path,
        budget: Arc<WorkerBudget>,
    ) -> io::Result<Self> {
        Self::start_with_spawner(cache, objects, budget, worker_threads(), |job| {
            thread::Builder::new()
                .name("checkpoint-store".into())
                .spawn(job)
        })
    }

    fn start_with_spawner(
        cache: &Path,
        objects: &Path,
        budget: Arc<WorkerBudget>,
        requested: usize,
        mut spawn: impl FnMut(Box<dyn FnOnce() + Send>) -> io::Result<thread::JoinHandle<()>>,
    ) -> io::Result<Self> {
        let permit = budget.acquire(requested);
        let threads = permit.count;
        let window = (threads * 2).max(1);
        let (jobs, receiver) = mpsc::sync_channel::<Submission>(window);
        let receiver = Arc::new(Mutex::new(receiver));
        let mut workers = Vec::new();
        for _ in 0..threads {
            let receiver = Arc::clone(&receiver);
            let cache = cache.to_path_buf();
            let objects = objects.to_path_buf();
            let worker = spawn(Box::new(move || loop {
                let next = receiver.lock().unwrap_or_else(|e| e.into_inner()).recv();
                let Ok((seq, bytes, done)) = next else { break };
                let result = worker_result(|| store_chunk(&cache, &objects, &bytes));
                // The submitter may already have abandoned this file; its
                // receiver being gone is not an error here.
                let _ = done.send(Done { seq, bytes, result });
            }));
            match worker {
                Ok(worker) => workers.push(worker),
                Err(error) => {
                    drop(jobs);
                    for worker in workers {
                        let _ = worker.join();
                    }
                    return Err(error);
                }
            }
        }
        Ok(Self {
            jobs: (threads != 0).then_some(jobs),
            workers,
            window,
            inline_paths: (cache.to_path_buf(), objects.to_path_buf()),
            _permit: permit,
        })
    }

    fn submit(&self, seq: usize, bytes: Vec<u8>, done: mpsc::Sender<Done>) -> Result<(), ()> {
        if self.workers.is_empty() {
            let result =
                worker_result(|| store_chunk(&self.inline_paths.0, &self.inline_paths.1, &bytes));
            return done.send(Done { seq, bytes, result }).map_err(|_| ());
        }
        self.jobs
            .as_ref()
            .expect("pool sender lives until drop")
            .send((seq, bytes, done))
            .map_err(|_| ())
    }
}

// Capture and restore share this budget. Contended operations run on their
// existing caller thread instead of waiting for another capture to finish.
struct WorkerBudget {
    limit: usize,
    used: AtomicUsize,
}

impl WorkerBudget {
    fn acquire(self: &Arc<Self>, requested: usize) -> WorkerPermit {
        let previous = self
            .used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                Some(used + requested.min(self.limit.saturating_sub(used)))
            })
            .expect("worker reservation always supplies a value");
        WorkerPermit {
            count: requested.min(self.limit.saturating_sub(previous)),
            budget: Arc::clone(self),
        }
    }
}

struct WorkerPermit {
    count: usize,
    budget: Arc<WorkerBudget>,
}

impl Drop for WorkerPermit {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.count, Ordering::AcqRel);
    }
}

fn process_worker_budget() -> Arc<WorkerBudget> {
    static BUDGET: OnceLock<Arc<WorkerBudget>> = OnceLock::new();
    Arc::clone(BUDGET.get_or_init(|| {
        Arc::new(WorkerBudget {
            limit: worker_threads(),
            used: AtomicUsize::new(0),
        })
    }))
}

fn worker_result<T>(work: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(work))
        .unwrap_or_else(|_| Err(io::Error::other("checkpoint worker panicked")))
}

/// Worker threads for chunk work: one per core unless `SMOLVM_CHECKPOINT_THREADS`
/// says otherwise (`1` reproduces the serial behaviour).
fn worker_threads() -> usize {
    std::env::var("SMOLVM_CHECKPOINT_THREADS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|count| *count > 0)
        .unwrap_or_else(|| {
            thread::available_parallelism()
                .map(|count| count.get())
                .unwrap_or(4)
        })
        .min(32)
}

/// Run `work` over `jobs` on up to `threads` scoped threads. The first error
/// stops new work from starting; jobs already running finish, and the error
/// is returned once every thread has stopped.
fn for_each_parallel<J: Send>(
    threads: usize,
    jobs: impl Iterator<Item = J>,
    work: impl Fn(J) -> io::Result<()> + Sync,
) -> io::Result<()> {
    for_each_with_budget(threads, jobs, work, process_worker_budget())
}

fn for_each_with_budget<J: Send>(
    requested: usize,
    mut jobs: impl Iterator<Item = J>,
    work: impl Fn(J) -> io::Result<()> + Sync,
    budget: Arc<WorkerBudget>,
) -> io::Result<()> {
    let permit = budget.acquire(requested);
    let threads = permit.count;
    if threads == 0 {
        return jobs.try_for_each(|job| worker_result(|| work(job)));
    }
    let failure: Mutex<Option<io::Error>> = Mutex::new(None);
    let failed = || failure.lock().unwrap_or_else(|e| e.into_inner()).is_some();
    let (sender, receiver) = mpsc::sync_channel::<J>(threads * 2);
    let receiver = Mutex::new(receiver);
    thread::scope(|scope| {
        for _ in 0..threads {
            let spawned = thread::Builder::new()
                .name("checkpoint-restore".into())
                .spawn_scoped(scope, || loop {
                    let job = receiver.lock().unwrap_or_else(|e| e.into_inner()).recv();
                    let Ok(job) = job else { break };
                    if failed() {
                        continue;
                    }
                    if let Err(error) = worker_result(|| work(job)) {
                        failure
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .get_or_insert(error);
                    }
                });
            if let Err(error) = spawned {
                failure
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .get_or_insert(error);
                break;
            }
        }
        for job in jobs {
            if failed() || sender.send(job).is_err() {
                break;
            }
        }
        // Closing the channel is what lets idle workers exit before the
        // scope joins them.
        drop(sender);
    });
    match failure.into_inner().unwrap_or_else(|e| e.into_inner()) {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Write `bytes` at `offset` without moving a shared cursor, so workers can
/// fill one file concurrently.
fn write_at(file: &File, offset: u64, bytes: &[u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.write_all_at(bytes, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let mut written = 0;
        while written < bytes.len() {
            let count = file.seek_write(&bytes[written..], offset + written as u64)?;
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "checkpoint asset write returned zero bytes",
                ));
            }
            written += count;
        }
        Ok(())
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        self.jobs.take();
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

/// Store one chunk: all-zero chunks are only counted; otherwise hash it, reuse
/// the cached object when it holds these exact bytes, else compress and
/// publish it, then hard-link it into this checkpoint. Two workers (or two
/// concurrent captures) storing the same content race on `persist_noclobber`;
/// the loser verifies and keeps the winner's object.
fn store_chunk(
    cache: &Path,
    objects: &Path,
    bytes: &[u8],
) -> io::Result<(Option<String>, WriteStats)> {
    let mut stats = WriteStats::default();
    let count = bytes.len() as u64;
    if smolvm_pack::is_zero_filled(bytes) {
        stats.zero_bytes += count;
        return Ok((None, stats));
    }
    let hash = digest(bytes);
    let cached = cache.join(&hash);
    match verify_object_matches(&cached, bytes) {
        Ok(_) => stats.reused_bytes += count,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut temp = tempfile::Builder::new()
                .prefix(OBJECT_STAGING_PREFIX)
                .tempfile_in(cache)?;
            let compressed = zstd::bulk::compress(bytes, 3)?;
            temp.write_all(&compressed)?;
            sync_object(temp.as_file())?;
            match temp.persist_noclobber(&cached) {
                Ok(_) => {
                    stats.new_bytes += compressed.len() as u64;
                    stats.new_logical_bytes += count;
                }
                Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
                    verify_object_matches(&cached, bytes)?;
                    stats.reused_bytes += count;
                }
                Err(error) => return Err(error.error),
            }
        }
        Err(error) => return Err(error),
    }
    let linked = objects.join(&hash);
    match fs::hard_link(&cached, &linked) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            verify_object_matches(&linked, bytes)?;
        }
        // Cross-device copies would silently remove the storage benefit, so
        // require the store and output on one volume.
        Err(error) => return Err(error),
    }
    Ok((Some(hash), stats))
}

fn cache_lock(cache: &Path, exclusive: bool) -> io::Result<File> {
    let lock = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(cache.join(".lock"))?;
    if exclusive {
        lock.lock()?;
    } else {
        lock.lock_shared()?;
    }
    Ok(lock)
}

/// Remove cache objects that no retained checkpoint references. Captures hold
/// a shared lock until all hard links are durable; pruning takes it exclusively.
#[cfg(unix)]
pub fn prune(cache: &Path) -> io::Result<u64> {
    let _lock = cache_lock(cache, true)?;
    let staging = cache.join("staging");
    if staging.is_dir() {
        for entry in fs::read_dir(&staging)? {
            let entry = entry?;
            if entry.file_type()?.is_dir()
                && entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".checkpoint-")
                && fs::read(entry.path().join(CAPTURE_MARKER)).ok().as_deref()
                    == Some(CAPTURE_MAGIC)
            {
                // No capture can hold this store's shared lock here. These are
                // unpublished directories left by a terminated capture.
                fs::remove_dir_all(entry.path())?;
            }
        }
        File::open(&staging)?.sync_all()?;
    }
    let objects = cache.join("objects");
    let mut removed = 0;
    for entry in fs::read_dir(&objects)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(OBJECT_STAGING_PREFIX) {
            removed += entry.metadata()?.len();
            fs::remove_file(entry.path())?;
            continue;
        }
        if name.len() != 64
            || !name
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            continue;
        }
        let meta = entry.metadata()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if meta.nlink() == 1 {
                fs::remove_file(entry.path())?;
                removed += meta.len();
            }
        }
    }
    File::open(&objects)?.sync_all()?;
    Ok(removed)
}

/// Stored checkpoint creation and pruning require Linux or macOS.
#[cfg(not(unix))]
pub fn prune(_cache: &Path) -> io::Result<u64> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "stored checkpoints require Linux or macOS",
    ))
}

fn validate_index(index: &Index) -> io::Result<()> {
    if index.version != VERSION || index.chunk_size != CHUNK_SIZE || index.files.len() > 100_000 {
        return Err(invalid("unsupported or oversized checkpoint index"));
    }
    let mut paths = HashSet::new();
    let mut total = 0_u64;
    for file in &index.files {
        total = total
            .checked_add(file.size)
            .ok_or_else(|| invalid("checkpoint size overflow"))?;
        if total > MAX_BYTES
            || !safe_relative(&file.path)
            || !paths.insert(&file.path)
            || file.chunks.len() as u64 != file.size.div_ceil(CHUNK_SIZE as u64)
            || file.mode & !0o777 != 0
        {
            return Err(invalid("invalid checkpoint file index"));
        }
        for hash in file.chunks.iter().flatten() {
            if hash.len() != 64
                || !hash
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(invalid("invalid checkpoint object digest"));
            }
        }
    }
    Ok(())
}

fn read_index_from(path: &Path) -> io::Result<Index> {
    if fs::symlink_metadata(path)?.len() > 256 * 1024 * 1024 {
        return Err(invalid("checkpoint index too large"));
    }
    let index: Index = serde_json::from_reader(File::open(path)?)?;
    validate_index(&index)?;
    Ok(index)
}

fn read_index(directory: &Path) -> io::Result<Index> {
    read_index_from(&directory.join(INDEX))
}

fn valid_generation_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Path of the index describing `generation`: the checkpoint's own index for
/// `None`, or the retained copy of an ancestor's index.
fn index_path(directory: &Path, generation: Option<&str>) -> io::Result<std::path::PathBuf> {
    match generation {
        None => Ok(directory.join(INDEX)),
        Some(id) if valid_generation_id(id) => Ok(directory.join(GENERATIONS).join(id).join(INDEX)),
        Some(_) => Err(invalid("invalid checkpoint generation id")),
    }
}

fn read_index_at(directory: &Path, generation: Option<&str>) -> io::Result<Index> {
    read_index_from(&index_path(directory, generation)?)
}

/// Read and validate the object index before allocating restore resources.
pub fn read_manifest(directory: &Path) -> io::Result<PackManifest> {
    read_manifest_at(directory, None)
}

/// [`read_manifest`] for the checkpoint's own generation (`None`) or one of the
/// ancestor generations it retains.
pub fn read_manifest_at(directory: &Path, generation: Option<&str>) -> io::Result<PackManifest> {
    let manifest = read_index_at(directory, generation)?.manifest;
    if manifest.checkpoint.is_none() {
        return Err(invalid("stored checkpoint has no live-state manifest"));
    }
    Ok(manifest)
}

/// Restore into a fresh private directory; never map writable VM memory from
/// an object shared with a retained checkpoint.
pub fn materialize(directory: &Path, output: &Path) -> io::Result<PackManifest> {
    materialize_with_base(directory, output, None)
}

/// [`materialize`] for a retained ancestor generation of `directory`. Every
/// object an ancestor needs was hard-linked into the checkpoint when it was
/// retained, so this works even after the ancestor's own directory is gone.
pub fn materialize_at(
    directory: &Path,
    generation: &str,
    output: &Path,
) -> io::Result<PackManifest> {
    materialize_generation(directory, Some(generation), output, None)
}

/// Like [`materialize`], but when `base` holds a pristine materialization of
/// another checkpoint (see [`promote_base`]), every file that exists in both
/// starts as a clone of the base's copy and only the chunks whose content hash
/// differs are decoded and written; chunks that became holes are punched out.
/// A save point typically changes a few MB of a multi-GiB disk, so this turns
/// a restore from "rewrite everything" into "rewrite the difference". Any file
/// that cannot be cloned is materialized in full, so a missing or unusable
/// base only costs speed.
pub fn materialize_with_base(
    directory: &Path,
    output: &Path,
    base: Option<&Path>,
) -> io::Result<PackManifest> {
    materialize_generation(directory, None, output, base)
}

fn materialize_generation(
    directory: &Path,
    generation: Option<&str>,
    output: &Path,
    base: Option<&Path>,
) -> io::Result<PackManifest> {
    let index = read_index_at(directory, generation)?;
    // Hold the base's shared lock for the whole restore: a concurrent
    // promotion takes it exclusively, so the files cloned below always belong
    // to the same base whose index the diff trusts.
    let _base_guard = base.and_then(|base| lock_base(base, false).ok());
    let base = match (&_base_guard, base) {
        (Some(_), Some(base)) => read_index(base)
            .ok()
            .map(|index| (base.to_path_buf(), index, base_identities(base))),
        _ => None,
    };
    fs::create_dir(output)?;
    let objects = directory.join("objects");
    let threads = worker_threads();
    let (mut reused_total, mut written_total) = (0u64, 0u64);
    for entry in &index.files {
        let destination = output.join(&entry.path);
        fs::create_dir_all(
            destination
                .parent()
                .ok_or_else(|| invalid("missing asset parent"))?,
        )?;
        let base_entry = base.as_ref().and_then(|(dir, index, _)| {
            index
                .files
                .iter()
                .find(|file| file.path == entry.path)
                .map(|file| (dir.join(&file.path), file))
        });
        // Unchanged since this process wrote and verified it: the clone of it
        // needs no read-back.
        let trusted = base.as_ref().zip(base_entry.as_ref()).is_some_and(
            |((_, _, identities), (source, _))| {
                identities
                    .get(&entry.path)
                    .zip(file_identity(source))
                    .is_some_and(|(recorded, current)| *recorded == current)
            },
        );
        let mut cloned = match &base_entry {
            Some((source, _)) => clone_file(source, &destination)?,
            None => false,
        };
        // A base file whose size disagrees with its index is not the base
        // the index describes; write this file in full instead.
        if cloned
            && fs::metadata(&destination)?.len()
                != base_entry.as_ref().map_or(0, |(_, base)| base.size)
        {
            fs::remove_file(&destination)?;
            cloned = false;
        }
        let file = File::options()
            .read(true)
            .write(true)
            .create_new(!cloned)
            .open(&destination)?;
        // Size the file first: ranges no worker writes stay holes (or keep
        // the base's bytes, which the diff below has checked are identical).
        file.set_len(entry.size)?;
        let data_map = cloned.then(|| chunk_data_map(&file, entry.size)).flatten();
        let data_map = data_map.as_ref();
        let base_chunks: &[Option<String>] = match (&base_entry, cloned) {
            (Some((_, base)), true) => &base.chunks,
            _ => &[],
        };
        let reused = AtomicU64::new(0);
        let written = AtomicU64::new(0);
        let jobs: Vec<(u64, usize, Option<&String>, bool)> = entry
            .chunks
            .iter()
            .enumerate()
            .filter_map(|(index, hash)| {
                let offset = index as u64 * CHUNK_SIZE as u64;
                let count = (entry.size - offset).min(CHUNK_SIZE as u64) as usize;
                let unchanged = base_chunks.get(index).is_some_and(|base| base == hash);
                if unchanged && trusted {
                    reused.fetch_add(1, Ordering::Relaxed);
                    return None;
                }
                match hash {
                    Some(hash) => Some((offset, count, Some(hash), unchanged)),
                    // A hole where the clone still has data must be punched;
                    // a fresh file is already a hole there.
                    None if cloned => Some((offset, count, None, unchanged)),
                    None => None,
                }
            })
            .collect();
        for_each_parallel(
            threads,
            jobs.into_iter(),
            |(offset, count, hash, unchanged)| {
                // The base index describes expected bytes, not proof that
                // its mutable cache file still contains them. Verify our
                // private clone so a later change to the base cannot race
                // verification against use.
                if unchanged
                    && cloned_chunk_matches(
                        &file,
                        data_map,
                        offset,
                        count,
                        hash.map(String::as_str),
                    )?
                {
                    reused.fetch_add(1, Ordering::Relaxed);
                    return Ok(());
                }
                match hash {
                    Some(hash) => {
                        let bytes = read_object(&objects.join(hash), hash, count)?;
                        write_at(&file, offset, &bytes)?;
                    }
                    None => punch_hole(&file, offset, count as u64)?,
                }
                written.fetch_add(1, Ordering::Relaxed);
                Ok(())
            },
        )?;
        let reused = reused.load(Ordering::Relaxed);
        let written = written.load(Ordering::Relaxed);
        reused_total += reused;
        written_total += written;
        tracing::debug!(
            path = %entry.path,
            cloned,
            trusted,
            reused_chunks = reused,
            written_chunks = written,
            "checkpoint file materialized"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(entry.mode))?;
        }
    }
    tracing::info!(
        base = base.is_some(),
        reused_chunks = reused_total,
        written_chunks = written_total,
        "checkpoint materialized"
    );
    Ok(index.manifest)
}

/// Keep `materialized` (a fresh, untouched output of [`materialize`] for the
/// checkpoint at `directory`) as the base the next restore diffs against. The
/// base is a filesystem clone, so it costs no space until the machine that
/// shares its blocks diverges, and it is swapped in atomically so a crash
/// leaves either the old base or the new one. Returns `Ok(false)` where the
/// filesystem cannot clone; a base is an accelerator, never a requirement.
pub fn promote_base(directory: &Path, materialized: &Path, base_root: &Path) -> io::Result<bool> {
    let parent = base_root
        .parent()
        .ok_or_else(|| invalid("restore base has no parent directory"))?;
    fs::create_dir_all(parent)?;
    let name = base_root
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| invalid("restore base name"))?;
    // Lock outside the replaceable directory, before inspecting or removing
    // staging paths. Otherwise a second promotion can delete a live staging
    // directory, or a reader can hold an obsolete generation's lock.
    let _guard = lock_base(base_root, true)?;
    // Leftovers of a promotion that died mid-way are safe to drop: the live
    // base is only ever renamed into place whole.
    for entry in fs::read_dir(parent)?.flatten() {
        let stale = entry.file_name();
        let stale = stale.to_string_lossy();
        if stale.starts_with(&format!("{name}.new-")) || stale.starts_with(&format!("{name}.old-"))
        {
            let _ = fs::remove_dir_all(entry.path());
        }
    }
    let pid = std::process::id();
    let fresh = parent.join(format!("{name}.new-{pid}"));
    let old = parent.join(format!("{name}.old-{pid}"));
    if !clone_tree(materialized, &fresh)? {
        let _ = fs::remove_dir_all(&fresh);
        return Ok(false);
    }
    fs::copy(directory.join(INDEX), fresh.join(INDEX))?;
    File::create(fresh.join(BASE_LOCK))?;
    // Stamp what we just cloned. Every byte of it came from an object this
    // process verified by hash, so the content is known good here; recording
    // the files' identity lets a later restore prove nothing has touched them
    // since, instead of re-reading gigabytes to learn the same thing.
    let identities: HashMap<String, String> = read_index(directory)
        .map(|index| {
            index
                .files
                .iter()
                .filter_map(|file| {
                    file_identity(&fresh.join(&file.path))
                        .map(|identity| (file.path.clone(), identity))
                })
                .collect()
        })
        .unwrap_or_default();
    fs::write(fresh.join(BASE_IDENTITY), serde_json::to_vec(&identities)?)?;
    // The stable exclusive lock also covers publication and old-base cleanup.
    match fs::rename(base_root, &old) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            let _ = fs::remove_dir_all(&fresh);
            return Err(error);
        }
    }
    if let Err(error) = fs::rename(&fresh, base_root) {
        // Another promotion won the race; its base is as good as ours.
        let _ = fs::remove_dir_all(&fresh);
        let _ = fs::rename(&old, base_root);
        return Err(error);
    }
    let _ = fs::remove_dir_all(&old);
    Ok(true)
}

const BASE_LOCK: &str = ".lock";

/// Which chunks of `file` hold data, from a single walk of its extents.
///
/// Verification only has to tell a hole from data, and `SEEK_DATA` answers
/// that — but it takes the file's lock, so asking once per chunk from every
/// worker turns a second of verification into half a minute of contention on
/// a sparse multi-gigabyte disk. Walking the extents once is a few hundred
/// seeks for the whole file and leaves the workers lock-free.
///
/// `None` where the filesystem cannot report extents: callers then verify by
/// reading, exactly as before.
fn chunk_data_map(file: &File, size: u64) -> Option<Vec<bool>> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let fd = file.as_raw_fd();
        let mut has_data = vec![false; size.div_ceil(CHUNK_SIZE as u64) as usize];
        let mut offset = 0i64;
        while (offset as u64) < size {
            let data = unsafe { libc::lseek(fd, offset, libc::SEEK_DATA) };
            if data < 0 {
                // No data at or after this offset: the rest is a hole.
                return match io::Error::last_os_error().raw_os_error() {
                    Some(libc::ENXIO) => Some(has_data),
                    _ => None,
                };
            }
            let end = unsafe { libc::lseek(fd, data, libc::SEEK_HOLE) };
            if end < 0 {
                return None;
            }
            let first = data as u64 / CHUNK_SIZE as u64;
            let last = (end as u64).min(size).div_ceil(CHUNK_SIZE as u64);
            for chunk in has_data.iter_mut().take(last as usize).skip(first as usize) {
                *chunk = true;
            }
            if end <= data {
                return None;
            }
            offset = end;
        }
        Some(has_data)
    }
    #[cfg(not(unix))]
    {
        let _ = (file, size);
        None
    }
}

/// Records what each base file was when this process wrote it, so a later
/// restore can tell "still exactly what we cloned into place" from "something
/// replaced, truncated or rewrote it" without reading the bytes back.
const BASE_IDENTITY: &str = ".identity";

/// Filesystem identity of one base file: device, inode, length and
/// modification time. Any in-place write moves the mtime, any replacement
/// moves the inode, and any truncation moves the length, so a match means the
/// file is byte-for-byte the one whose chunk hashes the index records.
fn file_identity(path: &Path) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::symlink_metadata(path).ok()?;
        Some(format!(
            "{}:{}:{}:{}.{}",
            meta.dev(),
            meta.ino(),
            meta.len(),
            meta.mtime(),
            meta.mtime_nsec()
        ))
    }
    #[cfg(not(unix))]
    {
        let meta = fs::symlink_metadata(path).ok()?;
        let modified = meta
            .modified()
            .ok()?
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?;
        Some(format!(
            "{}:{}.{}",
            meta.len(),
            modified.as_secs(),
            modified.subsec_nanos()
        ))
    }
}

/// Read the identities recorded for a base, as `path -> identity`.
fn base_identities(base_root: &Path) -> HashMap<String, String> {
    fs::read_to_string(base_root.join(BASE_IDENTITY))
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

fn cloned_chunk_matches(
    file: &File,
    data_map: Option<&Vec<bool>>,
    offset: u64,
    count: usize,
    hash: Option<&str>,
) -> io::Result<bool> {
    // A hole is intrinsically zero, so where the extent map says this range
    // holds none, there is nothing to read back.
    if let (None, Some(map)) = (hash, data_map) {
        let first = (offset / CHUNK_SIZE as u64) as usize;
        let last = ((offset + count as u64).div_ceil(CHUNK_SIZE as u64) as usize).min(map.len());
        if !map[first..last].iter().any(|held| *held) {
            return Ok(true);
        }
    }
    let mut bytes = vec![0; count];
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.read_exact_at(&mut bytes, offset)?;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let mut read = 0;
        while read < count {
            let n = file.seek_read(&mut bytes[read..], offset + read as u64)?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "short restore base chunk",
                ));
            }
            read += n;
        }
    }
    Ok(match hash {
        Some(hash) => digest(&bytes) == hash,
        None => smolvm_pack::is_zero_filled(&bytes),
    })
}

/// Shared while a restore diffs against the base, exclusive throughout
/// promotion. This sibling inode must never be renamed or deleted with a base.
fn lock_base(base_root: &Path, exclusive: bool) -> io::Result<File> {
    let mut name = base_root
        .file_name()
        .ok_or_else(|| invalid("restore base name"))?
        .to_os_string();
    name.push(".lock");
    let mut options = File::options();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let lock = options.open(base_root.with_file_name(name))?;
    if exclusive {
        lock.lock()?;
    } else {
        lock.lock_shared()?;
    }
    Ok(lock)
}

/// Clone a whole directory tree without copying payload bytes: one
/// `clonefile` on macOS, a reflink per file on Linux. `Ok(false)` when the
/// filesystem cannot reflink (ext4, tmpfs, Windows).
fn clone_tree(source: &Path, destination: &Path) -> io::Result<bool> {
    #[cfg(target_os = "macos")]
    {
        clone_path(source, destination)
    }
    #[cfg(target_os = "linux")]
    {
        fs::create_dir(destination)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            let target = destination.join(entry.file_name());
            let kind = entry.file_type()?;
            let ok = if kind.is_dir() {
                clone_tree(&entry.path(), &target)?
            } else if kind.is_file() {
                clone_file(&entry.path(), &target)?
            } else {
                false
            };
            if !ok {
                return Ok(false);
            }
        }
        Ok(true)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (source, destination);
        Ok(false)
    }
}

/// Clone one file as a copy-on-write reflink. `Ok(false)` when the
/// filesystem cannot, with no partial destination left behind.
fn clone_file(source: &Path, destination: &Path) -> io::Result<bool> {
    #[cfg(target_os = "macos")]
    {
        clone_path(source, destination)
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        const FICLONE: libc::c_ulong = 0x4004_9409;
        let Ok(from) = File::open(source) else {
            return Ok(false);
        };
        let to = File::options()
            .write(true)
            .create_new(true)
            .open(destination)?;
        if unsafe { libc::ioctl(to.as_raw_fd(), FICLONE as _, from.as_raw_fd()) } == 0 {
            Ok(true)
        } else {
            drop(to);
            let _ = fs::remove_file(destination);
            Ok(false)
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (source, destination);
        Ok(false)
    }
}

#[cfg(target_os = "macos")]
fn clone_path(source: &Path, destination: &Path) -> io::Result<bool> {
    use std::os::unix::ffi::OsStrExt;
    let from = std::ffi::CString::new(source.as_os_str().as_bytes())
        .map_err(|_| invalid("clone source path"))?;
    let to = std::ffi::CString::new(destination.as_os_str().as_bytes())
        .map_err(|_| invalid("clone destination path"))?;
    if unsafe { libc::clonefile(from.as_ptr(), to.as_ptr(), 0) } == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        // Not a clonable pair (different volume, non-APFS, missing source):
        // the caller materializes in full instead.
        Some(libc::ENOTSUP) | Some(libc::EXDEV) | Some(libc::ENOENT) | Some(libc::EINVAL) => {
            Ok(false)
        }
        _ => Err(error),
    }
}

/// Turn `[offset, offset + len)` of a cloned file back into a hole. Falls
/// back to writing zeros where the filesystem cannot punch.
fn punch_hole(file: &File, offset: u64, len: u64) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd;
        let range = libc::fpunchhole_t {
            fp_flags: 0,
            reserved: 0,
            fp_offset: offset as libc::off_t,
            fp_length: len as libc::off_t,
        };
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_PUNCHHOLE, &range) } == 0 {
            return Ok(());
        }
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let mode = libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE;
        if unsafe {
            libc::fallocate(
                file.as_raw_fd(),
                mode,
                offset as libc::off_t,
                len as libc::off_t,
            )
        } == 0
        {
            return Ok(());
        }
    }
    write_at(file, offset, &vec![0; len as usize])
}

/// Uncompressed length of an ingested file, including zero chunks.
pub fn logical_size(file: &StoredFile) -> u64 {
    file.size
}

/// Atomically publish without replacing an existing checkpoint, even when
/// another capture races with the initial existence check.
#[cfg(unix)]
pub fn publish(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let src = std::ffi::CString::new(source.as_os_str().as_bytes())?;
    let dst = std::ffi::CString::new(destination.as_os_str().as_bytes())?;
    #[cfg(target_os = "linux")]
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            src.as_ptr(),
            libc::AT_FDCWD,
            dst.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    #[cfg(target_os = "macos")]
    let result = unsafe { libc::renamex_np(src.as_ptr(), dst.as_ptr(), libc::RENAME_EXCL) };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let result = -1;
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
/// Publishing stored checkpoints is unsupported on non-Unix hosts.
pub fn publish(_source: &Path, _destination: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "stored checkpoints require Linux or macOS",
    ))
}

/// Make a stored directory independently transportable as a single file.
pub fn export(directory: &Path, output: &Path) -> io::Result<u64> {
    export_at(directory, None, output)
}

/// [`export`] for the checkpoint's own generation (`None`) or a retained
/// ancestor. The exported file is a single generation: it keeps its lineage
/// record (id and parent) but retains no ancestors of its own.
pub fn export_at(directory: &Path, generation: Option<&str>, output: &Path) -> io::Result<u64> {
    if output.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "checkpoint output exists",
        ));
    }
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let temporary = tempfile::Builder::new()
        .prefix(".checkpoint-export-")
        .tempdir_in(parent)?;
    let staging = temporary.path().join("staging");
    let manifest = materialize_generation(directory, generation, &staging, None)?;
    let collector =
        smolvm_pack::assets::AssetCollector::new(staging).map_err(|e| invalid(e.to_string()))?;
    let artifact = temporary.path().join("export.smolcheckpoint");
    let info = smolvm_pack::packer::Packer::new(manifest)
        .with_asset_collector(collector)
        .pack_artifact(&artifact)
        .map_err(|e| invalid(e.to_string()))?;
    File::open(&artifact)?.sync_all()?;
    publish(&artifact, output)?;
    Ok(info.total_size)
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    #[test]
    fn replacing_restore_base_keeps_the_same_lock_domain() {
        let root = tempfile::tempdir().unwrap();
        let base = root.path().join("base");
        fs::create_dir(&base).unwrap();
        File::create(base.join(BASE_LOCK)).unwrap();
        let held = lock_base(&base, false).unwrap();
        fs::rename(&base, root.path().join("old")).unwrap();
        fs::create_dir(&base).unwrap();
        File::create(base.join(BASE_LOCK)).unwrap();
        let next = lock_base(&base, false).unwrap();
        // Test contention with the first reader, not platform-specific
        // semantics for upgrading our own shared lock to an exclusive one.
        next.unlock().unwrap();
        assert!(
            next.try_lock().is_err(),
            "a replaced base bypassed an active reader's lock"
        );
        drop(held);
        next.try_lock().unwrap();
    }

    #[test]
    fn simultaneous_base_promotions_preserve_restore_contents() {
        let root = tempfile::tempdir().unwrap();
        let cache = root.path().join("cache");
        let base = root.path().join("base");
        let sources: Vec<_> = (0..4)
            .map(|index| {
                let bytes = vec![index as u8 + 1; CHUNK_SIZE + 17];
                let saved = root.path().join(format!("saved-{index}"));
                capture(&cache, &saved, &bytes);
                let output = root.path().join(format!("initial-{index}"));
                materialize(&saved, &output).unwrap();
                (saved, output, bytes)
            })
            .collect();
        let supported = promote_base(&sources[0].0, &sources[0].1, &base).unwrap();
        if std::env::var_os("SMOLVM_TEST_REQUIRE_REFLINK").is_some() {
            assert!(supported, "this QA gate requires real reflink support");
        }
        if !supported {
            return;
        }
        std::thread::scope(|scope| {
            for (index, (saved, initial, bytes)) in sources.iter().enumerate() {
                let base = &base;
                let root = root.path();
                scope.spawn(move || {
                    for repetition in 0..10 {
                        assert!(promote_base(saved, initial, base).unwrap());
                        let output = root.join(format!("output-{index}-{repetition}"));
                        materialize_with_base(saved, &output, Some(base)).unwrap();
                        assert_eq!(
                            fs::read(output.join("checkpoint/memory.bin")).unwrap(),
                            *bytes
                        );
                    }
                });
            }
        });
    }

    #[test]
    #[ignore = "128 MiB reflink restore benchmark; run on an isolated QA filesystem"]
    fn verified_base_restore_cost() {
        let root = tempfile::tempdir().unwrap();
        let mut state = 0x6a09e667f3bcc909u64;
        let bytes: Vec<u8> = (0..128 * CHUNK_SIZE)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect();
        let saved = root.path().join("saved");
        let initial = root.path().join("initial");
        let base = root.path().join("base");
        capture(&root.path().join("cache"), &saved, &bytes);
        materialize(&saved, &initial).unwrap();
        assert!(promote_base(&saved, &initial, &base).unwrap());
        for repetition in 0..3 {
            for use_base in if repetition % 2 == 0 {
                [false, true]
            } else {
                [true, false]
            } {
                let output = root.path().join(format!("restore-{repetition}-{use_base}"));
                let started = std::time::Instant::now();
                materialize_with_base(&saved, &output, use_base.then_some(base.as_path())).unwrap();
                let restored = output.join("checkpoint/memory.bin");
                File::open(&restored).unwrap().sync_all().unwrap();
                let elapsed = started.elapsed();
                assert!(fs::read(&restored).unwrap() == bytes);
                println!(
                    "{}",
                    serde_json::json!({
                        "probe": "128 MiB synthetic stored RAM asset; not VM readiness or Connor",
                        "verified_base": use_base,
                        "repetition": repetition,
                        "cache_state": "warm source, fresh destination, interleaved",
                        "restore_and_file_sync_ms": elapsed.as_secs_f64() * 1000.0,
                        "bytes_verified": bytes.len(),
                    })
                );
                fs::remove_dir_all(output).unwrap();
            }
        }
    }

    /// The extent map is what keeps verification off the per-chunk seek that
    /// serialized every worker on the file's lock: it must call a hole a hole,
    /// call data data, and — because a base whose file disagrees with its
    /// index is exactly what verification exists to catch — still refuse a
    /// range the map reports as holding data.
    #[cfg(unix)]
    #[test]
    fn the_extent_map_distinguishes_holes_from_data_without_reading() {
        use std::os::unix::fs::FileExt;
        // The hole has to be large enough for the filesystem to keep as one:
        // a gap of a chunk or two is smaller than APFS's allocation grain and
        // comes back as data, which is safe (it only costs a read-back) but
        // would make this test assert nothing.
        const CHUNKS: usize = 66;
        const LAST: usize = CHUNKS - 1;
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("sparse.img");
        let file = File::options()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let size = CHUNKS as u64 * CHUNK_SIZE as u64;
        file.set_len(size).unwrap();
        file.write_all_at(&vec![0xA5; CHUNK_SIZE], 0).unwrap();
        file.write_all_at(&vec![0x5A; CHUNK_SIZE], LAST as u64 * CHUNK_SIZE as u64)
            .unwrap();
        file.sync_all().unwrap();

        let Some(map) = chunk_data_map(&file, size) else {
            // A filesystem that cannot report extents falls back to reading,
            // which the sibling test already covers.
            return;
        };
        assert_eq!(map.len(), CHUNKS);
        assert!(map[0] && map[LAST], "written chunks hold data: {map:?}");
        let middle = CHUNKS / 2;
        if map[middle] {
            // This filesystem did not keep the gap as a hole; nothing to assert.
            return;
        }

        // A hole the map knows about needs no read-back.
        let hole_offset = middle as u64 * CHUNK_SIZE as u64;
        assert!(cloned_chunk_matches(&file, Some(&map), hole_offset, CHUNK_SIZE, None).unwrap());
        // A chunk the map reports as data is not accepted as a hole: the
        // caller punches it instead of leaving the base's bytes behind.
        assert!(!cloned_chunk_matches(&file, Some(&map), 0, CHUNK_SIZE, None).unwrap());
        // Data chunks still verify against their hash, map or not.
        let first = vec![0xA5; CHUNK_SIZE];
        assert!(
            cloned_chunk_matches(&file, Some(&map), 0, CHUNK_SIZE, Some(&digest(&first))).unwrap()
        );
        assert!(
            !cloned_chunk_matches(&file, Some(&map), 0, CHUNK_SIZE, Some(&digest(b"other")))
                .unwrap()
        );
    }

    #[test]
    fn cloned_chunk_verification_checks_data_holes_and_short_reads() {
        let file = tempfile::tempfile().unwrap();
        file.set_len((2 * CHUNK_SIZE) as u64).unwrap();
        let bytes = vec![7; CHUNK_SIZE];
        write_at(&file, 0, &bytes).unwrap();
        assert!(cloned_chunk_matches(&file, None, 0, CHUNK_SIZE, Some(&digest(&bytes))).unwrap());
        assert!(cloned_chunk_matches(&file, None, CHUNK_SIZE as u64, CHUNK_SIZE, None).unwrap());
        write_at(&file, 0, &[9]).unwrap();
        assert!(!cloned_chunk_matches(&file, None, 0, CHUNK_SIZE, Some(&digest(&bytes))).unwrap());
        write_at(&file, CHUNK_SIZE as u64, &[9]).unwrap();
        assert!(!cloned_chunk_matches(&file, None, CHUNK_SIZE as u64, CHUNK_SIZE, None).unwrap());
        file.set_len(17).unwrap();
        assert!(cloned_chunk_matches(&file, None, 0, CHUNK_SIZE, Some(&digest(&bytes))).is_err());
    }

    #[test]
    fn changed_base_bytes_are_not_reused_as_verified_checkpoint_data() {
        let root = tempfile::tempdir().unwrap();
        let saved = root.path().join("saved");
        let base = root.path().join("base");
        let output = root.path().join("output");
        let bytes = vec![7; CHUNK_SIZE];
        capture(&root.path().join("cache"), &saved, &bytes);
        materialize(&saved, &output).unwrap();
        let promoted = promote_base(&saved, &output, &base).unwrap();
        if std::env::var_os("SMOLVM_TEST_REQUIRE_REFLINK").is_some() {
            assert!(promoted, "this test gate requires real reflink support");
        }
        if !promoted {
            return;
        }
        // Keep the length and index unchanged: size is not a checksum.
        fs::write(base.join("checkpoint/memory.bin"), vec![9; CHUNK_SIZE]).unwrap();
        let restored = root.path().join("restored");
        materialize_with_base(&saved, &restored, Some(&base)).unwrap();
        let actual = fs::read(restored.join("checkpoint/memory.bin")).unwrap();
        assert!(
            actual == bytes,
            "restore reused changed base bytes without verification"
        );
    }
    use super::*;

    fn test_budget(limit: usize) -> Arc<WorkerBudget> {
        Arc::new(WorkerBudget {
            limit,
            used: AtomicUsize::new(0),
        })
    }

    #[test]
    fn checkpoint_worker_reservations_share_a_process_bound() {
        let budget = test_budget(3);
        let first = budget.acquire(2);
        let second = budget.acquire(2);
        assert_eq!((first.count, second.count), (2, 1));
        assert_eq!(budget.acquire(32).count, 0);
        drop(first);
        assert_eq!(budget.used.load(Ordering::Acquire), 1);
        drop(second);
        let start = std::sync::Barrier::new(16);
        thread::scope(|scope| {
            for _ in 0..16 {
                let budget = Arc::clone(&budget);
                let start = &start;
                scope.spawn(move || {
                    start.wait();
                    for _ in 0..1000 {
                        let permit = budget.acquire(2);
                        assert!(permit.count <= 2);
                        assert!(budget.used.load(Ordering::Acquire) <= 3);
                        thread::yield_now();
                    }
                });
            }
        });
        assert_eq!(budget.used.load(Ordering::Acquire), 0);
    }

    #[test]
    fn restore_uses_caller_when_capture_holds_worker_budget() {
        let budget = test_budget(2);
        let held = budget.acquire(2);
        let caller = thread::current().id();
        let count = AtomicUsize::new(0);
        for_each_with_budget(
            2,
            0..16,
            |_| {
                assert_eq!(thread::current().id(), caller);
                count.fetch_add(1, Ordering::Relaxed);
                Ok(())
            },
            Arc::clone(&budget),
        )
        .unwrap();
        assert_eq!(count.load(Ordering::Relaxed), 16);
        assert_eq!(budget.used.load(Ordering::Acquire), 2);
        drop(held);
        assert_eq!(budget.used.load(Ordering::Acquire), 0);
    }

    #[test]
    fn failed_parallel_work_releases_worker_budget() {
        for panic in [false, true] {
            let budget = test_budget(2);
            let result = for_each_with_budget(
                2,
                0..16,
                |_| {
                    if panic {
                        panic!("injected worker failure");
                    }
                    Err(io::Error::other("injected I/O failure"))
                },
                Arc::clone(&budget),
            );
            assert!(result.is_err());
            assert_eq!(budget.used.load(Ordering::Acquire), 0);
            for_each_with_budget(2, 0..4, |_| Ok(()), Arc::clone(&budget)).unwrap();
        }
    }

    #[test]
    fn capture_pool_falls_back_without_losing_checks_or_results() {
        let root = tempfile::tempdir().unwrap();
        let cache = root.path().join("cache");
        let objects = root.path().join("objects");
        fs::create_dir(&cache).unwrap();
        fs::create_dir(&objects).unwrap();
        let budget = test_budget(2);
        let held = budget.acquire(2);
        let pool = Pool::start_with_budget(&cache, &objects, Arc::clone(&budget)).unwrap();
        assert!(pool.workers.is_empty());
        assert_eq!(pool.window, 1);
        let bytes = vec![31; CHUNK_SIZE];
        let hash = digest(&bytes);
        let (done, results) = mpsc::channel();
        pool.submit(7, bytes.clone(), done).unwrap();
        let result = results
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        assert_eq!(result.seq, 7);
        assert_eq!(result.result.unwrap().0, Some(hash.clone()));
        verify_object_matches(&objects.join(&hash), &bytes).unwrap();
        fs::write(cache.join(&hash), b"invalid compressed object").unwrap();
        let (done, results) = mpsc::channel();
        pool.submit(8, bytes, done).unwrap();
        assert!(results
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap()
            .result
            .is_err());
        drop(pool);
        drop(held);
        assert_eq!(budget.used.load(Ordering::Acquire), 0);
    }

    #[test]
    fn partial_capture_pool_start_joins_workers_before_releasing_capacity() {
        for successful_spawns in 0..3 {
            let root = tempfile::tempdir().unwrap();
            let budget = test_budget(3);
            let finished = Arc::new(AtomicUsize::new(0));
            let mut attempts = 0;
            let result =
                Pool::start_with_spawner(root.path(), root.path(), Arc::clone(&budget), 3, |job| {
                    if attempts == successful_spawns {
                        return Err(io::Error::from(io::ErrorKind::WouldBlock));
                    }
                    attempts += 1;
                    let finished = Arc::clone(&finished);
                    thread::Builder::new().spawn(move || {
                        job();
                        finished.fetch_add(1, Ordering::Release);
                    })
                });
            assert!(result.is_err());
            assert_eq!(finished.load(Ordering::Acquire), successful_spawns);
            assert_eq!(budget.used.load(Ordering::Acquire), 0);
            assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
        }
    }

    #[test]
    #[cfg(unix)]
    fn prune_reclaims_only_owned_abandoned_captures() {
        let root = tempfile::tempdir().unwrap();
        let cache = root.path().join("cache");
        let staging = cache.join("staging");
        fs::create_dir_all(&staging).unwrap();
        let abandoned = staging.join(".checkpoint-abandoned");
        fs::create_dir(&abandoned).unwrap();
        let unrelated = staging.join(".checkpoint-user-data");
        fs::create_dir(&unrelated).unwrap();
        fs::write(unrelated.join("keep"), b"user data").unwrap();
        let mut writer = Writer::new(&cache, &abandoned).unwrap();
        writer
            .ingest("memory", 32, 0o600, &mut &[1u8; 32][..])
            .unwrap();
        assert_eq!(fs::read_dir(cache.join("objects")).unwrap().count(), 1);
        drop(writer);
        fs::write(
            cache
                .join("objects")
                .join(format!("{OBJECT_STAGING_PREFIX}interrupted")),
            b"partial compressed object",
        )
        .unwrap();
        assert!(prune(&cache).unwrap() > 0);
        assert!(!abandoned.exists());
        assert!(unrelated.join("keep").exists());
        assert_eq!(fs::read_dir(cache.join("objects")).unwrap().count(), 0);
    }

    fn manifest() -> PackManifest {
        PackManifest::new(
            "vm://test".into(),
            "none".into(),
            "linux/amd64".into(),
            "linux/amd64".into(),
        )
    }

    fn capture(cache: &Path, directory: &Path, bytes: &[u8]) -> WriteStats {
        fs::create_dir(directory).unwrap();
        let mut writer = Writer::new(cache, directory).unwrap();
        let file = writer
            .ingest(
                "checkpoint/memory.bin",
                bytes.len() as u64,
                0o600,
                &mut &*bytes,
            )
            .unwrap();
        writer.finish(directory, manifest(), vec![file]).unwrap()
    }

    fn lineage_manifest(id: &str, parent: Option<&str>, created_at: &str) -> PackManifest {
        use smolvm_pack::format::{
            CheckpointAsset, CheckpointCpuContract, CheckpointLineage, PortableCheckpointManifest,
        };
        let mut manifest = manifest();
        let asset = |path: &str| CheckpointAsset {
            path: path.into(),
            size: 0,
            sha256: String::new(),
        };
        manifest.checkpoint = Some(PortableCheckpointManifest {
            version: 1,
            runtime_abi: "test".into(),
            host_platform: "linux/amd64".into(),
            cpu_contract: CheckpointCpuContract::LinuxKvmIntelPortableV1,
            cpus: 1,
            memory_mib: 64,
            storage_gib: None,
            overlay_gib: None,
            device_profile: "test".into(),
            state: asset("checkpoint/checkpoint.bin"),
            memory: asset("checkpoint/memory.bin"),
            layout: asset("checkpoint/layout.json"),
            disks: Vec::new(),
            workload: None,
            network: None,
            packed_layers: None,
            lineage: Some(CheckpointLineage {
                id: id.into(),
                parent: parent.map(str::to_string),
                machine: "m".into(),
                created_at: created_at.into(),
            }),
            payload: Default::default(),
            history: Vec::new(),
            credential_ca: None,
        });
        manifest
    }

    /// Capture `bytes` as generation `id`, retaining `parent`'s generations.
    fn capture_generation(
        cache: &Path,
        directory: &Path,
        bytes: &[u8],
        id: &str,
        parent: Option<&Path>,
        created_at: &str,
    ) -> usize {
        fs::create_dir(directory).unwrap();
        let mut writer = Writer::new(cache, directory).unwrap();
        let file = writer
            .ingest(
                "checkpoint/memory.bin",
                bytes.len() as u64,
                0o600,
                &mut &*bytes,
            )
            .unwrap();
        let retained = match parent {
            Some(parent) => writer.retain_generations(directory, parent, 32).unwrap(),
            None => 0,
        };
        let parent_id = parent.and_then(|p| lineage_of(p).unwrap().first().map(|g| g.id.clone()));
        writer
            .finish(
                directory,
                lineage_manifest(id, parent_id.as_deref(), created_at),
                vec![file],
            )
            .unwrap();
        retained
    }

    const G1: &str = "11111111111111111111111111111111";
    const G2: &str = "22222222222222222222222222222222";
    const G3: &str = "33333333333333333333333333333333";

    #[test]
    #[cfg(unix)]
    fn a_checkpoint_retains_its_ancestors_and_restores_any_of_them() {
        let root = tempfile::tempdir().unwrap();
        let cache = root.path().join("cache");
        let first = root.path().join("first");
        let second = root.path().join("second");
        let third = root.path().join("third");
        let a = vec![0x11u8; CHUNK_SIZE + 10];
        let mut b = a.clone();
        b[CHUNK_SIZE + 3] = 0x22; // only the second chunk changes
        let c = vec![0x33u8; CHUNK_SIZE / 2];

        assert_eq!(
            capture_generation(&cache, &first, &a, G1, None, "2026-01-01T00:00:00Z"),
            0
        );
        assert_eq!(
            capture_generation(
                &cache,
                &second,
                &b,
                G2,
                Some(&first),
                "2026-01-02T00:00:00Z"
            ),
            1
        );
        assert_eq!(
            capture_generation(
                &cache,
                &third,
                &c,
                G3,
                Some(&second),
                "2026-01-03T00:00:00Z"
            ),
            2
        );

        let chain: Vec<(String, Option<String>, bool)> = lineage_of(&third)
            .unwrap()
            .into_iter()
            .map(|g| (g.id, g.parent, g.retained))
            .collect();
        assert_eq!(
            chain,
            vec![
                (G3.into(), Some(G2.into()), false),
                (G2.into(), Some(G1.into()), true),
                (G1.into(), None, true),
            ]
        );
        // The newest checkpoint alone can restore every generation, even after
        // the older directories are gone.
        fs::remove_dir_all(&first).unwrap();
        fs::remove_dir_all(&second).unwrap();
        assert_eq!(resolve_generation(&third, "~0").unwrap(), None);
        assert_eq!(resolve_generation(&third, "~1").unwrap(), Some(G2.into()));
        assert_eq!(
            resolve_generation(&third, "11111111").unwrap(),
            Some(G1.into())
        );
        assert!(resolve_generation(&third, "~3").is_err());
        assert!(resolve_generation(&third, "zz").is_err());
        for (generation, expected) in [(Some(G1), &a), (Some(G2), &b)] {
            let out = root.path().join(format!("restore-{}", generation.unwrap()));
            materialize_generation(&third, generation, &out, None).unwrap();
            assert_eq!(
                fs::read(out.join("checkpoint/memory.bin")).unwrap(),
                *expected
            );
        }
        let own = root.path().join("restore-own");
        materialize(&third, &own).unwrap();
        assert_eq!(fs::read(own.join("checkpoint/memory.bin")).unwrap(), c);
        assert_eq!(
            read_manifest_at(&third, Some(G1))
                .unwrap()
                .checkpoint
                .unwrap()
                .lineage
                .unwrap()
                .id,
            G1
        );
    }

    #[test]
    #[cfg(unix)]
    fn retained_generations_survive_prune_and_a_depth_limit_holds() {
        let root = tempfile::tempdir().unwrap();
        let cache = root.path().join("cache");
        let first = root.path().join("first");
        let second = root.path().join("second");
        let third = root.path().join("third");
        capture_generation(&cache, &first, &[1u8; 64], G1, None, "2026-01-01T00:00:00Z");
        capture_generation(
            &cache,
            &second,
            &[2u8; 64],
            G2,
            Some(&first),
            "2026-01-02T00:00:00Z",
        );
        fs::create_dir(&third).unwrap();
        let mut writer = Writer::new(&cache, &third).unwrap();
        let file = writer
            .ingest("checkpoint/memory.bin", 64, 0o600, &mut &[3u8; 64][..])
            .unwrap();
        assert_eq!(writer.retain_generations(&third, &second, 1).unwrap(), 1);
        writer
            .finish(
                &third,
                lineage_manifest(G3, Some(G2), "2026-01-03T00:00:00Z"),
                vec![file],
            )
            .unwrap();
        drop(writer);
        fs::remove_dir_all(&first).unwrap();
        fs::remove_dir_all(&second).unwrap();
        prune(&cache).unwrap();
        let ids: Vec<String> = lineage_of(&third)
            .unwrap()
            .into_iter()
            .map(|g| g.id)
            .collect();
        assert_eq!(ids, vec![G3.to_string(), G2.to_string()]);
        let out = root.path().join("g2");
        materialize_at(&third, G2, &out).unwrap();
        assert_eq!(
            fs::read(out.join("checkpoint/memory.bin")).unwrap(),
            vec![2u8; 64]
        );
    }

    #[test]
    #[cfg(unix)]
    fn a_deleted_parent_is_retained_from_whichever_checkpoint_still_holds_it() {
        let root = tempfile::tempdir().unwrap();
        let cache = root.path().join("cache");
        let (first, second, third) = (
            root.path().join("first"),
            root.path().join("second"),
            root.path().join("third"),
        );
        capture_generation(&cache, &first, &[1u8; 64], G1, None, "2026-01-01T00:00:00Z");
        capture_generation(
            &cache,
            &second,
            &[2u8; 64],
            G2,
            Some(&first),
            "2026-01-02T00:00:00Z",
        );
        for (id, path, parent) in [(G1, &first, None), (G2, &second, Some(G1))] {
            record_lineage(
                &cache,
                &LineageRecord {
                    id: id.into(),
                    parent: parent.map(str::to_string),
                    machine: "m".into(),
                    created_at: "2026-01-01T00:00:00Z".into(),
                    path: path.to_string_lossy().into_owned(),
                },
            )
            .unwrap();
        }
        // A machine restored at G1 captures again after G1's directory is gone:
        // G2 still holds G1, so the new checkpoint continues from it.
        fs::remove_dir_all(&first).unwrap();
        let (source, own) = find_generation_source(&cache, G1).unwrap().unwrap();
        assert_eq!((source.as_path(), own), (second.as_path(), false));
        fs::create_dir(&third).unwrap();
        let mut writer = Writer::new(&cache, &third).unwrap();
        let file = writer
            .ingest("checkpoint/memory.bin", 64, 0o600, &mut &[3u8; 64][..])
            .unwrap();
        assert_eq!(
            writer
                .retain_generations_from(&third, &source, Some(G1), 32)
                .unwrap(),
            1
        );
        assert!(writer
            .retain_generations_from(&third, &source, Some(G3), 32)
            .is_err());
        writer
            .finish(
                &third,
                lineage_manifest(G3, Some(G1), "2026-01-03T00:00:00Z"),
                vec![file],
            )
            .unwrap();
        let ids: Vec<String> = lineage_of(&third)
            .unwrap()
            .into_iter()
            .map(|g| g.id)
            .collect();
        assert_eq!(ids, vec![G3.to_string(), G1.to_string()]);
        let out = root.path().join("g1");
        materialize_at(&third, G1, &out).unwrap();
        assert_eq!(
            fs::read(out.join("checkpoint/memory.bin")).unwrap(),
            vec![1u8; 64]
        );
        assert_eq!(find_generation_source(&cache, G3).unwrap(), None);
    }

    #[test]
    #[cfg(unix)]
    fn a_history_file_carries_every_generation_it_was_exported_with() {
        let root = tempfile::tempdir().unwrap();
        let cache = root.path().join("cache");
        let (first, second) = (root.path().join("first"), root.path().join("second"));
        let a = vec![0xAAu8; CHUNK_SIZE + 5];
        let mut b = a.clone();
        b[0] = 0xBB;
        capture_generation(&cache, &first, &a, G1, None, "2026-01-01T00:00:00Z");
        capture_generation(
            &cache,
            &second,
            &b,
            G2,
            Some(&first),
            "2026-01-02T00:00:00Z",
        );
        let file = root.path().join("history.smolcheckpoint");
        let (bytes, carried) = export_with_history(&second, 32, &file, |manifest| {
            manifest.checkpoint.as_mut().unwrap().version = 99;
        })
        .unwrap();
        assert!(bytes > 0);
        assert_eq!(carried, 1);
        // The outer manifest is readable without unpacking and lists the history.
        let outer = smolvm_pack::packer::read_manifest_from_sidecar(&file).unwrap();
        let checkpoint = outer.checkpoint.unwrap();
        assert_eq!(
            checkpoint.payload,
            smolvm_pack::format::CheckpointLayout::Chunked
        );
        assert_eq!(checkpoint.version, 99);
        let ids: Vec<&str> = checkpoint
            .history
            .iter()
            .map(|g| g.lineage.id.as_str())
            .collect();
        assert_eq!(ids, vec![G2, G1]);
        assert_eq!(
            resolve_in(&generations_from_history(&checkpoint.history), "~1").unwrap(),
            Some(G1.to_string())
        );
        // Unpacked, it is a directory checkpoint again — every generation restores.
        let unpacked = root.path().join("unpacked");
        smolvm_pack::assets::decompress_assets_from_file(&file, &unpacked).unwrap();
        let ids: Vec<String> = lineage_of(&unpacked)
            .unwrap()
            .into_iter()
            .map(|g| g.id)
            .collect();
        assert_eq!(ids, vec![G2.to_string(), G1.to_string()]);
        let out = root.path().join("g1");
        materialize_at(&unpacked, G1, &out).unwrap();
        assert_eq!(fs::read(out.join("checkpoint/memory.bin")).unwrap(), a);
        let own = root.path().join("own");
        materialize(&unpacked, &own).unwrap();
        assert_eq!(fs::read(own.join("checkpoint/memory.bin")).unwrap(), b);
        // With nothing retained the export is the classic single-generation file.
        let single = root.path().join("single.smolcheckpoint");
        assert_eq!(
            export_with_history(&first, 32, &single, |_| {}).unwrap().1,
            0
        );
        let outer = smolvm_pack::packer::read_manifest_from_sidecar(&single).unwrap();
        assert_eq!(
            outer.checkpoint.unwrap().payload,
            smolvm_pack::format::CheckpointLayout::Assets
        );
    }

    #[test]
    fn the_store_lineage_index_round_trips() {
        let root = tempfile::tempdir().unwrap();
        let record = LineageRecord {
            id: G1.into(),
            parent: None,
            machine: "m".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            path: "/tmp/first.smolcheckpoint".into(),
        };
        record_lineage(root.path(), &record).unwrap();
        let child = LineageRecord {
            id: G2.into(),
            parent: Some(G1.into()),
            created_at: "2026-01-02T00:00:00Z".into(),
            ..record.clone()
        };
        record_lineage(root.path(), &child).unwrap();
        assert_eq!(find_lineage(root.path(), G1).unwrap(), Some(record.clone()));
        assert_eq!(find_lineage(root.path(), "nope").unwrap(), None);
        let ids: Vec<String> = list_lineage(root.path())
            .unwrap()
            .into_iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(ids, vec![G1.to_string(), G2.to_string()]);
        assert!(record_lineage(
            root.path(),
            &LineageRecord {
                id: "bad".into(),
                ..record
            }
        )
        .is_err());
    }

    /// A restore against a base only rewrites the chunks that differ; the
    /// result must still be exact in both directions (chunks changed, a chunk
    /// that became a hole, a hole that became data, a file that grew and one
    /// that shrank). Where the filesystem cannot clone, this degrades to a
    /// full materialization and must still be exact.
    #[test]
    fn restoring_against_a_base_is_exact_in_both_directions() {
        let root = tempfile::tempdir().unwrap();
        let cache = root.path().join("cache");
        let base = root.path().join("base");
        let mut a = Vec::new();
        for index in 0..16u8 {
            a.extend(std::iter::repeat_n(index + 1, CHUNK_SIZE));
        }
        let mut b = a.clone();
        b[3 * CHUNK_SIZE..4 * CHUNK_SIZE].fill(0xAB);
        b[7 * CHUNK_SIZE..8 * CHUNK_SIZE].fill(0);
        a[12 * CHUNK_SIZE..13 * CHUNK_SIZE].fill(0);
        b.extend(std::iter::repeat_n(0xCD, CHUNK_SIZE / 2));
        let saved_a = root.path().join("saved-a");
        let saved_b = root.path().join("saved-b");
        capture(&cache, &saved_a, &a);
        capture(&cache, &saved_b, &b);

        let out_a = root.path().join("out-a");
        materialize(&saved_a, &out_a).unwrap();
        let promoted = promote_base(&saved_a, &out_a, &base).unwrap();
        let out_b = root.path().join("out-b");
        materialize_with_base(&saved_b, &out_b, Some(&base)).unwrap();
        assert_eq!(fs::read(out_b.join("checkpoint/memory.bin")).unwrap(), b);

        if promoted {
            assert!(promote_base(&saved_b, &out_b, &base).unwrap());
            assert!(base.join(INDEX).is_file());
            assert!(!base.with_extension("new").exists());
            assert!(!base.with_extension("old").exists());
        }
        let out_a2 = root.path().join("out-a2");
        materialize_with_base(&saved_a, &out_a2, Some(&base)).unwrap();
        assert_eq!(fs::read(out_a2.join("checkpoint/memory.bin")).unwrap(), a);

        // A base that is not a checkpoint at all is ignored, not an error.
        let out_a3 = root.path().join("out-a3");
        materialize_with_base(&saved_a, &out_a3, Some(&root.path().join("nope"))).unwrap();
        assert_eq!(fs::read(out_a3.join("checkpoint/memory.bin")).unwrap(), a);
    }

    /// A base file whose size disagrees with the base index is not trusted:
    /// that file is written in full and the restore is still exact.
    #[test]
    fn a_base_file_of_the_wrong_size_is_written_in_full() {
        let root = tempfile::tempdir().unwrap();
        let cache = root.path().join("cache");
        let base = root.path().join("base");
        let bytes: Vec<u8> = (0..8 * CHUNK_SIZE).map(|i| (i / 977) as u8).collect();
        let saved = root.path().join("saved");
        capture(&cache, &saved, &bytes);
        let out = root.path().join("out");
        materialize(&saved, &out).unwrap();
        if !promote_base(&saved, &out, &base).unwrap() {
            return;
        }
        assert!(base.join(BASE_LOCK).is_file());
        let victim = base.join("checkpoint/memory.bin");
        File::options()
            .write(true)
            .open(&victim)
            .unwrap()
            .set_len(3 * CHUNK_SIZE as u64)
            .unwrap();
        let again = root.path().join("again");
        materialize_with_base(&saved, &again, Some(&base)).unwrap();
        assert_eq!(
            fs::read(again.join("checkpoint/memory.bin")).unwrap(),
            bytes
        );
    }

    /// A base this process wrote and stamped is trusted on the next restore,
    /// which is what keeps a jump from re-reading gigabytes to confirm bytes
    /// it just wrote. Touch the base's file and the stamp no longer matches,
    /// so verification comes back and the corruption is still caught.
    #[test]
    fn a_stamped_base_is_trusted_until_its_file_changes() {
        let root = tempfile::tempdir().unwrap();
        let cache = root.path().join("cache");
        let saved = root.path().join("saved");
        let base = root.path().join("base");
        let bytes: Vec<u8> = (0..4 * CHUNK_SIZE).map(|index| (index / 7) as u8).collect();
        capture(&cache, &saved, &bytes);
        let first = root.path().join("first");
        materialize(&saved, &first).unwrap();
        if !promote_base(&saved, &first, &base).unwrap() {
            return;
        }
        let stamped = base_identities(&base);
        assert!(
            stamped.contains_key("checkpoint/memory.bin"),
            "promotion records what it wrote: {stamped:?}"
        );

        // Trusted: restoring again reproduces the bytes.
        let again = root.path().join("again");
        materialize_with_base(&saved, &again, Some(&base)).unwrap();
        assert_eq!(
            fs::read(again.join("checkpoint/memory.bin")).unwrap(),
            bytes
        );

        // Corrupt the base's file. Its identity no longer matches the stamp,
        // so the restore verifies and rewrites from the store rather than
        // handing the caller the damaged bytes.
        let victim = base.join("checkpoint/memory.bin");
        fs::write(&victim, vec![0xEE; bytes.len()]).unwrap();
        assert_ne!(
            stamped.get("checkpoint/memory.bin").cloned(),
            file_identity(&victim),
            "a rewritten file must not keep its recorded identity"
        );
        let third = root.path().join("third");
        materialize_with_base(&saved, &third, Some(&base)).unwrap();
        assert_eq!(
            fs::read(third.join("checkpoint/memory.bin")).unwrap(),
            bytes
        );
    }

    /// Restore decodes chunks concurrently; a corrupted object in the middle
    /// of a many-chunk file must still fail the whole restore.
    #[test]
    fn a_corrupted_chunk_among_many_fails_restore() {
        let root = tempfile::tempdir().unwrap();
        let cache = root.path().join("cache");
        let saved = root.path().join("saved");
        let mut bytes = Vec::new();
        for index in 0..24u8 {
            bytes.extend(std::iter::repeat_n(index + 1, CHUNK_SIZE));
        }
        capture(&cache, &saved, &bytes);
        let victim = &bytes[13 * CHUNK_SIZE..14 * CHUNK_SIZE];
        fs::write(
            cache.join("objects").join(digest(victim)),
            zstd::bulk::compress(&vec![0xEE; CHUNK_SIZE], 3).unwrap(),
        )
        .unwrap();
        assert!(materialize(&saved, &root.path().join("restore")).is_err());
        fs::write(
            cache.join("objects").join(digest(victim)),
            zstd::bulk::compress(victim, 3).unwrap(),
        )
        .unwrap();
        let restored = root.path().join("restore-again");
        materialize(&saved, &restored).unwrap();
        assert_eq!(
            fs::read(restored.join("checkpoint/memory.bin")).unwrap(),
            bytes
        );
    }

    /// Chunks are stored by a pool of workers that finish in any order; the
    /// file must still come back byte-for-byte, holes and duplicates included.
    #[test]
    fn concurrently_stored_chunks_keep_file_order() {
        let root = tempfile::tempdir().unwrap();
        let cache = root.path().join("cache");
        let saved = root.path().join("saved");
        let mut bytes = Vec::new();
        for index in 0..24u8 {
            let fill = index.wrapping_mul(37).wrapping_add(1);
            bytes.extend(std::iter::repeat_n(fill, CHUNK_SIZE));
            if index % 5 == 0 {
                bytes.extend(std::iter::repeat_n(0, CHUNK_SIZE));
            }
            if index % 7 == 0 {
                bytes.extend(std::iter::repeat_n(fill, CHUNK_SIZE));
            }
        }
        bytes.extend(std::iter::repeat_n(9, CHUNK_SIZE / 3));
        let stats = capture(&cache, &saved, &bytes);
        assert_eq!(stats.zero_bytes, 5 * CHUNK_SIZE as u64);
        assert_eq!(stats.reused_bytes, 4 * CHUNK_SIZE as u64);
        let restored = root.path().join("restore");
        materialize(&saved, &restored).unwrap();
        assert_eq!(
            fs::read(restored.join("checkpoint/memory.bin")).unwrap(),
            bytes
        );
    }

    /// Reuse is decided from the object's presence, not by reading it back —
    /// re-verifying content was most of an incremental save's cost — so the
    /// one thing the presence check must still refuse is an object that cannot
    /// be a published one: a zero-length file under a content hash.
    #[test]
    fn a_truncated_cached_object_is_refused_rather_than_reused() {
        let root = tempfile::tempdir().unwrap();
        let cache = root.path().join("cache");
        let bytes = vec![0x5A; CHUNK_SIZE];
        let stats = capture(&cache, &root.path().join("first"), &bytes);
        assert_eq!(stats.new_logical_bytes, CHUNK_SIZE as u64);

        let hash = digest(&bytes);
        let object = cache.join("objects").join(&hash);
        assert!(object.is_file(), "object was not published under its hash");
        fs::write(&object, b"").unwrap();

        let again = root.path().join("second");
        fs::create_dir(&again).unwrap();
        let mut writer = Writer::new(&cache, &again).unwrap();
        let error = writer
            .ingest(
                "checkpoint/memory.bin",
                bytes.len() as u64,
                0o600,
                &mut &*bytes,
            )
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    /// The positive half: an intact object is reused without being rewritten.
    #[test]
    fn an_intact_cached_object_is_reused_without_rewriting() {
        let root = tempfile::tempdir().unwrap();
        let cache = root.path().join("cache");
        let bytes = vec![0x5A; CHUNK_SIZE];
        capture(&cache, &root.path().join("first"), &bytes);
        let stats = capture(&cache, &root.path().join("second"), &bytes);
        assert_eq!(stats.reused_bytes, CHUNK_SIZE as u64);
        assert_eq!(stats.new_bytes, 0);
    }

    #[test]
    fn unchanged_chunks_are_reused_and_old_checkpoints_remain_independent() {
        let root = tempfile::tempdir().unwrap();
        let cache = root.path().join("cache");
        let first = root.path().join("first");
        let second = root.path().join("second");
        let mut bytes = vec![0x11; 4 * CHUNK_SIZE + 17];
        bytes[CHUNK_SIZE..2 * CHUNK_SIZE].fill(0x22);
        bytes[2 * CHUNK_SIZE..3 * CHUNK_SIZE].fill(0x33);
        bytes[3 * CHUNK_SIZE..4 * CHUNK_SIZE].fill(0x44);
        let original = bytes.clone();
        let initial = capture(&cache, &first, &bytes);
        assert_eq!(initial.new_logical_bytes, bytes.len() as u64);
        assert!(initial.new_bytes < initial.new_logical_bytes);
        bytes[CHUNK_SIZE..2 * CHUNK_SIZE].fill(0);
        bytes[2 * CHUNK_SIZE + 7] = 0xFE;
        let delta = capture(&cache, &second, &bytes);
        assert_eq!(delta.new_logical_bytes, CHUNK_SIZE as u64);
        assert_eq!(delta.zero_bytes, CHUNK_SIZE as u64);
        assert_eq!(delta.reused_bytes, (2 * CHUNK_SIZE + 17) as u64);
        materialize(&first, &root.path().join("restore-first")).unwrap();
        assert_eq!(
            fs::read(root.path().join("restore-first/checkpoint/memory.bin")).unwrap(),
            original
        );
        fs::remove_dir_all(&first).unwrap();
        fs::remove_dir_all(&cache).unwrap();
        materialize(&second, &root.path().join("restore-second")).unwrap();
        assert_eq!(
            fs::read(root.path().join("restore-second/checkpoint/memory.bin")).unwrap(),
            bytes
        );
    }

    #[test]
    fn truncated_capture_never_publishes_an_index_and_retry_works() {
        let root = tempfile::tempdir().unwrap();
        let cache = root.path().join("cache");
        let incomplete = root.path().join("incomplete");
        fs::create_dir(&incomplete).unwrap();
        let mut writer = Writer::new(&cache, &incomplete).unwrap();
        let error = writer
            .ingest(
                "memory",
                (2 * CHUNK_SIZE) as u64,
                0o600,
                &mut &[1; CHUNK_SIZE][..],
            )
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        assert!(!incomplete.join(INDEX).exists());
        let retry = capture(&cache, &root.path().join("retry"), &vec![1; CHUNK_SIZE]);
        assert_eq!(retry.new_bytes, 0);
        assert_eq!(retry.reused_bytes, CHUNK_SIZE as u64);
    }

    #[test]
    fn reused_objects_require_exact_decoded_bytes() {
        let root = tempfile::tempdir().unwrap();
        let expected = vec![7; CHUNK_SIZE];
        let object = root.path().join(digest(&expected));
        for len in [CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1] {
            let mut contents = vec![7; len];
            if len == CHUNK_SIZE {
                contents[len - 1] = 8;
            }
            fs::write(&object, zstd::bulk::compress(&contents, 3).unwrap()).unwrap();
            assert!(verify_object_matches(&object, &expected).is_err());
            assert!(read_object(&object, &digest(&expected), expected.len()).is_err());
        }
        fs::write(&object, zstd::bulk::compress(&expected, 3).unwrap()).unwrap();
        verify_object_matches(&object, &expected).unwrap();
        assert_eq!(
            read_object(&object, &digest(&expected), expected.len()).unwrap(),
            expected
        );
    }

    #[test]
    fn corruption_is_rejected_on_reuse_and_restore() {
        for corrupt in [
            vec![8; CHUNK_SIZE],
            zstd::bulk::compress(&vec![8; CHUNK_SIZE], 3).unwrap(),
        ] {
            let root = tempfile::tempdir().unwrap();
            let cache = root.path().join("cache");
            let saved = root.path().join("saved");
            let bytes = vec![7; CHUNK_SIZE];
            capture(&cache, &saved, &bytes);
            fs::write(cache.join("objects").join(digest(&bytes)), corrupt).unwrap();
            assert!(materialize(&saved, &root.path().join("restore")).is_err());
            let next = root.path().join("next");
            fs::create_dir(&next).unwrap();
            let mut writer = Writer::new(&cache, &next).unwrap();
            assert!(writer
                .ingest("memory", bytes.len() as u64, 0o600, &mut bytes.as_slice())
                .is_err());
            assert!(!next.join(INDEX).exists());
        }
    }

    #[test]
    fn concurrent_writers_share_objects_without_losing_checkpoints() {
        let root = tempfile::tempdir().unwrap();
        let cache = root.path().join("cache");
        let bytes: Vec<u8> = (0..4)
            .flat_map(|index| std::iter::repeat_n(index + 1, CHUNK_SIZE))
            .chain([5; 5])
            .collect();
        std::thread::scope(|scope| {
            for n in 0..8 {
                let cache = &cache;
                let bytes = &bytes;
                let directory = root.path().join(n.to_string());
                scope.spawn(move || {
                    capture(cache, &directory, bytes);
                });
            }
        });
        std::thread::scope(|scope| {
            for n in 0..8 {
                let bytes = &bytes;
                let directory = root.path().join(n.to_string());
                scope.spawn(move || {
                    let restored = directory.join("restore");
                    materialize(&directory, &restored).unwrap();
                    assert_eq!(
                        fs::read(restored.join("checkpoint/memory.bin")).unwrap(),
                        *bytes
                    );
                });
            }
        });
        assert_eq!(fs::read_dir(cache.join("objects")).unwrap().count(), 5);
    }

    #[test]
    fn malformed_indices_and_streams_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let saved = root.path().join("saved");
        capture(&root.path().join("cache"), &saved, b"test");
        let mut index = read_index(&saved).unwrap();
        index.files[0].path = "../outside".into();
        assert!(validate_index(&index).is_err());
        index.files[0].path = "memory".into();
        index.files[0].chunks[0] = Some("../outside".into());
        assert!(validate_index(&index).is_err());
        index.files[0].chunks.clear();
        assert!(validate_index(&index).is_err());
        let dest = root.path().join("stream");
        fs::create_dir(&dest).unwrap();
        let mut writer = Writer::new(&root.path().join("cache"), &dest).unwrap();
        let mut wire = b"SMOLRAM1".to_vec();
        wire.extend_from_slice(&u64::MAX.to_le_bytes());
        assert!(writer.ingest_memory(&mut wire.as_slice(), 1024).is_err());
        assert!(writer
            .ingest_memory(&mut &b"ERR ENOTSUP\n"[..], 1024)
            .is_err());
    }

    #[test]
    fn sparse_assets_preserve_unaligned_extents_and_trailing_holes() {
        let root = tempfile::tempdir().unwrap();
        let source_path = root.path().join("sparse.bin");
        let mut source = File::options()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&source_path)
            .unwrap();
        source.set_len((16 * CHUNK_SIZE + 23) as u64).unwrap();
        source
            .seek(SeekFrom::Start((2 * CHUNK_SIZE + 9) as u64))
            .unwrap();
        source.write_all(b"nonzero extent").unwrap();
        let saved = root.path().join("saved");
        fs::create_dir(&saved).unwrap();
        let mut writer = Writer::new(&root.path().join("cache"), &saved).unwrap();
        let entry = writer.ingest_file("disk.bin", 0o600, &mut source).unwrap();
        let stats = writer.finish(&saved, manifest(), vec![entry]).unwrap();
        assert_eq!(stats.new_logical_bytes, CHUNK_SIZE as u64);
        materialize(&saved, &root.path().join("restore")).unwrap();
        assert_eq!(
            fs::read(source_path).unwrap(),
            fs::read(root.path().join("restore/disk.bin")).unwrap()
        );
    }

    #[test]
    fn publish_does_not_replace_existing_directory() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        let destination = root.path().join("destination");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&destination).unwrap();
        assert!(publish(&source, &destination).is_err());
        assert!(source.is_dir());
    }

    #[test]
    fn pruning_preserves_live_checkpoints_and_reclaims_deleted_ones() {
        let root = tempfile::tempdir().unwrap();
        let saved = root.path().join("saved");
        let cache = root.path().join("cache");
        capture(&cache, &saved, &vec![4; CHUNK_SIZE]);
        assert_eq!(prune(&cache).unwrap(), 0);
        materialize(&saved, &root.path().join("restore")).unwrap();
        fs::remove_dir_all(saved).unwrap();
        assert!(prune(&cache).unwrap() > 0);
        assert_eq!(prune(&cache).unwrap(), 0);
    }

    #[test]
    fn standalone_export_contains_exact_bytes_without_store() {
        let root = tempfile::tempdir().unwrap();
        let saved = root.path().join("saved");
        let cache = root.path().join("cache");
        let bytes = vec![0xA5; CHUNK_SIZE + 23];
        capture(&cache, &saved, &bytes);
        let artifact = root.path().join("export.smolcheckpoint");
        export(&saved, &artifact).unwrap();
        fs::remove_dir_all(&cache).unwrap();
        fs::remove_dir_all(&saved).unwrap();
        let footer = smolvm_pack::packer::read_footer_from_sidecar(&artifact).unwrap();
        let restored = root.path().join("restore");
        smolvm_pack::extract::extract_sidecar(&artifact, &restored, &footer, false, false).unwrap();
        assert_eq!(
            fs::read(restored.join("checkpoint/memory.bin")).unwrap(),
            bytes
        );
    }
}
