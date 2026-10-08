//! A POSIX filesystem over an S3 bucket.
//!
//! # Why this layer exists
//!
//! Object storage and POSIX disagree on nearly everything: objects are
//! immutable blobs addressed by a flat key space, while files are mutable byte
//! ranges inside a tree of directories. Bridging that is the actual work:
//!
//! * **Directories are synthetic.** S3 has no directories, only keys that share
//!   a prefix. Listing with `delimiter=/` turns one level of that key space into
//!   entries, and any prefix that appears becomes a directory — including ones
//!   no explicit object ever created.
//! * **Writes cannot be partial.** There is no "write 4 KiB at offset 12 KiB"
//!   in S3, only "replace the whole object". So an opened-for-write file is
//!   staged in a local scratch file, mutated freely as a normal file, and
//!   uploaded once on flush/close. This is the same shape rclone, s3fs and
//!   Mountpoint all converge on, because the API leaves no alternative.
//! * **Deletes must not resurrect data.** A staged file whose upload has not
//!   happened yet still has to be visible to readers, so lookups consult the
//!   staging table before the bucket.
//! * **Every question is a round trip.** Each lookup would be a HEAD (and a
//!   LIST when the name is not an object), and each read a GET, one network
//!   round trip apiece, while programs ask the same questions over and over.
//!   So answers are kept for [`S3Fs::cache_ttl`]: a listing records every
//!   child's size and time as it goes, a miss is remembered as a miss, and a
//!   small file is fetched once and read from memory. Changes made through
//!   this mount update the caches as they happen; a change made by another
//!   writer becomes visible within the TTL.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::fuse::{self, Attr, Filesystem, Reply, Request, DT_DIR, DT_REG, FUSE_ROOT_ID};
use crate::s3;

const DIR_MODE: u32 = 0o040755;
const FILE_MODE: u32 = 0o100644;

/// `fuse_setattr_in.valid` bits this filesystem acts on. Ownership, mode and
/// timestamps are accepted and ignored — an object store has no place to put
/// them — but a size change is real and must be applied.
const FATTR_SIZE: u32 = 1 << 3;
const FATTR_FH: u32 = 1 << 6;

/// Objects up to this size are read whole on first access and served from
/// memory after: a few KiB file otherwise costs a round trip per read.
const SMALL_FILE_MAX: u64 = 1024 * 1024;
/// Memory the small-file cache may hold; least recently used goes first.
const SMALL_CACHE_BYTES: u64 = 256 * 1024 * 1024;

/// What a path resolved to, kept for the cache TTL.
#[derive(Clone, Debug, PartialEq)]
enum Known {
    Present(Node),
    Absent,
}

/// A small object's bytes, valid while the object keeps this size and time.
struct SmallFile {
    size: u64,
    mtime: u64,
    bytes: std::sync::Arc<Vec<u8>>,
    /// When the bytes came from the bucket. They expire with the TTL because
    /// S3 times have one-second resolution: a same-size rewrite within that
    /// second would otherwise look unchanged forever.
    fetched: Instant,
    used: Instant,
}

/// A file opened for writing, staged on local disk until flush.
struct Staged {
    file: std::fs::File,
    path: std::path::PathBuf,
    /// Object key this handle stages, so a truncate that arrives without a
    /// file handle can still find the staging files it has to resize.
    key: String,
    size: u64,
    dirty: bool,
}

#[derive(Clone, Debug, PartialEq)]
enum Node {
    Dir,
    File { size: u64, mtime: u64 },
}

pub struct S3Fs {
    client: s3::Client,
    read_only: bool,
    scratch: std::path::PathBuf,
    next_ino: AtomicU64,
    next_fh: AtomicU64,
    /// inode -> path relative to the mount root ("" is the root).
    inodes: Mutex<HashMap<u64, String>>,
    /// path -> inode, so repeated lookups are stable (the kernel caches by ino).
    paths: Mutex<HashMap<String, u64>>,
    /// Open write handles, keyed by file handle.
    staged: Mutex<HashMap<u64, Staged>>,
    /// Paths with an unflushed staging file, so reads see pending writes.
    pending: Mutex<HashMap<String, u64>>,
    /// How long a lookup, a miss or a small file's bytes are trusted.
    cache_ttl: Duration,
    /// path -> what it resolved to, and when.
    meta: Mutex<HashMap<String, (Known, Instant)>>,
    /// path -> the whole bytes of a small object.
    small: Mutex<HashMap<String, SmallFile>>,
}

impl S3Fs {
    pub fn new(
        client: s3::Client,
        read_only: bool,
        scratch: std::path::PathBuf,
        cache_ttl: Duration,
    ) -> std::io::Result<Self> {
        std::fs::create_dir_all(&scratch)?;
        let mut inodes = HashMap::new();
        inodes.insert(FUSE_ROOT_ID, String::new());
        let mut paths = HashMap::new();
        paths.insert(String::new(), FUSE_ROOT_ID);
        Ok(Self {
            client,
            read_only,
            scratch,
            next_ino: AtomicU64::new(FUSE_ROOT_ID + 1),
            next_fh: AtomicU64::new(1),
            inodes: Mutex::new(inodes),
            paths: Mutex::new(paths),
            staged: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            cache_ttl,
            meta: Mutex::new(HashMap::new()),
            small: Mutex::new(HashMap::new()),
        })
    }

    /// What `path` resolved to, while that answer is within the TTL.
    fn known(&self, path: &str) -> Option<Known> {
        if self.cache_ttl.is_zero() {
            return None;
        }
        let meta = self.meta.lock().ok()?;
        let (known, at) = meta.get(path)?;
        (at.elapsed() < self.cache_ttl).then(|| known.clone())
    }

    /// Record what `path` is. A change made through this mount calls this as
    /// it happens, so the mount always reads its own writes.
    fn remember(&self, path: &str, known: Known) {
        if self.cache_ttl.is_zero() {
            return;
        }
        if let Ok(mut meta) = self.meta.lock() {
            // Bounded: drop what has expired once the table grows large.
            if meta.len() > 100_000 {
                let ttl = self.cache_ttl;
                meta.retain(|_, (_, at)| at.elapsed() < ttl);
            }
            meta.insert(path.to_string(), (known, Instant::now()));
        }
    }

    /// Record one listed level: every child, and the directory itself.
    fn remember_listing(&self, dir: &str, listing: &s3::Listing) {
        if !dir.is_empty() {
            self.remember(dir, Known::Present(Node::Dir));
        }
        for d in &listing.prefixes {
            self.remember(&Self::join(dir, d), Known::Present(Node::Dir));
        }
        for o in &listing.objects {
            if o.key.ends_with('/') {
                continue;
            }
            self.remember(
                &Self::join(dir, &o.key),
                Known::Present(Node::File {
                    size: o.size,
                    mtime: o.last_modified_secs,
                }),
            );
        }
    }

    /// Drop a small file's cached bytes after it changed through this mount.
    fn forget_bytes(&self, path: &str) {
        if let Ok(mut small) = self.small.lock() {
            small.remove(path);
        }
    }

    /// The whole bytes of a small object, from memory when this exact version
    /// was read before, else fetched once and kept.
    fn small_bytes(&self, path: &str, size: u64, mtime: u64) -> Option<std::sync::Arc<Vec<u8>>> {
        if let Ok(mut small) = self.small.lock() {
            if let Some(f) = small.get_mut(path) {
                if f.size == size && f.mtime == mtime && f.fetched.elapsed() < self.cache_ttl {
                    f.used = Instant::now();
                    return Some(f.bytes.clone());
                }
            }
        }
        let bytes = self.client.get(path, None).ok()?;
        if bytes.len() as u64 != size {
            // Changed since it was listed: refresh what we know, keep nothing.
            self.remember(
                path,
                Known::Present(Node::File {
                    size: bytes.len() as u64,
                    mtime: Self::now(),
                }),
            );
            return Some(std::sync::Arc::new(bytes));
        }
        let bytes = std::sync::Arc::new(bytes);
        if let Ok(mut small) = self.small.lock() {
            let mut total: u64 = small.values().map(|f| f.size).sum();
            while total + size > SMALL_CACHE_BYTES {
                let Some(oldest) = small
                    .iter()
                    .min_by_key(|(_, f)| f.used)
                    .map(|(k, _)| k.clone())
                else {
                    break;
                };
                if let Some(f) = small.remove(&oldest) {
                    total -= f.size;
                }
            }
            small.insert(
                path.to_string(),
                SmallFile {
                    size,
                    mtime,
                    bytes: bytes.clone(),
                    fetched: Instant::now(),
                    used: Instant::now(),
                },
            );
        }
        Some(bytes)
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn path_of(&self, ino: u64) -> Option<String> {
        self.inodes.lock().ok()?.get(&ino).cloned()
    }

    /// Stable inode for a path, allocating on first sight.
    fn ino_for(&self, path: &str) -> u64 {
        if let Ok(paths) = self.paths.lock() {
            if let Some(i) = paths.get(path) {
                return *i;
            }
        }
        let ino = self.next_ino.fetch_add(1, Ordering::Relaxed);
        if let (Ok(mut paths), Ok(mut inodes)) = (self.paths.lock(), self.inodes.lock()) {
            // Re-check: another thread may have allocated while we were unlocked.
            if let Some(existing) = paths.get(path) {
                return *existing;
            }
            paths.insert(path.to_string(), ino);
            inodes.insert(ino, path.to_string());
        }
        ino
    }

    fn forget_path(&self, path: &str) {
        if let (Ok(mut paths), Ok(mut inodes)) = (self.paths.lock(), self.inodes.lock()) {
            if let Some(ino) = paths.remove(path) {
                inodes.remove(&ino);
            }
        }
    }

    /// Move an inode's mapping from `from` to `to`.
    ///
    /// `rename(2)` does not mint a new inode: the kernel moves the dentry and
    /// keeps the same inode number under the new name. Forgetting the inode
    /// here instead would leave the kernel holding one this filesystem no
    /// longer recognises, and every later lookup on it would fail even though
    /// the object is intact in the bucket.
    fn rename_path(&self, from: &str, to: &str) {
        let (Ok(mut paths), Ok(mut inodes)) = (self.paths.lock(), self.inodes.lock()) else {
            return;
        };
        // A destination that already existed is replaced, exactly as rename
        // replaces it in the bucket.
        if let Some(old) = paths.remove(to) {
            inodes.remove(&old);
        }
        if let Some(ino) = paths.remove(from) {
            inodes.insert(ino, to.to_string());
            paths.insert(to.to_string(), ino);
        }
    }

    fn join(parent: &str, name: &str) -> String {
        if parent.is_empty() {
            name.to_string()
        } else {
            format!("{parent}/{name}")
        }
    }

    fn attr_for(&self, ino: u64, node: &Node) -> Attr {
        match node {
            Node::Dir => Attr {
                ino,
                size: 0,
                blocks: 0,
                mode: DIR_MODE,
                nlink: 2,
                ..Default::default()
            },
            Node::File { size, mtime } => Attr {
                ino,
                size: *size,
                blocks: size.div_ceil(512),
                atime: *mtime,
                mtime: *mtime,
                ctime: *mtime,
                mode: FILE_MODE,
                nlink: 1,
                ..Default::default()
            },
        }
    }

    /// Resolve a path to a node: staged writes first, then the bucket, then a
    /// directory probe (a prefix with any child is a directory).
    fn stat(&self, path: &str) -> Option<Node> {
        if path.is_empty() {
            return Some(Node::Dir);
        }
        if let Ok(pending) = self.pending.lock() {
            if let Some(size) = pending.get(path) {
                return Some(Node::File {
                    size: *size,
                    mtime: Self::now(),
                });
            }
        }
        match self.known(path) {
            Some(Known::Present(node)) => return Some(node),
            Some(Known::Absent) => return None,
            None => {}
        }
        let mut head_failed = false;
        match self.client.head(path) {
            Ok(Some(info)) => {
                let node = Node::File {
                    size: info.size,
                    mtime: info.last_modified_secs,
                };
                self.remember(path, Known::Present(node.clone()));
                return Some(node);
            }
            Ok(None) => {}
            Err(e) => {
                head_failed = true;
                tracing::debug!(path, error = %e, "head failed; treating as absent");
            }
        }
        // Not an object: it may still be a directory prefix. The listing that
        // answers that also describes its children, which come next.
        match self.client.list_dir(path) {
            Ok(l) if !l.objects.is_empty() || !l.prefixes.is_empty() => {
                self.remember_listing(path, &l);
                Some(Node::Dir)
            }
            // Only a definite answer is remembered: a failed HEAD or LIST is a
            // transient error, not proof the path is absent.
            Ok(_) if !head_failed => {
                self.remember(path, Known::Absent);
                None
            }
            _ => None,
        }
    }

    fn staging_path(&self, fh: u64) -> std::path::PathBuf {
        self.scratch.join(format!("stage-{fh}"))
    }

    /// Open a staging file, seeded with the object's current bytes when it
    /// exists — required so a partial write does not truncate the rest away.
    fn open_staged(&self, path: &str, truncate: bool) -> std::io::Result<u64> {
        let fh = self.next_fh.fetch_add(1, Ordering::Relaxed);
        let spath = self.staging_path(fh);
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&spath)?;
        let mut size = 0u64;
        if !truncate {
            if let Ok(bytes) = self.client.get(path, None) {
                file.write_all(&bytes)?;
                file.flush()?;
                size = bytes.len() as u64;
                file.seek(SeekFrom::Start(0))?;
            }
        }
        if let Ok(mut staged) = self.staged.lock() {
            staged.insert(
                fh,
                Staged {
                    file,
                    path: spath,
                    key: path.to_string(),
                    size,
                    dirty: truncate,
                },
            );
        }
        if let Ok(mut pending) = self.pending.lock() {
            pending.insert(path.to_string(), size);
        }
        Ok(fh)
    }

    /// Resize a file to `size`, in the staging file when a handle is open and
    /// in the object itself otherwise.
    ///
    /// Truncation is not a formality here: unless `atomic_o_trunc` is
    /// negotiated the kernel turns `O_TRUNC` into a `SETATTR` with a new size,
    /// so a filesystem that ignores this silently keeps the old contents — a
    /// program that rewrites a file with fewer bytes would leave the previous
    /// tail in place and read back a mix of old and new data.
    fn truncate(&self, path: &str, fh: Option<u64>, size: u64) -> Result<(), i32> {
        let mut staged_any = false;
        if let Ok(mut guard) = self.staged.lock() {
            // Resize every open handle on this object, not only the one the
            // request names. An `O_TRUNC` open arrives as a truncate with no
            // file handle while a staging file is already open, and leaving
            // that staging file at its old length puts the stale tail back
            // over the new contents at flush — the file reads correctly
            // through the mount while the stored object is corrupt.
            for (handle, st) in guard.iter_mut() {
                if st.key != path && Some(*handle) != fh {
                    continue;
                }
                st.file.set_len(size).map_err(|_| libc::EIO)?;
                st.size = size;
                st.dirty = true;
                staged_any = true;
            }
        }
        if staged_any {
            if let Ok(mut pending) = self.pending.lock() {
                pending.insert(path.to_string(), size);
            }
            return Ok(());
        }
        // No open handle: rewrite the object at its new length. Growing pads
        // with zeroes, which is what a sparse-less truncate(2) produces.
        let mut bytes = if size == 0 {
            Vec::new()
        } else {
            self.client.get(path, None).unwrap_or_default()
        };
        bytes.resize(size as usize, 0);
        self.client.put(path, &bytes).map_err(|_| libc::EIO)?;
        self.forget_bytes(path);
        self.remember(
            path,
            Known::Present(Node::File {
                size,
                mtime: Self::now(),
            }),
        );
        // The object now really is this size, so no pending entry is needed —
        // and a stale one would misreport the size of every later read.
        if let Ok(mut pending) = self.pending.lock() {
            pending.remove(path);
        }
        Ok(())
    }

    /// Upload a staged file and drop its staging state.
    fn flush_staged(&self, fh: u64, path: &str, close: bool) -> Result<(), i32> {
        let mut guard = match self.staged.lock() {
            Ok(g) => g,
            Err(_) => return Err(libc::EIO),
        };
        let Some(st) = guard.get_mut(&fh) else {
            return Ok(()); // read-only handle: nothing staged
        };
        if st.dirty {
            let mut buf = Vec::with_capacity(st.size as usize);
            if st.file.seek(SeekFrom::Start(0)).is_err() || st.file.read_to_end(&mut buf).is_err() {
                return Err(libc::EIO);
            }
            if let Err(e) = self.client.put(path, &buf) {
                tracing::warn!(path, error = %e, "upload failed");
                return Err(libc::EIO);
            }
            st.dirty = false;
            self.forget_bytes(path);
            self.remember(
                path,
                Known::Present(Node::File {
                    size: buf.len() as u64,
                    mtime: Self::now(),
                }),
            );
        }
        if close {
            if let Some(st) = guard.remove(&fh) {
                let _ = std::fs::remove_file(&st.path);
            }
            drop(guard);
            if let Ok(mut pending) = self.pending.lock() {
                pending.remove(path);
            }
        }
        Ok(())
    }

    fn deny_if_read_only(&self) -> Option<Reply> {
        self.read_only.then_some(Reply::Error(libc::EROFS))
    }
}

impl Filesystem for S3Fs {
    fn dispatch(&self, req: &Request<'_>) -> Reply {
        use fuse::op;
        match req.opcode {
            op::LOOKUP => {
                let Some(parent) = self.path_of(req.nodeid) else {
                    return Reply::Error(libc::ENOENT);
                };
                let Some(name) = req.name_at(0) else {
                    return Reply::Error(libc::EINVAL);
                };
                let path = Self::join(&parent, &name);
                match self.stat(&path) {
                    Some(node) => Reply::Entry(self.attr_for(self.ino_for(&path), &node)),
                    None => Reply::Error(libc::ENOENT),
                }
            }

            op::GETATTR => {
                let Some(path) = self.path_of(req.nodeid) else {
                    return Reply::Error(libc::ENOENT);
                };
                match self.stat(&path) {
                    Some(node) => Reply::Attr(self.attr_for(req.nodeid, &node)),
                    None => Reply::Error(libc::ENOENT),
                }
            }

            // Accept the metadata changes a normal write path performs (chmod,
            // utimes, truncate-to-zero) so editors and `cp` work; S3 keeps no
            // POSIX metadata, so we acknowledge rather than persist.
            op::SETATTR => {
                if let Some(d) = self.deny_if_read_only() {
                    return d;
                }
                let Some(path) = self.path_of(req.nodeid) else {
                    return Reply::Error(libc::ENOENT);
                };
                // fuse_setattr_in: valid(4) padding(4) fh(8) size(8) ...
                let valid = req.u32_at(0);
                if valid & FATTR_SIZE != 0 {
                    let fh = (valid & FATTR_FH != 0).then(|| req.u64_at(8));
                    if let Err(e) = self.truncate(&path, fh, req.u64_at(16)) {
                        return Reply::Error(e);
                    }
                }
                match self.stat(&path) {
                    Some(node) => Reply::Attr(self.attr_for(req.nodeid, &node)),
                    None => Reply::Error(libc::ENOENT),
                }
            }

            op::OPENDIR => Reply::Open(0),
            op::RELEASEDIR | op::FSYNCDIR => Reply::Ok,

            op::READDIR => {
                let Some(path) = self.path_of(req.nodeid) else {
                    return Reply::Error(libc::ENOENT);
                };
                // fuse_read_in: fh(8) offset(8) size(4) ...
                let offset = req.u64_at(8);
                let size = req.u32_at(16) as usize;
                if offset > 0 {
                    return Reply::Directory(Vec::new()); // single-shot listing
                }
                let listing = match self.client.list_dir(&path) {
                    Ok(l) => l,
                    Err(e) => {
                        tracing::warn!(path, error = %e, "list failed");
                        return Reply::Error(libc::EIO);
                    }
                };
                // `ls -l` and the lookups that follow a listing then cost
                // nothing: the listing already said what each child is.
                self.remember_listing(&path, &listing);
                let mut buf = Vec::new();
                let mut next = 1u64;
                for (name, kind) in [(".", DT_DIR), ("..", DT_DIR)] {
                    fuse::push_dirent(&mut buf, size, req.nodeid, next, kind, name);
                    next += 1;
                }
                for d in &listing.prefixes {
                    let child = Self::join(&path, d);
                    if !fuse::push_dirent(&mut buf, size, self.ino_for(&child), next, DT_DIR, d) {
                        break;
                    }
                    next += 1;
                }
                for o in &listing.objects {
                    // Keys ending in "/" are directory markers, not files.
                    if o.key.ends_with('/') {
                        continue;
                    }
                    let child = Self::join(&path, &o.key);
                    if !fuse::push_dirent(
                        &mut buf,
                        size,
                        self.ino_for(&child),
                        next,
                        DT_REG,
                        &o.key,
                    ) {
                        break;
                    }
                    next += 1;
                }
                Reply::Directory(buf)
            }

            op::OPEN => {
                let Some(path) = self.path_of(req.nodeid) else {
                    return Reply::Error(libc::ENOENT);
                };
                let flags = req.u32_at(0) as i32;
                let wants_write = flags & (libc::O_WRONLY | libc::O_RDWR) != 0;
                if wants_write {
                    if let Some(d) = self.deny_if_read_only() {
                        return d;
                    }
                    match self.open_staged(&path, flags & libc::O_TRUNC != 0) {
                        Ok(fh) => Reply::Open(fh),
                        Err(e) => {
                            tracing::warn!(path, error = %e, "staging open failed");
                            Reply::Error(libc::EIO)
                        }
                    }
                } else {
                    Reply::Open(0) // reads stream straight from the bucket
                }
            }

            op::CREATE => {
                if let Some(d) = self.deny_if_read_only() {
                    return d;
                }
                let Some(parent) = self.path_of(req.nodeid) else {
                    return Reply::Error(libc::ENOENT);
                };
                // fuse_create_in: flags(4) mode(4) umask(4) padding(4), then name
                let Some(name) = req.name_at(16) else {
                    return Reply::Error(libc::EINVAL);
                };
                let path = Self::join(&parent, &name);
                match self.open_staged(&path, true) {
                    Ok(fh) => {
                        let ino = self.ino_for(&path);
                        let attr = self.attr_for(
                            ino,
                            &Node::File {
                                size: 0,
                                mtime: Self::now(),
                            },
                        );
                        Reply::Create(attr, fh)
                    }
                    Err(e) => {
                        tracing::warn!(path, error = %e, "create failed");
                        Reply::Error(libc::EIO)
                    }
                }
            }

            op::READ => {
                let Some(path) = self.path_of(req.nodeid) else {
                    return Reply::Error(libc::ENOENT);
                };
                let fh = req.u64_at(0);
                let offset = req.u64_at(8);
                let size = req.u32_at(16) as u64;

                // A file with unflushed writes must read back what was written,
                // not the stale object still sitting in the bucket.
                if fh != 0 {
                    if let Ok(mut guard) = self.staged.lock() {
                        if let Some(st) = guard.get_mut(&fh) {
                            let mut buf = vec![0u8; size as usize];
                            if st.file.seek(SeekFrom::Start(offset)).is_err() {
                                return Reply::Error(libc::EIO);
                            }
                            let n = st.file.read(&mut buf).unwrap_or(0);
                            buf.truncate(n);
                            return Reply::Data(buf);
                        }
                    }
                }
                if size == 0 {
                    return Reply::Data(Vec::new());
                }
                if let Some(Known::Present(Node::File { size: total, mtime })) = self.known(&path) {
                    if total <= SMALL_FILE_MAX {
                        if let Some(bytes) = self.small_bytes(&path, total, mtime) {
                            let start = (offset as usize).min(bytes.len());
                            let end = (start + size as usize).min(bytes.len());
                            return Reply::Data(bytes[start..end].to_vec());
                        }
                    }
                }
                match self.client.get(&path, Some((offset, offset + size - 1))) {
                    Ok(d) => Reply::Data(d),
                    // A range past EOF is a normal end-of-file, not an error.
                    Err(s3::Error::Status { status: 416, .. }) => Reply::Data(Vec::new()),
                    Err(e) => {
                        tracing::warn!(path, error = %e, "read failed");
                        Reply::Error(libc::EIO)
                    }
                }
            }

            op::WRITE => {
                if let Some(d) = self.deny_if_read_only() {
                    return d;
                }
                let fh = req.u64_at(0);
                let offset = req.u64_at(8);
                let size = req.u32_at(16) as usize;
                // fuse_write_in is 40 bytes, then the payload.
                let Some(data) = req.data.get(40..40 + size) else {
                    return Reply::Error(libc::EINVAL);
                };
                let Some(path) = self.path_of(req.nodeid) else {
                    return Reply::Error(libc::ENOENT);
                };
                let Ok(mut guard) = self.staged.lock() else {
                    return Reply::Error(libc::EIO);
                };
                let Some(st) = guard.get_mut(&fh) else {
                    return Reply::Error(libc::EBADF);
                };
                if st.file.seek(SeekFrom::Start(offset)).is_err()
                    || st.file.write_all(data).is_err()
                {
                    return Reply::Error(libc::EIO);
                }
                st.dirty = true;
                st.size = st.size.max(offset + size as u64);
                let new_size = st.size;
                drop(guard);
                if let Ok(mut pending) = self.pending.lock() {
                    pending.insert(path, new_size);
                }
                Reply::Written(size as u32)
            }

            // FLUSH (close(2)) and FSYNC both have to make the data durable:
            // for object storage "durable" means the upload has happened.
            op::FLUSH | op::FSYNC => {
                let fh = req.u64_at(0);
                let Some(path) = self.path_of(req.nodeid) else {
                    return Reply::Error(libc::ENOENT);
                };
                match self.flush_staged(fh, &path, false) {
                    Ok(()) => Reply::Ok,
                    Err(e) => Reply::Error(e),
                }
            }

            op::RELEASE => {
                let fh = req.u64_at(0);
                let Some(path) = self.path_of(req.nodeid) else {
                    return Reply::Ok;
                };
                match self.flush_staged(fh, &path, true) {
                    Ok(()) => Reply::Ok,
                    Err(e) => Reply::Error(e),
                }
            }

            op::UNLINK => {
                if let Some(d) = self.deny_if_read_only() {
                    return d;
                }
                let Some(parent) = self.path_of(req.nodeid) else {
                    return Reply::Error(libc::ENOENT);
                };
                let Some(name) = req.name_at(0) else {
                    return Reply::Error(libc::EINVAL);
                };
                let path = Self::join(&parent, &name);
                match self.client.delete(&path) {
                    Ok(()) => {
                        self.forget_path(&path);
                        self.forget_bytes(&path);
                        self.remember(&path, Known::Absent);
                        Reply::Ok
                    }
                    Err(e) => {
                        tracing::warn!(path, error = %e, "delete failed");
                        Reply::Error(libc::EIO)
                    }
                }
            }

            // S3 has no directories, so mkdir writes an empty marker object —
            // the convention every S3 browser understands — and rmdir removes it.
            op::MKDIR => {
                if let Some(d) = self.deny_if_read_only() {
                    return d;
                }
                let Some(parent) = self.path_of(req.nodeid) else {
                    return Reply::Error(libc::ENOENT);
                };
                // fuse_mkdir_in: mode(4) umask(4), then name
                let Some(name) = req.name_at(8) else {
                    return Reply::Error(libc::EINVAL);
                };
                let path = Self::join(&parent, &name);
                match self.client.put(&format!("{path}/"), b"") {
                    Ok(()) => {
                        self.remember(&path, Known::Present(Node::Dir));
                        Reply::Entry(self.attr_for(self.ino_for(&path), &Node::Dir))
                    }
                    Err(e) => {
                        tracing::warn!(path, error = %e, "mkdir failed");
                        Reply::Error(libc::EIO)
                    }
                }
            }

            op::RMDIR => {
                if let Some(d) = self.deny_if_read_only() {
                    return d;
                }
                let Some(parent) = self.path_of(req.nodeid) else {
                    return Reply::Error(libc::ENOENT);
                };
                let Some(name) = req.name_at(0) else {
                    return Reply::Error(libc::EINVAL);
                };
                let path = Self::join(&parent, &name);
                match self.client.list_dir(&path) {
                    Ok(l) if !l.objects.is_empty() || !l.prefixes.is_empty() => {
                        Reply::Error(libc::ENOTEMPTY)
                    }
                    _ => match self.client.delete(&format!("{path}/")) {
                        Ok(()) => {
                            self.forget_path(&path);
                            self.remember(&path, Known::Absent);
                            Reply::Ok
                        }
                        Err(_) => Reply::Error(libc::EIO),
                    },
                }
            }

            // S3 cannot rename; copy-then-delete is the only implementation.
            op::RENAME => {
                if let Some(d) = self.deny_if_read_only() {
                    return d;
                }
                let Some(parent) = self.path_of(req.nodeid) else {
                    return Reply::Error(libc::ENOENT);
                };
                let newdir = req.u64_at(0);
                let Some(old_name) = req.name_at(8) else {
                    return Reply::Error(libc::EINVAL);
                };
                let Some(new_name) = req.name_at(8 + old_name.len() + 1) else {
                    return Reply::Error(libc::EINVAL);
                };
                let Some(new_parent) = self.path_of(newdir) else {
                    return Reply::Error(libc::ENOENT);
                };
                let from = Self::join(&parent, &old_name);
                let to = Self::join(&new_parent, &new_name);
                let bytes = match self.client.get(&from, None) {
                    Ok(b) => b,
                    Err(_) => return Reply::Error(libc::ENOENT),
                };
                if self.client.put(&to, &bytes).is_err() {
                    return Reply::Error(libc::EIO);
                }
                let _ = self.client.delete(&from);
                self.rename_path(&from, &to);
                self.forget_bytes(&from);
                self.forget_bytes(&to);
                self.remember(&from, Known::Absent);
                self.remember(
                    &to,
                    Known::Present(Node::File {
                        size: bytes.len() as u64,
                        mtime: Self::now(),
                    }),
                );
                Reply::Ok
            }

            // Object stores have no fixed capacity; report a large, constant
            // pool so tools that pre-check free space proceed.
            op::STATFS => Reply::StatFs {
                blocks: 1 << 40,
                bfree: 1 << 40,
                bavail: 1 << 40,
                files: 1 << 20,
            },

            // Answering ENOSYS makes the kernel stop asking for these entirely.
            op::GETXATTR | op::SETXATTR | op::LISTXATTR | op::REMOVEXATTR | op::LSEEK => {
                Reply::Error(libc::ENOSYS)
            }

            op::DESTROY => Reply::Ok,

            _ => Reply::Error(libc::ENOSYS),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fs() -> S3Fs {
        fs_with_ttl(Duration::ZERO)
    }

    /// A mount whose bucket is unreachable, so any answer it gives without an
    /// error came from its cache.
    fn fs_with_ttl(cache_ttl: Duration) -> S3Fs {
        let dir = std::env::temp_dir().join(format!("s3fs-test-{}", std::process::id()));
        S3Fs::new(
            s3::Client::new(s3::Config {
                endpoint: "http://127.0.0.1:1".into(),
                region: "us-east-1".into(),
                bucket: "b".into(),
                prefix: String::new(),
                credentials: None,
                path_style: true,
                timeout: std::time::Duration::from_millis(50),
            }),
            false,
            dir,
            cache_ttl,
        )
        .expect("scratch dir is creatable")
    }

    // Each lookup used to cost a HEAD (and a LIST on a miss) even for a name
    // asked about a moment ago; within the TTL the answer must come from memory.
    #[test]
    fn a_remembered_answer_needs_no_request() {
        let fs = fs_with_ttl(Duration::from_secs(60));
        let listing = s3::Listing {
            objects: vec![s3::ObjectInfo {
                key: "a.txt".into(),
                size: 5,
                last_modified_secs: 7,
            }],
            prefixes: vec!["sub".into()],
        };
        fs.remember_listing("d", &listing);
        fs.remember("d/missing", Known::Absent);
        assert!(matches!(
            fs.stat("d/a.txt"),
            Some(Node::File { size: 5, mtime: 7 })
        ));
        assert!(matches!(fs.stat("d/sub"), Some(Node::Dir)));
        assert!(matches!(fs.stat("d"), Some(Node::Dir)));
        assert!(fs.stat("d/missing").is_none());
    }

    // A zero TTL turns the cache off entirely, so every lookup reaches the
    // bucket and sees other writers' changes immediately.
    #[test]
    fn a_zero_ttl_remembers_nothing() {
        let fs = fs_with_ttl(Duration::ZERO);
        fs.remember("d/a.txt", Known::Present(Node::Dir));
        assert!(fs.known("d/a.txt").is_none());
    }

    // `rename(2)` keeps the inode and moves the name onto it. Forgetting the
    // inode instead leaves the kernel holding one the filesystem no longer
    // knows, and every later read of the renamed file comes back empty even
    // though the object is intact in the bucket.
    #[test]
    fn renaming_repoints_the_inode_instead_of_dropping_it() {
        let fs = fs();
        let ino = fs.ino_for("d/old.txt");
        fs.rename_path("d/old.txt", "d/new.txt");
        assert_eq!(
            fs.path_of(ino).as_deref(),
            Some("d/new.txt"),
            "the kernel still holds this inode, so it must resolve to the new name"
        );
        assert_eq!(
            fs.ino_for("d/new.txt"),
            ino,
            "looking the new name up again must not mint a second inode"
        );
    }

    // Renaming onto an existing name replaces it in the bucket, so the
    // replaced inode must not linger and shadow the survivor.
    #[test]
    fn renaming_over_an_existing_name_drops_the_replaced_inode() {
        let fs = fs();
        let src = fs.ino_for("d/src.txt");
        let dst = fs.ino_for("d/dst.txt");
        assert_ne!(src, dst);
        fs.rename_path("d/src.txt", "d/dst.txt");
        assert_eq!(fs.path_of(src).as_deref(), Some("d/dst.txt"));
        assert_eq!(fs.path_of(dst), None, "the replaced inode is gone");
    }

    #[test]
    fn inodes_are_stable_per_path_and_unique_across_paths() {
        let fs = fs();
        let a1 = fs.ino_for("data/a.txt");
        let a2 = fs.ino_for("data/a.txt");
        let b = fs.ino_for("data/b.txt");
        assert_eq!(
            a1, a2,
            "the kernel caches by inode; a path must keep its number"
        );
        assert_ne!(a1, b);
        assert_eq!(fs.path_of(a1).as_deref(), Some("data/a.txt"));
    }

    #[test]
    fn the_root_inode_maps_to_the_empty_path() {
        let fs = fs();
        assert_eq!(fs.path_of(FUSE_ROOT_ID).as_deref(), Some(""));
        assert!(matches!(fs.stat(""), Some(Node::Dir)));
    }

    #[test]
    fn joining_handles_the_root_without_a_leading_slash() {
        assert_eq!(S3Fs::join("", "a.txt"), "a.txt");
        assert_eq!(S3Fs::join("data", "a.txt"), "data/a.txt");
    }

    #[test]
    fn directories_and_files_get_the_modes_posix_expects() {
        let fs = fs();
        let d = fs.attr_for(2, &Node::Dir);
        assert_eq!(d.mode & 0o170000, 0o040000, "S_IFDIR");
        assert_eq!(d.nlink, 2);
        let f = fs.attr_for(
            3,
            &Node::File {
                size: 1000,
                mtime: 5,
            },
        );
        assert_eq!(f.mode & 0o170000, 0o100000, "S_IFREG");
        assert_eq!(f.size, 1000);
        assert_eq!(f.blocks, 2, "1000 bytes rounds up to two 512-byte blocks");
    }

    #[test]
    fn a_read_only_mount_refuses_every_mutating_operation() {
        let dir = std::env::temp_dir().join(format!("s3fs-ro-{}", std::process::id()));
        let ro = S3Fs::new(
            s3::Client::new(s3::Config {
                endpoint: "http://127.0.0.1:1".into(),
                region: "us-east-1".into(),
                bucket: "b".into(),
                prefix: String::new(),
                credentials: None,
                path_style: true,
                timeout: std::time::Duration::from_millis(50),
            }),
            true,
            dir,
            Duration::ZERO,
        )
        .unwrap();
        for opcode in [
            fuse::op::WRITE,
            fuse::op::CREATE,
            fuse::op::UNLINK,
            fuse::op::MKDIR,
            fuse::op::RMDIR,
        ] {
            let req = Request {
                opcode,
                unique: 1,
                nodeid: FUSE_ROOT_ID,
                uid: 0,
                gid: 0,
                data: &[0u8; 64],
            };
            assert!(
                matches!(ro.dispatch(&req), Reply::Error(libc::EROFS)),
                "opcode {opcode} must be refused on a read-only mount"
            );
        }
    }

    #[test]
    fn unknown_opcodes_report_enosys_rather_than_hanging() {
        let fs = fs();
        let req = Request {
            opcode: 9999,
            unique: 1,
            nodeid: FUSE_ROOT_ID,
            uid: 0,
            gid: 0,
            data: &[],
        };
        assert!(matches!(fs.dispatch(&req), Reply::Error(libc::ENOSYS)));
    }

    #[test]
    fn statfs_reports_a_pool_large_enough_not_to_block_writers() {
        let fs = fs();
        let req = Request {
            opcode: fuse::op::STATFS,
            unique: 1,
            nodeid: FUSE_ROOT_ID,
            uid: 0,
            gid: 0,
            data: &[],
        };
        match fs.dispatch(&req) {
            Reply::StatFs { bavail, .. } => assert!(bavail > 1 << 30),
            _ => panic!("statfs must not fail"),
        }
    }
}
