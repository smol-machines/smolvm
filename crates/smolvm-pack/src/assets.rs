//! Asset collection and compression for packed binaries.
//!
//! This module handles discovering and packaging runtime assets:
//! - Runtime libraries (libkrun, libkrunfw)
//! - Agent rootfs
//! - OCI image layers

use std::fs::{self, File};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::format::{AssetEntry, AssetInventory, LayerEntry};
use crate::{PackError, Result};

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug)]
struct SparseExtent {
    offset: u64,
    len: u64,
}

/// Return the allocated byte ranges of an APFS sparse file.
///
/// The `tar` crate intentionally disables its `SEEK_DATA`/`SEEK_HOLE` path on
/// macOS, so its otherwise sparse-aware builder expands holes into a dense tar
/// stream. Checkpoint RAM and disk images can be tens of GiB logically while
/// containing only a few MiB of allocated pages; preserve those extents using
/// the GNU sparse-tar representation that the same crate already restores.
#[cfg(target_os = "macos")]
fn macos_sparse_extents(file: &mut File) -> std::io::Result<Option<Vec<SparseExtent>>> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;

    let metadata = file.metadata()?;
    let logical_len = metadata.len();
    if logical_len == 0 || metadata.blocks().saturating_mul(512) >= logical_len {
        return Ok(None);
    }

    let mut extents = Vec::new();
    let mut offset = 0_u64;
    while offset < logical_len {
        let seek_offset = i64::try_from(offset).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "sparse file offset exceeds the host off_t range",
            )
        })?;
        let data_offset = unsafe { libc::lseek(file.as_raw_fd(), seek_offset, libc::SEEK_DATA) };
        if data_offset < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENXIO) {
                break;
            }
            // A filesystem without sparse-seek support is still valid; let the
            // ordinary tar path copy it densely rather than failing a pack.
            if error.raw_os_error() == Some(libc::EINVAL) {
                file.seek(SeekFrom::Start(0))?;
                return Ok(None);
            }
            return Err(error);
        }
        let data = data_offset as u64;
        if data >= logical_len {
            break;
        }

        let hole = unsafe { libc::lseek(file.as_raw_fd(), data_offset, libc::SEEK_HOLE) };
        if hole < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let hole = (hole as u64).min(logical_len);
        if hole <= data {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "sparse extent did not advance",
            ));
        }
        extents.push(SparseExtent {
            offset: data,
            len: hole - data,
        });
        offset = hole;
    }
    file.seek(SeekFrom::Start(0))?;

    let allocated = extents.iter().map(|extent| extent.len).sum::<u64>();
    if allocated >= logical_len {
        return Ok(None);
    }
    // A zero-length final entry carries a trailing hole's logical endpoint in
    // old-GNU sparse tar. Without it extraction would truncate the file at the
    // end of the final allocated extent.
    if extents
        .last()
        .is_none_or(|extent| extent.offset + extent.len < logical_len)
    {
        extents.push(SparseExtent {
            offset: logical_len,
            len: 0,
        });
    }
    Ok(Some(extents))
}

#[cfg(target_os = "macos")]
fn append_macos_sparse_file<W: Write>(
    builder: &mut tar::Builder<W>,
    source: &Path,
    archive_path: &Path,
) -> std::io::Result<bool> {
    let mut file = File::open(source)?;
    let metadata = file.metadata()?;
    let Some(extents) = macos_sparse_extents(&mut file)? else {
        return Ok(false);
    };
    let stored_len = extents.iter().try_fold(0_u64, |total, extent| {
        total.checked_add(extent.len).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "sparse archive payload is too large",
            )
        })
    })?;

    let mut header = tar::Header::new_gnu();
    // Old-GNU sparse headers have a short path field. Let the ordinary tar
    // builder emit its long-name extension rather than making an unrelated
    // sparse asset with a long path un-packable.
    if header.set_path(archive_path).is_err() {
        return Ok(false);
    }
    header.set_metadata(&metadata);
    header.set_entry_type(tar::EntryType::GNUSparse);
    header.set_size(stored_len);
    let first_header_entries = {
        let gnu = header.as_gnu_mut().expect("new GNU header");
        gnu.set_real_size(metadata.len());
        let slots_len = gnu.sparse.len();
        for (extent, slot) in extents.iter().zip(gnu.sparse.iter_mut()) {
            slot.set_offset(extent.offset);
            slot.set_length(extent.len);
        }
        gnu.set_is_extended(extents.len() > slots_len);
        slots_len
    };
    header.set_cksum();
    builder.get_mut().write_all(header.as_bytes())?;

    let remaining = &extents[first_header_entries.min(extents.len())..];
    for (index, chunk) in remaining.chunks(21).enumerate() {
        let mut extended = tar::GnuExtSparseHeader::new();
        for (extent, slot) in chunk.iter().zip(extended.sparse_mut().iter_mut()) {
            slot.set_offset(extent.offset);
            slot.set_length(extent.len);
        }
        extended.set_is_extended((index + 1) * 21 < remaining.len());
        builder.get_mut().write_all(extended.as_bytes())?;
    }

    for extent in &extents {
        if extent.len == 0 {
            continue;
        }
        file.seek(SeekFrom::Start(extent.offset))?;
        let copied = std::io::copy(&mut (&file).take(extent.len), builder.get_mut())?;
        if copied != extent.len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "sparse file changed while it was archived",
            ));
        }
    }
    let padding = (512 - stored_len % 512) % 512;
    if padding != 0 {
        builder
            .get_mut()
            .write_all(&[0_u8; 512][..padding as usize])?;
    }
    Ok(true)
}

#[cfg(target_os = "macos")]
fn append_macos_tree<W: Write>(
    builder: &mut tar::Builder<W>,
    source: &Path,
    archive_path: &Path,
) -> Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    if metadata.is_dir() {
        builder
            .append_dir(archive_path, source)
            .map_err(|error| PackError::Tar(error.to_string()))?;
        let mut entries = fs::read_dir(source)?.collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            append_macos_tree(
                builder,
                &entry.path(),
                &archive_path.join(entry.file_name()),
            )?;
        }
    } else if metadata.is_file() && append_macos_sparse_file(builder, source, archive_path)? {
        // The sparse entry was written directly above.
    } else {
        builder
            .append_path_with_name(source, archive_path)
            .map_err(|error| PackError::Tar(error.to_string()))?;
    }
    Ok(())
}

/// Convert a digest string to a filename for layer tars.
///
/// Strips an optional `sha256:` prefix and uses the full remaining digest hex.
/// Returns an error if the digest portion is shorter than 12 characters.
fn digest_to_filename(digest: &str) -> Result<String> {
    let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
    if hex.len() < 12 {
        return Err(PackError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "digest too short for filename: '{}' ({} chars, need 12)",
                digest,
                hex.len()
            ),
        )));
    }
    // The filename becomes `layers/{hex}.tar` joined onto the staging dir, so
    // the digest MUST be pure hex — otherwise a malicious `.smolmachine` with a
    // digest like `sha256:../../evil` would write the layer bytes outside the
    // staging root (path traversal). A real content digest is always hex.
    if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(PackError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("digest is not valid hex: '{}'", digest),
        )));
    }
    Ok(format!("{}.tar", hex))
}

/// Compression level for zstd (3 = zstd default, fast with good ratio).
/// Level 19 was ~100x slower for only ~10% better compression.
pub const ZSTD_LEVEL: i32 = 3;

/// zstd workers one asset compressor uses at most.
const MAX_COMPRESSION_WORKERS: usize = 4;

/// How long the waiting compressor sleeps between looks for a free slot.
const COMPRESSION_SLOT_POLL: std::time::Duration = std::time::Duration::from_millis(10);

/// Admission to one of `slots` asset compressors per cache root, shared with
/// every process using that cache. Released when the file is closed.
fn compression_permit(cache: &Path, slots: usize) -> Result<File> {
    fs::create_dir_all(cache)?;
    // Never unlink these files: API exports run in separate CLI processes and
    // must lock the same inodes. Closing the handle releases admission on errors
    // and process exit as well as success.
    let mut options = fs::OpenOptions::new();
    options.create(true).write(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    // The first slot keeps the single lock's name, so a process of an older
    // release still shares admission with this one.
    let slot_path = |slot: usize| match slot {
        0 => cache.join("asset-compression.lock"),
        n => cache.join(format!("asset-compression.{n}.lock")),
    };
    let try_slots = || -> Result<Option<File>> {
        for slot in 0..slots.max(1) {
            let file = options.open(slot_path(slot))?;
            match file.try_lock() {
                Ok(()) => return Ok(Some(file)),
                Err(fs::TryLockError::WouldBlock) => {}
                Err(fs::TryLockError::Error(error)) => return Err(error.into()),
            }
        }
        Ok(None)
    };
    if let Some(file) = try_slots()? {
        return Ok(file);
    }
    // Every slot is taken. Waiters queue on this lock in the kernel, and only
    // its holder looks for the next slot to come free.
    let waiters = options.open(cache.join("asset-compression.wait.lock"))?;
    crate::extract::lock_file_exclusive(&waiters)?;
    loop {
        if let Some(file) = try_slots()? {
            return Ok(file);
        }
        std::thread::sleep(COMPRESSION_SLOT_POLL);
    }
}

fn compression_workers(parallelism: usize) -> u32 {
    // Zero means zstd's synchronous mode, not automatic worker selection.
    if parallelism <= 1 {
        0
    } else {
        parallelism.min(MAX_COMPRESSION_WORKERS) as u32
    }
}

/// How many asset compressors may run at once: as many as keep all their
/// workers within the host's CPUs, and always one.
fn compression_slots(parallelism: usize) -> usize {
    (parallelism / MAX_COMPRESSION_WORKERS).max(1)
}

/// Where an agent rootfs tar built from `rootfs_dir` as it is now is kept, so
/// later packs can reuse it. The name is a digest of every entry's path, type,
/// size, mode, owner, inode and change time: any change to the tree, including
/// a reinstall, gives a new name. `None` when the tree cannot be read.
fn agent_rootfs_tar_cache(rootfs_dir: &Path) -> Option<PathBuf> {
    use sha2::{Digest, Sha256};
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;
    fn walk(dir: &Path, relative: &Path, top: bool, hash: &mut Sha256) -> std::io::Result<()> {
        let mut entries: Vec<fs::DirEntry> = fs::read_dir(dir)?.collect::<std::io::Result<_>>()?;
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let name = entry.file_name();
            // Skipped by the tar too: host-side readiness markers.
            if top
                && name
                    .to_string_lossy()
                    .starts_with(smolvm_protocol::AGENT_READY_MARKER)
            {
                continue;
            }
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            let relative = relative.join(&name);
            hash.update(relative.to_string_lossy().as_bytes());
            hash.update([0]);
            #[cfg(unix)]
            {
                for value in [
                    metadata.mode() as u64,
                    metadata.uid() as u64,
                    metadata.gid() as u64,
                    metadata.size(),
                    metadata.ino(),
                    metadata.ctime() as u64,
                    metadata.ctime_nsec() as u64,
                    metadata.mtime() as u64,
                    metadata.mtime_nsec() as u64,
                ] {
                    hash.update(value.to_le_bytes());
                }
            }
            #[cfg(not(unix))]
            hash.update(metadata.len().to_le_bytes());
            if metadata.file_type().is_symlink() {
                hash.update(fs::read_link(&path)?.to_string_lossy().as_bytes());
            } else if metadata.is_dir() {
                walk(&path, &relative, false, hash)?;
            }
        }
        Ok(())
    }
    let mut hash = Sha256::new();
    hash.update(b"agent-rootfs-tar-v1\0");
    walk(rootfs_dir, Path::new(""), true, &mut hash).ok()?;
    let cache = dirs::cache_dir()?.join("smolvm").join("agent-rootfs-tars");
    fs::create_dir_all(&cache).ok()?;
    Some(cache.join(format!("{:x}.tar", hash.finalize())))
}

/// Keep the tar just built at `built` as `cached` for later packs, and drop
/// all but the newest few. Best effort: a failure only costs a rebuild.
fn publish_agent_rootfs_tar(built: &Path, cached: &Path) {
    const KEEP: usize = 4;
    let Some(dir) = cached.parent() else {
        return;
    };
    let temporary = dir.join(format!(
        ".{}.{}",
        cached.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id()
    ));
    let _ = fs::remove_file(&temporary);
    if fs::hard_link(built, &temporary).is_err() || fs::rename(&temporary, cached).is_err() {
        let _ = fs::remove_file(&temporary);
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut tars: Vec<(std::time::SystemTime, PathBuf)> = entries
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tar"))
        .filter_map(|entry| Some((entry.metadata().ok()?.modified().ok()?, entry.path())))
        .collect();
    tars.sort_by_key(|tar| std::cmp::Reverse(tar.0));
    for (_, path) in tars.into_iter().skip(KEEP) {
        let _ = fs::remove_file(path);
    }
}

/// Find a pre-formatted disk template by filename.
///
/// Searches in order:
/// 1. `~/.smolvm/{filename}` (installed location)
/// 2. Next to the current executable (development)
///
/// Each location is checked for the plain file first and then for a `.zst`
/// sibling, which is expanded on demand by [`materialize_template`]. Releases
/// ship only the compressed form; the plain file is still honored so existing
/// installs and development trees keep working untouched.
pub fn find_existing_template(filename: &str) -> Option<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    if let Some(home) = dirs::home_dir() {
        roots.push(home.join(".smolvm"));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            roots.push(dir.to_path_buf());
        }
    }

    for root in &roots {
        let plain = root.join(filename);
        if plain.exists() {
            return Some(plain);
        }
    }
    for root in &roots {
        let compressed = root.join(format!("{filename}.zst"));
        if compressed.exists() {
            match expand_template(&compressed, filename) {
                Ok(path) => return Some(path),
                Err(e) => {
                    // Falling through would report the template as simply
                    // missing, which hides the real cause (usually no space or
                    // no writable location).
                    eprintln!("warning: could not expand {}: {e}", compressed.display());
                }
            }
        }
    }
    None
}

/// Expand `compressed` into a sparse file and return the expanded path.
///
/// Written next to the archive when that directory is writable, otherwise into
/// the user cache — the read-only case is the normal one for Nix and any other
/// immutable store. The result is reused on later runs: the plain-file lookup
/// above finds it first, so expansion happens once per install.
fn expand_template(compressed: &Path, filename: &str) -> std::io::Result<PathBuf> {
    let beside = compressed.parent().map(|d| d.join(filename));
    let cached = dirs::cache_dir().map(|c| c.join("smolvm").join(filename));

    let mut last_err = None;
    for dest in [beside, cached].into_iter().flatten() {
        if dest.exists() {
            return Ok(dest);
        }
        if let Some(parent) = dest.parent() {
            if fs::create_dir_all(parent).is_err() {
                continue;
            }
        }
        match materialize_template(compressed, &dest) {
            Ok(()) => return Ok(dest),
            Err(e) => {
                // A partial file would be mistaken for a good template by the
                // plain-file lookup, so remove it before trying the next root.
                let _ = fs::remove_file(&dest);
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        std::io::Error::other("no writable location to expand the disk template")
    }))
}

/// Decompress `src` into `dest`, writing only the non-zero regions.
///
/// The template is ~20 GiB logical and a few MiB of real data. Expanding it
/// with a plain copy would write every zero, so the zero runs are skipped and
/// left as holes — the same shape the file has when built. Decompression goes
/// to a temporary file that is renamed into place only on success, so a crash
/// or a full disk cannot leave a truncated template behind for the next run to
/// treat as valid.
fn materialize_template(src: &Path, dest: &Path) -> std::io::Result<()> {
    let tmp = dest.with_extension("partial");
    let _ = fs::remove_file(&tmp);
    let result = decompress_sparse(src, &tmp);
    if result.is_ok() {
        if let Err(e) = fs::rename(&tmp, dest) {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
        return Ok(());
    }
    // Leave nothing behind on failure: a stray scratch file wastes space, and a
    // renamed partial would be picked up as a valid template by the next run.
    let _ = fs::remove_file(&tmp);
    result
}

/// Stream `src` into `dest`, skipping the zero runs so they stay holes.
fn decompress_sparse(src: &Path, dest: &Path) -> std::io::Result<()> {
    use std::io::Read as _;

    let file = File::create(dest)?;
    // On Windows/NTFS, File::create makes a non-sparse file: seeking past the
    // zero runs and set_len-ing to the full 20 GiB would allocate and zero-fill
    // the whole gap, ballooning the template to its full logical size on disk.
    // Mark it sparse first so only the written extents consume space — matching
    // the implicit sparse behavior the seek/set_len path already gets on ext4
    // and APFS.
    #[cfg(windows)]
    crate::extract::mark_file_sparse(&file)?;
    let mut out = std::io::BufWriter::new(file);

    let mut decoder = zstd::Decoder::new(File::open(src)?)?;
    let mut buf = vec![0u8; 512 * 1024];
    let mut offset: u64 = 0;
    loop {
        let mut filled = 0;
        // Fill the whole buffer so the zero test sees full chunks rather than
        // whatever short reads the decoder happens to produce.
        while filled < buf.len() {
            match decoder.read(&mut buf[filled..])? {
                0 => break,
                n => filled += n,
            }
        }
        if filled == 0 {
            break;
        }
        let chunk = &buf[..filled];
        if chunk.iter().any(|&b| b != 0) {
            out.seek(SeekFrom::Start(offset))?;
            out.write_all(chunk)?;
        }
        offset += filled as u64;
    }
    out.flush()?;
    let file = out.into_inner().map_err(|e| e.into_error())?;
    // Trailing zeros are never written, so set the length explicitly to give the
    // file its full logical size with the tail left as a hole.
    file.set_len(offset)?;
    file.sync_all()?;
    Ok(())
}

/// Subdirectory of `layers/` holding the workspace seed. Shared with the guest
/// agent, which looks for exactly this path under `/packed_layers`.
pub const WORKSPACE_SEED_DIR: &str = "workspace-seed";
/// Name of the workspace seed tar inside [`WORKSPACE_SEED_DIR`].
pub const WORKSPACE_SEED_FILE: &str = "workspace.tar";

/// A file packed with a few byte ranges replaced, while the file itself is
/// only read.
///
/// This packs an immutable file the caller must not modify, such as a qcow2
/// layer still backing a running machine, with a rewritten header and without
/// copying it first.
#[derive(Debug)]
pub struct PatchedFile {
    /// Relative path of the entry in the archive.
    pub archive_path: String,
    /// The open file whose bytes are packed. Holding it open keeps exactly
    /// these bytes even if the file's path is replaced or removed meanwhile.
    pub source: File,
    /// Permission bits of the archive entry.
    pub mode: u32,
    /// `(offset, bytes)` written over the source's bytes in the archive.
    pub patches: Vec<(u64, Vec<u8>)>,
}

/// Asset collector for gathering runtime components.
pub struct AssetCollector {
    staging_dir: PathBuf,
    inventory: AssetInventory,
    /// Link host assets into staging instead of copying them. Only for a
    /// staging tree that is packed and then discarded unchanged.
    link_host_assets: bool,
    /// Files packed under `checkpoint/` from outside the staging tree.
    patched_files: Vec<PatchedFile>,
}

impl AssetCollector {
    /// Create a new asset collector with a staging directory.
    pub fn new(staging_dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&staging_dir)?;
        fs::create_dir_all(staging_dir.join("layers"))?;

        Ok(Self {
            staging_dir,
            inventory: AssetInventory {
                libraries: Vec::new(),
                agent_rootfs: AssetEntry {
                    path: "agent-rootfs.tar".to_string(),
                    size: 0,
                },
                layers: Vec::new(),
                storage_template: None,
                storage_logical_size: None,
                overlay_template: None,
                overlay_logical_size: None,
                workspace_seed: None,
            },
            link_host_assets: false,
            patched_files: Vec::new(),
        })
    }

    /// Pack `file` under `checkpoint/`, after the staged checkpoint files.
    /// Its archive path must not also exist in the staging tree.
    pub fn add_patched_file(&mut self, file: PatchedFile) -> Result<()> {
        let path = Path::new(&file.archive_path);
        let mut components = path.components();
        if components.next() != Some(std::path::Component::Normal("checkpoint".as_ref()))
            || !components.all(|c| matches!(c, std::path::Component::Normal(_)))
            || file.archive_path.len() > 100
            || fs::symlink_metadata(self.staging_dir.join(path)).is_ok()
            || self
                .patched_files
                .iter()
                .any(|other| other.archive_path == file.archive_path)
        {
            return Err(PackError::Tar(format!(
                "invalid patched archive path {}",
                file.archive_path
            )));
        }
        self.patched_files.push(file);
        Ok(())
    }

    /// Hard-link the libraries and storage template into staging, and reuse
    /// an agent rootfs tar built earlier from the same tree, instead of
    /// writing fresh copies. Use only when the staging tree is packed and then
    /// discarded: nothing may modify a staged file in place.
    pub fn with_linked_host_assets(mut self) -> Self {
        self.link_host_assets = true;
        self
    }

    /// Stage `src` at `dst`: a hard link when enabled and possible, else a copy.
    /// Like the copy, the link is to the file a symlink names.
    fn stage_host_file(&self, src: &Path, dst: &Path) -> Result<()> {
        if self.link_host_assets
            && fs::canonicalize(src).is_ok_and(|file| fs::hard_link(file, dst).is_ok())
        {
            return Ok(());
        }
        fs::copy(src, dst)?;
        Ok(())
    }

    /// Get the staging directory path.
    pub fn staging_dir(&self) -> &Path {
        &self.staging_dir
    }

    /// Discover and copy runtime libraries from the given lib directory.
    ///
    /// Always copies:
    /// - libkrun.dylib / libkrun.so — VM runtime
    /// - libkrunfw.5.dylib / libkrunfw.so.5 — kernel firmware
    ///
    /// Copies when present (GPU passthrough for `gpu = true` guests):
    /// - macOS: libvirglrenderer.1.dylib, libMoltenVK.dylib, libepoxy.0.dylib
    /// - Linux: libvirglrenderer.so.1, libepoxy.so.0, virgl_render_server binary
    ///
    /// GPU Vulkan ICDs (ANV, RADV) are hardware-specific and cannot be bundled.
    /// When GPU libs are bundled, loading them adds ~3ms overhead even for non-GPU
    /// workloads (lib load is unavoidable; virglrenderer init is deferred to GPU use).
    pub fn collect_libraries(&mut self, lib_dir: &Path) -> Result<()> {
        fs::create_dir_all(self.staging_dir.join("lib"))?;

        let lib_names = if cfg!(target_os = "macos") {
            vec!["libkrun.dylib", "libkrunfw.5.dylib"]
        } else if cfg!(target_os = "windows") {
            // Must match smolvm's loader (util::libkrun_filename): WHP uses the
            // Windows DLL names, not the Linux .so names.
            vec!["krun.dll", "libkrunfw.dll"]
        } else {
            vec!["libkrun.so", "libkrunfw.so.5"]
        };

        for name in lib_names {
            let src = lib_dir.join(name);
            if !src.exists() {
                return Err(PackError::AssetNotFound(format!(
                    "library not found: {}",
                    src.display()
                )));
            }

            let dst = self.staging_dir.join("lib").join(name);
            self.stage_host_file(&src, &dst)?;

            let metadata = fs::metadata(&dst)?;
            self.inventory.libraries.push(AssetEntry {
                path: format!("lib/{}", name),
                size: metadata.len(),
            });
        }

        // On macOS, bundle GPU rendering libraries when present in the lib dir.
        // The virglrenderer chain (Venus/Vulkan) enables hardware-accelerated GPU
        // passthrough for guests using virtio-gpu. All paths use @loader_path so
        // they resolve relative to where libkrun.dylib is loaded from.
        #[cfg(target_os = "macos")]
        {
            let gpu_libs = [
                "libvirglrenderer.1.dylib",
                "libMoltenVK.dylib",
                "libepoxy.0.dylib",
            ];
            for name in &gpu_libs {
                let src = lib_dir.join(name);
                if src.exists() {
                    let dst = self.staging_dir.join("lib").join(name);
                    fs::copy(&src, &dst)?;
                    let metadata = fs::metadata(&dst)?;
                    self.inventory.libraries.push(AssetEntry {
                        path: format!("lib/{}", name),
                        size: metadata.len(),
                    });
                }
            }
        }

        // On Linux, bundle GPU rendering libraries and render server when present.
        // virglrenderer + epoxy enable Venus/Vulkan via virtio-gpu.
        // virgl_render_server is the subprocess libkrun spawns during Venus init.
        // GPU Vulkan ICDs (ANV, RADV) are hardware-specific and cannot be bundled.
        #[cfg(target_os = "linux")]
        {
            let gpu_libs = ["libvirglrenderer.so.1", "libepoxy.so.0"];
            for name in &gpu_libs {
                let src = lib_dir.join(name);
                if src.exists() {
                    let dst = self.staging_dir.join("lib").join(name);
                    fs::copy(&src, &dst)?;
                    let metadata = fs::metadata(&dst)?;
                    self.inventory.libraries.push(AssetEntry {
                        path: format!("lib/{}", name),
                        size: metadata.len(),
                    });
                }
            }
            let server_src = lib_dir.join("virgl_render_server");
            if server_src.exists() {
                let server_dst = self.staging_dir.join("lib").join("virgl_render_server");
                fs::copy(&server_src, &server_dst)?;
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&server_dst, fs::Permissions::from_mode(0o755))?;
                let metadata = fs::metadata(&server_dst)?;
                self.inventory.libraries.push(AssetEntry {
                    path: "lib/virgl_render_server".to_string(),
                    size: metadata.len(),
                });
            }
        }

        Ok(())
    }

    /// Copy the agent rootfs directory and create a tarball.
    pub fn collect_agent_rootfs(&mut self, rootfs_dir: &Path) -> Result<()> {
        if !rootfs_dir.exists() {
            return Err(PackError::AssetNotFound(format!(
                "agent rootfs not found: {}",
                rootfs_dir.display()
            )));
        }

        let tar_path = self.staging_dir.join("agent-rootfs.tar");
        let cached = if self.link_host_assets {
            agent_rootfs_tar_cache(rootfs_dir)
        } else {
            None
        };
        if cached
            .as_ref()
            .is_some_and(|cached| fs::hard_link(cached, &tar_path).is_ok())
        {
            let metadata = fs::metadata(&tar_path)?;
            self.inventory.agent_rootfs = AssetEntry {
                path: "agent-rootfs.tar".to_string(),
                size: metadata.len(),
            };
            return Ok(());
        }
        let tar_file = File::create(&tar_path)?;
        let mut tar_builder = tar::Builder::new(BufWriter::new(tar_file));

        // Don't follow symlinks - preserve them as-is
        tar_builder.follow_symlinks(false);

        // The agent-rootfs directory doubles as the virtiofs mount the host
        // writes its per-boot readiness markers into (`.smolvm-ready.<hash>`,
        // see `AGENT_READY_MARKER`). Those are host-side runtime artifacts, not
        // part of the guest init system, and they accumulate across boots — and
        // a VM that ran under per-VM-uid isolation leaves them owned by a
        // foreign uid with mode 0600, unreadable to the packer. `append_dir_all`
        // over the whole directory then hard-failed the entire pack with an
        // opaque "tar error: Permission denied". Walk the top level instead,
        // skip the markers, and name the offending path on any real I/O error.
        let mut entries: Vec<fs::DirEntry> =
            fs::read_dir(rootfs_dir)?.collect::<std::io::Result<_>>()?;
        // Deterministic ordering so the tar (and its hash) is reproducible.
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let name = entry.file_name();
            if name
                .to_string_lossy()
                .starts_with(smolvm_protocol::AGENT_READY_MARKER)
            {
                continue;
            }
            let path = entry.path();
            let tar_err = |e: std::io::Error| PackError::Tar(format!("{}: {e}", path.display()));
            if entry.file_type()?.is_dir() {
                tar_builder.append_dir_all(&name, &path).map_err(tar_err)?;
            } else {
                // Regular file or symlink (follow_symlinks(false) archives the
                // link itself rather than its target).
                tar_builder
                    .append_path_with_name(&path, &name)
                    .map_err(tar_err)?;
            }
        }

        let tar_file = tar_builder
            .into_inner()
            .map_err(|e| PackError::Tar(e.to_string()))?
            .into_inner()
            .map_err(|e| PackError::Io(e.into_error()))?;
        if let Some(cached) = &cached {
            // Later packs trust the cached tar as complete.
            tar_file.sync_all()?;
            publish_agent_rootfs_tar(&tar_path, cached);
        }
        drop(tar_file);

        let metadata = fs::metadata(&tar_path)?;
        self.inventory.agent_rootfs = AssetEntry {
            path: "agent-rootfs.tar".to_string(),
            size: metadata.len(),
        };

        Ok(())
    }

    /// Add an OCI layer tarball.
    pub fn add_layer(&mut self, digest: &str, layer_data: &[u8]) -> Result<()> {
        let filename = digest_to_filename(digest)?;
        let path = format!("layers/{}", filename);

        let dst = self.staging_dir.join(&path);
        fs::write(&dst, layer_data)?;

        self.inventory.layers.push(LayerEntry {
            digest: digest.to_string(),
            path,
            size: layer_data.len() as u64,
        });

        Ok(())
    }

    /// Total bytes of the layer tars registered so far.
    ///
    /// From-vm packs record this as the manifest's `image_size` so the run-time
    /// storage auto-sizer accounts for the layers — essential when the guest
    /// unpacks staged tars onto the storage disk itself.
    pub fn staged_layer_bytes(&self) -> u64 {
        self.inventory.layers.iter().map(|l| l.size).sum()
    }

    /// Get the staging path where a layer file should be written.
    ///
    /// Call this before streaming the layer to get the destination path,
    /// then call `register_layer()` after writing to register it in the inventory.
    pub fn layer_staging_path(&self, digest: &str) -> PathBuf {
        let filename = digest_to_filename(digest)
            .expect("layer digest must be sha256:<hex> with at least 12 hex chars");
        self.staging_dir.join(format!("layers/{}", filename))
    }

    /// Register a layer that was already written to its staging path.
    ///
    /// Use after streaming a layer directly to `layer_staging_path()`.
    pub fn register_layer(&mut self, digest: &str) -> Result<()> {
        let filename = digest_to_filename(digest)?;
        let path = format!("layers/{}", filename);
        let dst = self.staging_dir.join(&path);

        let metadata = fs::metadata(&dst)?;
        self.inventory.layers.push(LayerEntry {
            digest: digest.to_string(),
            path,
            size: metadata.len(),
        });

        Ok(())
    }

    /// Add an OCI layer from a file path.
    pub fn add_layer_from_file(&mut self, digest: &str, layer_path: &Path) -> Result<()> {
        let filename = digest_to_filename(digest)?;
        let path = format!("layers/{}", filename);

        let dst = self.staging_dir.join(&path);
        fs::copy(layer_path, &dst)?;

        let metadata = fs::metadata(&dst)?;
        self.inventory.layers.push(LayerEntry {
            digest: digest.to_string(),
            path,
            size: metadata.len(),
        });

        Ok(())
    }

    /// Create and collect a pre-formatted ext4 storage template.
    ///
    /// Creates a small sparse ext4 disk image that can be used as a template
    /// for the storage disk at runtime. This eliminates the need for mkfs.ext4
    /// on first boot and improves reliability.
    ///
    /// Tries in order:
    /// 1. Copy an existing pre-formatted template from `~/.smolvm/` or next to the exe
    /// 2. Format a new one with `mkfs.ext4` (requires e2fsprogs)
    ///
    /// The template is a 512MB sparse file (actual size ~100KB when empty).
    pub fn create_storage_template(&mut self) -> Result<()> {
        use std::io::{Seek, SeekFrom, Write};
        use std::process::Command;

        const TEMPLATE_SIZE: u64 = 512 * 1024 * 1024; // 512MB virtual size
        const TEMPLATE_NAME: &str = "storage.ext4";

        let template_path = self.staging_dir.join(TEMPLATE_NAME);

        // Try to copy from an existing pre-formatted template first.
        // This avoids requiring e2fsprogs on the build machine.
        if let Some(existing) = find_existing_template("storage-template.ext4") {
            // Hole-preserving copy: the shipped storage-template.ext4 is a large
            // (multi-GiB) sparse file, and a plain fs::copy densifies it into its
            // full logical size of zeros on some Linux filesystems/mounts —
            // ballooning the staging dir and failing pack builds with ENOSPC.
            if !(self.link_host_assets
                && fs::canonicalize(&existing)
                    .is_ok_and(|file| fs::hard_link(file, &template_path).is_ok()))
            {
                crate::extract::sparse_copy(&existing, &template_path)?;
            }
            let metadata = fs::metadata(&template_path)?;
            self.inventory.storage_template = Some(AssetEntry {
                path: TEMPLATE_NAME.to_string(),
                size: metadata.len(),
            });
            return Ok(());
        }

        // No pre-formatted template found — create one with mkfs.ext4.

        // Create sparse file
        let mut file = File::create(&template_path)?;
        // On Windows/NTFS, File::create makes a dense file; seeking past the end
        // and writing a tail byte would allocate every intermediate block.
        #[cfg(windows)]
        crate::extract::mark_file_sparse(&file)?;
        file.seek(SeekFrom::Start(TEMPLATE_SIZE - 1))?;
        file.write_all(&[0])?;
        file.sync_all()?;
        drop(file);

        // Find mkfs.ext4
        let mkfs_paths = [
            "/opt/homebrew/opt/e2fsprogs/sbin/mkfs.ext4",
            "/usr/local/opt/e2fsprogs/sbin/mkfs.ext4",
            "/opt/homebrew/sbin/mkfs.ext4",
            "/usr/local/sbin/mkfs.ext4",
            "/sbin/mkfs.ext4",
            "/usr/sbin/mkfs.ext4",
            "mkfs.ext4",
        ];

        let mkfs_path = mkfs_paths
            .iter()
            .find(|p| {
                if p.contains('/') {
                    std::path::Path::new(p).exists()
                } else {
                    Command::new(p).arg("--version").output().is_ok()
                }
            })
            .ok_or_else(|| {
                // Windows has no host mkfs.ext4, so point the user at the
                // guest-VM recipe for staging a template (the agent rootfs has
                // e2fsprogs). On Unix the fix is just installing e2fsprogs.
                #[cfg(windows)]
                let msg = "storage-template.ext4 not found, and Windows has no host \
                     mkfs.ext4 to create one. Format a small template inside a guest VM \
                     once and place it next to smolvm.exe (or in %USERPROFILE%\\.smolvm\\):\n  \
                     smolvm machine create --name mktmpl --volume <dir>:/out\n  \
                     smolvm machine start --name mktmpl\n  \
                     smolvm machine exec --name mktmpl -- /bin/busybox sh -c \
                     \"truncate -s 512M /out/storage-template.ext4 && \
                     mkfs.ext4 -F -q -m 0 /out/storage-template.ext4\"\n  \
                     smolvm machine delete --name mktmpl --force\n  \
                     then copy <dir>\\storage-template.ext4 next to smolvm.exe";
                #[cfg(not(windows))]
                let msg = "mkfs.ext4 not found. Install e2fsprogs or place a pre-formatted \
                     storage-template.ext4 in ~/.smolvm/";
                PackError::AssetNotFound(msg.into())
            })?;

        // Format with ext4
        // Reset SIGCHLD to default before spawning to avoid issues after agent stop
        #[cfg(unix)]
        unsafe {
            libc::signal(libc::SIGCHLD, libc::SIG_DFL);
        }

        let mut child = Command::new(mkfs_path)
            .args([
                "-F", // Force (don't ask)
                "-q", // Quiet
                "-m", "0", // No reserved blocks
                "-L", "smolvm", // Label
            ])
            .arg(&template_path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| PackError::AssetNotFound(format!("failed to spawn mkfs.ext4: {}", e)))?;

        let status = child.wait().map_err(|e| {
            PackError::AssetNotFound(format!("failed to wait for mkfs.ext4: {}", e))
        })?;

        if !status.success() {
            return Err(PackError::AssetNotFound(
                "mkfs.ext4 failed to format storage template".into(),
            ));
        }

        // Get actual file size (sparse, so much smaller than 512MB)
        let metadata = fs::metadata(&template_path)?;
        self.inventory.storage_template = Some(AssetEntry {
            path: TEMPLATE_NAME.to_string(),
            size: metadata.len(),
        });

        Ok(())
    }

    /// Add an overlay disk template from an existing VM.
    ///
    /// Copies the VM's overlay disk (overlay.raw) to the staging directory as
    /// `overlay.raw`, stripping trailing sparse holes so only actual data bytes
    /// enter the tar/zstd pipeline.  For a typical 10 GiB overlay with ~50 MB
    /// of real ext4 data this reduces pack time by ~100x.
    ///
    /// The original full size is recorded in `overlay_logical_size` so that
    /// the extraction path can restore the sparse skeleton with `ftruncate`.
    pub fn add_overlay_template(&mut self, path: &Path) -> Result<()> {
        if !path.exists() {
            return Err(PackError::AssetNotFound(format!(
                "overlay disk not found: {}",
                path.display()
            )));
        }

        const OVERLAY_NAME: &str = "overlay.raw";
        let dst = self.staging_dir.join(OVERLAY_NAME);

        let (logical_size, truncated_size) = sparse_copy_overlay(path, &dst)?;

        self.inventory.overlay_template = Some(AssetEntry {
            path: OVERLAY_NAME.to_string(),
            size: truncated_size,
        });

        // Record the original full disk size so extract can restore it.
        if logical_size > truncated_size {
            self.inventory.overlay_logical_size = Some(logical_size);
        }

        Ok(())
    }

    /// Add a stopped VM's persistent storage disk as the VM-mode template.
    /// Trailing sparse space is stripped for packing and its original logical
    /// size is recorded so cold-create can normalize one safe COW base.
    pub fn add_vm_storage_template(&mut self, path: &Path) -> Result<()> {
        if !path.exists() {
            return Err(PackError::AssetNotFound(format!(
                "storage disk not found: {}",
                path.display()
            )));
        }

        const STORAGE_NAME: &str = "storage.ext4";
        let dst = self.staging_dir.join(STORAGE_NAME);
        let (logical_size, truncated_size) = sparse_copy_overlay(path, &dst)?;
        self.inventory.storage_template = Some(AssetEntry {
            path: STORAGE_NAME.to_string(),
            size: truncated_size,
        });
        self.inventory.storage_logical_size = Some(logical_size);
        Ok(())
    }

    /// Record a tar of the source machine's `/workspace` as the pack's
    /// workspace seed.
    ///
    /// It lives in its own subdirectory under `layers/` so the guest, which
    /// treats every top-level `*.tar` there as an image layer, never mistakes
    /// it for one.
    pub fn add_workspace_seed(&mut self, tar: &Path) -> Result<()> {
        if !tar.exists() {
            return Err(PackError::AssetNotFound(format!(
                "workspace seed not found: {}",
                tar.display()
            )));
        }
        let rel = format!("layers/{}/{}", WORKSPACE_SEED_DIR, WORKSPACE_SEED_FILE);
        let dst = self.staging_dir.join(&rel);
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::rename(tar, &dst).or_else(|_| std::fs::copy(tar, &dst).map(|_| ()))?;
        let size = std::fs::metadata(&dst)?.len();
        self.inventory.workspace_seed = Some(AssetEntry { path: rel, size });
        Ok(())
    }

    /// Get the current asset inventory.
    pub fn inventory(&self) -> &AssetInventory {
        &self.inventory
    }

    /// Consume the collector and return the final inventory.
    pub fn into_inventory(self) -> AssetInventory {
        self.inventory
    }

    /// Compress staged assets into a single zstd-compressed tarball.
    ///
    /// When `exclude_libs` is true, the `lib/` directory is excluded
    /// (two-file mode: libs are embedded in the stub binary instead).
    /// When false, everything is included (single-file mode).
    pub fn compress(&self, output: &Path, exclude_libs: bool) -> Result<u64> {
        let output_file = self.compress_with(|| File::create(output), exclude_libs, None)?;
        Ok(output_file.metadata()?.len())
    }

    /// Compress into an owned writer so callers can checksum bytes as they are
    /// emitted instead of copying and rereading a multi-GiB archive.
    pub(crate) fn compress_to<W: Write>(&self, output: W, exclude_libs: bool) -> Result<W> {
        self.compress_with(|| Ok(output), exclude_libs, None)
    }

    pub(crate) fn compress_checkpoint_to<W: Write>(
        &self,
        output: W,
        stream: &mut crate::checkpoint_stream::CheckpointStream<'_>,
    ) -> Result<W> {
        match fs::symlink_metadata(self.staging_dir.join("checkpoint/memory.bin")) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
            Ok(_) => {
                return Err(PackError::Tar(
                    "checkpoint RAM appears in both staging and stream".into(),
                ))
            }
        }
        self.compress_with(|| Ok(output), false, Some(stream))
    }

    fn compress_with<W: Write>(
        &self,
        output: impl FnOnce() -> std::io::Result<W>,
        exclude_libs: bool,
        stream: Option<&mut crate::checkpoint_stream::CheckpointStream<'_>>,
    ) -> Result<W> {
        // A bounded number of asset compressors per cache root, including API
        // subprocesses, so their workers together stay within the host's CPUs.
        // The permit also covers finish(), which drains outstanding zstd jobs.
        let parallelism =
            std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
        let cache = dirs::cache_dir()
            .ok_or_else(|| PackError::Compression("cannot locate compression cache".into()))?
            .join("smolvm");
        let _permit =
            compression_permit(&cache, compression_slots(parallelism)).map_err(|error| {
                PackError::Compression(format!(
                    "acquire compression admission at {}: {error}",
                    cache.display()
                ))
            })?;
        let mut encoder = zstd::stream::Encoder::new(output()?, ZSTD_LEVEL)
            .map_err(|e| PackError::Compression(e.to_string()))?;
        let workers = compression_workers(parallelism);
        if workers > 0 {
            encoder
                .multithread(workers)
                .map_err(|e| PackError::Compression(e.to_string()))?;
        }
        let mut tar_builder = tar::Builder::new(encoder);
        // Put resume inputs before disks and portable runtime assets so local
        // resume can stop decoding after the files it needs are extracted.
        let checkpoint_dir = self.staging_dir.join("checkpoint");
        let streamed = stream.is_some();
        if streamed && checkpoint_dir.is_dir() {
            tar_builder
                .append_dir("checkpoint", &checkpoint_dir)
                .map_err(|error| PackError::Tar(error.to_string()))?;
        }
        if let Some(stream) = stream {
            stream.append(&mut tar_builder)?;
        }

        // Sort entries for deterministic tar ordering (consistent checksums)
        let mut entries: Vec<_> = fs::read_dir(&self.staging_dir)?
            .filter_map(|e| e.ok())
            .collect();
        entries.sort_by_key(|e| (e.file_name() != "checkpoint", e.file_name()));

        for entry in entries {
            let name = entry.file_name();
            if exclude_libs && name == "lib" {
                continue; // libs go in the stub, not the sidecar
            }
            let path = entry.path();
            if name == "checkpoint" && path.is_dir() {
                if !streamed {
                    tar_builder
                        .append_dir("checkpoint", &path)
                        .map_err(|error| PackError::Tar(error.to_string()))?;
                }
                let mut children = fs::read_dir(&path)?.collect::<std::io::Result<Vec<_>>>()?;
                children.sort_by_key(|child| (child.file_name() == "disks", child.file_name()));
                for child in children {
                    let child_path = child.path();
                    let child_name = Path::new("checkpoint").join(child.file_name());
                    #[cfg(target_os = "macos")]
                    append_macos_tree(&mut tar_builder, &child_path, &child_name)?;
                    #[cfg(not(target_os = "macos"))]
                    append_checkpoint_tree(&mut tar_builder, &child_path, &child_name)?;
                }
                let mut patched: Vec<_> = self.patched_files.iter().collect();
                patched.sort_by(|a, b| a.archive_path.cmp(&b.archive_path));
                for file in patched {
                    append_patched_file(tar_builder.get_mut(), file)?;
                }
                continue;
            }
            #[cfg(target_os = "macos")]
            append_macos_tree(&mut tar_builder, &path, Path::new(&name))?;
            #[cfg(not(target_os = "macos"))]
            {
                if path.is_dir() {
                    tar_builder
                        .append_dir_all(name.to_string_lossy().as_ref(), &path)
                        .map_err(|e| PackError::Tar(e.to_string()))?;
                } else {
                    tar_builder
                        .append_path_with_name(&path, name.to_string_lossy().as_ref())
                        .map_err(|e| PackError::Tar(e.to_string()))?;
                }
            }
        }

        let encoder = tar_builder
            .into_inner()
            .map_err(|e| PackError::Tar(e.to_string()))?;
        encoder
            .finish()
            .map_err(|e| PackError::Compression(e.to_string()))
    }
}

/// The data ranges of `file`, `len` bytes long, as `(offset, length)`.
/// A filesystem without hole reporting gives one range for the whole file.
#[cfg(unix)]
fn data_ranges(file: &File, len: u64) -> std::io::Result<Vec<(u64, u64)>> {
    use std::os::unix::io::AsRawFd;
    let seek = |offset: u64, whence| -> std::io::Result<Option<u64>> {
        let offset = i64::try_from(offset)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "offset"))?;
        // Safety: the descriptor is a live regular file borrowed for the call.
        match unsafe { libc::lseek(file.as_raw_fd(), offset as libc::off_t, whence) } {
            -1 => match std::io::Error::last_os_error() {
                error if error.raw_os_error() == Some(libc::ENXIO) => Ok(None),
                error => Err(error),
            },
            found => Ok(Some(found as u64)),
        }
    };
    let mut ranges = Vec::new();
    let mut offset = 0;
    while offset < len {
        let start = match seek(offset, libc::SEEK_DATA) {
            Ok(Some(start)) if start >= offset => start.min(len),
            Ok(Some(_)) => {
                return Err(std::io::Error::other("SEEK_DATA went backwards"));
            }
            Ok(None) => break,
            // No hole reporting: treat the rest of the file as data.
            Err(error) if error.raw_os_error() == Some(libc::EINVAL) && ranges.is_empty() => {
                return Ok(vec![(0, len)]);
            }
            Err(error) => return Err(error),
        };
        if start >= len {
            break;
        }
        let end = seek(start, libc::SEEK_HOLE)?.unwrap_or(len).min(len);
        if end <= start {
            return Err(std::io::Error::other("SEEK_HOLE did not advance"));
        }
        ranges.push((start, end - start));
        offset = end;
    }
    Ok(ranges)
}

#[cfg(not(unix))]
fn data_ranges(_file: &File, len: u64) -> std::io::Result<Vec<(u64, u64)>> {
    Ok(if len == 0 { Vec::new() } else { vec![(0, len)] })
}

/// Sorted, disjoint ranges covering `ranges` and every patch, 512-aligned
/// around patches so they stay sector-aligned.
fn ranges_with_patches(
    mut ranges: Vec<(u64, u64)>,
    patches: &[(u64, Vec<u8>)],
    len: u64,
) -> std::io::Result<Vec<(u64, u64)>> {
    for (offset, bytes) in patches {
        let end = offset
            .checked_add(bytes.len() as u64)
            .filter(|end| *end <= len && !bytes.is_empty())
            .ok_or_else(|| std::io::Error::other("patch lies outside the file"))?;
        let start = offset - offset % 512;
        let end = end.div_ceil(512).saturating_mul(512).min(len);
        ranges.push((start, end - start));
    }
    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (offset, length) in ranges {
        match merged.last_mut() {
            Some((last, last_len)) if offset <= *last + *last_len => {
                *last_len = (*last_len).max(offset + length - *last);
            }
            _ => merged.push((offset, length)),
        }
    }
    Ok(merged)
}

/// Write a tar header for `path`: a regular entry when `ranges` is the whole
/// file, else an old-GNU sparse entry listing `ranges`, whose bytes follow
/// back to back.
pub(crate) fn write_sparse_header<W: Write>(
    archive: &mut W,
    mut header: tar::Header,
    logical: u64,
    ranges: &[(u64, u64)],
) -> std::io::Result<u64> {
    let stored: u64 = ranges.iter().map(|(_, len)| *len).sum();
    header.set_size(stored);
    if ranges == [(0, logical)] || logical == 0 {
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        archive.write_all(header.as_bytes())?;
        return Ok(stored);
    }
    let mut map = ranges.to_vec();
    // The terminal entry gives the logical size even when it ends in a hole.
    map.push((logical, 0));
    header.set_entry_type(tar::EntryType::GNUSparse);
    let gnu = header
        .as_gnu_mut()
        .ok_or_else(|| std::io::Error::other("sparse entries need a GNU header"))?;
    gnu.set_real_size(logical);
    for ((offset, len), slot) in map.iter().zip(gnu.sparse.iter_mut()) {
        slot.set_offset(*offset);
        slot.set_length(*len);
    }
    let slots = gnu.sparse.len();
    gnu.set_is_extended(map.len() > slots);
    header.set_cksum();
    archive.write_all(header.as_bytes())?;
    let rest = &map[map.len().min(slots)..];
    for (index, chunk) in rest.chunks(21).enumerate() {
        let mut extra = tar::GnuExtSparseHeader::new();
        for ((offset, len), slot) in chunk.iter().zip(extra.sparse_mut().iter_mut()) {
            slot.set_offset(*offset);
            slot.set_length(*len);
        }
        extra.set_is_extended((index + 1) * 21 < rest.len());
        archive.write_all(extra.as_bytes())?;
    }
    Ok(stored)
}

/// Append `file` with its patches applied, keeping its holes.
fn append_patched_file<W: Write>(archive: &mut W, file: &PatchedFile) -> Result<()> {
    append_file_entry(
        archive,
        &file.archive_path,
        &file.source,
        file.mode,
        &file.patches,
        false,
    )
}

/// Granularity of a checkpoint archive's RAM map. RAM is serialized as
/// whole aligned blocks of the logical image, each either data or a hole, so
/// however fragmented the source's extents are, the archive lists a few large
/// runs and a restore writes them with a few large writes.
pub(crate) const RAM_BLOCK: u64 = 64 * 1024;

/// `ranges` widened to whole `block`-aligned blocks within `logical` bytes,
/// with overlapping and adjacent blocks merged.
pub(crate) fn align_ranges(ranges: &[(u64, u64)], block: u64, logical: u64) -> Vec<(u64, u64)> {
    let mut aligned: Vec<(u64, u64)> = Vec::new();
    for &(offset, len) in ranges.iter().filter(|(_, len)| *len > 0) {
        let start = offset - offset % block;
        let end = (offset + len)
            .div_ceil(block)
            .saturating_mul(block)
            .min(logical);
        match aligned.last_mut() {
            Some((last, last_len)) if start <= *last + *last_len => {
                *last_len = end.max(*last + *last_len) - *last;
            }
            _ => aligned.push((start, end - start)),
        }
    }
    aligned
}

/// The [`RAM_BLOCK`]-aligned blocks of `file` covering `ranges` that are not
/// entirely zero, with adjacent blocks merged.
fn nonzero_ranges(
    file: &File,
    ranges: &[(u64, u64)],
    logical: u64,
) -> std::io::Result<Vec<(u64, u64)>> {
    let mut found: Vec<(u64, u64)> = Vec::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    for (start, len) in align_ranges(ranges, RAM_BLOCK, logical) {
        let end = start + len;
        let mut position = start;
        while position < end {
            let count = (end - position).min(buffer.len() as u64) as usize;
            read_exact_at(file, &mut buffer[..count], position)?;
            for (index, bytes) in buffer[..count].chunks(RAM_BLOCK as usize).enumerate() {
                if crate::is_zero_filled(bytes) {
                    continue;
                }
                let block = position + index as u64 * RAM_BLOCK;
                let block_end = block + bytes.len() as u64;
                match found.last_mut() {
                    Some((last, last_len)) if *last + *last_len == block => {
                        *last_len = block_end - *last;
                    }
                    _ => found.push((block, block_end - block)),
                }
            }
            position += count as u64;
        }
    }
    Ok(found)
}

fn read_exact_at(file: &File, buffer: &mut [u8], offset: u64) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.read_exact_at(buffer, offset)
    }
    #[cfg(not(unix))]
    {
        let mut file = file;
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(buffer)
    }
}

/// Append the regular file `source` as `archive_path`: a sparse entry of its
/// data extents, or with `ram_blocks` of its [`RAM_BLOCK`]-aligned blocks that
/// are not entirely zero, with `patches` written over its bytes. Reads are large and sequential so a cold
/// file streams at the device's rate. `source` itself is only read.
fn append_file_entry<W: Write>(
    archive: &mut W,
    archive_path: &str,
    source: &File,
    mode: u32,
    patches: &[(u64, Vec<u8>)],
    ram_blocks: bool,
) -> Result<()> {
    let before = source.metadata()?;
    if !before.is_file() {
        return Err(PackError::Tar(format!(
            "{archive_path} is not a regular file"
        )));
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        // Safety: advisory only, on a live descriptor.
        unsafe { libc::posix_fadvise(source.as_raw_fd(), 0, 0, libc::POSIX_FADV_SEQUENTIAL) };
    }
    let logical = before.len();
    let mut ranges = data_ranges(source, logical)?;
    if ram_blocks {
        ranges = nonzero_ranges(source, &ranges, logical)?;
    }
    let ranges = ranges_with_patches(ranges, patches, logical)?;
    let mut header = tar::Header::new_gnu();
    header
        .set_path(archive_path)
        .map_err(|error| PackError::Tar(error.to_string()))?;
    header.set_mode(mode);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        header.set_uid(u64::from(before.uid()));
        header.set_gid(u64::from(before.gid()));
    }
    header.set_mtime(
        before
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |time| time.as_secs()),
    );
    let stored = write_sparse_header(archive, header, logical, &ranges)?;
    let mut buffer = vec![0_u8; 1024 * 1024];
    for &(offset, len) in &ranges {
        let mut position = offset;
        let end = offset + len;
        while position < end {
            let chunk = (end - position).min(buffer.len() as u64) as usize;
            let bytes = &mut buffer[..chunk];
            read_exact_at(source, bytes, position)?;
            for (patch_offset, patch) in patches {
                let from = (*patch_offset).max(position);
                let to = (patch_offset + patch.len() as u64).min(position + chunk as u64);
                if from < to {
                    bytes[(from - position) as usize..(to - position) as usize].copy_from_slice(
                        &patch[(from - patch_offset) as usize..(to - patch_offset) as usize],
                    );
                }
            }
            archive.write_all(bytes)?;
            position += chunk as u64;
        }
    }
    let padding = (512 - stored % 512) % 512;
    archive.write_all(&[0; 512][..padding as usize])?;
    let after = source.metadata()?;
    if after.len() != logical || after.modified().ok() != before.modified().ok() {
        return Err(PackError::Tar(format!(
            "{archive_path} changed while it was packed"
        )));
    }
    Ok(())
}

/// Append the staged checkpoint tree at `path` as `name`: directories in
/// sorted order, files through [`append_file_entry`], with all-zero RAM left
/// out as holes.
#[cfg(not(target_os = "macos"))]
fn append_checkpoint_tree<W: Write>(
    builder: &mut tar::Builder<W>,
    path: &Path,
    name: &Path,
) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    // Tar paths use `/` on every host; a Windows `Path` joins with `\`.
    let archive_path = name
        .to_str()
        .ok_or_else(|| PackError::Tar(format!("{} is not UTF-8", name.display())))?
        .replace('\\', "/");
    let archive_path = archive_path.as_str();
    if metadata.is_dir() {
        builder
            .append_dir(name, path)
            .map_err(|error| PackError::Tar(error.to_string()))?;
        let mut children = fs::read_dir(path)?.collect::<std::io::Result<Vec<_>>>()?;
        children.sort_by_key(|child| child.file_name());
        for child in children {
            append_checkpoint_tree(builder, &child.path(), &name.join(child.file_name()))?;
        }
        return Ok(());
    }
    if !metadata.is_file() || archive_path.len() > 100 {
        return builder
            .append_path_with_name(path, name)
            .map_err(|error| PackError::Tar(error.to_string()));
    }
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o7777
    };
    #[cfg(not(unix))]
    let mode = 0o644;
    append_file_entry(
        builder.get_mut(),
        archive_path,
        &File::open(path)?,
        mode,
        &[],
        archive_path == "checkpoint/memory.bin",
    )
}

// =============================================================================
// Sparse-aware overlay copy
// =============================================================================

/// Copy a sparse overlay disk to `dst`, stripping trailing zeros.
///
/// Scans backwards from the end of the source to find the last non-zero byte,
/// then copies only bytes `[0, last_nonzero+1]` to `dst`, skipping zero
/// chunks in the forward pass.
///
/// `SEEK_DATA`/`SEEK_HOLE` is avoided because APFS reports zero-fill extents
/// (efficiently stored but containing zeros) as "data", making lseek-based
/// hole detection return the full file size even when 90%+ is zeros.
/// Content scanning works correctly on both APFS and Linux ext4/xfs.
///
/// Returns the original full (logical) size so the caller can record it for
/// the extraction side to restore the sparse skeleton via `ftruncate`.
/// Returns `(logical_size, truncated_size)`.
fn sparse_copy_overlay(src: &Path, dst: &Path) -> std::io::Result<(u64, u64)> {
    let mut src_file = File::open(src)?;
    let logical_size = src_file.metadata()?.len();

    // Scan backwards to find the last non-zero byte (= safe truncation point).
    // On APFS, zero-fill regions are served from page cache without disk I/O,
    // so even scanning 8+ GiB of trailing zeros takes only ~100–200 ms.
    let truncated_size = find_last_data_byte(&mut src_file, logical_size)?;

    // Create destination as a sparse skeleton; keep the handle for writing.
    let mut dst_file = File::create(dst)?;
    // On Windows/NTFS, File::create makes a non-sparse file: set_len-ing to the
    // (large) truncated size and then writing a chunk at a high offset would
    // zero-fill/allocate the entire gap, ballooning a ~50 MB overlay to ~10 GiB
    // of real disk. Mark it sparse first so only written extents consume space —
    // matching the implicit sparse behavior of Unix filesystems.
    #[cfg(windows)]
    crate::extract::mark_file_sparse(&dst_file)?;
    dst_file.set_len(truncated_size)?;

    if truncated_size == 0 {
        return Ok((logical_size, 0));
    }

    // Forward copy: read [0, truncated_size) in 512 KiB chunks,
    // writing only non-zero chunks (zero chunks remain as holes).
    src_file.seek(SeekFrom::Start(0))?;
    let mut buf = vec![0u8; 512 * 1024];
    let mut offset: u64 = 0;

    while offset < truncated_size {
        let to_read = (truncated_size - offset).min(buf.len() as u64) as usize;
        let n = src_file.read(&mut buf[..to_read])?;
        if n == 0 {
            break;
        }
        let chunk = &buf[..n];
        if chunk.iter().any(|&b| b != 0) {
            dst_file.seek(SeekFrom::Start(offset))?;
            dst_file.write_all(chunk)?;
        }
        offset += n as u64;
    }

    Ok((logical_size, truncated_size))
}

/// Find the truncation point: offset of the last non-zero byte + 1.
///
/// Reads the file backwards in 1 MiB chunks until a non-zero byte is found.
/// Returns 0 if the entire file is zeros.
fn find_last_data_byte(file: &mut File, logical_size: u64) -> std::io::Result<u64> {
    if logical_size == 0 {
        return Ok(0);
    }

    const CHUNK: u64 = 1024 * 1024; // 1 MiB scan chunk
    let mut buf = vec![0u8; CHUNK as usize];
    let mut pos = logical_size;

    while pos > 0 {
        let chunk_start = pos.saturating_sub(CHUNK);
        let chunk_size = (pos - chunk_start) as usize;

        file.seek(SeekFrom::Start(chunk_start))?;
        let n = file.read(&mut buf[..chunk_size])?;
        if n == 0 {
            break;
        }

        // Scan backwards for the last non-zero byte in this chunk.
        for i in (0..n).rev() {
            if buf[i] != 0 {
                return Ok(chunk_start + i as u64 + 1);
            }
        }

        pos = chunk_start;
    }

    Ok(0) // Entire file is zeros
}

/// Decompress a zstd-compressed assets blob.
pub fn decompress_assets(compressed: &[u8], output_dir: &Path) -> Result<()> {
    fs::create_dir_all(output_dir)?;

    let decoder = zstd::stream::Decoder::new(compressed)
        .map_err(|e| PackError::Compression(e.to_string()))?;
    let mut archive = tar::Archive::new(decoder);

    archive
        .unpack(output_dir)
        .map_err(|e| PackError::Tar(e.to_string()))?;

    Ok(())
}

/// Decompress assets from a file.
pub fn decompress_assets_from_file(compressed_path: &Path, output_dir: &Path) -> Result<()> {
    fs::create_dir_all(output_dir)?;

    let file = File::open(compressed_path)?;
    let decoder =
        zstd::stream::Decoder::new(file).map_err(|e| PackError::Compression(e.to_string()))?;
    let mut archive = tar::Archive::new(decoder);

    archive
        .unpack(output_dir)
        .map_err(|e| PackError::Tar(e.to_string()))?;

    Ok(())
}

/// Calculate CRC32 checksum of data.
pub fn crc32(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}

/// Calculate CRC32 checksum of a file.
pub fn crc32_file(path: &Path) -> Result<u32> {
    let mut file = File::open(path)?;
    let mut hasher = crc32fast::Hasher::new();

    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    Ok(hasher.finalize())
}

/// Calculate CRC32 checksum of multiple sections of a file.
pub fn crc32_file_range(path: &Path, offset: u64, size: u64) -> Result<u32> {
    let mut file = File::open(path)?;
    crc32_reader_range(&mut file, offset, size)
}

/// CRC32 of `size` bytes from `offset` of an already-open reader, so a caller
/// that pins an artifact by descriptor verifies exactly the bytes it holds open
/// rather than whatever a path resolves to at that instant.
pub fn crc32_reader_range<R: std::io::Read + std::io::Seek>(
    file: &mut R,
    offset: u64,
    size: u64,
) -> Result<u32> {
    use std::io::SeekFrom;

    file.seek(SeekFrom::Start(offset))?;

    let mut hasher = crc32fast::Hasher::new();
    let mut remaining = size;
    let mut buf = [0u8; 64 * 1024];

    while remaining > 0 {
        let to_read = remaining.min(buf.len() as u64) as usize;
        let n = file.read(&mut buf[..to_read])?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        remaining -= n as u64;
    }

    Ok(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_to_filename_rejects_path_traversal() {
        // A valid hex digest is accepted.
        assert_eq!(
            digest_to_filename("sha256:abcdef012345").unwrap(),
            "abcdef012345.tar"
        );
        // Non-hex / traversal digests are rejected before becoming a path.
        for bad in [
            "sha256:../../../../etc/evil",
            "sha256:..%2f..%2fevil",
            "sha256:abc/def/ghij",
            "sha256:abcdefabcdeZ",
        ] {
            assert!(
                digest_to_filename(bad).is_err(),
                "should reject non-hex digest: {bad}"
            );
        }
    }

    #[test]
    fn test_find_last_data_byte_all_zero() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        fs::write(temp.path(), vec![0u8; 4096]).unwrap();
        let mut file = File::open(temp.path()).unwrap();
        assert_eq!(find_last_data_byte(&mut file, 4096).unwrap(), 0);
    }

    #[test]
    fn test_find_last_data_byte_trailing_zeros() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        let mut data = vec![0u8; 4100];
        data[99] = 0xAB; // non-zero at 99, then 4000 trailing zeros
        fs::write(temp.path(), &data).unwrap();
        let mut file = File::open(temp.path()).unwrap();
        assert_eq!(find_last_data_byte(&mut file, 4100).unwrap(), 100);
    }

    #[test]
    fn test_find_last_data_byte_nonzero_at_end() {
        // Boundary: no trailing zeros — function must return full length.
        let temp = tempfile::NamedTempFile::new().unwrap();
        let mut data = vec![0u8; 1024];
        data[1023] = 1;
        fs::write(temp.path(), &data).unwrap();
        let mut file = File::open(temp.path()).unwrap();
        assert_eq!(find_last_data_byte(&mut file, 1024).unwrap(), 1024);
    }

    #[test]
    fn test_sparse_copy_overlay_all_zero() {
        // All-zero source: truncated_size=0, early exit before forward copy.
        let temp_dir = tempfile::tempdir().unwrap();
        let src = temp_dir.path().join("src.raw");
        let dst = temp_dir.path().join("dst.raw");
        fs::write(&src, vec![0u8; 8192]).unwrap();

        let (logical, truncated) = sparse_copy_overlay(&src, &dst).unwrap();
        assert_eq!(logical, 8192);
        assert_eq!(truncated, 0);
        assert_eq!(fs::metadata(&dst).unwrap().len(), 0);
    }

    #[test]
    fn test_sparse_copy_overlay_trailing_zeros_and_interior_holes() {
        // Verifies: trailing zeros are stripped, sizes are returned, interior
        // holes (zero chunks in the forward pass) are preserved in the copy.
        let temp_dir = tempfile::tempdir().unwrap();
        let src = temp_dir.path().join("src.raw");
        let dst = temp_dir.path().join("dst.raw");

        let mut data = vec![0u8; 8192];
        data[0] = 0x01; // non-zero at start
        data[511] = 0xFF; // last non-zero byte; trailing 7680 bytes are zeros
        fs::write(&src, &data).unwrap();

        let (logical, truncated) = sparse_copy_overlay(&src, &dst).unwrap();
        assert_eq!(logical, 8192);
        assert_eq!(truncated, 512);

        let dst_data = fs::read(&dst).unwrap();
        assert_eq!(dst_data[0], 0x01);
        assert_eq!(dst_data[511], 0xFF);
        assert_eq!(dst_data[256], 0x00); // interior zero is preserved
    }

    #[test]
    fn vm_storage_template_preserves_logical_size_without_packing_the_tail() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("storage.raw");
        let mut file = File::create(&source).unwrap();
        file.write_all(b"docker-layer").unwrap();
        file.set_len(4 * 1024 * 1024).unwrap();

        let staging = temp.path().join("staging");
        let mut collector = AssetCollector::new(staging.clone()).unwrap();
        collector.add_vm_storage_template(&source).unwrap();
        let inventory = collector.inventory();
        let template = inventory.storage_template.as_ref().unwrap();

        assert_eq!(template.path, "storage.ext4");
        assert_eq!(inventory.storage_logical_size, Some(4 * 1024 * 1024));
        assert_eq!(
            fs::metadata(staging.join(&template.path)).unwrap().len(),
            template.size
        );
        assert!(template.size < 4 * 1024 * 1024);
        assert_eq!(
            fs::read(staging.join(&template.path)).unwrap(),
            b"docker-layer"
        );
    }

    #[test]
    fn test_crc32_basic() {
        let data = b"hello world";
        let checksum = crc32(data);
        assert_eq!(checksum, 0x0D4A_1185); // Known CRC32 value
    }

    #[test]
    fn test_crc32_empty() {
        let data = b"";
        let checksum = crc32(data);
        assert_eq!(checksum, 0); // CRC32 of empty data is 0
    }

    #[test]
    fn test_asset_collector_staging() {
        let temp_dir = tempfile::tempdir().unwrap();
        let staging = temp_dir.path().join("staging");

        let _collector = AssetCollector::new(staging.clone()).unwrap();

        // lib/ is only created when collect_libraries() is called
        assert!(!staging.join("lib").exists());
        assert!(staging.join("layers").exists());
    }

    #[test]
    fn collect_agent_rootfs_excludes_ready_markers() {
        // The agent-rootfs dir doubles as the host's per-boot readiness-marker
        // mount (`.smolvm-ready.<hash>`). Those markers must never be packed
        // into the guest image — and on a host that ran uid-isolated VMs they
        // can be foreign-owned/unreadable, which used to hard-fail the whole
        // pack ("tar error: Permission denied"). Verify they're skipped while
        // real rootfs content is preserved.
        let temp = tempfile::tempdir().unwrap();
        let rootfs = temp.path().join("rootfs");
        fs::create_dir_all(rootfs.join("bin")).unwrap();
        fs::create_dir_all(rootfs.join("etc")).unwrap();
        fs::write(rootfs.join("bin/sh"), b"#!/bin/sh\n").unwrap();
        fs::write(rootfs.join("etc/hostname"), b"vm\n").unwrap();
        fs::write(rootfs.join("init"), b"agent").unwrap();
        fs::write(
            rootfs.join(format!("{}.deadbeef", smolvm_protocol::AGENT_READY_MARKER)),
            b"1",
        )
        .unwrap();
        fs::write(
            rootfs.join(format!("{}.cafef00d", smolvm_protocol::AGENT_READY_MARKER)),
            b"1",
        )
        .unwrap();

        let staging = temp.path().join("staging");
        let mut collector = AssetCollector::new(staging.clone()).unwrap();
        collector.collect_agent_rootfs(&rootfs).unwrap();

        let tar_path = staging.join("agent-rootfs.tar");
        let names: Vec<String> = tar::Archive::new(File::open(&tar_path).unwrap())
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
            .collect();

        assert!(
            names.iter().any(|n| n.ends_with("bin/sh")),
            "real rootfs file missing from pack: {names:?}"
        );
        assert!(
            names.iter().any(|n| n.ends_with("etc/hostname")),
            "real rootfs file missing from pack: {names:?}"
        );
        assert!(
            names.iter().any(|n| n.ends_with("init")),
            "top-level agent binary missing from pack: {names:?}"
        );
        assert!(
            !names.iter().any(|n| n.contains(".smolvm-ready")),
            "readiness marker leaked into the pack: {names:?}"
        );
    }

    #[test]
    fn test_compression_roundtrip() {
        let temp_dir = tempfile::tempdir().unwrap();
        let staging = temp_dir.path().join("staging");
        let output = temp_dir.path().join("output");

        // Create a file in staging
        fs::create_dir_all(&staging).unwrap();
        let test_file = staging.join("test.txt");
        fs::write(&test_file, b"hello world").unwrap();

        // Create collector and compress
        let collector = AssetCollector::new(staging).unwrap();
        let compressed = temp_dir.path().join("assets.tar.zst");
        collector.compress(&compressed, false).unwrap();

        // Decompress and verify
        decompress_assets_from_file(&compressed, &output).unwrap();
        let restored = output.join("test.txt");
        assert!(restored.exists());
        assert_eq!(fs::read_to_string(&restored).unwrap(), "hello world");
    }

    #[test]
    fn patched_files_pack_patched_bytes_and_keep_holes_and_source() {
        let temp_dir = tempfile::tempdir().unwrap();
        let staging = temp_dir.path().join("staging");
        fs::create_dir_all(staging.join("checkpoint/disks/storage")).unwrap();
        fs::write(staging.join("checkpoint/disks/storage/0"), b"top").unwrap();
        // Data, a 4 MiB hole, data, and a trailing hole.
        let source = temp_dir.path().join("layer");
        let mut file = File::create(&source).unwrap();
        file.write_all(&vec![7_u8; 65536]).unwrap();
        file.seek(SeekFrom::Start(4 << 20)).unwrap();
        file.write_all(&vec![9_u8; 65536]).unwrap();
        file.set_len(8 << 20).unwrap();
        drop(file);
        let original = fs::read(&source).unwrap();
        let mut expected = original.clone();
        expected[100..104].copy_from_slice(b"name");
        expected[(4 << 20) + 10] = 1;

        let mut collector = AssetCollector::new(staging.clone()).unwrap();
        let patched = |path: &str| PatchedFile {
            archive_path: path.to_string(),
            source: File::open(&source).unwrap(),
            mode: 0o600,
            patches: vec![(100, b"name".to_vec()), ((4 << 20) + 10, vec![1])],
        };
        collector
            .add_patched_file(patched("checkpoint/disks/storage/1"))
            .unwrap();
        // Paths outside `checkpoint/`, already staged, or repeated are refused.
        for path in [
            "other/1",
            "checkpoint/../x",
            "checkpoint/disks/storage/0",
            "checkpoint/disks/storage/1",
        ] {
            assert!(collector.add_patched_file(patched(path)).is_err(), "{path}");
        }
        let compressed = temp_dir.path().join("assets.tar.zst");
        collector.compress(&compressed, false).unwrap();
        assert_eq!(fs::read(&source).unwrap(), original);

        let output = temp_dir.path().join("output");
        decompress_assets_from_file(&compressed, &output).unwrap();
        let restored = output.join("checkpoint/disks/storage/1");
        assert_eq!(fs::read(&restored).unwrap(), expected);
        assert_eq!(
            fs::read(output.join("checkpoint/disks/storage/0")).unwrap(),
            b"top"
        );
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;
            let allocated = fs::metadata(&restored).unwrap().blocks() * 512;
            assert!(allocated < 1 << 20, "holes were filled: {allocated} bytes");
        }
    }

    // macOS packs checkpoints through `append_macos_sparse_file` instead.
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn checkpoint_ram_is_packed_as_aligned_nonzero_blocks() {
        let temp_dir = tempfile::tempdir().unwrap();
        let staging = temp_dir.path().join("staging");
        fs::create_dir_all(staging.join("checkpoint")).unwrap();
        // Scattered small pages, and a megabyte of zeros written as data.
        let logical = 8_u64 << 20;
        let mut memory = File::create(staging.join("checkpoint/memory.bin")).unwrap();
        memory.set_len(logical).unwrap();
        let mut expected = vec![0_u8; logical as usize];
        for (index, offset) in [4096_u64, 12288, 70_000, 3 << 20, (5 << 20) + 100]
            .into_iter()
            .enumerate()
        {
            memory.seek(SeekFrom::Start(offset)).unwrap();
            memory.write_all(&[index as u8 + 1; 4096]).unwrap();
            expected[offset as usize..offset as usize + 4096].fill(index as u8 + 1);
        }
        memory.seek(SeekFrom::Start(6 << 20)).unwrap();
        memory.write_all(&vec![0_u8; 1 << 20]).unwrap();
        drop(memory);

        let collector = AssetCollector::new(staging).unwrap();
        let compressed = temp_dir.path().join("assets.tar.zst");
        collector.compress(&compressed, false).unwrap();
        let decoder = zstd::stream::read::Decoder::new(File::open(&compressed).unwrap()).unwrap();
        let mut archive = tar::Archive::new(decoder);
        let mut entries = archive.entries().unwrap();
        let mut entry = loop {
            let entry = entries.next().unwrap().unwrap();
            if entry.path().unwrap() == Path::new("checkpoint/memory.bin") {
                break entry;
            }
        };
        let gnu = entry.header().as_gnu().unwrap();
        let map: Vec<_> = gnu
            .sparse
            .iter()
            .map(|s| (s.offset().unwrap(), s.length().unwrap()))
            .collect();
        // Blocks [0, 128 KiB), [3 MiB, +64 KiB), [5 MiB, +64 KiB): the zeros
        // written as data are a hole.
        assert_eq!(
            map,
            [
                (0, 131_072),
                (3 << 20, 65536),
                (5 << 20, 65536),
                (logical, 0)
            ]
        );
        let mut restored = Vec::new();
        entry.read_to_end(&mut restored).unwrap();
        assert_eq!(restored, expected);
    }

    #[test]
    fn aligned_ranges_cover_and_merge() {
        assert_eq!(
            align_ranges(&[(100, 10), (65_000, 1000), (200_000, 5)], 65536, 1 << 20),
            [(0, 131_072), (196_608, 65536)]
        );
        assert_eq!(
            align_ranges(&[(70_000, 10)], 65536, 70_010),
            [(65536, 4474)]
        );
        assert!(align_ranges(&[(0, 0)], 65536, 10).is_empty());
    }

    #[test]
    fn patches_outside_the_file_are_refused_and_merge_with_data() {
        assert!(ranges_with_patches(Vec::new(), &[(10, vec![1; 4])], 12).is_err());
        assert!(ranges_with_patches(Vec::new(), &[(0, Vec::new())], 12).is_err());
        assert_eq!(
            ranges_with_patches(
                vec![(0, 4096), (8192, 4096)],
                &[(4000, vec![1; 200])],
                1 << 20
            )
            .unwrap(),
            [(0, 4608), (8192, 4096)]
        );
        assert_eq!(
            ranges_with_patches(vec![(4096, 4096)], &[(9000, vec![1; 4])], 9100).unwrap(),
            [(4096, 4096), (8704, 396)]
        );
    }

    #[test]
    fn compression_worker_budget_is_bounded() {
        assert_eq!(compression_workers(0), 0);
        assert_eq!(compression_workers(1), 0);
        assert_eq!(compression_workers(2), 2);
        assert_eq!(compression_workers(4), 4);
        assert_eq!(compression_workers(8), 4);
        assert_eq!(compression_workers(usize::MAX), 4);
    }

    #[test]
    fn compression_slots_keep_workers_within_the_host() {
        assert_eq!(compression_slots(0), 1);
        assert_eq!(compression_slots(1), 1);
        assert_eq!(compression_slots(4), 1);
        assert_eq!(compression_slots(7), 1);
        assert_eq!(compression_slots(8), 2);
        assert_eq!(compression_slots(12), 3);
        assert_eq!(compression_slots(64), 16);
    }

    #[test]
    fn compression_admission_runs_up_to_its_slots_at_once() {
        use std::time::{Duration, Instant};

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().to_path_buf();
        // Each permit is its own open file, as in separate threads or processes.
        let mut held: Vec<_> = (0..3)
            .map(|_| compression_permit(&root, 3).unwrap())
            .collect();
        let (admitted, wait) = std::sync::mpsc::channel();
        let waiter = std::thread::spawn(move || {
            let permit = compression_permit(&root, 3).unwrap();
            admitted.send(()).unwrap();
            drop(permit);
        });
        assert!(wait.recv_timeout(Duration::from_millis(150)).is_err());
        let released = Instant::now();
        drop(held.remove(1));
        wait.recv_timeout(Duration::from_secs(10))
            .expect("waiter stayed blocked after a slot was released");
        assert!(released.elapsed() < Duration::from_secs(1));
        waiter.join().unwrap();
    }

    #[test]
    #[ignore = "subprocess helper for compression_admission_is_cross_process"]
    fn compression_admission_child() {
        let Some(root) = std::env::var_os("SMOLVM_TEST_COMPRESSION_ADMISSION") else {
            return;
        };
        let root = PathBuf::from(root);
        fs::write(root.join("ready"), b"ready").unwrap();
        let _permit = compression_permit(&root, 1).unwrap();
        fs::write(root.join("admitted"), b"admitted").unwrap();
    }

    #[test]
    fn compression_admission_is_cross_process() {
        use std::time::{Duration, Instant};

        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        let temp = tempfile::tempdir().unwrap();
        let permit = compression_permit(temp.path(), 1).unwrap();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "assets::tests::compression_admission_child",
                    "--ignored",
                ])
                .env("SMOLVM_TEST_COMPRESSION_ADMISSION", temp.path())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        while !temp.path().join("ready").exists() {
            assert!(Instant::now() < deadline, "child did not reach admission");
            assert!(child.0.try_wait().unwrap().is_none());
            std::thread::sleep(Duration::from_millis(5));
        }
        let blocked_until = Instant::now() + Duration::from_millis(100);
        while Instant::now() < blocked_until {
            assert!(!temp.path().join("admitted").exists());
            assert!(child.0.try_wait().unwrap().is_none());
            std::thread::sleep(Duration::from_millis(5));
        }
        drop(permit);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(
                Instant::now() < deadline,
                "child stayed blocked after release"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(temp.path().join("admitted").exists());
        // The inode remains available for later processes; it is not a stale
        // ownership marker and does not need cleanup after the owner exits.
        assert!(temp.path().join("asset-compression.lock").exists());
        drop(compression_permit(temp.path(), 1).unwrap());
    }

    #[test]
    fn compression_error_releases_admission() {
        let temp = tempfile::tempdir().unwrap();
        let collector = AssetCollector::new(temp.path().join("staging")).unwrap();
        // Opening a directory as the output fails after admission is acquired.
        assert!(collector.compress(temp.path(), false).is_err());
        let output = temp.path().join("retry.zst");
        assert!(collector.compress(&output, false).unwrap() > 0);
    }

    #[test]
    fn concurrent_large_asset_exports_roundtrip_independently() {
        let barrier = std::sync::Barrier::new(4);
        std::thread::scope(|scope| {
            for seed in 0..4u8 {
                let barrier = &barrier;
                scope.spawn(move || {
                    let temp = tempfile::tempdir().unwrap();
                    let staging = temp.path().join("staging");
                    let collector = AssetCollector::new(staging.clone()).unwrap();
                    // Larger than a zstd job, with a different payload per caller.
                    let payload: Vec<u8> = (0..12 * 1024 * 1024usize)
                        .map(|i| (i.wrapping_mul(31) ^ (i >> 9)) as u8 ^ seed)
                        .collect();
                    fs::write(staging.join("payload"), &payload).unwrap();
                    fs::create_dir(staging.join("lib")).unwrap();
                    fs::write(staging.join("lib/excluded"), b"excluded").unwrap();
                    barrier.wait();
                    let compressed = temp.path().join("assets.zst");
                    collector.compress(&compressed, true).unwrap();
                    let output = temp.path().join("restored");
                    decompress_assets_from_file(&compressed, &output).unwrap();
                    assert_eq!(fs::read(output.join("payload")).unwrap(), payload);
                    assert!(!output.join("lib").exists());
                });
            }
        });
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn compression_preserves_sparse_files_on_macos() {
        use std::os::unix::fs::MetadataExt;

        const LOGICAL_SIZE: u64 = 64 * 1024 * 1024;
        let temp_dir = tempfile::tempdir().unwrap();
        let staging = temp_dir.path().join("staging");
        let collector = AssetCollector::new(staging.clone()).unwrap();
        let checkpoint = staging.join("checkpoint");
        fs::create_dir_all(&checkpoint).unwrap();
        let memory = checkpoint.join("memory.bin");
        let mut file = File::create(&memory).unwrap();
        file.set_len(LOGICAL_SIZE).unwrap();
        file.seek(SeekFrom::Start(4096)).unwrap();
        file.write_all(&[0xA5; 4096]).unwrap();
        file.seek(SeekFrom::Start(32 * 1024 * 1024)).unwrap();
        file.write_all(&[0x5A; 4096]).unwrap();
        file.sync_all().unwrap();

        let compressed = temp_dir.path().join("assets.tar.zst");
        collector.compress(&compressed, false).unwrap();
        assert!(
            fs::metadata(&compressed).unwrap().len() < 1024 * 1024,
            "sparse holes were expanded into the compressed archive"
        );

        let output = temp_dir.path().join("output");
        decompress_assets_from_file(&compressed, &output).unwrap();
        let restored = output.join("checkpoint/memory.bin");
        let metadata = fs::metadata(&restored).unwrap();
        assert_eq!(metadata.len(), LOGICAL_SIZE);
        assert!(metadata.blocks() * 512 < LOGICAL_SIZE / 4);
        let mut restored = File::open(restored).unwrap();
        let mut page = [0_u8; 4096];
        restored.seek(SeekFrom::Start(4096)).unwrap();
        restored.read_exact(&mut page).unwrap();
        assert_eq!(page, [0xA5; 4096]);
        restored.seek(SeekFrom::Start(32 * 1024 * 1024)).unwrap();
        restored.read_exact(&mut page).unwrap();
        assert_eq!(page, [0x5A; 4096]);
        restored.seek(SeekFrom::End(-1)).unwrap();
        restored.read_exact(&mut page[..1]).unwrap();
        assert_eq!(page[0], 0);
    }
}

/// Expanding a compressed disk template back into a sparse file.
#[cfg(test)]
mod template_expand_tests {
    use super::*;

    /// Build a template-shaped file: a little real data, a large hole, a tail.
    /// Sized at 64 MiB: APFS does not report holes for files much smaller than
    /// this regardless of how they are written, so a smaller fixture would fail
    /// the sparseness assertion even for a correct implementation.
    fn template_bytes() -> Vec<u8> {
        let mut v = vec![0u8; 64 * 1024 * 1024];
        v[..4096].copy_from_slice(&[0xABu8; 4096]);
        let tail = v.len() - 16;
        v[tail..].copy_from_slice(&[0xCDu8; 16]);
        v
    }

    fn compress_to(path: &Path, data: &[u8]) {
        let out = File::create(path).expect("create zst");
        let mut enc = zstd::Encoder::new(out, 3).expect("encoder");
        enc.write_all(data).expect("write");
        enc.finish().expect("finish");
    }

    #[test]
    fn expansion_reproduces_the_original_bytes() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let src = tmp.path().join("t.ext4.zst");
        let dest = tmp.path().join("t.ext4");
        let data = template_bytes();
        compress_to(&src, &data);

        materialize_template(&src, &dest).expect("materialize");

        assert_eq!(fs::read(&dest).expect("read"), data);
    }

    /// The point of the exercise: the hole must not be written out.
    #[cfg(unix)]
    #[test]
    fn the_hole_is_left_unallocated() {
        use std::os::unix::fs::MetadataExt;
        let tmp = tempfile::tempdir().expect("tempdir");
        let src = tmp.path().join("t.ext4.zst");
        let dest = tmp.path().join("t.ext4");
        let data = template_bytes();
        compress_to(&src, &data);

        materialize_template(&src, &dest).expect("materialize");

        let meta = fs::metadata(&dest).expect("stat");
        assert_eq!(meta.len(), data.len() as u64, "logical size must match");
        let dense = data.len() as u64 / 512;
        assert!(
            meta.blocks() < dense / 4,
            "expected a sparse file, got {} blocks vs {dense} if dense",
            meta.blocks()
        );
    }

    /// The same guarantee on Windows/NTFS, where holes exist only after the file
    /// is explicitly marked sparse — the plain seek/set_len path leaves it dense.
    /// `GetCompressedFileSizeW` reports the bytes actually allocated on disk, so a
    /// sparse expansion reads far below the logical size while a dense one matches
    /// it. Cross-compilation cannot exercise this; it needs a native Windows run.
    #[cfg(windows)]
    #[test]
    fn the_hole_is_left_unallocated() {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::GetCompressedFileSizeW;

        let tmp = tempfile::tempdir().expect("tempdir");
        let src = tmp.path().join("t.ext4.zst");
        let dest = tmp.path().join("t.ext4");
        let data = template_bytes();
        compress_to(&src, &data);

        materialize_template(&src, &dest).expect("materialize");

        assert_eq!(
            fs::metadata(&dest).expect("stat").len(),
            data.len() as u64,
            "logical size must match"
        );

        let wide: Vec<u16> = dest.as_os_str().encode_wide().chain([0]).collect();
        let mut high: u32 = 0;
        // SAFETY: `wide` is a valid NUL-terminated path; `high` is a valid out ptr.
        let low = unsafe { GetCompressedFileSizeW(wide.as_ptr(), &mut high) };
        assert_ne!(low, u32::MAX, "GetCompressedFileSizeW failed");
        let on_disk = ((high as u64) << 32) | low as u64;
        assert!(
            on_disk < data.len() as u64 / 4,
            "expected a sparse file, got {on_disk} bytes on disk vs {} logical",
            data.len()
        );
    }

    /// A file that is entirely zeros still has to come back at full length.
    #[test]
    fn an_all_zero_template_keeps_its_length() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let src = tmp.path().join("z.ext4.zst");
        let dest = tmp.path().join("z.ext4");
        let data = vec![0u8; 4 * 1024 * 1024];
        compress_to(&src, &data);

        materialize_template(&src, &dest).expect("materialize");

        assert_eq!(fs::metadata(&dest).expect("stat").len(), data.len() as u64);
        assert!(fs::read(&dest).expect("read").iter().all(|&b| b == 0));
    }

    /// End-to-end discovery: a `.zst` beside the executable is found and
    /// expanded, exercising the same `current_exe()` branch a real install uses.
    /// The filename is unique so parallel tests cannot collide, and both the
    /// archive and its expansion are removed afterwards.
    #[test]
    fn a_zst_beside_the_executable_is_discovered_and_expanded() {
        let exe = std::env::current_exe().expect("current_exe");
        let dir = exe.parent().expect("exe dir");
        let name = format!("discovery-probe-{}.ext4", std::process::id());
        let zst = dir.join(format!("{name}.zst"));
        let expanded = dir.join(&name);
        let _ = fs::remove_file(&zst);
        let _ = fs::remove_file(&expanded);

        let data = template_bytes();
        compress_to(&zst, &data);

        let found = find_existing_template(&name);

        let cleanup = || {
            let _ = fs::remove_file(&zst);
            let _ = fs::remove_file(&expanded);
        };
        let Some(path) = found else {
            cleanup();
            panic!("compressed template beside the executable was not found");
        };
        let got = fs::read(&path).expect("read expanded");
        cleanup();
        assert_eq!(got, data, "expanded template must match the original");
    }

    /// A truncated archive must not leave a half-written file behind, or the
    /// plain-file lookup would treat the debris as a valid template.
    #[test]
    fn a_corrupt_archive_leaves_no_partial_file() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let src = tmp.path().join("bad.ext4.zst");
        let dest = tmp.path().join("bad.ext4");
        let data = template_bytes();
        compress_to(&src, &data);
        // Lop off the end so decompression fails partway.
        let whole = fs::read(&src).expect("read zst");
        fs::write(&src, &whole[..whole.len() / 2]).expect("truncate");

        assert!(materialize_template(&src, &dest).is_err());
        assert!(!dest.exists(), "no template should be left behind");
        assert!(
            !dest.with_extension("partial").exists(),
            "no scratch file should be left behind"
        );
    }
}
