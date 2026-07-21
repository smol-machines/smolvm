//! Asset extraction for packed binaries.
//!
//! Provides shared extraction logic used by both the main `smolvm` binary
//! (sidecar mode via `runpack`) and the standalone stub executable.

use crate::format::{PackFooter, SIDECAR_EXTENSION};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;

/// Mark an open file as sparse (Windows/NTFS) so a later `set_len` to a large
/// size — or writing chunks at high offsets after such a `set_len` — doesn't
/// allocate every intermediate block, ballooning a sparse disk image (overlay,
/// storage) to its full logical size on disk. Unix filesystems are sparse by
/// default and never call this.
///
/// `smolvm-pack` cannot depend on the main crate, so this mirrors the FSCTL
/// approach in the main crate's `src/disk_utils.rs::mark_file_sparse`.
#[cfg(windows)]
pub(crate) fn mark_file_sparse(file: &fs::File) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::IO::DeviceIoControl;
    // FSCTL_SET_SPARSE control code (winioctl.h).
    const FSCTL_SET_SPARSE: u32 = 0x000900C4;
    let mut returned: u32 = 0;
    // SAFETY: `file` is a valid open handle; FSCTL_SET_SPARSE uses no in/out buffers.
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            FSCTL_SET_SPARSE,
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Acquire a blocking, exclusive advisory lock on an open lock file.
///
/// Unix uses `flock(LOCK_EX)`; Windows uses `LockFileEx(LOCKFILE_EXCLUSIVE_LOCK)`
/// on the file handle. Without the Windows path, concurrent first-run
/// extractions of the same checksum race. The lock is released when the OS
/// closes the handle (i.e. when the `File` is dropped).
#[cfg(unix)]
fn lock_file_exclusive(lock_file: &fs::File) -> std::io::Result<()> {
    let ret = unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
fn lock_file_exclusive(lock_file: &fs::File) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{LockFileEx, LOCKFILE_EXCLUSIVE_LOCK};
    use windows_sys::Win32::System::IO::OVERLAPPED;

    let handle = lock_file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    // Lock the whole (empty) file: offset 0, maximum byte range.
    let ret = unsafe {
        LockFileEx(
            handle,
            LOCKFILE_EXCLUSIVE_LOCK,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    };
    if ret == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Set a Unix file mode on `path`, ignoring errors. No-op on non-Unix targets
/// (Windows has no POSIX mode bits).
#[inline]
fn set_mode(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
}

/// Files larger than this threshold are extracted with a sparse write
/// (ftruncate skeleton + pwrite only non-zero 64 KiB chunks) rather than a
/// dense sequential write.  Chosen to match typical overlay disk sizes while
/// staying well above any regular asset file.
const SPARSE_WRITE_THRESHOLD: u64 = 256 * 1024 * 1024; // 256 MiB

/// Extract a single tar entry as a sparse file.
///
/// Creates the destination with `ftruncate(entry_size)` so the OS allocates
/// no disk blocks for the zero regions, then streams `entry` in 64 KiB
/// chunks and `pwrite`s only the non-zero ones at their correct offsets.
///
/// This keeps a 10 GiB overlay disk (with ~50 MB of real data) from
/// materialising as a dense file during sidecar extraction.
fn unpack_sparse<R: Read>(
    entry: &mut tar::Entry<R>,
    path: &Path,
    entry_size: u64,
    mode: u32,
    real_dest: &Path,
) -> std::io::Result<()> {
    // Before creating any directory or opening the file, verify that the real
    // (symlink-resolved) parent of `path` stays within `real_dest`. A prior
    // tar entry may have placed a symlink parent component (e.g. `foo -> /`)
    // that `create_dir_all`/`open` would traverse OUT of the extraction root,
    // writing an attacker-controlled host file as root. `O_NOFOLLOW` below only
    // guards the FINAL path component, not an escaping parent — this closes
    // that gap. (The dense write path gets the same guarantee from the tar
    // crate's `validate_inside_dst`, which the sparse path bypasses.)
    verify_parent_within_dest(path, real_dest)?;

    // Ensure the parent directory exists (mirrors what entry.unpack_in does).
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Reject symlinks and unexpected directories at the destination.
    // A prior tar entry may have placed an intra-dest relative symlink at this
    // path; File::create would follow it, redirecting writes to the symlink
    // target instead of the intended path.
    match path.symlink_metadata() {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unpack_sparse: symlink at destination: {}", path.display()),
            ));
        }
        Ok(meta) if meta.file_type().is_dir() => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "unpack_sparse: directory at destination: {}",
                    path.display()
                ),
            ));
        }
        Ok(_) => {
            // Regular file: remove it so create_new (O_CREAT|O_EXCL) succeeds.
            // This handles idempotent re-extraction without silently overwriting.
            fs::remove_file(path)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }

    // Open with O_CREAT|O_EXCL|O_NOFOLLOW: rejects any symlink placed in the
    // TOCTOU window between the check above and the open (defense in depth).
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?
    };
    #[cfg(not(unix))]
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;

    // On Windows/NTFS the file is dense by default: set_len to the (large)
    // logical size and pwriting non-zero chunks at high offsets would allocate
    // every hole, materialising a 10 GiB overlay even though only ~50 MB is
    // real data. Mark it sparse first.
    #[cfg(windows)]
    mark_file_sparse(&file)?;

    // ftruncate: on APFS and ext4 this allocates zero disk blocks for the
    // hole regions — only written bytes consume real space.
    file.set_len(entry_size)?;

    let mut offset: u64 = 0;
    let mut buf = vec![0u8; 64 * 1024];

    loop {
        let n = entry.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let chunk = &buf[..n];
        if chunk.iter().any(|&b| b != 0) {
            file.seek(SeekFrom::Start(offset))?;
            file.write_all(chunk)?;
        }
        offset += n as u64;
    }

    // Only file mode is restored, not timestamps, uid/gid, or xattrs.
    // unpack_sparse applies to large cache assets (overlay disks, storage
    // images) extracted to a host-local cache directory; the extra metadata
    // does not affect functionality for those assets.
    //
    // Mask to the low permission bits (`& 0o777`) so a hostile header can't
    // preserve setuid/setgid/sticky bits on a host-extracted file — mirroring
    // the dense path, which never carries those bits through.
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o777))?;
    #[cfg(not(unix))]
    let _ = mode;

    Ok(())
}

/// Verify that the real (symlink-resolved) parent directory of `path` stays
/// within `real_dest`.
///
/// `canonicalize` resolves every symlink component, so if a prior tar entry
/// planted a symlink parent (e.g. `foo -> /`) that would let a later write
/// escape the extraction root, the deepest existing ancestor resolves to a
/// path outside `real_dest` and we reject before any directory is created or
/// file opened. `real_dest` must itself be a canonicalized path (so the
/// `starts_with` comparison is apples-to-apples, e.g. macOS `/tmp` →
/// `/private/tmp`).
fn verify_parent_within_dest(path: &Path, real_dest: &Path) -> std::io::Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    // Walk up until we hit a component that already exists on disk; canonicalize
    // it (following all symlinks) and require it to be inside real_dest.
    for ancestor in parent.ancestors() {
        match ancestor.canonicalize() {
            Ok(real) => {
                if real.starts_with(real_dest) {
                    return Ok(());
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "resolved parent '{}' of '{}' escapes destination '{}'",
                        real.display(),
                        path.display(),
                        real_dest.display()
                    ),
                ));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Safely unpack a tar archive, rejecting symlinks, hardlinks, and entries
/// that resolve outside `dest`.
///
/// The standard `tar::Archive::unpack()` strips `..` components but does
/// **not** reject symlinks. A crafted archive could create
/// `lib/libkrun.dylib → /tmp/evil.so`, and subsequent `dlopen()` would
/// load the attacker's library. This function rejects any entry that is
/// not a regular file or directory.
fn safe_unpack<R: Read>(archive: &mut tar::Archive<R>, dest: &Path) -> std::io::Result<()> {
    safe_unpack_with_limits(archive, dest, &SafeUnpackLimits::from_env())
}

/// Tunable resource ceilings and sparse-write threshold for [`safe_unpack`].
/// Extracted into a struct so tests can inject small values (exercising the
/// sparse-write path and the cap-rejection paths) without mutating process-wide
/// env vars, which would race with other concurrently-running tests.
#[derive(Clone, Copy)]
struct SafeUnpackLimits {
    /// Max number of tar entries before erroring (inode-flood guard).
    max_entries: u64,
    /// Max total apparent (header-declared) bytes before erroring
    /// (disk-exhaustion / decompression-bomb guard).
    max_total_bytes: u64,
    /// Regular files with a header size >= this use the sparse-write path.
    sparse_threshold: u64,
}

impl SafeUnpackLimits {
    fn from_env() -> Self {
        Self {
            max_entries: max_extract_entries(),
            max_total_bytes: max_extract_total_bytes(),
            sparse_threshold: SPARSE_WRITE_THRESHOLD,
        }
    }
}

fn safe_unpack_with_limits<R: Read>(
    archive: &mut tar::Archive<R>,
    dest: &Path,
    limits: &SafeUnpackLimits,
) -> std::io::Result<()> {
    // Use `normalize_path` (not `canonicalize`) for the containment base so it
    // matches the per-entry `normalized` paths, which are built from this same
    // plain `dest`. On Windows `canonicalize` returns a `\\?\`-verbatim path
    // while the entry paths stay plain, so `starts_with` would reject every
    // entry; `normalize_path` (which still resolves `..`, preserving the
    // traversal defense) keeps both sides in the same form on all platforms.
    let canonical_dest = normalize_path(dest);

    // Real (symlink-resolved) destination, used only for the sparse-write
    // parent-escape check. `dest` exists by the time we get here (callers
    // `create_dir_all` it first), so canonicalize succeeds; fall back to the
    // normalized form if not. Kept separate from `canonical_dest` because the
    // per-entry containment check compares against plain-joined paths.
    let real_dest = dest
        .canonicalize()
        .unwrap_or_else(|_| canonical_dest.clone());

    // Bound total work so a hostile layer can't exhaust host disk/inodes across
    // co-tenants (decompression bomb / entry flood). Counts apparent (header)
    // sizes and entries; both have generous finite ceilings, overridable via
    // env for constrained hosts / tests.
    let max_entries = limits.max_entries;
    let max_total_bytes = limits.max_total_bytes;
    let mut entry_count: u64 = 0;
    let mut total_bytes: u64 = 0;

    // Track directories with restrictive permissions. We extract all entries
    // with directories temporarily set to 0o755, then apply final permissions
    // after all children are written. This matches GNU tar / bsdtar behavior
    // and prevents extraction failures when a read-only directory appears
    // before its children in the tar stream (e.g., Fedora's mode-555
    // /usr/lib64/pm-utils/*.d directories).
    let mut deferred_dir_modes: Vec<(PathBuf, u32)> = Vec::new();

    for entry_result in archive.entries()? {
        let mut entry = entry_result?;
        let entry_type = entry.header().entry_type();
        let entry_path = entry.path()?.to_path_buf();

        // Enforce the entry-count and total-bytes ceilings (Fix 3): reject an
        // archive that would flood inodes or exhaust disk before we write it.
        entry_count += 1;
        if entry_count > max_entries {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("tar archive exceeds max entry count ({max_entries})"),
            ));
        }
        total_bytes = total_bytes.saturating_add(entry.header().size().unwrap_or(0));
        if total_bytes > max_total_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("tar archive exceeds max total size ({max_total_bytes} bytes)"),
            ));
        }

        match entry_type {
            tar::EntryType::Regular
            | tar::EntryType::GNUSparse
            | tar::EntryType::Directory
            | tar::EntryType::Continuous => {}
            // GNU/PAX extension headers are metadata for the next entry.
            // The tar crate normally consumes them internally, but some
            // archives surface them as explicit entries. Skip them.
            tar::EntryType::GNULongName
            | tar::EntryType::GNULongLink
            | tar::EntryType::XGlobalHeader
            | tar::EntryType::XHeader => {
                continue;
            }
            tar::EntryType::Symlink => {
                // Allow symlinks but validate the target stays within dest.
                if let Some(link_target) = entry.link_name()? {
                    let link_target = link_target.to_path_buf();
                    // tar targets use Unix semantics: an absolute target starts
                    // with '/'. `Path::is_absolute` is false for those on Windows
                    // (no drive), and `Path::join` would then treat the leading
                    // slash as a root that wipes `dest`, so detect it by string.
                    let target_str = link_target.to_string_lossy();
                    // Resolve relative symlinks against the entry's parent dir
                    let resolved = if target_str.starts_with('/') {
                        // Absolute symlinks: jail to dest (e.g., /lib/foo → dest/lib/foo)
                        dest.join(target_str.trim_start_matches('/'))
                    } else {
                        let parent = entry_path.parent().unwrap_or(Path::new(""));
                        dest.join(parent).join(&link_target)
                    };
                    // Normalize the path by resolving .. components
                    let normalized = normalize_path(&resolved);
                    if !normalized.starts_with(&canonical_dest) {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!(
                                "tar symlink '{}' -> '{}' escapes destination directory",
                                entry_path.display(),
                                link_target.display()
                            ),
                        ));
                    }
                    // Root-cause guard (Fix 1b): reject an ABSOLUTE symlink that
                    // resolves to the destination ROOT itself (e.g. `foo -> /`,
                    // `x -> /..`). The jailed check above passes these (they
                    // "stay within dest" only because the jail rewrite collapses
                    // them onto dest), but on disk the symlink is created with
                    // its LITERAL target, turning `foo` into an alias for the
                    // real filesystem root — the exact primitive a later
                    // `foo/etc/...` entry uses to escape. A legitimate absolute
                    // symlink points to a sub-path (`/usr/lib/y`), never at the
                    // root, so this preserves in-image absolute links.
                    if target_str.starts_with('/') && normalized == canonical_dest {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!(
                                "tar symlink '{}' -> '{}' aliases the destination root",
                                entry_path.display(),
                                link_target.display()
                            ),
                        ));
                    }
                }
            }
            tar::EntryType::Link => {
                // Allow hardlinks but validate the target stays within dest.
                if let Some(link_target) = entry.link_name()? {
                    // Same Unix-absolute handling as symlinks above.
                    let target_str = link_target.to_string_lossy();
                    let full_target = if target_str.starts_with('/') {
                        dest.join(target_str.trim_start_matches('/'))
                    } else {
                        dest.join(link_target.as_ref())
                    };
                    let normalized = normalize_path(&full_target);
                    if !normalized.starts_with(&canonical_dest) {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!(
                                "tar hardlink '{}' escapes destination directory",
                                entry_path.display()
                            ),
                        ));
                    }
                    // Skip hardlinks whose target was skipped (e.g., overlayfs
                    // whiteout char devices). The target doesn't exist on disk
                    // so creating the hardlink would fail.
                    if !normalized.exists() {
                        continue;
                    }
                }
            }
            tar::EntryType::Char | tar::EntryType::Block | tar::EntryType::Fifo => {
                // Device nodes and FIFOs appear in overlayfs upper-layer
                // exports (e.g., whiteout char devices from package upgrades,
                // named pipes from certain RPM scriptlets). These cannot be
                // created without root on macOS and aren't needed on the
                // host — skip them.
                continue;
            }
            _other => {
                // Unknown or unsupported entry types (sockets, vendor
                // extensions, future tar formats). Skip rather than fail —
                // the packed image runs inside a Linux VM where the agent
                // rootfs provides these files; missing non-regular entries
                // on the host extraction side don't affect functionality.
                continue;
            }
        }

        // Validate that the unpacked path stays within dest.
        let full_path = dest.join(&entry_path);
        let normalized = normalize_path(&full_path);
        if !normalized.starts_with(&canonical_dest) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "tar entry '{}' escapes destination directory",
                    entry_path.display()
                ),
            ));
        }

        // Ensure parent directories are writable before extracting any entry.
        // OCI layer tars may set restrictive directory modes (e.g., dr-xr-xr-x)
        // before child entries, which prevents creating files or subdirectories.
        if let Some(parent) = full_path.parent() {
            if parent.is_dir() {
                set_mode(parent, 0o755);
            }
        }

        // Save the tar's intended directory mode for deferred application.
        if entry_type == tar::EntryType::Directory {
            let mode = entry.header().mode().unwrap_or(0o755);
            if mode & 0o200 == 0 {
                deferred_dir_modes.push((full_path.clone(), mode));
            }
        }

        let is_regular =
            entry_type == tar::EntryType::Regular || entry_type == tar::EntryType::GNUSparse;

        // For large regular files use a sparse write: ftruncate creates the
        // hole skeleton, then we only pwrite non-zero 64 KiB chunks.  This
        // prevents 10 GiB overlay disks from materialising as dense files on
        // disk and causing ENOSPC or slow extraction.
        if is_regular && entry.header().size().unwrap_or(0) >= limits.sparse_threshold {
            let entry_size = entry.header().size()?;
            let mode = entry.header().mode().unwrap_or(0o644);
            if let Err(e) = unpack_sparse(&mut entry, &full_path, entry_size, mode, &real_dest) {
                return Err(std::io::Error::new(
                    e.kind(),
                    format!("failed to unpack '{}': {}", entry_path.display(), e),
                ));
            }
        } else {
            if let Err(e) = entry.unpack_in(dest) {
                // On macOS, certain entries fail to unpack due to platform
                // limitations (xattr encoding, uid/gid mapping, resource forks).
                // For non-Regular entries (symlinks, hardlinks, dirs), skip and
                // continue rather than aborting the entire extraction.
                if !is_regular {
                    continue;
                }
                return Err(std::io::Error::new(
                    e.kind(),
                    format!("failed to unpack '{}': {}", entry_path.display(), e),
                ));
            }

            // After extracting a directory, force it writable so subsequent
            // entries (children) can be created inside it. Final permissions
            // are applied after the loop.
            if entry_type == tar::EntryType::Directory && full_path.is_dir() {
                set_mode(&full_path, 0o755);
            }
        }
    }

    // Apply deferred directory permissions now that all children are written.
    for (path, mode) in deferred_dir_modes {
        if path.is_dir() {
            set_mode(&path, mode);
        }
    }

    Ok(())
}

/// Normalize a path by resolving `.` and `..` components without requiring
/// the path to exist on disk (unlike `canonicalize()`).
fn normalize_path(path: &Path) -> PathBuf {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                components.pop();
            }
            std::path::Component::CurDir => {}
            c => components.push(c),
        }
    }
    components.iter().collect()
}

/// Resolve a manifest asset path against an extraction cache without allowing
/// absolute paths, parent components, or symlink traversal outside the cache.
pub fn resolve_cache_asset_path(
    cache_dir: &Path,
    asset_rel_path: &str,
    context: &str,
) -> std::io::Result<PathBuf> {
    if asset_rel_path.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} path is empty", context),
        ));
    }

    let rel = Path::new(asset_rel_path);
    if rel.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} path must be relative", context),
        ));
    }

    for component in rel.components() {
        match component {
            std::path::Component::Normal(_) => {}
            std::path::Component::ParentDir
            | std::path::Component::CurDir
            | std::path::Component::RootDir
            | std::path::Component::Prefix(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("{} path contains disallowed components", context),
                ));
            }
        }
    }

    let cache_root = cache_dir
        .canonicalize()
        .unwrap_or_else(|_| normalize_path(cache_dir));
    let candidate = cache_dir.join(rel);

    let resolved = if candidate.exists() {
        candidate.canonicalize()?
    } else {
        // Candidate doesn't exist yet. Canonicalize its parent (which must
        // exist — it's the cache dir) and join the filename. This avoids
        // the macOS /tmp → /private/tmp symlink mismatch that would cause
        // the starts_with check below to fail when cache_root is canonical
        // but normalize_path is not.
        let parent = candidate.parent().unwrap_or(&candidate);
        let canonical_parent = parent
            .canonicalize()
            .unwrap_or_else(|_| normalize_path(parent));
        canonical_parent.join(candidate.file_name().unwrap_or_default())
    };

    if !resolved.starts_with(&cache_root) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} path escapes cache directory", context),
        ));
    }

    Ok(resolved)
}

/// Marker file indicating extraction is complete.
const EXTRACTION_MARKER: &str = ".smolvm-extracted";

/// Get the cache directory for a given checksum.
///
/// Returns `~/.cache/smolvm-pack/<checksum>/` (hex-formatted).
///
/// FOLLOW-UP (Finding D): `checksum` is a 32-bit CRC content fingerprint, which
/// is not collision-resistant — two distinct packs can share a cache dir. This
/// is a content-addressing weakness (not a write-escape) and warrants migrating
/// the cache key to a SHA-256 digest; tracked separately as it changes the
/// on-disk cache layout and footer format.
pub fn get_cache_dir(checksum: u32) -> std::io::Result<PathBuf> {
    let base = dirs::cache_dir()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no cache directory"))?;

    Ok(base.join("smolvm-pack").join(format!("{:08x}", checksum)))
}

/// Check if assets have already been extracted.
pub fn is_extracted(cache_dir: &Path) -> bool {
    cache_dir.join(EXTRACTION_MARKER).exists()
}

/// Maximum total size of the pack extraction cache before LRU eviction kicks in.
/// Override with `SMOLVM_PACK_CACHE_MAX_BYTES` (in bytes); default 5 GiB.
pub fn pack_cache_max_bytes() -> u64 {
    const DEFAULT: u64 = 5 * 1024 * 1024 * 1024;
    std::env::var("SMOLVM_PACK_CACHE_MAX_BYTES")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT)
}

/// Maximum number of entries `safe_unpack` will extract from a single archive
/// before erroring (inode-flood / entry-bomb guard). Override with
/// `SMOLVM_PACK_MAX_ENTRIES`; default 2,000,000 — far above any real image tar.
fn max_extract_entries() -> u64 {
    const DEFAULT: u64 = 2_000_000;
    std::env::var("SMOLVM_PACK_MAX_ENTRIES")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT)
}

/// Maximum total apparent (header-declared) size `safe_unpack` will extract from
/// a single archive before erroring (disk-exhaustion / decompression-bomb
/// guard). Override with `SMOLVM_PACK_MAX_EXTRACT_BYTES`; default 128 GiB —
/// generous enough for several large (sparse) overlay disks yet finite.
fn max_extract_total_bytes() -> u64 {
    const DEFAULT: u64 = 128 * 1024 * 1024 * 1024;
    std::env::var("SMOLVM_PACK_MAX_EXTRACT_BYTES")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT)
}

/// Real (sparse-aware) disk usage of a single file. Extraction dirs contain
/// large *sparse* overlay disks (e.g. a 10 GiB disk holding ~50 MB), so we must
/// count allocated blocks, not the apparent length — otherwise the cap would
/// over-count by orders of magnitude and evict far too aggressively.
#[cfg(unix)]
fn file_disk_usage(meta: &fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.blocks().saturating_mul(512)
}
#[cfg(not(unix))]
fn file_disk_usage(meta: &fs::Metadata) -> u64 {
    meta.len()
}

/// Recursive real disk usage of a directory tree (best-effort; unreadable
/// entries count as zero). Does not follow symlinks.
fn dir_disk_usage(path: &Path) -> u64 {
    let mut total = 0u64;
    let entries = match fs::read_dir(path) {
        Ok(e) => e,
        Err(_) => return 0,
    };
    for entry in entries.flatten() {
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.is_dir() {
            total = total.saturating_add(dir_disk_usage(&entry.path()));
        } else if meta.is_file() {
            total = total.saturating_add(file_disk_usage(&meta));
        }
    }
    total
}

/// Evict least-recently-modified extraction directories under `cache_root` until
/// the cache's total real disk usage is at or below `max_bytes`. Skips
/// directories with active leases (a running pack/VM) — they are never evicted,
/// even if that leaves the cache over the cap. Best-effort: per-entry errors are
/// skipped. Returns the number of bytes freed.
///
/// This is what bounds the otherwise-unbounded extraction cache; it runs
/// automatically after a new (cache-miss) extraction, and keeps the newest
/// entries (including the one just written) by evicting oldest-first.
pub fn evict_cache_to_size(cache_root: &Path, max_bytes: u64) -> u64 {
    evict_cache_to_size_protecting(cache_root, max_bytes, None)
}

/// Like [`evict_cache_to_size`], but never evicts `protect` (canonicalized),
/// even if that leaves the cache over the cap.
///
/// The eviction after a fresh extraction runs *before* the caller acquires a
/// layers lease, so the just-written directory has no lease yet. When a single
/// extraction is larger than the cap (a torch/CUDA pack is ~13 GiB vs the 5 GiB
/// default), oldest-first eviction would otherwise delete the very directory
/// about to be booted — the VM then mounts nonexistent virtio-fs shares and the
/// vcpu panics with `BadActivate`. Passing the current `cache_dir` as `protect`
/// prevents that; the cache is simply allowed over-cap until the run releases it
/// (same policy already applied to leased dirs).
pub fn evict_cache_to_size_protecting(
    cache_root: &Path,
    max_bytes: u64,
    protect: Option<&Path>,
) -> u64 {
    let protect_canon = protect.and_then(|p| fs::canonicalize(p).ok());
    let mut entries: Vec<(PathBuf, std::time::SystemTime, u64)> = Vec::new();
    let read_dir = match fs::read_dir(cache_root) {
        Ok(rd) => rd,
        Err(_) => return 0,
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        let meta = match fs::metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !meta.is_dir() {
            continue; // skip *.lock files and other non-extraction entries
        }
        let modified = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        entries.push((path, modified, dir_disk_usage(&entry.path())));
    }

    let total: u64 = entries.iter().map(|(_, _, s)| *s).sum();
    if total <= max_bytes {
        return 0;
    }

    // Oldest first — evict least-recently-used.
    entries.sort_by_key(|(_, modified, _)| *modified);

    let mut over = total - max_bytes;
    let mut freed = 0u64;
    for (path, _, size) in entries {
        if over == 0 {
            break;
        }
        if has_active_leases(&path) {
            continue; // never evict a running pack/VM
        }
        if protect_canon
            .as_deref()
            .is_some_and(|pc| fs::canonicalize(&path).ok().as_deref() == Some(pc))
        {
            continue; // never evict the extraction we just wrote / are about to boot
        }
        force_detach_layers_volume(&path);
        if fs::remove_dir_all(&path).is_ok() {
            // Also drop the adjacent <checksum>.lock file, if any.
            let _ = fs::remove_file(path.with_extension("lock"));
            freed = freed.saturating_add(size);
            over = over.saturating_sub(size);
        }
    }
    freed
}

/// Check if footer indicates sidecar mode.
fn is_sidecar_mode(footer: &PackFooter) -> bool {
    footer.assets_offset == 0
}

/// Get sidecar file path for the given executable.
pub fn sidecar_path_for(exe_path: &Path) -> PathBuf {
    let filename = exe_path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    exe_path.with_file_name(format!("{}{}", filename, SIDECAR_EXTENSION))
}

/// Extract assets from a sidecar `.smolmachine` file to the cache directory.
///
/// This is the primary extraction function for `smolvm pack run`.
/// The sidecar file format is: compressed_assets + manifest + footer.
///
/// Uses file-based locking (`flock`) to prevent races when multiple processes
/// attempt first-run extraction of the same sidecar concurrently. If `force`
/// is false and extraction has already completed (marker file present), this
/// is a no-op (after acquiring the lock to ensure visibility of a concurrent
/// extraction that just finished).
pub fn extract_sidecar(
    sidecar_path: &Path,
    cache_dir: &Path,
    footer: &PackFooter,
    force: bool,
    debug: bool,
) -> std::io::Result<()> {
    // Private per-machine caches are LRU-capped after extraction; the shared
    // store opts out (see `extract_sidecar_capped`).
    extract_sidecar_capped(sidecar_path, cache_dir, footer, force, debug, true)
}

/// Core of [`extract_sidecar`]. `cap_cache` runs the LRU size-cap on
/// `cache_dir.parent()` after a successful extraction.
///
/// It MUST be `false` for the node-shared store (`_shared`): those entries are
/// reference-shared across many VMs via `.pack-shared` pointers and hold NO
/// per-VM lease, so capping the shared root would LRU-evict a pack still mounted
/// by live pool VMs — their `/packed_layers` then reads empty and the guest
/// fails with "no layer directories found in /packed_layers" (exit 255 on
/// connect/exec). Only the private per-machine cache (`smolvm-pack/<checksum>`),
/// whose running entries DO hold leases, is safe to cap. See
/// `extract_sidecar_shared`, which passes `false`.
fn extract_sidecar_capped(
    sidecar_path: &Path,
    cache_dir: &Path,
    footer: &PackFooter,
    force: bool,
    debug: bool,
    cap_cache: bool,
) -> std::io::Result<()> {
    if !sidecar_path.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("sidecar file not found: {}", sidecar_path.display()),
        ));
    }

    // Ensure parent directory exists for the lockfile
    if let Some(parent) = cache_dir.parent() {
        fs::create_dir_all(parent)?;
    }

    // Acquire an exclusive lock adjacent to the cache directory.
    // This serializes concurrent first-run extractions of the same checksum.
    let lock_path = cache_dir.with_extension("lock");
    // Held open for the function's duration: backs the advisory lock below
    // (flock on Unix, LockFileEx on Windows) and releases on drop.
    let lock_file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)?;

    lock_file_exclusive(&lock_file)?;

    // Double-check inside the lock: another process may have completed
    // extraction while we were waiting for the lock.
    if !force && is_extracted(cache_dir) {
        if debug {
            eprintln!("debug: assets already extracted (possibly by another process)");
        }
        // Lock released on drop of lock_file
        return Ok(());
    }

    // If force-extracting over an existing cache, detach any mounted
    // case-sensitive volume first, then remove for a clean slate.
    if force && cache_dir.exists() {
        force_detach_layers_volume(cache_dir);
        let _ = fs::remove_dir_all(cache_dir);
    }

    let result = extract_sidecar_inner(sidecar_path, cache_dir, footer, debug);

    // If extraction failed mid-stream, partially extracted files remain on
    // disk without a completion marker. Subsequent retries hit the same
    // error at the same tar entry, never completing. Clean up the partial
    // directory so the next attempt starts fresh.
    if result.is_err() && cache_dir.exists() && !is_extracted(cache_dir) {
        let _ = fs::remove_dir_all(cache_dir);
    }

    // After a successful new extraction (cache miss — the early-return above
    // handles cache hits), cap the cache so old, unused extractions don't grow
    // without bound. LRU + lease-aware: keeps the newest (incl. what we just
    // wrote) and never evicts a running pack.
    if result.is_ok() && cap_cache {
        if let Some(root) = cache_dir.parent() {
            // Protect the directory we just extracted: the caller has not yet
            // acquired its layers lease, so without this the eviction can delete
            // the assets this very run is about to boot (→ virtio-fs ENOENT →
            // vcpu BadActivate). A torch pack (~13 GiB) alone exceeds the 5 GiB
            // default cap, which is exactly when oldest-first eviction reaches it.
            let freed =
                evict_cache_to_size_protecting(root, pack_cache_max_bytes(), Some(cache_dir));
            if freed > 0 && debug {
                eprintln!("debug: pack cache evicted {freed} bytes to stay under cap");
            }
        }
    }

    result
    // Lock released on drop of lock_file
}

/// Whether the shared content-addressed pack store is usable on this host.
///
/// The shared store extracts each build-constant pack exactly once per node into
/// `_shared/<checksum>` (root-owned, read-only) and presents it to each VM via a
/// per-VM idmapped bind mount, instead of re-extracting + re-chowning a private
/// copy per machine. That mechanism is Linux-only (idmapped mounts, kernel ≥5.12)
/// and the per-VM uid isolation it preserves only exists on the Linux fleet.
/// `SMOLVM_DISABLE_SHARED_EXTRACT` is a kill-switch to fall back to the per-machine
/// path without a redeploy.
pub fn shared_extract_enabled() -> bool {
    cfg!(target_os = "linux") && std::env::var_os("SMOLVM_DISABLE_SHARED_EXTRACT").is_none()
}

/// Directory holding the shared copy for one pack checksum, under `shared_root`.
pub fn shared_pack_dir(shared_root: &Path, checksum: u32) -> PathBuf {
    shared_root.join(format!("{:08x}", checksum))
}

/// Extract a sidecar pack ONCE into the shared content-addressed store and return
/// the path to the shared copy (`shared_root/<checksum>`).
///
/// Unlike [`extract_sidecar`] (which writes a private per-machine copy), this is
/// keyed purely by `footer.checksum` (a CRC32 content fingerprint), so every
/// machine on a node whose pack hashes identically reuses the same extracted tree.
/// The build-constant agent-rootfs (~28.6 MB / 362 files) therefore decodes once
/// per node instead of once per machine — the cold-start tax this removes.
///
/// The shared copy is left **root-owned** (the extractor runs as root and the tar
/// crate does not preserve ownership by default, so all files land `root:root`)
/// and the store directories are locked to `0700 root`. No other uid can read the
/// copy directly; a VM reaches it only through its own idmapped bind mount, which
/// re-presents on-disk uid 0 as that VM's uid — preserving the per-VM isolation
/// (#456) without a per-machine chown.
///
/// Idempotent + concurrency-safe: delegates to [`extract_sidecar`], whose flock +
/// `.smolvm-extracted` marker serialize concurrent first extractions of the same
/// checksum and make a warm hit a no-op.
pub fn extract_sidecar_shared(
    sidecar_path: &Path,
    shared_root: &Path,
    footer: &PackFooter,
    debug: bool,
) -> std::io::Result<PathBuf> {
    let shared_dir = shared_pack_dir(shared_root, footer.checksum);
    // cap_cache=false: NEVER LRU-evict the shared store. Its entries are
    // reference-shared across every VM via `.pack-shared` pointers and take no
    // per-VM lease, so an oldest-first size-cap here would delete a pack still
    // mounted by live pool VMs. See `extract_sidecar_capped`.
    extract_sidecar_capped(sidecar_path, &shared_dir, footer, false, debug, false)?;
    // Lock down the store so a dropped per-VM uid can't read the shared copy
    // directly (it must go through its idmapped mount). Best-effort: traversal
    // by root (the VMM before it drops privileges) is unaffected by 0700.
    restrict_to_owner(shared_root);
    restrict_to_owner(&shared_dir);
    Ok(shared_dir)
}

/// Set a directory to `0700` (owner-only) if possible. Best-effort; errors are
/// swallowed because the store is already root-owned and root traversal ignores
/// the mode — this only hardens against a *dropped* sibling uid reading the copy.
fn restrict_to_owner(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(dir) {
            let mut perms = meta.permissions();
            perms.set_mode(0o700);
            let _ = fs::set_permissions(dir, perms);
        }
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// Inner extraction logic (called under the lock).
fn extract_sidecar_inner(
    sidecar_path: &Path,
    cache_dir: &Path,
    footer: &PackFooter,
    debug: bool,
) -> std::io::Result<()> {
    fs::create_dir_all(cache_dir)?;

    if debug {
        eprintln!(
            "debug: reading {} bytes of compressed assets from sidecar {}",
            footer.assets_size,
            sidecar_path.display()
        );
    }

    let sidecar_file = File::open(sidecar_path)?;
    let limited_reader = sidecar_file.take(footer.assets_size);

    let decoder = zstd::stream::Decoder::new(limited_reader)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let mut archive = tar::Archive::new(decoder);
    safe_unpack(&mut archive, cache_dir)?;

    if debug {
        eprintln!("debug: extracted assets to {}", cache_dir.display());
    }

    // Layer order from the sidecar manifest (bottom→top). Best-effort: if the
    // manifest can't be read the agent falls back to a name sort.
    let layer_order = crate::packer::read_manifest_from_sidecar(sidecar_path)
        .ok()
        .map(|m| {
            m.assets
                .layers
                .iter()
                .filter_map(|l| layer_id_from_asset_path(&l.path))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    post_process_extraction(cache_dir, &layer_order, debug)?;
    Ok(())
}

/// Extract assets from a packed binary to the cache directory.
///
/// Supports both sidecar mode (assets_offset == 0) and embedded mode.
/// This is used by the stub executable.
pub fn extract_from_binary(
    exe_path: &Path,
    cache_dir: &Path,
    footer: &PackFooter,
    debug: bool,
) -> std::io::Result<()> {
    fs::create_dir_all(cache_dir)?;

    if is_sidecar_mode(footer) {
        let sidecar = sidecar_path_for(exe_path);
        extract_sidecar(&sidecar, cache_dir, footer, false, debug)
    } else {
        // Embedded mode: read compressed assets from the executable
        let mut exe_file = File::open(exe_path)?;
        exe_file.seek(SeekFrom::Start(footer.assets_offset))?;

        if debug {
            eprintln!(
                "debug: reading {} bytes of compressed assets from offset {}",
                footer.assets_size, footer.assets_offset
            );
        }

        let limited_reader = (&mut exe_file).take(footer.assets_size);

        let decoder = zstd::stream::Decoder::new(limited_reader)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let mut archive = tar::Archive::new(decoder);
        safe_unpack(&mut archive, cache_dir)?;

        if debug {
            eprintln!("debug: extracted assets to {}", cache_dir.display());
        }

        // Embedded self-exec stub: no separate sidecar manifest to source layer
        // order from here, so let the agent fall back to a name sort.
        post_process_extraction(cache_dir, &[], debug)?;
        Ok(())
    }
}

/// Extract assets from a memory pointer (for Mach-O section mode on macOS).
///
/// # Safety
///
/// `assets_ptr` must point to a valid, readable memory region of at least
/// `assets_size` bytes that remains valid for the duration of the call.
#[cfg(target_os = "macos")]
pub unsafe fn extract_from_section(
    cache_dir: &Path,
    assets_ptr: *const u8,
    assets_size: usize,
    debug: bool,
) -> std::io::Result<()> {
    fs::create_dir_all(cache_dir)?;

    if debug {
        eprintln!(
            "debug: extracting {} bytes of compressed assets from section",
            assets_size
        );
    }

    let assets_slice = unsafe { std::slice::from_raw_parts(assets_ptr, assets_size) };
    let cursor = std::io::Cursor::new(assets_slice);

    let decoder = zstd::stream::Decoder::new(cursor)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let mut archive = tar::Archive::new(decoder);
    safe_unpack(&mut archive, cache_dir)?;

    if debug {
        eprintln!("debug: extracted assets to {}", cache_dir.display());
    }

    // Mach-O section self-exec stub: same as embedded mode — name-sort fallback.
    post_process_extraction(cache_dir, &[], debug)?;
    Ok(())
}

/// Name of the index file written into the extracted-layers dir recording the
/// layers in OCI order (bottom-most first), one short layer id per line. The
/// guest agent honors it when stacking overlayfs lowerdirs; without it, layers
/// (which are named by content digest) sort arbitrarily and a multi-layer pack
/// can be mis-stacked. Must match the agent's `LAYER_ORDER_FILE`.
const LAYER_ORDER_FILE: &str = "layer-order";

/// Layer id used as the on-disk layer dir name, derived from the manifest asset
/// path stem so old short paths and new full-digest paths both preserve order.
fn layer_id_from_asset_path(path: &str) -> Option<String> {
    let rel = Path::new(path);
    (!rel.is_absolute())
        .then_some(rel)?
        .file_stem()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
}

/// Post-process extracted assets: unpack agent rootfs, OCI layers, fix
/// permissions, and (when `layer_order` is non-empty) write the layer-order
/// index so the guest stacks the layers in true OCI order rather than by their
/// content-addressed names. `layer_order` is the short layer ids bottom→top.
fn post_process_extraction(
    cache_dir: &Path,
    layer_order: &[String],
    debug: bool,
) -> std::io::Result<()> {
    // Extract agent-rootfs.tar to agent-rootfs directory
    let rootfs_tar = cache_dir.join("agent-rootfs.tar");
    let rootfs_dir = cache_dir.join("agent-rootfs");
    if rootfs_tar.exists() && !rootfs_dir.exists() {
        if debug {
            eprintln!("debug: extracting agent-rootfs.tar...");
        }
        fs::create_dir_all(&rootfs_dir)?;
        let tar_file = File::open(&rootfs_tar)?;
        let mut archive = tar::Archive::new(tar_file);
        safe_unpack(&mut archive, &rootfs_dir)?;
    }

    // Extract OCI layer tars to layers/{digest}/ directories.
    //
    // On macOS, the default APFS filesystem is case-insensitive. Linux OCI
    // layers may contain paths that differ only in case (e.g., "gdebi" script
    // and "GDebi/" directory). Extracting these onto case-insensitive APFS
    // would silently lose files. Since the extracted directories are mounted
    // into the guest via virtiofs as overlayfs lowerdirs, any missing files
    // would corrupt the packed image.
    //
    // To preserve all paths faithfully, we extract layers into a case-sensitive
    // APFS sparse disk image on macOS. The image is persisted in the cache and
    // re-mounted on subsequent runs.
    let layers_dir = cache_dir.join("layers");
    if layers_dir.exists() {
        if debug {
            eprintln!("debug: extracting OCI layers...");
        }
        // On macOS, extract into a case-sensitive volume to preserve Linux
        // paths that differ only in case. On Linux (ext4/xfs), the layers
        // dir is already case-sensitive. If the volume can't be created on
        // macOS, fail rather than silently corrupting case-colliding paths.
        let extract_dir = extraction_layers_dir(cache_dir, debug)?;

        for entry in fs::read_dir(&layers_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "tar") {
                let stem = path.file_stem().unwrap_or_default().to_string_lossy();
                let layer_dir = extract_dir.join(&*stem);
                if !layer_dir.exists() {
                    if debug {
                        eprintln!("debug: extracting layer {}...", stem);
                    }
                    fs::create_dir_all(&layer_dir)?;
                    let tar_file = File::open(&path)?;
                    let mut archive = tar::Archive::new(tar_file);
                    safe_unpack(&mut archive, &layer_dir)?;
                }
            }
        }

        // Record the manifest's layer order so the guest stacks overlayfs
        // lowerdirs correctly (layer dirs are named by digest and don't sort
        // into stack order). Only ids backed by an extracted dir are written.
        if !layer_order.is_empty() {
            let lines: Vec<&str> = layer_order
                .iter()
                .filter(|id| extract_dir.join(id).is_dir())
                .map(String::as_str)
                .collect();
            if !lines.is_empty() {
                fs::write(extract_dir.join(LAYER_ORDER_FILE), lines.join("\n"))?;
            }
        }
    }

    // Write marker file
    fs::write(cache_dir.join(EXTRACTION_MARKER), "")?;

    // Make libraries executable (they need to be loadable).
    let lib_dir = cache_dir.join("lib");
    if lib_dir.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for entry in fs::read_dir(&lib_dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() {
                    let mut perms = fs::metadata(&path)?.permissions();
                    perms.set_mode(0o755);
                    fs::set_permissions(&path, perms)?;
                }
            }
        }
    }

    Ok(())
}

// =============================================================================
// Case-sensitive layer extraction (macOS)
//
// On macOS, default APFS is case-insensitive. Linux OCI layers may contain
// paths that differ only in case (e.g., `gdebi` vs `GDebi/`). Extracting
// onto case-insensitive APFS silently drops one variant, corrupting the
// packed image.
//
// We extract layers into a case-sensitive APFS sparse disk image. The image
// lives in the cache directory and is mounted on demand. Because the cache
// is shared across concurrent runs of the same packed artifact, we use a
// lease-file protocol to coordinate mount/unmount:
//
//   cache_dir/layers-cs.sparseimage   — persisted sparse image
//   cache_dir/layers-cs/              — mount point
//   cache_dir/leases/<pid>            — one file per active user
//   cache_dir/leases.lock             — flock for lease operations
//
// Acquire: lock → gc stale leases → ensure mounted → write lease → unlock
// Release: lock → remove lease → if no leases remain, detach → unlock
// =============================================================================

/// Name of the sparse disk image used for case-sensitive layer extraction.
#[cfg(target_os = "macos")]
const CS_IMAGE_NAME: &str = "layers-cs.sparseimage";

/// Subdirectory name for the case-sensitive mount point.
#[cfg(target_os = "macos")]
const CS_MOUNT_DIR: &str = "layers-cs";

/// Subdirectory for lease files.
#[cfg(target_os = "macos")]
const LEASES_DIR: &str = "leases";

/// Lock file for lease coordination.
#[cfg(target_os = "macos")]
const LEASES_LOCK: &str = "leases.lock";

/// A lease on the case-sensitive layers volume. On macOS, this ensures the
/// APFS sparse image is mounted while any lease exists, and detaches it
/// when the last lease is released. On Linux, this is a no-op wrapper.
///
/// Implements `Drop` so all `?` error paths release the lease automatically.
pub struct LayersVolumeLease {
    /// Path to the layers directory (case-sensitive mount on macOS, or
    /// `cache_dir/layers` on Linux).
    pub path: PathBuf,
    /// Cache directory this lease belongs to (needed for cleanup on drop).
    #[cfg(target_os = "macos")]
    cache_dir: PathBuf,
}

impl Drop for LayersVolumeLease {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        {
            release_lease(&self.cache_dir);
        }
    }
}

/// Acquire a lease on the case-sensitive layers volume.
///
/// On macOS: creates the sparse image if needed, mounts it, writes a
/// per-PID lease file. The volume stays mounted until the last lease is
/// released. Returns a `LayersVolumeLease` whose `Drop` releases the lease.
///
/// On Linux: returns the `cache_dir/layers` path directly (no-op).
///
/// Called by `post_process_extraction` during first-time extraction and by
/// `pack_run` before launching the VM.
pub fn acquire_layers_lease(cache_dir: &Path, debug: bool) -> std::io::Result<LayersVolumeLease> {
    #[cfg(target_os = "macos")]
    {
        let image_path = cache_dir.join(CS_IMAGE_NAME);
        if image_path.exists() || has_layer_tars(cache_dir) {
            // Case-sensitive volume is required on macOS to preserve Linux
            // paths faithfully. Fail if it can't be acquired rather than
            // silently falling back to case-insensitive extraction.
            let path = acquire_lease(cache_dir, debug)?;
            return Ok(LayersVolumeLease {
                path,
                cache_dir: cache_dir.to_path_buf(),
            });
        }
    }

    let _ = debug;
    Ok(LayersVolumeLease {
        path: cache_dir.join("layers"),
        #[cfg(target_os = "macos")]
        cache_dir: cache_dir.to_path_buf(),
    })
}

/// Acquire a persistent daemon lease that survives process exit.
///
/// Unlike `acquire_layers_lease` (RAII, released on Drop), this creates a
/// lease file named `daemon` that persists until explicitly released by
/// `release_daemon_lease`. The daemon child PID is recorded in the file
/// so stale daemon leases can be garbage-collected.
///
/// On Linux this is a no-op that returns the layers path.
pub fn acquire_daemon_lease(
    cache_dir: &Path,
    daemon_pid: i32,
    debug: bool,
) -> std::io::Result<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let image_path = cache_dir.join(CS_IMAGE_NAME);
        if image_path.exists() || has_layer_tars(cache_dir) {
            let leases_dir = cache_dir.join(LEASES_DIR);
            fs::create_dir_all(&leases_dir)?;
            let lock = lock_leases(cache_dir)?;
            gc_stale_leases(&leases_dir);
            ensure_cs_volume_mounted(cache_dir, debug)?;
            fs::write(leases_dir.join("daemon"), format!("{}", daemon_pid))?;
            drop(lock);
            return Ok(cache_dir.join(CS_MOUNT_DIR));
        }
    }

    let _ = (daemon_pid, debug);
    Ok(cache_dir.join("layers"))
}

/// Release the persistent daemon lease and detach if no leases remain.
///
/// Called from `daemon_stop()` after the VM process has been terminated.
pub fn release_daemon_lease(cache_dir: &Path) {
    #[cfg(target_os = "macos")]
    {
        let leases_dir = cache_dir.join(LEASES_DIR);
        let daemon_lease = leases_dir.join("daemon");
        if !daemon_lease.exists() {
            return;
        }

        let Ok(lock) = lock_leases(cache_dir) else {
            let _ = fs::remove_file(&daemon_lease);
            return;
        };

        let _ = fs::remove_file(&daemon_lease);
        gc_stale_leases(&leases_dir);
        detach_if_unused(cache_dir);
        drop(lock);
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = cache_dir;
    }
}

/// Check whether any active leases exist for this cache directory.
///
/// Used by `pack prune` to skip in-use caches. Garbage-collects stale
/// leases first (dead PIDs, dead daemon processes).
pub fn has_active_leases(cache_dir: &Path) -> bool {
    #[cfg(target_os = "macos")]
    {
        let leases_dir = cache_dir.join(LEASES_DIR);
        if !leases_dir.exists() {
            return false;
        }

        let Ok(lock) = lock_leases(cache_dir) else {
            return false;
        };
        gc_stale_leases(&leases_dir);
        let active = count_leases(&leases_dir);
        drop(lock);
        active > 0
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = cache_dir;
        false
    }
}

/// Force-detach and clean up all leases for a cache directory.
///
/// Used by `--force-extract` before clearing the cache. NOT used by normal
/// `pack prune` — prune should check `has_active_leases` first and skip
/// active caches.
pub fn force_detach_layers_volume(cache_dir: &Path) {
    // A fork clone's cache dir is a symlink to its golden's — the clone doesn't
    // own the volume or the leases behind it, so detaching through the link
    // would rip the layers out from under the frozen golden and its siblings.
    if cache_dir
        .symlink_metadata()
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        return;
    }
    #[cfg(target_os = "macos")]
    {
        let mount_point = cache_dir.join(CS_MOUNT_DIR);
        if mount_point.exists() && is_mount_point(&mount_point) {
            let _ = std::process::Command::new("hdiutil")
                .args(["detach", "-quiet", "-force"])
                .arg(&mount_point)
                .output();
        }
        // Remove all lease files.
        let _ = fs::remove_dir_all(cache_dir.join(LEASES_DIR));
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = cache_dir;
    }
}

/// Mount the case-sensitive volume (if needed) and return the extraction
/// directory. Called during initial extraction (already under flock — no
/// lease needed). For runtime use, call `acquire_layers_lease()` instead.
fn extraction_layers_dir(cache_dir: &Path, debug: bool) -> std::io::Result<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        ensure_cs_volume_mounted(cache_dir, debug)?;
        Ok(cache_dir.join(CS_MOUNT_DIR))
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = debug;
        Ok(cache_dir.join("layers"))
    }
}

// --- macOS-only implementation details ---

#[cfg(target_os = "macos")]
fn has_layer_tars(cache_dir: &Path) -> bool {
    let layers_dir = cache_dir.join("layers");
    layers_dir.exists()
        && fs::read_dir(&layers_dir)
            .ok()
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .any(|e| e.path().extension().is_some_and(|ext| ext == "tar"))
            })
            .unwrap_or(false)
}

/// Sum the sizes of all `.tar` files in a directory.
#[cfg(target_os = "macos")]
fn sum_tar_sizes(dir: &Path) -> u64 {
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    entries
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "tar"))
        .filter_map(|e| e.metadata().ok())
        .map(|m| m.len())
        .sum()
}

/// Check whether `path` is a mount point by comparing device IDs with parent.
#[cfg(target_os = "macos")]
fn is_mount_point(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(meta) = fs::metadata(path) else {
        return false;
    };
    let Ok(parent_meta) = fs::metadata(path.parent().unwrap_or(Path::new("/"))) else {
        return false;
    };
    meta.dev() != parent_meta.dev()
}

/// Acquire a lease: lock → gc stale leases → ensure mounted → write lease.
#[cfg(target_os = "macos")]
fn acquire_lease(cache_dir: &Path, debug: bool) -> std::io::Result<PathBuf> {
    let mount_point = cache_dir.join(CS_MOUNT_DIR);
    let leases_dir = cache_dir.join(LEASES_DIR);
    fs::create_dir_all(&leases_dir)?;

    let lock = lock_leases(cache_dir)?;

    // Garbage-collect leases from dead processes.
    gc_stale_leases(&leases_dir);

    // Ensure the sparse image exists and is mounted.
    ensure_cs_volume_mounted(cache_dir, debug)?;

    // Write a lease file for this process.
    let lease_path = leases_dir.join(format!("{}", std::process::id()));
    fs::write(&lease_path, "")?;

    drop(lock);
    Ok(mount_point)
}

/// Release a lease: lock → remove lease → if no leases remain, detach.
#[cfg(target_os = "macos")]
fn release_lease(cache_dir: &Path) {
    let leases_dir = cache_dir.join(LEASES_DIR);
    let lease_path = leases_dir.join(format!("{}", std::process::id()));

    let Ok(lock) = lock_leases(cache_dir) else {
        let _ = fs::remove_file(&lease_path);
        return;
    };

    let _ = fs::remove_file(&lease_path);
    gc_stale_leases(&leases_dir);
    detach_if_unused(cache_dir);
    drop(lock);
}

/// Remove lease files whose PID is no longer alive.
///
/// Handles both per-PID leases (named by PID number) and daemon leases
/// (named "daemon", containing the daemon PID as text content).
#[cfg(target_os = "macos")]
fn gc_stale_leases(leases_dir: &Path) {
    let Ok(entries) = fs::read_dir(leases_dir) else {
        return;
    };
    for entry in entries.filter_map(|e| e.ok()) {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if name_str == "daemon" {
            // Daemon lease: PID is stored as file content.
            if let Ok(content) = fs::read_to_string(entry.path()) {
                if let Ok(pid) = content.trim().parse::<i32>() {
                    if unsafe { libc::kill(pid, 0) } != 0 {
                        let _ = fs::remove_file(entry.path());
                    }
                }
            }
        } else if let Ok(pid) = name_str.parse::<i32>() {
            // Per-PID lease: file name is the PID.
            if unsafe { libc::kill(pid, 0) } != 0 {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
}

/// Count active lease files in the leases directory.
#[cfg(target_os = "macos")]
fn count_leases(leases_dir: &Path) -> usize {
    fs::read_dir(leases_dir)
        .ok()
        .map(|rd| rd.filter_map(|e| e.ok()).count())
        .unwrap_or(0)
}

/// Detach the case-sensitive volume if no leases remain.
#[cfg(target_os = "macos")]
fn detach_if_unused(cache_dir: &Path) {
    let leases_dir = cache_dir.join(LEASES_DIR);
    if count_leases(&leases_dir) == 0 {
        let mount_point = cache_dir.join(CS_MOUNT_DIR);
        if mount_point.exists() && is_mount_point(&mount_point) {
            let _ = std::process::Command::new("hdiutil")
                .args(["detach", "-quiet"])
                .arg(&mount_point)
                .output();
        }
    }
}

/// Acquire the leases lock (flock-based, like extract_sidecar).
#[cfg(target_os = "macos")]
fn lock_leases(cache_dir: &Path) -> std::io::Result<File> {
    let lock_path = cache_dir.join(LEASES_LOCK);
    let lock_file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)?;
    let ret = unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(lock_file)
}

/// Create the sparse image if needed and mount it.
#[cfg(target_os = "macos")]
fn ensure_cs_volume_mounted(cache_dir: &Path, debug: bool) -> std::io::Result<()> {
    let image_path = cache_dir.join(CS_IMAGE_NAME);
    let mount_point = cache_dir.join(CS_MOUNT_DIR);

    // Already mounted — nothing to do.
    if mount_point.exists() && is_mount_point(&mount_point) {
        return Ok(());
    }

    // Create the sparse image if it doesn't exist.
    if !image_path.exists() {
        let layers_dir = cache_dir.join("layers");
        let total_tar_bytes = sum_tar_sizes(&layers_dir);
        // 2.5x headroom + 512 MiB for fs metadata, minimum 1 GiB.
        // Sparse format: only written bytes use real disk.
        let size_bytes = std::cmp::max(
            (total_tar_bytes as f64 * 2.5) as u64 + 512 * 1024 * 1024,
            1024 * 1024 * 1024,
        );
        let size_gib = size_bytes / (1024 * 1024 * 1024) + 1;
        let size_arg = format!("{}g", size_gib);

        if debug {
            eprintln!(
                "debug: creating case-sensitive APFS sparse image ({}g from {} bytes of tars)...",
                size_gib, total_tar_bytes
            );
        }
        let output = std::process::Command::new("hdiutil")
            .args([
                "create",
                "-size",
                &size_arg,
                "-fs",
                "Case-sensitive APFS",
                "-type",
                "SPARSE",
                "-volname",
                "smolvm-layers",
            ])
            .arg(&image_path)
            .output()?;
        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "hdiutil create failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
    }

    // Mount it.
    fs::create_dir_all(&mount_point)?;
    if debug {
        eprintln!(
            "debug: mounting case-sensitive volume at {}",
            mount_point.display()
        );
    }
    let output = std::process::Command::new("hdiutil")
        .args(["attach", "-mountpoint"])
        .arg(&mount_point)
        .args(["-nobrowse", "-noautoopen"])
        .arg(&image_path)
        .output()?;
    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "hdiutil attach failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok(())
}

/// Marker file indicating libs extraction is complete.
const LIBS_EXTRACTION_MARKER: &str = ".smolvm-libs-extracted";

/// Extract runtime libraries from a packed stub binary.
///
/// Reads the last 32 bytes of the executable looking for a SMOLLIBS footer.
/// If found, extracts the compressed libs bundle to a cache directory and
/// returns the path to the `lib/` directory containing libkrun/libkrunfw.
///
/// Returns `None` if the binary has no embedded libs (e.g., the base smolvm binary).
pub fn extract_libs_from_binary(exe_path: &Path, debug: bool) -> std::io::Result<Option<PathBuf>> {
    use crate::format::{LibsFooter, LIBS_FOOTER_SIZE};

    let mut file = File::open(exe_path)?;
    let file_size = file.metadata()?.len();
    if file_size < LIBS_FOOTER_SIZE as u64 {
        return Ok(None);
    }

    // Read the last 32 bytes
    file.seek(SeekFrom::End(-(LIBS_FOOTER_SIZE as i64)))?;
    let mut footer_buf = [0u8; LIBS_FOOTER_SIZE];
    file.read_exact(&mut footer_buf)?;

    let footer = match LibsFooter::from_bytes(&footer_buf) {
        Ok(f) => f,
        Err(_) => return Ok(None), // No SMOLLIBS footer — no embedded libs
    };

    if debug {
        eprintln!(
            "debug: found SMOLLIBS footer: offset={}, size={}",
            footer.libs_offset, footer.libs_size
        );
    }

    // Cache key based on libs content hash
    file.seek(SeekFrom::Start(footer.libs_offset))?;
    let mut hasher = crc32fast::Hasher::new();
    let mut remaining = footer.libs_size;
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
    let libs_checksum = hasher.finalize();

    let cache_base = dirs::cache_dir()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no cache directory"))?;
    let libs_cache_dir = cache_base
        .join("smolvm-libs")
        .join(format!("{:08x}", libs_checksum));
    let lib_dir = libs_cache_dir.join("lib");

    // Acquire exclusive lock to prevent concurrent extraction races.
    if let Some(parent) = libs_cache_dir.parent() {
        fs::create_dir_all(parent)?;
    }
    let lock_path = libs_cache_dir.with_extension("lock");
    let lock_file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)?;

    lock_file_exclusive(&lock_file)?;

    // Re-check after acquiring lock (another process may have finished)
    if libs_cache_dir.join(LIBS_EXTRACTION_MARKER).exists() {
        if debug {
            eprintln!("debug: libs already extracted at {}", lib_dir.display());
        }
        // Lock released on drop of lock_file
        let _ = lock_file;
        return Ok(Some(lib_dir));
    }

    // Extract
    fs::create_dir_all(&libs_cache_dir)?;
    file.seek(SeekFrom::Start(footer.libs_offset))?;
    let limited_reader = (&mut file).take(footer.libs_size);
    let decoder = zstd::stream::Decoder::new(limited_reader)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let mut archive = tar::Archive::new(decoder);
    safe_unpack(&mut archive, &libs_cache_dir)?;

    // Make libs executable
    if lib_dir.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for entry in fs::read_dir(&lib_dir)? {
                let entry = entry?;
                if entry.path().is_file() {
                    let mut perms = fs::metadata(entry.path())?.permissions();
                    perms.set_mode(0o755);
                    fs::set_permissions(entry.path(), perms)?;
                }
            }
        }
    }

    fs::write(libs_cache_dir.join(LIBS_EXTRACTION_MARKER), "")?;
    // Lock released on drop of lock_file
    let _ = lock_file;

    if debug {
        eprintln!("debug: extracted libs to {}", lib_dir.display());
    }

    Ok(Some(lib_dir))
}

/// Copy `src` to `dst` while preserving holes (sparseness), regardless of the
/// platform or filesystem.
///
/// `std::fs::copy` is *not* reliably hole-preserving. On Linux it prefers
/// `copy_file_range`/`sendfile`, but those fall back to a dense byte-for-byte
/// copy when the source and destination live on different mounts or on a
/// filesystem where the accelerated path isn't available — both common in CI
/// containers and under overlayfs. When that happens, a multi-GiB sparse
/// template (e.g. the 20 GiB `storage-template.ext4`, only ~25 MiB of which is
/// real data) is rehydrated into its full logical size of literal zeros on
/// disk, so two extractions can exhaust the runner and fail with ENOSPC.
///
/// This copy creates the destination as a sparse skeleton (`set_len` to the
/// source's logical size) and then writes only the chunks that contain non-zero
/// bytes, leaving every zero run as a hole. It mirrors the write-side
/// `assets::sparse_copy_overlay`, so behavior is consistent on both ends and on
/// APFS/ext4/xfs/NTFS alike. Reading over holes costs no disk I/O (the kernel
/// serves zero pages from cache), so scanning even a mostly-empty 20 GiB
/// template is fast.
///
/// Used on both ends: the extract/run side here, and the pack-create side in
/// `assets::create_storage_template` when it copies the pre-formatted
/// `storage-template.ext4` into the staging directory.
pub(crate) fn sparse_copy(src: &Path, dst: &Path) -> std::io::Result<()> {
    let mut src_file = File::open(src)?;
    let size = src_file.metadata()?.len();

    let mut dst_file = File::create(dst)?;
    // On Windows/NTFS a fresh file is dense: set_len-ing to a large size and then
    // writing chunks at high offsets would allocate the whole gap. Mark it sparse
    // first. Unix filesystems are sparse by default.
    #[cfg(windows)]
    mark_file_sparse(&dst_file)?;
    dst_file.set_len(size)?;

    // Forward pass: read in 512 KiB chunks, writing only chunks that contain a
    // non-zero byte. Zero chunks are skipped, so they stay as holes in `dst`.
    let mut buf = vec![0u8; 512 * 1024];
    let mut offset: u64 = 0;
    while offset < size {
        let to_read = (size - offset).min(buf.len() as u64) as usize;
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

    Ok(())
}

/// Create a storage disk file (empty sparse file).
pub fn create_storage_disk(path: &Path, size: u64) -> std::io::Result<()> {
    let file = File::create(path)?;
    // On Windows/NTFS, File::create makes a dense file; set_len to a multi-GiB
    // size would allocate every block. Mark it sparse first.
    #[cfg(windows)]
    mark_file_sparse(&file)?;
    file.set_len(size)?;
    Ok(())
}

/// Copy overlay disk template from cache to a runtime directory.
///
/// Copies the overlay template to `dest`, then restores the full sparse
/// skeleton if `overlay_logical_size` is set (new packs store a truncated
/// copy with the trailing hole stripped), and optionally extends further
/// when `size_gb_override` is larger still.
///
/// Returns an error if the template path is `None` or the template file
/// does not exist in the cache.
pub fn copy_overlay_template(
    cache_dir: &Path,
    template_path: Option<&str>,
    dest: &Path,
    size_gb_override: Option<u64>,
    overlay_logical_size: Option<u64>,
) -> std::io::Result<()> {
    let template = template_path.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "overlay template not specified in manifest",
        )
    })?;

    let src = resolve_cache_asset_path(cache_dir, template, "overlay template")?;
    if !src.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("overlay template not found: {}", src.display()),
        ));
    }

    // Hole-preserving copy: fs::copy can densify a sparse template on some
    // Linux filesystems/mounts, ballooning the overlay to its full logical size.
    sparse_copy(&src, dest)?;

    // Determine target size: max of the copied size, overlay_logical_size
    // (original sparse extent before trailing-hole truncation), and
    // size_gb_override (user-requested larger disk).  A single ftruncate
    // handles all three cases; ftruncate is instant and allocates no disk
    // blocks for the extended region.
    let copied_size = fs::metadata(dest)?.len();
    let target = [
        Some(copied_size),
        overlay_logical_size,
        size_gb_override.map(|gb| gb * 1024 * 1024 * 1024),
    ]
    .into_iter()
    .flatten()
    .max()
    .unwrap_or(copied_size);

    if target > copied_size {
        let file = fs::OpenOptions::new().write(true).open(dest)?;
        // On Windows/NTFS, extending with set_len would allocate every byte of
        // the gap unless the file is sparse. Mark it sparse first (idempotent).
        #[cfg(windows)]
        mark_file_sparse(&file)?;
        file.set_len(target)?;
    }

    Ok(())
}

/// Create or copy storage disk from template.
///
/// If a pre-formatted template exists in the cache, copy it.
/// Otherwise, create an empty sparse file (will be formatted by agent on first boot).
///
/// `size_gb_override` lets callers specify a custom disk size (in GiB).
/// When `None`, falls back to 512 MiB.
pub fn create_or_copy_storage_disk(
    cache_dir: &Path,
    template_path: Option<&str>,
    storage_path: &Path,
    size_gb_override: Option<u64>,
) -> std::io::Result<()> {
    if let Some(template) = template_path {
        let template_path = resolve_cache_asset_path(cache_dir, template, "storage template")?;
        if template_path.exists() {
            // Hole-preserving copy: a plain fs::copy densifies the (mostly-empty)
            // multi-GiB storage template on some Linux filesystems/mounts,
            // turning ~25 MiB of real data into its full logical size of zeros on
            // disk and risking ENOSPC when several extractions run.
            sparse_copy(&template_path, storage_path)?;
            // If a custom size was requested and it's larger than the template,
            // extend the sparse file (resize2fs in the agent will expand the FS).
            if let Some(gb) = size_gb_override {
                let desired = gb * 1024 * 1024 * 1024;
                let current = fs::metadata(storage_path)?.len();
                if desired > current {
                    let file = fs::OpenOptions::new().write(true).open(storage_path)?;
                    // On Windows/NTFS, extending with set_len would allocate the
                    // whole gap unless the file is sparse. Mark sparse first
                    // (idempotent).
                    #[cfg(windows)]
                    mark_file_sparse(&file)?;
                    file.set_len(desired)?;
                }
            }
            return Ok(());
        }
    }
    // Fallback: create empty sparse file (agent will format on first boot)
    let size = match size_gb_override {
        Some(gb) => gb * 1024 * 1024 * 1024,
        None => 512 * 1024 * 1024,
    };
    create_storage_disk(storage_path, size)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a single-file tar archive in memory with the given name and data.
    fn make_tar(name: &str, data: &[u8]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, name, data).unwrap();
        builder.into_inner().unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn test_unpack_sparse_rejects_symlink_at_destination() {
        use std::os::unix::fs::symlink;

        let temp_dir = tempfile::tempdir().unwrap();
        let outside = temp_dir.path().join("outside.bin");
        let dest = temp_dir.path().join("overlay.raw");

        fs::write(&outside, b"untouched").unwrap();
        symlink(&outside, &dest).unwrap(); // dest is now a symlink → outside

        let data = vec![0xFFu8; 512];
        let tar_bytes = make_tar("overlay.raw", &data);
        let mut archive = tar::Archive::new(tar_bytes.as_slice());
        let mut entry = archive.entries().unwrap().next().unwrap().unwrap();

        let real_dest = temp_dir.path().canonicalize().unwrap();
        let result = unpack_sparse(&mut entry, &dest, data.len() as u64, 0o644, &real_dest);

        assert!(result.is_err(), "should reject symlink at destination");
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
        // The symlink target must not be modified
        assert_eq!(fs::read(&outside).unwrap(), b"untouched");
    }

    /// Build a tar archive carrying a single symlink entry whose link target
    /// is `link_target`, plus (optionally) a trailing regular-file entry.
    fn make_symlink_tar(name: &str, link_target: &str) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        builder.append_link(&mut header, name, link_target).unwrap();
        builder.into_inner().unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn test_safe_unpack_rejects_symlink_entry_escaping_dest_relative() {
        // A crafted tar entry `evil -> ../../outside.bin` must be rejected by
        // safe_unpack before it is materialized: otherwise a later write
        // through `evil` would land outside the extraction directory.
        let temp_dir = tempfile::tempdir().unwrap();
        let outside = temp_dir.path().join("outside.bin");
        fs::write(&outside, b"untouched").unwrap();

        let dest = temp_dir.path().join("dest");
        fs::create_dir(&dest).unwrap();

        let tar_bytes = make_symlink_tar("evil", "../../outside.bin");
        let mut archive = tar::Archive::new(tar_bytes.as_slice());
        let result = safe_unpack(&mut archive, &dest);

        assert!(
            result.is_err(),
            "escaping relative symlink must be rejected"
        );
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
        assert!(!dest.join("evil").exists(), "symlink must not be created");
        assert_eq!(fs::read(&outside).unwrap(), b"untouched");
    }

    #[cfg(unix)]
    #[test]
    fn test_safe_unpack_rejects_symlink_entry_escaping_dest_absolute() {
        // An absolute-target symlink `evil -> /etc/passwd` is jailed to
        // `dest/etc/passwd`, staying inside dest, so it is allowed. But an
        // absolute target with `..` that climbs out (`/../escape`) must be
        // rejected — this guards the absolute-symlink jailing branch.
        let temp_dir = tempfile::tempdir().unwrap();
        let dest = temp_dir.path().join("dest");
        fs::create_dir(&dest).unwrap();

        let tar_bytes = make_symlink_tar("evil", "/../../escape");
        let mut archive = tar::Archive::new(tar_bytes.as_slice());
        let result = safe_unpack(&mut archive, &dest);

        assert!(
            result.is_err(),
            "escaping absolute symlink must be rejected"
        );
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
        assert!(!dest.join("evil").exists(), "symlink must not be created");
    }

    #[cfg(unix)]
    #[test]
    fn test_safe_unpack_allows_in_dest_symlink() {
        // A well-behaved relative symlink that stays within dest is accepted.
        let temp_dir = tempfile::tempdir().unwrap();
        let dest = temp_dir.path().join("dest");
        fs::create_dir(&dest).unwrap();

        let tar_bytes = make_symlink_tar("link", "target");
        let mut archive = tar::Archive::new(tar_bytes.as_slice());
        safe_unpack(&mut archive, &dest).unwrap();

        let meta = fs::symlink_metadata(dest.join("link")).unwrap();
        assert!(
            meta.file_type().is_symlink(),
            "in-dest symlink should exist"
        );
    }

    // ---------------------------------------------------------------------
    // Fix 1 (PRIMARY): the sparse-write path must NOT follow a symlink parent
    // component out of `dest`. Reproduces the host-escape: a prior entry plants
    // `foo -> <abs path OUTSIDE dest>`, then a sparse regular file under
    // `foo/...` tries to redirect the write through it. `safe_unpack` must
    // error AND write nothing at the escape target.
    // ---------------------------------------------------------------------
    #[cfg(unix)]
    #[test]
    fn test_safe_unpack_sparse_symlink_parent_escape_blocked() {
        use std::os::unix::fs::symlink;

        let temp_dir = tempfile::tempdir().unwrap();

        // Sentinel directory OUTSIDE dest (sibling under the temp dir). If the
        // escape worked, the payload would land here.
        let sentinel = temp_dir.path().join("ESCAPE");
        fs::create_dir(&sentinel).unwrap();

        let dest = temp_dir.path().join("dest");
        fs::create_dir(&dest).unwrap();

        // Plant the escaping symlink exactly as a prior tar entry would have:
        // `dest/foo` -> the sentinel dir outside dest. (Pre-planting instead of
        // relying on the tar crate's symlink-creation semantics keeps the test
        // deterministic; it reproduces the same on-disk state.)
        symlink(&sentinel, dest.join("foo")).unwrap();

        // A sparse regular file under `foo/...`: create_dir_all + open would
        // traverse the symlink parent and write into the sentinel. Small payload
        // + low sparse threshold forces the `unpack_sparse` path.
        let payload = vec![0xABu8; 4096];
        let tar_bytes = make_tar("foo/pwned.bin", &payload);

        let mut archive = tar::Archive::new(tar_bytes.as_slice());
        let limits = SafeUnpackLimits {
            max_entries: 1_000,
            max_total_bytes: 1 << 30,
            sparse_threshold: 512, // 4096-byte payload takes the sparse path
        };
        let result = safe_unpack_with_limits(&mut archive, &dest, &limits);

        assert!(
            result.is_err(),
            "symlink-parent escape via the sparse path must be rejected"
        );
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
        // Nothing may have been written through the escaping symlink.
        assert!(
            !sentinel.join("pwned.bin").exists(),
            "host file was written OUTSIDE dest — escape not blocked"
        );
    }

    // ---------------------------------------------------------------------
    // Fix 1b (root cause): an absolute symlink that aliases the dest ROOT
    // itself (`foo -> /`) is the parent-escape primitive and must be rejected
    // at creation — it must never appear on disk.
    // ---------------------------------------------------------------------
    #[cfg(unix)]
    #[test]
    fn test_safe_unpack_rejects_absolute_symlink_aliasing_root() {
        let temp_dir = tempfile::tempdir().unwrap();
        let dest = temp_dir.path().join("dest");
        fs::create_dir(&dest).unwrap();

        let tar_bytes = make_symlink_tar("foo", "/");
        let mut archive = tar::Archive::new(tar_bytes.as_slice());
        let result = safe_unpack(&mut archive, &dest);

        assert!(
            result.is_err(),
            "absolute symlink aliasing dest root must be rejected"
        );
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
        assert!(
            !dest.join("foo").exists() && fs::symlink_metadata(dest.join("foo")).is_err(),
            "root-aliasing symlink must never be created on disk"
        );
    }

    // ---------------------------------------------------------------------
    // Fix 1 (G): the sparse path must strip setuid/setgid/sticky bits, matching
    // the dense path — a hostile header must not yield a setuid host file.
    // ---------------------------------------------------------------------
    #[cfg(unix)]
    #[test]
    fn test_unpack_sparse_strips_setuid() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = tempfile::tempdir().unwrap();
        let dest = temp_dir.path().join("suid.bin");
        let real_dest = temp_dir.path().canonicalize().unwrap();

        let data = vec![0x11u8; 4096];
        let tar_bytes = make_tar("suid.bin", &data);
        let mut archive = tar::Archive::new(tar_bytes.as_slice());
        let mut entry = archive.entries().unwrap().next().unwrap().unwrap();

        // Header mode carries setuid (0o4000) + setgid (0o2000) + rwxr-xr-x.
        unpack_sparse(&mut entry, &dest, data.len() as u64, 0o6755, &real_dest).unwrap();

        let mode = fs::metadata(&dest).unwrap().permissions().mode() & 0o7777;
        assert_eq!(
            mode, 0o0755,
            "setuid/setgid/sticky bits must be stripped on the sparse path"
        );
    }

    // ---------------------------------------------------------------------
    // Fix 3: an archive exceeding the entry-count ceiling is rejected.
    // ---------------------------------------------------------------------
    #[test]
    fn test_safe_unpack_rejects_too_many_entries() {
        let temp_dir = tempfile::tempdir().unwrap();
        let dest = temp_dir.path().join("dest");
        fs::create_dir(&dest).unwrap();

        let mut builder = tar::Builder::new(Vec::new());
        for i in 0..10 {
            let data = b"x";
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            builder
                .append_data(&mut h, format!("file{i}.txt"), &data[..])
                .unwrap();
        }
        let tar_bytes = builder.into_inner().unwrap();

        let mut archive = tar::Archive::new(tar_bytes.as_slice());
        let limits = SafeUnpackLimits {
            max_entries: 3,
            max_total_bytes: 1 << 30,
            sparse_threshold: SPARSE_WRITE_THRESHOLD,
        };
        let err = safe_unpack_with_limits(&mut archive, &dest, &limits).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("max entry count"));
    }

    // ---------------------------------------------------------------------
    // Fix 3: an archive exceeding the total-bytes ceiling is rejected.
    // ---------------------------------------------------------------------
    #[test]
    fn test_safe_unpack_rejects_total_bytes_over_cap() {
        let temp_dir = tempfile::tempdir().unwrap();
        let dest = temp_dir.path().join("dest");
        fs::create_dir(&dest).unwrap();

        let data = vec![0u8; 4096];
        let tar_bytes = make_tar("big.bin", &data);

        let mut archive = tar::Archive::new(tar_bytes.as_slice());
        let limits = SafeUnpackLimits {
            max_entries: 1_000,
            max_total_bytes: 1024, // 4096-byte entry exceeds this
            sparse_threshold: SPARSE_WRITE_THRESHOLD,
        };
        let err = safe_unpack_with_limits(&mut archive, &dest, &limits).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("max total size"));
    }

    #[test]
    fn test_unpack_sparse_preserves_data_integrity() {
        let temp_dir = tempfile::tempdir().unwrap();
        let dest = temp_dir.path().join("data.raw");

        // Alternating 64 KiB zero and non-zero blocks: covers the skip-zero
        // path, the write-nonzero path, correct seek offsets, and the
        // ftruncate skeleton giving the right final size.
        let block = 64 * 1024;
        let mut data = vec![0u8; 8 * block];
        for i in (0..8).step_by(2) {
            data[i * block..(i + 1) * block].fill(0xFF);
        }

        let tar_bytes = make_tar("data.raw", &data);
        let mut archive = tar::Archive::new(tar_bytes.as_slice());
        let mut entry = archive.entries().unwrap().next().unwrap().unwrap();

        let real_dest = temp_dir.path().canonicalize().unwrap();
        unpack_sparse(&mut entry, &dest, data.len() as u64, 0o644, &real_dest).unwrap();

        assert_eq!(fs::read(&dest).unwrap(), data);
    }

    #[test]
    fn test_cache_dir_format() {
        let dir = get_cache_dir(0xDEADBEEF).unwrap();
        assert!(dir.to_string_lossy().contains("deadbeef"));
    }

    #[test]
    fn test_is_extracted() {
        let temp_dir = tempfile::tempdir().unwrap();

        assert!(!is_extracted(temp_dir.path()));

        fs::write(temp_dir.path().join(EXTRACTION_MARKER), "").unwrap();
        assert!(is_extracted(temp_dir.path()));
    }

    #[test]
    fn test_is_extracted_partial() {
        let temp_dir = tempfile::tempdir().unwrap();

        // Simulate partial extraction - files exist but no marker
        fs::create_dir_all(temp_dir.path().join("lib")).unwrap();
        fs::write(temp_dir.path().join("lib/libkrun.dylib"), "partial").unwrap();

        assert!(!is_extracted(temp_dir.path()));
    }

    #[test]
    fn test_sidecar_path_for() {
        let exe = Path::new("/path/to/my-app");
        let sidecar = sidecar_path_for(exe);
        assert_eq!(sidecar, PathBuf::from("/path/to/my-app.smolmachine"));
    }

    #[test]
    fn test_sidecar_mode_detection() {
        let sidecar_footer = PackFooter {
            stub_size: 0,
            assets_offset: 0,
            assets_size: 1000,
            manifest_offset: 1000,
            manifest_size: 500,
            checksum: 0x12345678,
        };
        assert!(is_sidecar_mode(&sidecar_footer));

        let embedded_footer = PackFooter {
            stub_size: 50000,
            assets_offset: 50000,
            assets_size: 1000,
            manifest_offset: 51000,
            manifest_size: 500,
            checksum: 0x12345678,
        };
        assert!(!is_sidecar_mode(&embedded_footer));
    }

    #[test]
    fn test_create_storage_disk() {
        let temp_dir = tempfile::tempdir().unwrap();
        let disk_path = temp_dir.path().join("test.ext4");

        create_storage_disk(&disk_path, 1024 * 1024).unwrap();

        assert!(disk_path.exists());
        assert_eq!(fs::metadata(&disk_path).unwrap().len(), 1024 * 1024);
    }

    #[test]
    fn test_copy_overlay_template_fails_when_none() {
        let temp_dir = tempfile::tempdir().unwrap();
        let dest = temp_dir.path().join("overlay.raw");

        let result = copy_overlay_template(temp_dir.path(), None, &dest, None, None);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn test_copy_overlay_template_fails_when_missing() {
        let temp_dir = tempfile::tempdir().unwrap();
        let dest = temp_dir.path().join("overlay.raw");

        let result =
            copy_overlay_template(temp_dir.path(), Some("nonexistent.raw"), &dest, None, None);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn test_copy_overlay_template_copies_and_extends() {
        let temp_dir = tempfile::tempdir().unwrap();
        let template = temp_dir.path().join("overlay.raw");
        let dest = temp_dir.path().join("output.raw");

        // Create a small template file (1 KB)
        let template_data = vec![0u8; 1024];
        fs::write(&template, &template_data).unwrap();

        // Copy without any size override or logical size
        copy_overlay_template(temp_dir.path(), Some("overlay.raw"), &dest, None, None).unwrap();
        assert_eq!(fs::metadata(&dest).unwrap().len(), 1024);

        // Copy with overlay_logical_size set — dest should be extended
        let dest2 = temp_dir.path().join("output2.raw");
        copy_overlay_template(
            temp_dir.path(),
            Some("overlay.raw"),
            &dest2,
            None,
            Some(4096),
        )
        .unwrap();
        assert_eq!(fs::metadata(&dest2).unwrap().len(), 4096);
    }

    #[test]
    fn test_copy_overlay_template_size_gb_takes_max() {
        let temp_dir = tempfile::tempdir().unwrap();
        let template = temp_dir.path().join("overlay.raw");
        fs::write(&template, vec![0u8; 1024]).unwrap();

        // size_gb_override wins when larger than overlay_logical_size
        let dest = temp_dir.path().join("out_a.raw");
        copy_overlay_template(
            temp_dir.path(),
            Some("overlay.raw"),
            &dest,
            Some(1), // 1 GiB
            Some(4096),
        )
        .unwrap();
        assert_eq!(fs::metadata(&dest).unwrap().len(), 1024 * 1024 * 1024);

        // overlay_logical_size wins when larger than size_gb_override
        let dest2 = temp_dir.path().join("out_b.raw");
        copy_overlay_template(
            temp_dir.path(),
            Some("overlay.raw"),
            &dest2,
            None,
            Some(8192), // overlay_logical_size bigger than template but smaller than size_gb_override test above
        )
        .unwrap();
        assert_eq!(fs::metadata(&dest2).unwrap().len(), 8192);
    }

    #[test]
    fn test_copy_overlay_template_rejects_traversal_path() {
        let temp_dir = tempfile::tempdir().unwrap();
        let outside = temp_dir.path().join("outside.raw");
        let dest = temp_dir.path().join("overlay.raw");
        fs::write(&outside, b"x").unwrap();

        let result =
            copy_overlay_template(temp_dir.path(), Some("../outside.raw"), &dest, None, None);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
    }

    #[cfg(unix)]
    #[test]
    fn test_create_or_copy_storage_disk_rejects_symlink_escape() {
        use std::os::unix::fs::symlink;

        let temp_dir = tempfile::tempdir().unwrap();
        let outside_dir = tempfile::tempdir().unwrap();
        let outside_file = outside_dir.path().join("storage-template.ext4");
        fs::write(&outside_file, b"template").unwrap();

        symlink(outside_dir.path(), temp_dir.path().join("symlink-out")).unwrap();

        let storage_path = temp_dir.path().join("storage.ext4");
        let result = create_or_copy_storage_disk(
            temp_dir.path(),
            Some("symlink-out/storage-template.ext4"),
            &storage_path,
            None,
        );
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
    }

    #[cfg(unix)]
    #[test]
    fn test_create_or_copy_storage_disk_preserves_sparseness() {
        use std::os::unix::fs::MetadataExt;

        // Build a sparse template: a small run of real data at the front, then a
        // large trailing hole (the shape of the real storage-template.ext4).
        let cache_dir = tempfile::tempdir().unwrap();
        let template = cache_dir.path().join("storage-template.ext4");
        {
            let mut f = File::create(&template).unwrap();
            // A few real (non-zero) bytes at the front...
            f.write_all(b"real ext4 superblock stand-in").unwrap();
            // ...then 1 GiB logical size, so the rest is a trailing hole.
            f.set_len(1024 * 1024 * 1024).unwrap();
        }

        let dest = cache_dir.path().join("storage.ext4");
        create_or_copy_storage_disk(cache_dir.path(), Some("storage-template.ext4"), &dest, None)
            .unwrap();

        let meta = fs::metadata(&dest).unwrap();
        // Logical size is preserved...
        assert_eq!(meta.len(), 1024 * 1024 * 1024);
        // ...but the destination must NOT be densified: allocated blocks
        // (512-byte units) should be a tiny fraction of the logical size. A
        // dense copy would report ~2M blocks (1 GiB); a sparse one only a few.
        let allocated_bytes = meta.blocks() * 512;
        assert!(
            allocated_bytes < 16 * 1024 * 1024,
            "storage disk was densified: {allocated_bytes} bytes allocated for a sparse template"
        );
    }

    #[test]
    fn test_extract_sidecar_skips_when_already_extracted() {
        // Verifies the double-check pattern inside the lock:
        // if the marker exists and force=false, extraction is a no-op.
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_dir = temp_dir.path().join("cache");
        fs::create_dir_all(&cache_dir).unwrap();

        // Write marker to simulate completed extraction
        fs::write(cache_dir.join(EXTRACTION_MARKER), "").unwrap();

        let dummy_footer = PackFooter {
            stub_size: 0,
            assets_offset: 0,
            assets_size: 0,
            manifest_offset: 0,
            manifest_size: 0,
            checksum: 0,
        };

        // Should succeed without trying to open a nonexistent sidecar,
        // because the marker check short-circuits.
        let result = extract_sidecar(
            Path::new("/nonexistent/sidecar.smolmachine"),
            &cache_dir,
            &dummy_footer,
            false, // force=false
            false,
        );
        // The sidecar doesn't exist, but we never try to open it because
        // the marker file is already present.
        // Note: the exists() check at the top will fail here, so this test
        // verifies the locking path only when the sidecar exists.
        // Let's adjust: use a real (empty) sidecar file for the existence check.
        drop(result);

        let dummy_sidecar = temp_dir.path().join("dummy.smolmachine");
        fs::write(&dummy_sidecar, b"").unwrap();

        let result = extract_sidecar(
            &dummy_sidecar,
            &cache_dir,
            &dummy_footer,
            false, // force=false
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_extract_sidecar_force_clears_marker() {
        // Verifies that force=true re-extracts even when the marker exists.
        // We can't do a full extraction without a real sidecar, so we verify
        // that force=true proceeds past the marker check (and then fails on
        // the actual extraction — which is fine for this test).
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_dir = temp_dir.path().join("cache-force");
        fs::create_dir_all(&cache_dir).unwrap();

        // Write marker
        fs::write(cache_dir.join(EXTRACTION_MARKER), "").unwrap();
        assert!(is_extracted(&cache_dir));

        // Create a dummy sidecar (empty — will fail during decompression)
        let dummy_sidecar = temp_dir.path().join("force.smolmachine");
        fs::write(&dummy_sidecar, b"not-a-real-zstd-stream").unwrap();

        let dummy_footer = PackFooter {
            stub_size: 0,
            assets_offset: 0,
            assets_size: 22, // matches "not-a-real-zstd-stream".len()
            manifest_offset: 22,
            manifest_size: 0,
            checksum: 0,
        };

        let result = extract_sidecar(
            &dummy_sidecar,
            &cache_dir,
            &dummy_footer,
            true, // force=true should bypass marker
            false,
        );

        // Should fail during decompression (not short-circuit on marker),
        // proving that force=true re-enters the extraction path.
        assert!(
            result.is_err(),
            "force extraction should attempt (and fail on dummy data)"
        );
    }

    /// Builds a tar archive in memory with the given entries.
    /// Each entry is (path, is_dir, content).
    fn build_tar(entries: &[(&str, bool, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, is_dir, content) in entries {
            let mut header = tar::Header::new_gnu();
            if *is_dir {
                header.set_entry_type(tar::EntryType::Directory);
                header.set_size(0);
                header.set_mode(0o755);
            } else {
                header.set_entry_type(tar::EntryType::Regular);
                header.set_size(content.len() as u64);
                header.set_mode(0o644);
            }
            header.set_cksum();
            builder
                .append_data(&mut header, *path, &content[..])
                .unwrap();
        }
        builder.into_inner().unwrap()
    }

    #[test]
    fn test_safe_unpack_normal_tar() {
        let temp_dir = tempfile::tempdir().unwrap();
        let dest_raw = temp_dir.path().join("out");
        fs::create_dir_all(&dest_raw).unwrap();
        // Canonicalize to resolve macOS /tmp -> /private/tmp symlink
        let dest = dest_raw.canonicalize().unwrap();

        let tar_data = build_tar(&[("dir/", true, b""), ("dir/file.txt", false, b"hello")]);
        let mut archive = tar::Archive::new(tar_data.as_slice());
        safe_unpack(&mut archive, &dest).unwrap();

        assert!(dest.join("dir").is_dir());
        assert_eq!(
            fs::read_to_string(dest.join("dir/file.txt")).unwrap(),
            "hello"
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_safe_unpack_case_collision_fails_on_case_insensitive_fs() {
        // On macOS case-insensitive APFS, extracting a tar with paths that
        // differ only in case (e.g., "lower" file vs "Lower/" directory)
        // should fail — callers must use a case-sensitive volume instead.
        let temp_dir = tempfile::tempdir().unwrap();
        let dest_raw = temp_dir.path().join("out");
        fs::create_dir_all(&dest_raw).unwrap();
        let dest = dest_raw.canonicalize().unwrap();

        let tar_data = build_tar(&[
            ("share/", true, b""),
            ("share/pkg/", true, b""),
            ("share/pkg/lower", false, b"script content"),
            ("share/pkg/Lower/", true, b""),
            ("share/pkg/Lower/__init__.py", false, b"python code"),
        ]);
        let mut archive = tar::Archive::new(tar_data.as_slice());

        // Should fail on case-insensitive APFS — the caller is responsible
        // for providing a case-sensitive destination (via acquire_layers_lease).
        let result = safe_unpack(&mut archive, &dest);
        assert!(
            result.is_err(),
            "case collision should fail on case-insensitive FS"
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_layers_lease_creates_and_cleans_volume() {
        // Verify that acquire_layers_lease creates a case-sensitive sparse
        // image, mounts it, and detaches on lease drop.
        // Skips gracefully if hdiutil is unavailable (CI, sandboxed envs).
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_dir = temp_dir.path().join("cache");
        // Create a dummy tar so has_layer_tars() returns true.
        fs::create_dir_all(cache_dir.join("layers")).unwrap();
        fs::write(cache_dir.join("layers/dummy.tar"), b"").unwrap();

        let lease = match acquire_layers_lease(&cache_dir, false) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("SKIP: hdiutil unavailable: {}", e);
                return;
            }
        };
        assert!(lease.path.exists());
        assert!(is_mount_point(&lease.path));

        // Both "lower" and "Lower" should coexist on the case-sensitive volume.
        fs::write(lease.path.join("lower"), "file").unwrap();
        fs::create_dir_all(lease.path.join("Lower")).unwrap();
        assert!(lease.path.join("lower").exists());
        assert!(lease.path.join("Lower").is_dir());

        // Lease file should exist while lease is held.
        let lease_file = cache_dir
            .join(LEASES_DIR)
            .join(format!("{}", std::process::id()));
        assert!(lease_file.exists());

        // Drop lease — should detach volume (last lease).
        let mount_point = lease.path.clone();
        drop(lease);
        assert!(
            !is_mount_point(&mount_point),
            "volume should be detached after last lease drop"
        );
    }

    #[test]
    fn test_safe_unpack_skips_char_and_block_devices() {
        // Char/Block entries appear in overlayfs exports from Debian images
        // (e.g., update-alternatives). They should be skipped, not rejected.
        let temp_dir = tempfile::tempdir().unwrap();
        let dest_raw = temp_dir.path().join("out");
        fs::create_dir_all(&dest_raw).unwrap();
        let dest = dest_raw.canonicalize().unwrap();

        let mut builder = tar::Builder::new(Vec::new());

        // Regular file before device entries
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(5);
        header.set_mode(0o644);
        header.set_path("before.txt").unwrap();
        header.set_cksum();
        builder
            .append_data(&mut header, "before.txt", &b"hello"[..])
            .unwrap();

        // Char device entry (should be skipped)
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Char);
        header.set_size(0);
        header.set_mode(0o644);
        header.set_path("etc/alternatives/pager.1.gz").unwrap();
        header.set_cksum();
        builder
            .append_data(&mut header, "etc/alternatives/pager.1.gz", &b""[..])
            .unwrap();

        // Block device entry (should be skipped)
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Block);
        header.set_size(0);
        header.set_mode(0o644);
        header.set_path("dev/sda").unwrap();
        header.set_cksum();
        builder
            .append_data(&mut header, "dev/sda", &b""[..])
            .unwrap();

        // Regular file after device entries (must survive)
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(5);
        header.set_mode(0o644);
        header.set_path("after.txt").unwrap();
        header.set_cksum();
        builder
            .append_data(&mut header, "after.txt", &b"world"[..])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();

        let mut archive = tar::Archive::new(tar_data.as_slice());
        let result = safe_unpack(&mut archive, &dest);
        assert!(
            result.is_ok(),
            "Char/Block entries should be skipped: {:?}",
            result.err()
        );

        // Files before AND after device entries are extracted
        assert_eq!(
            fs::read_to_string(dest.join("before.txt")).unwrap(),
            "hello"
        );
        assert_eq!(fs::read_to_string(dest.join("after.txt")).unwrap(), "world");

        // Device entries are not created
        assert!(!dest.join("etc/alternatives/pager.1.gz").exists());
        assert!(!dest.join("dev/sda").exists());
    }

    #[test]
    fn test_safe_unpack_skips_hardlink_to_whiteout() {
        // Overlayfs exports from Fedora produce hardlinks to char-device
        // whiteout entries (e.g., .build-id symlinks referencing replaced
        // base-layer files). The whiteout is skipped, so the hardlink target
        // doesn't exist — the hardlink must be skipped too.
        let temp_dir = tempfile::tempdir().unwrap();
        let dest_raw = temp_dir.path().join("out");
        fs::create_dir_all(&dest_raw).unwrap();
        let dest = dest_raw.canonicalize().unwrap();

        let mut builder = tar::Builder::new(Vec::new());

        // Char device whiteout (will be skipped)
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Char);
        header.set_size(0);
        header.set_mode(0o000);
        header.set_path("usr/lib/.build-id/84/target").unwrap();
        header.set_cksum();
        builder
            .append_data(&mut header, "usr/lib/.build-id/84/target", &b""[..])
            .unwrap();

        // Hardlink to the skipped whiteout (should also be skipped)
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Link);
        header.set_size(0);
        header.set_mode(0o000);
        header.set_path("usr/lib/.build-id/d9/link").unwrap();
        header.set_link_name("usr/lib/.build-id/84/target").unwrap();
        header.set_cksum();
        builder
            .append_data(&mut header, "usr/lib/.build-id/d9/link", &b""[..])
            .unwrap();

        // Regular file after (must survive)
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(2);
        header.set_mode(0o644);
        header.set_path("ok.txt").unwrap();
        header.set_cksum();
        builder
            .append_data(&mut header, "ok.txt", &b"ok"[..])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();

        let mut archive = tar::Archive::new(tar_data.as_slice());
        let result = safe_unpack(&mut archive, &dest);
        assert!(
            result.is_ok(),
            "hardlink to skipped whiteout should be skipped: {:?}",
            result.err()
        );

        // Whiteout and hardlink are not created
        assert!(!dest.join("usr/lib/.build-id/84/target").exists());
        assert!(!dest.join("usr/lib/.build-id/d9/link").exists());
        // Regular file survives
        assert_eq!(fs::read_to_string(dest.join("ok.txt")).unwrap(), "ok");
    }

    #[test]
    fn test_safe_unpack_readonly_parent_dir_does_not_block_children() {
        // Reproduces the Fedora extraction bug: a mode-555 directory entry
        // appears before its children in the tar. Without deferred permissions,
        // creating files inside the read-only directory fails.
        let temp_dir = tempfile::tempdir().unwrap();
        let dest_raw = temp_dir.path().join("out");
        fs::create_dir_all(&dest_raw).unwrap();
        let dest = dest_raw.canonicalize().unwrap();

        let mut builder = tar::Builder::new(Vec::new());

        // Parent directory with restrictive mode (read-only, no write)
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Directory);
        header.set_size(0);
        header.set_mode(0o555); // read + execute only, no write
        header.set_path("usr/lib64/pm-utils/").unwrap();
        header.set_cksum();
        builder
            .append_data(&mut header, "usr/lib64/pm-utils/", &b""[..])
            .unwrap();

        // Child directory inside the read-only parent
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Directory);
        header.set_size(0);
        header.set_mode(0o555);
        header.set_path("usr/lib64/pm-utils/module.d/").unwrap();
        header.set_cksum();
        builder
            .append_data(&mut header, "usr/lib64/pm-utils/module.d/", &b""[..])
            .unwrap();

        // File inside the nested read-only directory
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(4);
        header.set_mode(0o644);
        header
            .set_path("usr/lib64/pm-utils/module.d/test.conf")
            .unwrap();
        header.set_cksum();
        builder
            .append_data(
                &mut header,
                "usr/lib64/pm-utils/module.d/test.conf",
                &b"data"[..],
            )
            .unwrap();

        let tar_data = builder.into_inner().unwrap();

        let mut archive = tar::Archive::new(tar_data.as_slice());
        let result = safe_unpack(&mut archive, &dest);
        assert!(
            result.is_ok(),
            "read-only parent should not block children: {:?}",
            result.err()
        );

        // Child directory and file must exist
        assert!(dest.join("usr/lib64/pm-utils/module.d").is_dir());
        assert_eq!(
            fs::read_to_string(dest.join("usr/lib64/pm-utils/module.d/test.conf")).unwrap(),
            "data"
        );

        // Final permissions should be restored to the tar's mode (555)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dest.join("usr/lib64/pm-utils"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o555, "deferred directory mode should be 555");
        }
    }

    #[test]
    fn test_safe_unpack_mixed_fedora_overlay_layer() {
        // Realistic Fedora overlay layer: regular files interspersed with
        // whiteout char devices and hardlinks to those whiteouts.
        // All good files should extract; bad entries should be skipped.
        let temp_dir = tempfile::tempdir().unwrap();
        let dest_raw = temp_dir.path().join("out");
        fs::create_dir_all(&dest_raw).unwrap();
        let dest = dest_raw.canonicalize().unwrap();

        let mut builder = tar::Builder::new(Vec::new());

        // Directory
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Directory);
        header.set_size(0);
        header.set_mode(0o755);
        header.set_path("usr/").unwrap();
        header.set_cksum();
        builder.append_data(&mut header, "usr/", &b""[..]).unwrap();

        // Good file 1
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(11);
        header.set_mode(0o644);
        header.set_path("usr/good1.txt").unwrap();
        header.set_cksum();
        builder
            .append_data(&mut header, "usr/good1.txt", &b"good file 1"[..])
            .unwrap();

        // Char device whiteout
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Char);
        header.set_size(0);
        header.set_mode(0o000);
        header.set_device_major(0).unwrap();
        header.set_device_minor(0).unwrap();
        header.set_path("usr/.wh.removed-pkg").unwrap();
        header.set_cksum();
        builder
            .append_data(&mut header, "usr/.wh.removed-pkg", &b""[..])
            .unwrap();

        // Good file 2
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(11);
        header.set_mode(0o644);
        header.set_path("usr/good2.txt").unwrap();
        header.set_cksum();
        builder
            .append_data(&mut header, "usr/good2.txt", &b"good file 2"[..])
            .unwrap();

        // Hardlink to the whiteout (should be skipped)
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Link);
        header.set_size(0);
        header.set_mode(0o000);
        header.set_path("usr/link-to-removed").unwrap();
        header.set_link_name("usr/.wh.removed-pkg").unwrap();
        header.set_cksum();
        builder
            .append_data(&mut header, "usr/link-to-removed", &b""[..])
            .unwrap();

        // Good file 3
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(19); // == len("#!/usr/bin/env bash")
        header.set_mode(0o755);
        header.set_path("usr/good3.sh").unwrap();
        header.set_cksum();
        builder
            .append_data(&mut header, "usr/good3.sh", &b"#!/usr/bin/env bash"[..])
            .unwrap();

        // Another char device whiteout
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Char);
        header.set_size(0);
        header.set_mode(0o000);
        header.set_device_major(0).unwrap();
        header.set_device_minor(0).unwrap();
        header.set_path("usr/.wh.another-removed").unwrap();
        header.set_cksum();
        builder
            .append_data(&mut header, "usr/.wh.another-removed", &b""[..])
            .unwrap();

        // Good file 4 (final entry)
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(5);
        header.set_mode(0o644);
        header.set_path("usr/good4.dat").unwrap();
        header.set_cksum();
        builder
            .append_data(&mut header, "usr/good4.dat", &b"final"[..])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();

        let mut archive = tar::Archive::new(tar_data.as_slice());
        let result = safe_unpack(&mut archive, &dest);
        assert!(
            result.is_ok(),
            "mixed Fedora overlay should extract cleanly: {:?}",
            result.err()
        );

        // Good files are all extracted
        assert_eq!(
            fs::read_to_string(dest.join("usr/good1.txt")).unwrap(),
            "good file 1"
        );
        assert_eq!(
            fs::read_to_string(dest.join("usr/good2.txt")).unwrap(),
            "good file 2"
        );
        assert_eq!(
            fs::read_to_string(dest.join("usr/good3.sh")).unwrap(),
            "#!/usr/bin/env bash"
        );
        assert_eq!(
            fs::read_to_string(dest.join("usr/good4.dat")).unwrap(),
            "final"
        );

        // Bad entries are not created
        assert!(!dest.join("usr/.wh.removed-pkg").exists());
        assert!(!dest.join("usr/link-to-removed").exists());
        assert!(!dest.join("usr/.wh.another-removed").exists());
    }

    #[test]
    fn test_safe_unpack_unknown_tar_type_byte() {
        // Entry with unknown tar type byte (0x41 = 'A') — a vendor extension
        // not recognized by the tar crate (maps to __Nonexhaustive).
        // Should be skipped gracefully by safe_unpack's catch-all arm.
        // Note: byte '7' maps to EntryType::Continuous which is allowed.
        let temp_dir = tempfile::tempdir().unwrap();
        let dest_raw = temp_dir.path().join("out");
        fs::create_dir_all(&dest_raw).unwrap();
        let dest = dest_raw.canonicalize().unwrap();

        let mut builder = tar::Builder::new(Vec::new());

        // Regular file before the unknown entry
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(6);
        header.set_mode(0o644);
        header.set_path("before.txt").unwrap();
        header.set_cksum();
        builder
            .append_data(&mut header, "before.txt", &b"before"[..])
            .unwrap();

        // Unknown type byte entry ('A' = 0x41, truly unrecognized)
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::new(b'A'));
        header.set_size(0);
        header.set_mode(0o644);
        header.set_path("unknown-type-entry").unwrap();
        header.set_cksum();
        builder
            .append_data(&mut header, "unknown-type-entry", &b""[..])
            .unwrap();

        // Regular file after
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(5);
        header.set_mode(0o644);
        header.set_path("after.txt").unwrap();
        header.set_cksum();
        builder
            .append_data(&mut header, "after.txt", &b"after"[..])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();

        let mut archive = tar::Archive::new(tar_data.as_slice());
        let result = safe_unpack(&mut archive, &dest);
        assert!(
            result.is_ok(),
            "unknown tar type should be skipped: {:?}",
            result.err()
        );

        assert_eq!(
            fs::read_to_string(dest.join("before.txt")).unwrap(),
            "before"
        );
        assert_eq!(fs::read_to_string(dest.join("after.txt")).unwrap(), "after");
        assert!(!dest.join("unknown-type-entry").exists());
    }

    #[test]
    fn test_evict_cache_to_size_lru() {
        use std::ffi::CString;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let mk = |name: &str, mtime_secs: i64| {
            let d = root.join(name);
            fs::create_dir_all(&d).unwrap();
            fs::write(d.join("data"), vec![0u8; 1024 * 1024]).unwrap(); // ~1 MiB real
            let c = CString::new(d.to_string_lossy().as_bytes()).unwrap();
            let tv = libc::timeval {
                tv_sec: mtime_secs,
                tv_usec: 0,
            };
            let times = [tv, tv];
            unsafe {
                libc::utimes(c.as_ptr(), times.as_ptr());
            }
            d
        };
        let old = mk("aaaa", 1_000_000);
        let mid = mk("bbbb", 2_000_000);
        let new = mk("cccc", 3_000_000);

        // Total (~3 MiB) is under the cap → nothing evicted.
        assert_eq!(evict_cache_to_size(root, 100 * 1024 * 1024), 0);
        assert!(old.exists() && mid.exists() && new.exists());

        // Cap (~2.5 MiB) forces evicting the single oldest entry, LRU-first.
        let freed = evict_cache_to_size(root, 5 * 1024 * 1024 / 2);
        assert!(freed > 0, "expected some bytes freed");
        assert!(!old.exists(), "oldest extraction should be evicted");
        assert!(mid.exists() && new.exists(), "newer extractions kept");
    }

    #[test]
    fn test_evict_cache_protects_current_extraction() {
        use std::ffi::CString;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let mk = |name: &str, mtime_secs: i64| {
            let d = root.join(name);
            fs::create_dir_all(&d).unwrap();
            fs::write(d.join("data"), vec![0u8; 4 * 1024 * 1024]).unwrap(); // ~4 MiB real
            let c = CString::new(d.to_string_lossy().as_bytes()).unwrap();
            let tv = libc::timeval {
                tv_sec: mtime_secs,
                tv_usec: 0,
            };
            let times = [tv, tv];
            unsafe {
                libc::utimes(c.as_ptr(), times.as_ptr());
            }
            d
        };
        // The dir we just wrote is the NEWEST but still larger than the cap on
        // its own — the exact torch-pack shape (one ~13 GiB extraction vs a 5 GiB
        // cap). Without protection, oldest-first eviction would reach it and
        // delete the very assets about to boot.
        let old = mk("aaaa", 1_000_000);
        let current = mk("cccc", 3_000_000);

        // Cap smaller than `current` alone: everything is "over cap".
        let freed = evict_cache_to_size_protecting(root, 1024 * 1024, Some(&current));
        assert!(freed > 0, "the old entry should still be evicted");
        assert!(!old.exists(), "oldest unprotected extraction evicted");
        assert!(
            current.exists() && current.join("data").exists(),
            "the protected (just-extracted) dir must survive even over cap"
        );
    }

    // Lease tracking is a macOS case-sensitive-volume concept; on Linux
    // `has_active_leases` is always false (layers live at cache_dir/layers).
    #[cfg(target_os = "macos")]
    #[test]
    fn test_evict_cache_skips_active_lease() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let d = root.join("aaaa");
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("data"), vec![0u8; 2 * 1024 * 1024]).unwrap();
        // Simulate a running pack: a live daemon lease file (current PID).
        let leases = d.join(LEASES_DIR);
        fs::create_dir_all(&leases).unwrap();
        fs::write(leases.join("daemon"), format!("{}", std::process::id())).unwrap();
        assert!(has_active_leases(&d), "live lease should be detected");
        // Cap of 0 would evict everything — but the active lease must be spared.
        let freed = evict_cache_to_size(root, 0);
        assert_eq!(freed, 0, "leased extraction must not be evicted");
        assert!(d.exists());
    }
}
