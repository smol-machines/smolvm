//! Asset extraction for packed binaries.
//!
//! Provides shared extraction logic used by both the main `smolvm` binary
//! (sidecar mode via `runpack`) and the standalone stub executable.

use crate::format::{PackFooter, SIDECAR_EXTENSION};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
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

/// Restore a tar entry's numeric owner on `path`, ignoring errors. No-op on
/// non-Unix targets and whenever the process cannot change ownership.
///
/// Container images address their service accounts by numeric id — postgres is
/// uid 999, nginx 101, mysql 999 — and the guest sees the unpacked tree through
/// virtiofs with those host ids intact. Dropping them makes every file root's,
/// so the service cannot read the data directory it owns: PostgreSQL refuses to
/// start on a root-owned PGDATA, which is how this surfaced. The tar headers
/// carry the right ids; only the extraction discarded them.
///
/// `lchown`, not `chown`, so a symlink entry is not dereferenced and its target
/// re-owned instead.
///
/// Only attempted as root. An unprivileged extraction — the normal case on
/// macOS, where the VM's uid mapping makes the host owner irrelevant anyway —
/// can only ever chown to itself, so EPERM there is expected rather than a
/// failure worth reporting. Callers still mask setuid/setgid out of the mode,
/// so a hostile header cannot pair a chosen owner with an escalating bit.
#[inline]
fn set_owner(path: &Path, uid: u64, gid: u64) {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        if let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_bytes()) {
            unsafe {
                libc::lchown(c_path.as_ptr(), uid as libc::uid_t, gid as libc::gid_t);
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, uid, gid);
    }
}

/// Whether unpacking a pack's layers on this host reproduces the uid/gid the
/// archive recorded.
///
/// Only root on a Unix host can: `chown` to another id requires the privilege,
/// and Windows has no POSIX owner to restore at all. Unpacking anywhere else
/// silently re-owns every file to whoever ran the command — a container image's
/// postgres files (uid 999) land owned by the host user, and the service then
/// cannot read the data directory it owns.
///
/// When this is false the layers are staged as tars instead and unpacked inside
/// the guest, where the agent is always root. Host-side unpacking stays the
/// default where it is faithful, because one extracted copy is shared by every
/// VM built on the pack; the in-guest copy lives on a single machine's disk.
fn host_unpack_preserves_ownership() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// First release whose in-guest agent unpacks host-staged layer tars.
///
/// Staging was introduced together with that agent. A pack built before it
/// carries an agent that only recognises layer *directories*, so handing one
/// staged tars leaves `/packed_layers` with nothing it can use and the machine
/// dies with "no layer directories found in /packed_layers" — an error that
/// describes the host's staging area and says nothing about the real mismatch.
const MIN_STAGED_LAYERS_VERSION: (u64, u64, u64) = (1, 8, 1);

/// Whether the agent baked into a pack built by `version` can unpack staged
/// layer tars itself.
///
/// An absent or unreadable version answers "no". `smolvm_version` is a
/// defaulted field, so a pack without one necessarily predates it, and the
/// conservative answer merely costs host-side extraction — while guessing "yes"
/// costs a machine that will not boot.
fn packed_agent_unpacks_staged_layers(version: &str) -> bool {
    let Some(parsed) = parse_pack_version(version) else {
        return false;
    };
    parsed >= (MIN_STAGED_LAYERS_VERSION, true)
}

/// `((major, minor, patch), is_release)` from a pack's recorded version.
///
/// The bool carries prerelease ordering: `1.8.1-rc.1` predates the `1.8.1` that
/// introduced staging, so comparing the numbers alone would credit it with a
/// capability it does not have. Ordering `false < true` at equal numbers is
/// exactly the semver rule, without taking on a dependency for one comparison.
fn parse_pack_version(version: &str) -> Option<((u64, u64, u64), bool)> {
    let version = version.trim().trim_start_matches('v');
    if version.is_empty() {
        return None;
    }
    // Build metadata never affects precedence; a prerelease suffix does.
    let version = version.split('+').next()?;
    let (core, is_release) = match version.split_once('-') {
        Some((core, _prerelease)) => (core, false),
        None => (version, true),
    };
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    // A two-component "1.8" is not valid semver but is worth reading as 1.8.0
    // rather than refusing a version the pack plainly states.
    let minor = parts.next().unwrap_or("0").parse().ok()?;
    let patch = parts.next().unwrap_or("0").parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some(((major, minor, patch), is_release))
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

/// Safely unpack a tar archive: symlinks and hardlinks are allowed only when
/// their targets stay within `dest`, and any entry that resolves outside `dest`
/// is rejected.
///
/// The standard `tar::Archive::unpack()` strips `..` components but does
/// **not** validate symlink targets. A crafted archive could create
/// `lib/libkrun.dylib → /tmp/evil.so`, and subsequent `dlopen()` would
/// load the attacker's library. This function validates every symlink and
/// hardlink target against `dest` (rejecting escaping links and absolute
/// links that alias the destination root) and opens regular files with
/// `O_NOFOLLOW` plus a canonicalized-parent check, so a write can never
/// follow a planted symlink out of `dest`.
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
        //
        // Every directory has to be recorded, not just ones the owner cannot
        // write: each is forced to 0755 below so its children can be created, so
        // any mode that is not 0755 is lost unless it is restored afterwards.
        // Only checking for a missing owner-write bit caught `dr-xr-xr-x` while
        // silently widening the far more common restrictive-but-writable modes —
        // a 0700 data directory arrived as 0755, which PostgreSQL refuses to
        // start on, and a 0700 `.ssh` arrived world-readable.
        //
        // Masked to the permission bits so a hostile header cannot carry setuid,
        // setgid or sticky through, matching the sparse path.
        if entry_type == tar::EntryType::Directory {
            let mode = entry.header().mode().unwrap_or(0o755) & 0o777;
            if mode != 0o755 {
                deferred_dir_modes.push((full_path.clone(), mode));
            }
        }

        let is_regular =
            entry_type == tar::EntryType::Regular || entry_type == tar::EntryType::GNUSparse;

        // Read the owner off the header before the entry is consumed: the
        // sparse path streams `entry` to exhaustion, after which the header is
        // still available but reading it here keeps both branches symmetric.
        let uid = entry.header().uid().unwrap_or(0);
        let gid = entry.header().gid().unwrap_or(0);

        // GNU sparse entries already carry an exact extent map. Let the tar
        // reader seek over those holes directly instead of expanding them and
        // rediscovering zero chunks in `unpack_sparse`. This is especially
        // important for portable RAM images: scanning a mostly-empty 1 GiB
        // guest address space made checkpoint import take seconds even though
        // only tens of MiB were present in the archive.
        if entry_type == tar::EntryType::GNUSparse {
            verify_parent_within_dest(&full_path, &real_dest)?;
            if let Err(e) = entry.unpack_in(dest) {
                return Err(std::io::Error::new(
                    e.kind(),
                    format!("failed to unpack '{}': {}", entry_path.display(), e),
                ));
            }
            // `Entry::unpack_in` handles the sparse extent stream, while these
            // final assignments retain safe_unpack's permission policy.
            set_mode(&full_path, entry.header().mode().unwrap_or(0o644) & 0o777);
            set_owner(&full_path, uid, gid);
        // For large ordinary files use a sparse write: ftruncate creates the
        // hole skeleton, then we only pwrite non-zero 64 KiB chunks.  This
        // prevents 10 GiB overlay disks from materialising as dense files on
        // disk and causing ENOSPC or slow extraction.
        } else if is_regular && entry.header().size().unwrap_or(0) >= limits.sparse_threshold {
            let entry_size = entry.header().size()?;
            let mode = entry.header().mode().unwrap_or(0o644);
            if let Err(e) = unpack_sparse(&mut entry, &full_path, entry_size, mode, &real_dest) {
                return Err(std::io::Error::new(
                    e.kind(),
                    format!("failed to unpack '{}': {}", entry_path.display(), e),
                ));
            }
            set_owner(&full_path, uid, gid);
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

            // Ownership after the mode is in place: chown clears setuid/setgid,
            // and the deferred directory pass below only restores modes, never
            // owners, so doing it here is the single point that applies.
            set_owner(&full_path, uid, gid);
        }
    }

    // Apply deferred directory permissions now that all children are written.
    //
    // Deepest first: a tar lists a parent before its children, and restoring a
    // parent that drops the owner's execute bit (0o444, say) would make every
    // path beneath it untraversable, so the children's own restores would fail.
    deferred_dir_modes.sort_by_key(|(path, _)| std::cmp::Reverse(path.components().count()));
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

/// Whether an extraction's `layers/` cache is structurally usable: every id in
/// its `layer-order` index resolves to a layer dir or staged tar, or (with no
/// index) at least one layer entry exists. The extraction MARKER only proves an
/// extraction once finished — a cache cleaner that deletes the large layer
/// files but leaves the tiny marker produces a cache that passes `is_extracted`
/// yet can neither boot nor export, and the marker then blocks the re-extract
/// that would repair it. Callers that need the layers should require BOTH.
pub fn cached_layers_usable(cache_dir: &Path) -> bool {
    let layers_dir = cache_dir.join("layers");
    let has_form =
        |id: &str| layers_dir.join(id).is_dir() || layers_dir.join(format!("{id}.tar")).is_file();
    if let Ok(contents) = fs::read_to_string(layers_dir.join("layer-order")) {
        let ids: Vec<&str> = contents
            .lines()
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .collect();
        return !ids.is_empty() && ids.iter().all(|id| has_form(id));
    }
    fs::read_dir(&layers_dir)
        .map(|rd| {
            rd.flatten().any(|e| {
                let path = e.path();
                path.is_dir() || path.extension().is_some_and(|x| x == "tar")
            })
        })
        .unwrap_or(false)
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
/// reference-shared across many VMs via durable `.pack-shared` pointer leases,
/// but this generic size cap does not inspect those pointers. Blindly capping
/// the shared root could therefore evict a pack still mounted by live pool VMs —
/// their `/packed_layers` then reads empty and the guest fails with "no layer
/// directories found in /packed_layers" (exit 255 on connect/exec). Explicit
/// `smolvm pack prune` performs the reference-aware cleanup instead. See
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
    // cap_cache=false: never perform blind automatic LRU eviction here. Shared
    // entries are maintained explicitly by `smolvm pack prune`, which treats
    // each machine's `.pack-shared` pointer as a durable lease and therefore
    // cannot delete a pack mounted by a running or stopped VM.
    extract_sidecar_capped(sidecar_path, &shared_dir, footer, false, debug, false)?;
    ensure_shared_artifact_sha256(sidecar_path, &shared_dir)?;
    // Lock down the store so a dropped per-VM uid can't read the shared copy
    // directly (it must go through its idmapped mount). Best-effort: traversal
    // by root (the VMM before it drops privileges) is unaffected by 0700.
    restrict_to_owner(shared_root);
    restrict_to_owner(&shared_dir);
    Ok(shared_dir)
}

/// Path of the cached SHA-256 identity for one shared artifact extraction.
///
/// The digest sits beside (rather than inside) the extracted tree so the tree
/// remains byte-for-byte identical to a private extraction and can continue to
/// be mounted read-only into guests.
pub fn shared_artifact_sha256_path(shared_dir: &Path) -> PathBuf {
    shared_dir.with_extension("artifact-sha256")
}

/// Read and validate the full-artifact SHA-256 cached for a shared extraction.
/// Returns the lowercase 64-character hex digest without an algorithm prefix.
pub fn read_shared_artifact_sha256(shared_dir: &Path) -> std::io::Result<String> {
    let path = shared_artifact_sha256_path(shared_dir);
    let digest = fs::read_to_string(&path)?.trim().to_string();
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid artifact SHA-256 marker: {}", path.display()),
        ));
    }
    Ok(digest)
}

#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct ArtifactSourceIdentity {
    canonical_path: String,
    len: u64,
    modified_secs: Option<u64>,
    modified_nanos: Option<u32>,
}

fn artifact_source_identity(sidecar_path: &Path) -> std::io::Result<ArtifactSourceIdentity> {
    let canonical = sidecar_path.canonicalize()?;
    let metadata = fs::metadata(&canonical)?;
    let modified = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok());
    Ok(ArtifactSourceIdentity {
        canonical_path: canonical.to_string_lossy().into_owned(),
        len: metadata.len(),
        modified_secs: modified.map(|duration| duration.as_secs()),
        modified_nanos: modified.map(|duration| duration.subsec_nanos()),
    })
}

fn shared_artifact_source_path(shared_dir: &Path) -> PathBuf {
    shared_dir.with_extension("artifact-source.json")
}

fn hash_artifact_sha256(sidecar_path: &Path) -> std::io::Result<String> {
    let mut source = File::open(sidecar_path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 4 * 1024 * 1024];
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let mut digest = String::with_capacity(64);
    for byte in hasher.finalize() {
        write!(&mut digest, "{byte:02x}").expect("writing to a String cannot fail");
    }
    Ok(digest)
}

fn write_atomic_marker(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let tmp_path = path.with_extension(format!("tmp-{}", std::process::id()));
    // A process may have died after creating its PID-scoped temp file. The
    // caller's flock proves no live writer owns it now.
    if tmp_path.exists() {
        fs::remove_file(&tmp_path)?;
    }
    let write_result = (|| {
        let mut tmp = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp_path)?;
        tmp.write_all(contents)?;
        tmp.sync_all()?;
        fs::rename(&tmp_path, path)?;
        Ok::<(), std::io::Error>(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    write_result
}

/// Compute a shared artifact's full SHA-256 once, atomically, under a lock.
///
/// The pack footer uses CRC32 for compatibility. Disk COW bases need a
/// collision-resistant identity, so the first shared extraction pays one
/// streaming hash pass and every later machine only reads this tiny marker.
fn ensure_shared_artifact_sha256(
    sidecar_path: &Path,
    shared_dir: &Path,
) -> std::io::Result<String> {
    let digest_path = shared_artifact_sha256_path(shared_dir);
    let lock_path = digest_path.with_extension("artifact-sha256.lock");
    let lock_file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)?;
    lock_file_exclusive(&lock_file)?;

    let source_path = shared_artifact_source_path(shared_dir);
    let source_identity = artifact_source_identity(sidecar_path)?;
    if digest_path.exists() {
        let cached_digest = read_shared_artifact_sha256(shared_dir)?;
        let cached_source = fs::read(&source_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<ArtifactSourceIdentity>(&bytes).ok());
        if cached_source.as_ref() == Some(&source_identity) {
            return Ok(cached_digest);
        }

        // The shared extraction directory is historically keyed by the pack's
        // CRC32 footer. If a different artifact ever collides with that key,
        // fail instead of associating its SHA-256 with the already-extracted
        // bytes. A second path to identical content is safe and refreshes the
        // cheap source fingerprint for later warm creates.
        let actual_digest = hash_artifact_sha256(sidecar_path)?;
        if actual_digest != cached_digest {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "shared pack checksum collision at {}: artifact SHA-256 differs",
                    shared_dir.display()
                ),
            ));
        }
        write_atomic_marker(
            &source_path,
            &serde_json::to_vec(&source_identity)
                .map_err(|error| std::io::Error::other(error.to_string()))?,
        )?;
        return Ok(cached_digest);
    }

    let digest = hash_artifact_sha256(sidecar_path)?;
    write_atomic_marker(&digest_path, format!("{digest}\n").as_bytes())?;
    write_atomic_marker(
        &source_path,
        &serde_json::to_vec(&source_identity)
            .map_err(|error| std::io::Error::other(error.to_string()))?,
    )?;
    Ok(digest)
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

    // A sidecar can be any age while the smolvm running it is current, so its
    // manifest is the only thing that says what the agent inside can do.
    let manifest = crate::packer::read_manifest_from_sidecar(sidecar_path).ok();

    // Layer order from the sidecar manifest (bottom→top). Best-effort: if the
    // manifest can't be read the agent falls back to a name sort.
    let layer_order = manifest
        .as_ref()
        .map(|m| {
            m.assets
                .layers
                .iter()
                .filter_map(|l| layer_id_from_asset_path(&l.path))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let pack_version = manifest.as_ref().map(|m| m.smolvm_version.as_str());
    let guest_unpacks_layers = pack_version.is_some_and(packed_agent_unpacks_staged_layers);
    if !guest_unpacks_layers && !host_unpack_preserves_ownership() && has_layer_tars(cache_dir) {
        // Extracting here is what every smolvm did before staging existed, so
        // the pack runs exactly as it always has. Say why anyway: the ownership
        // this loses is silent at extraction time and only shows up later as a
        // service that cannot read its own data directory.
        eprintln!(
            "warning: this pack was built by smolvm {}, whose in-guest agent cannot unpack \
             staged layers; extracting them on the host instead.\n\
             warning: file ownership inside the machine will follow the current user rather \
             than the image. Re-pack with smolvm {}.{}.{} or later to restore it.",
            pack_version
                .filter(|v| !v.is_empty())
                .unwrap_or("an unknown version"),
            MIN_STAGED_LAYERS_VERSION.0,
            MIN_STAGED_LAYERS_VERSION.1,
            MIN_STAGED_LAYERS_VERSION.2,
        );
    }

    post_process_extraction(cache_dir, &layer_order, guest_unpacks_layers, debug)?;
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
        // order from here, so let the agent fall back to a name sort. The stub
        // and the agent it carries were built by the same release, so staging
        // can never outrun the agent the way a sidecar from another version can.
        post_process_extraction(cache_dir, &[], true, debug)?;
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

    // Mach-O section self-exec stub: same as embedded mode — name-sort fallback,
    // and likewise self-consistent on staging.
    post_process_extraction(cache_dir, &[], true, debug)?;
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
    guest_unpacks_layers: bool,
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
    if layers_dir.exists() && !host_unpack_preserves_ownership() && guest_unpacks_layers {
        // This host cannot reproduce the archived uid/gid (see
        // `host_unpack_preserves_ownership`), so leave the tars staged and let
        // the guest agent unpack them, where it is root on every host OS.
        // Only the stacking order has to be recorded here, against the tars.
        if debug {
            eprintln!("debug: staging OCI layers for in-guest extraction...");
        }
        if !layer_order.is_empty() {
            let lines: Vec<&str> = layer_order
                .iter()
                .filter(|id| layers_dir.join(format!("{id}.tar")).is_file())
                .map(String::as_str)
                .collect();
            if !lines.is_empty() {
                fs::write(layers_dir.join(LAYER_ORDER_FILE), lines.join("\n"))?;
            }
        }
    } else if layers_dir.exists() {
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
        // The case-sensitive volume only ever holds HOST-extracted layers.
        // When the host stages tars for in-guest extraction instead (see
        // `host_unpack_preserves_ownership`), the tars live in
        // `cache_dir/layers` and the volume was never created — returning it
        // here would hand the guest an empty directory. An existing sparse
        // image still wins, so packs extracted by an earlier version (or by a
        // root run) keep mounting the volume they were extracted into.
        let image_path = cache_dir.join(CS_IMAGE_NAME);
        if image_path.exists() || (host_unpack_preserves_ownership() && has_layer_tars(cache_dir)) {
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
        // Same gate as `acquire_layers_lease`: staged tars are shared to the
        // guest from `cache_dir/layers` directly, so the case-sensitive volume
        // is only in play when the host extracted into it.
        let image_path = cache_dir.join(CS_IMAGE_NAME);
        if image_path.exists() || (host_unpack_preserves_ownership() && has_layer_tars(cache_dir)) {
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

/// Whether the cache holds layer tars the host has not unpacked.
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

    // Reclaim volumes stranded by runs that were killed before releasing.
    reap_orphan_volumes(cache_dir);

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

/// The sibling cache directories that may hold a stranded volume.
///
/// Two layouts use this protocol: `<root>/<hash>` (standalone packs) and
/// `<root>/<hash>/pack` (VM-backed packs). Both are handled by walking up to the
/// directory that *contains the hashes* and re-applying our own suffix, so we
/// only ever look at peers of the same shape.
#[cfg(target_os = "macos")]
fn sibling_cache_dirs(cache_dir: &Path) -> Vec<PathBuf> {
    let nested = cache_dir.file_name().is_some_and(|n| n == "pack");
    let Some(root) = (if nested {
        cache_dir.parent().and_then(Path::parent)
    } else {
        cache_dir.parent()
    }) else {
        return Vec::new();
    };
    let Ok(entries) = fs::read_dir(root) else {
        return Vec::new();
    };
    entries
        .filter_map(|e| e.ok())
        .map(|e| {
            if nested {
                e.path().join("pack")
            } else {
                e.path()
            }
        })
        .filter(|p| p != cache_dir && p.is_dir())
        .collect()
}

/// Detach case-sensitive volumes stranded by runs that never released.
///
/// A run that is killed (or crashes) skips [`release_lease`], leaving its volume
/// mounted with a lease file whose PID is dead. Its *own* directory self-heals —
/// the next run of that same artifact acquires, GCs the dead lease, and detaches
/// on release. What never heals is an artifact that is not run again: its volume
/// holds a `/dev/diskN` for the life of the login session, and enough of them
/// exhaust the device table. So the sweep is over *siblings*, not self.
///
/// Each peer is locked non-blocking: a directory whose lock is held has a live
/// process inside acquire/release, which by definition is not stranded, and
/// blocking on it would let an unrelated artifact stall this run.
#[cfg(target_os = "macos")]
fn reap_orphan_volumes(cache_dir: &Path) {
    for dir in sibling_cache_dirs(cache_dir) {
        let mount_point = dir.join(CS_MOUNT_DIR);
        if !mount_point.exists() || !is_mount_point(&mount_point) {
            continue;
        }
        let Ok(lock) = try_lock_leases(&dir) else {
            continue;
        };
        gc_stale_leases(&dir.join(LEASES_DIR));
        detach_if_unused(&dir);
        drop(lock);
    }
}

/// Acquire the leases lock, or fail immediately if another process holds it.
#[cfg(target_os = "macos")]
fn try_lock_leases(cache_dir: &Path) -> std::io::Result<File> {
    let lock_path = cache_dir.join(LEASES_LOCK);
    let lock_file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)?;
    let ret = unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(lock_file)
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
/// source's logical size) and then writes only the regions that hold real data,
/// leaving every zero run as a hole. It mirrors the write-side
/// `assets::sparse_copy_overlay`, so behavior is consistent on both ends and on
/// APFS/ext4/xfs/NTFS alike.
///
/// The holes are located by asking the filesystem (`SEEK_DATA`/`SEEK_HOLE`)
/// rather than by reading across them. Reading a hole costs no *disk* I/O — the
/// kernel serves zero pages — but it still costs a syscall and a memory scan per
/// chunk, and that is not free at scale: the 20 GiB `storage-template.ext4`
/// holds ~9 MiB of real data, so a linear scan performed 40,960 read-and-compare
/// iterations to find it and took ~11 s, which landed on the critical path of
/// every packed `run`. Seeking straight between data extents reduces that to a
/// handful of syscalls.
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

    // Fast path: copy only the extents the filesystem reports as data. Falls
    // through to the scan below on any filesystem that does not implement the
    // SEEK_DATA/SEEK_HOLE extension.
    #[cfg(unix)]
    if copy_data_extents(&mut src_file, &mut dst_file, size)? {
        return Ok(());
    }

    // Portable fallback: read in 512 KiB chunks, writing only chunks that contain
    // a non-zero byte. Zero chunks are skipped, so they stay as holes in `dst`.
    src_file.seek(SeekFrom::Start(0))?;
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

/// Copy just the data extents of `src` into `dst`, skipping holes outright.
///
/// Returns `Ok(false)` — having written nothing — when the filesystem does not
/// support `SEEK_DATA`, so the caller can fall back to scanning. Support is
/// per-filesystem rather than per-OS (APFS, ext4, xfs and btrfs have it; some
/// network and FUSE filesystems do not), which is why this is detected at run
/// time instead of by `cfg`.
#[cfg(unix)]
fn copy_data_extents(src: &mut File, dst: &mut File, size: u64) -> std::io::Result<bool> {
    use std::os::unix::io::AsRawFd;

    let fd = src.as_raw_fd();
    let seek = |from: u64, whence: libc::c_int| -> Option<i64> {
        let r = unsafe { libc::lseek(fd, from as libc::off_t, whence) };
        if r < 0 {
            None
        } else {
            Some(r as i64)
        }
    };

    // Probe before writing anything: an unsupported filesystem must leave `dst`
    // untouched so the fallback starts from a clean slate. ENXIO means "no data
    // at or after this offset", which for offset 0 is a legitimately empty file.
    if seek(0, libc::SEEK_DATA).is_none() {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ENXIO) {
            return Ok(true); // entirely holes — the skeleton is already correct
        }
        return Ok(false);
    }

    let mut buf = vec![0u8; 512 * 1024];
    let mut offset: u64 = 0;
    while offset < size {
        // Start of the next region containing data.
        let Some(data_start) = seek(offset, libc::SEEK_DATA) else {
            break; // ENXIO: only holes remain
        };
        let data_start = data_start as u64;
        if data_start >= size {
            break;
        }
        // Where that region ends. A file always has an implicit hole at EOF, so
        // this resolves even for a trailing extent; clamp anyway for safety.
        let data_end = seek(data_start, libc::SEEK_HOLE)
            .map(|v| (v as u64).min(size))
            .unwrap_or(size);

        src.seek(SeekFrom::Start(data_start))?;
        dst.seek(SeekFrom::Start(data_start))?;
        let mut remaining = data_end.saturating_sub(data_start);
        while remaining > 0 {
            let want = remaining.min(buf.len() as u64) as usize;
            let n = src.read(&mut buf[..want])?;
            if n == 0 {
                break;
            }
            // An extent may be allocated yet zero-filled; keeping the zero test
            // means such regions stay holes in `dst` exactly as before.
            let chunk = &buf[..n];
            if chunk.iter().any(|&b| b != 0) {
                dst.write_all(chunk)?;
            } else {
                dst.seek(SeekFrom::Current(n as i64))?;
            }
            remaining -= n as u64;
        }
        offset = data_end.max(data_start + 1);
    }

    Ok(true)
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
    storage_logical_size: Option<u64>,
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
            // Restore a VM-mode disk's original trailing sparse extent and/or
            // honor a larger requested size. resize2fs in the guest grows only
            // when the requested block device is larger than the inherited FS.
            let current = fs::metadata(storage_path)?.len();
            let desired = [
                Some(current),
                storage_logical_size,
                size_gb_override.map(|gb| gb * 1024 * 1024 * 1024),
            ]
            .into_iter()
            .flatten()
            .max()
            .unwrap_or(current);
            if desired > current {
                let file = fs::OpenOptions::new().write(true).open(storage_path)?;
                // On Windows/NTFS, extending with set_len would allocate the
                // whole gap unless the file is sparse. Mark sparse first
                // (idempotent).
                #[cfg(windows)]
                mark_file_sparse(&file)?;
                file.set_len(desired)?;
            }
            return Ok(());
        }
    }
    // Fallback: create empty sparse file (agent will format on first boot)
    let size = [
        storage_logical_size,
        size_gb_override.map(|gb| gb * 1024 * 1024 * 1024),
    ]
    .into_iter()
    .flatten()
    .max()
    .unwrap_or(512 * 1024 * 1024);
    create_storage_disk(storage_path, size)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The version that shipped in the pack this was written for. A regression
    /// here is not cosmetic: crediting an old pack with staging support hands
    /// its agent an empty `/packed_layers` and the machine never boots.
    #[test]
    fn a_pack_older_than_staging_is_not_credited_with_it() {
        assert!(!packed_agent_unpacks_staged_layers("0.9.0"));
        assert!(!packed_agent_unpacks_staged_layers("1.8.0"));
        assert!(packed_agent_unpacks_staged_layers("1.8.1"));
        assert!(packed_agent_unpacks_staged_layers("1.12.0"));
        // Numeric order alone would rank 1.10 below 1.9 on a string compare.
        assert!(packed_agent_unpacks_staged_layers("1.10.0"));
    }

    /// A prerelease sorts BELOW its release, so the rc that predates the
    /// staging agent must not inherit the release's capability.
    #[test]
    fn a_prerelease_does_not_inherit_its_releases_capability() {
        assert!(!packed_agent_unpacks_staged_layers("1.8.1-rc.1"));
        assert!(packed_agent_unpacks_staged_layers("1.8.2-rc.1"));
        // Build metadata is not precedence.
        assert!(packed_agent_unpacks_staged_layers("1.8.1+build.5"));
    }

    /// `smolvm_version` is a defaulted field, so its absence means "older than
    /// the field" — never "new enough".
    #[test]
    fn an_unreadable_version_is_treated_as_too_old() {
        assert!(!packed_agent_unpacks_staged_layers(""));
        assert!(!packed_agent_unpacks_staged_layers("   "));
        assert!(!packed_agent_unpacks_staged_layers("not-a-version"));
        assert!(!packed_agent_unpacks_staged_layers("1.2.3.4"));
    }

    #[test]
    fn version_parsing_tolerates_what_packs_actually_record() {
        assert_eq!(parse_pack_version("v1.8.1"), Some(((1, 8, 1), true)));
        // Two components is not valid semver but is unambiguous.
        assert_eq!(parse_pack_version("1.8"), Some(((1, 8, 0), true)));
        assert_eq!(parse_pack_version("1.8.1-rc.1"), Some(((1, 8, 1), false)));
    }

    #[test]
    fn cached_layers_usable_requires_the_layers_not_just_the_marker() {
        let temp = tempfile::tempdir().unwrap();
        let cache = temp.path();
        // Marker alone (a cache cleaner deleted the layer files): unusable.
        fs::write(cache.join(EXTRACTION_MARKER), "").unwrap();
        assert!(!cached_layers_usable(cache));
        // Order file whose ids all resolve (dir or staged tar): usable.
        let layers = cache.join("layers");
        fs::create_dir_all(layers.join("aaa")).unwrap();
        fs::write(layers.join("bbb.tar"), "x").unwrap();
        fs::write(layers.join("layer-order"), "aaa\nbbb\n").unwrap();
        assert!(cached_layers_usable(cache));
        // An id in the order with no backing form: unusable again.
        fs::write(layers.join("layer-order"), "aaa\nbbb\nccc\n").unwrap();
        assert!(!cached_layers_usable(cache));
        // No order file, at least one layer entry: usable (legacy caches).
        fs::remove_file(layers.join("layer-order")).unwrap();
        assert!(cached_layers_usable(cache));
    }

    #[test]
    fn shared_artifact_digest_rejects_a_different_artifact_for_the_same_store() {
        let temp = tempfile::tempdir().unwrap();
        let shared = temp.path().join("shared");
        fs::create_dir(&shared).unwrap();
        let first = temp.path().join("first.smolmachine");
        let second = temp.path().join("second.smolmachine");
        fs::write(&first, b"first artifact").unwrap();
        fs::write(&second, b"different artifact").unwrap();

        let first_digest = ensure_shared_artifact_sha256(&first, &shared).unwrap();
        let error = ensure_shared_artifact_sha256(&second, &shared).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("checksum collision"));
        assert_eq!(read_shared_artifact_sha256(&shared).unwrap(), first_digest);
    }

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

    /// Container images address their service accounts numerically — postgres
    /// is uid 999 — so an extraction that drops the ids hands the service a
    /// data directory it cannot read, and PostgreSQL refuses to start on it.
    /// As root the ids must survive; unprivileged, extraction must still
    /// succeed rather than failing on the EPERM it cannot avoid.
    #[cfg(unix)]
    #[test]
    fn unpacking_preserves_the_headers_numeric_owner() {
        use std::os::unix::fs::MetadataExt;

        let temp_dir = tempfile::tempdir().unwrap();
        let dest = temp_dir.path().join("out");
        fs::create_dir_all(&dest).unwrap();

        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(4);
        header.set_mode(0o600);
        header.set_uid(999);
        header.set_gid(999);
        header.set_cksum();
        builder
            .append_data(&mut header, "pgdata", &b"data"[..])
            .unwrap();
        let tar_bytes = builder.into_inner().unwrap();

        let mut archive = tar::Archive::new(tar_bytes.as_slice());
        safe_unpack(&mut archive, &dest).expect("extraction succeeds at either privilege level");

        let meta = fs::metadata(dest.join("pgdata")).unwrap();
        let euid = unsafe { libc::geteuid() };
        if euid == 0 {
            assert_eq!(meta.uid(), 999, "the header's uid must survive extraction");
            assert_eq!(meta.gid(), 999, "the header's gid must survive extraction");
        } else {
            assert_eq!(
                meta.uid(),
                euid,
                "unprivileged extraction leaves the caller as owner, without erroring"
            );
        }
    }

    /// `lchown`, not `chown`: re-owning a symlink entry must not reach through
    /// the link and re-own whatever it points at.
    #[cfg(unix)]
    #[test]
    fn re_owning_a_symlink_leaves_its_target_untouched() {
        use std::os::unix::fs::{symlink, MetadataExt};

        if unsafe { libc::geteuid() } != 0 {
            return; // chown is a no-op unprivileged, so there is nothing to assert
        }

        let temp_dir = tempfile::tempdir().unwrap();
        let target = temp_dir.path().join("target");
        let link = temp_dir.path().join("link");
        fs::write(&target, b"x").unwrap();
        symlink(&target, &link).unwrap();

        set_owner(&link, 999, 999);

        assert_eq!(
            fs::metadata(&target).unwrap().uid(),
            0,
            "the link's target must keep its own owner"
        );
        assert_eq!(
            fs::symlink_metadata(&link).unwrap().uid(),
            999,
            "the link itself is re-owned"
        );
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

    /// Build a tar holding `dir/` at `dir_mode` with one regular file inside.
    #[cfg(unix)]
    fn make_dir_with_child_tar(dir: &str, dir_mode: u32) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());

        let mut dir_header = tar::Header::new_gnu();
        dir_header.set_entry_type(tar::EntryType::Directory);
        dir_header.set_size(0);
        dir_header.set_mode(dir_mode);
        dir_header.set_cksum();
        builder
            .append_data(&mut dir_header, format!("{dir}/"), std::io::empty())
            .unwrap();

        let contents = b"data";
        let mut file_header = tar::Header::new_gnu();
        file_header.set_entry_type(tar::EntryType::Regular);
        file_header.set_size(contents.len() as u64);
        file_header.set_mode(0o600);
        file_header.set_cksum();
        builder
            .append_data(&mut file_header, format!("{dir}/child"), &contents[..])
            .unwrap();

        builder.into_inner().unwrap()
    }

    /// Directories are forced writable mid-extraction so their children can be
    /// created, so every non-default mode has to be restored afterwards.
    ///
    /// Restoring only directories the owner could not write left every
    /// restrictive-but-writable mode widened to 0755: a packed PostgreSQL data
    /// directory arrived world-readable and the server refused to start on it,
    /// and a packed 0700 `.ssh` lost its privacy the same way.
    #[cfg(unix)]
    #[test]
    fn test_safe_unpack_restores_restrictive_but_writable_directory_mode() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = tempfile::tempdir().unwrap();
        let dest = temp_dir.path().join("dest");
        fs::create_dir(&dest).unwrap();

        let tar_bytes = make_dir_with_child_tar("pgdata", 0o700);
        let mut archive = tar::Archive::new(tar_bytes.as_slice());
        safe_unpack(&mut archive, &dest).unwrap();

        let extracted = dest.join("pgdata");
        let mode = fs::metadata(&extracted).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "0700 directory must not be widened to 0755 by the extraction"
        );
        assert_eq!(
            fs::read(extracted.join("child")).unwrap(),
            b"data",
            "the child still has to be written while the directory was writable"
        );
    }

    /// A read-only directory keeps working — the case the original condition
    /// was written for — and its children are still extracted.
    #[cfg(unix)]
    #[test]
    fn test_safe_unpack_restores_read_only_directory_mode() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = tempfile::tempdir().unwrap();
        let dest = temp_dir.path().join("dest");
        fs::create_dir(&dest).unwrap();

        let tar_bytes = make_dir_with_child_tar("readonly", 0o555);
        let mut archive = tar::Archive::new(tar_bytes.as_slice());
        safe_unpack(&mut archive, &dest).unwrap();

        let extracted = dest.join("readonly");
        let mode = fs::metadata(&extracted).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o555, "read-only directory mode must be restored");
        assert!(extracted.join("child").exists());
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

    #[cfg(target_os = "macos")]
    #[test]
    fn safe_unpack_uses_the_archived_sparse_extent_map() {
        use crate::assets::AssetCollector;
        use std::os::unix::fs::MetadataExt;

        const LOGICAL_SIZE: u64 = 64 * 1024 * 1024;
        let temp_dir = tempfile::tempdir().unwrap();
        let staging = temp_dir.path().join("staging");
        let collector = AssetCollector::new(staging.clone()).unwrap();
        let checkpoint = staging.join("checkpoint");
        fs::create_dir_all(&checkpoint).unwrap();
        let source = checkpoint.join("memory.bin");
        let mut source_file = File::create(&source).unwrap();
        source_file.set_len(LOGICAL_SIZE).unwrap();
        source_file.seek(SeekFrom::Start(4096)).unwrap();
        source_file.write_all(&[0xA5; 4096]).unwrap();
        source_file.seek(SeekFrom::Start(32 * 1024 * 1024)).unwrap();
        source_file.write_all(&[0x5A; 4096]).unwrap();
        source_file.sync_all().unwrap();

        let compressed = temp_dir.path().join("assets.tar.zst");
        collector.compress(&compressed, false).unwrap();
        let decoder = zstd::stream::Decoder::new(File::open(&compressed).unwrap()).unwrap();
        let mut archive = tar::Archive::new(decoder);
        let output = temp_dir.path().join("output");
        fs::create_dir(&output).unwrap();
        safe_unpack(&mut archive, &output).unwrap();

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
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn archived_sparse_extent_cannot_escape_through_a_symlink_parent() {
        use crate::assets::AssetCollector;
        use std::os::unix::fs::symlink;

        let temp_dir = tempfile::tempdir().unwrap();
        let staging = temp_dir.path().join("staging");
        let collector = AssetCollector::new(staging.clone()).unwrap();
        let source_dir = staging.join("foo");
        fs::create_dir_all(&source_dir).unwrap();
        let mut source = File::create(source_dir.join("pwned.bin")).unwrap();
        source.set_len(64 * 1024 * 1024).unwrap();
        source.seek(SeekFrom::Start(4096)).unwrap();
        source.write_all(&[0xA5; 4096]).unwrap();
        source.sync_all().unwrap();
        let compressed = temp_dir.path().join("assets.tar.zst");
        collector.compress(&compressed, false).unwrap();

        let output = temp_dir.path().join("output");
        let outside = temp_dir.path().join("outside");
        fs::create_dir(&output).unwrap();
        fs::create_dir(&outside).unwrap();
        symlink(&outside, output.join("foo")).unwrap();
        let decoder = zstd::stream::Decoder::new(File::open(&compressed).unwrap()).unwrap();
        let mut archive = tar::Archive::new(decoder);
        let error = safe_unpack(&mut archive, &output).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(!outside.join("pwned.bin").exists());
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
        create_or_copy_storage_disk(
            cache_dir.path(),
            Some("storage-template.ext4"),
            &dest,
            None,
            None,
        )
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

    /// Staged tars (in-guest extraction mode) must be shared from the plain
    /// `layers` dir — a case-sensitive volume was never created for them, so
    /// mounting one would hand the guest an empty directory.
    #[test]
    #[cfg(target_os = "macos")]
    fn staged_tars_do_not_mount_a_volume() {
        if host_unpack_preserves_ownership() {
            return; // as root the host extracts into the volume; covered below
        }
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_dir = temp_dir.path().join("cache");
        fs::create_dir_all(cache_dir.join("layers")).unwrap();
        fs::write(cache_dir.join("layers/dummy.tar"), b"").unwrap();

        let lease = acquire_layers_lease(&cache_dir, false).unwrap();
        assert_eq!(
            lease.path,
            cache_dir.join("layers"),
            "staged tars are shared to the guest as-is"
        );
        assert!(!is_mount_point(&lease.path));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_layers_lease_creates_and_cleans_volume() {
        // Verify the case-sensitive volume lifecycle: created and mounted on
        // acquire, detached on lease drop, and — once the sparse image exists
        // (a pack extracted by root or an earlier version) — chosen again by
        // the public accessor. Skips gracefully if hdiutil is unavailable
        // (CI, sandboxed envs).
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_dir = temp_dir.path().join("cache");
        // Create a dummy tar so has_layer_tars() returns true.
        fs::create_dir_all(cache_dir.join("layers")).unwrap();
        fs::write(cache_dir.join("layers/dummy.tar"), b"").unwrap();

        // Drive the volume machinery directly (the public accessor only takes
        // this path for root extraction or a pre-existing image).
        let lease = match acquire_lease(&cache_dir, false) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("SKIP: hdiutil unavailable: {}", e);
                return;
            }
        };
        assert!(lease.exists());
        assert!(is_mount_point(&lease));

        // Both "lower" and "Lower" should coexist on the case-sensitive volume.
        fs::write(lease.join("lower"), "file").unwrap();
        fs::create_dir_all(lease.join("Lower")).unwrap();
        assert!(lease.join("lower").exists());
        assert!(lease.join("Lower").is_dir());

        // Lease file should exist while lease is held.
        let lease_file = cache_dir
            .join(LEASES_DIR)
            .join(format!("{}", std::process::id()));
        assert!(lease_file.exists());

        // Release — should detach volume (last lease).
        release_lease(&cache_dir);
        assert!(
            !is_mount_point(&lease),
            "volume should be detached after last lease drop"
        );

        // The sparse image persists; the public accessor must now pick the
        // volume back up even though extraction mode would stage tars.
        let compat = acquire_layers_lease(&cache_dir, false).unwrap();
        assert!(is_mount_point(&compat.path), "existing image is honored");
        assert!(compat.path.join("lower").exists());
        drop(compat);
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

    // Sets directory mtimes via libc::utimes to drive the LRU ordering, so it
    // only compiles on Unix; the eviction logic under test is platform-agnostic.
    #[cfg(unix)]
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

    #[cfg(unix)]
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

/// Reaping stranded case-sensitive volumes (macOS-only lease protocol).
#[cfg(all(test, target_os = "macos"))]
mod orphan_reap_tests {
    use super::*;

    /// Standalone packs live at `<root>/<hash>`, so peers are the other hashes.
    #[test]
    fn flat_layout_sees_its_peers() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path();
        for h in ["aaa", "bbb", "ccc"] {
            fs::create_dir_all(root.join(h)).expect("mkdir");
        }
        let peers = sibling_cache_dirs(&root.join("aaa"));

        assert_eq!(peers.len(), 2, "both peers, and never itself");
        assert!(peers.contains(&root.join("bbb")));
        assert!(peers.contains(&root.join("ccc")));
        assert!(!peers.contains(&root.join("aaa")));
    }

    /// VM-backed packs live at `<root>/<hash>/pack` — a peer is another hash's
    /// `pack` subdir, not the hash directory itself.
    #[test]
    fn nested_layout_keeps_the_pack_suffix() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path();
        for h in ["aaa", "bbb"] {
            fs::create_dir_all(root.join(h).join("pack")).expect("mkdir");
        }
        let peers = sibling_cache_dirs(&root.join("aaa").join("pack"));

        assert_eq!(peers, vec![root.join("bbb").join("pack")]);
    }

    /// A hash directory with no `pack` subdir is simply skipped, rather than
    /// yielding a path that does not exist.
    #[test]
    fn nested_layout_skips_peers_without_a_pack_dir() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path();
        fs::create_dir_all(root.join("aaa").join("pack")).expect("mkdir");
        fs::create_dir_all(root.join("bbb")).expect("mkdir");

        assert!(sibling_cache_dirs(&root.join("aaa").join("pack")).is_empty());
    }

    /// The reaper must never block: a peer mid-acquire holds its lock, and
    /// waiting on it would stall an unrelated artifact's run.
    #[test]
    fn a_held_lock_is_skipped_not_waited_on() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path();
        let held = lock_leases(dir).expect("first lock");

        assert!(
            try_lock_leases(dir).is_err(),
            "must fail immediately while held"
        );

        drop(held);
        assert!(try_lock_leases(dir).is_ok(), "succeeds once released");
    }

    /// Reaping is a no-op when nothing is mounted — the common case, and it must
    /// not disturb a peer's directory contents.
    #[test]
    fn unmounted_peers_are_left_alone() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path();
        let peer = root.join("bbb");
        fs::create_dir_all(peer.join(LEASES_DIR)).expect("mkdir");
        fs::create_dir_all(root.join("aaa")).expect("mkdir");
        let marker = peer.join(LEASES_DIR).join("12345");
        fs::write(&marker, "").expect("write lease");

        reap_orphan_volumes(&root.join("aaa"));

        assert!(peer.exists(), "peer directory must survive");
    }
}

/// `sparse_copy` must reproduce the source exactly while preserving holes.
#[cfg(test)]
mod sparse_copy_tests {
    use super::*;

    /// Write `src`, copy it, and assert the bytes round-trip identically.
    fn roundtrip(build: impl FnOnce(&mut File)) -> (Vec<u8>, Vec<u8>, u64) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let src = tmp.path().join("src.img");
        let dst = tmp.path().join("dst.img");
        let mut f = File::create(&src).expect("create src");
        build(&mut f);
        f.sync_all().expect("sync");
        drop(f);

        sparse_copy(&src, &dst).expect("sparse_copy");

        let want = fs::read(&src).expect("read src");
        let got = fs::read(&dst).expect("read dst");
        let blocks = dst_blocks(&dst);
        (want, got, blocks)
    }

    #[cfg(unix)]
    fn dst_blocks(p: &Path) -> u64 {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(p).expect("stat").blocks()
    }
    #[cfg(not(unix))]
    fn dst_blocks(_p: &Path) -> u64 {
        0
    }

    /// Data at both ends with a large hole between — the storage-template shape.
    #[test]
    fn data_separated_by_a_large_hole_round_trips() {
        let (want, got, _) = roundtrip(|f| {
            f.write_all(b"HEAD").expect("head");
            f.seek(SeekFrom::Start(64 * 1024 * 1024)).expect("seek");
            f.write_all(b"TAIL").expect("tail");
        });
        assert_eq!(want.len(), 64 * 1024 * 1024 + 4);
        assert_eq!(want, got, "copy must be byte-identical across the hole");
    }

    /// The hole must survive the copy rather than being filled with zeros.
    #[cfg(unix)]
    #[test]
    fn the_hole_is_not_materialized() {
        let (want, _got, blocks) = roundtrip(|f| {
            f.write_all(b"HEAD").expect("head");
            f.seek(SeekFrom::Start(64 * 1024 * 1024)).expect("seek");
            f.write_all(b"TAIL").expect("tail");
        });
        // A dense 64 MiB copy would be ~131072 512-byte blocks; a sparse one is
        // a few. Assert well under a tenth to stay robust across filesystems.
        let dense = (want.len() as u64) / 512;
        assert!(
            blocks < dense / 10,
            "destination should stay sparse: {blocks} blocks vs {dense} if dense"
        );
    }

    /// A fully-zero file has no data extents at all — the SEEK_DATA probe
    /// returns ENXIO immediately, which must not be mistaken for failure.
    #[test]
    fn an_all_zero_file_round_trips() {
        let (want, got, _) = roundtrip(|f| {
            f.set_len(8 * 1024 * 1024).expect("set_len");
        });
        assert_eq!(want.len(), 8 * 1024 * 1024);
        assert_eq!(got, want, "all-zero file must copy as all zeros");
    }

    /// Dense, non-zero content must copy verbatim — the no-holes case.
    #[test]
    fn a_dense_file_round_trips() {
        let (want, got, _) = roundtrip(|f| {
            let data: Vec<u8> = (0..=255u8).cycle().take(3 * 1024 * 1024).collect();
            f.write_all(&data).expect("write");
        });
        assert_eq!(want, got, "dense content must be preserved exactly");
        assert!(want.iter().any(|&b| b != 0));
    }

    /// An empty file is a degenerate case both paths must survive.
    #[test]
    fn an_empty_file_round_trips() {
        let (want, got, _) = roundtrip(|_f| {});
        assert!(want.is_empty() && got.is_empty());
    }

    /// Data crossing the 512 KiB buffer boundary must not be truncated or
    /// misaligned by the chunked read inside an extent.
    #[test]
    fn an_extent_larger_than_the_buffer_round_trips() {
        let (want, got, _) = roundtrip(|f| {
            let data: Vec<u8> = (0..=255u8).cycle().take(1_500_000).collect();
            f.write_all(&data).expect("write");
            f.seek(SeekFrom::Start(32 * 1024 * 1024)).expect("seek");
            f.write_all(b"END").expect("end");
        });
        assert_eq!(want, got, "multi-chunk extent must copy exactly");
    }
}

/// Differential tests: the extent-based copy must agree with the exhaustive
/// scan it replaced, on every shape of sparse file.
#[cfg(test)]
mod sparse_copy_differential_tests {
    use super::*;
    /// The algorithm exactly as it was before the SEEK_DATA change, kept here as
    /// the reference oracle. Any divergence from this is a regression.
    fn reference_scan_copy(src: &Path, dst: &Path) -> std::io::Result<()> {
        let mut src_file = File::open(src)?;
        let size = src_file.metadata()?.len();
        let mut dst_file = File::create(dst)?;
        dst_file.set_len(size)?;
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

    /// Stream-compare two files. `memcmp` stays fast even in the unoptimized
    /// test profile, unlike a cryptographic digest — and comparing the bytes is
    /// a stronger check than comparing hashes of them.
    fn files_equal(a: &Path, b: &Path) -> bool {
        let (mut fa, mut fb) = (
            File::open(a).expect("open a"),
            File::open(b).expect("open b"),
        );
        if fa.metadata().expect("meta").len() != fb.metadata().expect("meta").len() {
            return false;
        }
        let (mut ba, mut bb) = (vec![0u8; 4 << 20], vec![0u8; 4 << 20]);
        loop {
            let na = fa.read(&mut ba).expect("read a");
            let nb = fb.read(&mut bb).expect("read b");
            if na != nb {
                return false;
            }
            if na == 0 {
                return true;
            }
            if ba[..na] != bb[..nb] {
                return false;
            }
        }
    }

    #[cfg(unix)]
    fn blocks(p: &Path) -> u64 {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(p).expect("stat").blocks()
    }

    /// Deterministic pseudo-random layouts: same seed, same file, every run.
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            self.0 >> 11
        }
    }

    /// Fuzz many sparse shapes; the new copy must agree with the old one and
    /// with the source, byte for byte, on every one.
    #[test]
    fn fuzz_layouts_agree_with_the_old_algorithm() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut rng = Lcg(0x5EED);

        for case in 0..60 {
            let src = tmp.path().join(format!("s{case}.img"));
            let fast = tmp.path().join(format!("f{case}.img"));
            let slow = tmp.path().join(format!("r{case}.img"));

            let size = 1 + (rng.next() % (24 * 1024 * 1024));
            let mut f = File::create(&src).expect("create");
            f.set_len(size).expect("set_len");
            // Scatter a handful of data runs, some tiny, some spanning chunks.
            let runs = rng.next() % 7;
            for _ in 0..runs {
                let at = rng.next() % size;
                let len = (1 + rng.next() % (2 * 1024 * 1024)).min(size - at);
                let byte = (1 + (rng.next() % 254)) as u8;
                f.seek(SeekFrom::Start(at)).expect("seek");
                f.write_all(&vec![byte; len as usize]).expect("write");
            }
            f.sync_all().expect("sync");
            drop(f);

            sparse_copy(&src, &fast).expect("fast");
            reference_scan_copy(&src, &slow).expect("slow");

            assert!(
                files_equal(&fast, &src),
                "case {case}: fast path diverged from source"
            );
            assert!(
                files_equal(&fast, &slow),
                "case {case}: fast path diverged from old algorithm"
            );
            #[cfg(unix)]
            assert!(
                blocks(&fast) <= blocks(&slow),
                "case {case}: fast path is less sparse than the old one"
            );
        }
    }

    /// Offsets beyond 4 GiB must not truncate through any 32-bit path.
    #[test]
    fn data_beyond_four_gib_round_trips() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let src = tmp.path().join("big.img");
        let dst = tmp.path().join("big-copy.img");
        let far: u64 = 6 * 1024 * 1024 * 1024; // 6 GiB, sparse

        let mut f = File::create(&src).expect("create");
        f.write_all(b"START").expect("start");
        f.seek(SeekFrom::Start(far)).expect("seek");
        f.write_all(b"BEYOND-4GIB").expect("far write");
        f.sync_all().expect("sync");
        drop(f);

        sparse_copy(&src, &dst).expect("copy");

        assert!(files_equal(&dst, &src), "6 GiB sparse file must round-trip");
        #[cfg(unix)]
        assert!(
            blocks(&dst) < 4096,
            "must stay sparse, got {}",
            blocks(&dst)
        );
    }

    /// Data touching the final byte: SEEK_HOLE has no hole to report past it.
    #[test]
    fn data_at_the_very_end_round_trips() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let src = tmp.path().join("tail.img");
        let dst = tmp.path().join("tail-copy.img");
        let mut f = File::create(&src).expect("create");
        f.set_len(8 * 1024 * 1024).expect("len");
        f.seek(SeekFrom::Start(8 * 1024 * 1024 - 3)).expect("seek");
        f.write_all(b"EOF").expect("write");
        f.sync_all().expect("sync");
        drop(f);

        sparse_copy(&src, &dst).expect("copy");
        assert!(files_equal(&dst, &src));
    }
}
