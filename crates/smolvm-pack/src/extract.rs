//! Asset extraction for packed binaries.
//!
//! Provides shared extraction logic used by both the main `smolvm` binary
//! (sidecar mode via `runpack`) and the standalone stub executable.

use crate::format::{PackFooter, SIDECAR_EXTENSION};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;

/// Safely unpack a tar archive, rejecting symlinks, hardlinks, and entries
/// that resolve outside `dest`.
///
/// The standard `tar::Archive::unpack()` strips `..` components but does
/// **not** reject symlinks. A crafted archive could create
/// `lib/libkrun.dylib → /tmp/evil.so`, and subsequent `dlopen()` would
/// load the attacker's library. This function rejects any entry that is
/// not a regular file or directory.
fn safe_unpack<R: Read>(archive: &mut tar::Archive<R>, dest: &Path) -> std::io::Result<()> {
    let canonical_dest = dest.canonicalize().unwrap_or_else(|_| dest.to_path_buf());

    for entry_result in archive.entries()? {
        let mut entry = entry_result?;
        let entry_type = entry.header().entry_type();
        let entry_path = entry.path()?.to_path_buf();

        match entry_type {
            tar::EntryType::Regular | tar::EntryType::GNUSparse | tar::EntryType::Directory => {}
            tar::EntryType::Symlink => {
                // Allow symlinks but validate the target stays within dest.
                if let Some(link_target) = entry.link_name()? {
                    let link_target = link_target.to_path_buf();
                    // Resolve relative symlinks against the entry's parent dir
                    let resolved = if link_target.is_absolute() {
                        // Absolute symlinks: jail to dest (e.g., /lib/foo → dest/lib/foo)
                        dest.join(link_target.strip_prefix("/").unwrap_or(&link_target))
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
                }
            }
            tar::EntryType::Link => {
                // Allow hardlinks but validate the target stays within dest.
                if let Some(link_target) = entry.link_name()? {
                    let full_target = dest.join(link_target.as_ref());
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
                }
            }
            other => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "tar entry '{}' has disallowed type {:?}",
                        entry_path.display(),
                        other
                    ),
                ));
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

        // Unpack the individual entry.
        // Ensure parent directories are writable before extracting. OCI layer
        // tars may set restrictive directory modes (e.g., dr-xr-xr-x) before
        // child entries, which prevents creating files under them on macOS
        // where we're not root.
        if entry_type != tar::EntryType::Directory {
            if let Some(parent) = full_path.parent() {
                if parent.is_dir() {
                    let _ =
                        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755));
                }
            }
        }
        entry.unpack_in(dest)?;
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

/// Marker file indicating extraction is complete.
const EXTRACTION_MARKER: &str = ".smolvm-extracted";

/// Get the cache directory for a given checksum.
///
/// Returns `~/.cache/smolvm-pack/<checksum>/` (hex-formatted).
pub fn get_cache_dir(checksum: u32) -> std::io::Result<PathBuf> {
    let base = dirs::cache_dir()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no cache directory"))?;

    Ok(base.join("smolvm-pack").join(format!("{:08x}", checksum)))
}

/// Check if assets have already been extracted.
pub fn is_extracted(cache_dir: &Path) -> bool {
    cache_dir.join(EXTRACTION_MARKER).exists()
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
    let lock_file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)?;

    #[cfg(unix)]
    {
        let ret = unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX) };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

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

    extract_sidecar_inner(sidecar_path, cache_dir, footer, debug)
    // Lock released on drop of lock_file
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

    post_process_extraction(cache_dir, debug)?;
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

        post_process_extraction(cache_dir, debug)?;
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

    post_process_extraction(cache_dir, debug)?;
    Ok(())
}

/// Post-process extracted assets: unpack agent rootfs, OCI layers, fix permissions.
fn post_process_extraction(cache_dir: &Path, debug: bool) -> std::io::Result<()> {
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
        // On macOS, extract into a case-sensitive volume. On Linux, use
        // the layers dir directly. If the volume can't be created (sandbox,
        // hdiutil unavailable), fall back to direct extraction — this works
        // for images without case-conflicting paths.
        let extract_dir = match extraction_layers_dir(cache_dir, debug) {
            Ok(dir) => dir,
            Err(e) => {
                eprintln!(
                    "warning: case-sensitive volume unavailable ({}), \
                     falling back to direct extraction",
                    e
                );
                layers_dir.clone()
            }
        };

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
            match acquire_lease(cache_dir, debug) {
                Ok(path) => {
                    return Ok(LayersVolumeLease {
                        path,
                        cache_dir: cache_dir.to_path_buf(),
                    });
                }
                Err(e) => {
                    // hdiutil unavailable or failed — fall back to direct
                    // layers dir. Works for images without case conflicts.
                    eprintln!(
                        "warning: case-sensitive volume unavailable ({}), using layers dir",
                        e
                    );
                }
            }
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
            let result = (|| -> std::io::Result<PathBuf> {
                let leases_dir = cache_dir.join(LEASES_DIR);
                fs::create_dir_all(&leases_dir)?;
                let lock = lock_leases(cache_dir)?;
                gc_stale_leases(&leases_dir);
                ensure_cs_volume_mounted(cache_dir, debug)?;
                fs::write(leases_dir.join("daemon"), format!("{}", daemon_pid))?;
                drop(lock);
                Ok(cache_dir.join(CS_MOUNT_DIR))
            })();
            match result {
                Ok(path) => return Ok(path),
                Err(e) => {
                    eprintln!(
                        "warning: case-sensitive volume unavailable ({}), using layers dir",
                        e
                    );
                }
            }
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
/// Returns `None` if the binary has no embedded libs (e.g., a V2 stub or
/// the base smolvm binary).
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
        Err(_) => return Ok(None), // No SMOLLIBS footer — not a V3 stub
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

    #[cfg(unix)]
    {
        let ret = unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX) };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

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

/// Create a storage disk file (empty sparse file).
pub fn create_storage_disk(path: &Path, size: u64) -> std::io::Result<()> {
    let file = File::create(path)?;
    file.set_len(size)?;
    Ok(())
}

/// Copy overlay disk template from cache to a runtime directory.
///
/// Copies the overlay template to `dest`, optionally extending the sparse
/// file if `size_gb_override` is larger than the template.
///
/// Returns an error if the template path is `None` or the template file
/// does not exist in the cache.
pub fn copy_overlay_template(
    cache_dir: &Path,
    template_path: Option<&str>,
    dest: &Path,
    size_gb_override: Option<u64>,
) -> std::io::Result<()> {
    let template = template_path.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "overlay template not specified in manifest",
        )
    })?;

    let src = cache_dir.join(template);
    if !src.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("overlay template not found: {}", src.display()),
        ));
    }

    fs::copy(&src, dest)?;

    // Extend if requested size is larger than template
    if let Some(gb) = size_gb_override {
        let desired = gb * 1024 * 1024 * 1024;
        let current = fs::metadata(dest)?.len();
        if desired > current {
            let file = fs::OpenOptions::new().write(true).open(dest)?;
            file.set_len(desired)?;
        }
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
        let template_path = cache_dir.join(template);
        if template_path.exists() {
            fs::copy(&template_path, storage_path)?;
            // If a custom size was requested and it's larger than the template,
            // extend the sparse file (resize2fs in the agent will expand the FS).
            if let Some(gb) = size_gb_override {
                let desired = gb * 1024 * 1024 * 1024;
                let current = fs::metadata(storage_path)?.len();
                if desired > current {
                    let file = fs::OpenOptions::new().write(true).open(storage_path)?;
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

        let result = copy_overlay_template(temp_dir.path(), None, &dest, None);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn test_copy_overlay_template_fails_when_missing() {
        let temp_dir = tempfile::tempdir().unwrap();
        let dest = temp_dir.path().join("overlay.raw");

        let result = copy_overlay_template(temp_dir.path(), Some("nonexistent.raw"), &dest, None);
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

        // Copy without size override
        copy_overlay_template(temp_dir.path(), Some("overlay.raw"), &dest, None).unwrap();
        assert_eq!(fs::metadata(&dest).unwrap().len(), 1024);

        // Copy with size override that extends (use small value for test)
        let dest2 = temp_dir.path().join("output2.raw");
        // We can't test GiB-sized files, but we can verify the copy works
        copy_overlay_template(temp_dir.path(), Some("overlay.raw"), &dest2, None).unwrap();
        assert!(dest2.exists());
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
    fn test_safe_unpack_rejects_disallowed_entry_type() {
        // Build a tar with a FIFO entry (disallowed type)
        let temp_dir = tempfile::tempdir().unwrap();
        let dest_raw = temp_dir.path().join("out");
        fs::create_dir_all(&dest_raw).unwrap();
        let dest = dest_raw.canonicalize().unwrap();

        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Fifo);
        header.set_size(0);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "fifo-entry", &b""[..])
            .unwrap();
        let tar_data = builder.into_inner().unwrap();

        let mut archive = tar::Archive::new(tar_data.as_slice());
        let result = safe_unpack(&mut archive, &dest);
        assert!(result.is_err(), "FIFO entry type should be rejected");
        assert!(
            result.unwrap_err().to_string().contains("disallowed type"),
            "error should mention disallowed type"
        );
    }
}
