//! Storage management for the helper daemon.
//!
//! This module handles:
//! - Storage disk initialization and formatting
//! - OCI image pulling via crane
//! - Layer extraction and deduplication
//! - Overlay filesystem management
//! - Container execution via crun OCI runtime
//! - Support for pre-packed OCI layers (smolvm pack)

use crate::crun::CrunCommand;
use crate::oci::{generate_container_id, OciSpec};
use crate::paths;
use crate::process::{WaitResult, TIMEOUT_EXIT_CODE};
use smolvm_protocol::guest_env;
use smolvm_protocol::{
    image_repo, normalize_image_ref, ImageInfo, OverlayInfo, RegistryAuth, StorageStatus,
};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use tracing::{debug, info, warn};

/// Storage root path (where the ext4 disk is mounted).
const STORAGE_ROOT: &str = "/storage";

/// Directory structure within storage.
const LAYERS_DIR: &str = "layers";
const CONFIGS_DIR: &str = "configs";
const MANIFESTS_DIR: &str = "manifests";
const OVERLAYS_DIR: &str = "overlays";
const WORKSPACE_DIR: &str = "workspace";
const DOCKER_HUB_AUTH_CONFIG_KEY: &str = "https://index.docker.io/v1/";
const DOCKER_HUB_REGISTRY_ALIASES: &[&str] = &["docker.io", "index.docker.io"];

fn validate_storage_id(value: &str, context: &str) -> Result<()> {
    if value.is_empty() {
        return Err(StorageError::ValidationFailed {
            context: context.to_string(),
            reason: "cannot be empty".to_string(),
        });
    }

    if value.len() > 128 {
        return Err(StorageError::ValidationFailed {
            context: context.to_string(),
            reason: "too long (max 128 chars)".to_string(),
        });
    }

    if value.contains('/') || value.contains('\\') {
        return Err(StorageError::ValidationFailed {
            context: context.to_string(),
            reason: "path separators are not allowed".to_string(),
        });
    }

    let path = Path::new(value);
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                return Err(StorageError::ValidationFailed {
                    context: context.to_string(),
                    reason: "parent traversal is not allowed".to_string(),
                });
            }
            std::path::Component::CurDir => {
                return Err(StorageError::ValidationFailed {
                    context: context.to_string(),
                    reason: "dot segments are not allowed".to_string(),
                });
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                return Err(StorageError::ValidationFailed {
                    context: context.to_string(),
                    reason: "path separators are not allowed".to_string(),
                });
            }
            std::path::Component::Normal(seg) => {
                let seg = seg.to_string_lossy();
                if !seg
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
                {
                    return Err(StorageError::ValidationFailed {
                        context: context.to_string(),
                        reason: format!("contains invalid character(s): {}", value),
                    });
                }
            }
        }
    }

    Ok(())
}

fn overlay_root_for_workload(workload_id: &str) -> Result<PathBuf> {
    validate_storage_id(workload_id, "workload_id")?;
    Ok(Path::new(STORAGE_ROOT).join(OVERLAYS_DIR).join(workload_id))
}

/// Merged rootfs directory of a persistent overlay, derived without preparing
/// it. Lets the keep-alive `crun exec` path read the running container's
/// `/etc/passwd` (to resolve a username to a numeric uid, #632) when joining an
/// already-running container, where no fresh `prepare_for_run_persistent` ran.
pub fn persistent_overlay_rootfs(overlay_id: &str) -> PathBuf {
    Path::new(STORAGE_ROOT)
        .join(OVERLAYS_DIR)
        .join(format!("persistent-{}", overlay_id))
        .join("merged")
}

fn validate_container_destination_path(container_path: &str) -> Result<PathBuf> {
    if !container_path.starts_with('/') {
        return Err(StorageError::ValidationFailed {
            context: "mount destination".to_string(),
            reason: "must be an absolute path".to_string(),
        });
    }
    if container_path == "/" {
        return Err(StorageError::ValidationFailed {
            context: "mount destination".to_string(),
            reason: "mounting to '/' is not allowed".to_string(),
        });
    }

    let mut relative = PathBuf::new();
    for component in Path::new(container_path).components() {
        match component {
            std::path::Component::RootDir => {}
            std::path::Component::Normal(seg) => relative.push(seg),
            std::path::Component::ParentDir => {
                return Err(StorageError::ValidationFailed {
                    context: "mount destination".to_string(),
                    reason: "parent traversal is not allowed".to_string(),
                });
            }
            std::path::Component::CurDir => {
                return Err(StorageError::ValidationFailed {
                    context: "mount destination".to_string(),
                    reason: "dot segments are not allowed".to_string(),
                });
            }
            std::path::Component::Prefix(_) => {
                return Err(StorageError::ValidationFailed {
                    context: "mount destination".to_string(),
                    reason: "path prefixes are not allowed".to_string(),
                });
            }
        }
    }

    if relative.as_os_str().is_empty() {
        return Err(StorageError::ValidationFailed {
            context: "mount destination".to_string(),
            reason: "cannot resolve mount destination".to_string(),
        });
    }

    Ok(relative)
}

fn ensure_mount_target_under_root(rootfs: &Path, container_path: &str) -> Result<PathBuf> {
    let root_canon = rootfs.canonicalize().map_err(|e| StorageError::ReadFile {
        path: rootfs.display().to_string(),
        cause: format!("failed to canonicalize rootfs: {}", e),
    })?;

    let relative = validate_container_destination_path(container_path)?;
    let components: Vec<_> = relative.components().collect();
    let last_idx = components.len().saturating_sub(1);
    let mut current = root_canon.clone();

    for (idx, component) in components.into_iter().enumerate() {
        let std::path::Component::Normal(seg) = component else {
            return Err(StorageError::ValidationFailed {
                context: "mount destination".to_string(),
                reason: "invalid destination component".to_string(),
            });
        };

        current.push(seg);
        match std::fs::symlink_metadata(&current) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    let canon = current.canonicalize().map_err(|e| StorageError::ReadFile {
                        path: current.display().to_string(),
                        cause: format!("failed to canonicalize symlink target: {}", e),
                    })?;
                    if !canon.starts_with(&root_canon) {
                        return Err(StorageError::ValidationFailed {
                            context: "mount destination".to_string(),
                            reason: "resolved path escapes rootfs".to_string(),
                        });
                    }
                    if idx == last_idx {
                        // The mount target itself is a symlink within the rootfs.
                        // Previous VM runs can leave such symlinks (e.g. /workspace →
                        // /storage/workspace) in the writable agent rootfs. Replace it
                        // with a real directory so the bind mount claims the path
                        // directly rather than following through to the symlink target.
                        std::fs::remove_file(&current).map_err(|e| StorageError::ReadFile {
                            path: current.display().to_string(),
                            cause: format!("failed to remove symlink at mount target: {}", e),
                        })?;
                        std::fs::create_dir(&current).map_err(|err| StorageError::CreateDir {
                            path: current.display().to_string(),
                            cause: err.to_string(),
                        })?;
                    } else if !current.is_dir() {
                        // Intermediate symlink must resolve to a directory.
                        return Err(StorageError::ValidationFailed {
                            context: "mount destination".to_string(),
                            reason: format!(
                                "destination component is not a directory: {}",
                                current.display()
                            ),
                        });
                    }
                } else if !meta.is_dir() {
                    return Err(StorageError::ValidationFailed {
                        context: "mount destination".to_string(),
                        reason: format!(
                            "destination component is not a directory: {}",
                            current.display()
                        ),
                    });
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&current).map_err(|err| StorageError::CreateDir {
                    path: current.display().to_string(),
                    cause: err.to_string(),
                })?;
            }
            Err(e) => {
                return Err(StorageError::ReadFile {
                    path: current.display().to_string(),
                    cause: e.to_string(),
                });
            }
        }
    }

    let final_canon = current.canonicalize().map_err(|e| StorageError::ReadFile {
        path: current.display().to_string(),
        cause: format!("failed to canonicalize mount destination: {}", e),
    })?;
    if !final_canon.starts_with(&root_canon) {
        return Err(StorageError::ValidationFailed {
            context: "mount destination".to_string(),
            reason: "resolved path escapes rootfs".to_string(),
        });
    }

    Ok(final_canon)
}

/// Global state for packed layers support.
/// Set at startup if SMOLVM_PACKED_LAYERS env var is present.
static PACKED_LAYERS_DIR: OnceLock<Option<PathBuf>> = OnceLock::new();

/// Global state for boot-time volume mounts.
/// Set at startup if SMOLVM_MOUNT_COUNT env var is present.
static BOOT_VOLUME_MOUNTS: OnceLock<Vec<(String, String, bool)>> = OnceLock::new();

/// Initialize packed layers support by checking SMOLVM_PACKED_LAYERS env var.
/// Format: "virtiofs_tag:mount_point" (e.g., "smolvm_layers:/packed_layers")
/// Returns the mount point path if successfully mounted.
pub fn init_packed_layers() -> Option<PathBuf> {
    let env_val = match std::env::var("SMOLVM_PACKED_LAYERS") {
        Ok(v) => v,
        Err(_) => return None,
    };

    // Parse "tag:mount_point"
    let parts: Vec<&str> = env_val.split(':').collect();
    if parts.len() != 2 {
        warn!(env_val = %env_val, "invalid SMOLVM_PACKED_LAYERS format, expected 'tag:mount_point'");
        return None;
    }

    let tag = parts[0];
    let mount_point = PathBuf::from(parts[1]);

    info!(tag = %tag, mount_point = %mount_point.display(), "setting up packed layers from virtiofs");

    // Create mount point
    if let Err(e) = std::fs::create_dir_all(&mount_point) {
        warn!(error = %e, mount_point = %mount_point.display(), "failed to create packed layers mount point");
        return None;
    }

    // Mount virtiofs using direct syscall (avoids ~3-5ms fork+exec overhead)
    #[cfg(target_os = "linux")]
    {
        let src = std::ffi::CString::new(tag).ok()?;
        let dst = std::ffi::CString::new(mount_point.to_str()?).ok()?;
        let fstype = std::ffi::CString::new("virtiofs").unwrap();
        // SAFETY: mount virtiofs with valid CString arguments
        let rc = unsafe {
            libc::mount(
                src.as_ptr(),
                dst.as_ptr(),
                fstype.as_ptr(),
                0,
                std::ptr::null(),
            )
        };

        if rc != 0 {
            let err = std::io::Error::last_os_error();
            warn!(error = %err, tag = %tag, "failed to mount packed layers virtiofs");
            return None;
        }
        info!(mount_point = %mount_point.display(), "packed layers mounted successfully");

        // List contents for debugging (only at debug level to avoid boot overhead)
        if let Ok(entries) = std::fs::read_dir(&mount_point) {
            let layer_dirs: Vec<_> = entries
                .filter_map(|e| e.ok())
                .filter(|e| e.path().is_dir())
                .map(|e| e.file_name().to_string_lossy().to_string())
                .collect();
            debug!(layer_count = layer_dirs.len(), layers = ?layer_dirs, "packed layers available");
        }

        Some(mount_point)
    }
    #[cfg(not(target_os = "linux"))]
    {
        warn!("packed layers mount not supported on non-Linux");
        None
    }
}

/// Get the packed layers directory if available.
pub fn get_packed_layers_dir() -> Option<&'static PathBuf> {
    PACKED_LAYERS_DIR.get_or_init(init_packed_layers).as_ref()
}

/// Initialize volume mounts at boot by reading SMOLVM_MOUNT_* env vars.
///
/// The host launcher sets:
///   SMOLVM_MOUNT_COUNT=N
///   SMOLVM_MOUNT_0=smolvm0:/data:rw
///   SMOLVM_MOUNT_1=smolvm1:/config:ro
///
/// This mounts each virtiofs device at its staging area and bind-mounts
/// to the guest target path, making volumes visible to all code paths
/// including VmExec.
pub fn init_volume_mounts() -> &'static [(String, String, bool)] {
    BOOT_VOLUME_MOUNTS.get_or_init(|| {
        let count: usize = match std::env::var("SMOLVM_MOUNT_COUNT") {
            Ok(v) => match v.parse() {
                Ok(n) => n,
                Err(_) => {
                    warn!(value = %v, "invalid SMOLVM_MOUNT_COUNT");
                    return Vec::new();
                }
            },
            Err(_) => return Vec::new(),
        };

        let mut mounts = Vec::with_capacity(count);
        for i in 0..count {
            let env_key = format!("SMOLVM_MOUNT_{}", i);
            let env_val = match std::env::var(&env_key) {
                Ok(v) => v,
                Err(_) => {
                    warn!(key = %env_key, "missing mount env var");
                    continue;
                }
            };

            // Parse "tag:guest_path:ro|rw"
            let parts: Vec<&str> = env_val.splitn(3, ':').collect();
            if parts.len() != 3 {
                warn!(key = %env_key, value = %env_val, "invalid mount format, expected tag:path:ro|rw");
                continue;
            }

            let tag = parts[0].to_string();
            let guest_path = parts[1].to_string();
            let read_only = parts[2] == "ro";

            info!(tag = %tag, guest_path = %guest_path, read_only = read_only, "boot volume mount");
            mounts.push((tag, guest_path, read_only));
        }

        // Mount using existing logic with empty rootfs prefix so bind mounts
        // go to absolute guest paths (e.g., "/data"), visible to VmExec.
        if !mounts.is_empty() {
            if let Err(e) = setup_volume_mounts("/", &mounts) {
                warn!(error = %e, "failed to setup boot volume mounts");
            }
        }

        mounts
    })
}

/// Add the /storage/workspace → /workspace fallback bind mount to an OCI spec,
/// unless a user-provided volume already claims /workspace.
///
/// The fallback exposes the storage disk's workspace directory inside containers
/// so that persistent files written to /workspace survive across VM restarts.
/// It must be skipped when the user provides `-v host:/workspace` to avoid
/// silently overwriting their virtiofs mount (which comes earlier in the spec).
///
/// Mount target comparison is slash-normalized to handle trailing slashes.
pub fn add_workspace_fallback(spec: &mut OciSpec, mounts: &[(String, String, bool)]) {
    let workspace_src = Path::new(STORAGE_ROOT).join(WORKSPACE_DIR);
    if !workspace_src.exists() {
        return;
    }
    let user_owns_workspace = mounts
        .iter()
        .any(|(_, path, _)| path.trim_end_matches('/') == paths::WORKSPACE_GUEST_PATH);
    if !user_owns_workspace {
        spec.add_bind_mount(
            &workspace_src.to_string_lossy(),
            paths::WORKSPACE_GUEST_PATH,
            false,
        );
    }
}

/// Expose the per-VM `/storage` disk inside privileged containers, so an
/// `--image` machine has the same filesystem topology as a bare VM: `/storage`
/// (and therefore `/storage/docker`, `/storage/workspace`, …) resolves to the
/// ext4 disk identically with or without `--image`, and bind-mounts the workload
/// makes against it — e.g. docker-in-VM binding `/storage/docker` →
/// `/var/lib/docker` so overlay2 lands on ext4, not the rootfs overlay — work
/// the same in a container as in a bare VM.
///
/// Privileged-only: when `unprivileged` the container is a defense-in-depth
/// boundary for untrusted code, so it must NOT see the VM's storage disk (its
/// image archives and overlay plumbing). `/storage` is per-machine, so for a
/// privileged workload — where the microVM is the security boundary — exposing
/// it crosses no isolation boundary; it only mirrors what a bare VM already has.
///
/// Skipped when the user already mounted something at `/storage`, and a no-op
/// when the disk isn't mounted (bare agent rootfs / no storage disk).
pub fn add_storage_fallback(
    spec: &mut OciSpec,
    mounts: &[(String, String, bool)],
    unprivileged: bool,
) {
    // Decide policy first (testable without a mounted disk), then gate on the
    // disk actually being present (a no-op on a bare agent rootfs).
    if should_expose_storage(mounts, unprivileged) && Path::new(STORAGE_ROOT).exists() {
        spec.add_bind_mount(STORAGE_ROOT, STORAGE_ROOT, false);
    }
}

/// Policy for [`add_storage_fallback`]: a privileged workload that hasn't already
/// claimed `/storage` should see the VM's storage disk. Unprivileged containers
/// never do (defense-in-depth boundary for untrusted code).
fn should_expose_storage(mounts: &[(String, String, bool)], unprivileged: bool) -> bool {
    if unprivileged {
        return false;
    }
    !mounts
        .iter()
        .any(|(_, path, _)| path.trim_end_matches('/') == STORAGE_ROOT)
}

/// Name of the optional index file (written into the packed-layers dir at
/// extraction time) recording the layers in OCI order, bottom-most first, one
/// short layer id per line.
///
/// Packed layer subdirs are content-addressed (named by digest), so sorting
/// their names does NOT reproduce the manifest's stacking order. That is fine
/// for the common single-flattened-layer image, but a multi-layer pack (e.g. an
/// init-cache base + init-overlay layer from `pack create --from-vm`) gets
/// mis-stacked: the base can sort above the overlay, so overlayfs shadows the
/// overlay's in-place edits to base files (`/etc/ld.so.cache`,
/// `/var/lib/dpkg/status`) while keeping its new files — installed packages then
/// appear on disk but unregistered, and libs in multiarch dirs fail to load.
/// Honoring this index restores the true order; absent (older packs) we fall
/// back to a name sort.
const LAYER_ORDER_FILE: &str = "layer-order";

/// Packed layer directory names in OCI order, **bottom-most layer first**.
///
/// Honors [`LAYER_ORDER_FILE`] when present and self-consistent; otherwise falls
/// back to a lexical name sort (correct for the single-flattened-layer case).
/// Only names backed by an existing subdirectory are returned, which also drops
/// stray non-layer dirs (e.g. macOS `.fseventsd`) when the index is present.
fn ordered_packed_layer_names(packed_dir: &Path) -> Result<Vec<String>> {
    // The layer subdirs actually present (excluding source `.tar` files and the
    // order index itself, which is a plain file).
    let mut present: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let entries = std::fs::read_dir(packed_dir)
        .map_err(|e| StorageError::read_error(packed_dir.display().to_string(), e))?;
    for entry in entries {
        let entry = entry?;
        if entry.path().is_dir() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.ends_with(".tar") {
                present.insert(name);
            }
        }
    }

    // Prefer the explicit order index when it resolves to layers we actually have.
    if let Ok(contents) = std::fs::read_to_string(packed_dir.join(LAYER_ORDER_FILE)) {
        let ordered: Vec<String> = contents
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| present.contains(l))
            .collect();
        if !ordered.is_empty() {
            return Ok(ordered);
        }
    }

    // Fallback: name sort (BTreeSet is already ascending = bottom→top by the
    // legacy "stub creates layers in order" convention).
    Ok(present.into_iter().collect())
}

/// Create a synthetic ImageInfo from packed layers.
/// This is used when running from a packed binary where layers are pre-extracted.
fn create_packed_image_info(image: &str, packed_dir: &Path) -> Result<ImageInfo> {
    // Layer dirs in OCI order (bottom→top), as sha256:{short_digest} ids.
    let layer_dirs: Vec<String> = ordered_packed_layer_names(packed_dir)?
        .into_iter()
        .map(|name| format!("sha256:{}", name))
        .collect();

    // Size is informational only — never walk the layer trees for it. The
    // packed dir is virtiofs-backed, and stat-ing a multi-GB extracted layer
    // (hundreds of thousands of files) costs a FUSE round-trip per entry:
    // minutes on the first Run, which blows the client's 120s read timeout and
    // surfaces as EAGAIN before the container ever assembles.
    let total_size = 0u64;

    // Determine architecture from environment or default
    #[cfg(target_arch = "aarch64")]
    let architecture = "arm64".to_string();
    #[cfg(target_arch = "x86_64")]
    let architecture = "amd64".to_string();
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    let architecture = "unknown".to_string();

    // For a flattened local archive these come from the recovered image config;
    // a .smolmachine has no config.json so they stay empty (its config lives in
    // the PackManifest).
    let (entrypoint, cmd, env, workdir, user) = read_packed_image_config(packed_dir);

    Ok(ImageInfo {
        reference: image.to_string(),
        digest: "packed".to_string(), // No real digest available for packed images
        size: total_size,
        created: None,
        architecture,
        os: "linux".to_string(),
        layer_count: layer_dirs.len(),
        layers: layer_dirs,
        entrypoint,
        cmd,
        env,
        workdir,
        user,
    })
}

// =============================================================================
// Local image archives (`docker save` / `podman save`)
// =============================================================================
//
// smolvm delegates turning a saved-image archive into a rootfs to the bundled
// `crane` (and `gunzip`/`tar`) rather than parsing OCI layers itself. The host
// stages `archive.tar` into a content-addressed dir mounted via virtiofs as the
// packed-layers dir; here we flatten it once into a rootfs on the writable
// storage disk, recover the image config, and present it as a single packed
// layer that the existing overlay path consumes.

/// Filename the host stages the saved-image archive under.
const ARCHIVE_FILE_NAME: &str = "archive.tar";
/// Subdir the flattened rootfs is written to (a single packed "layer").
const ARCHIVE_ROOTFS_DIR: &str = "0000_rootfs";
/// Recovered image config (`crane config` output) beside the rootfs.
const ARCHIVE_CONFIG_FILE: &str = "config.json";
/// Marker written once a flatten completes, so restarts reuse it.
const ARCHIVE_EXTRACTED_MARKER: &str = ".extracted";

/// If `packed_dir` is a staged local image archive (it contains `archive.tar`),
/// flatten it once into a rootfs on the storage disk and return that directory
/// (holding `0000_rootfs/` + `config.json`). Returns `None` for an ordinary
/// packed-layers dir (a `.smolmachine`'s pre-extracted layers).
///
/// The output is keyed by the virtiofs mount-point name (constant per VM, since
/// `/storage` is per-machine), and the completion marker stores the archive's
/// size+mtime signature. A start reuses the flatten only when that signature
/// still matches, so a machine re-created from a different image on a reused
/// disk re-flattens instead of booting the old rootfs. The marker is written
/// last, so the image-info and overlay paths share one flatten within a start.
fn ensure_archive_flattened(packed_dir: &Path) -> Result<Option<PathBuf>> {
    let archive = packed_dir.join(ARCHIVE_FILE_NAME);
    if !archive.exists() {
        return Ok(None);
    }
    let key = packed_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("archive");
    let out_base = Path::new(STORAGE_ROOT).join("image-archives").join(key);
    let marker = out_base.join(ARCHIVE_EXTRACTED_MARKER);
    let signature = archive_signature(&archive)?;
    if std::fs::read_to_string(&marker).ok().as_deref() == Some(signature.as_str()) {
        return Ok(Some(out_base));
    }

    // First flatten, or the archive changed under a reused disk: rebuild.
    let _ = std::fs::remove_dir_all(&out_base);
    let rootfs = out_base.join(ARCHIVE_ROOTFS_DIR);
    std::fs::create_dir_all(&rootfs)?;
    info!(archive = %archive.display(), rootfs = %rootfs.display(), "flattening local image archive");
    flatten_archive(&archive, &rootfs)?;
    // Recover the image config before writing the marker, so a later reuse can
    // rely on config.json being present. A docker/podman `save` always carries
    // one.
    recover_archive_config(&archive, &out_base.join(ARCHIVE_CONFIG_FILE))?;
    std::fs::write(&marker, signature)?;
    Ok(Some(out_base))
}

/// A cheap content signature for a staged archive (size + mtime), used to
/// invalidate a stale flatten when a reused disk's archive changed.
fn archive_signature(archive: &Path) -> Result<String> {
    let meta = std::fs::metadata(archive)?;
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    Ok(format!("{}:{}", meta.len(), mtime))
}

/// Feed an archive to `cmd`'s stdin, transparently decompressing a gzip- OR
/// zstd-compressed outer archive first. A compressed archive is expanded to a
/// temp file whose handle is returned so the caller keeps it alive until `cmd`
/// has consumed it; a plain archive streams straight through. This handles zstd,
/// which the old `gunzip`-only path silently mangled.
fn pipe_archive_into(cmd: &mut Command, archive: &Path) -> Result<Option<tempfile::NamedTempFile>> {
    let file = std::fs::File::open(archive)?;
    if !is_compressed(archive)? {
        cmd.stdin(Stdio::from(file));
        return Ok(None);
    }
    // Expand to a temp file, then feed that. `docker save` archives are a local
    // dev-import path, so the extra copy is cheap and avoids threading a
    // streaming decompressor into a subprocess's stdin. The guest ships no zstd
    // tool, so decompression is done in-process.
    let mut reader = decompress_layer_reader(file)?;
    let mut tmp = tempfile::NamedTempFile::new()
        .map_err(|e| StorageError::new(format!("failed to create temp file: {e}")))?;
    std::io::copy(&mut reader, tmp.as_file_mut())
        .map_err(|e| StorageError::new(format!("failed to decompress archive: {e}")))?;
    let reopened = tmp
        .reopen()
        .map_err(|e| StorageError::new(format!("failed to reopen temp file: {e}")))?;
    cmd.stdin(Stdio::from(reopened));
    Ok(Some(tmp))
}

/// Flatten a `docker save` archive into `rootfs`, delegating to the bundled
/// `crane export`. The flattened tar is a single layer with no whiteouts, so
/// plain `tar -x` is sufficient (no per-layer handling needed).
fn flatten_archive(archive: &Path, rootfs: &Path) -> Result<()> {
    // crane export - - : read an image tarball from stdin, write a flat rootfs
    // tar to stdout.
    let mut crane = Command::new("crane");
    crane
        .args(["export", "-", "-"])
        .stdout(Stdio::piped())
        // Capture (don't discard) crane's stderr so a failure reports the REAL
        // reason — e.g. "file manifest.json not found in tar" for an empty or
        // truncated archive — instead of a misleading guess.
        .stderr(Stdio::piped());
    // Held alive until crane has consumed it (the decompressed input, if any).
    let _archive_tmp = pipe_archive_into(&mut crane, archive)?;

    let mut crane_child = crane
        .spawn()
        .map_err(|e| StorageError::new(format!("failed to spawn crane export: {e}")))?;
    let crane_out = crane_child
        .stdout
        .take()
        .ok_or_else(|| StorageError::new("failed to capture crane stdout".to_string()))?;
    let mut crane_err = crane_child
        .stderr
        .take()
        .ok_or_else(|| StorageError::new("failed to capture crane stderr".to_string()))?;

    let tar_out = Command::new("tar")
        .arg("-x")
        .arg("-C")
        .arg(rootfs)
        .stdin(Stdio::from(crane_out))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| StorageError::new(format!("failed to run tar: {e}")))?;

    let crane_status = crane_child
        .wait()
        .map_err(|e| StorageError::new(format!("failed to wait for crane: {e}")))?;

    if !crane_status.success() {
        // crane's stderr is a single short line; reading it after the process
        // exits (its stdout was drained by `tar`) cannot deadlock.
        let mut stderr = String::new();
        let _ = std::io::Read::read_to_string(&mut crane_err, &mut stderr);
        let stderr = stderr.trim();
        return Err(StorageError::new(format!(
            "crane export failed{} (is the image a valid `docker save` / OCI archive?)",
            if stderr.is_empty() {
                String::new()
            } else {
                format!(": {stderr}")
            }
        )));
    }
    if !tar_out.status.success() {
        return Err(StorageError::new(format!(
            "extracting flattened rootfs failed: {}",
            String::from_utf8_lossy(&tar_out.stderr)
        )));
    }
    Ok(())
}

/// Recover the image config (Entrypoint/Cmd/Env/…) from a `docker save` archive
/// and write it to `dest`. The archive's `manifest.json` names the config blob
/// under its `Config` key; both are small JSON members extracted with `tar`
/// (image metadata, not layer/rootfs assembly — that stays delegated to crane).
fn recover_archive_config(archive: &Path, dest: &Path) -> Result<()> {
    let manifest_bytes = extract_tar_member(archive, "manifest.json")?;
    let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| StorageError::new(format!("parse archive manifest.json: {e}")))?;
    let config_path = manifest[0]["Config"].as_str().ok_or_else(|| {
        StorageError::new("archive manifest.json has no Config entry".to_string())
    })?;
    let config_bytes = extract_tar_member(archive, config_path)?;
    std::fs::write(dest, &config_bytes)?;
    Ok(())
}

/// Extract a single named member from an archive to memory via `tar -xO`,
/// transparently `gunzip`-ing a gzipped outer archive.
fn extract_tar_member(archive: &Path, member: &str) -> Result<Vec<u8>> {
    let mut tar = Command::new("tar");
    tar.args(["-x", "-O", "-f", "-"])
        .arg(member)
        .stderr(Stdio::null());
    // Held alive until tar has consumed it (the decompressed input, if any).
    let _archive_tmp = pipe_archive_into(&mut tar, archive)?;
    let out = tar
        .output()
        .map_err(|e| StorageError::new(format!("failed to run tar: {e}")))?;
    if !out.status.success() || out.stdout.is_empty() {
        return Err(StorageError::new(format!(
            "could not read '{member}' from archive"
        )));
    }
    Ok(out.stdout)
}

/// Whether a file begins with a supported compression magic — gzip (`1f 8b`) or
/// zstd (`28 b5 2f fd`).
fn is_compressed(path: &Path) -> Result<bool> {
    use std::io::Read;
    let mut magic = [0u8; 4];
    let n = std::fs::File::open(path)?.read(&mut magic).unwrap_or(0);
    Ok((n >= 2 && magic[0] == 0x1f && magic[1] == 0x8b)
        || (n >= 4 && magic[..4] == [0x28, 0xb5, 0x2f, 0xfd]))
}

/// Read `Entrypoint`/`Cmd`/`Env`/`WorkingDir`/`User` from a recovered image
/// `config.json` (the `crane config` output) in `packed_dir`, defaulting to
/// empty when absent — a `.smolmachine` has no such file.
#[allow(clippy::type_complexity)]
fn read_packed_image_config(
    packed_dir: &Path,
) -> (
    Vec<String>,
    Vec<String>,
    Vec<String>,
    Option<String>,
    Option<String>,
) {
    let empty = (Vec::new(), Vec::new(), Vec::new(), None, None);
    let Ok(content) = std::fs::read_to_string(packed_dir.join(ARCHIVE_CONFIG_FILE)) else {
        return empty;
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) else {
        return empty;
    };
    let cfg = &json["config"];
    let string_list = |key: &str| -> Vec<String> {
        cfg[key]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    let non_empty = |key: &str| -> Option<String> {
        cfg[key]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(String::from)
    };
    (
        string_list("Entrypoint"),
        string_list("Cmd"),
        string_list("Env"),
        non_empty("WorkingDir"),
        non_empty("User"),
    )
}

/// Error type for storage operations.
#[derive(Debug)]
#[allow(dead_code)] // Some variants reserved for future use
pub enum StorageError {
    // ========================================================================
    // I/O Errors
    // ========================================================================
    /// Failed to create a directory.
    CreateDir { path: String, cause: String },
    /// Failed to remove a directory.
    RemoveDir { path: String, cause: String },
    /// Failed to read a file or directory.
    ReadFile { path: String, cause: String },
    /// Failed to write a file.
    WriteFile { path: String, cause: String },
    /// Failed to create a symlink.
    Symlink {
        source: String,
        target: String,
        cause: String,
    },
    /// Path conversion error.
    InvalidPath { path: String },

    // ========================================================================
    // Image Errors
    // ========================================================================
    /// Image not found locally.
    ImageNotFound { image: String },
    /// Failed to pull image from registry.
    ImagePullFailed { image: String, cause: String },
    /// Invalid image reference format.
    InvalidImageReference { reference: String, reason: String },

    // ========================================================================
    // Layer Errors
    // ========================================================================
    /// Layer not found.
    LayerNotFound { digest: String },
    /// Failed to extract layer.
    LayerExtractionFailed { digest: String, cause: String },
    /// Layer index out of bounds.
    LayerIndexOutOfBounds {
        image: String,
        index: usize,
        total: usize,
    },

    // ========================================================================
    // Manifest/Config Errors
    // ========================================================================
    /// Failed to parse manifest or config JSON.
    ParseError { context: String, cause: String },
    /// Missing required field in manifest/config.
    MissingField { context: String, field: String },
    /// Unsupported manifest format.
    UnsupportedManifest { media_type: String },

    // ========================================================================
    // Mount Errors
    // ========================================================================
    /// Failed to mount overlay filesystem.
    OverlayMountFailed { path: String, cause: String },
    /// Failed to unmount filesystem.
    UnmountFailed { path: String, cause: String },

    // ========================================================================
    // Command Execution Errors
    // ========================================================================
    /// External command (crane, crun, etc.) failed.
    CommandFailed {
        command: String,
        exit_code: Option<i32>,
        stderr: String,
    },
    /// Failed to spawn external command.
    SpawnFailed { command: String, cause: String },

    // ========================================================================
    // Validation Errors
    // ========================================================================
    /// Input validation failed.
    ValidationFailed { context: String, reason: String },

    // ========================================================================
    // Storage State Errors
    // ========================================================================
    /// Storage not formatted/initialized.
    StorageNotReady { reason: String },
    /// No images found in storage.
    NoImagesFound,

    // ========================================================================
    // Generic
    // ========================================================================
    /// Internal error with message (fallback for complex cases).
    Internal { message: String },
}

#[allow(dead_code)] // Some helpers reserved for future use
impl StorageError {
    /// Create a new internal error with the given message.
    /// Use this as a fallback when no specific variant fits.
    pub fn new(message: impl Into<String>) -> Self {
        StorageError::Internal {
            message: message.into(),
        }
    }

    /// Create an I/O read error.
    pub fn read_error(path: impl Into<String>, cause: impl std::fmt::Display) -> Self {
        StorageError::ReadFile {
            path: path.into(),
            cause: cause.to_string(),
        }
    }

    /// Create an I/O write error.
    pub fn write_error(path: impl Into<String>, cause: impl std::fmt::Display) -> Self {
        StorageError::WriteFile {
            path: path.into(),
            cause: cause.to_string(),
        }
    }

    /// Create a directory creation error.
    pub fn create_dir_error(path: impl Into<String>, cause: impl std::fmt::Display) -> Self {
        StorageError::CreateDir {
            path: path.into(),
            cause: cause.to_string(),
        }
    }

    /// Create a parse error.
    pub fn parse_error(context: impl Into<String>, cause: impl std::fmt::Display) -> Self {
        StorageError::ParseError {
            context: context.into(),
            cause: cause.to_string(),
        }
    }

    /// Create a command failed error.
    pub fn command_failed(
        command: impl Into<String>,
        exit_code: Option<i32>,
        stderr: impl Into<String>,
    ) -> Self {
        StorageError::CommandFailed {
            command: command.into(),
            exit_code,
            stderr: stderr.into(),
        }
    }
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // I/O errors
            StorageError::CreateDir { path, cause } => {
                write!(f, "failed to create directory '{}': {}", path, cause)
            }
            StorageError::RemoveDir { path, cause } => {
                write!(f, "failed to remove directory '{}': {}", path, cause)
            }
            StorageError::ReadFile { path, cause } => {
                write!(f, "failed to read '{}': {}", path, cause)
            }
            StorageError::WriteFile { path, cause } => {
                write!(f, "failed to write '{}': {}", path, cause)
            }
            StorageError::Symlink {
                source,
                target,
                cause,
            } => {
                write!(
                    f,
                    "failed to create symlink '{}' -> '{}': {}",
                    source, target, cause
                )
            }
            StorageError::InvalidPath { path } => {
                write!(f, "invalid path: {}", path)
            }

            // Image errors
            StorageError::ImageNotFound { image } => {
                write!(f, "image not found: {}", image)
            }
            StorageError::ImagePullFailed { image, cause } => {
                write!(f, "failed to pull image '{}': {}", image, cause)
            }
            StorageError::InvalidImageReference { reference, reason } => {
                write!(f, "invalid image reference '{}': {}", reference, reason)
            }

            // Layer errors
            StorageError::LayerNotFound { digest } => {
                write!(f, "layer not found: {}", digest)
            }
            StorageError::LayerExtractionFailed { digest, cause } => {
                write!(f, "failed to extract layer '{}': {}", digest, cause)
            }
            StorageError::LayerIndexOutOfBounds {
                image,
                index,
                total,
            } => {
                write!(
                    f,
                    "layer index {} out of bounds for image '{}' (has {} layers)",
                    index, image, total
                )
            }

            // Manifest/config errors
            StorageError::ParseError { context, cause } => {
                write!(f, "failed to parse {}: {}", context, cause)
            }
            StorageError::MissingField { context, field } => {
                write!(f, "missing '{}' in {}", field, context)
            }
            StorageError::UnsupportedManifest { media_type } => {
                write!(f, "unsupported manifest format: {}", media_type)
            }

            // Mount errors
            StorageError::OverlayMountFailed { path, cause } => {
                write!(f, "overlay mount failed at '{}': {}", path, cause)
            }
            StorageError::UnmountFailed { path, cause } => {
                write!(f, "failed to unmount '{}': {}", path, cause)
            }

            // Command errors
            StorageError::CommandFailed {
                command,
                exit_code,
                stderr,
            } => {
                if let Some(code) = exit_code {
                    write!(f, "{} failed (exit {}): {}", command, code, stderr)
                } else {
                    write!(f, "{} failed: {}", command, stderr)
                }
            }
            StorageError::SpawnFailed { command, cause } => {
                write!(f, "failed to spawn '{}': {}", command, cause)
            }

            // Validation errors
            StorageError::ValidationFailed { context, reason } => {
                write!(f, "{}: {}", context, reason)
            }

            // Storage state errors
            StorageError::StorageNotReady { reason } => {
                write!(f, "storage not ready: {}", reason)
            }
            StorageError::NoImagesFound => {
                write!(f, "no images found")
            }

            // Generic
            StorageError::Internal { message } => {
                write!(f, "{}", message)
            }
        }
    }
}

impl std::error::Error for StorageError {}

impl From<std::io::Error> for StorageError {
    fn from(e: std::io::Error) -> Self {
        StorageError::Internal {
            message: e.to_string(),
        }
    }
}

type Result<T> = std::result::Result<T, StorageError>;

/// Check if a layer directory is properly cached (exists and has content).
///
/// An empty layer directory indicates failed/incomplete extraction and should
/// be re-extracted. This prevents issues where layer_dir.exists() returns true
/// but the directory is empty due to interrupted extraction.
fn is_layer_cached(layer_dir: &Path) -> bool {
    if !layer_dir.exists() {
        return false;
    }
    // Check if the directory has any entries
    match std::fs::read_dir(layer_dir) {
        Ok(mut entries) => entries.next().is_some(),
        Err(_) => false,
    }
}

/// Initialize storage directories.
///
/// This function ensures all required storage directories exist and are accessible.
/// Returns early (successfully) if storage hasn't been formatted yet.
///
/// Note: `mount_storage_disk()` already creates all directories, so this is
/// not called during boot. Kept for manual validation/repair use cases.
#[allow(dead_code)]
pub fn init() -> Result<()> {
    let root = Path::new(STORAGE_ROOT);

    // Check if storage root exists or can be created
    if !root.exists() {
        info!(path = %root.display(), "creating storage root directory");
        std::fs::create_dir_all(root).map_err(|e| {
            StorageError::new(format!(
                "failed to create storage root '{}': {} (check permissions and disk space)",
                root.display(),
                e
            ))
        })?;
    }

    // Verify storage root is accessible
    if let Err(e) = std::fs::read_dir(root) {
        return Err(StorageError::new(format!(
            "storage root '{}' exists but is not accessible: {} (check permissions)",
            root.display(),
            e
        )));
    }

    // Create container runtime directories unconditionally — these are needed
    // as soon as containers are requested, regardless of storage format state.
    let container_dirs = [
        (paths::CONTAINERS_RUN_DIR, "container runtime state"),
        (paths::CONTAINERS_LOGS_DIR, "container logs"),
        (paths::CONTAINERS_EXIT_DIR, "container exit codes"),
        (paths::CRUN_ROOT_DIR, "crun state root"),
    ];

    let mut created_count = 0;
    for (dir, description) in &container_dirs {
        let path = Path::new(dir);
        if !path.exists() {
            std::fs::create_dir_all(path).map_err(|e| {
                StorageError::new(format!(
                    "failed to create {} directory '{}': {}",
                    description,
                    path.display(),
                    e
                ))
            })?;
            debug!(path = %path.display(), description = %description, "created directory");
            created_count += 1;
        }
    }

    // Check for marker file to see if formatted
    let marker = root.join(".smolvm_formatted");
    if !marker.exists() {
        info!(path = %root.display(), "storage not formatted, waiting for format request");
        return Ok(());
    }

    // Create OCI storage directory structure
    let required_dirs = [
        (LAYERS_DIR, "OCI image layers"),
        (CONFIGS_DIR, "image configurations"),
        (MANIFESTS_DIR, "image manifests"),
        (OVERLAYS_DIR, "overlay filesystems"),
        (
            WORKSPACE_DIR,
            "shared workspace (visible inside containers)",
        ),
    ];

    for (dir, description) in &required_dirs {
        let path = root.join(dir);
        if !path.exists() {
            std::fs::create_dir_all(&path).map_err(|e| {
                StorageError::new(format!(
                    "failed to create {} directory '{}': {}",
                    description,
                    path.display(),
                    e
                ))
            })?;
            debug!(path = %path.display(), description = %description, "created directory");
            created_count += 1;
        }
    }

    info!(
        path = %root.display(),
        dirs_created = created_count,
        "storage initialized"
    );
    Ok(())
}

/// Format the storage disk.
///
/// Creates all required directories and writes the format marker file.
/// If directories already exist, they are left as-is.
pub fn format() -> Result<()> {
    let root = Path::new(STORAGE_ROOT);

    // Ensure storage root exists
    if !root.exists() {
        std::fs::create_dir_all(root).map_err(|e| {
            StorageError::new(format!(
                "failed to create storage root '{}': {}",
                root.display(),
                e
            ))
        })?;
    }

    // Create all storage directories
    let all_dirs = [
        (root.join(LAYERS_DIR), "layers"),
        (root.join(CONFIGS_DIR), "configs"),
        (root.join(MANIFESTS_DIR), "manifests"),
        (root.join(OVERLAYS_DIR), "overlays"),
        (PathBuf::from(paths::CONTAINERS_RUN_DIR), "container run"),
        (PathBuf::from(paths::CONTAINERS_LOGS_DIR), "container logs"),
        (PathBuf::from(paths::CONTAINERS_EXIT_DIR), "container exit"),
        (PathBuf::from(paths::CRUN_ROOT_DIR), "crun state root"),
    ];

    for (path, name) in &all_dirs {
        std::fs::create_dir_all(path).map_err(|e| {
            StorageError::new(format!(
                "failed to create {} directory '{}': {}",
                name,
                path.display(),
                e
            ))
        })?;
    }

    // Create marker file
    let marker = root.join(".smolvm_formatted");
    std::fs::write(&marker, "1").map_err(|e| {
        StorageError::new(format!(
            "failed to write format marker '{}': {}",
            marker.display(),
            e
        ))
    })?;

    info!(path = %root.display(), "storage formatted");
    Ok(())
}

/// Get storage status.
pub fn status() -> Result<StorageStatus> {
    let root = Path::new(STORAGE_ROOT);
    let marker = root.join(".smolvm_formatted");

    let ready = marker.exists();

    // Get disk usage (simplified)
    let (total_bytes, used_bytes) = get_disk_usage(root)?;

    // Count layers and images
    let layer_count = count_entries(&root.join(LAYERS_DIR))?;
    let image_count = count_entries(&root.join(MANIFESTS_DIR))?;

    Ok(StorageStatus {
        ready,
        total_bytes,
        used_bytes,
        layer_count,
        image_count,
    })
}

/// Extract a JSON array of strings from a JSON value.
fn json_string_array(value: &serde_json::Value, key: &str) -> Vec<String> {
    value[key]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// OCI/AUFS whiteout marker that deletes a single name from lower layers
/// (`.wh.<name>`).
const WHITEOUT_PREFIX: &str = ".wh.";
/// OCI/AUFS opaque-directory marker: the directory replaces, rather than merges
/// with, the same directory in lower layers (`.wh..wh..opq`).
const OPAQUE_WHITEOUT: &str = ".wh..wh..opq";

/// What an OCI layer tar entry means once its name is interpreted.
#[derive(Debug, PartialEq, Eq)]
enum LayerEntry<'a> {
    /// `.wh..wh..opq`: mark the parent directory opaque.
    OpaqueDir,
    /// `.wh.<name>`: delete `<name>` from lower layers (carries `<name>`).
    Whiteout(&'a str),
    /// An ordinary entry to extract as-is.
    Normal,
}

/// Classify an entry by its file name. The opaque marker must be checked before
/// the generic `.wh.` prefix, since `.wh..wh..opq` also starts with `.wh.`.
fn classify_layer_entry(file_name: &str) -> LayerEntry<'_> {
    if file_name == OPAQUE_WHITEOUT {
        return LayerEntry::OpaqueDir;
    }
    match file_name.strip_prefix(WHITEOUT_PREFIX) {
        Some(name) if !name.is_empty() => LayerEntry::Whiteout(name),
        _ => LayerEntry::Normal,
    }
}

/// Join `rel` under `base`, returning `None` if any component would escape the
/// base (`..`, an absolute path, or a Windows-style prefix). Mirrors the
/// containment guard tar extractors use to prevent path-traversal.
fn jailed_join(base: &Path, rel: &Path) -> Option<PathBuf> {
    use std::path::Component;
    let mut out = base.to_path_buf();
    for component in rel.components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(out)
}

/// Create an overlayfs whiteout (a `mknod` character device with device number
/// 0/0) at `path`, replacing any existing entry. This is how the kernel's
/// overlayfs records "this name is deleted from lower layers" — the on-disk
/// representation that OCI's `.wh.<name>` marker must be translated into.
///
/// Linux-only: overlayfs whiteouts are a Linux concept and the agent only runs
/// in the Linux guest. The non-Linux stub keeps the crate compiling on the
/// macOS host (where `mknod`/`makedev`/xattr signatures differ).
#[cfg(target_os = "linux")]
fn create_overlay_whiteout(path: &Path) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    // Clear any entry the layer may already have written at this name so mknod
    // doesn't fail with EEXIST.
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_dir_all(path);
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    // SAFETY: `c_path` is a valid NUL-terminated path; mode and dev are scalars.
    let rc = unsafe {
        libc::mknod(
            c_path.as_ptr(),
            libc::S_IFCHR as libc::mode_t,
            libc::makedev(0, 0),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn create_overlay_whiteout(_path: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "overlayfs whiteouts are only created in the Linux guest",
    ))
}

/// Mark `dir` opaque for overlayfs via the `trusted.overlay.opaque` xattr — the
/// representation of OCI's `.wh..wh..opq` marker. Linux-only (see
/// [`create_overlay_whiteout`]).
#[cfg(target_os = "linux")]
fn set_overlay_opaque(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(dir.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let name = std::ffi::CString::new("trusted.overlay.opaque").expect("static xattr name");
    let value = b"y";
    // SAFETY: path/name are NUL-terminated; value/len describe a valid buffer.
    let rc = unsafe {
        libc::setxattr(
            c_path.as_ptr(),
            name.as_ptr(),
            value.as_ptr() as *const libc::c_void,
            value.len(),
            0,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn set_overlay_opaque(_dir: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "overlayfs opaque dirs are only set in the Linux guest",
    ))
}

/// Extract one decompressed OCI layer tar into `dest`, applying OCI whiteout
/// semantics so the overlayfs composition is correct.
///
/// Each layer is extracted in isolation into its own directory (later stacked as
/// an overlayfs lowerdir). A plain `tar -x` does not give the kernel's overlayfs
/// what it needs, so this translates at unpack time — the same conversion
/// containerd / docker-overlay2 / containers-storage perform:
/// - `.wh.<name>` (delete marker) → an overlayfs whiteout (`mknod c 0 0`), so
///   the stacked overlay hides `<name>` from lower layers. (busybox `tar` left
///   it as a plain file overlayfs ignores, so deletions never applied; worse,
///   some images ship the marker as a hardlink to a lower-layer file, which
///   aborted the whole extraction — issue #397. Whiteouts are handled by name
///   here, before the hardlink path, so that case is just a normal whiteout.)
/// - `.wh..wh..opq` (opaque-dir marker) → the `trusted.overlay.opaque` xattr on
///   its parent directory.
/// - a hardlink whose target isn't in this layer (it lives in a lower layer) is
///   skipped rather than failing; overlayfs resolves the real file at runtime.
///
/// Requires `CAP_MKNOD` + `CAP_SYS_ADMIN`, which the agent has as guest PID 1.
/// Wrap a layer stream so gzip- AND zstd-compressed layers are transparently
/// decompressed; an already-plain tar passes through. OCI layers are `+gzip` or
/// (what `skopeo` and `smolvm pack` emit by default) `+zstd`. Detection is by
/// magic bytes, so it's correct regardless of the manifest mediaType or the
/// source — registry pull, local pack, or docker-save import — and needs no
/// external tool in the guest rootfs.
fn decompress_layer_reader<'a>(
    mut inner: impl std::io::Read + 'a,
) -> std::io::Result<Box<dyn std::io::Read + 'a>> {
    use std::io::Read;
    // Peek the compression magic without consuming it: read up to 4 bytes, then
    // chain them back in front of the rest of the stream.
    let mut magic = [0u8; 4];
    let mut n = 0;
    while n < magic.len() {
        match inner.read(&mut magic[n..])? {
            0 => break,
            k => n += k,
        }
    }
    let stream = std::io::Cursor::new(magic[..n].to_vec()).chain(inner);
    if n >= 2 && magic[0] == 0x1f && magic[1] == 0x8b {
        Ok(Box::new(flate2::read::GzDecoder::new(stream)))
    } else if n >= 4 && magic[..4] == [0x28, 0xb5, 0x2f, 0xfd] {
        // Pure-Rust zstd decoder — the C `zstd` crate can't link against musl
        // (see the note in Cargo.toml).
        let dec = ruzstd::StreamingDecoder::new(stream)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        Ok(Box::new(dec))
    } else {
        // Uncompressed tar (or unrecognized) — pass through untouched.
        Ok(Box::new(stream))
    }
}

/// The `.smolmachine` sidecar members that identify a smolmachine pack blob
/// masquerading as an OCI layer: `agent-rootfs.tar` is the archive's first
/// entry (so the guard fires before anything large is written) and
/// `storage.ext4` is the multi-GiB disk template that would fill the guest
/// disk. Only TOP-LEVEL entries match — a real container image nesting a
/// same-named file (e.g. `/var/lib/foo/storage.ext4`) must not trip the guard.
fn pack_sidecar_sentinel(path: &Path) -> Option<&'static str> {
    const SENTINELS: [&str; 2] = ["agent-rootfs.tar", "storage.ext4"];
    let mut components = path
        .components()
        .filter(|c| !matches!(c, std::path::Component::CurDir));
    match (components.next(), components.next()) {
        (Some(std::path::Component::Normal(name)), None) => {
            SENTINELS.into_iter().find(|s| name.to_str() == Some(s))
        }
        _ => None,
    }
}

fn extract_oci_layer<R: std::io::Read>(reader: R, dest: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    // Layers arrive gzip- or zstd-compressed (or, rarely, plain). Decompress
    // transparently so a zstd layer no longer breaks extraction.
    let reader = decompress_layer_reader(reader)?;
    let mut archive = tar::Archive::new(reader);
    archive.set_preserve_permissions(true);
    archive.set_preserve_mtime(true);
    // Preserve the archive's uid/gid. The agent runs as root (CAP_CHOWN) so this
    // chowns each entry to the image's intended owner; without it every file is
    // owned by root, breaking images that ship non-root-owned paths (e.g. a
    // `node`/`postgres` user's home or data dir). The previous busybox `tar`
    // preserved ownership by default — the Rust-tar rewrite dropped it.
    archive.set_preserve_ownerships(true);
    archive.set_overwrite(true);

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();

        // A smolmachine PACK blob (mediaType application/vnd.smolmachines.*) is
        // not an OCI filesystem layer: it is a .smolmachine sidecar carrying
        // agent-rootfs.tar and a multi-GiB non-sparse storage.ext4 disk
        // template. Unpacking it here fills the guest disk before failing, so
        // detect its top-level sentinels and abort immediately with a routing
        // hint instead.
        if let Some(sentinel) = pack_sidecar_sentinel(&path) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "layer is a smolmachine pack (contains '{sentinel}') — pull it on the \
                     host via the smolmachine flow, not as a container image"
                ),
            ));
        }

        // Jail the on-disk path under the layer dir (defends against `..` and
        // absolute paths embedded in the archive).
        let Some(full_path) = jailed_join(dest, &path) else {
            warn!(path = %path.display(), "skipping layer entry that escapes the layer dir");
            continue;
        };

        // Whiteout markers are interpreted by name, before normal extraction.
        if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
            match classify_layer_entry(file_name) {
                LayerEntry::OpaqueDir => {
                    if let Some(parent) = full_path.parent() {
                        std::fs::create_dir_all(parent)?;
                        set_overlay_opaque(parent)?;
                    }
                    continue;
                }
                LayerEntry::Whiteout(removed) => {
                    if let Some(parent) = full_path.parent() {
                        std::fs::create_dir_all(parent)?;
                        create_overlay_whiteout(&parent.join(removed))?;
                    }
                    continue;
                }
                LayerEntry::Normal => {}
            }
        }

        // A hardlink whose target wasn't extracted into this layer can't be
        // created here; skip it (overlayfs resolves the lower-layer file).
        if entry.header().entry_type() == tar::EntryType::Link {
            let target = entry.link_name()?.and_then(|link| jailed_join(dest, &link));
            if target.is_none_or(|t| !t.exists()) {
                continue;
            }
        }

        // Ensure the parent is writable before extracting children — OCI layers
        // can set restrictive directory modes before their contents.
        if let Some(parent) = full_path.parent() {
            if parent.is_dir() {
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755));
            }
        }

        if let Err(e) = entry.unpack_in(dest) {
            // Regular files and directories failing is a real error; non-regular
            // entries (symlinks, device nodes, fifos) can fail benignly — skip.
            match entry.header().entry_type() {
                tar::EntryType::Regular
                | tar::EntryType::GNUSparse
                | tar::EntryType::Continuous
                | tar::EntryType::Directory => {
                    return Err(std::io::Error::new(
                        e.kind(),
                        format!("failed to unpack '{}': {}", path.display(), e),
                    ));
                }
                _ => {
                    warn!(path = %path.display(), error = %e, "skipping non-regular layer entry");
                }
            }
        }
    }
    Ok(())
}

/// Pull an OCI image with progress callback and optional authentication.
///
/// The callback is called for each layer being pulled with (current, total, layer_id).
pub fn pull_image_with_progress_and_auth<F>(
    image: &str,
    oci_platform: Option<&str>,
    auth: Option<&RegistryAuth>,
    proxy: Option<&str>,
    no_proxy: Option<&str>,
    mut progress: F,
) -> Result<ImageInfo>
where
    F: FnMut(usize, usize, &str),
{
    // Validate image reference before any operations
    crate::oci::validate_image_reference(image).map_err(|e| {
        StorageError::InvalidImageReference {
            reference: image.to_string(),
            reason: e,
        }
    })?;

    // Canonicalize so all equivalent refs share the same on-disk cache key.
    let image = normalize_image_ref(image);
    let image = image.as_str();

    // If packed layers are available, return synthetic image info
    if let Some(packed_dir) = get_packed_layers_dir() {
        info!(image = %image, "using packed layers, skipping network pull");
        // A local image archive is flattened into a rootfs first; an ordinary
        // packed-layers dir is used as-is.
        if let Some(flattened) = ensure_archive_flattened(packed_dir)? {
            return create_packed_image_info(image, &flattened);
        }
        return create_packed_image_info(image, packed_dir);
    }

    // Determine OCI platform - default to current architecture
    // This must happen BEFORE the cache check so we can verify architecture
    let oci_platform = oci_platform.or({
        #[cfg(target_arch = "aarch64")]
        {
            Some("linux/arm64")
        }
        #[cfg(target_arch = "x86_64")]
        {
            Some("linux/amd64")
        }
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        {
            None
        }
    });

    // Check if already cached with correct architecture
    if let Ok(Some(info)) = query_image(image) {
        // Verify cached image architecture matches requested OCI platform
        let cached_arch = &info.architecture;
        let requested_arch = oci_platform
            .map(oci_platform_to_arch)
            .unwrap_or_else(|| cached_arch.clone());

        if cached_arch == &requested_arch {
            debug!(
                image = %image,
                architecture = %cached_arch,
                "image already cached with correct architecture, skipping pull"
            );
            return Ok(info);
        } else {
            // Architecture mismatch - need to re-pull
            info!(
                image = %image,
                cached_arch = %cached_arch,
                requested_arch = %requested_arch,
                "cached image has wrong architecture, will re-pull"
            );
            // Clean up the mismatched cached manifest
            let root = Path::new(STORAGE_ROOT);
            let manifest_path = root
                .join(MANIFESTS_DIR)
                .join(sanitize_image_name(image) + ".json");
            let _ = std::fs::remove_file(&manifest_path);
        }
    }

    let root = Path::new(STORAGE_ROOT);

    // Get manifest with OCI platform specified
    progress(0, 0, "fetching manifest");
    info!(image = %image, oci_platform = ?oci_platform, "fetching manifest");
    let manifest = crane_manifest(image, oci_platform, auth, proxy, no_proxy)?;

    // Parse manifest to get config and layers
    let manifest_json: serde_json::Value =
        serde_json::from_str(&manifest).map_err(|e| StorageError::parse_error("manifest", e))?;

    // Handle manifest list (multi-arch)
    let config_digest = if manifest_json.get("config").is_some() {
        manifest_json["config"]["digest"]
            .as_str()
            .ok_or_else(|| StorageError::MissingField {
                context: "manifest".into(),
                field: "config digest".into(),
            })?
    } else if manifest_json.get("manifests").is_some() {
        return Err(StorageError::new(format!(
            "got manifest list instead of image manifest - platform may not be available. \
             manifests: {:?}",
            manifest_json["manifests"].as_array().map(|arr| arr
                .iter()
                .filter_map(|m| m["platform"]["architecture"].as_str())
                .collect::<Vec<_>>())
        )));
    } else {
        return Err(StorageError::UnsupportedManifest {
            media_type: "unknown".into(),
        });
    };

    let layers: Vec<String> = manifest_json["layers"]
        .as_array()
        .ok_or_else(|| StorageError::MissingField {
            context: "manifest".into(),
            field: "layers".into(),
        })?
        .iter()
        .filter_map(|l| l["digest"].as_str().map(String::from))
        .collect();

    let total_layers = layers.len();

    // Save manifest
    let manifest_path = root
        .join(MANIFESTS_DIR)
        .join(sanitize_image_name(image) + ".json");
    std::fs::write(&manifest_path, &manifest)?;

    // Fetch and save config
    let config = crane_config(image, oci_platform, auth, proxy, no_proxy)?;
    let config_id = config_digest
        .strip_prefix("sha256:")
        .unwrap_or(config_digest);
    let config_path = root.join(CONFIGS_DIR).join(format!("{}.json", config_id));
    std::fs::write(&config_path, &config)?;

    // Parse config for metadata
    let config_json: serde_json::Value =
        serde_json::from_str(&config).map_err(|e| StorageError::parse_error("config", e))?;

    // Extract layers with progress updates
    let mut total_size = 0u64;
    for (i, layer_digest) in layers.iter().enumerate() {
        let layer_id = layer_digest.strip_prefix("sha256:").unwrap_or(layer_digest);
        let layer_dir = root.join(LAYERS_DIR).join(layer_id);

        if is_layer_cached(&layer_dir) {
            info!(layer = %layer_id, "layer already cached");
            // Report progress after confirming cache hit
            progress(i + 1, total_layers, layer_id);
            continue;
        }

        // Clean up empty/incomplete layer directory if it exists
        if layer_dir.exists() {
            warn!(layer = %layer_id, "removing empty/incomplete layer directory");
            if let Err(e) = std::fs::remove_dir_all(&layer_dir) {
                warn!(layer = %layer_id, error = %e, "failed to remove incomplete layer directory");
            }
        }

        info!(
            layer = %layer_id,
            progress = format!("{}/{}", i + 1, total_layers),
            "extracting layer"
        );

        std::fs::create_dir_all(&layer_dir)?;

        // Stream layer directly to tar extraction using direct process piping
        // (no shell to avoid injection risks)

        // Set up auth if provided (temp_dir must stay alive until command completes)
        let temp_dir = setup_docker_auth(image, auth)?;

        // Build crane command
        let mut crane_cmd = Command::new("crane");
        crane_cmd.arg("blob");
        crane_cmd.arg(format!("{}@{}", image_repo(image), layer_digest));
        if let Some(p) = oci_platform {
            crane_cmd.arg("--platform").arg(p);
        }
        crane_cmd.stdout(Stdio::piped());
        // Capture crane stderr to a file (not a pipe — a file can't deadlock on a
        // full buffer) so the real fetch failure (DNS, TLS, 4xx, redirect) is
        // surfaced instead of a bare "crane blob failed".
        let crane_stderr_path = layer_dir.join(".crane-stderr");
        match std::fs::File::create(&crane_stderr_path) {
            Ok(f) => {
                crane_cmd.stderr(Stdio::from(f));
            }
            Err(_) => {
                crane_cmd.stderr(Stdio::null());
            }
        }

        if let Some(ref td) = temp_dir {
            crane_cmd.env("DOCKER_CONFIG", td.path());
        }

        apply_proxy_env(&mut crane_cmd, proxy, no_proxy);

        // Spawn crane process
        let mut crane = crane_cmd
            .spawn()
            .map_err(|e| StorageError::new(format!("failed to spawn crane: {}", e)))?;

        // Extract straight from crane's stdout. `extract_oci_layer` transparently
        // decompresses gzip- OR zstd-compressed layers in-process (the guest
        // ships no zstd tool, and the old external `gunzip` pipe silently failed
        // on every zstd layer). Reading the stream to EOF also drives the crane
        // fetch to completion.
        let crane_stdout = crane
            .stdout
            .take()
            .ok_or_else(|| StorageError::new("failed to capture crane stdout".to_string()))?;

        let extract_result = extract_oci_layer(crane_stdout, &layer_dir);

        let crane_status = crane
            .wait()
            .map_err(|e| StorageError::new(format!("failed to wait for crane: {}", e)))?;

        let crane_stderr = std::fs::read_to_string(&crane_stderr_path).unwrap_or_default();
        let _ = std::fs::remove_file(&crane_stderr_path);
        let crane_stderr = crane_stderr.trim();

        // Order matters. A genuine crane fetch failure (network/auth) prints a
        // real message to its stderr, so surface that first. Otherwise, if
        // extraction failed, THAT is the real cause — a crane that exited
        // non-zero with empty stderr is just the SIGPIPE from us closing the pipe
        // when extraction stopped reading (the exact trap that made every zstd
        // layer look like "crane blob failed" when the real problem was that the
        // old pipeline couldn't decompress it).
        let layer_failure = if !crane_status.success() && !crane_stderr.is_empty() {
            Some(format!(
                "crane blob failed for layer {}: {}",
                layer_digest, crane_stderr
            ))
        } else if let Err(e) = extract_result {
            Some(format!(
                "layer extraction failed for layer {}: {}",
                layer_digest, e
            ))
        } else if !crane_status.success() {
            Some(format!("crane blob failed for layer {}", layer_digest))
        } else {
            None
        };

        if let Some(message) = layer_failure {
            if let Err(e) = std::fs::remove_dir_all(&layer_dir) {
                warn!(layer = %layer_id, error = %e, "failed to clean up layer directory after extraction failure");
            }
            return Err(StorageError::new(message));
        }

        if let Ok(size) = dir_size(&layer_dir) {
            total_size += size;
        }

        // Report progress after successful extraction
        progress(i + 1, total_layers, layer_id);
    }

    // Signal that layers are done and we're syncing — this can take a while
    // for large images (gigabytes flushed through virtio-blk).
    progress(total_layers, total_layers, "syncing");

    // Sync filesystem to ensure all layer data is persisted to the ext4 journal.
    // Defense in depth: even though shutdown waits for acknowledgment (which also
    // syncs), we sync here because:
    // 1. Commands may complete and VM may exit before shutdown is called
    // 2. Protects against ungraceful termination (SIGKILL, host crash)
    // 3. Empty layer directories cause "executable not found" errors that are
    //    hard to diagnose - better to be safe than sorry
    // SAFETY: sync() is always safe to call
    unsafe {
        libc::sync();
    }

    // Build ImageInfo
    let architecture = config_json["architecture"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    let os = config_json["os"].as_str().unwrap_or("linux").to_string();
    let created = config_json["created"].as_str().map(String::from);

    // Extract OCI config fields (Entrypoint, Cmd, Env, WorkingDir, User)
    let oci_config = &config_json["config"];
    let entrypoint = json_string_array(oci_config, "Entrypoint");
    let cmd = json_string_array(oci_config, "Cmd");
    let env = json_string_array(oci_config, "Env");
    let workdir = oci_config["WorkingDir"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(String::from);
    let user = oci_config["User"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(String::from);

    Ok(ImageInfo {
        reference: image.to_string(),
        digest: config_digest.to_string(),
        size: total_size,
        created,
        architecture,
        os,
        layer_count: layers.len(),
        layers,
        entrypoint,
        cmd,
        env,
        workdir,
        user,
    })
}

/// Query if an image exists locally.
pub fn query_image(image: &str) -> Result<Option<ImageInfo>> {
    let image = normalize_image_ref(image);
    let image = image.as_str();

    // Packed layers (a `.smolmachine` or a staged local image archive/dir):
    // synthesize image info without a registry manifest, mirroring the pull
    // path. A local image archive is flattened into a rootfs first.
    if let Some(packed_dir) = get_packed_layers_dir() {
        let flattened = ensure_archive_flattened(packed_dir)?;
        let effective = flattened.as_deref().unwrap_or(packed_dir);
        return Ok(Some(create_packed_image_info(image, effective)?));
    }

    let root = Path::new(STORAGE_ROOT);
    let manifest_path = root
        .join(MANIFESTS_DIR)
        .join(sanitize_image_name(image) + ".json");

    if !manifest_path.exists() {
        return Ok(None);
    }

    // Read and parse manifest
    let manifest = std::fs::read_to_string(&manifest_path)?;
    let manifest_json: serde_json::Value =
        serde_json::from_str(&manifest).map_err(|e| StorageError::parse_error("manifest", e))?;

    let config_digest =
        manifest_json["config"]["digest"]
            .as_str()
            .ok_or_else(|| StorageError::MissingField {
                context: "manifest".into(),
                field: "config digest".into(),
            })?;

    let layers: Vec<String> = manifest_json["layers"]
        .as_array()
        .ok_or_else(|| StorageError::MissingField {
            context: "manifest".into(),
            field: "layers".into(),
        })?
        .iter()
        .filter_map(|l| l["digest"].as_str().map(String::from))
        .collect();

    // Read config
    let config_id = config_digest
        .strip_prefix("sha256:")
        .unwrap_or(config_digest);
    let config_path = root.join(CONFIGS_DIR).join(format!("{}.json", config_id));
    let config = std::fs::read_to_string(&config_path)?;
    let config_json: serde_json::Value =
        serde_json::from_str(&config).map_err(|e| StorageError::parse_error("config", e))?;

    let architecture = config_json["architecture"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    let os = config_json["os"].as_str().unwrap_or("linux").to_string();
    let created = config_json["created"].as_str().map(String::from);

    // Verify all layers exist and calculate total size
    let mut total_size = 0u64;
    for layer_digest in &layers {
        let layer_id = layer_digest.strip_prefix("sha256:").unwrap_or(layer_digest);
        let layer_dir = root.join(LAYERS_DIR).join(layer_id);
        if !layer_dir.exists() {
            // Layer missing - image is incomplete, needs re-pull
            // Clean up corrupt manifest to avoid repeated failures
            warn!(layer = %layer_id, image = %image, "cached image has missing layer, cleaning up and will re-pull");
            let _ = std::fs::remove_file(&manifest_path);
            return Ok(None);
        }
        if let Ok(size) = dir_size(&layer_dir) {
            total_size += size;
        }
    }

    // Extract OCI config fields
    let oci_config = &config_json["config"];
    let entrypoint = json_string_array(oci_config, "Entrypoint");
    let cmd = json_string_array(oci_config, "Cmd");
    let env = json_string_array(oci_config, "Env");
    let workdir = oci_config["WorkingDir"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(String::from);
    let user = oci_config["User"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(String::from);

    Ok(Some(ImageInfo {
        reference: image.to_string(),
        digest: config_digest.to_string(),
        size: total_size,
        created,
        architecture,
        os,
        layer_count: layers.len(),
        layers,
        entrypoint,
        cmd,
        env,
        workdir,
        user,
    }))
}

/// List all cached images.
pub fn list_images() -> Result<Vec<ImageInfo>> {
    let root = Path::new(STORAGE_ROOT);
    let manifests_dir = root.join(MANIFESTS_DIR);

    if !manifests_dir.exists() {
        return Ok(Vec::new());
    }

    let mut images = Vec::new();

    for entry in std::fs::read_dir(&manifests_dir)? {
        let entry: std::fs::DirEntry = entry?;
        let path = entry.path();

        if path.extension().map(|e| e == "json").unwrap_or(false) {
            // Extract image name from filename
            let name = path
                .file_stem()
                .and_then(|s| s.to_str())
                .map(unsanitize_image_name)
                .unwrap_or_default();

            if let Ok(Some(info)) = query_image(&name) {
                images.push(info);
            }
        }
    }

    Ok(images)
}

/// Export a layer as a tar archive to a file.
///
/// Used by `smolvm pack` to extract layers for packaging.
/// Returns the path to the created tar file.
/// Find the directory path for a specific layer of an image.
///
/// Scans manifests to find the image by digest, then resolves the layer
/// directory. Used by the streaming export handler to pipe tar directly
/// without creating a temp file.
pub fn find_layer_path(image_digest: &str, layer_index: usize) -> Result<PathBuf> {
    let root = Path::new(STORAGE_ROOT);

    let manifests_dir = root.join(MANIFESTS_DIR);
    if !manifests_dir.exists() {
        return Err(StorageError::NoImagesFound);
    }

    let mut layers: Option<Vec<String>> = None;

    for entry in std::fs::read_dir(&manifests_dir)? {
        let entry = entry?;
        let content = std::fs::read_to_string(entry.path())?;
        if let Ok(manifest) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(config) = manifest.get("config") {
                if let Some(digest) = config.get("digest").and_then(|d| d.as_str()) {
                    if digest == image_digest {
                        layers = manifest["layers"].as_array().map(|arr| {
                            arr.iter()
                                .filter_map(|l| l["digest"].as_str().map(String::from))
                                .collect()
                        });
                        break;
                    }
                }
            }
        }
    }

    let layers = layers.ok_or_else(|| {
        StorageError::new(format!("image with digest {} not found", image_digest))
    })?;

    if layer_index >= layers.len() {
        return Err(StorageError::new(format!(
            "layer index {} out of bounds (image has {} layers)",
            layer_index,
            layers.len()
        )));
    }

    let layer_digest = &layers[layer_index];
    let layer_id = layer_digest.strip_prefix("sha256:").unwrap_or(layer_digest);
    let layer_dir = root.join(LAYERS_DIR).join(layer_id);

    if !layer_dir.exists() {
        return Err(StorageError::new(format!(
            "layer directory not found: {}",
            layer_dir.display()
        )));
    }

    Ok(layer_dir)
}

/// Remove all image manifests and configs, making all layers unreferenced.
///
/// Call this before `garbage_collect()` to implement `prune --all`.
pub fn purge_all_images() -> Result<()> {
    let root = Path::new(STORAGE_ROOT);
    let manifests_dir = root.join(MANIFESTS_DIR);
    let configs_dir = root.join(CONFIGS_DIR);

    if manifests_dir.exists() {
        std::fs::remove_dir_all(&manifests_dir)?;
    }
    if configs_dir.exists() {
        std::fs::remove_dir_all(&configs_dir)?;
    }

    Ok(())
}

/// Run garbage collection.
pub fn garbage_collect(dry_run: bool) -> Result<u64> {
    let root = Path::new(STORAGE_ROOT);
    let layers_dir = root.join(LAYERS_DIR);
    let manifests_dir = root.join(MANIFESTS_DIR);

    // Collect all referenced layers
    let mut referenced_layers = std::collections::HashSet::new();

    if manifests_dir.exists() {
        for entry in std::fs::read_dir(&manifests_dir)? {
            let entry = entry?;
            let content = std::fs::read_to_string(entry.path())?;
            if let Ok(manifest) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(layers) = manifest["layers"].as_array() {
                    for layer in layers {
                        if let Some(digest) = layer["digest"].as_str() {
                            let id = digest.strip_prefix("sha256:").unwrap_or(digest);
                            referenced_layers.insert(id.to_string());
                        }
                    }
                }
            }
        }
    }

    // Find unreferenced layers
    let mut freed = 0u64;

    if layers_dir.exists() {
        for entry in std::fs::read_dir(&layers_dir)? {
            let entry = entry?;
            let layer_id = entry.file_name().to_string_lossy().to_string();

            if !referenced_layers.contains(&layer_id) {
                let size = dir_size(&entry.path()).unwrap_or(0);
                info!(layer = %layer_id, size = size, dry_run = dry_run, "unreferenced layer");

                if !dry_run {
                    std::fs::remove_dir_all(entry.path())?;
                }

                freed += size;
            }
        }
    }

    Ok(freed)
}

// ============================================================================
// Overlay Setup Helper
// ============================================================================

/// Helper for setting up overlay filesystems.
///
/// Encapsulates the common logic for preparing overlay directories,
/// mounting layers, and creating OCI bundles.
struct OverlaySetup {
    overlay_root: PathBuf,
    upper_path: PathBuf,
    work_path: PathBuf,
    merged_path: PathBuf,
    workload_id: String,
}

impl OverlaySetup {
    /// Create a new overlay setup for the given workload.
    fn new(workload_id: &str) -> Result<Self> {
        let overlay_root = overlay_root_for_workload(workload_id)?;
        Ok(Self {
            upper_path: overlay_root.join("upper"),
            work_path: overlay_root.join("work"),
            merged_path: overlay_root.join("merged"),
            overlay_root,
            workload_id: workload_id.to_string(),
        })
    }

    /// Prepare overlay directories, cleaning up any previous state.
    fn prepare_directories(&self) -> Result<()> {
        // Clean up any previous overlay state - workdir must be empty for overlay mount
        if self.overlay_root.exists() {
            // Try to unmount if previously mounted
            if let Err(e) = Command::new("umount").arg(&self.merged_path).output() {
                debug!(path = %self.merged_path.display(), error = %e, "failed to unmount previous overlay (may not have been mounted)");
            }
            // Remove old directories to ensure clean state
            if let Err(e) = std::fs::remove_dir_all(&self.overlay_root) {
                warn!(path = %self.overlay_root.display(), error = %e, "failed to remove old overlay directory");
            }
        }

        std::fs::create_dir_all(&self.upper_path)?;
        std::fs::create_dir_all(&self.work_path)?;
        std::fs::create_dir_all(&self.merged_path)?;

        Ok(())
    }

    /// Set up the upper layer with DNS resolution and /dev directory.
    fn setup_upper_layer(&self) -> Result<()> {
        // Set up DNS resolution BEFORE mounting. Image-backed workloads read
        // `/etc/resolv.conf` from the overlay upper layer, so this file must
        // match the active networking mode rather than always hardcoding
        // public resolvers.
        let upper_etc = self.upper_path.join("etc");
        std::fs::create_dir_all(&upper_etc)?;
        let resolv_path = upper_etc.join("resolv.conf");
        let resolv_contents = overlay_resolv_conf_contents();
        if let Err(e) = std::fs::write(&resolv_path, resolv_contents) {
            warn!(error = %e, "failed to write resolv.conf to upper layer");
        }

        // Create /dev directory in upper layer - we'll bind mount the real /dev later
        let upper_dev = self.upper_path.join("dev");
        std::fs::create_dir_all(&upper_dev)?;

        Ok(())
    }

    /// Verify that all layer paths exist and log warnings for empty layers.
    fn verify_layers(&self, lowerdirs: &[String]) -> Result<()> {
        for layer_path in lowerdirs {
            let path = Path::new(layer_path);
            if !path.exists() {
                return Err(StorageError::new(format!(
                    "layer path does not exist: {}",
                    layer_path
                )));
            }
            // Check if layer has contents
            let entry_count = std::fs::read_dir(path)
                .map(|entries| entries.count())
                .unwrap_or(0);
            if entry_count == 0 {
                warn!(layer = %layer_path, "layer directory is empty");
            }
        }
        Ok(())
    }

    /// Mount the overlay filesystem with fallback from multi-lowerdir to sequential.
    fn mount(&self, lowerdirs: &[String]) -> Result<()> {
        // Try multi-lowerdir mount first (efficient)
        let mount_result = try_mount_overlay_multi_lower(
            lowerdirs,
            &self.upper_path,
            &self.work_path,
            &self.merged_path,
        );

        if let Err(multi_err) = mount_result {
            if lowerdirs.len() > 1 {
                // Multi-lowerdir failed, try sequential approach
                warn!(
                    layer_count = lowerdirs.len(),
                    error = %multi_err,
                    "multi-lowerdir mount failed, trying sequential overlay construction"
                );

                mount_overlay_sequential(
                    lowerdirs,
                    &self.upper_path,
                    &self.work_path,
                    &self.merged_path,
                    &self.overlay_root,
                )?;
            } else {
                // Single layer, can't use sequential approach
                return Err(multi_err);
            }
        }

        Ok(())
    }

    /// Verify that the mount succeeded by checking merged directory contents.
    fn verify_mount(&self) -> usize {
        let entry_count = std::fs::read_dir(&self.merged_path)
            .map(|entries| entries.count())
            .unwrap_or(0);

        if entry_count == 0 {
            warn!(
                workload_id = %self.workload_id,
                merged_path = %self.merged_path.display(),
                "overlay mount returned success but merged directory is empty"
            );
            // Try to get more info about the mount state
            if let Ok(mounts) = std::fs::read_to_string("/proc/mounts") {
                let merged_str = self.merged_path.to_string_lossy();
                let is_mounted = mounts.lines().any(|line| line.contains(&*merged_str));
                warn!(is_mounted = is_mounted, "mount point status");
            }
        }

        entry_count
    }

    /// Create OCI bundle directory structure.
    fn create_bundle(&self) -> Result<()> {
        let bundle_path = self.overlay_root.join("bundle");
        std::fs::create_dir_all(&bundle_path)?;

        // Create symlink: bundle/rootfs -> ../merged
        let rootfs_link = bundle_path.join("rootfs");
        if !rootfs_link.exists() {
            std::os::unix::fs::symlink("../merged", &rootfs_link).map_err(|e| {
                StorageError::new(format!("failed to create rootfs symlink: {}", e))
            })?;
        }

        debug!(bundle = %bundle_path.display(), "OCI bundle directory created");
        Ok(())
    }

    /// Convert to OverlayInfo result.
    fn into_overlay_info(self) -> OverlayInfo {
        OverlayInfo {
            rootfs_path: self.merged_path.display().to_string(),
            upper_path: self.upper_path.display().to_string(),
            work_path: self.work_path.display().to_string(),
        }
    }

    /// Execute the full overlay setup pipeline with the given lower directories.
    fn execute(self, lowerdirs: Vec<String>) -> Result<OverlayInfo> {
        self.prepare_directories()?;
        self.setup_upper_layer()?;
        self.verify_layers(&lowerdirs)?;
        self.mount(&lowerdirs)?;

        let entry_count = self.verify_mount();
        info!(workload_id = %self.workload_id, entry_count = entry_count, "overlay mounted");

        self.create_bundle()?;
        Ok(self.into_overlay_info())
    }

    /// Reuse an existing persistent overlay or create a new one.
    ///
    /// If the overlay is already mounted AND healthy, returns it immediately.
    /// A mounted-but-stale overlay (a fork clone's RAM image carries the
    /// golden's overlay mount, whose virtiofs lowerdirs died with the pre-fork
    /// virtiofsd session — every fresh lookup through it is ESTALE) is torn
    /// down and remounted from its intact upper layer, so the clone keeps the
    /// golden's exec-written state instead of erroring on every exec.
    /// If the overlay directory exists but is not mounted (e.g. after VM restart),
    /// remounts it preserving the upper layer (which contains previous changes).
    /// If the overlay does not exist at all, creates it fresh.
    fn execute_or_remount(self, lowerdirs: Vec<String>) -> Result<OverlayInfo> {
        // Already mounted — reuse it only if it actually answers lookups.
        if self.merged_path.exists() && is_mountpoint(&self.merged_path) {
            if mounted_overlay_is_healthy(&self.merged_path) {
                info!(workload_id = %self.workload_id, "reusing existing persistent overlay");
                self.create_bundle()?;
                return Ok(self.into_overlay_info());
            }
            // Stale restored mount (fork clone). The restored keep-alive
            // container (if any) still runs from it — kill it so the next
            // exec establishes a fresh one on the healed overlay, then detach
            // the dead mount and fall through to the remount path below,
            // which reuses the (CoW-inherited) upper layer.
            warn!(
                workload_id = %self.workload_id,
                "persistent overlay mount is stale (restored fork state); remounting from its upper layer"
            );
            let id_path = paths::main_container_id_path(&self.workload_id);
            if let Ok(cid) = std::fs::read_to_string(&id_path) {
                let cid = cid.trim();
                if !cid.is_empty() {
                    let _ = CrunCommand::delete(cid, true).output();
                }
            }
            let _ = std::fs::remove_file(&id_path);
            detach_mount(&self.merged_path);
        }

        // Upper layer exists from a previous session — remount preserving it
        if self.upper_path.exists() {
            info!(workload_id = %self.workload_id, "remounting persistent overlay with existing upper layer");

            // overlayfs requires an empty work directory at mount time
            if self.work_path.exists() {
                let _ = std::fs::remove_dir_all(&self.work_path);
            }
            std::fs::create_dir_all(&self.work_path)?;
            std::fs::create_dir_all(&self.merged_path)?;

            self.verify_layers(&lowerdirs)?;
            self.mount(&lowerdirs)?;

            let entry_count = self.verify_mount();
            info!(workload_id = %self.workload_id, entry_count = entry_count, "persistent overlay remounted");

            self.create_bundle()?;
            return Ok(self.into_overlay_info());
        }

        // First time — full setup
        info!(workload_id = %self.workload_id, "creating new persistent overlay");
        self.execute(lowerdirs)
    }
}

fn overlay_resolv_conf_contents() -> String {
    if std::env::var(guest_env::DNS_FILTER).as_deref() == Ok("1") {
        return "nameserver 127.0.0.1\n".to_string();
    }

    // A nameserver supplied by the host (SMOLVM_NETWORK_DNS) wins for either
    // backend: under virtio-net it's the gateway address, and under TSI it's a
    // custom resolver (--dns) the guest queries directly. Only fall back to
    // public resolvers when the host didn't specify one.
    if let Ok(dns_server) = std::env::var(guest_env::DNS) {
        if !dns_server.is_empty() {
            return format!("nameserver {}\n", dns_server);
        }
    }

    "nameserver 8.8.8.8\nnameserver 1.1.1.1\n".to_string()
}

/// Prepare an overlay filesystem for a workload.
///
/// Reuses an existing overlay if already mounted, remounts if the upper
/// directory exists (preserving state from previous sessions), or creates
/// a fresh overlay. This idempotent behavior is critical for `machine cp`
/// which may call this before or after `machine exec`.
pub fn prepare_overlay(image: &str, workload_id: &str) -> Result<OverlayInfo> {
    // Check if we have packed layers available
    if let Some(packed_dir) = get_packed_layers_dir() {
        info!(image = %image, packed_dir = %packed_dir.display(), "using packed layers");
        // A local image archive is flattened into a rootfs (a single packed
        // layer) first; an ordinary packed-layers dir is used as-is.
        let flattened = ensure_archive_flattened(packed_dir)?;
        let effective = flattened.as_deref().unwrap_or(packed_dir);
        return prepare_overlay_from_packed(image, workload_id, effective);
    }

    // Ensure image exists
    let info = query_image(image)?
        .ok_or_else(|| StorageError::new(format!("image not found: {}", image)))?;

    // Build lowerdir from layers (reversed for overlay order - top layer first)
    let root = Path::new(STORAGE_ROOT);
    let lowerdirs: Vec<String> = info
        .layers
        .iter()
        .rev()
        .map(|digest| {
            let id = digest.strip_prefix("sha256:").unwrap_or(digest);
            root.join(LAYERS_DIR).join(id).display().to_string()
        })
        .collect();

    OverlaySetup::new(workload_id)?.execute_or_remount(lowerdirs)
}

/// Prepare an overlay filesystem using pre-packed layers.
///
/// Packed layers are stored as directories named by short digest (first 12 chars)
/// in the packed_dir. This function builds the overlay using these layers.
fn prepare_overlay_from_packed(
    image: &str,
    workload_id: &str,
    packed_dir: &Path,
) -> Result<OverlayInfo> {
    // An unpacked-image directory IS the rootfs — one lowerdir, not its subdirs
    // treated as separate layers.
    if is_rootfs_dir(packed_dir) {
        return OverlaySetup::new(workload_id)?
            .execute_or_remount(vec![packed_dir.display().to_string()]);
    }

    // Packed layers are named by short digest (first 12 chars of sha256).
    // Order is taken from the layer-order index (manifest order, bottom→top),
    // falling back to a name sort — see `ordered_packed_layer_names`.
    let layer_names = ordered_packed_layer_names(packed_dir)?;

    if layer_names.is_empty() {
        return Err(StorageError::new(format!(
            "no layer directories found in {}",
            packed_dir.display()
        )));
    }

    info!(
        image = %image,
        layer_count = layer_names.len(),
        layers = ?layer_names,
        "found packed layers"
    );

    // Build lowerdir from layers (reversed so the top-most layer is leftmost,
    // as overlayfs gives leftmost lowerdir the highest priority).
    let lowerdirs: Vec<String> = layer_names
        .iter()
        .rev()
        .map(|name| packed_dir.join(name).display().to_string())
        .collect();

    // Use shared overlay setup logic — execute_or_remount preserves the
    // upper layer from a previous session (e.g., packages installed via exec)
    // instead of recreating the overlay from scratch.
    OverlaySetup::new(workload_id)?.execute_or_remount(lowerdirs)
}

/// Build lowerdir list from a pulled OCI image's layers.
fn get_image_lowerdirs(image: &str) -> Result<Vec<String>> {
    let info = query_image(image)?
        .ok_or_else(|| StorageError::new(format!("image not found: {}", image)))?;

    let root = Path::new(STORAGE_ROOT);
    Ok(info
        .layers
        .iter()
        .rev()
        .map(|digest| {
            let id = digest.strip_prefix("sha256:").unwrap_or(digest);
            root.join(LAYERS_DIR).join(id).display().to_string()
        })
        .collect())
}

/// Whether `dir` is itself a root filesystem (an unpacked-image directory,
/// `--image ./rootfs/`) rather than a set of layer subdirs — detected by the
/// presence of standard top-level rootfs directories. A `.smolmachine`'s
/// packed-layers dir holds per-layer subdirs, not these, so it reads as false.
fn is_rootfs_dir(dir: &Path) -> bool {
    ["bin", "usr", "etc", "sbin"]
        .iter()
        .any(|d| dir.join(d).is_dir())
}

/// Build lowerdir list from pre-packed layer directories.
fn get_packed_lowerdirs(packed_dir: &Path) -> Result<Vec<String>> {
    // An unpacked-image directory IS the rootfs — one lowerdir, not its subdirs
    // treated as separate layers.
    if is_rootfs_dir(packed_dir) {
        return Ok(vec![packed_dir.display().to_string()]);
    }

    // Order from the layer-order index (manifest order, bottom→top), falling
    // back to a name sort — see `ordered_packed_layer_names`.
    let layer_names = ordered_packed_layer_names(packed_dir)?;

    if layer_names.is_empty() {
        return Err(StorageError::new(format!(
            "no layer directories found in {}",
            packed_dir.display()
        )));
    }

    // Reversed so the top-most layer is leftmost (overlayfs priority order).
    Ok(layer_names
        .iter()
        .rev()
        .map(|name| packed_dir.join(name).display().to_string())
        .collect())
}

/// Clean up an overlay filesystem.
/// Log the error inside this function to skip the repetitive Err matching when unnecessary.
pub fn cleanup_overlay(workload_id: &str) -> Result<()> {
    let overlay_root = overlay_root_for_workload(workload_id)?;
    let merged_path = overlay_root.join("merged");

    // Unmount nested bind mounts inside the overlay rootfs first. Volume mounts
    // like /workspace are bind-mounted under merged/, and they keep the overlay
    // rootfs busy if we try to unmount merged directly.
    if let Ok(mounts) = std::fs::read_to_string("/proc/mounts") {
        let merged_prefix = format!("{}/", merged_path.display());
        let mut nested_mounts: Vec<PathBuf> = mounts
            .lines()
            .filter_map(|line| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 2 {
                    return None;
                }

                let mount_point = PathBuf::from(parts[1]);
                let mount_point_str = mount_point.to_string_lossy();
                if mount_point_str.starts_with(&merged_prefix) {
                    Some(mount_point)
                } else {
                    None
                }
            })
            .collect();

        nested_mounts.sort_by_key(|path| std::cmp::Reverse(path.components().count()));

        for mount_point in nested_mounts {
            if let Err(e) = Command::new("umount").arg(&mount_point).status() {
                debug!(
                    workload_id = %workload_id,
                    path = %mount_point.display(),
                    error = %e,
                    "failed to unmount nested overlay mount"
                );
            }
        }
    }

    // Unmount main merged path if mounted
    if merged_path.exists() {
        if let Err(e) = Command::new("umount").arg(&merged_path).status() {
            debug!(
                workload_id = %workload_id,
                path = %merged_path.display(),
                error = %e,
                "failed to unmount overlay (may not have been mounted)"
            );
        }
    }

    // Remove overlay directories (includes merged_layers, upper, work, etc.)
    if overlay_root.exists() {
        if let Err(cleanup_err) = std::fs::remove_dir_all(&overlay_root) {
            warn!(
                workload_id = %workload_id,
                error = %cleanup_err,
                "failed to clean up overlay."
            );
            return Err(cleanup_err.into());
        }
    }

    info!(workload_id = %workload_id, "overlay cleaned up");
    Ok(())
}

/// Result of running a command.
///
/// Uses `Vec<u8>` so binary output is preserved end-to-end.
pub struct RunResult {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Prepared rootfs info for a single ephemeral run.
pub struct PreparedOverlayRootfs {
    pub workload_id: String,
    pub rootfs_path: String,
}

fn prepare_rootfs_for_ephemeral_run(image: &str) -> Result<PreparedOverlayRootfs> {
    let workload_id = format!(
        "run-{}-{}",
        sanitize_image_name(image),
        generate_container_id()
    );
    let overlay = prepare_overlay(image, &workload_id)?;
    debug!(
        workload_id = %workload_id,
        rootfs = %overlay.rootfs_path,
        "prepared ephemeral overlay for command execution"
    );
    Ok(PreparedOverlayRootfs {
        workload_id,
        rootfs_path: overlay.rootfs_path,
    })
}

/// Run a command in an image's overlay rootfs using crun OCI runtime.
///
/// When `persistent_overlay_id` is `Some`, the overlay persists across runs
/// (filesystem changes accumulate). When `None`, an ephemeral overlay is
/// created and destroyed after the run.
pub fn run_command(
    image: &str,
    command: &[String],
    env: &[(String, String)],
    workdir: Option<&str>,
    user: Option<&str>,
    mounts: &[(String, String, bool)],
    timeout_ms: Option<u64>,
    persistent_overlay_id: Option<&str>,
    stdin_data: Option<&str>,
    client_fd: Option<std::os::unix::io::RawFd>,
    unprivileged: bool,
) -> Result<RunResult> {
    // Validate inputs
    crate::oci::validate_image_reference(image).map_err(StorageError::new)?;
    crate::oci::validate_env_vars(env).map_err(StorageError::new)?;

    let prepared = match persistent_overlay_id {
        Some(id) => prepare_for_run_persistent(image, id)?,
        None => prepare_rootfs_for_ephemeral_run(image)?,
    };
    debug!(rootfs = %prepared.rootfs_path, persistent = persistent_overlay_id.is_some(), "using overlay for command execution");

    // Gather all steps to run a command in a single anon function
    let result = (|| {
        // Setup volume mounts (mount virtiofs to staging area)
        let mounted_paths = setup_volume_mounts(&prepared.rootfs_path, mounts)?;

        // Get bundle path
        let overlay_root = Path::new(STORAGE_ROOT)
            .join(OVERLAYS_DIR)
            .join(&prepared.workload_id);
        let bundle_path = overlay_root.join("bundle");

        // Create OCI spec
        let workdir_str = workdir.unwrap_or("/");
        let identity = crate::oci::resolve_process_identity(Path::new(&prepared.rootfs_path), user)
            .map_err(StorageError::new)?;
        let mut spec = OciSpec::new(command, env, workdir_str, false, &identity, unprivileged);
        spec.add_gpu_devices_if_available();

        // Add virtiofs bind mounts to OCI spec
        for (tag, container_path, read_only) in mounts {
            let virtiofs_mount = Path::new(paths::VIRTIOFS_MOUNT_ROOT).join(tag);
            spec.add_bind_mount(
                &virtiofs_mount.to_string_lossy(),
                container_path,
                *read_only,
            );
        }

        add_workspace_fallback(&mut spec, mounts);
        add_storage_fallback(&mut spec, mounts, unprivileged);

        // Forward SSH agent into the container if enabled at boot.
        crate::ssh_agent::inject_into_container(&mut spec);
        crate::cuda::inject_into_container(&mut spec, Path::new(&prepared.rootfs_path));

        // Write config.json to bundle
        spec.write_to(&bundle_path)
            .map_err(|e| StorageError::new(format!("failed to write OCI spec: {}", e)))?;

        // If a main workload container is running for this overlay, join it
        // via crun exec instead of creating a fresh isolated container.
        if let Some(cid) = crate::resolve_main_container(persistent_overlay_id) {
            let result = run_exec_in_container(&cid, command, env, workdir, timeout_ms, client_fd);
            let _ = mounted_paths;
            return result;
        }

        // Generate unique container ID for this execution
        let container_id = generate_container_id();

        // Run with crun
        let result = run_with_crun(
            &bundle_path,
            &container_id,
            timeout_ms,
            stdin_data,
            client_fd,
        );

        // Note: virtiofs mounts are left in place for reuse
        // They will be cleaned up when the overlay is cleaned up or the VM shuts down
        let _ = mounted_paths; // Suppress unused warning

        result
    })();

    // Only clean up ephemeral overlays; persistent ones survive across runs
    if persistent_overlay_id.is_none() {
        let _ = cleanup_overlay(&prepared.workload_id);
    }
    result
}

/// Spawn a command in an image's overlay rootfs and return the crun PID.
///
/// Unlike `run_command`, this does not wait for the container to exit. The
/// container runs detached under crun with stdout/stderr redirected to
/// /dev/null; the returned PID is the crun process, which stays alive as
/// long as the container init runs.
///
/// Requires a persistent overlay ID — ephemeral overlays would leak their
/// upper/work/merged directories because nothing is waiting to clean them
/// up after the container exits.
pub fn spawn_in_overlay(
    image: &str,
    command: &[String],
    env: &[(String, String)],
    workdir: Option<&str>,
    user: Option<&str>,
    mounts: &[(String, String, bool)],
    persistent_overlay_id: &str,
    unprivileged: bool,
) -> Result<u32> {
    crate::oci::validate_image_reference(image).map_err(StorageError::new)?;
    crate::oci::validate_env_vars(env).map_err(StorageError::new)?;

    let prepared = prepare_for_run_persistent(image, persistent_overlay_id)?;
    debug!(rootfs = %prepared.rootfs_path, "using persistent overlay for background command");

    let mounted_paths = setup_volume_mounts(&prepared.rootfs_path, mounts)?;

    let overlay_root = Path::new(STORAGE_ROOT)
        .join(OVERLAYS_DIR)
        .join(&prepared.workload_id);
    let bundle_path = overlay_root.join("bundle");

    let workdir_str = workdir.unwrap_or("/");
    let identity = crate::oci::resolve_process_identity(Path::new(&prepared.rootfs_path), user)
        .map_err(StorageError::new)?;
    let mut spec = OciSpec::new(command, env, workdir_str, false, &identity, unprivileged);

    for (tag, container_path, read_only) in mounts {
        let virtiofs_mount = Path::new(paths::VIRTIOFS_MOUNT_ROOT).join(tag);
        spec.add_bind_mount(
            &virtiofs_mount.to_string_lossy(),
            container_path,
            *read_only,
        );
    }

    add_workspace_fallback(&mut spec, mounts);
    add_storage_fallback(&mut spec, mounts, unprivileged);

    crate::ssh_agent::inject_into_container(&mut spec);
    crate::cuda::inject_into_container(&mut spec, Path::new(&prepared.rootfs_path));
    spec.add_gpu_devices_if_available();

    spec.write_to(&bundle_path)
        .map_err(|e| StorageError::new(format!("failed to write OCI spec: {}", e)))?;

    let container_id = generate_container_id();

    let child = CrunCommand::run(&bundle_path, &container_id)
        .stdin_null()
        .discard_output()
        .spawn()
        .map_err(|e| {
            StorageError::new(format!(
                "failed to spawn crun: {}. Is crun installed at {}?",
                e,
                paths::CRUN_PATH
            ))
        })?;

    let pid = child.id();
    // Don't wait on the child; it reaps itself when the container exits.
    // reap_background_children() in the agent's accept loop collects the
    // eventual zombie.
    std::mem::forget(child);

    let _ = mounted_paths; // suppress unused warning; mounts persist with the overlay
    info!(container_id = %container_id, pid = pid, "background container started");
    Ok(pid)
}

/// Prepare for running a command - returns the rootfs path.
/// This is used by interactive mode which spawns the command separately.
pub fn prepare_for_run(image: &str) -> Result<PreparedOverlayRootfs> {
    prepare_rootfs_for_ephemeral_run(image)
}

/// Prepare a persistent overlay that survives across exec sessions.
///
/// Uses a deterministic workload ID derived from `overlay_id` (typically the
/// machine name). If the overlay already exists and is mounted, reuses it.
/// If it exists but is unmounted (e.g. after VM restart), remounts preserving
/// the upper layer that contains previous changes.
pub fn prepare_for_run_persistent(image: &str, overlay_id: &str) -> Result<PreparedOverlayRootfs> {
    validate_storage_id(overlay_id, "persistent overlay id")?;
    let workload_id = format!("persistent-{}", overlay_id);

    // Resolve image layers (same logic as prepare_overlay). A local image
    // archive is flattened into a rootfs first; a packed-layers dir is used
    // as-is.
    let lowerdirs = if let Some(packed_dir) = get_packed_layers_dir() {
        let flattened = ensure_archive_flattened(packed_dir)?;
        let effective = flattened.as_deref().unwrap_or(packed_dir);
        get_packed_lowerdirs(effective)?
    } else {
        get_image_lowerdirs(image)?
    };

    let setup = OverlaySetup::new(&workload_id)?;
    let overlay = setup.execute_or_remount(lowerdirs)?;

    debug!(
        workload_id = %workload_id,
        rootfs = %overlay.rootfs_path,
        "prepared persistent overlay for command execution"
    );
    Ok(PreparedOverlayRootfs {
        workload_id,
        rootfs_path: overlay.rootfs_path,
    })
}

/// Setup volume mounts for a rootfs (public wrapper).
/// Request mounts merged with the BOOT env mounts (SMOLVM_MOUNT_*): boot-time
/// binds land in a rootfs the workload's overlay later mounts OVER, so
/// launcher-injected mounts (e.g. the CUDA ring mount) must ride every
/// container's own mount list. Request entries win on target collision.
pub fn merged_with_boot_mounts(mounts: &[(String, String, bool)]) -> Vec<(String, String, bool)> {
    let mut v: Vec<(String, String, bool)> = mounts.to_vec();
    for bm in init_volume_mounts() {
        if !v.iter().any(|(_, t, _)| t == &bm.1) {
            v.push(bm.clone());
        }
    }
    v
}

pub fn setup_mounts(rootfs: &str, mounts: &[(String, String, bool)]) -> Result<()> {
    let _mounted_paths = setup_volume_mounts(rootfs, mounts)?;
    Ok(())
}

/// Setup volume mounts by mounting virtiofs and bind-mounting into the rootfs.
#[cfg(target_os = "linux")]
fn setup_volume_mounts(rootfs: &str, mounts: &[(String, String, bool)]) -> Result<Vec<PathBuf>> {
    let mut mounted_paths = Vec::new();
    let rootfs_path = Path::new(rootfs);

    for (tag, container_path, read_only) in mounts {
        validate_storage_id(tag, "mount tag")?;
        debug!(tag = %tag, container_path = %container_path, read_only = %read_only, "setting up volume mount");

        // First, mount the virtiofs device at a staging location
        let virtiofs_mount = Path::new(paths::VIRTIOFS_MOUNT_ROOT).join(tag);
        std::fs::create_dir_all(&virtiofs_mount)?;

        // Check if already mounted
        if !is_mountpoint(&virtiofs_mount) {
            info!(tag = %tag, mount_point = %virtiofs_mount.display(), "mounting virtiofs");

            // Mount virtiofs using direct syscall (avoids ~3-5ms fork+exec overhead).
            // Use sync option to ensure writes are persisted immediately.
            let src = std::ffi::CString::new(tag.as_str()).map_err(|e| StorageError::Internal {
                message: format!("invalid tag: {}", e),
            })?;
            let dst =
                std::ffi::CString::new(virtiofs_mount.to_string_lossy().as_ref()).map_err(|e| {
                    StorageError::Internal {
                        message: format!("invalid mount point: {}", e),
                    }
                })?;
            let fstype = std::ffi::CString::new("virtiofs").unwrap();
            // DAX first: when the device has a DAX window (host passed a
            // nonzero shm_size — SMOLVM_MOUNT_DAX=1), a dax mount maps host
            // page-cache pages directly into the guest, making guest/host
            // MAP_SHARED mmaps of the same file coherent shared memory (the
            // clone-ring transport). The kernel silently downgrades dax on a
            // window-less device; the explicit fallback covers kernels that
            // reject the option outright.
            let opts_dax = std::ffi::CString::new("dax,sync").unwrap();
            let opts_plain = std::ffi::CString::new("sync").unwrap();
            // SAFETY: mount virtiofs with valid CString arguments
            let mut rc = unsafe {
                libc::mount(
                    src.as_ptr(),
                    dst.as_ptr(),
                    fstype.as_ptr(),
                    0,
                    opts_dax.as_ptr() as *const libc::c_void,
                )
            };
            if rc != 0 {
                // SAFETY: as above, plain options.
                rc = unsafe {
                    libc::mount(
                        src.as_ptr(),
                        dst.as_ptr(),
                        fstype.as_ptr(),
                        0,
                        opts_plain.as_ptr() as *const libc::c_void,
                    )
                };
            }
            if rc != 0 {
                let err = std::io::Error::last_os_error();
                warn!(error = %err, tag = %tag, "failed to mount virtiofs device");
                continue;
            }
        }

        // Now bind-mount into the container rootfs
        let target_path = ensure_mount_target_under_root(rootfs_path, container_path)?;

        // Check if already bind-mounted
        if !is_mountpoint(&target_path) {
            info!(
                source = %virtiofs_mount.display(),
                target = %target_path.display(),
                read_only = %read_only,
                "bind-mounting into container"
            );

            // Bind mount using direct syscall
            let bind_src = std::ffi::CString::new(virtiofs_mount.to_string_lossy().as_ref())
                .map_err(|e| StorageError::Internal {
                    message: format!("invalid source: {}", e),
                })?;
            let bind_dst =
                std::ffi::CString::new(target_path.to_string_lossy().as_ref()).map_err(|e| {
                    StorageError::Internal {
                        message: format!("invalid target: {}", e),
                    }
                })?;
            // SAFETY: bind mount with MS_BIND flag
            let rc = unsafe {
                libc::mount(
                    bind_src.as_ptr(),
                    bind_dst.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND,
                    std::ptr::null(),
                )
            };
            if rc != 0 {
                let err = std::io::Error::last_os_error();
                warn!(error = %err, target = %target_path.display(), "failed to bind-mount");
                continue;
            }

            // Remount read-only if requested
            if *read_only {
                // SAFETY: remount with MS_BIND|MS_RDONLY|MS_REMOUNT
                unsafe {
                    libc::mount(
                        std::ptr::null(),
                        bind_dst.as_ptr(),
                        std::ptr::null(),
                        libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY,
                        std::ptr::null(),
                    );
                }
            }
        }

        mounted_paths.push(target_path);
    }

    Ok(mounted_paths)
}

/// Stub for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
fn setup_volume_mounts(_rootfs: &str, _mounts: &[(String, String, bool)]) -> Result<Vec<PathBuf>> {
    Ok(Vec::new())
}

/// Check if a path is a mountpoint (delegates to paths::is_mount_point).
fn is_mountpoint(path: &Path) -> bool {
    paths::is_mount_point(path)
}

/// Whether a persistent overlay's mounted state (if any) answers lookups.
/// True when the overlay isn't mounted at all — "nothing stale to heal".
/// Used by `resolve_main_container` to refuse handing out a restored
/// keep-alive container whose rootfs mount is dead.
pub fn persistent_overlay_mount_is_healthy(workload_id: &str) -> bool {
    let Ok(root) = overlay_root_for_workload(workload_id) else {
        return true;
    };
    let merged = root.join("merged");
    !(merged.exists() && is_mountpoint(&merged)) || mounted_overlay_is_healthy(&merged)
}

/// Whether an already-mounted persistent overlay actually answers lookups.
///
/// A fork clone's restored RAM image carries the golden's overlay mount, but
/// the mount's virtiofs lowerdirs reference the pre-fork virtiofsd session —
/// in the clone every *fresh* lookup through it fails with ESTALE, while
/// page-cached entries may still read fine. So the probe is a lookup that
/// cannot be served from cache: a name never looked up before. A healthy
/// mount answers NotFound; a stale one surfaces the lowerdir error.
fn mounted_overlay_is_healthy(merged: &Path) -> bool {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let probe = merged.join(format!(".smolvm-stale-probe-{nonce}"));
    match std::fs::metadata(&probe) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
        Err(e) => {
            warn!(path = %merged.display(), error = %e, "mounted overlay failed the lookup probe");
            false
        }
        Ok(_) => true,
    }
}

/// Lazily detach a dead mount (`umount2(MNT_DETACH)`): the tree is unhooked
/// immediately while any restored process still holding it keeps its
/// references until it exits. Best-effort — a failure here just means the
/// subsequent fresh mount shadows the stale one.
fn detach_mount(path: &Path) {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::ffi::OsStrExt;
        if let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) {
            let rc = unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) };
            if rc != 0 {
                warn!(
                    path = %path.display(),
                    errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
                    "could not detach stale overlay mount"
                );
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
    }
}

/// Run a command using crun OCI runtime (one-shot execution).
///
/// This uses `crun run` which creates, starts, waits, and deletes the container
/// in a single operation. Stdout and stderr are captured.
/// Join a running container via `crun exec` (non-interactive).
fn run_exec_in_container(
    container_id: &str,
    command: &[String],
    env: &[(String, String)],
    workdir: Option<&str>,
    timeout_ms: Option<u64>,
    client_fd: Option<std::os::unix::io::RawFd>,
) -> Result<RunResult> {
    info!(container_id = %container_id, command = ?command, "joining container via crun exec");

    let mut child = CrunCommand::exec(container_id, env, command, workdir, false)
        .stdin_null()
        .capture_output()
        .spawn()
        .map_err(|e| StorageError::new(format!("crun exec failed: {}", e)))?;

    // On timeout/disconnect, kill only the exec'd process — NOT the main
    // container. The main container hosts the shared namespace for all execs;
    // a timed-out `exec -- sleep 10` must not destroy the workload.
    let exec_pid = child.id();
    let result = crate::process::wait_with_timeout_cleanup_and_liveness(
        &mut child,
        timeout_ms,
        client_fd,
        || unsafe {
            libc::kill(exec_pid as libc::pid_t, libc::SIGKILL);
        },
    )?;

    match result {
        WaitResult::Completed { exit_code, output } => Ok(RunResult {
            exit_code,
            stdout: output.stdout,
            stderr: output.stderr,
        }),
        WaitResult::TimedOut { output, timeout_ms } => {
            let mut stderr = output.stderr;
            stderr.extend_from_slice(
                format!("\ncommand timed out after {}ms", timeout_ms).as_bytes(),
            );
            Ok(RunResult {
                exit_code: 124,
                stdout: output.stdout,
                stderr,
            })
        }
        WaitResult::ClientDisconnected { output } => {
            let mut stderr = output.stderr;
            stderr.extend_from_slice(b"\nclient disconnected");
            Ok(RunResult {
                exit_code: 137,
                stdout: output.stdout,
                stderr,
            })
        }
    }
}

fn run_with_crun(
    bundle_dir: &Path,
    container_id: &str,
    timeout_ms: Option<u64>,
    stdin_data: Option<&str>,
    client_fd: Option<std::os::unix::io::RawFd>,
) -> Result<RunResult> {
    info!(
        container_id = %container_id,
        bundle = %bundle_dir.display(),
        timeout_ms = ?timeout_ms,
        "running container with crun"
    );

    // Spawn the container using CrunCommand.
    // stdin_null() is critical when no input is supplied: without it, crun
    // inherits the agent's vsock stdin, and /bin/sh reads protocol bytes
    // instead of user input, hanging. With input, pipe it in and close the
    // pipe so the command sees EOF (same contract as the bare-VM exec path).
    let builder = CrunCommand::run(bundle_dir, container_id);
    let builder = if stdin_data.is_some() {
        builder.stdin_piped()
    } else {
        builder.stdin_null()
    };
    let mut child = builder.capture_output().spawn().map_err(|e| {
        StorageError::new(format!(
            "failed to spawn crun: {}. Is crun installed at {}?",
            e,
            paths::CRUN_PATH
        ))
    })?;

    // Write stdin on a separate thread so the wait/timeout loop stays live
    // even if the child never reads and the pipe buffer fills. Dropping the
    // handle closes the pipe → EOF.
    let _stdin_writer = stdin_data.and_then(|data| {
        child.stdin.take().map(|mut child_stdin| {
            let data = data.to_owned();
            std::thread::Builder::new()
                .name("run-stdin".into())
                .spawn(move || {
                    use std::io::Write;
                    let _ = child_stdin.write_all(data.as_bytes());
                })
        })
    });

    // Capture container_id for the cleanup closure
    let cid = container_id.to_string();

    // Wait with timeout + client liveness, cleaning up container on timeout.
    // If the client disconnects mid-exec, we kill the container so the agent's
    // accept loop is free to serve the next request.
    let result = crate::process::wait_with_timeout_cleanup_and_liveness(
        &mut child,
        timeout_ms,
        client_fd,
        || {
            // Kill and delete the container on timeout
            let _ = CrunCommand::kill(&cid, "SIGKILL").status();
            let _ = CrunCommand::delete(&cid, true).status();
        },
    )?;

    // Convert WaitResult to RunResult
    match result {
        WaitResult::Completed { exit_code, output } => {
            info!(
                container_id = %container_id,
                exit_code = exit_code,
                stdout_len = output.stdout.len(),
                stderr_len = output.stderr.len(),
                "container finished"
            );
            Ok(RunResult {
                exit_code,
                stdout: output.stdout,
                stderr: output.stderr,
            })
        }
        WaitResult::TimedOut { output, timeout_ms } => {
            warn!(
                container_id = %container_id,
                timeout_ms = timeout_ms,
                "container timed out"
            );
            let mut stderr = output.stderr;
            stderr.extend_from_slice(
                format!("\ncontainer timed out after {}ms", timeout_ms).as_bytes(),
            );
            Ok(RunResult {
                exit_code: TIMEOUT_EXIT_CODE,
                stdout: output.stdout,
                stderr,
            })
        }
        WaitResult::ClientDisconnected { output } => {
            // Client gave up before the container finished. Also clean up the
            // crun container state so the next exec starts fresh.
            let _ = CrunCommand::kill(container_id, "SIGKILL").status();
            let _ = CrunCommand::delete(container_id, true).status();
            warn!(
                container_id = %container_id,
                "container killed — client disconnected"
            );
            let mut stderr = output.stderr;
            stderr.extend_from_slice(b"\ncontainer killed: client disconnected");
            Ok(RunResult {
                exit_code: 129, // SIGHUP convention for disconnect
                stdout: output.stdout,
                stderr,
            })
        }
    }
}

// ============================================================================
// Overlay mounting helper functions
// ============================================================================

/// Mount an overlay with multiple lower layers, appending each layer via the new
/// mount API (`fsopen`/`fsconfig`/`fsmount`/`move_mount`) instead of shelling out
/// to `mount(8)`.
///
/// Why not `mount -o lowerdir=…`: the `mount(8)` command rejects a `lowerdir=`
/// value longer than ~255 bytes, so any image with ≥4 layers (each OCI layer path
/// `/storage/layers/<64-hex>` is ~79 bytes) failed this fast path and fell back to
/// a slow physical layer-merge on *every* (re)mount. The kernel has no such limit
/// — verified on the guest kernel (6.12) that a raw `mount(2)` AND this `fsconfig`
/// path both mount a 599-byte / 8-layer overlay. Passing each layer as its own
/// `lowerdir+` also sidesteps the classic `mount(2)` PAGE_SIZE option ceiling.
fn try_mount_overlay_multi_lower(
    lowerdirs: &[String],
    upper_path: &Path,
    work_path: &Path,
    merged_path: &Path,
) -> Result<()> {
    info!(
        layer_count = lowerdirs.len(),
        merged_path = %merged_path.display(),
        "attempting multi-lowerdir overlay mount (fsconfig API)"
    );
    mount_overlay_fsconfig(lowerdirs, upper_path, work_path, merged_path)
}

/// Linux implementation of the overlay mount via the new mount API. Requires
/// `lowerdir+` support (Linux ≥ 6.7); returns `Err` on older kernels (or any other
/// failure) so the caller falls back to the physical merge.
#[cfg(target_os = "linux")]
fn mount_overlay_fsconfig(
    lowerdirs: &[String],
    upper_path: &Path,
    work_path: &Path,
    merged_path: &Path,
) -> Result<()> {
    use rustix::fd::AsFd;
    use rustix::mount::{
        fsconfig_create, fsconfig_set_string, fsmount, fsopen, move_mount, FsMountFlags,
        FsOpenFlags, MountAttrFlags, MoveMountFlags,
    };

    let upper = upper_path
        .to_str()
        .ok_or_else(|| StorageError::new("upperdir path is not valid UTF-8".to_string()))?;
    let work = work_path
        .to_str()
        .ok_or_else(|| StorageError::new("workdir path is not valid UTF-8".to_string()))?;

    let fs = fsopen("overlay", FsOpenFlags::FSOPEN_CLOEXEC)
        .map_err(|e| StorageError::new(format!("fsopen(overlay) failed: {e}")))?;

    // Append each lower layer individually — no single long option string, so
    // neither the `mount(8)` ~255-byte limit nor the `mount(2)` page limit applies.
    for lower in lowerdirs {
        fsconfig_set_string(fs.as_fd(), "lowerdir+", lower.as_str()).map_err(|e| {
            StorageError::new(format!(
                "fsconfig lowerdir+={lower} failed (kernel may lack lowerdir+ (<6.7)): {e}"
            ))
        })?;
    }
    fsconfig_set_string(fs.as_fd(), "upperdir", upper)
        .map_err(|e| StorageError::new(format!("fsconfig upperdir failed: {e}")))?;
    fsconfig_set_string(fs.as_fd(), "workdir", work)
        .map_err(|e| StorageError::new(format!("fsconfig workdir failed: {e}")))?;
    // Preserve prior semantics: index=off disables the inode-index feature.
    fsconfig_set_string(fs.as_fd(), "index", "off")
        .map_err(|e| StorageError::new(format!("fsconfig index=off failed: {e}")))?;

    fsconfig_create(fs.as_fd())
        .map_err(|e| StorageError::new(format!("fsconfig create (overlay) failed: {e}")))?;

    let mnt = fsmount(
        fs.as_fd(),
        FsMountFlags::FSMOUNT_CLOEXEC,
        MountAttrFlags::empty(),
    )
    .map_err(|e| StorageError::new(format!("fsmount(overlay) failed: {e}")))?;

    // Attach the freshly-created mount at merged_path (the mount fd itself is the
    // source, via MOVE_MOUNT_F_EMPTY_PATH).
    move_mount(
        mnt.as_fd(),
        "",
        rustix::fs::CWD,
        merged_path,
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
    )
    .map_err(|e| {
        StorageError::new(format!(
            "move_mount to {} failed: {e}",
            merged_path.display()
        ))
    })?;

    Ok(())
}

/// Non-Linux stub: overlayfs is Linux-only, so error and let callers fall back.
#[cfg(not(target_os = "linux"))]
fn mount_overlay_fsconfig(
    _lowerdirs: &[String],
    _upper_path: &Path,
    _work_path: &Path,
    _merged_path: &Path,
) -> Result<()> {
    Err(StorageError::new(
        "overlay mount is only supported on Linux".to_string(),
    ))
}

/// Mount overlay by merging layers into a single directory (most compatible).
///
/// This approach physically copies all layers into a single merged directory,
/// then creates a simple overlay on top of it. This works on all kernels with
/// basic overlay support, but uses more disk space and is slower for initial setup.
///
/// This is the fallback when multi-lowerdir overlay mounts fail.
fn mount_overlay_sequential(
    lowerdirs: &[String],
    upper_path: &Path,
    work_path: &Path,
    merged_path: &Path,
    overlay_root: &Path,
) -> Result<()> {
    info!(
        layer_count = lowerdirs.len(),
        "building overlay by merging layers"
    );

    // If only one layer, mount directly
    if lowerdirs.len() == 1 {
        let mount_opts = format!(
            "lowerdir={},upperdir={},workdir={},index=off",
            lowerdirs[0],
            upper_path.display(),
            work_path.display()
        );

        let output = Command::new("mount")
            .args(["-t", "overlay", "overlay", "-o", &mount_opts])
            .arg(merged_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(StorageError::new(format!(
                "overlay mount failed: {}",
                stderr
            )));
        }
        return Ok(());
    }

    // Create a directory to hold the physically merged layers
    let merged_layers_dir = overlay_root.join("merged_layers");
    std::fs::create_dir_all(&merged_layers_dir)?;

    // lowerdirs is in overlay order (topmost first)
    // We need to copy from bottom up so top layers overwrite bottom layers
    let layers: Vec<&String> = lowerdirs.iter().rev().collect();

    info!(
        layer_count = layers.len(),
        merged_dir = %merged_layers_dir.display(),
        "physically merging layers"
    );

    for (i, layer_path) in layers.iter().enumerate() {
        debug!(
            layer_index = i,
            layer_path = %layer_path,
            "copying layer to merged directory"
        );

        // Copy layer contents preserving all attributes.
        // cp -a preserves symlinks, permissions, etc.
        // Uses explicit args instead of shell to avoid injection risks.
        let layer_src = format!("{}/.", layer_path);
        let output = Command::new("cp")
            .arg("-a")
            .arg(&layer_src)
            .arg(merged_layers_dir.as_os_str())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;

        // Don't fail on cp errors - some layers might have special files
        // that can't be copied, but the overlay should still work
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.is_empty() {
                debug!(
                    layer_index = i,
                    stderr = %stderr,
                    "layer copy had warnings (non-fatal)"
                );
            }
        }
    }

    info!(
        merged_dir = %merged_layers_dir.display(),
        "layer merge complete, mounting overlay"
    );

    // Now mount a simple overlay with just the merged directory as lowerdir
    let mount_opts = format!(
        "lowerdir={},upperdir={},workdir={},index=off",
        merged_layers_dir.display(),
        upper_path.display(),
        work_path.display()
    );

    let output = Command::new("mount")
        .args(["-t", "overlay", "overlay", "-o", &mount_opts])
        .arg(merged_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(StorageError::new(format!(
            "overlay mount on merged layers failed: {}",
            stderr
        )));
    }

    info!(
        layer_count = lowerdirs.len(),
        "overlay construction complete (merged layers approach)"
    );

    Ok(())
}

// ============================================================================
// Helper functions
// ============================================================================

/// Extract the registry hostname from an image reference.
/// e.g., "alpine:latest" -> "https://index.docker.io/v1/"
/// e.g., "ghcr.io/owner/repo" -> "ghcr.io"
fn extract_registry_from_image(image: &str) -> String {
    if let Some(slash_pos) = image.find('/') {
        let potential_registry = &image[..slash_pos];
        if potential_registry.contains('.') || potential_registry.contains(':') {
            return docker_config_registry_key(potential_registry).to_string();
        }
    }
    // Docker Hub uses this URL in config.json
    DOCKER_HUB_AUTH_CONFIG_KEY.to_string()
}

fn docker_config_registry_key(registry: &str) -> &str {
    if DOCKER_HUB_REGISTRY_ALIASES.contains(&registry) {
        DOCKER_HUB_AUTH_CONFIG_KEY
    } else {
        registry
    }
}

/// Simple base64 encoding for auth string.
fn base64_encode(input: &str) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut result = String::new();

    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;

        result.push(ALPHABET[b0 >> 2] as char);
        result.push(ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);

        if chunk.len() > 1 {
            result.push(ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(ALPHABET[b2 & 0x3f] as char);
        } else {
            result.push('=');
        }
    }

    result
}

/// Set up Docker auth configuration for crane commands.
///
/// Creates a temporary directory with a Docker config.json file containing
/// registry credentials. The returned TempDir must be kept alive for the
/// duration of the command execution.
///
/// Returns `Ok(None)` if no auth is provided.
fn setup_docker_auth(
    image: &str,
    auth: Option<&RegistryAuth>,
) -> Result<Option<tempfile::TempDir>> {
    let Some(a) = auth else {
        return Ok(None);
    };

    let registry = extract_registry_from_image(image);

    // The guest root filesystem (and thus the default temp dir, /tmp) is
    // read-only, so create the auth config under the writable storage disk.
    let temp_dir = tempfile::Builder::new()
        .prefix("smolauth")
        .tempdir_in(STORAGE_ROOT)
        .map_err(|e| {
            StorageError::new(format!("failed to create temp directory for auth: {}", e))
        })?;

    let auth_b64 = base64_encode(&format!("{}:{}", a.username, a.password));
    let config_json = format!(
        r#"{{"auths":{{"{}":{{"auth":"{}"}}}}}}"#,
        registry, auth_b64
    );

    let config_path = temp_dir.path().join("config.json");
    std::fs::write(&config_path, &config_json)
        .map_err(|e| StorageError::new(format!("failed to write docker auth config: {}", e)))?;

    debug!(
        registry = %registry,
        username = %a.username,
        "using registry credentials via docker config"
    );

    Ok(Some(temp_dir))
}

/// Set HTTP_PROXY / HTTPS_PROXY / NO_PROXY on a crane subprocess so the
/// in-VM registry client can reach the registry through a corporate proxy.
fn apply_proxy_env(cmd: &mut Command, proxy: Option<&str>, no_proxy: Option<&str>) {
    if let Some(p) = proxy {
        cmd.env("HTTP_PROXY", p);
        cmd.env("HTTPS_PROXY", p);
    }
    if let Some(np) = no_proxy {
        cmd.env("NO_PROXY", np);
    }
}

/// Run a crane command with the given operation.
///
/// If auth is provided, creates a temporary Docker config for crane to use.
/// Includes retry logic for transient network failures.
fn run_crane(
    operation: &str,
    image: &str,
    oci_platform: Option<&str>,
    auth: Option<&RegistryAuth>,
    proxy: Option<&str>,
    no_proxy: Option<&str>,
) -> Result<String> {
    use crate::retry::{
        is_permanent_error, is_transient_network_error, retry_with_backoff, RetryConfig,
    };

    let op_name = format!("crane {}", operation);

    retry_with_backoff(
        RetryConfig::for_network(),
        &op_name,
        || run_crane_once(operation, image, oci_platform, auth, proxy, no_proxy),
        |e| {
            let error_msg = e.to_string();
            // Don't retry permanent errors
            if is_permanent_error(&error_msg) {
                return false;
            }
            // Retry transient network errors
            is_transient_network_error(&error_msg)
        },
    )
}

/// Execute a single crane command attempt.
fn run_crane_once(
    operation: &str,
    image: &str,
    oci_platform: Option<&str>,
    auth: Option<&RegistryAuth>,
    proxy: Option<&str>,
    no_proxy: Option<&str>,
) -> Result<String> {
    let mut cmd = Command::new("crane");
    cmd.arg(operation).arg(image);

    if let Some(p) = oci_platform {
        cmd.arg("--platform").arg(p);
    }

    // Set up auth if provided (temp_dir must stay alive until command completes)
    let _temp_dir = setup_docker_auth(image, auth)?;
    if let Some(ref td) = _temp_dir {
        cmd.env("DOCKER_CONFIG", td.path());
    }

    apply_proxy_env(&mut cmd, proxy, no_proxy);

    let output = cmd.output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(StorageError::new(format!(
            "crane {} failed: {}",
            operation, stderr
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Run crane manifest command.
fn crane_manifest(
    image: &str,
    oci_platform: Option<&str>,
    auth: Option<&RegistryAuth>,
    proxy: Option<&str>,
    no_proxy: Option<&str>,
) -> Result<String> {
    run_crane("manifest", image, oci_platform, auth, proxy, no_proxy)
}

/// Run crane config command.
fn crane_config(
    image: &str,
    oci_platform: Option<&str>,
    auth: Option<&RegistryAuth>,
    proxy: Option<&str>,
    no_proxy: Option<&str>,
) -> Result<String> {
    run_crane("config", image, oci_platform, auth, proxy, no_proxy)
}

/// Sanitize image name for use as filename.
fn sanitize_image_name(image: &str) -> String {
    image.replace(['/', ':', '@'], "_")
}

/// Reverse sanitization of a canonical image filename back to an image reference.
///
/// Because we now always store under the canonical form the mapping is
/// deterministic:
/// - The last `_`-delimited segment is the tag (or digest hex), except when
///   the penultimate segment is `sha256`, in which case `sha256_<hex>` is the
///   digest.
/// - Everything else is the `registry/path` portion, with `_` reversed to `/`.
///
/// The result is passed to `query_image`, which normalizes it before
/// computing the cache key.
fn unsanitize_image_name(name: &str) -> String {
    let parts: Vec<&str> = name.split('_').collect();
    if parts.len() < 2 {
        return name.to_string();
    }

    // Detect sha256 digest: penultimate segment is "sha256", last is 64 hex chars.
    let n = parts.len();
    if n >= 2
        && parts[n - 2] == "sha256"
        && parts[n - 1].len() == 64
        && parts[n - 1].chars().all(|c| c.is_ascii_hexdigit())
    {
        let name_part = parts[..n - 2].join("/");
        return format!("{name_part}@sha256:{}", parts[n - 1]);
    }

    // Normal case: last segment is the tag.
    let name_part = parts[..n - 1].join("/");
    format!("{name_part}:{}", parts[n - 1])
}

/// Get disk usage for a path.
#[allow(unused_variables)] // path is used only on Linux
fn get_disk_usage(path: &Path) -> Result<(u64, u64)> {
    // Use statvfs on Linux
    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;
        use std::mem::MaybeUninit;

        let path_cstr = CString::new(path.to_string_lossy().as_bytes()).map_err(|_| {
            StorageError::InvalidPath {
                path: "overlay path".into(),
            }
        })?;

        unsafe {
            let mut stat: MaybeUninit<libc::statvfs> = MaybeUninit::uninit();
            if libc::statvfs(path_cstr.as_ptr(), stat.as_mut_ptr()) != 0 {
                return Err(std::io::Error::last_os_error().into());
            }

            let stat = stat.assume_init();
            let total = stat.f_blocks * stat.f_frsize;
            let free = stat.f_bfree * stat.f_frsize;
            let used = total - free;

            Ok((total as u64, used as u64))
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        Ok((0, 0))
    }
}

/// Count entries in a directory.
fn count_entries(path: &Path) -> Result<usize> {
    if !path.exists() {
        return Ok(0);
    }

    Ok(std::fs::read_dir(path)?.count())
}

/// Convert an OCI platform string to its architecture component.
///
/// # Examples
/// - "linux/arm64" -> "arm64"
/// - "linux/amd64" -> "amd64"
/// - "linux/arm64/v8" -> "arm64"
fn oci_platform_to_arch(oci_platform: &str) -> String {
    // OCI platform format is "os/arch" or "os/arch/variant"
    // We want just the arch part
    let parts: Vec<&str> = oci_platform.split('/').collect();
    if parts.len() >= 2 {
        parts[1].to_string()
    } else {
        // Fallback: return as-is if not in expected format
        oci_platform.to_string()
    }
}

/// Calculate directory size recursively.
fn dir_size(path: &Path) -> Result<u64> {
    let mut size = 0;

    if path.is_file() {
        return Ok(std::fs::metadata(path)?.len());
    }

    for entry in std::fs::read_dir(path)? {
        let entry: std::fs::DirEntry = entry?;
        let path = entry.path();

        if path.is_file() {
            size += std::fs::metadata(&path)?.len();
        } else if path.is_dir() {
            size += dir_size(&path)?;
        }
    }

    Ok(size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn storage_exposed_only_to_privileged_workloads_without_a_user_storage_mount() {
        // Privileged (default) and no user mount at /storage → expose it, so an
        // --image VM sees /storage like a bare VM (docker-in-VM bind targets work).
        assert!(should_expose_storage(&[], false));

        // Unprivileged (untrusted code) never sees the VM's storage disk.
        assert!(!should_expose_storage(&[], true));

        // The user already claimed /storage (e.g. -v host:/storage) → don't clobber
        // it, even when privileged. Trailing slash is normalized.
        let user_mount = vec![("tag".to_string(), "/storage/".to_string(), false)];
        assert!(!should_expose_storage(&user_mount, false));

        // A user mount elsewhere doesn't suppress the /storage fallback.
        let other_mount = vec![("tag".to_string(), "/data".to_string(), false)];
        assert!(should_expose_storage(&other_mount, false));
    }

    #[test]
    fn test_oci_platform_to_arch_linux_arm64() {
        assert_eq!(oci_platform_to_arch("linux/arm64"), "arm64");
    }

    #[test]
    fn classifies_oci_whiteout_markers() {
        // Opaque marker must win over the generic `.wh.` prefix.
        assert_eq!(classify_layer_entry(".wh..wh..opq"), LayerEntry::OpaqueDir);
        // `.wh.<name>` carries the name to delete.
        assert_eq!(
            classify_layer_entry(".wh.RPM-GPG-KEY-kojiv2"),
            LayerEntry::Whiteout("RPM-GPG-KEY-kojiv2")
        );
        // A bare `.wh.` (no name) and ordinary files are normal entries.
        assert_eq!(classify_layer_entry(".wh."), LayerEntry::Normal);
        assert_eq!(classify_layer_entry("CERN.repo"), LayerEntry::Normal);
        assert_eq!(classify_layer_entry(".wherever"), LayerEntry::Normal);
    }

    #[test]
    fn jailed_join_blocks_escapes() {
        let base = Path::new("/layer");
        assert_eq!(
            jailed_join(base, Path::new("tmp/CERN.repo")),
            Some(PathBuf::from("/layer/tmp/CERN.repo"))
        );
        assert_eq!(
            jailed_join(base, Path::new("./tmp/./x")),
            Some(PathBuf::from("/layer/tmp/x"))
        );
        // `..` and absolute paths escape the layer dir — rejected.
        assert!(jailed_join(base, Path::new("../etc/passwd")).is_none());
        assert!(jailed_join(base, Path::new("tmp/../../etc")).is_none());
        assert!(jailed_join(base, Path::new("/etc/passwd")).is_none());
    }

    /// End-to-end extraction with whiteout conversion. mknod/setxattr(trusted.*)
    /// need root, so skip when not privileged (the live guest is PID 1 root).
    /// Linux-only: the syscalls and overlayfs semantics don't exist on macOS.
    #[test]
    fn extract_oci_layer_decompresses_gzip_and_zstd() {
        use std::io::Write;

        // A minimal single-file tar, owned by the current uid/gid so extraction
        // (which preserves ownership) succeeds without root.
        let uid = unsafe { libc::getuid() } as u64;
        let gid = unsafe { libc::getgid() } as u64;
        let mut tar_buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_buf);
            let body = b"hello from a layer";
            let mut header = tar::Header::new_gnu();
            header.set_path("greeting.txt").unwrap();
            header.set_size(body.len() as u64);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_mode(0o644);
            header.set_uid(uid);
            header.set_gid(gid);
            header.set_cksum();
            builder.append(&header, &body[..]).unwrap();
            builder.finish().unwrap();
        }

        let extract = |bytes: &[u8]| -> Vec<u8> {
            let dir = tempfile::tempdir().unwrap();
            extract_oci_layer(bytes, dir.path()).expect("extraction should succeed");
            std::fs::read(dir.path().join("greeting.txt")).unwrap()
        };

        // Plain tar passes through unchanged.
        assert_eq!(extract(&tar_buf), b"hello from a layer");

        // gzip-compressed layer.
        let gz = {
            let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            enc.write_all(&tar_buf).unwrap();
            enc.finish().unwrap()
        };
        assert_eq!(&gz[..2], &[0x1f, 0x8b], "gzip magic");
        assert_eq!(extract(&gz), b"hello from a layer");

        // zstd-compressed layer — the format that broke every library-image pull.
        let zst = zstd::stream::encode_all(&tar_buf[..], 0).unwrap();
        assert_eq!(&zst[..4], &[0x28, 0xb5, 0x2f, 0xfd], "zstd magic");
        assert_eq!(extract(&zst), b"hello from a layer");
    }

    /// A smolmachine pack blob pulled as if it were a container image must
    /// fail fast on its sentinel entries — before the pack's multi-GiB
    /// storage.ext4 fills the guest disk — with a host-flow routing hint.
    #[test]
    fn extract_oci_layer_rejects_smolmachine_pack_blobs() {
        // Owned by the current uid/gid so the nested-file case (which really
        // extracts, preserving ownership) succeeds without root.
        let uid = unsafe { libc::getuid() } as u64;
        let gid = unsafe { libc::getgid() } as u64;
        let build_tar = |name: &str| -> Vec<u8> {
            let mut buf = Vec::new();
            let mut builder = tar::Builder::new(&mut buf);
            let body = b"not really a disk image";
            let mut header = tar::Header::new_gnu();
            header.set_path(name).unwrap();
            header.set_size(body.len() as u64);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_mode(0o644);
            header.set_uid(uid);
            header.set_gid(gid);
            header.set_cksum();
            builder.append(&header, &body[..]).unwrap();
            builder.finish().unwrap();
            drop(builder);
            buf
        };

        for sentinel in ["storage.ext4", "agent-rootfs.tar", "./storage.ext4"] {
            let dir = tempfile::tempdir().unwrap();
            let err = extract_oci_layer(&build_tar(sentinel)[..], dir.path())
                .expect_err("pack sentinel must abort extraction");
            assert!(
                err.to_string().contains("smolmachine pack"),
                "clear error for {sentinel}, got: {err}"
            );
            assert!(
                err.to_string().contains("host"),
                "routing hint for {sentinel}, got: {err}"
            );
        }

        // A NESTED file of the same name is legitimate image content.
        let dir = tempfile::tempdir().unwrap();
        extract_oci_layer(&build_tar("var/lib/foo/storage.ext4")[..], dir.path())
            .expect("nested same-named file extracts normally");
        assert!(dir.path().join("var/lib/foo/storage.ext4").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn extract_oci_layer_applies_whiteouts() {
        // SAFETY: geteuid is always safe.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipping: extract_oci_layer whiteout test needs root (mknod/setxattr)");
            return;
        }
        use std::os::unix::fs::FileTypeExt;

        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path();

        // Build a layer tar: a real file, a `.wh.` delete marker shipped as a
        // hardlink to that file (the issue #397 shape), and an opaque dir.
        let mut buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut buf);
            let mut header = tar::Header::new_gnu();
            let body = b"repo-contents";
            header.set_path("tmp/CERN.repo").unwrap();
            header.set_size(body.len() as u64);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, &body[..]).unwrap();

            // Whiteout as a hardlink to the sibling file (would crash busybox tar).
            let mut wh = tar::Header::new_gnu();
            wh.set_entry_type(tar::EntryType::Link);
            wh.set_size(0);
            wh.set_mode(0o644);
            wh.set_path("tmp/.wh.RPM-GPG-KEY-kojiv2").unwrap();
            wh.set_link_name("tmp/CERN.repo").unwrap();
            wh.set_cksum();
            builder.append(&wh, std::io::empty()).unwrap();

            // Opaque marker for an `etc` directory.
            let mut opq = tar::Header::new_gnu();
            opq.set_entry_type(tar::EntryType::Regular);
            opq.set_size(0);
            opq.set_mode(0o644);
            opq.set_path("etc/.wh..wh..opq").unwrap();
            opq.set_cksum();
            builder.append(&opq, std::io::empty()).unwrap();

            builder.finish().unwrap();
        }

        extract_oci_layer(&buf[..], dest).expect("extraction should succeed");

        // The real file extracted.
        assert_eq!(
            std::fs::read(dest.join("tmp/CERN.repo")).unwrap(),
            b"repo-contents"
        );
        // The whiteout became an overlayfs char-device whiteout (0/0).
        let wh = dest.join("tmp/RPM-GPG-KEY-kojiv2");
        let meta = std::fs::symlink_metadata(&wh).expect("whiteout node exists");
        assert!(
            meta.file_type().is_char_device(),
            "whiteout is a char device"
        );
        use std::os::unix::fs::MetadataExt;
        assert_eq!(meta.rdev(), 0, "whiteout device number is 0/0");
        // The `.wh.` marker file itself is gone.
        assert!(!dest.join("tmp/.wh.RPM-GPG-KEY-kojiv2").exists());
        // The opaque xattr is set on the directory, and the marker file is gone.
        assert!(dest.join("etc").is_dir());
        assert_eq!(read_opaque_xattr(&dest.join("etc")), Some(b"y".to_vec()));
        assert!(!dest.join("etc/.wh..wh..opq").exists());
    }

    /// Read `trusted.overlay.opaque` for the extraction test (root-only).
    #[cfg(target_os = "linux")]
    fn read_opaque_xattr(path: &Path) -> Option<Vec<u8>> {
        use std::os::unix::ffi::OsStrExt;
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
        let name = std::ffi::CString::new("trusted.overlay.opaque").ok()?;
        let mut buf = [0u8; 16];
        // SAFETY: path/name are NUL-terminated; buf/len describe a valid buffer.
        let len = unsafe {
            libc::getxattr(
                c_path.as_ptr(),
                name.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };
        if len < 0 {
            return None;
        }
        Some(buf[..len as usize].to_vec())
    }

    #[test]
    fn test_oci_platform_to_arch_linux_amd64() {
        assert_eq!(oci_platform_to_arch("linux/amd64"), "amd64");
    }

    #[test]
    fn test_oci_platform_to_arch_with_variant() {
        assert_eq!(oci_platform_to_arch("linux/arm64/v8"), "arm64");
        assert_eq!(oci_platform_to_arch("linux/arm/v7"), "arm");
    }

    #[test]
    fn test_oci_platform_to_arch_fallback() {
        // If not in expected format, return as-is
        assert_eq!(oci_platform_to_arch("arm64"), "arm64");
        assert_eq!(oci_platform_to_arch("unknown"), "unknown");
    }

    /// Collect (name, value) for env vars explicitly set on a Command, with
    /// inherited vars filtered out. `Command::get_envs()` yields a tuple per
    /// explicit `.env()` / `.env_remove()` call: the value is `None` for
    /// removals and `Some(_)` for sets. We only care about sets here.
    fn explicit_envs(cmd: &Command) -> Vec<(String, String)> {
        cmd.get_envs()
            .filter_map(|(k, v)| {
                v.map(|val| {
                    (
                        k.to_string_lossy().into_owned(),
                        val.to_string_lossy().into_owned(),
                    )
                })
            })
            .collect()
    }

    #[test]
    fn apply_proxy_env_sets_http_and_https_when_proxy_present() {
        let mut cmd = Command::new("crane");
        apply_proxy_env(&mut cmd, Some("http://proxy.example.com:3128"), None);

        let envs = explicit_envs(&cmd);
        assert!(envs.contains(&(
            "HTTP_PROXY".to_string(),
            "http://proxy.example.com:3128".to_string()
        )));
        assert!(envs.contains(&(
            "HTTPS_PROXY".to_string(),
            "http://proxy.example.com:3128".to_string()
        )));
        // No NO_PROXY when not asked for — silent overreach would be a bug.
        assert!(!envs.iter().any(|(k, _)| k == "NO_PROXY"));
    }

    #[test]
    fn apply_proxy_env_sets_no_proxy_when_present() {
        let mut cmd = Command::new("crane");
        apply_proxy_env(&mut cmd, None, Some("127.0.0.1,.internal"));

        let envs = explicit_envs(&cmd);
        assert!(envs.contains(&("NO_PROXY".to_string(), "127.0.0.1,.internal".to_string())));
        // proxy=None must not set HTTP_PROXY / HTTPS_PROXY.
        assert!(!envs.iter().any(|(k, _)| k == "HTTP_PROXY"));
        assert!(!envs.iter().any(|(k, _)| k == "HTTPS_PROXY"));
    }

    #[test]
    fn apply_proxy_env_with_both_sets_all_three() {
        let mut cmd = Command::new("crane");
        apply_proxy_env(
            &mut cmd,
            Some("http://192.168.127.254:3128"),
            Some("127.0.0.1,localhost"),
        );

        let envs = explicit_envs(&cmd);
        assert_eq!(
            envs.len(),
            3,
            "expected exactly HTTP_PROXY, HTTPS_PROXY, NO_PROXY"
        );
        let map: std::collections::HashMap<_, _> = envs.into_iter().collect();
        assert_eq!(
            map.get("HTTP_PROXY").map(String::as_str),
            Some("http://192.168.127.254:3128")
        );
        assert_eq!(
            map.get("HTTPS_PROXY").map(String::as_str),
            Some("http://192.168.127.254:3128")
        );
        assert_eq!(
            map.get("NO_PROXY").map(String::as_str),
            Some("127.0.0.1,localhost")
        );
    }

    #[test]
    fn apply_proxy_env_with_none_is_noop() {
        let mut cmd = Command::new("crane");
        apply_proxy_env(&mut cmd, None, None);

        // Without explicit envs the iterator is empty — no accidental fallbacks.
        assert_eq!(explicit_envs(&cmd).len(), 0);
    }

    #[test]
    fn test_sanitize_image_name() {
        // sanitize_image_name operates on already-canonical refs
        assert_eq!(
            sanitize_image_name("docker.io/library/alpine:latest"),
            "docker.io_library_alpine_latest"
        );
        assert_eq!(
            sanitize_image_name("docker.io/library/alpine:3.18"),
            "docker.io_library_alpine_3.18"
        );
        assert_eq!(
            sanitize_image_name("ghcr.io/owner/repo@sha256:abc123"),
            "ghcr.io_owner_repo_sha256_abc123"
        );
    }

    #[test]
    fn test_unsanitize_image_name() {
        // Normal tag case
        assert_eq!(
            unsanitize_image_name("docker.io_library_alpine_3.20"),
            "docker.io/library/alpine:3.20"
        );
        assert_eq!(
            unsanitize_image_name("ghcr.io_owner_repo_v1"),
            "ghcr.io/owner/repo:v1"
        );
        // Digest case
        let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(
            unsanitize_image_name(&format!("docker.io_library_alpine_sha256_{hex}")),
            format!("docker.io/library/alpine@sha256:{hex}")
        );
    }

    #[test]
    fn test_extract_registry_from_image_normalizes_docker_hub() {
        assert_eq!(
            extract_registry_from_image("alpine:latest"),
            DOCKER_HUB_AUTH_CONFIG_KEY
        );
        assert_eq!(
            extract_registry_from_image("library/alpine:latest"),
            DOCKER_HUB_AUTH_CONFIG_KEY
        );
        assert_eq!(
            extract_registry_from_image("docker.io/nginxinc/nginx-unprivileged:stable-alpine"),
            DOCKER_HUB_AUTH_CONFIG_KEY
        );
        assert_eq!(
            extract_registry_from_image("index.docker.io/library/alpine:latest"),
            DOCKER_HUB_AUTH_CONFIG_KEY
        );
    }

    #[test]
    fn test_extract_registry_from_image_preserves_non_docker_hub_registry() {
        assert_eq!(
            extract_registry_from_image("ghcr.io/owner/repo:tag"),
            "ghcr.io"
        );
        assert_eq!(
            extract_registry_from_image("registry.example.com:5000/image:tag"),
            "registry.example.com:5000"
        );
    }

    #[test]
    fn overlay_resolv_conf_uses_localhost_when_dns_filter_enabled() {
        let _guard = env_lock().lock().unwrap();
        std::env::set_var(guest_env::DNS_FILTER, "1");
        std::env::remove_var(guest_env::BACKEND);
        std::env::remove_var(guest_env::DNS);

        assert_eq!(overlay_resolv_conf_contents(), "nameserver 127.0.0.1\n");

        std::env::remove_var(guest_env::DNS_FILTER);
    }

    #[test]
    fn overlay_resolv_conf_uses_virtio_dns_server() {
        let _guard = env_lock().lock().unwrap();
        std::env::remove_var(guest_env::DNS_FILTER);
        std::env::set_var(guest_env::BACKEND, guest_env::BACKEND_VIRTIO_NET);
        std::env::set_var(guest_env::DNS, "100.96.0.1");

        assert_eq!(overlay_resolv_conf_contents(), "nameserver 100.96.0.1\n");

        std::env::remove_var(guest_env::BACKEND);
        std::env::remove_var(guest_env::DNS);
    }

    #[test]
    fn overlay_resolv_conf_uses_custom_dns_under_tsi() {
        // TSI sets SMOLVM_NETWORK_DNS without SMOLVM_NETWORK_BACKEND. The guest
        // must honor the custom resolver (--dns) rather than the public default.
        let _guard = env_lock().lock().unwrap();
        std::env::remove_var(guest_env::DNS_FILTER);
        std::env::remove_var(guest_env::BACKEND);
        std::env::set_var(guest_env::DNS, "100.100.100.100");

        assert_eq!(
            overlay_resolv_conf_contents(),
            "nameserver 100.100.100.100\n"
        );

        std::env::remove_var(guest_env::DNS);
    }

    #[test]
    fn overlay_resolv_conf_defaults_to_public_resolvers() {
        let _guard = env_lock().lock().unwrap();
        std::env::remove_var(guest_env::DNS_FILTER);
        std::env::remove_var(guest_env::BACKEND);
        std::env::remove_var(guest_env::DNS);

        assert_eq!(
            overlay_resolv_conf_contents(),
            "nameserver 8.8.8.8\nnameserver 1.1.1.1\n"
        );
    }

    #[test]
    fn test_validate_storage_id_rejects_traversal() {
        assert!(validate_storage_id("../escape", "workload_id").is_err());
        assert!(validate_storage_id("foo/bar", "workload_id").is_err());
    }

    #[test]
    fn test_validate_container_destination_path_requires_absolute() {
        assert!(validate_container_destination_path("var/data").is_err());
        assert!(validate_container_destination_path("/").is_err());
        assert!(validate_container_destination_path("/var/data").is_ok());
    }

    #[test]
    fn test_ensure_mount_target_under_root_rejects_parent_traversal() {
        let root = tempfile::tempdir().unwrap();
        let rootfs = root.path().join("rootfs");
        std::fs::create_dir_all(&rootfs).unwrap();

        assert!(ensure_mount_target_under_root(&rootfs, "/../../escape").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn test_ensure_mount_target_under_root_rejects_symlink_escape() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let rootfs = root.path().join("rootfs");
        std::fs::create_dir_all(&rootfs).unwrap();

        symlink(outside.path(), rootfs.join("link-out")).unwrap();
        assert!(ensure_mount_target_under_root(&rootfs, "/link-out/dir").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn test_ensure_mount_target_under_root_replaces_intra_rootfs_symlink_with_dir() {
        use std::os::unix::fs::symlink;

        // Simulates the agent-rootfs having a pre-baked /workspace symlink from
        // a previous VM run (via virtiofs write-through). The function must
        // replace it with a real directory so the bind mount can claim the path.
        let root = tempfile::tempdir().unwrap();
        let rootfs = root.path().join("rootfs");
        let target_dir = rootfs.join("storage").join("workspace");
        std::fs::create_dir_all(&target_dir).unwrap();

        // /workspace → /storage/workspace (relative to rootfs) — symlink within rootfs
        let workspace_link = rootfs.join("workspace");
        symlink(&target_dir, &workspace_link).unwrap();
        assert!(workspace_link.is_symlink());

        let result = ensure_mount_target_under_root(&rootfs, "/workspace");
        assert!(result.is_ok(), "expected Ok, got {:?}", result);

        // The symlink must have been replaced with a real directory.
        assert!(
            !workspace_link.is_symlink(),
            "/workspace should no longer be a symlink"
        );
        assert!(
            workspace_link.is_dir(),
            "/workspace should now be a directory"
        );
    }

    #[test]
    fn ordered_packed_layers_honor_index_over_name_sort() {
        // Two layers whose digest-named dirs sort base-above-overlay (the bug):
        // base "fff…" sorts after overlay "4c8…", so a plain name sort + rev
        // would stack the base on top and shadow the overlay's modified files.
        let dir = tempfile::tempdir().unwrap();
        for name in ["fff3795b4371", "4c857248e0e2"] {
            std::fs::create_dir_all(dir.path().join(name)).unwrap();
        }
        // A stray non-layer dir (e.g. macOS .fseventsd) must be excluded when an
        // index is present.
        std::fs::create_dir_all(dir.path().join(".fseventsd")).unwrap();

        // Index records true OCI order, bottom→top: base then overlay.
        std::fs::write(
            dir.path().join(LAYER_ORDER_FILE),
            "fff3795b4371\n4c857248e0e2\n",
        )
        .unwrap();

        let ordered = ordered_packed_layer_names(dir.path()).unwrap();
        assert_eq!(
            ordered,
            vec!["fff3795b4371".to_string(), "4c857248e0e2".to_string()],
            "must follow the index (base→overlay), not the name sort, and drop .fseventsd"
        );
    }

    #[test]
    fn ordered_packed_layers_fall_back_to_name_sort_without_index() {
        // No index → legacy behavior: ascending name sort (correct for the
        // single-flattened-layer common case).
        let dir = tempfile::tempdir().unwrap();
        for name in ["bbb", "aaa"] {
            std::fs::create_dir_all(dir.path().join(name)).unwrap();
        }
        let ordered = ordered_packed_layer_names(dir.path()).unwrap();
        assert_eq!(ordered, vec!["aaa".to_string(), "bbb".to_string()]);
    }

    #[test]
    fn ordered_packed_layers_ignore_index_entries_without_a_dir() {
        // An index naming a missing layer falls back to the name sort rather
        // than silently dropping real layers.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("aaa")).unwrap();
        std::fs::write(dir.path().join(LAYER_ORDER_FILE), "does-not-exist\n").unwrap();
        let ordered = ordered_packed_layer_names(dir.path()).unwrap();
        assert_eq!(ordered, vec!["aaa".to_string()]);
    }

    /// Regression for the >255-byte `lowerdir` bug: the fsconfig mount path must
    /// mount a multi-layer overlay whose joined lower paths far exceed 255 bytes —
    /// the length the old `mount(8)` shell-out rejected. Needs root + Linux
    /// overlayfs, so it's `#[ignore]`d; run on a Linux host with:
    ///   cargo test -p smolvm-agent -- --ignored overlay_fsconfig_mounts_long_lowerdir
    #[test]
    #[ignore = "requires root + Linux overlayfs"]
    #[cfg(target_os = "linux")]
    fn overlay_fsconfig_mounts_long_lowerdir() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        // 8 layers with 64-char names => joined lowerdir ~600 bytes (>255).
        let mut lowerdirs = Vec::new();
        for i in 0..8u32 {
            let d = root.join("layers").join(format!("{i:064}"));
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join(format!("f{i}")), b"x").unwrap();
            lowerdirs.push(d.to_string_lossy().into_owned());
        }
        let joined_len: usize = lowerdirs.iter().map(|s| s.len() + 1).sum();
        assert!(
            joined_len > 255,
            "test must exceed the old limit, got {joined_len}"
        );

        let upper = root.join("upper");
        let work = root.join("work");
        let merged = root.join("merged");
        for p in [&upper, &work, &merged] {
            std::fs::create_dir_all(p).unwrap();
        }

        mount_overlay_fsconfig(&lowerdirs, &upper, &work, &merged)
            .expect("fsconfig overlay mount with a >255B lowerdir should succeed");
        // The merged view exposes files from every layer.
        assert!(merged.join("f0").exists());
        assert!(merged.join("f7").exists());
        let _ = std::process::Command::new("umount").arg(&merged).status();
    }
}
