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
use crate::paths::{self, STORAGE_ROOT};
use crate::process::{WaitResult, TIMEOUT_EXIT_CODE};
use smolvm_oci_layer::{decompress_layer_reader, extract_oci_layer};
use smolvm_protocol::guest_env;
use smolvm_protocol::{
    image_repo, normalize_image_ref, ImageInfo, OverlayInfo, RegistryAuth, StorageStatus,
};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use tracing::{debug, info, warn};

/// Directory structure within storage.
const LAYERS_DIR: &str = "layers";
const CONFIGS_DIR: &str = "configs";
const MANIFESTS_DIR: &str = "manifests";
const IMAGE_METADATA_DIR: &str = "image-metadata";
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

/// Create a regular-file mountpoint without following a final symlink outside
/// the container root. OCI runtimes require a file destination when the bind
/// source is a file.
pub(crate) fn ensure_file_mount_target_under_root(
    rootfs: &Path,
    container_path: &str,
) -> Result<PathBuf> {
    let relative = validate_container_destination_path(container_path)?;
    let file_name = relative
        .file_name()
        .ok_or_else(|| StorageError::ValidationFailed {
            context: "mount destination".to_string(),
            reason: "file mount destination has no filename".to_string(),
        })?;
    let parent = relative
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| StorageError::ValidationFailed {
            context: "mount destination".to_string(),
            reason: "file mount destination must have a parent directory".to_string(),
        })?;
    let parent_destination = format!("/{}", parent.display());
    let parent_path = ensure_mount_target_under_root(rootfs, &parent_destination)?;
    let target = parent_path.join(file_name);

    match std::fs::symlink_metadata(&target) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            std::fs::remove_file(&target).map_err(|error| StorageError::ReadFile {
                path: target.display().to_string(),
                cause: format!("failed to replace symlink at file mount target: {error}"),
            })?;
            std::fs::File::create(&target).map_err(|error| StorageError::ReadFile {
                path: target.display().to_string(),
                cause: format!("failed to create file mount target: {error}"),
            })?;
        }
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => {
            return Err(StorageError::ValidationFailed {
                context: "mount destination".to_string(),
                reason: format!(
                    "file mount destination is not a regular file: {}",
                    target.display()
                ),
            });
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::File::create(&target).map_err(|error| StorageError::ReadFile {
                path: target.display().to_string(),
                cause: format!("failed to create file mount target: {error}"),
            })?;
        }
        Err(error) => {
            return Err(StorageError::ReadFile {
                path: target.display().to_string(),
                cause: error.to_string(),
            });
        }
    }
    Ok(target)
}

/// Global state for packed layers support.
/// Set at startup if SMOLVM_PACKED_LAYERS env var is present.
static PACKED_LAYERS_DIR: OnceLock<Option<PathBuf>> = OnceLock::new();

/// Global state for boot-time volume mounts.
/// Set at startup if SMOLVM_MOUNT_COUNT env var is present.
static BOOT_VOLUME_MOUNTS: OnceLock<Vec<(String, String, bool)>> = OnceLock::new();
static BOOT_VOLUME_MOUNTS_FAILED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Prefix used only inside the guest agent's mount table. Runtime tags are
/// `staged+<stable-id>+<device-tag>`: the virtiofs device keeps `device-tag`,
/// while `stable-id` prevents reordered/replaced mounts from reusing stale data.
const STAGED_MOUNT_TAG_PREFIX: &str = "staged+";
const STAGED_MOUNT_ROOT: &str = "/storage/staged-mounts";

fn split_staged_mount_tag(tag: &str) -> (&str, Option<&str>) {
    if let Some(rest) = tag.strip_prefix(STAGED_MOUNT_TAG_PREFIX) {
        if let Some((working_id, device_tag)) = rest.split_once('+') {
            return (device_tag, Some(working_id));
        }
    }
    (tag, None)
}

/// Path a workload container should bind for a prepared mount.
/// Staged mounts bind the guest-local working copy; live mounts bind the
/// virtiofs staging directory.
pub fn volume_bind_source(tag: &str) -> PathBuf {
    let (device_tag, staged_id) = split_staged_mount_tag(tag);
    if let Some(staged_id) = staged_id {
        Path::new(STAGED_MOUNT_ROOT).join(staged_id)
    } else {
        Path::new(paths::VIRTIOFS_MOUNT_ROOT).join(device_tag)
    }
}

/// Mount a virtiofs device with one policy for every host-backed filesystem:
/// request DAX first, then fall back to the normal buffered data path when the
/// host did not give this device a DAX window. Explicit fsync still provides
/// durability; forcing the whole mount synchronous serializes every small
/// write and is unlike Docker/Podman's bind-mount behavior.
#[cfg(target_os = "linux")]
fn mount_virtiofs(tag: &str, mount_point: &Path) -> std::io::Result<bool> {
    let src = std::ffi::CString::new(tag)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid tag"))?;
    let dst = std::ffi::CString::new(mount_point.to_string_lossy().as_bytes()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid mount point")
    })?;
    let fstype = std::ffi::CString::new("virtiofs").expect("static filesystem type");
    let opts_dax = std::ffi::CString::new("dax").expect("static mount options");

    // SAFETY: every argument is a valid, live CString and mount() copies them.
    let dax_rc = unsafe {
        libc::mount(
            src.as_ptr(),
            dst.as_ptr(),
            fstype.as_ptr(),
            0,
            opts_dax.as_ptr() as *const libc::c_void,
        )
    };
    if dax_rc == 0 {
        return Ok(true);
    }

    // SAFETY: same arguments and lifetime as the DAX attempt above.
    let plain_rc = unsafe {
        libc::mount(
            src.as_ptr(),
            dst.as_ptr(),
            fstype.as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if plain_rc == 0 {
        Ok(false)
    } else {
        Err(std::io::Error::last_os_error())
    }
}

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
        let dax = match mount_virtiofs(tag, &mount_point) {
            Ok(dax) => dax,
            Err(err) => {
                warn!(error = %err, tag = %tag, "failed to mount packed layers virtiofs");
                return None;
            }
        };
        info!(mount_point = %mount_point.display(), dax, "packed layers mounted successfully");

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

/// Whether any boot-time mount needs the persistent guest storage disk.
///
/// Live virtiofs mounts can be initialized before `/storage` is available, but
/// staged mounts place their working copy there and must not race the deferred
/// storage mount.
pub fn staged_boot_mount_requested() -> bool {
    let count = std::env::var("SMOLVM_MOUNT_COUNT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    (0..count).any(|index| {
        std::env::var(format!("SMOLVM_MOUNT_{index}")).is_ok_and(|value| value.ends_with(":staged"))
    })
}

pub fn boot_volume_mounts_failed() -> bool {
    BOOT_VOLUME_MOUNTS_FAILED.load(std::sync::atomic::Ordering::Acquire)
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

            let staged = parts[2] == "staged";
            if staged && split_staged_mount_tag(parts[0]).1.is_none() {
                BOOT_VOLUME_MOUNTS_FAILED.store(true, std::sync::atomic::Ordering::Release);
                warn!(key = %env_key, "staged mount is missing its stable working-copy identity");
                continue;
            }
            let tag = parts[0].to_string();
            let guest_path = parts[1].to_string();
            let read_only = parts[2] == "ro";

            info!(tag = %tag, guest_path = %guest_path, read_only, staged, "boot volume mount");
            mounts.push((tag, guest_path, read_only));
        }

        if mounts
            .iter()
            .any(|(tag, _, _)| split_staged_mount_tag(tag).1.is_some())
        {
            if let Err(error) = prune_staged_working_copies(&mounts) {
                BOOT_VOLUME_MOUNTS_FAILED.store(true, std::sync::atomic::Ordering::Release);
                warn!(error = %error, "failed to prune stale staged working copies");
                return mounts;
            }
        }

        // Mount using existing logic with empty rootfs prefix so bind mounts
        // go to absolute guest paths (e.g., "/data"), visible to VmExec.
        if !mounts.is_empty() {
            if let Err(e) = setup_volume_mounts("/", &mounts) {
                BOOT_VOLUME_MOUNTS_FAILED.store(true, std::sync::atomic::Ordering::Release);
                warn!(error = %e, "failed to setup boot volume mounts");
            }
        }

        mounts
    })
}

/// Re-establish boot-time virtiofs mounts after a fork restore.
///
/// A clone resumes the golden agent after its one-time boot initialization,
/// while libkrun attaches fresh virtiofs devices to the clone VMM. The restored
/// mount can remain under the golden's old overlay tree, but a newly selected
/// clone overlay hides its bind target. Accessing that stale mount can block in
/// the dead golden virtiofs session indefinitely. Check only mount metadata
/// (never the stale filesystem), detach a stale staging mount if present, and
/// bind the clone's fresh device before acknowledging its first host request.
#[cfg(target_os = "linux")]
pub fn repair_boot_volume_mounts() -> Result<()> {
    let missing = init_volume_mounts()
        .iter()
        .filter(|(_, target, _)| !is_mountpoint(Path::new(target)))
        .cloned()
        .collect::<Vec<_>>();
    if missing.is_empty() {
        return Ok(());
    }

    for mount in &missing {
        let (tag, target, _) = mount;
        let (device_tag, _) = split_staged_mount_tag(tag);
        let staging = Path::new(paths::VIRTIOFS_MOUNT_ROOT).join(device_tag);
        if is_mountpoint(&staging) {
            detach_mount(&staging);
        }
        setup_volume_mounts("/", std::slice::from_ref(mount))?;
        if !is_mountpoint(Path::new(target)) {
            return Err(StorageError::new(format!(
                "boot volume mount '{}' was not restored at '{}'",
                tag, target
            )));
        }
        info!(tag = %device_tag, target = %target, "restored boot volume mount after clone resume");
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn repair_boot_volume_mounts() -> Result<()> {
    Ok(())
}

/// True when a user mount target claims /workspace itself or anything beneath it.
///
/// Compares path *components*, not string prefixes: `/workspaces/project` begins
/// with the characters of `/workspace` but is a sibling rather than a child, and
/// must not suppress the fallback. Slash-normalized so a trailing `/` on the
/// user's target still matches.
fn claims_workspace(target: &str) -> bool {
    Path::new(target.trim_end_matches('/')).starts_with(paths::WORKSPACE_GUEST_PATH)
}

/// Add the /storage/workspace → /workspace fallback bind mount to an OCI spec,
/// unless a user-provided volume already claims /workspace or a path under it.
///
/// The fallback exposes the storage disk's workspace directory inside containers
/// so that persistent files written to /workspace survive across VM restarts.
/// It must be skipped whenever the user has mounted at or below /workspace, to
/// avoid silently overwriting their virtiofs mount (which comes earlier in the
/// spec). Binding /workspace on top of a user mount at, say, /workspace/project
/// replaces the parent directory the nested mount hangs from: the mount stays in
/// the namespace and is listed in /proc/self/mountinfo, but no longer resolves by
/// path, so the user sees an empty directory instead of their files.
pub fn add_workspace_fallback(spec: &mut OciSpec, mounts: &[(String, String, bool)]) {
    let workspace_src = Path::new(STORAGE_ROOT).join(WORKSPACE_DIR);
    if !workspace_src.exists() {
        return;
    }
    add_workspace_fallback_from(spec, mounts, &workspace_src);
}

/// Core of [`add_workspace_fallback`], with the fallback source injected so the
/// rule can be exercised without a real /storage/workspace on the test host.
fn add_workspace_fallback_from(
    spec: &mut OciSpec,
    mounts: &[(String, String, bool)],
    workspace_src: &Path,
) {
    let user_owns_workspace = mounts.iter().any(|(_, path, _)| claims_workspace(path));
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

/// Subdir on the storage disk holding layers this VM unpacked for itself.
const GUEST_LAYERS_DIR: &str = "packed-layers";
/// Marker written once every staged tar has been unpacked, holding the staged
/// set's signature so a restart reuses the work and a changed pack redoes it.
const GUEST_LAYERS_MARKER: &str = ".extracted";

/// The layer tars a host staged for us rather than unpacking itself, if any.
///
/// A `.tar` whose sibling directory already exists was unpacked by the host, so
/// it is not ours to redo.
fn staged_layer_tars(packed_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut tars = Vec::new();
    let entries = std::fs::read_dir(packed_dir)
        .map_err(|e| StorageError::read_error(packed_dir.display().to_string(), e))?;
    for entry in entries {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == "tar") && !path.with_extension("").is_dir() {
            tars.push(path);
        }
    }
    tars.sort();
    Ok(tars)
}

/// Unpack host-staged layer tars onto the storage disk and return that
/// directory, or `None` when the host already unpacked them.
///
/// A host only unpacks a pack's layers itself when it can reproduce the
/// archived uid/gid, which in practice means running as root on Unix.
/// Everywhere else — macOS, Windows, a rootless Linux daemon — `chown` is
/// simply unavailable, and unpacking there silently re-owns every file to
/// whoever ran the command: an image's postgres files (uid 999) arrive owned by
/// the host user, and the service cannot read the data directory it owns.
///
/// Those hosts stage the raw tars instead and we unpack them here, where the
/// agent is root no matter what the host OS is. That is the same reason the
/// ordinary registry-pull path (`crane` + `tar`, in-guest) has always got
/// ownership right on every platform; this brings packs onto it.
///
/// Returning `None` for an already-unpacked dir leaves that path untouched, so
/// artifacts made by earlier versions keep working and a root Linux host keeps
/// sharing one extracted copy across every VM built on the pack.
fn ensure_packed_layers_extracted_with_progress<F>(
    packed_dir: &Path,
    mut progress: F,
) -> Result<Option<PathBuf>>
where
    F: FnMut(&str, u64),
{
    let tars = staged_layer_tars(packed_dir)?;
    if tars.is_empty() {
        return Ok(None);
    }

    let key = packed_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("packed");
    let out = Path::new(STORAGE_ROOT).join(GUEST_LAYERS_DIR).join(key);
    let marker = out.join(GUEST_LAYERS_MARKER);
    let signature = staged_tars_signature(&tars)?;
    if std::fs::read_to_string(&marker).ok().as_deref() == Some(signature.as_str()) {
        return Ok(Some(out));
    }

    // First boot on this disk, or the pack changed under a reused one.
    let _ = std::fs::remove_dir_all(&out);
    std::fs::create_dir_all(&out)?;
    for tar in &tars {
        let stem = tar.file_stem().and_then(|s| s.to_str()).ok_or_else(|| {
            StorageError::new(format!("unreadable layer name: {}", tar.display()))
        })?;
        let dir = out.join(stem);
        std::fs::create_dir_all(&dir)?;
        info!(layer = %stem, "unpacking staged layer");
        progress("unpacking image layers", 0);
        extract_layer_tar(tar, &dir)?;
    }

    // Carry the stacking order across; without it the guest would fall back to
    // sorting layer dirs by digest, which is not OCI order.
    let order = packed_dir.join(LAYER_ORDER_FILE);
    if order.is_file() {
        let _ = std::fs::copy(&order, out.join(LAYER_ORDER_FILE));
    }

    // Marker last, so an interrupted unpack is redone rather than trusted.
    std::fs::write(&marker, signature)?;
    Ok(Some(out))
}

/// Identify the staged set by each tar's name, size and mtime — enough to catch
/// a machine re-created from a different pack on a reused storage disk, without
/// reading hundreds of megabytes to hash them.
fn staged_tars_signature(tars: &[PathBuf]) -> Result<String> {
    let mut parts = Vec::with_capacity(tars.len());
    for tar in tars {
        let meta = std::fs::metadata(tar)
            .map_err(|e| StorageError::read_error(tar.display().to_string(), e))?;
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let name = tar.file_name().unwrap_or_default().to_string_lossy();
        parts.push(format!("{name}:{}:{mtime}", meta.len()));
    }
    Ok(parts.join(","))
}

/// Unpack one layer tar into `dir`, preserving ownership.
///
/// `tar` restores the archived uid/gid when it runs as root, which the agent
/// always does — that is the whole point of unpacking here rather than on the
/// host.
fn extract_layer_tar(tar: &Path, dir: &Path) -> Result<()> {
    let out = Command::new("tar")
        .arg("-x")
        .arg("-f")
        .arg(tar)
        .arg("-C")
        .arg(dir)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| StorageError::new(format!("failed to run tar: {e}")))?;
    if !out.status.success() {
        return Err(StorageError::new(format!(
            "failed to unpack layer {}: {}",
            tar.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

/// The directory whose subdirs are this pack's layers, materialising them first
/// if the host staged tars for us or handed us a saved-image archive.
fn effective_packed_dir(packed_dir: &Path) -> Result<PathBuf> {
    effective_packed_dir_with_progress(packed_dir, |_, _| {})
}

fn effective_packed_dir_with_progress<F>(packed_dir: &Path, mut progress: F) -> Result<PathBuf>
where
    F: FnMut(&str, u64),
{
    if let Some(flattened) = ensure_archive_flattened_with_progress(packed_dir, &mut progress)? {
        return Ok(flattened);
    }
    if let Some(extracted) =
        ensure_packed_layers_extracted_with_progress(packed_dir, &mut progress)?
    {
        return Ok(extracted);
    }
    Ok(packed_dir.to_path_buf())
}

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
            // A packed store is a volume root on macOS, so it always carries
            // filesystem bookkeeping directories. They are not image layers,
            // and mistaking one for the whole image builds a rootfs out of it.
            if !name.ends_with(".tar") && !is_volume_metadata(&entry.file_name()) {
                present.insert(name);
            }
        }
    }

    // A store with no usable layer directory at all cannot produce the image's
    // filesystem. Returning an empty list here would hand the caller an overlay
    // with no lower layer, which surfaces much later as a missing executable.
    if present.is_empty() {
        return Err(StorageError::new(format!(
            "no image layers are present in {}. The image has to be unpacked again \
             before this machine can start.",
            packed_dir.display()
        )));
    }

    // Prefer the explicit order index when it resolves to layers we actually have.
    // A stale index that names a layer we do not have falls back to the name sort
    // below rather than dropping the real layers that are here.
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

/// Env var to override where archive staging spills its scratch. Point it at a
/// mounted volume with more room than the storage disk, or elsewhere entirely.
const ARCHIVE_SCRATCH_DIR_ENV: &str = "SMOLVM_ARCHIVE_SCRATCH_DIR";

/// Scratch space for archive staging. Defaults to the storage disk because the
/// guest's `/tmp` is a tmpfs sized from VM RAM, so multi-GiB scratch — crane's
/// stdin spool, the decompressed copy of a compressed archive — must land on
/// the machine's disk instead: a 10 GB `docker save` archive would otherwise
/// fill `/tmp` while `/storage` sits idle (#955). Precedence:
///   1. `SMOLVM_ARCHIVE_SCRATCH_DIR`, when set to a dir that can be created;
///   2. `/storage/tmp`, the storage disk;
///   3. the default temp dir, when the storage disk is absent (host-side unit
///      tests).
fn archive_scratch_dir() -> PathBuf {
    if let Ok(dir) = std::env::var(ARCHIVE_SCRATCH_DIR_ENV) {
        let dir = dir.trim();
        if !dir.is_empty() {
            let p = PathBuf::from(dir);
            if std::fs::create_dir_all(&p).is_ok() {
                return p;
            }
            warn!(dir = %p.display(), "{ARCHIVE_SCRATCH_DIR_ENV} unusable, falling back to the storage disk");
        }
    }
    let dir = Path::new(STORAGE_ROOT).join("tmp");
    if std::fs::create_dir_all(&dir).is_ok() {
        dir
    } else {
        std::env::temp_dir()
    }
}

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
fn ensure_archive_flattened_with_progress<F>(
    packed_dir: &Path,
    mut progress: F,
) -> Result<Option<PathBuf>>
where
    F: FnMut(&str, u64),
{
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
    progress("flattening local image archive", 0);
    flatten_archive_with_progress(&archive, &rootfs, &mut progress)?;
    // Recover the image config before writing the marker, so a later reuse can
    // rely on config.json being present. A docker/podman `save` always carries
    // one.
    progress("recovering image configuration", 0);
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
    pipe_archive_into_with_progress(cmd, archive, &mut |_, _| {})
}

fn pipe_archive_into_with_progress<F>(
    cmd: &mut Command,
    archive: &Path,
    progress: &mut F,
) -> Result<Option<tempfile::NamedTempFile>>
where
    F: FnMut(&str, u64),
{
    let (input, tmp) = prepare_archive_input_with_progress(archive, progress)?;
    cmd.stdin(Stdio::from(input));
    Ok(tmp)
}

fn prepare_archive_input_with_progress<F>(
    archive: &Path,
    progress: &mut F,
) -> Result<(std::fs::File, Option<tempfile::NamedTempFile>)>
where
    F: FnMut(&str, u64),
{
    let file = std::fs::File::open(archive)?;
    if !is_compressed(archive)? {
        return Ok((file, None));
    }
    // Expand to a temp file, then feed that. `docker save` archives are a local
    // dev-import path, so the extra copy is cheap and avoids threading a
    // streaming decompressor into a subprocess's stdin. The guest ships no zstd
    // tool, so decompression is done in-process.
    let mut reader = decompress_layer_reader(file)?;
    let mut tmp = tempfile::NamedTempFile::new_in(archive_scratch_dir())
        .map_err(|e| StorageError::new(format!("failed to create temp file: {e}")))?;
    copy_with_progress(
        &mut reader,
        tmp.as_file_mut(),
        "decompressing image archive",
        progress,
    )
    .map_err(|e| StorageError::new(format!("failed to decompress archive: {e}")))?;
    let reopened = tmp
        .reopen()
        .map_err(|e| StorageError::new(format!("failed to reopen temp file: {e}")))?;
    Ok((reopened, Some(tmp)))
}

fn copy_with_progress<R, W, F>(
    reader: &mut R,
    writer: &mut W,
    phase: &str,
    progress: &mut F,
) -> std::io::Result<u64>
where
    R: Read,
    W: Write,
    F: FnMut(&str, u64),
{
    const BUFFER_SIZE: usize = 1024 * 1024;
    const REPORT_BYTES: u64 = 16 * 1024 * 1024;
    const REPORT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

    let mut buffer = vec![0u8; BUFFER_SIZE];
    let mut total = 0u64;
    let mut last_reported = 0u64;
    let mut last_report = std::time::Instant::now();

    progress(phase, 0);
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        writer.write_all(&buffer[..read])?;
        total += read as u64;

        if total - last_reported >= REPORT_BYTES || last_report.elapsed() >= REPORT_INTERVAL {
            progress(phase, total);
            last_reported = total;
            last_report = std::time::Instant::now();
        }
    }
    writer.flush()?;
    if total != last_reported {
        progress(phase, total);
    }
    Ok(total)
}

fn spawn_copy_with_progress<R, W>(
    mut reader: R,
    mut writer: W,
    phase: &'static str,
) -> (
    std::thread::JoinHandle<std::io::Result<u64>>,
    std::sync::mpsc::Receiver<(&'static str, u64)>,
)
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    let (progress_tx, progress_rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        copy_with_progress(&mut reader, &mut writer, phase, &mut |_, bytes| {
            let _ = progress_tx.send((phase, bytes));
        })
    });
    (handle, progress_rx)
}

fn forward_latest_progress<F>(
    progress_rx: &std::sync::mpsc::Receiver<(&'static str, u64)>,
    progress: &mut F,
) where
    F: FnMut(&str, u64),
{
    let mut latest = None;
    while let Ok(update) = progress_rx.try_recv() {
        latest = Some(update);
    }
    if let Some((phase, bytes)) = latest {
        progress(phase, bytes);
    }
}

#[cfg(unix)]
fn copy_process_output_with_progress<R, W, F>(
    reader: &mut R,
    writer: &mut W,
    phase: &str,
    input_progress: &std::sync::mpsc::Receiver<(&'static str, u64)>,
    progress: &mut F,
) -> std::io::Result<u64>
where
    R: Read + AsRawFd,
    W: Write,
    F: FnMut(&str, u64),
{
    const BUFFER_SIZE: usize = 1024 * 1024;
    const REPORT_BYTES: u64 = 16 * 1024 * 1024;
    const REPORT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

    let mut buffer = vec![0u8; BUFFER_SIZE];
    let mut total = 0u64;
    let mut last_reported = 0u64;
    let mut last_report = std::time::Instant::now();

    progress(phase, 0);
    loop {
        forward_latest_progress(input_progress, progress);
        let mut poll_fd = libc::pollfd {
            fd: reader.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut poll_fd, 1, 1000) };
        if ready < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if ready == 0 {
            continue;
        }

        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        writer.write_all(&buffer[..read])?;
        total += read as u64;

        if total - last_reported >= REPORT_BYTES || last_report.elapsed() >= REPORT_INTERVAL {
            progress(phase, total);
            last_reported = total;
            last_report = std::time::Instant::now();
        }
    }
    writer.flush()?;
    forward_latest_progress(input_progress, progress);
    if total != last_reported {
        progress(phase, total);
    }
    Ok(total)
}

#[cfg(not(unix))]
fn copy_process_output_with_progress<R, W, F>(
    reader: &mut R,
    writer: &mut W,
    phase: &str,
    input_progress: &std::sync::mpsc::Receiver<(&'static str, u64)>,
    progress: &mut F,
) -> std::io::Result<u64>
where
    R: Read,
    W: Write,
    F: FnMut(&str, u64),
{
    let result = copy_with_progress(reader, writer, phase, progress);
    forward_latest_progress(input_progress, progress);
    result
}

/// Flatten a `docker save` archive into `rootfs`, delegating to the bundled
/// `crane export`. The flattened tar is a single layer with no whiteouts, so
/// plain `tar -x` is sufficient (no per-layer handling needed).
fn flatten_archive_with_progress<F>(archive: &Path, rootfs: &Path, progress: &mut F) -> Result<()>
where
    F: FnMut(&str, u64),
{
    // crane export - - : read an image tarball from stdin, write a flat rootfs
    // tar to stdout.
    let mut crane = Command::new("crane");
    crane
        .args(["export", "-", "-"])
        // crane spools the stdin tarball to a temp file before flattening it;
        // point that at the storage disk so an archive bigger than the RAM-sized
        // /tmp tmpfs doesn't fail with a full filesystem (#955).
        .env("TMPDIR", archive_scratch_dir())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // Capture (don't discard) crane's stderr so a failure reports the REAL
        // reason — e.g. "file manifest.json not found in tar" for an empty or
        // truncated archive — instead of a misleading guess.
        .stderr(Stdio::piped());
    // Held alive until crane has consumed it (the decompressed input, if any).
    let (archive_input, _archive_tmp) = prepare_archive_input_with_progress(archive, progress)?;

    let mut crane_child = crane
        .spawn()
        .map_err(|e| StorageError::new(format!("failed to spawn crane export: {e}")))?;
    let crane_in = crane_child
        .stdin
        .take()
        .ok_or_else(|| StorageError::new("failed to open crane stdin".to_string()))?;
    let (input_copy_thread, input_progress) =
        spawn_copy_with_progress(archive_input, crane_in, "reading image archive");
    let crane_out = crane_child
        .stdout
        .take()
        .ok_or_else(|| StorageError::new("failed to capture crane stdout".to_string()))?;
    let mut crane_err = crane_child
        .stderr
        .take()
        .ok_or_else(|| StorageError::new("failed to capture crane stderr".to_string()))?;

    let mut tar_child = Command::new("tar")
        .arg("-x")
        .arg("-C")
        .arg(rootfs)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| StorageError::new(format!("failed to run tar: {e}")))?;

    let mut tar_in = tar_child
        .stdin
        .take()
        .ok_or_else(|| StorageError::new("failed to open tar stdin".to_string()))?;

    // Drain stderr concurrently: crane may emit enough diagnostics to fill its
    // pipe while stdout is still flowing, which would otherwise deadlock the
    // crane -> host -> tar pipeline.
    let crane_err_thread = std::thread::spawn(move || {
        let mut stderr = String::new();
        let _ = std::io::Read::read_to_string(&mut crane_err, &mut stderr);
        stderr
    });

    let mut crane_out = crane_out;
    let copy_result = copy_process_output_with_progress(
        &mut crane_out,
        &mut tar_in,
        "extracting flattened rootfs",
        &input_progress,
        progress,
    );
    drop(tar_in);

    let tar_out = tar_child
        .wait_with_output()
        .map_err(|e| StorageError::new(format!("failed to wait for tar: {e}")))?;

    let crane_status = crane_child
        .wait()
        .map_err(|e| StorageError::new(format!("failed to wait for crane: {e}")))?;
    let input_copy_result = input_copy_thread
        .join()
        .unwrap_or_else(|_| Err(std::io::Error::other("archive input worker panicked")));
    let crane_stderr = crane_err_thread.join().unwrap_or_default();

    if !crane_status.success() {
        let stderr = crane_stderr.trim();
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
    input_copy_result
        .map_err(|e| StorageError::new(format!("streaming image archive failed: {e}")))?;
    copy_result
        .map_err(|e| StorageError::new(format!("streaming flattened rootfs failed: {e}")))?;
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

/// Marker recording that a layer finished extracting AND its data reached the
/// disk (written only after the writeback barrier in the pull). It sits NEXT TO
/// the layer directory, never inside it — layer dirs are overlay lowerdirs, so
/// a file inside would surface in every container's root.
fn layer_ok_marker(layer_dir: &Path) -> PathBuf {
    let mut name = layer_dir.file_name().unwrap_or_default().to_os_string();
    name.push(".ok");
    layer_dir.with_file_name(name)
}

fn image_size_cache_path(root: &Path, image: &str) -> PathBuf {
    root.join(IMAGE_METADATA_DIR)
        .join(sanitize_image_name(image) + ".size")
}

fn read_cached_image_size(root: &Path, image: &str) -> Option<u64> {
    std::fs::read_to_string(image_size_cache_path(root, image))
        .ok()?
        .trim()
        .parse()
        .ok()
}

fn calculate_image_size(root: &Path, layers: &[String]) -> u64 {
    layers
        .iter()
        .filter_map(|digest| {
            let id = digest.strip_prefix("sha256:").unwrap_or(digest);
            dir_size(&root.join(LAYERS_DIR).join(id)).ok()
        })
        .sum()
}

fn cache_image_size(root: &Path, image: &str, size: u64) {
    let dir = root.join(IMAGE_METADATA_DIR);
    if std::fs::create_dir_all(&dir).is_ok() {
        let _ = std::fs::write(image_size_cache_path(root, image), size.to_string());
    }
}

/// Check if a layer directory is properly cached: its completion marker and
/// directory both exist.
///
/// The marker is written only after extraction succeeded and the filesystem
/// reported the data flushed, so its absence covers every bad state the old
/// "directory is non-empty" check trusted: interrupted extraction, and
/// extraction whose writeback later failed (a host out of disk surfaces as
/// guest I/O errors AFTER tar exits, leaving corrupt layers that were then
/// reused on every restart). A successfully extracted OCI layer may legitimately
/// contain no filesystem entries, so the marker—not directory contents—is the
/// integrity signal.
fn is_layer_cached(layer_dir: &Path) -> bool {
    layer_dir.is_dir() && layer_ok_marker(layer_dir).is_file()
}

/// Force writeback of everything extracted onto the storage filesystem and
/// surface any I/O error doing so. `sync(2)` reports nothing — during a
/// host-out-of-disk incident it happily returned while every dirtied page
/// failed to land — so this uses `syncfs(2)`, which returns writeback errors.
#[cfg(target_os = "linux")]
fn sync_layer_writeback(root: &Path) -> Result<()> {
    use std::os::unix::io::AsRawFd;
    let dir = std::fs::File::open(root)
        .map_err(|e| StorageError::new(format!("open {} for syncfs: {}", root.display(), e)))?;
    // SAFETY: syncfs on a valid, owned fd.
    if unsafe { libc::syncfs(dir.as_raw_fd()) } != 0 {
        return Err(StorageError::new(format!(
            "flushing extracted layers to disk failed (out of space?): {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn sync_layer_writeback(_root: &Path) -> Result<()> {
    Ok(())
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
        (root.join(IMAGE_METADATA_DIR), "image metadata"),
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

    // Count layers and images. Layers count directories only — their `.ok`
    // completion markers are sibling files and would double the number.
    let layer_count = count_dir_entries(&root.join(LAYERS_DIR))?;
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
        // A saved-image archive is flattened, host-staged tars are unpacked
        // here, and an already-unpacked dir is used as-is.
        return create_packed_image_info(image, &effective_packed_dir(packed_dir)?);
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
            let _ = std::fs::remove_file(image_size_cache_path(root, image));
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
    // Layers extracted by THIS pull; their completion markers are written only
    // after the writeback barrier below confirms the data reached the disk.
    let mut newly_extracted: Vec<PathBuf> = Vec::new();
    for (i, layer_digest) in layers.iter().enumerate() {
        let layer_id = layer_digest.strip_prefix("sha256:").unwrap_or(layer_digest);
        let layer_dir = root.join(LAYERS_DIR).join(layer_id);

        if is_layer_cached(&layer_dir) {
            info!(layer = %layer_id, "layer already cached");
            // Report progress after confirming cache hit
            progress(i + 1, total_layers, layer_id);
            continue;
        }

        // Clean up an incomplete or unverified layer directory: empty, or left
        // by an interrupted/unflushed earlier extraction (no completion marker).
        if layer_dir.exists() {
            warn!(layer = %layer_id, "removing incomplete or unverified layer directory");
            if let Err(e) = std::fs::remove_dir_all(&layer_dir) {
                warn!(layer = %layer_id, error = %e, "failed to remove incomplete layer directory");
            }
        }
        let _ = std::fs::remove_file(layer_ok_marker(&layer_dir));

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

        newly_extracted.push(layer_dir);

        // Report progress after successful extraction
        progress(i + 1, total_layers, layer_id);
    }

    // Signal that layers are done and we're syncing — this can take a while
    // for large images (gigabytes flushed through virtio-blk).
    progress(total_layers, total_layers, "syncing");

    // Writeback barrier before anything marks these layers trustworthy.
    // Defense in depth: even though shutdown waits for acknowledgment (which also
    // syncs), we sync here because:
    // 1. Commands may complete and VM may exit before shutdown is called
    // 2. Protects against ungraceful termination (SIGKILL, host crash)
    // 3. tar can exit cleanly while every page it dirtied later fails writeback
    //    (a host out of disk surfaces exactly this way) — only an error-reporting
    //    sync catches it, and a pull must FAIL then, not report done.
    if let Err(sync_error) = sync_layer_writeback(root) {
        for dir in &newly_extracted {
            let _ = std::fs::remove_dir_all(dir);
            let _ = std::fs::remove_file(layer_ok_marker(dir));
        }
        return Err(sync_error);
    }

    // Markers last: a layer without one is re-pulled, never trusted.
    for dir in &newly_extracted {
        std::fs::write(layer_ok_marker(dir), "ok")
            .map_err(|e| StorageError::new(format!("write layer completion marker: {}", e)))?;
    }

    // Directory traversal is expensive for multi-gigabyte images and image
    // metadata is consulted on every persistent exec. Compute the physical
    // size once after the verified pull and keep it out of the command hot path.
    let total_size = calculate_image_size(root, &layers);
    cache_image_size(root, image, total_size);

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
        let effective = effective_packed_dir(packed_dir)?;
        return Ok(Some(create_packed_image_info(image, &effective)?));
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

    // Verify all layers are present AND verified (completion marker written
    // after the pull's writeback barrier) and calculate total size. A layer dir
    // that exists without its marker is an interrupted or unflushed extraction —
    // trusting it is how a corrupted store kept "booting" after an out-of-disk
    // pull — so the image re-pulls instead.
    for layer_digest in &layers {
        let layer_id = layer_digest.strip_prefix("sha256:").unwrap_or(layer_digest);
        let layer_dir = root.join(LAYERS_DIR).join(layer_id);
        if !is_layer_cached(&layer_dir) {
            // Clean up corrupt manifest to avoid repeated failures
            warn!(layer = %layer_id, image = %image, "cached image has a missing or unverified layer, cleaning up and will re-pull");
            let _ = std::fs::remove_file(&manifest_path);
            let _ = std::fs::remove_file(image_size_cache_path(root, image));
            return Ok(None);
        }
    }

    // Older stores have no size sidecar. Pay the directory walk once, persist
    // it, and keep all subsequent execs O(layer-count) instead of O(files).
    let total_size = read_cached_image_size(root, image).unwrap_or_else(|| {
        let size = calculate_image_size(root, &layers);
        cache_image_size(root, image, size);
        size
    });

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
    let metadata_dir = root.join(IMAGE_METADATA_DIR);

    if manifests_dir.exists() {
        std::fs::remove_dir_all(&manifests_dir)?;
    }
    if configs_dir.exists() {
        std::fs::remove_dir_all(&configs_dir)?;
    }
    if metadata_dir.exists() {
        std::fs::remove_dir_all(&metadata_dir)?;
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
/// Entries a filesystem puts at a volume root that never belong to an image
/// layer. A layer store on macOS is an APFS volume, so it always carries at
/// least `.fseventsd` -- which made an emptied store look populated and let a
/// container start on an image that no longer had a filesystem.
fn is_volume_metadata(name: &std::ffi::OsStr) -> bool {
    matches!(
        name.to_string_lossy().as_ref(),
        ".fseventsd"
            | ".Spotlight-V100"
            | ".Trashes"
            | ".TemporaryItems"
            | ".DS_Store"
            | ".DocumentRevisions-V100"
            | "lost+found"
    )
}

/// Reject lower layers that cannot produce the image's filesystem.
///
/// A single empty layer is legal -- an OCI layer may carry only metadata or
/// whiteouts. Every layer being empty is not: the image then contributes
/// nothing, the container runs on its upper layer alone, and the first sign of
/// trouble is `executable file not found in $PATH` for a binary the image was
/// supposed to provide. Failing here names the real problem instead.
fn verify_layers(lowerdirs: &[String]) -> Result<()> {
    let mut populated = 0usize;
    for layer_path in lowerdirs {
        let path = Path::new(layer_path);
        if !path.exists() {
            return Err(StorageError::new(format!(
                "layer path does not exist: {}",
                layer_path
            )));
        }
        let entry_count = std::fs::read_dir(path)
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .filter(|e| !is_volume_metadata(&e.file_name()))
                    .count()
            })
            .unwrap_or(0);
        if entry_count == 0 {
            warn!(layer = %layer_path, "layer directory is empty");
        } else {
            populated += 1;
        }
    }
    if populated == 0 && !lowerdirs.is_empty() {
        return Err(StorageError::new(format!(
            "the machine's image layers are missing: all {} unpacked layer \
             director{} empty, so the container would have no image \
             filesystem. The image has to be unpacked again before this \
             machine can start.",
            lowerdirs.len(),
            if lowerdirs.len() == 1 {
                "y is"
            } else {
                "ies are"
            },
        )));
    }
    Ok(())
}

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
    fn setup_upper_layer(&self, lowerdirs: &[String]) -> Result<()> {
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

        // Prefer IPv4 for dual-stack destinations so a flaky or wrongly-advertised
        // IPv6 path can never cause a hard hang: glibc reads /etc/gai.conf, and
        // this entry ranks IPv4-mapped addresses above the default IPv6
        // precedences (RFC 6724), so clients try v4 first and fall back to v6
        // only when v4 is unavailable. The host only advertises v6 when a real
        // reachability probe passes; this is the belt-and-suspenders for the
        // window where an advertised v6 later goes bad. Distros ship gai.conf
        // with this line COMMENTED (Debian/Ubuntu), so provide it unless the
        // image sets its own active rules; musl does its own sorting and ignores
        // gai.conf, so those guests rely solely on the host probe.
        let gai_path = upper_etc.join("gai.conf");
        let image_has_gai_rules = lowerdirs
            .iter()
            .any(|l| hosts_file_has_entries(&Path::new(l).join("etc/gai.conf")));
        if !image_has_gai_rules && !gai_path.exists() {
            let gai_contents =
                "# Managed by smolvm: prefer IPv4 so a flaky IPv6 path cannot hang clients.\n\
                 precedence ::ffff:0:0/96  100\n";
            if let Err(e) = std::fs::write(&gai_path, gai_contents) {
                warn!(error = %e, "failed to write gai.conf to upper layer");
            }
        }

        // Container runtimes are expected to provide /etc/hosts (Docker bind-
        // mounts a generated one), so minimal images like rancher/k3s ship
        // without it — and software that templates from it (containerd's pod
        // sandbox hosts generation, for one) hard-fails on the missing file.
        // Provide a default only when neither the image nor a previous session
        // supplies one: unlike resolv.conf this file is never overwritten, so
        // image-provided copies and in-container edits stay untouched. "Supplies
        // one" means actual name mappings — Ubuntu-derived images often ship an
        // empty or comments-only /etc/hosts, and counting those left `localhost`
        // unresolvable inside the container.
        let hosts_path = upper_etc.join("hosts");
        let image_has_hosts = lowerdirs
            .iter()
            .any(|l| hosts_file_has_entries(&Path::new(l).join("etc/hosts")));
        if !image_has_hosts && !hosts_path.exists() {
            let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
            if let Err(e) = std::fs::write(&hosts_path, overlay_hosts_contents(hostname.trim())) {
                warn!(error = %e, "failed to write hosts to upper layer");
            }
        }

        // Create /dev directory in upper layer - we'll bind mount the real /dev later
        let upper_dev = self.upper_path.join("dev");
        std::fs::create_dir_all(&upper_dev)?;

        Ok(())
    }

    /// Verify that all layer paths exist and log warnings for empty layers.
    fn verify_layers(&self, lowerdirs: &[String]) -> Result<()> {
        verify_layers(lowerdirs)
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
        self.setup_upper_layer(&lowerdirs)?;
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

/// Default /etc/hosts for images that ship without one, mirroring the file
/// Docker generates: loopback names plus the guest hostname (Debian-style
/// 127.0.1.1), so `hostname`-resolving software works out of the box.
fn overlay_hosts_contents(hostname: &str) -> String {
    let mut hosts =
        String::from("127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n");
    if !hostname.is_empty() && hostname != "localhost" {
        hosts.push_str(&format!("127.0.1.1\t{}\n", hostname));
    }
    hosts
}

/// True when this /etc/hosts actually provides name mappings — at least one
/// non-comment, non-blank line. An empty or comments-only file must not count
/// as image-provided, or `localhost` never resolves in the container.
fn hosts_file_has_entries(path: &Path) -> bool {
    std::fs::read_to_string(path)
        .map(|contents| {
            contents
                .lines()
                .map(str::trim)
                .any(|line| !line.is_empty() && !line.starts_with('#'))
        })
        .unwrap_or(false)
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
        // A saved-image archive is flattened into a rootfs (a single packed
        // layer), host-staged tars are unpacked here, and an already-unpacked
        // dir is used as-is.
        let effective = effective_packed_dir(packed_dir)?;
        return prepare_overlay_from_packed(image, workload_id, &effective);
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
// The workload parameter list, mirrored by `main::handle_run`; both want
// folding into a shared spec struct rather than trimming here.
#[allow(clippy::too_many_arguments)]
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

        // Build an OCI spec for `cmd` sharing this overlay's rootfs, virtiofs
        // mounts, workspace/storage fallbacks, and the same injections. Used for
        // both the one-shot exec spec and the keep-alive spec so a container the
        // execs join has the identical mount view as the exec itself.
        let build_spec = |cmd: &[String], spec_env: &[(String, String)]| {
            let mut spec = OciSpec::new(cmd, spec_env, workdir_str, false, &identity, unprivileged);
            spec.add_gpu_devices_if_available();
            for (tag, container_path, read_only) in mounts {
                let virtiofs_mount = volume_bind_source(tag);
                spec.add_bind_mount(
                    &virtiofs_mount.to_string_lossy(),
                    container_path,
                    *read_only,
                );
            }
            add_workspace_fallback(&mut spec, mounts);
            add_storage_fallback(&mut spec, mounts, unprivileged);
            // Forward SSH agent + published sockets + forkpoint if enabled at boot.
            crate::ssh_agent::inject_into_container(&mut spec);
            crate::publish_socket::inject_into_container(&mut spec);
            crate::forkpoint::inject_into_container(&mut spec);
            crate::cuda::inject_into_container(&mut spec, Path::new(&prepared.rootfs_path));
            crate::vulkan::inject_into_container(&mut spec, Path::new(&prepared.rootfs_path));
            spec
        };

        // If a main workload container is running for this overlay, join it
        // via crun exec instead of creating a fresh isolated container.
        if let Some(cid) = crate::resolve_main_container(persistent_overlay_id) {
            let result = run_exec_in_container(&cid, command, env, workdir, timeout_ms, client_fd);
            let _ = mounted_paths;
            return result;
        }

        // Persistent overlay with no keep-alive container. This is the fork-clone
        // path: the clone's restored keep-alive was reaped as stale during the
        // remount above, and without re-establishing one every exec would pay a
        // fresh container (~seconds) instead of a `crun exec` join (~ms).
        // Establish a keep-alive (PID 1 = `tail -f /dev/null`) sharing this
        // overlay's mounts, persist its id so subsequent execs join it, then
        // exec the command INTO it.
        if let Some(overlay_id) = persistent_overlay_id {
            let keepalive = [
                "tail".to_string(),
                "-f".to_string(),
                "/dev/null".to_string(),
            ];
            match establish_keepalive_container(
                &build_spec(&keepalive, env),
                &bundle_path,
                overlay_id,
            ) {
                Ok(cid) => {
                    let result =
                        run_exec_in_container(&cid, command, env, workdir, timeout_ms, client_fd);
                    let _ = mounted_paths;
                    return result;
                }
                Err(e) => {
                    warn!(error = %e, "keep-alive main container setup failed; running in a fresh container")
                }
            }
        }

        // Ephemeral overlay (or keep-alive setup failed): one-shot fresh container.
        let spec = build_spec(command, env);
        spec.write_to(&bundle_path)
            .map_err(|e| StorageError::new(format!("failed to write OCI spec: {}", e)))?;
        let container_id = generate_container_id();
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
// Same workload parameter list as `run_command`, minus the wait-related args.
#[allow(clippy::too_many_arguments)]
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
        let virtiofs_mount = volume_bind_source(tag);
        spec.add_bind_mount(
            &virtiofs_mount.to_string_lossy(),
            container_path,
            *read_only,
        );
    }

    add_workspace_fallback(&mut spec, mounts);
    add_storage_fallback(&mut spec, mounts, unprivileged);

    crate::ssh_agent::inject_into_container(&mut spec);
    crate::publish_socket::inject_into_container(&mut spec);
    crate::forkpoint::inject_into_container(&mut spec);
    crate::cuda::inject_into_container(&mut spec, Path::new(&prepared.rootfs_path));
    crate::vulkan::inject_into_container(&mut spec, Path::new(&prepared.rootfs_path));
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
    prepare_for_run_persistent_with_progress(image, overlay_id, |_, _| {})
}

pub fn prepare_for_run_persistent_with_progress<F>(
    image: &str,
    overlay_id: &str,
    mut progress: F,
) -> Result<PreparedOverlayRootfs>
where
    F: FnMut(&str, u64),
{
    validate_storage_id(overlay_id, "persistent overlay id")?;
    let workload_id = format!("persistent-{}", overlay_id);

    // Resolve image layers (same logic as prepare_overlay). A local image
    // archive is flattened into a rootfs first; a packed-layers dir is used
    // as-is.
    let lowerdirs = if let Some(packed_dir) = get_packed_layers_dir() {
        let effective = effective_packed_dir_with_progress(packed_dir, &mut progress)?;
        get_packed_lowerdirs(&effective)?
    } else {
        get_image_lowerdirs(image)?
    };

    progress("preparing persistent overlay", 0);
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
/// container's own mount list. Boot entries win on target collision because
/// they retain the launch-time positional tag and staged/live mode; a caller
/// rebuilding bindings from an older persisted shape may not have either.
pub fn merged_with_boot_mounts(mounts: &[(String, String, bool)]) -> Vec<(String, String, bool)> {
    let mut v = init_volume_mounts().to_vec();
    for mount in mounts {
        if !v.iter().any(|(_, target, _)| target == &mount.1) {
            v.push(mount.clone());
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
        let (device_tag, staged_id) = split_staged_mount_tag(tag);
        let staged = staged_id.is_some();
        validate_storage_id(device_tag, "mount tag")?;
        if let Some(staged_id) = staged_id {
            validate_storage_id(staged_id, "staged mount identity")?;
        }
        debug!(tag = %device_tag, container_path = %container_path, read_only = %read_only, staged, "setting up volume mount");

        // First, mount the virtiofs device at a staging location
        let virtiofs_mount = Path::new(paths::VIRTIOFS_MOUNT_ROOT).join(device_tag);
        std::fs::create_dir_all(&virtiofs_mount)?;

        // Check if already mounted
        if !is_mountpoint(&virtiofs_mount) {
            info!(tag = %device_tag, mount_point = %virtiofs_mount.display(), "mounting virtiofs");

            let dax = match mount_virtiofs(device_tag, &virtiofs_mount) {
                Ok(dax) => dax,
                Err(err) => {
                    warn!(error = %err, tag = %device_tag, "failed to mount virtiofs device");
                    if staged {
                        return Err(err.into());
                    }
                    continue;
                }
            };
            info!(tag = %device_tag, dax, "virtiofs mount active");
        }

        let bind_source = if staged {
            ensure_staged_working_copy(staged_id.expect("checked staged id"), &virtiofs_mount)?
        } else {
            virtiofs_mount.clone()
        };

        // Now bind-mount into the container rootfs
        let target_path = ensure_mount_target_under_root(rootfs_path, container_path)?;

        // Check if already bind-mounted
        if !is_mountpoint(&target_path) {
            info!(
                source = %bind_source.display(),
                target = %target_path.display(),
                read_only = %read_only,
                "bind-mounting into container"
            );

            // Bind mount using direct syscall
            let bind_src =
                std::ffi::CString::new(bind_source.to_string_lossy().as_ref()).map_err(|e| {
                    StorageError::Internal {
                        message: format!("invalid source: {}", e),
                    }
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
                if staged {
                    return Err(StorageError::new(format!(
                        "failed to bind staged mount '{}' at '{}': {err}",
                        device_tag,
                        target_path.display()
                    )));
                }
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

/// Materialize a host share once into the guest storage disk. The temporary
/// directory and atomic rename mean an interrupted first boot can never leave
/// a partially seeded working tree looking complete on the next start.
#[cfg(target_os = "linux")]
fn ensure_staged_working_copy(tag: &str, source: &Path) -> Result<PathBuf> {
    use std::process::{Command, Stdio};

    validate_storage_id(tag, "staged mount tag")?;
    let root = Path::new(STAGED_MOUNT_ROOT);
    std::fs::create_dir_all(root)?;
    let destination = root.join(tag);
    if destination.exists() {
        return Ok(destination);
    }

    let temporary = root.join(format!(".{tag}.seed-{}", std::process::id()));
    if temporary.exists() {
        std::fs::remove_dir_all(&temporary)?;
    }
    std::fs::create_dir(&temporary)?;

    let mut producer = Command::new("tar")
        .args(["-cf", "-", "-C"])
        .arg(source)
        .arg(".")
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|error| StorageError::new(format!("start staged mount archive: {error}")))?;
    let producer_stdout = producer
        .stdout
        .take()
        .ok_or_else(|| StorageError::new("staged mount archive stdout was not captured"))?;
    let consumer_status = Command::new("tar")
        .args(["-xf", "-", "-C"])
        .arg(&temporary)
        .stdin(Stdio::from(producer_stdout))
        .status()
        .map_err(|error| StorageError::new(format!("extract staged mount archive: {error}")))?;
    let producer_status = producer
        .wait()
        .map_err(|error| StorageError::new(format!("wait for staged mount archive: {error}")))?;
    if !producer_status.success() || !consumer_status.success() {
        let _ = std::fs::remove_dir_all(&temporary);
        return Err(StorageError::new(format!(
            "staged mount seed failed (archive={producer_status}, extract={consumer_status})"
        )));
    }
    std::fs::rename(&temporary, &destination)?;
    Ok(destination)
}

#[cfg(target_os = "linux")]
pub fn prune_staged_working_copies(mounts: &[(String, String, bool)]) -> Result<()> {
    let root = Path::new(STAGED_MOUNT_ROOT);
    if !root.exists() {
        return Ok(());
    }
    let wanted = mounts
        .iter()
        .filter_map(|(tag, _, _)| split_staged_mount_tag(tag).1)
        .collect::<std::collections::HashSet<_>>();
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name();
        if !wanted.contains(name.to_string_lossy().as_ref()) {
            let metadata = entry.metadata()?;
            if metadata.is_dir() {
                std::fs::remove_dir_all(entry.path())?;
            } else {
                std::fs::remove_file(entry.path())?;
            }
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn prune_staged_working_copies(_mounts: &[(String, String, bool)]) -> Result<()> {
    Ok(())
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
/// Establish a long-lived keep-alive main container for a persistent overlay so
/// that this and every subsequent exec joins it via `crun exec` (~ms) instead of
/// launching a fresh container (~seconds). `spec` is the keep-alive OCI spec
/// (PID 1 = `tail -f /dev/null`) already carrying this overlay's rootfs, mounts,
/// and injections; it is written into `bundle_dir`. Returns the new container id,
/// persisted under `persistent-<overlay_id>` so `resolve_main_container` finds it.
///
/// This mirrors `crate::ensure_main_container` (the machine-start / interactive
/// path) for the fork-clone case: a clone's restored keep-alive is reaped as
/// stale on the first exec's remount, and without re-establishing one here every
/// clone exec would one-shot a fresh container.
fn establish_keepalive_container(
    spec: &OciSpec,
    bundle_dir: &Path,
    overlay_id: &str,
) -> Result<String> {
    spec.write_to(bundle_dir)
        .map_err(|e| StorageError::new(format!("failed to write keep-alive OCI spec: {}", e)))?;

    let container_id = generate_container_id();

    let create = CrunCommand::create(bundle_dir, &container_id)
        .output()
        .map_err(|e| StorageError::new(format!("keep-alive crun create failed: {}", e)))?;
    if !create.status.success() {
        return Err(StorageError::new(format!(
            "keep-alive crun create failed: {}",
            crate::crun::create_failure_reason(&container_id, &create)
        )));
    }

    let start = CrunCommand::start(&container_id)
        .output()
        .map_err(|e| StorageError::new(format!("keep-alive crun start failed: {}", e)))?;
    if !start.status.success() {
        let _ = CrunCommand::delete(&container_id, true).output();
        return Err(StorageError::new(format!(
            "keep-alive crun start failed: {}",
            String::from_utf8_lossy(&start.stderr).trim()
        )));
    }

    let workload_id = format!("persistent-{}", overlay_id);
    if let Err(e) = std::fs::write(
        paths::main_container_id_path(&workload_id),
        container_id.as_bytes(),
    ) {
        let _ = CrunCommand::kill(&container_id, "SIGKILL").status();
        let _ = CrunCommand::delete(&container_id, true).output();
        return Err(StorageError::new(format!(
            "failed to persist keep-alive container id: {}",
            e
        )));
    }

    info!(container_id = %container_id, overlay_id = %overlay_id, "established keep-alive main container for clone exec");
    Ok(container_id)
}

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

    let exec_pid_file = crate::crun::ExecPidFile::new()
        .map_err(|e| StorageError::new(format!("create crun exec pid file failed: {}", e)))?;
    let mut child = CrunCommand::exec(container_id, env, command, workdir, false)
        .pid_file(exec_pid_file.path())
        .stdin_null()
        .capture_output()
        .spawn()
        .map_err(|e| StorageError::new(format!("crun exec failed: {}", e)))?;

    // On timeout/disconnect, kill only the exec'd process — NOT the main
    // container. The main container hosts the shared namespace for all execs;
    // a timed-out `exec -- sleep 10` must not destroy the workload.
    let result = crate::process::wait_with_timeout_cleanup_and_liveness(
        &mut child,
        timeout_ms,
        client_fd,
        || {
            exec_pid_file.kill_workload();
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

/// Merge `lowerdirs` into `output` as a single tar archive.
///
/// Backs [`AgentRequest::FlattenLayers`](smolvm_protocol::AgentRequest::FlattenLayers).
/// The merge is a read-only overlay mount so that whiteouts and opaque markers
/// resolve exactly as they do for a running container — a file copy would ship
/// deleted paths back into the flattened layer.
///
/// `lowerdirs` is **topmost first**, the same order the runtime container mount
/// uses, because that is the order `lowerdir+` stacks them in. Passing an image's
/// layers bottom-up instead silently inverts precedence: the base layer wins
/// every conflicting path, so a merged `/etc/passwd` loses the users later layers
/// added and the machine's own writes rank lowest of all.
///
/// Entries that are missing or empty are dropped: callers pass a container
/// overlay's upper dir without knowing whether the machine ever wrote to it, and
/// overlayfs rejects a lowerdir that does not exist. A single surviving directory
/// is tarred directly, since overlayfs requires two lower layers when there is no
/// upperdir.
pub fn flatten_layers_to_tar(lowerdirs: &[String], output: &Path) -> Result<()> {
    let present = mountable_lowerdirs(lowerdirs);

    let source = match present.len() {
        0 => {
            return Err(StorageError::new(
                "no layers to flatten: every directory was missing or empty".to_string(),
            ))
        }
        // One layer needs no merge, and overlayfs would refuse it anyway.
        1 => PathBuf::from(&present[0]),
        _ => {
            let merged = Path::new(STORAGE_ROOT).join("flatten-merged");
            let _ = std::fs::remove_dir_all(&merged);
            std::fs::create_dir_all(&merged)?;
            mount_overlay_lowers_only(&present, &merged)?;
            merged
        }
    };

    let tar_result = tar_directory(&source, output);

    if source != Path::new(&present[0]) {
        // Best-effort: a failed unmount must not mask a tar error.
        let _ = std::process::Command::new("umount").arg(&source).status();
        let _ = std::fs::remove_dir_all(&source);
    }

    tar_result
}

/// Keep the entries of `lowerdirs` that overlayfs can actually stack.
///
/// overlayfs fails the whole mount on a lowerdir that does not exist, and an
/// empty directory contributes nothing to the merge, so dropping both lets a
/// caller pass a container overlay's upper dir unconditionally.
fn mountable_lowerdirs(lowerdirs: &[String]) -> Vec<String> {
    lowerdirs
        .iter()
        .filter(|dir| {
            let path = Path::new(dir);
            path.is_dir()
                && std::fs::read_dir(path)
                    .map(|mut entries| entries.next().is_some())
                    .unwrap_or(false)
        })
        .cloned()
        .collect()
}

/// Tar `dir`'s contents (not the directory itself) into `output`.
fn tar_directory(dir: &Path, output: &Path) -> Result<()> {
    let status = std::process::Command::new("tar")
        .arg("cf")
        .arg(output)
        .arg("-C")
        .arg(dir)
        .arg(".")
        .status()
        .map_err(|e| StorageError::new(format!("spawning tar failed: {e}")))?;
    if !status.success() {
        return Err(StorageError::new(format!(
            "tar of {} failed: {status}",
            dir.display()
        )));
    }
    Ok(())
}

/// Mount a read-only overlay of `lowerdirs` (topmost first) at `merged_path`.
///
/// Same `fsconfig` path as [`mount_overlay_fsconfig`] but with no upperdir or
/// workdir, which is what makes the mount read-only. Appending each layer with
/// its own `lowerdir+` is the whole point: a single `lowerdir=` string caps out
/// at ~255 bytes through `mount(8)`, which is only about three layer paths.
#[cfg(target_os = "linux")]
fn mount_overlay_lowers_only(lowerdirs: &[String], merged_path: &Path) -> Result<()> {
    use rustix::fd::AsFd;
    use rustix::mount::{
        fsconfig_create, fsconfig_set_string, fsmount, fsopen, move_mount, FsMountFlags,
        FsOpenFlags, MountAttrFlags, MoveMountFlags,
    };

    info!(
        layer_count = lowerdirs.len(),
        merged_path = %merged_path.display(),
        "mounting read-only overlay for flatten"
    );

    let fs = fsopen("overlay", FsOpenFlags::FSOPEN_CLOEXEC)
        .map_err(|e| StorageError::new(format!("fsopen(overlay) failed: {e}")))?;

    // Each `lowerdir+` ranks below the one before it, so the caller's
    // topmost-first order is passed straight through.
    for lower in lowerdirs {
        fsconfig_set_string(fs.as_fd(), "lowerdir+", lower.as_str()).map_err(|e| {
            StorageError::new(format!(
                "fsconfig lowerdir+={lower} failed (kernel may lack lowerdir+ (<6.7)): {e}"
            ))
        })?;
    }

    fsconfig_create(fs.as_fd())
        .map_err(|e| StorageError::new(format!("fsconfig create (overlay) failed: {e}")))?;

    let mnt = fsmount(
        fs.as_fd(),
        FsMountFlags::FSMOUNT_CLOEXEC,
        MountAttrFlags::empty(),
    )
    .map_err(|e| StorageError::new(format!("fsmount(overlay) failed: {e}")))?;

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

/// Non-Linux stub: overlayfs is Linux-only.
#[cfg(not(target_os = "linux"))]
fn mount_overlay_lowers_only(_lowerdirs: &[String], _merged_path: &Path) -> Result<()> {
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

            Ok((total, used))
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

/// Count only the directory entries in a directory.
fn count_dir_entries(path: &Path) -> Result<usize> {
    if !path.exists() {
        return Ok(0);
    }

    Ok(std::fs::read_dir(path)?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .count())
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
    /// One empty layer is a legal OCI layer (metadata or whiteouts only), so
    /// verification must not reject an image just for containing one.
    #[test]
    fn a_single_empty_layer_beside_a_populated_one_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty");
        let full = dir.path().join("full");
        std::fs::create_dir_all(&empty).unwrap();
        std::fs::create_dir_all(full.join("usr")).unwrap();
        let layers = vec![
            empty.to_string_lossy().into_owned(),
            full.to_string_lossy().into_owned(),
        ];
        assert!(verify_layers(&layers).is_ok());
    }

    /// Every layer empty means the container would run on its upper layer
    /// alone. That used to be accepted with only a warning, and surfaced much
    /// later as a misleading "executable file not found in $PATH".
    #[test]
    fn layers_that_are_all_empty_are_rejected_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let layers = vec![
            a.to_string_lossy().into_owned(),
            b.to_string_lossy().into_owned(),
        ];
        let err = verify_layers(&layers).expect_err("all-empty layers must not be accepted");
        assert!(
            err.to_string().contains("image layers are missing"),
            "error should name the real problem, got: {err}"
        );
    }

    /// The failure this pair of fixes came from: an emptied macOS layer store
    /// still has `.fseventsd`, which was enumerated as the image's only layer,
    /// so the container came up on a rootfs made of filesystem bookkeeping.
    #[test]
    fn volume_metadata_is_never_enumerated_as_an_image_layer() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".fseventsd")).unwrap();
        std::fs::create_dir_all(dir.path().join(".Spotlight-V100")).unwrap();
        let err = ordered_packed_layer_names(dir.path())
            .expect_err("bookkeeping directories are not layers");
        assert!(err.to_string().contains("no image layers"), "got: {err}");
    }

    /// A store with no usable layer directory cannot produce the image, so it
    /// must fail by name rather than hand back an empty layer list.
    #[test]
    fn a_store_with_no_usable_layer_directory_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".fseventsd")).unwrap();
        std::fs::write(dir.path().join(LAYER_ORDER_FILE), "aaaa1111bbbb\n").unwrap();
        let err = ordered_packed_layer_names(dir.path())
            .expect_err("a store holding no layer must not resolve");
        assert!(err.to_string().contains("no image layers"), "got: {err}");
    }

    /// The fallback still works for a legacy store that has no index at all.
    #[test]
    fn a_store_without_an_order_index_still_sorts_by_name() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("bbbb")).unwrap();
        std::fs::create_dir_all(dir.path().join("aaaa")).unwrap();
        let names = ordered_packed_layer_names(dir.path()).unwrap();
        assert_eq!(names, vec!["aaaa".to_string(), "bbbb".to_string()]);
    }

    /// The exact shape that got through: a layer store that is an emptied
    /// macOS volume still carries `.fseventsd`, which counted as content and
    /// let a container start on an image with no filesystem.
    #[test]
    fn a_layer_holding_only_volume_metadata_counts_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("layers-cs");
        std::fs::create_dir_all(store.join(".fseventsd")).unwrap();
        std::fs::write(store.join(".DS_Store"), b"").unwrap();
        let layers = vec![store.to_string_lossy().into_owned()];
        let err = verify_layers(&layers).expect_err("volume metadata is not image content");
        assert!(
            err.to_string().contains("image layers are missing"),
            "got: {err}"
        );
    }

    /// A missing layer directory is still reported as such, not folded into
    /// the all-empty case.
    #[test]
    fn a_missing_layer_path_is_reported_as_missing() {
        let dir = tempfile::tempdir().unwrap();
        let gone = dir.path().join("gone");
        let layers = vec![gone.to_string_lossy().into_owned()];
        let err = verify_layers(&layers).expect_err("a missing layer must not be accepted");
        assert!(err.to_string().contains("does not exist"), "got: {err}");
    }

    use super::*;
    // OCI layer helpers now live in the shared crate; these tests exercise them
    // through its public API (the crate also unit-tests them independently).
    use smolvm_oci_layer::{classify_layer_entry, jailed_join, LayerEntry};
    use std::sync::{Mutex, OnceLock};

    /// The /workspace fallback is bound on top of the user's mounts, so it must
    /// stand down for anything at or below /workspace — not only an exact
    /// `-v host:/workspace`. A user mount at /workspace/project that keeps the
    /// fallback ends up shadowed by its own parent: still listed in
    /// /proc/self/mountinfo, but unreachable by path.
    ///
    /// The sibling /workspaces/project is the trap: it shares the string prefix
    /// but is not under /workspace, and must still get the fallback.
    #[test]
    fn a_user_mount_below_workspace_suppresses_the_fallback() {
        let fallback_src = std::path::Path::new("/storage/workspace");
        let user_source = "/host/source".to_string();

        // (user mount target, mount destinations expected in the spec afterwards)
        let cases: &[(&str, &[&str])] = &[
            // At /workspace: fallback suppressed, only the user's mount.
            ("/workspace", &["/workspace"]),
            // Below /workspace: fallback suppressed — the bug this guards.
            ("/workspace/project", &["/workspace/project"]),
            // Trailing slash is the same claim.
            ("/workspace/project/", &["/workspace/project/"]),
            // Sibling that merely shares the prefix: fallback still applies.
            (
                "/workspaces/project",
                &["/workspaces/project", "/workspace"],
            ),
            // Unrelated targets: fallback still applies.
            ("/mnt/project", &["/mnt/project", "/workspace"]),
            (
                "/opt/workspace/project",
                &["/opt/workspace/project", "/workspace"],
            ),
        ];

        for (target, expected) in cases {
            let mut spec = OciSpec::new(
                &[],
                &[],
                "/",
                false,
                &crate::oci::ProcessIdentity::root(),
                false,
            );
            spec.mounts.clear();
            let mounts = vec![(user_source.clone(), (*target).to_string(), false)];
            for (source, destination, read_only) in &mounts {
                spec.add_bind_mount(source, destination, *read_only);
            }

            add_workspace_fallback_from(&mut spec, &mounts, fallback_src);

            let got: Vec<&str> = spec.mounts.iter().map(|m| m.destination.as_str()).collect();
            assert_eq!(
                got, *expected,
                "user mount at {target} produced the wrong mount set"
            );
        }
    }

    /// With no user mount in play the fallback must still be added, otherwise
    /// /workspace stops surviving VM restarts.
    #[test]
    fn no_user_mount_still_gets_the_workspace_fallback() {
        let mut spec = OciSpec::new(
            &[],
            &[],
            "/",
            false,
            &crate::oci::ProcessIdentity::root(),
            false,
        );
        spec.mounts.clear();
        add_workspace_fallback_from(&mut spec, &[], std::path::Path::new("/storage/workspace"));
        let got: Vec<&str> = spec.mounts.iter().map(|m| m.destination.as_str()).collect();
        assert_eq!(got, vec!["/workspace"]);
    }

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    /// A machine that has never written to its container overlay still has the
    /// caller append that upper dir, and overlayfs fails the whole mount on a
    /// lowerdir that is not there — so it has to be dropped, not passed through.
    #[test]
    fn flatten_drops_lowerdirs_that_are_missing_or_empty() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let populated = tmp.path().join("layer");
        std::fs::create_dir_all(&populated).expect("create layer");
        std::fs::write(populated.join("file"), b"x").expect("write file");
        let empty = tmp.path().join("empty-upper");
        std::fs::create_dir_all(&empty).expect("create empty");
        let missing = tmp.path().join("never-created");

        let kept = mountable_lowerdirs(&[
            populated.to_string_lossy().into_owned(),
            empty.to_string_lossy().into_owned(),
            missing.to_string_lossy().into_owned(),
        ]);

        assert_eq!(
            kept,
            vec![populated.to_string_lossy().into_owned()],
            "only the populated directory is mountable"
        );
    }

    /// Order is the whole contract — `lowerdir+` ranks each layer below the one
    /// before it, so the caller's topmost-first list must survive filtering
    /// unreordered. Passing it bottom-up instead inverts precedence silently:
    /// the base layer wins every conflicting path and the machine's own writes
    /// rank lowest, which reads as an image that lost its later layers.
    #[test]
    fn flatten_preserves_topmost_first_order() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dirs: Vec<String> = ["upper", "top-layer", "base"]
            .iter()
            .map(|name| {
                let dir = tmp.path().join(name);
                std::fs::create_dir_all(&dir).expect("create dir");
                std::fs::write(dir.join("f"), name.as_bytes()).expect("write");
                dir.to_string_lossy().into_owned()
            })
            .collect();

        assert_eq!(mountable_lowerdirs(&dirs), dirs);
    }

    /// Dropping an empty entry must not disturb the rank of the ones that stay:
    /// a machine that never wrote anything still has its (empty) overlay passed
    /// first, and removing it has to leave the image layers in their own order.
    #[test]
    fn flatten_keeps_rank_when_an_entry_is_dropped() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let make = |name: &str, populated: bool| {
            let dir = tmp.path().join(name);
            std::fs::create_dir_all(&dir).expect("create dir");
            if populated {
                std::fs::write(dir.join("f"), name.as_bytes()).expect("write");
            }
            dir.to_string_lossy().into_owned()
        };
        let empty_upper = make("empty-upper", false);
        let top = make("top-layer", true);
        let base = make("base", true);

        assert_eq!(
            mountable_lowerdirs(&[empty_upper, top.clone(), base.clone()]),
            vec![top, base]
        );
    }

    #[test]
    fn copy_with_progress_reports_bytes_while_streaming() {
        let input = vec![0x5a; 17 * 1024 * 1024];
        let mut reader = std::io::Cursor::new(&input);
        let mut output = Vec::new();
        let mut reports = Vec::new();

        let copied = copy_with_progress(
            &mut reader,
            &mut output,
            "flattening",
            &mut |phase, bytes| reports.push((phase.to_string(), bytes)),
        )
        .unwrap();

        assert_eq!(copied, input.len() as u64);
        assert_eq!(output, input);
        assert_eq!(reports.first(), Some(&("flattening".to_string(), 0)));
        assert_eq!(
            reports.last(),
            Some(&("flattening".to_string(), input.len() as u64))
        );
        assert!(
            reports.iter().any(|(_, bytes)| *bytes >= 16 * 1024 * 1024),
            "large copies must report before completion"
        );
    }

    #[test]
    fn spawned_copy_reports_archive_input_progress() {
        let input = std::io::Cursor::new(vec![0x5a; 17 * 1024 * 1024]);
        let (copy_thread, progress_rx) =
            spawn_copy_with_progress(input, std::io::sink(), "reading archive");
        let reports: Vec<_> = progress_rx.iter().collect();
        let copied = copy_thread.join().unwrap().unwrap();

        assert_eq!(copied, 17 * 1024 * 1024);
        assert_eq!(reports.first(), Some(&("reading archive", 0)));
        assert_eq!(reports.last(), Some(&("reading archive", 17 * 1024 * 1024)));
        assert!(
            reports.iter().any(|(_, bytes)| *bytes >= 16 * 1024 * 1024),
            "large archive inputs must report before completion"
        );
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
    fn archive_scratch_dir_honors_env_override() {
        let _guard = env_lock().lock().unwrap();
        let base = tempfile::tempdir().unwrap();
        // A dir that doesn't exist yet, to prove it's created on demand.
        let target = base.path().join("scratch");
        std::env::set_var(ARCHIVE_SCRATCH_DIR_ENV, &target);

        assert_eq!(archive_scratch_dir(), target);
        assert!(target.is_dir(), "override dir should be created");

        std::env::remove_var(ARCHIVE_SCRATCH_DIR_ENV);
    }

    #[test]
    fn archive_scratch_dir_ignores_blank_override() {
        // A blank/whitespace override is treated as unset, not as "use CWD".
        let _guard = env_lock().lock().unwrap();
        std::env::set_var(ARCHIVE_SCRATCH_DIR_ENV, "   ");

        // Without a storage disk on the host, this falls through to the OS temp
        // dir — never the override, never an empty path.
        let dir = archive_scratch_dir();
        assert!(dir.is_absolute() && dir.is_dir());
        assert_ne!(dir.as_os_str(), "   ");

        std::env::remove_var(ARCHIVE_SCRATCH_DIR_ENV);
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
    fn overlay_hosts_names_loopback_and_the_guest_hostname() {
        assert_eq!(
            overlay_hosts_contents("container"),
            "127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n127.0.1.1\tcontainer\n"
        );
        // No hostname (or a redundant one) still yields valid loopback entries.
        for h in ["", "localhost"] {
            assert_eq!(
                overlay_hosts_contents(h),
                "127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n"
            );
        }
    }

    #[test]
    fn setup_upper_layer_defaults_hosts_only_when_image_lacks_it() {
        let tmp = tempfile::tempdir().unwrap();
        let builder = |name: &str| OverlaySetup {
            workload_id: format!("hosts-test-{name}"),
            overlay_root: tmp.path().join(name),
            upper_path: tmp.path().join(name).join("upper"),
            work_path: tmp.path().join(name).join("work"),
            merged_path: tmp.path().join(name).join("merged"),
        };

        // Image without /etc/hosts: the upper layer gains a default.
        let bare_layer = tmp.path().join("layer-bare");
        std::fs::create_dir_all(&bare_layer).unwrap();
        let b = builder("bare");
        b.prepare_directories().unwrap();
        b.setup_upper_layer(&[bare_layer.display().to_string()])
            .unwrap();
        let written = std::fs::read_to_string(b.upper_path.join("etc/hosts")).unwrap();
        assert!(written.contains("127.0.0.1\tlocalhost"));

        // Image that ships /etc/hosts: the upper layer must not shadow it.
        let full_layer = tmp.path().join("layer-full");
        std::fs::create_dir_all(full_layer.join("etc")).unwrap();
        std::fs::write(full_layer.join("etc/hosts"), "10.0.0.9 pinned\n").unwrap();
        let b = builder("full");
        b.prepare_directories().unwrap();
        b.setup_upper_layer(&[full_layer.display().to_string()])
            .unwrap();
        assert!(!b.upper_path.join("etc/hosts").exists());

        // An EMPTY image /etc/hosts provides no mappings, so the default must
        // still be written — otherwise `localhost` never resolves in-container.
        let empty_layer = tmp.path().join("layer-empty");
        std::fs::create_dir_all(empty_layer.join("etc")).unwrap();
        std::fs::write(empty_layer.join("etc/hosts"), "").unwrap();
        let b = builder("empty");
        b.prepare_directories().unwrap();
        b.setup_upper_layer(&[empty_layer.display().to_string()])
            .unwrap();
        let written = std::fs::read_to_string(b.upper_path.join("etc/hosts")).unwrap();
        assert!(written.contains("127.0.0.1\tlocalhost"));

        // Same for a comments-only file (Debian tooling ships these).
        let comment_layer = tmp.path().join("layer-comments");
        std::fs::create_dir_all(comment_layer.join("etc")).unwrap();
        std::fs::write(comment_layer.join("etc/hosts"), "# static hosts\n\n").unwrap();
        let b = builder("comments");
        b.prepare_directories().unwrap();
        b.setup_upper_layer(&[comment_layer.display().to_string()])
            .unwrap();
        let written = std::fs::read_to_string(b.upper_path.join("etc/hosts")).unwrap();
        assert!(written.contains("127.0.0.1\tlocalhost"));
    }

    #[test]
    fn layer_cache_trusts_only_marked_layers() {
        let tmp = tempfile::tempdir().unwrap();
        let layer = tmp.path().join("aabbccdd");

        // Missing entirely: not cached.
        assert!(!is_layer_cached(&layer));

        // Non-empty but unverified — the exact state an interrupted or
        // writeback-failed extraction leaves behind. Must NOT be trusted.
        std::fs::create_dir_all(layer.join("bin")).unwrap();
        assert!(!is_layer_cached(&layer));

        // Marker present: cached.
        std::fs::write(layer_ok_marker(&layer), "ok").unwrap();
        assert!(is_layer_cached(&layer));
        // The marker is a sibling of the layer dir, never inside it (layer
        // dirs are overlay lowerdirs).
        assert!(layer_ok_marker(&layer).parent() == layer.parent());

        // Empty directories are valid OCI layers once extraction is verified.
        std::fs::remove_dir_all(layer.join("bin")).unwrap();
        assert!(is_layer_cached(&layer));

        // The marker alone is insufficient if the layer directory disappeared.
        std::fs::remove_dir(&layer).unwrap();
        assert!(!is_layer_cached(&layer));
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
    fn file_mount_target_creates_parent_and_regular_file() {
        let root = tempfile::tempdir().unwrap();
        let rootfs = root.path().join("rootfs");
        std::fs::create_dir_all(&rootfs).unwrap();

        let target = ensure_file_mount_target_under_root(&rootfs, "/run/smolvm/init").unwrap();
        assert!(target.is_file());
        assert!(target.starts_with(rootfs.canonicalize().unwrap()));
    }

    #[cfg(unix)]
    #[test]
    fn file_mount_target_replaces_final_symlink_without_touching_target() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        let rootfs = root.path().join("rootfs");
        let destination_parent = rootfs.join("run/smolvm");
        std::fs::create_dir_all(&destination_parent).unwrap();
        let destination = destination_parent.join("init");
        symlink(outside.path(), &destination).unwrap();

        let target = ensure_file_mount_target_under_root(&rootfs, "/run/smolvm/init").unwrap();
        assert!(target.is_file());
        assert!(!target.is_symlink());
        assert!(outside.path().is_file());
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
