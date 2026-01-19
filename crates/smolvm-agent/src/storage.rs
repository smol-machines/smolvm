//! Storage management for the helper daemon.
//!
//! This module handles:
//! - Storage disk initialization and formatting
//! - OCI image pulling via crane
//! - Layer extraction and deduplication
//! - Overlay filesystem management
//! - Container execution via crun OCI runtime

use crate::oci::{generate_container_id, OciSpec};
use smolvm_protocol::{ImageInfo, OverlayInfo, StorageStatus};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tracing::{debug, info, warn};

/// Path to crun binary (static build on Alpine).
const CRUN_PATH: &str = "/usr/bin/crun";

/// Storage root path (where the ext4 disk is mounted).
const STORAGE_ROOT: &str = "/storage";

/// Directory structure within storage.
const LAYERS_DIR: &str = "layers";
const CONFIGS_DIR: &str = "configs";
const MANIFESTS_DIR: &str = "manifests";
const OVERLAYS_DIR: &str = "overlays";

/// Error type for storage operations.
#[derive(Debug)]
pub struct StorageError(pub(crate) String);

impl StorageError {
    /// Create a new storage error with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        StorageError(message.into())
    }
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for StorageError {}

impl From<std::io::Error> for StorageError {
    fn from(e: std::io::Error) -> Self {
        StorageError(e.to_string())
    }
}

type Result<T> = std::result::Result<T, StorageError>;

/// Initialize storage directories.
pub fn init() -> Result<()> {
    let root = Path::new(STORAGE_ROOT);

    // Check if storage is mounted
    if !root.exists() {
        // Create mount point
        std::fs::create_dir_all(root)?;
    }

    // Check for marker file to see if formatted
    let marker = root.join(".smolvm_formatted");
    if !marker.exists() {
        info!("storage not formatted, waiting for format request");
        return Ok(());
    }

    // Create directory structure
    for dir in &[LAYERS_DIR, CONFIGS_DIR, MANIFESTS_DIR, OVERLAYS_DIR] {
        let path = root.join(dir);
        if !path.exists() {
            std::fs::create_dir_all(&path)?;
            debug!(path = %path.display(), "created directory");
        }
    }

    info!("storage initialized");
    Ok(())
}

/// Format the storage disk.
pub fn format() -> Result<()> {
    let root = Path::new(STORAGE_ROOT);

    // Create directory structure
    for dir in &[LAYERS_DIR, CONFIGS_DIR, MANIFESTS_DIR, OVERLAYS_DIR] {
        let path = root.join(dir);
        std::fs::create_dir_all(&path)?;
    }

    // Create marker file
    let marker = root.join(".smolvm_formatted");
    std::fs::write(&marker, "1")?;

    info!("storage formatted");
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

/// Pull an OCI image using crane.
pub fn pull_image(image: &str, platform: Option<&str>) -> Result<ImageInfo> {
    // Check if already cached - skip network call entirely
    if let Ok(Some(info)) = query_image(image) {
        debug!(image = %image, "image already cached, skipping pull");
        return Ok(info);
    }

    let root = Path::new(STORAGE_ROOT);

    // Determine platform - default to current architecture
    let platform = platform.or_else(|| {
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

    // Get manifest with platform specified
    info!(image = %image, platform = ?platform, "fetching manifest");
    let manifest = crane_manifest(image, platform)?;

    // Parse manifest to get config and layers
    let manifest_json: serde_json::Value =
        serde_json::from_str(&manifest).map_err(|e| StorageError(e.to_string()))?;

    // Handle manifest list (multi-arch) - this shouldn't happen with --platform but just in case
    let config_digest = if manifest_json.get("config").is_some() {
        manifest_json["config"]["digest"]
            .as_str()
            .ok_or_else(|| StorageError("missing config digest".into()))?
    } else if manifest_json.get("manifests").is_some() {
        // This is a manifest list, need to fetch platform-specific manifest
        return Err(StorageError(format!(
            "got manifest list instead of image manifest - platform may not be available. \
             manifests: {:?}",
            manifest_json["manifests"].as_array().map(|arr| arr
                .iter()
                .filter_map(|m| m["platform"]["architecture"].as_str())
                .collect::<Vec<_>>())
        )));
    } else {
        return Err(StorageError("unknown manifest format".into()));
    };

    let layers: Vec<String> = manifest_json["layers"]
        .as_array()
        .ok_or_else(|| StorageError("missing layers".into()))?
        .iter()
        .filter_map(|l| l["digest"].as_str().map(String::from))
        .collect();

    // Save manifest
    let manifest_path = root
        .join(MANIFESTS_DIR)
        .join(sanitize_image_name(image) + ".json");
    std::fs::write(&manifest_path, &manifest)?;

    // Fetch and save config
    let config = crane_config(image, platform)?;
    let config_id = config_digest
        .strip_prefix("sha256:")
        .unwrap_or(config_digest);
    let config_path = root.join(CONFIGS_DIR).join(format!("{}.json", config_id));
    std::fs::write(&config_path, &config)?;

    // Parse config for metadata
    let config_json: serde_json::Value =
        serde_json::from_str(&config).map_err(|e| StorageError(e.to_string()))?;

    // Extract layers
    let mut total_size = 0u64;
    for (i, layer_digest) in layers.iter().enumerate() {
        let layer_id = layer_digest.strip_prefix("sha256:").unwrap_or(layer_digest);
        let layer_dir = root.join(LAYERS_DIR).join(layer_id);

        if layer_dir.exists() {
            info!(layer = %layer_id, "layer already cached");
            continue;
        }

        info!(
            layer = %layer_id,
            progress = format!("{}/{}", i + 1, layers.len()),
            "extracting layer"
        );

        std::fs::create_dir_all(&layer_dir)?;

        // Stream layer directly to tar extraction
        let status = Command::new("sh")
            .arg("-c")
            .arg(format!(
                "crane blob '{}@{}' {} | tar -xzf - -C '{}'",
                image,
                layer_digest,
                platform
                    .map(|p| format!("--platform={}", p))
                    .unwrap_or_default(),
                layer_dir.display()
            ))
            .status()?;

        if !status.success() {
            // Clean up failed layer
            let _ = std::fs::remove_dir_all(&layer_dir);
            return Err(StorageError(format!(
                "failed to extract layer {}",
                layer_digest
            )));
        }

        // Get layer size
        if let Ok(size) = dir_size(&layer_dir) {
            total_size += size;
        }
    }

    // Build ImageInfo
    let architecture = config_json["architecture"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    let os = config_json["os"].as_str().unwrap_or("linux").to_string();
    let created = config_json["created"].as_str().map(String::from);

    Ok(ImageInfo {
        reference: image.to_string(),
        digest: config_digest.to_string(),
        size: total_size,
        created,
        architecture,
        os,
        layer_count: layers.len(),
        layers,
    })
}

/// Query if an image exists locally.
pub fn query_image(image: &str) -> Result<Option<ImageInfo>> {
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
        serde_json::from_str(&manifest).map_err(|e| StorageError(e.to_string()))?;

    let config_digest = manifest_json["config"]["digest"]
        .as_str()
        .ok_or_else(|| StorageError("missing config digest".into()))?;

    let layers: Vec<String> = manifest_json["layers"]
        .as_array()
        .ok_or_else(|| StorageError("missing layers".into()))?
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
        serde_json::from_str(&config).map_err(|e| StorageError(e.to_string()))?;

    let architecture = config_json["architecture"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    let os = config_json["os"].as_str().unwrap_or("linux").to_string();
    let created = config_json["created"].as_str().map(String::from);

    // Calculate total size
    let mut total_size = 0u64;
    for layer_digest in &layers {
        let layer_id = layer_digest.strip_prefix("sha256:").unwrap_or(layer_digest);
        let layer_dir = root.join(LAYERS_DIR).join(layer_id);
        if let Ok(size) = dir_size(&layer_dir) {
            total_size += size;
        }
    }

    Ok(Some(ImageInfo {
        reference: image.to_string(),
        digest: config_digest.to_string(),
        size: total_size,
        created,
        architecture,
        os,
        layer_count: layers.len(),
        layers,
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
        let entry = entry?;
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

/// Prepare an overlay filesystem for a workload.
pub fn prepare_overlay(image: &str, workload_id: &str) -> Result<OverlayInfo> {
    let root = Path::new(STORAGE_ROOT);

    // Ensure image exists
    let info =
        query_image(image)?.ok_or_else(|| StorageError(format!("image not found: {}", image)))?;

    // Create overlay directories
    let overlay_root = root.join(OVERLAYS_DIR).join(workload_id);
    let upper_path = overlay_root.join("upper");
    let work_path = overlay_root.join("work");
    let merged_path = overlay_root.join("merged");

    std::fs::create_dir_all(&upper_path)?;
    std::fs::create_dir_all(&work_path)?;
    std::fs::create_dir_all(&merged_path)?;

    // Set up DNS resolution BEFORE mounting (TSI intercepts writes to mounted overlays)
    let upper_etc = upper_path.join("etc");
    std::fs::create_dir_all(&upper_etc)?;
    let resolv_path = upper_etc.join("resolv.conf");
    if let Err(e) = std::fs::write(&resolv_path, "nameserver 8.8.8.8\nnameserver 1.1.1.1\n") {
        warn!(error = %e, "failed to write resolv.conf to upper layer");
    }

    // Create /dev directory in upper layer - we'll bind mount the real /dev later
    let upper_dev = upper_path.join("dev");
    std::fs::create_dir_all(&upper_dev)?;

    // Build lowerdir from layers (in order)
    let lowerdirs: Vec<String> = info
        .layers
        .iter()
        .rev() // Reverse for overlay order (top layer first)
        .map(|digest| {
            let id = digest.strip_prefix("sha256:").unwrap_or(digest);
            root.join(LAYERS_DIR).join(id).display().to_string()
        })
        .collect();

    let lowerdir = lowerdirs.join(":");

    // Mount overlay
    let mount_opts = format!(
        "lowerdir={},upperdir={},workdir={}",
        lowerdir,
        upper_path.display(),
        work_path.display()
    );

    let status = Command::new("mount")
        .args(["-t", "overlay", "overlay", "-o", &mount_opts])
        .arg(&merged_path)
        .status()?;

    if !status.success() {
        return Err(StorageError("failed to mount overlay".into()));
    }

    info!(workload_id = %workload_id, "overlay mounted");

    // Create OCI bundle directory structure
    // crun will use this bundle to run containers
    let bundle_path = overlay_root.join("bundle");
    std::fs::create_dir_all(&bundle_path)?;

    // Create symlink: bundle/rootfs -> ../merged
    let rootfs_link = bundle_path.join("rootfs");
    if !rootfs_link.exists() {
        std::os::unix::fs::symlink("../merged", &rootfs_link)
            .map_err(|e| StorageError(format!("failed to create rootfs symlink: {}", e)))?;
    }

    debug!(bundle = %bundle_path.display(), "OCI bundle directory created");

    Ok(OverlayInfo {
        rootfs_path: merged_path.display().to_string(),
        upper_path: upper_path.display().to_string(),
        work_path: work_path.display().to_string(),
    })
}

/// Clean up an overlay filesystem.
pub fn cleanup_overlay(workload_id: &str) -> Result<()> {
    let root = Path::new(STORAGE_ROOT);
    let overlay_root = root.join(OVERLAYS_DIR).join(workload_id);
    let merged_path = overlay_root.join("merged");

    // Unmount if mounted
    if merged_path.exists() {
        let _ = Command::new("umount").arg(&merged_path).status();
    }

    // Remove overlay directories
    if overlay_root.exists() {
        std::fs::remove_dir_all(&overlay_root)?;
    }

    info!(workload_id = %workload_id, "overlay cleaned up");
    Ok(())
}

/// Result of running a command.
pub struct RunResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Run a command in an image's overlay rootfs using crun OCI runtime.
/// Uses a persistent overlay per image for fast repeated execution.
pub fn run_command(
    image: &str,
    command: &[String],
    env: &[(String, String)],
    workdir: Option<&str>,
    mounts: &[(String, String, bool)],
    timeout_ms: Option<u64>,
) -> Result<RunResult> {
    // Use consistent workload ID per image for overlay reuse
    let workload_id = format!("persistent-{}", sanitize_image_name(image));

    // Check if overlay is already mounted
    let overlay = get_or_create_overlay(image, &workload_id)?;
    debug!(rootfs = %overlay.rootfs_path, "using overlay for command execution");

    // Setup volume mounts (mount virtiofs to staging area)
    let mounted_paths = setup_volume_mounts(&overlay.rootfs_path, mounts)?;

    // Get bundle path
    let overlay_root = Path::new(STORAGE_ROOT)
        .join(OVERLAYS_DIR)
        .join(&workload_id);
    let bundle_path = overlay_root.join("bundle");

    // Create OCI spec
    let workdir_str = workdir.unwrap_or("/");
    let mut spec = OciSpec::new(command, env, workdir_str, false);

    // Add virtiofs bind mounts to OCI spec
    for (tag, container_path, read_only) in mounts {
        let virtiofs_mount = Path::new(VIRTIOFS_MOUNT_ROOT).join(tag);
        spec.add_bind_mount(
            &virtiofs_mount.to_string_lossy(),
            container_path,
            *read_only,
        );
    }

    // Write config.json to bundle
    spec.write_to(&bundle_path)
        .map_err(|e| StorageError(format!("failed to write OCI spec: {}", e)))?;

    // Generate unique container ID for this execution
    let container_id = generate_container_id();

    // Run with crun
    let result = run_with_crun(&bundle_path, &container_id, timeout_ms);

    // Note: virtiofs mounts are left in place for reuse
    // They will be cleaned up when the overlay is cleaned up or the VM shuts down
    let _ = mounted_paths; // Suppress unused warning

    result
}

/// Prepare for running a command - returns the rootfs path.
/// This is used by interactive mode which spawns the command separately.
pub fn prepare_for_run(image: &str) -> Result<String> {
    // Use consistent workload ID per image for overlay reuse
    let workload_id = format!("persistent-{}", sanitize_image_name(image));

    // Check if overlay is already mounted
    let overlay = get_or_create_overlay(image, &workload_id)?;
    debug!(rootfs = %overlay.rootfs_path, "prepared overlay for interactive run");

    Ok(overlay.rootfs_path)
}

/// Setup volume mounts for a rootfs (public wrapper).
pub fn setup_mounts(rootfs: &str, mounts: &[(String, String, bool)]) -> Result<()> {
    let _mounted_paths = setup_volume_mounts(rootfs, mounts)?;
    Ok(())
}

/// Directory where virtiofs mounts are mounted in the guest.
const VIRTIOFS_MOUNT_ROOT: &str = "/mnt/virtiofs";

/// Setup volume mounts by mounting virtiofs and bind-mounting into the rootfs.
fn setup_volume_mounts(rootfs: &str, mounts: &[(String, String, bool)]) -> Result<Vec<PathBuf>> {
    let mut mounted_paths = Vec::new();

    for (tag, container_path, read_only) in mounts {
        debug!(tag = %tag, container_path = %container_path, read_only = %read_only, "setting up volume mount");

        // First, mount the virtiofs device at a staging location
        let virtiofs_mount = Path::new(VIRTIOFS_MOUNT_ROOT).join(tag);
        std::fs::create_dir_all(&virtiofs_mount)?;

        // Check if already mounted
        if !is_mountpoint(&virtiofs_mount) {
            info!(tag = %tag, mount_point = %virtiofs_mount.display(), "mounting virtiofs");

            let status = Command::new("mount")
                .args(["-t", "virtiofs", tag])
                .arg(&virtiofs_mount)
                .status()?;

            if !status.success() {
                warn!(tag = %tag, "failed to mount virtiofs device");
                continue;
            }
        }

        // Now bind-mount into the container rootfs
        let target_path = format!("{}{}", rootfs, container_path);
        std::fs::create_dir_all(&target_path)?;

        // Check if already bind-mounted
        if !is_mountpoint(Path::new(&target_path)) {
            info!(
                source = %virtiofs_mount.display(),
                target = %target_path,
                read_only = %read_only,
                "bind-mounting into container"
            );

            let args = ["--bind", &virtiofs_mount.to_string_lossy(), &target_path];

            let status = Command::new("mount").args(args).status()?;

            if !status.success() {
                warn!(target = %target_path, "failed to bind-mount");
                continue;
            }

            // Remount read-only if requested
            if *read_only {
                let _ = Command::new("mount")
                    .args(["-o", "remount,ro,bind", &target_path])
                    .status();
            }
        }

        mounted_paths.push(PathBuf::from(target_path));
    }

    Ok(mounted_paths)
}

/// Get existing overlay or create new one.
fn get_or_create_overlay(image: &str, workload_id: &str) -> Result<OverlayInfo> {
    let root = Path::new(STORAGE_ROOT);
    let overlay_root = root.join(OVERLAYS_DIR).join(workload_id);
    let merged_path = overlay_root.join("merged");

    // Check if already mounted
    if merged_path.exists() && is_mountpoint(&merged_path) {
        debug!(workload_id = %workload_id, "reusing existing overlay");
        return Ok(OverlayInfo {
            rootfs_path: merged_path.display().to_string(),
            upper_path: overlay_root.join("upper").display().to_string(),
            work_path: overlay_root.join("work").display().to_string(),
        });
    }

    // Create new overlay
    prepare_overlay(image, workload_id)
}

/// Check if a path is a mountpoint.
fn is_mountpoint(path: &Path) -> bool {
    // Read /proc/mounts to check if path is mounted
    if let Ok(mounts) = std::fs::read_to_string("/proc/mounts") {
        let path_str = path.to_string_lossy();
        for line in mounts.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 && parts[1] == path_str {
                return true;
            }
        }
    }
    false
}

/// Exit code used when command is killed due to timeout.
const TIMEOUT_EXIT_CODE: i32 = 124;

/// Run a command using crun OCI runtime (one-shot execution).
///
/// This uses `crun run` which creates, starts, waits, and deletes the container
/// in a single operation. Stdout and stderr are captured.
fn run_with_crun(
    bundle_dir: &Path,
    container_id: &str,
    timeout_ms: Option<u64>,
) -> Result<RunResult> {
    use std::io::Read as _;
    use std::time::{Duration, Instant};

    info!(
        container_id = %container_id,
        bundle = %bundle_dir.display(),
        timeout_ms = ?timeout_ms,
        "running container with crun"
    );

    // Build crun run command
    let mut cmd = Command::new(CRUN_PATH);
    cmd.args([
        "run",
        "--bundle",
        &bundle_dir.to_string_lossy(),
        container_id,
    ]);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    // Spawn the container
    let mut child = cmd.spawn().map_err(|e| {
        StorageError(format!(
            "failed to spawn crun: {}. Is crun installed at {}?",
            e, CRUN_PATH
        ))
    })?;

    let start = Instant::now();
    let deadline = timeout_ms.map(|ms| start + Duration::from_millis(ms));

    // Poll for completion with timeout
    loop {
        match child.try_wait()? {
            Some(status) => {
                // Container finished - read output
                let mut stdout = String::new();
                let mut stderr = String::new();

                if let Some(mut out) = child.stdout.take() {
                    let _ = out.read_to_string(&mut stdout);
                }
                if let Some(mut err) = child.stderr.take() {
                    let _ = err.read_to_string(&mut stderr);
                }

                let exit_code = status.code().unwrap_or(-1);
                info!(
                    container_id = %container_id,
                    exit_code = exit_code,
                    stdout_len = stdout.len(),
                    stderr_len = stderr.len(),
                    "container finished"
                );

                return Ok(RunResult {
                    exit_code,
                    stdout,
                    stderr,
                });
            }
            None => {
                // Still running - check timeout
                if let Some(deadline) = deadline {
                    if Instant::now() >= deadline {
                        warn!(
                            container_id = %container_id,
                            timeout_ms = ?timeout_ms,
                            "container timed out, killing"
                        );

                        // Kill the crun process (which will kill the container)
                        let _ = child.kill();
                        let _ = child.wait();

                        // Also explicitly kill the container (in case it's orphaned)
                        let _ = Command::new(CRUN_PATH)
                            .args(["kill", container_id, "SIGKILL"])
                            .status();
                        let _ = Command::new(CRUN_PATH)
                            .args(["delete", "-f", container_id])
                            .status();

                        // Collect any partial output
                        let mut stdout = String::new();
                        let mut stderr = String::new();

                        if let Some(mut out) = child.stdout.take() {
                            let _ = out.read_to_string(&mut stdout);
                        }
                        if let Some(mut err) = child.stderr.take() {
                            let _ = err.read_to_string(&mut stderr);
                        }

                        return Ok(RunResult {
                            exit_code: TIMEOUT_EXIT_CODE,
                            stdout,
                            stderr: format!(
                                "{}\ncontainer timed out after {}ms",
                                stderr,
                                timeout_ms.unwrap_or(0)
                            ),
                        });
                    }
                }

                // Sleep briefly before checking again
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

// ============================================================================
// Helper functions
// ============================================================================

/// Run crane manifest command.
fn crane_manifest(image: &str, platform: Option<&str>) -> Result<String> {
    let mut cmd = Command::new("crane");
    cmd.arg("manifest").arg(image);

    if let Some(p) = platform {
        cmd.arg("--platform").arg(p);
    }

    let output = cmd.output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(StorageError(format!("crane manifest failed: {}", stderr)));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Run crane config command.
fn crane_config(image: &str, platform: Option<&str>) -> Result<String> {
    let mut cmd = Command::new("crane");
    cmd.arg("config").arg(image);

    if let Some(p) = platform {
        cmd.arg("--platform").arg(p);
    }

    let output = cmd.output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(StorageError(format!("crane config failed: {}", stderr)));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Sanitize image name for use as filename.
fn sanitize_image_name(image: &str) -> String {
    image.replace('/', "_").replace(':', "_").replace('@', "_")
}

/// Reverse sanitization.
fn unsanitize_image_name(name: &str) -> String {
    // This is approximate - we lose some info
    name.replacen('_', "/", 1).replacen('_', ":", 1)
}

/// Get disk usage for a path.
#[allow(unused_variables)] // path is used only on Linux
fn get_disk_usage(path: &Path) -> Result<(u64, u64)> {
    // Use statvfs on Linux
    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;
        use std::mem::MaybeUninit;

        let path_cstr = CString::new(path.to_string_lossy().as_bytes())
            .map_err(|_| StorageError("invalid path".into()))?;

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

/// Calculate directory size recursively.
fn dir_size(path: &Path) -> Result<u64> {
    let mut size = 0;

    if path.is_file() {
        return Ok(std::fs::metadata(path)?.len());
    }

    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() {
            size += std::fs::metadata(&path)?.len();
        } else if path.is_dir() {
            size += dir_size(&path)?;
        }
    }

    Ok(size)
}
