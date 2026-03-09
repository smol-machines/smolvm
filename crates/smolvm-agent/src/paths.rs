//! Centralized path constants and helpers for the smolvm agent.
//!
//! All filesystem paths used by the agent are defined here for consistency
//! and easy modification.

use std::path::PathBuf;

// =============================================================================
// Binary Paths
// =============================================================================

/// Path to crun OCI runtime binary.
pub const CRUN_PATH: &str = "/usr/bin/crun";

/// crun state root directory.
/// Stored on the persistent storage disk instead of `/run/crun` because
/// `/run` may not be writable under the overlayfs rootfs.
pub const CRUN_ROOT_DIR: &str = "/storage/containers/crun";

/// crun cgroup manager setting.
/// Set to "disabled" because libkrun mounts cgroup2 as read-only.
/// Without this, crun create/start hang trying to create container cgroups.
pub const CRUN_CGROUP_MANAGER: &str = "disabled";

// =============================================================================
// Mount Paths
// =============================================================================

/// Root directory for virtiofs mounts from the host.
pub const VIRTIOFS_MOUNT_ROOT: &str = "/mnt/virtiofs";

// =============================================================================
// Storage Paths
// =============================================================================

/// Root directory for all persistent storage.
pub const STORAGE_ROOT: &str = "/storage";

/// Directory for overlay filesystems.
pub const OVERLAYS_DIR: &str = "/storage/overlays";

// =============================================================================
// Container Runtime Paths
// =============================================================================

/// Directory for per-container runtime state (pidfile, etc).
pub const CONTAINERS_RUN_DIR: &str = "/storage/containers/run";

/// Directory for container logs.
pub const CONTAINERS_LOGS_DIR: &str = "/storage/containers/logs";

/// Directory for container exit code files.
pub const CONTAINERS_EXIT_DIR: &str = "/storage/containers/exit";

/// Path to the persistent container registry file.
pub const REGISTRY_PATH: &str = "/storage/containers/registry.json";

/// Path to the registry lock file.
pub const REGISTRY_LOCK_PATH: &str = "/storage/containers/registry.lock";

// =============================================================================
// Timeouts (milliseconds)
// =============================================================================

/// Timeout for acquiring registry lock.
pub const REGISTRY_LOCK_TIMEOUT_MS: u64 = 5000;

// =============================================================================
// Path Helper Functions
// =============================================================================

/// Get the runtime directory for a specific container.
pub fn container_run_dir(container_id: &str) -> PathBuf {
    PathBuf::from(CONTAINERS_RUN_DIR).join(container_id)
}

/// Get the log file path for a container.
pub fn container_log_path(container_id: &str) -> PathBuf {
    PathBuf::from(CONTAINERS_LOGS_DIR).join(format!("{}.log", container_id))
}

/// Get the exit code file path for a container.
pub fn container_exit_path(container_id: &str) -> PathBuf {
    PathBuf::from(CONTAINERS_EXIT_DIR).join(container_id)
}

/// Get the overlay directory for a workload.
pub fn overlay_dir(workload_id: &str) -> PathBuf {
    PathBuf::from(OVERLAYS_DIR).join(workload_id)
}

/// Get the bundle directory for a workload.
pub fn bundle_dir(workload_id: &str) -> PathBuf {
    overlay_dir(workload_id).join("bundle")
}

// =============================================================================
// Filesystem Helpers
// =============================================================================

/// Check if a path is a mountpoint by reading /proc/mounts.
///
/// Returns true if the path appears as a mount destination in /proc/mounts.
#[cfg(target_os = "linux")]
pub fn is_mount_point(path: &std::path::Path) -> bool {
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

/// Stub for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub fn is_mount_point(_path: &std::path::Path) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_container_paths() {
        let id = "abc123";
        assert_eq!(
            container_run_dir(id),
            PathBuf::from("/storage/containers/run/abc123")
        );
        assert_eq!(
            container_log_path(id),
            PathBuf::from("/storage/containers/logs/abc123.log")
        );
        assert_eq!(
            container_exit_path(id),
            PathBuf::from("/storage/containers/exit/abc123")
        );
    }

    #[test]
    fn test_overlay_paths() {
        let wl = "workload-123";
        assert_eq!(
            overlay_dir(wl),
            PathBuf::from("/storage/overlays/workload-123")
        );
        assert_eq!(
            bundle_dir(wl),
            PathBuf::from("/storage/overlays/workload-123/bundle")
        );
    }
}
