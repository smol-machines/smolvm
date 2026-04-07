//! Centralized path constants and helpers for the smolvm agent.
//!
//! All filesystem paths used by the agent are defined here for consistency
//! and easy modification.

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
// Container Runtime Paths
// =============================================================================

/// Directory for per-container runtime state (pidfile, etc).
pub const CONTAINERS_RUN_DIR: &str = "/storage/containers/run";

/// Directory for container logs.
pub const CONTAINERS_LOGS_DIR: &str = "/storage/containers/logs";

/// Directory for container exit code files.
pub const CONTAINERS_EXIT_DIR: &str = "/storage/containers/exit";

// =============================================================================
// Path Helper Functions
// =============================================================================

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
