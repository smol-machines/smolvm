//! Shared virtiofs DAX policy for every libkrun launch path.

use std::path::Path;

/// Root DAX keeps the guest ready marker coherent with the host.
pub(crate) const ROOTFS_DAX_WINDOW: u64 = 1 << 29;
/// Data mounts need room for large mapped libraries and model/data files.
pub(crate) const DATA_DAX_WINDOW: u64 = 1 << 31;
/// The CUDA file ring has a fixed, separately validated aperture.
pub(crate) const CUDA_RING_DAX_WINDOW: u64 = 1 << 29;

const ENV_ROOTFS_DAX: &str = "SMOLVM_ROOTFS_DAX";
const ENV_MOUNT_DAX: &str = "SMOLVM_MOUNT_DAX";

// Linux's filesystem DAX implementation is not correct on architectures with
// virtually mapped caches (including arm64), and the bundled arm64 guest kernel
// consequently has no FUSE_DAX support. Do not reserve a shared-memory window
// that the guest can only mount through the buffered path.
const VIRTIOFS_DAX_SUPPORTED: bool = cfg!(target_arch = "x86_64");

/// DAX window for the root filesystem. Root DAX is on unless explicitly
/// disabled for benchmarking.
pub(crate) fn rootfs_dax_window() -> u64 {
    if !VIRTIOFS_DAX_SUPPORTED || env_is_false(ENV_ROOTFS_DAX) {
        0
    } else {
        ROOTFS_DAX_WINDOW
    }
}

/// DAX window for one user mount. Normal mounts are explicit opt-in; on a
/// supported architecture the CUDA ring is always DAX because it cannot
/// function as a plain virtiofs mount.
pub(crate) fn user_mount_dax_window(guest_path: &Path) -> u64 {
    if !VIRTIOFS_DAX_SUPPORTED {
        0
    } else if guest_path == Path::new("/opt/smolvm-ring") {
        CUDA_RING_DAX_WINDOW
    } else if std::env::var(ENV_MOUNT_DAX).as_deref() == Ok("1") {
        DATA_DAX_WINDOW
    } else {
        0
    }
}

fn env_is_false(name: &str) -> bool {
    std::env::var(name)
        .map(|value| {
            matches!(
                value.as_str(),
                "0" | "false" | "False" | "FALSE" | "no" | "off"
            )
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dax_windows_follow_architecture_support() {
        if cfg!(target_arch = "x86_64") {
            assert_eq!(
                user_mount_dax_window(Path::new("/opt/smolvm-ring")),
                CUDA_RING_DAX_WINDOW
            );
        } else {
            assert_eq!(rootfs_dax_window(), 0);
            assert_eq!(user_mount_dax_window(Path::new("/opt/smolvm-ring")), 0);
        }
    }
}
