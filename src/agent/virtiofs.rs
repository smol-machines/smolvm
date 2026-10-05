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

/// Packed-layer DAX window for a fresh boot. The guest kernel spends 64 bytes
/// of `struct page` on every 4 KiB of a DAX window, so the window costs guest
/// RAM whether or not it is used: 2 GiB took 32 MiB on every pack machine.
/// 512 MiB (256 two-MiB mappings) measured the same as 2 GiB on warm imports
/// and file reads of a Python image; 64 MiB began to thrash.
pub(crate) const PACKED_LAYERS_DAX_WINDOW: u64 = 1 << 29;

/// The packed-layer window every machine booted with before its window was
/// recorded. A restored guest keeps DAX mappings anywhere in the window it
/// booted with, and libkrun replays them into the new one, so a snapshot must
/// restore into a window at least that large: one taken in a 2 GiB window and
/// restored into 512 MiB reads wrong data. Anything not known to have booted
/// smaller restores with this.
pub(crate) const LEGACY_PACKED_LAYERS_DAX_WINDOW: u64 = DATA_DAX_WINDOW;

/// Records the packed-layer window: in a machine's data dir (with the VMM's
/// identity, written at launch), and in a fork snapshot or installed checkpoint
/// (the window its guest booted with).
const PACKED_LAYERS_WINDOW_FILE: &str = "packed-layers-dax-window";

/// The legacy DAX window for immutable packed image layers, gated like the
/// root filesystem because the arm64 guest kernel has no FUSE DAX. Not the
/// fresh-boot size: it is for launches that cannot know the window a restored
/// guest booted with (packed executables, which may embed a snapshot), so they
/// map the largest one. Machines launched by the manager use
/// `packed_layers_window_for_launch`.
pub fn legacy_packed_layers_dax_window() -> u64 {
    if VIRTIOFS_DAX_SUPPORTED {
        LEGACY_PACKED_LAYERS_DAX_WINDOW
    } else {
        0
    }
}

/// The packed-layer window for one launch: a fresh boot gets the small window;
/// a guest restored from `snapshot_dir` gets the window recorded with that
/// snapshot, or the legacy window when none was.
pub(crate) fn packed_layers_window_for_launch(snapshot_dir: Option<&Path>) -> u64 {
    if !VIRTIOFS_DAX_SUPPORTED {
        return 0;
    }
    match snapshot_dir {
        None => PACKED_LAYERS_DAX_WINDOW,
        Some(snapshot) => read_window(&snapshot.join(PACKED_LAYERS_WINDOW_FILE))
            .unwrap_or(LEGACY_PACKED_LAYERS_DAX_WINDOW),
    }
}

/// Record the window a VMM process booted its guest with, bound to that
/// process so a stale record (say, from a boot by an older runtime) is ignored.
pub(crate) fn record_launch_window(vm_dir: &Path, window: u64, pid: u32, pid_start_time: u64) {
    let path = vm_dir.join(PACKED_LAYERS_WINDOW_FILE);
    if let Err(error) = atomic_write(
        &path,
        format!("{window} {pid} {pid_start_time}\n").as_bytes(),
    ) {
        // Without the record, captures of this machine restore with the legacy
        // window: larger than needed, never too small.
        tracing::warn!(%error, path = %path.display(), "could not record the packed-layer DAX window");
    }
}

/// The window the machine's running VMM booted with, if it was recorded for
/// exactly this process.
pub(crate) fn running_window(vm_dir: &Path, pid: u32, pid_start_time: u64) -> Option<u64> {
    let text = std::fs::read_to_string(vm_dir.join(PACKED_LAYERS_WINDOW_FILE)).ok()?;
    let mut fields = text.split_whitespace();
    let window = fields.next()?.parse().ok()?;
    let recorded_pid: u32 = fields.next()?.parse().ok()?;
    let recorded_start: u64 = fields.next()?.parse().ok()?;
    (recorded_pid == pid && recorded_start == pid_start_time && valid_window(window))
        .then_some(window)
}

/// Record, in a snapshot or installed checkpoint, the window its guest booted
/// with. Without the file the snapshot restores with the legacy window.
pub(crate) fn record_snapshot_window(snapshot_dir: &Path, window: u64) -> std::io::Result<()> {
    atomic_write(
        &snapshot_dir.join(PACKED_LAYERS_WINDOW_FILE),
        format!("{window}\n").as_bytes(),
    )
}

fn read_window(path: &Path) -> Option<u64> {
    let window = std::fs::read_to_string(path)
        .ok()?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    valid_window(window).then_some(window)
}

/// A window libkrun can map: a non-zero multiple of the 2 MiB mapping unit, no
/// larger than any window smolvm has used.
fn valid_window(window: u64) -> bool {
    window > 0 && window.is_multiple_of(2 << 20) && window <= LEGACY_PACKED_LAYERS_DAX_WINDOW
}

fn atomic_write(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let partial = path.with_extension(format!("partial-{}", std::process::id()));
    std::fs::write(&partial, contents)?;
    std::fs::rename(&partial, path)
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
    #[test]
    fn fresh_boots_get_the_small_window_and_snapshots_keep_theirs() {
        if !super::VIRTIOFS_DAX_SUPPORTED {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            super::packed_layers_window_for_launch(None),
            super::PACKED_LAYERS_DAX_WINDOW
        );
        // A snapshot from before windows were recorded restores with the legacy window.
        assert_eq!(
            super::packed_layers_window_for_launch(Some(dir.path())),
            super::LEGACY_PACKED_LAYERS_DAX_WINDOW
        );
        super::record_snapshot_window(dir.path(), super::PACKED_LAYERS_DAX_WINDOW).unwrap();
        assert_eq!(
            super::packed_layers_window_for_launch(Some(dir.path())),
            super::PACKED_LAYERS_DAX_WINDOW
        );
        // An unusable record is ignored rather than trusted.
        std::fs::write(dir.path().join(super::PACKED_LAYERS_WINDOW_FILE), "12345\n").unwrap();
        assert_eq!(
            super::packed_layers_window_for_launch(Some(dir.path())),
            super::LEGACY_PACKED_LAYERS_DAX_WINDOW
        );
    }

    #[test]
    fn a_running_window_is_trusted_only_for_the_process_that_recorded_it() {
        let dir = tempfile::tempdir().unwrap();
        super::record_launch_window(dir.path(), 1 << 29, 42, 1000);
        assert_eq!(super::running_window(dir.path(), 42, 1000), Some(1 << 29));
        assert_eq!(super::running_window(dir.path(), 42, 1001), None);
        assert_eq!(super::running_window(dir.path(), 43, 1000), None);
    }

    use super::*;

    #[test]
    fn dax_windows_follow_architecture_support() {
        if cfg!(target_arch = "x86_64") {
            assert_eq!(legacy_packed_layers_dax_window(), DATA_DAX_WINDOW);
            assert_eq!(
                user_mount_dax_window(Path::new("/opt/smolvm-ring")),
                CUDA_RING_DAX_WINDOW
            );
        } else {
            assert_eq!(rootfs_dax_window(), 0);
            assert_eq!(legacy_packed_layers_dax_window(), 0);
            assert_eq!(user_mount_dax_window(Path::new("/opt/smolvm-ring")), 0);
        }
    }
}
