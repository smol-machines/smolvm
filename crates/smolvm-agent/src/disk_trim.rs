//! Reclaim freed guest disk blocks back to the host sparse file, driven by the
//! *signal* that space was actually freed rather than a blind clock.
//!
//! The guest's storage and rootfs-overlay disks are sparse files on the host.
//! They grow as the guest writes, but deleting files inside the guest only
//! frees blocks in the guest filesystem — the host sparse file stays at its
//! high-water mark until the freed blocks are discarded. virtio-blk passes
//! `FITRIM` through to the host, punching holes back into the sparse file, so
//! an `fstrim` makes disk usage shrink symmetrically with the guest's usage —
//! the disk counterpart to the host-side idle memory reclaim.
//!
//! ## Why not a fixed interval
//!
//! A periodic timer trims on a clock whether or not anything was freed, and on
//! a hosted node it makes every machine trim in lockstep — a synchronized
//! discard-I/O herd against the shared host disk. Instead this polls free space
//! cheaply (`statvfs`, no I/O) and only runs `fstrim` once the guest has freed
//! at least [`FREE_DELTA_TRIGGER`] bytes since the last trim. So a stable or
//! idle machine never trims, a machine that deletes a build trims once shortly
//! after, and fleet-wide trim load scales with actual reclaim work — naturally
//! staggered, because each machine trims when *it* deletes, not on a shared
//! clock. A long fallback interval still catches slow drift below the trigger.
//!
//! `fstrim -a` trims every mounted filesystem that supports discard (the ext4
//! storage disk at `/storage` and the ext4 rootfs overlay) and skips the rest
//! (virtiofs, overlay, tmpfs) without error, so it needs no mount enumeration.
//!
//! Best-effort throughout: a failed trim is logged and retried; it never
//! touches the workload. `SMOLVM_DISK_TRIM=off`/`0` disables it entirely
//! (a hosted control plane can set this per node); a `<minutes>` value
//! overrides the fallback interval.

use std::time::{Duration, Instant};

/// How often to sample free space. Cheap (`statvfs`, no disk I/O), so a short
/// cadence just makes reclaim prompt without adding load.
const POLL: Duration = Duration::from_secs(30);

/// Free-space growth since the last trim that triggers a trim. Below this,
/// there is too little to reclaim to be worth a discard pass.
const FREE_DELTA_TRIGGER: u64 = 256 * 1024 * 1024;

/// Trim at least this often even if the trigger is never hit, to reclaim slow
/// drift. Overridable via `SMOLVM_DISK_TRIM=<minutes>`.
const DEFAULT_FALLBACK_MINUTES: u64 = 30;

/// The filesystem whose free space is sampled as the reclaim signal. `/storage`
/// is the data disk that grows the most; a trim discards every trimmable mount.
#[cfg(target_os = "linux")]
const SAMPLE_PATH: &str = "/storage";

/// Fallback interval, or `None` when disk trim is disabled.
fn fallback_interval() -> Option<Duration> {
    let minutes = match std::env::var("SMOLVM_DISK_TRIM") {
        Ok(v) => {
            let v = v.trim();
            if v.eq_ignore_ascii_case("off") || v == "0" {
                return None;
            }
            v.parse::<u64>().unwrap_or(DEFAULT_FALLBACK_MINUTES).max(1)
        }
        Err(_) => DEFAULT_FALLBACK_MINUTES,
    };
    Some(Duration::from_secs(minutes * 60))
}

/// Free bytes on `SAMPLE_PATH`, or `None` if it can't be read.
fn free_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;
        let path = CString::new(SAMPLE_PATH).ok()?;
        // SAFETY: `path` is a valid NUL-terminated string; `stat` is written
        // only on success (rc == 0).
        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::statvfs(path.as_ptr(), &mut stat) };
        if rc != 0 {
            return None;
        }
        Some(stat.f_bfree as u64 * stat.f_frsize as u64)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Spawn the background reclaim thread. No-op when disabled.
pub fn spawn() {
    let Some(fallback) = fallback_interval() else {
        return;
    };
    let _ = std::thread::Builder::new()
        .name("disk-trim".into())
        .spawn(move || run(fallback));
}

fn run(fallback: Duration) {
    // The lowest free space seen since the last trim. A rise above this
    // low-water mark means blocks that were in use have been freed and are now
    // reclaimable — the signal to trim. Comparing against the post-trim level
    // instead would miss a write-then-delete, which returns to the same level.
    let mut min_free = free_bytes().unwrap_or(0);
    let mut last_trim = Instant::now();
    loop {
        std::thread::sleep(POLL);
        let free = free_bytes().unwrap_or(min_free);
        min_free = min_free.min(free);
        let reclaimable = free.saturating_sub(min_free);
        if reclaimable >= FREE_DELTA_TRIGGER || last_trim.elapsed() >= fallback {
            trim_once();
            // Reset the low-water to the current level after reclaiming.
            min_free = free_bytes().unwrap_or(free);
            last_trim = Instant::now();
        }
    }
}

/// Run one `fstrim -a`. Logged best-effort; never propagates failure.
fn trim_once() {
    match std::process::Command::new("fstrim").arg("-a").output() {
        Ok(out) if out.status.success() => {
            tracing::debug!("disk trim: fstrim -a completed");
        }
        Ok(out) => {
            tracing::debug!(
                stderr = %String::from_utf8_lossy(&out.stderr).trim(),
                "disk trim: fstrim -a returned non-zero"
            );
        }
        Err(e) => {
            tracing::debug!(error = %e, "disk trim: fstrim not run");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{fallback_interval, DEFAULT_FALLBACK_MINUTES};
    use std::time::Duration;

    fn with_env<T>(val: Option<&str>, f: impl FnOnce() -> T) -> T {
        match val {
            Some(v) => std::env::set_var("SMOLVM_DISK_TRIM", v),
            None => std::env::remove_var("SMOLVM_DISK_TRIM"),
        }
        let out = f();
        std::env::remove_var("SMOLVM_DISK_TRIM");
        out
    }

    #[test]
    fn fallback_interval_parsing() {
        let default = Duration::from_secs(DEFAULT_FALLBACK_MINUTES * 60);
        assert_eq!(with_env(None, fallback_interval), Some(default));
        // Disabled forms.
        assert_eq!(with_env(Some("off"), fallback_interval), None);
        assert_eq!(with_env(Some("0"), fallback_interval), None);
        // Explicit minutes override the fallback.
        assert_eq!(
            with_env(Some("5"), fallback_interval),
            Some(Duration::from_secs(300))
        );
        // Garbage falls back to the default rather than disabling.
        assert_eq!(with_env(Some("nonsense"), fallback_interval), Some(default));
        // Sub-1 is floored to 1 minute.
        assert_eq!(
            with_env(Some("1"), fallback_interval),
            Some(Duration::from_secs(60))
        );
    }
}
