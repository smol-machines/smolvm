//! Live fractional CPU limit on a running machine.
//!
//! A limit caps the host CPU time a running VMM gets, in milli-CPUs across all
//! of its vCPUs (200 = a fifth of one CPU), through the same cgroup quota that
//! normally grants it one CPU per vCPU. The guest is not touched: its vCPUs stay
//! online and simply get less host time.
//!
//! Two files in the machine's data dir record it:
//! - `cpu-limit-desired` holds the limit the caller set. It outlives the VMM,
//!   so every later launch of the machine (restart, auto-restart, resume into a
//!   new VMM, guest reboot) starts under it; clearing the limit removes it.
//! - `cpu-limit` holds the limit applied now, with the identity of the VMM it
//!   was applied to, so live CPU resize keeps it as the cap and `MachineInfo`
//!   reports it, while a record left by an earlier VMM is ignored.

use super::{fork, AgentManager};
use crate::config::{RecordState, VmRecord};
use crate::db::SmolvmDb;
use crate::{Error, Result};
use std::path::{Path, PathBuf};

/// Milli-CPUs in one CPU.
const MILLICPUS_PER_CPU: u32 = 1_000;

/// File naming the limit applied to the current VMM.
const APPLIED_FILE: &str = "cpu-limit";
/// File naming the limit every launch of the machine starts under.
const DESIRED_FILE: &str = "cpu-limit-desired";

/// Per-VM applied CPU limit file: `<vm_data_dir>/cpu-limit`.
pub fn cpu_limit_file(name: &str) -> PathBuf {
    super::vm_data_dir(name).join(APPLIED_FILE)
}

/// The CPU limit recorded for one VMM process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ActiveLimit {
    millicpus: u32,
    pid: i32,
    started: Option<u64>,
}

impl ActiveLimit {
    /// `<millicpus> <pid> <start time or ->`.
    fn render(&self) -> String {
        let started = self
            .started
            .map_or_else(|| "-".to_string(), |started| started.to_string());
        format!("{} {} {started}\n", self.millicpus, self.pid)
    }

    fn parse(text: &str) -> Option<Self> {
        let mut fields = text.split_whitespace();
        let millicpus = fields.next()?.parse().ok().filter(|m| *m > 0)?;
        let pid = fields.next()?.parse().ok()?;
        let started = match fields.next()? {
            "-" => None,
            started => Some(started.parse().ok()?),
        };
        fields.next().is_none().then_some(Self {
            millicpus,
            pid,
            started,
        })
    }
}

/// The limit recorded at `path` for VMM `pid`, whose start time `started`
/// reports. The file is read first, so a machine without a limit costs no
/// process lookup.
fn read_limit_at(path: &Path, pid: i32, started: impl FnOnce() -> Option<u64>) -> Option<u32> {
    let limit = ActiveLimit::parse(&std::fs::read_to_string(path).ok()?)?;
    (limit.pid == pid && limit.started == started()).then_some(limit.millicpus)
}

/// The CPU limit active on `name`'s VMM process `pid`, if one was applied to
/// that same process. A limit recorded for an earlier VMM reads as `None`.
pub fn read_active_cpu_limit(name: &str, pid: Option<i32>) -> Option<u32> {
    let pid = pid?;
    read_limit_at(&cpu_limit_file(name), pid, || {
        crate::process::process_start_time(pid)
    })
}

fn read_desired_at(dir: &Path) -> Option<u32> {
    std::fs::read_to_string(dir.join(DESIRED_FILE))
        .ok()?
        .trim()
        .parse()
        .ok()
        .filter(|millicpus| *millicpus > 0)
}

/// Replace `path` with `contents` through a temp file and rename, so a reader
/// sees the old contents or the new ones, and a failed write leaves the old.
fn write_atomic(path: &Path, contents: &str) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    let written = std::fs::write(&tmp, contents).and_then(|()| std::fs::rename(&tmp, path));
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written
}

fn remove_if_present(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

/// Record `millicpus` (or no limit) as applied to VMM `pid` in `dir`.
fn record_applied_at(dir: &Path, pid: i32, millicpus: Option<u32>) -> std::io::Result<()> {
    let path = dir.join(APPLIED_FILE);
    match millicpus {
        Some(millicpus) => write_atomic(
            &path,
            // The live start time, which every reader compares against.
            &ActiveLimit {
                millicpus,
                pid,
                started: crate::process::process_start_time(pid),
            }
            .render(),
        ),
        None => remove_if_present(&path),
    }
}

/// Record `millicpus` (or no limit) as the one later launches start under.
fn record_desired_at(dir: &Path, millicpus: Option<u32>) -> std::io::Result<()> {
    let path = dir.join(DESIRED_FILE);
    match millicpus {
        Some(millicpus) => write_atomic(&path, &format!("{millicpus}\n")),
        None => remove_if_present(&path),
    }
}

/// Refuse a limit of zero or one above the machine's normal cap.
fn validate_millicpus(millicpus: u32, vcpus: u8) -> Result<()> {
    let ceiling = u32::from(vcpus) * MILLICPUS_PER_CPU;
    if millicpus == 0 || millicpus > ceiling {
        return Err(Error::config(
            "CPU limit",
            format!("millicpus must be between 1 and {ceiling} ({vcpus} vCPUs × 1000)"),
        ));
    }
    Ok(())
}

/// The CPU quota, in microseconds per second, a VMM with `vcpus` gets under
/// an optional limit: one CPU per vCPU, capped by the limit.
pub fn effective_quota_usec(vcpus: u8, limit_millicpus: Option<u32>) -> u64 {
    let normal = u64::from(vcpus.max(1)) * 1_000_000;
    limit_millicpus.map_or(normal, |limit| normal.min(u64::from(limit) * 1_000))
}

/// The quota a live resize to `vcpus` must give `name`'s VMM `pid` so an
/// active limit stays the cap.
pub(crate) fn resize_quota_usec(name: &str, pid: i32, vcpus: u8) -> u64 {
    effective_quota_usec(vcpus, read_active_cpu_limit(name, Some(pid)))
}

/// The limit a new VMM of the machine whose data dir is `dir` starts under,
/// if one was set, and the CPU quota that gives a VMM with `vcpus`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn launch_limit(dir: &Path, vcpus: u8) -> (Option<u32>, u64) {
    let desired = read_desired_at(dir);
    (desired, effective_quota_usec(vcpus, desired))
}

/// Record the limit a new VMM `pid` was launched under in `dir`, replacing
/// any record left by an earlier VMM. Best-effort: the quota is already in
/// place, and a missing record only hides it from `MachineInfo`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn record_launch_limit(dir: &Path, pid: i32, millicpus: Option<u32>) {
    if let Err(error) = record_applied_at(dir, pid, millicpus) {
        tracing::warn!(dir = %dir.display(), pid, error = %error, "cannot record launch CPU limit");
    }
}

fn unsupported_host() -> Error {
    Error::config(
        "CPU limit",
        "CPU limits are not supported on this host: the machine's VMM is not in a cgroup smolvm controls",
    )
}

/// Set (`Some`) or clear (`None`) the CPU limit of a running machine: applied
/// to its VMM now, and kept for every later launch until cleared.
pub fn set_cpu_limit(db: &SmolvmDb, name: &str, millicpus: Option<u32>) -> Result<VmRecord> {
    if !cfg!(target_os = "linux") {
        return Err(unsupported_host());
    }
    // Live CPU resize rewrites the same quota under this lock.
    let _source_guard = fork::lock_fork_source(name)?;
    let record = db.get_vm(name)?.ok_or_else(|| Error::vm_not_found(name))?;
    if record.actual_state() != RecordState::Running {
        return Err(Error::agent_conflict(
            "CPU limit",
            "machine must be running",
        ));
    }
    if let Some(millicpus) = millicpus {
        validate_millicpus(millicpus, record.cpus)?;
    }
    let manager = AgentManager::for_vm(name)?;
    let (pid, started) = manager
        .pid_and_start_time()
        .ok_or_else(|| Error::agent("CPU limit", "VMM process identity is unavailable"))?;
    let dir = super::vm_data_dir(name);
    let previous = read_active_cpu_limit(name, Some(pid));
    let previous_desired = read_desired_at(&dir);
    let restore_quota = || {
        let _ = crate::process::set_managed_vmm_cpu_quota(
            name,
            pid,
            started,
            effective_quota_usec(record.cpus, previous),
        );
    };
    let quota = effective_quota_usec(record.cpus, millicpus);
    match crate::process::set_managed_vmm_cpu_quota(name, pid, started, quota) {
        Ok(true) => {}
        Ok(false) => return Err(unsupported_host()),
        Err(error) => {
            // The quota may already be written when only its read-back or
            // the identity re-check failed; keep the cgroup and the record
            // in agreement.
            restore_quota();
            return Err(error);
        }
    }
    let recorded =
        record_applied_at(&dir, pid, millicpus).and_then(|()| record_desired_at(&dir, millicpus));
    if let Err(error) = recorded {
        // Put back what was in force before, never the unlimited quota: a
        // failed tightening must not release a throttled machine.
        restore_quota();
        let _ = record_applied_at(&dir, pid, previous);
        let _ = record_desired_at(&dir, previous_desired);
        return Err(Error::agent(
            "CPU limit",
            format!("cannot record CPU limit: {error}"),
        ));
    }
    tracing::info!(machine = %name, ?millicpus, quota_usec_per_sec = quota, "set CPU limit");
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limit_must_be_nonzero_and_within_the_normal_cap() {
        assert!(validate_millicpus(0, 4).is_err());
        assert!(validate_millicpus(1, 4).is_ok());
        assert!(validate_millicpus(200, 4).is_ok());
        assert!(validate_millicpus(4_000, 4).is_ok());
        assert!(validate_millicpus(4_001, 4).is_err());
        assert!(validate_millicpus(1_001, 1).is_err());
    }

    #[test]
    fn quota_is_one_cpu_per_vcpu_capped_by_the_limit() {
        assert_eq!(effective_quota_usec(4, None), 4_000_000);
        assert_eq!(effective_quota_usec(4, Some(200)), 200_000);
        assert_eq!(effective_quota_usec(4, Some(4_000)), 4_000_000);
        // A resize below the limit makes the vCPU count the cap again.
        assert_eq!(effective_quota_usec(2, Some(3_000)), 2_000_000);
    }

    #[test]
    fn limit_file_round_trips_and_applies_only_to_its_own_vmm() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cpu-limit");
        let limit = ActiveLimit {
            millicpus: 200,
            pid: 4242,
            started: Some(987_654),
        };
        std::fs::write(&path, limit.render()).unwrap();
        assert_eq!(read_limit_at(&path, 4242, || Some(987_654)), Some(200));
        // Same pid, different process (pid reuse after a restart).
        assert_eq!(read_limit_at(&path, 4242, || Some(1)), None);
        assert_eq!(read_limit_at(&path, 4243, || Some(987_654)), None);
        assert_eq!(
            read_limit_at(&dir.path().join("absent"), 4242, || None),
            None
        );

        let no_start = ActiveLimit {
            started: None,
            ..limit
        };
        assert_eq!(ActiveLimit::parse(&no_start.render()), Some(no_start));
        for bad in [
            "",
            "200",
            "200 4242",
            "0 4242 -",
            "x 4242 -",
            "200 4242 - extra",
        ] {
            assert_eq!(ActiveLimit::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn resize_keeps_an_active_limit_as_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cpu-limit");
        std::fs::write(
            &path,
            ActiveLimit {
                millicpus: 200,
                pid: 7,
                started: Some(1),
            }
            .render(),
        )
        .unwrap();
        let quota = |vcpus| effective_quota_usec(vcpus, read_limit_at(&path, 7, || Some(1)));
        assert_eq!(quota(8), 200_000);
        assert_eq!(quota(1), 200_000);
        // A limit left by an earlier boot does not cap the new VMM.
        assert_eq!(
            effective_quota_usec(8, read_limit_at(&path, 7, || Some(2))),
            8_000_000
        );
    }

    #[test]
    fn a_set_limit_carries_over_to_the_next_launch_until_cleared() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(launch_limit(dir.path(), 4), (None, 4_000_000));

        record_desired_at(dir.path(), Some(200)).unwrap();
        assert!(!dir.path().join("cpu-limit-desired.tmp").exists());
        // A relaunched VMM starts under the limit, whatever its vCPU count.
        assert_eq!(launch_limit(dir.path(), 4), (Some(200), 200_000));
        assert_eq!(launch_limit(dir.path(), 8), (Some(200), 200_000));

        // The new VMM's record replaces the one an earlier VMM left.
        let pid = std::process::id() as i32;
        let started = || crate::process::process_start_time(pid);
        std::fs::write(
            dir.path().join(APPLIED_FILE),
            ActiveLimit {
                millicpus: 900,
                pid: pid + 1,
                started: Some(1),
            }
            .render(),
        )
        .unwrap();
        record_launch_limit(dir.path(), pid, Some(200));
        assert_eq!(
            read_limit_at(&dir.path().join(APPLIED_FILE), pid, started),
            Some(200)
        );
        // A launch with no limit set removes a stale record.
        record_launch_limit(dir.path(), pid, None);
        assert!(!dir.path().join(APPLIED_FILE).exists());

        record_desired_at(dir.path(), None).unwrap();
        assert_eq!(launch_limit(dir.path(), 4), (None, 4_000_000));
        // Clearing twice is not an error.
        record_desired_at(dir.path(), None).unwrap();
    }

    #[test]
    fn a_failed_atomic_write_leaves_the_previous_limit() {
        let dir = tempfile::tempdir().unwrap();
        record_desired_at(dir.path(), Some(200)).unwrap();
        // A directory where the temp file goes makes the write fail.
        std::fs::create_dir(dir.path().join("cpu-limit-desired.tmp")).unwrap();
        assert!(record_desired_at(dir.path(), Some(50)).is_err());
        assert_eq!(read_desired_at(dir.path()), Some(200));
        for bad in ["", "0", "x"] {
            std::fs::write(dir.path().join(DESIRED_FILE), bad).unwrap();
            assert_eq!(read_desired_at(dir.path()), None, "{bad:?}");
        }
    }

    #[test]
    fn a_missing_limit_file_skips_the_process_lookup() {
        let dir = tempfile::tempdir().unwrap();
        let looked_up = std::cell::Cell::new(false);
        let started = || {
            looked_up.set(true);
            None
        };
        assert_eq!(
            read_limit_at(&dir.path().join(APPLIED_FILE), 1, started),
            None
        );
        assert!(!looked_up.get());
    }
}
