//! Live fractional CPU limit on a running machine.
//!
//! A limit caps the host CPU time a running VMM gets, in milli-CPUs across all
//! of its vCPUs (200 = a fifth of one CPU), through the same cgroup quota that
//! normally grants it one CPU per vCPU. The guest is not touched: its vCPUs stay
//! online and simply get less host time. A limit lasts for the VMM process it
//! was set on; a restarted machine runs at its normal quota until a caller
//! sets the limit again.
//!
//! The active limit is recorded in `<vm_dir>/cpu-limit` together with the
//! identity of the VMM it applies to, so live CPU resize keeps it as the cap
//! and `MachineInfo` can report it, while a record left by an earlier boot is
//! ignored.

use super::{fork, AgentManager};
use crate::config::{RecordState, VmRecord};
use crate::db::SmolvmDb;
use crate::{Error, Result};
use std::path::{Path, PathBuf};

/// Milli-CPUs in one CPU.
const MILLICPUS_PER_CPU: u32 = 1_000;

/// Per-VM active CPU limit file: `<vm_data_dir>/cpu-limit`.
pub fn cpu_limit_file(name: &str) -> PathBuf {
    super::vm_data_dir(name).join("cpu-limit")
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

    /// Whether this record belongs to the VMM `pid` started at `started`.
    fn applies_to(&self, pid: i32, started: Option<u64>) -> bool {
        self.pid == pid && self.started == started
    }
}

fn read_limit_at(path: &Path, pid: i32, started: Option<u64>) -> Option<u32> {
    let limit = ActiveLimit::parse(&std::fs::read_to_string(path).ok()?)?;
    limit.applies_to(pid, started).then_some(limit.millicpus)
}

/// The CPU limit active on `name`'s VMM process `pid`, if one was set on that
/// same process. A limit recorded for an earlier boot reads as `None`.
pub fn read_active_cpu_limit(name: &str, pid: Option<i32>) -> Option<u32> {
    let pid = pid?;
    read_limit_at(
        &cpu_limit_file(name),
        pid,
        crate::process::process_start_time(pid),
    )
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
    let normal = u64::from(vcpus) * 1_000_000;
    limit_millicpus.map_or(normal, |limit| normal.min(u64::from(limit) * 1_000))
}

/// The quota a live resize to `vcpus` must give `name`'s VMM `pid` so an
/// active limit stays the cap.
pub(crate) fn resize_quota_usec(name: &str, pid: i32, vcpus: u8) -> u64 {
    effective_quota_usec(vcpus, read_active_cpu_limit(name, Some(pid)))
}

fn unsupported_host() -> Error {
    Error::config(
        "CPU limit",
        "CPU limits are not supported on this host: the machine's VMM is not in a cgroup smolvm controls",
    )
}

/// Set (`Some`) or clear (`None`) the live CPU limit of a running machine.
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
    let path = cpu_limit_file(name);
    let quota = effective_quota_usec(record.cpus, millicpus);
    if !crate::process::set_managed_vmm_cpu_quota(name, pid, started, quota)? {
        return Err(unsupported_host());
    }
    let recorded = match millicpus {
        Some(millicpus) => std::fs::write(
            &path,
            // The live start time, which every reader compares against.
            ActiveLimit {
                millicpus,
                pid,
                started: crate::process::process_start_time(pid),
            }
            .render(),
        ),
        None => match std::fs::remove_file(&path) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error),
            _ => Ok(()),
        },
    };
    if let Err(error) = recorded {
        if millicpus.is_some() {
            // An unrecorded limit would be lost on the next resize and never
            // reported, so put the normal quota back rather than leave it.
            let _ = crate::process::set_managed_vmm_cpu_quota(
                name,
                pid,
                started,
                effective_quota_usec(record.cpus, None),
            );
        }
        return Err(Error::agent(
            "CPU limit",
            format!("cannot record CPU limit: {error}"),
        ));
    }
    tracing::info!(machine = %name, ?millicpus, quota_usec_per_sec = quota, "set live CPU limit");
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
        assert_eq!(read_limit_at(&path, 4242, Some(987_654)), Some(200));
        // Same pid, different process (pid reuse after a restart).
        assert_eq!(read_limit_at(&path, 4242, Some(1)), None);
        assert_eq!(read_limit_at(&path, 4243, Some(987_654)), None);
        assert_eq!(read_limit_at(&dir.path().join("absent"), 4242, None), None);

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
        let quota = |vcpus| effective_quota_usec(vcpus, read_limit_at(&path, 7, Some(1)));
        assert_eq!(quota(8), 200_000);
        assert_eq!(quota(1), 200_000);
        // A limit left by an earlier boot does not cap the new VMM.
        assert_eq!(
            effective_quota_usec(8, read_limit_at(&path, 7, Some(2))),
            8_000_000
        );
    }
}
