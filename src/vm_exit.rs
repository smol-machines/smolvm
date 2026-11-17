//! Why a machine's VMM process ended.
//!
//! A VMM that dies to a signal writes nothing, so its exit status is the only
//! evidence of what happened: SIGKILL from the OOM killer, SIGSYS from a
//! seccomp filter, a crash, or a plain exit. Only the parent can read that
//! status, so it is recorded where smolvm is the parent and reaps the VMM —
//! `serve`'s supervisor and an embedding SDK process — as `vmm-exit.json` in the
//! machine's directory. A VMM started by a CLI that has since exited is reaped
//! by init, and leaves no record.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// File name of the record in the machine's directory.
pub const VMM_EXIT_FILE: &str = "vmm-exit.json";

/// Marker smolvm writes, naming the VMM's PID, before it stops the VMM itself.
const STOP_REQUESTED_FILE: &str = "vmm-stop-requested";

/// What ended the VMM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Cause {
    /// It exited on its own, with `exit_code`.
    Exited,
    /// smolvm stopped it (`machine stop`, a delete, a restart), whatever
    /// signal that took.
    Stopped,
    /// The kernel's OOM killer: SIGKILL with an OOM kill counted in the
    /// VMM's own cgroup.
    OomKilled,
    /// A seccomp filter killed it (SIGSYS).
    Seccomp,
    /// A fault in the VMM or a library it loaded (SIGSEGV, SIGBUS, SIGABRT,
    /// SIGILL, SIGFPE).
    Crashed,
    /// Any other signal, SIGKILL included when no OOM kill was counted.
    Killed,
}

/// The recorded end of one VMM process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmmExit {
    /// The VMM's PID.
    pub pid: i32,
    /// When it was reaped, in milliseconds since the Unix epoch.
    pub exited_at_unix_ms: u64,
    /// What ended it.
    pub cause: Cause,
    /// Exit code, when it exited on its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Signal number, when a signal ended it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<i32>,
    /// Signal name, e.g. `SIGKILL`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal_name: Option<String>,
    /// Whether the kernel wrote a core dump.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub core_dumped: bool,
    /// OOM kills counted in the VMM's own cgroup (`memory.events`), when it
    /// had one and it could still be read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cgroup_oom_kills: Option<u64>,
}

impl VmmExit {
    /// One line for people: `killed by SIGKILL (the OOM killer)`.
    pub fn describe(&self) -> String {
        let signal = self.signal_name.as_deref().unwrap_or("a signal");
        match self.cause {
            Cause::Exited => format!("exited with code {}", self.exit_code.unwrap_or(0)),
            Cause::Stopped => "stopped by smolvm".to_string(),
            Cause::OomKilled => format!("killed by {signal} (the OOM killer)"),
            Cause::Seccomp => format!("killed by {signal} (a seccomp filter)"),
            Cause::Crashed => format!("crashed with {signal}"),
            Cause::Killed => format!("killed by {signal}"),
        }
    }
}

/// Classify a wait status. `oom_kills` is the VMM cgroup's OOM kill count.
#[cfg(unix)]
pub fn from_wait_status(pid: i32, status: libc::c_int, oom_kills: Option<u64>) -> VmmExit {
    let exited_at_unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let mut exit = VmmExit {
        pid,
        exited_at_unix_ms,
        cause: Cause::Exited,
        exit_code: None,
        signal: None,
        signal_name: None,
        core_dumped: false,
        cgroup_oom_kills: oom_kills,
    };
    if libc::WIFEXITED(status) {
        exit.exit_code = Some(libc::WEXITSTATUS(status));
        return exit;
    }
    if libc::WIFSIGNALED(status) {
        let signal = libc::WTERMSIG(status);
        exit.signal = Some(signal);
        exit.signal_name = Some(signal_name(signal));
        exit.core_dumped = libc::WCOREDUMP(status);
        exit.cause = match signal {
            libc::SIGSYS => Cause::Seccomp,
            libc::SIGKILL if oom_kills.is_some_and(|n| n > 0) => Cause::OomKilled,
            libc::SIGSEGV | libc::SIGBUS | libc::SIGABRT | libc::SIGILL | libc::SIGFPE => {
                Cause::Crashed
            }
            _ => Cause::Killed,
        };
    }
    exit
}

#[cfg(unix)]
fn signal_name(signal: libc::c_int) -> String {
    // SAFETY: strsignal returns a pointer to a static or thread-local string,
    // or null; it is copied before any other call.
    let described = unsafe {
        let text = libc::strsignal(signal);
        (!text.is_null()).then(|| {
            std::ffi::CStr::from_ptr(text)
                .to_string_lossy()
                .into_owned()
        })
    };
    let name = match signal {
        libc::SIGKILL => "SIGKILL",
        libc::SIGTERM => "SIGTERM",
        libc::SIGINT => "SIGINT",
        libc::SIGHUP => "SIGHUP",
        libc::SIGSYS => "SIGSYS",
        libc::SIGSEGV => "SIGSEGV",
        libc::SIGBUS => "SIGBUS",
        libc::SIGABRT => "SIGABRT",
        libc::SIGILL => "SIGILL",
        libc::SIGFPE => "SIGFPE",
        libc::SIGPIPE => "SIGPIPE",
        _ => {
            return described.map_or_else(
                || format!("signal {signal}"),
                |d| format!("signal {signal} ({d})"),
            )
        }
    };
    name.to_string()
}

/// The OOM kills counted for `pid`'s cgroup, read while it is still a zombie
/// (its `/proc` entry names the cgroup until it is reaped). Only a cgroup of
/// the VMM's own counts: in a shared one the kill may have been another
/// process's.
#[cfg(target_os = "linux")]
pub fn own_cgroup_oom_kills(pid: i32) -> Option<u64> {
    let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    let path = cgroup.lines().find_map(|line| line.strip_prefix("0::"))?;
    let leaf = path.rsplit('/').next()?;
    let own =
        leaf == format!("vm-{pid}") || (leaf.starts_with("smolvm-vm-") && leaf.ends_with(".scope"));
    if !own {
        return None;
    }
    let events = std::fs::read_to_string(format!("/sys/fs/cgroup{path}/memory.events")).ok()?;
    events
        .lines()
        .find_map(|line| line.strip_prefix("oom_kill "))
        .and_then(|count| count.trim().parse().ok())
}

/// Not available off Linux.
#[cfg(not(target_os = "linux"))]
pub fn own_cgroup_oom_kills(_pid: i32) -> Option<u64> {
    None
}

/// Note that smolvm is about to stop the VMM `pid` itself, so its exit is
/// recorded as [`Cause::Stopped`] rather than as a kill.
pub fn mark_stop_requested(machine_dir: &Path, pid: i32) {
    let _ = std::fs::write(machine_dir.join(STOP_REQUESTED_FILE), pid.to_string());
}

/// Write `exit` into `machine_dir`, replacing the previous run's record.
pub fn record(machine_dir: &Path, exit: &VmmExit) {
    let marker = machine_dir.join(STOP_REQUESTED_FILE);
    let requested = std::fs::read_to_string(&marker)
        .ok()
        .and_then(|pid| pid.trim().parse::<i32>().ok())
        == Some(exit.pid);
    let mut exit = exit.clone();
    if requested {
        let _ = std::fs::remove_file(&marker);
        if exit.cause != Cause::Exited {
            exit.cause = Cause::Stopped;
        }
    }
    let exit = &exit;
    let path = machine_dir.join(VMM_EXIT_FILE);
    let staged = machine_dir.join(format!(".{VMM_EXIT_FILE}.{}", std::process::id()));
    let written = serde_json::to_vec_pretty(exit)
        .map_err(std::io::Error::other)
        .and_then(|json| std::fs::write(&staged, json))
        .and_then(|()| std::fs::rename(&staged, &path));
    let expected = matches!(exit.cause, Cause::Stopped)
        || (exit.cause == Cause::Exited && exit.exit_code == Some(0));
    match written {
        Ok(()) if expected => {
            tracing::info!(pid = exit.pid, cause = ?exit.cause, "VMM {}", exit.describe())
        }
        Ok(()) => tracing::warn!(pid = exit.pid, cause = ?exit.cause, "VMM {}", exit.describe()),
        Err(error) => {
            let _ = std::fs::remove_file(&staged);
            tracing::warn!(pid = exit.pid, %error, "could not record why the VMM ended");
        }
    }
}

/// The last recorded VMM exit for the machine whose directory is `machine_dir`.
pub fn read(machine_dir: &Path) -> Option<VmmExit> {
    let json = std::fs::read(machine_dir.join(VMM_EXIT_FILE)).ok()?;
    serde_json::from_slice(&json).ok()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    // The raw wait status is the point, so the child is reaped by waitpid
    // rather than Child::wait.
    #[allow(clippy::zombie_processes)]
    fn status_of(script: &str) -> (i32, libc::c_int) {
        let child = std::process::Command::new("sh")
            .args(["-c", script])
            .spawn()
            .unwrap();
        let pid = child.id() as i32;
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        (pid, status)
    }

    #[test]
    fn exit_codes_signals_seccomp_and_oom_are_told_apart() {
        let (pid, status) = status_of("exit 3");
        let exit = from_wait_status(pid, status, None);
        assert_eq!((exit.cause, exit.exit_code), (Cause::Exited, Some(3)));

        let (pid, status) = status_of("kill -KILL $$");
        let killed = from_wait_status(pid, status, None);
        assert_eq!(killed.cause, Cause::Killed);
        assert_eq!(killed.signal_name.as_deref(), Some("SIGKILL"));
        // The same SIGKILL with an OOM kill in the VMM's own cgroup.
        assert_eq!(
            from_wait_status(pid, status, Some(1)).cause,
            Cause::OomKilled
        );
        assert_eq!(from_wait_status(pid, status, Some(0)).cause, Cause::Killed);

        let (pid, status) = status_of("kill -SYS $$");
        assert_eq!(from_wait_status(pid, status, None).cause, Cause::Seccomp);
        let (pid, status) = status_of("kill -SEGV $$");
        assert_eq!(from_wait_status(pid, status, None).cause, Cause::Crashed);
    }

    #[test]
    fn a_record_round_trips_and_describes_itself() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read(dir.path()), None);
        let (pid, status) = status_of("kill -KILL $$");
        let exit = from_wait_status(pid, status, Some(2));
        record(dir.path(), &exit);
        let back = read(dir.path()).unwrap();
        assert_eq!(back, exit);
        assert_eq!(back.describe(), "killed by SIGKILL (the OOM killer)");
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.path().join(VMM_EXIT_FILE)).unwrap())
                .unwrap();
        assert_eq!(json["cause"], "oom_killed");
    }

    #[test]
    fn a_stop_smolvm_asked_for_is_recorded_as_stopped_not_killed() {
        let dir = tempfile::tempdir().unwrap();
        let (pid, status) = status_of("kill -TERM $$");
        mark_stop_requested(dir.path(), pid + 1);
        record(dir.path(), &from_wait_status(pid, status, None));
        assert_eq!(
            read(dir.path()).unwrap().cause,
            Cause::Killed,
            "another PID's request"
        );
        mark_stop_requested(dir.path(), pid);
        record(dir.path(), &from_wait_status(pid, status, None));
        let exit = read(dir.path()).unwrap();
        assert_eq!(exit.cause, Cause::Stopped);
        assert_eq!(exit.signal_name.as_deref(), Some("SIGTERM"));
        assert!(!dir.path().join(STOP_REQUESTED_FILE).exists());
    }
}
