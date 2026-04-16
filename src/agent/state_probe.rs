//! Resolve the actual state of a VM by reconciling DB record,
//! process liveness, and agent reachability.
//!
//! Three signals can disagree:
//!
//! - `record.state` — what we last persisted (e.g., `Running` after
//!   a successful start).
//! - `is_process_alive(pid)` — whether the libkrun VMM process is
//!   still around. Cheap (`kill(pid, 0)` + start-time match).
//! - vsock ping — whether the guest agent inside the VM responds.
//!   The only signal that proves the VM is *useful*; everything
//!   else is approximation.
//!
//! The combinations and their resolutions:
//!
//! | record.state | PID alive | ping ok | resolved state |
//! |---|---|---|---|
//! | Running | yes | yes | Running |
//! | Running | yes | no  | **Unreachable** ← the bug 2 case |
//! | Running | no  | yes | Running (macOS PID-not-visible edge case) |
//! | Running | no  | no  | Stopped |
//! | Stopped/Created/Failed | * | * | record.state (no probe) |
//!
//! Used by:
//! - CLI `machine list` — so the column shows the truth.
//! - HTTP API list/get/exec handlers — same reason.
//! - CLI `machine start --name` — to detect the Unreachable state
//!   and recover by killing the zombie VMM.

use crate::agent::{AgentClient, AgentManager};
use crate::config::{RecordState, VmRecord};
use crate::db::SmolvmDb;

/// Compute the resolved state for a VM record. May perform a single
/// short-timeout vsock ping; all other paths are stat-only.
///
/// `name` is the machine name (used to locate the agent socket).
/// Pings use a 250 ms timeout — long enough to tolerate a busy host
/// but short enough that a `machine list` over a handful of stale
/// records doesn't take seconds.
pub fn resolve_state(name: &str, record: &VmRecord) -> RecordState {
    if record.state != RecordState::Running {
        return record.state.clone();
    }

    let pid_alive = record.is_process_alive();

    if pid_alive {
        // PID alive: confirm the agent responds. If it doesn't, the
        // VMM is zombied — agent crashed but libkrun stayed up. This
        // is the "machine list says running, exec says not running"
        // divergence the operator sees in the wild.
        if probe_agent(name) {
            RecordState::Running
        } else {
            RecordState::Unreachable
        }
    } else {
        // PID not visible. On macOS the session-leader VMM may not
        // be reachable via `kill(pid, 0)` from a different shell —
        // try the agent socket as a fallback before declaring stopped.
        if probe_agent(name) {
            RecordState::Running
        } else {
            RecordState::Stopped
        }
    }
}

/// Tear down a zombie libkrun VMM (live PID, dead agent) and clear
/// the record's PID/state so the caller can proceed to a clean
/// fresh start — or simply leave the VM Stopped.
///
/// Kills via verified SIGTERM (PID + start-time match, so a recycled
/// PID is never harmed), waits up to 2 s for the process to exit,
/// then escalates to verified SIGKILL.
///
/// Infallible by design: if the kill or DB write fails, downstream
/// code will surface a clear error (libkrun "address already in
/// use" on restart, or the next `list` will re-probe and converge
/// on Stopped since the PID ends up dead either way). The caller
/// doesn't need to branch on success.
///
/// This is the shared teardown used by both the CLI (`machine start
/// | stop | delete --stop`) and the HTTP API (`POST /machines/X/start`)
/// so all surfaces recover from the Unreachable state the same way.
pub fn recover_unreachable_machine(record: &VmRecord) {
    use std::time::{Duration, Instant};

    if let Some(pid) = record.pid {
        if crate::process::terminate_verified(pid, record.pid_start_time) {
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                if !crate::process::is_alive(pid) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            if crate::process::is_alive(pid) {
                crate::process::kill_verified(pid, record.pid_start_time);
            }
        }
    }

    // Best-effort DB clear. We write via SmolvmDb (not SmolvmConfig)
    // to avoid pulling the full in-memory config load; the db update
    // is targeted to the one record.
    if let Ok(db) = SmolvmDb::open() {
        let _ = db.update_vm(&record.name, |r| {
            r.state = RecordState::Stopped;
            r.pid = None;
            r.pid_start_time = None;
        });
    }
}

/// If the named VM resolves to `Unreachable`, recover it (kill the
/// zombie VMM, clear the record). No-op for any other state.
///
/// Loads the record via `SmolvmDb` so callers on either side of the
/// CLI/API boundary can share the helper without coupling to
/// `SmolvmConfig`.
///
/// Returns `true` when recovery actually ran, so callers can print
/// a user-facing notice (start/stop/delete all want to mention the
/// teardown happened — the alternative is a silent kill, which is
/// surprising when the operator didn't know a zombie existed).
pub fn recover_if_unreachable(name: &str) -> bool {
    let Ok(db) = SmolvmDb::open() else {
        return false;
    };
    let Ok(Some(record)) = db.get_vm(name) else {
        return false;
    };
    if resolve_state(name, &record) != RecordState::Unreachable {
        return false;
    }
    recover_unreachable_machine(&record);
    true
}

/// Return true if a short-timeout vsock ping to the agent for this
/// machine succeeds. Used as the liveness ground-truth.
fn probe_agent(name: &str) -> bool {
    let Ok(manager) = AgentManager::for_vm(name) else {
        return false;
    };
    // Detach immediately — this manager is only used to locate the vsock
    // socket. Without detach, Drop sends Shutdown and kills the VM.
    manager.detach();
    // Use a moderate 3s timeout (not the 100ms boot probe) so a busy agent
    // — e.g., processing a Run request's overlayfs setup or a container
    // operation — isn't falsely reported as Unreachable. The 100ms timeout
    // caused `machine ls` / `machine status` to flap to Unreachable any
    // time the agent happened to be processing another request.
    let Ok(mut client) = AgentClient::connect_for_state_probe(manager.vsock_socket()) else {
        return false;
    };
    client.ping().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a record in the given state. We don't need to populate
    /// every field — most of them are irrelevant to the resolver.
    fn record(state: RecordState, pid: Option<i32>) -> VmRecord {
        let mut r = VmRecord::new("test".to_string(), 1, 256, vec![], vec![], false);
        r.state = state;
        r.pid = pid;
        r
    }

    #[test]
    fn non_running_states_pass_through_without_probing() {
        // The resolver short-circuits on any state other than
        // Running — never touches the agent socket. This matters
        // both for performance (no per-record probe on big lists)
        // and for correctness (Stopped should never randomly
        // become Unreachable just because some unrelated socket
        // happens to be reachable).
        for s in [
            RecordState::Created,
            RecordState::Stopped,
            RecordState::Failed,
            RecordState::Unreachable, // already-unreachable stays unreachable
        ] {
            let r = record(s.clone(), Some(99999));
            // Pass a name that won't match any real agent socket on
            // disk, so any accidental probe would fail fast.
            let resolved = resolve_state("does-not-exist", &r);
            assert_eq!(resolved, s, "state {:?} should pass through", s);
        }
    }

    #[test]
    fn running_with_no_pid_and_no_agent_returns_stopped() {
        // No PID + no reachable agent socket → not running. The
        // macOS PID-fallback path probes anyway (in case the PID
        // check missed a session-leader process), but with a name
        // that has no agent socket, the probe fails and we
        // correctly return Stopped.
        //
        // Avoiding `Some(0)` here because PID 0 is a magic value
        // (`kill(0, 0)` targets the current process group and
        // returns success), which would mis-classify as "alive".
        let r = record(RecordState::Running, None);
        let resolved = resolve_state("ghost-does-not-exist", &r);
        assert_eq!(resolved, RecordState::Stopped);
    }

    /// The cases that require a live agent socket (Running with PID
    /// alive + ping ok, Running with PID alive + ping fail) are
    /// exercised by the manual repro in `docs/file-transfer-fixes-plan.md`
    /// because they need a real VM. Layer A's contract is otherwise
    /// nailed down by the cases above.
    #[test]
    fn unreachable_variant_round_trips_through_serde() {
        // The Unreachable variant must serialize cleanly so a record
        // marked Unreachable in memory persists to redb correctly.
        let r = record(RecordState::Unreachable, Some(12345));
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"state\":\"unreachable\""));
        let back: VmRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.state, RecordState::Unreachable);
    }

    #[test]
    fn unreachable_displays_as_unreachable() {
        // The state shown in the CLI list comes from Display.
        // Operator must see "unreachable" verbatim, not the debug
        // form or a fallback.
        assert_eq!(format!("{}", RecordState::Unreachable), "unreachable");
    }
}
