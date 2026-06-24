//! Machine supervisor for health monitoring and restart policies.
//!
//! The supervisor runs as a background task that periodically checks machine health
//! and automatically restarts machines based on their restart policies.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

use crate::api::state::ApiState;
use crate::config::RecordState;

/// Interval between health checks.
const CHECK_INTERVAL: Duration = Duration::from_secs(5);

/// Minimum delay between restart attempts.
const MIN_RESTART_DELAY: Duration = Duration::from_secs(1);

/// Outcome of [`Supervisor::restart_timing`] for a dead, restart-eligible machine.
#[derive(Debug, PartialEq, Eq)]
enum RestartTiming {
    /// Restart now (fast-path backoff, or the armed time has arrived).
    Fire,
    /// Just armed the backoff timer this tick; do not restart yet.
    Armed,
    /// Timer armed on an earlier tick and not yet due; keep waiting.
    Waiting,
}

/// Machine supervisor for health monitoring and automatic restarts.
pub struct Supervisor {
    state: Arc<ApiState>,
    shutdown_rx: watch::Receiver<bool>,
    /// Per-machine instant at which a scheduled restart becomes due. Lets the
    /// supervisor honor restart backoff WITHOUT sleeping inside the shared
    /// health-check loop: a crash-looping machine with a long exponential
    /// backoff must not stall every other machine's liveness check, gauge
    /// reconcile, and log rotation. The supervisor is the single task that owns
    /// the loop, so a plain map needs no synchronization. Entries are cleared
    /// when a machine is alive again, its restart fires, or its policy stops it.
    next_restart_at: std::collections::HashMap<String, tokio::time::Instant>,
}

impl Supervisor {
    /// Create a new supervisor.
    pub fn new(state: Arc<ApiState>, shutdown_rx: watch::Receiver<bool>) -> Self {
        Self {
            state,
            shutdown_rx,
            next_restart_at: std::collections::HashMap::new(),
        }
    }

    /// Run the supervisor loop.
    ///
    /// This method blocks until shutdown is signaled.
    pub async fn run(mut self) {
        let mut ticker = tokio::time::interval(CHECK_INTERVAL);
        // Don't catch up on missed ticks
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        tracing::info!("supervisor started");

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    // Reap exited VM boot subprocesses (selective, per registered
                    // PID) BEFORE the health check, so a just-crashed VM's zombie
                    // is gone and `is_alive` reports it crashed this same tick.
                    crate::process::reap_vm_children();
                    self.check_all_machines().await;
                }
                _ = self.shutdown_rx.changed() => {
                    if *self.shutdown_rx.borrow() {
                        tracing::info!("supervisor shutting down");
                        break;
                    }
                }
            }
        }
    }

    /// Check all machines and restart any that need it.
    async fn check_all_machines(&mut self) {
        let machine_names = self.state.list_machine_names();

        // Drop schedule entries for machines that no longer exist so the map
        // can't grow without bound across deletes.
        self.next_restart_at
            .retain(|name, _| machine_names.iter().any(|n| n == name));

        for name in machine_names {
            if let Err(e) = self.check_machine(&name).await {
                tracing::warn!(machine = %name, error = %e, "failed to check machine");
            }
        }

        // Reconcile the running gauge with actual state (handles crashed VMs
        // that never went through stop(), preventing gauge drift).
        let (total, running) = self.state.machine_counts();
        metrics::gauge!("smolvm_machines_running").set(running as f64);
        metrics::gauge!("smolvm_machines_total").set(total as f64);

        // Also rotate logs for all machines
        self.rotate_logs_if_needed().await;
    }

    /// Check a single machine and restart if needed.
    async fn check_machine(&mut self, name: &str) -> crate::Result<()> {
        // Check if machine is alive
        let is_alive = self.state.is_machine_alive(name);

        if is_alive {
            // Running again (recovered, or a prior restart took hold) — drop any
            // pending restart schedule so a future death re-arms from scratch.
            self.next_restart_at.remove(name);
            return Ok(());
        }

        // Machine is dead — try to retrieve its exit code via waitpid
        // and persist it so the restart policy can use it.
        if let Ok(Some(record)) = self.state.db().get_vm(name) {
            if let Some(pid) = record.pid {
                let exit_code = crate::process::try_wait(pid);
                self.state.set_last_exit_code(name, exit_code);
            }
        }

        let last_exit_code = self.state.get_last_exit_code(name);

        // Machine is dead, check restart policy
        let restart_config = match self.state.get_restart_config(name) {
            Some(config) => config,
            None => {
                self.next_restart_at.remove(name);
                return Ok(()); // Machine doesn't exist anymore
            }
        };

        // Determine if we should restart (delegate to RestartConfig)
        if !restart_config.should_restart(last_exit_code) {
            self.next_restart_at.remove(name);
            tracing::debug!(machine = %name, policy = %restart_config.policy, "machine dead, not restarting per policy");
            // Update state to stopped (best-effort in supervisor)
            if let Err(e) = self
                .state
                .update_machine_state(name, RecordState::Stopped, None)
            {
                tracing::warn!(machine = %name, error = %e, "failed to persist stopped state");
            }
            return Ok(());
        }

        // Honor the backoff by SCHEDULING, not sleeping: blocking here would
        // stall every other machine's check this tick. See `restart_timing`.
        let backoff = restart_config.backoff_duration();
        let now = tokio::time::Instant::now();
        match Self::restart_timing(&mut self.next_restart_at, name, backoff, now) {
            RestartTiming::Waiting => return Ok(()),
            RestartTiming::Armed => {
                tracing::info!(
                    machine = %name,
                    restart_count = restart_config.restart_count,
                    backoff_secs = backoff.as_secs(),
                    "machine dead, scheduling restart"
                );
                return Ok(());
            }
            RestartTiming::Fire => {}
        }

        // Increment restart count
        self.state.increment_restart_count(name);

        // Attempt restart
        self.restart_machine(name).await
    }

    /// Decide, for a dead machine that should restart, whether its restart fires
    /// on this tick — without ever sleeping. Mutates the schedule map in place:
    ///
    /// - backoff ≤ [`MIN_RESTART_DELAY`]: [`RestartTiming::Fire`] immediately
    ///   (the previous fast-path; nothing to schedule).
    /// - first dead tick with a longer backoff: arm `now + backoff` and return
    ///   [`RestartTiming::Armed`].
    /// - a later tick before the armed time: [`RestartTiming::Waiting`].
    /// - a tick at/after the armed time: clear the entry and [`RestartTiming::Fire`].
    ///
    /// Pulled out as a pure function (no `ApiState`) so the backoff scheduling is
    /// unit-testable; the live ticker's resolution bounds how promptly `Armed`
    /// transitions to `Fire`.
    fn restart_timing(
        schedule: &mut std::collections::HashMap<String, tokio::time::Instant>,
        name: &str,
        backoff: Duration,
        now: tokio::time::Instant,
    ) -> RestartTiming {
        if backoff <= MIN_RESTART_DELAY {
            schedule.remove(name);
            return RestartTiming::Fire;
        }
        match schedule.get(name).copied() {
            Some(due) if now < due => RestartTiming::Waiting,
            Some(_) => {
                schedule.remove(name);
                RestartTiming::Fire
            }
            None => {
                schedule.insert(name.to_string(), now + backoff);
                RestartTiming::Armed
            }
        }
    }

    /// Attempt to restart a machine.
    async fn restart_machine(&self, name: &str) -> crate::Result<()> {
        // Hold the per-machine lifecycle lock across the acquire+mount+launch so a
        // concurrent user-initiated stop/delete cannot detach the macOS layers
        // volume out from under this restart (review finding #3). Acquired before
        // get_machine and the entry-mutex lock taken inside the spawn_blocking
        // below, keeping the lifecycle → entry lock order that start/stop/delete
        // also follow. If a user op holds it, this restart blocks until that op
        // completes (operations are bounded), then re-derives state from the DB.
        // Linux: the guarded mount is a no-op.
        let lifecycle = self.state.lifecycle_lock(name);
        let _guard = lifecycle.lock().await;

        // Re-check liveness now that we hold the lock. We may have queued this
        // restart while the machine was mid-boot (an API start or an earlier
        // restart held the lock); by the time we acquire it the boot may have
        // completed, so re-launching would kill+reboot a healthy machine and —
        // under concurrent boots — double the disk-prep load. If it's alive
        // again, there's nothing to restart.
        if self.state.is_machine_alive(name) {
            tracing::debug!(machine = %name, "machine came back alive before restart; skipping");
            return Ok(());
        }

        let entry = match self.state.get_machine(name) {
            Ok(entry) => entry,
            Err(_) => {
                tracing::warn!(machine = %name, "machine no longer exists, skipping restart");
                return Ok(());
            }
        };

        // Load the authoritative config from the database record rather than
        // the in-memory MachineEntry, which may have lost fields (e.g.,
        // network_backend, gpu_vram_mib) during the ResourceSpec round-trip.
        let record = match self.state.db().get_vm(name) {
            Ok(Some(r)) => r,
            Ok(None) => {
                tracing::warn!(machine = %name, "machine not found in database, skipping restart");
                return Ok(());
            }
            Err(e) => {
                tracing::warn!(machine = %name, error = %e, "failed to read machine record, skipping restart");
                return Ok(());
            }
        };

        // Never auto-restart a fork base: clones CoW-read its disks by path, so
        // relaunching it writable would corrupt them. Clones keep working
        // without the base process, so skipping is safe (and avoids thrashing,
        // since `prepare_for_launch` would refuse the launch anyway).
        match self.state.db().dependent_clones(name) {
            Ok(clones) if !clones.is_empty() => {
                tracing::warn!(
                    machine = %name,
                    clones = %clones.join(", "),
                    "not auto-restarting: machine is a fork base with live clones"
                );
                return Ok(());
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(machine = %name, error = %e, "could not check dependent clones; proceeding")
            }
        }

        let mounts = record.host_mounts();
        let ports = record.port_mappings();
        let resources = record.vm_resources();
        let source_smolmachine = record.source_smolmachine.clone();
        let name_for_features = name.to_string();

        let entry_clone = entry.clone();
        let start_result = tokio::task::spawn_blocking(move || {
            let entry = entry_clone.lock();
            // Wire pre-extracted layers if this machine was created from a .smolmachine.
            let features = crate::api::state::build_launch_features(
                Some(&name_for_features),
                source_smolmachine.as_deref(),
            )?;
            entry
                .manager
                .ensure_running_via_subprocess(mounts, ports, resources, features)
        })
        .await
        .map_err(|e| crate::Error::agent("ensure running", e.to_string()))?;

        // Handle start result
        match start_result {
            Ok(_) => {
                // Get updated PID and persist state
                let pid = {
                    let entry = entry.lock();
                    entry.manager.child_pid()
                };
                if let Err(e) = self
                    .state
                    .update_machine_state(name, RecordState::Running, pid)
                {
                    tracing::warn!(machine = %name, error = %e, "failed to persist running state");
                }
                tracing::info!(machine = %name, pid = ?pid, "machine restarted successfully");
                Ok(())
            }
            Err(e) => {
                if let Err(db_err) =
                    self.state
                        .update_machine_state(name, RecordState::Failed, None)
                {
                    tracing::warn!(machine = %name, error = %db_err, "failed to persist failed state");
                }
                tracing::error!(machine = %name, error = %e, "failed to restart machine");
                Err(e)
            }
        }
    }

    /// Rotate logs for all machines if they exceed the size limit.
    async fn rotate_logs_if_needed(&self) {
        let machine_names = self.state.list_machine_names();

        for name in machine_names {
            if let Some(log_path) = self.get_machine_log_path(&name) {
                if let Err(e) = crate::log_rotation::rotate_if_needed(&log_path) {
                    tracing::debug!(machine = %name, error = %e, "failed to rotate logs");
                }
            }
        }
    }

    /// Get the console log path for a machine.
    ///
    /// Resolves to the VM's hash-derived data directory — the canonical
    /// layout used by `AgentManager::new_internal` and exposed via
    /// `vm_data_dir` / the `machine data-dir` CLI command.
    fn get_machine_log_path(&self, name: &str) -> Option<std::path::PathBuf> {
        if crate::data::validate_vm_name(name, "machine name").is_err() {
            tracing::warn!(machine = %name, "skipping invalid machine name when resolving log path");
            return None;
        }

        let log_path = crate::agent::vm_data_dir(name).join("agent-console.log");
        if log_path.exists() {
            Some(log_path)
        } else {
            None
        }
    }
}

// Tests for should_restart and backoff_duration live in src/config.rs
// since the logic now lives on RestartConfig directly.

#[cfg(test)]
mod restart_timing_tests {
    use super::{RestartTiming, Supervisor, MIN_RESTART_DELAY};
    use std::collections::HashMap;
    use std::time::Duration;
    use tokio::time::Instant;

    // A backoff at or below the minimum restarts immediately and schedules nothing.
    #[test]
    fn fast_path_fires_immediately() {
        let mut sched = HashMap::new();
        let now = Instant::now();
        assert_eq!(
            Supervisor::restart_timing(&mut sched, "m", MIN_RESTART_DELAY, now),
            RestartTiming::Fire
        );
        assert!(sched.is_empty(), "fast-path must not arm a timer");
    }

    // A longer backoff arms on the first dead tick and waits on the next, but does
    // NOT fire — proving one crash-looping machine never blocks the loop here.
    #[test]
    fn long_backoff_arms_then_waits_then_fires() {
        let mut sched = HashMap::new();
        let backoff = Duration::from_secs(8);
        let t0 = Instant::now();

        // First dead tick: arm, don't fire.
        assert_eq!(
            Supervisor::restart_timing(&mut sched, "m", backoff, t0),
            RestartTiming::Armed
        );
        assert!(sched.contains_key("m"));

        // A later tick still before the due time: keep waiting, schedule intact.
        let before_due = t0 + Duration::from_secs(5);
        assert_eq!(
            Supervisor::restart_timing(&mut sched, "m", backoff, before_due),
            RestartTiming::Waiting
        );
        assert!(sched.contains_key("m"));

        // A tick at/after the due time: fire and clear the schedule.
        let after_due = t0 + Duration::from_secs(9);
        assert_eq!(
            Supervisor::restart_timing(&mut sched, "m", backoff, after_due),
            RestartTiming::Fire
        );
        assert!(
            !sched.contains_key("m"),
            "firing must clear the schedule so a later death re-arms"
        );
    }

    // Independent machines don't interfere: a long-backoff machine waiting must
    // not stop a fast-path machine from firing on the same tick.
    #[test]
    fn machines_are_scheduled_independently() {
        let mut sched = HashMap::new();
        let now = Instant::now();
        // Arm "slow" with a long backoff.
        assert_eq!(
            Supervisor::restart_timing(&mut sched, "slow", Duration::from_secs(30), now),
            RestartTiming::Armed
        );
        // "fast" still fires immediately despite "slow" being parked.
        assert_eq!(
            Supervisor::restart_timing(&mut sched, "fast", MIN_RESTART_DELAY, now),
            RestartTiming::Fire
        );
        // "slow" is still parked, not due.
        assert_eq!(
            Supervisor::restart_timing(&mut sched, "slow", Duration::from_secs(30), now),
            RestartTiming::Waiting
        );
    }
}
