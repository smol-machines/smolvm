//! Background reconciliation for automatic held-fork worker pools.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

use crate::api::handlers::machines::{delete_one, fork_held_machines_inner, ForkHeldBatch};
use crate::api::state::ApiState;
use crate::pool::{ForkPoolRecord, ForkPoolSlotState};

const RECONCILE_INTERVAL: Duration = Duration::from_secs(1);
// Prepare enough workers to amortize one golden checkpoint across practical
// GPU pool sizes, while bounding the number of registered-but-unbooted clones.
const MAX_PREPARED_POOL_WORKERS: usize = 32;
// Limit simultaneous KVM/CUDA restores to avoid transient host-resource
// exhaustion. A continuous queue preserves that bound without introducing
// four-worker checkpoint barriers.
const MAX_CONCURRENT_POOL_BOOTS: usize = 4;

fn provision_failure_reason(message: &str) -> &'static str {
    if message.contains("Failure during vcpu run: Cannot allocate memory (os error 12)") {
        "kvm_enomem"
    } else if message.contains("clone agent did not respond to ping within timeout") {
        "agent_timeout"
    } else if message.contains("CUDA clone worker failed during reconstruction") {
        "cuda_reconstruction"
    } else {
        "other"
    }
}

fn record_provision(status: &'static str, reason: &'static str) {
    metrics::counter!(
        "smolvm_fork_pool_provisions_total",
        "status" => status,
        "reason" => reason
    )
    .increment(1);
}

type RetainedSnapshotMap = Arc<
    parking_lot::Mutex<std::collections::HashMap<String, crate::agent::fork::RetainedForkSnapshot>>,
>;

/// Maintains each pool's clean-worker target and reaps finished leases.
pub struct ForkPoolController {
    state: Arc<ApiState>,
    shutdown_rx: watch::Receiver<bool>,
    fills: tokio::task::JoinSet<String>,
    filling: std::collections::HashSet<String>,
    nvml: Option<crate::api::admission::NvmlSampler>,
    host_cpu: crate::api::admission::HostCpuSampler,
    retained_snapshots: RetainedSnapshotMap,
    boot_slots: Arc<tokio::sync::Semaphore>,
}

impl ForkPoolController {
    /// Create a controller sharing the API's durable state and shutdown signal.
    pub fn new(state: Arc<ApiState>, shutdown_rx: watch::Receiver<bool>) -> Self {
        let nvml = match crate::api::admission::NvmlSampler::new() {
            Ok(nvml) => Some(nvml),
            Err(error) => {
                tracing::info!(%error, "NVML unavailable; automatic admission will use full residency");
                None
            }
        };
        let retained_snapshots = match state.db().list_retained_fork_snapshots() {
            Ok(snapshots) => {
                if !snapshots.is_empty() {
                    tracing::info!(
                        count = snapshots.len(),
                        "restored retained fork pool checkpoints"
                    );
                }
                snapshots.into_iter().collect()
            }
            Err(error) => {
                tracing::warn!(%error, "failed to restore retained fork pool checkpoints");
                std::collections::HashMap::new()
            }
        };
        Self {
            state,
            shutdown_rx,
            fills: tokio::task::JoinSet::new(),
            filling: std::collections::HashSet::new(),
            nvml,
            host_cpu: crate::api::admission::HostCpuSampler::default(),
            retained_snapshots: Arc::new(parking_lot::Mutex::new(retained_snapshots)),
            boot_slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_POOL_BOOTS)),
        }
    }

    /// Reconcile until server shutdown.
    pub async fn run(mut self) {
        // A provisioning row can only have an in-flight creator in this process.
        // On startup every such row is therefore crash residue: recover a fully
        // booted held VM, otherwise retire it before admitting new capacity.
        if let Err(error) = self.recover_interrupted_provisioning().await {
            tracing::warn!(%error, "failed to recover interrupted fork-pool provisioning");
        }

        let mut ticker = tokio::time::interval(RECONCILE_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let reconcile_notify = self.state.pool_reconcile_notify();
        tracing::info!("fork pool controller started");
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    self.reap_fill_tasks();
                    if let Err(error) = self.reconcile_once(true).await {
                        tracing::warn!(%error, "fork pool reconciliation failed");
                    }
                }
                _ = reconcile_notify.notified() => {
                    self.reap_fill_tasks();
                    if let Err(error) = self.reconcile_once(false).await {
                        tracing::warn!(%error, "fork pool reconciliation failed");
                    }
                }
                result = self.fills.join_next(), if !self.fills.is_empty() => {
                    self.handle_fill_task(result);
                    if let Err(error) = self.reconcile_once(false).await {
                        tracing::warn!(%error, "fork pool reconciliation failed");
                    }
                }
                changed = self.shutdown_rx.changed() => {
                    if changed.is_err() || *self.shutdown_rx.borrow() {
                        self.fills.abort_all();
                        tracing::info!("fork pool controller shutting down");
                        break;
                    }
                }
            }
        }
    }

    fn handle_fill_task(&mut self, result: Option<Result<String, tokio::task::JoinError>>) {
        match result {
            Some(Ok(pool_name)) => {
                self.filling.remove(&pool_name);
            }
            Some(Err(error)) => {
                tracing::warn!(%error, "fork pool fill task failed");
                // A panic loses the task's return value, so conservatively
                // allow every pool to be scheduled again. Slot reservations
                // still prevent overfill if another task is winding down.
                self.filling.clear();
            }
            None => {}
        }
    }

    fn reap_fill_tasks(&mut self) {
        while let Some(result) = self.fills.try_join_next() {
            self.handle_fill_task(Some(result));
        }
    }

    async fn recover_interrupted_provisioning(&self) -> Result<(), String> {
        let db = self.state.db().clone();
        let pools = tokio::task::spawn_blocking(move || db.list_fork_pools())
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;
        for pool in pools {
            let db = self.state.db().clone();
            let pool_name = pool.name.clone();
            let slots = tokio::task::spawn_blocking(move || db.list_fork_pool_slots(&pool_name))
                .await
                .map_err(|e| e.to_string())?
                .map_err(|e| e.to_string())?;
            for slot in slots
                .into_iter()
                .filter(|slot| slot.state == ForkPoolSlotState::Provisioning)
            {
                let db = self.state.db().clone();
                let machine = slot.machine_name.clone();
                let vm = tokio::task::spawn_blocking(move || db.get_vm(&machine))
                    .await
                    .map_err(|e| e.to_string())?
                    .map_err(|e| e.to_string())?;
                let recoverable = vm
                    .as_ref()
                    .map(|record| {
                        record.forkpoint_held
                            && record.golden.as_deref() == Some(pool.golden.as_str())
                            && record.is_process_alive()
                    })
                    .unwrap_or(false);
                let db = self.state.db().clone();
                let machine = slot.machine_name;
                tokio::task::spawn_blocking(move || {
                    if recoverable {
                        db.mark_fork_pool_slot_ready(&machine, crate::util::current_timestamp())
                    } else {
                        db.mark_fork_pool_slot_retiring(
                            &machine,
                            crate::util::current_timestamp(),
                            Some("controller restarted during worker provisioning".into()),
                        )
                    }
                })
                .await
                .map_err(|e| e.to_string())?
                .map_err(|e| e.to_string())?;
            }
        }
        Ok(())
    }

    async fn reconcile_once(&mut self, sample_admission: bool) -> Result<(), String> {
        let now = crate::util::current_timestamp();
        let db = self.state.db().clone();
        let expired = tokio::task::spawn_blocking(move || db.expire_fork_leases(now))
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;
        for lease in expired {
            tracing::info!(
                pool = %lease.pool_name,
                lease = %lease.id,
                machine = %lease.machine_name,
                "fork pool lease expired"
            );
        }

        self.retire_invalid_ready_workers().await?;
        self.retire_dead_leased_workers().await?;
        self.delete_retired_workers().await?;

        let db = self.state.db().clone();
        tokio::task::spawn_blocking(move || db.finalize_deleted_fork_pools())
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;

        let db = self.state.db().clone();
        let pools = tokio::task::spawn_blocking(move || db.list_fork_pools())
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;
        // Retained checkpoints are shared by automatic pools and the plain
        // machine fork API.  A checkpoint stays valid for as long as its
        // source VM record exists; limiting this set to active pool goldens
        // discarded ordinary fork checkpoints on the first serve restart.
        let db = self.state.db().clone();
        let checkpoint_sources = tokio::task::spawn_blocking(move || db.list_vms())
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|(name, _)| name)
            .collect::<std::collections::HashSet<_>>();
        let stale_snapshots = {
            let mut snapshots = self.retained_snapshots.lock();
            retain_existing_checkpoint_sources(&mut snapshots, &checkpoint_sources)
        };
        if !stale_snapshots.is_empty() {
            let db = self.state.db().clone();
            match tokio::task::spawn_blocking(move || {
                for golden in stale_snapshots {
                    if let Err(error) = db.remove_retained_fork_snapshot(&golden) {
                        tracing::warn!(%golden, %error, "failed to remove orphan retained fork checkpoint");
                    }
                }
            })
            .await
            {
                Ok(()) => {}
                Err(error) => {
                    tracing::warn!(%error, "orphan retained fork checkpoint cleanup task failed");
                }
            }
        }
        self.update_admission(&pools, sample_admission).await?;
        for pool in pools.into_iter().filter(|pool| !pool.deleting) {
            if self.filling.contains(&pool.name) {
                continue;
            }
            let db = self.state.db().clone();
            let pool_for_deficit = pool.name.clone();
            let deficit =
                tokio::task::spawn_blocking(move || db.fork_pool_ready_deficit(&pool_for_deficit))
                    .await
                    .map_err(|e| e.to_string())?
                    .map_err(|e| e.to_string())?;
            if deficit > 0 && self.filling.insert(pool.name.clone()) {
                let state = self.state.clone();
                let retained_snapshots = self.retained_snapshots.clone();
                let boot_slots = self.boot_slots.clone();
                let pool_name = pool.name.clone();
                self.fills.spawn(async move {
                    Self::fill_pool(state, pool, retained_snapshots, boot_slots).await;
                    pool_name
                });
            }
        }
        Ok(())
    }

    async fn update_admission(
        &mut self,
        pools: &[ForkPoolRecord],
        sample: bool,
    ) -> Result<(), String> {
        let gpu_devices = if sample {
            self.nvml.as_mut().and_then(|nvml| nvml.sample_devices())
        } else {
            None
        };
        if sample {
            // Keep node capability reporting on the existing one-second NVML
            // sampling path. A failed sample clears the cache so the fleet
            // scheduler fails closed instead of dispatching to stale capacity.
            self.state.record_cuda_devices(gpu_devices.clone());
        }
        let gpu = gpu_devices.as_ref().map(|devices| {
            devices
                .iter()
                .map(|device| (device.device_ordinal, device.admission_sample()))
                .collect::<std::collections::HashMap<_, _>>()
        });
        let host_cpu = if sample { self.host_cpu.sample() } else { None };
        let mut observations = Vec::with_capacity(pools.len());
        for pool in pools.iter().filter(|pool| !pool.deleting) {
            let db = self.state.db().clone();
            let pool_name = pool.name.clone();
            let (active, completed) =
                tokio::task::spawn_blocking(move || db.fork_pool_admission_counts(&pool_name))
                    .await
                    .map_err(|error| error.to_string())?
                    .map_err(|error| error.to_string())?;
            observations.push((pool.clone(), active, completed));
        }
        if sample {
            self.state
                .admission()
                .observe_pools(&observations, gpu.as_ref(), host_cpu);
        } else {
            // Mutations and fill completions need an immediate capacity pass,
            // but admission's telemetry windows retain their periodic cadence.
            self.state.admission().ensure_pools(&observations);
        }

        for pool in pools
            .iter()
            .filter(|pool| !pool.deleting && pool.auto_admission)
        {
            if let Some(snapshot) = self.state.admission().snapshot(pool) {
                metrics::gauge!("smolvm_pool_admission_limit", "pool" => pool.name.clone())
                    .set(f64::from(snapshot.effective_limit));
                metrics::gauge!(
                    "smolvm_cuda_device_admission_limit",
                    "device" => snapshot.device_ordinal.to_string()
                )
                .set(f64::from(snapshot.device_limit));
                if let Some(utilization) = snapshot.gpu_utilization_percent {
                    metrics::gauge!("smolvm_pool_gpu_utilization_percent", "pool" => pool.name.clone())
                        .set(utilization);
                }
            }
        }
        Ok(())
    }

    async fn retire_invalid_ready_workers(&self) -> Result<(), String> {
        let db = self.state.db().clone();
        let pools = tokio::task::spawn_blocking(move || db.list_fork_pools())
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;
        for pool in pools {
            let db = self.state.db().clone();
            let pool_name = pool.name.clone();
            let slots = tokio::task::spawn_blocking(move || db.list_fork_pool_slots(&pool_name))
                .await
                .map_err(|e| e.to_string())?
                .map_err(|e| e.to_string())?;
            for slot in slots
                .into_iter()
                .filter(|slot| slot.state == ForkPoolSlotState::Ready)
            {
                let db = self.state.db().clone();
                let machine = slot.machine_name.clone();
                let vm = tokio::task::spawn_blocking(move || db.get_vm(&machine))
                    .await
                    .map_err(|e| e.to_string())?
                    .map_err(|e| e.to_string())?;
                let valid = vm
                    .as_ref()
                    .map(|record| {
                        record.forkpoint_held
                            && record.golden.as_deref() == Some(pool.golden.as_str())
                            && record.is_process_alive()
                    })
                    .unwrap_or(false);
                if !valid {
                    let db = self.state.db().clone();
                    let machine = slot.machine_name;
                    tokio::task::spawn_blocking(move || {
                        db.mark_fork_pool_slot_retiring(
                            &machine,
                            crate::util::current_timestamp(),
                            Some("ready worker is missing, dead, or no longer held".into()),
                        )
                    })
                    .await
                    .map_err(|e| e.to_string())?
                    .map_err(|e| e.to_string())?;
                }
            }
        }
        Ok(())
    }

    async fn delete_retired_workers(&self) -> Result<(), String> {
        let db = self.state.db().clone();
        let slots = tokio::task::spawn_blocking(move || db.list_retiring_fork_pool_slots())
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;
        for slot in slots {
            match delete_one(self.state.clone(), slot.machine_name.clone()).await {
                Ok(_) | Err(crate::api::error::ApiError::NotFound(_)) => {
                    let db = self.state.db().clone();
                    let machine = slot.machine_name;
                    tokio::task::spawn_blocking(move || db.remove_fork_pool_slot(&machine))
                        .await
                        .map_err(|e| e.to_string())?
                        .map_err(|e| e.to_string())?;
                }
                Err(error) => {
                    tracing::warn!(
                        pool = %slot.pool_name,
                        machine = %slot.machine_name,
                        error = ?error,
                        "failed to retire fork pool worker"
                    );
                }
            }
        }
        Ok(())
    }

    async fn retire_dead_leased_workers(&self) -> Result<(), String> {
        let db = self.state.db().clone();
        let leases = tokio::task::spawn_blocking(move || db.list_active_fork_leases())
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;
        for lease in leases {
            let db = self.state.db().clone();
            let machine = lease.machine_name.clone();
            let alive = tokio::task::spawn_blocking(move || {
                db.get_vm(&machine)
                    .map(|record| record.map(|vm| vm.is_process_alive()).unwrap_or(false))
            })
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;
            if !alive {
                let db = self.state.db().clone();
                let lease_id = lease.id.clone();
                tokio::task::spawn_blocking(move || {
                    db.fail_active_fork_lease(
                        &lease_id,
                        crate::util::current_timestamp(),
                        "leased worker process exited".into(),
                    )
                })
                .await
                .map_err(|e| e.to_string())?
                .map_err(|e| e.to_string())?;
                tracing::warn!(
                    pool = %lease.pool_name,
                    lease = %lease.id,
                    machine = %lease.machine_name,
                    "fork pool worker exited while leased"
                );
            }
        }
        Ok(())
    }

    async fn fill_pool(
        state: Arc<ApiState>,
        pool: ForkPoolRecord,
        retained_snapshots: RetainedSnapshotMap,
        boot_slots: Arc<tokio::sync::Semaphore>,
    ) {
        // A golden can produce only one RAM checkpoint at a time. Keep the
        // lifecycle lock through snapshot publication so another pool sharing
        // this golden reads the proven retained checkpoint instead of issuing
        // a second FORK command after the first caller has paused the VM.
        let golden_guard = state.lifecycle_lock(&pool.golden).lock_owned().await;

        // Bound each pool's work so a large cold fill cannot starve expiry and
        // cleanup for every other pool. Reserve the bounded deficit first so all
        // workers in this tick can share one golden checkpoint.
        let mut machines = Vec::new();
        for _ in 0..MAX_PREPARED_POOL_WORKERS {
            let suffix = crate::util::generate_short_id();
            // Pool names are validated ASCII. Keep room for `pool-`, `-`, and
            // the random suffix under MAX_VM_NAME_LENGTH.
            let max_prefix = crate::data::MAX_VM_NAME_LENGTH - "pool--".len() - suffix.len();
            let prefix = &pool.name[..pool.name.len().min(max_prefix)];
            let machine = format!("pool-{prefix}-{suffix}");
            let db = state.db().clone();
            let pool_name = pool.name.clone();
            let machine_for_reservation = machine.clone();
            let reserved = match tokio::task::spawn_blocking(move || {
                db.reserve_fork_pool_slot(
                    &pool_name,
                    &machine_for_reservation,
                    crate::util::current_timestamp(),
                )
            })
            .await
            {
                Ok(Ok(reserved)) => reserved,
                Ok(Err(error)) => {
                    tracing::warn!(pool = %pool.name, %error, "failed to reserve fork pool worker");
                    break;
                }
                Err(error) => {
                    tracing::warn!(pool = %pool.name, %error, "fork pool reservation task failed");
                    break;
                }
            };
            if !reserved {
                break;
            }
            machines.push(machine);
        }
        if machines.is_empty() {
            return;
        }

        let retained_snapshot = retained_snapshots.lock().get(&pool.golden).cloned();
        let retained_snapshot_hint = retained_snapshot.clone();
        let (result_tx, mut result_rx) = tokio::sync::mpsc::unbounded_channel();
        let (snapshot_ready_tx, snapshot_ready_rx) = tokio::sync::oneshot::channel();
        let provision = fork_held_machines_inner(
            state.clone(),
            ForkHeldBatch {
                golden: pool.golden.clone(),
                clones: machines.clone(),
                share_weights: pool.share_weights,
                ready_timeout: Duration::from_secs(pool.ready_timeout_secs),
                retained_snapshot,
                boot_slots,
                snapshot_ready: Some(snapshot_ready_tx),
            },
            result_tx,
        );
        let process_results = async {
            let mut completed = std::collections::HashSet::new();
            while let Some((machine, result)) = result_rx.recv().await {
                completed.insert(machine.clone());
                Self::finish_provision(&state, &pool, machine, result).await;
            }
            completed
        };
        let manage_provision = async {
            tokio::pin!(provision);
            let mut golden_guard = Some(golden_guard);
            let mut published_early = false;
            let provision_result = tokio::select! {
                ready = snapshot_ready_rx => {
                    if let Ok(snapshot) = ready {
                        update_retained_snapshot(
                            &mut retained_snapshots.lock(),
                            &pool.golden,
                            retained_snapshot_hint.as_ref(),
                            Some(snapshot),
                        );
                        published_early = true;
                        drop(golden_guard.take());
                    }
                    provision.await
                }
                result = &mut provision => result,
            };
            (provision_result, published_early)
        };
        let ((provision_result, published_early), completed) =
            tokio::join!(manage_provision, process_results);

        match provision_result {
            Ok(outcome) => {
                if !published_early {
                    update_retained_snapshot(
                        &mut retained_snapshots.lock(),
                        &pool.golden,
                        retained_snapshot_hint.as_ref(),
                        outcome.retained_snapshot,
                    );
                }
            }
            Err(error) => {
                tracing::warn!(pool = %pool.name, error = ?error, workers = machines.len(), "failed to prepare fork pool worker batch");
                for machine in machines {
                    if !completed.contains(&machine) {
                        record_provision("failed", "batch");
                        Self::retire_failed_provision(&state, machine, format!("{error:?}")).await;
                    }
                }
            }
        }
    }

    async fn finish_provision(
        state: &Arc<ApiState>,
        pool: &ForkPoolRecord,
        machine: String,
        result: Result<crate::api::types::MachineInfo, crate::api::error::ApiError>,
    ) {
        let retirement_reason = match result {
            Ok(info) if info.forkpoint_held => {
                let db = state.db().clone();
                let machine_ready = machine.clone();
                match tokio::task::spawn_blocking(move || {
                    db.mark_fork_pool_slot_ready(&machine_ready, crate::util::current_timestamp())
                })
                .await
                {
                    Ok(Ok(true)) => {
                        record_provision("ready", "none");
                        tracing::info!(pool = %pool.name, machine = %machine, "fork pool worker ready");
                        return;
                    }
                    Ok(Ok(false)) => {
                        record_provision("failed", "pool_changed");
                        tracing::info!(pool = %pool.name, machine = %machine, "pool changed while worker was provisioning; retiring worker");
                        "pool changed while worker was provisioning".into()
                    }
                    Ok(Err(error)) => {
                        record_provision("failed", "state");
                        tracing::warn!(pool = %pool.name, machine = %machine, %error, "failed to mark fork pool worker ready");
                        error.to_string()
                    }
                    Err(error) => {
                        record_provision("failed", "state_task");
                        tracing::warn!(pool = %pool.name, machine = %machine, %error, "fork pool ready task failed");
                        error.to_string()
                    }
                }
            }
            Ok(_) => {
                record_provision("failed", "not_held");
                tracing::warn!(pool = %pool.name, machine = %machine, "forked pool worker was not held");
                "forked pool worker was not held".into()
            }
            Err(error) => {
                let detail = format!("{error:?}");
                record_provision("failed", provision_failure_reason(&detail));
                tracing::warn!(pool = %pool.name, machine = %machine, error = ?error, "failed to provision fork pool worker");
                detail
            }
        };
        Self::retire_failed_provision(state, machine, retirement_reason).await;
    }

    async fn retire_failed_provision(state: &Arc<ApiState>, machine: String, message: String) {
        let db = state.db().clone();
        let _ = tokio::task::spawn_blocking(move || {
            db.mark_fork_pool_slot_retiring(
                &machine,
                crate::util::current_timestamp(),
                Some(message),
            )
        })
        .await;
    }
}

fn update_retained_snapshot(
    snapshots: &mut std::collections::HashMap<String, crate::agent::fork::RetainedForkSnapshot>,
    golden: &str,
    prior_hint: Option<&crate::agent::fork::RetainedForkSnapshot>,
    proven: Option<crate::agent::fork::RetainedForkSnapshot>,
) {
    if let Some(snapshot) = proven {
        snapshots.insert(golden.to_string(), snapshot);
    } else if snapshots.get(golden) == prior_hint {
        snapshots.remove(golden);
    }
}

fn retain_existing_checkpoint_sources(
    snapshots: &mut std::collections::HashMap<String, crate::agent::fork::RetainedForkSnapshot>,
    checkpoint_sources: &std::collections::HashSet<String>,
) -> Vec<String> {
    let stale = snapshots
        .keys()
        .filter(|golden| !checkpoint_sources.contains(golden.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    snapshots.retain(|golden, _| checkpoint_sources.contains(golden.as_str()));
    stale
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn snapshot(id: &str, pid: i32) -> crate::agent::fork::RetainedForkSnapshot {
        crate::agent::fork::RetainedForkSnapshot {
            path: PathBuf::from(format!("/golden/s/{id}")),
            golden_pid: pid,
            golden_pid_start_time: pid as u64 * 10,
        }
    }

    #[test]
    fn successful_batch_records_the_proven_snapshot() {
        let mut snapshots = std::collections::HashMap::new();
        let proven = snapshot("12345678", 1);
        update_retained_snapshot(&mut snapshots, "golden", None, Some(proven.clone()));
        assert_eq!(snapshots.get("golden"), Some(&proven));
    }

    #[test]
    fn failed_reuse_drops_only_the_snapshot_that_was_attempted() {
        let prior = snapshot("12345678", 1);
        let newer = snapshot("abcdef01", 2);
        let mut snapshots = std::collections::HashMap::from([("golden".into(), prior.clone())]);
        update_retained_snapshot(&mut snapshots, "golden", Some(&prior), None);
        assert!(!snapshots.contains_key("golden"));

        snapshots.insert("golden".into(), newer.clone());
        update_retained_snapshot(&mut snapshots, "golden", Some(&prior), None);
        assert_eq!(snapshots.get("golden"), Some(&newer));
    }

    #[test]
    fn reconciliation_keeps_plain_machine_checkpoints_without_a_pool() {
        let plain = snapshot("12345678", 1);
        let pooled = snapshot("abcdef01", 2);
        let orphan = snapshot("deadbeef", 3);
        let mut snapshots = std::collections::HashMap::from([
            ("plain-machine".into(), plain.clone()),
            ("pool-golden".into(), pooled.clone()),
            ("removed-machine".into(), orphan),
        ]);
        let checkpoint_sources = std::collections::HashSet::from([
            "plain-machine".to_string(),
            "pool-golden".to_string(),
        ]);

        let mut stale = retain_existing_checkpoint_sources(&mut snapshots, &checkpoint_sources);
        stale.sort();

        assert_eq!(stale, vec!["removed-machine"]);
        assert_eq!(snapshots.get("plain-machine"), Some(&plain));
        assert_eq!(snapshots.get("pool-golden"), Some(&pooled));
    }

    #[test]
    fn provisioning_metrics_classify_the_affected_kvm_enomem() {
        assert_eq!(
            provision_failure_reason(
                "Failure during vcpu run: Cannot allocate memory (os error 12)"
            ),
            "kvm_enomem"
        );
        assert_eq!(
            provision_failure_reason("clone agent did not respond to ping within timeout"),
            "agent_timeout"
        );
        assert_eq!(
            provision_failure_reason("CUDA clone worker failed during reconstruction"),
            "cuda_reconstruction"
        );
        assert_eq!(provision_failure_reason("agent never pinged"), "other");
    }
}
