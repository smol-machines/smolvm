//! An observed exit retains its execution identity until teardown completes.

use super::*;

pub(super) fn pending(record: &ContainerRecord) -> bool {
    record.state.status == "exited" && record.saved_execution.is_some()
}

fn needs_wake(record: &ContainerRecord) -> bool {
    pending(record) || record.state.status == "restarting"
}

/// Wake the existing workload owner; recovery and admission remain its job.
pub(in crate::engine) async fn wake_pending(engine: &Engine, id: &str) -> ApiResult<()> {
    if !engine
        .store
        .load_container(id)
        .map_err(internal_execution)?
        .is_some_and(|record| needs_wake(&record))
    {
        return Ok(());
    }
    let request = axum::http::Request::builder()
        .uri("/_ping")
        .body(axum::body::Body::empty())
        .map_err(internal_execution)?;
    let wake = async {
        let response = super::super::supervisor::forward(engine, id, request).await?;
        if !response.status().is_success() {
            return Err(ApiError::conflict("supervisor refused cleanup recovery"));
        }
        axum::body::to_bytes(response.into_body(), 64)
            .await
            .map_err(internal_execution)?;
        Ok::<_, ApiError>(())
    }
    .await;
    if wake.is_err()
        && engine
            .store
            .load_container(id)
            .map_err(internal_execution)?
            .is_some()
    {
        return Err(ApiError::conflict(
            "pending container cleanup recovery could not start; retry the operation",
        ));
    }
    Ok(())
}

/// A cancellation can commit just before the adapter dies. Reconcile durable
/// pending work once at adapter startup, without blocking its API or polling.
pub(in crate::engine) fn spawn_pending_recovery(engine: &Arc<Engine>) {
    let ids: Vec<_> = engine
        .containers
        .read()
        .values()
        .filter(|c| needs_wake(&c.record()))
        .map(|c| c.id())
        .collect();
    if ids.is_empty() {
        return;
    }
    let activity = engine.activity.hold();
    let engine = engine.clone();
    tokio::spawn(async move {
        let _activity = activity;
        let mut tasks = tokio::task::JoinSet::new();
        for id in ids {
            if tasks.len() >= 4 {
                if let Some(Err(error)) = tasks.join_next().await {
                    tracing::warn!(%error, "pending container recovery task stopped");
                }
            }
            let engine = engine.clone();
            tasks.spawn(async move {
                if let Err(error) = wake_pending(&engine, &id).await {
                    tracing::warn!(container = %id, error = %error.message, "pending container recovery requires retry");
                }
            });
        }
        while let Some(result) = tasks.join_next().await {
            if let Err(error) = result {
                tracing::warn!(%error, "pending container recovery task stopped");
            }
        }
    });
}

pub(super) async fn wait_for_admission(
    engine: &Engine,
    c: &Container,
) -> Vec<crate::db::transfer_admission::MutationGuard> {
    let mut delay = Duration::from_millis(100);
    let mut previous = None;
    loop {
        match c.admit_mutation(engine, false) {
            Ok(admission) => return admission,
            Err(error) => {
                if previous.as_deref() != Some(error.message.as_str()) {
                    tracing::info!(container = %c.id(), error = %error.message, "container exit cleanup deferred");
                    previous = Some(error.message);
                }
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(2));
            }
        }
    }
}

/// Names alone never authorize a delayed stop: both the database incarnation
/// and the VMM execution must still be the ones retained before the exit.
pub(super) fn reviewed_machine(
    engine: &Engine,
    record: &ContainerRecord,
) -> ApiResult<Option<crate::config::VmRecord>> {
    let saved = record
        .saved_execution
        .as_ref()
        .ok_or_else(|| ApiError::conflict("pending exit has no retained execution identity"))?;
    let member = saved
        .machine_execution
        .as_ref()
        .ok_or_else(|| ApiError::conflict("pending exit has no retained machine identity"))?;
    if !pending(record)
        || saved.container_generation == 0
        || saved.container_generation != record.execution_generation
        || member.name != saved.machine
        || member.created_at != saved.machine_created_at
    {
        return Err(ApiError::conflict(
            "pending container exit identity changed",
        ));
    }
    let vm = engine.db.get_vm(&member.name).map_err(internal_execution)?;
    let Some(vm) = vm else { return Ok(None) };
    if vm.database_identity.as_ref().map(|id| id.generation()) != member.generation.as_deref()
        || member.generation.is_none()
        || vm.created_at != member.created_at
        || vm.labels.get(MACHINE_LABEL) != Some(&saved.owner)
    {
        return Err(ApiError::conflict("pending exit machine was replaced"));
    }
    let stopped = vm.state == crate::config::RecordState::Stopped
        && vm.pid.is_none()
        && vm.pid_start_time.is_none();
    if saved.machine_execution_identity.is_none()
        || saved.machine_execution_identity != vm.execution_identity
        || (!stopped && (vm.pid, vm.pid_start_time) != (member.pid, member.pid_start_time))
    {
        return Err(ApiError::conflict("pending exit machine execution changed"));
    }
    Ok(Some(vm))
}

pub(super) async fn stop_original_machine(
    engine: &Arc<Engine>,
    record: &ContainerRecord,
) -> ApiResult<()> {
    let engine = engine.clone();
    let record = record.clone();
    tokio::task::spawn_blocking(move || {
        let vm = reviewed_machine(&engine, &record)?;
        // A guest owns exports, not its host VM. Pin the original execution
        // through all removals, rather than resolving the host's current name.
        if record.network_host().is_some() {
            let exports = vm
                .as_ref()
                .map(|vm| crate::attach::OwnedShares::new(&engine.db, vm))
                .transpose()
                .map_err(mutation_error)?;
            if let Some(exports) = &exports {
                for (index, share) in record.guest_shares.iter().enumerate() {
                    exports
                        .remove(
                            &record.guest_share_name(index),
                            &share.source,
                            share.read_only,
                        )
                        .map_err(mutation_error)?;
                }
            }
            let saved = record.saved_execution.as_ref().unwrap();
            if let Some(generation) = &saved.image_generation {
                super::super::image_share::Lease::release_retained(
                    engine.store.root(),
                    &saved.machine,
                    &saved.owner,
                    generation,
                    &record.id,
                    record.guest_image_share(),
                    exports.as_ref(),
                )
                .map_err(mutation_error)?;
            }
            return Ok(());
        }
        let Some(vm) = vm else { return Ok(()) };
        if vm.state == crate::config::RecordState::Stopped {
            return Ok(());
        }
        crate::embedded::control::stop_vm_record_with_timeout(&engine.db, &vm, Some(Duration::ZERO))
            .map_err(mutation_error)
    })
    .await
    .map_err(internal_execution)?
}

/// Commit cleanup completion and the restart decision together, so a crash
/// cannot lose an on-failure restart or charge its retry count twice.
pub(super) fn finish(engine: &Engine, c: &Container) -> ApiResult<Option<u64>> {
    let current = c.record();
    if !pending(&current) || current.host_config.auto_remove {
        return Err(ApiError::conflict(
            "container has no completed exit to finalize",
        ));
    }
    let mut restart = None;
    c.update_durable(engine, |record| {
        record.saved_execution = None;
        if should_restart(record, record.state.exit_code) {
            record.state.status = "restarting".into();
            record.restart_count = record.restart_count.saturating_add(1);
            restart = Some(record.execution_generation);
        }
    })?;
    Ok(restart)
}

fn restart_wait(record: &ContainerRecord) -> Duration {
    let Ok(finished) = humantime::parse_rfc3339(&record.state.finished_at) else {
        return Duration::ZERO;
    };
    let ran = super::super::util::unix_seconds(&record.state.finished_at)
        - super::super::util::unix_seconds(&record.state.started_at);
    let attempt = if ran >= 10 {
        0
    } else {
        record.restart_count.saturating_sub(1)
    };
    let delay = Duration::from_millis(100u64.saturating_mul(1 << attempt.min(10)))
        .min(Duration::from_secs(60));
    finished
        .checked_add(delay)
        .and_then(|deadline| deadline.duration_since(std::time::SystemTime::now()).ok())
        .unwrap_or_default()
}

struct RestartAdmission {
    _operation: tokio::sync::OwnedMutexGuard<()>,
    _admission: Vec<crate::db::transfer_admission::MutationGuard>,
}

async fn wait_for_restart_admission(
    engine: &Engine,
    c: &Arc<Container>,
    generation: u64,
) -> Option<RestartAdmission> {
    let mut delay = Duration::from_millis(100);
    let mut previous = None;
    loop {
        let operation = c.op.clone().lock_owned().await;
        let record = c.record();
        if record.execution_generation != generation || record.state.status != "restarting" {
            return None;
        }
        if record.user_stopped {
            if let Err(error) = c.update_durable(engine, |r| {
                r.state.status = "exited".into();
                r.running_at_shutdown = false;
            }) {
                tracing::error!(container = %c.id(), error = %error.message, "could not retain stopped restart policy");
            }
            return None;
        }
        match c.admit_mutation(engine, false) {
            Ok(admission) => {
                return Some(RestartAdmission {
                    _operation: operation,
                    _admission: admission,
                })
            }
            Err(error) => {
                if previous.as_deref() != Some(error.message.as_str()) {
                    tracing::info!(container = %c.id(), error = %error.message, "container restart deferred");
                    previous = Some(error.message);
                }
            }
        }
        drop(operation);
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_secs(2));
    }
}

pub(super) async fn resume_restart(engine: Arc<Engine>, c: Arc<Container>, generation: u64) {
    tokio::time::sleep(restart_wait(&c.record())).await;
    let Some(_admission) = wait_for_restart_admission(&engine, &c, generation).await else {
        return;
    };
    if let Err(error) = start_boxed(engine.clone(), c.clone()).await {
        tracing::warn!(container = %c.id(), error = %error.message, "restart failed");
        if let Err(persist) = c.update_durable(&engine, |r| {
            r.state.status = "exited".into();
            r.state.error = error.message;
        }) {
            tracing::error!(container = %c.id(), error = %persist.message, "could not retain restart failure");
        }
    }
}

#[cfg(test)]
mod tests;
