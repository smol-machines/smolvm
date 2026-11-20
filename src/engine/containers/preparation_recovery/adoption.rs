//! Upgrade terminal cleanup ownership without reattaching a live execution.

use super::*;

fn same_execution(a: &ContainerRecord, b: &ContainerRecord) -> bool {
    a.id == b.id
        && a.created == b.created
        && a.execution_generation == b.execution_generation
        && a.state.started_at == b.state.started_at
}

fn stable_configuration(record: &ContainerRecord) -> ApiResult<serde_json::Value> {
    let mut record = record.clone();
    record.state = StateRecord::default();
    record.agent_socket = None;
    record.saved_execution = None;
    record.execution_suspended = false;
    record.restart_count = 0;
    record.running_at_shutdown = false;
    record.user_stopped = false;
    for endpoint in record.networks.values_mut() {
        endpoint.ip.clear();
        endpoint.prefix_len = 0;
        endpoint.gateway.clear();
        endpoint.endpoint_id.clear();
        endpoint.ip6.clear();
        endpoint.prefix_len6 = 0;
        endpoint.gateway6.clear();
    }
    serde_json::to_value(record).map_err(internal_execution)
}

fn execution_roots<'a>(
    engine: &Engine,
    journal: &'a Journal,
    retained: &ContainerRecord,
) -> ApiResult<Vec<&'a Root>> {
    // Siblings may already have completed automatic removal. Resolve the
    // retained execution's own roots, requiring an original identity for each.
    let mut paths = BTreeSet::from([
        std::path::absolute(engine.store.root()).map_err(internal_execution)?,
        std::path::absolute(engine.store.container_dir(&retained.id))
            .map_err(internal_execution)?,
    ]);
    let canonical_engine =
        std::fs::canonicalize(engine.store.root()).map_err(internal_execution)?;
    for mount in &retained.mounts {
        if mount.kind == "volume" {
            paths.insert(
                canonical_engine
                    .join("volumes")
                    .join(&mount.source)
                    .join("_data"),
            );
        }
    }
    paths
        .iter()
        .map(|path| {
            journal
                .roots
                .iter()
                .find(|root| root.path == *path)
                .ok_or_else(|| {
                    ApiError::conflict("preparation journal is missing an execution's data root")
                })
        })
        .collect()
}

fn pending_record(
    engine: &Engine,
    journal: &Journal,
    retained: &ContainerRecord,
) -> ApiResult<ContainerRecord> {
    for root in execution_roots(engine, journal, retained)? {
        root.check().map_err(mutation_error)?;
    }
    let mut current = engine
        .store
        .load_container(&retained.id)
        .map_err(internal_execution)?
        .ok_or_else(|| ApiError::conflict("terminal container disappeared during adoption"))?;
    if !same_execution(&current, retained)
        || !matches!(current.state.status.as_str(), "exited" | "restarting")
        || stable_configuration(&current)? != stable_configuration(retained)?
    {
        return Err(ApiError::conflict(
            "terminal container changed during adoption",
        ));
    }
    let saved = retained
        .saved_execution
        .clone()
        .ok_or_else(|| ApiError::conflict("retained preparation execution is missing"))?;
    current.saved_execution = Some(saved);
    current.state.status = "exited".into();
    current.state.pid = 0;
    current.execution_suspended = false;
    // The older owner can charge a restart before admission denies its start.
    // The canonical pending-exit transition charges that decision exactly once.
    current.restart_count = retained.restart_count;
    current.running_at_shutdown = false;
    exit_cleanup::reviewed_machine(engine, &current)?;
    Ok(current)
}

pub(super) async fn pass(
    engine: &Arc<Engine>,
    operation: &str,
) -> ApiResult<(Vec<String>, Vec<ContainerRecord>)> {
    let db = engine.db.clone();
    let operation = operation.to_owned();
    let Some(guard) = tokio::task::spawn_blocking(move || db.preparation_recovery(&operation))
        .await
        .map_err(internal_execution)?
        .map_err(mutation_error)?
    else {
        return Ok((vec![], vec![]));
    };
    let journal = decode(&guard.preparation, &guard.data).map_err(mutation_error)?;
    // The engine root must still be the one that reserved this journal, even
    // when all container directories have already been removed normally.
    let engine_path = std::path::absolute(engine.store.root()).map_err(internal_execution)?;
    journal
        .roots
        .iter()
        .find(|root| root.path == engine_path)
        .ok_or_else(|| ApiError::conflict("preparation recovery engine root is missing"))?
        .check()
        .map_err(mutation_error)?;
    let mut live = Vec::new();
    let mut wake = Vec::new();
    let mut complete = true;
    for retained in &journal.executions {
        let current = engine
            .store
            .load_container(&retained.id)
            .map_err(internal_execution)?;
        let Some(current) = current else { continue };
        if !same_execution(&current, retained) {
            continue;
        }
        if matches!(current.state.status.as_str(), "running" | "paused") {
            live.push(retained.clone());
            complete = false;
            continue;
        }
        if current
            .saved_execution
            .as_ref()
            .is_some_and(|saved| saved.machine_execution_identity.is_some())
        {
            // A new owner may be completing its durable write. Only sync the
            // canonical record if it has no writer; never signal that owner.
            if let Some(owner) =
                super::super::super::supervisor::available_terminal_owner(engine, &current.id)
                    .await?
            {
                let current = engine
                    .store
                    .load_container(&current.id)
                    .map_err(internal_execution)?
                    .ok_or_else(|| {
                        ApiError::conflict("adopted cleanup disappeared while acquiring ownership")
                    })?;
                exit_cleanup::reviewed_machine(engine, &current)?;
                engine
                    .store
                    .save_container_durable(&current)
                    .map_err(internal_execution)?;
                drop(owner);
            } else {
                complete = false;
            }
            wake.push(current.id);
            continue;
        }
        let pending = pending_record(engine, &journal, retained)?;
        let engine_path = std::path::absolute(engine.store.root()).map_err(internal_execution)?;
        let paths: Vec<_> = execution_roots(engine, &journal, retained)?
            .into_iter()
            .filter(|root| root.path != engine_path)
            .map(|root| root.path.clone())
            .collect();
        let vm = exit_cleanup::reviewed_machine(engine, &pending)?;
        let db = engine.db.clone();
        let reviewed = vm.clone();
        let (storage, control) = tokio::task::spawn_blocking(move || {
            let storage = db.admit_storage_mutation(&paths)?;
            let control = reviewed
                .as_ref()
                .map(|vm| db.reserve_vm_control(vm, &crate::agent::vm_data_dir(&vm.name), &paths))
                .transpose()?;
            Ok::<_, crate::Error>((storage, control))
        })
        .await
        .map_err(internal_execution)?
        .map_err(mutation_error)?;
        // Pin only this VM and its storage. Unrelated legacy exits must remain
        // admitted while a private owner drains its existing connections.
        let owner = if let Some(control) = &control {
            let vm = vm.as_ref().unwrap();
            super::super::super::supervisor::terminal_owner(
                engine,
                &retained.id,
                vm.pid,
                control,
                || {
                    control.validate_staged_record(vm).map_err(mutation_error)?;
                    pending_record(engine, &journal, retained).map(|_| ())
                },
            )
            .await?
        } else {
            // With no VM row, do not signal an owner that could begin a new
            // execution. An available singleton lock proves it has exited.
            super::super::super::supervisor::available_terminal_owner(engine, &retained.id)
                .await?
                .ok_or_else(|| {
                    ApiError::conflict(
                        "retired machine's supervisor is still exiting; retry cancellation",
                    )
                })?
        };
        // The old supervisor can finish its network/restart bookkeeping while
        // shutting down. Preserve its final exit code and user-stop decision.
        let pending = pending_record(engine, &journal, retained)?;
        engine
            .store
            .save_container_durable(&pending)
            .map_err(internal_execution)?;
        wake.push(pending.id);
        drop(owner);
        drop(control);
        drop(storage);
    }
    if complete {
        guard.retire().map_err(mutation_error)?;
    } else {
        drop(guard);
    }
    Ok((wake, live))
}

pub(in crate::engine) async fn recover_cancelled(
    engine: &Arc<Engine>,
    operation: &str,
) -> ApiResult<()> {
    // Each repeat must observe an additional terminal execution. This is a
    // bounded cancellation reconciliation, not an idle or periodic poller.
    for _ in 0..=1024 {
        let (wake, live) = pass(engine, operation).await?;
        for id in wake {
            wake_pending(engine, &id).await?;
        }
        // A shared-host command can exit while another retained container's
        // scoped ownership defers cleanup. Recheck after those scopes drop.
        let mut raced = false;
        for retained in live {
            if let Some(current) = engine
                .store
                .load_container(&retained.id)
                .map_err(internal_execution)?
            {
                raced |= same_execution(&current, &retained)
                    && matches!(current.state.status.as_str(), "exited" | "restarting");
            }
        }
        if !raced {
            return Ok(());
        }
    }
    Err(ApiError::conflict(
        "preparation recovery changed repeatedly; retry cancellation",
    ))
}

pub(in crate::engine) fn spawn_recovery(engine: &Arc<Engine>) {
    let engine = engine.clone();
    let activity = engine.activity.hold();
    tokio::spawn(async move {
        let _activity = activity;
        let db = engine.db.clone();
        let operations =
            match tokio::task::spawn_blocking(move || db.pending_preparation_recoveries()).await {
                Ok(Ok(operations)) => operations,
                _ => {
                    tracing::warn!("could not read preparation recovery journals");
                    return;
                }
            };
        // Reconcile startup journals sequentially; ownership remains per VM.
        for operation in operations {
            if let Err(error) = recover_cancelled(&engine, &operation).await {
                tracing::warn!(%operation,error=%error.message,"preparation cleanup requires retry");
            }
        }
    });
}
