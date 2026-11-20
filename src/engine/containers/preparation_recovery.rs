//! Retain execution ownership before an older supervisor can discard it.
//!
//! The journal commits in the same transaction as transfer admission. It is
//! separate from the reviewed inventory, whose fingerprint remains unchanged.

use super::*;
use crate::db::transfer_admission::preparation::Preparation;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    operation: String,
    fingerprint: String,
    roots: Vec<Root>,
    executions: Vec<ContainerRecord>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Root {
    path: PathBuf,
    device: u64,
    inode: u64,
}

fn conflict(message: &str) -> crate::Error {
    crate::Error::agent_conflict("recover preparation", message)
}

impl Root {
    fn read(path: &Path) -> crate::Result<Self> {
        // Retain the lookup path: canonicalizing it away would hide a later
        // symlink retarget while the original directory still exists.
        let path = std::path::absolute(path)?;
        let metadata = std::fs::metadata(&path)?;
        if !metadata.is_dir() {
            return Err(conflict("preparation root is not a directory"));
        }
        Ok(Self {
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    fn check(&self) -> crate::Result<()> {
        let current = Self::read(&self.path)?;
        if (current.device, current.inode) != (self.device, self.inode) {
            return Err(conflict("preparation data directory was replaced"));
        }
        Ok(())
    }
}

/// Called before admission, then protected by the ordinary post-claim review.
/// Never infer an execution's history from an already terminal legacy record.
pub(in crate::engine) fn capture(
    engine: &Engine,
    operation: &str,
    fingerprint: &str,
    selected: &[String],
    protected_roots: &[PathBuf],
) -> ApiResult<Option<Vec<u8>>> {
    let mut executions = Vec::new();
    for id in selected {
        let mut record = engine
            .store
            .load_container(id)
            .map_err(internal_execution)?
            .ok_or_else(|| ApiError::conflict("container disappeared before preparation"))?;
        let Some(saved) = record.saved_execution.as_mut() else {
            if matches!(
                record.state.status.as_str(),
                "running" | "paused" | "restarting"
            ) {
                return Err(ApiError::conflict("container has no retained execution; retry preparation after its current transition"));
            }
            if record.state.status == "exited" {
                let machine_pending = record.network_host().is_none()
                    && engine
                        .db
                        .get_vm(&record.machine)
                        .map_err(internal_execution)?
                        .is_some_and(|vm| {
                            vm.pid.is_some()
                                || vm.paused_checkpoint.is_some()
                                || vm.state != crate::config::RecordState::Stopped
                        });
                if machine_pending
                    || record.host_config.auto_remove
                    || should_restart(&record, record.state.exit_code)
                {
                    return Err(ApiError::conflict("container exit cleanup has no retained identity; finish its transition before preparation"));
                }
            }
            continue;
        };
        if saved.machine_execution_identity.is_some() {
            continue;
        }
        let origin = saved.session.origin();
        if !matches!(record.state.status.as_str(), "running" | "paused")
            || record.execution_generation == 0
            || origin.generation != record.execution_generation
            || origin.started_at != record.state.started_at
            || record.execution_suspended
        {
            return Err(ApiError::conflict(
                "older container execution changed before preparation",
            ));
        }
        let vm = engine
            .db
            .get_vm(&saved.machine)
            .map_err(internal_execution)?
            .ok_or_else(|| {
                ApiError::conflict("container machine disappeared before preparation")
            })?;
        if vm.created_at != saved.machine_created_at
            || vm.labels.get(MACHINE_LABEL) != Some(&saved.owner)
            || vm.pid.map(i64::from) != Some(record.state.pid)
            || vm.pid_start_time.is_none()
        {
            return Err(ApiError::conflict(
                "older container machine changed before preparation",
            ));
        }
        let generation = vm
            .database_identity
            .as_ref()
            .ok_or_else(|| ApiError::conflict("container machine has no durable identity"))?
            .generation()
            .to_owned();
        saved.container_generation = record.execution_generation;
        saved.machine_execution = Some(crate::db::transfer_admission::Member {
            name: vm.name,
            generation: Some(generation),
            created_at: vm.created_at,
            pid: vm.pid,
            pid_start_time: vm.pid_start_time,
        });
        saved.machine_execution_identity = Some(vm.execution_identity.ok_or_else(|| {
            ApiError::conflict("container machine has no durable execution identity")
        })?);
        executions.push(record);
    }
    if executions.is_empty() {
        return Ok(None);
    }
    let paths: BTreeSet<_> = protected_roots
        .iter()
        .cloned()
        .chain(std::iter::once(engine.store.root().to_path_buf()))
        .chain(executions.iter().map(|r| engine.store.container_dir(&r.id)))
        .collect();
    let roots = paths
        .iter()
        .map(|p| Root::read(p))
        .collect::<crate::Result<Vec<_>>>()
        .map_err(internal_execution)?;
    let bytes = serde_json::to_vec(&Journal {
        version: 1,
        operation: operation.into(),
        fingerprint: fingerprint.into(),
        roots,
        executions,
    })
    .map_err(internal_execution)?;
    if bytes.len() > 16 * 1024 * 1024 {
        return Err(ApiError::conflict(
            "preparation execution journal exceeds its size limit",
        ));
    }
    Ok(Some(bytes))
}

/// Runs inside the cancellation transaction's exclusive admission gate.
/// This rejects already lost ownership, but cannot exclude a subsequent exit:
/// legacy cleanup fails immediately against the gate. Retain the journal.
pub(in crate::engine) fn check_cancel(
    engine: &Engine,
    preparation: &Preparation,
    bytes: Option<&[u8]>,
) -> crate::Result<()> {
    let Some(bytes) = bytes else { return Ok(()) };
    let journal = decode(preparation, bytes)?;
    if preparation.phase == crate::db::transfer_admission::preparation::Phase::Cancelled {
        return Ok(());
    }
    for root in &journal.roots {
        root.check()?;
    }
    for retained in &journal.executions {
        let saved = retained.saved_execution.as_ref().unwrap();
        let current = engine
            .store
            .load_container(&retained.id)?
            .ok_or_else(|| conflict("retained preparation container disappeared"))?;
        if current.created != retained.created
            || current.execution_generation != retained.execution_generation
            || current.state.started_at != retained.state.started_at
        {
            return Err(conflict("retained preparation container execution changed"));
        }
        if let Some(current_saved) = &current.saved_execution {
            if current_saved.session.origin().generation != saved.session.origin().generation
                || current_saved.session.origin().started_at != saved.session.origin().started_at
                || current_saved.machine != saved.machine
                || current_saved.machine_created_at != saved.machine_created_at
                || current_saved.owner != saved.owner
                || (current_saved.machine_execution_identity.is_some()
                    && (current_saved.machine_execution_identity
                        != saved.machine_execution_identity
                        || current_saved.machine_execution != saved.machine_execution
                        || current_saved.container_generation != saved.container_generation))
            {
                return Err(conflict("preparation cleanup ownership changed"));
            }
        } else if matches!(current.state.status.as_str(), "running" | "paused") {
            return Err(conflict(
                "live preparation container lost its execution identity",
            ));
        }
        if !matches!(
            current.state.status.as_str(),
            "running" | "paused" | "exited" | "restarting"
        ) {
            return Err(conflict(
                "retained preparation container has an unsupported transition",
            ));
        }
    }
    Ok(())
}

fn decode(preparation: &Preparation, bytes: &[u8]) -> crate::Result<Journal> {
    if bytes.len() > 16 * 1024 * 1024 {
        return Err(conflict(
            "preparation execution journal exceeds its size limit",
        ));
    }
    let journal: Journal = serde_json::from_slice(bytes)
        .map_err(|_| conflict("preparation execution journal is unreadable"))?;
    if journal.version != 1
        || journal.operation != preparation.operation
        || journal.fingerprint != preparation.fingerprint
        || journal.executions.is_empty()
        || journal.executions.len() > 1024
        || journal.roots.is_empty()
        || journal.roots.len() > 2049
        || journal.roots.iter().any(|root| !root.path.is_absolute())
    {
        return Err(conflict("preparation execution journal identity changed"));
    }
    let mut ids = BTreeSet::new();
    for retained in &journal.executions {
        if !super::super::store::valid_id(&retained.id)
            || !ids.insert(&retained.id)
            || retained.execution_generation == 0
            || !preparation.inventory["selected"]
                .as_array()
                .is_some_and(|ids| ids.iter().any(|id| id.as_str() == Some(&retained.id)))
        {
            return Err(conflict("invalid retained preparation container"));
        }
        let saved = retained
            .saved_execution
            .as_ref()
            .ok_or_else(|| conflict("preparation journal has no retained execution"))?;
        if saved.container_generation != retained.execution_generation
            || saved.session.origin().generation != retained.execution_generation
            || saved.machine_execution.is_none()
            || saved.machine_execution_identity.is_none()
        {
            return Err(conflict(
                "preparation journal has incomplete execution identity",
            ));
        }
    }
    Ok(journal)
}

mod adoption;
pub(in crate::engine) use adoption::{recover_cancelled, spawn_recovery};

#[cfg(test)]
mod tests;
