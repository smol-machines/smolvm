//! Delete a reviewed machine without releasing its identity or disk ownership.
use crate::{agent::AgentManager, config::VmRecord, db::SmolvmDb, Error, Result};
use std::path::Path;

/// The caller holds the machine's lifecycle/fork-source lock throughout this
/// call. A cached manager is retained on failure so staged files can be repaired.
pub fn delete_machine_locked(
    db: &SmolvmDb,
    record: &VmRecord,
    manager: Option<&AgentManager>,
    stop_if_running: bool,
    allow_held: bool,
) -> Result<()> {
    crate::db::launch_admission::LaunchReview::from_record(record)?.validate(db)?;
    // A runtime root is owned storage, never an alias into another directory.
    // Check the unresolved leaf before the ownership guard canonicalizes paths.
    match std::fs::symlink_metadata(crate::agent::vm_data_dir(&record.name)) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(Error::agent_conflict("delete machine", "machine data directory is a symlink; restore its original location before deletion"));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(Error::storage("inspect machine data", error.to_string())),
    }
    refuse_dependents(db, &record.name)?;
    let live = record.is_process_alive();
    let held = record.held_process();
    if live && held.is_none() && !stop_if_running {
        return Err(Error::agent_conflict(
            "delete machine",
            "machine is still running; stop it before deletion",
        ));
    }
    let observer;
    let manager = if live && held.is_none() {
        if let Some(manager) = manager {
            Some(manager)
        } else {
            observer = AgentManager::for_existing_vm_record(record)?;
            observer.detach();
            Some(&observer)
        }
    } else {
        None
    };
    let mut ownership = if let Some(manager) = manager {
        manager.stop_for_deletion(record)?
    } else {
        db.reserve_vm_deletion_at(record, &crate::agent::vm_data_dir(&record.name))?
    };
    if record.is_process_alive() && record.held_process().is_none() {
        return Err(Error::agent_conflict(
            "delete machine",
            "machine process remains alive after shutdown",
        ));
    }
    // Persist the stop before destructive work, retaining the same fence.
    ownership.prepare_delete()?;
    if let Some(held) = held_process_delete_gate(record, allow_held)? {
        tracing::warn!(machine = %record.name, pid = held.pid,
            "explicit deletion leaves a kernel-held process behind");
    }
    refuse_dependents(db, &record.name)?;
    let removed = remove_owned_data_and_record(db, ownership, &record.name)?;
    if let Some(parent) = removed.golden.as_deref() {
        if let Err(error) =
            crate::agent::fork::collect_parent_generations_after_child_delete(db, parent)
        {
            tracing::warn!(%parent, %error, "could not collect unreferenced fork generation");
        }
    }
    Ok(())
}

/// Refuse deleting storage still held by the kernel unless explicitly forced.
pub fn held_process_delete_gate(
    record: &VmRecord,
    force: bool,
) -> Result<Option<crate::process::HeldProcess>> {
    let Some(held) = record.held_process() else {
        return Ok(None);
    };
    if force {
        return Ok(Some(held));
    }
    Err(Error::agent("delete machine", format!(
        "machine '{}' is stopped, but {}; pass --force to delete the machine and leave that process behind",
        record.name, held.explain())))
}

/// Requires confirmed process stop and retained execution ownership.
pub(crate) fn remove_owned_data_and_record(
    db: &SmolvmDb,
    ownership: crate::db::VmRecoveryGuard,
    name: &str,
) -> Result<VmRecord> {
    let runtime = ownership.runtime_dir();
    crate::agent::cleanup_dead_vm_runtime_at(name, db, runtime)?;
    smolvm_pack::extract::force_detach_layers_volume(&runtime.join("pack"));
    crate::process::free_vm_uid(&crate::agent::vm_uid_registry_dir(), runtime);
    remove_data_dir(name, runtime)?;
    crate::portable_checkpoint::remove_paused_layers(runtime)?;
    ownership.finish_delete()
}

fn refuse_dependents(db: &SmolvmDb, name: &str) -> Result<()> {
    let dependents = db.dependent_clones(name)?;
    if !dependents.is_empty() {
        return Err(Error::agent_conflict(
            "delete machine",
            format!(
                "machine '{name}' has dependent fork(s) ({}); delete descendants first",
                dependents.join(", ")
            ),
        ));
    }
    Ok(())
}

fn remove_data_dir(name: &str, runtime: &Path) -> Result<()> {
    // Inspect explicitly: exists() hides permission and I/O failures.
    match std::fs::symlink_metadata(runtime) {
        Ok(meta) if !meta.is_dir() || meta.file_type().is_symlink() => {
            return Err(Error::storage(
                "delete machine data",
                format!("{} is not a machine directory", runtime.display()),
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(Error::storage("inspect machine data", error.to_string())),
    }
    for attempt in 1..=6 {
        match std::fs::remove_dir_all(runtime) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::DirectoryNotEmpty && attempt < 6 => {
                tracing::warn!(
                    machine = name,
                    attempt,
                    "machine data changed during removal; retrying"
                );
                std::thread::sleep(std::time::Duration::from_millis(250 << attempt.min(4)));
            }
            Err(error) => {
                return Err(Error::storage(
                    "delete machine data",
                    format!(
                        "{}: {error}; repair host storage and retry deletion",
                        runtime.display()
                    ),
                ))
            }
        }
    }
    unreachable!("the final removal attempt returns its result")
}
