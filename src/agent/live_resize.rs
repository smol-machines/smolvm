//! Live disk growth shared by engine entry points.
//!
//! The caller holds its API/CLI lifecycle guard. This layer additionally
//! serializes the operation with cross-process checkpoint and branch capture.

use super::{fork, AgentClient, AgentManager};
use crate::config::{RecordState, VmRecord};
use crate::db::SmolvmDb;
use crate::storage::{DEFAULT_OVERLAY_SIZE_GIB, DEFAULT_STORAGE_SIZE_GIB};
use crate::{Error, Result};
use smolvm_protocol::{ManagedDisk, ONLINE_FILESYSTEM_GROWTH_CAPABILITY};
use std::time::Duration;

fn validate_growth(current: u64, requested: u64) -> Result<u64> {
    if requested == 0 || requested < current {
        return Err(Error::config(
            "live resize",
            "disk capacity cannot shrink or be zero",
        ));
    }
    requested
        .checked_mul(1 << 30)
        .ok_or_else(|| Error::config("live resize", "disk capacity overflows bytes"))
}

/// Grow running disks and their mounted filesystems without restarting the VM.
/// After the runtime confirms growth, record the new disk limit even if the
/// subsequent filesystem operation fails. Retrying the same limit then finishes
/// the filesystem operation instead of attempting to undo disk growth.
pub fn grow_disks(
    db: &SmolvmDb,
    name: &str,
    storage_gb: Option<u64>,
    overlay_gb: Option<u64>,
) -> Result<VmRecord> {
    let _source_guard = fork::lock_fork_source(name)?;
    let record = db
        .get_vm(name)?
        .ok_or_else(|| Error::VmNotFound { name: name.into() })?;
    if record.actual_state() != RecordState::Running {
        return Err(Error::agent_conflict(
            "live resize",
            "machine must be running",
        ));
    }
    if storage_gb.is_none() && overlay_gb.is_none() {
        return Err(Error::config(
            "live resize",
            "specify storage or overlay capacity",
        ));
    }
    if !db.dependent_clones(name)?.is_empty() {
        return Err(Error::agent_conflict(
            "live resize",
            "cannot modify a disk with dependent branches",
        ));
    }
    let mut requested = Vec::new();
    for (disk, id, current, target) in [
        (
            ManagedDisk::Storage,
            "storage",
            record.storage_gb.unwrap_or(DEFAULT_STORAGE_SIZE_GIB),
            storage_gb,
        ),
        (
            ManagedDisk::Overlay,
            "overlay",
            record.overlay_gb.unwrap_or(DEFAULT_OVERLAY_SIZE_GIB),
            overlay_gb,
        ),
    ] {
        if let Some(target) = target {
            requested.push((disk, id, target, validate_growth(current, target)?));
        }
    }
    let manager = AgentManager::for_vm(name)?;
    let mut client = AgentClient::connect(manager.vsock_socket())?;
    if !client.supports_capability(ONLINE_FILESYSTEM_GROWTH_CAPABILITY)? {
        return Err(Error::agent(
            "live resize",
            "running guest agent lacks online growth support; no disks changed",
        ));
    }
    let socket = fork::control_socket_path(name);
    let capabilities = fork::control_socket_cmd(&socket, "GROW_DISK_CAPABILITIES")?;
    if capabilities.trim() != "OK grow-disk-v1" {
        return Err(Error::agent(
            "live resize",
            "running runtime lacks online disk growth support; no disks changed",
        ));
    }
    for (disk, id, target, bytes) in requested {
        let reply = fork::control_socket_cmd_with_timeout(
            &socket, &format!("GROW_DISK {id} {bytes}"), Duration::from_secs(120),
        ).map_err(|error| Error::agent("live resize", format!(
            "{id} growth outcome is unknown: {error}; reconcile or retry the same target, never shrink to roll back"
        )))?;
        if reply.trim() != format!("OK disk {id} capacity {bytes}") {
            return Err(Error::agent(
                "live resize",
                format!("{id} growth not confirmed: {reply}"),
            ));
        }
        db.update_vm(name, |record| match disk {
            ManagedDisk::Storage => record.storage_gb = Some(target),
            ManagedDisk::Overlay => record.overlay_gb = Some(target),
        })?
        .ok_or_else(|| Error::agent("live resize", "disk grew but machine record disappeared"))?;
        client.grow_filesystem(disk, bytes).map_err(|error| Error::agent(
            "live resize", format!("{id} disk is now {target} GiB; filesystem growth incomplete: {error}; retry the same target"),
        ))?;
    }
    db.get_vm(name)?
        .ok_or_else(|| Error::config("live resize", "machine record disappeared"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_disk_targets_never_shrink_or_overflow() {
        assert!(validate_growth(2, 1).is_err());
        assert!(validate_growth(0, 0).is_err());
        assert!(validate_growth(1, u64::MAX).is_err());
        assert_eq!(validate_growth(2, 2).unwrap(), 2 << 30);
        assert_eq!(validate_growth(2, 4).unwrap(), 4 << 30);
    }
}
