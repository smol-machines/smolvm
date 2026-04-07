//! VM lifecycle operations.
//!
//! DB-backed operations take a `&SmolvmDb`. Runtime connection helpers return
//! `VmHandle`, which owns process management and lazy agent access.

use crate::data::disk::{Overlay, Storage, DEFAULT_OVERLAY_SIZE_GIB, DEFAULT_STORAGE_SIZE_GIB};
use crate::data::mount::HostMount;
use crate::data::vm::MicroVm;
use crate::error::{Error, Result};
pub use crate::handle::VmHandle;
use crate::internal::agent::{vm_data_dir, AgentClient, AgentManager, LaunchFeatures};
use crate::internal::config::RecordState;
use crate::internal::convert;
use crate::internal::db::SmolvmDb;
use crate::internal::process::process_start_time;
use crate::internal::storage::expand_disk;

// ============================================================================
// Name validation
// ============================================================================

/// Maximum length for VM names.
const MAX_NAME_LENGTH: usize = 40;

/// Validate a VM name.
///
/// Rules: alphanumeric + hyphens/underscores, must start with letter or digit,
/// no trailing hyphen, no consecutive hyphens, max 40 chars.
pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::config("validate name", "name cannot be empty"));
    }
    if name.len() > MAX_NAME_LENGTH {
        return Err(Error::config(
            "validate name",
            format!(
                "name too long: {} characters (max {})",
                name.len(),
                MAX_NAME_LENGTH
            ),
        ));
    }
    let first_char = name.chars().next().unwrap();
    if !first_char.is_ascii_alphanumeric() {
        return Err(Error::config(
            "validate name",
            "name must start with a letter or digit",
        ));
    }
    if name.ends_with('-') {
        return Err(Error::config(
            "validate name",
            "name cannot end with a hyphen",
        ));
    }
    let mut prev_was_hyphen = false;
    for c in name.chars() {
        if c == '-' {
            if prev_was_hyphen {
                return Err(Error::config(
                    "validate name",
                    "name cannot contain consecutive hyphens",
                ));
            }
            prev_was_hyphen = true;
        } else {
            prev_was_hyphen = false;
        }
        if !c.is_ascii_alphanumeric() && c != '-' && c != '_' {
            return Err(Error::config(
                "validate name",
                format!("name contains invalid character: '{}'", c),
            ));
        }
    }
    Ok(())
}

// ============================================================================
// CRUD operations
// ============================================================================

/// Create a new VM. Validates the name and persists to the database.
///
/// The input `MicroVm.status` is ignored — the returned MicroVm has
/// `status.phase = Created`.
pub fn create_vm(db: &SmolvmDb, vm: MicroVm) -> Result<MicroVm> {
    validate_name(&vm.name)?;

    if db.get_vm(&vm.name)?.is_some() {
        return Err(Error::config(
            "create vm",
            format!("'{}' already exists", vm.name),
        ));
    }

    let record = convert::vm_to_record(&vm);
    db.insert_vm(&vm.name, &record)?;

    Ok(convert::record_to_vm(&record))
}

/// Get a VM by name.
pub fn get_vm(db: &SmolvmDb, name: &str) -> Result<MicroVm> {
    let record = db
        .get_vm(name)?
        .ok_or_else(|| Error::vm_not_found(name))?;
    Ok(convert::record_to_vm(&record))
}

/// List all persisted VMs.
pub fn list_vms(db: &SmolvmDb) -> Result<Vec<MicroVm>> {
    let records = db.list_vms()?;
    Ok(records.into_iter().map(|(_, r)| convert::record_to_vm(&r)).collect())
}

/// Update a MicroVm's spec and/or status in the DB.
pub fn update_vm(db: &SmolvmDb, vm: &MicroVm) -> Result<()> {
    let record = convert::vm_to_record(vm);
    db.insert_vm(&vm.name, &record)?;
    Ok(())
}

// ============================================================================
// Start and connect operations
// ============================================================================

/// Start a VM directly from a `MicroVm` spec without reading or writing the DB.
///
/// This preserves `machine run` semantics: foreground runs use runtime config
/// without creating a persisted named machine.
pub fn start_vm_from_spec(vm: &MicroVm) -> Result<VmHandle> {
    let manager = AgentManager::for_vm_with_sizes(
        &vm.name,
        vm.spec.resources.storage_gib,
        vm.spec.resources.overlay_gib,
    )
    .map_err(|e| Error::agent("create agent manager", e.to_string()))?;

    let ssh_agent_socket = if vm.spec.ssh_agent {
        match std::env::var("SSH_AUTH_SOCK") {
            Ok(path) => Some(std::path::PathBuf::from(path)),
            Err(_) => {
                return Err(Error::config(
                    "--ssh-agent",
                    "SSH_AUTH_SOCK is not set. Start an SSH agent with: eval $(ssh-agent) && ssh-add",
                ));
            }
        }
    } else {
        None
    };
    let features = LaunchFeatures {
        ssh_agent_socket,
        dns_filter_hosts: vm.spec.dns_filter_hosts.clone(),
    };

    let freshly_started = manager
        .ensure_running_with_full_config(
            vm.spec.mounts.clone(),
            vm.spec.ports.clone(),
            vm.spec.resources.clone(),
            features,
        )
        .map_err(|e| Error::agent("start vm", e.to_string()))?;

    Ok(VmHandle::new(manager, freshly_started, None))
}

/// Start a VM from persisted DB config and persist the Running state.
///
/// Returns a `VmHandle` with `freshly_started()` indicating whether the
/// VM was just booted (true) or was already running and reconnected (false).
///
/// Idempotent — safe to call on an already-running VM.
pub fn start_vm(db: &SmolvmDb, name: &str) -> Result<VmHandle> {
    let vm = get_vm(db, name)?;
    let handle = start_vm_from_spec(&vm)?;

    let pid = handle.child_pid();
    let pid_start_time = pid.and_then(process_start_time);
    if let Err(e) = db.update_vm(name, |r| {
        r.state = RecordState::Running;
        r.pid = pid;
        r.pid_start_time = pid_start_time;
    }) {
        tracing::warn!(error = %e, vm = %name, "failed to persist running state");
    }

    Ok(handle)
}

/// Connect to a VM by name.
///
/// This function does not read the database. Callers are responsible for
/// checking persistence separately before connecting. If `auto_start_vm` is
/// true, the VM is started with the default manager config when needed.
pub fn connect_vm(name: &str, auto_start_vm: bool) -> Result<VmHandle> {
    let manager = AgentManager::for_vm(name)
        .map_err(|e| Error::agent("create agent manager", e.to_string()))?;

    let freshly_started = if manager.try_connect_existing().is_none() {
        if !auto_start_vm {
            return Err(Error::agent(
                "connect",
                format!("machine '{}' is not running", name),
            ));
        }

        manager.ensure_running()?;
        true
    } else {
        false
    };

    let client = AgentClient::connect_with_retry(manager.vsock_socket())?;
    Ok(VmHandle::new(manager, freshly_started, Some(client)))
}

// ============================================================================
// Stop, delete, and resize operations
// ============================================================================

/// Stop a running VM and persist the Stopped state.
///
/// Returns an error if the VM is not found or not running.
pub fn stop_vm(db: &SmolvmDb, name: &str) -> Result<()> {
    let record = db
        .get_vm(name)?
        .ok_or_else(|| Error::vm_not_found(name))?;

    let actual_state = record.actual_state();
    if actual_state != RecordState::Running {
        return Err(Error::InvalidState {
            expected: "running".into(),
            actual: format!("{}", actual_state),
        });
    }

    let manager = AgentManager::for_vm(name)
        .map_err(|e| Error::agent("create agent manager", e.to_string()))?;

    manager.try_connect_existing();
    manager.stop()?;

    if let Err(e) = db.update_vm(name, |r| {
        r.state = RecordState::Stopped;
        r.pid = None;
        r.pid_start_time = None;
    }) {
        tracing::warn!(error = %e, vm = %name, "failed to persist stopped state");
    }

    Ok(())
}

/// Delete a VM. Optionally stops it first, removes from DB, and
/// deletes the data directory.
///
/// Does NOT prompt for confirmation — that's a CLI concern.
pub fn delete_vm(db: &SmolvmDb, name: &str, force: bool) -> Result<()> {
    let record = db
        .get_vm(name)?
        .ok_or_else(|| Error::vm_not_found(name))?;

    if force && record.actual_state() == RecordState::Running {
        if let Ok(manager) = AgentManager::for_vm(name) {
            if let Err(e) = manager.stop() {
                tracing::warn!(error = %e, "failed to stop vm before delete");
            }
        }
    }

    db.remove_vm(name)?;

    let data_dir = vm_data_dir(name);
    if data_dir.exists() {
        if let Err(e) = std::fs::remove_dir_all(&data_dir) {
            tracing::warn!(error = %e, "failed to remove vm data directory: {}", data_dir.display());
        }
    }

    Ok(())
}

/// Resize a VM's disks. The VM must be stopped. Only expansion is supported.
pub fn resize_vm(
    db: &SmolvmDb,
    name: &str,
    new_storage_gib: Option<u64>,
    new_overlay_gib: Option<u64>,
) -> Result<()> {
    let record = db
        .get_vm(name)?
        .ok_or_else(|| Error::vm_not_found(name))?;

    let actual_state = record.actual_state();
    match actual_state {
        RecordState::Stopped | RecordState::Created => {}
        _ => {
            return Err(Error::InvalidState {
                expected: "stopped".into(),
                actual: format!("{:?}", actual_state),
            });
        }
    }

    let current_storage = record.storage_gb.unwrap_or(DEFAULT_STORAGE_SIZE_GIB);
    let current_overlay = record.overlay_gb.unwrap_or(DEFAULT_OVERLAY_SIZE_GIB);
    let target_storage = new_storage_gib.unwrap_or(current_storage);
    let target_overlay = new_overlay_gib.unwrap_or(current_overlay);

    if target_storage < current_storage {
        return Err(Error::config(
            "resize",
            format!(
                "storage disk cannot be shrunk from {} GiB to {} GiB",
                current_storage, target_storage
            ),
        ));
    }
    if target_overlay < current_overlay {
        return Err(Error::config(
            "resize",
            format!(
                "overlay disk cannot be shrunk from {} GiB to {} GiB",
                current_overlay, target_overlay
            ),
        ));
    }

    let manager = AgentManager::for_vm(name)
        .map_err(|e| Error::agent("get agent manager", e.to_string()))?;

    if let Some(s) = new_storage_gib {
        if s > current_storage {
            expand_disk::<Storage>(manager.storage_path(), s)
                .map_err(|e| Error::storage("expand storage disk", e.to_string()))?;
        }
    }
    if let Some(o) = new_overlay_gib {
        if o > current_overlay {
            expand_disk::<Overlay>(manager.overlay_path(), o)
                .map_err(|e| Error::storage("expand overlay disk", e.to_string()))?;
        }
    }

    db.update_vm(name, |r| {
        if let Some(s) = new_storage_gib {
            r.storage_gb = Some(s);
        }
        if let Some(o) = new_overlay_gib {
            r.overlay_gb = Some(o);
        }
    })?;

    Ok(())
}

// ============================================================================
// Maintenance helpers
// ============================================================================

/// Remove generated ephemeral VM records whose process no longer exists.
pub fn cleanup_orphaned_ephemeral_vms() {
    let db = match SmolvmDb::open() {
        Ok(db) => db,
        Err(_) => return,
    };

    let records = match db.list_vms() {
        Ok(records) => records,
        Err(_) => return,
    };

    for (name, record) in records {
        if !record.ephemeral {
            continue;
        }

        let is_orphan = match record.pid {
            Some(pid) => !crate::internal::process::is_alive(pid),
            None => true,
        };

        if is_orphan {
            tracing::debug!(name = %name, pid = ?record.pid, "cleaning up orphaned ephemeral VM");
            let _ = db.remove_vm(&name);
        }
    }
}

// ============================================================================
// Container helpers
// ============================================================================

/// Resolve container mounts against a VM's host mounts.
///
/// Assigns virtiofs tags (`smolvm0`, `smolvm1`, ...) and validates that
/// all host paths referenced exist in the VM's configured mounts.
pub fn resolve_container_mounts(
    vm_mounts: &[HostMount],
    container_mounts: &[(String, String, bool)],
) -> Result<Vec<(String, String, bool)>> {
    // Auto-propagate all VM mounts to the container
    let mut result: Vec<(String, String, bool)> = vm_mounts
        .iter()
        .enumerate()
        .map(|(i, m)| {
            (
                HostMount::mount_tag(i),
                m.target.to_string_lossy().to_string(),
                m.read_only,
            )
        })
        .collect();

    // Apply explicit container mount overrides
    for (host_path, guest_path, read_only) in container_mounts {
        // Find the matching VM mount by host path
        let found = vm_mounts.iter().enumerate().find(|(_, m)| {
            m.source.to_string_lossy() == *host_path
        });

        match found {
            Some((idx, _)) => {
                // Override the auto-propagated entry
                let tag = HostMount::mount_tag(idx);
                if let Some(entry) = result.iter_mut().find(|(t, _, _)| t == &tag) {
                    entry.1 = guest_path.clone();
                    entry.2 = *read_only;
                }
            }
            None => {
                return Err(Error::mount(
                    "resolve container mounts",
                    format!(
                        "host path '{}' is not mounted on the VM. Add it with --volume first.",
                        host_path
                    ),
                ));
            }
        }
    }

    Ok(result)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_name_valid() {
        assert!(validate_name("my-vm").is_ok());
        assert!(validate_name("test123").is_ok());
        assert!(validate_name("a").is_ok());
        assert!(validate_name("vm-with-hyphens").is_ok());
        assert!(validate_name("vm_with_underscores").is_ok());
    }

    #[test]
    fn test_validate_name_invalid() {
        assert!(validate_name("").is_err());
        assert!(validate_name("-starts-with-hyphen").is_err());
        assert!(validate_name("ends-with-hyphen-").is_err());
        assert!(validate_name("double--hyphen").is_err());
        assert!(validate_name("has space").is_err());
        assert!(validate_name("has.dot").is_err());
        assert!(validate_name(&"a".repeat(41)).is_err());
    }

    #[test]
    fn test_validate_name_max_length() {
        assert!(validate_name(&"a".repeat(40)).is_ok());
        assert!(validate_name(&"a".repeat(41)).is_err());
    }
}
