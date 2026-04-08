//! DB-backed VM lifecycle helpers for the NAPI backend.
//!
//! These helpers intentionally stay inside `smolvm-napi`: they provide the
//! useful shape of the old control layer without adding a new public core
//! module to `src/`.

use smolvm::agent::{AgentClient, AgentManager, HostMount, LaunchFeatures, VmResources};
use smolvm::config::{RecordState, VmRecord};
use smolvm::data::network::PortMapping;
use smolvm::db::SmolvmDb;
use smolvm::{Error, Result};

use crate::handle::VmHandle;

const MAX_NAME_LENGTH: usize = 40;

/// Runtime configuration supplied by the JS SDK constructor.
#[derive(Debug, Clone)]
pub(crate) struct MachineSpec {
    pub(crate) name: String,
    pub(crate) mounts: Vec<HostMount>,
    pub(crate) ports: Vec<PortMapping>,
    pub(crate) resources: VmResources,
    pub(crate) persistent: bool,
}

impl MachineSpec {
    pub(crate) fn to_record(&self) -> VmRecord {
        let mut record = VmRecord::new(
            self.name.clone(),
            self.resources.cpus,
            self.resources.memory_mib,
            self.mounts
                .iter()
                .map(HostMount::to_storage_tuple)
                .collect(),
            self.ports.iter().map(PortMapping::to_tuple).collect(),
            self.resources.network,
        );
        record.storage_gb = self.resources.storage_gib;
        record.overlay_gb = self.resources.overlay_gib;
        record.allowed_cidrs = self.resources.allowed_cidrs.clone();
        record.ephemeral = !self.persistent;
        record
    }
}

/// Validate a machine name for SDK-created machines.
pub(crate) fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::config(
            "validate machine name",
            "name cannot be empty",
        ));
    }
    if name.len() > MAX_NAME_LENGTH {
        return Err(Error::config(
            "validate machine name",
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
            "validate machine name",
            "name must start with a letter or digit",
        ));
    }
    if name.ends_with('-') {
        return Err(Error::config(
            "validate machine name",
            "name cannot end with a hyphen",
        ));
    }

    let mut prev_was_hyphen = false;
    for c in name.chars() {
        if c == '-' {
            if prev_was_hyphen {
                return Err(Error::config(
                    "validate machine name",
                    "name cannot contain consecutive hyphens",
                ));
            }
            prev_was_hyphen = true;
        } else {
            prev_was_hyphen = false;
        }

        if !c.is_ascii_alphanumeric() && c != '-' && c != '_' {
            return Err(Error::config(
                "validate machine name",
                format!("name contains invalid character: '{}'", c),
            ));
        }
    }

    Ok(())
}

/// Create a DB record for a new SDK machine.
pub(crate) fn create_vm(db: &SmolvmDb, spec: &MachineSpec) -> Result<()> {
    validate_name(&spec.name)?;
    let record = spec.to_record();
    if db.insert_vm_if_not_exists(&spec.name, &record)? {
        Ok(())
    } else {
        Err(Error::agent_conflict(
            "create machine",
            format!("machine '{}' already exists", spec.name),
        ))
    }
}

/// Load a persisted VM record.
pub(crate) fn get_record(db: &SmolvmDb, name: &str) -> Result<VmRecord> {
    db.get_vm(name)?.ok_or_else(|| Error::vm_not_found(name))
}

/// Start a persisted VM and update its DB state.
pub(crate) fn start_vm(db: &SmolvmDb, name: &str) -> Result<VmHandle> {
    let record = get_record(db, name)?;
    let handle = start_vm_from_record(&record)?;
    mark_running(db, name, handle.child_pid())?;
    Ok(handle)
}

fn start_vm_from_record(record: &VmRecord) -> Result<VmHandle> {
    let manager =
        AgentManager::for_vm_with_sizes(&record.name, record.storage_gb, record.overlay_gb)
            .map_err(|e| Error::agent("create agent manager", e.to_string()))?;

    manager
        .ensure_running_with_full_config(
            record.host_mounts(),
            record.port_mappings(),
            record.vm_resources(),
            LaunchFeatures::default(),
        )
        .map_err(|e| Error::agent("start machine", e.to_string()))?;

    Ok(VmHandle::new(manager, None))
}

/// Connect to an already-running VM and return a cached handle.
pub(crate) fn connect_vm(db: &SmolvmDb, name: &str) -> Result<VmHandle> {
    let record = get_record(db, name)?;
    let manager = AgentManager::for_vm_with_sizes(name, record.storage_gb, record.overlay_gb)
        .map_err(|e| Error::agent("create agent manager", e.to_string()))?;

    if manager.try_connect_existing().is_none() {
        return Err(Error::agent_not_found(
            "connect machine",
            format!("machine '{}' is not running", name),
        ));
    }

    let client = AgentClient::connect_with_retry(manager.vsock_socket())?;
    Ok(VmHandle::new(manager, Some(client)))
}

/// Stop a persisted VM and update its DB state.
pub(crate) fn stop_vm(db: &SmolvmDb, name: &str) -> Result<()> {
    let record = get_record(db, name)?;
    let manager = AgentManager::for_vm_with_sizes(name, record.storage_gb, record.overlay_gb)
        .map_err(|e| Error::agent("create agent manager", e.to_string()))?;
    manager.try_connect_existing();
    manager.stop()?;
    mark_stopped(db, name)
}

/// Remove a VM record and its storage directory.
pub(crate) fn delete_vm(db: &SmolvmDb, name: &str) -> Result<()> {
    let removed = db.remove_vm(name)?;
    if removed.is_none() {
        return Err(Error::vm_not_found(name));
    }

    let data_dir = smolvm::agent::vm_data_dir(name);
    if data_dir.exists() {
        std::fs::remove_dir_all(&data_dir).map_err(|e| {
            Error::storage(
                "delete machine data",
                format!("{}: {}", data_dir.display(), e),
            )
        })?;
    }

    Ok(())
}

pub(crate) fn mark_running(db: &SmolvmDb, name: &str, pid: Option<i32>) -> Result<()> {
    let pid_start_time = pid.and_then(smolvm::process::process_start_time);
    db.update_vm(name, |record| {
        record.state = RecordState::Running;
        record.pid = pid;
        record.pid_start_time = pid_start_time;
    })?
    .ok_or_else(|| Error::vm_not_found(name))?;
    Ok(())
}

pub(crate) fn mark_stopped(db: &SmolvmDb, name: &str) -> Result<()> {
    db.update_vm(name, |record| {
        record.state = RecordState::Stopped;
        record.pid = None;
        record.pid_start_time = None;
    })?
    .ok_or_else(|| Error::vm_not_found(name))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> SmolvmDb {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "smolvm-napi-control-{}-{}.redb",
            std::process::id(),
            unique
        ));
        SmolvmDb::open_at(&path).unwrap()
    }

    fn test_spec(name: &str, persistent: bool) -> MachineSpec {
        MachineSpec {
            name: name.to_string(),
            mounts: Vec::new(),
            ports: Vec::new(),
            resources: VmResources::default(),
            persistent,
        }
    }

    #[test]
    fn record_ephemeral_follows_persistent_flag() {
        assert!(test_spec("ephemeral", false).to_record().ephemeral);
        assert!(!test_spec("persistent", true).to_record().ephemeral);
    }

    #[test]
    fn create_vm_rejects_duplicates() {
        let db = test_db();
        let spec = test_spec("duplicate", false);
        create_vm(&db, &spec).unwrap();

        let err = create_vm(&db, &spec).unwrap_err();
        assert!(matches!(
            err,
            Error::Agent {
                kind: smolvm::error::AgentErrorKind::Conflict,
                ..
            }
        ));
    }

    #[test]
    fn mark_running_and_stopped_update_record_state() {
        let db = test_db();
        let spec = test_spec("stateful", true);
        create_vm(&db, &spec).unwrap();

        mark_running(&db, "stateful", Some(12345)).unwrap();
        let running = get_record(&db, "stateful").unwrap();
        assert_eq!(running.state, RecordState::Running);
        assert_eq!(running.pid, Some(12345));

        mark_stopped(&db, "stateful").unwrap();
        let stopped = get_record(&db, "stateful").unwrap();
        assert_eq!(stopped.state, RecordState::Stopped);
        assert_eq!(stopped.pid, None);
        assert_eq!(stopped.pid_start_time, None);
    }
}
