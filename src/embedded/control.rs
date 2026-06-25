//! DB-backed VM lifecycle helpers for embedded SDK backends.

use crate::agent::{AgentClient, AgentManager, HostMount, LaunchFeatures, VmResources};
use crate::config::{RecordState, VmRecord};
use crate::data::network::PortMapping;
use crate::data::validate_vm_name;
use crate::db::SmolvmDb;
use crate::embedded::handle::VmHandle;
use crate::{Error, Result};

/// Runtime configuration supplied by an embedded SDK constructor.
#[derive(Debug, Clone)]
pub struct MachineSpec {
    /// Unique machine name.
    pub name: String,
    /// Host directory mounts to expose in the guest.
    pub mounts: Vec<HostMount>,
    /// Host-to-guest port mappings.
    pub ports: Vec<PortMapping>,
    /// VM resources for this machine.
    pub resources: VmResources,
    /// Whether the machine should persist across stop/start.
    pub persistent: bool,
}

impl MachineSpec {
    /// Convert the embedded-machine spec into the canonical DB record.
    pub fn to_record(&self) -> VmRecord {
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
        record.gpu = Some(self.resources.gpu);
        record.gpu_vram_mib = self.resources.gpu_vram_mib;
        record.ephemeral = !self.persistent;
        record
    }
}

/// Create a DB record for a new SDK machine.
pub fn create_vm(db: &SmolvmDb, spec: &MachineSpec) -> Result<()> {
    validate_vm_name(&spec.name, "name")
        .map_err(|reason| Error::config("validate machine name", reason))?;
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
pub fn get_record(db: &SmolvmDb, name: &str) -> Result<VmRecord> {
    db.get_vm(name)?.ok_or_else(|| Error::vm_not_found(name))
}

/// Start a persisted VM and update its DB state.
pub fn start_vm(db: &SmolvmDb, name: &str) -> Result<VmHandle> {
    let record = get_record(db, name)?;
    let handle = start_vm_from_record(&record)?;
    mark_running(db, name, handle.child_pid())?;
    Ok(handle)
}

fn start_vm_from_record(record: &VmRecord) -> Result<VmHandle> {
    launch_from_record(record, LaunchFeatures::default())
}

/// Boot `record` with the given launch features and return a handle. Shared by
/// the plain, forkable-golden, and fork-clone start paths so they can't drift.
fn launch_from_record(record: &VmRecord, features: LaunchFeatures) -> Result<VmHandle> {
    let manager =
        AgentManager::for_vm_with_sizes(&record.name, record.storage_gb, record.overlay_gb)
            .map_err(|e| Error::agent("create agent manager", e.to_string()))?;

    manager
        .ensure_running_with_full_config(
            record.host_mounts(),
            record.port_mappings(),
            record.vm_resources(),
            features,
        )
        .map_err(|e| Error::agent("start machine", e.to_string()))?;

    Ok(VmHandle::new(manager, None))
}

/// Start a persisted VM as a FORKABLE fork base: its guest RAM is backed by a
/// memfd (copy-on-write cloneable) and a control socket is exposed so the machine
/// can later be forked with [`fork_vm`]. Same mechanics as the CLI's
/// `machine start --forkable`, surfaced for the embedded SDK.
pub fn start_forkable_vm(db: &SmolvmDb, name: &str) -> Result<VmHandle> {
    let record = get_record(db, name)?;
    let features = LaunchFeatures {
        forkable: true,
        control_socket: Some(crate::agent::fork::control_socket_path(name)),
        ..LaunchFeatures::default()
    };
    let handle = launch_from_record(&record, features)?;
    mark_running(db, name, handle.child_pid())?;
    Ok(handle)
}

/// Fork a running, forkable `golden` into a new `clone` via copy-on-write guest
/// RAM + disks (same host). Freezes the golden (it stays paused as the shared
/// base — clones map its RAM `MAP_PRIVATE`, so it must not run again while clones
/// exist), boots the clone from the golden's snapshot, and returns the clone's
/// handle. `pinned_ports` are `(host, guest)` inbound forwards for the clone;
/// empty means the golden's forwards are remapped to freshly-allocated host
/// ports. Shares `agent::fork` with the CLI/serve fork paths.
pub fn fork_vm(
    db: &SmolvmDb,
    golden: &str,
    clone: &str,
    pinned_ports: &[(u16, u16)],
) -> Result<VmHandle> {
    // Freeze + snapshot the golden, register the clone (CoW disks + DB record).
    // `clone_forkable = false`: a clone can't itself be re-forked (nested fork).
    let prep = crate::agent::fork::prepare_fork(db, golden, clone, pinned_ports, false)?;

    // Boot the clone from the golden's in-memory snapshot instead of cold-booting.
    let features = LaunchFeatures {
        snapshot_dir: Some(prep.snapshot_dir.clone()),
        ..LaunchFeatures::default()
    };
    match launch_from_record(&prep.clone_record, features) {
        Ok(handle) => {
            crate::agent::fork::rejuvenate_clone(clone);
            mark_running(db, clone, handle.child_pid())?;
            Ok(handle)
        }
        Err(e) => {
            // prepare_fork already registered the clone; roll it back on boot failure.
            let _ = db.remove_vm(clone);
            let _ = std::fs::remove_dir_all(crate::agent::vm_data_dir(clone));
            Err(e)
        }
    }
}

/// Connect to an already-running VM and return a cached handle.
pub fn connect_vm(db: &SmolvmDb, name: &str) -> Result<VmHandle> {
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
pub fn stop_vm(db: &SmolvmDb, name: &str) -> Result<()> {
    let record = get_record(db, name)?;
    let manager = AgentManager::for_vm_with_sizes(name, record.storage_gb, record.overlay_gb)
        .map_err(|e| Error::agent("create agent manager", e.to_string()))?;
    manager.try_connect_existing();
    manager.stop()?;
    // Detach the per-machine layers volume if a (possibly cross-tool) bundle start
    // left it mounted. Unconditional on purpose: the embedded record may carry no
    // source_smolmachine even when a CLI/API `machine create <bundle>` extracted and
    // mounted this name's volume in the shared DB, so we cannot gate on it.
    // force_detach is infallible and no-ops when unmounted; macOS hdiutil detach, a
    // compile-time no-op on Linux.
    smolvm_pack::extract::force_detach_layers_volume(&crate::agent::machine_layers_cache_dir(name));
    mark_stopped(db, name)
}

/// Remove a VM record and its storage directory.
pub fn delete_vm(db: &SmolvmDb, name: &str) -> Result<()> {
    let removed = db.remove_vm(name)?;
    if removed.is_none() {
        return Err(Error::vm_not_found(name));
    }

    let data_dir = crate::agent::vm_data_dir(name);
    // Detach the per-machine layers volume before removing the data dir, else on
    // macOS the live mountpoint under it makes remove_dir_all fail with "Resource
    // busy", stranding both the mount and the data dir. Unconditional on purpose:
    // the embedded record may carry no source_smolmachine even when a CLI/API create
    // mounted this name's volume. hdiutil detach; a no-op on Linux and when nothing
    // is mounted.
    smolvm_pack::extract::force_detach_layers_volume(&crate::agent::machine_layers_cache_dir(name));
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

/// Mark a machine record as running.
pub fn mark_running(db: &SmolvmDb, name: &str, pid: Option<i32>) -> Result<()> {
    let pid_start_time = pid.and_then(crate::process::process_start_time);
    db.update_vm(name, |record| {
        record.state = RecordState::Running;
        record.pid = pid;
        record.pid_start_time = pid_start_time;
    })?
    .ok_or_else(|| Error::vm_not_found(name))?;
    Ok(())
}

/// Mark a machine record as stopped.
pub fn mark_stopped(db: &SmolvmDb, name: &str) -> Result<()> {
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
            "smolvm-embedded-control-{}-{}.db",
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
    fn record_carries_gpu_resources() {
        // GPU must survive MachineSpec -> VmRecord (the `_boot-vm` config),
        // otherwise the SDK's `resources.gpu` is silently dropped before launch.
        let mut spec = test_spec("gpu", false);
        spec.resources.gpu = true;
        spec.resources.gpu_vram_mib = Some(512);
        let record = spec.to_record();
        assert_eq!(record.gpu, Some(true));
        assert_eq!(record.gpu_vram_mib, Some(512));
        assert!(record.vm_resources().gpu);

        // Default (no GPU) records leave gpu off.
        let plain = test_spec("plain", false).to_record();
        assert_eq!(plain.gpu, Some(false));
        assert!(!plain.vm_resources().gpu);
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
                kind: crate::error::AgentErrorKind::Conflict,
                ..
            }
        ));
    }
}
