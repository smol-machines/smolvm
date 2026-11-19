//! Observe newly published CLI/SDK machines without taking over their controller.
use super::{ApiState, MachineEntry};
use crate::config::VmRecord;
use std::collections::btree_map::Entry;
use std::sync::Arc;

/// Container, builder, warm-base and Kubernetes lifecycles have their own owners.
/// Use ownership metadata, not names: a user's machine can be called docker-*.
pub(crate) fn externally_supervised(record: &VmRecord) -> bool {
    record.runtime_managed
        || record
            .labels
            .keys()
            .any(|key| key.starts_with("smolvm.engine/") || key.starts_with("smolvm.engine."))
}

impl ApiState {
    /// Inventory and disk observation run off the reactor; no guest ping, boot,
    /// cleanup or database mutation is needed to register a new machine.
    pub(crate) async fn discover_persisted_machines(self: &Arc<Self>) -> crate::Result<()> {
        let state = self.clone();
        tokio::task::spawn_blocking(move || {
            for (_, record) in state.db.list_vms()? {
                if externally_supervised(&record)
                    || state.machines.read().contains_key(&record.name)
                {
                    continue;
                }
                let lifecycle = state.lifecycle_lock(&record.name);
                let Ok(_guard) = lifecycle.try_lock() else {
                    continue;
                };
                if let Err(error) = state.discover_machine(&record) {
                    tracing::debug!(machine = %record.name, %error, "machine discovery deferred");
                }
            }
            Ok(())
        })
        .await
        .map_err(|error| crate::Error::agent("discover machines", error.to_string()))?
    }

    // Caller holds the lifecycle lock. Observer managers have no child process,
    // so losing an insertion race cannot stop another controller's guest.
    fn discover_machine(&self, observed: &VmRecord) -> crate::Result<bool> {
        if externally_supervised(observed) || self.machines.read().contains_key(&observed.name) {
            return Ok(false);
        }
        let manager = crate::agent::AgentManager::for_existing_vm_record(observed)?;
        // A later exec/status reconnect may populate its process handle. It
        // still belongs to the CLI/SDK caller, not this observer's lifetime.
        manager.detach();
        let Some(current) = self.db.get_vm(&observed.name)? else {
            return Ok(false);
        };
        if !super::same_observation(observed, &current) || externally_supervised(&current) {
            return Ok(false);
        }
        let entry = crate::api::handlers::machines::machine_entry_from_record(&current, manager);
        Ok(self.insert_discovered_machine(&current.name, entry))
    }

    fn insert_discovered_machine(&self, name: &str, entry: MachineEntry) -> bool {
        match self.machines.write().entry(name.to_owned()) {
            Entry::Vacant(slot) => {
                slot.insert(Arc::new(parking_lot::Mutex::new(entry)));
                true
            }
            Entry::Occupied(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn discovery_enrolls_late_cli_records_without_replacing_controllers_or_writing_state() {
        let db = crate::db::SmolvmDb::open().unwrap();
        let state = Arc::new(ApiState::with_db(db.clone()));
        let name = format!("discovery-{:032x}", rand::random::<u128>());
        let mut record = VmRecord::new(name.clone(), 1, 128, vec![], vec![], false);
        record.state = crate::config::RecordState::Paused;
        record.paused_checkpoint = Some("saved.checkpoint".into());
        db.insert_vm(&name, &record).unwrap();
        let observed = db.get_vm(&name).unwrap().unwrap();
        let before = serde_json::to_value(&observed).unwrap();
        let lifecycle = state.lifecycle_lock(&name);
        let held = lifecycle.lock().await;
        state.discover_persisted_machines().await.unwrap();
        assert!(state.get_machine(&name).is_err(), "skip busy lifecycle");
        drop(held);
        state.discover_persisted_machines().await.unwrap();
        let first = state.get_machine(&name).unwrap();
        assert!(first.lock().manager.is_detached());
        // An entry lock held by an active request must not block discovery.
        {
            let _held = first.lock();
            assert!(!state.discover_machine(&observed).unwrap());
        }
        state.discover_persisted_machines().await.unwrap();
        assert!(Arc::ptr_eq(&first, &state.get_machine(&name).unwrap()));
        assert_eq!(
            serde_json::to_value(db.get_vm(&name).unwrap().unwrap()).unwrap(),
            before
        );
        assert!(
            !crate::agent::vm_data_dir(&name).exists(),
            "discovery creates no disks"
        );
        db.remove_vm(&name).unwrap();
        db.insert_vm(&name, &record).unwrap();
        let other = ApiState::with_db(db.clone());
        assert!(
            other.discover_machine(&observed).is_err(),
            "stale scan cannot enroll replacement"
        );
        assert!(other.get_machine(&name).is_err());
        db.remove_vm(&name).unwrap();
    }

    #[test]
    fn discovery_leaves_private_runtime_owners_alone() {
        let root = tempfile::tempdir().unwrap();
        let db = crate::db::SmolvmDb::open_at(&root.path().join("machines.db")).unwrap();
        let state = ApiState::with_db(db);
        let mut record = VmRecord::new("docker-user-machine".into(), 1, 128, vec![], vec![], false);
        assert!(!externally_supervised(&record));
        for key in [
            "smolvm.engine/container",
            "smolvm.engine/base",
            "smolvm.engine.builder",
        ] {
            record.labels.insert(key.into(), "owner".into());
            assert!(!state.discover_machine(&record).unwrap());
            record.labels.clear();
        }
        record.runtime_managed = true;
        assert!(!state.discover_machine(&record).unwrap());
        assert!(state.list_machine_names().is_empty());
    }
}
