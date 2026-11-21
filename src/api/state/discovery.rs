//! Observe newly published CLI/SDK machines without taking over their controller.
use super::ApiState;
use crate::config::VmRecord;
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

    // Caller holds the lifecycle lock. Retired entries keep their own identity:
    // queued requests must fail rather than inherit the replacement's manager.
    fn discover_machine(&self, observed: &VmRecord) -> crate::Result<bool> {
        let prior = self.machines.read().get(&observed.name).cloned();
        let external = externally_supervised(observed);
        if let Some(prior) = &prior {
            let Some(entry) = prior.try_lock() else {
                return Ok(false);
            };
            if !external && entry.manager.matches_record_execution(observed) {
                return Ok(false);
            }
        } else if external {
            return Ok(false);
        }
        let replacement = if external {
            None
        } else {
            let manager = crate::agent::AgentManager::for_existing_vm_record(observed)?;
            manager.detach();
            Some(crate::api::handlers::machines::machine_entry_from_record(
                observed, manager,
            ))
        };
        let Some(current) = self.db.get_vm(&observed.name)? else {
            return Ok(false);
        };
        if !super::same_observation(observed, &current) {
            return Ok(false);
        }

        let mut machines = self.machines.write();
        // Creation or a start may have registered an entry since this scan
        // began. Compare the slot too, not merely its name.
        match (machines.get(&observed.name), prior.as_ref()) {
            (None, None) => {}
            (Some(actual), Some(expected)) if Arc::ptr_eq(actual, expected) => {}
            _ => return Ok(false),
        }
        let mut replacement = replacement;
        if let Some(prior) = prior {
            let Some(entry) = prior.try_lock() else {
                return Ok(false);
            };
            if !external && entry.manager.matches_record_execution(&current) {
                return Ok(false);
            }
            if let Some(new) = &mut replacement {
                if current.external_interceptor_required
                    && entry.manager.matches_record_incarnation(&current)
                {
                    new.external_interceptor = entry.external_interceptor;
                }
            }
            // Never stop a guest when releasing a superseded controller.
            entry.manager.detach();
        }
        match replacement {
            Some(entry) => {
                machines.insert(current.name, Arc::new(parking_lot::Mutex::new(entry)));
            }
            None => {
                machines.remove(&current.name);
            }
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn discovery_replaces_recreated_names_without_retargeting_old_handles() {
        let db = crate::db::SmolvmDb::open().unwrap();
        let state = Arc::new(ApiState::with_db(db.clone()));
        let name = format!("recreated-{:032x}", rand::random::<u128>());
        let record = VmRecord::new(name.clone(), 1, 128, vec![], vec![], false);
        db.insert_vm(&name, &record).unwrap();
        state.discover_persisted_machines().await.unwrap();
        let old = state.get_machine(&name).unwrap();
        db.remove_vm(&name).unwrap();
        db.insert_vm(&name, &record).unwrap();
        state.discover_persisted_machines().await.unwrap();
        let current = state.get_machine(&name).unwrap();
        let replacement = db.get_vm(&name).unwrap().unwrap();
        assert!(old
            .lock()
            .manager
            .connect()
            .err()
            .unwrap()
            .to_string()
            .contains("changed"));
        assert!(
            super::super::ensure_machine_running(&old, replacement.clone())
                .await
                .is_err()
        );
        assert!(current
            .lock()
            .manager
            .matches_record_incarnation(&replacement));
        assert!(!crate::agent::vm_data_dir(&name).exists());
        db.remove_vm(&name).unwrap();
        assert!(
            !Arc::ptr_eq(&old, &current),
            "replacement kept the old manager"
        );
    }

    #[tokio::test]
    async fn discovery_refreshes_external_restarts_and_retires_private_owners_without_writes() {
        let db = crate::db::SmolvmDb::open().unwrap();
        let state = Arc::new(ApiState::with_db(db.clone()));
        let name = format!("restarted-{:032x}", rand::random::<u128>());
        let record = VmRecord::new(name.clone(), 1, 128, vec![], vec![], false);
        db.insert_vm(&name, &record).unwrap();
        state.discover_persisted_machines().await.unwrap();
        let old = state.get_machine(&name).unwrap();
        let running = db
            .update_vm(&name, |r| {
                r.pid = Some(i32::MAX);
                r.pid_start_time = Some(1);
                r.state = crate::config::RecordState::Running;
            })
            .unwrap()
            .unwrap();
        {
            let _busy = old.lock();
            assert!(!state.discover_machine(&running).unwrap());
        }
        state.discover_persisted_machines().await.unwrap();
        let current = state.get_machine(&name).unwrap();
        assert!(!Arc::ptr_eq(&old, &current));
        assert!(current.lock().manager.matches_record_execution(&running));
        assert!(old.lock().manager.matches_record_incarnation(&running));
        let private = db
            .update_vm(&name, |r| {
                r.runtime_managed = true;
            })
            .unwrap()
            .unwrap();
        state.discover_persisted_machines().await.unwrap();
        assert!(state.get_machine(&name).is_err());
        assert_eq!(
            serde_json::to_value(db.get_vm(&name).unwrap().unwrap()).unwrap(),
            serde_json::to_value(private).unwrap()
        );
        db.remove_vm(&name).unwrap();
    }

    #[test]
    fn explicit_registration_does_not_retarget_a_replaced_incarnation() {
        let db = crate::db::SmolvmDb::open().unwrap();
        let state = ApiState::with_db(db.clone());
        let name = format!("registered-{:032x}", rand::random::<u128>());
        let record = VmRecord::new(name.clone(), 1, 128, vec![], vec![], false);
        let register = || {
            let stored = db.get_vm(&name).unwrap().unwrap();
            let manager = crate::agent::AgentManager::for_existing_vm_record(&stored).unwrap();
            manager.detach();
            state.insert_machine(
                &name,
                crate::api::handlers::machines::machine_entry_from_record(&stored, manager),
            );
        };
        db.insert_vm(&name, &record).unwrap();
        register();
        let old = state.get_machine(&name).unwrap();
        db.remove_vm(&name).unwrap();
        db.insert_vm(&name, &record).unwrap();
        register();
        let current = state.get_machine(&name).unwrap();
        assert!(!Arc::ptr_eq(&old, &current));
        assert!(old
            .lock()
            .manager
            .connect()
            .err()
            .unwrap()
            .to_string()
            .contains("changed"));
        db.remove_vm(&name).unwrap();
    }

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
