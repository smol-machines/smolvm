//! Publish observations only for the machine and execution actually observed.
use super::ApiState;
use crate::config::{RecordState, VmRecord};
use crate::{Error, Result};

pub(crate) fn same_observation(a: &VmRecord, b: &VmRecord) -> bool {
    a.database_identity.is_some() && a.database_identity == b.database_identity && same_state(a, b)
}

fn same_state(a: &VmRecord, b: &VmRecord) -> bool {
    a.name == b.name
        && (a.pid, a.pid_start_time) == (b.pid, b.pid_start_time)
        && a.state == b.state
        && a.paused_checkpoint == b.paused_checkpoint
        && a.restart == b.restart
        && a.last_exit_code == b.last_exit_code
        && a.runtime_managed == b.runtime_managed
        && a.labels == b.labels
}

fn changed() -> Error {
    Error::agent_conflict(
        "publish supervisor observation",
        "machine execution or restart policy changed since it was observed; review it again",
    )
}

fn require_dead_observation(current: &VmRecord, observed: &VmRecord) -> Result<()> {
    // update_vm_for_record verifies row identity in this same transaction;
    // its mutable payload deliberately carries no deserialized identity.
    if !same_state(current, observed)
        || super::externally_supervised(current)
        || current.is_process_alive()
        || current.paused_checkpoint.is_some()
        || matches!(
            current.state,
            RecordState::Paused | RecordState::Pausing | RecordState::Frozen
        )
    {
        return Err(changed());
    }
    Ok(())
}

impl ApiState {
    pub(crate) fn publish_supervisor_exit(
        &self,
        observed: &VmRecord,
        code: i32,
    ) -> Result<VmRecord> {
        self.db.update_vm_for_record(observed, |current| {
            require_dead_observation(current, observed)?;
            current.last_exit_code = Some(code);
            Ok(())
        })
    }

    pub(crate) fn publish_supervisor_stopped(&self, observed: &VmRecord) -> Result<VmRecord> {
        self.db.update_vm_for_record(observed, |current| {
            require_dead_observation(current, observed)?;
            current.state = RecordState::Stopped;
            current.pid = None;
            current.pid_start_time = None;
            current.engine_build = None;
            Ok(())
        })
    }

    /// Consume one retry only after lifecycle/start locks and policy checks.
    /// A delayed attempt may not spend a replacement's or a new boot's budget.
    pub(crate) fn reserve_supervisor_retry(&self, observed: &VmRecord) -> Result<VmRecord> {
        self.db.update_vm_for_record(observed, |current| {
            require_dead_observation(current, observed)?;
            if !current.restart.should_restart(current.last_exit_code) {
                return Err(changed());
            }
            current.restart.restart_count = current
                .restart
                .restart_count
                .checked_add(1)
                .ok_or_else(changed)?;
            Ok(())
        })
    }

    pub(crate) fn publish_supervisor_failure(&self, observed: &VmRecord) -> Result<VmRecord> {
        self.db.update_vm_for_record(observed, |current| {
            require_dead_observation(current, observed)?;
            current.state = RecordState::Failed;
            current.pid = None;
            current.pid_start_time = None;
            current.engine_build = None;
            Ok(())
        })
    }

    /// Boot admission already registers the PID and re-enables supervision.
    /// Finish only that execution, without clearing a later stop or retry budget.
    pub(crate) fn publish_observed_start(
        &self,
        observed: &VmRecord,
        execution: Option<(i32, Option<u64>)>,
    ) -> Result<VmRecord> {
        let (pid, start) = execution.ok_or_else(changed)?;
        if pid <= 0 || start.is_none() {
            return Err(changed());
        }
        self.db.update_vm_for_record(observed, |current| {
            if (current.pid, current.pid_start_time) != (Some(pid), start)
                || current.restart.user_stopped
                || current.paused_checkpoint.is_some()
                || matches!(
                    current.state,
                    RecordState::Paused | RecordState::Pausing | RecordState::Frozen
                )
            {
                return Err(changed());
            }
            current.state = RecordState::Running;
            current.engine_build = Some(crate::ENGINE_BUILD.to_owned());
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RestartPolicy;

    fn fixture() -> (tempfile::TempDir, ApiState, VmRecord) {
        let root = tempfile::tempdir().unwrap();
        let db = crate::db::SmolvmDb::open_at(&root.path().join("machines.db")).unwrap();
        let mut record = VmRecord::new("reviewed-observer".into(), 1, 128, vec![], vec![], false);
        record.restart.policy = RestartPolicy::Always;
        record.restart.max_retries = 2;
        db.insert_vm(&record.name, &record).unwrap();
        let record = db.get_vm(&record.name).unwrap().unwrap();
        (root, ApiState::with_db(db), record)
    }

    fn assert_refused(state: &ApiState, observed: &VmRecord) {
        let before = state.db.get_vm(&observed.name).unwrap().unwrap();
        assert!(state.publish_supervisor_exit(observed, 42).is_err());
        assert!(state.publish_supervisor_stopped(observed).is_err());
        assert!(state.reserve_supervisor_retry(observed).is_err());
        assert!(state.publish_supervisor_failure(observed).is_err());
        assert_eq!(
            serde_json::to_value(state.db.get_vm(&observed.name).unwrap().unwrap()).unwrap(),
            serde_json::to_value(before).unwrap()
        );
    }

    #[test]
    fn supervision_refuses_replacements_and_changed_stop_pause_or_policy() {
        let (_root, state, observed) = fixture();
        state.db.remove_vm(&observed.name).unwrap();
        state.db.insert_vm(&observed.name, &observed).unwrap();
        assert_refused(&state, &observed);
        for mutation in 0..6 {
            let observed = state.db.get_vm(&observed.name).unwrap().unwrap();
            state
                .db
                .update_vm(&observed.name, |r| match mutation {
                    0 => r.restart.user_stopped = true,
                    1 => r.state = RecordState::Pausing,
                    2 => r.restart.policy = RestartPolicy::Never,
                    3 => r.last_exit_code = Some(9),
                    4 => {
                        r.labels
                            .insert("smolvm.engine/container".into(), "owner".into());
                    }
                    _ => r.runtime_managed = true,
                })
                .unwrap();
            assert_refused(&state, &observed);
        }
    }

    #[test]
    fn supervision_consumes_each_reviewed_retry_once_and_preserves_exit_status() {
        let (_root, state, observed) = fixture();
        let exited = state.publish_supervisor_exit(&observed, 42).unwrap();
        let retry = state.reserve_supervisor_retry(&exited).unwrap();
        assert_eq!(retry.restart.restart_count, 1);
        assert_eq!(retry.last_exit_code, Some(42));
        assert!(state.reserve_supervisor_retry(&exited).is_err());
        let failed = state.publish_supervisor_failure(&retry).unwrap();
        let second = state.reserve_supervisor_retry(&failed).unwrap();
        assert_eq!(second.restart.restart_count, 2);
        assert!(state.reserve_supervisor_retry(&second).is_err());
        let stopped = state.publish_supervisor_stopped(&second).unwrap();
        assert_eq!(stopped.restart.restart_count, 2);
        assert_eq!(stopped.last_exit_code, Some(42));
    }

    #[test]
    fn startup_publication_keeps_the_observed_process_and_later_stop() {
        let (_root, state, observed) = fixture();
        state
            .db
            .update_vm(&observed.name, |r| {
                r.pid = Some(123);
                r.pid_start_time = Some(456);
                r.restart.restart_count = 1;
            })
            .unwrap();
        let running = state
            .publish_observed_start(&observed, Some((123, Some(456))))
            .unwrap();
        assert_eq!(running.state, RecordState::Running);
        assert_eq!(running.restart.restart_count, 1);
        state
            .db
            .update_vm(&observed.name, |r| r.pid_start_time = Some(789))
            .unwrap();
        assert!(state
            .publish_observed_start(&observed, Some((123, Some(456))))
            .is_err());
        state
            .db
            .update_vm(&observed.name, |r| r.restart.user_stopped = true)
            .unwrap();
        assert!(state
            .publish_observed_start(&observed, Some((123, Some(789))))
            .is_err());
        assert!(
            state
                .db
                .get_vm(&observed.name)
                .unwrap()
                .unwrap()
                .restart
                .user_stopped
        );
        state.db.remove_vm(&observed.name).unwrap();
        let mut replacement = running.clone();
        replacement.restart.user_stopped = false;
        state.db.insert_vm(&observed.name, &replacement).unwrap();
        assert!(state
            .publish_observed_start(&observed, Some((123, Some(456))))
            .is_err());
        assert!(state.publish_observed_start(&replacement, None).is_err());
    }

    #[test]
    fn supervision_and_startup_publication_respect_transfer_admission() {
        let (_root, state, observed) = fixture();
        state
            .db
            .claim_workload_transfer(
                "move",
                vec![state.db.review_workload_member(&observed.name).unwrap()],
                &[],
            )
            .unwrap();
        assert_refused(&state, &observed);
        assert!(state
            .publish_observed_start(&observed, Some((123, Some(456))))
            .is_err());
    }
}
