use super::*;
use crate::db::SmolvmDb;
use axum::response::IntoResponse;
use std::sync::atomic::{AtomicBool, Ordering};

fn fixture() -> (tempfile::TempDir, Arc<ApiState>, VmRecord) {
    let root = tempfile::tempdir().unwrap();
    let db = SmolvmDb::open_at(&root.path().join("state.db")).unwrap();
    let record = VmRecord::new("reviewed-api".into(), 1, 128, vec![], vec![], false);
    db.insert_vm(&record.name, &record).unwrap();
    let reviewed = db.get_vm(&record.name).unwrap().unwrap();
    (root, Arc::new(ApiState::with_db(db)), reviewed)
}

fn bytes(state: &ApiState, name: &str) -> Vec<u8> {
    serde_json::to_vec(&state.db().get_vm(name).unwrap().unwrap()).unwrap()
}

fn conflict(error: ApiError) {
    assert_eq!(
        error.into_response().status(),
        axum::http::StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn a_queued_api_update_cannot_adopt_a_replacement_committed_while_it_waited() {
    let (root, state, reviewed) = fixture();
    let original = bytes(&state, &reviewed.name);
    let mut raw = rusqlite::Connection::open(root.path().join("state.db")).unwrap();
    let tx = raw
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    tx.execute(
        "INSERT OR REPLACE INTO vms(name,data) VALUES (?1,?2)",
        rusqlite::params![reviewed.name, &original],
    )
    .unwrap();
    let touched = Arc::new(AtomicBool::new(false));
    let touched_worker = touched.clone();
    let worker_state = state.clone();
    let original_record = reviewed.clone();
    let mut worker = tokio::spawn(async move {
        worker_state
            .update_vm_for_record(&original_record, move |r| {
                touched_worker.store(true, Ordering::SeqCst);
                r.cuda_fork_pool_size = Some(4);
                r.external_interceptor_required = true;
                Ok(())
            })
            .await
    });
    assert!(tokio::time::timeout(Duration::from_millis(30), &mut worker)
        .await
        .is_err());
    tx.commit().unwrap();
    conflict(worker.await.unwrap().unwrap_err());
    assert!(!touched.load(Ordering::SeqCst));
    assert_eq!(bytes(&state, &reviewed.name), original);
    let fresh = state.db().get_vm(&reviewed.name).unwrap().unwrap();
    let updated = state
        .update_vm_for_record(&fresh, |r| {
            r.cuda_fork_pool_size = Some(4);
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(updated.cuda_fork_pool_size, Some(4));
}

#[tokio::test]
async fn delayed_stop_cannot_clear_a_replacement_or_a_new_execution() {
    let (_root, state, reviewed) = fixture();
    state.db().remove_vm(&reviewed.name).unwrap();
    state.db().insert_vm(&reviewed.name, &reviewed).unwrap();
    let before = bytes(&state, &reviewed.name);
    conflict(
        reconcile_confirmed_stopped_machine(&state, &reviewed, true)
            .await
            .unwrap_err(),
    );
    assert_eq!(bytes(&state, &reviewed.name), before);
    let fresh = state.db().get_vm(&reviewed.name).unwrap().unwrap();
    let observed = state
        .db()
        .update_vm(&fresh.name, |r| {
            r.pid = Some(0x7fff_fff0);
            r.pid_start_time = Some(1);
            r.state = RecordState::Running;
        })
        .unwrap()
        .unwrap();
    for (pid, start) in [(0x7fff_fff1, 2), (0x7fff_fff0, 2)] {
        state
            .db()
            .update_vm(&fresh.name, |r| {
                r.pid = Some(pid);
                r.pid_start_time = Some(start);
            })
            .unwrap();
        let before = bytes(&state, &fresh.name);
        conflict(
            reconcile_confirmed_stopped_machine(&state, &observed, true)
                .await
                .unwrap_err(),
        );
        assert_eq!(bytes(&state, &fresh.name), before);
    }
}

#[tokio::test]
async fn stopped_reconciliation_accepts_its_own_exit_and_preserves_saved_execution() {
    let (_root, state, record) = fixture();
    let reviewed = state
        .db()
        .update_vm(&record.name, |r| {
            r.pid = Some(0x7fff_fff0);
            r.pid_start_time = Some(1);
            r.state = RecordState::Running;
            r.paused_checkpoint = Some("/saved/execution".into());
        })
        .unwrap()
        .unwrap();
    let stopped = reconcile_confirmed_stopped_machine(&state, &reviewed, true)
        .await
        .unwrap();
    assert_eq!(stopped.pid, None);
    assert!(stopped.restart.user_stopped);
    assert_eq!(stopped.paused_checkpoint, reviewed.paused_checkpoint);
    // Another recovery step may have already cleared the same dead process.
    let repeated = reconcile_confirmed_stopped_machine(&state, &reviewed, true)
        .await
        .unwrap();
    assert_eq!(repeated.pid, None);
    assert_eq!(repeated.paused_checkpoint, reviewed.paused_checkpoint);
}

#[tokio::test]
async fn delayed_start_publication_cannot_overwrite_a_different_boot() {
    let (_root, state, reviewed) = fixture();
    let pid = Some(0x7fff_fff0);
    let start = Some(10);
    let booted = state
        .db()
        .update_vm(&reviewed.name, |r| {
            r.pid = pid;
            r.pid_start_time = start;
            r.restart.user_stopped = true;
            r.restart.restart_count = 3;
        })
        .unwrap()
        .unwrap();
    state
        .db()
        .update_vm(&reviewed.name, |r| r.pid_start_time = Some(11))
        .unwrap();
    let before = bytes(&state, &reviewed.name);
    conflict(
        persist_started_machine(&state, &booted, pid, start, true)
            .await
            .unwrap_err(),
    );
    assert_eq!(bytes(&state, &reviewed.name), before);
    state
        .db()
        .update_vm(&reviewed.name, |r| r.pid_start_time = start)
        .unwrap();
    let current = persist_started_machine(&state, &booted, pid, start, false)
        .await
        .unwrap();
    assert_eq!(current.state, RecordState::Running);
    assert!(!current.restart.user_stopped);
    assert_eq!(current.restart.restart_count, 0);
    state.db().remove_vm(&reviewed.name).unwrap();
    state.db().insert_vm(&reviewed.name, &current).unwrap();
    let before = bytes(&state, &reviewed.name);
    conflict(
        persist_started_machine(&state, &booted, pid, start, true)
            .await
            .unwrap_err(),
    );
    assert_eq!(bytes(&state, &reviewed.name), before);
}

#[tokio::test]
async fn a_refused_metadata_transition_rolls_back_and_a_deleted_request_stays_deleted() {
    let (_root, state, reviewed) = fixture();
    let before = bytes(&state, &reviewed.name);
    conflict(
        state
            .update_vm_for_record(&reviewed, |r| {
                r.mem = 4096;
                Err(SmolvmError::agent_conflict(
                    "update machine",
                    "configuration changed",
                ))
            })
            .await
            .unwrap_err(),
    );
    assert_eq!(bytes(&state, &reviewed.name), before);
    state.db().remove_vm(&reviewed.name).unwrap();
    conflict(
        state
            .update_vm_for_record(&reviewed, |_| panic!("deleted request must not run"))
            .await
            .unwrap_err(),
    );
    assert!(state.db().get_vm(&reviewed.name).unwrap().is_none());
}

#[tokio::test]
async fn reviewed_metadata_updates_respect_transfer_claims_and_new_shared_roots() {
    let (root, state, reviewed) = fixture();
    let shared = root.path().join("shared");
    std::fs::create_dir(&shared).unwrap();
    let peer = VmRecord::new("peer".into(), 1, 128, vec![], vec![], false);
    state.db().insert_vm("peer", &peer).unwrap();
    let member = state.db().review_workload_member("peer").unwrap();
    state
        .db()
        .claim_workload_transfer("moving-peer", vec![member], std::slice::from_ref(&shared))
        .unwrap();
    let before = bytes(&state, &reviewed.name);
    let path = shared.to_string_lossy().into_owned();
    conflict(
        state
            .update_vm_for_record(&reviewed, move |r| {
                r.mounts.push((path, "/data".into(), false));
                Ok(())
            })
            .await
            .unwrap_err(),
    );
    assert_eq!(bytes(&state, &reviewed.name), before);
    state.db().retire_workload_transfer("moving-peer").unwrap();
    let member = state.db().review_workload_member(&reviewed.name).unwrap();
    state
        .db()
        .claim_workload_transfer("moving-self", vec![member], &[])
        .unwrap();
    conflict(
        state
            .update_vm_for_record(&reviewed, |_| {
                panic!("claimed machine must remain unchanged")
            })
            .await
            .unwrap_err(),
    );
    assert_eq!(bytes(&state, &reviewed.name), before);
    state.db().retire_workload_transfer("moving-self").unwrap();
    let current = state
        .update_vm_for_record(&reviewed, |r| {
            r.mem = 256;
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(current.mem, 256);
}
