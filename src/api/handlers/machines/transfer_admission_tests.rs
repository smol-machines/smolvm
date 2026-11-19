use super::*;
use crate::db::transfer_admission::Member;
use crate::db::SmolvmDb;

fn fixture() -> (tempfile::TempDir, Arc<ApiState>, VmRecord) {
    let root = tempfile::tempdir().unwrap();
    let db = SmolvmDb::open_at(&root.path().join("machines.db")).unwrap();
    let mut record = VmRecord::new("transfer-api".into(), 1, 128, vec![], vec![], false);
    record.paused_checkpoint = Some(root.path().join("saved.checkpoint"));
    assert!(db.insert_vm_if_not_exists(&record.name, &record).unwrap());
    db.claim_workload_transfer(
        "move",
        vec![Member::from_record(&record.name, &record)],
        &[],
    )
    .unwrap();
    let state = Arc::new(ApiState::with_db(db));
    // Transfer-owned entries must load without preparing disks or repairing
    // metadata; these tests require neither runtime assets nor virtualization.
    assert_eq!(state.load_persisted_machines(), vec![record.name.clone()]);
    (root, state, record)
}

fn refused(error: ApiError) {
    assert!(
        matches!(error, ApiError::Conflict(ref message) if message.contains("environment is moving")),
        "{error:?}"
    );
}

#[tokio::test]
async fn transfer_admission_refuses_api_lifecycle_before_side_effects() {
    let (_root, state, record) = fixture();
    let name = record.name.clone();
    refused(
        start_machine(
            State(state.clone()),
            Path(name.clone()),
            Query(Default::default()),
            Default::default(),
            Bytes::new(),
        )
        .await
        .unwrap_err(),
    );
    refused(
        stop_machine(
            State(state.clone()),
            Path(name.clone()),
            Query(Default::default()),
        )
        .await
        .unwrap_err(),
    );
    refused(
        sync_machine(State(state.clone()), Path(name.clone()))
            .await
            .unwrap_err(),
    );
    refused(
        delete_machine(
            State(state.clone()),
            Path(name.clone()),
            Query(DeleteQuery {
                cascade: true,
                ..Default::default()
            }),
        )
        .await
        .unwrap_err(),
    );
    refused(
        saved_execution_operation(state.clone(), name.clone(), true, None)
            .await
            .unwrap_err(),
    );
    refused(
        saved_execution_operation(state.clone(), name.clone(), false, None)
            .await
            .unwrap_err(),
    );
    let entry = state.get_machine(&name).unwrap();
    let error = crate::api::state::ensure_running_and_persist(&state, &name, &entry)
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("environment is moving"),
        "{error}"
    );
    let fork = serde_json::from_value(serde_json::json!({"name":"transfer-child"})).unwrap();
    refused(
        fork_machine(State(state.clone()), Path(name.clone()), Json(fork))
            .await
            .unwrap_err(),
    );
    let req = serde_json::from_value(serde_json::json!({"name":"transfer-child"})).unwrap();
    let (reply, result) = tokio::sync::oneshot::channel();
    branch_batch_transaction(
        &state,
        &name,
        vec![crate::api::state::QueuedBranch { req, reply }],
    )
    .await;
    refused(result.await.unwrap().unwrap_err());
    assert_eq!(
        serde_json::to_value(&record).unwrap(),
        serde_json::to_value(state.db().get_vm(&name).unwrap().unwrap()).unwrap()
    );
    assert!(state.db().get_vm("transfer-child").unwrap().is_none());
    assert!(
        state.get_machine(&name).is_ok(),
        "observation remains available"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn transfer_admission_survives_disconnected_start_requests() {
    use std::fs::{File, TryLockError};
    let (root, state, record) = fixture();
    state.db().retire_workload_transfer("move").unwrap();
    let lifecycle = state.lifecycle_lock(&record.name);
    let lock = lifecycle.lock().await;
    let owned_state = state.clone();
    let name = record.name.clone();
    let request = tokio::spawn(async move {
        start_machine(
            State(owned_state),
            Path(name),
            Query(Default::default()),
            Default::default(),
            Bytes::new(),
        )
        .await
    });
    let gate = File::options()
        .read(true)
        .write(true)
        .open(root.path().join("machines.transfer-admission.lock"))
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match gate.try_lock() {
                Err(TryLockError::WouldBlock) => break,
                Ok(()) => gate.unlock().unwrap(),
                Err(error) => panic!("{error}"),
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    assert!(
        matches!(gate.try_lock(), Err(TryLockError::WouldBlock)),
        "request cancellation released the operation's admission"
    );
    drop(lock);
    // The owned task then encounters the saved-execution refusal, without
    // allocating a VM; only after it finishes may a new move be admitted.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match gate.try_lock() {
                Ok(()) => {
                    gate.unlock().unwrap();
                    break;
                }
                Err(TryLockError::WouldBlock) => tokio::task::yield_now().await,
                Err(error) => panic!("{error}"),
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(
        serde_json::to_value(&record).unwrap(),
        serde_json::to_value(state.db().get_vm(&record.name).unwrap().unwrap()).unwrap()
    );
    state
        .db()
        .claim_workload_transfer(
            "next",
            vec![Member::from_record(&record.name, &record)],
            &[],
        )
        .unwrap();
}

#[test]
fn transfer_admission_preserves_dead_ephemeral_record_on_server_restart() {
    let (_root, state, mut record) = fixture();
    record.paused_checkpoint = None;
    record.ephemeral = true;
    record.pid = Some(i32::MAX);
    record.state = RecordState::Running;
    // Simulate an already-captured record whose process died while the server
    // was absent. Startup must not erase it or its disks as ordinary garbage.
    state.db().insert_vm(&record.name, &record).unwrap();
    assert_eq!(state.load_persisted_machines(), vec![record.name.clone()]);
    assert_eq!(
        serde_json::to_value(&record).unwrap(),
        serde_json::to_value(state.db().get_vm(&record.name).unwrap().unwrap()).unwrap()
    );
    assert!(state.get_machine(&record.name).is_ok());
}
