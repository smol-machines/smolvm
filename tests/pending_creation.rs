//! A create reservation must remain visible to control-plane reconciliation.
use axum::extract::{Path, Query, State};
use smolvm::{
    api::{
        handlers::machines::{delete_machine, list_machines},
        state::ApiState,
        types::DeleteQuery,
    },
    db::SmolvmDb,
};
use std::sync::Arc;

#[tokio::test]
async fn pending_creation_is_visible_and_delete_does_not_claim_absence() {
    let root = tempfile::tempdir().unwrap();
    let db = SmolvmDb::open_at(&root.path().join("test.db")).unwrap();
    let state = Arc::new(ApiState::with_db(db));
    state
        .reserve_machine_name("pending-test", "test-reservation")
        .unwrap();
    let listed = list_machines(State(state.clone())).await.unwrap();
    let wire = serde_json::to_value(listed.0).unwrap();
    assert_eq!(wire["pendingCreates"], serde_json::json!(["pending-test"]));
    let result = delete_machine(
        State(state),
        Path("pending-test".into()),
        Query(DeleteQuery {
            cascade: false,
            force: false,
        }),
    )
    .await;
    assert!(
        result.is_ok(),
        "delete must reclaim the owned pending reservation"
    );
}

#[tokio::test]
async fn pending_ownership_survives_api_state_restart() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("test.db");
    {
        let state = ApiState::with_db(SmolvmDb::open_at(&path).unwrap());
        state
            .reserve_machine_name("interrupted", "interrupted-token")
            .unwrap();
    }
    let state = Arc::new(ApiState::with_db(SmolvmDb::open_at(&path).unwrap()));
    let listed = list_machines(State(state.clone())).await.unwrap();
    assert_eq!(
        serde_json::to_value(listed.0).unwrap()["pendingCreates"],
        serde_json::json!(["interrupted"])
    );
    let _ = delete_machine(
        State(state.clone()),
        Path("interrupted".into()),
        Query(DeleteQuery {
            cascade: false,
            force: false,
        }),
    )
    .await
    .unwrap();
    assert!(state.db().pending_vm_creates().unwrap().is_empty());
}

#[tokio::test]
async fn create_obeys_the_same_lifecycle_lock_as_delete() {
    use smolvm::api::{handlers::machines::create_machine, types::CreateMachineRequest};
    let root = tempfile::tempdir().unwrap();
    let state = Arc::new(ApiState::with_db(
        SmolvmDb::open_at(&root.path().join("test.db")).unwrap(),
    ));
    let lock = state.lifecycle_lock("locked-test");
    let guard = lock.lock_owned().await;
    let request: CreateMachineRequest = serde_json::from_value(
        serde_json::json!({"name":"locked-test", "image":"alpine", "from":"/invalid"}),
    )
    .unwrap();
    let creator =
        tokio::spawn(async move { create_machine(State(state), axum::Json(request)).await });
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    assert!(
        !creator.is_finished(),
        "create bypassed delete's lifecycle lock"
    );
    drop(guard);
    assert!(creator.await.unwrap().is_err()); // invalid request allocates nothing
}

#[tokio::test]
async fn pending_creation_in_another_live_process_is_preserved() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("test.db");
    let state = Arc::new(ApiState::with_db(SmolvmDb::open_at(&path).unwrap()));
    state
        .reserve_machine_name("live-owner", "live-token")
        .unwrap();
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute("UPDATE vm_create_reservations SET owner_pid=1", [])
        .unwrap();
    let result = delete_machine(
        State(state.clone()),
        Path("live-owner".into()),
        Query(DeleteQuery {
            cascade: false,
            force: false,
        }),
    )
    .await;
    assert!(matches!(
        result,
        Err(smolvm::api::error::ApiError::Conflict(_))
    ));
    assert_eq!(state.db().pending_vm_creates().unwrap().len(), 1);
}

#[tokio::test]
async fn failed_preparation_keeps_its_disks_discoverable_until_delete() {
    use smolvm::api::state::ReservationGuard;
    let root = tempfile::tempdir().unwrap();
    let state = Arc::new(ApiState::with_db(
        SmolvmDb::open_at(&root.path().join("test.db")).unwrap(),
    ));
    let name = format!(
        "pending-regression-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let reservation = ReservationGuard::new(&state, name.clone()).unwrap();
    let dir = smolvm::agent::ensure_vm_dir(&name).unwrap();
    std::fs::write(dir.join("partial-storage"), b"partial").unwrap();
    drop(reservation);
    assert_eq!(state.db().pending_vm_creates().unwrap()[0].0, name);
    let _ = delete_machine(
        State(state.clone()),
        Path(name.clone()),
        Query(DeleteQuery {
            cascade: false,
            force: false,
        }),
    )
    .await
    .unwrap();
    assert!(!dir.exists());
    assert!(state.db().pending_vm_creates().unwrap().is_empty());
}
