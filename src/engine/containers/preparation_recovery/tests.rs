use super::*;
use crate::db::transfer_admission::preparation::Phase;
use sha2::{Digest, Sha256};

fn fixture(root: &Path) -> (Arc<Engine>, ContainerRecord, Preparation) {
    let engine = crate::engine::test_engine(root);
    let id = "a".repeat(64);
    let mut vm = crate::config::VmRecord::new("legacy-owner".into(), 1, 128, vec![], vec![], false);
    vm.pid = Some(12345);
    vm.pid_start_time = Some(77);
    vm.state = crate::config::RecordState::Running;
    vm.labels.insert(MACHINE_LABEL.into(), id.clone());
    engine.db.insert_vm(&vm.name, &vm).unwrap();
    let mut record: ContainerRecord = serde_json::from_value(serde_json::json!({
        "id":id,"name":"legacy","created":"2026-11-19T00:00:00Z",
        "image":"alpine","image_id":"","pull_ref":"","machine":vm.name,
        "config":{},"host_config":{},"host_config_raw":{},"networks":{},
        "path":"true","args":[],"state":StateRecord::default(),
        "restart_count":0,"execution_generation":1,"ports":[],"mounts":[]
    }))
    .unwrap();
    record.state.status = "running".into();
    record.state.pid = 12345;
    record.state.started_at = "2026-11-19T00:01:00Z".into();
    let session = crate::engine::container_session::Session::new(
        root.join("agent.sock"),
        vm.name,
        smolvm_protocol::container_session::Origin {
            generation: 1,
            started_at: record.state.started_at.clone(),
        },
    );
    let mut saved = saved_execution(&engine, &record, &session).unwrap();
    saved.container_generation = 0;
    saved.machine_execution = None;
    saved.machine_execution_identity = None;
    record.saved_execution = Some(saved);
    engine.store.save_container(&record).unwrap();
    let inventory = serde_json::json!({"version":3,"selected":[record.id]});
    let fingerprint = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&inventory).unwrap())
    );
    let preparation = Preparation {
        version: 1,
        operation: "legacy-proof".into(),
        phase: Phase::Reserved,
        fingerprint,
        inventory,
    };
    (engine, record, preparation)
}

fn journal(engine: &Engine, record: &ContainerRecord, preparation: &Preparation) -> Vec<u8> {
    capture(
        engine,
        &preparation.operation,
        &preparation.fingerprint,
        std::slice::from_ref(&record.id),
        &[],
    )
    .unwrap()
    .unwrap()
}

fn reserve(
    engine: &Engine,
    record: &ContainerRecord,
    preparation: &Preparation,
    journal: &[u8],
) -> crate::Result<Preparation> {
    engine.db.reserve_workload_preparation_with_recovery(
        preparation.clone(),
        vec![engine.db.review_workload_member(&record.machine).unwrap()],
        &[engine.store.container_dir(&record.id)],
        Some(journal),
    )
}

fn legacy_exit(engine: &Engine, record: &ContainerRecord) {
    let mut record = record.clone();
    record.saved_execution = None;
    record.state.status = "exited".into();
    record.state.pid = 0;
    record.state.exit_code = 17;
    engine.store.save_container(&record).unwrap();
}

fn counts(root: &Path) -> (i64, i64, i64) {
    let db = rusqlite::Connection::open(root.join("test.db")).unwrap();
    (
        db.query_row(
            "SELECT count(*) FROM workload_transfer_preparations",
            [],
            |r| r.get(0),
        )
        .unwrap(),
        db.query_row(
            "SELECT count(*) FROM workload_transfer_admission WHERE retired=0",
            [],
            |r| r.get(0),
        )
        .unwrap(),
        db.query_row(
            "SELECT count(*) FROM workload_preparation_recovery",
            [],
            |r| r.get(0),
        )
        .unwrap(),
    )
}

#[test]
fn legacy_execution_journal_and_admission_commit_or_rollback_together() {
    let root = tempfile::tempdir().unwrap();
    let (engine, record, preparation) = fixture(root.path());
    let journal = journal(&engine, &record, &preparation);
    let db = rusqlite::Connection::open(root.path().join("test.db")).unwrap();
    db.execute_batch("CREATE TRIGGER refuse_recovery BEFORE INSERT ON workload_preparation_recovery BEGIN SELECT RAISE(ABORT, 'disk failure'); END;").unwrap();
    assert!(reserve(&engine, &record, &preparation, &journal).is_err());
    assert_eq!(counts(root.path()), (0, 0, 0));
    engine.db.admit_machine_mutation(&record.machine).unwrap();
    db.execute_batch("DROP TRIGGER refuse_recovery").unwrap();
    reserve(&engine, &record, &preparation, &journal).unwrap();
    assert_eq!(counts(root.path()), (1, 1, 1));
    assert!(engine.db.admit_machine_mutation(&record.machine).is_err());
    assert!(reserve(&engine, &record, &preparation, b"changed ownership").is_err());
    assert_eq!(counts(root.path()), (1, 1, 1));
    let retained: Journal = serde_json::from_slice(&journal).unwrap();
    assert!(retained.executions[0]
        .saved_execution
        .as_ref()
        .unwrap()
        .machine_execution_identity
        .is_some());
    // Upgrading ownership never rewrites the live old supervisor's record.
    assert!(engine
        .store
        .load_container(&record.id)
        .unwrap()
        .unwrap()
        .saved_execution
        .unwrap()
        .machine_execution_identity
        .is_none());
}

#[test]
fn legacy_exit_journal_survives_owner_loss_and_cancellation() {
    let root = tempfile::tempdir().unwrap();
    let (engine, record, preparation) = fixture(root.path());
    let journal = journal(&engine, &record, &preparation);
    // The old supervisor can exit between capture and claim admission.
    legacy_exit(&engine, &record);
    reserve(&engine, &record, &preparation, &journal).unwrap();
    drop(engine);
    let engine = crate::engine::test_engine(root.path());
    assert!(engine
        .db
        .cancel_workload_preparation(&preparation.operation)
        .is_err());
    let cancelled = engine
        .db
        .cancel_workload_preparation_checked(&preparation.operation, |p, b| {
            check_cancel(&engine, p, b)
        })
        .unwrap();
    assert_eq!(cancelled.phase, Phase::Cancelled);
    assert_eq!(counts(root.path()), (1, 0, 1));
    engine.db.admit_machine_mutation(&record.machine).unwrap();
}

#[test]
fn cancellation_retains_recovery_for_a_legacy_exit_racing_its_gate() {
    let root = tempfile::tempdir().unwrap();
    let (engine, record, preparation) = fixture(root.path());
    reserve(
        &engine,
        &record,
        &preparation,
        &journal(&engine, &record, &preparation),
    )
    .unwrap();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let other_db = crate::db::SmolvmDb::open_at(&root.path().join("test.db")).unwrap();
    let machine = record.machine.clone();
    let worker = std::thread::spawn(move || {
        ready_rx.recv().unwrap();
        let result = other_db.admit_machine_mutation(&machine);
        done_tx.send(result.is_ok()).unwrap();
    });
    let cancelled = engine
        .db
        .cancel_workload_preparation_checked(&preparation.operation, |p, b| {
            check_cancel(&engine, p, b)?;
            legacy_exit(&engine, &record);
            ready_tx.send(()).unwrap();
            assert!(
                !done_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
                "legacy cleanup fails immediately against an occupied admission gate"
            );
            Ok(())
        })
        .unwrap();
    assert_eq!(cancelled.phase, Phase::Cancelled);
    worker.join().unwrap();
    assert_eq!(
        counts(root.path()),
        (1, 0, 1),
        "cancellation must not discard ownership needed after the old cleanup failed"
    );
    drop(engine);
    let engine = crate::engine::test_engine(root.path());
    assert!(engine
        .db
        .cancel_workload_preparation_checked(&preparation.operation, |p, b| check_cancel(
            &engine, p, b
        ))
        .is_ok());
    assert_eq!(counts(root.path()), (1, 0, 1));
}

#[test]
fn cancellation_failure_preserves_both_the_claim_and_recovery() {
    let root = tempfile::tempdir().unwrap();
    let (engine, record, preparation) = fixture(root.path());
    reserve(
        &engine,
        &record,
        &preparation,
        &journal(&engine, &record, &preparation),
    )
    .unwrap();
    let db = rusqlite::Connection::open(root.path().join("test.db")).unwrap();
    db.execute_batch("CREATE TRIGGER refuse_cancellation BEFORE UPDATE ON workload_transfer_preparations BEGIN SELECT RAISE(ABORT, 'disk failure'); END;").unwrap();
    assert!(engine
        .db
        .cancel_workload_preparation_checked(&preparation.operation, |p, b| check_cancel(
            &engine, p, b
        ))
        .is_err());
    assert_eq!(counts(root.path()), (1, 1, 1));
    assert_eq!(
        engine
            .db
            .workload_preparation(&preparation.operation)
            .unwrap()
            .unwrap()
            .phase,
        Phase::Reserved
    );
    db.execute_batch("DROP TRIGGER refuse_cancellation")
        .unwrap();
    engine
        .db
        .cancel_workload_preparation_checked(&preparation.operation, |p, b| {
            check_cancel(&engine, p, b)
        })
        .unwrap();
    assert_eq!(counts(root.path()), (1, 0, 1));
}

#[test]
fn recovery_refuses_an_engine_root_symlink_retarget() {
    let root = tempfile::tempdir().unwrap();
    let original = root.path().join("original");
    let replacement = root.path().join("replacement");
    std::fs::create_dir(&original).unwrap();
    std::fs::create_dir(&replacement).unwrap();
    let (_, record, preparation) = fixture(&original);
    let (replacement_engine, _, _) = fixture(&replacement);
    replacement_engine.store.save_container(&record).unwrap();
    let alias = root.path().join("alias");
    std::os::unix::fs::symlink(&original, &alias).unwrap();
    let engine = crate::engine::test_engine(&alias);
    let journal = journal(&engine, &record, &preparation);
    assert!(check_cancel(&engine, &preparation, Some(&journal)).is_ok());
    std::fs::remove_file(&alias).unwrap();
    std::os::unix::fs::symlink(&replacement, &alias).unwrap();
    assert!(check_cancel(&engine, &preparation, Some(&journal)).is_err());
}

#[test]
fn preparation_refuses_an_exit_that_lost_ownership_before_capture() {
    let root = tempfile::tempdir().unwrap();
    let (engine, record, preparation) = fixture(root.path());
    legacy_exit(&engine, &record);
    let capture_now = || {
        capture(
            &engine,
            &preparation.operation,
            &preparation.fingerprint,
            std::slice::from_ref(&record.id),
            &[],
        )
    };
    assert!(capture_now().is_err());
    assert_eq!(counts(root.path()), (0, 0, 0));
    engine
        .db
        .update_vm(&record.machine, |vm| {
            vm.pid = None;
            vm.pid_start_time = None;
            vm.state = crate::config::RecordState::Stopped;
        })
        .unwrap();
    assert!(
        capture_now().unwrap().is_none(),
        "finished stopped containers remain transferable"
    );
    let mut terminal = engine.store.load_container(&record.id).unwrap().unwrap();
    terminal.host_config.auto_remove = true;
    engine.store.save_container(&terminal).unwrap();
    assert!(
        capture_now().is_err(),
        "do not race automatic removal even after the VM stops"
    );
    terminal.host_config.auto_remove = false;
    terminal.host_config.restart_policy.name = "on-failure".into();
    engine.store.save_container(&terminal).unwrap();
    assert!(
        capture_now().is_err(),
        "do not steal a not-yet-queued legacy restart"
    );
}

#[test]
fn recovery_refuses_replaced_directories_generations_and_corrupt_journals() {
    let root = tempfile::tempdir().unwrap();
    let (engine, record, preparation) = fixture(root.path());
    let journal = journal(&engine, &record, &preparation);
    assert!(check_cancel(&engine, &preparation, Some(&journal)).is_ok());
    assert!(check_cancel(&engine, &preparation, Some(b"{")).is_err());
    let mut later = record.clone();
    later.execution_generation += 1;
    engine.store.save_container(&later).unwrap();
    assert!(check_cancel(&engine, &preparation, Some(&journal)).is_err());
    engine.store.save_container(&record).unwrap();
    let dir = engine.store.container_dir(&record.id);
    std::fs::rename(&dir, root.path().join("original-container")).unwrap();
    engine.store.save_container(&record).unwrap();
    assert!(check_cancel(&engine, &preparation, Some(&journal)).is_err());
}

fn cancel_retaining(engine: &Engine, preparation: &Preparation) {
    engine
        .db
        .cancel_workload_preparation_checked(&preparation.operation, |p, b| {
            check_cancel(engine, p, b)
        })
        .unwrap();
}

#[tokio::test]
async fn cancelled_legacy_exit_is_adopted_after_adapter_reopen() {
    let root = tempfile::tempdir().unwrap();
    let (engine, record, preparation) = fixture(root.path());
    reserve(
        &engine,
        &record,
        &preparation,
        &journal(&engine, &record, &preparation),
    )
    .unwrap();
    legacy_exit(&engine, &record);
    // Simulate old restart bookkeeping failing against the reservation.
    let mut old = engine.store.load_container(&record.id).unwrap().unwrap();
    old.restart_count = 1;
    old.state.error = "environment is moving".into();
    old.user_stopped = true;
    engine.store.save_container(&old).unwrap();
    cancel_retaining(&engine, &preparation);
    drop(engine);
    let engine = crate::engine::test_engine(root.path());
    assert_eq!(
        engine.db.pending_preparation_recoveries().unwrap(),
        vec![preparation.operation.clone()]
    );
    let (wake, live) = adoption::pass(&engine, &preparation.operation)
        .await
        .unwrap();
    assert_eq!(wake, vec![record.id.clone()]);
    assert!(live.is_empty());
    let adopted = engine.store.load_container(&record.id).unwrap().unwrap();
    assert!(exit_cleanup::pending(&adopted));
    assert_eq!(adopted.state.exit_code, 17);
    assert_eq!(adopted.restart_count, 0);
    assert!(adopted.user_stopped);
    assert!(adopted
        .saved_execution
        .unwrap()
        .machine_execution_identity
        .is_some());
    assert_eq!(counts(root.path()), (1, 0, 0));
    assert!(engine
        .db
        .pending_preparation_recoveries()
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn recovery_does_not_adopt_or_modify_a_live_legacy_execution() {
    let root = tempfile::tempdir().unwrap();
    let (engine, record, preparation) = fixture(root.path());
    reserve(
        &engine,
        &record,
        &preparation,
        &journal(&engine, &record, &preparation),
    )
    .unwrap();
    cancel_retaining(&engine, &preparation);
    let path = engine.store.container_dir(&record.id).join("config.json");
    let before = std::fs::read(&path).unwrap();
    let (wake, live) = adoption::pass(&engine, &preparation.operation)
        .await
        .unwrap();
    assert!(wake.is_empty());
    assert_eq!(live.len(), 1);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(counts(root.path()), (1, 0, 1));
    legacy_exit(&engine, &record);
    let (wake, live) = adoption::pass(&engine, &preparation.operation)
        .await
        .unwrap();
    assert_eq!(wake, vec![record.id]);
    assert!(live.is_empty());
    assert_eq!(counts(root.path()), (1, 0, 0));
}

#[tokio::test]
async fn adoption_rejects_a_later_machine_execution_and_changed_configuration() {
    for changed_configuration in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let (engine, record, preparation) = fixture(root.path());
        reserve(
            &engine,
            &record,
            &preparation,
            &journal(&engine, &record, &preparation),
        )
        .unwrap();
        legacy_exit(&engine, &record);
        cancel_retaining(&engine, &preparation);
        if changed_configuration {
            let mut current = engine.store.load_container(&record.id).unwrap().unwrap();
            current.config.env.push("CHANGED=1".into());
            engine.store.save_container(&current).unwrap();
        } else {
            engine
                .db
                .update_vm(&record.machine, |vm| {
                    vm.pid = Some(23456);
                    vm.pid_start_time = Some(88);
                })
                .unwrap();
            engine
                .db
                .update_vm(&record.machine, |vm| {
                    vm.pid = None;
                    vm.pid_start_time = None;
                    vm.state = crate::config::RecordState::Stopped;
                })
                .unwrap();
        }
        let path = engine.store.container_dir(&record.id).join("config.json");
        let before = std::fs::read(&path).unwrap();
        assert!(adoption::pass(&engine, &preparation.operation)
            .await
            .is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(counts(root.path()), (1, 0, 1));
    }
}

#[tokio::test]
async fn adopted_exit_survives_failed_journal_retirement_and_retry() {
    let root = tempfile::tempdir().unwrap();
    let (engine, record, preparation) = fixture(root.path());
    reserve(
        &engine,
        &record,
        &preparation,
        &journal(&engine, &record, &preparation),
    )
    .unwrap();
    legacy_exit(&engine, &record);
    cancel_retaining(&engine, &preparation);
    let db = rusqlite::Connection::open(root.path().join("test.db")).unwrap();
    db.execute_batch("CREATE TRIGGER refuse_retirement BEFORE DELETE ON workload_preparation_recovery BEGIN SELECT RAISE(ABORT,'fixture failure'); END;").unwrap();
    assert!(adoption::pass(&engine, &preparation.operation)
        .await
        .is_err());
    assert!(exit_cleanup::pending(
        &engine.store.load_container(&record.id).unwrap().unwrap()
    ));
    assert_eq!(counts(root.path()), (1, 0, 1));
    db.execute_batch("DROP TRIGGER refuse_retirement").unwrap();
    drop(engine);
    let engine = crate::engine::test_engine(root.path());
    let (wake, live) = adoption::pass(&engine, &preparation.operation)
        .await
        .unwrap();
    assert_eq!(wake, vec![record.id]);
    assert!(live.is_empty());
    assert_eq!(counts(root.path()), (1, 0, 0));
}

#[tokio::test]
async fn obsolete_journals_do_not_change_replacements_or_recreate_removed_containers() {
    for removed in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let (engine, record, preparation) = fixture(root.path());
        reserve(
            &engine,
            &record,
            &preparation,
            &journal(&engine, &record, &preparation),
        )
        .unwrap();
        cancel_retaining(&engine, &preparation);
        if removed {
            engine.store.remove_container(&record.id);
        } else {
            let mut current = record.clone();
            current.execution_generation += 1;
            engine.store.save_container(&current).unwrap();
        }
        let path = engine.store.container_dir(&record.id).join("config.json");
        let before = std::fs::read(&path).ok();
        let (wake, live) = adoption::pass(&engine, &preparation.operation)
            .await
            .unwrap();
        assert!(wake.is_empty() && live.is_empty());
        assert_eq!(std::fs::read(&path).ok(), before);
        assert_eq!(counts(root.path()), (1, 0, 0));
    }
}

#[tokio::test]
async fn another_transfer_blocks_only_its_own_recovery_resources() {
    for same_machine in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let (engine, record, preparation) = fixture(root.path());
        let unrelated =
            crate::config::VmRecord::new("unrelated".into(), 1, 128, vec![], vec![], false);
        engine.db.insert_vm(&unrelated.name, &unrelated).unwrap();
        let data = engine.store.root().join("unrelated-volume");
        std::fs::create_dir(&data).unwrap();
        reserve(
            &engine,
            &record,
            &preparation,
            &journal(&engine, &record, &preparation),
        )
        .unwrap();
        legacy_exit(&engine, &record);
        cancel_retaining(&engine, &preparation);
        let machine = if same_machine {
            &record.machine
        } else {
            &unrelated.name
        };
        engine
            .db
            .claim_workload_transfer(
                "later-move",
                vec![engine.db.review_workload_member(machine).unwrap()],
                &[data],
            )
            .unwrap();
        let result = adoption::pass(&engine, &preparation.operation).await;
        if same_machine {
            assert!(result.is_err());
            assert_eq!(counts(root.path()), (1, 1, 1));
            assert!(engine
                .store
                .load_container(&record.id)
                .unwrap()
                .unwrap()
                .saved_execution
                .is_none());
        } else {
            assert_eq!(result.unwrap().0, vec![record.id]);
            assert_eq!(counts(root.path()), (1, 1, 0));
        }
        engine.db.retire_workload_transfer("later-move").unwrap();
    }
}

#[tokio::test]
async fn terminal_handoff_keeps_unrelated_ordinary_operations_admitted() {
    let root = tempfile::tempdir().unwrap();
    let (engine, record, preparation) = fixture(root.path());
    let unrelated =
        crate::config::VmRecord::new("outside-handoff".into(), 1, 128, vec![], vec![], false);
    engine.db.insert_vm(&unrelated.name, &unrelated).unwrap();
    let outside_data = engine.store.root().join("outside-data");
    std::fs::create_dir(&outside_data).unwrap();
    reserve(
        &engine,
        &record,
        &preparation,
        &journal(&engine, &record, &preparation),
    )
    .unwrap();
    legacy_exit(&engine, &record);
    cancel_retaining(&engine, &preparation);
    let spawn = crate::engine::supervisor::lock(
        engine
            .store
            .root()
            .join(format!("spawn-{}.lock", record.id)),
    )
    .await
    .unwrap();
    let worker_engine = engine.clone();
    let operation = preparation.operation.clone();
    let task = tokio::spawn(async move { adoption::pass(&worker_engine, &operation).await });
    let db = rusqlite::Connection::open(root.path().join("test.db")).unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let owned: bool = db
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM vm_recovery_owners WHERE name=?1)",
                    [&record.machine],
                    |row| row.get(0),
                )
                .unwrap();
            if owned {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(!task.is_finished());
    engine
        .db
        .admit_machine_mutation(&unrelated.name)
        .expect("unrelated old cleanup must not fail during handoff");
    engine.db.admit_storage_mutation(&[outside_data]).unwrap();
    assert!(engine.db.admit_machine_mutation(&record.machine).is_err());
    drop(spawn);
    let (wake, live) = tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(wake, vec![record.id]);
    assert!(live.is_empty());
    assert_eq!(counts(root.path()), (1, 0, 0));
    let owners: i64 = db
        .query_row("SELECT count(*) FROM vm_recovery_owners", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(owners, 0);
}

#[tokio::test]
async fn already_removed_vm_needs_no_signal_to_adopt_its_unowned_exit_record() {
    let root = tempfile::tempdir().unwrap();
    let (engine, record, preparation) = fixture(root.path());
    reserve(
        &engine,
        &record,
        &preparation,
        &journal(&engine, &record, &preparation),
    )
    .unwrap();
    legacy_exit(&engine, &record);
    cancel_retaining(&engine, &preparation);
    engine.db.remove_vm(&record.machine).unwrap();
    let (wake, live) = adoption::pass(&engine, &preparation.operation)
        .await
        .unwrap();
    assert_eq!(wake, vec![record.id.clone()]);
    assert!(live.is_empty());
    assert!(engine.db.get_vm(&record.machine).unwrap().is_none());
    assert!(exit_cleanup::pending(
        &engine.store.load_container(&record.id).unwrap().unwrap()
    ));
    assert_eq!(counts(root.path()), (1, 0, 0));
}

#[tokio::test]
async fn recovery_of_remaining_container_survives_removed_sibling() {
    let root = tempfile::tempdir().unwrap();
    let (engine, mut first, mut preparation) = fixture(root.path());
    let mut second = first.clone();
    second.id = "b".repeat(64);
    second.name = "remaining-legacy".into();
    second.machine = "remaining-owner".into();
    let mut vm =
        crate::config::VmRecord::new(second.machine.clone(), 1, 128, vec![], vec![], false);
    vm.pid = Some(23456);
    vm.pid_start_time = Some(88);
    vm.state = crate::config::RecordState::Running;
    vm.labels.insert(MACHINE_LABEL.into(), second.id.clone());
    engine.db.insert_vm(&vm.name, &vm).unwrap();
    second.state.pid = 23456;
    let session = crate::engine::container_session::Session::new(
        root.path().join("remaining.sock"),
        vm.name,
        smolvm_protocol::container_session::Origin {
            generation: second.execution_generation,
            started_at: second.state.started_at.clone(),
        },
    );
    let mut saved = saved_execution(&engine, &second, &session).unwrap();
    saved.container_generation = 0;
    saved.machine_execution = None;
    saved.machine_execution_identity = None;
    second.saved_execution = Some(saved);
    engine.store.save_container(&second).unwrap();
    let first_volume = engine.volumes.mountpoint("finished-data");
    let second_volume = engine.volumes.mountpoint("remaining-data");
    for (record, name, path) in [
        (&mut first, "finished-data", &first_volume),
        (&mut second, "remaining-data", &second_volume),
    ] {
        std::fs::create_dir_all(path).unwrap();
        record.mounts.push(
            serde_json::from_value(serde_json::json!({
                "kind":"volume", "source":name, "destination":"/data", "read_only":false
            }))
            .unwrap(),
        );
        engine.store.save_container(record).unwrap();
    }
    preparation.inventory["selected"] = serde_json::json!([first.id, second.id]);
    preparation.fingerprint = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&preparation.inventory).unwrap())
    );
    let retained = capture(
        &engine,
        &preparation.operation,
        &preparation.fingerprint,
        &[first.id.clone(), second.id.clone()],
        &[first_volume.clone(), second_volume.clone()],
    )
    .unwrap()
    .unwrap();
    engine
        .db
        .reserve_workload_preparation_with_recovery(
            preparation.clone(),
            vec![
                engine.db.review_workload_member(&first.machine).unwrap(),
                engine.db.review_workload_member(&second.machine).unwrap(),
            ],
            &[
                engine.store.container_dir(&first.id),
                engine.store.container_dir(&second.id),
            ],
            Some(&retained),
        )
        .unwrap();
    cancel_retaining(&engine, &preparation);
    // One older workload can finish normally while its sibling still runs.
    engine.store.remove_container(&first.id);
    std::fs::remove_dir_all(&first_volume).unwrap();
    std::fs::write(second_volume.join("proof"), "remaining data").unwrap();
    legacy_exit(&engine, &second);
    drop(engine);
    let engine = crate::engine::test_engine(root.path());
    let (wake, live) = adoption::pass(&engine, &preparation.operation)
        .await
        .unwrap();
    assert_eq!(wake, vec![second.id.clone()]);
    assert!(live.is_empty());
    assert!(!engine.store.container_dir(&first.id).exists());
    assert!(!first_volume.exists());
    assert_eq!(
        std::fs::read_to_string(second_volume.join("proof")).unwrap(),
        "remaining data"
    );
    assert!(exit_cleanup::pending(
        &engine.store.load_container(&second.id).unwrap().unwrap()
    ));
    assert_eq!(counts(root.path()), (1, 0, 0));
}

#[tokio::test]
async fn recovery_requires_original_identity_for_every_remaining_volume() {
    for missing_identity in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let (engine, mut record, preparation) = fixture(root.path());
        let volume = engine.volumes.mountpoint("retained-volume");
        std::fs::create_dir_all(&volume).unwrap();
        record.mounts.push(serde_json::from_value(serde_json::json!({
            "kind":"volume", "source":"retained-volume", "destination":"/data", "read_only":false
        })).unwrap());
        engine.store.save_container(&record).unwrap();
        let bytes = capture(
            &engine,
            &preparation.operation,
            &preparation.fingerprint,
            std::slice::from_ref(&record.id),
            std::slice::from_ref(&volume),
        )
        .unwrap()
        .unwrap();
        let mut journal: Journal = serde_json::from_slice(&bytes).unwrap();
        if missing_identity {
            journal.roots.retain(|entry| entry.path != volume);
        }
        reserve(
            &engine,
            &record,
            &preparation,
            &serde_json::to_vec(&journal).unwrap(),
        )
        .unwrap();
        cancel_retaining(&engine, &preparation);
        if !missing_identity {
            std::fs::rename(&volume, volume.with_extension("original")).unwrap();
            std::fs::create_dir(&volume).unwrap();
        }
        std::fs::write(volume.join("proof"), "do not touch").unwrap();
        legacy_exit(&engine, &record);
        let config = engine.store.container_dir(&record.id).join("config.json");
        let before = std::fs::read(&config).unwrap();
        assert!(adoption::pass(&engine, &preparation.operation)
            .await
            .is_err());
        assert_eq!(std::fs::read(&config).unwrap(), before);
        assert_eq!(
            std::fs::read_to_string(volume.join("proof")).unwrap(),
            "do not touch"
        );
        assert_eq!(counts(root.path()), (1, 0, 1));
    }
}
