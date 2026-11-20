use super::*;
use crate::db::transfer_admission::preparation::{Phase, Preparation};
use sha2::{Digest, Sha256};

fn fixture(root: &std::path::Path) -> (Arc<Engine>, Arc<Container>) {
    let id = "a".repeat(64);
    let engine = Engine::open_with_db(
        crate::engine::EngineConfig {
            root: root.join("engine"),
            socket: root.join("api.sock"),
        },
        Some(id.clone()),
        crate::db::SmolvmDb::open_at(&root.join("test.db")).unwrap(),
    )
    .unwrap();
    let mut vm = crate::config::VmRecord::new("exit-owner".into(), 1, 128, vec![], vec![], false);
    vm.labels.insert(MACHINE_LABEL.into(), id.clone());
    vm.state = crate::config::RecordState::Stopped;
    engine.db.insert_vm(&vm.name, &vm).unwrap();
    let mut record: ContainerRecord = serde_json::from_value(serde_json::json!({
        "id": id, "name": "exit", "created": "", "image": "", "image_id": "",
        "pull_ref": "", "machine": vm.name, "config": {}, "host_config": {}, "host_config_raw": {},
        "networks": {}, "path": "true", "args": [], "state": StateRecord::default(),
        "restart_count": 0, "execution_generation": 1, "ports": [], "mounts": []
    }))
    .unwrap();
    let session = crate::engine::container_session::Session::new(
        root.join("agent.sock"),
        vm.name,
        smolvm_protocol::container_session::Origin {
            generation: 1,
            started_at: "2026-11-19T00:00:00Z".into(),
        },
    );
    record.saved_execution = Some(saved_execution(&engine, &record, &session).unwrap());
    record.state.status = "exited".into();
    record.state.exit_code = 17;
    std::fs::create_dir_all(engine.store.container_dir(&record.id)).unwrap();
    engine.store.save_container_durable(&record).unwrap();
    let c = Container::from_record(record);
    engine.containers.write().insert(c.id(), c.clone());
    (engine, c)
}

#[test]
fn deferred_exit_refuses_recreated_machines_and_later_executions() {
    let root = tempfile::tempdir().unwrap();
    let (engine, c) = fixture(root.path());
    let record = c.record();
    let original = reviewed_machine(&engine, &record).unwrap().unwrap();
    let mut later = record.clone();
    later.execution_generation += 1;
    assert!(reviewed_machine(&engine, &later).is_err());
    engine
        .db
        .update_vm(&original.name, |vm| {
            vm.pid = Some(12345);
            vm.pid_start_time = Some(77);
            vm.state = crate::config::RecordState::Running;
        })
        .unwrap();
    assert!(reviewed_machine(&engine, &record).is_err());
    let mut current_execution = record.clone();
    let current_vm = engine.db.get_vm(&original.name).unwrap().unwrap();
    let current_saved = current_execution.saved_execution.as_mut().unwrap();
    current_saved.machine_execution_identity = current_vm.execution_identity;
    current_saved.machine_execution =
        Some(engine.db.review_workload_member(&original.name).unwrap());
    engine
        .db
        .update_vm(&original.name, |vm| {
            vm.pid = None;
            vm.pid_start_time = None;
            vm.state = crate::config::RecordState::Stopped;
        })
        .unwrap();
    assert!(
        reviewed_machine(&engine, &record).is_err(),
        "stopping a later execution must not reauthorize the earlier cleanup"
    );
    assert!(
        reviewed_machine(&engine, &current_execution).is_ok(),
        "the stopped execution must remain recoverable by its own journal"
    );
    engine.db.remove_vm(&original.name).unwrap();
    engine.db.insert_vm(&original.name, &original).unwrap();
    assert!(
        reviewed_machine(&engine, &record).is_err(),
        "same name and creation timestamp must not authorize deleting a replacement"
    );
    assert_eq!(
        engine
            .db
            .get_vm(&original.name)
            .unwrap()
            .unwrap()
            .created_at,
        original.created_at
    );
}

#[tokio::test]
async fn deferred_exit_waits_for_cancel_without_losing_durable_identity() {
    let root = tempfile::tempdir().unwrap();
    let (engine, c) = fixture(root.path());
    let member = c
        .record()
        .saved_execution
        .unwrap()
        .machine_execution
        .unwrap();
    let inventory = serde_json::json!({"version": 3, "selected": [c.id()]});
    let fingerprint = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&inventory).unwrap())
    );
    engine
        .db
        .reserve_workload_preparation(
            Preparation {
                version: 1,
                operation: "exit-test".into(),
                phase: Phase::Reserved,
                fingerprint,
                inventory,
            },
            vec![member],
            &[engine.store.container_dir(&c.id())],
        )
        .unwrap();
    let (e, container) = (engine.clone(), c.clone());
    let task = tokio::spawn(async move { wait_for_admission(&e, &container).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!task.is_finished());
    assert!(pending(
        &engine.store.load_container(&c.id()).unwrap().unwrap()
    ));
    engine.db.cancel_workload_preparation("exit-test").unwrap();
    let guards = tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap();
    drop(guards);
    on_exit(
        engine.clone(),
        c.clone(),
        Exit {
            code: 17,
            oom: false,
        },
        None,
    )
    .await;
    let saved = engine.store.load_container(&c.id()).unwrap().unwrap();
    assert!(!pending(&saved));
    assert_eq!(saved.state.exit_code, 17);
    assert_eq!(
        c.exits.borrow().exits,
        0,
        "recovery must not publish the same exit twice"
    );
}

#[tokio::test]
async fn supervisor_recovery_finishes_a_durable_exit_after_the_vm_stopped() {
    let root = tempfile::tempdir().unwrap();
    let (engine, c) = fixture(root.path());
    assert!(start(&engine, &c)
        .await
        .unwrap_err()
        .message
        .contains("cleanup"));
    let config = engine.config.clone();
    let id = c.id();
    let db = engine.db.clone();
    drop(c);
    drop(engine);
    let engine = Engine::open_with_db(config, Some(id.clone()), db).unwrap();
    recover(&engine).await;
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if !pending(&engine.store.load_container(&id).unwrap().unwrap()) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        engine
            .store
            .load_container(&id)
            .unwrap()
            .unwrap()
            .state
            .exit_code,
        17
    );
}

#[test]
fn exit_completion_commits_the_restart_decision_and_retry_count_once() {
    let root = tempfile::tempdir().unwrap();
    let (engine, c) = fixture(root.path());
    c.update_durable(&engine, |r| {
        r.host_config.restart_policy.name = "on-failure".into();
        r.host_config.restart_policy.maximum_retry_count = 2;
        r.restart_count = 1;
    })
    .unwrap();
    assert_eq!(finish(&engine, &c).unwrap(), Some(1));
    assert!(finish(&engine, &c).is_err());
    let restored = engine.store.load_container(&c.id()).unwrap().unwrap();
    assert_eq!(restored.state.status, "restarting");
    assert_eq!(restored.restart_count, 2);
    assert_eq!(restored.state.exit_code, 17);
    assert!(restored.saved_execution.is_none());
}

#[tokio::test]
async fn shared_exit_retries_failed_image_cleanup_without_deleting_the_host() {
    retry_shared_cleanup(false).await;
}

#[tokio::test]
async fn shared_removal_preserves_failed_cleanup_for_retry() {
    retry_shared_cleanup(true).await;
}

async fn retry_shared_cleanup(remove_guest: bool) {
    let root = tempfile::tempdir().unwrap();
    let (mut engine, host) = fixture(root.path());
    let mut record = host.record();
    record.id = "b".repeat(64);
    record.name = "shared-exit".into();
    record.machine.clear();
    record.host_config.network_mode = format!("container:{}", host.id());
    record.saved_execution.as_mut().unwrap().image_generation = Some("boot1".into());
    let vm = reviewed_machine(&engine, &record).unwrap().unwrap();
    Arc::get_mut(&mut engine).unwrap().owner = Some(record.id.clone());
    std::fs::create_dir_all(engine.store.container_dir(&record.id)).unwrap();
    engine.store.save_container_durable(&record).unwrap();
    let guest = Container::from_record(record.clone());
    engine.containers.write().insert(guest.id(), guest.clone());
    let path = engine
        .store
        .root()
        .join("guest-image-shares")
        .join(host.id())
        .join(format!("{}.json", record.guest_image_share()));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, b"invalid json").unwrap();
    on_exit(
        engine.clone(),
        guest.clone(),
        Exit {
            code: 17,
            oom: false,
        },
        None,
    )
    .await;
    assert!(pending(
        &engine.store.load_container(&guest.id()).unwrap().unwrap()
    ));
    assert!(engine.db.admit_machine_mutation(&vm.name).is_ok());
    if remove_guest {
        for force in [false, true] {
            assert!(remove(&engine, &guest, force, false).await.is_err());
            assert!(pending(
                &engine.store.load_container(&guest.id()).unwrap().unwrap()
            ));
            assert!(engine.containers.read().contains_key(&guest.id()));
        }
    }
    std::fs::write(
        &path,
        serde_json::to_vec(&serde_json::json!({
            "generation": "boot1", "source": root.path(), "containers": [guest.id()]
        }))
        .unwrap(),
    )
    .unwrap();
    if remove_guest {
        remove(&engine, &guest, true, false).await.unwrap();
        assert!(engine.store.load_container(&guest.id()).unwrap().is_none());
        assert!(!engine.containers.read().contains_key(&guest.id()));
    } else {
        on_exit(
            engine.clone(),
            guest.clone(),
            Exit {
                code: 17,
                oom: false,
            },
            None,
        )
        .await;
        assert!(!pending(
            &engine.store.load_container(&guest.id()).unwrap().unwrap()
        ));
    }
    assert_eq!(
        engine
            .db
            .get_vm(&vm.name)
            .unwrap()
            .unwrap()
            .database_identity,
        vm.database_identity
    );
    let owners: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(owners["containers"], serde_json::json!([]));
}

#[test]
fn exit_completion_respects_stop_success_and_retry_limit() {
    for case in ["stopped", "success", "limit"] {
        let root = tempfile::tempdir().unwrap();
        let (engine, c) = fixture(root.path());
        c.update_durable(&engine, |r| {
            r.host_config.restart_policy.name = "on-failure".into();
            r.host_config.restart_policy.maximum_retry_count = 1;
            if case == "stopped" {
                r.user_stopped = true;
            }
            if case == "success" {
                r.state.exit_code = 0;
            }
            if case == "limit" {
                r.restart_count = 1;
            }
        })
        .unwrap();
        let attempts = c.record().restart_count;
        assert_eq!(finish(&engine, &c).unwrap(), None);
        let stored = engine.store.load_container(&c.id()).unwrap().unwrap();
        assert_eq!(stored.state.status, "exited");
        assert_eq!(stored.restart_count, attempts);
        assert!(stored.saved_execution.is_none());
    }
}

#[test]
fn failed_exit_completion_keeps_the_recoverable_exit_and_retry_budget() {
    let root = tempfile::tempdir().unwrap();
    let (engine, c) = fixture(root.path());
    c.update_durable(&engine, |r| {
        r.host_config.restart_policy.name = "always".into()
    })
    .unwrap();
    let dir = engine.store.container_dir(&c.id());
    std::fs::rename(&dir, root.path().join("retained-record")).unwrap();
    std::fs::write(&dir, "cannot publish here").unwrap();
    assert!(finish(&engine, &c).is_err());
    assert!(pending(&c.record()));
    assert_eq!(c.record().restart_count, 0);
}

fn queued_restart(engine: &Engine, c: &Container) -> crate::db::transfer_admission::Member {
    let member = c
        .record()
        .saved_execution
        .unwrap()
        .machine_execution
        .unwrap();
    c.update_durable(engine, |r| {
        r.host_config.restart_policy.name = "on-failure".into()
    })
    .unwrap();
    assert_eq!(finish(engine, c).unwrap(), Some(1));
    member
}

#[tokio::test]
async fn a_new_reservation_defers_a_queued_restart_without_consuming_an_attempt() {
    let root = tempfile::tempdir().unwrap();
    let (engine, c) = fixture(root.path());
    let member = queued_restart(&engine, &c);
    let roots = [engine.store.container_dir(&c.id())];
    engine
        .db
        .claim_workload_transfer("queued-move", vec![member.clone()], &roots)
        .unwrap();
    let mut wait = Box::pin(wait_for_restart_admission(&engine, &c, 1));
    tokio::select! {
        _ = &mut wait => panic!("restart passed an active transfer"),
        _ = tokio::time::sleep(Duration::from_millis(50)) => {}
    }
    let saved = engine.store.load_container(&c.id()).unwrap().unwrap();
    assert_eq!(saved.state.status, "restarting");
    assert_eq!(saved.restart_count, 1);
    assert_eq!(saved.execution_generation, 1);
    engine.db.retire_workload_transfer("queued-move").unwrap();
    let admitted = tokio::time::timeout(Duration::from_secs(3), wait)
        .await
        .unwrap()
        .unwrap();
    assert!(engine
        .db
        .claim_workload_transfer("racing-move", vec![member], &roots)
        .is_err());
    drop(admitted);
}

#[tokio::test]
async fn stop_and_later_generations_cancel_a_deferred_restart() {
    let root = tempfile::tempdir().unwrap();
    let (engine, c) = fixture(root.path());
    let member = queued_restart(&engine, &c);
    engine
        .db
        .claim_workload_transfer(
            "queued-move",
            vec![member],
            &[engine.store.container_dir(&c.id())],
        )
        .unwrap();
    let mut wait = Box::pin(wait_for_restart_admission(&engine, &c, 1));
    tokio::select! {
        _ = &mut wait => panic!("restart passed an active transfer"),
        _ = tokio::time::sleep(Duration::from_millis(50)) => {}
    }
    engine.db.retire_workload_transfer("queued-move").unwrap();
    c.update_durable(&engine, |r| r.running_at_shutdown = true)
        .unwrap();
    assert!(stop(&engine, &c, None, None).await.unwrap());
    assert!(wait.await.is_none());
    let saved = engine.store.load_container(&c.id()).unwrap().unwrap();
    assert!(saved.user_stopped);
    assert!(
        !saved.running_at_shutdown,
        "an explicit Stop must not be revived by recovery"
    );
    assert_eq!(saved.state.status, "exited");
    c.update_durable(&engine, |r| {
        r.execution_generation = 2;
        r.state.status = "restarting".into();
        r.user_stopped = false;
    })
    .unwrap();
    assert!(wait_for_restart_admission(&engine, &c, 1).await.is_none());
    assert_eq!(c.record().execution_generation, 2);
    assert_eq!(c.record().state.status, "restarting");
}

#[tokio::test]
async fn start_waits_for_in_progress_exit_cleanup_and_releases_its_locks_when_cancelled() {
    let root = tempfile::tempdir().unwrap();
    let (engine, c) = fixture(root.path());
    let teardown = c.vm.clone().lock_owned().await;
    let (e, container) = (engine.clone(), c.clone());
    let start = tokio::spawn(async move { super::super::start(&e, &container).await });
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            assert!(
                !start.is_finished(),
                "Start must wait for the ongoing teardown"
            );
            if c.op.try_lock().is_err() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    start.abort();
    assert!(start.await.unwrap_err().is_cancelled());
    assert!(c.op.try_lock().is_ok());
    assert_eq!(c.record().execution_generation, 1);
    assert!(pending(&c.record()));
    drop(teardown);
}

#[tokio::test]
async fn supervisor_shutdown_retains_a_deferred_restart_for_the_next_supervisor() {
    let root = tempfile::tempdir().unwrap();
    let (engine, c) = fixture(root.path());
    let member = queued_restart(&engine, &c);
    engine
        .db
        .claim_workload_transfer(
            "shutdown-move",
            vec![member],
            &[engine.store.container_dir(&c.id())],
        )
        .unwrap();
    shutdown_all(&engine).await;
    let saved = engine.store.load_container(&c.id()).unwrap().unwrap();
    assert!(saved.running_at_shutdown);
    assert!(!saved.user_stopped);
    assert_eq!(saved.state.status, "restarting");
    assert_eq!(saved.restart_count, 1);
    engine.db.retire_workload_transfer("shutdown-move").unwrap();
}
