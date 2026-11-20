use super::*;
use crate::config::{RecordState, VmRecord};
use crate::db::{params, SmolvmDb};

fn fixture() -> (tempfile::TempDir, SmolvmDb) {
    let root = tempfile::tempdir().unwrap();
    let db = SmolvmDb::open_at(&root.path().join("state.db")).unwrap();
    db.insert_vm(
        "web",
        &VmRecord::new("web".into(), 1, 128, vec![], vec![], false),
    )
    .unwrap();
    (root, db)
}

#[test]
fn execution_identity_survives_stop_updates_reopen_and_rollback() {
    let (root, db) = fixture();
    let initial = db.get_vm("web").unwrap().unwrap();
    db.update_vm("web", |r| {
        r.pid = Some(12345);
        r.pid_start_time = Some(77);
        r.state = RecordState::Running;
    })
    .unwrap();
    let running = db.get_vm("web").unwrap().unwrap();
    assert_ne!(initial.execution_identity, running.execution_identity);
    assert_eq!(initial.database_identity, running.database_identity);
    db.update_vm("web", |r| r.mem = 256).unwrap();
    assert_eq!(
        db.get_vm("web").unwrap().unwrap().execution_identity,
        running.execution_identity
    );
    db.update_vm("web", |r| {
        r.pid = None;
        r.pid_start_time = None;
        r.state = RecordState::Stopped;
    })
    .unwrap();
    let stopped = db.get_vm("web").unwrap().unwrap();
    assert_eq!(stopped.execution_identity, running.execution_identity);
    assert_eq!(
        db.list_vms().unwrap()[0].1.execution_identity,
        running.execution_identity
    );
    assert!(!serde_json::to_value(&stopped)
        .unwrap()
        .as_object()
        .unwrap()
        .contains_key("execution_identity"));
    let mut raw = Connection::open(&db.path).unwrap();
    {
        let tx = raw.transaction().unwrap();
        tx.execute(
            "UPDATE vms SET data=?1 WHERE name='web'",
            [serde_json::to_vec(&running).unwrap()],
        )
        .unwrap();
        let next: String = tx
            .query_row(
                "SELECT generation FROM vm_execution_epochs WHERE name='web'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_ne!(Some(next), stopped.execution_identity);
    }
    drop(db);
    let reopened = SmolvmDb::open_at(&root.path().join("state.db")).unwrap();
    assert_eq!(
        reopened.get_vm("web").unwrap().unwrap().execution_identity,
        stopped.execution_identity
    );
    let guard = reopened
        .reserve_vm_control(&stopped, &root.path().join("runtime"), &[])
        .unwrap();
    drop(guard);
}

#[test]
fn legacy_process_start_stop_invalidates_stale_cleanup_review() {
    const KEY: &str = "SMOL_TEST_EXECUTION_DATABASE";
    if let Some(path) = std::env::var_os(KEY) {
        // This writer knows only the original JSON row format, and never opens
        // SmolvmDb or reads the execution side table.
        let raw = Connection::open(path).unwrap();
        let bytes: Vec<u8> = raw
            .query_row("SELECT data FROM vms WHERE name='web'", [], |r| r.get(0))
            .unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["pid"] = 12345.into();
        value["pid_start_time"] = 77.into();
        value["state"] = "running".into();
        raw.execute(
            "UPDATE vms SET data=?1 WHERE name='web'",
            [serde_json::to_vec(&value).unwrap()],
        )
        .unwrap();
        raw.execute("UPDATE vms SET data=?1 WHERE name='web'", [bytes])
            .unwrap();
        return;
    }
    let (root, db) = fixture();
    let reviewed = db.get_vm("web").unwrap().unwrap();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "db::execution::tests::legacy_process_start_stop_invalidates_stale_cleanup_review",
            "--test-threads=1",
        ])
        .env(KEY, &db.path)
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("legacy writer timed out");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let current = db.get_vm("web").unwrap().unwrap();
    assert_eq!(
        serde_json::to_vec(&reviewed).unwrap(),
        serde_json::to_vec(&current).unwrap()
    );
    assert_ne!(reviewed.execution_identity, current.execution_identity);
    assert!(db
        .reserve_vm_control(&reviewed, &root.path().join("runtime"), &[])
        .is_err());
    assert!(db
        .reserve_vm_deletion_at(&reviewed, &root.path().join("runtime"))
        .is_err());
    drop(
        db.reserve_vm_control(&current, &root.path().join("runtime"), &[])
            .unwrap(),
    );
}

#[test]
fn execution_migration_is_atomic_and_old_connections_observe_it() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("legacy.db");
    let raw = Connection::open(&path).unwrap();
    raw.execute_batch("CREATE TABLE vms(name TEXT PRIMARY KEY NOT NULL, data BLOB NOT NULL);")
        .unwrap();
    let record = VmRecord::new("web".into(), 1, 128, vec![], vec![], false);
    let bytes = serde_json::to_vec(&record).unwrap();
    raw.execute("INSERT INTO vms VALUES ('web',?1)", [&bytes])
        .unwrap();
    raw.execute_batch(
        "CREATE TRIGGER vm_execution_delete AFTER DELETE ON vms BEGIN SELECT 1; END;",
    )
    .unwrap();
    assert!(SmolvmDb::open_at(&path).is_err());
    assert!(!installed(&raw).unwrap());
    raw.execute_batch("DROP TRIGGER vm_execution_delete;")
        .unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
    let workers: Vec<_> = (0..4)
        .map(|_| {
            let path = path.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                SmolvmDb::open_at(&path)
                    .unwrap()
                    .get_vm("web")
                    .unwrap()
                    .unwrap()
                    .execution_identity
                    .unwrap()
            })
        })
        .collect();
    let ids: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
    assert!(ids.iter().all(|id| id == &ids[0]));
    assert_eq!(
        raw.query_row("SELECT data FROM vms WHERE name='web'", [], |r| r
            .get::<_, Vec<u8>>(0))
            .unwrap(),
        bytes
    );
    raw.execute("INSERT OR REPLACE INTO vms VALUES ('web',?1)", [&bytes])
        .unwrap();
    let db = SmolvmDb::open_at(&path).unwrap();
    assert_ne!(
        db.get_vm("web")
            .unwrap()
            .unwrap()
            .execution_identity
            .as_deref(),
        Some(ids[0].as_str())
    );
}

#[test]
fn missing_execution_identity_is_not_regenerated_by_observation() {
    let (root, db) = fixture();
    let raw = Connection::open(&db.path).unwrap();
    raw.execute(
        "DELETE FROM vm_execution_epochs WHERE name=?1",
        params!["web"],
    )
    .unwrap();
    drop(db);
    let db = SmolvmDb::open_at(&root.path().join("state.db")).unwrap();
    let record = db.get_vm("web").unwrap().unwrap();
    assert!(record.execution_identity.is_none());
    assert!(db
        .reserve_vm_control(&record, &root.path().join("runtime"), &[])
        .is_err());
    assert!(db.list_vms().unwrap()[0].1.execution_identity.is_none());
}
