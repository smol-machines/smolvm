use super::*;
use crate::config::VmRecord;
use crate::db::{params, SmolvmDb};
use std::process::Command;
use std::time::{Duration, Instant};

fn fixture() -> (tempfile::TempDir, SmolvmDb, VmRecord) {
    let root = tempfile::tempdir().unwrap();
    let db = SmolvmDb::open_at(&root.path().join("state.db")).unwrap();
    let mut record = VmRecord::new("web".into(), 1, 128, vec![], vec![], false);
    record.created_at = 1; // every replacement is deliberately indistinguishable by time
    db.insert_vm("web", &record).unwrap();
    (root, db, record)
}

#[test]
fn stopped_machine_recreation_invalidates_review_even_with_identical_record_bytes() {
    let (_root, db, record) = fixture();
    let reviewed = db.review_workload_member("web").unwrap();
    let before = serde_json::to_vec(&db.get_vm("web").unwrap().unwrap()).unwrap();
    db.remove_vm("web").unwrap();
    db.insert_vm("web", &record).unwrap();
    let current = db.review_workload_member("web").unwrap();
    assert_eq!(current.created_at, reviewed.created_at);
    assert_eq!((current.pid, current.pid_start_time), (None, None));
    assert_ne!(current.generation, reviewed.generation);
    assert_eq!(
        before,
        serde_json::to_vec(&db.get_vm("web").unwrap().unwrap()).unwrap()
    );
    assert!(db
        .claim_workload_transfer("stale", vec![reviewed], &[])
        .is_err());
    db.claim_workload_transfer("fresh", vec![current.clone()], &[])
        .unwrap();
    db.claim_workload_transfer("fresh", vec![current], &[])
        .unwrap();
}

#[test]
fn identity_survives_updates_reopen_and_rolled_back_replacement() {
    let (root, db, mut record) = fixture();
    let before = db.review_workload_member("web").unwrap();
    record.mem = 256;
    db.insert_vm("web", &record).unwrap();
    db.update_vm("web", |record| record.cpus = 2).unwrap();
    db.update_vms(&["web".into()], |_, record| record.mem = 512)
        .unwrap();
    assert_eq!(db.review_workload_member("web").unwrap(), before);
    assert!(!db.insert_vm_if_not_exists("web", &record).unwrap());
    assert_eq!(db.review_workload_member("web").unwrap(), before);
    let mut raw = Connection::open(&db.path).unwrap();
    {
        let tx = raw.transaction().unwrap();
        tx.execute("DELETE FROM vms WHERE name = 'web'", [])
            .unwrap();
        tx.execute(
            "INSERT INTO vms(name,data) VALUES ('web', ?1)",
            [serde_json::to_vec(&record).unwrap()],
        )
        .unwrap();
        assert_ne!(
            crate::db::transfer_admission::Member::read(&tx, "web")
                .unwrap()
                .0
                .generation,
            before.generation
        );
        // Rollback must restore both the row and its original identity.
    }
    drop(raw);
    drop(db);
    let reopened = SmolvmDb::open_at(&root.path().join("state.db")).unwrap();
    assert_eq!(reopened.review_workload_member("web").unwrap(), before);
    assert_eq!(reopened.get_vm("web").unwrap().unwrap().mem, 512);
}

#[test]
fn legacy_database_migration_is_atomic_and_concurrent_openers_agree() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("legacy.db");
    let raw = Connection::open(&path).unwrap();
    raw.execute_batch("CREATE TABLE vms(name TEXT PRIMARY KEY NOT NULL, data BLOB NOT NULL);")
        .unwrap();
    let record = VmRecord::new("legacy".into(), 1, 128, vec![], vec![], false);
    let bytes = serde_json::to_vec(&record).unwrap();
    raw.execute("INSERT INTO vms VALUES ('legacy', ?1)", [&bytes])
        .unwrap();
    // An obstructed migration must roll back its table, not leave a partial
    // schema that a subsequent opener mistakes for a finished migration.
    raw.execute_batch(
        "CREATE TRIGGER vm_incarnation_delete AFTER DELETE ON vms BEGIN SELECT 1; END;",
    )
    .unwrap();
    assert!(SmolvmDb::open_at(&path).is_err());
    assert!(!installed(&raw).unwrap());
    raw.execute_batch("DROP TRIGGER vm_incarnation_delete;")
        .unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
    let workers = (0..4)
        .map(|_| {
            let path = path.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                SmolvmDb::open_at(&path)
                    .unwrap()
                    .review_workload_member("legacy")
                    .unwrap()
            })
        })
        .collect::<Vec<_>>();
    let identities = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();
    assert!(identities.iter().all(|member| member == &identities[0]));
    assert!(valid(identities[0].generation.as_deref().unwrap()));
    assert_eq!(
        raw.query_row("SELECT data FROM vms WHERE name='legacy'", [], |row| row
            .get::<_, Vec<u8>>(0))
            .unwrap(),
        bytes
    );
    // A connection opened before the migration must still use the new triggers.
    raw.execute("INSERT OR REPLACE INTO vms VALUES ('legacy', ?1)", [&bytes])
        .unwrap();
    let after = SmolvmDb::open_at(&path)
        .unwrap()
        .review_workload_member("legacy")
        .unwrap();
    assert_ne!(after.generation, identities[0].generation);
}

#[test]
fn independent_legacy_writer_cannot_reauthorize_a_stale_claim_retry() {
    const PATH: &str = "SMOL_TEST_INCARNATION_DATABASE";
    if let Some(path) = std::env::var_os(PATH) {
        // Use only the old vms row API, without opening the updated engine.
        let raw = Connection::open(path).unwrap();
        let bytes: Vec<u8> = raw
            .query_row("SELECT data FROM vms WHERE name='web'", [], |row| {
                row.get(0)
            })
            .unwrap();
        raw.execute("INSERT OR REPLACE INTO vms VALUES ('web', ?1)", [bytes])
            .unwrap();
        return;
    }
    let (_root, db, _) = fixture();
    let reviewed = db.review_workload_member("web").unwrap();
    db.claim_workload_transfer("move", vec![reviewed.clone()], &[])
        .unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "db::incarnation::tests::independent_legacy_writer_cannot_reauthorize_a_stale_claim_retry", "--test-threads=1"])
        .env(PATH, &db.path).spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("legacy writer timed out");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_ne!(
        db.review_workload_member("web").unwrap().generation,
        reviewed.generation
    );
    assert!(db
        .claim_workload_transfer("move", vec![reviewed], &[])
        .is_err());
    assert!(db.admit_workload_mutation(Some("web"), &[]).is_err());
    db.retire_workload_transfer("move").unwrap();
    db.claim_workload_transfer(
        "replacement",
        vec![db.review_workload_member("web").unwrap()],
        &[],
    )
    .unwrap();
}

#[test]
fn missing_identity_is_not_regenerated_by_readers_or_database_reopen() {
    let (root, db, _) = fixture();
    db.with_conn(|conn| {
        conn.execute("DELETE FROM vm_incarnations WHERE name='web'", [])
            .unwrap();
        Ok(())
    })
    .unwrap();
    assert!(db.review_workload_member("web").is_err());
    drop(db);
    let reopened = SmolvmDb::open_at(&root.path().join("state.db")).unwrap();
    assert!(reopened.review_workload_member("web").is_err());
    assert!(reopened.get_vm("web").unwrap().is_some());
}

#[test]
fn legacy_claims_keep_fencing_but_cannot_authorize_a_new_transfer() {
    let (_root, db, _) = fixture();
    let mut legacy = db.review_workload_member("web").unwrap();
    legacy.generation = None;
    assert!(db
        .claim_workload_transfer("new", vec![legacy.clone()], &[])
        .is_err());
    let bytes = serde_json::to_vec(&serde_json::json!({"version":1,"members":[legacy],"roots":[]}))
        .unwrap();
    db.with_conn(|conn| {
        conn.execute(
            "INSERT INTO workload_transfer_admission(operation,data) VALUES ('legacy',?1)",
            [bytes],
        )
        .unwrap();
        Ok(())
    })
    .unwrap();
    assert!(db.admit_workload_mutation(Some("web"), &[]).is_err());
    assert!(db
        .claim_workload_transfer(
            "legacy",
            vec![db.review_workload_member("web").unwrap()],
            &[]
        )
        .is_err());
    db.retire_workload_transfer("legacy").unwrap();
    db.claim_workload_transfer(
        "reviewed",
        vec![db.review_workload_member("web").unwrap()],
        &[],
    )
    .unwrap();
}

#[test]
fn boot_ticket_cannot_register_a_replacement_with_identical_stopped_metadata() {
    let (root, db, record) = fixture();
    let storage = root.path().join("disk");
    std::fs::write(&storage, b"untouched").unwrap();
    let pending = db
        .reserve_vm_launch(Some(record.clone()), &storage, &[], &[])
        .unwrap();
    let raw = Connection::open(&db.path).unwrap();
    raw.execute(
        "INSERT OR REPLACE INTO vms VALUES ('web',?1)",
        [serde_json::to_vec(&record).unwrap()],
    )
    .unwrap();
    assert!(db.admit_vm_boot(&pending.ticket.token).is_err());
    assert!(db.get_vm("web").unwrap().unwrap().pid.is_none());
    assert_eq!(std::fs::read(storage).unwrap(), b"untouched");
}

#[test]
fn legacy_boot_ticket_requires_a_new_review_before_process_registration() {
    let (root, db, record) = fixture();
    let storage = root.path().join("disk");
    std::fs::write(&storage, b"untouched").unwrap();
    let pending = db
        .reserve_vm_launch(Some(record), &storage, &[], &[])
        .unwrap();
    db.with_conn(|conn| {
        let bytes: Vec<u8> = conn
            .query_row(
                "SELECT data FROM vm_launch_admission WHERE token=?1",
                [&pending.ticket.token],
                |row| row.get(0),
            )
            .unwrap();
        let mut legacy: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        legacy["version"] = 1.into();
        legacy["member"]
            .as_object_mut()
            .unwrap()
            .remove("generation");
        conn.execute(
            "UPDATE vm_launch_admission SET data=?2 WHERE token=?1",
            params![pending.ticket.token, serde_json::to_vec(&legacy).unwrap()],
        )
        .unwrap();
        Ok(())
    })
    .unwrap();
    assert!(db.admit_vm_boot(&pending.ticket.token).is_err());
    assert!(db.get_vm("web").unwrap().unwrap().pid.is_none());
    drop(pending);
    let retry = db
        .reserve_vm_launch(Some(db.get_vm("web").unwrap().unwrap()), &storage, &[], &[])
        .unwrap();
    db.admit_vm_boot(&retry.ticket.token).unwrap();
    assert!(db.get_vm("web").unwrap().unwrap().pid.is_some());
}
