use super::*;
use std::{
    fs,
    process::Command,
    time::{Duration, Instant},
};

fn isolated(name: &str, run: impl FnOnce()) {
    if std::env::var_os("SMOL_RECOVERY_OWNER_TEST").is_some() {
        run();
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            &format!("db::recovery::tests::{name}"),
            "--test-threads=1",
            "--nocapture",
        ])
        .env("SMOL_RECOVERY_OWNER_TEST", "1")
        .env("HOME", root.path())
        .env("SMOLVM_DATA_DIR", root.path())
        .env("DOCKER_CONFIG", root.path().join("docker"))
        .env_remove("XDG_DATA_HOME")
        .env_remove("XDG_CACHE_HOME")
        .env_remove("XDG_CONFIG_HOME")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn fixture() -> (SmolvmDb, VmRecord) {
    let db = SmolvmDb::open().unwrap();
    let record = VmRecord::new("recovery-owner".into(), 1, 128, vec![], vec![], false);
    db.insert_vm(&record.name, &record).unwrap();
    let record = db.get_vm(&record.name).unwrap().unwrap();
    (db, record)
}

#[test]
fn recovery_fences_legacy_writers_without_blocking_other_machines_or_readers() {
    isolated(
        "recovery_fences_legacy_writers_without_blocking_other_machines_or_readers",
        || {
            let (db, record) = fixture();
            let guard = db.reserve_vm_recovery(&record).unwrap();
            let raw = Connection::open(&db.path).unwrap();
            for sql in [
            "DELETE FROM vms WHERE name='recovery-owner'",
            "UPDATE vms SET data=data WHERE name='recovery-owner'",
            "INSERT OR REPLACE INTO vms SELECT * FROM vms WHERE name='recovery-owner'",
            "DELETE FROM vm_incarnations WHERE name='recovery-owner'",
            "UPDATE vm_incarnations SET generation=lower(hex(randomblob(24))) WHERE name='recovery-owner'",
            "INSERT OR REPLACE INTO vm_incarnations SELECT * FROM vm_incarnations WHERE name='recovery-owner'",
        ] { assert!(raw.execute(sql, []).unwrap_err().to_string().contains("owned by recovery"), "{sql}"); }
            assert_eq!(
                db.get_vm(&record.name).unwrap().unwrap().database_identity,
                record.database_identity
            );
            assert_eq!(db.load_all().unwrap().1.len(), 1);
            let other = VmRecord::new("unrelated".into(), 1, 128, vec![], vec![], false);
            db.insert_vm(&other.name, &other).unwrap();
            db.update_vm(&other.name, |r| r.mem = 256).unwrap();
            let reviewed_other = db.get_vm(&other.name).unwrap().unwrap();
            db.update_vm_for_record(&reviewed_other, |r| {
                r.mem = 512;
                Ok(())
            })
            .unwrap();
            assert!(raw
                .execute(
                    "UPDATE vms SET name='recovery-owner' WHERE name='unrelated'",
                    []
                )
                .is_err());
            db.remove_vm(&other.name).unwrap();
            assert!(db.admit_machine_mutation(&record.name).is_err());
            guard.mark_stopped().unwrap();
            db.update_vm(&record.name, |r| r.mem = 256).unwrap();
            assert_eq!(
                db.get_vm(&record.name).unwrap().unwrap().database_identity,
                record.database_identity
            );
            assert!(rows(&raw).unwrap().is_empty());
        },
    );
}

#[test]
fn recovery_reserves_runtime_aliases_and_refuses_pending_preparation() {
    isolated(
        "recovery_reserves_runtime_aliases_and_refuses_pending_preparation",
        || {
            let (db, record) = fixture();
            let root = tempfile::tempdir().unwrap();
            let disk = root.path().join("disk");
            fs::write(&disk, b"disk").unwrap();
            let review = LaunchReview::from_record(&record).unwrap();
            let pending = db
                .reserve_reviewed_vm_preparation(&review, Some(&record.name), &disk, &[])
                .unwrap();
            assert!(db.reserve_vm_recovery(&record).is_err());
            drop(pending);
            let guard = db.reserve_vm_recovery(&record).unwrap();
            assert!(db
                .reserve_reviewed_vm_preparation(&review, Some(&record.name), &disk, &[])
                .is_err());
            let anonymous = LaunchReview::capture(&db, None).unwrap();
            assert!(db
                .reserve_reviewed_vm_preparation(
                    &anonymous,
                    None,
                    &guard.runtime.join("storage"),
                    &[]
                )
                .is_err());
            #[cfg(unix)]
            {
                fs::create_dir_all(&guard.runtime).unwrap();
                let alias = root.path().join("alias");
                std::os::unix::fs::symlink(&guard.runtime, &alias).unwrap();
                assert!(db
                    .admit_workload_mutation(None, &[alias.join("storage")])
                    .is_err());
            }
            drop(guard);
            db.reserve_reviewed_vm_preparation(&review, Some(&record.name), &disk, &[])
                .unwrap();
        },
    );
}

#[test]
fn recovery_rejects_stale_reviews_and_old_guards_cannot_release_new_owners() {
    isolated(
        "recovery_rejects_stale_reviews_and_old_guards_cannot_release_new_owners",
        || {
            let (db, record) = fixture();
            db.update_vm(&record.name, |r| r.pid = Some(i32::MAX))
                .unwrap();
            assert!(db.reserve_vm_recovery(&record).is_err());
            db.update_vm(&record.name, |r| r.pid = None).unwrap();
            db.remove_vm(&record.name).unwrap();
            db.insert_vm(&record.name, &record).unwrap();
            assert!(db.reserve_vm_recovery(&record).is_err());
            let current = db.get_vm(&record.name).unwrap().unwrap();
            let first = db.reserve_vm_recovery(&current).unwrap();
            let raw = Connection::open(&db.path).unwrap();
            raw.execute("DELETE FROM vm_recovery_owners", []).unwrap();
            let second = db.reserve_vm_recovery(&current).unwrap();
            drop(first);
            assert!(db.admit_machine_mutation(&record.name).is_err());
            second.mark_stopped().unwrap();
            db.admit_machine_mutation(&record.name).unwrap();
        },
    );
}

#[test]
fn corrupt_recovery_ownership_fails_closed_but_remains_observable() {
    isolated(
        "corrupt_recovery_ownership_fails_closed_but_remains_observable",
        || {
            let (db, record) = fixture();
            let guard = db.reserve_vm_recovery(&record).unwrap();
            let raw = Connection::open(&db.path).unwrap();
            raw.execute("UPDATE vm_recovery_owners SET data='{}'", [])
                .unwrap();
            assert!(db.admit_machine_mutation(&record.name).is_err());
            assert!(db.reserve_vm_recovery(&record).is_err());
            assert!(db.get_vm(&record.name).unwrap().is_some());
            assert!(raw.execute("DELETE FROM vms", []).is_err());
            drop(guard);
            db.admit_machine_mutation(&record.name).unwrap();
        },
    );
}

#[test]
fn crashed_recovery_owner_releases_only_after_confirmed_exit() {
    const CHILD: &str = "SMOL_RECOVERY_OWNER_CHILD";
    if let Some(ready) = std::env::var_os(CHILD) {
        let db = SmolvmDb::open().unwrap();
        let record = db.get_vm("recovery-owner").unwrap().unwrap();
        let _guard = db.reserve_vm_recovery(&record).unwrap();
        fs::write(ready, b"owned").unwrap();
        std::thread::sleep(Duration::from_secs(60));
        panic!("owner was not terminated");
    }
    isolated(
        "crashed_recovery_owner_releases_only_after_confirmed_exit",
        || {
            let (db, record) = fixture();
            let root = tempfile::tempdir().unwrap();
            let ready = root.path().join("ready");
            let mut child=Command::new(std::env::current_exe().unwrap()).args(["--exact","db::recovery::tests::crashed_recovery_owner_releases_only_after_confirmed_exit","--test-threads=1"]).env(CHILD,&ready).spawn().unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            while !ready.exists() && Instant::now() < deadline {
                if child.try_wait().unwrap().is_some() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let owned = ready.exists();
            let fenced = owned && db.admit_machine_mutation(&record.name).is_err();
            let _ = child.kill();
            child.wait().unwrap();
            assert!(owned && fenced);
            db.admit_machine_mutation(&record.name).unwrap();
            assert_eq!(
                db.get_vm(&record.name).unwrap().unwrap().database_identity,
                record.database_identity
            );
            assert!(rows(&Connection::open(&db.path).unwrap())
                .unwrap()
                .is_empty());
            db.reserve_vm_recovery(&record)
                .unwrap()
                .mark_stopped()
                .unwrap();
        },
    );
}

#[test]
fn recovery_reviews_competing_owners_of_disks_outside_the_runtime_directory() {
    isolated(
        "recovery_reviews_competing_owners_of_disks_outside_the_runtime_directory",
        || {
            let (db, record) = fixture();
            let root = tempfile::tempdir().unwrap();
            let disk = root.path().join("external-disk");
            fs::write(&disk, b"external disk").unwrap();
            let review = LaunchReview::from_record(&record).unwrap();
            let launch = db
                .reserve_reviewed_vm_launch(&review, Some(record.clone()), &disk, &[], &[])
                .unwrap();
            // Register this isolated test process without starting a VMM. The
            // reservation's file ownership is the same as an admitted helper's.
            db.admit_vm_boot(&launch.ticket.token).unwrap();
            let current = db.get_vm(&record.name).unwrap().unwrap();
            let raw = Connection::open(&db.path).unwrap();
            let bytes: Vec<u8> = raw
                .query_row(
                    "SELECT data FROM vm_launch_admission WHERE token=?1",
                    [&launch.ticket.token],
                    |r| r.get(0),
                )
                .unwrap();
            let mut competing: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            competing["child"] = serde_json::Value::Null;
            competing["member"] = serde_json::Value::Null;
            competing["purpose"] = serde_json::json!({"Prepare":{"name":null}});
            raw.execute(
                "INSERT INTO vm_launch_admission(token,data) VALUES ('competing',?1)",
                [serde_json::to_vec(&competing).unwrap()],
            )
            .unwrap();
            assert!(db.reserve_vm_recovery(&current).is_err());
            assert_eq!(fs::read(&disk).unwrap(), b"external disk");
            raw.execute(
                "DELETE FROM vm_launch_admission WHERE token='competing'",
                [],
            )
            .unwrap();
            let guard = db.reserve_vm_recovery(&current).unwrap();
            assert!(db
                .admit_workload_mutation(None, std::slice::from_ref(&disk))
                .is_err());
            drop(guard);
            db.admit_workload_mutation(None, &[disk]).unwrap();
        },
    );
}
