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

#[test]
fn deletion_keeps_identity_and_disk_fences_after_stopped_publication() {
    isolated(
        "deletion_keeps_identity_and_disk_fences_after_stopped_publication",
        || {
            let (db, record) = fixture();
            let mut guard = db.reserve_vm_recovery(&record).unwrap();
            guard.prepare_delete().unwrap();
            let stopped = db.get_vm(&record.name).unwrap().unwrap();
            assert_eq!(stopped.state, crate::config::RecordState::Stopped);
            assert!(stopped.restart.user_stopped);
            assert_eq!(stopped.database_identity, record.database_identity);
            let raw = Connection::open(&db.path).unwrap();
            assert!(raw
                .execute("DELETE FROM vms WHERE name=?1", [&record.name])
                .is_err());
            assert!(raw
                .execute("UPDATE vms SET data=data WHERE name=?1", [&record.name])
                .is_err());
            assert!(db.reserve_vm_recovery(&stopped).is_err());
            assert!(db
                .admit_workload_mutation(None, &[guard.runtime_dir().to_path_buf()])
                .is_err());
            let other = VmRecord::new("unrelated-delete".into(), 1, 128, vec![], vec![], false);
            db.insert_vm(&other.name, &other).unwrap();
            guard.finish_delete().unwrap();
            assert!(db.get_vm(&record.name).unwrap().is_none());
            assert!(db.get_vm(&other.name).unwrap().is_some());
            db.insert_vm(&record.name, &record).unwrap();
            assert_ne!(
                db.get_vm(&record.name).unwrap().unwrap().database_identity,
                record.database_identity
            );
        },
    );
}

#[test]
fn failed_owned_deletion_preserves_stopped_record_and_storage_for_retry() {
    isolated(
        "failed_owned_deletion_preserves_stopped_record_and_storage_for_retry",
        || {
            let (db, record) = fixture();
            let runtime = crate::agent::vm_data_dir(&record.name);
            fs::create_dir_all(runtime.parent().unwrap()).unwrap();
            fs::write(&runtime, b"not a directory").unwrap();
            assert!(
                crate::deletion::delete_machine_locked(&db, &record, None, true, false).is_err()
            );
            let stopped = db.get_vm(&record.name).unwrap().unwrap();
            assert!(stopped.restart.user_stopped);
            assert_eq!(stopped.state, crate::config::RecordState::Stopped);
            assert_eq!(fs::read(&runtime).unwrap(), b"not a directory");
            assert!(db.reserve_vm_recovery(&stopped).is_err());
            assert!(db.reserve_vm_deletion_at(&stopped, &runtime).is_ok());
            fs::remove_file(&runtime).unwrap();
            fs::create_dir(&runtime).unwrap();
            fs::write(runtime.join("storage.raw"), b"saved").unwrap();
            crate::deletion::delete_machine_locked(&db, &stopped, None, true, false).unwrap();
            assert!(!runtime.exists());
            assert!(db.get_vm(&record.name).unwrap().is_none());
        },
    );
}

#[test]
fn reviewed_deletion_refuses_a_replacement_before_touching_storage() {
    isolated(
        "reviewed_deletion_refuses_a_replacement_before_touching_storage",
        || {
            let (db, record) = fixture();
            db.remove_vm(&record.name).unwrap();
            db.insert_vm(&record.name, &record).unwrap();
            let replacement = db.get_vm(&record.name).unwrap().unwrap();
            let runtime = crate::agent::vm_data_dir(&record.name);
            fs::create_dir_all(&runtime).unwrap();
            fs::write(runtime.join("storage.raw"), b"replacement").unwrap();
            assert!(
                crate::deletion::delete_machine_locked(&db, &record, None, true, false).is_err()
            );
            assert_eq!(
                fs::read(runtime.join("storage.raw")).unwrap(),
                b"replacement"
            );
            assert_eq!(
                db.get_vm(&record.name).unwrap().unwrap().database_identity,
                replacement.database_identity
            );
        },
    );
}

#[test]
fn interrupted_owned_deletion_leaves_an_intentional_stop_after_owner_release() {
    isolated(
        "interrupted_owned_deletion_leaves_an_intentional_stop_after_owner_release",
        || {
            if std::env::var_os("SMOL_DELETE_CRASH_CHILD").is_some() {
                let db = SmolvmDb::open().unwrap();
                let record = db.get_vm("recovery-owner").unwrap().unwrap();
                let mut guard = db.reserve_vm_recovery(&record).unwrap();
                guard.prepare_delete().unwrap();
                std::process::exit(77);
            }
            let (db, record) = fixture();
            let status = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "db::recovery::tests::interrupted_owned_deletion_leaves_an_intentional_stop_after_owner_release", "--test-threads=1"])
                .env("SMOL_DELETE_CRASH_CHILD", "1")
                .status().unwrap();
            assert_eq!(status.code(), Some(77));
            let reopened = SmolvmDb::open_at(&db.path).unwrap();
            let stopped = reopened.get_vm(&record.name).unwrap().unwrap();
            assert!(stopped.restart.user_stopped);
            assert_eq!(stopped.state, crate::config::RecordState::Stopped);
            assert!(reopened.admit_machine_mutation(&record.name).is_err());
            assert!(reopened
                .reserve_reviewed_vm_preparation(
                    &LaunchReview::from_record(&stopped).unwrap(),
                    Some(&record.name),
                    &crate::agent::vm_data_dir(&record.name).join("storage.raw"),
                    &[]
                )
                .is_err());
            crate::deletion::delete_machine_locked(&reopened, &stopped, None, true, false).unwrap();
            assert!(reopened.get_vm(&record.name).unwrap().is_none());
        },
    );
}

#[cfg(unix)]
#[test]
fn deletion_refuses_symlinked_runtime_without_touching_its_target() {
    isolated(
        "deletion_refuses_symlinked_runtime_without_touching_its_target",
        || {
            let (db, record) = fixture();
            let runtime = crate::agent::vm_data_dir(&record.name);
            let other = tempfile::tempdir().unwrap();
            fs::write(other.path().join("storage.raw"), b"other machine").unwrap();
            fs::create_dir_all(runtime.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(other.path(), &runtime).unwrap();
            assert!(
                crate::deletion::delete_machine_locked(&db, &record, None, true, false)
                    .unwrap_err()
                    .to_string()
                    .contains("symlink")
            );
            assert_eq!(
                fs::read(other.path().join("storage.raw")).unwrap(),
                b"other machine"
            );
            assert!(db.get_vm(&record.name).unwrap().is_some());
            assert!(fs::symlink_metadata(runtime)
                .unwrap()
                .file_type()
                .is_symlink());
        },
    );
}

#[test]
fn interrupted_deletion_blocks_new_preparation_until_cleanup_is_retried() {
    isolated(
        "interrupted_deletion_blocks_new_preparation_until_cleanup_is_retried",
        || {
            let (db, record) = fixture();
            let runtime = crate::agent::vm_data_dir(&record.name);
            fs::create_dir_all(&runtime).unwrap();
            let disk = runtime.join("storage.raw");
            fs::write(&disk, b"old storage").unwrap();
            let mut guard = db.reserve_vm_recovery(&record).unwrap();
            guard.prepare_delete().unwrap();
            fs::remove_file(&disk).unwrap();
            drop(guard);
            let reopened = SmolvmDb::open_at(&db.path).unwrap();
            let stopped = reopened.get_vm(&record.name).unwrap().unwrap();
            let review = LaunchReview::from_record(&stopped).unwrap();
            assert!(
                reopened
                    .reserve_reviewed_vm_preparation(&review, Some(&record.name), &disk, &[])
                    .is_err(),
                "partly deleted storage was admitted for fresh disk creation"
            );
            assert!(!disk.exists());
            crate::deletion::delete_machine_locked(&reopened, &stopped, None, true, false).unwrap();
            assert!(reopened.get_vm(&record.name).unwrap().is_none());
        },
    );
}

#[test]
fn pending_deletion_fences_legacy_writers_aliases_and_cloud_claims() {
    isolated(
        "pending_deletion_fences_legacy_writers_aliases_and_cloud_claims",
        || {
            let (db, record) = fixture();
            let runtime = crate::agent::vm_data_dir(&record.name);
            fs::create_dir_all(&runtime).unwrap();
            let disk = runtime.join("storage.raw");
            fs::write(&disk, b"saved").unwrap();
            let mut guard = db
                .reserve_vm_control(&record, &runtime, std::slice::from_ref(&disk))
                .unwrap();
            guard.prepare_delete().unwrap();
            drop(guard);
            let raw = Connection::open(&db.path).unwrap();
            for sql in [
            "DELETE FROM vms WHERE name='recovery-owner'",
            "UPDATE vms SET data=data WHERE name='recovery-owner'",
            "INSERT OR REPLACE INTO vms SELECT * FROM vms WHERE name='recovery-owner'",
            "DELETE FROM vm_incarnations WHERE name='recovery-owner'",
            "UPDATE vm_incarnations SET generation=lower(hex(randomblob(24))) WHERE name='recovery-owner'",
        ] { assert!(raw.execute(sql, []).unwrap_err().to_string().contains("deletion")); }
            let legacy = serde_json::to_vec(
                &serde_json::json!({"purpose":{"Prepare":{"name":record.name}},"storage":disk}),
            )
            .unwrap();
            assert!(raw
                .execute(
                    "INSERT INTO vm_launch_admission(token,data) VALUES('legacy-delete-test',?1)",
                    [legacy]
                )
                .unwrap_err()
                .to_string()
                .contains("deletion"));
            let (member, stopped) = Member::read(&raw, &record.name).unwrap();
            assert!(stopped.restart.user_stopped);
            assert!(db
                .claim_workload_transfer("delete-cloud-refused", vec![member], &[])
                .is_err());
            let alias = runtime.parent().unwrap().join("deleting-disk-alias");
            fs::hard_link(&disk, &alias).unwrap();
            assert!(db
                .admit_workload_mutation(None, std::slice::from_ref(&alias))
                .is_err());
            let anonymous = LaunchReview::capture(&db, None).unwrap();
            assert!(db
                .reserve_reviewed_vm_preparation(&anonymous, None, &alias, &[])
                .is_err());
            let other = VmRecord::new("unrelated-pending".into(), 1, 128, vec![], vec![], false);
            db.insert_vm(&other.name, &other).unwrap();
            db.update_vm(&other.name, |r| r.mem = 256).unwrap();
            let reviewed = db.get_vm(&record.name).unwrap().unwrap();
            crate::deletion::delete_machine_locked(&db, &reviewed, None, true, false).unwrap();
            assert_eq!(fs::read(&alias).unwrap(), b"saved");
            db.admit_workload_mutation(None, &[alias]).unwrap();
            db.insert_vm(&record.name, &record).unwrap();
            let replacement = db.get_vm(&record.name).unwrap().unwrap();
            assert_ne!(replacement.database_identity, record.database_identity);
            db.reserve_reviewed_vm_preparation(
                &LaunchReview::from_record(&replacement).unwrap(),
                Some(&record.name),
                &disk,
                &[],
            )
            .unwrap();
        },
    );
}

#[test]
fn pending_deletion_rejects_corruption_and_retargeted_retry() {
    isolated(
        "pending_deletion_rejects_corruption_and_retargeted_retry",
        || {
            let (db, record) = fixture();
            let runtime = crate::agent::vm_data_dir(&record.name);
            let mut guard = db.reserve_vm_recovery(&record).unwrap();
            guard.prepare_delete().unwrap();
            drop(guard);
            let stopped = db.get_vm(&record.name).unwrap().unwrap();
            let wrong = tempfile::tempdir().unwrap();
            fs::write(wrong.path().join("keep"), b"other").unwrap();
            assert!(db.reserve_vm_deletion_at(&stopped, wrong.path()).is_err());
            assert_eq!(fs::read(wrong.path().join("keep")).unwrap(), b"other");
            let raw = Connection::open(&db.path).unwrap();
            let bytes: Vec<u8> = raw
                .query_row(
                    "SELECT data FROM vm_deletion_intents WHERE name=?1",
                    [&record.name],
                    |r| r.get(0),
                )
                .unwrap();
            raw.execute(
                "UPDATE vm_deletion_intents SET data=?2 WHERE name=?1",
                params![record.name, b"{}".as_slice()],
            )
            .unwrap();
            assert!(db.admit_machine_mutation(&record.name).is_err());
            assert!(db.reserve_vm_deletion_at(&stopped, &runtime).is_err());
            assert!(db.get_vm(&record.name).unwrap().is_some());
            raw.execute(
                "UPDATE vm_deletion_intents SET data=?2 WHERE name=?1",
                params![record.name, bytes],
            )
            .unwrap();
            crate::deletion::delete_machine_locked(&db, &stopped, None, true, false).unwrap();
        },
    );
}

#[test]
fn deletion_intent_migration_is_atomic_for_concurrent_legacy_openers() {
    isolated(
        "deletion_intent_migration_is_atomic_for_concurrent_legacy_openers",
        || {
            let (db, record) = fixture();
            let path = db.path.clone();
            drop(db);
            let raw = Connection::open(&path).unwrap();
            let triggers=raw.prepare("SELECT name FROM sqlite_schema WHERE type='trigger' AND name LIKE 'vm_deletion_%'").unwrap().query_map([],|r|r.get::<_,String>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
            for name in triggers {
                raw.execute_batch(&format!("DROP TRIGGER {name};")).unwrap();
            }
            raw.execute_batch("DROP TABLE vm_deletion_intents;")
                .unwrap();
            drop(raw);
            let workers = (0..4)
                .map(|_| {
                    let path = path.clone();
                    std::thread::spawn(move || {
                        SmolvmDb::open_at(&path).unwrap().list_vms().unwrap();
                    })
                })
                .collect::<Vec<_>>();
            for worker in workers {
                worker.join().unwrap();
            }
            let db = SmolvmDb::open_at(&path).unwrap();
            let reviewed = db.get_vm(&record.name).unwrap().unwrap();
            let mut guard = db.reserve_vm_recovery(&reviewed).unwrap();
            guard.prepare_delete().unwrap();
            drop(guard);
            assert!(db.admit_machine_mutation(&record.name).is_err());
            let stopped = db.get_vm(&record.name).unwrap().unwrap();
            crate::deletion::delete_machine_locked(&db, &stopped, None, true, false).unwrap();
        },
    );
}
