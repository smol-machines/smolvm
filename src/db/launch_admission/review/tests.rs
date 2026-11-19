use super::*;
use crate::agent::AgentManager;
use std::{fs, process::Command};

fn fixture() -> (tempfile::TempDir, SmolvmDb, VmRecord, PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let db = SmolvmDb::open_at(&root.path().join("state.db")).unwrap();
    let record = VmRecord::new("web".into(), 1, 128, vec![], vec![], false);
    db.insert_vm("web", &record).unwrap();
    let record = db.get_vm("web").unwrap().unwrap();
    let disk = root.path().join("storage");
    fs::write(&disk, b"replacement disk stays intact").unwrap();
    (root, db, record, disk)
}

#[test]
fn read_identities_survive_clones_and_updates_but_never_exports() {
    let (_root, db, record, _) = fixture();
    let review = LaunchReview::from_record(&record.clone()).unwrap();
    let batched = db.load_all().unwrap().1.remove("web").unwrap();
    assert_eq!(batched.database_identity, record.database_identity);
    LaunchReview::from_record(&batched)
        .unwrap()
        .validate(&db)
        .unwrap();
    assert_eq!(
        serde_json::to_vec(&batched).unwrap(),
        serde_json::to_vec(&record).unwrap()
    );
    let listed = db.list_vms().unwrap().remove(0).1;
    assert_eq!(listed.database_identity, record.database_identity);
    let updated = db.update_vm("web", |r| r.mem = 256).unwrap().unwrap();
    assert_eq!(updated.database_identity, record.database_identity);
    review.validate(&db).unwrap();
    let bytes = serde_json::to_vec(&record).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("database_identity"));
    let imported: VmRecord = serde_json::from_slice(&bytes).unwrap();
    assert!(LaunchReview::from_record(&imported).is_err());
    let mut renamed = record;
    renamed.name = "clone".into();
    assert!(LaunchReview::from_record(&renamed).is_err());
    let published = db.insert_vm_for_launch("clone", &renamed).unwrap();
    LaunchReview::from_record(&published)
        .unwrap()
        .validate(&db)
        .unwrap();
    assert_ne!(published.database_identity, renamed.database_identity);
}

#[test]
fn stale_settings_cannot_prepare_boot_or_update_an_identical_replacement() {
    let (_root, db, record, disk) = fixture();
    let review = LaunchReview::from_record(&record).unwrap();
    let batched = db.load_all().unwrap().1.remove("web").unwrap();
    let batched_review = LaunchReview::from_record(&batched).unwrap();
    db.remove_vm("web").unwrap();
    db.insert_vm("web", &record).unwrap();
    let bytes = serde_json::to_vec(&db.get_vm("web").unwrap().unwrap()).unwrap();
    assert_eq!(bytes, serde_json::to_vec(&record).unwrap());
    assert!(batched_review.validate(&db).is_err());
    assert!(db
        .update_vm_for_record(&batched, |_| panic!("must not touch replacement"))
        .is_err());
    assert!(db
        .reserve_reviewed_vm_preparation(&review, Some("web"), &disk, &[])
        .is_err());
    assert!(db
        .reserve_reviewed_vm_launch(&review, Some(record.clone()), &disk, &[], &[])
        .is_err());
    assert!(db
        .update_reviewed_vm(&review, "web", |_| panic!("must not touch replacement"))
        .is_err());
    assert!(db
        .update_reviewed_vm_durable(&review, "web", |_| panic!("must not touch replacement"))
        .is_err());
    assert_eq!(
        bytes,
        serde_json::to_vec(&db.get_vm("web").unwrap().unwrap()).unwrap()
    );
    assert_eq!(fs::read(&disk).unwrap(), b"replacement disk stays intact");
    let current = LaunchReview::capture(&db, Some("web")).unwrap();
    let preparation = db
        .reserve_reviewed_vm_preparation(&current, Some("web"), &disk, &[])
        .unwrap();
    drop(preparation);
    let ticket = db
        .reserve_reviewed_vm_launch(&current, Some(record), &disk, &[], &[])
        .unwrap();
    ticket.review().unwrap().validate(&db).unwrap();
}

#[test]
fn deleted_or_previously_absent_reviews_cannot_adopt_a_new_machine() {
    let (_root, db, record, disk) = fixture();
    let existing = LaunchReview::from_record(&record).unwrap();
    db.remove_vm("web").unwrap();
    assert!(db
        .reserve_reviewed_vm_launch(&existing, Some(record.clone()), &disk, &[], &[])
        .is_err());
    assert!(db.get_vm("web").unwrap().is_none());
    let absent = LaunchReview::capture(&db, Some("web")).unwrap();
    db.insert_vm("web", &record).unwrap();
    assert!(db
        .reserve_reviewed_vm_preparation(&absent, Some("web"), &disk, &[])
        .is_err());
    assert!(db
        .reserve_reviewed_vm_launch(&absent, Some(record.clone()), &disk, &[], &[])
        .is_err());
    db.remove_vm("web").unwrap();
    let ticket = db
        .reserve_reviewed_vm_launch(&absent, Some(record), &disk, &[], &[])
        .unwrap();
    assert!(absent.validate(&db).is_err());
    ticket.review().unwrap().validate(&db).unwrap();
}

#[test]
fn a_review_cannot_cross_databases_even_with_copied_row_identities() {
    let (root, db, record, disk) = fixture();
    let other = SmolvmDb::open_at(&root.path().join("other.db")).unwrap();
    other.insert_vm("web", &record).unwrap();
    let generation = record
        .database_identity
        .as_ref()
        .unwrap()
        .generation
        .clone();
    other
        .with_conn(|conn| {
            conn.execute(
                "UPDATE vm_incarnations SET generation = ?1 WHERE name = 'web'",
                [generation],
            )
            .unwrap();
            Ok(())
        })
        .unwrap();
    let review = LaunchReview::from_record(&record).unwrap();
    assert!(other
        .reserve_reviewed_vm_launch(&review, Some(record), &disk, &[], &[])
        .is_err());
    review.validate(&db).unwrap();
}

#[test]
fn corrupt_identity_remains_observable_but_never_means_an_absent_machine() {
    let (_root, db, _record, disk) = fixture();
    db.with_conn(|conn| {
        conn.execute("DELETE FROM vm_incarnations WHERE name = 'web'", [])
            .unwrap();
        Ok(())
    })
    .unwrap();
    let record = db.get_vm("web").unwrap().unwrap();
    assert_eq!(db.list_vms().unwrap().len(), 1);
    let batched = db.load_all().unwrap().1.remove("web").unwrap();
    assert!(batched.database_identity.is_none());
    assert!(LaunchReview::from_record(&batched).is_err());
    assert!(LaunchReview::capture(&db, Some("web")).is_err());
    assert!(LaunchReview::from_record(&record).is_err());
    assert!(db.reserve_vm_launch(Some(record), &disk, &[], &[]).is_err());
    assert_eq!(fs::read(disk).unwrap(), b"replacement disk stays intact");
}

#[test]
fn stale_manager_refuses_replacement_before_disk_growth_or_startup_side_effects() {
    const ROOT: &str = "SMOL_TEST_REVIEWED_LAUNCH_ROOT";
    const TEST: &str = "db::launch_admission::review::tests::stale_manager_refuses_replacement_before_disk_growth_or_startup_side_effects";
    const REPLACE: &str = "SMOL_TEST_REPLACE_REVIEWED_MACHINE";
    if let Some(path) = std::env::var_os(REPLACE) {
        let raw = rusqlite::Connection::open(path).unwrap();
        raw.execute(
            "INSERT OR REPLACE INTO vms(name,data) SELECT name,data FROM vms WHERE name = 'web'",
            [],
        )
        .unwrap();
        return;
    }
    let Some(root) = std::env::var_os(ROOT).map(PathBuf::from) else {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("rootfs")).unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--test-threads=1", "--nocapture"])
            .env(ROOT, root.path())
            .env("HOME", root.path().join("home"))
            .env("SMOLVM_DATA_DIR", root.path().join("home"))
            .env("SMOLVM_AGENT_ROOTFS", root.path().join("rootfs"))
            .env("SMOLVM_USAGE_DIR", "")
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
        return;
    };
    let db = SmolvmDb::open().unwrap();
    assert!(db.path.starts_with(root.join("home")));
    let mut record = VmRecord::new("web".into(), 1, 128, vec![], vec![], false);
    record.storage_gb = Some(1);
    record.overlay_gb = Some(1);
    db.insert_vm("web", &record).unwrap();
    let mut reviewed = db.get_vm("web").unwrap().unwrap();
    let manager = AgentManager::for_vm_record(&reviewed).unwrap();
    manager.detach();
    // A second process performs the replacement with the legacy row format.
    // Keep settings byte-identical and the same on-disk paths.
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", TEST, "--test-threads=1", "--nocapture"])
        .env(REPLACE, &db.path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let storage = manager.storage_path().to_path_buf();
    let bytes = storage.metadata().unwrap().len();
    let config = crate::agent::vm_data_dir("web").join("agent.config.json");
    fs::write(&config, b"replacement runtime config").unwrap();
    reviewed.storage_gb = Some(2);
    assert!(AgentManager::for_vm_record(&reviewed).is_err());
    assert_eq!(storage.metadata().unwrap().len(), bytes);
    let error = manager
        .start_via_subprocess(
            vec![],
            vec![],
            crate::agent::VmResources::default(),
            crate::agent::LaunchFeatures::default(),
        )
        .unwrap_err();
    assert!(error.to_string().contains("changed since"), "{error}");
    assert_eq!(fs::read(config).unwrap(), b"replacement runtime config");
    assert_eq!(storage.metadata().unwrap().len(), bytes);
    assert!(db
        .get_vm("web")
        .unwrap()
        .unwrap()
        .agent_rootfs_digest
        .is_none());
    assert_eq!(
        db.with_read_conn(|conn| Ok(conn
            .query_row("SELECT count(*) FROM vm_launch_admission", [], |row| row
                .get::<_, i64>(0))
            .unwrap()))
            .unwrap(),
        0
    );
    AgentManager::for_vm_record(&db.get_vm("web").unwrap().unwrap())
        .unwrap()
        .detach();
}
