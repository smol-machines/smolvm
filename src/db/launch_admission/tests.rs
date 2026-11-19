use super::*;
use std::fs;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn fixture() -> (tempfile::TempDir, SmolvmDb, PathBuf, VmRecord) {
    let root = tempfile::tempdir().unwrap();
    let db = SmolvmDb::open_at(&root.path().join("state.db")).unwrap();
    let storage = root.path().join("storage.img");
    fs::write(&storage, b"untouched").unwrap();
    let record = VmRecord::new("web".into(), 1, 128, vec![], vec![], false);
    (root, db, storage, record)
}

fn member(db: &SmolvmDb) -> Member {
    Member::from_record("web", &db.get_vm("web").unwrap().unwrap())
}

#[test]
fn startup_cancellation_rejects_delayed_boot_and_preserves_storage() {
    let (_root, db, storage, record) = fixture();
    let reservation = db.reserve_vm_launch(Some(record), &storage, &[]).unwrap();
    let token = reservation.ticket.token.clone();
    assert!(db
        .reserve_vm_launch(Some(db.get_vm("web").unwrap().unwrap()), &storage, &[])
        .is_err());
    assert!(db
        .claim_workload_transfer("pending", vec![member(&db)], &[])
        .is_err());
    drop(reservation);
    db.claim_workload_transfer("cancelled", vec![member(&db)], &[])
        .unwrap();
    assert!(db.admit_vm_boot(&token).is_err());
    db.retire_workload_transfer("cancelled").unwrap();
    assert!(
        db.admit_vm_boot(&token).is_err(),
        "retiring transfer must not restore old boot authority"
    );
    assert_eq!(fs::read(storage).unwrap(), b"untouched");
}

#[test]
fn startup_deletion_revokes_ticket_even_when_name_generation_is_reused() {
    let (_root, db, storage, record) = fixture();
    let reservation = db
        .reserve_vm_launch(Some(record.clone()), &storage, &[])
        .unwrap();
    db.remove_vm("web").unwrap().unwrap();
    assert!(db.insert_vm_if_not_exists("web", &record).unwrap());
    assert!(db.admit_vm_boot(&reservation.ticket.token).is_err());
    assert!(db.get_vm("web").unwrap().unwrap().pid.is_none());
}

#[test]
fn startup_registration_is_atomic_and_cannot_be_replayed_or_forgotten() {
    let (_root, db, storage, record) = fixture();
    let reservation = db.reserve_vm_launch(Some(record), &storage, &[]).unwrap();
    let before = member(&db);
    db.admit_vm_boot(&reservation.ticket.token).unwrap();
    let after = member(&db);
    assert_eq!(after.pid, Some(std::process::id() as i32));
    assert_eq!(
        after.pid_start_time,
        Some(ProcessIdentity::current().unwrap().start)
    );
    assert_eq!(after.created_at, before.created_at);
    assert!(db.admit_vm_boot(&reservation.ticket.token).is_err());
    drop(reservation);
    assert!(db
        .claim_workload_transfer("stale", vec![before], &[])
        .is_err());
    assert!(db.remove_vm("web").is_err());
    db.claim_workload_transfer("reviewed", vec![after], &[])
        .unwrap();
}

#[test]
fn startup_registration_preserves_saved_execution_until_restore_succeeds() {
    let (_root, db, storage, mut record) = fixture();
    record.state = RecordState::Paused;
    record.paused_checkpoint = Some(PathBuf::from("retained.checkpoint"));
    assert!(db.insert_vm_if_not_exists("web", &record).unwrap());
    db.claim_pause_operation("web", "pause-before-startup", true)
        .unwrap();
    let reservation = db
        .reserve_vm_launch(Some(record.clone()), &storage, &[])
        .unwrap();
    db.admit_vm_boot(&reservation.ticket.token).unwrap();
    let after = db.get_vm("web").unwrap().unwrap();
    assert_eq!(after.state, RecordState::Paused);
    assert_eq!(after.paused_checkpoint, record.paused_checkpoint);
    assert!(after.is_process_alive());
    assert!(db
        .pause_operation_is_active("web", "pause-before-startup")
        .unwrap());
}

#[test]
fn startup_shared_roots_include_anonymous_helpers_in_transfer_review() {
    let (root, db, storage, record) = fixture();
    assert!(db.insert_vm_if_not_exists("web", &record).unwrap());
    let share = root.path().join("share");
    let nested = share.join("child");
    fs::create_dir_all(&nested).unwrap();
    let reservation = db
        .reserve_vm_launch(None, &storage, std::slice::from_ref(&nested))
        .unwrap();
    assert!(db
        .claim_workload_transfer("pending", vec![member(&db)], std::slice::from_ref(&share))
        .is_err());
    db.admit_vm_boot(&reservation.ticket.token).unwrap();
    drop(reservation);
    assert!(db
        .claim_workload_transfer("running", vec![member(&db)], &[share])
        .is_err());
    // Unrelated environments can still be reviewed while this helper runs.
    db.claim_workload_transfer("independent", vec![member(&db)], &[])
        .unwrap();
}

#[test]
fn startup_corruption_fails_closed_and_pid_reuse_does_not_hold_ownership() {
    let (_root, db, storage, record) = fixture();
    let reservation = db.reserve_vm_launch(Some(record), &storage, &[]).unwrap();
    let identity = ProcessIdentity::current().unwrap();
    assert!(!ProcessIdentity {
        start: identity.start.wrapping_add(1),
        ..identity
    }
    .may_be_alive());
    db.with_conn(|conn| {
        conn.execute("UPDATE vm_launch_admission SET data = X'00'", [])
            .unwrap();
        Ok(())
    })
    .unwrap();
    assert!(db.admit_vm_boot(&reservation.ticket.token).is_err());
    assert!(db
        .claim_workload_transfer("corrupt", vec![member(&db)], &[])
        .is_err());
    assert!(db.remove_vm("web").is_err());
}

#[test]
fn owned_boot_rejects_replaced_config_and_legacy_entry_before_disk_access() {
    let (root, db, storage, record) = fixture();
    let reservation = db.reserve_vm_launch(Some(record), &storage, &[]).unwrap();
    let path = root.path().join("boot-config.json");
    let config = serde_json::json!({
        "startup_ticket": reservation.ticket,
        "rootfs_path": root.path().join("missing-rootfs"),
        "storage_disk_path": storage,
        "overlay_disk_path": root.path().join("missing-overlay"),
        "vsock_socket": root.path().join("socket"),
        "console_log": null,
        "startup_error_log": root.path().join("error.log"),
        "storage_size_gb": 1,
        "overlay_size_gb": 1,
        "mounts": [],
        "ports": [],
        "resources": crate::data::resources::VmResources::default(),
    });
    fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    let original = fs::read(&path).unwrap();
    let error =
        crate::internal_boot::run_owned(path.clone(), "previous-launch".into()).unwrap_err();
    assert!(error.to_string().contains("does not belong"), "{error}");
    let error = crate::internal_boot::run(path.clone()).unwrap_err();
    assert!(
        error.to_string().contains("requires the owned boot"),
        "{error}"
    );
    assert_eq!(fs::read(&path).unwrap(), original);
    assert_eq!(fs::read(&storage).unwrap(), b"untouched");
    assert!(!root.path().join("missing-overlay").exists());
    assert!(member(&db).pid.is_none());
}

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait_file(path: &Path, child: &mut OwnedChild) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !path.exists() {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "owned test child exited before publishing {}",
            path.display()
        );
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn startup_survives_controller_crash_on_both_sides_of_boot_admission() {
    const ROLE: &str = "SMOL_TEST_OWNED_STARTUP_ROLE";
    const ROOT: &str = "SMOL_TEST_OWNED_STARTUP_ROOT";
    const TEST: &str = "db::launch_admission::tests::startup_survives_controller_crash_on_both_sides_of_boot_admission";
    if let Ok(role) = std::env::var(ROLE) {
        let root = PathBuf::from(std::env::var_os(ROOT).unwrap());
        let db = SmolvmDb::open_at(&root.join("state.db")).unwrap();
        if role == "controller" {
            let record = db.get_vm("web").unwrap().unwrap();
            let _reservation = db
                .reserve_vm_launch(Some(record), &root.join("storage.img"), &[])
                .unwrap();
            fs::write(
                root.join("ticket"),
                serde_json::to_vec(&_reservation.ticket).unwrap(),
            )
            .unwrap();
            loop {
                if root.join("detach").exists() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        let ticket: BootTicket =
            serde_json::from_slice(&fs::read(root.join("ticket")).unwrap()).unwrap();
        if role == "late-boot" {
            assert!(db.admit_vm_boot(&ticket.token).is_err());
            return;
        }
        assert_eq!(role, "boot");
        db.admit_vm_boot(&ticket.token).unwrap();
        fs::write(root.join("admitted"), b"ready").unwrap();
        loop {
            std::thread::park();
        }
    }

    for phase in ["before-boot", "after-boot", "detached"] {
        let (root, db, _storage, record) = fixture();
        assert!(db.insert_vm_if_not_exists("web", &record).unwrap());
        let before = member(&db);
        let spawn = |role: &str| {
            OwnedChild(
                Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", TEST, "--nocapture"])
                    .env(ROLE, role)
                    .env(ROOT, root.path())
                    .stdout(Stdio::null())
                    .stderr(fs::File::create(root.path().join(format!("{role}.log"))).unwrap())
                    .spawn()
                    .unwrap(),
            )
        };
        let mut controller = spawn("controller");
        wait_file(&root.path().join("ticket"), &mut controller);
        let mut boot = if phase != "before-boot" {
            let mut boot = spawn("boot");
            wait_file(&root.path().join("admitted"), &mut boot);
            Some(boot)
        } else {
            None
        };
        if phase == "detached" {
            fs::write(root.path().join("detach"), b"done").unwrap();
            let deadline = Instant::now() + Duration::from_secs(15);
            while controller.0.try_wait().unwrap().is_none() {
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(10));
            }
        } else {
            controller.0.kill().unwrap();
            controller.0.wait().unwrap();
        }
        if let Some(boot) = &mut boot {
            assert!(boot.0.try_wait().unwrap().is_none());
            assert!(db
                .claim_workload_transfer("stale", vec![before], &[])
                .is_err());
            let after = member(&db);
            assert_eq!(after.pid, Some(boot.0.id() as i32));
            db.claim_workload_transfer("reviewed", vec![after], &[])
                .unwrap();
            db.retire_workload_transfer("reviewed").unwrap();
            assert!(db.remove_vm("web").is_err());
            boot.0.kill().unwrap();
            boot.0.wait().unwrap();
            db.remove_vm("web").unwrap().unwrap();
        } else {
            db.claim_workload_transfer("recovered", vec![before], &[])
                .unwrap();
            let mut late = spawn("late-boot");
            let deadline = Instant::now() + Duration::from_secs(15);
            loop {
                if let Some(status) = late.0.try_wait().unwrap() {
                    assert!(status.success());
                    break;
                }
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(db.get_vm("web").unwrap().unwrap().pid.is_none());
        }
        assert_eq!(
            fs::read(root.path().join("storage.img")).unwrap(),
            b"untouched"
        );
    }
}
