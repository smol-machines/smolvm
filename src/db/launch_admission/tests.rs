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
fn preparation_is_exclusive_without_creating_a_machine_or_authorizing_boot() {
    if !crate::test_support::in_own_process!() {
        return;
    }
    let (root, db, storage, record) = fixture();
    let preparation = db
        .reserve_vm_preparation(Some("web"), &storage, &[])
        .unwrap();
    assert!(db.get_vm("web").unwrap().is_none());
    assert!(db.admit_vm_boot(&preparation.ticket.token).is_err());
    assert!(db
        .reserve_vm_launch(Some(record.clone()), &storage, &[], &[])
        .is_err());
    assert!(db
        .reserve_vm_preparation(Some("web"), &root.path().join("new-disk"), &[])
        .is_err());
    assert!(db.remove_vm("web").is_err());
    let unrelated = db
        .reserve_vm_preparation(Some("other"), &root.path().join("other-disk"), &[])
        .unwrap();
    assert!(!root.path().join("other-disk").exists());
    assert_eq!(fs::read(&storage).unwrap(), b"untouched");
    drop(unrelated);
    drop(preparation);
    let boot = db
        .reserve_vm_launch(Some(record), &storage, &[], &[])
        .unwrap();
    db.admit_vm_boot(&boot.ticket.token).unwrap();
}

#[test]
fn preparation_and_boot_refuse_hardlinked_disks_and_shared_runtime_paths() {
    if !crate::test_support::in_own_process!() {
        return;
    }
    let (root, db, storage, _) = fixture();
    let alias = root.path().join("alias");
    fs::hard_link(&storage, &alias).unwrap();
    let runtime = root.path().join("runtime/agent.sock");
    let owner = db
        .reserve_vm_launch(None, &storage, &[], std::slice::from_ref(&runtime))
        .unwrap();
    assert!(db
        .reserve_vm_preparation(Some("other"), &alias, &[])
        .is_err());
    let other = root.path().join("other");
    fs::write(&other, b"another disk").unwrap();
    assert!(db
        .reserve_vm_launch(None, &other, &[], std::slice::from_ref(&runtime))
        .is_err());
    db.admit_vm_boot(&owner.ticket.token).unwrap();
    drop(owner);
    assert!(db.reserve_vm_preparation(None, &alias, &[]).is_err());
    assert!(db.reserve_vm_preparation(None, &other, &[runtime]).is_err());
    assert_eq!(fs::read(alias).unwrap(), b"untouched");
    assert_eq!(fs::read(other).unwrap(), b"another disk");
}

#[cfg(unix)]
#[test]
fn prospective_resources_resolve_symlink_parents_and_refuse_dangling_links() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let real = root.path().join("real");
    fs::create_dir(&real).unwrap();
    symlink(&real, root.path().join("alias")).unwrap();
    assert_eq!(
        resource_path(&root.path().join("alias/new/disk")).unwrap(),
        real.canonicalize().unwrap().join("new/disk")
    );
    symlink(root.path().join("missing"), root.path().join("dangling")).unwrap();
    assert!(resource_path(&root.path().join("dangling/disk")).is_err());
    assert!(!real.join("new").exists());
}

#[test]
fn transfer_refuses_preparation_aliases_and_future_paths_until_release() {
    if !crate::test_support::in_own_process!() {
        return;
    }
    let (root, db, storage, record) = fixture();
    db.insert_vm("web", &record).unwrap();
    let alias = root.path().join("alias");
    fs::hard_link(&storage, &alias).unwrap();
    let pending = db.reserve_vm_preparation(None, &alias, &[]).unwrap();
    assert!(db
        .claim_workload_transfer("busy", vec![member(&db)], std::slice::from_ref(&storage))
        .is_err());
    drop(pending);
    db.claim_workload_transfer("disk", vec![member(&db)], &[storage])
        .unwrap();
    assert!(db.reserve_vm_preparation(None, &alias, &[]).is_err());
    assert!(db
        .admit_workload_mutation(None, std::slice::from_ref(&alias))
        .is_err());
    db.retire_workload_transfer("disk").unwrap();
    let directory = root.path().join("shared");
    fs::create_dir(&directory).unwrap();
    let future = directory.join("new/disk");
    db.claim_workload_transfer("directory", vec![member(&db)], &[directory])
        .unwrap();
    assert!(db.reserve_vm_preparation(None, &future, &[]).is_err());
    assert!(!future.exists());
    db.retire_workload_transfer("directory").unwrap();
    let _released = db.reserve_vm_preparation(None, &future, &[]).unwrap();
    assert!(!future.exists());
    assert_eq!(fs::read(alias).unwrap(), b"untouched");
}

#[test]
fn preparation_crash_releases_ownership_without_reviving_boot_authority() {
    const ROOT: &str = "SMOL_TEST_PREPARATION_CRASH_ROOT";
    const TEST: &str = "db::launch_admission::tests::preparation_crash_releases_ownership_without_reviving_boot_authority";
    if let Some(root) = std::env::var_os(ROOT) {
        let root = PathBuf::from(root);
        let db = SmolvmDb::open_at(&root.join("state.db")).unwrap();
        let preparation = db
            .reserve_vm_preparation(Some("web"), &root.join("storage.img"), &[])
            .unwrap();
        fs::write(
            root.join("prepared"),
            serde_json::to_vec(&preparation.ticket).unwrap(),
        )
        .unwrap();
        loop {
            std::thread::park();
        }
    }
    if !crate::test_support::in_own_process!() {
        return;
    }
    let (root, db, storage, record) = fixture();
    db.insert_vm("web", &record).unwrap();
    let mut child = OwnedChild(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--test-threads=1", "--nocapture"])
            .env(ROOT, root.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait_file(&root.path().join("prepared"), &mut child);
    let ticket: BootTicket =
        serde_json::from_slice(&fs::read(root.path().join("prepared")).unwrap()).unwrap();
    assert!(db
        .claim_workload_transfer("pending-prepare", vec![member(&db)], &[])
        .is_err());
    assert!(db
        .reserve_vm_launch(Some(record.clone()), &storage, &[], &[])
        .is_err());
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    db.claim_workload_transfer("after-prepare", vec![member(&db)], &[])
        .unwrap();
    db.retire_workload_transfer("after-prepare").unwrap();
    assert!(db.admit_vm_boot(&ticket.token).is_err());
    let _fresh = db
        .reserve_vm_launch(Some(record), &storage, &[], &[])
        .unwrap();
    assert_eq!(fs::read(storage).unwrap(), b"untouched");
}

#[test]
fn preparation_blocks_real_manager_mutations_and_failed_cleanup_keeps_inventory() {
    const ROOT: &str = "SMOL_TEST_PREPARATION_ROOT";
    const TEST: &str = "db::launch_admission::tests::preparation_blocks_real_manager_mutations_and_failed_cleanup_keeps_inventory";
    let Ok(root) = std::env::var(ROOT) else {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("rootfs")).unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--test-threads=1", "--nocapture"])
            .env(ROOT, root.path())
            .env("SMOLVM_DATA_DIR", root.path().join("data"))
            .env("SMOLVM_AGENT_ROOTFS", root.path().join("rootfs"))
            .env("HOME", root.path().join("home"))
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
    use crate::agent::AgentManager;
    use crate::storage::{DiskFormat, OverlayDisk, StorageDisk};
    let root = PathBuf::from(root);
    let db = SmolvmDb::open().unwrap();
    assert!(db.path.starts_with(root.join("data")));
    let manager = AgentManager::for_vm_with_sizes("owned", Some(1), Some(1)).unwrap();
    manager.detach();
    let storage = manager.storage_path().to_path_buf();
    let record = VmRecord::new("owned".into(), 1, 128, vec![], vec![], false);
    let boot = db
        .reserve_vm_launch(Some(record), &storage, &[], &[])
        .unwrap();
    db.admit_vm_boot(&boot.ticket.token).unwrap();
    let before = storage.metadata().unwrap().len();
    assert!(AgentManager::for_vm_with_sizes("owned", Some(2), Some(2)).is_err());
    assert_eq!(storage.metadata().unwrap().len(), before);
    AgentManager::for_vm("owned").unwrap().detach();

    let anonymous = |suffix: &str| {
        let storage = root.join(format!("storage-{suffix}"));
        let overlay = root.join(format!("overlay-{suffix}"));
        fs::write(&storage, b"storage stays unchanged").unwrap();
        fs::write(&overlay, b"overlay stays unchanged").unwrap();
        let manager = AgentManager::new(
            root.join("rootfs"),
            StorageDisk::open_existing_with_format(&storage, DiskFormat::Raw).unwrap(),
            OverlayDisk::open_existing_with_format(&overlay, DiskFormat::Raw).unwrap(),
        )
        .unwrap();
        manager.detach();
        manager
    };
    let first = anonymous("first");
    let runtime = first.vsock_socket().to_path_buf();
    fs::write(&runtime, b"live runtime sentinel").unwrap();
    let owner = db
        .reserve_vm_launch(
            None,
            first.storage_path(),
            &[],
            std::slice::from_ref(&runtime),
        )
        .unwrap();
    db.admit_vm_boot(&owner.ticket.token).unwrap();
    let second = anonymous("second");
    let error = second
        .start_via_subprocess(vec![], vec![], Default::default(), Default::default())
        .unwrap_err();
    assert!(
        error.to_string().contains("owns this disk or runtime path"),
        "{error}"
    );
    assert_eq!(fs::read(runtime).unwrap(), b"live runtime sentinel");
    assert_eq!(
        fs::read(root.join("storage-second")).unwrap(),
        b"storage stays unchanged"
    );
    assert_eq!(
        fs::read(root.join("overlay-second")).unwrap(),
        b"overlay stays unchanged"
    );

    let held = AgentManager::for_vm_with_sizes("preparing", Some(1), Some(1)).unwrap();
    held.detach();
    let mut record = VmRecord::new("preparing".into(), 1, 128, vec![], vec![], false);
    record.ephemeral = true;
    record.pid = Some(i32::MAX);
    record.pid_start_time = Some(1);
    db.insert_vm("preparing", &record).unwrap();
    let preparation = db
        .reserve_vm_preparation(Some("preparing"), held.storage_path(), &[])
        .unwrap();
    let sentinel = crate::agent::vm_data_dir("preparing").join("keep");
    fs::write(&sentinel, b"preparation data").unwrap();
    let state = crate::api::state::ApiState::with_db(db.clone());
    assert!(state
        .load_persisted_machines()
        .iter()
        .any(|name| name == "preparing"));
    assert_eq!(fs::read(sentinel).unwrap(), b"preparation data");
    assert!(db.get_vm("preparing").unwrap().is_some());
    drop(preparation);
}

#[test]
fn startup_cancellation_rejects_delayed_boot_and_preserves_storage() {
    let (_root, db, storage, record) = fixture();
    let reservation = db
        .reserve_vm_launch(Some(record), &storage, &[], &[])
        .unwrap();
    let token = reservation.ticket.token.clone();
    assert!(db
        .reserve_vm_launch(Some(db.get_vm("web").unwrap().unwrap()), &storage, &[], &[])
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
        .reserve_vm_launch(Some(record.clone()), &storage, &[], &[])
        .unwrap();
    let token = reservation.ticket.token.clone();
    assert!(db.remove_vm("web").is_err());
    assert!(db.get_vm("web").unwrap().is_some());
    assert_eq!(fs::read(&storage).unwrap(), b"untouched");
    drop(reservation);
    db.remove_vm("web").unwrap().unwrap();
    assert!(db.insert_vm_if_not_exists("web", &record).unwrap());
    assert!(db.admit_vm_boot(&token).is_err());
    assert!(db.get_vm("web").unwrap().unwrap().pid.is_none());
}

#[test]
fn startup_registration_is_atomic_and_cannot_be_replayed_or_forgotten() {
    let (_root, db, storage, record) = fixture();
    let reservation = db
        .reserve_vm_launch(Some(record), &storage, &[], &[])
        .unwrap();
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
        .reserve_vm_launch(Some(record.clone()), &storage, &[], &[])
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
        .reserve_vm_launch(None, &storage, std::slice::from_ref(&nested), &[])
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
    let reservation = db
        .reserve_vm_launch(Some(record), &storage, &[], &[])
        .unwrap();
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
    let reservation = db
        .reserve_vm_launch(Some(record), &storage, &[], &[])
        .unwrap();
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
                .reserve_vm_launch(Some(record), &root.join("storage.img"), &[], &[])
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
