use super::*;
use crate::{config::VmRecord, db::SmolvmDb, storage::DiskFormat};

fn isolated(test: &str, run: impl FnOnce(&std::path::Path)) {
    const ROOT: &str = "SMOL_REVIEWED_CONTROL_TEST";
    if let Ok(root) = std::env::var(ROOT) {
        run(std::path::Path::new(&root));
        return;
    }
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("rootfs")).unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            &format!("agent::manager::reviewed_control_tests::{test}"),
            "--test-threads=1",
            "--nocapture",
        ])
        .env(ROOT, root.path())
        .env("SMOLVM_DATA_DIR", root.path().join("data"))
        .env("SMOLVM_AGENT_ROOTFS", root.path().join("rootfs"))
        .env("HOME", root.path().join("data"))
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

fn make_manager(root: &std::path::Path) -> AgentManager {
    let storage = root.join("storage");
    let overlay = root.join("overlay");
    std::fs::write(&storage, b"storage sentinel").unwrap();
    std::fs::write(&overlay, b"overlay sentinel").unwrap();
    let manager = AgentManager::new_named(
        "reviewed-control",
        root.join("rootfs"),
        StorageDisk::open_existing_with_format(&storage, DiskFormat::Raw).unwrap(),
        OverlayDisk::open_existing_with_format(&overlay, DiskFormat::Raw).unwrap(),
    )
    .unwrap();
    manager.detach();
    std::fs::create_dir_all(manager.pid_file.parent().unwrap()).unwrap();
    manager
}

fn fixture() -> (SmolvmDb, VmRecord) {
    let db = SmolvmDb::open().unwrap();
    let record = VmRecord::new("reviewed-control".into(), 1, 128, vec![], vec![], false);
    db.insert_vm(&record.name, &record).unwrap();
    let record = db.get_vm(&record.name).unwrap().unwrap();
    (db, record)
}

struct Child(std::process::Child);
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn child() -> Child {
    Child(
        std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .unwrap(),
    )
}

#[test]
fn retained_manager_never_adopts_a_new_pid_file_or_replacement() {
    isolated(
        "retained_manager_never_adopts_a_new_pid_file_or_replacement",
        |root| {
            let (db, record) = fixture();
            let manager = make_manager(root);
            let mut child = child();
            let pid = child.0.id() as i32;
            let start = process::process_start_time(pid).unwrap();
            let marker = format!("{pid}\n{start}");
            std::fs::write(&manager.pid_file, &marker).unwrap();
            let current = db
                .update_vm(&record.name, |r| {
                    r.pid = Some(pid);
                    r.pid_start_time = Some(start);
                })
                .unwrap()
                .unwrap();
            assert_eq!(
                manager.pid_and_start_time(),
                None,
                "a stopped handle must not adopt a newer PID file"
            );
            assert!(manager.stop().is_err());
            manager.kill_and_wait(Duration::ZERO);
            assert!(child.0.try_wait().unwrap().is_none());
            assert_eq!(std::fs::read_to_string(&manager.pid_file).unwrap(), marker);
            let fresh = make_manager(root);
            fresh.detach();
            db.remove_vm(&record.name).unwrap();
            db.insert_vm(&record.name, &current).unwrap();
            assert!(fresh.stop().is_err());
            fresh.kill_and_wait(Duration::ZERO);
            assert!(child.0.try_wait().unwrap().is_none());
            assert_eq!(std::fs::read_to_string(&manager.pid_file).unwrap(), marker);
            let mut stale = crate::embedded::handle::VmHandle::new(manager, None);
            assert!(stale
                .sync_staged_mounts(&current)
                .unwrap_err()
                .to_string()
                .contains("changed"));
        },
    );
}

#[test]
fn manager_refuses_transfer_before_shutdown_or_signal_side_effects() {
    isolated(
        "manager_refuses_transfer_before_shutdown_or_signal_side_effects",
        |root| {
            let (db, record) = fixture();
            let manager = make_manager(root);
            let mut child = child();
            let pid = child.0.id() as i32;
            let start = process::process_start_time(pid).unwrap();
            std::fs::write(&manager.pid_file, format!("{pid}\n{start}")).unwrap();
            let before = std::fs::read(&manager.pid_file).unwrap();
            let member = db.review_workload_member(&record.name).unwrap();
            db.claim_workload_transfer("moving", vec![member], &[])
                .unwrap();
            assert!(manager.stop().is_err());
            manager.kill_and_wait(Duration::ZERO);
            assert_eq!(std::fs::read(&manager.pid_file).unwrap(), before);
            assert!(child.0.try_wait().unwrap().is_none());
            assert!(!crate::agent::vm_data_dir(&record.name)
                .join("vmm-stop-requested")
                .exists());
            let mut handle = crate::embedded::handle::VmHandle::new(manager, None);
            assert!(handle
                .sync_staged_mounts(&record)
                .unwrap_err()
                .to_string()
                .contains("moving"));
            db.retire_workload_transfer("moving").unwrap();
        },
    );
}

#[test]
fn shutdown_and_cached_kill_refuse_a_recycled_process_identity() {
    isolated(
        "shutdown_and_cached_kill_refuse_a_recycled_process_identity",
        |root| {
            let (db, record) = fixture();
            let mut child = child();
            let pid = child.0.id() as i32;
            let wrong_start = process::process_start_time(pid)
                .unwrap()
                .saturating_add(123456789);
            db.update_vm(&record.name, |r| {
                r.pid = Some(pid);
                r.pid_start_time = Some(wrong_start);
            })
            .unwrap();
            let manager = make_manager(root);
            manager.inner.lock().child = Some(ChildProcess::from_identity(pid, Some(wrong_start)));
            std::fs::write(&manager.pid_file, b"keep pid file").unwrap();
            assert!(manager
                .stop_vm_process(pid, Some(wrong_start), false, None)
                .is_err());
            manager.kill_and_wait(Duration::ZERO);
            assert!(child.0.try_wait().unwrap().is_none());
            assert_eq!(std::fs::read(&manager.pid_file).unwrap(), b"keep pid file");
            assert_eq!(manager.pid_and_start_time(), Some((pid, Some(wrong_start))));
        },
    );
}

#[test]
fn manager_control_fences_original_record_and_external_disks_until_release() {
    isolated(
        "manager_control_fences_original_record_and_external_disks_until_release",
        |root| {
            let (db, record) = fixture();
            let manager = make_manager(root);
            let operation = manager.reserve_control_operation().unwrap();
            let raw = rusqlite::Connection::open(SmolvmDb::default_path().unwrap()).unwrap();
            assert!(raw
                .execute("DELETE FROM vms WHERE name='reviewed-control'", [])
                .unwrap_err()
                .to_string()
                .contains("owned by recovery"));
            assert!(db
                .reserve_vm_preparation(None, manager.storage_disk.path(), &[])
                .is_err());
            assert!(db
                .reserve_vm_preparation(None, manager.overlay_disk.path(), &[])
                .is_err());
            assert!(
                manager.reserve_control_operation().is_err(),
                "ownership is not reentrant"
            );
            let other = VmRecord::new("unrelated-control".into(), 1, 128, vec![], vec![], false);
            db.insert_vm(&other.name, &other).unwrap();
            assert_eq!(db.load_all().unwrap().1.len(), 2);
            drop(operation);
            db.update_vm(&record.name, |r| r.mem = 256).unwrap();
            assert_eq!(
                std::fs::read(manager.storage_disk.path()).unwrap(),
                b"storage sentinel"
            );
        },
    );
}

#[test]
fn paused_stop_retains_ownership_through_signal_wait_and_cleanup() {
    isolated(
        "paused_stop_retains_ownership_through_signal_wait_and_cleanup",
        |root| {
            let (db, record) = fixture();
            let ready = root.join("child-ready");
            let mut child = Child(
                std::process::Command::new("sh")
                    .args([
                        "-c",
                        "trap '' TERM; touch \"$1\"; exec sleep 60",
                        "owned-test",
                    ])
                    .arg(&ready)
                    .spawn()
                    .unwrap(),
            );
            let deadline = Instant::now() + Duration::from_secs(5);
            while !ready.exists() {
                assert!(Instant::now() < deadline);
                assert!(child.0.try_wait().unwrap().is_none());
                std::thread::sleep(Duration::from_millis(5));
            }
            let pid = child.0.id() as i32;
            let start = process::process_start_time(pid).unwrap();
            db.update_vm(&record.name, |r| {
                r.pid = Some(pid);
                r.pid_start_time = Some(start);
            })
            .unwrap();
            let manager = make_manager(root);
            std::fs::write(&manager.pid_file, format!("{pid}\n{start}")).unwrap();
            std::thread::scope(|scope| {
                let stopping = scope.spawn(|| manager.stop_paused());
                let raw = rusqlite::Connection::open(SmolvmDb::default_path().unwrap()).unwrap();
                let deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    let count: i64 = raw
                        .query_row("SELECT count(*) FROM vm_recovery_owners", [], |r| r.get(0))
                        .unwrap();
                    if count == 1 {
                        break;
                    }
                    assert!(Instant::now() < deadline && !stopping.is_finished());
                    std::thread::sleep(Duration::from_millis(5));
                }
                assert!(raw
                    .execute("UPDATE vms SET data=data WHERE name='reviewed-control'", [])
                    .unwrap_err()
                    .to_string()
                    .contains("owned by recovery"));
                let other = VmRecord::new("during-stop".into(), 1, 128, vec![], vec![], false);
                db.insert_vm(&other.name, &other).unwrap();
                assert!(!stopping.is_finished());
                stopping.join().unwrap().unwrap();
                assert_eq!(
                    raw.query_row("SELECT count(*) FROM vm_recovery_owners", [], |r| r
                        .get::<_, i64>(0))
                        .unwrap(),
                    0
                );
            });
            assert!(!process::is_our_process_strict(pid, Some(start)));
            assert!(!manager.pid_file.exists());
            db.update_vm(&record.name, |r| r.mark_process_stopped())
                .unwrap();
        },
    );
}

#[test]
fn staged_sync_refuses_retargeted_settings_before_connecting() {
    isolated(
        "staged_sync_refuses_retargeted_settings_before_connecting",
        |root| {
            let (db, record) = fixture();
            let manager = make_manager(root);
            let mut handle = crate::embedded::handle::VmHandle::new(manager, None);
            let mut altered = record.clone();
            altered.staged_mounts_detached_from = Some("another-machine".into());
            assert!(handle
                .sync_staged_mounts(&altered)
                .unwrap_err()
                .to_string()
                .contains("staged mount settings changed"));
            db.update_vm(&record.name, |r| r.mem = 256).unwrap();
        },
    );
}
