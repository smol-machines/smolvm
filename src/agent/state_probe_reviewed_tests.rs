use super::*;

fn isolated(test: &str, run: impl FnOnce()) {
    const FLAG: &str = "SMOL_REVIEWED_RECOVERY_TEST";
    if std::env::var_os(FLAG).is_some() {
        run();
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            &format!("agent::state_probe::reviewed_recovery_tests::{test}"),
            "--test-threads=1",
            "--nocapture",
        ])
        .env(FLAG, "1")
        .env("HOME", root.path())
        .env("SMOLVM_DATA_DIR", root.path())
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

struct Child(std::process::Child);
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn fixture() -> (SmolvmDb, VmRecord, Child, std::path::PathBuf) {
    let child = Child(
        std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .unwrap(),
    );
    let db = SmolvmDb::open().unwrap();
    let mut record = VmRecord::new("reviewed-recovery".into(), 1, 128, vec![], vec![], false);
    record.state = RecordState::Unreachable;
    record.pid = Some(child.0.id() as i32);
    record.pid_start_time = Some(crate::process::process_start_time(record.pid.unwrap()).unwrap());
    db.insert_vm(&record.name, &record).unwrap();
    let record = db.get_vm(&record.name).unwrap().unwrap();
    let proof = crate::agent::vm_data_dir(&record.name).join("s/proof");
    std::fs::create_dir_all(proof.parent().unwrap()).unwrap();
    std::fs::write(&proof, b"retained snapshot").unwrap();
    (db, record, child, proof)
}

fn bytes(db: &SmolvmDb, name: &str) -> Vec<u8> {
    serde_json::to_vec(&db.get_vm(name).unwrap()).unwrap()
}

#[test]
fn stale_recovery_cannot_signal_or_clean_a_replacement_or_new_execution() {
    isolated(
        "stale_recovery_cannot_signal_or_clean_a_replacement_or_new_execution",
        || {
            let (db, record, mut child, proof) = fixture();
            db.update_vm(&record.name, |r| {
                r.pid_start_time = r.pid_start_time.map(|v| v + 1)
            })
            .unwrap();
            let before = bytes(&db, &record.name);
            assert!(recover_unreachable_machine_in_db(&record, &db).is_err());
            assert_eq!(bytes(&db, &record.name), before);
            assert!(child.0.try_wait().unwrap().is_none());
            db.remove_vm(&record.name).unwrap();
            db.insert_vm(&record.name, &record).unwrap();
            let before = bytes(&db, &record.name);
            assert!(recover_unreachable_machine_in_db(&record, &db).is_err());
            assert_eq!(bytes(&db, &record.name), before);
            assert!(child.0.try_wait().unwrap().is_none());
            assert_eq!(std::fs::read(proof).unwrap(), b"retained snapshot");
            assert!(!crate::agent::vm_data_dir(&record.name)
                .join("vmm-stop-requested")
                .exists());
        },
    );
}

#[test]
fn transfer_ownership_refuses_recovery_before_any_teardown() {
    isolated(
        "transfer_ownership_refuses_recovery_before_any_teardown",
        || {
            let (db, record, mut child, proof) = fixture();
            let member = db.review_workload_member(&record.name).unwrap();
            db.claim_workload_transfer("recover-move", vec![member], &[])
                .unwrap();
            let before = bytes(&db, &record.name);
            assert!(recover_unreachable_machine_in_db(&record, &db)
                .unwrap_err()
                .to_string()
                .contains("recover-move"));
            assert_eq!(bytes(&db, &record.name), before);
            assert!(child.0.try_wait().unwrap().is_none());
            assert_eq!(std::fs::read(proof).unwrap(), b"retained snapshot");
            assert!(!crate::agent::vm_data_dir(&record.name)
                .join("vmm-stop-requested")
                .exists());
            db.retire_workload_transfer("recover-move").unwrap();
        },
    );
}

#[test]
fn replacement_during_recovery_wait_keeps_its_runtime_and_record() {
    isolated(
        "replacement_during_recovery_wait_keeps_its_runtime_and_record",
        || {
            let (db, record, mut child, proof) = fixture();
            let mut replacement = Vec::new();
            let error = recover_unreachable_machine_with(&record, &db, |_| {
                child.0.kill().unwrap();
                child.0.wait().unwrap();
                db.remove_vm(&record.name).unwrap();
                db.insert_vm(&record.name, &record).unwrap();
                replacement = bytes(&db, &record.name);
                Ok(crate::process::VmStop::Exited(0))
            })
            .unwrap_err();
            assert!(error.to_string().contains("changed"));
            assert_eq!(bytes(&db, &record.name), replacement);
            assert_eq!(std::fs::read(proof).unwrap(), b"retained snapshot");
        },
    );
}

#[test]
fn recovery_requires_a_database_review_and_rejects_a_deleted_request() {
    isolated(
        "recovery_requires_a_database_review_and_rejects_a_deleted_request",
        || {
            let (db, record, mut child, proof) = fixture();
            let portable: VmRecord =
                serde_json::from_slice(&serde_json::to_vec(&record).unwrap()).unwrap();
            assert!(recover_unreachable_machine_in_db(&portable, &db).is_err());
            db.remove_vm(&record.name).unwrap();
            assert!(recover_unreachable_machine_in_db(&record, &db).is_err());
            assert!(db.get_vm(&record.name).unwrap().is_none());
            assert!(child.0.try_wait().unwrap().is_none());
            assert_eq!(std::fs::read(proof).unwrap(), b"retained snapshot");
        },
    );
}

#[test]
fn reviewed_recovery_reaps_its_original_process_and_cleans_its_runtime() {
    isolated(
        "reviewed_recovery_reaps_its_original_process_and_cleans_its_runtime",
        || {
            let (db, record, _child, proof) = fixture();
            recover_unreachable_machine_in_db(&record, &db).unwrap();
            assert!(!crate::process::is_alive(record.pid.unwrap()));
            let current = db.get_vm(&record.name).unwrap().unwrap();
            assert_eq!(current.state, RecordState::Stopped);
            assert_eq!(current.pid, None);
            assert!(!proof.exists());
        },
    );
}
