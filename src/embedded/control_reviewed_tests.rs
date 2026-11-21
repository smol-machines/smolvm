use super::*;

fn fixture() -> (tempfile::TempDir, SmolvmDb, VmRecord) {
    let root = tempfile::tempdir().unwrap();
    let db = SmolvmDb::open_at(&root.path().join("state.db")).unwrap();
    let mut record = VmRecord::new("reviewed".into(), 1, 128, vec![], vec![], false);
    record.pid = Some(0x7fff_fff0);
    record.pid_start_time = Some(1);
    db.insert_vm(&record.name, &record).unwrap();
    let reviewed = db.get_vm(&record.name).unwrap().unwrap();
    (root, db, reviewed)
}

fn bytes(db: &SmolvmDb) -> Vec<u8> {
    serde_json::to_vec(&get_record(db, "reviewed").unwrap()).unwrap()
}

#[test]
fn sdk_publication_rejects_replacements_and_reused_process_ids() {
    let (_root, db, reviewed) = fixture();
    db.update_vm(&reviewed.name, |r| r.pid_start_time = Some(2))
        .unwrap();
    let before = bytes(&db);
    assert!(mark_running_for_record(&db, &reviewed).is_err());
    assert!(mark_stopped_for_record(&db, &reviewed).is_err());
    assert_eq!(bytes(&db), before);
    db.remove_vm(&reviewed.name).unwrap();
    db.insert_vm(&reviewed.name, &reviewed).unwrap();
    let before = bytes(&db);
    assert!(mark_running_for_record(&db, &reviewed).is_err());
    assert!(mark_stopped_for_record(&db, &reviewed).is_err());
    assert_eq!(bytes(&db), before);
    let fresh = get_record(&db, &reviewed.name).unwrap();
    mark_running_for_record(&db, &fresh).unwrap();
    mark_stopped_for_record(&db, &fresh).unwrap();
    assert_eq!(get_record(&db, &reviewed.name).unwrap().pid, None);
}

#[test]
fn sdk_resume_retires_retry_authority_only_for_the_original_saved_execution() {
    let (_root, db, record) = fixture();
    let reviewed = db
        .update_vm(&record.name, |r| {
            r.paused_checkpoint = Some("/saved/first".into())
        })
        .unwrap()
        .unwrap();
    db.claim_pause_operation(&record.name, "pause-first", true)
        .unwrap();
    db.update_vm(&record.name, |r| {
        r.paused_checkpoint = Some("/saved/second".into())
    })
    .unwrap();
    let before = bytes(&db);
    assert!(finish_resumed_execution(&db, &reviewed).is_err());
    assert_eq!(bytes(&db), before);
    assert!(db
        .pause_operation_is_active(&record.name, "pause-first")
        .unwrap());
    db.update_vm(&record.name, |r| {
        r.paused_checkpoint = reviewed.paused_checkpoint.clone();
        r.pid_start_time = Some(2);
    })
    .unwrap();
    assert!(finish_resumed_execution(&db, &reviewed).is_err());
    assert!(db
        .pause_operation_is_active(&record.name, "pause-first")
        .unwrap());
    db.update_vm(&record.name, |r| r.pid_start_time = reviewed.pid_start_time)
        .unwrap();
    finish_resumed_execution(&db, &reviewed).unwrap();
    let current = get_record(&db, &record.name).unwrap();
    assert_eq!(current.state, RecordState::Running);
    assert!(current.paused_checkpoint.is_none());
    assert!(db
        .pause_operation_was_consumed(&record.name, "pause-first")
        .unwrap());
}

#[test]
fn held_process_recovery_cannot_clear_a_recreated_or_restarted_machine() {
    let (_root, db, record) = fixture();
    let reviewed = db
        .update_vm(&record.name, |r| r.state = RecordState::Stopped)
        .unwrap()
        .unwrap();
    db.update_vm(&record.name, |r| r.pid_start_time = Some(2))
        .unwrap();
    let before = bytes(&db);
    assert!(crate::agent::state_probe::refuse_start_while_held_record(&db, &reviewed).is_err());
    assert_eq!(bytes(&db), before);
    db.remove_vm(&record.name).unwrap();
    db.insert_vm(&record.name, &reviewed).unwrap();
    let before = bytes(&db);
    assert!(crate::agent::state_probe::refuse_start_while_held_record(&db, &reviewed).is_err());
    assert_eq!(bytes(&db), before);
    let fresh = get_record(&db, &record.name).unwrap();
    crate::agent::state_probe::refuse_start_while_held_record(&db, &fresh).unwrap();
    assert_eq!(get_record(&db, &record.name).unwrap().pid, None);
}

#[test]
fn sdk_resume_and_publication_leave_transfer_owned_execution_untouched() {
    let (_root, db, record) = fixture();
    let reviewed = db
        .update_vm(&record.name, |r| {
            r.paused_checkpoint = Some("/saved".into())
        })
        .unwrap()
        .unwrap();
    db.claim_pause_operation(&record.name, "saved", true)
        .unwrap();
    let member = db.review_workload_member(&record.name).unwrap();
    db.claim_workload_transfer("move", vec![member], &[])
        .unwrap();
    let before = bytes(&db);
    assert!(mark_running_for_record(&db, &reviewed).is_err());
    assert!(mark_stopped_for_record(&db, &reviewed).is_err());
    assert!(finish_resumed_execution(&db, &reviewed).is_err());
    assert_eq!(bytes(&db), before);
    assert!(db.pause_operation_is_active(&record.name, "saved").unwrap());
    db.retire_workload_transfer("move").unwrap();
    finish_resumed_execution(&db, &reviewed).unwrap();
}
