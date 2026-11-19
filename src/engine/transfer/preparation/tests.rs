use super::*;

fn fixture(root: &Path) -> (Arc<Engine>, Vec<String>) {
    let engine = crate::engine::test_engine(root);
    let mut ids = Vec::new();
    for (byte, name) in [('a', "web"), ('b', "database")] {
        let record = super::super::tests::record(&engine, byte, name, Some("shared"));
        let mut vm =
            crate::config::VmRecord::new(record.machine.clone(), 1, 128, vec![], vec![], false);
        vm.labels.insert(
            crate::engine::containers::MACHINE_LABEL.into(),
            record.id.clone(),
        );
        vm.env
            .push(("TOKEN".into(), "machine-preparation-secret".into()));
        engine.db.insert_vm(&record.machine, &vm).unwrap();
        ids.push(record.id);
    }
    (engine, ids)
}

fn request(engine: &Engine, ids: &[String], operation: &str) -> PrepareRequest {
    let plan = build(engine, ids).unwrap();
    PrepareRequest {
        operation: operation.into(),
        containers: plan.selected,
        fingerprint: plan.fingerprint,
    }
}

fn run(engine: &Engine, request: PrepareRequest) -> ApiResult<Preparation> {
    prepare_with_review(engine, request, |engine, selected| {
        review_with_inventory(engine, selected, live_shares)
    })
}

#[test]
fn preparation_survives_reopen_and_retries_without_leaking_or_releasing_ownership() {
    let root = tempfile::tempdir().unwrap();
    let (engine, ids) = fixture(root.path());
    let prepared = run(&engine, request(&engine, &ids, "reviewed-move")).unwrap();
    assert_eq!(prepared.phase, Phase::Prepared);
    assert!(engine.db.admit_machine_mutation("vm-web").is_err());
    assert!(engine
        .db
        .admit_storage_mutation(&[engine.volumes.mountpoint("shared")])
        .is_err());
    assert!(engine.db.retire_workload_transfer("reviewed-move").is_err());
    let public = serde_json::to_string(&response(prepared.clone()).unwrap()).unwrap();
    assert!(!public.contains("machine-preparation-secret"));
    assert!(!public.contains("image-fixture-secret"));
    assert!(!public.contains("inventory"));
    let outside = crate::config::VmRecord::new("outside".into(), 1, 128, vec![], vec![], false);
    engine.db.insert_vm("outside", &outside).unwrap();
    engine.db.admit_machine_mutation("outside").unwrap();
    drop(engine);
    let engine = crate::engine::test_engine(root.path());
    let retry = run(&engine, request(&engine, &ids, "reviewed-move")).unwrap();
    assert_eq!(retry, prepared);
    let cancelled = engine
        .db
        .cancel_workload_preparation("reviewed-move")
        .unwrap();
    assert_eq!(cancelled.phase, Phase::Cancelled);
    assert_eq!(
        engine
            .db
            .cancel_workload_preparation("reviewed-move")
            .unwrap(),
        cancelled
    );
    engine.db.admit_machine_mutation("vm-web").unwrap();
    engine
        .db
        .admit_storage_mutation(&[engine.volumes.mountpoint("shared")])
        .unwrap();
    assert!(run(&engine, request(&engine, &ids, "reviewed-move")).is_err());
}

#[test]
fn preparation_rechecks_changed_metadata_and_new_dependencies_after_reservation() {
    for add_dependency in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let (engine, ids) = fixture(root.path());
        let request = request(&engine, &ids, "changed-review");
        let mut reads = 0;
        let result = prepare_with_review(&engine, request, |engine, selected| {
            let reviewed = review_with_inventory(engine, selected, live_shares)?;
            reads += 1;
            if reads == 1 {
                if add_dependency {
                    super::super::tests::record(engine, 'c', "new-reader", Some("shared"));
                } else {
                    let mut image: ImageRecord = engine
                        .store
                        .transfer_object("images", &"e".repeat(64))
                        .unwrap();
                    image.repo_tags.push("changed:latest".into());
                    engine
                        .store
                        .save_object("images", &"e".repeat(64), &image)
                        .unwrap();
                }
            }
            Ok(reviewed)
        });
        assert!(result.is_err());
        assert_eq!(reads, 2);
        assert_eq!(
            engine
                .db
                .workload_preparation("changed-review")
                .unwrap()
                .unwrap()
                .phase,
            Phase::Cancelled
        );
        engine.db.admit_machine_mutation("vm-web").unwrap();
        engine
            .db
            .admit_storage_mutation(&[engine.volumes.mountpoint("shared")])
            .unwrap();
    }
}

#[test]
fn preparation_confirmation_cannot_revive_a_concurrent_cancellation() {
    let root = tempfile::tempdir().unwrap();
    let (engine, ids) = fixture(root.path());
    let mut reads = 0;
    let result = prepare_with_review(
        &engine,
        request(&engine, &ids, "cancelled-review"),
        |engine, selected| {
            let reviewed = review_with_inventory(engine, selected, live_shares)?;
            reads += 1;
            if reads == 2 {
                engine
                    .db
                    .cancel_workload_preparation("cancelled-review")
                    .unwrap();
            }
            Ok(reviewed)
        },
    );
    assert!(result.is_err());
    assert_eq!(
        engine
            .db
            .workload_preparation("cancelled-review")
            .unwrap()
            .unwrap()
            .phase,
        Phase::Cancelled
    );
    engine.db.admit_machine_mutation("vm-web").unwrap();
}

#[test]
fn preparation_inventory_and_ownership_commit_atomically() {
    let root = tempfile::tempdir().unwrap();
    let (engine, ids) = fixture(root.path());
    let conn = rusqlite::Connection::open(root.path().join("test.db")).unwrap();
    conn.execute_batch("CREATE TRIGGER refuse_inventory BEFORE INSERT ON workload_transfer_preparations BEGIN SELECT RAISE(ABORT, 'fixture failure'); END;").unwrap();
    assert!(run(&engine, request(&engine, &ids, "atomic-review")).is_err());
    assert!(engine
        .db
        .workload_preparation("atomic-review")
        .unwrap()
        .is_none());
    let count: i64 = conn
        .query_row(
            "SELECT count(*) FROM workload_transfer_admission WHERE operation='atomic-review'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
    engine.db.admit_machine_mutation("vm-web").unwrap();
    conn.execute_batch("DROP TRIGGER refuse_inventory").unwrap();
    run(&engine, request(&engine, &ids, "atomic-review")).unwrap();
    engine
        .db
        .cancel_workload_preparation("atomic-review")
        .unwrap();
}

#[test]
fn preparation_requires_explicit_complete_selection_and_current_review() {
    let root = tempfile::tempdir().unwrap();
    let (engine, ids) = fixture(root.path());
    let partial = request(&engine, &ids[..1], "partial-review");
    assert!(run(&engine, partial).is_err());
    assert!(engine
        .db
        .workload_preparation("partial-review")
        .unwrap()
        .is_none());
    let mut stale = request(&engine, &ids, "stale-review");
    stale.fingerprint = format!("sha256:{}", "0".repeat(64));
    assert!(run(&engine, stale).is_err());
    assert!(engine
        .db
        .workload_preparation("stale-review")
        .unwrap()
        .is_none());
    engine.db.admit_machine_mutation("vm-web").unwrap();
}

#[test]
fn preparation_never_adopts_or_releases_a_legacy_claim_with_the_same_operation() {
    let root = tempfile::tempdir().unwrap();
    let (engine, ids) = fixture(root.path());
    let reviewed = review_with_inventory(&engine, &ids, live_shares).unwrap();
    engine
        .db
        .claim_workload_transfer("legacy-owner", reviewed.claims, &reviewed.roots)
        .unwrap();
    assert!(run(&engine, request(&engine, &ids, "legacy-owner")).is_err());
    assert!(engine
        .db
        .workload_preparation("legacy-owner")
        .unwrap()
        .is_none());
    assert!(engine
        .db
        .cancel_workload_preparation("legacy-owner")
        .is_err());
    assert!(engine.db.admit_machine_mutation("vm-web").is_err());
    engine.db.retire_workload_transfer("legacy-owner").unwrap();
    engine.db.admit_machine_mutation("vm-web").unwrap();
}

#[test]
fn unreadable_preparation_never_releases_the_reserved_workload() {
    let root = tempfile::tempdir().unwrap();
    let (engine, ids) = fixture(root.path());
    run(&engine, request(&engine, &ids, "corrupt-review")).unwrap();
    let conn = rusqlite::Connection::open(root.path().join("test.db")).unwrap();
    let original: Vec<u8> = conn
        .query_row(
            "SELECT data FROM workload_transfer_preparations WHERE operation='corrupt-review'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    conn.execute(
        "UPDATE workload_transfer_preparations SET data=?1 WHERE operation='corrupt-review'",
        [b"{".as_slice()],
    )
    .unwrap();
    assert!(engine.db.workload_preparation("corrupt-review").is_err());
    assert!(engine
        .db
        .cancel_workload_preparation("corrupt-review")
        .is_err());
    assert!(engine
        .db
        .retire_workload_transfer("corrupt-review")
        .is_err());
    assert!(engine.db.admit_machine_mutation("vm-web").is_err());
    conn.execute(
        "UPDATE workload_transfer_preparations SET data=?1 WHERE operation='corrupt-review'",
        [original],
    )
    .unwrap();
    engine
        .db
        .cancel_workload_preparation("corrupt-review")
        .unwrap();
}

#[test]
fn preparation_crash_child() {
    let Some(root) = std::env::var_os("SMOLVM_TEST_PREPARATION_ROOT") else {
        return;
    };
    let (engine, ids) = fixture(Path::new(&root));
    let mut reads = 0;
    let _ = prepare_with_review(
        &engine,
        request(&engine, &ids, "interrupted-review"),
        |engine, selected| {
            reads += 1;
            if reads == 2 {
                // Exit after reservation committed, without Rust destructors.
                unsafe { libc::_exit(0) }
            }
            review_with_inventory(engine, selected, live_shares)
        },
    );
    panic!("child failed to reach the reserved boundary");
}

#[test]
fn interrupted_preparation_keeps_ownership_and_resumes_the_same_review() {
    let root = tempfile::tempdir().unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "engine::transfer::preparation::tests::preparation_crash_child",
            "--nocapture",
        ])
        .env("SMOLVM_TEST_PREPARATION_ROOT", root.path())
        .status()
        .unwrap();
    assert!(status.success());
    let engine = crate::engine::test_engine(root.path());
    let reserved = engine
        .db
        .workload_preparation("interrupted-review")
        .unwrap()
        .unwrap();
    assert_eq!(reserved.phase, Phase::Reserved);
    assert!(engine.db.admit_machine_mutation("vm-web").is_err());
    let request = PrepareRequest {
        operation: reserved.operation.clone(),
        containers: selection(&reserved).unwrap(),
        fingerprint: reserved.fingerprint.clone(),
    };
    let prepared = run(&engine, request).unwrap();
    assert_eq!(prepared.phase, Phase::Prepared);
    assert_eq!(prepared.inventory, reserved.inventory);
    engine
        .db
        .cancel_workload_preparation("interrupted-review")
        .unwrap();
    engine.db.admit_machine_mutation("vm-web").unwrap();
}
