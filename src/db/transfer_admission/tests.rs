use super::*;

fn machine(db: &SmolvmDb, name: &str) -> Member {
    let record = VmRecord::new(name.into(), 1, 128, vec![], vec![], false);
    assert!(db.insert_vm_if_not_exists(name, &record).unwrap());
    db.review_workload_member(name).unwrap()
}

#[cfg(unix)]
#[test]
fn transfer_admission_survives_owner_crash_and_fences_real_entrypoints() {
    const ROLE: &str = "SMOL_TEST_ADMISSION_ROLE";
    const ROOT: &str = "SMOL_TEST_ADMISSION_ROOT";
    if let Ok(role) = std::env::var(ROLE) {
        let root = PathBuf::from(std::env::var_os(ROOT).unwrap());
        assert!(SmolvmDb::default_path()
            .unwrap()
            .starts_with(root.join("data")));
        let db = SmolvmDb::open().unwrap();
        if role == "entrypoints" {
            let data = crate::agent::vm_data_dir("web");
            assert!(!data.exists());
            let error = crate::agent::AgentManager::for_vm_with_sizes("web", Some(1), Some(1))
                .err()
                .expect("claimed launch must fail before allocating disks");
            assert!(
                error.to_string().contains("environment is moving"),
                "{error}"
            );
            assert!(!data.exists(), "refused launch created machine storage");
            let manager = crate::agent::AgentManager::for_vm("web").unwrap();
            let error = manager
                .start_via_subprocess(vec![], vec![], Default::default(), Default::default())
                .unwrap_err();
            assert!(
                error.to_string().contains("environment is moving"),
                "{error}"
            );
            let error = manager
                .ensure_running_with_full_config(
                    vec![],
                    vec![],
                    Default::default(),
                    Default::default(),
                )
                .unwrap_err();
            assert!(
                error.to_string().contains("environment is moving"),
                "{error}"
            );
            let error = manager
                .ensure_running_via_subprocess(
                    vec![],
                    vec![],
                    Default::default(),
                    Default::default(),
                )
                .unwrap_err();
            assert!(
                error.to_string().contains("environment is moving"),
                "{error}"
            );
            let source = root.join("volume");
            for result in [
                crate::attach::attach("outside", &source, Path::new("/data"), false, &[])
                    .map(|_| ()),
                crate::attach::attach("outside", &source, Path::new("/data"), true, &[])
                    .map(|_| ()),
                crate::attach::add_share("outside", "data", &source, true),
                crate::attach::remove_share("web", "data", false),
                crate::attach::detach("web", Path::new("/data")).map(|_| ()),
            ] {
                let error = result.unwrap_err().to_string();
                assert!(
                    error.contains("transfer") || error.contains("moving"),
                    "{error}"
                );
            }
            assert!(db.get_vm("web").unwrap().unwrap().pid.is_none());
            return;
        }
        let _guard = if role == "mutation" {
            Some(db.admit_workload_mutation(Some("web"), &[]).unwrap())
        } else {
            assert_eq!(role, "claim");
            db.claim_workload_transfer(
                "crashed-owner",
                vec![db.review_workload_member("web").unwrap()],
                &[root.join("volume")],
            )
            .unwrap();
            None
        };
        std::fs::write(root.join("ready"), b"ready").unwrap();
        // The parent intentionally kills this owned child. Neither the
        // OS-lock guard nor a destructor may release the durable claim.
        loop {
            std::thread::park();
        }
    }

    let root = tempfile::tempdir().unwrap();
    let isolated_command = || {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .env(ROOT, root.path())
            .env("HOME", root.path().join("data"))
            .env("SMOLVM_DATA_DIR", root.path().join("data"))
            .env("SMOLVM_CONFIG", root.path().join("config.toml"))
            .env("DOCKER_CONFIG", root.path().join("docker"))
            .env_remove("XDG_DATA_HOME")
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("XDG_CACHE_HOME");
        command
    };
    let spawn = |role: &str| {
        isolated_command()
            .args(["--exact", "db::transfer_admission::tests::transfer_admission_survives_owner_crash_and_fences_real_entrypoints", "--nocapture"])
            .env(ROLE, role)
            .stdout(std::process::Stdio::null())
            .stderr(File::create(root.path().join(format!("{role}.log"))).unwrap())
            .spawn().unwrap()
    };
    // Resolve the default database in a child too, without mutating the
    // test runner's process-wide path environment. HOME also isolates macOS,
    // where dirs ignores XDG; CLI startup applies this same data-root mapping.
    let status = isolated_command()
        .args([
            "--exact",
            "db::transfer_admission::tests::transfer_admission_prepare_child",
            "--nocapture",
        ])
        .status()
        .unwrap();
    assert!(status.success());
    let db_path =
        PathBuf::from(std::fs::read_to_string(root.path().join("database-path")).unwrap());
    assert!(db_path.starts_with(root.path().join("data")));
    let db = SmolvmDb::open_at(&db_path).unwrap();
    let member = db.review_workload_member("web").unwrap();
    let wait_ready = |child: &mut std::process::Child| {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !root.path().join("ready").exists() {
            assert!(
                child.try_wait().unwrap().is_none(),
                "child exited before admission"
            );
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("child admission deadline expired");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    };
    let mut mutation = spawn("mutation");
    wait_ready(&mut mutation);
    let refused = db
        .claim_workload_transfer("first", vec![member.clone()], &[])
        .is_err();
    mutation.kill().unwrap();
    mutation.wait().unwrap();
    assert!(refused);
    std::fs::remove_file(root.path().join("ready")).unwrap();
    db.claim_workload_transfer("first", vec![member], &[])
        .unwrap();
    db.retire_workload_transfer("first").unwrap();
    let mut owner = spawn("claim");
    wait_ready(&mut owner);
    owner.kill().unwrap();
    owner.wait().unwrap();
    assert!(db.admit_workload_mutation(Some("web"), &[]).is_err());
    // A late release for an older operation cannot release the new owner.
    db.retire_workload_transfer("first").unwrap();
    assert!(db.admit_workload_mutation(Some("web"), &[]).is_err());
    let mut entrypoints = spawn("entrypoints");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if let Some(status) = entrypoints.try_wait().unwrap() {
            assert!(
                status.success(),
                "{}",
                std::fs::read_to_string(root.path().join("entrypoints.log")).unwrap()
            );
            break;
        }
        if std::time::Instant::now() >= deadline {
            entrypoints.kill().unwrap();
            entrypoints.wait().unwrap();
            panic!("entrypoint admission deadline expired");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    db.retire_workload_transfer("crashed-owner").unwrap();
    drop(db.admit_workload_mutation(Some("web"), &[]).unwrap());
}

#[test]
fn transfer_admission_prepare_child() {
    let Some(root) = std::env::var_os("SMOL_TEST_ADMISSION_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    assert!(SmolvmDb::default_path()
        .unwrap()
        .starts_with(root.join("data")));
    let db = SmolvmDb::open().unwrap();
    machine(&db, "web");
    std::fs::create_dir(root.join("volume")).unwrap();
    std::fs::write(root.join("database-path"), db.path.to_str().unwrap()).unwrap();
}

#[test]
fn transfer_admission_is_atomic_durable_and_never_reuses_a_retired_operation() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("state.db");
    let db = SmolvmDb::open_at(&path).unwrap();
    let a = machine(&db, "web");
    let b = machine(&db, "database");
    let mut stale = b.clone();
    stale.created_at += 1;
    assert!(db
        .claim_workload_transfer("move-one", vec![a.clone(), stale], &[])
        .is_err());
    drop(db.admit_workload_mutation(Some("web"), &[]).unwrap());
    db.claim_workload_transfer("move-one", vec![a.clone(), b.clone()], &[])
        .unwrap();
    db.claim_workload_transfer("move-one", vec![b.clone(), a.clone()], &[])
        .unwrap();
    assert!(db
        .claim_workload_transfer("move-one", vec![a.clone()], &[])
        .is_err());
    assert!(db
        .claim_workload_transfer("move-two", vec![a.clone()], &[])
        .is_err());
    // Dropping every connection represents owner exit; reopening cannot
    // release a move simply because its originating process disappeared.
    drop(db);
    let db = SmolvmDb::open_at(&path).unwrap();
    for name in ["web", "database"] {
        assert!(db.admit_workload_mutation(Some(name), &[]).is_err());
    }
    drop(db.admit_workload_mutation(Some("unrelated"), &[]).unwrap());
    assert!(db.retire_workload_transfer("wrong-owner").is_err());
    assert!(db.admit_workload_mutation(Some("web"), &[]).is_err());
    db.retire_workload_transfer("move-one").unwrap();
    db.retire_workload_transfer("move-one").unwrap();
    drop(db.admit_workload_mutation(Some("web"), &[]).unwrap());
    assert!(db
        .claim_workload_transfer("move-one", vec![a.clone(), b], &[])
        .is_err());
    db.claim_workload_transfer("move-two", vec![a], &[])
        .unwrap();
}

#[test]
fn transfer_claim_waits_for_inflight_mutations_without_serializing_readers() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("state.db");
    let db = SmolvmDb::open_at(&path).unwrap();
    let member = machine(&db, "web");
    let other = SmolvmDb::open_at(&path).unwrap();
    let first = db.admit_workload_mutation(Some("web"), &[]).unwrap();
    let second = other.admit_workload_mutation(Some("other"), &[]).unwrap();
    assert!(db
        .claim_workload_transfer("move", vec![member.clone()], &[])
        .is_err());
    drop(first);
    assert!(db
        .claim_workload_transfer("move", vec![member.clone()], &[])
        .is_err());
    drop(second);
    db.claim_workload_transfer("move", vec![member], &[])
        .unwrap();
    assert!(other.admit_workload_mutation(Some("web"), &[]).is_err());
}

#[cfg(unix)]
#[test]
fn transfer_admission_gate_releases_only_in_its_owning_process() {
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    struct Forked(i32);
    impl Drop for Forked {
        fn drop(&mut self) {
            // SAFETY: This unreaped direct child still owns its PID. It runs
            // only the pipe handshake below, with no guest or external work.
            unsafe {
                libc::kill(self.0, libc::SIGKILL);
                while libc::waitpid(self.0, std::ptr::null_mut(), 0) < 0 {
                    if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                        break;
                    }
                }
            }
        }
    }

    let root = tempfile::tempdir().unwrap();
    let db = SmolvmDb::open_at(&root.path().join("state.db")).unwrap();
    for exclusive in [false, true] {
        for child_drops_guard in [false, true] {
            let gate = db.transfer_gate(exclusive).unwrap();
            let (mut parent, child) = UnixStream::pair().unwrap();
            // SAFETY: The child uses only descriptor close, getpid, pipe I/O,
            // and _exit; it never touches the inherited SQLite connection or
            // any lock held by another test-runner thread.
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0);
            if pid == 0 {
                drop(parent);
                if child_drops_guard {
                    drop(gate);
                } else {
                    std::mem::forget(gate);
                }
                let mut byte = [0_u8];
                // SAFETY: Buffers and the owned socket descriptor are valid;
                // _exit bypasses inherited Rust/SQLite destructors.
                unsafe {
                    libc::write(child.as_raw_fd(), b"R".as_ptr().cast(), 1);
                    libc::read(child.as_raw_fd(), byte.as_mut_ptr().cast(), 1);
                    libc::_exit(0);
                }
            }
            let child_process = Forked(pid);
            drop(child);
            parent
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut ready = [0];
            parent.read_exact(&mut ready).unwrap();
            assert_eq!(ready, *b"R");
            assert!(
                db.transfer_gate(true).is_err(),
                "a child released its parent's gate"
            );
            drop(gate);
            let next = db.transfer_gate(true);
            // The child still lives with its inherited descriptor: success
            // must not depend on that unrelated process reaching exec/exit.
            assert!(
                next.is_ok(),
                "an inherited descriptor retained a completed operation's gate"
            );
            drop(next);
            parent.write_all(b"D").unwrap();
            drop(child_process);
        }
    }
}

#[cfg(unix)]
#[test]
fn transfer_admission_fences_shared_data_aliases_and_both_directory_directions() {
    let root = tempfile::tempdir().unwrap();
    let db = SmolvmDb::open_at(&root.path().join("state.db")).unwrap();
    let member = machine(&db, "web");
    let data = root.path().join("data é= ");
    std::fs::create_dir_all(data.join("child")).unwrap();
    let alias = root.path().join("alias");
    std::os::unix::fs::symlink(&data, &alias).unwrap();
    let unrelated = root.path().join("unrelated");
    std::fs::create_dir(&unrelated).unwrap();
    db.claim_workload_transfer("move", vec![member], std::slice::from_ref(&alias))
        .unwrap();
    for path in [
        data.clone(),
        data.join("child"),
        alias,
        root.path().to_path_buf(),
    ] {
        // No read-only exception: a retained reader would still see old data.
        assert!(db
            .admit_workload_mutation(Some("outside"), &[path])
            .is_err());
    }
    drop(
        db.admit_workload_mutation(Some("outside"), &[unrelated])
            .unwrap(),
    );
    assert!(db.admit_workload_mutation(None, &[data]).is_err());
}

#[test]
fn corrupt_transfer_admission_is_not_treated_as_an_empty_inventory() {
    let root = tempfile::tempdir().unwrap();
    let db = SmolvmDb::open_at(&root.path().join("state.db")).unwrap();
    let member = machine(&db, "web");
    db.with_conn(|conn| {
        conn.execute(
            "INSERT INTO workload_transfer_admission(operation, data) VALUES ('broken', X'7B')",
            [],
        )
        .unwrap();
        Ok(())
    })
    .unwrap();
    assert!(db.admit_workload_mutation(Some("web"), &[]).is_err());
    assert!(db
        .claim_workload_transfer("new", vec![member], &[])
        .is_err());
}

#[test]
fn transfer_admission_blocks_resume_recovery_before_it_changes_saved_state() {
    let root = tempfile::tempdir().unwrap();
    let db = SmolvmDb::open_at(&root.path().join("state.db")).unwrap();
    let member = machine(&db, "saved");
    db.update_vm("saved", |record| {
        record.state = crate::config::RecordState::Pausing;
        record.paused_checkpoint = Some(root.path().join("saved.checkpoint"));
    })
    .unwrap();
    let before = serde_json::to_value(db.get_vm("saved").unwrap().unwrap()).unwrap();
    db.claim_workload_transfer("move", vec![member], &[])
        .unwrap();
    let runtime = crate::embedded::EmbeddedRuntime::with_db(db.clone());
    let error = runtime
        .resume_machine_detached("saved")
        .unwrap_err()
        .to_string();
    assert!(error.contains("environment is moving"), "{error}");
    assert_eq!(
        before,
        serde_json::to_value(db.get_vm("saved").unwrap().unwrap()).unwrap()
    );
    for error in [
        runtime
            .pause_machine_with_operation("saved", "retry")
            .unwrap_err(),
        runtime.start_machine("saved").unwrap_err(),
        runtime.connect_or_start_machine("saved").unwrap_err(),
        runtime.start_forkable_machine("saved").unwrap_err(),
        runtime
            .start_machine_with_netns("saved", root.path().join("unused-netns"))
            .unwrap_err(),
        runtime.stop_machine("saved").unwrap_err(),
        runtime.delete_machine("saved").unwrap_err(),
    ] {
        assert!(
            error.to_string().contains("environment is moving"),
            "{error}"
        );
    }
    assert_eq!(
        before,
        serde_json::to_value(db.get_vm("saved").unwrap().unwrap()).unwrap()
    );
}
