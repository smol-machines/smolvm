use super::*;
use std::{
    fs,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const ROOT: &str = "SMOL_TEST_CREATION_ROOT";

fn isolated(here: &str) -> Option<PathBuf> {
    if let Some(root) = std::env::var_os(ROOT) {
        return Some(PathBuf::from(root));
    }
    let test = here
        .strip_suffix("::here")
        .unwrap()
        .split_once("::")
        .unwrap()
        .1;
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("rootfs")).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--test-threads=1", "--nocapture"])
        .env(ROOT, root.path())
        .env("HOME", root.path().join("data"))
        .env("SMOLVM_DATA_DIR", root.path().join("data"))
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
    None
}

fn record(name: &str) -> VmRecord {
    VmRecord::new(name.into(), 1, 128, vec![], vec![], false)
}

#[test]
fn live_creation_never_expires_or_authorizes_unowned_preparation() {
    fn here() {}
    let Some(root) = isolated(std::any::type_name_of_val(&here)) else {
        return;
    };
    let db = SmolvmDb::open().unwrap();
    assert!(db.path.starts_with(root.join("data")));
    let lease = VmCreationLease::reserve(db.clone(), "slow-import").unwrap();
    db.with_conn(|conn| {
        conn.execute("UPDATE vm_create_reservations SET created_at = 0", [])
            .unwrap();
        Ok(())
    })
    .unwrap();
    assert!(!db.reserve_vm_create(lease.name(), "competing").unwrap());
    assert!(crate::agent::AgentManager::for_vm_with_sizes(lease.name(), Some(1), Some(1)).is_err());
    let manager = crate::agent::AgentManager::for_vm_creation(&lease, Some(1), Some(1)).unwrap();
    manager.detach();
    assert!(db
        .reserve_vm_launch(Some(record(lease.name())), manager.storage_path(), &[], &[])
        .is_err());
    assert!(db.remove_vm(lease.name()).is_err());
    assert!(db.insert_vm(lease.name(), &record(lease.name())).is_err());
    assert!(!db
        .insert_vm_if_not_exists(lease.name(), &record(lease.name()))
        .unwrap());
    assert!(db.admit_vm_boot(lease.token()).is_err());
    assert!(!db
        .commit_reserved_vm(lease.name(), "wrong-token", &record(lease.name()))
        .unwrap());
    let worker = lease.clone();
    assert!(lease.commit(&record(lease.name())).is_err());
    drop(worker);
    let sentinel = crate::agent::vm_data_dir(lease.name()).join("keep");
    fs::write(&sentinel, b"published data").unwrap();
    lease.commit(&record(lease.name())).unwrap();
    drop(lease);
    assert_eq!(fs::read(sentinel).unwrap(), b"published data");
    assert!(db.get_vm("slow-import").unwrap().is_some());
    crate::agent::AgentManager::for_vm_with_sizes("slow-import", Some(1), Some(1))
        .unwrap()
        .detach();
}

#[test]
fn stale_creation_cleanup_cannot_remove_a_replacement() {
    fn here() {}
    let Some(_root) = isolated(std::any::type_name_of_val(&here)) else {
        return;
    };
    let db = SmolvmDb::open().unwrap();
    let old = VmCreationLease::reserve(db.clone(), "replacement").unwrap();
    let old_token = old.token().to_owned();
    let dir = crate::agent::ensure_vm_dir(old.name()).unwrap();
    fs::write(dir.join("old"), b"partial").unwrap();
    // Simulate loss of the old capability before its destructor gets to run.
    db.release_vm_create_reservation(old.name(), old.token())
        .unwrap();
    let new = VmCreationLease::reserve(db.clone(), old.name()).unwrap();
    assert!(
        !dir.join("old").exists(),
        "new creation must discard abandoned preparation"
    );
    crate::agent::ensure_vm_dir(new.name()).unwrap();
    fs::write(dir.join("new"), b"replacement data").unwrap();
    assert!(db
        .recover_vm_creation("replacement", &old_token)
        .unwrap()
        .is_none());
    drop(old);
    assert_eq!(fs::read(dir.join("new")).unwrap(), b"replacement data");
    new.commit(&record(new.name())).unwrap();
    drop(new);
    assert_eq!(fs::read(dir.join("new")).unwrap(), b"replacement data");
}

#[test]
fn aborted_api_waiter_keeps_ownership_until_blocking_writer_finishes() {
    fn here() {}
    let Some(_root) = isolated(std::any::type_name_of_val(&here)) else {
        return;
    };
    let db = SmolvmDb::open().unwrap();
    let state = Arc::new(crate::api::state::ApiState::with_db(db.clone()));
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let worker_state = state.clone();
    let task = runtime.spawn(async move {
        let guard =
            crate::api::state::ReservationGuard::new(&worker_state, "aborted-create".into())
                .unwrap();
        guard
            .spawn_blocking(move || {
                let dir = crate::agent::ensure_vm_dir("aborted-create").unwrap();
                fs::write(dir.join("before"), b"still preparing").unwrap();
                ready_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(15)).unwrap();
                fs::write(dir.join("after"), b"finished preparing").unwrap();
            })
            .await
            .unwrap();
    });
    ready_rx.recv_timeout(Duration::from_secs(15)).unwrap();
    task.abort();
    assert!(runtime.block_on(task).unwrap_err().is_cancelled());
    let dir = crate::agent::vm_data_dir("aborted-create");
    assert_eq!(fs::read(dir.join("before")).unwrap(), b"still preparing");
    assert!(!db.reserve_vm_create("aborted-create", "too-early").unwrap());
    assert!(db.remove_vm("aborted-create").is_err());
    release_tx.send(()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    while !db
        .reserve_vm_create("aborted-create", "after-worker")
        .unwrap()
    {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!dir.exists(), "the name cannot be released before cleanup");
    crate::agent::ensure_vm_dir("aborted-create").unwrap();
    fs::write(dir.join("new"), b"next creation").unwrap();
    drop(state);
    drop(runtime);
    assert_eq!(fs::read(dir.join("new")).unwrap(), b"next creation");
    db.release_vm_create_reservation("aborted-create", "after-worker")
        .unwrap();
}

struct ChildOwner(Child);
impl Drop for ChildOwner {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn crashed_creation_is_recovered_without_reusing_partial_data_or_old_authority() {
    fn here() {}
    let Some(root) = isolated(std::any::type_name_of_val(&here)) else {
        return;
    };
    let db = SmolvmDb::open().unwrap();
    if std::env::var_os("SMOL_CREATION_WORKER").is_some() {
        let lease = VmCreationLease::reserve(db, "crashed-import").unwrap();
        let dir = crate::agent::ensure_vm_dir(lease.name()).unwrap();
        fs::write(dir.join("partial"), b"incomplete import").unwrap();
        fs::write(root.join("ready"), lease.token()).unwrap();
        loop {
            std::thread::park();
        }
    }
    let test = std::any::type_name_of_val(&here)
        .strip_suffix("::here")
        .unwrap()
        .split_once("::")
        .unwrap()
        .1;
    let mut child = ChildOwner(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--test-threads=1", "--nocapture"])
            .env("SMOL_CREATION_WORKER", "1")
            .stdout(Stdio::null())
            .stderr(fs::File::create(root.join("worker.log")).unwrap())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    while !root.join("ready").exists() {
        assert!(child.0.try_wait().unwrap().is_none());
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    let token = fs::read_to_string(root.join("ready")).unwrap();
    assert!(db
        .commit_reserved_vm("crashed-import", &token, &record("crashed-import"))
        .is_err());
    assert!(db
        .release_vm_create_reservation("crashed-import", &token)
        .is_err());
    assert!(!db.reserve_vm_create("crashed-import", "contender").unwrap());
    let dir = crate::agent::vm_data_dir("crashed-import");
    db.insert_vm("transfer-member", &record("transfer-member"))
        .unwrap();
    let members = vec![db.review_workload_member("transfer-member").unwrap()];
    assert!(db
        .claim_workload_transfer("busy", members.clone(), std::slice::from_ref(&dir))
        .is_err());
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    db.claim_workload_transfer("recovered", members, std::slice::from_ref(&dir))
        .unwrap();
    db.retire_workload_transfer("recovered").unwrap();
    let fresh = VmCreationLease::reserve(db.clone(), "crashed-import").unwrap();
    assert!(!dir.join("partial").exists());
    assert!(db.admit_vm_boot(&token).is_err());
    assert!(!db
        .commit_reserved_vm("crashed-import", &token, &record("crashed-import"))
        .unwrap());
    fresh.commit(&record(fresh.name())).unwrap();
}

#[test]
fn legacy_live_creation_does_not_expire_and_pid_reuse_releases_new_ownership() {
    fn here() {}
    let Some(_root) = isolated(std::any::type_name_of_val(&here)) else {
        return;
    };
    let db = SmolvmDb::open().unwrap();
    db.with_conn(|conn| {
        conn.execute("INSERT INTO vm_create_reservations(name, owner_token, owner_pid, created_at) VALUES ('legacy', 'old', ?1, 0)", [std::process::id()]).unwrap();Ok(())
    }).unwrap();
    assert!(!db.reserve_vm_create("legacy", "replacement").unwrap());
    db.with_conn(|conn| {
        conn.execute(
            "UPDATE vm_create_reservations SET owner_pid = ?1",
            [i32::MAX],
        )
        .unwrap();
        Ok(())
    })
    .unwrap();
    assert!(db.reserve_vm_create("legacy", "replacement").unwrap());
    db.with_conn(|conn| {
        let data: Vec<u8> = conn
            .query_row(
                "SELECT data FROM vm_launch_admission WHERE token = 'replacement'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&data).unwrap();
        value["owner"]["start"] = serde_json::json!(0);
        conn.execute(
            "UPDATE vm_launch_admission SET data = ?1 WHERE token = 'replacement'",
            [serde_json::to_vec(&value).unwrap()],
        )
        .unwrap();
        Ok(())
    })
    .unwrap();
    assert!(db.reserve_vm_create("legacy", "new-generation").unwrap());
    assert!(!db
        .commit_reserved_vm("legacy", "replacement", &record("legacy"))
        .unwrap());
    db.commit_reserved_vm("legacy", "new-generation", &record("legacy"))
        .unwrap();
}

#[test]
fn creation_cleanup_uses_its_captured_directory_after_home_changes() {
    fn here() {}
    let Some(root) = isolated(std::any::type_name_of_val(&here)) else {
        return;
    };
    let db = SmolvmDb::open().unwrap();
    let lease = VmCreationLease::reserve(db, "home-change").unwrap();
    let old = crate::agent::ensure_vm_dir(lease.name()).unwrap();
    fs::write(old.join("old"), b"partial old creation").unwrap();
    std::env::set_var("HOME", root.join("other-home"));
    std::env::set_var("SMOLVM_DATA_DIR", root.join("other-home"));
    let new = crate::agent::ensure_vm_dir(lease.name()).unwrap();
    assert_ne!(old, new);
    fs::write(new.join("new"), b"unrelated state root").unwrap();
    assert!(crate::agent::AgentManager::for_vm_creation(&lease, Some(1), Some(1)).is_err());
    drop(lease);
    assert!(!old.exists());
    assert_eq!(fs::read(new.join("new")).unwrap(), b"unrelated state root");
}

#[cfg(unix)]
#[test]
fn creation_refuses_a_symlink_or_unbound_nonempty_directory() {
    fn here() {}
    let Some(root) = isolated(std::any::type_name_of_val(&here)) else {
        return;
    };
    let db = SmolvmDb::open().unwrap();
    let outside = root.join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("keep"), b"not creation data").unwrap();
    let dir = crate::agent::vm_data_dir("symlink");
    fs::create_dir_all(dir.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&outside, &dir).unwrap();
    assert!(VmCreationLease::reserve(db.clone(), "symlink").is_err());
    assert_eq!(
        fs::read(outside.join("keep")).unwrap(),
        b"not creation data"
    );
    let dir = crate::agent::vm_data_dir("unbound");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("keep"), b"unbound data").unwrap();
    assert!(VmCreationLease::reserve(db, "unbound").is_err());
    assert_eq!(fs::read(dir.join("keep")).unwrap(), b"unbound data");
}

#[test]
fn startup_sweep_preserves_active_and_unknown_directories_and_reclaims_dead_creation() {
    fn here() {}
    let Some(root) = isolated(std::any::type_name_of_val(&here)) else {
        return;
    };
    let db = SmolvmDb::open().unwrap();
    if std::env::var_os("SMOL_CREATION_SWEEP_WORKER").is_some() {
        let lease = VmCreationLease::reserve(db, "sweep-dead").unwrap();
        fs::write(
            crate::agent::vm_data_dir(lease.name()).join("partial"),
            b"abandoned",
        )
        .unwrap();
        fs::write(root.join("sweep-ready"), lease.token()).unwrap();
        loop {
            std::thread::park();
        }
    }
    let active = VmCreationLease::reserve(db.clone(), "sweep-live").unwrap();
    let live = crate::agent::vm_data_dir(active.name());
    fs::write(live.join("keep"), b"active writer").unwrap();
    let unknown = crate::agent::ensure_vm_dir("sweep-unknown").unwrap();
    fs::write(unknown.join("keep"), b"unknown writer").unwrap();
    let test = std::any::type_name_of_val(&here)
        .strip_suffix("::here")
        .unwrap()
        .split_once("::")
        .unwrap()
        .1;
    let mut child = ChildOwner(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--test-threads=1", "--nocapture"])
            .env("SMOL_CREATION_SWEEP_WORKER", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    while !root.join("sweep-ready").exists() {
        assert!(child.0.try_wait().unwrap().is_none());
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    let state = crate::api::state::ApiState::with_db(db.clone());
    assert_eq!(state.reclaim_dangling_vm_dirs(), 0);
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    assert_eq!(state.reclaim_dangling_vm_dirs(), 1);
    assert!(!crate::agent::vm_data_dir("sweep-dead").exists());
    assert_eq!(fs::read(live.join("keep")).unwrap(), b"active writer");
    assert_eq!(fs::read(unknown.join("keep")).unwrap(), b"unknown writer");
    assert_eq!(state.reclaim_dangling_vm_dirs(), 0);
}
