use super::*;

fn fixture(root: &Path) -> (SmolvmDb, VmRecord, PathBuf) {
    let db = SmolvmDb::open_at(&root.join("test.db")).unwrap();
    let runtime = root.join("vm");
    std::fs::create_dir(&runtime).unwrap();
    let vm = VmRecord::new("share-owner".into(), 1, 128, vec![], vec![], false);
    db.insert_vm(&vm.name, &vm).unwrap();
    let vm = db.get_vm(&vm.name).unwrap().unwrap();
    (db, vm, runtime)
}

#[test]
fn share_cleanup_pins_the_original_machine_until_released() {
    let root = tempfile::tempdir().unwrap();
    let (db, vm, runtime) = fixture(root.path());
    let shares = OwnedShares::reserve(&db, &vm, &runtime).unwrap();
    assert!(db.update_vm(&vm.name, |r| r.pid = Some(12345)).is_err());
    assert!(db.remove_vm(&vm.name).is_err());
    assert!(db.admit_machine_mutation(&vm.name).is_err());
    assert!(shares.source("oldshare", false).unwrap().is_none());
    shares.remove("oldshare", root.path(), false).unwrap();
    drop(shares);
    db.update_vm(&vm.name, |r| r.pid = Some(12345)).unwrap();
    assert!(OwnedShares::reserve(&db, &vm, &runtime).is_err());
    db.remove_vm(&vm.name).unwrap();
    db.insert_vm(&vm.name, &vm).unwrap();
    assert!(OwnedShares::reserve(&db, &vm, &runtime).is_err());
}

#[test]
fn changed_share_source_is_not_removed() {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::time::{Duration, Instant};

    let root = tempfile::tempdir().unwrap();
    let (db, vm, runtime) = fixture(root.path());
    db.update_vm(&vm.name, |r| {
        r.pid = Some(std::process::id() as i32);
        r.pid_start_time = crate::process::process_start_time(std::process::id() as i32);
        r.state = crate::config::RecordState::Running;
    })
    .unwrap();
    let vm = db.get_vm(&vm.name).unwrap().unwrap();
    let listener = UnixListener::bind(runtime.join("control.sock")).unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Ok((mut stream, _)) = listener.accept() {
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut command = String::new();
                BufReader::new(&mut stream).read_line(&mut command).unwrap();
                assert!(command.starts_with("SHARE_LIST "));
                stream.write_all(b"OK oldshare=/replaced/source\n").unwrap();
                return listener;
            }
            assert!(Instant::now() < deadline, "no reviewed control request");
            std::thread::sleep(Duration::from_millis(5));
        }
    });
    let shares = OwnedShares::reserve(&db, &vm, &runtime).unwrap();
    assert!(shares
        .remove("oldshare", Path::new("/original/source"), false)
        .is_err());
    let listener = server.join().unwrap();
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
