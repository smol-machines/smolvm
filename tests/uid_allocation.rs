//! UID allocation and shutdown regressions without VMs or root privileges.
#![cfg(target_os = "linux")]

#[test]
fn silent_peer_shutdown_is_bounded() {
    use std::io::Read;
    use std::time::{Duration, Instant};
    let temp = tempfile::tempdir().unwrap();
    let socket = temp.path().join("agent.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut data = [0; 1024];
        assert!(stream.read(&mut data).unwrap() > 0);
        std::thread::sleep(Duration::from_secs(6));
    });
    let start = Instant::now();
    let mut client = smolvm::agent::AgentClient::connect_with_short_timeout(&socket).unwrap();
    let result = client.shutdown();
    let elapsed = start.elapsed();
    eprintln!("silent-peer connect+shutdown: {elapsed:?}, result={result:?}");
    server.join().unwrap();
    assert!(result.is_err());
    assert!(elapsed < Duration::from_secs(6));
}

#[test]
fn concurrent_same_machine_uid_is_stable() {
    let mut unstable = 0;
    let rounds = 100;
    for _ in 0..rounds {
        let temp = tempfile::tempdir().unwrap();
        let registry = temp.path().join("uids");
        let machine = temp.path().join("vms/same-machine");
        std::fs::create_dir_all(&registry).unwrap();
        std::fs::create_dir_all(&machine).unwrap();
        let barrier = std::sync::Barrier::new(16);
        let assignments = std::thread::scope(|scope| {
            let jobs: Vec<_> = (0..16)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        smolvm::process::allocate_vm_uid(&registry, &machine, "same-machine")
                            .unwrap()
                    })
                })
                .collect();
            jobs.into_iter()
                .map(|job| job.join().unwrap())
                .collect::<std::collections::BTreeSet<_>>()
        });
        if assignments.len() != 1 {
            unstable += 1;
        }
    }
    eprintln!("same-machine UID allocation: {unstable}/{rounds} waves returned multiple UIDs (16 callers/wave)");
    assert_eq!(unstable, 0, "one machine must receive exactly one UID");
}
