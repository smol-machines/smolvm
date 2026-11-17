//! Separate processes are essential: containerd's SIGCHLD handler and Linux's
//! subreaper setting affect a whole process. Run the real framework bootstrap,
//! signal loop and a task-service stub, without KVM, Pods or a containerd daemon.

#[cfg(target_os = "linux")]
#[path = "../src/reaper.rs"]
mod reaper;

#[cfg(target_os = "linux")]
mod linux {
    use async_trait::async_trait;
    use containerd_shim::asynchronous::monitor::{monitor_subscribe, monitor_unsubscribe};
    use containerd_shim::asynchronous::{run, Shim};
    use containerd_shim::monitor::{Subject, Topic};
    use containerd_shim::publisher::RemotePublisher;
    use containerd_shim::{Config, Error, Flags, StartOpts};
    use containerd_shim_protos::api::DeleteResponse;
    use std::fs;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    use std::os::unix::net::UnixListener;
    use std::os::unix::process::ExitStatusExt;
    use std::path::Path;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    struct NoTasks;

    #[async_trait]
    impl containerd_shim_protos::shim_async::Task for NoTasks {}

    struct Fixture;

    #[async_trait]
    impl Shim for Fixture {
        type T = NoTasks;

        async fn new(_: &str, _: &Flags, _: &mut Config) -> Self {
            Self
        }

        async fn start_shim(&mut self, _: StartOpts) -> Result<String, Error> {
            unreachable!("fixture starts the long-lived shim directly")
        }

        async fn delete_shim(&mut self) -> Result<DeleteResponse, Error> {
            unreachable!("fixture never invokes a delete action")
        }

        async fn create_task_service(&self, _: RemotePublisher) -> Self::T {
            NoTasks
        }

        async fn wait(&mut self) {
            let case = std::env::var("SMOLVM_CHILD_OWNERSHIP_CASE").unwrap();
            match case.as_str() {
                "legacy" => legacy_failure().await,
                "helpers" => foreground_helpers().await,
                "vm-exits" => detached_vm_exit().await,
                "orphans" => orphan_ownership().await,
                _ => panic!("unknown fixture case"),
            }
            eprintln!("child ownership passed: {case}");
        }
    }

    async fn legacy_failure() {
        let mut events = monitor_subscribe(Topic::Pid).await.unwrap();
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("etc-hosts");
        let destination = root.path().join("copied-hosts");
        fs::write(&source, b"127.0.0.1 localhost\n").unwrap();
        let mut child = Command::new("cp")
            .args(["-aT", "--reflink=auto"])
            .arg(&source)
            .arg(&destination)
            .spawn()
            .unwrap();
        let pid = i32::try_from(child.id()).unwrap();
        // A real notification proves the framework has already waitpid'd this
        // specific child. No sleep or probabilistic scheduling assertion.
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let event = events.rx.recv().await.unwrap();
                if matches!(event.subject, Subject::Pid(value) if value == pid) {
                    assert_eq!(event.exit_code, 0);
                    break;
                }
            }
        })
        .await
        .expect("real framework reaper must observe the helper exit");
        monitor_unsubscribe(events.id).await.unwrap();
        assert_eq!(
            child.wait().unwrap_err().raw_os_error(),
            Some(nix::libc::ECHILD)
        );
        assert_eq!(fs::read(source).unwrap(), fs::read(destination).unwrap());
    }

    fn exited_without_reaping(child: &Child) {
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            let stat = fs::read_to_string(format!("/proc/{}/stat", child.id()))
                .expect("foreground child must remain waitable until its owner waits");
            if stat.rsplit_once(')').unwrap().1.split_whitespace().next() == Some("Z") {
                return;
            }
            assert!(Instant::now() < end, "helper did not exit");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    async fn foreground_helpers() {
        let _reaper = crate::reaper::VmReaper::start();
        tokio::task::spawn_blocking(|| {
            for code in [0, 17, 91] {
                let runtime = tokio::runtime::Handle::current();
                let mut events = runtime.block_on(monitor_subscribe(Topic::Pid)).unwrap();
                let mut child = Command::new("/bin/sh")
                    .args(["-c", &format!("exit {code}")])
                    .spawn()
                    .unwrap();
                if crate::reaper::configuration().no_reaper {
                    exited_without_reaping(&child);
                } else {
                    let expected_pid = i32::try_from(child.id()).unwrap();
                    runtime.block_on(async {
                        tokio::time::timeout(Duration::from_secs(5), async {
                            loop {
                                let event = events.rx.recv().await.unwrap();
                                if matches!(event.subject, Subject::Pid(pid) if pid == expected_pid)
                                {
                                    break;
                                }
                            }
                        })
                        .await
                        .unwrap();
                    });
                }
                runtime.block_on(monitor_unsubscribe(events.id)).unwrap();
                smolvm::process::reap_vm_children();
                assert_eq!(child.wait().unwrap().code(), Some(code));
            }
            let mut child = Command::new("/bin/sh")
                .args(["-c", "kill -TERM $$"])
                .spawn()
                .unwrap();
            exited_without_reaping(&child);
            assert_eq!(child.wait().unwrap().signal(), Some(nix::libc::SIGTERM));

            assert_eq!(
                Command::new("/smolvm-missing-helper")
                    .status()
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::NotFound
            );
            let mut sleeping = Command::new("/bin/sleep").arg("30").spawn().unwrap();
            sleeping.kill().unwrap();
            assert_eq!(sleeping.wait().unwrap().signal(), Some(nix::libc::SIGKILL));

            let mut concurrent = (0..16)
                .map(|code| {
                    let child = Command::new("/bin/sh")
                        .args(["-c", &format!("exit {code}")])
                        .spawn()
                        .unwrap();
                    (code, child)
                })
                .collect::<Vec<_>>();
            for (code, child) in &mut concurrent {
                exited_without_reaping(child);
                smolvm::process::reap_vm_children();
                assert_eq!(child.wait().unwrap().code(), Some(*code));
            }

            copied_files_preserve_metadata();
        })
        .await
        .unwrap();
    }

    fn copied_files_preserve_metadata() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        let destination = root.path().join("copy");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("payload"), [0, 255, 128, 17]).unwrap();
        fs::set_permissions(source.join("payload"), fs::Permissions::from_mode(0o640)).unwrap();
        symlink("payload", source.join("link")).unwrap();
        assert!(Command::new("cp")
            .args(["-aT", "--reflink=auto"])
            .arg(&source)
            .arg(&destination)
            .status()
            .unwrap()
            .success());
        assert_eq!(
            fs::read(destination.join("payload")).unwrap(),
            [0, 255, 128, 17]
        );
        assert_eq!(
            fs::read_link(destination.join("link")).unwrap(),
            Path::new("payload")
        );
        assert_eq!(
            fs::metadata(destination.join("payload"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
        let before = fs::metadata(source.join("payload")).unwrap();
        let copied = fs::metadata(destination.join("payload")).unwrap();
        assert_eq!((copied.uid(), copied.gid()), (before.uid(), before.gid()));
        assert_eq!(copied.modified().unwrap(), before.modified().unwrap());
        assert!(Command::new("chmod")
            .args(["-R", "a+rX"])
            .arg(&destination)
            .status()
            .unwrap()
            .success());
    }

    async fn detached_vm_exit() {
        let _reaper = crate::reaper::VmReaper::start();
        let child = Command::new("/bin/sh")
            .args(["-c", "exit 23"])
            .spawn()
            .unwrap();
        let pid = i32::try_from(child.id()).unwrap();
        smolvm::process::register_vm_child(pid, None);
        drop(child);
        // No liveness query or explicit sweep: the shim's background reaper
        // must drain its detached VM registration and retain the actual exit.
        tokio::time::timeout(Duration::from_secs(5), async {
            while Path::new(&format!("/proc/{pid}")).exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("registered VM child was left as a zombie");
        assert_eq!(smolvm::process::try_wait(pid), Some(23));
    }

    async fn orphan_ownership() {
        let mut is_subreaper: nix::libc::c_int = -1;
        // SAFETY: GET_CHILD_SUBREAPER writes one int through this valid pointer.
        assert_eq!(
            unsafe { nix::libc::prctl(nix::libc::PR_GET_CHILD_SUBREAPER, &mut is_subreaper) },
            0
        );
        assert_eq!(
            is_subreaper, 0,
            "engine must not adopt unregistered orphans"
        );
        let root = tempfile::tempdir().unwrap();
        let pid_file = root.path().join("orphan.pid");
        let mut child = Command::new("/bin/sh")
            .args(["-c", "sleep 0.2 & echo $! > \"$1\"", "sh"])
            .arg(&pid_file)
            .spawn()
            .unwrap();
        assert!(child.wait().unwrap().success());
        let pid = fs::read_to_string(pid_file).unwrap();
        let stat = format!("/proc/{}/stat", pid.trim());
        if let Ok(value) = fs::read_to_string(&stat) {
            let parent_pid: u32 = value
                .rsplit_once(')')
                .unwrap()
                .1
                .split_whitespace()
                .nth(1)
                .unwrap()
                .parse()
                .unwrap();
            assert_ne!(parent_pid, std::process::id());
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            while Path::new(&stat).exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("orphan was not reaped by its supervising ancestor");
    }

    pub fn main() {
        if let Ok(case) = std::env::var("SMOLVM_CHILD_OWNERSHIP_CASE") {
            let mut config = if case == "legacy" {
                Config::default()
            } else {
                crate::reaper::configuration()
            };
            config.no_setup_logger = true;
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap()
                .block_on(run::<Fixture>(
                    "io.containerd.smolvm.child-test.v2",
                    Some(config),
                ));
            return;
        }
        for case in ["legacy", "helpers", "vm-exits", "orphans"] {
            let root = tempfile::tempdir().unwrap();
            let publisher = root.path().join("publisher.sock");
            let _publisher = UnixListener::bind(&publisher).unwrap();
            let socket = root.path().join("shim.sock");
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args(["-namespace", "child-test", "-id", "child-test", "-socket"])
                .arg(&socket)
                .env("TTRPC_ADDRESS", &publisher)
                .env("SMOLVM_CHILD_OWNERSHIP_CASE", case)
                .current_dir(root.path())
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let end = Instant::now() + Duration::from_secs(15);
            while child.try_wait().unwrap().is_none() {
                if Instant::now() >= end {
                    child.kill().unwrap();
                    panic!("child ownership fixture timed out: {case}");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "{case}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stderr)
                .contains(&format!("child ownership passed: {case}")));
            println!("passed real framework child ownership: {case}");
        }
    }
}

fn main() {
    #[cfg(target_os = "linux")]
    linux::main();
}
