//! Cross-process ownership of SDK batch forks.
//!
//! Run with a signed SMOLVM_BOOT_BINARY and the usual runtime/rootfs paths:
//! cargo test --test embedded_fork_lifetime -- --ignored --test-threads=1

#![cfg(unix)]

use smolvm::embedded::{EmbeddedRuntime, ForkOptions};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

const SOURCE: &str = "fork-lifetime-source";
const CHILDREN: [&str; 2] = ["fork-lifetime-a", "fork-lifetime-b"];

struct Fixture {
    directory: tempfile::TempDir,
    binary: PathBuf,
}

impl Fixture {
    fn command(&self, binary: &Path) -> Command {
        let mut command = Command::new(binary);
        command
            .env("SMOLVM_DATA_DIR", self.directory.path().join("state"))
            .env("SMOLVM_CONFIG", self.directory.path().join("config.toml"));
        command
    }

    fn cli(&self, args: &[&str]) -> Vec<u8> {
        let output = self.command(&self.binary).args(args).output().unwrap();
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    fn status(&self, name: &str) -> serde_json::Value {
        serde_json::from_slice(&self.cli(&["machine", "status", "--name", name, "--json"])).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for name in CHILDREN.into_iter().chain([SOURCE]) {
            let _ = self
                .command(&self.binary)
                .args(["machine", "delete", "--name", name, "--force"])
                .output();
        }
    }
}

struct Owner(Child);

impl Drop for Owner {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Invoked in a separate process so the actual VM parent can be killed.
#[test]
#[ignore = "helper for the real-VM lifetime regression"]
fn fork_owner_process() {
    let Some(ready) = std::env::var_os("SMOL_TEST_FORK_READY") else {
        return;
    };
    smolvm::process::apply_system_data_root(false);
    let runtime = EmbeddedRuntime::new().unwrap();
    let detached = std::env::var("SMOL_TEST_FORK_DETACHED").unwrap() == "true";
    runtime
        .fork_machines_opts(
            SOURCE,
            &CHILDREN.map(str::to_owned),
            &[],
            2,
            ForkOptions {
                detached,
                ..Default::default()
            },
        )
        .unwrap();
    std::fs::write(ready, b"ready").unwrap();
    // The parent kills us, bypassing Runtime/Handle Drop. Attached machines
    // must still be reaped by the watchdog; detached machines must survive.
    std::thread::sleep(Duration::from_secs(60));
}

#[test]
#[ignore = "boots real forkable machines"]
fn batch_forks_honor_detachment_after_the_sdk_process_exits() {
    let binary = PathBuf::from(std::env::var_os("SMOLVM_BOOT_BINARY").expect("boot binary"));
    for detached in [false, true] {
        let fixture = Fixture {
            directory: tempfile::Builder::new()
                .prefix(".fork-life-")
                .tempdir_in(std::env::var_os("HOME").expect("home directory"))
                .unwrap(),
            binary: binary.clone(),
        };
        fixture.cli(&[
            "machine",
            "create",
            "--name",
            SOURCE,
            "--cpus",
            "1",
            "--mem",
            "384",
            "--storage",
            "1",
            "--overlay",
            "1",
        ]);
        fixture.cli(&["machine", "start", "--name", SOURCE, "--forkable"]);
        let source_pid = fixture.status(SOURCE)["pid"].clone();
        let ready = fixture.directory.path().join("ready");
        let mut owner = Owner(
            fixture
                .command(&std::env::current_exe().unwrap())
                .args(["--exact", "fork_owner_process", "--ignored"])
                .env("SMOL_TEST_FORK_READY", &ready)
                .env("SMOL_TEST_FORK_DETACHED", detached.to_string())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(45);
        while !ready.exists() {
            assert!(owner.0.try_wait().unwrap().is_none(), "SDK fork failed");
            assert!(Instant::now() < deadline, "SDK fork never became ready");
            std::thread::sleep(Duration::from_millis(20));
        }
        let pids = CHILDREN.map(|name| fixture.status(name)["pid"].clone());
        owner.0.kill().unwrap();
        owner.0.wait().unwrap();
        // A quick command can beat the watchdog's first 500ms poll and hide
        // incorrect detachment. Always observe beyond that interval.
        std::thread::sleep(Duration::from_secs(2));
        for (name, pid) in CHILDREN.into_iter().zip(pids) {
            if detached {
                let status = fixture.status(name);
                assert_eq!(status["state"].as_str().unwrap().to_lowercase(), "running");
                assert_eq!(status["pid"], pid, "child must not silently restart");
                assert_eq!(
                    fixture.cli(&["machine", "exec", "--name", name, "--", "printf", "alive"]),
                    b"alive"
                );
            } else {
                let deadline = Instant::now() + Duration::from_secs(8);
                while smolvm::process::is_alive(pid.as_i64().unwrap() as i32) {
                    assert!(
                        Instant::now() < deadline,
                        "attached child survived its owner"
                    );
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
        assert_eq!(fixture.status(SOURCE)["pid"], source_pid);
        assert_eq!(
            fixture.cli(&[
                "machine",
                "exec",
                "--name",
                SOURCE,
                "--",
                "printf",
                "preserved"
            ]),
            b"preserved"
        );
    }
}
