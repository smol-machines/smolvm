//! CLI and SDK connections must wait for initialization owned by another process.
//! Run with SMOLVM_BOOT_BINARY and the runtime/rootfs paths, using --ignored.
#![cfg(unix)]

use smolvm::embedded::EmbeddedRuntime;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const NAME: &str = "connection-readiness";

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

    fn cli(&self, args: &[&str]) {
        let output = self.command(&self.binary).args(args).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::write(self.directory.path().join("gate/release"), b"");
        let _ = self
            .command(&self.binary)
            .args(["machine", "delete", "--name", NAME, "--force"])
            .output();
    }
}

struct Process(Child);

impl Process {
    fn wait(&mut self) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < deadline, "operation did not finish");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "helper for the cross-process initialization regression"]
fn connecting_sdk_process() {
    let Some(gate) = std::env::var_os("SMOL_TEST_CONNECT_GATE") else {
        return;
    };
    smolvm::process::apply_system_data_root(false);
    let gate = PathBuf::from(gate);
    let runtime = EmbeddedRuntime::new().unwrap();
    std::fs::write(gate.join("sdk-attempting"), b"").unwrap();
    runtime.connect_machine(NAME).unwrap();
    std::fs::write(gate.join("sdk-connected"), b"").unwrap();
}

#[test]
#[ignore = "boots machines with gated initialization"]
fn connections_wait_for_success_or_failure_of_initialization() {
    let binary = PathBuf::from(std::env::var_os("SMOLVM_BOOT_BINARY").expect("boot binary"));
    for fails in [false, true] {
        let fixture = Fixture {
            directory: tempfile::Builder::new()
                .prefix(".connect-ready-")
                .tempdir_in(std::env::var_os("HOME").expect("home directory"))
                .unwrap(),
            binary: binary.clone(),
        };
        let gate = fixture.directory.path().join("gate");
        std::fs::create_dir(&gate).unwrap();
        let init = format!(
            "touch /gate/entered; while [ ! -e /gate/release ]; do sleep .05; done; {}",
            if fails {
                "exit 37"
            } else {
                "touch /gate/ready"
            },
        );
        fixture.cli(&[
            "machine",
            "create",
            "--name",
            NAME,
            "--cpus",
            "1",
            "--mem",
            "384",
            "--storage",
            "1",
            "--overlay",
            "1",
            "-v",
            &format!("{}:/gate", gate.display()),
            "--init",
            &init,
        ]);
        let mut owner = Process(
            fixture
                .command(&binary)
                .args(["machine", "start", "--name", NAME])
                .stdout(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(30);
        while !gate.join("entered").exists() {
            assert!(
                owner.0.try_wait().unwrap().is_none(),
                "startup failed before init"
            );
            assert!(Instant::now() < deadline, "initialization never began");
            std::thread::sleep(Duration::from_millis(20));
        }
        let mut cli = Process(
            fixture
                .command(&binary)
                .args([
                    "machine",
                    "exec",
                    "--name",
                    NAME,
                    "--",
                    "sh",
                    "-c",
                    "test -f /gate/ready && touch /gate/executed",
                ])
                .spawn()
                .unwrap(),
        );
        let mut sdk = Process(
            fixture
                .command(&std::env::current_exe().unwrap())
                .args(["--exact", "connecting_sdk_process", "--ignored"])
                .env("SMOL_TEST_CONNECT_GATE", &gate)
                .spawn()
                .unwrap(),
        );
        while !gate.join("sdk-attempting").exists() {
            assert!(sdk.0.try_wait().unwrap().is_none(), "SDK helper failed");
            assert!(Instant::now() < deadline, "SDK connection never began");
            std::thread::sleep(Duration::from_millis(20));
        }
        // Resource diagnostics remain usable while workload access waits.
        fixture.cli(&["machine", "stats", "--name", NAME, "--json"]);
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            cli.0.try_wait().unwrap().is_none(),
            "exec bypassed initialization"
        );
        assert!(
            sdk.0.try_wait().unwrap().is_none(),
            "SDK bypassed initialization"
        );
        assert!(!gate.join("sdk-connected").exists());
        std::fs::write(gate.join("release"), b"").unwrap();
        assert_eq!(owner.wait().success(), !fails);
        assert_eq!(cli.wait().success(), !fails);
        assert_eq!(sdk.wait().success(), !fails);
        assert_eq!(gate.join("executed").exists(), !fails);
        assert_eq!(gate.join("sdk-connected").exists(), !fails);
        if !fails {
            // Dropping the observer SDK must not stop the CLI-owned machine.
            fixture.cli(&[
                "machine",
                "exec",
                "--name",
                NAME,
                "--",
                "test",
                "-f",
                "/gate/ready",
            ]);
        }
    }
}
