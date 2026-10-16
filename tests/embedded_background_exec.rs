//! A background exec through the embedded runtime every SDK drives returns
//! its pid at once, and the command keeps running after the call returns, on
//! bare and image machines alike.
//!
//! Boots real machines, so it is `#[ignore]`d by default. Run on a host the
//! engine supports, with network access to pull the test image and a signed
//! boot binary:
//!   cargo build --release --bin smolvm   (codesign it with smolvm.entitlements on macOS)
//!   SMOLVM_BOOT_BINARY=$PWD/target/release/smolvm \
//!     cargo test --release --test embedded_background_exec -- --ignored --test-threads=1

use smolvm::agent::VmResources;
use smolvm::embedded::{runtime, EmbeddedRuntime, ExecOptions, MachineSpec};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// A machine deleted when the test ends, however it ends.
struct Machine {
    runtime: Arc<EmbeddedRuntime>,
    name: String,
}

impl Machine {
    fn create(name: &str, image: Option<&str>) -> Self {
        let runtime = runtime().expect("embedded runtime");
        let _ = runtime.delete_machine(name);
        let spec = MachineSpec {
            name: name.to_string(),
            image: image.map(str::to_string),
            resources: VmResources {
                cpus: 1,
                memory_mib: 1024,
                network: true,
                ..Default::default()
            },
            ..Default::default()
        };
        runtime
            .create_machine_with_workload(spec, Vec::new(), None, None)
            .expect("create machine");
        let machine = Self {
            runtime,
            name: name.to_string(),
        };
        machine.runtime.start_machine(name).expect("start machine");
        machine
    }

    fn background(&self, script: &str) -> u32 {
        self.runtime
            .exec_background(
                &self.name,
                vec!["sh".into(), "-c".into(), script.into()],
                ExecOptions::default(),
            )
            .expect("background exec")
    }

    fn read(&self, path: &str) -> Option<String> {
        let (code, stdout, _) = self
            .runtime
            .exec(
                &self.name,
                vec!["cat".into(), path.into()],
                Vec::new(),
                None,
                Some(Duration::from_secs(30)),
            )
            .expect("exec");
        (code == 0).then(|| String::from_utf8(stdout).expect("utf-8 stdout"))
    }

    /// A command that outlives its call: it writes a file only after the call
    /// has returned, and the file then appears.
    fn assert_background_outlives_its_call(&self) {
        let started = Instant::now();
        let pid = self.background("sleep 3; echo done > /root/bg-done");
        assert!(pid > 0, "a background exec returns the command's pid");
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "the call returned after {:?}, so it waited for the command",
            started.elapsed()
        );
        let deadline = Instant::now() + Duration::from_secs(60);
        while self.read("/root/bg-done").is_none() {
            assert!(
                Instant::now() < deadline,
                "the background command never finished"
            );
            std::thread::sleep(Duration::from_millis(500));
        }
        assert_eq!(self.read("/root/bg-done").as_deref(), Some("done\n"));
    }
}

impl Drop for Machine {
    fn drop(&mut self) {
        let _ = self.runtime.delete_machine(&self.name);
    }
}

#[test]
#[ignore = "boots real machines"]
fn a_bare_machines_background_command_outlives_its_call() {
    Machine::create("bg-exec-bare", None).assert_background_outlives_its_call();
}

#[test]
#[ignore = "boots real machines"]
fn an_image_machines_background_command_outlives_its_call() {
    Machine::create("bg-exec-image", Some("alpine:3.20")).assert_background_outlives_its_call();
}

#[test]
#[ignore = "boots real machines"]
fn a_background_command_takes_no_stdin_or_timeout() {
    let machine = Machine::create("bg-exec-options", None);
    for options in [
        ExecOptions {
            stdin: Some("input".into()),
            ..Default::default()
        },
        ExecOptions {
            timeout: Some(Duration::from_secs(5)),
            ..Default::default()
        },
    ] {
        assert!(machine
            .runtime
            .exec_background(&machine.name, vec!["true".into()], options)
            .is_err());
    }
}
