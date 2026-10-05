//! File operations act on the filesystem a machine's commands run in, through
//! the embedded runtime every SDK drives.
//!
//! A file written with `write_file` is the file `exec` reads, and the reverse,
//! on bare and image machines alike, however many containers `run` has used on
//! the machine. `run` of different images on one machine keeps each image's
//! filesystem to itself.
//!
//! Boots real machines, so it is `#[ignore]`d by default. Run on a host the
//! engine supports, with network access to pull the test images and a signed
//! boot binary:
//!   cargo build --release --bin smolvm   (codesign it with smolvm.entitlements on macOS)
//!   SMOLVM_BOOT_BINARY=$PWD/target/release/smolvm \
//!     cargo test --release --test embedded_file_targets -- --ignored --test-threads=1

use smolvm::agent::VmResources;
use smolvm::embedded::{runtime, EmbeddedRuntime, MachineSpec};
use std::sync::Arc;
use std::time::Duration;

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

    fn sh(&self, script: &str) -> String {
        let (code, stdout, stderr) = self
            .runtime
            .exec(
                &self.name,
                vec!["sh".into(), "-c".into(), script.into()],
                Vec::new(),
                None,
                Some(Duration::from_secs(60)),
            )
            .expect("exec");
        assert_eq!(
            code,
            0,
            "`{script}` exited {code}: {}",
            String::from_utf8_lossy(&stderr)
        );
        String::from_utf8(stdout).expect("utf-8 stdout")
    }

    fn run(&self, image: &str, script: &str) -> String {
        let (code, stdout, stderr) = self
            .runtime
            .run(
                &self.name,
                image,
                vec!["sh".into(), "-c".into(), script.into()],
                Vec::new(),
                None,
                Some(Duration::from_secs(120)),
            )
            .expect("run");
        assert_eq!(
            code,
            0,
            "`{script}` in {image} exited {code}: {}",
            String::from_utf8_lossy(&stderr)
        );
        String::from_utf8(stdout).expect("utf-8 stdout")
    }

    fn write(&self, path: &str, contents: &str) {
        self.runtime
            .write_file(&self.name, path, contents.as_bytes().to_vec(), None)
            .expect("write_file");
    }

    fn read(&self, path: &str) -> String {
        String::from_utf8(self.runtime.read_file(&self.name, path).expect("read_file"))
            .expect("utf-8 file")
    }

    /// Files and commands agree both ways.
    fn assert_files_match_exec(&self, label: &str) {
        let path = format!("/root/{label}-from-sdk");
        self.write(&path, label);
        assert_eq!(
            self.sh(&format!("cat {path}")),
            label,
            "{label}: exec reads write_file"
        );
        self.sh(&format!("echo -n {label} > /root/{label}-from-exec"));
        assert_eq!(
            self.read(&format!("/root/{label}-from-exec")),
            label,
            "{label}: read_file reads exec"
        );
    }
}

impl Drop for Machine {
    fn drop(&mut self) {
        let _ = self.runtime.delete_machine(&self.name);
    }
}

#[test]
#[ignore = "boots real machines"]
fn a_bare_machines_files_are_its_commands_files_whatever_run_has_done() {
    let m = Machine::create("ft-bare", None);
    m.assert_files_match_exec("fresh");

    // A container `run` leaves on the machine is not where the machine's own
    // commands run, so files must not move into it.
    m.run("alpine:3.20", "true");
    m.assert_files_match_exec("after-run");
    m.run("python:3.12-alpine", "true");
    m.assert_files_match_exec("after-two-runs");
}

#[test]
#[ignore = "boots real machines"]
fn run_keeps_each_images_filesystem_to_itself() {
    let m = Machine::create("ft-run", None);
    m.run("alpine:3.20", "echo alpine > /marker");
    let python = m.run(
        "python:3.12-alpine",
        "test -e /marker && echo leaked; python3 -c 'print(2 ** 10)'",
    );
    assert_eq!(python, "1024\n", "python ran in its own filesystem");
    // Each image's changes persist across its own runs.
    assert_eq!(m.run("alpine:3.20", "cat /marker"), "alpine\n");
    m.run("python:3.12-alpine", "echo python > /marker");
    assert_eq!(m.run("python:3.12-alpine", "cat /marker"), "python\n");
    assert_eq!(m.run("alpine:3.20", "cat /marker"), "alpine\n");
}

#[test]
#[ignore = "boots real machines"]
fn an_image_machines_files_are_its_containers_files() {
    let m = Machine::create("ft-image", Some("alpine:3.20"));
    assert!(m.sh("cat /etc/alpine-release").starts_with("3.20"));
    m.assert_files_match_exec("image");

    // Running the machine's own image is its workload container.
    assert_eq!(m.run("alpine:3.20", "cat /root/image-from-sdk"), "image");
    // Another image runs apart from it, and leaves the machine's files alone.
    let other = m.run(
        "python:3.12-alpine",
        "test -e /root/image-from-sdk && echo leaked; echo -n python > /root/other",
    );
    assert_eq!(other, "", "the other image saw the machine's files");
    assert_eq!(
        m.sh("test -e /root/other && echo leaked || echo kept"),
        "kept\n"
    );
    m.assert_files_match_exec("image-after-run");
}
