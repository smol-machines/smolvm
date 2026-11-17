//! Native WHP regression; run explicitly with SMOLVM_TEST_BINARY set to the candidate CLI.
#![cfg(windows)]

use smolvm::data::network::SwitchAttachment;
use smolvm_network::switch::{
    publish_route, render_endpoint_file, Member, NetworkName, SwitchEndpoint,
};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

struct Fixture {
    root: tempfile::TempDir,
    binary: PathBuf,
    cleaned: bool,
}

impl Fixture {
    fn run(&self, args: &[&str]) -> Output {
        let stdout = tempfile::tempfile().unwrap();
        let stderr = tempfile::tempfile().unwrap();
        let mut cmd = Command::new(&self.binary);
        // The fixture owns its database, VM files, Docker config and commands.
        for (key, _) in std::env::vars_os() {
            let key_text = key.to_string_lossy();
            if key_text.starts_with("SMOLVM_") || key_text.starts_with("DOCKER_") {
                cmd.env_remove(key);
            }
        }
        cmd.env(
            "SMOLVM_LIB_DIR",
            std::env::var_os("SMOLVM_LIB_DIR").expect("packaged runtime location required"),
        );
        for key in ["SMOLVM_AGENT_ROOTFS", "SMOLVM_AGENT_ROOTFS_TAR"] {
            if let Some(value) = std::env::var_os(key) {
                cmd.env(key, value);
            }
        }
        let mut child = cmd
            .args(args)
            .env("SMOLVM_DATA_DIR", self.root.path().join("state"))
            .env("DOCKER_CONFIG", self.root.path().join("docker"))
            .stdin(Stdio::null())
            .stdout(stdout.try_clone().unwrap())
            .stderr(stderr.try_clone().unwrap())
            .spawn()
            .unwrap();
        let until = Instant::now() + Duration::from_secs(120);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= until {
                let _ = child.kill();
                let _ = child.wait();
                panic!("timed out: {args:?}");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        fn read(mut file: std::fs::File) -> Vec<u8> {
            use std::io::{Read, Seek};
            file.rewind().unwrap();
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).unwrap();
            bytes
        }
        Output {
            status,
            stdout: read(stdout),
            stderr: read(stderr),
        }
    }

    fn ok(&self, args: &[&str]) -> String {
        let output = self.run(args);
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    fn exec(&self, name: &str, script: &str) -> String {
        self.ok(&["machine", "exec", "--name", name, "--", "sh", "-c", script])
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if self.cleaned {
            return;
        }
        for name in ["switch-a", "switch-b"] {
            for action in ["stop", "delete"] {
                let mut args = vec!["machine", action, "--name", name];
                if action == "delete" {
                    args.push("-f");
                }
                let output = self.run(&args);
                if !output.status.success() {
                    eprintln!(
                        "fixture cleanup {args:?}: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
            }
        }
    }
}

fn member(ip: &str) -> Member {
    Member {
        network: NetworkName::new("shared").unwrap(),
        ip: ip.parse().unwrap(),
        prefix: 24,
    }
}

#[test]
#[ignore = "requires native Windows WHP and a packaged candidate CLI"]
fn running_windows_guests_use_switch_dns_tcp_and_network_isolation() {
    let binary = std::env::var_os("SMOLVM_TEST_BINARY").expect("set candidate CLI path");
    assert!(Path::new(&binary).is_absolute());
    let mut fixture = Fixture {
        root: tempfile::Builder::new()
            .prefix("smol-windows-switch-")
            .tempdir()
            .unwrap(),
        binary: binary.into(),
        cleaned: false,
    };
    let dir = fixture.root.path().join("switch workspace");
    std::fs::create_dir_all(dir.join("ep")).unwrap();
    let a = SwitchEndpoint {
        dir: dir.clone(),
        id: "switch-a".into(),
    };
    let b = SwitchEndpoint {
        dir: dir.clone(),
        id: "switch-b".into(),
    };
    for (endpoint, ip) in [(&a, "172.28.40.2"), (&b, "172.28.40.3")] {
        fixture.ok(&[
            "machine",
            "create",
            "--name",
            &endpoint.id,
            "--cpus",
            "2",
            "--mem",
            "256",
            "--storage",
            "1",
            "--overlay",
            "1",
            "--net",
            "--net-backend",
            "virtio-net",
        ]);
        let db = smolvm::db::SmolvmDb::open_at(
            &fixture
                .root
                .path()
                .join("state/AppData/Local/smolvm/server/smolvm.db"),
        )
        .unwrap();
        assert!(db
            .update_vm(&endpoint.id, |record| {
                record.switch = Some(SwitchAttachment {
                    dir: dir.clone(),
                    endpoint: endpoint.id.clone(),
                });
            })
            .unwrap()
            .is_some());
        let m = member(ip);
        std::fs::write(endpoint.config_path(), render_endpoint_file(&[m])).unwrap();
        publish_route(endpoint, m.network, m.ip).unwrap();
    }
    std::fs::write(
        dir.join("n/shared/names"),
        "app 172.28.40.2\ndb 172.28.40.3\n",
    )
    .unwrap();
    for name in ["switch-a", "switch-b"] {
        fixture.ok(&["machine", "start", "--name", name]);
    }
    assert!(fixture
        .exec("switch-a", "ip -4 addr show dev eth0")
        .contains("172.28.40.2/24"));
    assert!(fixture
        .exec("switch-b", "ip -4 addr show dev eth0")
        .contains("172.28.40.3/24"));
    fixture.exec("switch-b", "dd if=/dev/zero of=/workspace/source bs=65536 count=32; (while :; do nc -l -p 8080 -e cat /workspace/source; done) </dev/null >/workspace/server.log 2>&1 &");
    fixture.exec("switch-a", "nc -w 3 db 8080 </dev/null > /workspace/probe; test $(wc -c < /workspace/probe) -eq 2097152");
    assert_eq!(
        fixture
            .exec("switch-a", "sha256sum /workspace/probe")
            .split_whitespace()
            .next(),
        fixture
            .exec("switch-b", "sha256sum /workspace/source")
            .split_whitespace()
            .next()
    );
    println!("PASS: two WHP guests, switch addressing, DNS and 2 MiB TCP transfer");
    // A live receiver leaves the shared network without restarting either VM.
    let other = Member {
        network: NetworkName::new("other").unwrap(),
        ip: "172.29.40.3".parse().unwrap(),
        prefix: 24,
    };
    std::fs::write(b.config_path(), render_endpoint_file(&[other])).unwrap();
    std::thread::sleep(Duration::from_millis(500));
    let started = Instant::now();
    let denied = fixture.run(&[
        "machine",
        "exec",
        "--name",
        "switch-a",
        "--",
        "nc",
        "-w",
        "2",
        "172.28.40.3",
        "8080",
    ]);
    assert!(
        !denied.status.success(),
        "removed network still carries guest traffic"
    );
    assert_eq!(denied.status.code(), Some(1));
    assert!(
        started.elapsed() >= Duration::from_secs(1),
        "connection did not wait for its network timeout: {denied:?}"
    );
    fixture.exec("switch-b", "test -f /workspace/source");
    println!("PASS: live membership removal isolates the guest without stopping it");
    // Rejoining also exercises cached streams after a network generation change.
    std::fs::write(
        b.config_path(),
        render_endpoint_file(&[member("172.28.40.3")]),
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(500));
    fixture.exec("switch-a", "nc -w 3 db 8080 </dev/null > /workspace/probe; test $(wc -c < /workspace/probe) -eq 2097152");
    println!("PASS: rejoining restores guest connectivity");
    for name in ["switch-a", "switch-b"] {
        fixture.ok(&["machine", "stop", "--name", name]);
        fixture.ok(&["machine", "delete", "--name", name, "-f"]);
    }
    let inventory: serde_json::Value =
        serde_json::from_str(&fixture.ok(&["machine", "ls", "--json"])).unwrap();
    assert!(inventory.as_array().unwrap().is_empty());
    fixture.cleaned = true;
    println!("PASS: all fixture machines removed");
}
