//! Live validation of the snapshot-capture helper-VM mechanism.
//!
//! This exercises the exact path `snapshot_machine`'s `capture_overlay_blocking`
//! uses — boot a helper VM with a source machine's storage disk attached as
//! `/dev/vdc`, mount it read-only, and `tar` the container overlay upper dir —
//! against a REAL ext4 `storage.raw`, using only public `smolvm` API.
//!
//! Ignored by default (needs a libkrun dylib + a real storage disk). Run with:
//!   SMOLVM_LIB_DIR=/path/to/lib \
//!   SNAP_TEST_STORAGE=/path/to/vms/<id>/storage.raw \
//!   cargo test --test snapshot_capture_live -- --ignored --nocapture

use smolvm::agent::{AgentManager, LaunchFeatures, VmResources};

#[test]
#[ignore]
fn helper_vm_captures_overlay_tar() {
    let storage = std::env::var("SNAP_TEST_STORAGE")
        .expect("set SNAP_TEST_STORAGE to a machine storage.raw path");
    let storage_path = std::path::PathBuf::from(&storage);
    assert!(storage_path.exists(), "storage disk not found: {}", storage);

    let helper = format!("snaptest-helper-{}", std::process::id());
    let manager = AgentManager::for_vm(&helper).expect("helper manager");

    let features = LaunchFeatures {
        extra_disks: vec![(storage_path, false)],
        ..Default::default()
    };
    manager
        .start_with_full_config(
            Vec::new(),
            Vec::new(),
            VmResources {
                cpus: 2,
                memory_mib: 2048,
                network: false,
                network_backend: None,
                gpu: false,
                gpu_vram_mib: None,
                storage_gib: None,
                overlay_gib: None,
                allowed_cidrs: None,
            },
            features,
        )
        .expect("start helper VM");

    let outcome = {
        let mut client = manager.connect().expect("connect helper VM");

        // Mount the source storage disk (/dev/vdc) read-only.
        let (code, _, stderr) = client
            .vm_exec(
                vec![
                    "sh".into(),
                    "-c".into(),
                    "mkdir -p /mnt/src && mount -o ro /dev/vdc /mnt/src".into(),
                ],
                vec![],
                None,
                None,
                None,
            )
            .expect("mount exec");
        assert_eq!(
            code,
            0,
            "mount /dev/vdc failed: {}",
            String::from_utf8_lossy(&stderr)
        );

        // Show what overlays exist — this is what a real capture would tar.
        let (_, out, _) = client
            .vm_exec(
                vec![
                    "sh".into(),
                    "-c".into(),
                    "ls -1 /mnt/src/overlays 2>/dev/null; \
                     echo '---upper sizes---'; \
                     du -sh /mnt/src/overlays/*/upper 2>/dev/null | head"
                        .into(),
                ],
                vec![],
                None,
                None,
                None,
            )
            .expect("list overlays exec");
        println!("[overlays on disk]\n{}", String::from_utf8_lossy(&out));

        // Tar the FIRST persistent overlay's upper dir if one exists, else tar an
        // empty dir — same empty-safe behavior as capture_overlay_blocking.
        let script = "set -e; \
             U=$(ls -d /mnt/src/overlays/persistent-*/upper 2>/dev/null | head -1); \
             mkdir -p /tmp/empty; \
             if [ -n \"$U\" ]; then echo \"capturing $U\"; tar cf /tmp/snap.tar -C \"$U\" . ; \
             else echo 'no persistent overlay; empty tar'; tar cf /tmp/snap.tar -C /tmp/empty . ; fi; \
             echo \"tar bytes: $(wc -c < /tmp/snap.tar)\"";
        let (code, out, stderr) = client
            .vm_exec(
                vec!["sh".into(), "-c".into(), script.into()],
                vec![],
                None,
                None,
                None,
            )
            .expect("tar exec");
        println!("[tar step]\n{}", String::from_utf8_lossy(&out));
        assert_eq!(code, 0, "tar failed: {}", String::from_utf8_lossy(&stderr));

        // Read the tar back out — this is the byte stream the endpoint returns.
        let tar = client.read_file("/tmp/snap.tar").expect("read snap.tar");
        assert!(!tar.is_empty(), "snapshot tar is unexpectedly empty");
        // A valid (even empty) tar is >= 512 bytes (one zeroed record block).
        assert!(
            tar.len() >= 512,
            "snapshot tar too small to be a valid archive: {} bytes",
            tar.len()
        );
        println!(
            "[captured] {} tar bytes read back from helper VM",
            tar.len()
        );
        tar.len()
    };

    let _ = manager.stop();
    println!("helper VM stopped; captured {} bytes", outcome);
}

/// Round-trip the RESTORE write path: seed an overlay into a real ext4 disk via
/// one helper VM, then prove it survived (sync + umount + VM teardown reached
/// the host disk image) by reading it back in a SECOND helper VM. This is the
/// property capture's read-only test can't cover.
///
/// Writes to a COW copy of SNAP_TEST_STORAGE so the source disk is untouched.
/// Run with the same env as `helper_vm_captures_overlay_tar` (see module docs).
#[test]
#[ignore]
fn restore_seeds_overlay_persistently() {
    let src = std::env::var("SNAP_TEST_STORAGE")
        .expect("set SNAP_TEST_STORAGE to a machine storage.raw path");
    // COW copy (clonefile on APFS) so the original disk is never modified.
    let scratch = format!("/tmp/snaptest-restore-{}.raw", std::process::id());
    let status = std::process::Command::new("cp")
        .args(["-c", src.as_str(), scratch.as_str()])
        .status()
        .expect("cp -c");
    assert!(status.success(), "failed to COW-copy disk");
    let scratch_path = std::path::PathBuf::from(&scratch);
    let _cleanup = DropFile(scratch.clone());

    // Build a tiny overlay tar host-side containing a known marker file.
    let stage = format!("/tmp/snaptest-stage-{}", std::process::id());
    std::fs::create_dir_all(format!("{}/etc", stage)).unwrap();
    std::fs::write(format!("{}/RESTORE_MARKER", stage), b"durable-restore\n").unwrap();
    std::fs::write(format!("{}/etc/myconf", stage), b"hello\n").unwrap();
    let tar_path = format!("/tmp/snaptest-overlay-{}.tar", std::process::id());
    let status = std::process::Command::new("tar")
        .args(["cf", tar_path.as_str(), "-C", stage.as_str(), "."])
        .status()
        .expect("tar");
    assert!(status.success(), "failed to build overlay tar");
    let tar = std::fs::read(&tar_path).unwrap();
    let _t = DropFile(tar_path);
    let _s = DropDir(stage);
    println!("[restore] staged overlay tar: {} bytes", tar.len());

    let overlay_id = "roundtrip";

    // --- Phase 1: write the overlay into the scratch disk via a helper VM. ---
    {
        let wname = format!("snaptest-w-{}", std::process::id());
        let m = AgentManager::for_vm(&wname).expect("writer manager");
        m.start_with_full_config(
            Vec::new(),
            Vec::new(),
            helper_resources(),
            LaunchFeatures {
                extra_disks: vec![(scratch_path.clone(), false)], // read-write
                ..Default::default()
            },
        )
        .expect("start writer VM");

        {
            let mut c = m.connect().expect("connect writer");
            let (code, _, e) = c
                .vm_exec(
                    sh("mkdir -p /mnt/src && mount /dev/vdc /mnt/src"),
                    vec![],
                    None,
                    None,
                    None,
                )
                .expect("mount rw");
            assert_eq!(code, 0, "mount rw failed: {}", String::from_utf8_lossy(&e));

            c.write_file("/tmp/restore.tar", &tar, None)
                .expect("push tar");

            let root = format!("/mnt/src/overlays/persistent-{}", overlay_id);
            let script = format!(
                "set -e; rm -rf '{r}'; mkdir -p '{r}/upper'; \
                 tar xf /tmp/restore.tar -C '{r}/upper'; sync; umount /mnt/src",
                r = root
            );
            let (code, _, e) = c
                .vm_exec(sh(&script), vec![], None, None, None)
                .expect("untar");
            assert_eq!(code, 0, "untar failed: {}", String::from_utf8_lossy(&e));
        }
        let _ = m.stop();
        println!("[restore] phase 1 done — overlay written + VM torn down");
    }

    // --- Phase 2: a fresh helper VM must see the persisted marker. ---
    {
        let rname = format!("snaptest-r-{}", std::process::id());
        let m = AgentManager::for_vm(&rname).expect("reader manager");
        m.start_with_full_config(
            Vec::new(),
            Vec::new(),
            helper_resources(),
            LaunchFeatures {
                extra_disks: vec![(scratch_path.clone(), true)], // read-only verify
                ..Default::default()
            },
        )
        .expect("start reader VM");

        let found = {
            let mut c = m.connect().expect("connect reader");
            let (code, _, e) = c
                .vm_exec(
                    sh("mkdir -p /mnt/src && mount -o ro /dev/vdc /mnt/src"),
                    vec![],
                    None,
                    None,
                    None,
                )
                .expect("mount ro");
            assert_eq!(code, 0, "mount ro failed: {}", String::from_utf8_lossy(&e));

            let upper = format!("/mnt/src/overlays/persistent-{}/upper", overlay_id);
            let (code, out, _) = c
                .vm_exec(
                    sh(&format!(
                        "cat '{u}/RESTORE_MARKER' 2>/dev/null; echo '|'; cat '{u}/etc/myconf' 2>/dev/null",
                        u = upper
                    )),
                    vec![],
                    None,
                    None,
                    None,
                )
                .expect("read marker");
            assert_eq!(code, 0, "read marker exec failed");
            String::from_utf8_lossy(&out).to_string()
        };
        let _ = m.stop();

        println!("[restore] phase 2 read back: {:?}", found);
        assert!(
            found.contains("durable-restore"),
            "RESTORE_MARKER did not persist across VM teardown: {:?}",
            found
        );
        assert!(
            found.contains("hello"),
            "nested etc/myconf missing: {:?}",
            found
        );
        println!("[restore] PASS — overlay persisted across helper-VM teardown");
    }
}

fn helper_resources() -> VmResources {
    VmResources {
        cpus: 2,
        memory_mib: 2048,
        network: false,
        network_backend: None,
        gpu: false,
        gpu_vram_mib: None,
        storage_gib: None,
        overlay_gib: None,
        allowed_cidrs: None,
    }
}

fn sh(script: &str) -> Vec<String> {
    vec!["sh".into(), "-c".into(), script.into()]
}

struct DropFile(String);
impl Drop for DropFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

struct DropDir(String);
impl Drop for DropDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
