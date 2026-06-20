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
