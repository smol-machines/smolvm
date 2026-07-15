//! Live validation of the shared container-overlay primitive (capture + seed).
//!
//! Exercises the REAL `agent::capture_overlay_tar` / `agent::seed_overlay_tar` —
//! the exact functions `pack create --from-vm`, the snapshot endpoint, and
//! restore all route through — by booting helper VMs against a synthetic ext4
//! `storage.raw` built in-test with `mkfs.ext4 -d` (no root required).
//!
//! `#[ignore]` by default: needs a libkrun dylib to boot a VM, plus `mkfs.ext4`
//! (Linux, e2fsprogs) to build the disk. The boot-helper binary is located
//! automatically via `CARGO_BIN_EXE_smolvm`, so `SMOLVM_BOOT_BINARY` does NOT
//! need to be set by hand. Run with:
//!   SMOLVM_LIB_DIR=/path/to/lib \
//!   cargo test --test snapshot_capture_live -- --ignored --nocapture
//!
//! Without the `SMOLVM_BOOT_BINARY` shim below, these tests would silently
//! "fail to boot" (`boot process exited code 0 before agent ready`): under
//! `cargo test`, `current_exe()` is the test harness, which has no `_boot-vm`
//! subcommand, so `start_via_subprocess` spawns a process that exits instantly.

use smolvm::agent::{capture_overlay_tar, seed_overlay_tar};
use smolvm::storage::DiskFormat;
use std::path::PathBuf;

const VM: &str = "snaplive";

/// Point the boot subprocess at the freshly-built `smolvm` binary. Cargo builds
/// the `smolvm` bin before integration tests and exposes its path via
/// `CARGO_BIN_EXE_smolvm`; the harness binary that `current_exe()` returns can't
/// serve `_boot-vm`. Idempotent, and only sets the var if the caller hasn't.
fn ensure_boot_binary() {
    if std::env::var_os("SMOLVM_BOOT_BINARY").is_none() {
        std::env::set_var("SMOLVM_BOOT_BINARY", env!("CARGO_BIN_EXE_smolvm"));
    }
}

/// Build a synthetic ext4 `storage.raw` holding `overlays/persistent-<VM>/upper`
/// populated with `files` (relative path → contents). Uses `mkfs.ext4 -d` so no
/// root/loop-mount is needed. Panics with a clear message if `mkfs.ext4` is
/// absent — the test is explicitly opt-in (`--ignored`), so a silent skip would
/// just re-create the gap this file exists to close.
fn build_storage_disk(files: &[(&str, &[u8])]) -> Disk {
    let base = std::env::temp_dir().join(format!("snaplive-{}", std::process::id()));
    let stage = base.join("stage");
    let upper = stage.join(format!("overlays/persistent-{}/upper", VM));
    std::fs::create_dir_all(&upper).unwrap();
    for (rel, contents) in files {
        let p = upper.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&p, contents).unwrap();
    }

    let disk = base.join("storage.raw");
    let status = std::process::Command::new("mkfs.ext4")
        .args([
            "-F",
            "-q",
            "-d",
            &stage.to_string_lossy(),
            &disk.to_string_lossy(),
            "128M",
        ])
        .status()
        .expect("run mkfs.ext4 (install e2fsprogs; this test needs Linux)");
    assert!(status.success(), "mkfs.ext4 failed to build the test disk");
    Disk { disk, base }
}

struct Disk {
    disk: PathBuf,
    base: PathBuf,
}
impl Drop for Disk {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

fn tar_has(tar: &[u8], name: &str) -> bool {
    // tar stores each member's path as ASCII in its 512-byte header.
    String::from_utf8_lossy(tar).contains(name)
}

/// Capture must boot a read-only helper VM, mount the disk, and return the
/// overlay `upper` dir as a tar with the expected files.
#[test]
#[ignore]
fn capture_overlay_reads_persisted_overlay() {
    ensure_boot_binary();
    let d = build_storage_disk(&[("MARKER", b"capture-me\n"), ("etc/conf", b"nested\n")]);

    let cap = capture_overlay_tar(VM, &d.disk, DiskFormat::Raw).expect("capture_overlay_tar");
    println!(
        "[capture] {} tar bytes, had_content={}",
        cap.tar.len(),
        cap.had_content
    );
    assert!(cap.had_content, "expected a non-empty overlay");
    assert!(
        cap.tar.len() >= 512,
        "tar too small to be valid: {}",
        cap.tar.len()
    );
    assert!(tar_has(&cap.tar, "MARKER"), "captured tar missing MARKER");
    assert!(tar_has(&cap.tar, "conf"), "captured tar missing etc/conf");
    println!("[capture] PASS — overlay contents captured via shared primitive");
}

/// Empty-safe: a never-modified overlay still yields a valid (empty) archive.
#[test]
#[ignore]
fn capture_empty_overlay_is_valid_archive() {
    ensure_boot_binary();
    let d = build_storage_disk(&[]); // upper dir exists but is empty

    let cap = capture_overlay_tar(VM, &d.disk, DiskFormat::Raw).expect("capture_overlay_tar");
    println!(
        "[empty] {} tar bytes, had_content={}",
        cap.tar.len(),
        cap.had_content
    );
    assert!(
        !cap.had_content,
        "empty overlay should report had_content=false"
    );
    assert!(
        cap.tar.len() >= 512,
        "empty tar must still be a valid archive"
    );
    println!("[empty] PASS — empty overlay yields a valid empty archive");
}

/// Round-trip the RESTORE write path: seed an overlay into a real ext4 disk
/// (read-write helper VM, sync + umount + teardown), then prove it reached the
/// host disk image by re-capturing it in a fresh (read-only) helper VM. Also
/// proves the replace semantics: prior overlay content is gone.
#[test]
#[ignore]
fn seed_then_capture_roundtrips() {
    ensure_boot_binary();
    // Start with an OLD overlay so we can prove seed replaces it.
    let d = build_storage_disk(&[("OLD_MARKER", b"stale\n")]);

    // Build the new overlay tar host-side.
    let stage = std::env::temp_dir().join(format!("snaplive-seed-{}", std::process::id()));
    std::fs::create_dir_all(stage.join("etc")).unwrap();
    std::fs::write(stage.join("SEEDED_MARKER"), b"durable-restore\n").unwrap();
    std::fs::write(stage.join("etc/myconf"), b"hello\n").unwrap();
    let tar_path = std::env::temp_dir().join(format!("snaplive-seed-{}.tar", std::process::id()));
    let ok = std::process::Command::new("tar")
        .args([
            "cf",
            &tar_path.to_string_lossy(),
            "-C",
            &stage.to_string_lossy(),
            ".",
        ])
        .status()
        .expect("tar")
        .success();
    assert!(ok, "failed to build overlay tar");
    let tar = std::fs::read(&tar_path).unwrap();

    seed_overlay_tar(VM, &d.disk, DiskFormat::Raw, &tar).expect("seed_overlay_tar");
    let cap = capture_overlay_tar(VM, &d.disk, DiskFormat::Raw).expect("recapture");
    println!("[roundtrip] recaptured {} tar bytes", cap.tar.len());

    assert!(
        tar_has(&cap.tar, "SEEDED_MARKER"),
        "seeded marker did not persist"
    );
    assert!(tar_has(&cap.tar, "myconf"), "nested seeded file missing");
    assert!(
        !tar_has(&cap.tar, "OLD_MARKER"),
        "prior overlay survived a replace-seed"
    );
    println!("[roundtrip] PASS — seed persisted across teardown and replaced prior overlay");

    let _ = std::fs::remove_file(&tar_path);
    let _ = std::fs::remove_dir_all(&stage);
}
