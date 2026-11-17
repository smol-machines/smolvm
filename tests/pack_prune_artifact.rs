#![cfg(target_os = "linux")]

use smolvm_pack::{PackManifest, Packer};
use std::path::{Path, PathBuf};

fn write_file(path: &Path) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, b"data").unwrap();
}

#[test]
fn artifact_prune_removes_the_extraction_and_keeps_daemon_disks_and_libs() {
    let temp = tempfile::tempdir().unwrap();
    let artifact = temp.path().join("app.smolmachine");
    let manifest = PackManifest::new(
        "vm://prune-test".into(),
        "none".into(),
        "linux/amd64".into(),
        "linux/amd64".into(),
    );
    Packer::new(manifest).pack_artifact(&artifact).unwrap();
    let footer = smolvm_pack::packer::read_footer_from_sidecar(&artifact).unwrap();
    let checksum = format!("{:08x}", footer.checksum);

    let cache = temp.path().join("cache");
    let shared_root = cache.join("smolvm/vms/_shared");
    let shared = shared_root.join(&checksum);
    let other_shared = shared_root.join("00000000");
    write_file(&shared.join("layers/data"));
    write_file(&other_shared.join("layers/data"));
    // More entries than the default --keep, so a prune of this cache would reach them.
    let daemon_disks: Vec<PathBuf> = std::iter::once(checksum.clone())
        .chain((1..=6).map(|n| format!("0000000{n}")))
        .map(|pack| cache.join(format!("smolvm-pack/{pack}/daemon/storage.ext4")))
        .collect();
    daemon_disks.iter().for_each(|disk| write_file(disk));
    let libs: Vec<PathBuf> = (1..=6)
        .map(|n| cache.join(format!("smolvm-libs/0000000{n}/libkrun.so")))
        .collect();
    libs.iter().for_each(|lib| write_file(lib));

    let result = std::process::Command::new(env!("CARGO_BIN_EXE_smolvm"))
        .args(["pack", "prune", "--artifact"])
        .arg(&artifact)
        .env("HOME", temp.path())
        .env("XDG_CACHE_HOME", &cache)
        .output()
        .unwrap();

    let error = String::from_utf8_lossy(&result.stderr);
    assert!(result.status.success(), "{error}");
    assert!(!shared.exists());
    assert!(other_shared.exists());
    for kept in daemon_disks.iter().chain(&libs) {
        assert!(kept.exists(), "{}", kept.display());
    }
}
