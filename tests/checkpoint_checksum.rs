use smolvm_pack::{PackManifest, Packer};

#[test]
fn create_rejects_damaged_sidecar_before_extraction() {
    let temp = tempfile::tempdir().unwrap();
    let artifact = temp.path().join("damaged.smolcheckpoint");
    let manifest = PackManifest::new(
        "vm://checksum-test".into(),
        "none".into(),
        "linux/amd64".into(),
        "linux/amd64".into(),
    );
    Packer::new(manifest).pack_artifact(&artifact).unwrap();
    let original = std::fs::read(&artifact).unwrap();
    let footer = smolvm_pack::packer::read_footer_from_sidecar(&artifact).unwrap();
    for offset in [0, footer.manifest_offset as usize] {
        let mut damaged = original.clone();
        damaged[offset] ^= 0xff;
        std::fs::write(&artifact, damaged).unwrap();
        let result = std::process::Command::new(env!("CARGO_BIN_EXE_smolvm"))
            .args(["machine", "create", "--name", "checksum-test", "--from"])
            .arg(&artifact)
            .env("SMOLVM_DATA_DIR", temp.path())
            .output()
            .unwrap();
        assert!(!result.status.success());
        let error = String::from_utf8_lossy(&result.stderr);
        assert!(error.contains("checksum mismatch"), "{error}");
        assert!(!String::from_utf8_lossy(&result.stdout).contains("Extracting"));
    }
}
