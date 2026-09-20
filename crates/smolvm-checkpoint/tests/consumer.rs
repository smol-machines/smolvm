//! Exercise only the public API, as an external consumer would.
#![cfg(any(target_os = "linux", target_os = "macos"))]

use smolvm_checkpoint::{format::PackManifest, materialize, prune, publish, Writer};
use std::{fs, io};

#[test]
fn published_checkpoint_survives_older_checkpoint_and_cache_deletion() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    let cache = root.path().join("cache");
    let bytes = vec![42; 1024 * 1024 + 37];
    for generation in 0..2 {
        let staging = root.path().join(format!("staging-{generation}"));
        fs::create_dir(&staging)?;
        let mut writer = Writer::new(&cache, &staging)?;
        let file = writer.ingest("data.bin", bytes.len() as u64, 0o600, &mut &bytes[..])?;
        let manifest = PackManifest::new(
            "application://test".into(),
            "none".into(),
            "linux/amd64".into(),
            "linux/amd64".into(),
        );
        let stats = writer.finish(&staging, manifest, vec![file])?;
        if generation == 1 {
            assert_eq!(stats.new_bytes, 0);
            assert_eq!(stats.reused_bytes, bytes.len() as u64);
        }
        drop(writer);
        publish(&staging, &root.path().join(format!("saved-{generation}")))?;
    }
    fs::remove_dir_all(root.path().join("saved-0"))?;
    assert_eq!(prune(&cache)?, 0);
    fs::remove_dir_all(&cache)?;
    let saved = root.path().join("saved-1");
    let first = root.path().join("first");
    let second = root.path().join("second");
    materialize(&saved, &first)?;
    materialize(&saved, &second)?;
    fs::write(first.join("data.bin"), b"private change")?;
    assert_eq!(fs::read(second.join("data.bin"))?, bytes);
    Ok(())
}
