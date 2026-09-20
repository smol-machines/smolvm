//! Store application data; this example does not capture a running VM.
use smolvm_checkpoint::{format::PackManifest, materialize, publish, Writer};
use std::{fs, io};

fn main() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    let staging = root.path().join("staging");
    fs::create_dir(&staging)?;
    let saved = root.path().join("saved");
    let payload = b"application state";
    let mut writer = Writer::new(&root.path().join("cache"), &staging)?;
    let file = writer.ingest("state.bin", payload.len() as u64, 0o600, &mut &payload[..])?;
    let manifest = PackManifest::new(
        "application://example".into(),
        "none".into(),
        "linux/amd64".into(),
        "linux/amd64".into(),
    );
    let stats = writer.finish(&staging, manifest, vec![file])?;
    drop(writer);
    publish(&staging, &saved)?;
    let restored = root.path().join("restored");
    materialize(&saved, &restored)?;
    assert_eq!(fs::read(restored.join("state.bin"))?, payload);
    println!(
        "Restored {} bytes; {} new compressed bytes",
        payload.len(),
        stats.new_bytes
    );
    Ok(())
}
