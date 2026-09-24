use super::*;

fn wire(reply: &[u8]) -> Vec<u8> {
    let mut out = b"SMOLCKS1".to_vec();
    out.extend_from_slice(&3_u32.to_le_bytes());
    out.extend_from_slice(&3_u32.to_le_bytes());
    out.extend_from_slice(b"cpumapSMOLRSP1");
    out.extend_from_slice(&8192_u64.to_le_bytes());
    out.extend_from_slice(&2_u32.to_le_bytes());
    for value in [1024_u64, 3, 8192, 0] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out.extend_from_slice(b"RAM");
    out.extend_from_slice(reply);
    out
}

#[test]
fn sparse_archive_preserves_bytes_and_requires_completion() {
    let good = wire(b"OK saved (8192 bytes, 1 regions)\n");
    let mut input = good.as_slice();
    let mut stream = CheckpointStream::read(&mut input, 8192).unwrap();
    assert_eq!(stream.state(), b"cpu");
    assert_eq!(stream.layout(), b"map");
    let mut archive = tar::Builder::new(Vec::new());
    stream.append(&mut archive).unwrap();
    assert!(stream.append(&mut archive).is_err());
    let bytes = archive.into_inner().unwrap();
    let mut archive = tar::Archive::new(bytes.as_slice());
    let mut entries = archive.entries().unwrap();
    let mut entry = entries.next().unwrap().unwrap();
    assert_eq!(
        entry.path().unwrap().as_ref(),
        std::path::Path::new("checkpoint/memory.bin")
    );
    let mut restored = Vec::new();
    entry.read_to_end(&mut restored).unwrap();
    let mut expected = vec![0; 8192];
    expected[1024..1027].copy_from_slice(b"RAM");
    assert_eq!(restored, expected);
    assert!(entries.next().is_none());
    for end in 0..good.len() {
        let mut input = &good[..end];
        if let Ok(mut stream) = CheckpointStream::read(&mut input, 8192) {
            assert!(
                stream.append(&mut tar::Builder::new(Vec::new())).is_err(),
                "accepted truncated frame at {end}"
            );
        }
    }
}

#[test]
fn failed_runtime_completion_never_publishes_an_artifact() {
    for reply in [
        b"ERR EIO output failed\n".as_slice(),
        b"OK saved (8193 bytes, 1 regions)\n",
        b"OK saved (8192 bytes, 0 regions)\n",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let staging = temp.path().join("staging");
        let collector = crate::assets::AssetCollector::new(staging).unwrap();
        let manifest = crate::PackManifest::new(
            "test".into(),
            "none".into(),
            "linux/amd64".into(),
            "linux/amd64".into(),
        );
        let bytes = wire(reply);
        let mut source = bytes.as_slice();
        let mut stream = CheckpointStream::read(&mut source, 8192).unwrap();
        let output = temp.path().join("failed.smolcheckpoint");
        assert!(crate::Packer::new(manifest)
            .with_asset_collector(collector)
            .pack_checkpoint_stream(&output, &mut stream)
            .is_err());
        assert!(!output.exists());
    }
}

#[test]
fn interrupted_stream_preserves_existing_checkpoint_and_cleans_temporary_output() {
    let good = wire(b"OK saved (8192 bytes, 1 regions)\n");
    for end in 0..good.len() {
        let mut source = &good[..end];
        let Ok(mut stream) = CheckpointStream::read(&mut source, 8192) else {
            continue;
        };
        let temp = tempfile::tempdir().unwrap();
        let output = temp.path().join("existing.smolcheckpoint");
        let previous = b"previous durable checkpoint";
        std::fs::write(&output, previous).unwrap();
        let collector = crate::assets::AssetCollector::new(temp.path().join("staging")).unwrap();
        let manifest = crate::PackManifest::new(
            "test".into(),
            "none".into(),
            "linux/amd64".into(),
            "linux/amd64".into(),
        );
        assert!(
            crate::Packer::new(manifest)
                .with_asset_collector(collector)
                .pack_checkpoint_stream(&output, &mut stream)
                .is_err(),
            "accepted truncated stream at {end}"
        );
        assert_eq!(std::fs::read(&output).unwrap(), previous);
        let mut entries: Vec<_> = std::fs::read_dir(temp.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        entries.sort();
        assert_eq!(entries, ["existing.smolcheckpoint", "staging"]);
    }
}

#[test]
fn malformed_maps_and_unbounded_metadata_are_rejected() {
    let good = wire(b"OK saved (8192 bytes, 1 regions)\n");
    let mut source = good.as_slice();
    assert!(CheckpointStream::read(&mut source, 8191).is_err());
    for (offset, bytes) in [
        (8, u32::MAX.to_le_bytes().to_vec()),
        (38, 65538_u32.to_le_bytes().to_vec()),
        (42, u64::MAX.to_le_bytes().to_vec()),
        (66, 1_u64.to_le_bytes().to_vec()),
    ] {
        let mut bad = good.clone();
        bad[offset..offset + bytes.len()].copy_from_slice(&bytes);
        assert!(CheckpointStream::read(&mut bad.as_slice(), 8192).is_err());
    }
}

#[test]
fn extended_sparse_headers_preserve_every_range() {
    let logical = 32768_u64;
    let mut wire = b"SMOLCKS1".to_vec();
    wire.extend_from_slice(&3_u32.to_le_bytes());
    wire.extend_from_slice(&3_u32.to_le_bytes());
    wire.extend_from_slice(b"cpumapSMOLRSP1");
    wire.extend_from_slice(&logical.to_le_bytes());
    wire.extend_from_slice(&31_u32.to_le_bytes());
    for index in 0..30_u64 {
        wire.extend_from_slice(&(index * 1024).to_le_bytes());
        wire.extend_from_slice(&512_u64.to_le_bytes());
    }
    wire.extend_from_slice(&logical.to_le_bytes());
    wire.extend_from_slice(&0_u64.to_le_bytes());
    for value in 1..=30_u8 {
        wire.extend_from_slice(&[value; 512]);
    }
    wire.extend_from_slice(b"OK saved (32768 bytes, 1 regions)\n");
    let mut unaligned = wire.clone();
    unaligned[50..58].copy_from_slice(&1_u64.to_le_bytes());
    assert!(CheckpointStream::read(&mut unaligned.as_slice(), logical).is_err());
    let mut source = wire.as_slice();
    let mut stream = CheckpointStream::read(&mut source, logical).unwrap();
    let mut builder = tar::Builder::new(Vec::new());
    stream.append(&mut builder).unwrap();
    let bytes = builder.into_inner().unwrap();
    let mut archive = tar::Archive::new(bytes.as_slice());
    let mut restored = Vec::new();
    archive
        .entries()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .read_to_end(&mut restored)
        .unwrap();
    let mut expected = vec![0; logical as usize];
    for index in 0..30 {
        expected[index * 1024..index * 1024 + 512].fill(index as u8 + 1);
    }
    assert_eq!(restored, expected);
}

#[test]
fn memory_copy_matches_the_unpacked_entry_without_changing_the_archive() {
    let good = wire(b"OK saved (8192 bytes, 1 regions)\n");
    let pack = |copy: Option<std::fs::File>| {
        let mut input = good.as_slice();
        let mut stream = CheckpointStream::read(&mut input, 8192).unwrap();
        let copying = copy.is_some();
        if let Some(file) = copy {
            stream.copy_memory_to(file);
        }
        let mut archive = tar::Builder::new(Vec::new());
        stream.append(&mut archive).unwrap();
        assert_eq!(stream.memory_copied(), copying);
        archive.into_inner().unwrap()
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("memory.bin");
    let with_copy = pack(Some(std::fs::File::create(&path).unwrap()));
    assert_eq!(with_copy, pack(None));
    let mut expected = vec![0; 8192];
    expected[1024..1027].copy_from_slice(b"RAM");
    assert_eq!(std::fs::read(&path).unwrap(), expected);
}
