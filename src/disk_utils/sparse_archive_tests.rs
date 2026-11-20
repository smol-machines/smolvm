use std::fs::{self, File};

fn sparse(logical: u64, extents: &[(u64, u64)], payload: &[u8]) -> Vec<u8> {
    let mut extents = extents.to_vec();
    extents.push((logical, 0)); // GNU sparse tar explicitly records trailing holes.
    let extents = extents.as_slice();
    let mut header = tar::Header::new_gnu();
    header.set_path("checkpoint/memory.bin").unwrap();
    header.set_mode(0o600);
    header.set_size(payload.len() as u64);
    header.set_entry_type(tar::EntryType::GNUSparse);
    let gnu = header.as_gnu_mut().unwrap();
    gnu.set_real_size(logical);
    for (slot, (offset, length)) in gnu.sparse.iter_mut().zip(extents) {
        slot.set_offset(*offset);
        slot.set_length(*length);
    }
    gnu.set_is_extended(extents.len() > 4);
    header.set_cksum();
    let mut bytes = header.as_bytes().to_vec();
    let extra = extents.get(4..).unwrap_or(&[]);
    let chunks = extra.chunks(21).collect::<Vec<_>>();
    for (index, chunk) in chunks.iter().enumerate() {
        let mut extension = tar::GnuExtSparseHeader::new();
        for (slot, (offset, length)) in extension.sparse_mut().iter_mut().zip(*chunk) {
            slot.set_offset(*offset);
            slot.set_length(*length);
        }
        extension.set_is_extended(index + 1 < chunks.len());
        bytes.extend_from_slice(extension.as_bytes());
    }
    bytes.extend_from_slice(payload);
    bytes.resize(bytes.len().next_multiple_of(512) + 1024, 0);
    bytes
}

#[test]
fn sparse_archive_preserves_contents_and_holes_after_writeback() {
    use std::os::unix::fs::MetadataExt;
    let mib = 1024 * 1024;
    let cases = [
        ("small", 8 * mib, vec![(0, 4096), (8 * mib - 4096, 4096)]),
        (
            "fragmented",
            64 * mib,
            (0..8).map(|i| (i * 8 * mib, 4096)).collect(),
        ),
        (
            "large-hole",
            64 * mib,
            vec![(0, 4096), (64 * mib - 4096, 4096)],
        ),
        ("trailing-hole", 8 * mib, vec![(0, 4096)]),
        (
            "unaligned-small",
            8 * mib,
            vec![(0, 512), (8 * mib - 15, 15)],
        ),
        (
            "unaligned-fragmented",
            64 * mib,
            (0..8).map(|i| (i * 8 * mib + 1, 512)).collect(),
        ),
    ];
    let mut excessive = Vec::new();
    for (name, logical, extents) in cases {
        let root = tempfile::tempdir().unwrap();
        let stored = extents.iter().map(|(_, n)| n).sum::<u64>() as usize;
        let archive = sparse(logical, &extents, &vec![7; stored]);
        tar::Archive::new(archive.as_slice())
            .unpack(root.path().join("output"))
            .unwrap();
        // Allow boundary blocks around each extent, but never full logical
        // allocation: this must stay sparse after the filesystem flushes it.
        let allocation_limit = (extents.len() as u64 * 2 + 1) * 64 * 1024;
        let file = File::open(root.path().join("output/checkpoint/memory.bin")).unwrap();
        let contents = fs::read(root.path().join("output/checkpoint/memory.bin")).unwrap();
        assert_eq!(contents.len() as u64, logical);
        let mut previous_end = 0;
        for (offset, length) in &extents {
            assert!(contents[previous_end..*offset as usize]
                .iter()
                .all(|b| *b == 0));
            assert!(contents[*offset as usize..(*offset + *length) as usize]
                .iter()
                .all(|b| *b == 7));
            previous_end = (*offset + *length) as usize;
        }
        assert!(contents[previous_end..].iter().all(|b| *b == 0));
        file.sync_all().unwrap();
        let allocated = file.metadata().unwrap().blocks() * 512;
        eprintln!(
            "{name}: logical={logical} limit={} allocated={allocated}",
            allocation_limit
        );
        if allocated > allocation_limit {
            excessive.push((name, allocated, allocation_limit));
        }
    }
    assert!(
        excessive.is_empty(),
        "sparse extraction allocated its holes: {excessive:?}"
    );
}
