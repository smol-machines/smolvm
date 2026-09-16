//! Bounded checkpoint RAM input for packing without a temporary memory file.

use std::io::{self, Read, Write};

/// A captured CPU/layout boundary and an immutable sparse RAM stream.
///
/// Construction validates framing, not artifact durability. Packing must read
/// the exact payload and successful completion reply before publishing output.
pub struct CheckpointStream<'a> {
    source: &'a mut dyn Read,
    state: Vec<u8>,
    layout: Vec<u8>,
    logical: u64,
    ranges: Vec<(u64, u64)>,
    consumed: bool,
}

#[cfg(test)]
mod tests {
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
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid checkpoint stream")
}

impl<'a> CheckpointStream<'a> {
    /// Read bounded metadata and a validated sparse map from the local runtime.
    pub fn read(source: &'a mut dyn Read, max_memory_bytes: u64) -> io::Result<Self> {
        let mut header = [0; 16];
        source.read_exact(&mut header)?;
        let state_len = u32::from_le_bytes(header[8..12].try_into().unwrap()) as usize;
        let layout_len = u32::from_le_bytes(header[12..16].try_into().unwrap()) as usize;
        if &header[..8] != b"SMOLCKS1"
            || state_len == 0
            || layout_len == 0
            || state_len > 16 * 1024 * 1024
            || layout_len > 1024 * 1024
        {
            return Err(invalid());
        }
        let mut state = vec![0; state_len];
        let mut layout = vec![0; layout_len];
        source.read_exact(&mut state)?;
        source.read_exact(&mut layout)?;
        let mut sparse = [0; 20];
        source.read_exact(&mut sparse)?;
        let logical = u64::from_le_bytes(sparse[8..16].try_into().unwrap());
        let count = u32::from_le_bytes(sparse[16..20].try_into().unwrap()) as usize;
        if &sparse[..8] != b"SMOLRSP1"
            || logical == 0
            || logical > max_memory_bytes
            || count == 0
            || count > 65537
        {
            return Err(invalid());
        }
        let mut ranges = Vec::with_capacity(count);
        let mut end = 0;
        for index in 0..count {
            let mut entry = [0; 16];
            source.read_exact(&mut entry)?;
            let offset = u64::from_le_bytes(entry[..8].try_into().unwrap());
            let len = u64::from_le_bytes(entry[8..].try_into().unwrap());
            if index + 1 == count {
                if (offset, len) != (logical, 0) {
                    return Err(invalid());
                }
            } else {
                let next = offset.checked_add(len).ok_or_else(invalid)?;
                if len == 0 || offset < end || next > logical {
                    return Err(invalid());
                }
                end = next;
            }
            ranges.push((offset, len));
        }
        Ok(Self {
            source,
            state,
            layout,
            logical,
            ranges,
            consumed: false,
        })
    }

    /// Captured CPU/device bytes; the caller must validate the runtime format.
    pub fn state(&self) -> &[u8] {
        &self.state
    }

    /// Captured RAM layout; the caller must validate its runtime format.
    pub fn layout(&self) -> &[u8] {
        &self.layout
    }

    /// Logical RAM length, including holes.
    pub fn memory_len(&self) -> u64 {
        self.logical
    }

    pub(crate) fn append<W: Write>(&mut self, archive: &mut tar::Builder<W>) -> io::Result<()> {
        if self.consumed {
            return Err(invalid());
        }
        self.consumed = true;
        // Sorted, disjoint ranges were checked against logical length above.
        let stored: u64 = self.ranges.iter().map(|(_, len)| *len).sum();
        let mut header = tar::Header::new_gnu();
        header.set_path("checkpoint/memory.bin")?;
        header.set_mode(0o600);
        header.set_entry_type(tar::EntryType::GNUSparse);
        header.set_size(stored);
        let gnu = header.as_gnu_mut().unwrap();
        gnu.set_real_size(self.logical);
        for ((offset, len), slot) in self.ranges.iter().zip(gnu.sparse.iter_mut()) {
            slot.set_offset(*offset);
            slot.set_length(*len);
        }
        gnu.set_is_extended(self.ranges.len() > 4);
        header.set_cksum();
        archive.get_mut().write_all(header.as_bytes())?;
        let rest = &self.ranges[self.ranges.len().min(4)..];
        for (index, chunk) in rest.chunks(21).enumerate() {
            let mut extra = tar::GnuExtSparseHeader::new();
            for ((offset, len), slot) in chunk.iter().zip(extra.sparse_mut().iter_mut()) {
                slot.set_offset(*offset);
                slot.set_length(*len);
            }
            extra.set_is_extended((index + 1) * 21 < rest.len());
            archive.get_mut().write_all(extra.as_bytes())?;
        }
        let copied = io::copy(&mut (&mut *self.source).take(stored), archive.get_mut())?;
        if copied != stored {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let padding = (512 - stored % 512) % 512;
        archive.get_mut().write_all(&[0; 512][..padding as usize])?;
        let mut reply = Vec::new();
        (&mut *self.source).take(4097).read_to_end(&mut reply)?;
        if reply.len() > 4096 {
            return Err(invalid());
        }
        let reply = std::str::from_utf8(&reply).map_err(|_| invalid())?;
        let prefix = format!("OK saved ({} bytes, ", self.logical);
        let regions = reply
            .strip_prefix(&prefix)
            .and_then(|s| s.strip_suffix(" regions)\n"))
            .and_then(|s| s.parse::<u32>().ok())
            .filter(|n| *n > 0);
        if regions.is_none() {
            return Err(invalid());
        }
        Ok(())
    }
}
