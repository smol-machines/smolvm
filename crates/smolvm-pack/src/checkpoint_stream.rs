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
        if ranges
            .iter()
            .take(count - 1)
            .any(|(offset, _)| offset % 512 != 0)
            || ranges
                .iter()
                .take(count.saturating_sub(2))
                .any(|(_, len)| len % 512 != 0)
        {
            return Err(invalid());
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

#[cfg(test)]
#[path = "checkpoint_stream_tests.rs"]
mod tests;
