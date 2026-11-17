//! Bounded checkpoint RAM input for packing without a temporary memory file.

use std::io::{self, Read, Seek, SeekFrom, Write};

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
    position: u64,
    range_index: usize,
    consumed: bool,
    copy: Option<std::fs::File>,
    copy_failed: bool,
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
            position: 0,
            range_index: 0,
            consumed: false,
            copy: None,
            copy_failed: false,
        })
    }

    /// Also write the RAM image, unpacked and sparse, to `file` while packing,
    /// so the capture can keep a ready-to-restore copy without writing the
    /// holes or decompressing the artifact again. Best-effort: a failed copy
    /// never fails packing; see [`Self::memory_copied`].
    pub fn copy_memory_to(&mut self, file: std::fs::File) {
        self.copy = Some(file);
    }

    /// Whether the copy requested by [`Self::copy_memory_to`] is complete.
    pub fn memory_copied(&self) -> bool {
        self.consumed && self.copy.is_some() && !self.copy_failed
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

    /// Read the next logical RAM chunk for a checkpoint store. A whole hole
    /// returns `false` without allocating or reading from the socket. Chunks
    /// containing data are filled with zeros between the sparse ranges.
    pub fn read_sparse_chunk(&mut self, buffer: &mut Vec<u8>, count: usize) -> io::Result<bool> {
        let end = self
            .position
            .checked_add(count as u64)
            .ok_or_else(invalid)?;
        if self.consumed || count == 0 || end > self.logical {
            return Err(invalid());
        }
        let start = self.position;
        while self.range_index + 1 < self.ranges.len() {
            let (offset, len) = self.ranges[self.range_index];
            if offset + len > start {
                break;
            }
            self.range_index += 1;
        }
        if self.ranges[self.range_index].0 >= end {
            self.position = end;
            return Ok(false);
        }
        buffer.resize(count, 0);
        buffer.fill(0);
        while self.range_index + 1 < self.ranges.len() {
            let (offset, len) = self.ranges[self.range_index];
            if offset >= end {
                break;
            }
            let from = offset.max(self.position);
            let to = (offset + len).min(end);
            if from < to {
                self.source
                    .read_exact(&mut buffer[(from - start) as usize..(to - start) as usize])?;
                self.position = to;
            }
            if to == offset + len {
                self.range_index += 1;
            } else {
                break;
            }
        }
        self.position = end;
        Ok(true)
    }

    /// Require the runtime's success reply after the complete sparse RAM
    /// payload. A stored checkpoint must call this before publishing its index.
    pub fn finish_sparse(&mut self) -> io::Result<()> {
        if self.consumed || self.position != self.logical {
            return Err(invalid());
        }
        self.consumed = true;
        self.read_completion_reply()
    }

    fn read_completion_reply(&mut self) -> io::Result<()> {
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

    pub(crate) fn append<W: Write>(&mut self, archive: &mut tar::Builder<W>) -> io::Result<()> {
        if self.consumed || self.position != 0 {
            return Err(invalid());
        }
        self.consumed = true;
        // Sorted, disjoint ranges were checked against logical length above;
        // the last is the terminal `(logical, 0)` entry. The archive lists
        // them widened to whole aligned blocks, the widening written as the
        // zeros the runtime left out, so a fragmented map stays a few runs.
        let mut header = tar::Header::new_gnu();
        header.set_path("checkpoint/memory.bin")?;
        header.set_mode(0o600);
        let data = &self.ranges[..self.ranges.len() - 1];
        let blocks = crate::assets::align_ranges(data, crate::assets::RAM_BLOCK, self.logical);
        let stored =
            crate::assets::write_sparse_header(archive.get_mut(), header, self.logical, &blocks)?;
        let mut copy = self.copy.take();
        let mut buffer = vec![0; 1024 * 1024];
        let zeros = vec![0; 1024 * 1024];
        let mut data = data.iter().peekable();
        for &(block, block_len) in &blocks {
            let mut position = block;
            let end = block + block_len;
            while position < end {
                // The runtime's next range, if it starts inside this block run.
                let (offset, len) = match data.peek() {
                    Some(&&(offset, len)) if offset < end => (offset, len),
                    _ => (end, 0),
                };
                if position < offset {
                    let gap = (offset - position).min(zeros.len() as u64) as usize;
                    archive.get_mut().write_all(&zeros[..gap])?;
                    position += gap as u64;
                    continue;
                }
                if len > 0 && !self.copy_failed {
                    if let Some(copy) = copy.as_mut() {
                        self.copy_failed = copy.seek(SeekFrom::Start(offset)).is_err();
                    }
                }
                let mut left = len;
                while left > 0 {
                    let chunk = left.min(buffer.len() as u64) as usize;
                    self.source.read_exact(&mut buffer[..chunk])?;
                    archive.get_mut().write_all(&buffer[..chunk])?;
                    if let Some(copy) = copy.as_mut().filter(|_| !self.copy_failed) {
                        self.copy_failed = copy.write_all(&buffer[..chunk]).is_err();
                    }
                    left -= chunk as u64;
                }
                position = offset + len;
                data.next();
            }
        }
        if data.next().is_some() {
            return Err(invalid());
        }
        if let Some(copy) = copy {
            if !self.copy_failed {
                self.copy_failed = copy.set_len(self.logical).is_err();
            }
            self.copy = Some(copy);
        }
        let padding = (512 - stored % 512) % 512;
        archive.get_mut().write_all(&[0; 512][..padding as usize])?;
        self.read_completion_reply()
    }
}

#[cfg(test)]
#[path = "checkpoint_stream_tests.rs"]
mod tests;
