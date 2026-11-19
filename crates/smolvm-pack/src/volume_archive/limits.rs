//! Bound the tar parser before it allocates extensions or expands sparse files.
//!
//! Entry-level checks run too late: `tar::Entries::next` has already buffered
//! GNU/PAX names and built the sparse extent map. This reader validates the wire
//! framing first, retaining only a bounded extension and streaming file data.

use super::{invalid, PAX};
use std::io::{self, Read};

/// Per-volume allowances reserved by the destination before accepting a stream.
/// There is deliberately no unbounded/default import. A workload coordinator
/// must also reserve the sum across its volumes and concurrent transfers.
/// The format additionally bounds each PAX/GNU extension to 16 KiB, names to
/// 4096 bytes, ownership JSON to 1024 bytes and each sparse map to 1024 extension
/// blocks (at most 21,508 extents); unsupported input is refused, never flattened.
#[derive(Clone, Copy, Debug)]
pub struct ImportLimits {
    /// Entire tar stream, including headers, padding and trailing zero blocks.
    pub archive_bytes: u64,
    /// Sum of regular files' logical lengths, including sparse holes; hardlinks
    /// do not charge the same inode twice.
    pub logical_bytes: u64,
    /// Content headers, including the root directory and completion marker.
    pub entries: u64,
    /// All headers and extension bodies, including sparse extent headers.
    pub metadata_bytes: u64,
}

const MAX_EXTENSION_BYTES: u64 = 16 * 1024;
const MAX_PATH_BYTES: usize = 4096;
const MAX_SPARSE_EXTENSIONS: u32 = 1024;

#[derive(Clone, Copy)]
enum Frame {
    Header,
    Sparse { data: u64, extensions: u32 },
    Data(u64),
    Trailer,
}

pub(super) struct BoundedTar<R> {
    input: R,
    limits: ImportLimits,
    bytes: u64,
    metadata: u64,
    entries: u64,
    logical: u64,
    frame: Frame,
    pending: Vec<u8>,
    position: usize,
}

fn charge(total: &mut u64, amount: u64, limit: u64, kind: &str) -> io::Result<()> {
    *total = total
        .checked_add(amount)
        .filter(|value| *value <= limit)
        .ok_or_else(|| invalid(format!("volume import exceeds {kind} limit")))?;
    Ok(())
}

fn padded(size: u64) -> io::Result<u64> {
    size.checked_add(511)
        .map(|size| size & !511)
        .ok_or_else(|| invalid("volume entry size overflow"))
}

impl<R: Read> BoundedTar<R> {
    pub(super) fn new(input: R, limits: ImportLimits) -> Self {
        Self {
            input,
            limits,
            bytes: 0,
            metadata: 0,
            entries: 0,
            logical: 0,
            frame: Frame::Header,
            pending: Vec::new(),
            position: 0,
        }
    }

    fn exact(&mut self, bytes: &mut [u8]) -> io::Result<()> {
        charge(
            &mut self.bytes,
            bytes.len() as u64,
            self.limits.archive_bytes,
            "archive byte",
        )?;
        self.input.read_exact(bytes)
    }

    fn metadata(&mut self, amount: u64) -> io::Result<()> {
        charge(
            &mut self.metadata,
            amount,
            self.limits.metadata_bytes,
            "metadata byte",
        )
    }

    fn header(&mut self) -> io::Result<()> {
        let mut bytes = [0; 512];
        self.exact(&mut bytes)?;
        self.pending.extend_from_slice(&bytes);
        if bytes == [0; 512] {
            self.frame = Frame::Trailer;
            return Ok(());
        }
        self.metadata(512)?;
        let header = tar::Header::from_byte_slice(&bytes);
        let checksum: u32 = bytes[..148]
            .iter()
            .chain(&bytes[156..])
            .map(|b| u32::from(*b))
            .sum::<u32>()
            + 8 * 32;
        if header.cksum()? != checksum {
            return Err(invalid("volume archive header checksum mismatch"));
        }
        let kind = header.entry_type();
        let size = header.entry_size()?;
        let data = padded(size)?;
        if data > self.limits.archive_bytes.saturating_sub(self.bytes) {
            return Err(invalid("volume import exceeds archive byte limit"));
        }
        if kind.is_pax_local_extensions() || kind.is_gnu_longname() || kind.is_gnu_longlink() {
            if header.as_gnu().is_none() && header.as_ustar().is_none() {
                return Err(invalid("unrecognized volume extension header"));
            }
            if size > MAX_EXTENSION_BYTES {
                return Err(invalid("volume archive extension is too large"));
            }
            self.metadata(data)?;
            let mut body = vec![0; data as usize];
            self.exact(&mut body)?;
            let value = &body[..size as usize];
            if kind.is_pax_local_extensions() {
                validate_pax(value)?;
            } else if value.strip_suffix(&[0]).unwrap_or(value).len() > MAX_PATH_BYTES {
                return Err(invalid("volume archive name is too long"));
            }
            self.pending.extend_from_slice(&body);
            self.frame = Frame::Header;
            return Ok(());
        }
        if !(kind.is_file()
            || kind.is_gnu_sparse()
            || kind.is_dir()
            || kind.is_symlink()
            || kind.is_hard_link())
        {
            return Err(invalid("unsupported volume archive entry type"));
        }
        charge(&mut self.entries, 1, self.limits.entries, "entry count")?;
        if kind.is_file() || kind.is_gnu_sparse() {
            charge(
                &mut self.logical,
                header.size()?,
                self.limits.logical_bytes,
                "logical byte",
            )?;
        } else if size != 0 {
            return Err(invalid("data attached to a volume link or directory"));
        }
        self.frame = if kind.is_gnu_sparse() && header.as_gnu().is_some_and(|h| h.is_extended()) {
            Frame::Sparse {
                data,
                extensions: 0,
            }
        } else {
            Frame::Data(data)
        };
        Ok(())
    }

    fn sparse(&mut self, data: u64, extensions: u32) -> io::Result<()> {
        if extensions >= MAX_SPARSE_EXTENSIONS {
            return Err(invalid("volume sparse extent map is too large"));
        }
        self.metadata(512)?;
        let mut header = tar::GnuExtSparseHeader::new();
        self.exact(header.as_mut_bytes())?;
        self.pending.extend_from_slice(header.as_bytes());
        self.frame = if header.is_extended() {
            Frame::Sparse {
                data,
                extensions: extensions + 1,
            }
        } else {
            Frame::Data(data)
        };
        Ok(())
    }

    /// The tar iterator stops at the first zero block. Consume the bounded
    /// remainder so appended data, a second archive or a truncated terminator
    /// cannot be accepted as part of a complete transfer.
    pub(super) fn finish(mut self) -> io::Result<()> {
        if !matches!(self.frame, Frame::Trailer) || self.position != self.pending.len() {
            return Err(invalid("missing volume archive terminator"));
        }
        let mut trailer = 512u64;
        let mut buffer = [0; 8192];
        loop {
            // One byte beyond the allowance distinguishes exact-size EOF from
            // an over-limit stream without draining attacker-controlled input.
            let available = self.limits.archive_bytes.saturating_sub(self.bytes);
            let len = available.min(buffer.len() as u64).max(1) as usize;
            let read = match self.input.read(&mut buffer[..len]) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => result?,
            };
            if read == 0 {
                break;
            }
            charge(
                &mut self.bytes,
                read as u64,
                self.limits.archive_bytes,
                "archive byte",
            )?;
            if buffer[..read].iter().any(|b| *b != 0) {
                return Err(invalid("data after volume archive terminator"));
            }
            trailer += read as u64;
        }
        if trailer < 1024 || !trailer.is_multiple_of(512) {
            return Err(invalid("incomplete volume archive terminator"));
        }
        Ok(())
    }
}

fn validate_pax(value: &[u8]) -> io::Result<()> {
    let mut keys = std::collections::BTreeSet::new();
    for extension in tar::PaxExtensions::new(value) {
        let extension = extension?;
        let key = extension.key_bytes();
        if !keys.insert(key) {
            return Err(invalid("duplicate volume archive extension"));
        }
        let limit = if key == PAX.as_bytes() {
            1024
        } else if matches!(key, b"path" | b"linkpath") {
            MAX_PATH_BYTES
        } else {
            // In particular, PAX size and GNU.sparse.* may not change the wire
            // framing or logical size checked before the parser sees it.
            return Err(invalid("unsupported volume archive extension"));
        };
        if extension.value_bytes().len() > limit {
            return Err(invalid("volume archive extension value is too large"));
        }
    }
    Ok(())
}

impl<R: Read> Read for BoundedTar<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            if self.position < self.pending.len() {
                let size = buffer.len().min(self.pending.len() - self.position);
                buffer[..size].copy_from_slice(&self.pending[self.position..self.position + size]);
                self.position += size;
                return Ok(size);
            }
            self.pending.clear();
            self.position = 0;
            match self.frame {
                Frame::Header => self.header()?,
                Frame::Sparse { data, extensions } => self.sparse(data, extensions)?,
                Frame::Data(0) => self.frame = Frame::Header,
                Frame::Data(remaining) => {
                    let size = remaining.min(buffer.len() as u64) as usize;
                    self.exact(&mut buffer[..size])?;
                    self.frame = Frame::Data(remaining - size as u64);
                    return Ok(size);
                }
                Frame::Trailer => return Ok(0),
            }
        }
    }
}
