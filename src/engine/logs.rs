//! Container logs, in Docker's `json-file` format: one JSON object per line
//! of output, `{"log": "...", "stream": "stdout", "time": "..."}`.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Longest line kept as one entry before it is split, as Docker does.
const MAX_ENTRY: usize = 16 * 1024;

/// One logged piece of output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Entry {
    pub log: String,
    pub stream: String,
    pub time: String,
}

/// Appends a running container's output to its log.
pub(crate) struct LogWriter {
    file: std::fs::File,
    tty: bool,
    partial: [Vec<u8>; 3],
}

impl LogWriter {
    pub(crate) fn open(path: &Path, tty: bool) -> std::io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Self {
            file,
            tty,
            partial: Default::default(),
        })
    }

    /// Log `data` written on `stream` (1 stdout, 2 stderr). Complete lines
    /// are logged at once; a trailing partial line waits for its end.
    pub(crate) fn write(&mut self, stream: u8, mut data: &[u8]) {
        let idx = (stream as usize).min(2);
        if self.tty {
            // A terminal's output is not line-structured; log it as it comes.
            self.entry(stream, data);
            return;
        }
        let mut partial = std::mem::take(&mut self.partial[idx]);
        while !data.is_empty() {
            let take = data.len().min(MAX_ENTRY - partial.len());
            let end = data[..take]
                .iter()
                .position(|b| *b == b'\n')
                .map_or(take, |pos| pos + 1);
            let piece = &data[..end];
            data = &data[end..];
            let complete = piece.last() == Some(&b'\n') || partial.len() + end == MAX_ENTRY;
            if partial.is_empty() && complete {
                // Complete entries can be logged directly from the input;
                // only an unfinished line needs an owned buffer.
                self.entry(stream, piece);
            } else {
                partial.extend_from_slice(piece);
                if complete {
                    self.entry(stream, &partial);
                    partial.clear();
                }
            }
        }
        self.partial[idx] = partial;
    }

    /// Log whatever partial lines are left, at the process's exit.
    pub(crate) fn flush(&mut self) {
        for stream in [1u8, 2] {
            let rest = std::mem::take(&mut self.partial[stream as usize]);
            if !rest.is_empty() {
                self.entry(stream, &rest);
            }
        }
        let _ = self.file.flush();
    }

    fn entry(&mut self, stream: u8, data: &[u8]) {
        let entry = Entry {
            log: String::from_utf8_lossy(data).into_owned(),
            stream: if stream == 2 { "stderr" } else { "stdout" }.into(),
            time: super::util::now_rfc3339(),
        };
        if let Ok(mut line) = serde_json::to_vec(&entry) {
            line.push(b'\n');
            let _ = self.file.write_all(&line);
        }
    }
}

/// What a `docker logs` request asks for.
#[derive(Debug, Clone, Default)]
pub(crate) struct LogQuery {
    pub stdout: bool,
    pub stderr: bool,
    pub since: Option<std::time::SystemTime>,
    pub until: Option<std::time::SystemTime>,
    pub timestamps: bool,
    /// Only the last `n` entries.
    pub tail: Option<usize>,
}

impl LogQuery {
    fn wants(&self, entry: &Entry) -> bool {
        let stream_ok = match entry.stream.as_str() {
            "stderr" => self.stderr,
            _ => self.stdout,
        };
        if !stream_ok {
            return false;
        }
        if self.since.is_some() || self.until.is_some() {
            let Ok(t) = humantime::parse_rfc3339_weak(&entry.time) else {
                return true;
            };
            if self.since.is_some_and(|s| t < s) || self.until.is_some_and(|u| t > u) {
                return false;
            }
        }
        true
    }
}

/// Entries already in the log at `path` that `query` asks for, and the byte
/// offset reading stopped at (to follow from).
pub(crate) fn read(path: &Path, query: &LogQuery) -> (Vec<Entry>, u64) {
    if let Some(n) = query.tail {
        return std::fs::File::open(path)
            .and_then(|mut file| read_tail(&mut file, query, n))
            .unwrap_or_default();
    }
    let Ok(bytes) = std::fs::read(path) else {
        return (Vec::new(), 0);
    };
    let complete = bytes
        .iter()
        .rposition(|b| *b == b'\n')
        .map(|p| p + 1)
        .unwrap_or(0);
    let mut entries: Vec<Entry> = bytes[..complete]
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .filter_map(|l| serde_json::from_slice::<Entry>(l).ok())
        .filter(|e| query.wants(e))
        .collect();
    if let Some(n) = query.tail {
        let skip = entries.len().saturating_sub(n);
        entries.drain(..skip);
    }
    (entries, complete as u64)
}

// Scan a snapshot backwards, retaining only one record and the requested
// matching entries. An unfinished last record stays available to read_from.
fn read_tail<R: std::io::Read + std::io::Seek>(
    file: &mut R,
    query: &LogQuery,
    n: usize,
) -> std::io::Result<(Vec<Entry>, u64)> {
    use std::io::SeekFrom;
    let mut position = file.seek(SeekFrom::End(0))?;
    let mut block = [0u8; 64 * 1024];
    let mut complete = None;
    let mut reversed = Vec::new();
    let mut entries = Vec::new();
    while position > 0 {
        let count = position.min(block.len() as u64) as usize;
        position -= count as u64;
        file.seek(SeekFrom::Start(position))?;
        file.read_exact(&mut block[..count])?;
        for (i, &byte) in block[..count].iter().enumerate().rev() {
            if complete.is_none() {
                if byte == b'\n' {
                    complete = Some(position + i as u64 + 1);
                    if n == 0 {
                        return Ok((entries, complete.unwrap()));
                    }
                }
                continue;
            }
            if byte == b'\n' {
                take_reversed_entry(&mut reversed, query, &mut entries);
                if entries.len() == n {
                    entries.reverse();
                    return Ok((entries, complete.unwrap()));
                }
            } else {
                reversed.push(byte);
            }
        }
    }
    take_reversed_entry(&mut reversed, query, &mut entries);
    entries.reverse();
    Ok((entries, complete.unwrap_or(0)))
}

fn take_reversed_entry(bytes: &mut Vec<u8>, query: &LogQuery, entries: &mut Vec<Entry>) {
    bytes.reverse();
    if let Ok(entry) = serde_json::from_slice::<Entry>(bytes) {
        if query.wants(&entry) {
            entries.push(entry);
        }
    }
    bytes.clear();
}

/// Entries appended to the log after `offset`, and the new offset.
pub(crate) fn read_from(path: &Path, offset: u64, query: &LogQuery) -> (Vec<Entry>, u64) {
    use std::io::{Read, Seek, SeekFrom};
    let Ok(mut file) = std::fs::File::open(path) else {
        return (Vec::new(), offset);
    };
    if file.seek(SeekFrom::Start(offset)).is_err() {
        return (Vec::new(), offset);
    }
    let mut bytes = Vec::new();
    if file.read_to_end(&mut bytes).is_err() {
        return (Vec::new(), offset);
    }
    let complete = bytes
        .iter()
        .rposition(|b| *b == b'\n')
        .map(|p| p + 1)
        .unwrap_or(0);
    let entries = bytes[..complete]
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .filter_map(|l| serde_json::from_slice::<Entry>(l).ok())
        .filter(|e| query.wants(e))
        .collect();
    (entries, offset + complete as u64)
}

/// The bytes a client receives for `entry`: a multiplexed frame (unless the
/// container has a TTY), with a timestamp prefix when asked.
pub(crate) fn encode(entry: &Entry, query: &LogQuery, tty: bool) -> Vec<u8> {
    let mut payload = Vec::with_capacity(entry.log.len() + 40);
    if query.timestamps {
        payload.extend_from_slice(entry.time.as_bytes());
        payload.push(b' ');
    }
    payload.extend_from_slice(entry.log.as_bytes());
    if tty {
        payload
    } else {
        super::stream::frame(if entry.stream == "stderr" { 2 } else { 1 }, &payload)
    }
}

/// The log path of a container, given the engine's store.
pub(crate) fn path(store: &super::store::Store, id: &str) -> PathBuf {
    store.container_log(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_are_split_and_partials_wait() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c-json.log");
        let mut w = LogWriter::open(&path, false).unwrap();
        w.write(1, b"one\ntw");
        w.write(2, b"err\n");
        w.write(1, b"o\n");
        w.write(1, b"tail");
        w.flush();
        let all = LogQuery {
            stdout: true,
            stderr: true,
            ..Default::default()
        };
        let (entries, _) = read(&path, &all);
        let logs: Vec<_> = entries
            .iter()
            .map(|e| (e.stream.as_str(), e.log.as_str()))
            .collect();
        assert_eq!(
            logs,
            [
                ("stdout", "one\n"),
                ("stderr", "err\n"),
                ("stdout", "two\n"),
                ("stdout", "tail")
            ]
        );
        let only_err = LogQuery {
            stderr: true,
            ..Default::default()
        };
        assert_eq!(read(&path, &only_err).0.len(), 1);
        let tail = LogQuery {
            tail: Some(2),
            ..all.clone()
        };
        assert_eq!(read(&path, &tail).0[0].log, "two\n");
    }

    #[test]
    fn long_lines_have_the_same_entries_for_every_input_chunk_size() {
        let mut output = b"first\n".to_vec();
        output.extend(vec![b'x'; MAX_ENTRY * 3 + 7]);
        output.extend_from_slice(b"\nlast");
        let expected = vec![
            "first\n".to_string(),
            "x".repeat(MAX_ENTRY),
            "x".repeat(MAX_ENTRY),
            "x".repeat(MAX_ENTRY),
            "xxxxxxx\n".to_string(),
            "last".to_string(),
        ];
        for chunk_size in [1, 4096, MAX_ENTRY, 64 * 1024] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("c-json.log");
            let mut writer = LogWriter::open(&path, false).unwrap();
            for chunk in output.chunks(chunk_size) {
                writer.write(1, chunk);
                assert!(writer.partial[1].len() < MAX_ENTRY);
            }
            writer.flush();
            let query = LogQuery {
                stdout: true,
                ..Default::default()
            };
            let logs: Vec<_> = read(&path, &query).0.into_iter().map(|e| e.log).collect();
            assert_eq!(logs, expected, "input chunk size {chunk_size}");
        }
    }

    #[test]
    fn reverse_tail_matches_forward_filtering_across_blocks_and_partial_records() {
        use std::io::Cursor;
        let mut bytes = Vec::new();
        for i in 0..1500 {
            let entry = Entry {
                log: format!("{i}: {}\n", "λ".repeat(i % 113)),
                stream: if i % 3 == 0 { "stderr" } else { "stdout" }.into(),
                time: if i % 2 == 0 {
                    "2026-01-01T00:00:00Z"
                } else {
                    "2026-01-02T00:00:00Z"
                }
                .into(),
            };
            serde_json::to_writer(&mut bytes, &entry).unwrap();
            bytes.push(b'\n');
            if i % 17 == 0 {
                bytes.extend_from_slice(b"invalid\n\n");
            }
        }
        let complete = bytes.len() as u64;
        bytes.extend_from_slice(b"{\"log\":\"unfinished");
        for stdout in [false, true] {
            for stderr in [false, true] {
                for since in [
                    None,
                    Some(humantime::parse_rfc3339("2026-01-02T00:00:00Z").unwrap()),
                ] {
                    let query = LogQuery {
                        stdout,
                        stderr,
                        since,
                        ..Default::default()
                    };
                    let expected: Vec<Entry> = bytes[..complete as usize]
                        .split(|b| *b == b'\n')
                        .filter_map(|line| serde_json::from_slice::<Entry>(line).ok())
                        .filter(|e| query.wants(e))
                        .collect();
                    for n in [0, 1, 100, 2000, usize::MAX] {
                        let (actual, offset) =
                            read_tail(&mut Cursor::new(&bytes), &query, n).unwrap();
                        assert_eq!(offset, complete);
                        assert_eq!(
                            serde_json::to_value(actual).unwrap(),
                            serde_json::to_value(&expected[expected.len().saturating_sub(n)..])
                                .unwrap()
                        );
                    }
                }
            }
        }
        for input in [b"".as_slice(), b"unfinished", b"\n", b"invalid\n"] {
            assert!(read_tail(&mut Cursor::new(input), &LogQuery::default(), 1)
                .unwrap()
                .0
                .is_empty());
        }
    }

    #[test]
    fn short_tail_reads_only_the_last_block_of_a_large_log() {
        use std::io::{Cursor, Read, Seek, SeekFrom};
        struct Counted {
            inner: Cursor<Vec<u8>>,
            bytes: usize,
        }
        impl Read for Counted {
            fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
                let n = self.inner.read(out)?;
                self.bytes += n;
                Ok(n)
            }
        }
        impl Seek for Counted {
            fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
                self.inner.seek(position)
            }
        }
        let entry =
            b"{\"log\":\"hello\\n\",\"stream\":\"stdout\",\"time\":\"2026-01-01T00:00:00Z\"}\n";
        let mut file = Counted {
            inner: Cursor::new(entry.repeat(100_000)),
            bytes: 0,
        };
        let query = LogQuery {
            stdout: true,
            ..Default::default()
        };
        assert_eq!(read_tail(&mut file, &query, 100).unwrap().0.len(), 100);
        assert_eq!(file.bytes, 64 * 1024);
    }

    #[test]
    fn frames_carry_the_stream_and_length() {
        let e = Entry {
            log: "hi\n".into(),
            stream: "stderr".into(),
            time: "2026-01-01T00:00:00Z".into(),
        };
        let q = LogQuery {
            timestamps: true,
            ..Default::default()
        };
        let framed = encode(&e, &q, false);
        assert_eq!(framed[0], 2);
        assert_eq!(&framed[4..8], &(24u32).to_be_bytes());
        assert!(framed.ends_with(b"2026-01-01T00:00:00Z hi\n"));
        assert_eq!(encode(&e, &LogQuery::default(), true), b"hi\n");
    }
}
