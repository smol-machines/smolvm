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
    pub(crate) fn write(&mut self, stream: u8, data: &[u8]) {
        let idx = (stream as usize).min(2);
        if self.tty {
            // A terminal's output is not line-structured; log it as it comes.
            self.entry(stream, data);
            return;
        }
        let mut buf = std::mem::take(&mut self.partial[idx]);
        buf.extend_from_slice(data);
        let mut start = 0;
        while let Some(pos) = buf[start..].iter().position(|b| *b == b'\n') {
            let end = start + pos + 1;
            self.entry(stream, &buf[start..end]);
            start = end;
        }
        let mut rest = buf.split_off(start);
        while rest.len() >= MAX_ENTRY {
            let tail = rest.split_off(MAX_ENTRY);
            self.entry(stream, &rest);
            rest = tail;
        }
        self.partial[idx] = rest;
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
