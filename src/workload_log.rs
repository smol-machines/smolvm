//! Host side of a machine's workload log.
//!
//! The guest agent forwards a detached workload's stdout and stderr over the
//! `WORKLOAD_LOGS` vsock port, which libkrun bridges to a Unix socket in the
//! machine's directory. The boot process listens there for the machine's
//! whole life and appends what arrives to `workload.log` beside it, rotating
//! the file by size, so the log outlives the machine's process and is readable
//! while the machine is stopped.

use crate::platform::uds::{UdsListener, UdsStream};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// File name of the workload log in a machine's data directory.
pub const WORKLOAD_LOG_FILE: &str = "workload.log";

/// Path of the workload log for the machine whose data directory is `dir`.
pub fn workload_log_path(dir: &Path) -> PathBuf {
    dir.join(WORKLOAD_LOG_FILE)
}

/// Listen on `socket_path` and append everything the guest sends to `log`.
pub fn start(socket_path: &Path, log: &Path) -> io::Result<()> {
    let _ = std::fs::remove_file(socket_path);
    let listener = UdsListener::bind(socket_path)?;
    let writer = Arc::new(Mutex::new(LogWriter::open(log)?));
    std::thread::Builder::new()
        .name("workload-log".into())
        .spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        let writer = Arc::clone(&writer);
                        // A connection lasts until the guest drops it; a
                        // restored or reconnecting guest opens another.
                        let spawned = std::thread::Builder::new()
                            .name("workload-log-conn".into())
                            .spawn(move || copy_into(stream, &writer));
                        if let Err(e) = spawned {
                            tracing::warn!(error = %e, "could not serve a workload log connection");
                        }
                    }
                    Err(e) => tracing::debug!(error = %e, "workload log accept failed"),
                }
            }
        })?;
    Ok(())
}

fn copy_into(mut stream: UdsStream, writer: &Mutex<LogWriter>) {
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = match stream.read(&mut buffer) {
            Ok(0) => return,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return,
        };
        let mut writer = writer.lock().unwrap_or_else(|e| e.into_inner());
        if let Err(e) = writer.append(&buffer[..read]) {
            tracing::warn!(error = %e, "writing the workload log failed");
        }
    }
}

/// Appends to a log file and rotates it by size.
struct LogWriter {
    path: PathBuf,
    file: File,
}

impl LogWriter {
    fn open(path: &Path) -> io::Result<Self> {
        Ok(Self {
            path: path.to_path_buf(),
            file: OpenOptions::new().create(true).append(true).open(path)?,
        })
    }

    fn append(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.file.write_all(bytes)?;
        // Rotation copies the file aside and truncates it in place, so this
        // append-mode handle keeps writing to the live file.
        crate::log_rotation::rotate_if_needed(&self.path)?;
        Ok(())
    }
}

/// The last `lines` lines of the workload log, reaching into rotated files
/// when the live one is shorter.
pub fn tail(log: &Path, lines: usize) -> io::Result<Vec<u8>> {
    if lines == 0 {
        return Ok(Vec::new());
    }
    let mut files = vec![log.to_path_buf()];
    for n in 1..=crate::log_rotation::MAX_LOG_FILES {
        files.push(PathBuf::from(format!("{}.{n}", log.display())));
    }
    // Newest first; prepend older content until enough lines are collected.
    let mut collected: Vec<u8> = Vec::new();
    for path in files {
        let content = match std::fs::read(&path) {
            Ok(content) => content,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        let mut joined = content;
        joined.extend_from_slice(&collected);
        collected = joined;
        if count_lines(&collected) > lines {
            break;
        }
    }
    Ok(last_lines(&collected, lines).to_vec())
}

/// The whole workload log, oldest rotated file first.
pub fn read_all(log: &Path) -> io::Result<Vec<u8>> {
    let mut all = Vec::new();
    for n in (1..=crate::log_rotation::MAX_LOG_FILES).rev() {
        match std::fs::read(format!("{}.{n}", log.display())) {
            Ok(content) => all.extend_from_slice(&content),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    match std::fs::read(log) {
        Ok(content) => all.extend_from_slice(&content),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    Ok(all)
}

/// Write what is appended to the workload log from byte `offset` on to `out`
/// as it arrives, until `done` returns true. A rotation (the live file
/// shrinking) restarts from its beginning.
pub fn follow(
    log: &Path,
    mut offset: u64,
    out: &mut impl Write,
    poll: std::time::Duration,
    done: impl Fn() -> bool,
) -> io::Result<()> {
    use std::io::{Seek, SeekFrom};
    let mut buffer = vec![0u8; 64 * 1024];
    while !done() {
        let len = std::fs::metadata(log).map(|m| m.len()).unwrap_or(0);
        if len < offset {
            offset = 0;
        }
        if len > offset {
            let mut file = File::open(log)?;
            file.seek(SeekFrom::Start(offset))?;
            loop {
                let read = file.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                out.write_all(&buffer[..read])?;
                offset += read as u64;
            }
            out.flush()?;
        }
        std::thread::sleep(poll);
    }
    Ok(())
}

fn count_lines(bytes: &[u8]) -> usize {
    let newlines = bytes.iter().filter(|b| **b == b'\n').count();
    newlines + usize::from(bytes.last().is_some_and(|b| *b != b'\n'))
}

fn last_lines(bytes: &[u8], lines: usize) -> &[u8] {
    // Ignore a trailing newline so it does not count as an empty last line.
    let body = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let mut seen = 0;
    for (i, byte) in body.iter().enumerate().rev() {
        if *byte == b'\n' {
            seen += 1;
            if seen == lines {
                return &bytes[i + 1..];
            }
        }
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn wait_for(path: &Path, expected: &str) {
        let started = Instant::now();
        loop {
            let content = std::fs::read_to_string(path).unwrap_or_default();
            if content == expected {
                return;
            }
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "log is {content:?}, expected {expected:?}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn output_from_successive_connections_is_appended_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("wl.sock");
        let log = workload_log_path(dir.path());
        std::fs::write(&log, "from an earlier start\n").unwrap();
        start(&socket, &log).unwrap();

        let mut first = UdsStream::connect(&socket).unwrap();
        first.write_all(b"one\n").unwrap();
        wait_for(&log, "from an earlier start\none\n");
        drop(first);
        // A guest that reconnects (as after a restore) keeps appending.
        let mut second = UdsStream::connect(&socket).unwrap();
        second.write_all(b"two\n").unwrap();
        wait_for(&log, "from an earlier start\none\ntwo\n");
    }

    #[test]
    fn read_all_joins_rotated_files_oldest_first() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("workload.log");
        assert!(read_all(&log).unwrap().is_empty());
        std::fs::write(format!("{}.2", log.display()), "a\n").unwrap();
        std::fs::write(format!("{}.1", log.display()), "b\n").unwrap();
        std::fs::write(&log, "c\n").unwrap();
        assert_eq!(read_all(&log).unwrap(), b"a\nb\nc\n");
    }

    #[test]
    fn follow_streams_appends_and_survives_rotation() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("workload.log");
        std::fs::write(&log, "old\n").unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let out = Arc::new(Mutex::new(Vec::new()));
        struct Shared(Arc<Mutex<Vec<u8>>>);
        impl Write for Shared {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let follower = {
            let (log, stop) = (log.clone(), Arc::clone(&stop));
            let mut sink = Shared(Arc::clone(&out));
            std::thread::spawn(move || {
                follow(&log, 4, &mut sink, Duration::from_millis(5), || {
                    stop.load(Ordering::SeqCst)
                })
                .unwrap();
            })
        };
        let wait_out = |expected: &[u8]| {
            let started = Instant::now();
            while out.lock().unwrap().as_slice() != expected {
                assert!(
                    started.elapsed() < Duration::from_secs(5),
                    "{:?}",
                    String::from_utf8_lossy(&out.lock().unwrap())
                );
                std::thread::sleep(Duration::from_millis(5));
            }
        };
        OpenOptions::new()
            .append(true)
            .open(&log)
            .unwrap()
            .write_all(b"new\n")
            .unwrap();
        wait_out(b"new\n");
        // Rotation truncates the live file; following picks up from its start.
        std::fs::write(&log, "").unwrap();
        std::thread::sleep(Duration::from_millis(30));
        OpenOptions::new()
            .append(true)
            .open(&log)
            .unwrap()
            .write_all(b"after\n")
            .unwrap();
        wait_out(b"new\nafter\n");
        stop.store(true, Ordering::SeqCst);
        follower.join().unwrap();
    }

    #[test]
    fn tail_returns_the_last_lines_across_rotated_files() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("workload.log");
        std::fs::write(format!("{}.2", log.display()), "a\nb\n").unwrap();
        std::fs::write(format!("{}.1", log.display()), "c\nd\n").unwrap();
        std::fs::write(&log, "e\nf").unwrap();
        assert_eq!(tail(&log, 1).unwrap(), b"f");
        assert_eq!(tail(&log, 3).unwrap(), b"d\ne\nf");
        assert_eq!(tail(&log, 5).unwrap(), b"b\nc\nd\ne\nf");
        assert_eq!(tail(&log, 50).unwrap(), b"a\nb\nc\nd\ne\nf");
        assert_eq!(tail(&log, 0).unwrap(), b"");
        std::fs::write(&log, "e\nf\n").unwrap();
        assert_eq!(tail(&log, 2).unwrap(), b"e\nf\n");
        assert!(tail(&dir.path().join("missing.log"), 3).unwrap().is_empty());
    }
}
