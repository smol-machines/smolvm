//! A bounded Docker log connection owned by the visible log view.
use std::{
    collections::VecDeque,
    io::Read,
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex, mpsc},
    thread,
    time::Duration,
};

const MAX_BYTES: usize = 256 * 1024;
const MAX_LINES: usize = 2000;

#[derive(Clone, Debug, PartialEq)]
pub enum Status {
    Following,
    Finished(i32),
    Failed(String),
}

pub struct Snapshot {
    pub revision: u64,
    pub text: String,
    pub status: Status,
    pub discarded: bool,
}

struct State {
    bytes: VecDeque<u8>,
    lines: usize,
    revision: u64,
    status: Status,
    discarded: bool,
}
impl State {
    fn new() -> Self {
        Self {
            bytes: VecDeque::with_capacity(MAX_BYTES),
            lines: 0,
            revision: 1,
            status: Status::Following,
            discarded: false,
        }
    }
    fn remove_front(&mut self) {
        if self.bytes.pop_front() == Some(b'\n') {
            self.lines -= 1;
        }
        self.discarded = true;
    }
    fn append(&mut self, chunk: &[u8]) {
        for &byte in chunk {
            if self.bytes.len() == MAX_BYTES {
                self.remove_front();
            }
            self.bytes.push_back(byte);
            self.lines += usize::from(byte == b'\n');
            while self.lines > MAX_LINES {
                self.remove_front();
            }
        }
        // Byte eviction can cut a UTF-8 character; never leave its continuation
        // bytes at the beginning of an otherwise valid text stream.
        if self.discarded {
            while self.bytes.front().is_some_and(|b| b & 0xc0 == 0x80) {
                self.remove_front();
            }
        }
        self.revision = self.revision.wrapping_add(1);
    }
}

pub struct LogStream {
    state: Arc<Mutex<State>>,
    child: Arc<Mutex<Child>>,
    stop: Option<mpsc::Sender<()>>,
}

impl LogStream {
    pub fn container(id: &str, wake: impl Fn() + Send + Sync + 'static) -> Result<Self, String> {
        crate::docker::validate_container_id(id)?;
        let mut command = Command::new(crate::runtime::find_tool(if cfg!(windows) {
            "docker.exe"
        } else {
            "docker"
        }));
        command.args([
            "--context",
            "smol",
            "container",
            "logs",
            "--follow",
            "--tail",
            "200",
            id,
        ]);
        command.env_remove("DOCKER_HOST");
        command.env_remove("DOCKER_CONTEXT");
        command.env("NO_COLOR", "1");
        Self::spawn(command, wake)
    }

    fn spawn(
        mut command: Command,
        wake: impl Fn() + Send + Sync + 'static,
    ) -> Result<Self, String> {
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        let mut child = command
            .spawn()
            .map_err(|e| format!("Cannot follow container logs: {e}"))?;
        let stdout = child.stdout.take().expect("piped log stdout");
        let stderr = child.stderr.take().expect("piped log stderr");
        let state = Arc::new(Mutex::new(State::new()));
        let wake: Arc<dyn Fn() + Send + Sync> = Arc::new(wake);
        let out = read_pipe(stdout, state.clone(), wake.clone());
        let err = read_pipe(stderr, state.clone(), wake.clone());
        let child = Arc::new(Mutex::new(child));
        let monitor = child.clone();
        let view = state.clone();
        let (stop, stopped) = mpsc::channel();
        thread::spawn(move || {
            let status = loop {
                match stopped.recv_timeout(Duration::from_millis(100)) {
                    Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                        let mut child = monitor.lock().unwrap();
                        cancel(&mut child);
                        break child.wait();
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        match monitor.lock().unwrap().try_wait() {
                            Ok(Some(status)) => break Ok(status),
                            Ok(None) => {}
                            Err(error) => break Err(error),
                        }
                    }
                }
            };
            // Drain both streams before marking completion, including the last
            // bytes written just before a normal process exit.
            let _ = out.join();
            let _ = err.join();
            let mut state = view.lock().unwrap();
            if !matches!(state.status, Status::Failed(_)) {
                state.status = match status {
                    Ok(status) => Status::Finished(status.code().unwrap_or(-1)),
                    Err(error) => Status::Failed(format!("Log connection failed: {error}")),
                };
            }
            state.revision = state.revision.wrapping_add(1);
            drop(state);
            wake();
        });
        Ok(Self {
            state,
            child,
            stop: Some(stop),
        })
    }

    /// Unchanged output incurs no text allocation on a UI repaint.
    pub fn snapshot_after(&self, revision: u64) -> Option<Snapshot> {
        let mut state = self.state.lock().unwrap();
        if state.revision == revision {
            return None;
        }
        Some(Snapshot {
            revision: state.revision,
            status: state.status.clone(),
            discarded: state.discarded,
            text: String::from_utf8_lossy(state.bytes.make_contiguous()).into_owned(),
        })
    }
}

fn read_pipe(
    reader: impl Read + Send + 'static,
    state: Arc<Mutex<State>>,
    wake: Arc<dyn Fn() + Send + Sync>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut reader = reader;
        let mut bytes = [0u8; 8192];
        let mut pending_utf8 = Vec::with_capacity(8196);
        loop {
            match reader.read(&mut bytes) {
                Ok(0) => {
                    if !pending_utf8.is_empty() {
                        state.lock().unwrap().append("�".as_bytes());
                        wake();
                    }
                    break;
                }
                Ok(n) => {
                    append_utf8(&mut state.lock().unwrap(), &mut pending_utf8, &bytes[..n]);
                    wake();
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    let mut state = state.lock().unwrap();
                    state.status = Status::Failed(format!("Cannot read container logs: {error}"));
                    state.revision = state.revision.wrapping_add(1);
                    drop(state);
                    wake();
                    break;
                }
            }
        }
    })
}

// Each pipe keeps its own incomplete character so stderr cannot be inserted
// between the bytes of a Unicode character being read from stdout.
fn append_utf8(state: &mut State, pending: &mut Vec<u8>, chunk: &[u8]) {
    pending.extend_from_slice(chunk);
    let mut consumed = 0;
    while consumed < pending.len() {
        match std::str::from_utf8(&pending[consumed..]) {
            Ok(_) => {
                state.append(&pending[consumed..]);
                consumed = pending.len();
            }
            Err(error) => {
                let end = consumed + error.valid_up_to();
                if end > consumed {
                    state.append(&pending[consumed..end]);
                }
                match error.error_len() {
                    Some(length) => {
                        state.append("�".as_bytes());
                        consumed = end + length;
                    }
                    None => {
                        consumed = end;
                        break;
                    }
                }
            }
        }
    }
    pending.drain(..consumed);
}

fn cancel(child: &mut Child) {
    // Check the owned handle before signaling so a reaped/reused PID is never
    // targeted. A separate group also cleans up a CLI launcher on Unix.
    if matches!(child.try_wait(), Ok(None)) {
        #[cfg(unix)]
        if let Ok(pid) = i32::try_from(child.id()) {
            // SAFETY: process_group(0) assigned this child its own group.
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
        }
        let _ = child.kill();
    }
}

impl Drop for LogStream {
    fn drop(&mut self) {
        // Kill synchronously, reap on the monitor: leaving the view does not
        // block on pipe readers or leave a Docker CLI alive on application exit.
        cancel(&mut self.child.lock().unwrap());
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::time::Instant;

    #[test]
    fn retention_is_bounded_for_lines_and_unterminated_output() {
        let mut state = State::new();
        for _ in 0..MAX_LINES + 50 {
            state.append(b"old\n");
        }
        assert_eq!(state.lines, MAX_LINES);
        assert!(state.discarded);
        state.append(&vec![b'x'; MAX_BYTES * 3]);
        assert_eq!(state.bytes.len(), MAX_BYTES);
        assert_eq!(state.lines, 0);
        assert!(state.bytes.iter().all(|b| *b == b'x'));
    }

    #[test]
    fn split_unicode_reassembles_and_eviction_preserves_character_boundaries() {
        let mut state = State::new();
        state.append(&[0xe2, 0x82]);
        state.append(&[0xac, b'\n']);
        assert_eq!(
            std::str::from_utf8(state.bytes.make_contiguous()).unwrap(),
            "€\n"
        );
        for _ in 0..MAX_BYTES / 3 + 5 {
            state.append("€".as_bytes());
        }
        assert!(state.bytes.len() <= MAX_BYTES);
        assert!(std::str::from_utf8(state.bytes.make_contiguous()).is_ok());
    }

    #[test]
    fn interleaved_streams_do_not_split_unicode_characters() {
        let mut state = State::new();
        let mut stdout = vec![];
        let mut stderr = vec![];
        append_utf8(&mut state, &mut stdout, &[0xe2, 0x82]);
        append_utf8(&mut state, &mut stderr, b"diagnostic\n");
        append_utf8(&mut state, &mut stdout, &[0xac, b'\n']);
        assert_eq!(
            std::str::from_utf8(state.bytes.make_contiguous()).unwrap(),
            "diagnostic\n€\n"
        );
        assert!(stdout.is_empty());
        append_utf8(&mut state, &mut stdout, &[0xff, b'x']);
        assert!(
            std::str::from_utf8(state.bytes.make_contiguous())
                .unwrap()
                .ends_with("�x")
        );
    }

    #[cfg(unix)]
    #[test]
    fn incremental_output_drains_both_streams_and_records_exit() {
        let directory = tempfile::tempdir().unwrap();
        let signal = directory.path().join("continue");
        let mut command = Command::new("sh");
        command.env("STUDIO_LOG_TEST_SIGNAL", &signal);
        command.args(["-c", "printf first; while [ ! -f \"$STUDIO_LOG_TEST_SIGNAL\" ]; do sleep 0.01; done; printf second; printf diagnostic >&2; exit 7"]);
        let stream = LogStream::spawn(command, || {}).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut revision = 0;
        let mut saw_first_while_running = false;
        loop {
            if let Some(snapshot) = stream.snapshot_after(revision) {
                revision = snapshot.revision;
                if snapshot.text == "first" && snapshot.status == Status::Following {
                    saw_first_while_running = true;
                    std::fs::write(&signal, b"continue").unwrap();
                }
                if snapshot.status == Status::Finished(7) {
                    assert!(saw_first_while_running);
                    assert!(snapshot.text.contains("first"));
                    assert!(snapshot.text.contains("second"));
                    assert!(snapshot.text.contains("diagnostic"));
                    assert!(stream.snapshot_after(revision).is_none());
                    break;
                }
            }
            assert!(Instant::now() < deadline, "log process did not complete");
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[cfg(unix)]
    #[test]
    fn dropping_a_live_reader_kills_and_reaps_its_process() {
        let mut command = Command::new("sh");
        command.args(["-c", "echo ready; sleep 60"]);
        let stream = LogStream::spawn(command, || {}).unwrap();
        let child = stream.child.clone();
        let state = stream.state.clone();
        let deadline = Instant::now() + Duration::from_secs(5);
        while state.lock().unwrap().bytes.is_empty() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(10));
        }
        let start = Instant::now();
        drop(stream);
        assert!(start.elapsed() < Duration::from_secs(1));
        loop {
            if matches!(state.lock().unwrap().status, Status::Finished(_)) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "log reader did not drain after cancellation"
            );
            thread::sleep(Duration::from_millis(10));
        }
        assert!(child.lock().unwrap().try_wait().unwrap().is_some());
    }
}
