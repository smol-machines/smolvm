//! A bounded terminal session; dropping it closes the CLI connection, not the VM.
use crate::runtime::Runtime;
use portable_pty::{CommandBuilder, PtySize};
use std::{
    io::{Read, Write},
    num::NonZeroU16,
    sync::{Arc, Mutex, mpsc},
    thread,
};

pub struct TerminalState {
    pub parser: vt100::Parser,
    pub status: String,
    pub exited: bool,
    pub revision: u64,
}
enum Input {
    Bytes(Vec<u8>),
    Resize(u16, u16),
}
pub struct Terminal {
    pub state: Arc<Mutex<TerminalState>>,
    input: Option<mpsc::SyncSender<Input>>,
    stop: Option<mpsc::Sender<()>>,
}
fn nz(v: u16) -> NonZeroU16 {
    NonZeroU16::new(v.max(1)).unwrap()
}
impl Terminal {
    pub fn start(runtime: Runtime, name: String, wake: impl Fn() + Send + Sync + 'static) -> Self {
        let mut command = CommandBuilder::new(runtime.executable);
        if let Some(path) = runtime.state_dir {
            command.env("SMOLVM_DATA_DIR", &path);
            #[cfg(target_os = "linux")]
            {
                command.env("XDG_DATA_HOME", path.join("data"));
                command.env("XDG_CONFIG_HOME", path.join("config"));
                command.env("XDG_CACHE_HOME", path.join("cache"));
            }
        }
        command.args([
            "machine", "exec", "--local", "--name", &name, "-it", "--", "/bin/sh", "-l",
        ]);
        command.env("TERM", "xterm-256color");
        command.env("RUST_LOG", "error");
        Self::spawn(command, wake)
    }
    pub fn container(id: &str, wake: impl Fn() + Send + Sync + 'static) -> Result<Self, String> {
        crate::docker::validate_container_id(id)?;
        let mut command = CommandBuilder::new(crate::runtime::find_tool(if cfg!(windows) {
            "docker.exe"
        } else {
            "docker"
        }));
        command.args([
            "--context",
            "smol",
            "container",
            "exec",
            "-it",
            id,
            "/bin/sh",
        ]);
        command.env_remove("DOCKER_HOST");
        command.env_remove("DOCKER_CONTEXT");
        command.env("TERM", "xterm-256color");
        Ok(Self::spawn(command, wake))
    }
    fn spawn(command: CommandBuilder, wake: impl Fn() + Send + Sync + 'static) -> Self {
        let state = Arc::new(Mutex::new(TerminalState {
            parser: vt100::Parser::new(nz(24), nz(80), 1000),
            status: "Connecting…".into(),
            exited: false,
            revision: 0,
        }));
        let (input, incoming) = mpsc::sync_channel(32);
        let (stop, stopped) = mpsc::channel();
        let view = state.clone();
        let wake = Arc::new(wake);
        thread::spawn(move || {
            let result = (|| -> Result<(), String> {
                let pair = portable_pty::native_pty_system()
                    .openpty(PtySize {
                        rows: 24,
                        cols: 80,
                        pixel_width: 0,
                        pixel_height: 0,
                    })
                    .map_err(|e| e.to_string())?;
                let mut reader = pair.master.try_clone_reader().map_err(|e| e.to_string())?;
                let mut writer = pair.master.take_writer().map_err(|e| e.to_string())?;
                let mut child = pair
                    .slave
                    .spawn_command(command)
                    .map_err(|e| format!("Cannot start terminal: {e}"))?;
                drop(pair.slave);
                view.lock().unwrap().status = "Connected".into();
                let read_view = view.clone();
                let read_wake = wake.clone();
                thread::spawn(move || {
                    let mut bytes = [0u8; 8192];
                    while let Ok(n) = reader.read(&mut bytes) {
                        if n == 0 {
                            break;
                        }
                        let mut state = read_view.lock().unwrap();
                        state.parser.process(&bytes[..n]);
                        state.revision = state.revision.wrapping_add(1);
                        drop(state);
                        read_wake();
                    }
                });
                let exit_view = view.clone();
                let exit_wake = wake.clone();
                thread::spawn(move || {
                    let result = loop {
                        match stopped.recv_timeout(std::time::Duration::from_millis(100)) {
                            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                                let _ = child.kill();
                                break child.wait();
                            }
                            Err(mpsc::RecvTimeoutError::Timeout) => match child.try_wait() {
                                Ok(Some(status)) => break Ok(status),
                                Ok(None) => {}
                                Err(e) => break Err(e),
                            },
                        }
                    };
                    let mut state = exit_view.lock().unwrap();
                    state.exited = true;
                    state.status = match result {
                        Ok(status) => format!("Shell exited ({})", status.exit_code()),
                        Err(e) => format!("Terminal disconnected: {e}"),
                    };
                    drop(state);
                    exit_wake();
                });
                wake();
                while let Ok(input) = incoming.recv() {
                    match input {
                        Input::Bytes(bytes) => {
                            writer.write_all(&bytes).map_err(|e| e.to_string())?;
                            writer.flush().map_err(|e| e.to_string())?;
                        }
                        Input::Resize(rows, cols) => {
                            pair.master
                                .resize(PtySize {
                                    rows,
                                    cols,
                                    pixel_width: 0,
                                    pixel_height: 0,
                                })
                                .map_err(|e| e.to_string())?;
                            let mut state = view.lock().unwrap();
                            state.parser.set_size(nz(rows), nz(cols));
                            state.revision = state.revision.wrapping_add(1);
                        }
                    }
                }
                Ok(())
            })();
            if let Err(error) = result {
                let mut state = view.lock().unwrap();
                state.status = error;
                state.exited = true;
                drop(state);
                wake();
            }
        });
        Self {
            state,
            input: Some(input),
            stop: Some(stop),
        }
    }
    pub fn input(&self, bytes: Vec<u8>) -> Result<(), String> {
        if bytes.len() > 16 * 1024 {
            return Err("Paste is limited to 16 KiB at a time.".into());
        }
        self.input
            .as_ref()
            .ok_or("Terminal closed")?
            .try_send(Input::Bytes(bytes))
            .map_err(|_| "Terminal input is busy. Try again.".into())
    }
    pub fn resize(&self, rows: u16, cols: u16) -> bool {
        self.input.as_ref().is_some_and(|sender| {
            sender
                .try_send(Input::Resize(rows.clamp(2, 100), cols.clamp(10, 240)))
                .is_ok()
        })
    }
}
impl Drop for Terminal {
    fn drop(&mut self) {
        self.input.take();
        self.stop.take();
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn terminal_parser_bounds_history_and_handles_unicode_and_escape_sequences() {
        let mut parser = vt100::Parser::new(nz(4), nz(20), 10);
        parser.process("\x1b[31m世界\x1b[0m".as_bytes());
        assert!(parser.screen().contents().contains("世界"));
        for _ in 0..100 {
            parser.process(b"line\r\n");
        }
        assert!(parser.screen().scrollback_len() <= 10);
    }
    #[test]
    #[cfg(unix)]
    fn native_pty_accepts_input_resizes_and_reports_exit() {
        let mut command = CommandBuilder::new("/bin/sh");
        command.args([
            "-c",
            "read answer; printf 'received:%s' \"$answer\"; exit 7",
        ]);
        let terminal = Terminal::spawn(command, || {});
        assert!(terminal.resize(30, 90));
        terminal.input(b"hello\n".to_vec()).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let state = terminal.state.lock().unwrap();
            if state.exited && state.parser.screen().contents().contains("received:hello") {
                assert!(state.status.contains('7'));
                break;
            }
            drop(state);
            assert!(std::time::Instant::now() < deadline);
            thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}
