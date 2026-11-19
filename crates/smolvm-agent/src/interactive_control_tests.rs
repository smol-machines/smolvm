//! Exercise the actual framed session handler with an independent control RPC.
use crate::{handle_interactive_vm_exec, handle_request, WireStream};
use smolvm_protocol::{
    interactive_control::{Action, Request, Session},
    AgentRequest, AgentResponse,
};
use std::{
    io::{Read, Write},
    net::Shutdown,
    os::unix::net::UnixStream,
    sync::atomic::{AtomicU64, Ordering},
    thread::JoinHandle,
    time::{Duration, Instant},
};

struct Running {
    id: String,
    stream: UnixStream,
    worker: Option<JoinHandle<Result<(), String>>>,
}
impl Running {
    fn start(command: &str, tty: bool) -> Self {
        Self::with_terminal(command, tty.then(Default::default))
    }
    fn with_terminal(
        command: &str,
        terminal: Option<smolvm_protocol::interactive_control::Terminal>,
    ) -> Self {
        static SEQUENCE: AtomicU64 = AtomicU64::new(1);
        let id = format!("{:032x}", SEQUENCE.fetch_add(1, Ordering::Relaxed));
        let session = Session {
            id: id.clone(),
            command: vec!["sh".into(), "-c".into(), command.into()],
            builtin: None,
            env: vec![],
            workdir: None,
            timeout_ms: Some(5000),
            terminal,
            target: None,
            user: None,
        };
        let (mut agent, stream) = UnixStream::pair().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let worker = std::thread::spawn(move || {
            handle_interactive_vm_exec(
                &mut WireStream::new(&mut agent),
                AgentRequest::VmExecControlled { session },
            )
            .map_err(|e| e.to_string())
        });
        let mut result = Self {
            id,
            stream,
            worker: Some(worker),
        };
        assert!(matches!(result.read(), AgentResponse::Started));
        result
    }
    fn read(&mut self) -> AgentResponse {
        let mut header = [0; 4];
        self.stream.read_exact(&mut header).unwrap();
        let size = u32::from_be_bytes(header) as usize;
        assert!(size < 1024 * 1024);
        let mut bytes = vec![0; size];
        self.stream.read_exact(&mut bytes).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }
    fn control(&self, action: Action) -> AgentResponse {
        handle_request(
            AgentRequest::InteractiveControl {
                request: Request {
                    id: self.id.clone(),
                    action,
                },
            },
            None,
        )
    }
    fn finish(&mut self) -> (i32, Vec<u8>) {
        let mut output = vec![];
        loop {
            match self.read() {
                AgentResponse::Stdout { data } | AgentResponse::Stderr { data } => {
                    output.extend(data)
                }
                AgentResponse::Exited { exit_code, .. } => return (exit_code, output),
                response => panic!("unexpected response: {response:?}"),
            }
            assert!(output.len() < 16 * 1024 * 1024);
        }
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.stream.shutdown(Shutdown::Both);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[test]
fn interactive_control_fast_exit_preserves_output_and_status() {
    for _ in 0..25 {
        let mut session = Running::start("printf fast; exit 23", false);
        assert_eq!(session.finish(), (23, b"fast".to_vec()));
        assert!(matches!(
            session.control(Action::Signal { signal: 15 }),
            AgentResponse::Error { .. }
        ));
    }
}

#[test]
fn interactive_control_signal_bypasses_blocked_stdin() {
    let mut session = Running::start("exec sleep 5", false);
    let frame = smolvm_protocol::encode_message(&AgentRequest::Stdin {
        data: vec![b'x'; 256 * 1024],
    })
    .unwrap();
    let mut blocked = false;
    for _ in 0..32 {
        if let Err(error) = session.stream.write_all(&frame) {
            assert!(matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ));
            blocked = true;
            break;
        }
    }
    assert!(blocked, "fixture must fill the independent stdin stream");
    let start = Instant::now();
    assert!(matches!(
        session.control(Action::Signal { signal: 15 }),
        AgentResponse::Ok { .. }
    ));
    assert!(start.elapsed() < Duration::from_secs(1));
    assert_ne!(session.finish().0, 0);
    assert!(matches!(
        session.control(Action::Signal { signal: 15 }),
        AgentResponse::Error { .. }
    ));
}

#[test]
fn interactive_control_signal_bypasses_unread_output() {
    let mut session = Running::start("exec yes owned-output", false);
    // Let the bounded socket fill; output remains unread until after control.
    std::thread::sleep(Duration::from_millis(150));
    let start = Instant::now();
    assert!(matches!(
        session.control(Action::Signal { signal: 15 }),
        AgentResponse::Ok { .. }
    ));
    assert!(start.elapsed() < Duration::from_secs(1));
    let (code, output) = session.finish();
    assert_ne!(code, 0);
    assert!(!output.is_empty());
}

#[test]
fn interactive_control_resize_reaches_owned_terminal() {
    let mut session = Running::start(
        "stty -echo; printf ready; read value; stty size; exit 17",
        true,
    );
    let mut ready = vec![];
    while !ready.ends_with(b"ready") {
        match session.read() {
            AgentResponse::Stdout { data } => ready.extend(data),
            other => panic!("{other:?}"),
        }
    }
    assert!(matches!(
        session.control(Action::Resize { cols: 0, rows: 37 }),
        AgentResponse::Error { .. }
    ));
    assert!(matches!(
        session.control(Action::Resize {
            cols: 119,
            rows: 37
        }),
        AgentResponse::Ok { .. }
    ));
    session
        .stream
        .write_all(
            &smolvm_protocol::encode_message(&AgentRequest::Stdin {
                data: b"go\n".to_vec(),
            })
            .unwrap(),
        )
        .unwrap();
    let (code, output) = session.finish();
    assert_eq!(code, 17);
    assert!(String::from_utf8_lossy(&output).contains("37 119"));
    assert!(matches!(
        session.control(Action::Resize { cols: 80, rows: 24 }),
        AgentResponse::Error { .. }
    ));
}

#[test]
fn interactive_control_terminal_modes_apply_before_exec_and_custom_eof_works() {
    use smolvm_protocol::interactive_control::Terminal;
    let terminal = Terminal {
        cols: 113,
        rows: 31,
        modes: vec![(53, 0), (1, 24), (5, 5), (128, 9600), (129, 9600)],
    };
    let mut inspect = Running::with_terminal("stty size; stty -a", Some(terminal.clone()));
    let (code, output) = inspect.finish();
    assert_eq!(code, 0);
    let output = String::from_utf8_lossy(&output);
    assert!(output.starts_with("31 113"), "{output}");
    assert!(
        output.contains("-echo ")
            && output.contains("intr = ^X")
            && output.contains("eof = ^E")
            && output.contains("9600"),
        "{output}"
    );
    let mut session = Running::with_terminal("cat; exit 17", Some(terminal));
    for data in [b"unterminated".to_vec(), vec![]] {
        session
            .stream
            .write_all(&smolvm_protocol::encode_message(&AgentRequest::Stdin { data }).unwrap())
            .unwrap();
    }
    assert_eq!(session.finish(), (17, b"unterminated".to_vec()));
}

#[test]
fn interactive_control_raw_terminal_preserves_binary_bytes() {
    use smolvm_protocol::interactive_control::Terminal;
    let terminal = Terminal {
        cols: 80,
        rows: 24,
        modes: vec![(50, 0), (51, 0), (53, 0), (70, 0), (38, 0), (36, 0)],
    };
    let mut session = Running::with_terminal("head -c 256", Some(terminal));
    let data: Vec<u8> = (0..=255).collect();
    session
        .stream
        .write_all(
            &smolvm_protocol::encode_message(&AgentRequest::Stdin { data: data.clone() }).unwrap(),
        )
        .unwrap();
    assert_eq!(session.finish(), (0, data));
}
