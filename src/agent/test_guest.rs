//! A stand-in for the guest agent's interactive exec, for host-side tests.
//!
//! It speaks the agent wire protocol on one end of a socket pair and runs the
//! requested command as a real process on pipes, the way the guest agent does
//! when no PTY is allocated: `Stdin` frames are written to the command's stdin
//! with a blocking write (so a command that reads slowly slows the sender down
//! and no byte is lost), its stdout and stderr come back as `Stdout` and
//! `Stderr` frames, and `Exited` ends the session. An empty `Stdin` frame closes
//! the command's stdin.

use crate::platform::uds::UdsStream;
use smolvm_protocol::{encode_message, AgentRequest, AgentResponse, Envelope};
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

pub(crate) struct FakeGuest {
    /// How many `Resize` frames the host sent.
    pub resizes: Arc<AtomicUsize>,
    thread: JoinHandle<()>,
}

impl FakeGuest {
    /// Serve one interactive session on `stream`.
    pub fn spawn(stream: UdsStream) -> Self {
        let resizes = Arc::new(AtomicUsize::new(0));
        let counted = resizes.clone();
        let thread = std::thread::spawn(move || serve(stream, counted));
        Self { resizes, thread }
    }

    /// Wait for the session to end.
    pub fn finish(self) {
        self.thread.join().expect("fake guest thread");
    }
}

fn read_frame(stream: &mut UdsStream) -> Option<AgentRequest> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).ok()?;
    let mut payload = vec![0u8; u32::from_be_bytes(header) as usize];
    stream.read_exact(&mut payload).ok()?;
    let envelope: Envelope<AgentRequest> = serde_json::from_slice(&payload).ok()?;
    Some(envelope.body)
}

fn send(stream: &Mutex<UdsStream>, response: &AgentResponse) -> bool {
    let bytes = encode_message(response).expect("encode response");
    stream.lock().unwrap().write_all(&bytes).is_ok()
}

/// Forward everything `source` produces until it ends.
fn pump<R: Read + Send + 'static>(
    mut source: R,
    stream: Arc<Mutex<UdsStream>>,
    wrap: fn(Vec<u8>) -> AgentResponse,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let mut chunk = [0u8; 8192];
        while let Ok(count) = source.read(&mut chunk) {
            if count == 0 || !send(&stream, &wrap(chunk[..count].to_vec())) {
                break;
            }
        }
    })
}

fn serve(mut stream: UdsStream, resizes: Arc<AtomicUsize>) {
    let command = match read_frame(&mut stream) {
        Some(AgentRequest::VmExec { command, .. }) | Some(AgentRequest::Run { command, .. }) => {
            command
        }
        other => panic!("expected an interactive exec request, got {other:?}"),
    };
    let mut child = Command::new(&command[0])
        .args(&command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the command");
    let pid = child.id() as libc::pid_t;
    let mut stdin = child.stdin.take();
    let writer = Arc::new(Mutex::new(stream.try_clone().expect("clone the socket")));
    send(&writer, &AgentResponse::Started);
    let out = pump(child.stdout.take().unwrap(), writer.clone(), |data| {
        AgentResponse::Stdout { data }
    });
    let err = pump(child.stderr.take().unwrap(), writer.clone(), |data| {
        AgentResponse::Stderr { data }
    });
    // The session ends when the command does, whatever the host is doing.
    let finished = {
        let writer = writer.clone();
        std::thread::spawn(move || {
            let _ = out.join();
            let _ = err.join();
            let code = child.wait().ok().and_then(|s| s.code()).unwrap_or(-1);
            send(
                &writer,
                &AgentResponse::Exited {
                    exit_code: code,
                    oom: false,
                },
            );
        })
    };

    loop {
        match read_frame(&mut stream) {
            Some(AgentRequest::Stdin { data }) if data.is_empty() => {
                drop(stdin.take());
            }
            Some(AgentRequest::Stdin { data }) => {
                if let Some(pipe) = stdin.as_mut() {
                    // A blocking write: this is the backpressure.
                    let _ = pipe.write_all(&data);
                }
            }
            Some(AgentRequest::Resize { .. }) => {
                resizes.fetch_add(1, Ordering::SeqCst);
            }
            Some(_) => {}
            None => break,
        }
    }
    // The host went away, or the session is over. Either way the command must
    // not outlive it: the agent kills what it cannot report to.
    // SAFETY: killing a process id this thread spawned; at worst it has exited.
    unsafe { libc::kill(pid, libc::SIGKILL) };
    let _ = finished.join();
}
