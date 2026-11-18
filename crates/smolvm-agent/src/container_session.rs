//! Guest-owned container execution. A vsock attachment never owns the process.
//!
//! The existing pipe/PTY pumps talk to a private Unix socket. An event-driven
//! broker owns its other end and retains bounded output while the host is
//! detached. Neither socket is closed when a host attachment disappears.
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use smolvm_protocol::container_session::{
    Control, Event, ExecutionId, ExecutionState, Exit, Input, InputCursor, InputDisposition,
    Origin, OutputLog, OutputResume, OutputStream, Resume, Snapshot,
};
use smolvm_protocol::{binary_stream, error_codes, AgentRequest, AgentResponse};
use std::collections::HashMap;
use std::io as stdio;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, LazyLock};

mod attachment;
mod io;
use io::{invalid, poll, watch, Frame, Wake, WriteFrame};

const MAX_SESSIONS: usize = 64;
static SESSIONS: LazyLock<Registry> = LazyLock::new(Registry::default);

#[derive(Default)]
struct Registry(Mutex<HashMap<String, Arc<Session>>>);
impl Registry {
    fn start(
        &self,
        execution: ExecutionId,
        origin: Origin,
        spec: Box<smolvm_protocol::ContainerStartSpec>,
    ) -> stdio::Result<Arc<Session>> {
        if origin.generation == 0 || origin.started_at.is_empty() || origin.started_at.len() > 64 {
            return Err(invalid("invalid container start origin"));
        }
        let fingerprint: [u8; 32] = Sha256::digest(serde_json::to_vec(&spec)?).into();
        let mut sessions = self.0.lock();
        if let Some(session) = sessions.get(&spec.overlay_id) {
            if session.execution == execution
                && session.fingerprint == fingerprint
                && session.origin == origin
            {
                return Ok(session.clone());
            }
            let state = session.state.lock();
            if state.attached
                || !state.owner_done
                || (state.output.exit().is_none() && state.failure.is_none())
            {
                return Err(invalid("overlay already owns a container execution; stop and forget it before another start"));
            }
            // A new, explicit start may replace its own completed execution
            // if the host's Forget reply was lost. Never evict a live owner.
            drop(state);
            if origin.generation <= session.origin.generation {
                return Err(invalid("container start generation did not advance"));
            }
            sessions.remove(&spec.overlay_id);
        }
        if sessions.len() >= MAX_SESSIONS {
            return Err(invalid(
                "container session limit reached; release completed executions",
            ));
        }
        let overlay = spec.overlay_id.clone();
        let session = Session::spawn(
            execution,
            origin,
            fingerprint,
            spec.open_stdin,
            move |socket| {
                let mut wire = crate::WireStream::new(socket);
                wire.binary = true;
                if let Err(error) = crate::container::handle_container_start(&mut wire, *spec) {
                    let _ = crate::send_response(
                        &mut wire,
                        &AgentResponse::error(error.to_string(), error_codes::INTERNAL_ERROR),
                    );
                }
            },
        )?;
        sessions.insert(overlay, session.clone());
        Ok(session)
    }
    fn find(&self, overlay: &str, execution: &ExecutionId) -> stdio::Result<Arc<Session>> {
        let sessions = self.0.lock();
        let session = sessions.get(overlay).ok_or_else(|| {
            stdio::Error::new(
                stdio::ErrorKind::NotFound,
                "container execution is absent from this VM state",
            )
        })?;
        if &session.execution != execution {
            return Err(stdio::Error::new(
                stdio::ErrorKind::AlreadyExists,
                "container execution changed in this VM state",
            ));
        }
        Ok(session.clone())
    }
    fn inspect(&self, overlay: &str) -> stdio::Result<Option<ExecutionState>> {
        let sessions = self.0.lock();
        let Some(session) = sessions.get(overlay) else {
            return Ok(None);
        };
        let state = session.state.lock();
        Ok(Some(ExecutionState {
            snapshot: session.snapshot(&state)?,
            origin: session.origin.clone(),
            fingerprint: session.fingerprint,
        }))
    }
    fn forget(&self, overlay: &str, execution: &ExecutionId) -> stdio::Result<()> {
        let mut sessions = self.0.lock();
        let Some(session) = sessions.get(overlay) else {
            return Ok(());
        };
        if &session.execution != execution {
            return Err(invalid("container execution changed"));
        }
        let state = session.state.lock();
        if state.output.exit().is_none() && !(state.failure.is_some() && state.owner_done) {
            return Err(invalid("cannot forget a live container execution"));
        }
        // Acknowledging Exited and forgetting may race the attachment's last
        // return; its Arc keeps it alive until the handler releases its lease.
        drop(state);
        sessions.remove(overlay);
        Ok(())
    }
}

struct Session {
    execution: ExecutionId,
    origin: Origin,
    open_stdin: bool,
    fingerprint: [u8; 32],
    state: Mutex<State>,
    owner_wake: Wake,
    attachment_wake: Wake,
}
#[derive(Default)]
struct State {
    ready: bool,
    owner_done: bool,
    cancelled: bool,
    attached: bool,
    output: OutputLog,
    input: InputCursor,
    // At most one accepted input record waits for the broker. The broker
    // additionally holds at most one partially written frame.
    pending_input: Option<Input>,
    failure: Option<String>,
}
impl Session {
    fn spawn(
        execution: ExecutionId,
        origin: Origin,
        fingerprint: [u8; 32],
        open_stdin: bool,
        run: impl FnOnce(&mut UnixStream) + Send + 'static,
    ) -> stdio::Result<Arc<Self>> {
        let (mut worker, broker) = UnixStream::pair()?;
        let session = Arc::new(Self {
            execution,
            origin,
            open_stdin,
            fingerprint,
            state: Mutex::new(State::default()),
            owner_wake: Wake::new()?,
            attachment_wake: Wake::new()?,
        });
        let owner = session.clone();
        std::thread::Builder::new()
            .name("container-session-io".into())
            .spawn(move || {
                if let Err(error) = owner.broker(broker) {
                    owner.state.lock().failure =
                        Some(format!("container execution I/O failed: {error}"));
                    owner.attachment_wake.signal();
                }
            })?;
        // On spawn failure dropping worker closes the private connection and
        // wakes the broker; no process has been started yet.
        let owner = session.clone();
        std::thread::Builder::new()
            .name("container-session-owner".into())
            .spawn(move || {
                struct Done(Arc<Session>);
                impl Drop for Done {
                    fn drop(&mut self) {
                        self.0.state.lock().owner_done = true;
                        self.0.attachment_wake.signal();
                    }
                }
                let _done = Done(owner);
                run(&mut worker);
            })?;
        Ok(session)
    }

    fn snapshot(&self, state: &State) -> stdio::Result<Snapshot> {
        Ok(Snapshot {
            execution: self.execution.clone(),
            output_first: state.output.first(),
            output_next: state.output.next(),
            input_next: state
                .input
                .next()
                .ok_or_else(|| invalid("input sequence exhausted"))?,
        })
    }

    fn broker(&self, socket: UnixStream) -> stdio::Result<()> {
        let fd = socket.as_raw_fd();
        let mut frame = Frame::default();
        let mut pending_output: Option<(OutputStream, Vec<u8>)> = None;
        let mut pending_write: Option<WriteFrame> = None;
        let mut write_closed = false;
        loop {
            self.owner_wake.drain();
            if self.state.lock().cancelled {
                // Closing only the private owner socket cancels its pump and
                // triggers the existing child-tree/crun cleanup, even when
                // prepare has not finished yet. External detach never does this.
                return Err(invalid("container execution was cancelled"));
            }
            if let Some((stream, bytes)) = &pending_output {
                let mut state = self.state.lock();
                let attached = state.attached;
                if state
                    .output
                    .push(*stream, bytes, attached)
                    .map_err(invalid)?
                    .is_some()
                {
                    pending_output = None;
                    self.attachment_wake.signal();
                }
            }
            if pending_write.is_none() && !write_closed {
                let input = self.state.lock().pending_input.take();
                if let Some(input) = input {
                    let request = match input {
                        Input::Data { bytes } => AgentRequest::Stdin { data: bytes },
                        Input::Eof {} => AgentRequest::Stdin { data: Vec::new() },
                        Input::Resize { cols, rows } => AgentRequest::Resize { cols, rows },
                    };
                    let bytes = match binary_stream::encode_request(&request, None)? {
                        Some(bytes) => bytes,
                        None => smolvm_protocol::encode_message(&request)
                            .map_err(|e| invalid(e.to_string()))?,
                    };
                    pending_write = Some(WriteFrame::new(bytes));
                    self.attachment_wake.signal();
                }
            }
            if let Some(write) = &mut pending_write {
                match write.write(fd) {
                    Ok(true) => {
                        pending_write = None;
                        continue;
                    }
                    Ok(false) => {}
                    Err(error)
                        if matches!(
                            error.kind(),
                            stdio::ErrorKind::BrokenPipe | stdio::ErrorKind::ConnectionReset
                        ) =>
                    {
                        // Exit can race stdin. Drain the owner's output and
                        // explicit exit before concluding anything about it.
                        pending_write = None;
                        write_closed = true;
                    }
                    Err(error) => return Err(error),
                }
            }
            if pending_output.is_none() {
                if let Some(body) = frame.read(fd)? {
                    let (response, _) = binary_stream::decode_response(&body)?;
                    match response {
                        AgentResponse::Started => {
                            self.state.lock().ready = true;
                            self.attachment_wake.signal();
                        }
                        AgentResponse::Stdout { data } | AgentResponse::Stderr { data }
                            if data.is_empty() => {}
                        AgentResponse::Stdout { data } => {
                            pending_output = Some((OutputStream::Stdout, data))
                        }
                        AgentResponse::Stderr { data } => {
                            pending_output = Some((OutputStream::Stderr, data))
                        }
                        AgentResponse::Exited { exit_code, oom } => {
                            self.state
                                .lock()
                                .output
                                .complete(Exit {
                                    code: exit_code,
                                    oom,
                                })
                                .map_err(invalid)?;
                            self.attachment_wake.signal();
                            return Ok(());
                        }
                        AgentResponse::Error { message, .. } => return Err(invalid(message)),
                        _ => return Err(invalid("unexpected process-owner response")),
                    }
                    continue;
                }
            }
            let mut events = libc::POLLRDHUP;
            if pending_output.is_none() {
                events |= libc::POLLIN;
            }
            if pending_write.is_some() {
                events |= libc::POLLOUT;
            }
            // A closed worker with output awaiting ACK must not cause a HUP
            // busy loop. Its EOF is observed after retention pressure clears.
            let observed = if pending_output.is_some() && pending_write.is_none() {
                -1
            } else {
                fd
            };
            let mut fds = [
                watch(observed, events),
                watch(self.owner_wake.fd(), libc::POLLIN),
            ];
            poll(&mut fds)?;
            // Drain queued output and the real exit even if the worker has
            // closed its write side. EOF without Exited is a failure, not 137.
            if fds[0].revents & libc::POLLNVAL != 0 {
                return Err(invalid("invalid process-owner socket"));
            }
        }
    }
}

pub(crate) fn serve(
    stream: &mut crate::WireStream<impl crate::ReadWrite>,
    control: Control,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = match control {
        Control::Inspect { overlay_id } => {
            let state = SESSIONS.inspect(&overlay_id)?;
            return crate::send_response(
                stream,
                &AgentResponse::ContainerSession {
                    event: Event::State { state },
                },
            );
        }
        Control::Cancel {
            overlay_id,
            execution,
        } => match SESSIONS.find(&overlay_id, &execution) {
            Ok(session) => {
                session.state.lock().cancelled = true;
                session.owner_wake.signal();
                return crate::send_response(stream, &AgentResponse::Ok { data: None });
            }
            Err(error) => Err(error),
        },
        Control::Start {
            execution,
            origin,
            spec,
        } => {
            let resume = Resume {
                execution: execution.clone(),
                output_next: 1,
                input_next: 1,
            };
            SESSIONS
                .start(execution, origin, spec)
                .and_then(|session| session.attach(stream.as_raw_fd(), stream.binary, resume))
        }
        Control::Attach { overlay_id, resume } => SESSIONS
            .find(&overlay_id, &resume.execution)
            .and_then(|session| session.attach(stream.as_raw_fd(), stream.binary, resume)),
        Control::Forget {
            overlay_id,
            execution,
        } => match SESSIONS.forget(&overlay_id, &execution) {
            Ok(()) => return crate::send_response(stream, &AgentResponse::Ok { data: None }),
            Err(error) => Err(error),
        },
        _ => Err(invalid(
            "container session input requires an attached connection",
        )),
    };
    if let Err(error) = result {
        // Transport errors are ordinary detach, and cannot cancel the owner.
        if !matches!(
            error.kind(),
            stdio::ErrorKind::BrokenPipe
                | stdio::ErrorKind::ConnectionReset
                | stdio::ErrorKind::UnexpectedEof
        ) {
            let code = match error.kind() {
                stdio::ErrorKind::WouldBlock => smolvm_protocol::container_session::BUSY,
                stdio::ErrorKind::NotFound => smolvm_protocol::container_session::ABSENT,
                stdio::ErrorKind::AlreadyExists => smolvm_protocol::container_session::CHANGED,
                _ => error_codes::INVALID_REQUEST,
            };
            crate::send_response(stream, &AgentResponse::error(error.to_string(), code))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
