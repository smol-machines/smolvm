//! Container execution survives transport resets. Only an explicit guest exit
//! ends the normal I/O path; reconnect never starts a replacement execution.
use super::runtime::{self, AgentReader, AgentWriter, Exit, Input, InputQueue};
use sha2::{Digest, Sha256};
use smolvm_protocol::container_session::{
    self as wire, Control, Event, Origin, OutputResume, Resume, Snapshot,
};
use smolvm_protocol::{AgentRequest, AgentResponse, ContainerStartSpec};
use std::{io, path::PathBuf, time::Duration};
use tokio::time::{sleep, timeout, Instant};

mod outbound;
use outbound::Outbound;
const FRAME_LIMIT: usize = 2 * wire::MAX_INPUT_BYTES;
const RETRY_MIN: Duration = Duration::from_millis(25);
const RETRY_MAX: Duration = Duration::from_secs(1);
const ATTACH_TIMEOUT: Duration = Duration::from_secs(5);

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "container session did not answer")
}
fn response_error(response: AgentResponse) -> io::Error {
    match response {
        AgentResponse::Error { message, code } => io::Error::new(
            if code.as_deref() == Some(wire::BUSY) {
                io::ErrorKind::WouldBlock
            } else {
                io::ErrorKind::InvalidData
            },
            GuestError { message, code },
        ),
        _ => invalid("unexpected container session response"),
    }
}
#[derive(Debug)]
struct GuestError {
    message: String,
    code: Option<String>,
}
impl std::fmt::Display for GuestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for GuestError {}
fn owner_changed(error: &io::Error) -> bool {
    error
        .get_ref()
        .and_then(|error| error.downcast_ref::<GuestError>())
        .is_some_and(|error| matches!(error.code.as_deref(), Some(wire::ABSENT | wire::CHANGED)))
}
fn transient(error: &io::Error) -> bool {
    !matches!(
        error.kind(),
        io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput | io::ErrorKind::Unsupported
    )
}

/// Transport-independent observations of an existing guest execution. This
/// never contains a start request: restoring it can only attach to that identity.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SavedSession {
    origin: Origin,
    fingerprint: [u8; 32],
    resume: Resume,
    pending: Option<u64>,
    stdin_closed: bool,
}

pub(super) struct Session {
    socket: PathBuf,
    overlay: String,
    origin: Origin,
    fingerprint: [u8; 32],
    resume: Resume,
    pending: Option<u64>,
    stdin_closed: bool,
    requested: bool,
    startup_notices: Vec<String>,
    reset_input: bool,
    connection: Option<(AgentReader, AgentWriter)>,
}
impl Session {
    pub(super) fn origin(&self) -> &Origin {
        &self.origin
    }
    pub(super) fn saved(&self) -> SavedSession {
        SavedSession {
            origin: self.origin.clone(),
            fingerprint: self.fingerprint,
            resume: self.resume.clone(),
            pending: self.pending,
            stdin_closed: self.stdin_closed,
        }
    }

    /// Reattach saved execution without ever sending Start, including when the
    /// restored guest does not have the requested identity.
    pub(super) async fn from_saved(
        socket: PathBuf,
        overlay: String,
        saved: SavedSession,
    ) -> io::Result<Self> {
        if saved.origin.generation == 0
            || humantime::parse_rfc3339(&saved.origin.started_at).is_err()
            || saved.resume.output_next == 0
            || saved.resume.input_next == 0
            || saved
                .pending
                .is_some_and(|pending| pending != saved.resume.input_next)
        {
            return Err(invalid("invalid saved container session"));
        }
        let mut session = Self {
            socket,
            overlay,
            origin: saved.origin,
            fingerprint: saved.fingerprint,
            resume: saved.resume,
            pending: saved.pending,
            stdin_closed: saved.stdin_closed,
            requested: true,
            startup_notices: Vec::new(),
            reset_input: false,
            connection: None,
        };
        let deadline = Instant::now() + ATTACH_TIMEOUT;
        loop {
            match session.attach().await {
                Ok(snapshot) => {
                    session.reconcile_start(snapshot)?;
                    return Ok(session);
                }
                Err(error) if transient(&error) && Instant::now() < deadline => {
                    sleep(RETRY_MIN).await
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub(super) fn new(socket: PathBuf, overlay: String, origin: Origin) -> Self {
        let identity = super::util::new_id()[..32]
            .to_owned()
            .try_into()
            .expect("hex execution identity");
        Self {
            socket,
            overlay,
            origin,
            fingerprint: [0; 32],
            resume: Resume {
                execution: identity,
                output_next: 1,
                input_next: 1,
            },
            pending: None,
            stdin_closed: false,
            requested: false,
            startup_notices: Vec::new(),
            reset_input: false,
            connection: None,
        }
    }
    pub(super) async fn start(&mut self, spec: ContainerStartSpec) -> io::Result<()> {
        if self.origin.generation == 0 || humantime::parse_rfc3339(&self.origin.started_at).is_err()
        {
            return Err(invalid("invalid container start origin"));
        }
        self.fingerprint = Sha256::digest(serde_json::to_vec(&spec)?).into();
        self.stdin_closed = !spec.open_stdin;
        let initial = timeout(Duration::from_secs(120), async {
            let (mut reader, mut writer) = runtime::connect(&self.socket).await?;
            writer.send(&AgentRequest::Ping).await?;
            match reader.recv_limited(FRAME_LIMIT).await? {
                AgentResponse::Pong { capabilities, .. }
                    if capabilities.iter().any(|c| c == wire::CAPABILITY) => {}
                AgentResponse::Pong { .. } => return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "Container recovery requires an updated Smol runtime and a restarted machine",
                )),
                reply => return Err(response_error(reply)),
            }
            self.requested = true;
            writer
                .send(&AgentRequest::ContainerSession {
                    control: Control::Start {
                        execution: self.resume.execution.clone(),
                        origin: self.origin.clone(),
                        spec: Box::new(spec),
                    },
                })
                .await?;
            let (snapshot, stdin_closed) = attached(reader.recv_limited(FRAME_LIMIT).await?)?;
            Ok((reader, writer, snapshot, stdin_closed))
        })
        .await
        .unwrap_or_else(|_| Err(timed_out()));
        match initial {
            Ok((reader, writer, snapshot, stdin_closed)) => {
                self.stdin_closed = stdin_closed;
                self.reconcile_start(snapshot)?;
                self.connection = Some((reader, writer));
                Ok(())
            }
            Err(error) if transient(&error) => {
                // An interrupted Started reply is ambiguous. Attach to the
                // same identity; never resend Start after a transport failure.
                let deadline = Instant::now() + Duration::from_secs(10);
                loop {
                    match self.attach().await {
                        Ok(snapshot) => {
                            self.reconcile_start(snapshot)?;
                            return Ok(());
                        }
                        Err(error) if transient(&error) && Instant::now() < deadline => {
                            sleep(RETRY_MIN).await
                        }
                        Err(error) => return Err(error),
                    }
                }
            }
            Err(error) => Err(error),
        }
    }
    async fn attach(&mut self) -> io::Result<Snapshot> {
        let (reader, writer, snapshot, stdin_closed) = self.attach_resume(&self.resume).await?;
        self.connection = Some((reader, writer));
        self.stdin_closed = stdin_closed;
        Ok(snapshot)
    }
    async fn attach_resume(
        &self,
        resume: &Resume,
    ) -> io::Result<(AgentReader, AgentWriter, Snapshot, bool)> {
        let result = timeout(ATTACH_TIMEOUT, async {
            let (mut reader, mut writer) = runtime::connect(&self.socket).await?;
            writer
                .send(&AgentRequest::ContainerSession {
                    control: Control::Attach {
                        overlay_id: self.overlay.clone(),
                        resume: resume.clone(),
                    },
                })
                .await?;
            let (snapshot, stdin_closed) = attached(reader.recv_limited(FRAME_LIMIT).await?)?;
            Ok::<_, io::Error>((reader, writer, snapshot, stdin_closed))
        })
        .await
        .map_err(|_| timed_out())??;
        Ok(result)
    }

    async fn recover_owner(
        &mut self,
        input: &InputQueue,
        notice: &mut impl FnMut(&str),
        restored: &mut impl FnMut(&Origin),
    ) -> io::Result<()> {
        let state = timeout(ATTACH_TIMEOUT, async {
            let (mut reader, mut writer) = runtime::connect(&self.socket).await?;
            writer
                .send(&AgentRequest::ContainerSession {
                    control: Control::Inspect {
                        overlay_id: self.overlay.clone(),
                    },
                })
                .await?;
            match reader.recv_limited(FRAME_LIMIT).await? {
                AgentResponse::ContainerSession {
                    event: Event::State { state: Some(state) },
                } => Ok(state),
                AgentResponse::ContainerSession {
                    event: Event::State { state: None },
                } => Err(invalid(
                    "the restored VM does not contain this container execution",
                )),
                other => Err(response_error(other)),
            }
        })
        .await
        .map_err(|_| timed_out())??;
        if state.origin.generation == 0
            || state.origin.generation >= self.origin.generation
            || state.fingerprint != self.fingerprint
            || humantime::parse_rfc3339(&state.origin.started_at).is_err()
            || state.snapshot.execution == self.resume.execution
        {
            return Err(invalid("the guest has a different execution which cannot be verified as an earlier start of this container"));
        }
        let resume = Resume {
            execution: state.snapshot.execution.clone(),
            output_next: state.snapshot.output_first,
            input_next: state.snapshot.input_next,
        };
        // Inspect grants no ownership. This exact-identity attach fails if the
        // guest owner changes between observation and attachment.
        let (reader, writer, snapshot, stdin_closed) = self.attach_resume(&resume).await?;
        let plan = snapshot.reconcile(&resume).map_err(invalid)?;
        let output_next = match plan.output {
            OutputResume::Continuous(next) => next,
            OutputResume::Gap { available, .. } => available,
            OutputResume::Rewound { current, .. } => current,
        };
        input.finish(); // Old clients and queued bytes belong to the discarded execution.
        self.pending = None;
        self.stdin_closed = stdin_closed;
        self.resume = Resume {
            execution: snapshot.execution,
            output_next,
            input_next: snapshot.input_next,
        };
        self.origin = state.origin;
        self.connection = Some((reader, writer));
        restored(&self.origin);
        notice("The VM restored an earlier execution of this container; queued input was discarded and retained output may repeat. Reconnect stdin to send new input.");
        Ok(())
    }
    fn reconcile_start(&mut self, snapshot: Snapshot) -> io::Result<()> {
        let mut notices = Vec::new();
        self.reconcile(snapshot, &mut |notice| notices.push(notice.to_owned()))?;
        self.startup_notices.extend(notices);
        Ok(())
    }

    fn reconcile(&mut self, snapshot: Snapshot, notice: &mut impl FnMut(&str)) -> io::Result<()> {
        let plan = snapshot.reconcile(&self.resume).map_err(invalid)?;
        self.reset_input |=
            plan.input_rewound || matches!(plan.output, OutputResume::Rewound { .. });
        self.resume.output_next = match plan.output {
            OutputResume::Continuous(next) => next,
            OutputResume::Gap {
                requested,
                available,
            } => {
                notice(&format!("Container output records {requested}..{available} were lost while disconnected"));
                available
            }
            OutputResume::Rewound { previous, current } => {
                notice(&format!("The VM restored an earlier container output cursor ({previous} to {current}); previously sent input will not be replayed"));
                current
            }
        };
        if plan.input_rewound {
            notice("The VM restored earlier stdin state; previously acknowledged input will not be replayed");
        }
        if let Some(sequence) = self.pending.take() {
            if plan.input_next
                != sequence
                    .checked_add(1)
                    .ok_or_else(|| invalid("input sequence exhausted"))?
                || !plan.may_retry_pending_input()
            {
                // Guest cursors themselves roll back. If it expects the same
                // input again, that cannot prove it did not execute before a
                // checkpoint restore. Decline the ambiguous retry explicitly.
                notice("Unacknowledged container input was not replayed after reconnect because its execution could not be confirmed");
            }
        } else if plan.input_next > self.resume.input_next {
            return Err(invalid(
                "guest acknowledged input which the host never sent",
            ));
        }
        self.resume.input_next = plan.input_next;
        Ok(())
    }

    fn discard_rewound_input(&mut self, input: &InputQueue, notice: &mut impl FnMut(&str)) {
        if std::mem::take(&mut self.reset_input) {
            input.finish();
            notice("Queued input from before the VM restore was discarded. Reconnect stdin to send new input.");
        }
    }

    pub(super) async fn pump(
        &mut self,
        input: &InputQueue,
        mut output: impl FnMut(u8, Vec<u8>),
        mut notice: impl FnMut(&str),
        mut restored: impl FnMut(&Origin),
        mut alive: impl FnMut() -> bool,
    ) -> io::Result<Exit> {
        for message in self.startup_notices.drain(..) {
            notice(&message);
        }
        self.discard_rewound_input(input, &mut notice);
        loop {
            let (reader, writer) = self
                .connection
                .take()
                .ok_or_else(|| invalid("container session has no attachment"))?;
            match self.connected(reader, writer, input, &mut output).await {
                Ok(exit) => return Ok(exit),
                Err(error) if !transient(&error) && !owner_changed(&error) => return Err(error),
                Err(error) => {
                    tracing::debug!(error = %error, "container transport detached; reconnecting")
                }
            }
            let mut backoff = RETRY_MIN;
            loop {
                if !alive() {
                    return Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "container VM exited before reporting the process exit status",
                    ));
                }
                sleep(backoff).await;
                match self.attach().await {
                    Ok(snapshot) => {
                        self.reconcile(snapshot, &mut notice)?;
                        self.discard_rewound_input(input, &mut notice);
                        break;
                    }
                    Err(error) if owner_changed(&error) => {
                        match self.recover_owner(input, &mut notice, &mut restored).await {
                            Ok(()) => break,
                            Err(error) if transient(&error) || owner_changed(&error) => {
                                backoff = (backoff * 2).min(RETRY_MAX)
                            }
                            Err(error) => return Err(error),
                        }
                    }
                    Err(error) if transient(&error) => backoff = (backoff * 2).min(RETRY_MAX),
                    Err(error) => return Err(error),
                }
            }
        }
    }

    async fn connected(
        &mut self,
        mut reader: AgentReader,
        writer: AgentWriter,
        input: &InputQueue,
        output: &mut impl FnMut(u8, Vec<u8>),
    ) -> io::Result<Exit> {
        let outbound = Outbound::default();
        let receive = async {
            loop {
                // Keep the in-progress read pinned across input notifications:
                // cancelling read_exact would discard a partial frame header.
                let reading = reader.recv_limited(FRAME_LIMIT);
                tokio::pin!(reading);
                let response = loop {
                    tokio::select! {
                        biased;
                        response = &mut reading => break response?,
                        next = input.next(), if self.pending.is_none() => {
                            let input = match next {
                                Input::Data(bytes) if bytes.is_empty() || self.stdin_closed => continue,
                                Input::Data(bytes) if bytes.len() <= wire::MAX_INPUT_BYTES => wire::Input::Data { bytes },
                                Input::Data(_) => return Err(invalid("container input exceeds 64 KiB")),
                                Input::Eof if self.stdin_closed => continue,
                                Input::Eof => { self.stdin_closed = true; wire::Input::Eof {} },
                                Input::Resize { cols, rows } if cols > 0 && rows > 0 => wire::Input::Resize { cols, rows },
                                Input::Resize { .. } => continue,
                            };
                            let sequence = self.resume.input_next;
                            sequence.checked_add(1).ok_or_else(|| invalid("input sequence exhausted"))?;
                            self.pending = Some(sequence);
                            outbound.input(sequence, input);
                        }
                    }
                };
                match response {
                    AgentResponse::ContainerSession {
                        event:
                            Event::Output {
                                sequence,
                                stream,
                                bytes,
                            },
                    } => {
                        if sequence != self.resume.output_next
                            || bytes.is_empty()
                            || bytes.len() > wire::MAX_INPUT_BYTES
                        {
                            return Err(invalid("invalid container output sequence or size"));
                        }
                        output(
                            match stream {
                                wire::OutputStream::Stdout => 1,
                                wire::OutputStream::Stderr => 2,
                            },
                            bytes,
                        );
                        self.resume.output_next = sequence
                            .checked_add(1)
                            .ok_or_else(|| invalid("output sequence exhausted"))?;
                        outbound.ack(self.resume.output_next);
                    }
                    AgentResponse::ContainerSession {
                        event: Event::InputAck { next },
                    } => {
                        if self.pending.and_then(|sequence| sequence.checked_add(1)) != Some(next) {
                            return Err(invalid("unexpected container input acknowledgement"));
                        }
                        self.pending = None;
                        self.resume.input_next = next;
                    }
                    AgentResponse::ContainerSession {
                        event: Event::Exited { exit },
                    } => {
                        return Ok(Exit {
                            code: exit.code.into(),
                            oom: exit.oom,
                        })
                    }
                    other => return Err(response_error(other)),
                }
            }
        };
        tokio::pin!(receive);
        tokio::select! {
            biased;
            result = &mut receive => result,
            error = outbound.send(writer) => {
                // A process can exit while the last output ACK is being sent.
                // Preserve its already queued real exit before reconnecting.
                match timeout(ATTACH_TIMEOUT, &mut receive).await {
                    Ok(result) => result,
                    Err(_) => Err(error),
                }
            }
        }
    }

    pub(super) async fn forget(&mut self) -> io::Result<()> {
        self.connection = None;
        self.control(Control::Forget {
            overlay_id: self.overlay.clone(),
            execution: self.resume.execution.clone(),
        })
        .await
    }
    pub(super) async fn cancel_and_forget(&mut self) -> io::Result<()> {
        if !self.requested {
            return Ok(());
        }
        self.connection = None;
        let _ = self
            .control(Control::Cancel {
                overlay_id: self.overlay.clone(),
                execution: self.resume.execution.clone(),
            })
            .await;
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match self.forget().await {
                Ok(()) => return Ok(()),
                Err(_) if Instant::now() < deadline => sleep(RETRY_MIN).await,
                Err(error) => return Err(error),
            }
        }
    }
    async fn control(&self, control: Control) -> io::Result<()> {
        let response = timeout(
            ATTACH_TIMEOUT,
            runtime::request(&self.socket, &AgentRequest::ContainerSession { control }),
        )
        .await
        .map_err(|_| timed_out())??;
        match response {
            AgentResponse::Ok { .. } => Ok(()),
            other => Err(response_error(other)),
        }
    }
}
fn attached(response: AgentResponse) -> io::Result<(Snapshot, bool)> {
    match response {
        AgentResponse::ContainerSession {
            event:
                Event::Attached {
                    snapshot,
                    stdin_closed,
                },
        } => Ok((snapshot, stdin_closed)),
        other => Err(response_error(other)),
    }
}

#[cfg(test)]
mod tests;
