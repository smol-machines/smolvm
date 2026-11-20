use super::*;
use std::os::fd::RawFd;

struct Lease<'a>(&'a Session);
impl Drop for Lease<'_> {
    fn drop(&mut self) {
        self.0.state.lock().attached = false;
        self.0.owner_wake.signal();
    }
}
struct Outbound {
    frame: WriteFrame,
    output_next: Option<u64>,
    exited: bool,
}
impl Outbound {
    fn event(event: Event, binary: bool) -> stdio::Result<Self> {
        let output_next = match &event {
            Event::Output { sequence, .. } => Some(sequence + 1),
            _ => None,
        };
        let exited = matches!(event, Event::Exited { .. });
        let response = AgentResponse::ContainerSession { event };
        let mut bytes = Vec::new();
        if !binary || !binary_stream::write_response(&mut bytes, &response)? {
            let mut envelope = smolvm_protocol::Envelope::new(response);
            if binary {
                envelope.binary_stream = Some(binary_stream::VERSION);
            }
            bytes =
                smolvm_protocol::encode_message(&envelope).map_err(|e| invalid(e.to_string()))?;
        }
        Ok(Self {
            frame: WriteFrame::new(bytes),
            output_next,
            exited,
        })
    }
}

impl Session {
    pub(super) fn attach(&self, fd: RawFd, binary: bool, resume: Resume) -> stdio::Result<()> {
        {
            let mut state = self.state.lock();
            if state.attached {
                return Err(stdio::Error::new(
                    stdio::ErrorKind::WouldBlock,
                    "container execution already has an attachment; retry after it detaches",
                ));
            }
            if self.execution != resume.execution {
                return Err(invalid("container execution changed"));
            }
            state.attached = true;
        }
        let _lease = Lease(self);
        let mut frame = Frame::default();
        let mut outgoing: Option<Outbound> = None;
        let mut pending_input: Option<(u64, Input)> = None;
        let mut input_ack: Option<u64> = None;
        let mut output_next = None;
        loop {
            self.attachment_wake.drain();
            {
                let mut state = self.state.lock();
                if let Some(failure) = &state.failure {
                    return Err(invalid(failure.clone()));
                }
                if state.ready && output_next.is_none() {
                    let snapshot = self.snapshot(&state)?;
                    let plan = snapshot.reconcile(&resume).map_err(invalid)?;
                    let next = match plan.output {
                        OutputResume::Continuous(next) => next,
                        OutputResume::Gap { available, .. } => available,
                        OutputResume::Rewound { current, .. } => current,
                    };
                    // The attachment itself is an acknowledgement of records
                    // already delivered before the previous connection died.
                    state.output.acknowledge(next).map_err(invalid)?;
                    self.owner_wake.signal();
                    output_next = Some(next);
                    let stdin_closed = !self.open_stdin || state.input.stdin_closed();
                    outgoing = Some(Outbound::event(
                        Event::Attached {
                            snapshot,
                            stdin_closed,
                        },
                        binary,
                    )?);
                }
                if let Some((sequence, input)) = &pending_input {
                    match state.input.check(*sequence, input).map_err(invalid)? {
                        InputDisposition::Acknowledge => {
                            input_ack = state.input.next();
                            pending_input = None;
                        }
                        InputDisposition::Apply
                            if state.pending_input.is_none() && state.output.exit().is_none() =>
                        {
                            // Queue insertion and cursor commit are one critical
                            // section. A lost ACK can never duplicate this write.
                            state.pending_input = Some(input.clone());
                            state
                                .input
                                .commit(*sequence, input.clone())
                                .map_err(invalid)?;
                            input_ack = state.input.next();
                            pending_input = None;
                            self.owner_wake.signal();
                        }
                        InputDisposition::Apply => {}
                    }
                }
                if outgoing.is_none() {
                    if let Some(next) = input_ack.take() {
                        outgoing = Some(Outbound::event(Event::InputAck { next }, binary)?);
                    } else if let Some(next) = output_next {
                        if let Some(record) = state.output.records_from(next).next() {
                            outgoing = Some(Outbound::event(
                                Event::Output {
                                    sequence: record.sequence,
                                    stream: record.stream,
                                    bytes: record.bytes.to_vec(),
                                },
                                binary,
                            )?);
                        } else if let Some(exit) = state.output.exit() {
                            outgoing = Some(Outbound::event(Event::Exited { exit }, binary)?);
                        }
                    }
                }
            }
            if let Some(write) = &mut outgoing {
                if write.frame.write(fd)? {
                    if write.exited {
                        return Ok(());
                    }
                    if let Some(next) = write.output_next {
                        output_next = Some(next);
                    }
                    outgoing = None;
                    // Read once before choosing the next output record so ACKs
                    // and stdin are not starved by a busy stdout producer.
                }
            }
            if let Some(body) = frame.read(fd)? {
                match binary_stream::decode_request(&body)?.body {
                    AgentRequest::ContainerSession {
                        control: Control::Input { sequence, input },
                    } => {
                        if output_next.is_none() {
                            return Err(invalid("container has not started"));
                        }
                        if pending_input.is_some() || input_ack.is_some() {
                            return Err(invalid("only one unacknowledged input record is allowed"));
                        }
                        // Validate payload before retaining it between wakeups.
                        self.state
                            .lock()
                            .input
                            .check(sequence, &input)
                            .map_err(invalid)?;
                        pending_input = Some((sequence, input));
                    }
                    AgentRequest::ContainerSession {
                        control: Control::OutputAck { next },
                    } => {
                        if output_next.is_none_or(|sent| next > sent) {
                            return Err(invalid("acknowledgement exceeds delivered output"));
                        }
                        self.state
                            .lock()
                            .output
                            .acknowledge(next)
                            .map_err(invalid)?;
                        self.owner_wake.signal();
                    }
                    _ => return Err(invalid("unexpected request on a container attachment")),
                }
                continue;
            }
            // If a frame just completed, choose another queued event without
            // waiting for a new wake. Otherwise both sides can sleep indefinitely.
            if outgoing.is_none() {
                let state = self.state.lock();
                if input_ack.is_some()
                    || output_next.is_some_and(|next| {
                        state.output.next() > next || state.output.exit().is_some()
                    })
                {
                    continue;
                }
            }
            let mut events = libc::POLLIN | libc::POLLRDHUP;
            if outgoing.is_some() {
                events |= libc::POLLOUT;
            }
            let mut fds = [
                watch(fd, events),
                watch(self.attachment_wake.fd(), libc::POLLIN),
            ];
            poll(&mut fds)?;
            if fds[0].revents & (libc::POLLHUP | libc::POLLRDHUP | libc::POLLERR | libc::POLLNVAL)
                != 0
            {
                return Err(stdio::ErrorKind::UnexpectedEof.into());
            }
        }
    }
}
