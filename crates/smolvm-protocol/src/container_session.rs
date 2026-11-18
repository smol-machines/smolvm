//! Reconnection identities and cursor reconciliation for container execution.
//!
//! An execution identity belongs to one start, not a reusable container name.
//! Output and input cursors are independent: reconnect must never resend input
//! that the guest already committed. A checkpoint can rewind either cursor;
//! that is reported explicitly instead of silently replaying later commands.
use serde::{Deserialize, Serialize};

mod output;
pub use output::{
    Exit, OutputLog, OutputRecord, OutputStream, MAX_OUTPUT_BYTES, MAX_OUTPUT_RECORDS,
};

/// Bound each pending/replayed stdin record independently of outer framing.
pub const MAX_INPUT_BYTES: usize = 64 * 1024;
/// Guest-owned execution and sequenced reconnect support.
pub const CAPABILITY: &str = "container-session-v2";
/// A previous attachment has not observed its transport closing yet.
pub const BUSY: &str = "CONTAINER_SESSION_BUSY";
/// No execution exists on the requested overlay in this VM state.
pub const ABSENT: &str = "CONTAINER_SESSION_ABSENT";
/// The overlay exists, but is owned by a different execution.
pub const CHANGED: &str = "CONTAINER_SESSION_CHANGED";

/// Host-persisted start order; unlike the guest, this counter does not rewind.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Origin {
    /// Monotonic start generation of this container, beginning at one.
    pub generation: u64,
    /// Original host RFC 3339 start timestamp, retained across VM restores.
    pub started_at: String,
}

/// Read-only evidence used before attempting an exact-identity attachment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionState {
    /// The current execution and its stream cursors.
    pub snapshot: Snapshot,
    /// The start which created this execution.
    pub origin: Origin,
    /// SHA-256 of the serialized start specification, including the full container ID.
    pub fingerprint: [u8; 32],
}

/// Container session control messages. Input and acknowledgements are valid
/// only on a connection which has successfully attached to an execution.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Control {
    /// Describe the current owner without attaching, starting, or cancelling it.
    Inspect {
        /// Overlay whose current owner is being reconciled.
        overlay_id: String,
    },
    /// Cancel this exact execution after a failed start or unrecoverable owner
    /// error; never target another execution sharing the overlay name.
    Cancel {
        /// Overlay owning the execution.
        overlay_id: String,
        /// Exact execution to cancel.
        execution: ExecutionId,
    },
    /// Create one execution; retrying the same identity must not spawn twice.
    Start {
        /// Host-generated identity for this start.
        execution: ExecutionId,
        /// Persisted host start generation and original timestamp.
        origin: Origin,
        /// OCI configuration, including the owning overlay.
        spec: Box<crate::ContainerStartSpec>,
    },
    /// Reconnect to an existing execution without starting a replacement.
    Attach {
        /// Overlay owning the execution.
        overlay_id: String,
        /// Last host observations for reconciliation.
        resume: Resume,
    },
    /// Commit one bounded input record, deduplicated by sequence and payload.
    Input {
        /// Record sequence, starting at one.
        sequence: u64,
        /// Stdin, EOF, or terminal resize.
        input: Input,
    },
    /// Release output already delivered by the host.
    OutputAck {
        /// First output record not yet delivered.
        next: u64,
    },
    /// Release a completed execution after the host recorded its real exit.
    Forget {
        /// Overlay owning the execution.
        overlay_id: String,
        /// Exact execution; a live execution must never be forgotten.
        execution: ExecutionId,
    },
}

/// Events on a connection attached to one durable container execution.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub enum Event {
    /// Current owner, or absence after a checkpoint predating its creation.
    State {
        /// No owner is distinct from a different, still-live execution.
        state: Option<ExecutionState>,
    },
    /// The guest accepted attachment; reconcile before sending any input.
    Attached {
        /// Atomically captured execution cursors.
        snapshot: Snapshot,
        /// Whether this execution has closed stdin, including accepted EOF.
        stdin_closed: bool,
    },
    /// Raw output in the original stream order.
    Output {
        /// Sequence in this execution, starting at one.
        sequence: u64,
        /// Original stream identity.
        stream: OutputStream,
        /// Payload; negotiated binary transport avoids base64 expansion.
        #[serde(with = "crate::base64_bytes")]
        bytes: Vec<u8>,
    },
    /// Input was accepted once into the execution owner's bounded queue.
    InputAck {
        /// First uncommitted input sequence.
        next: u64,
    },
    /// Actual process exit, delivered after retained output.
    Exited {
        /// Status reported by the process owner, never inferred from disconnect.
        exit: Exit,
    },
}

/// A host-generated 128-bit execution identity, encoded as lowercase hex.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ExecutionId(String);

impl TryFrom<String> for ExecutionId {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.len() != 32
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("execution identity must be 32 lowercase hexadecimal characters");
        }
        Ok(Self(value))
    }
}
impl From<ExecutionId> for String {
    fn from(value: ExecutionId) -> Self {
        value.0
    }
}
impl ExecutionId {
    /// The exact identity carried by start, attach, output and exit messages.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One input record. The guest commits its sequence before acknowledging it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Input {
    /// Bytes for stdin. EOF has its own record and cannot be confused with data.
    Data {
        /// Raw bytes, encoded as base64 on the JSON control path.
        #[serde(with = "crate::base64_bytes")]
        bytes: Vec<u8>,
    },
    /// Close stdin once; a reconnect does not itself imply EOF.
    Eof {},
    /// Resize a terminal associated with this execution.
    Resize {
        /// Terminal columns.
        cols: u16,
        /// Terminal rows.
        rows: u16,
    },
}

/// The host's last durable observations when requesting another attachment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resume {
    /// Exact execution to attach; mismatches must never start a replacement.
    pub execution: ExecutionId,
    /// First output record not yet delivered by the host (records begin at one).
    pub output_next: u64,
    /// First input record not acknowledged as committed by the guest.
    pub input_next: u64,
}

/// Guest state captured atomically while establishing an attachment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    /// Exact current execution.
    pub execution: ExecutionId,
    /// Oldest retained output record; equals `output_next` when empty.
    pub output_first: u64,
    /// Sequence assigned to the next output record.
    pub output_next: u64,
    /// Sequence expected for the next input record.
    pub input_next: u64,
}

/// How the host must resume output after examining a guest snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutputResume {
    /// Continue exactly at the host's cursor.
    Continuous(u64),
    /// Detached output exceeded retention; report the loss before replaying.
    Gap {
        /// First record the host expected.
        requested: u64,
        /// Oldest record still available.
        available: u64,
    },
    /// A checkpoint restored an earlier output cursor; report the rewind.
    Rewound {
        /// Cursor observed by the host before restore.
        previous: u64,
        /// Guest cursor after restore. Previously delivered input is not replayed.
        current: u64,
    },
}

/// A checked resume plan. It cannot authorize attachment to another execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    /// Output replay position and any discontinuity to report.
    pub output: OutputResume,
    /// Guest's authoritative next input sequence.
    pub input_next: u64,
    /// A checkpoint rolled back input state; do not replay acknowledged commands.
    pub input_rewound: bool,
}
impl Plan {
    /// Pending input must not be replayed automatically across a detected rewind.
    /// A matching cursor alone cannot exclude a checkpoint restored before an
    /// unacknowledged record. Callers must also fence VM restores, or decline
    /// ambiguous retries; this check is not an exactly-once guarantee across
    /// rollback of the guest's committed state.
    pub fn may_retry_pending_input(&self) -> bool {
        !self.input_rewound && !matches!(self.output, OutputResume::Rewound { .. })
    }
}

impl Snapshot {
    /// Validate a resume handshake and determine replay without applying input.
    ///
    /// The host may have at most one unacknowledged input record. The guest can
    /// therefore be one record ahead when its acknowledgement was lost, but a
    /// larger forward jump is a protocol error, not permission to skip input.
    pub fn reconcile(&self, resume: &Resume) -> Result<Plan, &'static str> {
        if self.execution != resume.execution {
            return Err("container execution changed");
        }
        if self.output_first == 0
            || self.output_first > self.output_next
            || self.input_next == 0
            || resume.output_next == 0
            || resume.input_next == 0
        {
            return Err("invalid container session cursor");
        }
        if self.input_next > resume.input_next.saturating_add(1) {
            return Err("guest input cursor exceeds the single pending input record");
        }
        let output = if resume.output_next > self.output_next {
            OutputResume::Rewound {
                previous: resume.output_next,
                current: self.output_next,
            }
        } else if resume.output_next < self.output_first {
            OutputResume::Gap {
                requested: resume.output_next,
                available: self.output_first,
            }
        } else {
            OutputResume::Continuous(resume.output_next)
        };
        Ok(Plan {
            output,
            input_next: self.input_next,
            input_rewound: self.input_next < resume.input_next,
        })
    }
}

/// Guest input sequencing, retained with the execution across transport resets.
///
/// A record must first be placed into the bounded process-input queue and then
/// committed. The acknowledgement is sent only after commit. Retrying the last
/// record is safe only when its payload also matches, including EOF and resize.
#[derive(Debug, Default)]
pub struct InputCursor {
    committed: Option<(u64, Input)>,
    stdin_closed: bool,
}

/// Result of checking an incoming record before any process I/O is performed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputDisposition {
    /// Queue once, commit, then acknowledge.
    Apply,
    /// Already committed; acknowledge again without writing to the process.
    Acknowledge,
}

impl InputCursor {
    /// Whether an EOF record has been accepted for this execution.
    pub fn stdin_closed(&self) -> bool {
        self.stdin_closed
    }
    /// First sequence not committed. `None` means the sequence space is exhausted.
    pub fn next(&self) -> Option<u64> {
        self.committed
            .as_ref()
            .map_or(Some(1), |(sequence, _)| sequence.checked_add(1))
    }

    /// Reject gaps and changed replays before they can affect stdin or the PTY.
    pub fn check(&self, sequence: u64, input: &Input) -> Result<InputDisposition, &'static str> {
        match input {
            Input::Data { bytes } if bytes.is_empty() => {
                return Err("empty container input is not EOF; use an EOF record");
            }
            Input::Data { bytes } if bytes.len() > MAX_INPUT_BYTES => {
                return Err("container input record exceeds 64 KiB");
            }
            Input::Resize { cols, rows } if *cols == 0 || *rows == 0 => {
                return Err("terminal dimensions must be nonzero");
            }
            _ => {}
        }
        if self
            .committed
            .as_ref()
            .is_some_and(|(last, data)| *last == sequence && data == input)
        {
            return Ok(InputDisposition::Acknowledge);
        }
        if Some(sequence) == self.next() {
            if self.stdin_closed && !matches!(input, Input::Resize { .. }) {
                return Err("container stdin is already closed");
            }
            return Ok(InputDisposition::Apply);
        }
        Err("input sequence or replay payload does not match the execution")
    }

    /// Commit only after accepting the record into the process-input queue.
    pub fn commit(&mut self, sequence: u64, input: Input) -> Result<(), &'static str> {
        match self.check(sequence, &input)? {
            InputDisposition::Apply => {
                self.stdin_closed |= matches!(input, Input::Eof { .. });
                self.committed = Some((sequence, input));
            }
            InputDisposition::Acknowledge => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
