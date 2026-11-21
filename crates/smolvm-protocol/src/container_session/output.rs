use super::MAX_INPUT_BYTES;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// Maximum retained output payload per execution while its host is detached.
pub const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
/// Bound metadata too, including workloads which write one byte at a time.
pub const MAX_OUTPUT_RECORDS: usize = 256;

/// Original container stream; PTY output is represented as stdout.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputStream {
    /// Standard output, or merged output from a PTY.
    Stdout,
    /// Standard error for a non-PTY container.
    Stderr,
}

/// One retained output record; the byte allocation has no spare capacity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputRecord {
    /// Monotonic sequence within the execution.
    pub sequence: u64,
    /// Original stream identity.
    pub stream: OutputStream,
    /// Raw output, never interpreted as UTF-8.
    pub bytes: Box<[u8]>,
}

/// Confirmed process exit, retained separately from bounded output history.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exit {
    /// Actual exit status reported by the guest process owner.
    pub code: i32,
    /// Whether the process owner observed an OOM kill.
    pub oom: bool,
}

/// Bounded output retained by the execution owner, independent of connections.
///
/// Callers serialize access with session attachment/acknowledgement changes.
/// A connected reader applies backpressure; a detached execution keeps making
/// progress with bounded retention and reports a gap through `Snapshot` when
/// its host returns. EOF on a transport must never call `complete`.
#[derive(Debug)]
pub struct OutputLog {
    records: VecDeque<OutputRecord>,
    bytes: usize,
    next: u64,
    exit: Option<Exit>,
}
impl Default for OutputLog {
    fn default() -> Self {
        Self {
            records: VecDeque::new(),
            bytes: 0,
            next: 1,
            exit: None,
        }
    }
}
impl OutputLog {
    /// Oldest retained output sequence, or `next()` when there is no backlog.
    pub fn first(&self) -> u64 {
        self.records
            .front()
            .map_or(self.next, |record| record.sequence)
    }
    /// Sequence for the next appended record.
    pub fn next(&self) -> u64 {
        self.next
    }
    /// Number of bytes retained, excluding bounded record metadata.
    pub fn retained_bytes(&self) -> usize {
        self.bytes
    }
    /// Retained records at or after a checked resume cursor, in original order.
    pub fn records_from(&self, sequence: u64) -> impl Iterator<Item = &OutputRecord> {
        self.records
            .iter()
            .filter(move |record| record.sequence >= sequence)
    }
    fn pop(&mut self) {
        if let Some(record) = self.records.pop_front() {
            self.bytes -= record.bytes.len();
        }
    }
    /// Append a bounded raw chunk; `Ok(None)` means wait for an acknowledgement
    /// or detachment, without consuming data or advancing its sequence.
    pub fn push(
        &mut self,
        stream: OutputStream,
        bytes: &[u8],
        attached: bool,
    ) -> Result<Option<u64>, &'static str> {
        if self.exit.is_some() {
            return Err("container execution has exited");
        }
        if bytes.is_empty() || bytes.len() > MAX_INPUT_BYTES {
            return Err("output record must contain 1 to 65536 bytes");
        }
        let next = self
            .next
            .checked_add(1)
            .ok_or("output sequence exhausted")?;
        let full = |log: &Self| {
            log.bytes + bytes.len() > MAX_OUTPUT_BYTES || log.records.len() >= MAX_OUTPUT_RECORDS
        };
        if attached && full(self) {
            return Ok(None);
        }
        while full(self) {
            self.pop();
        }
        let sequence = self.next;
        self.records.push_back(OutputRecord {
            sequence,
            stream,
            bytes: bytes.into(),
        });
        self.bytes += bytes.len();
        self.next = next;
        Ok(Some(sequence))
    }
    /// Release records the host has consumed. An acknowledgement cannot refer
    /// to output which has not been produced, and old acknowledgements are safe.
    pub fn acknowledge(&mut self, next: u64) -> Result<(), &'static str> {
        if next == 0 || next > self.next {
            return Err("invalid output acknowledgement");
        }
        while self
            .records
            .front()
            .is_some_and(|record| record.sequence < next)
        {
            self.pop();
        }
        Ok(())
    }
    /// Record an authenticated process exit after draining its output. Retention
    /// pressure cannot evict the exit or turn a transport error into success.
    pub fn complete(&mut self, exit: Exit) -> Result<(), &'static str> {
        if self.exit.is_some_and(|previous| previous != exit) {
            return Err("conflicting container exit");
        }
        self.exit = Some(exit);
        Ok(())
    }
    /// Actual process exit, if one has been observed; detach leaves this unset.
    pub fn exit(&self) -> Option<Exit> {
        self.exit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connected_backpressure_preserves_interleaved_bytes_until_acknowledged() {
        let mut log = OutputLog::default();
        let data = vec![0xff; MAX_INPUT_BYTES];
        for n in 1..=16 {
            let stream = if n % 2 == 0 {
                OutputStream::Stderr
            } else {
                OutputStream::Stdout
            };
            assert_eq!(log.push(stream, &data, true), Ok(Some(n)));
        }
        assert_eq!(log.push(OutputStream::Stdout, b"pending", true), Ok(None));
        assert_eq!(
            (log.first(), log.next(), log.retained_bytes()),
            (1, 17, MAX_OUTPUT_BYTES)
        );
        let records: Vec<_> = log.records_from(1).collect();
        assert_eq!(records.len(), 16);
        for (n, record) in records.iter().enumerate() {
            assert_eq!(record.bytes.as_ref(), data);
            assert_eq!(
                record.stream,
                if n % 2 == 0 {
                    OutputStream::Stdout
                } else {
                    OutputStream::Stderr
                }
            );
        }
        assert!(log.acknowledge(18).is_err());
        assert_eq!(log.first(), 1);
        log.acknowledge(2).unwrap();
        assert_eq!(
            log.push(OutputStream::Stdout, b"pending", true),
            Ok(Some(17))
        );
        log.acknowledge(1).unwrap();
        assert_eq!(log.first(), 2);
    }

    #[test]
    fn detached_churn_bounds_payload_and_metadata_and_preserves_the_real_exit() {
        let mut log = OutputLog::default();
        let bytes = vec![7; MAX_INPUT_BYTES];
        for _ in 0..10000 {
            log.push(OutputStream::Stdout, &bytes, false).unwrap();
            assert!(log.retained_bytes() <= MAX_OUTPUT_BYTES);
            assert!(log.records.len() <= MAX_OUTPUT_RECORDS);
        }
        for _ in 0..10000 {
            log.push(OutputStream::Stderr, b"x", false).unwrap();
        }
        assert_eq!(log.records.len(), MAX_OUTPUT_RECORDS);
        assert_eq!(log.retained_bytes(), MAX_OUTPUT_RECORDS);
        assert!(log.first() > 1);
        assert_eq!(log.exit(), None);
        let exit = Exit {
            code: 7,
            oom: false,
        };
        log.complete(exit).unwrap();
        log.acknowledge(log.next()).unwrap();
        assert_eq!(log.retained_bytes(), 0);
        assert_eq!(log.exit(), Some(exit));
        assert!(log.push(OutputStream::Stdout, b"late", false).is_err());
        log.complete(exit).unwrap();
        assert!(log
            .complete(Exit {
                code: 0,
                oom: false
            })
            .is_err());
    }

    #[test]
    fn invalid_chunks_and_sequence_exhaustion_do_not_mutate_retained_output() {
        let mut log = OutputLog::default();
        assert!(log.push(OutputStream::Stdout, b"", false).is_err());
        assert!(log
            .push(OutputStream::Stdout, &vec![0; MAX_INPUT_BYTES + 1], false)
            .is_err());
        assert_eq!(log.next(), 1);
        log.push(OutputStream::Stdout, b"saved", false).unwrap();
        log.next = u64::MAX;
        assert!(log.push(OutputStream::Stdout, b"overflow", false).is_err());
        assert_eq!(log.first(), 1);
        assert_eq!(log.retained_bytes(), 5);
        assert_eq!(log.records_from(1).next().unwrap().bytes.as_ref(), b"saved");
    }
}
