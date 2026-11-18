//! Bounded output framing for a controlled TCP helper's stdout.
//! Input is raw TCP payload and pipe EOF closes only the socket's write half.
//! Output frames distinguish connection readiness, data and a read-half EOF.

/// The guest has connected successfully.
pub const CONNECTED: u8 = 0;
/// A big-endian u32 payload length and that many TCP bytes follow.
pub const DATA: u8 = 1;
/// The TCP peer closed its write half; client input remains valid.
pub const EOF: u8 = 2;
/// Maximum payload in one helper frame.
pub const MAX_DATA: usize = 32768;

/// One decoded helper event.
#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    /// The destination accepted the TCP connection.
    Connected,
    /// Unmodified bytes received from the destination.
    Data(Vec<u8>),
    /// No further bytes will arrive from the destination.
    Eof,
}

/// Incremental decoder that buffers at most one bounded helper frame.
pub struct Decoder {
    pending: Vec<u8>,
    expected: usize,
    connected: bool,
    eof: bool,
}
impl Default for Decoder {
    fn default() -> Self {
        Self {
            pending: Vec::new(),
            expected: 1,
            connected: false,
            eof: false,
        }
    }
}
impl Decoder {
    /// Consume input until one event is ready or this chunk is exhausted.
    /// The caller continues with the remaining input after each returned event.
    pub fn consume(&mut self, input: &mut &[u8]) -> Result<Option<Event>, &'static str> {
        while !input.is_empty() {
            let take = (self.expected - self.pending.len()).min(input.len());
            self.pending.extend_from_slice(&input[..take]);
            *input = &input[take..];
            if self.pending.len() != self.expected {
                return Ok(None);
            }
            if self.eof {
                return Err("TCP output followed EOF");
            }
            if self.expected == 1 {
                match self.pending[0] {
                    CONNECTED if !self.connected => {
                        self.connected = true;
                        self.pending.clear();
                        return Ok(Some(Event::Connected));
                    }
                    EOF if self.connected => {
                        self.eof = true;
                        self.pending.clear();
                        return Ok(Some(Event::Eof));
                    }
                    DATA if self.connected => self.expected = 5,
                    _ => return Err("invalid TCP helper event"),
                }
            } else if self.expected == 5 {
                let length = u32::from_be_bytes(self.pending[1..5].try_into().unwrap()) as usize;
                if length == 0 || length > MAX_DATA {
                    return Err("invalid TCP payload length");
                }
                self.expected += length;
            } else {
                let bytes = self.pending.split_off(5);
                self.pending.clear();
                self.expected = 1;
                return Ok(Some(Event::Data(bytes)));
            }
        }
        Ok(None)
    }

    /// A successful relay must finish at a frame boundary after read-half EOF.
    pub fn finish(&self) -> Result<(), &'static str> {
        if self.connected && self.eof && self.pending.is_empty() {
            Ok(())
        } else {
            Err("incomplete TCP helper stream")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arbitrary_transport_boundaries_preserve_binary_data_and_half_close() {
        let payload: Vec<_> = (0..=255).cycle().take(MAX_DATA).collect();
        let mut wire = vec![CONNECTED, DATA];
        wire.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        wire.extend_from_slice(&payload);
        wire.push(EOF);
        for size in [1, 2, 5, 17, 32768, wire.len()] {
            let mut decoder = Decoder::default();
            let mut events = Vec::new();
            for mut chunk in wire.chunks(size) {
                while !chunk.is_empty() {
                    if let Some(event) = decoder.consume(&mut chunk).unwrap() {
                        events.push(event);
                    }
                }
            }
            assert_eq!(
                events,
                vec![Event::Connected, Event::Data(payload.clone()), Event::Eof]
            );
            decoder.finish().unwrap();
        }
    }

    #[test]
    fn malformed_order_lengths_and_truncation_are_rejected() {
        for wire in [
            vec![DATA],
            vec![EOF],
            vec![CONNECTED, CONNECTED],
            vec![CONNECTED, EOF, DATA],
            vec![CONNECTED, DATA, 0, 0, 0, 0],
            vec![CONNECTED, DATA, 0, 1, 0, 0],
        ] {
            let mut decoder = Decoder::default();
            let mut input = wire.as_slice();
            let result = (|| {
                while !input.is_empty() {
                    decoder.consume(&mut input)?;
                }
                decoder.finish()
            })();
            assert!(result.is_err(), "{wire:?}");
            assert!(decoder.pending.len() <= 5);
        }
        for wire in [
            &[][..],
            &[CONNECTED],
            &[CONNECTED, DATA, 0, 0],
            &[CONNECTED, DATA, 0, 0, 0, 2, 7],
        ] {
            let mut decoder = Decoder::default();
            let mut input = wire;
            while !input.is_empty() {
                decoder.consume(&mut input).unwrap();
            }
            assert!(decoder.finish().is_err());
        }
    }
}
