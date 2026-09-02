//! Server-side RFC 6455: the handshake reply and a `Read + Write` adapter
//! that turns WebSocket frames back into a plain byte stream.
//!
//! This exists so a browser can drive the RFB server on the same port a native
//! VNC viewer uses. RFB is a byte stream while WebSocket carries messages, so
//! the adapter deliberately discards message boundaries and concatenates
//! payloads: nothing above it has to know the transport is framed.

use std::io::{ErrorKind, Read, Result, Write};

use base64::Engine as _;

/// RFC 6455 §4.2.2: the fixed GUID a server appends to the client's key
/// before hashing.
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

const OP_CONTINUATION: u8 = 0x0;
const OP_TEXT: u8 = 0x1;
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xa;

/// Refuse to buffer a single frame larger than this. A client controls the
/// declared length, so an unbounded value would let one header allocate
/// arbitrary memory before a single byte of payload arrives.
const MAX_FRAME: u64 = 16 << 20;

/// The value for `Sec-WebSocket-Accept`, proving to the client that we
/// understood the handshake rather than echoing bytes back.
pub fn accept_key(client_key: &str) -> String {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(client_key.as_bytes());
    hasher.update(WS_GUID.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
}

/// A WebSocket seen as a byte stream. Reads yield payload bytes in order;
/// each write becomes one binary frame.
pub struct WsStream<S> {
    inner: S,
    /// Payload decoded from frames but not yet handed to the reader.
    pending: Vec<u8>,
    /// How much of `pending` has been consumed.
    read_at: usize,
    /// The peer sent Close, or we did: further reads are EOF.
    closed: bool,
}

impl<S: Read + Write> WsStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            pending: Vec::new(),
            read_at: 0,
            closed: false,
        }
    }

    /// Send exactly one binary message, preserving its boundary for clients
    /// such as WebCodecs that consume one encoded video access unit at a time.
    #[cfg(unix)]
    pub fn write_binary(&mut self, payload: &[u8]) -> Result<()> {
        self.send_frame(OP_BINARY, payload)
    }

    /// Read frames until one carries payload. Control frames are answered
    /// here and never surface to the caller.
    ///
    /// Returns `false` once the stream is closed.
    fn next_payload(&mut self) -> Result<bool> {
        loop {
            let mut head = [0u8; 2];
            match self.inner.read_exact(&mut head) {
                Ok(()) => {}
                // A peer that vanishes mid-session is a normal end of
                // session here, not an error worth propagating upward.
                Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
                    self.closed = true;
                    return Ok(false);
                }
                Err(e) => return Err(e),
            }

            let opcode = head[0] & 0x0f;
            let masked = head[1] & 0x80 != 0;
            let len = match head[1] & 0x7f {
                126 => {
                    let mut ext = [0u8; 2];
                    self.inner.read_exact(&mut ext)?;
                    u16::from_be_bytes(ext) as u64
                }
                127 => {
                    let mut ext = [0u8; 8];
                    self.inner.read_exact(&mut ext)?;
                    u64::from_be_bytes(ext)
                }
                n => n as u64,
            };

            // RFC 6455 §5.1 requires every client frame to be masked. Browsers
            // always do; refusing an unmasked one keeps us from decoding a
            // stream some other peer framed differently than we assume.
            if !masked {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "websocket client frame was not masked",
                ));
            }
            if len > MAX_FRAME {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "websocket frame exceeds the maximum accepted size",
                ));
            }

            let mut mask = [0u8; 4];
            self.inner.read_exact(&mut mask)?;

            let mut payload = vec![0u8; len as usize];
            self.inner.read_exact(&mut payload)?;
            for (i, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask[i & 3];
            }

            match opcode {
                OP_BINARY | OP_TEXT | OP_CONTINUATION => {
                    // Fragmentation is irrelevant to a byte stream: whatever
                    // arrived is simply the next bytes.
                    if payload.is_empty() {
                        continue;
                    }
                    self.pending = payload;
                    self.read_at = 0;
                    return Ok(true);
                }
                OP_PING => {
                    self.send_frame(OP_PONG, &payload)?;
                }
                OP_PONG => {}
                OP_CLOSE => {
                    // Echo the close so the browser sees a clean shutdown
                    // rather than a dropped socket.
                    let _ = self.send_frame(OP_CLOSE, &payload);
                    self.closed = true;
                    return Ok(false);
                }
                other => {
                    return Err(std::io::Error::new(
                        ErrorKind::InvalidData,
                        format!("unknown websocket opcode {other}"),
                    ));
                }
            }
        }
    }

    /// Write one frame. Server frames are never masked.
    fn send_frame(&mut self, opcode: u8, payload: &[u8]) -> Result<()> {
        let mut header = Vec::with_capacity(10);
        header.push(0x80 | opcode); // FIN + opcode
        match payload.len() {
            n if n < 126 => header.push(n as u8),
            n if n <= u16::MAX as usize => {
                header.push(126);
                header.extend_from_slice(&(n as u16).to_be_bytes());
            }
            n => {
                header.push(127);
                header.extend_from_slice(&(n as u64).to_be_bytes());
            }
        }
        self.inner.write_all(&header)?;
        self.inner.write_all(payload)
    }
}

impl<S: Read + Write> Read for WsStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        while self.read_at >= self.pending.len() {
            if self.closed || !self.next_payload()? {
                return Ok(0);
            }
        }
        let n = (self.pending.len() - self.read_at).min(buf.len());
        buf[..n].copy_from_slice(&self.pending[self.read_at..self.read_at + n]);
        self.read_at += n;
        Ok(n)
    }
}

impl<S: Read + Write> Write for WsStream<S> {
    /// One frame per call. The RFB code writes a header then a payload, so
    /// this costs a few bytes of framing per update rather than the buffering
    /// machinery a flush-based design would need.
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.send_frame(OP_BINARY, buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A stream that reads from a fixed script and records what was written.
    struct Duplex {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl Read for Duplex {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            self.input.read(buf)
        }
    }

    impl Write for Duplex {
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            self.output.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> Result<()> {
            Ok(())
        }
    }

    fn duplex(input: Vec<u8>) -> WsStream<Duplex> {
        WsStream::new(Duplex {
            input: Cursor::new(input),
            output: Vec::new(),
        })
    }

    /// Build a masked client frame the way a browser would.
    fn client_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mask = [0xa1u8, 0xb2, 0xc3, 0xd4];
        let mut out = vec![0x80 | opcode];
        match payload.len() {
            n if n < 126 => out.push(0x80 | n as u8),
            n if n <= u16::MAX as usize => {
                out.push(0x80 | 126);
                out.extend_from_slice(&(n as u16).to_be_bytes());
            }
            n => {
                out.push(0x80 | 127);
                out.extend_from_slice(&(n as u64).to_be_bytes());
            }
        }
        out.extend_from_slice(&mask);
        out.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i & 3]));
        out
    }

    #[test]
    fn accept_key_matches_the_rfc_example() {
        // RFC 6455 §1.3 worked example.
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn masked_payload_is_decoded() {
        let mut ws = duplex(client_frame(OP_BINARY, b"RFB 003.008\n"));
        let mut got = [0u8; 12];
        ws.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"RFB 003.008\n");
    }

    #[test]
    fn frames_concatenate_into_one_byte_stream() {
        // Message boundaries must not be visible to the RFB code above: a
        // read spanning two frames has to succeed.
        let mut input = client_frame(OP_BINARY, b"abc");
        input.extend(client_frame(OP_BINARY, b"def"));
        let mut ws = duplex(input);
        let mut got = [0u8; 6];
        ws.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"abcdef");
    }

    #[test]
    fn continuation_frames_are_just_more_bytes() {
        let mut input = client_frame(OP_BINARY, b"one");
        input.extend(client_frame(OP_CONTINUATION, b"two"));
        let mut ws = duplex(input);
        let mut got = [0u8; 6];
        ws.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"onetwo");
    }

    #[test]
    fn ping_is_answered_with_pong_and_hidden_from_the_reader() {
        let mut input = client_frame(OP_PING, b"hi");
        input.extend(client_frame(OP_BINARY, b"data"));
        let mut ws = duplex(input);
        let mut got = [0u8; 4];
        ws.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"data");
        // A pong carrying the ping's payload went back, unmasked.
        assert_eq!(ws.inner.output, vec![0x80 | OP_PONG, 2, b'h', b'i']);
    }

    #[test]
    fn close_reads_as_end_of_stream() {
        let mut ws = duplex(client_frame(OP_CLOSE, &[]));
        let mut got = [0u8; 1];
        assert_eq!(ws.read(&mut got).unwrap(), 0);
    }

    #[test]
    fn peer_vanishing_is_end_of_stream_not_an_error() {
        let mut ws = duplex(Vec::new());
        let mut got = [0u8; 1];
        assert_eq!(ws.read(&mut got).unwrap(), 0);
    }

    #[test]
    fn unmasked_client_frame_is_rejected() {
        // Same frame as a browser would send, minus the mask bit.
        let mut ws = duplex(vec![0x80 | OP_BINARY, 3, b'a', b'b', b'c']);
        let mut got = [0u8; 3];
        assert!(ws.read_exact(&mut got).is_err());
    }

    #[test]
    fn oversized_frame_is_refused_before_allocating() {
        let mut input = vec![0x80 | OP_BINARY, 0x80 | 127];
        input.extend_from_slice(&(MAX_FRAME + 1).to_be_bytes());
        input.extend_from_slice(&[0u8; 4]); // mask
        let mut ws = duplex(input);
        let mut got = [0u8; 1];
        assert!(ws.read(&mut got).is_err());
    }

    #[test]
    fn writes_become_unmasked_binary_frames() {
        let mut ws = duplex(Vec::new());
        ws.write_all(b"xy").unwrap();
        assert_eq!(ws.inner.output, vec![0x80 | OP_BINARY, 2, b'x', b'y']);
    }

    #[test]
    fn large_writes_use_an_extended_length() {
        let mut ws = duplex(Vec::new());
        let payload = vec![7u8; 1000];
        ws.write_all(&payload).unwrap();
        assert_eq!(&ws.inner.output[..4], &[0x80 | OP_BINARY, 126, 0x03, 0xe8]);
        assert_eq!(&ws.inner.output[4..], &payload[..]);
    }
}
