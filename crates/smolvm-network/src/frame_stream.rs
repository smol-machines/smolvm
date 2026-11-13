//! libkrun unix-stream framing for the virtio-net backend.
//!
//! Context
//! =======
//!
//! libkrun's `krun_add_net_unixstream()` interface does not hand us raw virtio
//! rings or a tap device. Instead, it exposes a Unix stream file descriptor
//! carrying Ethernet frames in a tiny framing protocol:
//!
//! ```text
//! [4-byte big-endian frame length][raw ethernet frame bytes]
//! ```
//!
//! Important details:
//! - the payload is a raw Ethernet frame
//! - there is no virtio-net header on this stream
//! - libkrun adds/removes its internal virtio-net header itself
//! - partial reads and partial writes are normal stream-socket behavior and
//!   must be handled explicitly
//!
//! So this module is not the TCP/IP stack. It is just the bridge between:
//! - libkrun's Unix stream transport
//! - the in-process frame queues consumed by the host smoltcp runtime
//!
//! Data flow:
//!
//! ```text
//! guest -> libkrun -> UnixStream -> run_reader() -> guest_to_host queue
//! host  <- libkrun <- UnixStream <- run_writer() <- host_to_guest queue
//! ```
//!
//! In the broader runtime, this module sits here:
//!
//! ```text
//! libkrun unixstream
//!   <-> FrameStreamBridge
//!   <-> NetworkFrameQueues
//!   <-> VirtioNetworkDevice / smoltcp poll loop
//! ```

use crate::queues::NetworkFrameQueues;
use socket2::Socket;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::sync::Arc;
use std::thread::{self, JoinHandle};

const FRAME_HEADER_LEN: usize = 4;
const SOCKET_SENDBUF_BYTES: usize = 16 * 1024 * 1024;
const MAX_FRAME_LEN: usize = 64 * 1024;

/// Running libkrun unix-stream bridge for one virtio NIC.
///
/// The bridge owns:
/// - the shared AF_UNIX stream socket (used to trigger shutdown via `shutdown`)
/// - a reader thread for guest->host frames
/// - a writer thread for host->guest frames
///
/// The transport is an AF_UNIX stream socket, wrapped in [`socket2::Socket`] so
/// the same code serves Unix hosts and Windows (10 1809+ has native AF_UNIX).
/// On Unix the launcher hands us one end of a `socketpair`; on Windows it hands
/// us the socket it `accept`ed from libkrun on a per-VM path.
///
/// The socket is shared via `Arc` and the reader/writer threads use it through
/// `&Socket` (socket2 implements `Read`/`Write` for `&Socket`), rather than
/// `try_clone`-ing it three ways: duplicating an AF_UNIX socket handle is
/// unreliable on Windows (a clone may not observe the peer's writes), which
/// silently stalled all guest traffic. Concurrent read + write on one socket is
/// safe — the directions are independent.
pub struct FrameStreamBridge {
    socket: Arc<Socket>,
    queues: Arc<NetworkFrameQueues>,
    reader_handle: Option<JoinHandle<()>>,
    writer_handle: Option<JoinHandle<()>>,
}

/// Start the libkrun stream reader and writer threads for one virtio NIC.
///
/// Takes ownership of an already-connected AF_UNIX stream socket to libkrun.
pub fn start_frame_stream_bridge(
    stream: Socket,
    queues: Arc<NetworkFrameQueues>,
) -> io::Result<FrameStreamBridge> {
    set_socket_send_buffer(&stream);
    let socket = Arc::new(stream);

    let reader_socket = socket.clone();
    let reader_handle = thread::Builder::new()
        .name("smolvm-net-reader".into())
        .spawn({
            let queues = queues.clone();
            move || run_reader(reader_socket, queues)
        })?;

    let writer_socket = socket.clone();
    let writer_queues = queues.clone();
    let writer_handle = thread::Builder::new()
        .name("smolvm-net-writer".into())
        .spawn(move || run_writer(writer_socket, writer_queues))?;

    Ok(FrameStreamBridge {
        socket,
        queues,
        reader_handle: Some(reader_handle),
        writer_handle: Some(writer_handle),
    })
}

impl Drop for FrameStreamBridge {
    /// Request shutdown and join the reader/writer workers.
    ///
    /// `shutdown(Shutdown::Both)` is the important part here: it forces any
    /// blocking read/write on the shared socket to wake up and fail, which lets
    /// the threads notice shutdown and return.
    fn drop(&mut self) {
        self.queues.begin_shutdown();
        let _ = self.socket.shutdown(Shutdown::Both);

        if let Some(handle) = self.reader_handle.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.writer_handle.take() {
            let _ = handle.join();
        }
    }
}

/// How much the reader takes from the socket at once, and how much the writer
/// gathers into one write: a frame per syscall (two, header and body) was a
/// large share of the bridge's CPU.
const STREAM_BATCH_BYTES: usize = 256 * 1024;

fn run_reader(reader: Arc<Socket>, queues: Arc<NetworkFrameQueues>) {
    // Reader thread:
    // libkrun -> Unix stream -> guest_to_host queue -> smoltcp poll loop
    let mut sock = io::BufReader::with_capacity(STREAM_BATCH_BYTES, &*reader);
    loop {
        match read_frame(&mut sock) {
            Ok(frame) => {
                if queues.guest_to_host.push(frame).is_ok() {
                    queues.guest_wake.wake();
                } else {
                    tracing::warn!("dropping guest ethernet frame because the host queue is full");
                }
            }
            Err(err) => {
                queues.begin_shutdown();
                tracing::debug!(error = %err, "virtio-net reader thread stopped");
                return;
            }
        }
    }
}

fn run_writer(writer: Arc<Socket>, queues: Arc<NetworkFrameQueues>) {
    // Writer thread:
    // smoltcp / host runtime -> host_to_guest queue -> Unix stream -> libkrun
    let mut sock: &Socket = &writer;
    loop {
        if queues.is_shutting_down() && queues.host_to_guest.is_empty() {
            return;
        }
        match queues.host_wake.wait(None) {
            Ok(true) => queues.host_wake.drain(),
            Ok(false) => continue,
            Err(err) => {
                queues.begin_shutdown();
                tracing::debug!(error = %err, "virtio-net writer wake pipe failed");
                return;
            }
        }

        // Gather the queued frames, each with its length prefix, and hand them
        // to the socket in as few writes as possible.
        let mut batch = Vec::with_capacity(STREAM_BATCH_BYTES);
        loop {
            let frame = queues.host_to_guest.pop();
            if let Some(frame) = &frame {
                if let Err(err) = encode_frame(&mut batch, frame) {
                    tracing::warn!(error = %err, "dropping host ethernet frame");
                }
            }
            if frame.is_none() || batch.len() >= STREAM_BATCH_BYTES {
                if !batch.is_empty() {
                    if let Err(err) = write_all(&mut sock, &batch) {
                        queues.begin_shutdown();
                        tracing::debug!(error = %err, "virtio-net writer thread stopped");
                        return;
                    }
                    batch.clear();
                }
                if frame.is_none() {
                    break;
                }
            }
        }
    }
}

/// Read one raw Ethernet frame using libkrun's 4-byte big-endian length prefix.
///
/// Wire format:
///
/// ```text
/// 0               3 4 ...
/// +----------------+----------------------+
/// | frame_len (BE) | ethernet frame bytes |
/// +----------------+----------------------+
/// ```
///
/// `read_exact` is intentional:
/// - Unix stream sockets are byte streams, not message sockets
/// - one `read` may return only part of the header or part of the frame
/// - the bridge must keep reading until the whole logical frame arrives
///
/// Outcome:
/// - returns the next complete raw Ethernet frame
/// - rejects zero-length or implausibly large frames as protocol errors
pub(crate) fn read_frame<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    reader.read_exact(&mut header)?;
    let frame_len = u32::from_be_bytes(header) as usize;

    if frame_len == 0 || frame_len > MAX_FRAME_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid ethernet frame length: {frame_len}"),
        ));
    }

    let mut frame = vec![0u8; frame_len];
    reader.read_exact(&mut frame)?;
    Ok(frame)
}

/// Append one raw Ethernet frame to `out` with libkrun's 4-byte big-endian
/// length prefix, the encoding [`write_frame`] writes.
pub(crate) fn encode_frame(out: &mut Vec<u8>, frame: &[u8]) -> io::Result<()> {
    if frame.is_empty() || frame.len() > MAX_FRAME_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid ethernet frame length: {}", frame.len()),
        ));
    }
    out.extend_from_slice(&(frame.len() as u32).to_be_bytes());
    out.extend_from_slice(frame);
    Ok(())
}

/// Write one raw Ethernet frame using libkrun's 4-byte big-endian length prefix.
///
/// This is the inverse of [`read_frame`]: the prefix and the frame go out in
/// one write, completed with `write_all` since a stream socket may take only
/// part of a buffer. Used by the pod tap bridge, which forwards one frame at a
/// time; the gateway bridge batches with [`encode_frame`] instead.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn write_frame<W: Write>(writer: &mut W, frame: &[u8]) -> io::Result<()> {
    let mut buf = Vec::with_capacity(FRAME_HEADER_LEN + frame.len());
    encode_frame(&mut buf, frame)?;
    write_all(writer, &buf)?;
    writer.flush()
}

fn write_all<W: Write>(writer: &mut W, mut buf: &[u8]) -> io::Result<()> {
    // This is the stream-socket equivalent of "keep sending until the whole
    // logical message is written". `Write::write` may legally write fewer bytes
    // than requested even on success.
    while !buf.is_empty() {
        let written = writer.write(buf)?;
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short write while sending ethernet frame",
            ));
        }
        buf = &buf[written..];
    }
    Ok(())
}

/// Increase the socket's send-buffer size (SO_SNDBUF). This stream carries
/// Ethernet frames toward libkrun; a large send buffer absorbs bursts so we can
/// queue several frames before libkrun catches up. The OS may clamp the request,
/// and the option is non-critical, so a failure is logged and ignored.
/// `socket2` issues the platform `setsockopt` so this works on Unix and Windows.
fn set_socket_send_buffer(stream: &Socket) {
    if let Err(err) = stream.set_send_buffer_size(SOCKET_SENDBUF_BYTES) {
        tracing::warn!(
            error = %err,
            "failed to increase SO_SNDBUF for virtio-net unixstream"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct PartialWriter {
        written: Vec<u8>,
        chunk_size: usize,
    }

    impl Write for PartialWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let take = buf.len().min(self.chunk_size);
            self.written.extend_from_slice(&buf[..take]);
            Ok(take)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_batch_of_encoded_frames_reads_back_frame_by_frame() {
        let frames: Vec<Vec<u8>> = vec![vec![1, 2, 3], vec![9; 65_534], vec![7]];
        let mut batch = Vec::new();
        for frame in &frames {
            encode_frame(&mut batch, frame).unwrap();
        }
        assert!(encode_frame(&mut batch, &[]).is_err());
        assert!(encode_frame(&mut batch, &vec![0; MAX_FRAME_LEN + 1]).is_err());
        let mut reader = io::BufReader::with_capacity(16, std::io::Cursor::new(batch));
        for frame in &frames {
            assert_eq!(&read_frame(&mut reader).unwrap(), frame);
        }
        assert!(read_frame(&mut reader).is_err(), "nothing after the batch");
    }

    #[test]
    fn write_frame_handles_partial_writes() {
        let mut writer = PartialWriter {
            written: Vec::new(),
            chunk_size: 3,
        };
        write_frame(&mut writer, &[1, 2, 3, 4, 5, 6]).unwrap();
        assert_eq!(writer.written[..4], [0, 0, 0, 6]);
        assert_eq!(writer.written[4..], [1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn read_frame_decodes_length_prefix() {
        let mut input = std::io::Cursor::new(vec![0, 0, 0, 3, 7, 8, 9]);
        assert_eq!(read_frame(&mut input).unwrap(), vec![7, 8, 9]);
    }

    #[cfg(unix)]
    #[test]
    fn unix_stream_round_trip_multiple_frames() {
        use std::os::unix::net::UnixStream;
        let (mut left, mut right) = UnixStream::pair().unwrap();
        write_frame(&mut left, &[1, 2, 3]).unwrap();
        write_frame(&mut left, &[4, 5]).unwrap();

        assert_eq!(read_frame(&mut right).unwrap(), vec![1, 2, 3]);
        assert_eq!(read_frame(&mut right).unwrap(), vec![4, 5]);
    }
}
