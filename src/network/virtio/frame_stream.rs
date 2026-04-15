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

use crate::network::virtio::queues::NetworkFrameQueues;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::thread::{self, JoinHandle};

const FRAME_HEADER_LEN: usize = 4;
const SOCKET_SENDBUF_BYTES: libc::c_int = 16 * 1024 * 1024;
const MAX_FRAME_LEN: usize = 64 * 1024;

/// Running libkrun unix-stream bridge for one virtio NIC.
///
/// The bridge owns:
/// - a control clone of the Unix stream used to trigger shutdown
/// - a reader thread for guest->host frames
/// - a writer thread for host->guest frames
pub struct FrameStreamBridge {
    control: UnixStream,
    queues: Arc<NetworkFrameQueues>,
    reader_handle: Option<JoinHandle<()>>,
    writer_handle: Option<JoinHandle<()>>,
}

/// Start the libkrun unix-stream reader and writer threads for one virtio NIC.
pub fn start_frame_stream_bridge(
    fd: RawFd,
    queues: Arc<NetworkFrameQueues>,
) -> io::Result<FrameStreamBridge> {
    // SAFETY: ownership of the provided host-side socket fd transfers here.
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    set_socket_send_buffer(&stream)?;
    // create 3 handles for the unix socket
    let control = stream.try_clone()?;
    let reader = stream.try_clone()?;
    let writer = stream;

    let reader_handle = thread::Builder::new()
        .name("smolvm-net-reader".into())
        .spawn({
            let queues = queues.clone();
            move || run_reader(reader, queues)
        })?;

    let writer_queues = queues.clone();
    let writer_handle = thread::Builder::new()
        .name("smolvm-net-writer".into())
        .spawn(move || run_writer(writer, writer_queues))?;

    Ok(FrameStreamBridge {
        control,
        queues,
        reader_handle: Some(reader_handle),
        writer_handle: Some(writer_handle),
    })
}

impl Drop for FrameStreamBridge {
    /// Request shutdown and join the reader/writer workers.
    ///
    /// `shutdown(Shutdown::Both)` is the important part here: it forces any
    /// blocking read/write on the other stream clones to wake up and fail,
    /// which lets the threads notice shutdown and return.
    fn drop(&mut self) {
        self.queues.begin_shutdown();
        let _ = self.control.shutdown(Shutdown::Both);

        if let Some(handle) = self.reader_handle.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.writer_handle.take() {
            let _ = handle.join();
        }
    }
}

fn run_reader(mut reader: UnixStream, queues: Arc<NetworkFrameQueues>) {
    // Reader thread:
    // libkrun -> Unix stream -> guest_to_host queue -> smoltcp poll loop
    loop {
        match read_frame(&mut reader) {
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

fn run_writer(mut writer: UnixStream, queues: Arc<NetworkFrameQueues>) {
    // Writer thread:
    // smoltcp / host runtime -> host_to_guest queue -> Unix stream -> libkrun
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

        while let Some(frame) = queues.host_to_guest.pop() {
            if let Err(err) = write_frame(&mut writer, &frame) {
                queues.begin_shutdown();
                tracing::debug!(error = %err, "virtio-net writer thread stopped");
                return;
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

/// Write one raw Ethernet frame using libkrun's 4-byte big-endian length prefix.
///
/// This is the inverse of [`read_frame`]:
///
/// ```text
/// write 4-byte BE length
/// write raw frame bytes
/// flush stream
/// ```
///
/// `write_all` is used instead of a single `write` because stream sockets may
/// accept only part of the buffer. The caller should not need to reason about
/// partial-write state; this helper completes the logical frame write or fails.
pub(crate) fn write_frame<W: Write>(writer: &mut W, frame: &[u8]) -> io::Result<()> {
    if frame.is_empty() || frame.len() > MAX_FRAME_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid ethernet frame length: {}", frame.len()),
        ));
    }

    let header = (frame.len() as u32).to_be_bytes();
    write_all(writer, &header)?;
    write_all(writer, frame)?;
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

/// set_socket_send_buffer is used to set the "send buffer size" of the provided unix socket.this unix socket is
/// used to send the Ethernet frames toward libkrun. Setting a large "send buffer size" is helpful for bursty
/// traffics. This is because we can burst multiple Ethernet frames before the consumer catches up. The
/// kernel may clamp the requested size, so failure here is logged but not treated as fatal.
fn set_socket_send_buffer(stream: &UnixStream) -> io::Result<()> {
    // using the default 16 MiB as the send buffer size
    let size = SOCKET_SENDBUF_BYTES;
    // syscall to set the option of a provided socket. Read this:
    let result = unsafe {
        libc::setsockopt(
            // this is the fd of the target socket.
            stream.as_raw_fd(),
            // the option to be set is a general socket-level option
            libc::SOL_SOCKET,
            // the option name is “the send buffer size”
            libc::SO_SNDBUF,
            // and here is the value we want to set for that option (passing it as a c_int pointer)
            (&size as *const libc::c_int).cast(),
            // this is needed only because setsockopt is a generic syscall,
            // and the kernel needs to know how many bytes that option value takes
            std::mem::size_of_val(&size) as libc::socklen_t,
        )
    };
    if result < 0 {
        tracing::warn!(
            error = %io::Error::last_os_error(),
            "failed to increase SO_SNDBUF for virtio-net unixstream"
        );
        return Ok(());
    }
    Ok(())
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

    #[test]
    fn unix_stream_round_trip_multiple_frames() {
        let (mut left, mut right) = UnixStream::pair().unwrap();
        write_frame(&mut left, &[1, 2, 3]).unwrap();
        write_frame(&mut left, &[4, 5]).unwrap();

        assert_eq!(read_frame(&mut right).unwrap(), vec![1, 2, 3]);
        assert_eq!(read_frame(&mut right).unwrap(), vec![4, 5]);
    }
}
