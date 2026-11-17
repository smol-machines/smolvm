//! Event-driven guest-agent streams, including Windows AF_UNIX sockets.
//!
//! Windows uses Tokio's Winsock stream registration for its AF_UNIX handle;
//! only stream reads, writes, readiness and shutdown are used, never TCP
//! addresses or options. No blocking worker or polling thread is retained.

use std::io;
use std::path::Path;

#[cfg(windows)]
pub use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
#[cfg(unix)]
pub use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
#[cfg(unix)]
/// An asynchronous local stream returned by [`connect`].
pub type Stream = tokio::net::UnixStream;
#[cfg(windows)]
/// Winsock stream registration used for the AF_UNIX handle returned by [`connect`].
/// Use its stream I/O methods; TCP addresses and options do not apply.
pub type Stream = tokio::net::TcpStream;

/// Connect without blocking the executor, retaining a deep-path alias until
/// the connect operation has finished.
pub async fn connect(path: &Path) -> io::Result<Stream> {
    let address = krun_socket::SocketPath::new(path)?;
    #[cfg(unix)]
    {
        Stream::connect(address.path()).await
    }
    #[cfg(windows)]
    {
        use socket2::{Domain, SockAddr, Socket, Type};
        let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
        socket.set_nonblocking(true)?;
        match socket.connect(&SockAddr::unix(address.path())?) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
        // Both socket families use the same Winsock stream operations and
        // Mio readiness registration. This conversion transfers ownership;
        // it does not open a TCP connection or change the socket family.
        let stream = Stream::from_std(socket.into())?;
        stream.writable().await?;
        if let Some(error) = stream.take_error()? {
            return Err(error);
        }
        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::uds::UdsListener;
    use std::io::{Read, Write};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn backpressure_yields_and_half_close_keeps_the_reply() {
        let directory = tempfile::tempdir().unwrap();
        let parent = directory.path().join("agent-workspace-".repeat(9));
        std::fs::create_dir(&parent).unwrap();
        let path = parent.join("agent.sock");
        let listener = UdsListener::bind(&path).unwrap();
        let (release, held) = std::sync::mpsc::channel();
        let (accepted, ready) = tokio::sync::oneshot::channel();
        const LEN: usize = 4 * 1024 * 1024;
        let server = std::thread::spawn(move || {
            let mut stream = listener.accept().unwrap();
            stream.as_socket().set_recv_buffer_size(4096).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            accepted.send(()).unwrap();
            held.recv_timeout(Duration::from_secs(5)).unwrap();
            let mut received = Vec::new();
            stream.read_to_end(&mut received).unwrap();
            assert_eq!(received.len(), LEN);
            assert!(received
                .iter()
                .enumerate()
                .all(|(i, b)| *b == (i % 251) as u8));
            stream.write_all(b"complete").unwrap();
        });
        let stream = connect(&path).await.unwrap();
        socket2::SockRef::from(&stream)
            .set_send_buffer_size(4096)
            .unwrap();
        ready.await.unwrap();
        let (mut read, mut write) = stream.into_split();
        let mut sending = tokio::spawn(async move {
            let data: Vec<_> = (0..LEN).map(|i| (i % 251) as u8).collect();
            // Windows can accept one oversized send beyond SO_SNDBUF; a
            // sequence of frames exercises readiness after the queue fills.
            for chunk in data.chunks(4096) {
                write.write_all(chunk).await.unwrap();
            }
            write.shutdown().await.unwrap();
        });
        // This test uses Tokio's single-thread executor: the timer cannot
        // fire if a full socket blocks that executor in a synchronous write.
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut sending)
                .await
                .is_err()
        );
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), sending)
            .await
            .unwrap()
            .unwrap();
        let mut reply = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), read.read_to_end(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply, b"complete");
        server.join().unwrap();
    }

    #[tokio::test]
    async fn cancelled_read_can_resume_and_drop_closes_the_peer() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("agent.sock");
        let listener = UdsListener::bind(&path).unwrap();
        let (release, held) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let mut stream = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            held.recv_timeout(Duration::from_secs(5)).unwrap();
            stream.write_all(b"ready").unwrap();
            assert_eq!(stream.read(&mut [0; 1]).unwrap(), 0);
        });
        let mut stream = connect(&path).await.unwrap();
        let mut reply = [0; 5];
        assert!(
            tokio::time::timeout(Duration::from_millis(25), stream.read_exact(&mut reply))
                .await
                .is_err()
        );
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&reply, b"ready");
        drop(stream);
        server.join().unwrap();
    }

    #[tokio::test]
    async fn missing_or_stale_listener_returns_an_error() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("agent.sock");
        assert!(connect(&path).await.is_err());
        let listener = UdsListener::bind(&path).unwrap();
        drop(listener);
        assert!(tokio::time::timeout(Duration::from_secs(2), connect(&path))
            .await
            .unwrap()
            .is_err());
    }
}
