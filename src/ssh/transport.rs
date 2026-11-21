//! Cancel either half of a blocked SSH transport without periodic polling.
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{futures::OwnedNotified, Notify},
};

#[derive(Clone, Default)]
pub(super) struct Cancellation {
    closed: Arc<AtomicBool>,
    notify: Arc<Notify>,
}
impl Cancellation {
    pub fn cancel(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }
    pub fn wrap<T>(&self, inner: T) -> Transport<T> {
        Transport {
            inner,
            cancellation: self.clone(),
            reader: Box::pin(self.notify.clone().notified_owned()),
            writer: Box::pin(self.notify.clone().notified_owned()),
        }
    }
}

pub(super) struct Transport<T> {
    inner: T,
    cancellation: Cancellation,
    reader: Pin<Box<OwnedNotified>>,
    writer: Pin<Box<OwnedNotified>>,
}
fn canceled(wait: &mut Pin<Box<OwnedNotified>>, flag: &AtomicBool, cx: &mut Context<'_>) -> bool {
    // Register before checking the flag, closing the notification race.
    wait.as_mut().poll(cx).is_ready() || flag.load(Ordering::SeqCst)
}
fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "SSH connection canceled")
}
impl<T: AsyncRead + Unpin> AsyncRead for Transport<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if canceled(&mut this.reader, &this.cancellation.closed, cx) {
            return Poll::Ready(Err(closed()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for Transport<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if canceled(&mut this.writer, &this.cancellation.closed, cx) {
            return Poll::Ready(Err(closed()));
        }
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if canceled(&mut this.writer, &this.cancellation.closed, cx) {
            return Poll::Ready(Err(closed()));
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if canceled(&mut this.writer, &this.cancellation.closed, cx) {
            return Poll::Ready(Err(closed()));
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn cancellation_wakes_both_blocked_halves() {
        let cancellation = Cancellation::default();
        let (stream, _unread_peer) = tokio::io::duplex(1);
        let (mut reader, mut writer) = tokio::io::split(cancellation.wrap(stream));
        // Fill the peer's buffer so the next write cannot make progress.
        writer.write_all(b"x").await.unwrap();
        let read = tokio::spawn(async move { reader.read_u8().await });
        let write = tokio::spawn(async move { writer.write_all(b"y").await });
        tokio::task::yield_now().await;
        assert!(!read.is_finished());
        assert!(!write.is_finished());
        cancellation.cancel();
        let (read, write) = tokio::time::timeout(Duration::from_secs(1), async {
            (read.await.unwrap(), write.await.unwrap())
        })
        .await
        .expect("both registered wakers must be notified");
        assert_eq!(read.unwrap_err().kind(), io::ErrorKind::ConnectionAborted);
        assert_eq!(write.unwrap_err().kind(), io::ErrorKind::ConnectionAborted);
    }

    #[tokio::test]
    async fn cancellation_before_registration_still_closes_transport() {
        let cancellation = Cancellation::default();
        cancellation.cancel();
        let (stream, _peer) = tokio::io::duplex(1);
        let mut stream = cancellation.wrap(stream);
        assert_eq!(
            stream.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert_eq!(
            stream.write_all(b"x").await.unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
    }
}
