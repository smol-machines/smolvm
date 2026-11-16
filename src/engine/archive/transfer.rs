//! Bounded bridges between the async agent connection and the synchronous tar codec.
use axum::body::Bytes;
use std::io::{self, Read, Write};
use tokio::sync::mpsc;

const CHUNK: usize = 64 * 1024;
const QUEUE: usize = 4;
pub(super) type Sender = mpsc::Sender<io::Result<Bytes>>;
pub(super) type Receiver = mpsc::Receiver<io::Result<Bytes>>;

pub(super) fn channel() -> (Sender, Receiver) {
    mpsc::channel(QUEUE)
}

pub(super) struct Reader {
    receiver: Receiver,
    pending: Bytes,
}
impl Reader {
    pub(super) fn new(receiver: Receiver) -> Self {
        Self {
            receiver,
            pending: Bytes::new(),
        }
    }
}
impl Read for Reader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        while self.pending.is_empty() {
            match self.receiver.blocking_recv() {
                Some(Ok(bytes)) => self.pending = bytes,
                Some(Err(error)) => return Err(error),
                None => return Ok(0),
            }
        }
        let count = out.len().min(self.pending.len());
        out[..count].copy_from_slice(&self.pending[..count]);
        self.pending = self.pending.slice(count..);
        Ok(count)
    }
}

pub(super) struct Writer {
    sender: Sender,
    pending: Vec<u8>,
}
impl Writer {
    pub(super) fn new(sender: Sender) -> Self {
        Self {
            sender,
            pending: Vec::with_capacity(CHUNK),
        }
    }
}
impl Write for Writer {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let count = input.len().min(CHUNK - self.pending.len());
        self.pending.extend_from_slice(&input[..count]);
        if self.pending.len() == CHUNK {
            self.flush()?;
        }
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        if !self.pending.is_empty() {
            let bytes = std::mem::replace(&mut self.pending, Vec::with_capacity(CHUNK));
            self.sender.blocking_send(Ok(bytes.into())).map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "archive download disconnected")
            })?;
        }
        Ok(())
    }
}

/// tar::Builder writes a footer in Drop; suppress it after a source failure,
/// otherwise a client can interpret the partial archive as a successful copy.
pub(super) struct AbortWriter<W> {
    inner: W,
    aborted: bool,
}
impl<W> AbortWriter<W> {
    pub(super) fn new(inner: W) -> Self {
        Self {
            inner,
            aborted: false,
        }
    }
    pub(super) fn abort(&mut self) {
        self.aborted = true;
    }
    pub(super) fn into_inner(self) -> W {
        self.inner
    }
}
impl<W: Write> Write for AbortWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.aborted {
            return Err(io::Error::other("archive source failed"));
        }
        self.inner.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.aborted {
            return Err(io::Error::other("archive source failed"));
        }
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn a_slow_consumer_backpressures_and_disconnect_unblocks_the_writer() {
        let (sender, receiver) = channel();
        let (started, ready) = tokio::sync::oneshot::channel();
        let mut producer = tokio::task::spawn_blocking(move || {
            let mut writer = Writer::new(sender);
            started.send(()).unwrap();
            writer.write_all(&vec![7; 16 * 1024 * 1024])
        });
        ready.await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut producer)
                .await
                .is_err()
        );
        drop(receiver);
        let error = tokio::time::timeout(std::time::Duration::from_secs(2), producer)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    }
}
