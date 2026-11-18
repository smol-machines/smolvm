//! Bounded stdin shared by attachments to one execution.
use super::Input;
use parking_lot::Mutex;
use std::{
    collections::VecDeque,
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

const CAPACITY: usize = 256 * 1024;
const MAX_CHUNK: usize = 64 * 1024;
// Charge small messages too, so tiny writes cannot grow metadata forever.
const MIN_CHARGE: usize = 1024;

struct Queued {
    input: Input,
    _capacity: Option<OwnedSemaphorePermit>,
}

struct Generation {
    queue: Mutex<VecDeque<Queued>>,
    capacity: Arc<Semaphore>,
    available: Notify,
    closed: Notify,
    eof: AtomicBool,
}

impl Default for Generation {
    fn default() -> Self {
        Self {
            queue: Mutex::default(),
            capacity: Arc::new(Semaphore::new(CAPACITY)),
            available: Notify::new(),
            closed: Notify::new(),
            eof: AtomicBool::new(false),
        }
    }
}

/// Attachments can queue input before start, but never across an execution exit.
#[derive(Default)]
pub(crate) struct InputQueue(Mutex<Arc<Generation>>);

#[derive(Clone)]
pub(crate) struct InputSender(Arc<Generation>);

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "container input execution ended")
}

impl InputQueue {
    pub(crate) fn sender(&self) -> InputSender {
        InputSender(self.0.lock().clone())
    }

    pub(crate) fn resize(&self, cols: u16, rows: u16) {
        self.sender().resize(cols, rows);
    }

    /// Discard unsent bytes and wake old writers before publishing an exit.
    /// A new attachment may then prepare stdin for the next explicit start.
    pub(crate) fn finish(&self) {
        let mut current = self.0.lock();
        let mut queue = current.queue.lock();
        current.capacity.close();
        queue.clear();
        current.closed.notify_waiters();
        current.available.notify_waiters();
        drop(queue);
        *current = Arc::default();
    }

    pub(crate) async fn next(&self) -> Input {
        let current = self.0.lock().clone();
        loop {
            let available = current.available.notified();
            if let Some(queued) = current.queue.lock().pop_front() {
                return queued.input;
            }
            if current.capacity.is_closed() {
                return Input::Eof;
            }
            available.await;
        }
    }
}

impl InputSender {
    pub(crate) async fn send(&self, input: Input) -> io::Result<()> {
        let charge = match &input {
            Input::Data(bytes) if bytes.len() > MAX_CHUNK => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "stdin chunk exceeds 64 KiB",
                ));
            }
            Input::Data(bytes) if bytes.is_empty() => return Ok(()),
            Input::Data(bytes) => bytes.len().max(MIN_CHARGE),
            Input::Eof => {
                self.eof();
                return Ok(());
            }
            Input::Resize { cols, rows } => {
                self.resize(*cols, *rows);
                return Ok(());
            }
        };
        if self.0.capacity.is_closed() || self.0.eof.load(Ordering::Acquire) {
            return Err(closed());
        }
        let capacity = self
            .0
            .capacity
            .clone()
            .acquire_many_owned(charge as u32)
            .await
            .map_err(|_| closed())?;
        let mut queue = self.0.queue.lock();
        if self.0.capacity.is_closed() || self.0.eof.load(Ordering::Acquire) {
            return Err(closed());
        }
        queue.push_back(Queued {
            input,
            _capacity: Some(capacity),
        });
        self.0.available.notify_one();
        Ok(())
    }

    fn resize(&self, cols: u16, rows: u16) {
        let mut queue = self.0.queue.lock();
        if self.0.capacity.is_closed() {
            return;
        }
        // Only the latest pending size matters. One uncharged control slot
        // keeps resize responsive without allocating per UI event.
        if let Some(queued) = queue
            .iter_mut()
            .find(|q| matches!(q.input, Input::Resize { .. }))
        {
            queued.input = Input::Resize { cols, rows };
        } else {
            queue.push_back(Queued {
                input: Input::Resize { cols, rows },
                _capacity: None,
            });
        }
        self.0.available.notify_one();
    }

    /// One reserved EOF slot preserves stdin-once on attachment cancellation
    /// even when the data budget is exhausted. It follows already queued bytes.
    pub(crate) fn eof(&self) {
        let mut queue = self.0.queue.lock();
        if self.0.capacity.is_closed() || self.0.eof.swap(true, Ordering::AcqRel) {
            return;
        }
        queue.push_back(Queued {
            input: Input::Eof,
            _capacity: None,
        });
        self.0.closed.notify_waiters();
        self.0.available.notify_one();
    }

    pub(crate) async fn closed(&self) {
        let closed = self.0.closed.notified();
        if !self.0.capacity.is_closed() && !self.0.eof.load(Ordering::Acquire) {
            closed.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::timeout;

    #[tokio::test]
    async fn stalled_input_is_bounded_and_resumes_without_losing_bytes() {
        let queue = InputQueue::default();
        let sender = queue.sender();
        for n in 0..4u8 {
            sender.send(Input::Data(vec![n; MAX_CHUNK])).await.unwrap();
        }
        let blocked = sender.send(Input::Data(vec![4; MAX_CHUNK]));
        tokio::pin!(blocked);
        assert!(timeout(Duration::from_millis(20), &mut blocked)
            .await
            .is_err());
        for cols in 1..=1000 {
            queue.resize(cols, 24);
        }
        assert_eq!(sender.0.queue.lock().len(), 5);
        assert!(matches!(queue.next().await, Input::Data(b) if b == vec![0; MAX_CHUNK]));
        timeout(Duration::from_secs(1), &mut blocked)
            .await
            .unwrap()
            .unwrap();
        for n in 1..4u8 {
            assert!(matches!(queue.next().await, Input::Data(b) if b == vec![n; MAX_CHUNK]));
        }
        assert!(matches!(
            queue.next().await,
            Input::Resize {
                cols: 1000,
                rows: 24
            }
        ));
        assert!(matches!(queue.next().await, Input::Data(b) if b == vec![4; MAX_CHUNK]));
        sender.send(Input::Eof).await.unwrap();
        assert!(matches!(queue.next().await, Input::Eof));
    }

    #[tokio::test]
    async fn ending_execution_rejects_old_writers_and_clears_queued_stdin() {
        let queue = InputQueue::default();
        let old = queue.sender();
        for _ in 0..CAPACITY / MIN_CHARGE {
            old.send(Input::Data(vec![1])).await.unwrap();
        }
        let blocked = old.send(Input::Data(vec![2]));
        tokio::pin!(blocked);
        assert!(timeout(Duration::from_millis(20), &mut blocked)
            .await
            .is_err());
        queue.finish();
        assert_eq!(blocked.await.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        assert!(old.send(Input::Data(vec![2])).await.is_err());
        timeout(Duration::from_secs(1), old.closed()).await.unwrap();
        let new = queue.sender();
        new.send(Input::Data(vec![3])).await.unwrap();
        assert!(matches!(queue.next().await, Input::Data(b) if b == vec![3]));
        assert!(old.0.queue.lock().is_empty());
    }

    #[tokio::test]
    async fn oversize_input_is_rejected_without_consuming_capacity() {
        let queue = InputQueue::default();
        let sender = queue.sender();
        assert_eq!(
            sender
                .send(Input::Data(vec![0; MAX_CHUNK + 1]))
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(sender.0.capacity.available_permits(), CAPACITY);
    }

    #[tokio::test]
    async fn eof_with_a_full_queue_is_ordered_and_cannot_be_duplicated() {
        let queue = InputQueue::default();
        let sender = queue.sender();
        for n in 0..4u8 {
            sender.send(Input::Data(vec![n; MAX_CHUNK])).await.unwrap();
        }
        for _ in 0..1000 {
            sender.eof();
        }
        assert_eq!(sender.0.queue.lock().len(), 5);
        assert_eq!(
            timeout(Duration::from_secs(1), sender.send(Input::Data(vec![5])))
                .await
                .unwrap()
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
        for n in 0..4u8 {
            assert!(matches!(queue.next().await, Input::Data(b) if b == vec![n; MAX_CHUNK]));
        }
        assert!(matches!(queue.next().await, Input::Eof));
        sender.eof();
        assert!(sender.0.queue.lock().is_empty());
        assert!(sender.send(Input::Data(vec![5])).await.is_err());
    }
}
