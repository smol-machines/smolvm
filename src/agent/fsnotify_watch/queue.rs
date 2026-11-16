//! Bounded pending host changes, including while the guest cannot accept them.
use notify::Event;
use parking_lot::{Condvar, Mutex};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc::RecvTimeoutError, Arc};
use std::time::{Duration, Instant};

const CAPACITY: usize = 256;
const STOP_CHECK: Duration = Duration::from_millis(50);

pub(super) struct EventQueue {
    pending: Mutex<VecDeque<notify::Result<Event>>>,
    changed: Condvar,
    stop: Arc<AtomicBool>,
}

impl EventQueue {
    pub(super) fn new(stop: Arc<AtomicBool>) -> Self {
        Self {
            pending: Mutex::new(VecDeque::new()),
            changed: Condvar::new(),
            stop,
        }
    }

    pub(super) fn push(&self, event: notify::Result<Event>) {
        let mut pending = self.pending.lock();
        while !self.stop.load(Ordering::SeqCst) {
            if let Ok(new) = &event {
                // Delivery reads the current host metadata, not an event's old
                // timestamp. Repeated changes of the same kind and path need
                // one announcement; keep create/remove/rename kinds distinct.
                if pending.iter().any(|queued| {
                    queued.as_ref().is_ok_and(|old| {
                        old.kind == new.kind
                            && old.paths == new.paths
                            && old.need_rescan() == new.need_rescan()
                    })
                }) {
                    return;
                }
            }
            if pending.len() < CAPACITY {
                pending.push_back(event);
                self.changed.notify_all();
                return;
            }
            // Backpressure distinct changes instead of allocating indefinitely
            // or silently discarding them. Never block watcher teardown: the
            // OS callback also observes the VM owner's stop flag.
            self.changed.wait_for(&mut pending, STOP_CHECK);
        }
    }

    pub(super) fn recv_timeout(
        &self,
        timeout: Duration,
    ) -> Result<notify::Result<Event>, RecvTimeoutError> {
        let deadline = Instant::now() + timeout;
        let mut pending = self.pending.lock();
        loop {
            if self.stop.load(Ordering::SeqCst) {
                return Err(RecvTimeoutError::Disconnected);
            }
            if let Some(event) = pending.pop_front() {
                self.changed.notify_all();
                return Ok(event);
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Err(RecvTimeoutError::Timeout);
            };
            self.changed.wait_for(&mut pending, remaining);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use notify::event::{CreateKind, ModifyKind, RemoveKind};
    use std::path::PathBuf;

    fn change(path: impl Into<PathBuf>) -> notify::Result<Event> {
        Ok(Event::new(notify::EventKind::Modify(ModifyKind::Any)).add_path(path.into()))
    }

    #[test]
    fn repeated_edits_do_not_grow_a_disconnected_guests_backlog() {
        let queue = EventQueue::new(Arc::new(AtomicBool::new(false)));
        for _ in 0..100_000 {
            queue.push(change("/project/app.rs"));
        }
        assert_eq!(queue.pending.lock().len(), 1);
        let event = queue.recv_timeout(Duration::ZERO).unwrap().unwrap();
        assert_eq!(event.paths, vec![PathBuf::from("/project/app.rs")]);
    }

    #[test]
    fn different_kinds_and_names_are_preserved() {
        let queue = EventQueue::new(Arc::new(AtomicBool::new(false)));
        let kinds = [
            notify::EventKind::Create(CreateKind::File),
            notify::EventKind::Modify(ModifyKind::Any),
            notify::EventKind::Remove(RemoveKind::File),
        ];
        for kind in kinds {
            queue.push(Ok(Event::new(kind).add_path("/project/app.rs".into())));
        }
        queue.push(change("/project/other.rs"));
        for kind in kinds {
            assert_eq!(
                queue.recv_timeout(Duration::ZERO).unwrap().unwrap().kind,
                kind
            );
        }
        assert_eq!(queue.pending.lock().len(), 1);
    }

    #[test]
    fn a_full_queue_preserves_distinct_changes_when_delivery_resumes() {
        let stop = Arc::new(AtomicBool::new(false));
        let queue = Arc::new(EventQueue::new(stop));
        for index in 0..CAPACITY {
            queue.push(change(format!("/project/{index}")));
        }
        let producer = {
            let queue = queue.clone();
            std::thread::spawn(move || {
                for index in CAPACITY..CAPACITY * 4 {
                    queue.push(change(format!("/project/{index}")));
                }
            })
        };
        std::thread::sleep(Duration::from_millis(100));
        assert!(!producer.is_finished());
        assert_eq!(queue.pending.lock().len(), CAPACITY);
        for index in 0..CAPACITY * 4 {
            let event = queue.recv_timeout(Duration::from_secs(2)).unwrap().unwrap();
            assert_eq!(
                event.paths,
                vec![PathBuf::from(format!("/project/{index}"))]
            );
            assert!(queue.pending.lock().len() <= CAPACITY);
        }
        producer.join().unwrap();
    }

    #[test]
    fn shutdown_releases_a_callback_waiting_on_a_full_queue() {
        let stop = Arc::new(AtomicBool::new(false));
        let queue = Arc::new(EventQueue::new(stop.clone()));
        for index in 0..CAPACITY {
            queue.push(change(format!("/project/{index}")));
        }
        let producer = {
            let queue = queue.clone();
            std::thread::spawn(move || queue.push(change("/project/last")))
        };
        std::thread::sleep(Duration::from_millis(100));
        assert!(!producer.is_finished());
        let start = Instant::now();
        stop.store(true, Ordering::SeqCst);
        producer.join().unwrap();
        assert!(start.elapsed() < Duration::from_secs(1));
    }
}
