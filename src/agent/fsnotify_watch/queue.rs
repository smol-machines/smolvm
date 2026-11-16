//! Bounded, nonblocking dirty paths; overflow requests state reconciliation.
use notify::Event;
use parking_lot::{Condvar, Mutex};
use std::{
    collections::BTreeSet,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
const CAPACITY: usize = 256;
#[derive(Default)]
struct Pending {
    paths: BTreeSet<PathBuf>,
    all: bool,
}
pub(super) struct EventQueue {
    pending: Mutex<Pending>,
    changed: Condvar,
    stop: Arc<AtomicBool>,
}
#[derive(Debug)]
pub(super) enum Work {
    Paths(Vec<PathBuf>),
    All,
}
impl EventQueue {
    pub fn new(stop: Arc<AtomicBool>) -> Self {
        Self {
            pending: Mutex::new(Pending::default()),
            changed: Condvar::new(),
            stop,
        }
    }
    pub fn push(&self, event: notify::Result<Event>) {
        if self.stop.load(Ordering::SeqCst) {
            return;
        }
        let mut pending = self.pending.lock();
        if pending.all {
            return;
        }
        match event {
            Ok(event) if !event.need_rescan() => {
                if matches!(event.kind, notify::EventKind::Access(_)) {
                    return;
                }
                for path in event.paths {
                    if pending.paths.iter().any(|p| path.starts_with(p)) {
                        continue;
                    }
                    pending.paths.retain(|p| !p.starts_with(&path));
                    if pending.paths.len() == CAPACITY {
                        pending.paths.clear();
                        pending.all = true;
                        break;
                    }
                    pending.paths.insert(path);
                }
            }
            _ => {
                pending.paths.clear();
                pending.all = true;
            }
        }
        self.changed.notify_one();
    }
    pub fn retry_all(&self) {
        let mut pending = self.pending.lock();
        pending.paths.clear();
        pending.all = true;
        self.changed.notify_one();
    }
    pub fn take(&self, timeout: Duration) -> Option<Work> {
        let deadline = Instant::now() + timeout;
        let mut pending = self.pending.lock();
        let mut burst_deadline = None;
        loop {
            if self.stop.load(Ordering::SeqCst) {
                return None;
            }
            if pending.all {
                pending.all = false;
                return Some(Work::All);
            }
            if !pending.paths.is_empty() {
                let burst = *burst_deadline.get_or_insert_with(|| {
                    (Instant::now() + Duration::from_millis(25)).min(deadline)
                });
                if let Some(remaining) = burst.checked_duration_since(Instant::now()) {
                    self.changed.wait_for(&mut pending, remaining);
                    continue;
                }
                return Some(Work::Paths(
                    std::mem::take(&mut pending.paths).into_iter().collect(),
                ));
            }
            let remaining = deadline.checked_duration_since(Instant::now())?;
            self.changed
                .wait_for(&mut pending, remaining.min(Duration::from_millis(50)));
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn write(p: impl Into<PathBuf>) -> notify::Result<Event> {
        Ok(Event::new(notify::EventKind::Any).add_path(p.into()))
    }
    #[test]
    fn a_disconnected_consumer_never_blocks_the_native_callback() {
        let q = Arc::new(EventQueue::new(Arc::new(AtomicBool::new(false))));
        let producer = q.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            for i in 0..100000 {
                producer.push(write(format!("/source/file-{i}")));
            }
            tx.send(()).unwrap();
        });
        rx.recv_timeout(Duration::from_secs(5))
            .expect("callback waited for guest delivery");
        worker.join().unwrap();
        assert!(q.pending.lock().paths.len() <= CAPACITY);
        assert!(matches!(q.take(Duration::ZERO), Some(Work::All)));
        assert!(q.take(Duration::ZERO).is_none());
    }
    #[test]
    fn changes_during_recovery_and_failed_delivery_remain_pending() {
        let q = EventQueue::new(Arc::new(AtomicBool::new(false)));
        q.retry_all();
        assert!(matches!(q.take(Duration::ZERO), Some(Work::All)));
        q.push(write("/source/after-scan-start"));
        assert!(
            matches!(q.take(Duration::ZERO),Some(Work::Paths(p)) if p==[PathBuf::from("/source/after-scan-start")])
        );
        q.retry_all();
        q.push(write("/source/while-disconnected"));
        assert!(matches!(q.take(Duration::ZERO), Some(Work::All)));
    }
    #[test]
    fn native_overflow_is_not_mistaken_for_an_empty_event() {
        let q = EventQueue::new(Arc::new(AtomicBool::new(false)));
        q.push(Ok(
            Event::new(notify::EventKind::Other).set_flag(notify::event::Flag::Rescan)
        ));
        assert!(matches!(q.take(Duration::ZERO), Some(Work::All)));
    }
    #[test]
    fn parents_coalesce_descendants_but_not_similarly_named_siblings() {
        let q = EventQueue::new(Arc::new(AtomicBool::new(false)));
        q.push(write("/source/a/child"));
        q.push(write("/source/a-sibling"));
        q.push(write("/source/a"));
        assert!(
            matches!(q.take(Duration::ZERO),Some(Work::Paths(p)) if p==[PathBuf::from("/source/a"),PathBuf::from("/source/a-sibling")])
        );
    }
}
