//! Shared-memory command/completion rings: the low-latency transport between
//! a guest shim and the host CUDA service.
//!
//! The guest allocates two rings in its own RAM (request: guest→host,
//! completion: host→guest) and hands their guest-physical page lists to the
//! host over the bootstrap vsock connection (`Request::RingSetup`). The host
//! already maps guest RAM for zero-copy transfers, so both sides then share
//! the rings at memory speed: a sync round-trip costs ~1-2µs of polling
//! instead of a vsock wakeup (~50-70µs).
//!
//! Layout (one ring): a 64-byte header page-prefix followed by `capacity`
//! fixed-size records. Records never straddle a page boundary
//! (`RECORD_SIZE` divides the page size), because guest pages are physically
//! discontiguous — each side addresses record `i` through a per-page mapping
//! table, not one flat pointer.
//!
//! Record publish protocol: the producer writes payload then `len`, then
//! stores the slot's wrapping sequence number with release ordering; the
//! consumer reads the sequence with acquire ordering and only then the
//! payload — a torn read is impossible because a slot's sequence only
//! becomes valid after its bytes are complete.
//!
//! Doorbells: pure polling burns a core, so each side may park. A consumer
//! that decides to sleep sets `PARKED` in its ring's header *then re-checks
//! for new records* (the producer's publish-then-check mirrors it) and blocks
//! on the bootstrap vsock socket; a producer that sees `PARKED` after
//! publishing clears it and writes one byte to the socket. The socket carries
//! only doorbells after ring setup — every request and response rides the
//! rings, preserving the single program-ordered queue.

use std::sync::atomic::{AtomicU32, Ordering};

/// Bytes per record. Divides 4096 so records never straddle a guest page.
/// Sized so common frames stay inline: a Triton launch with ~30 pointer args
/// serializes to ~300 bytes, cudnn attribute blobs run to ~1 KiB.
pub const RECORD_SIZE: usize = 1024;
/// Per-record header: sequence (u32) + payload length (u32).
pub const RECORD_HDR: usize = 8;
/// Largest payload that fits inline in one record.
pub const INLINE_MAX: usize = RECORD_SIZE - RECORD_HDR;
/// Ring header size (one cache line, at the start of the first page).
pub const HEADER_SIZE: usize = 64;

/// Consumer-parked flag in the header `flags` word: the producer must clear
/// it and kick the doorbell after publishing.
pub const FLAG_PARKED: u32 = 1;

/// Payload `len` flag bit: the record body is not the payload itself but a
/// list of `(gpa: u64, len: u64)` segments the consumer must gather from
/// guest RAM (requests too large for a record — H2D byte-ship, fatbins).
pub const LEN_INDIRECT: u32 = 1 << 31;

/// Offsets within the 64-byte header.
const OFF_HEAD: usize = 0; // producer: next sequence to publish (u32)
const OFF_TAIL: usize = 8; // consumer: next sequence to consume (u32)
const OFF_FLAGS: usize = 16; // FLAG_PARKED etc.

/// One side of a ring: raw per-page pointers into the shared memory. The
/// guest builds this over its own allocation; the host over its mapping of
/// the same guest pages. `pages[0]` begins with the header; records start at
/// `HEADER_SIZE` and continue across pages (each page after the first is
/// wall-to-wall records).
pub struct Ring {
    pages: Vec<*mut u8>,
    page_size: usize,
    capacity: u32,
}

// SAFETY: the ring is shared memory by design; all cross-thread access goes
// through atomics with acquire/release ordering per the publish protocol.
unsafe impl Send for Ring {}
unsafe impl Sync for Ring {}

impl Ring {
    /// Records that fit in `pages` (first page loses `HEADER_SIZE` bytes).
    pub fn capacity_for(num_pages: usize, page_size: usize) -> u32 {
        let first = (page_size - HEADER_SIZE) / RECORD_SIZE;
        let rest = (num_pages - 1) * (page_size / RECORD_SIZE);
        (first + rest) as u32
    }

    /// Wrap `pages` (each `page_size` bytes, zeroed by the creator).
    ///
    /// # Safety
    /// Every pointer must be valid for `page_size` bytes for the ring's
    /// lifetime, and the memory must not be moved or unmapped.
    pub unsafe fn from_pages(pages: Vec<*mut u8>, page_size: usize) -> Ring {
        let capacity = Self::capacity_for(pages.len(), page_size);
        Ring {
            pages,
            page_size,
            capacity,
        }
    }

    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    fn header_atomic(&self, off: usize) -> &AtomicU32 {
        // SAFETY: header lives in the first page, within HEADER_SIZE.
        unsafe { AtomicU32::from_ptr(self.pages[0].add(off) as *mut u32) }
    }

    /// (page pointer, offset) of record `slot`.
    fn record_ptr(&self, slot: u32) -> *mut u8 {
        let first_cap = (self.page_size - HEADER_SIZE) / RECORD_SIZE;
        let slot = slot as usize;
        if slot < first_cap {
            // SAFETY: slot bounds-checked against the first page's capacity.
            unsafe { self.pages[0].add(HEADER_SIZE + slot * RECORD_SIZE) }
        } else {
            let per_page = self.page_size / RECORD_SIZE;
            let rest = slot - first_cap;
            let page = 1 + rest / per_page;
            // SAFETY: capacity_for bounds slots to the page list.
            unsafe { self.pages[page].add((rest % per_page) * RECORD_SIZE) }
        }
    }

    /// Producer: try to publish `payload` (with `flags` OR-ed into its
    /// length). Returns false when the ring is full.
    pub fn try_push(&self, payload: &[u8], flags: u32) -> bool {
        debug_assert!(payload.len() <= INLINE_MAX);
        let head = self.header_atomic(OFF_HEAD);
        let tail = self.header_atomic(OFF_TAIL);
        let seq = head.load(Ordering::Relaxed);
        if seq.wrapping_sub(tail.load(Ordering::Acquire)) >= self.capacity {
            return false; // full
        }
        let slot = seq % self.capacity;
        let rec = self.record_ptr(slot);
        // SAFETY: rec points at a full RECORD_SIZE record inside our pages;
        // the slot is ours until we bump `head` (single producer).
        unsafe {
            std::ptr::copy_nonoverlapping(payload.as_ptr(), rec.add(RECORD_HDR), payload.len());
            (rec.add(4) as *mut u32).write_volatile(payload.len() as u32 | flags);
            // Publish: sequence write is the release gate for the payload.
            AtomicU32::from_ptr(rec as *mut u32).store(seq.wrapping_add(1), Ordering::Release);
        }
        head.store(seq.wrapping_add(1), Ordering::Release);
        true
    }

    /// Consumer: read the next record if one is published. Returns
    /// `(payload, flags)`.
    pub fn try_pop(&self) -> Option<(Vec<u8>, u32)> {
        let tail = self.header_atomic(OFF_TAIL);
        let seq = tail.load(Ordering::Relaxed);
        let slot = seq % self.capacity;
        let rec = self.record_ptr(slot);
        // SAFETY: reading the slot's sequence atomically; payload only after
        // the acquire load observes the publish.
        let published = unsafe { AtomicU32::from_ptr(rec as *mut u32).load(Ordering::Acquire) };
        if published != seq.wrapping_add(1) {
            return None;
        }
        let (len_flags, payload) = unsafe {
            let lf = (rec.add(4) as *const u32).read_volatile();
            let len = (lf & !LEN_INDIRECT) as usize;
            let mut buf = vec![0u8; len.min(INLINE_MAX)];
            std::ptr::copy_nonoverlapping(rec.add(RECORD_HDR), buf.as_mut_ptr(), buf.len());
            (lf, buf)
        };
        tail.store(seq.wrapping_add(1), Ordering::Release);
        Some((payload, len_flags & LEN_INDIRECT))
    }

    /// Consumer: about to block — set the parked flag. Returns true if new
    /// records were published in the meantime (caller must NOT sleep).
    pub fn park(&self) -> bool {
        self.header_atomic(OFF_FLAGS)
            .fetch_or(FLAG_PARKED, Ordering::SeqCst);
        // Re-check after the flag is visible: a producer that published
        // before seeing the flag would not kick.
        let head = self.header_atomic(OFF_HEAD).load(Ordering::SeqCst);
        let tail = self.header_atomic(OFF_TAIL).load(Ordering::Relaxed);
        if head != tail {
            self.unpark();
            return true;
        }
        false
    }

    pub fn unpark(&self) {
        self.header_atomic(OFF_FLAGS)
            .fetch_and(!FLAG_PARKED, Ordering::SeqCst);
    }

    /// Producer: does the consumer need a doorbell kick? (Checked after
    /// publishing; clears the flag when set so exactly one kick is sent.)
    pub fn take_parked(&self) -> bool {
        // StoreLoad barrier: our record publish (the head advance in try_push)
        // MUST be globally visible before we read PARKED. Without it, the head
        // store (Release) reorders after this flag load, so a consumer that
        // parks concurrently reads a stale head (sleeps) while we read a stale
        // (clear) PARKED and skip the kick -> LOST WAKEUP: the consumer sleeps
        // forever and is never doorbelled. This was the fork-clone sync stall
        // (worker parked, guest never kicked its CtxSynchronize request).
        std::sync::atomic::fence(Ordering::SeqCst);
        let flags = self.header_atomic(OFF_FLAGS);
        if flags.load(Ordering::SeqCst) & FLAG_PARKED != 0 {
            flags.fetch_and(!FLAG_PARKED, Ordering::SeqCst) & FLAG_PARKED != 0
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ring(num_pages: usize) -> (Ring, Vec<Vec<u8>>) {
        let page = 4096;
        let mut backing: Vec<Vec<u8>> = (0..num_pages).map(|_| vec![0u8; page]).collect();
        let pages: Vec<*mut u8> = backing.iter_mut().map(|p| p.as_mut_ptr()).collect();
        // SAFETY: backing outlives the ring within each test.
        (unsafe { Ring::from_pages(pages, page) }, backing)
    }

    #[test]
    fn push_pop_roundtrip() {
        let (ring, _keep) = make_ring(2);
        assert!(ring.try_push(b"hello", 0));
        assert!(ring.try_push(b"world", LEN_INDIRECT));
        let (a, f_a) = ring.try_pop().unwrap();
        let (b, f_b) = ring.try_pop().unwrap();
        assert_eq!((a.as_slice(), f_a), (b"hello".as_slice(), 0));
        assert_eq!((b.as_slice(), f_b), (b"world".as_slice(), LEN_INDIRECT));
        assert!(ring.try_pop().is_none());
    }

    #[test]
    fn fills_and_wraps() {
        let (ring, _keep) = make_ring(1);
        let cap = ring.capacity();
        for i in 0..cap {
            assert!(ring.try_push(&[i as u8], 0), "push {i}");
        }
        assert!(!ring.try_push(b"x", 0), "must report full");
        for i in 0..cap {
            assert_eq!(ring.try_pop().unwrap().0, vec![i as u8]);
        }
        // Wrapped sequences keep working past capacity.
        for round in 0..3u32 {
            assert!(ring.try_push(&round.to_le_bytes(), 0));
            assert_eq!(ring.try_pop().unwrap().0, round.to_le_bytes());
        }
    }

    #[test]
    fn record_slots_never_straddle_pages() {
        let (ring, keep) = make_ring(3);
        let page = 4096;
        for slot in 0..ring.capacity() {
            let p = ring.record_ptr(slot) as usize;
            let off_in_page = keep
                .iter()
                .map(|b| b.as_ptr() as usize)
                .filter(|&base| p >= base && p < base + page)
                .map(|base| p - base)
                .next()
                .expect("record outside all pages");
            assert!(off_in_page + RECORD_SIZE <= page, "slot {slot} straddles");
        }
    }

    #[test]
    fn park_sees_concurrent_publish() {
        let (ring, _keep) = make_ring(1);
        assert!(!ring.park(), "empty ring parks");
        ring.unpark();
        assert!(ring.try_push(b"x", 0));
        assert!(ring.park(), "publish before park must cancel the sleep");
        // Producer-side doorbell handoff.
        assert!(ring.try_pop().is_some());
        assert!(!ring.park());
        assert!(ring.try_push(b"y", 0));
        assert!(ring.take_parked(), "producer collects exactly one kick");
        assert!(!ring.take_parked());
    }

    #[test]
    fn cross_thread_stream() {
        use std::sync::Arc;
        let (ring, keep) = make_ring(4);
        let ring = Arc::new(ring);
        let producer = {
            let ring = Arc::clone(&ring);
            std::thread::spawn(move || {
                for i in 0..10_000u32 {
                    while !ring.try_push(&i.to_le_bytes(), 0) {
                        std::hint::spin_loop();
                    }
                }
            })
        };
        let mut expected = 0u32;
        while expected < 10_000 {
            if let Some((payload, _)) = ring.try_pop() {
                assert_eq!(payload, expected.to_le_bytes());
                expected += 1;
            } else {
                std::hint::spin_loop();
            }
        }
        producer.join().unwrap();
        drop(keep);
    }
}
