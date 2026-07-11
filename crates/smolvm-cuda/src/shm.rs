//! A named POSIX shared-memory region, mapped by both the guest shim and the
//! host CUDA server, used as a **zero-copy bulk-data channel**.
//!
//! Bulk `cudaMemcpy` is the bandwidth bottleneck of socket-based remoting: the
//! bytes are copied guest→socket→host→GPU. With a region both sides map, a
//! host-pinned/`cudaMallocHost` buffer lives *in* the region, and a memcpy
//! ships only an `(offset, size)` descriptor — the host reads the bytes
//! straight from the shared mapping and DMAs them to the GPU. No bulk bytes
//! cross the socket.
//!
//! Same-host today (guest shim + host server share `/dev/shm/<name>`). The
//! microVM case backs the *same protocol* with guest RAM the host already maps
//! (a libkrun API to expose the guest-memory base; see docs).
//!
//! Selected by `SMOLVM_CUDA_SHM=<name>` (+ `SMOLVM_CUDA_SHM_SIZE`, default
//! 512 MiB). Unset → the region is absent and callers fall back to byte-shipping.

use std::ffi::CString;
use std::sync::OnceLock;

/// A mapped shared region: base pointer + length. `Send`/`Sync` because it is a
/// process-lifetime mapping accessed under the server's per-connection ordering.
pub struct ShmRegion {
    base: *mut u8,
    len: usize,
}
// SAFETY: the mapping lives for the whole process; concurrent access is
// serialized by the CUDA server's single-threaded-per-connection model and, on
// the guest, by the client mutex.
unsafe impl Send for ShmRegion {}
unsafe impl Sync for ShmRegion {}

impl ShmRegion {
    pub fn base(&self) -> *mut u8 {
        self.base
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    /// A checked slice `[offset, offset+size)` into the region, or `None` if out
    /// of bounds (guards a hostile/buggy offset).
    pub fn checked(&self, offset: u64, size: u64) -> Option<*mut u8> {
        let end = offset.checked_add(size)?;
        if end > self.len as u64 {
            return None;
        }
        Some(unsafe { self.base.add(offset as usize) })
    }
}

fn shm_size() -> usize {
    std::env::var("SMOLVM_CUDA_SHM_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(512 * 1024 * 1024)
}

/// Open (server: `create=true`) or attach (`create=false`) the region named by
/// `SMOLVM_CUDA_SHM`. Returns `None` if the env var is unset (no shm channel).
pub fn open(create: bool) -> Option<ShmRegion> {
    let trace = std::env::var_os("SMOLVM_CUDA_SHM_TRACE").is_some();
    let name = match std::env::var("SMOLVM_CUDA_SHM") {
        Ok(n) => n,
        Err(_) => {
            if trace {
                eprintln!("shm: SMOLVM_CUDA_SHM not set (create={create})");
            }
            return None;
        }
    };
    if trace {
        eprintln!("shm: open name={name:?} create={create}");
    }
    let len = shm_size();
    let cname = CString::new(name).ok()?;
    unsafe {
        let mut flags = libc::O_RDWR;
        if create {
            flags |= libc::O_CREAT;
        }
        let fd = libc::shm_open(cname.as_ptr(), flags, 0o600);
        if fd < 0 {
            if trace {
                eprintln!(
                    "shm: shm_open failed errno={}",
                    std::io::Error::last_os_error()
                );
            }
            return None;
        }
        if create && libc::ftruncate(fd, len as libc::off_t) != 0 {
            if trace {
                eprintln!("shm: ftruncate failed");
            }
            libc::close(fd);
            return None;
        }
        let base = libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        );
        libc::close(fd); // the mapping keeps the region alive
        if base == libc::MAP_FAILED {
            return None;
        }
        Some(ShmRegion {
            base: base as *mut u8,
            len,
        })
    }
}

/// Process-wide handle, opened once on first use (attach mode).
pub fn get() -> Option<&'static ShmRegion> {
    static REGION: OnceLock<Option<ShmRegion>> = OnceLock::new();
    REGION.get_or_init(|| open(false)).as_ref()
}

/// Server-side: create-or-attach the region once.
pub fn get_or_create() -> Option<&'static ShmRegion> {
    static REGION: OnceLock<Option<ShmRegion>> = OnceLock::new();
    REGION.get_or_init(|| open(true)).as_ref()
}
