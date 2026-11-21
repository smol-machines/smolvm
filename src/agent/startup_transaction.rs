//! A batch's boot processes remain provisional until a single shared commit.
//! The anonymous file is passed as stdin, mapped before descriptor cleanup,
//! and never exposed to the guest; successful batches retain no extra watcher.

use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub(crate) const PARENT_ENV: &str = "SMOLVM_BOOT_STARTUP_PARENT";
const PENDING: u8 = 0;
const COMMITTED: u8 = 1;
const ABORTED: u8 = 2;

struct Page(*mut AtomicU8);

// SAFETY: The mapping has a fixed lifetime/size, and its only shared value is
// accessed atomically; a Page is unmapped only after its owning thread exits.
unsafe impl Send for Page {}
unsafe impl Sync for Page {}

impl Page {
    fn map(fd: RawFd, writable: bool) -> io::Result<Self> {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: stat points to writable storage for fstat's output.
        if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fstat initialized the structure on success.
        let stat = unsafe { stat.assume_init() };
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG || stat.st_size != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid startup commit file",
            ));
        }
        let prot = libc::PROT_READ | if writable { libc::PROT_WRITE } else { 0 };
        // SAFETY: The transaction owns an anonymous, fixed-size file. Neither
        // side truncates it, and mmap retains its backing after descriptors close.
        let address = unsafe { libc::mmap(std::ptr::null_mut(), 1, prot, libc::MAP_SHARED, fd, 0) };
        if address == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(address.cast()))
    }

    fn state(&self) -> &AtomicU8 {
        // SAFETY: mmap is aligned for AtomicU8 and lives for all accesses;
        // the freshly extended file starts at zero (PENDING), a valid atomic byte.
        unsafe { &*self.0 }
    }
}

impl Drop for Page {
    fn drop(&mut self) {
        // SAFETY: This Page uniquely owns this mapping (not the shared backing).
        unsafe { libc::munmap(self.0.cast(), 1) };
    }
}

pub(crate) struct Transaction {
    file: Arc<File>,
    page: Page,
}

impl Transaction {
    pub(crate) fn new() -> io::Result<Self> {
        let file = Arc::new(tempfile::tempfile()?);
        file.set_len(1)?;
        let page = Page::map(file.as_raw_fd(), true)?;
        Ok(Self { file, page })
    }

    pub(crate) fn file(&self) -> Arc<File> {
        self.file.clone()
    }

    pub(crate) fn commit(&self) {
        self.page.state().store(COMMITTED, Ordering::Release);
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        let _ = self.page.state().compare_exchange(
            PENDING,
            ABORTED,
            Ordering::Release,
            Ordering::Relaxed,
        );
    }
}

pub(crate) fn watch_stdin(
    parent: i32,
    before_exit: impl FnOnce() + Send + 'static,
) -> io::Result<()> {
    if parent <= 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid startup owner PID",
        ));
    }
    let page = Page::map(libc::STDIN_FILENO, false)?;
    std::thread::Builder::new()
        .name("startup-commit-watch".into())
        .spawn(move || {
            loop {
                match page.state().load(Ordering::Acquire) {
                    COMMITTED => return,
                    PENDING if unsafe { libc::getppid() } == parent => {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    _ => {
                        // The parent may have committed between our first load
                        // and its exit; committed children deliberately survive.
                        if page.state().load(Ordering::Acquire) != COMMITTED {
                            before_exit();
                            crate::process::exit_child(0);
                        }
                        return;
                    }
                }
            }
        })?;
    Ok(())
}
