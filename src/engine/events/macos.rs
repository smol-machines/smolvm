//! An immediate directory watch without FSEvents journal batching.
//!
//! Event files are immutable and published by atomic rename. A single vnode
//! subscription sees publication and pruning without opening every event file
//! or changing the recursive watchers used for guest filesystem sharing.

use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::sync::Arc;

use tokio::io::unix::AsyncFd;
use tokio::sync::watch;

use super::DirectoryWatch;

const INVALIDATED: u32 = libc::NOTE_DELETE | libc::NOTE_RENAME | libc::NOTE_REVOKE;

pub(super) fn watch(path: &Path, changed: watch::Sender<()>) -> io::Result<DirectoryWatch> {
    let runtime = tokio::runtime::Handle::try_current().map_err(io::Error::other)?;
    let directory = File::open(path)?;
    // SAFETY: kqueue takes no pointers and returns a new descriptor we own.
    let raw = unsafe { libc::kqueue() };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: raw is a fresh descriptor and is transferred exactly once.
    let queue = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: fcntl operates on our live descriptor; no pointer argument.
    if unsafe { libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let change = libc::kevent {
        ident: directory.as_raw_fd() as usize,
        filter: libc::EVFILT_VNODE,
        flags: libc::EV_ADD | libc::EV_CLEAR,
        fflags: libc::NOTE_WRITE | INVALIDATED,
        data: 0,
        udata: std::ptr::null_mut(),
    };
    // SAFETY: change is initialized and valid for this call; no output buffer.
    if unsafe { libc::kevent(raw, &change, 1, std::ptr::null_mut(), 0, std::ptr::null()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // A kqueue is readable, never writable; registering write interest is
    // rejected by macOS with EINVAL.
    // SAFETY: AsyncFd exclusively owns this OwnedFd; it is never replaced or
    // closed through a raw descriptor while registered with the reactor.
    let queue = unsafe { AsyncFd::register_with_interest(queue, tokio::io::Interest::READABLE) }?;
    let error = Arc::new(parking_lot::Mutex::new(None));
    let failure = error.clone();
    let task = runtime.spawn(async move {
        // Keep the vnode descriptor alive until this task is aborted or fails.
        let _directory = directory;
        let result: io::Result<()> = async {
            loop {
                let mut ready = queue.readable().await?;
                match ready.try_io(|queue| receive(queue.get_ref().as_raw_fd())) {
                    Err(_) => continue,
                    Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Ok(Err(error)) => return Err(error),
                    Ok(Ok(flags)) if flags & INVALIDATED != 0 => {
                        return Err(io::Error::other(
                            "The engine event directory was removed or moved",
                        ));
                    }
                    Ok(Ok(_)) => {
                        changed.send_replace(());
                    }
                }
            }
        }
        .await;
        if let Err(error) = result {
            *failure.lock() = Some(error.to_string());
            changed.send_replace(());
        }
    });
    Ok(DirectoryWatch {
        task: task.abort_handle(),
        error,
    })
}

fn receive(queue: RawFd) -> io::Result<u32> {
    // SAFETY: every field of kevent accepts a zero representation; the kernel
    // initializes it before we inspect it when it returns one event.
    let mut event: libc::kevent = unsafe { std::mem::zeroed() };
    let now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: the buffers are valid and the zero timeout makes this read
    // nonblocking, as required by AsyncFd's readiness protocol.
    let count = unsafe { libc::kevent(queue, std::ptr::null(), 0, &mut event, 1, &now) };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    if count == 0 {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    if event.flags & libc::EV_ERROR != 0 {
        return Err(io::Error::from_raw_os_error(event.data as i32));
    }
    Ok(event.fflags)
}
