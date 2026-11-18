//! Lifetime-bound process and PTY descriptors, reached through independent RPCs.
use smolvm_protocol::{
    error_codes,
    interactive_control::{self, Action},
    AgentResponse,
};

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::{
        collections::HashMap,
        io,
        os::fd::{AsRawFd, FromRawFd, OwnedFd},
        process::Child,
        sync::{Arc, Mutex, OnceLock},
    };

    // Linux 6.9+: target the process group through its leader's pidfd. A stale
    // descriptor returns ESRCH; it cannot signal a later reuse of that PID.
    const PIDFD_SIGNAL_PROCESS_GROUP: u32 = 1 << 2;
    const MAX_SESSIONS: usize = 1024;
    struct Target {
        process: OwnedFd,
        terminal: Option<OwnedFd>,
    }
    type Entry = Arc<Mutex<Option<Target>>>;
    fn registry() -> &'static Mutex<HashMap<String, Entry>> {
        static ENTRIES: OnceLock<Mutex<HashMap<String, Entry>>> = OnceLock::new();
        ENTRIES.get_or_init(Default::default)
    }
    fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        mutex
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    fn pidfd_signal(fd: &OwnedFd, signal: i32) -> io::Result<()> {
        // SAFETY: the owned pidfd names only this command's process-group leader.
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd.as_raw_fd(),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                PIDFD_SIGNAL_PROCESS_GROUP,
            )
        };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
    /// Reservation exists only while the command's data connection is handled.
    pub struct Registration {
        id: String,
        entry: Entry,
    }
    impl Registration {
        pub fn reserve(id: &str) -> io::Result<Self> {
            if !interactive_control::valid_id(id) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid session identifier",
                ));
            }
            let mut entries = lock(registry());
            if entries.contains_key(id) {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "session identifier already in use",
                ));
            }
            if entries.len() >= MAX_SESSIONS {
                return Err(io::Error::other("too many controlled sessions"));
            }
            let entry = Arc::new(Mutex::new(None));
            entries.insert(id.to_string(), entry.clone());
            Ok(Self {
                id: id.into(),
                entry,
            })
        }
        pub fn activate(&self, child: &Child, terminal: Option<i32>) -> io::Result<()> {
            // SAFETY: child is owned and unreaped; pidfd_open returns a fresh fd.
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id() as libc::pid_t, 0) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let process = unsafe { OwnedFd::from_raw_fd(fd as i32) };
            // Check both kernel support and process-group ownership before
            // acknowledging Started; never fall back to an unpinned killpg.
            if let Err(error) = pidfd_signal(&process, 0) {
                // Fast commands can exit before registration; their output and
                // exit status still belong to this session. Keep the stale
                // pidfd, whose future controls fail safely with ESRCH.
                if error.raw_os_error() != Some(libc::ESRCH) {
                    return Err(error);
                }
            }
            let terminal = terminal
                .map(|fd| {
                    // SAFETY: duplicate the live PTY before its owner enters the I/O loop.
                    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
                    if duplicate < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
                    }
                })
                .transpose()?;
            *lock(&self.entry) = Some(Target { process, terminal });
            Ok(())
        }
    }
    impl Drop for Registration {
        fn drop(&mut self) {
            // Revocation waits for an in-flight operation before descriptors
            // are closed; no lookup can retain a usable target past revocation.
            *lock(&self.entry) = None;
            lock(registry()).remove(&self.id);
        }
    }
    pub fn perform(request: &interactive_control::Request) -> io::Result<()> {
        if !interactive_control::valid_id(&request.id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid session identifier",
            ));
        }
        let entry = lock(registry())
            .get(&request.id)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "session is not running"))?;
        let target = lock(&entry);
        let target = target
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "session is not running"))?;
        match request.action {
            Action::Signal { signal } => {
                if !(1..=64).contains(&signal) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "invalid Linux signal",
                    ));
                }
                pidfd_signal(&target.process, signal as i32)
            }
            Action::Resize { cols, rows } => {
                if cols == 0 || rows == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "terminal dimensions must be nonzero",
                    ));
                }
                // Ensure the pinned command is still alive before changing its PTY.
                pidfd_signal(&target.process, 0)?;
                let fd = target.terminal.as_ref().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "session has no terminal")
                })?;
                let size = libc::winsize {
                    ws_row: rows,
                    ws_col: cols,
                    ws_xpixel: 0,
                    ws_ypixel: 0,
                };
                // SAFETY: fd owns the session's terminal and size is initialized.
                if unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCSWINSZ, &size) } < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{
            os::unix::process::CommandExt,
            process::{Command, Stdio},
            time::{Duration, Instant},
        };
        struct OwnedChild(Child);
        impl std::ops::Deref for OwnedChild {
            type Target = Child;
            fn deref(&self) -> &Child {
                &self.0
            }
        }
        impl std::ops::DerefMut for OwnedChild {
            fn deref_mut(&mut self) -> &mut Child {
                &mut self.0
            }
        }
        impl Drop for OwnedChild {
            fn drop(&mut self) {
                if matches!(self.0.try_wait(), Ok(None)) {
                    crate::process::kill_child_tree(&mut self.0);
                }
                let _ = self.0.wait();
            }
        }
        #[test]
        fn controlled_process_group_isolated_and_revoked_after_exit() {
            let id = "0123456789abcdef0123456789abcdef";
            let owned = Registration::reserve(id).unwrap();
            assert!(Registration::reserve(id).is_err());
            let mut child = OwnedChild(
                Command::new("sh")
                    .args(["-c", "sleep 30 & wait"])
                    .process_group(0)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .spawn()
                    .unwrap(),
            );
            let mut sibling = OwnedChild(
                Command::new("sleep")
                    .arg("30")
                    .process_group(0)
                    .spawn()
                    .unwrap(),
            );
            let result = (|| -> io::Result<()> {
                owned.activate(&child, None)?;
                assert!(perform(&interactive_control::Request {
                    id: id.into(),
                    action: Action::Resize { cols: 80, rows: 24 }
                })
                .is_err());
                perform(&interactive_control::Request {
                    id: id.into(),
                    action: Action::Signal { signal: 15 },
                })?;
                let deadline = Instant::now() + Duration::from_secs(2);
                while child.try_wait()?.is_none() {
                    assert!(Instant::now() < deadline);
                    std::thread::sleep(Duration::from_millis(10));
                }
                assert!(sibling.try_wait()?.is_none());
                assert!(perform(&interactive_control::Request {
                    id: id.into(),
                    action: Action::Signal { signal: 15 }
                })
                .is_err());
                Ok(())
            })();
            let _ = child.kill();
            let _ = child.wait();
            let _ = sibling.kill();
            let _ = sibling.wait();
            result.unwrap();
            drop(owned);
            assert!(perform(&interactive_control::Request {
                id: id.into(),
                action: Action::Signal { signal: 15 }
            })
            .is_err());
            assert!(Registration::reserve(id).is_ok());
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::Registration;

/// Dispatch on a connection separate from the session's potentially blocked I/O.
pub fn handle(request: &interactive_control::Request) -> AgentResponse {
    #[cfg(target_os = "linux")]
    match linux::perform(request) {
        Ok(()) => AgentResponse::Ok { data: None },
        Err(error) => AgentResponse::from_err(error, error_codes::EXEC_FAILED),
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = request;
        AgentResponse::error(
            "interactive controls require Linux",
            error_codes::INVALID_REQUEST,
        )
    }
}

#[cfg(not(target_os = "linux"))]
pub struct Registration;
#[cfg(not(target_os = "linux"))]
impl Registration {
    pub fn reserve(_: &str) -> std::io::Result<Self> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "interactive controls require Linux",
        ))
    }
    pub fn activate(&self, _: &std::process::Child, _: Option<i32>) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "interactive controls require Linux",
        ))
    }
}
