//! Share operation locks with a supervised startup child without releasing
//! ownership during cancellation. These descriptors never enter the VMM.
use std::{
    fs::File,
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{fs::MetadataExt, process::CommandExt},
    },
    path::Path,
    process::Command,
};

const ENV: &str = "SMOLVM_INHERITED_OPERATION_LOCKS";

#[derive(serde::Serialize, serde::Deserialize)]
struct Descriptor {
    fd: i32,
    device: u64,
    inode: u64,
}

pub(super) fn configure<'a>(
    command: &mut Command,
    files: impl Iterator<Item = &'a File>,
) -> io::Result<()> {
    let descriptors: Vec<Descriptor> = files
        .map(|file| {
            let metadata = file.metadata()?;
            Ok(Descriptor {
                fd: file.as_raw_fd(),
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        })
        .collect::<io::Result<_>>()?;
    let fds: Vec<i32> = descriptors.iter().map(|value| value.fd).collect();
    command.env(
        ENV,
        serde_json::to_string(&descriptors).map_err(io::Error::other)?,
    );
    // This changes only the forked child's descriptor flags. The parent keeps
    // CLOEXEC and its own references until startup and rollback are complete.
    unsafe {
        command.pre_exec(move || {
            for fd in &fds {
                let flags = libc::fcntl(*fd, libc::F_GETFD);
                if flags < 0 || libc::fcntl(*fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    Ok(())
}

pub(super) fn take_matching(path: &Path) -> io::Result<Option<File>> {
    let Some(encoded) = std::env::var_os(ENV) else {
        return Ok(None);
    };
    let encoded = encoded
        .to_str()
        .filter(|s| s.len() <= 4096)
        .ok_or_else(|| io::Error::other("invalid inherited operation locks"))?;
    let descriptors: Vec<Descriptor> = serde_json::from_str(encoded).map_err(io::Error::other)?;
    if descriptors.len() > 16 || descriptors.iter().any(|value| value.fd < 3) {
        return Err(io::Error::other(
            "invalid inherited operation lock descriptors",
        ));
    }
    // Missing means this is a different machine (for example an image seed).
    let expected = match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => Some(metadata),
        Ok(_) => return Err(io::Error::other("operation lock is not a regular file")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    let mut matched = None;
    for descriptor in descriptors {
        let fd = descriptor.fd;
        let copied = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        if copied < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EBADF) {
                continue;
            }
            return Err(error);
        }
        let file = unsafe { File::from_raw_fd(copied) };
        let actual = file.metadata()?;
        if !actual.is_file()
            || actual.dev() != descriptor.device
            || actual.ino() != descriptor.inode
        {
            // An exec'd helper can inherit the variable after the descriptors
            // have closed. Never change flags on a reused descriptor number.
            continue;
        }
        // Re-arm CLOEXEC on every valid inherited lock, including the pause
        // lock unused by plain start, before launching helpers or the VMM.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        if expected.as_ref().is_some_and(|expected| {
            actual.is_file() && actual.dev() == expected.dev() && actual.ino() == expected.ino()
        }) {
            matched = Some(file);
        }
    }
    Ok(matched)
}

#[cfg(test)]
mod tests {
    use super::super::ForkSourceLock;
    use super::*;
    use std::{
        process::Stdio,
        time::{Duration, Instant},
    };

    const CHILD: &str = "SMOLVM_TEST_OPERATION_LOCK_CHILD";
    const PATH: &str = "SMOLVM_TEST_OPERATION_LOCK_PATH";
    const TEST: &str = "agent::fork::inherited_lock::tests::inherited_lock_child";

    fn child(mode: &str, path: &Path) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", TEST, "--nocapture"])
            .env(CHILD, mode)
            .env(PATH, path)
            .stdin(Stdio::null())
            .stdout(Stdio::null());
        command
    }

    fn finish(mut child: std::process::Child) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "operation lock child failed");
                return;
            }
            if Instant::now() >= deadline {
                // The unreaped direct child still owns this process-group ID.
                unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
                let _ = child.kill();
                let _ = child.wait();
                panic!("operation lock inheritance deadlocked");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn inherited_lock_child() {
        let Ok(mode) = std::env::var(CHILD) else {
            return;
        };
        let path = std::path::PathBuf::from(std::env::var_os(PATH).unwrap());
        match mode.as_str() {
            "borrow" => {
                let guard = ForkSourceLock::acquire_at(&path).unwrap();
                drop(guard);
                // An ordinary helper inherits the variable but not descriptors;
                // it cannot borrow the parent's lock or release its ownership.
                finish(child("probe", &path).process_group(0).spawn().unwrap());
            }
            "probe" => assert!(ForkSourceLock::try_acquire_at(&path).unwrap().is_none()),
            _ => panic!("unknown test child mode"),
        }
    }

    #[test]
    fn child_borrows_lock_without_releasing_parent_or_leaking_to_helpers() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("operation.lock");
        let guard = ForkSourceLock::acquire_at(&path).unwrap();
        let mut command = child("borrow", &path);
        command.process_group(0);
        configure(&mut command, [&guard._file].into_iter()).unwrap();
        finish(command.spawn().unwrap());
        assert!(ForkSourceLock::try_acquire_at(&path).unwrap().is_none());
        drop(guard);
        assert!(ForkSourceLock::try_acquire_at(&path).unwrap().is_some());
    }
}
