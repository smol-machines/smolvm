//! Reading and writing below a directory another user may control, without
//! following links.
//!
//! A machine's data directory belongs to the machine's own user while it runs
//! under per-VM uid isolation, and the host (root under `serve`) still reads
//! and writes files there: its credential CAs, its running configuration. A
//! process escaped from the machine could swap any of them, or a directory on
//! the way, for a link to somewhere only root can reach, a hard link to a file
//! elsewhere, or a FIFO that hangs the reader. So every component below the
//! trusted base directory is opened relative to its parent's descriptor
//! without following a link, directories with `O_DIRECTORY`, files only when
//! regular and never blocking on open. A file read or written in place must
//! have one name only and belong to this process's user or the base
//! directory's owner, and reads are capped.

use std::path::Path;

/// Read `base/<components…>`, at most `max` bytes. A longer file is an error,
/// never a truncated read.
#[cfg(unix)]
pub(crate) fn read(base: &Path, components: &[&str], max: u64) -> std::io::Result<Vec<u8>> {
    let (name, dirs) = split(components)?;
    let (dir, base_owner) = unix::open_dirs(base, dirs, false)?;
    let file = std::fs::File::from(unix::open_at(
        &dir,
        name,
        libc::O_RDONLY | libc::O_NONBLOCK,
        0,
    )?);
    unix::check_file(&file, base_owner)?;
    read_capped(&file, max)
}

#[cfg(not(unix))]
pub(crate) fn read(base: &Path, components: &[&str], max: u64) -> std::io::Result<Vec<u8>> {
    let file = std::fs::File::open(windows::checked_path(base, components, false)?)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    read_capped(&file, max)
}

fn read_capped(file: &std::fs::File, max: u64) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut std::io::Read::take(file, max + 1), &mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(std::io::Error::other(format!("larger than {max} bytes")));
    }
    Ok(bytes)
}

/// Whether `base/<components…>` is a regular file, its own name and every
/// directory on the way not a link.
#[cfg(unix)]
pub(crate) fn is_file(base: &Path, components: &[&str]) -> bool {
    let Ok((name, dirs)) = split(components) else {
        return false;
    };
    unix::open_dirs(base, dirs, false)
        .and_then(|(dir, _)| unix::stat_at(&dir, name))
        .is_ok_and(|mode| mode & libc::S_IFMT == libc::S_IFREG)
}

#[cfg(not(unix))]
pub(crate) fn is_file(base: &Path, components: &[&str]) -> bool {
    windows::checked_path(base, components, false)
        .and_then(std::fs::symlink_metadata)
        .is_ok_and(|meta| meta.is_file())
}

/// The names in directory `base/<components…>`, which must not be a link nor
/// lie below one.
#[cfg(unix)]
pub(crate) fn list(base: &Path, components: &[&str]) -> std::io::Result<Vec<String>> {
    let (dir, _) = unix::open_dirs(base, components, false)?;
    unix::list(dir)
}

#[cfg(not(unix))]
pub(crate) fn list(base: &Path, components: &[&str]) -> std::io::Result<Vec<String>> {
    Ok(
        std::fs::read_dir(windows::checked_path(base, components, false)?)?
            .flatten()
            .filter_map(|entry| entry.file_name().into_string().ok())
            .collect(),
    )
}

/// Replace `base/<components…>` with `bytes`, mode `mode` from its creation:
/// written to a new file beside it and renamed over it, so a reader never sees
/// it partly written. Missing directories on the way are made (mode `0o755`).
/// No component is followed if it is a link, and a link at the file's own
/// name is replaced, never written through.
#[cfg(unix)]
pub(crate) fn write_replacing(
    base: &Path,
    components: &[&str],
    bytes: &[u8],
    mode: u32,
) -> std::io::Result<()> {
    use std::io::Write;
    let (name, dirs) = split(components)?;
    let (dir, _) = unix::open_dirs(base, dirs, true)?;
    let (tmp, fd) = unique_temp(name, |tmp| {
        unix::open_at(
            &dir,
            tmp,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            mode,
        )
    })?;
    let written = Ok::<_, std::io::Error>(std::fs::File::from(fd))
        .and_then(|mut file| {
            // its final mode whatever the umask was
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(mode))?;
            file.write_all(bytes)
        })
        .and_then(|()| unix::rename_at(&dir, &tmp, name));
    if written.is_err() {
        let _ = unix::unlink_at(&dir, &tmp);
    }
    written
}

/// Windows has no per-VM user to defend against: this only refuses a link or
/// junction on the way and otherwise replaces the file as Unix does.
#[cfg(not(unix))]
pub(crate) fn write_replacing(
    base: &Path,
    components: &[&str],
    bytes: &[u8],
    _mode: u32,
) -> std::io::Result<()> {
    let path = windows::checked_path(base, components, true)?;
    let (name, _) = split(components)?;
    let (tmp, file) = unique_temp(name, |tmp| {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path.with_file_name(tmp))
    })?;
    let tmp = path.with_file_name(tmp);
    let written = Ok::<_, std::io::Error>(file)
        .and_then(|mut file| std::io::Write::write_all(&mut file, bytes))
        .and_then(|()| std::fs::rename(&tmp, &path));
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written
}

/// Overwrite `base/<components…>` with `bytes` in place, keeping its inode,
/// for a file a running guest reads through a mount of its directory. The
/// file is created (mode `0o644`) when missing; an existing one must be
/// regular, have one name only and belong to this user or the base
/// directory's owner. No component is followed if it is a link.
#[cfg(unix)]
pub(crate) fn write_in_place(
    base: &Path,
    components: &[&str],
    bytes: &[u8],
) -> std::io::Result<()> {
    use std::io::Write;
    let (name, dirs) = split(components)?;
    let (dir, base_owner) = unix::open_dirs(base, dirs, false)?;
    let mut file = std::fs::File::from(unix::open_at(
        &dir,
        name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_NONBLOCK,
        0o644,
    )?);
    unix::check_file(&file, base_owner)?;
    file.set_len(0)?;
    file.write_all(bytes)
}

#[cfg(not(unix))]
pub(crate) fn write_in_place(
    base: &Path,
    components: &[&str],
    bytes: &[u8],
) -> std::io::Result<()> {
    std::fs::write(windows::checked_path(base, components, false)?, bytes)
}

fn split<'a>(components: &'a [&'a str]) -> std::io::Result<(&'a str, &'a [&'a str])> {
    components
        .split_last()
        .map(|(name, dirs)| (*name, dirs))
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))
}

/// Create a temporary file beside `name` with `create` (which must refuse an
/// existing file), under a name unique to this call: this process, a counter
/// and random bytes, so a name left by a crash or planted by another user is
/// skipped, never reused.
fn unique_temp<T>(
    name: &str,
    mut create: impl FnMut(&str) -> std::io::Result<T>,
) -> std::io::Result<(String, T)> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let mut last = None;
    for _ in 0..16 {
        let mut random = [0u8; 8];
        getrandom::fill(&mut random).map_err(std::io::Error::other)?;
        let tmp = format!(
            ".{name}.{}.{}.{}.tmp",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            u64::from_ne_bytes(random)
        );
        match create(&tmp) {
            Ok(made) => return Ok((tmp, made)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => last = Some(error),
            Err(error) => return Err(error),
        }
    }
    Err(last.unwrap_or_else(|| std::io::ErrorKind::AlreadyExists.into()))
}

#[cfg(unix)]
mod unix {
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    fn c_name(name: &[u8]) -> std::io::Result<std::ffi::CString> {
        std::ffi::CString::new(name).map_err(|_| std::io::ErrorKind::InvalidInput.into())
    }

    /// One name, never a path: no separator, and not `.` or `..`.
    fn component(name: &str) -> std::io::Result<std::ffi::CString> {
        if name.is_empty() || name == "." || name == ".." || name.contains('/') {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }
        c_name(name.as_bytes())
    }

    fn owned(fd: libc::c_int) -> std::io::Result<OwnedFd> {
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: a descriptor the caller just received and now owns.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    pub(super) fn open_at(
        dir: &OwnedFd,
        name: &str,
        flags: libc::c_int,
        mode: u32,
    ) -> std::io::Result<OwnedFd> {
        let name = component(name)?;
        // SAFETY: a NUL-terminated name and a live directory descriptor.
        owned(unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                mode as libc::c_uint,
            )
        })
    }

    /// `base`, then each of `dirs` below it, opened as directories without
    /// following a link (a missing one made first with `create`), with the
    /// owner of `base` as it was opened.
    pub(super) fn open_dirs(
        base: &Path,
        dirs: &[&str],
        create: bool,
    ) -> std::io::Result<(OwnedFd, u32)> {
        let path = c_name(base.as_os_str().as_bytes())?;
        // SAFETY: a NUL-terminated path.
        let mut dir = owned(unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        })?;
        let owner = std::fs::File::from(dir.try_clone()?).metadata()?.uid();
        for name in dirs {
            if create {
                let c = component(name)?;
                // SAFETY: a NUL-terminated name and a live directory descriptor.
                if unsafe { libc::mkdirat(dir.as_raw_fd(), c.as_ptr(), 0o755) } != 0 {
                    let error = std::io::Error::last_os_error();
                    if error.kind() != std::io::ErrorKind::AlreadyExists {
                        return Err(error);
                    }
                }
            }
            dir = open_at(&dir, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        }
        Ok((dir, owner))
    }

    /// An opened file may be read or written: regular, one name only (a hard
    /// link to a file elsewhere has two), and owned by this process's user or
    /// by `base_owner`, never by anyone else.
    pub(super) fn check_file(file: &std::fs::File, base_owner: u32) -> std::io::Result<()> {
        let meta = file.metadata()?;
        if !meta.is_file() {
            return Err(std::io::Error::other("not a regular file"));
        }
        if meta.nlink() != 1 {
            return Err(std::io::Error::other("a file with more than one name"));
        }
        // SAFETY: geteuid has no preconditions.
        if !owner_allowed(meta.uid(), unsafe { libc::geteuid() }, base_owner) {
            return Err(std::io::Error::other(
                "a file owned by neither this user nor the directory's owner",
            ));
        }
        Ok(())
    }

    /// Whether a file `owner` owns may be trusted by a process running as `me`
    /// below a directory `base_owner` owns.
    pub(super) fn owner_allowed(owner: u32, me: u32, base_owner: u32) -> bool {
        owner == me || owner == base_owner
    }

    /// The file type and mode of `name` in `dir`, itself when it is a link.
    pub(super) fn stat_at(dir: &OwnedFd, name: &str) -> std::io::Result<libc::mode_t> {
        let name = component(name)?;
        // SAFETY: plain data the call fills in.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: a NUL-terminated name, a live directory descriptor and a buffer of the right type.
        if unsafe {
            libc::fstatat(
                dir.as_raw_fd(),
                name.as_ptr(),
                &mut stat,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(stat.st_mode)
    }

    pub(super) fn list(dir: OwnedFd) -> std::io::Result<Vec<String>> {
        let fd = dir.into_raw_fd();
        // SAFETY: a live directory descriptor, owned by the stream from here on.
        let stream = unsafe { libc::fdopendir(fd) };
        if stream.is_null() {
            let error = std::io::Error::last_os_error();
            // SAFETY: fdopendir failed, so the descriptor is still ours.
            unsafe { libc::close(fd) };
            return Err(error);
        }
        let mut names = Vec::new();
        loop {
            // SAFETY: a live directory stream.
            let entry = unsafe { libc::readdir(stream) };
            if entry.is_null() {
                break;
            }
            // SAFETY: readdir returned a live entry whose name is NUL-terminated.
            let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
            if let Ok(name) = name.to_str() {
                if name != "." && name != ".." {
                    names.push(name.to_string());
                }
            }
        }
        // SAFETY: a live directory stream, closed once.
        unsafe { libc::closedir(stream) };
        Ok(names)
    }

    pub(super) fn unlink_at(dir: &OwnedFd, name: &str) -> std::io::Result<()> {
        let name = component(name)?;
        // SAFETY: a NUL-terminated name and a live directory descriptor.
        if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    pub(super) fn rename_at(dir: &OwnedFd, from: &str, to: &str) -> std::io::Result<()> {
        let (from, to) = (component(from)?, component(to)?);
        // SAFETY: NUL-terminated names and a live directory descriptor.
        if unsafe { libc::renameat(dir.as_raw_fd(), from.as_ptr(), dir.as_raw_fd(), to.as_ptr()) }
            != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(not(unix))]
mod windows {
    use std::path::{Path, PathBuf};

    /// `base/<components…>`, refusing a link or junction at `base` or any
    /// component; with `create`, missing directories on the way are made.
    pub(super) fn checked_path(
        base: &Path,
        components: &[&str],
        create: bool,
    ) -> std::io::Result<PathBuf> {
        fn refuse_link(path: &Path) -> std::io::Result<()> {
            use std::os::windows::fs::MetadataExt;
            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
            match std::fs::symlink_metadata(path) {
                Ok(meta)
                    if meta.file_type().is_symlink()
                        || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 =>
                {
                    Err(std::io::Error::other(format!(
                        "{} is a link",
                        path.display()
                    )))
                }
                Ok(_) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error),
            }
        }
        refuse_link(base)?;
        let mut path = base.to_path_buf();
        for (index, name) in components.iter().enumerate() {
            if name.is_empty() || *name == "." || *name == ".." || name.contains(['/', '\\']) {
                return Err(std::io::ErrorKind::InvalidInput.into());
            }
            path.push(name);
            refuse_link(&path)?;
            if create && index + 1 < components.len() {
                match std::fs::create_dir(&path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(path)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// Nothing is read through a link, on the way or at the file's name; a
    /// FIFO never blocks the reader; a file with a second name is refused;
    /// and a file past the cap is refused rather than read whole.
    #[test]
    fn reads_refuse_links_fifos_hard_links_and_oversized_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("plain"), b"hello").unwrap();
        assert_eq!(read(dir.path(), &["plain"], 16).unwrap(), b"hello");
        assert!(is_file(dir.path(), &["plain"]));
        assert!(read(dir.path(), &["plain"], 4).is_err(), "over the cap");

        std::os::unix::fs::symlink(dir.path().join("plain"), dir.path().join("link")).unwrap();
        assert!(read(dir.path(), &["link"], 16).is_err());
        assert!(!is_file(dir.path(), &["link"]));

        let fifo = std::ffi::CString::new(dir.path().join("fifo").to_str().unwrap()).unwrap();
        // SAFETY: a NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(
            read(dir.path(), &["fifo"], 16).is_err(),
            "refused, not blocked"
        );
        assert!(write_in_place(dir.path(), &["fifo"], b"x").is_err());
        assert!(!is_file(dir.path(), &["fifo"]));

        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("f"), b"x").unwrap();
        std::os::unix::fs::symlink(&sub, dir.path().join("linked")).unwrap();
        assert!(read(dir.path(), &["linked", "f"], 16).is_err());
        assert!(read(&dir.path().join("linked"), &["f"], 16).is_err());
        assert!(list(dir.path(), &["linked"]).is_err());
        assert_eq!(list(dir.path(), &["sub"]).unwrap(), ["f"]);

        std::fs::hard_link(dir.path().join("plain"), sub.join("second")).unwrap();
        let err = read(&sub, &["second"], 64).unwrap_err();
        assert!(err.to_string().contains("more than one name"), "{err}");
        assert!(write_in_place(&sub, &["second"], b"x").is_err());
        assert_eq!(std::fs::read(dir.path().join("plain")).unwrap(), b"hello");
    }

    /// A file owned by anyone but this user or the directory's owner is never
    /// trusted (planting one takes root, so the rule is checked directly).
    #[test]
    fn files_of_a_third_user_are_refused() {
        assert!(unix::owner_allowed(0, 0, 5001));
        assert!(unix::owner_allowed(5001, 0, 5001));
        assert!(!unix::owner_allowed(5002, 0, 5001));
        assert!(unix::owner_allowed(1000, 1000, 1000));
        assert!(!unix::owner_allowed(0, 1000, 1000));
    }

    /// Writers in many threads at once never share a temporary file: every
    /// write lands whole, and none is left behind.
    #[test]
    fn concurrent_writes_never_collide() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().to_path_buf();
        let threads: Vec<_> = (0..16)
            .map(|i| {
                let base = base.clone();
                std::thread::spawn(move || {
                    let body = vec![b'a' + (i as u8 % 26); 4096];
                    for _ in 0..20 {
                        write_replacing(&base, &["shared"], &body, 0o644).unwrap();
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        let content = std::fs::read(base.join("shared")).unwrap();
        assert_eq!(content.len(), 4096);
        assert!(content.iter().all(|b| *b == content[0]));
        assert_eq!(list(&base, &[]).unwrap(), ["shared"]);
    }

    /// A write never goes through a link: a linked directory on the way is
    /// refused, a link at the file's own name is replaced, not followed, and
    /// an in-place write refuses it.
    #[test]
    fn writes_never_go_through_links() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        write_replacing(dir.path(), &["a", "b", "file"], b"one", 0o600).unwrap();
        let file = dir.path().join("a/b/file");
        assert_eq!(std::fs::read(&file).unwrap(), b"one");
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        write_in_place(dir.path(), &["a", "b", "file"], b"two").unwrap();
        assert_eq!(std::fs::read(&file).unwrap(), b"two");

        std::os::unix::fs::symlink(elsewhere.path(), dir.path().join("linked")).unwrap();
        assert!(write_replacing(dir.path(), &["linked", "file"], b"x", 0o644).is_err());
        assert!(write_in_place(dir.path(), &["linked", "file"], b"x").is_err());
        assert!(std::fs::read_dir(elsewhere.path())
            .unwrap()
            .next()
            .is_none());

        let target = elsewhere.path().join("target");
        std::fs::write(&target, b"root's").unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join("swapped")).unwrap();
        assert!(write_in_place(dir.path(), &["swapped"], b"new").is_err());
        write_replacing(dir.path(), &["swapped"], b"new", 0o644).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"root's");
        let swapped = dir.path().join("swapped");
        assert!(std::fs::symlink_metadata(&swapped).unwrap().is_file());
        assert_eq!(std::fs::read(&swapped).unwrap(), b"new");

        assert!(write_replacing(dir.path(), &["..", "escape"], b"x", 0o644).is_err());
    }
}
