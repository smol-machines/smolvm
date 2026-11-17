//! Reading and writing below a directory another user may control, without
//! following links.
//!
//! A machine's data directory belongs to the machine's own user while it runs
//! under per-VM uid isolation, and the host (root under `serve`) still reads
//! and writes a few files there. A process escaped from the machine could swap
//! any of them, or a directory on the way, for a link to somewhere root can
//! reach, a FIFO that hangs the reader, or a device that never ends. Every
//! component below the base directory is therefore opened without following a
//! link, directories with `O_DIRECTORY`, files only if they are regular, never
//! blocking on open, and reads are capped.

use std::path::Path;

/// Read `base/<components…>`, at most `max` bytes: `base` itself and every
/// component below it opened without following a link, each directory with
/// `O_DIRECTORY` and the file required to be regular. A longer file is an
/// error, never a truncated read.
#[cfg(unix)]
pub(crate) fn read(base: &Path, components: &[&str], max: u64) -> std::io::Result<Vec<u8>> {
    let (file, dirs) = components
        .split_last()
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let dir = unix::open_dirs(base, dirs, false)?;
    let file = std::fs::File::from(unix::open_at(
        &dir,
        file,
        libc::O_RDONLY | libc::O_NONBLOCK,
        0,
    )?);
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    read_capped(&file, max)
}

#[cfg(not(unix))]
pub(crate) fn read(base: &Path, components: &[&str], max: u64) -> std::io::Result<Vec<u8>> {
    let path = windows::checked_path(base, components, false)?;
    let file = std::fs::File::open(&path)?;
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

/// Replace `base/<components…>` with `bytes`, mode `mode`, whole: written to a
/// new file beside it and renamed over it, so a reader never sees it partly
/// written. Missing directories on the way are created (mode `0o755`). No
/// component is followed if it is a link; a link at the file's own name is
/// replaced, never written through.
#[cfg(unix)]
pub(crate) fn write_replacing(
    base: &Path,
    components: &[&str],
    bytes: &[u8],
    mode: u32,
) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::fd::AsRawFd;
    let (name, dirs) = components
        .split_last()
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let dir = unix::open_dirs(base, dirs, true)?;
    let tmp = format!(".{name}.{}.tmp", std::process::id());
    let _ = unix::unlink_at(&dir, &tmp);
    let written = unix::open_at(
        &dir,
        &tmp,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        mode,
    )
    .and_then(|fd| {
        let mut file = std::fs::File::from(fd);
        file.write_all(bytes)?;
        // Its final mode whatever the umask was.
        // SAFETY: a live descriptor this function owns.
        if unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    })
    .and_then(|()| unix::rename_at(&dir, &tmp, name));
    if written.is_err() {
        let _ = unix::unlink_at(&dir, &tmp);
    }
    written
}

/// Windows has no per-VM user to defend against, so this only refuses a link
/// or junction on the way and otherwise replaces the file as Unix does.
#[cfg(not(unix))]
pub(crate) fn write_replacing(
    base: &Path,
    components: &[&str],
    bytes: &[u8],
    mode: u32,
) -> std::io::Result<()> {
    let _ = mode;
    let path = windows::checked_path(base, components, true)?;
    let name = path
        .file_name()
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?
        .to_string_lossy()
        .into_owned();
    let tmp = path.with_file_name(format!(".{name}.{}.tmp", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .and_then(|mut file| std::io::Write::write_all(&mut file, bytes))
        .and_then(|()| std::fs::rename(&tmp, &path));
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written
}

#[cfg(unix)]
mod unix {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    fn c_name(name: &[u8]) -> std::io::Result<std::ffi::CString> {
        std::ffi::CString::new(name)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))
    }

    fn component(name: &str) -> std::io::Result<std::ffi::CString> {
        // One name, never a path: no separator, and not `.` or `..`.
        if name.is_empty() || name == "." || name == ".." || name.contains('/') {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
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
    /// following a link; with `create`, a missing one is made first.
    pub(super) fn open_dirs(base: &Path, dirs: &[&str], create: bool) -> std::io::Result<OwnedFd> {
        let path = c_name(base.as_os_str().as_bytes())?;
        // SAFETY: a NUL-terminated path.
        let mut dir = owned(unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        })?;
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
        Ok(dir)
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
        let refuse_link = |path: &Path| -> std::io::Result<()> {
            match std::fs::symlink_metadata(path) {
                Ok(meta) if meta.file_type().is_symlink() => Err(std::io::Error::other(format!(
                    "{} is a link",
                    path.display()
                ))),
                Ok(meta) if is_reparse_point(&meta) => Err(std::io::Error::other(format!(
                    "{} is a reparse point",
                    path.display()
                ))),
                Ok(_) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error),
            }
        };
        refuse_link(base)?;
        let (_, dirs) = components
            .split_last()
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        let mut path = base.to_path_buf();
        for (index, name) in components.iter().enumerate() {
            if name.is_empty() || *name == "." || *name == ".." || name.contains(['/', '\\']) {
                return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
            }
            path.push(name);
            refuse_link(&path)?;
            if create && index < dirs.len() {
                match std::fs::create_dir(&path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(path)
    }

    fn is_reparse_point(meta: &std::fs::Metadata) -> bool {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// Nothing is read through a link, a FIFO never blocks the reader, and a
    /// file past the cap is refused rather than read whole.
    #[test]
    fn reads_refuse_links_fifos_and_oversized_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("plain"), b"hello").unwrap();
        assert_eq!(read(dir.path(), &["plain"], 16).unwrap(), b"hello");
        assert!(read(dir.path(), &["plain"], 4).is_err(), "over the cap");

        std::os::unix::fs::symlink(dir.path().join("plain"), dir.path().join("link")).unwrap();
        assert!(read(dir.path(), &["link"], 16).is_err());
        std::os::unix::fs::symlink("/dev/zero", dir.path().join("zero")).unwrap();
        assert!(read(dir.path(), &["zero"], 16).is_err());

        let fifo = std::ffi::CString::new(dir.path().join("fifo").to_str().unwrap()).unwrap();
        // SAFETY: a NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(
            read(dir.path(), &["fifo"], 16).is_err(),
            "refused, not blocked"
        );

        // A linked directory on the way is refused too.
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("f"), b"x").unwrap();
        std::os::unix::fs::symlink(&sub, dir.path().join("linked")).unwrap();
        assert!(read(dir.path(), &["linked", "f"], 16).is_err());
        assert!(read(&dir.path().join("linked"), &["f"], 16).is_err());
    }

    /// A write never goes through a link: a linked directory on the way is
    /// refused, and a link at the file's own name is replaced, not followed.
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

        std::os::unix::fs::symlink(elsewhere.path(), dir.path().join("linked")).unwrap();
        assert!(write_replacing(dir.path(), &["linked", "file"], b"x", 0o644).is_err());
        assert!(std::fs::read_dir(elsewhere.path())
            .unwrap()
            .next()
            .is_none());

        let target = elsewhere.path().join("target");
        std::fs::write(&target, b"root's").unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join("swapped")).unwrap();
        write_replacing(dir.path(), &["swapped"], b"new", 0o644).unwrap();
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"root's",
            "not written through"
        );
        let swapped = dir.path().join("swapped");
        assert!(std::fs::symlink_metadata(&swapped).unwrap().is_file());
        assert_eq!(std::fs::read(&swapped).unwrap(), b"new");

        assert!(write_replacing(dir.path(), &["..", "escape"], b"x", 0o644).is_err());
    }
}
