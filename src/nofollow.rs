//! Reading and writing below a directory another user may control, without
//! following links.
//!
//! A machine's data directory belongs to the machine's own user while it runs
//! under per-VM uid isolation, and the host (root under `serve`) still reads
//! and writes files there: its credential CAs, its running configuration. A
//! process escaped from the machine could swap any of them, or a directory on
//! the way, for a link to somewhere only root can reach, a hard link to a file
//! elsewhere, or a FIFO that hangs the reader. So every component below the
//! base directory is opened relative to its parent's descriptor without
//! following a link, directories with `O_DIRECTORY`, files only when regular
//! and never blocking on open. The base itself is the trusted path to the
//! machine's directory: its ancestors (a linked cache or runtime directory)
//! are followed as usual. A file read, or opened to lock, must have one name
//! only and belong to this process's user, root or the base directory's
//! owner, and reads are capped. What root creates below the base takes the
//! owner of the directory it is created in, so the machine's own process can
//! still read it.

use std::path::Path;

/// Read `base/<components…>`, at most `max` bytes. A longer file is an error,
/// never a truncated read.
#[cfg(unix)]
pub(crate) fn read(base: &Path, components: &[&str], max: u64) -> std::io::Result<Vec<u8>> {
    let (name, dirs) = split(components)?;
    let (dir, base_owner) = unix::open_dirs(base, dirs, false)?;
    let base_owner = base_owner.uid;
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
        .is_ok_and(|stat| stat.st_mode & libc::S_IFMT == libc::S_IFREG)
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
    let (dir, owner) = unix::open_dirs(base, dirs, true)?;
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
            unix::adopt(owner, &file)?;
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

/// Open `base/<components…>` to hold an advisory lock on, read and write,
/// creating it (mode `0o600`, handed to the base directory's owner when root
/// creates it) and any directory on the way when missing. An existing one must
/// be regular, have one name only and belong to this user, root or the base
/// directory's owner; a FIFO in its place never blocks the open. No component
/// is followed if it is a link.
#[cfg(unix)]
pub(crate) fn open_lock_file(base: &Path, components: &[&str]) -> std::io::Result<std::fs::File> {
    let (name, dirs) = split(components)?;
    let (dir, owner) = unix::open_dirs(base, dirs, true)?;
    let flags = libc::O_RDWR | libc::O_NONBLOCK;
    let file = match unix::open_at(&dir, name, flags | libc::O_CREAT | libc::O_EXCL, 0o600) {
        Ok(created) => {
            let file = std::fs::File::from(created);
            unix::adopt(owner, &file)?;
            file
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            std::fs::File::from(unix::open_at(&dir, name, flags, 0)?)
        }
        Err(e) => return Err(e),
    };
    unix::check_file(&file, owner.uid)?;
    Ok(file)
}

#[cfg(not(unix))]
pub(crate) fn open_lock_file(base: &Path, components: &[&str]) -> std::io::Result<std::fs::File> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(windows::checked_path(base, components, true)?)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    Ok(file)
}

/// A socket file found in a machine's directory without following a link.
#[cfg(unix)]
pub(crate) struct SocketFile {
    /// The socket file itself, opened `O_PATH`, to connect to through
    /// `/proc/self/fd`: what is reached is then the inode checked here,
    /// whatever its name is swapped for meanwhile.
    #[cfg(target_os = "linux")]
    path_fd: std::os::fd::OwnedFd,
    /// Device and inode of the socket file.
    pub(crate) id: (u64, u64),
    /// Owner of the directory holding it: the machine's own user.
    pub(crate) dir_owner: u32,
}

#[cfg(unix)]
impl SocketFile {
    /// A short path naming exactly this socket file, where the platform has
    /// one (`/proc/self/fd/N` on Linux, when `/proc` is mounted).
    pub(crate) fn pinned_path(&self) -> Option<std::path::PathBuf> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            let path =
                std::path::PathBuf::from(format!("/proc/self/fd/{}", self.path_fd.as_raw_fd()));
            if path.exists() {
                return Some(path);
            }
        }
        None
    }
}

/// Find socket `name` in directory `base` without following a link: it must
/// be a socket, have one name only (a hard link to a socket elsewhere has
/// two) and belong to this user, root or `base`'s owner.
#[cfg(unix)]
pub(crate) fn socket(base: &Path, name: &str) -> std::io::Result<SocketFile> {
    let (dir, owner) = unix::open_dirs(base, &[], false)?;
    let dir_owner = owner.uid;
    // (is a socket, names, owner, device, inode), read off the file itself, never a link's target
    #[cfg(target_os = "linux")]
    let (path_fd, (is_socket, nlink, uid, dev, ino)) = {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let fd = unix::open_at(&dir, name, libc::O_PATH, 0)?;
        let meta = std::fs::File::from(fd.try_clone()?).metadata()?;
        let status = (
            meta.file_type().is_socket(),
            meta.nlink(),
            meta.uid(),
            meta.dev(),
            meta.ino(),
        );
        (fd, status)
    };
    #[cfg(not(target_os = "linux"))]
    #[allow(clippy::unnecessary_cast)] // the field types differ between platforms
    let (is_socket, nlink, uid, dev, ino) = {
        let stat = unix::stat_at(&dir, name)?;
        (
            stat.st_mode & libc::S_IFMT == libc::S_IFSOCK,
            stat.st_nlink as u64,
            stat.st_uid,
            stat.st_dev as u64,
            stat.st_ino as u64,
        )
    };
    if !is_socket {
        return Err(std::io::Error::other("not a socket"));
    }
    if nlink != 1 {
        return Err(std::io::Error::other("a socket with more than one name"));
    }
    // SAFETY: geteuid has no preconditions.
    if !unix::owner_allowed(uid, unsafe { libc::geteuid() }, dir_owner) {
        return Err(std::io::Error::other(
            "a socket owned by neither this user, root nor the directory's owner",
        ));
    }
    Ok(SocketFile {
        #[cfg(target_os = "linux")]
        path_fd,
        id: (dev, ino),
        dir_owner,
    })
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

    /// The owner of a machine's directory: what root hands the files and
    /// directories it creates below it to.
    #[derive(Clone, Copy)]
    pub(crate) struct Owner {
        pub(crate) uid: u32,
        pub(crate) gid: u32,
    }

    /// `base` (its own path followed as usual: it and its ancestors are
    /// trusted), then each of `dirs` below it, opened as directories without
    /// following a link, with the owner of `base` as it was opened. With
    /// `create`, a missing one is made first; one root makes for another
    /// user is handed to `base`'s owner ([`make_dir_handed_over`]).
    pub(super) fn open_dirs(
        base: &Path,
        dirs: &[&str],
        create: bool,
    ) -> std::io::Result<(OwnedFd, Owner)> {
        let path = c_name(base.as_os_str().as_bytes())?;
        // SAFETY: a NUL-terminated path.
        let mut dir = owned(unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        })?;
        let meta = std::fs::File::from(dir.try_clone()?).metadata()?;
        let owner = Owner {
            uid: meta.uid(),
            gid: meta.gid(),
        };
        let open =
            |dir: &OwnedFd, name: &str| open_at(dir, name, libc::O_RDONLY | libc::O_DIRECTORY, 0);
        for name in dirs {
            dir = match open(&dir, name) {
                Err(e) if create && e.kind() == std::io::ErrorKind::NotFound => {
                    // SAFETY: geteuid has no preconditions.
                    match adopted_owner(unsafe { libc::geteuid() }, owner.uid, owner.gid) {
                        Some((uid, gid)) => make_dir_handed_over(&dir, name, uid, gid)?,
                        None => {
                            make_dir_at(&dir, name, 0o755).or_else(|e| {
                                if e.kind() == std::io::ErrorKind::AlreadyExists {
                                    Ok(())
                                } else {
                                    Err(e)
                                }
                            })?;
                            open(&dir, name)?
                        }
                    }
                }
                opened => opened?,
            };
        }
        Ok((dir, owner))
    }

    fn make_dir_at(dir: &OwnedFd, name: &str, mode: libc::mode_t) -> std::io::Result<()> {
        let c = component(name)?;
        // SAFETY: a NUL-terminated name and a live directory descriptor.
        if unsafe { libc::mkdirat(dir.as_raw_fd(), c.as_ptr(), mode) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn remove_dir_at(dir: &OwnedFd, name: &str) -> std::io::Result<()> {
        let name = component(name)?;
        // SAFETY: a NUL-terminated name and a live directory descriptor.
        if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Make directory `name` in `parent` (which another user may write to),
    /// owned by `uid`:`gid`, and open it. A directory is only ever handed
    /// over on a descriptor known to be the one just made: it is made inside
    /// a new staging directory private to this process, which nobody else
    /// can enter to swap it, then renamed into place. Handing over whatever
    /// is at `name` once made would let the other user rename one of root's
    /// own directories there first. Should `name` appear meanwhile, that one
    /// is opened as it is, not handed over.
    pub(super) fn make_dir_handed_over(
        parent: &OwnedFd,
        name: &str,
        uid: u32,
        gid: u32,
    ) -> std::io::Result<OwnedFd> {
        let (stage_name, ()) = super::unique_temp(name, |tmp| make_dir_at(parent, tmp, 0o700))?;
        let made = (|| {
            let stage = open_at(parent, &stage_name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
            // whatever is at the staging name now, nobody else may enter it
            let meta = std::fs::File::from(stage.try_clone()?).metadata()?;
            // SAFETY: geteuid has no preconditions.
            if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
                return Err(std::io::Error::other("staging directory is not private"));
            }
            make_dir_at(&stage, name, 0o755)?;
            let child = open_at(&stage, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
            // SAFETY: a live descriptor.
            if unsafe { libc::fchown(child.as_raw_fd(), uid, gid) } != 0 {
                let error = std::io::Error::last_os_error();
                let _ = remove_dir_at(&stage, name);
                return Err(error);
            }
            let (from, to) = (component(name)?, component(name)?);
            // SAFETY: NUL-terminated names and live directory descriptors.
            if unsafe {
                libc::renameat(
                    stage.as_raw_fd(),
                    from.as_ptr(),
                    parent.as_raw_fd(),
                    to.as_ptr(),
                )
            } != 0
            {
                let error = std::io::Error::last_os_error();
                let _ = remove_dir_at(&stage, name);
                return match error.raw_os_error() {
                    Some(libc::EEXIST) | Some(libc::ENOTEMPTY) => {
                        open_at(parent, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)
                    }
                    _ => Err(error),
                };
            }
            Ok(child)
        })();
        let _ = remove_dir_at(parent, &stage_name);
        made
    }

    /// An opened file may be read or written: regular, one name only (a hard
    /// link to a file elsewhere has two), and owned by this process's user,
    /// root or `base_owner` ([`owner_allowed`]), never by anyone else.
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
                "a file owned by neither this user, root nor the directory's owner",
            ));
        }
        Ok(())
    }

    /// Whether a file `owner` owns may be trusted by a process running as `me`
    /// below a directory `base_owner` owns: its own, root's (a machine
    /// directory a root process wrote into) or the directory owner's (the
    /// machine's own user), never a third user's.
    pub(super) fn owner_allowed(owner: u32, me: u32, base_owner: u32) -> bool {
        owner == me || owner == 0 || owner == base_owner
    }

    /// Give `made`, a file this process just created below a machine's
    /// directory, that directory's `owner` when this process is root and the
    /// directory is another user's: a file root writes there stays readable
    /// by the machine's own process, as everything else there is, whoever
    /// owns the directory it is created in (one an older root left behind).
    pub(super) fn adopt(owner: Owner, made: &std::fs::File) -> std::io::Result<()> {
        // SAFETY: geteuid has no preconditions.
        let me = unsafe { libc::geteuid() };
        match adopted_owner(me, owner.uid, owner.gid) {
            // SAFETY: a live descriptor.
            Some((uid, gid)) if unsafe { libc::fchown(made.as_raw_fd(), uid, gid) } != 0 => {
                Err(std::io::Error::last_os_error())
            }
            _ => Ok(()),
        }
    }

    /// The owner a file created by `me` in a directory `dir_uid`:`dir_gid`
    /// owns is given, when it is not left as created: only root hands a file
    /// over, and only to another user.
    pub(super) fn adopted_owner(me: u32, dir_uid: u32, dir_gid: u32) -> Option<(u32, u32)> {
        (me == 0 && dir_uid != 0).then_some((dir_uid, dir_gid))
    }

    /// The status of `name` in `dir`, itself when it is a link.
    pub(super) fn stat_at(dir: &OwnedFd, name: &str) -> std::io::Result<libc::stat> {
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
        Ok(stat)
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
        assert!(!is_file(dir.path(), &["fifo"]));

        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("f"), b"x").unwrap();
        std::os::unix::fs::symlink(&sub, dir.path().join("linked")).unwrap();
        assert!(read(dir.path(), &["linked", "f"], 16).is_err());
        // the base is the trusted path itself: a link above the machine's directory is followed
        assert_eq!(read(&dir.path().join("linked"), &["f"], 16).unwrap(), b"x");
        assert!(list(dir.path(), &["linked"]).is_err());
        assert_eq!(list(dir.path(), &["sub"]).unwrap(), ["f"]);

        std::fs::hard_link(dir.path().join("plain"), sub.join("second")).unwrap();
        let err = read(&sub, &["second"], 64).unwrap_err();
        assert!(err.to_string().contains("more than one name"), "{err}");
        // replaced by name, never written through to the file it shares
        write_replacing(&sub, &["second"], b"x", 0o644).unwrap();
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
        // root's file in a user's directory (written by an earlier `sudo smolvm`) stays readable
        assert!(unix::owner_allowed(0, 1000, 1000));
        assert!(!unix::owner_allowed(5001, 1000, 1000));
    }

    /// Root hands what it creates in a machine's directory to the directory's
    /// owner; anyone else, or root in its own directory, leaves it as created.
    #[test]
    fn only_root_hands_what_it_creates_to_the_directorys_owner() {
        assert_eq!(unix::adopted_owner(0, 5001, 5001), Some((5001, 5001)));
        assert_eq!(unix::adopted_owner(0, 0, 0), None);
        assert_eq!(unix::adopted_owner(1000, 1000, 1000), None);
        assert_eq!(unix::adopted_owner(1000, 5001, 5001), None);
        // as this test's user, a new file and directory stay its own
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        write_replacing(dir.path(), &["d", "f"], b"x", 0o600).unwrap();
        // SAFETY: geteuid has no preconditions.
        let me = unsafe { libc::geteuid() };
        assert_eq!(std::fs::metadata(dir.path().join("d/f")).unwrap().uid(), me);
    }

    /// A directory handed to another owner is made in a private staging
    /// directory and renamed into place: it ends up at its name, owned as
    /// asked, with no staging directory left; a directory already at the
    /// name is opened as it is, never replaced.
    #[test]
    fn a_handed_over_directory_is_made_privately_then_moved_into_place() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let (parent, owner) = unix::open_dirs(dir.path(), &[], false).unwrap();
        let made = unix::make_dir_handed_over(&parent, "ca", owner.uid, owner.gid).unwrap();
        let meta = std::fs::metadata(dir.path().join("ca")).unwrap();
        assert!(meta.is_dir());
        assert_eq!((meta.uid(), meta.gid()), (owner.uid, owner.gid));
        assert_eq!(
            std::fs::File::from(made).metadata().unwrap().ino(),
            meta.ino(),
            "the descriptor is the directory now at the name"
        );
        assert_eq!(list(dir.path(), &[]).unwrap(), ["ca"], "no staging left");

        std::fs::create_dir(dir.path().join("taken")).unwrap();
        std::fs::write(dir.path().join("taken/keep"), b"x").unwrap();
        let taken = unix::make_dir_handed_over(&parent, "taken", owner.uid, owner.gid).unwrap();
        assert_eq!(
            std::fs::File::from(taken).metadata().unwrap().ino(),
            std::fs::metadata(dir.path().join("taken")).unwrap().ino()
        );
        assert!(dir.path().join("taken/keep").exists());
        let mut names = list(dir.path(), &[]).unwrap();
        names.sort();
        assert_eq!(names, ["ca", "taken"], "no staging left");
    }

    /// A socket is found only when it is one, under its own single name.
    #[test]
    fn sockets_are_found_only_unlinked_and_under_one_name() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let _listener = std::os::unix::net::UnixListener::bind(dir.path().join("s")).unwrap();
        let found = socket(dir.path(), "s").unwrap();
        // SAFETY: geteuid has no preconditions.
        assert_eq!(found.dir_owner, unsafe { libc::geteuid() });
        std::fs::write(dir.path().join("f"), b"x").unwrap();
        assert!(socket(dir.path(), "f").is_err());
        std::os::unix::fs::symlink(dir.path().join("s"), dir.path().join("l")).unwrap();
        assert!(socket(dir.path(), "l").is_err());
        let _other = std::os::unix::net::UnixListener::bind(elsewhere.path().join("o")).unwrap();
        std::fs::hard_link(elsewhere.path().join("o"), dir.path().join("h")).unwrap();
        assert!(socket(dir.path(), "h").is_err());
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
        write_replacing(dir.path(), &["a", "b", "file"], b"two", 0o600).unwrap();
        assert_eq!(std::fs::read(&file).unwrap(), b"two");

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
        assert_eq!(std::fs::read(&target).unwrap(), b"root's");
        let swapped = dir.path().join("swapped");
        assert!(std::fs::symlink_metadata(&swapped).unwrap().is_file());
        assert_eq!(std::fs::read(&swapped).unwrap(), b"new");

        assert!(write_replacing(dir.path(), &["..", "escape"], b"x", 0o644).is_err());
    }
}
