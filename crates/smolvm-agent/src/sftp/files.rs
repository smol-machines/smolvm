//! Guest filesystem operations; kernel permissions apply to the helper's user.
use super::wire::{self, Failure, Packet, Result};
use std::{
    ffi::CString,
    fs::{self, File, Metadata},
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{FileExt, MetadataExt},
        },
    },
    path::{Path, PathBuf},
};

#[derive(Default)]
pub struct Attributes {
    pub size: Option<u64>,
    pub owner: Option<(u32, u32)>,
    pub mode: Option<u32>,
    pub times: Option<(u32, u32)>,
}
impl Attributes {
    pub fn read(packet: &mut Packet<'_>) -> Result<Self> {
        let flags = packet.u32()?;
        if flags & !0x8000000f != 0 {
            return Err(Failure::bad());
        }
        let attrs = Self {
            size: if flags & 1 != 0 {
                Some(packet.u64()?)
            } else {
                None
            },
            owner: if flags & 2 != 0 {
                Some((packet.u32()?, packet.u32()?))
            } else {
                None
            },
            mode: if flags & 4 != 0 {
                Some(packet.u32()?)
            } else {
                None
            },
            times: if flags & 8 != 0 {
                Some((packet.u32()?, packet.u32()?))
            } else {
                None
            },
        };
        if flags & 0x80000000 != 0 {
            let count = packet.u32()? as usize;
            if count > packet.0.len() / 8 {
                return Err(Failure::bad());
            }
            for _ in 0..count {
                packet.string()?;
                packet.string()?;
            }
        }
        if attrs.size.is_some_and(|size| size > i64::MAX as u64) {
            return Err(Failure::bad());
        }
        Ok(attrs)
    }
}
pub fn attrs(out: &mut Vec<u8>, m: &Metadata) {
    wire::u32(out, 15);
    wire::u64(out, m.len());
    wire::u32(out, m.uid());
    wire::u32(out, m.gid());
    wire::u32(out, m.mode());
    wire::u32(out, m.atime().clamp(0, u32::MAX as i64) as u32);
    wire::u32(out, m.mtime().clamp(0, u32::MAX as i64) as u32);
}
pub fn name(out: &mut Vec<u8>, bytes: &[u8], m: Option<&Metadata>) {
    wire::string(out, bytes);
    let mut long = Vec::new();
    if let Some(m) = m {
        let mode = m.mode();
        let mut perms = *b"----------";
        perms[0] = match mode & libc::S_IFMT {
            libc::S_IFDIR => b'd',
            libc::S_IFLNK => b'l',
            libc::S_IFCHR => b'c',
            libc::S_IFBLK => b'b',
            libc::S_IFIFO => b'p',
            libc::S_IFSOCK => b's',
            _ => b'-',
        };
        for (i, letter) in b"rwxrwxrwx".iter().enumerate() {
            if mode & (1 << (8 - i)) != 0 {
                perms[i + 1] = *letter;
            }
        }
        for (flag, index, lower, upper) in [
            (0o4000, 3, b's', b'S'),
            (0o2000, 6, b's', b'S'),
            (0o1000, 9, b't', b'T'),
        ] {
            if mode & flag != 0 {
                perms[index] = if perms[index] == b'x' { lower } else { upper };
            }
        }
        long.extend_from_slice(&perms);
        long.extend_from_slice(
            format!(" {} {} {} {} ", m.nlink(), m.uid(), m.gid(), m.len()).as_bytes(),
        );
        let seconds = m.mtime() as _;
        let mut time = std::mem::MaybeUninit::<libc::tm>::uninit();
        // SAFETY: valid input and output storage, no shared libc time buffer.
        if !unsafe { libc::gmtime_r(&seconds, time.as_mut_ptr()) }.is_null() {
            let time = unsafe { time.assume_init() };
            let month = [
                "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
            ]
            .get(time.tm_mon as usize)
            .unwrap_or(&"Jan");
            long.extend_from_slice(
                format!("{month} {:2} {:04} ", time.tm_mday, time.tm_year + 1900).as_bytes(),
            );
        }
    }
    long.extend_from_slice(bytes);
    wire::string(out, &long);
    if let Some(m) = m {
        attrs(out, m);
    } else {
        wire::u32(out, 0);
    }
}
fn cpath(path: &Path) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| Failure::bad())
}
fn checked(result: libc::c_int) -> Result<()> {
    if result < 0 {
        Err(io::Error::last_os_error().into())
    } else {
        Ok(())
    }
}

pub fn open(path: &Path, flags: u32, attrs: &Attributes) -> Result<File> {
    if flags & !63 != 0
        || flags & 3 == 0
        || (flags & 20 != 0 && flags & 2 == 0)
        || (flags & 32 != 0 && flags & 8 == 0)
    {
        return Err(Failure::bad());
    }
    let mut native = libc::O_CLOEXEC
        | match flags & 3 {
            1 => libc::O_RDONLY,
            2 => libc::O_WRONLY,
            _ => libc::O_RDWR,
        };
    for (flag, value) in [
        (4, libc::O_APPEND),
        (8, libc::O_CREAT),
        (16, libc::O_TRUNC),
        (32, libc::O_EXCL),
    ] {
        if flags & flag != 0 {
            native |= value;
        }
    }
    let path = cpath(path)?;
    // SAFETY: NUL-terminated path and valid open flags; successful fd is owned.
    let fd = unsafe { libc::open(path.as_ptr(), native, attrs.mode.unwrap_or(0o666) & 0o7777) };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
pub enum Target<'a> {
    Path(&'a Path),
    File(&'a File),
}
pub fn set(target: Target<'_>, attrs: Attributes) -> Result<()> {
    let path = match target {
        Target::Path(p) => Some(cpath(p)?),
        Target::File(_) => None,
    };
    if let Some(size) = attrs.size {
        match target {
            Target::Path(p) => fs::OpenOptions::new().write(true).open(p)?.set_len(size)?,
            Target::File(file) => file.set_len(size)?,
        }
    }
    if let Some((uid, gid)) = attrs.owner {
        // SAFETY: path or descriptor remains valid throughout the syscall.
        checked(unsafe {
            match target {
                Target::Path(_) => libc::chown(path.as_ref().unwrap().as_ptr(), uid, gid),
                Target::File(f) => libc::fchown(f.as_raw_fd(), uid, gid),
            }
        })?;
    }
    if let Some(mode) = attrs.mode {
        checked(unsafe {
            match target {
                Target::Path(_) => libc::chmod(path.as_ref().unwrap().as_ptr(), mode & 0o7777),
                Target::File(f) => libc::fchmod(f.as_raw_fd(), mode & 0o7777),
            }
        })?;
    }
    if let Some((atime, mtime)) = attrs.times {
        let times = [
            libc::timespec {
                tv_sec: atime.into(),
                tv_nsec: 0,
            },
            libc::timespec {
                tv_sec: mtime.into(),
                tv_nsec: 0,
            },
        ];
        checked(unsafe {
            match target {
                Target::Path(_) => libc::utimensat(
                    libc::AT_FDCWD,
                    path.as_ref().unwrap().as_ptr(),
                    times.as_ptr(),
                    0,
                ),
                Target::File(f) => libc::futimens(f.as_raw_fd(), times.as_ptr()),
            }
        })?;
    }
    Ok(())
}
pub fn rename(source: &Path, destination: &Path) -> Result<()> {
    let source = cpath(source)?;
    let destination = cpath(destination)?;
    // SFTP v3 rename must not replace an existing destination; check atomically.
    checked(unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        ) as libc::c_int
    })
}
pub fn realpath(path: &Path) -> Result<PathBuf> {
    canonical(path, 0)
}
fn canonical(path: &Path, depth: usize) -> Result<PathBuf> {
    if depth >= 40 {
        return Err(Failure::failed("Too many symbolic links"));
    }
    let path = if path.as_os_str().is_empty() {
        Path::new(".")
    } else {
        path
    };
    match fs::canonicalize(path) {
        Ok(path) => Ok(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // OpenSSH allows a missing final component, including the target of
            // a dangling symlink, but requires its parent to exist.
            if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
                let target = fs::read_link(path)?;
                let target = if target.is_absolute() {
                    target
                } else {
                    path.parent().unwrap_or(Path::new(".")).join(target)
                };
                return canonical(&target, depth + 1);
            }
            if path.as_os_str().as_bytes().ends_with(b"/") {
                return Err(error.into());
            }
            let file = path.file_name().ok_or_else(|| Failure::from(error))?;
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            Ok(fs::canonicalize(parent)?.join(file))
        }
        Err(error) => Err(error.into()),
    }
}
pub fn expand(path: &Path) -> Result<PathBuf> {
    let bytes = path.as_os_str().as_bytes();
    if !bytes.starts_with(b"~") {
        return realpath(path);
    }
    let end = bytes.iter().position(|b| *b == b'/').unwrap_or(bytes.len());
    let user = &bytes[1..end];
    let home = if user.is_empty() {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| Failure::failed("Home directory unavailable"))?
    } else {
        use std::io::Read;
        let mut passwd = Vec::new();
        File::open("/etc/passwd")?
            .take(1024 * 1024)
            .read_to_end(&mut passwd)?;
        let entry = passwd
            .split(|b| *b == b'\n')
            .find(|entry| entry.split(|b| *b == b':').next() == Some(user))
            .ok_or_else(|| Failure::failed("Unknown user"))?;
        PathBuf::from(std::ffi::OsStr::from_bytes(
            entry
                .split(|b| *b == b':')
                .nth(5)
                .ok_or_else(|| Failure::failed("Invalid user entry"))?,
        ))
    };
    realpath(
        &home.join(std::ffi::OsStr::from_bytes(if end < bytes.len() {
            &bytes[end + 1..]
        } else {
            b""
        })),
    )
}
pub fn statvfs(target: Target<'_>, out: &mut Vec<u8>) -> Result<()> {
    let mut value = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    let path = match target {
        Target::Path(p) => Some(cpath(p)?),
        Target::File(_) => None,
    };
    checked(unsafe {
        match target {
            Target::Path(_) => libc::statvfs(path.as_ref().unwrap().as_ptr(), value.as_mut_ptr()),
            Target::File(f) => libc::fstatvfs(f.as_raw_fd(), value.as_mut_ptr()),
        }
    })?;
    let v = unsafe { value.assume_init() };
    #[allow(clippy::unnecessary_cast)]
    for n in [
        v.f_bsize as u64,
        v.f_frsize as u64,
        v.f_blocks as u64,
        v.f_bfree as u64,
        v.f_bavail as u64,
        v.f_files as u64,
        v.f_ffree as u64,
        v.f_favail as u64,
        v.f_fsid as u64,
        (v.f_flag & (libc::ST_RDONLY | libc::ST_NOSUID)) as u64,
        v.f_namemax as u64,
    ] {
        wire::u64(out, n);
    }
    Ok(())
}
pub fn copy(
    source: &File,
    mut from: u64,
    length: u64,
    destination: &File,
    mut to: u64,
) -> Result<()> {
    let a = source.metadata()?;
    let b = destination.metadata()?;
    if a.dev() == b.dev() && a.ino() == b.ino() {
        return Err(Failure::failed("Source and destination are the same file"));
    }
    let mut remaining = if length == 0 {
        a.len().saturating_sub(from)
    } else {
        length
    };
    if from
        .checked_add(remaining)
        .is_none_or(|n| n > i64::MAX as u64)
        || to
            .checked_add(remaining)
            .is_none_or(|n| n > i64::MAX as u64)
    {
        return Err(Failure::bad());
    }
    let mut buffer = [0; 65536];
    while remaining > 0 {
        let count = source.read_at(&mut buffer[..remaining.min(65536) as usize], from)?;
        if count == 0 {
            return Err(Failure::eof());
        }
        destination.write_all_at(&buffer[..count], to)?;
        from += count as u64;
        to += count as u64;
        remaining -= count as u64;
    }
    Ok(())
}
