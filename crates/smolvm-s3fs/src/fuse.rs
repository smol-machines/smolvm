//! FUSE transport: mount, wire protocol, and the request loop.
//!
//! Talks the kernel protocol directly over `/dev/fuse` and mounts with
//! `mount(2)`. There is deliberately no libfuse and no `fusermount3`: the agent
//! runs as root (PID 1) in the guest, so it can mount without the setuid helper
//! that exists for unprivileged users. That is what lets a bucket be mounted
//! into *any* image — including distroless and scratch, where no helper binary
//! or package manager exists.

#[cfg(target_os = "linux")]
use std::fs::{File, OpenOptions};
#[cfg(target_os = "linux")]
use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "linux")]
use std::sync::Arc;

pub const FUSE_ROOT_ID: u64 = 1;

// Opcodes we handle; everything else is answered ENOSYS.
pub mod op {
    pub const LOOKUP: u32 = 1;
    pub const FORGET: u32 = 2;
    pub const GETATTR: u32 = 3;
    pub const SETATTR: u32 = 4;
    pub const MKDIR: u32 = 9;
    pub const UNLINK: u32 = 10;
    pub const RMDIR: u32 = 11;
    pub const RENAME: u32 = 12;
    pub const OPEN: u32 = 14;
    pub const READ: u32 = 15;
    pub const WRITE: u32 = 16;
    pub const STATFS: u32 = 17;
    pub const RELEASE: u32 = 18;
    pub const FSYNC: u32 = 20;
    pub const SETXATTR: u32 = 21;
    pub const GETXATTR: u32 = 22;
    pub const LISTXATTR: u32 = 23;
    pub const REMOVEXATTR: u32 = 24;
    pub const FLUSH: u32 = 25;
    pub const INIT: u32 = 26;
    pub const OPENDIR: u32 = 27;
    pub const READDIR: u32 = 28;
    pub const RELEASEDIR: u32 = 29;
    pub const FSYNCDIR: u32 = 30;
    pub const CREATE: u32 = 35;
    pub const DESTROY: u32 = 38;
    pub const LSEEK: u32 = 46;
}

/// File attributes, in the order `fuse_attr` declares them.
#[derive(Clone, Copy, Debug, Default)]
pub struct Attr {
    pub ino: u64,
    pub size: u64,
    pub blocks: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
}

impl Attr {
    /// Serialise into the kernel's `fuse_attr` layout.
    ///
    /// Only a mounted session replies to the kernel, and that is Linux-only, so
    /// off Linux the sole caller is the layout test — without this gate the
    /// method reads as dead code and fails a `-D warnings` build there.
    #[cfg(any(target_os = "linux", test))]
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.ino.to_ne_bytes());
        out.extend_from_slice(&self.size.to_ne_bytes());
        out.extend_from_slice(&self.blocks.to_ne_bytes());
        out.extend_from_slice(&self.atime.to_ne_bytes());
        out.extend_from_slice(&self.mtime.to_ne_bytes());
        out.extend_from_slice(&self.ctime.to_ne_bytes());
        out.extend_from_slice(&0u32.to_ne_bytes()); // atimensec
        out.extend_from_slice(&0u32.to_ne_bytes()); // mtimensec
        out.extend_from_slice(&0u32.to_ne_bytes()); // ctimensec
        out.extend_from_slice(&self.mode.to_ne_bytes());
        out.extend_from_slice(&self.nlink.to_ne_bytes());
        out.extend_from_slice(&self.uid.to_ne_bytes());
        out.extend_from_slice(&self.gid.to_ne_bytes());
        out.extend_from_slice(&0u32.to_ne_bytes()); // rdev
        out.extend_from_slice(&4096u32.to_ne_bytes()); // blksize
        out.extend_from_slice(&0u32.to_ne_bytes()); // flags
    }
}

/// A parsed request handed to the filesystem.
pub struct Request<'a> {
    pub opcode: u32,
    pub unique: u64,
    pub nodeid: u64,
    pub uid: u32,
    pub gid: u32,
    pub data: &'a [u8],
}

impl Request<'_> {
    /// NUL-terminated name at `offset`, as LOOKUP/CREATE/MKDIR carry.
    pub fn name_at(&self, offset: usize) -> Option<String> {
        let rest = self.data.get(offset..)?;
        let end = rest.iter().position(|b| *b == 0)?;
        std::str::from_utf8(&rest[..end])
            .ok()
            .map(|s| s.to_string())
    }

    pub fn u32_at(&self, offset: usize) -> u32 {
        self.data
            .get(offset..offset + 4)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_ne_bytes)
            .unwrap_or(0)
    }

    pub fn u64_at(&self, offset: usize) -> u64 {
        self.data
            .get(offset..offset + 8)
            .and_then(|b| b.try_into().ok())
            .map(u64::from_ne_bytes)
            .unwrap_or(0)
    }
}

/// Replies a handler can produce. Keeping this an enum (rather than letting
/// handlers write to the device) means the loop owns all framing, so a handler
/// can never emit a malformed or duplicate reply.
pub enum Reply {
    Ok,
    Error(i32),
    Attr(Attr),
    /// (attr, generation) for LOOKUP-style replies.
    Entry(Attr),
    /// CREATE answers with both the new entry and an open file handle.
    Create(Attr, u64),
    Open(u64),
    Data(Vec<u8>),
    Written(u32),
    Directory(Vec<u8>),
    StatFs {
        blocks: u64,
        bfree: u64,
        bavail: u64,
        files: u64,
    },
}

/// What the session calls for each request.
pub trait Filesystem: Send + Sync {
    fn dispatch(&self, req: &Request<'_>) -> Reply;
}

/// An active mount. Dropping it unmounts.
///
/// Linux-only: the mount(2) signature and MS_* flags are Linux's. The protocol
/// encoding above stays portable so it can be unit-tested anywhere.
#[cfg(target_os = "linux")]
pub struct Session {
    dev: File,
    mountpoint: std::ffi::CString,
    stop: Arc<AtomicBool>,
}

#[cfg(target_os = "linux")]
impl Session {
    /// Mount at `mountpoint` and return the session.
    ///
    /// `read_only` maps to `MS_RDONLY`, so the kernel itself rejects writes and
    /// the filesystem never sees them — cheaper and more trustworthy than
    /// checking a flag in every handler.
    pub fn mount(mountpoint: &str, read_only: bool, allow_other: bool) -> std::io::Result<Self> {
        std::fs::create_dir_all(mountpoint)?;

        // Minimal images have no /dev/fuse; as root we can create it.
        if !std::path::Path::new("/dev/fuse").exists() {
            let path = std::ffi::CString::new("/dev/fuse").expect("static string");
            let rc = unsafe {
                libc::mknod(path.as_ptr(), libc::S_IFCHR | 0o600, libc::makedev(10, 229))
            };
            if rc != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }

        let dev = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC)
            .open("/dev/fuse")?;

        let mut opts = format!(
            "fd={},rootmode=40000,user_id=0,group_id=0,default_permissions",
            dev.as_raw_fd()
        );
        if allow_other {
            opts.push_str(",allow_other");
        }

        let target = std::ffi::CString::new(mountpoint)?;
        let source = std::ffi::CString::new("s3")?;
        let fstype = std::ffi::CString::new("fuse")?;
        let copts = std::ffi::CString::new(opts)?;
        let mut flags = libc::MS_NOSUID | libc::MS_NODEV;
        if read_only {
            flags |= libc::MS_RDONLY;
        }
        let rc = unsafe {
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                fstype.as_ptr(),
                flags as libc::c_ulong,
                copts.as_ptr() as *const libc::c_void,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(Self {
            dev,
            mountpoint: target,
            stop: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Handle requests until the filesystem is unmounted.
    pub fn run(&mut self, fs: &dyn Filesystem) {
        // One read must hold a full write payload plus header; the kernel
        // rejects a smaller buffer at INIT time.
        let mut buf = vec![0u8; 1024 * 1024 + 4096];
        while !self.stop.load(Ordering::Relaxed) {
            let n = match self.dev.read(&mut buf) {
                Ok(0) => return,
                Ok(n) => n,
                Err(e) => match e.raw_os_error() {
                    // The kernel interrupts blocking reads on unmount/signals.
                    Some(libc::EINTR) | Some(libc::EAGAIN) => continue,
                    // ENODEV means the filesystem was unmounted: a clean exit.
                    Some(libc::ENODEV) => return,
                    _ => return,
                },
            };
            if n < 40 {
                continue;
            }
            let opcode = u32::from_ne_bytes(buf[4..8].try_into().unwrap());
            let unique = u64::from_ne_bytes(buf[8..16].try_into().unwrap());
            let nodeid = u64::from_ne_bytes(buf[16..24].try_into().unwrap());
            let uid = u32::from_ne_bytes(buf[24..28].try_into().unwrap());
            let gid = u32::from_ne_bytes(buf[28..32].try_into().unwrap());

            if opcode == op::INIT {
                self.reply_init(unique, &buf[40..n]);
                continue;
            }
            // FORGET expects no reply at all; answering it corrupts the stream.
            if opcode == op::FORGET {
                continue;
            }

            let req = Request {
                opcode,
                unique,
                nodeid,
                uid,
                gid,
                data: &buf[40..n],
            };
            let reply = fs.dispatch(&req);
            self.send(unique, reply);
        }
    }

    fn reply_init(&mut self, unique: u64, data: &[u8]) {
        let major = u32::from_ne_bytes(data[0..4].try_into().unwrap_or([0; 4]));
        let minor = u32::from_ne_bytes(data[4..8].try_into().unwrap_or([0; 4]));
        let mut b = Vec::new();
        b.extend_from_slice(&7u32.to_ne_bytes()); // major we speak
        b.extend_from_slice(&(minor.min(31)).to_ne_bytes());
        b.extend_from_slice(&(128u32 * 1024).to_ne_bytes()); // max_readahead
        b.extend_from_slice(&0u32.to_ne_bytes()); // flags: opt into nothing
        b.extend_from_slice(&0u16.to_ne_bytes()); // max_background
        b.extend_from_slice(&0u16.to_ne_bytes()); // congestion_threshold
        b.extend_from_slice(&(1024u32 * 1024).to_ne_bytes()); // max_write
        b.extend_from_slice(&0u32.to_ne_bytes()); // time_gran
        b.extend_from_slice(&0u16.to_ne_bytes()); // max_pages
        b.extend_from_slice(&0u16.to_ne_bytes()); // map_alignment
        b.resize(b.len() + 8 * 4, 0); // reserved
        let _ = major;
        self.raw_reply(unique, 0, &b);
    }

    fn send(&mut self, unique: u64, reply: Reply) {
        match reply {
            Reply::Ok => self.raw_reply(unique, 0, &[]),
            Reply::Error(e) => self.raw_reply(unique, -e, &[]),
            Reply::Attr(a) => {
                let mut b = Vec::new();
                b.extend_from_slice(&1u64.to_ne_bytes()); // attr_valid secs
                b.extend_from_slice(&0u32.to_ne_bytes()); // attr_valid nsec
                b.extend_from_slice(&0u32.to_ne_bytes()); // dummy
                a.encode(&mut b);
                self.raw_reply(unique, 0, &b);
            }
            Reply::Entry(a) => {
                let mut b = Vec::new();
                Self::encode_entry(&mut b, &a);
                self.raw_reply(unique, 0, &b);
            }
            Reply::Create(a, fh) => {
                let mut b = Vec::new();
                Self::encode_entry(&mut b, &a);
                b.extend_from_slice(&fh.to_ne_bytes());
                b.extend_from_slice(&0u32.to_ne_bytes()); // open_flags
                b.extend_from_slice(&0u32.to_ne_bytes()); // padding
                self.raw_reply(unique, 0, &b);
            }
            Reply::Open(fh) => {
                let mut b = Vec::new();
                b.extend_from_slice(&fh.to_ne_bytes());
                b.extend_from_slice(&0u32.to_ne_bytes()); // open_flags
                b.extend_from_slice(&0u32.to_ne_bytes()); // padding
                self.raw_reply(unique, 0, &b);
            }
            Reply::Data(d) | Reply::Directory(d) => self.raw_reply(unique, 0, &d),
            Reply::Written(n) => {
                let mut b = Vec::new();
                b.extend_from_slice(&n.to_ne_bytes());
                b.extend_from_slice(&0u32.to_ne_bytes());
                self.raw_reply(unique, 0, &b);
            }
            Reply::StatFs {
                blocks,
                bfree,
                bavail,
                files,
            } => {
                let mut b = Vec::new();
                b.extend_from_slice(&blocks.to_ne_bytes());
                b.extend_from_slice(&bfree.to_ne_bytes());
                b.extend_from_slice(&bavail.to_ne_bytes());
                b.extend_from_slice(&files.to_ne_bytes());
                b.extend_from_slice(&files.to_ne_bytes()); // ffree
                b.extend_from_slice(&4096u32.to_ne_bytes()); // bsize
                b.extend_from_slice(&255u32.to_ne_bytes()); // namelen
                b.extend_from_slice(&4096u32.to_ne_bytes()); // frsize
                b.extend_from_slice(&0u32.to_ne_bytes()); // padding
                b.resize(b.len() + 6 * 4, 0); // spare
                self.raw_reply(unique, 0, &b);
            }
        }
    }

    fn encode_entry(b: &mut Vec<u8>, a: &Attr) {
        b.extend_from_slice(&a.ino.to_ne_bytes()); // nodeid
        b.extend_from_slice(&0u64.to_ne_bytes()); // generation
        b.extend_from_slice(&1u64.to_ne_bytes()); // entry_valid
        b.extend_from_slice(&1u64.to_ne_bytes()); // attr_valid
        b.extend_from_slice(&0u32.to_ne_bytes()); // entry_valid_nsec
        b.extend_from_slice(&0u32.to_ne_bytes()); // attr_valid_nsec
        a.encode(b);
    }

    fn raw_reply(&mut self, unique: u64, error: i32, body: &[u8]) {
        let len = (16 + body.len()) as u32;
        let mut out = Vec::with_capacity(len as usize);
        out.extend_from_slice(&len.to_ne_bytes());
        out.extend_from_slice(&error.to_ne_bytes());
        out.extend_from_slice(&unique.to_ne_bytes());
        out.extend_from_slice(body);
        // A failed reply means the mount is gone; the read loop will notice.
        let _ = self.dev.write(&out);
    }
}

#[cfg(target_os = "linux")]
impl Drop for Session {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // Lazy unmount: detach now even if a handler is mid-flight, so a stuck
        // request cannot leave a wedged mountpoint behind in the container.
        unsafe { libc::umount2(self.mountpoint.as_ptr(), libc::MNT_DETACH) };
    }
}

/// Append one entry to a READDIR reply buffer.
///
/// Returns false when the entry would exceed `max`, which is the caller's
/// signal to stop and let the kernel ask again from `offset`.
pub fn push_dirent(
    buf: &mut Vec<u8>,
    max: usize,
    ino: u64,
    offset: u64,
    kind: u32,
    name: &str,
) -> bool {
    let padded = (name.len() + 7) & !7;
    if buf.len() + 24 + padded > max {
        return false;
    }
    buf.extend_from_slice(&ino.to_ne_bytes());
    buf.extend_from_slice(&offset.to_ne_bytes());
    buf.extend_from_slice(&(name.len() as u32).to_ne_bytes());
    buf.extend_from_slice(&kind.to_ne_bytes());
    buf.extend_from_slice(name.as_bytes());
    buf.resize(buf.len() + padded - name.len(), 0);
    true
}

pub const DT_DIR: u32 = 4;
pub const DT_REG: u32 = 8;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dirents_are_eight_byte_aligned_and_bounded() {
        let mut buf = Vec::new();
        assert!(push_dirent(&mut buf, 4096, 2, 1, DT_REG, "a.txt"));
        assert_eq!(buf.len() % 8, 0, "the kernel requires 8-byte alignment");
        let before = buf.len();
        // A tiny budget must refuse rather than emit a truncated entry.
        assert!(!push_dirent(&mut buf, before + 4, 3, 2, DT_REG, "b.txt"));
        assert_eq!(
            buf.len(),
            before,
            "a refused entry must not be partially written"
        );
    }

    #[test]
    fn attrs_encode_to_the_kernels_expected_width() {
        let mut out = Vec::new();
        Attr {
            ino: 1,
            mode: 0o040755,
            nlink: 2,
            ..Default::default()
        }
        .encode(&mut out);
        // fuse_attr is 88 bytes on every arch we target.
        assert_eq!(out.len(), 88);
    }

    #[test]
    fn request_field_readers_handle_short_payloads() {
        let req = Request {
            opcode: 0,
            unique: 0,
            nodeid: 0,
            uid: 0,
            gid: 0,
            data: &[1, 0, 0, 0],
        };
        assert_eq!(req.u32_at(0), 1);
        // Reading past the end must not panic — a malformed request from the
        // kernel (or a short read) should degrade, not crash the mount.
        assert_eq!(req.u64_at(0), 0);
        assert_eq!(req.u32_at(64), 0);
    }

    #[test]
    fn names_stop_at_the_nul_terminator() {
        let req = Request {
            opcode: 0,
            unique: 0,
            nodeid: 0,
            uid: 0,
            gid: 0,
            data: b"hello.txt\0trailing",
        };
        assert_eq!(req.name_at(0).as_deref(), Some("hello.txt"));
        assert_eq!(req.name_at(100), None);
    }
}
