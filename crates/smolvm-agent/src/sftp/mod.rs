//! A connection-owned SFTP v3 server inside the selected workload.
//! Protocol: draft-ietf-secsh-filexfer-02 and OpenSSH PROTOCOL section 4.
//! Requests execute in order; packets, directory pages and handles are bounded.
mod files;
mod wire;
use files::{Attributes, Target};
use std::{
    collections::HashMap,
    fs::{self, File, ReadDir},
    io::{self, Read, Write},
    os::{
        fd::IntoRawFd,
        unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt, FileExt},
        },
    },
};
use wire::{Failure, Packet, Result, MAX_HANDLES, MAX_IO, MAX_PACKET};

const EXTENSIONS: &[(&[u8], &[u8])] = &[
    (b"posix-rename@openssh.com", b"1"),
    (b"hardlink@openssh.com", b"1"),
    (b"fsync@openssh.com", b"1"),
    (b"statvfs@openssh.com", b"2"),
    (b"fstatvfs@openssh.com", b"2"),
    (b"limits@openssh.com", b"1"),
    (b"expand-path@openssh.com", b"1"),
    (b"copy-data", b"1"),
];
enum Handle {
    File(File),
    Directory { file: File, entries: ReadDir },
}
impl Handle {
    fn file(&self) -> &File {
        match self {
            Self::File(f) | Self::Directory { file: f, .. } => f,
        }
    }
    fn regular(&self) -> Result<&File> {
        match self {
            Self::File(f) => Ok(f),
            _ => Err(Failure::failed("Not a file handle")),
        }
    }
}
#[derive(Default)]
struct Server {
    handles: HashMap<u64, Handle>,
    next: u64,
}
impl Server {
    fn room(&self) -> Result<()> {
        if self.handles.len() >= MAX_HANDLES || self.next == u64::MAX {
            Err(Failure::failed("Too many open handles"))
        } else {
            Ok(())
        }
    }
    fn insert(&mut self, id: u32, handle: Handle) -> Vec<u8> {
        self.next += 1;
        self.handles.insert(self.next, handle);
        let mut out = wire::response(102, id);
        wire::string(&mut out, &self.next.to_be_bytes());
        out
    }
    fn get(&self, handle: u64) -> Result<&Handle> {
        self.handles
            .get(&handle)
            .ok_or_else(|| Failure::failed("Invalid handle"))
    }
    fn request(&mut self, kind: u8, id: u32, p: &mut Packet<'_>) -> Result<Vec<u8>> {
        match kind {
            3 => {
                let path = p.path()?;
                let flags = p.u32()?;
                let attrs = Attributes::read(p)?;
                p.end()?;
                self.room()?;
                let file = files::open(&path, flags, &attrs)?;
                return Ok(self.insert(id, Handle::File(file)));
            }
            4 => {
                let handle = p.handle()?;
                p.end()?;
                let handle = self
                    .handles
                    .remove(&handle)
                    .ok_or_else(|| Failure::failed("Invalid handle"))?;
                match handle {
                    Handle::File(file) => {
                        // close(2) can report a delayed write error; never retry
                        // close after EINTR because Linux already released the fd.
                        let fd = file.into_raw_fd();
                        if unsafe { libc::close(fd) } < 0 {
                            return Err(io::Error::last_os_error().into());
                        }
                    }
                    Handle::Directory { .. } => (),
                }
            }
            5 => {
                let handle = p.handle()?;
                let offset = p.u64()?;
                let requested = p.u32()? as usize;
                p.end()?;
                if offset > i64::MAX as u64 {
                    return Err(Failure::bad());
                }
                let length = requested.min(MAX_IO);
                let mut bytes = vec![0; length];
                let count = self.get(handle)?.regular()?.read_at(&mut bytes, offset)?;
                if count == 0 && length != 0 {
                    return Err(Failure::eof());
                }
                let mut out = wire::response(103, id);
                wire::string(&mut out, &bytes[..count]);
                return Ok(out);
            }
            6 => {
                let handle = p.handle()?;
                let offset = p.u64()?;
                let bytes = p.string()?;
                p.end()?;
                if bytes.len() > MAX_IO
                    || offset
                        .checked_add(bytes.len() as u64)
                        .is_none_or(|n| n > i64::MAX as u64)
                {
                    return Err(Failure::bad());
                }
                self.get(handle)?.regular()?.write_all_at(bytes, offset)?;
            }
            7 | 17 => {
                let path = p.path()?;
                p.end()?;
                let meta = if kind == 7 {
                    fs::symlink_metadata(path)?
                } else {
                    fs::metadata(path)?
                };
                let mut out = wire::response(105, id);
                files::attrs(&mut out, &meta);
                return Ok(out);
            }
            8 => {
                let handle = p.handle()?;
                p.end()?;
                let meta = self.get(handle)?.file().metadata()?;
                let mut out = wire::response(105, id);
                files::attrs(&mut out, &meta);
                return Ok(out);
            }
            9 => {
                let path = p.path()?;
                let attrs = Attributes::read(p)?;
                p.end()?;
                files::set(Target::Path(&path), attrs)?;
            }
            10 => {
                let handle = p.handle()?;
                let attrs = Attributes::read(p)?;
                p.end()?;
                files::set(Target::File(self.get(handle)?.file()), attrs)?;
            }
            11 => {
                let path = p.path()?;
                p.end()?;
                self.room()?;
                let file = File::open(&path)?;
                let entries = fs::read_dir(path)?;
                return Ok(self.insert(id, Handle::Directory { file, entries }));
            }
            12 => {
                let handle = p.handle()?;
                p.end()?;
                let Some(Handle::Directory { entries, .. }) = self.handles.get_mut(&handle) else {
                    return Err(Failure::failed("Invalid directory handle"));
                };
                return read_directory(id, entries);
            }
            13 => {
                let path = p.path()?;
                p.end()?;
                fs::remove_file(path)?;
            }
            14 => {
                let path = p.path()?;
                let mut attrs = Attributes::read(p)?;
                p.end()?;
                if attrs.size.is_some() {
                    return Err(Failure::bad());
                }
                fs::DirBuilder::new()
                    .mode(attrs.mode.take().unwrap_or(0o777) & 0o7777)
                    .create(&path)?;
                files::set(Target::Path(&path), attrs)?;
            }
            15 => {
                let path = p.path()?;
                p.end()?;
                fs::remove_dir(path)?;
            }
            16 => {
                let path = p.path()?;
                p.end()?;
                return Ok(path_response(id, &files::realpath(&path)?));
            }
            18 => {
                let from = p.path()?;
                let to = p.path()?;
                p.end()?;
                files::rename(&from, &to)?;
            }
            19 => {
                let path = p.path()?;
                p.end()?;
                return Ok(path_response(id, &fs::read_link(path)?));
            }
            20 => {
                // OpenSSH's deployed argument order, also used by other clients.
                let target = p.path()?;
                let link = p.path()?;
                p.end()?;
                std::os::unix::fs::symlink(target, link)?;
            }
            200 => return self.extended(id, p),
            _ => return Err(Failure::unsupported()),
        }
        Ok(wire::status(id, None))
    }
    fn extended(&mut self, id: u32, p: &mut Packet<'_>) -> Result<Vec<u8>> {
        match p.string()? {
            b"posix-rename@openssh.com" => {
                let from = p.path()?;
                let to = p.path()?;
                p.end()?;
                fs::rename(from, to)?;
            }
            b"hardlink@openssh.com" => {
                let from = p.path()?;
                let to = p.path()?;
                p.end()?;
                fs::hard_link(from, to)?;
            }
            b"fsync@openssh.com" => {
                let handle = p.handle()?;
                p.end()?;
                self.get(handle)?.file().sync_all()?;
            }
            b"limits@openssh.com" => {
                p.end()?;
                let mut out = wire::response(201, id);
                for n in [MAX_PACKET, MAX_IO, MAX_IO, MAX_HANDLES] {
                    wire::u64(&mut out, n as u64);
                }
                return Ok(out);
            }
            b"statvfs@openssh.com" => {
                let path = p.path()?;
                p.end()?;
                let mut out = wire::response(201, id);
                files::statvfs(Target::Path(&path), &mut out)?;
                return Ok(out);
            }
            b"fstatvfs@openssh.com" => {
                let handle = p.handle()?;
                p.end()?;
                let mut out = wire::response(201, id);
                files::statvfs(Target::File(self.get(handle)?.file()), &mut out)?;
                return Ok(out);
            }
            b"expand-path@openssh.com" => {
                let path = p.path()?;
                p.end()?;
                return Ok(path_response(id, &files::expand(&path)?));
            }
            b"copy-data" => {
                let source = p.handle()?;
                let from = p.u64()?;
                let length = p.u64()?;
                let destination = p.handle()?;
                let to = p.u64()?;
                p.end()?;
                files::copy(
                    self.get(source)?.regular()?,
                    from,
                    length,
                    self.get(destination)?.regular()?,
                    to,
                )?;
            }
            _ => return Err(Failure::unsupported()),
        }
        Ok(wire::status(id, None))
    }
}
fn read_directory(
    id: u32,
    entries: &mut impl Iterator<Item = io::Result<fs::DirEntry>>,
) -> Result<Vec<u8>> {
    let mut out = wire::response(104, id);
    wire::u32(&mut out, 0);
    let mut count = 0u32;
    // Bound returned entries, not attempted stats: a page of concurrently
    // removed names must not report EOF and hide surviving entries after it.
    while count < 64 {
        let Some(entry) = entries.next() else { break };
        let entry = entry?;
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        files::name(&mut out, entry.file_name().as_bytes(), Some(&meta));
        count += 1;
    }
    if count == 0 {
        return Err(Failure::eof());
    }
    out[5..9].copy_from_slice(&count.to_be_bytes());
    Ok(out)
}
fn path_response(id: u32, path: &std::path::Path) -> Vec<u8> {
    let mut out = wire::response(104, id);
    wire::u32(&mut out, 1);
    files::name(&mut out, path.as_os_str().as_bytes(), None);
    out
}

pub fn serve(input: &mut impl Read, output: &mut impl Write) -> io::Result<()> {
    let Some(hello) = wire::read(input)? else {
        return Ok(());
    };
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid SFTP initialization");
    let mut hello = Packet(&hello);
    if hello.byte().map_err(|_| invalid())? != 1 || hello.u32().map_err(|_| invalid())? < 3 {
        return Err(invalid());
    }
    while !hello.0.is_empty() {
        hello.string().map_err(|_| invalid())?;
        hello.string().map_err(|_| invalid())?;
    }
    let mut reply = vec![2];
    wire::u32(&mut reply, 3);
    for (name, version) in EXTENSIONS {
        wire::string(&mut reply, name);
        wire::string(&mut reply, version);
    }
    wire::write(output, &reply)?;
    let mut server = Server::default();
    while let Some(bytes) = wire::read(input)? {
        let mut p = Packet(&bytes);
        let kind = p.byte().map_err(|_| invalid())?;
        let id = p.u32().map_err(|_| invalid())?;
        let reply = server
            .request(kind, id, &mut p)
            .unwrap_or_else(|error| wire::status(id, Some(error)));
        wire::write(output, &reply)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
