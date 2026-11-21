//! SFTP v3 framing, with bounded packets and byte-preserving Unix paths.
use std::{
    ffi::OsString,
    io::{self, Read, Write},
    os::unix::ffi::OsStringExt,
    path::PathBuf,
};

pub const MAX_PACKET: usize = 256 * 1024;
pub const MAX_IO: usize = 128 * 1024;
pub const MAX_HANDLES: usize = 256;
pub type Result<T> = std::result::Result<T, Failure>;

#[derive(Debug)]
pub struct Failure {
    pub code: u32,
    pub message: &'static str,
}
impl Failure {
    pub fn bad() -> Self {
        Self {
            code: 5,
            message: "Malformed request",
        }
    }
    pub fn unsupported() -> Self {
        Self {
            code: 8,
            message: "Operation unsupported",
        }
    }
    pub fn failed(message: &'static str) -> Self {
        Self { code: 4, message }
    }
    pub fn eof() -> Self {
        Self {
            code: 1,
            message: "End of file",
        }
    }
}
impl From<io::Error> for Failure {
    fn from(error: io::Error) -> Self {
        match error.raw_os_error() {
            Some(libc::ENOENT | libc::ENOTDIR) => Self {
                code: 2,
                message: "No such file or directory",
            },
            Some(libc::EACCES | libc::EPERM) => Self {
                code: 3,
                message: "Permission denied",
            },
            _ => Self::failed("Filesystem operation failed"),
        }
    }
}

pub struct Packet<'a>(pub &'a [u8]);
impl<'a> Packet<'a> {
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            return Err(Failure::bad());
        }
        let (value, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(value)
    }
    pub fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub fn string(&mut self) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    pub fn path(&mut self) -> Result<PathBuf> {
        let bytes = self.string()?;
        if bytes.contains(&0) {
            return Err(Failure::bad());
        }
        if bytes.is_empty() {
            return Ok(PathBuf::from("."));
        }
        Ok(PathBuf::from(OsString::from_vec(bytes.to_vec())))
    }
    pub fn handle(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(
            self.string()?
                .try_into()
                .map_err(|_| Failure::failed("Invalid handle"))?,
        ))
    }
    pub fn end(&self) -> Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Failure::bad())
        }
    }
}

pub fn u32(out: &mut Vec<u8>, n: u32) {
    out.extend_from_slice(&n.to_be_bytes());
}
pub fn u64(out: &mut Vec<u8>, n: u64) {
    out.extend_from_slice(&n.to_be_bytes());
}
pub fn string(out: &mut Vec<u8>, bytes: &[u8]) {
    u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}
pub fn response(kind: u8, id: u32) -> Vec<u8> {
    let mut out = vec![kind];
    u32(&mut out, id);
    out
}
pub fn status(id: u32, failure: Option<Failure>) -> Vec<u8> {
    let mut out = response(101, id);
    let failure = failure.unwrap_or(Failure {
        code: 0,
        message: "Success",
    });
    u32(&mut out, failure.code);
    string(&mut out, failure.message.as_bytes());
    string(&mut out, b"");
    out
}
pub fn read(input: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut header = [0; 4];
    loop {
        match input.read(&mut header[..1]) {
            Ok(0) => return Ok(None),
            Ok(_) => break,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => (),
            Err(e) => return Err(e),
        }
    }
    input.read_exact(&mut header[1..])?;
    let len = u32::from_be_bytes(header) as usize;
    if !(5..=MAX_PACKET - 4).contains(&len) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid SFTP packet length",
        ));
    }
    let mut bytes = vec![0; len];
    input.read_exact(&mut bytes)?;
    Ok(Some(bytes))
}
pub fn write(output: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    if bytes.len() > MAX_PACKET - 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SFTP response exceeds packet limit",
        ));
    }
    output.write_all(&(bytes.len() as u32).to_be_bytes())?;
    output.write_all(bytes)?;
    output.flush()
}
