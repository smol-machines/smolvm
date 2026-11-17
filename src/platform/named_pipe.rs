//! Private Windows API pipes with Docker-compatible stdin half-close.
//!
//! Message pipes carry bytes normally and a zero-length message for shutdown,
//! as used by go-winio's CloseWrite. Tokio's ordinary pipe shutdown only flushes;
//! it does not send this marker. No listener thread or host service is required.

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, PipeMode, ServerOptions,
};
use windows_sys::Win32::Foundation::{
    LocalFree, ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_BUSY, ERROR_PIPE_NOT_CONNECTED,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenUser, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Pipes::PeekNamedPipe;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

fn validate_path(path: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    let name = path.as_os_str().encode_wide().collect::<Vec<_>>();
    let prefix = r"\\.\pipe\".encode_utf16().collect::<Vec<_>>();
    if !name.starts_with(&prefix)
        || name.len() <= prefix.len()
        || name.len() > 256
        || name[prefix.len()..]
            .iter()
            .any(|&c| c == 0 || c == b'\\' as u16 || c == b'/' as u16)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected a local \\\\.\\pipe\\NAME endpoint",
        ));
    }
    Ok(())
}

struct LocalAllocation(*mut std::ffi::c_void);
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: these allocations are returned by the Windows SDDL helpers.
        unsafe { LocalFree(self.0) };
    }
}

fn user_sid() -> io::Result<String> {
    let mut token = std::ptr::null_mut();
    // SAFETY: a valid output pointer and the current process pseudo-handle.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: ownership of the newly opened token transfers to this wrapper.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut len = 0;
    // SAFETY: query the required buffer length without supplying a buffer.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            std::ptr::null_mut(),
            0,
            &mut len,
        )
    };
    if len < std::mem::size_of::<TOKEN_USER>() as u32 {
        return Err(io::Error::last_os_error());
    }
    let mut data = vec![0usize; (len as usize).div_ceil(std::mem::size_of::<usize>())];
    // SAFETY: the buffer is sized and aligned for TOKEN_USER and its SID.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            data.as_mut_ptr().cast(),
            len,
            &mut len,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut sid = std::ptr::null_mut();
    // SAFETY: TOKEN_USER and its SID remain valid in data for this call.
    if unsafe { ConvertSidToStringSidW((*data.as_ptr().cast::<TOKEN_USER>()).User.Sid, &mut sid) }
        == 0
    {
        return Err(io::Error::last_os_error());
    }
    let _allocation = LocalAllocation(sid.cast());
    let mut len = 0;
    // SAFETY: ConvertSidToStringSidW returns a null-terminated UTF-16 string.
    unsafe {
        while *sid.add(len) != 0 {
            len += 1;
        }
        Ok(String::from_utf16_lossy(std::slice::from_raw_parts(
            sid, len,
        )))
    }
}

// Self-relative security descriptor, aligned and owned without thread-bound handles.
struct SecurityDescriptor(Vec<usize>);
impl SecurityDescriptor {
    fn private() -> io::Result<Self> {
        let sid = user_sid()?;
        let sddl = format!("O:{sid}D:P(A;;GA;;;SY)(A;;GA;;;{sid})")
            .encode_utf16()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let mut descriptor = std::ptr::null_mut();
        let mut len = 0;
        // SAFETY: terminated SDDL and valid output pointers.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                &mut len,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let _allocation = LocalAllocation(descriptor);
        let mut data = vec![0usize; (len as usize).div_ceil(std::mem::size_of::<usize>())];
        // SAFETY: copy the entire self-relative descriptor into a sufficiently
        // sized, aligned allocation; it contains offsets, not absolute pointers.
        unsafe {
            std::ptr::copy_nonoverlapping(
                descriptor.cast::<u8>(),
                data.as_mut_ptr().cast(),
                len as usize,
            );
        }
        Ok(Self(data))
    }

    fn create(&self, path: &Path, first: bool) -> io::Result<NamedPipeServer> {
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0.as_ptr().cast_mut().cast(),
            bInheritHandle: 0,
        };
        // SAFETY: attributes and the self-relative descriptor outlive creation;
        // CreateNamedPipe copies them and does not retain their addresses.
        unsafe {
            ServerOptions::new()
                .pipe_mode(PipeMode::Message)
                .first_pipe_instance(first)
                .reject_remote_clients(true)
                .in_buffer_size(65536)
                .out_buffer_size(65536)
                .create_with_security_attributes_raw(
                    path,
                    (&mut attributes as *mut SECURITY_ATTRIBUTES).cast(),
                )
        }
    }
}

/// A local-only listener owned by the current Windows user and SYSTEM.
/// A second listener cannot take over an existing pipe name.
pub struct Listener {
    path: PathBuf,
    security: SecurityDescriptor,
    pending: NamedPipeServer,
}

impl Listener {
    /// Bind a canonical `\\.\pipe\NAME` endpoint without replacing another listener.
    pub fn bind(path: &Path) -> io::Result<Self> {
        validate_path(path)?;
        let security = SecurityDescriptor::private()?;
        let pending = security.create(path, true)?;
        Ok(Self {
            path: path.to_owned(),
            security,
            pending,
        })
    }

    /// Accept one client, retaining a listening instance before returning.
    /// Cancelling this future preserves the pending connection.
    pub async fn accept(&mut self) -> io::Result<Stream> {
        loop {
            match self.pending.connect().await {
                Ok(()) => {
                    let next = self.security.create(&self.path, false)?;
                    let connected = std::mem::replace(&mut self.pending, next);
                    return Ok(Stream::new(Pipe::Server(connected)));
                }
                Err(error) if error.raw_os_error() == Some(ERROR_NO_DATA as i32) => {
                    // A client can disappear before ConnectNamedPipe completes.
                    // Preserve ownership while replacing the disconnected instance.
                    self.pending = self.security.create(&self.path, false)?;
                }
                Err(error) => return Err(error),
            }
        }
    }
}

/// Connect to a local pipe; busy instances are retried asynchronously for 5 seconds.
pub async fn connect(path: &Path) -> io::Result<Stream> {
    validate_path(path)?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        // Tokio defaults to SECURITY_IDENTIFICATION, preventing server impersonation.
        match ClientOptions::new().open(path) {
            Ok(pipe) => {
                if pipe.info()?.mode != PipeMode::Message {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "local API pipe does not support write shutdown",
                    ));
                }
                return Ok(Stream::new(Pipe::Client(pipe)));
            }
            Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "local pipe is busy",
                    ));
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => return Err(error),
        }
    }
}

enum Pipe {
    Server(NamedPipeServer),
    Client(NamedPipeClient),
}

/// An asynchronous byte stream with go-winio-compatible write shutdown.
pub struct Stream {
    pipe: Pipe,
    read_eof: bool,
    write_closed: bool,
}

impl Stream {
    fn new(pipe: Pipe) -> Self {
        Self {
            pipe,
            read_eof: false,
            write_closed: false,
        }
    }

    /// Observe a full disconnect without consuming data or confusing stdin EOF
    /// with the peer closing its read side.
    pub fn is_disconnected(&self) -> io::Result<bool> {
        // SAFETY: a borrowed live pipe handle; no buffers are supplied or retained.
        let ok = unsafe {
            PeekNamedPipe(
                self.as_raw_handle(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ok != 0 {
            return Ok(false);
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error().map(|e| e as u32) {
            Some(ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED | ERROR_NO_DATA) => Ok(true),
            _ => Err(error),
        }
    }
}

impl AsRawHandle for Stream {
    fn as_raw_handle(&self) -> RawHandle {
        match &self.pipe {
            Pipe::Server(pipe) => pipe.as_raw_handle(),
            Pipe::Client(pipe) => pipe.as_raw_handle(),
        }
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.read_eof || buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let before = buf.filled().len();
        let result = match &mut self.pipe {
            Pipe::Server(pipe) => Pin::new(pipe).poll_read(cx, buf),
            Pipe::Client(pipe) => Pin::new(pipe).poll_read(cx, buf),
        };
        if matches!(result, Poll::Ready(Ok(()))) && before == buf.filled().len() {
            self.read_eof = true;
        }
        result
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        // Ordinary empty writes must not become a shutdown marker.
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match &mut self.pipe {
            Pipe::Server(pipe) => Pin::new(pipe).poll_write(cx, buf),
            Pipe::Client(pipe) => Pin::new(pipe).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Tokio/Mio queue at most one write. The next write (including shutdown)
        // waits for its completion; there is no extra user-space buffer here.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.write_closed {
            let result = match &mut self.pipe {
                Pipe::Server(pipe) => Pin::new(pipe).poll_write(cx, &[]),
                Pipe::Client(pipe) => Pin::new(pipe).poll_write(cx, &[]),
            };
            ready!(result)?;
            self.write_closed = true;
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn path() -> PathBuf {
        let unique = tempfile::Builder::new()
            .prefix("smol-pipe-")
            .tempdir()
            .unwrap();
        PathBuf::from(format!(
            r"\\.\pipe\{}-{}",
            std::process::id(),
            unique.path().file_name().unwrap().to_string_lossy()
        ))
    }

    async fn pair() -> (Listener, Stream, Stream) {
        let path = path();
        let mut listener = Listener::bind(&path).unwrap();
        let (client, server) = tokio::join!(connect(&path), listener.accept());
        (listener, client.unwrap(), server.unwrap())
    }

    #[tokio::test]
    async fn message_boundaries_backpressure_and_half_close_preserve_output() {
        tokio::time::timeout(Duration::from_secs(20), async {
            let (_listener, mut client, mut server) = pair().await;
            // A read with no capacity is not EOF; an empty write is not CloseWrite.
            client.read_exact(&mut []).await.unwrap();
            assert_eq!(client.write(&[]).await.unwrap(), 0);
            let payload: Vec<u8> = (0..4 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
            let expected = payload.clone();
            let (written, mut did_write) = tokio::sync::oneshot::channel();
            let writer = tokio::spawn(async move {
                // Multiple messages force bounded pipe buffers to apply backpressure.
                // Messages larger than Mio's read buffer exercise ERROR_MORE_DATA.
                for chunk in payload.chunks(65537) {
                    client.write_all(chunk).await.unwrap();
                }
                written.send(()).unwrap();
                client.shutdown().await.unwrap();
                client.shutdown().await.unwrap();
                assert_eq!(
                    client.write(b"late").await.unwrap_err().kind(),
                    io::ErrorKind::BrokenPipe
                );
                let mut response = Vec::new();
                client.read_to_end(&mut response).await.unwrap();
                assert_eq!(response, b"finished after stdin EOF");
                client
            });
            assert!(
                tokio::time::timeout(Duration::from_millis(100), &mut did_write)
                    .await
                    .is_err(),
                "writes must wait for a reader"
            );
            let mut received = Vec::new();
            server.read_to_end(&mut received).await.unwrap();
            did_write.await.unwrap();
            assert_eq!(received.len(), expected.len());
            assert!(
                received == expected,
                "received bytes differ from the payload"
            );
            assert!(
                !server.is_disconnected().unwrap(),
                "stdin EOF is not full close"
            );
            let mut byte = [0];
            assert_eq!(
                server.read(&mut byte).await.unwrap(),
                0,
                "EOF stays latched"
            );
            server.write_all(b"finished after stdin EOF").await.unwrap();
            server.shutdown().await.unwrap();
            let client = writer.await.unwrap();
            assert!(!server.is_disconnected().unwrap());
            drop(client);
            while !server.is_disconnected().unwrap() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn accept_cancellation_concurrent_clients_and_listener_ownership() {
        tokio::time::timeout(Duration::from_secs(15), async {
            let path = path();
            let mut listener = Listener::bind(&path).unwrap();
            assert!(Listener::bind(&path).is_err());
            assert!(
                tokio::time::timeout(Duration::from_millis(30), listener.accept())
                    .await
                    .is_err()
            );
            // Connecting and disappearing before accept must not poison the listener.
            drop(connect(&path).await.unwrap());
            let mut clients = tokio::task::JoinSet::new();
            for i in 0..24u8 {
                let path = path.clone();
                clients.spawn(async move {
                    let mut stream = connect(&path).await.unwrap();
                    stream.write_all(&[i]).await.unwrap();
                    stream.shutdown().await.unwrap();
                    let mut reply = Vec::new();
                    stream.read_to_end(&mut reply).await.unwrap();
                    assert_eq!(reply, [i]);
                });
            }
            let mut servers = tokio::task::JoinSet::new();
            while servers.len() < 24 {
                let mut stream = listener.accept().await.unwrap();
                // A vanished client's accepted stream can legitimately report EOF.
                let mut data = Vec::new();
                stream.read_to_end(&mut data).await.unwrap();
                if data.is_empty() {
                    continue;
                }
                servers.spawn(async move {
                    stream.write_all(&data).await.unwrap();
                    stream.shutdown().await.unwrap();
                });
            }
            while let Some(result) = clients.join_next().await {
                result.unwrap();
            }
            while let Some(result) = servers.join_next().await {
                result.unwrap();
            }
            assert!(Listener::bind(&path).is_err());
            drop(listener);
            // Mio may finish cancelling its pending overlapped read after drop.
            loop {
                match Listener::bind(&path) {
                    Ok(listener) => {
                        drop(listener);
                        break;
                    }
                    Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                }
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn cancelled_read_and_full_disconnect_are_observed() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (_listener, mut client, mut server) = pair().await;
            let mut byte = [0];
            assert!(
                tokio::time::timeout(Duration::from_millis(30), server.read(&mut byte))
                    .await
                    .is_err()
            );
            client.write_all(b"x").await.unwrap();
            server.read_exact(&mut byte).await.unwrap();
            assert_eq!(&byte, b"x");
            drop(client);
            assert_eq!(server.read(&mut byte).await.unwrap(), 0);
            assert!(server.is_disconnected().unwrap());
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn endpoint_validation_and_missing_server_fail_closed() {
        for invalid in [
            r"\\host\pipe\smol",
            r"C:\pipe",
            r"\\.\pipe\",
            r"\\.\pipe\a\b",
            "\\\\.\\pipe\\a\0b",
        ] {
            let path = Path::new(invalid);
            assert_eq!(
                Listener::bind(path).err().unwrap().kind(),
                io::ErrorKind::InvalidInput
            );
            assert_eq!(
                connect(path).await.err().unwrap().kind(),
                io::ErrorKind::InvalidInput
            );
        }
        assert!(connect(&path()).await.is_err());
        let byte_path = path();
        let _byte_pipe = ServerOptions::new().create(&byte_path).unwrap();
        assert_eq!(
            connect(&byte_path).await.err().unwrap().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[tokio::test]
    async fn pipe_acl_is_private_and_anonymous_open_is_denied() {
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSidToSidW, GetExplicitEntriesFromAclW, GetSecurityInfo, GRANT_ACCESS,
            SE_KERNEL_OBJECT, TRUSTEE_IS_SID,
        };
        use windows_sys::Win32::Security::{
            EqualSid, GetSecurityDescriptorControl, ImpersonateAnonymousToken, RevertToSelf,
            DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, SE_DACL_PROTECTED,
        };
        use windows_sys::Win32::System::Threading::GetCurrentThread;

        fn sid(value: &str) -> LocalAllocation {
            let wide: Vec<u16> = value.encode_utf16().chain(Some(0)).collect();
            let mut ptr = std::ptr::null_mut();
            // SAFETY: terminated SID string and a valid output pointer.
            assert_ne!(
                unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut ptr) },
                0
            );
            LocalAllocation(ptr)
        }

        let path = path();
        let listener = Listener::bind(&path).unwrap();
        let mut descriptor = std::ptr::null_mut();
        let mut owner = std::ptr::null_mut();
        let mut dacl = std::ptr::null_mut();
        let info = DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION;
        // SAFETY: borrowed live handle, valid output pointer, unused outputs null.
        let result = unsafe {
            GetSecurityInfo(
                listener.pending.as_raw_handle(),
                SE_KERNEL_OBJECT,
                info,
                &mut owner,
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut descriptor,
            )
        };
        assert_eq!(result, 0);
        let _allocation = LocalAllocation(descriptor);
        assert!(!owner.is_null() && !dacl.is_null());
        let user = sid(&user_sid().unwrap());
        let system = sid("S-1-5-18");
        // Compare identities, not SDDL text: Windows can render the same SID as
        // a numeric string or an alias such as LA for the local Administrator.
        assert_ne!(unsafe { EqualSid(owner, user.0) }, 0);
        let (mut control, mut revision) = (0, 0);
        // SAFETY: the returned descriptor is live and both outputs are valid.
        assert_ne!(
            unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) },
            0
        );
        assert_ne!(control & SE_DACL_PROTECTED, 0);
        let (mut count, mut entries) = (0, std::ptr::null_mut());
        // SAFETY: a live DACL and valid outputs; LocalFree owns the resulting array.
        assert_eq!(
            unsafe { GetExplicitEntriesFromAclW(dacl, &mut count, &mut entries) },
            0
        );
        let _entries = LocalAllocation(entries.cast());
        assert_eq!(count, 2);
        let (mut found_user, mut found_system) = (false, false);
        // SAFETY: Windows returned count initialized entries and their SID storage.
        for entry in unsafe { std::slice::from_raw_parts(entries, count as usize) } {
            assert_eq!(entry.grfAccessMode, GRANT_ACCESS);
            assert_eq!(entry.Trustee.TrusteeForm, TRUSTEE_IS_SID);
            let actual: *mut std::ffi::c_void = entry.Trustee.ptstrName.cast();
            assert!(!actual.is_null());
            let is_user = unsafe { EqualSid(actual, user.0) } != 0;
            let is_system = unsafe { EqualSid(actual, system.0) } != 0;
            assert!(
                is_user || is_system,
                "unexpected principal can access the pipe"
            );
            found_user |= is_user;
            found_system |= is_system;
        }
        assert!(found_user && found_system);
        // Do not await or panic while impersonating: always revert on this thread.
        assert_ne!(unsafe { ImpersonateAnonymousToken(GetCurrentThread()) }, 0);
        let opened = ClientOptions::new().open(&path);
        let reverted = unsafe { RevertToSelf() };
        assert_ne!(reverted, 0);
        assert_eq!(
            opened.err().unwrap().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(connect(&path).await.is_ok());
    }
}
