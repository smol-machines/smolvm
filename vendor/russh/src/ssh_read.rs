use std::pin::Pin;

use futures::task::*;
use log::trace;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

use crate::Error;

const SSH_ID_BUF_SIZE: usize = 256;
const SSH_ID_MAX_LINE_LEN: usize = 255;
const SSH_ID_MAX_PRE_BANNER_LINES: usize = 20;

/// The buffer to read the identification string (first line in the
/// protocol).  Not sensitive data — just protocol version exchange.
struct ReadSshIdBuffer {
    pub buf: Box<[u8; SSH_ID_BUF_SIZE]>,
    pub total: usize,
    pub bytes_read: usize,
    pub sshid_len: usize,
    pub pre_banner_lines: usize,
}

impl ReadSshIdBuffer {
    pub fn id(&self) -> &[u8] {
        #[allow(clippy::indexing_slicing)] // length checked
        &self.buf[..self.sshid_len]
    }

    pub fn new() -> ReadSshIdBuffer {
        ReadSshIdBuffer {
            buf: Box::new([0; SSH_ID_BUF_SIZE]),
            sshid_len: 0,
            bytes_read: 0,
            total: 0,
            pre_banner_lines: 0,
        }
    }

    fn line(&self) -> Option<(usize, usize)> {
        if self.total < 2 {
            return None;
        }
        #[allow(clippy::indexing_slicing)] // loop bounds keep i + 1 in range
        for i in 0..self.total - 1 {
            if self.buf[i] == b'\r' && self.buf[i + 1] == b'\n' {
                return Some((i, i + 2));
            }
            if self.buf[i + 1] == b'\n' {
                return Some((i + 1, i + 2));
            }
        }
        None
    }

    fn discard_line(&mut self) {
        let remaining = self.total - self.bytes_read;
        self.buf.copy_within(self.bytes_read..self.total, 0);
        self.total = remaining;
        self.bytes_read = 0;
    }
}

impl std::fmt::Debug for ReadSshIdBuffer {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "ReadSshId {:?}", self.id())
    }
}

/// SshRead<R> is the same as R, plus a small buffer in the beginning to
/// read the identification string. After the first line in the
/// connection, the `id` parameter is never used again.
pub struct SshRead<R> {
    id: Option<ReadSshIdBuffer>,
    pub r: R,
}

impl<R: AsyncRead + AsyncWrite> SshRead<R> {
    pub fn split(self) -> (SshRead<tokio::io::ReadHalf<R>>, tokio::io::WriteHalf<R>) {
        let (r, w) = tokio::io::split(self.r);
        (SshRead { id: self.id, r }, w)
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for SshRead<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<Result<(), std::io::Error>> {
        if let Some(mut id) = self.id.take() {
            trace!("id {:?} {:?}", id.total, id.bytes_read);
            if id.total > id.bytes_read {
                let total = id.total.min(id.bytes_read + buf.remaining());
                #[allow(clippy::indexing_slicing)] // length checked
                buf.put_slice(&id.buf[id.bytes_read..total]);
                id.bytes_read += total - id.bytes_read;
                self.id = Some(id);
                return Poll::Ready(Ok(()));
            }
        }
        AsyncRead::poll_read(Pin::new(&mut self.get_mut().r), cx, buf)
    }
}

impl<R: std::io::Write> std::io::Write for SshRead<R> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        self.r.write(buf)
    }
    fn flush(&mut self) -> Result<(), std::io::Error> {
        self.r.flush()
    }
}

impl<R: AsyncWrite + Unpin> AsyncWrite for SshRead<R> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        AsyncWrite::poll_write(Pin::new(&mut self.r), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), std::io::Error>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.r), cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<(), std::io::Error>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.r), cx)
    }
}

impl<R: AsyncRead + Unpin> SshRead<R> {
    pub fn new(r: R) -> Self {
        SshRead {
            id: Some(ReadSshIdBuffer::new()),
            r,
        }
    }

    pub async fn read_ssh_id(&mut self) -> Result<&[u8], Error> {
        self.read_ssh_id_inner(true).await
    }

    pub async fn read_client_ssh_id(&mut self) -> Result<&[u8], Error> {
        self.read_ssh_id_inner(false).await
    }

    async fn read_ssh_id_inner(&mut self, allow_pre_banner_lines: bool) -> Result<&[u8], Error> {
        let ssh_id = self.id.as_mut().ok_or(Error::Inconsistent)?;
        loop {
            let i = if let Some((line_len, bytes_read)) = ssh_id.line() {
                ssh_id.bytes_read = bytes_read;
                line_len
            } else {
                trace!("read_ssh_id: reading");

                #[allow(clippy::indexing_slicing)] // length checked
                let n = AsyncReadExt::read(&mut self.r, &mut ssh_id.buf[ssh_id.total..]).await?;
                trace!("read {n:?}");

                ssh_id.total += n;
                #[allow(clippy::indexing_slicing)] // length checked
                {
                    trace!("{:?}", std::str::from_utf8(&ssh_id.buf[..ssh_id.total]));
                }
                if n == 0 {
                    return Err(Error::Disconnect);
                }

                if let Some((line_len, bytes_read)) = ssh_id.line() {
                    ssh_id.bytes_read = bytes_read;
                    line_len
                } else if ssh_id.total >= SSH_ID_MAX_LINE_LEN {
                    return Err(Error::Version);
                } else {
                    trace!("bytes_read: {:?}", ssh_id.bytes_read);
                    continue;
                }
            };

            if ssh_id.bytes_read > 0 {
                if ssh_id.bytes_read > SSH_ID_MAX_LINE_LEN {
                    return Err(Error::Version);
                }
                // If we have a full line, handle it.
                if i >= 8 {
                    // Check if we have a valid SSH protocol identifier
                    #[allow(clippy::indexing_slicing)]
                    if let Ok(s) = std::str::from_utf8(&ssh_id.buf[..i])
                        && (s.starts_with("SSH-1.99-") || s.starts_with("SSH-2.0-"))
                    {
                        ssh_id.sshid_len = i;
                        return Ok(ssh_id.id());
                    }
                }
                if !allow_pre_banner_lines {
                    return Err(Error::Version);
                }
                ssh_id.pre_banner_lines += 1;
                if ssh_id.pre_banner_lines > SSH_ID_MAX_PRE_BANNER_LINES {
                    return Err(Error::Version);
                }
                // Else, it is a "preliminary" (see
                // https://tools.ietf.org/html/rfc4253#section-4.2),
                // and we can discard it and read the next one.
                ssh_id.discard_line();
            }
            trace!("bytes_read: {:?}", ssh_id.bytes_read);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::iter;

    #[tokio::test]
    async fn test_ssh_id_openssh() {
        let data = "SSH-2.0-OpenSSH_10.2\r\n";
        let mut read = SshRead::new(data.as_bytes());

        let received = read.read_ssh_id().await.unwrap();
        assert_eq!(received, b"SSH-2.0-OpenSSH_10.2");
    }

    #[tokio::test]
    async fn test_ssh_id_openssh_7_4() {
        let data = "SSH-2.0-OpenSSH_7.4\n";
        let mut read = SshRead::new(data.as_bytes());

        let received = read.read_ssh_id().await.unwrap();
        assert_eq!(received, b"SSH-2.0-OpenSSH_7.4");
    }

    #[tokio::test]
    async fn test_ssh_id_too_long() {
        let data = String::from_iter(iter::once("SSH-2.0-").chain(
            iter::repeat("A").take(500)));
        let mut read = SshRead::new(data.as_bytes());

        let received = read.read_ssh_id().await;
        assert!(matches!(received.err(), Some(Error::Version)));
    }

    #[tokio::test]
    async fn test_ssh_id_accepts_maximum_line_length() {
        let data = format!("SSH-2.0-{}\r\n", "A".repeat(245));
        let mut read = SshRead::new(data.as_bytes());

        let received = read.read_ssh_id().await.unwrap();
        assert_eq!(received.len(), SSH_ID_MAX_LINE_LEN - 2);
    }

    #[tokio::test]
    async fn test_ssh_id_rejects_oversized_line_with_terminator() {
        let data = format!("SSH-2.0-{}\r\n", "A".repeat(246));
        let mut read = SshRead::new(data.as_bytes());

        let received = read.read_ssh_id().await;
        assert!(matches!(received.err(), Some(Error::Version)));
    }

    #[tokio::test]
    async fn test_ssh_id_rejects_too_many_pre_banner_lines() {
        let data = format!(
            "{}SSH-2.0-OpenSSH_10.2\r\n",
            "debug\r\n".repeat(SSH_ID_MAX_PRE_BANNER_LINES + 1)
        );
        let mut read = SshRead::new(data.as_bytes());

        let received = read.read_ssh_id().await;
        assert!(matches!(received.err(), Some(Error::Version)));
    }

    #[tokio::test]
    async fn test_server_ssh_id_rejects_pre_banner_line() {
        let data = "debug\r\nSSH-2.0-OpenSSH_10.2\r\n";
        let mut read = SshRead::new(data.as_bytes());

        let received = read.read_client_ssh_id().await;
        assert!(matches!(received.err(), Some(Error::Version)));
    }

    #[tokio::test]
    async fn test_ssh_id_empty() {
        let data = "";
        let mut read = SshRead::new(data.as_bytes());

        let received = read.read_ssh_id().await;
        assert!(matches!(received.err(), Some(Error::Disconnect)));
    }

    #[tokio::test]
    async fn test_ssh_id_almost_empty_cr_nl() {
        let data = "SSH-2.0-\n";
        let mut read = SshRead::new(data.as_bytes());

        let received = read.read_ssh_id().await.unwrap();
        assert_eq!(received, b"SSH-2.0-");
    }

    #[tokio::test]
    async fn test_ssh_id_almost_empty_nl() {
        let data = "SSH-2.0-\n";
        let mut read = SshRead::new(data.as_bytes());

        let received = read.read_ssh_id().await.unwrap();
        assert_eq!(received, b"SSH-2.0-");
    }

    #[tokio::test]
    async fn test_ssh_id_newline() {
        let data = "\n";
        let mut read = SshRead::new(data.as_bytes());

        let received = read.read_ssh_id().await;
        assert!(matches!(received.err(), Some(Error::Disconnect)));
    }

    #[tokio::test]
    async fn test_ssh_id_contains_cr() {
        // A \r that isn't followed by \n has no special meaning
        let data = "SSH-2.0-OpenSSH\r10.2\n";
        let mut read = SshRead::new(data.as_bytes());

        let received = read.read_ssh_id().await.unwrap();
        assert_eq!(received, b"SSH-2.0-OpenSSH\r10.2");
    }

    #[tokio::test]
    async fn test_ssh_id_trailing_cr() {
        // Verify this doesn't cause an out-of-bounds access when testing for \r\n
        let data = "SSH-2.0-OpenSSH_10.2\r";
        let mut read = SshRead::new(data.as_bytes());

        let received = read.read_ssh_id().await;
        assert!(matches!(received.err(), Some(Error::Disconnect)));
    }

    #[tokio::test]
    async fn test_ssh_id_nl_cr() {
        // Like \r\n but backwards
        let data = "SSH-2.0-OpenSSH_10.2\n\r";
        let mut read = SshRead::new(data.as_bytes());

        let received = read.read_ssh_id().await.unwrap();
        assert_eq!(received, b"SSH-2.0-OpenSSH_10.2");
    }

    #[tokio::test]
    async fn test_ssh_id_nl_cr_nl() {
        // Like \r\n but backwards, but also part of \r\n
        let data = "SSH-2.0-OpenSSH_10.2\n\r\n";
        let mut read = SshRead::new(data.as_bytes());

        let received = read.read_ssh_id().await.unwrap();
        assert_eq!(received, b"SSH-2.0-OpenSSH_10.2");
    }
}
