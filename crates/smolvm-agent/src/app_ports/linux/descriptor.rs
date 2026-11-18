//! Duplicate a live process descriptor solely to query TSI socket metadata.
//! pidfd pins the process; fstat pins the observed socket inode. Never accept,
//! consume bytes, change flags, or transfer a workload descriptor to a client.
use super::{invalid, Listener};
use std::{
    io, mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

pub(super) fn process(pid: u32) -> io::Result<OwnedFd> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}
fn option(fd: &OwnedFd, name: i32) -> io::Result<i32> {
    let mut value = 0i32;
    let mut length = mem::size_of_val(&value) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            name,
            (&mut value as *mut i32).cast(),
            &mut length,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    if length as usize != mem::size_of_val(&value) {
        return Err(invalid("invalid socket metadata"));
    }
    Ok(value)
}
fn namespace(fd: &impl AsRawFd) -> io::Result<u64> {
    let mut cookie = 0u64;
    let mut length = mem::size_of_val(&cookie) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_NETNS_COOKIE,
            (&mut cookie as *mut u64).cast(),
            &mut length,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    if length as usize != mem::size_of_val(&cookie) {
        return Err(invalid("invalid socket namespace"));
    }
    Ok(cookie)
}
fn local_namespace() -> io::Result<u64> {
    // A socket is tied to its creation namespace even when passed to a process
    // in another namespace. Comparing process namespace symlinks is insufficient.
    static COOKIE: std::sync::OnceLock<Result<u64, i32>> = std::sync::OnceLock::new();
    COOKIE
        .get_or_init(|| {
            std::os::unix::net::UnixDatagram::unbound()
                .and_then(|socket| namespace(&socket))
                .map_err(|error| error.raw_os_error().unwrap_or(libc::EIO))
        })
        .as_ref()
        .copied()
        .map_err(|code| io::Error::from_raw_os_error(*code))
}
pub(super) fn tsi_listener(
    process: &OwnedFd,
    target: i32,
    inode: u64,
) -> io::Result<Option<Listener>> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_getfd, process.as_raw_fd(), target, 0) };
    if fd < 0 {
        let error = io::Error::last_os_error();
        return if matches!(error.raw_os_error(), Some(libc::EBADF | libc::ESRCH)) {
            Ok(None)
        } else {
            Err(error)
        };
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    let mut stat: libc::stat = unsafe { mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if stat.st_ino != inode || stat.st_mode & libc::S_IFMT != libc::S_IFSOCK {
        return Ok(None);
    }
    // AF_TSI and AF_TSI6 are part of the bundled guest kernel ABI. Do not
    // mistake a Unix, SCTP or other stream listener for an Internet TCP app.
    let domain = option(&fd, libc::SO_DOMAIN)?;
    if !matches!(domain, 46 | 47)
        || option(&fd, libc::SO_TYPE)? != libc::SOCK_STREAM
        || option(&fd, libc::SO_ACCEPTCONN)? != 1
    {
        return Ok(None);
    }
    if namespace(&fd)? != local_namespace()? {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "private app listener belongs to a separate network namespace",
        ));
    }
    if option(&fd, libc::SO_REUSEPORT)? != 0 {
        // The host may share this endpoint with a process outside the VM.
        // Connecting by port cannot prove which listener will accept it.
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "private app access cannot identify a shared host SO_REUSEPORT listener",
        ));
    }
    let mut address: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut length = mem::size_of_val(&address) as libc::socklen_t;
    if unsafe {
        libc::getsockname(
            fd.as_raw_fd(),
            (&mut address as *mut libc::sockaddr_storage).cast(),
            &mut length,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let address = match address.ss_family as i32 {
        libc::AF_INET if length as usize == mem::size_of::<libc::sockaddr_in>() && domain == 46 => {
            let addr = unsafe {
                (&address as *const libc::sockaddr_storage)
                    .cast::<libc::sockaddr_in>()
                    .read()
            };
            SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes())),
                u16::from_be(addr.sin_port),
            )
        }
        libc::AF_INET6
            if length as usize == mem::size_of::<libc::sockaddr_in6>() && domain == 47 =>
        {
            let addr = unsafe {
                (&address as *const libc::sockaddr_storage)
                    .cast::<libc::sockaddr_in6>()
                    .read()
            };
            SocketAddr::V6(std::net::SocketAddrV6::new(
                Ipv6Addr::from(addr.sin6_addr.s6_addr),
                u16::from_be(addr.sin6_port),
                addr.sin6_flowinfo,
                addr.sin6_scope_id,
            ))
        }
        _ => return Err(invalid("invalid TSI listener address")),
    };
    if address.port() == 0 {
        return Err(invalid("invalid TSI listener port"));
    }
    Ok(Some(Listener { address, inode }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        os::{
            fd::AsRawFd,
            unix::{fs::MetadataExt, net::UnixStream},
        },
        time::Duration,
    };
    #[test]
    fn querying_a_descriptor_does_not_consume_bytes_change_flags_or_accept_non_tsi_sockets() {
        let (mut app, mut other) = UnixStream::pair().unwrap();
        app.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let inode = std::fs::metadata(format!("/proc/self/fd/{}", app.as_raw_fd()))
            .unwrap()
            .ino();
        let owner = process(std::process::id()).unwrap();
        assert_eq!(namespace(&app).unwrap(), local_namespace().unwrap());
        other.write_all(b"untouched").unwrap();
        let before = unsafe { libc::fcntl(app.as_raw_fd(), libc::F_GETFL) };
        assert!(tsi_listener(&owner, app.as_raw_fd(), inode)
            .unwrap()
            .is_none());
        assert_eq!(before, unsafe {
            libc::fcntl(app.as_raw_fd(), libc::F_GETFL)
        });
        let mut bytes = [0; 9];
        app.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"untouched");
        assert!(tsi_listener(&owner, app.as_raw_fd(), inode + 1)
            .unwrap()
            .is_none());
        assert!(tsi_listener(&owner, -1, inode).unwrap().is_none());
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let inode = std::fs::metadata(format!("/proc/self/fd/{}", tcp.as_raw_fd()))
            .unwrap()
            .ino();
        assert!(tsi_listener(&owner, tcp.as_raw_fd(), inode)
            .unwrap()
            .is_none());
    }
}
