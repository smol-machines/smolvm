//! Bidirectional relay between a host connection arriving over vsock and an
//! in-guest peer socket, shared by the Docker socket bridge and the port
//! forwarder.

use std::io;

/// Relay bytes both ways between `host` and `peer` with independent
/// half-close: when one side closes its write half, its FIN is mirrored to the
/// other while the opposite direction keeps flowing until it closes too.
///
/// Connections are often long-lived and idle (`docker logs -f`, a dev server's
/// keep-alive, a hijacked attach stream), so this blocks on `poll`
/// indefinitely and only returns once both directions have closed. Honoring
/// half-close is required for hijacked Docker attach streams, which close
/// their write half before the daemon has finished streaming output.
#[cfg(target_os = "linux")]
pub(crate) fn relay_half_close<H, P>(mut host: H, mut daemon: P) -> io::Result<()>
where
    H: io::Read + io::Write + std::os::unix::io::AsRawFd,
    P: io::Read + io::Write + std::os::unix::io::AsRawFd,
{
    let host_fd = host.as_raw_fd();
    let daemon_fd = daemon.as_raw_fd();

    let mut buf = [0u8; 65536];

    // Track each direction independently so a half-close is mirrored, not
    // treated as a full teardown. A hijacked Docker attach (`docker run`/`exec`
    // with no stdin) half-closes its write side right after `101 UPGRADED`, so
    // host→daemon hits EOF while the daemon is still streaming output back.
    // Tearing the whole relay down there silently drops that output — instead we
    // forward the FIN to the peer and keep pumping the other direction until it
    // closes too.
    let mut host_read_open = true;
    let mut daemon_read_open = true;

    while host_read_open || daemon_read_open {
        let mut poll_fds = [
            libc::pollfd {
                // A negative fd is ignored by poll(), so a closed read side
                // stops waking the loop while the other direction drains.
                fd: if host_read_open { host_fd } else { -1 },
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: if daemon_read_open { daemon_fd } else { -1 },
                events: libc::POLLIN,
                revents: 0,
            },
        ];

        // Block until an open side is readable/closed (no idle timeout).
        let ret = unsafe { libc::poll(poll_fds.as_mut_ptr(), 2, -1) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }

        // host → daemon
        if host_read_open
            && poll_fds[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
        {
            let n = io::Read::read(&mut host, &mut buf)?;
            if n == 0 {
                // Host closed its write half: deliver EOF to the daemon so it
                // finishes the request, but keep relaying daemon→host.
                host_read_open = false;
                // SAFETY: daemon_fd is the valid, open fd owned by `daemon`.
                unsafe { libc::shutdown(daemon_fd, libc::SHUT_WR) };
            } else {
                io::Write::write_all(&mut daemon, &buf[..n])?;
            }
        }

        // daemon → host
        if daemon_read_open
            && poll_fds[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
        {
            let n = io::Read::read(&mut daemon, &mut buf)?;
            if n == 0 {
                // Daemon closed its write half: deliver EOF to the host over
                // vsock, but keep relaying host→daemon.
                daemon_read_open = false;
                // SAFETY: host_fd is the valid, open fd owned by `host`.
                unsafe { libc::shutdown(host_fd, libc::SHUT_WR) };
            } else {
                io::Write::write_all(&mut host, &buf[..n])?;
            }
        }
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn relay_half_close<H, P>(_host: H, _peer: P) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "guest relays are only supported on Linux guests",
    ))
}
