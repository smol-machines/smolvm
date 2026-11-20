//! Demand-driven kernel listener notifications over the existing agent socket.
//! One host engine shares a watch for every container in the same VM.
use smolvm_protocol::{error_codes, AgentResponse};

pub(crate) fn supported() -> bool {
    std::path::Path::new("/proc/smolvm-listeners").exists()
}

pub(crate) fn serve(
    stream: &mut crate::WireStream<impl crate::ReadWrite>,
) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    {
        use std::{
            fs::OpenOptions,
            os::unix::fs::OpenOptionsExt,
            sync::atomic::{AtomicUsize, Ordering},
        };
        static ACTIVE: AtomicUsize = AtomicUsize::new(0);
        struct Slot;
        impl Drop for Slot {
            fn drop(&mut self) {
                ACTIVE.fetch_sub(1, Ordering::AcqRel);
            }
        }
        if ACTIVE.fetch_add(1, Ordering::AcqRel) >= 4 {
            ACTIVE.fetch_sub(1, Ordering::AcqRel);
            crate::send_response(
                stream,
                &AgentResponse::error("too many listener watchers", error_codes::QUERY_FAILED),
            )?;
            return Ok(());
        }
        let _slot = Slot;
        let mut events = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open("/proc/smolvm-listeners")
        {
            Ok(events) => events,
            Err(error) => {
                crate::send_response(
                    stream,
                    &AgentResponse::error(
                        format!("listener notifications unavailable: {error}"),
                        error_codes::INVALID_REQUEST,
                    ),
                )?;
                return Ok(());
            }
        };
        crate::send_response(
            stream,
            &AgentResponse::ok_with_data(serde_json::json!({"protocol":"smol-listener-watch-v1"})),
        )?;
        relay(stream, &mut events)?;
    }
    #[cfg(not(target_os = "linux"))]
    crate::send_response(
        stream,
        &AgentResponse::error(
            "listener notifications require Linux",
            error_codes::INVALID_REQUEST,
        ),
    )?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn relay(
    host: &mut impl crate::ReadWrite,
    events: &mut (impl std::io::Read + std::os::fd::AsRawFd),
) -> std::io::Result<()> {
    use std::{
        io,
        time::{Duration, Instant},
    };
    let _host_flags = crate::relay::Nonblocking::new(host.as_raw_fd())?;
    let _event_flags = crate::relay::Nonblocking::new(events.as_raw_fd())?;
    let mut pending = [0u8; 8];
    let mut sent = 8;
    let mut next_read = Instant::now();
    loop {
        // Coalesce busy listener churn without introducing an idle timer.
        // The kernel retains the newest generation while this one-shot
        // cooldown is active, including while the host applies backpressure.
        let cooldown = next_read.saturating_duration_since(Instant::now());
        let timeout = if sent == 8 && !cooldown.is_zero() {
            cooldown.as_millis().saturating_add(1).min(i32::MAX as u128) as i32
        } else {
            -1
        };
        let mut fds = [
            libc::pollfd {
                fd: host.as_raw_fd(),
                events: libc::POLLIN | libc::POLLRDHUP | if sent < 8 { libc::POLLOUT } else { 0 },
                revents: 0,
            },
            libc::pollfd {
                fd: events.as_raw_fd(),
                events: if sent == 8 && cooldown.is_zero() {
                    libc::POLLIN
                } else {
                    0
                },
                revents: 0,
            },
        ];
        // SAFETY: both descriptors remain borrowed and the two pollfd entries
        // are writable for this call; cancellation arrives on the host socket.
        if unsafe { libc::poll(fds.as_mut_ptr(), 2, timeout) } < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if fds[0].revents & (libc::POLLHUP | libc::POLLRDHUP | libc::POLLERR) != 0 {
            return Ok(());
        }
        if fds.iter().any(|p| p.revents & libc::POLLNVAL != 0) {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }
        if fds[0].revents & libc::POLLIN != 0 {
            match host.read(&mut [0]) {
                Ok(0) => return Ok(()),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(e),
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unexpected input after listener watch",
                    ))
                }
            }
        }
        if sent < 8 && fds[0].revents & libc::POLLOUT != 0 {
            match host.write(&pending[sent..]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => {
                    sent += n;
                    if sent == 8 {
                        next_read = Instant::now() + Duration::from_millis(100);
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(e),
            }
        }
        if sent == 8 && fds[1].revents & libc::POLLIN != 0 {
            match events.read(&mut pending) {
                Ok(8) => sent = 0,
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid listener generation",
                    ))
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(e),
            }
        }
        if fds[1].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        os::unix::net::UnixStream,
        time::Duration,
    };
    #[test]
    fn notifications_stop_immediately_when_an_idle_subscriber_disconnects() {
        let (mut host, mut client) = UnixStream::pair().unwrap();
        let (mut notify, mut kernel) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let (done, finished) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let _ = done.send(relay(&mut host, &mut notify));
        });
        for generation in [1u64, 2, 1000] {
            kernel.write_all(&generation.to_le_bytes()).unwrap();
            let mut bytes = [0; 8];
            client.read_exact(&mut bytes).unwrap();
            assert_eq!(u64::from_le_bytes(bytes), generation);
        }
        drop(client);
        finished
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap();
        thread.join().unwrap();
    }
}
