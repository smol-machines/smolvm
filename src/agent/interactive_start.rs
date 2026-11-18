//! Cancellation-aware initial interactive frame exchange, before the writer starts.
use crate::platform::uds::UdsStream;
use std::io;
#[cfg(unix)]
use std::io::{Read, Write};

#[cfg(unix)]
pub(super) fn exchange(
    stream: &mut UdsStream,
    request: &[u8],
    cancellation_fd: std::os::fd::RawFd,
    cancelled: impl Fn() -> bool,
    maximum_frame: usize,
) -> io::Result<Option<Vec<u8>>> {
    use std::os::fd::AsRawFd;
    if request.len() > maximum_frame.saturating_add(4) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interactive request too large",
        ));
    }
    stream.as_socket().set_nonblocking(true)?;
    let result = (|| {
        let mut sent = 0;
        let mut header = [0; 4];
        let mut header_read = 0;
        let mut body: Option<Vec<u8>> = None;
        let mut body_read = 0;
        loop {
            if cancelled() {
                // The data connection owns the guest command, including while
                // it waits for admission. Closing it also revokes late starts.
                let _ = stream.shutdown(std::net::Shutdown::Both);
                return Ok(None);
            }
            let io_result = if sent < request.len() {
                stream.write(&request[sent..]).inspect(|&n| {
                    sent += n;
                })
            } else if header_read < header.len() {
                stream.read(&mut header[header_read..]).inspect(|&n| {
                    header_read += n;
                })
            } else {
                if body.is_none() {
                    let size = u32::from_be_bytes(header) as usize;
                    if size > maximum_frame {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "interactive response too large",
                        ));
                    }
                    body = Some(vec![0; size]);
                }
                let bytes = body.as_mut().unwrap();
                if body_read == bytes.len() {
                    return Ok(body);
                }
                stream.read(&mut bytes[body_read..]).inspect(|&n| {
                    body_read += n;
                })
            };
            match io_result {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "interactive connection closed",
                    ))
                }
                Ok(_) => continue,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
            let mut fds = [
                // Darwin does not report a socket hangup with events=0.
                // Drain notifications below, keeping stdin in its bounded queue.
                libc::pollfd {
                    fd: cancellation_fd,
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: stream.as_raw_fd(),
                    events: if sent < request.len() {
                        libc::POLLOUT
                    } else {
                        libc::POLLIN
                    },
                    revents: 0,
                },
            ];
            // SAFETY: both pollfd entries are initialized and live for this call.
            let ready = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, -1) };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            } else if fds.iter().any(|fd| fd.revents & libc::POLLNVAL != 0) {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "interactive descriptor closed",
                ));
            }
            if fds[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
                let mut notifications = [0u8; 64];
                loop {
                    // SAFETY: the borrowed wake socket is live for this exchange;
                    // these bytes are notifications, never the queued stdin data.
                    let count = unsafe {
                        libc::recv(
                            cancellation_fd,
                            notifications.as_mut_ptr().cast(),
                            notifications.len(),
                            libc::MSG_DONTWAIT,
                        )
                    };
                    if count == 0 {
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        return Ok(None);
                    }
                    if count < 0 {
                        let error = io::Error::last_os_error();
                        match error.kind() {
                            io::ErrorKind::WouldBlock => break,
                            io::ErrorKind::Interrupted => continue,
                            _ => return Err(error),
                        }
                    }
                }
            }
        }
    })();
    let reset = stream.as_socket().set_nonblocking(false);
    if result.is_err() || reset.is_err() {
        let _ = stream.shutdown(std::net::Shutdown::Both);
    }
    reset?;
    result
}

#[cfg(not(unix))]
pub(super) fn exchange(
    _: &mut UdsStream,
    _: &[u8],
    _: i64,
    _: impl Fn() -> bool,
    _: usize,
) -> io::Result<Option<Vec<u8>>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "interactive sessions require Unix",
    ))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        os::fd::AsRawFd,
        sync::{
            atomic::{AtomicBool, Ordering},
            mpsc, Arc,
        },
        time::Duration,
    };
    fn cancel_during_start(fragment: &[u8], large_request: bool) {
        let (mut client, mut guest) = UdsStream::pair().unwrap();
        client.as_socket().set_send_buffer_size(4096).unwrap();
        guest
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let (mut wake, notification) = UdsStream::pair().unwrap();
        wake.write_all(b"queued-input-wakeup").unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        let flag = cancelled.clone();
        let (done, result) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let request = if large_request {
                vec![1; 1024 * 1024]
            } else {
                vec![0, 0, 0, 1, 1]
            };
            let reply = exchange(
                &mut client,
                &request,
                notification.as_raw_fd(),
                || flag.load(Ordering::SeqCst),
                2 * 1024 * 1024,
            );
            let _ = done.send(reply);
        });
        let mut prefix = [0; 5];
        guest.read_exact(&mut prefix).unwrap();
        if !fragment.is_empty() {
            guest.write_all(fragment).unwrap();
        }
        cancelled.store(true, Ordering::SeqCst);
        drop(wake);
        let ended = result.recv_timeout(Duration::from_secs(2));
        let _ = guest.shutdown(std::net::Shutdown::Both);
        worker.join().unwrap();
        assert!(ended.unwrap().unwrap().is_none());
    }
    #[test]
    fn cancellation_interrupts_queued_stdin_before_started_and_partial_frames() {
        for fragment in [&b""[..], &[0][..], &[0, 0, 0, 20, b'{'][..]] {
            cancel_during_start(fragment, false);
        }
    }
    #[test]
    fn cancellation_interrupts_blocked_start_request_write() {
        cancel_during_start(&[], true);
    }
}
