//! A short-lived TCP relay running with the workload's namespaces and user.
//! It uses no image binaries and never opens a host-side network connection.
use smolvm_protocol::{
    interactive_control::Builtin,
    tcp_forward::{CONNECTED, DATA, EOF, MAX_DATA},
};
use std::{
    io::{self, Read, Write},
    net::{Shutdown, TcpStream, ToSocketAddrs},
    os::fd::AsRawFd,
    time::{Duration, Instant},
};

const HELPER: &str = "tcp-forward";

#[cfg(target_os = "linux")]
pub fn command(builtin: &Builtin) -> Vec<String> {
    match builtin {
        Builtin::TcpConnect { host, port } => vec![HELPER.into(), host.clone(), port.to_string()],
    }
}

pub fn helper_requested() -> bool {
    std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new(HELPER))
}

pub fn run_helper() -> i32 {
    match run(&std::env::args_os().skip(1).collect::<Vec<_>>()) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("smolvm TCP connection: {error}");
            1
        }
    }
}

pub fn run(args: &[std::ffi::OsString]) -> io::Result<()> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidInput, "invalid TCP operation");
    if args.len() != 3 || args[0] != HELPER {
        return Err(invalid());
    }
    let host = args[1].to_str().ok_or_else(invalid)?;
    let port = args[2]
        .to_str()
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(invalid)?;
    Builtin::TcpConnect {
        host: host.into(),
        port,
    }
    .validate()
    .map_err(|_| invalid())?;
    let mut stream = connect(host, port)?;
    // TSI serializes operations on a socket. A blocking receive can prevent
    // the other thread from sending a request that would produce its reply.
    // Wait for readiness outside the socket operation, keeping both directions
    // independent without polling while idle.
    stream.set_nonblocking(true)?;
    // The SSH side does not accept a forwarding channel until this byte arrives.
    io::stdout().write_all(&[CONNECTED])?;
    io::stdout().flush()?;
    let mut outbound = stream.try_clone()?;
    let input = std::thread::Builder::new()
        .name("tcp-stdin".into())
        .spawn(move || {
            // Explicitly handle readiness: io::copy (including its splice
            // optimization) cannot resume after a nonblocking WouldBlock.
            let result = (|| {
                let mut input = io::stdin().lock();
                let mut buffer = [0; MAX_DATA];
                loop {
                    let count = match input.read(&mut buffer) {
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        result => result?,
                    };
                    if count == 0 {
                        return Ok::<_, io::Error>(());
                    }
                    let mut bytes = &buffer[..count];
                    while !bytes.is_empty() {
                        match outbound.write(bytes) {
                            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                            Ok(sent) => bytes = &bytes[sent..],
                            Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                                wait_socket(&outbound, libc::POLLOUT)?;
                            }
                            Err(error) => return Err(error),
                        }
                    }
                }
            })();
            let _ = outbound.shutdown(if result.is_ok() {
                Shutdown::Write
            } else {
                Shutdown::Both
            });
            result
        })?;
    let result = (|| {
        let mut buffer = [0u8; MAX_DATA + 5];
        buffer[0] = DATA;
        let mut output = io::stdout().lock();
        loop {
            let count = match stream.read(&mut buffer[5..]) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    wait_socket(&stream, libc::POLLIN)?;
                    continue;
                }
                result => result?,
            };
            if count == 0 {
                output.write_all(&[EOF])?;
                output.flush()?;
                break;
            }
            buffer[1..5].copy_from_slice(&(count as u32).to_be_bytes());
            output.write_all(&buffer[..count + 5])?;
            // TCP protocols cannot wait for a newline or a later write to flush
            // Rust's standard-output buffering (small request/reply messages).
            output.flush()?;
        }
        Ok::<_, io::Error>(())
    })();
    if result.is_err() {
        let _ = stream.shutdown(Shutdown::Both);
        // An error ends this process and its blocked stdin thread. A clean
        // read-half EOF instead waits for the client to finish sending.
        return result;
    }
    input
        .join()
        .map_err(|_| io::Error::other("TCP input worker failed"))??;
    Ok(())
}

fn wait_socket(stream: &TcpStream, events: i16) -> io::Result<()> {
    let mut descriptor = libc::pollfd {
        fd: stream.as_raw_fd(),
        events,
        revents: 0,
    };
    loop {
        // SAFETY: one valid pollfd, owned by this thread for the entire call.
        let result = unsafe { libc::poll(&mut descriptor, 1, -1) };
        if result > 0 {
            if descriptor.revents & libc::POLLNVAL != 0 {
                return Err(io::ErrorKind::NotConnected.into());
            }
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn connect(host: &str, port: u16) -> io::Result<TcpStream> {
    let deadline = Instant::now() + Duration::from_secs(5);
    // DNS uses the workload's resolver. The host also bounds admission and
    // cancels this owned process if the guest resolver does not return.
    let addresses = (host, port).to_socket_addrs()?;
    let mut failure = io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "destination has no addresses",
    );
    for address in addresses {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "TCP connection timed out",
            ));
        }
        match TcpStream::connect_timeout(&address, remaining.min(Duration::from_secs(3))) {
            Ok(stream) => return Ok(stream),
            Err(error) => failure = error,
        }
    }
    Err(failure)
}
