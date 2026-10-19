//! Guest-side port forwarder for ports published while a machine runs.
//!
//! A machine without virtio-net has no host-side listener of its own, so the
//! host relays each connection to a live-published port over vsock: the guest
//! listens on [`ports::PORT_FORWARD`], reads the target guest port as one
//! decimal line, connects to `127.0.0.1:<port>` and relays both ways. Enabled by
//! [`guest_env::PORT_FORWARD`]. A connection to a port nothing listens on is
//! dropped, which the host client sees as a closed connection.

use smolvm_protocol::{guest_env, ports};
use std::io::{self, Read};
use std::thread;

/// Longest header the host sends: a port number and a newline.
const MAX_HEADER: usize = 6;

/// Whether the forwarder is enabled for this launch.
pub fn is_enabled() -> bool {
    std::env::var(guest_env::PORT_FORWARD).as_deref() == Ok(guest_env::VALUE_ON)
}

/// Start the guest-side port forwarder in a background thread.
pub fn start() {
    thread::Builder::new()
        .name("port-forward-guest".into())
        .spawn(|| {
            if let Err(e) = run() {
                tracing::warn!(error = %e, "guest port forwarder stopped");
            }
        })
        .ok();
}

fn run() -> io::Result<()> {
    let listener = crate::vsock::VsockListener::bind(ports::PORT_FORWARD)?;
    tracing::info!(
        vsock_port = ports::PORT_FORWARD,
        "guest port forwarder listening"
    );
    loop {
        let host_conn = match listener.accept() {
            Ok(conn) => conn,
            Err(e) => {
                if e.kind() == io::ErrorKind::InvalidInput {
                    return Err(e);
                }
                tracing::debug!(error = %e, "port forwarder accept error");
                continue;
            }
        };
        thread::Builder::new()
            .name("port-forward-fwd".into())
            .spawn(move || {
                if let Err(e) = forward(host_conn) {
                    tracing::debug!(error = %e, "port forward ended");
                }
            })
            .ok();
    }
}

fn forward(mut host: crate::vsock::VsockStream) -> io::Result<()> {
    let port = read_target_port(&mut host)?;
    let guest = std::net::TcpStream::connect(("127.0.0.1", port))?;
    crate::relay::relay_half_close(host, guest)
}

/// Read the `<port>\n` header one byte at a time, so no byte of the relayed
/// stream that follows it is consumed.
fn read_target_port(stream: &mut impl Read) -> io::Result<u16> {
    let mut header = Vec::with_capacity(MAX_HEADER);
    let mut byte = [0u8; 1];
    while header.len() < MAX_HEADER {
        stream.read_exact(&mut byte)?;
        if byte[0] == b'\n' {
            return parse_port(&header);
        }
        header.push(byte[0]);
    }
    Err(invalid("port forward header too long"))
}

fn parse_port(header: &[u8]) -> io::Result<u16> {
    std::str::from_utf8(header)
        .ok()
        .and_then(|text| text.parse::<u16>().ok())
        .filter(|&port| port != 0)
        .ok_or_else(|| invalid("port forward header is not a port number"))
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_header_names_one_port_and_leaves_the_stream_after_it() {
        let mut stream: &[u8] = b"8080\nGET / HTTP/1.1\r\n";
        assert_eq!(read_target_port(&mut stream).unwrap(), 8080);
        assert_eq!(stream, b"GET / HTTP/1.1\r\n");
        for bad in [
            &b"0\n"[..],
            b"65536\n",
            b"80a\n",
            b"\n",
            b"1234567\n",
            b"80",
        ] {
            let mut stream = bad;
            assert!(read_target_port(&mut stream).is_err(), "{bad:?}");
        }
    }
}
