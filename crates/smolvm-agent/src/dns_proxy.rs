//! Guest-side DNS filtering proxy.
//!
//! Listens on `127.0.0.1:53` (both UDP and TCP) inside the VM and forwards
//! raw DNS packets to the host via vsock for filtering. The host decides
//! whether to resolve the query (domain is in the allowlist) or return
//! NXDOMAIN.
//!
//! This is a dumb bridge — no DNS parsing happens in the agent. The host
//! does all filtering, keeping the agent binary small.
//!
//! TCP/53 is required for:
//! - Responses that exceed 512 bytes (TC bit set in the UDP reply)
//! - Clients that prefer TCP (Go's `net` resolver, some systemd-resolved configs)
//!
//! Framing over the vsock stream (stream-oriented, so we need packet
//! boundaries):
//!   [2-byte BE length] [raw DNS packet bytes]
//!
//! The host responds with the same framing. This matches the standard TCP DNS
//! wire format (RFC 1035 §4.2.2) exactly, so no extra wrapping is needed for
//! the TCP path.

use smolvm_protocol::guest_env;
use smolvm_protocol::ports;
use std::io::{self, Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::thread;

/// Maximum DNS packet size over UDP (RFC 1035 §2.3.4).
const MAX_DNS_UDP_PACKET: usize = 512;

/// Maximum DNS response size over TCP (2-byte length field limit).
const MAX_DNS_TCP_PACKET: usize = 65535;

/// Start the guest-side DNS proxy in background threads.
///
/// Spawns one thread for UDP/53 and one for TCP/53. Both reuse the same
/// `forward_to_host` path — the vsock channel framing is identical for both
/// protocols since TCP DNS already uses 2-byte length prefixes.
///
/// Rewrites `/etc/resolv.conf` to point to localhost so all DNS queries
/// from guest applications go through this proxy.
pub fn start() {
    // Rewrite resolv.conf to route DNS through our proxy
    if let Err(e) = std::fs::write("/etc/resolv.conf", "nameserver 127.0.0.1\n") {
        tracing::warn!(error = %e, "failed to rewrite /etc/resolv.conf for DNS filtering");
        return;
    }

    thread::Builder::new()
        .name("dns-proxy-udp".into())
        .spawn(|| {
            if let Err(e) = run_udp_proxy() {
                tracing::warn!(error = %e, "guest UDP DNS proxy stopped");
            }
        })
        .ok();

    thread::Builder::new()
        .name("dns-proxy-tcp".into())
        .spawn(|| {
            if let Err(e) = run_tcp_proxy() {
                tracing::warn!(error = %e, "guest TCP DNS proxy stopped");
            }
        })
        .ok();
}

/// Check if DNS filtering is enabled via environment variable.
/// The host sets this when `--allow-host` is used.
pub fn is_enabled() -> bool {
    std::env::var(guest_env::DNS_FILTER).as_deref() == Ok("1")
}

fn run_udp_proxy() -> io::Result<()> {
    let udp = UdpSocket::bind("127.0.0.1:53")?;
    tracing::info!("guest DNS proxy listening on UDP 127.0.0.1:53");

    let mut buf = [0u8; MAX_DNS_UDP_PACKET];

    loop {
        let (len, src_addr) = udp.recv_from(&mut buf)?;
        if len == 0 {
            continue;
        }

        let response = match forward_to_host(&buf[..len]) {
            Ok(resp) => resp,
            Err(e) => {
                tracing::debug!(error = %e, "DNS forward to host failed, returning SERVFAIL");
                build_servfail(&buf[..len])
            }
        };

        if let Err(e) = udp.send_to(&response, src_addr) {
            tracing::debug!(error = %e, "failed to send DNS response");
        }
    }
}

fn run_tcp_proxy() -> io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:53")?;
    tracing::info!("guest DNS proxy listening on TCP 127.0.0.1:53");

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                thread::spawn(move || {
                    if let Err(e) = handle_tcp_connection(&mut stream) {
                        tracing::debug!(error = %e, "TCP DNS connection error");
                    }
                });
            }
            Err(e) => tracing::debug!(error = %e, "TCP DNS accept error"),
        }
    }
    Ok(())
}

/// Handle a single TCP DNS connection.
///
/// RFC 1035 §4.2.2 allows multiple queries on a single TCP connection
/// (pipelining). Each query is length-prefixed with a 2-byte BE value,
/// matching our vsock framing exactly — `forward_to_host` is used unchanged.
fn handle_tcp_connection(stream: &mut (impl Read + Write)) -> io::Result<()> {
    loop {
        let mut len_buf = [0u8; 2];
        match stream.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
        let query_len = u16::from_be_bytes(len_buf) as usize;
        if query_len == 0 {
            break;
        }

        let mut query = vec![0u8; query_len];
        stream.read_exact(&mut query)?;

        let response = match forward_to_host(&query) {
            Ok(resp) => resp,
            Err(e) => {
                tracing::debug!(error = %e, "DNS forward to host failed, returning SERVFAIL");
                build_servfail(&query)
            }
        };

        let resp_len = response.len() as u16;
        stream.write_all(&resp_len.to_be_bytes())?;
        stream.write_all(&response)?;
        stream.flush()?;
    }
    Ok(())
}

/// Forward a raw DNS packet to the host via vsock and return the response.
///
/// One vsock connection per query. The host may return a response larger than
/// 512 bytes if it performed a TCP retry on the guest's behalf (TC-bit path),
/// so the cap is the protocol maximum (65535) for both UDP and TCP callers.
fn forward_to_host(query: &[u8]) -> io::Result<Vec<u8>> {
    let mut stream = super::vsock::connect(ports::DNS_FILTER)?;

    // Send: [2-byte BE length] [query bytes]
    let len = query.len() as u16;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(query)?;
    stream.flush()?;

    // Receive: [2-byte BE length] [response bytes]
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf)?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;

    if resp_len > MAX_DNS_TCP_PACKET {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("DNS response too large: {resp_len}"),
        ));
    }

    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp)?;

    Ok(resp)
}

/// Build a minimal SERVFAIL response from a query.
/// Copies the query ID and question, sets the SERVFAIL rcode.
fn build_servfail(query: &[u8]) -> Vec<u8> {
    if query.len() < 12 {
        return vec![];
    }

    let mut resp = query.to_vec();
    // Set QR bit (response), keep opcode, set RCODE=2 (SERVFAIL)
    resp[2] = 0x80 | (resp[2] & 0x78); // QR=1, preserve opcode
    resp[3] = (resp[3] & 0xF0) | 0x02; // RCODE=SERVFAIL
                                       // Zero answer/authority/additional counts
    resp[6..12].fill(0);
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_servfail_preserves_id() {
        // Minimal DNS query header (12 bytes)
        let query = vec![
            0xAB, 0xCD, // ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x00, // ANCOUNT: 0
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
        ];
        let resp = build_servfail(&query);
        assert_eq!(resp[0], 0xAB); // ID preserved
        assert_eq!(resp[1], 0xCD);
        assert_eq!(resp[2] & 0x80, 0x80); // QR=1 (response)
        assert_eq!(resp[3] & 0x0F, 0x02); // RCODE=SERVFAIL
    }

    #[test]
    fn test_build_servfail_short_query() {
        let resp = build_servfail(&[0x00, 0x01]);
        assert!(resp.is_empty());
    }
}
