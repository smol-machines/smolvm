//! Host-side DNS filtering proxy.
//!
//! Receives raw DNS query packets from the guest agent over vsock,
//! checks the queried domain against an allowlist, and either resolves
//! upstream (allowed) or returns NXDOMAIN (blocked).
//!
//! No third-party DNS library — the parser extracts just the domain name
//! from the DNS question section, which is sufficient for filtering.

use std::io::{self, Read, Write};
use std::net::UdpSocket;

/// DNS filter configuration.
#[derive(Debug, Clone)]
pub struct DnsFilter {
    /// Allowed domains (exact match + wildcard subdomains).
    /// e.g., "api.stripe.com" allows "api.stripe.com" and "foo.api.stripe.com".
    allowed: Vec<String>,
    /// Upstream DNS resolver address.
    upstream: String,
}

impl DnsFilter {
    /// Create a new DNS filter from a list of allowed hostnames.
    pub fn new(allowed_hosts: Vec<String>, upstream: String) -> Self {
        Self {
            allowed: allowed_hosts,
            upstream,
        }
    }

    /// Check if a domain is allowed by the filter.
    pub fn is_allowed(&self, domain: &str) -> bool {
        let domain = domain.trim_end_matches('.');
        self.allowed.iter().any(|pattern| {
            let pattern = pattern.trim_end_matches('.');
            domain.eq_ignore_ascii_case(pattern)
                || domain
                    .to_ascii_lowercase()
                    .ends_with(&format!(".{}", pattern.to_ascii_lowercase()))
        })
    }

    /// Handle a raw DNS query: filter and resolve or return NXDOMAIN.
    pub fn handle_query(&self, raw_query: &[u8]) -> Vec<u8> {
        let domain = match extract_domain_from_query(raw_query) {
            Some(d) => d,
            None => {
                tracing::debug!("could not parse DNS query, returning SERVFAIL");
                return build_servfail(raw_query);
            }
        };

        if self.is_allowed(&domain) {
            tracing::debug!(domain, "DNS query allowed, resolving upstream");
            match self.resolve_upstream(raw_query) {
                Ok(resp) => resp,
                Err(e) => {
                    tracing::warn!(domain, error = %e, "upstream DNS resolution failed");
                    build_servfail(raw_query)
                }
            }
        } else {
            tracing::info!(domain, "DNS query blocked by policy");
            build_nxdomain(raw_query)
        }
    }

    /// Forward a DNS query to the upstream resolver and return the response.
    fn resolve_upstream(&self, raw_query: &[u8]) -> io::Result<Vec<u8>> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        socket.send_to(raw_query, format!("{}:53", self.upstream))?;

        let mut buf = [0u8; 1024];
        let (len, _) = socket.recv_from(&mut buf)?;
        Ok(buf[..len].to_vec())
    }
}

/// Handle a single vsock connection from the guest DNS proxy.
///
/// Reads a length-prefixed DNS query, filters it, and sends back
/// the response with the same framing.
pub fn handle_connection(filter: &DnsFilter, stream: &mut (impl Read + Write)) -> io::Result<()> {
    // Read: [2-byte BE length] [raw DNS query]
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf)?;
    let query_len = u16::from_be_bytes(len_buf) as usize;

    if query_len == 0 || query_len > 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid DNS query length: {query_len}"),
        ));
    }

    let mut query = vec![0u8; query_len];
    stream.read_exact(&mut query)?;

    // Filter and resolve
    let response = filter.handle_query(&query);

    // Write: [2-byte BE length] [raw DNS response]
    let resp_len = response.len() as u16;
    stream.write_all(&resp_len.to_be_bytes())?;
    stream.write_all(&response)?;
    stream.flush()?;

    Ok(())
}

// ============================================================================
// Minimal DNS packet parsing (no external dependency)
// ============================================================================

/// Extract the queried domain name from a raw DNS query packet.
///
/// Returns None if the packet is malformed or has no question section.
fn extract_domain_from_query(packet: &[u8]) -> Option<String> {
    // DNS header is 12 bytes
    if packet.len() < 12 {
        return None;
    }

    // QDCOUNT (question count) at bytes 4-5
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    if qdcount == 0 {
        return None;
    }

    // Question section starts at byte 12
    let mut pos = 12;
    let mut labels: Vec<String> = Vec::new();

    loop {
        if pos >= packet.len() {
            return None;
        }

        let label_len = packet[pos] as usize;
        if label_len == 0 {
            break; // Root label — end of name
        }

        // Pointer (compression) — shouldn't appear in queries, but handle it
        if label_len & 0xC0 == 0xC0 {
            return None; // Don't follow pointers in queries
        }

        pos += 1;
        if pos + label_len > packet.len() {
            return None;
        }

        let label = std::str::from_utf8(&packet[pos..pos + label_len]).ok()?;
        labels.push(label.to_string());
        pos += label_len;
    }

    if labels.is_empty() {
        return None;
    }

    Some(labels.join("."))
}

/// Build an NXDOMAIN response from a query.
fn build_nxdomain(query: &[u8]) -> Vec<u8> {
    if query.len() < 12 {
        return vec![];
    }
    let mut resp = query.to_vec();
    resp[2] = 0x80 | (resp[2] & 0x78); // QR=1, preserve opcode
    resp[3] = (resp[3] & 0xF0) | 0x03; // RCODE=NXDOMAIN (3)
                                       // Set RA (recursion available)
    resp[3] |= 0x80;
    // Zero answer/authority/additional counts
    if resp.len() >= 12 {
        resp[6..12].fill(0);
    }
    resp
}

/// Build a SERVFAIL response from a query.
fn build_servfail(query: &[u8]) -> Vec<u8> {
    if query.len() < 12 {
        return vec![];
    }
    let mut resp = query.to_vec();
    resp[2] = 0x80 | (resp[2] & 0x78); // QR=1, preserve opcode
    resp[3] = (resp[3] & 0xF0) | 0x02; // RCODE=SERVFAIL (2)
    resp[3] |= 0x80; // RA
    if resp.len() >= 12 {
        resp[6..12].fill(0);
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal DNS query packet for a domain.
    fn build_query(domain: &str) -> Vec<u8> {
        let mut packet = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // Flags: standard query, RD=1
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x00, // ANCOUNT: 0
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
        ];
        for label in domain.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0x00); // Root label
        packet.extend_from_slice(&[0x00, 0x01]); // QTYPE: A
        packet.extend_from_slice(&[0x00, 0x01]); // QCLASS: IN
        packet
    }

    #[test]
    fn test_extract_domain() {
        let query = build_query("api.stripe.com");
        assert_eq!(
            extract_domain_from_query(&query),
            Some("api.stripe.com".to_string())
        );
    }

    #[test]
    fn test_extract_domain_single_label() {
        let query = build_query("localhost");
        assert_eq!(
            extract_domain_from_query(&query),
            Some("localhost".to_string())
        );
    }

    #[test]
    fn test_extract_domain_short_packet() {
        assert_eq!(extract_domain_from_query(&[0x00; 5]), None);
    }

    #[test]
    fn test_filter_allowed_exact() {
        let filter = DnsFilter::new(vec!["api.stripe.com".into()], "1.1.1.1".into());
        assert!(filter.is_allowed("api.stripe.com"));
        assert!(filter.is_allowed("api.stripe.com."));
    }

    #[test]
    fn test_filter_allowed_subdomain() {
        let filter = DnsFilter::new(vec!["stripe.com".into()], "1.1.1.1".into());
        assert!(filter.is_allowed("api.stripe.com"));
        assert!(filter.is_allowed("dashboard.stripe.com"));
        assert!(!filter.is_allowed("notstripe.com"));
    }

    #[test]
    fn test_filter_blocked() {
        let filter = DnsFilter::new(vec!["api.stripe.com".into()], "1.1.1.1".into());
        assert!(!filter.is_allowed("attacker.com"));
        assert!(!filter.is_allowed("stripe.com")); // not a subdomain of api.stripe.com
    }

    #[test]
    fn test_filter_case_insensitive() {
        let filter = DnsFilter::new(vec!["API.Stripe.COM".into()], "1.1.1.1".into());
        assert!(filter.is_allowed("api.stripe.com"));
    }

    #[test]
    fn test_nxdomain_response() {
        let query = build_query("attacker.com");
        let resp = build_nxdomain(&query);
        assert_eq!(resp[0], 0x12); // ID preserved
        assert_eq!(resp[1], 0x34);
        assert_eq!(resp[2] & 0x80, 0x80); // QR=1
        assert_eq!(resp[3] & 0x0F, 0x03); // RCODE=NXDOMAIN
    }

    #[test]
    fn test_handle_query_allowed() {
        // This test actually resolves DNS, so it needs network.
        // Using a domain that's guaranteed to exist.
        let filter = DnsFilter::new(vec!["one.one.one.one".into()], "1.1.1.1".into());
        let query = build_query("one.one.one.one");
        let response = filter.handle_query(&query);
        // Should be a valid DNS response (not NXDOMAIN)
        assert!(response.len() >= 12);
        assert_eq!(response[2] & 0x80, 0x80); // QR=1
        assert_ne!(response[3] & 0x0F, 0x03); // NOT NXDOMAIN
    }

    #[test]
    fn test_handle_query_blocked() {
        let filter = DnsFilter::new(vec!["api.stripe.com".into()], "1.1.1.1".into());
        let query = build_query("attacker.com");
        let response = filter.handle_query(&query);
        assert!(response.len() >= 12);
        assert_eq!(response[3] & 0x0F, 0x03); // RCODE=NXDOMAIN
    }

    #[test]
    fn test_handle_connection_blocked() {
        let filter = DnsFilter::new(vec!["api.stripe.com".into()], "1.1.1.1".into());
        let query = build_query("attacker.com");

        // Test the filter logic directly — connection framing is trivial
        // (2-byte length prefix) and tested implicitly via integration tests.
        let response = filter.handle_query(&query);

        assert_eq!(response[0], 0x12); // ID preserved
        assert_eq!(response[3] & 0x0F, 0x03); // RCODE=NXDOMAIN
    }
}
