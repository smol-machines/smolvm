//! Minimal DNS wire parsing + allow-host filtering for the virtio-net gateway.
//!
//! This mirrors libkrun's TSI DNS filter (`vsock/dns_filter.rs`) so `--allow-host`
//! behaves identically on both backends: a query is forwarded upstream only when
//! its name matches the allow-host list (exact match or a subdomain), the answer's
//! A and AAAA records are learned as temporarily-allowed egress IPs, and a
//! disallowed name gets an NXDOMAIN. Hostname matching and TTL clamping match the
//! libkrun rules exactly.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const DNS_HEADER_LEN: usize = 12;
const DNS_ID_LEN: usize = 2;
const DNS_U16_LEN: usize = 2;
const DNS_U32_LEN: usize = 4;
const DNS_FLAGS_OFFSET: usize = 2;
const DNS_QDCOUNT_OFFSET: usize = 4;
const DNS_ANCOUNT_OFFSET: usize = 6;
const DNS_QUESTION_FIXED_LEN: usize = 4;
const DNS_RR_FIXED_LEN: usize = 10;
const DNS_RR_TYPE_OFFSET: usize = 0;
const DNS_RR_CLASS_OFFSET: usize = 2;
const DNS_RR_TTL_OFFSET: usize = 4;
const DNS_RR_RDLEN_OFFSET: usize = 8;
const DNS_CLASS_IN: u16 = 1;
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_A_RDATA_LEN: usize = 4;
const DNS_AAAA_RDATA_LEN: usize = 16;
pub const DNS_RCODE_SERVFAIL: u16 = 2;
pub const DNS_RCODE_NXDOMAIN: u16 = 3;
const DNS_RCODE_MASK: u16 = 0x000f;
const DNS_ONE_QUESTION: u16 = 1;
const DNS_FLAG_RESPONSE: u16 = 0x8000;
const DNS_FLAG_RECURSION_DESIRED: u16 = 0x0100;
const DNS_FLAG_RECURSION_AVAILABLE: u16 = 0x0080;
const DNS_POINTER_TAG: u8 = 0xc0;
const DNS_POINTER_MASK: u8 = 0xc0;
const DNS_POINTER_OFFSET_MASK: u8 = 0x3f;
const DNS_MAX_COMPRESSION_JUMPS: usize = 16;
const DNS_MAX_LABEL_LEN: usize = 63;

/// Lowercase + strip a trailing dot. `None` for an empty name.
pub fn normalize_hostname(hostname: &str) -> Option<String> {
    let hostname = hostname.trim_end_matches('.').to_ascii_lowercase();
    if hostname.is_empty() {
        None
    } else {
        Some(hostname)
    }
}

/// Whether `hostname` matches the allow-list: exact match, or a subdomain of an
/// allowed entry (`foo.example.com` matches `example.com`, `notexample.com` does
/// not). Mirrors libkrun's `is_hostname_allowed`.
pub fn hostname_allowed(hostname: &str, allowed_hosts: &[String]) -> bool {
    let Some(hostname) = normalize_hostname(hostname) else {
        return false;
    };
    allowed_hosts.iter().any(|allowed| {
        hostname == *allowed
            || hostname
                .strip_suffix(allowed)
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

/// The question name in a DNS query (first question only). `None` on malformed input.
pub fn question_name(packet: &[u8]) -> Option<String> {
    if packet.len() < DNS_HEADER_LEN || read_u16(packet, DNS_QDCOUNT_OFFSET)? != DNS_ONE_QUESTION {
        return None;
    }
    let (name, _) = read_name(packet, DNS_HEADER_LEN)?;
    Some(name)
}

/// Extract `(IpAddr, ttl)` pairs from the A and AAAA records in a DNS response.
pub fn answer_ip_records(packet: &[u8]) -> Vec<(IpAddr, u32)> {
    parse_answer_ip_records(packet).unwrap_or_default()
}

fn parse_answer_ip_records(packet: &[u8]) -> Option<Vec<(IpAddr, u32)>> {
    if packet.len() < DNS_HEADER_LEN {
        return None;
    }
    let qdcount = read_u16(packet, DNS_QDCOUNT_OFFSET)? as usize;
    let ancount = read_u16(packet, DNS_ANCOUNT_OFFSET)? as usize;
    let mut offset = DNS_HEADER_LEN;

    for _ in 0..qdcount {
        let (_, after_name) = read_name(packet, offset)?;
        if after_name + DNS_QUESTION_FIXED_LEN > packet.len() {
            return None;
        }
        offset = after_name + DNS_QUESTION_FIXED_LEN;
    }

    let mut ips = Vec::new();
    for _ in 0..ancount {
        let (_, after_name) = read_name(packet, offset)?;
        if after_name + DNS_RR_FIXED_LEN > packet.len() {
            return None;
        }
        offset = after_name;

        let rr_type = read_u16(packet, offset + DNS_RR_TYPE_OFFSET)?;
        let class = read_u16(packet, offset + DNS_RR_CLASS_OFFSET)?;
        let ttl = read_u32(packet, offset + DNS_RR_TTL_OFFSET)?;
        let rdlen = read_u16(packet, offset + DNS_RR_RDLEN_OFFSET)? as usize;
        offset += DNS_RR_FIXED_LEN;

        if offset + rdlen > packet.len() {
            return None;
        }
        if class == DNS_CLASS_IN && rr_type == DNS_TYPE_A && rdlen == DNS_A_RDATA_LEN {
            ips.push((
                IpAddr::V4(Ipv4Addr::new(
                    packet[offset],
                    packet[offset + 1],
                    packet[offset + 2],
                    packet[offset + 3],
                )),
                ttl,
            ));
        } else if class == DNS_CLASS_IN && rr_type == DNS_TYPE_AAAA && rdlen == DNS_AAAA_RDATA_LEN {
            let octets: [u8; DNS_AAAA_RDATA_LEN] = packet[offset..offset + DNS_AAAA_RDATA_LEN]
                .try_into()
                .ok()?;
            ips.push((IpAddr::V6(Ipv6Addr::from(octets)), ttl));
        }
        offset += rdlen;
    }
    Some(ips)
}

/// Build a DNS response carrying just an error `rcode` (e.g. NXDOMAIN), echoing
/// the query id and question. Mirrors libkrun's `build_error_response`.
pub fn error_response(query: &[u8], rcode: u16) -> Vec<u8> {
    let id: &[u8] = if query.len() >= DNS_ID_LEN {
        &query[..DNS_ID_LEN]
    } else {
        &[0, 0]
    };
    let req_flags = if query.len() >= DNS_FLAGS_OFFSET + DNS_U16_LEN {
        read_u16(query, DNS_FLAGS_OFFSET).unwrap_or(0)
    } else {
        0
    };
    let flags = DNS_FLAG_RESPONSE
        | (req_flags & DNS_FLAG_RECURSION_DESIRED)
        | DNS_FLAG_RECURSION_AVAILABLE
        | (rcode & DNS_RCODE_MASK);

    // Echo the question section (qdcount stays as in the query) when parseable.
    let question_end = question_section_end(query);
    let qdcount = if question_end.is_some() { 1u16 } else { 0 };

    let mut response = Vec::with_capacity(question_end.unwrap_or(DNS_HEADER_LEN));
    response.extend_from_slice(id);
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&qdcount.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes()); // ancount
    response.extend_from_slice(&0u16.to_be_bytes()); // nscount
    response.extend_from_slice(&0u16.to_be_bytes()); // arcount
    if let Some(end) = question_end {
        response.extend_from_slice(&query[DNS_HEADER_LEN..end]);
    }
    response
}

/// Synthesize a DNS response for `query` with the given `ips` (A/AAAA, `ttl` s).
/// SERVFAIL if the question is unparseable; QTYPE filtering — only matching record
/// types are answered.
pub fn build_ip_response(query: &[u8], ips: &[IpAddr], ttl: u32) -> Vec<u8> {
    let Some(question_end) = question_section_end(query) else {
        return error_response(query, DNS_RCODE_SERVFAIL);
    };
    let qtype = read_u16(query, question_end - 4).unwrap_or(0);
    let ips: Vec<IpAddr> = ips
        .iter()
        .copied()
        .filter(|ip| {
            matches!(
                (qtype, ip),
                (DNS_TYPE_A, IpAddr::V4(_)) | (DNS_TYPE_AAAA, IpAddr::V6(_))
            )
        })
        .collect();
    let flags = DNS_FLAG_RESPONSE
        | (read_u16(query, DNS_FLAGS_OFFSET).unwrap_or(0) & DNS_FLAG_RECURSION_DESIRED)
        | DNS_FLAG_RECURSION_AVAILABLE;
    let ancount = u16::try_from(ips.len()).unwrap_or(0);

    let mut response =
        Vec::with_capacity(question_end + ips.len() * (DNS_RR_FIXED_LEN + DNS_AAAA_RDATA_LEN));
    response.extend_from_slice(&query[..DNS_ID_LEN]);
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&DNS_ONE_QUESTION.to_be_bytes()); // qdcount
    response.extend_from_slice(&ancount.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes()); // nscount
    response.extend_from_slice(&0u16.to_be_bytes()); // arcount
    response.extend_from_slice(&query[DNS_HEADER_LEN..question_end]); // echo question

    // Name pointer to the question name at the fixed header offset.
    let name_pointer = [DNS_POINTER_TAG, DNS_HEADER_LEN as u8];
    for ip in &ips {
        response.extend_from_slice(&name_pointer);
        let (rtype, rdata) = match ip {
            IpAddr::V4(v4) => (DNS_TYPE_A, v4.octets().to_vec()),
            IpAddr::V6(v6) => (DNS_TYPE_AAAA, v6.octets().to_vec()),
        };
        response.extend_from_slice(&rtype.to_be_bytes());
        response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        response.extend_from_slice(&ttl.to_be_bytes());
        response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        response.extend_from_slice(&rdata);
    }
    response
}

fn question_section_end(packet: &[u8]) -> Option<usize> {
    if packet.len() < DNS_HEADER_LEN || read_u16(packet, DNS_QDCOUNT_OFFSET)? != DNS_ONE_QUESTION {
        return None;
    }
    let (_, after_name) = read_name(packet, DNS_HEADER_LEN)?;
    let end = after_name + DNS_QUESTION_FIXED_LEN;
    if end > packet.len() {
        return None;
    }
    Some(end)
}

/// Parse a DNS name (with compression pointers), returning `(name, next_offset)`.
/// `next_offset` is the byte after the name in the *original* (non-jumped) stream.
fn read_name(packet: &[u8], offset: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut pos = offset;
    let mut next_offset = offset;
    let mut jumped = false;
    let mut jumps = 0;

    loop {
        let len = *packet.get(pos)?;
        if len & DNS_POINTER_MASK == DNS_POINTER_TAG {
            let lo = *packet.get(pos + 1)?;
            let pointer = (((len & DNS_POINTER_OFFSET_MASK) as usize) << 8) | lo as usize;
            if pointer >= packet.len() {
                return None;
            }
            if !jumped {
                next_offset = pos + DNS_U16_LEN;
            }
            pos = pointer;
            jumped = true;
            jumps += 1;
            if jumps > DNS_MAX_COMPRESSION_JUMPS {
                return None;
            }
            continue;
        }
        if len & DNS_POINTER_MASK != 0 {
            return None;
        }

        pos += 1;
        if len == 0 {
            if !jumped {
                next_offset = pos;
            }
            break;
        }

        let len = len as usize;
        if len > DNS_MAX_LABEL_LEN || pos + len > packet.len() {
            return None;
        }
        let label = std::str::from_utf8(&packet[pos..pos + len]).ok()?;
        labels.push(label.to_ascii_lowercase());
        pos += len;
        if !jumped {
            next_offset = pos;
        }
    }

    Some((labels.join("."), next_offset))
}

fn read_u16(buf: &[u8], offset: usize) -> Option<u16> {
    let bytes = buf.get(offset..offset + DNS_U16_LEN)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(buf: &[u8], offset: usize) -> Option<u32> {
    let bytes = buf.get(offset..offset + DNS_U32_LEN)?;
    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A query for `name` with one question (A/IN).
    fn query_for(name: &str) -> Vec<u8> {
        query_for_type(name, DNS_TYPE_A)
    }

    fn query_for_type(name: &str, qtype: u16) -> Vec<u8> {
        let mut q = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        q
    }

    #[test]
    fn parses_question_name() {
        assert_eq!(
            question_name(&query_for("www.example.com")).as_deref(),
            Some("www.example.com")
        );
    }

    #[test]
    fn hostname_matching_allows_exact_and_subdomain_only() {
        let allow = vec!["example.com".to_string()];
        assert!(hostname_allowed("example.com", &allow));
        assert!(hostname_allowed("www.example.com", &allow));
        assert!(hostname_allowed("a.b.example.com", &allow));
        assert!(!hostname_allowed("notexample.com", &allow));
        assert!(!hostname_allowed("example.com.evil.com", &allow));
    }

    #[test]
    fn empty_allow_list_blocks_all() {
        assert!(!hostname_allowed("example.com", &[]));
    }

    #[test]
    fn extracts_a_records_with_ttl() {
        // Response: echo the question, then one A record 93.184.216.34 ttl 300.
        let mut r = query_for("example.com");
        r[2] = 0x81; // QR=1, RD=1
        r[3] = 0x80; // RA=1
        r[6] = 0x00;
        r[7] = 0x01; // ancount = 1
                     // Answer: name pointer to question (0xc00c), type A, class IN, ttl, rdlen, rdata
        r.extend_from_slice(&[0xc0, 0x0c]);
        r.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        r.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        r.extend_from_slice(&300u32.to_be_bytes());
        r.extend_from_slice(&(DNS_A_RDATA_LEN as u16).to_be_bytes());
        r.extend_from_slice(&[93, 184, 216, 34]);

        let records = answer_ip_records(&r);
        assert_eq!(
            records,
            vec![(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 300)]
        );
        // A response echoes its question, so the name is recoverable from the
        // answer alone — which is how the gateway learns records under a name
        // without carrying the query string alongside the pending request.
        assert_eq!(question_name(&r).as_deref(), Some("example.com"));
    }

    #[test]
    fn extracts_aaaa_records_with_ttl() {
        // Response with one AAAA record 2606:2800:21f:cb07:6820:80da:af6b:8b2c ttl 600.
        let v6: Ipv6Addr = "2606:2800:21f:cb07:6820:80da:af6b:8b2c".parse().unwrap();
        let mut r = query_for("example.com");
        r[2] = 0x81;
        r[3] = 0x80;
        r[6] = 0x00;
        r[7] = 0x01; // ancount = 1
        r.extend_from_slice(&[0xc0, 0x0c]);
        r.extend_from_slice(&DNS_TYPE_AAAA.to_be_bytes());
        r.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        r.extend_from_slice(&600u32.to_be_bytes());
        r.extend_from_slice(&(DNS_AAAA_RDATA_LEN as u16).to_be_bytes());
        r.extend_from_slice(&v6.octets());

        let records = answer_ip_records(&r);
        assert_eq!(records, vec![(IpAddr::V6(v6), 600)]);
    }

    #[test]
    fn extracts_mixed_a_and_aaaa_records() {
        let v6: Ipv6Addr = "2606:4700::6810:84e5".parse().unwrap();
        let mut r = query_for("example.com");
        r[2] = 0x81;
        r[3] = 0x80;
        r[6] = 0x00;
        r[7] = 0x02; // ancount = 2
        r.extend_from_slice(&[0xc0, 0x0c]);
        r.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        r.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        r.extend_from_slice(&300u32.to_be_bytes());
        r.extend_from_slice(&(DNS_A_RDATA_LEN as u16).to_be_bytes());
        r.extend_from_slice(&[104, 16, 132, 229]);
        r.extend_from_slice(&[0xc0, 0x0c]);
        r.extend_from_slice(&DNS_TYPE_AAAA.to_be_bytes());
        r.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        r.extend_from_slice(&600u32.to_be_bytes());
        r.extend_from_slice(&(DNS_AAAA_RDATA_LEN as u16).to_be_bytes());
        r.extend_from_slice(&v6.octets());

        let records = answer_ip_records(&r);
        assert_eq!(
            records,
            vec![
                (IpAddr::V4(Ipv4Addr::new(104, 16, 132, 229)), 300),
                (IpAddr::V6(v6), 600),
            ]
        );
    }

    #[test]
    fn error_response_is_well_formed() {
        let q = query_for("blocked.test");
        let resp = error_response(&q, DNS_RCODE_NXDOMAIN);
        // QR bit set + rcode NXDOMAIN in low nibble of flags.
        let flags = read_u16(&resp, DNS_FLAGS_OFFSET).unwrap();
        assert_eq!(flags & DNS_FLAG_RESPONSE, DNS_FLAG_RESPONSE);
        assert_eq!(flags & DNS_RCODE_MASK, DNS_RCODE_NXDOMAIN);
        assert_eq!(&resp[..2], &q[..2]); // echoed id
    }

    #[test]
    fn build_ip_response_round_trips_through_parser() {
        let v4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        let v6 = IpAddr::V6("2606:4700::1".parse().unwrap());
        let ips = vec![v4, v6];

        // build_ip_response answers only the records matching the query type, so
        // an A query yields the A record and an AAAA query yields the AAAA record
        // — each must round-trip through our own parser exactly.
        for (qtype, want) in [(DNS_TYPE_A, v4), (DNS_TYPE_AAAA, v6)] {
            let query = query_for_type("api.internal", qtype);
            let response = build_ip_response(&query, &ips, 60);
            assert_eq!(&response[..2], &query[..2]); // echoed id
            let flags = read_u16(&response, DNS_FLAGS_OFFSET).unwrap();
            assert_eq!(flags & DNS_FLAG_RESPONSE, DNS_FLAG_RESPONSE);
            assert_eq!(answer_ip_records(&response), vec![(want, 60)]);
        }
    }

    #[test]
    fn build_ip_response_servfails_on_bad_query() {
        let response = build_ip_response(&[0, 1, 2], &[IpAddr::V4(Ipv4Addr::LOCALHOST)], 60);
        let flags = read_u16(&response, DNS_FLAGS_OFFSET).unwrap();
        assert_eq!(flags & DNS_RCODE_MASK, DNS_RCODE_SERVFAIL);
    }

    #[test]
    fn malformed_packets_dont_panic() {
        assert_eq!(question_name(&[0, 1, 2]), None);
        assert!(answer_ip_records(&[0xff; 4]).is_empty());
    }
}
