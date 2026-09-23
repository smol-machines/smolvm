//! TLS ClientHello inspection.
//!
//! The interceptor receives every redirected HTTPS flow before deciding
//! whether it belongs to a credential host. It peeks at the first TLS record
//! for the `server_name` extension; the record is then either handed to the
//! terminating TLS stack or replayed toward the real destination unchanged.

/// Largest ClientHello the interceptor will buffer while looking for SNI.
pub const MAX_CLIENT_HELLO: usize = 16 * 1024;

/// Result of inspecting the bytes buffered so far.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Peek {
    /// More bytes are required before a decision can be made.
    Incomplete,
    /// A complete ClientHello carrying this server name.
    ServerName(String),
    /// Not a TLS ClientHello, or one without a usable SNI.
    NoServerName,
}

/// Inspect `buf` for a TLS ClientHello and extract its SNI.
pub fn peek_client_hello(buf: &[u8]) -> Peek {
    // TLS record header: type(1) version(2) length(2)
    if buf.len() < 5 {
        return if buf.is_empty() || buf[0] == 0x16 {
            Peek::Incomplete
        } else {
            Peek::NoServerName
        };
    }
    if buf[0] != 0x16 || buf[1] != 0x03 {
        return Peek::NoServerName;
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if record_len == 0 || record_len > MAX_CLIENT_HELLO {
        return Peek::NoServerName;
    }
    if buf.len() < 5 + record_len {
        return Peek::Incomplete;
    }
    let hs = &buf[5..5 + record_len];
    // Handshake header: type(1) length(3)
    if hs.len() < 4 || hs[0] != 0x01 {
        return Peek::NoServerName;
    }
    let hs_len = u32::from_be_bytes([0, hs[1], hs[2], hs[3]]) as usize;
    if hs.len() < 4 + hs_len {
        // A ClientHello split across records is rare; treat it as opaque.
        return Peek::NoServerName;
    }
    parse_client_hello(&hs[4..4 + hs_len]).unwrap_or(Peek::NoServerName)
}

fn parse_client_hello(mut body: &[u8]) -> Option<Peek> {
    // version(2) random(32)
    body = body.get(34..)?;
    let session_len = *body.first()? as usize;
    body = body.get(1 + session_len..)?;
    let cipher_len = u16::from_be_bytes([*body.first()?, *body.get(1)?]) as usize;
    body = body.get(2 + cipher_len..)?;
    let compression_len = *body.first()? as usize;
    body = body.get(1 + compression_len..)?;
    if body.is_empty() {
        return Some(Peek::NoServerName);
    }
    let ext_len = u16::from_be_bytes([*body.first()?, *body.get(1)?]) as usize;
    let mut exts = body.get(2..2 + ext_len)?;
    while exts.len() >= 4 {
        let ext_type = u16::from_be_bytes([exts[0], exts[1]]);
        let len = u16::from_be_bytes([exts[2], exts[3]]) as usize;
        let data = exts.get(4..4 + len)?;
        if ext_type == 0x0000 {
            return Some(parse_server_name(data).unwrap_or(Peek::NoServerName));
        }
        exts = &exts[4 + len..];
    }
    Some(Peek::NoServerName)
}

fn parse_server_name(data: &[u8]) -> Option<Peek> {
    let list_len = u16::from_be_bytes([*data.first()?, *data.get(1)?]) as usize;
    let mut list = data.get(2..2 + list_len)?;
    while list.len() >= 3 {
        let name_type = list[0];
        let len = u16::from_be_bytes([list[1], list[2]]) as usize;
        let name = list.get(3..3 + len)?;
        if name_type == 0 {
            let name = std::str::from_utf8(name).ok()?;
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_'))
            {
                return Some(Peek::NoServerName);
            }
            return Some(Peek::ServerName(
                name.trim_end_matches('.').to_ascii_lowercase(),
            ));
        }
        list = &list[3 + len..];
    }
    Some(Peek::NoServerName)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal TLS 1.2-style ClientHello record carrying `sni`.
    pub(crate) fn client_hello(sni: Option<&str>) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0u8; 32]);
        body.push(0); // session id
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // one cipher suite
        body.extend_from_slice(&[0x01, 0x00]); // null compression
        let mut exts = Vec::new();
        if let Some(name) = sni {
            let mut entry = vec![0x00];
            entry.extend_from_slice(&(name.len() as u16).to_be_bytes());
            entry.extend_from_slice(name.as_bytes());
            let mut list = (entry.len() as u16).to_be_bytes().to_vec();
            list.extend_from_slice(&entry);
            exts.extend_from_slice(&[0x00, 0x00]);
            exts.extend_from_slice(&(list.len() as u16).to_be_bytes());
            exts.extend_from_slice(&list);
        }
        // an unrelated extension after SNI
        exts.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);
        let mut hs = vec![0x01];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs);
        record
    }

    #[test]
    fn extracts_sni_from_a_complete_hello() {
        let hello = client_hello(Some("API.Notion.com"));
        assert_eq!(
            peek_client_hello(&hello),
            Peek::ServerName("api.notion.com".into())
        );
        assert_eq!(
            peek_client_hello(&hello[..hello.len() - 1]),
            Peek::Incomplete
        );
        assert_eq!(peek_client_hello(&hello[..3]), Peek::Incomplete);
    }

    #[test]
    fn non_tls_and_sni_less_hellos_are_opaque() {
        assert_eq!(peek_client_hello(b"GET / HTTP/1.1\r\n"), Peek::NoServerName);
        assert_eq!(peek_client_hello(&client_hello(None)), Peek::NoServerName);
        assert_eq!(peek_client_hello(&[]), Peek::Incomplete);
    }
}
