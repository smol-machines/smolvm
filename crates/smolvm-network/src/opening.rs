//! What the first bytes a guest sends on an outbound TCP connection say about
//! the connection.
//!
//! Two openings are worth knowing about. A stratum handshake is a miner logging
//! in to its pool, which no other program sends, so it is evidence of mining
//! whatever the pool's name or address: a list of pools only ever covers the
//! pools someone has seen. A TLS ClientHello names the server the guest wants,
//! which the egress watchlist can match even when the guest resolved that name
//! without asking the gateway's DNS (DNS over HTTPS, or an address baked in).

use smolvm_protocol::sni::{peek_client_hello, Peek, MAX_CLIENT_HELLO};

/// The most opening bytes held while waiting for a verdict: one whole TLS
/// record. Anything longer gets [`Opening::Other`].
pub const MAX_OPENING_BYTES: usize = 5 + MAX_CLIENT_HELLO;

/// The longest first line read as a possible stratum request. A stratum login
/// is one JSON object of a few hundred bytes on its own line.
const MAX_STRATUM_LINE: usize = 4096;

/// Stratum methods a miner opens with. Each belongs to a mining protocol and
/// to nothing else, so a match is not a guess about what the program is.
const STRATUM_METHODS: &[&str] = &[
    // Stratum v1 (Bitcoin and most proof-of-work coins), opened by
    // ccminer, cpuminer and cgminer.
    "mining.subscribe",
    "mining.authorize",
    "mining.configure",
    "mining.extranonce.subscribe",
    // EthereumStratum and its proxies.
    "eth_submitLogin",
];

/// What a connection's opening bytes are.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Opening {
    /// A miner's stratum handshake; carries the method it opened with.
    Stratum(&'static str),
    /// A TLS ClientHello asking for this server name, lowercased.
    ServerName(String),
    /// Anything else, including a ClientHello without a name.
    Other,
}

/// Classify the bytes a guest has sent on a connection so far, or `None` when
/// more of them are needed. Never `None` once `bytes` reach
/// [`MAX_OPENING_BYTES`].
pub fn classify(bytes: &[u8]) -> Option<Opening> {
    let verdict = match bytes.first()? {
        0x16 => match peek_client_hello(bytes) {
            Peek::Incomplete => None,
            Peek::ServerName(name) => Some(Opening::ServerName(name)),
            Peek::NoServerName => Some(Opening::Other),
        },
        b'{' => match bytes.iter().position(|&b| b == b'\n') {
            Some(end) => {
                Some(stratum_method(&bytes[..end]).map_or(Opening::Other, Opening::Stratum))
            }
            None if bytes.len() >= MAX_STRATUM_LINE => Some(Opening::Other),
            None => None,
        },
        _ => Some(Opening::Other),
    };
    match verdict {
        None if bytes.len() >= MAX_OPENING_BYTES => Some(Opening::Other),
        verdict => verdict,
    }
}

/// The stratum method `line` requests, when it is a stratum request.
fn stratum_method(line: &[u8]) -> Option<&'static str> {
    let request: serde_json::Value = serde_json::from_slice(line).ok()?;
    let method = request.get("method")?.as_str()?;
    if let Some(known) = STRATUM_METHODS.iter().copied().find(|m| *m == method) {
        return Some(known);
    }
    // The CryptoNote stratum XMRig speaks opens with a bare `login`, a word
    // plenty of JSON-RPC services use, so it counts only with the pool login's
    // own fields: the wallet as `login` and the worker password as `pass`.
    let params = request.get("params")?.as_object()?;
    (method == "login" && params.contains_key("login") && params.contains_key("pass"))
        .then_some("login")
}

#[cfg(test)]
/// A minimal TLS ClientHello record carrying `sni`.
pub(crate) fn client_hello(sni: &str) -> Vec<u8> {
    let mut entry = vec![0x00];
    entry.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    entry.extend_from_slice(sni.as_bytes());
    let mut list = (entry.len() as u16).to_be_bytes().to_vec();
    list.extend_from_slice(&entry);
    let mut exts = vec![0x00, 0x00];
    exts.extend_from_slice(&(list.len() as u16).to_be_bytes());
    exts.extend_from_slice(&list);
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[0u8; 32]);
    body.extend_from_slice(&[0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00]);
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);
    let mut handshake = vec![0x01];
    handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    handshake.extend_from_slice(&body);
    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn miners_opening_their_pool_login_are_stratum() {
        // ccminer, as it opened to pool.nerbus.com on 2026-10-19.
        let ccminer = br#"{"id": 1, "method": "mining.subscribe", "params": ["ccminer/2.3.1"]}"#;
        let xmrig = br#"{"id":1,"jsonrpc":"2.0","method":"login","params":{"login":"4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfpAV5Usx","pass":"x","agent":"XMRig/6.21.0"}}"#;
        let eth = br#"{"id":1,"method":"eth_submitLogin","params":["0xabc"],"worker":"rig"}"#;
        for (line, method) in [
            (&ccminer[..], "mining.subscribe"),
            (&xmrig[..], "login"),
            (&eth[..], "eth_submitLogin"),
        ] {
            let mut opening = line.to_vec();
            opening.push(b'\n');
            assert_eq!(classify(&opening), Some(Opening::Stratum(method)));
        }
    }

    #[test]
    fn other_json_rpc_and_other_protocols_are_not_stratum() {
        for opening in [
            &br#"{"jsonrpc":"2.0","id":1,"method":"login","params":{"user":"a","password":"b"}}"#[..],
            br#"{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}"#,
            br#"{"method":"mining.subscribe""#,
            b"{not json at all}",
        ] {
            let mut opening = opening.to_vec();
            opening.push(b'\n');
            assert_eq!(classify(&opening), Some(Opening::Other), "{opening:?}");
        }
        assert_eq!(classify(b"GET / HTTP/1.1\r\n"), Some(Opening::Other));
        assert_eq!(classify(b"SSH-2.0-OpenSSH_9.6\r\n"), Some(Opening::Other));
    }

    #[test]
    fn an_opening_waits_for_its_whole_line_or_record_but_not_forever() {
        assert_eq!(classify(b""), None);
        assert_eq!(classify(br#"{"id": 1, "method": "mining.sub"#), None);
        assert_eq!(classify(&[b'{'; MAX_STRATUM_LINE]), Some(Opening::Other));
        let hello = client_hello("Pool.Example.com");
        assert_eq!(classify(&hello[..hello.len() - 1]), None);
        assert_eq!(
            classify(&hello),
            Some(Opening::ServerName("pool.example.com".into()))
        );
    }
}
