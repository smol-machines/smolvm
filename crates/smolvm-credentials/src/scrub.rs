//! Keep injected credential values out of what the guest reads back.
//!
//! An allowed host can reflect a request's credential: header echo endpoints,
//! error pages that quote the request, an API that returns a stored copy. The
//! guest never holds the value, so it must not get it back from a response
//! either. [`Scrubber`] finds every value the interceptor may have injected
//! toward the host, in the forms it naturally comes back in, and replaces it in
//! response headers and in the body as it streams.

use zeroize::Zeroizing;

/// What replaces a reflected value that has no placeholder to restore.
pub(crate) const REDACTED: &[u8] = b"[smolvm-redacted]";

/// Shortest form worth looking for. Anything shorter matches ordinary text.
const MIN_FORM_LEN: usize = 8;

/// One value the interceptor may have sent the host, and the placeholder the
/// guest knows it by, if any.
pub(crate) struct Secret<'a> {
    pub value: &'a [u8],
    pub placeholder: Option<&'a str>,
}

struct Pattern {
    needle: Zeroizing<Vec<u8>>,
    replacement: Vec<u8>,
}

/// Replaces every known form of a set of secrets.
pub(crate) struct Scrubber {
    /// Longest first, so the longest form at a position wins.
    patterns: Vec<Pattern>,
    first_bytes: [bool; 256],
    longest: usize,
}

impl Scrubber {
    /// `None` when no secret has a form long enough to look for.
    pub(crate) fn new(secrets: &[Secret<'_>]) -> Option<Self> {
        let mut patterns: Vec<Pattern> = Vec::new();
        for secret in secrets {
            let restored = secret
                .placeholder
                .map(|p| p.as_bytes().to_vec())
                .unwrap_or_else(|| REDACTED.to_vec());
            for (needle, raw) in forms(secret.value) {
                if needle.len() < MIN_FORM_LEN || patterns.iter().any(|p| *p.needle == *needle) {
                    continue;
                }
                // Only the value exactly as sent maps back to its placeholder;
                // an encoded copy has no placeholder form the guest could use.
                let replacement = if raw {
                    restored.clone()
                } else {
                    REDACTED.to_vec()
                };
                patterns.push(Pattern {
                    needle,
                    replacement,
                });
            }
        }
        if patterns.is_empty() {
            return None;
        }
        patterns.sort_by_key(|p| std::cmp::Reverse(p.needle.len()));
        let mut first_bytes = [false; 256];
        for pattern in &patterns {
            first_bytes[pattern.needle[0] as usize] = true;
        }
        let longest = patterns[0].needle.len();
        Some(Self {
            patterns,
            first_bytes,
            longest,
        })
    }

    /// Bytes a streaming caller must hold back after each chunk: a form may
    /// start in them and end in the next chunk.
    pub(crate) fn overlap(&self) -> usize {
        self.longest - 1
    }

    /// Scrub `buf` into `out`. Unless `last`, stops short of the final
    /// [`Self::overlap`] bytes, which may begin a form that the next chunk
    /// completes. Returns how many bytes of `buf` were consumed and how many
    /// forms were replaced.
    pub(crate) fn scan(&self, buf: &[u8], last: bool, out: &mut Vec<u8>) -> (usize, usize) {
        let limit = if last {
            buf.len()
        } else {
            buf.len().saturating_sub(self.overlap())
        };
        let mut i = 0;
        let mut copied = 0;
        let mut hits = 0;
        while i < limit {
            if self.first_bytes[buf[i] as usize] {
                if let Some(pattern) = self
                    .patterns
                    .iter()
                    .find(|p| buf[i..].starts_with(&p.needle))
                {
                    out.extend_from_slice(&buf[copied..i]);
                    out.extend_from_slice(&pattern.replacement);
                    i += pattern.needle.len();
                    copied = i;
                    hits += 1;
                    continue;
                }
            }
            i += 1;
        }
        out.extend_from_slice(&buf[copied..i]);
        (i, hits)
    }

    /// Scrub a complete value. `None` when nothing in it matched.
    pub(crate) fn scrub(&self, value: &[u8]) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(value.len());
        let (_, hits) = self.scan(value, true, &mut out);
        (hits > 0).then_some(out)
    }
}

/// Every form `value` is looked for in, each flagged whether it is the value
/// exactly as sent.
fn forms(value: &[u8]) -> Vec<(Zeroizing<Vec<u8>>, bool)> {
    let mut bases = vec![(Zeroizing::new(value.to_vec()), true)];
    // `Bearer abc`, `token abc`, `Basic abc`: the token alone is what a
    // service most often echoes back.
    if let Some(space) = value.iter().position(|b| *b == b' ') {
        let (scheme, rest) = (&value[..space], &value[space + 1..]);
        if !scheme.is_empty() && scheme.iter().all(u8::is_ascii_alphabetic) && !rest.is_empty() {
            bases.push((Zeroizing::new(rest.to_vec()), false));
        }
    }
    let mut out = Vec::new();
    for (base, raw) in bases {
        for escaped in [json_escape(&base, false), json_escape(&base, true)] {
            if *escaped != *base {
                out.push((escaped, false));
            }
        }
        for upper in [true, false] {
            let encoded = percent_encode(&base, upper);
            if *encoded != *base {
                out.push((encoded, false));
            }
        }
        for url_safe in [false, true] {
            for offset in 0..3 {
                if let Some(encoded) = base64_core(&base, offset, url_safe) {
                    out.push((encoded, false));
                }
            }
        }
        out.push((base, raw));
    }
    out
}

/// JSON string escaping, optionally with `/` escaped as `\/`.
fn json_escape(value: &[u8], slash: bool) -> Zeroizing<Vec<u8>> {
    let mut out = Vec::with_capacity(value.len() + 8);
    for &byte in value {
        match byte {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'/' if slash => out.extend_from_slice(b"\\/"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0..=0x1f => out.extend_from_slice(format!("\\u{byte:04x}").as_bytes()),
            _ => out.push(byte),
        }
    }
    Zeroizing::new(out)
}

/// Percent-encoding of everything outside the unreserved set.
fn percent_encode(value: &[u8], upper: bool) -> Zeroizing<Vec<u8>> {
    let hex: &[u8; 16] = if upper {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    let mut out = Vec::with_capacity(value.len() * 3);
    for &byte in value {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte);
        } else {
            out.extend_from_slice(&[b'%', hex[(byte >> 4) as usize], hex[(byte & 0xf) as usize]]);
        }
    }
    Zeroizing::new(out)
}

/// The Base64 characters that encode only bytes of `value` when it starts
/// `offset` bytes into a 3-byte group, whatever surrounds it. The value then
/// shows up inside any longer Base64 text that contains it.
fn base64_core(value: &[u8], offset: usize, url_safe: bool) -> Option<Zeroizing<Vec<u8>>> {
    let alphabet: &[u8; 64] = if url_safe {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    } else {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    };
    // Whole groups lying inside the value: skip the partial first group, stop
    // before the partial last one.
    let skip = (3 - offset) % 3;
    let whole = value.len().checked_sub(skip)? / 3;
    if whole == 0 {
        return None;
    }
    let mut out = Vec::with_capacity(whole * 4);
    for group in value[skip..skip + whole * 3].as_chunks::<3>().0 {
        let n = (u32::from(group[0]) << 16) | (u32::from(group[1]) << 8) | u32::from(group[2]);
        for shift in [18, 12, 6, 0] {
            out.push(alphabet[((n >> shift) & 0x3f) as usize]);
        }
    }
    Some(Zeroizing::new(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scrubber(value: &str, placeholder: Option<&str>) -> Scrubber {
        Scrubber::new(&[Secret {
            value: value.as_bytes(),
            placeholder,
        }])
        .expect("patterns")
    }

    fn standard_b64(value: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(value)
    }

    #[test]
    fn the_raw_value_maps_back_to_its_placeholder() {
        let s = scrubber("ghp_secretvalue123", Some("SMOL_PLACEHOLDER_GIT_1"));
        assert_eq!(
            s.scrub(br#"{"Authorization":"Bearer ghp_secretvalue123"}"#)
                .unwrap(),
            br#"{"Authorization":"Bearer SMOL_PLACEHOLDER_GIT_1"}"#.to_vec()
        );
        assert_eq!(s.scrub(b"nothing to see here"), None);
    }

    #[test]
    fn a_header_value_and_its_bare_token_are_both_found() {
        let s = scrubber("Bearer tok_0123456789", None);
        let out = s
            .scrub(b"a=Bearer tok_0123456789 b=tok_0123456789")
            .unwrap();
        assert_eq!(out, b"a=[smolvm-redacted] b=[smolvm-redacted]".to_vec());
    }

    #[test]
    fn json_and_percent_encodings_are_found() {
        let secret = r#"pa"ss/w\rd+&=1"#;
        let s = scrubber(secret, None);
        for reflected in [
            r#"{"v":"pa\"ss/w\\rd+&=1"}"#.to_string(),
            r#"{"v":"pa\"ss\/w\\rd+&=1"}"#.to_string(),
            "q=pa%22ss%2Fw%5Crd%2B%26%3D1".to_string(),
            "q=pa%22ss%2fw%5crd%2b%26%3d1".to_string(),
        ] {
            let out = s.scrub(reflected.as_bytes()).expect(&reflected);
            assert!(
                String::from_utf8_lossy(&out).contains("[smolvm-redacted]"),
                "{reflected}"
            );
        }
    }

    #[test]
    fn base64_is_found_at_every_alignment_inside_longer_text() {
        let secret = b"s3cr3t-token-value-0123";
        let s = Scrubber::new(&[Secret {
            value: secret,
            placeholder: None,
        }])
        .unwrap();
        for prefix in ["", "a", "ab", "abc", "Authorization: Basic "] {
            let mut plain = prefix.as_bytes().to_vec();
            plain.extend_from_slice(secret);
            plain.extend_from_slice(b"-trailer");
            let encoded = standard_b64(&plain);
            assert!(
                s.scrub(encoded.as_bytes()).is_some(),
                "missed base64 with prefix {prefix:?}: {encoded}"
            );
            let url_safe = encoded.replace('+', "-").replace('/', "_");
            assert!(
                s.scrub(url_safe.as_bytes()).is_some(),
                "url-safe {prefix:?}"
            );
        }
    }

    #[test]
    fn a_value_split_across_chunks_is_still_replaced() {
        let s = scrubber("abcdefghijklmnop", Some("SMOL_PLACEHOLDER_X_1"));
        let body = b"head abcdefghijklmnop tail abcdefghijklmnop".to_vec();
        for chunk in 1..body.len() {
            let mut carry = Vec::new();
            let mut out = Vec::new();
            for piece in body.chunks(chunk) {
                carry.extend_from_slice(piece);
                let (used, _) = s.scan(&carry, false, &mut out);
                carry.drain(..used);
                assert!(carry.len() <= s.overlap() + chunk);
            }
            s.scan(&carry, true, &mut out);
            assert_eq!(
                out,
                b"head SMOL_PLACEHOLDER_X_1 tail SMOL_PLACEHOLDER_X_1".to_vec(),
                "chunk size {chunk}"
            );
        }
    }

    #[test]
    fn short_values_are_not_looked_for() {
        assert!(Scrubber::new(&[Secret {
            value: b"abc",
            placeholder: None
        }])
        .is_none());
    }
}
