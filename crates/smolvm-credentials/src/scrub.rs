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

/// Longest form of a value of at most [`MAX_CREDENTIAL_VALUE_BYTES`](crate::policy::MAX_CREDENTIAL_VALUE_BYTES)
/// bytes: JSON escapes a control byte as six.
pub(crate) const MAX_FORM_LEN: usize = 6 * crate::policy::MAX_CREDENTIAL_VALUE_BYTES;

/// One value the interceptor may have sent the host, and the placeholder the
/// guest knows it by, if any.
pub(crate) struct Secret<'a> {
    pub value: &'a [u8],
    pub placeholder: Option<&'a str>,
}

/// Replaces every known form of a set of secrets, in time linear in what it
/// scans however many forms it knows.
pub(crate) struct Scrubber {
    /// Every form, matched leftmost-longest: the longest form starting at the
    /// first position where any starts wins, as a scan form by form would pick.
    matcher: aho_corasick::AhoCorasick,
    /// What replaces each form, by its pattern id.
    replacements: Vec<Vec<u8>>,
    longest: usize,
    /// The values whose forms it knows, sorted.
    values: Vec<Zeroizing<Vec<u8>>>,
}

impl Scrubber {
    /// `None` when no secret has a form long enough to look for. An error means the forms could not be compiled
    /// into a matcher: the caller must not pass the response on unchecked.
    pub(crate) fn new(secrets: &[Secret<'_>]) -> Result<Option<Self>, aho_corasick::BuildError> {
        // (form, replacement, which secret): sorted and deduplicated so the
        // first secret giving a form decides what replaces it.
        let mut forms_found: Vec<(Zeroizing<Vec<u8>>, Vec<u8>, usize)> = Vec::new();
        for (order, secret) in secrets.iter().enumerate() {
            let restored = secret
                .placeholder
                .map(|p| p.as_bytes().to_vec())
                .unwrap_or_else(|| REDACTED.to_vec());
            for (needle, raw) in forms(secret.value) {
                if needle.len() < MIN_FORM_LEN {
                    continue;
                }
                // Only the value exactly as sent maps back to its placeholder;
                // an encoded copy has no placeholder form the guest could use.
                let replacement = if raw {
                    restored.clone()
                } else {
                    REDACTED.to_vec()
                };
                forms_found.push((needle, replacement, order));
            }
        }
        if forms_found.is_empty() {
            return Ok(None);
        }
        forms_found.sort_by(|a, b| a.0.cmp(&b.0).then(a.2.cmp(&b.2)));
        forms_found.dedup_by(|later, kept| later.0 == kept.0);
        let longest = forms_found.iter().map(|f| f.0.len()).max().unwrap_or(0);
        let matcher = aho_corasick::AhoCorasick::builder()
            .match_kind(aho_corasick::MatchKind::LeftmostLongest)
            .start_kind(aho_corasick::StartKind::Both)
            .build(forms_found.iter().map(|f| f.0.as_slice()))?;
        let replacements = forms_found.into_iter().map(|f| f.1).collect();
        let mut values: Vec<Zeroizing<Vec<u8>>> = secrets
            .iter()
            .map(|s| Zeroizing::new(s.value.to_vec()))
            .collect();
        values.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
        values.dedup_by(|a, b| a.as_slice() == b.as_slice());
        Ok(Some(Self {
            matcher,
            replacements,
            longest,
            values,
        }))
    }

    /// Whether this scrubber looks for every form of `value`.
    pub(crate) fn covers(&self, value: &[u8]) -> bool {
        self.values
            .binary_search_by(|known| known.as_slice().cmp(value))
            .is_ok()
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
        let mut copied = 0;
        let mut hits = 0;
        // A form starting before `limit` has all its bytes in `buf`, so it is
        // found exactly as it would be with the next chunk joined on.
        for found in self.matcher.find_iter(buf) {
            if found.start() >= limit {
                break;
            }
            out.extend_from_slice(&buf[copied..found.start()]);
            out.extend_from_slice(&self.replacements[found.pattern().as_usize()]);
            copied = found.end();
            hits += 1;
        }
        let used = copied.max(limit);
        out.extend_from_slice(&buf[copied..used]);
        (used, hits)
    }

    /// [`Self::scan`] for `buf` following `sent`, the input bytes already passed on just before it, perhaps under a
    /// scrubber that did not know every value this one does. A form that began in `sent` and ends in `buf` is
    /// matched too: what of it is in `buf` is replaced, so nothing passed on from here completes it. While such a
    /// form might still end beyond `buf`, none of `buf` is consumed.
    pub(crate) fn scan_after(
        &self,
        sent: &[u8],
        buf: &[u8],
        last: bool,
        out: &mut Vec<u8>,
    ) -> (usize, usize) {
        let lead = sent.len().min(self.overlap());
        if lead == 0 {
            return self.scan(buf, last, out);
        }
        // A position in `sent` is checked only with a whole form's worth of bytes after it.
        if !last && buf.len() < self.overlap() {
            return (0, 0);
        }
        // Only what a form begun in `sent` can reach.
        let reach = buf.len().min(lead + self.overlap());
        let mut joined = Vec::with_capacity(lead + reach);
        joined.extend_from_slice(&sent[sent.len() - lead..]);
        joined.extend_from_slice(&buf[..reach]);
        let swallowed = (0..lead)
            .filter_map(|i| {
                let input = aho_corasick::Input::new(&joined)
                    .range(i..)
                    .anchored(aho_corasick::Anchored::Yes);
                self.matcher.find(input).map(|found| found.end())
            })
            .filter(|&end| end > lead)
            .max()
            .map_or(0, |end| end - lead);
        if swallowed == 0 {
            return self.scan(buf, last, out);
        }
        out.extend_from_slice(REDACTED);
        let (used, hits) = self.scan(&buf[swallowed..], last, out);
        (swallowed + used, hits + 1)
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
        .unwrap()
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
        .unwrap()
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
    fn the_rest_of_a_value_begun_in_what_was_passed_on_is_replaced() {
        let s = scrubber("ghp_straddlesecret1234", Some("SMOL_PLACEHOLDER_X_1"));
        let sent = b"lead ghp_straddl";
        let mut out = Vec::new();
        // not enough after the start yet to tell: nothing passes
        assert_eq!(s.scan_after(sent, b"esecr", false, &mut out), (0, 0));
        assert!(out.is_empty());
        let rest = b"esecret1234 and the tail goes on past the overlap";
        let (used, hits) = s.scan_after(sent, rest, false, &mut out);
        assert_eq!(hits, 1);
        let mut carry = rest[used..].to_vec();
        let (_, _) = s.scan(&carry, true, &mut out);
        carry.clear();
        let out = String::from_utf8(out).unwrap();
        assert!(out.starts_with("[smolvm-redacted] and the tail"), "{out}");
        assert!(!out.contains("esecret1234"), "{out}");
        // nothing begun before: the same as `scan`
        let mut plain = Vec::new();
        let mut after = Vec::new();
        let body = b"x ghp_straddlesecret1234 y";
        assert_eq!(
            s.scan(body, true, &mut plain),
            s.scan_after(b"unrelated text before it", body, true, &mut after)
        );
        assert_eq!(plain, after);
    }

    /// Form by form, longest first at each position: what the matcher must agree with.
    fn naive_scrub(secrets: &[Secret<'_>], body: &[u8]) -> Vec<u8> {
        let mut patterns: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        for secret in secrets {
            let restored = secret
                .placeholder
                .map(|p| p.as_bytes().to_vec())
                .unwrap_or_else(|| REDACTED.to_vec());
            for (needle, raw) in forms(secret.value) {
                if needle.len() >= MIN_FORM_LEN && !patterns.iter().any(|p| *p.0 == *needle) {
                    let replacement = if raw {
                        restored.clone()
                    } else {
                        REDACTED.to_vec()
                    };
                    patterns.push((needle.to_vec(), replacement));
                }
            }
        }
        patterns.sort_by_key(|p| std::cmp::Reverse(p.0.len()));
        let mut out = Vec::new();
        let mut i = 0;
        while i < body.len() {
            match patterns.iter().find(|p| body[i..].starts_with(&p.0)) {
                Some((needle, replacement)) => {
                    out.extend_from_slice(replacement);
                    i += needle.len();
                }
                None => {
                    out.push(body[i]);
                    i += 1;
                }
            }
        }
        out
    }

    #[test]
    fn many_values_are_found_as_a_form_by_form_scan_would_in_any_chunking() {
        let mut seed = 0x2545_f491_u32;
        let mut next = move || {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            seed >> 8
        };
        const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        // shared prefixes, one value inside another, a scheme, and characters that encode
        let mut values: Vec<String> = (0..48)
            .map(|i| {
                let mut v = if i % 2 == 0 { "sk-proj-" } else { "ghp_" }.to_string();
                for _ in 0..(12 + next() % 30) {
                    v.push(ALNUM[(next() % 62) as usize] as char);
                }
                v
            })
            .collect();
        values.push(format!("{}XYZ", values[0]));
        values.push(format!("Bearer {}", values[1]));
        values.push("pa\"ss/w\\rd+&=12".to_string());
        let placeholders: Vec<String> = (0..values.len())
            .map(|i| format!("SMOL_PLACEHOLDER_V_{i}"))
            .collect();
        let secrets: Vec<Secret<'_>> = values
            .iter()
            .zip(&placeholders)
            .enumerate()
            .map(|(i, (v, p))| Secret {
                value: v.as_bytes(),
                placeholder: (i % 3 != 0).then_some(p.as_str()),
            })
            .collect();
        let s = Scrubber::new(&secrets).unwrap().unwrap();
        let mut body = Vec::new();
        for i in 0..400 {
            let v = values[(next() as usize) % values.len()].as_bytes();
            match i % 5 {
                0 => body.extend_from_slice(v),
                1 => body.extend_from_slice(&v[..v.len() / 2]),
                2 => body.extend_from_slice(standard_b64(v).as_bytes()),
                _ => body.extend((0..(next() % 20)).map(|_| ALNUM[(next() % 62) as usize])),
            }
        }
        let expected = naive_scrub(&secrets, &body);
        assert_eq!(s.scrub(&body).unwrap_or_else(|| body.clone()), expected);
        for chunk in [1, 7, 64, 1000] {
            let (mut carry, mut out) = (Vec::new(), Vec::new());
            for piece in body.chunks(chunk) {
                carry.extend_from_slice(piece);
                let (used, _) = s.scan(&carry, false, &mut out);
                carry.drain(..used);
            }
            s.scan(&carry, true, &mut out);
            assert_eq!(out, expected, "chunk size {chunk}");
        }
        assert!(values.iter().all(|v| s.covers(v.as_bytes())));
        assert!(!s.covers(b"not-a-value-at-all"));
    }

    #[test]
    fn short_values_are_not_looked_for() {
        assert!(Scrubber::new(&[Secret {
            value: b"abc",
            placeholder: None
        }])
        .unwrap()
        .is_none());
    }
}
