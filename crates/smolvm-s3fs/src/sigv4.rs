//! AWS Signature Version 4 for S3 requests.
//!
//! Implemented directly rather than pulled from an SDK: the agent is a 1.6 MiB
//! static binary in the guest rootfs, and the AWS SDK (plus its async runtime)
//! would dominate that budget. Signing is a well-specified, testable algorithm —
//! the canonical-request → string-to-sign → derived-key chain below matches the
//! AWS documentation's own worked examples, which the tests assert against.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// The payload hash header S3 requires. Streaming uploads use the unsigned
/// sentinel: we cannot hash a body we have not buffered, and S3 accepts it over
/// HTTPS (the transport already protects integrity).
pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";
pub const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Credentials for signing. `session_token` is set when the caller supplies
/// temporary (STS) credentials, which most workloads on cloud instances use.
#[derive(Clone, Debug)]
pub struct Credentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
}

/// A request to sign, reduced to the parts SigV4 covers.
pub struct SignRequest<'a> {
    pub method: &'a str,
    /// Already-encoded path, beginning with `/` (e.g. `/bucket/some%20key`).
    pub path: &'a str,
    /// Query pairs in any order; signing sorts them canonically.
    pub query: &'a [(String, String)],
    /// Headers to sign. `host` must be present; `x-amz-date` and
    /// `x-amz-content-sha256` are added by the signer.
    pub headers: &'a mut Vec<(String, String)>,
    pub payload_sha256: &'a str,
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut m = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac accepts any key length");
    m.update(data);
    m.finalize().into_bytes().to_vec()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

/// Percent-encode for canonical URIs/queries. S3 signing requires the strict
/// RFC 3986 unreserved set — notably `/` is encoded in query values but kept
/// literal in the path, so the caller passes the path pre-encoded.
pub fn uri_encode(s: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b'/' if !encode_slash => out.push('/'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Sign `req` in place, appending `Authorization` (plus the amz headers).
///
/// `now` is `(YYYYMMDD, YYYYMMDDTHHMMSSZ)` — passed in rather than read from the
/// clock so the tests can pin AWS's published example timestamps.
pub fn sign(req: SignRequest<'_>, creds: &Credentials, region: &str, now: (&str, &str)) {
    let (date_stamp, amz_date) = now;

    req.headers.retain(|(k, _)| {
        let k = k.to_ascii_lowercase();
        k != "x-amz-date"
            && k != "x-amz-content-sha256"
            && k != "authorization"
            && k != "x-amz-security-token"
    });
    req.headers
        .push(("x-amz-date".into(), amz_date.to_string()));
    req.headers.push((
        "x-amz-content-sha256".into(),
        req.payload_sha256.to_string(),
    ));
    if let Some(token) = &creds.session_token {
        req.headers
            .push(("x-amz-security-token".into(), token.clone()));
    }

    // Canonical headers: lowercase names, trimmed values, sorted, each newline-terminated.
    let mut canon: Vec<(String, String)> = req
        .headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    canon.sort_by(|a, b| a.0.cmp(&b.0));
    let signed_headers = canon
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let canonical_headers: String = canon.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();

    let mut q: Vec<(String, String)> = req
        .query
        .iter()
        .map(|(k, v)| (uri_encode(k, true), uri_encode(v, true)))
        .collect();
    q.sort();
    let canonical_query = q
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        req.method,
        req.path,
        canonical_query,
        canonical_headers,
        signed_headers,
        req.payload_sha256
    );

    let scope = format!("{date_stamp}/{region}/s3/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );

    let k_date = hmac(
        format!("AWS4{}", creds.secret_access_key).as_bytes(),
        date_stamp.as_bytes(),
    );
    let k_region = hmac(&k_date, region.as_bytes());
    let k_service = hmac(&k_region, b"s3");
    let k_signing = hmac(&k_service, b"aws4_request");
    let signature = hex(&hmac(&k_signing, string_to_sign.as_bytes()));

    req.headers.push((
        "authorization".into(),
        format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
            creds.access_key_id
        ),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creds() -> Credentials {
        // The example credentials from AWS's SigV4 test suite.
        Credentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            session_token: None,
        }
    }

    // AWS's documented "GET Object" example: if our canonical-request and
    // key-derivation chain is right, we reproduce their published signature
    // byte for byte. This is the whole reason to hand-roll signing with
    // confidence rather than hope.
    #[test]
    fn matches_the_aws_published_get_object_signature() {
        let mut headers = vec![
            (
                "host".to_string(),
                "examplebucket.s3.amazonaws.com".to_string(),
            ),
            ("range".to_string(), "bytes=0-9".to_string()),
        ];
        sign(
            SignRequest {
                method: "GET",
                path: "/test.txt",
                query: &[],
                headers: &mut headers,
                payload_sha256: EMPTY_SHA256,
            },
            &creds(),
            "us-east-1",
            ("20130524", "20130524T000000Z"),
        );
        let auth = headers
            .iter()
            .find(|(k, _)| k == "authorization")
            .unwrap()
            .1
            .clone();
        assert!(
            auth.ends_with(
                "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
            ),
            "unexpected signature: {auth}"
        );
    }

    // Same suite, "PUT Object" — exercises a signed payload hash and extra
    // x-amz-* headers, which change both the canonical headers and the digest.
    #[test]
    fn matches_the_aws_published_put_object_signature() {
        let body_hash = "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072";
        let mut headers = vec![
            (
                "date".to_string(),
                "Fri, 24 May 2013 00:00:00 GMT".to_string(),
            ),
            (
                "host".to_string(),
                "examplebucket.s3.amazonaws.com".to_string(),
            ),
            (
                "x-amz-storage-class".to_string(),
                "REDUCED_REDUNDANCY".to_string(),
            ),
        ];
        sign(
            SignRequest {
                method: "PUT",
                path: "/test%24file.text",
                query: &[],
                headers: &mut headers,
                payload_sha256: body_hash,
            },
            &creds(),
            "us-east-1",
            ("20130524", "20130524T000000Z"),
        );
        let auth = headers
            .iter()
            .find(|(k, _)| k == "authorization")
            .unwrap()
            .1
            .clone();
        assert!(
            auth.ends_with(
                "Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
            ),
            "unexpected signature: {auth}"
        );
    }

    // Listing uses a query string, which must be sorted and encoded canonically.
    #[test]
    fn matches_the_aws_published_list_signature() {
        let mut headers = vec![(
            "host".to_string(),
            "examplebucket.s3.amazonaws.com".to_string(),
        )];
        sign(
            SignRequest {
                method: "GET",
                path: "/",
                query: &[
                    ("max-keys".into(), "2".into()),
                    ("prefix".into(), "J".into()),
                ],
                headers: &mut headers,
                payload_sha256: EMPTY_SHA256,
            },
            &creds(),
            "us-east-1",
            ("20130524", "20130524T000000Z"),
        );
        let auth = headers
            .iter()
            .find(|(k, _)| k == "authorization")
            .unwrap()
            .1
            .clone();
        assert!(
            auth.ends_with(
                "Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"
            ),
            "unexpected signature: {auth}"
        );
    }

    #[test]
    fn uri_encoding_follows_the_unreserved_set() {
        assert_eq!(uri_encode("a b/c", false), "a%20b/c");
        assert_eq!(uri_encode("a b/c", true), "a%20b%2Fc");
        assert_eq!(uri_encode("~-_.", true), "~-_.");
    }
}
