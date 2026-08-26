//! Minimal S3 client: only the operations a filesystem needs.
//!
//! Deliberately not an SDK. The agent is a static binary in the guest rootfs,
//! so every dependency is paid for on every machine; `ureq` is blocking (the
//! agent has no async runtime) and, with rustls, costs under a megabyte where
//! an SDK plus tokio would cost tens.

use std::io::Read;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::sigv4::{self, Credentials, SignRequest, EMPTY_SHA256, UNSIGNED_PAYLOAD};

#[derive(Debug)]
pub enum Error {
    /// Transport or TLS failure.
    Transport(String),
    /// S3 answered with a non-2xx status; `code` is the parsed `<Code>` when present.
    Status {
        status: u16,
        code: String,
        message: String,
    },
    Parse(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Transport(e) => write!(f, "transport: {e}"),
            Error::Status {
                status,
                code,
                message,
            } => {
                if code.is_empty() {
                    write!(f, "http {status}")
                } else {
                    write!(f, "http {status} {code}: {message}")
                }
            }
            Error::Parse(e) => write!(f, "parse: {e}"),
        }
    }
}
impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// How to reach one bucket.
#[derive(Clone, Debug)]
pub struct Config {
    /// e.g. `https://s3.us-east-1.amazonaws.com` or `http://127.0.0.1:9000`.
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    /// Optional key prefix so a mount can expose a sub-tree of a bucket.
    pub prefix: String,
    pub credentials: Option<Credentials>,
    /// Path-style addressing (`endpoint/bucket/key`). Required by MinIO and most
    /// S3-compatible servers; AWS accepts it too, so it is the default.
    pub path_style: bool,
    pub timeout: Duration,
}

/// One object as returned by a listing.
#[derive(Clone, Debug, PartialEq)]
pub struct ObjectInfo {
    /// Key relative to the mount prefix.
    pub key: String,
    pub size: u64,
    pub last_modified_secs: u64,
}

/// Result of listing one "directory" level.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Listing {
    pub objects: Vec<ObjectInfo>,
    /// Sub-prefixes, i.e. child directories (without the trailing `/`).
    pub prefixes: Vec<String>,
}

pub struct Client {
    cfg: Config,
    agent: ureq::Agent,
}

impl Client {
    pub fn new(cfg: Config) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(cfg.timeout)
            .user_agent(concat!("smolvm-s3fs/", env!("CARGO_PKG_VERSION")))
            .build();
        Self { cfg, agent }
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// Full key for a mount-relative path, applying the configured prefix.
    fn full_key(&self, rel: &str) -> String {
        let rel = rel.trim_start_matches('/');
        if self.cfg.prefix.is_empty() {
            rel.to_string()
        } else {
            format!("{}/{}", self.cfg.prefix.trim_matches('/'), rel)
        }
    }

    fn url_for(&self, key: &str) -> (String, String) {
        let enc = sigv4::uri_encode(key, false);
        if self.cfg.path_style {
            let path = format!("/{}/{}", self.cfg.bucket, enc);
            (
                format!("{}{}", self.cfg.endpoint.trim_end_matches('/'), path),
                path,
            )
        } else {
            let path = format!("/{enc}");
            let host = self
                .cfg
                .endpoint
                .trim_end_matches('/')
                .replace("://", &format!("://{}.", self.cfg.bucket));
            (format!("{host}{path}"), path)
        }
    }

    fn host_of(url: &str) -> String {
        url.split("://")
            .nth(1)
            .unwrap_or(url)
            .split('/')
            .next()
            .unwrap_or("")
            .to_string()
    }

    fn now() -> (String, String) {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        (format_date(secs), format_datetime(secs))
    }

    /// Build, sign and send. `body` is `None` for bodyless verbs.
    fn send(
        &self,
        method: &str,
        key: &str,
        query: &[(String, String)],
        mut headers: Vec<(String, String)>,
        body: Option<&[u8]>,
    ) -> Result<ureq::Response> {
        let (url, path) = self.url_for(key);
        headers.push(("host".into(), Self::host_of(&url)));

        let payload_hash = match (&self.cfg.credentials, body) {
            // Anonymous access needs no signature at all.
            (None, _) => String::new(),
            (Some(_), Some(b)) => sigv4::sha256_hex(b),
            (Some(_), None) => EMPTY_SHA256.to_string(),
        };

        if let Some(creds) = &self.cfg.credentials {
            let (d, t) = Self::now();
            sigv4::sign(
                SignRequest {
                    method,
                    path: &path,
                    query,
                    headers: &mut headers,
                    payload_sha256: if payload_hash.is_empty() {
                        UNSIGNED_PAYLOAD
                    } else {
                        &payload_hash
                    },
                },
                creds,
                &self.cfg.region,
                (&d, &t),
            );
        }

        let qs = query
            .iter()
            .map(|(k, v)| {
                format!(
                    "{}={}",
                    sigv4::uri_encode(k, true),
                    sigv4::uri_encode(v, true)
                )
            })
            .collect::<Vec<_>>()
            .join("&");
        let full = if qs.is_empty() {
            url
        } else {
            format!("{url}?{qs}")
        };

        let mut req = self.agent.request(method, &full);
        for (k, v) in &headers {
            // ureq sets Host itself from the URL; re-adding it breaks signing parity.
            if k.eq_ignore_ascii_case("host") {
                continue;
            }
            req = req.set(k, v);
        }

        let res = match body {
            Some(b) => req.send_bytes(b),
            None => req.call(),
        };
        match res {
            Ok(r) => Ok(r),
            Err(ureq::Error::Status(status, r)) => {
                let text = r.into_string().unwrap_or_default();
                let code = xml_field(&text, "Code").unwrap_or_default();
                let message = xml_field(&text, "Message").unwrap_or_default();
                Err(Error::Status {
                    status,
                    code,
                    message,
                })
            }
            Err(e) => Err(Error::Transport(e.to_string())),
        }
    }

    /// HEAD one object: size and mtime, or `Ok(None)` when absent.
    pub fn head(&self, rel: &str) -> Result<Option<ObjectInfo>> {
        let key = self.full_key(rel);
        match self.send("HEAD", &key, &[], Vec::new(), None) {
            Ok(r) => {
                let size = r
                    .header("content-length")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                let last_modified_secs = r
                    .header("last-modified")
                    .and_then(parse_http_date)
                    .unwrap_or(0);
                Ok(Some(ObjectInfo {
                    key: rel.to_string(),
                    size,
                    last_modified_secs,
                }))
            }
            Err(Error::Status { status: 404, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// GET an object, optionally a byte range (`start`, inclusive `end`).
    pub fn get(&self, rel: &str, range: Option<(u64, u64)>) -> Result<Vec<u8>> {
        let key = self.full_key(rel);
        let mut headers = Vec::new();
        if let Some((start, end)) = range {
            headers.push(("range".into(), format!("bytes={start}-{end}")));
        }
        let r = self.send("GET", &key, &[], headers, None)?;
        let mut buf = Vec::with_capacity(
            r.header("content-length")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
        );
        r.into_reader()
            .read_to_end(&mut buf)
            .map_err(|e| Error::Transport(e.to_string()))?;
        Ok(buf)
    }

    /// PUT a whole object.
    pub fn put(&self, rel: &str, body: &[u8]) -> Result<()> {
        let key = self.full_key(rel);
        let headers = vec![("content-length".into(), body.len().to_string())];
        self.send("PUT", &key, &[], headers, Some(body))?;
        Ok(())
    }

    pub fn delete(&self, rel: &str) -> Result<()> {
        let key = self.full_key(rel);
        match self.send("DELETE", &key, &[], Vec::new(), None) {
            Ok(_) => Ok(()),
            // Deleting something already gone is success for a filesystem.
            Err(Error::Status { status: 404, .. }) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// List one directory level under `rel` using a delimiter, so the result
    /// separates child objects from child "directories" the way readdir needs.
    pub fn list_dir(&self, rel: &str) -> Result<Listing> {
        let mut prefix = self.full_key(rel);
        if !prefix.is_empty() && !prefix.ends_with('/') {
            prefix.push('/');
        }
        let mut out = Listing::default();
        let mut token: Option<String> = None;
        loop {
            let mut query = vec![
                ("list-type".to_string(), "2".to_string()),
                ("delimiter".to_string(), "/".to_string()),
                ("max-keys".to_string(), "1000".to_string()),
            ];
            if !prefix.is_empty() {
                query.push(("prefix".to_string(), prefix.clone()));
            }
            if let Some(t) = &token {
                query.push(("continuation-token".to_string(), t.clone()));
            }
            // Listing addresses the bucket itself, not a key.
            let r = self.send("GET", "", &query, Vec::new(), None)?;
            let body = r
                .into_string()
                .map_err(|e| Error::Transport(e.to_string()))?;

            for c in xml_blocks(&body, "Contents") {
                let Some(key) = xml_field(&c, "Key") else {
                    continue;
                };
                if key == prefix {
                    continue; // the directory marker itself
                }
                let rel_key = key.strip_prefix(&prefix).unwrap_or(&key).to_string();
                if rel_key.is_empty() {
                    continue;
                }
                out.objects.push(ObjectInfo {
                    key: rel_key,
                    size: xml_field(&c, "Size")
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0),
                    last_modified_secs: xml_field(&c, "LastModified")
                        .and_then(|s| parse_iso8601(&s))
                        .unwrap_or(0),
                });
            }
            for p in xml_blocks(&body, "CommonPrefixes") {
                if let Some(pfx) = xml_field(&p, "Prefix") {
                    let name = pfx
                        .strip_prefix(&prefix)
                        .unwrap_or(&pfx)
                        .trim_end_matches('/')
                        .to_string();
                    if !name.is_empty() {
                        out.prefixes.push(name);
                    }
                }
            }

            match xml_field(&body, "NextContinuationToken") {
                Some(t) if xml_field(&body, "IsTruncated").as_deref() == Some("true") => {
                    token = Some(t)
                }
                _ => break,
            }
        }
        Ok(out)
    }
}

/// Extract the text of the first `<tag>…</tag>`.
///
/// A dependency-free reader rather than a full XML parser: S3's list/error
/// documents are flat and machine-generated, and a parser crate would cost more
/// than the ~20 lines it replaces.
pub(crate) fn xml_field(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(unescape(&xml[start..end]))
}

/// Every `<tag>…</tag>` block, for repeated elements.
pub(crate) fn xml_blocks(xml: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(s) = rest.find(&open) {
        let after = &rest[s + open.len()..];
        let Some(e) = after.find(&close) else { break };
        out.push(after[..e].to_string());
        rest = &after[e + close.len()..];
    }
    out
}

fn unescape(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

fn is_leap(y: u64) -> bool {
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}

fn days_in_month(y: u64, m: u64) -> u64 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(y) => 29,
        2 => 28,
        _ => 30,
    }
}

fn ymd_to_days(y: u64, m: u64, d: u64) -> u64 {
    let mut days = 0;
    for yy in 1970..y {
        days += if is_leap(yy) { 366 } else { 365 };
    }
    for mm in 1..m {
        days += days_in_month(y, mm);
    }
    days + d - 1
}

fn civil_from_days(mut days: u64) -> (u64, u64, u64) {
    let mut y = 1970;
    loop {
        let len = if is_leap(y) { 366 } else { 365 };
        if days < len {
            break;
        }
        days -= len;
        y += 1;
    }
    let mut m = 1;
    while days >= days_in_month(y, m) {
        days -= days_in_month(y, m);
        m += 1;
    }
    (y, m, days + 1)
}

/// `YYYYMMDD` in UTC, as SigV4's credential scope requires.
pub fn format_date(secs: u64) -> String {
    let (y, m, d) = civil_from_days(secs / 86400);
    format!("{y:04}{m:02}{d:02}")
}

/// `YYYYMMDDTHHMMSSZ` in UTC, as SigV4's `x-amz-date` requires.
pub fn format_datetime(secs: u64) -> String {
    let (y, m, d) = civil_from_days(secs / 86400);
    let rem = secs % 86400;
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// `2006-01-02T15:04:05.000Z` → epoch seconds (listing timestamps).
fn parse_iso8601(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 19 {
        return None;
    }
    let num = |r: std::ops::Range<usize>| s.get(r).and_then(|x| x.parse::<u64>().ok());
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    Some(ymd_to_days(y, mo, d) * 86400 + h * 3600 + mi * 60 + sec)
}

/// RFC 1123 (`Fri, 24 May 2013 00:00:00 GMT`) → epoch seconds (HEAD responses).
fn parse_http_date(s: &str) -> Option<u64> {
    let p: Vec<&str> = s.split_whitespace().collect();
    if p.len() < 5 {
        return None;
    }
    let d: u64 = p[1].parse().ok()?;
    let mo = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ]
    .iter()
    .position(|m| *m == p[2])? as u64
        + 1;
    let y: u64 = p[3].parse().ok()?;
    let t: Vec<&str> = p[4].split(':').collect();
    if t.len() != 3 {
        return None;
    }
    let h: u64 = t[0].parse().ok()?;
    let mi: u64 = t[1].parse().ok()?;
    let sec: u64 = t[2].parse().ok()?;
    Some(ymd_to_days(y, mo, d) * 86400 + h * 3600 + mi * 60 + sec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_listing_into_objects_and_child_directories() {
        let xml = r#"<?xml version="1.0"?><ListBucketResult>
          <Contents><Key>data/a.txt</Key><Size>12</Size><LastModified>2026-08-23T01:02:03.000Z</LastModified></Contents>
          <Contents><Key>data/b.bin</Key><Size>4096</Size><LastModified>2026-08-23T01:02:04.000Z</LastModified></Contents>
          <CommonPrefixes><Prefix>data/sub/</Prefix></CommonPrefixes>
          <IsTruncated>false</IsTruncated></ListBucketResult>"#;
        let objs: Vec<_> = xml_blocks(xml, "Contents")
            .iter()
            .filter_map(|c| xml_field(c, "Key"))
            .collect();
        assert_eq!(objs, vec!["data/a.txt", "data/b.bin"]);
        let pfx: Vec<_> = xml_blocks(xml, "CommonPrefixes")
            .iter()
            .filter_map(|p| xml_field(p, "Prefix"))
            .collect();
        assert_eq!(pfx, vec!["data/sub/"]);
    }

    #[test]
    fn parses_an_error_document() {
        let xml = "<Error><Code>NoSuchKey</Code><Message>The key does not exist</Message></Error>";
        assert_eq!(xml_field(xml, "Code").as_deref(), Some("NoSuchKey"));
        assert_eq!(
            xml_field(xml, "Message").as_deref(),
            Some("The key does not exist")
        );
    }

    // Dates feed SigV4's scope; a wrong day silently breaks every signature.
    #[test]
    fn formats_the_dates_sigv4_expects() {
        assert_eq!(format_date(1369353600), "20130524");
        assert_eq!(format_datetime(1369353600), "20130524T000000Z");
        assert_eq!(format_datetime(0), "19700101T000000Z");
    }

    #[test]
    fn round_trips_listing_and_http_timestamps() {
        assert_eq!(parse_iso8601("2013-05-24T00:00:00.000Z"), Some(1369353600));
        assert_eq!(
            parse_http_date("Fri, 24 May 2013 00:00:00 GMT"),
            Some(1369353600)
        );
        // A leap day, since the civil-date maths is hand-rolled.
        assert_eq!(parse_iso8601("2024-02-29T12:00:00.000Z"), Some(1709208000));
    }

    #[test]
    fn unescapes_xml_entities_in_keys() {
        assert_eq!(
            xml_field("<Key>a&amp;b</Key>", "Key").as_deref(),
            Some("a&b")
        );
    }
}
