//! An operator-supplied egress watchlist: destinations to flag, or to block.
//!
//! The list holds SHA-256 digests, never names or addresses, so a copy of the
//! file (or this source) does not reveal what is watched. A guest DNS question
//! matches a `dns-sha256` entry when the digest of the queried name, or of any
//! of its parent domains, is listed; an outbound destination matches an
//! `ip-sha256` entry when the digest of its address's canonical text is listed.
//! A match records a signal; unless its line says `block`, the egress policy
//! still decides the traffic.
//!
//! File format, one entry per line, `#` comments and blank lines ignored:
//!
//! ```text
//! <label> dns-sha256:<64 lowercase hex> [block]
//! <label> ip-sha256:<64 lowercase hex> [block]
//! ```
//!
//! A line may end in `block`: a matching lookup is then answered as
//! nonexistent and a matching connection or datagram is dropped, as well as
//! recorded. The guest sees an ordinary failure, not a policy refusal.
//!
//! `label` is 1 to 32 of `[a-z0-9_-]` and is what a match reports, so it should
//! be opaque. Names are hashed lowercased with any trailing dot removed
//! (`sha256("watched.example")`); addresses as Rust prints them (`192.0.2.7`,
//! `2001:db8::7`), with no port.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use sha2::{Digest, Sha256};

/// Filename of the per-VM copy of the watchlist, in the VM's data directory.
/// `smolvm serve --egress-watchlist` writes it before boot and rewrites it when
/// the source changes; the network runtime reloads it when its mtime moves.
pub const EGRESS_WATCHLIST_FILE: &str = "egress-watchlist";

/// The most entries a list may hold, so a bad file can't exhaust memory.
const MAX_ENTRIES: usize = 1_000_000;

/// How often the runtime checks its copy of the list for a change.
const RELOAD_CHECK_INTERVAL: Duration = Duration::from_secs(30);

/// How long a repeated match on the same label and destination stays quiet,
/// so a workload hitting a watched destination at packet rate writes one line.
const REPEAT_QUIET: Duration = Duration::from_secs(60);

/// Distinct matches remembered for `REPEAT_QUIET`; cleared past this size.
const MAX_REMEMBERED_MATCHES: usize = 4096;

type Digest32 = [u8; 32];

/// A parsed watchlist: digests of names and of addresses, each with its label.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Watchlist {
    dns: HashMap<Digest32, Entry>,
    ip: HashMap<Digest32, Entry>,
}

/// What one line of the list says to do with a match.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    label: String,
    /// Refuse the lookup or connection as well as recording it.
    block: bool,
}

/// Why a watchlist file was refused, with the 1-based line it failed on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchlistError {
    pub line: usize,
    pub reason: String,
}

impl std::fmt::Display for WatchlistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "line {}: {}", self.line, self.reason)
    }
}

impl std::error::Error for WatchlistError {}

fn digest(text: &str) -> Digest32 {
    Sha256::digest(text.as_bytes()).into()
}

fn parse_digest(hex: &str) -> Option<Digest32> {
    if hex.len() != 64 || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn valid_label(label: &str) -> bool {
    (1..=32).contains(&label.len())
        && label
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'))
}

impl Watchlist {
    /// Parse a watchlist, refusing the whole file at the first bad line so a
    /// typo never silently drops entries.
    pub fn parse(text: &str) -> Result<Self, WatchlistError> {
        let mut list = Watchlist::default();
        for (index, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let err = |reason: &str| WatchlistError {
                line: index + 1,
                reason: reason.to_string(),
            };
            let mut fields = line.split_whitespace();
            let (Some(label), Some(entry), action, None) =
                (fields.next(), fields.next(), fields.next(), fields.next())
            else {
                return Err(err("expected `<label> <kind>:<sha256> [block]`"));
            };
            let block = match action {
                None => false,
                Some("block") => true,
                Some(_) => return Err(err("the only action is `block`")),
            };
            if !valid_label(label) {
                return Err(err("label must be 1 to 32 of [a-z0-9_-]"));
            }
            let (kind, hex) = entry
                .split_once(':')
                .ok_or_else(|| err("expected `<kind>:<sha256>`"))?;
            let digest = parse_digest(hex)
                .ok_or_else(|| err("digest must be 64 lowercase hex characters"))?;
            let table = match kind {
                "dns-sha256" => &mut list.dns,
                "ip-sha256" => &mut list.ip,
                _ => return Err(err("kind must be dns-sha256 or ip-sha256")),
            };
            table.insert(
                digest,
                Entry {
                    label: label.to_string(),
                    block,
                },
            );
            if list.dns.len() + list.ip.len() > MAX_ENTRIES {
                return Err(err("too many entries"));
            }
        }
        Ok(list)
    }

    /// Read and parse a watchlist file.
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Self::parse(&text).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    pub fn is_empty(&self) -> bool {
        self.dns.is_empty() && self.ip.is_empty()
    }

    /// The label of the entry `name` (as asked in a DNS question) matches: the
    /// name itself or any parent domain, most specific first.
    pub fn match_dns(&self, name: &str) -> Option<&str> {
        self.entry_dns(name).map(|entry| entry.label.as_str())
    }

    fn entry_dns(&self, name: &str) -> Option<&Entry> {
        if self.dns.is_empty() {
            return None;
        }
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        let mut rest = name.as_str();
        loop {
            if rest.is_empty() {
                return None;
            }
            if let Some(entry) = self.dns.get(&digest(rest)) {
                return Some(entry);
            }
            rest = rest.split_once('.')?.1;
        }
    }

    /// The label of the entry `ip` matches, by the digest of its canonical text.
    pub fn match_ip(&self, ip: IpAddr) -> Option<&str> {
        self.entry_ip(ip).map(|entry| entry.label.as_str())
    }

    fn entry_ip(&self, ip: IpAddr) -> Option<&Entry> {
        if self.ip.is_empty() {
            return None;
        }
        self.ip.get(&digest(&ip.to_string()))
    }
}

/// What the watchlist says about one lookup or destination.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Verdict {
    /// The label to record, unless the same match was recorded within the last minute.
    pub record: Option<String>,
    /// Refuse it: answer the lookup as nonexistent, or drop the connection.
    pub block: bool,
}

/// A VM's live view of its watchlist copy: reloaded when the file changes, and
/// remembering recent matches so a repeated one is recorded once per minute.
pub struct WatchlistSource {
    path: PathBuf,
    state: Mutex<SourceState>,
}

struct SourceState {
    list: Arc<Watchlist>,
    modified: Option<SystemTime>,
    checked: Instant,
    recent: HashMap<(String, String), Instant>,
}

impl WatchlistSource {
    /// Open the VM's copy at `path`, or `None` when there is none (the feature
    /// is off for this VM) or it does not parse.
    pub fn open(path: PathBuf) -> Option<Arc<Self>> {
        let modified = std::fs::metadata(&path).and_then(|m| m.modified()).ok()?;
        let list = match Watchlist::load(&path) {
            Ok(list) => list,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "egress watchlist not loaded");
                return None;
            }
        };
        Some(Arc::new(Self {
            path,
            state: Mutex::new(SourceState {
                list: Arc::new(list),
                modified: Some(modified),
                checked: Instant::now(),
                recent: HashMap::new(),
            }),
        }))
    }

    /// The current list, reloading it first when the copy changed on disk. A
    /// copy that stops parsing keeps the last good list.
    fn current(&self, state: &mut SourceState) -> Arc<Watchlist> {
        if state.checked.elapsed() >= RELOAD_CHECK_INTERVAL {
            state.checked = Instant::now();
            let modified = std::fs::metadata(&self.path)
                .and_then(|m| m.modified())
                .ok();
            if modified != state.modified {
                state.modified = modified;
                match Watchlist::load(&self.path) {
                    Ok(list) => state.list = Arc::new(list),
                    Err(e) => tracing::warn!(
                        path = %self.path.display(),
                        error = %e,
                        "egress watchlist reload failed; keeping the previous list"
                    ),
                }
            }
        }
        Arc::clone(&state.list)
    }

    /// What a match means for `dest`: the label to record, `None` when nothing
    /// matched or the same label and destination were recorded within the last
    /// minute, and whether to refuse it. Refusal never goes quiet.
    fn record_once(
        &self,
        matched: impl FnOnce(&Watchlist) -> Option<Entry>,
        dest: &str,
    ) -> Verdict {
        let Ok(mut state) = self.state.lock() else {
            return Verdict::default();
        };
        let list = self.current(&mut state);
        let Some(entry) = matched(&list) else {
            return Verdict::default();
        };
        let key = (entry.label.clone(), dest.to_string());
        let now = Instant::now();
        let quiet = state
            .recent
            .get(&key)
            .is_some_and(|at| now.duration_since(*at) < REPEAT_QUIET);
        if !quiet {
            if state.recent.len() >= MAX_REMEMBERED_MATCHES {
                state.recent.clear();
            }
            state.recent.insert(key, now);
        }
        Verdict {
            record: (!quiet).then_some(entry.label),
            block: entry.block,
        }
    }

    /// What the list says about a DNS question for `name`.
    pub fn observe_dns(&self, name: &str) -> Verdict {
        self.record_once(|list| list.entry_dns(name).cloned(), name)
    }

    /// What the list says about an outbound destination.
    pub fn observe_ip(&self, ip: IpAddr, dest: &str) -> Verdict {
        self.record_once(|list| list.entry_ip(ip).cloned(), dest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> String {
        digest(text).iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn a_name_matches_itself_or_any_parent_domain_case_insensitively() {
        let list =
            Watchlist::parse(&format!("w1 dns-sha256:{}\n", hex("watched.example"))).unwrap();
        assert_eq!(list.match_dns("watched.example"), Some("w1"));
        assert_eq!(list.match_dns("a.b.WATCHED.example."), Some("w1"));
        assert_eq!(list.match_dns("notwatched.example"), None);
        assert_eq!(list.match_dns("example"), None);
        assert_eq!(list.match_dns(""), None);
    }

    #[test]
    fn an_address_matches_by_its_canonical_text() {
        let list = Watchlist::parse(&format!(
            "# comment\n\nw2 ip-sha256:{}\nw3 ip-sha256:{}\n",
            hex("192.0.2.7"),
            hex("2001:db8::7")
        ))
        .unwrap();
        assert_eq!(list.match_ip("192.0.2.7".parse().unwrap()), Some("w2"));
        assert_eq!(
            list.match_ip("2001:0db8:0:0::7".parse().unwrap()),
            Some("w3")
        );
        assert_eq!(list.match_ip("192.0.2.8".parse().unwrap()), None);
    }

    #[test]
    fn a_bad_line_refuses_the_whole_file_naming_the_line() {
        for (text, line) in [
            ("w1 dns-sha256:zz\n", 1),
            ("\nUPPER dns-sha256:00\n", 2),
            ("w1 md5:0000\n", 1),
            ("w1\n", 1),
            ("w1 dns-sha256:x y\n", 1),
        ] {
            assert_eq!(Watchlist::parse(text).unwrap_err().line, line, "{text:?}");
        }
        let wrong_kind = format!("w1 url-sha256:{}\n", hex("x"));
        assert!(Watchlist::parse(&wrong_kind).is_err());
    }

    #[test]
    fn a_repeated_match_is_recorded_once_and_a_changed_file_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(EGRESS_WATCHLIST_FILE);
        std::fs::write(&path, format!("w1 dns-sha256:{}\n", hex("watched.example"))).unwrap();
        let source = WatchlistSource::open(path.clone()).unwrap();
        assert_eq!(
            source.observe_dns("watched.example").record.as_deref(),
            Some("w1")
        );
        assert_eq!(
            source.observe_dns("watched.example").record,
            None,
            "quiet on repeat"
        );
        assert_eq!(source.observe_dns("other.example"), Verdict::default());

        std::fs::write(&path, format!("w9 dns-sha256:{}\n", hex("other.example"))).unwrap();
        let mtime = SystemTime::now() + Duration::from_secs(5);
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(mtime)
            .unwrap();
        source.state.lock().unwrap().checked = Instant::now() - RELOAD_CHECK_INTERVAL;
        assert_eq!(
            source.observe_dns("other.example").record.as_deref(),
            Some("w9")
        );
    }

    /// A `block` entry refuses every match, including the repeats it no longer
    /// records; an entry without it only records.
    #[test]
    fn a_block_entry_refuses_each_match_and_records_it_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(EGRESS_WATCHLIST_FILE);
        std::fs::write(
            &path,
            format!(
                "b1 dns-sha256:{} block\nw1 dns-sha256:{}\nb2 ip-sha256:{} block\n",
                hex("blocked.example"),
                hex("watched.example"),
                hex("192.0.2.9"),
            ),
        )
        .unwrap();
        let source = WatchlistSource::open(path).unwrap();
        let first = source.observe_dns("pool.blocked.example");
        assert_eq!((first.record.as_deref(), first.block), (Some("b1"), true));
        let repeat = source.observe_dns("pool.blocked.example");
        assert_eq!(
            (repeat.record, repeat.block),
            (None, true),
            "refused even when quiet"
        );
        let flagged = source.observe_dns("watched.example");
        assert_eq!(
            (flagged.record.as_deref(), flagged.block),
            (Some("w1"), false)
        );
        assert!(
            source
                .observe_ip("192.0.2.9".parse().unwrap(), "192.0.2.9:443")
                .block
        );
        assert!(
            !source
                .observe_ip("192.0.2.10".parse().unwrap(), "192.0.2.10:443")
                .block
        );
    }

    #[test]
    fn an_unknown_action_refuses_the_file() {
        let line = format!("b1 dns-sha256:{} drop\n", hex("x.example"));
        assert_eq!(Watchlist::parse(&line).unwrap_err().line, 1);
    }

    #[test]
    fn no_copy_means_no_source() {
        let dir = tempfile::tempdir().unwrap();
        assert!(WatchlistSource::open(dir.path().join(EGRESS_WATCHLIST_FILE)).is_none());
    }
}
