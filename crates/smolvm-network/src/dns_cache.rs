//! A small DNS answer cache for the gateway's upstream resolver.
//!
//! Every guest lookup used to cost one upstream round trip, and a burst of
//! concurrent lookups (128 gRPC dials resolving one service name) became 256
//! simultaneous upstream queries. One lost datagram among them left a client
//! waiting for its own retry timer: exactly 5 s for glibc and Go.
//!
//! This cache sits *behind* the egress policy: a query reaches it only after
//! the allow-host filter and the egress watchlist have passed it, every time,
//! so a cached answer can never resolve a name the policy does not allow. It
//! holds only what the upstream answered, for no longer than the answer's own
//! TTL (capped), and it lives in the VMM process: a restored checkpoint, a
//! branch or a fork starts with an empty cache.
//!
//! Only plain recursive queries are cached: one question, opcode QUERY, no
//! answer/authority records, at most one EDNS OPT record. The key is the
//! lowercased question plus the bits that change an answer (RD, CD, EDNS, DO),
//! and the upstreams that answer it. Positive answers live for the smallest TTL of
//! their records, NXDOMAIN and NODATA answers for their SOA's negative TTL, and
//! nothing else (SERVFAIL, REFUSED, truncated) is kept. A served answer carries
//! the asking query's id and question bytes, and TTLs reduced by its age.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const HEADER_LEN: usize = 12;
const FLAG_QR: u16 = 0x8000;
const FLAG_TC: u16 = 0x0200;
const FLAG_RD: u16 = 0x0100;
const FLAG_CD: u16 = 0x0010;
const OPCODE_MASK: u16 = 0x7800;
const RCODE_MASK: u16 = 0x000f;
const RCODE_NOERROR: u16 = 0;
const RCODE_NXDOMAIN: u16 = 3;
const TYPE_SOA: u16 = 6;
const TYPE_OPT: u16 = 41;
const EDNS_DO: u32 = 0x8000;
const RR_FIXED_LEN: usize = 10;
const MAX_JUMPS: usize = 32;

/// Longest a positive answer is kept, whatever its TTL says.
pub const MAX_POSITIVE_TTL: Duration = Duration::from_secs(300);
/// Longest a negative (NXDOMAIN / NODATA) answer is kept.
pub const MAX_NEGATIVE_TTL: Duration = Duration::from_secs(60);
/// Entries kept at most; the oldest go first once it is reached.
pub const MAX_ENTRIES: usize = 4096;
/// Largest answer worth keeping.
const MAX_ANSWER_LEN: usize = 4096;

/// What identifies a cacheable query.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CacheKey {
    /// The upstreams that answer it, in order.
    upstreams: Vec<SocketAddr>,
    /// Lowercased question name in wire form, then QTYPE and QCLASS.
    question: Vec<u8>,
    /// RD, CD, EDNS present, DO.
    flags: u8,
}

/// A query the cache understands.
#[derive(Clone, Debug)]
pub struct Query {
    pub key: CacheKey,
    id: u16,
    /// The question section exactly as the guest sent it.
    question_wire: Vec<u8>,
}

impl Query {
    /// Parse a guest query for `upstreams`. `None` when it is not a plain
    /// cacheable query; such queries are forwarded as they are.
    pub fn parse(packet: &[u8], upstreams: &[SocketAddr]) -> Option<Self> {
        if packet.len() < HEADER_LEN {
            return None;
        }
        let flags = u16::from_be_bytes([packet[2], packet[3]]);
        if flags & FLAG_QR != 0 || flags & OPCODE_MASK != 0 {
            return None;
        }
        let (qd, an, ns, ar) = counts(packet);
        if qd != 1 || an != 0 || ns != 0 || ar > 1 {
            return None;
        }
        let name_end = skip_uncompressed_name(packet, HEADER_LEN)?;
        let question_end = name_end.checked_add(4)?;
        if question_end > packet.len() {
            return None;
        }
        let mut question = packet[HEADER_LEN..question_end].to_vec();
        lowercase_name(&mut question[..name_end - HEADER_LEN]);
        let mut key_flags = 0u8;
        if flags & FLAG_RD != 0 {
            key_flags |= 1;
        }
        if flags & FLAG_CD != 0 {
            key_flags |= 2;
        }
        if ar == 1 {
            // The one additional record must be EDNS OPT at the end.
            let (rtype, ttl, end) = parse_rr(packet, question_end)?;
            if rtype != TYPE_OPT || end != packet.len() {
                return None;
            }
            key_flags |= 4;
            if ttl & EDNS_DO != 0 {
                key_flags |= 8;
            }
        } else if question_end != packet.len() {
            return None;
        }
        Some(Self {
            key: CacheKey {
                upstreams: upstreams.to_vec(),
                question,
                flags: key_flags,
            },
            id: u16::from_be_bytes([packet[0], packet[1]]),
            question_wire: packet[HEADER_LEN..question_end].to_vec(),
        })
    }

    /// `answer` rewritten for this query: its id and its question bytes (the
    /// same name, possibly in different case, so offsets are unchanged).
    pub fn adopt(&self, answer: &[u8]) -> Option<Vec<u8>> {
        let end = HEADER_LEN + self.question_wire.len();
        if answer.len() < end {
            return None;
        }
        let mut out = answer.to_vec();
        out[..2].copy_from_slice(&self.id.to_be_bytes());
        out[HEADER_LEN..end].copy_from_slice(&self.question_wire);
        Some(out)
    }

    /// Whether `answer` is a response to this query's question.
    pub fn answered_by(&self, answer: &[u8]) -> bool {
        let end = HEADER_LEN + self.question_wire.len();
        if answer.len() < end || answer[..2] != self.id.to_be_bytes()[..] {
            return false;
        }
        let flags = u16::from_be_bytes([answer[2], answer[3]]);
        if flags & FLAG_QR == 0 || counts(answer).0 != 1 {
            return false;
        }
        let mut question = answer[HEADER_LEN..end].to_vec();
        let name_len = self.key.question.len() - 4;
        lowercase_name(&mut question[..name_len]);
        question == self.key.question
    }
}

struct Entry {
    answer: Vec<u8>,
    stored: Instant,
    ttl: Duration,
    /// Offsets of every TTL field to age when the answer is served.
    ttl_offsets: Vec<usize>,
}

/// The cache itself. Not thread-safe; owned by the DNS relay thread.
#[derive(Default)]
pub struct DnsCache {
    entries: HashMap<CacheKey, Entry>,
    hits: u64,
    misses: u64,
}

impl DnsCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// A cached answer for `query`, adjusted for it, if one is still fresh.
    pub fn get(&mut self, query: &Query, now: Instant) -> Option<Vec<u8>> {
        let Some(entry) = self.entries.get(&query.key) else {
            self.misses += 1;
            return None;
        };
        let age = now.saturating_duration_since(entry.stored);
        if age >= entry.ttl {
            self.entries.remove(&query.key);
            self.misses += 1;
            return None;
        }
        let mut out = query.adopt(&entry.answer)?;
        let age_secs = age.as_secs() as u32;
        for &offset in &entry.ttl_offsets {
            let ttl = u32::from_be_bytes(out[offset..offset + 4].try_into().ok()?);
            out[offset..offset + 4].copy_from_slice(&ttl.saturating_sub(age_secs).to_be_bytes());
        }
        self.hits += 1;
        Some(out)
    }

    /// Keep `answer` for `query` if it is a cacheable response to it.
    pub fn insert(&mut self, query: &Query, answer: &[u8], now: Instant) {
        if !query.answered_by(answer) {
            return;
        }
        let Some((ttl, ttl_offsets)) = cache_lifetime(answer) else {
            return;
        };
        if self.entries.len() >= MAX_ENTRIES && !self.entries.contains_key(&query.key) {
            self.entries
                .retain(|_, e| now.saturating_duration_since(e.stored) < e.ttl);
            if self.entries.len() >= MAX_ENTRIES {
                if let Some(oldest) = self
                    .entries
                    .iter()
                    .min_by_key(|(_, e)| e.stored)
                    .map(|(k, _)| k.clone())
                {
                    self.entries.remove(&oldest);
                }
            }
        }
        self.entries.insert(
            query.key.clone(),
            Entry {
                answer: answer.to_vec(),
                stored: now,
                ttl,
                ttl_offsets,
            },
        );
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Lookups answered from the cache and lookups that were not.
    pub fn stats(&self) -> (u64, u64) {
        (self.hits, self.misses)
    }
}

/// How long `answer` may be kept, and where its TTL fields are. `None` when it
/// must not be kept.
fn cache_lifetime(answer: &[u8]) -> Option<(Duration, Vec<usize>)> {
    if answer.len() > MAX_ANSWER_LEN || answer.len() < HEADER_LEN {
        return None;
    }
    let flags = u16::from_be_bytes([answer[2], answer[3]]);
    if flags & FLAG_TC != 0 {
        return None;
    }
    let rcode = flags & RCODE_MASK;
    if rcode != RCODE_NOERROR && rcode != RCODE_NXDOMAIN {
        return None;
    }
    let (qd, an, ns, ar) = counts(answer);
    let mut offset = HEADER_LEN;
    for _ in 0..qd {
        offset = skip_name(answer, offset)?.checked_add(4)?;
    }
    let mut ttl_offsets = Vec::new();
    let mut answer_min: Option<u32> = None;
    let mut negative: Option<u32> = None;
    for section in 0..3 {
        let count = [an, ns, ar][section];
        for _ in 0..count {
            let name_end = skip_name(answer, offset)?;
            let (rtype, ttl, end) = parse_rr(answer, offset)?;
            if rtype != TYPE_OPT {
                ttl_offsets.push(name_end + 4);
                match section {
                    0 => answer_min = Some(answer_min.map_or(ttl, |m| m.min(ttl))),
                    1 if rtype == TYPE_SOA && end >= name_end + RR_FIXED_LEN + 4 => {
                        // RFC 2308: the negative TTL is the smaller of the
                        // SOA's own TTL and its MINIMUM field (the last four
                        // bytes of its data).
                        let minimum =
                            u32::from_be_bytes(answer.get(end - 4..end)?.try_into().ok()?);
                        negative = Some(ttl.min(minimum));
                    }
                    _ => {}
                }
            }
            offset = end;
        }
    }
    if offset != answer.len() {
        return None;
    }
    let ttl = if rcode == RCODE_NOERROR && an > 0 {
        Duration::from_secs(u64::from(answer_min?)).min(MAX_POSITIVE_TTL)
    } else {
        Duration::from_secs(u64::from(negative?)).min(MAX_NEGATIVE_TTL)
    };
    (!ttl.is_zero()).then_some((ttl, ttl_offsets))
}

fn counts(packet: &[u8]) -> (u16, u16, u16, u16) {
    let at = |i: usize| u16::from_be_bytes([packet[i], packet[i + 1]]);
    (at(4), at(6), at(8), at(10))
}

/// End of the (possibly compressed) name starting at `offset`.
fn skip_name(packet: &[u8], mut offset: usize) -> Option<usize> {
    for _ in 0..=MAX_JUMPS * 8 {
        let len = *packet.get(offset)?;
        match len & 0xc0 {
            0x00 if len == 0 => return Some(offset + 1),
            0x00 => offset = offset.checked_add(1 + usize::from(len))?,
            0xc0 => {
                packet.get(offset + 1)?;
                return Some(offset + 2);
            }
            _ => return None,
        }
    }
    None
}

/// End of an uncompressed name (queries carry no pointers).
fn skip_uncompressed_name(packet: &[u8], mut offset: usize) -> Option<usize> {
    let mut total = 0usize;
    loop {
        let len = usize::from(*packet.get(offset)?);
        if len == 0 {
            return Some(offset + 1);
        }
        if len > 63 {
            return None;
        }
        total += len + 1;
        if total > 255 {
            return None;
        }
        offset += 1 + len;
    }
}

/// Lowercase the label bytes of an uncompressed wire name in place.
fn lowercase_name(name: &mut [u8]) {
    let mut i = 0;
    while i < name.len() {
        let len = usize::from(name[i]);
        if len == 0 {
            break;
        }
        let end = (i + 1 + len).min(name.len());
        name[i + 1..end].make_ascii_lowercase();
        i = end;
    }
}

/// One resource record at `offset`: its type, TTL and end.
fn parse_rr(packet: &[u8], offset: usize) -> Option<(u16, u32, usize)> {
    let fixed = skip_name(packet, offset)?;
    let header = packet.get(fixed..fixed + RR_FIXED_LEN)?;
    let rtype = u16::from_be_bytes([header[0], header[1]]);
    let ttl = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
    let rdlen = usize::from(u16::from_be_bytes([header[8], header[9]]));
    let end = fixed.checked_add(RR_FIXED_LEN)?.checked_add(rdlen)?;
    (end <= packet.len()).then_some((rtype, ttl, end))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    const UP: &[SocketAddr] = &[SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53)];

    fn name(n: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in n.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    pub(crate) fn query(id: u16, n: &str, qtype: u16, edns: bool) -> Vec<u8> {
        let mut q = vec![0u8; 12];
        q[..2].copy_from_slice(&id.to_be_bytes());
        q[2] = 0x01; // RD
        q[5] = 1;
        q[11] = u8::from(edns);
        q.extend(name(n));
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        if edns {
            q.extend_from_slice(&[0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0]);
        }
        q
    }

    /// A response to `q` with one A record per `(ttl, ip)` pair, compressed
    /// against the question.
    pub(crate) fn answer(q: &[u8], records: &[(u32, [u8; 4])]) -> Vec<u8> {
        let qend = 12 + skip_uncompressed_name(q, 12).unwrap() - 12 + 4;
        let mut a = q[..qend].to_vec();
        a[2] |= 0x80;
        a[3] = 0x80;
        a[6..8].copy_from_slice(&(records.len() as u16).to_be_bytes());
        a[10..12].copy_from_slice(&0u16.to_be_bytes());
        for (ttl, ip) in records {
            a.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1]);
            a.extend_from_slice(&ttl.to_be_bytes());
            a.extend_from_slice(&[0, 4]);
            a.extend_from_slice(ip);
        }
        a
    }

    fn nxdomain(q: &[u8], soa_ttl: u32, minimum: u32) -> Vec<u8> {
        let qend = skip_uncompressed_name(q, 12).unwrap() + 4;
        let mut a = q[..qend].to_vec();
        a[2] |= 0x80;
        a[3] = 0x80 | 3;
        a[8..10].copy_from_slice(&1u16.to_be_bytes());
        a[10..12].copy_from_slice(&0u16.to_be_bytes());
        // SOA owned by the root, minimal MNAME/RNAME.
        a.extend_from_slice(&[0, 0, 6, 0, 1]);
        a.extend_from_slice(&soa_ttl.to_be_bytes());
        let rdata = [0u8, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4];
        a.extend_from_slice(&((rdata.len() + 4) as u16).to_be_bytes());
        a.extend_from_slice(&rdata);
        a.extend_from_slice(&minimum.to_be_bytes());
        a
    }

    fn ttls(a: &[u8]) -> Vec<u32> {
        cache_lifetime(a)
            .unwrap()
            .1
            .iter()
            .map(|&o| u32::from_be_bytes(a[o..o + 4].try_into().unwrap()))
            .collect()
    }

    #[test]
    fn a_repeated_name_is_answered_from_the_cache_with_the_askers_id() {
        let t0 = Instant::now();
        let mut cache = DnsCache::new();
        let q1 = query(0x1111, "api.example.com", 1, false);
        let p1 = Query::parse(&q1, UP).unwrap();
        assert!(cache.get(&p1, t0).is_none());
        cache.insert(&p1, &answer(&q1, &[(120, [10, 0, 0, 1])]), t0);

        let q2 = query(0x2222, "API.Example.com", 1, false);
        let p2 = Query::parse(&q2, UP).unwrap();
        let hit = cache.get(&p2, t0 + Duration::from_secs(20)).unwrap();
        assert_eq!(&hit[..2], &[0x22, 0x22]);
        // The question comes back exactly as the second guest asked it.
        assert_eq!(&hit[12..12 + p2.question_wire.len()], &p2.question_wire[..]);
        assert_eq!(ttls(&hit), vec![100]);
        assert_eq!(cache.stats(), (1, 1));
    }

    #[test]
    fn an_answer_expires_with_its_smallest_ttl() {
        let t0 = Instant::now();
        let mut cache = DnsCache::new();
        let q = query(1, "a.example", 1, false);
        let p = Query::parse(&q, UP).unwrap();
        cache.insert(
            &p,
            &answer(&q, &[(30, [1, 2, 3, 4]), (10, [1, 2, 3, 5])]),
            t0,
        );
        assert!(cache.get(&p, t0 + Duration::from_secs(9)).is_some());
        assert!(cache.get(&p, t0 + Duration::from_secs(10)).is_none());
        assert!(cache.is_empty());
    }

    #[test]
    fn long_ttls_are_capped() {
        let t0 = Instant::now();
        let mut cache = DnsCache::new();
        let q = query(1, "a.example", 1, false);
        let p = Query::parse(&q, UP).unwrap();
        cache.insert(&p, &answer(&q, &[(86400, [1, 2, 3, 4])]), t0);
        assert!(cache
            .get(&p, t0 + MAX_POSITIVE_TTL - Duration::from_secs(1))
            .is_some());
        assert!(cache.get(&p, t0 + MAX_POSITIVE_TTL).is_none());
    }

    #[test]
    fn nxdomain_lives_for_the_soa_negative_ttl() {
        let t0 = Instant::now();
        let mut cache = DnsCache::new();
        let q = query(1, "nope.example", 1, false);
        let p = Query::parse(&q, UP).unwrap();
        cache.insert(&p, &nxdomain(&q, 900, 20), t0);
        assert!(cache.get(&p, t0 + Duration::from_secs(19)).is_some());
        assert!(cache.get(&p, t0 + Duration::from_secs(20)).is_none());
    }

    #[test]
    fn failures_truncation_and_zero_ttls_are_not_kept() {
        let t0 = Instant::now();
        let mut cache = DnsCache::new();
        let q = query(1, "a.example", 1, false);
        let p = Query::parse(&q, UP).unwrap();
        let mut servfail = answer(&q, &[]);
        servfail[3] |= 2;
        cache.insert(&p, &servfail, t0);
        let mut truncated = answer(&q, &[(60, [1, 1, 1, 1])]);
        truncated[2] |= 0x02;
        cache.insert(&p, &truncated, t0);
        cache.insert(&p, &answer(&q, &[(0, [1, 1, 1, 1])]), t0);
        // NODATA without an SOA has no negative TTL.
        cache.insert(&p, &answer(&q, &[]), t0);
        assert!(cache.is_empty());
    }

    #[test]
    fn the_key_separates_types_upstreams_and_edns() {
        let t0 = Instant::now();
        let mut cache = DnsCache::new();
        let q = query(1, "a.example", 1, false);
        let p = Query::parse(&q, UP).unwrap();
        cache.insert(&p, &answer(&q, &[(60, [1, 1, 1, 1])]), t0);
        let aaaa = Query::parse(&query(2, "a.example", 28, false), UP).unwrap();
        let edns = Query::parse(&query(3, "a.example", 1, true), UP).unwrap();
        let eight = [SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53)];
        let other = Query::parse(&query(4, "a.example", 1, false), &eight).unwrap();
        for miss in [aaaa, edns, other] {
            assert!(cache.get(&miss, t0).is_none());
        }
    }

    #[test]
    fn an_answer_to_another_question_is_not_kept() {
        let t0 = Instant::now();
        let mut cache = DnsCache::new();
        let q = query(1, "a.example", 1, false);
        let p = Query::parse(&q, UP).unwrap();
        let other = query(1, "b.example", 1, false);
        cache.insert(&p, &answer(&other, &[(60, [1, 1, 1, 1])]), t0);
        let wrong_id = answer(&query(9, "a.example", 1, false), &[(60, [1, 1, 1, 1])]);
        cache.insert(&p, &wrong_id, t0);
        assert!(cache.is_empty());
    }

    #[test]
    fn only_plain_queries_are_cacheable() {
        let mut two_questions = query(1, "a.example", 1, false);
        two_questions[5] = 2;
        assert!(Query::parse(&two_questions, UP).is_none());
        let mut notify = query(1, "a.example", 1, false);
        notify[2] |= 0x20; // opcode 4
        assert!(Query::parse(&notify, UP).is_none());
        let mut trailing = query(1, "a.example", 1, false);
        trailing.push(0);
        assert!(Query::parse(&trailing, UP).is_none());
        assert!(Query::parse(&[0u8; 5], UP).is_none());
        let a = answer(&query(1, "a.example", 1, false), &[(1, [0; 4])]);
        assert!(Query::parse(&a, UP).is_none());
        assert!(Query::parse(&query(1, "a.example", 1, true), UP).is_some());
    }

    #[test]
    fn the_cache_stays_bounded() {
        let t0 = Instant::now();
        let mut cache = DnsCache::new();
        for i in 0..MAX_ENTRIES + 10 {
            let q = query(1, &format!("h{i}.example"), 1, false);
            let p = Query::parse(&q, UP).unwrap();
            cache.insert(
                &p,
                &answer(&q, &[(60, [1, 1, 1, 1])]),
                t0 + Duration::from_millis(i as u64),
            );
        }
        assert_eq!(cache.len(), MAX_ENTRIES);
        let first = Query::parse(&query(1, "h0.example", 1, false), UP).unwrap();
        assert!(
            cache.get(&first, t0).is_none(),
            "the oldest entry went first"
        );
    }

    #[test]
    fn malformed_answers_are_ignored() {
        let q = query(1, "a.example", 1, false);
        let a = answer(&q, &[(60, [1, 1, 1, 1])]);
        for cut in 12..a.len() {
            assert!(cache_lifetime(&a[..cut]).is_none(), "cut at {cut}");
        }
        let mut looped = a.clone();
        let at = looped.len() - 16;
        looped[at] = 0xc0;
        looped[at + 1] = at as u8;
        let _ = cache_lifetime(&looped);
    }
}
