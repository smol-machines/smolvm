//! Outbound egress policy for the virtio-net gateway.
//!
//! TSI enforces `allowed_cidrs` + `--allow-host` inside libkrun's socket-intercept
//! layer; the virtio-net gateway terminates every guest flow itself, so it applies
//! the same allow-list at the point it opens a host connection
//! (`TcpRelayTable::create_tcp_socket`). This mirrors libkrun's `vsock/dns_filter.rs`
//! `EgressPolicy` so both backends behave identically:
//!
//! - static `allowed_cidrs` (IPv4 or IPv6) are always permitted;
//! - `--allow-host` names are matched by the gateway's DNS interception, and the
//!   A/AAAA records of allowed answers are *learned* as temporarily-allowed IPs
//!   (TTL clamped to [60s, 3600s]) so the follow-up connection passes;
//! - with hosts set but no CIDRs, egress is gated entirely by learned IPs.
//!
//! Disallowed destinations are dropped before any host socket is created. DNS
//! forwarding (gateway-internal) is never gated by this filter.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::dns;

/// Learned-IP TTL clamp, matching libkrun's DNS filter.
const MIN_LEARNED_TTL: u64 = 60;
const MAX_LEARNED_TTL: u64 = 3600;

/// A parsed CIDR (IPv4 or IPv6) with cheap containment testing.
#[derive(Clone, Copy, Debug)]
enum Cidr {
    V4 { network: u32, mask: u32 },
    V6 { network: u128, mask: u128 },
}

impl Cidr {
    /// Parse `"a.b.c.d"` / `"a.b.c.d/n"` / `"x::y"` / `"x::y/n"`. A bare address
    /// gets a full-length prefix. Returns `None` for malformed input or a prefix
    /// length beyond the address width.
    fn parse(spec: &str) -> Option<Self> {
        let (addr, prefix) = match spec.trim().split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix.parse::<u8>().ok()?)),
            None => (spec.trim(), None),
        };
        match addr.parse::<IpAddr>().ok()? {
            IpAddr::V4(ip) => {
                let prefix = prefix.unwrap_or(32);
                if prefix > 32 {
                    return None;
                }
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                Some(Self::V4 {
                    network: u32::from(ip) & mask,
                    mask,
                })
            }
            IpAddr::V6(ip) => {
                let prefix = prefix.unwrap_or(128);
                if prefix > 128 {
                    return None;
                }
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                Some(Self::V6 {
                    network: u128::from(ip) & mask,
                    mask,
                })
            }
        }
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Self::V4 { network, mask }, IpAddr::V4(ip)) => (u32::from(ip) & mask) == *network,
            (Self::V6 { network, mask }, IpAddr::V6(ip)) => (u128::from(ip) & mask) == *network,
            _ => false,
        }
    }
}

struct AllowList {
    cidrs: Vec<Cidr>,
    /// Normalized allow-host names. `None` = no DNS hostname filtering.
    allowed_hosts: Option<Vec<String>>,
    /// IPs learned from allowed DNS answers → expiry instant.
    learned: Mutex<HashMap<IpAddr, Instant>>,
}

/// Whether the platform hard-floor is disabled (trusted single-tenant / local
/// dev). Default false: link-local/metadata/private/loopback are always denied.
fn allow_private_egress() -> bool {
    std::env::var("SMOLVM_EGRESS_ALLOW_PRIVATE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// IPv4 destinations the gateway must NEVER relay to (platform hard-floor).
fn is_reserved_v4(v4: Ipv4Addr) -> bool {
    v4.is_loopback()        // 127.0.0.0/8
        || v4.is_link_local() // 169.254.0.0/16 — incl. 169.254.169.254 (cloud metadata)
        || v4.is_private()    // 10/8, 172.16/12, 192.168/16 — host/control internal subnet
        || v4.is_unspecified()
        || v4.is_broadcast()
        // 100.64.0.0/10 (CGNAT) — the gateway's own guest/gateway addresses live here.
        || matches!(v4.octets(), [100, b, ..] if (64..=127).contains(&b))
}

/// Destinations the gateway must NEVER relay a guest connection to, regardless
/// of the tenant allow-list — the platform's hard floor. Blocks the cloud
/// metadata server, the host/control internal subnets, loopback, and the
/// gateway's own CGNAT range, so a guest cannot steal host credentials, pivot to
/// the control plane / worker node API, or reach co-resident tenants over the
/// internal network. Also defeats DNS-rebinding (a learned IP in these ranges is
/// still denied). Override only for trusted single-tenant/local use with
/// `SMOLVM_EGRESS_ALLOW_PRIVATE=1`.
fn is_reserved_destination(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_reserved_v4(v4),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // fc00::/7 unique-local
                // IPv4-mapped (::ffff:a.b.c.d) must not bypass the v4 floor.
                || v6.to_ipv4_mapped().is_some_and(is_reserved_v4)
        }
    }
}

/// Outbound egress policy enforced by the gateway before opening a host
/// connection. `unrestricted` allows everything EXCEPT the platform hard-floor
/// (`is_reserved_destination`), unless `allow_private` is set.
#[derive(Clone)]
pub struct EgressPolicy {
    inner: Option<Arc<AllowList>>,
    /// When false (default), the hard-floor denies metadata/internal/loopback
    /// regardless of the allow-list. Set via `SMOLVM_EGRESS_ALLOW_PRIVATE=1`.
    allow_private: bool,
}

impl EgressPolicy {
    /// No allow-list — every destination is allowed EXCEPT the platform hard-floor.
    pub fn unrestricted() -> Self {
        Self {
            inner: None,
            allow_private: allow_private_egress(),
        }
    }

    /// Build from `VmResources::allowed_cidrs` and the `--allow-host` list.
    /// Both `None` → unrestricted. Otherwise a policy is in force: only the
    /// listed CIDRs and IPs learned from allowed DNS answers may be reached
    /// (an empty CIDR list with no hosts denies everything).
    pub fn new(allowed_cidrs: Option<&[String]>, allowed_hosts: Option<&[String]>) -> Self {
        if allowed_cidrs.is_none() && allowed_hosts.is_none() {
            return Self::unrestricted();
        }
        let cidrs = allowed_cidrs
            .unwrap_or(&[])
            .iter()
            .filter_map(|spec| {
                let parsed = Cidr::parse(spec);
                if parsed.is_none() {
                    tracing::warn!(cidr = %spec, "ignoring unparseable egress CIDR");
                }
                parsed
            })
            .collect();
        let allowed_hosts = allowed_hosts.map(|hosts| {
            hosts
                .iter()
                .filter_map(|h| dns::normalize_hostname(h))
                .collect()
        });
        Self {
            inner: Some(Arc::new(AllowList {
                cidrs,
                allowed_hosts,
                learned: Mutex::new(HashMap::new()),
            })),
            allow_private: allow_private_egress(),
        }
    }

    /// Convenience for the CIDR-only case.
    pub fn from_allowed_cidrs(allowed: Option<&[String]>) -> Self {
        Self::new(allowed, None)
    }

    /// Whether any policy is in force (false = allow-all).
    pub fn is_restricted(&self) -> bool {
        self.inner.is_some()
    }

    /// Whether the gateway should DNS-filter queries (an allow-host list is set).
    pub fn dns_filter_active(&self) -> bool {
        self.inner
            .as_ref()
            .is_some_and(|list| list.allowed_hosts.is_some())
    }

    /// Whether a DNS query for `hostname` should be forwarded upstream. With no
    /// allow-host list, all queries pass (exact + subdomain match otherwise).
    pub fn hostname_allowed(&self, hostname: &str) -> bool {
        match &self.inner {
            None => true,
            Some(list) => match &list.allowed_hosts {
                None => true,
                Some(hosts) => dns::hostname_allowed(hostname, hosts),
            },
        }
    }

    /// Whether an outbound connection to `ip` (v4 or v6) is permitted.
    pub fn allows(&self, ip: IpAddr) -> bool {
        // Platform hard-floor: metadata/internal/loopback are denied regardless
        // of the allow-list (and even when unrestricted), unless explicitly
        // overridden for trusted single-tenant/local use.
        if !self.allow_private && is_reserved_destination(ip) {
            return false;
        }
        match &self.inner {
            None => true,
            Some(list) => {
                if list.cidrs.iter().any(|cidr| cidr.contains(ip)) {
                    return true;
                }
                list.learned
                    .lock()
                    .map(|learned| {
                        learned
                            .get(&ip)
                            .is_some_and(|expires_at| *expires_at > Instant::now())
                    })
                    .unwrap_or(false)
            }
        }
    }

    /// Convenience for IPv4 call sites.
    pub fn allows_v4(&self, ip: Ipv4Addr) -> bool {
        self.allows(IpAddr::V4(ip))
    }

    /// Convenience for IPv6 call sites.
    pub fn allows_v6(&self, ip: Ipv6Addr) -> bool {
        self.allows(IpAddr::V6(ip))
    }

    /// Learn the A/AAAA records of an allowed DNS answer as temporarily-allowed
    /// IPs. TTLs are clamped to [60s, 3600s]; expired entries are pruned. No-op
    /// when unrestricted.
    pub fn learn_ip_records(&self, records: &[(IpAddr, u32)]) {
        let Some(list) = &self.inner else {
            return;
        };
        let Ok(mut learned) = list.learned.lock() else {
            return;
        };
        let now = Instant::now();
        learned.retain(|_, expires_at| *expires_at > now);
        for (ip, ttl) in records {
            let ttl = u64::from(*ttl).clamp(MIN_LEARNED_TTL, MAX_LEARNED_TTL);
            let expires_at = now + Duration::from_secs(ttl);
            learned
                .entry(*ip)
                .and_modify(|existing| *existing = (*existing).max(expires_at))
                .or_insert(expires_at);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unrestricted_allows_everything() {
        let policy = EgressPolicy::unrestricted();
        assert!(!policy.is_restricted());
        assert!(policy.allows_v4(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(policy.allows_v6("2001:4860:4860::8888".parse().unwrap()));
        assert!(policy.hostname_allowed("anything.test"));
        assert!(!policy.dns_filter_active());
    }

    #[test]
    fn empty_allowlist_denies_all() {
        let policy = EgressPolicy::from_allowed_cidrs(Some(&[]));
        assert!(policy.is_restricted());
        assert!(!policy.allows_v4(Ipv4Addr::new(1, 1, 1, 1)));
        assert!(!policy.allows_v6("2606:4700::1111".parse().unwrap()));
    }

    #[test]
    fn cidr_membership_v4() {
        // Public CIDRs only — private ranges are denied by the hard-floor below.
        let policy = EgressPolicy::new(Some(&["8.8.8.0/24".into(), "1.1.1.1".into()]), None);
        assert!(policy.allows_v4(Ipv4Addr::new(8, 8, 8, 7)));
        assert!(policy.allows_v4(Ipv4Addr::new(1, 1, 1, 1)));
        assert!(!policy.allows_v4(Ipv4Addr::new(1, 1, 1, 2)));
        assert!(!policy.allows_v4(Ipv4Addr::new(9, 0, 0, 1)));
    }

    #[test]
    fn hard_floor_denies_metadata_internal_loopback_even_unrestricted() {
        let p = EgressPolicy::unrestricted();
        // The exact things the live probe reached.
        assert!(!p.allows_v4(Ipv4Addr::new(169, 254, 169, 254))); // cloud metadata
        assert!(!p.allows_v4(Ipv4Addr::new(10, 0, 0, 4))); // worker/control internal
        assert!(!p.allows_v4(Ipv4Addr::new(127, 0, 0, 1))); // loopback
        assert!(!p.allows_v4(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!p.allows_v4(Ipv4Addr::new(172, 16, 0, 1)));
        assert!(!p.allows_v4(Ipv4Addr::new(100, 96, 0, 1))); // gateway CGNAT
                                                             // Public internet still flows.
        assert!(p.allows_v4(Ipv4Addr::new(1, 1, 1, 1)));
        assert!(p.allows_v4(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn hard_floor_overrides_allowlist_and_learned_ips() {
        // A tenant cannot re-open the floor by allow-listing a private range...
        let p = EgressPolicy::new(Some(&["10.0.0.0/8".into()]), None);
        assert!(!p.allows_v4(Ipv4Addr::new(10, 0, 0, 4)));
        // ...nor via DNS-rebinding: a learned internal IP stays denied.
        let p2 = EgressPolicy::new(None, Some(&["evil.test".into()]));
        let meta = IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254));
        p2.learn_ip_records(&[(meta, 300)]);
        assert!(!p2.allows(meta));
    }

    #[test]
    fn hard_floor_blocks_ipv4_mapped_v6_bypass() {
        let p = EgressPolicy::unrestricted();
        let mapped: Ipv6Addr = "::ffff:169.254.169.254".parse().unwrap();
        assert!(!p.allows_v6(mapped));
        // v6 link-local / ULA also denied.
        assert!(!p.allows_v6("fe80::1".parse().unwrap()));
        assert!(!p.allows_v6("fc00::1".parse().unwrap()));
        // global unicast v6 allowed.
        assert!(p.allows_v6("2606:4700::1111".parse().unwrap()));
    }

    #[test]
    fn cidr_membership_v6() {
        let policy =
            EgressPolicy::new(Some(&["2606:4700::/32".into(), "2001:db8::1".into()]), None);
        assert!(policy.allows_v6("2606:4700::1111".parse().unwrap()));
        assert!(policy.allows_v6("2606:4700:ffff::1".parse().unwrap()));
        assert!(policy.allows_v6("2001:db8::1".parse().unwrap()));
        assert!(!policy.allows_v6("2001:db8::2".parse().unwrap()));
        assert!(!policy.allows_v6("2607::1".parse().unwrap()));
        // A v6 CIDR never matches a v4 address and vice versa.
        assert!(!policy.allows_v4(Ipv4Addr::new(1, 1, 1, 1)));
    }

    #[test]
    fn allow_host_gates_dns_and_learns_ips() {
        let policy = EgressPolicy::new(None, Some(&["example.com".into()]));
        assert!(policy.dns_filter_active());
        assert!(policy.hostname_allowed("example.com"));
        assert!(policy.hostname_allowed("www.example.com"));
        assert!(!policy.hostname_allowed("evil.test"));

        let v4 = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let v6: IpAddr = "2606:2800:21f:cb07:6820:80da:af6b:8b2c"
            .parse::<Ipv6Addr>()
            .unwrap()
            .into();
        assert!(!policy.allows(v4));
        assert!(!policy.allows(v6));
        policy.learn_ip_records(&[(v4, 300), (v6, 600)]);
        assert!(policy.allows(v4));
        assert!(policy.allows(v6));
    }

    #[test]
    fn learned_ip_respects_min_ttl() {
        // A tiny TTL is clamped up to MIN_LEARNED_TTL, so the entry is live now.
        let policy = EgressPolicy::new(None, Some(&["example.com".into()]));
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        policy.learn_ip_records(&[(ip, 1)]);
        assert!(policy.allows(ip));
    }

    #[test]
    fn unparseable_cidr_is_skipped_not_panicked() {
        let policy = EgressPolicy::new(Some(&["nonsense".into(), "1.1.1.1".into()]), None);
        assert!(policy.allows_v4(Ipv4Addr::new(1, 1, 1, 1)));
        assert!(!policy.allows_v4(Ipv4Addr::new(2, 2, 2, 2)));
    }

    #[test]
    fn v6_prefix_bounds_checked() {
        assert!(Cidr::parse("2001:db8::/129").is_none());
        assert!(Cidr::parse("1.2.3.4/33").is_none());
        assert!(Cidr::parse("::/0").is_some());
        assert!(Cidr::parse("0.0.0.0/0").is_some());
    }
}
