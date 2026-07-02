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

/// How much of the platform hard-floor applies, chosen once per policy from the
/// deployment context — NOT a default-on blanket deny. Reaching the host's own
/// LAN from a local VM is legitimate and expected, so the broad internal-subnet
/// floor is reserved for the multi-tenant context where it's actually needed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum FloorMode {
    /// Trusted single-tenant/local override (`SMOLVM_EGRESS_ALLOW_PRIVATE=1`):
    /// floor nothing — the guest reaches exactly what the host can.
    Off,
    /// Local default: deny ONLY the cloud-metadata link-local range
    /// (`169.254.0.0/16`, incl. `169.254.169.254`) — never a legitimate
    /// destination and the canonical SSRF/credential-theft target, but still
    /// protects users running on their own cloud VM. The guest keeps reaching the
    /// host's LAN, loopback, etc., so local behavior is reasonable and clear.
    MetadataOnly,
    /// Multi-tenant/fleet (`SMOLVM_PUBLISH_ADDR` set): the full floor — metadata,
    /// host/control internal subnets, loopback, link/unique-local, and the
    /// gateway CGNAT range — so a guest can't steal host credentials, pivot to
    /// the control plane / worker API, or reach co-resident tenants.
    Strict,
}

/// Resolve the floor from the deployment context. Read once at policy creation
/// (never per-packet): explicit local override wins, else fleet ⇒ strict, else
/// the metadata-only local default.
/// Parse an explicit `SMOLVM_EGRESS_FLOOR` value into a mode. Returns `None`
/// for an absent/unrecognized value so the caller falls back to the inferred
/// default. Pure (no env) so it is unit-testable.
fn parse_floor_override(v: &str) -> Option<FloorMode> {
    match v.trim().to_ascii_lowercase().as_str() {
        "strict" => Some(FloorMode::Strict),
        "metadata" | "metadata-only" | "metadataonly" => Some(FloorMode::MetadataOnly),
        "off" | "none" => Some(FloorMode::Off),
        _ => None,
    }
}

fn floor_mode() -> FloorMode {
    // Explicit override wins (highest precedence). A multi-tenant node sets
    // `SMOLVM_EGRESS_FLOOR=strict` so the floor is fail-closed and never
    // silently degrades to metadata-only if `SMOLVM_PUBLISH_ADDR` is missing
    // from the environment (a dropped unit override, a new provisioner, or a
    // manual launch must NOT quietly expose the host LAN / control plane /
    // co-tenants to a guest). `metadata`/`off` allow a deliberate downgrade.
    if let Ok(v) = std::env::var("SMOLVM_EGRESS_FLOOR") {
        if let Some(mode) = parse_floor_override(&v) {
            return mode;
        }
    }
    let allow_private = std::env::var("SMOLVM_EGRESS_ALLOW_PRIVATE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if allow_private {
        FloorMode::Off
    } else if std::env::var_os("SMOLVM_PUBLISH_ADDR").is_some() {
        FloorMode::Strict
    } else {
        FloorMode::MetadataOnly
    }
}

/// The cloud-metadata link-local range (`169.254.0.0/16` / `fe80::/10`) — the
/// one destination floored in every mode except `Off`, including via an
/// IPv4-mapped IPv6 address so it can't be smuggled past.
fn is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => {
            (v6.segments()[0] & 0xffc0) == 0xfe80
                || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_link_local())
        }
    }
}

/// The full multi-tenant IPv4 floor (metadata + internal + loopback + CGNAT).
fn is_reserved_v4(v4: Ipv4Addr) -> bool {
    v4.is_loopback()        // 127.0.0.0/8
        || v4.is_link_local() // 169.254.0.0/16 — incl. 169.254.169.254 (cloud metadata)
        || v4.is_private()    // 10/8, 172.16/12, 192.168/16 — host/control internal subnet
        || v4.is_unspecified()
        || v4.is_broadcast()
        // 100.64.0.0/10 (CGNAT) — the gateway's own guest/gateway addresses live here.
        || matches!(v4.octets(), [100, b, ..] if (64..=127).contains(&b))
}

/// Whether `ip` is floored under `mode` — the single hard-floor predicate. Also
/// defeats DNS-rebinding (a learned IP in a floored range is still denied).
fn is_floored(ip: IpAddr, mode: FloorMode) -> bool {
    match mode {
        FloorMode::Off => false,
        FloorMode::MetadataOnly => is_link_local(ip),
        FloorMode::Strict => match ip {
            IpAddr::V4(v4) => is_reserved_v4(v4),
            IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6.is_unspecified()
                    || (v6.segments()[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
                    || (v6.segments()[0] & 0xfe00) == 0xfc00 // fc00::/7 unique-local
                    || v6.to_ipv4_mapped().is_some_and(is_reserved_v4)
            }
        },
    }
}

/// Outbound egress policy enforced by the gateway before opening a host
/// connection. `unrestricted` allows everything EXCEPT the platform hard-floor
/// (`is_floored`), whose scope is set once by `FloorMode`.
#[derive(Clone)]
pub struct EgressPolicy {
    inner: Option<Arc<AllowList>>,
    /// Hard-floor scope, resolved once from the deployment context at creation.
    floor: FloorMode,
}

impl EgressPolicy {
    /// No allow-list — every destination is allowed EXCEPT the platform hard-floor.
    pub fn unrestricted() -> Self {
        Self {
            inner: None,
            floor: floor_mode(),
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
            floor: floor_mode(),
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
        // Platform hard-floor: deny per the resolved FloorMode (metadata-only
        // locally, full floor under fleet mode) regardless of the allow-list.
        if is_floored(ip, self.floor) {
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
    fn floor_override_parsing() {
        assert_eq!(parse_floor_override("strict"), Some(FloorMode::Strict));
        assert_eq!(parse_floor_override("  STRICT "), Some(FloorMode::Strict));
        assert_eq!(
            parse_floor_override("metadata"),
            Some(FloorMode::MetadataOnly)
        );
        assert_eq!(
            parse_floor_override("metadata-only"),
            Some(FloorMode::MetadataOnly)
        );
        assert_eq!(parse_floor_override("off"), Some(FloorMode::Off));
        assert_eq!(parse_floor_override("none"), Some(FloorMode::Off));
        // Unrecognized falls through to the inferred default (None).
        assert_eq!(parse_floor_override(""), None);
        assert_eq!(parse_floor_override("yes"), None);
    }

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
    fn unrestricted_local_floors_only_metadata() {
        // Local default (no fleet mode): only the cloud-metadata link-local range
        // is denied; the host's LAN, loopback, and CGNAT stay reachable — so a
        // local VM behaves predictably.
        let p = EgressPolicy::unrestricted();
        assert!(!p.allows_v4(Ipv4Addr::new(169, 254, 169, 254))); // metadata: denied
        assert!(p.allows_v4(Ipv4Addr::new(10, 0, 0, 4))); // LAN: reachable
        assert!(p.allows_v4(Ipv4Addr::new(127, 0, 0, 1))); // loopback: reachable
        assert!(p.allows_v4(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(p.allows_v4(Ipv4Addr::new(172, 16, 0, 1)));
        assert!(p.allows_v4(Ipv4Addr::new(100, 96, 0, 1))); // CGNAT: reachable
        assert!(p.allows_v4(Ipv4Addr::new(1, 1, 1, 1))); // public: reachable
    }

    #[test]
    fn metadata_floor_overrides_allowlist_and_learned_ips() {
        // The metadata range can't be re-opened by allow-listing it...
        let p = EgressPolicy::new(Some(&["169.254.0.0/16".into()]), None);
        assert!(!p.allows_v4(Ipv4Addr::new(169, 254, 169, 254)));
        // ...nor via DNS-rebinding: a learned metadata IP stays denied.
        let p2 = EgressPolicy::new(None, Some(&["evil.test".into()]));
        let meta = IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254));
        p2.learn_ip_records(&[(meta, 300)]);
        assert!(!p2.allows(meta));
        // But a LAN IP in the allow-list IS reachable locally.
        let p3 = EgressPolicy::new(Some(&["10.0.0.0/8".into()]), None);
        assert!(p3.allows_v4(Ipv4Addr::new(10, 0, 0, 4)));
    }

    #[test]
    fn metadata_floor_blocks_mapped_and_v6_link_local() {
        let p = EgressPolicy::unrestricted(); // MetadataOnly default
                                              // mapped metadata + v6 link-local are denied...
        assert!(!p.allows_v6("::ffff:169.254.169.254".parse().unwrap()));
        assert!(!p.allows_v6("fe80::1".parse().unwrap()));
        // ...but v6 ULA (the LAN equivalent) and global unicast are reachable.
        assert!(p.allows_v6("fc00::1".parse().unwrap()));
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

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn floor_off_blocks_nothing() {
        // Trusted override: even metadata/loopback/private pass.
        for ip in [
            v4(8, 8, 8, 8),
            v4(169, 254, 169, 254),
            v4(192, 168, 1, 5),
            v4(127, 0, 0, 1),
        ] {
            assert!(
                !is_floored(ip, FloorMode::Off),
                "{ip} should not be floored when Off"
            );
        }
    }

    #[test]
    fn floor_metadata_only_blocks_just_link_local() {
        // Local default: only the cloud-metadata link-local range is denied; the
        // host's LAN, loopback and the public internet stay reachable.
        assert!(is_floored(v4(169, 254, 169, 254), FloorMode::MetadataOnly));
        assert!(is_floored(v4(169, 254, 0, 1), FloorMode::MetadataOnly));
        for ip in [
            v4(8, 8, 8, 8),
            v4(192, 168, 1, 5),
            v4(10, 0, 0, 7),
            v4(127, 0, 0, 1),
            v4(172, 16, 5, 5),
        ] {
            assert!(
                !is_floored(ip, FloorMode::MetadataOnly),
                "{ip} should be reachable locally"
            );
        }
        // IPv4-mapped metadata must not slip past.
        assert!(is_floored(
            "::ffff:169.254.169.254".parse().unwrap(),
            FloorMode::MetadataOnly
        ));
    }

    #[test]
    fn floor_strict_blocks_internal_and_metadata() {
        // Fleet/multi-tenant: the full floor.
        for ip in [
            v4(169, 254, 169, 254), // metadata
            v4(192, 168, 1, 5),     // RFC1918
            v4(10, 0, 0, 7),
            v4(172, 16, 5, 5),
            v4(127, 0, 0, 1),  // loopback
            v4(100, 64, 0, 1), // CGNAT gateway range
        ] {
            assert!(
                is_floored(ip, FloorMode::Strict),
                "{ip} should be floored under Strict"
            );
        }
        // Public + just-outside-CGNAT stay reachable.
        assert!(!is_floored(v4(8, 8, 8, 8), FloorMode::Strict));
        assert!(!is_floored(v4(100, 128, 0, 1), FloorMode::Strict));
        // IPv6 internal ranges + mapped private.
        assert!(is_floored("fe80::1".parse().unwrap(), FloorMode::Strict));
        assert!(is_floored("fc00::1".parse().unwrap(), FloorMode::Strict));
        assert!(is_floored(
            "::ffff:10.0.0.1".parse().unwrap(),
            FloorMode::Strict
        ));
        assert!(!is_floored(
            "2606:4700::1111".parse().unwrap(),
            FloorMode::Strict
        ));
    }
}
