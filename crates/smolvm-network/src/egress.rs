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
use crate::policy::{DnsDecision, Policy};
use crate::virtio_net_log;

/// Learned-IP TTL clamp, matching libkrun's DNS filter.
const MIN_LEARNED_TTL: u64 = 60;
const MAX_LEARNED_TTL: u64 = 3600;

/// A parsed CIDR (IPv4 or IPv6) with cheap containment testing.
#[derive(Clone, Copy, Debug)]
pub enum Cidr {
    V4 { network: u32, mask: u32 },
    V6 { network: u128, mask: u128 },
}

impl Cidr {
    /// Parse `"a.b.c.d"` / `"a.b.c.d/n"` / `"x::y"` / `"x::y/n"`. A bare address
    /// gets a full-length prefix. Returns `None` for malformed input or a prefix
    /// length beyond the address width.
    pub fn parse(spec: &str) -> Option<Self> {
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

    pub fn contains(&self, ip: IpAddr) -> bool {
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
pub enum FloorMode {
    /// Trusted single-tenant/local override (`SMOLVM_EGRESS_ALLOW_PRIVATE=1`):
    /// floor nothing — the guest reaches exactly what the host can.
    Off,
    /// Loopback-permitted local mode (`SMOLVM_ALLOW_HOST_LOOPBACK=1`, e.g. the
    /// `--allow-host-loopback` CLI flag): deny ONLY the cloud-metadata link-local
    /// range, leaving the host's own loopback reachable so a developer can hit a
    /// service on their host's `127.0.0.1` from the sandbox on purpose.
    MetadataOnly,
    /// Local DEFAULT: deny the cloud-metadata link-local range
    /// (`169.254.0.0/16`, incl. `169.254.169.254`) AND the host's own loopback
    /// (`127.0.0.0/8`, `::1`, `0.0.0.0`/`::`). A guest reaching `127.0.0.1`
    /// means "myself", but the gateway would forward it to the HOST's loopback —
    /// a confused-deputy path onto host debuggers, Docker, and local databases.
    /// The host's LAN stays reachable (legitimate local dev), and an explicit
    /// allow-list entry can also re-open loopback (see [`EgressPolicy::allows`]).
    MetadataAndLoopback,
    /// Multi-tenant/fleet (`SMOLVM_PUBLISH_ADDR` set): the full floor — metadata,
    /// host/control internal subnets, loopback, link/unique-local, and the
    /// gateway CGNAT range — so a guest can't steal host credentials, pivot to
    /// the control plane / worker API, or reach co-resident tenants.
    Strict,
}

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

/// Resolve the floor from the deployment context. Read once at policy creation
/// (never per-packet): explicit `SMOLVM_EGRESS_FLOOR` override wins, else the
/// `ALLOW_PRIVATE` opt-out, else fleet ⇒ strict, else the metadata-only default.
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
        return FloorMode::Off;
    }
    // Fleet mode is absolute: no env flag relaxes Strict once
    // `SMOLVM_PUBLISH_ADDR` is set, so host loopback / control-plane doors stay
    // shut on a multi-tenant node.
    if std::env::var_os("SMOLVM_PUBLISH_ADDR").is_some() {
        return FloorMode::Strict;
    }
    // Fork default: inverted vs upstream — this fork keeps host loopback
    // reachable locally (the loopback-forwarding feature relies on it), so
    // `MetadataOnly` is the default and `SMOLVM_ALLOW_HOST_LOOPBACK=0` opts
    // into upstream's hardened `MetadataAndLoopback` floor. Fleet mode above
    // is unaffected.
    let allow_host_loopback = std::env::var("SMOLVM_ALLOW_HOST_LOOPBACK")
        .map(|v| !(v == "0" || v.eq_ignore_ascii_case("false")))
        .unwrap_or(true);
    if allow_host_loopback {
        FloorMode::MetadataOnly
    } else {
        FloorMode::MetadataAndLoopback
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

/// The host's own loopback / unspecified addresses — what `127.0.0.1` and `::1`
/// mean to the guest, but which the gateway forwards to the HOST. Floored in
/// every mode except `Off`; re-openable in the local modes only by an explicit
/// static allow-list entry (never a learned DNS IP, so it can't be reached by
/// rebinding). Covers the IPv4-mapped IPv6 form so it can't be smuggled past.
fn is_host_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_unspecified(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| v4.is_loopback() || v4.is_unspecified())
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
        // 224.0.0.0/4 — host LAN segment the floor exists to block
        || v4.is_multicast()
        // 100.64.0.0/10 (CGNAT) — the gateway's own guest/gateway addresses live here.
        || matches!(v4.octets(), [100, b, ..] if (64..=127).contains(&b))
}

/// Whether `ip` is floored under `mode` — the single hard-floor predicate. Also
/// defeats DNS-rebinding (a learned IP in a floored range is still denied).
pub fn is_floored(ip: IpAddr, mode: FloorMode) -> bool {
    match mode {
        FloorMode::Off => false,
        FloorMode::MetadataOnly => is_link_local(ip),
        FloorMode::MetadataAndLoopback => is_link_local(ip) || is_host_loopback(ip),
        FloorMode::Strict => match ip {
            IpAddr::V4(v4) => is_reserved_v4(v4),
            IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6.is_unspecified()
                    || v6.is_multicast() // ff00::/8, incl. ff02::1 — see is_reserved_v4
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
    /// Audit sink for denials. When set, every denied connect/sendto/resolve is
    /// appended here in addition to the runtime's stderr line, so the record
    /// can't be evicted by ordinary connection chatter in the boot log.
    denial_log: Option<Arc<std::path::PathBuf>>,
}

impl EgressPolicy {
    /// No allow-list — every destination is allowed EXCEPT the platform hard-floor.
    pub fn unrestricted() -> Self {
        Self {
            inner: None,
            floor: floor_mode(),
            denial_log: None,
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
            denial_log: None,
        }
    }

    /// Attach the audit sink denials are appended to. The launcher points this
    /// at the machine's data dir so the host can read denials back.
    pub fn with_denial_log(mut self, path: std::path::PathBuf) -> Self {
        self.denial_log = Some(Arc::new(path));
        self
    }

    /// Record one denial: a stderr line for anyone tailing the boot log, and —
    /// when a sink is attached — an appended line in the dedicated audit file,
    /// which connection chatter can never evict. Keep the marker text stable:
    /// the host's `read_egress_denials` parses `egress policy denied <op> <dest>`.
    ///
    /// The sink rotates once past 8 MiB (`.1` suffix) so a workload hammering a
    /// denied destination at packet rate can't fill the host disk.
    pub fn record_denial(&self, operation: &str, dest: &dyn std::fmt::Display) {
        crate::virtio_net_log!("egress policy denied {} {}", operation, dest);
        let Some(path) = self.denial_log.as_deref() else {
            return;
        };
        const ROTATE_BYTES: u64 = 8 * 1024 * 1024;
        if std::fs::metadata(path).is_ok_and(|m| m.len() > ROTATE_BYTES) {
            let _ = std::fs::rename(path, path.with_extension("log.1"));
        }
        use std::io::Write;
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = writeln!(
                file,
                "{}",
                crate::format_network_log_line(
                    std::time::SystemTime::now(),
                    &format!("egress policy denied {operation} {dest}"),
                )
            );
        }
    }

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
        // Platform hard-floor: deny per the resolved FloorMode (metadata + host
        // loopback locally, the full internal floor under fleet mode). The floor
        // is absolute under `Strict`; in the softer local modes an EXPLICIT
        // static allow-list CIDR (`--allow-cidr`, `--outbound-localhost-only`)
        // may deliberately re-open a floored destination — e.g. reaching a dev
        // server on the host's 127.0.0.1. A learned DNS IP never qualifies, so
        // the floor still defeats DNS rebinding.
        if is_floored(ip, self.floor) {
            // Only host loopback, floored by the local default, may be
            // deliberately re-opened by an explicit static CIDR. Cloud-metadata
            // (link-local) and — under Strict — the internal ranges stay
            // absolute: no allow-list entry can re-expose the credential door.
            if self.floor != FloorMode::Strict && is_host_loopback(ip) {
                return self
                    .inner
                    .as_ref()
                    .is_some_and(|list| list.cidrs.iter().any(|cidr| cidr.contains(ip)));
            }
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

/// The gateway's built-in policy, portless and address-scoped — a consumer
/// with different grants implements [`Policy`] itself.
impl Policy for EgressPolicy {
    fn allows(&self, ip: IpAddr, _port: Option<u16>) -> bool {
        EgressPolicy::allows(self, ip)
    }

    fn dns(&self, query: &[u8]) -> DnsDecision {
        if !self.dns_filter_active() {
            return DnsDecision::Forward { learn: false };
        }
        match dns::question_name(query) {
            Some(name) if self.hostname_allowed(&name) => DnsDecision::Forward { learn: true },
            Some(name) => {
                virtio_net_log!(
                    "virtio-net: blocking DNS query by allow-host policy name={}",
                    name
                );
                // Standardized marker for the egress audit trail (`read_egress_denials`).
                self.record_denial("resolve", &name);
                DnsDecision::Immediate(dns::error_response(query, dns::DNS_RCODE_NXDOMAIN))
            }
            None => DnsDecision::Immediate(dns::error_response(query, dns::DNS_RCODE_SERVFAIL)),
        }
    }

    fn learn(&self, answer: &[u8]) {
        self.learn_ip_records(&dns::answer_ip_records(answer));
    }

    fn denied(&self, operation: &str, dest: &dyn std::fmt::Display) {
        self.record_denial(operation, dest);
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
        // Local default (no fleet mode): only the cloud-metadata link-local
        // range is denied — the fork keeps host loopback reachable by default
        // (`SMOLVM_ALLOW_HOST_LOOPBACK=0` opts into the harder floor). The
        // host's LAN and CGNAT stay reachable, so a local VM behaves predictably.
        let p = EgressPolicy::unrestricted();
        assert!(!p.allows_v4(Ipv4Addr::new(169, 254, 169, 254))); // metadata: denied
        assert!(p.allows_v4(Ipv4Addr::new(127, 0, 0, 1))); // loopback: reachable
        assert!(p.allows_v4(Ipv4Addr::new(10, 0, 0, 4))); // LAN: reachable
        assert!(p.allows_v4(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(p.allows_v4(Ipv4Addr::new(172, 16, 0, 1)));
        assert!(p.allows_v4(Ipv4Addr::new(100, 96, 0, 1))); // CGNAT: reachable
        assert!(p.allows_v4(Ipv4Addr::new(1, 1, 1, 1))); // public: reachable
    }

    #[test]
    fn explicit_cidr_reopens_loopback_locally_but_learned_ip_does_not() {
        // Under the hardened local floor (upstream's default), a developer who
        // deliberately allow-lists loopback CAN reach a host service on
        // 127.0.0.1. Constructed directly so the test pins this floor mode
        // regardless of the environment-defaulted one.
        let local = EgressPolicy {
            inner: Some(Arc::new(AllowList {
                cidrs: vec![Cidr::parse("127.0.0.1/32").unwrap()],
                allowed_hosts: None,
                learned: Mutex::new(HashMap::new()),
            })),
            floor: FloorMode::MetadataAndLoopback,
            denial_log: None,
        };
        assert!(local.allows_v4(Ipv4Addr::new(127, 0, 0, 1)));
        // ...but only the named address — a sibling loopback IP stays floored.
        assert!(!local.allows_v4(Ipv4Addr::new(127, 0, 0, 2)));
        // A learned DNS answer for loopback never re-opens it (anti-rebinding):
        // only a static CIDR defeats the floor, and Strict keeps it absolute
        // (see `floor_strict_blocks_internal_and_metadata`).
        let learned = EgressPolicy {
            inner: Some(Arc::new(AllowList {
                cidrs: vec![],
                allowed_hosts: Some(vec!["evil.test".into()]),
                learned: Mutex::new(HashMap::new()),
            })),
            floor: FloorMode::MetadataAndLoopback,
            denial_log: None,
        };
        learned.learn_ip_records(&[(IpAddr::V4(Ipv4Addr::LOCALHOST), 300)]);
        assert!(!learned.allows_v4(Ipv4Addr::LOCALHOST));
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
        let p = EgressPolicy::unrestricted(); // MetadataAndLoopback default
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
    fn floor_default_blocks_link_local_and_loopback() {
        // Local default: the cloud-metadata link-local range AND host loopback /
        // unspecified are denied; the host's LAN and the public internet stay
        // reachable.
        for ip in [
            v4(169, 254, 169, 254),
            v4(169, 254, 0, 1),
            v4(127, 0, 0, 1), // loopback
            v4(127, 1, 2, 3),
            v4(0, 0, 0, 0), // unspecified
        ] {
            assert!(
                is_floored(ip, FloorMode::MetadataAndLoopback),
                "{ip} should be floored locally"
            );
        }
        for ip in [
            v4(8, 8, 8, 8),
            v4(192, 168, 1, 5),
            v4(10, 0, 0, 7),
            v4(172, 16, 5, 5),
        ] {
            assert!(
                !is_floored(ip, FloorMode::MetadataAndLoopback),
                "{ip} should be reachable locally"
            );
        }
        // IPv4-mapped metadata and loopback must not slip past via the v6 form.
        assert!(is_floored(
            "::ffff:169.254.169.254".parse().unwrap(),
            FloorMode::MetadataAndLoopback
        ));
        assert!(is_floored(
            "::1".parse().unwrap(),
            FloorMode::MetadataAndLoopback
        ));
        assert!(is_floored(
            "::ffff:127.0.0.1".parse().unwrap(),
            FloorMode::MetadataAndLoopback
        ));
    }

    #[test]
    fn floor_metadata_only_allows_loopback() {
        // The `--allow-host-loopback` mode floors cloud-metadata but lets a guest
        // reach the host's own 127.0.0.1 on purpose.
        assert!(is_floored(v4(169, 254, 169, 254), FloorMode::MetadataOnly));
        assert!(!is_floored(v4(127, 0, 0, 1), FloorMode::MetadataOnly));
        assert!(!is_floored(v4(0, 0, 0, 0), FloorMode::MetadataOnly));
    }

    #[test]
    fn floor_strict_blocks_internal_and_metadata() {
        // Fleet/multi-tenant: the full floor.
        for ip in [
            v4(169, 254, 169, 254), // metadata
            v4(192, 168, 1, 5),     // RFC1918
            v4(10, 0, 0, 7),
            v4(172, 16, 5, 5),
            v4(127, 0, 0, 1),       // loopback
            v4(100, 64, 0, 1),      // CGNAT gateway range
            v4(224, 0, 0, 251),     // multicast (mDNS) — the host LAN segment
            v4(239, 255, 255, 250), // multicast (SSDP)
            "ff02::1".parse().unwrap(),
            "::ffff:239.255.255.250".parse().unwrap(), // …and the mapped spelling
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

    /// An A query for `name` — enough for a policy to read the question.
    fn query_for(name: &str) -> Vec<u8> {
        let mut q = vec![0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            q.push(u8::try_from(label.len()).expect("test label fits a DNS label"));
            q.extend_from_slice(label.as_bytes());
        }
        q.extend_from_slice(&[0, 0, 1, 0, 1]); // root label, QTYPE=A, QCLASS=IN
        q
    }

    /// The DNS gate, reached the way the gateway reaches it.
    ///
    /// Forwarding a name upstream is what decides whether that name — and the
    /// data a guest can encode in one — leaves the box at all. The decision used
    /// to sit inline in `stack.rs` with no test of its own; it is a trait method
    /// now, so pin it here.
    #[test]
    fn the_dns_gate_forwards_only_listed_names() {
        let policy = EgressPolicy::new(None, Some(&["example.com".into()]));
        let p: &dyn Policy = &policy;

        // A listed name, and anything under it, goes upstream and is learned so
        // the connection that follows passes.
        for allowed in ["example.com", "www.example.com"] {
            assert!(
                matches!(
                    p.dns(&query_for(allowed)),
                    DnsDecision::Forward { learn: true }
                ),
                "{allowed} should be forwarded"
            );
        }
        // Everything else is answered here rather than sent on: NXDOMAIN for a
        // name nobody listed, SERVFAIL for a query that will not parse.
        for refused in ["evil.test", "example.com.evil.test", "notexample.com"] {
            assert!(
                matches!(p.dns(&query_for(refused)), DnsDecision::Immediate(_)),
                "{refused} must not reach the resolver"
            );
        }
        assert!(matches!(p.dns(&[0, 1, 2]), DnsDecision::Immediate(_)));

        // No allow-host list: nothing is filtered, and nothing is learned either
        // — otherwise resolving any name would defeat `allowed_cidrs`.
        let open = EgressPolicy::unrestricted();
        let o: &dyn Policy = &open;
        assert!(matches!(
            o.dns(&query_for("anything.test")),
            DnsDecision::Forward { learn: false }
        ));
    }

    /// The rest of the trait surface: the built-in policy learns from raw answer
    /// bytes, ignores ports, rewrites nothing, and answers no name itself.
    #[test]
    fn the_builtin_policy_learns_from_bytes_and_ignores_ports() {
        let policy = EgressPolicy::new(None, Some(&["example.com".into()]));
        let p: &dyn Policy = &policy;
        let ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        assert!(!p.allows(ip, Some(443)));

        // `learn` is handed the answer whole, question and all.
        p.learn(&dns::build_ip_response(
            &query_for("example.com"),
            &[ip],
            300,
        ));
        // Learned, and on every port: ports are not this policy's vocabulary, so
        // a consumer needing them implements its own.
        for port in [Some(443), Some(22), None] {
            assert!(p.allows(ip, port), "{port:?} should be allowed");
        }

        // It publishes no stand-in address and answers no name, so the gateway
        // has nothing to rewrite and no reason to intercept TCP/53 for it.
        assert_eq!(p.rewrite(ip), None);
        assert!(!p.intercepts_dns());
    }
}
