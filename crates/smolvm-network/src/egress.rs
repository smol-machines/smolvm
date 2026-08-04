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
//!
//! Additionally: [`EgressConfig::static_names`] resolves names locally;
//! [`StaticTarget::Host`] forwards to the host loopback via [`HOST_SENTINEL`];
//! and any allow-list entry may carry `:port` for per-port rules.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
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

/// The one address published for a static record naming a host-local target.
/// RFC 5737 TEST-NET-1: never a real destination, and not caught by any
/// `FloorMode`, so the mapping works in every floor mode. NOT link-local, which
/// is floored everywhere but `Off` and would be ARPed for rather than routed here.
const HOST_SENTINEL: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

/// The address [`HOST_SENTINEL`] is translated to before connecting.
pub const HOST_LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

/// What a static record answers with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StaticTarget {
    /// A literal address, handed to the guest as-is.
    Ip(IpAddr),
    /// The host itself. Published as [`HOST_SENTINEL`] and translated to
    /// [`HOST_LOOPBACK`] on connect — a guest handed `127.0.0.1` would reach its
    /// own loopback, never the gateway. Say this rather than naming a loopback
    /// address, so wanting host access is a declaration and not an inference.
    Host,
}

/// Split a trailing `:port` off an allow-list entry. Uses `host:port` /
/// `[v6]:port` convention: bare host+colon is a v6 literal or CIDR. `None` =
/// malformed port (caller drops the entry).
fn split_port(entry: &str) -> Option<(&str, Option<u16>)> {
    let port = |p: &str| p.parse::<u16>().ok().filter(|p| *p != 0);
    if let Some(rest) = entry.strip_prefix('[') {
        let (addr, tail) = rest.split_once(']')?;
        return match tail.strip_prefix(':') {
            Some(p) => Some((addr, Some(port(p)?))),
            None if tail.is_empty() => Some((addr, None)),
            None => None,
        };
    }
    match entry.rsplit_once(':') {
        Some((host, p)) if !host.contains(':') => Some((host, Some(port(p)?))),
        _ => Some((entry, None)),
    }
}

struct AllowList {
    /// Allowed CIDRs, each with the port it narrows to (`None` = any port).
    cidrs: Vec<(Cidr, Option<u16>)>,
    /// Normalized allow-host names with their port grants. `None` = no DNS
    /// hostname filtering.
    allowed_hosts: Option<Vec<(String, Option<u16>)>>,
    /// `(IP, port grant)` learned from allowed DNS answers → expiry instant. Keyed
    /// by the pair so one IP learned from two names keeps both grants.
    learned: Mutex<HashMap<(IpAddr, Option<u16>), Instant>>,
}

impl AllowList {
    /// Port grants for `hostname`; empty = none match. The opposite sense to
    /// [`EgressPolicy::hostname_allowed`]: unset means queries pass but earn no
    /// address grant (otherwise resolving any name would defeat `allowed_cidrs`).
    fn name_grants(&self, hostname: &str) -> Vec<Option<u16>> {
        let Some(hosts) = &self.allowed_hosts else {
            return Vec::new();
        };
        hosts
            .iter()
            .filter(|(name, _)| dns::hostname_allowed(hostname, std::slice::from_ref(name)))
            .map(|(_, grant)| *grant)
            .collect()
    }
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
        // 224.0.0.0/4 — host LAN segment the floor exists to block
        || v4.is_multicast()
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
    /// Names the policy resolves itself → the IPs published to the guest.
    static_names: Arc<HashMap<String, Vec<IpAddr>>>,
    /// Whether one of them published [`HOST_SENTINEL`]. Without this the relays
    /// would translate the sentinel for a guest that merely invented the address,
    /// handing over the host's loopback past the hard floor.
    host_sentinel_live: bool,
}

/// Everything a policy is built from. `Default` = unrestricted with no static
/// names, i.e. allow everything except the platform hard-floor.
#[derive(Clone, Debug, Default)]
pub struct EgressConfig {
    /// Allowed CIDRs/IPs, each with an optional `:port` (`1.1.1.1:443`,
    /// `[::1]:443`). Either list being `Some` puts the allow-list in force.
    pub allowed_cidrs: Option<Vec<String>>,
    /// Allowed DNS names, each with an optional `:port` (`api.test:443`).
    /// Subdomains match. `None` = no name filtering; `Some(vec![])` allows none.
    pub allowed_hosts: Option<Vec<String>>,
    /// Names the gateway answers itself: hostname → what to answer with. Ports
    /// play no part here — put `name:port` in `allowed_hosts` to narrow access.
    pub static_names: Vec<(String, Vec<StaticTarget>)>,
    /// Hard-floor scope. `None` (the default) infers it from the environment;
    /// set it to pin the floor without depending on env vars.
    pub floor: Option<FloorMode>,
}

impl EgressConfig {
    /// The plain `allowed_cidrs` + `--allow-host` shape, with no static names.
    pub fn from_allow_lists(cidrs: Option<Vec<String>>, hosts: Option<Vec<String>>) -> Self {
        Self {
            allowed_cidrs: cidrs,
            allowed_hosts: hosts,
            ..Self::default()
        }
    }
}

impl EgressPolicy {
    /// No allow-list — every destination is allowed EXCEPT the platform hard-floor.
    pub fn unrestricted() -> Self {
        Self::new(EgressConfig::default())
    }

    /// Build the policy described by `config`. Both allow-lists `None` →
    /// unrestricted. Otherwise a policy is in force: only the listed CIDRs and
    /// IPs learned from allowed DNS answers may be reached (an empty CIDR list
    /// with no hosts denies everything).
    pub fn new(config: EgressConfig) -> Self {
        let EgressConfig {
            allowed_cidrs,
            allowed_hosts,
            static_names,
            floor,
        } = config;
        let floor = floor.unwrap_or_else(floor_mode);
        let publish = |t: &StaticTarget| match t {
            StaticTarget::Ip(ip) => *ip,
            StaticTarget::Host => HOST_SENTINEL,
        };
        let host_sentinel_live = static_names
            .iter()
            .any(|(_, t)| t.contains(&StaticTarget::Host));
        let static_names: HashMap<String, Vec<IpAddr>> = static_names
            .iter()
            .filter_map(|(n, ts)| {
                Some((
                    dns::normalize_hostname(n)?,
                    ts.iter().map(publish).collect(),
                ))
            })
            .collect();
        let static_names = Arc::new(static_names);
        if allowed_cidrs.is_none() && allowed_hosts.is_none() {
            return Self {
                inner: None,
                floor,
                static_names,
                host_sentinel_live,
            };
        }
        let mut cidrs: Vec<(Cidr, Option<u16>)> = allowed_cidrs
            .unwrap_or_default()
            .iter()
            .filter_map(|spec| {
                let parsed = split_port(spec.trim()).and_then(|(s, p)| Some((Cidr::parse(s)?, p)));
                if parsed.is_none() {
                    tracing::warn!(cidr = %spec, "ignoring unparseable egress CIDR");
                }
                parsed
            })
            .collect();
        let allowed_hosts = allowed_hosts.map(|hosts| {
            hosts
                .iter()
                .filter_map(|h| {
                    let (name, port) = split_port(h.trim())?;
                    Some((dns::normalize_hostname(name)?, port))
                })
                .collect::<Vec<_>>()
        });
        // A statically answered IP is reached by address, never by name: the
        // grant on that name becomes an address rule here. Without an allow-host
        // list the record itself authorizes (`Host` sentinel otherwise unreachable
        // — nobody puts it in `allowed_cidrs`). Upstream answers earn nothing
        // (`name_grants`): operator authorization is different from a resolver's.
        for (name, ips) in static_names.iter() {
            let grants: Vec<Option<u16>> = match &allowed_hosts {
                None => vec![None],
                Some(hosts) => hosts
                    .iter()
                    .filter(|(rule, _)| dns::hostname_allowed(name, std::slice::from_ref(rule)))
                    .map(|(_, port)| *port)
                    .collect(),
            };
            for grant in grants {
                cidrs.extend(
                    ips.iter()
                        .filter_map(|i| Some((Cidr::parse(&i.to_string())?, grant))),
                );
            }
        }
        Self {
            inner: Some(Arc::new(AllowList {
                cidrs,
                allowed_hosts,
                learned: Mutex::new(HashMap::new()),
            })),
            floor,
            static_names,
            host_sentinel_live,
        }
    }

    /// Whether the policy answers any name itself. The gateway then intercepts
    /// DNS/TCP too, so those answers win over whatever resolver the guest picked.
    pub fn has_static_dns(&self) -> bool {
        !self.static_names.is_empty()
    }

    /// The IPs to answer a statically mapped `name` with, if one is configured.
    pub fn static_answer(&self, name: &str) -> Option<Vec<IpAddr>> {
        self.static_names
            .get(&dns::normalize_hostname(name)?)
            .cloned()
    }

    /// The address [`HOST_SENTINEL`] really stands for, once a static record has
    /// published it. Relays call this before connect; `None` = `ip` is already the
    /// real destination. The port is untouched — only the address is swapped.
    pub fn host_forward(&self, ip: IpAddr) -> Option<IpAddr> {
        (ip == HOST_SENTINEL && self.host_sentinel_live).then_some(HOST_LOOPBACK)
    }

    /// Whether any policy is in force (false = allow-all).
    pub fn is_restricted(&self) -> bool {
        self.inner.is_some()
    }

    /// Whether the gateway should DNS-filter queries (an allow-host list is set,
    /// or the policy answers some name itself).
    pub fn dns_filter_active(&self) -> bool {
        self.has_static_dns()
            || self
                .inner
                .as_ref()
                .is_some_and(|l| l.allowed_hosts.is_some())
    }

    /// Whether a DNS query for `hostname` should be forwarded upstream. With no
    /// allow-host list, all queries pass (exact + subdomain match otherwise).
    pub fn hostname_allowed(&self, hostname: &str) -> bool {
        match &self.inner {
            None => true,
            Some(list) => match &list.allowed_hosts {
                None => true,
                Some(_) => !list.name_grants(hostname).is_empty(),
            },
        }
    }

    /// Whether an outbound connection to `ip` (v4 or v6) is permitted. `port` is
    /// `None` for a portless flow (ICMP echo), which only an any-port grant covers.
    pub fn allows(&self, ip: IpAddr, port: Option<u16>) -> bool {
        // Platform hard-floor: deny per the resolved FloorMode (metadata-only
        // locally, full floor under fleet mode) regardless of the allow-list.
        if is_floored(ip, self.floor) {
            return false;
        }
        // The floor judges the sentinel, not its translation: a static record IS
        // the operator authorizing that target. Which is why an unclaimed sentinel
        // must die here — otherwise a guest that simply dials the address is handed
        // the host's loopback past the floor.
        if ip == HOST_SENTINEL && !self.host_sentinel_live {
            return false;
        }
        // A grant of `None` covers every port, including a portless flow.
        let covers = |grant: Option<u16>| grant.is_none() || port == grant;
        match &self.inner {
            None => true,
            Some(list) => {
                if list.cidrs.iter().any(|(c, g)| c.contains(ip) && covers(*g)) {
                    return true;
                }
                list.learned
                    .lock()
                    .map(|learned| {
                        let now = Instant::now();
                        [None, port]
                            .iter()
                            .any(|g| learned.get(&(ip, *g)).is_some_and(|at| *at > now))
                    })
                    .unwrap_or(false)
            }
        }
    }

    /// Learn the A/AAAA records of an allowed DNS answer as temporarily-allowed
    /// IPs. TTLs are clamped to [60s, 3600s]; expired entries are pruned. No-op
    /// when unrestricted.
    ///
    /// The grant is keyed by name — `api.test:443` narrows the addresses
    /// `api.test` resolves to — so the name is read from the answer's question,
    /// not the query. Safe: the echoed name only selects among existing grants.
    pub fn learn_ip_records(&self, answer: &[u8]) {
        let Some(hostname) = dns::question_name(answer) else {
            return;
        };
        self.learn_named(&hostname, &dns::answer_ip_records(answer));
    }

    /// [`Self::learn_ip_records`] with the answer already parsed.
    fn learn_named(&self, hostname: &str, records: &[(IpAddr, u32)]) {
        let Some(list) = &self.inner else {
            return;
        };
        let grants = list.name_grants(hostname);
        if grants.is_empty() {
            return;
        }
        let Ok(mut learned) = list.learned.lock() else {
            return;
        };
        let now = Instant::now();
        learned.retain(|_, expires_at| *expires_at > now);
        for (ip, ttl) in records {
            // Learned addresses are attacker-controlled — floor them too.
            // Also exclude HOST_SENTINEL so a static `to: host` record can
            // publish it without letting every allowed name reach the host loopback.
            if is_floored(*ip, self.floor) || *ip == HOST_SENTINEL {
                continue;
            }
            let ttl = u64::from(*ttl).clamp(MIN_LEARNED_TTL, MAX_LEARNED_TTL);
            let expires_at = now + Duration::from_secs(ttl);
            for grant in &grants {
                learned
                    .entry((*ip, *grant))
                    .and_modify(|existing| *existing = (*existing).max(expires_at))
                    .or_insert(expires_at);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    /// Restricted-policy fixture: a CIDR allow-list, an allow-host list, or both.
    fn policy(cidrs: &[&str], hosts: Option<&[&str]>) -> EgressPolicy {
        EgressPolicy::new(EgressConfig::from_allow_lists(
            Some(cidrs.iter().map(|s| s.to_string()).collect()),
            hosts.map(|hosts| hosts.iter().map(|s| s.to_string()).collect()),
        ))
    }

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
        assert!(policy.allows(v4(8, 8, 8, 8), None));
        assert!(policy.allows(v6("2001:4860:4860::8888"), None));
        assert!(policy.hostname_allowed("anything.test"));
        assert!(!policy.dns_filter_active());
    }

    #[test]
    fn empty_allowlist_denies_all() {
        let policy = policy(&[], None);
        assert!(policy.is_restricted());
        assert!(!policy.allows(v4(1, 1, 1, 1), None));
        assert!(!policy.allows(v6("2606:4700::1111"), None));
    }

    #[test]
    fn cidr_membership_v4() {
        // Public CIDRs only — private ranges are denied by the hard-floor below.
        let policy = policy(&["8.8.8.0/24", "1.1.1.1"], None);
        assert!(policy.allows(v4(8, 8, 8, 7), None));
        assert!(policy.allows(v4(1, 1, 1, 1), None));
        assert!(!policy.allows(v4(1, 1, 1, 2), None));
        assert!(!policy.allows(v4(9, 0, 0, 1), None));
    }

    #[test]
    fn unrestricted_local_floors_only_metadata() {
        // Local default (no fleet mode): only the cloud-metadata link-local range
        // is denied; the host's LAN, loopback, and CGNAT stay reachable — so a
        // local VM behaves predictably.
        let p = EgressPolicy::unrestricted();
        assert!(!p.allows(v4(169, 254, 169, 254), None)); // metadata: denied
        assert!(p.allows(v4(10, 0, 0, 4), None)); // LAN: reachable
        assert!(p.allows(v4(127, 0, 0, 1), None)); // loopback: reachable
        assert!(p.allows(v4(192, 168, 1, 1), None));
        assert!(p.allows(v4(172, 16, 0, 1), None));
        assert!(p.allows(v4(100, 96, 0, 1), None)); // CGNAT: reachable
        assert!(p.allows(v4(1, 1, 1, 1), None)); // public: reachable
    }

    #[test]
    fn metadata_floor_overrides_allowlist_and_learned_ips() {
        // The metadata range can't be re-opened by allow-listing it...
        let p = policy(&["169.254.0.0/16"], None);
        assert!(!p.allows(v4(169, 254, 169, 254), None));
        // ...nor via DNS-rebinding: a learned metadata IP stays denied.
        let p2 = policy(&[], Some(&["evil.test"]));
        let meta = IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254));
        p2.learn_named("evil.test", &[(meta, 300)]);
        assert!(!p2.allows(meta, None));
        // But a LAN IP in the allow-list IS reachable locally.
        let p3 = policy(&["10.0.0.0/8"], None);
        assert!(p3.allows(v4(10, 0, 0, 4), None));
    }

    #[test]
    fn metadata_floor_blocks_mapped_and_v6_link_local() {
        let p = EgressPolicy::unrestricted(); // MetadataOnly default
                                              // mapped metadata + v6 link-local are denied...
        assert!(!p.allows(v6("::ffff:169.254.169.254"), None));
        assert!(!p.allows(v6("fe80::1"), None));
        // ...but v6 ULA (the LAN equivalent) and global unicast are reachable.
        assert!(p.allows(v6("fc00::1"), None));
        assert!(p.allows(v6("2606:4700::1111"), None));
    }

    #[test]
    fn cidr_membership_v6() {
        let policy = policy(&["2606:4700::/32", "2001:db8::1"], None);
        assert!(policy.allows(v6("2606:4700::1111"), None));
        assert!(policy.allows(v6("2606:4700:ffff::1"), None));
        assert!(policy.allows(v6("2001:db8::1"), None));
        assert!(!policy.allows(v6("2001:db8::2"), None));
        assert!(!policy.allows(v6("2607::1"), None));
        // A v6 CIDR never matches a v4 address and vice versa.
        assert!(!policy.allows(v4(1, 1, 1, 1), None));
    }

    #[test]
    fn allow_host_gates_dns_and_learns_ips() {
        let policy = policy(&[], Some(&["example.com"]));
        assert!(policy.dns_filter_active());
        assert!(policy.hostname_allowed("example.com"));
        assert!(policy.hostname_allowed("www.example.com"));
        assert!(!policy.hostname_allowed("evil.test"));

        let v4 = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let v6: IpAddr = "2606:2800:21f:cb07:6820:80da:af6b:8b2c"
            .parse::<Ipv6Addr>()
            .unwrap()
            .into();
        assert!(!policy.allows(v4, None));
        assert!(!policy.allows(v6, None));
        policy.learn_named("example.com", &[(v4, 300), (v6, 600)]);
        assert!(policy.allows(v4, None));
        assert!(policy.allows(v6, None));
    }

    #[test]
    fn learned_ip_respects_min_ttl() {
        // A tiny TTL is clamped up to MIN_LEARNED_TTL, so the entry is live now.
        let policy = policy(&[], Some(&["example.com"]));
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        policy.learn_named("example.com", &[(ip, 1)]);
        assert!(policy.allows(ip, None));
    }

    #[test]
    fn split_port_follows_the_socketaddr_convention() {
        // Bare address forms carry no port; the colons in a v6 literal or CIDR are
        // not separators.
        assert_eq!(split_port("10.0.0.0/8"), Some(("10.0.0.0/8", None)));
        assert_eq!(split_port("::1"), Some(("::1", None)));
        assert_eq!(split_port("fc00::/7"), Some(("fc00::/7", None)));
        assert_eq!(split_port("api.test"), Some(("api.test", None)));
        // Ports, including the bracketed v6 form.
        assert_eq!(split_port("1.1.1.1:443"), Some(("1.1.1.1", Some(443))));
        assert_eq!(split_port("[::1]:443"), Some(("::1", Some(443))));
        assert_eq!(split_port("[fc00::/7]:443"), Some(("fc00::/7", Some(443))));
        assert_eq!(split_port("api.test:443"), Some(("api.test", Some(443))));
        // A present-but-unusable port drops the entry rather than widening it.
        assert!(split_port("1.1.1.1:").is_none());
        assert!(split_port("1.1.1.1:0").is_none());
        assert!(split_port("api.test:99999").is_none());
    }

    #[test]
    fn unparseable_cidr_is_skipped_not_panicked() {
        let policy = policy(&["nonsense", "10.0.0.0/33", "1.1.1.1"], None);
        assert!(policy.allows(v4(1, 1, 1, 1), None));
        assert!(!policy.allows(v4(2, 2, 2, 2), None));
        // A bad CIDR stays a bad CIDR: it never turns into a name rule, so DNS
        // filtering is not switched on behind the operator's back.
        assert!(!policy.dns_filter_active());
    }

    #[test]
    fn cidr_list_alone_leaves_dns_unfiltered() {
        // An address-only policy gates connections but not resolution, so a guest
        // still resolves names it will simply not be allowed to reach.
        let p = policy(&["8.8.8.0/24"], None);
        assert!(!p.dns_filter_active());
        assert!(p.hostname_allowed("anything.test"));
        assert!(p.allows(v4(8, 8, 8, 8), None));
        assert!(!p.allows(v4(1, 1, 1, 1), None));
    }

    #[test]
    fn port_suffix_narrows_cidrs_and_learned_ips_alike() {
        let p = policy(&["8.8.8.0/24:53"], Some(&["api.test:443"]));
        // CIDR entry: only its port.
        assert!(p.allows(v4(8, 8, 8, 8), Some(53)));
        assert!(!p.allows(v4(8, 8, 8, 8), Some(80)));
        assert!(!p.allows(v4(8, 8, 8, 8), None)); // portless ICMP: no

        // Name entry: the port rides onto whatever the name resolves to.
        let resolved = v4(93, 184, 216, 34);
        p.learn_named("api.test", &[(resolved, 300)]);
        assert!(p.allows(resolved, Some(443)));
        assert!(!p.allows(resolved, Some(80)));

        // A name with no rule learns nothing at all.
        let other = v4(5, 5, 5, 5);
        p.learn_named("evil.test", &[(other, 300)]);
        assert!(!p.allows(other, Some(443)));
    }

    #[test]
    fn two_names_on_one_ip_keep_both_port_grants() {
        let p = policy(&[], Some(&["a.test:80", "b.test:443"]));
        let shared = v4(9, 9, 9, 9);
        p.learn_named("a.test", &[(shared, 300)]);
        p.learn_named("b.test", &[(shared, 300)]);
        assert!(p.allows(shared, Some(80)));
        assert!(p.allows(shared, Some(443)));
        assert!(!p.allows(shared, Some(22)));
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

    fn v6(addr: &str) -> IpAddr {
        IpAddr::V6(addr.parse::<Ipv6Addr>().expect("test IPv6 literal"))
    }

    #[test]
    fn config_floor_pins_the_scope_without_env() {
        // A pinned floor makes the policy independent of ambient env vars.
        let strict = EgressPolicy::new(EgressConfig {
            floor: Some(FloorMode::Strict),
            ..Default::default()
        });
        assert!(!strict.allows(v4(10, 0, 0, 4), None)); // Strict floors RFC1918
        let off = EgressPolicy::new(EgressConfig {
            floor: Some(FloorMode::Off),
            ..Default::default()
        });
        assert!(off.allows(v4(169, 254, 169, 254), None)); // Off floors nothing
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

    /// Static-record fixture: names answered by the policy, gated by allow-hosts.
    fn statics(hosts: Option<&[&str]>, names: &[(&str, StaticTarget)]) -> EgressPolicy {
        EgressPolicy::new(EgressConfig {
            allowed_hosts: hosts.map(|h| h.iter().map(|s| s.to_string()).collect()),
            static_names: names
                .iter()
                .map(|(n, t)| (n.to_string(), vec![*t]))
                .collect(),
            floor: Some(FloorMode::MetadataOnly),
            ..Default::default()
        })
    }

    #[test]
    fn static_records_answer_names_and_translate_host_local_ones() {
        let p = statics(
            Some(&["api.internal", "db.local:5432"]),
            &[
                ("api.internal", StaticTarget::Ip(v4(10, 0, 0, 5))),
                ("db.local", StaticTarget::Host),
            ],
        );
        assert!(p.dns_filter_active());

        // A routable record is published as-is, looked up on the normalized name.
        let api = p.static_answer("API.Internal.").expect("normalized lookup");
        assert_eq!(api, vec![v4(10, 0, 0, 5)]);
        assert_eq!(p.host_forward(v4(10, 0, 0, 5)), None);
        assert!(p.static_answer("other.internal").is_none());

        // A host-local record is published as the sentinel and translated back.
        assert_eq!(p.static_answer("db.local"), Some(vec![HOST_SENTINEL]));
        assert_eq!(p.host_forward(HOST_SENTINEL), Some(HOST_LOOPBACK));

        // The allow-host entry grants the record's address with no CIDR entry
        // covering it — the one thing naming a record does that listing an
        // address cannot, and why `allowed_cidrs` stays addresses-only.
        assert!(p.allows(v4(10, 0, 0, 5), Some(8080)));
        assert!(!p.allows(v4(10, 0, 0, 6), Some(8080)));
        // ...and the port on the other entry still binds its own record.
        assert!(p.allows(HOST_SENTINEL, Some(5432)));
        assert!(!p.allows(HOST_SENTINEL, Some(22)));
    }

    #[test]
    fn allow_hosts_gate_static_records_by_name() {
        // The whole point of the split: the port is written against the *name* in
        // the allow-list, and binds the address that name was answered with.
        let p = statics(
            Some(&["db.local:5432"]),
            &[("db.local", StaticTarget::Host)],
        );
        assert!(p.allows(HOST_SENTINEL, Some(5432)));
        assert!(!p.allows(HOST_SENTINEL, Some(22))); // exposing Postgres must not expose SSH
        assert!(!p.allows(HOST_SENTINEL, None)); // portless ICMP: no

        // No port on the rule = every port on what it resolves to.
        let open = statics(Some(&["open.local"]), &[("open.local", StaticTarget::Host)]);
        assert!(open.allows(HOST_SENTINEL, Some(22)));
        assert!(open.allows(HOST_SENTINEL, None));

        // Answered by DNS, but no allow-host rule names it: resolvable, unreachable.
        let unlisted = statics(Some(&["other.local"]), &[("db.local", StaticTarget::Host)]);
        assert_eq!(
            unlisted.static_answer("db.local"),
            Some(vec![HOST_SENTINEL])
        );
        assert_eq!(unlisted.host_forward(HOST_SENTINEL), Some(HOST_LOOPBACK));
        assert!(!unlisted.allows(HOST_SENTINEL, Some(5432)));
        assert!(!unlisted.allows(HOST_SENTINEL, Some(22)));

        // A record's address is still just an address: a CIDR rule covering it
        // grants it, with no allow-host entry naming it at all.
        let by_cidr = EgressPolicy::new(EgressConfig {
            allowed_cidrs: Some(vec!["10.0.0.0/8".into()]),
            static_names: vec![(
                "api.internal".into(),
                vec![StaticTarget::Ip(v4(10, 0, 0, 5))],
            )],
            ..Default::default()
        });
        assert!(by_cidr.allows(v4(10, 0, 0, 5), Some(8080)));
    }

    #[test]
    fn a_dns_answer_cannot_publish_the_host_sentinel() {
        // A DNS answer for an allowed name must not earn a grant on the sentinel
        // — that would give every allowed name access to the host loopback.
        let p = statics(
            Some(&["db.local:5432", "api.test"]),
            &[("db.local", StaticTarget::Host)],
        );
        p.learn_named("api.test", &[(HOST_SENTINEL, 300)]);
        assert!(!p.allows(HOST_SENTINEL, Some(22)));
        assert!(!p.allows(HOST_SENTINEL, None));
        // The record's own grant is untouched.
        assert!(p.allows(HOST_SENTINEL, Some(5432)));
    }

    #[test]
    fn the_floor_covers_multicast() {
        // Floor-only (no allow-list) must block multicast from the host LAN.
        let p = EgressPolicy::new(EgressConfig {
            floor: Some(FloorMode::Strict),
            ..Default::default()
        });
        for addr in ["224.0.0.1", "239.255.255.250", "224.0.0.251", "ff02::1"] {
            let ip: IpAddr = addr.parse().unwrap();
            assert!(!p.allows(ip, Some(1900)), "reached {addr}");
        }
        // …including the IPv4-mapped spelling, which `Ipv6Addr::is_multicast`
        // answers `false` for on its own.
        assert!(!p.allows("::ffff:239.255.255.250".parse().unwrap(), Some(1900)));
    }

    #[test]
    fn unclaimed_sentinel_never_reaches_the_host() {
        // No static record publishes it, so it translates to nothing and is denied
        // — including under a Strict floor, where translating would otherwise hand
        // a guest the host's loopback past the floor.
        let p = EgressPolicy::unrestricted();
        assert_eq!(p.host_forward(HOST_SENTINEL), None);
        assert!(!p.allows(HOST_SENTINEL, Some(22)));
        assert!(!p.allows(HOST_SENTINEL, None));
        // Everything else is still wide open in this mode.
        assert!(p.allows(v4(1, 1, 1, 1), Some(22)));

        // Published but unrestricted: reachable on any port, which matches this
        // mode already permitting the host's loopback directly.
        let live = statics(None, &[("db.local", StaticTarget::Host)]);
        assert!(!live.is_restricted());
        assert!(live.allows(HOST_SENTINEL, Some(5432)));
        assert!(live.allows(HOST_SENTINEL, Some(22)));
    }

    #[test]
    fn host_record_needs_no_name_filter_but_a_resolver_earns_nothing() {
        // No allow-host list = names are not filtered, so the record itself is the
        // authorization; otherwise a Host record would be silently unreachable.
        let p = EgressPolicy::new(EgressConfig {
            allowed_cidrs: Some(vec!["1.1.1.1".into()]),
            allowed_hosts: None,
            static_names: vec![("db.local".into(), vec![StaticTarget::Host])],
            floor: Some(FloorMode::MetadataOnly),
        });
        assert!(p.allows(HOST_SENTINEL, Some(5432)));
        assert!(p.allows(HOST_SENTINEL, Some(22)));

        // An upstream answer still earns nothing: those addresses come from the
        // resolver, so `allowed_cidrs` keeps gating them.
        p.learn_named("evil.test", &[(v4(9, 9, 9, 9), 300)]);
        assert!(!p.allows(v4(9, 9, 9, 9), Some(443)));
        assert!(p.allows(v4(1, 1, 1, 1), Some(443)));

        // A name filter that omits the record puts it back out of reach.
        let filtered = statics(Some(&["other.local"]), &[("db.local", StaticTarget::Host)]);
        assert!(!filtered.allows(HOST_SENTINEL, Some(5432)));
    }

    #[test]
    fn floor_beats_a_static_record_pointing_at_it() {
        // A record onto the metadata range is answered but never reachable: the
        // hard floor sits under the allow-list, not beside it.
        let p = statics(
            Some(&["meta.test"]),
            &[("meta.test", StaticTarget::Ip(v4(169, 254, 169, 254)))],
        );
        assert_eq!(
            p.static_answer("meta.test"),
            Some(vec![v4(169, 254, 169, 254)])
        );
        assert!(!p.allows(v4(169, 254, 169, 254), Some(80)));
    }
}
