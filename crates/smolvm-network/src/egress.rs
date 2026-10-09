//! Outbound egress policy for the virtio-net gateway.
//!
//! The virtio-net gateway terminates every guest flow and applies this policy
//! before it opens a host connection (`TcpRelayTable::create_tcp_socket`). TSI
//! is rejected for policy-bearing machines because its libkrun filter has not
//! enforced the equivalent policy in empirical tests:
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
//! A restricted policy's allow list can be replaced while the machine runs
//! ([`EgressPolicy::replace_allow_list`]), by the host over a socket only it can
//! reach. A replacement can never lift the policy: an empty list admits nothing.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use crate::dns;
use smolvm_protocol::{EgressRule, FlowTransport, RuleAction};

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

/// The destinations an allow list admits.
struct Rules {
    cidrs: Vec<Cidr>,
    /// Normalized allow-host names. `None` = no DNS hostname filtering.
    allowed_hosts: Option<Vec<String>>,
}

impl Rules {
    fn build(allowed_cidrs: Option<&[String]>, allowed_hosts: Option<&[String]>) -> Self {
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
            cidrs,
            allowed_hosts,
        }
    }

    fn hostname_allowed(&self, hostname: &str) -> bool {
        match &self.allowed_hosts {
            None => true,
            Some(hosts) => dns::hostname_allowed(hostname, hosts),
        }
    }
}

/// An IP learned from an allowed DNS answer.
struct Learned {
    expires_at: Instant,
    /// The name whose answer admitted it, so revoking the name revokes it.
    name: Option<String>,
}

struct AllowList {
    rules: RwLock<Arc<Rules>>,
    /// IPs learned from allowed DNS answers.
    learned: Mutex<HashMap<IpAddr, Learned>>,
}

impl AllowList {
    /// The rules in force.
    fn rules(&self) -> Arc<Rules> {
        Arc::clone(&self.rules.read().unwrap_or_else(|e| e.into_inner()))
    }
}

/// Render an allow list for [`EgressPolicy::replace_allow_list`]: one
/// `cidr <range>` or `host <name-or-pattern>` per line, hosts as `machine
/// create` stores them.
pub fn render_live_policy(cidrs: &[String], hosts: &[String]) -> String {
    let mut out = String::from("# smolvm egress allow list\n");
    for cidr in cidrs {
        out.push_str("cidr ");
        out.push_str(cidr.trim());
        out.push('\n');
    }
    for host in hosts {
        out.push_str("host ");
        out.push_str(host.trim());
        out.push('\n');
    }
    out
}

/// Parse a rendered allow list. An absent kind of entry means none of it, and a
/// list with no entries at all admits nothing.
fn parse_live_policy(bytes: &[u8]) -> Result<Rules, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "not UTF-8".to_string())?;
    let mut cidrs = Vec::new();
    let mut hosts = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match line.split_once(char::is_whitespace) {
            Some(("cidr", value)) if Cidr::parse(value.trim()).is_some() => {
                cidrs.push(value.trim().to_string())
            }
            Some(("host", value)) if !value.trim().is_empty() => {
                hosts.push(value.trim().to_string())
            }
            _ => {
                return Err(format!(
                    "line {}: expected `cidr <range>` or `host <name>`",
                    index + 1
                ))
            }
        }
    }
    if cidrs.is_empty() && hosts.is_empty() {
        return Ok(Rules::build(Some(&[]), Some(&[])));
    }
    Ok(Rules::build(
        (!cidrs.is_empty()).then_some(cidrs.as_slice()),
        (!hosts.is_empty()).then_some(hosts.as_slice()),
    ))
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
    // Fleet mode is absolute: `SMOLVM_ALLOW_HOST_LOOPBACK` only relaxes the LOCAL
    // default, never Strict, so it can't re-expose the host loopback / control
    // door on a multi-tenant node.
    if std::env::var_os("SMOLVM_PUBLISH_ADDR").is_some() {
        return FloorMode::Strict;
    }
    let allow_host_loopback = std::env::var("SMOLVM_ALLOW_HOST_LOOPBACK")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
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
        // 100.64.0.0/10 (CGNAT) — the gateway's own guest/gateway addresses live here.
        || matches!(v4.octets(), [100, b, ..] if (64..=127).contains(&b))
}

/// Whether `ip` is floored under `mode` — the single hard-floor predicate. Also
/// defeats DNS-rebinding (a learned IP in a floored range is still denied).
fn is_floored(ip: IpAddr, mode: FloorMode) -> bool {
    match mode {
        FloorMode::Off => false,
        FloorMode::MetadataOnly => is_link_local(ip),
        FloorMode::MetadataAndLoopback => is_link_local(ip) || is_host_loopback(ip),
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
    rules: Arc<Vec<CompiledRule>>,
    /// Hard-floor scope, resolved once from the deployment context at creation.
    floor: FloorMode,
    /// Audit sink for denials. When set, every denied connect/sendto/resolve is
    /// appended here in addition to the runtime's stderr line, so the record
    /// can't be evicted by ordinary connection chatter in the boot log.
    denial_log: Option<Arc<std::path::PathBuf>>,
    /// The operator's egress watchlist for this VM, when one was provisioned:
    /// destinations to flag in `signal_log`, never to block.
    watchlist: Option<Arc<crate::watchlist::WatchlistSource>>,
    /// Audit sink for watchlist matches, kept apart from denials so neither
    /// evicts the other. Created on the first match only.
    signal_log: Option<Arc<std::path::PathBuf>>,
    decision_log: Option<Arc<DecisionLog>>,
}

/// Append one timestamped line to an audit file, rotating it once past 8 MiB
/// (`.1` suffix) so a workload repeating an event at packet rate can't fill the
/// host disk.
fn append_audit_line(path: &std::path::Path, message: &str) {
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
            crate::format_network_log_line(std::time::SystemTime::now(), message)
        );
    }
}

impl std::fmt::Debug for EgressPolicy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EgressPolicy")
            .field("restricted", &self.is_restricted())
            .finish()
    }
}

struct DecisionLog {
    path: std::path::PathBuf,
    machine_id: [u8; 16],
    parent_id: [u8; 16],
    lock: Mutex<()>,
}

#[derive(Clone)]
struct CompiledRule {
    transport: Option<FlowTransport>,
    cidr: Option<Cidr>,
    ports: Option<smolvm_protocol::PortRange>,
    action: RuleAction,
}

impl EgressPolicy {
    /// No allow-list — every destination is allowed EXCEPT the platform hard-floor.
    pub fn unrestricted() -> Self {
        Self {
            inner: None,
            rules: Arc::new(Vec::new()),
            floor: floor_mode(),
            denial_log: None,
            watchlist: None,
            signal_log: None,
            decision_log: None,
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
        Self {
            inner: Some(Arc::new(AllowList {
                rules: RwLock::new(Arc::new(Rules::build(allowed_cidrs, allowed_hosts))),
                learned: Mutex::new(HashMap::new()),
            })),
            rules: Arc::new(Vec::new()),
            floor: floor_mode(),
            denial_log: None,
            watchlist: None,
            signal_log: None,
            decision_log: None,
        }
    }

    /// Replace the allow list of a restricted policy with a rendered one (see
    /// [`render_live_policy`]), for every clone of this policy at once. Learned
    /// addresses of names the new list no longer allows are forgotten. An
    /// unrestricted policy has no list to replace.
    pub fn replace_allow_list(&self, rendered: &str) -> Result<(), String> {
        let Some(list) = &self.inner else {
            return Err("this machine has no allow list to replace".to_string());
        };
        let next = Arc::new(parse_live_policy(rendered.as_bytes())?);
        if let Ok(mut learned) = list.learned.lock() {
            learned.retain(|_, entry| {
                entry
                    .name
                    .as_deref()
                    .is_none_or(|name| next.hostname_allowed(name))
            });
        }
        *list.rules.write().unwrap_or_else(|e| e.into_inner()) = next;
        Ok(())
    }

    /// Convenience for the CIDR-only case.
    /// Attach the audit sink denials are appended to. The launcher points this
    /// at the machine's data dir so the host can read denials back.
    pub fn with_denial_log(mut self, path: std::path::PathBuf) -> Self {
        self.denial_log = Some(Arc::new(path));
        self
    }

    /// Compile an ordered rule list at launch. Invalid rules fail launch rather
    /// than silently weakening the effective policy.
    pub fn with_rules(mut self, rules: &[EgressRule]) -> Result<Self, String> {
        let mut compiled = Vec::with_capacity(rules.len());
        for (index, rule) in rules.iter().enumerate() {
            let cidr = match rule.cidr.as_deref() {
                Some(spec) => Some(
                    Cidr::parse(spec)
                        .ok_or_else(|| format!("egress rule {index}: invalid CIDR"))?,
                ),
                None => None,
            };
            if let Some(ports) = rule.ports {
                if ports.start == 0
                    || ports.end < ports.start
                    || rule.transport == Some(FlowTransport::Icmp)
                {
                    return Err(format!(
                        "egress rule {index}: invalid port range or transport"
                    ));
                }
            }
            if rule.action == RuleAction::Redirect && rule.transport != Some(FlowTransport::Tcp) {
                return Err(format!(
                    "egress rule {index}: redirect requires TCP transport"
                ));
            }
            compiled.push(CompiledRule {
                transport: rule.transport,
                cidr,
                ports: rule.ports,
                action: rule.action,
            });
        }
        self.rules = Arc::new(compiled);
        Ok(self)
    }

    /// First matching rule after the platform floor. The strict floor is
    /// absolute; local loopback needs an explicit matching static allow.
    pub fn rule_action(
        &self,
        transport: FlowTransport,
        ip: IpAddr,
        port: Option<u16>,
    ) -> Option<RuleAction> {
        let action = self
            .rules
            .iter()
            .find(|rule| {
                rule.transport.is_none_or(|value| value == transport)
                    && rule.cidr.is_none_or(|cidr| cidr.contains(ip))
                    && rule.ports.is_none_or(|ports| {
                        port.is_some_and(|port| (ports.start..=ports.end).contains(&port))
                    })
            })
            .map(|rule| rule.action);
        action?;
        if !is_floored(ip, self.floor) {
            return action;
        }
        if self.floor != FloorMode::Strict
            && is_host_loopback(ip)
            && action == Some(RuleAction::Allow)
        {
            return action;
        }
        Some(RuleAction::Deny)
    }

    pub fn allows_flow(&self, transport: FlowTransport, ip: IpAddr, port: Option<u16>) -> bool {
        match self.rule_action(transport, ip, port) {
            Some(RuleAction::Allow | RuleAction::Redirect) => true,
            Some(RuleAction::Deny) => false,
            None => self.allows(ip),
        }
    }

    /// Attach the structured decision record for a host-minted launch.
    pub fn with_mediation_audit(
        mut self,
        path: std::path::PathBuf,
        machine_id: [u8; 16],
        parent_id: [u8; 16],
    ) -> Self {
        self.decision_log = Some(Arc::new(DecisionLog {
            path,
            machine_id,
            parent_id,
            lock: Mutex::new(()),
        }));
        self
    }

    /// Append one host-observed enforcement decision. A caller admitting a
    /// flow must propagate an I/O error rather than dial without its record.
    pub fn record_decision(
        &self,
        transport: &str,
        action: &str,
        destination: &dyn std::fmt::Display,
        reason: &str,
    ) -> std::io::Result<()> {
        let Some(log) = &self.decision_log else {
            return Ok(());
        };
        let _guard = log
            .lock
            .lock()
            .map_err(|_| std::io::Error::other("mediated egress audit lock is poisoned"))?;
        const ROTATE_BYTES: u64 = 8 * 1024 * 1024;
        if std::fs::metadata(&log.path).is_ok_and(|metadata| metadata.len() >= ROTATE_BYTES) {
            std::fs::rename(&log.path, log.path.with_extension("jsonl.1"))?;
        }
        let hex_id = |bytes: &[u8; 16]| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let event = serde_json::json!({
            "timestampMs": timestamp_ms,
            "machineId": hex_id(&log.machine_id),
            "parentId": hex_id(&log.parent_id),
            "transport": transport,
            "action": action,
            "destination": destination.to_string(),
            "reason": reason,
        });
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log.path)?;
        serde_json::to_writer(&mut file, &event)?;
        file.write_all(b"\n")
    }

    /// Record one denial: a stderr line for anyone tailing the boot log, and —
    /// when a sink is attached — an appended line in the dedicated audit file,
    /// which connection chatter can never evict. Keep the marker text stable:
    /// the host's `read_egress_denials` parses `egress policy denied <op> <dest>`.
    ///
    /// The sink rotates once past 8 MiB (`.1` suffix) so a workload hammering a
    /// denied destination at packet rate can't fill the host disk.
    pub fn record_denial(&self, operation: &str, dest: &dyn std::fmt::Display) {
        let transport = match operation {
            "connect" => "tcp",
            "sendto" => "udp",
            "icmp" => "icmp",
            "resolve" => "dns",
            _ => "unknown",
        };
        if let Err(error) = self.record_decision(transport, "deny", dest, "local_policy") {
            tracing::warn!(%error, "could not record mediated egress denial");
        }
        crate::virtio_net_log!("egress policy denied {} {}", operation, dest);
        if let Some(path) = self.denial_log.as_deref() {
            append_audit_line(path, &format!("egress policy denied {operation} {dest}"));
        }
    }

    /// Attach the operator's watchlist and the file its matches are appended to.
    /// `watchlist` is the VM's copy (`EGRESS_WATCHLIST_FILE`); when there is no
    /// copy the policy observes nothing and never creates the signal log.
    pub fn with_watchlist(
        mut self,
        watchlist: std::path::PathBuf,
        signal_log: std::path::PathBuf,
    ) -> Self {
        if let Some(source) = crate::watchlist::WatchlistSource::open(watchlist) {
            self.watchlist = Some(source);
            self.signal_log = Some(Arc::new(signal_log));
        }
        self
    }

    /// Whether a watchlist is attached, so callers can skip work when not.
    pub fn watching(&self) -> bool {
        self.watchlist.is_some()
    }

    /// Note a guest DNS question for `name` against the watchlist, returning
    /// whether a `block` entry refuses it. Otherwise the policy decides.
    pub fn observe_dns(&self, name: &str) -> bool {
        let Some(watchlist) = self.watchlist.as_deref() else {
            return false;
        };
        let verdict = watchlist.observe_dns(name);
        if let Some(label) = &verdict.record {
            self.record_signal(label, &name);
        }
        verdict.block
    }

    /// Note an outbound destination against the watchlist, like `observe_dns`.
    pub fn observe_destination(&self, destination: std::net::SocketAddr) -> bool {
        let Some(watchlist) = self.watchlist.as_deref() else {
            return false;
        };
        let dest = destination.to_string();
        let verdict = watchlist.observe_ip(destination.ip(), &dest);
        if let Some(label) = &verdict.record {
            self.record_signal(label, &dest);
        }
        verdict.block
    }

    /// Record one match. Keep the marker text stable: the host's
    /// `read_egress_signals` parses `egress watch <label> <dest>`.
    fn record_signal(&self, label: &str, dest: &dyn std::fmt::Display) {
        crate::virtio_net_log!("egress watch {} {}", label, dest);
        if let Some(path) = self.signal_log.as_deref() {
            append_audit_line(path, &format!("egress watch {label} {dest}"));
        }
    }

    /// A policy that admits no destination and resolves no name (beyond the
    /// gateway's own, which the stack answers itself), for a guest that has a
    /// network device only to serve published ports.
    pub fn deny_all() -> Self {
        Self::new(Some(&[]), Some(&[]))
    }

    pub fn from_allowed_cidrs(allowed: Option<&[String]>) -> Self {
        Self::new(allowed, None)
    }

    /// Deny outbound datagrams while retaining this VM's floor and audit sink.
    /// Full TCP interception uses this for UDP and ICMP so neither protocol can
    /// bypass the interceptor, and denials remain visible in the VM audit log.
    pub fn deny_all_datagrams(&self) -> Self {
        Self {
            // No CIDR admits anything, and DNS filtering stays as it was off.
            inner: Some(Arc::new(AllowList {
                rules: RwLock::new(Arc::new(Rules {
                    cidrs: Vec::new(),
                    allowed_hosts: None,
                })),
                learned: Mutex::new(HashMap::new()),
            })),
            rules: self.rules.clone(),
            floor: self.floor,
            denial_log: self.denial_log.clone(),
            watchlist: self.watchlist.clone(),
            signal_log: self.signal_log.clone(),
            decision_log: self.decision_log.clone(),
        }
    }

    /// Whether any policy is in force (false = allow-all).
    pub fn is_restricted(&self) -> bool {
        self.inner.is_some() || !self.rules.is_empty()
    }

    /// Whether the gateway should DNS-filter queries (an allow-host list is set).
    pub fn dns_filter_active(&self) -> bool {
        self.inner
            .as_ref()
            .is_some_and(|list| list.rules().allowed_hosts.is_some())
    }

    /// Whether a DNS query for `hostname` should be forwarded upstream. With no
    /// allow-host list, all queries pass (exact + subdomain match otherwise).
    pub fn hostname_allowed(&self, hostname: &str) -> bool {
        let allowed = match &self.inner {
            None => true,
            Some(list) => list.rules().hostname_allowed(hostname),
        };
        allowed
            && self
                .record_decision("dns", "allow", &hostname, "local_policy")
                .is_ok()
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
                    .is_some_and(|list| list.rules().cidrs.iter().any(|cidr| cidr.contains(ip)));
            }
            return false;
        }
        match &self.inner {
            None => true,
            Some(list) => {
                if list.rules().cidrs.iter().any(|cidr| cidr.contains(ip)) {
                    return true;
                }
                list.learned
                    .lock()
                    .map(|learned| {
                        learned
                            .get(&ip)
                            .is_some_and(|entry| entry.expires_at > Instant::now())
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
        self.learn(None, records);
    }

    /// Learn the A/AAAA records of an allowed DNS `answer`, remembering the
    /// name asked so revoking that name later revokes these IPs too. An answer
    /// for a name revoked while the query was in flight is not learned.
    pub fn learn_dns_answer(&self, answer: &[u8]) {
        let name = dns::question_name(answer).and_then(|n| dns::normalize_hostname(&n));
        if let (Some(list), Some(name)) = (&self.inner, name.as_deref()) {
            if !list.rules().hostname_allowed(name) {
                return;
            }
        }
        self.learn(name, &dns::answer_ip_records(answer));
    }

    fn learn(&self, name: Option<String>, records: &[(IpAddr, u32)]) {
        let Some(list) = &self.inner else {
            return;
        };
        let Ok(mut learned) = list.learned.lock() else {
            return;
        };
        let now = Instant::now();
        learned.retain(|_, entry| entry.expires_at > now);
        for (ip, ttl) in records {
            let ttl = u64::from(*ttl).clamp(MIN_LEARNED_TTL, MAX_LEARNED_TTL);
            let expires_at = now + Duration::from_secs(ttl);
            let entry = learned.entry(*ip).or_insert(Learned {
                expires_at,
                name: name.clone(),
            });
            if expires_at >= entry.expires_at {
                entry.expires_at = expires_at;
                entry.name = name.clone();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_replaced_allow_list_grants_and_revokes_for_every_clone() {
        let policy = EgressPolicy::new(None, Some(&["api.github.com".into()]));
        let gateway_copy = policy.clone();
        assert!(!gateway_copy.hostname_allowed("pypi.org"));

        policy
            .replace_allow_list(&render_live_policy(
                &[],
                &["api.github.com".into(), "pypi.org".into()],
            ))
            .unwrap();
        assert!(gateway_copy.hostname_allowed("pypi.org"));
        assert!(gateway_copy.hostname_allowed("api.github.com"));

        policy
            .replace_allow_list(&render_live_policy(
                &["8.8.8.0/24".into()],
                &["pypi.org".into()],
            ))
            .unwrap();
        assert!(!gateway_copy.hostname_allowed("api.github.com"));
        assert!(gateway_copy.allows_v4(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn an_empty_allow_list_admits_nothing_and_never_lifts_the_policy() {
        let policy = EgressPolicy::new(Some(&["8.8.8.0/24".into()]), None);
        policy.replace_allow_list("# nothing allowed\n").unwrap();
        assert!(policy.is_restricted());
        assert!(!policy.allows_v4(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!policy.hostname_allowed("example.com"));
    }

    #[test]
    fn a_bad_allow_list_is_refused_and_the_current_one_kept() {
        let policy = EgressPolicy::new(None, Some(&["api.github.com".into()]));
        assert!(policy.replace_allow_list("allow everything\n").is_err());
        assert!(policy.replace_allow_list("cidr not-a-cidr\n").is_err());
        assert!(policy.hostname_allowed("api.github.com"));
        assert!(!policy.hostname_allowed("pypi.org"));
    }

    #[test]
    fn revoking_a_host_revokes_the_addresses_learned_for_it() {
        let policy = EgressPolicy::new(None, Some(&["api.github.com".into(), "pypi.org".into()]));
        let github = IpAddr::V4(Ipv4Addr::new(140, 82, 112, 6));
        let pypi = IpAddr::V4(Ipv4Addr::new(151, 101, 0, 223));
        policy.learn(Some("api.github.com".into()), &[(github, 300)]);
        policy.learn(Some("pypi.org".into()), &[(pypi, 300)]);
        assert!(policy.allows(github));

        policy
            .replace_allow_list(&render_live_policy(&[], &["pypi.org".into()]))
            .unwrap();
        assert!(!policy.allows(github));
        assert!(policy.allows(pypi));
    }

    #[test]
    fn an_unrestricted_policy_has_no_allow_list_to_replace() {
        let open = EgressPolicy::unrestricted();
        assert!(open
            .replace_allow_list(&render_live_policy(&[], &["pypi.org".into()]))
            .is_err());
        assert!(!open.is_restricted());
    }

    #[test]
    fn ordered_rules_match_transport_cidr_and_port_before_legacy_policy() {
        use smolvm_protocol::{EgressRule, FlowTransport, PortRange, RuleAction};
        let policy = EgressPolicy::from_allowed_cidrs(Some(&[]))
            .with_rules(&[
                EgressRule {
                    transport: Some(FlowTransport::Tcp),
                    cidr: Some("1.1.1.0/24".into()),
                    ports: Some(PortRange {
                        start: 443,
                        end: 443,
                    }),
                    action: RuleAction::Deny,
                },
                EgressRule {
                    transport: Some(FlowTransport::Tcp),
                    cidr: Some("1.1.1.0/24".into()),
                    ports: Some(PortRange {
                        start: 400,
                        end: 500,
                    }),
                    action: RuleAction::Allow,
                },
                EgressRule {
                    transport: Some(FlowTransport::Udp),
                    cidr: Some("1.1.1.1".into()),
                    ports: Some(PortRange {
                        start: 123,
                        end: 123,
                    }),
                    action: RuleAction::Allow,
                },
            ])
            .unwrap();
        let target = "1.1.1.1".parse().unwrap();
        assert!(!policy.allows_flow(FlowTransport::Tcp, target, Some(443)));
        assert!(policy.allows_flow(FlowTransport::Tcp, target, Some(444)));
        assert!(!policy.allows_flow(FlowTransport::Tcp, target, Some(123)));
        assert!(policy.allows_flow(FlowTransport::Udp, target, Some(123)));
        assert!(!policy.allows_flow(FlowTransport::Icmp, target, None));
    }

    #[test]
    fn invalid_rules_fail_launch_and_strict_floor_cannot_be_overridden() {
        use smolvm_protocol::{EgressRule, FlowTransport, PortRange, RuleAction};
        let allow = |cidr: &str| EgressRule {
            transport: Some(FlowTransport::Tcp),
            cidr: Some(cidr.into()),
            ports: None,
            action: RuleAction::Allow,
        };
        assert!(EgressPolicy::unrestricted()
            .with_rules(&[allow("bad-cidr")])
            .is_err());
        assert!(EgressPolicy::unrestricted()
            .with_rules(&[EgressRule {
                transport: Some(FlowTransport::Icmp),
                cidr: None,
                ports: Some(PortRange { start: 1, end: 2 }),
                action: RuleAction::Allow
            }])
            .is_err());
        assert!(EgressPolicy::unrestricted()
            .with_rules(&[EgressRule {
                transport: None,
                cidr: None,
                ports: None,
                action: RuleAction::Redirect
            }])
            .is_err());
        let mut policy = EgressPolicy::unrestricted()
            .with_rules(&[allow("127.0.0.1")])
            .unwrap();
        policy.floor = FloorMode::Strict;
        assert!(!policy.allows_flow(FlowTransport::Tcp, "127.0.0.1".parse().unwrap(), Some(80)));
    }

    #[test]
    fn intercepted_datagrams_are_denied_without_losing_the_audit_sink() {
        let original = EgressPolicy::unrestricted()
            .with_denial_log(std::path::PathBuf::from("/tmp/smolvm-egress-audit-test"));
        let datagrams = original.deny_all_datagrams();
        let destination = "1.1.1.1".parse().unwrap();
        assert!(original.allows(destination));
        assert!(!datagrams.allows(destination));
        assert!(Arc::ptr_eq(
            original.denial_log.as_ref().unwrap(),
            datagrams.denial_log.as_ref().unwrap(),
        ));
    }

    #[test]
    fn mediated_decisions_are_structured_and_dns_fails_closed_without_audit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("decisions.jsonl");
        let policy =
            EgressPolicy::unrestricted().with_mediation_audit(path.clone(), [7; 16], [3; 16]);
        assert!(policy.hostname_allowed("example.com"));
        policy
            .record_decision("tcp", "redirect", &"1.1.1.1:443", "broker_decision")
            .unwrap();
        let events: Vec<serde_json::Value> = std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["transport"], "dns");
        assert_eq!(events[1]["action"], "redirect");
        assert_eq!(events[1]["machineId"], "07".repeat(16));
        assert_eq!(events[1]["parentId"], "03".repeat(16));

        let unwritable = EgressPolicy::unrestricted().with_mediation_audit(
            dir.path().to_path_buf(),
            [7; 16],
            [0; 16],
        );
        assert!(!unwritable.hostname_allowed("example.com"));
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
    fn deny_all_admits_no_destination_and_resolves_no_name() {
        let policy = EgressPolicy::deny_all();
        assert!(policy.is_restricted());
        assert!(!policy.allows_v4(Ipv4Addr::new(1, 1, 1, 1)));
        assert!(!policy.allows_v6("2606:4700::1111".parse().unwrap()));
        assert!(policy.dns_filter_active());
        assert!(!policy.hostname_allowed("example.com"));
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
    fn unrestricted_local_floors_metadata_and_loopback() {
        // Local default (no fleet mode): the cloud-metadata link-local range AND
        // the host's own loopback are denied — a guest reaching `127.0.0.1` would
        // otherwise hit the host's loopback services. The host's LAN and CGNAT
        // stay reachable, so a local VM still behaves predictably.
        let p = EgressPolicy::unrestricted();
        assert!(!p.allows_v4(Ipv4Addr::new(169, 254, 169, 254))); // metadata: denied
        assert!(!p.allows_v4(Ipv4Addr::new(127, 0, 0, 1))); // loopback: denied
        assert!(!p.allows_v4(Ipv4Addr::new(0, 0, 0, 0))); // unspecified: denied
        assert!(p.allows_v4(Ipv4Addr::new(10, 0, 0, 4))); // LAN: reachable
        assert!(p.allows_v4(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(p.allows_v4(Ipv4Addr::new(172, 16, 0, 1)));
        assert!(p.allows_v4(Ipv4Addr::new(100, 96, 0, 1))); // CGNAT: reachable
        assert!(p.allows_v4(Ipv4Addr::new(1, 1, 1, 1))); // public: reachable
    }

    #[test]
    fn explicit_cidr_reopens_loopback_locally_but_learned_ip_does_not() {
        // A developer who deliberately allow-lists loopback CAN reach a host
        // service on 127.0.0.1 in the local modes...
        let local = EgressPolicy::new(Some(&["127.0.0.1/32".into()]), None);
        assert!(local.allows_v4(Ipv4Addr::new(127, 0, 0, 1)));
        // ...but only the named address — a sibling loopback IP stays floored.
        assert!(!local.allows_v4(Ipv4Addr::new(127, 0, 0, 2)));
        // A learned DNS answer for loopback never re-opens it (anti-rebinding):
        // only a static CIDR defeats the floor, and Strict keeps it absolute
        // (see `floor_strict_blocks_internal_and_metadata`).
        let learned = EgressPolicy::new(None, Some(&["evil.test".into()]));
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
