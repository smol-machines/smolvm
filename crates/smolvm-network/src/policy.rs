//! Egress policy support for the host-side virtio-net runtime.

use ipnet::IpNet;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::{Arc, RwLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const EGRESS_REFRESH_ENV: &str = "SMOLVM_EGRESS_REFRESH_SECS";
const DEFAULT_EGRESS_REFRESH_SECS: u64 = 5 * 60;

const DNS_HEADER_LEN: usize = 12;
const DNS_FLAGS_HIGH_OFFSET: usize = 2;
const DNS_FLAGS_LOW_OFFSET: usize = 3;
const DNS_QUESTION_COUNT_OFFSET: usize = 4;
const DNS_QUESTION_START: usize = DNS_HEADER_LEN;
const DNS_RESPONSE_COUNT_START: usize = 6;
const DNS_RESPONSE_COUNT_END: usize = DNS_HEADER_LEN;
const DNS_ROOT_LABEL: u8 = 0;
const DNS_LABEL_POINTER_MASK: u8 = 0xC0;
const DNS_RESPONSE_FLAG: u8 = 0x80;
const DNS_OPCODE_BITS: u8 = 0x78;
const DNS_LOW_FLAG_BITS: u8 = 0xF0;
const DNS_RECURSION_AVAILABLE_FLAG: u8 = 0x80;

#[derive(Debug, Clone, Copy)]
enum DnsResponseCode {
    ServFail = 0x02,
    NxDomain = 0x03,
}

impl DnsResponseCode {
    fn bits(self) -> u8 {
        self as u8
    }
}

/// Launch-time egress policy inputs for the virtio-net runtime.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EgressPolicy {
    /// Allowed guest egress destination ranges. `None` means unrestricted;
    /// `Some([])` means no TCP destinations are allowed.
    pub allowed_cidrs: Option<Vec<String>>,
    /// Allowed DNS hostnames. When set, guest DNS queries for other names get
    /// NXDOMAIN responses from the gateway.
    pub dns_filter_hosts: Option<Vec<String>>,
}

/// Runtime-ready egress policy.
#[derive(Debug)]
pub(crate) struct ResolvedEgressPolicy {
    allowed_cidrs: Option<AllowedCidrs>,
    dns_filter: Option<DnsFilter>,
}

impl ResolvedEgressPolicy {
    /// Compile launch-time strings into efficient runtime checks.
    pub(crate) fn compile(policy: EgressPolicy) -> Result<Self, String> {
        let dns_filter_hosts = policy.dns_filter_hosts.unwrap_or_default();
        let has_cidr_policy = policy.allowed_cidrs.is_some() || !dns_filter_hosts.is_empty();

        let allowed_cidrs = if has_cidr_policy {
            Some(AllowedCidrs::new(
                policy.allowed_cidrs.unwrap_or_default(),
                dns_filter_hosts.clone(),
            )?)
        } else {
            None
        };

        let dns_filter = if dns_filter_hosts.is_empty() {
            None
        } else {
            Some(DnsFilter::new(dns_filter_hosts))
        };

        Ok(Self {
            allowed_cidrs,
            dns_filter,
        })
    }

    /// Whether a guest TCP destination IP is allowed.
    pub(crate) fn allows_ip(&self, ip: IpAddr) -> bool {
        match &self.allowed_cidrs {
            None => true,
            Some(cidrs) => cidrs.allows_ip(ip),
        }
    }

    /// Filter a raw DNS query when hostname policy is configured.
    ///
    /// Returns `None` when DNS filtering is not active.
    pub(crate) fn filter_dns_query(&self, query: &[u8]) -> Option<DnsQueryAction> {
        self.dns_filter
            .as_ref()
            .map(|filter| filter.classify_query(query))
    }
}

/// Policy result for one raw DNS query.
pub(crate) enum DnsQueryAction {
    /// The query is allowed and should be forwarded upstream.
    Forward,
    /// Return this DNS response to the guest without forwarding.
    Respond(Vec<u8>),
}

#[derive(Debug)]
struct AllowedCidrs {
    static_cidrs: Vec<IpNet>,
    _refresh_thread: Option<RefreshThread>,
    refreshed_host_cidrs: Option<Arc<RwLock<Vec<IpNet>>>>,
}

impl AllowedCidrs {
    fn new(static_cidrs: Vec<String>, refresh_hosts: Vec<String>) -> Result<Self, String> {
        let static_cidrs = static_cidrs
            .into_iter()
            .map(|cidr| parse_cidr_or_ip(&cidr))
            .collect::<Result<Vec<_>, _>>()?;

        let (refreshed_host_cidrs, refresh_thread) = if refresh_hosts.is_empty() {
            (None, None)
        } else {
            let initial = resolve_hosts_to_ipnets(&refresh_hosts);
            let refreshed = Arc::new(RwLock::new(initial));
            let refresh_thread = spawn_egress_refresh_thread(refresh_hosts, refreshed.clone());
            (Some(refreshed), refresh_thread)
        };

        Ok(Self {
            static_cidrs,
            _refresh_thread: refresh_thread,
            refreshed_host_cidrs,
        })
    }

    fn allows_ip(&self, ip: IpAddr) -> bool {
        self.static_cidrs.iter().any(|cidr| cidr.contains(&ip))
            || self.refreshed_host_cidrs.as_ref().is_some_and(|cidrs| {
                cidrs
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .iter()
                    .any(|cidr| cidr.contains(&ip))
            })
    }
}

struct RefreshThread {
    shutdown_tx: Sender<()>,
    handle: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for RefreshThread {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshThread").finish_non_exhaustive()
    }
}

impl Drop for RefreshThread {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(());
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[derive(Debug, Clone)]
struct DnsFilter {
    allowed: Vec<String>,
}

impl DnsFilter {
    fn new(allowed: Vec<String>) -> Self {
        Self { allowed }
    }

    fn is_allowed(&self, domain: &str) -> bool {
        let domain = domain.trim_end_matches('.');
        self.allowed.iter().any(|pattern| {
            let pattern = pattern.trim_end_matches('.');
            domain.eq_ignore_ascii_case(pattern)
                || domain
                    .to_ascii_lowercase()
                    .ends_with(&format!(".{}", pattern.to_ascii_lowercase()))
        })
    }

    fn classify_query(&self, query: &[u8]) -> DnsQueryAction {
        let Some(domain) = extract_domain_from_query(query) else {
            return DnsQueryAction::Respond(build_error_response(query, DnsResponseCode::ServFail));
        };

        if !self.is_allowed(&domain) {
            return DnsQueryAction::Respond(build_error_response(query, DnsResponseCode::NxDomain));
        }

        DnsQueryAction::Forward
    }
}

fn parse_cidr_or_ip(value: &str) -> Result<IpNet, String> {
    value
        .parse::<IpNet>()
        .or_else(|_| value.parse::<IpAddr>().map(IpNet::from))
        .map_err(|_| format!("invalid CIDR or IP address in egress policy: {value}"))
}

fn resolve_host_to_ipnets(host: &str) -> Result<Vec<IpNet>, String> {
    if host.contains(':') {
        return Err(format!(
            "invalid hostname '{host}': port suffixes are not supported"
        ));
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![IpNet::from(ip)]);
    }

    let mut ipnets = Vec::new();
    for addr in format!("{host}:0")
        .to_socket_addrs()
        .map_err(|e| format!("failed to resolve '{host}': {e}"))?
    {
        push_unique_ipnet(&mut ipnets, IpNet::from(addr.ip()));
    }

    if ipnets.is_empty() {
        return Err(format!("'{host}' resolved to no IP addresses"));
    }

    Ok(ipnets)
}

fn resolve_hosts_to_ipnets(hosts: &[String]) -> Vec<IpNet> {
    let mut fresh = Vec::new();
    for host in hosts {
        match resolve_host_to_ipnets(host) {
            Ok(ipnets) => {
                for ipnet in ipnets {
                    push_unique_ipnet(&mut fresh, ipnet);
                }
            }
            Err(err) => {
                tracing::warn!(
                    host = %host,
                    error = %err,
                    "virtio-net egress refresh: resolve failed"
                );
            }
        }
    }
    fresh
}

fn push_unique_ipnet(ipnets: &mut Vec<IpNet>, ipnet: IpNet) {
    if !ipnets.contains(&ipnet) {
        ipnets.push(ipnet);
    }
}

fn spawn_egress_refresh_thread(
    hosts: Vec<String>,
    cidrs: Arc<RwLock<Vec<IpNet>>>,
) -> Option<RefreshThread> {
    let (shutdown_tx, shutdown_rx) = mpsc::channel();
    let spawn_result = thread::Builder::new()
        .name("virtio-net-egress-refresh".into())
        .spawn(move || {
            let refresh_interval = Duration::from_secs(
                std::env::var(EGRESS_REFRESH_ENV)
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .filter(|secs| *secs > 0)
                    .unwrap_or(DEFAULT_EGRESS_REFRESH_SECS),
            );

            loop {
                match shutdown_rx.recv_timeout(refresh_interval) {
                    Ok(()) | Err(RecvTimeoutError::Disconnected) => return,
                    Err(RecvTimeoutError::Timeout) => {}
                }

                let fresh = resolve_hosts_to_ipnets(&hosts);
                if fresh.is_empty() {
                    tracing::warn!(
                        "virtio-net egress refresh resolved no hosts; keeping previous CIDR list"
                    );
                    continue;
                }

                let mut guard = cidrs.write().unwrap_or_else(|e| e.into_inner());
                *guard = fresh;
            }
        });

    match spawn_result {
        Ok(handle) => Some(RefreshThread {
            shutdown_tx,
            handle: Some(handle),
        }),
        Err(err) => {
            tracing::warn!(error = %err, "virtio-net egress refresh spawn failed");
            None
        }
    }
}

fn extract_domain_from_query(packet: &[u8]) -> Option<String> {
    if packet.len() < DNS_HEADER_LEN {
        return None;
    }

    if dns_question_count(packet) == 0 {
        return None;
    }

    let mut pos = DNS_QUESTION_START;
    let mut labels = Vec::new();

    loop {
        if pos >= packet.len() {
            return None;
        }

        let label_len = packet[pos];
        if label_len == DNS_ROOT_LABEL {
            break;
        }
        if is_dns_compression_pointer(label_len) {
            return None;
        }

        pos += 1;
        let label_len = usize::from(label_len);
        if pos + label_len > packet.len() {
            return None;
        }

        let label = std::str::from_utf8(&packet[pos..pos + label_len]).ok()?;
        labels.push(label.to_string());
        pos += label_len;
    }

    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

fn dns_question_count(packet: &[u8]) -> u16 {
    u16::from_be_bytes([
        packet[DNS_QUESTION_COUNT_OFFSET],
        packet[DNS_QUESTION_COUNT_OFFSET + 1],
    ])
}

fn is_dns_compression_pointer(label_len: u8) -> bool {
    label_len & DNS_LABEL_POINTER_MASK == DNS_LABEL_POINTER_MASK
}

fn build_error_response(query: &[u8], rcode: DnsResponseCode) -> Vec<u8> {
    if query.len() < DNS_HEADER_LEN {
        return vec![];
    }

    let mut response = query.to_vec();

    // Turn the copied query into a DNS response while preserving the query opcode.
    response[DNS_FLAGS_HIGH_OFFSET] =
        DNS_RESPONSE_FLAG | (response[DNS_FLAGS_HIGH_OFFSET] & DNS_OPCODE_BITS);

    // Preserve the high flag bits in the low flag byte and set the DNS response code.
    response[DNS_FLAGS_LOW_OFFSET] =
        (response[DNS_FLAGS_LOW_OFFSET] & DNS_LOW_FLAG_BITS) | rcode.bits();

    // Tell the guest resolver recursion is available, matching normal recursive DNS replies.
    response[DNS_FLAGS_LOW_OFFSET] |= DNS_RECURSION_AVAILABLE_FLAG;

    // Error responses answer the original question but carry no DNS records.
    response[DNS_RESPONSE_COUNT_START..DNS_RESPONSE_COUNT_END].fill(0);
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_query(domain: &str) -> Vec<u8> {
        let mut packet = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in domain.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0x00);
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        packet
    }

    #[test]
    fn cidr_policy_allows_matching_ips() {
        let policy = ResolvedEgressPolicy::compile(EgressPolicy {
            allowed_cidrs: Some(vec!["10.0.0.0/8".into(), "1.1.1.1".into()]),
            dns_filter_hosts: None,
        })
        .unwrap();

        assert!(policy.allows_ip("10.2.3.4".parse().unwrap()));
        assert!(policy.allows_ip("1.1.1.1".parse().unwrap()));
        assert!(!policy.allows_ip("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn empty_cidr_policy_denies_tcp_destinations() {
        let policy = ResolvedEgressPolicy::compile(EgressPolicy {
            allowed_cidrs: Some(vec![]),
            dns_filter_hosts: None,
        })
        .unwrap();

        assert!(!policy.allows_ip("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn invalid_cidr_is_rejected() {
        let err = ResolvedEgressPolicy::compile(EgressPolicy {
            allowed_cidrs: Some(vec!["not-a-cidr".into()]),
            dns_filter_hosts: None,
        })
        .unwrap_err();

        assert!(err.contains("invalid CIDR or IP address"));
    }

    #[test]
    fn hostname_policy_restricts_tcp_destinations_without_static_cidrs() {
        let policy = ResolvedEgressPolicy::compile(EgressPolicy {
            allowed_cidrs: None,
            dns_filter_hosts: Some(vec!["1.1.1.1".into()]),
        })
        .unwrap();

        assert!(policy.allows_ip("1.1.1.1".parse().unwrap()));
        assert!(!policy.allows_ip("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn hostname_policy_extends_static_cidrs() {
        let policy = ResolvedEgressPolicy::compile(EgressPolicy {
            allowed_cidrs: Some(vec!["10.0.0.0/8".into()]),
            dns_filter_hosts: Some(vec!["1.1.1.1".into()]),
        })
        .unwrap();

        assert!(policy.allows_ip("10.2.3.4".parse().unwrap()));
        assert!(policy.allows_ip("1.1.1.1".parse().unwrap()));
        assert!(!policy.allows_ip("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn dns_filter_matches_exact_and_subdomain_names() {
        let filter = DnsFilter::new(vec!["api.example.com".into()]);

        assert!(filter.is_allowed("api.example.com"));
        assert!(filter.is_allowed("v1.api.example.com"));
        assert!(!filter.is_allowed("example.com"));
    }

    #[test]
    fn dns_filter_blocks_disallowed_queries() {
        let policy = ResolvedEgressPolicy::compile(EgressPolicy {
            allowed_cidrs: None,
            dns_filter_hosts: Some(vec!["allowed.example.com".into()]),
        })
        .unwrap();

        let action = policy
            .filter_dns_query(&build_query("blocked.example.com"))
            .unwrap();

        let DnsQueryAction::Respond(response) = action else {
            panic!("blocked query should return a synthetic DNS response");
        };
        assert_eq!(response[3] & 0x0F, 0x03);
    }

    #[test]
    fn dns_filter_forwards_allowed_queries() {
        let policy = ResolvedEgressPolicy::compile(EgressPolicy {
            allowed_cidrs: None,
            dns_filter_hosts: Some(vec!["allowed.example.com".into()]),
        })
        .unwrap();

        assert!(matches!(
            policy
                .filter_dns_query(&build_query("allowed.example.com"))
                .unwrap(),
            DnsQueryAction::Forward
        ));
    }
}
