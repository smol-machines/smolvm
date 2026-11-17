//! Smolfile support for smolvm.
//!
//! Re-exports all types and parsing from the standalone [`smolfile`] crate,
//! plus smolvm-specific helpers (file loading with smolvm error types,
//! network policy resolution).
//!
//! See the [`smolfile`] crate documentation for the full Smolfile specification.

// Re-export everything from the standalone crate.
pub use smolfile::*;

use std::path::Path;

// ============================================================================
// smolvm-specific loading (wraps crate error into smolvm::Error)
// ============================================================================

/// Load and parse a Smolfile from the given path.
///
/// This is a convenience wrapper that converts [`smolfile::SmolfileError`]
/// into [`crate::Error`] for use within smolvm.
pub fn load(path: &Path) -> crate::Result<Smolfile> {
    smolfile::load(path).map_err(|e| crate::Error::config("load smolfile", e.to_string()))
}

// ============================================================================
// Network helpers (smolvm-specific, depend on ipnet and std::net)
// ============================================================================

/// Resolve a hostname or IP address to CIDRs suitable for TSI egress policy.
///
/// IPv4 addresses become `/32` CIDRs; IPv6 addresses become `/128` CIDRs.
/// Hostnames are resolved via the host DNS at VM start time and each result
/// address is formatted with the correct prefix length.
///
/// Rejects `host:port` syntax — port filtering is not supported by the TSI
/// egress policy (all ports to a resolved IP are implicitly allowed).
pub fn resolve_host_to_cidrs(host: &str) -> Result<Vec<String>, String> {
    use ipnet::IpNet;
    use std::net::{IpAddr, ToSocketAddrs};

    // Try parsing as a bare IP first — must come before the ':' check so that
    // IPv6 addresses like "::1" or "2001:db8::1" (which contain ':') are
    // handled correctly rather than being rejected as host:port syntax.
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![IpNet::from(ip).to_string()]);
    }

    // Reject host:port syntax (e.g. "example.com:443").
    if host.contains(':') {
        return Err(format!(
            "invalid hostname '{}': port suffixes are not supported. \
             Use the hostname only (all ports are allowed to resolved IPs).",
            host
        ));
    }

    // Resolve hostname with a timeout to avoid hanging on slow/unreachable DNS.
    let host_owned = host.to_string();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = format!("{}:0", host_owned).to_socket_addrs().map(|addrs| {
            addrs
                .map(|addr| IpNet::from(addr.ip()).to_string())
                .collect::<Vec<_>>()
        });
        let _ = tx.send(result);
    });

    let addrs: Vec<String> = rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .map_err(|_| format!("DNS resolution for '{}' timed out after 10 seconds", host))?
        .map_err(|e| format!("failed to resolve '{}': {}", host, e))?;

    if addrs.is_empty() {
        return Err(format!("'{}' resolved to no addresses", host));
    }

    Ok(addrs)
}

/// Parse and validate a CIDR specification (e.g., `"10.0.0.0/8"`, `"1.1.1.1"`).
///
/// Accepts `IP/prefix` or bare `IP` (auto-appends /32 for IPv4, /128 for IPv6).
/// Returns the normalized CIDR string.
pub fn parse_cidr(s: &str) -> Result<String, String> {
    use ipnet::IpNet;
    use std::net::IpAddr;

    let net: IpNet = match s.parse::<IpNet>() {
        Ok(net) => net,
        Err(_) => match s.parse::<IpAddr>() {
            Ok(ip) => IpNet::from(ip),
            Err(_) => {
                return Err(format!(
                    "invalid CIDR '{}': expected format like 10.0.0.0/8 or 1.1.1.1",
                    s
                ))
            }
        },
    };

    Ok(net.to_string())
}

#[allow(missing_docs)]
pub fn parse_allow_udp(s: &str) -> Result<smolvm_protocol::EgressRule, String> {
    let invalid = |reason: String| {
        format!(
            "invalid UDP allow '{s}': {reason}; expected CIDR[:PORT[-END]], like 10.0.0.0/8, \
             1.1.1.1:123, 192.0.2.0/24:3478-3480 or [2001:db8::1]:443"
        )
    };
    let (cidr, ports) = if let Some(bracketed) = s.strip_prefix('[') {
        let (inside, rest) = bracketed
            .split_once(']')
            .ok_or_else(|| invalid("missing ']'".to_string()))?;
        let ports = match rest {
            "" => None,
            _ => Some(
                rest.strip_prefix(':')
                    .ok_or_else(|| invalid("expected ':' after ']'".to_string()))?,
            ),
        };
        (parse_cidr(inside).map_err(invalid)?, ports)
    } else if let Ok(cidr) = parse_cidr(s) {
        (cidr, None)
    } else {
        let (address, ports) = s
            .rsplit_once(':')
            .ok_or_else(|| invalid("not a CIDR".to_string()))?;
        (parse_cidr(address).map_err(invalid)?, Some(ports))
    };
    let ports = ports
        .map(|spec| parse_udp_port_range(spec).map_err(invalid))
        .transpose()?;
    Ok(smolvm_protocol::EgressRule {
        transport: Some(smolvm_protocol::FlowTransport::Udp),
        cidr: Some(cidr),
        ports,
        action: smolvm_protocol::RuleAction::Allow,
    })
}

fn parse_udp_port_range(spec: &str) -> Result<smolvm_protocol::PortRange, String> {
    let port = |text: &str| match text.parse::<u16>() {
        Ok(0) | Err(_) => Err(format!("'{text}' is not a port from 1 to 65535")),
        Ok(port) => Ok(port),
    };
    let (start, end) = match spec.split_once('-') {
        Some((start, end)) => (port(start)?, port(end)?),
        None => {
            let single = port(spec)?;
            (single, single)
        }
    };
    if end < start {
        return Err(format!("port range {start}-{end} ends before it starts"));
    }
    Ok(smolvm_protocol::PortRange { start, end })
}

#[allow(missing_docs)]
pub fn udp_allow_label(rule: &smolvm_protocol::EgressRule) -> String {
    let cidr = rule.cidr.as_deref().unwrap_or("any");
    match rule.ports {
        None => cidr.to_string(),
        Some(ports) if ports.start == ports.end => format!("{cidr}:{}", ports.start),
        Some(ports) => format!("{cidr}:{}-{}", ports.start, ports.end),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_host_bare_ipv4() {
        let cidrs = resolve_host_to_cidrs("1.2.3.4").unwrap();
        assert_eq!(cidrs, vec!["1.2.3.4/32"]);
    }

    #[test]
    fn resolve_host_bare_ipv6() {
        let cidrs = resolve_host_to_cidrs("::1").unwrap();
        assert_eq!(cidrs, vec!["::1/128"]);

        let cidrs = resolve_host_to_cidrs("2001:db8::1").unwrap();
        assert_eq!(cidrs, vec!["2001:db8::1/128"]);
    }

    #[test]
    fn resolve_host_rejects_port_suffix() {
        let err = resolve_host_to_cidrs("example.com:443").unwrap_err();
        assert!(err.contains("port suffixes are not supported"), "{}", err);

        // Bracketed IPv6 with port must also be rejected.
        let err = resolve_host_to_cidrs("[::1]:80").unwrap_err();
        assert!(err.contains("port suffixes are not supported"), "{}", err);
    }

    #[test]
    fn parse_cidr_valid() {
        assert_eq!(parse_cidr("10.0.0.0/8").unwrap(), "10.0.0.0/8");
        assert_eq!(parse_cidr("1.1.1.1").unwrap(), "1.1.1.1/32");
    }

    #[test]
    fn parse_cidr_invalid() {
        assert!(parse_cidr("not-a-cidr").is_err());
    }

    #[test]
    fn load_basic_smolfile() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Smolfile");
        std::fs::write(
            &path,
            r#"
image = "alpine"
cpus = 2
memory = 1024
net = true

[dev]
volumes = ["./src:/app"]
init = ["echo hello"]
"#,
        )
        .unwrap();
        let sf = load(&path).unwrap();
        assert_eq!(sf.image.as_deref(), Some("alpine"));
        assert_eq!(sf.cpus, Some(2));
        assert_eq!(sf.dev.unwrap().volumes, vec!["./src:/app"]);
    }

    #[test]
    fn smolfile_gpu_field() {
        let dir = tempfile::tempdir().unwrap();

        // With gpu = true
        let path = dir.path().join("gpu.smolfile");
        std::fs::write(&path, "image = \"alpine\"\ngpu = true\n").unwrap();
        let sf = load(&path).unwrap();
        assert_eq!(sf.gpu, Some(true));

        // Without gpu field (defaults to None)
        let path = dir.path().join("nogpu.smolfile");
        std::fs::write(&path, "image = \"alpine\"\n").unwrap();
        let sf = load(&path).unwrap();
        assert_eq!(sf.gpu, None);

        // With gpu = false
        let path = dir.path().join("gpuoff.smolfile");
        std::fs::write(&path, "image = \"alpine\"\ngpu = false\n").unwrap();
        let sf = load(&path).unwrap();
        assert_eq!(sf.gpu, Some(false));
    }

    fn udp_allow(cidr: &str, ports: Option<(u16, u16)>) -> smolvm_protocol::EgressRule {
        smolvm_protocol::EgressRule {
            transport: Some(smolvm_protocol::FlowTransport::Udp),
            cidr: Some(cidr.to_string()),
            ports: ports.map(|(start, end)| smolvm_protocol::PortRange { start, end }),
            action: smolvm_protocol::RuleAction::Allow,
        }
    }

    #[test]
    fn allow_udp_takes_a_cidr_with_an_optional_port_or_range() {
        assert_eq!(
            parse_allow_udp("10.0.0.0/8").unwrap(),
            udp_allow("10.0.0.0/8", None)
        );
        assert_eq!(
            parse_allow_udp("1.1.1.1:123").unwrap(),
            udp_allow("1.1.1.1/32", Some((123, 123)))
        );
        assert_eq!(
            parse_allow_udp("192.0.2.0/24:3478-3480").unwrap(),
            udp_allow("192.0.2.0/24", Some((3478, 3480)))
        );
        assert_eq!(
            parse_allow_udp("2001:db8::/32").unwrap(),
            udp_allow("2001:db8::/32", None)
        );
        assert_eq!(
            parse_allow_udp("2001:db8::1").unwrap(),
            udp_allow("2001:db8::1/128", None)
        );
        assert_eq!(
            parse_allow_udp("2001:db8::/32:443").unwrap(),
            udp_allow("2001:db8::/32", Some((443, 443)))
        );
        assert_eq!(
            parse_allow_udp("[2001:db8::1]").unwrap(),
            udp_allow("2001:db8::1/128", None)
        );
        assert_eq!(
            parse_allow_udp("[2001:db8::1]:443").unwrap(),
            udp_allow("2001:db8::1/128", Some((443, 443)))
        );
        assert_eq!(
            parse_allow_udp("[2001:db8::/32]:1000-2000").unwrap(),
            udp_allow("2001:db8::/32", Some((1000, 2000)))
        );
    }

    #[test]
    fn allow_udp_rejects_a_bad_cidr_or_port() {
        for value in [
            "",
            "10.0.0.0/33",
            "example.com",
            "example.com:53",
            "1.1.1.1:",
            "1.1.1.1:0",
            "1.1.1.1:65536",
            "1.1.1.1:dns",
            "1.1.1.1:500-400",
            "1.1.1.1:0-10",
            "1.1.1.1:10-",
            "[2001:db8::1]53",
            "[2001:db8::1:53",
        ] {
            let error = match parse_allow_udp(value) {
                Ok(rule) => panic!("'{value}' must be rejected, got {rule:?}"),
                Err(error) => error,
            };
            assert!(error.contains("CIDR[:PORT[-END]]"), "{value}: {error}");
        }
    }
}
