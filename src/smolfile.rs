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

/// Resolve a hostname to IP addresses and return as /32 CIDRs.
///
/// Resolution happens on the host at VM start time. Rejects hostnames with
/// `:port` suffixes — port filtering is not supported by the TSI egress policy.
pub fn resolve_host_to_cidrs(host: &str) -> Result<Vec<String>, String> {
    use std::net::{IpAddr, ToSocketAddrs};

    // Reject host:port syntax
    if host.contains(':') {
        return Err(format!(
            "invalid hostname '{}': port suffixes are not supported. \
             Use the hostname only (all ports are allowed to resolved IPs).",
            host
        ));
    }

    // Try parsing as bare IP first
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![format!("{}/32", ip)]);
    }

    // Resolve hostname with a timeout to avoid hanging on slow/unreachable DNS.
    let host_owned = host.to_string();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = format!("{}:0", host_owned).to_socket_addrs().map(|addrs| {
            addrs
                .map(|addr| format!("{}/32", addr.ip()))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_host_bare_ip() {
        let cidrs = resolve_host_to_cidrs("1.2.3.4").unwrap();
        assert_eq!(cidrs, vec!["1.2.3.4/32"]);
    }

    #[test]
    fn resolve_host_rejects_port_suffix() {
        let err = resolve_host_to_cidrs("example.com:443").unwrap_err();
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
}
