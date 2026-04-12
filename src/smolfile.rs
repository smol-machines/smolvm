//! Smolfile parser for declarative microVM workload configuration.
//!
//! A Smolfile is the declarative source of truth for a microVM workload.
//! This module provides the types and parser, usable by both the smolvm CLI
//! and the smol CLI.
//!
//! # Example Smolfile
//!
//! ```toml
//! image = "ghcr.io/acme/api:1.2.3"
//! entrypoint = ["/app/api"]
//! cmd = ["serve"]
//! workdir = "/app"
//! env = ["PORT=8080"]
//!
//! cpus = 2
//! memory = 1024
//! net = true
//!
//! [dev]
//! volumes = ["./src:/app"]
//! init = ["cargo build"]
//! ports = ["8080:8080"]
//!
//! [artifact]
//! cpus = 4
//! memory = 2048
//!
//! [network]
//! allow_hosts = ["pypi.org"]
//! allow_cidrs = ["10.0.0.0/8"]
//!
//! [health]
//! exec = ["curl", "-f", "http://localhost:8080/health"]
//! interval = "10s"
//! timeout = "2s"
//! retries = 3
//!
//! [restart]
//! policy = "on-failure"
//! max_retries = 5
//!
//! [auth]
//! ssh_agent = true
//! ```

use serde::Deserialize;
use std::path::Path;

// ============================================================================
// Smolfile types
// ============================================================================

/// Parsed Smolfile configuration.
///
/// The workload command model follows Docker/OCI semantics:
///
/// - `entrypoint`: the executable and its fixed leading arguments (like Dockerfile ENTRYPOINT)
/// - `cmd`: default arguments appended to entrypoint (like Dockerfile CMD)
/// - `init`: dev bootstrap commands run on every VM start (like RUN at boot, NOT like CMD)
///
/// When set, `entrypoint` and `cmd` override the base image's OCI config values.
/// If neither is set, the image's built-in entrypoint and cmd are used.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Smolfile {
    /// OCI image (optional — omit for bare Alpine VM).
    pub image: Option<String>,
    /// Executable and fixed leading arguments (overrides image ENTRYPOINT).
    #[serde(default)]
    pub entrypoint: Vec<String>,
    /// Default arguments appended to entrypoint (overrides image CMD).
    #[serde(default)]
    pub cmd: Vec<String>,
    /// Environment variables as `KEY=VALUE` strings.
    #[serde(default)]
    pub env: Vec<String>,
    /// Working directory inside the VM.
    pub workdir: Option<String>,

    // Resources
    /// Number of vCPUs.
    pub cpus: Option<u8>,
    /// Memory in MiB.
    pub memory: Option<u32>,
    /// Enable outbound networking.
    pub net: Option<bool>,
    /// Enable GPU acceleration (Vulkan via virtio-gpu).
    pub gpu: Option<bool>,
    /// Storage disk size in GiB.
    pub storage: Option<u64>,
    /// Overlay disk size in GiB.
    pub overlay: Option<u64>,

    // Legacy top-level fields (prefer [dev] section)
    /// Port mappings (e.g., `["8080:8080"]`).
    #[serde(default)]
    pub ports: Vec<String>,
    /// Volume mounts (e.g., `["./src:/app"]`).
    #[serde(default)]
    pub volumes: Vec<String>,
    /// Init commands run on every VM start.
    #[serde(default)]
    pub init: Vec<String>,

    // Profiles
    /// Artifact/pack overrides for `smol pack create`.
    pub artifact: Option<ArtifactConfig>,
    /// Alias for `artifact`.
    pub pack: Option<ArtifactConfig>,
    /// Local development profile.
    pub dev: Option<DevConfig>,

    // Sections
    /// Network egress policy.
    pub network: Option<NetworkConfig>,
    /// Health check configuration.
    pub health: Option<HealthConfig>,
    /// Restart policy.
    pub restart: Option<RestartSmolfileConfig>,
    /// Credential forwarding.
    pub auth: Option<AuthConfig>,
    /// Service metadata for deployment.
    pub service: Option<ServiceConfig>,
}

/// Network policy — egress filtering by hostname and/or CIDR.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    /// Allowed egress hostnames (resolved to IPs at VM start).
    #[serde(default)]
    pub allow_hosts: Vec<String>,
    /// Allowed egress CIDR ranges (e.g., `["10.0.0.0/8", "1.1.1.1"]`).
    #[serde(default)]
    pub allow_cidrs: Vec<String>,
}

/// Credential forwarding configuration.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    /// Forward host SSH agent into the VM.
    pub ssh_agent: Option<bool>,
}

/// Distribution-specific overrides for packed artifacts.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ArtifactConfig {
    /// Override vCPU count for artifact.
    pub cpus: Option<u8>,
    /// Override memory (MiB) for artifact.
    pub memory: Option<u32>,
    /// Override entrypoint for artifact.
    #[serde(default)]
    pub entrypoint: Vec<String>,
    /// Override cmd for artifact.
    #[serde(default)]
    pub cmd: Vec<String>,
    /// Target OCI platform (e.g., `linux/amd64`).
    pub oci_platform: Option<String>,
}

/// Local development profile.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DevConfig {
    /// Volume mounts for development (e.g., `["./src:/app"]`).
    #[serde(default)]
    pub volumes: Vec<String>,
    /// Development-only environment variables.
    #[serde(default)]
    pub env: Vec<String>,
    /// Init commands run on every VM start.
    #[serde(default)]
    pub init: Vec<String>,
    /// Development working directory override.
    pub workdir: Option<String>,
    /// Port mappings for development (e.g., `["8080:8080"]`).
    #[serde(default)]
    pub ports: Vec<String>,
}

/// Health check configuration.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct HealthConfig {
    /// Health check command (run via `sh -c`).
    #[serde(default)]
    pub exec: Vec<String>,
    /// Check interval (e.g., `"10s"`, `"1m"`).
    pub interval: Option<String>,
    /// Check timeout (e.g., `"2s"`).
    pub timeout: Option<String>,
    /// Number of consecutive failures before unhealthy.
    pub retries: Option<u32>,
    /// Grace period before first health check (e.g., `"20s"`).
    pub startup_grace: Option<String>,
}

/// Restart policy configuration.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RestartSmolfileConfig {
    /// Policy: `"never"`, `"always"`, `"on-failure"`, `"unless-stopped"`.
    pub policy: Option<String>,
    /// Maximum restart attempts.
    pub max_retries: Option<u32>,
    /// Maximum backoff duration between restarts (e.g., `"60s"`, `"5m"`).
    pub max_backoff: Option<String>,
}

/// Service metadata for deployment.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    /// Port the service listens on inside the VM.
    pub port: Option<u16>,
    /// Protocol (`"http"`, `"tcp"`).
    pub protocol: Option<String>,
    /// Alternate field name for port.
    pub listen: Option<u16>,
}

// ============================================================================
// Loading
// ============================================================================

/// Load and parse a Smolfile from the given path.
pub fn load(path: &Path) -> crate::Result<Smolfile> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| crate::Error::config("load smolfile", format!("{}: {}", path.display(), e)))?;

    toml::from_str(&content)
        .map_err(|e| crate::Error::config("parse smolfile", format!("{}: {}", path.display(), e)))
}

// ============================================================================
// Network helpers
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

    // Resolve hostname
    let addrs: Vec<String> = format!("{}:0", host)
        .to_socket_addrs()
        .map_err(|e| format!("failed to resolve '{}': {}", host, e))?
        .map(|addr| format!("{}/32", addr.ip()))
        .collect();

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

/// Parse a duration string like `"10s"`, `"5m"`, `"2h"` to seconds.
pub fn parse_duration_secs(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(n) = s.strip_suffix('s') {
        n.parse().ok()
    } else if let Some(n) = s.strip_suffix('m') {
        n.parse::<u64>().ok().map(|n| n * 60)
    } else if let Some(n) = s.strip_suffix('h') {
        n.parse::<u64>().ok().map(|n| n * 3600)
    } else {
        s.parse().ok() // bare number = seconds
    }
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
    fn parse_duration_secs_formats() {
        assert_eq!(parse_duration_secs("10s"), Some(10));
        assert_eq!(parse_duration_secs("5m"), Some(300));
        assert_eq!(parse_duration_secs("2h"), Some(7200));
        assert_eq!(parse_duration_secs("42"), Some(42));
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
