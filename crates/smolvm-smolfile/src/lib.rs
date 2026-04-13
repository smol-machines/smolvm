//! Smolfile specification and parser.
//!
//! # Overview
//!
//! A **Smolfile** is a TOML file that declaratively defines a microVM workload.
//! It is the single source of truth for what image to run, how to configure it,
//! and how to package it for distribution.
//!
//! The file is named `Smolfile` (no extension) and lives in the project root.
//!
//! # Specification
//!
//! ## Top-level Fields
//!
//! | Field | Type | Required | Description |
//! |-------|------|----------|-------------|
//! | `image` | string | No | OCI image reference. Omit for bare Alpine VM. |
//! | `entrypoint` | string[] | No | Executable + fixed args. Overrides image ENTRYPOINT. |
//! | `cmd` | string[] | No | Default args appended to entrypoint. Overrides image CMD. |
//! | `env` | string[] | No | Environment variables as `KEY=VALUE`. |
//! | `workdir` | string | No | Working directory inside the VM. |
//! | `cpus` | int | No | Number of vCPUs (default: 1). |
//! | `memory` | int | No | Memory in MiB (default: 256). |
//! | `net` | bool | No | Enable outbound networking via NAT. |
//! | `storage` | int | No | Storage disk size in GiB. |
//! | `overlay` | int | No | Overlay disk size in GiB. |
//! | `ports` | string[] | No | Port mappings (`"host:guest"`). Prefer `[dev] ports`. |
//! | `volumes` | string[] | No | Volume mounts (`"host:guest"`). Prefer `[dev] volumes`. |
//! | `init` | string[] | No | Commands run on every VM start. Prefer `[dev] init`. |
//!
//! ## Sections
//!
//! ### `[dev]` — Local development overrides
//!
//! Applied when running `smol up`. Not included in packed artifacts.
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `volumes` | string[] | Bind mounts (`"./src:/app"`) |
//! | `env` | string[] | Dev-only environment variables |
//! | `init` | string[] | Bootstrap commands run on start |
//! | `workdir` | string | Dev working directory override |
//! | `ports` | string[] | Port mappings for development |
//!
//! ### `[artifact]` — Pack/distribution overrides
//!
//! Applied when running `smol pack create`. Overrides top-level values for the
//! packaged `.smolmachine` artifact.
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `cpus` | int | vCPU count for packed artifact |
//! | `memory` | int | Memory (MiB) for packed artifact |
//! | `entrypoint` | string[] | Entrypoint override for artifact |
//! | `cmd` | string[] | Cmd override for artifact |
//! | `oci_platform` | string | Target platform (`"linux/amd64"`) |
//!
//! ### `[network]` — Egress filtering
//!
//! Controls outbound network access when `net = true`.
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `allow_hosts` | string[] | Allowed hostnames (resolved to IPs at start) |
//! | `allow_cidrs` | string[] | Allowed CIDR ranges (`"10.0.0.0/8"`) |
//!
//! ### `[health]` — Health checks
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `exec` | string[] | Health check command |
//! | `interval` | string | Check interval (`"10s"`, `"1m"`) |
//! | `timeout` | string | Check timeout (`"2s"`) |
//! | `retries` | int | Failures before unhealthy |
//! | `startup_grace` | string | Delay before first check |
//!
//! ### `[restart]` — Restart policy
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `policy` | string | `"never"`, `"always"`, `"on-failure"`, `"unless-stopped"` |
//! | `max_retries` | int | Max restart attempts |
//! | `max_backoff` | string | Max delay between restarts |
//!
//! ### `[auth]` — Credential forwarding
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `ssh_agent` | bool | Forward host SSH agent into the VM |
//!
//! ### `[service]` — Deployment metadata
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `port` | int | Service listen port inside the VM |
//! | `protocol` | string | `"http"` or `"tcp"` |
//!
//! # Command Model
//!
//! Follows Docker/OCI semantics:
//! - `entrypoint`: the executable (like Dockerfile ENTRYPOINT)
//! - `cmd`: default arguments (like Dockerfile CMD)
//! - `init`: dev bootstrap commands run at VM start (NOT part of the container command)
//!
//! When set, `entrypoint` and `cmd` override the base image's OCI config.
//! If neither is set, the image's built-in values are used.
//!
//! # Example
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
use thiserror::Error;

/// Errors from Smolfile parsing.
#[derive(Debug, Error)]
pub enum SmolfileError {
    /// Failed to read the file.
    #[error("failed to read {path}: {source}")]
    Read {
        /// File path.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// Failed to parse the TOML content.
    #[error("failed to parse {path}: {source}")]
    Parse {
        /// File path.
        path: String,
        /// Underlying TOML error.
        source: toml::de::Error,
    },
}

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
    /// GPU VRAM (shared memory region) size in MiB. Ignored unless
    /// `gpu = true`. Default comes from `DEFAULT_GPU_VRAM_MIB` (4 GiB).
    pub gpu_vram: Option<u32>,
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
    pub restart: Option<RestartConfig>,
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
pub struct RestartConfig {
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
// Parsing
// ============================================================================

/// Parse a Smolfile from a TOML string.
pub fn parse(content: &str) -> Result<Smolfile, toml::de::Error> {
    toml::from_str(content)
}

/// Load and parse a Smolfile from a file path.
pub fn load(path: &Path) -> Result<Smolfile, SmolfileError> {
    let content = std::fs::read_to_string(path).map_err(|e| SmolfileError::Read {
        path: path.display().to_string(),
        source: e,
    })?;

    toml::from_str(&content).map_err(|e| SmolfileError::Parse {
        path: path.display().to_string(),
        source: e,
    })
}

// ============================================================================
// Utilities
// ============================================================================

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
    fn parse_minimal() {
        let sf: Smolfile = parse("").unwrap();
        assert_eq!(sf.image, None);
        assert_eq!(sf.cpus, None);
    }

    #[test]
    fn parse_full_example() {
        let sf = parse(
            r#"
image = "alpine"
cpus = 2
memory = 1024
net = true
entrypoint = ["/bin/sh"]
cmd = ["-c", "echo hello"]
env = ["FOO=bar"]
workdir = "/app"

[dev]
volumes = ["./src:/app"]
init = ["echo hello"]
ports = ["8080:8080"]

[artifact]
cpus = 4
memory = 2048

[network]
allow_hosts = ["pypi.org"]
allow_cidrs = ["10.0.0.0/8"]

[health]
exec = ["curl", "-f", "http://localhost/health"]
interval = "10s"
timeout = "2s"
retries = 3

[restart]
policy = "on-failure"
max_retries = 5

[auth]
ssh_agent = true

[service]
port = 8080
protocol = "http"
"#,
        )
        .unwrap();

        assert_eq!(sf.image.as_deref(), Some("alpine"));
        assert_eq!(sf.cpus, Some(2));
        assert_eq!(sf.memory, Some(1024));
        assert_eq!(sf.net, Some(true));
        assert_eq!(sf.entrypoint, vec!["/bin/sh"]);
        assert_eq!(sf.cmd, vec!["-c", "echo hello"]);
        assert_eq!(sf.env, vec!["FOO=bar"]);
        assert_eq!(sf.workdir.as_deref(), Some("/app"));

        let dev = sf.dev.unwrap();
        assert_eq!(dev.volumes, vec!["./src:/app"]);
        assert_eq!(dev.init, vec!["echo hello"]);

        let artifact = sf.artifact.unwrap();
        assert_eq!(artifact.cpus, Some(4));
        assert_eq!(artifact.memory, Some(2048));

        let network = sf.network.unwrap();
        assert_eq!(network.allow_hosts, vec!["pypi.org"]);

        let health = sf.health.unwrap();
        assert_eq!(health.retries, Some(3));

        let restart = sf.restart.unwrap();
        assert_eq!(restart.policy.as_deref(), Some("on-failure"));

        assert_eq!(sf.auth.unwrap().ssh_agent, Some(true));
        assert_eq!(sf.service.unwrap().port, Some(8080));
    }

    #[test]
    fn parse_rejects_unknown_fields() {
        let err = parse("bogus_field = true");
        assert!(err.is_err());
    }

    #[test]
    fn load_from_file() {
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
    fn load_nonexistent_file() {
        let err = load(Path::new("/nonexistent/Smolfile")).unwrap_err();
        assert!(matches!(err, SmolfileError::Read { .. }));
    }

    #[test]
    fn parse_duration_secs_formats() {
        assert_eq!(parse_duration_secs("10s"), Some(10));
        assert_eq!(parse_duration_secs("5m"), Some(300));
        assert_eq!(parse_duration_secs("2h"), Some(7200));
        assert_eq!(parse_duration_secs("42"), Some(42));
    }
}
