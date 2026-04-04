//! Smolfile parser for declarative microVM workload configuration.
//!
//! A Smolfile is the declarative source of truth for a microVM workload.
//! It is only loaded when explicitly specified via `--smolfile`/`-s`.
//!
//! Example Smolfile:
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
//! [service]
//! listen = 8080
//! protocol = "http"
//!
//! [dev]
//! volumes = ["./src:/app"]
//! init = ["cargo build"]
//! ports = ["8080:8080"]
//!
//! [artifact]
//! cpus = 4
//! memory = 2048
//! ```

use crate::cli::parsers::parse_cidr;
use crate::cli::vm_common::CreateVmParams;
use serde::Deserialize;
use smolvm::data::network::PortMapping;
use smolvm::data::resources::{DEFAULT_MICROVM_CPU_COUNT, DEFAULT_MICROVM_MEMORY_MIB};
use std::path::{Path, PathBuf};

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
    // Top-level workload fields
    /// OCI image (optional — omit for bare Alpine VM).
    pub image: Option<String>,
    /// Executable and fixed leading arguments (overrides image ENTRYPOINT).
    #[serde(default)]
    pub entrypoint: Vec<String>,
    /// Default arguments appended to entrypoint (overrides image CMD).
    #[serde(default)]
    pub cmd: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
    pub workdir: Option<String>,

    // Resources
    pub cpus: Option<u8>,
    pub memory: Option<u32>,
    pub net: Option<bool>,
    pub storage: Option<u64>,
    pub overlay: Option<u64>,
    /// Allowed egress CIDR ranges (e.g., ["10.0.0.0/8", "1.1.1.1"]).
    #[serde(default)]
    pub allowed_cidrs: Vec<String>,

    // Legacy top-level fields (will move to [dev] in Step 4)
    #[serde(default)]
    pub ports: Vec<String>,
    #[serde(default)]
    pub volumes: Vec<String>,
    #[serde(default)]
    pub init: Vec<String>,

    // Profiles
    pub artifact: Option<ArtifactConfig>,
    pub pack: Option<ArtifactConfig>, // alias for artifact
    pub dev: Option<DevConfig>,

    // Wired: flows into VmRecord health fields + monitor command
    pub health: Option<HealthConfig>,
    // Wired: flows into VmRecord restart config
    pub restart: Option<RestartSmolfileConfig>,

    // Credential forwarding
    pub auth: Option<AuthConfig>,
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
    pub cpus: Option<u8>,
    pub memory: Option<u32>,
    #[serde(default)]
    pub entrypoint: Vec<String>,
    #[serde(default)]
    pub cmd: Vec<String>,
    pub oci_platform: Option<String>,
}

/// Local development profile.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DevConfig {
    #[serde(default)]
    pub volumes: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub init: Vec<String>,
    pub workdir: Option<String>,
    #[serde(default)]
    pub ports: Vec<String>,
}

/// Health check configuration for the monitor command.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct HealthConfig {
    #[serde(default)]
    pub exec: Vec<String>,
    pub interval: Option<String>,
    pub timeout: Option<String>,
    pub retries: Option<u32>,
    pub startup_grace: Option<String>,
}

/// Restart policy for the Smolfile [restart] section.
/// Named to avoid conflict with smolvm::config::RestartConfig.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RestartSmolfileConfig {
    pub policy: Option<String>,
    pub max_retries: Option<u32>,
    /// Maximum backoff duration between restarts (e.g., "60s", "5m").
    pub max_backoff: Option<String>,
}

/// Load and parse a Smolfile from the given path.
pub fn load(path: &Path) -> smolvm::Result<Smolfile> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        smolvm::Error::config("load smolfile", format!("{}: {}", path.display(), e))
    })?;

    toml::from_str(&content)
        .map_err(|e| smolvm::Error::config("parse smolfile", format!("{}: {}", path.display(), e)))
}

/// Parse a duration string like "10s", "5m", "2h" to seconds.
fn parse_duration_secs(s: &str) -> Option<u64> {
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

/// Build `CreateVmParams` by merging CLI flags with an optional Smolfile.
///
/// CLI flags override Smolfile values. For Vec fields, CLI values are appended
/// to Smolfile values. For scalar fields, non-default CLI values take priority.
///
/// Merge precedence:
///   image:      CLI > Smolfile > None (bare Alpine)
///   entrypoint: CLI override > Smolfile > image metadata
///   cmd:        CLI trailing args > Smolfile cmd (full replacement)
///   env:        Smolfile + CLI extends
///   init:       Smolfile + CLI extends
#[allow(clippy::too_many_arguments)]
pub fn build_create_params(
    name: String,
    cli_image: Option<String>,
    cli_entrypoint: Option<String>,
    cli_cmd: Vec<String>,
    cli_cpus: u8,
    cli_mem: u32,
    cli_volume: Vec<String>,
    cli_port: Vec<PortMapping>,
    cli_net: bool,
    cli_init: Vec<String>,
    cli_env: Vec<String>,
    cli_workdir: Option<String>,
    smolfile_path: Option<PathBuf>,
    cli_storage_gb: Option<u64>,
    cli_overlay_gb: Option<u64>,
    cli_allow_cidr: Vec<String>,
) -> smolvm::Result<CreateVmParams> {
    let cidrs_to_option = |v: Vec<String>| if v.is_empty() { None } else { Some(v) };

    let sf = match smolfile_path {
        Some(path) => load(&path)?,
        None => {
            let net = cli_net || !cli_allow_cidr.is_empty();
            return Ok(CreateVmParams {
                name,
                image: cli_image,
                entrypoint: cli_entrypoint.map(|e| vec![e]).unwrap_or_default(),
                cmd: cli_cmd,
                cpus: cli_cpus,
                mem: cli_mem,
                volume: cli_volume,
                port: cli_port,
                net,
                init: cli_init,
                env: cli_env,
                workdir: cli_workdir,
                storage_gb: cli_storage_gb,
                overlay_gb: cli_overlay_gb,
                allowed_cidrs: cidrs_to_option(cli_allow_cidr),
                restart_policy: None,
                restart_max_retries: None,
                restart_max_backoff_secs: None,
                health_cmd: None,
                health_interval_secs: None,
                health_timeout_secs: None,
                health_retries: None,
                health_startup_grace_secs: None,
                ssh_agent: false,
            });
        }
    };

    // Image: CLI > Smolfile > None
    let image = cli_image.or(sf.image);

    // Entrypoint: CLI > Smolfile
    let entrypoint = if let Some(ep) = cli_entrypoint {
        vec![ep]
    } else {
        sf.entrypoint
    };

    // Cmd: CLI > Smolfile (full replacement, not append)
    let cmd = if cli_cmd.is_empty() { sf.cmd } else { cli_cmd };

    // Resolve [dev] fields, falling back to top-level
    let dev = sf.dev.unwrap_or_default();

    // Ports: [dev].ports > top-level ports, then CLI extends
    let sf_ports = if !dev.ports.is_empty() {
        dev.ports
    } else {
        sf.ports
    };
    let mut ports: Vec<PortMapping> = sf_ports
        .iter()
        .map(|s| PortMapping::parse(s))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| smolvm::Error::config("smolfile ports", e))?;
    ports.extend(cli_port);

    // Volumes: [dev].volumes > top-level volumes, then CLI extends
    let sf_volumes = if !dev.volumes.is_empty() {
        dev.volumes
    } else {
        sf.volumes
    };
    let mut volumes = sf_volumes;
    volumes.extend(cli_volume);

    // Env: top-level env + [dev].env + CLI extends (whitespace trimmed)
    let mut env: Vec<String> = sf.env.into_iter().map(|e| e.trim().to_string()).collect();
    env.extend(dev.env.into_iter().map(|e| e.trim().to_string()));
    env.extend(cli_env.into_iter().map(|e| e.trim().to_string()));

    // Init: [dev].init > top-level init, then CLI extends
    let sf_init = if !dev.init.is_empty() {
        dev.init
    } else {
        sf.init
    };
    let mut init = sf_init;
    init.extend(cli_init);

    // Workdir: CLI > [dev].workdir > top-level workdir
    let dev_workdir = dev.workdir;

    // Scalars: CLI non-default overrides Smolfile
    let default_cpus = DEFAULT_MICROVM_CPU_COUNT;
    let default_mem = DEFAULT_MICROVM_MEMORY_MIB;

    let cpus = if cli_cpus != default_cpus {
        cli_cpus
    } else {
        sf.cpus.unwrap_or(cli_cpus)
    };

    let mem = if cli_mem != default_mem {
        cli_mem
    } else {
        sf.memory.unwrap_or(cli_mem)
    };

    let net = if cli_net {
        true
    } else {
        sf.net.unwrap_or(false)
    };

    let workdir = cli_workdir.or(dev_workdir).or(sf.workdir);

    // Scalars: CLI overrides Smolfile
    let storage_gb = cli_storage_gb.or(sf.storage);
    let overlay_gb = cli_overlay_gb.or(sf.overlay);

    // Merge allowed_cidrs: Smolfile first (validated), CLI extends
    let mut allowed_cidrs_vec: Vec<String> = sf
        .allowed_cidrs
        .iter()
        .map(|s| parse_cidr(s))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| smolvm::Error::config("smolfile allowed_cidrs", e))?;
    allowed_cidrs_vec.extend(cli_allow_cidr);
    // --allow-cidr implies --net
    let net = if !allowed_cidrs_vec.is_empty() {
        true
    } else {
        net
    };
    let allowed_cidrs = cidrs_to_option(allowed_cidrs_vec);

    // Restart policy from [restart] section
    let restart_policy = sf
        .restart
        .as_ref()
        .and_then(|r| r.policy.as_deref())
        .map(|p| {
            p.parse::<smolvm::config::RestartPolicy>()
                .map_err(|e| smolvm::Error::config("smolfile [restart] policy", e))
        })
        .transpose()?;
    let restart_max_retries = sf.restart.as_ref().and_then(|r| r.max_retries);
    let restart_max_backoff_secs = sf
        .restart
        .as_ref()
        .and_then(|r| r.max_backoff.as_ref())
        .and_then(|s| parse_duration_secs(s));

    // Health check from [health] section
    let health_cmd = sf
        .health
        .as_ref()
        .filter(|h| !h.exec.is_empty())
        .map(|h| h.exec.clone());
    let health_interval_secs = sf
        .health
        .as_ref()
        .and_then(|h| h.interval.as_ref())
        .and_then(|s| parse_duration_secs(s));
    let health_timeout_secs = sf
        .health
        .as_ref()
        .and_then(|h| h.timeout.as_ref())
        .and_then(|s| parse_duration_secs(s));
    let health_retries = sf.health.as_ref().and_then(|h| h.retries);
    let health_startup_grace_secs = sf
        .health
        .as_ref()
        .and_then(|h| h.startup_grace.as_ref())
        .and_then(|s| parse_duration_secs(s));

    Ok(CreateVmParams {
        name,
        image,
        entrypoint,
        cmd,
        cpus,
        mem,
        volume: volumes,
        port: ports,
        net,
        init,
        env,
        workdir,
        storage_gb,
        overlay_gb,
        allowed_cidrs,
        restart_policy,
        restart_max_retries,
        restart_max_backoff_secs,
        health_cmd,
        health_interval_secs,
        health_timeout_secs,
        health_retries,
        health_startup_grace_secs,
        ssh_agent: sf.auth.as_ref().and_then(|a| a.ssh_agent).unwrap_or(false),
    })
}

/// Resolved pack configuration from Smolfile + CLI args.
pub struct PackConfig {
    pub image: Option<String>,
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
    pub cpus: u8,
    pub mem: u32,
    pub oci_platform: Option<String>,
    pub env: Vec<String>,
    pub workdir: Option<String>,
}

/// Resolve pack configuration by merging CLI flags with an optional Smolfile.
///
/// Merge precedence:
///   image:        CLI --image > Smolfile image > None
///   entrypoint:   CLI --entrypoint > [artifact].entrypoint > Smolfile entrypoint > image metadata
///   cmd:          [artifact].cmd > Smolfile cmd > image metadata
///   cpus:         CLI --cpus (non-default) > [artifact].cpus > Smolfile cpus > default
///   memory:       CLI --mem (non-default) > [artifact].memory > Smolfile memory > default
///   oci_platform: CLI --oci-platform > [artifact].oci_platform > None
///   env:          Smolfile top-level env (trimmed)
///   workdir:      Smolfile top-level workdir
pub fn resolve_pack_config(
    cli_image: Option<String>,
    cli_entrypoint: Option<String>,
    cli_cpus: u8,
    cli_mem: u32,
    cli_oci_platform: Option<String>,
    smolfile_path: Option<PathBuf>,
) -> smolvm::Result<PackConfig> {
    let default_cpus = DEFAULT_MICROVM_CPU_COUNT;
    let default_mem = crate::cli::pack::PACK_DEFAULT_MEMORY_MIB;
    let sf = match smolfile_path {
        Some(path) => load(&path)?,
        None => {
            return Ok(PackConfig {
                image: cli_image,
                entrypoint: cli_entrypoint.map(|e| vec![e]).unwrap_or_default(),
                cmd: vec![],
                cpus: cli_cpus,
                mem: cli_mem,
                oci_platform: cli_oci_platform,
                env: vec![],
                workdir: None,
            });
        }
    };

    // Resolve [artifact] (preferred) or [pack] (alias)
    let artifact = sf.artifact.or(sf.pack).unwrap_or_default();

    // Image: CLI > Smolfile top-level
    let image = cli_image.or(sf.image);

    // Entrypoint: CLI > [artifact] > top-level
    let entrypoint = if let Some(ep) = cli_entrypoint {
        vec![ep]
    } else if !artifact.entrypoint.is_empty() {
        artifact.entrypoint
    } else {
        sf.entrypoint
    };

    // Cmd: [artifact] > top-level (CLI doesn't have a cmd flag for pack)
    let cmd = if !artifact.cmd.is_empty() {
        artifact.cmd
    } else {
        sf.cmd
    };

    // Scalars: CLI non-default > [artifact] > top-level > default
    let cpus = if cli_cpus != default_cpus {
        cli_cpus
    } else {
        artifact.cpus.or(sf.cpus).unwrap_or(cli_cpus)
    };

    let mem = if cli_mem != default_mem {
        cli_mem
    } else {
        artifact.memory.or(sf.memory).unwrap_or(cli_mem)
    };

    // oci_platform: CLI > [artifact]
    let oci_platform = cli_oci_platform.or(artifact.oci_platform);

    Ok(PackConfig {
        image,
        entrypoint,
        cmd,
        cpus,
        mem,
        oci_platform,
        env: sf.env.into_iter().map(|e| e.trim().to_string()).collect(),
        workdir: sf.workdir,
    })
}
