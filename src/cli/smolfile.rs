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

use crate::cli::vm_common::CreateVmParams;
use serde::Deserialize;
use smolvm::data::network::PortMapping;
use smolvm::data::resources::{DEFAULT_MICROVM_CPU_COUNT, DEFAULT_MICROVM_MEMORY_MIB};
use std::path::{Path, PathBuf};

/// Parsed Smolfile configuration.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Smolfile {
    // Top-level workload fields
    pub image: Option<String>,
    #[serde(default)]
    pub entrypoint: Vec<String>,
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

    // Parsed but not wired yet
    #[allow(dead_code)]
    pub service: Option<ServiceConfig>,
    #[allow(dead_code)]
    pub health: Option<HealthConfig>,
    #[allow(dead_code)]
    pub restart: Option<RestartSmolfileConfig>,
    #[allow(dead_code)]
    pub deploy: Option<DeployConfig>,
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

/// Service semantics (parsed, not yet wired).
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct ServiceConfig {
    pub listen: Option<u16>,
    pub protocol: Option<String>,
    #[serde(default)]
    pub ports: Vec<String>,
}

/// Health check configuration (parsed, not yet wired).
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct HealthConfig {
    #[serde(default)]
    pub exec: Vec<String>,
    pub interval: Option<String>,
    pub timeout: Option<String>,
    pub retries: Option<u32>,
    pub startup_grace: Option<String>,
}

/// Restart policy (parsed, not yet wired).
/// Named to avoid conflict with smolvm::config::RestartConfig.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct RestartSmolfileConfig {
    pub policy: Option<String>,
    pub max_retries: Option<u32>,
}

/// Deployment configuration (parsed, not yet wired).
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct DeployConfig {
    pub replicas: Option<u32>,
    pub min_ready_seconds: Option<u32>,
    pub strategy: Option<String>,
    pub max_unavailable: Option<u32>,
    pub max_surge: Option<u32>,
}

/// Load and parse a Smolfile from the given path.
pub fn load(path: &Path) -> smolvm::Result<Smolfile> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        smolvm::Error::config("load smolfile", format!("{}: {}", path.display(), e))
    })?;

    toml::from_str(&content)
        .map_err(|e| smolvm::Error::config("parse smolfile", format!("{}: {}", path.display(), e)))
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
) -> smolvm::Result<CreateVmParams> {
    let sf = match smolfile_path {
        Some(path) => load(&path)?,
        None => {
            return Ok(CreateVmParams {
                name,
                image: cli_image,
                entrypoint: cli_entrypoint.map(|e| vec![e]).unwrap_or_default(),
                cmd: cli_cmd,
                cpus: cli_cpus,
                mem: cli_mem,
                volume: cli_volume,
                port: cli_port,
                net: cli_net,
                init: cli_init,
                env: cli_env,
                workdir: cli_workdir,
                storage_gb: cli_storage_gb,
                overlay_gb: cli_overlay_gb,
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
    let cmd = if cli_cmd.is_empty() {
        sf.cmd
    } else {
        cli_cmd
    };

    // Resolve [dev] fields, falling back to top-level
    let dev = sf.dev.unwrap_or_default();

    // Ports: [dev].ports > top-level ports, then CLI extends
    let sf_ports = if !dev.ports.is_empty() { dev.ports } else { sf.ports };
    let mut ports: Vec<PortMapping> = sf_ports
        .iter()
        .map(|s| PortMapping::parse(s))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| smolvm::Error::config("smolfile ports", e))?;
    ports.extend(cli_port);

    // Volumes: [dev].volumes > top-level volumes, then CLI extends
    let sf_volumes = if !dev.volumes.is_empty() { dev.volumes } else { sf.volumes };
    let mut volumes = sf_volumes;
    volumes.extend(cli_volume);

    // Env: top-level env + [dev].env + CLI extends
    let mut env = sf.env;
    env.extend(dev.env);
    env.extend(cli_env);

    // Init: [dev].init > top-level init, then CLI extends
    let sf_init = if !dev.init.is_empty() { dev.init } else { sf.init };
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
///   image:        CLI positional > Smolfile image > None
///   entrypoint:   CLI --entrypoint > Smolfile entrypoint > (image metadata later)
///   cmd:          Smolfile cmd > (image metadata later)
///   cpus:         CLI --cpus (non-default) > Smolfile cpus > default
///   memory:       CLI --mem (non-default) > Smolfile memory > default
///   oci_platform: CLI --oci-platform > Smolfile (future [artifact]) > None
pub fn resolve_pack_config(
    cli_image: Option<String>,
    cli_entrypoint: Option<String>,
    cli_cpus: u8,
    cli_mem: u32,
    cli_oci_platform: Option<String>,
    smolfile_path: Option<PathBuf>,
    default_cpus: u8,
    default_mem: u32,
) -> smolvm::Result<PackConfig> {
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
        env: sf.env,
        workdir: sf.workdir,
    })
}
