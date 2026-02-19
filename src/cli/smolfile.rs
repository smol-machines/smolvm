//! Smolfile parser for declarative VM configuration.
//!
//! A Smolfile is a TOML file that defines VM configuration and init commands.
//! It is only loaded when explicitly specified via `--smolfile`/`-s`.
//!
//! Example Smolfile:
//! ```toml
//! cpus = 2
//! memory = 1024
//! net = true
//!
//! ports = ["8080:80", "2222:22"]
//! volumes = ["./src:/app"]
//! env = ["NODE_ENV=production"]
//! workdir = "/app"
//!
//! init = [
//!     "apk add --no-cache openssh",
//!     "ssh-keygen -A",
//!     "/usr/sbin/sshd",
//! ]
//! ```

use crate::cli::parsers::parse_port;
use crate::cli::vm_common::CreateVmParams;
use serde::Deserialize;
use smolvm::agent::PortMapping;
use std::path::{Path, PathBuf};

/// Parsed Smolfile configuration.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Smolfile {
    pub cpus: Option<u8>,
    pub memory: Option<u32>,
    pub net: Option<bool>,
    #[serde(default)]
    pub ports: Vec<String>,
    #[serde(default)]
    pub volumes: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub init: Vec<String>,
    pub workdir: Option<String>,
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
#[allow(clippy::too_many_arguments)]
pub fn build_create_params(
    name: String,
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

    // Parse Smolfile ports
    let mut ports: Vec<PortMapping> = sf
        .ports
        .iter()
        .map(|s| parse_port(s))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| smolvm::Error::config("smolfile ports", e))?;
    // CLI ports override/extend
    ports.extend(cli_port);

    // Merge volumes: Smolfile first, CLI extends
    let mut volumes = sf.volumes;
    volumes.extend(cli_volume);

    // Merge env: Smolfile first, CLI extends
    let mut env = sf.env;
    env.extend(cli_env);

    // Merge init: Smolfile first, CLI extends
    let mut init = sf.init;
    init.extend(cli_init);

    // Scalars: CLI non-default overrides Smolfile
    let default_cpus = smolvm::agent::DEFAULT_CPUS;
    let default_mem = smolvm::agent::DEFAULT_MEMORY_MIB;

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

    let workdir = cli_workdir.or(sf.workdir);

    Ok(CreateVmParams {
        name,
        cpus,
        mem,
        volume: volumes,
        port: ports,
        net,
        init,
        env,
        workdir,
        storage_gb: cli_storage_gb,
        overlay_gb: cli_overlay_gb,
    })
}
