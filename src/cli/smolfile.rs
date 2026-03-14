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

use crate::cli::parsers::{parse_cidr, parse_port};
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
    #[serde(default)]
    pub allow_ip: Vec<String>,
    pub storage: Option<u64>,
    pub overlay: Option<u64>,
    #[serde(default)]
    pub allowed_cidrs: Vec<String>,
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
    cli_allow_cidr: Vec<String>,
) -> smolvm::Result<CreateVmParams> {
    let cidrs_to_option = |v: Vec<String>| if v.is_empty() { None } else { Some(v) };

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
                allowed_cidrs: cidrs_to_option(cli_allow_cidr),
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

    // Merge allow_ip: Smolfile first (validated), CLI extends (already validated by clap)
    let mut allow_cidrs: Vec<String> = sf
        .allow_ip
        .iter()
        .map(|s| parse_cidr(s))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| smolvm::Error::config("smolfile allow_ip", e))?;
    allow_cidrs.extend(cli_allow_cidr.clone());

    // Scalars: CLI overrides Smolfile
    let storage_gb = cli_storage_gb.or(sf.storage);
    let overlay_gb = cli_overlay_gb.or(sf.overlay);

    // Merge allowed_cidrs: Smolfile first (validated), CLI extends (already validated by clap)
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

    Ok(CreateVmParams {
        name,
        cpus,
        mem,
        volume: volumes,
        port: ports,
        net: net || !allow_cidrs.is_empty(),
        init,
        env,
        workdir,
        storage_gb,
        overlay_gb,
        allowed_cidrs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::parsers::parse_cidr;

    #[test]
    fn test_parse_cidr_validation() {
        // Valid CIDRs
        assert_eq!(parse_cidr("10.0.0.0/8").unwrap(), "10.0.0.0/8");
        assert_eq!(parse_cidr("1.1.1.1").unwrap(), "1.1.1.1/32"); // auto /32
        assert_eq!(parse_cidr("::1").unwrap(), "::1/128"); // auto /128
        assert_eq!(parse_cidr("0.0.0.0/0").unwrap(), "0.0.0.0/0");

        // Invalid CIDRs
        assert!(parse_cidr("not-an-ip").is_err());
        assert!(parse_cidr("10.0.0.0/33").is_err()); // prefix too large
        assert!(parse_cidr("10.0.0.0/abc").is_err());
    }

    #[test]
    fn test_smolfile_invalid_cidr_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Smolfile");
        std::fs::write(&path, r#"allowed_cidrs = ["not-a-cidr"]"#).unwrap();

        let result = build_create_params(
            "test".to_string(), 1, 512, vec![], vec![], false,
            vec![], vec![], None, Some(path), None, None, vec![],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_smolfile_allowed_cidrs_implies_net() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Smolfile");
        std::fs::write(
            &path,
            r#"allowed_cidrs = ["10.0.0.0/8"]"#,
        )
        .unwrap();

        let params = build_create_params(
            "test".to_string(),
            1,
            512,
            vec![],
            vec![],
            false, // net=false on CLI
            vec![],
            vec![],
            None,
            Some(path),
            None,
            None,
            vec![],
        )
        .unwrap();

        assert!(params.net); // Should be true because allowed_cidrs implies --net
        assert_eq!(
            params.allowed_cidrs,
            Some(vec!["10.0.0.0/8".to_string()])
        );
    }

    #[test]
    fn test_smolfile_cidrs_merge_with_cli() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Smolfile");
        std::fs::write(
            &path,
            r#"allowed_cidrs = ["10.0.0.0/8"]"#,
        )
        .unwrap();

        let params = build_create_params(
            "test".to_string(),
            1,
            512,
            vec![],
            vec![],
            false,
            vec![],
            vec![],
            None,
            Some(path),
            None,
            None,
            vec!["192.168.0.0/16".to_string()], // CLI extends Smolfile
        )
        .unwrap();

        let cidrs = params.allowed_cidrs.unwrap();
        assert_eq!(cidrs.len(), 2);
        assert!(cidrs.contains(&"10.0.0.0/8".to_string()));
        assert!(cidrs.contains(&"192.168.0.0/16".to_string()));
    }
}
