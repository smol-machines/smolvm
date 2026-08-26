//! Smolfile CLI integration — merges Smolfile config with CLI flags.
//!
//! Types and parsing live in [`smolvm::smolfile`]. This module provides
//! the merge logic that combines Smolfile values with CLI arguments
//! to produce [`CreateVmParams`] and [`PackConfig`].

use crate::cli::parsers::parse_cidr;
use crate::cli::vm_common::CreateVmParams;
use smolvm::data::network::PortMapping;
use smolvm::data::resources::{DEFAULT_MICROVM_CPU_COUNT, DEFAULT_MICROVM_MEMORY_MIB};
use smolvm::network::NetworkBackend;
use std::path::PathBuf;

// Re-export from the library
pub use smolvm::smolfile::{parse_duration_secs, Smolfile};

/// Load and parse a Smolfile from the given path.
pub fn load(path: &std::path::Path) -> smolvm::Result<Smolfile> {
    smolvm::smolfile::load(path)
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
    cli_network_backend: Option<NetworkBackend>,
    cli_dns: Option<std::net::Ipv4Addr>,
    cli_network_name: Option<String>,
    cli_init: Vec<String>,
    cli_env: Vec<String>,
    cli_workdir: Option<String>,
    smolfile_path: Option<PathBuf>,
    cli_storage_gb: Option<u64>,
    cli_overlay_gb: Option<u64>,
    cli_allow_cidr: Vec<String>,
    // Labels come only from the CLI today; a Smolfile has no `labels` key yet.
    // Threaded explicitly so `--label` is not silently dropped when a Smolfile
    // is also supplied.
    cli_labels: std::collections::BTreeMap<String, String>,
) -> smolvm::Result<CreateVmParams> {
    let cidrs_to_option = |v: Vec<String>| if v.is_empty() { None } else { Some(v) };

    let sf = match smolfile_path {
        Some(path) => load(&path)?,
        None => {
            let net = cli_net
                || !cli_allow_cidr.is_empty()
                || cli_dns.is_some()
                || cli_network_name.is_some();
            return Ok(CreateVmParams {
                secret_refs: Default::default(),
                name,
                labels: cli_labels,
                image: cli_image,
                entrypoint: cli_entrypoint.map(|e| vec![e]).unwrap_or_default(),
                cmd: cli_cmd,
                cpus: cli_cpus,
                mem: cli_mem,
                volume: cli_volume,
                port: cli_port,
                net,
                network_backend: cli_network_backend,
                dns: cli_dns,
                network_name: cli_network_name,
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
                cuda: false,
                forkable: false,
                cuda_fork_pool_size: None,
                cuda_vram_limit_mib: None,
                docker_socket: false,
                gpu: false,
                gpu_vram_mib: None,
                rosetta: false,
                dns_filter_hosts: None,
                published_sockets: Vec::new(),
                source_smolmachine: None,
            });
        }
    };
    let auto_graph = sf.auto_graph.unwrap_or(false);
    let cuda = sf.cuda.unwrap_or(false) || auto_graph;
    let fork = sf.fork.unwrap_or_default();
    if fork.pool_size == Some(0) {
        return Err(smolvm::Error::config(
            "smolfile [fork] pool_size",
            "must be greater than zero",
        ));
    }
    if fork.cuda_vram_limit_mib == Some(0) {
        return Err(smolvm::Error::config(
            "smolfile [fork] cuda_vram_limit_mib",
            "must be greater than zero",
        ));
    }
    if fork.pool_size.is_some() && !cuda {
        return Err(smolvm::Error::config(
            "smolfile [fork] pool_size",
            "requires cuda = true (or auto_graph = true)",
        ));
    }
    if fork.cuda_vram_limit_mib.is_some() && fork.pool_size.is_none() {
        return Err(smolvm::Error::config(
            "smolfile [fork] cuda_vram_limit_mib",
            "requires pool_size",
        ));
    }
    let forkable = fork.enabled.unwrap_or(false) || fork.pool_size.is_some();

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
    if auto_graph {
        smolvm::util::enable_cuda_auto_graph_env_specs(&mut env);
    }

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

    let gpu = sf.gpu.unwrap_or(false);
    let rosetta = sf.rosetta.unwrap_or(false);

    let workdir = cli_workdir.or(dev_workdir).or(sf.workdir);

    // Scalars: CLI overrides Smolfile
    let storage_gb = cli_storage_gb.or(sf.storage);
    let overlay_gb = cli_overlay_gb.or(sf.overlay);

    // Merge network policy: [network] section, then CLI extends
    let network = sf.network.unwrap_or_default();

    // Preserve original hostnames for DNS filtering.
    // Do NOT resolve these to CIDRs here — CDN-backed hosts rotate IPs and the
    // resolved addresses would be stale by the time the machine is started.
    // Re-resolution happens at `machine start` time (see start_vm_named).
    let sf_allow_hosts = network.allow_hosts;

    // Parse [network].allow_cidrs — these are explicit stable CIDRs, stored as-is.
    let mut allowed_cidrs_vec: Vec<String> = Vec::new();
    let sf_cidrs: Vec<String> = network
        .allow_cidrs
        .iter()
        .map(|s| parse_cidr(s))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| smolvm::Error::config("smolfile [network] allow_cidrs", e))?;
    allowed_cidrs_vec.extend(sf_cidrs);

    // CLI extends
    allowed_cidrs_vec.extend(cli_allow_cidr);

    // --allow-cidr / --allow-host / [network] / --dns implies --net
    let net = if !allowed_cidrs_vec.is_empty() || !sf_allow_hosts.is_empty() || cli_dns.is_some() {
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
        labels: cli_labels,
        secret_refs: sf.secrets,
        name,
        image,
        entrypoint,
        cmd,
        cpus,
        mem,
        volume: volumes,
        port: ports,
        net,
        network_backend: cli_network_backend,
        dns: cli_dns,
        network_name: cli_network_name,
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
        cuda,
        forkable,
        cuda_fork_pool_size: fork.pool_size,
        cuda_vram_limit_mib: fork.cuda_vram_limit_mib,
        docker_socket: sf.docker_socket.unwrap_or(false),
        gpu,
        gpu_vram_mib: sf.gpu_vram,
        rosetta,
        dns_filter_hosts: if sf_allow_hosts.is_empty() {
            None
        } else {
            Some(sf_allow_hosts)
        },
        published_sockets: Vec::new(),
        source_smolmachine: None,
    })
}

/// Resolved pack configuration from Smolfile + CLI args.
pub struct PackConfig {
    /// Resolved image.
    pub image: Option<String>,
    /// Resolved entrypoint.
    pub entrypoint: Vec<String>,
    /// Resolved cmd.
    pub cmd: Vec<String>,
    /// Resolved vCPU count.
    pub cpus: u8,
    /// Resolved memory in MiB.
    pub mem: u32,
    /// Target OCI platform.
    pub oci_platform: Option<String>,
    /// Resolved environment variables.
    pub env: Vec<String>,
    /// Resolved working directory.
    pub workdir: Option<String>,
    /// Whether outbound networking is enabled.
    /// `None` = unspecified (caller decides default), `Some(true)` = explicitly
    /// enabled, `Some(false)` = explicitly disabled. This tri-state is needed
    /// so `--from-vm` can distinguish "Smolfile says net = false" from "no
    /// Smolfile, fall back to source VM's setting".
    pub net: Option<bool>,
    /// Whether GPU acceleration is enabled in the packed VM.
    pub gpu: bool,
    /// Secrets carried into the pack manifest as references. They are resolved
    /// to plaintext on the run host at exec time and are never packed as
    /// values.
    pub secret_refs: std::collections::BTreeMap<String, smolvm::secrets::SecretRef>,
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
///   gpu:          CLI --gpu (true overrides) > Smolfile gpu > false
pub fn resolve_pack_config(
    cli_image: Option<String>,
    cli_entrypoint: Option<String>,
    cli_cpus: u8,
    cli_mem: u32,
    cli_oci_platform: Option<String>,
    cli_gpu: bool,
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
                net: None,
                gpu: cli_gpu,
                secret_refs: Default::default(),
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

    // Cmd: [artifact] > top-level
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
        // [network].allow_hosts / allow_cidrs implies net = true,
        // matching the same logic in build_create_params().
        // Preserve the tri-state: None = unspecified, Some = explicit.
        net: {
            let network_section_implies_net = sf
                .network
                .as_ref()
                .is_some_and(|n| !n.allow_hosts.is_empty() || !n.allow_cidrs.is_empty());
            if network_section_implies_net {
                Some(true)
            } else {
                sf.net // None if key absent, Some(true/false) if explicit
            }
        },
        // CLI --gpu wins; Smolfile gpu = true also enables it.
        gpu: cli_gpu || sf.gpu.unwrap_or(false),
        secret_refs: sf.secrets,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_from_smolfile(path: PathBuf) -> smolvm::Result<CreateVmParams> {
        build_create_params(
            "test-vm".to_string(),
            None,
            None,
            vec![],
            DEFAULT_MICROVM_CPU_COUNT,
            DEFAULT_MICROVM_MEMORY_MIB,
            vec![],
            vec![],
            false,
            None,
            None,
            None,
            vec![],
            vec![],
            None,
            Some(path),
            None,
            None,
            vec![],
            Default::default(),
        )
    }

    #[test]
    fn auto_graph_smolfile_enables_cuda_and_framework_policy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Smolfile");
        std::fs::write(
            &path,
            "auto_graph = true\nenv = [\"KEEP=yes\", \"TORCHINDUCTOR_CUDAGRAPHS=0\"]\n",
        )
        .unwrap();

        let params = build_create_params(
            "graph-vm".to_string(),
            None,
            None,
            vec![],
            DEFAULT_MICROVM_CPU_COUNT,
            DEFAULT_MICROVM_MEMORY_MIB,
            vec![],
            vec![],
            false,
            None,
            None,
            None,
            vec![],
            vec![],
            None,
            Some(path),
            None,
            None,
            vec![],
            Default::default(),
        )
        .unwrap();

        assert!(params.cuda);
        assert_eq!(
            params.env,
            vec![
                "KEEP=yes".to_string(),
                "SMOLVM_CUDA_AUTO_GRAPH=1".to_string(),
                "TORCHINDUCTOR_CUDAGRAPHS=1".to_string(),
            ]
        );
    }

    #[test]
    fn fork_smolfile_persists_launch_and_cuda_capacity_policy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Smolfile");
        std::fs::write(
            &path,
            "cuda = true\n[fork]\nenabled = true\npool_size = 8\ncuda_vram_limit_mib = 6144\n",
        )
        .unwrap();

        let params = build_from_smolfile(path).unwrap();
        assert!(params.forkable);
        assert_eq!(params.cuda_fork_pool_size, Some(8));
        assert_eq!(params.cuda_vram_limit_mib, Some(6144));

        let record = crate::cli::vm_common::build_vm_record(&params).unwrap();
        assert!(record.forkable_on_start());
        assert_eq!(record.cuda_fork_pool_size, Some(8));
        assert_eq!(record.cuda_vram_limit_mib, Some(6144));
    }

    #[test]
    fn fork_pool_requires_cuda() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Smolfile");
        std::fs::write(&path, "[fork]\npool_size = 8\n").unwrap();

        let error = build_from_smolfile(path).err().unwrap().to_string();
        assert!(error.contains("requires cuda = true"), "{error}");
    }

    #[test]
    fn cuda_vram_limit_requires_pool_size() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Smolfile");
        std::fs::write(&path, "cuda = true\n[fork]\ncuda_vram_limit_mib = 6144\n").unwrap();

        let error = build_from_smolfile(path).err().unwrap().to_string();
        assert!(error.contains("requires pool_size"), "{error}");
    }
}
