//! Smolfile CLI integration — merges Smolfile config with CLI flags.
//!
//! Types and parsing live in [`smolvm::smolfile`]. This module provides
//! the merge logic that combines Smolfile values with CLI arguments
//! to produce [`CreateVmParams`] and [`PackConfig`].

use crate::cli::parsers::parse_cidr;
use crate::cli::vm_common::CreateVmParams;
use smolvm::data::network::PortMappingSpec;
use smolvm::data::resources::{
    BlockIoEngine, DEFAULT_MICROVM_CPU_COUNT, DEFAULT_MICROVM_MEMORY_MIB,
};
use smolvm::network::NetworkBackend;
use std::path::PathBuf;

// Re-export from the library
pub use smolvm::smolfile::{parse_duration_secs, Smolfile};

/// Load and parse a Smolfile from the given path.
pub fn load(path: &std::path::Path) -> smolvm::Result<Smolfile> {
    smolvm::smolfile::load(path)
}

/// Parse a Smolfile `net_backend` value with the very parser `--net-backend`
/// uses, so the two can never accept different spellings. Serde would also
/// reject an unknown value, but only with its own vocabulary ("unknown
/// variant"); naming the flag and listing the accepted values tells the reader
/// what to write instead.
fn parse_net_backend(raw: &str) -> smolvm::Result<NetworkBackend> {
    <NetworkBackend as clap::ValueEnum>::from_str(raw, false).map_err(|_| {
        smolvm::Error::config(
            "Smolfile",
            format!(
                "net_backend = \"{raw}\" is not a networking backend; expected \"tsi\" or \
                 \"virtio-net\" (the same values as --net-backend)"
            ),
        )
    })
}

fn parse_block_io(raw: &str) -> smolvm::Result<BlockIoEngine> {
    <BlockIoEngine as clap::ValueEnum>::from_str(raw, false).map_err(|_| {
        smolvm::Error::config(
            "Smolfile",
            format!("block_io = \"{raw}\" is invalid; expected \"sync\" or \"async\""),
        )
    })
}

/// A CLI list that is empty, or holds only empty strings, contributes
/// nothing. Trailing args and `--entrypoint` both go through here so an
/// accidental `""` never becomes a one-element command the runtime tries to
/// execute.
fn cli_list_override(values: Vec<String>) -> Option<Vec<String>> {
    if values.iter().all(|v| v.is_empty()) {
        None
    } else {
        Some(values)
    }
}

/// The entrypoint a `--entrypoint` flag contributes, if any.
fn cli_entrypoint_override(cli_entrypoint: Option<String>) -> Option<Vec<String>> {
    cli_list_override(cli_entrypoint.into_iter().collect())
}

/// A `[dev]` list overrides the top-level one when set; an empty `[dev]` list
/// means "not set", not "none".
fn dev_or_top<T>(dev: Vec<T>, top: Vec<T>) -> Vec<T> {
    if dev.is_empty() {
        top
    } else {
        dev
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
    cli_cpus: Option<u8>,
    cli_mem: Option<u32>,
    cli_volume: Vec<String>,
    cli_port: Vec<PortMappingSpec>,
    cli_net: bool,
    cli_network_backend: Option<NetworkBackend>,
    cli_dns: Option<std::net::Ipv4Addr>,
    cli_network_name: Option<String>,
    cli_init: Vec<String>,
    cli_env: Vec<String>,
    cli_workdir: Option<String>,
    cli_user: Option<String>,
    smolfile_path: Option<PathBuf>,
    cli_storage_gb: Option<u64>,
    cli_overlay_gb: Option<u64>,
    cli_block_io: Option<BlockIoEngine>,
    cli_allow_cidr: Vec<String>,
    cli_deny_cidr: Vec<String>,
    // Labels come only from the CLI today; a Smolfile has no `labels` key yet.
    // Threaded explicitly so `--label` is not silently dropped when a Smolfile
    // is also supplied.
    cli_labels: std::collections::BTreeMap<String, String>,
) -> smolvm::Result<CreateVmParams> {
    let cidrs_to_option = |v: Vec<String>| if v.is_empty() { None } else { Some(v) };

    let sf = match smolfile_path {
        Some(path) => load(&path)?,
        None => {
            let ports = PortMappingSpec::expand_all(&cli_port)
                .map_err(|e| smolvm::Error::config("CLI ports", e))?;
            let net = cli_net
                || !cli_allow_cidr.is_empty()
                || !cli_deny_cidr.is_empty()
                || cli_dns.is_some()
                || cli_network_name.is_some();
            return Ok(CreateVmParams {
                secret_refs: Default::default(),
                name,
                labels: cli_labels,
                image: cli_image,
                entrypoint: cli_entrypoint_override(cli_entrypoint).unwrap_or_default(),
                cmd: cli_cmd,
                cpus: cli_cpus.unwrap_or(DEFAULT_MICROVM_CPU_COUNT),
                mem: cli_mem.unwrap_or(DEFAULT_MICROVM_MEMORY_MIB),
                volume: cli_volume,
                allow_system_mounts: false,
                port: ports,
                net,
                network_backend: cli_network_backend,
                dns: cli_dns,
                network_name: cli_network_name,
                init: cli_init,
                env: cli_env,
                workdir: cli_workdir,
                user: cli_user,
                storage_gb: cli_storage_gb,
                overlay_gb: cli_overlay_gb,
                block_io: cli_block_io.unwrap_or_default(),
                allowed_cidrs: cidrs_to_option(cli_allow_cidr),
                denied_cidrs: cidrs_to_option(cli_deny_cidr),
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
                nested_virt: false,
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
    let entrypoint = cli_entrypoint_override(cli_entrypoint).unwrap_or(sf.entrypoint);

    // Cmd: CLI > Smolfile (full replacement, not append)
    let cmd = cli_list_override(cli_cmd).unwrap_or(sf.cmd);

    // Resolve [dev] fields, falling back to top-level
    let dev = sf.dev.unwrap_or_default();

    // Ports: [dev].ports > top-level ports, then CLI extends
    let sf_ports = dev_or_top(dev.ports, sf.ports);
    let mut port_specs: Vec<PortMappingSpec> = sf_ports
        .iter()
        .map(|s| PortMappingSpec::parse(s))
        .collect::<Result<_, _>>()
        .map_err(|e| smolvm::Error::config("smolfile ports", e))?;
    port_specs.extend(cli_port);
    let ports = PortMappingSpec::expand_all(&port_specs)
        .map_err(|e| smolvm::Error::config("smolfile ports", e))?;

    // Volumes: [dev].volumes > top-level volumes, then CLI extends
    let sf_volumes = dev_or_top(dev.volumes, sf.volumes);
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
    let sf_init = dev_or_top(dev.init, sf.init);
    let mut init = sf_init;
    init.extend(cli_init);

    // Workdir: CLI > [dev].workdir > top-level workdir
    let dev_workdir = dev.workdir;
    let dev_user = dev.user;

    // Resource caps: CLI > Smolfile > default. The flags are Option so an
    // explicit value that happens to equal the default still wins; the old
    // "CLI differs from default" sentinel silently dropped `--cpus 4` against
    // a Smolfile that said otherwise.
    let cpus = cli_cpus.or(sf.cpus).unwrap_or(DEFAULT_MICROVM_CPU_COUNT);
    let mem = cli_mem.or(sf.memory).unwrap_or(DEFAULT_MICROVM_MEMORY_MIB);

    let net = if cli_net {
        true
    } else {
        sf.net.unwrap_or(false)
    };

    // CLI wins over the Smolfile, like every other scalar here.
    let network_backend = match cli_network_backend {
        Some(backend) => Some(backend),
        None => sf
            .net_backend
            .as_deref()
            .map(parse_net_backend)
            .transpose()?,
    };

    let gpu = sf.gpu.unwrap_or(false);
    let rosetta = sf.rosetta.unwrap_or(false);

    let workdir = cli_workdir.or(dev_workdir).or(sf.workdir);
    let user = cli_user.or(dev_user).or(sf.user);

    // Scalars: CLI overrides Smolfile
    let storage_gb = cli_storage_gb.or(sf.storage);
    let overlay_gb = cli_overlay_gb.or(sf.overlay);
    let block_io = match cli_block_io {
        Some(engine) => engine,
        None => sf
            .block_io
            .as_deref()
            .map(parse_block_io)
            .transpose()?
            .unwrap_or_default(),
    };

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

    // Parse [network].deny_cidrs the same way, then CLI extends.
    let mut denied_cidrs_vec: Vec<String> = network
        .deny_cidrs
        .iter()
        .map(|s| parse_cidr(s))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| smolvm::Error::config("smolfile [network] deny_cidrs", e))?;
    denied_cidrs_vec.extend(cli_deny_cidr);

    // --allow-cidr / --deny-cidr / --allow-host / [network] / --dns implies --net
    let net = if !allowed_cidrs_vec.is_empty()
        || !denied_cidrs_vec.is_empty()
        || !sf_allow_hosts.is_empty()
        || cli_dns.is_some()
    {
        true
    } else {
        net
    };
    let allowed_cidrs = cidrs_to_option(allowed_cidrs_vec);
    let denied_cidrs = cidrs_to_option(denied_cidrs_vec);

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
        nested_virt: false,
        labels: cli_labels,
        secret_refs: sf.secrets,
        name,
        image,
        entrypoint,
        cmd,
        cpus,
        mem,
        volume: volumes,
        allow_system_mounts: false,
        port: ports,
        net,
        network_backend,
        dns: cli_dns,
        network_name: cli_network_name,
        init,
        env,
        workdir,
        user,
        storage_gb,
        overlay_gb,
        block_io,
        allowed_cidrs,
        denied_cidrs,
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
    /// User the packed workload runs as, from the Smolfile; `None` leaves the
    /// image's `USER` in force.
    pub user: Option<String>,
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
    cli_cpus: Option<u8>,
    cli_mem: Option<u32>,
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
                entrypoint: cli_entrypoint_override(cli_entrypoint).unwrap_or_default(),
                cmd: vec![],
                cpus: cli_cpus.unwrap_or(default_cpus),
                mem: cli_mem.unwrap_or(default_mem),
                oci_platform: cli_oci_platform,
                env: vec![],
                workdir: None,
                user: None,
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
    let entrypoint = if let Some(ep) = cli_entrypoint_override(cli_entrypoint) {
        ep
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
    // Resource caps: CLI > [artifact] > Smolfile > default.
    let cpus = cli_cpus
        .or(artifact.cpus)
        .or(sf.cpus)
        .unwrap_or(default_cpus);
    let mem = cli_mem
        .or(artifact.memory)
        .or(sf.memory)
        .unwrap_or(default_mem);

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
        user: sf.user,
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
    use smolvm::data::network::PortMapping;

    fn build_from_smolfile(path: PathBuf) -> smolvm::Result<CreateVmParams> {
        build_create_params(
            "test-vm".to_string(),
            None,
            None,
            vec![],
            None,
            None,
            vec![],
            vec![],
            false,
            None,
            None,
            None,
            vec![],
            vec![],
            None,
            None,
            Some(path),
            None,
            None,
            None,
            vec![],
            vec![],
            Default::default(),
        )
    }

    /// Every launch setting a Smolfile can express must reach every carrier
    /// it is later read from. Each hop below is the one function that path
    /// uses, so a setting added to the Smolfile but not carried by one of them
    /// fails here instead of surfacing as a machine that silently ignores it
    /// (which is how `user` was lost once on the record and once on the pack
    /// manifest). Add a line per hop when adding a launch setting.
    #[test]
    fn every_launch_setting_survives_every_hop() {
        use crate::cli::vm_common::{apply_overrides, build_vm_record, DefaultVmOverrides};
        use smolvm::config::VmRecord;
        use smolvm::pack_export::{seed_manifest_from_vm, FromVmAssets};
        use smolvm_pack::format::{PackManifest, PackMode};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Smolfile");
        std::fs::write(
            &path,
            r#"
image = "library/alpine:latest"
net = true
net_backend = "virtio-net"
entrypoint = ["/bin/sh", "-c"]
cmd = ["sleep infinity"]
env = ["GREETING=hello", "EMPTY="]
workdir = "/srv/app"
user = "501:20"
init = ["echo init"]

[network]
allow_cidrs = ["10.0.0.0/8"]
deny_cidrs = ["10.1.0.0/16"]
"#,
        )
        .unwrap();
        let params = build_from_smolfile(path).unwrap();

        // Hop 1: Smolfile -> create params.
        assert_eq!(params.image.as_deref(), Some("library/alpine:latest"));
        assert_eq!(params.entrypoint, vec!["/bin/sh", "-c"]);
        assert_eq!(params.cmd, vec!["sleep infinity"]);
        assert_eq!(params.env, vec!["GREETING=hello", "EMPTY="]);
        assert_eq!(params.workdir.as_deref(), Some("/srv/app"));
        assert_eq!(params.user.as_deref(), Some("501:20"));
        assert_eq!(params.init, vec!["echo init"]);
        assert_eq!(params.network_backend, Some(NetworkBackend::VirtioNet));
        assert_eq!(params.allowed_cidrs, Some(vec!["10.0.0.0/8".to_string()]));
        assert_eq!(params.denied_cidrs, Some(vec!["10.1.0.0/16".to_string()]));

        // Hop 2a: create params -> record, the `machine create` path.
        let created = build_vm_record(&params).unwrap();
        assert_eq!(created.image, params.image);
        assert_eq!(created.entrypoint, params.entrypoint);
        assert_eq!(created.cmd, params.cmd);
        assert_eq!(
            created.env,
            vec![
                ("GREETING".to_string(), "hello".to_string()),
                ("EMPTY".to_string(), String::new())
            ]
        );
        assert_eq!(created.workdir, params.workdir);
        assert_eq!(created.user, params.user);
        assert_eq!(created.init, params.init);
        assert_eq!(created.network_backend, params.network_backend);
        assert_eq!(created.allowed_cidrs, params.allowed_cidrs);
        assert_eq!(created.denied_cidrs, params.denied_cidrs);

        // Hop 2b: create params -> overrides -> record, the `run` and
        // first-launch paths.
        let overrides = DefaultVmOverrides::from_create_params(&params, vec![], vec![], vec![]);
        let mut persisted = VmRecord::new("parity".to_string(), 1, 512, vec![], vec![], true);
        apply_overrides(&mut persisted, &overrides);
        assert_eq!(persisted.image, params.image);
        assert_eq!(persisted.entrypoint, params.entrypoint);
        assert_eq!(persisted.cmd, params.cmd);
        assert_eq!(persisted.env, created.env);
        assert_eq!(persisted.workdir, params.workdir);
        assert_eq!(persisted.user, params.user);
        assert_eq!(persisted.init, params.init);
        assert_eq!(persisted.network_backend, params.network_backend);
        assert_eq!(persisted.allowed_cidrs, params.allowed_cidrs);
        assert_eq!(persisted.denied_cidrs, params.denied_cidrs);

        // Hop 3: record -> pack manifest, the `pack create --from-vm` path.
        let mut manifest = PackManifest::new(
            "library/alpine:latest".to_string(),
            "sha256:0".to_string(),
            "linux/arm64".to_string(),
            "darwin/arm64".to_string(),
        );
        let assets = FromVmAssets {
            mode: PackMode::Container,
            image: params.image.clone(),
            image_env: vec![],
            image_user: None,
            layer_bytes: 0,
        };
        seed_manifest_from_vm(&mut manifest, &persisted, &assets);
        assert_eq!(manifest.entrypoint, params.entrypoint);
        assert_eq!(manifest.cmd, params.cmd);
        assert!(manifest.env.contains(&"GREETING=hello".to_string()));
        assert_eq!(manifest.workdir, params.workdir);
        assert_eq!(manifest.user, params.user);

        // Hop 4: pack manifest -> what a packed machine launches with, the
        // `pack run` and standalone-binary paths. The manifest fills every
        // setting the command line leaves out, and the command line wins for
        // each one it gives.
        use crate::cli::pack_run::resolve_packed_launch;
        let launch = resolve_packed_launch(&manifest, &[], &[], None, None).unwrap();
        assert_eq!(launch.command, vec!["/bin/sh", "-c", "sleep infinity"]);
        assert!(launch
            .env
            .contains(&("GREETING".to_string(), "hello".to_string())));
        assert_eq!(launch.workdir, params.workdir);
        assert_eq!(launch.user, params.user);
        let overridden = resolve_packed_launch(
            &manifest,
            &["id".to_string()],
            &["GREETING=bye".to_string()],
            Some("/tmp".to_string()),
            Some("0".to_string()),
        )
        .unwrap();
        assert_eq!(overridden.command, vec!["id"]);
        assert!(overridden
            .env
            .contains(&("GREETING".to_string(), "bye".to_string())));
        assert_eq!(overridden.workdir.as_deref(), Some("/tmp"));
        assert_eq!(overridden.user.as_deref(), Some("0"));
    }

    /// A Smolfile must be able to express the backend the workload needs, so a
    /// checked-in file fully describes the machine instead of relying on a flag
    /// the next person forgets. Both spellings are the CLI's own, and are
    /// parsed by the CLI's own value parser. See smol-machines/smolvm#1153.
    #[test]
    fn a_smolfile_can_select_either_networking_backend() {
        for (declared, expected) in [
            ("virtio-net", NetworkBackend::VirtioNet),
            ("tsi", NetworkBackend::Tsi),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("Smolfile");
            std::fs::write(
                &path,
                format!("image = \"alpine\"\nnet = true\nnet_backend = \"{declared}\"\n"),
            )
            .unwrap();

            let params = build_from_smolfile(path).unwrap();

            assert_eq!(
                params.network_backend,
                Some(expected),
                "net_backend = \"{declared}\" must select {expected:?}"
            );
        }
    }

    /// An unusable value must be rejected where it is written, naming the flag
    /// it mirrors and the values it accepts -- not deep in a launch failure
    /// after the machine is already created.
    #[test]
    fn an_unknown_networking_backend_is_rejected_with_the_accepted_values() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Smolfile");
        std::fs::write(
            &path,
            "image = \"alpine\"\nnet = true\nnet_backend = \"virtio\"\n",
        )
        .unwrap();

        // `unwrap_err` would require CreateVmParams: Debug, which it is not.
        let error = match build_from_smolfile(path) {
            Ok(_) => panic!("an unknown networking backend must be rejected"),
            Err(error) => error.to_string(),
        };

        assert!(
            error.contains("virtio"),
            "must quote what was written: {error}"
        );
        assert!(
            error.contains("tsi"),
            "must list the accepted values: {error}"
        );
        assert!(
            error.contains("virtio-net"),
            "must list the accepted values: {error}"
        );
        assert!(
            error.contains("--net-backend"),
            "must name the flag it mirrors: {error}"
        );
    }

    /// CLI over Smolfile, the same precedence every other scalar here follows.
    #[test]
    fn the_net_backend_flag_overrides_the_smolfile() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Smolfile");
        std::fs::write(
            &path,
            "image = \"alpine\"\nnet = true\nnet_backend = \"tsi\"\n",
        )
        .unwrap();

        let params = build_create_params(
            "test-vm".to_string(),
            None,
            None,
            vec![],
            None,
            None,
            vec![],
            vec![],
            false,
            Some(NetworkBackend::VirtioNet),
            None,
            None,
            vec![],
            vec![],
            None,
            None,
            Some(path),
            None,
            None,
            None,
            vec![],
            vec![],
            Default::default(),
        )
        .unwrap();

        assert_eq!(params.network_backend, Some(NetworkBackend::VirtioNet));
    }

    /// Absent stays absent: the launcher picks the default backend, and a
    /// Smolfile without the key must not start pinning one.
    #[test]
    fn a_smolfile_without_the_key_leaves_the_backend_unset() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Smolfile");
        std::fs::write(&path, "image = \"alpine\"\nnet = true\n").unwrap();

        assert_eq!(build_from_smolfile(path).unwrap().network_backend, None);
    }

    #[test]
    fn smolfile_port_ranges_expand_before_create() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Smolfile");
        std::fs::write(&path, "[dev]\nports = [\"5173-5175:6173-6175\"]\n").unwrap();

        let params = build_from_smolfile(path).unwrap();

        assert_eq!(
            params.port,
            vec![
                PortMapping::new(5173, 6173),
                PortMapping::new(5174, 6174),
                PortMapping::new(5175, 6175),
            ]
        );
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
            None,
            None,
            vec![],
            vec![],
            false,
            None,
            None,
            None,
            vec![],
            vec![],
            None,
            None,
            Some(path),
            None,
            None,
            None,
            vec![],
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
    fn block_io_smolfile_selects_async_engine() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Smolfile");
        std::fs::write(&path, "block_io = \"async\"\n").unwrap();

        let params = build_from_smolfile(path).unwrap();
        assert_eq!(params.block_io, BlockIoEngine::Async);
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

#[cfg(test)]
mod resource_cap_precedence_tests {
    use super::*;
    use smolvm::data::resources::{DEFAULT_MICROVM_CPU_COUNT, DEFAULT_MICROVM_MEMORY_MIB};

    fn smolfile(contents: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("Smolfile");
        std::fs::write(&path, contents).expect("write");
        (dir, path)
    }

    /// `build_create_params` with only the resource caps and trailing args
    /// varied; everything else is off.
    fn create(
        cli_cpus: Option<u8>,
        cli_mem: Option<u32>,
        cli_cmd: Vec<String>,
        smolfile_path: Option<PathBuf>,
    ) -> CreateVmParams {
        build_create_params(
            "m".to_string(),
            None,
            None,
            cli_cmd,
            cli_cpus,
            cli_mem,
            vec![],
            vec![],
            false,
            None,
            None,
            None,
            vec![],
            vec![],
            None,
            None,
            smolfile_path,
            None,
            None,
            None,
            vec![],
            vec![],
            Default::default(),
        )
        .expect("params")
    }

    /// The bug: `--cpus 4` against a Smolfile saying 8 yielded 8, because 4 is
    /// the default and the resolver could not tell "typed the default" from
    /// "typed nothing". An explicit flag must win regardless of its value.
    #[test]
    fn an_explicit_default_valued_flag_still_overrides_the_smolfile() {
        let (_d, path) = smolfile("image = \"alpine\"\ncpus = 8\nmemory = 16384\n");

        let p = create(
            Some(DEFAULT_MICROVM_CPU_COUNT),
            Some(DEFAULT_MICROVM_MEMORY_MIB),
            vec![],
            Some(path),
        );

        assert_eq!(
            p.cpus, DEFAULT_MICROVM_CPU_COUNT,
            "--cpus was silently dropped"
        );
        assert_eq!(
            p.mem, DEFAULT_MICROVM_MEMORY_MIB,
            "--mem was silently dropped"
        );
    }

    /// With no flag, the Smolfile's cap applies.
    #[test]
    fn the_smolfile_cap_applies_when_no_flag_is_given() {
        let (_d, path) = smolfile("image = \"alpine\"\ncpus = 8\nmemory = 16384\n");

        let p = create(None, None, vec![], Some(path));

        assert_eq!((p.cpus, p.mem), (8, 16384));
    }

    /// With neither, the default applies exactly once.
    #[test]
    fn the_default_applies_only_when_nothing_else_spoke() {
        let (_d, path) = smolfile("image = \"alpine\"\n");

        let with_smolfile = create(None, None, vec![], Some(path));
        let without = create(None, None, vec![], None);

        for p in [with_smolfile, without] {
            assert_eq!(
                (p.cpus, p.mem),
                (DEFAULT_MICROVM_CPU_COUNT, DEFAULT_MICROVM_MEMORY_MIB)
            );
        }
    }

    /// The pack route has one more layer, `[artifact]`, and the same bug.
    #[test]
    fn an_explicit_default_valued_flag_overrides_the_artifact_and_smolfile() {
        let (_d, path) = smolfile(
            "image = \"alpine\"\ncpus = 8\nmemory = 16384\n[artifact]\ncpus = 16\nmemory = 32768\n",
        );

        let cfg = resolve_pack_config(
            None,
            None,
            Some(DEFAULT_MICROVM_CPU_COUNT),
            Some(crate::cli::pack::PACK_DEFAULT_MEMORY_MIB),
            None,
            false,
            Some(path.clone()),
        )
        .expect("resolves");
        assert_eq!(cfg.cpus, DEFAULT_MICROVM_CPU_COUNT);
        assert_eq!(cfg.mem, crate::cli::pack::PACK_DEFAULT_MEMORY_MIB);

        // And without a flag, [artifact] outranks the top level.
        let cfg =
            resolve_pack_config(None, None, None, None, None, false, Some(path)).expect("resolves");
        assert_eq!((cfg.cpus, cfg.mem), (16, 32768));
    }

    /// A trailing `""` is not a command, any more than `--entrypoint ""` is an
    /// entrypoint; the Smolfile's cmd must survive it.
    #[test]
    fn an_empty_trailing_arg_does_not_replace_the_smolfile_cmd() {
        let (_d, path) = smolfile("image = \"alpine\"\ncmd = [\"sleep\", \"infinity\"]\n");

        let p = create(None, None, vec![String::new()], Some(path));

        assert_eq!(p.cmd, vec!["sleep", "infinity"]);
    }

    /// `[dev]` lists override the top level only when set.
    #[test]
    fn an_empty_dev_list_falls_back_to_the_top_level() {
        assert_eq!(dev_or_top(Vec::<u8>::new(), vec![1, 2]), vec![1, 2]);
        assert_eq!(dev_or_top(vec![3], vec![1, 2]), vec![3]);
    }
}

#[cfg(test)]
mod smolfile_local_image_tests {
    use super::*;
    use smolvm::data::image_source::{classify, ImageSource};

    /// A Smolfile `image = "./x.tar"` reached `create` verbatim and was stored
    /// as a registry reference, so `start` asked the registry for
    /// `./x.tar:latest`. The merged image a Smolfile produces must classify
    /// as the local archive it is, exactly as the same value on `--image` does.
    #[test]
    fn a_smolfile_archive_image_is_a_local_source_like_the_flag() {
        let dir = tempfile::tempdir().expect("tempdir");
        let archive = dir.path().join("debian-trixie.tar");
        std::fs::write(&archive, b"not really a tar").expect("write");
        let path = dir.path().join("Smolfile");
        std::fs::write(&path, format!("image = \"{}\"\n", archive.display())).expect("write");

        let params = build_create_params(
            "m".to_string(),
            None,
            None,
            vec![],
            None,
            None,
            vec![],
            vec![],
            false,
            None,
            None,
            None,
            vec![],
            vec![],
            None,
            None,
            Some(path),
            None,
            None,
            None,
            vec![],
            vec![],
            Default::default(),
        )
        .expect("params");

        let image = params.image.expect("smolfile image is carried");
        assert!(
            matches!(classify(&image), ImageSource::Archive(_)),
            "smolfile image {image} must classify as a local archive"
        );

        // And the flag, given the same value, agrees — one rule, two routes.
        let flagged = build_create_params(
            "m".to_string(),
            Some(archive.display().to_string()),
            None,
            vec![],
            None,
            None,
            vec![],
            vec![],
            false,
            None,
            None,
            None,
            vec![],
            vec![],
            None,
            None,
            None,
            None,
            None,
            None,
            vec![],
            vec![],
            Default::default(),
        )
        .expect("params");
        assert_eq!(flagged.image, Some(image));
    }

    /// A deny list must behave like the allow list it mirrors: the Smolfile
    /// values come first, CLI `--deny-cidr` extends them, a deny list alone
    /// implies networking, and a malformed entry is rejected at parse time
    /// (never silently dropped, which would widen the policy).
    #[test]
    fn deny_cidrs_merge_imply_net_and_reject_bad_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Smolfile");
        std::fs::write(
            &path,
            "image = \"alpine\"\n[network]\ndeny_cidrs = [\"192.168.0.0/16\"]\n",
        )
        .unwrap();

        let with_cli = |smolfile: Option<PathBuf>, deny: Vec<String>| {
            build_create_params(
                "deny-vm".to_string(),
                if smolfile.is_some() {
                    None
                } else {
                    Some("alpine".to_string())
                },
                None,
                vec![],
                None,
                None,
                vec![],
                vec![],
                false,
                None,
                None,
                None,
                vec![],
                vec![],
                None,
                None,
                smolfile,
                None,
                None,
                None,
                vec![],
                deny,
                Default::default(),
            )
        };

        // Smolfile + CLI merge, Smolfile first; deny alone implies --net.
        let params = with_cli(Some(path.clone()), vec!["10.0.0.0/8".to_string()]).unwrap();
        assert_eq!(
            params.denied_cidrs,
            Some(vec!["192.168.0.0/16".to_string(), "10.0.0.0/8".to_string()])
        );
        assert!(params.net, "a deny list implies networking");

        // CLI-only path (no Smolfile) carries and implies net the same way.
        let params = with_cli(None, vec!["172.16.0.0/12".to_string()]).unwrap();
        assert_eq!(params.denied_cidrs, Some(vec!["172.16.0.0/12".to_string()]));
        assert!(params.net);

        // A malformed Smolfile deny entry is a config error, not a skip.
        std::fs::write(
            &path,
            "image = \"alpine\"\n[network]\ndeny_cidrs = [\"not-a-cidr\"]\n",
        )
        .unwrap();
        let err = match with_cli(Some(path), vec![]) {
            Ok(_) => panic!("a malformed deny CIDR must be rejected"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("deny_cidrs"), "{err}");
    }
}

#[cfg(test)]
mod cli_entrypoint_tests {
    use super::resolve_pack_config;

    /// `--entrypoint ""` used to become an entrypoint of one empty string,
    /// which the runtime then tried to execute. It must resolve to no
    /// override at all.
    #[test]
    fn an_empty_cli_entrypoint_is_not_an_entrypoint() {
        let cfg = resolve_pack_config(
            Some("alpine".to_string()),
            Some(String::new()),
            None,
            None,
            None,
            false,
            None,
        )
        .expect("resolves");

        assert!(cfg.entrypoint.is_empty(), "got {:?}", cfg.entrypoint);
    }

    /// Same through the Smolfile route, where the CLI value competes with an
    /// [artifact] entrypoint: an empty flag must not shadow it.
    #[test]
    fn an_empty_cli_entrypoint_does_not_shadow_a_smolfile_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("Smolfile");
        std::fs::write(
            &path,
            "image = \"alpine\"\nentrypoint = [\"/from/smolfile\"]\n",
        )
        .expect("write");

        let cfg = resolve_pack_config(
            None,
            Some(String::new()),
            None,
            None,
            None,
            false,
            Some(path),
        )
        .expect("resolves");

        assert_eq!(cfg.entrypoint, vec!["/from/smolfile"]);
    }

    /// A Smolfile `user` reaches an image pack's config; without one the
    /// field stays empty so the image's USER applies at pack time.
    #[test]
    fn a_smolfile_user_reaches_the_pack_config() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("Smolfile");
        std::fs::write(&path, "image = \"alpine\"\nuser = \"501:20\"\n").expect("write");
        let cfg =
            resolve_pack_config(None, None, None, None, None, false, Some(path)).expect("resolves");
        assert_eq!(cfg.user.as_deref(), Some("501:20"));

        let cfg = resolve_pack_config(
            Some("alpine".to_string()),
            None,
            None,
            None,
            None,
            false,
            None,
        )
        .expect("resolves");
        assert!(cfg.user.is_none());
    }

    #[test]
    fn a_real_cli_entrypoint_is_kept() {
        let cfg = resolve_pack_config(
            Some("alpine".to_string()),
            Some("/app/run".to_string()),
            None,
            None,
            None,
            false,
            None,
        )
        .expect("resolves");

        assert_eq!(cfg.entrypoint, vec!["/app/run"]);
    }
}
