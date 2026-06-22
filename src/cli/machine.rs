//! Machine management commands.
//!
//! All VM-related commands are under the `machine` subcommand:
//! - exec: Persistent execution (machine keeps running)
//! - create: Create named VM configuration
//! - start: Start a machine (named or default)
//! - stop: Stop a machine (named or default)
//! - delete: Delete a named VM configuration
//! - status: Show machine status
//! - ls: List all named VMs

use crate::cli::flush_output;
use crate::cli::format_bytes;
use crate::cli::parsers::{
    mounts_to_virtiofs_bindings, parse_cidr, parse_duration, parse_env_list, parse_image,
};
use crate::cli::vm_common::{self, DeleteVmOptions};
use clap::{Args, Subcommand};
use smolvm::agent::{docker_config_mount, AgentClient, AgentManager, RunConfig, VmResources};
use smolvm::data::network::PortMapping;
use smolvm::data::resources::{DEFAULT_MICROVM_CPU_COUNT, DEFAULT_MICROVM_MEMORY_MIB};
use smolvm::data::storage::HostMount;
use smolvm::network::{validate_requested_network_backend, NetworkBackend};
use smolvm::{DEFAULT_IDLE_CMD, DEFAULT_SHELL_CMD};
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::time::Duration;

/// Resolve `--allow-cidr`, `--allow-host`, and `--outbound-localhost-only` into a CIDR list,
/// net flag, and the original hostname list (for DNS filtering).
///
/// Resolution failure for `--allow-host` is a hard error — a typo or DNS outage
/// should not silently weaken the security policy.
/// Returns true when `s` structurally looks like an OCI image reference
/// rather than an executable name or path.
///
/// Catches the common mistake of writing `smolvm machine run ubuntu:22.04 --
/// bash` instead of `smolvm machine run --image ubuntu:22.04 -- bash`.
/// Only unambiguous structural signals are checked:
///   - `image:tag` form — colons are not valid in executable names
///   - `registry/image` or `namespace/image` form (non-absolute slash path)
///
/// Bare names like `alpine` or `nginx` are intentionally not flagged here
/// because they are indistinguishable from valid bare commands.
fn is_likely_image_ref(s: &str) -> bool {
    if s.contains(':') {
        return true;
    }
    s.contains('/') && !s.starts_with('/') && !s.starts_with("./") && !s.starts_with("../")
}

fn resolve_egress_flags(
    mut allow_cidr: Vec<String>,
    allow_host: Vec<String>,
    outbound_localhost_only: bool,
    net: bool,
) -> smolvm::Result<(Vec<String>, bool, Option<Vec<String>>)> {
    // Resolve hostnames to CIDRs — fail hard on resolution errors
    for host in &allow_host {
        let cidrs = crate::cli::parsers::resolve_host_to_cidrs(host)
            .map_err(|e| smolvm::Error::config("--allow-host", e))?;
        tracing::info!(host, ?cidrs, "resolved hostname for egress policy");
        allow_cidr.extend(cidrs);
    }

    if outbound_localhost_only {
        allow_cidr.push("127.0.0.0/8".to_string());
        allow_cidr.push("::1/128".to_string());
    }
    let net = net || !allow_cidr.is_empty();

    // Preserve original hostnames for DNS filtering (None if no --allow-host was used)
    let dns_filter_hosts = if allow_host.is_empty() {
        None
    } else {
        Some(allow_host)
    };

    Ok((allow_cidr, net, dns_filter_hosts))
}

/// Parse `--secret-env KEY=HOST_VAR` and `--secret-file KEY=PATH` flag values
/// into validated [`SecretRef`]s keyed by the guest-side env var name.
///
/// CLI-supplied refs are `TrustedLocal` (the host user invoked the command), so
/// both source kinds are allowed; `validate_ref` still enforces structure and
/// absolute `from_file` paths. A key that appears more than once — across or
/// within the two flags — is a hard error, since silently keeping the last
/// occurrence would mask a typo.
fn parse_cli_secret_refs(
    secret_env: &[String],
    secret_file: &[String],
) -> smolvm::Result<std::collections::BTreeMap<String, smolvm::secrets::SecretRef>> {
    use smolvm::secrets::{env_ref, file_ref, validate_ref, ResolutionScope, SecretRef};
    use std::collections::BTreeMap;

    let mut out: BTreeMap<String, SecretRef> = BTreeMap::new();

    let mut add =
        |flag: &str, spec: &str, make: &dyn Fn(&str) -> SecretRef| -> smolvm::Result<()> {
            let (key, value) = spec.split_once('=').ok_or_else(|| {
                smolvm::Error::config(flag, format!("expected KEY=VALUE, got '{}'", spec))
            })?;
            if key.is_empty() {
                return Err(smolvm::Error::config(
                    flag,
                    format!("empty secret name in '{}'", spec),
                ));
            }
            let r = make(value);
            validate_ref(&r, ResolutionScope::TrustedLocal)
                .map_err(|e| smolvm::Error::config(flag, format!("secret '{}': {}", key, e)))?;
            if out.insert(key.to_string(), r).is_some() {
                return Err(smolvm::Error::config(
                    flag,
                    format!("secret '{}' specified more than once", key),
                ));
            }
            Ok(())
        };

    for spec in secret_env {
        add("--secret-env", spec, &|v| env_ref(v))?;
    }
    for spec in secret_file {
        add("--secret-file", spec, &|v| file_ref(v))?;
    }
    Ok(out)
}

/// Spawn a detached `smolvm _cleanup-ephemeral` helper process so the parent
/// CLI can exit immediately after flushing output.
///
/// Returns `true` if the helper was spawned successfully. The caller must then
/// call `std::process::exit(exit_code)` without doing any further cleanup.
///
/// Returns `false` if spawn fails (binary not found, exec error, etc.).
/// The caller falls back to synchronous cleanup in that case.
fn try_spawn_detached_cleanup(
    vm_name: &str,
    pid: i32,
    start_time: Option<u64>,
    ephemeral_name: &str,
) -> bool {
    // Require a verified start time so the helper can use is_our_process_strict
    // before sending SIGKILL. Without it, fall back to synchronous cleanup.
    let start_time_val = match start_time {
        Some(t) => t,
        None => return false,
    };
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let result = std::process::Command::new(exe)
        .arg("_cleanup-ephemeral")
        .arg(vm_name)
        .arg(pid.to_string())
        .arg(start_time_val.to_string())
        .arg(ephemeral_name)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        // New process group so the helper is immune to SIGHUP when the
        // parent terminal closes. pgid = child pid.
        .process_group(0)
        .spawn();
    // Drop the Child handle without waiting — we exit immediately after this.
    // The OS will not create a zombie because the helper outlives us and its
    // real parent (launchd/init) reaps it when it exits.
    result.is_ok()
}

/// Manage machines
#[derive(Subcommand, Debug)]
pub enum MachineCmd {
    /// Run a container image in an ephemeral machine
    Run(RunCmd),

    /// Run a command directly in the VM (not in a container)
    Exec(ExecCmd),

    /// Create a new named machine configuration
    Create(CreateCmd),

    /// Start a machine
    Start(StartCmd),

    /// Fork a running forkable machine into a new clone (CoW memory + disks)
    Fork(ForkCmd),

    /// Stop a running machine
    Stop(StopCmd),

    /// Delete a machine configuration
    #[command(visible_alias = "rm")]
    Delete(DeleteCmd),

    /// Show machine status
    Status(StatusCmd),

    /// List all machines
    #[command(visible_alias = "list")]
    Ls(LsCmd),

    /// Resize a machine's disk resources (use `update` instead)
    #[command(hide = true)]
    Resize(ResizeCmd),

    /// Modify settings on a stopped machine (mounts, ports, resources, disks)
    Update(UpdateCmd),

    /// List cached images and storage usage
    Images(ImagesCmd),

    /// Remove unused images and layers to free disk space
    Prune(PruneCmd),

    /// Open an interactive shell in a machine (starts it if stopped)
    #[command(visible_alias = "sh")]
    Shell(ShellCmd),

    /// Copy files between host and machine
    Cp(CpCmd),

    /// Monitor a machine with health checks and restart policy
    Monitor(MonitorCmd),

    /// Test network connectivity from inside the VM
    #[command(hide = true)]
    NetworkTest(NetworkTestCmd),

    /// Print the on-disk data directory path for a named machine.
    ///
    /// Useful for scripting and debugging — returns the path where the VM's
    /// storage disk, overlay disk, and agent socket live. The path is
    /// hash-derived, not name-derived.
    #[command(name = "data-dir")]
    DataDir(DataDirCmd),
}

impl MachineCmd {
    pub fn run(self) -> smolvm::Result<()> {
        // Skip orphan cleanup for ephemeral `machine run` — it creates and
        // immediately destroys its VM, so stale records don't affect it.
        // Other commands (ls, exec, create, etc.) clean up first.
        if !matches!(self, MachineCmd::Run(_)) {
            super::vm_common::cleanup_orphaned_ephemeral_vms();
        }

        match self {
            MachineCmd::Run(cmd) => cmd.run(),
            MachineCmd::Exec(cmd) => cmd.run(),
            MachineCmd::Create(cmd) => cmd.run(),
            MachineCmd::Start(cmd) => cmd.run(),
            MachineCmd::Fork(cmd) => cmd.run(),
            MachineCmd::Stop(cmd) => cmd.run(),
            MachineCmd::Delete(cmd) => cmd.run(),
            MachineCmd::Status(cmd) => cmd.run(),
            MachineCmd::Ls(cmd) => cmd.run(),
            MachineCmd::Resize(cmd) => cmd.run(),
            MachineCmd::Update(cmd) => cmd.run(),
            MachineCmd::Images(cmd) => cmd.run(),
            MachineCmd::Prune(cmd) => cmd.run(),
            MachineCmd::Shell(cmd) => cmd.run(),
            MachineCmd::Cp(cmd) => cmd.run(),
            MachineCmd::Monitor(cmd) => cmd.run(),
            MachineCmd::NetworkTest(cmd) => cmd.run(),
            MachineCmd::DataDir(cmd) => cmd.run(),
        }
    }
}

// ============================================================================
// Run Command (Ephemeral)
// ============================================================================

/// Run a container image in an ephemeral machine.
///
/// By default, runs in ephemeral mode (machine cleaned up after exit).
/// Use -d/--detach to keep the machine running for later interaction.
///
/// Examples:
///   smolvm machine run --image alpine -- echo "hello"
///   smolvm machine run -it -I alpine
///   smolvm machine run -d --net -I ubuntu
///   smolvm machine run --net -v ./src:/app --image node -- npm start
#[derive(Args, Debug)]
pub struct RunCmd {
    /// Container image (e.g., alpine, ubuntu:22.04, ghcr.io/org/image).
    /// Optional when a Smolfile provides the image, or for bare VM mode.
    #[arg(short = 'I', long, value_name = "IMAGE", value_parser = parse_image)]
    pub image: Option<String>,

    /// Raise the max accepted local image-archive size (e.g. 16GiB, 512M, or a
    /// raw byte count); default 8GiB. For legitimately large images — sets
    /// SMOLVM_MAX_IMAGE_BYTES for this run.
    #[arg(long = "max-image-size", value_name = "SIZE",
          value_parser = crate::cli::parsers::parse_size_bytes, help_heading = "Execution")]
    pub max_image_size: Option<u64>,

    /// Run a packed `.smolmachine` artifact ephemerally (the VM is discarded on
    /// exit) — the one-shot equivalent of `machine create --from … + start`.
    /// CPU/memory fall back to the artifact's baked manifest unless overridden.
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with_all = ["image", "smolfile", "detach", "name", "gpu", "gpu_vram_mib", "oci_platform", "allow_cidr", "allow_host", "outbound_localhost_only", "secret_env", "secret_file"],
        help_heading = "Machine source"
    )]
    pub from: Option<PathBuf>,

    /// Name a persistent machine when used with --detach.
    /// Matches the --name flag on start/stop/exec/status/resize. In foreground
    /// mode (no -d), --name is ignored with a warning.
    #[arg(short = 'n', long, value_name = "NAME", help_heading = "Execution")]
    pub name: Option<String>,

    /// Command and arguments to run (default: image entrypoint or /bin/sh)
    #[arg(trailing_var_arg = true, value_name = "COMMAND")]
    pub command: Vec<String>,

    /// Start the command in the background and detach, leaving the VM
    /// running. Use `machine exec` to run further commands against the VM
    /// and `machine stop` to tear it down.
    #[arg(short = 'd', long, help_heading = "Execution")]
    pub detach: bool,

    /// Keep stdin open for interactive input
    #[arg(short = 'i', long, help_heading = "Execution")]
    pub interactive: bool,

    /// Allocate a pseudo-TTY (use with -i for interactive shells)
    #[arg(short = 't', long, help_heading = "Execution")]
    pub tty: bool,

    /// Kill command after duration (e.g., "30s", "5m", "1h")
    #[arg(long, value_parser = parse_duration, value_name = "DURATION", help_heading = "Execution")]
    pub timeout: Option<Duration>,

    /// Set working directory inside container
    #[arg(short = 'w', long, value_name = "DIR", help_heading = "Container")]
    pub workdir: Option<String>,

    /// Set environment variable (can be used multiple times)
    #[arg(
        short = 'e',
        long = "env",
        value_name = "KEY=VALUE",
        help_heading = "Container"
    )]
    pub env: Vec<String>,

    /// Target OCI platform for multi-arch images
    #[arg(
        long = "oci-platform",
        value_name = "OS/ARCH",
        help_heading = "Container"
    )]
    pub oci_platform: Option<String>,

    /// Mount host directory into container (can be used multiple times)
    #[arg(
        short = 'v',
        long = "volume",
        value_name = "HOST:CONTAINER[:ro]",
        help_heading = "Container"
    )]
    pub volume: Vec<String>,

    /// Expose port from container to host (can be used multiple times)
    #[arg(short = 'p', long = "port", value_parser = PortMapping::parse, value_name = "HOST:GUEST", help_heading = "Network")]
    pub port: Vec<PortMapping>,

    /// Enable outbound network access
    #[arg(long, help_heading = "Network")]
    pub net: bool,

    /// Select the networking backend.
    #[arg(long = "net-backend", value_enum, help_heading = "Network")]
    pub net_backend: Option<NetworkBackend>,

    /// Allow egress to specific CIDR range (can be used multiple times, implies --net)
    #[arg(long = "allow-cidr", value_parser = parse_cidr, value_name = "CIDR", help_heading = "Network")]
    pub allow_cidr: Vec<String>,

    /// Allow egress to specific hostname, resolved at VM start (can be used multiple times, implies --net)
    #[arg(long = "allow-host", value_name = "HOSTNAME", help_heading = "Network")]
    pub allow_host: Vec<String>,

    /// Restrict outbound to localhost only (implies --net)
    #[arg(long, help_heading = "Network")]
    pub outbound_localhost_only: bool,

    /// Enable GPU acceleration (Vulkan via virtio-gpu)
    #[arg(long, help_heading = "Resources")]
    pub gpu: bool,

    /// GPU shared-memory region size in MiB. Ignored without --gpu.
    /// Default 4096 (4 GiB). Must be > 0.
    #[arg(
        long = "gpu-vram",
        value_name = "MiB",
        help_heading = "Resources",
        value_parser = crate::cli::parsers::parse_gpu_vram_mib,
    )]
    pub gpu_vram_mib: Option<u32>,

    /// Number of virtual CPUs
    #[arg(long, default_value_t = DEFAULT_MICROVM_CPU_COUNT, value_name = "N", help_heading = "Resources")]
    pub cpus: u8,

    /// Memory allocation in MiB
    #[arg(long, default_value_t = DEFAULT_MICROVM_MEMORY_MIB, value_name = "MiB", help_heading = "Resources")]
    pub mem: u32,

    /// Storage disk size in GiB
    #[arg(long, value_name = "GiB", help_heading = "Resources")]
    pub storage: Option<u64>,

    /// Overlay disk size in GiB
    #[arg(long, value_name = "GiB", help_heading = "Resources")]
    pub overlay: Option<u64>,

    /// Load VM configuration from a Smolfile (TOML)
    #[arg(
        long = "smolfile",
        visible_short_alias = 's',
        value_name = "PATH",
        help_heading = "Resources"
    )]
    pub smolfile: Option<PathBuf>,

    /// Forward host SSH agent into the VM (enables git/ssh without exposing keys)
    #[arg(long, help_heading = "Security")]
    pub ssh_agent: bool,

    /// Mount ~/.docker/ config into VM for registry authentication
    #[arg(long, help_heading = "Registry")]
    pub docker_config: bool,

    /// Inject a secret from a host env var (GUEST_VAR=HOST_VAR), resolved at
    /// launch. The value is never persisted to the machine record or a pack.
    #[arg(
        long = "secret-env",
        value_name = "GUEST_VAR=HOST_VAR",
        help_heading = "Security"
    )]
    pub secret_env: Vec<String>,

    /// Inject a secret from a host file (GUEST_VAR=/abs/path), resolved at
    /// launch. The value is never persisted to the machine record or a pack.
    #[arg(
        long = "secret-file",
        value_name = "GUEST_VAR=PATH",
        help_heading = "Security"
    )]
    pub secret_file: Vec<String>,

    #[command(flatten, next_help_heading = "Network")]
    pub proxy_opts: crate::cli::proxy_opts::ProxyOpts,
}

impl RunCmd {
    pub fn run(self) -> smolvm::Result<()> {
        use smolvm::Error;

        // --max-image-size raises the archive cap for this invocation by setting
        // the env var the resolver reads (image_source::max_archive_bytes).
        if let Some(bytes) = self.max_image_size {
            std::env::set_var("SMOLVM_MAX_IMAGE_BYTES", bytes.to_string());
        }

        // `--from`: run a packed .smolmachine artifact ephemerally, reusing the
        // proven pack-run path. Resource flags fall back to the artifact's baked
        // manifest values (matching `machine create --from`); the remaining run
        // flags pass through. Flags the sidecar runner can't honor are rejected
        // at parse time via `conflicts_with_all` on `from`.
        if let Some(from) = self.from {
            return crate::cli::pack_run::PackRunCmd {
                sidecar: Some(from),
                command: self.command,
                interactive: self.interactive,
                tty: self.tty,
                timeout: self.timeout,
                workdir: self.workdir,
                env: self.env,
                volume: self.volume,
                port: self.port,
                net: self.net,
                net_backend: self.net_backend,
                cpus: (self.cpus != DEFAULT_MICROVM_CPU_COUNT).then_some(self.cpus),
                mem: (self.mem != DEFAULT_MICROVM_MEMORY_MIB).then_some(self.mem),
                storage: self.storage,
                overlay: self.overlay,
                force_extract: false,
                info: false,
                debug: false,
            }
            .run();
        }

        let requested_name = self.name.clone();
        let vm_name = if self.detach {
            requested_name.unwrap_or_else(|| "default".to_string())
        } else {
            smolvm::util::generate_machine_name()
        };

        if self.name.is_some() && vm_name != "default" && self.detach {
            let config = smolvm::config::SmolvmConfig::load()?;
            if config.get_vm(&vm_name).is_some() {
                return Err(Error::config(
                    "machine run -d --name",
                    format!(
                        "a machine named '{}' already exists. Use 'machine start --name {}' to start it, or 'machine delete --name {} -f' to remove it.",
                        vm_name, vm_name, vm_name
                    ),
                ));
            }
        }

        let (cli_allow_cidrs, net, cli_dns_filter_hosts) = resolve_egress_flags(
            self.allow_cidr,
            self.allow_host,
            self.outbound_localhost_only,
            self.net,
        )?;

        let params = crate::cli::smolfile::build_create_params(
            vm_name.clone(),
            self.image.clone(),
            None,
            self.command.clone(),
            self.cpus,
            self.mem,
            self.volume,
            self.port,
            net,
            self.net_backend,
            vec![],
            self.env,
            self.workdir,
            self.smolfile,
            self.storage,
            self.overlay,
            cli_allow_cidrs,
        )?;

        let mut params = params;
        params.dns_filter_hosts = match (params.dns_filter_hosts.take(), cli_dns_filter_hosts) {
            (Some(mut from_smolfile), Some(mut from_cli)) => {
                from_smolfile.append(&mut from_cli);
                Some(from_smolfile)
            }
            (Some(from_smolfile), None) => Some(from_smolfile),
            (None, some) => some,
        };
        // CLI `--secret-env`/`--secret-file` refs merge over any Smolfile
        // `[secrets]` of the same name (CLI wins).
        for (key, r) in parse_cli_secret_refs(&self.secret_env, &self.secret_file)? {
            params.secret_refs.insert(key, r);
        }
        let mut mounts = HostMount::parse(&params.volume)?;
        let ports = params.port.clone();
        PortMapping::check_duplicates(&ports)
            .map_err(|e| smolvm::Error::config("validate ports", e))?;

        if self.docker_config {
            if let Some(docker_mount) = docker_config_mount() {
                mounts.push(docker_mount);
            } else {
                tracing::warn!("Docker config directory not found");
            }
        }

        // Require an explicit command, -it flag, or Smolfile entrypoint/cmd.
        // Without any of these, /bin/sh hangs waiting for input — confusing UX.
        if self.detach && (self.interactive || self.tty) {
            eprintln!("warning: -i/-t flags are ignored in detached mode (-d)");
        }

        let has_smolfile_command = !params.entrypoint.is_empty() || !params.cmd.is_empty();
        let (interactive, tty) = if !self.interactive
            && !self.tty
            && !self.detach
            && self.command.is_empty()
            && !has_smolfile_command
        {
            return Err(smolvm::Error::config(
                "machine run",
                "no command specified.\n\
                     Use: smolvm machine run -- <command>\n\
                     Or:  smolvm machine run -it",
            ));
        } else {
            (self.interactive, self.tty)
        };

        // `--image -` consumes stdin to read the archive; `-i`/`-t` also bind
        // stdin to the guest. They cannot both own stdin.
        if self.image.as_deref() == Some("-") && (interactive || tty) {
            return Err(smolvm::Error::config(
                "machine run",
                "`--image -` reads the image archive from stdin and cannot be \
                 combined with -i/-t, which also use stdin.\n\
                 Pipe the archive from a file instead: --image ./image.tar",
            ));
        }

        // Detect the common mistake of passing an image reference as a positional
        // argument instead of using --image.  clap's trailing_var_arg captures any
        // positional before "--" into `command`, so `smolvm machine run ubuntu:22.04
        // -- bash` silently puts "ubuntu:22.04" into command[0] and fails with a
        // confusing ENOENT after the VM boots.  Catching the unambiguous cases
        // (image:tag, registry/image) here avoids an unnecessary boot round-trip.
        {
            let resolved_image = self.image.as_deref().or(params.image.as_deref());
            if resolved_image.is_none()
                && !self.command.is_empty()
                && is_likely_image_ref(&self.command[0])
            {
                let cmd0 = &self.command[0];
                // Strip the "--" separator that trailing_var_arg includes
                // in the vec so the suggestion doesn't show a double "--".
                let rest: Vec<&str> = self.command[1..]
                    .iter()
                    .filter(|s| s.as_str() != "--")
                    .map(|s| s.as_str())
                    .collect();
                let suggestion = if rest.is_empty() {
                    format!("smolvm machine run --image {cmd0}")
                } else {
                    format!("smolvm machine run --image {cmd0} -- {}", rest.join(" "))
                };
                return Err(Error::config(
                    "machine run",
                    format!(
                        "'{cmd0}' looks like a container image reference, not a command.\n\
                         To run a container, use --image:\n  {suggestion}"
                    ),
                ));
            }
        }

        let resources = VmResources {
            cpus: params.cpus,
            memory_mib: params.mem,
            network: params.net,
            network_backend: params.network_backend,
            // CLI --gpu wins; Smolfile gpu = true also enables it.
            gpu: self.gpu || params.gpu,
            gpu_vram_mib: self.gpu_vram_mib.or(params.gpu_vram_mib),
            storage_gib: params.storage_gb,
            overlay_gib: params.overlay_gb,
            allowed_cidrs: params.allowed_cidrs.clone(),
        };
        validate_requested_network_backend(
            &resources,
            params.dns_filter_hosts.as_deref(),
            params.port.len(),
        )?;

        let manager =
            AgentManager::for_vm_with_sizes(&vm_name, params.storage_gb, params.overlay_gb)
                .map_err(|e| Error::agent("create agent manager", e.to_string()))?;

        if self.detach {
            eprintln!("Starting persistent machine...");
        } else {
            eprintln!("Starting ephemeral machine ({})...", vm_name);
        }

        let ssh_agent_socket = if self.ssh_agent || params.ssh_agent {
            match std::env::var("SSH_AUTH_SOCK") {
                Ok(path) => Some(std::path::PathBuf::from(path)),
                Err(_) => {
                    return Err(Error::config(
                        "--ssh-agent",
                        "SSH_AUTH_SOCK is not set. Start an SSH agent with: eval $(ssh-agent) && ssh-add",
                    ));
                }
            }
        } else {
            None
        };

        // Resolve the image source on the host before launch: registry refs
        // pass through to the guest pull; a local `docker save` archive or an
        // unpacked rootfs directory is staged/validated and mounted via
        // virtiofs (the `.smolmachine` packed-layers path), so no pull happens.
        let raw_image = self.image.clone().or(params.image.clone());
        let mut packed_layers_dir = None;
        let image = match raw_image.as_deref() {
            Some(img) => {
                use smolvm::data::image_source::{classify, resolve, ResolvedImage};
                match resolve(classify(img))? {
                    ResolvedImage::Registry(reference) => Some(reference),
                    ResolvedImage::Local {
                        reference,
                        packed_layers_dir: dir,
                    } => {
                        packed_layers_dir = Some(dir);
                        Some(reference)
                    }
                }
            }
            None => None,
        };
        let uses_packed_layers = packed_layers_dir.is_some();

        let features = smolvm::agent::LaunchFeatures {
            ssh_agent_socket,
            dns_filter_hosts: params.dns_filter_hosts.clone(),
            packed_layers_dir,
            extra_disks: Vec::new(),
        };

        let freshly_started = manager
            .ensure_running_with_full_config(mounts.clone(), ports, resources, features)
            .map_err(|e| Error::agent("start machine", e.to_string()))?;

        // Register ephemeral VM for tracking (machine list, orphan cleanup).
        // Detached runs are tracked via persist_named_running instead — skip
        // ephemeral registration so the detach path does not leave an
        // unreachable orphan record after persist_named_running succeeds.
        let ephemeral_name = smolvm::util::generate_machine_name();
        if !self.detach {
            vm_common::register_ephemeral_vm(
                &ephemeral_name,
                manager.child_pid(),
                params.cpus,
                params.mem,
                params.net,
                image.clone(),
            );
        }

        let mut client = AgentClient::connect_with_retry(manager.vsock_socket())?;

        // Install SIGINT guard so Ctrl+C during pull kills the VM process
        // instead of orphaning it. The guard is disarmed before interactive
        // exec (which has its own SIGINT handling).
        let sigint_guard = manager.child_pid().map(smolvm::process::SigintGuard::new);

        // Resolve image: CLI > Smolfile > None (bare VM)
        // Pull only registry images; a local source's layers are already
        // mounted via virtiofs and the guest assembles its rootfs from them.
        let image_info = if uses_packed_layers {
            None
        } else if let Some(ref img) = image {
            match crate::cli::pull_with_progress(
                &mut client,
                img,
                self.oci_platform.as_deref(),
                self.proxy_opts.proxy(),
                self.proxy_opts.no_proxy(),
            ) {
                Ok(info) => Some(info),
                Err(e) if !params.net => {
                    // Add a hint when pull fails and networking is disabled —
                    // this is the most common user error.
                    return Err(smolvm::Error::agent(
                        "pull image",
                        format!(
                            "{}\n\nHint: networking is disabled. Add --net to enable image pulls:\n  smolvm machine run --net --image {} ...",
                            e, img
                        ),
                    ));
                }
                Err(e) => return Err(e),
            }
        } else {
            None
        };

        // Resolve Smolfile [secrets] for this launch. Tuples are plaintext;
        // do not log them. Zeroizing buffers were scrubbed inside the helper.
        // These are merged into `env`/`init_env` below but never flow into
        // `params.env`, so the plaintext values never touch the persisted
        // VM record — only the refs are stored (via DefaultVmOverrides), and
        // they get re-resolved at each subsequent `machine start`.
        let resolved_secrets = vm_common::resolve_secret_refs_for_env(&params.secret_refs)?;

        if freshly_started && !params.init.is_empty() {
            // Route through `run_init_commands` so init runs inside the
            // container when an image is set (so package managers like
            // pacman/apt/dnf resolve against the image's rootfs), and
            // in the bare agent otherwise. The persistent `start_*`
            // paths use the same helper — keep parity.
            //
            // Convert the parsed HostMount list into the record-shape
            // tuples the runner expects. This is a thin local conversion;
            // the runner does its own tag assignment internally so call
            // sites don't have to track which form the agent wants.
            let record_mounts: Vec<(String, String, bool)> = mounts
                .iter()
                .map(|m| {
                    (
                        m.source.to_string_lossy().into_owned(),
                        m.target.to_string_lossy().into_owned(),
                        m.read_only,
                    )
                })
                .collect();
            let mut init_env = parse_env_list(&params.env);
            init_env.extend(resolved_secrets.iter().cloned());
            // Use the machine name as the overlay ID so any rootfs changes
            // init makes (e.g. `pacman -S git`) are visible to a
            // subsequent `machine exec`. The exec path resolves the
            // overlay from the machine name, falling back to "default",
            // so matching that name here is what makes init's effects
            // observable to the user.
            if let Err(e) = vm_common::run_init_commands(
                &mut client,
                &params.init,
                vm_common::InitRunContext {
                    image: image.as_deref(),
                    image_info: image_info.as_ref(),
                    env: &init_env,
                    workdir: params.workdir.as_deref(),
                    record_mounts: &record_mounts,
                    overlay_id: &vm_name,
                },
            ) {
                // Ephemeral VMs have no state to preserve — `kill()`
                // matches the success path's lifetime semantics
                // (manager.kill() at line ~563/655) and avoids the
                // graceful-shutdown latency `stop()` adds when no one
                // is going to use this VM again.
                vm_common::deregister_ephemeral_vm(&ephemeral_name);
                manager.kill();
                return Err(e);
            }
        }

        // Resolve command: CLI trailing args > Smolfile entrypoint+cmd > image metadata > defaults
        let command = if !self.command.is_empty() {
            self.command.clone()
        } else if !params.entrypoint.is_empty() || !params.cmd.is_empty() {
            let mut cmd = params.entrypoint.clone();
            cmd.extend(params.cmd.clone());
            cmd
        } else if let Some(ref info) = image_info {
            let mut cmd = info.entrypoint.clone();
            cmd.extend(info.cmd.clone());
            if cmd.is_empty() {
                if self.detach {
                    DEFAULT_IDLE_CMD.iter().map(|s| s.to_string()).collect()
                } else {
                    vec![DEFAULT_SHELL_CMD.to_string()]
                }
            } else {
                cmd
            }
        } else if self.detach {
            DEFAULT_IDLE_CMD.iter().map(|s| s.to_string()).collect()
        } else {
            vec![DEFAULT_SHELL_CMD.to_string()]
        };

        let mut env = parse_env_list(&params.env);
        env.extend(resolved_secrets.iter().cloned());
        let mount_bindings = mounts_to_virtiofs_bindings(&mounts);

        // Two modes: with image or bare VM (no image)
        if let Some(ref img) = image {
            let defaults = vm_common::resolve_image_runtime_defaults(
                image_info.as_ref(),
                &env,
                params.workdir.as_deref(),
            );
            if self.detach {
                // Start the main workload container first. If this fails, the
                // VM is stopped and no DB record is written — a retry won't
                // hit "machine already exists."
                {
                    let run_config = smolvm::agent::RunConfig::new(img.clone(), command.clone())
                        .with_env(defaults.env.clone())
                        .with_workdir(defaults.workdir.clone())
                        .with_user(defaults.user.clone())
                        .with_mounts(mount_bindings.clone())
                        .with_persistent_overlay(Some(vm_name.clone()));
                    client.run_container_detached(run_config)?;
                }

                // Container started — persist the DB record. If this fails,
                // stop the VM to avoid an orphan that lifecycle commands can't find.
                {
                    use smolvm::config::SmolvmConfig;
                    use vm_common::DefaultVmOverrides;
                    let mount_tuples: Vec<(String, String, bool)> = mounts
                        .iter()
                        .map(|m| {
                            (
                                m.source.to_string_lossy().to_string(),
                                m.target.to_string_lossy().to_string(),
                                m.read_only,
                            )
                        })
                        .collect();
                    let port_tuples: Vec<(u16, u16)> =
                        params.port.iter().map(|p| (p.host, p.guest)).collect();
                    let persist_result = SmolvmConfig::load().and_then(|mut config| {
                        vm_common::persist_named_running(
                            &mut config,
                            &vm_name,
                            manager.child_pid(),
                            Some(DefaultVmOverrides {
                                // Persist the REFS (re-resolved at each start via
                                // record_env_with_secrets), never the resolved
                                // plaintext — see `env` below.
                                secret_refs: params.secret_refs.clone(),
                                cpus: params.cpus,
                                mem: params.mem,
                                mounts: mount_tuples,
                                ports: port_tuples,
                                network: params.net,
                                network_backend: params.network_backend,
                                storage_gb: params.storage_gb,
                                overlay_gb: params.overlay_gb,
                                allowed_cidrs: params.allowed_cidrs.clone(),
                                init: params.init.clone(),
                                // Strip resolved secret values so plaintext never
                                // reaches the DB/pack record. defaults.env still
                                // carries them for RUNNING the container above; the
                                // record keeps only refs + non-secret env.
                                env: defaults
                                    .env
                                    .iter()
                                    .filter(|(k, _)| !params.secret_refs.contains_key(k))
                                    .cloned()
                                    .collect(),
                                workdir: defaults.workdir.clone(),
                                user: defaults.user.clone(),
                                image: Some(img.clone()),
                                entrypoint: Vec::new(),
                                cmd: command.clone(),
                                ssh_agent: self.ssh_agent || params.ssh_agent,
                                dns_filter_hosts: params.dns_filter_hosts.clone(),
                                gpu: self.gpu || params.gpu,
                                gpu_vram_mib: self.gpu_vram_mib.or(params.gpu_vram_mib),
                            }),
                        )
                    });
                    if let Err(e) = persist_result {
                        let _ = manager.stop();
                        return Err(Error::config(
                            "persist machine record",
                            format!("VM started but record could not be saved: {}. VM stopped to avoid orphan.", e),
                        ));
                    }
                }

                // Disarm SIGINT guard — detaching, VM stays running.
                drop(sigint_guard);

                if vm_name == "default" {
                    println!("Machine running in background");
                    println!("\nTo interact:");
                    println!("  smolvm machine exec -- <command>");
                    println!("\nTo stop:");
                    println!("  smolvm machine stop");
                } else {
                    println!("Machine '{}' running in background", vm_name);
                    println!("\nTo interact:");
                    println!("  smolvm machine exec --name {} -- <command>", vm_name);
                    println!("\nTo stop:");
                    println!("  smolvm machine stop --name {}", vm_name);
                }

                manager.detach();
                Ok(())
            } else {
                // Disarm SIGINT guard — exec phase has its own signal handling.
                if let Some(guard) = sigint_guard {
                    guard.disarm();
                }

                let exit_code = if interactive || tty {
                    let config = RunConfig::new(img, command)
                        .with_env(defaults.env.clone())
                        .with_workdir(defaults.workdir.clone())
                        .with_user(defaults.user.clone())
                        .with_mounts(mount_bindings)
                        .with_timeout(self.timeout)
                        .with_tty(tty);
                    client.run_interactive(config)?
                } else {
                    let config = RunConfig::new(img, command)
                        .with_env(defaults.env)
                        .with_workdir(defaults.workdir)
                        .with_user(defaults.user)
                        .with_mounts(mount_bindings)
                        .with_timeout(self.timeout);
                    let (exit_code, stdout, stderr) = client.run_non_interactive(config)?;
                    if !stdout.is_empty() {
                        let _ = std::io::stdout().write_all(&stdout);
                    }
                    if !stderr.is_empty() {
                        let _ = std::io::stderr().write_all(&stderr);
                    }
                    flush_output();
                    exit_code
                };

                // Ephemeral run — tear down VM and its data directory.
                // Spawn a detached helper so the parent exits immediately after
                // flushing output. Falls back to synchronous cleanup if spawn fails.
                let (pid, start_time) = manager.pid_and_start_time().unwrap_or((0, None));
                if pid > 0 && try_spawn_detached_cleanup(&vm_name, pid, start_time, &ephemeral_name)
                {
                    std::process::exit(exit_code);
                }
                // Fallback: synchronous cleanup (helper spawn failed).
                vm_common::deregister_ephemeral_vm(&ephemeral_name);
                manager.kill();
                manager.cleanup_data_dir();
                std::process::exit(exit_code);
            }
        } else {
            // Bare VM mode (no image) — disarm SIGINT guard before exec.
            if let Some(guard) = sigint_guard {
                guard.disarm();
            }

            if self.detach {
                // Run entrypoint+cmd in background if present
                let is_idle = command.is_empty()
                    || command
                        == DEFAULT_IDLE_CMD
                            .iter()
                            .map(|s| s.to_string())
                            .collect::<Vec<_>>();
                if !is_idle {
                    let pid = client.vm_exec_background(command, env, params.workdir.clone())?;
                    tracing::info!(pid = pid, "background workload started");
                }

                // Persist the VM state so it survives stop/start.
                {
                    use smolvm::config::SmolvmConfig;
                    use vm_common::DefaultVmOverrides;
                    let mount_tuples: Vec<(String, String, bool)> = mounts
                        .iter()
                        .map(|m| {
                            (
                                m.source.to_string_lossy().to_string(),
                                m.target.to_string_lossy().to_string(),
                                m.read_only,
                            )
                        })
                        .collect();
                    let port_tuples: Vec<(u16, u16)> =
                        params.port.iter().map(|p| (p.host, p.guest)).collect();
                    let mut config = SmolvmConfig::load()?;
                    vm_common::persist_named_running(
                        &mut config,
                        &vm_name,
                        manager.child_pid(),
                        Some(DefaultVmOverrides {
                            // Persist the refs so secrets re-resolve on restart
                            // (env below is already secret-free: parse_env_list).
                            secret_refs: params.secret_refs.clone(),
                            cpus: params.cpus,
                            mem: params.mem,
                            mounts: mount_tuples,
                            ports: port_tuples,
                            network: params.net,
                            network_backend: params.network_backend,
                            storage_gb: params.storage_gb,
                            overlay_gb: params.overlay_gb,
                            allowed_cidrs: params.allowed_cidrs.clone(),
                            init: params.init.clone(),
                            env: parse_env_list(&params.env),
                            workdir: params.workdir.clone(),
                            user: None,
                            image: None,
                            entrypoint: params.entrypoint.clone(),
                            cmd: params.cmd.clone(),
                            ssh_agent: self.ssh_agent || params.ssh_agent,
                            dns_filter_hosts: params.dns_filter_hosts.clone(),
                            gpu: self.gpu || params.gpu,
                            gpu_vram_mib: self.gpu_vram_mib.or(params.gpu_vram_mib),
                        }),
                    )?;
                }

                if vm_name == "default" {
                    println!(
                        "Machine running (PID: {})",
                        manager.child_pid().unwrap_or(0)
                    );
                    println!("\nTo interact:");
                    println!("  smolvm machine exec -- <command>");
                    println!("\nTo stop:");
                    println!("  smolvm machine stop");
                } else {
                    println!(
                        "Machine '{}' running (PID: {})",
                        vm_name,
                        manager.child_pid().unwrap_or(0)
                    );
                    println!("\nTo interact:");
                    println!("  smolvm machine exec --name {} -- <command>", vm_name);
                    println!("\nTo stop:");
                    println!("  smolvm machine stop --name {}", vm_name);
                }

                manager.detach();
                Ok(())
            } else {
                let exit_code = if interactive || tty {
                    client.vm_exec_interactive(
                        command,
                        env,
                        params.workdir.clone(),
                        self.timeout,
                        tty,
                    )?
                } else {
                    // Capture for error context before command is moved into vm_exec.
                    let cmd0 = command.first().cloned().unwrap_or_default();
                    let (exit_code, stdout, stderr) = client
                        .vm_exec(command, env, params.workdir.clone(), self.timeout, None)
                        .map_err(|e| {
                            // In bare VM mode a spawn ENOENT often means the user
                            // forgot --image and passed the image name as a positional.
                            // Name the command that wasn't found so the hint is actionable.
                            let msg = e.to_string();
                            if image.is_none()
                                && (msg.contains("No such file or directory")
                                    || msg.contains("os error 2"))
                                && !cmd0.starts_with('/')
                                && !cmd0.starts_with('.')
                            {
                                Error::agent(
                                    "vm exec",
                                    format!(
                                        "{msg}\n\nNote: '{cmd0}' was not found in the VM. \
                                         If you meant to run a container image, use --image:\n  \
                                         smolvm machine run --image {cmd0} -- <command>"
                                    ),
                                )
                            } else {
                                e
                            }
                        })?;
                    if !stdout.is_empty() {
                        let _ = std::io::stdout().write_all(&stdout);
                    }
                    if !stderr.is_empty() {
                        let _ = std::io::stderr().write_all(&stderr);
                    }
                    flush_output();
                    exit_code
                };
                // Ephemeral run — tear down VM and its data directory.
                // Spawn a detached helper so the parent exits immediately after
                // flushing output. Falls back to synchronous cleanup if spawn fails.
                let (pid, start_time) = manager.pid_and_start_time().unwrap_or((0, None));
                if pid > 0 && try_spawn_detached_cleanup(&vm_name, pid, start_time, &ephemeral_name)
                {
                    std::process::exit(exit_code);
                }
                // Fallback: synchronous cleanup (helper spawn failed).
                vm_common::deregister_ephemeral_vm(&ephemeral_name);
                manager.kill();
                manager.cleanup_data_dir();
                std::process::exit(exit_code);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parse_cli_secret_refs_builds_env_and_file_refs() {
        let refs = parse_cli_secret_refs(
            &["GUEST_TOKEN=HOST_TOKEN".to_string()],
            &["GUEST_KEY=/abs/key".to_string()],
        )
        .unwrap();
        assert_eq!(refs["GUEST_TOKEN"].from_env.as_deref(), Some("HOST_TOKEN"));
        assert_eq!(
            refs["GUEST_KEY"]
                .from_file
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned()),
            Some("/abs/key".to_string())
        );
    }

    #[test]
    fn parse_cli_secret_refs_rejects_bad_specs() {
        // Missing '='.
        assert!(parse_cli_secret_refs(&["NO_EQUALS".to_string()], &[]).is_err());
        // Empty key.
        assert!(parse_cli_secret_refs(&["=HOST".to_string()], &[]).is_err());
        // Relative from_file path (validate_ref under TrustedLocal).
        assert!(parse_cli_secret_refs(&[], &["K=relative/path".to_string()]).is_err());
        // Duplicate key across the two flags.
        assert!(
            parse_cli_secret_refs(&["DUP=HOST".to_string()], &["DUP=/abs/path".to_string()])
                .is_err()
        );
    }

    #[derive(Parser, Debug)]
    #[command(name = "machine")]
    struct TestMachineCli {
        #[command(subcommand)]
        command: MachineCmd,
    }

    #[test]
    fn run_detach_accepts_name_flag() {
        let cli = TestMachineCli::parse_from([
            "machine", "run", "-d", "--name", "foo", "--image", "alpine",
        ]);

        let MachineCmd::Run(cmd) = cli.command else {
            panic!("expected machine run command");
        };
        assert_eq!(cmd.name, Some("foo".to_string()));
        assert!(cmd.detach);
    }

    // Documents the clap parsing behaviour: positionals before "--" land in
    // `command`, not `image`.  is_likely_image_ref() catches the unambiguous
    // cases before a VM is booted.
    #[test]
    fn run_image_ref_as_positional_lands_in_command_vec() {
        let cli = TestMachineCli::parse_from(["machine", "run", "ubuntu:22.04", "--", "bash"]);
        let MachineCmd::Run(cmd) = cli.command else {
            panic!("expected machine run command");
        };
        assert_eq!(cmd.image, None);
        // With trailing_var_arg, clap includes the "--" separator in the vec.
        assert_eq!(cmd.command, ["ubuntu:22.04", "--", "bash"]);
        // is_likely_image_ref catches this before the VM starts
        assert!(is_likely_image_ref(&cmd.command[0]));
    }

    #[test]
    fn create_accepts_trailing_workload_command() {
        let cli = TestMachineCli::parse_from([
            "machine", "create", "--name", "golden", "--image", "alpine", "--", "echo", "hi",
        ]);
        let MachineCmd::Create(cmd) = cli.command else {
            panic!("expected machine create command");
        };
        assert_eq!(cmd.name, Some("golden".to_string()));
        assert_eq!(cmd.image, Some("alpine".to_string()));
        // The trailing command is captured (clap may include the "--" separator).
        let words: Vec<&str> = cmd
            .command
            .iter()
            .map(String::as_str)
            .filter(|s| *s != "--")
            .collect();
        assert_eq!(words, ["echo", "hi"]);
    }

    #[test]
    fn create_without_command_leaves_command_empty() {
        // Regression: adding the trailing COMMAND arg must not break the common
        // no-command form `machine create --name <name> --net`.
        let cli = TestMachineCli::parse_from(["machine", "create", "--name", "golden", "--net"]);
        let MachineCmd::Create(cmd) = cli.command else {
            panic!("expected machine create command");
        };
        assert_eq!(cmd.name, Some("golden".to_string()));
        assert!(cmd.command.is_empty());
        assert!(cmd.net);
    }

    #[test]
    fn create_rejects_bare_positional_name() {
        // Machine names are flags everywhere (issue #370). A bare positional —
        // the old `machine create myvm` habit — must error, not be silently
        // captured as the workload command.
        assert!(TestMachineCli::try_parse_from(["machine", "create", "myvm"]).is_err());
    }

    #[test]
    fn is_likely_image_ref_classifies_correctly() {
        // Unambiguous image references
        assert!(is_likely_image_ref("ubuntu:22.04")); // image:tag
        assert!(is_likely_image_ref("ghcr.io/org/image")); // registry/path
        assert!(is_likely_image_ref("library/alpine")); // namespace/image

        // Bare names are not flagged — indistinguishable from commands at parse time
        assert!(!is_likely_image_ref("alpine"));
        assert!(!is_likely_image_ref("bash"));

        // Absolute and relative paths are always commands
        assert!(!is_likely_image_ref("/bin/sh"));
        assert!(!is_likely_image_ref("./script.sh"));
    }
}

// ============================================================================
// Exec Command (Persistent) - Direct VM Execution
// ============================================================================

/// Execute a command directly in the VM's Alpine rootfs.
///
/// This runs commands at the VM level, not inside a container. Useful for
/// debugging, inspecting the VM environment, or running VM-level operations.
///
/// Examples:
///   smolvm machine exec -- uname -a
///   smolvm machine exec --name myvm -- df -h
///   smolvm machine exec -it -- /bin/sh
#[derive(Args, Debug)]
pub struct ExecCmd {
    /// Command and arguments to execute
    #[arg(trailing_var_arg = true, required = true, value_name = "COMMAND")]
    pub command: Vec<String>,

    /// Target machine (default: "default")
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,

    /// Set working directory in the VM
    #[arg(short = 'w', long, value_name = "DIR")]
    pub workdir: Option<String>,

    /// Set environment variable (can be used multiple times)
    #[arg(short = 'e', long = "env", value_name = "KEY=VALUE")]
    pub env: Vec<String>,

    /// Inject a secret from a host env var (GUEST_VAR=HOST_VAR) for this exec,
    /// resolved on the host. The value never persists to the record.
    #[arg(long = "secret-env", value_name = "GUEST_VAR=HOST_VAR")]
    pub secret_env: Vec<String>,

    /// Inject a secret from a host file (GUEST_VAR=/abs/path) for this exec,
    /// resolved on the host. The value never persists to the record.
    #[arg(long = "secret-file", value_name = "GUEST_VAR=PATH")]
    pub secret_file: Vec<String>,

    /// Kill command after duration (e.g., "30s", "5m")
    #[arg(long, value_parser = parse_duration, value_name = "DURATION")]
    pub timeout: Option<Duration>,

    /// Keep stdin open for interactive input
    #[arg(short = 'i', long)]
    pub interactive: bool,

    /// Allocate a pseudo-TTY (use with -i for shells)
    #[arg(short = 't', long)]
    pub tty: bool,

    /// Stream output in real-time (prints as it arrives)
    #[arg(long)]
    pub stream: bool,
}

impl ExecCmd {
    pub fn run(self) -> smolvm::Result<()> {
        let (manager, mut client) = vm_common::ensure_running_and_connect(&self.name)?;

        // Detach immediately — exec never owns the VM lifecycle. Without this,
        // any early return (failed exec, timeout, client signal) triggers
        // AgentManager::Drop which calls stop() and kills the VM.
        manager.detach();

        let env = parse_env_list(&self.env);

        // Load machine record for workdir and image info
        let name = self.name.clone().unwrap_or_else(|| "default".to_string());
        let record = smolvm::db::SmolvmDb::open()
            .ok()
            .and_then(|db| db.get_vm(&name).ok().flatten());

        // Resolve workdir: CLI --workdir flag takes priority over Smolfile/machine config
        let workdir = self
            .workdir
            .clone()
            .or_else(|| record.as_ref().and_then(|r| r.workdir.clone()));
        let record_image = record.as_ref().and_then(|r| r.image.clone());

        // Check if this machine has an image — if so, exec inside the image's
        // rootfs via client.run_interactive()/run_non_interactive() instead of bare vm_exec().
        let mount_bindings = record
            .as_ref()
            .map(|r| mounts_to_virtiofs_bindings(&r.host_mounts()))
            .unwrap_or_default();

        // Base env for the exec: the record's persisted `env` plus its
        // `secret_refs` resolved to plaintext on the host (RecordReplay scope).
        // CLI `--env` flags are layered on top via `merge_env_overrides`. The
        // resolved plaintext lives only in this local for the exec's duration —
        // it is never written back to the record or the DB.
        let mut record_env: Vec<(String, String)> = match record.as_ref() {
            Some(r) => vm_common::record_env_with_secrets(r)?,
            None => Vec::new(),
        };
        // Ad-hoc `--secret-env`/`--secret-file` refs for this exec only. The CLI
        // user is TrustedLocal; resolved plaintext lives only in this local and
        // is layered under any explicit `--env` overrides below.
        let exec_secret_refs = parse_cli_secret_refs(&self.secret_env, &self.secret_file)?;
        record_env.extend(smolvm::secrets::expose_into_env(
            smolvm::secrets::resolve_refs_to_env(
                &exec_secret_refs,
                smolvm::secrets::ResolutionScope::TrustedLocal,
            )?,
        ));

        if let Some(ref image) = record_image {
            let image_info = match client.query(image) {
                Ok(info) => info,
                Err(e) => {
                    tracing::debug!(
                        error = %e,
                        image = %image,
                        "failed to query local image metadata"
                    );
                    None
                }
            };
            let configured_env = vm_common::merge_env_overrides(&record_env, &env);
            let defaults = vm_common::resolve_image_runtime_defaults(
                image_info.as_ref(),
                &configured_env,
                workdir.as_deref(),
            );
            // Image-based machine: exec inside the image's rootfs via crun.
            // Use machine name as persistent overlay ID so filesystem changes
            // (e.g. package installs) survive across exec sessions.
            let machine_name = name.clone();
            if self.interactive || self.tty {
                let config = smolvm::agent::RunConfig::new(image, self.command.clone())
                    .with_env(defaults.env.clone())
                    .with_workdir(defaults.workdir.clone())
                    .with_user(defaults.user.clone())
                    .with_mounts(mount_bindings)
                    .with_timeout(self.timeout)
                    .with_tty(self.tty)
                    .with_persistent_overlay(Some(machine_name.clone()));
                let exit_code = client.run_interactive(config)?;
                std::process::exit(exit_code);
            }

            if self.stream {
                let config = smolvm::agent::RunConfig::new(image, self.command.clone())
                    .with_env(defaults.env.clone())
                    .with_workdir(defaults.workdir.clone())
                    .with_user(defaults.user.clone())
                    .with_mounts(mount_bindings)
                    .with_timeout(self.timeout)
                    .with_persistent_overlay(Some(machine_name.clone()));
                let mut printer = ExecEventPrinter::default();
                client.run_streaming_with(config, |event| printer.handle(event))?;
                std::process::exit(printer.exit_code);
            }

            let config = smolvm::agent::RunConfig::new(image, self.command.clone())
                .with_env(defaults.env)
                .with_workdir(defaults.workdir)
                .with_user(defaults.user)
                .with_mounts(mount_bindings)
                .with_timeout(self.timeout)
                .with_persistent_overlay(Some(machine_name));
            let (exit_code, stdout, stderr) = client.run_non_interactive(config)?;
            vm_common::print_output_and_exit(&manager, exit_code, &stdout, &stderr);
        } else {
            // Bare VM: exec directly in the VM rootfs.
            // Merge record env + resolved secrets with CLI env, same as image path.
            let env = vm_common::merge_env_overrides(&record_env, &env);
            if self.interactive || self.tty {
                let exit_code = client.vm_exec_interactive(
                    self.command.clone(),
                    env.clone(),
                    workdir.clone(),
                    self.timeout,
                    self.tty,
                )?;
                std::process::exit(exit_code);
            }

            if self.stream {
                let mut printer = ExecEventPrinter::default();
                client.vm_exec_streaming_with(
                    self.command.clone(),
                    env.clone(),
                    workdir.clone(),
                    self.timeout,
                    |event| printer.handle(event),
                )?;
                std::process::exit(printer.exit_code);
            }

            let (exit_code, stdout, stderr) = client.vm_exec(
                self.command.clone(),
                env,
                workdir.clone(),
                self.timeout,
                None,
            )?;
            vm_common::print_output_and_exit(&manager, exit_code, &stdout, &stderr);
        }
    }
}

#[derive(Default)]
struct ExecEventPrinter {
    exit_code: i32,
}

impl ExecEventPrinter {
    fn handle(&mut self, event: smolvm::agent::ExecEvent) {
        match event {
            smolvm::agent::ExecEvent::Stdout(data) => {
                let _ = std::io::stdout().write_all(&data);
                let _ = std::io::stdout().flush();
            }
            smolvm::agent::ExecEvent::Stderr(data) => {
                let _ = std::io::stderr().write_all(&data);
                let _ = std::io::stderr().flush();
            }
            smolvm::agent::ExecEvent::Exit(code) => {
                self.exit_code = code;
            }
            smolvm::agent::ExecEvent::Error(msg) => {
                eprintln!("error: {}", msg);
                self.exit_code = 1;
            }
        }
    }
}

// ============================================================================
// Shell Command
// ============================================================================

/// Open an interactive shell in a machine.
///
/// Shortcut for `machine exec -it -- /bin/sh`. Starts the machine if stopped.
///
/// Examples:
///   smolvm machine shell
///   smolvm machine shell --name myvm
///   smolvm machine sh --name myvm
#[derive(Args, Debug)]
pub struct ShellCmd {
    /// Target machine (default: "default")
    #[arg(long, short = 'n', value_name = "NAME")]
    pub name: Option<String>,
}

impl ShellCmd {
    pub fn run(self) -> smolvm::Result<()> {
        // Delegate to exec with -it -- /bin/sh
        ExecCmd {
            command: vec!["/bin/sh".to_string()],
            name: self.name,
            workdir: None,
            env: vec![],
            secret_env: vec![],
            secret_file: vec![],
            timeout: None,
            interactive: true,
            tty: true,
            stream: false,
        }
        .run()
    }
}

// ============================================================================
// Create Command
// ============================================================================

/// Create a named machine configuration.
///
/// Creates a persistent VM configuration that can be started later.
/// Use `smolvm machine start --name <name>` to start, then
/// `smolvm machine exec --name <name> -- <command>` to run commands inside.
///
/// Examples:
///   smolvm machine create --name myvm
///   smolvm machine create --name webserver --cpus 2 --mem 1024 -p 80:80
#[derive(Args, Debug)]
pub struct CreateCmd {
    /// Name for the machine (auto-generated if omitted)
    #[arg(short = 'n', long, value_name = "NAME")]
    pub name: Option<String>,

    /// Container image (e.g., alpine, python:3.12-alpine)
    #[arg(short = 'I', long, value_name = "IMAGE", value_parser = parse_image)]
    pub image: Option<String>,

    /// Raise the max accepted local image-archive size (e.g. 16GiB, 512M, or a
    /// raw byte count); default 8GiB. For legitimately large images — sets
    /// SMOLVM_MAX_IMAGE_BYTES for this run.
    #[arg(long = "max-image-size", value_name = "SIZE",
          value_parser = crate::cli::parsers::parse_size_bytes)]
    pub max_image_size: Option<u64>,

    /// Number of virtual CPUs
    #[arg(long, default_value_t = DEFAULT_MICROVM_CPU_COUNT, value_name = "N")]
    pub cpus: u8,

    /// Memory allocation in MiB
    #[arg(long, default_value_t = DEFAULT_MICROVM_MEMORY_MIB, value_name = "MiB")]
    pub mem: u32,

    /// Storage disk size in GiB (for OCI layers and container data)
    #[arg(long, value_name = "GiB")]
    pub storage: Option<u64>,

    /// Overlay disk size in GiB (for persistent rootfs changes)
    #[arg(long, value_name = "GiB")]
    pub overlay: Option<u64>,

    /// Mount host directory (can be used multiple times)
    #[arg(short = 'v', long = "volume", value_name = "HOST:GUEST[:ro]")]
    pub volume: Vec<String>,

    /// Expose port from VM to host (can be used multiple times)
    #[arg(short = 'p', long = "port", value_parser = PortMapping::parse, value_name = "HOST:GUEST")]
    pub port: Vec<PortMapping>,

    /// Enable outbound network access
    #[arg(long)]
    pub net: bool,

    /// Select the networking backend.
    #[arg(long = "net-backend", value_enum)]
    pub net_backend: Option<NetworkBackend>,

    /// Allow egress to specific CIDR range (can be used multiple times, implies --net)
    #[arg(long = "allow-cidr", value_parser = parse_cidr, value_name = "CIDR")]
    pub allow_cidr: Vec<String>,

    /// Allow egress to specific hostname, resolved at VM start (can be used multiple times, implies --net)
    #[arg(long = "allow-host", value_name = "HOSTNAME")]
    pub allow_host: Vec<String>,

    /// Restrict outbound to localhost only (implies --net)
    #[arg(long)]
    pub outbound_localhost_only: bool,

    /// Enable GPU acceleration (Vulkan via virtio-gpu)
    #[arg(long)]
    pub gpu: bool,

    /// GPU shared-memory region size in MiB. Ignored without --gpu.
    /// Default 4096 (4 GiB). Must be > 0.
    #[arg(
        long = "gpu-vram",
        value_name = "MiB",
        value_parser = crate::cli::parsers::parse_gpu_vram_mib,
    )]
    pub gpu_vram_mib: Option<u32>,

    /// Run command on every VM start (can be used multiple times)
    #[arg(long = "init", value_name = "COMMAND")]
    pub init: Vec<String>,

    /// Set environment variable (can be used multiple times)
    #[arg(short = 'e', long = "env", value_name = "KEY=VALUE")]
    pub env: Vec<String>,

    /// Set working directory inside the machine
    #[arg(short = 'w', long = "workdir", value_name = "DIR")]
    pub workdir: Option<String>,

    /// Forward host SSH agent into the VM (enables git/ssh without exposing keys)
    #[arg(long)]
    pub ssh_agent: bool,

    /// Inject a secret from a host env var (GUEST_VAR=HOST_VAR), resolved at
    /// each launch. Only the reference is persisted, never the value.
    #[arg(long = "secret-env", value_name = "GUEST_VAR=HOST_VAR")]
    pub secret_env: Vec<String>,

    /// Inject a secret from a host file (GUEST_VAR=/abs/path), resolved at
    /// each launch. Only the reference is persisted, never the value.
    #[arg(long = "secret-file", value_name = "GUEST_VAR=PATH")]
    pub secret_file: Vec<String>,

    /// Load configuration from a Smolfile (TOML)
    #[arg(long = "smolfile", visible_short_alias = 's', value_name = "PATH")]
    pub smolfile: Option<PathBuf>,

    /// Create machine from a packed .smolmachine artifact.
    /// Uses pre-extracted layers instead of pulling from a registry.
    #[arg(long, value_name = "PATH", conflicts_with_all = ["image", "smolfile"])]
    pub from: Option<PathBuf>,

    /// Command to run as the machine's persistent workload (image machines).
    /// Launched as a detached container on every `start`, so it stays running
    /// (e.g. a pre-warmed browser to be forked). Without this, an image machine
    /// boots to a bare agent and the image's CMD is not run.
    ///
    /// `last = true` requires the `--` separator. With the machine name now a
    /// flag, a bare positional (an old-style `machine create myvm`) must fail
    /// loudly instead of being silently captured as the workload command.
    #[arg(last = true, value_name = "COMMAND")]
    pub command: Vec<String>,
}

impl CreateCmd {
    pub fn run(self) -> smolvm::Result<()> {
        // --max-image-size raises the archive cap for this invocation by setting
        // the env var the resolver reads (image_source::max_archive_bytes).
        if let Some(bytes) = self.max_image_size {
            std::env::set_var("SMOLVM_MAX_IMAGE_BYTES", bytes.to_string());
        }
        // Branch for --from: create machine from .smolmachine artifact.
        if let Some(ref sidecar_path) = self.from {
            return self.run_from_smolmachine(sidecar_path);
        }

        let (cli_allow_cidrs, net, cli_dns_filter_hosts) = resolve_egress_flags(
            self.allow_cidr,
            self.allow_host,
            self.outbound_localhost_only,
            self.net,
        )?;

        let name = self
            .name
            .unwrap_or_else(smolvm::util::generate_machine_name);

        // Resolve a local image source (archive/dir) on the host now: stage it
        // into the content-addressed cache and persist the resulting `local:…`
        // reference, so `start` re-derives the mount dir without a registry
        // pull. Registry refs pass through unchanged.
        let image = match self.image.as_deref() {
            Some(img) => {
                use smolvm::data::image_source::{classify, resolve, ResolvedImage};
                Some(match resolve(classify(img))? {
                    ResolvedImage::Registry(reference) => reference,
                    ResolvedImage::Local { reference, .. } => reference,
                })
            }
            None => None,
        };

        let params = crate::cli::smolfile::build_create_params(
            name,
            image,
            None,         // entrypoint: from Smolfile only
            self.command, // persistent-workload command (detached container on start)
            self.cpus,
            self.mem,
            self.volume,
            self.port,
            net,
            self.net_backend,
            self.init,
            self.env,
            self.workdir,
            self.smolfile,
            self.storage,
            self.overlay,
            cli_allow_cidrs,
        )?;
        let mut params = params;
        params.dns_filter_hosts = match (params.dns_filter_hosts.take(), cli_dns_filter_hosts) {
            (Some(mut from_smolfile), Some(mut from_cli)) => {
                from_smolfile.append(&mut from_cli);
                Some(from_smolfile)
            }
            (Some(from_smolfile), None) => Some(from_smolfile),
            (None, some) => some,
        };
        // CLI `--secret-env`/`--secret-file` refs merge over any Smolfile
        // `[secrets]` of the same name (CLI wins). Only refs are persisted.
        for (key, r) in parse_cli_secret_refs(&self.secret_env, &self.secret_file)? {
            params.secret_refs.insert(key, r);
        }
        let resources = VmResources {
            cpus: params.cpus,
            memory_mib: params.mem,
            network: params.net,
            network_backend: params.network_backend,
            gpu: params.gpu,
            gpu_vram_mib: params.gpu_vram_mib,
            storage_gib: params.storage_gb,
            overlay_gib: params.overlay_gb,
            allowed_cidrs: params.allowed_cidrs.clone(),
        };
        // Reject zero-valued resources before the machine is persisted.
        // Without this, `machine create` succeeds and the failure only
        // surfaces later at `machine start` (see QA BUG-44).
        resources.validate()?;
        validate_requested_network_backend(
            &resources,
            params.dns_filter_hosts.as_deref(),
            params.port.len(),
        )?;
        if self.ssh_agent {
            params.ssh_agent = true;
        }
        if self.gpu {
            params.gpu = true;
        }
        // CLI --gpu-vram takes precedence over Smolfile gpu_vram.
        if let Some(vram) = self.gpu_vram_mib {
            params.gpu_vram_mib = Some(vram);
        }
        PortMapping::check_duplicates(&params.port)
            .map_err(|e| smolvm::Error::config("validate ports", e))?;
        vm_common::create_vm(params)
    }

    /// Create a machine from a .smolmachine artifact.
    fn run_from_smolmachine(&self, sidecar_path: &std::path::Path) -> smolvm::Result<()> {
        use smolvm::data::resources::{DEFAULT_MICROVM_CPU_COUNT, DEFAULT_MICROVM_MEMORY_MIB};

        if !sidecar_path.exists() {
            return Err(smolvm::Error::config(
                "create from .smolmachine",
                format!("file not found: {}", sidecar_path.display()),
            ));
        }

        // Read manifest from the sidecar to get image metadata.
        let manifest = smolvm_pack::packer::read_manifest_from_sidecar(sidecar_path)
            .map_err(|e| smolvm::Error::agent("read .smolmachine", e.to_string()))?;

        // Read the footer now; the bundle is extracted into the machine's own
        // data dir after `create_vm` succeeds (below), so a duplicate-name create
        // cannot clobber an existing machine's layers.
        let footer = smolvm_pack::packer::read_footer_from_sidecar(sidecar_path)
            .map_err(|e| smolvm::Error::agent("read sidecar footer", e.to_string()))?;

        // Resolve the canonical path for storage in VmRecord.
        let canonical_path = sidecar_path
            .canonicalize()
            .unwrap_or_else(|_| sidecar_path.to_path_buf())
            .to_string_lossy()
            .into_owned();

        let name = self
            .name
            .clone()
            .unwrap_or_else(smolvm::util::generate_machine_name);
        // `name` is moved into `params` below; keep a copy for the post-create
        // extraction that targets this machine's own data dir.
        let name_for_layers = name.clone();

        // CLI flags override manifest defaults.
        let cpus = if self.cpus != DEFAULT_MICROVM_CPU_COUNT {
            self.cpus
        } else {
            manifest.cpus
        };
        let mem = if self.mem != DEFAULT_MICROVM_MEMORY_MIB {
            self.mem
        } else {
            manifest.mem
        };

        // A .smolmachine is an untrusted, portable artifact: validate its secret
        // refs under the Untrusted scope, which rejects every source kind. A
        // packed `from_env`/`from_file` ref would otherwise read THIS host's
        // env/files at exec time — reject at create rather than carry an exfil
        // primitive. Configure secrets locally via the CLI instead.
        for (key, r) in &manifest.secret_refs {
            smolvm::secrets::validate_ref(r, smolvm::secrets::ResolutionScope::Untrusted).map_err(
                |e| {
                    smolvm::Error::config(
                        "create from .smolmachine",
                        format!("secret '{}': {} (packs may not carry secret refs)", key, e),
                    )
                },
            )?;
        }

        let params = vm_common::CreateVmParams {
            secret_refs: manifest.secret_refs,
            name,
            image: Some(manifest.image),
            entrypoint: manifest.entrypoint,
            cmd: manifest.cmd,
            cpus,
            mem,
            volume: self.volume.clone(),
            port: self.port.clone(),
            net: self.net || manifest.network,
            network_backend: self.net_backend,
            init: self.init.clone(),
            env: {
                let mut env = manifest.env;
                env.extend(self.env.iter().cloned());
                env
            },
            workdir: manifest.workdir,
            storage_gb: self.storage,
            overlay_gb: self.overlay,
            allowed_cidrs: None,
            restart_policy: None,
            restart_max_retries: None,
            restart_max_backoff_secs: None,
            health_cmd: None,
            health_interval_secs: None,
            health_timeout_secs: None,
            health_retries: None,
            health_startup_grace_secs: None,
            ssh_agent: self.ssh_agent,
            dns_filter_hosts: None,
            gpu: manifest.gpu,
            gpu_vram_mib: None,
            source_smolmachine: Some(canonical_path),
        };

        let record = vm_common::build_vm_record(&params)?;
        let reservation = vm_common::CreateVmReservation::reserve(&name_for_layers)?;

        // Create the machine data dir while the DB reservation is held, then
        // extract before publishing the VM row. Other processes either see the
        // reservation conflict or the finished VM, never a half-created record.
        let create_result = (|| -> smolvm::Result<()> {
            let _manager = AgentManager::for_vm_with_sizes(
                &name_for_layers,
                params.storage_gb,
                params.overlay_gb,
            )?;

            let cache_dir = smolvm::agent::machine_layers_cache_dir(&name_for_layers);
            smolvm_pack::extract::force_detach_layers_volume(&cache_dir);
            match std::fs::remove_dir_all(&cache_dir) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(smolvm::Error::agent(
                        "clear packed layers cache",
                        e.to_string(),
                    ));
                }
            }

            println!("Extracting .smolmachine assets...");
            let result = smolvm_pack::extract::extract_sidecar(
                sidecar_path,
                &cache_dir,
                &footer,
                false,
                false,
            )
            .map_err(|e| smolvm::Error::agent("extract sidecar", e.to_string()));
            // Detach unconditionally: extraction mounts the case-sensitive volume on
            // macOS even when it later fails, so the detach must run on both success
            // and failure paths to honor the "mounted iff running" invariant.
            smolvm_pack::extract::force_detach_layers_volume(&cache_dir);
            result?;

            reservation.commit(&record)?;
            Ok(())
        })();

        if let Err(e) = create_result {
            smolvm_pack::extract::force_detach_layers_volume(
                &smolvm::agent::machine_layers_cache_dir(&name_for_layers),
            );
            let data_dir = smolvm::agent::vm_data_dir(&name_for_layers);
            if let Err(remove_err) = std::fs::remove_dir_all(&data_dir) {
                if remove_err.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(
                        machine = %name_for_layers,
                        dir = %data_dir.display(),
                        error = %remove_err,
                        "failed to remove machine data dir after create failure"
                    );
                }
            }
            return Err(e);
        }

        vm_common::print_create_success(&params);
        Ok(())
    }
}

// ============================================================================
// Start Command
// ============================================================================

/// Start a machine.
///
/// Starts the VM process. If no name is given, starts the default VM.
#[derive(Args, Debug)]
pub struct StartCmd {
    /// Machine to start (default: "default")
    #[arg(short = 'n', long, value_name = "NAME")]
    pub name: Option<String>,

    /// Start as a fork base: back guest RAM with a memfd (CoW-cloneable) and
    /// expose a control socket so the machine can be forked with `machine fork`.
    #[arg(long)]
    pub forkable: bool,

    #[command(flatten, next_help_heading = "Network")]
    pub proxy_opts: crate::cli::proxy_opts::ProxyOpts,
}

impl StartCmd {
    pub fn run(self) -> smolvm::Result<()> {
        let explicit_name = self.name.is_some();
        let name = self.name.unwrap_or_else(|| "default".to_string());
        let proxy = self.proxy_opts.proxy();
        let no_proxy = self.proxy_opts.no_proxy();
        if self.forkable {
            // Read by launcher.rs in the spawned _boot-vm (inherits our env):
            // memfd-back guest RAM and register a control socket at a known path
            // so `machine fork` can later freeze this machine as a CoW base.
            vm_common::enable_forkable_env(&name);
        }
        match vm_common::start_vm_named(&name, proxy, no_proxy, /* from_snapshot */ false) {
            Ok(()) => Ok(()),
            Err(smolvm::Error::VmNotFound { .. }) if !explicit_name => {
                // Only fall back to creating a default VM when no --name was given.
                // With an explicit --name, VmNotFound is a real error.
                vm_common::start_vm_default(proxy, no_proxy)
            }
            Err(e) => Err(e),
        }
    }
}

// ============================================================================
// Fork Command
// ============================================================================

/// Fork a running forkable machine into a new clone.
///
/// Freezes the source (the "golden") via its control socket, copy-on-write
/// clones its disks, and boots the new machine from the golden's in-memory
/// snapshot instead of cold-booting — so the clone comes up already warm
/// (same processes, same filesystem state), in well under a second.
///
/// The golden must have been started with `--forkable`.
#[derive(Args, Debug)]
pub struct ForkCmd {
    /// The running, forkable source machine to clone from.
    #[arg(long, value_name = "NAME")]
    pub golden: String,

    /// Name for the new clone machine.
    #[arg(short = 'n', long = "name", value_name = "NAME")]
    pub clone: String,

    /// Make the clone itself forkable (memfd RAM + control socket), so it can
    /// in turn be forked.
    #[arg(long)]
    pub forkable: bool,

    /// Pin the clone's inbound port forwards (repeatable). Without this, the
    /// golden's forwards are remapped to freshly-allocated host ports.
    #[arg(short = 'p', long = "port", value_parser = PortMapping::parse, value_name = "HOST:GUEST", help_heading = "Network")]
    pub port: Vec<PortMapping>,
}

impl ForkCmd {
    pub fn run(self) -> smolvm::Result<()> {
        let ports: Vec<(u16, u16)> = self.port.iter().map(|p| (p.host, p.guest)).collect();
        vm_common::fork_vm(&self.golden, &self.clone, self.forkable, &ports)
    }
}

// ============================================================================
// Stop Command
// ============================================================================

/// Stop a running machine.
///
/// Gracefully stops the VM process. Running containers will be terminated.
#[derive(Args, Debug)]
pub struct StopCmd {
    /// Machine to stop (default: "default")
    #[arg(short = 'n', long, value_name = "NAME")]
    pub name: Option<String>,
}

impl StopCmd {
    pub fn run(self) -> smolvm::Result<()> {
        let name = vm_common::resolve_vm_name(self.name)?;
        match &name {
            Some(name) => vm_common::stop_vm_named(name),
            None => vm_common::stop_vm_default(),
        }
    }
}

// ============================================================================
// Delete Command
// ============================================================================

/// Delete a machine configuration.
///
/// Removes the VM configuration. Does not delete container data.
#[derive(Args, Debug)]
pub struct DeleteCmd {
    /// Machine to delete
    #[arg(short = 'n', long, value_name = "NAME")]
    pub name: String,

    /// Skip confirmation prompt
    #[arg(short, long)]
    pub force: bool,
}

impl DeleteCmd {
    pub fn run(&self) -> smolvm::Result<()> {
        vm_common::delete_vm(
            &self.name,
            self.force,
            DeleteVmOptions {
                // Stop the VM before removing its config and data dir.
                // Without this, deleting a running machine orphans the
                // `_boot-vm` process (leaking host RAM) and removes the data
                // dir out from under the live VM. The API delete handler and
                // `delete_vm`'s own teardown already do this.
                stop_if_running: true,
            },
        )
    }
}

// ============================================================================
// Status Command
// ============================================================================

/// Show machine status.
///
/// Displays whether the VM is running and its process ID.
#[derive(Args, Debug)]
pub struct StatusCmd {
    /// Machine to check (default: "default")
    #[arg(short = 'n', long, value_name = "NAME")]
    pub name: Option<String>,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

impl StatusCmd {
    pub fn run(self) -> smolvm::Result<()> {
        if self.json {
            return vm_common::status_vm_json(&self.name);
        }
        vm_common::status_vm(&self.name, |_| {})
    }
}

// ============================================================================
// Ls Command
// ============================================================================

/// List all machines.
///
/// Shows all configured VMs with their state, resources, and configuration.
#[derive(Args, Debug)]
pub struct LsCmd {
    /// Show detailed configuration (mounts, ports, PID)
    #[arg(short, long)]
    pub verbose: bool,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

impl LsCmd {
    pub fn run(&self) -> smolvm::Result<()> {
        vm_common::list_vms(self.verbose, self.json)
    }
}

// ============================================================================
// Resize Command
// ============================================================================

/// Resize a machine's disk resources.
///
/// Expands the storage and/or overlay disk for a stopped machine.
/// The VM must be stopped before resizing. Disk expansion happens
/// immediately; filesystem resize occurs automatically on next boot.
///
/// Examples:
///   smolvm machine resize --name my-vm --storage 50
///   smolvm machine resize --name my-vm --overlay 20
///   smolvm machine resize --name my-vm --storage 50 --overlay 20
///   smolvm machine resize --storage 50  # default VM
#[derive(Args, Debug)]
#[command(group(
    clap::ArgGroup::new("resize-target")
        .required(true)
        .args(["storage", "overlay"])
        .multiple(true)
))]
pub struct ResizeCmd {
    /// Machine to resize (default: "default")
    #[arg(short = 'n', long, value_name = "NAME")]
    pub name: Option<String>,

    /// Storage disk size in GiB (expand only)
    #[arg(long, value_name = "GiB")]
    pub storage: Option<u64>,

    /// Overlay disk size in GiB (expand only)
    #[arg(long, value_name = "GiB")]
    pub overlay: Option<u64>,
}

impl ResizeCmd {
    pub fn run(self) -> smolvm::Result<()> {
        let name = vm_common::resolve_vm_name(self.name)?;
        let name_str = name.as_deref().unwrap_or("default");

        vm_common::resize_vm(name_str, self.storage, self.overlay).map_err(|e| {
            if matches!(&e, smolvm::Error::InvalidState { .. }) {
                smolvm::Error::agent(
                    "resize",
                    format!(
                        "VM '{}' is running. Stop it first with: smolvm machine stop --name {}",
                        name_str, name_str
                    ),
                )
            } else {
                e
            }
        })
    }
}

// ============================================================================
// Update Command
// ============================================================================

/// Modify settings on a stopped machine.
///
/// Changes are applied to the DB record and take effect on the next
/// `machine start`. The machine must be stopped.
///
/// Examples:
///   smolvm machine update --name myvm -v ./src:/app -p 8080:8080
///   smolvm machine update --name myvm --cpus 4 --mem 4096
///   smolvm machine update --name myvm --remove-volume ./src:/app
///   smolvm machine update --name myvm --net -e DEBUG=1
#[derive(Args, Debug)]
pub struct UpdateCmd {
    /// Machine to update
    #[arg(short = 'n', long, value_name = "NAME")]
    pub name: String,

    /// Add volume mount (HOST:GUEST[:ro])
    #[arg(short = 'v', long = "volume", value_name = "HOST:GUEST[:ro]")]
    pub volume: Vec<String>,

    /// Remove volume mount (HOST:GUEST)
    #[arg(long, value_name = "HOST:GUEST")]
    pub remove_volume: Vec<String>,

    /// Add port mapping (HOST:GUEST)
    #[arg(short = 'p', long = "port", value_parser = PortMapping::parse, value_name = "HOST:GUEST")]
    pub port: Vec<PortMapping>,

    /// Remove port mapping (HOST:GUEST)
    #[arg(long, value_parser = PortMapping::parse, value_name = "HOST:GUEST")]
    pub remove_port: Vec<PortMapping>,

    /// Set vCPU count
    #[arg(long, value_name = "N")]
    pub cpus: Option<u8>,

    /// Set memory in MiB
    #[arg(long, value_name = "MiB")]
    pub mem: Option<u32>,

    /// Enable outbound network access
    #[arg(long)]
    pub net: bool,

    /// Disable outbound network access
    #[arg(long, conflicts_with = "net")]
    pub no_net: bool,

    /// Add/replace environment variable (KEY=VALUE)
    #[arg(short = 'e', long = "env", value_name = "KEY=VALUE")]
    pub env: Vec<String>,

    /// Remove environment variable by key
    #[arg(long, value_name = "KEY")]
    pub remove_env: Vec<String>,

    /// Set working directory
    #[arg(short = 'w', long, value_name = "DIR")]
    pub workdir: Option<String>,

    /// Enable GPU acceleration
    #[arg(long)]
    pub gpu: bool,

    /// Disable GPU acceleration
    #[arg(long, conflicts_with = "gpu")]
    pub no_gpu: bool,

    /// Storage disk size in GiB (expand only)
    #[arg(long, value_name = "GiB")]
    pub storage: Option<u64>,

    /// Overlay disk size in GiB (expand only)
    #[arg(long, value_name = "GiB")]
    pub overlay: Option<u64>,
}

impl UpdateCmd {
    pub fn run(self) -> smolvm::Result<()> {
        use smolvm::config::RecordState;
        use smolvm::data::storage::HostMount;

        let db = smolvm::db::SmolvmDb::open()?;
        let record = db.get_vm(&self.name)?.ok_or_else(|| {
            smolvm::Error::config("update", format!("machine '{}' not found", self.name))
        })?;

        // Must be stopped (same check as resize)
        let state = record.actual_state();
        match state {
            RecordState::Stopped | RecordState::Created => {}
            _ => {
                return Err(smolvm::Error::InvalidState {
                    expected: "stopped".into(),
                    actual: format!("{:?}", state),
                });
            }
        }

        // Validate proposed resource values using the same logic as machine start.
        // Construct a temporary VmResources with the new values (falling back to
        // the record's current values) and run validate() — single source of truth.
        let proposed = smolvm::agent::VmResources {
            cpus: self.cpus.unwrap_or(record.cpus),
            memory_mib: self.mem.unwrap_or(record.mem),
            ..record.vm_resources()
        };
        proposed.validate()?;

        // Validate env specs have KEY=VALUE format with non-empty key
        for spec in &self.env {
            match spec.split_once('=') {
                Some((key, _)) if !key.is_empty() => {}
                _ => {
                    return Err(smolvm::Error::config(
                        "update",
                        format!("invalid env format '{}': expected KEY=VALUE", spec),
                    ));
                }
            }
        }

        // Parse and validate new mounts (after state check so
        // "machine is running" takes priority over "directory not found")
        let new_mounts = HostMount::parse(&self.volume)?;

        // Validate no duplicate host ports after proposed changes
        {
            let mut final_ports: Vec<PortMapping> = record
                .ports
                .iter()
                .filter(|&&(h, g)| {
                    !self
                        .remove_port
                        .iter()
                        .any(|rm| rm.host == h && rm.guest == g)
                })
                .map(|&(h, g)| PortMapping::new(h, g))
                .collect();
            for p in &self.port {
                if !final_ports
                    .iter()
                    .any(|existing| existing.host == p.host && existing.guest == p.guest)
                {
                    final_ports.push(*p);
                }
            }
            PortMapping::check_duplicates(&final_ports)
                .map_err(|e| smolvm::Error::config("update", e))?;
        }

        // Expand physical disk files before the DB write. If expansion fails,
        // no DB changes are made — the record stays consistent.
        let mut changes: Vec<String> = Vec::new();
        if self.storage.is_some() || self.overlay.is_some() {
            let disk_changes =
                vm_common::expand_disks(&self.name, &record, self.storage, self.overlay)?;
            changes.extend(disk_changes);
        }

        // Single DB transaction: all settings + disk sizes together.
        db.update_vm(&self.name, |r| {
            // Disk sizes (must match the physical expansion above)
            if let Some(s) = self.storage {
                r.storage_gb = Some(s);
            }
            if let Some(o) = self.overlay {
                r.overlay_gb = Some(o);
            }
            // Volumes: add new, remove specified.
            // Canonicalize the remove spec's source path so ./src matches
            // the stored /absolute/path/to/src.
            for rm in &self.remove_volume {
                let canonical_rm = if let Some((rm_src, rm_tgt)) = rm.split_once(':') {
                    let resolved = std::fs::canonicalize(rm_src)
                        .unwrap_or_else(|_| std::path::PathBuf::from(rm_src));
                    format!("{}:{}", resolved.display(), rm_tgt)
                } else {
                    rm.clone()
                };
                let before = r.mounts.len();
                r.mounts.retain(|(src, tgt, _)| {
                    let spec = format!("{}:{}", src, tgt);
                    spec != canonical_rm && spec != *rm
                });
                if r.mounts.len() < before {
                    changes.push(format!("  removed volume: {}", rm));
                }
            }
            for m in &new_mounts {
                let tuple = m.to_storage_tuple();
                if !r
                    .mounts
                    .iter()
                    .any(|(s, t, _)| *s == tuple.0 && *t == tuple.1)
                {
                    changes.push(format!(
                        "  added volume: {}:{}{}",
                        tuple.0,
                        tuple.1,
                        if tuple.2 { ":ro" } else { "" }
                    ));
                    r.mounts.push(tuple);
                }
            }

            // Ports: add new, remove specified
            for rm in &self.remove_port {
                let before = r.ports.len();
                r.ports.retain(|&(h, g)| h != rm.host || g != rm.guest);
                if r.ports.len() < before {
                    changes.push(format!("  removed port: {}:{}", rm.host, rm.guest));
                }
            }
            for p in &self.port {
                let tuple = p.to_tuple();
                if !r.ports.contains(&tuple) {
                    changes.push(format!("  added port: {}:{}", tuple.0, tuple.1));
                    r.ports.push(tuple);
                }
            }

            // Resources
            if let Some(cpus) = self.cpus {
                changes.push(format!("  cpus: {} → {}", r.cpus, cpus));
                r.cpus = cpus;
            }
            if let Some(mem) = self.mem {
                changes.push(format!("  memory: {} MiB → {} MiB", r.mem, mem));
                r.mem = mem;
            }

            // Network
            if self.net {
                changes.push("  network: enabled".to_string());
                r.network = true;
            }
            if self.no_net {
                changes.push("  network: disabled".to_string());
                r.network = false;
                // Clear egress policy — allow_cidrs and dns_filter_hosts imply
                // networking. Leaving them set would re-enable egress on start.
                if r.allowed_cidrs.is_some() {
                    changes.push("  cleared allow_cidrs".to_string());
                    r.allowed_cidrs = None;
                }
                if r.dns_filter_hosts.is_some() {
                    changes.push("  cleared dns_filter_hosts".to_string());
                    r.dns_filter_hosts = None;
                }
            }

            // Env vars
            for rm_key in &self.remove_env {
                let before = r.env.len();
                r.env.retain(|(k, _)| k != rm_key);
                if r.env.len() < before {
                    changes.push(format!("  removed env: {}", rm_key));
                }
            }
            for spec in &self.env {
                if let Some((key, val)) = spec.split_once('=') {
                    r.env.retain(|(k, _)| k != key);
                    r.env.push((key.to_string(), val.to_string()));
                    changes.push(format!("  env: {}={}", key, val));
                }
            }

            // Workdir
            if let Some(ref wd) = self.workdir {
                changes.push(format!("  workdir: {}", wd));
                r.workdir = Some(wd.clone());
            }

            // GPU
            if self.gpu {
                changes.push("  gpu: enabled".to_string());
                r.gpu = Some(true);
            }
            if self.no_gpu {
                changes.push("  gpu: disabled".to_string());
                r.gpu = Some(false);
            }
        })?;

        if changes.is_empty() {
            println!("No changes specified.");
        } else {
            println!("Updated machine '{}':", self.name);
            for change in &changes {
                println!("{}", change);
            }
            println!("\nStart with: smolvm machine start --name {}", self.name);
        }

        Ok(())
    }
}

// ============================================================================
// Data Dir Command
// ============================================================================

/// Print the on-disk data directory for a named machine.
///
/// Equivalent to calling `smolvm::agent::vm_data_dir(name)` — exposed as a
/// CLI command so shell scripts and external tooling have a single source
/// of truth for the path computation (which is hash-derived, not
/// name-derived).
#[derive(Args, Debug)]
pub struct DataDirCmd {
    /// Machine name.
    #[arg(short = 'n', long, value_name = "NAME")]
    pub name: String,
}

impl DataDirCmd {
    pub fn run(self) -> smolvm::Result<()> {
        // Error (exit 1) for a machine that does not exist, rather than
        // printing a computed path for a name that was never created —
        // consistent with `status`/`start`/`delete`.
        let config = smolvm::config::SmolvmConfig::load()?;
        if config.get_vm(&self.name).is_none() {
            return Err(smolvm::Error::vm_not_found(&self.name));
        }
        let dir = smolvm::agent::vm_data_dir(&self.name);
        println!("{}", dir.display());
        Ok(())
    }
}

// ============================================================================
// Network Test Command
// ============================================================================

/// Test network connectivity directly from machine (debug TSI).
#[derive(Args, Debug)]
pub struct NetworkTestCmd {
    /// Named machine to test (omit for default)
    #[arg(long)]
    pub name: Option<String>,

    /// URL to test
    #[arg(default_value = "http://1.1.1.1")]
    pub url: String,
}

impl NetworkTestCmd {
    pub fn run(self) -> smolvm::Result<()> {
        let manager = vm_common::get_vm_manager(&self.name)?;
        let label = vm_common::vm_label(&self.name);

        // Ensure machine is running
        let already_running = manager.try_connect_existing().is_some();
        if !already_running {
            eprintln!("Starting machine '{}'...", label);
            manager.ensure_running()?;
        }

        // Connect and test
        println!("Testing network from machine: {}", self.url);
        let mut client = manager.connect()?;
        let result = client.network_test(&self.url)?;

        println!(
            "Result: {}",
            serde_json::to_string_pretty(&result).unwrap_or_default()
        );

        // VM was already running — don't stop it when we're done
        if already_running {
            manager.detach();
        }
        Ok(())
    }
}

// ============================================================================
// Images Command
// ============================================================================

/// List cached images and storage usage.
///
/// Shows all OCI images cached in the machine's storage, along with their
/// sizes and layer counts. Also displays total storage usage.
///
/// Examples:
///   smolvm machine images --name myvm
///   smolvm machine images --name myvm --json
#[derive(Args, Debug)]
pub struct ImagesCmd {
    /// Machine to query
    #[arg(long, required = true, value_name = "NAME")]
    pub name: String,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

impl ImagesCmd {
    pub fn run(self) -> smolvm::Result<()> {
        // Validate VM exists before creating storage (for_vm creates dirs).
        let db = smolvm::db::SmolvmDb::open()?;
        let record = db.get_vm(&self.name)?.ok_or_else(|| {
            smolvm::Error::config("images", format!("machine '{}' not found", self.name))
        })?;

        let manager =
            AgentManager::for_vm_with_sizes(&self.name, record.storage_gb, record.overlay_gb)?;

        let started_for_query = if manager.try_connect_existing().is_some() {
            manager.detach();
            false
        } else {
            eprintln!("Starting machine '{}' to query storage...", self.name);
            manager.start()?;
            true
        };
        let mut client = AgentClient::connect_with_retry(manager.vsock_socket())?;

        let status = client.storage_status()?;
        let images = client.list_images()?;

        if self.json {
            let output = serde_json::json!({
                "storage": {
                    "total_bytes": status.total_bytes,
                    "used_bytes": status.used_bytes,
                    "layer_count": status.layer_count,
                    "image_count": status.image_count,
                },
                "images": images,
            });
            let json = serde_json::to_string_pretty(&output)
                .map_err(|e| smolvm::Error::config("serialize json", e.to_string()))?;
            println!("{}", json);
        } else {
            println!("Storage Usage:");
            println!("  Total:  {}", format_bytes(status.total_bytes));
            println!("  Used:   {}", format_bytes(status.used_bytes));
            println!("  Layers: {}", status.layer_count);
            println!();

            if images.is_empty() {
                println!("No cached images.");
            } else {
                println!("Cached Images:");
                println!("{:<40} {:>10} {:>8}", "IMAGE", "SIZE", "LAYERS");
                println!("{}", "-".repeat(60));

                for image in &images {
                    let name = if image.reference.len() > 38 {
                        format!("{}...", &image.reference[..35])
                    } else {
                        image.reference.clone()
                    };
                    println!(
                        "{:<40} {:>10} {:>8}",
                        name,
                        format_bytes(image.size),
                        image.layer_count
                    );
                }

                println!();
                println!("Total: {} images", images.len());
            }
        }

        if started_for_query {
            let _ = manager.stop();
        }

        Ok(())
    }
}

// ============================================================================
// Prune Command
// ============================================================================

/// Remove unused images and layers to free disk space.
///
/// This removes layers that are not referenced by any cached image manifest.
/// Use --dry-run to see what would be removed without actually deleting.
///
/// Examples:
///   smolvm machine prune --name myvm --dry-run
///   smolvm machine prune --name myvm
///   smolvm machine prune --name myvm --all
#[derive(Args, Debug)]
pub struct PruneCmd {
    /// Machine to prune
    #[arg(long, required = true, value_name = "NAME")]
    pub name: String,

    /// Show what would be removed without actually removing
    #[arg(long)]
    pub dry_run: bool,

    /// Remove all cached images (not just unreferenced layers)
    #[arg(long)]
    pub all: bool,
}

impl PruneCmd {
    pub fn run(self) -> smolvm::Result<()> {
        // Validate VM exists before creating storage (for_vm creates dirs).
        let db = smolvm::db::SmolvmDb::open()?;
        let record = db.get_vm(&self.name)?.ok_or_else(|| {
            smolvm::Error::config("prune", format!("machine '{}' not found", self.name))
        })?;

        let manager =
            AgentManager::for_vm_with_sizes(&self.name, record.storage_gb, record.overlay_gb)?;

        // Regular prune (unreferenced layers only) is safe on a running VM —
        // referenced layers can't be collected. --all deletes manifests for
        // layers that may be in active use, so it requires a stop first.
        let already_running = manager.try_connect_existing().is_some();
        let started_for_prune;

        if already_running && self.all {
            manager.detach();
            return Err(smolvm::Error::agent(
                "prune",
                format!("cannot prune --all while machine '{}' is running. Stop it first with: smolvm machine stop --name {}", self.name, self.name),
            ));
        } else if already_running {
            started_for_prune = false;
            manager.detach();
        } else {
            eprintln!("Starting machine...");
            manager.start()?;
            started_for_prune = true;
        }

        let mut client = AgentClient::connect_with_retry(manager.vsock_socket())?;

        if self.all {
            let images = client.list_images()?;

            if images.is_empty() {
                println!("No cached images to remove.");
            } else if record.image.is_some() {
                // An image-backed machine needs its cached image to restart, so
                // purging it would brick a *stopped* machine ("image not found"
                // on the next start). Keep the cache and reclaim only
                // unreferenced layers; to reclaim everything, delete the machine.
                let total_size: u64 = images.iter().map(|i| i.size).sum();
                if self.dry_run {
                    let would_free = client.garbage_collect(true, false)?;
                    println!(
                        "Machine '{}' is image-backed: would keep {} cached image(s) ({}) it needs to restart, and free {} of unreferenced layers.",
                        self.name,
                        images.len(),
                        format_bytes(total_size),
                        format_bytes(would_free)
                    );
                } else {
                    let freed = client.garbage_collect(false, false)?;
                    println!(
                        "Kept {} cached image(s) in use by machine '{}'; freed {} of unreferenced layers.",
                        images.len(),
                        self.name,
                        format_bytes(freed)
                    );
                    eprintln!(
                        "(--all keeps images a machine needs to restart; to reclaim everything: smolvm machine delete --name {})",
                        self.name
                    );
                }
            } else {
                // Bare VM: nothing depends on the image cache, so purge all.
                let total_size: u64 = images.iter().map(|i| i.size).sum();
                if self.dry_run {
                    println!(
                        "Would remove {} images ({})",
                        images.len(),
                        format_bytes(total_size)
                    );
                    for image in &images {
                        println!(
                            "  - {} ({}, {} layers)",
                            image.reference,
                            format_bytes(image.size),
                            image.layer_count
                        );
                    }
                } else {
                    println!("Removing all cached images...");
                    let freed = client.garbage_collect(false, true)?;
                    println!(
                        "Removed {} images, freed {}",
                        images.len(),
                        format_bytes(freed)
                    );
                }
            }
        } else if self.dry_run {
            println!("Scanning for unreferenced layers...");
            let would_free = client.garbage_collect(true, false)?;

            if would_free > 0 {
                println!(
                    "Would free {} of unreferenced layers",
                    format_bytes(would_free)
                );
            } else {
                println!("No unreferenced layers to remove.");
            }
        } else {
            println!("Removing unreferenced layers...");
            let freed = client.garbage_collect(false, false)?;

            if freed > 0 {
                println!("Freed {}", format_bytes(freed));
            } else {
                println!("No unreferenced layers to remove.");
            }
        }

        // Only stop the VM if we started it for this prune operation.
        // If the user's machine was already running, leave it running.
        if started_for_prune {
            let _ = manager.stop();
        }

        Ok(())
    }
}

// ============================================================================
// Cp (File Copy) Command
// ============================================================================

/// Copy files between host and a running machine.
///
/// Uses `machine:path` syntax to specify the remote side.
///
/// Examples:
///   smolvm machine cp ./script.py myvm:/workspace/script.py    # upload
///   smolvm machine cp myvm:/workspace/output.json ./output.json # download
#[derive(Args, Debug)]
pub struct CpCmd {
    /// Source path (local file or machine:path)
    #[arg(value_name = "SRC")]
    pub src: String,

    /// Destination path (local file or machine:path)
    #[arg(value_name = "DST")]
    pub dst: String,
}

impl CpCmd {
    pub fn run(self) -> smolvm::Result<()> {
        // Parse src/dst to determine direction
        let (machine_name, guest_path, local_path, is_upload) =
            if let Some((name, path)) = self.src.split_once(':') {
                // Download: machine:path -> local
                (name.to_string(), path.to_string(), self.dst.clone(), false)
            } else if let Some((name, path)) = self.dst.split_once(':') {
                // Upload: local -> machine:path
                (name.to_string(), path.to_string(), self.src.clone(), true)
            } else {
                return Err(smolvm::Error::config(
                    "cp",
                    "one of SRC or DST must use machine:path syntax (e.g., myvm:/workspace/file)",
                ));
            };

        let (manager, mut client) =
            vm_common::ensure_running_and_connect(&Some(machine_name.clone()))?;
        // Detach so the VM keeps running after cp exits.
        manager.detach();

        // For image-based VMs, ensure the persistent container overlay is
        // mounted so cp targets the container filesystem (not the VM rootfs).
        // prepare_overlay is idempotent: reuses if mounted, remounts if upper
        // exists, creates fresh otherwise.
        if let Some(image) = smolvm::db::SmolvmDb::open()
            .ok()
            .and_then(|db| db.get_vm(&machine_name).ok().flatten())
            .and_then(|r| r.image.clone())
        {
            let overlay_id = format!("persistent-{}", machine_name);
            client.prepare_overlay(&image, &overlay_id)?;
        }

        if is_upload {
            // Stream from file — only one chunk (~1 MiB) in memory at a time.
            let file = std::fs::File::open(&local_path).map_err(|e| {
                smolvm::Error::agent("read local file", format!("{}: {}", local_path, e))
            })?;
            let size = file.metadata().map(|m| m.len()).map_err(|e| {
                smolvm::Error::agent("stat local file", format!("{}: {}", local_path, e))
            })?;
            let mut bar = crate::cli::ProgressBar::new(
                format!("Uploading {} -> {}", local_path, guest_path),
                Some(size),
            );
            client.write_file_from_reader_with_progress(&guest_path, file, size, None, |sent| {
                bar.update(sent)
            })?;
            bar.finish(size);
        } else {
            // Stream to file — only one chunk (~16 MiB) in memory at a time.
            let mut bar = crate::cli::ProgressBar::new(
                format!("Downloading {} -> {}", guest_path, local_path),
                None,
            );
            let local = std::path::Path::new(&local_path);
            let size =
                client.read_file_to_path(&guest_path, local, |received| bar.update(received))?;
            bar.finish(size);
        }

        Ok(())
    }
}

// ============================================================================
// Monitor Command
// ============================================================================

/// Monitor a running machine with health checks and restart policy.
///
/// Runs in the foreground, watching the machine and restarting on crash
/// or health check failure. Uses the restart policy from the machine's
/// config (set via Smolfile [restart] or --restart flag on create).
///
/// Ctrl+C stops monitoring; the machine keeps running.
///
/// Examples:
///   smolvm machine monitor --name myvm
///   smolvm machine monitor --name myvm --health-cmd "curl -f http://localhost:8080/health"
///   smolvm machine monitor --name myvm --restart always --interval 10
#[derive(Args, Debug)]
pub struct MonitorCmd {
    /// Machine to monitor (default: "default")
    #[arg(short = 'n', long, value_name = "NAME")]
    pub name: Option<String>,

    /// Override restart policy (never, always, on-failure, unless-stopped)
    #[arg(long, value_name = "POLICY")]
    pub restart: Option<String>,

    /// Health check command (run inside the VM via sh -c)
    #[arg(long, value_name = "CMD")]
    pub health_cmd: Option<String>,

    /// Health check timeout in seconds
    #[arg(long, default_value = "5", value_name = "SECS")]
    pub health_timeout: u64,

    /// Check interval in seconds
    #[arg(long, default_value = "5", value_name = "SECS")]
    pub interval: u64,

    /// Health check failures before triggering restart
    #[arg(long, default_value = "3", value_name = "N")]
    pub health_retries: u32,
}

impl MonitorCmd {
    pub fn run(self) -> smolvm::Result<()> {
        use smolvm::config::{RecordState, RestartPolicy};
        use smolvm::db::SmolvmDb;
        use smolvm::Error;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let name = self.name.unwrap_or_else(|| "default".to_string());

        // Load machine config from DB
        let db = SmolvmDb::open()?;
        let record = db
            .get_vm(&name)?
            .ok_or_else(|| Error::vm_not_found(&name))?;

        // Build restart config: CLI override > VmRecord config
        let mut restart = record.restart.clone();
        if let Some(ref policy_str) = self.restart {
            restart.policy = policy_str
                .parse::<RestartPolicy>()
                .map_err(|e| Error::config("--restart", e))?;
        }

        // Resolve health check: CLI override > VmRecord config
        let health_cmd = self
            .health_cmd
            .clone()
            .map(|c| vec!["sh".into(), "-c".into(), c])
            .or_else(|| record.health_cmd.clone());
        let health_timeout =
            Duration::from_secs(record.health_timeout_secs.unwrap_or(self.health_timeout));
        let health_retries = record.health_retries.unwrap_or(self.health_retries);
        let interval = Duration::from_secs(record.health_interval_secs.unwrap_or(self.interval));
        let startup_grace = record
            .health_startup_grace_secs
            .map(Duration::from_secs)
            .unwrap_or(Duration::ZERO);

        drop(db);

        // Ensure machine is running
        let manager = AgentManager::for_vm(&name)
            .map_err(|e| Error::agent("create agent manager", e.to_string()))?;

        if !manager.is_process_alive() {
            println!("Machine '{}' is not running, starting...", name);
            vm_common::start_vm_named(&name, None, None, /* from_snapshot */ false)?;
        }

        println!(
            "Monitoring machine '{}' (policy: {}, interval: {}s)",
            name,
            restart.policy,
            interval.as_secs()
        );
        if health_cmd.is_some() {
            println!(
                "  Health check: retries={}, timeout={}s",
                health_retries,
                health_timeout.as_secs()
            );
        }

        // Ctrl+C handler via SIGINT
        //
        // SAFETY: `stop` is an Arc<AtomicBool> that lives until the end of this
        // function. The cloned Arc below keeps a strong reference alive for the
        // duration of the monitor loop, so the raw pointer stored in STOP_FLAG
        // remains valid until after we break out of the loop and the function
        // returns. The handler only does an atomic store, which is async-signal-safe.
        let stop = Arc::new(AtomicBool::new(false));
        {
            let stop = stop.clone();
            unsafe {
                let _ = libc::signal(libc::SIGINT, {
                    static mut STOP_FLAG: *const AtomicBool = std::ptr::null();
                    STOP_FLAG = Arc::as_ptr(&stop);
                    extern "C" fn handler(_: libc::c_int) {
                        unsafe {
                            if !STOP_FLAG.is_null() {
                                (*STOP_FLAG).store(true, Ordering::SeqCst);
                            }
                        }
                    }
                    handler as *const () as libc::sighandler_t
                });
            }
        }

        let mut consecutive_health_failures: u32 = 0;
        let mut last_check = std::time::Instant::now();
        let mut last_start = std::time::Instant::now(); // tracks startup grace period

        loop {
            std::thread::sleep(interval);

            if stop.load(Ordering::SeqCst) {
                break;
            }

            // Detect sleep/wake: if the elapsed wall time is much longer than
            // the expected interval, the machine was likely suspended (laptop lid
            // closed). Reset health failures and skip this cycle to give the VM
            // time to recover network connections.
            let elapsed = last_check.elapsed();
            last_check = std::time::Instant::now();
            if elapsed > interval * 3 {
                let sleep_secs = elapsed.as_secs() - interval.as_secs();
                println!(
                    "  detected suspend (~{}s) — skipping health check for recovery",
                    sleep_secs
                );
                consecutive_health_failures = 0;
                continue;
            }

            // Refresh manager to pick up PID changes after restart
            let manager = match AgentManager::for_vm(&name) {
                Ok(m) => m,
                Err(_) => continue,
            };

            if manager.is_process_alive() {
                // Skip health checks during startup grace period
                if !startup_grace.is_zero() && last_start.elapsed() < startup_grace {
                    continue;
                }

                // Machine is alive — run health check if configured
                if let Some(ref cmd) = health_cmd {
                    match AgentClient::connect_with_short_timeout(manager.vsock_socket()) {
                        Ok(mut client) => {
                            match client.vm_exec(
                                cmd.clone(),
                                vec![],
                                None,
                                Some(health_timeout),
                                None,
                            ) {
                                Ok((0, _, _)) => {
                                    if consecutive_health_failures > 0 {
                                        println!("  health check passed (recovered)");
                                    }
                                    consecutive_health_failures = 0;
                                }
                                Ok((code, _, stderr)) => {
                                    consecutive_health_failures += 1;
                                    println!(
                                        "  health check failed (exit {}, {}/{}): {}",
                                        code,
                                        consecutive_health_failures,
                                        health_retries,
                                        String::from_utf8_lossy(&stderr).trim()
                                    );
                                }
                                Err(e) => {
                                    consecutive_health_failures += 1;
                                    println!(
                                        "  health check error ({}/{}): {}",
                                        consecutive_health_failures, health_retries, e
                                    );
                                }
                            }

                            if consecutive_health_failures >= health_retries {
                                println!("  unhealthy — stopping machine for restart");
                                let _ = vm_common::stop_vm_named(&name);
                                continue;
                            }
                        }
                        Err(_) => {
                            consecutive_health_failures += 1;
                            println!(
                                "  cannot connect to agent ({}/{})",
                                consecutive_health_failures, health_retries
                            );
                        }
                    }
                }
            } else {
                // Machine is dead
                consecutive_health_failures = 0;

                let exit_code = manager.child_pid().and_then(smolvm::process::try_wait);

                println!(
                    "  machine exited (exit code: {})",
                    exit_code
                        .map(|c| c.to_string())
                        .unwrap_or_else(|| "unknown".into())
                );

                // Update DB state
                if let Ok(db) = SmolvmDb::open() {
                    let _ = db.update_vm(&name, |r| {
                        r.state = RecordState::Stopped;
                        r.pid = None;
                        r.last_exit_code = exit_code;
                    });
                }

                if restart.should_restart(exit_code) {
                    let backoff = restart.backoff_duration();
                    restart.restart_count += 1;

                    println!(
                        "  restarting (attempt {}, backoff {}s)...",
                        restart.restart_count,
                        backoff.as_secs()
                    );

                    if let Ok(db) = SmolvmDb::open() {
                        let _ = db.update_vm(&name, |r| {
                            r.restart.restart_count = restart.restart_count;
                        });
                    }

                    std::thread::sleep(backoff);

                    if stop.load(Ordering::SeqCst) {
                        break;
                    }

                    match vm_common::start_vm_named(
                        &name, None, None, /* from_snapshot */ false,
                    ) {
                        Ok(()) => {
                            println!("  machine restarted");
                            last_start = std::time::Instant::now();
                        }
                        Err(e) => println!("  restart failed: {}", e),
                    }
                } else {
                    println!(
                        "  not restarting (policy: {}, count: {}/{})",
                        restart.policy,
                        restart.restart_count,
                        if restart.max_retries > 0 {
                            restart.max_retries.to_string()
                        } else {
                            "unlimited".into()
                        }
                    );
                    break;
                }
            }
        }

        // Mark user stopped
        if let Ok(db) = SmolvmDb::open() {
            let _ = db.update_vm(&name, |r| {
                r.restart.user_stopped = true;
            });
        }

        println!(
            "\nStopped monitoring. Machine '{}' may still be running.",
            name
        );
        Ok(())
    }
}
