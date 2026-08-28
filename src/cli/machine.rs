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
use sha2::{Digest, Sha256};
use smolvm::agent::{docker_config_mount, AgentClient, AgentManager, RunConfig, VmResources};
use smolvm::data::network::{PortMapping, PortMappingSpec, MAX_PORT_MAPPINGS};
use smolvm::data::resources::{DEFAULT_MICROVM_CPU_COUNT, DEFAULT_MICROVM_MEMORY_MIB};
use smolvm::data::storage::HostMount;
use smolvm::network::{validate_requested_network_backend, NetworkBackend};
use smolvm::{DEFAULT_IDLE_CMD, DEFAULT_SHELL_CMD};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// How many orphaned ephemeral VMs `machine run` reaps per boot. Small so the
/// hot path never stalls on a large backlog; a heavier backlog drains over
/// successive runs (and other commands sweep without a cap).
const EPHEMERAL_RUN_SWEEP_CAP: usize = 8;

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

/// `machine create`'s own long options that appear in a workload command, i.e.
/// after the `--` separator, where they are arguments for the guest process
/// rather than machine options.
///
/// Short flags are deliberately ignored: `-v`, `-e` and `-p` are far too common
/// in ordinary commands to name without drowning the real signal. The long
/// options come from clap itself, so a newly added flag is covered without
/// touching this list.
fn create_flags_in_workload(command: &[String]) -> Vec<String> {
    use clap::Args as _;
    let spec = CreateCmd::augment_args(clap::Command::new("create"));
    let longs: std::collections::HashSet<String> = spec
        .get_arguments()
        .filter_map(|arg| arg.get_long().map(|long| format!("--{long}")))
        .collect();
    let mut found: Vec<String> = Vec::new();
    for word in command {
        if longs.contains(word.as_str()) && !found.contains(word) {
            found.push(word.clone());
        }
    }
    found
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

fn smolmachine_egress_fields(
    manifest_network: bool,
    allow_cidrs: Vec<String>,
    cli_network: bool,
    dns_filter_hosts: Option<Vec<String>>,
) -> (bool, Option<Vec<String>>, Option<Vec<String>>) {
    let allowed_cidrs = if allow_cidrs.is_empty() {
        None
    } else {
        Some(allow_cidrs)
    };
    (
        manifest_network || cli_network,
        allowed_cidrs,
        dns_filter_hosts,
    )
}

/// Parse `--secret-env KEY=HOST_VAR` and `--secret-file KEY=PATH` flag values
/// into validated [`SecretRef`]s keyed by the guest-side env var name.
///
/// CLI-supplied refs are `TrustedLocal` (the host user invoked the command), so
/// both source kinds are allowed; `validate_ref` still enforces structure and
/// absolute `from_file` paths. A key that appears more than once — across or
/// within the two flags — is a hard error, since silently keeping the last
/// occurrence would mask a typo.
/// Parse `--expose-socket`/`--mount-socket` specs into published-socket configs.
///
/// - `--expose-socket GUEST_PATH[:HOST_PATH]`: expose a guest-listening socket to
///   the host. `HOST_PATH` optional (defaults to `<vm-dir>/<basename>`).
/// - `--mount-socket HOST_PATH:GUEST_PATH`: mount a host socket into the guest.
fn parse_published_sockets(
    expose: &[String],
    mount: &[String],
) -> smolvm::Result<Vec<smolvm::config::PublishedSocketConfig>> {
    use smolvm::config::{PublishedSocketConfig, SocketDirection};

    let mut out = Vec::new();
    for spec in expose {
        let (guest_path, host_path) = match spec.split_once(':') {
            Some((g, h)) => (g.to_string(), Some(h.to_string())),
            None => (spec.clone(), None),
        };
        if guest_path.is_empty() {
            return Err(smolvm::Error::config(
                "expose-socket",
                format!("empty guest path in '{spec}'"),
            ));
        }
        out.push(PublishedSocketConfig {
            direction: SocketDirection::Expose,
            guest_path,
            host_path: host_path.filter(|h| !h.is_empty()),
        });
    }
    for spec in mount {
        let (host_path, guest_path) = spec.split_once(':').ok_or_else(|| {
            smolvm::Error::config(
                "mount-socket",
                format!("expected HOST_PATH:GUEST_PATH, got '{spec}'"),
            )
        })?;
        if host_path.is_empty() || guest_path.is_empty() {
            return Err(smolvm::Error::config(
                "mount-socket",
                format!("both HOST_PATH and GUEST_PATH are required in '{spec}'"),
            ));
        }
        out.push(PublishedSocketConfig {
            direction: SocketDirection::Mount,
            guest_path: guest_path.to_string(),
            host_path: Some(host_path.to_string()),
        });
    }
    if out.len() > smolvm_protocol::ports::PUBLISH_SOCKET_MAX {
        return Err(smolvm::Error::config(
            "publish-socket",
            format!(
                "too many published sockets ({}); max is {}",
                out.len(),
                smolvm_protocol::ports::PUBLISH_SOCKET_MAX
            ),
        ));
    }
    // The guest env encoding uses ';' and '|' as separators; reject paths that
    // would corrupt it.
    for s in &out {
        if s.guest_path.contains(';') || s.guest_path.contains('|') {
            return Err(smolvm::Error::config(
                "publish-socket",
                format!(
                    "guest path '{}' contains an unsupported character (';' or '|')",
                    s.guest_path
                ),
            ));
        }
        // The guest resolves this path in its own namespace (and bind-mounts a
        // mounted socket there), so a relative path would silently land next to
        // whatever the resolving process happens to be rooted at.
        if !s.guest_path.starts_with('/') {
            return Err(smolvm::Error::config(
                "publish-socket",
                format!("guest path '{}' must be absolute", s.guest_path),
            ));
        }
    }
    // Two mount bridges at the same guest path silently shadow each other in
    // the guest, the later bind mount wins, leaving the first bridge's host
    // socket unreachable. Reject the config instead of paying out a dead
    // bridge. (Expose entries only *dial* their guest path, so duplicates
    // there are harmless.)
    let mut mounted_paths = std::collections::HashSet::new();
    for s in &out {
        if s.direction == smolvm::config::SocketDirection::Mount
            && !mounted_paths.insert(&s.guest_path)
        {
            return Err(smolvm::Error::config(
                "mount-socket",
                format!("guest path '{}' is mounted more than once", s.guest_path),
            ));
        }
    }
    Ok(out)
}

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
fn try_spawn_detached_cleanup(vm_name: &str, pid: i32, start_time: Option<u64>) -> bool {
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
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("_cleanup-ephemeral")
        .arg(vm_name)
        .arg(pid.to_string())
        .arg(start_time_val.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // New process group so the helper is immune to SIGHUP when the parent
    // terminal closes (pgid = child pid). POSIX-only; no Windows equivalent.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let result = cmd.spawn();
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

    /// Save a running machine, including RAM, as a portable checkpoint
    Checkpoint(super::pack::CheckpointCmd),

    /// Assign parameters and release one held fork-pool slot
    ForkRelease(ForkReleaseCmd),

    /// Stop a running machine
    Stop(StopCmd),

    /// Delete a machine configuration
    #[command(visible_alias = "rm")]
    Delete(DeleteCmd),

    /// Show machine status
    Status(StatusCmd),

    /// Show egress denials — outbound connections the machine's egress policy refused
    EgressEvents(EgressEventsCmd),

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
        // Reclaim orphaned ephemeral VMs before doing work. `machine run` uses a
        // BOUNDED sweep: a workflow that only ever calls `machine run` would
        // otherwise never reclaim a data dir left by a run whose detached cleanup
        // helper didn't finish (Ctrl-C / SIGKILL / host sleep mid-run). The cap
        // keeps the boot hot path from stalling on a large backlog — it drains
        // over successive runs. Other commands sweep everything.
        if matches!(self, MachineCmd::Run(_)) {
            super::vm_common::cleanup_orphaned_ephemeral_vms_bounded(EPHEMERAL_RUN_SWEEP_CAP);
        } else {
            super::vm_common::cleanup_orphaned_ephemeral_vms();
        }

        match self {
            MachineCmd::Run(cmd) => cmd.run(),
            MachineCmd::Exec(cmd) => cmd.run(),
            MachineCmd::Create(cmd) => cmd.run(),
            MachineCmd::Start(cmd) => cmd.run(),
            MachineCmd::Fork(cmd) => cmd.run(),
            MachineCmd::Checkpoint(cmd) => cmd.run(),
            MachineCmd::ForkRelease(cmd) => cmd.run(),
            MachineCmd::Stop(cmd) => cmd.run(),
            MachineCmd::Delete(cmd) => cmd.run(),
            MachineCmd::Status(cmd) => cmd.run(),
            MachineCmd::EgressEvents(cmd) => cmd.run(),
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
    /// Container image: a registry reference (alpine, ubuntu:22.04,
    /// ghcr.io/org/image), a `docker save` archive (./myapp.tar, or `-` to read
    /// one from stdin), or an unpacked rootfs directory (./rootfs/). A bare name
    /// is always a registry reference — pipe `docker save` to use a locally
    /// built image. Optional when a Smolfile provides the image, or for bare VM mode.
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

    /// Expose port from container to host (single port or one-to-one range, repeatable)
    #[arg(short = 'p', long = "port", value_parser = PortMappingSpec::parse, value_name = "PORT[-END]|HOST[-END]:GUEST[-END]", help_heading = "Network")]
    pub port: Vec<PortMappingSpec>,

    /// Enable outbound network access
    #[arg(long, help_heading = "Network")]
    pub net: bool,

    /// Select the networking backend.
    #[arg(long = "net-backend", value_enum, help_heading = "Network")]
    pub net_backend: Option<NetworkBackend>,

    /// Custom DNS resolver for the guest (implies --net). Use this when the
    /// default public resolvers (8.8.8.8/1.1.1.1) are blocked on your network.
    #[arg(long, value_name = "IP", help_heading = "Network")]
    pub dns: Option<std::net::Ipv4Addr>,

    /// Join a named inter-VM network (implies --net, virtio-net only): members
    /// get distinct addresses and can reach each other directly
    #[arg(long = "network", value_name = "NAME", help_heading = "Network")]
    pub network_name: Option<String>,

    /// Allow egress to specific CIDR range (can be used multiple times, implies --net)
    #[arg(long = "allow-cidr", value_parser = parse_cidr, value_name = "CIDR", help_heading = "Network")]
    pub allow_cidr: Vec<String>,

    /// Allow egress to specific hostname, resolved at VM start (can be used multiple times, implies --net)
    #[arg(long = "allow-host", value_name = "HOSTNAME", help_heading = "Network")]
    pub allow_host: Vec<String>,

    /// Restrict outbound to localhost only (implies --net)
    #[arg(long, help_heading = "Network")]
    pub outbound_localhost_only: bool,

    /// Let the guest reach services on the HOST's own loopback (127.0.0.1 / ::1);
    /// off by default so a sandbox can't reach host debuggers, Docker, or local
    /// databases. Cloud-metadata stays blocked. Implies --net.
    #[arg(long = "allow-host-loopback", help_heading = "Network")]
    pub allow_host_loopback: bool,

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

    /// Enable Rosetta 2 for x86_64 binary translation on Apple Silicon
    #[arg(long, help_heading = "Resources")]
    pub rosetta: bool,

    /// Number of virtual CPUs
    #[arg(long, default_value_t = DEFAULT_MICROVM_CPU_COUNT, value_name = "N", help_heading = "Resources")]
    pub cpus: u8,

    /// Memory allocation in MiB
    #[arg(long, default_value_t = DEFAULT_MICROVM_MEMORY_MIB, value_name = "MiB", help_heading = "Resources")]
    pub mem: u32,

    /// Writable data disk size in GiB (default 20). Bounds how much a workload
    /// can write: a disk-heavy or untrusted command fills this disk (ENOSPC),
    /// never the host. This is the flag to lower when sandboxing untrusted code.
    #[arg(long, value_name = "GiB", help_heading = "Resources")]
    pub storage: Option<u64>,

    /// Container rootfs overlay (copy-on-write upper layer) size in GiB. NOT the
    /// writable-data cap — use --storage to bound how much a workload can write.
    /// Rarely needs setting.
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

    /// Remote guest CUDA Driver-API calls to the host NVIDIA GPU over vsock
    #[arg(long, help_heading = "Hardware")]
    pub cuda: bool,

    /// Ask compatible CUDA frameworks to graph safe compiled regions.
    /// Implies --cuda; arbitrary eager CUDA calls are not captured.
    #[arg(long, help_heading = "Hardware")]
    pub auto_graph: bool,

    /// Expose the guest's Docker daemon socket to the host as a Unix socket
    /// (DOCKER_HOST=unix://…). Requires dockerd running in the VM.
    #[arg(long, help_heading = "Network")]
    pub docker_socket: bool,

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

    /// Skip the init-layer cache: re-run `init` on every ephemeral run instead of
    /// baking `image + init` once into a cached, reusable artifact. Use this when
    /// `init` depends on live volume contents (and so cannot be safely cached).
    #[arg(long, help_heading = "Resources")]
    pub no_init_cache: bool,

    /// Rebuild the cached init layer even if a matching one already exists.
    #[arg(long, help_heading = "Resources")]
    pub rebuild_init_cache: bool,

    /// Cache the pulled OCI image on the host so repeat ephemeral runs of the same
    /// `--image` skip the registry pull. The image is baked once into a reusable
    /// `.smolmachine` (keyed by image + env) and every later run rehydrates from it
    /// instead of re-pulling inside the guest. The VM stays throwaway; only the
    /// image is cached. Registry images only.
    #[arg(long, help_heading = "Resources")]
    pub oci_cache: bool,

    /// Run the workload as an unprivileged container: restricted capabilities,
    /// read-only cgroup, and no extra tmpfs. By default the workload is "VM-grade"
    /// (the microVM is the isolation boundary, so it gets full privileges and any
    /// image — incl. systemd — boots). Use this for defense-in-depth with untrusted
    /// code. `init` always runs VM-grade (it needs privileges for apt/mounts).
    #[arg(long, help_heading = "Security")]
    pub unprivileged: bool,

    #[command(flatten, next_help_heading = "Network")]
    pub proxy_opts: crate::cli::proxy_opts::ProxyOpts,
}

/// Cache directory for baked init layers: a sibling of the per-VM cache
/// (`<cache>/smolvm/init-layers`), derived from the same canonical root as
/// [`smolvm::agent::vm_cache_root`] so it shares the install's cache location.
fn init_layer_cache_dir() -> PathBuf {
    smolvm::agent::vm_cache_root()
        .parent()
        .map(|smolvm_root| smolvm_root.join("init-layers"))
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp/smolvm-init-layers"))
}

/// Max real bytes the init-layer cache may occupy before eviction; override via
/// `SMOLVM_INIT_CACHE_MAX_BYTES`. Default 10 GiB (~tens of layers).
fn init_cache_max_bytes() -> u64 {
    const DEFAULT: u64 = 10 * 1024 * 1024 * 1024;
    std::env::var("SMOLVM_INIT_CACHE_MAX_BYTES")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT)
}

/// Bump a cache entry's modification time to now so the LRU prune treats it as
/// recently used. Best-effort and cross-platform (`File::set_modified`); a
/// failure just leaves the old mtime, which at worst evicts a hot entry sooner.
fn touch_cache_entry(path: &Path) {
    if let Ok(f) = std::fs::OpenOptions::new().write(true).open(path) {
        let _ = f.set_modified(std::time::SystemTime::now());
    }
}

/// Evict least-recently-modified cached layers until the cache is at or below
/// `max_bytes`, never evicting `keep` (the layer just published). Best-effort:
/// per-entry errors are skipped. The `.smolmachine` sidecars are zstd-compressed
/// (dense) files, so apparent length is an accurate size.
fn prune_init_cache(dir: &Path, max_bytes: u64, keep: &Path) {
    let mut layers: Vec<(PathBuf, std::time::SystemTime, u64)> = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        if path.extension().and_then(|x| x.to_str()) != Some("smolmachine") {
            continue;
        }
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        let mtime = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        layers.push((path, mtime, meta.len()));
    }
    let total: u64 = layers.iter().map(|(_, _, s)| *s).sum();
    if total <= max_bytes {
        return;
    }
    layers.sort_by_key(|(_, mtime, _)| *mtime); // oldest first
    let mut over = total - max_bytes;
    for (path, _, size) in layers {
        if over == 0 {
            break;
        }
        if path == keep {
            continue;
        }
        if std::fs::remove_file(&path).is_ok() {
            over = over.saturating_sub(size);
        }
    }
}

/// Best-effort sweep of leftover `init-bake-*` temp machines from crashed bakes.
/// Age is taken from the DB record's `created_at` (always present — unlike the data
/// dir, which a create-then-crash leaves absent) and gated on a generous threshold
/// so an in-flight concurrent bake — which finishes in seconds — is never touched.
/// Override the threshold (seconds) with `SMOLVM_INIT_BAKE_GC_SECS`.
fn gc_stale_bake_machines(exe: &Path) {
    let stale_after = std::env::var("SMOLVM_INIT_BAKE_GC_SECS")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(30 * 60);
    let Ok(cfg) = smolvm::config::SmolvmConfig::load() else {
        return;
    };
    let now = smolvm::util::current_timestamp();
    let stale: Vec<String> = cfg
        .list_vms()
        .filter(|(name, _)| name.starts_with("init-bake-"))
        .filter(|(_, record)| now.saturating_sub(record.created_at) >= stale_after)
        .map(|(name, _)| name.clone())
        .collect();
    for name in stale {
        let _ = run_smolvm(exe, &["machine", "delete", "--name", &name, "-f"]);
    }
}

/// Content key for an init layer: a hash of the image + init commands + env, so the
/// cache rebuilds exactly when those inputs change.
///
/// When `digest` is supplied (the `--oci-cache` path resolves it at the auth
/// gate) it is mixed in, so the key pins the image's CONTENT rather than its
/// reference string. Without it, `alpine:latest` would hash the same forever and
/// a cached entry would keep serving the image as it was on the first run — the
/// tag moving upstream (including for a security fix) would never be picked up.
///
/// PROTOTYPE LIMITATION: if `init` runs a script that lives on a mounted volume
/// (e.g. `bash /project/init.sh`), the script's CONTENTS are not part of the key —
/// inline the init steps into the Smolfile, or pass `--no-init-cache`.
fn init_layer_key(
    image: Option<&str>,
    init: &[String],
    env: &[String],
    digest: Option<&str>,
) -> String {
    let mut h = Sha256::new();
    h.update(image.unwrap_or("").as_bytes());
    h.update([0u8]);
    if let Some(d) = digest {
        h.update(d.as_bytes());
    }
    h.update([0u8]);
    for c in init {
        h.update(c.as_bytes());
        h.update([0u8]);
    }
    h.update([0u8]);
    for e in env {
        h.update(e.as_bytes());
        h.update([0u8]);
    }
    hex::encode(h.finalize())[..16].to_string()
}

/// Whether a `--image` value is an init-cache-bakeable source. Only registry
/// refs are: the bake snapshots via `pack create --from-vm`, which sources base
/// layers by pulling the image's registry manifest. A local archive or rootfs
/// dir has no registry manifest (it is flattened on boot), so it takes the
/// direct, uncached init path instead of a broken bake (#459).
fn image_bakeable(image: Option<&str>) -> bool {
    matches!(
        image.map(smolvm::data::image_source::classify),
        Some(smolvm::data::image_source::ImageSource::Registry(_))
    )
}

/// Build the bake's `machine start` argv, forwarding the run's `--proxy` /
/// `--no-proxy` so the one-time init pull reaches the registry through the same
/// proxy the outer run uses. Without this, a Smolfile with `init` steps pulls
/// direct in the bake and times out on a proxy-only network.
fn bake_start_args<'a>(
    tmp: &'a str,
    proxy: Option<&'a str>,
    no_proxy: Option<&'a str>,
) -> Vec<&'a str> {
    let mut start = vec!["machine", "start", "--name", tmp];
    if let Some(p) = proxy {
        start.push("--proxy");
        start.push(p);
    }
    if let Some(n) = no_proxy {
        start.push("--no-proxy");
        start.push(n);
    }
    start
}

/// Bake `image + init` into a cached `.smolmachine` (or reuse an existing one) and
/// return its path. Runs the well-tested `machine create/start/stop` + `pack create
/// --from-vm` flow as subprocesses of this same binary: create a temp machine from
/// the Smolfile with the workload replaced by a `/bin/true` no-op so only `init`
/// runs, snapshot it, and delete the temp machine. The real workload command is
/// supplied at run time against the resulting artifact.
fn ensure_init_layer(
    params: &vm_common::CreateVmParams,
    smolfile: Option<&Path>,
    rebuild: bool,
    digest: Option<&str>,
    proxy: Option<&str>,
    no_proxy: Option<&str>,
) -> smolvm::Result<PathBuf> {
    // The bake here only ever receives a registry image: `ensure_init_layer` is
    // gated on `image_bakeable()` (local archives/dirs take the direct path),
    // because the `pack create --from-vm` snapshot below cannot source a local
    // image's layers (they're flattened, with no registry manifest to pull).
    let key = init_layer_key(params.image.as_deref(), &params.init, &params.env, digest);
    let dir = init_layer_cache_dir();
    std::fs::create_dir_all(&dir)
        .map_err(|e| smolvm::Error::config("init-layer cache", e.to_string()))?;
    let cached = dir.join(format!("{key}.smolmachine"));
    if cached.exists() && !rebuild {
        if params.init.is_empty() {
            println!("Using cached image {key} (host cache hit; no pull)");
        } else {
            println!("Using cached init layer {key}");
        }
        // Mark the entry recently used (bump mtime) so the LRU sweep keeps hot
        // images and evicts cold ones — without this a frequently-run cached image
        // could be evicted just for having an old bake time. Then bound the cache
        // on the hit path too, not only after a bake. Both best-effort.
        touch_cache_entry(&cached);
        prune_init_cache(&dir, init_cache_max_bytes(), &cached);
        return Ok(cached);
    }

    // The Smolfile is the source of init commands, so it's required only when there
    // ARE init steps. A bare `--oci-cache` image (no init) bakes from `--image`
    // alone and needs no Smolfile.
    if !params.init.is_empty() && smolfile.is_none() {
        return Err(smolvm::Error::config(
            "init-layer cache",
            "init caching requires a --smolfile (the init source); pass --no-init-cache otherwise",
        ));
    }
    if params.init.is_empty() {
        println!("Caching image {key} (one-time; reused on later runs)");
    } else {
        println!(
            "Baking init layer (one-time; reused on later runs) [{key}, {} init step(s)]",
            params.init.len()
        );
    }
    let started = std::time::Instant::now();

    let exe = std::env::current_exe()
        .map_err(|e| smolvm::Error::config("init-layer cache", e.to_string()))?;
    // Reap any temp machines orphaned by previously crashed bakes (age-gated so it
    // never touches a concurrent in-flight bake).
    gc_stale_bake_machines(&exe);
    let pid = std::process::id();
    let tmp = format!("init-bake-{key}-{pid}");

    // Bake into a per-process staging dir, then atomically rename the sidecar into
    // its final cache path. This makes an interrupted bake leave nothing usable (no
    // truncated `.smolmachine` a later run would treat as valid), and makes two
    // concurrent bakes of the same key safe — each stages independently and the last
    // rename wins. The staging dir also absorbs `pack`'s stub binary, discarded when
    // the dir is removed (the cache only needs the sidecar).
    let staging = dir.join(format!(".staging-{key}-{pid}"));
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging)
        .map_err(|e| smolvm::Error::config("init-layer cache", e.to_string()))?;
    let staged_out = staging.join("layer").to_string_lossy().to_string();
    let staged_sidecar = staging.join("layer.smolmachine");

    // Clear any temp machine left by a prior failed bake (best-effort; the common
    // case is "doesn't exist", whose error is captured and discarded by run_smolvm).
    let _ = run_smolvm(&exe, &["machine", "delete", "--name", &tmp, "-f"]);

    let bake = (|| -> smolvm::Result<()> {
        // Create from the Smolfile (init + volumes) but replace the workload with
        // `/bin/true` so `start` runs init only. Forward the RESOLVED image and env
        // (CLI overrides included) so the baked rootfs matches the cache key, which
        // is derived from those same resolved params.
        let mut create: Vec<String> = ["machine", "create", "--name", &tmp]
            .iter()
            .map(|s| s.to_string())
            .collect();
        if let Some(sf) = smolfile {
            create.push("--smolfile".into());
            create.push(sf.to_string_lossy().to_string());
        }
        if let Some(image) = &params.image {
            create.push("--image".into());
            create.push(image.clone());
        }
        for e in &params.env {
            create.push("-e".into());
            create.push(e.clone());
        }
        // Forward the run's network config so the bake's one-time in-guest pull can
        // reach the registry. The cached artifact carries the layers, so later runs
        // from it need no network to source the image.
        if params.net {
            create.push("--net".into());
        }
        if let Some(dns) = params.dns {
            create.push("--dns".into());
            create.push(dns.to_string());
        }
        for c in params.allowed_cidrs.iter().flatten() {
            create.push("--allow-cidr".into());
            create.push(c.clone());
        }
        for h in params.dns_filter_hosts.iter().flatten() {
            create.push("--allow-host".into());
            create.push(h.clone());
        }
        create.push("--".into());
        create.push("/bin/true".into());
        let create: Vec<&str> = create.iter().map(String::as_str).collect();

        println!("  · pulling image and running init...");
        run_smolvm(&exe, &create)?;
        // The image pull happens at `start`; forward the run's proxy so the
        // bake reaches the registry through a corporate/loopback proxy too —
        // otherwise a Smolfile with `init` steps pulls direct and times out
        // even when the outer run was given --proxy.
        let start = bake_start_args(&tmp, proxy, no_proxy);
        run_smolvm(&exe, &start)?;
        run_smolvm(&exe, &["machine", "stop", "--name", &tmp])?;
        println!("  · snapshotting...");
        run_smolvm(
            &exe,
            &["pack", "create", "--from-vm", &tmp, "-o", &staged_out],
        )?;
        if !staged_sidecar.exists() {
            return Err(smolvm::Error::config(
                "init-layer cache",
                format!("bake did not produce {}", staged_sidecar.display()),
            ));
        }
        Ok(())
    })();
    let _ = run_smolvm(&exe, &["machine", "delete", "--name", &tmp, "-f"]);

    // Publish atomically only on success; always clear staging (drops the stub + any
    // partial output) so a failed bake leaves the existing cache untouched.
    let publish = bake.and_then(|_| {
        std::fs::rename(&staged_sidecar, &cached).map_err(|e| {
            smolvm::Error::config("init-layer cache", format!("publish cached layer: {e}"))
        })
    });
    let _ = std::fs::remove_dir_all(&staging);
    publish?;

    // Bound the cache: evict oldest layers if we're over the cap (keeping the one
    // just baked). Best-effort — failure to prune never fails the run.
    prune_init_cache(&dir, init_cache_max_bytes(), &cached);

    println!("  ✓ baked in {}s", started.elapsed().as_secs());
    Ok(cached)
}

/// Run this same smolvm binary as a subprocess for one bake step. Output is
/// CAPTURED (not inherited) so the bake's internal create/pull/pack chatter — and
/// the harmless "vm not found" from the best-effort pre-clean — never reach the
/// user's terminal; on failure the captured stderr tail is surfaced in the error.
fn run_smolvm(exe: &Path, args: &[&str]) -> smolvm::Result<()> {
    let out = std::process::Command::new(exe)
        .args(args)
        .output()
        .map_err(|e| smolvm::Error::config("init-layer bake", e.to_string()))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let tail = stderr
            .lines()
            .filter(|l| !l.trim().is_empty())
            .rev()
            .take(12)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("\n");
        return Err(smolvm::Error::config(
            "init-layer bake",
            format!(
                "`smolvm {}` failed ({}):\n{tail}",
                args.join(" "),
                out.status
            ),
        ));
    }
    Ok(())
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
            let port = PortMappingSpec::expand_all(&self.port)
                .map_err(|e| smolvm::Error::config("machine run ports", e))?;
            let mut env = self.env;
            if self.auto_graph {
                smolvm::util::enable_cuda_auto_graph_env_specs(&mut env);
            }
            return crate::cli::pack_run::PackRunCmd {
                sidecar: Some(from),
                command: self.command,
                interactive: self.interactive,
                tty: self.tty,
                timeout: self.timeout,
                workdir: self.workdir,
                env,
                volume: self.volume,
                port: port.into_iter().map(PortMappingSpec::from).collect(),
                net: self.net,
                net_backend: self.net_backend,
                cpus: (self.cpus != DEFAULT_MICROVM_CPU_COUNT).then_some(self.cpus),
                mem: (self.mem != DEFAULT_MICROVM_MEMORY_MIB).then_some(self.mem),
                storage: self.storage,
                overlay: self.overlay,
                force_extract: false,
                info: false,
                debug: false,
                cuda: self.cuda,
                auto_graph: self.auto_graph,
                // `--from` rejects the egress flags at parse time
                // (`conflicts_with_all`), so there is no policy to carry.
                egress: None,
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

        // `--allow-host-loopback` relaxes only the host-loopback part of the egress
        // floor via libkrun's `SMOLVM_ALLOW_HOST_LOOPBACK` env (read once at launch),
        // rather than adding loopback to the allow-list — an allow-list would make
        // egress restrictive and force the guest onto virtio-net, where a guest's
        // 127.0.0.1 never reaches the host. Setting the env keeps the default TSI
        // datapath and leaves cloud-metadata blocked.
        if self.allow_host_loopback {
            std::env::set_var("SMOLVM_ALLOW_HOST_LOOPBACK", "1");
        }
        let (cli_allow_cidrs, net, cli_dns_filter_hosts) = resolve_egress_flags(
            self.allow_cidr,
            self.allow_host,
            self.outbound_localhost_only,
            self.net || self.allow_host_loopback,
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
            self.dns,
            self.network_name.clone(),
            vec![],
            self.env,
            self.workdir,
            self.smolfile.clone(),
            self.storage,
            self.overlay,
            cli_allow_cidrs,
            // Ephemeral runs are not addressable later, so they carry no labels;
            // `machine create` is the path an orchestrator labels.
            Default::default(),
        )?;

        let mut params = params;
        if self.auto_graph {
            smolvm::util::enable_cuda_auto_graph_env_specs(&mut params.env);
            params.cuda = true;
        }
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

        // A registry --image can name a smolmachine PACK artifact (e.g.
        // registry.smolmachines.com/library/alpine), whose single "layer" is a
        // full .smolmachine sidecar — not an OCI filesystem layer. The in-guest
        // OCI puller would tar-unpack its multi-GiB storage.ext4 into the guest
        // disk, so probe the manifest on the host and reroute through the
        // proven pack-run path (same as `--from`); a failed probe falls back to
        // the normal in-guest pull.
        if let Some(img) = params.image.clone() {
            if let Some(sidecar) = smolvm::data::pack_ref::resolve_pack_ref_blocking(&img)? {
                if self.detach {
                    // pack-run is ephemeral-only; a persistent machine from a
                    // pack ref goes through create (which reroutes the same way).
                    return Err(Error::config(
                        "machine run",
                        format!(
                            "'{img}' is a smolmachine pack artifact and cannot run detached \
                             via --image. Create a persistent machine instead:\n  \
                             smolvm machine create --image {img} && smolvm machine start"
                        ),
                    ));
                }
                let command = if !self.command.is_empty() {
                    self.command.clone()
                } else {
                    let mut c = params.entrypoint.clone();
                    c.extend(params.cmd.clone());
                    c
                };
                return crate::cli::pack_run::PackRunCmd {
                    sidecar: Some(sidecar),
                    command,
                    interactive: self.interactive,
                    tty: self.tty,
                    timeout: self.timeout,
                    workdir: params.workdir.clone(),
                    env: params.env.clone(),
                    volume: params.volume.clone(),
                    port: params
                        .port
                        .iter()
                        .copied()
                        .map(PortMappingSpec::from)
                        .collect(),
                    net: params.net,
                    net_backend: params.network_backend,
                    cpus: (params.cpus != DEFAULT_MICROVM_CPU_COUNT).then_some(params.cpus),
                    mem: (params.mem != DEFAULT_MICROVM_MEMORY_MIB).then_some(params.mem),
                    storage: params.storage_gb,
                    overlay: params.overlay_gb,
                    force_extract: false,
                    info: false,
                    debug: false,
                    cuda: self.cuda || params.cuda,
                    auto_graph: self.auto_graph,
                    // A user-supplied artifact's manifest keeps deciding the
                    // network default (no override), but any allow-list / DNS
                    // filter from the flags or Smolfile must still be enforced.
                    egress: Some(crate::cli::pack_run::ResolvedEgressPolicy {
                        network_override: None,
                        allowed_cidrs: params.allowed_cidrs.clone(),
                        dns_filter_hosts: params.dns_filter_hosts.clone(),
                    }),
                }
                .run();
            }
        }

        // Init-layer cache (prototype): for an ephemeral run of an IMAGE with `init`
        // commands, bake `image + init` once into a cached `.smolmachine` and run from
        // that artifact, so init's cost (e.g. `apt install`) is paid once and reused
        // on every later run instead of re-running on each ephemeral boot. Skipped for
        // detached/persistent runs (`-d`) and when `--no-init-cache` is set.
        //
        // Only REGISTRY images are baked. A local image (`--image -` / `--image
        // file.tar` / a rootfs dir) is flattened with no registry manifest, so the
        // bake's `pack create --from-vm` snapshot can't source its layers; and a
        // `--image -` archive can't be re-read by the bake's child subprocess
        // (null stdin) anyway. Local images take the direct path below, which
        // stages the archive once in this process and runs init inline (#459).
        // The cache normally applies to runs with `init` steps (bake `image + init`
        // once). `--oci-cache` extends it to a bare `--image` run with no init, so
        // the OCI image itself is cached on the host and repeat ephemeral runs skip
        // the pull — the same bake path, just with an empty init layer.
        if !self.no_init_cache
            && !self.detach
            && image_bakeable(params.image.as_deref())
            && (!params.init.is_empty() || self.oci_cache)
        {
            // `--oci-cache` needs an explicit workload for the same reason the
            // non-cached path does: with no command the baked artifact's own
            // entrypoint is a `/bin/true` no-op, so the run would exit 0 having
            // done nothing. Fail with the same guidance instead of pretending.
            if self.oci_cache
                && self.command.is_empty()
                && !self.interactive
                && self.smolfile.is_none()
                && params.entrypoint.is_empty()
                && params.cmd.is_empty()
            {
                return Err(Error::config(
                    "machine run",
                    "--oci-cache needs a command to run: pass one after `--`, use -it for a \
                     shell, or supply a Smolfile with an entrypoint/cmd"
                        .to_string(),
                ));
            }
            // Auth gate: resolve + authorize the image on the HOST before baking
            // or serving a cached bake. A private image the caller cannot pull is
            // rejected here — the same registry-authorization gate the cloud path
            // uses, so caching never bypasses pull authorization. `FromConfig`
            // reads the local docker-config credentials (so `docker login`ed
            // private images resolve); anonymous is the fallback for public ones.
            //
            // The resolved digest also becomes part of the cache key, so the entry
            // tracks the image's CONTENT: when a mutable tag moves upstream the key
            // changes and the new content is baked, instead of serving the first
            // run's image forever.
            let mut resolved_digest = None;
            if self.oci_cache {
                if let Some(image) = params.image.as_deref() {
                    let auth = smolvm::registry::PullAuth::FromConfig;
                    let rt = tokio::runtime::Runtime::new()
                        .map_err(|e| Error::config("oci-cache", e.to_string()))?;
                    resolved_digest =
                        Some(rt.block_on(smolvm::image_store::authorized_digest(image, &auth))?);
                }
            }
            let cached = ensure_init_layer(
                &params,
                self.smolfile.as_deref(),
                self.rebuild_init_cache,
                resolved_digest.as_deref(),
                self.proxy_opts.resolved_proxy()?.as_deref(),
                self.proxy_opts.no_proxy().as_deref(),
            )?;
            // The real workload: CLI trailing args win, else the Smolfile's
            // entrypoint+cmd (the baked artifact's own command is a `/bin/true` no-op).
            let command = if !self.command.is_empty() {
                self.command.clone()
            } else {
                let mut c = params.entrypoint.clone();
                c.extend(params.cmd.clone());
                c
            };
            return crate::cli::pack_run::PackRunCmd {
                sidecar: Some(cached),
                command,
                interactive: self.interactive,
                tty: self.tty,
                timeout: self.timeout,
                workdir: params.workdir.clone(),
                env: params.env.clone(),
                volume: params.volume.clone(),
                port: params
                    .port
                    .iter()
                    .copied()
                    .map(PortMappingSpec::from)
                    .collect(),
                net: params.net,
                net_backend: params.network_backend,
                cpus: (params.cpus != DEFAULT_MICROVM_CPU_COUNT).then_some(params.cpus),
                mem: (params.mem != DEFAULT_MICROVM_MEMORY_MIB).then_some(params.mem),
                storage: params.storage_gb,
                overlay: params.overlay_gb,
                force_extract: false,
                info: false,
                debug: false,
                cuda: self.cuda || params.cuda,
                auto_graph: self.auto_graph,
                // The workload's network policy, resolved above from the flags
                // and Smolfile. The override is absolute: the baked artifact's
                // manifest records the BAKE VM's networking (enabled, for the
                // pull), so without it a cache hit would run the workload with
                // unrestricted egress no matter what the caller asked for.
                egress: Some(crate::cli::pack_run::ResolvedEgressPolicy {
                    network_override: Some(params.net),
                    allowed_cidrs: params.allowed_cidrs.clone(),
                    dns_filter_hosts: params.dns_filter_hosts.clone(),
                }),
            }
            .run();
        }

        // Remote volumes are mounted inside the guest by the agent, so peel them
        // off before the host-directory parse, which would reject an `s3://`
        // source as a missing directory.
        let (host_volume_specs, remote_volumes) =
            smolvm::remote_volume::split_specs(&params.volume)?;
        let mut mounts = HostMount::parse(&host_volume_specs)?;
        if !remote_volumes.is_empty() && !params.net {
            return Err(Error::config(
                "machine run",
                "remote volumes need network access to reach the bucket: add --net",
            ));
        }
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
            dns: params.dns,
            network_name: params.network_name.clone(),
            // CLI --gpu wins; Smolfile gpu = true also enables it.
            gpu: self.gpu || params.gpu,
            gpu_vram_mib: self.gpu_vram_mib.or(params.gpu_vram_mib),
            cuda: self.cuda || params.cuda,
            rosetta: self.rosetta || params.rosetta,
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

        let mut features = smolvm::agent::LaunchFeatures {
            ssh_agent_socket,
            cuda: self.cuda || params.cuda,
            expose_docker: self.docker_socket || params.docker_socket,
            dns_filter_hosts: params.dns_filter_hosts.clone(),
            // A foreground ephemeral VM exists only to serve this command, so bind
            // its lifetime to this process. Without the watchdog the VM survives a
            // SIGKILL of the CLI — which is how orchestrators (and CI) enforce
            // timeouts — and then holds its full RAM until some later `machine run`
            // happens to sweep it (see the bounded reclaim in `MachineCmd::run`).
            // That sweep stays as the backstop for cases the watchdog can't cover,
            // such as a host that sleeps mid-run.
            //
            // `--detach` deliberately leaves the VM up for later `machine exec`, so
            // it must opt out: arming this there would kill the VM the moment the
            // launching CLI returned.
            watch_parent: Some(!self.detach),
            packed_layers_dir,
            extra_disks: std::env::var("SMOLVM_EXTRA_DISK")
                .ok()
                .into_iter()
                .flat_map(|spec| {
                    spec.split(',')
                        .filter(|s| !s.is_empty())
                        .map(|entry| {
                            let (path, ro) = match entry.strip_suffix(":ro") {
                                Some(p) => (p, true),
                                None => (entry, false),
                            };
                            (
                                std::path::PathBuf::from(path),
                                ro,
                                smolvm::data::disk::DiskFormat::Raw,
                            )
                        })
                        .collect::<Vec<_>>()
                })
                .collect(),
            ..Default::default()
        };

        // This launch pulls a registry image in-guest, subject to the egress
        // filter — fold its registry into the enforced policy so a hostname
        // scope doesn't block its own pull.
        features.allow_image_pull_egress(image.as_deref(), uses_packed_layers);

        let freshly_started = manager
            .ensure_running_with_full_config(mounts.clone(), ports, resources, features)
            .map_err(|e| Error::agent("start machine", e.to_string()))?;

        // Tell the user how to reach the guest's Docker daemon from the host.
        // libkrun exposes the bridge as a Unix socket in the VM data dir; a
        // host docker client uses it via DOCKER_HOST. dockerd must be running
        // inside the VM (start it once the machine is up).
        if self.docker_socket || params.docker_socket {
            let sock = smolvm::agent::vm_data_dir(&vm_name).join("docker.sock");
            eprintln!(
                "Docker socket exposed — once dockerd is running in the VM, reach it with:\n  \
                 DOCKER_HOST=unix://{} docker ps",
                sock.display()
            );
        }

        // Register the ephemeral VM for tracking (machine list, orphan cleanup),
        // keyed by the VM's OWN name. The orphan sweep only has the DB record and
        // locates the disks via `vm_data_dir(record.name)`, so the record name
        // MUST be the VM name — a separate generated name would hash to a
        // different, nonexistent dir and the sweep would delete the record but
        // leak the real (multi-GB) data dir.
        //
        // Detached runs are tracked via persist_named_running instead — skip
        // ephemeral registration so the detach path does not leave an
        // unreachable orphan record after persist_named_running succeeds.
        if !self.detach {
            vm_common::register_ephemeral_vm(
                &vm_name,
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
        // When Rosetta is enabled, default the image pull to linux/amd64 so there
        // is an x86_64 binary to translate; an explicit --oci-platform still wins.
        // Without this, a multi-arch image resolves to the guest-native arm64
        // variant and Rosetta has nothing to do.
        let rosetta_requested = self.rosetta || params.rosetta;
        let effective_platform: Option<String> = self
            .oci_platform
            .clone()
            .or_else(|| rosetta_requested.then(|| "linux/amd64".to_string()));

        // Pull only registry images; a local source's layers are already
        // mounted via virtiofs and the guest assembles its rootfs from them.
        let image_info = if uses_packed_layers {
            None
        } else if let Some(ref img) = image {
            match crate::cli::pull_with_progress(
                &mut client,
                img,
                effective_platform.as_deref(),
                self.proxy_opts.resolved_proxy()?.as_deref(),
                self.proxy_opts.no_proxy().as_deref(),
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
                vm_common::deregister_ephemeral_vm(&vm_name);
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
            // Credentials and endpoint come from the workload's own env, the
            // same place every AWS SDK reads them, so a remote volume needs no
            // configuration beyond the `-v` spec and the usual variables.
            let s3_volumes = smolvm::remote_volume::to_s3_volumes(&remote_volumes, &defaults.env);
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
                        .with_persistent_overlay(Some(vm_name.clone()))
                        .with_unprivileged(self.unprivileged)
                        .with_s3_volumes(s3_volumes.clone());
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
                                dns: params.dns,
                                network_name: params.network_name.clone(),
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
                                cuda: self.cuda || params.cuda,
                                docker_socket: self.docker_socket || params.docker_socket,
                                dns_filter_hosts: params.dns_filter_hosts.clone(),
                                gpu: self.gpu || params.gpu,
                                gpu_vram_mib: self.gpu_vram_mib.or(params.gpu_vram_mib),
                                rosetta: self.rosetta || params.rosetta,
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

                // Use the machine's persistent overlay so the foreground workload
                // sees init's filesystem changes (init ran with the same overlay id).
                // Without this the workload runs in a fresh overlay and init appears
                // to "do nothing" (e.g. `apt install`ed binaries are missing).
                let exit_code = if interactive || tty {
                    let config = RunConfig::new(img, command)
                        .with_env(defaults.env.clone())
                        .with_workdir(defaults.workdir.clone())
                        .with_user(defaults.user.clone())
                        .with_mounts(mount_bindings)
                        .with_timeout(self.timeout)
                        .with_tty(tty)
                        .with_persistent_overlay(Some(vm_name.clone()))
                        .with_unprivileged(self.unprivileged)
                        .with_s3_volumes(s3_volumes.clone());
                    client.run_interactive(config)?
                } else {
                    let config = RunConfig::new(img, command)
                        .with_env(defaults.env)
                        .with_workdir(defaults.workdir)
                        .with_user(defaults.user)
                        .with_mounts(mount_bindings)
                        .with_timeout(self.timeout)
                        .with_persistent_overlay(Some(vm_name.clone()))
                        .with_unprivileged(self.unprivileged)
                        .with_s3_volumes(s3_volumes.clone());
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
                if pid > 0 && try_spawn_detached_cleanup(&vm_name, pid, start_time) {
                    std::process::exit(exit_code);
                }
                // Fallback: synchronous cleanup (helper spawn failed).
                vm_common::deregister_ephemeral_vm(&vm_name);
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
                            dns: params.dns,
                            network_name: params.network_name.clone(),
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
                            cuda: self.cuda || params.cuda,
                            docker_socket: self.docker_socket || params.docker_socket,
                            dns_filter_hosts: params.dns_filter_hosts.clone(),
                            gpu: self.gpu || params.gpu,
                            gpu_vram_mib: self.gpu_vram_mib.or(params.gpu_vram_mib),
                            rosetta: false,
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
                if pid > 0 && try_spawn_detached_cleanup(&vm_name, pid, start_time) {
                    std::process::exit(exit_code);
                }
                // Fallback: synchronous cleanup (helper spawn failed).
                vm_common::deregister_ephemeral_vm(&vm_name);
                manager.kill();
                manager.cleanup_data_dir();
                std::process::exit(exit_code);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn bake_start_forwards_proxy_when_set() {
        // No proxy: plain start.
        assert_eq!(
            super::bake_start_args("t", None, None),
            ["machine", "start", "--name", "t"]
        );
        // Proxy only.
        assert_eq!(
            super::bake_start_args("t", Some("http://host.smolvm.internal:8118"), None),
            [
                "machine",
                "start",
                "--name",
                "t",
                "--proxy",
                "http://host.smolvm.internal:8118"
            ]
        );
        // Proxy + no_proxy.
        assert_eq!(
            super::bake_start_args("t", Some("http://p:3128"), Some("localhost,.internal")),
            [
                "machine",
                "start",
                "--name",
                "t",
                "--proxy",
                "http://p:3128",
                "--no-proxy",
                "localhost,.internal"
            ]
        );
    }

    #[test]
    fn cp_mode_parses_common_octal_forms_and_rejects_garbage() {
        assert_eq!(super::parse_octal_mode("644").unwrap(), 0o644);
        assert_eq!(super::parse_octal_mode("0755").unwrap(), 0o755);
        assert_eq!(super::parse_octal_mode("0o600").unwrap(), 0o600);
        assert!(super::parse_octal_mode("8x").is_err());
        assert!(super::parse_octal_mode("77777").is_err());
    }

    use super::*;
    use clap::Parser;

    #[test]
    fn cli_overlay_owner_uses_the_golden_for_fork_clones() {
        let ordinary =
            smolvm::config::VmRecord::new("ordinary".into(), 1, 512, Vec::new(), Vec::new(), false);
        assert_eq!(
            persistent_overlay_owner_for_record("ordinary", Some(&ordinary)),
            "ordinary"
        );

        let mut clone =
            smolvm::config::VmRecord::new("clone-a".into(), 1, 512, Vec::new(), Vec::new(), false);
        clone.golden = Some("golden-a".into());
        assert_eq!(
            persistent_overlay_owner_for_record("clone-a", Some(&clone)),
            "golden-a"
        );
    }

    /// `--oci-cache` resolves the image digest at the auth gate and mixes it into
    /// the key, so the cache tracks CONTENT. Without this a mutable tag like
    /// `alpine:latest` hashes identically forever and the first run's image keeps
    /// being served — upstream updates (security fixes included) never land.
    #[test]
    fn init_layer_key_pins_the_resolved_digest() {
        let init: Vec<String> = vec![];
        let env: Vec<String> = vec![];
        let untagged = init_layer_key(Some("alpine:latest"), &init, &env, None);
        let first = init_layer_key(Some("alpine:latest"), &init, &env, Some("sha256:aaa"));
        let moved = init_layer_key(Some("alpine:latest"), &init, &env, Some("sha256:bbb"));

        assert_ne!(
            first, moved,
            "the same tag at a NEW digest must be a new cache entry"
        );
        assert_eq!(
            first,
            init_layer_key(Some("alpine:latest"), &init, &env, Some("sha256:aaa")),
            "the same tag at the same digest still hits"
        );
        assert_ne!(
            untagged, first,
            "supplying a digest changes the key (no collision with the un-pinned path)"
        );
    }

    #[test]
    fn init_layer_key_is_stable_and_input_sensitive() {
        let init = vec!["apt-get install -y jq".to_string()];
        let env = vec!["FOO=bar".to_string()];
        let base = init_layer_key(Some("ubuntu:noble"), &init, &env, None);
        // Deterministic for identical inputs.
        assert_eq!(
            base,
            init_layer_key(Some("ubuntu:noble"), &init, &env, None)
        );
        assert_eq!(base.len(), 16);
        // Sensitive to each input: image, init, env.
        assert_ne!(
            base,
            init_layer_key(Some("ubuntu:jammy"), &init, &env, None)
        );
        assert_ne!(
            base,
            init_layer_key(Some("ubuntu:noble"), &["other".to_string()], &env, None)
        );
        assert_ne!(
            base,
            init_layer_key(Some("ubuntu:noble"), &init, &["FOO=baz".to_string()], None)
        );
        // Order of init steps matters (different layer).
        let init_rev = vec!["b".to_string(), "a".to_string()];
        let init_fwd = vec!["a".to_string(), "b".to_string()];
        assert_ne!(
            init_layer_key(Some("x"), &init_fwd, &[], None),
            init_layer_key(Some("x"), &init_rev, &[], None)
        );
    }

    #[test]
    fn parse_published_sockets_both_directions() {
        use smolvm::config::SocketDirection;
        let out = parse_published_sockets(
            &[
                "/var/run/app.sock".to_string(),
                "/run/svc.sock:/tmp/pinned.sock".to_string(),
            ],
            &["/run/host.sock:/run/guest.sock".to_string()],
        )
        .unwrap();
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].direction, SocketDirection::Expose);
        assert_eq!(out[0].guest_path, "/var/run/app.sock");
        assert_eq!(out[0].host_path, None);
        assert_eq!(out[1].host_path.as_deref(), Some("/tmp/pinned.sock"));
        assert_eq!(out[2].direction, SocketDirection::Mount);
        assert_eq!(out[2].guest_path, "/run/guest.sock");
        assert_eq!(out[2].host_path.as_deref(), Some("/run/host.sock"));
    }

    #[test]
    fn smolmachine_egress_fields_preserve_resolved_cli_policy() {
        let cidrs = vec!["192.0.2.10/32".to_string()];
        let hosts = Some(vec!["provider.test".to_string()]);
        assert_eq!(
            smolmachine_egress_fields(false, cidrs.clone(), true, hosts.clone()),
            (true, Some(cidrs), hosts)
        );
    }

    #[test]
    fn smolmachine_egress_fields_preserve_manifest_network_default() {
        assert_eq!(
            smolmachine_egress_fields(true, Vec::new(), false, None),
            (true, None, None)
        );
    }

    #[test]
    fn parse_published_sockets_rejects_bad_specs() {
        assert!(parse_published_sockets(&[], &["/only-host".to_string()]).is_err());
        assert!(parse_published_sockets(&[":/tmp/h.sock".to_string()], &[]).is_err());
        assert!(parse_published_sockets(&["/run/a;b.sock".to_string()], &[]).is_err());
        // Relative guest paths resolve against whatever the guest process is
        // rooted at, so they can never name the socket the user meant.
        assert!(parse_published_sockets(&["app.sock".to_string()], &[]).is_err());
        assert!(parse_published_sockets(&[], &["/run/h.sock:app.sock".to_string()]).is_err());
        // Two mount bridges at one guest path shadow each other in the guest,
        // leaving the first host socket unreachable.
        assert!(parse_published_sockets(
            &[],
            &[
                "/run/h1.sock:/run/control/engine.sock".to_string(),
                "/run/h2.sock:/run/control/engine.sock".to_string(),
            ]
        )
        .is_err());
    }

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
    fn create_accepts_port_ranges() {
        let cli = TestMachineCli::parse_from([
            "machine",
            "create",
            "--name",
            "range-test",
            "--port",
            "5173-5175:6173-6175",
        ]);
        let MachineCmd::Create(cmd) = cli.command else {
            panic!("expected machine create command");
        };

        assert_eq!(
            PortMappingSpec::expand_all(&cmd.port).unwrap(),
            vec![
                PortMapping::new(5173, 6173),
                PortMapping::new(5174, 6174),
                PortMapping::new(5175, 6175),
            ]
        );
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

    #[test]
    fn start_cuda_pool_flags_parse_and_limit_requires_pool() {
        let cli = TestMachineCli::parse_from([
            "machine",
            "start",
            "--name",
            "golden",
            "--fork-pool-size",
            "4",
            "--cuda-vram-limit-mib",
            "10240",
        ]);
        let MachineCmd::Start(cmd) = cli.command else {
            panic!("expected machine start command");
        };
        assert_eq!(cmd.fork_pool_size.map(|v| v.get()), Some(4));
        assert_eq!(cmd.cuda_vram_limit_mib.map(|v| v.get()), Some(10240));

        assert!(TestMachineCli::try_parse_from([
            "machine",
            "start",
            "--name",
            "golden",
            "--cuda-vram-limit-mib",
            "10240",
        ])
        .is_err());
    }

    #[test]
    fn fork_accepts_single_and_batch_forms() {
        let single =
            TestMachineCli::parse_from(["machine", "fork", "--golden", "base", "--name", "worker"]);
        let MachineCmd::Fork(single) = single.command else {
            panic!("expected machine fork command");
        };
        assert_eq!(single.clone.as_deref(), Some("worker"));
        assert_eq!(single.count.get(), 1);
        assert!(!single.wait_ready);

        let batch = TestMachineCli::parse_from([
            "machine",
            "fork",
            "--golden",
            "base",
            "--count",
            "8",
            "--name-prefix",
            "worker",
            "--parallel",
            "3",
            "--ready-timeout",
            "2m",
        ]);
        let MachineCmd::Fork(batch) = batch.command else {
            panic!("expected machine fork command");
        };
        assert_eq!(batch.count.get(), 8);
        assert_eq!(batch.name_prefix.as_deref(), Some("worker"));
        assert_eq!(batch.parallel.get(), 3);
        assert!(!batch.wait_ready);
        assert_eq!(batch.ready_timeout, Duration::from_secs(120));
        assert_eq!(
            forkpoint_timeout(
                batch.count.get(),
                batch.wait_ready,
                batch.hold,
                batch.ready_timeout,
            ),
            Some(Duration::from_secs(120))
        );
        assert_eq!(
            forkpoint_timeout(1, false, false, Duration::from_secs(120)),
            None
        );
        assert_eq!(
            forkpoint_timeout(1, false, true, Duration::from_secs(120)),
            Some(Duration::from_secs(120))
        );

        let release = TestMachineCli::parse_from([
            "machine",
            "fork-release",
            "--name",
            "worker-0",
            "--env",
            "LR=3e-4",
        ]);
        let MachineCmd::ForkRelease(release) = release.command else {
            panic!("expected fork-release command");
        };
        assert_eq!(release.name, "worker-0");
        assert_eq!(release.env, vec!["LR=3e-4"]);
    }

    #[test]
    fn indexed_fork_env_renders_each_clone() {
        let specs = vec![
            "TRIAL={index}".to_string(),
            "OUTPUT=/runs/{name}".to_string(),
            "SMOLVM_FORK_INDEX=wrong".to_string(),
            "SMOLVM_FORK_BATCH_ID=wrong".to_string(),
            "SMOLVM_FORK_BATCH_SIZE=999".to_string(),
        ];
        assert_eq!(
            render_indexed_fork_env(
                &specs,
                3,
                "worker-3",
                true,
                Some(&ForkBatchIdentity {
                    id: "batch-1".to_string(),
                    size: 8,
                }),
            ),
            vec![
                ("TRIAL".to_string(), "3".to_string()),
                ("OUTPUT".to_string(), "/runs/worker-3".to_string()),
                ("SMOLVM_FORK_INDEX".to_string(), "3".to_string()),
                ("SMOLVM_FORK_NAME".to_string(), "worker-3".to_string()),
                ("SMOLVM_FORK_BATCH_ID".to_string(), "batch-1".to_string()),
                ("SMOLVM_FORK_BATCH_SIZE".to_string(), "8".to_string()),
            ]
        );
        assert_eq!(
            render_indexed_fork_env(&specs, 3, "worker-3", true, None),
            vec![
                ("TRIAL".to_string(), "3".to_string()),
                ("OUTPUT".to_string(), "/runs/worker-3".to_string()),
                ("SMOLVM_FORK_INDEX".to_string(), "3".to_string()),
                ("SMOLVM_FORK_NAME".to_string(), "worker-3".to_string()),
            ]
        );
    }

    #[test]
    fn run_accepts_auto_graph_flag() {
        let cli = TestMachineCli::parse_from([
            "machine",
            "run",
            "--auto-graph",
            "--image",
            "alpine",
            "--",
            "true",
        ]);

        let MachineCmd::Run(cmd) = cli.command else {
            panic!("expected machine run command");
        };
        assert!(cmd.auto_graph);
        assert!(!cmd.cuda, "auto-graph implies CUDA during parameter merge");
    }

    #[test]
    fn create_accepts_auto_graph_flag() {
        let cli =
            TestMachineCli::parse_from(["machine", "create", "--name", "golden", "--auto-graph"]);

        let MachineCmd::Create(cmd) = cli.command else {
            panic!("expected machine create command");
        };
        assert!(cmd.auto_graph);
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

    // Machine options after `--` are workload arguments; clap cannot reject
    // them, so they must at least be named.
    #[test]
    fn create_flags_after_separator_are_detected() {
        let cli = TestMachineCli::parse_from([
            "machine",
            "create",
            "--name",
            "x",
            "--",
            "/bin/sh",
            "-c",
            "sleep infinity",
            "--mem",
            "32768",
            "--storage",
            "120",
            "--net",
        ]);
        let MachineCmd::Create(cmd) = cli.command else {
            panic!("expected machine create command");
        };
        // They configured nothing: the machine still has the defaults.
        assert_eq!(cmd.mem, DEFAULT_MICROVM_MEMORY_MIB);
        assert_eq!(cmd.storage, None);
        assert!(!cmd.net);
        assert_eq!(
            create_flags_in_workload(&cmd.command),
            ["--mem", "--storage", "--net"]
        );
    }

    #[test]
    fn create_workload_own_options_are_not_reported() {
        // A workload's own long options are not machine options, and short
        // flags are never reported — `-v`, `-e` and `-p` are too common.
        let words: Vec<String> = ["myserver", "--listen", "0.0.0.0", "-v", "-e", "-p", "8080"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(create_flags_in_workload(&words).is_empty());
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

    #[test]
    fn prune_evicts_oldest_and_a_touch_saves_a_hot_entry() {
        let dir = tempfile::tempdir().unwrap();
        let write = |name: &str, bytes: usize| {
            let p = dir.path().join(name);
            std::fs::write(&p, vec![0u8; bytes]).unwrap();
            p
        };
        // Three 4 KiB entries; cap at 6 KiB forces evicting down to one.
        let cold = write("cold.smolmachine", 4096);
        let mid = write("mid.smolmachine", 4096);
        let hot = write("hot.smolmachine", 4096);

        // Establish an age order: cold < mid < hot, then simulate a cache HIT on
        // `cold` by touching it so it becomes the most-recently-used.
        let base = std::time::SystemTime::now() - std::time::Duration::from_secs(300);
        for (p, age) in [(&cold, 300), (&mid, 200), (&hot, 100)] {
            std::fs::OpenOptions::new()
                .write(true)
                .open(p)
                .unwrap()
                .set_modified(base + std::time::Duration::from_secs(300 - age))
                .unwrap();
        }
        touch_cache_entry(&cold); // hit → now newest

        // Cap at 8 KiB keeps two of the three 4 KiB entries, evicting exactly one.
        prune_init_cache(dir.path(), 8192, &hot);

        // `hot` is kept (explicit keep), `cold` survives (just touched), and the
        // now-oldest `mid` is the one evicted.
        assert!(hot.exists(), "the just-baked entry is always kept");
        assert!(cold.exists(), "a touched (recently-used) entry survives");
        assert!(!mid.exists(), "the least-recently-used entry is evicted");
    }
}

// ============================================================================
// Exec Command (Persistent) - Direct VM Execution
// ============================================================================

/// Resolve the persistent container overlay visible to CLI operations.
///
/// A fork clone inherits the golden's overlay directory through its CoW storage
/// disk. Addressing a new directory under the clone's name would silently give
/// `machine exec` and `machine cp` a clean image instead of the forked rootfs.
fn persistent_overlay_owner_for_record(
    machine_name: &str,
    record: Option<&smolvm::config::VmRecord>,
) -> String {
    smolvm::workload::persistent_overlay_owner_with_lineage(
        machine_name,
        record.and_then(|record| record.golden.as_deref()),
        record.and_then(|record| record.fork_overlay_owner.as_deref()),
    )
}

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

    /// Detach: spawn the command in the background and return its PID
    /// immediately. The process keeps running (it is not killed when this
    /// command returns), so it can host long-lived services — e.g. a server
    /// bound to a published port. Incompatible with -i/-t and --stream.
    #[arg(short = 'd', long, conflicts_with_all = ["interactive", "tty", "stream"])]
    pub detach: bool,
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
            // Fork clones address the golden's inherited overlay; ordinary
            // machines use their own name.
            let overlay_owner = persistent_overlay_owner_for_record(&name, record.as_ref());
            // An exec may be what establishes the workload container — the
            // machine's command exited, or the image's own default was
            // short-lived — and that container is where the mount lives. Carry
            // the machine's volumes so the bucket is in whichever container
            // serves this session, not only when a long-running workload
            // happened to survive.
            let exec_s3_volumes = record
                .as_ref()
                .map(|r| smolvm::remote_volume::to_s3_volumes(&r.remote_volumes, &r.env))
                .unwrap_or_default();
            if self.detach {
                let config = smolvm::agent::RunConfig::new(image, self.command.clone())
                    .with_env(defaults.env)
                    .with_workdir(defaults.workdir)
                    .with_user(defaults.user)
                    .with_mounts(mount_bindings)
                    .with_s3_volumes(exec_s3_volumes.clone())
                    .with_s3_volumes(exec_s3_volumes.clone())
                    .with_persistent_overlay(Some(overlay_owner));
                let pid = client.run_background(config)?;
                println!("{pid}");
                return Ok(());
            }
            if self.interactive || self.tty {
                let config = smolvm::agent::RunConfig::new(image, self.command.clone())
                    .with_env(defaults.env.clone())
                    .with_workdir(defaults.workdir.clone())
                    .with_user(defaults.user.clone())
                    .with_mounts(mount_bindings)
                    .with_timeout(self.timeout)
                    .with_tty(self.tty)
                    .with_s3_volumes(exec_s3_volumes.clone())
                    .with_persistent_overlay(Some(overlay_owner.clone()));
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
                    .with_s3_volumes(exec_s3_volumes.clone())
                    .with_persistent_overlay(Some(overlay_owner.clone()));
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
                .with_s3_volumes(exec_s3_volumes.clone())
                .with_persistent_overlay(Some(overlay_owner));
            let (exit_code, stdout, stderr) = client.run_non_interactive(config)?;
            vm_common::print_output_and_exit(&manager, exit_code, &stdout, &stderr);
        } else {
            // Bare VM: exec directly in the VM rootfs.
            // Merge record env + resolved secrets with CLI env, same as image path.
            let env = vm_common::merge_env_overrides(&record_env, &env);
            if self.detach {
                // Spawn detached in the guest root netns — no setsid/killpg, so
                // a daemon (e.g. a server on a published port) survives. TSI sees
                // the listen() and opens the host-side forward.
                let pid = client.vm_exec_background(self.command.clone(), env, workdir.clone())?;
                println!("{pid}");
                return Ok(());
            }
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
            detach: false,
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

    /// Attach metadata to the machine (repeatable), e.g.
    /// `--label owner=exo --label sandbox=agent-7`.
    ///
    /// smolvm never interprets these. They exist so a process managing many
    /// machines can identify its own later — which sandbox a machine serves, who
    /// created it, whether it may be reclaimed — instead of encoding that into
    /// the name. Read them back with `machine ls --json`.
    #[arg(long = "label", value_name = "KEY=VALUE")]
    pub labels: Vec<String>,

    /// Container image: a registry reference (alpine, python:3.12-alpine), a
    /// `docker save` archive (./myapp.tar, or `-` to read one from stdin), or an
    /// unpacked rootfs directory (./rootfs/). A bare name is always a registry
    /// reference — pipe `docker save` to use a locally built image.
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

    /// Mount host directory (can be used multiple times). Also accepts
    /// S3-compatible object storage, mounted inside the guest on every start:
    /// `s3://bucket/prefix:/data[:ro]` (credentials from --env
    /// AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, optional AWS_ENDPOINT_URL
    /// for R2/MinIO; anonymous without them). Nothing is required of the
    /// image: the agent performs the mount itself.
    #[arg(short = 'v', long = "volume", value_name = "HOST|REMOTE:GUEST[:ro]")]
    pub volume: Vec<String>,

    /// Expose port from VM to host (single port or one-to-one range, repeatable)
    #[arg(short = 'p', long = "port", value_parser = PortMappingSpec::parse, value_name = "PORT[-END]|HOST[-END]:GUEST[-END]")]
    pub port: Vec<PortMappingSpec>,

    /// Enable outbound network access
    #[arg(long)]
    pub net: bool,

    /// Select the networking backend.
    #[arg(long = "net-backend", value_enum)]
    pub net_backend: Option<NetworkBackend>,

    /// Custom DNS resolver for the guest (implies --net). Use this when the
    /// default public resolvers (8.8.8.8/1.1.1.1) are blocked on your network.
    #[arg(long, value_name = "IP")]
    pub dns: Option<std::net::Ipv4Addr>,

    /// Join a named inter-VM network (implies --net, virtio-net only): members
    /// get distinct addresses and can reach each other directly
    #[arg(long = "network", value_name = "NAME")]
    pub network_name: Option<String>,

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

    /// Enable Rosetta 2 for x86_64 binary translation on Apple Silicon
    #[arg(long)]
    pub rosetta: bool,

    /// Expose a Unix socket the guest listens on to the host (repeatable). The
    /// host reaches it at the given host path, or `<vm-dir>/<basename>` by
    /// default. Format: GUEST_PATH[:HOST_PATH].
    #[arg(long = "expose-socket", value_name = "GUEST_PATH[:HOST_PATH]")]
    pub expose_socket: Vec<String>,

    /// Mount a host Unix socket into the guest (repeatable), so a guest process
    /// reaches the host service at GUEST_PATH. Format: HOST_PATH:GUEST_PATH.
    #[arg(long = "mount-socket", value_name = "HOST_PATH:GUEST_PATH")]
    pub mount_socket: Vec<String>,

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

    /// Remote guest CUDA Driver-API calls to the host NVIDIA GPU over vsock
    #[arg(long)]
    pub cuda: bool,

    /// Ask compatible CUDA frameworks to graph safe compiled regions.
    /// Implies --cuda; arbitrary eager CUDA calls are not captured.
    #[arg(long)]
    pub auto_graph: bool,

    /// Expose the guest's Docker daemon socket to the host as a Unix socket
    /// (DOCKER_HOST=unix://…). Requires dockerd running in the VM.
    #[arg(long)]
    pub docker_socket: bool,

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

    /// Create from a `.smolmachine` pack or restore a `.smolcheckpoint`.
    #[arg(long, value_name = "PATH", conflicts_with_all = ["image", "smolfile"])]
    pub from: Option<PathBuf>,

    /// Command to run as the machine's persistent workload (image machines).
    /// Launched as a detached container on every `start`, so it stays running
    /// (e.g. a pre-warmed browser to be forked). Without this, the image's own
    /// ENTRYPOINT/CMD is launched instead; if the image defines neither (e.g.
    /// a bare rootfs directory), the machine boots to just the agent and
    /// commands come from `exec`/`shell`.
    ///
    /// `last = true` requires the `--` separator. With the machine name now a
    /// flag, a bare positional (an old-style `machine create myvm`) must fail
    /// loudly instead of being silently captured as the workload command.
    #[arg(last = true, value_name = "COMMAND")]
    pub command: Vec<String>,
}

impl CreateCmd {
    pub fn run(self) -> smolvm::Result<()> {
        // Everything after `--` is the workload, so machine options written
        // there are handed to the guest command and quietly do not configure the
        // machine — a swallowed `--mem`/`--storage` boots a machine at the
        // defaults with no diagnostic. Rejecting them is not an option (a
        // workload may legitimately take an option of the same name), so name
        // them. Checked before the `--from` branch so both create paths warn.
        let stray_flags = create_flags_in_workload(&self.command);
        if !stray_flags.is_empty() {
            eprintln!(
                "note: {} came after `--`, so {} passed to the workload and did not \
                 configure the machine. Machine options go before `--`.",
                stray_flags.join(", "),
                if stray_flags.len() == 1 {
                    "it was"
                } else {
                    "they were"
                }
            );
        }

        // --max-image-size raises the archive cap for this invocation by setting
        // the env var the resolver reads (image_source::max_archive_bytes).
        if let Some(bytes) = self.max_image_size {
            std::env::set_var("SMOLVM_MAX_IMAGE_BYTES", bytes.to_string());
        }
        // Branch for --from: create machine from .smolmachine artifact.
        if let Some(ref sidecar_path) = self.from {
            return self.run_from_smolmachine(sidecar_path);
        }

        // A registry --image can name a smolmachine PACK artifact (e.g.
        // registry.smolmachines.com/library/alpine), whose single "layer" is a
        // full .smolmachine sidecar — not an OCI filesystem layer the in-guest
        // puller could unpack (its multi-GiB storage.ext4 would fill the guest
        // disk). Probe the manifest on the host and, if so, pull the sidecar
        // and continue exactly as `--from`; a failed probe falls back to the
        // normal in-guest pull.
        if let Some(img) = self.image.as_deref() {
            if let Some(sidecar) = smolvm::data::pack_ref::resolve_pack_ref_blocking(img)? {
                return self.run_from_smolmachine(&sidecar);
            }
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
            self.dns,
            self.network_name.clone(),
            self.init,
            self.env,
            self.workdir,
            self.smolfile.clone(),
            self.storage,
            self.overlay,
            cli_allow_cidrs,
            smolvm::util::parse_labels(&self.labels)?,
        )?;
        let mut params = params;
        if self.auto_graph {
            smolvm::util::enable_cuda_auto_graph_env_specs(&mut params.env);
            params.cuda = true;
        }
        params.dns_filter_hosts = match (params.dns_filter_hosts.take(), cli_dns_filter_hosts) {
            (Some(mut from_smolfile), Some(mut from_cli)) => {
                from_smolfile.append(&mut from_cli);
                Some(from_smolfile)
            }
            (Some(from_smolfile), None) => Some(from_smolfile),
            (None, some) => some,
        };
        params.published_sockets =
            parse_published_sockets(&self.expose_socket, &self.mount_socket)?;
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
            dns: params.dns,
            network_name: params.network_name.clone(),
            gpu: params.gpu,
            gpu_vram_mib: params.gpu_vram_mib,
            cuda: params.cuda,
            rosetta: params.rosetta,
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
        if self.cuda {
            params.cuda = true;
        }
        if self.docker_socket {
            params.docker_socket = true;
        }
        if self.gpu {
            params.gpu = true;
        }
        if self.rosetta {
            params.rosetta = true;
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
        let checkpoint = manifest.checkpoint.clone();
        if let Some(ref checkpoint) = checkpoint {
            smolvm::portable_checkpoint::validate_compatibility(checkpoint)?;
            let topology_overridden = !self.volume.is_empty()
                || !self.port.is_empty()
                || self.net
                || self.net_backend.is_some()
                || self.dns.is_some()
                || self.network_name.is_some()
                || !self.allow_cidr.is_empty()
                || !self.allow_host.is_empty()
                || self.outbound_localhost_only
                || self.gpu
                || self.gpu_vram_mib.is_some()
                || self.rosetta
                || !self.expose_socket.is_empty()
                || !self.mount_socket.is_empty()
                || self.ssh_agent
                || self.cuda
                || self.auto_graph
                || self.docker_socket
                || self.storage.is_some()
                || self.overlay.is_some();
            if topology_overridden {
                return Err(smolvm::Error::config(
                    "create from .smolcheckpoint",
                    "a live checkpoint must restore its captured CPU, memory, disk, and device topology; topology-changing create flags are not supported",
                ));
            }
        }

        // Reject a cross-architecture artifact up front: a packed VM/image carries
        // native binaries and cannot boot under a different-arch guest kernel. Only
        // the guest arch must match — the host OS does not (see the fn's docs).
        smolvm::platform::ensure_artifact_arch_matches_host(&manifest.platform)?;

        // Read the footer now; the bundle is extracted into the machine's own
        // data dir after `create_vm` succeeds (below), so a duplicate-name create
        // cannot clobber an existing machine's layers.
        let footer = smolvm_pack::packer::read_footer_from_sidecar(sidecar_path)
            .map_err(|e| smolvm::Error::agent("read sidecar footer", e.to_string()))?;

        // A VM-mode pack (`--from-vm`) carries the source VM's overlay+storage
        // DISKS (the real rootfs), not OCI layers. Capture the templates before
        // `manifest` is moved into `params`; the disks are seeded from them after
        // extraction below, or the machine boots the bare agent-rootfs with no
        // /bin/sh (mirrors pack_run + the serve API create path).
        struct VmModeSeed {
            overlay_template: Option<String>,
            storage_template: Option<String>,
            overlay_logical_size: Option<u64>,
            storage_logical_size: Option<u64>,
        }
        let vm_seed = if checkpoint.is_none() && manifest.mode == smolvm_pack::format::PackMode::Vm
        {
            Some(VmModeSeed {
                overlay_template: manifest
                    .assets
                    .overlay_template
                    .as_ref()
                    .map(|t| t.path.clone()),
                storage_template: manifest
                    .assets
                    .storage_template
                    .as_ref()
                    .map(|t| t.path.clone()),
                overlay_logical_size: manifest.assets.overlay_logical_size,
                storage_logical_size: manifest.assets.storage_logical_size,
            })
        } else {
            None
        };

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
        if let Some(ref checkpoint) = checkpoint {
            if cpus != checkpoint.cpus || mem != checkpoint.memory_mib {
                return Err(smolvm::Error::config(
                    "create from .smolcheckpoint",
                    format!(
                        "checkpoint requires {} vCPU(s) and {} MiB memory (requested {cpus} and {mem})",
                        checkpoint.cpus, checkpoint.memory_mib
                    ),
                ));
            }
        }

        let (cli_allow_cidrs, cli_network, cli_dns_filter_hosts) = resolve_egress_flags(
            self.allow_cidr.clone(),
            self.allow_host.clone(),
            self.outbound_localhost_only,
            self.net,
        )?;
        let (network, allowed_cidrs, dns_filter_hosts) = smolmachine_egress_fields(
            manifest.network,
            cli_allow_cidrs,
            cli_network,
            cli_dns_filter_hosts,
        );
        let checkpoint_network = checkpoint
            .as_ref()
            .and_then(|checkpoint| checkpoint.network.as_ref());
        let network = checkpoint_network
            .map(|captured| captured.enabled)
            .unwrap_or(network);
        let allowed_cidrs = checkpoint_network
            .and_then(|captured| captured.allowed_cidrs.clone())
            .or(allowed_cidrs);
        let dns_filter_hosts = checkpoint_network
            .and_then(|captured| captured.dns_filter_hosts.clone())
            .or(dns_filter_hosts);

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

        let ports = if checkpoint.is_some() && self.port.is_empty() {
            checkpoint_network
                .into_iter()
                .flat_map(|network| network.ports.iter())
                .map(|port| PortMapping::new(port.host, port.guest))
                .collect()
        } else {
            PortMappingSpec::expand_all(&self.port)
                .map_err(|e| smolvm::Error::config("create from .smolmachine ports", e))?
        };
        let checkpoint_backend = match checkpoint.as_ref() {
            Some(checkpoint) => smolvm::portable_checkpoint::restored_network_backend(checkpoint)?,
            None => None,
        };
        let params = vm_common::CreateVmParams {
            secret_refs: manifest.secret_refs,
            name,
            // A VM-mode pack is a VM, not a container: its synthetic `vm://<name>`
            // label would make exec/start/re-pack treat it as a pullable image
            // (the /bin/sh-not-found bug). None routes every `image.is_some()`
            // consumer to VM behavior; provenance is in `source_smolmachine`.
            image: if let Some(workload) = checkpoint
                .as_ref()
                .and_then(|checkpoint| checkpoint.workload.as_ref())
            {
                Some(workload.image.clone())
            } else if vm_seed.is_some() || checkpoint.is_some() {
                None
            } else {
                Some(manifest.image)
            },
            // CLI trailing args override the artifact's baked (entrypoint, cmd),
            // matching the --image create path's precedence — without this a
            // `machine create --from art -- <workload>` silently never runs it.
            entrypoint: if self.command.is_empty() {
                manifest.entrypoint
            } else {
                Vec::new()
            },
            cmd: if self.command.is_empty() {
                manifest.cmd
            } else {
                self.command.clone()
            },
            cpus,
            mem,
            volume: self.volume.clone(),
            port: ports,
            net: network,
            network_backend: checkpoint_backend.or(self.net_backend),
            dns: self.dns,
            network_name: self.network_name.clone(),
            init: self.init.clone(),
            env: {
                let mut env = manifest.env;
                env.extend(self.env.iter().cloned());
                if self.auto_graph {
                    smolvm::util::enable_cuda_auto_graph_env_specs(&mut env);
                }
                env
            },
            workdir: manifest.workdir,
            storage_gb: checkpoint
                .as_ref()
                .and_then(|checkpoint| checkpoint.storage_gib)
                .or(self.storage),
            overlay_gb: checkpoint
                .as_ref()
                .and_then(|checkpoint| checkpoint.overlay_gib)
                .or(self.overlay),
            allowed_cidrs,
            restart_policy: checkpoint
                .as_ref()
                .and_then(|checkpoint| checkpoint.workload.as_ref())
                .map(|workload| workload.restart_policy.parse())
                .transpose()
                .map_err(|error: String| {
                    smolvm::Error::config("restore checkpoint restart policy", error)
                })?,
            restart_max_retries: checkpoint
                .as_ref()
                .and_then(|checkpoint| checkpoint.workload.as_ref())
                .map(|workload| workload.restart_max_retries),
            restart_max_backoff_secs: checkpoint
                .as_ref()
                .and_then(|checkpoint| checkpoint.workload.as_ref())
                .map(|workload| workload.restart_max_backoff_secs),
            labels: smolvm::util::parse_labels(&self.labels)?,
            health_cmd: None,
            health_interval_secs: None,
            health_timeout_secs: None,
            health_retries: None,
            health_startup_grace_secs: None,
            ssh_agent: self.ssh_agent,
            cuda: self.cuda || self.auto_graph,
            // A restored durable checkpoint remains eligible to become a new
            // fork/checkpoint source without a topology-changing restart.
            forkable: checkpoint.is_some(),
            cuda_fork_pool_size: None,
            cuda_vram_limit_mib: None,
            docker_socket: self.docker_socket,
            dns_filter_hosts,
            published_sockets: parse_published_sockets(&self.expose_socket, &self.mount_socket)?,
            gpu: manifest.gpu,
            gpu_vram_mib: None,
            rosetta: false,
            // A live checkpoint uses the pack only as a transport envelope.
            // Its block devices and running guest state are restored from the
            // checkpoint payload, so treating the artifact as an OCI-layer
            // source would attach an extra virtiofs device and change the
            // captured device topology. The payload is private to the machine
            // after install and no longer depends on the original artifact.
            source_smolmachine: checkpoint.is_none().then_some(canonical_path),
        };

        let resources = VmResources {
            cpus: params.cpus,
            memory_mib: params.mem,
            network: params.net,
            network_backend: params.network_backend,
            dns: params.dns,
            network_name: params.network_name.clone(),
            gpu: params.gpu,
            gpu_vram_mib: params.gpu_vram_mib,
            cuda: params.cuda,
            rosetta: params.rosetta,
            storage_gib: params.storage_gb,
            overlay_gib: params.overlay_gb,
            allowed_cidrs: params.allowed_cidrs.clone(),
        };
        resources.validate()?;
        validate_requested_network_backend(
            &resources,
            params.dns_filter_hosts.as_deref(),
            params.port.len(),
        )?;

        let mut record = vm_common::build_vm_record(&params)?;
        if checkpoint.is_some() {
            // The restored RAM already contains the initialized guest and its
            // running workload. Re-running image pull/init after resume would
            // duplicate side effects and violate checkpoint semantics.
            record.init_completed = true;
            record.user = checkpoint
                .as_ref()
                .and_then(|checkpoint| checkpoint.workload.as_ref())
                .and_then(|workload| workload.user.clone());
            record.fork_overlay_owner = checkpoint
                .as_ref()
                .and_then(|checkpoint| checkpoint.workload.as_ref())
                .map(|workload| workload.overlay_owner.clone());
        }
        let reservation = vm_common::CreateVmReservation::reserve(&name_for_layers)?;

        // Create the machine data dir while the DB reservation is held, then
        // extract before publishing the VM row. Other processes either see the
        // reservation conflict or the finished VM, never a half-created record.
        let create_result = (|| -> smolvm::Result<()> {
            let manager = AgentManager::for_vm_with_sizes(
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
            let result = if smolvm_pack::extract::shared_extract_enabled() {
                #[cfg(target_os = "linux")]
                {
                    let lease = smolvm::artifact_cache::materialize_shared_pack_lease(
                        sidecar_path,
                        &footer,
                        &cache_dir,
                        false,
                    )
                    .map_err(|e| smolvm::Error::agent("extract sidecar (shared)", e.to_string()))?;
                    Ok((lease.shared_dir, Some(lease.artifact_sha256)))
                }
                #[cfg(not(target_os = "linux"))]
                unreachable!("shared pack extraction is Linux-only")
            } else {
                smolvm_pack::extract::extract_sidecar(
                    sidecar_path,
                    &cache_dir,
                    &footer,
                    false,
                    false,
                )
                .map(|()| (cache_dir.clone(), None::<String>))
                .map_err(|e| smolvm::Error::agent("extract sidecar", e.to_string()))
            };
            // Detach unconditionally: extraction mounts the case-sensitive volume on
            // macOS even when it later fails, so the detach must run on both success
            // and failure paths to honor the "mounted iff running" invariant.
            smolvm_pack::extract::force_detach_layers_volume(&cache_dir);
            let (pack_content_dir, artifact_sha256) = result?;

            // VM-mode pack: seed this machine's overlay+storage disks from the
            // packed templates so a start boots the source VM's rootfs rather than
            // the bare agent-rootfs. Shared with the serve API create path: it
            // resizes the truncated templates into valid raw disks and removes the
            // manager's default `.qcow2` overlays so the start resolves these.
            // (Writing the resized copy onto `manager.overlay_path()` — the default
            // `.qcow2` — handed the guest raw bytes named `.qcow2`, the /bin/sh-missing
            // bug's disk counterpart.)
            if let Some(seed) = &vm_seed {
                let disk_dir = manager
                    .storage_path()
                    .parent()
                    .map(std::path::Path::to_path_buf)
                    .unwrap_or_else(|| smolvm::agent::vm_data_dir(&name_for_layers));
                smolvm::storage::seed_vm_mode_disks(
                    &disk_dir,
                    &pack_content_dir,
                    smolvm::storage::VmModeDiskSeedSpec {
                        artifact_sha256: artifact_sha256.as_deref(),
                        overlay_template: seed.overlay_template.as_deref(),
                        storage_template: seed.storage_template.as_deref(),
                        overlay_logical_size: seed.overlay_logical_size,
                        storage_logical_size: seed.storage_logical_size,
                        overlay_gb: params.overlay_gb,
                        storage_gb: params.storage_gb,
                    },
                )
                .map_err(|e| smolvm::Error::agent("seed VM-mode disks", e.to_string()))?;
            }

            if let Some(ref checkpoint) = checkpoint {
                let vm_data_dir = smolvm::agent::vm_data_dir(&name_for_layers);
                smolvm::portable_checkpoint::install(&pack_content_dir, &vm_data_dir, checkpoint)?;
                smolvm::portable_checkpoint::discard_transport_pack(&vm_data_dir)?;
            }

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

    /// Plan a CUDA fork pool with this many runnable clones. Smolvm reports a
    /// safe per-session VRAM share before the golden initializes, so vLLM and
    /// similar runtimes size private caches without workload changes. Implies
    /// --forkable.
    #[arg(long, value_name = "CLONES")]
    pub fork_pool_size: Option<std::num::NonZeroU32>,

    /// Override the automatic logical VRAM budget for each golden/clone CUDA
    /// session. The workload still needs no changes. Requires --fork-pool-size.
    #[arg(long, value_name = "MIB", requires = "fork_pool_size")]
    pub cuda_vram_limit_mib: Option<std::num::NonZeroU64>,

    #[command(flatten, next_help_heading = "Network")]
    pub proxy_opts: crate::cli::proxy_opts::ProxyOpts,
}

impl StartCmd {
    pub fn run(self) -> smolvm::Result<()> {
        let explicit_name = self.name.is_some();
        let name = self.name.unwrap_or_else(|| "default".to_string());
        let proxy = self.proxy_opts.resolved_proxy()?;
        let no_proxy = self.proxy_opts.no_proxy();
        // Forkable start: memfd-back guest RAM and register a control socket at a
        // known path so `machine fork` can later freeze this machine as a CoW base.
        let fork = if self.forkable || self.fork_pool_size.is_some() {
            let mut launch = vm_common::forkable_launch();
            launch.pool_size = self.fork_pool_size.map(std::num::NonZeroU32::get);
            launch.vram_limit_mib = self.cuda_vram_limit_mib.map(std::num::NonZeroU64::get);
            launch
        } else {
            vm_common::ForkLaunch::default()
        };
        match vm_common::start_vm_named(
            &name,
            proxy.as_deref(),
            no_proxy.as_deref(),
            /* from_snapshot */ false,
            fork,
        ) {
            Ok(()) => Ok(()),
            Err(smolvm::Error::VmNotFound { .. }) if !explicit_name => {
                // Only fall back to creating a default VM when no --name was given.
                // With an explicit --name, VmNotFound is a real error.
                vm_common::start_vm_default(proxy.as_deref(), no_proxy.as_deref())
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
    #[arg(long, visible_alias = "from", value_name = "NAME")]
    pub golden: String,

    /// Name for the new clone machine.
    #[arg(short = 'n', long = "name", value_name = "NAME")]
    pub clone: Option<String>,

    /// Number of clones to create from one snapshot. Batch forks wait for the
    /// standard `smolvm-fork-ready` boundary automatically. Direct batches
    /// receive one shared `SMOLVM_FORK_BATCH_ID` and `SMOLVM_FORK_BATCH_SIZE`;
    /// held slots remain independent until assigned by their controller.
    #[arg(long, default_value = "1", value_name = "COUNT")]
    pub count: std::num::NonZeroU32,

    /// Name batch clones PREFIX-0 through PREFIX-(COUNT-1).
    #[arg(long, value_name = "PREFIX")]
    pub name_prefix: Option<String>,

    /// Maximum number of clone boots in flight during a batch fork.
    #[arg(long, default_value = "4", value_name = "COUNT")]
    pub parallel: std::num::NonZeroU32,

    /// Wait for `smolvm-fork-ready` in a single-clone fork. Batch forks always
    /// wait; unless held, they release clones only after identity and fork env
    /// are installed.
    #[arg(long)]
    pub wait_ready: bool,

    /// Keep each clone parked at the inherited forkpoint as an already-booted
    /// pool slot. Assign and release a slot later with `machine fork-release`.
    /// A consumed slot is disposable; delete and replenish it from the golden
    /// rather than reusing mutated training state.
    #[arg(long)]
    pub hold: bool,

    /// Maximum time to wait for the golden workload's forkpoint.
    #[arg(
        long,
        default_value = "10m",
        value_parser = parse_duration,
        value_name = "DURATION",
    )]
    pub ready_timeout: Duration,

    /// Make the clone itself forkable (memfd RAM + control socket), so it can
    /// in turn be forked.
    #[arg(long, visible_alias = "checkpointable")]
    pub forkable: bool,

    /// Pin the clone's inbound port forwards (single port or one-to-one range, repeatable).
    /// Without this, the golden's forwards are remapped to freshly-allocated host ports.
    #[arg(short = 'p', long = "port", value_parser = PortMappingSpec::parse, value_name = "PORT[-END]|HOST[-END]:GUEST[-END]", help_heading = "Network")]
    pub port: Vec<PortMappingSpec>,

    /// Share the golden's loaded CUDA weights with this clone instead of
    /// copying them — sibling clones then keep ONE copy of the base model in
    /// VRAM. Correct when the base stays frozen (LoRA/QLoRA fine-tuning,
    /// inference); use a plain fork when the clone trains the base weights.
    #[arg(long)]
    pub share_weights: bool,

    /// Per-fork parameter (repeatable, KEY=VALUE). Delivered to the clone as
    /// `/etc/smolvm/fork-env` (dotenv format) for the already-running workload
    /// to read, and merged into the clone's env for later `machine exec`
    /// sessions. This is how sweep/rollout clones learn which variant they
    /// are — no shared-mount claim files needed.
    #[arg(short = 'e', long = "env", value_name = "KEY=VALUE")]
    pub env: Vec<String>,

    /// Inject a per-fork secret from a host env var (GUEST_VAR=HOST_VAR),
    /// resolved fresh on every `exec` in the clone. Unlike `--env`, the value is
    /// never written to the clone's record, the overlay/pack, or the fork-env
    /// guest file — and each clone's secrets are its own, invisible to the
    /// golden and sibling clones.
    #[arg(
        long = "secret-env",
        value_name = "GUEST_VAR=HOST_VAR",
        help_heading = "Security"
    )]
    pub secret_env: Vec<String>,

    /// Inject a per-fork secret from a host file (GUEST_VAR=/abs/path), resolved
    /// fresh on every `exec` in the clone. Never persisted to the record,
    /// overlay/pack, or fork-env guest file. See `--secret-env`.
    #[arg(
        long = "secret-file",
        value_name = "GUEST_VAR=PATH",
        help_heading = "Security"
    )]
    pub secret_file: Vec<String>,
}

impl ForkCmd {
    pub fn run(self) -> smolvm::Result<()> {
        let ports: Vec<(u16, u16)> = PortMappingSpec::expand_all(&self.port)
            .map_err(|e| smolvm::Error::config("fork ports", e))?
            .into_iter()
            .map(|port| port.to_tuple())
            .collect();
        // Parse per-fork secret refs (TrustedLocal — host env/absolute file);
        // they merge into the clone's secret_refs and resolve fresh per exec.
        let fork_secrets = parse_cli_secret_refs(&self.secret_env, &self.secret_file)?;
        let count = self.count.get();
        let wait_ready = forkpoint_timeout(count, self.wait_ready, self.hold, self.ready_timeout);
        if count > 1024 {
            return Err(smolvm::Error::config(
                "fork",
                "--count cannot exceed 1024 clones per batch",
            ));
        }
        if self.hold && self.forkable {
            return Err(smolvm::Error::config(
                "fork",
                "--hold cannot be combined with --forkable; pool slots are disposable leaves",
            ));
        }

        if count == 1 {
            let clone = match (self.clone, self.name_prefix) {
                (Some(clone), None) => clone,
                (None, Some(prefix)) => format!("{prefix}-0"),
                (Some(_), Some(_)) => {
                    return Err(smolvm::Error::config(
                        "fork",
                        "use either --name or --name-prefix, not both",
                    ));
                }
                (None, None) => {
                    return Err(smolvm::Error::config(
                        "fork",
                        "--name is required for one clone; use --name-prefix with --count for a batch",
                    ));
                }
            };
            let fork_env = render_indexed_fork_env(&self.env, 0, &clone, false, None);
            return vm_common::fork_vm(
                &self.golden,
                &clone,
                vm_common::ForkVmOptions {
                    clone_forkable: self.forkable,
                    pinned_ports: &ports,
                    share_weights: self.share_weights,
                    fork_env: &fork_env,
                    fork_secrets: &fork_secrets,
                    wait_ready,
                    hold: self.hold,
                },
            );
        }

        if self.clone.is_some() {
            return Err(smolvm::Error::config(
                "fork",
                "--name cannot be used with --count greater than 1; use --name-prefix",
            ));
        }
        let prefix = self.name_prefix.ok_or_else(|| {
            smolvm::Error::config(
                "fork",
                "--name-prefix is required with --count greater than 1",
            )
        })?;
        if self.forkable {
            return Err(smolvm::Error::config(
                "fork",
                "--forkable is not supported for batch clones",
            ));
        }
        if !ports.is_empty() {
            return Err(smolvm::Error::config(
                "fork",
                "pinned --port mappings are not supported for a batch; inherited ports are remapped automatically",
            ));
        }

        let batch = (!self.hold).then(|| ForkBatchIdentity {
            id: fork_batch_id(&self.golden, &prefix),
            size: count,
        });
        let clones: Vec<_> = (0..count)
            .map(|index| {
                let name = format!("{prefix}-{index}");
                let env = render_indexed_fork_env(&self.env, index, &name, true, batch.as_ref());
                (name, env)
            })
            .collect();
        vm_common::fork_vm_batch(
            &self.golden,
            &clones,
            self.share_weights,
            &fork_secrets,
            wait_ready,
            self.parallel.get() as usize,
            self.hold,
        )
    }
}

/// Assign job-specific parameters and release one held fork-pool slot.
#[derive(Args, Debug)]
pub struct ForkReleaseCmd {
    /// Held clone to assign and release.
    #[arg(short = 'n', long = "name", value_name = "NAME")]
    pub name: String,

    /// Assignment parameter (repeatable, KEY=VALUE). Values override matching
    /// parameters installed when the slot was provisioned.
    #[arg(short = 'e', long = "env", value_name = "KEY=VALUE")]
    pub env: Vec<String>,
}

impl ForkReleaseCmd {
    pub fn run(self) -> smolvm::Result<()> {
        let env = smolvm::util::parse_env_list(&self.env);
        vm_common::release_held_fork(&self.name, &env)
    }
}

fn render_indexed_fork_env(
    specs: &[String],
    index: u32,
    name: &str,
    include_identity: bool,
    batch: Option<&ForkBatchIdentity>,
) -> Vec<(String, String)> {
    let mut env = smolvm::util::parse_env_list(specs);
    for (_, value) in &mut env {
        *value = value
            .replace("{index}", &index.to_string())
            .replace("{name}", name);
    }
    if include_identity {
        env.retain(|(key, _)| {
            !matches!(
                key.as_str(),
                "SMOLVM_FORK_INDEX"
                    | "SMOLVM_FORK_NAME"
                    | "SMOLVM_FORK_BATCH_ID"
                    | "SMOLVM_FORK_BATCH_SIZE"
            )
        });
        env.push(("SMOLVM_FORK_INDEX".to_string(), index.to_string()));
        env.push(("SMOLVM_FORK_NAME".to_string(), name.to_string()));
        if let Some(batch) = batch {
            env.push(("SMOLVM_FORK_BATCH_ID".to_string(), batch.id.clone()));
            env.push(("SMOLVM_FORK_BATCH_SIZE".to_string(), batch.size.to_string()));
        }
    }
    env
}

#[derive(Debug)]
struct ForkBatchIdentity {
    id: String,
    size: u32,
}

fn fork_batch_id(golden: &str, prefix: &str) -> String {
    let created = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut digest = Sha256::new();
    digest.update(golden.as_bytes());
    digest.update([0]);
    digest.update(prefix.as_bytes());
    digest.update([0]);
    digest.update(std::process::id().to_le_bytes());
    digest.update(created.to_le_bytes());
    hex::encode(digest.finalize())[..32].to_string()
}

fn forkpoint_timeout(
    count: u32,
    explicitly_requested: bool,
    hold: bool,
    timeout: Duration,
) -> Option<Duration> {
    (count > 1 || explicitly_requested || hold).then_some(timeout)
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

    /// Also delete any clones forked from this machine. A fork base cannot be
    /// removed while its clones' disks depend on it; --cascade removes the
    /// clones first (children before the base). Implies no confirmation.
    #[arg(long)]
    pub cascade: bool,
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
                // Delete dependent clones too when requested, instead of
                // refusing on a fork base.
                cascade: self.cascade,
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
// EgressEvents Command
// ============================================================================

/// Show the machine's egress denials.
///
/// Lists outbound connects and sendtos the egress policy refused — the record
/// of what a confined workload tried and failed to reach. Empty for machines
/// without an egress policy, or with no denials.
#[derive(Args, Debug)]
pub struct EgressEventsCmd {
    /// Machine to inspect (default: "default")
    #[arg(short = 'n', long, value_name = "NAME")]
    pub name: Option<String>,

    /// Maximum number of events to show (newest kept)
    #[arg(long, default_value_t = 200)]
    pub limit: usize,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

impl EgressEventsCmd {
    pub fn run(self) -> smolvm::Result<()> {
        let name = self.name.as_deref().unwrap_or("default");
        let events = smolvm::agent::read_egress_denials(name, self.limit);
        // Write through the io API instead of println!: piping into a pager
        // that exits early (`| head`) closes stdout, and println! turns that
        // EPIPE into a panic. A closed pipe just means the reader is done.
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        let result = (|| -> std::io::Result<()> {
            use std::io::Write;
            if self.json {
                writeln!(
                    out,
                    "{}",
                    serde_json::to_string_pretty(&events).unwrap_or_default()
                )?;
                return Ok(());
            }
            if events.is_empty() {
                writeln!(out, "No egress denials recorded for '{name}'.")?;
                return Ok(());
            }
            writeln!(out, "{:<30} {:<9} DESTINATION", "TIMESTAMP", "OP")?;
            for e in &events {
                writeln!(out, "{:<30} {:<9} {}", e.timestamp, e.operation, e.dest)?;
            }
            Ok(())
        })();
        match result {
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
            Err(e) => Err(smolvm::Error::config("egress-events", e.to_string())),
            Ok(()) => Ok(()),
        }
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

    /// Add port mapping or one-to-one range
    #[arg(short = 'p', long = "port", value_parser = PortMappingSpec::parse, value_name = "PORT[-END]|HOST[-END]:GUEST[-END]")]
    pub port: Vec<PortMappingSpec>,

    /// Remove port mapping or one-to-one range
    #[arg(long, value_parser = PortMappingSpec::parse, value_name = "PORT[-END]|HOST[-END]:GUEST[-END]")]
    pub remove_port: Vec<PortMappingSpec>,

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

    /// Enable Rosetta 2 for x86_64 binary translation
    #[arg(long)]
    pub rosetta: bool,

    /// Disable Rosetta 2
    #[arg(long, conflicts_with = "rosetta")]
    pub no_rosetta: bool,

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
        let add_ports = PortMappingSpec::expand_all(&self.port)
            .map_err(|e| smolvm::Error::config("update ports", e))?;
        let remove_ports = PortMappingSpec::expand_all(&self.remove_port)
            .map_err(|e| smolvm::Error::config("update remove ports", e))?;

        // Validate no duplicate host ports after proposed changes
        {
            let mut final_ports: Vec<PortMapping> = record
                .ports
                .iter()
                .filter(|&&(h, g)| !remove_ports.iter().any(|rm| rm.host == h && rm.guest == g))
                .map(|&(h, g)| PortMapping::new(h, g))
                .collect();
            for p in &add_ports {
                if !final_ports
                    .iter()
                    .any(|existing| existing.host == p.host && existing.guest == p.guest)
                {
                    final_ports.push(*p);
                }
            }
            if final_ports.len() > MAX_PORT_MAPPINGS {
                return Err(smolvm::Error::config(
                    "update",
                    format!(
                        "port mappings expand to {} entries; the maximum per machine is {MAX_PORT_MAPPINGS}",
                        final_ports.len()
                    ),
                ));
            }
            PortMapping::check_duplicates(&final_ports)
                .map_err(|e| smolvm::Error::config("update", e))?;
        }

        // Validate no duplicate guest mount targets after proposed changes. The
        // merge below only skips an exact (source,target) re-add, so a new mount
        // whose guest target collides with a DIFFERENT existing source would
        // otherwise leave two virtiofs mounts at one guest path — the ambiguous
        // config create-time validation rejects. Mirror the port check above by
        // computing the final mount set exactly as the DB closure does, then
        // rejecting duplicate targets.
        {
            let mut final_mounts: Vec<(String, String, bool)> = record.mounts.clone();
            for rm in &self.remove_volume {
                let canonical_rm = if let Some((rm_src, rm_tgt)) = rm.split_once(':') {
                    let resolved = std::fs::canonicalize(rm_src)
                        .unwrap_or_else(|_| std::path::PathBuf::from(rm_src));
                    format!("{}:{}", resolved.display(), rm_tgt)
                } else {
                    rm.clone()
                };
                final_mounts.retain(|(src, tgt, _)| {
                    let spec = format!("{}:{}", src, tgt);
                    spec != canonical_rm && spec != *rm
                });
            }
            for m in &new_mounts {
                let tuple = m.to_storage_tuple();
                if !final_mounts
                    .iter()
                    .any(|(s, t, _)| *s == tuple.0 && *t == tuple.1)
                {
                    final_mounts.push(tuple);
                }
            }
            let mut seen = std::collections::HashSet::new();
            for (_, tgt, _) in &final_mounts {
                if !seen.insert(tgt.clone()) {
                    return Err(smolvm::Error::config(
                        "update",
                        format!("duplicate mount target: {tgt} is specified more than once"),
                    ));
                }
            }
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
            for rm in &remove_ports {
                let before = r.ports.len();
                r.ports.retain(|&(h, g)| h != rm.host || g != rm.guest);
                if r.ports.len() < before {
                    changes.push(format!("  removed port: {}:{}", rm.host, rm.guest));
                }
            }
            for p in &add_ports {
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
            if self.rosetta {
                changes.push("  rosetta: enabled".to_string());
                r.rosetta = Some(true);
            }
            if self.no_rosetta {
                changes.push("  rosetta: disabled".to_string());
                r.rosetta = Some(false);
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

    /// Set the file's mode on upload (octal, e.g. 644)
    #[arg(long, value_name = "OCTAL")]
    pub mode: Option<String>,

    /// Set the file's owner uid on upload (default: root)
    #[arg(long, value_name = "UID")]
    pub uid: Option<u32>,

    /// Set the file's owner gid on upload (default: root)
    #[arg(long, value_name = "GID")]
    pub gid: Option<u32>,
}

/// Parse a chmod-style octal mode ("644", "0755", "0o600").
fn parse_octal_mode(s: &str) -> smolvm::Result<u32> {
    let digits = s.trim_start_matches("0o");
    u32::from_str_radix(digits, 8)
        .ok()
        .filter(|m| *m <= 0o7777)
        .ok_or_else(|| {
            smolvm::Error::config(
                "cp",
                format!("invalid octal mode '{s}' (expected e.g. 644)"),
            )
        })
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

        if !is_upload && (self.mode.is_some() || self.uid.is_some() || self.gid.is_some()) {
            return Err(smolvm::Error::config(
                "cp",
                "--mode/--uid/--gid apply to uploads only (host -> machine)",
            ));
        }

        let (manager, mut client) =
            vm_common::ensure_running_and_connect(&Some(machine_name.clone()))?;
        // Detach so the VM keeps running after cp exits.
        manager.detach();

        // For image-based VMs, ensure the persistent container overlay is
        // mounted so cp targets the container filesystem (not the VM rootfs).
        // prepare_overlay is idempotent: reuses if mounted, remounts if upper
        // exists, creates fresh otherwise.
        if let Some(record) = smolvm::db::SmolvmDb::open()
            .ok()
            .and_then(|db| db.get_vm(&machine_name).ok().flatten())
        {
            if let Some(image) = record.image.as_ref() {
                let owner = persistent_overlay_owner_for_record(&machine_name, Some(&record));
                let overlay_id = format!("persistent-{owner}");
                client.prepare_overlay(image, &overlay_id)?;
            }
        }

        if is_upload {
            let meta = smolvm::agent::FileWriteMeta {
                mode: self.mode.as_deref().map(parse_octal_mode).transpose()?,
                uid: self.uid,
                gid: self.gid,
            };
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
            client.write_file_from_reader_with_progress(&guest_path, file, size, meta, |sent| {
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
            vm_common::start_vm_named(
                &name,
                None,
                None,
                /* from_snapshot */ false,
                vm_common::ForkLaunch::default(),
            )?;
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
                        &name,
                        None,
                        None,
                        /* from_snapshot */ false,
                        vm_common::ForkLaunch::default(),
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
