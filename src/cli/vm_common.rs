//! Shared helpers for machine CLI commands.
//!
//! The `machine` subcommand exposes lifecycle commands
//! (create, start, stop, delete, ls). This module provides the common
//! implementations used by those commands.

use crate::cli::{format_pid_suffix, truncate};
use smolvm::agent::{vm_data_dir, AgentManager};
use smolvm::config::{RecordState, SmolvmConfig, VmRecord};
use smolvm::data::network::PortMapping;
use smolvm::data::resources::{DEFAULT_MICROVM_CPU_COUNT, DEFAULT_MICROVM_MEMORY_MIB};
use smolvm::data::storage::HostMount;
use smolvm::data::validate_vm_name;
use smolvm::db::SmolvmDb;
use smolvm::network::NetworkBackend;
use smolvm::storage::{DEFAULT_OVERLAY_SIZE_GIB, DEFAULT_STORAGE_SIZE_GIB};
use std::io::Write;

// ============================================================================
// Shared helpers
// ============================================================================

/// Resolve an optional VM name: if no name is given and a VM named "default"
/// exists in the config database, return `Some("default")` so callers route
/// through the named-VM code path (which loads config, init commands, network
/// settings, etc.). Otherwise returns the input unchanged.
pub fn resolve_vm_name(name: Option<String>) -> smolvm::Result<Option<String>> {
    if name.is_some() {
        return Ok(name);
    }
    // Use direct DB lookup instead of SmolvmConfig::load() to avoid
    // loading all config + all VMs just to check if "default" exists.
    let db = SmolvmDb::open()?;
    if db.get_vm("default")?.is_some() {
        Ok(Some("default".to_string()))
    } else {
        Ok(None)
    }
}

/// Get the agent manager for an optional name (default if `None`).
///
/// When no name is given, uses `AgentManager::new_default()` which is
/// canonicalized to `for_vm("default")` — same socket/PID/storage paths
/// regardless of whether the caller specifies a name or not.
pub fn get_vm_manager(name: &Option<String>) -> smolvm::Result<AgentManager> {
    if let Some(name) = name {
        AgentManager::for_vm(name)
    } else {
        AgentManager::new_default()
    }
}

/// Return the display label for an optional VM name.
pub fn vm_label(name: &Option<String>) -> String {
    name.as_deref().unwrap_or("default").to_string()
}

/// Ensure a VM is running and return a connected client.
///
/// This is the common pattern used by exec commands in the machine subcommand.
/// It resolves the VM manager, checks connectivity, and establishes a client connection.
pub fn ensure_running_and_connect(
    name: &Option<String>,
) -> smolvm::Result<(AgentManager, smolvm::agent::AgentClient)> {
    let manager = get_vm_manager(name)?;
    let label = vm_label(name);
    let start_hint = match name {
        Some(name) => format!("smolvm machine start --name {}", name),
        None => "smolvm machine start".to_string(),
    };

    if manager.try_connect_existing().is_none() {
        // Best-effort reconcile: if we can't connect to the agent
        // but the libkrun PID is alive, we're in the bug 2 zombie
        // state — record says "running" but agent is dead. Mark
        // the record `Unreachable` so subsequent `machine list`
        // calls reflect truth without re-pinging. DB write is
        // best-effort: we ignore failures so a bad DB doesn't mask
        // the real "can't connect" error the user is about to see.
        mark_unreachable_if_zombie(&label);

        return Err(smolvm::Error::agent(
            "connect",
            format!(
                "machine '{}' is not running. Use '{}' first.",
                label, start_hint
            ),
        ));
    }

    let client = smolvm::agent::AgentClient::connect_with_retry(manager.vsock_socket())?;
    Ok((manager, client))
}

/// CLI wrapper around `state_probe::recover_if_unreachable` that
/// prints a one-line notice when recovery actually runs. The shared
/// helper is silent (the HTTP API doesn't have a stdout to write
/// to); CLI callers want the operator to see the zombie teardown.
fn cli_recover_if_unreachable(name: &str) {
    // Peek at the record before recovery so we can show the PID in
    // the notice. Losing the PID after recovery is fine — the DB
    // gets cleared — but we want the operator to know *which*
    // process got killed.
    let pid_for_notice = SmolvmDb::open()
        .ok()
        .and_then(|db| db.get_vm(name).ok().flatten())
        .and_then(|r| r.pid);

    if smolvm::agent::state_probe::recover_if_unreachable(name) {
        println!(
            "Machine '{}' is unreachable (PID {} alive but agent unresponsive); \
             cleaning up.",
            name,
            pid_for_notice.unwrap_or(0)
        );
    }
}

/// If the VM record says `Running` and the libkrun PID is alive but
/// the agent isn't responding, transition the record to
/// `Unreachable`. Caller invokes this on `ensure_running_and_connect`
/// failure so the next `machine list` is honest.
///
/// All errors are swallowed (logged at debug level) — this is a
/// best-effort cleanup, not a critical path.
fn mark_unreachable_if_zombie(name: &str) {
    let Ok(mut config) = SmolvmConfig::load() else {
        return;
    };
    let Some(record) = config.get_vm(name) else {
        return;
    };
    // Only transition Running → Unreachable. Stopped/Created/Failed
    // are already accurate.
    if record.state != RecordState::Running {
        return;
    }
    if !record.is_process_alive() {
        // PID dead → next list will see Stopped without our help.
        return;
    }
    // PID alive + ensure_running_and_connect failed → zombie. Persist
    // the new state. Update via the closure-based helper if available;
    // fall back to nothing on failure (best-effort).
    let _ = config.update_vm(name, |r| {
        r.state = RecordState::Unreachable;
    });
    tracing::debug!(
        machine = %name,
        "marked machine Unreachable: PID alive but agent not responding"
    );
}

/// Print command output and exit with the given code.
///
/// Prints stdout to stdout, stderr to stderr, detaches the manager
/// (keeping the VM running), and exits the process.
pub fn print_output_and_exit(
    manager: &AgentManager,
    exit_code: i32,
    stdout: &[u8],
    stderr: &[u8],
) -> ! {
    // write_all on raw bytes preserves binary output (image bytes, tarballs,
    // etc.) that print!("{}", ...) would corrupt or refuse to write.
    if !stdout.is_empty() {
        let _ = std::io::stdout().write_all(stdout);
    }
    if !stderr.is_empty() {
        let _ = std::io::stderr().write_all(stderr);
    }
    crate::cli::flush_output();
    manager.detach();
    std::process::exit(exit_code);
}

// ============================================================================
// Init runner
// ============================================================================

/// Run a machine's `init` commands list against the agent.
///
/// Branches on `image`:
///
/// - `Some(img)`: each command runs *inside* the container's rootfs via
///   `client.run_non_interactive`. `record_mounts` are bind-mounted into
///   the container (so `[dev].volumes` like `.:/app` are visible to init,
///   not just to later `machine exec` calls). `overlay_id` ensures
///   filesystem changes (e.g. `pacman -Syu` package installs) persist
///   across this init invocation and into future `machine exec` calls —
///   matches the convention `machine exec` already uses
///   (`src/cli/machine.rs:750`).
///
/// - `None`: each command runs in the agent's bare VM filesystem via
///   `client.vm_exec`. There's no container, so `record_mounts` and
///   `overlay_id` are unused on this branch.
///
/// On the first non-zero exit, returns an error containing the command
/// index, exit code, and any stdout/stderr the command produced.
/// **Both** streams are surfaced because package managers often write
/// the actual failure reason to stdout (`pacman`'s "target not found",
/// `apt`'s resolver diagnostics) — surfacing only stderr would leave
/// the operator with an exit code and no explanation. The caller is
/// responsible for stopping the VM if appropriate.
pub(crate) fn run_init_commands(
    client: &mut smolvm::agent::AgentClient,
    init: &[String],
    image: Option<&str>,
    env: &[(String, String)],
    workdir: Option<&str>,
    record_mounts: &[(String, String, bool)],
    overlay_id: &str,
) -> smolvm::Result<()> {
    if init.is_empty() {
        return Ok(());
    }
    println!("Running {} init command(s)...", init.len());
    for (i, cmd) in init.iter().enumerate() {
        let (exit_code, stdout, stderr) = if let Some(image) = image {
            let config = build_init_run_config(image, cmd, env, workdir, record_mounts, overlay_id);
            client.run_non_interactive(config)?
        } else {
            client.vm_exec(
                init_argv(cmd),
                env.to_vec(),
                workdir.map(|s| s.to_string()),
                None,
            )?
        };
        if exit_code != 0 {
            // Init output is generally text — lossy conversion is fine for
            // error messages. Binary init output isn't a real use case.
            return Err(smolvm::Error::agent(
                "init",
                format_init_failure(
                    i,
                    exit_code,
                    &String::from_utf8_lossy(&stdout),
                    &String::from_utf8_lossy(&stderr),
                ),
            ));
        }
    }
    Ok(())
}

/// Wrap a single init command line in `sh -c` argv form. Init commands
/// are user-supplied shell snippets (e.g. `"pacman -Sy && pacman -S git"`)
/// — we intentionally route them through `sh` so operators can use shell
/// features (`&&`, `|`, env expansion) without quoting gymnastics.
fn init_argv(cmd: &str) -> Vec<String> {
    vec!["sh".into(), "-c".into(), cmd.to_string()]
}

/// Build the `RunConfig` an image-based init command runs under.
///
/// Pure function so the *shape* of the request (overlay ID, mount tags,
/// env, workdir, the `sh -c` wrap) can be unit-tested without mocking
/// `AgentClient`. Any of these silently regressing — e.g. mounts not
/// flowing through, or overlay ID drifting from the machine name —
/// would leave init working but `machine exec` no longer seeing init's
/// effects, exactly the class of bug that would lurk for months.
fn build_init_run_config(
    image: &str,
    cmd: &str,
    env: &[(String, String)],
    workdir: Option<&str>,
    record_mounts: &[(String, String, bool)],
    overlay_id: &str,
) -> smolvm::agent::RunConfig {
    let mounts = crate::cli::parsers::record_mounts_to_runconfig_bindings(record_mounts);
    smolvm::agent::RunConfig::new(image, init_argv(cmd))
        .with_env(env.to_vec())
        .with_workdir(workdir.map(|s| s.to_string()))
        .with_mounts(mounts)
        .with_persistent_overlay(Some(overlay_id.to_string()))
}

/// Compose the user-facing init-failure message. Pure function — split
/// out for testability and so the formatting choice (which stream goes
/// in which order, separators, trimming) is in one place.
fn format_init_failure(index: usize, exit_code: i32, stdout: &str, stderr: &str) -> String {
    let so = stdout.trim();
    let se = stderr.trim();
    let suffix = match (so, se) {
        ("", "") => String::new(),
        (so, "") => format!(": {}", so),
        ("", se) => format!(": {}", se),
        // Both populated: keep stderr first (canonical error channel)
        // but include stdout because `pacman`/`apt`/`dnf` often put the
        // real reason there. Single line, semicolon-separated, so the
        // message stays grep-friendly.
        (so, se) => format!(": {}; stdout: {}", se, so),
    };
    format!("init[{}] failed (exit {}){}", index, exit_code, suffix)
}

// ============================================================================
// Create
// ============================================================================

/// Parameters for [`create_vm`].
pub struct CreateVmParams {
    pub name: String,
    pub image: Option<String>,
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
    pub cpus: u8,
    pub mem: u32,
    pub volume: Vec<String>,
    pub port: Vec<PortMapping>,
    pub net: bool,
    pub network_backend: Option<NetworkBackend>,
    pub init: Vec<String>,
    pub env: Vec<String>,
    pub workdir: Option<String>,
    pub storage_gb: Option<u64>,
    pub overlay_gb: Option<u64>,
    pub allowed_cidrs: Option<Vec<String>>,
    pub restart_policy: Option<smolvm::config::RestartPolicy>,
    pub restart_max_retries: Option<u32>,
    pub restart_max_backoff_secs: Option<u64>,
    pub health_cmd: Option<Vec<String>>,
    pub health_interval_secs: Option<u64>,
    pub health_timeout_secs: Option<u64>,
    pub health_retries: Option<u32>,
    pub health_startup_grace_secs: Option<u64>,
    pub ssh_agent: bool,
    /// Hostnames for DNS filtering (from --allow-host / [network].allow_hosts).
    pub dns_filter_hosts: Option<Vec<String>>,
    /// Absolute path to .smolmachine sidecar (for machines created with --from).
    pub source_smolmachine: Option<String>,
}

/// Create a named machine configuration (does not start it).
pub fn create_vm(params: CreateVmParams) -> smolvm::Result<()> {
    // Validate name before touching the database. The on-disk layout uses
    // a hash-derived directory (see `vm_data_dir`), so the name itself has
    // no impact on socket path length — only character sanity + a generous
    // length cap are needed here.
    validate_vm_name(&params.name, "machine name")
        .map_err(|reason| smolvm::Error::config("create machine", reason))?;

    let mut config = SmolvmConfig::load()?;

    // Check if already exists
    if config.get_vm(&params.name).is_some() {
        return Err(smolvm::Error::config(
            "create machine",
            format!("machine '{}' already exists", params.name),
        ));
    }

    // Parse and validate volume mounts
    let mounts = HostMount::parse(&params.volume)?
        .into_iter()
        .map(|m| m.to_storage_tuple())
        .collect();

    // Convert port mappings to tuple format for storage
    let ports = PortMapping::to_tuples(&params.port);

    // Parse environment variables for init
    let env = smolvm::util::parse_env_list(&params.env);

    // Create record with restart policy if configured
    let restart = smolvm::config::RestartConfig {
        policy: params
            .restart_policy
            .unwrap_or(smolvm::config::RestartPolicy::Never),
        max_retries: params.restart_max_retries.unwrap_or(0),
        max_backoff_secs: params.restart_max_backoff_secs.unwrap_or(0),
        ..Default::default()
    };
    let mut record = VmRecord::new_with_restart(
        params.name.clone(),
        params.cpus,
        params.mem,
        mounts,
        ports,
        params.net,
        restart,
    );
    record.init = params.init.clone();
    record.env = env;
    record.workdir = params.workdir.clone();
    record.storage_gb = params.storage_gb;
    record.overlay_gb = params.overlay_gb;
    record.allowed_cidrs = params.allowed_cidrs.clone();
    record.network_backend = params.network_backend;
    record.image = params.image.clone();
    record.entrypoint = params.entrypoint.clone();
    record.cmd = params.cmd.clone();
    record.health_cmd = params.health_cmd.clone();
    record.health_interval_secs = params.health_interval_secs;
    record.health_timeout_secs = params.health_timeout_secs;
    record.health_retries = params.health_retries;
    record.health_startup_grace_secs = params.health_startup_grace_secs;
    record.ssh_agent = params.ssh_agent;
    record.dns_filter_hosts = params.dns_filter_hosts.clone();
    record.source_smolmachine = params.source_smolmachine.clone();

    // Store in config (persisted immediately to database)
    config.insert_vm(params.name.clone(), record)?;

    println!("Created machine: {}", params.name);
    println!("  CPUs: {}, Memory: {} MiB", params.cpus, params.mem);
    if !params.volume.is_empty() {
        println!("  Mounts: {}", params.volume.len());
    }
    if !params.port.is_empty() {
        println!("  Ports: {}", params.port.len());
    }
    if !params.init.is_empty() {
        println!("  Init commands: {}", params.init.len());
    }
    println!(
        "\nUse 'smolvm machine start --name {}' to start the machine",
        params.name
    );
    println!(
        "Then use 'smolvm machine exec --name {} -- <command>' to run commands",
        params.name
    );

    Ok(())
}

// ============================================================================
// Start
// ============================================================================

/// Start a named machine that has a config record.
///
/// Uses direct DB operations instead of SmolvmConfig::load() to avoid
/// loading all config settings and all VM records. Only reads the single
/// named record (1 DB cycle) and updates it after start (1 DB cycle).
pub fn start_vm_named(name: &str) -> smolvm::Result<()> {
    use smolvm::Error;

    // Direct DB lookup — 1 read cycle instead of loading everything
    let db = SmolvmDb::open()?;
    let record = db.get_vm(name)?.ok_or_else(|| Error::vm_not_found(name))?;

    // Resolve via the shared probe (PID + vsock ping). The plain
    // `actual_state()` is PID-only and would treat a zombie VMM
    // (alive process, dead agent) as Running — exactly the bug 2
    // case where `start` later said "already running" but every
    // `exec` failed.
    match smolvm::agent::state_probe::resolve_state(name, &record) {
        RecordState::Running => {
            let pid_suffix = format_pid_suffix(record.pid);
            println!("Machine '{}' already running{}", name, pid_suffix);
            return Ok(());
        }
        RecordState::Unreachable => {
            // Zombie VMM: kill it, clear the record, fall through to
            // a clean fresh start.
            cli_recover_if_unreachable(name);
        }
        RecordState::Stopped | RecordState::Created | RecordState::Failed => {
            // Normal start path.
        }
    }

    let mounts = record.host_mounts();
    let ports = record.port_mappings();
    let resources = record.vm_resources();

    // Check for host port conflicts with other running VMs.
    if !ports.is_empty() {
        check_port_conflicts(name, &ports, &db)?;
    }

    // Start agent VM
    let manager = AgentManager::for_vm_with_sizes(name, record.storage_gb, record.overlay_gb)
        .map_err(|e| Error::agent("create agent manager", e.to_string()))?;

    let mount_info = if !mounts.is_empty() {
        format!(" with {} mount(s)", mounts.len())
    } else {
        String::new()
    };
    let port_info = if !ports.is_empty() {
        format!(" and {} port mapping(s)", ports.len())
    } else {
        String::new()
    };
    println!("Starting machine '{}'{}{}...", name, mount_info, port_info);

    // Resolve SSH agent socket path if enabled
    let ssh_agent_socket = if record.ssh_agent {
        match std::env::var("SSH_AUTH_SOCK") {
            Ok(path) => Some(std::path::PathBuf::from(path)),
            Err(_) => {
                return Err(Error::config(
                    "ssh-agent",
                    "SSH_AUTH_SOCK is not set. Start an SSH agent with: eval $(ssh-agent) && ssh-add",
                ));
            }
        }
    } else {
        None
    };

    let mut features = smolvm::agent::LaunchFeatures {
        ssh_agent_socket,
        dns_filter_hosts: record.dns_filter_hosts.clone(),
        packed_layers_dir: None,
        extra_disks: Vec::new(),
    };

    // If machine was created from .smolmachine, extract layers to cache and
    // mount via virtiofs so the agent uses pre-extracted layers instead of
    // pulling from a registry.
    if let Some(ref sidecar_path) = record.source_smolmachine {
        let sidecar = std::path::Path::new(sidecar_path);
        if !sidecar.exists() {
            return Err(Error::agent(
                "start machine",
                format!(
                    "source .smolmachine not found: {}\nThe file may have been moved or deleted.",
                    sidecar_path
                ),
            ));
        }
        let footer = smolvm_pack::packer::read_footer_from_sidecar(sidecar)
            .map_err(|e| Error::agent("read sidecar footer", e.to_string()))?;
        let cache_dir = smolvm_pack::extract::get_cache_dir(footer.checksum)
            .map_err(|e| Error::agent("get cache dir", e.to_string()))?;
        smolvm_pack::extract::extract_sidecar(sidecar, &cache_dir, &footer, false, false)
            .map_err(|e| Error::agent("extract sidecar", e.to_string()))?;
        let layers_lease = smolvm_pack::extract::acquire_layers_lease(&cache_dir, false)
            .map_err(|e| Error::agent("acquire layers lease", e.to_string()))?;
        features.packed_layers_dir = Some(layers_lease.path.clone());
        // Leak the lease — the volume must stay mounted while the VM runs.
        // Cleanup happens via `pack prune` or on next `machine start`.
        std::mem::forget(layers_lease);
    }

    let _ = manager
        .ensure_running_with_full_config(mounts, ports, resources, features)
        .map_err(|e| Error::agent("start machine", e.to_string()))?;

    // Get PID immediately (cheap) and print output before DB write
    let pid = manager.child_pid();

    // Install SIGINT guard so Ctrl+C during init/pull kills the VM process
    // instead of orphaning it. Disarmed before detach.
    let _sigint_guard = pid.map(smolvm::process::SigintGuard::new);

    // Pull image first (if configured), then run init. Init can
    // target the container's rootfs (via `run_non_interactive`) when
    // an image is set, so the container layers must be in place
    // before init runs — otherwise any init command referencing the
    // image's filesystem (package managers, distro-specific paths)
    // would hit the bare Alpine agent and fail with "not found".
    let mut client = smolvm::agent::AgentClient::connect_with_retry(manager.vsock_socket())?;

    if record.source_smolmachine.is_some() {
        // Layers already mounted via virtiofs — no pull needed.
    } else if let Some(ref image) = record.image {
        println!("Pulling {}...", image);
        let _image_info = crate::cli::pull_with_progress(&mut client, image, None)?;
    }

    // Run init commands if configured (before reporting success).
    // `run_init_commands` branches on image: container path for
    // image-based VMs, bare-agent path for plain VMs.
    if let Err(e) = run_init_commands(
        &mut client,
        &record.init,
        record.image.as_deref(),
        &record.env,
        record.workdir.as_deref(),
        &record.mounts,
        name,
    ) {
        if let Err(stop_err) = manager.stop() {
            tracing::warn!(error = %stop_err, "failed to stop machine after init failure");
        }
        return Err(e);
    }

    if record.image.is_some() {
        // Image-based machine: VM is running, image pulled and cached,
        // init done. Sits idle until `machine exec` is called.
        println!("Machine '{}' running (PID: {})", name, pid.unwrap_or(0));
    } else {
        // No image — bare VM mode. Run entrypoint+cmd if configured.
        let mut bare_cmd = record.entrypoint.clone();
        bare_cmd.extend(record.cmd.clone());
        if !bare_cmd.is_empty() {
            let env = record.env.clone();
            let (exit_code, stdout, stderr) =
                client.vm_exec(bare_cmd, env, record.workdir.clone(), None)?;
            if !stdout.is_empty() {
                let _ = std::io::stdout().write_all(&stdout);
            }
            if !stderr.is_empty() {
                let _ = std::io::stderr().write_all(&stderr);
            }
            if exit_code != 0 {
                eprintln!("workload exited with code {}", exit_code);
            }
        }
        println!("Machine '{}' running (PID: {})", name, pid.unwrap_or(0));
    }

    // Persist running state after output — 1 write cycle (not on critical path)
    let pid_start_time = pid.and_then(smolvm::process::process_start_time);
    if let Err(e) = db.update_vm(name, |r| {
        r.state = RecordState::Running;
        r.pid = pid;
        r.pid_start_time = pid_start_time;
    }) {
        tracing::warn!(error = %e, vm = %name, "failed to persist running state");
    }

    // Keep VM running (persistent)
    manager.detach();
    Ok(())
}

/// Persist the "default" VM as running in the database.
///
/// Creates the record if it doesn't exist, then updates state to Running
/// with the current PID and optional config overrides (cpus, mem, etc.).
pub fn persist_default_running(
    config: &mut SmolvmConfig,
    pid: Option<i32>,
    overrides: Option<DefaultVmOverrides>,
) {
    if config.get_vm("default").is_none() {
        let record = VmRecord::new(
            "default".to_string(),
            DEFAULT_MICROVM_CPU_COUNT,
            DEFAULT_MICROVM_MEMORY_MIB,
            vec![],
            vec![],
            false,
        );
        if let Err(e) = config.insert_vm("default".to_string(), record) {
            tracing::warn!(error = %e, "failed to insert default VM record");
            return;
        }
    }
    let pid_start_time = pid.and_then(smolvm::process::process_start_time);
    if config
        .update_vm("default", |r| {
            r.state = RecordState::Running;
            r.pid = pid;
            r.pid_start_time = pid_start_time;
            if let Some(ref o) = overrides {
                r.cpus = o.cpus;
                r.mem = o.mem;
                r.mounts = o.mounts.clone();
                r.ports = o.ports.clone();
                r.network = o.network;
                r.network_backend = o.network_backend;
                r.storage_gb = o.storage_gb;
                r.overlay_gb = o.overlay_gb;
                r.allowed_cidrs = o.allowed_cidrs.clone();
                r.init = o.init.clone();
                r.env = o.env.clone();
                r.workdir = o.workdir.clone();
                r.image = o.image.clone();
                r.entrypoint = o.entrypoint.clone();
                r.cmd = o.cmd.clone();
                r.ssh_agent = o.ssh_agent;
                r.dns_filter_hosts = o.dns_filter_hosts.clone();
            }
        })
        .is_none()
    {
        tracing::warn!("failed to update default VM record (record missing after insert)");
    }
}

/// Config overrides for the default VM record.
pub struct DefaultVmOverrides {
    pub cpus: u8,
    pub mem: u32,
    pub mounts: Vec<(String, String, bool)>,
    pub ports: Vec<(u16, u16)>,
    pub network: bool,
    pub network_backend: Option<NetworkBackend>,
    pub storage_gb: Option<u64>,
    pub overlay_gb: Option<u64>,
    pub allowed_cidrs: Option<Vec<String>>,
    pub init: Vec<String>,
    pub env: Vec<(String, String)>,
    pub workdir: Option<String>,
    pub image: Option<String>,
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
    pub ssh_agent: bool,
    pub dns_filter_hosts: Option<Vec<String>>,
}

/// Check if any running VM already binds to the same host ports.
///
/// Iterates all VM records, skipping the current VM (`self_name`), and checks
/// for host port overlaps with running VMs. This prevents silent port binding
/// failures where two VMs claim the same host port but only one succeeds.
fn check_port_conflicts(
    self_name: &str,
    ports: &[PortMapping],
    db: &SmolvmDb,
) -> smolvm::Result<()> {
    let host_ports: std::collections::HashSet<u16> = ports.iter().map(|p| p.host).collect();
    if host_ports.is_empty() {
        return Ok(());
    }

    let all_vms = db.list_vms()?;
    for (name, record) in &all_vms {
        if name == self_name {
            continue;
        }
        // Only check running VMs (PID-based quick check).
        if record.actual_state() != smolvm::config::RecordState::Running {
            continue;
        }
        for (host, _guest) in &record.ports {
            if host_ports.contains(host) {
                return Err(smolvm::Error::config(
                    "start machine",
                    format!(
                        "host port {} is already in use by running machine '{}'",
                        host, name
                    ),
                ));
            }
        }
    }
    Ok(())
}

/// Start the default machine.
pub fn start_vm_default() -> smolvm::Result<()> {
    let manager = AgentManager::new_default()?;

    if manager.try_connect_existing().is_some() {
        let pid_suffix = format_pid_suffix(manager.child_pid());
        println!("Machine 'default' already running{}", pid_suffix);
        manager.detach();
        return Ok(());
    }

    // try_connect_existing failed — could be "really stopped" or
    // "zombie VMM with dead agent". Recover the zombie case before
    // starting fresh; no-op otherwise.
    cli_recover_if_unreachable("default");

    println!("Starting machine 'default'...");
    manager.ensure_running()?;

    let mut config = SmolvmConfig::load()?;
    persist_default_running(&mut config, manager.child_pid(), None);

    // Pull image (if persisted via `machine run -d -s`) before running
    // init, then run init through the shared runner — same fix as
    // `start_vm_named`. Both paths must agree so an init that works on
    // a named machine also works on the default one.
    let record = config.get_vm("default").cloned();

    if let Some(record) = record {
        let needs_pull = record.image.is_some();
        let needs_init = !record.init.is_empty();

        if needs_pull || needs_init {
            let mut client =
                smolvm::agent::AgentClient::connect_with_retry(manager.vsock_socket())?;

            if let Some(ref image) = record.image {
                println!("Pulling {}...", image);
                let _ = crate::cli::pull_with_progress(&mut client, image, None)?;
            }

            if let Err(e) = run_init_commands(
                &mut client,
                &record.init,
                record.image.as_deref(),
                &record.env,
                record.workdir.as_deref(),
                &record.mounts,
                "default",
            ) {
                if let Err(stop_err) = manager.stop() {
                    tracing::warn!(error = %stop_err, "failed to stop machine after init failure");
                }
                return Err(e);
            }
        }
    }

    println!(
        "Machine 'default' running (PID: {})",
        manager.child_pid().unwrap_or(0)
    );

    manager.detach();
    Ok(())
}

// ============================================================================
// Stop
// ============================================================================

/// Stop a named machine that has a config record (or fall back to
/// agent-only stop if the name is not in config).
pub fn stop_vm_named(name: &str) -> smolvm::Result<()> {
    let mut config = SmolvmConfig::load()?;

    // Check config for the named VM
    let record = match config.get_vm(name) {
        Some(r) => r.clone(),
        None => {
            // Not in config — try to stop a running VM with this name directly
            let manager = AgentManager::for_vm(name)?;
            if manager.try_connect_existing().is_some() {
                println!("Stopping machine '{}'...", name);
                manager.stop()?;
                println!("Machine '{}' stopped", name);
            } else {
                println!("Machine '{}' not found or not running", name);
            }
            return Ok(());
        }
    };

    // Resolve via the shared probe so an `Unreachable` VM (live PID,
    // dead agent) is correctly stopped instead of skipped with a
    // misleading "not running" message. `cli_recover_if_unreachable`
    // handles that case by killing the zombie VMM; after it runs the
    // record is `Stopped` and `manager.stop()` becomes a no-op.
    let resolved = smolvm::agent::state_probe::resolve_state(name, &record);
    match resolved {
        RecordState::Unreachable => {
            cli_recover_if_unreachable(name);
            println!("Stopped machine: {}", name);
            return Ok(());
        }
        RecordState::Running => {
            // fall through to the normal stop path
        }
        other => {
            println!("Machine '{}' is not running (state: {})", name, other);
            return Ok(());
        }
    }

    println!("Stopping machine '{}'...", name);

    let manager = AgentManager::for_vm(name)
        .map_err(|e| smolvm::Error::agent("create agent manager", e.to_string()))?;
    manager.stop()?;

    config.update_vm(name, |r| {
        r.state = RecordState::Stopped;
        r.pid = None;
        r.pid_start_time = None;
    });

    println!("Stopped machine: {}", name);
    Ok(())
}

/// Stop the default machine.
pub fn stop_vm_default() -> smolvm::Result<()> {
    let manager = AgentManager::new_default()?;

    // try_connect_existing sets internal state if agent is reachable;
    // stop() handles both responsive agents and orphans via PID file.
    manager.try_connect_existing();
    println!("Stopping machine 'default'...");
    manager.stop()?;

    // Update database record if it exists
    if let Ok(mut config) = SmolvmConfig::load() {
        config.update_vm("default", |r| {
            r.state = RecordState::Stopped;
            r.pid = None;
            r.pid_start_time = None;
        });
    }

    println!("Machine 'default' stopped");

    Ok(())
}

// ============================================================================
// Delete
// ============================================================================

/// Options for machine delete behavior.
pub struct DeleteVmOptions {
    /// If true, stop the VM before deleting when it is running.
    pub stop_if_running: bool,
}

/// Delete a named machine configuration.
pub fn delete_vm(name: &str, force: bool, options: DeleteVmOptions) -> smolvm::Result<()> {
    let mut config = SmolvmConfig::load()?;

    // Check if exists
    let record = config
        .get_vm(name)
        .ok_or_else(|| smolvm::Error::vm_not_found(name))?
        .clone();

    // Stop if running (machine run does this). Use the shared
    // resolver so an `Unreachable` VM (live PID, dead agent) is also
    // torn down — otherwise the record gets deleted while the zombie
    // libkrun process keeps running, orphaned forever.
    if options.stop_if_running {
        match smolvm::agent::state_probe::resolve_state(name, &record) {
            RecordState::Running => {
                if let Ok(manager) = AgentManager::for_vm(name) {
                    println!("Stopping machine '{}'...", name);
                    if let Err(e) = manager.stop() {
                        tracing::warn!(error = %e, "failed to stop machine");
                    }
                }
            }
            RecordState::Unreachable => {
                cli_recover_if_unreachable(name);
            }
            _ => {}
        }
    }

    // Confirm deletion unless --force
    if !force {
        eprint!("Delete machine '{}'? [y/N] ", name);
        let mut input = String::new();
        if std::io::stdin().read_line(&mut input).is_ok() {
            let input = input.trim().to_lowercase();
            if input != "y" && input != "yes" {
                println!("Cancelled");
                return Ok(());
            }
        } else {
            println!("Cancelled");
            return Ok(());
        }
    }

    // Remove from config (persists immediately to database)
    config.remove_vm(name);

    // If the machine was created from a .smolmachine sidecar, release the
    // case-sensitive volume (macOS hdiutil mount). The lease was intentionally
    // leaked with `std::mem::forget` at start time so the volume stayed
    // mounted while the VM ran. On delete we must detach it, otherwise
    // `rm -rf` of the pack cache fails with "Resource busy".
    if let Some(ref sidecar_path) = record.source_smolmachine {
        let sidecar = std::path::Path::new(sidecar_path);
        if sidecar.exists() {
            if let Ok(footer) = smolvm_pack::packer::read_footer_from_sidecar(sidecar) {
                if let Ok(cache_dir) = smolvm_pack::extract::get_cache_dir(footer.checksum) {
                    smolvm_pack::extract::force_detach_layers_volume(&cache_dir);
                }
            }
        }
    }

    let data_dir = vm_data_dir(name);
    if data_dir.exists() {
        println!("Cleaning up data directory for vm: {}", name);
        if let Err(e) = std::fs::remove_dir_all(&data_dir) {
            tracing::warn!(error = %e, "Failed to remove VM data directory: {}", data_dir.display());
        }
    }

    println!("Deleted machine: {}", name);
    Ok(())
}

// ============================================================================
// Status
// ============================================================================

/// Show status of a named or default machine.
///
/// The `extra` callback is invoked when the VM is running, allowing callers
/// to display additional information (e.g., machine lists containers).
pub fn status_vm<F>(name: &Option<String>, extra: F) -> smolvm::Result<()>
where
    F: FnOnce(&AgentManager),
{
    let manager = get_vm_manager(name)?;
    let label = vm_label(name);

    if manager.try_connect_existing().is_some() {
        let pid_suffix = crate::cli::format_pid_suffix(manager.child_pid());
        println!("Machine '{}': running{}", label, pid_suffix);
        extra(&manager);
        manager.detach();
    } else {
        println!("Machine '{}': not running", label);
    }

    Ok(())
}

// ============================================================================
// List
// ============================================================================

/// List all machines.
pub fn list_vms(verbose: bool, json: bool) -> smolvm::Result<()> {
    let config = SmolvmConfig::load()?;
    let vms: Vec<_> = config.list_vms().collect();

    let empty_label = "No machines found";

    if vms.is_empty() {
        if !json {
            println!("{}", empty_label);
        } else {
            println!("[]");
        }
        return Ok(());
    }

    if json {
        let json_vms: Vec<_> = vms
            .iter()
            .map(|(name, record)| {
                // Resolve via vsock probe so the JSON output reflects
                // truth (Unreachable vs Running) instead of trusting
                // the PID-only check that fooled bug 2 victims.
                let actual_state = smolvm::agent::state_probe::resolve_state(name, record);
                let mut obj = serde_json::json!({
                    "name": name,
                    "state": actual_state.to_string(),
                    "cpus": record.cpus,
                    "memory_mib": record.mem,
                    "pid": record.pid,
                    "mounts": record.mounts.len(),
                    "ports": record.ports.len(),
                    "created_at": record.created_at,
                    "storage_gb": record.storage_gb,
                    "overlay_gb": record.overlay_gb,
                    "image": record.image,
                    "entrypoint": record.entrypoint,
                    "cmd": record.cmd,
                    "ephemeral": record.ephemeral,
                });
                obj.as_object_mut()
                    .unwrap()
                    .insert("network".into(), serde_json::json!(record.network));
                obj
            })
            .collect();
        let json = serde_json::to_string_pretty(&json_vms)
            .map_err(|e| smolvm::Error::config("serialize json", e.to_string()))?;
        println!("{}", json);
    } else {
        println!(
            "{:<20} {:<12} {:>5} {:>10} {:>7} {:>7} {:>8} {:>8}",
            "NAME", "STATE", "CPUS", "MEMORY", "MOUNTS", "PORTS", "STORAGE", "OVERLAY"
        );
        println!("{}", "-".repeat(88));

        for (name, record) in vms {
            let actual_state = smolvm::agent::state_probe::resolve_state(name, record);
            let state_display = if record.ephemeral {
                format!("{} (eph)", actual_state)
            } else {
                actual_state.to_string()
            };
            let storage_gb = record.storage_gb.unwrap_or(DEFAULT_STORAGE_SIZE_GIB);
            let overlay_gb = record.overlay_gb.unwrap_or(DEFAULT_OVERLAY_SIZE_GIB);
            println!(
                "{:<20} {:<12} {:>5} {:>10} {:>7} {:>7} {:>8} {:>8}",
                truncate(name, 18),
                state_display,
                record.cpus,
                format!("{} MiB", record.mem),
                record.mounts.len(),
                record.ports.len(),
                format!("{} GiB", storage_gb),
                format!("{} GiB", overlay_gb),
            );

            if verbose {
                if let Some(pid) = record.pid {
                    println!("  PID: {}", pid);
                }
                for (host, guest, ro) in &record.mounts {
                    let ro_str = if *ro { " (ro)" } else { "" };
                    println!("  Mount: {} -> {}{}", host, guest, ro_str);
                }
                for (host, guest) in &record.ports {
                    println!("  Port: {} -> {}", host, guest);
                }
                if record.network {
                    println!("  Network: enabled");
                }
                for cmd in &record.init {
                    println!("  Init: {}", cmd);
                }
                for (k, v) in &record.env {
                    println!("  Env: {}={}", k, v);
                }
                if let Some(wd) = &record.workdir {
                    println!("  Workdir: {}", wd);
                }
                println!("  Created: {}", record.created_at);
                println!();
            }
        }
    }

    Ok(())
}

// ============================================================================
// Resize
// ============================================================================

/// Resize a microVM's disk resources.
///
/// The VM must be stopped before resizing. Only expansion is supported
/// (no shrinking to prevent data loss).
pub fn resize_vm(
    name: &str,
    new_storage_gb: Option<u64>,
    new_overlay_gb: Option<u64>,
) -> smolvm::Result<()> {
    use smolvm::config::RecordState;
    use smolvm::data::disk::{Overlay, Storage};
    use smolvm::db::SmolvmDb;
    use smolvm::storage::{expand_disk, DEFAULT_OVERLAY_SIZE_GIB, DEFAULT_STORAGE_SIZE_GIB};

    // Get VM record from database
    let db = SmolvmDb::open()?;
    let record = db
        .get_vm(name)?
        .ok_or_else(|| smolvm::Error::vm_not_found(name))?
        .clone();

    // Check state - VM must be stopped (Created state also allowed for never-started VMs)
    let actual_state = record.actual_state();
    match actual_state {
        RecordState::Stopped | RecordState::Created => {} // OK to resize
        _ => {
            return Err(smolvm::Error::InvalidState {
                expected: "stopped".into(),
                actual: format!("{:?}", actual_state),
            });
        }
    }

    // Get current disk sizes (use defaults if not set)
    let current_storage_gb = record.storage_gb.unwrap_or(DEFAULT_STORAGE_SIZE_GIB);
    let current_overlay_gb = record.overlay_gb.unwrap_or(DEFAULT_OVERLAY_SIZE_GIB);

    // Determine target sizes
    let target_storage_gb = new_storage_gb.unwrap_or(current_storage_gb);
    let target_overlay_gb = new_overlay_gb.unwrap_or(current_overlay_gb);

    // Validate no shrinking
    if target_storage_gb < current_storage_gb {
        return Err(smolvm::Error::config(
            "resize",
            format!(
                "storage disk cannot be shrunk from {} GiB to {} GiB. Only expanding is supported to prevent data loss.",
                current_storage_gb, target_storage_gb
            ),
        ));
    }
    if target_overlay_gb < current_overlay_gb {
        return Err(smolvm::Error::config(
            "resize",
            format!(
                "overlay disk cannot be shrunk from {} GiB to {} GiB. Only expanding is supported to prevent data loss.",
                current_overlay_gb, target_overlay_gb
            ),
        ));
    }

    // Get agent manager for disk paths
    let manager = AgentManager::for_vm(name)
        .map_err(|e| smolvm::Error::agent("get agent manager", e.to_string()))?;

    // Print resize header
    println!("Resizing machine '{}'...", name);

    // Expand storage disk if requested and changed
    if let Some(storage_gb) = new_storage_gb {
        if storage_gb > current_storage_gb {
            print!(
                "  Storage: {} GiB → {} GiB (expanding disk...)",
                current_storage_gb, storage_gb
            );
            std::io::Write::flush(&mut std::io::stdout()).ok();

            let storage_path = manager.storage_path();
            expand_disk::<Storage>(storage_path, storage_gb)
                .map_err(|e| smolvm::Error::storage("expand storage disk", e.to_string()))?;
            println!(" done");
        }
    }

    // Expand overlay disk if requested and changed
    if let Some(overlay_gb) = new_overlay_gb {
        if overlay_gb > current_overlay_gb {
            print!(
                "  Overlay: {} GiB → {} GiB (expanding disk...)",
                current_overlay_gb, overlay_gb
            );
            std::io::Write::flush(&mut std::io::stdout()).ok();

            let overlay_path = manager.overlay_path();
            expand_disk::<Overlay>(overlay_path, overlay_gb)
                .map_err(|e| smolvm::Error::storage("expand overlay disk", e.to_string()))?;
            println!(" done");
        }
    }

    // Update database record with new sizes
    db.update_vm(name, |r| {
        if let Some(s) = new_storage_gb {
            r.storage_gb = Some(s);
        }
        if let Some(o) = new_overlay_gb {
            r.overlay_gb = Some(o);
        }
    })?;

    println!();
    println!("Machine '{}' resized successfully.", name);
    println!("Disk changes are applied immediately; filesystem will expand on next boot.");

    Ok(())
}

// ============================================================================
// Ephemeral VM Tracking
// ============================================================================

/// Register an ephemeral VM in the database for tracking.
///
/// Called by `machine run` after the VM is forked. The record is removed
/// on clean exit. Stale records from crashes are cleaned up by
/// `cleanup_orphaned_ephemeral_vms()`.
pub fn register_ephemeral_vm(
    name: &str,
    pid: Option<i32>,
    cpus: u8,
    mem: u32,
    network: bool,
    image: Option<String>,
) {
    let mut record = VmRecord::new(name.to_string(), cpus, mem, vec![], vec![], network);
    record.ephemeral = true;
    record.state = RecordState::Running;
    record.pid = pid;
    record.image = image;

    if let Ok(db) = SmolvmDb::open() {
        if let Err(e) = db.insert_vm(name, &record) {
            tracing::debug!(error = %e, name, "failed to register ephemeral VM");
        }
    }
}

/// Remove an ephemeral VM record from the database.
pub fn deregister_ephemeral_vm(name: &str) {
    if let Ok(db) = SmolvmDb::open() {
        if let Err(e) = db.remove_vm(name) {
            tracing::debug!(error = %e, name, "failed to deregister ephemeral VM");
        }
    }
}

/// Clean up orphaned ephemeral VM records.
///
/// Called once at CLI startup. Scans for ephemeral records whose PID is no
/// longer alive and removes them. Fast path: if no ephemeral records exist,
/// this is a single DB read (~0.2ms).
pub fn cleanup_orphaned_ephemeral_vms() {
    let db = match SmolvmDb::open() {
        Ok(db) => db,
        Err(_) => return,
    };

    let vms = match db.list_vms() {
        Ok(vms) => vms,
        Err(_) => return,
    };

    for (name, record) in &vms {
        if !record.ephemeral {
            continue;
        }

        let is_orphan = match record.pid {
            Some(pid) => !smolvm::process::is_alive(pid),
            None => true, // No PID recorded — stale
        };

        if is_orphan {
            tracing::debug!(name = %name, pid = ?record.pid, "cleaning up orphaned ephemeral VM");
            let _ = db.remove_vm(name);
        }
    }
}

#[cfg(test)]
mod init_runner_tests {
    use super::*;

    #[test]
    fn format_init_failure_includes_stderr_only() {
        // Single stream → no "stdout:" / "stderr:" labels needed; the
        // colon-prefixed form keeps the message compact for the common
        // case of a tool writing only to stderr.
        let msg = format_init_failure(0, 1, "", "command not found");
        assert_eq!(msg, "init[0] failed (exit 1): command not found");
    }

    #[test]
    fn format_init_failure_includes_stdout_only() {
        // Some tools emit their failure reason on stdout instead of
        // stderr (curl with -s, certain pacman/apt failure modes).
        // Dropping stdout would leave the operator with just an exit
        // code and no explanation.
        let msg = format_init_failure(2, 127, "could not resolve mirror", "");
        assert_eq!(msg, "init[2] failed (exit 127): could not resolve mirror");
    }

    #[test]
    fn format_init_failure_combines_both_streams() {
        // Both populated: stderr leads (canonical error channel) but
        // stdout follows so package-manager errors that put the real
        // reason on stdout are still visible. Single-line for greppability.
        let msg = format_init_failure(0, 2, "saw 3 errors", "fatal: aborting");
        assert_eq!(
            msg,
            "init[0] failed (exit 2): fatal: aborting; stdout: saw 3 errors"
        );
    }

    #[test]
    fn format_init_failure_handles_empty_streams() {
        // Some commands exit non-zero with no output (e.g. `false`).
        // The error must still be informative — the index + exit code
        // alone tell the user which command failed and how.
        let msg = format_init_failure(5, 1, "", "");
        assert_eq!(msg, "init[5] failed (exit 1)");
    }

    #[test]
    fn format_init_failure_trims_whitespace() {
        // Subprocess output usually ends in a trailing newline; the
        // formatter trims so the assembled message doesn't have weird
        // mid-line breaks.
        let msg = format_init_failure(0, 1, "  ", "  bad thing happened  \n");
        assert_eq!(msg, "init[0] failed (exit 1): bad thing happened");
    }

    #[test]
    fn init_argv_routes_through_sh_dash_c() {
        // Shell wrapping is load-bearing: user init strings commonly
        // chain commands with `&&`, pipe through tools, rely on env
        // expansion. If a future refactor "simplifies" by passing the
        // command argv directly to exec, those features break silently.
        assert_eq!(
            init_argv("pacman -Sy && pacman -S git"),
            vec![
                "sh".to_string(),
                "-c".to_string(),
                "pacman -Sy && pacman -S git".to_string(),
            ]
        );
    }

    #[test]
    fn build_init_run_config_overlay_matches_machine_name() {
        // The overlay ID is what makes init's filesystem changes visible
        // to subsequent `machine exec`. If this drifts (e.g. someone
        // hardcodes "init-overlay"), `pacman -S git` during init would
        // succeed but `git --version` post-start would fail with "not
        // found" — exactly the user-confusing regression we're guarding
        // against.
        let config = build_init_run_config("alpine", "true", &[], None, &[], "my-vm");
        assert_eq!(config.persistent_overlay_id.as_deref(), Some("my-vm"));
    }

    #[test]
    fn build_init_run_config_threads_env_workdir_image() {
        // Each input must reach the agent untouched. The runner passes
        // record values verbatim; if a `with_*` call gets dropped in a
        // refactor, the user's `[dev].env` or `[dev].workdir` would
        // silently stop applying to init.
        let env = vec![("HTTP_PROXY".to_string(), "http://proxy:3128".to_string())];
        let config =
            build_init_run_config("debian:slim", "apt update", &env, Some("/work"), &[], "vm");
        assert_eq!(config.image, "debian:slim");
        assert_eq!(config.env, env);
        assert_eq!(config.workdir.as_deref(), Some("/work"));
        // Command is sh-wrapped; assert the wrapped form arrives.
        assert_eq!(
            config.command,
            vec!["sh".to_string(), "-c".to_string(), "apt update".to_string(),]
        );
    }

    #[test]
    fn build_init_run_config_assigns_virtiofs_tags_to_mounts() {
        // Mount tags are positional and must align with the virtiofs
        // devices libkrun set up at VM start. If the converter were
        // skipped (or renamed and not rewired), init would still run
        // but mounted volumes wouldn't be visible inside the container.
        let mounts = vec![
            ("/host/src".to_string(), "/app".to_string(), false),
            ("/host/data".to_string(), "/data".to_string(), true),
        ];
        let config = build_init_run_config("alpine", "true", &[], None, &mounts, "vm");
        assert_eq!(
            config.mounts,
            vec![
                ("smolvm0".to_string(), "/app".to_string(), false),
                ("smolvm1".to_string(), "/data".to_string(), true),
            ]
        );
    }

    #[test]
    fn build_init_run_config_no_mounts_no_workdir() {
        // The image path is also the bare-minimum path: image + cmd is
        // a valid init invocation. No mounts, no workdir, no env — must
        // still produce a usable RunConfig (vs. e.g. panicking on
        // `unwrap` somewhere in the builder).
        let config = build_init_run_config("alpine", "echo hi", &[], None, &[], "vm");
        assert!(config.mounts.is_empty());
        assert!(config.workdir.is_none());
        assert!(config.env.is_empty());
        assert_eq!(config.persistent_overlay_id.as_deref(), Some("vm"));
    }
}
