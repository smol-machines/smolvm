//! Shared helpers for machine CLI commands.
//!
//! The `machine` subcommand exposes lifecycle commands
//! (create, start, stop, delete, ls) with only cosmetic differences.
//! This module provides the common implementations, parameterised by
//! [`VmKind`].

use crate::cli::{format_pid_suffix, truncate};
use smolvm::agent::{vm_data_dir, AgentManager};
use smolvm::config::{RecordState, SmolvmConfig, VmRecord};
use smolvm::data::network::PortMapping;
use smolvm::data::resources::{DEFAULT_MICROVM_CPU_COUNT, DEFAULT_MICROVM_MEMORY_MIB};
use smolvm::data::storage::HostMount;
use smolvm::db::SmolvmDb;
use smolvm::storage::{DEFAULT_OVERLAY_SIZE_GIB, DEFAULT_STORAGE_SIZE_GIB};

// ============================================================================
// VmKind
// ============================================================================

/// VM kind for display strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmKind {
    Machine,
}

impl VmKind {
    /// Lowercase label used in user-facing messages.
    pub fn label(self) -> &'static str {
        "machine"
    }

    /// Title-case label.
    pub fn display_name(self) -> &'static str {
        "Machine"
    }

    /// CLI prefix for help text.
    pub fn cli_prefix(self) -> &'static str {
        "smolvm machine"
    }

    /// Whether the JSON list output should include the `network` field.
    pub fn include_network_in_json(self) -> bool {
        true
    }
}

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
    kind: VmKind,
) -> smolvm::Result<(AgentManager, smolvm::agent::AgentClient)> {
    let manager = get_vm_manager(name)?;
    let label = vm_label(name);

    if manager.try_connect_existing().is_none() {
        return Err(smolvm::Error::agent(
            "connect",
            format!(
                "{} '{}' is not running. Use '{} start' first.",
                kind.label(),
                label,
                kind.cli_prefix(),
            ),
        ));
    }

    let client = smolvm::agent::AgentClient::connect_with_retry(manager.vsock_socket())?;
    Ok((manager, client))
}

/// Print command output and exit with the given code.
///
/// Prints stdout to stdout, stderr to stderr, detaches the manager
/// (keeping the VM running), and exits the process.
pub fn print_output_and_exit(
    manager: &AgentManager,
    exit_code: i32,
    stdout: &str,
    stderr: &str,
) -> ! {
    if !stdout.is_empty() {
        print!("{}", stdout);
    }
    if !stderr.is_empty() {
        eprint!("{}", stderr);
    }
    crate::cli::flush_output();
    manager.detach();
    std::process::exit(exit_code);
}

/// Get the agent manager for a VM by name, auto-starting it if not running.
///
/// Unlike [`ensure_running_and_connect`] which errors if the VM isn't running,
/// this calls `ensure_running()` to start the VM on demand. Used by container
/// commands that need the VM to be available.
pub fn get_or_start_vm(name: &str) -> smolvm::Result<AgentManager> {
    let name_opt = if name == "default" {
        None
    } else {
        Some(name.to_string())
    };
    let manager = get_vm_manager(&name_opt)?;

    if manager.try_connect_existing().is_none() {
        println!("Starting machine '{}'...", name);
        manager.ensure_running()?;
    }

    Ok(manager)
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
}

/// Maximum length for machine names.
const MAX_NAME_LENGTH: usize = 40;

/// Validate a machine name for CLI commands.
///
/// Same rules as the API validation but returns `smolvm::Error` instead of `ApiError`.
fn validate_name(name: &str, kind: VmKind) -> smolvm::Result<()> {
    if name.is_empty() {
        return Err(smolvm::Error::config(
            format!("create {}", kind.label()),
            format!("{} name cannot be empty", kind.label()),
        ));
    }
    if name.len() > MAX_NAME_LENGTH {
        return Err(smolvm::Error::config(
            format!("create {}", kind.label()),
            format!(
                "{} name too long: {} characters (max {})",
                kind.label(),
                name.len(),
                MAX_NAME_LENGTH
            ),
        ));
    }
    let first_char = name.chars().next().unwrap();
    if !first_char.is_ascii_alphanumeric() {
        return Err(smolvm::Error::config(
            format!("create {}", kind.label()),
            format!("{} name must start with a letter or digit", kind.label()),
        ));
    }
    if name.ends_with('-') {
        return Err(smolvm::Error::config(
            format!("create {}", kind.label()),
            format!("{} name cannot end with a hyphen", kind.label()),
        ));
    }
    let mut prev_was_hyphen = false;
    for c in name.chars() {
        if c == '-' {
            if prev_was_hyphen {
                return Err(smolvm::Error::config(
                    format!("create {}", kind.label()),
                    format!("{} name cannot contain consecutive hyphens", kind.label()),
                ));
            }
            prev_was_hyphen = true;
        } else {
            prev_was_hyphen = false;
        }
        if !c.is_ascii_alphanumeric() && c != '-' && c != '_' {
            return Err(smolvm::Error::config(
                format!("create {}", kind.label()),
                format!("{} name contains invalid character: '{}'", kind.label(), c),
            ));
        }
    }
    Ok(())
}

/// Create a named machine configuration (does not start it).
pub fn create_vm(kind: VmKind, params: CreateVmParams) -> smolvm::Result<()> {
    // Validate name before touching the database
    validate_name(&params.name, kind)?;

    let mut config = SmolvmConfig::load()?;

    // Check if already exists
    if config.get_vm(&params.name).is_some() {
        return Err(smolvm::Error::config(
            format!("create {}", kind.label()),
            format!("{} '{}' already exists", kind.label(), params.name),
        ));
    }

    // Parse and validate volume mounts
    let mounts = HostMount::parse(&params.volume)?
        .into_iter()
        .map(|m| m.to_storage_tuple())
        .collect();

    // Convert port mappings to tuple format for storage
    let ports: Vec<(u16, u16)> = params.port.iter().map(|p| (p.host, p.guest)).collect();

    // Parse environment variables for init
    let env: Vec<(String, String)> = params
        .env
        .iter()
        .filter_map(|e| {
            let (k, v) = e.split_once('=')?;
            if k.is_empty() {
                None
            } else {
                Some((k.to_string(), v.to_string()))
            }
        })
        .collect();

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

    // Store in config (persisted immediately to database)
    config.insert_vm(params.name.clone(), record)?;

    println!("Created {}: {}", kind.label(), params.name);
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
        "\nUse '{} start {}' to start the {}",
        kind.cli_prefix(),
        params.name,
        kind.label(),
    );
    println!(
        "Then use 'smolvm container create -m {} --image <image>' to run containers",
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
pub fn start_vm_named(kind: VmKind, name: &str) -> smolvm::Result<()> {
    use smolvm::Error;

    // Direct DB lookup — 1 read cycle instead of loading everything
    let db = SmolvmDb::open()?;
    let record = db.get_vm(name)?.ok_or_else(|| Error::vm_not_found(name))?;

    // Check state
    let actual_state = record.actual_state();
    if actual_state == RecordState::Running {
        let pid_suffix = format_pid_suffix(record.pid);
        println!(
            "{} '{}' already running{}",
            kind.display_name(),
            name,
            pid_suffix
        );
        return Ok(());
    }

    let mounts = record.host_mounts();
    let ports = record.port_mappings();
    let resources = record.vm_resources();

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
    println!(
        "Starting {} '{}'{}{}...",
        kind.label(),
        name,
        mount_info,
        port_info
    );

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

    let features = smolvm::agent::LaunchFeatures {
        ssh_agent_socket,
        dns_filter_hosts: record.dns_filter_hosts.clone(),
    };

    let _ = manager
        .ensure_running_with_full_config(mounts, ports, resources, features)
        .map_err(|e| Error::agent(format!("start {}", kind.label()), e.to_string()))?;

    // Get PID immediately (cheap) and print output before DB write
    let pid = manager.child_pid();

    // Run init commands if configured (before reporting success)
    if !record.init.is_empty() {
        println!("Running {} init command(s)...", record.init.len());
        let mut client = smolvm::agent::AgentClient::connect_with_retry(manager.vsock_socket())?;
        for (i, cmd) in record.init.iter().enumerate() {
            let argv = vec!["sh".into(), "-c".into(), cmd.clone()];
            let (exit_code, _stdout, stderr) =
                client.vm_exec(argv, record.env.clone(), record.workdir.clone(), None)?;
            if exit_code != 0 {
                if let Err(e) = manager.stop() {
                    tracing::warn!(error = %e, "failed to stop machine after init failure");
                }
                return Err(smolvm::Error::agent(
                    "init",
                    format!("init[{}] failed (exit {}): {}", i, exit_code, stderr.trim()),
                ));
            }
        }
    }

    // Auto-create container if image is configured (from Smolfile)
    if let Some(ref image) = record.image {
        let mut client = smolvm::agent::AgentClient::connect_with_retry(manager.vsock_socket())?;

        println!("Pulling {}...", image);
        let image_info = crate::cli::pull_with_progress(&mut client, image, None)?;

        // Build command: record (from Smolfile) > image metadata > idle default
        let ep = if !record.entrypoint.is_empty() {
            record.entrypoint.clone()
        } else {
            image_info.entrypoint.clone()
        };
        let args = if !record.cmd.is_empty() {
            record.cmd.clone()
        } else {
            image_info.cmd.clone()
        };
        let mut command = ep;
        command.extend(args);
        if command.is_empty() {
            command = smolvm::DEFAULT_IDLE_CMD
                .iter()
                .map(|s| s.to_string())
                .collect();
        }

        let env = record.env.clone();
        let mount_bindings =
            crate::cli::parsers::mounts_to_virtiofs_bindings(&record.host_mounts());

        let info =
            client.create_container(image, command, env, record.workdir.clone(), mount_bindings)?;

        println!(
            "{} '{}' running (PID: {}, container: {})",
            kind.display_name(),
            name,
            pid.unwrap_or(0),
            &info.id[..12]
        );
    } else {
        // No image — bare VM mode. Run entrypoint+cmd if configured.
        let mut bare_cmd = record.entrypoint.clone();
        bare_cmd.extend(record.cmd.clone());
        if !bare_cmd.is_empty() {
            let mut client =
                smolvm::agent::AgentClient::connect_with_retry(manager.vsock_socket())?;
            let env = record.env.clone();
            let (exit_code, stdout, stderr) =
                client.vm_exec(bare_cmd, env, record.workdir.clone(), None)?;
            if !stdout.is_empty() {
                print!("{}", stdout);
            }
            if !stderr.is_empty() {
                eprint!("{}", stderr);
            }
            if exit_code != 0 {
                eprintln!("workload exited with code {}", exit_code);
            }
        }
        println!(
            "{} '{}' running (PID: {})",
            kind.display_name(),
            name,
            pid.unwrap_or(0)
        );
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
                r.storage_gb = o.storage_gb;
                r.overlay_gb = o.overlay_gb;
                r.init = o.init.clone();
                r.env = o.env.clone();
                r.workdir = o.workdir.clone();
                r.image = o.image.clone();
                r.entrypoint = o.entrypoint.clone();
                r.cmd = o.cmd.clone();
                r.ssh_agent = o.ssh_agent;
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
    pub storage_gb: Option<u64>,
    pub overlay_gb: Option<u64>,
    pub init: Vec<String>,
    pub env: Vec<(String, String)>,
    pub workdir: Option<String>,
    pub image: Option<String>,
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
    pub ssh_agent: bool,
}

/// Start the default machine.
pub fn start_vm_default(kind: VmKind) -> smolvm::Result<()> {
    let manager = AgentManager::new_default()?;

    if manager.try_connect_existing().is_some() {
        let pid_suffix = format_pid_suffix(manager.child_pid());
        println!(
            "{} 'default' already running{}",
            kind.display_name(),
            pid_suffix
        );
        manager.detach();
        return Ok(());
    }

    println!("Starting {} 'default'...", kind.label());
    manager.ensure_running()?;

    let mut config = SmolvmConfig::load()?;
    persist_default_running(&mut config, manager.child_pid(), None);

    // Run init commands if the default record has them (persisted from machine run -d -s)
    let record = config.get_vm("default").cloned();

    if let Some(record) = record {
        if !record.init.is_empty() {
            println!("Running {} init command(s)...", record.init.len());
            let mut client =
                smolvm::agent::AgentClient::connect_with_retry(manager.vsock_socket())?;
            for (i, cmd) in record.init.iter().enumerate() {
                let argv = vec!["sh".into(), "-c".into(), cmd.clone()];
                let (exit_code, _stdout, stderr) =
                    client.vm_exec(argv, record.env.clone(), record.workdir.clone(), None)?;
                if exit_code != 0 {
                    if let Err(e) = manager.stop() {
                        tracing::warn!(error = %e, "failed to stop machine after init failure");
                    }
                    return Err(smolvm::Error::agent(
                        "init",
                        format!("init[{}] failed (exit {}): {}", i, exit_code, stderr.trim()),
                    ));
                }
            }
        }
    }

    println!(
        "{} 'default' running (PID: {})",
        kind.display_name(),
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
pub fn stop_vm_named(kind: VmKind, name: &str) -> smolvm::Result<()> {
    let mut config = SmolvmConfig::load()?;

    // Check config for the named VM
    let record = match config.get_vm(name) {
        Some(r) => r.clone(),
        None => {
            // Not in config — try to stop a running VM with this name directly
            let manager = AgentManager::for_vm(name)?;
            if manager.try_connect_existing().is_some() {
                println!("Stopping {} '{}'...", kind.label(), name);
                manager.stop()?;
                println!("{} '{}' stopped", kind.display_name(), name);
            } else {
                println!(
                    "{} '{}' not found or not running",
                    kind.display_name(),
                    name
                );
            }
            return Ok(());
        }
    };

    let actual_state = record.actual_state();
    if actual_state != RecordState::Running {
        println!(
            "{} '{}' is not running (state: {})",
            kind.display_name(),
            name,
            actual_state,
        );
        return Ok(());
    }

    println!("Stopping {} '{}'...", kind.label(), name);

    let manager = AgentManager::for_vm(name)
        .map_err(|e| smolvm::Error::agent("create agent manager", e.to_string()))?;
    manager.stop()?;

    config.update_vm(name, |r| {
        r.state = RecordState::Stopped;
        r.pid = None;
        r.pid_start_time = None;
    });

    println!("Stopped {}: {}", kind.label(), name);
    Ok(())
}

/// Stop the default machine.
pub fn stop_vm_default(kind: VmKind) -> smolvm::Result<()> {
    let manager = AgentManager::new_default()?;

    // try_connect_existing sets internal state if agent is reachable;
    // stop() handles both responsive agents and orphans via PID file.
    manager.try_connect_existing();
    println!("Stopping {} 'default'...", kind.label());
    manager.stop()?;

    // Update database record if it exists
    if let Ok(mut config) = SmolvmConfig::load() {
        config.update_vm("default", |r| {
            r.state = RecordState::Stopped;
            r.pid = None;
            r.pid_start_time = None;
        });
    }

    println!("{} 'default' stopped", kind.display_name());

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
pub fn delete_vm(
    kind: VmKind,
    name: &str,
    force: bool,
    options: DeleteVmOptions,
) -> smolvm::Result<()> {
    let mut config = SmolvmConfig::load()?;

    // Check if exists
    let record = config
        .get_vm(name)
        .ok_or_else(|| smolvm::Error::vm_not_found(name))?
        .clone();

    // Stop if running (machine run does this)
    if options.stop_if_running && record.actual_state() == RecordState::Running {
        if let Ok(manager) = AgentManager::for_vm(name) {
            println!("Stopping {} '{}'...", kind.label(), name);
            if let Err(e) = manager.stop() {
                tracing::warn!(error = %e, "failed to stop {}", kind.label());
            }
        }
    }

    // Confirm deletion unless --force
    if !force {
        eprint!("Delete {} '{}'? [y/N] ", kind.label(), name);
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

    let data_dir = vm_data_dir(name);
    if data_dir.exists() {
        println!("Cleaning up data directory for vm: {}", name);
        if let Err(e) = std::fs::remove_dir_all(&data_dir) {
            tracing::warn!(error = %e, "Failed to remove VM data directory: {}", data_dir.display());
        }
    }

    println!("Deleted {}: {}", kind.label(), name);
    Ok(())
}

// ============================================================================
// Status
// ============================================================================

/// Show status of a named or default machine.
///
/// The `extra` callback is invoked when the VM is running, allowing callers
/// to display additional information (e.g., machine lists containers).
pub fn status_vm<F>(kind: VmKind, name: &Option<String>, extra: F) -> smolvm::Result<()>
where
    F: FnOnce(&AgentManager),
{
    let manager = get_vm_manager(name)?;
    let label = vm_label(name);

    if manager.try_connect_existing().is_some() {
        let pid_suffix = crate::cli::format_pid_suffix(manager.child_pid());
        println!("{} '{}': running{}", kind.display_name(), label, pid_suffix);
        extra(&manager);
        manager.detach();
    } else {
        println!("{} '{}': not running", kind.display_name(), label);
    }

    Ok(())
}

// ============================================================================
// List
// ============================================================================

/// List all machines.
pub fn list_vms(kind: VmKind, verbose: bool, json: bool) -> smolvm::Result<()> {
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
                let actual_state = record.actual_state();
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
                });
                if kind.include_network_in_json() {
                    obj.as_object_mut()
                        .unwrap()
                        .insert("network".into(), serde_json::json!(record.network));
                }
                obj
            })
            .collect();
        let json = serde_json::to_string_pretty(&json_vms)
            .map_err(|e| smolvm::Error::config("serialize json", e.to_string()))?;
        println!("{}", json);
    } else {
        println!(
            "{:<20} {:<10} {:>5} {:>10} {:>7} {:>7} {:>8} {:>8}",
            "NAME", "STATE", "CPUS", "MEMORY", "MOUNTS", "PORTS", "STORAGE", "OVERLAY"
        );
        println!("{}", "-".repeat(82));

        for (name, record) in vms {
            let actual_state = record.actual_state();
            let storage_gb = record.storage_gb.unwrap_or(DEFAULT_STORAGE_SIZE_GIB);
            let overlay_gb = record.overlay_gb.unwrap_or(DEFAULT_OVERLAY_SIZE_GIB);
            println!(
                "{:<20} {:<10} {:>5} {:>10} {:>7} {:>7} {:>8} {:>8}",
                truncate(name, 18),
                actual_state,
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
                if kind.include_network_in_json() && record.network {
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
    kind: VmKind,
    name: &str,
    new_storage_gb: Option<u64>,
    new_overlay_gb: Option<u64>,
) -> smolvm::Result<()> {
    use smolvm::config::RecordState;
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
    println!("Resizing {} '{}'...", kind.label(), name);

    // Expand storage disk if requested and changed
    if let Some(storage_gb) = new_storage_gb {
        if storage_gb > current_storage_gb {
            print!(
                "  Storage: {} GiB → {} GiB (expanding disk...)",
                current_storage_gb, storage_gb
            );
            std::io::Write::flush(&mut std::io::stdout()).ok();

            let storage_path = manager.storage_path();
            expand_disk(storage_path, storage_gb, "storage")
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
            expand_disk(overlay_path, overlay_gb, "overlay")
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
    println!("{} '{}' resized successfully.", kind.display_name(), name);
    println!("Disk changes are applied immediately; filesystem will expand on next boot.");

    Ok(())
}
