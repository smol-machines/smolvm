//! Shared helpers for microvm and sandbox CLI commands.
//!
//! Both `microvm` and `sandbox` expose the same lifecycle commands
//! (create, start, stop, delete, ls) with only cosmetic differences.
//! This module provides the common implementations, parameterised by
//! [`VmKind`].

use crate::cli::parsers::parse_mounts_as_tuples;
use crate::cli::{format_pid_suffix, truncate};
use smolvm::agent::{vm_data_dir, AgentManager, PortMapping};
use smolvm::config::{RecordState, SmolvmConfig, VmRecord};

// ============================================================================
// VmKind
// ============================================================================

/// Distinguishes microvm vs sandbox for display strings and minor
/// behavioural differences.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmKind {
    Microvm,
    Sandbox,
}

impl VmKind {
    /// Lowercase label used in user-facing messages ("microvm" / "sandbox").
    pub fn label(self) -> &'static str {
        match self {
            VmKind::Microvm => "microvm",
            VmKind::Sandbox => "sandbox",
        }
    }

    /// Title-case label ("MicroVM" / "Sandbox").
    pub fn display_name(self) -> &'static str {
        match self {
            VmKind::Microvm => "MicroVM",
            VmKind::Sandbox => "Sandbox",
        }
    }

    /// CLI prefix for help text ("smolvm microvm" / "smolvm sandbox").
    pub fn cli_prefix(self) -> &'static str {
        match self {
            VmKind::Microvm => "smolvm microvm",
            VmKind::Sandbox => "smolvm sandbox",
        }
    }

    /// Whether the JSON list output should include the `network` field.
    pub fn include_network_in_json(self) -> bool {
        matches!(self, VmKind::Sandbox)
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
    let config = SmolvmConfig::load()?;
    if config.get_vm("default").is_some() {
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
/// This is the common pattern used by exec commands in both microvm and sandbox.
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
        println!("Starting microvm '{}'...", name);
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
}

/// Maximum length for VM/sandbox names.
const MAX_NAME_LENGTH: usize = 40;

/// Validate a VM/sandbox name for CLI commands.
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

/// Create a named VM/sandbox configuration (does not start it).
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
    let mounts = parse_mounts_as_tuples(&params.volume)?;

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

    // Create record
    let mut record = VmRecord::new(
        params.name.clone(),
        params.cpus,
        params.mem,
        mounts,
        ports,
        params.net,
    );
    record.init = params.init.clone();
    record.env = env;
    record.workdir = params.workdir.clone();
    record.storage_gb = params.storage_gb;
    record.overlay_gb = params.overlay_gb;

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
        "Then use 'smolvm container create {}' to run containers",
        params.name,
    );

    Ok(())
}

// ============================================================================
// Start
// ============================================================================

/// Start a named VM/sandbox that has a config record.
pub fn start_vm_named(kind: VmKind, name: &str) -> smolvm::Result<()> {
    use smolvm::Error;

    let mut config = SmolvmConfig::load()?;

    // Get record
    let record = config
        .get_vm(name)
        .ok_or_else(|| Error::vm_not_found(name))?
        .clone();

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

    let _ = manager
        .ensure_running_with_full_config(mounts, ports, resources)
        .map_err(|e| Error::agent(format!("start {}", kind.label()), e.to_string()))?;

    // Update state with PID start time for safe process identification
    let pid = manager.child_pid();
    let pid_start_time = pid.and_then(smolvm::process::process_start_time);
    config.update_vm(name, |r| {
        r.state = RecordState::Running;
        r.pid = pid;
        r.pid_start_time = pid_start_time;
    });
    config.save()?;

    // Release the database lock so other smolvm commands can run concurrently
    // (e.g. `smolvm microvm exec` while init commands are still running).
    config.close_db();

    // Run init commands if configured
    if !record.init.is_empty() {
        println!("Running {} init command(s)...", record.init.len());
        let mut client = smolvm::agent::AgentClient::connect_with_retry(manager.vsock_socket())?;
        for (i, cmd) in record.init.iter().enumerate() {
            let argv = vec!["sh".into(), "-c".into(), cmd.clone()];
            let (exit_code, _stdout, stderr) =
                client.vm_exec(argv, record.env.clone(), record.workdir.clone(), None)?;
            if exit_code != 0 {
                eprintln!("init[{}] failed (exit {}): {}", i, exit_code, stderr.trim());
            }
        }
    }

    println!(
        "{} '{}' running (PID: {})",
        kind.display_name(),
        name,
        pid.unwrap_or(0)
    );
    println!(
        "\nUse 'smolvm container create {} <image>' to run containers",
        name,
    );

    // Keep VM running (persistent)
    manager.detach();
    Ok(())
}

/// Persist the "default" VM as running in the database.
///
/// Creates the record if it doesn't exist, then updates state to Running
/// with the current PID and optional config overrides (cpus, mem, etc.).
/// Call `config.close_db()` after this to release the lock.
pub fn persist_default_running(
    config: &mut SmolvmConfig,
    pid: Option<i32>,
    overrides: Option<DefaultVmOverrides>,
) {
    if config.get_vm("default").is_none() {
        let record = VmRecord::new(
            "default".to_string(),
            smolvm::config::DEFAULT_VM_CPUS,
            smolvm::config::DEFAULT_VM_MEMORY_MIB,
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
}

/// Start the default VM/sandbox.
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

    // Run init commands if the default record has them (persisted from sandbox run -d -s)
    let record = config.get_vm("default").cloned();
    config.close_db();

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
                    eprintln!("init[{}] failed (exit {}): {}", i, exit_code, stderr.trim());
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

/// Stop a named VM/sandbox that has a config record (or fall back to
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

/// Stop the default VM/sandbox.
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

/// Options that vary between microvm and sandbox delete.
pub struct DeleteVmOptions {
    /// If true, stop the VM before deleting when it is running.
    pub stop_if_running: bool,
}

/// Delete a named VM/sandbox configuration.
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

    // Stop if running (sandbox does this, microvm does not)
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

    // Remove from config
    config.remove_vm(name);
    config.save()?;

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

/// Show status of a named or default VM/sandbox.
///
/// The `extra` callback is invoked when the VM is running, allowing callers
/// to display additional information (e.g., sandbox lists containers).
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

/// List all VMs/sandboxes.
pub fn list_vms(kind: VmKind, verbose: bool, json: bool) -> smolvm::Result<()> {
    let config = SmolvmConfig::load()?;
    let vms: Vec<_> = config.list_vms().collect();

    let empty_label = match kind {
        VmKind::Microvm => "No VMs found",
        VmKind::Sandbox => "No sandboxes found",
    };

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
            "{:<20} {:<10} {:<5} {:<8} {:<6} {:<6}",
            "NAME", "STATE", "CPUS", "MEMORY", "MOUNTS", "PORTS"
        );
        println!("{}", "-".repeat(60));

        for (name, record) in vms {
            let actual_state = record.actual_state();
            println!(
                "{:<20} {:<10} {:<5} {:<8} {:<6} {:<6}",
                truncate(name, 18),
                actual_state,
                record.cpus,
                format!("{} MiB", record.mem),
                record.mounts.len(),
                record.ports.len(),
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
