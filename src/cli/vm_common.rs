//! Shared helpers for machine CLI commands.
//!
//! The `machine` subcommand exposes lifecycle commands
//! (create, start, stop, delete, ls) with only cosmetic differences.
//! This module provides the common implementations, parameterised by
//! [`VmKind`].

use crate::cli::format_pid_suffix;
use smolvm::agent::AgentManager;
use smolvm::config::{RecordState, SmolvmConfig, VmRecord};
use smolvm::control;
use smolvm::data::mount::HostMount;
use smolvm::data::network::PortMapping;
use smolvm::data::resources::{DEFAULT_MICROVM_CPU_COUNT, DEFAULT_MICROVM_MEMORY_MIB};
use smolvm::data::vm::{MicroVm, VmPhase, VmSpec};
use smolvm::db::SmolvmDb;

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


/// Create a named machine configuration (does not start it).
///
/// Delegates core persistence to `control::create_vm`.
pub fn create_vm(kind: VmKind, params: CreateVmParams) -> smolvm::Result<()> {
    // Parse and validate volume mounts
    let mounts = HostMount::parse(&params.volume)?;

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

    // Build MicroVm and delegate to control layer
    let vm = MicroVm {
        name: params.name.clone(),
        spec: VmSpec {
            resources: smolvm::data::resources::VmResources {
                cpus: params.cpus,
                memory_mib: params.mem,
                network: params.net,
                storage_gib: params.storage_gb,
                overlay_gib: params.overlay_gb,
                allowed_cidrs: params.allowed_cidrs.clone(),
            },
            mounts,
            ports: params.port.clone(),
            image: params.image.clone(),
            entrypoint: params.entrypoint.clone(),
            cmd: params.cmd.clone(),
            env,
            workdir: params.workdir.clone(),
            init: params.init.clone(),
        },
        status: None,
    };

    let db = SmolvmDb::open()?;
    control::create_vm(&db, vm)?;

    // CLI output
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
/// Delegates core lifecycle to `control::start_vm`, then handles
/// CLI-specific post-start behavior (init commands, image pull, container creation).
pub fn start_vm_named(kind: VmKind, name: &str) -> smolvm::Result<()> {
    let db = SmolvmDb::open()?;

    // Pre-start info for CLI output
    let vm = control::get_vm(&db, name)?;
    let spec = &vm.spec;

    // Check if already running
    if let Some(ref status) = vm.status {
        if status.phase == VmPhase::Running {
            let pid_suffix = format_pid_suffix(status.pid);
            println!(
                "{} '{}' already running{}",
                kind.display_name(),
                name,
                pid_suffix
            );
            return Ok(());
        }
    }

    // CLI progress output
    let mount_info = if !spec.mounts.is_empty() {
        format!(" with {} mount(s)", spec.mounts.len())
    } else {
        String::new()
    };
    let port_info = if !spec.ports.is_empty() {
        format!(" and {} port mapping(s)", spec.ports.len())
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

    // Core lifecycle (delegated to control layer — handles AgentManager, ensure_running, DB persist)
    let handle = control::start_vm(&db, name)?;
    let pid = handle.child_pid();

    // CLI-specific: run init commands
    if !spec.init.is_empty() {
        println!("Running {} init command(s)...", spec.init.len());
        let mut client = smolvm::agent::AgentClient::connect_with_retry(handle.vsock_socket())?;
        for (i, cmd) in spec.init.iter().enumerate() {
            let argv = vec!["sh".into(), "-c".into(), cmd.clone()];
            let env: Vec<(String, String)> = spec.env.clone();
            let workdir = spec.workdir.clone();
            let (exit_code, _stdout, stderr) = client.vm_exec(argv, env, workdir, None)?;
            if exit_code != 0 {
                // Stop on init failure
                drop(handle); // release the handle
                let _ = control::stop_vm(&db, name);
                return Err(smolvm::Error::agent(
                    "init",
                    format!("init[{}] failed (exit {}): {}", i, exit_code, stderr.trim()),
                ));
            }
        }
    }

    // CLI-specific: auto-create container if image configured (from Smolfile)
    if let Some(ref image) = spec.image {
        let mut client = smolvm::agent::AgentClient::connect_with_retry(handle.vsock_socket())?;

        println!("Pulling {}...", image);
        let _image_info = crate::cli::pull_with_progress(&mut client, image, None)?;

        // Image is pulled and cached. The VM is running and ready for
        // `machine exec` commands. No background process is started — the
        // VM sits idle until the user execs into it.

        println!(
            "{} '{}' running (PID: {})",
            kind.display_name(),
            name,
            pid.unwrap_or(0)
        );
    } else {
        // No image — bare VM mode. Run entrypoint+cmd if configured.
        let mut bare_cmd = spec.entrypoint.clone();
        bare_cmd.extend(spec.cmd.clone());
        if !bare_cmd.is_empty() {
            let mut client =
                smolvm::agent::AgentClient::connect_with_retry(handle.vsock_socket())?;
            let env: Vec<(String, String)> = spec.env.clone();
            let (exit_code, stdout, stderr) =
                client.vm_exec(bare_cmd, env, spec.workdir.clone(), None)?;
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

    handle.detach();
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
///
/// If the default VM exists in the DB, delegates to `start_vm_named`.
/// Otherwise creates a fresh default VM via AgentManager.
pub fn start_vm_default(kind: VmKind) -> smolvm::Result<()> {
    let db = SmolvmDb::open()?;

    // If default exists in DB, use the named path (gets full config, init, etc.)
    if db.get_vm("default")?.is_some() {
        return start_vm_named(kind, "default");
    }

    // No record — start a bare default VM
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

    // Persist the default record
    let mut config = SmolvmConfig::load()?;
    persist_default_running(&mut config, manager.child_pid(), None);

    println!(
        "{} 'default' running (PID: {})",
        kind.display_name(),
        manager.child_pid().unwrap_or(0)
    );

    manager.detach();
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
///
/// Handles CLI-specific confirmation prompt, then delegates to
/// `control::delete_vm` for the actual deletion.
pub fn delete_vm(
    kind: VmKind,
    name: &str,
    force: bool,
    options: DeleteVmOptions,
) -> smolvm::Result<()> {
    let db = SmolvmDb::open()?;

    // Check if exists (for CLI messaging)
    let _ = control::get_vm(&db, name)?;

    // Stop if running and option set (machine run does this)
    if options.stop_if_running {
        let vm = control::get_vm(&db, name)?;
        if let Some(ref status) = vm.status {
            if status.phase == VmPhase::Running {
                println!("Stopping {} '{}'...", kind.label(), name);
                let _ = control::stop_vm(&db, name);
            }
        }
    }

    // CLI-specific: confirm deletion unless --force
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

    // Delegate to control layer
    control::delete_vm(&db, name, true)?;

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
// Resize
// ============================================================================

/// Resize a VM's disk resources.
///
/// Delegates core resize logic to `smolvm::control::resize_vm`.
/// CLI adds progress output.
pub fn resize_vm(
    kind: VmKind,
    name: &str,
    new_storage_gb: Option<u64>,
    new_overlay_gb: Option<u64>,
) -> smolvm::Result<()> {
    println!("Resizing {} '{}'...", kind.label(), name);

    let db = SmolvmDb::open()?;
    smolvm::control::resize_vm(&db, name, new_storage_gb, new_overlay_gb)?;

    println!();
    println!("{} '{}' resized successfully.", kind.display_name(), name);
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
