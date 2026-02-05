//! MicroVM management commands.
//!
//! All VM-related commands are under the `microvm` subcommand:
//! - exec: Persistent execution (microvm keeps running)
//! - create: Create named VM configuration
//! - start: Start a microvm (named or default)
//! - stop: Stop a microvm (named or default)
//! - delete: Delete a named VM configuration
//! - status: Show microvm status
//! - ls: List all named VMs

use crate::cli::parsers::{parse_duration, parse_env_spec, parse_mounts_as_tuples, parse_port};
use crate::cli::{flush_output, format_pid_suffix, truncate};
use clap::{Args, Subcommand};
use smolvm::agent::{AgentClient, AgentManager, HostMount, PortMapping, VmResources};
use smolvm::config::{RecordState, SmolvmConfig, VmRecord};
use std::path::PathBuf;
use std::time::Duration;

/// Manage persistent microVMs
#[derive(Subcommand, Debug)]
pub enum MicrovmCmd {
    /// Run a command directly in the VM (not in a container)
    Exec(ExecCmd),

    /// Create a new named microVM configuration
    Create(CreateCmd),

    /// Start a microVM
    Start(StartCmd),

    /// Stop a running microVM
    Stop(StopCmd),

    /// Delete a microVM configuration
    #[command(visible_alias = "rm")]
    Delete(DeleteCmd),

    /// Show microVM status
    Status(StatusCmd),

    /// List all microVMs
    #[command(visible_alias = "list")]
    Ls(LsCmd),

    /// Test network connectivity from inside the VM
    #[command(hide = true)]
    NetworkTest(NetworkTestCmd),
}

impl MicrovmCmd {
    pub fn run(self) -> smolvm::Result<()> {
        match self {
            MicrovmCmd::Exec(cmd) => cmd.run(),
            MicrovmCmd::Create(cmd) => cmd.run(),
            MicrovmCmd::Start(cmd) => cmd.run(),
            MicrovmCmd::Stop(cmd) => cmd.run(),
            MicrovmCmd::Delete(cmd) => cmd.run(),
            MicrovmCmd::Status(cmd) => cmd.run(),
            MicrovmCmd::Ls(cmd) => cmd.run(),
            MicrovmCmd::NetworkTest(cmd) => cmd.run(),
        }
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
///   smolvm microvm exec -- uname -a
///   smolvm microvm exec --name myvm -- df -h
///   smolvm microvm exec -it -- /bin/sh
#[derive(Args, Debug)]
pub struct ExecCmd {
    /// Command and arguments to execute
    #[arg(trailing_var_arg = true, required = true, value_name = "COMMAND")]
    pub command: Vec<String>,

    /// Target microVM (default: "default")
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,

    /// Set working directory in the VM
    #[arg(short = 'w', long, value_name = "DIR")]
    pub workdir: Option<String>,

    /// Set environment variable (can be used multiple times)
    #[arg(short = 'e', long = "env", value_name = "KEY=VALUE")]
    pub env: Vec<String>,

    /// Kill command after duration (e.g., "30s", "5m")
    #[arg(long, value_parser = parse_duration, value_name = "DURATION")]
    pub timeout: Option<Duration>,

    /// Keep stdin open for interactive input
    #[arg(short = 'i', long)]
    pub interactive: bool,

    /// Allocate a pseudo-TTY (use with -i for shells)
    #[arg(short = 't', long)]
    pub tty: bool,
}

impl ExecCmd {
    pub fn run(self) -> smolvm::Result<()> {
        let manager = get_manager(&self.name)?;
        let label = microvm_label(&self.name);

        // Check if microvm is running - exec requires a running VM
        if manager.try_connect_existing().is_none() {
            return Err(smolvm::Error::AgentError(format!(
                "microvm '{}' is not running. Use 'smolvm microvm start' first.",
                label
            )));
        }

        // Connect to agent
        let mut client = AgentClient::connect_with_retry(manager.vsock_socket())?;

        // Parse environment variables
        let env: Vec<(String, String)> =
            self.env.iter().filter_map(|e| parse_env_spec(e)).collect();

        // Run command directly in VM
        let exit_code = if self.interactive || self.tty {
            client.vm_exec_interactive(
                self.command.clone(),
                env,
                self.workdir.clone(),
                self.timeout,
                self.tty,
            )?
        } else {
            let (exit_code, stdout, stderr) = client.vm_exec(
                self.command.clone(),
                env,
                self.workdir.clone(),
                self.timeout,
            )?;

            if !stdout.is_empty() {
                print!("{}", stdout);
            }
            if !stderr.is_empty() {
                eprint!("{}", stderr);
            }
            flush_output();
            exit_code
        };

        // Keep microvm running (persistent)
        manager.detach();
        std::process::exit(exit_code);
    }
}

// ============================================================================
// Create Command
// ============================================================================

/// Create a named microVM configuration.
///
/// Creates a persistent VM configuration that can be started later.
/// Use `smolvm microvm start <name>` to start, then `smolvm container`
/// commands to run containers inside.
///
/// Examples:
///   smolvm microvm create myvm
///   smolvm microvm create webserver --cpus 2 --mem 1024 -p 80:80
#[derive(Args, Debug)]
pub struct CreateCmd {
    /// Name for the microVM
    #[arg(value_name = "NAME")]
    pub name: String,

    /// Number of virtual CPUs
    #[arg(long, default_value = "1", value_name = "N")]
    pub cpus: u8,

    /// Memory allocation in MiB
    #[arg(long, default_value = "512", value_name = "MiB")]
    pub mem: u32,

    /// Mount host directory (can be used multiple times)
    #[arg(short = 'v', long = "volume", value_name = "HOST:GUEST[:ro]")]
    pub volume: Vec<String>,

    /// Expose port from VM to host (can be used multiple times)
    #[arg(short = 'p', long = "port", value_parser = parse_port, value_name = "HOST:GUEST")]
    pub port: Vec<PortMapping>,

    /// Enable outbound network access
    #[arg(long)]
    pub net: bool,
}

impl CreateCmd {
    pub fn run(self) -> smolvm::Result<()> {
        let mut config = SmolvmConfig::load()?;

        // Check if VM already exists
        if config.get_vm(&self.name).is_some() {
            return Err(smolvm::Error::Config(format!(
                "VM '{}' already exists",
                self.name
            )));
        }

        // Parse and validate volume mounts
        let mounts = parse_mounts_as_tuples(&self.volume)?;

        // Convert port mappings to tuple format for storage
        let ports: Vec<(u16, u16)> = self.port.iter().map(|p| (p.host, p.guest)).collect();

        // Create record
        let record = VmRecord::new(
            self.name.clone(),
            self.cpus,
            self.mem,
            mounts,
            ports,
            self.net,
        );

        // Store in config (persisted immediately to database)
        config.insert_vm(self.name.clone(), record)?;

        println!("Created microvm: {}", self.name);
        println!("  CPUs: {}, Memory: {} MiB", self.cpus, self.mem);
        if !self.volume.is_empty() {
            println!("  Mounts: {}", self.volume.len());
        }
        if !self.port.is_empty() {
            println!("  Ports: {}", self.port.len());
        }
        println!(
            "\nUse 'smolvm microvm start {}' to start the microvm",
            self.name
        );
        println!(
            "Then use 'smolvm container create {}' to run containers",
            self.name
        );

        Ok(())
    }
}

// ============================================================================
// Start Command
// ============================================================================

/// Start a microVM.
///
/// Starts the VM process. If no name is given, starts the default VM.
#[derive(Args, Debug)]
pub struct StartCmd {
    /// MicroVM to start (default: "default")
    #[arg(value_name = "NAME")]
    pub name: Option<String>,
}

impl StartCmd {
    pub fn run(self) -> smolvm::Result<()> {
        use smolvm::Error;

        // If no name provided, start default anonymous microvm
        let Some(name) = &self.name else {
            return self.start_anonymous();
        };
        let mut config = SmolvmConfig::load()?;

        // Get VM record
        let record = config
            .get_vm(name)
            .ok_or_else(|| Error::VmNotFound(name.clone()))?
            .clone();

        // Check state
        let actual_state = record.actual_state();
        if actual_state == RecordState::Running {
            let pid_suffix = format_pid_suffix(record.pid);
            println!("MicroVM '{}' already running{}", name, pid_suffix);
            return Ok(());
        }

        // Convert stored mounts to HostMount
        let mounts: Vec<HostMount> = record
            .mounts
            .iter()
            .map(|(host, guest, ro)| HostMount {
                source: PathBuf::from(host),
                target: PathBuf::from(guest),
                read_only: *ro,
            })
            .collect();

        // Convert stored ports to PortMapping
        let ports: Vec<PortMapping> = record
            .ports
            .iter()
            .map(|(host, guest)| PortMapping::new(*host, *guest))
            .collect();

        let resources = VmResources {
            cpus: record.cpus,
            mem: record.mem,
            network: record.network,
        };

        // Start agent VM for this named VM
        let manager = AgentManager::for_vm(name)
            .map_err(|e| Error::AgentError(format!("failed to create agent manager: {}", e)))?;

        // Show startup message
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
        println!("Starting microvm '{}'{}{}...", name, mount_info, port_info);

        manager
            .ensure_running_with_full_config(mounts, ports, resources)
            .map_err(|e| Error::AgentError(format!("failed to start microvm: {}", e)))?;

        // Update state
        let pid = manager.child_pid();
        config.update_vm(name, |r| {
            r.state = RecordState::Running;
            r.pid = pid;
        });
        config.save()?;

        println!("MicroVM '{}' running (PID: {})", name, pid.unwrap_or(0));
        println!(
            "\nUse 'smolvm container create {} <image>' to run containers",
            name
        );

        // Keep microvm running (persistent)
        manager.detach();
        Ok(())
    }

    fn start_anonymous(&self) -> smolvm::Result<()> {
        let manager = AgentManager::new_default()?;

        // Check if already running
        if manager.try_connect_existing().is_some() {
            let pid_suffix = format_pid_suffix(manager.child_pid());
            println!("MicroVM 'default' already running{}", pid_suffix);
            manager.detach();
            return Ok(());
        }

        println!("Starting microvm 'default'...");
        manager.ensure_running()?;

        let pid = manager.child_pid().unwrap_or(0);
        println!("MicroVM 'default' running (PID: {})", pid);

        manager.detach();
        Ok(())
    }
}

// ============================================================================
// Stop Command
// ============================================================================

/// Stop a running microVM.
///
/// Gracefully stops the VM process. Running containers will be terminated.
#[derive(Args, Debug)]
pub struct StopCmd {
    /// MicroVM to stop (default: "default")
    #[arg(value_name = "NAME")]
    pub name: Option<String>,
}

impl StopCmd {
    pub fn run(self) -> smolvm::Result<()> {
        // If no name provided, stop default anonymous microvm
        let Some(name) = &self.name else {
            return self.stop_anonymous();
        };
        let mut config = SmolvmConfig::load()?;

        // Get VM record
        let record = match config.get_vm(name) {
            Some(r) => r.clone(),
            None => {
                // Maybe it's a running anonymous microvm with this name?
                return self.stop_named_microvm(name);
            }
        };

        // Check state
        let actual_state = record.actual_state();
        if actual_state != RecordState::Running {
            println!("VM '{}' is not running (state: {})", name, actual_state);
            return Ok(());
        }

        println!("Stopping VM '{}'...", name);

        // Stop this VM's agent
        if let Ok(manager) = AgentManager::for_vm(name) {
            if let Err(e) = manager.stop() {
                tracing::warn!(error = %e, "failed to stop microvm");
            }
        }

        // Update state
        config.update_vm(name, |r| {
            r.state = RecordState::Stopped;
            r.pid = None;
        });
        config.save()?;

        println!("Stopped VM: {}", name);
        Ok(())
    }

    fn stop_anonymous(&self) -> smolvm::Result<()> {
        let manager = AgentManager::new_default()?;

        if manager.try_connect_existing().is_some() {
            println!("Stopping microvm 'default'...");
            manager.stop()?;
            println!("MicroVM 'default' stopped");
        } else {
            println!("MicroVM 'default' not running");
        }

        Ok(())
    }

    fn stop_named_microvm(&self, name: &str) -> smolvm::Result<()> {
        if let Ok(manager) = AgentManager::for_vm(name) {
            if manager.try_connect_existing().is_some() {
                println!("Stopping microvm '{}'...", name);
                manager.stop()?;
                println!("MicroVM '{}' stopped", name);
            } else {
                println!("MicroVM '{}' not running", name);
            }
        } else {
            println!("MicroVM '{}' not found", name);
        }
        Ok(())
    }
}

// ============================================================================
// Delete Command
// ============================================================================

/// Delete a microVM configuration.
///
/// Removes the VM configuration. Does not delete container data.
#[derive(Args, Debug)]
pub struct DeleteCmd {
    /// MicroVM to delete
    #[arg(value_name = "NAME")]
    pub name: String,

    /// Skip confirmation prompt
    #[arg(short, long)]
    pub force: bool,
}

impl DeleteCmd {
    pub fn run(&self) -> smolvm::Result<()> {
        let mut config = SmolvmConfig::load()?;

        // Check if VM exists
        if config.get_vm(&self.name).is_none() {
            return Err(smolvm::Error::VmNotFound(self.name.clone()));
        }

        // Confirm deletion unless --force
        if !self.force {
            eprint!("Delete VM '{}'? [y/N] ", self.name);
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
        config.remove_vm(&self.name);
        config.save()?;

        println!("Deleted VM: {}", self.name);
        Ok(())
    }
}

// ============================================================================
// Status Command
// ============================================================================

/// Show microVM status.
///
/// Displays whether the VM is running and its process ID.
#[derive(Args, Debug)]
pub struct StatusCmd {
    /// MicroVM to check (default: "default")
    #[arg(value_name = "NAME")]
    pub name: Option<String>,
}

impl StatusCmd {
    pub fn run(self) -> smolvm::Result<()> {
        let manager = get_manager(&self.name)?;
        let label = microvm_label(&self.name);

        if manager.try_connect_existing().is_some() {
            let pid_suffix = format_pid_suffix(manager.child_pid());
            println!("MicroVM '{}': running{}", label, pid_suffix);
            manager.detach();
        } else {
            println!("MicroVM '{}': stopped", label);
        }

        Ok(())
    }
}

// ============================================================================
// Ls Command
// ============================================================================

/// List all microVMs.
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
        let config = SmolvmConfig::load()?;
        let vms: Vec<_> = config.list_vms().collect();

        if vms.is_empty() {
            if !self.json {
                println!("No VMs found");
            } else {
                println!("[]");
            }
            return Ok(());
        }

        if self.json {
            let json_vms: Vec<_> = vms
                .iter()
                .map(|(name, record)| {
                    let actual_state = record.actual_state();
                    serde_json::json!({
                        "name": name,
                        "state": actual_state.to_string(),
                        "cpus": record.cpus,
                        "memory_mib": record.mem,
                        "pid": record.pid,
                        "mounts": record.mounts.len(),
                        "ports": record.ports.len(),
                        "created_at": record.created_at,
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&json_vms).expect("JSON serialization failed")
            );
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

                if self.verbose {
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
                    println!("  Created: {}", record.created_at);
                    println!();
                }
            }
        }

        Ok(())
    }
}

// ============================================================================
// Network Test Command
// ============================================================================

/// Test network connectivity directly from microvm (debug TSI).
#[derive(Args, Debug)]
pub struct NetworkTestCmd {
    /// Named microvm to test (omit for default anonymous)
    #[arg(long)]
    pub name: Option<String>,

    /// URL to test
    #[arg(default_value = "http://1.1.1.1")]
    pub url: String,
}

impl NetworkTestCmd {
    pub fn run(self) -> smolvm::Result<()> {
        let manager = get_manager(&self.name)?;
        let label = microvm_label(&self.name);

        // Ensure microvm is running
        if manager.try_connect_existing().is_none() {
            println!("Starting microvm '{}'...", label);
            manager.ensure_running()?;
        }

        // Connect and test
        println!("Testing network from microvm: {}", self.url);
        let mut client = manager.connect()?;
        let result = client.network_test(&self.url)?;

        println!(
            "Result: {}",
            serde_json::to_string_pretty(&result).unwrap_or_default()
        );

        manager.detach();
        Ok(())
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Get the agent manager for a name (or default if None).
fn get_manager(name: &Option<String>) -> smolvm::Result<AgentManager> {
    if let Some(name) = name {
        AgentManager::for_vm(name)
    } else {
        AgentManager::new_default()
    }
}

/// Format the microvm label for display.
fn microvm_label(name: &Option<String>) -> String {
    name.as_deref().unwrap_or("default").to_string()
}
