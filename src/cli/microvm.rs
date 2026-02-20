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

use crate::cli::flush_output;
use crate::cli::parsers::{parse_duration, parse_env_list, parse_port};
use crate::cli::vm_common::{self, DeleteVmOptions, VmKind};
use clap::{Args, Subcommand};
use smolvm::agent::{AgentClient, PortMapping};
use std::path::PathBuf;
use std::time::Duration;

const KIND: VmKind = VmKind::Microvm;

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
        let manager = vm_common::get_vm_manager(&self.name)?;
        let label = vm_common::vm_label(&self.name);

        // Check if microvm is running - exec requires a running VM
        if manager.try_connect_existing().is_none() {
            return Err(smolvm::Error::agent(
                "exec command",
                format!(
                    "microvm '{}' is not running. Use 'smolvm microvm start' first.",
                    label
                ),
            ));
        }

        // Connect to agent
        let mut client = AgentClient::connect_with_retry(manager.vsock_socket())?;

        // Parse environment variables
        let env = parse_env_list(&self.env);

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
    #[arg(long, default_value_t = smolvm::agent::DEFAULT_CPUS, value_name = "N")]
    pub cpus: u8,

    /// Memory allocation in MiB
    #[arg(long, default_value_t = smolvm::agent::DEFAULT_MEMORY_MIB, value_name = "MiB")]
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
    #[arg(short = 'p', long = "port", value_parser = parse_port, value_name = "HOST:GUEST")]
    pub port: Vec<PortMapping>,

    /// Enable outbound network access
    #[arg(long)]
    pub net: bool,

    /// Run command on every VM start (can be used multiple times)
    #[arg(long = "init", value_name = "COMMAND")]
    pub init: Vec<String>,

    /// Set environment variable for init commands (can be used multiple times)
    #[arg(short = 'e', long = "env", value_name = "KEY=VALUE")]
    pub env: Vec<String>,

    /// Set working directory for init commands
    #[arg(short = 'w', long = "workdir", value_name = "DIR")]
    pub workdir: Option<String>,

    /// Load configuration from a Smolfile (TOML)
    #[arg(long = "smolfile", visible_short_alias = 's', value_name = "PATH")]
    pub smolfile: Option<PathBuf>,
}

impl CreateCmd {
    pub fn run(self) -> smolvm::Result<()> {
        let params = crate::cli::smolfile::build_create_params(
            self.name,
            self.cpus,
            self.mem,
            self.volume,
            self.port,
            self.net,
            self.init,
            self.env,
            self.workdir,
            self.smolfile,
            self.storage,
            self.overlay,
        )?;
        vm_common::create_vm(KIND, params)
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
        let name = vm_common::resolve_vm_name(self.name)?;
        match &name {
            Some(name) => vm_common::start_vm_named(KIND, name),
            None => vm_common::start_vm_anonymous(KIND),
        }
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
        let name = vm_common::resolve_vm_name(self.name)?;
        match &name {
            Some(name) => vm_common::stop_vm_named(KIND, name),
            None => vm_common::stop_vm_anonymous(KIND),
        }
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
        vm_common::delete_vm(
            KIND,
            &self.name,
            self.force,
            DeleteVmOptions {
                stop_if_running: false,
            },
        )
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
        vm_common::status_vm(KIND, &self.name, |_| {})
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
        vm_common::list_vms(KIND, self.verbose, self.json)
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
        let manager = vm_common::get_vm_manager(&self.name)?;
        let label = vm_common::vm_label(&self.name);

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
