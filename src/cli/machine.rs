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
use crate::cli::parsers::{mounts_to_virtiofs_bindings, parse_duration, parse_env_list};
use crate::cli::vm_common::{self, DeleteVmOptions, VmKind};
use clap::{Args, Subcommand};
use smolvm::agent::{docker_config_mount, AgentClient, AgentManager, RunConfig, VmResources};
use smolvm::data::network::PortMapping;
use smolvm::data::resources::{DEFAULT_MICROVM_CPU_COUNT, DEFAULT_MICROVM_MEMORY_MIB};
use smolvm::data::storage::HostMount;
use smolvm::{DEFAULT_IDLE_CMD, DEFAULT_SHELL_CMD};
use std::path::PathBuf;
use std::time::Duration;

const KIND: VmKind = VmKind::Machine;

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

    /// Resize a machine's disk resources
    Resize(ResizeCmd),

    /// List cached images and storage usage
    Images(ImagesCmd),

    /// Remove unused images and layers to free disk space
    Prune(PruneCmd),

    /// Test network connectivity from inside the VM
    #[command(hide = true)]
    NetworkTest(NetworkTestCmd),
}

impl MachineCmd {
    pub fn run(self) -> smolvm::Result<()> {
        match self {
            MachineCmd::Run(cmd) => cmd.run(),
            MachineCmd::Exec(cmd) => cmd.run(),
            MachineCmd::Create(cmd) => cmd.run(),
            MachineCmd::Start(cmd) => cmd.run(),
            MachineCmd::Stop(cmd) => cmd.run(),
            MachineCmd::Delete(cmd) => cmd.run(),
            MachineCmd::Status(cmd) => cmd.run(),
            MachineCmd::Ls(cmd) => cmd.run(),
            MachineCmd::Resize(cmd) => cmd.run(),
            MachineCmd::Images(cmd) => cmd.run(),
            MachineCmd::Prune(cmd) => cmd.run(),
            MachineCmd::NetworkTest(cmd) => cmd.run(),
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
    /// Container image (e.g., alpine, ubuntu:22.04, ghcr.io/org/image)
    #[arg(short = 'I', long, value_name = "IMAGE")]
    pub image: String,

    /// Command and arguments to run (default: image entrypoint or /bin/sh)
    #[arg(trailing_var_arg = true, value_name = "COMMAND")]
    pub command: Vec<String>,

    /// Run in background and keep machine alive after command exits
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

    /// Mount ~/.docker/ config into VM for registry authentication
    #[arg(long, help_heading = "Registry")]
    pub docker_config: bool,
}

impl RunCmd {
    pub fn run(self) -> smolvm::Result<()> {
        use smolvm::Error;

        let params = crate::cli::smolfile::build_create_params(
            "default".to_string(),
            Some(self.image.clone()),
            None,
            self.command.clone(),
            self.cpus,
            self.mem,
            self.volume,
            self.port,
            self.net,
            vec![],
            self.env,
            self.workdir,
            self.smolfile,
            self.storage,
            self.overlay,
        )?;

        let mut mounts = HostMount::parse(&params.volume)?;
        let ports = params.port.clone();

        if self.docker_config {
            if let Some(docker_mount) = docker_config_mount() {
                mounts.push(docker_mount);
            } else {
                tracing::warn!("Docker config directory not found");
            }
        }

        let resources = VmResources {
            cpus: params.cpus,
            memory_mib: params.mem,
            network: params.net,
            storage_gib: params.storage_gb,
            overlay_gib: params.overlay_gb,
        };

        let manager = AgentManager::new_default_with_sizes(params.storage_gb, params.overlay_gb)
            .map_err(|e| Error::agent("create agent manager", e.to_string()))?;

        let mode = if self.detach {
            "persistent"
        } else {
            "ephemeral"
        };
        println!("Starting {} machine...", mode);

        let freshly_started = manager
            .ensure_running_with_full_config(mounts.clone(), ports, resources)
            .map_err(|e| Error::agent("start machine", e.to_string()))?;

        let mut client = AgentClient::connect_with_retry(manager.vsock_socket())?;

        crate::cli::pull_with_progress(&mut client, &self.image, self.oci_platform.as_deref())?;

        if freshly_started && !params.init.is_empty() {
            for (i, cmd) in params.init.iter().enumerate() {
                let argv = vec!["sh".into(), "-c".into(), cmd.clone()];
                let init_env = parse_env_list(&params.env);
                let (exit_code, _stdout, stderr) =
                    client.vm_exec(argv, init_env, params.workdir.clone(), None)?;
                if exit_code != 0 {
                    if let Err(e) = manager.stop() {
                        tracing::warn!(error = %e, "failed to stop machine after init failure");
                    }
                    return Err(Error::agent(
                        "init",
                        format!("init[{}] failed (exit {}): {}", i, exit_code, stderr.trim()),
                    ));
                }
            }
        }

        let command = if self.command.is_empty() {
            if self.detach {
                DEFAULT_IDLE_CMD.iter().map(|s| s.to_string()).collect()
            } else {
                vec![DEFAULT_SHELL_CMD.to_string()]
            }
        } else {
            self.command.clone()
        };

        let env = parse_env_list(&params.env);
        let mount_bindings = mounts_to_virtiofs_bindings(&mounts);

        if self.detach {
            let info = client.create_container(
                &self.image,
                command,
                env,
                params.workdir.clone(),
                mount_bindings,
            )?;

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
                if let Ok(mut config) = SmolvmConfig::load() {
                    vm_common::persist_default_running(
                        &mut config,
                        manager.child_pid(),
                        Some(DefaultVmOverrides {
                            cpus: params.cpus,
                            mem: params.mem,
                            mounts: mount_tuples,
                            ports: port_tuples,
                            network: params.net,
                            storage_gb: params.storage_gb,
                            overlay_gb: params.overlay_gb,
                            init: params.init.clone(),
                            env: parse_env_list(&params.env),
                            workdir: params.workdir.clone(),
                            image: Some(self.image.clone()),
                            entrypoint: vec![],
                            cmd: vec![],
                        }),
                    );
                }
            }

            println!("Machine running (container: {})", &info.id[..12]);
            println!("\nTo interact:");
            println!(
                "  smolvm container exec --container {} -- <command>",
                &info.id[..12]
            );
            println!("\nTo stop:");
            println!("  smolvm machine stop");

            manager.detach();
            Ok(())
        } else {
            let exit_code = if self.interactive || self.tty {
                let config = RunConfig::new(&self.image, command)
                    .with_env(env)
                    .with_workdir(params.workdir.clone())
                    .with_mounts(mount_bindings)
                    .with_timeout(self.timeout)
                    .with_tty(self.tty);
                client.run_interactive(config)?
            } else {
                let (exit_code, stdout, stderr) = client.run_with_mounts_and_timeout(
                    &self.image,
                    command,
                    env,
                    params.workdir.clone(),
                    mount_bindings,
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

            if let Err(e) = manager.stop() {
                tracing::warn!(error = %e, "failed to stop machine");
            }
            std::process::exit(exit_code);
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
        let (manager, mut client) =
            vm_common::ensure_running_and_connect(&self.name, vm_common::VmKind::Machine)?;

        let env = parse_env_list(&self.env);

        // Run command directly in VM
        if self.interactive || self.tty {
            let exit_code = client.vm_exec_interactive(
                self.command.clone(),
                env,
                self.workdir.clone(),
                self.timeout,
                self.tty,
            )?;
            manager.detach();
            std::process::exit(exit_code);
        }

        let (exit_code, stdout, stderr) = client.vm_exec(
            self.command.clone(),
            env,
            self.workdir.clone(),
            self.timeout,
        )?;

        vm_common::print_output_and_exit(&manager, exit_code, &stdout, &stderr);
    }
}

// ============================================================================
// Create Command
// ============================================================================

/// Create a named machine configuration.
///
/// Creates a persistent VM configuration that can be started later.
/// Use `smolvm machine start --name <name>` to start, then `smolvm container`
/// commands to run containers inside.
///
/// Examples:
///   smolvm machine create myvm
///   smolvm machine create webserver --cpus 2 --mem 1024 -p 80:80
#[derive(Args, Debug)]
pub struct CreateCmd {
    /// Name for the machine
    #[arg(value_name = "NAME")]
    pub name: String,

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
            None,   // image: from Smolfile only
            None,   // entrypoint: from Smolfile only
            vec![], // cmd: from Smolfile only
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

/// Start a machine.
///
/// Starts the VM process. If no name is given, starts the default VM.
#[derive(Args, Debug)]
pub struct StartCmd {
    /// Machine to start (default: "default")
    #[arg(short = 'n', long, value_name = "NAME")]
    pub name: Option<String>,
}

impl StartCmd {
    pub fn run(self) -> smolvm::Result<()> {
        let name = self.name.unwrap_or_else(|| "default".to_string());
        match vm_common::start_vm_named(KIND, &name) {
            Ok(()) => Ok(()),
            Err(smolvm::Error::VmNotFound { .. }) => vm_common::start_vm_default(KIND),
            Err(e) => Err(e),
        }
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
            Some(name) => vm_common::stop_vm_named(KIND, name),
            None => vm_common::stop_vm_default(KIND),
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

/// Show machine status.
///
/// Displays whether the VM is running and its process ID.
#[derive(Args, Debug)]
pub struct StatusCmd {
    /// Machine to check (default: "default")
    #[arg(short = 'n', long, value_name = "NAME")]
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
        vm_common::list_vms(KIND, self.verbose, self.json)
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

        vm_common::resize_vm(KIND, name_str, self.storage, self.overlay)
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
        if manager.try_connect_existing().is_none() {
            println!("Starting machine '{}'...", label);
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

        manager.detach();
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
///   smolvm machine images
///   smolvm machine images --json
#[derive(Args, Debug)]
pub struct ImagesCmd {
    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

impl ImagesCmd {
    pub fn run(self) -> smolvm::Result<()> {
        let manager = AgentManager::new_default()?;

        let mut client = if manager.try_connect_existing().is_some() {
            AgentClient::connect_with_retry(manager.vsock_socket())?
        } else {
            println!("Starting machine to query storage...");
            manager.start()?;
            AgentClient::connect_with_retry(manager.vsock_socket())?
        };

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
///   smolvm machine prune --dry-run
///   smolvm machine prune
///   smolvm machine prune --all
#[derive(Args, Debug)]
pub struct PruneCmd {
    /// Show what would be removed without actually removing
    #[arg(long)]
    pub dry_run: bool,

    /// Remove all cached images (not just unreferenced layers)
    #[arg(long)]
    pub all: bool,
}

impl PruneCmd {
    pub fn run(self) -> smolvm::Result<()> {
        let manager = AgentManager::new_default()?;

        let mut client = if manager.try_connect_existing().is_some() {
            AgentClient::connect_with_retry(manager.vsock_socket())?
        } else {
            println!("Starting machine...");
            manager.start()?;
            AgentClient::connect_with_retry(manager.vsock_socket())?
        };

        if self.all {
            let images = client.list_images()?;

            if images.is_empty() {
                println!("No cached images to remove.");
                return Ok(());
            }

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
                let freed = client.garbage_collect(false)?;
                println!("Freed {} of unreferenced layers", format_bytes(freed));
            }
        } else if self.dry_run {
            println!("Scanning for unreferenced layers...");
            let would_free = client.garbage_collect(true)?;

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
            let freed = client.garbage_collect(false)?;

            if freed > 0 {
                println!("Freed {}", format_bytes(freed));
            } else {
                println!("No unreferenced layers to remove.");
            }
        }

        Ok(())
    }
}
