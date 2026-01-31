//! Sandbox commands for quick container execution.
//!
//! The sandbox provides a simple, well-defined entry point for running
//! containers in an ephemeral microVM. It handles all the setup:
//! - Starts an agent VM with sensible defaults
//! - Pulls the OCI image
//! - Runs the container
//! - Cleans up after execution

use crate::cli::parsers::{
    mounts_to_virtiofs_bindings, parse_duration, parse_env_spec, parse_mounts, parse_port,
};
use crate::cli::{flush_output, format_pid_suffix, truncate_id};
use clap::{Args, Subcommand};
use smolvm::agent::{
    docker_config_mount, AgentClient, AgentManager, PortMapping, RunConfig, VmResources,
};
use std::time::Duration;

/// Quick sandbox commands for running containers
#[derive(Subcommand, Debug)]
pub enum SandboxCmd {
    /// Run a container image (ephemeral by default, use -d to keep running)
    Run(RunCmd),

    /// Execute a command in an existing sandbox container
    Exec(ExecCmd),

    /// Stop the sandbox and clean up
    Stop(StopCmd),

    /// Show sandbox status and running containers
    Status(StatusCmd),

    /// List cached images and storage usage
    Images(ImagesCmd),

    /// Remove unused images and layers to free disk space
    Prune(PruneCmd),
}

impl SandboxCmd {
    pub fn run(self) -> smolvm::Result<()> {
        match self {
            SandboxCmd::Run(cmd) => cmd.run(),
            SandboxCmd::Exec(cmd) => cmd.run(),
            SandboxCmd::Stop(cmd) => cmd.run(),
            SandboxCmd::Status(cmd) => cmd.run(),
            SandboxCmd::Images(cmd) => cmd.run(),
            SandboxCmd::Prune(cmd) => cmd.run(),
        }
    }
}

// ============================================================================
// Exec Command
// ============================================================================

/// Execute a command in the running sandbox container.
///
/// Requires a sandbox started with `sandbox run -d`. Use `sandbox status`
/// to check if a sandbox is running.
///
/// Examples:
///   smolvm sandbox exec -- ls -la
///   smolvm sandbox exec -- python script.py
///   smolvm sandbox exec -e FOO=bar -- env
#[derive(Args, Debug)]
pub struct ExecCmd {
    /// Command and arguments to execute
    #[arg(trailing_var_arg = true, required = true, value_name = "COMMAND")]
    pub command: Vec<String>,

    /// Set working directory inside container
    #[arg(short = 'w', long, value_name = "DIR")]
    pub workdir: Option<String>,

    /// Set environment variable (can be used multiple times)
    #[arg(short = 'e', long = "env", value_name = "KEY=VALUE")]
    pub env: Vec<String>,

    /// Kill command after duration (e.g., "30s", "5m")
    #[arg(long, value_parser = parse_duration, value_name = "DURATION")]
    pub timeout: Option<Duration>,
}

impl ExecCmd {
    pub fn run(self) -> smolvm::Result<()> {
        use smolvm::Error;

        let manager = AgentManager::new_default()?;

        // Check if sandbox is running
        if manager.try_connect_existing().is_none() {
            return Err(Error::AgentError(
                "No sandbox running. Start one with: smolvm sandbox run -d <image>".to_string(),
            ));
        }

        let mut client = AgentClient::connect(manager.vsock_socket())?;

        // Find the container in the sandbox
        let containers = client.list_containers()?;
        let container = containers.iter().find(|c| c.state == "running");

        let container_id = match container {
            Some(c) => c.id.clone(),
            None => {
                return Err(Error::AgentError(
                    "No running container in sandbox".to_string(),
                ));
            }
        };

        // Parse environment variables
        let env: Vec<(String, String)> = self
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

        // Execute in container
        let (exit_code, stdout, stderr) = client.exec(
            &container_id,
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

        // Keep sandbox running
        std::mem::forget(manager);
        std::process::exit(exit_code);
    }
}

// ============================================================================
// Stop Command
// ============================================================================

/// Stop a running sandbox.
#[derive(Args, Debug)]
pub struct StopCmd;

impl StopCmd {
    pub fn run(self) -> smolvm::Result<()> {
        let manager = AgentManager::new_default()?;

        if manager.try_connect_existing().is_some() {
            println!("Stopping sandbox...");
            manager.stop()?;
            println!("Sandbox stopped");
        } else {
            println!("No sandbox running");
        }

        Ok(())
    }
}

// ============================================================================
// Status Command
// ============================================================================

/// Show sandbox status.
#[derive(Args, Debug)]
pub struct StatusCmd;

impl StatusCmd {
    pub fn run(self) -> smolvm::Result<()> {
        let manager = AgentManager::new_default()?;

        if manager.try_connect_existing().is_some() {
            let pid_suffix = format_pid_suffix(manager.child_pid());
            println!("Sandbox: running{}", pid_suffix);

            // Try to list containers
            if let Ok(mut client) = AgentClient::connect(manager.vsock_socket()) {
                if let Ok(containers) = client.list_containers() {
                    if !containers.is_empty() {
                        println!("\nContainers:");
                        for c in containers {
                            println!("  {} {} ({})", truncate_id(&c.id), c.image, c.state);
                        }
                    }
                }
            }

            std::mem::forget(manager);
        } else {
            println!("Sandbox: not running");
        }

        Ok(())
    }
}

// ============================================================================
// Run Command
// ============================================================================

/// Run a container in a sandbox.
///
/// By default, runs in ephemeral mode (container + VM cleaned up after exit).
/// Use -d/--detach to keep the sandbox running for later interaction.
///
/// Examples:
///   smolvm sandbox run alpine -- echo "Hello"     # Ephemeral, exits after
///   smolvm sandbox run -it alpine                  # Interactive shell
///   smolvm sandbox run -d ubuntu                   # Detached, keeps running
///   smolvm sandbox run -d -p 8080:80 nginx        # Web server with port
///   smolvm sandbox run -v ./src:/app node -- npm start
#[derive(Args, Debug)]
pub struct RunCmd {
    /// Container image (e.g., alpine, ubuntu:22.04, ghcr.io/org/image)
    #[arg(value_name = "IMAGE")]
    pub image: String,

    /// Command and arguments to run (default: image entrypoint or /bin/sh)
    #[arg(trailing_var_arg = true, value_name = "COMMAND")]
    pub command: Vec<String>,

    /// Run in background and keep sandbox alive after command exits
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

    /// Target platform for multi-arch images (e.g., linux/arm64, linux/amd64)
    ///
    /// By default, uses the host architecture. Use this to override, for example
    /// to run x86_64 images via Rosetta on Apple Silicon.
    #[arg(long, value_name = "OS/ARCH", help_heading = "Container")]
    pub platform: Option<String>,

    /// Mount host directory into container (can be used multiple times)
    #[arg(
        short = 'v',
        long = "volume",
        value_name = "HOST:CONTAINER[:ro]",
        help_heading = "Container"
    )]
    pub volume: Vec<String>,

    /// Expose port from container to host (can be used multiple times)
    #[arg(short = 'p', long = "port", value_parser = parse_port, value_name = "HOST:GUEST", help_heading = "Network")]
    pub port: Vec<PortMapping>,

    /// Enable outbound network access
    #[arg(long, help_heading = "Network")]
    pub net: bool,

    /// Number of virtual CPUs
    #[arg(
        long,
        default_value = "1",
        value_name = "N",
        help_heading = "Resources"
    )]
    pub cpus: u8,

    /// Memory allocation in MiB
    #[arg(
        long,
        default_value = "512",
        value_name = "MiB",
        help_heading = "Resources"
    )]
    pub mem: u32,

    /// Mount ~/.docker/ config into VM for registry authentication
    ///
    /// When enabled, the Docker config directory (typically ~/.docker/) is
    /// mounted into the VM at /root/.docker/, allowing crane to use Docker
    /// credentials for private registry access and authenticated pulls.
    #[arg(long, help_heading = "Registry")]
    pub docker_config: bool,
}

impl RunCmd {
    pub fn run(self) -> smolvm::Result<()> {
        use smolvm::Error;

        // Parse volume mounts
        let mut mounts = parse_mounts(&self.volume)?;
        let ports = self.port.clone();

        // Add docker config mount if requested
        if self.docker_config {
            if let Some(docker_mount) = docker_config_mount() {
                mounts.push(docker_mount);
            } else {
                tracing::warn!(
                    "Docker config directory not found, --docker-config will have no effect"
                );
            }
        }

        let resources = VmResources {
            cpus: self.cpus,
            mem: self.mem,
        };

        // Start agent VM
        let manager = AgentManager::new_default()
            .map_err(|e| Error::AgentError(format!("failed to create agent manager: {}", e)))?;

        // Show startup message
        let mode = if self.detach {
            "persistent"
        } else {
            "ephemeral"
        };
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
        println!("Starting {} sandbox{}{}...", mode, mount_info, port_info);

        manager
            .ensure_running_with_full_config(mounts.clone(), ports, resources)
            .map_err(|e| Error::AgentError(format!("failed to start sandbox: {}", e)))?;

        // Connect to agent
        let mut client = AgentClient::connect(manager.vsock_socket())?;

        // Pull image with progress display
        // Use registry config for automatic credential lookup
        print!("Pulling image {}...", self.image);
        let _ = std::io::Write::flush(&mut std::io::stdout());

        let mut last_percent = 0u8;
        client.pull_with_registry_config_and_progress(
            &self.image,
            self.platform.as_deref(),
            |percent, _total, _layer| {
                let percent = percent as u8;
                if percent != last_percent && percent <= 100 {
                    // Clear line and show progress bar
                    print!("\rPulling image {}... [", self.image);
                    let filled = (percent as usize) / 5; // 20 chars wide
                    for i in 0..20 {
                        if i < filled {
                            print!("=");
                        } else if i == filled {
                            print!(">");
                        } else {
                            print!(" ");
                        }
                    }
                    print!("] {}%", percent);
                    let _ = std::io::Write::flush(&mut std::io::stdout());
                    last_percent = percent;
                }
            },
        )?;
        println!(
            "\rPulling image {}... done.                              ",
            self.image
        );

        // Build command - for detached mode, default to sleep infinity
        let command = if self.command.is_empty() {
            if self.detach {
                vec!["sleep".to_string(), "infinity".to_string()]
            } else {
                vec!["/bin/sh".to_string()]
            }
        } else {
            self.command.clone()
        };

        // Parse environment variables
        let env: Vec<(String, String)> =
            self.env.iter().filter_map(|e| parse_env_spec(e)).collect();

        // Convert mounts to agent format
        let mount_bindings = mounts_to_virtiofs_bindings(&mounts);

        if self.detach {
            // Detached/persistent mode: create container and keep running
            let info = client.create_container(
                &self.image,
                command,
                env,
                self.workdir.clone(),
                mount_bindings,
            )?;

            println!("Sandbox running (container: {})", &info.id[..12]);
            println!("\nTo interact with the sandbox:");
            println!(
                "  smolvm container exec default {} -- <command>",
                &info.id[..12]
            );
            println!(
                "  smolvm container exec default {} -it -- /bin/sh",
                &info.id[..12]
            );
            println!("\nTo stop the sandbox:");
            println!("  smolvm sandbox stop");

            // Keep sandbox running
            std::mem::forget(manager);
            Ok(())
        } else {
            // Ephemeral mode: run command and clean up
            let exit_code = if self.interactive || self.tty {
                let config = RunConfig::new(&self.image, command)
                    .with_env(env)
                    .with_workdir(self.workdir.clone())
                    .with_mounts(mount_bindings)
                    .with_timeout(self.timeout)
                    .with_tty(self.tty);
                client.run_interactive(config)?
            } else {
                let (exit_code, stdout, stderr) = client.run_with_mounts_and_timeout(
                    &self.image,
                    command,
                    env,
                    self.workdir.clone(),
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

            // Stop the sandbox (ephemeral mode)
            if let Err(e) = manager.stop() {
                tracing::warn!(error = %e, "failed to stop sandbox");
            }

            std::process::exit(exit_code);
        }
    }
}

// ============================================================================
// Images Command
// ============================================================================

/// List cached images and storage usage.
///
/// Shows all OCI images cached in the sandbox storage, along with their
/// sizes and layer counts. Also displays total storage usage.
///
/// Examples:
///   smolvm sandbox images
///   smolvm sandbox images --json
#[derive(Args, Debug)]
pub struct ImagesCmd {
    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

impl ImagesCmd {
    pub fn run(self) -> smolvm::Result<()> {
        let manager = AgentManager::new_default()?;

        // Start VM if not running (needed to query storage)
        let mut client = if manager.try_connect_existing().is_some() {
            AgentClient::connect(manager.vsock_socket())?
        } else {
            println!("Starting sandbox VM to query storage...");
            manager.start()?;
            AgentClient::connect(manager.vsock_socket())?
        };

        // Get storage status
        let status = client.storage_status()?;

        // Get images list
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
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
        } else {
            // Print storage summary
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
///   smolvm sandbox prune --dry-run
///   smolvm sandbox prune
///   smolvm sandbox prune --all
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

        // Start VM if not running
        let mut client = if manager.try_connect_existing().is_some() {
            AgentClient::connect(manager.vsock_socket())?
        } else {
            println!("Starting sandbox VM...");
            manager.start()?;
            AgentClient::connect(manager.vsock_socket())?
        };

        if self.all {
            // Get list of images first
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

                // Remove each image by clearing storage
                // Note: This requires a storage clear API which we may need to add
                // For now, we use garbage_collect which only removes unreferenced layers
                let freed = client.garbage_collect(false)?;

                println!("Freed {} of unreferenced layers", format_bytes(freed));
                println!();
                println!(
                    "Note: To remove all images, stop the sandbox and delete the storage disk:"
                );
                println!("  smolvm sandbox stop");
                println!("  rm ~/.smolvm/vms/default/storage.raw");
            }
        } else {
            // Just garbage collect unreferenced layers
            if self.dry_run {
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
        }

        Ok(())
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Format bytes as human-readable string.
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}
