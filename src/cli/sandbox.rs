//! Sandbox commands for quick container execution.
//!
//! The sandbox provides a simple, well-defined entry point for running
//! containers in an ephemeral microVM. It handles all the setup:
//! - Starts an agent VM with sensible defaults
//! - Pulls the OCI image
//! - Runs the container
//! - Cleans up after execution

use clap::{Args, Subcommand};
use smolvm::agent::{AgentClient, AgentManager, HostMount, PortMapping, VmResources};
use std::path::PathBuf;
use std::time::Duration;

/// Parse a duration string (e.g., "30s", "5m", "1h").
fn parse_duration(s: &str) -> Result<Duration, humantime::DurationError> {
    humantime::parse_duration(s)
}

/// Parse a port mapping specification (HOST:GUEST or PORT).
fn parse_port(s: &str) -> Result<PortMapping, String> {
    if let Some((host, guest)) = s.split_once(':') {
        let host: u16 = host
            .parse()
            .map_err(|_| format!("invalid host port: {}", host))?;
        let guest: u16 = guest
            .parse()
            .map_err(|_| format!("invalid guest port: {}", guest))?;
        Ok(PortMapping::new(host, guest))
    } else {
        let port: u16 = s.parse().map_err(|_| format!("invalid port: {}", s))?;
        Ok(PortMapping::same(port))
    }
}

/// Parse an environment variable specification (KEY=VALUE).
fn parse_env_spec(spec: &str) -> Option<(String, String)> {
    let (key, value) = spec.split_once('=')?;
    if key.is_empty() {
        return None;
    }
    Some((key.to_string(), value.to_string()))
}

/// Quick sandbox commands for running containers
#[derive(Subcommand, Debug)]
pub enum SandboxCmd {
    /// Run a container in a sandbox (ephemeral or persistent with -d)
    Run(RunCmd),

    /// Execute a command in the running sandbox
    Exec(ExecCmd),

    /// Stop a running sandbox
    Stop(StopCmd),

    /// Show sandbox status
    Status(StatusCmd),
}

impl SandboxCmd {
    pub fn run(self) -> smolvm::Result<()> {
        match self {
            SandboxCmd::Run(cmd) => cmd.run(),
            SandboxCmd::Exec(cmd) => cmd.run(),
            SandboxCmd::Stop(cmd) => cmd.run(),
            SandboxCmd::Status(cmd) => cmd.run(),
        }
    }
}

// ============================================================================
// Exec Command
// ============================================================================

/// Execute a command in the running sandbox.
///
/// This finds the container in the sandbox and runs a command inside it.
///
/// Examples:
///   smolvm sandbox exec -- ls -la
///   smolvm sandbox exec -- python script.py
///   smolvm sandbox exec -e FOO=bar -- env
#[derive(Args, Debug)]
pub struct ExecCmd {
    /// Command to execute
    #[arg(trailing_var_arg = true, required = true)]
    pub command: Vec<String>,

    /// Working directory inside container
    #[arg(short = 'w', long)]
    pub workdir: Option<String>,

    /// Environment variable (KEY=VALUE)
    #[arg(short = 'e', long = "env")]
    pub env: Vec<String>,

    /// Timeout for command execution (e.g., "30s", "5m")
    #[arg(long, value_parser = parse_duration)]
    pub timeout: Option<Duration>,
}

impl ExecCmd {
    pub fn run(self) -> smolvm::Result<()> {
        use smolvm::Error;
        use std::io::Write;

        let manager = AgentManager::default()?;

        // Check if sandbox is running
        if manager.try_connect_existing().is_none() {
            return Err(Error::AgentError("No sandbox running. Start one with: smolvm sandbox run -d <image>".to_string()));
        }

        let mut client = AgentClient::connect(manager.vsock_socket())?;

        // Find the container in the sandbox
        let containers = client.list_containers()?;
        let container = containers.iter().find(|c| c.state == "running");

        let container_id = match container {
            Some(c) => c.id.clone(),
            None => {
                return Err(Error::AgentError("No running container in sandbox".to_string()));
            }
        };

        // Parse environment variables
        let env: Vec<(String, String)> = self
            .env
            .iter()
            .filter_map(|e| {
                let (k, v) = e.split_once('=')?;
                if k.is_empty() { None } else { Some((k.to_string(), v.to_string())) }
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
        let _ = std::io::stdout().flush();
        let _ = std::io::stderr().flush();

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
        let manager = AgentManager::default()?;

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
        let manager = AgentManager::default()?;

        if manager.try_connect_existing().is_some() {
            let pid = manager
                .child_pid()
                .map(|p| format!(" (PID: {})", p))
                .unwrap_or_default();
            println!("Sandbox: running{}", pid);

            // Try to list containers
            if let Ok(mut client) = AgentClient::connect(manager.vsock_socket()) {
                if let Ok(containers) = client.list_containers() {
                    if !containers.is_empty() {
                        println!("\nContainers:");
                        for c in containers {
                            let short_id = if c.id.len() > 12 { &c.id[..12] } else { &c.id };
                            println!("  {} {} ({})", short_id, c.image, c.state);
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
/// By default, runs in ephemeral mode:
/// - Starts a microVM automatically
/// - Pulls and runs the container image
/// - Cleans up everything after the command exits
///
/// With --detach, runs in persistent mode:
/// - Starts microVM and container in background
/// - Returns container ID for later interaction
/// - Use `smolvm container exec` to run commands
/// - Use `smolvm sandbox stop` to clean up
///
/// Examples:
///   smolvm sandbox run alpine -- echo "Hello"     # Ephemeral
///   smolvm sandbox run -d ubuntu                   # Persistent
///   smolvm sandbox run -d -p 8080:80 nginx        # Persistent with port
#[derive(Args, Debug)]
pub struct RunCmd {
    /// OCI image reference (e.g., alpine, ubuntu:22.04, ghcr.io/org/image)
    pub image: String,

    /// Command to execute inside the container
    #[arg(trailing_var_arg = true)]
    pub command: Vec<String>,

    /// Run in detached/persistent mode (keeps sandbox running)
    #[arg(short = 'd', long)]
    pub detach: bool,

    /// Number of vCPUs (default: 1)
    #[arg(long, default_value = "1")]
    pub cpus: u8,

    /// Memory in MiB (default: 512)
    #[arg(long, default_value = "512")]
    pub mem: u32,

    /// Working directory inside the container
    #[arg(short = 'w', long)]
    pub workdir: Option<String>,

    /// Environment variable (KEY=VALUE)
    #[arg(short = 'e', long = "env")]
    pub env: Vec<String>,

    /// Volume mount (host:container[:ro])
    #[arg(short = 'v', long = "volume")]
    pub volume: Vec<String>,

    /// Enable network egress (auto-enabled when -p is used)
    #[arg(long)]
    pub net: bool,

    /// Port mapping from host to guest (HOST:GUEST or PORT)
    #[arg(short = 'p', long = "port", value_parser = parse_port)]
    pub port: Vec<PortMapping>,

    /// Timeout for command execution (e.g., "30s", "5m")
    #[arg(long, value_parser = parse_duration)]
    pub timeout: Option<Duration>,

    /// Keep stdin open (interactive mode)
    #[arg(short = 'i', long)]
    pub interactive: bool,

    /// Allocate a pseudo-TTY
    #[arg(short = 't', long)]
    pub tty: bool,
}

impl RunCmd {
    pub fn run(self) -> smolvm::Result<()> {
        use smolvm::Error;
        use std::io::Write;

        // Parse volume mounts
        let mounts = parse_mounts(&self.volume)?;
        let ports = self.port.clone();

        let resources = VmResources {
            cpus: self.cpus,
            mem: self.mem,
        };

        // Start agent VM
        let manager = AgentManager::default()
            .map_err(|e| Error::AgentError(format!("failed to create agent manager: {}", e)))?;

        // Show startup message
        let mode = if self.detach { "persistent" } else { "ephemeral" };
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

        // Pull image
        println!("Pulling image {}...", self.image);
        client.pull(&self.image, None)?;

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
        let mount_bindings: Vec<(String, String, bool)> = mounts
            .iter()
            .enumerate()
            .map(|(i, m)| {
                (
                    format!("smolvm{}", i),
                    m.target.to_string_lossy().to_string(),
                    m.read_only,
                )
            })
            .collect();

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
            println!("  smolvm container exec default {} -- <command>", &info.id[..12]);
            println!("  smolvm container exec default {} -it -- /bin/sh", &info.id[..12]);
            println!("\nTo stop the sandbox:");
            println!("  smolvm sandbox stop");

            // Keep sandbox running
            std::mem::forget(manager);
            Ok(())
        } else {
            // Ephemeral mode: run command and clean up
            let exit_code = if self.interactive || self.tty {
                client.run_interactive(
                    &self.image,
                    command,
                    env,
                    self.workdir.clone(),
                    mount_bindings,
                    self.timeout,
                    self.tty,
                )?
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
                let _ = std::io::stdout().flush();
                let _ = std::io::stderr().flush();
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
// Helper Functions
// ============================================================================

/// Parse volume mount specifications into HostMount structs.
fn parse_mounts(specs: &[String]) -> smolvm::Result<Vec<HostMount>> {
    use smolvm::Error;

    let mut mounts = Vec::new();

    for spec in specs {
        let parts: Vec<&str> = spec.split(':').collect();
        if parts.len() < 2 {
            return Err(Error::Mount(format!(
                "invalid volume specification '{}': expected host:container[:ro]",
                spec
            )));
        }

        let host_path = PathBuf::from(parts[0]);
        let guest_path = PathBuf::from(parts[1]);
        let read_only = parts.get(2).map(|&s| s == "ro").unwrap_or(false);

        // Validate host path exists
        if !host_path.exists() {
            return Err(Error::Mount(format!(
                "host path does not exist: {}",
                host_path.display()
            )));
        }

        // Must be a directory (virtiofs limitation)
        if !host_path.is_dir() {
            return Err(Error::Mount(format!(
                "host path must be a directory (virtiofs limitation): {}",
                host_path.display()
            )));
        }

        // Canonicalize host path
        let host_path = host_path.canonicalize().map_err(|e| {
            Error::Mount(format!("failed to resolve host path '{}': {}", parts[0], e))
        })?;

        mounts.push(HostMount {
            source: host_path,
            target: guest_path,
            read_only,
        });
    }

    Ok(mounts)
}
