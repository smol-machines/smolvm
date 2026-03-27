//! Container lifecycle management commands.
//!
//! These commands manage long-running containers via a microvm.
//! Containers can be created, started, stopped, and deleted independently.

use crate::cli::parsers::{parse_duration, parse_env_list};
use crate::cli::vm_common;
use crate::cli::{flush_output, truncate, truncate_id, COMMAND_WIDTH, IMAGE_NAME_WIDTH};
use clap::{Args, Subcommand};
use smolvm::agent::{AgentClient, AgentManager};
use smolvm::data::storage::HostMount;
use smolvm::db::SmolvmDb;
use smolvm::{DEFAULT_IDLE_CMD, DEFAULT_SHELL_CMD};
use std::time::Duration;

/// Manage containers inside a microVM
#[derive(Subcommand, Debug)]
pub enum ContainerCmd {
    /// Create a container from an image (does not start it)
    Create(ContainerCreateCmd),

    /// Start a stopped container
    Start(ContainerStartCmd),

    /// Stop a running container
    Stop(ContainerStopCmd),

    /// Remove a container
    #[command(visible_alias = "rm")]
    Remove(ContainerRemoveCmd),

    /// List containers in a microVM
    #[command(visible_alias = "ls")]
    List(ContainerListCmd),

    /// Run a command inside a container
    Exec(ContainerExecCmd),
}

impl ContainerCmd {
    pub fn run(self) -> smolvm::Result<()> {
        match self {
            ContainerCmd::Create(cmd) => cmd.run(),
            ContainerCmd::Start(cmd) => cmd.run(),
            ContainerCmd::Stop(cmd) => cmd.run(),
            ContainerCmd::Remove(cmd) => cmd.run(),
            ContainerCmd::List(cmd) => cmd.run(),
            ContainerCmd::Exec(cmd) => cmd.run(),
        }
    }
}

/// Get the agent manager for a microvm, ensuring it's running.
fn ensure_microvm(name: &str) -> smolvm::Result<AgentManager> {
    vm_common::get_or_start_vm(name)
}

// ============================================================================
// Create
// ============================================================================

/// Create a container from an image.
///
/// Creates a container in the specified microVM. The container starts
/// automatically if no command is specified (runs sleep infinity).
///
/// Examples:
///   smolvm container create default alpine
///   smolvm container create myvm nginx -- nginx -g "daemon off;"
#[derive(Args, Debug)]
pub struct ContainerCreateCmd {
    /// Target microVM name
    #[arg(value_name = "MICROVM")]
    pub microvm: String,

    /// Container image (e.g., alpine, nginx:latest)
    #[arg(value_name = "IMAGE")]
    pub image: String,

    /// Command to run (default: sleep infinity)
    #[arg(trailing_var_arg = true, value_name = "COMMAND")]
    pub command: Vec<String>,

    /// Set working directory inside container
    #[arg(short = 'w', long, value_name = "DIR")]
    pub workdir: Option<String>,

    /// Set environment variable (can be used multiple times)
    #[arg(short = 'e', long = "env", value_name = "KEY=VALUE")]
    pub env: Vec<String>,

    /// Mount host directory (can be used multiple times)
    #[arg(short = 'v', long = "volume", value_name = "HOST:CONTAINER[:ro]")]
    pub volume: Vec<String>,
}

impl ContainerCreateCmd {
    pub fn run(self) -> smolvm::Result<()> {
        let manager = ensure_microvm(&self.microvm)?;

        // Connect to agent
        let mut client = AgentClient::connect_with_retry(manager.vsock_socket())?;

        // Pull image if needed
        if !std::path::Path::new(&self.image).exists() {
            crate::cli::pull_with_progress(&mut client, &self.image, None)?;
        }

        // Parse environment variables
        let env = parse_env_list(&self.env);

        // Resolve volume mounts against the microvm's virtiofs devices.
        let vm_mounts = SmolvmDb::open()
            .ok()
            .and_then(|db| db.get_vm(&self.microvm).ok().flatten())
            .map(|r| r.mounts)
            .unwrap_or_default();

        let explicit_host_mounts = HostMount::parse(&self.volume)?;
        let mounts = resolve_container_mounts(&self.microvm, &vm_mounts, &explicit_host_mounts)?;

        // Default command is sleep infinity for long-running containers
        let command = if self.command.is_empty() {
            DEFAULT_IDLE_CMD.iter().map(|s| s.to_string()).collect()
        } else {
            self.command.clone()
        };

        // Create container
        let info =
            client.create_container(&self.image, command, env, self.workdir.clone(), mounts)?;

        println!("Created container: {}", info.id);
        println!("  Image: {}", info.image);
        println!("  State: {}", info.state);

        // Keep microvm running
        manager.detach();

        Ok(())
    }
}

// ============================================================================
// Start
// ============================================================================

/// Start a stopped container.
///
/// Resumes execution of a container that was previously stopped.
#[derive(Args, Debug)]
pub struct ContainerStartCmd {
    /// Target microVM name
    #[arg(value_name = "MICROVM")]
    pub microvm: String,

    /// Container ID (full or prefix)
    #[arg(value_name = "CONTAINER")]
    pub container_id: String,
}

impl ContainerStartCmd {
    pub fn run(self) -> smolvm::Result<()> {
        let manager = ensure_microvm(&self.microvm)?;
        let mut client = AgentClient::connect_with_retry(manager.vsock_socket())?;

        client.start_container(&self.container_id)?;
        println!("Started container: {}", self.container_id);

        // Keep microvm running
        manager.detach();

        Ok(())
    }
}

// ============================================================================
// Stop
// ============================================================================

/// Stop a running container.
///
/// Sends SIGTERM, then SIGKILL after timeout if container doesn't stop.
#[derive(Args, Debug)]
pub struct ContainerStopCmd {
    /// Target microVM name
    #[arg(value_name = "MICROVM")]
    pub microvm: String,

    /// Container ID (full or prefix)
    #[arg(value_name = "CONTAINER")]
    pub container_id: String,

    /// Seconds to wait before force kill (default: 10)
    #[arg(short = 't', long, value_parser = parse_duration, value_name = "DURATION")]
    pub timeout: Option<Duration>,
}

impl ContainerStopCmd {
    pub fn run(self) -> smolvm::Result<()> {
        let manager = ensure_microvm(&self.microvm)?;
        let mut client = AgentClient::connect_with_retry(manager.vsock_socket())?;

        let timeout_secs = self.timeout.map(|d| d.as_secs());
        client.stop_container(&self.container_id, timeout_secs)?;
        println!("Stopped container: {}", self.container_id);

        // Keep microvm running
        manager.detach();

        Ok(())
    }
}

// ============================================================================
// Remove
// ============================================================================

/// Remove a container.
///
/// Deletes a stopped container. Use -f to remove a running container.
#[derive(Args, Debug)]
pub struct ContainerRemoveCmd {
    /// Target microVM name
    #[arg(value_name = "MICROVM")]
    pub microvm: String,

    /// Container ID (full or prefix)
    #[arg(value_name = "CONTAINER")]
    pub container_id: String,

    /// Force remove even if running
    #[arg(short = 'f', long)]
    pub force: bool,
}

impl ContainerRemoveCmd {
    pub fn run(self) -> smolvm::Result<()> {
        let manager = ensure_microvm(&self.microvm)?;
        let mut client = AgentClient::connect_with_retry(manager.vsock_socket())?;

        client.delete_container(&self.container_id, self.force)?;
        println!("Removed container: {}", self.container_id);

        // Keep microvm running
        manager.detach();

        Ok(())
    }
}

// ============================================================================
// List
// ============================================================================

/// List containers in a microVM.
///
/// By default shows only running containers. Use -a to include stopped.
#[derive(Args, Debug)]
pub struct ContainerListCmd {
    /// Target microVM name
    #[arg(value_name = "MICROVM")]
    pub microvm: String,

    /// Show all containers including stopped
    #[arg(short = 'a', long)]
    pub all: bool,

    /// Only show container IDs
    #[arg(short = 'q', long)]
    pub quiet: bool,
}

impl ContainerListCmd {
    pub fn run(self) -> smolvm::Result<()> {
        // "default" refers to the default microvm
        let manager = if self.microvm == "default" {
            AgentManager::new_default()?
        } else {
            AgentManager::for_vm(&self.microvm)?
        };

        // Check if microvm is running
        if manager.try_connect_existing().is_none() {
            if self.quiet {
                return Ok(());
            }
            println!("No containers (microvm '{}' not running)", self.microvm);
            return Ok(());
        }

        let mut client = AgentClient::connect_with_retry(manager.vsock_socket())?;
        let containers = client.list_containers()?;

        if self.quiet {
            // Just print IDs
            for c in &containers {
                if self.all || c.state == "running" {
                    println!("{}", c.id);
                }
            }
        } else if containers.is_empty() {
            println!("No containers");
        } else {
            // Table format
            println!(
                "{:<16} {:<20} {:<12} {:<30}",
                "CONTAINER ID", "IMAGE", "STATE", "COMMAND"
            );

            for c in &containers {
                if !self.all && c.state != "running" {
                    continue;
                }

                let short_id = truncate_id(&c.id);
                let short_image = truncate(&c.image, IMAGE_NAME_WIDTH);
                let short_cmd = truncate(&c.command.join(" "), COMMAND_WIDTH);

                println!(
                    "{:<16} {:<20} {:<12} {:<30}",
                    short_id, short_image, c.state, short_cmd
                );
            }
        }

        // Keep microvm running
        manager.detach();

        Ok(())
    }
}

// ============================================================================
// Exec
// ============================================================================

/// Execute a command in a running container.
///
/// Runs a command inside an existing container. Returns the exit code.
///
/// Examples:
///   smolvm container exec default abc123 -- ls -la
///   smolvm container exec myvm web -- /bin/sh
#[derive(Args, Debug)]
pub struct ContainerExecCmd {
    /// Target microVM name
    #[arg(value_name = "MICROVM")]
    pub microvm: String,

    /// Container ID (full or prefix)
    #[arg(value_name = "CONTAINER")]
    pub container_id: String,

    /// Command to execute (default: /bin/sh)
    #[arg(trailing_var_arg = true, value_name = "COMMAND")]
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

impl ContainerExecCmd {
    pub fn run(self) -> smolvm::Result<()> {
        let manager = ensure_microvm(&self.microvm)?;
        let mut client = AgentClient::connect_with_retry(manager.vsock_socket())?;

        // Parse environment variables
        let env = parse_env_list(&self.env);

        // Default command
        let command = if self.command.is_empty() {
            vec![DEFAULT_SHELL_CMD.to_string()]
        } else {
            self.command.clone()
        };

        // Execute in container
        let (exit_code, stdout, stderr) = client.exec(
            &self.container_id,
            command,
            env,
            self.workdir.clone(),
            self.timeout,
        )?;

        // Print output
        if !stdout.is_empty() {
            print!("{}", stdout);
        }
        if !stderr.is_empty() {
            eprint!("{}", stderr);
        }

        flush_output();

        // Keep microvm running
        manager.detach();

        std::process::exit(exit_code);
    }
}

// ============================================================================
// Mount resolution
// ============================================================================

/// Resolve container volume mounts against a microvm's virtiofs devices.
///
/// Virtiofs devices are registered at VM launch and cannot be added later.
/// Their tags (`smolvm0`, `smolvm1`, ...) correspond 1:1 to the VM's mount
/// list order.
///
/// - All VM mounts are included by default (auto-propagation).
/// - Explicit container `-v` overrides are matched by host path to find the
///   correct virtiofs tag, allowing guest-path remapping.
/// - An explicit `-v` referencing a host path not in the VM is an error.
fn resolve_container_mounts(
    microvm_name: &str,
    vm_mounts: &[(String, String, bool)],
    explicit: &[HostMount],
) -> smolvm::Result<Vec<(String, String, bool)>> {
    // Start with all VM mounts as the base
    let mut mounts: Vec<(String, String, bool)> = vm_mounts
        .iter()
        .enumerate()
        .map(|(i, (_, guest_path, read_only))| {
            (HostMount::mount_tag(i), guest_path.clone(), *read_only)
        })
        .collect();

    // Apply explicit -v overrides by matching host path to VM mount index
    for host_mount in explicit {
        let host_path_str = host_mount.source.to_string_lossy();
        let vm_index = vm_mounts
            .iter()
            .position(|(hp, _, _)| *hp == *host_path_str);

        match vm_index {
            Some(i) => {
                mounts[i] = (
                    HostMount::mount_tag(i),
                    host_mount.target.to_string_lossy().to_string(),
                    host_mount.read_only,
                );
            }
            None => {
                return Err(smolvm::Error::mount(
                    "resolve volume",
                    format!(
                        "host path '{}' is not mounted in microvm '{}'. \
                         Add it when creating the microvm: smolvm microvm create {} -v {}:{}",
                        host_path_str,
                        microvm_name,
                        microvm_name,
                        host_path_str,
                        host_mount.target.display(),
                    ),
                ));
            }
        }
    }

    Ok(mounts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn vm_mount(host: &str, guest: &str, ro: bool) -> (String, String, bool) {
        (host.to_string(), guest.to_string(), ro)
    }

    fn host_mount(source: &str, target: &str, read_only: bool) -> HostMount {
        HostMount {
            source: PathBuf::from(source),
            target: PathBuf::from(target),
            read_only,
        }
    }

    #[test]
    fn test_no_vm_mounts_no_explicit() {
        let result = resolve_container_mounts("test", &[], &[]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_vm_mounts_auto_propagated() {
        let vm = vec![
            vm_mount("/host/data", "/data", false),
            vm_mount("/host/config", "/config", true),
        ];
        let result = resolve_container_mounts("test", &vm, &[]).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(
            result[0],
            ("smolvm0".to_string(), "/data".to_string(), false)
        );
        assert_eq!(
            result[1],
            ("smolvm1".to_string(), "/config".to_string(), true)
        );
    }

    #[test]
    fn test_explicit_remaps_guest_path() {
        let vm = vec![vm_mount("/host/data", "/data", false)];
        let explicit = vec![host_mount("/host/data", "/app/data", false)];
        let result = resolve_container_mounts("test", &vm, &explicit).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0],
            ("smolvm0".to_string(), "/app/data".to_string(), false)
        );
    }

    #[test]
    fn test_explicit_overrides_read_only() {
        let vm = vec![vm_mount("/host/data", "/data", false)];
        let explicit = vec![host_mount("/host/data", "/data", true)];
        let result = resolve_container_mounts("test", &vm, &explicit).unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].2);
    }

    #[test]
    fn test_explicit_unknown_host_path_errors() {
        let vm = vec![vm_mount("/host/data", "/data", false)];
        let explicit = vec![host_mount("/other/path", "/other", false)];
        let result = resolve_container_mounts("myvm", &vm, &explicit);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("/other/path"),
            "error should mention the path: {err}"
        );
        assert!(
            err.contains("myvm"),
            "error should mention the vm name: {err}"
        );
    }

    #[test]
    fn test_explicit_on_empty_vm_errors() {
        let explicit = vec![host_mount("/host/data", "/data", false)];
        let result = resolve_container_mounts("myvm", &[], &explicit);
        assert!(result.is_err());
    }

    #[test]
    fn test_partial_override_preserves_other_mounts() {
        let vm = vec![
            vm_mount("/host/a", "/a", false),
            vm_mount("/host/b", "/b", false),
            vm_mount("/host/c", "/c", true),
        ];
        // Only override the second mount
        let explicit = vec![host_mount("/host/b", "/remapped-b", true)];
        let result = resolve_container_mounts("test", &vm, &explicit).unwrap();
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], ("smolvm0".to_string(), "/a".to_string(), false));
        assert_eq!(
            result[1],
            ("smolvm1".to_string(), "/remapped-b".to_string(), true)
        );
        assert_eq!(result[2], ("smolvm2".to_string(), "/c".to_string(), true));
    }

    #[test]
    fn test_multiple_explicit_overrides() {
        let vm = vec![
            vm_mount("/host/a", "/a", false),
            vm_mount("/host/b", "/b", false),
        ];
        let explicit = vec![
            host_mount("/host/a", "/x", true),
            host_mount("/host/b", "/y", true),
        ];
        let result = resolve_container_mounts("test", &vm, &explicit).unwrap();
        assert_eq!(result[0], ("smolvm0".to_string(), "/x".to_string(), true));
        assert_eq!(result[1], ("smolvm1".to_string(), "/y".to_string(), true));
    }
}
