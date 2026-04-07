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
use crate::cli::format_pid_suffix;
use crate::cli::parsers::{mounts_to_virtiofs_bindings, parse_cidr, parse_env_list};
use crate::cli::truncate;
use clap::{Args, Subcommand};
use smolvm::agent::{docker_config_mount, AgentClient, AgentManager};
use smolvm::control;
use smolvm::data::consts::DEFAULT_MACHINE_NAME;
use smolvm::data::disk::{DEFAULT_OVERLAY_SIZE_GIB, DEFAULT_STORAGE_SIZE_GIB};
use smolvm::data::network::PortMapping;
use smolvm::data::resources::{DEFAULT_MICROVM_CPU_COUNT, DEFAULT_MICROVM_MEMORY_MIB};
use smolvm::data::vm::MicroVm;
use smolvm::SmolvmDb;
use smolvm::{DEFAULT_IDLE_CMD, DEFAULT_SHELL_CMD, Error};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};


/// Resolve `--allow-cidr`, `--allow-host`, and `--outbound-localhost-only` into a CIDR list,
/// net flag, and the original hostname list (for DNS filtering).
///
/// Resolution failure for `--allow-host` is a hard error — a typo or DNS outage
/// should not silently weaken the security policy.
fn resolve_egress_flags(
    mut allow_cidr: Vec<String>,
    allow_host: Vec<String>,
    outbound_localhost_only: bool,
    net: bool,
) -> smolvm::Result<(Vec<String>, bool, Option<Vec<String>>)> {
    // Resolve hostnames to CIDRs — fail hard on resolution errors
    for host in &allow_host {
        let cidrs = crate::cli::parsers::resolve_host_to_cidrs(host)
            .map_err(|e| smolvm::Error::config("--allow-host", e))?;
        tracing::info!(host, ?cidrs, "resolved hostname for egress policy");
        allow_cidr.extend(cidrs);
    }

    if outbound_localhost_only {
        allow_cidr.push("127.0.0.0/8".to_string());
        allow_cidr.push("::1/128".to_string());
    }
    let net = net || !allow_cidr.is_empty();

    // Preserve original hostnames for DNS filtering (None if no --allow-host was used)
    let dns_filter_hosts = if allow_host.is_empty() {
        None
    } else {
        Some(allow_host)
    };

    Ok((allow_cidr, net, dns_filter_hosts))
}

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

    /// Copy files between host and machine
    Cp(CpCmd),

    /// Monitor a machine with health checks and restart policy
    Monitor(MonitorCmd),

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
            MachineCmd::Cp(cmd) => cmd.run(),
            MachineCmd::Monitor(cmd) => cmd.run(),
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
    /// Container image (e.g., alpine, ubuntu:22.04, ghcr.io/org/image).
    /// Optional when a Smolfile provides the image, or for bare VM mode.
    #[arg(short = 'I', long, value_name = "IMAGE")]
    pub image: Option<String>,

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
    #[arg(long, value_parser = humantime::parse_duration, value_name = "DURATION", help_heading = "Execution")]
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

    /// Allow egress to specific CIDR range (can be used multiple times, implies --net)
    #[arg(long = "allow-cidr", value_parser = parse_cidr, value_name = "CIDR", help_heading = "Network")]
    pub allow_cidr: Vec<String>,

    /// Allow egress to specific hostname, resolved at VM start (can be used multiple times, implies --net)
    #[arg(long = "allow-host", value_name = "HOSTNAME", help_heading = "Network")]
    pub allow_host: Vec<String>,

    /// Restrict outbound to localhost only (implies --net)
    #[arg(long, help_heading = "Network")]
    pub outbound_localhost_only: bool,

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

    /// Forward host SSH agent into the VM (enables git/ssh without exposing keys)
    #[arg(long, help_heading = "Security")]
    pub ssh_agent: bool,

    /// Mount ~/.docker/ config into VM for registry authentication
    #[arg(long, help_heading = "Registry")]
    pub docker_config: bool,
}

impl RunCmd {
    fn to_microvm(&self, name: String) -> smolvm::Result<MicroVm> {
        let (cli_allow_cidrs, net, dns_filter_hosts) = resolve_egress_flags(
            self.allow_cidr.clone(),
            self.allow_host.clone(),
            self.outbound_localhost_only,
            self.net,
        )?;

        let mut spec = crate::cli::smolfile::build_vm_spec(
            self.image.clone(),
            None,
            self.command.clone(),
            self.cpus,
            self.mem,
            self.volume.clone(),
            self.port.clone(),
            net,
            vec![],
            self.env.clone(),
            self.workdir.clone(),
            self.smolfile.clone(),
            self.storage,
            self.overlay,
            cli_allow_cidrs,
        )?;

        if let Some(hosts) = dns_filter_hosts {
            match &mut spec.dns_filter_hosts {
                Some(existing) => existing.extend(hosts),
                None => spec.dns_filter_hosts = Some(hosts),
            }
        }
        if self.ssh_agent {
            spec.ssh_agent = true;
        }
        spec.ephemeral = !self.detach;
        if self.docker_config {
            if let Some(docker_mount) = docker_config_mount() {
                spec.mounts.push(docker_mount);
            } else {
                tracing::warn!("Docker config directory not found");
            }
        }

        Ok(MicroVm {
            name,
            spec,
            status: None,
        })
    }

    fn generated_name(&self, db: &SmolvmDb) -> smolvm::Result<String> {
        let prefix = if self.detach {
            "persistent-run"
        } else {
            "ephemeral-run"
        };
        let pid = std::process::id() & 0x000f_ffff;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Error::config("generate run name", e.to_string()))?
            .as_nanos() as u64;

        for attempt in 0..100u32 {
            let name = format!("{}-{:016x}-{:05x}-{:02x}", prefix, now, pid, attempt);
            if db.get_vm(&name)?.is_none() {
                return Ok(name);
            }
        }

        Err(Error::config(
            "generate run name",
            "failed to generate a unique VM name",
        ))
    }

    pub fn run(self) -> smolvm::Result<()> {
        if !self.interactive && !self.tty && !self.detach && self.command.is_empty() {
            return Err(smolvm::Error::config(
                "machine run",
                "no command specified.\n\
                 Use: smolvm machine run -- <command>\n\
                 Or:  smolvm machine run -it",
            ));
        }

        let db = SmolvmDb::open()?;
        let name = self.generated_name(&db)?;
        let vm = self.to_microvm(name.clone())?;

        control::create_vm(&db, vm.clone())?;

        let mode = if self.detach {
            "persistent"
        } else {
            "ephemeral"
        };
        println!("Starting {} machine '{}'...", mode, name);

        let mut handle = match control::start_vm(&db, &name) {
            Ok(handle) => handle,
            Err(e) => {
                let _ = control::delete_vm(&db, &name, true);
                return Err(e);
            }
        };

        let image_info = if let Some(ref image) = vm.spec.image {
            match crate::cli::pull_with_progress(&mut handle, image, self.oci_platform.as_deref()) {
                Ok(info) => Some(info),
                Err(e) => {
                    drop(handle);
                    let _ = control::delete_vm(&db, &name, true);
                    return Err(e);
                }
            }
        } else {
            None
        };

        for (i, cmd) in vm.spec.init.iter().enumerate() {
            let argv = vec!["sh".into(), "-c".into(), cmd.clone()];
            let (exit_code, _stdout, stderr) = match handle.vm_exec(
                &argv,
                &vm.spec.env,
                vm.spec.workdir.as_deref(),
                None,
            ) {
                Ok(result) => result,
                Err(e) => {
                    drop(handle);
                    let _ = control::delete_vm(&db, &name, true);
                    return Err(e);
                }
            };
            if exit_code != 0 {
                drop(handle);
                let _ = control::delete_vm(&db, &name, true);
                return Err(Error::agent(
                    "init",
                    format!("init[{}] failed (exit {}): {}", i, exit_code, stderr.trim()),
                ));
            }
        }

        let command = if !self.command.is_empty() {
            self.command.clone()
        } else if !vm.spec.entrypoint.is_empty() || !vm.spec.cmd.is_empty() {
            let mut cmd = vm.spec.entrypoint.clone();
            cmd.extend(vm.spec.cmd.clone());
            cmd
        } else if let Some(ref info) = image_info {
            let mut cmd = info.entrypoint.clone();
            cmd.extend(info.cmd.clone());
            if cmd.is_empty() {
                if self.detach {
                    DEFAULT_IDLE_CMD.iter().map(|s| s.to_string()).collect()
                } else {
                    vec![DEFAULT_SHELL_CMD.to_string()]
                }
            } else {
                cmd
            }
        } else if self.detach {
            DEFAULT_IDLE_CMD.iter().map(|s| s.to_string()).collect()
        } else {
            vec![DEFAULT_SHELL_CMD.to_string()]
        };
        let mount_bindings = mounts_to_virtiofs_bindings(&vm.spec.mounts);

        if let Some(ref image) = vm.spec.image {
            if self.detach {
                let _ = command;
                let _ = mount_bindings;
                println!("Machine '{}' running in background", name);
                println!("\nTo stop:");
                println!("  smolvm machine stop --name {}", name);

                handle.detach();
                Ok(())
            } else {
                let run_result = if self.interactive || self.tty {
                    handle.run_interactive(
                        image,
                        &command,
                        &vm.spec.env,
                        vm.spec.workdir.as_deref(),
                        &mount_bindings,
                        self.timeout,
                        self.tty,
                    )
                } else {
                    handle
                        .run_with_mounts_and_timeout(
                            image,
                            &command,
                            &vm.spec.env,
                            vm.spec.workdir.as_deref(),
                            &mount_bindings,
                            self.timeout,
                        )
                        .map(|(exit_code, stdout, stderr)| {
                            if !stdout.is_empty() {
                                print!("{}", stdout);
                            }
                            if !stderr.is_empty() {
                                eprint!("{}", stderr);
                            }
                            flush_output();
                            exit_code
                        })
                };

                drop(handle);
                if let Err(e) = control::stop_vm(&db, &name) {
                    tracing::warn!(error = %e, "failed to stop machine");
                }
                if let Err(e) = control::delete_vm(&db, &name, true) {
                    tracing::warn!(error = %e, "failed to delete ephemeral machine");
                }
                let exit_code = run_result?;
                std::process::exit(exit_code);
            }
        } else if self.detach {
            let is_idle = command.is_empty()
                || command
                    == DEFAULT_IDLE_CMD
                        .iter()
                        .map(|s| s.to_string())
                        .collect::<Vec<_>>();
            if !is_idle {
                if let Err(e) =
                    handle.vm_exec_background(&command, &vm.spec.env, vm.spec.workdir.as_deref())
                {
                    drop(handle);
                    let _ = control::delete_vm(&db, &name, true);
                    return Err(e);
                }
            }

            println!("Machine '{}' running in background", name);
            println!("\nTo stop:");
            println!("  smolvm machine stop --name {}", name);

            handle.detach();
            Ok(())
        } else {
            let run_result = if self.interactive || self.tty {
                handle.vm_exec_interactive(
                    &command,
                    &vm.spec.env,
                    vm.spec.workdir.as_deref(),
                    self.timeout,
                    self.tty,
                )
            } else {
                handle
                    .vm_exec(
                        &command,
                        &vm.spec.env,
                        vm.spec.workdir.as_deref(),
                        self.timeout,
                    )
                    .map(|(exit_code, stdout, stderr)| {
                        if !stdout.is_empty() {
                            print!("{}", stdout);
                        }
                        if !stderr.is_empty() {
                            eprint!("{}", stderr);
                        }
                        flush_output();
                        exit_code
                    })
            };

            drop(handle);
            if let Err(e) = control::stop_vm(&db, &name) {
                tracing::warn!(error = %e, "failed to stop machine");
            }
            if let Err(e) = control::delete_vm(&db, &name, true) {
                tracing::warn!(error = %e, "failed to delete ephemeral machine");
            }
            let exit_code = run_result?;
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

    /// Target machine
    #[arg(long, value_name = "NAME", default_value = DEFAULT_MACHINE_NAME)]
    pub name: String,

    /// Set working directory in the VM
    #[arg(short = 'w', long, value_name = "DIR")]
    pub workdir: Option<String>,

    /// Set environment variable (can be used multiple times)
    #[arg(short = 'e', long = "env", value_name = "KEY=VALUE")]
    pub env: Vec<String>,

    /// Kill command after duration (e.g., "30s", "5m")
    #[arg(long, value_parser = humantime::parse_duration, value_name = "DURATION")]
    pub timeout: Option<Duration>,

    /// Keep stdin open for interactive input
    #[arg(short = 'i', long)]
    pub interactive: bool,

    /// Allocate a pseudo-TTY (use with -i for shells)
    #[arg(short = 't', long)]
    pub tty: bool,

    /// Stream output in real-time (prints as it arrives)
    #[arg(long)]
    pub stream: bool,
}

impl ExecCmd {
    pub fn run(self) -> smolvm::Result<()> {
        let db = SmolvmDb::open()?;
        let _ = control::get_vm(&db, &self.name)?;
        let mut handle = control::connect_vm(&self.name, false)?;

        let env = parse_env_list(&self.env);

        // Streaming mode — print output as it arrives, no buffering
        if self.stream {
            let events = handle.vm_exec_streaming(
                &self.command,
                &env,
                self.workdir.as_deref(),
                self.timeout,
            )?;
            let mut exit_code = 0;
            for event in events {
                match event {
                    smolvm::agent::ExecEvent::Stdout(data) => {
                        use std::io::Write;
                        let _ = std::io::stdout().write_all(&data);
                        let _ = std::io::stdout().flush();
                    }
                    smolvm::agent::ExecEvent::Stderr(data) => {
                        use std::io::Write;
                        let _ = std::io::stderr().write_all(&data);
                        let _ = std::io::stderr().flush();
                    }
                    smolvm::agent::ExecEvent::Exit(code) => {
                        exit_code = code;
                    }
                    smolvm::agent::ExecEvent::Error(msg) => {
                        eprintln!("error: {}", msg);
                        exit_code = 1;
                    }
                }
            }
            handle.detach();
            std::process::exit(exit_code);
        }

        // Run command directly in VM
        if self.interactive || self.tty {
            let exit_code = handle.vm_exec_interactive(
                &self.command,
                &env,
                self.workdir.as_deref(),
                self.timeout,
                self.tty,
            )?;
            handle.detach();
            std::process::exit(exit_code);
        }

        let (exit_code, stdout, stderr) = handle.vm_exec(
            &self.command,
            &env,
            self.workdir.as_deref(),
            self.timeout,
        )?;

        if !stdout.is_empty() {
            print!("{}", stdout);
        }
        if !stderr.is_empty() {
            eprint!("{}", stderr);
        }
        flush_output();
        handle.detach();
        std::process::exit(exit_code);
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
    /// Name for the machine (auto-generated if omitted)
    #[arg(value_name = "NAME")]
    pub name: Option<String>,

    /// Container image (e.g., alpine, python:3.12-alpine)
    #[arg(short = 'I', long, value_name = "IMAGE")]
    pub image: Option<String>,

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

    /// Allow egress to specific CIDR range (can be used multiple times, implies --net)
    #[arg(long = "allow-cidr", value_parser = parse_cidr, value_name = "CIDR")]
    pub allow_cidr: Vec<String>,

    /// Allow egress to specific hostname, resolved at VM start (can be used multiple times, implies --net)
    #[arg(long = "allow-host", value_name = "HOSTNAME")]
    pub allow_host: Vec<String>,

    /// Restrict outbound to localhost only (implies --net)
    #[arg(long)]
    pub outbound_localhost_only: bool,

    /// Run command on every VM start (can be used multiple times)
    #[arg(long = "init", value_name = "COMMAND")]
    pub init: Vec<String>,

    /// Set environment variable (can be used multiple times)
    #[arg(short = 'e', long = "env", value_name = "KEY=VALUE")]
    pub env: Vec<String>,

    /// Set working directory inside the machine
    #[arg(short = 'w', long = "workdir", value_name = "DIR")]
    pub workdir: Option<String>,

    /// Forward host SSH agent into the VM (enables git/ssh without exposing keys)
    #[arg(long)]
    pub ssh_agent: bool,

    /// Load configuration from a Smolfile (TOML)
    #[arg(long = "smolfile", visible_short_alias = 's', value_name = "PATH")]
    pub smolfile: Option<PathBuf>,
}

impl CreateCmd {
    fn to_microvm(&self) -> smolvm::Result<MicroVm> {
        let (cli_allow_cidrs, net, dns_filter_hosts) = resolve_egress_flags(
            self.allow_cidr.clone(),
            self.allow_host.clone(),
            self.outbound_localhost_only,
            self.net,
        )?;

        let mut spec = crate::cli::smolfile::build_vm_spec(
            self.image.clone(),
            None,
            vec![],
            self.cpus,
            self.mem,
            self.volume.clone(),
            self.port.clone(),
            net,
            self.init.clone(),
            self.env.clone(),
            self.workdir.clone(),
            self.smolfile.clone(),
            self.storage,
            self.overlay,
            cli_allow_cidrs,
        )?;

        if let Some(hosts) = dns_filter_hosts {
            match &mut spec.dns_filter_hosts {
                Some(existing) => existing.extend(hosts),
                None => spec.dns_filter_hosts = Some(hosts),
            }
        }
        if self.ssh_agent {
            spec.ssh_agent = true;
        }

        Ok(MicroVm {
            name: self
                .name
                .clone()
                .unwrap_or_else(smolvm::util::generate_machine_name),
            spec,
            status: None,
        })
    }

    pub fn run(self) -> smolvm::Result<()> {
        let vm = self.to_microvm()?;
        let name = vm.name.clone();
        let cpus = vm.spec.resources.cpus;
        let mem = vm.spec.resources.memory_mib;
        let mount_count = vm.spec.mounts.len();
        let port_count = vm.spec.ports.len();
        let init_count = vm.spec.init.len();

        let db = SmolvmDb::open()?;
        control::create_vm(&db, vm)?;

        println!("Created {}: {}", "machine", name);
        println!("  CPUs: {}, Memory: {} MiB", cpus, mem);
        if mount_count != 0 {
            println!("  Mounts: {}", mount_count);
        }
        if port_count != 0 {
            println!("  Ports: {}", port_count);
        }
        if init_count != 0 {
            println!("  Init commands: {}", init_count);
        }
        println!(
            "\nUse '{} start {}' to start the {}",
            "smolvm machine",
            name,
            "machine",
        );
        println!(
            "Then use 'smolvm machine exec --name {} -- <command>' to run commands",
            name
        );

        Ok(())
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
    /// Machine to start
    #[arg(short = 'n', long, value_name = "NAME", default_value = DEFAULT_MACHINE_NAME)]
    pub name: String,
}

impl StartCmd {
    pub fn run(self) -> smolvm::Result<()> {
        let name = self.name;
        let db = SmolvmDb::open()?;

        // Pre-start info for CLI output
        let vm = control::get_vm(&db, &name)?;
        let spec = &vm.spec;

        // Core lifecycle owns the actual running/config check.
        let mut handle = control::start_vm(&db, &name)?;
        let pid = handle.child_pid();
        if !handle.freshly_started() {
            let pid_suffix = format_pid_suffix(pid);
            println!("{} '{}' already running{}", "Machine", name, pid_suffix);
            handle.detach();
            return Ok(());
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
        println!("Starting machine '{}'{}{}...", name, mount_info, port_info);

        // CLI-specific: run init commands
        if !spec.init.is_empty() {
            println!("Running {} init command(s)...", spec.init.len());
        }
        for (i, cmd) in spec.init.iter().enumerate() {
            let argv = vec!["sh".to_string(), "-c".to_string(), cmd.to_string()];
            let (exit_code, _stdout, stderr) =
                handle.vm_exec(&argv, &spec.env, spec.workdir.as_deref(), None)?;
            if exit_code != 0 {
                drop(handle);
                let _ = control::stop_vm(&db, &name);
                return Err(smolvm::Error::agent(
                    "init",
                    format!("init[{}] failed (exit {}): {}", i, exit_code, stderr.trim()),
                ));
            }
        }

        // CLI-specific: pull image if configured (from Smolfile)
        if let Some(ref image) = spec.image {
            println!("Pulling {}...", image);
            let _image_info = crate::cli::pull_with_progress(&mut handle, image, None)?;

            println!(
                "Machine '{}' running (PID: {})",
                name,
                pid.unwrap_or(0)
            );
        } else {
            println!("Machine '{}' running (PID: {})", name, pid.unwrap_or(0));
        }

        handle.detach();
        Ok(())
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
    /// Machine to stop
    #[arg(short = 'n', long, value_name = "NAME", default_value = DEFAULT_MACHINE_NAME)]
    pub name: String,
}

impl StopCmd {
    pub fn run(self) -> smolvm::Result<()> {
        let name = self.name;

        let db = SmolvmDb::open()?;
        println!("Stopping {} '{}'...", "machine", name);
        control::stop_vm(&db, &name)?;
        println!("Stopped {}: {}", "machine", name);
        Ok(())
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
        let db = SmolvmDb::open()?;

        // Check if exists
        let _ = control::get_vm(&db, &self.name)?;

        // Confirm deletion unless --force
        if !self.force {
            eprint!("Delete {} '{}'? [y/N] ", "machine", self.name);
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

        control::delete_vm(&db, &self.name, true)?;
        println!("Deleted {}: {}", "machine", self.name);
        Ok(())
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
    /// Machine to check
    #[arg(short = 'n', long, value_name = "NAME", default_value = DEFAULT_MACHINE_NAME)]
    pub name: String,
}

impl StatusCmd {
    pub fn run(self) -> smolvm::Result<()> {
        let name = self.name;

        let manager = AgentManager::for_vm(&name)?;

        if manager.try_connect_existing().is_some() {
            let pid_suffix = crate::cli::format_pid_suffix(manager.child_pid());
            println!("{} '{}': running{}", "Machine", name, pid_suffix);
            manager.detach();
        } else {
            println!("{} '{}': not running", "Machine", name);
        }

        Ok(())
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
        let db = SmolvmDb::open()?;
        let vms: Vec<MicroVm> = control::list_vms(&db)?;

        if vms.is_empty() {
            if !self.json {
                println!("No machines found");
            } else {
                println!("[]");
            }
            return Ok(());
        }

        if self.json {
            let json_vms: Vec<_> = vms
                .iter()
                .map(|vm| {
                    let phase = vm
                        .status
                        .as_ref()
                        .map(|s| s.phase.to_string())
                        .unwrap_or_else(|| "unknown".into());
                    let pid = vm.status.as_ref().and_then(|s| s.pid);
                    let created_at = vm
                        .status
                        .as_ref()
                        .map(|s| s.created_at.as_str())
                        .unwrap_or("");
                    let obj = serde_json::json!({
                        "name": vm.name,
                        "state": phase,
                        "cpus": vm.spec.resources.cpus,
                        "memory_mib": vm.spec.resources.memory_mib,
                        "pid": pid,
                        "mounts": vm.spec.mounts.len(),
                        "ports": vm.spec.ports.len(),
                        "created_at": created_at,
                        "storage_gib": vm.spec.resources.storage_gib,
                        "overlay_gib": vm.spec.resources.overlay_gib,
                        "image": vm.spec.image,
                        "entrypoint": vm.spec.entrypoint,
                        "cmd": vm.spec.cmd,
                        "network": vm.spec.resources.network,
                    });
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

            for vm in &vms {
                let phase = vm
                    .status
                    .as_ref()
                    .map(|s| s.phase.to_string())
                    .unwrap_or_else(|| "unknown".into());
                let storage_gib = vm
                    .spec
                    .resources
                    .storage_gib
                    .unwrap_or(DEFAULT_STORAGE_SIZE_GIB);
                let overlay_gib = vm
                    .spec
                    .resources
                    .overlay_gib
                    .unwrap_or(DEFAULT_OVERLAY_SIZE_GIB);
                println!(
                    "{:<20} {:<10} {:>5} {:>10} {:>7} {:>7} {:>8} {:>8}",
                    truncate(&vm.name, 18),
                    phase,
                    vm.spec.resources.cpus,
                    format!("{} MiB", vm.spec.resources.memory_mib),
                    vm.spec.mounts.len(),
                    vm.spec.ports.len(),
                    format!("{} GiB", storage_gib),
                    format!("{} GiB", overlay_gib),
                );

                if self.verbose {
                    if let Some(ref status) = vm.status {
                        if let Some(pid) = status.pid {
                            println!("  PID: {}", pid);
                        }
                    }
                    for m in &vm.spec.mounts {
                        let ro_str = if m.read_only { " (ro)" } else { "" };
                        println!(
                            "  Mount: {} -> {}{}",
                            m.source.display(),
                            m.target.display(),
                            ro_str
                        );
                    }
                    for p in &vm.spec.ports {
                        println!("  Port: {} -> {}", p.host, p.guest);
                    }
                    if vm.spec.resources.network {
                        println!("  Network: enabled");
                    }
                    for cmd in &vm.spec.init {
                        println!("  Init: {}", cmd);
                    }
                    for (k, v) in &vm.spec.env {
                        println!("  Env: {}={}", k, v);
                    }
                    if let Some(ref wd) = vm.spec.workdir {
                        println!("  Workdir: {}", wd);
                    }
                    if let Some(ref status) = vm.status {
                        println!("  Created: {}", status.created_at);
                    }
                    println!();
                }
            }
        }

        Ok(())
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
    /// Machine to resize
    #[arg(short = 'n', long, value_name = "NAME", default_value = DEFAULT_MACHINE_NAME)]
    pub name: String,

    /// Storage disk size in GiB (expand only)
    #[arg(long, value_name = "GiB")]
    pub storage: Option<u64>,

    /// Overlay disk size in GiB (expand only)
    #[arg(long, value_name = "GiB")]
    pub overlay: Option<u64>,
}

impl ResizeCmd {
    pub fn run(self) -> smolvm::Result<()> {
        let db = SmolvmDb::open()?;
        control::resize_vm(&db, &self.name, self.storage, self.overlay)?;

        println!();
        println!("{} '{}' resized successfully.", "Machine", self.name);
        println!("Disk changes are applied immediately; filesystem will expand on next boot.");
        Ok(())
    }
}

// ============================================================================
// Network Test Command
// ============================================================================

/// Test network connectivity directly from machine (debug TSI).
#[derive(Args, Debug)]
pub struct NetworkTestCmd {
    /// Machine to test
    #[arg(long, default_value = DEFAULT_MACHINE_NAME)]
    pub name: String,

    /// URL to test
    #[arg(default_value = "http://1.1.1.1")]
    pub url: String,
}

impl NetworkTestCmd {
    pub fn run(self) -> smolvm::Result<()> {
        let db = SmolvmDb::open()?;
        let _ = control::get_vm(&db, &self.name)?;

        // Connect and test
        println!("Testing network from machine: {}", self.url);
        let mut handle = control::connect_vm(&self.name, true)?;
        let result = handle.network_test(&self.url)?;

        println!(
            "Result: {}",
            serde_json::to_string_pretty(&result).unwrap_or_default()
        );

        handle.detach();
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
    /// Machine to inspect
    #[arg(short = 'n', long, value_name = "NAME", default_value = DEFAULT_MACHINE_NAME)]
    pub name: String,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

impl ImagesCmd {
    pub fn run(self) -> smolvm::Result<()> {
        let db = SmolvmDb::open()?;
        let _ = control::get_vm(&db, &self.name)?;
        let mut handle = control::connect_vm(&self.name, true)?;

        let status = handle.storage_status()?;
        let images = handle.list_images()?;

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

        handle.detach();
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
    /// Machine to prune
    #[arg(short = 'n', long, value_name = "NAME", default_value = DEFAULT_MACHINE_NAME)]
    pub name: String,

    /// Show what would be removed without actually removing
    #[arg(long)]
    pub dry_run: bool,

    /// Remove all cached images (not just unreferenced layers)
    #[arg(long)]
    pub all: bool,
}

impl PruneCmd {
    pub fn run(self) -> smolvm::Result<()> {
        let db = SmolvmDb::open()?;
        let _ = control::get_vm(&db, &self.name)?;
        let mut handle = control::connect_vm(&self.name, true)?;

        if self.all {
            let images = handle.list_images()?;

            if images.is_empty() {
                println!("No cached images to remove.");
                handle.detach();
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
                let freed = handle.garbage_collect(false)?;
                println!("Freed {} of unreferenced layers", format_bytes(freed));
            }
        } else if self.dry_run {
            println!("Scanning for unreferenced layers...");
            let would_free = handle.garbage_collect(true)?;

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
            let freed = handle.garbage_collect(false)?;

            if freed > 0 {
                println!("Freed {}", format_bytes(freed));
            } else {
                println!("No unreferenced layers to remove.");
            }
        }

        handle.detach();
        Ok(())
    }
}

// ============================================================================
// Cp (File Copy) Command
// ============================================================================

/// Copy files between host and a running machine.
///
/// Uses `machine:path` syntax to specify the remote side.
///
/// Examples:
///   smolvm machine cp ./script.py myvm:/workspace/script.py    # upload
///   smolvm machine cp myvm:/workspace/output.json ./output.json # download
#[derive(Args, Debug)]
pub struct CpCmd {
    /// Source path (local file or machine:path)
    #[arg(value_name = "SRC")]
    pub src: String,

    /// Destination path (local file or machine:path)
    #[arg(value_name = "DST")]
    pub dst: String,
}

impl CpCmd {
    pub fn run(self) -> smolvm::Result<()> {
        // Parse src/dst to determine direction
        let (machine_name, guest_path, local_path, is_upload) =
            if let Some((name, path)) = self.src.split_once(':') {
                // Download: machine:path -> local
                (name.to_string(), path.to_string(), self.dst.clone(), false)
            } else if let Some((name, path)) = self.dst.split_once(':') {
                // Upload: local -> machine:path
                (name.to_string(), path.to_string(), self.src.clone(), true)
            } else {
                return Err(smolvm::Error::config(
                    "cp",
                    "one of SRC or DST must use machine:path syntax (e.g., myvm:/workspace/file)",
                ));
            };

        let db = SmolvmDb::open()?;
        let _ = control::get_vm(&db, &machine_name)?;
        let mut handle = control::connect_vm(&machine_name, false)?;

        if is_upload {
            let data = std::fs::read(&local_path).map_err(|e| {
                smolvm::Error::agent("read local file", format!("{}: {}", local_path, e))
            })?;
            let size = data.len();
            handle.write_file(&guest_path, &data, None)?;
            eprintln!("Uploaded {} ({} bytes) -> {}", local_path, size, guest_path);
        } else {
            let data = handle.read_file(&guest_path)?;
            std::fs::write(&local_path, &data).map_err(|e| {
                smolvm::Error::agent("write local file", format!("{}: {}", local_path, e))
            })?;
            eprintln!(
                "Downloaded {} ({} bytes) -> {}",
                guest_path,
                data.len(),
                local_path
            );
        }

        handle.detach();
        Ok(())
    }
}

// ============================================================================
// Monitor Command
// ============================================================================

/// Monitor a running machine with health checks and restart policy.
///
/// Runs in the foreground, watching the machine and restarting on crash
/// or health check failure. Uses the restart policy from the machine's
/// config (set via Smolfile [restart] or --restart flag on create).
///
/// Ctrl+C stops monitoring; the machine keeps running.
///
/// Examples:
///   smolvm machine monitor --name myvm
///   smolvm machine monitor --name myvm --health-cmd "curl -f http://localhost:8080/health"
///   smolvm machine monitor --name myvm --restart always --interval 10
#[derive(Args, Debug)]
pub struct MonitorCmd {
    /// Machine to monitor (default: "default")
    #[arg(short = 'n', long, value_name = "NAME")]
    pub name: Option<String>,

    /// Override restart policy (never, always, on-failure, unless-stopped)
    #[arg(long, value_name = "POLICY")]
    pub restart: Option<String>,

    /// Health check command (run inside the VM via sh -c)
    #[arg(long, value_name = "CMD")]
    pub health_cmd: Option<String>,

    /// Health check timeout in seconds
    #[arg(long, default_value = "5", value_name = "SECS")]
    pub health_timeout: u64,

    /// Check interval in seconds
    #[arg(long, default_value = "5", value_name = "SECS")]
    pub interval: u64,

    /// Health check failures before triggering restart
    #[arg(long, default_value = "3", value_name = "N")]
    pub health_retries: u32,
}

impl MonitorCmd {
    pub fn run(self) -> smolvm::Result<()> {
        use smolvm::config::{RecordState, RestartPolicy};
        use smolvm::db::SmolvmDb;
        use smolvm::Error;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let name = self.name.unwrap_or_else(|| "default".to_string());

        // Load machine config from DB
        let db = SmolvmDb::open()?;
        let record = db
            .get_vm(&name)?
            .ok_or_else(|| Error::vm_not_found(&name))?;

        // Build restart config: CLI override > VmRecord config
        let mut restart = record.restart.clone();
        if let Some(ref policy_str) = self.restart {
            restart.policy = policy_str
                .parse::<RestartPolicy>()
                .map_err(|e| Error::config("--restart", e))?;
        }

        // Resolve health check: CLI override > VmRecord config
        let health_cmd = self
            .health_cmd
            .clone()
            .map(|c| vec!["sh".into(), "-c".into(), c])
            .or_else(|| record.health_cmd.clone());
        let health_timeout =
            Duration::from_secs(record.health_timeout_secs.unwrap_or(self.health_timeout));
        let health_retries = record.health_retries.unwrap_or(self.health_retries);
        let interval = Duration::from_secs(record.health_interval_secs.unwrap_or(self.interval));
        let startup_grace = record
            .health_startup_grace_secs
            .map(Duration::from_secs)
            .unwrap_or(Duration::ZERO);

        drop(db);

        // Ensure machine is running
        let manager = AgentManager::for_vm(&name)
            .map_err(|e| Error::agent("create agent manager", e.to_string()))?;

        if !manager.is_process_alive() {
            println!("Machine '{}' is not running, starting...", name);
            let db = SmolvmDb::open()?;
            control::start_vm(&db, &name)?.detach();
        }

        println!(
            "Monitoring machine '{}' (policy: {}, interval: {}s)",
            name,
            restart.policy,
            interval.as_secs()
        );
        if health_cmd.is_some() {
            println!(
                "  Health check: retries={}, timeout={}s",
                health_retries,
                health_timeout.as_secs()
            );
        }

        // Ctrl+C handler via SIGINT
        //
        // SAFETY: `stop` is an Arc<AtomicBool> that lives until the end of this
        // function. The cloned Arc below keeps a strong reference alive for the
        // duration of the monitor loop, so the raw pointer stored in STOP_FLAG
        // remains valid until after we break out of the loop and the function
        // returns. The handler only does an atomic store, which is async-signal-safe.
        let stop = Arc::new(AtomicBool::new(false));
        {
            let stop = stop.clone();
            unsafe {
                let _ = libc::signal(libc::SIGINT, {
                    static mut STOP_FLAG: *const AtomicBool = std::ptr::null();
                    STOP_FLAG = Arc::as_ptr(&stop);
                    extern "C" fn handler(_: libc::c_int) {
                        unsafe {
                            if !STOP_FLAG.is_null() {
                                (*STOP_FLAG).store(true, Ordering::SeqCst);
                            }
                        }
                    }
                    handler as *const () as libc::sighandler_t
                });
            }
        }

        let mut consecutive_health_failures: u32 = 0;
        let mut last_check = std::time::Instant::now();
        let mut last_start = std::time::Instant::now(); // tracks startup grace period

        loop {
            std::thread::sleep(interval);

            if stop.load(Ordering::SeqCst) {
                break;
            }

            // Detect sleep/wake: if the elapsed wall time is much longer than
            // the expected interval, the machine was likely suspended (laptop lid
            // closed). Reset health failures and skip this cycle to give the VM
            // time to recover network connections.
            let elapsed = last_check.elapsed();
            last_check = std::time::Instant::now();
            if elapsed > interval * 3 {
                let sleep_secs = elapsed.as_secs() - interval.as_secs();
                println!(
                    "  detected suspend (~{}s) — skipping health check for recovery",
                    sleep_secs
                );
                consecutive_health_failures = 0;
                continue;
            }

            // Refresh manager to pick up PID changes after restart
            let manager = match AgentManager::for_vm(&name) {
                Ok(m) => m,
                Err(_) => continue,
            };

            if manager.is_process_alive() {
                // Skip health checks during startup grace period
                if !startup_grace.is_zero() && last_start.elapsed() < startup_grace {
                    continue;
                }

                // Machine is alive — run health check if configured
                if let Some(ref cmd) = health_cmd {
                    match AgentClient::connect_with_short_timeout(manager.vsock_socket()) {
                        Ok(mut client) => {
                            match client.vm_exec(cmd.clone(), vec![], None, Some(health_timeout)) {
                                Ok((0, _, _)) => {
                                    if consecutive_health_failures > 0 {
                                        println!("  health check passed (recovered)");
                                    }
                                    consecutive_health_failures = 0;
                                }
                                Ok((code, _, stderr)) => {
                                    consecutive_health_failures += 1;
                                    println!(
                                        "  health check failed (exit {}, {}/{}): {}",
                                        code,
                                        consecutive_health_failures,
                                        health_retries,
                                        stderr.trim()
                                    );
                                }
                                Err(e) => {
                                    consecutive_health_failures += 1;
                                    println!(
                                        "  health check error ({}/{}): {}",
                                        consecutive_health_failures, health_retries, e
                                    );
                                }
                            }

                            if consecutive_health_failures >= health_retries {
                                println!("  unhealthy — stopping machine for restart");
                                if let Ok(db) = SmolvmDb::open() {
                                    let _ = control::stop_vm(&db, &name);
                                }
                                continue;
                            }
                        }
                        Err(_) => {
                            consecutive_health_failures += 1;
                            println!(
                                "  cannot connect to agent ({}/{})",
                                consecutive_health_failures, health_retries
                            );
                        }
                    }
                }
            } else {
                // Machine is dead
                consecutive_health_failures = 0;

                let exit_code = manager.child_pid().and_then(smolvm::process::try_wait);

                println!(
                    "  machine exited (exit code: {})",
                    exit_code
                        .map(|c| c.to_string())
                        .unwrap_or_else(|| "unknown".into())
                );

                // Update DB state
                if let Ok(db) = SmolvmDb::open() {
                    let _ = db.update_vm(&name, |r| {
                        r.state = RecordState::Stopped;
                        r.pid = None;
                        r.last_exit_code = exit_code;
                    });
                }

                if restart.should_restart(exit_code) {
                    let backoff = restart.backoff_duration();
                    restart.restart_count += 1;

                    println!(
                        "  restarting (attempt {}, backoff {}s)...",
                        restart.restart_count,
                        backoff.as_secs()
                    );

                    if let Ok(db) = SmolvmDb::open() {
                        let _ = db.update_vm(&name, |r| {
                            r.restart.restart_count = restart.restart_count;
                        });
                    }

                    std::thread::sleep(backoff);

                    if stop.load(Ordering::SeqCst) {
                        break;
                    }

                    match SmolvmDb::open().and_then(|db| control::start_vm(&db, &name)) {
                        Ok(handle) => {
                            handle.detach();
                            println!("  machine restarted");
                            last_start = std::time::Instant::now();
                        }
                        Err(e) => println!("  restart failed: {}", e),
                    }
                } else {
                    println!(
                        "  not restarting (policy: {}, count: {}/{})",
                        restart.policy,
                        restart.restart_count,
                        if restart.max_retries > 0 {
                            restart.max_retries.to_string()
                        } else {
                            "unlimited".into()
                        }
                    );
                    break;
                }
            }
        }

        // Mark user stopped
        if let Ok(db) = SmolvmDb::open() {
            let _ = db.update_vm(&name, |r| {
                r.restart.user_stopped = true;
            });
        }

        println!(
            "\nStopped monitoring. Machine '{}' may still be running.",
            name
        );
        Ok(())
    }
}
