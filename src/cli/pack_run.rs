//! `pack run` subcommand: run a VM from a `.smolmachine` sidecar file.
//!
//! This module provides two entry points:
//!
//! 1. **`PackRunCmd`** — the explicit `smolvm pack run` subcommand
//! 2. **`run_as_packed_binary()`** — auto-detected packed binary mode,
//!    called from `main()` before clap parses the normal CLI
//!
//! Both paths converge on the same VM launch infrastructure.

use crate::cli::parsers::{mounts_to_virtiofs_bindings, parse_env_spec};
use clap::{Args, Parser, Subcommand};
use smolvm::agent::launcher_dynamic::{
    launch_agent_vm_dynamic, KrunFunctions, PackedLaunchConfig, PackedMount,
};
use smolvm::agent::{AgentClient, RunConfig, VmResources};
use smolvm::data::network::PortMapping;
use smolvm::data::storage::HostMount;
use smolvm::Error;
use smolvm::DEFAULT_SHELL_CMD;
use smolvm_pack::detect::PackedMode;
use smolvm_pack::extract;
use smolvm_pack::format::PackMode;
use smolvm_pack::packer::{
    read_footer_from_sidecar, read_manifest_from_sidecar, verify_sidecar_checksum,
};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Timeout waiting for the agent to become ready.
const AGENT_READY_TIMEOUT: Duration = Duration::from_secs(30);

/// Resolve the lib directory containing libkrun/libkrunfw.
///
/// Two-file mode: libs embedded in stub binary (SMOLLIBS footer).
/// Single-file mode: libs extracted from Mach-O section to cache_dir/lib/.
/// `smolvm pack run`: uses the host-installed libs.
fn resolve_lib_dir(cache_dir: &Path, debug: bool) -> smolvm::Result<PathBuf> {
    // Two-file mode: libs embedded in stub binary (SMOLLIBS footer)
    if let Ok(exe_path) = std::env::current_exe() {
        if let Ok(Some(lib_dir)) = extract::extract_libs_from_binary(&exe_path, debug) {
            if debug {
                eprintln!("debug: using libs from stub binary: {}", lib_dir.display());
            }
            return Ok(lib_dir);
        }
    }

    // Single-file mode: libs extracted from Mach-O section alongside other assets
    let cache_lib = cache_dir.join("lib");
    if cache_lib.exists() {
        if debug {
            eprintln!("debug: using libs from cache: {}", cache_lib.display());
        }
        return Ok(cache_lib);
    }

    // Host-installed libs (for `smolvm pack run .smolmachine`)
    if let Some(host_lib) = smolvm::agent::find_lib_dir() {
        if debug {
            eprintln!(
                "debug: using libs from host install: {}",
                host_lib.display()
            );
        }
        return Ok(host_lib);
    }

    Err(Error::agent(
        "find libraries",
        "libkrun/libkrunfw not found. The binary may be corrupted or the libraries are missing.",
    ))
}

/// Convert parsed mounts to PackedMount format for the VM launcher.
fn mounts_to_packed(mounts: &[smolvm::data::storage::HostMount]) -> Vec<PackedMount> {
    mounts
        .iter()
        .enumerate()
        .map(|(i, m)| PackedMount {
            tag: HostMount::mount_tag(i),
            host_path: m.source.to_string_lossy().to_string(),
            guest_path: m.target.to_string_lossy().to_string(),
            read_only: m.read_only,
        })
        .collect()
}

/// Run a VM from a packed `.smolmachine` sidecar file.
///
/// Extracts runtime assets (if not already cached), boots a VM using
/// dynamically loaded libkrun, and executes a command using the full
/// smolvm agent infrastructure.
///
/// Examples:
///   smolvm pack run -- echo hello
///   smolvm pack run --sidecar my-app.smolmachine -it -- /bin/sh
///   smolvm pack run -p 8080:80 --net
#[derive(Args, Debug)]
pub struct PackRunCmd {
    /// Path to the `.smolmachine` sidecar file.
    ///
    /// If not specified, looks for `<exe_name>.smolmachine` next to the
    /// smolvm binary, or any `.smolmachine` file in the current directory.
    #[arg(long, value_name = "PATH")]
    pub sidecar: Option<PathBuf>,

    /// Command and arguments to run (default: image entrypoint)
    #[arg(trailing_var_arg = true, value_name = "COMMAND")]
    pub command: Vec<String>,

    /// Keep stdin open for interactive input
    #[arg(short = 'i', long, help_heading = "Execution")]
    pub interactive: bool,

    /// Allocate a pseudo-TTY (use with -i for interactive shells)
    #[arg(short = 't', long, help_heading = "Execution")]
    pub tty: bool,

    /// Kill command after duration (e.g., "30s", "5m")
    #[arg(
        long,
        value_parser = crate::cli::parsers::parse_duration,
        value_name = "DURATION",
        help_heading = "Execution"
    )]
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

    /// Mount host directory into container (can be used multiple times)
    #[arg(
        short = 'v',
        long = "volume",
        value_name = "HOST:CONTAINER[:ro]",
        help_heading = "Container"
    )]
    pub volume: Vec<String>,

    /// Expose port from container to host (can be used multiple times)
    #[arg(
        short = 'p',
        long = "port",
        value_parser = PortMapping::parse,
        value_name = "HOST:GUEST",
        help_heading = "Network"
    )]
    pub port: Vec<PortMapping>,

    /// Enable outbound network access
    #[arg(long, help_heading = "Network")]
    pub net: bool,

    /// Number of virtual CPUs (overrides manifest default)
    #[arg(long, value_name = "N", help_heading = "Resources")]
    pub cpus: Option<u8>,

    /// Memory allocation in MiB (overrides manifest default)
    #[arg(long, value_name = "MiB", help_heading = "Resources")]
    pub mem: Option<u32>,

    /// Storage disk size in GiB (for OCI layers and container data)
    #[arg(long, value_name = "GiB", help_heading = "Resources")]
    pub storage: Option<u64>,

    /// Overlay disk size in GiB (for persistent rootfs changes)
    #[arg(long, value_name = "GiB", help_heading = "Resources")]
    pub overlay: Option<u64>,

    /// Re-extract assets even if already cached
    #[arg(long)]
    pub force_extract: bool,

    /// Show manifest info and exit
    #[arg(long)]
    pub info: bool,

    /// Enable debug output
    #[arg(long)]
    pub debug: bool,
}

impl PackRunCmd {
    /// Execute the pack run command.
    pub fn run(self) -> smolvm::Result<()> {
        // 1. Resolve sidecar path
        let sidecar_path = resolve_sidecar_path(self.sidecar.as_deref())?;

        if self.debug {
            eprintln!("debug: using sidecar: {}", sidecar_path.display());
        }

        // 2. Read footer and verify checksum before trusting any content
        let footer = read_footer_from_sidecar(&sidecar_path)
            .map_err(|e| Error::agent("read footer", e.to_string()))?;

        match verify_sidecar_checksum(&sidecar_path, &footer) {
            Ok(true) => {
                if self.debug {
                    eprintln!("debug: sidecar checksum verified ({:08x})", footer.checksum);
                }
            }
            Ok(false) => {
                return Err(Error::agent(
                    "verify sidecar",
                    format!(
                        "checksum mismatch for {}: sidecar may be corrupt or tampered with.\n\
                         Try re-packing the image with `smolvm pack`.",
                        sidecar_path.display()
                    ),
                ));
            }
            Err(e) => {
                return Err(Error::agent(
                    "verify sidecar",
                    format!("failed to verify checksum: {}", e),
                ));
            }
        }

        // 3. Read manifest (safe now that checksum is verified)
        let manifest = read_manifest_from_sidecar(&sidecar_path)
            .map_err(|e| Error::agent("read manifest", e.to_string()))?;

        // 4. Handle --info: show manifest and exit
        if self.info {
            let mode_str = match manifest.mode {
                PackMode::Container => "container",
                PackMode::Vm => "vm",
            };
            println!("Mode:       {}", mode_str);
            println!("Image:      {}", manifest.image);
            println!("Digest:     {}", manifest.digest);
            println!("Platform:   {}", manifest.platform);
            println!("CPUs:       {}", manifest.cpus);
            println!("Memory:     {} MiB", manifest.mem);
            if !manifest.entrypoint.is_empty() {
                println!("Entrypoint: {}", manifest.entrypoint.join(" "));
            }
            if !manifest.cmd.is_empty() {
                println!("Cmd:        {}", manifest.cmd.join(" "));
            }
            if let Some(ref wd) = manifest.workdir {
                println!("Workdir:    {}", wd);
            }
            if !manifest.env.is_empty() {
                println!("Env:");
                for e in &manifest.env {
                    println!("  {}", e);
                }
            }
            println!("Checksum:   {:08x}", footer.checksum);
            return Ok(());
        }

        // 5. Extract assets to cache (locked to prevent concurrent extraction races)
        let cache_dir = extract::get_cache_dir(footer.checksum)
            .map_err(|e| Error::agent("get cache dir", e.to_string()))?;

        extract::extract_sidecar(
            &sidecar_path,
            &cache_dir,
            &footer,
            self.force_extract,
            self.debug,
        )
        .map_err(|e| Error::agent("extract assets", e.to_string()))?;

        // 6. Set up paths — use a unique runtime directory per invocation so
        //    concurrent runs of the same checksum don't conflict on
        //    storage.ext4 / agent.sock.  tempdir_in gives us a truly unique
        //    directory that survives PID reuse and abrupt termination.
        let rootfs_path = cache_dir.join("agent-rootfs");
        let lib_dir = resolve_lib_dir(&cache_dir, self.debug)?;
        let layers_dir = cache_dir.join("layers");
        let runtime_parent = cache_dir.join("runtime");
        std::fs::create_dir_all(&runtime_parent)
            .map_err(|e| Error::agent("create runtime parent", e.to_string()))?;
        let runtime_dir = tempfile::tempdir_in(&runtime_parent)
            .map_err(|e| Error::agent("create runtime dir", e.to_string()))?;

        let storage_path = runtime_dir.path().join("storage.ext4");
        let vsock_path = runtime_dir.path().join("agent.sock");

        // Create storage disk (each invocation gets its own copy)
        let template = manifest
            .assets
            .storage_template
            .as_ref()
            .map(|t| t.path.as_str());
        extract::create_or_copy_storage_disk(&cache_dir, template, &storage_path, self.storage)
            .map_err(|e| Error::agent("create storage disk", e.to_string()))?;

        let overlay_runtime_path = setup_vm_overlay(
            &manifest,
            &cache_dir,
            &runtime_dir.path().join("overlay.raw"),
            self.overlay,
        )?;

        // 7. Parse CLI args
        let mounts = HostMount::parse(&self.volume)?;
        let port_mappings = PortMapping::to_tuples(&self.port);

        let resources = VmResources {
            cpus: self.cpus.unwrap_or(manifest.cpus),
            memory_mib: self.mem.unwrap_or(manifest.mem),
            network: self.net || !self.port.is_empty(),
            storage_gib: self.storage,
            overlay_gib: self.overlay,
            allowed_cidrs: None,
        };

        // Build packed mounts for the launcher
        let packed_mounts = mounts_to_packed(&mounts);

        if self.debug {
            eprintln!("debug: rootfs={}", rootfs_path.display());
            eprintln!("debug: lib_dir={}", lib_dir.display());
            eprintln!("debug: storage={}", storage_path.display());
            eprintln!("debug: vsock={}", vsock_path.display());
            eprintln!(
                "debug: resources cpus={} mem={} net={}",
                resources.cpus, resources.memory_mib, resources.network
            );
        }

        // 8. Fork child → launch VM with dynamically loaded libkrun
        smolvm::process::install_sigchld_handler();

        let console_log_path = runtime_dir.path().join("console.log");
        let vsock_path_clone = vsock_path.clone();
        let child_pid = smolvm::process::fork_session_leader(move || {
            // Child process: load libkrun via dlopen and launch VM
            let krun = match unsafe { KrunFunctions::load(&lib_dir) } {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("failed to load libkrun: {}", e);
                    smolvm::process::exit_child(1);
                }
            };

            let config = PackedLaunchConfig {
                rootfs_path: &rootfs_path,
                storage_path: &storage_path,
                vsock_socket: &vsock_path_clone,
                layers_dir: &layers_dir,
                mounts: &packed_mounts,
                port_mappings: &port_mappings,
                resources,
                overlay_path: overlay_runtime_path.as_deref(),
                debug: self.debug,
                console_log: console_log_path,
            };

            // Detach from parent's terminal so libkrun doesn't
            // steal keystrokes or corrupt terminal state.
            smolvm::process::detach_stdio();

            if let Err(e) = launch_agent_vm_dynamic(&krun, &config) {
                let _ = e;
            }

            smolvm::process::exit_child(1);
        })
        .map_err(|e| Error::agent("fork VM process", e.to_string()))?;

        // Capture the child's start time so we can verify PID identity
        // later (guards against PID reuse).  The proc info may not be
        // available on the very first try if the kernel hasn't finished
        // setting up the child, so retry briefly.
        let child_start_time = {
            let mut st = smolvm::process::process_start_time(child_pid);
            if st.is_none() && smolvm::process::is_alive(child_pid) {
                for _ in 0..5 {
                    std::thread::sleep(Duration::from_millis(1));
                    st = smolvm::process::process_start_time(child_pid);
                    if st.is_some() {
                        break;
                    }
                }
            }
            // If the child is alive but we still can't get its start
            // time, we have no way to safely verify PID identity later.
            // Kill it now (we KNOW it's our child — we just forked it)
            // rather than risk either an orphan or a misidentified kill.
            if st.is_none() && smolvm::process::is_alive(child_pid) {
                let _ = smolvm::process::stop_process_fast(child_pid, Duration::from_secs(5), true);
                // Clean up runtime dir ourselves since the guard won't
                // be created.
                if let Err(e) = std::fs::remove_dir_all(runtime_dir.path()) {
                    tracing::debug!(error = %e, "cleanup: remove runtime dir after failed child start");
                }
                return Err(Error::agent(
                    "verify child process",
                    "unable to capture child start time for safe lifecycle management",
                ));
            }
            st
        };

        if self.debug {
            eprintln!("debug: forked VM process with PID {}", child_pid);
        }

        // Guard ensures the VM child is terminated and runtime dir is
        // cleaned up on every exit path — including ? propagation,
        // panics, AND the explicit process::exit() on the success path
        // (which skips Rust destructors, so we must drop manually).
        // start_time is guaranteed Some when the child is alive (enforced
        // above), so is_our_process_strict always has data to verify.
        let child_guard = ChildGuard {
            pid: child_pid,
            start_time: child_start_time,
            runtime_dir,
        };

        // 9. Parent: wait for agent, connect, execute command
        let mut client = wait_for_agent(&vsock_path, self.debug)?;

        let exit_code = execute_command(&mut client, &manifest, &self, &mounts)?;

        // std::process::exit skips destructors, so drop explicitly first.
        drop(child_guard);
        std::process::exit(exit_code);
    }
}

/// RAII guard that terminates the VM child process and cleans up the
/// per-invocation runtime directory on drop.
struct ChildGuard {
    pid: libc::pid_t,
    start_time: Option<u64>,
    runtime_dir: tempfile::TempDir,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        // Only signal the child if we can verify it's still ours via
        // start_time.  When start_time is None (child exited before we
        // could query it), we skip signaling entirely — the PID may have
        // been recycled and we must not target an unrelated process.
        if smolvm::process::is_our_process_strict(self.pid, self.start_time) {
            let _ = smolvm::process::stop_process_fast(self.pid, Duration::from_secs(5), true);
        }
        // TempDir removes itself on drop, but we also do an explicit
        // remove to handle partially-cleaned states.
        if let Err(e) = std::fs::remove_dir_all(self.runtime_dir.path()) {
            tracing::debug!(error = %e, "cleanup: remove runtime dir on drop");
        }
    }
}

/// Resolve the path to the `.smolmachine` sidecar file.
fn resolve_sidecar_path(explicit: Option<&Path>) -> smolvm::Result<PathBuf> {
    // Explicit path
    if let Some(path) = explicit {
        if path.exists() {
            return Ok(path.to_path_buf());
        }
        return Err(Error::agent(
            "find sidecar",
            format!(
                "sidecar file not found: {}\nSpecify with --sidecar PATH",
                path.display()
            ),
        ));
    }

    // Try next to the executable: <exe>.smolmachine
    if let Ok(exe) = std::env::current_exe() {
        let sidecar = smolvm_pack::sidecar_path_for(&exe);
        if sidecar.exists() {
            return Ok(sidecar);
        }
    }

    // Try any .smolmachine file in the current directory
    if let Ok(cwd) = std::env::current_dir() {
        let entries: Vec<_> = std::fs::read_dir(&cwd)
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "smolmachine"))
            .collect();

        if entries.len() == 1 {
            return Ok(entries[0].path());
        }
        if entries.len() > 1 {
            return Err(Error::agent(
                "find sidecar",
                "multiple .smolmachine files in current directory. Specify with --sidecar PATH"
                    .to_string(),
            ));
        }
    }

    Err(Error::agent(
        "find sidecar",
        "no .smolmachine sidecar file found.\n\
         Specify with: smolvm pack run --sidecar PATH",
    ))
}

/// Set up the overlay disk for VM mode.
///
/// If the manifest specifies VM mode, copies the overlay template from
/// `cache_dir` to `dest`. Returns the overlay path (for `PackedLaunchConfig`)
/// or `None` for container mode.
///
/// Fails hard if the manifest is VM mode but the overlay template is missing.
fn setup_vm_overlay(
    manifest: &smolvm_pack::PackManifest,
    cache_dir: &Path,
    dest: &Path,
    overlay_gb: Option<u64>,
) -> smolvm::Result<Option<PathBuf>> {
    if manifest.mode == PackMode::Vm {
        // VM mode: use the overlay template from the pack
        let overlay_template = manifest
            .assets
            .overlay_template
            .as_ref()
            .map(|t| t.path.as_str());

        extract::copy_overlay_template(cache_dir, overlay_template, dest, overlay_gb).map_err(
            |e| {
                Error::agent(
                    "setup overlay",
                    format!(
                        "VM mode overlay template is missing or corrupt: {}. \
                         Try re-packing with `smolvm pack --from-vm`.",
                        e
                    ),
                )
            },
        )?;

        return Ok(Some(dest.to_path_buf()));
    }

    // OCI image mode: create a fresh overlay disk so the guest has a
    // writable root (needed for crun to mkdir /dev, mount proc, etc.)
    if !dest.exists() {
        let size_gb = overlay_gb.unwrap_or(smolvm::storage::DEFAULT_OVERLAY_SIZE_GIB);
        smolvm::storage::OverlayDisk::open_or_create_at(dest, size_gb)
            .map_err(|e| Error::agent("create overlay disk", e.to_string()))?;
    }

    Ok(Some(dest.to_path_buf()))
}

/// Wait for the agent to become ready on the vsock socket.
fn wait_for_agent(vsock_path: &Path, debug: bool) -> smolvm::Result<AgentClient> {
    use std::thread;
    use std::time::Instant;

    let start = Instant::now();
    let poll_interval = Duration::from_millis(100);

    loop {
        if start.elapsed() > AGENT_READY_TIMEOUT {
            return Err(Error::agent(
                "wait for agent",
                format!(
                    "agent did not become ready within {} seconds",
                    AGENT_READY_TIMEOUT.as_secs()
                ),
            ));
        }

        if vsock_path.exists() {
            // Connect opens the Unix socket to the muxer, but the guest agent
            // may not be listening on vsock port 6000 yet. We must ping to
            // verify end-to-end connectivity before declaring the agent ready.
            match AgentClient::connect(vsock_path) {
                Ok(mut client) => match client.ping() {
                    Ok(_) => {
                        if debug {
                            eprintln!(
                                "debug: agent ready after {:.1}s",
                                start.elapsed().as_secs_f64()
                            );
                        }
                        return Ok(client);
                    }
                    Err(_) => {
                        // Muxer accepted but guest agent not ready yet
                    }
                },
                Err(_) => {
                    // Socket exists but not connectable yet
                }
            }
        }

        thread::sleep(poll_interval);
    }
}

/// Build the command to execute from manifest defaults and CLI overrides.
fn build_command(manifest: &smolvm_pack::PackManifest, cli_command: &[String]) -> Vec<String> {
    if !cli_command.is_empty() {
        return cli_command.to_vec();
    }

    // Use manifest entrypoint + cmd
    let mut cmd = manifest.entrypoint.clone();
    cmd.extend(manifest.cmd.clone());

    if cmd.is_empty() {
        vec![DEFAULT_SHELL_CMD.to_string()]
    } else {
        cmd
    }
}

/// Build environment variables from manifest defaults and CLI overrides.
fn build_env(manifest: &smolvm_pack::PackManifest, cli_env: &[String]) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = manifest
        .env
        .iter()
        .filter_map(|e| parse_env_spec(e))
        .collect();

    // CLI env overrides manifest env
    for spec in cli_env {
        if let Some((key, value)) = parse_env_spec(spec) {
            // Remove existing key if present
            env.retain(|(k, _)| k != &key);
            env.push((key, value));
        }
    }

    env
}

/// Execute the command in the VM using the existing AgentClient.
///
/// In Container mode, runs via `client.run()` / `client.run_interactive()` (crun container).
/// In VM mode, runs via `client.vm_exec()` / `client.vm_exec_interactive()` (direct in rootfs).
fn execute_command(
    client: &mut AgentClient,
    manifest: &smolvm_pack::PackManifest,
    args: &PackRunCmd,
    mounts: &[smolvm::data::storage::HostMount],
) -> smolvm::Result<i32> {
    let command = build_command(manifest, &args.command);
    let env = build_env(manifest, &args.env);
    let workdir = args.workdir.clone().or_else(|| manifest.workdir.clone());

    let params = ExecParams {
        command,
        env,
        workdir,
        interactive: args.interactive,
        tty: args.tty,
        timeout: args.timeout,
    };
    execute_packed_command(client, manifest, params, mounts)
}

/// Resolved execution parameters for a packed command.
struct ExecParams {
    command: Vec<String>,
    env: Vec<(String, String)>,
    workdir: Option<String>,
    interactive: bool,
    tty: bool,
    timeout: Option<Duration>,
}

/// Execute a command in the VM — shared by both `PackRunCmd` and packed binary paths.
#[allow(clippy::too_many_arguments)]
fn execute_packed_command(
    client: &mut AgentClient,
    manifest: &smolvm_pack::PackManifest,
    params: ExecParams,
    mounts: &[smolvm::data::storage::HostMount],
) -> smolvm::Result<i32> {
    let ExecParams {
        command,
        env,
        workdir,
        interactive,
        tty,
        timeout,
    } = params;
    match manifest.mode {
        PackMode::Vm => {
            // VM mode: execute directly in the VM rootfs
            if interactive || tty {
                client.vm_exec_interactive(command, env, workdir, timeout, tty)
            } else {
                let (exit_code, stdout, stderr) = client.vm_exec(command, env, workdir, timeout)?;

                if !stdout.is_empty() {
                    print!("{}", stdout);
                }
                if !stderr.is_empty() {
                    eprint!("{}", stderr);
                }
                crate::cli::flush_output();
                Ok(exit_code)
            }
        }
        PackMode::Container => {
            // Container mode: run inside crun container
            let mount_bindings = mounts_to_virtiofs_bindings(mounts);

            if interactive || tty {
                let config = RunConfig::new(&manifest.image, command)
                    .with_env(env)
                    .with_workdir(workdir)
                    .with_mounts(mount_bindings)
                    .with_timeout(timeout)
                    .with_tty(tty);
                client.run_interactive(config)
            } else {
                let (exit_code, stdout, stderr) = client.run_with_mounts_and_timeout(
                    &manifest.image,
                    command,
                    env,
                    workdir,
                    mount_bindings,
                    timeout,
                )?;

                if !stdout.is_empty() {
                    print!("{}", stdout);
                }
                if !stderr.is_empty() {
                    eprint!("{}", stderr);
                }
                crate::cli::flush_output();
                Ok(exit_code)
            }
        }
    }
}

// ===========================================================================
// Packed binary auto-detection entry point
// ===========================================================================

// CLI for packed binary mode. Parsed in `run_as_packed_binary()` before
// the normal smolvm CLI. Uses subcommands matching the smolvm pattern.
#[derive(Parser, Debug)]
#[command(about = "a smol machine")]
#[command(
    long_about = "A portable, self-contained virtual machine.\n\nRun with no arguments to execute the packaged entrypoint.\nUse subcommands for more control."
)]
#[command(version)]
#[command(subcommand_required = false)]
struct PackedCli {
    /// Subcommand to execute (defaults to `run` if omitted)
    #[command(subcommand)]
    command: Option<PackedCmd>,

    /// Force re-extraction of assets
    #[arg(long, global = true)]
    force_extract: bool,

    /// Print debug information
    #[arg(long, global = true)]
    debug: bool,
}

#[derive(Subcommand, Debug)]
enum PackedCmd {
    /// Run a command in an ephemeral VM (cleaned up after exit)
    Run(PackedRunArgs),
    /// Start a persistent VM
    Start(PackedStartArgs),
    /// Execute a command in a running VM
    Exec(PackedExecArgs),
    /// Stop the VM
    Stop,
    /// Show VM status
    Status,
    /// Show packed binary info
    Info,
}

/// Arguments for the `run` subcommand (ephemeral execution).
#[derive(Args, Debug, Default)]
struct PackedRunArgs {
    /// Command to run (overrides image entrypoint/cmd)
    #[arg(trailing_var_arg = true, value_name = "COMMAND")]
    command: Vec<String>,

    /// Keep stdin open for interactive input
    #[arg(short = 'i', long)]
    interactive: bool,

    /// Allocate a pseudo-TTY (use with -i for interactive shells)
    #[arg(short = 't', long)]
    tty: bool,

    /// Kill command after duration (e.g., "30s", "5m")
    #[arg(long, value_parser = crate::cli::parsers::parse_duration, value_name = "DURATION")]
    timeout: Option<Duration>,

    /// Working directory inside the container
    #[arg(short = 'w', long = "workdir", value_name = "PATH")]
    workdir: Option<String>,

    /// Set environment variable (KEY=VALUE)
    #[arg(short = 'e', long = "env", value_name = "KEY=VALUE")]
    env: Vec<String>,

    /// Mount a volume (HOST:GUEST[:ro])
    #[arg(short = 'v', long = "volume", value_name = "HOST:GUEST[:ro]")]
    volume: Vec<String>,

    /// Expose port from container to host
    #[arg(short = 'p', long = "port", value_parser = PortMapping::parse, value_name = "HOST:GUEST")]
    port: Vec<PortMapping>,

    /// Enable outbound network access
    #[arg(long)]
    net: bool,

    /// Number of vCPUs (overrides default)
    #[arg(long, value_name = "N")]
    cpus: Option<u8>,

    /// Memory in MiB (overrides default)
    #[arg(long, value_name = "MiB")]
    mem: Option<u32>,

    /// Storage disk size in GiB
    #[arg(long, value_name = "GiB")]
    storage: Option<u64>,

    /// Overlay disk size in GiB
    #[arg(long, value_name = "GiB")]
    overlay: Option<u64>,
}

/// Arguments for the `start` subcommand (persistent daemon).
#[derive(Args, Debug)]
struct PackedStartArgs {
    /// Number of vCPUs (overrides default)
    #[arg(long, value_name = "N")]
    cpus: Option<u8>,

    /// Memory in MiB (overrides default)
    #[arg(long, value_name = "MiB")]
    mem: Option<u32>,

    /// Storage disk size in GiB
    #[arg(long, value_name = "GiB")]
    storage: Option<u64>,

    /// Overlay disk size in GiB
    #[arg(long, value_name = "GiB")]
    overlay: Option<u64>,

    /// Mount a volume (HOST:GUEST[:ro])
    #[arg(short = 'v', long = "volume", value_name = "HOST:GUEST[:ro]")]
    volume: Vec<String>,

    /// Expose port from container to host
    #[arg(short = 'p', long = "port", value_parser = PortMapping::parse, value_name = "HOST:GUEST")]
    port: Vec<PortMapping>,

    /// Enable outbound network access
    #[arg(long)]
    net: bool,
}

/// Arguments for the `exec` subcommand (run in existing VM).
#[derive(Args, Debug)]
struct PackedExecArgs {
    /// Command to run
    #[arg(trailing_var_arg = true, value_name = "COMMAND")]
    command: Vec<String>,

    /// Keep stdin open for interactive input
    #[arg(short = 'i', long)]
    interactive: bool,

    /// Allocate a pseudo-TTY (use with -i for interactive shells)
    #[arg(short = 't', long)]
    tty: bool,

    /// Kill command after duration (e.g., "30s", "5m")
    #[arg(long, value_parser = crate::cli::parsers::parse_duration, value_name = "DURATION")]
    timeout: Option<Duration>,

    /// Working directory inside the container
    #[arg(short = 'w', long = "workdir", value_name = "PATH")]
    workdir: Option<String>,

    /// Set environment variable (KEY=VALUE)
    #[arg(short = 'e', long = "env", value_name = "KEY=VALUE")]
    env: Vec<String>,
    // Note: -v/--volume is intentionally absent from exec. Virtiofs devices
    // are fixed at VM boot time, so mounts must be specified on `start`.
}

/// Entry point when auto-detection determines we are a packed binary.
///
/// Called from `main()` before clap parses the normal CLI.
/// Parses its own `PackedCli` args and executes accordingly.
/// Never returns — calls `std::process::exit()`.
pub fn run_as_packed_binary(mode: PackedMode) -> ! {
    // Use argv[0] as the binary name so --help and --version display
    // "my-app 0.5.1" instead of "smolvm 0.5.1".
    let bin_name = std::env::args()
        .next()
        .and_then(|a| {
            std::path::Path::new(&a)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| "packed-binary".to_string());

    let args: Vec<String> = std::iter::once(bin_name.clone())
        .chain(std::env::args().skip(1))
        .collect();
    // Leak is safe: this function is `-> !` so the process exits after parsing.
    let name_static: &'static str = Box::leak(bin_name.into_boxed_str());
    let matches = <PackedCli as clap::CommandFactory>::command()
        .name(name_static)
        .get_matches_from(args);
    let cli = <PackedCli as clap::FromArgMatches>::from_arg_matches(&matches)
        .unwrap_or_else(|e| e.exit());

    let result = pack_run_inner(mode, cli);
    match result {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("error: {}", e);
            std::process::exit(1);
        }
    }
}

fn pack_run_inner(mode: PackedMode, cli: PackedCli) -> smolvm::Result<()> {
    let debug = cli.debug;
    let force_extract = cli.force_extract;
    let command = cli
        .command
        .unwrap_or(PackedCmd::Run(PackedRunArgs::default()));

    match command {
        PackedCmd::Run(args) => run_ephemeral(mode, args, debug, force_extract),
        PackedCmd::Start(args) => daemon_start(&mode, args, debug, force_extract),
        PackedCmd::Exec(args) => {
            let checksum = mode_checksum(&mode);
            let manifest = read_manifest_for_mode(&mode)?;
            daemon_exec(checksum, args, debug, &manifest)
        }
        PackedCmd::Stop => {
            let checksum = mode_checksum(&mode);
            daemon_stop(checksum, debug)
        }
        PackedCmd::Status => {
            let checksum = mode_checksum(&mode);
            daemon_status(checksum)
        }
        PackedCmd::Info => {
            let checksum = mode_checksum(&mode);
            let manifest = read_manifest_for_mode(&mode)?;
            print_manifest_info(&manifest, checksum);
            Ok(())
        }
    }
}

/// Run an ephemeral VM from the packed binary (cleaned up after exit).
fn run_ephemeral(
    mode: PackedMode,
    args: PackedRunArgs,
    debug: bool,
    force_extract: bool,
) -> smolvm::Result<()> {
    match mode {
        PackedMode::Sidecar {
            sidecar_path,
            footer: _,
        } => {
            // Construct PackRunCmd from PackedRunArgs and delegate to existing path
            let cmd = PackRunCmd {
                sidecar: Some(sidecar_path),
                command: args.command,
                interactive: args.interactive,
                tty: args.tty,
                timeout: args.timeout,
                workdir: args.workdir,
                env: args.env,
                volume: args.volume,
                port: args.port,
                net: args.net,
                cpus: args.cpus,
                mem: args.mem,
                storage: args.storage,
                overlay: args.overlay,
                force_extract,
                info: false,
                debug,
            };
            cmd.run()
        }

        #[cfg(target_os = "macos")]
        PackedMode::Section {
            manifest,
            checksum,
            assets_ptr,
            assets_size,
        } => run_section_mode(
            *manifest,
            checksum,
            assets_ptr,
            assets_size,
            args,
            debug,
            force_extract,
        ),

        PackedMode::Embedded { exe_path, footer } => {
            run_embedded_mode(exe_path, footer, args, debug, force_extract)
        }
    }
}

/// Run from Mach-O section-embedded assets.
#[cfg(target_os = "macos")]
fn run_section_mode(
    manifest: smolvm_pack::PackManifest,
    checksum: u32,
    assets_ptr: *const u8,
    assets_size: usize,
    args: PackedRunArgs,
    debug: bool,
    force_extract: bool,
) -> smolvm::Result<()> {
    let cache_dir = extract::get_cache_dir(checksum)
        .map_err(|e| Error::agent("get cache dir", e.to_string()))?;

    let needs_extract = force_extract || !extract::is_extracted(&cache_dir);
    if needs_extract {
        unsafe {
            extract::extract_from_section(&cache_dir, assets_ptr, assets_size, debug)
                .map_err(|e| Error::agent("extract section assets", e.to_string()))?;
        }
    }

    run_from_cache(&cache_dir, &manifest, args, debug)
}

/// Run from binary-appended assets.
fn run_embedded_mode(
    exe_path: PathBuf,
    footer: smolvm_pack::PackFooter,
    args: PackedRunArgs,
    debug: bool,
    force_extract: bool,
) -> smolvm::Result<()> {
    // Read manifest from the binary
    let manifest = smolvm_pack::read_manifest(&exe_path)
        .map_err(|e| Error::agent("read manifest", e.to_string()))?;

    let cache_dir = extract::get_cache_dir(footer.checksum)
        .map_err(|e| Error::agent("get cache dir", e.to_string()))?;

    let needs_extract = force_extract || !extract::is_extracted(&cache_dir);
    if needs_extract {
        extract::extract_from_binary(&exe_path, &cache_dir, &footer, debug)
            .map_err(|e| Error::agent("extract embedded assets", e.to_string()))?;
    }

    run_from_cache(&cache_dir, &manifest, args, debug)
}

/// Shared launch path for section and embedded modes.
///
/// Assets are already extracted to `cache_dir`. Boot VM and run the command.
fn run_from_cache(
    cache_dir: &Path,
    manifest: &smolvm_pack::PackManifest,
    args: PackedRunArgs,
    debug: bool,
) -> smolvm::Result<()> {
    let rootfs_path = cache_dir.join("agent-rootfs");
    let lib_dir = resolve_lib_dir(cache_dir, debug)?;
    let layers_dir = cache_dir.join("layers");
    let runtime_parent = cache_dir.join("runtime");
    std::fs::create_dir_all(&runtime_parent)
        .map_err(|e| Error::agent("create runtime parent", e.to_string()))?;
    let runtime_dir = tempfile::tempdir_in(&runtime_parent)
        .map_err(|e| Error::agent("create runtime dir", e.to_string()))?;

    let storage_path = runtime_dir.path().join("storage.ext4");
    let vsock_path = runtime_dir.path().join("agent.sock");

    let template = manifest
        .assets
        .storage_template
        .as_ref()
        .map(|t| t.path.as_str());
    extract::create_or_copy_storage_disk(cache_dir, template, &storage_path, args.storage)
        .map_err(|e| Error::agent("create storage disk", e.to_string()))?;

    let overlay_runtime_path = setup_vm_overlay(
        manifest,
        cache_dir,
        &runtime_dir.path().join("overlay.raw"),
        args.overlay,
    )?;

    let mounts = HostMount::parse(&args.volume)?;
    let port_mappings = PortMapping::to_tuples(&args.port);

    let resources = VmResources {
        cpus: args.cpus.unwrap_or(manifest.cpus),
        memory_mib: args.mem.unwrap_or(manifest.mem),
        network: args.net || !args.port.is_empty(),
        storage_gib: args.storage,
        overlay_gib: args.overlay,
        allowed_cidrs: None,
    };

    let packed_mounts = mounts_to_packed(&mounts);

    smolvm::process::install_sigchld_handler();

    let console_log_path = runtime_dir.path().join("console.log");
    let vsock_path_clone = vsock_path.clone();
    let child_pid = smolvm::process::fork_session_leader(move || {
        let krun = match unsafe { KrunFunctions::load(&lib_dir) } {
            Ok(k) => k,
            Err(e) => {
                eprintln!("failed to load libkrun: {}", e);
                smolvm::process::exit_child(1);
            }
        };

        let config = PackedLaunchConfig {
            rootfs_path: &rootfs_path,
            storage_path: &storage_path,
            vsock_socket: &vsock_path_clone,
            layers_dir: &layers_dir,
            mounts: &packed_mounts,
            port_mappings: &port_mappings,
            resources,
            overlay_path: overlay_runtime_path.as_deref(),
            debug,
            console_log: console_log_path,
        };

        // Detach from parent's terminal so libkrun doesn't
        // steal keystrokes or corrupt terminal state.
        smolvm::process::detach_stdio();

        if let Err(e) = launch_agent_vm_dynamic(&krun, &config) {
            let _ = e;
        }
        smolvm::process::exit_child(1);
    })
    .map_err(|e| Error::agent("fork VM process", e.to_string()))?;

    let child_start_time = {
        let mut st = smolvm::process::process_start_time(child_pid);
        if st.is_none() && smolvm::process::is_alive(child_pid) {
            for _ in 0..5 {
                std::thread::sleep(Duration::from_millis(1));
                st = smolvm::process::process_start_time(child_pid);
                if st.is_some() {
                    break;
                }
            }
        }
        if st.is_none() && smolvm::process::is_alive(child_pid) {
            let _ = smolvm::process::stop_process_fast(child_pid, Duration::from_secs(5), true);
            if let Err(e) = std::fs::remove_dir_all(runtime_dir.path()) {
                tracing::debug!(error = %e, "cleanup: remove runtime dir after failed daemon child start");
            }
            return Err(Error::agent(
                "verify child process",
                "unable to capture child start time for safe lifecycle management",
            ));
        }
        st
    };

    let child_guard = ChildGuard {
        pid: child_pid,
        start_time: child_start_time,
        runtime_dir,
    };

    let mut client = wait_for_agent(&vsock_path, debug)?;

    let params = ExecParams {
        command: build_command(manifest, &args.command),
        env: build_env(manifest, &args.env),
        workdir: args.workdir.or_else(|| manifest.workdir.clone()),
        interactive: args.interactive,
        tty: args.tty,
        timeout: args.timeout,
    };
    let exit_code = execute_packed_command(&mut client, manifest, params, &mounts)?;

    drop(child_guard);
    std::process::exit(exit_code);
}

fn print_manifest_info(manifest: &smolvm_pack::PackManifest, checksum: u32) {
    let mode_str = match manifest.mode {
        PackMode::Container => "container",
        PackMode::Vm => "vm",
    };
    println!("Mode:       {}", mode_str);
    println!("Image:      {}", manifest.image);
    println!("Digest:     {}", manifest.digest);
    println!("Platform:   {}", manifest.platform);
    println!("CPUs:       {}", manifest.cpus);
    println!("Memory:     {} MiB", manifest.mem);
    if !manifest.entrypoint.is_empty() {
        println!("Entrypoint: {}", manifest.entrypoint.join(" "));
    }
    if !manifest.cmd.is_empty() {
        println!("Cmd:        {}", manifest.cmd.join(" "));
    }
    if let Some(ref wd) = manifest.workdir {
        println!("Workdir:    {}", wd);
    }
    if !manifest.env.is_empty() {
        println!("Env:");
        for e in &manifest.env {
            println!("  {}", e);
        }
    }
    println!("Checksum:   {:08x}", checksum);
}

// ===========================================================================
// Daemon mode helpers and implementation
// ===========================================================================

/// Extract the checksum from any PackedMode variant.
fn mode_checksum(mode: &PackedMode) -> u32 {
    match mode {
        #[cfg(target_os = "macos")]
        PackedMode::Section { checksum, .. } => *checksum,
        PackedMode::Embedded { footer, .. } => footer.checksum,
        PackedMode::Sidecar { footer, .. } => footer.checksum,
    }
}

/// Get the daemon state directory for a given checksum.
///
/// Returns `~/.cache/smolvm-pack/{checksum:08x}/daemon/`.
fn daemon_dir(checksum: u32) -> smolvm::Result<PathBuf> {
    let cache_dir = extract::get_cache_dir(checksum)
        .map_err(|e| Error::agent("get cache dir", e.to_string()))?;
    Ok(cache_dir.join("daemon"))
}

/// Read PID and start time from the daemon PID file.
///
/// The PID file format is: `{pid}\n{start_time}`.
/// Returns `None` if the file doesn't exist or is malformed.
fn read_daemon_pid(checksum: u32) -> Option<(libc::pid_t, Option<u64>)> {
    let dir = daemon_dir(checksum).ok()?;
    let pid_path = dir.join("agent.pid");
    let contents = std::fs::read_to_string(&pid_path).ok()?;
    let mut lines = contents.lines();
    let pid: libc::pid_t = lines.next()?.parse().ok()?;
    let start_time: Option<u64> = lines.next().and_then(|s| s.parse().ok());
    Some((pid, start_time))
}

/// Write PID and start time to the daemon PID file.
fn write_daemon_pid(
    checksum: u32,
    pid: libc::pid_t,
    start_time: Option<u64>,
) -> smolvm::Result<()> {
    let dir = daemon_dir(checksum)?;
    let pid_path = dir.join("agent.pid");
    let contents = match start_time {
        Some(st) => format!("{}\n{}", pid, st),
        None => format!("{}", pid),
    };
    std::fs::write(&pid_path, contents).map_err(|e| Error::agent("write PID file", e.to_string()))
}

/// Read the manifest for any PackedMode variant.
fn read_manifest_for_mode(mode: &PackedMode) -> smolvm::Result<smolvm_pack::PackManifest> {
    match mode {
        #[cfg(target_os = "macos")]
        PackedMode::Section { manifest, .. } => Ok((**manifest).clone()),
        PackedMode::Embedded { exe_path, .. } => smolvm_pack::read_manifest(exe_path)
            .map_err(|e| Error::agent("read manifest", e.to_string())),
        PackedMode::Sidecar { sidecar_path, .. } => {
            smolvm_pack::read_manifest_from_sidecar(sidecar_path)
                .map_err(|e| Error::agent("read manifest", e.to_string()))
        }
    }
}

/// Ensure assets are extracted to the cache directory for the given mode.
fn ensure_extracted(mode: &PackedMode, force: bool, debug: bool) -> smolvm::Result<PathBuf> {
    let checksum = mode_checksum(mode);
    let cache_dir = extract::get_cache_dir(checksum)
        .map_err(|e| Error::agent("get cache dir", e.to_string()))?;

    let needs_extract = force || !extract::is_extracted(&cache_dir);
    if needs_extract {
        match mode {
            #[cfg(target_os = "macos")]
            PackedMode::Section {
                assets_ptr,
                assets_size,
                ..
            } => unsafe {
                extract::extract_from_section(&cache_dir, *assets_ptr, *assets_size, debug)
                    .map_err(|e| Error::agent("extract section assets", e.to_string()))?;
            },
            PackedMode::Embedded {
                exe_path, footer, ..
            } => {
                extract::extract_from_binary(exe_path, &cache_dir, footer, debug)
                    .map_err(|e| Error::agent("extract embedded assets", e.to_string()))?;
            }
            PackedMode::Sidecar {
                sidecar_path,
                footer,
                ..
            } => {
                extract::extract_sidecar(sidecar_path, &cache_dir, footer, force, debug)
                    .map_err(|e| Error::agent("extract sidecar assets", e.to_string()))?;
            }
        }
    }

    Ok(cache_dir)
}

/// Check if the daemon is currently running and connectable.
fn is_daemon_running(checksum: u32) -> bool {
    let Some((pid, start_time)) = read_daemon_pid(checksum) else {
        return false;
    };

    // Check PID identity (guards against PID reuse)
    if !smolvm::process::is_our_process_strict(pid, start_time) {
        return false;
    }

    // Try to actually connect and ping
    let dir = match daemon_dir(checksum) {
        Ok(d) => d,
        Err(_) => return false,
    };
    let sock_path = dir.join("agent.sock");
    if !sock_path.exists() {
        return false;
    }

    AgentClient::connect(&sock_path)
        .and_then(|mut c| c.ping())
        .is_ok()
}

/// Start the daemon VM.
///
/// Extracts assets if needed, creates the daemon directory, forks a child
/// process that runs the VM, writes a PID file, and waits for the agent
/// to become ready.
fn daemon_start(
    mode: &PackedMode,
    args: PackedStartArgs,
    debug: bool,
    force_extract: bool,
) -> smolvm::Result<()> {
    let checksum = mode_checksum(mode);
    let manifest = read_manifest_for_mode(mode)?;

    // Extract assets to cache
    let cache_dir = ensure_extracted(mode, force_extract, debug)?;

    // Create daemon directory
    let daemon = cache_dir.join("daemon");
    std::fs::create_dir_all(&daemon)
        .map_err(|e| Error::agent("create daemon dir", e.to_string()))?;

    // Check if already running
    if is_daemon_running(checksum) {
        let (pid, _) = read_daemon_pid(checksum).unwrap();
        println!("Daemon already running (PID: {})", pid);
        return Ok(());
    }

    // Clean up stale PID/socket files from previous runs
    if let Err(e) = std::fs::remove_file(daemon.join("agent.pid")) {
        tracing::debug!(error = %e, "cleanup: remove stale daemon PID file");
    }
    if let Err(e) = std::fs::remove_file(daemon.join("agent.sock")) {
        tracing::debug!(error = %e, "cleanup: remove stale daemon socket");
    }

    // Create storage disk if not exists (preserves existing disk on restart)
    let storage_path = daemon.join("storage.ext4");
    if !storage_path.exists() {
        let template = manifest
            .assets
            .storage_template
            .as_ref()
            .map(|t| t.path.as_str());
        extract::create_or_copy_storage_disk(&cache_dir, template, &storage_path, args.storage)
            .map_err(|e| Error::agent("create storage disk", e.to_string()))?;
    }

    // Create overlay disk (preserves existing disk on restart)
    let overlay_daemon_path = {
        let overlay_path = daemon.join("overlay.raw");
        if !overlay_path.exists() {
            setup_vm_overlay(&manifest, &cache_dir, &overlay_path, args.overlay)?;
        }
        Some(overlay_path)
    };

    let vsock_path = daemon.join("agent.sock");

    // Parse CLI args
    let mounts = HostMount::parse(&args.volume)?;
    let port_mappings = PortMapping::to_tuples(&args.port);

    let resources = VmResources {
        cpus: args.cpus.unwrap_or(manifest.cpus),
        memory_mib: args.mem.unwrap_or(manifest.mem),
        network: args.net || !args.port.is_empty(),
        storage_gib: args.storage,
        overlay_gib: args.overlay,
        allowed_cidrs: None,
    };

    let packed_mounts = mounts_to_packed(&mounts);

    let rootfs_path = cache_dir.join("agent-rootfs");
    let lib_dir = resolve_lib_dir(&cache_dir, debug)?;
    let layers_dir = cache_dir.join("layers");

    if debug {
        eprintln!("debug: daemon dir={}", daemon.display());
        eprintln!("debug: rootfs={}", rootfs_path.display());
        eprintln!("debug: lib_dir={}", lib_dir.display());
        eprintln!("debug: storage={}", storage_path.display());
        eprintln!("debug: vsock={}", vsock_path.display());
        eprintln!(
            "debug: resources cpus={} mem={} net={}",
            resources.cpus, resources.memory_mib, resources.network
        );
    }

    // Fork child → launch VM
    smolvm::process::install_sigchld_handler();

    let console_log_path = daemon.join("console.log");
    let vsock_path_clone = vsock_path.clone();
    let child_pid = smolvm::process::fork_session_leader(move || {
        let krun = match unsafe { KrunFunctions::load(&lib_dir) } {
            Ok(k) => k,
            Err(e) => {
                eprintln!("failed to load libkrun: {}", e);
                smolvm::process::exit_child(1);
            }
        };

        let config = PackedLaunchConfig {
            rootfs_path: &rootfs_path,
            storage_path: &storage_path,
            vsock_socket: &vsock_path_clone,
            layers_dir: &layers_dir,
            mounts: &packed_mounts,
            port_mappings: &port_mappings,
            resources,
            overlay_path: overlay_daemon_path.as_deref(),
            debug,
            console_log: console_log_path,
        };

        // Detach from parent's terminal before launching the VM.
        // Without this, libkrun's threads inherit stdin and steal
        // keystrokes from the user's shell.
        smolvm::process::detach_stdio();

        if let Err(e) = launch_agent_vm_dynamic(&krun, &config) {
            // stderr is /dev/null here, but the error is also logged
            // to console.log via set_console_output
            let _ = e;
        }

        smolvm::process::exit_child(1);
    })
    .map_err(|e| Error::agent("fork VM process", e.to_string()))?;

    // Capture child start time for PID identity verification
    let child_start_time = {
        let mut st = smolvm::process::process_start_time(child_pid);
        if st.is_none() && smolvm::process::is_alive(child_pid) {
            for _ in 0..5 {
                std::thread::sleep(Duration::from_millis(1));
                st = smolvm::process::process_start_time(child_pid);
                if st.is_some() {
                    break;
                }
            }
        }
        if st.is_none() && smolvm::process::is_alive(child_pid) {
            let _ = smolvm::process::stop_process_fast(child_pid, Duration::from_secs(5), true);
            return Err(Error::agent(
                "verify child process",
                "unable to capture child start time for safe lifecycle management",
            ));
        }
        st
    };

    // Write PID file
    write_daemon_pid(checksum, child_pid, child_start_time)?;

    if debug {
        eprintln!("debug: forked VM process with PID {}", child_pid);
    }

    // Wait for agent to become ready
    println!("Starting daemon...");
    let _client = wait_for_agent(&vsock_path, debug)?;

    println!("Daemon started (PID: {})", child_pid);
    Ok(())
}

/// Execute a command in the running daemon VM.
fn daemon_exec(
    checksum: u32,
    args: PackedExecArgs,
    debug: bool,
    manifest: &smolvm_pack::PackManifest,
) -> smolvm::Result<()> {
    let dir = daemon_dir(checksum)?;
    let sock_path = dir.join("agent.sock");

    // Check daemon is running
    if !is_daemon_running(checksum) {
        return Err(Error::agent(
            "daemon exec",
            "daemon is not running. Start it with: <binary> start",
        ));
    }

    if debug {
        eprintln!("debug: connecting to daemon at {}", sock_path.display());
    }

    // Connect to agent
    let mut client = AgentClient::connect(&sock_path)?;

    // Build command from args or manifest defaults
    // Virtiofs devices are fixed at boot — exec cannot add new host mounts.
    let mounts: Vec<smolvm::data::storage::HostMount> = Vec::new();
    let params = ExecParams {
        command: build_command(manifest, &args.command),
        env: build_env(manifest, &args.env),
        workdir: args.workdir.or_else(|| manifest.workdir.clone()),
        interactive: args.interactive,
        tty: args.tty,
        timeout: args.timeout,
    };

    let exit_code = execute_packed_command(&mut client, manifest, params, &mounts)?;

    std::process::exit(exit_code);
}

/// Stop the daemon VM.
fn daemon_stop(checksum: u32, debug: bool) -> smolvm::Result<()> {
    let Some((pid, start_time)) = read_daemon_pid(checksum) else {
        println!("Daemon not running");
        return Ok(());
    };

    let dir = daemon_dir(checksum)?;
    let sock_path = dir.join("agent.sock");

    // Try graceful shutdown via agent protocol.
    // If the agent responds, this also confirms the PID belongs to our VM.
    let mut vsock_confirmed = false;
    if sock_path.exists() {
        if let Ok(mut client) = AgentClient::connect(&sock_path) {
            vsock_confirmed = true;
            if debug {
                eprintln!("debug: sending shutdown to agent");
            }
            let _ = client.shutdown();
        }
    }

    // Identity check: vsock acknowledgement OR strict PID start-time match.
    // We intentionally do NOT use the lenient is_our_process() here because
    // it treats any alive PID as "ours" when start_time is None — which risks
    // killing an unrelated process if the OS reused the PID.
    let identity_ok = vsock_confirmed || smolvm::process::is_our_process_strict(pid, start_time);
    if identity_ok {
        if debug {
            eprintln!(
                "debug: stopping process {} (start_time: {:?})",
                pid, start_time
            );
        }
        let _ = smolvm::process::stop_vm_process(
            pid,
            Duration::from_secs(5),
            smolvm::process::VM_SIGKILL_TIMEOUT,
        );
    }

    // Clean up PID and socket files (keep storage.ext4 for persistence)
    if let Err(e) = std::fs::remove_file(dir.join("agent.pid")) {
        tracing::debug!(error = %e, "cleanup: remove daemon PID file");
    }
    if let Err(e) = std::fs::remove_file(dir.join("agent.sock")) {
        tracing::debug!(error = %e, "cleanup: remove daemon socket");
    }

    println!("Daemon stopped");
    Ok(())
}

/// Check daemon status.
fn daemon_status(checksum: u32) -> smolvm::Result<()> {
    let Some((pid, start_time)) = read_daemon_pid(checksum) else {
        println!("Status: not running");
        return Ok(());
    };

    // Check if PID is still our process
    if !smolvm::process::is_our_process_strict(pid, start_time) {
        println!("Status: not running (stale PID file)");
        // Clean up stale files
        if let Ok(dir) = daemon_dir(checksum) {
            if let Err(e) = std::fs::remove_file(dir.join("agent.pid")) {
                tracing::debug!(error = %e, "cleanup: remove stale status PID file");
            }
            if let Err(e) = std::fs::remove_file(dir.join("agent.sock")) {
                tracing::debug!(error = %e, "cleanup: remove stale status socket");
            }
        }
        return Ok(());
    }

    // Try to connect and ping
    let dir = daemon_dir(checksum)?;
    let sock_path = dir.join("agent.sock");

    if sock_path.exists() {
        if let Ok(mut client) = AgentClient::connect(&sock_path) {
            if client.ping().is_ok() {
                println!("Status: running (PID: {})", pid);
                return Ok(());
            }
        }
    }

    println!("Status: running (PID: {}, agent not responding)", pid);
    Ok(())
}
