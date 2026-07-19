//! smolvm CLI entry point.

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

mod cli;

/// smolvm - build and run portable, self-contained virtual machines
#[derive(Parser, Debug)]
#[command(name = "smolvm")]
#[command(
    about = "Build and run portable, self-contained virtual machines",
    after_help = "Agents: run `smolvm --help` for full documentation including CLI reference and Smolfile schema"
)]
#[command(
    long_about = include_str!("../AGENTS.md")
)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Manage machines (create, start, stop, exec)
    #[command(subcommand, visible_alias = "vm")]
    Machine(cli::machine::MachineCmd),

    /// Start the HTTP API server for programmatic control
    #[command(subcommand)]
    Serve(cli::serve::ServeCmd),

    /// Package and run self-contained VM executables
    #[command(subcommand)]
    Pack(cli::pack::PackCmd),

    /// Manage smolvm configuration (registries, defaults)
    #[command(subcommand)]
    Config(cli::config::ConfigCmd),

    /// Internal: boot a VM subprocess (not for direct use)
    #[command(name = "_boot-vm", hide = true)]
    BootVm {
        /// Path to boot config JSON file
        config: std::path::PathBuf,
    },

    /// Internal: run the shared CUDA daemon (not for direct use)
    #[command(name = "_cuda-daemon", hide = true)]
    CudaDaemon {
        /// Control-socket path to bind
        socket: std::path::PathBuf,
    },

    /// Internal: serve one isolating fork-clone connection in its own process
    /// (Path 3 per-clone worker; not for direct use)
    #[command(name = "_cuda-clone-worker", hide = true)]
    CudaCloneWorker {
        /// Accepted connection fd handed over by the daemon
        fd: i32,
    },

    /// Internal: clean up an ephemeral VM after its command exits (not for direct use)
    #[command(name = "_cleanup-ephemeral", hide = true)]
    CleanupEphemeral {
        /// Ephemeral VM name (its data dir + DB record are both keyed by this)
        vm_name: String,
        /// VM process PID
        pid: i32,
        /// Process start time for PID-reuse verification (0 = unknown, skips strict check)
        start_time: u64,
    },
}

fn main() {
    // Honor an explicit SMOLVM_DATA_DIR for EVERY command (so the CLI and serve
    // agree on where smolvm state lives) before anything computes a path. The
    // auto /var/lib/smolvm default is serve-only (applied in its run()). Done
    // first, single-threaded, so the set_var is safe.
    smolvm::process::apply_system_data_root(/* allow_auto */ false);

    // Auto-detect packed binary mode BEFORE parsing the normal CLI.
    // If this executable has a `.smolmachine` sidecar, appended assets,
    // or a Mach-O section with packed data, run as a packed binary instead.
    //
    // EXCEPTION: skip auto-detection when re-invoked as `_boot-vm`. On Windows
    // (and any non-fork path) pack rehydrate boots the VM by re-spawning this
    // same packed executable as `current_exe _boot-vm <config.json>`. That child
    // still carries the packed footer/sidecar, so without this guard it would
    // re-trigger packed-mode detection and rehydrate again instead of booting
    // the VM from the config it was handed.
    // Internal re-invocations (`_boot-vm`, `_cuda-daemon`) run the same packed
    // executable but must do their job, not re-trigger packed rehydration.
    let internal = matches!(
        std::env::args_os()
            .nth(1)
            .as_deref()
            .and_then(|s| s.to_str()),
        Some("_boot-vm") | Some("_cuda-daemon") | Some("_cuda-clone-worker")
    );
    if !internal {
        if let Some(mode) = smolvm_pack::detect_packed_mode() {
            cli::pack_run::run_as_packed_binary(mode);
        }
        // A packed stub separated from its `.smolmachine` sidecar is
        // byte-identical to the plain CLI, so detection can't hard-fail —
        // but silently becoming a different program strands users (QA
        // BUG-167). A non-`smolvm` executable name is the tell: say what
        // happened before falling through to the normal CLI.
        let exe_name = std::env::current_exe()
            .ok()
            .and_then(|p| p.file_stem().map(|s| s.to_string_lossy().into_owned()));
        if let Some(name) = exe_name {
            if name != "smolvm" {
                eprintln!(
                    "note: no packed assets found for '{name}' (looked for a \
                     '{name}.smolmachine' sidecar next to the executable); \
                     running as the plain smolvm CLI. If this is a packed \
                     binary, keep its .smolmachine file alongside it."
                );
            }
        }
    }

    let cli = Cli::parse();

    // Initialize logging based on RUST_LOG or default to warn
    init_logging();

    tracing::debug!(version = smolvm::VERSION, "starting smolvm");

    // Execute command
    // Note: orphan cleanup is handled per-command (skipped for ephemeral `machine run`).
    let result = match cli.command {
        Commands::Machine(cmd) => cmd.run(),
        Commands::Serve(cmd) => cmd.run(),
        Commands::Pack(cmd) => cmd.run(),
        Commands::Config(cmd) => cmd.run(),
        Commands::BootVm { config } => cli::internal_boot::run(config),
        #[cfg(unix)]
        Commands::CudaDaemon { socket } => {
            smolvm::cuda_daemon::run(&socket).map_err(smolvm::Error::Io)
        }
        #[cfg(not(unix))]
        Commands::CudaDaemon { .. } => Err(smolvm::Error::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "the shared CUDA daemon is unix-only",
        ))),
        #[cfg(unix)]
        Commands::CudaCloneWorker { fd } => {
            smolvm::cuda_daemon::run_clone_worker(fd).map_err(smolvm::Error::Io)
        }
        #[cfg(not(unix))]
        Commands::CudaCloneWorker { .. } => Err(smolvm::Error::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "the CUDA clone worker is unix-only",
        ))),
        Commands::CleanupEphemeral {
            vm_name,
            pid,
            start_time,
        } => {
            cli::cleanup_ephemeral::run(&vm_name, pid, start_time);
            Ok(())
        }
    };

    // Handle errors
    if let Err(e) = result {
        tracing::debug!(error = %e, "command failed");
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

/// Initialize the tracing subscriber.
///
/// JSON mode is enabled via `SMOLVM_LOG_FORMAT=json` env var or when
/// running as `smolvm serve --json-logs`. Default is human-readable.
fn init_logging() {
    let json = std::env::var("SMOLVM_LOG_FORMAT")
        .map(|v| v == "json")
        .unwrap_or(false);

    // Skip EnvFilter::try_from_default_env() when RUST_LOG is not set —
    // avoids parsing an env var that doesn't exist.
    let filter = match std::env::var_os("RUST_LOG") {
        Some(_) => {
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("smolvm=warn"))
        }
        None => EnvFilter::new("smolvm=warn"),
    };

    if json {
        tracing_subscriber::fmt()
            .json()
            .with_writer(std::io::stderr)
            .with_env_filter(filter)
            .with_current_span(true)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_env_filter(filter)
            .with_target(false)
            .init();
    }
}
