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

    /// Manage host-side secrets injected into workload env
    #[command(subcommand)]
    Secret(cli::secret::SecretCmd),

    /// Internal: boot a VM subprocess (not for direct use)
    #[command(name = "_boot-vm", hide = true)]
    BootVm {
        /// Path to boot config JSON file
        config: std::path::PathBuf,
    },
}

fn main() {
    // Auto-detect packed binary mode BEFORE parsing the normal CLI.
    // If this executable has a `.smolmachine` sidecar, appended assets,
    // or a Mach-O section with packed data, run as a packed binary instead.
    if let Some(mode) = smolvm_pack::detect_packed_mode() {
        cli::pack_run::run_as_packed_binary(mode);
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
        Commands::Secret(cmd) => cmd.run(),
        Commands::BootVm { config } => cli::internal_boot::run(config),
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
            .with_env_filter(filter)
            .with_current_span(true)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .init();
    }
}
