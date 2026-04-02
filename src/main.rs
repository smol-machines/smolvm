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

    /// Manage containers inside a machine
    #[command(subcommand, visible_alias = "ct")]
    Container(cli::container::ContainerCmd),

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
    let result = match cli.command {
        Commands::Machine(cmd) => cmd.run(),
        Commands::Container(cmd) => cmd.run(),
        Commands::Serve(cmd) => cmd.run(),
        Commands::Pack(cmd) => cmd.run(),
        Commands::Config(cmd) => cmd.run(),
        Commands::BootVm { config } => cli::internal_boot::run(config),
    };

    // Handle errors
    if let Err(e) = result {
        tracing::error!(error = %e, "command failed");
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

/// Initialize the tracing subscriber.
fn init_logging() {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("smolvm=warn"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}
