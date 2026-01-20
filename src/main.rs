//! smolvm CLI entry point.

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

mod cli;

/// smolvm - OCI-native microVM runtime
#[derive(Parser, Debug)]
#[command(name = "smolvm")]
#[command(about = "OCI-native microVM runtime")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run a container in an ephemeral sandbox (quick start)
    #[command(subcommand)]
    Sandbox(cli::sandbox::SandboxCmd),

    /// Manage microvms (exec, create, start, stop, delete, status, ls)
    #[command(subcommand)]
    Microvm(cli::microvm::MicrovmCmd),

    /// Manage containers inside the microvm
    #[command(subcommand)]
    Container(cli::container::ContainerCmd),
}

fn main() {
    let cli = Cli::parse();

    // Initialize logging based on RUST_LOG or default to warn
    init_logging();

    tracing::debug!(version = smolvm::VERSION, "starting smolvm");

    // Execute command
    let result = match cli.command {
        Commands::Sandbox(cmd) => cmd.run(),
        Commands::Microvm(cmd) => cmd.run(),
        Commands::Container(cmd) => cmd.run(),
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
