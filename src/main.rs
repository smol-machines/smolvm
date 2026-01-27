//! smolvm CLI entry point.

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

mod cli;

/// smolvm - OCI-native microVM runtime
#[derive(Parser, Debug)]
#[command(name = "smolvm")]
#[command(about = "Run containers in lightweight VMs with VM-level isolation")]
#[command(
    long_about = "smolvm is an OCI-native microVM runtime for macOS and Linux.\n\n\
It runs container images inside lightweight VMs using libkrun, providing \
VM-level isolation with container-like UX.\n\n\
Quick start:\n  \
smolvm sandbox run alpine -- echo hello\n  \
smolvm sandbox run -d nginx -p 8080:80\n\n\
For programmatic access:\n  \
smolvm serve"
)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run containers quickly (ephemeral or detached)
    #[command(subcommand, visible_alias = "sb")]
    Sandbox(cli::sandbox::SandboxCmd),

    /// Manage persistent microVMs
    #[command(subcommand, visible_alias = "vm")]
    Microvm(cli::microvm::MicrovmCmd),

    /// Manage containers inside a microVM
    #[command(subcommand, visible_alias = "ct")]
    Container(cli::container::ContainerCmd),

    /// Start the HTTP API server for programmatic control
    Serve(cli::serve::ServeCmd),

    /// Package an OCI image into a self-contained executable
    Pack(cli::pack::PackCmd),
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
        Commands::Serve(cmd) => cmd.run(),
        Commands::Pack(cmd) => cmd.run(),
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
