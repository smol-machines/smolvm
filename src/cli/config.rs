//! Configuration CLI commands.
//!
//! Commands for managing smolvm configuration, including registry settings.

use clap::{Args, Subcommand};
use smolvm::data::network::DEFAULT_DNS;
use smolvm::data::resources::{DEFAULT_MICROVM_CPU_COUNT, DEFAULT_MICROVM_MEMORY_MIB};
use smolvm::db::SmolvmDb;
use smolvm::registry::RegistryConfig;
use smolvm::Result;

/// Configuration commands
#[derive(Subcommand, Debug)]
pub enum ConfigCmd {
    /// Show current configuration
    Show(ShowCmd),

    /// Manage registry configuration
    #[command(subcommand)]
    Registries(RegistriesCmd),
}

impl ConfigCmd {
    pub fn run(self) -> Result<()> {
        match self {
            ConfigCmd::Show(cmd) => cmd.run(),
            ConfigCmd::Registries(cmd) => cmd.run(),
        }
    }
}

// ============================================================================
// Show Command
// ============================================================================

/// Show current configuration
#[derive(Args, Debug)]
pub struct ShowCmd {}

impl ShowCmd {
    pub fn run(self) -> Result<()> {
        // Load and display global config
        let db = SmolvmDb::open()?;
        let default_cpus = db
            .get_config("default_cpus")?
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_MICROVM_CPU_COUNT);
        let default_mem = db
            .get_config("default_mem")?
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_MICROVM_MEMORY_MIB);
        let default_dns = db
            .get_config("default_dns")?
            .unwrap_or_else(|| DEFAULT_DNS.to_string());

        println!("Global Configuration:");
        println!("  Default CPUs: {}", default_cpus);
        println!("  Default Memory: {} MiB", default_mem);
        println!("  Default DNS: {}", default_dns);

        // Load and display registry config
        let registry_config = RegistryConfig::load().unwrap_or_default();
        println!();
        println!("Registry Configuration:");
        if let Ok(path) = RegistryConfig::config_path() {
            println!("  Config file: {}", path.display());
            if path.exists() {
                println!("  Status: configured");
            } else {
                println!("  Status: not configured (using defaults)");
            }
        }
        println!("  Default registry: {}", registry_config.default_registry());
        println!(
            "  Configured registries: {}",
            registry_config.registries.len()
        );

        if !registry_config.registries.is_empty() {
            println!();
            println!("  Registries:");
            for (name, entry) in &registry_config.registries {
                let auth_status = if entry.username.is_some() {
                    if entry.password_env.is_some() {
                        "auth (env var)"
                    } else if entry.password.is_some() {
                        "auth (direct)"
                    } else {
                        "no password"
                    }
                } else {
                    "no auth"
                };
                let mirror_status = entry
                    .mirror
                    .as_ref()
                    .map(|m| format!(" -> {}", m))
                    .unwrap_or_default();
                println!("    {}: {}{}", name, auth_status, mirror_status);
            }
        }

        Ok(())
    }
}

// ============================================================================
// Registries Commands
// ============================================================================

/// Registry configuration commands
#[derive(Subcommand, Debug)]
pub enum RegistriesCmd {
    /// Show the path to the registries configuration file
    Path,

    /// Edit the registries configuration file in your default editor
    Edit,

    /// Show current registries configuration
    Show,

    /// Create an example configuration file
    Init,
}

impl RegistriesCmd {
    pub fn run(self) -> Result<()> {
        match self {
            RegistriesCmd::Path => {
                let path = RegistryConfig::config_path()?;
                println!("{}", path.display());
                Ok(())
            }
            RegistriesCmd::Edit => {
                let path = RegistryConfig::config_path()?;

                // Create parent directory if needed
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }

                // Create file with example content if it doesn't exist
                if !path.exists() {
                    std::fs::write(&path, EXAMPLE_CONFIG)?;
                    println!("Created example configuration at {}", path.display());
                }

                // Open in editor
                let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_string());
                let status = std::process::Command::new(&editor).arg(&path).status()?;

                if !status.success() {
                    return Err(smolvm::Error::config(
                        "edit config",
                        format!("editor '{}' exited with non-zero status", editor),
                    ));
                }

                // Validate the config after editing
                match RegistryConfig::load() {
                    Ok(config) => {
                        println!(
                            "Configuration valid: {} registries configured",
                            config.registries.len()
                        );
                    }
                    Err(e) => {
                        eprintln!("Warning: Configuration file has errors: {}", e);
                    }
                }

                Ok(())
            }
            RegistriesCmd::Show => {
                let config = RegistryConfig::load().unwrap_or_default();

                if config.registries.is_empty() {
                    println!("No registries configured.");
                    if let Ok(path) = RegistryConfig::config_path() {
                        println!();
                        println!("To configure registries, create: {}", path.display());
                        println!("Or run: smolvm config registries init");
                    }
                    return Ok(());
                }

                println!("Configured registries:");
                println!();

                for (name, entry) in &config.registries {
                    println!("  [{}]", name);

                    if let Some(ref username) = entry.username {
                        println!("    username: {}", username);
                    }

                    if let Some(ref password_env) = entry.password_env {
                        // Check if env var is set
                        let status = if std::env::var(password_env).is_ok() {
                            " (set)"
                        } else {
                            " (NOT SET)"
                        };
                        println!("    password_env: {}{}", password_env, status);
                    } else if entry.password.is_some() {
                        println!("    password: <configured>");
                    }

                    if let Some(ref mirror) = entry.mirror {
                        println!("    mirror: {}", mirror);
                    }

                    println!();
                }

                Ok(())
            }
            RegistriesCmd::Init => {
                let path = RegistryConfig::config_path()?;

                if path.exists() {
                    eprintln!("Configuration file already exists at {}", path.display());
                    eprintln!("Use 'smolvm config registries edit' to modify it.");
                    return Ok(());
                }

                // Create parent directory if needed
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }

                std::fs::write(&path, EXAMPLE_CONFIG)?;
                println!("Created example configuration at {}", path.display());
                println!();
                println!("Edit the file to add your registry credentials.");
                println!("Run 'smolvm config registries edit' to open in your editor.");

                Ok(())
            }
        }
    }
}

/// Example configuration file content
const EXAMPLE_CONFIG: &str = r#"# smolvm Registry Configuration
#
# This file configures authentication for OCI registries.
# Location: ~/.config/smolvm/registries.toml
#
# For security, use password_env to reference environment variables
# instead of storing passwords directly in this file.

[defaults]
# Default registry when none specified (default: docker.io)
# registry = "docker.io"

# Docker Hub authentication
# [registries."docker.io"]
# username = "your-username"
# password_env = "DOCKER_HUB_TOKEN"  # Set: export DOCKER_HUB_TOKEN="your-token"

# GitHub Container Registry
# [registries."ghcr.io"]
# username = "your-github-username"
# password_env = "GHCR_TOKEN"  # Set: export GHCR_TOKEN="your-pat"

# Google Container Registry
# [registries."gcr.io"]
# username = "_json_key"
# password_env = "GCR_KEY"  # Set: export GCR_KEY="$(cat key.json)"

# Private registry with mirror
# [registries."registry.example.com"]
# username = "user"
# password_env = "REGISTRY_PASSWORD"
# mirror = "mirror.example.com"  # Optional: pull from mirror instead
"#;
