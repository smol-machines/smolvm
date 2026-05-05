//! Configuration CLI commands.
//!
//! Commands for managing smolvm configuration, including registry settings.

use clap::{Args, Subcommand};
use smolvm::settings::SmolSettings;
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
        let config = smolvm::SmolvmConfig::load()?;
        println!("Global Configuration:");
        println!("  Default CPUs: {}", config.default_cpus);
        println!("  Default Memory: {} MiB", config.default_mem);
        println!("  Default DNS: {}", config.default_dns);

        // Load and display unified settings
        let settings = SmolSettings::load().unwrap_or_default();
        println!();
        println!("Settings:");
        if let Ok(path) = SmolSettings::config_path() {
            println!("  Config file: {}", path.display());
            if path.exists() {
                println!("  Status: configured");
            } else {
                println!("  Status: not configured (using defaults)");
            }
        }

        println!();
        println!("  [machines] (smolmachine artifact registries):");
        println!("    Default: {}", settings.machines.default_registry());
        println!("    Configured: {}", settings.machines.registries.len());
        for (name, entry) in &settings.machines.registries {
            let auth_status = format_auth_status(entry);
            println!("      {}: {}", name, auth_status);
        }

        println!();
        println!("  [images] (container image registries):");
        println!("    Default: {}", settings.images.default_registry());
        println!("    Configured: {}", settings.images.registries.len());
        for (name, entry) in &settings.images.registries {
            let auth_status = format_auth_status(entry);
            let mirror_status = entry
                .mirror
                .as_ref()
                .map(|m| format!(" -> {}", m))
                .unwrap_or_default();
            println!("      {}: {}{}", name, auth_status, mirror_status);
        }

        Ok(())
    }
}

fn format_auth_status(entry: &smolvm::registry::RegistryEntry) -> &'static str {
    if entry.username.is_some() {
        if entry.password_env.is_some() {
            "auth (env var)"
        } else if entry.password.is_some() {
            "auth (direct)"
        } else {
            "no password"
        }
    } else {
        "no auth"
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
                let path = SmolSettings::config_path()?;
                println!("{}", path.display());
                Ok(())
            }
            RegistriesCmd::Edit => {
                let path = SmolSettings::config_path()?;

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
                match SmolSettings::load() {
                    Ok(settings) => {
                        println!(
                            "Configuration valid: {} machine registries, {} image registries configured",
                            settings.machines.registries.len(),
                            settings.images.registries.len(),
                        );
                    }
                    Err(e) => {
                        eprintln!("Warning: Configuration file has errors: {}", e);
                    }
                }

                Ok(())
            }
            RegistriesCmd::Show => {
                let settings = SmolSettings::load().unwrap_or_default();
                let has_machines = !settings.machines.registries.is_empty();
                let has_images = !settings.images.registries.is_empty();

                if !has_machines && !has_images {
                    println!("No registries configured.");
                    if let Ok(path) = SmolSettings::config_path() {
                        println!();
                        println!("To configure registries, create: {}", path.display());
                        println!("Or run: smolvm config registries init");
                    }
                    return Ok(());
                }

                if has_machines {
                    println!("[machines] (smolmachine artifact registries):");
                    println!();
                    print_registry_entries(&settings.machines.registries);
                }

                if has_images {
                    if has_machines {
                        println!();
                    }
                    println!("[images] (container image registries):");
                    println!();
                    print_registry_entries(&settings.images.registries);
                }

                Ok(())
            }
            RegistriesCmd::Init => {
                let path = SmolSettings::config_path()?;

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

fn print_registry_entries(
    registries: &std::collections::HashMap<String, smolvm::registry::RegistryEntry>,
) {
    for (name, entry) in registries {
        println!("  [{}]", name);

        if let Some(ref username) = entry.username {
            println!("    username: {}", username);
        }

        if let Some(ref password_env) = entry.password_env {
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
}

/// Example configuration file content
const EXAMPLE_CONFIG: &str = r#"# smolvm Configuration
#
# Location: ~/.config/smolvm/config.toml
#
# [cloud]        — smolcloud API settings
# [machines]     — credentials for .smolmachine artifact registries
# [images]       — credentials for container image registries (base images for VMs)
#
# For security, use password_env to reference environment variables
# instead of storing passwords directly in this file.

# [cloud]
# endpoint = "https://api.smolmachines.com"
# api_key = "smk_..."

# [machines.defaults]
# registry = "registry.smolmachines.com"

# [machines.registries."registry.smolmachines.com"]
# username = "token"
# password = "your-jwt-token"

# [images.defaults]
# registry = "docker.io"

# [images.registries."docker.io"]
# username = "your-username"
# password_env = "DOCKER_HUB_TOKEN"  # Set: export DOCKER_HUB_TOKEN="your-token"

# [images.registries."ghcr.io"]
# username = "your-github-username"
# password_env = "GHCR_TOKEN"  # Set: export GHCR_TOKEN="your-pat"

# [images.registries."registry.example.com"]
# username = "user"
# password_env = "REGISTRY_PASSWORD"
# mirror = "mirror.example.com"  # Optional: pull from mirror instead
"#;
