//! Registry configuration for OCI image authentication.
//!
//! This module provides support for:
//! - Loading registry credentials from a TOML configuration file
//! - Environment variable-based password resolution
//! - Registry mirrors for pull-through caching
//!
//! # Configuration File
//!
//! The configuration file is located at `~/.config/smolvm/registries.toml`:
//!
//! ```toml
//! [defaults]
//! # registry = "docker.io"  # Optional: default registry
//!
//! [registries."docker.io"]
//! username = "myuser"
//! password_env = "DOCKER_HUB_TOKEN"  # Reads from env var
//!
//! [registries."ghcr.io"]
//! username = "github_user"
//! password_env = "GHCR_TOKEN"
//!
//! [registries."registry.example.com"]
//! username = "user"
//! password = "secret"  # Direct password (not recommended)
//! mirror = "mirror.example.com"  # Optional mirror
//! ```

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Registry configuration loaded from `~/.config/smolvm/registries.toml`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegistryConfig {
    /// Per-registry configuration entries.
    #[serde(default)]
    pub registries: HashMap<String, RegistryEntry>,
    /// Default settings.
    #[serde(default)]
    pub defaults: RegistryDefaults,
}

/// Configuration for a single registry.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegistryEntry {
    /// Username for authentication.
    pub username: Option<String>,
    /// Password (plaintext - not recommended, use password_env instead).
    pub password: Option<String>,
    /// Environment variable containing the password.
    pub password_env: Option<String>,
    /// Mirror URL to use instead of this registry.
    pub mirror: Option<String>,
}

/// Default registry settings.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegistryDefaults {
    /// Default registry when none specified (defaults to docker.io).
    pub registry: Option<String>,
}

// Re-export RegistryAuth from protocol to avoid duplication
pub use smolvm_protocol::RegistryAuth;

impl RegistryConfig {
    /// Load registry configuration from the default config file.
    ///
    /// If the config file doesn't exist, returns an empty configuration.
    /// Errors are logged but don't cause failure - we fall back to empty config.
    pub fn load() -> Result<Self> {
        let config_path = match Self::config_path() {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!(error = %e, "could not determine registry config path");
                return Ok(Self::default());
            }
        };

        if !config_path.exists() {
            tracing::debug!(
                path = %config_path.display(),
                "registry config file not found, using defaults"
            );
            return Ok(Self::default());
        }

        let contents = std::fs::read_to_string(&config_path).map_err(|e| {
            Error::ConfigLoad(format!(
                "failed to read registry config at {}: {}",
                config_path.display(),
                e
            ))
        })?;

        let config: Self = toml::from_str(&contents).map_err(|e| {
            Error::ConfigLoad(format!(
                "failed to parse registry config at {}: {}",
                config_path.display(),
                e
            ))
        })?;

        tracing::debug!(
            path = %config_path.display(),
            registry_count = config.registries.len(),
            "loaded registry configuration"
        );

        Ok(config)
    }

    /// Get the path to the registry configuration file.
    pub fn config_path() -> Result<PathBuf> {
        let config_dir =
            dirs::config_dir().ok_or_else(|| Error::Config("no config directory found".into()))?;
        Ok(config_dir.join("smolvm").join("registries.toml"))
    }

    /// Get credentials for a registry, resolving environment variables.
    ///
    /// Returns `Some((username, password))` if credentials are configured and available.
    /// Returns `None` if:
    /// - No entry for this registry
    /// - No username configured
    /// - Password not available (env var not set, no direct password)
    pub fn get_credentials(&self, registry: &str) -> Option<RegistryAuth> {
        let entry = self.registries.get(registry)?;
        let username = entry.username.as_ref()?;

        // Try password_env first, then fall back to direct password
        let password = entry
            .password_env
            .as_ref()
            .and_then(|env| {
                std::env::var(env).ok().or_else(|| {
                    tracing::debug!(
                        registry = %registry,
                        env_var = %env,
                        "password environment variable not set"
                    );
                    None
                })
            })
            .or_else(|| entry.password.clone())?;

        Some(RegistryAuth {
            username: username.clone(),
            password,
        })
    }

    /// Get mirror URL for a registry if configured.
    pub fn get_mirror(&self, registry: &str) -> Option<&str> {
        self.registries.get(registry)?.mirror.as_deref()
    }

    /// Get the default registry (defaults to "docker.io").
    pub fn default_registry(&self) -> &str {
        self.defaults
            .registry
            .as_deref()
            .unwrap_or(DEFAULT_REGISTRY)
    }

    /// Check if any registries are configured.
    pub fn has_registries(&self) -> bool {
        !self.registries.is_empty()
    }
}

/// Default registry when none specified in image reference.
pub const DEFAULT_REGISTRY: &str = "docker.io";

/// Extract the registry hostname from an image reference.
///
/// # Examples
///
/// ```ignore
/// extract_registry("alpine") == "docker.io"
/// extract_registry("library/alpine") == "docker.io"
/// extract_registry("docker.io/library/alpine") == "docker.io"
/// extract_registry("ghcr.io/owner/repo") == "ghcr.io"
/// extract_registry("registry.example.com:5000/image") == "registry.example.com:5000"
/// ```
pub fn extract_registry(image: &str) -> String {
    // Check if the image starts with a registry (contains . or : before first /)
    if let Some(slash_pos) = image.find('/') {
        let potential_registry = &image[..slash_pos];

        // A registry hostname contains a dot (.) or a port (:)
        // This distinguishes "ghcr.io/owner/repo" from "library/alpine"
        if potential_registry.contains('.') || potential_registry.contains(':') {
            return potential_registry.to_string();
        }
    }

    // No explicit registry - use default
    DEFAULT_REGISTRY.to_string()
}

/// Rewrite an image reference to use a different registry.
///
/// # Examples
///
/// ```ignore
/// rewrite_image_registry("alpine", "mirror.example.com") == "mirror.example.com/library/alpine"
/// rewrite_image_registry("docker.io/library/alpine", "mirror.example.com") == "mirror.example.com/library/alpine"
/// rewrite_image_registry("ghcr.io/owner/repo", "mirror.example.com") == "mirror.example.com/owner/repo"
/// ```
pub fn rewrite_image_registry(image: &str, new_registry: &str) -> String {
    let current_registry = extract_registry(image);

    if image.starts_with(&current_registry) {
        // Explicit registry - replace it
        format!("{}{}", new_registry, &image[current_registry.len()..])
    } else {
        // Implicit docker.io - need to add "library/" for single-name images
        if image.contains('/') {
            format!("{}/{}", new_registry, image)
        } else {
            format!("{}/library/{}", new_registry, image)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_registry_implicit_dockerhub() {
        assert_eq!(extract_registry("alpine"), "docker.io");
        assert_eq!(extract_registry("alpine:latest"), "docker.io");
        assert_eq!(extract_registry("library/alpine"), "docker.io");
        assert_eq!(extract_registry("myuser/myimage"), "docker.io");
    }

    #[test]
    fn test_extract_registry_explicit() {
        assert_eq!(extract_registry("docker.io/library/alpine"), "docker.io");
        assert_eq!(extract_registry("ghcr.io/owner/repo"), "ghcr.io");
        assert_eq!(extract_registry("gcr.io/project/image"), "gcr.io");
        assert_eq!(
            extract_registry("registry.example.com/image"),
            "registry.example.com"
        );
        assert_eq!(extract_registry("localhost:5000/image"), "localhost:5000");
    }

    #[test]
    fn test_rewrite_image_registry() {
        // Implicit docker.io
        assert_eq!(
            rewrite_image_registry("alpine", "mirror.example.com"),
            "mirror.example.com/library/alpine"
        );
        assert_eq!(
            rewrite_image_registry("myuser/myimage", "mirror.example.com"),
            "mirror.example.com/myuser/myimage"
        );

        // Explicit registry
        assert_eq!(
            rewrite_image_registry("docker.io/library/alpine", "mirror.example.com"),
            "mirror.example.com/library/alpine"
        );
        assert_eq!(
            rewrite_image_registry("ghcr.io/owner/repo", "mirror.example.com"),
            "mirror.example.com/owner/repo"
        );
    }

    #[test]
    fn test_registry_config_default() {
        let config = RegistryConfig::default();
        assert!(config.registries.is_empty());
        assert_eq!(config.default_registry(), "docker.io");
    }

    #[test]
    fn test_get_credentials_with_direct_password() {
        let mut config = RegistryConfig::default();
        config.registries.insert(
            "docker.io".to_string(),
            RegistryEntry {
                username: Some("testuser".to_string()),
                password: Some("testpass".to_string()),
                password_env: None,
                mirror: None,
            },
        );

        let creds = config.get_credentials("docker.io");
        assert!(creds.is_some());
        let creds = creds.unwrap();
        assert_eq!(creds.username, "testuser");
        assert_eq!(creds.password, "testpass");
    }

    #[test]
    fn test_get_credentials_missing_username() {
        let mut config = RegistryConfig::default();
        config.registries.insert(
            "docker.io".to_string(),
            RegistryEntry {
                username: None,
                password: Some("testpass".to_string()),
                password_env: None,
                mirror: None,
            },
        );

        assert!(config.get_credentials("docker.io").is_none());
    }

    #[test]
    fn test_get_credentials_missing_password() {
        let mut config = RegistryConfig::default();
        config.registries.insert(
            "docker.io".to_string(),
            RegistryEntry {
                username: Some("testuser".to_string()),
                password: None,
                password_env: None,
                mirror: None,
            },
        );

        assert!(config.get_credentials("docker.io").is_none());
    }

    #[test]
    fn test_get_mirror() {
        let mut config = RegistryConfig::default();
        config.registries.insert(
            "docker.io".to_string(),
            RegistryEntry {
                username: None,
                password: None,
                password_env: None,
                mirror: Some("mirror.example.com".to_string()),
            },
        );

        assert_eq!(config.get_mirror("docker.io"), Some("mirror.example.com"));
        assert_eq!(config.get_mirror("ghcr.io"), None);
    }

    #[test]
    fn test_parse_config() {
        let toml_content = r#"
[defaults]
registry = "docker.io"

[registries."docker.io"]
username = "myuser"
password_env = "DOCKER_TOKEN"

[registries."ghcr.io"]
username = "github_user"
password = "direct_password"
mirror = "ghcr-mirror.example.com"
"#;

        let config: RegistryConfig = toml::from_str(toml_content).unwrap();
        assert_eq!(config.registries.len(), 2);
        assert_eq!(config.default_registry(), "docker.io");

        let docker_entry = config.registries.get("docker.io").unwrap();
        assert_eq!(docker_entry.username.as_deref(), Some("myuser"));
        assert_eq!(docker_entry.password_env.as_deref(), Some("DOCKER_TOKEN"));

        let ghcr_entry = config.registries.get("ghcr.io").unwrap();
        assert_eq!(ghcr_entry.username.as_deref(), Some("github_user"));
        assert_eq!(ghcr_entry.password.as_deref(), Some("direct_password"));
        assert_eq!(
            ghcr_entry.mirror.as_deref(),
            Some("ghcr-mirror.example.com")
        );
    }
}
