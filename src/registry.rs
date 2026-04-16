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
            Error::config(
                format!("read registry config at {}", config_path.display()),
                e.to_string(),
            )
        })?;

        let config: Self = toml::from_str(&contents).map_err(|e| {
            Error::config(
                format!("parse registry config at {}", config_path.display()),
                e.to_string(),
            )
        })?;

        tracing::debug!(
            path = %config_path.display(),
            registry_count = config.registries.len(),
            "loaded registry configuration"
        );

        Ok(config)
    }

    /// Get the path to the registry configuration file.
    ///
    /// Always uses `~/.config/smolvm/registries.toml` regardless of platform
    /// for consistent behavior across macOS and Linux.
    pub fn config_path() -> Result<PathBuf> {
        let home = dirs::home_dir()
            .ok_or_else(|| Error::config("resolve path", "no home directory found"))?;
        Ok(home.join(".config").join("smolvm").join("registries.toml"))
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
            .or_else(|| {
                if entry.password.is_some() {
                    tracing::warn!(
                        registry = %registry,
                        "using plaintext password from config — use password_env instead"
                    );
                }
                entry.password.clone()
            })?;

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

    /// Set credentials for a registry, creating the entry if needed.
    pub fn set_credentials(&mut self, registry: &str, username: String, password: String) {
        let entry = self.registries.entry(registry.to_string()).or_default();
        entry.username = Some(username);
        entry.password = Some(password);
        entry.password_env = None;
    }

    /// Save the configuration back to disk.
    pub fn save(&self) -> Result<()> {
        let config_path = Self::config_path()?;
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::config("create config directory", e.to_string()))?;
        }
        let contents = toml::to_string_pretty(self)
            .map_err(|e| Error::config("serialize registry config", e.to_string()))?;
        std::fs::write(&config_path, contents).map_err(|e| {
            Error::config(
                format!("write registry config to {}", config_path.display()),
                e.to_string(),
            )
        })?;
        Ok(())
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

/// Default registry for smolmachines artifacts.
pub const SMOLMACHINES_REGISTRY: &str = "registry.smolmachines.com";

/// Error parsing an artifact reference.
#[derive(Debug, Clone, PartialEq)]
pub struct ReferenceError {
    /// The original input that failed to parse.
    pub input: String,
    /// What went wrong.
    pub reason: String,
}

impl std::fmt::Display for ReferenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid reference '{}': {}", self.input, self.reason)
    }
}

impl std::error::Error for ReferenceError {}

/// A parsed OCI-style reference for smolmachine artifacts.
///
/// Supports both tag and digest references:
/// ```text
/// smolmachines.com/python-dev:latest              # tag
/// smolmachines.com/python-dev@sha256:abc123...    # digest (immutable)
/// smolmachines.com/binsquare/custom:v1            # user namespace
/// python-dev:latest                                # shorthand (default registry)
/// python-dev                                       # bare (default registry + "latest")
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct Reference {
    /// Registry hostname (e.g., "registry.smolmachines.com").
    pub registry: String,
    /// User namespace, if present (e.g., "binsquare"). None for official.
    pub namespace: Option<String>,
    /// Machine name (e.g., "python-dev").
    pub name: String,
    /// Tag (e.g., "latest", "v1.0"). None if digest is set.
    pub tag: Option<String>,
    /// Digest (e.g., "sha256:abc123..."). None if tag is set.
    pub digest: Option<String>,
}

impl Reference {
    /// Parse a reference string.
    ///
    /// Returns a [`ReferenceError`] if the reference is empty or malformed.
    pub fn parse(input: &str) -> std::result::Result<Self, ReferenceError> {
        let raw_input = input;
        let input = input.trim();

        let err = |reason: &str| ReferenceError {
            input: raw_input.to_string(),
            reason: reason.to_string(),
        };

        if input.is_empty() {
            return Err(err("empty reference"));
        }

        // Split off digest (@sha256:...) or tag (:tag) from the end.
        // Digest takes precedence: `image@sha256:...` is a digest ref even if
        // there's a `:` in the name part.
        let (path, tag, digest) = if let Some(at_pos) = input.find('@') {
            let path = &input[..at_pos];
            let digest_str = &input[at_pos + 1..];
            validate_digest(raw_input, digest_str)?;
            (path, None, Some(digest_str.to_string()))
        } else {
            // No digest — check for tag after the last colon.
            // But we must not split on `:` inside a registry hostname with port
            // (e.g., "localhost:5000/image:tag").
            // Strategy: find the last `/`, then look for `:` after it.
            let tag_split_from = input.rfind('/').map(|p| p + 1).unwrap_or(0);
            let after_last_slash = &input[tag_split_from..];

            if let Some(colon_pos) = after_last_slash.find(':') {
                let abs_colon = tag_split_from + colon_pos;
                let path = &input[..abs_colon];
                let tag = &input[abs_colon + 1..];
                if tag.is_empty() {
                    return Err(err("empty tag"));
                }
                (path, Some(tag.to_string()), None)
            } else {
                (input, None, None)
            }
        };

        // Now parse the path into registry / namespace / name.
        let parts: Vec<&str> = path.split('/').collect();

        let (registry, namespace, name) = match parts.len() {
            1 => {
                // "python-dev" — bare name, default registry
                (
                    SMOLMACHINES_REGISTRY.to_string(),
                    None,
                    parts[0].to_string(),
                )
            }
            2 => {
                let first = parts[0];
                if first.contains('.') || first.contains(':') {
                    // "smolmachines.com/python-dev" — registry + name (official)
                    (first.to_string(), None, parts[1].to_string())
                } else {
                    // "binsquare/custom" — namespace + name (default registry)
                    (
                        SMOLMACHINES_REGISTRY.to_string(),
                        Some(first.to_string()),
                        parts[1].to_string(),
                    )
                }
            }
            3 => {
                // "smolmachines.com/binsquare/custom" — registry + namespace + name
                let first = parts[0];
                if !first.contains('.') && !first.contains(':') {
                    return Err(ReferenceError {
                        input: raw_input.to_string(),
                        reason: format!(
                            "first component '{}' doesn't look like a registry hostname",
                            first
                        ),
                    });
                }
                (
                    first.to_string(),
                    Some(parts[1].to_string()),
                    parts[2].to_string(),
                )
            }
            _ => {
                return Err(err("too many path components"));
            }
        };

        if name.is_empty() {
            return Err(err("empty name"));
        }

        Ok(Reference {
            registry,
            namespace,
            name,
            tag,
            digest,
        })
    }

    /// The full repository path (namespace/name or just name).
    pub fn repository(&self) -> String {
        match &self.namespace {
            Some(ns) => format!("{}/{}", ns, self.name),
            None => self.name.clone(),
        }
    }
}

impl std::fmt::Display for Reference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let repo = self.repository();
        let suffix = if let Some(ref d) = self.digest {
            format!("@{}", d)
        } else if let Some(ref t) = self.tag {
            format!(":{}", t)
        } else {
            ":latest".to_string()
        };
        write!(f, "{}/{}{}", self.registry, repo, suffix)
    }
}

/// Validate a digest string: must be `sha256:` followed by exactly 64 hex chars.
fn validate_digest(raw_input: &str, digest: &str) -> std::result::Result<(), ReferenceError> {
    let hex = match digest.strip_prefix("sha256:") {
        Some(h) => h,
        None => {
            return Err(ReferenceError {
                input: raw_input.to_string(),
                reason: format!(
                    "unsupported digest algorithm in '{}': only sha256 is supported",
                    digest
                ),
            });
        }
    };

    if hex.len() != 64 {
        return Err(ReferenceError {
            input: raw_input.to_string(),
            reason: format!("digest has {} hex chars, expected 64", hex.len()),
        });
    }

    if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ReferenceError {
            input: raw_input.to_string(),
            reason: "digest contains non-hex characters".to_string(),
        });
    }

    Ok(())
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

    #[test]
    fn test_get_credentials_with_env_password() {
        // Set environment variable for this test
        std::env::set_var("SMOLVM_TEST_TOKEN", "env_password_123");

        let mut config = RegistryConfig::default();
        config.registries.insert(
            "test.io".to_string(),
            RegistryEntry {
                username: Some("envuser".to_string()),
                password: None,
                password_env: Some("SMOLVM_TEST_TOKEN".to_string()),
                mirror: None,
            },
        );

        let creds = config.get_credentials("test.io");
        assert!(creds.is_some());
        let creds = creds.unwrap();
        assert_eq!(creds.username, "envuser");
        assert_eq!(creds.password, "env_password_123");

        // Clean up
        std::env::remove_var("SMOLVM_TEST_TOKEN");
    }

    #[test]
    fn test_get_credentials_env_var_not_set() {
        let mut config = RegistryConfig::default();
        config.registries.insert(
            "test.io".to_string(),
            RegistryEntry {
                username: Some("user".to_string()),
                password: None,
                password_env: Some("SMOLVM_NONEXISTENT_VAR".to_string()),
                mirror: None,
            },
        );

        // Should return None when env var is not set
        assert!(config.get_credentials("test.io").is_none());
    }

    #[test]
    fn test_has_registries() {
        let mut config = RegistryConfig::default();
        assert!(!config.has_registries());

        config
            .registries
            .insert("docker.io".to_string(), RegistryEntry::default());
        assert!(config.has_registries());
    }

    #[test]
    fn test_extract_registry_edge_cases() {
        // Image with tag containing colon (version)
        assert_eq!(extract_registry("alpine:3.18.0"), "docker.io");

        // Image with digest
        assert_eq!(extract_registry("alpine@sha256:abc123"), "docker.io");

        // Registry with port and path
        assert_eq!(
            extract_registry("registry.example.com:5000/myorg/myimage:latest"),
            "registry.example.com:5000"
        );
    }

    #[test]
    fn test_rewrite_image_registry_with_tag() {
        assert_eq!(
            rewrite_image_registry("alpine:3.18", "mirror.example.com"),
            "mirror.example.com/library/alpine:3.18"
        );

        assert_eq!(
            rewrite_image_registry("nginx:latest", "mirror.example.com"),
            "mirror.example.com/library/nginx:latest"
        );
    }

    #[test]
    fn test_default_registry_custom() {
        let mut config = RegistryConfig::default();
        config.defaults.registry = Some("custom.registry.io".to_string());
        assert_eq!(config.default_registry(), "custom.registry.io");
    }

    // --- Reference parser tests ---

    #[test]
    fn test_reference_bare_name() {
        let r = Reference::parse("python-dev").unwrap();
        assert_eq!(r.registry, SMOLMACHINES_REGISTRY);
        assert_eq!(r.namespace, None);
        assert_eq!(r.name, "python-dev");
        assert_eq!(r.tag, None);
        assert_eq!(r.digest, None);
    }

    #[test]
    fn test_reference_name_with_tag() {
        let r = Reference::parse("python-dev:latest").unwrap();
        assert_eq!(r.registry, SMOLMACHINES_REGISTRY);
        assert_eq!(r.namespace, None);
        assert_eq!(r.name, "python-dev");
        assert_eq!(r.tag, Some("latest".to_string()));
        assert_eq!(r.digest, None);
    }

    #[test]
    fn test_reference_registry_and_name() {
        let r = Reference::parse("smolmachines.com/python-dev:latest").unwrap();
        assert_eq!(r.registry, "smolmachines.com");
        assert_eq!(r.namespace, None);
        assert_eq!(r.name, "python-dev");
        assert_eq!(r.tag, Some("latest".to_string()));
    }

    #[test]
    fn test_reference_registry_namespace_name() {
        let r = Reference::parse("smolmachines.com/binsquare/custom:v1").unwrap();
        assert_eq!(r.registry, "smolmachines.com");
        assert_eq!(r.namespace, Some("binsquare".to_string()));
        assert_eq!(r.name, "custom");
        assert_eq!(r.tag, Some("v1".to_string()));
    }

    #[test]
    fn test_reference_namespace_without_registry() {
        let r = Reference::parse("binsquare/custom:v1").unwrap();
        assert_eq!(r.registry, SMOLMACHINES_REGISTRY);
        assert_eq!(r.namespace, Some("binsquare".to_string()));
        assert_eq!(r.name, "custom");
        assert_eq!(r.tag, Some("v1".to_string()));
    }

    #[test]
    fn test_reference_digest() {
        let digest = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let input = format!("python-dev@{}", digest);
        let r = Reference::parse(&input).unwrap();
        assert_eq!(r.registry, SMOLMACHINES_REGISTRY);
        assert_eq!(r.name, "python-dev");
        assert_eq!(r.tag, None);
        assert_eq!(r.digest, Some(digest.to_string()));
    }

    #[test]
    fn test_reference_registry_with_port() {
        let r = Reference::parse("localhost:5000/myimage:latest").unwrap();
        assert_eq!(r.registry, "localhost:5000");
        assert_eq!(r.namespace, None);
        assert_eq!(r.name, "myimage");
        assert_eq!(r.tag, Some("latest".to_string()));
    }

    #[test]
    fn test_reference_display() {
        let r = Reference::parse("python-dev:latest").unwrap();
        assert_eq!(
            r.to_string(),
            format!("{}/python-dev:latest", SMOLMACHINES_REGISTRY)
        );

        let r = Reference::parse("python-dev").unwrap();
        // Bare name gets :latest in display
        assert_eq!(
            r.to_string(),
            format!("{}/python-dev:latest", SMOLMACHINES_REGISTRY)
        );
    }

    #[test]
    fn test_reference_display_digest() {
        let digest = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let input = format!("smolmachines.com/python-dev@{}", digest);
        let r = Reference::parse(&input).unwrap();
        assert_eq!(
            r.to_string(),
            format!("smolmachines.com/python-dev@{}", digest)
        );
    }

    #[test]
    fn test_reference_error_empty() {
        let err = Reference::parse("").unwrap_err();
        assert_eq!(err.reason, "empty reference");
        assert!(Reference::parse("  ").is_err());
    }

    #[test]
    fn test_reference_error_invalid_digest_algorithm() {
        let err = Reference::parse("python-dev@md5:abc123").unwrap_err();
        assert!(err.reason.contains("unsupported digest algorithm"));
    }

    #[test]
    fn test_reference_error_digest_too_short() {
        let err = Reference::parse("python-dev@sha256:tooshort").unwrap_err();
        assert!(err.reason.contains("hex chars, expected 64"));
    }

    #[test]
    fn test_reference_error_digest_non_hex() {
        // 64 chars but contains 'g' which is not hex
        let bad = format!(
            "python-dev@sha256:{}",
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567g9"
        );
        let err = Reference::parse(&bad).unwrap_err();
        assert!(err.reason.contains("non-hex"));
    }

    #[test]
    fn test_reference_error_empty_tag() {
        let err = Reference::parse("python-dev:").unwrap_err();
        assert_eq!(err.reason, "empty tag");
    }

    #[test]
    fn test_reference_error_too_many_components() {
        let err = Reference::parse("a.com/b/c/d:latest").unwrap_err();
        assert!(err.reason.contains("too many path components"));
    }

    #[test]
    fn test_set_credentials_new_entry() {
        let mut config = RegistryConfig::default();
        config.set_credentials("registry.example.com", "user".into(), "pass".into());

        let creds = config.get_credentials("registry.example.com").unwrap();
        assert_eq!(creds.username, "user");
        assert_eq!(creds.password, "pass");
    }

    #[test]
    fn test_set_credentials_overwrites_existing() {
        let mut config = RegistryConfig::default();
        config.registries.insert(
            "registry.example.com".to_string(),
            RegistryEntry {
                username: Some("old_user".to_string()),
                password: None,
                password_env: Some("OLD_TOKEN".to_string()),
                mirror: Some("mirror.example.com".to_string()),
            },
        );

        config.set_credentials("registry.example.com", "new_user".into(), "new_pass".into());

        let entry = config.registries.get("registry.example.com").unwrap();
        assert_eq!(entry.username.as_deref(), Some("new_user"));
        assert_eq!(entry.password.as_deref(), Some("new_pass"));
        // password_env should be cleared when setting direct password
        assert_eq!(entry.password_env, None);
        // mirror should be preserved
        assert_eq!(entry.mirror.as_deref(), Some("mirror.example.com"));
    }

    #[test]
    fn test_save_and_reload() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("registries.toml");

        let mut config = RegistryConfig::default();
        config.set_credentials(
            "registry.smolmachines.com",
            "testuser".into(),
            "testpass".into(),
        );

        // Write manually to the temp path (save() uses the real config path)
        let contents = toml::to_string_pretty(&config).unwrap();
        std::fs::write(&config_path, &contents).unwrap();

        // Reload and verify
        let reloaded: RegistryConfig =
            toml::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        let creds = reloaded
            .get_credentials("registry.smolmachines.com")
            .unwrap();
        assert_eq!(creds.username, "testuser");
        assert_eq!(creds.password, "testpass");
    }

    #[test]
    fn test_save_roundtrip_preserves_all_fields() {
        let mut config = RegistryConfig::default();
        config.defaults.registry = Some("custom.io".to_string());
        config.registries.insert(
            "ghcr.io".to_string(),
            RegistryEntry {
                username: Some("gh_user".to_string()),
                password: Some("gh_pass".to_string()),
                password_env: None,
                mirror: Some("ghcr-mirror.example.com".to_string()),
            },
        );

        let serialized = toml::to_string_pretty(&config).unwrap();
        let reloaded: RegistryConfig = toml::from_str(&serialized).unwrap();

        assert_eq!(reloaded.default_registry(), "custom.io");
        let entry = reloaded.registries.get("ghcr.io").unwrap();
        assert_eq!(entry.username.as_deref(), Some("gh_user"));
        assert_eq!(entry.password.as_deref(), Some("gh_pass"));
        assert_eq!(entry.mirror.as_deref(), Some("ghcr-mirror.example.com"));
    }
}
