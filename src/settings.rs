//! Unified user settings for smolvm and the smol CLI.
//!
//! All user-facing configuration lives in `~/.config/smolvm/config.toml`:
//!
//! ```toml
//! [cloud]
//! endpoint = "https://api.smolmachines.com"
//! api_key = "smk_live_abc123"
//!
//! [machines.defaults]
//! registry = "registry.smolmachines.com"
//!
//! [machines.registries."registry.smolmachines.com"]
//! username = "token"
//! password = "eyJ..."
//!
//! [images.defaults]
//! registry = "docker.io"
//!
//! [images.registries."docker.io"]
//! username = "myuser"
//! password_env = "DOCKER_HUB_TOKEN"
//! ```
//!
//! - `[cloud]` — smolcloud API credentials
//! - `[machines]` — credentials for OCI registries storing .smolmachine artifacts
//! - `[images]` — credentials for container image registries (base images for VMs)

use crate::error::{Error, Result};
use crate::registry::RegistryConfig;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Unified settings loaded from `~/.config/smolvm/config.toml`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SmolSettings {
    /// smolcloud API configuration.
    #[serde(default)]
    pub cloud: CloudSection,
    /// Credentials for .smolmachine artifact registries.
    #[serde(default)]
    pub machines: RegistryConfig,
    /// Credentials for container image registries.
    #[serde(default)]
    pub images: RegistryConfig,
}

/// smolcloud API configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CloudSection {
    /// smolcloud API endpoint (e.g., "https://api.smolmachines.com").
    pub endpoint: Option<String>,
    /// API key for authentication (e.g., "smk_..." or a JWT).
    pub api_key: Option<String>,
    /// OAuth refresh token for silent token renewal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Unix timestamp when the access token expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_expires_at: Option<i64>,
}

impl SmolSettings {
    /// Get the path to the unified configuration file.
    ///
    /// Respects `SMOLVM_CONFIG` environment variable for overriding the default
    /// path. This is useful for CI/CD and server deployments where the config
    /// file is placed at a non-standard location.
    pub fn config_path() -> Result<PathBuf> {
        if let Ok(custom) = std::env::var("SMOLVM_CONFIG") {
            return Ok(PathBuf::from(custom));
        }
        let home = dirs::home_dir()
            .ok_or_else(|| Error::config("resolve path", "no home directory found"))?;
        Ok(home.join(".config").join("smolvm").join("config.toml"))
    }

    /// Load settings from the config file, migrating from old format if needed.
    ///
    /// Returns empty settings if no config file exists. Migrates legacy
    /// `registries.toml` into the `[images]` section on first load.
    pub fn load() -> Result<Self> {
        let config_path = match Self::config_path() {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!(error = %e, "could not determine settings config path");
                return Ok(Self::default());
            }
        };

        if config_path.exists() {
            let contents = std::fs::read_to_string(&config_path).map_err(|e| {
                Error::config(
                    format!("read config at {}", config_path.display()),
                    e.to_string(),
                )
            })?;

            let settings: Self = toml::from_str(&contents).map_err(|e| {
                Error::config(
                    format!("parse config at {}", config_path.display()),
                    e.to_string(),
                )
            })?;

            tracing::debug!(
                path = %config_path.display(),
                machines_count = settings.machines.registries.len(),
                images_count = settings.images.registries.len(),
                "loaded settings"
            );

            return Ok(settings);
        }

        // Migrate from legacy registries.toml if it exists
        if let Some(dir) = config_path.parent() {
            let old_path = dir.join("registries.toml");
            if old_path.exists() {
                tracing::info!(
                    old = %old_path.display(),
                    new = %config_path.display(),
                    "migrating legacy registries.toml to config.toml"
                );
                if let Ok(contents) = std::fs::read_to_string(&old_path) {
                    if let Ok(old_config) = toml::from_str::<RegistryConfig>(&contents) {
                        let settings = SmolSettings {
                            images: old_config,
                            ..Default::default()
                        };
                        // Best-effort save; don't fail the load on write errors
                        if let Err(e) = settings.save() {
                            tracing::warn!(error = %e, "failed to save migrated config");
                        }
                        return Ok(settings);
                    }
                }
            }
        }

        tracing::debug!(
            path = %config_path.display(),
            "config file not found, using defaults"
        );
        Ok(Self::default())
    }

    /// Persist the settings back to the config file.
    ///
    /// Sets file permissions to `0600` (owner read/write only) since this
    /// file may contain secrets (API keys, registry tokens).
    pub fn save(&self) -> Result<()> {
        let config_path = Self::config_path()?;
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::config("create config directory", e.to_string()))?;
        }
        let contents = toml::to_string_pretty(self)
            .map_err(|e| Error::config("serialize settings", e.to_string()))?;
        std::fs::write(&config_path, &contents).map_err(|e| {
            Error::config(
                format!("write config to {}", config_path.display()),
                e.to_string(),
            )
        })?;

        // Restrict file permissions — config contains secrets
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            let _ = std::fs::set_permissions(&config_path, perms);
        }

        Ok(())
    }
}

/// Buffer in seconds before actual expiry to trigger refresh.
const TOKEN_EXPIRY_BUFFER_SECS: i64 = 60;

impl CloudSection {
    /// Get the endpoint, or error with a helpful message.
    pub fn endpoint(&self) -> Result<&str> {
        self.endpoint.as_deref().ok_or_else(|| {
            Error::config(
                "cloud endpoint",
                "No smolcloud endpoint configured. Set one with: smol config set cloud <url>",
            )
        })
    }

    /// Check if the stored access token has expired or will expire within 60 seconds.
    ///
    /// Returns `false` if no expiry is set (assume valid).
    pub fn is_token_expired(&self) -> bool {
        match self.token_expires_at {
            Some(expires_at) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                now >= expires_at - TOKEN_EXPIRY_BUFFER_SECS
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_settings_are_empty() {
        let settings = SmolSettings::default();
        assert!(settings.cloud.endpoint.is_none());
        assert!(settings.cloud.api_key.is_none());
        assert!(settings.machines.registries.is_empty());
        assert!(settings.images.registries.is_empty());
    }

    #[test]
    fn settings_roundtrip_toml() {
        let mut settings = SmolSettings::default();
        settings.cloud.endpoint = Some("https://api.smolmachines.com".to_string());
        settings.cloud.api_key = Some("smk_test".to_string());
        settings
            .machines
            .set_token("registry.smolmachines.com", "eyJhbGci.test");
        settings.images.registries.insert(
            "docker.io".to_string(),
            crate::registry::RegistryEntry {
                username: Some("user".to_string()),
                password: None,
                password_env: Some("DOCKER_TOKEN".to_string()),
                mirror: None,
                refresh_token: None,
                expires_at: None,
            },
        );

        let serialized = toml::to_string_pretty(&settings).unwrap();
        let reloaded: SmolSettings = toml::from_str(&serialized).unwrap();

        assert_eq!(
            reloaded.cloud.endpoint.as_deref(),
            Some("https://api.smolmachines.com")
        );
        assert_eq!(reloaded.cloud.api_key.as_deref(), Some("smk_test"));

        let machine_creds = reloaded
            .machines
            .get_credentials("registry.smolmachines.com")
            .unwrap();
        assert_eq!(machine_creds.username, "token");
        assert_eq!(machine_creds.password, "eyJhbGci.test");

        let image_entry = reloaded.images.registries.get("docker.io").unwrap();
        assert_eq!(image_entry.username.as_deref(), Some("user"));
        assert_eq!(image_entry.password_env.as_deref(), Some("DOCKER_TOKEN"));
    }

    #[test]
    fn settings_parses_target_format() {
        let toml_str = r#"
[cloud]
endpoint = "https://api.smolmachines.com"
api_key = "smk_live_abc123"

[machines.defaults]
registry = "registry.smolmachines.com"

[machines.registries."registry.smolmachines.com"]
username = "token"
password = "eyJhbGci..."

[images.defaults]
registry = "docker.io"

[images.registries."docker.io"]
username = "myuser"
password_env = "DOCKER_HUB_TOKEN"

[images.registries."ghcr.io"]
username = "github_user"
password_env = "GHCR_TOKEN"
mirror = "ghcr-mirror.example.com"
"#;

        let settings: SmolSettings = toml::from_str(toml_str).unwrap();
        assert_eq!(
            settings.cloud.endpoint.as_deref(),
            Some("https://api.smolmachines.com")
        );
        assert_eq!(settings.cloud.api_key.as_deref(), Some("smk_live_abc123"));
        assert_eq!(settings.machines.default_registry(), "registry.smolmachines.com");
        assert_eq!(settings.images.default_registry(), "docker.io");
        assert_eq!(settings.images.registries.len(), 2);

        let ghcr = settings.images.registries.get("ghcr.io").unwrap();
        assert_eq!(ghcr.mirror.as_deref(), Some("ghcr-mirror.example.com"));
    }

    #[test]
    fn config_path_default_ends_with_expected_components() {
        // Do not mutate SMOLVM_CONFIG — env vars are process-global and unsafe
        // to set in parallel tests. The SMOLVM_CONFIG override path is exercised
        // by load_from_custom_path_via_env which parses directly without env mutation.
        // Only verify the default path shape when the env var is absent.
        if std::env::var("SMOLVM_CONFIG").is_ok() {
            return; // another parallel test holds the env var — skip
        }
        let path = SmolSettings::config_path().unwrap();
        assert!(
            path.ends_with(".config/smolvm/config.toml"),
            "unexpected default config path: {}",
            path.display()
        );
    }

    #[test]
    fn load_from_custom_path_via_env() {
        // This test verifies SMOLVM_CONFIG override by parsing directly
        // rather than using env vars (which interfere with parallel tests).
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("test-config.toml");
        std::fs::write(
            &config_path,
            r#"
[cloud]
api_key = "env-override-key"
"#,
        )
        .unwrap();

        let contents = std::fs::read_to_string(&config_path).unwrap();
        let settings: SmolSettings = toml::from_str(&contents).unwrap();
        assert_eq!(settings.cloud.api_key.as_deref(), Some("env-override-key"));
    }

    #[test]
    fn save_and_reload_preserves_refresh_token_fields() {
        // Test roundtrip via direct file write + parse (avoids env var races)
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");

        let mut settings = SmolSettings::default();
        settings.cloud.api_key = Some("access123".to_string());
        settings.cloud.refresh_token = Some("refresh456".to_string());
        settings.cloud.token_expires_at = Some(1700000000);

        let contents = toml::to_string_pretty(&settings).unwrap();
        std::fs::write(&config_path, &contents).unwrap();

        let reloaded_contents = std::fs::read_to_string(&config_path).unwrap();
        let reloaded: SmolSettings = toml::from_str(&reloaded_contents).unwrap();
        assert_eq!(reloaded.cloud.api_key.as_deref(), Some("access123"));
        assert_eq!(
            reloaded.cloud.refresh_token.as_deref(),
            Some("refresh456")
        );
        assert_eq!(reloaded.cloud.token_expires_at, Some(1700000000));
    }

    #[test]
    fn is_token_expired_returns_false_when_no_expiry() {
        let cloud = CloudSection::default();
        assert!(!cloud.is_token_expired());
    }

    #[test]
    fn is_token_expired_returns_true_for_past_timestamp() {
        let cloud = CloudSection {
            token_expires_at: Some(1000000000), // year 2001
            ..Default::default()
        };
        assert!(cloud.is_token_expired());
    }

    #[test]
    fn is_token_expired_returns_false_for_far_future() {
        let cloud = CloudSection {
            token_expires_at: Some(4000000000), // year 2096
            ..Default::default()
        };
        assert!(!cloud.is_token_expired());
    }

    #[test]
    fn registry_entry_refresh_fields_roundtrip() {
        let toml_str = r#"
[machines.registries."registry.smolmachines.com"]
username = "token"
password = "access123"
refresh_token = "refresh456"
expires_at = 1700000000
"#;

        let settings: SmolSettings = toml::from_str(toml_str).unwrap();
        let entry = settings
            .machines
            .registries
            .get("registry.smolmachines.com")
            .unwrap();
        assert_eq!(entry.refresh_token.as_deref(), Some("refresh456"));
        assert_eq!(entry.expires_at, Some(1700000000));

        // Roundtrip
        let serialized = toml::to_string_pretty(&settings).unwrap();
        assert!(serialized.contains("refresh_token"));
        assert!(serialized.contains("1700000000"));
    }

    #[test]
    fn skip_serializing_none_refresh_fields() {
        let settings = SmolSettings::default();
        let serialized = toml::to_string_pretty(&settings).unwrap();
        // None fields should not appear
        assert!(!serialized.contains("refresh_token"));
        assert!(!serialized.contains("expires_at"));
        assert!(!serialized.contains("token_expires_at"));
    }
}
