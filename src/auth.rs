//! OIDC-based authentication for registry operations.
//!
//! Manages JWT tokens from OIDC providers (Auth0 by default) for
//! authenticated registry push operations. Pulls remain anonymous.
//!
//! # Token Storage
//!
//! Tokens are stored in `~/.config/smolvm/auth.json` (mode `0600`),
//! separate from `registries.toml` which handles basic auth.
//!
//! # Provider Portability
//!
//! The [`OidcProvider`] config abstracts all provider-specific URLs.
//! Defaults point to Auth0; users can override via `~/.config/smolvm/oidc.toml`
//! or environment variables (`SMOLVM_OIDC_ISSUER`, etc.).

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

// ============================================================================
// Token Storage
// ============================================================================

/// Authentication tokens for registries, loaded from `~/.config/smolvm/auth.json`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthConfig {
    /// Per-registry token entries.
    #[serde(flatten)]
    pub entries: HashMap<String, AuthEntry>,
}

/// A stored JWT token for a single registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthEntry {
    /// JWT access token.
    pub token: String,
    /// Refresh token for renewing expired access tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Username (extracted from JWT custom claim).
    pub username: String,
    /// Token expiration time (ISO 8601).
    pub expires: String,
}

impl AuthConfig {
    /// Path to the auth token file.
    pub fn config_path() -> Result<PathBuf> {
        let home = dirs::home_dir()
            .ok_or_else(|| Error::config("resolve path", "no home directory found"))?;
        Ok(home.join(".config").join("smolvm").join("auth.json"))
    }

    /// Load auth config from disk. Returns empty config if file doesn't exist.
    pub fn load() -> Result<Self> {
        let path = Self::config_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }

        let contents = std::fs::read_to_string(&path).map_err(|e| {
            Error::config(
                format!("read auth config at {}", path.display()),
                e.to_string(),
            )
        })?;

        let config: Self = serde_json::from_str(&contents).map_err(|e| {
            Error::config(
                format!("parse auth config at {}", path.display()),
                e.to_string(),
            )
        })?;

        Ok(config)
    }

    /// Save auth config to disk with restrictive permissions.
    pub fn save(&self) -> Result<()> {
        let path = Self::config_path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::config("create config directory", e.to_string()))?;
        }

        let contents = serde_json::to_string_pretty(self)
            .map_err(|e| Error::config("serialize auth config", e.to_string()))?;

        std::fs::write(&path, &contents).map_err(|e| {
            Error::config(
                format!("write auth config to {}", path.display()),
                e.to_string(),
            )
        })?;

        // Set file permissions to 0600 (owner read/write only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&path, perms)
                .map_err(|e| Error::config("set auth config permissions", e.to_string()))?;
        }

        Ok(())
    }

    /// Get a valid (non-expired) token for a registry.
    pub fn get_token(&self, registry: &str) -> Option<&str> {
        let entry = self.entries.get(registry)?;
        if is_expired(&entry.expires) {
            tracing::debug!(registry = %registry, "auth token expired");
            return None;
        }
        Some(&entry.token)
    }

    /// Set a token entry for a registry.
    pub fn set_entry(&mut self, registry: String, entry: AuthEntry) {
        self.entries.insert(registry, entry);
    }

    /// Remove a token entry for a registry (logout).
    pub fn remove(&mut self, registry: &str) -> bool {
        self.entries.remove(registry).is_some()
    }
}

/// Check if an ISO 8601 timestamp is in the past.
fn is_expired(expires: &str) -> bool {
    // Parse ISO 8601 timestamp and compare to now.
    // If parsing fails, treat as expired (safe default).
    let Ok(exp) = chrono::DateTime::parse_from_rfc3339(expires) else {
        return true;
    };
    exp < chrono::Utc::now()
}

// ============================================================================
// OIDC Provider Configuration
// ============================================================================

/// Default Auth0 domain for smolmachines.
const DEFAULT_ISSUER: &str = "https://smolmachines.us.auth0.com";
/// Default audience (registry API identifier).
const DEFAULT_AUDIENCE: &str = "https://registry.smolmachines.com";
/// Default client ID for the CLI application (public, safe to embed).
const DEFAULT_CLIENT_ID: &str = "PLACEHOLDER_CLI_CLIENT_ID";
/// Default JWT claim containing the GitHub username.
const DEFAULT_USERNAME_CLAIM: &str = "https://smolmachines.com/github_username";

/// OIDC provider configuration. Provider-agnostic — works with any
/// OIDC-compliant provider (Auth0, WorkOS, Keycloak, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcProvider {
    /// OIDC issuer URL (e.g., `https://smolmachines.us.auth0.com`).
    pub issuer: String,
    /// Device authorization endpoint (RFC 8628).
    #[serde(default)]
    pub device_authorization_endpoint: Option<String>,
    /// Token endpoint.
    #[serde(default)]
    pub token_endpoint: Option<String>,
    /// OAuth client ID (public for CLI apps — safe to embed).
    pub client_id: String,
    /// API audience identifier.
    pub audience: String,
    /// OAuth scopes to request.
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
    /// JWT claim name containing the username for namespace authorization.
    #[serde(default = "default_username_claim")]
    pub username_claim: String,
}

fn default_scopes() -> Vec<String> {
    vec![
        "openid".to_string(),
        "profile".to_string(),
        "offline_access".to_string(),
    ]
}

fn default_username_claim() -> String {
    DEFAULT_USERNAME_CLAIM.to_string()
}

impl OidcProvider {
    /// Load provider config from `~/.config/smolvm/oidc.toml`,
    /// environment variables, or built-in defaults (in that priority order).
    pub fn load() -> Self {
        // Try loading from config file
        if let Ok(home) = dirs::home_dir().ok_or(()) {
            let path = home.join(".config").join("smolvm").join("oidc.toml");
            if path.exists() {
                if let Ok(contents) = std::fs::read_to_string(&path) {
                    if let Ok(config) = toml::from_str::<OidcProvider>(&contents) {
                        tracing::debug!(path = %path.display(), "loaded OIDC config from file");
                        return config;
                    }
                }
            }
        }

        // Fall back to env vars + defaults
        Self::from_env_or_defaults()
    }

    /// Build from environment variables, falling back to built-in defaults.
    fn from_env_or_defaults() -> Self {
        let issuer =
            std::env::var("SMOLVM_OIDC_ISSUER").unwrap_or_else(|_| DEFAULT_ISSUER.to_string());
        let client_id = std::env::var("SMOLVM_OIDC_CLIENT_ID")
            .unwrap_or_else(|_| DEFAULT_CLIENT_ID.to_string());
        let audience =
            std::env::var("SMOLVM_OIDC_AUDIENCE").unwrap_or_else(|_| DEFAULT_AUDIENCE.to_string());

        Self {
            issuer,
            device_authorization_endpoint: None,
            token_endpoint: None,
            client_id,
            audience,
            scopes: default_scopes(),
            username_claim: default_username_claim(),
        }
    }

    /// Get the device authorization endpoint, deriving from issuer if not set.
    pub fn device_endpoint(&self) -> String {
        self.device_authorization_endpoint
            .clone()
            .unwrap_or_else(|| format!("{}/oauth/device/code", self.issuer))
    }

    /// Get the token endpoint, deriving from issuer if not set.
    pub fn token_endpoint(&self) -> String {
        self.token_endpoint
            .clone()
            .unwrap_or_else(|| format!("{}/oauth/token", self.issuer))
    }

    /// Get the scopes as a space-separated string.
    pub fn scope_string(&self) -> String {
        self.scopes.join(" ")
    }
}

impl Default for OidcProvider {
    fn default() -> Self {
        Self {
            issuer: DEFAULT_ISSUER.to_string(),
            device_authorization_endpoint: None,
            token_endpoint: None,
            client_id: DEFAULT_CLIENT_ID.to_string(),
            audience: DEFAULT_AUDIENCE.to_string(),
            scopes: default_scopes(),
            username_claim: default_username_claim(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_config_roundtrip() {
        let mut config = AuthConfig::default();
        config.set_entry(
            "registry.smolmachines.com".to_string(),
            AuthEntry {
                token: "eyJhbGciOiJSUzI1NiJ9.test".to_string(),
                refresh_token: Some("refresh_123".to_string()),
                username: "testuser".to_string(),
                expires: "2099-01-01T00:00:00Z".to_string(),
            },
        );

        let json = serde_json::to_string_pretty(&config).unwrap();
        let reloaded: AuthConfig = serde_json::from_str(&json).unwrap();

        let entry = reloaded.entries.get("registry.smolmachines.com").unwrap();
        assert_eq!(entry.username, "testuser");
        assert_eq!(entry.refresh_token.as_deref(), Some("refresh_123"));
    }

    #[test]
    fn test_get_token_returns_valid() {
        let mut config = AuthConfig::default();
        config.set_entry(
            "registry.example.com".to_string(),
            AuthEntry {
                token: "valid_token".to_string(),
                refresh_token: None,
                username: "user".to_string(),
                expires: "2099-12-31T23:59:59Z".to_string(),
            },
        );

        assert_eq!(
            config.get_token("registry.example.com"),
            Some("valid_token")
        );
    }

    #[test]
    fn test_get_token_returns_none_when_expired() {
        let mut config = AuthConfig::default();
        config.set_entry(
            "registry.example.com".to_string(),
            AuthEntry {
                token: "expired_token".to_string(),
                refresh_token: None,
                username: "user".to_string(),
                expires: "2020-01-01T00:00:00Z".to_string(),
            },
        );

        assert_eq!(config.get_token("registry.example.com"), None);
    }

    #[test]
    fn test_get_token_returns_none_for_unknown_registry() {
        let config = AuthConfig::default();
        assert_eq!(config.get_token("unknown.example.com"), None);
    }

    #[test]
    fn test_remove_entry() {
        let mut config = AuthConfig::default();
        config.set_entry(
            "registry.example.com".to_string(),
            AuthEntry {
                token: "token".to_string(),
                refresh_token: None,
                username: "user".to_string(),
                expires: "2099-01-01T00:00:00Z".to_string(),
            },
        );

        assert!(config.remove("registry.example.com"));
        assert!(!config.remove("registry.example.com")); // already removed
        assert_eq!(config.get_token("registry.example.com"), None);
    }

    #[test]
    fn test_oidc_provider_defaults() {
        let provider = OidcProvider::default();
        assert!(provider.issuer.contains("auth0.com"));
        assert_eq!(provider.audience, "https://registry.smolmachines.com");
        assert!(provider.scopes.contains(&"openid".to_string()));
    }

    #[test]
    fn test_oidc_provider_endpoint_derivation() {
        let provider = OidcProvider::default();
        assert!(provider.device_endpoint().ends_with("/oauth/device/code"));
        assert!(provider.token_endpoint().ends_with("/oauth/token"));
    }

    #[test]
    fn test_oidc_provider_explicit_endpoints() {
        let provider = OidcProvider {
            device_authorization_endpoint: Some("https://custom.example.com/device".to_string()),
            token_endpoint: Some("https://custom.example.com/token".to_string()),
            ..OidcProvider::default()
        };
        assert_eq!(
            provider.device_endpoint(),
            "https://custom.example.com/device"
        );
        assert_eq!(
            provider.token_endpoint(),
            "https://custom.example.com/token"
        );
    }

    #[test]
    fn test_is_expired() {
        assert!(is_expired("2020-01-01T00:00:00Z"));
        assert!(!is_expired("2099-01-01T00:00:00Z"));
        assert!(is_expired("invalid")); // bad format → expired (safe default)
    }
}
