//! Credential policy: which credential bindings a machine may use, and where.
//!
//! Shared between the Smolfile parser, the machine record, the API and the
//! interceptor in `smolvm-credentials`, so every surface speaks one shape.
//!
//! The shape mirrors the egress policy used by agent harnesses that target
//! several sandbox backends, so a caller can hand the same document to every
//! backend it supports:
//!
//! ```json
//! {
//!   "credentials": [{
//!     "name": "notion",
//!     "environment_variable": "NOTION_API_KEY",
//!     "allowed_hosts": ["api.notion.com"],
//!     "injection_location": { "header": true }
//!   }]
//! }
//! ```
//!
//! A binding names a credential; it never carries the value. Every binding
//! lists the exact hosts substitution is permitted for, independently of the
//! machine's network allow-list — widening the network never widens a
//! credential, and a credential with no hosts is a configuration error rather
//! than an implicit "anywhere".

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Prefix every generated placeholder starts with. The interceptor refuses
/// requests that carry this prefix anywhere it does not substitute (path,
/// query, body, unsupported headers) so a placeholder can never leak upstream
/// unreplaced.
pub const PLACEHOLDER_PREFIX: &str = "SMOL_PLACEHOLDER_";

/// Guest directory the machine's public credential CA is mounted at.
pub const GUEST_CA_DIR: &str = "/run/smol/credentials";
/// File name of the public CA certificate inside [`GUEST_CA_DIR`].
pub const GUEST_CA_FILE: &str = "ca.pem";
/// Bundle the guest agent assembles from the image's own trust roots plus the
/// machine CA, so clients whose CA variable *replaces* the system store
/// (OpenSSL, curl, Python `requests`, Git) keep trusting public hosts.
pub const GUEST_CA_BUNDLE: &str = "/run/smolvm/ca-bundle.pem";

/// Environment the guest receives so common HTTP clients trust the machine CA.
pub const GUEST_TRUST_ENV: &[(&str, &str)] = &[
    ("SSL_CERT_FILE", GUEST_CA_BUNDLE),
    ("CURL_CA_BUNDLE", GUEST_CA_BUNDLE),
    ("REQUESTS_CA_BUNDLE", GUEST_CA_BUNDLE),
    ("GIT_SSL_CAINFO", GUEST_CA_BUNDLE),
    ("NODE_EXTRA_CA_CERTS", "/run/smol/credentials/ca.pem"),
    ("DENO_CERT", "/run/smol/credentials/ca.pem"),
];

/// HTTP methods a binding may be used with unless it says otherwise.
pub const DEFAULT_METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

const SUPPORTED_METHODS: &[&str] = DEFAULT_METHODS;

/// Where the interceptor substitutes a placeholder.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InjectionLocation {
    /// Substitute inside request header values (`Authorization`, `x-api-key`,
    /// or any other ordinary header). Routing and framing headers are excluded.
    #[serde(default = "yes")]
    pub header: bool,
}

fn yes() -> bool {
    true
}

impl Default for InjectionLocation {
    fn default() -> Self {
        Self { header: true }
    }
}

/// One named credential a workload may use against explicit hosts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialBinding {
    /// Binding name handed to the resolver. Scoped by the caller, never a
    /// storage identifier.
    pub name: String,
    /// Guest environment variable that receives the placeholder.
    pub environment_variable: String,
    /// Exact DNS hosts (lowercase, no wildcard, no scheme or port) the
    /// credential may be sent to.
    pub allowed_hosts: Vec<String>,
    /// Where substitution happens.
    #[serde(default)]
    pub injection_location: InjectionLocation,
    /// HTTP methods the binding may be used with. Defaults to every supported
    /// method; narrow it for read-only tokens.
    #[serde(default = "default_methods")]
    pub methods: Vec<String>,
}

fn default_methods() -> Vec<String> {
    DEFAULT_METHODS.iter().map(|m| m.to_string()).collect()
}

impl CredentialBinding {
    /// Whether this binding permits substitution toward `host`.
    pub fn allows_host(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.');
        self.allowed_hosts
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(host))
    }

    /// Whether this binding permits `method`.
    pub fn allows_method(&self, method: &str) -> bool {
        self.methods.iter().any(|m| m.eq_ignore_ascii_case(method))
    }
}

/// The complete credential section of a machine's network policy.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CredentialPolicy {
    /// Bindings the machine may use, in declaration order.
    pub credentials: Vec<CredentialBinding>,
}

/// Why a policy was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyError(pub String);

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PolicyError {}

fn refuse(message: String) -> Result<(), PolicyError> {
    Err(PolicyError(message))
}

impl CredentialPolicy {
    /// No bindings.
    pub fn is_empty(&self) -> bool {
        self.credentials.is_empty()
    }

    /// Validate structure and, when the machine also restricts egress by
    /// hostname, require every credential host to be reachable under that
    /// allow-list. `network_allowed_hosts = None` means the machine's network is
    /// not hostname-restricted; the credential's own list still applies.
    pub fn validate(&self, network_allowed_hosts: Option<&[String]>) -> Result<(), PolicyError> {
        let mut names = BTreeSet::new();
        let mut env_vars = BTreeSet::new();
        for binding in &self.credentials {
            let name = &binding.name;
            let env_var = &binding.environment_variable;
            if !valid_binding_name(name) {
                return refuse(format!(
                    "credential name {name:?} is not a valid binding name"
                ));
            }
            if !valid_env_name(env_var) {
                return refuse(format!(
                    "credential environment variable {env_var:?} is not a valid name"
                ));
            }
            if !names.insert(name.as_str()) {
                return refuse(format!("credential {name:?} is declared twice"));
            }
            if !env_vars.insert(env_var.as_str()) {
                return refuse(format!(
                    "environment variable {env_var:?} is bound to more than one credential"
                ));
            }
            if binding.allowed_hosts.is_empty() {
                return refuse(format!(
                    "credential {name:?} lists no allowed_hosts; a credential is never sent anywhere by default"
                ));
            }
            for host in &binding.allowed_hosts {
                if !valid_exact_host(host) {
                    return refuse(format!(
                        "credential {name:?} host {host:?} must be an exact lowercase DNS name (no wildcard, scheme, port or IP)"
                    ));
                }
                if network_allowed_hosts
                    .is_some_and(|allowed| !covered_by_allow_list(host, allowed))
                {
                    return refuse(format!(
                        "credential {name:?} host {host:?} is not reachable under the machine's network allow_hosts"
                    ));
                }
            }
            if binding.methods.is_empty() {
                return refuse(format!("credential {name:?} allows no HTTP methods"));
            }
            if let Some(method) = binding.methods.iter().find(|method| {
                !SUPPORTED_METHODS
                    .iter()
                    .any(|m| m.eq_ignore_ascii_case(method))
            }) {
                return refuse(format!(
                    "credential {name:?} method {method:?} is not supported"
                ));
            }
            if !binding.injection_location.header {
                return refuse(format!("credential {name:?} enables no injection location"));
            }
        }
        Ok(())
    }

    /// Bindings permitted to substitute toward `host`, in declaration order.
    pub fn bindings_for_host<'a>(
        &'a self,
        host: &'a str,
    ) -> impl Iterator<Item = &'a CredentialBinding> + 'a {
        self.credentials.iter().filter(move |b| b.allows_host(host))
    }

    /// Look up a binding by name.
    pub fn binding(&self, name: &str) -> Option<&CredentialBinding> {
        self.credentials.iter().find(|b| b.name == name)
    }

    /// Guest environment assignments (`environment_variable`, placeholder).
    /// Bindings without a placeholder are skipped; callers persist placeholders
    /// alongside the policy so this can never silently regenerate them.
    pub fn guest_env<'a>(
        &'a self,
        placeholders: &'a BTreeMap<String, String>,
    ) -> impl Iterator<Item = (String, String)> + 'a {
        self.credentials.iter().filter_map(move |b| {
            placeholders
                .get(&b.name)
                .map(|p| (b.environment_variable.clone(), p.clone()))
        })
    }
}

/// Whether `host` is admitted by a smolvm `allow_hosts` list, whose entries
/// match themselves and any subdomain.
pub fn covered_by_allow_list(host: &str, allowed: &[String]) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    allowed.iter().any(|pattern| {
        let pattern = pattern.trim_end_matches('.').to_ascii_lowercase();
        host == pattern || host.ends_with(&format!(".{pattern}"))
    })
}

fn valid_binding_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'))
}

fn valid_env_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == b'_')
        && bytes.all(|c| c.is_ascii_alphanumeric() || c == b'_')
}

fn valid_exact_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.parse::<std::net::IpAddr>().is_err()
        && !host.contains(['/', ':', '*', '@', '?', '#'])
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn notion() -> CredentialBinding {
        CredentialBinding {
            name: "notion".into(),
            environment_variable: "NOTION_API_KEY".into(),
            allowed_hosts: vec!["api.notion.com".into()],
            injection_location: InjectionLocation::default(),
            methods: default_methods(),
        }
    }

    #[test]
    fn parses_the_harness_shape() {
        let policy: CredentialPolicy = serde_json::from_str(
            r#"{"credentials":[{"name":"notion","environment_variable":"NOTION_API_KEY",
               "allowed_hosts":["api.notion.com"],"injection_location":{"header":true}}]}"#,
        )
        .unwrap();
        assert_eq!(policy.credentials, vec![notion()]);
        policy.validate(None).unwrap();
    }

    #[test]
    fn credential_hosts_must_sit_inside_the_network_allow_list() {
        let policy = CredentialPolicy {
            credentials: vec![notion()],
        };
        policy.validate(Some(&["notion.com".to_string()])).unwrap();
        policy
            .validate(Some(&["api.notion.com".to_string()]))
            .unwrap();
        let err = policy
            .validate(Some(&["api.github.com".to_string()]))
            .unwrap_err();
        assert!(err.0.contains("network allow_hosts"), "{err}");
    }

    #[test]
    fn rejects_empty_wildcard_and_ip_hosts() {
        for host in [
            "",
            "*.notion.com",
            "10.0.0.1",
            "API.notion.com",
            "notion.com:443",
        ] {
            let mut b = notion();
            b.allowed_hosts = vec![host.to_string()];
            let policy = CredentialPolicy {
                credentials: vec![b],
            };
            assert!(policy.validate(None).is_err(), "{host:?} accepted");
        }
        let mut b = notion();
        b.allowed_hosts.clear();
        let policy = CredentialPolicy {
            credentials: vec![b],
        };
        assert!(policy
            .validate(None)
            .unwrap_err()
            .0
            .contains("no allowed_hosts"));
    }

    #[test]
    fn rejects_duplicates_and_bad_names() {
        let policy = CredentialPolicy {
            credentials: vec![notion(), notion()],
        };
        assert!(policy
            .validate(None)
            .unwrap_err()
            .0
            .contains("declared twice"));
        let mut other = notion();
        other.name = "notion-2".into();
        let policy = CredentialPolicy {
            credentials: vec![notion(), other],
        };
        assert!(policy
            .validate(None)
            .unwrap_err()
            .0
            .contains("more than one credential"));
        let mut bad = notion();
        bad.environment_variable = "1BAD".into();
        let policy = CredentialPolicy {
            credentials: vec![bad],
        };
        assert!(policy
            .validate(None)
            .unwrap_err()
            .0
            .contains("not a valid name"));
    }

    #[test]
    fn guest_env_maps_placeholders_onto_bound_variables() {
        let mut github = notion();
        github.name = "github".into();
        github.environment_variable = "GITHUB_TOKEN".into();
        github.allowed_hosts = vec!["api.github.com".into()];
        let policy = CredentialPolicy {
            credentials: vec![notion(), github],
        };
        let placeholders: BTreeMap<String, String> = [
            (
                "notion".to_string(),
                "SMOL_PLACEHOLDER_NOTION_1".to_string(),
            ),
            (
                "github".to_string(),
                "SMOL_PLACEHOLDER_GITHUB_2".to_string(),
            ),
        ]
        .into_iter()
        .collect();
        let env: Vec<_> = policy.guest_env(&placeholders).collect();
        assert_eq!(
            env,
            vec![
                (
                    "NOTION_API_KEY".to_string(),
                    "SMOL_PLACEHOLDER_NOTION_1".to_string()
                ),
                (
                    "GITHUB_TOKEN".to_string(),
                    "SMOL_PLACEHOLDER_GITHUB_2".to_string()
                ),
            ]
        );
        assert!(policy
            .bindings_for_host("api.github.com")
            .all(|b| b.name == "github"));
    }
}
