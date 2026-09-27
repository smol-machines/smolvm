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
    /// Guest environment variable that receives the placeholder. May be empty
    /// for a binding that only sets a header (see [`Self::set_header`]).
    #[serde(default)]
    pub environment_variable: String,
    /// Hosts the credential may be sent to: exact lowercase DNS names, or a
    /// whole-label wildcard (`*.example.com`) matching every subdomain but not
    /// `example.com` itself. No scheme, port or IP.
    pub allowed_hosts: Vec<String>,
    /// Where substitution happens.
    #[serde(default)]
    pub injection_location: InjectionLocation,
    /// HTTP methods the binding may be used with. Defaults to every supported
    /// method; narrow it for read-only tokens.
    #[serde(default = "default_methods")]
    pub methods: Vec<String>,
    /// Set this request header to the credential's value on every request to
    /// an allowed host with an allowed method, replacing whatever the guest
    /// sent. The value is the whole header value (`Bearer …`, `Basic …`). The
    /// guest needs no placeholder and never learns the value — the shape of a
    /// firewall that brokers credentials by domain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set_header: Option<String>,
}

fn default_methods() -> Vec<String> {
    DEFAULT_METHODS.iter().map(|m| m.to_string()).collect()
}

impl CredentialBinding {
    /// Whether this binding permits substitution toward `host`.
    pub fn allows_host(&self, host: &str) -> bool {
        self.allowed_hosts
            .iter()
            .any(|allowed| host_matches(allowed, host))
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
            // A header-setting binding needs no placeholder, so no variable.
            let env_optional = binding.set_header.is_some() && env_var.is_empty();
            if !env_optional && !valid_env_name(env_var) {
                return refuse(format!(
                    "credential environment variable {env_var:?} is not a valid name"
                ));
            }
            if !names.insert(name.as_str()) {
                return refuse(format!("credential {name:?} is declared twice"));
            }
            if !env_optional && !env_vars.insert(env_var.as_str()) {
                return refuse(format!(
                    "environment variable {env_var:?} is bound to more than one credential"
                ));
            }
            if let Some(header) = &binding.set_header {
                if !valid_header_name(header) {
                    return refuse(format!(
                        "credential {name:?} set_header {header:?} must be a lowercase HTTP header name"
                    ));
                }
                if PROTECTED_HEADERS.contains(&header.as_str()) {
                    return refuse(format!(
                        "credential {name:?} may not set {header:?}, a routing or framing header"
                    ));
                }
            }
            if binding.allowed_hosts.is_empty() {
                return refuse(format!(
                    "credential {name:?} lists no allowed_hosts; a credential is never sent anywhere by default"
                ));
            }
            for host in &binding.allowed_hosts {
                if !valid_host_pattern(host) {
                    return refuse(format!(
                        "credential {name:?} host {host:?} must be a lowercase DNS name, optionally \
                         `*.` plus a name with at least two labels (no scheme, port or IP)"
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
        // Two bindings setting the same header for the same host would leave
        // which value is sent up to declaration order; refuse the ambiguity.
        for (i, a) in self.credentials.iter().enumerate() {
            for b in &self.credentials[i + 1..] {
                let (Some(ha), Some(hb)) = (&a.set_header, &b.set_header) else {
                    continue;
                };
                let overlap = ha == hb
                    && a.allowed_hosts
                        .iter()
                        .any(|x| b.allowed_hosts.iter().any(|y| patterns_overlap(x, y)));
                if overlap {
                    return refuse(format!(
                        "credentials {:?} and {:?} both set {ha:?} for the same host",
                        a.name, b.name
                    ));
                }
            }
        }
        Ok(())
    }

    /// Bindings that set a header toward `host` for `method`, in declaration
    /// order.
    pub fn header_bindings<'a>(
        &'a self,
        host: &'a str,
        method: &'a str,
    ) -> impl Iterator<Item = &'a CredentialBinding> + 'a {
        self.credentials.iter().filter(move |b| {
            b.set_header.is_some() && b.allows_host(host) && b.allows_method(method)
        })
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
        self.credentials
            .iter()
            .filter(|b| !b.environment_variable.is_empty())
            .filter_map(move |b| {
                placeholders
                    .get(&b.name)
                    .map(|p| (b.environment_variable.clone(), p.clone()))
            })
    }
}

/// Whether a credential host pattern (an exact name, or `*.` plus a name for
/// every subdomain of it) matches `host`.
pub fn host_matches(pattern: &str, host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    match pattern.strip_prefix("*.") {
        Some(parent) => host.len() > parent.len() + 1 && host.ends_with(&format!(".{parent}")),
        None => pattern.eq_ignore_ascii_case(&host),
    }
}

/// The DNS subtree a credential host pattern lives in: the name itself, or a
/// wildcard's parent. Used to name-constrain the machine CA and to check the
/// pattern against the network allow-list.
pub fn host_subtree(pattern: &str) -> &str {
    pattern.strip_prefix("*.").unwrap_or(pattern)
}

/// Headers a credential may never be placed in: they steer routing or framing,
/// or (cookies) carry state the credential must not be mixed into.
pub const PROTECTED_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "upgrade",
    "proxy-authorization",
    "proxy-authenticate",
    "proxy-connection",
    "cookie",
];

/// Whether two host patterns can match the same host.
fn patterns_overlap(a: &str, b: &str) -> bool {
    match (a.strip_prefix("*."), b.strip_prefix("*.")) {
        (None, None) => a == b,
        (Some(_), None) => host_matches(a, b),
        (None, Some(_)) => host_matches(b, a),
        (Some(pa), Some(pb)) => {
            pa == pb || pa.ends_with(&format!(".{pb}")) || pb.ends_with(&format!(".{pa}"))
        }
    }
}

/// Whether `host` is admitted by a legacy or opt-in network allow-list entry.
pub fn covered_by_allow_list(host: &str, allowed: &[String]) -> bool {
    match host.strip_prefix("*.") {
        // A wildcard binding reaches every name under its parent, so only an
        // entry admitting that whole subtree covers it; an exact entry never does.
        Some(parent) => allowed.iter().any(|entry| {
            let subtree = entry
                .strip_prefix("*.")
                .or_else(|| (!entry.starts_with('=')).then_some(entry.as_str()));
            subtree.is_some_and(|subtree| crate::host_pattern::matches(parent, subtree))
        }),
        None => allowed
            .iter()
            .any(|pattern| crate::host_pattern::matches(host, pattern)),
    }
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

fn valid_host_pattern(host: &str) -> bool {
    match host.strip_prefix("*.") {
        // `*.com` would cover a whole public suffix.
        Some(parent) => valid_exact_host(parent) && parent.contains('.'),
        None => valid_exact_host(host),
    }
}

fn valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|c| {
            c.is_ascii_lowercase()
                || c.is_ascii_digit()
                || matches!(
                    c,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
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
            set_header: None,
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
            .validate(Some(&["*.notion.com".to_string()]))
            .unwrap();
        policy
            .validate(Some(&["api.notion.com".to_string()]))
            .unwrap();
        assert!(policy.validate(Some(&["=notion.com".to_string()])).is_err());
        let err = policy
            .validate(Some(&["api.github.com".to_string()]))
            .unwrap_err();
        assert!(err.0.contains("network allow_hosts"), "{err}");
    }

    #[test]
    fn a_wildcard_credential_host_needs_its_whole_subtree_allowed() {
        let mut b = notion();
        b.allowed_hosts = vec!["*.notion.com".to_string()];
        let policy = CredentialPolicy {
            credentials: vec![b],
        };
        for allowed in ["notion.com", "*.notion.com", "*.com"] {
            policy.validate(Some(&[allowed.to_string()])).unwrap();
        }
        for allowed in ["=notion.com", "api.notion.com", "*.api.notion.com"] {
            assert!(
                policy.validate(Some(&[allowed.to_string()])).is_err(),
                "{allowed:?} accepted"
            );
        }
    }

    #[test]
    fn rejects_empty_wildcard_and_ip_hosts() {
        for host in [
            "",
            "*.com",
            "*",
            "api.*.com",
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

    fn header_setter(name: &str, header: &str, hosts: &[&str]) -> CredentialBinding {
        CredentialBinding {
            name: name.into(),
            environment_variable: String::new(),
            allowed_hosts: hosts.iter().map(|h| h.to_string()).collect(),
            injection_location: InjectionLocation::default(),
            methods: default_methods(),
            set_header: Some(header.into()),
        }
    }

    #[test]
    fn wildcards_match_subdomains_only() {
        assert!(host_matches("*.github.com", "codeload.github.com"));
        assert!(host_matches("*.github.com", "a.b.github.com"));
        assert!(host_matches("*.github.com", "API.GitHub.com."));
        assert!(!host_matches("*.github.com", "github.com"));
        assert!(!host_matches("*.github.com", "evilgithub.com"));
        assert!(host_matches("github.com", "GitHub.com"));
        assert!(!host_matches("github.com", "api.github.com"));
        let mut b = notion();
        b.allowed_hosts = vec!["*.notion.com".into()];
        let policy = CredentialPolicy {
            credentials: vec![b],
        };
        policy.validate(None).unwrap();
        policy.validate(Some(&["notion.com".to_string()])).unwrap();
        assert!(policy
            .validate(Some(&["api.notion.com".to_string()]))
            .is_err());
    }

    #[test]
    fn a_header_setter_needs_no_variable_and_gets_no_placeholder_env() {
        let policy = CredentialPolicy {
            credentials: vec![
                header_setter("git", "authorization", &["github.com", "*.github.com"]),
                notion(),
            ],
        };
        policy.validate(None).unwrap();
        let placeholders: BTreeMap<String, String> = [
            ("git".to_string(), "SMOL_PLACEHOLDER_GIT_1".to_string()),
            (
                "notion".to_string(),
                "SMOL_PLACEHOLDER_NOTION_2".to_string(),
            ),
        ]
        .into_iter()
        .collect();
        let env: Vec<_> = policy.guest_env(&placeholders).collect();
        assert_eq!(env.len(), 1, "{env:?}");
        assert_eq!(env[0].0, "NOTION_API_KEY");
        let setters: Vec<_> = policy
            .header_bindings("codeload.github.com", "GET")
            .map(|b| b.name.as_str())
            .collect();
        assert_eq!(setters, ["git"]);
        assert_eq!(policy.header_bindings("api.notion.com", "GET").count(), 0);
    }

    #[test]
    fn header_setters_are_refused_for_protected_or_conflicting_headers() {
        for header in [
            "host",
            "cookie",
            "content-length",
            "Authorization",
            "x y",
            "",
        ] {
            let policy = CredentialPolicy {
                credentials: vec![header_setter("a", header, &["api.a.com"])],
            };
            assert!(policy.validate(None).is_err(), "{header:?} accepted");
        }
        let conflicting = CredentialPolicy {
            credentials: vec![
                header_setter("a", "authorization", &["*.github.com"]),
                header_setter("b", "authorization", &["api.github.com"]),
            ],
        };
        assert!(conflicting
            .validate(None)
            .unwrap_err()
            .0
            .contains("same host"));
        let distinct = CredentialPolicy {
            credentials: vec![
                header_setter("a", "authorization", &["api.github.com"]),
                header_setter("b", "authorization", &["api.notion.com"]),
                header_setter("c", "x-api-key", &["api.github.com"]),
            ],
        };
        distinct.validate(None).unwrap();
    }

    #[test]
    fn a_placeholder_binding_still_needs_its_variable() {
        let mut b = notion();
        b.environment_variable.clear();
        let policy = CredentialPolicy {
            credentials: vec![b],
        };
        assert!(policy.validate(None).is_err());
    }
}
