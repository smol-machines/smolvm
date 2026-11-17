//! Credential resolution.
//!
//! The interceptor never stores a credential. Every substituted request asks
//! the resolver for the current value of a binding, given who is asking and
//! where the request is going, so an embedder can pin a binding to its own
//! secret store per machine, enforce its own destination rules, and rotate or
//! revoke without touching the machine.

use std::collections::BTreeMap;
use std::fmt;
use zeroize::Zeroizing;

/// One resolution request.
#[derive(Clone, Debug)]
pub struct CredentialRequest {
    /// Machine (or clone) the request originates from. Each fork clone is a
    /// distinct identity so a resolver can revoke one branch without the rest.
    pub machine: String,
    /// Binding name from the policy.
    pub binding: String,
    /// Destination host, already checked against the binding's `allowed_hosts`.
    pub host: String,
    pub port: u16,
    pub method: String,
    /// Request path and query.
    pub path: String,
}

/// Why a binding could not be resolved. Reported to the guest only as a
/// generic failure; the detail stays in host logs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolveError {
    /// The resolver knows no such binding for this machine.
    Unknown,
    /// The resolver refused this destination or operation.
    Denied,
    /// The backing store could not be read right now.
    Unavailable(String),
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => write!(f, "unknown credential binding"),
            Self::Denied => write!(f, "credential use denied"),
            Self::Unavailable(why) => write!(f, "credential unavailable: {why}"),
        }
    }
}

impl std::error::Error for ResolveError {}

/// Source of credential values.
///
/// Implementations are called from the interceptor's runtime on a blocking
/// thread, so short synchronous reads (files, environment, a local keychain)
/// are fine. Return the raw value without any `Bearer ` or similar prefix;
/// the guest supplies surrounding syntax and only the placeholder is replaced.
pub trait CredentialResolver: Send + Sync + 'static {
    fn resolve(&self, request: &CredentialRequest) -> Result<Zeroizing<String>, ResolveError>;
}

/// Fixed in-memory values, keyed by binding name. For tests and embedders that
/// resolve ahead of time.
#[derive(Default)]
pub struct StaticResolver {
    values: BTreeMap<String, Zeroizing<String>>,
}

impl StaticResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, binding: impl Into<String>, value: impl Into<String>) -> Self {
        self.values
            .insert(binding.into(), Zeroizing::new(value.into()));
        self
    }
}

impl CredentialResolver for StaticResolver {
    fn resolve(&self, request: &CredentialRequest) -> Result<Zeroizing<String>, ResolveError> {
        self.values
            .get(&request.binding)
            .cloned()
            .ok_or(ResolveError::Unknown)
    }
}
