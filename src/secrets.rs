//! Host-side secret *references*.
//!
//! smolvm does not store secret material. A [`SecretRef`] is a pointer to
//! a secret that already lives somewhere on the host — a host environment
//! variable (`from_env`) or a host file (`from_file`) — and resolution
//! reads that source fresh at workload launch, injecting the value into
//! the guest env as part of the existing `env` field in
//! `AgentRequest::Run`/`VmExec` (no protocol change).
//!
//! Bring your own secrets manager: have Vault/1Password/AWS/sops/your
//! shell render the secret into an env var or a file, then reference it.
//! Because resolution is late-bound (per launch), rotating the underlying
//! source takes effect on the next run with nothing to re-sync.
//!
//! # Scope and non-goals
//!
//! This is defense-in-depth, not zero-knowledge. The target guest process
//! sees plaintext in its own environment. Isolation comes from:
//! (a) never persisting resolved plaintext to the VM record / DB / pack,
//! (b) not logging values, (c) scrubbing the immediate resolve buffers.
//!
//! # What Zeroize actually covers here
//!
//! Resolved plaintext lives in a `Zeroizing<String>` from the moment it's
//! read until the resolution helper copies it into the caller-visible env
//! vector; those intermediate buffers scrub on drop. After that copy,
//! plaintext lives in a regular `String` inside a `Vec<(String, String)>`
//! until the outer request is serialized to vsock. We do not attempt to
//! zero that storage — doing so would not change the fundamental property
//! that the guest process's env contains plaintext. If you need true
//! "use without access," use a broker pattern (e.g. SSH agent forwarding).

use crate::error::{Error, Result};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// Maximum number of bytes read when resolving a `from_file` source. A
/// file larger than this is almost never a credential; we refuse rather
/// than silently injecting a huge env var into the workload.
pub const MAX_FROM_FILE_BYTES: u64 = 1024 * 1024;

// The *shape* of a ref lives in `smolvm-protocol` (it's what flows
// across wire / on-disk boundaries). The *policy* — which source kinds
// are allowed at which trust boundary — lives here, alongside the code
// that enforces it at validation and resolution time.
pub use smolvm_protocol::{SecretRef, SecretSourceKind};

// ============================================================================
// File-source reading
// ============================================================================

/// Structured error from bounded-read / file-source helpers so
/// callers can classify without string-matching the inner `io::Error`.
#[derive(Debug)]
enum FileSourceError {
    /// The stored path points at a symlink; we refuse to follow.
    Symlink,
    /// File size exceeded the per-call cap.
    TooLarge,
    /// Any other I/O failure (missing, permission denied, non-UTF-8
    /// content, etc.). The inner error is available for callers that
    /// want to log it; classifiers treat this as `FileReadFailed`.
    Io(std::io::Error),
}

impl std::fmt::Display for FileSourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Symlink => write!(
                f,
                "from_file path is a symlink; refusing to follow \
                 (store the canonicalized target instead)"
            ),
            Self::TooLarge => write!(f, "file size exceeds maximum"),
            Self::Io(e) => write!(f, "{}", e),
        }
    }
}

impl From<std::io::Error> for FileSourceError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Read a file to string while refusing to allocate more than `cap`
/// bytes. The cap is enforced against *bytes actually read*, not against
/// the length reported by `metadata()` — this closes a TOCTOU where the
/// file grows between stat and read.
fn read_file_bounded(
    mut f: std::fs::File,
    cap: u64,
) -> std::result::Result<String, FileSourceError> {
    use std::io::Read;
    let mut buf = String::new();
    // `take` caps the actual read. We request `cap + 1` so an over-cap
    // file fills the reader by one byte, letting us detect the breach.
    (&mut f).take(cap + 1).read_to_string(&mut buf)?;
    if buf.len() as u64 > cap {
        return Err(FileSourceError::TooLarge);
    }
    Ok(buf)
}

/// Read a `from_file` source with both the size cap and a symlink refusal.
///
/// The leaf is opened with `O_NOFOLLOW` so a symlink at the final path
/// component is refused ATOMICALLY at open time — there is no lstat-then-open
/// window where the target could be swapped for a symlink to (e.g.)
/// `/etc/shadow`. We then read from that fd only, never re-opening by path, so
/// the bytes come from exactly what we opened. (Parent-directory symlinks are
/// not covered — that would need a component-by-component `openat` walk.)
fn read_from_file_source(path: &std::path::Path) -> std::result::Result<String, FileSourceError> {
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| {
            // O_NOFOLLOW on a symlink leaf fails with ELOOP — surface it as the
            // dedicated Symlink class rather than a generic I/O error.
            if e.raw_os_error() == Some(libc::ELOOP) {
                FileSourceError::Symlink
            } else {
                FileSourceError::Io(e)
            }
        })?;
    read_file_bounded(f, MAX_FROM_FILE_BYTES)
}

/// Map a [`FileSourceError`] into the resolution-failure taxonomy. No
/// string matching; the classes are structural, so this is a pure enum
/// translation.
fn classify_file_source_error(e: FileSourceError) -> ResolutionFailure {
    match e {
        FileSourceError::TooLarge => ResolutionFailure::FileTooLarge,
        FileSourceError::Symlink | FileSourceError::Io(_) => ResolutionFailure::FileReadFailed,
    }
}

// ============================================================================
// Trust scope and validation
// ============================================================================

/// Trust level of the actor that supplied a [`SecretRef`].
///
/// The smolvm process resolves secrets against its own host. Different
/// input surfaces present refs with different trust; the scope chosen at
/// the validation site determines which source kinds can be honored.
///
/// | Scope | `from_env` | `from_file` |
/// |---|:-:|:-:|
/// | `TrustedLocal` | yes | yes (absolute paths only) |
/// | `RecordReplay` | yes | yes |
/// | `Untrusted` | no | no |
///
/// Both source kinds dereference *this host's* environment / filesystem,
/// so they are only meaningful for a trusted-local actor (the CLI running
/// as the host user) or for refs that actor persisted earlier
/// (`RecordReplay`). An `Untrusted` surface — an HTTP request body or a
/// portable `.smolmachine` pack authored elsewhere — must not be able to
/// read this host's env (`from_env`) or files (`from_file`), so it can
/// carry no resolvable secret at all.
///
/// Callers must call [`validate_ref`] before acting on a ref received
/// from any source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionScope {
    /// Caller is trusted equivalently to the smolvm process itself
    /// (typically: the CLI running as the host user). All source kinds
    /// are accepted; `from_file` still requires an absolute path for
    /// defense-in-depth against CWD-dependent surprises.
    TrustedLocal,

    /// Ref was persisted by a `TrustedLocal` actor in a prior session
    /// (e.g., read back from a VM record). Trust is preserved across time.
    RecordReplay,

    /// Ref came in from an unauthenticated or semi-trusted source: an
    /// HTTP request body, or a portable pack manifest. Neither source
    /// kind is honored — `from_env` would leak the smolvm process's
    /// environment and `from_file` would turn the ref field into an
    /// arbitrary host-file read primitive.
    Untrusted,
}

impl ResolutionScope {
    fn allows_env(self) -> bool {
        !matches!(self, Self::Untrusted)
    }
    fn allows_file(self) -> bool {
        !matches!(self, Self::Untrusted)
    }
}

/// Structural or scope-policy violations rejected by [`validate_ref`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretRefError {
    /// Neither `from_env` nor `from_file` was set.
    NoSource,
    /// More than one source field was set.
    MultipleSources,
    /// `from_file` was given a relative path. Persisted refs must be
    /// absolute to avoid CWD-dependent resolution surprises.
    RelativeFilePath(std::path::PathBuf),
    /// The source kind is valid in general but not in the given scope —
    /// e.g., `from_file` submitted via an untrusted HTTP request body.
    SourceNotAllowedInScope {
        /// Which source kind was attempted.
        kind: SecretSourceKind,
        /// Which scope rejected it.
        scope: ResolutionScope,
    },
}

impl std::fmt::Display for SecretRefError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSource => write!(
                f,
                "no source set: exactly one of from_env, from_file must be specified"
            ),
            Self::MultipleSources => write!(
                f,
                "multiple sources set: exactly one of from_env, from_file must be specified"
            ),
            Self::RelativeFilePath(p) => write!(
                f,
                "from_file path '{}' is relative; absolute paths are required",
                p.display()
            ),
            Self::SourceNotAllowedInScope { kind, scope } => write!(
                f,
                "source kind '{}' is not allowed in scope {:?}; \
                 secret refs may only be resolved on the trusted local host",
                kind.as_str(),
                scope
            ),
        }
    }
}

impl std::error::Error for SecretRefError {}

/// Validate structure and scope policy for a [`SecretRef`].
///
/// Call before persisting or acting on any ref received from an outside
/// source. There are no "partial" refs in this codebase — if it wasn't
/// validated, it shouldn't be stored or resolved.
pub fn validate_ref(
    r: &SecretRef,
    scope: ResolutionScope,
) -> std::result::Result<(), SecretRefError> {
    let count = [r.from_env.is_some(), r.from_file.is_some()]
        .into_iter()
        .filter(|b| *b)
        .count();

    match count {
        0 => return Err(SecretRefError::NoSource),
        1 => {}
        _ => return Err(SecretRefError::MultipleSources),
    }

    if r.from_env.is_some() && !scope.allows_env() {
        return Err(SecretRefError::SourceNotAllowedInScope {
            kind: SecretSourceKind::Env,
            scope,
        });
    }
    if let Some(path) = &r.from_file {
        if !scope.allows_file() {
            return Err(SecretRefError::SourceNotAllowedInScope {
                kind: SecretSourceKind::File,
                scope,
            });
        }
        if !path.is_absolute() {
            return Err(SecretRefError::RelativeFilePath(path.clone()));
        }
    }

    Ok(())
}

// ============================================================================
// Resolution failure taxonomy
// ============================================================================

/// Classified reasons a resolution can fail.
///
/// Distinct from [`SecretRefError`]: `SecretRefError` is a validation
/// failure (the ref itself is malformed or rejected by policy), while
/// [`ResolutionFailure`] happens *after* validation, when we actually
/// try to turn an accepted ref into a value.
///
/// The classification drives two things: audit log records and HTTP
/// status-code mapping for the API (client-side 400 vs. server-side 500).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionFailure {
    /// `from_env` references an env var that isn't set on the host.
    EnvUnset,
    /// `from_file` path is missing, not readable, or not a regular
    /// file. Also covers the "target is a symlink" refusal.
    FileReadFailed,
    /// `from_file` target exceeds the size cap.
    FileTooLarge,
    /// Any other failure: an internal/unexpected condition (e.g. a ref
    /// with no source reaching resolution despite validation).
    Internal,
}

impl ResolutionFailure {
    /// Whether the failure reflects something the caller can fix.
    /// Determines whether the HTTP layer should return 4xx or 5xx.
    pub fn is_client_error(self) -> bool {
        matches!(
            self,
            Self::EnvUnset | Self::FileReadFailed | Self::FileTooLarge
        )
    }

    /// Stable short identifier suitable for logs and public-facing
    /// error payloads. Never includes path, env-var name, or value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EnvUnset => "env_unset",
            Self::FileReadFailed => "file_read_failed",
            Self::FileTooLarge => "file_too_large",
            Self::Internal => "internal",
        }
    }
}

impl std::fmt::Display for ResolutionFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A resolution failure attached to the secret key it happened on.
///
/// API handlers want this form so they can produce a response body
/// that names the bad secret without exposing the underlying error
/// text (which may include paths or env-var names).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionError {
    /// Secret key (the map key in `[secrets]` or `req.secrets`).
    pub key: String,
    /// Classified failure kind.
    pub kind: ResolutionFailure,
}

impl std::fmt::Display for ResolutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "secret '{}': {}", self.key, self.kind)
    }
}

impl std::error::Error for ResolutionError {}

// ============================================================================
// Resolution
// ============================================================================

/// Tracing target for secret-resolution audit records.
///
/// Operators tail this stream with
/// `RUST_LOG=smolvm::secrets::audit=info` to see every resolution event.
/// Records include the secret key, source kind, scope, and outcome —
/// never the resolved value, never the `from_file` path, never the
/// `from_env` variable name (those can themselves be revealing).
pub const AUDIT_TARGET: &str = "smolvm::secrets::audit";

fn scope_label(scope: ResolutionScope) -> &'static str {
    match scope {
        ResolutionScope::TrustedLocal => "trusted-local",
        ResolutionScope::RecordReplay => "record-replay",
        ResolutionScope::Untrusted => "untrusted",
    }
}

/// Resolve a single ref into plaintext and emit an audit record.
///
/// **Caller responsibility:** validate the ref at its trust boundary
/// (`validate_ref(scope)`) before calling this. Resolution assumes the
/// ref has already been accepted by policy; the `scope` argument here
/// is recorded for forensics, not re-checked.
///
/// Every call emits exactly one tracing event at `AUDIT_TARGET`: fields
/// are `secret_key`, `source_kind`, `scope`, and `result` (`ok` |
/// `error`). The full error message is deliberately omitted from the
/// log because it may contain `from_file` paths or `from_env` names.
pub fn resolve_secret_ref_classified(
    name: &str,
    r: &SecretRef,
    scope: ResolutionScope,
) -> std::result::Result<Zeroizing<String>, ResolutionFailure> {
    let kind_str = r.source_kind().map(|k| k.as_str()).unwrap_or("unknown");
    let scope_str = scope_label(scope);

    let result: std::result::Result<Zeroizing<String>, ResolutionFailure> =
        if let Some(env_var) = &r.from_env {
            std::env::var(env_var)
                .map(Zeroizing::new)
                .map_err(|_| ResolutionFailure::EnvUnset)
        } else if let Some(path) = &r.from_file {
            read_from_file_source(path)
                .map(|v| Zeroizing::new(v.trim_end_matches(['\n', '\r']).to_string()))
                .map_err(classify_file_source_error)
        } else {
            // Never reachable if validate_ref was called at the boundary.
            Err(ResolutionFailure::Internal)
        };

    match &result {
        Ok(_) => tracing::info!(
            target: AUDIT_TARGET,
            secret_key = %name,
            source_kind = %kind_str,
            scope = %scope_str,
            result = "ok",
        ),
        Err(f) => tracing::info!(
            target: AUDIT_TARGET,
            secret_key = %name,
            source_kind = %kind_str,
            scope = %scope_str,
            result = "error",
            error_kind = %f.as_str(),
        ),
    }

    result
}

/// Resolve a single ref, returning the project-wide [`Error`] type.
fn resolve_secret_ref(
    name: &str,
    r: &SecretRef,
    scope: ResolutionScope,
) -> Result<Zeroizing<String>> {
    resolve_secret_ref_classified(name, r, scope)
        .map_err(|f| Error::config(format!("resolve secret '{}'", name), f.as_str().to_string()))
}

/// Resolve a map of secret refs and flatten into `(name, value)` pairs
/// ready to append to an agent-bound env vector.
///
/// Returns an empty vec for empty input.
///
/// **No caching.** Every call redoes all resolutions. This is
/// deliberate: rotating the underlying env var / file takes effect at the
/// next resolution with no restart. Do not add a cache here without
/// replacing the rotation semantics with an explicit invalidation path.
///
/// Callers choose the scope based on where the refs came from:
/// `TrustedLocal` for refs a CLI user just supplied, `RecordReplay` for
/// refs read out of a VM record.
pub fn resolve_refs_to_env(
    refs: &BTreeMap<String, SecretRef>,
    scope: ResolutionScope,
) -> Result<Vec<(String, Secret)>> {
    let mut out = Vec::with_capacity(refs.len());
    for (name, r) in refs {
        out.push((name.clone(), Secret(resolve_secret_ref(name, r, scope)?)));
    }
    Ok(out)
}

/// Like [`resolve_refs_to_env`] but surfaces a classified
/// [`ResolutionError`] on the first failure, so API handlers can map
/// failure kinds to HTTP status codes and name the offending secret.
pub fn resolve_refs_to_env_classified(
    refs: &BTreeMap<String, SecretRef>,
    scope: ResolutionScope,
) -> std::result::Result<Vec<(String, Secret)>, ResolutionError> {
    let mut out = Vec::with_capacity(refs.len());
    for (name, r) in refs {
        let value =
            resolve_secret_ref_classified(name, r, scope).map_err(|kind| ResolutionError {
                key: name.clone(),
                kind,
            })?;
        out.push((name.clone(), Secret(value)));
    }
    Ok(out)
}

// ============================================================================
// Resolved secret value
// ============================================================================

/// A resolved secret plaintext value.
///
/// Deliberately has NO `Serialize`, `Display`, or `Deref` impl, and a REDACTING
/// `Debug`, so resolved plaintext cannot leak into logs, error messages, the
/// DB, or a pack by accident — the type system enforces the "plaintext never
/// persists / never logs" invariant. Zeroized on drop. Cross it into the guest
/// env (the one legitimate boundary) only via the explicit, greppable
/// `expose` / `into_plaintext`.
#[derive(Clone)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    /// Borrow the plaintext. Each call site is a reviewable point where a
    /// secret crosses a trust boundary.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Consume into the plaintext `String` for the one place it must go plain:
    /// the agent env vector serialized to the guest over vsock. Moves the inner
    /// buffer out, leaving nothing extra to scrub.
    pub fn into_plaintext(mut self) -> String {
        std::mem::take(&mut *self.0)
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

/// Expose resolved secrets into plain `(name, value)` tuples for the agent env
/// vector. This is THE boundary where secret plaintext deliberately crosses into
/// the guest's environment (serialized over vsock to the guest). Every call site
/// is a greppable point where plaintext leaves the `Secret` type's protection —
/// keep them few and obvious.
pub fn expose_into_env(secrets: Vec<(String, Secret)>) -> Vec<(String, String)> {
    secrets
        .into_iter()
        .map(|(k, v)| (k, v.into_plaintext()))
        .collect()
}

/// Build a `from_env` ref pointing at the named host environment variable.
pub fn env_ref(env_var: impl Into<String>) -> SecretRef {
    SecretRef {
        from_env: Some(env_var.into()),
        from_file: None,
    }
}

/// Build a `from_file` ref pointing at the given host path.
pub fn file_ref(path: impl Into<std::path::PathBuf>) -> SecretRef {
    SecretRef {
        from_env: None,
        from_file: Some(path.into()),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn env_ref_for(name: &str) -> SecretRef {
        env_ref(name)
    }

    fn file_ref_for(path: &Path) -> SecretRef {
        file_ref(path)
    }

    #[test]
    fn secret_debug_redacts_and_exposes_only_explicitly() {
        let s = Secret(Zeroizing::new("hunter2".to_string()));
        let dbg = format!("{:?}", s);
        assert_eq!(dbg, "Secret(<redacted>)");
        assert!(!dbg.contains("hunter2"), "Debug leaked the secret: {}", dbg);
        assert_eq!(s.expose(), "hunter2");
        assert_eq!(s.into_plaintext(), "hunter2");
    }

    #[test]
    fn env_ref_resolves() {
        std::env::set_var("SMOLVM_TEST_SECRET_ENV", "from-env-value");
        let r = env_ref_for("SMOLVM_TEST_SECRET_ENV");
        assert_eq!(
            &*resolve_secret_ref("DST", &r, ResolutionScope::TrustedLocal).unwrap(),
            "from-env-value"
        );
        std::env::remove_var("SMOLVM_TEST_SECRET_ENV");
        assert!(resolve_secret_ref("DST", &r, ResolutionScope::TrustedLocal).is_err());
    }

    #[test]
    fn file_ref_resolves_and_trims_newline() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("cred");
        std::fs::write(&p, "hunter2\n").unwrap();
        let r = file_ref_for(&p);
        assert_eq!(
            &*resolve_secret_ref("FILE_SECRET", &r, ResolutionScope::TrustedLocal).unwrap(),
            "hunter2"
        );
    }

    #[test]
    fn validate_rejects_no_source_and_multiple_sources() {
        let none = SecretRef {
            from_env: None,
            from_file: None,
        };
        assert_eq!(
            validate_ref(&none, ResolutionScope::TrustedLocal),
            Err(SecretRefError::NoSource)
        );
        let both = SecretRef {
            from_env: Some("X".into()),
            from_file: Some("/abs".into()),
        };
        assert_eq!(
            validate_ref(&both, ResolutionScope::TrustedLocal),
            Err(SecretRefError::MultipleSources)
        );
    }

    #[test]
    fn validate_requires_absolute_file_paths() {
        let rel = file_ref_for(Path::new("relative/path"));
        assert!(matches!(
            validate_ref(&rel, ResolutionScope::TrustedLocal),
            Err(SecretRefError::RelativeFilePath(_))
        ));
        let abs = file_ref_for(Path::new("/etc/hostname"));
        assert!(validate_ref(&abs, ResolutionScope::TrustedLocal).is_ok());
    }

    #[test]
    fn untrusted_scope_rejects_every_source_kind() {
        let env = env_ref_for("X");
        assert!(matches!(
            validate_ref(&env, ResolutionScope::Untrusted),
            Err(SecretRefError::SourceNotAllowedInScope {
                kind: SecretSourceKind::Env,
                ..
            })
        ));
        let file = file_ref_for(Path::new("/etc/hostname"));
        assert!(matches!(
            validate_ref(&file, ResolutionScope::Untrusted),
            Err(SecretRefError::SourceNotAllowedInScope {
                kind: SecretSourceKind::File,
                ..
            })
        ));
    }

    #[test]
    fn record_replay_allows_env_and_file() {
        let env = env_ref_for("X");
        assert!(validate_ref(&env, ResolutionScope::RecordReplay).is_ok());
        let file = file_ref_for(Path::new("/etc/hostname"));
        assert!(validate_ref(&file, ResolutionScope::RecordReplay).is_ok());
    }

    #[test]
    fn resolution_failure_client_vs_server_classification() {
        assert!(ResolutionFailure::EnvUnset.is_client_error());
        assert!(ResolutionFailure::FileReadFailed.is_client_error());
        assert!(ResolutionFailure::FileTooLarge.is_client_error());
        assert!(!ResolutionFailure::Internal.is_client_error());
    }

    #[test]
    fn resolve_refs_to_env_classified_names_failing_key() {
        let mut refs = BTreeMap::new();
        refs.insert(
            "MISSING".to_string(),
            env_ref_for("SMOLVM_TEST_DEFINITELY_UNSET"),
        );
        std::env::remove_var("SMOLVM_TEST_DEFINITELY_UNSET");
        let err = resolve_refs_to_env_classified(&refs, ResolutionScope::TrustedLocal).unwrap_err();
        assert_eq!(err.key, "MISSING");
        assert_eq!(err.kind, ResolutionFailure::EnvUnset);
    }

    #[test]
    fn empty_refs_resolve_to_empty_vec() {
        let refs = BTreeMap::new();
        assert!(resolve_refs_to_env(&refs, ResolutionScope::TrustedLocal)
            .unwrap()
            .is_empty());
    }
}
