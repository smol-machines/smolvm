//! HTTP request handlers.

pub mod exec;
pub mod files;
pub mod health;
pub mod images;
pub mod machines;
pub mod node;
pub mod p2p;
pub mod volumes;

use crate::api::error::ApiError;
use crate::api::state::MachineEntry;
use crate::secrets::ResolutionError;

/// Maximum number of ad-hoc secret refs in a single API request body.
/// Bounds the per-request resolution work and blocks trivial DOS
/// attempts that flood `secrets: {...}` with thousands of entries.
pub(crate) const MAX_REQ_SECRETS_PER_REQUEST: usize = 64;

/// Resolve a [`MachineEntry`]'s persisted `secret_refs` under
/// `RecordReplay` scope. In-memory access — no DB hit per request.
///
/// Returns the resolved `(key, value)` tuples ready to extend into an
/// env vector. Failures map to structured [`ApiError`]s via
/// [`classify_resolution_error`] so HTTP status codes are consistent
/// across exec/run handlers.
pub(crate) fn record_secret_refs_env(
    entry: &std::sync::Arc<parking_lot::Mutex<MachineEntry>>,
) -> Result<Vec<(String, crate::secrets::Secret)>, ApiError> {
    let refs = {
        let guard = entry.lock();
        guard.secret_refs.clone()
    };
    if refs.is_empty() {
        return Ok(Vec::new());
    }
    crate::secrets::resolve_refs_to_env_classified(
        &refs,
        crate::secrets::ResolutionScope::RecordReplay,
    )
    .map_err(classify_resolution_error)
}

/// Map a classified [`ResolutionError`] to an [`ApiError`] per the
/// status-code table in `docs/secrets-api-pack-plan.md` §4.3.
///
/// Client-fixable failures (`EnvUnset`, `FileReadFailed`,
/// `FileTooLarge`) → 400; server-state failures (`Internal`) → 500.
/// Body always includes the secret key and the
/// failure class, never the raw error message (which may include the
/// `from_file` path or `from_env` variable name).
pub(crate) fn classify_resolution_error(e: ResolutionError) -> ApiError {
    let ResolutionError { key, kind } = e;
    let body = format!("secret '{}': {}", key, kind.as_str());
    if kind.is_client_error() {
        ApiError::BadRequest(body)
    } else {
        ApiError::internal(body)
    }
}

/// Maximum length of a secret key (guest-side env var name).
///
/// Aligned with the agent's env-var validation so API and agent agree.
pub(crate) const MAX_SECRET_KEY_LEN: usize = 256;

/// Check that a request-supplied secret key is a valid POSIX-style env
/// var name. This is the same rule the agent applies to the final env
/// list; enforcing it at API ingress converts a deep-in-agent confused
/// error into a clear 400 at the boundary.
///
/// Rules:
/// - non-empty
/// - ≤ `MAX_SECRET_KEY_LEN` bytes
/// - first char is ASCII letter or `_`
/// - all chars are ASCII alphanumeric or `_`
fn check_env_key_shape(key: &str) -> Result<(), String> {
    if key.is_empty() {
        return Err("env key must not be empty".into());
    }
    if key.len() > MAX_SECRET_KEY_LEN {
        return Err(format!("env key exceeds {}-byte limit", MAX_SECRET_KEY_LEN));
    }
    let first = key.chars().next().expect("non-empty");
    if !first.is_ascii_alphabetic() && first != '_' {
        return Err("env key must start with an ASCII letter or underscore".into());
    }
    if !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err("env key must contain only ASCII alphanumeric and underscore".into());
    }
    Ok(())
}

/// Validate an incoming `req.secrets` map against:
///
/// - the per-request size cap (`MAX_REQ_SECRETS_PER_REQUEST`),
/// - the POSIX env-var key rule for the map key, and
/// - the untrusted-source ref policy: an HTTP caller is `Untrusted`, and
///   no ref source kind (`from_env`/`from_file`) is resolvable in that
///   scope, so any non-empty `secrets` map is rejected. Secrets must be
///   configured locally via the CLI instead.
///
/// On failure, produces a `BadRequest` response body naming the
/// specific key and rule. Used by exec/run/create handlers before
/// resolution is attempted.
pub(crate) fn validate_request_secrets(
    refs: &std::collections::BTreeMap<String, smolvm_protocol::SecretRef>,
) -> Result<(), ApiError> {
    if refs.len() > MAX_REQ_SECRETS_PER_REQUEST {
        return Err(ApiError::BadRequest(format!(
            "request `secrets` map has {} entries; maximum is {}",
            refs.len(),
            MAX_REQ_SECRETS_PER_REQUEST
        )));
    }
    for (name, r) in refs {
        // Validate the *key* before the ref. A malformed key can't
        // safely be included in an error message back to the caller
        // (could contain control chars or huge strings), so we only
        // echo its byte length when it's malformed.
        check_env_key_shape(name).map_err(|rule| {
            ApiError::BadRequest(format!(
                "secrets entry with {}-byte key rejected: {}",
                name.len(),
                rule
            ))
        })?;
        crate::secrets::validate_ref(r, crate::secrets::ResolutionScope::Untrusted)
            .map_err(|e| ApiError::BadRequest(format!("secret '{}': {}", name, e)))?;
    }
    Ok(())
}

/// Validate per-fork `secrets` refs. Unlike [`validate_request_secrets`]
/// (`Untrusted`), fork secrets are operator-declared and become the clone's
/// *persisted* `secret_refs` — the same trust as a Smolfile's `[secrets]` — so
/// they resolve under `TrustedLocal` (host env / absolute file allowed). The
/// key-shape and count caps are identical. NOTE: the cloud control plane must
/// not forward tenant-controlled refs to a shared node's fork endpoint (that
/// would resolve against the node's env/files); cloud delivery is a later phase.
pub(crate) fn validate_fork_secrets(
    refs: &std::collections::BTreeMap<String, smolvm_protocol::SecretRef>,
) -> Result<(), ApiError> {
    if refs.len() > MAX_REQ_SECRETS_PER_REQUEST {
        return Err(ApiError::BadRequest(format!(
            "fork `secrets` map has {} entries; maximum is {}",
            refs.len(),
            MAX_REQ_SECRETS_PER_REQUEST
        )));
    }
    for (name, r) in refs {
        check_env_key_shape(name).map_err(|rule| {
            ApiError::BadRequest(format!(
                "fork secrets entry with {}-byte key rejected: {}",
                name.len(),
                rule
            ))
        })?;
        crate::secrets::validate_ref(r, crate::secrets::ResolutionScope::TrustedLocal)
            .map_err(|e| ApiError::BadRequest(format!("fork secret '{}': {}", name, e)))?;
    }
    Ok(())
}

/// Validate caller-supplied env var *names* with the same shape rule as secret
/// keys ([`check_env_key_shape`]). Env *values* stay unrestricted, but a name is
/// materialized into the guest environment verbatim, so one carrying `=`, a
/// control character, or a newline could inject or corrupt a second variable in
/// anything that parses the environment line-by-line. As with secret keys, a
/// malformed name is not echoed back (only its byte length) since it may hold
/// control characters. Used by the exec/run/create handlers on `req.env`.
pub(crate) fn validate_request_env(env: &[crate::api::types::EnvVar]) -> Result<(), ApiError> {
    for var in env {
        check_env_key_shape(&var.name).map_err(|rule| {
            ApiError::BadRequest(format!(
                "env entry with {}-byte name rejected: {}",
                var.name.len(),
                rule
            ))
        })?;
    }
    Ok(())
}

/// Resolve request-body `req.secrets` under `Untrusted` scope. Caller
/// must have already called [`validate_request_secrets`].
pub(crate) fn resolve_request_secrets(
    refs: &std::collections::BTreeMap<String, smolvm_protocol::SecretRef>,
) -> Result<Vec<(String, crate::secrets::Secret)>, ApiError> {
    if refs.is_empty() {
        return Ok(Vec::new());
    }
    // `Untrusted` here is defense-in-depth — validate_request_secrets
    // has already enforced allowed source kinds and size caps.
    // resolve_refs_to_env_classified maps failures to ResolutionError
    // which we then map to structured ApiError via the status-code
    // table above.
    //
    // Note: we deliberately pass the ref map through twice (validate
    // then resolve) instead of doing one combined pass, so validation
    // failures are distinguishable in the audit log from resolution
    // failures — the first emits a `SecretRefError` trail via the
    // handler's own logs, the second emits `secrets::audit` records
    // with classified `error_kind`.
    crate::secrets::resolve_refs_to_env_classified(refs, crate::secrets::ResolutionScope::Untrusted)
        .map_err(classify_resolution_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use smolvm_protocol::SecretRef;
    use std::collections::BTreeMap;

    fn env_ref(name: &str) -> SecretRef {
        SecretRef {
            from_env: Some(name.to_string()),
            from_file: None,
        }
    }

    #[test]
    fn validate_request_env_rejects_malformed_names() {
        use crate::api::types::EnvVar;
        let ev = |name: &str| EnvVar {
            name: name.to_string(),
            value: "v".to_string(),
        };
        // Well-formed names pass; values are never inspected.
        assert!(validate_request_env(&[ev("FOO"), ev("_BAR2")]).is_ok());
        assert!(validate_request_env(&[]).is_ok());
        // Injection/corruption-prone names are rejected.
        for bad in ["", "HAS=EQ", "HAS SPACE", "HAS\nNL", "1LEADINGDIGIT"] {
            assert!(
                validate_request_env(&[ev(bad)]).is_err(),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn validate_request_secrets_accepts_empty_map() {
        // The HTTP API can no longer carry resolvable secret refs (an
        // untrusted caller must not read this host's env/files), so the
        // only request that passes secret validation is one with none.
        let refs = BTreeMap::new();
        assert!(validate_request_secrets(&refs).is_ok());
    }

    #[test]
    fn validate_fork_secrets_accepts_host_refs_but_rejects_bad_shape() {
        // Fork secrets are operator-declared (TrustedLocal), so unlike the
        // untrusted request path they MAY resolve from host env/absolute files —
        // they become the clone's persisted secret_refs.
        let mut refs = BTreeMap::new();
        refs.insert("GUEST_TOKEN".to_string(), env_ref("HOST_TOKEN"));
        refs.insert(
            "GUEST_KEY".to_string(),
            SecretRef {
                from_env: None,
                from_file: Some("/abs/key".into()),
            },
        );
        assert!(
            validate_fork_secrets(&refs).is_ok(),
            "host refs must be allowed for fork"
        );

        // Empty is fine (the common case).
        assert!(validate_fork_secrets(&BTreeMap::new()).is_ok());

        // A malformed key is still rejected at ingress.
        let mut bad = BTreeMap::new();
        bad.insert("HAS=EQ".to_string(), env_ref("HOST"));
        assert!(matches!(
            validate_fork_secrets(&bad),
            Err(ApiError::BadRequest(_))
        ));

        // A relative file path is rejected (validate_ref TrustedLocal).
        let mut rel = BTreeMap::new();
        rel.insert(
            "K".to_string(),
            SecretRef {
                from_env: None,
                from_file: Some("relative/path".into()),
            },
        );
        assert!(matches!(
            validate_fork_secrets(&rel),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn validate_request_secrets_rejects_from_env() {
        let mut refs = BTreeMap::new();
        refs.insert("X".to_string(), env_ref("HOST_VAR"));
        let err = validate_request_secrets(&refs).unwrap_err();
        match err {
            ApiError::BadRequest(msg) => {
                assert!(msg.contains("X"), "body must name the bad key: {}", msg);
                assert!(
                    msg.contains("env") || msg.contains("trusted local host"),
                    "body must explain rule: {}",
                    msg
                );
            }
            other => panic!("expected BadRequest, got {:?}", other),
        }
    }

    #[test]
    fn validate_request_secrets_rejects_from_file() {
        let mut refs = BTreeMap::new();
        refs.insert(
            "X".to_string(),
            SecretRef {
                from_env: None,
                from_file: Some("/absolute/path".into()),
            },
        );
        let err = validate_request_secrets(&refs).unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn validate_request_secrets_rejects_bad_keys() {
        // Every failing key shape should be rejected at ingress with a
        // BadRequest, never allowed through to the agent where it would
        // become an opaque error.
        let bad_keys = [
            "",         // empty
            "1FOO",     // leading digit
            "FOO BAR",  // space
            "FOO=BAR",  // equals sign
            "FOO-BAR",  // hyphen
            "FOO.BAR",  // dot
            "FOO\0BAR", // NUL
            "FOO\nBAR", // control char
            "ünicöde",  // non-ASCII
        ];
        for bad in bad_keys {
            let mut refs = BTreeMap::new();
            refs.insert(bad.to_string(), env_ref("K"));
            let err = validate_request_secrets(&refs)
                .expect_err(&format!("key '{}' must be rejected", bad.escape_default()));
            assert!(
                matches!(err, ApiError::BadRequest(_)),
                "key '{}' should be 400, got {:?}",
                bad.escape_default(),
                err
            );
        }
    }

    #[test]
    fn validate_request_secrets_rejects_oversized_keys() {
        let huge_key = "A".repeat(MAX_SECRET_KEY_LEN + 1);
        let mut refs = BTreeMap::new();
        refs.insert(huge_key, env_ref("K"));
        let err = validate_request_secrets(&refs).unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn validate_request_secrets_enforces_size_cap() {
        let mut refs = BTreeMap::new();
        for i in 0..=MAX_REQ_SECRETS_PER_REQUEST {
            refs.insert(format!("K{}", i), env_ref(&format!("K{}", i)));
        }
        let err = validate_request_secrets(&refs).unwrap_err();
        match err {
            ApiError::BadRequest(msg) => {
                assert!(msg.contains(&MAX_REQ_SECRETS_PER_REQUEST.to_string()));
            }
            other => panic!("expected BadRequest, got {:?}", other),
        }
    }

    #[test]
    fn classify_resolution_error_maps_to_status() {
        use crate::secrets::{ResolutionError, ResolutionFailure};

        let e = ResolutionError {
            key: "MY_KEY".to_string(),
            kind: ResolutionFailure::EnvUnset,
        };
        match classify_resolution_error(e) {
            ApiError::BadRequest(body) => {
                assert!(body.contains("MY_KEY"));
                assert!(body.contains("env_unset"));
            }
            other => panic!("EnvUnset must be 4xx, got {:?}", other),
        }

        let e = ResolutionError {
            key: "MY_KEY".to_string(),
            kind: ResolutionFailure::Internal,
        };
        // Internal is a server-state issue → 5xx. We can't easily
        // pattern-match ApiError's internal variant name, but we can
        // verify it's not a client error.
        let mapped = classify_resolution_error(e);
        assert!(
            !matches!(mapped, ApiError::BadRequest(_)),
            "Internal must not map to 4xx: {:?}",
            mapped
        );
    }
}
