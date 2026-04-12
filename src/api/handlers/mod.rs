//! HTTP request handlers.

pub mod exec;
pub mod files;
pub mod health;
pub mod images;
pub mod machines;

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
) -> Result<Vec<(String, String)>, ApiError> {
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
/// Client-fixable failures (`StoreMiss`, `EnvUnset`, `FileReadFailed`,
/// `FileTooLarge`) → 400; server-state failures (`CryptoFailed`,
/// `Internal`) → 500. Body always includes the secret key and the
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
/// - the untrusted-source ref policy (`from_store` only).
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

/// Resolve request-body `req.secrets` under `Untrusted` scope. Caller
/// must have already called [`validate_request_secrets`].
pub(crate) fn resolve_request_secrets(
    refs: &std::collections::BTreeMap<String, smolvm_protocol::SecretRef>,
) -> Result<Vec<(String, String)>, ApiError> {
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

    fn store_ref(name: &str) -> SecretRef {
        SecretRef {
            from_store: Some(name.to_string()),
            from_env: None,
            from_file: None,
        }
    }

    #[test]
    fn validate_request_secrets_accepts_store_refs() {
        let mut refs = BTreeMap::new();
        refs.insert("API_KEY".to_string(), store_ref("API_KEY"));
        assert!(validate_request_secrets(&refs).is_ok());
    }

    #[test]
    fn validate_request_secrets_rejects_from_env() {
        let mut refs = BTreeMap::new();
        refs.insert(
            "X".to_string(),
            SecretRef {
                from_store: None,
                from_env: Some("HOST_VAR".to_string()),
                from_file: None,
            },
        );
        let err = validate_request_secrets(&refs).unwrap_err();
        match err {
            ApiError::BadRequest(msg) => {
                assert!(msg.contains("X"), "body must name the bad key: {}", msg);
                assert!(
                    msg.contains("from_store") || msg.contains("env"),
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
                from_store: None,
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
            refs.insert(bad.to_string(), store_ref("K"));
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
        refs.insert(huge_key, store_ref("K"));
        let err = validate_request_secrets(&refs).unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn validate_request_secrets_accepts_valid_keys() {
        let ok_keys = ["FOO", "foo", "_FOO", "_", "FOO_BAR_123", "x1"];
        for ok in ok_keys {
            let mut refs = BTreeMap::new();
            refs.insert(ok.to_string(), store_ref("K"));
            validate_request_secrets(&refs)
                .unwrap_or_else(|e| panic!("key '{}' rejected: {:?}", ok, e));
        }
    }

    #[test]
    fn validate_request_secrets_enforces_size_cap() {
        let mut refs = BTreeMap::new();
        for i in 0..=MAX_REQ_SECRETS_PER_REQUEST {
            refs.insert(format!("K{}", i), store_ref(&format!("K{}", i)));
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
            kind: ResolutionFailure::StoreMiss,
        };
        match classify_resolution_error(e) {
            ApiError::BadRequest(body) => {
                assert!(body.contains("MY_KEY"));
                assert!(body.contains("store_miss"));
            }
            other => panic!("StoreMiss must be 4xx, got {:?}", other),
        }

        let e = ResolutionError {
            key: "MY_KEY".to_string(),
            kind: ResolutionFailure::CryptoFailed,
        };
        // CryptoFailed is a server-state issue → 5xx. We can't easily
        // pattern-match ApiError's internal variant name, but we can
        // verify it's not a client error.
        let mapped = classify_resolution_error(e);
        assert!(
            !matches!(mapped, ApiError::BadRequest(_)),
            "CryptoFailed must not map to 4xx: {:?}",
            mapped
        );
    }
}
