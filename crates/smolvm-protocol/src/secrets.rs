//! Secret reference types shared across smolvm surfaces.
//!
//! A [`SecretRef`] is a *pointer* to a secret. Refs travel across trust
//! boundaries (HTTP request bodies, persisted VM records, `.smolmachine`
//! pack manifests); resolved plaintext values do not.
//!
//! This crate carries only the *shape* of a ref — the on-the-wire and
//! on-disk representation plus trivial introspection. The validation
//! policy (which source kinds are allowed at which trust boundary)
//! lives in the host crate alongside the code that enforces it. See
//! `smolvm::secrets` for `ResolutionScope` and `validate_ref`.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Which source a [`SecretRef`] points at, independent of the data
/// inside. Used by audit logging so the logger never sees the path or
/// env-var name (which can themselves be revealing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretSourceKind {
    /// The ref points at an entry in the host secret store.
    Store,
    /// The ref points at a host environment variable.
    Env,
    /// The ref points at a host file path.
    File,
}

impl SecretSourceKind {
    /// Human-readable label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Store => "store",
            Self::Env => "env",
            Self::File => "file",
        }
    }
}

/// A reference to a secret. Exactly one of the three sources must be
/// populated; validation is performed by the host crate's
/// `validate_ref` (policy lives where it's enforced).
///
/// Round-trips through `serde_json` for persistence in the VM record DB
/// and in `.smolmachine` pack manifests. Refs are not sensitive; the
/// resolved plaintext is produced only at the workload launch site and
/// never touches any of these stores.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretRef {
    /// Look up the secret by name in the host secret store.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_store: Option<String>,

    /// Read the secret from a host environment variable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_env: Option<String>,

    /// Read the secret from a host file path (must be absolute).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_file: Option<PathBuf>,
}

impl SecretRef {
    /// Return the source kind for this ref, if exactly one source is set.
    ///
    /// Returns `None` for structurally invalid refs (0 or >1 sources).
    /// Callers are expected to have already validated with the host
    /// crate's `validate_ref` before calling this; this function is
    /// primarily for audit logging of a known-good ref.
    pub fn source_kind(&self) -> Option<SecretSourceKind> {
        match (
            self.from_store.is_some(),
            self.from_env.is_some(),
            self.from_file.is_some(),
        ) {
            (true, false, false) => Some(SecretSourceKind::Store),
            (false, true, false) => Some(SecretSourceKind::Env),
            (false, false, true) => Some(SecretSourceKind::File),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_kind_reports_variant() {
        assert_eq!(
            SecretRef {
                from_store: Some("x".into()),
                from_env: None,
                from_file: None,
            }
            .source_kind(),
            Some(SecretSourceKind::Store)
        );
        assert_eq!(
            SecretRef {
                from_store: None,
                from_env: Some("Y".into()),
                from_file: None,
            }
            .source_kind(),
            Some(SecretSourceKind::Env)
        );
        assert_eq!(
            SecretRef {
                from_store: None,
                from_env: None,
                from_file: Some(PathBuf::from("/z")),
            }
            .source_kind(),
            Some(SecretSourceKind::File)
        );
        let empty = SecretRef {
            from_store: None,
            from_env: None,
            from_file: None,
        };
        assert_eq!(empty.source_kind(), None);
    }

    #[test]
    fn deny_unknown_fields() {
        let bad = r#"{ "from_stor": "typo" }"#;
        let res: Result<SecretRef, _> = serde_json::from_str(bad);
        assert!(res.is_err());
    }

    #[test]
    fn roundtrip_json() {
        let r = SecretRef {
            from_store: Some("API_KEY".into()),
            from_env: None,
            from_file: None,
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: SecretRef = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn serialization_omits_empty_fields() {
        let r = SecretRef {
            from_store: Some("X".into()),
            from_env: None,
            from_file: None,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("from_store"));
        assert!(!json.contains("from_env"));
        assert!(!json.contains("from_file"));
    }
}
