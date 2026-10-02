//! Persist challenge-exchanged bearer tokens across processes.
//!
//! The in-memory token cache dies with the process, and the CLI is a fresh
//! process per command, so every `machine run` paid the full challenge
//! exchange again: a 401 to discover the challenge, a token-service round
//! trip, then the real request. For Docker Hub that is three TLS connections
//! before any work. Persisting the token with its challenge lets a cold
//! process attach a preemptive bearer and go straight to the real request.
//!
//! Scope and safety:
//! - only pull-scoped tokens are persisted; anything whose scope mentions
//!   `push` stays in memory only;
//! - the file name is a hash of the registry, challenge, scope, and an identity
//!   fingerprint (a hash of the credentials in use, or `anonymous`), so one
//!   identity can never pick up another's token, and no credential material
//!   itself is written, only the short-lived token the registry minted;
//! - entries live under the user cache directory with 0600 permissions in a
//!   0700 directory, carry the server-reported expiry, and stale files are
//!   pruned opportunistically;
//! - everything is best-effort: any IO or parse failure means a normal
//!   challenge exchange, never a failed request. `SMOLVM_REGISTRY_TOKEN_CACHE=0`
//!   turns persistence off.

use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// One persisted token: the challenge it answers and when it stops being valid.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct PersistedToken {
    pub realm: String,
    pub service: Option<String>,
    pub scope: Option<String>,
    pub token: String,
    /// Unix seconds. Entries without a server-reported expiry are not
    /// persisted at all: "valid forever" is not a claim worth writing to disk.
    pub expires_at_unix: u64,
}

impl PersistedToken {
    /// Remaining validity as an [`Instant`], applying the same 30 second
    /// buffer the in-memory cache uses. `None` when already stale.
    pub(crate) fn expires_at_instant(&self) -> Option<Instant> {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_secs();
        let remaining = self.expires_at_unix.checked_sub(now_unix)?;
        if remaining <= 30 {
            return None;
        }
        Some(Instant::now() + Duration::from_secs(remaining))
    }
}

/// Whether persistence is enabled (default on, `SMOLVM_REGISTRY_TOKEN_CACHE=0`
/// disables).
pub(crate) fn enabled() -> bool {
    !std::env::var("SMOLVM_REGISTRY_TOKEN_CACHE").is_ok_and(|v| v.trim() == "0")
}

fn store_dir() -> Option<PathBuf> {
    Some(dirs::cache_dir()?.join("smolvm").join("registry-tokens"))
}

/// The file holding the token for this registry, challenge, scope, and
/// identity. Scope is part of the name so tokens for different repositories
/// coexist instead of overwriting each other.
fn entry_path(
    base_url: &str,
    realm: &str,
    scope: Option<&str>,
    identity_fingerprint: &str,
) -> Option<PathBuf> {
    let mut hasher = Sha256::new();
    hasher.update(base_url.as_bytes());
    hasher.update([0]);
    hasher.update(realm.as_bytes());
    hasher.update([0]);
    hasher.update(scope.unwrap_or("").as_bytes());
    hasher.update([0]);
    hasher.update(identity_fingerprint.as_bytes());
    let name = format!("{:x}.json", hasher.finalize());
    Some(store_dir()?.join(name))
}

/// Best-effort write. Pull scopes only; the caller has already checked that.
pub(crate) fn save(base_url: &str, identity_fingerprint: &str, entry: &PersistedToken) {
    let Some(path) = entry_path(
        base_url,
        &entry.realm,
        entry.scope.as_deref(),
        identity_fingerprint,
    ) else {
        return;
    };
    let Some(dir) = path.parent() else { return };
    let _ = std::fs::create_dir_all(dir);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    let Ok(body) = serde_json::to_vec(entry) else {
        return;
    };
    let tmp = path.with_extension("tmp");
    if std::fs::write(&tmp, body).is_ok() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        let _ = std::fs::rename(&tmp, &path);
    }
    prune_stale();
}

/// A cold process does not know the realm before any challenge. Return the
/// newest still-valid entry for this registry and identity regardless of
/// realm, so the first request can already carry a bearer.
pub(crate) fn load_any(base_url: &str, identity_fingerprint: &str) -> Option<PersistedToken> {
    let dir = store_dir()?;
    let mut best: Option<PersistedToken> = None;
    for item in std::fs::read_dir(dir).ok()? {
        let Ok(item) = item else { continue };
        let Ok(body) = std::fs::read(item.path()) else {
            continue;
        };
        let Ok(entry) = serde_json::from_slice::<PersistedToken>(&body) else {
            continue;
        };
        // The filename binds registry + scope + identity; recompute to match.
        if entry_path(
            base_url,
            &entry.realm,
            entry.scope.as_deref(),
            identity_fingerprint,
        )
        .as_deref()
            != Some(item.path().as_path())
        {
            continue;
        }
        if entry.expires_at_instant().is_none() {
            continue;
        }
        if best
            .as_ref()
            .is_none_or(|b| entry.expires_at_unix > b.expires_at_unix)
        {
            best = Some(entry);
        }
    }
    best
}

/// Drop expired files so the directory never grows without bound. Tokens are
/// minutes-lived, so this keeps the store at a handful of entries.
fn prune_stale() {
    let Some(dir) = store_dir() else { return };
    let Ok(items) = std::fs::read_dir(dir) else {
        return;
    };
    for item in items.flatten() {
        let path = item.path();
        let stale = std::fs::read(&path)
            .ok()
            .and_then(|body| serde_json::from_slice::<PersistedToken>(&body).ok())
            .is_none_or(|entry| entry.expires_at_instant().is_none());
        if stale {
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// A stable, non-reversible fingerprint of the credentials a client uses, so
/// cache entries are private to one identity. Never the credentials themselves.
pub(crate) fn identity_fingerprint(
    auth_token: Option<&str>,
    identity_token: Option<&str>,
    basic: Option<&(String, String)>,
) -> String {
    let mut hasher = Sha256::new();
    match (auth_token, identity_token, basic) {
        (Some(t), _, _) => {
            hasher.update(b"auth:");
            hasher.update(t.as_bytes());
        }
        (_, Some(t), _) => {
            hasher.update(b"identity:");
            hasher.update(t.as_bytes());
        }
        (_, _, Some((user, pass))) => {
            hasher.update(b"basic:");
            hasher.update(user.as_bytes());
            hasher.update([0]);
            hasher.update(pass.as_bytes());
        }
        _ => hasher.update(b"anonymous"),
    }
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(realm: &str, expires_in: u64) -> PersistedToken {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        PersistedToken {
            realm: realm.to_string(),
            service: Some("registry.docker.io".into()),
            scope: Some("repository:library/alpine:pull".into()),
            token: "tok".into(),
            expires_at_unix: now + expires_in,
        }
    }

    #[test]
    fn expiry_applies_the_thirty_second_buffer() {
        assert!(entry("r", 300).expires_at_instant().is_some());
        // 20 s left is inside the buffer, so it counts as stale.
        assert!(entry("r", 20).expires_at_instant().is_none());
    }

    #[test]
    fn identities_never_share_a_path() {
        let anon = identity_fingerprint(None, None, None);
        let basic = ("user".to_string(), "pass".to_string());
        let user = identity_fingerprint(None, None, Some(&basic));
        assert_ne!(anon, user);
        assert_ne!(
            entry_path("https://registry-1.docker.io", "r", None, &anon),
            entry_path("https://registry-1.docker.io", "r", None, &user)
        );
    }

    #[test]
    fn scopes_never_share_a_path() {
        let anon = identity_fingerprint(None, None, None);
        assert_ne!(
            entry_path(
                "https://registry-1.docker.io",
                "r",
                Some("repository:library/alpine:pull"),
                &anon
            ),
            entry_path(
                "https://registry-1.docker.io",
                "r",
                Some("repository:library/busybox:pull"),
                &anon
            )
        );
    }
}
