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
//!   challenge exchange, never a failed request.

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
        let now_unix = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        let remaining = self.expires_at_unix.checked_sub(now_unix)?;
        if remaining <= 30 {
            return None;
        }
        Some(Instant::now() + Duration::from_secs(remaining))
    }
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

/// True when every action in an OCI auth scope is `pull`. Scopes look like
/// `repository:library/alpine:pull`, several can be space separated, and the
/// action list is comma separated. Anything else (`push`, `delete`, `*`, an
/// unparsable part) is not pull only. Resource names may themselves contain
/// colons (`repository:host:5000/foo:pull`), so the actions are whatever
/// follows the last colon.
pub(crate) fn scope_is_pull_only(scope: &str) -> bool {
    let mut parts = scope.split_whitespace().peekable();
    parts.peek().is_some()
        && parts.all(|part| {
            part.rsplit_once(':').is_some_and(|(_, actions)| {
                !actions.is_empty() && actions.split(',').all(|a| a.trim() == "pull")
            })
        })
}

/// Best-effort write. Pull-only scopes; the caller has already checked that.
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
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    let _ = builder.create(dir);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    let Ok(body) = serde_json::to_vec(entry) else {
        return;
    };
    // Per-process tmp name so concurrent savers never rename each other's
    // half-written file; a leftover from a crash parses as garbage and the
    // prune below removes it.
    let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
    if write_private(&tmp, &body).is_ok() {
        let _ = std::fs::rename(&tmp, &path);
    } else {
        let _ = std::fs::remove_file(&tmp);
    }
    prune_stale();
}

/// Create `path` fresh with 0600 permissions and write `body` to it, so the
/// token is never readable through a default-mode window before a chmod.
fn write_private(path: &std::path::Path, body: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(body)
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
    fn only_strictly_pull_scopes_qualify() {
        assert!(scope_is_pull_only("repository:library/alpine:pull"));
        assert!(scope_is_pull_only("repository:host:5000/foo:pull"));
        assert!(scope_is_pull_only("repository:a:pull repository:b:pull"));
        // Write-capable actions that never say "push".
        assert!(!scope_is_pull_only("repository:foo:*"));
        assert!(!scope_is_pull_only("repository:foo:delete"));
        assert!(!scope_is_pull_only("repository:foo:pull,push"));
        assert!(!scope_is_pull_only("repository:foo:pull,delete"));
        assert!(!scope_is_pull_only("registry:catalog:*"));
        assert!(!scope_is_pull_only("repository:a:pull repository:b:*"));
        assert!(!scope_is_pull_only(""));
        assert!(!scope_is_pull_only("no-colons-here"));
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
