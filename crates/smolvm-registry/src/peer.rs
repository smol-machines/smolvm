//! Brokered peer-to-peer layer-blob fetch.
//!
//! On a cache miss, before falling back to the registry, [`pull`](crate::pull)
//! can fetch a layer blob from a sibling fleet node's `GET /p2p/blob/<digest>`
//! endpoint over node→node mTLS. The candidate peers are supplied by the control
//! plane (in the machine-create request body); when none are supplied, none of
//! this code runs and the pull path is byte-for-byte the registry path.
//!
//! ## Trust model / security
//!
//! The serve-side `GET /p2p/blob/<digest>` is reachable by ANY client whose cert
//! chains to the fleet node-CA, so on a MULTI-TENANT fleet it is a cross-tenant
//! read oracle for private blobs: a node that knows (or guesses) another
//! tenant's private layer digest can read that layer. This is bounded by mTLS
//! (only fleet nodes reach it) and by sha256 pre-image resistance (you must
//! already possess the exact digest), but it is NOT tenant-scoped.
//!
//! A broker-minted, request-scoped token binding the requester to the specific
//! reference's layer digests (verified at the app layer on top of mTLS) is
//! REQUIRED before enabling P2P on a multi-tenant fleet that hosts PRIVATE
//! artifacts. As shipped, P2P is safe on single-tenant or public-artifact fleets
//! and is off by default (peers only arrive when the control plane sends them).

use crate::cache::BlobCache;
use crate::pull::{stream_verify_adopt, PullResult};
use crate::{RegistryError, Result};
use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

/// The node's own mTLS material, REUSED from the serve listener (`serve_tls.rs`):
/// a node presents its server cert/key as the *client* identity to a peer, and
/// trusts peer server certs chained to the same node-CA.
const ENV_CERT: &str = "SMOLVM_SERVE_TLS_CERT";
const ENV_KEY: &str = "SMOLVM_SERVE_TLS_KEY";
const ENV_CLIENT_CA: &str = "SMOLVM_SERVE_TLS_CLIENT_CA";

/// Bound on how long a single dead/unreachable peer may stall a launch before we
/// give up on it and move to the next peer (and ultimately the registry).
const PEER_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Idle-read bound: abort a peer that accepts the connection but then stalls
/// mid-body. This is per-read, not a whole-response deadline, so a large but
/// steady blob transfer is never cut off.
const PEER_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Process-wide node→node mTLS client, built once from the serve-TLS env vars.
///
/// Returns `None` (P2P disabled, registry-only) if the mTLS material is absent or
/// unparseable — a node with no serve identity simply never does P2P.
pub(crate) fn peer_client() -> Option<&'static reqwest::Client> {
    static CLIENT: OnceLock<Option<reqwest::Client>> = OnceLock::new();
    CLIENT
        .get_or_init(|| match build_peer_client() {
            Ok(client) => Some(client),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "P2P blob fetch disabled: could not build node->node mTLS client"
                );
                None
            }
        })
        .as_ref()
}

/// Build the node→node mTLS client: our node cert/key as the client identity,
/// trusting only the fleet node-CA (built-in roots disabled — peers are private
/// fleet nodes, never public CAs).
fn build_peer_client() -> std::result::Result<reqwest::Client, String> {
    let cert = read_env_file(ENV_CERT)?;
    let key = read_env_file(ENV_KEY)?;
    let ca = read_env_file(ENV_CLIENT_CA)?;

    // reqwest's rustls identity wants the cert chain and private key in a single
    // PEM buffer.
    let mut identity_pem = cert;
    identity_pem.push(b'\n');
    identity_pem.extend_from_slice(&key);
    let identity = reqwest::Identity::from_pem(&identity_pem)
        .map_err(|e| format!("build client identity from {ENV_CERT}/{ENV_KEY}: {e}"))?;

    let ca_cert = reqwest::Certificate::from_pem(&ca)
        .map_err(|e| format!("parse node CA from {ENV_CLIENT_CA}: {e}"))?;

    reqwest::Client::builder()
        .use_rustls_tls()
        // Peers are private fleet nodes signed by our node-CA; do not trust the
        // public web PKI for node→node traffic.
        .tls_built_in_root_certs(false)
        .add_root_certificate(ca_cert)
        .identity(identity)
        .connect_timeout(PEER_CONNECT_TIMEOUT)
        .read_timeout(PEER_READ_TIMEOUT)
        .build()
        .map_err(|e| format!("build node->node mTLS client: {e}"))
}

/// Read the file named by env var `name`. Errs (rather than panics) so a missing
/// or unreadable cert just disables P2P instead of taking the process down.
fn read_env_file(name: &str) -> std::result::Result<Vec<u8>, String> {
    let path = std::env::var_os(name)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| format!("{name} is unset"))?;
    std::fs::read(&path).map_err(|e| format!("read {name} ({}): {e}", Path::new(&path).display()))
}

/// Try each peer's `GET /p2p/blob/<digest>` in order, returning the first blob
/// that streams and verifies against `digest`. Returns `None` when every peer
/// fails — the caller then falls back to the registry.
///
/// Never returns `Err`: a peer failure (connect / timeout / non-200 / 404 /
/// digest mismatch) is logged and the next peer is tried. Any `.partial` a
/// failed attempt leaves is removed so the next source (peer or registry) starts
/// from a clean slate.
pub(crate) async fn fetch_blob_from_peers(
    client: &reqwest::Client,
    peers: &[String],
    digest: &str,
    output: Option<&Path>,
    cache: &BlobCache,
) -> Option<PullResult> {
    let partial_path = cache.blob_path_for(digest).with_extension("partial");

    for peer in peers {
        match fetch_one(client, peer, digest, output, cache).await {
            Ok(result) => {
                tracing::info!(peer = %peer, digest = %digest, "fetched layer blob from peer (P2P)");
                return Some(result);
            }
            Err(e) => {
                tracing::warn!(
                    peer = %peer,
                    digest = %digest,
                    error = %e,
                    "P2P peer fetch failed; trying next source"
                );
                // Drop any partial this attempt wrote so the next peer / the
                // registry fallback starts clean.
                let _ = tokio::fs::remove_file(&partial_path).await;
            }
        }
    }
    None
}

/// Fetch one blob from a single peer: `GET <peer>/p2p/blob/<digest>`, check the
/// status, then stream→hash→verify→adopt through the shared pull helper.
async fn fetch_one(
    client: &reqwest::Client,
    peer: &str,
    digest: &str,
    output: Option<&Path>,
    cache: &BlobCache,
) -> Result<PullResult> {
    let url = format!("{}/p2p/blob/{}", peer.trim_end_matches('/'), digest);
    let resp = client.get(&url).send().await.map_err(RegistryError::Http)?;

    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(RegistryError::BlobNotFound(digest.to_string()));
    }
    if !resp.status().is_success() {
        return Err(RegistryError::ApiError {
            status: resp.status().as_u16(),
            body: resp.text().await.unwrap_or_default(),
        });
    }

    // Identical verification + cache accounting to the registry path: the digest
    // is re-checked while streaming, so a lying peer can never poison the cache.
    stream_verify_adopt(resp.bytes_stream(), digest, output, cache).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // A valid, well-formed sha256 digest of the test blob below. Computed once
    // so the tests assert against a real content address, not a placeholder.
    fn blob_and_digest() -> (Vec<u8>, String) {
        use sha2::{Digest, Sha256};
        let data = b"the-quick-brown-fox-p2p-blob".to_vec();
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&data)));
        (data, digest)
    }

    fn cache() -> (tempfile::TempDir, BlobCache) {
        let tmp = tempfile::tempdir().unwrap();
        let cache = BlobCache::open(tmp.path().to_path_buf(), 1024 * 1024).unwrap();
        (tmp, cache)
    }

    /// Mount `GET /p2p/blob/<digest>` on `server` returning `status` with `body`.
    async fn mount_blob(server: &MockServer, digest: &str, status: u16, body: Vec<u8>) {
        Mock::given(method("GET"))
            .and(path(format!("/p2p/blob/{digest}")))
            .respond_with(ResponseTemplate::new(status).set_body_bytes(body))
            .mount(server)
            .await;
    }

    /// Peer hit → the blob is adopted into the cache and returned. The registry
    /// is never consulted (this helper takes no registry at all).
    #[tokio::test]
    async fn peer_hit_adopts_blob() {
        let (data, digest) = blob_and_digest();
        let (_tmp, cache) = cache();
        let peer = MockServer::start().await;
        mount_blob(&peer, &digest, 200, data.clone()).await;

        let client = reqwest::Client::new();
        let result = fetch_blob_from_peers(&client, &[peer.uri()], &digest, None, &cache)
            .await
            .expect("peer hit must yield a result");

        assert_eq!(result.digest, digest);
        assert_eq!(result.size, data.len() as u64);
        assert!(!result.cached);
        // Adopted through the same LRU path — a subsequent cache lookup hits.
        let cached = cache
            .get(&digest)
            .expect("blob must be in cache after peer fetch");
        assert_eq!(std::fs::read(cached).unwrap(), data);
    }

    /// First peer 404s; the fetch cleanly falls through to the next peer.
    #[tokio::test]
    async fn peer_404_falls_through_to_next_peer() {
        let (data, digest) = blob_and_digest();
        let (_tmp, cache) = cache();

        let miss = MockServer::start().await;
        mount_blob(&miss, &digest, 404, Vec::new()).await;
        let hit = MockServer::start().await;
        mount_blob(&hit, &digest, 200, data.clone()).await;

        let client = reqwest::Client::new();
        let result =
            fetch_blob_from_peers(&client, &[miss.uri(), hit.uri()], &digest, None, &cache)
                .await
                .expect("second peer must satisfy the fetch");
        assert_eq!(result.size, data.len() as u64);
    }

    /// A peer that returns the WRONG bytes (digest mismatch) is skipped, its
    /// partial is cleaned up, and the next peer succeeds.
    #[tokio::test]
    async fn peer_digest_mismatch_falls_through_and_cleans_partial() {
        let (data, digest) = blob_and_digest();
        let (_tmp, cache) = cache();

        let liar = MockServer::start().await;
        mount_blob(&liar, &digest, 200, b"totally-different-bytes".to_vec()).await;
        let honest = MockServer::start().await;
        mount_blob(&honest, &digest, 200, data.clone()).await;

        let client = reqwest::Client::new();
        let result =
            fetch_blob_from_peers(&client, &[liar.uri(), honest.uri()], &digest, None, &cache)
                .await
                .expect("honest peer must satisfy the fetch");
        assert_eq!(result.size, data.len() as u64);

        // No leftover partial from the mismatching peer.
        let partial = cache.blob_path_for(&digest).with_extension("partial");
        assert!(!partial.exists(), "partial must be cleaned after mismatch");
    }

    /// A peer that stalls past the client's timeout is abandoned; the next peer
    /// serves the blob. Uses a test-local client with a tiny timeout (production
    /// uses connect+read timeouts).
    #[tokio::test]
    async fn peer_timeout_falls_through() {
        let (data, digest) = blob_and_digest();
        let (_tmp, cache) = cache();

        let slow = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/p2p/blob/{digest}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(data.clone())
                    .set_delay(Duration::from_secs(30)),
            )
            .mount(&slow)
            .await;
        let fast = MockServer::start().await;
        mount_blob(&fast, &digest, 200, data.clone()).await;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(150))
            .build()
            .unwrap();
        let result =
            fetch_blob_from_peers(&client, &[slow.uri(), fast.uri()], &digest, None, &cache)
                .await
                .expect("fast peer must satisfy the fetch after the slow one times out");
        assert_eq!(result.size, data.len() as u64);
    }

    /// Every peer fails → `None`, so the caller falls back to the registry. The
    /// cache stays empty and no partial is left behind.
    #[tokio::test]
    async fn all_peers_fail_returns_none() {
        let (_data, digest) = blob_and_digest();
        let (_tmp, cache) = cache();

        let a = MockServer::start().await;
        mount_blob(&a, &digest, 404, Vec::new()).await;
        let b = MockServer::start().await;
        mount_blob(&b, &digest, 500, b"boom".to_vec()).await;

        let client = reqwest::Client::new();
        let result =
            fetch_blob_from_peers(&client, &[a.uri(), b.uri()], &digest, None, &cache).await;
        assert!(result.is_none(), "all-peers-fail must return None");
        assert!(cache.get(&digest).is_none(), "cache must stay empty");
        let partial = cache.blob_path_for(&digest).with_extension("partial");
        assert!(!partial.exists(), "no partial should remain");
    }

    /// An unreachable peer (connection refused) is a clean failure, not a panic:
    /// the next peer serves the blob. Covers the connect-error branch that a real
    /// connect timeout also takes.
    #[tokio::test]
    async fn unreachable_peer_falls_through() {
        let (data, digest) = blob_and_digest();
        let (_tmp, cache) = cache();

        let hit = MockServer::start().await;
        mount_blob(&hit, &digest, 200, data.clone()).await;

        let client = reqwest::Client::new();
        // Port 1 has nothing listening → connection refused.
        let dead = "http://127.0.0.1:1".to_string();
        let result = fetch_blob_from_peers(&client, &[dead, hit.uri()], &digest, None, &cache)
            .await
            .expect("live peer must satisfy the fetch");
        assert_eq!(result.size, data.len() as u64);
    }

    /// With the serve-TLS env vars unset, no peer client can be built, so P2P is
    /// disabled (registry-only). Guarded by a mutex because it mutates process
    /// env; other suites don't touch these vars.
    #[test]
    fn build_peer_client_errs_when_env_unset() {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        for v in [ENV_CERT, ENV_KEY, ENV_CLIENT_CA] {
            std::env::remove_var(v);
        }
        let err = build_peer_client().unwrap_err();
        assert!(err.contains(ENV_CERT), "{err}");
    }
}
