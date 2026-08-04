//! Content-addressed store of OCI image layers, extracted once on the host and
//! mounted read-only by every machine that runs the image (issue #756).
//!
//! Without it each VM pulls the image from the registry and flattens it into its
//! own storage — work whose cost scales with the *extracted* size and is repeated
//! per machine. The store does it once: the layers become overlayfs lowerdirs the
//! guest mounts through the existing packed-layers path, so a repeat run skips
//! both the pull and the flatten.
//!
//! # Two properties this store is built around
//!
//! **Access is re-authorized per caller, every time.** [`ImageStore::ensure_image`]
//! resolves the manifest with the caller's credentials before the cache is
//! consulted, so the registry's own `repository:<repo>:pull` decision gates a hit
//! exactly as it gates a miss. Entries are additionally keyed by the registry and
//! repository they were authorized against ([`entry_key`]), so passing the gate at
//! one registry can never unlock content filled from another.
//!
//! **The on-disk entry is shaped like a packed-layers directory**, because that is
//! what the guest already consumes: digest-named layer dirs, a `layer-order`
//! index, and the image's own config as `config.json`. Producing that shape
//! rather than inventing a parallel one is what lets the idmapped mount, the
//! config parsing, and the overlay stacking all work unchanged.
//!
//! # Why this store does not live in the pack store's directory
//!
//! The shared pack store is deliberately never size-capped: its entries are
//! reference-shared by live VMs with no lease, so evicting one can pull the rug
//! from under a running machine. This store keeps its own root, so it can be
//! bounded without touching anything it does not own.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::registry::{registry_client, PullAuth, Reference};
use crate::{Error, Result};

/// A content-addressed store of extracted image layers, rooted at its own
/// directory (never the pack store's — see the module docs).
pub struct ImageStore {
    root: PathBuf,
}

impl ImageStore {
    /// Store rooted at `root`; each image lives at `root/<entry-key>/`.
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// The node/host image store — a sibling of the pack store, not a tenant.
    pub fn shared() -> Self {
        Self::new(crate::agent::vm_cache_root().join("_images"))
    }

    /// Resolve and authorize `reference`, ensure its layers are extracted, and
    /// return the directory to present as the guest's packed layers.
    ///
    /// The auth gate runs on every call, before the cache is consulted, so a hit
    /// cannot serve an image the caller is not entitled to pull.
    pub async fn ensure_image(&self, reference: &str, auth: &PullAuth) -> Result<PathBuf> {
        let r = resolve_authorized(reference, auth).await?;
        let key = entry_key(&r.registry, &r.repo, &r.digest);
        let entry = self.root.join(&key);

        if is_intact(&entry) {
            touch(&entry);
            return Ok(entry);
        }

        std::fs::create_dir_all(&self.root)
            .map_err(|e| Error::config("image-store", e.to_string()))?;
        // Serialize fills of the same key across processes AND tasks. Without it
        // two fillers share a staging dir: one wipes the other's extracted layers
        // and then publishes an entry whose `layer-order` names dirs that are gone.
        let _guard = FillLock::acquire(&self.root.join(format!(".lock-{key}")))?;
        // Whoever held the lock before us may have just filled it.
        if is_intact(&entry) {
            touch(&entry);
            return Ok(entry);
        }

        let manifest: smolvm_registry::OciManifest = serde_json::from_slice(&r.manifest_bytes)
            .map_err(|e| Error::agent("image-store: parse manifest", e.to_string()))?;
        let staging = self.root.join(format!(".staging-{key}-{}", fill_nonce()));
        let _ = std::fs::remove_dir_all(&staging);
        materialize_entry(&r.client, &r.repo, &manifest, &staging)
            .await
            .inspect_err(|_| {
                let _ = std::fs::remove_dir_all(&staging);
            })?;

        // Atomic publish. A pre-existing directory here is debris (a crash, or a
        // partial removal): rename would fail with ENOTEMPTY forever, so clear it
        // and retry once rather than poisoning the key permanently.
        match std::fs::rename(&staging, &entry) {
            Ok(()) => {}
            Err(_) if is_intact(&entry) => {
                let _ = std::fs::remove_dir_all(&staging);
            }
            Err(_) if entry.exists() => {
                let _ = std::fs::remove_dir_all(&entry);
                std::fs::rename(&staging, &entry).map_err(|e| {
                    let _ = std::fs::remove_dir_all(&staging);
                    Error::config("image-store: publish", e.to_string())
                })?;
            }
            Err(e) => {
                let _ = std::fs::remove_dir_all(&staging);
                return Err(Error::config("image-store: publish", e.to_string()));
            }
        }

        sweep_staging(&self.root);
        prune_store(&self.root, image_cache_max_bytes(), &entry);
        Ok(entry)
    }
}

/// The image's own config, under the name and shape the guest already parses
/// (`config.json`, OCI `{"config": {...}}`), so entrypoint, cmd, env, working
/// directory and user all reach the container with no host-side translation.
const CONFIG_FILE: &str = "config.json";

/// The layer-stacking index, bottom-most layer first.
const LAYER_ORDER_FILE: &str = "layer-order";

/// Declares which xattr namespace this entry's opaque-directory markers use, so
/// the guest can mount the overlay with a matching `userxattr` setting. Read by
/// the agent; absent means `trusted.*`, which is what every pre-existing packed
/// artifact uses.
const OPAQUE_XATTR_MARKER: &str = "opaque-xattr";

/// An entry is usable only once its `layer-order` index exists. It is written
/// last, so its presence means every layer and the config are already in place —
/// a crash mid-fill can never present a partial entry as a hit.
fn is_intact(entry: &Path) -> bool {
    entry.join(LAYER_ORDER_FILE).is_file() && entry.join(CONFIG_FILE).is_file()
}

/// Whether this process can materialize an entry.
///
/// Translating an OCI whiteout into an overlayfs whiteout is a `mknod` of a
/// character device, which needs `CAP_MKNOD`. Ownership is deliberately NOT
/// preserved (see `ExtractOptions::HOST_SHARED`), so no `CAP_CHOWN` is required.
/// Rather than degrade into half-applied deletions, the store declines and the
/// caller keeps the in-guest pull.
#[cfg(unix)]
pub fn can_extract() -> bool {
    // SAFETY: geteuid is always safe and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// Non-Unix hosts cannot create the device nodes overlayfs whiteouts require,
/// so the store never serves them and the caller keeps the in-guest pull.
#[cfg(not(unix))]
pub fn can_extract() -> bool {
    false
}

/// Fill (or reuse) the store for `reference` and return the directory to present
/// as packed layers, from a synchronous caller.
///
/// Returns `None` whenever the store cannot serve this caller — it is a cache,
/// never a hard dependency, so a registry outage, a rate limit, or a host that
/// cannot extract must not stop a machine that could still pull in-guest.
pub fn ensure_image_blocking(reference: &str, auth: &PullAuth) -> Option<PathBuf> {
    if !can_extract() {
        tracing::debug!("image store skipped: layer extraction needs CAP_MKNOD");
        return None;
    }
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            tracing::warn!(error = %e, "image store skipped: runtime");
            return None;
        }
    };
    match rt.block_on(ImageStore::shared().ensure_image(reference, auth)) {
        Ok(dir) => Some(dir),
        Err(e) => {
            tracing::warn!(error = %e, "image store unavailable; falling back to in-guest pull");
            None
        }
    }
}

/// A machine's back-reference file: records which entry served it.
///
/// The name is dot-prefixed so `prune_store` skips it as a non-content entry,
/// the same way it skips the fill locks.
fn ref_path(machine: &str) -> PathBuf {
    let safe: String = machine
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    ImageStore::shared().root.join(format!(".ref-{safe}"))
}

/// Record that `machine` boots from `entry`, so later starts can re-present the
/// same layers without a registry round-trip, and so the LRU knows the entry is
/// in use.
pub fn remember_entry(machine: &str, entry: &Path) {
    let Some(name) = entry.file_name().and_then(|n| n.to_str()) else {
        return;
    };
    if let Err(e) = std::fs::write(ref_path(machine), name) {
        tracing::debug!(error = %e, "image store: could not record machine back-reference");
    }
}

/// The entry `machine` last booted from, if it is still present.
///
/// Returning it lets a warm restart re-present layers that are already on disk,
/// so a machine survives a registry outage instead of depending on it.
pub fn remembered_entry(machine: &str) -> Option<PathBuf> {
    let name = std::fs::read_to_string(ref_path(machine)).ok()?;
    let name = name.trim();
    // Reject anything that is not a bare entry directory name: the file is
    // host-local, but a path component here would escape the store root.
    if name.is_empty() || name.contains('/') || name.starts_with('.') {
        return None;
    }
    let dir = ImageStore::shared().root.join(name);
    dir.is_dir().then_some(dir)
}

/// Drop `machine`'s claim on its entry, so the LRU may reclaim it.
pub fn forget_entry(machine: &str) {
    let _ = std::fs::remove_file(ref_path(machine));
}

/// Drop claims held by machines that no longer exist.
///
/// `delete_vm` releases a claim on the normal path, but a machine can also
/// vanish without it — a restored or discarded database, a data dir removed by
/// hand. A claim left behind pins its entry against the LRU forever, which is
/// exactly the unbounded growth the size cap exists to prevent, so reconcile
/// against the live machine list on start.
pub fn sweep_refs<I, S>(live: I)
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let live: std::collections::HashSet<PathBuf> =
        live.into_iter().map(|m| ref_path(m.as_ref())).collect();
    let root = ImageStore::shared().root;
    let Ok(entries) = std::fs::read_dir(&root) else {
        return;
    };
    for e in entries.flatten() {
        let path = e.path();
        if !e.file_name().to_string_lossy().starts_with(".ref-") {
            continue;
        }
        if !live.contains(&path) {
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// The shared layers to present to a machine, in the shape the packed-layers
/// path already consumes.
pub struct PreparedLayers {
    /// The shared, content-addressed entry holding the extracted layers.
    pub idmap_source: PathBuf,
    /// The machine's own EMPTY mountpoint the source is bound onto.
    pub mountpoint: PathBuf,
}

/// Resolve the layers `machine` should boot from, filling the store if needed.
///
/// The single implementation behind both the CLI and the API start paths — they
/// differ only in the credential they gate with, never in the mechanics.
///
/// Call this on EVERY boot, not just the first: packed layers are a per-boot
/// mount, not persistent machine state. A machine whose layers came from the
/// store has no in-guest image to fall back on, so presenting them once would
/// leave every later start with no rootfs at all.
///
/// Only a *fill* needs `image` and `auth`. Re-presenting the entry this machine
/// already booted from needs neither: it is keyed by the machine, it passed the
/// gate when it was filled, and it belongs to this machine alone. That is what
/// lets a start path with no image reference in hand — an exec autostart, a
/// supervisor restart — keep a store-backed machine bootable, and what lets a
/// warm restart survive a registry outage.
///
/// `auth` is `None` when the caller holds no credential it may gate a fill with.
/// That declines the fill rather than falling back to ambient host credentials,
/// which on a shared node would authorize one tenant's cache hit with another's
/// rights.
///
/// Returns `None` whenever the store cannot serve this machine. It is a cache,
/// never a hard dependency, so every miss falls through to the in-guest pull.
pub fn prepare_layers(
    machine: &str,
    image: Option<&str>,
    auth: Option<&PullAuth>,
) -> Option<PreparedLayers> {
    let entry = match remembered_entry(machine) {
        Some(entry) => entry,
        None => ensure_image_blocking(image?, auth?)?,
    };
    // `mountpoint` must be an EMPTY per-machine directory and `idmap_source` the
    // shared content. While the uid drop is active `internal_boot` idmap-binds
    // the source onto that mountpoint, mapping on-disk uid 0 to the VM's uid;
    // pointing both at the same directory would ask it to bind the store onto
    // itself. Without the drop the manager collapses the indirection on its own.
    let mountpoint = crate::agent::machine_layers_cache_dir(machine);
    if let Err(e) = std::fs::create_dir_all(&mountpoint) {
        tracing::warn!(error = %e, "image store skipped: no layers mountpoint");
        return None;
    }
    remember_entry(machine, &entry);
    Some(PreparedLayers {
        idmap_source: entry,
        mountpoint,
    })
}

/// Entry directory names that some machine still boots from.
fn entries_in_use(root: &Path) -> std::collections::HashSet<std::ffi::OsString> {
    let mut used = std::collections::HashSet::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return used;
    };
    for e in entries.flatten() {
        let name = e.file_name();
        if !name.to_string_lossy().starts_with(".ref-") {
            continue;
        }
        if let Ok(target) = std::fs::read_to_string(e.path()) {
            used.insert(std::ffi::OsString::from(target.trim()));
        }
    }
    used
}

/// The outcome of the auth gate.
struct Resolved {
    client: smolvm_registry::RegistryClient,
    /// The registry the manifest was actually authorized against — part of the
    /// key, so an entry is only served to a caller who passed the gate there.
    registry: String,
    repo: String,
    manifest_bytes: Vec<u8>,
    digest: String,
}

/// Resolve + authorize `reference` across the candidate registries the guest
/// would try, returning the winning client, repo, manifest, and content digest.
async fn resolve_authorized(reference: &str, auth: &PullAuth) -> Result<Resolved> {
    let parsed = Reference::parse(reference)
        .map_err(|e| Error::config("image-store", format!("bad reference: {}", e.reason)))?;
    let want = parsed
        .digest
        .clone()
        .or_else(|| parsed.tag.clone())
        .unwrap_or_else(|| "latest".to_string());
    let config = crate::SmolSettings::load()?.images;

    // Resolve the way the GUEST does — via `registry_pull_hosts`, not the
    // configured default — so the host-side gate targets the same registry the
    // in-guest pull would (a bare `alpine` is Docker Hub, not the smol registry).
    let mut first_err: Option<String> = None;
    for host in &crate::registry::registry_pull_hosts(reference) {
        let client = registry_client(host, &config, auth);
        let repo = repo_for(host, &parsed);
        match client.get_manifest_resolved(&repo, &want).await {
            Ok(manifest_bytes) => {
                let digest = format!("sha256:{}", hex::encode(Sha256::digest(&manifest_bytes)));
                return Ok(Resolved {
                    client,
                    registry: host.clone(),
                    repo,
                    manifest_bytes,
                    digest,
                });
            }
            // Keep the FIRST failure: `registry_pull_hosts` is a DNS allow-list,
            // not a list of endpoints — Docker Hub yields ["docker.io",
            // "docker.com"] — so a later marketing-host failure would otherwise
            // mask the real 401/429.
            Err(e) => {
                let _ = first_err.get_or_insert_with(|| e.to_string());
            }
        }
    }
    Err(Error::agent(
        "image-store: authorize",
        first_err.unwrap_or_else(|| "no candidate registry resolved the image".to_string()),
    ))
}

/// The auth gate alone: resolve `reference` with the caller's credentials and
/// return its manifest digest. Callers key content on it, so an entry tracks the
/// image's CONTENT rather than a mutable tag.
pub async fn authorized_digest(reference: &str, auth: &PullAuth) -> Result<String> {
    Ok(resolve_authorized(reference, auth).await?.digest)
}

/// The repository path for a reference against a candidate `host`. Docker Hub
/// official images (no namespace) live under the implicit `library/` namespace,
/// so a bare `alpine` becomes `library/alpine` — without which the pull scope is
/// wrong and the registry answers 401.
fn repo_for(host: &str, r: &Reference) -> String {
    let docker_hub = matches!(
        host,
        "docker.io" | "docker.com" | "index.docker.io" | "registry-1.docker.io"
    );
    match &r.namespace {
        Some(ns) => format!("{}/{}", ns, r.name),
        None if docker_hub => format!("library/{}", r.name),
        None => r.name.clone(),
    }
}

/// A filesystem-safe directory name for a digest (`sha256:abc` → `sha256-abc`).
fn digest_dir(digest: &str) -> String {
    digest.replace(':', "-")
}

/// The cache key: the manifest digest bound to the registry and repository it was
/// authorized against.
///
/// Keying on the digest ALONE would make the gate bypassable. Resolution accepts
/// the first candidate registry that answers, including one the caller controls,
/// so anyone holding a private image's manifest bytes (manifests leak far more
/// easily than blobs — an old public tag, a CI log) could serve them from their
/// own registry, pass the gate there, and be handed the private image's extracted
/// layers. Dedup is preserved where it matters: every caller pulling
/// `docker.io/library/alpine` at the same digest still shares one entry.
fn entry_key(registry: &str, repo: &str, manifest_digest: &str) -> String {
    let scoped = format!("{registry}/{repo}@{manifest_digest}");
    format!("sha256-{}", hex::encode(Sha256::digest(scoped.as_bytes())))
}

/// Environment override (bytes) for the store's on-disk ceiling.
const IMAGE_CACHE_MAX_BYTES_ENV: &str = "SMOLVM_IMAGE_CACHE_MAX_BYTES";

/// Size ceiling for the store, default 20 GiB. Extracted layers are far larger
/// than the blobs they came from, so an unbounded store fills a node's disk and
/// every machine on it then fails to start.
fn image_cache_max_bytes() -> u64 {
    std::env::var(IMAGE_CACHE_MAX_BYTES_ENV)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20 * 1024 * 1024 * 1024)
}

/// Mark an entry recently used so LRU eviction keeps hot images.
fn touch(entry: &Path) {
    if let Ok(f) = std::fs::File::open(entry) {
        let _ = f.set_modified(std::time::SystemTime::now());
    }
}

/// A unique-per-fill suffix, so a crashed fill's debris is never mistaken for an
/// in-progress one. (Uniqueness only — the lock provides mutual exclusion.)
fn fill_nonce() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{}-{}", std::process::id(), nanos)
}

/// An exclusive advisory lock held for one fill, released when the handle closes.
struct FillLock(
    // Never read: the handle IS the lock. The OS releases it when this file
    // closes, so the field's only job is to live as long as the guard.
    #[allow(dead_code)] std::fs::File,
);

impl FillLock {
    fn acquire(path: &Path) -> Result<Self> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| Error::config("image-store: lock", e.to_string()))?;
        lock_exclusive(&file).map_err(|e| Error::config("image-store: lock", e.to_string()))?;
        Ok(Self(file))
    }
}

#[cfg(unix)]
fn lock_exclusive(file: &std::fs::File) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    // SAFETY: `fd` is a valid open descriptor for the duration of the call.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
fn lock_exclusive(file: &std::fs::File) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{LockFileEx, LOCKFILE_EXCLUSIVE_LOCK};
    use windows_sys::Win32::System::IO::OVERLAPPED;
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    // SAFETY: handle is valid; overlapped is a zeroed, correctly sized struct.
    let ok = unsafe {
        LockFileEx(
            file.as_raw_handle() as _,
            LOCKFILE_EXCLUSIVE_LOCK,
            0,
            !0,
            !0,
            &mut overlapped,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Reap staging debris left by a crashed fill; without this every crash leaks a
/// full extracted image that nothing reclaims. Only demonstrably stale debris is
/// removed, so a concurrent fill in another process is never pulled out from
/// under itself.
fn sweep_staging(root: &Path) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for e in entries.flatten() {
        let name = e.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with(".staging-") {
            continue;
        }
        let stale = e
            .metadata()
            .and_then(|m| m.modified())
            .map(|t| {
                t.elapsed()
                    .map(|age| age > std::time::Duration::from_secs(3600))
                    .unwrap_or(false)
            })
            .unwrap_or(false);
        if stale {
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
}

/// Evict least-recently-used entries until the store fits `max_bytes`, never
/// removing `keep` (the entry the caller is about to mount).
///
/// Safe here precisely because this root belongs to the store: the pack store is
/// never-evict, since its entries are reference-shared by live VMs.
fn prune_store(root: &Path, max_bytes: u64, keep: &Path) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    // Entries a machine still boots from are pinned. Evicting one does not just
    // cost a re-pull: the machine's layers ARE those directories, so removing
    // them leaves it unable to start with nothing to fall back on.
    let in_use = entries_in_use(root);
    let mut items: Vec<(std::time::SystemTime, u64, PathBuf)> = Vec::new();
    let mut total = 0u64;
    for e in entries.flatten() {
        let path = e.path();
        let name = e.file_name();
        if in_use.contains(&name) {
            total += dir_size(&path);
            continue;
        }
        let name = name.to_string_lossy();
        // Only content entries participate; locks and staging are not evictable.
        if name.starts_with('.') || !path.is_dir() {
            continue;
        }
        let size = dir_size(&path);
        total += size;
        let mtime = e
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(std::time::UNIX_EPOCH);
        items.push((mtime, size, path));
    }
    if total <= max_bytes {
        return;
    }
    items.sort_by_key(|(mtime, _, _)| *mtime);
    for (_, size, path) in items {
        if total <= max_bytes {
            break;
        }
        if path == keep {
            continue;
        }
        if std::fs::remove_dir_all(&path).is_ok() {
            total = total.saturating_sub(size);
        }
    }
}

/// Bytes a file actually occupies on disk.
///
/// `st_blocks × 512`, not the apparent length: sparse files report a length far
/// larger than they consume, so counting apparent size would over-count by orders
/// of magnitude and evict far too aggressively.
#[cfg(unix)]
fn file_disk_usage(md: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    md.blocks() * 512
}

#[cfg(not(unix))]
fn file_disk_usage(md: &std::fs::Metadata) -> u64 {
    md.len()
}

/// Recursive on-disk size of a directory, following no symlinks.
fn dir_size(path: &Path) -> u64 {
    let mut total = 0;
    let Ok(entries) = std::fs::read_dir(path) else {
        return 0;
    };
    for e in entries.flatten() {
        let Ok(md) = e.metadata() else { continue };
        if md.is_dir() {
            total += dir_size(&e.path());
        } else {
            total += file_disk_usage(&md);
        }
    }
    total
}

/// Environment override (bytes) for the largest single blob accepted.
const MAX_LAYER_BYTES_ENV: &str = "SMOLVM_MAX_LAYER_BYTES";

/// Ceiling on one blob, default 8 GiB — larger than any real base image, small
/// enough that a runaway download cannot fill the disk before the digest check.
fn max_layer_bytes() -> u64 {
    std::env::var(MAX_LAYER_BYTES_ENV)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8 * 1024 * 1024 * 1024)
}

/// Stream a blob to `dest`, hashing as it goes, and reject it unless the content
/// hashes to `digest`. Streaming (rather than a buffered pull) removes both the
/// body size cap and the full-blob memory buffer; verifying from the streamed
/// bytes keeps the content-addressing guarantee.
async fn stream_blob_verified(
    client: &smolvm_registry::RegistryClient,
    repo: &str,
    digest: &str,
    dest: &Path,
) -> Result<()> {
    use futures_util::StreamExt;
    use std::io::Write;

    let mut stream = client
        .pull_blob_stream(repo, digest)
        .await
        .map_err(|e| Error::agent("image-store: pull blob", e.to_string()))?;
    let file =
        std::fs::File::create(dest).map_err(|e| Error::config("image-store", e.to_string()))?;
    let mut writer = std::io::BufWriter::new(file);
    let mut hasher = Sha256::new();
    let mut written: u64 = 0;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| Error::agent("image-store: pull blob", e.to_string()))?;
        written += chunk.len() as u64;
        // Bound the write so a hostile or broken registry cannot fill the disk
        // before the digest is checked at the end.
        if written > max_layer_bytes() {
            let _ = std::fs::remove_file(dest);
            return Err(Error::agent(
                "image-store: pull blob",
                format!("blob exceeds {} bytes", max_layer_bytes()),
            ));
        }
        hasher.update(&chunk);
        writer
            .write_all(&chunk)
            .map_err(|e| Error::config("image-store: write blob", e.to_string()))?;
    }
    writer
        .flush()
        .map_err(|e| Error::config("image-store: write blob", e.to_string()))?;

    let got = format!("sha256:{}", hex::encode(hasher.finalize()));
    if got != digest {
        let _ = std::fs::remove_file(dest);
        return Err(Error::agent(
            "image-store: blob digest",
            format!("content mismatch: expected {digest}, got {got}"),
        ));
    }
    Ok(())
}

/// Materialize a full entry into `staging`, in the shape the guest's packed-layers
/// path already consumes: one extracted directory per layer, the image's own
/// config as `config.json`, and the `layer-order` index written LAST.
///
/// Layers extract with `ExtractOptions::HOST_SHARED`: ownership is not preserved
/// (the guest sees these through an idmapped mount) and opaque markers use the
/// `user.*` namespace, because the virtiofs server that will read them has
/// dropped privileges and cannot see `trusted.*` at all.
async fn materialize_entry(
    client: &smolvm_registry::RegistryClient,
    repo: &str,
    manifest: &smolvm_registry::OciManifest,
    staging: &Path,
) -> Result<()> {
    std::fs::create_dir_all(staging).map_err(|e| Error::config("image-store", e.to_string()))?;

    let mut order = Vec::with_capacity(manifest.layers.len());
    for descriptor in &manifest.layers {
        smolvm_registry::validate_digest(&descriptor.digest)
            .map_err(|e| Error::agent("image-store: layer digest", e.to_string()))?;
        let blob_path = staging.join(format!("{}.blob", digest_dir(&descriptor.digest)));
        stream_blob_verified(client, repo, &descriptor.digest, &blob_path).await?;

        let dir = staging.join(digest_dir(&descriptor.digest));
        std::fs::create_dir_all(&dir).map_err(|e| Error::config("image-store", e.to_string()))?;
        let blob = std::fs::File::open(&blob_path)
            .map_err(|e| Error::config("image-store: open layer", e.to_string()))?;
        let extracted = smolvm_oci_layer::extract_oci_layer(
            std::io::BufReader::new(blob),
            &dir,
            smolvm_oci_layer::ExtractOptions::HOST_SHARED,
        )
        .map_err(|e| Error::agent("image-store: extract layer", e.to_string()));
        // The compressed blob is scratch — drop it either way, so a fill never
        // leaves both representations on disk.
        let _ = std::fs::remove_file(&blob_path);
        extracted?;
        order.push(digest_dir(&descriptor.digest));
    }

    // The image config, verbatim. The guest parses this exact shape already, so
    // entrypoint/cmd/env/workdir/user reach the container with no host-side
    // translation and nothing to drift out of sync.
    smolvm_registry::validate_digest(&manifest.config.digest)
        .map_err(|e| Error::agent("image-store: config digest", e.to_string()))?;
    stream_blob_verified(
        client,
        repo,
        &manifest.config.digest,
        &staging.join(CONFIG_FILE),
    )
    .await?;

    // Declare the opaque-marker namespace these layers use, so the guest mounts
    // the overlay with `userxattr` and actually honors them. The layers describe
    // themselves rather than relying on an out-of-band signal, which keeps every
    // existing artifact correct by absence: no marker means `trusted.*`.
    std::fs::write(staging.join(OPAQUE_XATTR_MARKER), b"user")
        .map_err(|e| Error::config("image-store", e.to_string()))?;

    // Written LAST: its presence is what `is_intact` treats as "complete".
    std::fs::write(staging.join(LAYER_ORDER_FILE), order.join("\n"))
        .map_err(|e| Error::config("image-store", e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_dir_is_filesystem_safe() {
        assert_eq!(digest_dir("sha256:abc123"), "sha256-abc123");
    }

    #[test]
    fn repo_for_maps_docker_hub_and_namespaced_refs() {
        let bare = Reference::parse("alpine").unwrap();
        assert_eq!(repo_for("docker.io", &bare), "library/alpine");
        let ns = Reference::parse("ghcr.io/org/tool:v1").unwrap();
        assert_eq!(repo_for("ghcr.io", &ns), "org/tool");
        assert_eq!(repo_for("ghcr.io", &bare), "alpine");
    }

    /// The store must never share the pack store's root: that tree is
    /// deliberately never-evict (its entries are reference-shared by live VMs
    /// with no lease), and this store size-caps its own root.
    #[test]
    fn store_root_is_not_the_pack_store_root() {
        let store = ImageStore::shared().root;
        assert_ne!(store, crate::agent::shared_pack_cache_root());
        assert!(store.ends_with("_images"));
    }

    /// THE key-scoping property: the same manifest digest served from a different
    /// registry or repo must land on a different entry, or merely holding a
    /// private image's manifest would unlock its cached layers.
    #[test]
    fn entry_key_is_scoped_to_registry_and_repo() {
        let d = "sha256:abc";
        let real = entry_key("registry.example.com", "team/private", d);
        assert_ne!(real, entry_key("evil.example.com", "team/private", d));
        assert_ne!(real, entry_key("registry.example.com", "other/repo", d));
        assert_ne!(
            real,
            entry_key("registry.example.com", "team/private", "sha256:def")
        );
        assert_eq!(real, entry_key("registry.example.com", "team/private", d));
        assert!(!real.contains('/') && !real.contains(':'));
    }

    /// The order index is written last, so an entry missing it — or missing the
    /// config — is never treated as a hit.
    #[test]
    fn intact_requires_config_and_order_index() {
        let tmp = tempfile::tempdir().unwrap();
        let entry = tmp.path().join("e");
        std::fs::create_dir_all(entry.join("sha256-l1")).unwrap();
        assert!(!is_intact(&entry));
        std::fs::write(entry.join(CONFIG_FILE), b"{}").unwrap();
        assert!(!is_intact(&entry), "config alone is not a complete entry");
        std::fs::write(entry.join(LAYER_ORDER_FILE), "sha256-l1").unwrap();
        assert!(is_intact(&entry));
    }

    /// Eviction is LRU and never drops the entry the caller is about to mount.
    #[test]
    fn prune_store_evicts_oldest_and_never_the_kept_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let mk = |name: &str, bytes: usize, age: u64| -> PathBuf {
            let dir = root.join(name);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("blob"), vec![0u8; bytes]).unwrap();
            let f = std::fs::File::open(&dir).unwrap();
            let _ =
                f.set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(age));
            dir
        };
        let oldest = mk("a", 8192, 300);
        let middle = mk("b", 8192, 200);
        let newest = mk("c", 8192, 100);
        // Cap admits two of three entries → exactly one eviction.
        prune_store(root, 20000, &newest);
        assert!(!oldest.exists(), "least-recently-used entry evicted");
        assert!(middle.exists());
        assert!(newest.exists(), "the kept entry is never evicted");
    }

    /// THE security property: authorization is the registry's decision, made with
    /// the caller's credentials on every call.
    #[test]
    fn resolution_requires_authorization() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let server = MockServer::start().await;
            let body = br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","size":0},"layers":[]}"#.to_vec();

            Mock::given(method("GET"))
                .and(path("/v2/myrepo/manifests/latest"))
                .and(header("authorization", "Bearer good-token"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("content-type", "application/vnd.oci.image.manifest.v1+json")
                        .set_body_bytes(body.clone()),
                )
                .with_priority(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/v2/myrepo/manifests/latest"))
                .respond_with(ResponseTemplate::new(401).set_body_string("unauthorized"))
                .with_priority(5)
                .mount(&server)
                .await;

            let host = server.uri().strip_prefix("http://").unwrap().to_string();
            let reference = format!("{host}/myrepo:latest");

            let denied = authorized_digest(&reference, &PullAuth::Anonymous).await;
            assert!(denied.is_err(), "unauthorized caller must be rejected");

            let digest = authorized_digest(&reference, &PullAuth::Bearer("good-token".into()))
                .await
                .expect("authorized caller should resolve");
            assert_eq!(
                digest,
                format!("sha256:{}", hex::encode(Sha256::digest(&body)))
            );
        });
    }
}
