//! Shared storage seeds for registry images.
//!
//! A machine created with `--image` pulls that image inside the guest on its
//! first start: the manifest, config and every layer come over the network and
//! are extracted onto the machine's own storage disk. Nothing is shared, so every
//! new machine of the same image repeats the whole pull (seconds, and two
//! rate-limited manifest GETs against Docker Hub).
//!
//! A seed is that pulled state, captured once per image: the storage disk of a
//! throwaway machine that pulled the image and never ran a workload. It is a
//! read-only qcow2 over the storage template. A new machine's `storage.qcow2` is
//! created as a copy-on-write overlay on the seed instead of on the bare template,
//! so its guest finds the image already present and its first start skips the
//! pull, exactly as a restart does.
//!
//! The key includes the digest the image reference points to, resolved on the
//! host with the caller's credentials on every first start (one manifest HEAD,
//! the same registry authorization a pull gets). A moved tag gets a new seed, and
//! a caller the registry refuses never reaches a cached one. Portable checkpoints
//! copy the whole disk chain, so they do not depend on a seed staying on disk.
//! Seeding is best-effort: any failure falls back to the in-guest pull.
//! `SMOLVM_IMAGE_SEEDS=0` turns it off.
//!
//! Without a sized storage template (macOS, or an SDK install that ships none)
//! the seed is the builder's raw disk instead, and each machine takes a
//! copy-on-write clone of it: an APFS clone on macOS, a reflink or sparse copy
//! on Linux. Clones are independent of the seed, so eviction never has to keep
//! one alive.

#[cfg(unix)]
pub use imp::{
    prewarm_recent_seeds, revalidate_seed, seed_root, seed_storage, seed_storage_with_trust,
    seedable_image, wants_seed, SEED_MACHINE_PREFIX,
};

/// The smolvm binary that builds seeds. The SDKs run inside `node` or `python`,
/// so their own executable is not smolvm; they point `SMOLVM_BOOT_BINARY` at the
/// smolvm they bundle. The CLI and the server build with themselves.
pub fn builder_exe() -> std::io::Result<std::path::PathBuf> {
    match std::env::var_os("SMOLVM_BOOT_BINARY") {
        Some(path) => Ok(path.into()),
        None => std::env::current_exe(),
    }
}

/// Give a fresh registry-image machine a seeded storage disk before its first
/// start. Best-effort: without a seed the guest pulls as before.
pub fn seed_first_start(
    name: &str,
    record: &crate::config::VmRecord,
    from_snapshot: bool,
    digest_ttl: Option<u64>,
    proxy: Option<&str>,
    no_proxy: Option<&str>,
) {
    let Some(image) = wants_seed(name, record, from_snapshot) else {
        return;
    };
    // A seed is built by a separate VM. Carry the same opt-in host trust
    // mount to that VM so a private-CA registry can use the seed fast path.
    let trust_host_certs = record.host_mounts().iter().any(|mount| {
        mount.read_only && mount.target == std::path::Path::new("/etc/smolvm-host-trust")
    });
    let seeded = builder_exe()
        .map_err(|e| crate::Error::config("image seed", e.to_string()))
        .and_then(|exe| {
            seed_storage_with_trust(
                &exe,
                name,
                &image,
                &crate::registry::PullAuth::FromConfig,
                record.storage_gb,
                digest_ttl,
                proxy,
                no_proxy,
                trust_host_certs,
            )
        });
    if let Err(error) = seeded {
        tracing::warn!(machine = name, %error, "no image seed; pulling in the guest");
    }
}

/// [`seed_first_start`] for the ephemeral `machine run` path, which boots
/// before any record exists. The record-level gates cannot apply to a machine
/// this very run is creating: it has completed no init, was not created from a
/// pack (the `--from` and cached-artifact paths branch off earlier), and has
/// no branch golden or foreign uid owner. Gating on the image and storage size
/// is therefore the whole check, exactly [`seedable_image`]. Best-effort like
/// every seed: without one the guest pulls as before.
pub fn seed_ephemeral_run(
    name: &str,
    image: Option<&str>,
    storage_gb: Option<u64>,
    digest_ttl: Option<u64>,
    proxy: Option<&str>,
    no_proxy: Option<&str>,
) {
    seed_ephemeral_run_with_trust(name, image, storage_gb, digest_ttl, proxy, no_proxy, false);
}

/// Seed an ephemeral run whose workload also trusts the host's certificates.
#[allow(clippy::too_many_arguments)]
pub fn seed_ephemeral_run_with_trust(
    name: &str,
    image: Option<&str>,
    storage_gb: Option<u64>,
    digest_ttl: Option<u64>,
    proxy: Option<&str>,
    no_proxy: Option<&str>,
    trust_host_certs: bool,
) {
    let Some(image) = seedable_image(name, image, storage_gb) else {
        return;
    };
    let seeded = builder_exe()
        .map_err(|e| crate::Error::config("image seed", e.to_string()))
        .and_then(|exe| {
            seed_storage_with_trust(
                &exe,
                name,
                &image,
                &crate::registry::PullAuth::FromConfig,
                storage_gb,
                digest_ttl,
                proxy,
                no_proxy,
                trust_host_certs,
            )
        });
    if let Err(error) = seeded {
        tracing::warn!(machine = name, %error, "no image seed; pulling in the guest");
    }
}

/// Seeds need a Unix host; elsewhere nothing seeds.
#[cfg(not(unix))]
pub fn wants_seed(_: &str, _: &crate::config::VmRecord, _: bool) -> Option<String> {
    None
}

/// Seeds need a Unix host; elsewhere nothing seeds.
#[cfg(not(unix))]
pub fn seedable_image(_: &str, _: Option<&str>, _: Option<u64>) -> Option<String> {
    None
}

/// Seeds need a Unix host; elsewhere nothing seeds.
#[cfg(not(unix))]
#[allow(clippy::too_many_arguments)]
pub fn seed_storage(
    _: &std::path::Path,
    _: &str,
    _: &str,
    _: &crate::registry::PullAuth,
    _: Option<u64>,
    _: Option<u64>,
    _: Option<&str>,
    _: Option<&str>,
) -> crate::Result<bool> {
    Ok(false)
}

/// Seeds need a Unix host; on other platforms a trust-aware seed is unavailable.
#[cfg(not(unix))]
#[allow(clippy::too_many_arguments)]
pub fn seed_storage_with_trust(
    _: &std::path::Path,
    _: &str,
    _: &str,
    _: &crate::registry::PullAuth,
    _: Option<u64>,
    _: Option<u64>,
    _: Option<&str>,
    _: Option<&str>,
    _: bool,
) -> crate::Result<bool> {
    Ok(false)
}

#[cfg(not(unix))]
/// Seeds need a Unix host, so other platforms have nothing to revalidate.
pub fn revalidate_seed(_: &str, _: &str, _: &crate::registry::PullAuth) -> crate::Result<bool> {
    Ok(false)
}

#[cfg(unix)]
mod imp {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};

    use sha2::{Digest, Sha256};

    use crate::config::VmRecord;
    use crate::registry::PullAuth;
    use crate::storage::DiskFormat;
    use crate::{Error, Result};

    /// Bumped when the guest's storage layout changes in a way an old seed would not
    /// satisfy.
    const SEED_FORMAT: &str = "image-seed-v2";

    /// Name prefix of the throwaway machines that build seeds.
    pub const SEED_MACHINE_PREFIX: &str = "image-seed-";

    /// A builder machine older than this is left over from a crashed build.
    const STALE_BUILDER_SECS: u64 = 30 * 60;

    /// Default cap on the seed cache before unreferenced seeds are evicted;
    /// `SMOLVM_IMAGE_SEED_MAX_BYTES` overrides it.
    const DEFAULT_MAX_BYTES: u64 = 20 * 1024 * 1024 * 1024;

    /// The image a machine's first start can seed from, or `None` when it cannot
    /// (not a fresh registry-image machine, a clone, a checkpoint restore) or
    /// seeding is off.
    pub fn wants_seed(name: &str, record: &VmRecord, from_snapshot: bool) -> Option<String> {
        if record.init_completed
            || from_snapshot
            || record.source_smolmachine.is_some()
            || record.vm_uid_owner().is_some()
            || record.golden.is_some()
        {
            return None;
        }
        seedable_image(name, record.image.as_deref(), record.storage_gb)
    }

    /// `image` when a machine called `name` with that image and storage size can
    /// start on a seed: a registry image, at least the default storage size (a
    /// larger disk is the seed grown, see [`grow`]), no storage disk yet, and
    /// seeding on.
    pub fn seedable_image(
        name: &str,
        image: Option<&str>,
        storage_gb: Option<u64>,
    ) -> Option<String> {
        // The builder's own machine pulls the normal way.
        if name.starts_with(SEED_MACHINE_PREFIX)
            || std::env::var("SMOLVM_IMAGE_SEEDS").is_ok_and(|v| v.trim() == "0")
            || storage_gb.is_some_and(|gb| gb < crate::storage::DEFAULT_STORAGE_SIZE_GIB)
        {
            return None;
        }
        let image = image?;
        if crate::data::image_source::is_local_ref(image)
            || crate::data::image_source::packed_layers_dir_for_ref(image).is_some()
        {
            return None;
        }
        // An existing disk already holds whatever it pulled.
        let storage = crate::agent::vm_data_dir(name).join(crate::storage::STORAGE_DISK_FILENAME);
        if storage.exists()
            || storage
                .with_extension(DiskFormat::Qcow2.extension())
                .exists()
        {
            return None;
        }
        Some(image.to_string())
    }

    /// One remembered resolution: the digest `image` pointed to for one
    /// credential fingerprint, and when it was resolved.
    #[derive(serde::Serialize, serde::Deserialize)]
    struct CachedDigest {
        image: String,
        digest: String,
        resolved_at_unix: u64,
    }

    /// Cache file for `image` as resolved by `auth`. The credential
    /// fingerprint is part of the name, so a caller only ever reuses a
    /// resolution its own credentials performed. `FromConfig` is one
    /// fingerprint, so a `docker login` change inside the window is not
    /// noticed, same as any other credential change while the TTL runs.
    fn digest_cache_path(image: &str, auth: &PullAuth) -> PathBuf {
        let mut hash = Sha256::new();
        hash.update(image.as_bytes());
        hash.update([0]);
        match auth {
            PullAuth::FromConfig => hash.update(b"from-config"),
            PullAuth::Anonymous => hash.update(b"anonymous"),
            PullAuth::Basic { username, password } => {
                hash.update(b"basic:");
                hash.update(username.as_bytes());
                hash.update([0]);
                hash.update(password.as_bytes());
            }
            PullAuth::Bearer(token) => {
                hash.update(b"bearer:");
                hash.update(token.as_bytes());
            }
            PullAuth::Identity(token) => {
                hash.update(b"identity:");
                hash.update(token.as_bytes());
            }
        }
        seed_root()
            .join("digests")
            .join(format!("{}.json", hex::encode(hash.finalize())))
    }

    /// The digest in `body` when it is for `image` and younger than the TTL.
    pub(super) fn fresh_cached_digest(
        body: &[u8],
        image: &str,
        ttl_secs: u64,
        now_unix: u64,
    ) -> Option<String> {
        let entry: CachedDigest = serde_json::from_slice(body).ok()?;
        // A timestamp in the future means a clock moved; that entry would
        // otherwise read as fresh until wall time caught up past it.
        if entry.image != image
            || entry.resolved_at_unix > now_unix
            || now_unix - entry.resolved_at_unix > ttl_secs
        {
            return None;
        }
        Some(entry.digest)
    }

    /// The digest `image` points to, through the opt-in TTL cache
    /// (`--seed-digest-ttl`). With no TTL (the default) this is exactly
    /// `resolve()`: every first start resolves at the registry, which doubles
    /// as the per-start authorization check. Within a window a moved tag or a
    /// revoked credential is not observed, so the TTL is for tight loops
    /// starting many machines of one image, not a general default.
    fn resolved_digest(
        image: &str,
        auth: &PullAuth,
        digest_ttl: Option<u64>,
        resolve: impl Fn() -> Result<String>,
    ) -> Result<String> {
        let Some(ttl_secs) = digest_ttl.filter(|secs| *secs > 0) else {
            return resolve();
        };
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let path = digest_cache_path(image, auth);
        if let Ok(body) = std::fs::read(&path) {
            if let Some(digest) = fresh_cached_digest(&body, image, ttl_secs, now_unix) {
                return Ok(digest);
            }
        }
        let digest = resolve()?;
        // Best effort: a failed write only means the next start resolves again.
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
            if let Ok(body) = serde_json::to_vec(&CachedDigest {
                image: image.to_string(),
                digest: digest.clone(),
                resolved_at_unix: now_unix,
            }) {
                let tmp = path.with_extension("tmp");
                if std::fs::write(&tmp, body).is_ok() {
                    let _ = std::fs::rename(&tmp, &path);
                }
            }
        }
        Ok(digest)
    }

    /// Give machine `name` a storage disk over the seed for `image`, building the
    /// seed first (with `exe`, this smolvm binary) if its digest has none yet,
    /// and grown to `storage_gb` when that is larger than the seed.
    /// Returns `Ok(false)` when the storage template cannot back a seed.
    #[allow(clippy::too_many_arguments)]
    pub fn seed_storage(
        exe: &Path,
        name: &str,
        image: &str,
        auth: &PullAuth,
        storage_gb: Option<u64>,
        digest_ttl: Option<u64>,
        proxy: Option<&str>,
        no_proxy: Option<&str>,
    ) -> Result<bool> {
        seed_storage_with_trust(
            exe, name, image, auth, storage_gb, digest_ttl, proxy, no_proxy, false,
        )
    }

    /// Build or attach an image seed with host trust in its throwaway builder
    /// when `trust_host_certs` was selected on the parent machine.
    #[allow(clippy::too_many_arguments)]
    pub fn seed_storage_with_trust(
        exe: &Path,
        name: &str,
        image: &str,
        auth: &PullAuth,
        storage_gb: Option<u64>,
        digest_ttl: Option<u64>,
        proxy: Option<&str>,
        no_proxy: Option<&str>,
        trust_host_certs: bool,
    ) -> Result<bool> {
        let EnsuredSeed {
            root,
            key_dir,
            cache,
            built,
        } = ensure_seed(
            exe,
            image,
            auth,
            digest_ttl,
            proxy,
            no_proxy,
            trust_host_certs,
        )?;
        let Some((seed, format)) = seed_disk(&key_dir) else {
            return Err(Error::config(
                "image seed",
                "seed disappeared before overlay creation",
            ));
        };
        attach_seed_disk(name, &seed, format, storage_gb)?;
        // Recently used seeds are the last to be evicted.
        let _ =
            std::fs::File::open(&seed).and_then(|f| f.set_modified(std::time::SystemTime::now()));
        drop(cache);
        note_recent_image(&root, image);
        if built {
            prune(&root, max_bytes(), &seed);
        }
        Ok(true)
    }

    /// The seed directory for `image` once its seed exists, holding the shared
    /// cache lock so prune cannot remove it before the caller attaches it.
    struct EnsuredSeed {
        root: PathBuf,
        key_dir: PathBuf,
        cache: CacheLock,
        built: bool,
    }

    /// Make sure the seed for `image` at its current digest exists, building it
    /// (with `exe`) when it does not.
    fn ensure_seed(
        exe: &Path,
        image: &str,
        auth: &PullAuth,
        digest_ttl: Option<u64>,
        proxy: Option<&str>,
        no_proxy: Option<&str>,
        trust_host_certs: bool,
    ) -> Result<EnsuredSeed> {
        let template = storage_template();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| Error::config("image seed", e.to_string()))?;
        let resolve = || rt.block_on(crate::image_store::authorized_reference_digest(image, auth));
        let digest = resolved_digest(image, auth, digest_ttl, resolve)?;
        let key = seed_key(image, &digest, template.as_deref())?;
        let root = seed_root();
        std::fs::create_dir_all(&root).map_err(|e| Error::config("image seed", e.to_string()))?;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o711))
            .map_err(|e| Error::config("image seed", e.to_string()))?;
        let key_dir = root.join(&key);
        let mut built = false;
        // A cache hit holds the shared lock through overlay publication. Prune
        // takes the exclusive lock before scanning backing references, so it
        // cannot miss an overlay being created and then delete its base.
        let mut cache = CacheLock::shared(&root)?;
        if seed_disk(&key_dir).is_none() {
            drop(cache);
            // One builder per image; concurrent first starts wait for it and
            // then share it. This lock file is permanent: unlinking a locked
            // file would let new callers lock a different inode for this key.
            let _build = Lock::exclusive(&root.join(format!("{key}.lock")))?;
            if seed_disk(&key_dir).is_none() {
                build_seed(
                    exe,
                    image,
                    auth,
                    &key,
                    &key_dir,
                    proxy,
                    no_proxy,
                    trust_host_certs,
                )?;
                // The builder pulled the tag, not the digest. If the tag moved
                // in the meantime, discard the seed rather than miskey it.
                if resolve()? != digest {
                    let _ = std::fs::remove_dir_all(&key_dir);
                    // The cached digest is what moved. Drop it, or every
                    // retry inside the TTL window repeats this build and
                    // fails the same way.
                    let _ = std::fs::remove_file(digest_cache_path(image, auth));
                    return Err(Error::config(
                        "image seed",
                        format!("{image} moved during the seed build"),
                    ));
                }
                built = true;
            }
            cache = CacheLock::shared(&root)?;
        }
        Ok(EnsuredSeed {
            root,
            key_dir,
            cache,
            built,
        })
    }

    /// Give machine `name` its storage disk over `seed`, grown to `storage_gb`.
    fn attach_seed_disk(
        name: &str,
        seed: &Path,
        format: DiskFormat,
        storage_gb: Option<u64>,
    ) -> Result<()> {
        let dir = crate::agent::ensure_vm_dir(name)
            .map_err(|e| Error::config("image seed", e.to_string()))?;
        let storage = dir
            .join(crate::storage::STORAGE_DISK_FILENAME)
            .with_extension(format.extension());
        // Build under a unique name and publish with a no-replace hard link.
        // A failed libkrun call cannot leave a partial final disk, and a
        // concurrent start cannot have its finished disk removed or replaced.
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let staging = dir.join(format!(
            ".seed-disk-{}-{nonce}.{}",
            std::process::id(),
            format.extension()
        ));
        let size_bytes = storage_gb
            .unwrap_or(crate::storage::DEFAULT_STORAGE_SIZE_GIB)
            .saturating_mul(crate::data::consts::BYTES_PER_GIB);
        let created = attach(&staging, seed, format).and_then(|()| {
            grow(&staging, format, size_bytes)?;
            // A clone keeps no link to its seed; record it for revalidation.
            if matches!(format, DiskFormat::Raw) {
                std::fs::write(source_marker(&storage), seed.as_os_str().as_encoded_bytes())
                    .map_err(|e| Error::config("image seed", e.to_string()))?;
            }
            Ok(())
        });
        if let Err(error) = created {
            let _ = std::fs::remove_file(staging);
            return Err(error);
        }
        let published = std::fs::hard_link(&staging, &storage)
            .map_err(|e| Error::config("image seed", e.to_string()));
        let _ = std::fs::remove_file(staging);
        published?;
        if matches!(format, DiskFormat::Raw) {
            // A raw disk without its format marker counts as blank, and the
            // launcher would copy the empty template over the clone.
            std::fs::write(storage.with_extension("formatted"), "1")
                .map_err(|e| Error::config("image seed", e.to_string()))?;
        }
        Ok(())
    }

    /// Images whose seeds machines used recently, newest first: what to rebuild
    /// after a new smolvm version invalidates every seed.
    const RECENT_IMAGES: &str = ".recent-images.json";
    /// Images the index remembers.
    const RECENT_IMAGES_KEPT: usize = 32;
    /// How far back a seed counts as recently used for prewarming.
    pub(super) const PREWARM_WINDOW_SECS: u64 = 7 * 24 * 60 * 60;
    /// Seeds rebuilt at most per prewarm, so a server start does not spend
    /// long building images nobody needs.
    const PREWARM_MAX_IMAGES: usize = 8;

    pub(super) fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }

    fn read_recent_images(root: &Path) -> Vec<(String, u64)> {
        std::fs::read(root.join(RECENT_IMAGES))
            .ok()
            .and_then(|raw| serde_json::from_slice::<Vec<(String, u64)>>(&raw).ok())
            .unwrap_or_default()
    }

    /// Record that a machine just used the seed for `image`. Best effort: the
    /// index only steers prewarming.
    pub(super) fn note_recent_image(root: &Path, image: &str) {
        let Ok(_lock) = Lock::exclusive(&root.join(".recent-images.lock")) else {
            return;
        };
        let mut images = read_recent_images(root);
        images.retain(|(seen, _)| seen != image);
        images.insert(0, (image.to_string(), now_secs()));
        images.truncate(RECENT_IMAGES_KEPT);
        let staging = root.join(format!("{RECENT_IMAGES}.{}.tmp", std::process::id()));
        let written = serde_json::to_vec(&images)
            .map_err(std::io::Error::other)
            .and_then(|raw| std::fs::write(&staging, raw))
            .and_then(|()| std::fs::rename(&staging, root.join(RECENT_IMAGES)));
        if written.is_err() {
            let _ = std::fs::remove_file(&staging);
        }
    }

    /// The images to prewarm: used within the window, newest first, capped.
    pub(super) fn prewarm_candidates(root: &Path, now: u64) -> Vec<String> {
        read_recent_images(root)
            .into_iter()
            .filter(|(_, used)| now.saturating_sub(*used) <= PREWARM_WINDOW_SECS)
            .map(|(image, _)| image)
            .take(PREWARM_MAX_IMAGES)
            .collect()
    }

    /// Build seeds for the images machines used recently on this host, so the
    /// first machine of each after an upgrade (whose version change made every
    /// seed stale) does not wait for a build. Runs the builds one at a time;
    /// an image this host cannot pull without the machine's own credentials is
    /// skipped and seeds on its next machine as before.
    pub fn prewarm_recent_seeds(exe: &Path) {
        let root = seed_root();
        for image in prewarm_candidates(&root, now_secs()) {
            let started = std::time::Instant::now();
            match ensure_seed(exe, &image, &PullAuth::FromConfig, None, None, None, false) {
                Ok(EnsuredSeed { built, .. }) => tracing::info!(
                    %image,
                    built,
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "prewarmed image seed"
                ),
                Err(error) => {
                    tracing::info!(%image, %error, "could not prewarm image seed; it seeds on first use")
                }
            }
        }
    }

    /// Reauthorize a seed attached at API create with the credentials supplied
    /// at start. A moved tag or denied request discards the untouched overlay;
    /// the start path can then seed again or let the guest pull normally.
    pub fn revalidate_seed(name: &str, image: &str, auth: &PullAuth) -> Result<bool> {
        let dir = crate::agent::vm_data_dir(name);
        let base = dir.join(crate::storage::STORAGE_DISK_FILENAME);
        let qcow2 = base.with_extension(DiskFormat::Qcow2.extension());
        let (storage, backing) = match qcow2_backing(&qcow2) {
            Some(backing) => (qcow2, backing),
            None => match std::fs::read(source_marker(&base)) {
                // SAFETY: written by `seed_storage` from an `OsStr` on this host.
                Ok(bytes) => (
                    base.clone(),
                    PathBuf::from(unsafe {
                        std::ffi::OsString::from_encoded_bytes_unchecked(bytes)
                    }),
                ),
                Err(_) => return Ok(false),
            },
        };
        let root = seed_root();
        let Some(key_dir) = backing.parent() else {
            return Ok(false);
        };
        if key_dir.parent() != Some(root.as_path())
            || seed_disk(key_dir).is_none_or(|(seed, _)| seed.file_name() != backing.file_name())
        {
            return Ok(false);
        }
        let expected = (|| -> Result<PathBuf> {
            let template = storage_template();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| Error::config("image seed", e.to_string()))?;
            let digest =
                rt.block_on(crate::image_store::authorized_reference_digest(image, auth))?;
            let key_dir = root.join(seed_key(image, &digest, template.as_deref())?);
            seed_disk(&key_dir)
                .map(|(seed, _)| seed)
                .ok_or_else(|| Error::config("image seed", "no seed for the authorized digest"))
        })();
        match expected {
            Ok(expected)
                if expected.canonicalize().ok() == backing.canonicalize().ok()
                    && backing.is_file() =>
            {
                Ok(true)
            }
            result => {
                // Only a fresh machine's storage overlay is passed here. Do not
                // leave unauthorized or stale image contents for the guest.
                std::fs::remove_file(&storage)
                    .map_err(|e| Error::config("image seed", e.to_string()))?;
                let _ = std::fs::remove_file(source_marker(&base));
                result?;
                Ok(false)
            }
        }
    }

    /// Pull `image` once in a throwaway machine that never runs a workload, and
    /// publish its storage disk as the seed.
    #[allow(clippy::too_many_arguments)]
    fn build_seed(
        exe: &Path,
        image: &str,
        auth: &PullAuth,
        key: &str,
        key_dir: &Path,
        proxy: Option<&str>,
        no_proxy: Option<&str>,
        trust_host_certs: bool,
    ) -> Result<()> {
        reap_stale_builders(exe);
        let tmp = format!("{SEED_MACHINE_PREFIX}{}-{}", &key[..16], std::process::id());
        let _ = run(exe, &["machine", "delete", "--name", &tmp, "-f"]);
        // Set once the builder's disk format is known.
        let mut staged: Option<(PathBuf, PathBuf)> = None;
        let started = std::time::Instant::now();
        let built = (|| -> Result<()> {
            let mut create = vec![
                "machine", "create", "--name", &tmp, "--image", image, "--net",
            ];
            if trust_host_certs {
                create.push("--trust-host-certs");
            }
            run(exe, &create)?;
            let mut start = vec!["machine", "start", "--name", &tmp, "--no-workload"];
            if let Some(proxy) = proxy {
                start.extend(["--proxy", proxy]);
            }
            if let Some(no_proxy) = no_proxy {
                start.extend(["--no-proxy", no_proxy]);
            }
            run(exe, &start)?;
            // Compare the guest's stored config and layer digests to the
            // caller-authorized platform manifest. A second HEAD alone misses
            // tag ABA and a registry mirror serving different image bytes.
            let manager = crate::agent::AgentManager::for_vm(&tmp)?;
            let mut client = manager.connect()?;
            let pulled = client
                .query(image)?
                .ok_or_else(|| Error::config("image seed", "builder did not cache its image"))?;
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| Error::config("image seed", e.to_string()))?;
            let (config, layers) =
                rt.block_on(crate::image_store::authorized_image_content(image, auth))?;
            if pulled.digest != config || pulled.layers != layers {
                return Err(Error::config(
                    "image seed",
                    "builder image differs from authorized registry image",
                ));
            }
            run(exe, &["machine", "stop", "--name", &tmp])?;
            // A template overlay where the host has a sized template, else the
            // builder's own raw disk.
            let builder = crate::agent::vm_data_dir(&tmp);
            let (disk, format) = seed_disk_in(&builder, crate::storage::STORAGE_DISK_FILENAME)
                .ok_or_else(|| Error::config("image seed", "the builder has no storage disk"))?;
            std::fs::create_dir_all(key_dir)
                .map_err(|e| Error::config("image seed", e.to_string()))?;
            std::fs::set_permissions(key_dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| Error::config("image seed", e.to_string()))?;
            let seed = key_dir.join(seed_file(format));
            let staging =
                seed.with_extension(format!("{}.{}", format.extension(), std::process::id()));
            std::fs::rename(&disk, &staging)
                .map_err(|e| Error::config("image seed", e.to_string()))?;
            staged = Some((staging, seed));
            Ok(())
        })();
        let _ = run(exe, &["machine", "delete", "--name", &tmp, "-f"]);
        let published = built.and_then(|()| {
            let (staging, seed) = staged.as_ref().expect("a built seed is staged");
            publish(staging, seed)
        });
        if published.is_err() {
            if let Some((staging, _)) = &staged {
                let _ = std::fs::remove_file(staging);
            }
        }
        published?;
        tracing::info!(
            image,
            key,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "built image seed"
        );
        Ok(())
    }

    /// Publish the seed privately. A dropped VMM uid sees its selected seed
    /// through a read-only idmapped mount in its private mount namespace.
    fn publish(staging: &Path, seed: &Path) -> Result<()> {
        let seed_error = |e: std::io::Error| Error::config("image seed", e.to_string());
        let file = std::fs::File::open(staging).map_err(seed_error)?;
        if unsafe { libc::fchown(file.as_raw_fd(), libc::geteuid(), libc::getegid()) } != 0 {
            return Err(seed_error(std::io::Error::last_os_error()));
        }
        file.sync_all().map_err(seed_error)?;
        std::fs::set_permissions(staging, std::fs::Permissions::from_mode(0o400))
            .map_err(seed_error)?;
        std::fs::set_permissions(
            seed.parent().expect("seed path has a parent"),
            std::fs::Permissions::from_mode(0o700),
        )
        .map_err(seed_error)?;
        std::fs::rename(staging, seed).map_err(seed_error)
    }

    /// A seed depends on the exact template bytes under it, the image content, the
    /// guest architecture and the guest's storage layout.
    pub(super) fn seed_key(image: &str, digest: &str, template: Option<&Path>) -> Result<String> {
        // Without a template the disk is formatted by this smolvm version,
        // which the key already carries.
        let (path, identity) = match template {
            Some(template) => {
                let meta = std::fs::metadata(template)
                    .map_err(|e| Error::config("image seed", e.to_string()))?;
                (
                    template.display().to_string(),
                    format!(
                        "{}:{}:{}:{}",
                        meta.dev(),
                        meta.ino(),
                        meta.len(),
                        meta.mtime()
                    ),
                )
            }
            None => (String::from("no-template"), String::new()),
        };
        let mut hash = Sha256::new();
        for part in [
            SEED_FORMAT,
            env!("CARGO_PKG_VERSION"),
            image,
            digest,
            std::env::consts::ARCH,
            &path,
            &identity,
        ] {
            hash.update(part.as_bytes());
            hash.update([0]);
        }
        Ok(hex::encode(hash.finalize()))
    }

    /// The storage template a machine's disk starts from, if the host has one.
    /// Its identity is part of the seed key.
    fn storage_template() -> Option<PathBuf> {
        smolvm_pack::assets::find_existing_template("storage-template.ext4")?
            .canonicalize()
            .ok()
    }

    /// A seed's file name: `storage.qcow2` over the template, `storage.raw` as a
    /// standalone disk.
    fn seed_file(format: DiskFormat) -> String {
        format!("storage.{}", format.extension())
    }

    /// The published seed in `key_dir`, and its format.
    fn seed_disk(key_dir: &Path) -> Option<(PathBuf, DiskFormat)> {
        seed_disk_in(key_dir, "storage")
    }

    #[cfg(test)]
    pub(super) fn seed_disk_for_test(key_dir: &Path) -> Option<PathBuf> {
        seed_disk(key_dir).map(|(seed, _)| seed)
    }

    /// The storage disk named `stem` in `dir` (either extension), preferring a
    /// template overlay.
    fn seed_disk_in(dir: &Path, stem: &str) -> Option<(PathBuf, DiskFormat)> {
        let base = dir.join(stem);
        [DiskFormat::Qcow2, DiskFormat::Raw]
            .into_iter()
            .map(|format| (base.with_extension(format.extension()), format))
            .find(|(path, _)| path.is_file())
    }

    /// Where a raw clone records the seed it came from.
    fn source_marker(storage: &Path) -> PathBuf {
        storage.with_extension("seed")
    }

    /// Make `staging` a new machine's storage on `seed`: a qcow2 overlay on a
    /// template-overlay seed, a copy-on-write clone of a raw one.
    fn attach(staging: &Path, seed: &Path, format: DiskFormat) -> Result<()> {
        if matches!(format, DiskFormat::Qcow2) {
            return crate::agent::create_disk_overlays(&[(
                staging.to_path_buf(),
                seed.to_path_buf(),
                DiskFormat::Qcow2,
            )]);
        }
        clone_raw(seed, staging)?;
        // The clone keeps the seed's read-only mode; the machine writes its disk.
        std::fs::set_permissions(staging, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| Error::config("image seed", e.to_string()))
    }

    /// Grow a freshly attached disk to `size_bytes` (sparse; never shrinks). The
    /// guest grows the seed's ext4 into the new space at boot, as it does for a
    /// template disk, so a larger machine starts from the same seed.
    pub(super) fn grow(disk: &Path, format: DiskFormat, size_bytes: u64) -> Result<()> {
        let fail = |e: std::io::Error| Error::config("grow seeded disk", e.to_string());
        match format {
            DiskFormat::Raw => {
                let file = std::fs::OpenOptions::new()
                    .write(true)
                    .open(disk)
                    .map_err(fail)?;
                if file.metadata().map_err(fail)?.len() < size_bytes {
                    file.set_len(size_bytes).map_err(fail)?;
                }
                Ok(())
            }
            DiskFormat::Qcow2 => {
                use imago::FormatDriverBuilder;
                let qcow = imago::qcow2::Qcow2::<imago::file::File>::builder_path(disk)
                    .write(true)
                    .open_sync(imago::PermissiveImplicitOpenGate::default())
                    .map_err(fail)?;
                let access = imago::SyncFormatAccess::new(qcow).map_err(fail)?;
                if access.size() < size_bytes {
                    access
                        .resize_grow(size_bytes, imago::format::PreallocateMode::None)
                        .map_err(fail)?;
                }
                access.flush().map_err(fail)
            }
        }
    }

    /// An APFS clone. Never a full copy: that would write the whole 20 GiB disk,
    /// far slower than the pull it replaces.
    #[cfg(target_os = "macos")]
    fn clone_raw(seed: &Path, staging: &Path) -> Result<()> {
        use std::os::unix::ffi::OsStrExt;
        let path = |p: &Path| {
            std::ffi::CString::new(p.as_os_str().as_bytes())
                .map_err(|e| Error::config("image seed", e.to_string()))
        };
        let (src, dst) = (path(seed)?, path(staging)?);
        if unsafe { libc::clonefile(src.as_ptr(), dst.as_ptr(), 0) } != 0 {
            return Err(Error::config(
                "image seed",
                format!("clone seed: {}", std::io::Error::last_os_error()),
            ));
        }
        Ok(())
    }

    /// A reflink where the filesystem has one, else a copy of only the seed's
    /// data (the pulled image), skipping its holes.
    #[cfg(not(target_os = "macos"))]
    fn clone_raw(seed: &Path, staging: &Path) -> Result<()> {
        crate::disk_utils::clone_or_copy_file(seed, staging)
    }

    /// `~/.cache/smolvm/image-seeds`.
    pub fn seed_root() -> PathBuf {
        crate::agent::vm_cache_root()
            .parent()
            .map(|root| root.join("image-seeds"))
            .unwrap_or_else(|| PathBuf::from("/tmp/smolvm-image-seeds"))
    }

    fn max_bytes() -> u64 {
        std::env::var("SMOLVM_IMAGE_SEED_MAX_BYTES")
            .ok()
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(DEFAULT_MAX_BYTES)
    }

    /// Evict least recently used seeds while the cache is over `max_bytes`. A seed
    /// is only evicted when no disk image under smolvm's cache backs onto it: every
    /// machine, fork generation and paused disk that uses one keeps it.
    fn prune(root: &Path, max_bytes: u64, keep: &Path) {
        let Ok(_cache) = CacheLock::exclusive(root) else {
            return;
        };
        let Ok(entries) = std::fs::read_dir(root) else {
            return;
        };
        let mut seeds: Vec<(PathBuf, u64, std::time::SystemTime)> = entries
            .flatten()
            .filter_map(|entry| seed_disk(&entry.path()).map(|(seed, _)| seed))
            .filter_map(|seed| {
                let meta = std::fs::metadata(&seed).ok()?;
                Some((seed, meta.blocks() * 512, meta.modified().ok()?))
            })
            .collect();
        let mut total: u64 = seeds.iter().map(|(_, bytes, _)| bytes).sum();
        if total <= max_bytes {
            return;
        }
        let Ok(referenced) = backing_references(
            &crate::agent::vm_cache_root()
                .parent()
                .map_or_else(crate::agent::vm_cache_root, Path::to_path_buf),
        ) else {
            // An incomplete scan cannot prove an old seed is unreferenced.
            return;
        };
        seeds.sort_by_key(|(_, _, used)| *used);
        for (seed, bytes, _) in seeds {
            if total <= max_bytes {
                break;
            }
            let canonical = seed.canonicalize().unwrap_or_else(|_| seed.clone());
            if seed == keep || referenced.contains(&canonical) {
                continue;
            }
            let dir = seed.parent().expect("seed path has a parent");
            let lock = root.join(format!(
                "{}.lock",
                dir.file_name().unwrap_or_default().to_string_lossy()
            ));
            // Skip a seed another process is building or about to use.
            let Some(_lock) = Lock::try_exclusive(&lock) else {
                continue;
            };
            if std::fs::remove_dir_all(dir).is_ok() {
                total = total.saturating_sub(bytes);
                tracing::info!(seed = %seed.display(), "evicted image seed");
            }
        }
    }

    /// Every backing file named by a qcow2 image under `dir`, recursively (seeds
    /// themselves excluded).
    fn backing_references(dir: &Path) -> std::io::Result<std::collections::HashSet<PathBuf>> {
        let mut found = std::collections::HashSet::new();
        let mut stack = vec![dir.to_path_buf()];
        let seeds = seed_root();
        while let Some(dir) = stack.pop() {
            let entries = std::fs::read_dir(&dir)?;
            for entry in entries {
                let entry = entry?;
                let path = entry.path();
                let kind = entry.file_type()?;
                if kind.is_dir() {
                    if path != seeds {
                        stack.push(path);
                    }
                } else if kind.is_file() {
                    if path.extension().is_some_and(|ext| ext == "qcow2") {
                        // Treat unreadable disk headers as an incomplete scan.
                        let _ = std::fs::File::open(&path)?;
                    }
                    if let Some(backing) = qcow2_backing(&path) {
                        let backing = if backing.is_absolute() {
                            backing
                        } else {
                            dir.join(backing)
                        };
                        found.insert(backing.canonicalize().unwrap_or(backing));
                    }
                }
            }
        }
        Ok(found)
    }

    /// The backing file a qcow2 image names in its header, if it is one.
    pub(super) fn qcow2_backing(path: &Path) -> Option<PathBuf> {
        use std::io::{Read, Seek, SeekFrom};
        use std::os::unix::ffi::OsStrExt;
        let mut file = std::fs::File::open(path).ok()?;
        let mut header = [0u8; 20];
        file.read_exact(&mut header).ok()?;
        if header[..4] != *b"QFI\xfb" {
            return None;
        }
        let offset = u64::from_be_bytes(header[8..16].try_into().ok()?);
        let len = u32::from_be_bytes(header[16..20].try_into().ok()?) as usize;
        if offset == 0 || len == 0 || len > 4096 {
            return None;
        }
        let mut name = vec![0u8; len];
        file.seek(SeekFrom::Start(offset)).ok()?;
        file.read_exact(&mut name).ok()?;
        Some(PathBuf::from(std::ffi::OsStr::from_bytes(&name)))
    }

    /// Delete builder machines left behind by a build that crashed.
    fn reap_stale_builders(exe: &Path) {
        let Ok(config) = crate::config::SmolvmConfig::load() else {
            return;
        };
        let now = crate::util::current_timestamp();
        let stale: Vec<String> = config
            .list_vms()
            .filter(|(name, _)| name.starts_with(SEED_MACHINE_PREFIX))
            .filter(|(_, record)| now.saturating_sub(record.created_at) >= STALE_BUILDER_SECS)
            .map(|(name, _)| name.clone())
            .collect();
        for name in stale {
            let _ = run(exe, &["machine", "delete", "--name", &name, "-f"]);
        }
    }

    /// Run one step of a seed build with this smolvm binary, capturing its output so
    /// the builder's chatter stays off the caller's terminal.
    fn run(exe: &Path, args: &[&str]) -> Result<()> {
        let out = std::process::Command::new(exe)
            .args(args)
            .env("SMOLVM_IMAGE_SEEDS", "0")
            // An embedder's helper variable would tie the builder VM's life to
            // this short-lived CLI process, killing it as soon as `start` returns.
            .env_remove("SMOLVM_BOOT_BINARY")
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|e| Error::config("image seed", e.to_string()))?;
        if out.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&out.stderr);
        let tail: Vec<&str> = stderr.lines().filter(|l| !l.trim().is_empty()).collect();
        Err(Error::config(
            "image seed",
            format!(
                "`smolvm {}` failed ({}): {}",
                args.join(" "),
                out.status,
                tail[tail.len().saturating_sub(6)..].join("\n")
            ),
        ))
    }

    struct Lock(std::fs::File);

    struct CacheLock {
        _lock: Lock,
    }

    impl CacheLock {
        fn shared(root: &Path) -> Result<Self> {
            Lock::with_mode(&root.join(".cache.lock"), libc::LOCK_SH)
                .map(|lock| Self { _lock: lock })
        }

        fn exclusive(root: &Path) -> Result<Self> {
            Lock::with_mode(&root.join(".cache.lock"), libc::LOCK_EX)
                .map(|lock| Self { _lock: lock })
        }
    }

    impl Lock {
        fn open(path: &Path) -> Result<std::fs::File> {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .write(true)
                .open(path)
                .map_err(|e| Error::config("image seed lock", e.to_string()))
        }

        fn with_mode(path: &Path, mode: libc::c_int) -> Result<Self> {
            let file = Self::open(path)?;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|e| Error::config("image seed lock", e.to_string()))?;
            if unsafe { libc::flock(file.as_raw_fd(), mode) } != 0 {
                return Err(Error::config(
                    "image seed lock",
                    std::io::Error::last_os_error().to_string(),
                ));
            }
            Ok(Self(file))
        }

        fn exclusive(path: &Path) -> Result<Self> {
            Self::with_mode(path, libc::LOCK_EX)
        }

        fn try_exclusive(path: &Path) -> Option<Self> {
            let file = Self::open(path).ok()?;
            (unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0)
                .then_some(Self(file))
        }
    }

    impl Drop for Lock {
        fn drop(&mut self) {
            let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::imp::*;
    use std::path::PathBuf;

    #[test]
    fn recently_used_images_are_prewarmed_newest_first_within_the_window() {
        let root = tempfile::tempdir().unwrap();
        assert!(prewarm_candidates(root.path(), 0).is_empty());
        note_recent_image(root.path(), "alpine");
        note_recent_image(root.path(), "docker:dind");
        note_recent_image(root.path(), "alpine"); // used again: moves to the front
        let now = now_secs();
        assert_eq!(
            prewarm_candidates(root.path(), now),
            vec!["alpine".to_string(), "docker:dind".to_string()]
        );
        // Outside the window, nothing is prewarmed.
        assert!(prewarm_candidates(root.path(), now + PREWARM_WINDOW_SECS + 1).is_empty());
    }

    #[test]
    fn a_larger_disk_seeds_and_a_smaller_one_pulls() {
        let default = crate::storage::DEFAULT_STORAGE_SIZE_GIB;
        let name = "seed-size-gate-test";
        assert!(seedable_image(name, Some("alpine"), None).is_some());
        assert!(seedable_image(name, Some("alpine"), Some(default)).is_some());
        assert!(seedable_image(name, Some("alpine"), Some(default * 5)).is_some());
        assert!(seedable_image(name, Some("alpine"), Some(default - 1)).is_none());
    }

    #[test]
    fn a_seeded_disk_grows_to_the_requested_size_and_keeps_the_seed() {
        use crate::storage::DiskFormat;
        use imago::{FormatCreateBuilder, FormatDriverBuilder};
        const MIB: u64 = 1024 * 1024;
        let dir = tempfile::tempdir().unwrap();

        // A raw clone grows sparsely and keeps its bytes.
        let raw = dir.path().join("storage.raw");
        std::fs::write(&raw, b"seeded").unwrap();
        grow(&raw, DiskFormat::Raw, 64 * MIB).unwrap();
        assert_eq!(std::fs::metadata(&raw).unwrap().len(), 64 * MIB);
        assert_eq!(&std::fs::read(&raw).unwrap()[..6], b"seeded");
        // Never shrinks.
        grow(&raw, DiskFormat::Raw, MIB).unwrap();
        assert_eq!(std::fs::metadata(&raw).unwrap().len(), 64 * MIB);

        // A qcow2 overlay over a seed grows its virtual size and still reads
        // the seed through its backing.
        let base = dir.path().join("seed.raw");
        let mut seed = vec![0_u8; (16 * MIB) as usize];
        seed[..6].copy_from_slice(b"seeded");
        std::fs::write(&base, &seed).unwrap();
        let overlay = dir.path().join("storage.qcow2");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&overlay)
            .unwrap();
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(
                imago::qcow2::Qcow2::<imago::file::File>::create_builder(
                    imago::file::File::try_from(file).unwrap(),
                )
                .size(16 * MIB)
                .backing("seed.raw".to_string(), "raw".to_string())
                .create(),
            )
            .unwrap();
        grow(&overlay, DiskFormat::Qcow2, 64 * MIB).unwrap();
        let qcow = imago::qcow2::Qcow2::<imago::file::File>::builder_path(&overlay)
            .open_sync(imago::PermissiveImplicitOpenGate::default())
            .unwrap();
        let access = imago::SyncFormatAccess::new(qcow).unwrap();
        assert_eq!(access.size(), 64 * MIB);
        let mut head = [0_u8; 6];
        access.read(&mut head[..], 0).unwrap();
        assert_eq!(&head, b"seeded");
        let mut tail = [0xff_u8; 4];
        access.read(&mut tail[..], 64 * MIB - 4).unwrap();
        assert_eq!(tail, [0; 4]);
    }

    #[test]
    fn a_started_machine_does_not_seed_again() {
        let mut record = crate::config::VmRecord::new(
            "seed-test-started-machine".to_string(),
            1,
            512,
            vec![],
            vec![],
            false,
        );
        record.image = Some("alpine:3.20".to_string());
        record.mark_image_on_storage();
        assert_eq!(wants_seed(&record.name, &record, false), None);
    }

    #[test]
    fn key_changes_with_digest_and_image() {
        let template = std::env::temp_dir().join("seed-key-template");
        std::fs::write(&template, b"t").unwrap();
        let template = Some(template.as_path());
        let a = seed_key("alpine", "sha256:aa", template).unwrap();
        assert_eq!(a, seed_key("alpine", "sha256:aa", template).unwrap());
        assert_ne!(a, seed_key("alpine", "sha256:bb", template).unwrap());
        assert_ne!(a, seed_key("busybox", "sha256:aa", template).unwrap());
        // A raw seed built without a template never answers for one built on it.
        let bare = seed_key("alpine", "sha256:aa", None).unwrap();
        assert_ne!(a, bare);
        assert_eq!(bare, seed_key("alpine", "sha256:aa", None).unwrap());
    }

    #[test]
    fn finds_a_seed_of_either_format_preferring_the_overlay() {
        let dir = tempfile::tempdir().unwrap();
        assert!(seed_disk_for_test(dir.path()).is_none());
        std::fs::write(dir.path().join("storage.raw"), b"raw").unwrap();
        assert_eq!(
            seed_disk_for_test(dir.path()),
            Some(dir.path().join("storage.raw"))
        );
        std::fs::write(dir.path().join("storage.qcow2"), b"qcow2").unwrap();
        assert_eq!(
            seed_disk_for_test(dir.path()),
            Some(dir.path().join("storage.qcow2"))
        );
    }

    #[test]
    fn reads_qcow2_backing_and_ignores_other_files() {
        let dir = tempfile::tempdir().unwrap();
        let backing = b"/seeds/k/storage.qcow2";
        let mut image = vec![0u8; 512];
        image[..4].copy_from_slice(b"QFI\xfb");
        image[8..16].copy_from_slice(&256u64.to_be_bytes());
        image[16..20].copy_from_slice(&(backing.len() as u32).to_be_bytes());
        image[256..256 + backing.len()].copy_from_slice(backing);
        std::fs::write(dir.path().join("a.qcow2"), &image).unwrap();
        std::fs::write(dir.path().join("b.raw"), b"not an image").unwrap();
        assert_eq!(
            qcow2_backing(&dir.path().join("a.qcow2")),
            Some(PathBuf::from("/seeds/k/storage.qcow2"))
        );
        assert_eq!(qcow2_backing(&dir.path().join("b.raw")), None);
    }

    #[test]
    fn cached_digest_honors_image_and_ttl() {
        let body = serde_json::json!({
            "image": "alpine",
            "digest": "sha256:aa",
            "resolved_at_unix": 1000
        })
        .to_string();
        let body = body.as_bytes();
        // Fresh: 60 s old inside a 300 s window.
        assert_eq!(
            fresh_cached_digest(body, "alpine", 300, 1060),
            Some("sha256:aa".into())
        );
        // Stale: 400 s old.
        assert_eq!(fresh_cached_digest(body, "alpine", 300, 1400), None);
        // A different image never reuses the entry.
        assert_eq!(fresh_cached_digest(body, "busybox", 300, 1060), None);
        // A future timestamp (clock moved) reads as a miss.
        assert_eq!(fresh_cached_digest(body, "alpine", 300, 900), None);
        // Garbage reads as a miss, not an error.
        assert_eq!(fresh_cached_digest(b"not json", "alpine", 300, 1060), None);
    }
}
