//! Image archive support.
//!
//! Stages a Docker-format image archive produced by `docker save` /
//! `podman save` — piped on stdin (`-`) or stored as a `.tar`/`.tar.gz` file —
//! into a content-addressed cache directory, then hands that directory to the
//! VM through the established `packed_layers_dir` virtiofs mount.
//!
//! smolvm stays strictly on the image-source / transport side: it hashes the
//! archive bytes for caching and stages the raw tar. It never parses layers,
//! decompresses, or assembles a rootfs on the host — the in-VM `crane` does
//! that (see the agent's `materialize_image_archive`), exactly as it does for a
//! registry pull. This keeps archive/extraction responsibilities delegated to
//! existing OCI tooling rather than baked into smolvm.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// Marker written once an archive has been fully staged into its cache dir.
const STAGE_MARKER: &str = ".smolvm-archive";

/// Filename the archive is staged as inside its cache dir. Must match the
/// agent's `IMAGE_ARCHIVE_FILE`, which the agent looks for to switch into
/// crane-based archive-ingest mode.
const ARCHIVE_FILE: &str = "archive.tar";

/// True when `image_ref` denotes an image archive (stdin pipe, `.tar`/`.tar.gz`
/// file, or a resolved `local:<hash>` cache reference) rather than a remote
/// registry reference.
pub fn is_image_archive(image_ref: &str) -> bool {
    image_ref == "-"
        || image_ref.starts_with("local:")
        || image_ref.ends_with(".tar")
        || image_ref.ends_with(".tar.gz")
}

/// Stage an image archive for mounting via virtiofs.
///
/// Accepts a stdin pipe (`-`), a `.tar`/`.tar.gz` file path, or an
/// already-resolved `local:<sha256>` cache reference. Returns the path to the
/// cache directory holding the raw archive (to mount through
/// `packed_layers_dir`) and the canonical `local:<sha256>` reference that
/// callers should persist so subsequent boots resolve straight from the cache.
pub fn prepare_image_archive(image_ref: &str) -> Result<(PathBuf, String)> {
    // Already-resolved cache reference (e.g. on `machine start`): the source
    // archive is gone, so this must resolve from the cache or fail clearly.
    if let Some(hash) = image_ref.strip_prefix("local:") {
        let dir = cache_dir(hash)?;
        if is_staged(&dir) {
            return Ok((dir, image_ref.to_string()));
        }
        return Err(Error::config(
            "prepare_image_archive",
            format!(
                "cached image archive '{image_ref}' not found. Re-pipe the source archive (e.g. `docker save IMAGE | smolvm ...`)."
            ),
        ));
    }

    // Hash the archive bytes (the cache key). A stdin stream is single-pass, so
    // it is buffered to a tempfile while hashing; on-disk archives are hashed in
    // place. Either way the raw archive is then staged into the cache as
    // `archive.tar` for the agent to flatten with crane.
    if image_ref == "-" {
        // Buffer into the cache base so the later `persist` (a rename) stays on
        // the same filesystem as the destination.
        let base = cache_base()?;
        fs::create_dir_all(&base).map_err(|e| {
            Error::config(
                "prepare_image_archive",
                format!("failed to create cache dir: {e}"),
            )
        })?;
        let mut tmp = tempfile::NamedTempFile::new_in(&base).map_err(|e| {
            Error::config(
                "prepare_image_archive",
                format!("failed to create temp file: {e}"),
            )
        })?;
        let mut stdin = std::io::stdin().lock();
        let hash = buffer_and_hash(&mut stdin, tmp.as_file_mut())?;
        let dir = cache_dir(&hash)?;
        let resolved = format!("local:{hash}");
        if is_staged(&dir) {
            return Ok((dir, resolved));
        }
        stage(&dir, |dest| {
            tmp.persist(dest).map(|_| ()).map_err(|e| {
                Error::config(
                    "prepare_image_archive",
                    format!("failed to persist staged archive: {e}"),
                )
            })
        })?;
        Ok((dir, resolved))
    } else {
        let path = Path::new(image_ref);
        if !path.exists() {
            return Err(Error::config(
                "prepare_image_archive",
                format!("image archive not found: {image_ref}"),
            ));
        }
        let hash = hash_file(path)?;
        let dir = cache_dir(&hash)?;
        let resolved = format!("local:{hash}");
        if is_staged(&dir) {
            return Ok((dir, resolved));
        }
        stage(&dir, |dest| link_or_copy(path, dest))?;
        Ok((dir, resolved))
    }
}

/// Resolve an optional image reference, staging it when it is a local image
/// archive (stdin pipe, `.tar`/`.tar.gz` file, or resolved `local:<hash>`).
///
/// Returns `Some((packed_layers_dir, resolved_ref))` for archives — the cache
/// directory to mount via virtiofs and the canonical `local:<hash>` reference
/// to persist — or `None` when `image` is absent or a normal registry ref.
pub fn resolve_if_archive(image: Option<&str>) -> Result<Option<(PathBuf, String)>> {
    match image {
        Some(img) if is_image_archive(img) => prepare_image_archive(img).map(Some),
        _ => Ok(None),
    }
}

/// `~/.cache/smolvm/image-archives`.
fn cache_base() -> Result<PathBuf> {
    let base = cache_root()
        .ok_or_else(|| Error::config("prepare_image_archive", "no cache directory available"))?;
    Ok(base.join("smolvm").join("image-archives"))
}

/// `~/.cache/smolvm/image-archives/<hash>`.
fn cache_dir(hash: &str) -> Result<PathBuf> {
    Ok(cache_base()?.join(hash))
}

#[cfg(not(test))]
fn cache_root() -> Option<PathBuf> {
    dirs::cache_dir()
}

/// In tests, an optional per-thread cache root keeps the content-addressed
/// cache inside a tempdir instead of the real `~/.cache`.
#[cfg(test)]
fn cache_root() -> Option<PathBuf> {
    tests::CACHE_ROOT_OVERRIDE
        .with(|c| c.borrow().clone())
        .or_else(dirs::cache_dir)
}

/// True when `dir` holds a fully staged archive (both the tar and its marker).
fn is_staged(dir: &Path) -> bool {
    dir.join(STAGE_MARKER).exists() && dir.join(ARCHIVE_FILE).exists()
}

/// Stage an archive into `dir` by running `place` to put the bytes at
/// `dir/archive.tar`, then writing the completion marker. Any partial state is
/// cleaned up on failure so the next attempt starts fresh.
fn stage<F>(dir: &Path, place: F) -> Result<()>
where
    F: FnOnce(&Path) -> Result<()>,
{
    if dir.exists() {
        let _ = fs::remove_dir_all(dir);
    }
    fs::create_dir_all(dir).map_err(|e| {
        Error::config(
            "prepare_image_archive",
            format!("failed to create cache dir: {e}"),
        )
    })?;

    let archive_path = dir.join(ARCHIVE_FILE);
    if let Err(e) = place(&archive_path) {
        let _ = fs::remove_dir_all(dir);
        return Err(e);
    }

    if let Err(e) = fs::write(dir.join(STAGE_MARKER), b"") {
        let _ = fs::remove_dir_all(dir);
        return Err(Error::config(
            "prepare_image_archive",
            format!("failed to write stage marker: {e}"),
        ));
    }
    Ok(())
}

/// Hardlink `src` to `dest`, falling back to a copy across filesystems.
fn link_or_copy(src: &Path, dest: &Path) -> Result<()> {
    if fs::hard_link(src, dest).is_ok() {
        return Ok(());
    }
    fs::copy(src, dest).map(|_| ()).map_err(|e| {
        Error::config(
            "prepare_image_archive",
            format!("failed to stage archive '{}': {e}", src.display()),
        )
    })
}

/// Stream `reader` into `out` while computing the SHA-256 of the bytes.
fn buffer_and_hash<R: Read>(reader: &mut R, out: &mut fs::File) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf).map_err(|e| {
            Error::config(
                "prepare_image_archive",
                format!("failed to read archive: {e}"),
            )
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        out.write_all(&buf[..n]).map_err(|e| {
            Error::config(
                "prepare_image_archive",
                format!("failed to buffer archive: {e}"),
            )
        })?;
    }
    out.flush().map_err(|e| {
        Error::config(
            "prepare_image_archive",
            format!("failed to flush archive: {e}"),
        )
    })?;
    Ok(hex::encode(hasher.finalize()))
}

/// Stream a file through SHA-256 without copying it, returning the hex digest.
fn hash_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path).map_err(|e| {
        Error::config(
            "prepare_image_archive",
            format!("failed to open archive '{}': {e}", path.display()),
        )
    })?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(|e| {
            Error::config(
                "prepare_image_archive",
                format!("failed to read archive: {e}"),
            )
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    thread_local! {
        /// Per-thread cache root override so each test writes into its own
        /// tempdir (race-free across the parallel test runner).
        pub(super) static CACHE_ROOT_OVERRIDE: std::cell::RefCell<Option<PathBuf>> =
            const { std::cell::RefCell::new(None) };
    }

    /// Redirect the content-addressed cache into `dir` for the current test.
    fn use_cache_root(dir: &Path) {
        CACHE_ROOT_OVERRIDE.with(|c| *c.borrow_mut() = Some(dir.to_path_buf()));
    }

    #[test]
    fn test_is_image_archive() {
        assert!(is_image_archive("-"));
        assert!(is_image_archive("local:abc"));
        assert!(is_image_archive("./img.tar"));
        assert!(is_image_archive("img.tar.gz"));
        assert!(!is_image_archive("alpine"));
        assert!(!is_image_archive("ghcr.io/owner/repo:v1"));
    }

    #[test]
    fn test_stage_from_file_produces_cache_dir() {
        // A real `docker save` tarball is not needed here: host-side staging is
        // format-agnostic (extraction is delegated to the in-VM crane). Any
        // bytes exercise hashing + staging.
        let tmp = tempfile::tempdir().unwrap();
        use_cache_root(tmp.path());
        let archive = tmp.path().join("image.tar");
        fs::write(&archive, b"fake docker save archive").unwrap();

        let (dir, resolved) = prepare_image_archive(archive.to_str().unwrap()).unwrap();

        assert!(resolved.starts_with("local:"));
        assert!(is_staged(&dir));
        assert!(dir.starts_with(tmp.path()));
        assert_eq!(
            fs::read(dir.join(ARCHIVE_FILE)).unwrap(),
            b"fake docker save archive"
        );

        // A resolved `local:<hash>` ref now resolves straight from the cache.
        let (dir2, _) = prepare_image_archive(&resolved).unwrap();
        assert_eq!(dir, dir2);
    }

    #[test]
    fn test_stage_is_content_addressed_and_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        use_cache_root(tmp.path());
        let a = tmp.path().join("a.tar");
        let b = tmp.path().join("b.tar");
        fs::write(&a, b"identical bytes").unwrap();
        fs::write(&b, b"identical bytes").unwrap();

        let (dir_a, ref_a) = prepare_image_archive(a.to_str().unwrap()).unwrap();
        // Same bytes → same hash → same cache dir (cache hit, no error).
        let (dir_b, ref_b) = prepare_image_archive(b.to_str().unwrap()).unwrap();

        assert_eq!(ref_a, ref_b);
        assert_eq!(dir_a, dir_b);
    }

    #[test]
    fn test_local_ref_cache_miss_errors() {
        let tmp = tempfile::tempdir().unwrap();
        use_cache_root(tmp.path());
        let result = prepare_image_archive(
            "local:0000000000000000000000000000000000000000000000000000000000000000",
        );
        assert!(result.is_err());
    }
}
