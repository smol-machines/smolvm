//! Classifying the `--image` value into an image *source*.
//!
//! smolvm is a microVM runtime, not a container runtime: it does not parse OCI
//! manifests, extract layers, or apply whiteouts itself. It delegates producing
//! a root filesystem to container-specific tooling (the guest's bundled `crane`
//! for registries and `docker save` archives, or the user for an already-
//! unpacked directory). This module's only job is to decide *which* kind of
//! source the user gave, so the right delegation runs.
//!
//! Detection is intentionally conservative so a bare registry reference is never
//! mistaken for a local path:
//! - `-` → an archive streamed on stdin (`docker save img | smolvm … --image -`).
//! - an explicit path (`/…`, `./…`, `../…`) or an archive-extensioned name
//!   (`*.tar`, `*.tar.gz`, `*.tgz`) → a local source. A directory is used as a
//!   ready-made rootfs; anything else is treated as a `docker save` archive.
//! - everything else (`alpine`, `repo:tag`, `ghcr.io/owner/repo@sha256:…`) → a
//!   registry reference, even if a same-named file happens to sit in the cwd.

use crate::{Error, Result};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Where a machine's root filesystem comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageSource {
    /// An OCI registry reference (`alpine`, `repo:tag`, `repo@sha256:…`).
    /// Resolved by the guest agent pulling with `crane` — the existing path.
    Registry(String),
    /// A `docker save` / `podman save` tar archive (optionally gzipped), read
    /// from a file or stdin. Flattened into a rootfs by `crane export`.
    Archive(ArchiveInput),
    /// An already-unpacked root filesystem directory (apptainer-style). Used
    /// as-is — no extraction.
    Directory(PathBuf),
}

/// Where an [`ImageSource::Archive`]'s bytes come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveInput {
    /// Read the archive from this file path.
    File(PathBuf),
    /// Read the archive from stdin (`--image -`).
    Stdin,
}

/// Known archive filename suffixes that mark a bare name as a local archive
/// even without an explicit path prefix (e.g. `image.tar` in the cwd).
const ARCHIVE_SUFFIXES: [&str; 3] = [".tar", ".tar.gz", ".tgz"];

/// Classify a `--image` value into its [`ImageSource`].
///
/// This decides *intent* only; whether the path actually exists (and is a valid
/// archive) is validated when the source is resolved, so a missing `./foo.tar`
/// produces a clear "no such file" rather than a confusing registry error.
pub fn classify(image: &str) -> ImageSource {
    if image == "-" {
        return ImageSource::Archive(ArchiveInput::Stdin);
    }
    if looks_local(image) {
        let path = Path::new(image);
        // Only an existing directory is treated as a ready-made rootfs; a
        // missing path or a regular file is treated as an archive (resolve
        // surfaces a clear error if it's absent).
        if path.is_dir() {
            return ImageSource::Directory(path.to_path_buf());
        }
        return ImageSource::Archive(ArchiveInput::File(path.to_path_buf()));
    }
    ImageSource::Registry(image.to_string())
}

/// Whether a value should be treated as a local path rather than a registry
/// reference: an explicit path prefix or a known archive suffix.
fn looks_local(image: &str) -> bool {
    image.starts_with('/')
        || image.starts_with("./")
        || image.starts_with("../")
        || ARCHIVE_SUFFIXES
            .iter()
            .any(|suffix| image.ends_with(suffix))
}

/// Whether a local path is a Dockerfile rather than an image archive — so we can
/// reject it with a build-first hint instead of a confusing flatten failure.
/// Detected by the conventional name (`Dockerfile`/`Containerfile`, or a
/// `*.Dockerfile`/`*.Containerfile` suffix) or a first meaningful line of `FROM`.
fn looks_like_dockerfile(path: &Path) -> bool {
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        let lower = name.to_ascii_lowercase();
        if lower == "dockerfile"
            || lower == "containerfile"
            || lower.ends_with(".dockerfile")
            || lower.ends_with(".containerfile")
        {
            return true;
        }
    }
    // Content sniff over the first few KB only (never slurp a multi-GB archive):
    // skip blank/comment lines; a Dockerfile opens with FROM (or an ARG before
    // it). A tar archive's header is binary, so the UTF-8 read simply fails.
    let mut head = [0u8; 4096];
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let Ok(n) = std::io::Read::read(&mut file, &mut head) else {
        return false;
    };
    let Ok(text) = std::str::from_utf8(&head[..n]) else {
        return false;
    };
    for line in text.lines().take(50) {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let word = line.split_whitespace().next().unwrap_or("");
        return word.eq_ignore_ascii_case("FROM") || word.eq_ignore_ascii_case("ARG");
    }
    false
}

/// A classified source resolved into something launchable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedImage {
    /// Pulled from a registry by the guest agent — the existing path.
    Registry(String),
    /// A local source materialized on the host. `reference` is the stable ref
    /// persisted on the machine record; `packed_layers_dir` is mounted into the
    /// guest via virtiofs (the same path `.smolmachine` layers use).
    Local {
        /// Stable `local:<hash>` / `local-dir:<path>` reference to persist on
        /// the machine record so later starts re-resolve to the same source.
        reference: String,
        /// Host directory mounted into the guest via virtiofs — the staged
        /// archive's cache dir, or the rootfs directory itself.
        packed_layers_dir: PathBuf,
    },
}

/// Largest archive accepted. The staged copy plus the guest's flattened rootfs
/// both consume disk, so the default guards against runaway/hostile inputs while
/// still covering very large dev images.
///
/// Override with `SMOLVM_MAX_IMAGE_BYTES` (in bytes), or per-invocation with the
/// `--max-image-size` flag on `machine run`/`machine create` (which sets that
/// env var). A legitimate large image is a valid reason to raise it; the cap
/// only exists to bound disk use for untrusted inputs.
pub fn max_archive_bytes() -> u64 {
    const DEFAULT: u64 = 8 * 1024 * 1024 * 1024;
    std::env::var("SMOLVM_MAX_IMAGE_BYTES")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT)
}
/// Streaming hash/copy buffer.
const COPY_CHUNK: usize = 1 << 20;
/// Filename the staged archive is stored under inside its cache dir.
const ARCHIVE_FILE: &str = "archive.tar";

/// Resolve a classified [`ImageSource`] into a [`ResolvedImage`].
///
/// Registry refs pass straight through (the guest pulls them). Archives are
/// content-hashed and staged into a shared cache, so identical inputs dedupe
/// and re-runs skip the staging; directories are validated and used in place.
/// Both local kinds yield a `packed_layers_dir` to mount and a `local:…`
/// reference to persist on the machine record.
pub fn resolve(source: ImageSource) -> Result<ResolvedImage> {
    match source {
        ImageSource::Registry(reference) => Ok(ResolvedImage::Registry(reference)),
        ImageSource::Directory(path) => resolve_directory(&path),
        ImageSource::Archive(input) => resolve_archive(input),
    }
}

fn resolve_directory(path: &Path) -> Result<ResolvedImage> {
    let canonical = path.canonicalize().map_err(|e| {
        Error::config(
            "--image",
            format!("cannot use rootfs directory {}: {}", path.display(), e),
        )
    })?;
    if !canonical.is_dir() {
        return Err(Error::config(
            "--image",
            format!("{} is not a directory", canonical.display()),
        ));
    }
    Ok(ResolvedImage::Local {
        reference: format!("{LOCAL_DIR_PREFIX}{}", canonical.display()),
        packed_layers_dir: canonical,
    })
}

fn resolve_archive(input: ArchiveInput) -> Result<ResolvedImage> {
    let cache_base = archive_cache_base()?;
    std::fs::create_dir_all(&cache_base)?;
    let hash = match input {
        ArchiveInput::File(path) => stage_from_file(&path, &cache_base)?,
        ArchiveInput::Stdin => stage_from_stdin(&cache_base)?,
    };
    Ok(ResolvedImage::Local {
        reference: format!("{LOCAL_ARCHIVE_PREFIX}{hash}"),
        packed_layers_dir: cache_base.join(hash),
    })
}

/// Hash an on-disk archive and hardlink (or copy) it into `cache/<hash>/`.
fn stage_from_file(path: &Path, cache_base: &Path) -> Result<String> {
    let meta = std::fs::metadata(path).map_err(|e| {
        Error::config(
            "--image",
            format!("cannot read archive {}: {}", path.display(), e),
        )
    })?;
    if !meta.is_file() {
        return Err(Error::config(
            "--image",
            format!("{} is not a file", path.display()),
        ));
    }
    if looks_like_dockerfile(path) {
        return Err(Error::config(
            "--image",
            format!(
                "{} looks like a Dockerfile, not an image.\n\
                 smolvm boots images, it does not build them — build first, then \
                 pass the result:\n  \
                 docker build -t myapp . && docker save myapp | smolvm machine run --image - -- ...",
                path.display()
            ),
        ));
    }
    if meta.len() > max_archive_bytes() {
        return Err(too_large(meta.len()));
    }
    let hash = hash_file(path)?;
    let archive_path = cache_base.join(&hash).join(ARCHIVE_FILE);
    if !archive_path.exists() {
        std::fs::create_dir_all(archive_path.parent().expect("hash dir has a parent"))?;
        link_or_copy(path, &archive_path)?;
    }
    Ok(hash)
}

/// Stream stdin to a temp file (hashing as we go), then place it at
/// `cache/<hash>/`. Single-pass, so one write is unavoidable.
fn stage_from_stdin(cache_base: &Path) -> Result<String> {
    let mut tmp = tempfile::NamedTempFile::new_in(cache_base)?;
    let mut hasher = Sha256::new();
    let mut stdin = std::io::stdin().lock();
    let mut buf = vec![0u8; COPY_CHUNK];
    let mut total: u64 = 0;
    loop {
        let n = stdin.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > max_archive_bytes() {
            return Err(too_large(total));
        }
        hasher.update(&buf[..n]);
        tmp.write_all(&buf[..n])?;
    }
    tmp.flush()?;
    let hash = hex::encode(hasher.finalize());
    let archive_path = cache_base.join(&hash).join(ARCHIVE_FILE);
    if archive_path.exists() {
        return Ok(hash); // already staged; the temp file is dropped/removed
    }
    std::fs::create_dir_all(archive_path.parent().expect("hash dir has a parent"))?;
    tmp.persist(&archive_path)
        .map_err(|e| Error::storage("stage stdin archive", e.to_string()))?;
    Ok(hash)
}

fn hash_file(path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; COPY_CHUNK];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Hardlink `src` into the cache, copying as a fallback across filesystems.
fn link_or_copy(src: &Path, dst: &Path) -> Result<()> {
    if std::fs::hard_link(src, dst).is_ok() {
        return Ok(());
    }
    std::fs::copy(src, dst)?;
    Ok(())
}

/// Reference prefixes produced by [`resolve`] for the two local-source kinds.
const LOCAL_ARCHIVE_PREFIX: &str = "local:";
const LOCAL_DIR_PREFIX: &str = "local-dir:";

/// Whether a persisted image reference points at a local source (produced by
/// [`resolve`]) rather than a registry.
pub fn is_local_ref(reference: &str) -> bool {
    reference.starts_with(LOCAL_ARCHIVE_PREFIX) || reference.starts_with(LOCAL_DIR_PREFIX)
}

/// Map a persisted `local:…`/`local-dir:…` reference back to the host directory
/// to mount into the guest via virtiofs, so a later `start` re-resolves to the
/// same source without re-staging. Returns `None` for a registry reference. The
/// directory may be gone if the archive cache was pruned — `start` then fails
/// with a clear "no such directory" rather than silently pulling.
pub fn packed_layers_dir_for_ref(reference: &str) -> Option<PathBuf> {
    if let Some(hash) = reference.strip_prefix(LOCAL_ARCHIVE_PREFIX) {
        return archive_cache_base().ok().map(|base| base.join(hash));
    }
    reference.strip_prefix(LOCAL_DIR_PREFIX).map(PathBuf::from)
}

fn archive_cache_base() -> Result<PathBuf> {
    let base = dirs::cache_dir()
        .ok_or_else(|| Error::storage("image archive cache", "no cache directory available"))?;
    Ok(base.join("smolvm-image-archives"))
}

fn too_large(bytes: u64) -> Error {
    let limit = max_archive_bytes();
    Error::config(
        "--image",
        format!(
            "image archive is {bytes} bytes, over the {limit}-byte limit. \
             Raise it with --max-image-size (e.g. --max-image-size 16GiB) or the \
             SMOLVM_MAX_IMAGE_BYTES env var if this is a legitimate large image."
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_refs_are_not_treated_as_local() {
        for r in [
            "alpine",
            "alpine:3.20",
            "ghcr.io/owner/repo",
            "ghcr.io/owner/repo:v1",
            "repo@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "localhost:5000/myimage:dev",
        ] {
            assert_eq!(classify(r), ImageSource::Registry(r.to_string()), "{r}");
        }
    }

    #[test]
    fn stdin_dash_is_an_archive() {
        assert_eq!(classify("-"), ImageSource::Archive(ArchiveInput::Stdin));
    }

    #[test]
    fn archive_extensions_and_paths_are_local_archives() {
        // Suffix-based (bare name in cwd) — file need not exist to classify.
        for a in ["image.tar", "image.tar.gz", "image.tgz"] {
            assert_eq!(
                classify(a),
                ImageSource::Archive(ArchiveInput::File(PathBuf::from(a))),
                "{a}"
            );
        }
        // Explicit path prefixes, even without an archive extension.
        for a in ["./img", "/abs/img.tar", "../up/img"] {
            assert_eq!(
                classify(a),
                ImageSource::Archive(ArchiveInput::File(PathBuf::from(a))),
                "{a}"
            );
        }
    }

    #[test]
    fn dockerfiles_are_rejected_with_a_build_hint() {
        let dir = tempfile::tempdir().unwrap();

        // By name: `Dockerfile` (any case) and `*.Dockerfile`.
        for name in [
            "Dockerfile",
            "dockerfile",
            "Containerfile",
            "app.Dockerfile",
        ] {
            let p = dir.path().join(name);
            std::fs::write(&p, b"unreadable as a name test").unwrap();
            assert!(looks_like_dockerfile(&p), "{name}");
        }

        // By content: a file not named Dockerfile but opening with FROM.
        let by_content = dir.path().join("build-recipe");
        std::fs::write(
            &by_content,
            b"# build\nFROM alpine:3.20\nRUN apk add curl\n",
        )
        .unwrap();
        assert!(looks_like_dockerfile(&by_content));

        // A binary archive must not be mistaken for a Dockerfile.
        let archive = dir.path().join("image.bin");
        std::fs::write(&archive, [0u8, 1, 2, 0xff, b'F', b'R', b'O', b'M']).unwrap();
        assert!(!looks_like_dockerfile(&archive));

        // And resolve surfaces the build-first hint, not a flatten failure.
        let err = stage_from_file(&dir.path().join("Dockerfile"), dir.path()).unwrap_err();
        assert!(err.to_string().contains("build"), "{err}");
    }

    #[test]
    fn existing_directory_is_a_directory_source() {
        let dir = tempfile::tempdir().unwrap();
        // Reference it with an explicit path prefix so it reads as local.
        let as_path = format!("{}/.", dir.path().display());
        match classify(&as_path) {
            ImageSource::Directory(p) => assert!(p.is_dir()),
            other => panic!("expected Directory, got {other:?}"),
        }
    }

    #[test]
    fn bare_name_matching_a_cwd_file_still_resolves_to_registry() {
        // A registry ref like `alpine` must not be hijacked by a same-named
        // file: it isn't an explicit path and has no archive suffix.
        assert_eq!(
            classify("alpine"),
            ImageSource::Registry("alpine".to_string())
        );
    }

    #[test]
    fn resolve_registry_passes_through() {
        assert_eq!(
            resolve(ImageSource::Registry("alpine".into())).unwrap(),
            ResolvedImage::Registry("alpine".into())
        );
    }

    #[test]
    fn stage_from_file_hashes_and_dedupes() {
        let cache = tempfile::tempdir().unwrap();
        let src = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(src.path(), b"fake docker save archive").unwrap();

        let h1 = stage_from_file(src.path(), cache.path()).unwrap();
        let staged = cache.path().join(&h1).join(ARCHIVE_FILE);
        assert!(staged.exists(), "archive staged at {}", staged.display());
        assert_eq!(std::fs::read(&staged).unwrap(), b"fake docker save archive");

        // Identical content → identical hash, idempotent (no error, reused).
        let h2 = stage_from_file(src.path(), cache.path()).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn local_refs_round_trip_to_a_packed_layers_dir() {
        assert!(is_local_ref("local:abc123"));
        assert!(is_local_ref("local-dir:/srv/rootfs"));
        assert!(!is_local_ref("alpine"));
        assert!(!is_local_ref("ghcr.io/o/r:v1"));

        // A dir ref maps straight back to the directory.
        assert_eq!(
            packed_layers_dir_for_ref("local-dir:/srv/rootfs"),
            Some(PathBuf::from("/srv/rootfs"))
        );
        // An archive ref maps under the shared cache base, keyed by hash.
        let dir = packed_layers_dir_for_ref("local:deadbeef").unwrap();
        assert!(dir.ends_with("smolvm-image-archives/deadbeef"));
        // Registry refs have no packed-layers dir.
        assert_eq!(packed_layers_dir_for_ref("alpine"), None);
    }

    #[test]
    fn resolve_directory_yields_local_with_the_dir() {
        let dir = tempfile::tempdir().unwrap();
        match resolve_directory(dir.path()).unwrap() {
            ResolvedImage::Local {
                reference,
                packed_layers_dir,
            } => {
                assert!(reference.starts_with("local-dir:"));
                assert_eq!(packed_layers_dir, dir.path().canonicalize().unwrap());
            }
            other => panic!("expected Local, got {other:?}"),
        }
    }
}
