//! Image archive support.
//!
//! Consumes a Docker- or OCI-format image archive produced by `docker save` /
//! `podman save` — piped on stdin (`-`) or stored as a `.tar`/`.tar.gz` file —
//! and extracts its layers into a content-addressed cache laid out exactly like
//! the packed-layers directory that `.smolmachine` artifacts already use. The
//! extracted directory is then mounted into the VM via virtiofs
//! (`packed_layers_dir`). The outer archive and the individual layer blobs may
//! be gzip-compressed; gzip is detected from magic bytes and decompressed
//! transparently.
//!
//! smolvm stays strictly on the image-source / transport side: it only reads a
//! tar stream and unpacks layers. It never contacts a registry, builds an
//! image, or invokes a container daemon — the in-VM runtime executes the
//! mounted layers exactly as it does for a registry pull.

use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

const EXTRACT_MARKER: &str = ".smolvm-extracted";

/// True when `image_ref` denotes an image archive (stdin pipe, `.tar`/`.tar.gz`
/// file, or a resolved `local:<hash>` cache reference) rather than a remote
/// registry reference.
pub fn is_image_archive(image_ref: &str) -> bool {
    image_ref == "-"
        || image_ref.starts_with("local:")
        || image_ref.ends_with(".tar")
        || image_ref.ends_with(".tar.gz")
}

/// Prepare an image archive for mounting via virtiofs.
///
/// Accepts a stdin pipe (`-`), a `.tar`/`.tar.gz` file path, or an
/// already-resolved `local:<sha256>` cache reference. Returns the path to the
/// extracted layers directory and the canonical `local:<sha256>` reference that
/// callers should persist so subsequent boots resolve straight from the cache.
pub fn prepare_image_archive(image_ref: &str) -> Result<(PathBuf, String)> {
    // Already-resolved cache reference (e.g. on `machine start`): the source
    // archive is gone, so this must resolve from the cache or fail clearly.
    if let Some(hash) = image_ref.strip_prefix("local:") {
        let layers_dir = cache_layers_dir(hash)?;
        let marker = cache_dir_of(&layers_dir).join(EXTRACT_MARKER);
        if marker.exists() && layers_dir.exists() {
            return Ok((layers_dir, image_ref.to_string()));
        }
        return Err(Error::config(
            "prepare_image_archive",
            format!(
                "cached image archive '{image_ref}' not found. Re-pipe the source archive (e.g. `docker save IMAGE | smolvm ...`)."
            ),
        ));
    }

    // Obtain a seekable handle to the archive plus the SHA-256 of its bytes
    // (the cache key). A stdin stream is single-pass, so it is buffered to a
    // tempfile while hashing; on-disk archives are hashed in place and reopened
    // for extraction — no second full-size copy.
    let mut tmp_guard = None;
    let (hash, archive_file) = if image_ref == "-" {
        let mut tmp = tempfile::NamedTempFile::new().map_err(|e| {
            Error::config(
                "prepare_image_archive",
                format!("failed to create temp file: {e}"),
            )
        })?;
        let mut stdin = std::io::stdin().lock();
        let hash = buffer_and_hash(&mut stdin, tmp.as_file_mut())?;
        let file = tmp.reopen().map_err(|e| {
            Error::config(
                "prepare_image_archive",
                format!("failed to reopen temp archive: {e}"),
            )
        })?;
        tmp_guard = Some(tmp);
        (hash, file)
    } else {
        let path = Path::new(image_ref);
        if !path.exists() {
            return Err(Error::config(
                "prepare_image_archive",
                format!("image archive not found: {image_ref}"),
            ));
        }
        let hash = hash_file(path)?;
        let file = fs::File::open(path).map_err(|e| {
            Error::config(
                "prepare_image_archive",
                format!("failed to open archive '{image_ref}': {e}"),
            )
        })?;
        (hash, file)
    };
    // Keep the stdin tempfile (if any) alive until extraction completes.
    let _tmp_guard = tmp_guard;

    let layers_dir = cache_layers_dir(&hash)?;
    let cache_dir = cache_dir_of(&layers_dir);
    let marker = cache_dir.join(EXTRACT_MARKER);
    let resolved_ref = format!("local:{hash}");

    // Cache hit — extraction already complete.
    if marker.exists() && layers_dir.exists() {
        return Ok((layers_dir, resolved_ref));
    }

    // Clean any stale/partial extraction before re-extracting.
    if cache_dir.exists() {
        let _ = fs::remove_dir_all(&cache_dir);
    }
    fs::create_dir_all(&layers_dir).map_err(|e| {
        Error::config(
            "prepare_image_archive",
            format!("failed to create layers dir: {e}"),
        )
    })?;

    let result =
        decompress_file(archive_file).and_then(|reader| extract_archive(reader, &layers_dir));
    if let Err(e) = result {
        let _ = fs::remove_dir_all(&cache_dir);
        return Err(e);
    }

    fs::write(&marker, "").map_err(|e| {
        Error::config(
            "prepare_image_archive",
            format!("failed to write extraction marker: {e}"),
        )
    })?;

    Ok((layers_dir, resolved_ref))
}

/// Resolve an optional image reference, extracting it when it is a local image
/// archive (stdin pipe, `.tar`/`.tar.gz` file, or resolved `local:<hash>`).
///
/// Returns `Some((packed_layers_dir, resolved_ref))` for archives — the layers
/// directory to mount via virtiofs and the canonical `local:<hash>` reference
/// to persist — or `None` when `image` is absent or a normal registry ref.
pub fn resolve_if_archive(image: Option<&str>) -> Result<Option<(PathBuf, String)>> {
    match image {
        Some(img) if is_image_archive(img) => prepare_image_archive(img).map(Some),
        _ => Ok(None),
    }
}

/// `~/.cache/smolvm/image-archives/<hash>/layers`.
fn cache_layers_dir(hash: &str) -> Result<PathBuf> {
    let base = dirs::cache_dir()
        .ok_or_else(|| Error::config("prepare_image_archive", "no cache directory available"))?;
    Ok(base
        .join("smolvm")
        .join("image-archives")
        .join(hash)
        .join("layers"))
}

/// The parent (`<hash>`) directory of a `.../layers` path.
fn cache_dir_of(layers_dir: &Path) -> PathBuf {
    layers_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| layers_dir.to_path_buf())
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

/// Unpack an image archive (Docker or OCI layout) into `layers_dir`.
fn extract_archive<R: Read>(reader: R, layers_dir: &Path) -> Result<()> {
    let staging = tempfile::tempdir().map_err(|e| {
        Error::config(
            "extract_archive",
            format!("failed to create staging dir: {e}"),
        )
    })?;
    let mut archive = tar::Archive::new(reader);
    archive.unpack(staging.path()).map_err(|e| {
        Error::config(
            "extract_archive",
            format!("failed to unpack image archive: {e}"),
        )
    })?;

    let root = staging.path();
    if root.join("manifest.json").exists() {
        extract_docker_archive(root, layers_dir)
    } else if root.join("index.json").exists() {
        extract_oci_archive(root, layers_dir)
    } else {
        Err(Error::config(
            "extract_archive",
            "unrecognized image archive: no manifest.json (docker) or index.json (OCI) found",
        ))
    }
}

/// Extract a `docker save` archive (`manifest.json` + uncompressed layer tars).
fn extract_docker_archive(root: &Path, layers_dir: &Path) -> Result<()> {
    let manifest = read_json(&root.join("manifest.json"))?;
    let first = manifest
        .as_array()
        .and_then(|a| a.first())
        .ok_or_else(|| Error::config("extract_docker_archive", "empty manifest.json"))?;

    let config_file = first["Config"]
        .as_str()
        .ok_or_else(|| Error::config("extract_docker_archive", "manifest.json missing Config"))?;
    copy_config(&root.join(config_file), layers_dir)?;

    let layers = first["Layers"]
        .as_array()
        .ok_or_else(|| Error::config("extract_docker_archive", "manifest.json missing Layers"))?;
    for (index, layer) in layers.iter().enumerate() {
        let rel = layer.as_str().ok_or_else(|| {
            Error::config(
                "extract_docker_archive",
                "invalid layer path in manifest.json",
            )
        })?;
        let name = rel.replace('/', "_").replace(".tar", "");
        extract_layer(&root.join(rel), &layer_dest(layers_dir, index, &name))?;
    }
    Ok(())
}

/// Extract an OCI layout archive (`index.json` + gzip layer blobs).
fn extract_oci_archive(root: &Path, layers_dir: &Path) -> Result<()> {
    let index = read_json(&root.join("index.json"))?;
    let manifest_digest = index["manifests"]
        .as_array()
        .and_then(|manifests| pick_manifest(manifests))
        .and_then(|m| m["digest"].as_str())
        .ok_or_else(|| Error::config("extract_oci_archive", "index.json has no manifest entry"))?;

    let manifest = resolve_manifest(root, manifest_digest)?;

    let config_digest = manifest["config"]["digest"]
        .as_str()
        .ok_or_else(|| Error::config("extract_oci_archive", "manifest missing config digest"))?;
    copy_config(&blob_path(root, config_digest)?, layers_dir)?;

    let layers = manifest["layers"]
        .as_array()
        .ok_or_else(|| Error::config("extract_oci_archive", "manifest missing layers"))?;
    for (index, layer) in layers.iter().enumerate() {
        let digest = layer["digest"].as_str().ok_or_else(|| {
            Error::config("extract_oci_archive", "invalid layer digest in manifest")
        })?;
        let short = digest.strip_prefix("sha256:").unwrap_or(digest);
        let short = &short[..short.len().min(12)];
        extract_layer(
            &blob_path(root, digest)?,
            &layer_dest(layers_dir, index, short),
        )?;
    }
    Ok(())
}

/// Follow `index.json` entries (descending through nested indexes) until an
/// image manifest with a `layers` array is found.
fn resolve_manifest(root: &Path, digest: &str) -> Result<serde_json::Value> {
    let mut current = digest.to_string();
    for _ in 0..4 {
        let blob = read_json(&blob_path(root, &current)?)?;
        if blob.get("layers").is_some() {
            return Ok(blob);
        }
        let next = blob["manifests"]
            .as_array()
            .and_then(|manifests| pick_manifest(manifests))
            .and_then(|m| m["digest"].as_str().map(String::from));
        match next {
            Some(d) => current = d,
            None => break,
        }
    }
    Err(Error::config(
        "extract_oci_archive",
        "could not resolve image manifest from index.json",
    ))
}

/// Prefer the manifest entry matching the host architecture, else the first.
fn pick_manifest(manifests: &[serde_json::Value]) -> Option<&serde_json::Value> {
    let arch = host_oci_arch();
    manifests
        .iter()
        .find(|m| {
            m["platform"]["architecture"].as_str() == Some(arch)
                && m["platform"]["os"].as_str().is_none_or(|os| os == "linux")
        })
        .or_else(|| manifests.first())
}

/// Host architecture using OCI naming (`amd64`/`arm64`).
fn host_oci_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

/// Map an OCI `algo:hex` digest to its `blobs/<algo>/<hex>` path.
fn blob_path(root: &Path, digest: &str) -> Result<PathBuf> {
    let (algo, hex) = digest
        .split_once(':')
        .ok_or_else(|| Error::config("extract_oci_archive", format!("invalid digest: {digest}")))?;
    Ok(root.join("blobs").join(algo).join(hex))
}

/// Copy the image config blob to `<layers_dir>/config.json` (read by the agent
/// to recover Entrypoint/Cmd/Env), if present.
fn copy_config(src: &Path, layers_dir: &Path) -> Result<()> {
    if src.exists() {
        fs::copy(src, layers_dir.join("config.json")).map_err(|e| {
            Error::config(
                "extract_archive",
                format!("failed to copy image config: {e}"),
            )
        })?;
    }
    Ok(())
}

/// Extract a single layer tar (gzip-compressed or plain) into `dest`.
fn extract_layer(src: &Path, dest: &Path) -> Result<()> {
    fs::create_dir_all(dest)
        .map_err(|e| Error::config("extract_layer", format!("failed to create layer dir: {e}")))?;
    let file = fs::File::open(src).map_err(|e| {
        Error::config(
            "extract_layer",
            format!("failed to open layer '{}': {e}", src.display()),
        )
    })?;
    unpack_tar(decompress_file(file)?, dest)
}

/// gzip stream identifier (leading magic bytes).
const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];

/// Wrap `file` in a reader that transparently decompresses gzip input, detected
/// from leading magic bytes; uncompressed input is read as-is.
///
/// Used for both the outer image archive (so `.tar.gz` works) and individual
/// layer blobs (Docker layers are plain; OCI layers are gzip).
fn decompress_file(mut file: fs::File) -> Result<Box<dyn Read>> {
    let mut magic = [0u8; 2];
    let n = read_up_to(&mut file, &mut magic)?;
    file.seek(SeekFrom::Start(0)).map_err(|e| {
        Error::config("extract_archive", format!("failed to rewind archive: {e}"))
    })?;
    if magic[..n].starts_with(&GZIP_MAGIC) {
        Ok(Box::new(flate2::read::GzDecoder::new(file)))
    } else {
        Ok(Box::new(file))
    }
}

/// Read up to `buf.len()` bytes, tolerating short reads and `Interrupted`.
fn read_up_to<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => {
                return Err(Error::config(
                    "extract_archive",
                    format!("failed to read archive header: {e}"),
                ))
            }
        }
    }
    Ok(filled)
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

/// Unpack a tar stream into `dest`.
fn unpack_tar<R: Read>(reader: R, dest: &Path) -> Result<()> {
    let mut archive = tar::Archive::new(reader);
    archive.unpack(dest).map_err(|e| {
        Error::config(
            "extract_layer",
            format!("failed to extract layer into '{}': {e}", dest.display()),
        )
    })
}

/// `<layers_dir>/<NNNN>_<name>` — the indexed per-layer directory the agent
/// scans in `create_packed_image_info`.
fn layer_dest(layers_dir: &Path, index: usize, name: &str) -> PathBuf {
    layers_dir.join(format!("{index:04}_{name}"))
}

/// Read and parse a JSON file into a [`serde_json::Value`].
fn read_json(path: &Path) -> Result<serde_json::Value> {
    let content = fs::read_to_string(path).map_err(|e| {
        Error::config(
            "extract_archive",
            format!("failed to read '{}': {e}", path.display()),
        )
    })?;
    serde_json::from_str(&content).map_err(|e| {
        Error::config(
            "extract_archive",
            format!("failed to parse '{}': {e}", path.display()),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;

    /// Build an in-memory tar archive from `(path, bytes)` entries.
    fn make_tar(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, data) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            builder
                .append_data(&mut header, name, data.as_slice())
                .unwrap();
        }
        builder.into_inner().unwrap()
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    /// Write `bytes` to a temp file and return an open, rewound handle to it.
    fn temp_file_with(bytes: &[u8]) -> fs::File {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(bytes).unwrap();
        tmp.flush().unwrap();
        tmp.reopen().unwrap()
    }

    #[test]
    fn test_extract_docker_archive_layout() {
        let layer_tar = make_tar(&[("hello.txt", b"hi".to_vec())]);
        let config = br#"{"architecture":"amd64","config":{"Cmd":["/bin/sh"]}}"#.to_vec();
        let manifest = br#"[{"Config":"config.json","Layers":["layer0.tar"]}]"#.to_vec();
        let archive = make_tar(&[
            ("manifest.json", manifest),
            ("config.json", config),
            ("layer0.tar", layer_tar),
        ]);

        let layers_dir = tempfile::tempdir().unwrap();
        extract_archive(archive.as_slice(), layers_dir.path()).unwrap();

        assert!(layers_dir.path().join("config.json").exists());
        let layer_file = layers_dir.path().join("0000_layer0").join("hello.txt");
        assert_eq!(std::fs::read_to_string(layer_file).unwrap(), "hi");
    }

    #[test]
    fn test_extract_oci_archive_layout() {
        let layer_tar = make_tar(&[("data.txt", b"oci".to_vec())]);
        let layer_gz = gzip(&layer_tar);
        let config = br#"{"architecture":"arm64","config":{"Entrypoint":["/run"]}}"#.to_vec();
        let manifest =
            br#"{"config":{"digest":"sha256:cfg"},"layers":[{"digest":"sha256:lyr"}]}"#.to_vec();
        let index = br#"{"manifests":[{"digest":"sha256:man"}]}"#.to_vec();
        let archive = make_tar(&[
            ("oci-layout", br#"{"imageLayoutVersion":"1.0.0"}"#.to_vec()),
            ("index.json", index),
            ("blobs/sha256/man", manifest),
            ("blobs/sha256/cfg", config),
            ("blobs/sha256/lyr", layer_gz),
        ]);

        let layers_dir = tempfile::tempdir().unwrap();
        extract_archive(archive.as_slice(), layers_dir.path()).unwrap();

        assert!(layers_dir.path().join("config.json").exists());
        let layer_file = layers_dir.path().join("0000_lyr").join("data.txt");
        assert_eq!(std::fs::read_to_string(layer_file).unwrap(), "oci");
    }

    #[test]
    fn test_gzipped_outer_archive() {
        // `docker save | gzip` / a `.tar.gz` file: the whole archive is gzip
        // wrapped and must be decompressed before the tar is read.
        let layer_tar = make_tar(&[("hello.txt", b"hi".to_vec())]);
        let config = br#"{"architecture":"amd64"}"#.to_vec();
        let manifest = br#"[{"Config":"config.json","Layers":["layer0.tar"]}]"#.to_vec();
        let archive = make_tar(&[
            ("manifest.json", manifest),
            ("config.json", config),
            ("layer0.tar", layer_tar),
        ]);

        let layers_dir = tempfile::tempdir().unwrap();
        let reader = decompress_file(temp_file_with(&gzip(&archive))).unwrap();
        extract_archive(reader, layers_dir.path()).unwrap();

        let layer_file = layers_dir.path().join("0000_layer0").join("hello.txt");
        assert_eq!(std::fs::read_to_string(layer_file).unwrap(), "hi");
    }

    #[test]
    fn test_missing_manifest_rejected() {
        let archive = make_tar(&[("random.txt", b"nope".to_vec())]);
        let layers_dir = tempfile::tempdir().unwrap();
        assert!(extract_archive(archive.as_slice(), layers_dir.path()).is_err());
    }

    #[test]
    fn test_archive_ref_cache_miss_errors() {
        let result = prepare_image_archive(
            "local:0000000000000000000000000000000000000000000000000000000000000000",
        );
        assert!(result.is_err());
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
}
