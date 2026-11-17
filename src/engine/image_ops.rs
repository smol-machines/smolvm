//! Images in and out of the engine: `docker save`, `load`, `push`, `import`,
//! `commit`, and pulls from a registry on this host.
//!
//! An image pulled from a registry boots from its registry reference: each
//! container's guest pulls it, as every smolvm image pull happens. Every
//! other image is a `docker save` archive in smolvm's local image cache,
//! booted the way `smolvm machine run --image ./image.tar` boots one: a
//! loaded archive, an import, a commit, and a pull from a registry on this
//! host's loopback (which a guest cannot reach, so the host fetches it).
//!
//! Saving or pushing a registry image needs its layers on the host, so the
//! host fetches them with the same authorization a pull uses; the fetched
//! archive is cached like any other.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use sha2::{Digest, Sha256};

use super::images::{ImageRecord, ImageRef};
use super::util::{ApiError, ApiResult};
use super::Engine;

/// One image of a `docker save` (or OCI layout) archive, unpacked.
#[derive(Debug, Clone)]
pub(crate) struct ArchiveImage {
    /// The config blob.
    pub config: Vec<u8>,
    /// The layer files, bottom first (compressed or not).
    pub layers: Vec<PathBuf>,
    /// The tags the archive names it by.
    pub repo_tags: Vec<String>,
}

impl ArchiveImage {
    /// `sha256:<config digest>`, the image id.
    pub(crate) fn id(&self) -> String {
        format!("sha256:{}", hex::encode(Sha256::digest(&self.config)))
    }

    fn size(&self) -> i64 {
        self.layers
            .iter()
            .filter_map(|l| std::fs::metadata(l).ok())
            .map(|m| m.len() as i64)
            .sum()
    }
}

fn io_error(context: &str) -> impl Fn(std::io::Error) -> ApiError + '_ {
    move |e| ApiError::internal(format!("{context}: {e}"))
}

/// Unpack `archive` (a tar, possibly gzip or zstd compressed) into `dir`.
pub(crate) fn unpack(archive: &Path, dir: &Path) -> std::io::Result<()> {
    let file = std::io::BufReader::new(std::fs::File::open(archive)?);
    let reader = smolvm_oci_layer::decompress_layer_reader(file)?;
    let mut tar = tar::Archive::new(reader);
    tar.set_preserve_permissions(false);
    tar.unpack(dir)
}

/// The images of an unpacked archive: `manifest.json` (`docker save`) or,
/// without one, `index.json` (an OCI image layout).
pub(crate) fn read_images(dir: &Path) -> Result<Vec<ArchiveImage>, String> {
    let inside = |name: &str| -> Result<PathBuf, String> {
        let rel = Path::new(name.trim_start_matches('/'));
        if rel
            .components()
            .any(|c| !matches!(c, std::path::Component::Normal(_)))
        {
            return Err(format!("archive names a path outside itself: {name}"));
        }
        Ok(dir.join(rel))
    };
    if let Ok(bytes) = std::fs::read(dir.join("manifest.json")) {
        let entries: Vec<serde_json::Value> =
            serde_json::from_slice(&bytes).map_err(|e| format!("manifest.json: {e}"))?;
        let mut out = Vec::new();
        for entry in entries {
            let config = entry["Config"]
                .as_str()
                .ok_or("manifest.json entry without Config")?;
            let layers = entry["Layers"]
                .as_array()
                .map(|l| l.iter().filter_map(|v| v.as_str()).map(&inside).collect())
                .transpose()?
                .unwrap_or_default();
            out.push(ArchiveImage {
                config: std::fs::read(inside(config)?)
                    .map_err(|e| format!("read config {config}: {e}"))?,
                layers,
                repo_tags: entry["RepoTags"]
                    .as_array()
                    .map(|t| {
                        t.iter()
                            .filter_map(|v| v.as_str())
                            .map(String::from)
                            .collect()
                    })
                    .unwrap_or_default(),
            });
        }
        return Ok(out);
    }
    let index: serde_json::Value = serde_json::from_slice(
        &std::fs::read(dir.join("index.json"))
            .map_err(|_| "neither manifest.json nor index.json in the archive".to_string())?,
    )
    .map_err(|e| format!("index.json: {e}"))?;
    let blob = |digest: &str| -> Result<PathBuf, String> {
        let (alg, hex) = digest
            .split_once(':')
            .ok_or_else(|| format!("bad digest {digest}"))?;
        inside(&format!("blobs/{alg}/{hex}"))
    };
    let mut out = Vec::new();
    let mut pending: Vec<(serde_json::Value, Option<String>)> = index["manifests"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|d| {
            let name = d["annotations"]["io.containerd.image.name"]
                .as_str()
                .map(String::from);
            (d, name)
        })
        .collect();
    while let Some((descriptor, name)) = pending.pop() {
        let digest = descriptor["digest"]
            .as_str()
            .ok_or("descriptor without digest")?;
        let doc: serde_json::Value = serde_json::from_slice(
            &std::fs::read(blob(digest)?).map_err(|e| format!("read {digest}: {e}"))?,
        )
        .map_err(|e| format!("{digest}: {e}"))?;
        if let Some(manifests) = doc["manifests"].as_array() {
            // An index: take the entry for this host's platform.
            let arch = super::util::host_arch();
            let chosen = manifests
                .iter()
                .find(|m| m["platform"]["architecture"] == arch)
                .or_else(|| manifests.first());
            if let Some(m) = chosen {
                pending.push((m.clone(), name));
            }
            continue;
        }
        let config_digest = doc["config"]["digest"]
            .as_str()
            .ok_or("manifest without config")?;
        let layers = doc["layers"]
            .as_array()
            .map(|l| {
                l.iter()
                    .filter_map(|d| d["digest"].as_str())
                    .map(&blob)
                    .collect()
            })
            .transpose()?
            .unwrap_or_default();
        out.push(ArchiveImage {
            config: std::fs::read(blob(config_digest)?)
                .map_err(|e| format!("read config {config_digest}: {e}"))?,
            layers,
            repo_tags: name.into_iter().collect(),
        });
    }
    out.reverse();
    Ok(out)
}

/// Hash a file with SHA-256.
fn file_digest(path: &Path) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)?;
    Ok(hex::encode(hasher.finalize()))
}

/// Write `images` (each with the tags it goes under) to `out` as one
/// `docker save` archive, blobs under `blobs/sha256/`.
pub(crate) fn write_archive(
    out: &Path,
    images: &[(ArchiveImage, Vec<String>)],
) -> std::io::Result<()> {
    let mut tar = tar::Builder::new(std::io::BufWriter::new(std::fs::File::create(out)?));
    let mut written = std::collections::HashSet::new();
    let mut manifest = Vec::new();
    let mut add = |tar: &mut tar::Builder<_>, name: &str, data: &mut dyn Read, size: u64| {
        if !written.insert(name.to_string()) {
            return Ok(());
        }
        let mut header = tar::Header::new_gnu();
        header.set_size(size);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, name, data)
    };
    for (image, tags) in images {
        let config_name = format!("blobs/sha256/{}", image.id().trim_start_matches("sha256:"));
        add(
            &mut tar,
            &config_name,
            &mut image.config.as_slice(),
            image.config.len() as u64,
        )?;
        let mut layer_names = Vec::new();
        for layer in &image.layers {
            let name = format!("blobs/sha256/{}", file_digest(layer)?);
            let size = std::fs::metadata(layer)?.len();
            add(&mut tar, &name, &mut std::fs::File::open(layer)?, size)?;
            layer_names.push(name);
        }
        manifest.push(serde_json::json!({
            "Config": config_name,
            "RepoTags": if tags.is_empty() { serde_json::Value::Null } else { serde_json::json!(tags) },
            "Layers": layer_names,
        }));
    }
    let manifest = serde_json::to_vec(&manifest).map_err(std::io::Error::other)?;
    add(
        &mut tar,
        "manifest.json",
        &mut manifest.as_slice(),
        manifest.len() as u64,
    )?;
    tar.into_inner()?.flush()
}

/// The `docker save` archive `image` boots from, fetched on the host first
/// when it is a registry image.
pub(crate) async fn archive_of(image: &ImageRecord) -> ApiResult<PathBuf> {
    if crate::data::image_source::is_local_ref(&image.pull_ref) {
        return crate::data::image_source::archive_file_for_ref(&image.pull_ref)
            .filter(|p| p.exists())
            .ok_or_else(|| ApiError::internal(format!("the archive of {} is gone", image.id)));
    }
    let fetched = crate::image_store::fetch_image_archive(
        &image.pull_ref,
        &crate::registry::PullAuth::FromConfig,
    )
    .await
    .map_err(|e| ApiError::internal(format!("fetch {}: {e}", image.pull_ref)))?;
    crate::data::image_source::archive_file_for_ref(&fetched.local)
        .ok_or_else(|| ApiError::internal(format!("the archive of {} is gone", image.id)))
}

/// Unpack the archive of `image` into `dir` and return its image.
async fn unpacked(image: &ImageRecord, dir: &Path) -> ApiResult<ArchiveImage> {
    let archive = archive_of(image).await?;
    let dir = dir.to_path_buf();
    tokio::task::spawn_blocking(move || {
        unpack(&archive, &dir).map_err(io_error("unpack the image archive"))?;
        read_images(&dir)
            .map_err(ApiError::internal)?
            .into_iter()
            .next()
            .ok_or_else(|| ApiError::internal("the image archive holds no image"))
    })
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?
}

/// Store `image` in the local image cache as its own archive and record it
/// in the engine under `tags`.
pub(crate) fn register(
    engine: &Engine,
    image: &ArchiveImage,
    tags: &[String],
    work: &Path,
) -> ApiResult<ImageRecord> {
    let config: serde_json::Value = serde_json::from_slice(&image.config)
        .map_err(|e| ApiError::bad_request(format!("image config: {e}")))?;
    let archive = work.join(format!("{}.tar", image.id().trim_start_matches("sha256:")));
    write_archive(&archive, &[(image.clone(), tags.to_vec())])
        .map_err(io_error("write the image archive"))?;
    let reference =
        match crate::data::image_source::resolve(crate::data::image_source::ImageSource::Archive(
            crate::data::image_source::ArchiveInput::File(archive.clone()),
        ))
        .map_err(|e| ApiError::internal(format!("store the image: {e}")))?
        {
            crate::data::image_source::ResolvedImage::Local { reference, .. } => reference,
            crate::data::image_source::ResolvedImage::Registry(r) => r,
        };
    let _ = std::fs::remove_file(&archive);
    let record = ImageRecord {
        id: image.id(),
        repo_tags: familiar_tags(tags),
        repo_digests: Vec::new(),
        pull_ref: reference,
        config,
        size: image.size(),
        pulled: super::util::now_rfc3339(),
        last_tag_time: String::new(),
    };
    engine.images.insert(&engine.store, record.clone())?;
    Ok(engine.images.resolve(&record.id).unwrap_or(record))
}

/// Tags as the CLI shows them (`alpine:latest`), dropping malformed ones.
fn familiar_tags(tags: &[String]) -> Vec<String> {
    tags.iter()
        .filter_map(|t| ImageRef::parse(t).ok()?.familiar_tag())
        .collect()
}

fn temp_dir() -> ApiResult<tempfile::TempDir> {
    let base = crate::data::image_source::archive_staging_dir()
        .map_err(|e| ApiError::internal(format!("staging directory: {e}")))?;
    Ok(base)
}

/// The body of a request, written to `path` as it arrives.
pub(crate) async fn body_to_file(body: axum::body::Body, path: &Path) -> ApiResult<u64> {
    use tokio::io::AsyncWriteExt as _;
    use tokio_stream::StreamExt as _;
    let mut file = tokio::fs::File::create(path)
        .await
        .map_err(io_error("stage the upload"))?;
    let mut stream = body.into_data_stream();
    let mut total = 0u64;
    let limit = crate::data::image_source::max_archive_bytes();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| ApiError::bad_request(format!("read the upload: {e}")))?;
        total += chunk.len() as u64;
        if total > limit {
            return Err(ApiError::bad_request(format!(
                "the upload is over the {limit}-byte image limit"
            )));
        }
        file.write_all(&chunk)
            .await
            .map_err(io_error("stage the upload"))?;
    }
    file.flush().await.map_err(io_error("stage the upload"))?;
    Ok(total)
}

/// A response that streams `path`, keeping `keep` (the temporary directory
/// it lives in) until the last byte is sent.
fn stream_file(path: PathBuf, keep: tempfile::TempDir) -> ApiResult<axum::response::Response> {
    use tokio_stream::StreamExt as _;
    let file = std::fs::File::open(&path).map_err(io_error("open the archive"))?;
    let stream =
        tokio_util::io::ReaderStream::with_capacity(tokio::fs::File::from_std(file), 256 * 1024)
            .map(move |chunk| {
                let _ = &keep;
                chunk
            });
    let mut r = axum::response::Response::new(axum::body::Body::from_stream(stream));
    r.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/x-tar"),
    );
    Ok(r)
}

// ============================================================================
// docker save / load
// ============================================================================

/// `GET /images/{name}/get` and `GET /images/get?names=`: one archive of
/// every named image, each under the tag it was named by.
pub(crate) async fn save(
    engine: &Arc<Engine>,
    names: &[String],
) -> ApiResult<axum::response::Response> {
    if names.is_empty() {
        return Err(ApiError::bad_request("no image to save"));
    }
    let work = temp_dir()?;
    let mut images = Vec::new();
    for (i, name) in names.iter().enumerate() {
        let record = engine
            .images
            .resolve(name)
            .ok_or_else(|| ApiError::not_found(format!("No such image: {name}")))?;
        let tags: Vec<String> = match ImageRef::parse(name).ok().and_then(|r| r.familiar_tag()) {
            Some(tag) if record.repo_tags.contains(&tag) => vec![tag],
            _ if record.id.contains(name.trim_start_matches("sha256:")) => Vec::new(),
            _ => record.repo_tags.clone(),
        };
        let dir = work.path().join(i.to_string());
        let image = unpacked(&record, &dir).await?;
        images.push((image, tags));
    }
    let out = work.path().join("save.tar");
    let out2 = out.clone();
    tokio::task::spawn_blocking(move || write_archive(&out2, &images))
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
        .map_err(io_error("write the archive"))?;
    stream_file(out, work)
}

/// `POST /images/load`: every image in a `docker save` or OCI archive.
pub(crate) async fn load(
    engine: &Arc<Engine>,
    body: axum::body::Body,
    tx: tokio::sync::mpsc::Sender<serde_json::Value>,
) {
    let result: ApiResult<Vec<ImageRecord>> = async {
        let work = temp_dir()?;
        let upload = work.path().join("upload.tar");
        body_to_file(body, &upload).await?;
        let e = engine.clone();
        tokio::task::spawn_blocking(move || {
            let dir = work.path().join("unpacked");
            unpack(&upload, &dir)
                .map_err(|e| ApiError::bad_request(format!("unpack the archive: {e}")))?;
            let _ = std::fs::remove_file(&upload);
            let images = read_images(&dir).map_err(ApiError::bad_request)?;
            if images.is_empty() {
                return Err(ApiError::bad_request("the archive holds no image"));
            }
            images
                .iter()
                .map(|image| register(&e, image, &image.repo_tags, work.path()))
                .collect()
        })
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
    }
    .await;
    match result {
        Ok(records) => {
            for record in records {
                let line = if record.repo_tags.is_empty() {
                    format!("Loaded image ID: {}\n", record.id)
                } else {
                    record
                        .repo_tags
                        .iter()
                        .map(|t| format!("Loaded image: {t}\n"))
                        .collect()
                };
                engine.events.emit(
                    "image",
                    "load",
                    &record.id,
                    BTreeMap::from([("name".to_string(), record.id.clone())]),
                );
                let _ = tx.send(serde_json::json!({ "stream": line })).await;
            }
        }
        Err(e) => {
            let _ = tx
                .send(
                    serde_json::json!({"errorDetail": {"message": e.message}, "error": e.message}),
                )
                .await;
        }
    }
}

// ============================================================================
// docker import
// ============================================================================

/// `POST /images/create?fromSrc=`: a root filesystem tar (from the body with
/// `fromSrc=-`, or from a URL) as a one-layer image.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn import(
    engine: &Arc<Engine>,
    from: &str,
    repo: &str,
    tag: &str,
    message: &str,
    changes: &[String],
    platform: Option<&str>,
    body: axum::body::Body,
    tx: tokio::sync::mpsc::Sender<serde_json::Value>,
) {
    let result: ApiResult<ImageRecord> = async {
        let work = temp_dir()?;
        let upload = work.path().join("upload");
        if from == "-" {
            body_to_file(body, &upload).await?;
        } else {
            download(from, &upload).await?;
        }
        let (arch, variant) = match platform.and_then(|p| p.split('/').nth(1)) {
            Some(arch) => (
                arch.to_string(),
                platform.and_then(|p| p.split('/').nth(2)).map(String::from),
            ),
            None => (super::util::host_arch().to_string(), None),
        };
        let mut config = serde_json::Map::new();
        apply_changes(&mut config, changes)?;
        let tags = tag_list(repo, tag)?;
        let comment = if message.is_empty() {
            format!("Imported from {from}")
        } else {
            message.to_string()
        };
        let e = engine.clone();
        tokio::task::spawn_blocking(move || {
            let layer = work.path().join("layer.tar");
            let diff_id = decompress_to(&upload, &layer)?;
            let _ = std::fs::remove_file(&upload);
            let now = super::util::now_rfc3339();
            let mut image_config = serde_json::json!({
                "architecture": arch,
                "os": "linux",
                "created": now,
                "config": config,
                "rootfs": {"type": "layers", "diff_ids": [format!("sha256:{diff_id}")]},
                "history": [{"created": now, "comment": comment}],
            });
            if let Some(v) = variant {
                image_config["variant"] = serde_json::json!(v);
            }
            let image = ArchiveImage {
                config: serde_json::to_vec(&image_config)
                    .map_err(|e| ApiError::internal(e.to_string()))?,
                layers: vec![layer],
                repo_tags: tags.clone(),
            };
            register(&e, &image, &tags, work.path())
        })
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
    }
    .await;
    match result {
        Ok(record) => {
            engine.events.emit(
                "image",
                "import",
                &record.id,
                BTreeMap::from([("name".to_string(), record.id.clone())]),
            );
            let _ = tx.send(serde_json::json!({ "status": record.id })).await;
        }
        Err(e) => {
            let _ = tx
                .send(
                    serde_json::json!({"errorDetail": {"message": e.message}, "error": e.message}),
                )
                .await;
        }
    }
}

/// Fetch a root filesystem tar from a URL, as `docker import <url>` does.
async fn download(url: &str, path: &Path) -> ApiResult<()> {
    use tokio::io::AsyncWriteExt as _;
    use tokio_stream::StreamExt as _;
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(ApiError::bad_request(format!(
            "fromSrc must be - or an http(s) URL, not {url}"
        )));
    }
    let response = reqwest::get(url)
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| ApiError::bad_request(format!("download {url}: {e}")))?;
    let mut file = tokio::fs::File::create(path)
        .await
        .map_err(io_error("stage the download"))?;
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| ApiError::bad_request(format!("download {url}: {e}")))?;
        file.write_all(&chunk)
            .await
            .map_err(io_error("stage the download"))?;
    }
    file.flush().await.map_err(io_error("stage the download"))
}

/// Decompress `from` (tar, gzip or zstd) into `to` as a layer, returning the
/// SHA-256 of the plain tar: the layer's diff id. Entry names lose a leading
/// `./` (`tar -C dir .` writes them so), as image layers name their files.
fn decompress_to(from: &Path, to: &Path) -> ApiResult<String> {
    let reader = smolvm_oci_layer::decompress_layer_reader(std::io::BufReader::new(
        std::fs::File::open(from).map_err(io_error("open the upload"))?,
    ))
    .map_err(io_error("read the upload"))?;
    struct Hashing<W> {
        inner: W,
        hasher: Sha256,
    }
    impl<W: Write> Write for Hashing<W> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let n = self.inner.write(buf)?;
            self.hasher.update(&buf[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.inner.flush()
        }
    }
    let out = Hashing {
        inner: std::io::BufWriter::new(
            std::fs::File::create(to).map_err(io_error("write the layer"))?,
        ),
        hasher: Sha256::new(),
    };
    let bad = |e: std::io::Error| ApiError::bad_request(format!("read the upload: {e}"));
    let mut builder = tar::Builder::new(out);
    let mut archive = tar::Archive::new(reader);
    for entry in archive.entries().map_err(bad)? {
        let mut entry = entry.map_err(bad)?;
        let path = layer_path(&entry.path().map_err(bad)?);
        let Some(path) = path else { continue };
        let mut header = entry.header().clone();
        match header.entry_type() {
            tar::EntryType::Symlink | tar::EntryType::Link => {
                let target = entry
                    .link_name()
                    .map_err(bad)?
                    .unwrap_or_default()
                    .into_owned();
                let target = if header.entry_type() == tar::EntryType::Link {
                    layer_path(&target).unwrap_or(target)
                } else {
                    target
                };
                builder
                    .append_link(&mut header, &path, &target)
                    .map_err(io_error("write the layer"))?;
            }
            _ => builder
                .append_data(&mut header, &path, &mut entry)
                .map_err(io_error("write the layer"))?,
        }
    }
    let mut out = builder.into_inner().map_err(io_error("write the layer"))?;
    out.flush().map_err(io_error("write the layer"))?;
    Ok(hex::encode(out.hasher.finalize()))
}

/// A tar entry's name as a layer names it: no leading `./` or `/`, and
/// `None` for the archive's root itself.
fn layer_path(path: &Path) -> Option<PathBuf> {
    let rel: PathBuf = path
        .components()
        .filter(|c| matches!(c, std::path::Component::Normal(_)))
        .collect();
    (!rel.as_os_str().is_empty()).then_some(rel)
}

/// `repo:tag` as a tag list (`[]` without a repo).
fn tag_list(repo: &str, tag: &str) -> ApiResult<Vec<String>> {
    if repo.is_empty() {
        return Ok(Vec::new());
    }
    let name = if tag.is_empty() {
        repo.to_string()
    } else {
        format!("{repo}:{tag}")
    };
    let parsed = ImageRef::parse(&name).map_err(ApiError::bad_request)?;
    Ok(parsed.familiar_tag().into_iter().collect())
}

/// Apply Dockerfile instructions (`--change`) to an image's container
/// config: `CMD`, `ENTRYPOINT`, `ENV`, `EXPOSE`, `LABEL`, `USER`, `WORKDIR`,
/// `VOLUME`, `STOPSIGNAL`, `ONBUILD`.
pub(crate) fn apply_changes(
    config: &mut serde_json::Map<String, serde_json::Value>,
    changes: &[String],
) -> ApiResult<()> {
    for change in changes.iter().map(|c| c.trim()).filter(|c| !c.is_empty()) {
        let (instruction, rest) = change
            .split_once(char::is_whitespace)
            .unwrap_or((change, ""));
        let rest = rest.trim();
        let words = || -> Vec<String> {
            serde_json::from_str::<Vec<String>>(rest)
                .unwrap_or_else(|_| vec!["/bin/sh".into(), "-c".into(), rest.to_string()])
        };
        let pairs = || -> Vec<(String, String)> {
            if rest.contains('=') {
                split_words(rest)
                    .into_iter()
                    .filter_map(|w| {
                        w.split_once('=')
                            .map(|(k, v)| (k.to_string(), v.to_string()))
                    })
                    .collect()
            } else {
                let (k, v) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
                vec![(k.to_string(), v.trim().to_string())]
            }
        };
        match instruction.to_ascii_uppercase().as_str() {
            "CMD" => {
                config.insert("Cmd".into(), serde_json::json!(words()));
            }
            "ENTRYPOINT" => {
                config.insert("Entrypoint".into(), serde_json::json!(words()));
            }
            "ENV" => {
                let mut env: Vec<String> = config
                    .get("Env")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default();
                for (k, v) in pairs() {
                    env.retain(|e| e.split('=').next() != Some(k.as_str()));
                    env.push(format!("{k}={v}"));
                }
                config.insert("Env".into(), serde_json::json!(env));
            }
            "LABEL" => {
                let labels = config
                    .entry("Labels")
                    .or_insert_with(|| serde_json::json!({}));
                if !labels.is_object() {
                    *labels = serde_json::json!({});
                }
                for (k, v) in pairs() {
                    labels[k] = serde_json::json!(v.trim_matches('"'));
                }
            }
            "EXPOSE" => {
                let ports = config
                    .entry("ExposedPorts")
                    .or_insert_with(|| serde_json::json!({}));
                if !ports.is_object() {
                    *ports = serde_json::json!({});
                }
                for p in rest.split_whitespace() {
                    let key = if p.contains('/') {
                        p.to_string()
                    } else {
                        format!("{p}/tcp")
                    };
                    ports[key] = serde_json::json!({});
                }
            }
            "VOLUME" => {
                let volumes = config
                    .entry("Volumes")
                    .or_insert_with(|| serde_json::json!({}));
                if !volumes.is_object() {
                    *volumes = serde_json::json!({});
                }
                let paths = serde_json::from_str::<Vec<String>>(rest)
                    .unwrap_or_else(|_| rest.split_whitespace().map(String::from).collect());
                for p in paths {
                    volumes[p] = serde_json::json!({});
                }
            }
            "USER" => {
                config.insert("User".into(), serde_json::json!(rest));
            }
            "WORKDIR" => {
                config.insert("WorkingDir".into(), serde_json::json!(rest));
            }
            "STOPSIGNAL" => {
                config.insert("StopSignal".into(), serde_json::json!(rest));
            }
            "ONBUILD" => {
                let mut list: Vec<String> = config
                    .get("OnBuild")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default();
                list.push(rest.to_string());
                config.insert("OnBuild".into(), serde_json::json!(list));
            }
            other => {
                return Err(ApiError::bad_request(format!(
                    "{other} is not a valid change command"
                )))
            }
        }
    }
    Ok(())
}

/// Split on whitespace, keeping double-quoted runs together.
fn split_words(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut word = String::new();
    let mut quoted = false;
    for c in s.chars() {
        match c {
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => {
                if !word.is_empty() {
                    out.push(std::mem::take(&mut word));
                }
            }
            c => word.push(c),
        }
    }
    if !word.is_empty() {
        out.push(word);
    }
    out
}

// ============================================================================
// docker commit
// ============================================================================

/// What a commit takes from the request.
pub(crate) struct CommitRequest {
    pub repo: String,
    pub tag: String,
    pub comment: String,
    pub author: String,
    pub changes: Vec<String>,
    /// Container config fields the client set, over the container's own.
    pub config: serde_json::Value,
}

/// `POST /commit`: the container's changes as a new layer on its image,
/// with its config (the container's, then the client's, then `changes`).
pub(crate) async fn commit(
    engine: &Arc<Engine>,
    id: &str,
    req: CommitRequest,
) -> ApiResult<ImageRecord> {
    let c = engine
        .find_container(id)
        .ok_or_else(|| ApiError::no_such_container(id))?;
    let record = c.record();
    let base = engine
        .images
        .resolve(&record.image_id)
        .ok_or_else(|| ApiError::conflict(format!("the image of {} is gone", record.name)))?;
    let tags = tag_list(&req.repo, &req.tag)?;
    let work = temp_dir()?;
    let layer = work.path().join("diff.tar");
    super::archive::container_diff(engine, &c, &layer).await?;
    let base_image = unpacked(&base, &work.path().join("base")).await?;

    let mut config: serde_json::Value = serde_json::from_slice(&base_image.config)
        .map_err(|e| ApiError::internal(format!("base image config: {e}")))?;
    let mut container_config = serde_json::to_value(&record.config)
        .ok()
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default();
    for key in [
        "Hostname",
        "Domainname",
        "AttachStdin",
        "AttachStdout",
        "AttachStderr",
        "Tty",
        "OpenStdin",
        "StdinOnce",
        "Image",
    ] {
        container_config.remove(key);
    }
    if let Some(over) = req.config.as_object() {
        for (k, v) in over {
            let empty = v.is_null()
                || v.as_str().is_some_and(str::is_empty)
                || v.as_array().is_some_and(Vec::is_empty)
                || v.as_object().is_some_and(serde_json::Map::is_empty);
            if !empty {
                container_config.insert(k.clone(), v.clone());
            }
        }
    }
    apply_changes(&mut container_config, &req.changes)?;
    container_config.retain(|_, v| !v.is_null());
    let now = super::util::now_rfc3339();
    let (layer_path, diff_id) = {
        let layer = layer.clone();
        tokio::task::spawn_blocking(move || file_digest(&layer).map(|d| (layer, d)))
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?
            .map_err(io_error("hash the layer"))?
    };
    if let Some(obj) = config.as_object_mut() {
        obj.insert("config".into(), serde_json::Value::Object(container_config));
        obj.insert("created".into(), serde_json::json!(now));
        obj.insert("container".into(), serde_json::json!(record.id));
        obj.insert(
            "docker_version".into(),
            serde_json::json!(super::model::ENGINE_VERSION),
        );
        if !req.author.is_empty() {
            obj.insert("author".into(), serde_json::json!(req.author));
        }
        if !req.comment.is_empty() {
            obj.insert("comment".into(), serde_json::json!(req.comment));
        }
        obj.remove("id");
        obj.remove("parent");
    }
    if let Some(ids) = config["rootfs"]["diff_ids"].as_array_mut() {
        ids.push(serde_json::json!(format!("sha256:{diff_id}")));
    } else {
        config["rootfs"] =
            serde_json::json!({"type": "layers", "diff_ids": [format!("sha256:{diff_id}")]});
    }
    let mut created_by = record.path.clone();
    for a in &record.args {
        created_by.push(' ');
        created_by.push_str(a);
    }
    let entry = serde_json::json!({
        "created": now, "created_by": created_by, "author": req.author, "comment": req.comment,
    });
    match config["history"].as_array_mut() {
        Some(h) => h.push(entry),
        None => config["history"] = serde_json::json!([entry]),
    }
    let mut layers = base_image.layers.clone();
    layers.push(layer_path);
    let image = ArchiveImage {
        config: serde_json::to_vec(&config).map_err(|e| ApiError::internal(e.to_string()))?,
        layers,
        repo_tags: tags.clone(),
    };
    let e = engine.clone();
    let committed = tokio::task::spawn_blocking(move || {
        let result = register(&e, &image, &tags, work.path());
        drop(work);
        result
    })
    .await
    .map_err(|e| ApiError::internal(e.to_string()))??;
    engine.events.emit(
        "container",
        "commit",
        &record.id,
        BTreeMap::from([
            ("name".to_string(), record.name.clone()),
            ("comment".to_string(), req.comment.clone()),
        ]),
    );
    Ok(committed)
}

// ============================================================================
// docker push
// ============================================================================

/// `POST /images/{name}/push`: upload the image under `name:tag` (every tag
/// of `name` when no tag is given) to its registry.
pub(crate) async fn push(
    engine: &Arc<Engine>,
    name: &str,
    tag: &str,
    auth: crate::registry::PullAuth,
    tx: tokio::sync::mpsc::Sender<serde_json::Value>,
) {
    if let Err(e) = push_inner(engine, name, tag, auth, &tx).await {
        let _ = tx
            .send(serde_json::json!({"errorDetail": {"message": e.message}, "error": e.message}))
            .await;
    }
}

async fn push_inner(
    engine: &Arc<Engine>,
    name: &str,
    tag: &str,
    auth: crate::registry::PullAuth,
    tx: &tokio::sync::mpsc::Sender<serde_json::Value>,
) -> ApiResult<()> {
    let base = ImageRef::parse(name).map_err(ApiError::bad_request)?;
    let refs: Vec<ImageRef> = if !tag.is_empty() {
        vec![ImageRef::parse(&format!("{}:{tag}", base.familiar_repo()))
            .map_err(ApiError::bad_request)?]
    } else if name.contains(':') && !name.ends_with(':') {
        vec![base.clone()]
    } else {
        let repo = base.familiar_repo();
        let mut all: Vec<ImageRef> = engine
            .images
            .all()
            .iter()
            .flat_map(|i| i.repo_tags.clone())
            .filter(|t| t.rsplit_once(':').is_some_and(|(r, _)| r == repo))
            .filter_map(|t| ImageRef::parse(&t).ok())
            .collect();
        all.sort_by(|a, b| a.tag.cmp(&b.tag));
        all
    };
    if refs.is_empty() {
        return Err(ApiError::not_found(format!(
            "An image does not exist locally with the tag: {name}"
        )));
    }
    let _ = tx
        .send(serde_json::json!({"status": format!("The push refers to repository [{}/{}]", base.domain, base.path)}))
        .await;
    for reference in refs {
        let shown = reference.familiar_tag().unwrap_or_default();
        let record = engine.images.resolve(&shown).ok_or_else(|| {
            ApiError::not_found(format!(
                "An image does not exist locally with the tag: {shown}"
            ))
        })?;
        let work = temp_dir()?;
        let image = unpacked(&record, &work.path().join("image")).await?;
        let client = push_client(&reference, &auth)?;
        let repo = match reference.domain.as_str() {
            "docker.io" => reference.path.clone(),
            _ => reference.path.clone(),
        };
        let mut descriptors = Vec::new();
        for layer in &image.layers {
            let blob = compressed(layer, work.path())?;
            let short: String = blob
                .digest
                .trim_start_matches("sha256:")
                .chars()
                .take(12)
                .collect();
            let _ = tx
                .send(serde_json::json!({"status": "Preparing", "progressDetail": {}, "id": short}))
                .await;
            let exists = client
                .blob_exists(&repo, &blob.digest)
                .await
                .unwrap_or(false);
            if exists {
                let _ = tx
                    .send(serde_json::json!({"status": "Layer already exists", "progressDetail": {}, "id": short}))
                    .await;
            } else {
                client
                    .push_blob_file(&repo, &blob.digest, &blob.path)
                    .await
                    .map_err(|e| push_error(&reference, e))?;
                let _ = tx
                    .send(
                        serde_json::json!({"status": "Pushed", "progressDetail": {}, "id": short}),
                    )
                    .await;
            }
            descriptors.push(serde_json::json!({
                "mediaType": blob.media_type, "digest": blob.digest, "size": blob.size,
            }));
        }
        let config_digest = image.id();
        if !client
            .blob_exists(&repo, &config_digest)
            .await
            .unwrap_or(false)
        {
            client
                .push_blob(&repo, &image.config)
                .await
                .map_err(|e| push_error(&reference, e))?;
        }
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
                "size": image.config.len(),
            },
            "layers": descriptors,
        });
        let manifest =
            serde_json::to_vec(&manifest).map_err(|e| ApiError::internal(e.to_string()))?;
        let tag = reference.tag.clone().unwrap_or_else(|| "latest".into());
        client
            .put_manifest(&repo, &tag, &manifest)
            .await
            .map_err(|e| push_error(&reference, e))?;
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&manifest)));
        let mut record = record;
        let pinned = format!("{}@{digest}", reference.familiar_repo());
        if !record.repo_digests.contains(&pinned) {
            record.repo_digests.push(pinned);
            let _ = engine.images.insert(&engine.store, record);
        }
        let _ = tx
            .send(serde_json::json!({"status": format!("{tag}: digest: {digest} size: {}", manifest.len())}))
            .await;
        let _ = tx
            .send(serde_json::json!({"progressDetail": {}, "aux": {"Tag": tag, "Digest": digest, "Size": manifest.len()}}))
            .await;
        engine.events.emit(
            "image",
            "push",
            &shown,
            BTreeMap::from([("name".to_string(), shown.clone())]),
        );
    }
    Ok(())
}

fn push_error(reference: &ImageRef, e: impl std::fmt::Display) -> ApiError {
    ApiError::internal(format!("push {}: {e}", reference.full()))
}

/// A registry client for pushing to `reference`'s registry itself, never a
/// pull mirror configured for it.
fn push_client(
    reference: &ImageRef,
    auth: &crate::registry::PullAuth,
) -> ApiResult<smolvm_registry::RegistryClient> {
    let mut config = crate::SmolSettings::load()
        .map_err(|e| ApiError::internal(format!("settings: {e}")))?
        .images;
    for entry in config.registries.values_mut() {
        entry.mirror = None;
    }
    Ok(crate::registry::registry_client(
        &reference.domain,
        &config,
        auth,
    ))
}

/// A layer ready to upload: compressed with gzip unless it already is.
struct Blob {
    path: PathBuf,
    digest: String,
    size: u64,
    media_type: &'static str,
}

fn compressed(layer: &Path, work: &Path) -> ApiResult<Blob> {
    let mut magic = [0u8; 4];
    let n = std::fs::File::open(layer)
        .and_then(|mut f| f.read(&mut magic))
        .map_err(io_error("read the layer"))?;
    let media_type = if n >= 2 && magic[..2] == [0x1f, 0x8b] {
        Some("application/vnd.oci.image.layer.v1.tar+gzip")
    } else if n >= 4 && magic == [0x28, 0xb5, 0x2f, 0xfd] {
        Some("application/vnd.oci.image.layer.v1.tar+zstd")
    } else {
        None
    };
    let (path, media_type) = match media_type {
        Some(m) => (layer.to_path_buf(), m),
        None => {
            let out = work.join(format!(
                "{}.gz",
                layer
                    .file_name()
                    .and_then(|f| f.to_str())
                    .unwrap_or("layer")
            ));
            let mut encoder = flate2::write::GzEncoder::new(
                std::io::BufWriter::new(
                    std::fs::File::create(&out).map_err(io_error("compress the layer"))?,
                ),
                flate2::Compression::default(),
            );
            std::io::copy(
                &mut std::fs::File::open(layer).map_err(io_error("read the layer"))?,
                &mut encoder,
            )
            .map_err(io_error("compress the layer"))?;
            encoder
                .finish()
                .and_then(|mut w| w.flush())
                .map_err(io_error("compress the layer"))?;
            (out, "application/vnd.oci.image.layer.v1.tar+gzip")
        }
    };
    let digest = format!(
        "sha256:{}",
        file_digest(&path).map_err(io_error("hash the layer"))?
    );
    let size = std::fs::metadata(&path)
        .map_err(io_error("read the layer"))?
        .len();
    Ok(Blob {
        path,
        digest,
        size,
        media_type,
    })
}

// ============================================================================
// Pulls from a registry on this host
// ============================================================================

/// Whether a pull of `reference` must be fetched by the host: its registry is
/// on this host's loopback, which a guest cannot reach.
pub(crate) fn host_fetched(reference: &ImageRef) -> bool {
    smolvm_registry::is_local_registry(&reference.domain)
}

/// Fetch `pull_ref` on the host and return the local reference it boots
/// from.
pub(crate) async fn fetch_on_host(
    pull_ref: &str,
    auth: &crate::registry::PullAuth,
) -> ApiResult<String> {
    crate::image_store::fetch_image_archive(pull_ref, auth)
        .await
        .map(|f| f.local)
        .map_err(|e| ApiError::internal(format!("fetch {pull_ref}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changes_set_the_config_as_dockerfile_instructions_do() {
        let mut c = serde_json::Map::new();
        apply_changes(
            &mut c,
            &[
                r#"CMD ["nginx", "-g", "daemon off;"]"#.into(),
                "ENV A=1 B=two".into(),
                "ENV C 3".into(),
                "EXPOSE 8080 53/udp".into(),
                r#"LABEL org.example="yes""#.into(),
                "WORKDIR /srv".into(),
                "USER app".into(),
                "ENTRYPOINT /run.sh".into(),
            ],
        )
        .unwrap();
        assert_eq!(c["Cmd"], serde_json::json!(["nginx", "-g", "daemon off;"]));
        assert_eq!(c["Env"], serde_json::json!(["A=1", "B=two", "C=3"]));
        assert!(c["ExposedPorts"]["8080/tcp"].is_object());
        assert!(c["ExposedPorts"]["53/udp"].is_object());
        assert_eq!(c["Labels"]["org.example"], "yes");
        assert_eq!(c["WorkingDir"], "/srv");
        assert_eq!(c["User"], "app");
        assert_eq!(
            c["Entrypoint"],
            serde_json::json!(["/bin/sh", "-c", "/run.sh"])
        );
        assert!(apply_changes(&mut c, &["RUN true".into()]).is_err());
    }

    #[test]
    fn archives_round_trip_with_their_tags() {
        let dir = tempfile::tempdir().unwrap();
        let layer = dir.path().join("l.tar");
        std::fs::write(&layer, b"layer bytes").unwrap();
        let image = ArchiveImage {
            config:
                br#"{"architecture":"arm64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}"#
                    .to_vec(),
            layers: vec![layer],
            repo_tags: vec![],
        };
        let out = dir.path().join("out.tar");
        write_archive(&out, &[(image.clone(), vec!["app:1".into()])]).unwrap();
        let unpacked = dir.path().join("u");
        unpack(&out, &unpacked).unwrap();
        let images = read_images(&unpacked).unwrap();
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].id(), image.id());
        assert_eq!(images[0].repo_tags, vec!["app:1".to_string()]);
        assert_eq!(std::fs::read(&images[0].layers[0]).unwrap(), b"layer bytes");
    }

    #[test]
    fn imported_layers_name_files_as_layers_do() {
        assert_eq!(
            layer_path(Path::new("./bin/sh")),
            Some(PathBuf::from("bin/sh"))
        );
        assert_eq!(layer_path(Path::new("./")), None);
        assert_eq!(
            layer_path(Path::new("/etc/hosts")),
            Some(PathBuf::from("etc/hosts"))
        );
    }

    #[test]
    fn archive_paths_stay_inside_the_archive() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("manifest.json"),
            br#"[{"Config":"../../etc/passwd","Layers":[]}]"#,
        )
        .unwrap();
        assert!(read_images(dir.path()).is_err());
    }
}
