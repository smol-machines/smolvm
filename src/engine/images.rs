//! Images: references, the engine's image records, and `docker pull`.
//!
//! A pull resolves the image on the host (manifest and config only, with the
//! caller's registry authorization) and then builds the image's seed: a
//! throwaway machine pulls the layers in its guest, as every smolvm image
//! pull happens, and its storage disk becomes the disk every container of the
//! image starts from. The record keeps the config so containers resolve their
//! command without booting anything, and the digest-pinned reference so
//! every container of the image runs exactly what was pulled.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use super::filters::Filters;
use super::store::Store;
use super::util::{ApiError, ApiResult};

/// A Docker image reference, normalized the way the Docker CLI does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ImageRef {
    /// Registry host (`docker.io`, `ghcr.io`, `localhost:5000`).
    pub domain: String,
    /// Repository path (`library/alpine`, `user/app`).
    pub path: String,
    /// Tag, when the reference has one.
    pub tag: Option<String>,
    /// Digest, when the reference has one.
    pub digest: Option<String>,
}

impl ImageRef {
    /// Parse `name`, defaulting the registry to Docker Hub and the tag to
    /// `latest` when there is neither tag nor digest.
    pub(crate) fn parse(name: &str) -> Result<Self, String> {
        let name = name.trim();
        if name.is_empty() {
            return Err("empty image reference".into());
        }
        let (rest, digest) = match name.split_once('@') {
            Some((rest, digest)) => (rest, Some(digest.to_string())),
            None => (name, None),
        };
        if let Some(d) = &digest {
            let ok = d
                .strip_prefix("sha256:")
                .is_some_and(|hex| hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()));
            if !ok {
                return Err(format!("invalid reference format: {name}"));
            }
        }
        let (repo, tag) = match rest.rfind(':') {
            Some(i) if !rest[i + 1..].contains('/') => {
                (&rest[..i], Some(rest[i + 1..].to_string()))
            }
            _ => (rest, None),
        };
        let (domain, path) = match repo.split_once('/') {
            Some((first, remainder))
                if first.contains('.') || first.contains(':') || first == "localhost" =>
            {
                (first.to_string(), remainder.to_string())
            }
            _ => ("docker.io".to_string(), repo.to_string()),
        };
        let domain = match domain.as_str() {
            "index.docker.io" | "registry-1.docker.io" => "docker.io".to_string(),
            _ => domain,
        };
        let path = if domain == "docker.io" && !path.contains('/') {
            format!("library/{path}")
        } else {
            path
        };
        let valid = !path.is_empty()
            && path.split('/').all(|part| {
                !part.is_empty()
                    && part
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "._-".contains(c))
            })
            && tag.as_deref().is_none_or(|t| {
                !t.is_empty()
                    && t.len() <= 128
                    && t.chars()
                        .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
            });
        if !valid {
            return Err(format!("invalid reference format: {name}"));
        }
        let tag = match (&tag, &digest) {
            (None, None) => Some("latest".to_string()),
            _ => tag,
        };
        Ok(Self {
            domain,
            path,
            tag,
            digest,
        })
    }

    /// The repository as the CLI shows it: `alpine`, `user/app`, `ghcr.io/x/y`.
    pub(crate) fn familiar_repo(&self) -> String {
        if self.domain == "docker.io" {
            self.path
                .strip_prefix("library/")
                .unwrap_or(&self.path)
                .to_string()
        } else {
            format!("{}/{}", self.domain, self.path)
        }
    }

    /// `repo:tag` in familiar form, when the reference has a tag.
    pub(crate) fn familiar_tag(&self) -> Option<String> {
        self.tag
            .as_ref()
            .map(|t| format!("{}:{t}", self.familiar_repo()))
    }

    /// The fully qualified reference a registry resolves.
    pub(crate) fn full(&self) -> String {
        let mut s = format!("{}/{}", self.domain, self.path);
        if let Some(t) = &self.tag {
            s.push(':');
            s.push_str(t);
        }
        if let Some(d) = &self.digest {
            s.push('@');
            s.push_str(d);
        }
        s
    }

    /// The fully qualified reference pinned to `digest`.
    pub(crate) fn pinned(&self, digest: &str) -> String {
        format!("{}/{}@{digest}", self.domain, self.path)
    }
}

/// What the engine knows about one pulled image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ImageRecord {
    /// `sha256:<config digest>`.
    pub id: String,
    pub repo_tags: Vec<String>,
    pub repo_digests: Vec<String>,
    /// The digest-pinned reference containers of this image run.
    pub pull_ref: String,
    /// The image's config blob.
    pub config: serde_json::Value,
    pub size: i64,
    /// When the engine pulled it.
    pub pulled: String,
    #[serde(default)]
    pub last_tag_time: String,
}

impl ImageRecord {
    pub(crate) fn architecture(&self) -> &str {
        self.config["architecture"].as_str().unwrap_or("")
    }

    pub(crate) fn created(&self) -> String {
        self.config["created"]
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| self.pulled.clone())
    }

    /// The image's container config (`Env`, `Cmd`, `Entrypoint`, ...).
    pub(crate) fn container_config(&self) -> &serde_json::Value {
        &self.config["config"]
    }

    pub(crate) fn labels(&self) -> BTreeMap<String, String> {
        self.container_config()["Labels"]
            .as_object()
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_string())))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn short_id(&self) -> &str {
        let hex = self.id.strip_prefix("sha256:").unwrap_or(&self.id);
        &hex[..hex.len().min(12)]
    }

    /// `GET /images/json` entry.
    pub(crate) fn summary(&self, containers: i64) -> serde_json::Value {
        serde_json::json!({
            "Id": self.id,
            "ParentId": "",
            "RepoTags": self.repo_tags,
            "RepoDigests": self.repo_digests,
            "Created": super::util::unix_seconds(&self.created()),
            "Size": self.size,
            "SharedSize": -1,
            "VirtualSize": self.size,
            "Labels": self.labels(),
            "Containers": containers,
        })
    }

    /// `GET /images/{name}/json` body.
    pub(crate) fn inspect(&self) -> serde_json::Value {
        serde_json::json!({
            "Id": self.id,
            "RepoTags": self.repo_tags,
            "RepoDigests": self.repo_digests,
            "Parent": "",
            "Comment": self.config["comment"].as_str().unwrap_or(""),
            "Created": self.created(),
            "DockerVersion": self.config["docker_version"].as_str().unwrap_or(""),
            "Author": self.config["author"].as_str().unwrap_or(""),
            "Config": self.container_config(),
            "Architecture": self.architecture(),
            "Variant": self.config["variant"].as_str().unwrap_or(""),
            "Os": self.config["os"].as_str().unwrap_or("linux"),
            "Size": self.size,
            "VirtualSize": self.size,
            "GraphDriver": {"Name": "smolvm", "Data": null},
            "RootFS": {
                "Type": "layers",
                "Layers": self.config["rootfs"]["diff_ids"],
            },
            "Metadata": {"LastTagTime": if self.last_tag_time.is_empty() { super::util::ZERO_TIME } else { &self.last_tag_time }},
        })
    }

    /// `GET /images/{name}/history` body.
    pub(crate) fn history(&self) -> serde_json::Value {
        let entries = self.config["history"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let mut out: Vec<serde_json::Value> = entries
            .iter()
            .rev()
            .enumerate()
            .map(|(i, h)| {
                serde_json::json!({
                    "Id": if i == 0 { self.id.as_str() } else { "<missing>" },
                    "Created": super::util::unix_seconds(h["created"].as_str().unwrap_or("")),
                    "CreatedBy": h["created_by"].as_str().unwrap_or(""),
                    "Tags": if i == 0 { serde_json::json!(self.repo_tags) } else { serde_json::Value::Null },
                    "Size": 0,
                    "Comment": h["comment"].as_str().unwrap_or(""),
                })
            })
            .collect();
        if out.is_empty() {
            out.push(serde_json::json!({
                "Id": self.id, "Created": 0, "CreatedBy": "", "Tags": self.repo_tags,
                "Size": self.size, "Comment": "",
            }));
        }
        serde_json::Value::Array(out)
    }
}

/// The engine's images.
pub(crate) struct Images {
    records: parking_lot::RwLock<HashMap<String, ImageRecord>>,
    /// One pull per image at a time; concurrent pulls of it wait and share.
    pulls: parking_lot::Mutex<HashMap<String, std::sync::Arc<tokio::sync::Mutex<()>>>>,
}

impl Images {
    pub(crate) fn load(store: &Store) -> crate::Result<Self> {
        let records = store
            .load_objects::<ImageRecord>("images")?
            .into_iter()
            .map(|r| (r.id.clone(), r))
            .collect();
        Ok(Self {
            records: parking_lot::RwLock::new(records),
            pulls: parking_lot::Mutex::new(HashMap::new()),
        })
    }

    /// The image `name` refers to: an id (full or a unique prefix, with or
    /// without `sha256:`), a tag, or a digest reference.
    pub(crate) fn resolve(&self, name: &str) -> Option<ImageRecord> {
        let records = self.records.read();
        let hex = name.strip_prefix("sha256:").unwrap_or(name);
        if hex.len() >= 4 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
            let mut matches = records
                .values()
                .filter(|r| r.id.trim_start_matches("sha256:").starts_with(hex));
            if let (Some(r), None) = (matches.next(), matches.next()) {
                return Some(r.clone());
            }
        }
        let parsed = ImageRef::parse(name).ok()?;
        if let Some(digest) = &parsed.digest {
            let want = format!("{}@{digest}", parsed.familiar_repo());
            return records
                .values()
                .find(|r| r.repo_digests.contains(&want))
                .cloned();
        }
        let tag = parsed.familiar_tag()?;
        records
            .values()
            .find(|r| r.repo_tags.contains(&tag))
            .cloned()
    }

    pub(crate) fn all(&self) -> Vec<ImageRecord> {
        self.records.read().values().cloned().collect()
    }

    /// Store `record`, moving each of its tags off any other image.
    pub(crate) fn insert(&self, store: &Store, record: ImageRecord) -> crate::Result<()> {
        let mut records = self.records.write();
        let mut retagged = Vec::new();
        for other in records.values_mut() {
            if other.id == record.id {
                continue;
            }
            let before = other.repo_tags.len();
            other.repo_tags.retain(|t| !record.repo_tags.contains(t));
            if other.repo_tags.len() != before {
                retagged.push(other.clone());
            }
        }
        for other in retagged {
            store.save_object("images", other.id.trim_start_matches("sha256:"), &other)?;
        }
        let merged = match records.remove(&record.id) {
            Some(mut existing) => {
                for t in record.repo_tags {
                    if !existing.repo_tags.contains(&t) {
                        existing.repo_tags.push(t);
                    }
                }
                for d in record.repo_digests {
                    if !existing.repo_digests.contains(&d) {
                        existing.repo_digests.push(d);
                    }
                }
                existing.pull_ref = record.pull_ref;
                existing.config = record.config;
                existing
            }
            None => record,
        };
        store.save_object("images", merged.id.trim_start_matches("sha256:"), &merged)?;
        records.insert(merged.id.clone(), merged);
        Ok(())
    }

    fn save(&self, store: &Store, record: &ImageRecord) -> crate::Result<()> {
        store.save_object("images", record.id.trim_start_matches("sha256:"), record)?;
        self.records
            .write()
            .insert(record.id.clone(), record.clone());
        Ok(())
    }

    /// Add `repo:tag` to the image `name`.
    pub(crate) fn tag(&self, store: &Store, name: &str, repo: &str, tag: &str) -> ApiResult<()> {
        let image = self
            .resolve(name)
            .ok_or_else(|| ApiError::not_found(format!("No such image: {name}")))?;
        let target = if tag.is_empty() {
            repo.to_string()
        } else {
            format!("{repo}:{tag}")
        };
        let parsed = ImageRef::parse(&target).map_err(ApiError::bad_request)?;
        let familiar = parsed
            .familiar_tag()
            .ok_or_else(|| ApiError::bad_request("refusing to create a tag with a digest"))?;
        let mut record = image;
        if !record.repo_tags.contains(&familiar) {
            record.repo_tags.push(familiar);
        }
        record.last_tag_time = super::util::now_rfc3339();
        self.insert(store, record).map_err(ApiError::from)
    }

    /// `DELETE /images/{name}`: untag, then delete when no tag is left.
    pub(crate) fn remove(
        &self,
        store: &Store,
        name: &str,
        force: bool,
        in_use_by: impl Fn(&str) -> Option<String>,
    ) -> ApiResult<Vec<serde_json::Value>> {
        let image = self
            .resolve(name)
            .ok_or_else(|| ApiError::not_found(format!("No such image: {name}")))?;
        let mut out = Vec::new();
        let by_tag = ImageRef::parse(name)
            .ok()
            .and_then(|r| r.familiar_tag())
            .filter(|t| image.repo_tags.contains(t));
        let mut record = image.clone();
        if let Some(tag) = by_tag {
            if record.repo_tags.len() > 1 || force {
                record.repo_tags.retain(|t| t != &tag);
                out.push(serde_json::json!({ "Untagged": tag }));
                if !record.repo_tags.is_empty() {
                    self.save(store, &record)?;
                    return Ok(out);
                }
            }
        }
        if let Some(container) = in_use_by(&image.id) {
            if !force {
                return Err(ApiError::conflict(format!(
                    "conflict: unable to delete {} (must be forced) - image is being used by container {}",
                    image.short_id(),
                    &container[..container.len().min(12)]
                )));
            }
        }
        for tag in &record.repo_tags {
            out.push(serde_json::json!({ "Untagged": tag }));
        }
        for digest in &record.repo_digests {
            out.push(serde_json::json!({ "Untagged": digest }));
        }
        out.push(serde_json::json!({ "Deleted": image.id }));
        store.remove_object("images", image.id.trim_start_matches("sha256:"));
        self.records.write().remove(&image.id);
        Ok(out)
    }

    /// The lock serializing pulls of `key`.
    pub(crate) fn pull_lock(&self, key: &str) -> std::sync::Arc<tokio::sync::Mutex<()>> {
        self.pulls
            .lock()
            .entry(key.to_string())
            .or_default()
            .clone()
    }
}

/// Whether `image` passes the `docker images` filters.
pub(crate) fn matches(image: &ImageRecord, filters: &Filters) -> bool {
    filters.any("dangling", |d| (d == "true") == image.repo_tags.is_empty())
        && filters.labels_match("label", &image.labels())
        && filters.any("reference", |pattern| {
            image
                .repo_tags
                .iter()
                .any(|t| reference_matches(pattern, t))
        })
}

/// `docker images --filter reference=...`: a shell-style pattern against
/// `repo:tag`, or against the repository alone when it has no tag part.
fn reference_matches(pattern: &str, repo_tag: &str) -> bool {
    let repo = repo_tag
        .rsplit_once(':')
        .map(|(r, _)| r)
        .unwrap_or(repo_tag);
    glob(pattern, repo_tag) || (!pattern.contains(':') && glob(pattern, repo))
}

fn glob(pattern: &str, text: &str) -> bool {
    fn go(p: &[u8], t: &[u8]) -> bool {
        match (p.first(), t.first()) {
            (None, None) => true,
            (Some(b'*'), _) => go(&p[1..], t) || (!t.is_empty() && t[0] != b'/' && go(p, &t[1..])),
            (Some(b'?'), Some(c)) if *c != b'/' => go(&p[1..], &t[1..]),
            (Some(a), Some(b)) if a == b => go(&p[1..], &t[1..]),
            _ => false,
        }
    }
    go(pattern.as_bytes(), text.as_bytes())
}

/// Registry credentials from an `X-Registry-Auth` header, or the host's own
/// Docker config when the client sent none.
pub(crate) fn pull_auth(header: Option<&str>) -> crate::registry::PullAuth {
    use base64::Engine as _;
    let Some(header) = header.map(str::trim).filter(|h| !h.is_empty()) else {
        return crate::registry::PullAuth::FromConfig;
    };
    let decoded = base64::engine::general_purpose::URL_SAFE
        .decode(header)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(header))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(header));
    let Ok(decoded) = decoded else {
        return crate::registry::PullAuth::FromConfig;
    };
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct AuthConfig {
        username: String,
        password: String,
        auth: String,
        identitytoken: String,
        registrytoken: String,
    }
    let Ok(cfg) = serde_json::from_slice::<AuthConfig>(&decoded) else {
        return crate::registry::PullAuth::FromConfig;
    };
    if !cfg.registrytoken.is_empty() {
        return crate::registry::PullAuth::Bearer(cfg.registrytoken);
    }
    if !cfg.identitytoken.is_empty() {
        return crate::registry::PullAuth::Identity(cfg.identitytoken);
    }
    let (username, password) = if !cfg.username.is_empty() {
        (cfg.username, cfg.password)
    } else if !cfg.auth.is_empty() {
        match base64::engine::general_purpose::STANDARD
            .decode(&cfg.auth)
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .and_then(|s| {
                s.split_once(':')
                    .map(|(u, p)| (u.to_string(), p.to_string()))
            }) {
            Some(pair) => pair,
            None => return crate::registry::PullAuth::FromConfig,
        }
    } else {
        return crate::registry::PullAuth::FromConfig;
    };
    crate::registry::PullAuth::Basic { username, password }
}

/// How long a resolved digest stays trusted for seed lookups. A pinned
/// reference never resolves to anything else, so this only spares the
/// registry round trip each container's first start would otherwise make.
pub(crate) const PINNED_DIGEST_TTL_SECS: u64 = 365 * 24 * 3600;

/// Resolve `reference` on the host: everything a pull needs before layers.
pub(crate) async fn resolve(
    reference: &ImageRef,
    auth: &crate::registry::PullAuth,
    platform: Option<&str>,
) -> ApiResult<crate::image_store::ImageMetadata> {
    let mut attempt = 0;
    let result = loop {
        let result =
            crate::image_store::authorized_image_metadata(&reference.full(), auth, platform).await;
        match &result {
            Err(e) if rate_limited(&e.to_string()) && attempt < RATE_LIMIT_RETRIES => {
                attempt += 1;
                tokio::time::sleep(rate_limit_backoff(attempt)).await;
            }
            _ => break result,
        }
    };
    result.map_err(|e| {
            let text = e.to_string();
            let lower = text.to_ascii_lowercase();
            if lower.contains("404")
                || lower.contains("not found")
                || lower.contains("401")
                || lower.contains("unauthorized")
                || lower.contains("denied")
            {
                ApiError::not_found(format!(
                    "pull access denied for {}, repository does not exist or may require 'docker login': {text}",
                    reference.familiar_repo()
                ))
            } else {
                ApiError::internal(format!(
                    "failed to resolve reference \"{}\": {text}",
                    reference.full()
                ))
            }
        })
}

/// Attempts after a registry answers 429 before a pull gives up.
const RATE_LIMIT_RETRIES: u32 = 6;

/// Whether a registry error is a rate limit, which passes with time.
fn rate_limited(error: &str) -> bool {
    error.contains("429") || error.contains("TOOMANYREQUESTS")
}

/// Wait before retry `attempt` (1-based) after a rate limit: 2, 4, 8, ... s.
fn rate_limit_backoff(attempt: u32) -> std::time::Duration {
    std::time::Duration::from_secs(1u64 << attempt.min(5))
}

/// Build the seed for a resolved image, so its containers start on it. Runs
/// a throwaway machine; blocking. A rate-limited registry is retried with
/// backoff, as a busy registry mirror answers bursts of pulls.
pub(crate) fn build_seed(pull_ref: &str, auth: &crate::registry::PullAuth) -> crate::Result<()> {
    let exe = crate::image_seed::builder_exe()
        .map_err(|e| crate::Error::config("image seed", e.to_string()))?;
    let mut attempt = 0;
    loop {
        match crate::image_seed::ensure_image_seed(
            &exe,
            pull_ref,
            auth,
            Some(PINNED_DIGEST_TTL_SECS),
        ) {
            Err(e) if rate_limited(&e.to_string()) && attempt < RATE_LIMIT_RETRIES => {
                attempt += 1;
                std::thread::sleep(rate_limit_backoff(attempt));
            }
            other => return other,
        }
    }
}

/// The streamed part of `docker pull`, after the image resolved: build its
/// seed, record it, and report progress lines the CLI renders.
pub(crate) async fn finish_pull(
    engine: std::sync::Arc<super::Engine>,
    reference: ImageRef,
    meta: crate::image_store::ImageMetadata,
    auth: crate::registry::PullAuth,
    tx: tokio::sync::mpsc::Sender<serde_json::Value>,
) {
    let shown = reference.familiar_tag().unwrap_or_else(|| {
        format!(
            "{}@{}",
            reference.familiar_repo(),
            reference.digest.clone().unwrap_or_default()
        )
    });
    let label = reference
        .tag
        .clone()
        .or_else(|| reference.digest.clone())
        .unwrap_or_else(|| "latest".into());
    let _ = tx
        .send(
            serde_json::json!({"status": format!("Pulling from {}", reference.path), "id": label}),
        )
        .await;
    let pull_ref = reference.pinned(&meta.manifest_digest);
    let lock = engine.images.pull_lock(&pull_ref);
    let _guard = lock.lock().await;
    let present = engine
        .images
        .resolve(&meta.config_digest)
        .is_some_and(|r| r.pull_ref == pull_ref);
    let layers: Vec<String> = meta.config["rootfs"]["diff_ids"]
        .as_array()
        .map(|l| {
            l.iter()
                .filter_map(|d| d.as_str())
                .map(|d| d.trim_start_matches("sha256:").chars().take(12).collect())
                .collect()
        })
        .unwrap_or_default();
    if !present {
        for layer in &layers {
            let _ = tx
                .send(serde_json::json!({"status": "Pulling fs layer", "progressDetail": {}, "id": layer}))
                .await;
        }
    }
    let seed_ref = pull_ref.clone();
    let seed_auth = auth.clone();
    let built = tokio::task::spawn_blocking(move || build_seed(&seed_ref, &seed_auth)).await;
    let err = match built {
        Ok(Ok(())) => None,
        Ok(Err(e)) => Some(e.to_string()),
        Err(e) => Some(e.to_string()),
    };
    if let Some(message) = err {
        let _ = tx
            .send(serde_json::json!({"errorDetail": {"message": message}, "error": message}))
            .await;
        return;
    }
    if !present {
        for layer in &layers {
            let _ = tx
                .send(serde_json::json!({"status": "Pull complete", "progressDetail": {}, "id": layer}))
                .await;
        }
    }
    let record = ImageRecord {
        id: meta.config_digest.clone(),
        repo_tags: reference.familiar_tag().into_iter().collect(),
        repo_digests: vec![format!(
            "{}@{}",
            reference.familiar_repo(),
            meta.manifest_digest
        )],
        pull_ref,
        config: meta.config,
        size: meta.compressed_size as i64,
        pulled: super::util::now_rfc3339(),
        last_tag_time: String::new(),
    };
    if let Err(e) = engine.images.insert(&engine.store, record) {
        let message = e.to_string();
        let _ = tx
            .send(serde_json::json!({"errorDetail": {"message": message}, "error": message}))
            .await;
        return;
    }
    let _ = tx
        .send(serde_json::json!({"status": format!("Digest: {}", meta.manifest_digest)}))
        .await;
    let status = if present {
        format!("Status: Image is up to date for {shown}")
    } else {
        format!("Status: Downloaded newer image for {shown}")
    };
    let _ = tx.send(serde_json::json!({ "status": status })).await;
    engine.events.emit(
        "image",
        "pull",
        &shown,
        BTreeMap::from([("name".to_string(), shown.clone())]),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_normalize_like_the_docker_cli() {
        let r = ImageRef::parse("alpine").unwrap();
        assert_eq!(r.full(), "docker.io/library/alpine:latest");
        assert_eq!(r.familiar_tag().unwrap(), "alpine:latest");
        let r = ImageRef::parse("user/app:1.0").unwrap();
        assert_eq!(r.full(), "docker.io/user/app:1.0");
        assert_eq!(r.familiar_repo(), "user/app");
        let r = ImageRef::parse("localhost:5000/app").unwrap();
        assert_eq!(r.domain, "localhost:5000");
        assert_eq!(r.familiar_tag().unwrap(), "localhost:5000/app:latest");
        let r = ImageRef::parse("ghcr.io/org/img@sha256:".to_string().as_str());
        assert!(r.is_err());
        let digest = format!("sha256:{}", "a".repeat(64));
        let r = ImageRef::parse(&format!("postgres:16@{digest}")).unwrap();
        assert_eq!(r.tag.as_deref(), Some("16"));
        assert_eq!(
            r.pinned(&digest),
            format!("docker.io/library/postgres@{digest}")
        );
        assert!(ImageRef::parse("Upper/case").is_err());
    }

    #[test]
    fn reference_filters_glob() {
        assert!(reference_matches("alpine", "alpine:latest"));
        assert!(reference_matches("alp*", "alpine:3"));
        assert!(!reference_matches("busybox", "alpine:latest"));
        assert!(reference_matches("*/app:*", "user/app:1"));
    }

    #[test]
    fn auth_header_forms() {
        use base64::Engine as _;
        let h = base64::engine::general_purpose::URL_SAFE
            .encode(r#"{"username":"u","password":"p","serveraddress":"x"}"#);
        assert!(
            matches!(pull_auth(Some(&h)), crate::registry::PullAuth::Basic { username, .. } if username == "u")
        );
        assert!(matches!(
            pull_auth(None),
            crate::registry::PullAuth::FromConfig
        ));
        let h = base64::engine::general_purpose::URL_SAFE.encode("{}");
        assert!(matches!(
            pull_auth(Some(&h)),
            crate::registry::PullAuth::FromConfig
        ));
    }
}
