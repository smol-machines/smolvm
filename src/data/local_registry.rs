//! Pulling images from a registry on the host's own loopback.
//!
//! A registry reachable only at `127.0.0.1:<port>` on the host — the usual shape
//! of a build tool's scratch registry (`docker run -p 127.0.0.1:5000:5000
//! registry:2`) — cannot be pulled by the guest: the guest's own `127.0.0.1` is
//! itself, and opening host loopback to a machine to let it pull would also
//! hand it every other service listening there. So such a reference is pulled
//! here on the host instead, written as a `docker save` archive into the same
//! content-addressed cache a local archive uses, and booted from that. The
//! guest never needs networking for it.

use std::io::Write;
use std::path::Path;

use futures_util::StreamExt;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{Error, Result};

/// The tar block size; every entry's header and data are padded to it.
const BLOCK: u64 = 512;

/// The registry host of `image` when it names a loopback registry
/// (`127.0.0.1:5000/app`, `localhost:5000/app`, `[::1]:5000/app`), else `None`.
/// Only an explicit host counts: `app` or `library/app` is Docker Hub.
pub fn loopback_registry(image: &str) -> Option<&str> {
    let (host, rest) = image.split_once('/')?;
    if rest.is_empty() {
        return None;
    }
    smolvm_registry::is_local_registry(host).then_some(host)
}

/// The parts of an image manifest (OCI or Docker schema 2) a pull needs.
#[derive(Debug, Deserialize)]
struct ImageManifest {
    config: Descriptor,
    layers: Vec<Descriptor>,
}

#[derive(Debug, Deserialize)]
struct Descriptor {
    digest: String,
    size: u64,
}

/// Pull `image` from its loopback registry into `cache_base/<key>/<archive_file>`
/// as a `docker save` archive, returning `<key>`.
///
/// The key is the hex digest of the image's (platform) manifest, so pulling an
/// unchanged image again reuses the archive after one manifest request, and a
/// tag pushed anew pulls the new content. Blocks the calling thread; safe to call
/// from inside or outside an async runtime.
pub(crate) fn pull_to_archive_cache(
    image: &str,
    cache_base: &Path,
    archive_file: &str,
    max_bytes: u64,
) -> Result<String> {
    let image = image.to_string();
    let cache_base = cache_base.to_path_buf();
    let archive_file = archive_file.to_string();
    // A thread of its own with its own runtime: `block_on` would panic on a
    // thread that is already driving one (the API server's handlers).
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| Error::agent("pull image", format!("start a runtime: {e}")))?;
        runtime.block_on(pull(&image, &cache_base, &archive_file, max_bytes))
    })
    .join()
    .map_err(|_| Error::agent("pull image", "the pull thread panicked"))?
}

async fn pull(
    image: &str,
    cache_base: &Path,
    archive_file: &str,
    max_bytes: u64,
) -> Result<String> {
    let failed = |reason: String| Error::agent("pull image", format!("{image}: {reason}"));
    let reference = crate::registry::Reference::parse(image).map_err(|e| failed(e.to_string()))?;
    // Credentials for a loopback registry are unusual but honored, from the
    // same `images` section the in-guest pull reads.
    let settings = crate::settings::SmolSettings::load().unwrap_or_default();
    let client = crate::registry::registry_client(
        &reference.registry,
        &settings.images,
        &crate::registry::PullAuth::FromConfig,
    );
    let repo = reference.repository();
    let tag = reference
        .digest
        .as_deref()
        .or(reference.tag.as_deref())
        .unwrap_or("latest");
    // The guest is always Linux; only the architecture follows the host.
    let platform = smolvm_registry::OciPlatform {
        os: "linux".to_string(),
        architecture: smolvm_registry::OciPlatform::current().architecture,
        variant: None,
    };
    let manifest_bytes = client
        .get_image_manifest(&repo, tag, &platform)
        .await
        .map_err(|e| match e {
            smolvm_registry::RegistryError::BlobNotFound(_) => {
                failed(format!("the registry has no {repo}:{tag}"))
            }
            smolvm_registry::RegistryError::Http(_) => {
                failed(format!("{e} (is the registry running?)"))
            }
            e => failed(e.to_string()),
        })?;
    let manifest: ImageManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| failed(format!("unreadable image manifest: {e}")))?;

    let key = hex::encode(Sha256::digest(&manifest_bytes));
    let entries = entries(&manifest)?;
    let expected_len = archive_len(&entries, &manifest_json(&entries)?);
    let archive_path = cache_base.join(&key).join(archive_file);
    if std::fs::metadata(&archive_path).is_ok_and(|m| m.len() == expected_len) {
        return Ok(key);
    }
    let content: u64 = entries.iter().map(|e| e.size).sum();
    if content > max_bytes {
        return Err(Error::config(
            "--image",
            format!(
                "{image} is {content} bytes, over the {max_bytes}-byte limit. Raise it \
                 with --max-image-size or SMOLVM_MAX_IMAGE_BYTES if it is legitimate."
            ),
        ));
    }

    let dir = cache_base.join(&key);
    std::fs::create_dir_all(&dir)?;
    // Written beside its final name and renamed into place, so a failed or
    // interrupted pull never leaves a truncated archive to be reused.
    let mut staged = tempfile::NamedTempFile::new_in(&dir)?;
    {
        let out = staged.as_file_mut();
        for entry in &entries {
            write_header(out, &entry.path, entry.size)?;
            let mut stream = client
                .pull_blob_stream(&repo, &entry.digest)
                .await
                .map_err(|e| failed(format!("fetch {}: {e}", entry.digest)))?;
            let mut hasher = Sha256::new();
            let mut written = 0u64;
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|e| failed(format!("fetch {}: {e}", entry.digest)))?;
                written += chunk.len() as u64;
                if written > entry.size {
                    return Err(failed(format!(
                        "{} is larger than its manifest says ({} bytes)",
                        entry.digest, entry.size
                    )));
                }
                hasher.update(&chunk);
                out.write_all(&chunk)?;
            }
            let actual = format!("sha256:{}", hex::encode(hasher.finalize()));
            if written != entry.size || actual != entry.digest {
                return Err(failed(format!(
                    "{} arrived as {written} bytes with digest {actual}; the manifest \
                     says {} bytes",
                    entry.digest, entry.size
                )));
            }
            write_padding(out, entry.size)?;
        }
        let manifest_json = manifest_json(&entries)?;
        write_header(out, "manifest.json", manifest_json.len() as u64)?;
        out.write_all(&manifest_json)?;
        write_padding(out, manifest_json.len() as u64)?;
        // End of archive: two zero blocks.
        out.write_all(&[0u8; (2 * BLOCK) as usize])?;
        out.flush()?;
    }
    staged
        .persist(&archive_path)
        .map_err(|e| Error::storage("stage pulled image", e.to_string()))?;
    Ok(key)
}

/// One blob to write into the archive.
struct Entry {
    path: String,
    digest: String,
    size: u64,
    is_config: bool,
}

/// The config followed by each distinct layer, at `blobs/sha256/<hex>` — the
/// layout `docker save` has used since Docker 25.
fn entries(manifest: &ImageManifest) -> Result<Vec<Entry>> {
    let mut seen = std::collections::HashSet::new();
    let mut entries = Vec::new();
    for (descriptor, is_config) in std::iter::once((&manifest.config, true))
        .chain(manifest.layers.iter().map(|layer| (layer, false)))
    {
        let hex = descriptor
            .digest
            .strip_prefix("sha256:")
            .filter(|hex| hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or_else(|| {
                Error::agent(
                    "pull image",
                    format!("unsupported blob digest '{}'", descriptor.digest),
                )
            })?;
        if !seen.insert(hex.to_string()) {
            continue;
        }
        entries.push(Entry {
            path: format!("blobs/sha256/{hex}"),
            digest: descriptor.digest.clone(),
            size: descriptor.size,
            is_config,
        });
    }
    Ok(entries)
}

/// The archive's `manifest.json`: which entry is the config, and the layers in
/// order (a repeated layer is written once and listed each time it occurs).
fn manifest_json(entries: &[Entry]) -> Result<Vec<u8>> {
    let config = entries
        .iter()
        .find(|e| e.is_config)
        .map(|e| e.path.clone())
        .unwrap_or_default();
    let layers: Vec<&str> = entries
        .iter()
        .filter(|e| !e.is_config)
        .map(|e| e.path.as_str())
        .collect();
    serde_json::to_vec(&serde_json::json!([{
        "Config": config,
        "RepoTags": [],
        "Layers": layers,
    }]))
    .map_err(|e| Error::storage("stage pulled image", e.to_string()))
}

/// The exact size of the archive these entries produce.
fn archive_len(entries: &[Entry], manifest_json: &[u8]) -> u64 {
    let entry = |size: u64| BLOCK + size.div_ceil(BLOCK) * BLOCK;
    entries.iter().map(|e| entry(e.size)).sum::<u64>()
        + entry(manifest_json.len() as u64)
        + 2 * BLOCK
}

fn write_header(out: &mut impl Write, path: &str, size: u64) -> Result<()> {
    let mut header = tar::Header::new_ustar();
    header
        .set_path(path)
        .map_err(|e| Error::storage("stage pulled image", e.to_string()))?;
    header.set_size(size);
    header.set_mode(0o644);
    header.set_mtime(0);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_cksum();
    out.write_all(header.as_bytes())?;
    Ok(())
}

fn write_padding(out: &mut impl Write, size: u64) -> Result<()> {
    let pad = (size.div_ceil(BLOCK) * BLOCK - size) as usize;
    out.write_all(&vec![0u8; pad])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_explicit_loopback_host_counts() {
        assert_eq!(
            loopback_registry("127.0.0.1:51921/eve/app"),
            Some("127.0.0.1:51921")
        );
        assert_eq!(
            loopback_registry("localhost:5000/app:v1"),
            Some("localhost:5000")
        );
        assert_eq!(loopback_registry("[::1]:5000/app"), Some("[::1]:5000"));
        assert_eq!(loopback_registry("ghcr.io/org/app"), None);
        assert_eq!(loopback_registry("alpine"), None);
        assert_eq!(loopback_registry("library/alpine"), None);
        assert_eq!(loopback_registry("127.0.0.1:5000/"), None);
    }

    #[test]
    fn the_archive_length_matches_what_is_written() {
        let manifest = ImageManifest {
            config: Descriptor {
                digest: format!("sha256:{}", "a".repeat(64)),
                size: 700,
            },
            layers: vec![
                Descriptor {
                    digest: format!("sha256:{}", "b".repeat(64)),
                    size: 1024,
                },
                Descriptor {
                    digest: format!("sha256:{}", "b".repeat(64)),
                    size: 1024,
                },
                Descriptor {
                    digest: format!("sha256:{}", "c".repeat(64)),
                    size: 1,
                },
            ],
        };
        let entries = entries(&manifest).unwrap();
        assert_eq!(entries.len(), 3, "a repeated layer is written once");
        let json = manifest_json(&entries).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed[0]["Layers"].as_array().unwrap().len(), 2);

        let mut out = Vec::new();
        for entry in &entries {
            write_header(&mut out, &entry.path, entry.size).unwrap();
            out.extend(std::iter::repeat_n(0u8, entry.size as usize));
            write_padding(&mut out, entry.size).unwrap();
        }
        write_header(&mut out, "manifest.json", json.len() as u64).unwrap();
        out.extend_from_slice(&json);
        write_padding(&mut out, json.len() as u64).unwrap();
        out.extend_from_slice(&[0u8; 1024]);
        assert_eq!(out.len() as u64, archive_len(&entries, &json));

        // And it reads back as a tar with the expected members.
        let mut archive = tar::Archive::new(out.as_slice());
        let names: Vec<String> = archive
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().display().to_string())
            .collect();
        assert_eq!(names.last().map(String::as_str), Some("manifest.json"));
        assert_eq!(names.len(), 4);
    }

    #[test]
    fn a_non_sha256_digest_is_refused() {
        let manifest = ImageManifest {
            config: Descriptor {
                digest: "sha512:abc".into(),
                size: 1,
            },
            layers: vec![],
        };
        assert!(entries(&manifest).is_err());
    }
}
