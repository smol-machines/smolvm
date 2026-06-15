//! Image reference canonicalization.
//!
//! OCI image references have many valid spellings for the same image.
//! This module provides [`normalize_image_ref`], which maps every spelling
//! to a single canonical form so that cache keys, log messages, and
//! protocol messages are consistent regardless of how the caller spelled
//! the reference.

/// Canonicalize an OCI image reference.
///
/// All equivalent spellings of the same image produce an identical string,
/// which is safe to use as a cache key or protocol field.
///
/// # Normalization rules (applied in order)
///
/// 1. `index.docker.io` is rewritten to `docker.io` (legacy alias).
/// 2. A missing registry defaults to `docker.io`.
/// 3. Single-component names on `docker.io` receive the `library/` prefix
///    (e.g. `alpine` → `docker.io/library/alpine`).
/// 4. A missing tag defaults to `:latest`.  When a digest (`@sha256:…`) is
///    present it takes precedence and any tag is dropped.
///
/// # Examples
///
/// ```
/// use smolvm_protocol::normalize_image_ref;
///
/// assert_eq!(normalize_image_ref("alpine"),
///            "docker.io/library/alpine:latest");
/// assert_eq!(normalize_image_ref("alpine:3.20"),
///            "docker.io/library/alpine:3.20");
/// assert_eq!(normalize_image_ref("docker.io/alpine:3.20"),
///            "docker.io/library/alpine:3.20");
/// assert_eq!(normalize_image_ref("docker.io/library/alpine:3.20"),
///            "docker.io/library/alpine:3.20");
/// assert_eq!(normalize_image_ref("ghcr.io/owner/repo:v1"),
///            "ghcr.io/owner/repo:v1");
/// ```
pub fn normalize_image_ref(image: &str) -> String {
    // 1. Resolve index.docker.io alias.
    let owned;
    let image = if let Some(rest) = image.strip_prefix("index.docker.io/") {
        owned = format!("docker.io/{rest}");
        owned.as_str()
    } else {
        image
    };

    // 2. and 3. Separate the digest, and the tag from the bare repository.
    let (ref_no_tag, tag, digest) = split_suffix(image);

    // 4. Detect registry: the first '/'-delimited component is a registry
    //    hostname when it contains '.' or ':' (port).  Everything else is
    //    an implicit docker.io reference.
    let (registry, path) = split_registry(ref_no_tag);

    // 5. Single-component docker.io paths get the `library/` prefix.
    let canonical_path = if registry == "docker.io" && !path.contains('/') {
        format!("library/{path}")
    } else {
        path.to_string()
    };

    // 6. Suffix: digest wins over tag; absent tag defaults to `:latest`.
    let suffix = match digest {
        Some(d) => format!("@{d}"),
        None => format!(":{}", tag.unwrap_or("latest")),
    };

    format!("{registry}/{canonical_path}{suffix}")
}

/// Split an image reference into `(repo, tag, digest)`.
///
/// The repo is the `registry/repository` portion with no suffix.
///
/// The digest is everything after '@'.  When a digest is present the tag is
/// informational (the digest is authoritative), but both are still returned.
///
/// The tag separator is the last ':' with no '/' after it.  A colon that is
/// part of a registry hostname (e.g. `localhost:5000/repo`) always has a '/'
/// after it, so this rule does not mistake a port for a tag.
fn split_suffix(image: &str) -> (&str, Option<&str>, Option<&str>) {
    let (ref_no_digest, digest) = match image.split_once('@') {
        Some((left, right)) => (left, Some(right)),
        None => (image, None),
    };
    let (repo, tag) = match ref_no_digest.rfind(':') {
        Some(pos) if !ref_no_digest[pos..].contains('/') => {
            (&ref_no_digest[..pos], Some(&ref_no_digest[pos + 1..]))
        }
        _ => (ref_no_digest, None),
    };
    (repo, tag, digest)
}

/// Strip the tag and/or digest suffix from an image reference, returning the registry/repo
///
/// # Examples
///
/// ```
/// use smolvm_protocol::image_repo;
///
/// assert_eq!(image_repo("ghcr.io/owner/repo@sha256:abc"), "ghcr.io/owner/repo");
/// assert_eq!(image_repo("ghcr.io/owner/repo:v1"), "ghcr.io/owner/repo");
/// ```
pub fn image_repo(image: &str) -> &str {
    split_suffix(image).0
}

/// Split a tag-free, digest-free image string into `(registry, path)`.
///
/// Returns `("docker.io", whole_string)` when no explicit registry is found.
fn split_registry(image: &str) -> (&str, &str) {
    if let Some(slash) = image.find('/') {
        let prefix = &image[..slash];
        if prefix.contains('.') || prefix.contains(':') {
            return (prefix, &image[slash + 1..]);
        }
    }
    ("docker.io", image)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_image_ref() {
        let cases: &[(&str, &str)] = &[
            // Bare name and with tag — docker.io library prefix + :latest default.
            ("alpine", "docker.io/library/alpine:latest"),
            ("alpine:3.20", "docker.io/library/alpine:3.20"),
            // Explicit docker.io without library/ — library/ is inserted.
            ("docker.io/alpine:3.20", "docker.io/library/alpine:3.20"),
            // Already canonical — idempotent.
            (
                "docker.io/library/alpine:3.20",
                "docker.io/library/alpine:3.20",
            ),
            // index.docker.io legacy alias.
            (
                "index.docker.io/library/alpine",
                "docker.io/library/alpine:latest",
            ),
            // library/ without a registry prefix.
            ("library/alpine", "docker.io/library/alpine:latest"),
            // User-namespaced docker.io image — no extra library/ prefix.
            ("myuser/myimage:v2", "docker.io/myuser/myimage:v2"),
            // Non-docker.io registry.
            ("ghcr.io/owner/repo", "ghcr.io/owner/repo:latest"),
            ("ghcr.io/owner/repo:v1", "ghcr.io/owner/repo:v1"),
            // Port in registry — colon-detection must not confuse port with tag.
            ("localhost:5000/myimage:dev", "localhost:5000/myimage:dev"),
        ];

        for (input, expected) in cases {
            assert_eq!(
                normalize_image_ref(input),
                *expected,
                "normalize_image_ref({input:?})"
            );
        }
    }

    #[test]
    fn test_normalize_digest_refs() {
        let digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        // Digest without tag.
        assert_eq!(
            normalize_image_ref(&format!("alpine@{digest}")),
            format!("docker.io/library/alpine@{digest}"),
        );

        // Digest with tag — tag is dropped, digest is authoritative.
        assert_eq!(
            normalize_image_ref(&format!("alpine:3.20@{digest}")),
            format!("docker.io/library/alpine@{digest}"),
        );
    }

    #[test]
    fn test_image_repo() {
        let digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        // Digest suffix is stripped.
        assert_eq!(
            image_repo(&format!("ghcr.io/owner/repo@{digest}")),
            "ghcr.io/owner/repo",
        );
        // Tag suffix is stripped.
        assert_eq!(image_repo("ghcr.io/owner/repo:v1"), "ghcr.io/owner/repo");
        // No suffix — returned unchanged.
        assert_eq!(image_repo("ghcr.io/owner/repo"), "ghcr.io/owner/repo");
        // Port in registry — colon-detection must not confuse port with tag.
        assert_eq!(
            image_repo("localhost:5000/myimage:dev"),
            "localhost:5000/myimage",
        );
        assert_eq!(
            image_repo("localhost:5000/myimage"),
            "localhost:5000/myimage"
        );
    }
}
