//! This module handles:
//! - parsing image refs

// Reference definition (https://pkg.go.dev/github.com/distribution/reference#pkg-overview)
// reference                       := name [ ":" tag ] [ "@" digest ]
// name                            := [domain '/'] remote-name
// domain                          := host [':' port-number]
// host                            := domain-name | IPv4address | \[ IPv6address \]	; rfc3986 appendix-A
// domain-name                     := domain-component ['.' domain-component]*
// domain-component                := /([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])/
// port-number                     := /[0-9]+/
// path-component                  := alpha-numeric [separator alpha-numeric]*
// path (or "remote-name")         := path-component ['/' path-component]*
// alpha-numeric                   := /[a-z0-9]+/
// separator                       := /[_.]|__|[-]*/
// tag                             := /[\w][\w.-]{0,127}/

// digest                          := digest-algorithm ":" digest-hex
// digest-algorithm                := digest-algorithm-component [ digest-algorithm-separator digest-algorithm-component ]*
// digest-algorithm-separator      := /[+.-_]/
// digest-algorithm-component      := /[A-Za-z][A-Za-z0-9]*/
// digest-hex                      := /[0-9a-fA-F]{32,}/ ; At least 128 bit digest value

// identifier                      := /[a-f0-9]{64}/
//
use regex::Regex;
use std::fmt;

const DEFAULT_REGISTRY: &str = "index.docker.io";
const DEFAULT_REGISTRY_ALIAS: &str = "docker.io";
const DEFAULT_REPOSITORY: &str = "library";
const DEFAULT_TAG: &str = "latest";

pub enum ImageRefError {
    InvalidReference,
    InvalidDigestAlgorithm,
    InvalidDigestContent,
    InvalidTagLength,
    InvalidTagCharacters,
    InvalidRepoLength,
    // InvalidRepoCharacters,
}

impl fmt::Display for ImageRefError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            ImageRefError::InvalidReference => write!(f, "Invalid reference"),
            ImageRefError::InvalidDigestAlgorithm => {
                write!(f, "Invalid digest algorithm: only sha256 supported")
            }
            ImageRefError::InvalidDigestContent => {
                write!(f, "Invalid digest content, must be sha256")
            }
            ImageRefError::InvalidTagLength => {
                write!(f, "Invalid tag: must be between 1 and 128 chars")
            }
            ImageRefError::InvalidTagCharacters => write!(f, "Invalid tag: unsupported characters"),
            ImageRefError::InvalidRepoLength => {
                write!(f, "Invalid repostory name: must be between 1 and 255 chars")
            }
        }
    }
}

pub struct Reference {
    tag: String,
    registry: String,
    repository: String,
    // TODO: swap this to an Option<>
    digest: String,
}

impl Reference {
    pub fn to_fqdn(&self) -> String {
        if self.digest != "" {
            return format!("{}/{}@{}", self.registry, self.repository, self.digest);
        }
        return format!("{}/{}:{}", self.registry, self.repository, self.tag);
    }

    pub fn sanitized(&self) -> String {
        self.to_fqdn().replace(['/', ':', '@'], "_").to_string()
    }
}

pub fn parse_image_ref(img: &str) -> Result<Reference, ImageRefError> {
    if img == "" {
        return Err(ImageRefError::InvalidReference);
    }
    if let Some((root, digest)) = img.split_once("@") {
        let (registry, repository, tag) = parse_tag(root);
        let reference = canonicalize(registry, repository, tag, digest);
        validate_registry(&reference.registry)?;
        validate_tag(&reference.tag)?;
        validate_dig(&reference.digest)?;
        validate_repo(&reference.repository)?;
        Ok(reference)
    } else {
        let (registry, repository, tag) = parse_tag(img);
        let reference = canonicalize(registry, repository, tag, "");
        validate_registry(&reference.registry)?;
        validate_tag(&reference.tag)?;
        validate_repo(&reference.repository)?;
        Ok(reference)
    }
}

fn parse_tag(root_no_dig: &str) -> (Option<&str>, &str, Option<&str>) {
    let last_slash = root_no_dig.rfind("/");
    let last_colon = root_no_dig.rfind(":");
    if last_colon > last_slash {
        if let Some((root, tag)) = root_no_dig.rsplit_once(":") {
            let (registry, repository) = parse_remote(root);
            return (registry, repository, Some(tag));
        }
    }
    let (registry, repository) = parse_remote(root_no_dig);
    (registry, repository, None)
}

fn parse_remote(root: &str) -> (Option<&str>, &str) {
    if let Some((first, rest)) = root.split_once("/") {
        if first.contains(".") || first.contains(":") || first == "localhost" {
            return (Some(first), rest);
        }
    }
    (None, root)
}

fn canonicalize(
    registry: Option<&str>,
    repository: &str,
    tag: Option<&str>,
    digest: &str,
) -> Reference {
    let rslvd_registry = registry.unwrap_or(DEFAULT_REGISTRY_ALIAS).to_string();
    let is_docker_registry =
        rslvd_registry == DEFAULT_REGISTRY || rslvd_registry == DEFAULT_REGISTRY_ALIAS;
    let rslvd_repo = if !repository.contains("/") && is_docker_registry && !repository.is_empty() {
        format!("{}/{}", DEFAULT_REPOSITORY, repository)
    } else {
        repository.to_string()
    };

    let rslvd_tag = tag.unwrap_or(DEFAULT_TAG).to_string();
    let rslvd_dig = digest.to_string();
    Reference {
        registry: rslvd_registry,
        repository: rslvd_repo,
        tag: rslvd_tag,
        digest: rslvd_dig,
    }
}

fn validate_registry(registry: &str) -> Result<(), ImageRefError> {
    if registry.len() < 1 {
        return Err(ImageRefError::InvalidReference);
    }
    Ok(())
}

fn validate_tag(tag: &str) -> Result<(), ImageRefError> {
    let length = tag.len();
    if length < 1 || length > 128 {
        return Err(ImageRefError::InvalidTagLength);
    };
    let re = Regex::new(r"^[A-Za-z0-9_.-]+$").unwrap();
    if !re.is_match(tag) {
        return Err(ImageRefError::InvalidTagCharacters);
    };
    Ok(())
}

fn validate_repo(repo: &str) -> Result<(), ImageRefError> {
    let length = repo.len();
    if length < 1 || length > 255 {
        return Err(ImageRefError::InvalidRepoLength);
    }
    // More complex parsers check that repo names
    // conform to path component type. I think it's
    // okay to rely on upstream resistance to these
    // pickier elements of the repo/image names.
    // TODO: path component regex checks for repo
    Ok(())
}

fn validate_dig(dig: &str) -> Result<(), ImageRefError> {
    if dig == "" {
        return Ok(());
    }
    if let Some((_, sha)) = dig.split_once("sha256:") {
        let re = Regex::new(r"^[A-Fa-f0-9]{64}$").unwrap();
        if re.is_match(sha) {
            return Ok(());
        }
        Err(ImageRefError::InvalidDigestContent)
    } else {
        Err(ImageRefError::InvalidDigestAlgorithm)
    }
}

/// Reverse sanitization
pub fn unsanitize_image_name(name: &str) -> String {
    // This is approximate - we lose some info
    name.replacen('_', "/", 1).replacen('_', ":", 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parser_normalizes_simple_refs() {
        let valid_refs = [
            "alpine",
            "alpine:latest",
            "library/alpine:latest",
            "docker.io/alpine:latest",
            "docker.io/library/alpine:latest",
        ];

        for image in valid_refs {
            let parsed = parse_image_ref(image);
            match parsed {
                Ok(reference) => assert_eq!(reference.to_fqdn(), "docker.io/library/alpine:latest"),
                _ => panic!("Failed to parse valid ref"),
            }
        }
    }

    #[test]
    fn test_parser_sanitizes_fqdn_for_fs() {
        let image = Reference {
            tag: "latest".to_string(),
            registry: "docker.io".to_string(),
            repository: "library/alpine".to_string(),
            digest: "".to_string(),
        };

        assert_eq!(image.sanitized(), "docker.io_library_alpine_latest");
    }

    #[test]
    fn test_parser_handles_digest_refs() {}

    #[test]
    fn test_parser_handles_subdomains() {
        let cases = [
            (
                "registry.example.com/alpine",
                "registry.example.com/alpine:latest",
            ),
            (
                "registry.example.com/team/api:1.2.3",
                "registry.example.com/team/api:1.2.3",
            ),
        ];

        for (image, expected) in cases {
            let parsed = parse_image_ref(image);
            match parsed {
                Ok(reference) => assert_eq!(reference.to_fqdn(), expected),
                _ => panic!("Failed to parse ref with subdomain registry"),
            }
        }
    }

    #[test]
    fn test_parser_handles_host_variants() {
        let cases = [
            ("localhost/alpine", "localhost/alpine:latest"),
            ("localhost/team/api:dev", "localhost/team/api:dev"),
            ("192.168.1.1:5000/repo:tag", "192.168.1.1:5000/repo:tag"),
            ("[2001:db8::1]:5000/repo:tag", "[2001:db8::1]:5000/repo:tag"),
        ];

        for (image, expected) in cases {
            let parsed = parse_image_ref(image);
            match parsed {
                Ok(reference) => assert_eq!(reference.to_fqdn(), expected),
                _ => panic!("Failed to parse host variant"),
            }
        }
    }

    #[test]
    fn test_parser_handles_ports() {
        let cases = [
            ("localhost:5000/alpine", "localhost:5000/alpine:latest"),
            (
                "localhost:5000/alpine:latest",
                "localhost:5000/alpine:latest",
            ),
            (
                "registry.internal:8443/org/api:v2",
                "registry.internal:8443/org/api:v2",
            ),
        ];

        for (image, expected) in cases {
            let parsed = parse_image_ref(image);
            match parsed {
                Ok(reference) => assert_eq!(reference.to_fqdn(), expected),
                _ => panic!("Failed to parse host:port reference"),
            }
        }
    }

    #[test]
    fn test_parser_handles_nested_namespaces() {
        let cases = [
            (
                "ghcr.io/owner/platform/image:1.0",
                "ghcr.io/owner/platform/image:1.0",
            ),
            ("docker.io/repo/image:latest", "docker.io/repo/image:latest"),
            ("repo/image:latest", "docker.io/repo/image:latest"),
        ];

        for (image, expected) in cases {
            let parsed = parse_image_ref(image);
            match parsed {
                Ok(reference) => assert_eq!(reference.to_fqdn(), expected),
                _ => panic!("Failed to parse nested namespace reference"),
            }
        }
    }

    #[test]
    fn test_parser_rejects_invalid_refs() {
        let invalid_refs = [
            // TODO: uncomment after adding path component validation
            // "aa/badchars$$^/abc",
            // "Uppercase/repo:tag",
            // "test:5000/Uppercase/lowercase:tag",
            "",
            ":onlytag",
            "@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "alpine@sha256:wrong",
            "alpine:latest@sha123:deadbeef",
            "alpine:latest@sha256:deadbeef",
            "alpine:bad tag@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "alpine:@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ];

        for image in invalid_refs {
            let parsed = parse_image_ref(image);
            assert!(
                parsed.is_err(),
                "Expected parse to fail for invalid ref: {image}"
            );
        }
    }
}
