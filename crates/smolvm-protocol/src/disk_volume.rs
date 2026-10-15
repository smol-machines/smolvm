//! Disk volumes: a guest directory backed by the machine's own storage disk.
//!
//! `-v /var/lib/docker` (a guest path with no host side, Docker's anonymous
//! volume syntax) asks for a directory that lives on the machine's ext4 storage
//! disk instead of the container's overlay root. Software that nests overlayfs
//! (Docker, containerd, Podman, BuildKit) needs exactly that, because overlayfs
//! cannot use another overlay as its upper layer. The data persists for the
//! machine's lifetime, across stop and start, like the rest of `/storage`.
//!
//! The host passes only the guest targets, joined into
//! [`crate::guest_env::DISK_VOLUMES`]; the guest agent derives each volume's
//! directory on the disk with [`storage_dir_name`] and binds it into every
//! workload it starts.

/// Separator between targets in the env value. Guest targets never contain it
/// because `-v` itself splits on `:`.
const SEPARATOR: char = ':';

/// Guest trees a disk volume must not cover: kernel filesystems, the storage
/// disk itself, and the root.
const RESERVED: &[&str] = &["/proc", "/sys", "/dev", "/storage"];

/// Validate and normalize one guest target (`/var/lib/docker/` becomes
/// `/var/lib/docker`). Returns the reason on rejection.
pub fn normalize_target(target: &str) -> Result<String, String> {
    if !target.starts_with('/') {
        return Err(format!(
            "disk volume path must be absolute inside the machine: '{target}'"
        ));
    }
    if target.contains(SEPARATOR) {
        return Err(format!("disk volume path must not contain ':': '{target}'"));
    }
    let parts: Vec<&str> = target.split('/').filter(|p| !p.is_empty()).collect();
    if parts.iter().any(|p| *p == "." || *p == "..") {
        return Err(format!(
            "disk volume path must not contain '.' or '..': '{target}'"
        ));
    }
    if parts.is_empty() {
        return Err("a disk volume cannot be mounted at '/'".to_string());
    }
    let normalized = format!("/{}", parts.join("/"));
    if let Some(reserved) = RESERVED
        .iter()
        .find(|r| normalized == **r || normalized.starts_with(&format!("{r}/")))
    {
        return Err(format!(
            "disk volume path '{normalized}' is inside {reserved}, which smolvm manages"
        ));
    }
    Ok(normalized)
}

/// Join normalized targets into the env value.
pub fn encode(targets: &[String]) -> String {
    targets.join(&SEPARATOR.to_string())
}

/// Split the env value back into targets, dropping any that fail validation so
/// a malformed value can never bind over a reserved path.
pub fn decode(value: &str) -> Vec<String> {
    value
        .split(SEPARATOR)
        .filter(|t| !t.is_empty())
        .filter_map(|t| normalize_target(t).ok())
        .collect()
}

/// Directory name under the disk's volume root for a normalized target. It is
/// readable (`var-lib-docker`) and carries a hash of the exact path, so
/// `/a-b` and `/a/b` cannot share a directory.
pub fn storage_dir_name(target: &str) -> String {
    let readable: String = target
        .trim_start_matches('/')
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .take(48)
        .collect();
    // FNV-1a: stable across builds and platforms, unlike std's hasher.
    let mut hash: u32 = 0x811c_9dc5;
    for byte in target.as_bytes() {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    format!("{readable}-{hash:08x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_are_normalized_and_validated() {
        assert_eq!(
            normalize_target("/var/lib/docker/").unwrap(),
            "/var/lib/docker"
        );
        assert_eq!(normalize_target("//srv//data").unwrap(), "/srv/data");
        assert!(normalize_target("var/lib/docker").is_err());
        assert!(normalize_target("/").is_err());
        assert!(normalize_target("/a/../etc").is_err());
        assert!(normalize_target("/a:b").is_err());
        assert!(normalize_target("/proc").is_err());
        assert!(normalize_target("/storage/x").is_err());
        assert!(normalize_target("/devices").is_ok());
    }

    #[test]
    fn encode_round_trips_and_decode_drops_invalid_entries() {
        let targets = vec![
            "/var/lib/docker".to_string(),
            "/var/lib/containerd".to_string(),
        ];
        assert_eq!(decode(&encode(&targets)), targets);
        assert_eq!(decode("/ok::relative:/proc/x"), vec!["/ok".to_string()]);
    }

    #[test]
    fn storage_dir_names_are_readable_and_distinct() {
        let docker = storage_dir_name("/var/lib/docker");
        assert!(docker.starts_with("var-lib-docker-"), "{docker}");
        assert_ne!(storage_dir_name("/a-b"), storage_dir_name("/a/b"));
        assert_eq!(docker, storage_dir_name("/var/lib/docker"));
    }
}
