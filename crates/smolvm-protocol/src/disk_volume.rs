//! Disk volumes: a guest directory backed by the machine's own storage disk.
//!
//! `-v /var/lib/docker` (a guest path with no host side, Docker's anonymous
//! volume syntax) asks for a directory that lives on the machine's ext4 storage
//! disk instead of the container's overlay root. Software that nests overlayfs
//! (Docker, containerd, Podman, BuildKit) needs exactly that, because overlayfs
//! cannot use another overlay as its upper layer. The data persists for the
//! machine's lifetime, across stop and start, like the rest of `/storage`.
//!
//! `-v /data:uid=1000,gid=1000,mode=750` also gives the volume's directory
//! that owner and mode, the way `machine cp --uid --gid --mode` does for a
//! file. The agent applies them when the volume is created and again when they
//! change, so a `chown` inside the machine survives a restart, as it does for a
//! volume without them.
//!
//! The host passes each volume's spec ([`DiskVolume`]), joined into
//! [`crate::guest_env::DISK_VOLUMES`]; the guest agent derives each volume's
//! directory on the disk with [`storage_dir_name`] and binds it into every
//! workload it starts.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Separator between targets in the env value, and between a target and its
/// options. Guest targets never contain it because `-v` itself splits on `:`.
const SEPARATOR: char = ':';

/// A disk volume: its normalized guest target, and the owner and mode its
/// directory is given when it is created or they change. An unset field leaves
/// the directory as it is, so a new volume keeps the ownership it takes from
/// the image.
///
/// It is stored as its spec string (`/data` or `/data:uid=1000,mode=0750`), so
/// records written before the options existed, a bare target, still read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DiskVolume {
    /// Normalized guest path (see [`normalize_target`]).
    pub target: String,
    /// Owner uid for the volume's directory.
    pub uid: Option<u32>,
    /// Owner gid for the volume's directory.
    pub gid: Option<u32>,
    /// Permission bits for the volume's directory (at most `0o7777`).
    pub mode: Option<u32>,
}

impl DiskVolume {
    /// A volume at `target` with no owner or mode of its own.
    pub fn new(target: String) -> Self {
        Self {
            target,
            uid: None,
            gid: None,
            mode: None,
        }
    }

    /// Whether the spec gives an owner or mode for the directory.
    pub fn has_options(&self) -> bool {
        self.uid.is_some() || self.gid.is_some() || self.mode.is_some()
    }

    /// Parse `TARGET[:uid=UID,gid=GID,mode=OCTAL]`, any subset of the options
    /// in any order. Returns the reason on rejection.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let (target, options) = match spec.split_once(SEPARATOR) {
            Some((target, options)) => (target, Some(options)),
            None => (spec, None),
        };
        let mut volume = Self::new(normalize_target(target)?);
        for option in options.into_iter().flat_map(|options| options.split(',')) {
            volume.set_option(option)?;
        }
        Ok(volume)
    }

    fn set_option(&mut self, option: &str) -> Result<(), String> {
        let invalid = || {
            format!(
                "invalid disk volume option '{option}' (expected uid=UID, gid=GID or mode=OCTAL)"
            )
        };
        let (key, value) = option.split_once('=').ok_or_else(invalid)?;
        let (slot, parsed) = match key {
            "uid" => (&mut self.uid, value.parse().ok()),
            "gid" => (&mut self.gid, value.parse().ok()),
            "mode" => (&mut self.mode, parse_mode(value)),
            _ => return Err(invalid()),
        };
        if slot.is_some() {
            return Err(format!(
                "disk volume option '{key}' is given more than once"
            ));
        }
        *slot = Some(parsed.ok_or_else(invalid)?);
        Ok(())
    }
}

/// Parse a chmod-style octal mode ("750", "0750", "0o750"), as `machine cp
/// --mode` does.
fn parse_mode(value: &str) -> Option<u32> {
    u32::from_str_radix(value.trim_start_matches("0o"), 8)
        .ok()
        .filter(|mode| *mode <= 0o7777)
}

impl fmt::Display for DiskVolume {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.target)?;
        let options = [
            self.uid.map(|uid| format!("uid={uid}")),
            self.gid.map(|gid| format!("gid={gid}")),
            self.mode.map(|mode| format!("mode={mode:04o}")),
        ];
        for (index, option) in options.iter().flatten().enumerate() {
            let separator = if index == 0 { SEPARATOR } else { ',' };
            write!(f, "{separator}{option}")?;
        }
        Ok(())
    }
}

impl TryFrom<String> for DiskVolume {
    type Error = String;

    fn try_from(spec: String) -> Result<Self, String> {
        Self::parse(&spec)
    }
}

impl From<DiskVolume> for String {
    fn from(volume: DiskVolume) -> Self {
        volume.to_string()
    }
}

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

/// Join volume specs into the env value: `/data:uid=1000,gid=1000:/var/lib/docker`.
pub fn encode(volumes: &[DiskVolume]) -> String {
    volumes
        .iter()
        .map(DiskVolume::to_string)
        .collect::<Vec<_>>()
        .join(&SEPARATOR.to_string())
}

/// Split the env value back into volumes, dropping any that fail validation so
/// a malformed value can never bind over a reserved path. A part holding
/// options (`uid=1000,gid=1000`) belongs to the target before it.
pub fn decode(value: &str) -> Vec<DiskVolume> {
    let mut specs: Vec<String> = Vec::new();
    for part in value.split(SEPARATOR).filter(|p| !p.is_empty()) {
        match specs.last_mut() {
            Some(spec) if !part.starts_with('/') && part.contains('=') => {
                spec.push(SEPARATOR);
                spec.push_str(part);
            }
            _ => specs.push(part.to_string()),
        }
    }
    specs
        .iter()
        .filter_map(|spec| DiskVolume::parse(spec).ok())
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
        let volumes = vec![
            DiskVolume::new("/var/lib/docker".to_string()),
            DiskVolume::parse("/data:mode=700,uid=1000").unwrap(),
            DiskVolume::new("/var/lib/containerd".to_string()),
        ];
        let encoded = encode(&volumes);
        assert_eq!(
            encoded,
            "/var/lib/docker:/data:uid=1000,mode=0700:/var/lib/containerd"
        );
        assert_eq!(decode(&encoded), volumes);
        assert_eq!(
            decode("/ok::relative:/proc/x"),
            vec![DiskVolume::new("/ok".to_string())]
        );
        // A volume whose options do not parse is dropped, not mounted without them.
        assert_eq!(
            decode("/bad:uid=x:/ok"),
            vec![DiskVolume::new("/ok".to_string())]
        );
    }

    #[test]
    fn decode_of_a_bare_target_list_is_unchanged() {
        // The value hosts sent before volumes had options.
        let volumes = decode("/var/lib/docker:/var/lib/containerd");
        let targets: Vec<_> = volumes.iter().map(|v| v.target.as_str()).collect();
        assert_eq!(targets, ["/var/lib/docker", "/var/lib/containerd"]);
        assert!(volumes
            .iter()
            .all(|v| v.uid.is_none() && v.gid.is_none() && v.mode.is_none()));
    }

    #[test]
    fn specs_parse_owner_and_mode_options() {
        let volume = DiskVolume::parse("/data/:gid=50,uid=1000,mode=0o2775").unwrap();
        assert_eq!(volume.target, "/data");
        assert_eq!(volume.uid, Some(1000));
        assert_eq!(volume.gid, Some(50));
        assert_eq!(volume.mode, Some(0o2775));
        assert_eq!(volume.to_string(), "/data:uid=1000,gid=50,mode=2775");

        let mode_only = DiskVolume::parse("/data:mode=750").unwrap();
        assert_eq!((mode_only.uid, mode_only.mode), (None, Some(0o750)));
        assert_eq!(mode_only.to_string(), "/data:mode=0750");
        assert_eq!(DiskVolume::parse("/data").unwrap().to_string(), "/data");

        for bad in [
            "/data:",
            "/data:ro",
            "/data:uid",
            "/data:uid=-1",
            "/data:uid=1,uid=2",
            "/data:mode=8",
            "/data:mode=17777",
            "/data:owner=1",
            "/data:uid=1:gid=2",
            "/proc/x:uid=1",
        ] {
            assert!(DiskVolume::parse(bad).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn volumes_serialize_as_their_spec_and_read_bare_targets() {
        let volume = DiskVolume::parse("/data:uid=1000,gid=1000").unwrap();
        let json = serde_json::to_string(&vec![volume.clone()]).unwrap();
        assert_eq!(json, r#"["/data:uid=1000,gid=1000"]"#);
        let back: Vec<DiskVolume> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, vec![volume]);

        let old: Vec<DiskVolume> = serde_json::from_str(r#"["/var/lib/docker"]"#).unwrap();
        assert_eq!(old, vec![DiskVolume::new("/var/lib/docker".to_string())]);
        assert!(serde_json::from_str::<DiskVolume>(r#""/proc""#).is_err());
    }

    #[test]
    fn storage_dir_names_are_readable_and_distinct() {
        let docker = storage_dir_name("/var/lib/docker");
        assert!(docker.starts_with("var-lib-docker-"), "{docker}");
        assert_ne!(storage_dir_name("/a-b"), storage_dir_name("/a/b"));
        assert_eq!(docker, storage_dir_name("/var/lib/docker"));
    }
}
