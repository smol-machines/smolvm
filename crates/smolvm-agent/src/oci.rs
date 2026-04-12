//! OCI Runtime Specification generation for crun integration.
//!
//! This module provides types and functions for generating OCI-compliant
//! config.json files used by crun to execute containers.

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// OCI Runtime Specification (subset for container execution).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciSpec {
    #[serde(rename = "ociVersion")]
    pub oci_version: String,
    pub root: OciRoot,
    pub process: OciProcess,
    pub linux: OciLinux,
    pub mounts: Vec<OciMount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
}

/// Root filesystem configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciRoot {
    /// Path to the root filesystem (relative to bundle or absolute).
    pub path: String,
    /// Whether the root filesystem should be read-only.
    #[serde(default)]
    pub readonly: bool,
}

/// Process configuration for the container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciProcess {
    /// Whether to allocate a pseudo-terminal.
    #[serde(default)]
    pub terminal: bool,
    /// User and group IDs.
    pub user: OciUser,
    /// Command and arguments to execute.
    pub args: Vec<String>,
    /// Environment variables in KEY=VALUE format.
    #[serde(default)]
    pub env: Vec<String>,
    /// Working directory inside the container.
    pub cwd: String,
    /// Linux capabilities (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<OciCapabilities>,
    /// Resource limits (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rlimits: Option<Vec<OciRlimit>>,
    /// Do not create a new session for the process.
    #[serde(rename = "noNewPrivileges", default)]
    pub no_new_privileges: bool,
}

/// User configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciUser {
    pub uid: u32,
    pub gid: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_gids: Vec<u32>,
}

/// Linux capabilities configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciCapabilities {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bounding: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effective: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inheritable: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permitted: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ambient: Vec<String>,
}

/// Resource limit configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciRlimit {
    #[serde(rename = "type")]
    pub rlimit_type: String,
    pub hard: u64,
    pub soft: u64,
}

/// Linux-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciLinux {
    /// Namespaces to create.
    pub namespaces: Vec<OciNamespace>,
    /// Device nodes to create in the container.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<OciDevice>,
    /// Masked paths (paths that should appear empty).
    #[serde(rename = "maskedPaths", default, skip_serializing_if = "Vec::is_empty")]
    pub masked_paths: Vec<String>,
    /// Read-only paths.
    #[serde(
        rename = "readonlyPaths",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub readonly_paths: Vec<String>,
}

/// Device node configuration for OCI runtime.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciDevice {
    /// Device type: "c" (char), "b" (block), "p" (pipe)
    #[serde(rename = "type")]
    pub device_type: String,
    /// Path inside the container
    pub path: String,
    /// Major device number
    pub major: u32,
    /// Minor device number
    pub minor: u32,
    /// File mode/permissions
    #[serde(rename = "fileMode", skip_serializing_if = "Option::is_none")]
    pub file_mode: Option<u32>,
    /// Owner UID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    /// Owner GID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
}

/// Namespace configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciNamespace {
    /// Type of namespace (pid, network, mount, ipc, uts, user, cgroup).
    #[serde(rename = "type")]
    pub ns_type: String,
    /// Path to an existing namespace to join (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// Mount configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciMount {
    /// Destination path inside the container.
    pub destination: String,
    /// Filesystem type (proc, sysfs, tmpfs, bind, etc.).
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub mount_type: Option<String>,
    /// Source path or device.
    pub source: String,
    /// Mount options.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<String>,
}

impl OciSpec {
    /// Create a new OCI spec with sensible defaults for container execution.
    ///
    /// # Arguments
    /// * `command` - Command and arguments to execute
    /// * `env` - Environment variables as (key, value) pairs
    /// * `workdir` - Working directory inside the container
    /// * `tty` - Whether to allocate a pseudo-terminal
    pub fn new(command: &[String], env: &[(String, String)], workdir: &str, tty: bool) -> Self {
        // Build environment variables
        let env_strings: Vec<String> = [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
            "HOME=/root".to_string(),
            "TERM=xterm-256color".to_string(),
        ]
        .into_iter()
        .chain(env.iter().map(|(k, v)| format!("{}={}", k, v)))
        .collect();

        // Default capabilities for root containers
        let capabilities = OciCapabilities {
            bounding: default_capabilities(),
            effective: default_capabilities(),
            inheritable: vec![],
            permitted: default_capabilities(),
            ambient: vec![],
        };

        Self {
            oci_version: "1.0.2".to_string(),
            root: OciRoot {
                path: "rootfs".to_string(),
                readonly: false,
            },
            process: OciProcess {
                terminal: tty,
                user: OciUser {
                    uid: 0,
                    gid: 0,
                    additional_gids: vec![],
                },
                args: command.to_vec(),
                env: env_strings,
                cwd: workdir.to_string(),
                capabilities: Some(capabilities),
                rlimits: Some(vec![OciRlimit {
                    rlimit_type: "RLIMIT_NOFILE".to_string(),
                    hard: 1024,
                    soft: 1024,
                }]),
                no_new_privileges: false,
            },
            linux: OciLinux {
                namespaces: vec![
                    OciNamespace {
                        ns_type: "pid".to_string(),
                        path: None,
                    },
                    OciNamespace {
                        ns_type: "mount".to_string(),
                        path: None,
                    },
                    OciNamespace {
                        ns_type: "ipc".to_string(),
                        path: None,
                    },
                    OciNamespace {
                        ns_type: "uts".to_string(),
                        path: None,
                    },
                ],
                devices: default_devices(),
                masked_paths: vec![
                    "/proc/asound".to_string(),
                    "/proc/acpi".to_string(),
                    "/proc/kcore".to_string(),
                    "/proc/keys".to_string(),
                    "/proc/latency_stats".to_string(),
                    "/proc/timer_list".to_string(),
                    "/proc/timer_stats".to_string(),
                    "/proc/sched_debug".to_string(),
                    "/proc/scsi".to_string(),
                    "/sys/firmware".to_string(),
                ],
                readonly_paths: vec![
                    "/proc/bus".to_string(),
                    "/proc/fs".to_string(),
                    "/proc/irq".to_string(),
                    "/proc/sys".to_string(),
                    "/proc/sysrq-trigger".to_string(),
                ],
            },
            mounts: default_mounts(),
            hostname: Some("container".to_string()),
        }
    }

    /// Add a bind mount to the spec.
    ///
    /// # Arguments
    /// * `source` - Source path on the host
    /// * `destination` - Destination path inside the container
    /// * `read_only` - Whether the mount should be read-only
    pub fn add_bind_mount(&mut self, source: &str, destination: &str, read_only: bool) {
        let mut options = vec!["bind".to_string(), "rprivate".to_string()];
        if read_only {
            options.push("ro".to_string());
        }
        self.mounts.push(OciMount {
            destination: destination.to_string(),
            mount_type: Some("bind".to_string()),
            source: source.to_string(),
            options,
        });
    }

    /// Expose GPU render nodes to the container if /dev/dri exists in the VM.
    ///
    /// Detects virtio-gpu devices at runtime and adds them to the OCI spec.
    /// This allows containers to use Vulkan (via Mesa Venus) without any
    /// special configuration — if the VM was started with `--gpu`, the
    /// devices appear automatically.
    pub fn add_gpu_devices_if_available(&mut self) {
        let dri_path = std::path::Path::new("/dev/dri");
        if !dri_path.exists() {
            return;
        }

        // DRM card device (for modesetting, display)
        if std::path::Path::new("/dev/dri/card0").exists() {
            self.linux.devices.push(OciDevice {
                device_type: "c".to_string(),
                path: "/dev/dri/card0".to_string(),
                major: 226,
                minor: 0,
                file_mode: Some(0o666),
                uid: Some(0),
                gid: Some(0),
            });
        }

        // Render node (for Vulkan/OpenGL compute — no modesetting privileges)
        if std::path::Path::new("/dev/dri/renderD128").exists() {
            self.linux.devices.push(OciDevice {
                device_type: "c".to_string(),
                path: "/dev/dri/renderD128".to_string(),
                major: 226,
                minor: 128,
                file_mode: Some(0o666),
                uid: Some(0),
                gid: Some(0),
            });
        }
    }

    /// Write the OCI spec to a config.json file in the bundle directory.
    pub fn write_to(&self, bundle_dir: &Path) -> std::io::Result<()> {
        let config_path = bundle_dir.join("config.json");
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(config_path, json)
    }
}

/// Maximum allowed length for an image reference.
const MAX_IMAGE_REF_LENGTH: usize = 512;

/// Validate an OCI image reference format.
///
/// This validates that the image reference follows the expected format:
/// `[registry/][repository/]name[:tag][@digest]`
///
/// # Arguments
/// * `image` - The image reference to validate
///
/// # Returns
/// * `Ok(())` if valid
/// * `Err(message)` if invalid
///
/// # Example valid references:
/// * `alpine`
/// * `alpine:latest`
/// * `alpine:3.18`
/// * `library/alpine`
/// * `docker.io/library/alpine:latest`
/// * `ghcr.io/owner/repo:tag`
/// * `alpine@sha256:abc123...`
pub fn validate_image_reference(image: &str) -> Result<(), String> {
    // Check length
    if image.is_empty() {
        return Err("image reference cannot be empty".into());
    }
    if image.len() > MAX_IMAGE_REF_LENGTH {
        return Err(format!(
            "image reference too long: {} bytes (max: {})",
            image.len(),
            MAX_IMAGE_REF_LENGTH
        ));
    }

    // Check for obviously dangerous characters that could enable injection
    // These should never appear in valid OCI references
    let forbidden_chars = ['$', '`', '|', ';', '&', '>', '<', '\n', '\r', '\0'];
    for c in forbidden_chars {
        if image.contains(c) {
            return Err(format!(
                "image reference contains forbidden character: {:?}",
                c
            ));
        }
    }

    // Check for shell metacharacters in sequence
    if image.contains("..") && image.contains('/') {
        // Path traversal attempt
        return Err("image reference contains suspicious path traversal".into());
    }

    // Basic format validation: must have at least one valid character
    // Valid characters: alphanumeric, '.', '-', '_', '/', ':', '@'
    let valid_chars = |c: char| {
        c.is_ascii_alphanumeric()
            || c == '.'
            || c == '-'
            || c == '_'
            || c == '/'
            || c == ':'
            || c == '@'
    };

    if !image.chars().all(valid_chars) {
        return Err("image reference contains invalid characters".into());
    }

    // Must not start or end with special characters
    // Note: We already checked for empty above, but use defensive programming
    let first = match image.chars().next() {
        Some(c) => c,
        None => return Err("image reference is empty".into()),
    };
    let last = match image.chars().last() {
        Some(c) => c,
        None => return Err("image reference is empty".into()),
    };

    if !first.is_ascii_alphanumeric() {
        return Err("image reference must start with alphanumeric character".into());
    }
    if !last.is_ascii_alphanumeric() {
        return Err("image reference must end with alphanumeric character".into());
    }

    Ok(())
}

/// Validate environment variables.
///
/// Environment variable keys must:
/// - Not be empty
/// - Start with a letter or underscore
/// - Contain only alphanumeric characters and underscores
/// - Not exceed 256 characters
///
/// Values can be any string but must not exceed 32KB.
pub fn validate_env_vars(env: &[(String, String)]) -> Result<(), String> {
    const MAX_KEY_LEN: usize = 256;
    const MAX_VALUE_LEN: usize = 32 * 1024; // 32KB

    for (key, value) in env {
        // Key validation
        if key.is_empty() {
            return Err("environment variable key cannot be empty".into());
        }

        if key.len() > MAX_KEY_LEN {
            return Err(format!(
                "environment variable key '{}...' exceeds {} character limit",
                &key[..32.min(key.len())],
                MAX_KEY_LEN
            ));
        }

        // Key must start with letter or underscore
        // SAFETY: empty keys are rejected above
        let first_char = key.chars().next().expect("key is non-empty");
        if !first_char.is_ascii_alphabetic() && first_char != '_' {
            return Err(format!(
                "environment variable key '{}' must start with a letter or underscore",
                key
            ));
        }

        // Key must contain only alphanumeric and underscore
        if !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(format!(
                "environment variable key '{}' contains invalid characters (only alphanumeric and underscore allowed)",
                key
            ));
        }

        // Value length validation
        if value.len() > MAX_VALUE_LEN {
            return Err(format!(
                "environment variable '{}' value exceeds {} byte limit",
                key, MAX_VALUE_LEN
            ));
        }
    }

    Ok(())
}

/// Generate a unique container ID.
///
/// Uses a combination of timestamp and random bytes to ensure uniqueness
/// even when containers are created in rapid succession.
pub fn generate_container_id() -> String {
    use std::fs::File;
    use std::io::Read;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    // Get 4 bytes of randomness from /dev/urandom
    let random_bytes: u32 = File::open("/dev/urandom")
        .and_then(|mut f| {
            let mut buf = [0u8; 4];
            f.read_exact(&mut buf)?;
            Ok(u32::from_ne_bytes(buf))
        })
        .unwrap_or_else(|_| {
            // Fallback: use process ID and more timestamp bits if /dev/urandom fails
            std::process::id() ^ ((timestamp >> 32) as u32)
        });

    // Combine lower 32 bits of timestamp with 32 bits of randomness
    format!(
        "smolvm-{:08x}{:08x}",
        (timestamp & 0xFFFF_FFFF) as u32,
        random_bytes
    )
}

/// Default Linux capabilities for root containers.
fn default_capabilities() -> Vec<String> {
    vec![
        "CAP_CHOWN".to_string(),
        "CAP_DAC_OVERRIDE".to_string(),
        "CAP_FSETID".to_string(),
        "CAP_FOWNER".to_string(),
        "CAP_MKNOD".to_string(),
        "CAP_NET_RAW".to_string(),
        "CAP_SETGID".to_string(),
        "CAP_SETUID".to_string(),
        "CAP_SETFCAP".to_string(),
        "CAP_SETPCAP".to_string(),
        "CAP_NET_BIND_SERVICE".to_string(),
        "CAP_SYS_CHROOT".to_string(),
        "CAP_KILL".to_string(),
        "CAP_AUDIT_WRITE".to_string(),
    ]
}

/// Default device nodes for container execution.
/// These are standard Linux devices that should exist in /dev.
fn default_devices() -> Vec<OciDevice> {
    vec![
        // /dev/null - discard all writes, reads return EOF
        OciDevice {
            device_type: "c".to_string(),
            path: "/dev/null".to_string(),
            major: 1,
            minor: 3,
            file_mode: Some(0o666),
            uid: Some(0),
            gid: Some(0),
        },
        // /dev/zero - reads return null bytes
        OciDevice {
            device_type: "c".to_string(),
            path: "/dev/zero".to_string(),
            major: 1,
            minor: 5,
            file_mode: Some(0o666),
            uid: Some(0),
            gid: Some(0),
        },
        // /dev/full - writes fail with ENOSPC
        OciDevice {
            device_type: "c".to_string(),
            path: "/dev/full".to_string(),
            major: 1,
            minor: 7,
            file_mode: Some(0o666),
            uid: Some(0),
            gid: Some(0),
        },
        // /dev/random - random number generator (blocking)
        OciDevice {
            device_type: "c".to_string(),
            path: "/dev/random".to_string(),
            major: 1,
            minor: 8,
            file_mode: Some(0o666),
            uid: Some(0),
            gid: Some(0),
        },
        // /dev/urandom - random number generator (non-blocking)
        OciDevice {
            device_type: "c".to_string(),
            path: "/dev/urandom".to_string(),
            major: 1,
            minor: 9,
            file_mode: Some(0o666),
            uid: Some(0),
            gid: Some(0),
        },
        // /dev/tty - controlling terminal
        OciDevice {
            device_type: "c".to_string(),
            path: "/dev/tty".to_string(),
            major: 5,
            minor: 0,
            file_mode: Some(0o666),
            uid: Some(0),
            gid: Some(0),
        },
    ]
}

/// Default mounts for container execution.
fn default_mounts() -> Vec<OciMount> {
    vec![
        // /proc - process information
        OciMount {
            destination: "/proc".to_string(),
            mount_type: Some("proc".to_string()),
            source: "proc".to_string(),
            options: vec![
                "nosuid".to_string(),
                "noexec".to_string(),
                "nodev".to_string(),
            ],
        },
        // /dev - device nodes
        OciMount {
            destination: "/dev".to_string(),
            mount_type: Some("tmpfs".to_string()),
            source: "tmpfs".to_string(),
            options: vec![
                "nosuid".to_string(),
                "strictatime".to_string(),
                "mode=755".to_string(),
                "size=65536k".to_string(),
            ],
        },
        // /dev/pts - pseudo-terminal devices
        OciMount {
            destination: "/dev/pts".to_string(),
            mount_type: Some("devpts".to_string()),
            source: "devpts".to_string(),
            options: vec![
                "nosuid".to_string(),
                "noexec".to_string(),
                "newinstance".to_string(),
                "ptmxmode=0666".to_string(),
                "mode=0620".to_string(),
            ],
        },
        // /dev/shm - shared memory
        OciMount {
            destination: "/dev/shm".to_string(),
            mount_type: Some("tmpfs".to_string()),
            source: "shm".to_string(),
            options: vec![
                "nosuid".to_string(),
                "noexec".to_string(),
                "nodev".to_string(),
                "mode=1777".to_string(),
                "size=65536k".to_string(),
            ],
        },
        // /dev/mqueue - POSIX message queues
        OciMount {
            destination: "/dev/mqueue".to_string(),
            mount_type: Some("mqueue".to_string()),
            source: "mqueue".to_string(),
            options: vec![
                "nosuid".to_string(),
                "noexec".to_string(),
                "nodev".to_string(),
            ],
        },
        // /sys - sysfs (read-only for security)
        OciMount {
            destination: "/sys".to_string(),
            mount_type: Some("sysfs".to_string()),
            source: "sysfs".to_string(),
            options: vec![
                "nosuid".to_string(),
                "noexec".to_string(),
                "nodev".to_string(),
                "ro".to_string(),
            ],
        },
        // /sys/fs/cgroup - cgroup filesystem (read-only)
        OciMount {
            destination: "/sys/fs/cgroup".to_string(),
            mount_type: Some("cgroup2".to_string()),
            source: "cgroup".to_string(),
            options: vec![
                "nosuid".to_string(),
                "noexec".to_string(),
                "nodev".to_string(),
                "ro".to_string(),
            ],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_image_reference_valid() {
        // Valid references should pass
        assert!(validate_image_reference("alpine").is_ok());
        assert!(validate_image_reference("alpine:latest").is_ok());
        assert!(validate_image_reference("alpine:3.18").is_ok());
        assert!(validate_image_reference("library/alpine").is_ok());
        assert!(validate_image_reference("docker.io/library/alpine").is_ok());
        assert!(validate_image_reference("ghcr.io/owner/repo:tag").is_ok());
        assert!(validate_image_reference("my-registry.com/my-image:v1.0.0").is_ok());
        assert!(validate_image_reference("alpine@sha256:abc123def456").is_ok());
    }

    #[test]
    fn test_validate_image_reference_invalid() {
        // Empty
        assert!(validate_image_reference("").is_err());

        // Forbidden characters (shell injection)
        assert!(validate_image_reference("alpine; rm -rf /").is_err());
        assert!(validate_image_reference("alpine | cat /etc/passwd").is_err());
        assert!(validate_image_reference("alpine`whoami`").is_err());
        assert!(validate_image_reference("alpine$PATH").is_err());
        assert!(validate_image_reference("alpine > /tmp/x").is_err());
        assert!(validate_image_reference("alpine\nmalicious").is_err());

        // Invalid characters
        assert!(validate_image_reference("alpine image").is_err()); // space
        assert!(validate_image_reference("alpine!").is_err());

        // Must start/end with alphanumeric
        assert!(validate_image_reference("/alpine").is_err());
        assert!(validate_image_reference("alpine:").is_err());
        assert!(validate_image_reference("-alpine").is_err());
    }

    #[test]
    fn test_validate_image_reference_length() {
        // Very long reference should fail
        let long_ref = "a".repeat(600);
        assert!(validate_image_reference(&long_ref).is_err());

        // Just under limit should pass
        let ok_ref = "a".repeat(500);
        assert!(validate_image_reference(&ok_ref).is_ok());
    }

    #[test]
    fn test_generate_container_id() {
        let id1 = generate_container_id();
        let id2 = generate_container_id();

        assert!(id1.starts_with("smolvm-"));
        assert!(id2.starts_with("smolvm-"));
        // ID format: smolvm-{8 hex}{8 hex} = "smolvm-" (7) + 16 hex chars = 23 total
        assert_eq!(id1.len(), 23);
        assert_eq!(id2.len(), 23);
        // IDs should be unique (different timestamps + random bytes)
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_oci_spec_creation() {
        let spec = OciSpec::new(
            &["echo".to_string(), "hello".to_string()],
            &[("FOO".to_string(), "bar".to_string())],
            "/",
            false,
        );

        assert_eq!(spec.oci_version, "1.0.2");
        assert_eq!(spec.process.args, vec!["echo", "hello"]);
        assert!(spec.process.env.contains(&"FOO=bar".to_string()));
        assert!(!spec.process.terminal);
    }

    #[test]
    fn test_add_bind_mount() {
        let mut spec = OciSpec::new(&["sh".to_string()], &[], "/", false);
        spec.add_bind_mount("/host/path", "/container/path", true);

        let mount = spec.mounts.last().unwrap();
        assert_eq!(mount.destination, "/container/path");
        assert_eq!(mount.source, "/host/path");
        assert!(mount.options.contains(&"ro".to_string()));
    }

    #[test]
    fn test_validate_env_vars_valid() {
        // Valid env vars should pass
        assert!(validate_env_vars(&[]).is_ok());
        assert!(validate_env_vars(&[("FOO".to_string(), "bar".to_string())]).is_ok());
        assert!(validate_env_vars(&[("_FOO".to_string(), "bar".to_string())]).is_ok());
        assert!(validate_env_vars(&[("FOO_BAR".to_string(), "baz".to_string())]).is_ok());
        assert!(validate_env_vars(&[("FOO123".to_string(), "value".to_string())]).is_ok());
        assert!(validate_env_vars(&[("PATH".to_string(), "/usr/bin:/bin".to_string())]).is_ok());
        // Empty values are allowed
        assert!(validate_env_vars(&[("EMPTY".to_string(), "".to_string())]).is_ok());
    }

    #[test]
    fn test_validate_env_vars_invalid_keys() {
        // Empty key
        assert!(validate_env_vars(&[("".to_string(), "value".to_string())]).is_err());

        // Key starting with number
        assert!(validate_env_vars(&[("1FOO".to_string(), "value".to_string())]).is_err());

        // Key with invalid characters
        assert!(validate_env_vars(&[("FOO-BAR".to_string(), "value".to_string())]).is_err());
        assert!(validate_env_vars(&[("FOO.BAR".to_string(), "value".to_string())]).is_err());
        assert!(validate_env_vars(&[("FOO BAR".to_string(), "value".to_string())]).is_err());
        assert!(validate_env_vars(&[("FOO=BAR".to_string(), "value".to_string())]).is_err());
    }

    #[test]
    fn test_validate_env_vars_length_limits() {
        // Key too long (> 256 chars)
        let long_key = "A".repeat(300);
        assert!(validate_env_vars(&[(long_key, "value".to_string())]).is_err());

        // Value too long (> 32KB)
        let long_value = "x".repeat(33 * 1024);
        assert!(validate_env_vars(&[("KEY".to_string(), long_value)]).is_err());

        // Values just under limit should pass
        let ok_value = "x".repeat(32 * 1024);
        assert!(validate_env_vars(&[("KEY".to_string(), ok_value)]).is_ok());
    }

    #[test]
    fn test_gpu_devices_added_when_dri_exists() {
        // On a system with /dev/dri (GPU-enabled VM), devices should be added
        let mut spec = OciSpec::new(&["echo".to_string()], &[], "/", false);
        let before = spec.linux.devices.len();
        spec.add_gpu_devices_if_available();

        if std::path::Path::new("/dev/dri/renderD128").exists() {
            // GPU present — devices were added
            assert!(spec.linux.devices.len() > before);
            assert!(spec
                .linux
                .devices
                .iter()
                .any(|d| d.path == "/dev/dri/renderD128"));
            assert!(spec.linux.devices.iter().any(|d| d.major == 226));
        } else {
            // No GPU — no devices added (no-op)
            assert_eq!(spec.linux.devices.len(), before);
        }
    }

    #[test]
    fn test_gpu_devices_correct_properties() {
        let mut spec = OciSpec::new(&["echo".to_string()], &[], "/", false);
        // Manually add GPU devices to verify properties
        spec.linux.devices.push(super::OciDevice {
            device_type: "c".to_string(),
            path: "/dev/dri/renderD128".to_string(),
            major: 226,
            minor: 128,
            file_mode: Some(0o666),
            uid: Some(0),
            gid: Some(0),
        });

        let dev = spec
            .linux
            .devices
            .iter()
            .find(|d| d.path == "/dev/dri/renderD128")
            .unwrap();
        assert_eq!(dev.device_type, "c");
        assert_eq!(dev.major, 226);
        assert_eq!(dev.minor, 128);
        assert_eq!(dev.file_mode, Some(0o666)); // world-readable for non-root Vulkan
    }
}
