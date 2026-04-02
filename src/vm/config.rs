//! VM configuration types.

pub use crate::data::storage::HostMount;

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

/// Unique identifier for a VM instance.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VmId(pub String);

impl VmId {
    /// Create a new VmId from a string.
    ///
    /// The ID is sanitized to only allow alphanumeric characters, dashes, and underscores.
    /// IDs are limited to 64 characters. If the input is empty or contains only invalid
    /// characters, a generated ID is used instead.
    pub fn new(id: impl Into<String>) -> Self {
        let id = id.into();
        // Sanitize: only allow alphanumeric, dash, underscore
        let sanitized: String = id
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
            .take(64) // Max length
            .collect();
        if sanitized.is_empty() {
            Self::generate()
        } else {
            Self(sanitized)
        }
    }

    /// Generate a unique VmId based on timestamp.
    pub fn generate() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_millis();
        Self(format!("vm-{:x}", ts))
    }

    /// Get the ID as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for VmId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for VmId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Timeout configuration (aligned with DESIGN.md defaults).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Timeouts {
    /// Boot timeout (default: 30s).
    #[serde(with = "humantime_serde")]
    pub boot: Duration,

    /// Shutdown timeout (default: 10s).
    #[serde(with = "humantime_serde")]
    pub shutdown: Duration,

    /// Optional execution timeout.
    #[serde(default, with = "option_duration")]
    pub exec: Option<Duration>,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            boot: Duration::from_secs(30),
            shutdown: Duration::from_secs(10),
            exec: None,
        }
    }
}

mod humantime_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        duration.as_secs().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = u64::deserialize(deserializer)?;
        Ok(Duration::from_secs(secs))
    }
}

mod option_duration {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Option<Duration>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match duration {
            Some(d) => Some(d.as_secs()).serialize(serializer),
            None => None::<u64>.serialize(serializer),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt = Option::<u64>::deserialize(deserializer)?;
        Ok(opt.map(Duration::from_secs))
    }
}

/// Network policy (from DESIGN.md).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum NetworkPolicy {
    /// vsock only, no network access.
    #[default]
    None,

    /// Outbound internet via NAT.
    Egress {
        /// Custom DNS server (default: inherit from host).
        dns: Option<IpAddr>,
        /// If set, only these CIDR ranges are reachable. Omit for unrestricted.
        #[serde(default)]
        allowed_cidrs: Option<Vec<String>>,
    },
}

/// Disk image format for block devices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
#[repr(u32)]
pub enum DiskFormat {
    /// Raw disk image.
    #[default]
    Raw = 0,
    /// QCOW2 format (copy-on-write).
    Qcow2 = 1,
}

/// Block device configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiskConfig {
    /// Unique identifier for this block device.
    pub block_id: String,
    /// Path to the disk image.
    pub path: PathBuf,
    /// Disk format.
    pub format: DiskFormat,
    /// Whether the disk is read-only.
    pub read_only: bool,
}

impl DiskConfig {
    /// Create a new disk configuration.
    pub fn new(block_id: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        Self {
            block_id: block_id.into(),
            path: path.into(),
            format: DiskFormat::Raw,
            read_only: false,
        }
    }

    /// Set the disk as read-only.
    pub fn read_only(mut self) -> Self {
        self.read_only = true;
        self
    }

    /// Set the disk format.
    pub fn format(mut self, format: DiskFormat) -> Self {
        self.format = format;
        self
    }
}

/// vsock port configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VsockPort {
    /// Port number (CID 3 is guest, 2 is host).
    pub port: u32,
    /// Unix socket path on the host.
    pub socket_path: PathBuf,
    /// If true, the host listens; if false, the guest listens.
    pub listen: bool,
}

impl VsockPort {
    /// Create a new vsock port where host listens.
    pub fn host_listen(port: u32, socket_path: impl Into<PathBuf>) -> Self {
        Self {
            port,
            socket_path: socket_path.into(),
            listen: true,
        }
    }

    /// Create a new vsock port where guest listens.
    pub fn guest_listen(port: u32, socket_path: impl Into<PathBuf>) -> Self {
        Self {
            port,
            socket_path: socket_path.into(),
            listen: false,
        }
    }
}

/// Source of the guest root filesystem.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum RootfsSource {
    /// Direct path to a directory or image.
    Path {
        /// Path to the rootfs directory.
        path: PathBuf,
    },
}

impl RootfsSource {
    /// Create a path-based rootfs source.
    pub fn path(p: impl Into<PathBuf>) -> Self {
        Self::Path { path: p.into() }
    }
}

/// Complete VM configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmConfig {
    /// Unique VM identifier.
    pub id: VmId,

    /// Root filesystem source.
    pub rootfs: RootfsSource,

    /// Memory in MiB (default: 512).
    pub memory_mib: u32,

    /// Number of vCPUs (default: 1).
    pub cpus: u8,

    /// Timeouts.
    pub timeouts: Timeouts,

    /// Network policy.
    pub network: NetworkPolicy,

    /// Host mounts (virtiofs).
    pub mounts: Vec<HostMount>,

    /// Block devices (virtio-blk).
    pub disks: Vec<DiskConfig>,

    /// vsock ports for host-guest communication.
    pub vsock_ports: Vec<VsockPort>,

    /// Console output log file (for debugging).
    pub console_log: Option<PathBuf>,

    /// Enable Rosetta for x86_64 binaries on Apple Silicon.
    pub rosetta: bool,

    /// Command to execute (None = use rootfs default).
    pub command: Option<Vec<String>>,

    /// Working directory.
    pub workdir: Option<PathBuf>,

    /// Environment variables.
    pub env: Vec<(String, String)>,
}

impl VmConfig {
    /// Create a builder for VmConfig.
    pub fn builder(rootfs: RootfsSource) -> VmConfigBuilder {
        VmConfigBuilder::new(rootfs)
    }
}

/// Builder for VmConfig.
#[derive(Debug)]
pub struct VmConfigBuilder {
    config: VmConfig,
}

impl VmConfigBuilder {
    /// Create a new builder with the given rootfs source.
    pub fn new(rootfs: RootfsSource) -> Self {
        Self {
            config: VmConfig {
                id: VmId::generate(),
                rootfs,
                memory_mib: 512,
                cpus: 1,
                timeouts: Timeouts::default(),
                network: NetworkPolicy::default(),
                mounts: Vec::new(),
                disks: Vec::new(),
                vsock_ports: Vec::new(),
                console_log: None,
                rosetta: false,
                command: None,
                workdir: None,
                env: Vec::new(),
            },
        }
    }

    /// Set the VM ID.
    pub fn id(mut self, id: VmId) -> Self {
        self.config.id = id;
        self
    }

    /// Set the memory in MiB.
    pub fn memory(mut self, mib: u32) -> Self {
        self.config.memory_mib = mib;
        self
    }

    /// Set the number of CPUs.
    pub fn cpus(mut self, cpus: u8) -> Self {
        self.config.cpus = cpus;
        self
    }

    /// Set the network policy.
    pub fn network(mut self, policy: NetworkPolicy) -> Self {
        self.config.network = policy;
        self
    }

    /// Add a host mount.
    pub fn mount(mut self, mount: HostMount) -> Self {
        self.config.mounts.push(mount);
        self
    }

    /// Set the command to execute.
    pub fn command(mut self, cmd: Vec<String>) -> Self {
        self.config.command = Some(cmd);
        self
    }

    /// Set the working directory.
    pub fn workdir(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.workdir = Some(path.into());
        self
    }

    /// Add an environment variable.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.config.env.push((key.into(), value.into()));
        self
    }

    /// Set the boot timeout.
    pub fn boot_timeout(mut self, timeout: Duration) -> Self {
        self.config.timeouts.boot = timeout;
        self
    }

    /// Set the shutdown timeout.
    pub fn shutdown_timeout(mut self, timeout: Duration) -> Self {
        self.config.timeouts.shutdown = timeout;
        self
    }

    /// Set the execution timeout.
    pub fn exec_timeout(mut self, timeout: Duration) -> Self {
        self.config.timeouts.exec = Some(timeout);
        self
    }

    /// Add a block device.
    pub fn disk(mut self, disk: DiskConfig) -> Self {
        self.config.disks.push(disk);
        self
    }

    /// Add a vsock port.
    pub fn vsock(mut self, port: VsockPort) -> Self {
        self.config.vsock_ports.push(port);
        self
    }

    /// Set the console log file.
    pub fn console_log(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.console_log = Some(path.into());
        self
    }

    /// Enable Rosetta for x86_64 binaries.
    pub fn rosetta(mut self, enabled: bool) -> Self {
        self.config.rosetta = enabled;
        self
    }

    /// Build the VmConfig.
    pub fn build(self) -> VmConfig {
        self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vm_id_sanitization() {
        // Normal ID passes through
        let id = VmId::new("my-test_vm123");
        assert_eq!(id.as_str(), "my-test_vm123");

        // Invalid characters are stripped (security: prevents directory traversal)
        let id = VmId::new("../../../etc/passwd");
        assert_eq!(id.as_str(), "etcpasswd");

        // Slashes and dots removed
        let id = VmId::new("vm/name.with.dots");
        assert_eq!(id.as_str(), "vmnamewithdots");

        // Empty after sanitization uses generated ID
        let id = VmId::new("///");
        assert!(id.as_str().starts_with("vm-"));

        // Long IDs are truncated
        let long_id = "a".repeat(100);
        let id = VmId::new(long_id);
        assert_eq!(id.as_str().len(), 64);
    }

    #[test]
    fn test_vm_config_builder() {
        let config = VmConfig::builder(RootfsSource::path("/rootfs"))
            .id(VmId::new("my-vm"))
            .memory(1024)
            .cpus(2)
            .network(NetworkPolicy::Egress {
                dns: None,
                allowed_cidrs: None,
            })
            .mount(HostMount {
                source: "/host".into(),
                target: "/guest".into(),
                read_only: true,
            })
            .command(vec!["/bin/sh".to_string()])
            .workdir("/app")
            .env("FOO", "bar")
            .build();

        assert_eq!(config.id.as_str(), "my-vm");
        assert_eq!(config.memory_mib, 1024);
        assert_eq!(config.cpus, 2);
        assert!(matches!(config.network, NetworkPolicy::Egress { .. }));
        assert_eq!(config.mounts.len(), 1);
        assert_eq!(config.command, Some(vec!["/bin/sh".to_string()]));
        assert_eq!(config.workdir, Some(PathBuf::from("/app")));
        assert_eq!(config.env, vec![("FOO".to_string(), "bar".to_string())]);
    }

    #[test]
    fn test_network_policy_serialization() {
        let none = NetworkPolicy::None;
        let json = serde_json::to_string(&none).unwrap();
        assert!(json.contains("none"));

        let egress = NetworkPolicy::Egress {
            dns: Some("8.8.8.8".parse().unwrap()),
            allowed_cidrs: None,
        };
        let json = serde_json::to_string(&egress).unwrap();
        assert!(json.contains("egress"));
        assert!(json.contains("8.8.8.8"));
    }

    #[test]
    fn test_network_policy_allowed_cidrs_roundtrip() {
        let policy = NetworkPolicy::Egress {
            dns: None,
            allowed_cidrs: Some(vec!["10.0.0.0/8".to_string(), "1.1.1.1/32".to_string()]),
        };
        let json = serde_json::to_string(&policy).unwrap();
        let roundtripped: NetworkPolicy = serde_json::from_str(&json).unwrap();
        match roundtripped {
            NetworkPolicy::Egress { dns, allowed_cidrs } => {
                assert!(dns.is_none());
                let cidrs = allowed_cidrs.expect("allowed_cidrs should be Some");
                assert_eq!(cidrs, vec!["10.0.0.0/8", "1.1.1.1/32"]);
            }
            _ => panic!("expected Egress variant"),
        }
    }
}
