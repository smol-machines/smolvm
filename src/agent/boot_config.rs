//! Boot configuration for subprocess-based VM launch.
//!
//! On macOS, `fork()` in a multi-threaded process (e.g., the tokio-based API
//! server) creates unstable children because Apple frameworks like
//! Hypervisor.framework detect the forked state and abort. To avoid this,
//! the server spawns a fresh single-threaded `smolvm _boot-vm` subprocess
//! that safely runs `krun_start_enter`.
//!
//! This module defines the serializable config passed to that subprocess.

use crate::data::network::PortMapping;
use crate::data::resources::VmResources;
use crate::data::storage::HostMount;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Configuration for the `_boot-vm` subprocess.
///
/// Written to a temp file by the parent and read by the child.
#[derive(Debug, Serialize, Deserialize)]
pub struct BootConfig {
    /// Path to the agent rootfs directory.
    pub rootfs_path: PathBuf,
    /// Path to the storage disk file.
    pub storage_disk_path: PathBuf,
    /// Path to the overlay disk file.
    pub overlay_disk_path: PathBuf,
    /// Path to the vsock Unix socket.
    pub vsock_socket: PathBuf,
    /// Optional path to console log file.
    pub console_log: Option<PathBuf>,
    /// Path to write startup errors.
    pub startup_error_log: PathBuf,
    /// Storage disk size in GiB.
    pub storage_size_gb: u64,
    /// Overlay disk size in GiB.
    pub overlay_size_gb: u64,
    /// Host directory mounts.
    pub mounts: Vec<HostMount>,
    /// Port mappings.
    pub ports: Vec<PortMapping>,
    /// VM resources (CPU, memory, network, disk sizes).
    pub resources: VmResources,
    /// Path to the host-side Unix socket for SSH agent forwarding.
    /// When set, a vsock port is registered so the guest can reach the host's SSH agent.
    #[serde(default)]
    pub ssh_agent_socket: Option<PathBuf>,
    /// Hostnames for DNS filtering. When set, the host starts a DNS filter
    /// listener and the guest agent proxies DNS queries through it.
    #[serde(default)]
    pub dns_filter_hosts: Option<Vec<String>>,
}
