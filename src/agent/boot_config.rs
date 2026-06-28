//! Boot configuration for subprocess-based VM launch.
//!
//! On macOS, `fork()` in a multi-threaded process (e.g., the tokio-based API
//! server) creates unstable children because Apple frameworks like
//! Hypervisor.framework detect the forked state and abort. To avoid this,
//! the server spawns a fresh single-threaded `smolvm _boot-vm` subprocess
//! that safely runs `krun_start_enter`.
//!
//! This module defines the serializable config passed to that subprocess.

use crate::data::disk::DiskFormat;
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
    /// Enable CUDA-over-vsock: smolvm starts a host CUDA server and remotes the
    /// guest's CUDA Driver-API calls to the host GPU.
    #[serde(default)]
    pub cuda: bool,
    /// Hostnames for DNS filtering. When set, the host starts a DNS filter
    /// listener and the guest agent proxies DNS queries through it.
    #[serde(default)]
    pub dns_filter_hosts: Option<Vec<String>>,
    /// Pre-extracted OCI layers directory for .smolmachine-sourced machines.
    /// When `pack_idmap_source` is set, this is an empty per-VM mountpoint the
    /// boot subprocess idmap-binds the shared pack onto; otherwise it is the
    /// directory holding the extracted pack directly.
    #[serde(default)]
    pub packed_layers_dir: Option<PathBuf>,
    /// Root-owned shared pack directory (`_shared/<checksum>`) to present at
    /// `packed_layers_dir` via a per-VM idmapped bind mount that maps on-disk
    /// uid 0 -> the VM's dropped uid. Set only when per-VM uid isolation is
    /// active (Linux fleet); the mount lives in the boot subprocess's private
    /// mount namespace and is torn down automatically on exit. When `None`,
    /// `packed_layers_dir` is consumed as-is (no idmap mount).
    #[serde(default)]
    pub pack_idmap_source: Option<PathBuf>,
    /// Additional disk images to attach (path, read_only, format). The format
    /// lets the `pack --from-vm` exporter attach a source qcow2 disk read-only.
    #[serde(default)]
    pub extra_disks: Vec<(PathBuf, bool, DiskFormat)>,
}
