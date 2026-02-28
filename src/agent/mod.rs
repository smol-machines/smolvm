//! Agent VM management.
//!
//! This module manages the agent VM lifecycle and provides a client
//! for communicating with the smolvm-agent via vsock.

mod client;
mod launcher;
pub mod launcher_dynamic;
mod manager;
pub mod terminal;

pub use crate::vm::config::HostMount;
pub use client::{AgentClient, PullOptions, RunConfig};
pub use manager::{docker_config_dir, docker_config_mount, vm_data_dir, AgentManager, AgentState};

/// Default agent VM memory in MiB.
pub const DEFAULT_MEMORY_MIB: u32 = 512;

/// Default agent VM CPU count.
pub const DEFAULT_CPUS: u8 = 1;

/// Agent VM name.
pub const AGENT_VM_NAME: &str = "smolvm-agent";

/// Generate a virtiofs mount tag for a given index.
///
/// Mount tags follow the format "smolvm0", "smolvm1", etc. and are used
/// consistently across the host launcher, API handlers, and guest agent.
pub fn mount_tag(index: usize) -> String {
    format!("smolvm{}", index)
}

/// TCP port mapping from host to guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PortMapping {
    /// Port on the host.
    pub host: u16,
    /// Port inside the guest.
    pub guest: u16,
}

impl PortMapping {
    /// Create a new port mapping.
    pub fn new(host: u16, guest: u16) -> Self {
        Self { host, guest }
    }

    /// Create a port mapping where host and guest ports are the same.
    pub fn same(port: u16) -> Self {
        Self {
            host: port,
            guest: port,
        }
    }
}

/// VM configuration for the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VmResources {
    /// Number of vCPUs.
    pub cpus: u8,
    /// Memory in MiB.
    pub mem: u32,
    /// Enable outbound network access (TSI).
    pub network: bool,
    /// Storage disk size in GiB (None = default 20 GiB).
    pub storage_gb: Option<u64>,
    /// Overlay disk size in GiB (None = default 2 GiB).
    pub overlay_gb: Option<u64>,
}

impl Default for VmResources {
    fn default() -> Self {
        Self {
            cpus: DEFAULT_CPUS,
            mem: DEFAULT_MEMORY_MIB,
            network: false,
            storage_gb: None,
            overlay_gb: None,
        }
    }
}
