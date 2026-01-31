//! Agent VM management.
//!
//! This module manages the agent VM lifecycle and provides a client
//! for communicating with the smolvm-agent via vsock.

mod client;
mod launcher;
mod manager;

pub use crate::vm::config::HostMount;
pub use client::{AgentClient, PullOptions, RunConfig};
pub use manager::{docker_config_dir, docker_config_mount, AgentManager, AgentState};

/// Default agent VM memory in MiB.
pub const DEFAULT_MEMORY_MIB: u32 = 256;

/// Default agent VM CPU count.
pub const DEFAULT_CPUS: u8 = 1;

/// Agent VM name.
pub const AGENT_VM_NAME: &str = "smolvm-agent";

/// TCP port mapping from host to guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmResources {
    /// Number of vCPUs.
    pub cpus: u8,
    /// Memory in MiB.
    pub mem: u32,
}

impl Default for VmResources {
    fn default() -> Self {
        Self {
            cpus: DEFAULT_CPUS,
            mem: DEFAULT_MEMORY_MIB,
        }
    }
}
