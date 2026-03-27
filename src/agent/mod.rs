//! Agent VM management.
//!
//! This module manages the agent VM lifecycle and provides a client
//! for communicating with the smolvm-agent via vsock.

mod client;
mod launcher;
pub mod launcher_dynamic;
mod manager;
pub mod terminal;

pub use crate::data::network::PortMapping;
pub use crate::data::resources::VmResources;
pub use crate::data::storage::HostMount;
pub use client::{AgentClient, PullOptions, RunConfig};
pub use manager::{docker_config_dir, docker_config_mount, vm_data_dir, AgentManager, AgentState};

/// Agent VM name.
pub const AGENT_VM_NAME: &str = "smolvm-agent";
