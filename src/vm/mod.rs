//! VM creation and lifecycle management.
//!
//! This module provides the core abstractions for creating and managing microVMs:
//! - [`VmConfig`]: Configuration for a VM instance
//! - [`VmHandle`]: Trait for controlling a running VM
//! - [`VmBackend`]: Trait for VM backend implementations (e.g., libkrun)

pub mod backend;
pub mod config;
pub mod rosetta;
pub mod state;

use crate::error::Result;
pub use config::{
    DiskConfig, DiskFormat, HostMount, NetworkPolicy, RootfsSource, Timeouts, VmConfig, VmId,
    VsockPort,
};
pub use state::{ExitReason, VmState};

/// Handle to a running or stopped VM.
///
/// This trait provides the interface for controlling a VM's lifecycle.
/// Implementations handle the platform-specific details of VM management.
pub trait VmHandle: Send {
    /// Get the VM ID.
    fn id(&self) -> &VmId;

    /// Get current state.
    fn state(&self) -> VmState;

    /// Wait for VM to exit (blocking).
    ///
    /// Returns the exit reason once the VM terminates.
    fn wait(&mut self) -> Result<ExitReason>;

    /// Request graceful shutdown.
    ///
    /// This sends a shutdown signal to the VM and waits for it to terminate
    /// gracefully. The shutdown timeout from the VM config is used.
    fn stop(&mut self) -> Result<()>;

    /// Force kill the VM.
    ///
    /// This immediately terminates the VM without waiting for graceful shutdown.
    fn kill(&mut self) -> Result<()>;
}

/// Factory for creating VMs.
///
/// This trait abstracts over different hypervisor backends (e.g., libkrun, KVM).
pub trait VmBackend: Send + Sync {
    /// Backend name (e.g., "libkrun", "kvm").
    fn name(&self) -> &'static str;

    /// Check if this backend is available on the current system.
    fn is_available(&self) -> bool;

    /// Create and start a VM with the given configuration.
    ///
    /// This creates a new VM, starts it, and returns a handle for controlling it.
    fn create(&self, config: VmConfig) -> Result<Box<dyn VmHandle>>;
}

/// Get the default backend for this platform.
///
/// On macOS, this returns the libkrun backend.
/// On Linux, this also returns libkrun (KVM via libkrun).
///
/// # Errors
///
/// Returns an error if no suitable backend is available.
pub fn default_backend() -> Result<Box<dyn VmBackend>> {
    backend::create_default()
}
