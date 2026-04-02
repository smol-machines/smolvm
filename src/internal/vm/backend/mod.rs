//! VM backend implementations.
//!
//! This module provides hypervisor backend implementations for different platforms.

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod libkrun;

use crate::error::{Error, Result};
use crate::internal::vm::VmBackend;

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub use libkrun::LibkrunBackend;

/// Create the default backend for this platform.
pub fn create_default() -> Result<Box<dyn VmBackend>> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let backend = LibkrunBackend::new()?;
        if backend.is_available() {
            return Ok(Box::new(backend));
        }
    }

    Err(Error::HypervisorUnavailable(
        "no available backend for this platform".into(),
    ))
}
