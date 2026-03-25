//! Canonical shared data models and constants for smolvm.

/// Shared constants used across the runtime and adapters.
pub mod consts;
/// Canonical error types used by the shared data layer.
#[path = "errors.rs"]
pub mod error;
/// Canonical network-related data models.
pub mod network;
/// Canonical resource configuration data models.
pub mod resources;
/// Canonical storage and mount data models.
pub mod storage;

/// Target VM identifier used by shared operations.
pub enum VmTarget {
    /// The default micro vm
    Default,
    /// A specifically named micro vm
    Named(String),
}

impl VmTarget {
    /// Return the stable VM name for this target.
    pub fn name(&self) -> &str {
        match self {
            Self::Default => "default",
            Self::Named(name) => name.as_str(),
        }
    }
}

impl From<&str> for VmTarget {
    fn from(name: &str) -> VmTarget {
        if name == "default" {
            VmTarget::Default
        } else {
            VmTarget::Named(String::from(name))
        }
    }
}
