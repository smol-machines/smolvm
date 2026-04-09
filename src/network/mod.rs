//! Network configuration and backend selection.

/// Backend selection and serialization helpers.
pub mod backend;
/// Launch-time backend planning and fallback rules.
pub mod launch;
pub mod policy;

pub use backend::NetworkBackend;
pub use launch::{
    plan_launch_network, EffectiveNetworkBackend, LaunchNetworkPlan, NetworkFallbackReason,
};
pub use policy::get_dns_server;
