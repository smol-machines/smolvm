//! Network configuration and backend selection.

/// Backend selection and serialization helpers.
pub mod backend;
/// Launch-time backend planning and request validation rules.
pub mod launch;
pub mod policy;

pub use backend::NetworkBackend;
pub use launch::{
    plan_launch_network, validate_requested_network_backend, EffectiveNetworkBackend,
    LaunchNetworkPlan, NetworkFallbackReason,
};
pub use policy::get_dns_server;
