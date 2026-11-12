//! Network configuration and backend selection.

/// Backend selection and serialization helpers.
pub mod backend;
/// Launch-time backend planning and request validation rules.
pub mod launch;
pub mod port_forward;
/// Named hosts that `--block-private` leaves unreachable.
pub mod private_floor;

pub use backend::NetworkBackend;
pub use launch::{
    plan_launch_network, plan_launch_network_with, validate_requested_network_backend,
    EffectiveNetworkBackend, LaunchNetworkPlan,
};
