//! The backend default flips to virtio-net once the internal guest gateway is
//! enabled — which `serve` does for every server, so every networked machine
//! created through the API runs virtio-net rather than TSI.
//!
//! This lived only in a comment, and the divergence it caused was invisible:
//! the schema documented TSI, the server ran virtio-net, and a libkrun built
//! without the net feature turned that gap into "machine cannot start" for the
//! most ordinary request shape there is. Pin the flip so the documented default
//! and the real one cannot drift apart again silently.
//!
//! Its own test binary on purpose: the gateway registration is a process-global
//! set-once atomic, so a test that enables it would leak into every other test
//! sharing the process and make their defaults depend on execution order.

use smolvm::agent::VmResources;
use smolvm::network::launch::{
    configure_guest_host_service, plan_launch_network, EffectiveNetworkBackend,
};

#[test]
fn guest_host_service_flips_the_default_to_virtio_net() {
    let mut resources = VmResources {
        network: true,
        ..Default::default()
    };

    // No ports, no egress policy, no gateway: the light outbound-only default.
    assert_eq!(
        plan_launch_network(&resources, None, 0).backend,
        EffectiveNetworkBackend::Tsi,
        "an outbound-only machine should take the lighter TSI path before the \
         guest gateway is configured"
    );

    configure_guest_host_service(1, 1).expect("configure guest host service");

    // Same request, same machine shape — the server-side gateway alone decides.
    assert_eq!(
        plan_launch_network(&resources, None, 0).backend,
        EffectiveNetworkBackend::VirtioNet,
        "once the guest gateway is configured every networked machine must run \
         virtio-net, which is what `serve` does for all API-created machines"
    );

    // An explicit request still wins over the conditional default.
    resources.network_backend = Some(smolvm::network::NetworkBackend::Tsi);
    assert_eq!(
        plan_launch_network(&resources, None, 0).backend,
        EffectiveNetworkBackend::Tsi,
        "an explicitly pinned backend must not be overridden by the default"
    );
}
