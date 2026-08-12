//! The backend default is contextual (issue #884): a machine with networking
//! and no explicit `networkBackend` gets TSI on a bare CLI launch, but
//! virtio-net once the guest host-service is configured — which `serve` does
//! unconditionally, so every networked API machine defaults to virtio-net.
//! This pins the behavior the API schema documents (src/api/types.rs).
//!
//! Lives in its own integration-test binary because the host-service signal is
//! process-global (a one-shot static + `SMOLVM_GUEST_HOST_SERVICE`); mutating
//! it inside the unit-test binary would poison the launch.rs default tests.

use smolvm::data::resources::VmResources;
use smolvm::network::launch::{
    plan_launch_network, validate_requested_network_backend, EffectiveNetworkBackend,
};

const HOST_SERVICE_ENV: &str = "SMOLVM_GUEST_HOST_SERVICE";

#[test]
fn host_service_flips_the_default_backend_to_virtio_net() {
    // Single test function: the env var is process-wide, and cargo runs tests
    // in the same binary concurrently — sequential phases avoid the race.
    std::env::remove_var(HOST_SERVICE_ENV);

    let resources = VmResources {
        network: true,
        ..Default::default()
    };

    // Outside serve (no host-service): outbound-only default stays TSI.
    let plan = plan_launch_network(&resources, None, 0);
    assert_eq!(plan.backend, EffectiveNetworkBackend::Tsi);

    // With the host-service configured (what `serve` always does via
    // configure_guest_host_service; the env var is the inherited form the
    // spawned `_boot-vm` sees): the default becomes virtio-net.
    std::env::set_var(HOST_SERVICE_ENV, "4500:4500");
    let plan = plan_launch_network(&resources, None, 0);
    assert_eq!(plan.backend, EffectiveNetworkBackend::VirtioNet);

    // And validation accepts the defaulted shape (no ports, no policy).
    validate_requested_network_backend(&resources, None, 0)
        .expect("default-shaped networked machine under serve must validate");

    std::env::remove_var(HOST_SERVICE_ENV);
}
