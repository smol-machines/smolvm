use crate::data::resources::VmResources;
use crate::network::backend::NetworkBackend;

/// Effective backend selected for a launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectiveNetworkBackend {
    /// No network device.
    None,
    /// TSI networking.
    Tsi,
    /// Virtio-net networking.
    VirtioNet,
}

/// Network launch decision for a VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaunchNetworkPlan {
    /// Selected backend.
    pub backend: EffectiveNetworkBackend,
}

impl LaunchNetworkPlan {
    /// Whether the launch should attach any network backend at all.
    pub const fn has_network(self) -> bool {
        !matches!(self.backend, EffectiveNetworkBackend::None)
    }
}

/// Compute the effective launch backend from user intent.
///
/// virtio-net now enforces the full egress policy (CIDR + allow-host DNS
/// filtering) and serves inbound published ports, so an explicit virtio-net
/// request is always honored; nothing downgrades to TSI.
pub fn plan_launch_network(
    resources: &VmResources,
    dns_filter_hosts: Option<&[String]>,
    port_count: usize,
) -> LaunchNetworkPlan {
    let has_ports = port_count > 0;
    let has_cidr_policy = resources
        .allowed_cidrs
        .as_ref()
        .is_some_and(|cidrs| !cidrs.is_empty());
    let has_dns_filter = dns_filter_hosts.is_some_and(|hosts| !hosts.is_empty());
    let wants_network = resources.network || has_ports || has_cidr_policy || has_dns_filter;

    if !wants_network {
        return LaunchNetworkPlan {
            backend: EffectiveNetworkBackend::None,
        };
    }

    // Published ports need the inbound path, which only virtio-net provides.
    // When the caller didn't pick a backend explicitly, default to virtio-net
    // IFF there are ports (TSI otherwise — it's lighter for outbound-only VMs).
    // This is ONE rule in the shared launch path, so a machine that's reachable
    // on a laptop is reachable in the fleet by construction — no per-deployment
    // backend wiring to drift between local and cloud.
    let backend = resources.network_backend.unwrap_or(if has_ports {
        NetworkBackend::VirtioNet
    } else {
        NetworkBackend::Tsi
    });
    match backend {
        NetworkBackend::Tsi => LaunchNetworkPlan {
            backend: EffectiveNetworkBackend::Tsi,
        },
        NetworkBackend::VirtioNet => LaunchNetworkPlan {
            backend: EffectiveNetworkBackend::VirtioNet,
        },
    }
}

/// Validate the requested networking against what each backend can do.
///
/// - Published ports need virtio-net: TSI is outbound-only, so a port request on
///   TSI (the default) would silently never accept connections — reject instead.
/// - `--net-backend virtio-net` with no networking intent at all is rejected.
pub fn validate_requested_network_backend(
    resources: &VmResources,
    dns_filter_hosts: Option<&[String]>,
    port_count: usize,
) -> crate::Result<()> {
    // Mirror plan_launch_network's default: unset backend + ports ⇒ virtio-net.
    // So only an EXPLICIT `--net-backend tsi` alongside ports is a misconfig.
    let backend = resources.network_backend.unwrap_or(if port_count > 0 {
        NetworkBackend::VirtioNet
    } else {
        NetworkBackend::Tsi
    });

    // Published ports require the inbound path that only virtio-net has. With the
    // default above this only fires when the caller EXPLICITLY forced TSI + ports.
    if port_count > 0 && backend != NetworkBackend::VirtioNet {
        return Err(crate::Error::config(
            "ports",
            "published ports require the virtio-net backend (TSI is outbound-only); \
             remove --net-backend tsi or set it to virtio-net",
        ));
    }

    if resources.network_backend != Some(NetworkBackend::VirtioNet) {
        return Ok(());
    }

    let has_cidr_policy = resources
        .allowed_cidrs
        .as_ref()
        .is_some_and(|cidrs| !cidrs.is_empty());
    let has_dns_filter = dns_filter_hosts.is_some_and(|hosts| !hosts.is_empty());
    let wants_network = resources.network || port_count > 0 || has_cidr_policy || has_dns_filter;

    if !wants_network {
        return Err(crate::Error::config(
            "--net-backend",
            "--net-backend virtio-net requires --net",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resources() -> VmResources {
        VmResources::default()
    }

    #[test]
    fn test_no_network_plan() {
        let plan = plan_launch_network(&resources(), None, 0);
        assert_eq!(plan.backend, EffectiveNetworkBackend::None);
    }

    #[test]
    fn test_default_network_uses_tsi() {
        let mut resources = resources();
        resources.network = true;
        let plan = plan_launch_network(&resources, None, 0);
        assert_eq!(plan.backend, EffectiveNetworkBackend::Tsi);
    }

    #[test]
    fn test_plain_virtio_selects_virtio_backend() {
        let mut resources = resources();
        resources.network = true;
        resources.network_backend = Some(NetworkBackend::VirtioNet);
        let plan = plan_launch_network(&resources, None, 0);
        assert_eq!(plan.backend, EffectiveNetworkBackend::VirtioNet);
    }

    #[test]
    fn test_ports_work_with_virtio() {
        let mut resources = resources();
        resources.network = true;
        resources.network_backend = Some(NetworkBackend::VirtioNet);
        let plan = plan_launch_network(&resources, None, 1);
        assert_eq!(plan.backend, EffectiveNetworkBackend::VirtioNet);
    }

    #[test]
    fn test_cidr_policy_stays_virtio() {
        // CIDR egress policy is enforced by the virtio-net gateway, so it no
        // longer downgrades an explicit virtio-net request.
        let mut resources = resources();
        resources.network = true;
        resources.network_backend = Some(NetworkBackend::VirtioNet);
        resources.allowed_cidrs = Some(vec!["1.1.1.1/32".into()]);
        let plan = plan_launch_network(&resources, None, 0);
        assert_eq!(plan.backend, EffectiveNetworkBackend::VirtioNet);
    }

    #[test]
    fn test_dns_filter_stays_virtio() {
        // allow-host filtering is now enforced by the virtio-net gateway, so an
        // explicit virtio-net request is honored rather than downgraded.
        let mut resources = resources();
        resources.network = true;
        resources.network_backend = Some(NetworkBackend::VirtioNet);
        let hosts = ["example.com".to_string()];
        let plan = plan_launch_network(&resources, Some(&hosts), 0);
        assert_eq!(plan.backend, EffectiveNetworkBackend::VirtioNet);
    }

    #[test]
    fn test_validate_plain_virtio_allowed() {
        let mut resources = resources();
        resources.network = true;
        resources.network_backend = Some(NetworkBackend::VirtioNet);
        validate_requested_network_backend(&resources, None, 0).unwrap();
    }

    #[test]
    fn test_validate_ports_allowed_for_virtio() {
        let mut resources = resources();
        resources.network = true;
        resources.network_backend = Some(NetworkBackend::VirtioNet);
        validate_requested_network_backend(&resources, None, 1).unwrap();
    }

    #[test]
    fn test_ports_default_to_virtio() {
        // Ports with NO explicit backend now auto-select virtio-net (the inbound
        // path) — both in the plan and in validation, so it "just works".
        let mut resources = resources();
        resources.network = true;
        let plan = plan_launch_network(&resources, None, 1);
        assert_eq!(plan.backend, EffectiveNetworkBackend::VirtioNet);
        validate_requested_network_backend(&resources, None, 1).unwrap();
    }

    #[test]
    fn test_validate_ports_explicit_tsi_rejected() {
        // Only an EXPLICIT TSI choice alongside ports is a misconfig (TSI has no
        // inbound path); the auto-default case above is allowed.
        let mut resources = resources();
        resources.network = true;
        resources.network_backend = Some(NetworkBackend::Tsi);
        let err = validate_requested_network_backend(&resources, None, 1).unwrap_err();
        assert!(err.to_string().contains("require the virtio-net backend"));
    }

    #[test]
    fn test_no_ports_defaults_to_tsi() {
        // Outbound-only VMs keep the lighter TSI default — no virtio overhead.
        let mut resources = resources();
        resources.network = true;
        assert_eq!(
            plan_launch_network(&resources, None, 0).backend,
            EffectiveNetworkBackend::Tsi
        );
    }

    #[test]
    fn test_validate_cidr_allowed_for_virtio() {
        // CIDR egress policy is now honored on virtio-net, so validation passes.
        let mut resources = resources();
        resources.network = true;
        resources.network_backend = Some(NetworkBackend::VirtioNet);
        resources.allowed_cidrs = Some(vec!["1.1.1.1/32".into()]);
        validate_requested_network_backend(&resources, None, 0).unwrap();
    }

    #[test]
    fn test_validate_dns_filter_allowed_for_virtio() {
        // allow-host is now honored on virtio-net, so validation passes.
        let mut resources = resources();
        resources.network = true;
        resources.network_backend = Some(NetworkBackend::VirtioNet);
        let hosts = ["example.com".to_string()];
        validate_requested_network_backend(&resources, Some(&hosts), 0).unwrap();
    }
}
