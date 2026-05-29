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

/// Reason a requested backend was downgraded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkFallbackReason {
    /// Current egress policies and DNS filtering are only implemented on TSI.
    PolicyRequiresTsi,
}

impl NetworkFallbackReason {
    /// User-facing explanation for the fallback.
    pub const fn user_message(self) -> &'static str {
        match self {
            Self::PolicyRequiresTsi => {
                "allow-cidr/allow-host policies still use the TSI backend; falling back from virtio-net"
            }
        }
    }

    /// User-facing explanation when an explicit virtio-net request must be rejected.
    pub const fn unsupported_message(self) -> &'static str {
        match self {
            Self::PolicyRequiresTsi => {
                "allow-cidr/allow-host policies are not supported by the current virtio-net implementation"
            }
        }
    }
}

/// Network launch decision for a VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaunchNetworkPlan {
    /// Selected backend.
    pub backend: EffectiveNetworkBackend,
    /// Downgrade reason when a requested backend cannot be honored.
    pub fallback_reason: Option<NetworkFallbackReason>,
}

impl LaunchNetworkPlan {
    /// Whether the launch should attach any network backend at all.
    pub const fn has_network(self) -> bool {
        !matches!(self.backend, EffectiveNetworkBackend::None)
    }
}

/// Compute the effective launch backend from user intent and current feature support.
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
    let has_policy = has_cidr_policy || has_dns_filter;
    let wants_network = resources.network || has_ports || has_policy;

    if !wants_network {
        return LaunchNetworkPlan {
            backend: EffectiveNetworkBackend::None,
            fallback_reason: None,
        };
    }

    match resources.network_backend.unwrap_or(NetworkBackend::Tsi) {
        NetworkBackend::Tsi => LaunchNetworkPlan {
            backend: EffectiveNetworkBackend::Tsi,
            fallback_reason: None,
        },
        NetworkBackend::VirtioNet if has_policy => LaunchNetworkPlan {
            backend: EffectiveNetworkBackend::Tsi,
            fallback_reason: Some(NetworkFallbackReason::PolicyRequiresTsi),
        },
        NetworkBackend::VirtioNet => LaunchNetworkPlan {
            backend: EffectiveNetworkBackend::VirtioNet,
            fallback_reason: None,
        },
    }
}

/// Reject explicit virtio-net requests that the current branch cannot honor.
pub fn validate_requested_network_backend(
    resources: &VmResources,
    dns_filter_hosts: Option<&[String]>,
    port_count: usize,
) -> crate::Result<()> {
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

    let plan = plan_launch_network(resources, dns_filter_hosts, port_count);
    if plan.backend != EffectiveNetworkBackend::VirtioNet {
        let reason = plan
            .fallback_reason
            .unwrap_or(NetworkFallbackReason::PolicyRequiresTsi);
        return Err(crate::Error::config(
            "--net-backend",
            reason.unsupported_message(),
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
        assert_eq!(plan.fallback_reason, None);
    }

    #[test]
    fn test_ports_work_with_virtio() {
        let mut resources = resources();
        resources.network = true;
        resources.network_backend = Some(NetworkBackend::VirtioNet);
        let plan = plan_launch_network(&resources, None, 1);
        assert_eq!(plan.backend, EffectiveNetworkBackend::VirtioNet);
        assert_eq!(plan.fallback_reason, None);
    }

    #[test]
    fn test_policy_forces_tsi() {
        let mut resources = resources();
        resources.network = true;
        resources.network_backend = Some(NetworkBackend::VirtioNet);
        resources.allowed_cidrs = Some(vec!["1.1.1.1/32".into()]);
        let plan = plan_launch_network(&resources, None, 0);
        assert_eq!(plan.backend, EffectiveNetworkBackend::Tsi);
        assert_eq!(
            plan.fallback_reason,
            Some(NetworkFallbackReason::PolicyRequiresTsi)
        );
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
    fn test_validate_policy_rejected_for_virtio() {
        let mut resources = resources();
        resources.network = true;
        resources.network_backend = Some(NetworkBackend::VirtioNet);
        resources.allowed_cidrs = Some(vec!["1.1.1.1/32".into()]);
        let err = validate_requested_network_backend(&resources, None, 0).unwrap_err();
        assert!(err
            .to_string()
            .contains("allow-cidr/allow-host policies are not supported"));
    }
}
