use crate::data::resources::VmResources;
use crate::network::backend::NetworkBackend;
use std::sync::atomic::{AtomicU32, Ordering};

static GUEST_HOST_SERVICE: AtomicU32 = AtomicU32::new(0);

/// Enable one smolvm-owned gateway service for VMs launched by this server.
pub fn configure_guest_host_service(
    guest_port: u16,
    host_port: u16,
) -> std::result::Result<(), String> {
    if guest_port == 0 || host_port == 0 {
        return Err("guest host service ports must be between 1 and 65535".into());
    }
    let mapping = (u32::from(guest_port) << 16) | u32::from(host_port);
    match GUEST_HOST_SERVICE.compare_exchange(0, mapping, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => Ok(()),
        Err(current) if current == mapping => Ok(()),
        Err(_) => Err("guest host service is already configured differently".into()),
    }
}

fn guest_host_service_configured() -> bool {
    GUEST_HOST_SERVICE.load(Ordering::Acquire) != 0
        || std::env::var_os(crate::api::guest_rollout::GUEST_HOST_SERVICE_ENV).is_some()
}

/// Resolve the internal, smolvm-owned gateway service enabled by `serve`.
pub fn guest_host_service(
) -> std::result::Result<Option<smolvm_network::GatewayHostService>, String> {
    let configured = GUEST_HOST_SERVICE.load(Ordering::Acquire);
    if configured != 0 {
        return Ok(Some(smolvm_network::GatewayHostService {
            guest_port: (configured >> 16) as u16,
            host_port: configured as u16,
        }));
    }
    let Some(value) = std::env::var_os(crate::api::guest_rollout::GUEST_HOST_SERVICE_ENV) else {
        return Ok(None);
    };
    let value = value
        .to_str()
        .ok_or_else(|| "guest host service mapping is not valid UTF-8".to_string())?;
    let (guest_port, host_port) = value
        .split_once(':')
        .ok_or_else(|| "guest host service mapping must be GUEST_PORT:HOST_PORT".to_string())?;
    let parse_port = |port: &str| {
        port.parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(|| "guest host service ports must be between 1 and 65535".to_string())
    };
    Ok(Some(smolvm_network::GatewayHostService {
        guest_port: parse_port(guest_port)?,
        host_port: parse_port(host_port)?,
    }))
}

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
    let has_host_service = guest_host_service_configured();
    let has_fabric = resources.network_name.is_some();
    let wants_network =
        resources.network || has_ports || has_cidr_policy || has_dns_filter || has_fabric;

    if !wants_network {
        return LaunchNetworkPlan {
            backend: EffectiveNetworkBackend::None,
        };
    }

    // Published ports need the inbound path, which only virtio-net provides.
    // When the caller didn't pick a backend explicitly, default to virtio-net
    // IFF there are ports (TSI otherwise — it's lighter for outbound-only VMs).
    //
    // Fleet/multi-tenant mode (SMOLVM_PUBLISH_ADDR set) additionally routes ALL
    // machines through virtio-net, so the egress hard-floor (the smolvm-network
    // `EgressPolicy` that denies metadata/internal/loopback) applies to no-ports
    // machines too. TSI's egress filter lives in libkrun and may not carry the
    // floor, so a default outbound-only tenant VM must not silently fall to TSI
    // on a fleet node. Outside fleet mode, no-ports VMs keep the lighter default.
    //
    // An explicit egress policy (--allow-cidr/--allow-host/--outbound-localhost-only)
    // must also use virtio-net: its egress allow-list is enforced reliably by the
    // host-side smolvm-network stack, whereas TSI's in-libkrun filter does not
    // enforce it (verified: a non-allowed IP stays reachable under TSI). Falling
    // to TSI here would make the egress flags a silent no-op — a security hole —
    // so a policy forces virtio-net unless the caller explicitly picked a backend.
    //
    // A configured guest host-service (the rollout ingress `serve` always sets
    // up) likewise forces virtio-net: the guest reaches it through the virtio
    // gateway's port mapping, which TSI doesn't provide. Net effect: EVERY
    // networked machine under `serve` defaults to virtio-net — keep the API
    // schema docs on `networkBackend` (src/api/types.rs) in sync with this.
    let fleet_mode = std::env::var_os("SMOLVM_PUBLISH_ADDR").is_some();
    // A named inter-VM network is fabric routing in the host-side stack, which
    // only virtio-net has — it forces the default the same way ports do.
    let backend = resources.network_backend.unwrap_or(
        if has_ports
            || fleet_mode
            || has_cidr_policy
            || has_dns_filter
            || has_host_service
            || has_fabric
        {
            NetworkBackend::VirtioNet
        } else {
            NetworkBackend::Tsi
        },
    );
    // virtio-net works on Windows too: the host-side smolvm-network gateway is
    // cross-platform and libkrun's net device bridges over an AF_UNIX path
    // (Windows 10 1809+ has native AF_UNIX). See launcher's VirtioNet arm.
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
    // An egress policy is only enforced under virtio-net; TSI would silently let
    // it through.
    let has_egress_policy = resources
        .allowed_cidrs
        .as_ref()
        .is_some_and(|c| !c.is_empty())
        || dns_filter_hosts.is_some_and(|h| !h.is_empty());
    let has_host_service = guest_host_service_configured();

    // Mirror plan_launch_network's default: unset backend + (ports OR egress
    // policy) ⇒ virtio-net. So only an EXPLICIT `--net-backend tsi` alongside
    // ports/egress is a misconfig.
    let backend = resources.network_backend.unwrap_or(
        if port_count > 0
            || has_egress_policy
            || has_host_service
            || resources.network_name.is_some()
        {
            NetworkBackend::VirtioNet
        } else {
            NetworkBackend::Tsi
        },
    );

    // Published ports require the inbound path that only virtio-net has. With
    // the default above this only fires when the caller EXPLICITLY forced TSI.
    if port_count > 0 && backend != NetworkBackend::VirtioNet {
        return Err(crate::Error::config(
            "ports",
            "published ports require the virtio-net backend (TSI is outbound-only); \
             remove --net-backend tsi or set it to virtio-net",
        ));
    }

    // A named network's fabric lives in the virtio-net stack; explicit TSI
    // alongside --network would silently isolate the member.
    if resources.network_name.is_some() && backend != NetworkBackend::VirtioNet {
        return Err(crate::Error::config(
            "network",
            "--network requires the virtio-net backend; remove --net-backend tsi or set it to virtio-net",
        ));
    }

    // Same for an egress policy — fires only on EXPLICIT TSI + policy.
    if has_egress_policy && backend != NetworkBackend::VirtioNet {
        return Err(crate::Error::config(
            "egress",
            "egress policy (--allow-cidr/--allow-host/--outbound-localhost-only) requires the \
             virtio-net backend; TSI does not enforce it. Remove --net-backend tsi or set it to virtio-net",
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
    fn test_cidr_policy_default_selects_virtio() {
        // No explicit backend + a CIDR egress policy must default to virtio-net
        // (TSI doesn't enforce egress, so defaulting there is a silent no-op).
        let mut resources = resources();
        resources.network = true;
        resources.allowed_cidrs = Some(vec!["1.1.1.1/32".into()]);
        let plan = plan_launch_network(&resources, None, 0);
        assert_eq!(plan.backend, EffectiveNetworkBackend::VirtioNet);
    }

    #[test]
    fn test_dns_filter_default_selects_virtio() {
        let mut resources = resources();
        resources.network = true;
        let hosts = ["example.com".to_string()];
        let plan = plan_launch_network(&resources, Some(&hosts), 0);
        assert_eq!(plan.backend, EffectiveNetworkBackend::VirtioNet);
    }

    #[test]
    fn test_validate_egress_explicit_tsi_rejected() {
        let mut resources = resources();
        resources.network = true;
        resources.network_backend = Some(NetworkBackend::Tsi);
        resources.allowed_cidrs = Some(vec!["1.1.1.1/32".into()]);
        assert!(validate_requested_network_backend(&resources, None, 0).is_err());
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
