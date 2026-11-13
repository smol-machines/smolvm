use clap::ValueEnum;

/// `VIRTIO_NET_F_GUEST_CSUM`: the guest may receive packets with checksums it
/// does not have to verify (the host still sends full checksums).
const NET_FEATURE_GUEST_CSUM: u32 = 1 << 1;
/// `VIRTIO_NET_F_GUEST_TSO4` / `_TSO6`: the guest may receive segments larger
/// than one packet.
const NET_FEATURE_GUEST_TSO4: u32 = 1 << 7;
const NET_FEATURE_GUEST_TSO6: u32 = 1 << 8;

/// Feature set advertised to libkrun for unixstream-backed virtio-net.
///
/// Only the receive-side features, and only for their side effect: with them
/// the guest's virtio-net driver posts 64 KB receive buffers instead of
/// 1500-byte ones, so it can take the large frames of the gateway link
/// ([`smolvm_protocol::guest_env::GATEWAY_LINK_MTU`]). The host never sends a
/// GSO packet (libkrun's header carries no GSO type) and offers no transmit
/// offload, so the guest still hands the host ordinary, fully checksummed
/// packets, which is all the host stack understands.
pub const COMPAT_NET_FEATURES: u32 =
    NET_FEATURE_GUEST_CSUM | NET_FEATURE_GUEST_TSO4 | NET_FEATURE_GUEST_TSO6;
/// TSI feature bit that enables INET socket hijacking.
pub const TSI_FEATURE_HIJACK_INET: u32 = 1 << 0;

/// Network backend override for machine launch.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    ValueEnum,
    utoipa::ToSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkBackend {
    /// Use libkrun TSI networking.
    #[value(name = "tsi")]
    Tsi,
    /// Use virtio-net with the host-side smolvm network stack.
    #[value(name = "virtio-net")]
    VirtioNet,
}

impl NetworkBackend {
    /// Stable CLI/storage label for the backend.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tsi => "tsi",
            Self::VirtioNet => "virtio-net",
        }
    }

    /// Human-readable backend label for logs.
    pub const fn log_label(self) -> &'static str {
        match self {
            Self::Tsi => "tsi",
            Self::VirtioNet => "virtio-net",
        }
    }
}

impl std::fmt::Display for NetworkBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::NetworkBackend;

    #[test]
    fn virtio_net_serializes_to_canonical_name() {
        let value = serde_json::to_string(&NetworkBackend::VirtioNet).unwrap();
        assert_eq!(value, "\"virtio-net\"");
    }

    #[test]
    fn legacy_virtio_name_is_rejected() {
        let value = serde_json::from_str::<NetworkBackend>("\"virtio\"");
        assert!(value.is_err());
    }
}
