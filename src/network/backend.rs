use clap::ValueEnum;

/// Feature set advertised to libkrun for unixstream-backed virtio-net.
///
/// The current smoltcp-backed MVP expects ordinary packets from the guest.
/// Leave checksum and segmentation offloads disabled until the host path
/// explicitly handles those packet shapes.
pub const COMPAT_NET_FEATURES: u32 = 0;
/// TSI feature bit that enables INET socket hijacking.
pub const TSI_FEATURE_HIJACK_INET: u32 = 1 << 0;

/// Network backend override for machine launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, ValueEnum)]
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
