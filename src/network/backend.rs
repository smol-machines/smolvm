use clap::ValueEnum;

/// virtio-net checksum offload feature bit.
pub const NET_FEATURE_CSUM: u32 = 1 << 0;
/// virtio-net guest checksum offload feature bit.
pub const NET_FEATURE_GUEST_CSUM: u32 = 1 << 1;
/// virtio-net guest TCP segmentation offload for IPv4.
pub const NET_FEATURE_GUEST_TSO4: u32 = 1 << 7;
/// virtio-net guest UDP fragmentation offload.
pub const NET_FEATURE_GUEST_UFO: u32 = 1 << 10;
/// virtio-net host TCP segmentation offload for IPv4.
pub const NET_FEATURE_HOST_TSO4: u32 = 1 << 11;
/// virtio-net host UDP fragmentation offload.
pub const NET_FEATURE_HOST_UFO: u32 = 1 << 14;
/// libkrun's compatibility feature set for unixstream-backed virtio-net.
pub const COMPAT_NET_FEATURES: u32 = NET_FEATURE_CSUM
    | NET_FEATURE_GUEST_CSUM
    | NET_FEATURE_GUEST_TSO4
    | NET_FEATURE_GUEST_UFO
    | NET_FEATURE_HOST_TSO4
    | NET_FEATURE_HOST_UFO;

/// Network backend override for machine launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkBackend {
    /// Use libkrun TSI networking.
    #[value(name = "tsi")]
    Tsi,
    /// Use virtio-net with the host-side smolvm network stack.
    #[serde(rename = "virtio")]
    #[value(name = "virtio")]
    VirtioNet,
}

impl NetworkBackend {
    /// Stable CLI/storage label for the backend.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tsi => "tsi",
            Self::VirtioNet => "virtio",
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
