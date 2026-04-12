/// Default agent VM virtual CPU count.
/// vCPU threads sleep in the hypervisor when idle, so over-provisioning
/// is low-cost — the host OS time-slices them like any other threads.
pub const DEFAULT_MICROVM_CPU_COUNT: u8 = 4;
/// Default agent VM memory in MiB.
/// Virtio balloon with free page reporting means this is a ceiling, not a
/// reservation — the host only consumes what the guest actually uses.
pub const DEFAULT_MICROVM_MEMORY_MIB: u32 = 8192;

/// Resources available to a micro vm.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VmResources {
    /// Number of vCPUs.
    pub cpus: u8,
    /// Memory in MiB.
    pub memory_mib: u32,
    /// Enable outbound network access (TSI).
    pub network: bool,
    /// Enable GPU acceleration (virtio-gpu with Venus/Vulkan).
    #[serde(default)]
    pub gpu: bool,
    /// Storage disk size in GiB (None = default 20 GiB).
    pub storage_gib: Option<u64>,
    /// Overlay disk size in GiB (None = default 10 GiB).
    pub overlay_gib: Option<u64>,
    /// Allowed egress CIDR ranges. None = unrestricted, Some([]) = deny all.
    #[serde(default)]
    pub allowed_cidrs: Option<Vec<String>>,
}

impl Default for VmResources {
    fn default() -> Self {
        Self {
            cpus: DEFAULT_MICROVM_CPU_COUNT,
            memory_mib: DEFAULT_MICROVM_MEMORY_MIB,
            network: false,
            gpu: false,
            storage_gib: None,
            overlay_gib: None,
            allowed_cidrs: None,
        }
    }
}
