/// Default agent VM virtual CPU count.
pub const DEFAULT_MICROVM_CPU_COUNT: u8 = 1;
/// Default agent VM memory in MiB.
pub const DEFAULT_MICROVM_MEMORY_MIB: u32 = 512;

/// Resources available to a micro vm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VmResources {
    /// Number of vCPUs.
    pub cpus: u8,
    /// Memory in MiB.
    pub memory_mib: u32,
    /// Enable outbound network access (TSI).
    pub network: bool,
    /// Storage disk size in GiB (None = default 20 GiB).
    pub storage_gib: Option<u64>,
    /// Overlay disk size in GiB (None = default 10 GiB).
    pub overlay_gib: Option<u64>,
}

impl Default for VmResources {
    fn default() -> Self {
        Self {
            cpus: DEFAULT_MICROVM_CPU_COUNT,
            memory_mib: DEFAULT_MICROVM_MEMORY_MIB,
            network: false,
            storage_gib: None,
            overlay_gib: None,
        }
    }
}
