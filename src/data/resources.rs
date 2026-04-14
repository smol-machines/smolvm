/// Default agent VM virtual CPU count.
/// vCPU threads sleep in the hypervisor when idle, so over-provisioning
/// is low-cost — the host OS time-slices them like any other threads.
pub const DEFAULT_MICROVM_CPU_COUNT: u8 = 4;
/// Default agent VM memory in MiB.
/// Virtio balloon with free page reporting means this is a ceiling, not a
/// reservation — the host only consumes what the guest actually uses.
pub const DEFAULT_MICROVM_MEMORY_MIB: u32 = 8192;

use crate::network::NetworkBackend;

/// Resources available to a micro vm.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VmResources {
    /// Number of vCPUs.
    pub cpus: u8,
    /// Memory in MiB.
    pub memory_mib: u32,
    /// Enable outbound network access (TSI).
    pub network: bool,
    /// Preferred network backend override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_backend: Option<NetworkBackend>,
    /// Storage disk size in GiB (None = default 20 GiB).
    pub storage_gib: Option<u64>,
    /// Overlay disk size in GiB (None = default 10 GiB).
    pub overlay_gib: Option<u64>,
    /// Allowed egress CIDR ranges. None = unrestricted, Some([]) = deny all.
    #[serde(default)]
    pub allowed_cidrs: Option<Vec<String>>,
}

/// Minimum memory required for the VM to boot (kernel + agent).
const MIN_MEMORY_MIB: u32 = 64;

/// Maximum vCPUs supported by the hypervisor (Hypervisor.framework on macOS).
/// Requests above this are silently capped by libkrun.
const MAX_EFFECTIVE_CPUS: u8 = 16;

impl VmResources {
    /// Validate resource values before starting a VM. Returns an error with
    /// a clear message for values that would cause an opaque hypervisor failure.
    pub fn validate(&self) -> Result<(), crate::Error> {
        if self.cpus == 0 {
            return Err(crate::Error::config(
                "validate resources",
                "CPU count must be at least 1",
            ));
        }
        if self.cpus > MAX_EFFECTIVE_CPUS {
            eprintln!(
                "warning: requested {} vCPUs but the hypervisor supports at most {}; \
                 the VM will run with {} vCPUs",
                self.cpus, MAX_EFFECTIVE_CPUS, MAX_EFFECTIVE_CPUS
            );
        }
        if self.memory_mib < MIN_MEMORY_MIB {
            return Err(crate::Error::config(
                "validate resources",
                format!(
                    "memory must be at least {} MiB (got {} MiB)",
                    MIN_MEMORY_MIB, self.memory_mib
                ),
            ));
        }
        Ok(())
    }
}

impl Default for VmResources {
    fn default() -> Self {
        Self {
            cpus: DEFAULT_MICROVM_CPU_COUNT,
            memory_mib: DEFAULT_MICROVM_MEMORY_MIB,
            network: false,
            network_backend: None,
            storage_gib: None,
            overlay_gib: None,
            allowed_cidrs: None,
        }
    }
}
