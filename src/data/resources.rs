/// Default agent VM virtual CPU count.
/// vCPU threads sleep in the hypervisor when idle, so over-provisioning
/// is low-cost — the host OS time-slices them like any other threads.
pub const DEFAULT_MICROVM_CPU_COUNT: u8 = 4;
/// Default agent VM memory in MiB.
/// Virtio balloon with free page reporting means this is a ceiling, not a
/// reservation — the host only consumes what the guest actually uses.
pub const DEFAULT_MICROVM_MEMORY_MIB: u32 = 8192;

/// Default VRAM (host shared memory region) exposed to the guest
/// virtio-gpu device, in MiB.
///
/// This sizes the shared buffer libkrun reserves for GPU transfers
/// (textures, staging, Venus/Vulkan descriptor pools). 4 GiB is large
/// enough for typical Vulkan workloads including headless browsers and
/// modest compute, without being so big that low-memory hosts commit
/// most of their RAM when GPU is enabled. Override with
/// `--gpu-vram <MiB>` or Smolfile `gpu_vram = <MiB>`.
pub const DEFAULT_GPU_VRAM_MIB: u32 = 4096;

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
    /// Enable GPU acceleration (virtio-gpu with Venus/Vulkan).
    #[serde(default)]
    pub gpu: bool,
    /// GPU shared-memory region size in MiB (ignored if `gpu` is false).
    /// `None` → use `DEFAULT_GPU_VRAM_MIB`.
    #[serde(default)]
    pub gpu_vram_mib: Option<u32>,
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
            gpu: false,
            gpu_vram_mib: None,
            storage_gib: None,
            overlay_gib: None,
            allowed_cidrs: None,
        }
    }
}

impl VmResources {
    /// Effective GPU VRAM in MiB, applying the default when unset.
    ///
    /// Invariant: the returned value is always `>= 1`. `gpu_vram_mib`
    /// is validated at ingress (`validate_gpu_vram_mib`) so it cannot
    /// contain `Some(0)`; the default is 4 GiB. A `None` here means
    /// "caller didn't specify," and we fill it with the default.
    pub fn effective_gpu_vram_mib(&self) -> u32 {
        self.gpu_vram_mib.unwrap_or(DEFAULT_GPU_VRAM_MIB)
    }
}

/// Validate a user-supplied GPU VRAM value. `Some(0)` is nonsensical
/// — virtio-gpu's shared memory region can't be zero-sized without
/// the guest driver crashing on first use. We reject at ingress
/// (CLI, Smolfile, and direct DB writes) rather than passing 0 down
/// to libkrun and hoping for a clean failure.
///
/// `None` is fine (means "use default"). Positive values are
/// accepted without an upper bound; libkrun errors at allocation
/// time if the host can't back the region.
///
/// Returns the value unchanged on success so callers can chain:
/// `params.gpu_vram_mib = validate_gpu_vram_mib(user_input)?;`
pub fn validate_gpu_vram_mib(v: Option<u32>) -> Result<Option<u32>, &'static str> {
    match v {
        Some(0) => Err(
            "--gpu-vram must be a positive number of MiB; \
             use a value >= 1 or omit the flag to get the default",
        ),
        other => Ok(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_gpu_vram_defaults_when_unset() {
        let r = VmResources::default();
        assert_eq!(r.effective_gpu_vram_mib(), DEFAULT_GPU_VRAM_MIB);
    }

    #[test]
    fn effective_gpu_vram_honors_override() {
        let r = VmResources {
            gpu_vram_mib: Some(8192),
            ..Default::default()
        };
        assert_eq!(r.effective_gpu_vram_mib(), 8192);
    }

    #[test]
    fn vm_resources_serde_roundtrip_preserves_vram() {
        let r = VmResources {
            gpu: true,
            gpu_vram_mib: Some(2048),
            ..Default::default()
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: VmResources = serde_json::from_str(&json).unwrap();
        assert_eq!(back.gpu_vram_mib, Some(2048));
    }

    #[test]
    fn validate_gpu_vram_mib_rejects_zero() {
        assert!(validate_gpu_vram_mib(Some(0)).is_err());
    }

    #[test]
    fn validate_gpu_vram_mib_accepts_positive() {
        assert_eq!(validate_gpu_vram_mib(Some(1)).unwrap(), Some(1));
        assert_eq!(validate_gpu_vram_mib(Some(4096)).unwrap(), Some(4096));
        // No upper bound — libkrun errors at allocation time if the
        // host can't back the region.
        assert_eq!(
            validate_gpu_vram_mib(Some(u32::MAX)).unwrap(),
            Some(u32::MAX)
        );
    }

    #[test]
    fn validate_gpu_vram_mib_accepts_none() {
        assert_eq!(validate_gpu_vram_mib(None).unwrap(), None);
    }
}
