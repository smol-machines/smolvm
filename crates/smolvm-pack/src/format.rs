//! `.smolmachine` binary format specification.
//!
//! # Overview
//!
//! A `.smolmachine` is a portable, self-contained microVM artifact. It bundles
//! everything needed to run a workload: OCI image layers, the agent rootfs,
//! runtime libraries (libkrun), and a manifest describing the configuration.
//!
//! # File Layout
//!
//! A `.smolmachine` file is a zstd-compressed tar archive with a JSON manifest
//! appended as a footer. The manifest is also stored inside the OCI registry
//! as the config blob when pushed.
//!
//! ```text
//! +---------------------------+
//! | Assets Blob (zstd tar)    |  30-150 MB
//! |  - agent-rootfs.tar       |  Guest init system
//! |  - layers/*.tar           |  OCI image layers
//! |  - lib/libkrun.*          |  Runtime libraries (platform-specific)
//! |  - storage.ext4 (opt)     |  Pre-formatted disk template
//! |  - overlay.raw (opt)      |  VM snapshot (VM mode only)
//! +---------------------------+
//! | Manifest (JSON)           |  ~2 KB (PackManifest)
//! +---------------------------+
//! | Footer (64 bytes)         |
//! |  - magic: "SMOLPACK"      |
//! |  - version: 1             |
//! |  - offsets + sizes         |
//! |  - CRC32 checksum         |
//! +---------------------------+
//! ```
//!
//! # OCI Registry Representation
//!
//! When pushed to an OCI registry, a `.smolmachine` is stored as:
//! - **Config blob**: `PackManifest` JSON (`application/vnd.smolmachines.machine.config.v1+json`)
//! - **Layer blob**: The full `.smolmachine` file (`application/vnd.smolmachines.smolmachine.v1`)
//! - **Manifest**: Standard OCI Image Manifest referencing both blobs
//!
//! # Execution Modes
//!
//! - **Container mode** (default): OCI image layers are unpacked and run via crun.
//! - **VM mode**: An overlay disk snapshot is restored directly into the VM.

use serde::{Deserialize, Serialize};

use crate::{PackError, Result};

/// Magic bytes identifying a packed smolvm binary.
pub const MAGIC: &[u8; 8] = b"SMOLPACK";

/// Magic bytes for embedded section header.
pub const SECTION_MAGIC: &[u8; 8] = b"SMOLSECT";

/// Magic bytes for libs footer appended to the stub binary.
pub const LIBS_MAGIC: &[u8; 8] = b"SMOLLIBS";

/// Current format version — the version stamped into newly written packs.
pub const FORMAT_VERSION: u32 = 1;

/// Format versions this build can READ. New packs are always WRITTEN at
/// `FORMAT_VERSION`, but older `.smolmachine` artifacts stay readable: the
/// on-disk layout (footer, manifest, assets blob) is identical across these
/// versions — only the version number ever differed. It was reset 3→1 in a
/// format refactor, which orphaned pre-reset packs behind a strict
/// `version == FORMAT_VERSION` check. Accepting the older numbers keeps those
/// artifacts runnable instead of failing with "unsupported version: 3".
pub const SUPPORTED_READ_VERSIONS: &[u32] = &[1, 2, 3];

/// Whether a pack stamped with `version` can be read by this build.
pub fn is_supported_read_version(version: u32) -> bool {
    SUPPORTED_READ_VERSIONS.contains(&version)
}

/// Extension for sidecar assets file.
pub const SIDECAR_EXTENSION: &str = ".smolmachine";

/// Footer size in bytes (fixed).
pub const FOOTER_SIZE: usize = 64;

/// Embedded section header size (fixed).
pub const SECTION_HEADER_SIZE: usize = 32;

/// Libs footer size in bytes (fixed).
pub const LIBS_FOOTER_SIZE: usize = 32;

/// Header for data embedded in the __SMOLVM,__smolvm Mach-O section.
///
/// This format is used for macOS single-file binaries where assets are
/// stored inside the executable's Mach-O structure, allowing proper code signing.
///
/// Layout (32 bytes total):
/// ```text
/// Offset  Size  Field
/// 0       8     magic ("SMOLSECT")
/// 8       4     version (u32 LE)
/// 12      4     manifest_size (u32 LE)
/// 16      8     assets_size (u64 LE)
/// 24      4     checksum (u32 LE)
/// 28      4     reserved (zeroes)
/// ```
///
/// Following the header:
/// - Manifest JSON (manifest_size bytes)
/// - Compressed assets (assets_size bytes)
#[derive(Debug, Clone, Copy)]
pub struct SectionHeader {
    /// Size of manifest JSON in bytes.
    pub manifest_size: u32,
    /// Size of compressed assets in bytes.
    pub assets_size: u64,
    /// CRC32 checksum of manifest + assets.
    pub checksum: u32,
}

impl SectionHeader {
    /// Serialize header to bytes.
    pub fn to_bytes(&self) -> [u8; SECTION_HEADER_SIZE] {
        let mut buf = [0u8; SECTION_HEADER_SIZE];

        // Magic
        buf[0..8].copy_from_slice(SECTION_MAGIC);

        // Version
        buf[8..12].copy_from_slice(&FORMAT_VERSION.to_le_bytes());

        // Manifest size
        buf[12..16].copy_from_slice(&self.manifest_size.to_le_bytes());

        // Assets size
        buf[16..24].copy_from_slice(&self.assets_size.to_le_bytes());

        // Checksum
        buf[24..28].copy_from_slice(&self.checksum.to_le_bytes());

        // Reserved (already zeroed)

        buf
    }

    /// Deserialize header from bytes.
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < SECTION_HEADER_SIZE {
            return Err(PackError::InvalidMagic);
        }

        // Validate magic
        if &buf[0..8] != SECTION_MAGIC {
            return Err(PackError::InvalidMagic);
        }

        // Check version
        let version = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        if !is_supported_read_version(version) {
            return Err(PackError::UnsupportedVersion(version));
        }

        Ok(Self {
            manifest_size: u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]),
            assets_size: u64::from_le_bytes([
                buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23],
            ]),
            checksum: u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]]),
        })
    }
}

/// Footer appended to the stub binary to locate embedded runtime libraries.
///
/// The stub reads its own last 32 bytes to find the compressed libs bundle,
/// extracts them to a cache directory, and dlopen's libkrun from there.
/// This keeps the .smolmachine sidecar cross-platform (no platform-specific libs).
///
/// Layout (32 bytes total):
/// ```text
/// Offset  Size  Field
/// 0       8     magic ("SMOLLIBS")
/// 8       4     version (u32 LE)
/// 12      8     libs_offset (u64 LE) - offset to compressed libs blob
/// 20      8     libs_size (u64 LE) - size of compressed libs blob
/// 28      4     reserved (zeroes)
/// ```
#[derive(Debug, Clone, Copy)]
pub struct LibsFooter {
    /// Offset from start of file to the compressed libs blob.
    pub libs_offset: u64,
    /// Size of the compressed libs blob.
    pub libs_size: u64,
}

impl LibsFooter {
    /// Serialize footer to bytes.
    pub fn to_bytes(&self) -> [u8; LIBS_FOOTER_SIZE] {
        let mut buf = [0u8; LIBS_FOOTER_SIZE];
        buf[0..8].copy_from_slice(LIBS_MAGIC);
        buf[8..12].copy_from_slice(&1u32.to_le_bytes()); // version 1
        buf[12..20].copy_from_slice(&self.libs_offset.to_le_bytes());
        buf[20..28].copy_from_slice(&self.libs_size.to_le_bytes());
        // 28..32 reserved (zeroed)
        buf
    }

    /// Deserialize footer from bytes.
    pub fn from_bytes(buf: &[u8; LIBS_FOOTER_SIZE]) -> Result<Self> {
        if &buf[0..8] != LIBS_MAGIC {
            return Err(PackError::InvalidMagic);
        }
        let version = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        if version != 1 {
            return Err(PackError::UnsupportedVersion(version));
        }
        Ok(Self {
            libs_offset: u64::from_le_bytes([
                buf[12], buf[13], buf[14], buf[15], buf[16], buf[17], buf[18], buf[19],
            ]),
            libs_size: u64::from_le_bytes([
                buf[20], buf[21], buf[22], buf[23], buf[24], buf[25], buf[26], buf[27],
            ]),
        })
    }
}

/// Fixed-size footer at the end of a packed binary.
///
/// Layout (64 bytes total):
/// ```text
/// Offset  Size  Field
/// 0       8     magic ("SMOLPACK")
/// 8       4     version (u32 LE)
/// 12      8     stub_size (u64 LE) - size of stub executable
/// 20      8     assets_offset (u64 LE) - offset to compressed assets
/// 28      8     assets_size (u64 LE) - size of compressed assets
/// 36      8     manifest_offset (u64 LE) - offset to manifest JSON
/// 44      8     manifest_size (u64 LE) - size of manifest JSON
/// 52      4     checksum (u32 LE) - CRC32 of assets + manifest
/// 56      8     reserved (zeroes)
/// ```
#[derive(Debug, Clone, Copy)]
pub struct PackFooter {
    /// Size of the stub executable.
    pub stub_size: u64,
    /// Offset to compressed assets blob.
    pub assets_offset: u64,
    /// Size of compressed assets blob.
    pub assets_size: u64,
    /// Offset to manifest JSON.
    pub manifest_offset: u64,
    /// Size of manifest JSON.
    pub manifest_size: u64,
    /// CRC32 checksum of assets + manifest.
    pub checksum: u32,
}

impl PackFooter {
    /// Serialize footer to bytes.
    pub fn to_bytes(&self) -> [u8; FOOTER_SIZE] {
        let mut buf = [0u8; FOOTER_SIZE];

        // Magic
        buf[0..8].copy_from_slice(MAGIC);

        // Version
        buf[8..12].copy_from_slice(&FORMAT_VERSION.to_le_bytes());

        // Stub size
        buf[12..20].copy_from_slice(&self.stub_size.to_le_bytes());

        // Assets offset and size
        buf[20..28].copy_from_slice(&self.assets_offset.to_le_bytes());
        buf[28..36].copy_from_slice(&self.assets_size.to_le_bytes());

        // Manifest offset and size
        buf[36..44].copy_from_slice(&self.manifest_offset.to_le_bytes());
        buf[44..52].copy_from_slice(&self.manifest_size.to_le_bytes());

        // Checksum
        buf[52..56].copy_from_slice(&self.checksum.to_le_bytes());

        // Reserved (already zeroed)

        buf
    }

    /// Deserialize footer from bytes.
    pub fn from_bytes(buf: &[u8; FOOTER_SIZE]) -> Result<Self> {
        // Validate magic
        if &buf[0..8] != MAGIC {
            return Err(PackError::InvalidMagic);
        }

        // Check version
        let version = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        if !is_supported_read_version(version) {
            return Err(PackError::UnsupportedVersion(version));
        }

        Ok(Self {
            stub_size: u64::from_le_bytes([
                buf[12], buf[13], buf[14], buf[15], buf[16], buf[17], buf[18], buf[19],
            ]),
            assets_offset: u64::from_le_bytes([
                buf[20], buf[21], buf[22], buf[23], buf[24], buf[25], buf[26], buf[27],
            ]),
            assets_size: u64::from_le_bytes([
                buf[28], buf[29], buf[30], buf[31], buf[32], buf[33], buf[34], buf[35],
            ]),
            manifest_offset: u64::from_le_bytes([
                buf[36], buf[37], buf[38], buf[39], buf[40], buf[41], buf[42], buf[43],
            ]),
            manifest_size: u64::from_le_bytes([
                buf[44], buf[45], buf[46], buf[47], buf[48], buf[49], buf[50], buf[51],
            ]),
            checksum: u32::from_le_bytes([buf[52], buf[53], buf[54], buf[55]]),
        })
    }
}

/// Execution mode for packed binaries.
///
/// Determines how commands are executed at runtime:
/// - `Container`: commands run inside a crun container (OCI layers)
/// - `Vm`: commands run directly in the VM rootfs (overlay disk)
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PackMode {
    /// Container mode: OCI image layers + crun container execution.
    #[default]
    Container,
    /// VM mode: overlay disk + direct VM execution.
    Vm,
}

/// One integrity-protected file belonging to a portable live checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckpointAsset {
    /// Relative path within the artifact assets.
    pub path: String,
    /// Uncompressed byte length.
    pub size: u64,
    /// Lowercase SHA-256 digest of the file contents. Empty for sparse memory
    /// or block files whose integrity is provided by the pack container.
    pub sha256: String,
}

/// One file in a checkpoint's portable block-image chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckpointDiskFile {
    /// Integrity metadata and artifact-relative source path.
    pub asset: CheckpointAsset,
    /// Safe filename installed in the machine data directory.
    pub target: String,
    /// `raw` or `qcow2`.
    pub format: String,
}

/// An exact block-image chain captured for one virtual disk.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckpointDisk {
    /// Stable disk role: `storage` or `overlay`.
    pub role: String,
    /// Ordered top-to-base chain. The first file is the disk attached to the VM.
    pub files: Vec<CheckpointDiskFile>,
}

/// Container workload identity needed after a live checkpoint is restored.
///
/// The running container itself is present in guest RAM. These fields are for
/// host-side routing (`machine exec`) and for launching the same persistent
/// workload exactly once after a later ordinary stop/start cycle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckpointWorkload {
    /// OCI image identity used by the persistent workload.
    pub image: String,
    /// Container user resolved from the image or supplied by the caller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Persistent overlay identifier containing the restored container state.
    ///
    /// A checkpoint may be restored under a different machine name, but the
    /// live overlay mount and crun state retain the identifier used at capture.
    pub overlay_owner: String,
    /// Restart policy to apply after the live checkpoint has been consumed.
    pub restart_policy: String,
    /// Maximum automatic restart attempts (`0` means unlimited).
    #[serde(default)]
    pub restart_max_retries: u32,
    /// Maximum restart backoff in seconds (`0` selects the runtime default).
    #[serde(default)]
    pub restart_max_backoff_secs: u64,
}

/// One host-to-guest TCP forward restored around a live VM.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckpointPort {
    /// Host TCP port on the restoring node.
    pub host: u16,
    /// Guest TCP port reached by the host listener.
    pub guest: u16,
}

/// Re-creatable host networking attached to a live checkpoint.
///
/// Open host sockets are deliberately not serialized. The target recreates
/// the same virtual network device and fresh host listeners before resuming
/// the captured guest; pre-existing external connections may be lost.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CheckpointNetwork {
    /// Whether the captured VM had a network backend attached.
    #[serde(default)]
    pub enabled: bool,
    /// Host listeners to recreate around the restored VM.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<CheckpointPort>,
    /// Effective backend used at capture: `tsi` or `virtio-net`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    /// Custom IPv4 DNS resolver, when one was explicitly configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<String>,
    /// Named local inter-VM network joined by the captured machine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_name: Option<String>,
    /// Captured outbound CIDR allow-list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_cidrs: Option<Vec<String>>,
    /// Captured outbound DNS hostname allow-list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_filter_hosts: Option<Vec<String>>,
}

/// Versioned host CPU compatibility contract for a live checkpoint.
///
/// A recognized contract permits a restore on a different CPU model while the
/// hypervisor remains the final authority for applying the captured
/// architectural CPU state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum CheckpointCpuContract {
    /// Stable Haswell-era Intel/KVM virtual CPU profile. The source VM ran
    /// under this profile from its first instruction, so host-specific extended
    /// state cannot leak into a live checkpoint.
    LinuxKvmIntelPortableV1,
    /// Platforms without a hypervisor-level compatibility check require the
    /// exact source CPU feature fingerprint.
    ExactV1 {
        /// Hash of the host CPU virtualization feature contract.
        fingerprint: String,
    },
}

/// Compatibility and payload metadata for a portable live checkpoint.
///
/// The pack container itself is portable storage; live CPU/device state is
/// deliberately accepted only by a runtime with the same checkpoint ABI,
/// architecture, CPU contract, and device profile.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortableCheckpointManifest {
    /// Version of this metadata contract.
    pub version: u32,
    /// Exact libkrun checkpoint-state ABI required by this artifact.
    pub runtime_abi: String,
    /// Host OS and architecture that captured the live state.
    pub host_platform: String,
    /// Versioned CPU migration contract.
    pub cpu_contract: CheckpointCpuContract,
    /// Number of virtual CPUs in the captured machine.
    pub cpus: u8,
    /// Configured guest memory in MiB.
    pub memory_mib: u32,
    /// Effective persistent storage size in GiB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_gib: Option<u64>,
    /// Effective writable overlay size in GiB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overlay_gib: Option<u64>,
    /// Stable identifier for the captured virtual device topology.
    pub device_profile: String,
    /// Serialized VM, vCPU, and device state.
    pub state: CheckpointAsset,
    /// Eager guest-memory image.
    pub memory: CheckpointAsset,
    /// Guest physical-memory layout manifest.
    pub layout: CheckpointAsset,
    /// Exact block-image chains from the same paused boundary as RAM.
    #[serde(default)]
    pub disks: Vec<CheckpointDisk>,
    /// Persistent container identity. Absent on version-one bare-VM
    /// checkpoints and on checkpoints captured from an imageless machine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload: Option<CheckpointWorkload>,
    /// Host networking reconstructed around the restored VM.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<CheckpointNetwork>,
}

/// Manifest describing the packed image and configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackManifest {
    /// Execution mode (container or VM).
    #[serde(default)]
    pub mode: PackMode,

    /// Original image reference (e.g., "alpine:latest").
    pub image: String,

    /// Image digest (sha256:...).
    pub digest: String,

    /// Target platform (e.g., "linux/arm64").
    pub platform: String,

    /// Entrypoint command (from image config or override).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entrypoint: Vec<String>,

    /// Default command arguments (from image config or override).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cmd: Vec<String>,

    /// Default environment variables.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,

    /// Secret references carried with the pack. Each maps an env var name to a
    /// reference (host store entry, host env var, or file) — never an inline
    /// value. The plaintext is resolved on the run host at exec time, so a
    /// `.smolmachine` never contains secret material at rest.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub secret_refs: std::collections::BTreeMap<String, smolvm_protocol::SecretRef>,

    /// Working directory (from image config or override).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workdir: Option<String>,

    /// Default number of vCPUs.
    pub cpus: u8,

    /// Default memory in MiB.
    pub mem: u32,

    /// Total extracted (on-disk) image size in bytes.
    /// Used to auto-size the storage disk at runtime.
    #[serde(default)]
    pub image_size: u64,

    /// Whether outbound networking is enabled by default.
    #[serde(default)]
    pub network: bool,

    /// Enable GPU acceleration (Vulkan via virtio-gpu).
    #[serde(default)]
    pub gpu: bool,

    /// Enable CUDA-over-vsock: the runtime starts a host CUDA server and bridges
    /// the guest's CUDA client to it. Preserved from the source VM's `cuda` flag
    /// when packing `--from-vm`. `#[serde(default)]` keeps older sidecars (which
    /// lack the field) loadable.
    #[serde(default)]
    pub cuda: bool,

    /// Host platform this .smolmachine runs on (e.g., "darwin/arm64").
    /// Distinct from `platform` which is the guest architecture (always linux).
    /// Used for registry Image Index resolution. `#[serde(default)]` keeps
    /// pre-reset packs (which predate this field) loadable — a local run selects
    /// libs by the actual host, so an empty value is harmless.
    #[serde(default)]
    pub host_platform: String,

    /// RFC 3339 timestamp when this machine was packed. Defaulted so older packs
    /// that lack it still load.
    #[serde(default)]
    pub created: String,

    /// smolvm version that built this machine (e.g., "0.1.15"). Defaulted so
    /// older packs that lack it still load.
    #[serde(default)]
    pub smolvm_version: String,

    /// Asset inventory - files included in the assets blob.
    pub assets: AssetInventory,

    /// Live execution state when this artifact is a `.smolcheckpoint`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<PortableCheckpointManifest>,
}

/// Inventory of assets included in the packed binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetInventory {
    /// Runtime libraries (relative paths within assets).
    pub libraries: Vec<AssetEntry>,

    /// Agent rootfs tarball.
    pub agent_rootfs: AssetEntry,

    /// OCI layer tarballs.
    pub layers: Vec<LayerEntry>,

    /// Pre-formatted storage disk template (optional).
    /// When present, copied to cache on first run instead of formatting at runtime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_template: Option<AssetEntry>,

    /// Original sparse size of a VM-mode storage disk, in bytes.
    ///
    /// Like the root overlay, a stopped VM's storage disk is packed without its
    /// trailing hole and must be extended to this size before it is used as a
    /// raw backing disk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_logical_size: Option<u64>,

    /// Overlay disk template (optional, VM mode only).
    /// Contains the VM's persistent rootfs state from a `--from-vm` pack.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overlay_template: Option<AssetEntry>,

    /// Original sparse size of the overlay disk, in bytes (optional, VM mode only).
    ///
    /// When set, the overlay.raw entry in the archive is a truncated copy with
    /// the trailing sparse hole removed. On extraction the file is extended to
    /// this size via `ftruncate`, restoring the sparse skeleton the VM expects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overlay_logical_size: Option<u64>,
}

/// An asset file entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetEntry {
    /// Path within the assets archive.
    pub path: String,

    /// Uncompressed size in bytes.
    pub size: u64,
}

/// An OCI layer entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerEntry {
    /// Layer digest (sha256:...).
    pub digest: String,

    /// Path within the assets archive.
    pub path: String,

    /// Uncompressed size in bytes.
    pub size: u64,
}

/// Generate an RFC 3339 timestamp for the current time in UTC.
fn rfc3339_now() -> String {
    let now = time::OffsetDateTime::now_utc();
    now.format(&time::format_description::well_known::Rfc3339)
        .expect("RFC 3339 formatting should never fail for a valid OffsetDateTime")
}

impl PackManifest {
    /// Create a new manifest with default values.
    pub fn new(image: String, digest: String, platform: String, host_platform: String) -> Self {
        Self {
            mode: PackMode::default(),
            image,
            digest,
            platform,
            entrypoint: Vec::new(),
            cmd: Vec::new(),
            env: Vec::new(),
            secret_refs: std::collections::BTreeMap::new(),
            workdir: None,
            cpus: 1,
            mem: 256,
            image_size: 0,
            network: false,
            gpu: false,
            cuda: false,
            host_platform,
            created: rfc3339_now(),
            smolvm_version: env!("CARGO_PKG_VERSION").to_string(),
            assets: AssetInventory {
                libraries: Vec::new(),
                agent_rootfs: AssetEntry {
                    path: "agent-rootfs.tar".to_string(),
                    size: 0,
                },
                layers: Vec::new(),
                storage_template: None,
                storage_logical_size: None,
                overlay_template: None,
                overlay_logical_size: None,
            },
            checkpoint: None,
        }
    }

    /// Serialize manifest to JSON.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec_pretty(self)?)
    }

    /// Deserialize manifest from JSON.
    pub fn from_json(data: &[u8]) -> Result<Self> {
        Ok(serde_json::from_slice(data)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manifest_secret_refs_roundtrip() {
        // Secret refs survive a JSON round-trip through the manifest, and are
        // omitted entirely when empty (skip_serializing_if) so existing packs
        // stay byte-compatible.
        let empty = PackManifest::new(
            "alpine".to_string(),
            "sha256:abc".to_string(),
            "linux/arm64".to_string(),
            "linux/arm64".to_string(),
        );
        let json = String::from_utf8(empty.to_json().unwrap()).unwrap();
        assert!(
            !json.contains("secret_refs"),
            "empty secret_refs must not be serialized"
        );

        let mut m = empty;
        m.secret_refs.insert(
            "DB_PASSWORD".to_string(),
            smolvm_protocol::SecretRef {
                from_env: Some("PGPASSWORD".to_string()),
                from_file: None,
            },
        );
        let restored = PackManifest::from_json(&m.to_json().unwrap()).unwrap();
        assert_eq!(restored.secret_refs.len(), 1);
        assert_eq!(
            restored.secret_refs["DB_PASSWORD"].from_env.as_deref(),
            Some("PGPASSWORD")
        );
    }

    #[test]
    fn test_footer_roundtrip() {
        let footer = PackFooter {
            stub_size: 512 * 1024,
            assets_offset: 512 * 1024,
            assets_size: 50 * 1024 * 1024,
            manifest_offset: 512 * 1024 + 50 * 1024 * 1024,
            manifest_size: 2048,
            checksum: 0xDEADBEEF,
        };

        let bytes = footer.to_bytes();
        assert_eq!(bytes.len(), FOOTER_SIZE);

        let restored = PackFooter::from_bytes(&bytes).unwrap();
        assert_eq!(restored.stub_size, footer.stub_size);
        assert_eq!(restored.assets_offset, footer.assets_offset);
        assert_eq!(restored.assets_size, footer.assets_size);
        assert_eq!(restored.manifest_offset, footer.manifest_offset);
        assert_eq!(restored.manifest_size, footer.manifest_size);
        assert_eq!(restored.checksum, footer.checksum);
    }

    #[test]
    fn test_footer_invalid_magic() {
        let mut bytes = [0u8; FOOTER_SIZE];
        bytes[0..8].copy_from_slice(b"BADMAGIC");

        let result = PackFooter::from_bytes(&bytes);
        assert!(matches!(result, Err(PackError::InvalidMagic)));
    }

    #[test]
    fn test_footer_unsupported_version() {
        let mut bytes = [0u8; FOOTER_SIZE];
        bytes[0..8].copy_from_slice(MAGIC);
        bytes[8..12].copy_from_slice(&99u32.to_le_bytes()); // Bad version

        let result = PackFooter::from_bytes(&bytes);
        assert!(matches!(result, Err(PackError::UnsupportedVersion(99))));
    }

    #[test]
    fn test_footer_reads_legacy_v2_v3() {
        // Packs written before FORMAT_VERSION was reset 3->1 stamp version 2 or 3
        // but share the identical byte layout, so they must still read. Regression
        // for "read footer: unsupported version: 3" on pre-reset .smolmachine files.
        for legacy in [2u32, 3u32] {
            let footer = PackFooter {
                stub_size: 0,
                assets_offset: 0,
                assets_size: 10,
                manifest_offset: 10,
                manifest_size: 20,
                checksum: 0,
            };
            let mut bytes = footer.to_bytes();
            bytes[8..12].copy_from_slice(&legacy.to_le_bytes());
            let restored = PackFooter::from_bytes(&bytes)
                .unwrap_or_else(|_| panic!("legacy v{legacy} footer must read"));
            assert_eq!(restored.assets_size, 10);
            assert_eq!(restored.manifest_size, 20);
        }
    }

    #[test]
    fn test_manifest_roundtrip() {
        let mut manifest = PackManifest::new(
            "alpine:latest".to_string(),
            "sha256:abc123".to_string(),
            "linux/arm64".to_string(),
            "darwin/arm64".to_string(),
        );
        manifest.cpus = 2;
        manifest.mem = 1024;
        manifest.entrypoint = vec!["/bin/sh".to_string()];
        manifest.env = vec!["PATH=/usr/local/bin:/usr/bin:/bin".to_string()];
        manifest.assets.libraries.push(AssetEntry {
            path: "lib/libkrun.dylib".to_string(),
            size: 4 * 1024 * 1024,
        });

        let json = manifest.to_json().unwrap();
        let restored = PackManifest::from_json(&json).unwrap();

        assert_eq!(restored.image, "alpine:latest");
        assert_eq!(restored.digest, "sha256:abc123");
        assert_eq!(restored.cpus, 2);
        assert_eq!(restored.mem, 1024);
        assert_eq!(restored.entrypoint, vec!["/bin/sh"]);
        assert_eq!(restored.assets.libraries.len(), 1);
    }

    #[test]
    fn test_manifest_json_format() {
        let manifest = PackManifest::new(
            "ubuntu:22.04".to_string(),
            "sha256:def456".to_string(),
            "linux/amd64".to_string(),
            "linux/amd64".to_string(),
        );

        let json = String::from_utf8(manifest.to_json().unwrap()).unwrap();
        assert!(json.contains("\"image\": \"ubuntu:22.04\""));
        assert!(json.contains("\"platform\": \"linux/amd64\""));
        // Phase 0 fields: verify key names serialize correctly
        assert!(json.contains("\"host_platform\": \"linux/amd64\""));
        assert!(json.contains("\"smolvm_version\""));
        assert!(json.contains("\"created\""));
    }

    #[test]
    fn test_pack_mode_default_is_container() {
        assert_eq!(PackMode::default(), PackMode::Container);
    }

    #[test]
    fn test_pack_mode_vm_roundtrip() {
        let mut manifest = PackManifest::new(
            "vm://myvm".to_string(),
            "none".to_string(),
            "linux/arm64".to_string(),
            "darwin/arm64".to_string(),
        );
        manifest.mode = PackMode::Vm;
        manifest.assets.overlay_template = Some(AssetEntry {
            path: "overlay.raw".to_string(),
            size: 2 * 1024 * 1024 * 1024,
        });

        let json = manifest.to_json().unwrap();
        let restored = PackManifest::from_json(&json).unwrap();
        assert_eq!(restored.mode, PackMode::Vm);
        assert!(restored.assets.overlay_template.is_some());
        assert_eq!(
            restored.assets.overlay_template.unwrap().path,
            "overlay.raw"
        );
    }
}
