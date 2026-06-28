//! Agent VM launcher.
//!
//! This module provides the low-level VM launching functionality.
//! All setup is done in the child process after fork, where
//! DYLD_LIBRARY_PATH is still available for dlopen.

use crate::data::consts::{ENV_SMOLVM_KRUN_LOG_LEVEL, ENV_SMOLVM_LIB_DIR};
use crate::data::disk::DiskFormat;
use crate::data::storage::HostMount;
use crate::error::{Error, Result};
use crate::network::backend::COMPAT_NET_FEATURES;
use crate::network::backend::TSI_FEATURE_HIJACK_INET;
use crate::network::{plan_launch_network, EffectiveNetworkBackend};
use crate::storage::{OverlayDisk, StorageDisk};
use crate::util::{libkrun_filename, libkrunfw_filename};

use crate::agent::vsock_service;
use smolvm_network::PortMapping as VirtioPortMapping;
use smolvm_network::{start_virtio_network, GuestNetworkConfig, VirtioNetworkRuntime};
use smolvm_protocol::{guest_env, ports};
use socket2::Socket;
#[cfg(windows)]
use socket2::{Domain, SockAddr, Type};
use std::ffi::CString;
#[cfg(unix)]
use std::os::fd::FromRawFd;
// `std::os::fd` does not exist on Windows. Keep the `RawFd` name working in
// signatures on both platforms via a portable alias.
#[cfg(unix)]
use std::os::fd::RawFd;
#[cfg(not(unix))]
#[allow(dead_code)]
type RawFd = std::os::raw::c_int;
use std::path::{Path, PathBuf};

use super::{KrunFunctions, PortMapping, VmResources};

/// Maximum number of CIDR entries held in the live egress allow-list.
/// Protects the muxer's per-packet O(n) scan from unbounded growth when
/// a host resolves to many IPs across many refresh cycles.
const EGRESS_CIDR_CAP: usize = 512;

/// Hidden benchmark knob for root virtiofs DAX.
///
/// Default configures the root virtiofs device with a 512 MB DAX window (the
/// same default the removed `krun_set_root` used). Set `SMOLVM_ROOTFS_DAX=0` to
/// use `krun_add_virtiofs3("/dev/root", ..., shm_size=0, read_only=false)`,
/// disabling the root DAX region for benchmarking.
const ENV_SMOLVM_ROOTFS_DAX: &str = "SMOLVM_ROOTFS_DAX";

/// Root virtiofs DAX window (512 MB), matching the default the removed
/// `krun_set_root` configured. DAX gives the host a coherent shared mapping of
/// the root fs so the guest agent's ready-marker write is visible to the host
/// immediately. Plain `krun_add_virtiofs` passes shm_size=0 (no DAX), dropping
/// virtiofs to writeback caching — the marker isn't seen until the multi-second
/// socket-probe grace, regressing boot time from ~hundreds of ms to ~5 s.
const ROOTFS_DAX_WINDOW: u64 = 1 << 29;

/// The Arc type shared between the egress-refresh thread and libkrun's vsock muxer.
type EgressArc = std::sync::Arc<std::sync::RwLock<Vec<(std::net::IpAddr, u8)>>>;

/// Disks to attach to the agent VM.
pub struct VmDisks<'a> {
    /// Storage disk for OCI layers (/dev/vda in guest).
    pub storage: &'a StorageDisk,
    /// Optional overlay disk for persistent rootfs (/dev/vdb in guest).
    pub overlay: Option<&'a OverlayDisk>,
}

/// Find the directory containing libkrun/libkrunfw by checking explicit overrides and
/// paths relative to the current executable.
///
/// Checks:
/// - `$SMOLVM_LIB_DIR` (explicit override for embedded runtimes)
/// - `<exe_dir>/lib/` (distribution layout)
/// - `<exe_dir>/../lib/` (alternative layout)
/// - `<exe_dir>/../../lib/linux-<arch>/` (source tree dev builds)
pub fn find_lib_dir() -> Option<PathBuf> {
    let lib_names = [libkrun_filename(), libkrunfw_filename()];
    if let Ok(explicit_dir) = std::env::var(ENV_SMOLVM_LIB_DIR) {
        let path = PathBuf::from(explicit_dir);
        if lib_names.iter().all(|lib| path.join(lib).exists()) {
            return path.canonicalize().ok().or(Some(path));
        }

        tracing::warn!(
            path = %path.display(),
            "{} does not contain the expected libkrun/libkrunfw libraries", ENV_SMOLVM_LIB_DIR
        );
    }

    let exe = std::env::current_exe().ok()?;
    let exe_dir = exe.parent()?;

    let candidates = [
        exe_dir.join("lib"),
        // The Windows release ships krun.dll / libkrunfw.dll directly beside
        // smolvm.exe (no lib/ subdir, no wrapper to set SMOLVM_LIB_DIR), matching
        // the convention that Windows resolves DLLs from the executable's own
        // directory. Harmless on Unix dists, where the libs live in lib/.
        exe_dir.to_path_buf(),
        exe_dir.join("../lib"),
        exe_dir.join("../../lib"),
        exe_dir.join(format!("../../lib/linux-{}", std::env::consts::ARCH)),
    ];

    for dir in &candidates {
        if lib_names.iter().all(|lib| dir.join(lib).exists()) {
            return dir.canonicalize().ok();
        }
    }

    None
}

/// A qcow2 copy-on-write overlay to create: `(overlay_path, base_path, base_format)`.
/// `base_path` must be absolute — it is written verbatim into the overlay header,
/// and imago resolves a relative backing path against the overlay's own directory.
pub type DiskOverlaySpec = (PathBuf, PathBuf, DiskFormat);

/// Create the given qcow2 copy-on-write overlays, loading libkrun once for the
/// whole batch (overlay creation is a pure filesystem op, but the only place the
/// `krun_create_disk_overlay` symbol lives is libkrun). Stops at the first error.
pub fn create_disk_overlays(specs: &[DiskOverlaySpec]) -> Result<()> {
    if specs.is_empty() {
        return Ok(());
    }
    let lib_dir = find_lib_dir().ok_or_else(|| {
        Error::agent(
            "create disk overlay",
            "could not locate the libkrun library directory",
        )
    })?;
    let krun = unsafe { KrunFunctions::load(&lib_dir) }
        .map_err(|e| Error::agent("create disk overlay", e))?;
    let create = krun.create_disk_overlay.ok_or_else(|| {
        Error::agent(
            "create disk overlay",
            "libkrun is missing krun_create_disk_overlay (rebuild libkrun)",
        )
    })?;

    for (overlay, base, base_format) in specs {
        let overlay_c = path_to_cstring(overlay)?;
        let base_c = path_to_cstring(base)?;
        let rc = unsafe {
            create(
                overlay_c.as_ptr(),
                base_c.as_ptr(),
                base_format.to_krun_u32(),
            )
        };
        if rc < 0 {
            return Err(Error::agent(
                "create disk overlay",
                format!(
                    "krun_create_disk_overlay failed (rc={rc}) for {} <- {}",
                    overlay.display(),
                    base.display()
                ),
            ));
        }
    }
    Ok(())
}

/// Launch the agent VM (call in the forked child process).
///
/// This function sets up and starts the VM in a single call.
/// It should be called in the child process after fork, where
/// DYLD_LIBRARY_PATH is still available for dlopen to find libkrunfw.
///
/// Optional features for VM launch (SSH agent, DNS filtering, etc.).
///
/// Groups optional capabilities that don't affect core VM operation.
/// New features should be added here rather than as additional parameters
/// on manager/launcher functions.
#[derive(Debug, Clone, Default)]
pub struct LaunchFeatures {
    /// Host SSH agent socket path for forwarding into the guest.
    pub ssh_agent_socket: Option<std::path::PathBuf>,
    /// Enable CUDA-over-vsock: smolvm starts a host CUDA server and the guest
    /// remotes its CUDA Driver-API calls to the host GPU.
    pub cuda: bool,
    /// Hostnames for DNS filtering. When set, the host starts a DNS filter
    /// listener and the guest agent proxies DNS queries through it.
    pub dns_filter_hosts: Option<Vec<String>>,
    /// Pre-extracted OCI layer directory for machines created from .smolmachine.
    /// When set, the launcher mounts this directory via virtiofs so the agent
    /// can use pre-extracted layers instead of pulling from a registry.
    pub packed_layers_dir: Option<std::path::PathBuf>,
    /// Root-owned shared pack copy (`_shared/<checksum>`) to present at
    /// `packed_layers_dir` via a per-VM idmapped bind mount. Set by
    /// [`with_packed_layers`](LaunchFeatures::with_packed_layers) when create
    /// wrote a shared pointer; the manager keeps it only when the per-VM uid drop
    /// is active (else it collapses `packed_layers_dir` onto the shared copy).
    pub pack_idmap_source: Option<std::path::PathBuf>,
    /// Additional disk images to attach to the VM (path, read_only, format).
    /// Appear as /dev/vdc, /dev/vdd, ... after the storage and overlay disks.
    pub extra_disks: Vec<(std::path::PathBuf, bool, DiskFormat)>,
    /// Start as a fork base: back guest RAM with a memfd (copy-on-write
    /// cloneable) and expose `control_socket` so the machine can be forked.
    pub forkable: bool,
    /// Boot this VM as a fork clone, restoring from the golden's snapshot at
    /// this directory (set on the clone; `None` for a normal cold boot).
    pub snapshot_dir: Option<std::path::PathBuf>,
    /// Control socket path for a forkable machine (pause/resume/checkpoint/FORK).
    pub control_socket: Option<std::path::PathBuf>,
    /// Override the parent-death watchdog. `None` = default (arm it iff a
    /// separate boot binary is used, i.e. an in-process SDK embedder whose VM
    /// must die with it). `Some(false)` forces it off — for a CLI that sets
    /// `SMOLVM_BOOT_BINARY` (so `current_exe` need not handle `_boot-vm`) yet
    /// DETACHES the VM to persist after the CLI exits (e.g. `smol start`/`fork`).
    pub watch_parent: Option<bool>,
}

impl LaunchFeatures {
    /// Wire pre-extracted OCI layers for a machine created from a `.smolmachine`.
    ///
    /// `layers_cache_dir` is the machine's OWN extraction directory (under its
    /// [`vm_data_dir`](crate::agent::vm_data_dir), via
    /// [`machine_layers_cache_dir`](crate::agent::machine_layers_cache_dir)), not
    /// the shared content-addressed pack cache. The bundle is extracted there
    /// once at create time, so every subsequent start is independent of the
    /// original `.smolmachine` file. When `source_smolmachine` is `None` the
    /// machine is image/registry-sourced and `self` is returned unchanged.
    ///
    /// Normal path: the layers are already extracted, so this only acquires a
    /// lease (re-mounting the case-sensitive volume on macOS; a no-op on Linux)
    /// and points `packed_layers_dir` at it — no dependency on the sidecar.
    /// Fallback path: if the per-machine directory has no extracted layers (a
    /// machine created before this layout, or an interrupted create), extract
    /// from the `source_smolmachine` sidecar, which must still exist in that case.
    ///
    /// This is the single source of truth shared by every start path — the CLI
    /// `machine start` and the API start/ensure/restart handlers — so they
    /// cannot drift apart and silently drop the bundled layers.
    ///
    /// Performs blocking filesystem work; on async paths call it from within a
    /// `spawn_blocking` context.
    pub fn with_packed_layers(
        mut self,
        layers_cache_dir: &Path,
        source_smolmachine: Option<&str>,
    ) -> Result<Self> {
        let Some(sidecar_path) = source_smolmachine else {
            return Ok(self);
        };

        // Shared pack store: if create extracted the pack into the node's shared
        // content-addressed store and dropped a pointer beside this machine, the
        // per-machine `pack` dir is an empty mountpoint. Point `packed_layers_dir`
        // at it and carry the shared copy as the idmap source; the manager keeps
        // the idmap only when the per-VM uid drop is active (else it collapses
        // `packed_layers_dir` onto the shared copy directly). No lease — the
        // shared copy is never the macOS case-sensitive volume (Linux-only path).
        if let Some(shared) = super::read_shared_pack_pointer(layers_cache_dir) {
            self.packed_layers_dir = Some(layers_cache_dir.to_path_buf());
            self.pack_idmap_source = Some(shared);
            return Ok(self);
        }

        if !smolvm_pack::extract::is_extracted(layers_cache_dir) {
            // Fallback: layers not yet extracted into this machine's own dir
            // (pre-this-layout machine, or an interrupted create). Extract from
            // the source bundle, which must still be present in that case.
            let sidecar = Path::new(sidecar_path);
            if !sidecar.exists() {
                return Err(Error::agent(
                    "start machine",
                    format!(
                        "packed layers are not extracted for this machine and its \
                         source .smolmachine is missing: {}\nRe-create the machine \
                         from the bundle.",
                        sidecar_path
                    ),
                ));
            }
            let footer = smolvm_pack::packer::read_footer_from_sidecar(sidecar)
                .map_err(|e| Error::agent("read sidecar footer", e.to_string()))?;
            smolvm_pack::extract::extract_sidecar(sidecar, layers_cache_dir, &footer, false, false)
                .map_err(|e| Error::agent("extract sidecar", e.to_string()))?;
        }

        let layers_lease = smolvm_pack::extract::acquire_layers_lease(layers_cache_dir, false)
            .map_err(|e| Error::agent("acquire layers lease", e.to_string()))?;
        self.packed_layers_dir = Some(layers_lease.path.clone());
        // Leak the lease so the case-sensitive layers volume stays mounted for
        // the VM's lifetime (macOS only; a no-op on Linux). Unlike the previous
        // shared-cache design, this volume is owned 1:1 by the machine: the stop
        // and delete handlers detach it unconditionally via
        // `force_detach_layers_volume`, so no co-tenant can be relying on it and
        // no lease outlives the machine.
        std::mem::forget(layers_lease);

        Ok(self)
    }
}

/// Configuration for launching an agent VM.
pub struct LaunchConfig<'a> {
    /// Path to the agent rootfs directory.
    pub rootfs_path: &'a Path,
    /// Storage and overlay disk handles.
    pub disks: &'a VmDisks<'a>,
    /// Path to the vsock Unix socket for the control channel.
    pub vsock_socket: &'a Path,
    /// Optional path to write console output.
    pub console_log: Option<&'a Path>,
    /// Host directory mounts to expose to the guest.
    pub mounts: &'a [HostMount],
    /// Port mappings (host:guest).
    pub port_mappings: &'a [PortMapping],
    /// VM resources (CPU, memory, network, disk sizes).
    pub resources: VmResources,
    /// Host SSH agent socket path for forwarding into the guest.
    pub ssh_agent_socket: Option<&'a Path>,
    /// Host DNS filter socket path. When set, the guest DNS proxy forwards
    /// queries over vsock to this socket for filtering.
    pub dns_filter_socket: Option<&'a Path>,
    /// Host CUDA-over-vsock server socket (experimental). When set, the guest
    /// CUDA client connects out to this AF_UNIX path and the host server runs
    /// the calls on the NVIDIA GPU. Resolved at the boot-config boundary (the
    /// subprocess reads `SMOLVM_CUDA_SOCK`) so the launcher stays policy-free.
    pub cuda_socket: Option<&'a Path>,
    /// Pre-extracted OCI layers directory for .smolmachine-sourced machines.
    /// Mounted via virtiofs as "smolvm_layers" so the agent uses packed layers.
    pub packed_layers_dir: Option<&'a Path>,
    /// Additional disk images (path, read_only, format). Appear as /dev/vdc, /dev/vdd, ...
    pub extra_disks: &'a [(std::path::PathBuf, bool, DiskFormat)],
    /// Whether DNS filtering was configured for this launch, even if the
    /// host-side proxy socket could not be created.
    pub dns_filter_enabled: bool,
    /// Hostnames to periodically re-resolve for the live egress policy.
    /// When set, a background thread re-resolves these every 5 minutes and
    /// atomically replaces the CIDR list via the Arc handle obtained from
    /// libkrun. This keeps the egress allow-list accurate for long-running VMs
    /// hitting CDN-backed hosts whose IPs rotate.
    pub egress_refresh_hosts: Option<Vec<String>>,
    /// Where to flush this VM's cumulative egress byte count (virtio-net only).
    /// A background thread writes it here every few seconds; serve reads it to
    /// surface `egressBytes` in the machine info, the same per-VM-dir bridge the
    /// vsock/console paths use. `None` disables egress telemetry (e.g. TSI).
    pub egress_telemetry: Option<&'a Path>,
}

/// Launch the agent VM using libkrun.
///
/// This function never returns on success.
pub fn launch_agent_vm(config: &LaunchConfig<'_>) -> Result<()> {
    let t0 = std::time::Instant::now();

    // Emit boot timing to stderr (captured in the startup error log by the
    // subprocess's stdio redirect) when INFO logging is enabled.
    // tracing_subscriber writes to stdout by default, but the subprocess has
    // stdout=/dev/null; stderr is the only channel that reaches the log file.
    macro_rules! boot_timing {
        ($label:expr) => {
            if tracing::enabled!(tracing::Level::INFO) {
                eprintln!("[boot] {:25} {}ms", $label, t0.elapsed().as_millis());
            }
        };
    }

    // `egress_telemetry` is consumed only by the unix-only virtio-net path.
    #[cfg_attr(not(unix), allow(unused_variables))]
    let LaunchConfig {
        rootfs_path,
        disks,
        vsock_socket,
        console_log,
        mounts,
        port_mappings,
        resources,
        ssh_agent_socket,
        dns_filter_socket,
        cuda_socket,
        packed_layers_dir,
        extra_disks,
        dns_filter_enabled,
        egress_refresh_hosts,
        egress_telemetry,
    } = config;

    crate::network::validate_requested_network_backend(resources, None, port_mappings.len())?;

    // Raise file descriptor limits
    raise_fd_limits();

    let lib_dir = find_lib_dir().ok_or_else(|| {
        Error::agent(
            "find libraries",
            "libkrun/libkrunfw not found. Install smolvm with bundled libraries or set SMOLVM_LIB_DIR.",
        )
    })?;
    let krun =
        unsafe { KrunFunctions::load(&lib_dir) }.map_err(|e| Error::agent("load libkrun", e))?;
    boot_timing!("dylib loaded");

    // Pre-read the agent binary into the OS page cache so the virtiofs thread
    // can serve the guest's first exec without waiting for disk I/O.
    // Runs concurrently with krun context setup below — by the time
    // krun_start_enter is called, the file is already in page cache.
    {
        let agent_bin = rootfs_path.join("usr/local/bin/smolvm-agent");
        if agent_bin.exists() {
            let _ = std::thread::Builder::new()
                .name("agent-preread".into())
                .spawn(move || {
                    let _ = std::fs::read(&agent_bin);
                });
        }
    }

    unsafe {
        let krun_set_log_level = krun.set_log_level;
        let krun_create_ctx = krun.create_ctx;
        let krun_free_ctx = krun.free_ctx;
        let krun_set_vm_config = krun.set_vm_config;
        let krun_set_workdir = krun.set_workdir;
        let krun_set_exec = krun.set_exec;
        let krun_add_disk2 = krun.add_disk2;
        let krun_add_vsock_port2 = krun.add_vsock_port2;
        let krun_set_port_map = krun.set_port_map;
        let krun_add_virtiofs = krun.add_virtiofs;
        let krun_add_virtiofs3 = krun.add_virtiofs3;
        let krun_start_enter = krun.start_enter;
        let krun_add_vsock = krun.add_vsock;

        // Set log level (0 = off, 1 = error, 2 = warn, 3 = info, 4 = debug)
        // Enable debug logging to trace vsock timing issues
        let log_level = std::env::var(ENV_SMOLVM_KRUN_LOG_LEVEL)
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        krun_set_log_level(log_level);

        // Create VM context
        let ctx = krun_create_ctx();
        if ctx < 0 {
            return Err(Error::agent("create vm context", "krun_create_ctx failed"));
        }
        let ctx = ctx as u32;
        boot_timing!("ctx created");

        // Set VM config
        if krun_set_vm_config(ctx, resources.cpus, resources.memory_mib) < 0 {
            krun_free_ctx(ctx);
            return Err(Error::agent("configure vm", "krun_set_vm_config failed"));
        }

        // Enable GPU if requested (virgl for OpenGL + Venus for Vulkan via virtio-gpu).
        // Requires libkrun built with `gpu` feature and host virglrenderer.
        // On macOS, also requires MoltenVK (Vulkan → Metal translation).
        if resources.gpu {
            let virgl_flags = super::gpu_virgl_flags();
            // Size the GPU shared-memory region. Caller may override
            // via `--gpu-vram <MiB>` (CLI) or `gpu_vram = N` (Smolfile);
            // default is `DEFAULT_GPU_VRAM_MIB`.
            let vram_mib = resources.effective_gpu_vram_mib();
            let vram_bytes: u64 = (vram_mib as u64) * crate::data::consts::BYTES_PER_MIB;

            // Resolve krun_set_gpu_options2 dynamically — it may not exist
            // if libkrun was built without the `gpu` feature.
            let set_gpu = match krun.set_gpu_options2 {
                Some(f) => f,
                None => {
                    krun_free_ctx(ctx);
                    return Err(Error::agent(
                        "configure gpu",
                        "libkrun was built without GPU support (krun_set_gpu_options2 not found). \
                         Rebuild libkrun with GPU=1 — see project README for details.",
                    ));
                }
            };

            let ret = set_gpu(ctx, virgl_flags, vram_bytes);
            if ret < 0 {
                krun_free_ctx(ctx);
                return Err(Error::agent(
                    "configure gpu",
                    format!("krun_set_gpu_options2 failed (ret={}). Check that virglrenderer is installed.", ret),
                ));
            }
            tracing::info!("GPU enabled (Venus/Vulkan via virtio-gpu)");
        }

        // Helper: evaluate a fallible expression, freeing ctx if it fails.
        // Replaces bare `?` which would leak the libkrun context.
        macro_rules! try_or_free_ctx {
            ($expr:expr, $op:expr, $msg:expr) => {
                match $expr {
                    Ok(val) => val,
                    Err(_) => {
                        krun_free_ctx(ctx);
                        return Err(Error::agent($op, $msg));
                    }
                }
            };
        }

        // Set root filesystem via the root virtiofs tag ("/dev/root").
        //
        // Upstream libkrun removed krun_set_root in favor of krun_add_virtiofs*
        // with KRUN_FS_ROOT_TAG. Default path: krun_add_virtiofs, preserving the
        // established rootfs DAX defaults. Benchmark path: SMOLVM_ROOTFS_DAX=0
        // uses krun_add_virtiofs3 with shm_size=0, disabling the root DAX region
        // while keeping the root read-write.
        let root = try_or_free_ctx!(
            path_to_cstring(rootfs_path),
            "set rootfs",
            "path contains null byte"
        );
        let root_tag = cstr("/dev/root");
        if rootfs_dax_disabled() {
            let Some(add_virtiofs3) = krun_add_virtiofs3 else {
                krun_free_ctx(ctx);
                return Err(Error::agent(
                    "set rootfs",
                    "SMOLVM_ROOTFS_DAX=0 requires libkrun with krun_add_virtiofs3",
                ));
            };

            if add_virtiofs3(ctx, root_tag.as_ptr(), root.as_ptr(), 0, false) < 0 {
                krun_free_ctx(ctx);
                return Err(Error::agent(
                    "set rootfs",
                    "krun_add_virtiofs3 failed for root filesystem",
                ));
            }
            tracing::info!("rootfs configured via virtiofs without DAX");
        } else {
            // Default: restore the 512 MB root DAX window the removed krun_set_root
            // configured. Plain krun_add_virtiofs passes shm_size=0 (no DAX), which
            // drops virtiofs to writeback caching and hides the guest's ready-marker
            // write from the host until the socket-probe grace — a boot-time regression.
            let Some(add_virtiofs3) = krun_add_virtiofs3 else {
                krun_free_ctx(ctx);
                return Err(Error::agent(
                    "set rootfs",
                    "root DAX requires libkrun with krun_add_virtiofs3",
                ));
            };
            if add_virtiofs3(
                ctx,
                root_tag.as_ptr(),
                root.as_ptr(),
                ROOTFS_DAX_WINDOW,
                false,
            ) < 0
            {
                krun_free_ctx(ctx);
                return Err(Error::agent(
                    "set rootfs",
                    "krun_add_virtiofs3 failed for root filesystem",
                ));
            }
        }

        let network_plan = select_network_plan(resources, *dns_filter_enabled, port_mappings.len());

        // `mut` is only needed on unix (the VirtioNet arm assigns it); on
        // Windows the runtime is owned by the accept thread, so the launcher's
        // binding stays `None`.
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut virtio_network_runtime: Option<VirtioNetworkRuntime> = None;
        let guest_network: Option<GuestNetworkConfig> = match network_plan.backend {
            EffectiveNetworkBackend::None => {
                // Upstream libkrun no longer creates an implicit vsock (the old
                // krun_disable_implicit_vsock is gone), so just add it explicitly.
                if krun_add_vsock(ctx, 0) < 0 {
                    krun_free_ctx(ctx);
                    return Err(Error::agent("configure vsock", "krun_add_vsock failed"));
                }

                tracing::debug!("configured vsock without guest networking");
                None
            }
            EffectiveNetworkBackend::Tsi => {
                if krun_add_vsock(ctx, TSI_FEATURE_HIJACK_INET) < 0 {
                    krun_free_ctx(ctx);
                    return Err(Error::agent(
                        "configure vsock",
                        "krun_add_vsock with TSI failed",
                    ));
                }

                let port_cstrings: Vec<CString> = port_mappings
                    .iter()
                    .map(|p| {
                        CString::new(format!("{}:{}", p.host, p.guest))
                            .expect("port mapping format cannot contain null bytes")
                    })
                    .collect();
                let mut port_ptrs: Vec<*const libc::c_char> =
                    port_cstrings.iter().map(|s| s.as_ptr()).collect();
                port_ptrs.push(std::ptr::null());

                if krun_set_port_map(ctx, port_ptrs.as_ptr()) < 0 {
                    krun_free_ctx(ctx);
                    return Err(Error::agent("set port mapping", "krun_set_port_map failed"));
                }

                // Egress policy: static CIDRs plus DNS allow-host filtering
                // enforced inside libkrun. When allow-hosts are set, the guest's
                // UDP DNS queries to port 53 are intercepted and forwarded only
                // to the host-trusted resolver; A/AAAA answers are learned as
                // temporary allowed IPs. The guest-side DNS proxy is left off
                // (see below) so those queries leave as real UDP datagrams.
                let egress_hosts = egress_refresh_hosts.clone().unwrap_or_default();
                if resources.allowed_cidrs.is_some() || !egress_hosts.is_empty() {
                    let Some(set_egress) = krun.set_egress_policy else {
                        krun_free_ctx(ctx);
                        return Err(Error::agent(
                            "set egress policy",
                            "libkrun does not support egress policy (krun_set_egress_policy not found). \
                             Update libkrun or remove --allow-cidr/--allow-host flags.",
                        ));
                    };

                    // CIDRs (plus the resolver IP via ensure_dns_in_cidrs) — a
                    // null-terminated array.
                    let mut all_cidrs = resources.allowed_cidrs.clone().unwrap_or_default();
                    crate::data::network::ensure_dns_in_cidrs(&mut all_cidrs);
                    let cidr_cstrings: Vec<CString> = all_cidrs
                        .iter()
                        .map(|c| CString::new(c.as_str()).expect("CIDR cannot contain null bytes"))
                        .collect();
                    let mut cidr_ptrs: Vec<*const libc::c_char> =
                        cidr_cstrings.iter().map(|s| s.as_ptr()).collect();
                    cidr_ptrs.push(std::ptr::null());

                    // Allow-host list + trusted resolver, only when hosts are set.
                    let host_cstrings: Vec<CString> = egress_hosts
                        .iter()
                        .map(|h| CString::new(h.as_str()).expect("host cannot contain null bytes"))
                        .collect();
                    let mut host_ptrs: Vec<*const libc::c_char> =
                        host_cstrings.iter().map(|s| s.as_ptr()).collect();
                    host_ptrs.push(std::ptr::null());

                    let resolver_cstring =
                        CString::new(crate::data::network::default_dns_addr().to_string())
                            .expect("resolver IP has no null bytes");
                    let resolver_ptrs: Vec<*const libc::c_char> =
                        vec![resolver_cstring.as_ptr(), std::ptr::null()];

                    let (host_arg, resolver_arg) = if egress_hosts.is_empty() {
                        (std::ptr::null(), std::ptr::null())
                    } else {
                        (host_ptrs.as_ptr(), resolver_ptrs.as_ptr())
                    };

                    if set_egress(ctx, cidr_ptrs.as_ptr(), host_arg, resolver_arg) < 0 {
                        krun_free_ctx(ctx);
                        return Err(Error::agent(
                            "set egress policy",
                            "krun_set_egress_policy failed",
                        ));
                    }
                }

                tracing::info!("network backend: tsi");
                None
            }
            EffectiveNetworkBackend::VirtioNet => {
                let add_net_unixstream = krun.add_net_unixstream.ok_or_else(|| {
                    Error::agent(
                        "configure virtio-net",
                        "libkrun does not expose krun_add_net_unixstream; update libkrun or use --net-backend tsi",
                    )
                })?;
                // virtio-net carries guest networking, but the host-guest control
                // channel still rides vsock. Upstream libkrun no longer creates an
                // implicit vsock, so add it explicitly (no TSI hijacking — virtio-net
                // owns the network path); otherwise krun_add_vsock_port2 below fails
                // with ENODEV.
                if krun_add_vsock(ctx, 0) < 0 {
                    krun_free_ctx(ctx);
                    return Err(Error::agent("configure vsock", "krun_add_vsock failed"));
                }

                let mut guest_network = GuestNetworkConfig::default();
                // A custom resolver (--dns) becomes the gateway's upstream: the
                // guest still points at the gateway (100.96.0.1), which forwards
                // queries to this address instead of the default.
                if let Some(dns) = resources.dns {
                    guest_network.upstream_dns = dns;
                }
                let mut guest_mac = guest_network.guest_mac;

                let virtio_port_mappings: Vec<VirtioPortMapping> = port_mappings
                    .iter()
                    .map(|mapping| VirtioPortMapping::new(mapping.host, mapping.guest))
                    .collect();
                let egress = smolvm_network::EgressPolicy::new(
                    resources.allowed_cidrs.as_deref(),
                    egress_refresh_hosts.as_deref(),
                );
                let egress_path = egress_telemetry.map(|p| p.to_path_buf());

                // The host and guest ends of the virtio-net channel are an AF_UNIX
                // stream. On Unix we hand libkrun one end of a socketpair fd and run
                // the gateway on the other immediately. Windows has no socketpair
                // for AF_UNIX, so we bind a listener on a per-VM path, hand libkrun
                // the path, and accept its connection (made when the VM boots inside
                // the blocking `krun_start_enter`) on a background thread.
                #[cfg(unix)]
                {
                    let (host_fd, guest_fd) = create_unix_stream_pair().map_err(|e| {
                        Error::agent("configure virtio-net", format!("socketpair failed: {e}"))
                    })?;
                    // SAFETY: ownership of the host-side socketpair fd transfers
                    // here (already inside the function's outer `unsafe` block).
                    let host_stream = Socket::from_raw_fd(host_fd);
                    let runtime = match start_virtio_network(
                        host_stream,
                        guest_network,
                        &virtio_port_mappings,
                        egress,
                    ) {
                        Ok(runtime) => runtime,
                        Err(err) => {
                            libc::close(guest_fd);
                            krun_free_ctx(ctx);
                            return Err(Error::agent(
                                "configure virtio-net",
                                format!("failed to start virtio network runtime: {err}"),
                            ));
                        }
                    };

                    if add_net_unixstream(
                        ctx,
                        std::ptr::null(),
                        guest_fd,
                        guest_mac.as_mut_ptr(),
                        COMPAT_NET_FEATURES,
                        0,
                    ) < 0
                    {
                        libc::close(guest_fd);
                        krun_free_ctx(ctx);
                        return Err(Error::agent(
                            "configure virtio-net",
                            "krun_add_net_unixstream failed",
                        ));
                    }

                    // Flush this NIC's egress counter to the per-VM dir so serve can
                    // bill it (parity with how disk size reaches the node API).
                    if let Some(path) = egress_path {
                        crate::agent::manager::spawn_egress_flush(path, runtime.egress_counter());
                    }
                    virtio_network_runtime = Some(runtime);
                }
                #[cfg(windows)]
                {
                    // Per-VM AF_UNIX path for the net channel, a sibling of the
                    // agent-control vsock socket (already a working AF_UNIX path).
                    let net_sock_path = vsock_socket.with_extension("net");
                    let listener = bind_unix_listener(&net_sock_path).map_err(|e| {
                        krun_free_ctx(ctx);
                        Error::agent(
                            "configure virtio-net",
                            format!("failed to bind virtio-net socket: {e}"),
                        )
                    })?;
                    let path_c = try_or_free_ctx!(
                        path_to_cstring(&net_sock_path),
                        "configure virtio-net",
                        "virtio-net socket path contains null byte"
                    );
                    if add_net_unixstream(
                        ctx,
                        path_c.as_ptr(),
                        -1,
                        guest_mac.as_mut_ptr(),
                        COMPAT_NET_FEATURES,
                        0,
                    ) < 0
                    {
                        krun_free_ctx(ctx);
                        return Err(Error::agent(
                            "configure virtio-net",
                            "krun_add_net_unixstream failed",
                        ));
                    }

                    // libkrun connects to the path while the VM boots inside the
                    // blocking krun_start_enter, so accept on a background thread.
                    // The accepted runtime owns its worker threads and parks here
                    // until libkrun closes the stream (VM exit) for a clean teardown.
                    let spawn = std::thread::Builder::new()
                        .name("smolvm-net-accept".into())
                        .spawn(move || match listener.accept() {
                            Ok((sock, _)) => match start_virtio_network(
                                sock,
                                guest_network,
                                &virtio_port_mappings,
                                egress,
                            ) {
                                Ok(runtime) => {
                                    if let Some(path) = egress_path {
                                        crate::agent::manager::spawn_egress_flush(
                                            path,
                                            runtime.egress_counter(),
                                        );
                                    }
                                    runtime.block_until_shutdown();
                                }
                                Err(err) => {
                                    tracing::error!(error = %err, "virtio-net runtime failed to start");
                                }
                            },
                            Err(err) => {
                                tracing::warn!(error = %err, "virtio-net accept failed");
                            }
                        });
                    if let Err(e) = spawn {
                        krun_free_ctx(ctx);
                        return Err(Error::agent(
                            "configure virtio-net",
                            format!("failed to spawn virtio-net accept thread: {e}"),
                        ));
                    }
                }

                tracing::info!("network backend: virtio-net");
                Some(guest_network)
            }
        };

        // Add storage disk (critical - VM needs storage to function)
        // This is the first disk → /dev/vda in guest
        let block_id = cstr("storage");
        let disk_path = try_or_free_ctx!(
            path_to_cstring(disks.storage.path()),
            "add storage disk",
            "path contains null byte"
        );
        let storage_format = disks.storage.format().to_krun_u32();
        if krun_add_disk2(
            ctx,
            block_id.as_ptr(),
            disk_path.as_ptr(),
            storage_format,
            false,
        ) < 0
        {
            krun_free_ctx(ctx);
            return Err(Error::agent(
                "add storage disk",
                "krun_add_disk2 failed - VM cannot function without storage",
            ));
        }

        // Add overlay disk for persistent rootfs changes (optional)
        // This is the second disk → /dev/vdb in guest
        if let Some(overlay) = disks.overlay {
            let overlay_id = cstr("overlay");
            let overlay_path = try_or_free_ctx!(
                path_to_cstring(overlay.path()),
                "add overlay disk",
                "path contains null byte"
            );
            let overlay_format = overlay.format().to_krun_u32();
            if krun_add_disk2(
                ctx,
                overlay_id.as_ptr(),
                overlay_path.as_ptr(),
                overlay_format,
                false,
            ) < 0
            {
                krun_free_ctx(ctx);
                return Err(Error::agent(
                    "add overlay disk",
                    "krun_add_disk2 failed for rootfs overlay",
                ));
            }
        }

        // Add extra disks (e.g., source VM storage for --from-vm export)
        // These appear as /dev/vdc, /dev/vdd, ... after storage and overlay
        for (i, (disk_path, read_only, format)) in extra_disks.iter().enumerate() {
            let block_id_str = format!("extra{}", i);
            let block_id = try_or_free_ctx!(
                CString::new(block_id_str.as_str()),
                "add extra disk",
                "block id contains null byte"
            );
            let path = try_or_free_ctx!(
                path_to_cstring(disk_path),
                "add extra disk",
                "path contains null byte"
            );
            if krun_add_disk2(
                ctx,
                block_id.as_ptr(),
                path.as_ptr(),
                format.to_krun_u32(),
                *read_only,
            ) < 0
            {
                krun_free_ctx(ctx);
                return Err(Error::agent(
                    "add extra disk",
                    format!("krun_add_disk2 failed for extra disk {}", i),
                ));
            }
            tracing::debug!(disk = i, path = %disk_path.display(), read_only, "added extra disk");
        }

        // Add vsock port for control channel (critical - host-guest communication)
        let socket_path = try_or_free_ctx!(
            path_to_cstring(vsock_socket),
            "add vsock port",
            "path contains null byte"
        );
        if krun_add_vsock_port2(ctx, ports::AGENT_CONTROL, socket_path.as_ptr(), true) < 0 {
            krun_free_ctx(ctx);
            return Err(Error::agent(
                "add vsock port",
                "krun_add_vsock_port2 failed - control channel required for host-guest communication",
            ));
        }

        // Guest↔host vsock services (SSH agent, DNS filter, CUDA, …). The set
        // and its wiring live in `vsock_service`; here we just register the
        // port for each one enabled for this launch. Adding a capability needs
        // no new control flow in this function. The `active_vsock` set is reused
        // below to inject each service's guest-side activation env vars, so the
        // host and guest sides cannot drift.
        let vsock_inputs = vsock_service::VsockServiceInputs {
            ssh_agent_socket: ssh_agent_socket.as_deref(),
            dns_filter_socket: dns_filter_socket.as_deref(),
            cuda_socket: cuda_socket.as_deref(),
        };
        let active_vsock: Vec<_> = vsock_service::registry()
            .iter()
            .filter_map(|svc| svc.resolve(&vsock_inputs))
            .collect();
        for svc in &active_vsock {
            // An egress port must never shadow the required control channel.
            debug_assert_ne!(
                svc.port,
                ports::AGENT_CONTROL,
                "{} would shadow the agent control channel",
                svc.name
            );
            let sock_path = try_or_free_ctx!(
                path_to_cstring(svc.socket),
                "add vsock port",
                "path contains null byte"
            );
            if krun_add_vsock_port2(ctx, svc.port, sock_path.as_ptr(), svc.listen) < 0 {
                tracing::warn!(
                    "failed to add {} vsock port {} — disabled",
                    svc.name,
                    svc.port
                );
            } else {
                tracing::info!("{} enabled on vsock port {}", svc.name, svc.port);
            }
        }

        // Redirect console output to a file if specified, via the upstream
        // virtio-console API (krun_set_console_output was removed).
        if let Some(log_path) = console_log {
            if krun.console_output_to_file(ctx, log_path) < 0 {
                tracing::warn!("failed to set console output");
            }
        }

        // Register a control socket (pause/resume/checkpoint/restore) when
        // requested via SMOLVM_CONTROL_SOCKET. Best-effort: a missing symbol
        // (older libkrun) or a failure just leaves the VM without a control
        // channel rather than aborting the boot.
        if let Ok(ctl_path) = std::env::var("SMOLVM_CONTROL_SOCKET") {
            if !ctl_path.is_empty() {
                match krun.set_control_socket {
                    Some(set_control_socket) => match CString::new(ctl_path.clone()) {
                        Ok(ctl_c) => {
                            let ret = set_control_socket(ctx, ctl_c.as_ptr());
                            if ret < 0 {
                                tracing::warn!("krun_set_control_socket failed: {ret}");
                            } else {
                                tracing::info!(socket = %ctl_path, "control socket enabled");
                            }
                        }
                        Err(_) => tracing::warn!("control socket path contains null byte"),
                    },
                    None => tracing::warn!(
                        "SMOLVM_CONTROL_SOCKET set but libkrun lacks krun_set_control_socket"
                    ),
                }
            }
        }

        // Fork clone: boot from a snapshot dir (CoW-map a golden VM's RAM +
        // restore state) instead of cold-booting, when SMOLVM_SNAPSHOT_DIR is set.
        if let Ok(snap_dir) = std::env::var("SMOLVM_SNAPSHOT_DIR") {
            if !snap_dir.is_empty() {
                match krun.set_snapshot {
                    Some(set_snapshot) => match CString::new(snap_dir.clone()) {
                        Ok(dir_c) => {
                            let ret = set_snapshot(ctx, dir_c.as_ptr());
                            if ret < 0 {
                                tracing::error!("krun_set_snapshot failed: {ret}");
                            } else {
                                tracing::info!(dir = %snap_dir, "booting as fork clone from snapshot");
                            }
                        }
                        Err(_) => tracing::warn!("snapshot dir contains null byte"),
                    },
                    None => tracing::warn!(
                        "SMOLVM_SNAPSHOT_DIR set but libkrun lacks krun_set_snapshot"
                    ),
                }
            }
        }

        // Add virtiofs mounts
        // Each mount gets a tag like "smolvm0", "smolvm1", etc.
        // The guest must mount these manually (or via the agent)
        for (i, mount) in mounts.iter().enumerate() {
            let mount_tag = HostMount::mount_tag(i);
            let tag = try_or_free_ctx!(
                CString::new(mount_tag.clone()),
                "configure mount",
                "mount tag contains null byte"
            );
            let host_path = try_or_free_ctx!(
                path_to_cstring(&mount.source),
                "configure mount",
                "mount path contains null byte"
            );

            tracing::debug!(
                tag = %mount_tag,
                host = %mount.source.display(),
                guest = %mount.target.display(),
                read_only = mount.read_only,
                "adding virtiofs mount"
            );

            if krun_add_virtiofs(ctx, tag.as_ptr(), host_path.as_ptr()) < 0 {
                krun_free_ctx(ctx);
                return Err(Error::agent(
                    "add virtiofs mount",
                    format!(
                        "krun_add_virtiofs failed for '{}' - requested mount cannot be attached",
                        mount.source.display()
                    ),
                ));
            }
        }

        // Mount pre-extracted OCI layers for .smolmachine-sourced machines.
        // The agent detects this via SMOLVM_PACKED_LAYERS and uses the layers
        // as container overlay lowerdirs instead of pulling from a registry.
        if let Some(layers_dir) = packed_layers_dir {
            if layers_dir.exists() {
                let tag = cstr("smolvm_layers");
                let host_path = path_to_cstring(layers_dir)?;
                if krun_add_virtiofs(ctx, tag.as_ptr(), host_path.as_ptr()) < 0 {
                    krun_free_ctx(ctx);
                    return Err(Error::agent(
                        "add packed layers virtiofs",
                        "krun_add_virtiofs failed for packed layers",
                    ));
                }
            } else {
                // packed_layers_dir was set — which only happens after
                // `with_packed_layers` acquired the lease — but the directory is
                // not on disk at mount time. On macOS that means the per-machine
                // case-sensitive layers volume isn't mounted (e.g. a concurrent
                // stop/delete detached it). Mounting nothing would silently fall
                // the guest back to a registry pull and break offline runs, and the
                // launcher has no path to re-extract or re-mount here. Rather than
                // boot a VM that is doomed to fail offline, free the context and
                // fail fast with an actionable error.
                krun_free_ctx(ctx);
                return Err(Error::agent(
                    "add packed layers virtiofs",
                    format!(
                        "packed layers directory not found at {}: this machine's \
                         layers volume is not mounted, so the guest cannot use its \
                         bundled image and an offline run would fail. Restart the \
                         machine, or re-create it from the .smolmachine bundle.",
                        layers_dir.display()
                    ),
                ));
            }
        }

        boot_timing!("devices configured");

        // Set working directory
        let workdir = cstr("/");
        krun_set_workdir(ctx, workdir.as_ptr());

        // Build environment
        let mut env_strings = vec![
            cstr("HOME=/root"),
            cstr("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
            cstr("TERM=xterm-256color"),
        ];

        // Host wall-clock at launch, so the agent can seed the guest clock on
        // hypervisors without a guest-readable paravirt clock (WHP/Windows). The
        // agent ignores it unless its own clock looks obviously wrong.
        if let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            env_strings.push(cstr(&format!(
                "{}={}",
                guest_env::HOST_TIME_NS,
                now.as_nanos()
            )));
        }

        // Pass mount info to the agent via environment
        // Format: SMOLVM_MOUNT_0=tag:guest_path:ro
        for (i, mount) in mounts.iter().enumerate() {
            let mount_tag = HostMount::mount_tag(i);
            let ro_flag = if mount.read_only { "ro" } else { "rw" };
            let env_val = format!(
                "SMOLVM_MOUNT_{}={}:{}:{}",
                i,
                mount_tag,
                mount.target.display(),
                ro_flag
            );
            if let Ok(cstr) = CString::new(env_val) {
                env_strings.push(cstr);
            }
        }

        // Pass mount count
        if !mounts.is_empty() {
            if let Ok(cstr) = CString::new(format!("SMOLVM_MOUNT_COUNT={}", mounts.len())) {
                env_strings.push(cstr);
            }
        }

        // Activate the guest side of each enabled vsock service (e.g. tell the
        // agent to start the SSH agent bridge). The env pairs come from the same
        // registry that wired the ports above, so the two sides cannot diverge.
        for svc in &active_vsock {
            for (key, value) in svc.guest_env {
                env_strings.push(cstr(&format!("{key}={value}")));
            }
        }

        // Tell the agent GPU was requested so it can sanity-check the
        // virtio-gpu device actually appeared in the guest. libkrun
        // happily accepts `krun_set_gpu_options2` even if the embedded
        // kernel lacks the driver; without this check the user sees
        // "VM started" and discovers missing GPU only when their
        // workload hits a rendering call.
        if resources.gpu {
            let gpu_env = format!("{}={}", guest_env::GPU, guest_env::VALUE_ON);
            if let Ok(cs) = CString::new(gpu_env) {
                env_strings.push(cs);
            }
        }

        // Forward this VM's per-VM readiness-marker name into the guest env (the
        // manager set it on this boot subprocess) so the agent writes the marker
        // the host pre-created and polls. See manager::ready_marker_name.
        if let Ok(marker) = std::env::var(guest_env::READY_MARKER) {
            env_strings.push(cstr(&format!("{}={}", guest_env::READY_MARKER, marker)));
        }

        // DNS allow-host filtering is now enforced inside libkrun (see the
        // egress policy above). The guest-side DNS proxy is intentionally NOT
        // started: the guest keeps its default resolv.conf (1.1.1.1/8.8.8.8) so
        // its UDP DNS queries leave as real datagrams and are intercepted at the
        // TSI layer. The DNS-filter vsock port is still registered (above, via
        // the service registry) for the host-side proxy.

        // Guest-network env vars — virtio-net interface config plus the TSI
        // `--dns` override — are built in one shared place so the static and
        // dynamic launchers can't diverge (see `agent::guest_network_env`).
        env_strings.extend(crate::agent::guest_network_env(
            guest_network,
            resources.dns,
        ));

        // Tell the agent about pre-extracted packed layers
        if packed_layers_dir.is_some_and(|d| d.exists()) {
            env_strings.push(cstr("SMOLVM_PACKED_LAYERS=smolvm_layers:/packed_layers"));
        }

        let mut envp: Vec<*const libc::c_char> = env_strings.iter().map(|s| s.as_ptr()).collect();
        envp.push(std::ptr::null());

        // Set exec command (/sbin/init)
        let exec_path = cstr("/sbin/init");
        let argv_strings = [cstr("/sbin/init")];
        let mut argv: Vec<*const libc::c_char> = argv_strings.iter().map(|s| s.as_ptr()).collect();
        argv.push(std::ptr::null());

        if krun_set_exec(ctx, exec_path.as_ptr(), argv.as_ptr(), envp.as_ptr()) < 0 {
            krun_free_ctx(ctx);
            return Err(Error::agent("set exec command", "krun_set_exec failed"));
        }

        // Egress CIDR live-refresh thread.
        //
        // Re-resolves DNS filter hostnames every SMOLVM_EGRESS_REFRESH_SECS
        // (default 5 min) and atomically replaces the Arc<RwLock<Vec<...>>>
        // that the vsock muxer reads on every packet. The Arc is borrowed from
        // libkrun via `krun_get_egress_handle` — see libkrun/src/libkrun/src/lib.rs.
        //
        // Each cycle: resolve all hosts → build fresh list → single write-lock
        // swap. If all hosts fail to resolve, the previous list is kept intact.
        if let Some(hosts) = egress_refresh_hosts.as_ref().filter(|h| !h.is_empty()) {
            if let Some(krun_get_egress_handle) = krun.get_egress_handle {
                let raw_handle = krun_get_egress_handle(ctx);

                if !raw_handle.is_null() {
                    let arc: EgressArc = *Box::from_raw(raw_handle as *mut EgressArc);
                    let hosts_copy = hosts.clone();
                    if let Err(e) = std::thread::Builder::new()
                        .name("egress-refresh".into())
                        .spawn(move || {
                            let refresh_secs: u64 = std::env::var("SMOLVM_EGRESS_REFRESH_SECS")
                                .ok()
                                .and_then(|s| s.parse().ok())
                                .unwrap_or(5 * 60);
                            let refresh_interval = std::time::Duration::from_secs(refresh_secs);
                            loop {
                                std::thread::sleep(refresh_interval);
                                // Resolve all hosts into a fresh list, then swap
                                // the shared Vec in a single write-lock acquisition.
                                // This ensures old rotated-away IPs are removed.
                                let mut fresh: Vec<(std::net::IpAddr, u8)> = Vec::new();
                                'hosts: for host in &hosts_copy {
                                    match resolve_host_subprocess(host) {
                                        Ok(new_cidrs) => {
                                            for cidr_str in new_cidrs {
                                                if fresh.len() >= EGRESS_CIDR_CAP {
                                                    break 'hosts;
                                                }
                                                if let Some((ip_str, prefix_str)) =
                                                    cidr_str.split_once('/')
                                                {
                                                    if let (Ok(ip), Ok(prefix)) = (
                                                        ip_str.parse::<std::net::IpAddr>(),
                                                        prefix_str.parse::<u8>(),
                                                    ) {
                                                        if !fresh.contains(&(ip, prefix)) {
                                                            fresh.push((ip, prefix));
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!(
                                                host = %host,
                                                error = %e,
                                                "egress-refresh: resolve failed"
                                            );
                                        }
                                    }
                                }
                                // Only replace if at least one host resolved
                                // successfully; keeps the old list on total failure.
                                if !fresh.is_empty() {
                                    let mut guard = arc.write().unwrap_or_else(|e| e.into_inner());
                                    *guard = fresh;
                                }
                            }
                        })
                    {
                        tracing::warn!(error = %e, "egress-refresh spawn failed");
                    }
                }
            }
        }

        // Start VM (this replaces the process on success)
        boot_timing!("entering vm");
        let ret = krun_start_enter(ctx);

        // If we get here, something went wrong — free the context before returning
        krun_free_ctx(ctx);
        drop(virtio_network_runtime);
        Err(Error::agent(
            "start vm",
            format!("krun_start_enter returned: {}", ret),
        ))
    }
}

/// Create a CString from a static string that is known not to contain NUL bytes.
fn cstr(s: &str) -> CString {
    CString::new(s).expect("string literal must not contain NUL bytes")
}

/// Convert a Path to a CString.
fn path_to_cstring(path: &Path) -> Result<CString> {
    CString::new(path.to_string_lossy().as_bytes())
        .map_err(|_| Error::agent("convert path", "path contains null byte"))
}

fn rootfs_dax_disabled() -> bool {
    std::env::var(ENV_SMOLVM_ROOTFS_DAX)
        .map(|value| {
            matches!(
                value.as_str(),
                "0" | "false" | "False" | "FALSE" | "no" | "off"
            )
        })
        .unwrap_or(false)
}

// Unix-only: virtio-net is the sole caller and is itself unix-gated.
#[cfg(unix)]
fn create_unix_stream_pair() -> std::io::Result<(RawFd, RawFd)> {
    let mut fds = [0; 2];
    // SAFETY: `socketpair` initializes both descriptors on success.
    let result = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    if result < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((fds[0], fds[1]))
}

// Windows has no AF_UNIX `socketpair`, so the virtio-net host end binds a
// listener on a per-VM path and accepts the connection libkrun makes to it.
#[cfg(windows)]
pub(crate) fn bind_unix_listener(path: &Path) -> std::io::Result<Socket> {
    // A leftover socket file from a previous run would make bind fail with
    // EADDRINUSE, so clear it first (ignore "not found").
    let _ = std::fs::remove_file(path);
    let listener = Socket::new(Domain::UNIX, Type::STREAM, None)?;
    listener.bind(&SockAddr::unix(path)?)?;
    listener.listen(1)?;
    Ok(listener)
}

fn select_network_plan(
    resources: &VmResources,
    dns_filter_enabled: bool,
    port_count: usize,
) -> crate::network::LaunchNetworkPlan {
    let dns_filter_placeholder = [String::from("configured")];
    let dns_filter_hosts = dns_filter_enabled.then_some(dns_filter_placeholder.as_slice());
    plan_launch_network(resources, dns_filter_hosts, port_count)
}

/// Resolve a hostname to /32 CIDR strings for the egress-refresh thread.
///
/// ## Why not `getaddrinfo`?
///
/// The `egress-refresh` thread runs inside the `_boot-vm` subprocess. Before
/// `krun_start_enter` is called, `internal_boot.rs` closes every inherited FD
/// from 3 up to `max_fd`. Apple's Network framework maps shared memory at
/// process launch and accesses it via FD-derived handles. After the mass close,
/// those handles are invalid, so any call to `getaddrinfo` (which routes
/// through the Network framework on macOS) crashes with SIGBUS at
/// `_os_log_preferences_refresh` inside `nw_path_libinfo_path_check`.
///
/// Spawning an external `dig` process sidesteps this: `exec()` gives the child
/// a completely fresh address space, so it never touches the broken inherited
/// shared memory. On non-macOS platforms `getaddrinfo` via glibc is safe and
/// is used directly.
#[cfg(target_os = "macos")]
#[inline(never)]
fn resolve_host_subprocess(host: &str) -> std::result::Result<Vec<String>, String> {
    // `/usr/bin/dig` is always present on macOS (part of BIND-tools in the
    // base system). `+short` prints one result per line (IPs and CNAMEs);
    // `+timeout=5 +tries=2` keeps the refresh loop from stalling the VM on
    // a flaky network.
    let output = std::process::Command::new("/usr/bin/dig")
        .args(["+short", "+timeout=5", "+tries=2", host])
        .output()
        .map_err(|e| format!("dig subprocess failed for '{}': {}", host, e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    // `+short` emits CNAMEs (ending in '.') interleaved with IPs; parse::<IpAddr>
    // silently skips the CNAME lines, leaving only valid addresses.
    let cidrs: Vec<String> = stdout
        .lines()
        .filter_map(|line| {
            line.trim()
                .parse::<std::net::IpAddr>()
                .ok()
                .map(|ip| format!("{}/32", ip))
        })
        .collect();

    if cidrs.is_empty() {
        return Err(format!("dig resolved '{}' to no IP addresses", host));
    }
    Ok(cidrs)
}

/// On non-macOS (Linux), `getaddrinfo` is safe to call from background threads
/// in child processes — glibc does not use shared-memory handles that become
/// invalid after a mass FD close. Delegate directly to the standard resolver.
#[cfg(not(target_os = "macos"))]
#[inline(never)]
fn resolve_host_subprocess(host: &str) -> std::result::Result<Vec<String>, String> {
    crate::smolfile::resolve_host_to_cidrs(host)
}

/// Raise file descriptor limits (required by libkrun).
fn raise_fd_limits() {
    // rlimit is a unix concept; no-op on Windows. The function stays callable
    // on all platforms so its (unconditional) call sites need no gating.
    #[cfg(unix)]
    unsafe {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };

        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) == 0 {
            limit.rlim_cur = limit.rlim_max;
            libc::setrlimit(libc::RLIMIT_NOFILE, &limit);
        }
    }
}
