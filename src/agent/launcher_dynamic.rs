//! Dynamic (dlopen-based) libkrun launcher for packed/sidecar mode.
//!
//! This module provides a `KrunFunctions` struct that loads libkrun via `dlopen`
//! at runtime, enabling the main smolvm binary to boot VMs using libraries
//! extracted from a `.smolmachine` sidecar file.
//!
//! The static FFI path in `launcher.rs` remains untouched for normal operations.

use crate::network::backend::COMPAT_NET_FEATURES;
use crate::network::backend::TSI_FEATURE_HIJACK_INET;
use crate::network::{plan_launch_network, EffectiveNetworkBackend};
use smolvm_network::PortMapping as VirtioPortMapping;
use smolvm_network::{start_virtio_network, GuestNetworkConfig, VirtioNetworkRuntime};
use smolvm_protocol::{guest_env, ports};
#[cfg(unix)]
use socket2::Socket;
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

pub use super::krun::KrunFunctions;
use super::VmResources;

/// Volume mount for packed binaries.
#[derive(Debug, Clone)]
pub struct PackedMount {
    /// Virtiofs tag (e.g., "smolvm0").
    pub tag: String,
    /// Host source path (passed to `krun_add_virtiofs`).
    pub host_path: String,
    /// Guest mount path (passed to agent via `SMOLVM_MOUNT_*` env).
    pub guest_path: String,
    /// Whether the mount is read-only.
    pub read_only: bool,
}

/// Configuration for launching a packed VM.
pub struct PackedLaunchConfig<'a> {
    /// Path to agent rootfs directory.
    pub rootfs_path: &'a Path,
    /// Path to storage disk.
    pub storage_path: &'a Path,
    /// Path to vsock Unix socket.
    pub vsock_socket: &'a Path,
    /// Path to layers directory (for virtiofs).
    pub layers_dir: &'a Path,
    /// Volume mounts.
    pub mounts: &'a [PackedMount],
    /// Port mappings (host, guest).
    pub port_mappings: &'a [(u16, u16)],
    /// VM resources.
    pub resources: VmResources,
    /// Debug logging.
    pub debug: bool,
    /// Path to overlay disk (VM mode only, mounted as /dev/vdb).
    pub overlay_path: Option<&'a Path>,
    /// Path to redirect VM console output (prevents libkrun from putting
    /// the inherited terminal into raw mode).
    pub console_log: PathBuf,
    /// Host CUDA-over-vsock server socket. When set, the guest's CUDA client
    /// (vsock port [`ports::CUDA`]) is bridged to this AF_UNIX path, where a
    /// `cuda_host` server loaded the real driver. Mirrors the non-packed
    /// launcher's `cuda_socket`.
    pub cuda_socket: Option<&'a Path>,
    /// Hostnames the egress policy permits resolving and connecting to
    /// (`--allow-host`), mirroring the main launcher's `egress_refresh_hosts`.
    /// Owned because the launch runs in a forked child that outlives the
    /// caller's borrows.
    pub dns_filter_hosts: Option<Vec<String>>,
}

/// The `krun_add_disk2` image-format code for a disk file: `1` (qcow2) when it
/// begins with the qcow2 magic (`QFI\xfb`), else `0` (raw). Matches
/// `DiskFormat::to_krun_u32`. Reading the bytes keeps the format in sync with
/// what libkrun will parse, regardless of the file's extension.
fn krun_disk_format(path: &Path) -> u32 {
    use std::io::Read;
    const QCOW2_MAGIC: [u8; 4] = [0x51, 0x46, 0x49, 0xfb];
    let mut magic = [0u8; 4];
    let is_qcow2 = std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut magic))
        .is_ok()
        && magic == QCOW2_MAGIC;
    if is_qcow2 {
        1
    } else {
        0
    }
}

/// Launch VM using dynamically loaded libkrun (for packed/sidecar mode).
///
/// This mirrors the setup logic in `launcher.rs:launch_agent_vm()` but calls
/// through `KrunFunctions` instead of static `extern "C"` symbols.
///
/// # Safety
///
/// Must be called in a forked child process. Never returns on success.
pub fn launch_agent_vm_dynamic(
    krun: &KrunFunctions,
    config: &PackedLaunchConfig,
) -> Result<(), String> {
    crate::network::validate_requested_network_backend(
        &config.resources,
        config.dns_filter_hosts.as_deref(),
        config.port_mappings.len(),
    )
    .map_err(|e| e.to_string())?;

    // Raise file descriptor limits
    raise_fd_limits();

    // Set library path so libkrun can find libkrunfw. Only consumed by the
    // macos/linux env-var blocks below, so unused on other targets (Windows).
    #[cfg_attr(
        not(any(target_os = "macos", target_os = "linux")),
        allow(unused_variables)
    )]
    let lib_dir = config
        .rootfs_path
        .parent()
        .unwrap_or(Path::new("."))
        .join("lib");
    #[cfg(target_os = "macos")]
    {
        let lib_path = lib_dir.to_string_lossy();
        unsafe { std::env::set_var("DYLD_LIBRARY_PATH", lib_path.as_ref()) };
    }
    #[cfg(target_os = "linux")]
    {
        let lib_path = lib_dir.to_string_lossy();
        unsafe { std::env::set_var("LD_LIBRARY_PATH", lib_path.as_ref()) };
    }

    // SAFETY: Each FFI call below is individually wrapped in unsafe.
    // All CString/pointer construction is safe Rust outside the unsafe blocks.

    if config.resources.gpu {
        krun.ensure_gpu_runtime()?;
    }

    // Set log level (0 = off, 1 = error, 2 = warn, 3 = info, 4 = debug).
    // Honor SMOLVM_KRUN_LOG_LEVEL like the non-packed launcher so a packed VM's
    // boot can be traced; otherwise fall back to info under --debug.
    let log_level = std::env::var(crate::data::consts::ENV_SMOLVM_KRUN_LOG_LEVEL)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(if config.debug { 3 } else { 0 });
    // SAFETY: set_log_level is a valid function pointer loaded from libkrun
    unsafe { (krun.set_log_level)(log_level) };

    // Create VM context
    // SAFETY: create_ctx is a valid function pointer loaded from libkrun
    let ctx = unsafe { (krun.create_ctx)() };
    if ctx < 0 {
        return Err("krun_create_ctx failed".to_string());
    }
    let ctx = ctx as u32;

    // Helper: clean up context on error (string message)
    macro_rules! free_ctx_on_err {
        ($msg:expr) => {{
            // SAFETY: ctx is a valid context from krun_create_ctx
            unsafe { (krun.free_ctx)(ctx) };
            return Err($msg.to_string());
        }};
    }

    // Helper: evaluate a fallible expression, freeing ctx if it fails.
    // Replaces bare `?` which would leak the libkrun context.
    macro_rules! try_or_free_ctx {
        ($expr:expr, $msg:expr) => {
            match $expr {
                Ok(val) => val,
                Err(_) => free_ctx_on_err!($msg),
            }
        };
    }

    // Set VM config
    // SAFETY: ctx is valid, cpus and mem are primitive values
    if unsafe { (krun.set_vm_config)(ctx, config.resources.cpus, config.resources.memory_mib) } < 0
    {
        free_ctx_on_err!("krun_set_vm_config failed");
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        let cpu_profile_result = unsafe { (krun.set_cpu_template)(ctx, 1) };
        if cpu_profile_result < 0 && cpu_profile_result != -libc::ENOTSUP {
            free_ctx_on_err!("libkrun does not support the portable CPU profile");
        }
    }

    // Enable GPU (virtio-gpu / Venus Vulkan) when requested by the manifest.
    // Flag logic lives in super::gpu_virgl_flags() — see mod.rs for the full
    // explanation of each flag's purpose on Linux vs macOS.
    if config.resources.gpu {
        let virgl_flags = super::gpu_virgl_flags();
        let vram_mib = config.resources.effective_gpu_vram_mib();
        let vram_bytes: u64 = (vram_mib as u64) * crate::data::consts::BYTES_PER_MIB;

        match krun.set_gpu_options2 {
            Some(set_gpu) => {
                let ret = unsafe { set_gpu(ctx, virgl_flags, vram_bytes) };
                if ret < 0 {
                    free_ctx_on_err!(format!(
                        "krun_set_gpu_options2 failed (ret={}). Check that virglrenderer is installed.",
                        ret
                    ));
                }
                tracing::info!("GPU enabled (Venus/Vulkan via virtio-gpu)");

                // Optional virtio-gpu scanout. Venus gives the guest GPU
                // *rendering*; a scanout gives it a *display*. Without one the
                // device reports num_scanouts = 0, so the guest sees no
                // connector and card0 is render-only — which is why DRM
                // compositors fail with "not a KMS device". Opt-in for now:
                // adding a connector changes guest topology, and existing GPU
                // workloads (CUDA, headless Vulkan) neither need nor want one.
                if let Some((w, h)) =
                    super::parse_display_size(std::env::var("SMOLVM_DISPLAY").ok().as_deref())
                {
                    super::default_gpu_backend_for_display();
                    match krun.add_display {
                        Some(add_display) => {
                            let ret = unsafe { add_display(ctx, w, h) };
                            if ret < 0 {
                                free_ctx_on_err!(format!(
                                    "krun_add_display({w}x{h}) failed (ret={ret})"
                                ));
                            }
                            tracing::info!(
                                width = w,
                                height = h,
                                display_id = ret,
                                "virtio-gpu scanout added (guest gets a KMS connector)"
                            );

                            // A described display is not a usable one. With no
                            // backend to consume frames libkrun installs a
                            // no-op that fails every scanout call, so the
                            // guest's first page flip never completes and a
                            // compositor blocks on it forever.
                            let Some(set_backend) = krun.set_display_backend else {
                                free_ctx_on_err!(
                                    "SMOLVM_DISPLAY set but this libkrun has no \
                                     krun_set_display_backend; without it the guest \
                                     would hang on its first page flip"
                                );
                            };
                            let framebuffer = match crate::agent::display::install(set_backend, ctx)
                            {
                                Ok(fb) => fb,
                                Err(e) => free_ctx_on_err!(e.to_string()),
                            };

                            // Serving RFB from the host means the guest needs
                            // no capture tool and no compositor-specific
                            // screencopy protocol.
                            if let Some(bind) = std::env::var("SMOLVM_VNC")
                                .ok()
                                .as_deref()
                                .and_then(crate::agent::vnc::parse_bind_addr)
                            {
                                // Input is best-effort: a libkrun without the
                                // input feature degrades to view-only rather
                                // than blocking the display.
                                let input = match krun.add_input_device {
                                    Some(add_input) => {
                                        match crate::agent::input::install(add_input, ctx) {
                                            Ok(i) => {
                                                tracing::info!(
                                                    "vnc input devices attached \
                                                     (keyboard + pointer)"
                                                );
                                                Some(i)
                                            }
                                            Err(e) => {
                                                tracing::warn!(
                                                    error = %e,
                                                    "vnc input unavailable; view-only"
                                                );
                                                None
                                            }
                                        }
                                    }
                                    None => {
                                        tracing::info!(
                                            "libkrun has no krun_add_input_device; \
                                             vnc is view-only"
                                        );
                                        None
                                    }
                                };
                                match crate::agent::vnc::serve(&bind, framebuffer, input) {
                                    Ok(addr) => tracing::info!(
                                        %addr,
                                        url = %crate::agent::vnc::browser_url(addr),
                                        "vnc server listening"
                                    ),
                                    // A failed viewer must not take down the
                                    // VM; the display works without it.
                                    Err(e) => tracing::warn!(
                                        bind = %bind,
                                        error = %e,
                                        "vnc server failed to start"
                                    ),
                                }
                            }
                        }
                        None => {
                            free_ctx_on_err!(
                                "SMOLVM_DISPLAY set but this libkrun has no krun_add_display"
                            );
                        }
                    }
                }
            }
            None => {
                free_ctx_on_err!(
                    "libkrun was built without GPU support (krun_set_gpu_options2 not found). \
                     Rebuild libkrun with GPU=1 — see project README for details."
                );
            }
        }
    }

    // Set root filesystem via the root virtiofs tag (upstream removed
    // krun_set_root in favor of krun_add_virtiofs with KRUN_FS_ROOT_TAG).
    let root = try_or_free_ctx!(
        path_to_cstring(config.rootfs_path),
        "rootfs path contains null byte"
    );
    let root_tag = cstr("/dev/root");
    // Default root with a 512 MB DAX window (matches the removed krun_set_root).
    // Plain krun_add_virtiofs passes shm_size=0 (no DAX), dropping virtiofs to
    // writeback caching so the guest's ready-marker write isn't visible to the
    // host until the socket-probe grace — a multi-second boot-time regression.
    let Some(add_virtiofs3) = krun.add_virtiofs3 else {
        free_ctx_on_err!("root DAX requires libkrun with krun_add_virtiofs3");
    };
    // SAFETY: ctx is valid; root_tag/root are valid null-terminated C strings.
    if unsafe { add_virtiofs3(ctx, root_tag.as_ptr(), root.as_ptr(), 1 << 29, false) } < 0 {
        free_ctx_on_err!("krun_add_virtiofs3 failed for root filesystem");
    }

    let network_plan = plan_launch_network(&config.resources, None, config.port_mappings.len());

    // `mut` is only needed on unix (the VirtioNet arm assigns it); on Windows
    // the runtime is owned by the accept thread, so the binding stays `None`.
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut virtio_network_runtime: Option<VirtioNetworkRuntime> = None;
    let guest_network: Option<GuestNetworkConfig> = match network_plan.backend {
        EffectiveNetworkBackend::None => {
            // Upstream libkrun no longer creates an implicit vsock; add explicitly.
            if unsafe { (krun.add_vsock)(ctx, 0) } < 0 {
                free_ctx_on_err!("krun_add_vsock failed");
            }
            tracing::debug!("configured vsock without guest networking");
            None
        }
        EffectiveNetworkBackend::Tsi => {
            if unsafe { (krun.add_vsock)(ctx, TSI_FEATURE_HIJACK_INET) } < 0 {
                free_ctx_on_err!("krun_add_vsock with TSI failed");
            }

            let port_cstrings: Vec<CString> = config
                .port_mappings
                .iter()
                .map(|(host, guest)| {
                    CString::new(format!("{}:{}", host, guest))
                        .expect("port mapping cannot contain null bytes")
                })
                .collect();
            let mut port_ptrs: Vec<*const libc::c_char> =
                port_cstrings.iter().map(|s| s.as_ptr()).collect();
            port_ptrs.push(std::ptr::null());

            if unsafe { (krun.set_port_map)(ctx, port_ptrs.as_ptr()) } < 0 {
                free_ctx_on_err!("krun_set_port_map failed");
            }

            // Egress policy: static CIDRs plus DNS allow-host filtering enforced
            // inside libkrun, mirroring the main launcher's TSI arm. When
            // allow-hosts are set, guest UDP:53 queries are forwarded only to the
            // trusted resolver and A/AAAA answers for allowed hosts become
            // temporarily allowed IPs.
            let egress_hosts = config.dns_filter_hosts.clone().unwrap_or_default();
            let has_cidrs = config
                .resources
                .allowed_cidrs
                .as_ref()
                .is_some_and(|cidrs| !cidrs.is_empty());
            if has_cidrs || !egress_hosts.is_empty() {
                let set_egress = krun.set_egress_policy.ok_or_else(|| {
                    "libkrun does not support egress policy (krun_set_egress_policy not found). \
                     Update libkrun or remove --allow-cidr/--allow-host flags."
                        .to_string()
                })?;

                let mut all_cidrs = config.resources.allowed_cidrs.clone().unwrap_or_default();
                crate::data::network::ensure_dns_in_cidrs(&mut all_cidrs);

                let cidr_cstrings: Vec<CString> = match all_cidrs
                    .iter()
                    .map(|c| CString::new(c.as_str()))
                    .collect::<std::result::Result<Vec<_>, _>>()
                {
                    Ok(v) => v,
                    Err(_) => free_ctx_on_err!("allow-CIDR contains an interior NUL byte"),
                };
                let mut cidr_ptrs: Vec<*const libc::c_char> =
                    cidr_cstrings.iter().map(|s| s.as_ptr()).collect();
                cidr_ptrs.push(std::ptr::null());

                let host_cstrings: Vec<CString> = match egress_hosts
                    .iter()
                    .map(|h| CString::new(h.as_str()))
                    .collect::<std::result::Result<Vec<_>, _>>()
                {
                    Ok(v) => v,
                    Err(_) => free_ctx_on_err!("allow-host contains an interior NUL byte"),
                };
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

                if unsafe { (set_egress)(ctx, cidr_ptrs.as_ptr(), host_arg, resolver_arg) } < 0 {
                    free_ctx_on_err!("krun_set_egress_policy failed");
                }
            }

            tracing::info!("network backend: tsi");
            None
        }
        EffectiveNetworkBackend::VirtioNet => {
            let add_net_unixstream = krun.add_net_unixstream.ok_or_else(|| {
                "libkrun does not expose krun_add_net_unixstream; update libkrun or use --net-backend tsi"
                    .to_string()
            })?;

            // virtio-net carries guest networking, but the host-guest control
            // channel still rides vsock. Upstream libkrun no longer creates an
            // implicit vsock, so add it explicitly (no TSI hijacking — virtio-net
            // owns the network path); otherwise krun_add_vsock_port2 below fails
            // with ENODEV.
            if unsafe { (krun.add_vsock)(ctx, 0) } < 0 {
                free_ctx_on_err!("krun_add_vsock failed");
            }

            let mut guest_network = GuestNetworkConfig::default();
            guest_network.host_service = crate::network::launch::guest_host_service()?;
            let mut guest_mac = guest_network.guest_mac;
            let port_mappings: Vec<VirtioPortMapping> = config
                .port_mappings
                .iter()
                .map(|(host, guest)| VirtioPortMapping::new(*host, *guest))
                .collect();
            // Denial sink beside the vsock socket, mirroring the static launcher.
            let mut egress = smolvm_network::EgressPolicy::new(
                config.resources.allowed_cidrs.as_deref(),
                config.dns_filter_hosts.as_deref(),
            );
            if let Some(dir) = config.vsock_socket.parent() {
                egress = egress.with_denial_log(dir.join(smolvm_network::EGRESS_DENIALS_LOG));
            }

            // The host/guest ends of the virtio-net channel are an AF_UNIX
            // stream: a socketpair fd on Unix, a per-VM path listener libkrun
            // connects to on Windows. Mirrors the static launcher's VirtioNet arm.
            #[cfg(unix)]
            {
                let (host_fd, guest_fd) =
                    create_unix_stream_pair().map_err(|e| format!("socketpair failed: {e}"))?;
                // SAFETY: ownership of the host-side socketpair fd transfers here.
                let host_stream = unsafe { Socket::from_raw_fd(host_fd) };
                let runtime = match start_virtio_network(
                    host_stream,
                    guest_network,
                    &port_mappings,
                    egress,
                    None,
                ) {
                    Ok(runtime) => runtime,
                    Err(err) => {
                        // SAFETY: guest_fd was created by socketpair above and not moved elsewhere.
                        unsafe { libc::close(guest_fd) };
                        return Err(format!("failed to start virtio network runtime: {err}"));
                    }
                };

                if unsafe {
                    (add_net_unixstream)(
                        ctx,
                        std::ptr::null(),
                        guest_fd,
                        guest_mac.as_mut_ptr(),
                        COMPAT_NET_FEATURES,
                        0,
                    )
                } < 0
                {
                    // SAFETY: guest_fd was created by socketpair above and not moved elsewhere.
                    unsafe { libc::close(guest_fd) };
                    free_ctx_on_err!("krun_add_net_unixstream failed");
                }

                virtio_network_runtime = Some(runtime);
            }
            #[cfg(windows)]
            {
                let net_sock_path = config.vsock_socket.with_extension("net");
                let listener = match super::launcher::bind_unix_listener(&net_sock_path) {
                    Ok(listener) => listener,
                    Err(e) => free_ctx_on_err!(format!("failed to bind virtio-net socket: {e}")),
                };
                let path_c = match path_to_cstring(&net_sock_path) {
                    Ok(path_c) => path_c,
                    Err(_) => free_ctx_on_err!("virtio-net socket path contains null byte"),
                };
                if unsafe {
                    (add_net_unixstream)(
                        ctx,
                        path_c.as_ptr(),
                        -1,
                        guest_mac.as_mut_ptr(),
                        COMPAT_NET_FEATURES,
                        0,
                    )
                } < 0
                {
                    free_ctx_on_err!("krun_add_net_unixstream failed");
                }

                // libkrun connects to the path while the VM boots inside the
                // blocking krun_start_enter, so accept on a background thread; the
                // runtime parks there until libkrun closes the stream (VM exit).
                let spawn = std::thread::Builder::new()
                    .name("smolvm-net-accept".into())
                    .spawn(move || match listener.accept() {
                        Ok((sock, _)) => {
                            match start_virtio_network(sock, guest_network, &port_mappings, egress, None) {
                                Ok(runtime) => runtime.block_until_shutdown(),
                                Err(err) => {
                                    tracing::error!(error = %err, "virtio-net runtime failed to start")
                                }
                            }
                        }
                        Err(err) => tracing::warn!(error = %err, "virtio-net accept failed"),
                    });
                if let Err(e) = spawn {
                    free_ctx_on_err!(format!("failed to spawn virtio-net accept thread: {e}"));
                }
            }

            tracing::info!("network backend: virtio-net");
            Some(guest_network)
        }
    };

    // Add storage disk. The format MUST match the on-disk image: a machine's
    // storage/overlay can be an instant qcow2 CoW overlay, and telling libkrun a
    // qcow2 file is raw makes it expose the tiny overlay file (~256 KiB) as the
    // whole device, so the guest formats a tiny ext4 and image writes fail with
    // "no space left on device". Detect the format from the file's magic so it
    // can't drift from what libkrun parses (mirrors `launcher.rs`, which passes
    // the disk object's `format()`).
    let block_id = cstr("storage");
    let disk_path = try_or_free_ctx!(
        path_to_cstring(config.storage_path),
        "storage path contains null byte"
    );
    let storage_format = krun_disk_format(config.storage_path);
    // SAFETY: ctx is valid, block_id and disk_path are valid C strings
    if unsafe {
        (krun.add_disk2)(
            ctx,
            block_id.as_ptr(),
            disk_path.as_ptr(),
            storage_format,
            false,
        )
    } < 0
    {
        free_ctx_on_err!("krun_add_disk2 failed");
    }

    // Add overlay disk as 2nd disk (/dev/vdb) for VM mode
    if let Some(overlay) = config.overlay_path {
        let overlay_id = cstr("overlay");
        let overlay_disk =
            try_or_free_ctx!(path_to_cstring(overlay), "overlay path contains null byte");
        let overlay_format = krun_disk_format(overlay);
        // SAFETY: ctx is valid, overlay_id and overlay_disk are valid C strings
        if unsafe {
            (krun.add_disk2)(
                ctx,
                overlay_id.as_ptr(),
                overlay_disk.as_ptr(),
                overlay_format,
                false,
            )
        } < 0
        {
            free_ctx_on_err!("krun_add_disk2 failed for overlay disk");
        }
    }

    // Add vsock port for control channel
    let socket_path = try_or_free_ctx!(
        path_to_cstring(config.vsock_socket),
        "vsock socket path contains null byte"
    );
    // SAFETY: ctx is valid, socket_path is a valid C string
    if unsafe { (krun.add_vsock_port2)(ctx, ports::AGENT_CONTROL, socket_path.as_ptr(), true) } < 0
    {
        free_ctx_on_err!("krun_add_vsock_port2 failed");
    }

    // Bridge the guest CUDA client (vsock port `ports::CUDA`) to the host CUDA
    // server socket. `listen=false`: the guest connects out and libkrun forwards
    // to the AF_UNIX path where `cuda_host::start` is serving. Mirrors the
    // non-packed launcher; keeps this launcher policy-free (the caller owns the
    // server lifecycle).
    if let Some(cuda_sock) = config.cuda_socket {
        let cuda_sock_c = try_or_free_ctx!(
            path_to_cstring(cuda_sock),
            "cuda socket path contains null byte"
        );
        // SAFETY: ctx is valid, cuda_sock_c is a valid C string.
        if unsafe { (krun.add_vsock_port2)(ctx, ports::CUDA, cuda_sock_c.as_ptr(), false) } < 0 {
            free_ctx_on_err!("krun_add_vsock_port2 (CUDA) failed");
        }
        if config.debug {
            eprintln!("debug: CUDA-over-vsock bridged to {}", cuda_sock.display());
        }
    }

    // Truncate the console log so it reflects only THIS boot. libkrun's
    // virtio-console opens the file in append mode, so a per-machine dir that is
    // reused across boots (e.g. the deterministic ephemeral `run` dir) otherwise
    // accumulates every past boot's console. A boot that fails then shows a prior
    // run's *successful* console, making a real boot failure look like a healthy
    // boot that mysteriously shut down — actively misleading whoever debugs it.
    // Best-effort: if truncation fails we still boot (worst case, stale history).
    truncate_console_log(&config.console_log);

    // Redirect console output to a log file so libkrun doesn't put the
    // inherited terminal into raw mode (which would break terminal echo
    // if the child is killed before exit observers can restore it). Uses the
    // upstream virtio-console API (krun_set_console_output was removed).
    // SAFETY: ctx is a valid, not-yet-started libkrun context.
    if unsafe { krun.console_output_to_file(ctx, &config.console_log) } < 0 {
        // On Windows the fd-based virtio-console redirection isn't wired (the
        // wrapper is a known no-op that always returns < 0), so this is expected
        // — NOT a boot failure. Keep it out of the startup error log at WARN so a
        // benign line can't become what the readiness monitor surfaces as "the
        // error" when the boot later fails for a real reason (see
        // `boot_failure_reason`).
        #[cfg(windows)]
        tracing::debug!("guest console not captured on Windows (fd redirection unsupported)");
        #[cfg(not(windows))]
        tracing::warn!("failed to set console output");
    }

    // Set working directory
    let workdir = cstr("/");
    // SAFETY: ctx is valid, workdir is a valid C string
    unsafe { (krun.set_workdir)(ctx, workdir.as_ptr()) };

    // Build environment (all safe Rust)
    let mut env_strings = vec![
        cstr("HOME=/root"),
        cstr("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
        cstr("TERM=xterm-256color"),
    ];

    // Tell agent about packed layers mount
    if config.layers_dir.exists() {
        env_strings.push(cstr("SMOLVM_PACKED_LAYERS=smolvm_layers:/packed_layers"));
    }

    // Pass mount info to the agent via environment
    for (i, mount) in config.mounts.iter().enumerate() {
        let ro_flag = if mount.read_only { "ro" } else { "rw" };
        let env_val = format!(
            "SMOLVM_MOUNT_{}={}:{}:{}",
            i, mount.tag, mount.guest_path, ro_flag
        );
        if let Ok(cstr) = CString::new(env_val) {
            env_strings.push(cstr);
        }
    }

    if !config.mounts.is_empty() {
        if let Ok(cstr) = CString::new(format!("SMOLVM_MOUNT_COUNT={}", config.mounts.len())) {
            env_strings.push(cstr);
        }
    }

    // Tell the agent GPU was requested so it creates /dev/dri nodes and starts
    // seatd after pivot_root. Keep this in sync with the normal launcher.
    if config.resources.gpu {
        let gpu_env = format!("{}={}", guest_env::GPU, guest_env::VALUE_ON);
        if let Ok(cstr) = CString::new(gpu_env) {
            env_strings.push(cstr);
        }
    }

    // The packed launcher wires CUDA directly instead of going through the
    // shared vsock-service builder, so it must carry the same guest feature
    // sentinel explicitly. Without it the agent never stages the bundled
    // shims and `pack run --cuda` boots a CUDA bridge that workloads cannot use.
    if config.cuda_socket.is_some() {
        let cuda_env = format!("{}={}", guest_env::CUDA_ZEROCOPY, guest_env::VALUE_ON);
        if let Ok(cstr) = CString::new(cuda_env) {
            env_strings.push(cstr);
        }
    }

    if let Ok(pool_size) = std::env::var(guest_env::CUDA_FORK_POOL_SIZE) {
        env_strings.push(cstr(&format!(
            "{}={pool_size}",
            guest_env::CUDA_FORK_POOL_SIZE
        )));
    }

    if std::env::var(guest_env::FORKABLE).as_deref() == Ok(guest_env::VALUE_ON) {
        env_strings.push(cstr(&format!(
            "{}={}",
            guest_env::FORKABLE,
            guest_env::VALUE_ON
        )));
    }

    // Enable Rosetta only when requested AND actually available on this host, so
    // a stray `--rosetta` on a non-Rosetta host degrades to a no-op rather than a
    // dangling virtiofs tag the guest would fail to mount. The guest agent reads
    // guest_env::ROSETTA and mounts the runtime + registers binfmt_misc.
    let rosetta_enabled = config.resources.rosetta && crate::vm::rosetta::is_available();
    if rosetta_enabled {
        let rosetta_env = format!("{}={}", guest_env::ROSETTA, guest_env::VALUE_ON);
        if let Ok(cstr) = CString::new(rosetta_env) {
            env_strings.push(cstr);
        }
    }

    // Guest-network env vars — virtio-net interface config plus the TSI `--dns`
    // override — are built in one shared place so the static and dynamic
    // launchers can't diverge (see `agent::guest_network_env`). The dynamic
    // launcher having open-coded this is exactly how it once dropped `--dns` on
    // TSI (PR #466).
    env_strings.extend(crate::agent::guest_network_env(
        guest_network,
        config.resources.dns,
    ));

    let mut envp: Vec<*const libc::c_char> = env_strings.iter().map(|s| s.as_ptr()).collect();
    envp.push(std::ptr::null());

    // Set exec command (MUST be before add_virtiofs)
    let exec_path = cstr("/sbin/init");
    let argv_strings = [cstr("/sbin/init")];
    let mut argv: Vec<*const libc::c_char> = argv_strings.iter().map(|s| s.as_ptr()).collect();
    argv.push(std::ptr::null());

    // SAFETY: ctx is valid, all pointers are valid null-terminated C strings/arrays
    if unsafe { (krun.set_exec)(ctx, exec_path.as_ptr(), argv.as_ptr(), envp.as_ptr()) } < 0 {
        free_ctx_on_err!("krun_set_exec failed");
    }

    // Every virtiofs mount gets a DAX window (like the root fs above): without
    // DAX, virtiofs falls back to writeback caching where each file access is a
    // FUSE round-trip over the virtio queue — pathological for read-heavy mounts
    // with many files (a multi-GB Python venv took minutes just to import, and a
    // single file larger than the window stalled entirely). 2 GiB exceeds any
    // realistic single mapped file; the window is virtual host address space
    // backed on demand, so oversizing costs nothing until touched.
    const VIRTIOFS_DAX_WINDOW: u64 = 1 << 31;

    // Add virtiofs mount for packed layers (AFTER set_exec)
    if config.layers_dir.exists() {
        let layers_tag = cstr("smolvm_layers");
        let layers_path = try_or_free_ctx!(
            path_to_cstring(config.layers_dir),
            "layers dir path contains null byte"
        );
        // SAFETY: ctx is valid, tag and path are valid C strings
        if unsafe {
            add_virtiofs3(
                ctx,
                layers_tag.as_ptr(),
                layers_path.as_ptr(),
                VIRTIOFS_DAX_WINDOW,
                false,
            )
        } < 0
        {
            free_ctx_on_err!("krun_add_virtiofs failed for packed layers");
        }
    }

    // Add user-specified virtiofs mounts
    for mount in config.mounts.iter() {
        let tag = try_or_free_ctx!(
            CString::new(mount.tag.as_str()),
            "mount tag contains null byte"
        );
        let host_path = try_or_free_ctx!(
            CString::new(mount.host_path.as_str()),
            "mount path contains null byte"
        );

        // SAFETY: ctx is valid, tag and host_path are valid C strings
        if unsafe {
            add_virtiofs3(
                ctx,
                tag.as_ptr(),
                host_path.as_ptr(),
                VIRTIOFS_DAX_WINDOW,
                mount.read_only,
            )
        } < 0
        {
            free_ctx_on_err!(format!(
                "krun_add_virtiofs failed for '{}' - requested mount cannot be attached",
                mount.tag
            ));
        }
    }

    // Attach the Rosetta 2 Linux runtime (read-write is unnecessary but the plain
    // add_virtiofs is what the guest expects for this tag; the runtime dir is
    // never written). runtime_path() is Some iff is_available() held above.
    if rosetta_enabled {
        if let Some(runtime) = crate::vm::rosetta::runtime_path() {
            let rosetta_tag = cstr(smolvm_protocol::ROSETTA_TAG);
            let rosetta_path = try_or_free_ctx!(
                CString::new(runtime),
                "rosetta runtime path contains null byte"
            );
            // SAFETY: ctx is valid, tag and path are valid C strings
            if unsafe { (krun.add_virtiofs)(ctx, rosetta_tag.as_ptr(), rosetta_path.as_ptr()) } < 0
            {
                free_ctx_on_err!("krun_add_virtiofs failed for Rosetta runtime");
            }
        }
    }

    // Start VM (never returns on success)
    // SAFETY: ctx is valid, all configuration has been set
    let ret = unsafe { (krun.start_enter)(ctx) };
    let start_error_detail = krun.last_error_message();

    // If we get here, something went wrong — free the context before returning
    // SAFETY: ctx is a valid context from krun_create_ctx
    unsafe { (krun.free_ctx)(ctx) };
    drop(virtio_network_runtime);
    Err(describe_krun_start_error_with_detail(
        ret,
        start_error_detail.as_deref(),
    ))
}

/// Create a CString from a static string that is known not to contain NUL bytes.
fn cstr(s: &str) -> CString {
    CString::new(s).expect("string literal must not contain NUL bytes")
}

/// Turn a `krun_start_enter` failure code into an actionable message.
///
/// libkrun returns a negative errno; the bare number ("krun_start_enter
/// returned: -22") is opaque and, when it bubbles up through the readiness
/// monitor as "boot process exited before the agent was ready", tells the user
/// nothing about what to fix. Decode the common codes and name the usual cause.
pub(crate) fn describe_krun_start_error(ret: i32) -> String {
    // For hypervisor-access errnos, re-probe /dev/kvm from THIS context. The
    // server's preflight (`check_kvm_available`) runs before the per-VM uid
    // drop, so it can pass while the dropped VMM process — landing on a uid
    // outside the kvm group — can't open /dev/kvm, and libkrun then fails here.
    // The probe runs post-drop, so its group/permission hint is the real cause,
    // not the generic "usually a disk/overlay" guess.
    #[cfg(target_os = "linux")]
    let kvm_error = if matches!(-ret, 1 | 13 | 19 | 22) {
        crate::platform::linux::check_kvm_available()
            .err()
            .map(|e| e.to_string())
    } else {
        None
    };
    #[cfg(not(target_os = "linux"))]
    let kvm_error: Option<String> = None;

    // Same idea on macOS: `hv_vm_create` returns HV_UNSUPPORTED without the
    // com.apple.security.hypervisor entitlement, and libkrun reports that in
    // the same errno class as a disk that could not be opened — so the generic
    // hint sends the user after disks when the real fix is re-signing. A
    // re-signed (`codesign --force --sign -` with no `--entitlements`) or
    // freshly built binary silently loses the entitlement.
    #[cfg(target_os = "macos")]
    if matches!(-ret, 1 | 13 | 19 | 22) && !has_hypervisor_entitlement() {
        return format!(
            "krun_start_enter returned: {ret} (this binary is not signed with the \
             com.apple.security.hypervisor entitlement required by \
             Hypervisor.framework — re-sign it: codesign --force --sign - \
             --entitlements hv.entitlements <path-to-binary>)"
        );
    }

    describe_start_error_with_probe(ret, kvm_error.as_deref())
}

pub(crate) fn describe_krun_start_error_with_detail(ret: i32, detail: Option<&str>) -> String {
    let summary = describe_krun_start_error(ret);
    match detail.map(str::trim).filter(|detail| !detail.is_empty()) {
        Some(detail) => format!("{summary}; libkrun detail: {detail}"),
        None => summary,
    }
}

/// Whether the running binary carries the macOS hypervisor entitlement.
///
/// Probed with `codesign`, the same tool `smolvm_pack::signing` uses to add the
/// entitlement when packing. An unreadable signature counts as missing (an
/// unsigned binary is not entitled); a missing `codesign` counts as present, so
/// a tooling gap never rewrites an unrelated boot failure.
#[cfg(target_os = "macos")]
fn has_hypervisor_entitlement() -> bool {
    let Ok(exe) = std::env::current_exe() else {
        return true;
    };
    // The packed run/start paths install a global `waitpid(-1)` SIGCHLD reaper
    // before forking (`process::install_sigchld_handler`), which can reap
    // `codesign` before `output()` waits and yield ECHILD — the same race
    // `smolvm_pack::signing` documents. Probe under the default disposition.
    let previous = unsafe { libc::signal(libc::SIGCHLD, libc::SIG_DFL) };
    let probed = std::process::Command::new("codesign")
        .args(["-d", "--entitlements", "-"])
        .arg(&exe)
        .output();
    unsafe { libc::signal(libc::SIGCHLD, previous) };

    let Ok(out) = probed else {
        return true;
    };
    out.status.success() && entitlement_enabled(&String::from_utf8_lossy(&out.stdout))
}

/// Whether a `codesign -d --entitlements -` dump grants the hypervisor
/// entitlement.
///
/// codesign names the key even when a signature sets it to `false`, so the
/// value decides. It prints either `[Key] … [Value] [Bool] true` lines or an
/// XML plist, so require a `true` between the key and the next entitlement.
#[cfg(target_os = "macos")]
fn entitlement_enabled(entitlements: &str) -> bool {
    let Some((_, rest)) = entitlements.split_once("com.apple.security.hypervisor") else {
        return false;
    };
    let mut value = rest;
    if let Some(end) = value.find("[Key]") {
        value = &value[..end];
    }
    if let Some(end) = value.find("<key>") {
        value = &value[..end];
    }
    value.contains("true")
}

/// Pure core of [`describe_krun_start_error`], with the KVM probe result
/// injected so the decoding is testable without a live `/dev/kvm`.
fn describe_start_error_with_probe(ret: i32, kvm_error: Option<&str>) -> String {
    let errno = -ret;
    if matches!(errno, 1 | 13 | 19 | 22) {
        if let Some(kvm) = kvm_error {
            return format!(
                "krun_start_enter returned: {ret} (KVM inaccessible to the VM process \
                 after privilege drop — {kvm})"
            );
        }
    }
    let hint = match errno {
        22 => {
            "EINVAL — libkrun rejected the VM configuration; usually a disk/overlay \
               that could not be opened (still held by another VM that has not fully \
               exited, or a corrupt/foreign-owned image) or an unsupported device option"
        }
        5 => "EIO — a backing disk or overlay could not be read/created",
        13 => "EACCES — permission denied opening a VM resource (disk, socket, or rootfs)",
        16 => "EBUSY — a VM resource is already in use by another process",
        12 => "ENOMEM — out of memory starting the VM",
        1 => "EPERM — the hypervisor rejected the operation (KVM/HVF/WHP access)",
        19 => "ENODEV — the hypervisor device is unavailable (is KVM/HVF/WHP enabled?)",
        _ => "the VM failed to start at the hypervisor layer",
    };
    format!("krun_start_enter returned: {ret} ({hint})")
}

/// Truncate the guest console log to empty so it holds only the current boot.
///
/// libkrun's virtio-console appends, and per-machine dirs are reused across
/// boots, so without this the console grows unbounded and — worse — a failed
/// boot inherits the previous boot's output, so the log shows a successful boot
/// that does not correspond to the crashed run. Only truncates a file that
/// already exists (never creates a spurious log where console capture is a no-op,
/// e.g. Windows); a failure here is non-fatal.
pub(crate) fn truncate_console_log(path: &Path) {
    if path.exists() {
        if let Err(e) = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(path)
        {
            tracing::debug!(path = %path.display(), error = %e, "could not truncate console log");
        }
    }
}

/// Convert a Path to a CString.
fn path_to_cstring(path: &Path) -> Result<CString, String> {
    CString::new(path.to_string_lossy().as_bytes())
        .map_err(|_| "path contains null byte".to_string())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describe_krun_start_error_decodes_common_codes() {
        // The exact string the readiness monitor greps for must survive so
        // boot_failure_reason still surfaces it as "the error". Use the pure
        // form with no KVM probe failure so decoding is deterministic on hosts
        // both with and without /dev/kvm.
        let einval = describe_start_error_with_probe(-22, None);
        assert!(einval.contains("krun_start_enter returned: -22"));
        assert!(einval.contains("EINVAL"));
        assert!(describe_start_error_with_probe(-13, None).contains("EACCES"));
        // Unknown codes still render the raw number with a generic explanation.
        let unknown = describe_start_error_with_probe(-999, None);
        assert!(unknown.contains("-999"));
        assert!(unknown.contains("hypervisor"));
        // The live wrapper still emits the grep contract regardless of host KVM.
        assert!(describe_krun_start_error(-22).contains("krun_start_enter returned: -22"));
    }

    #[test]
    fn describe_krun_start_error_surfaces_post_drop_kvm_cause() {
        // When a hypervisor-access errno coincides with a failed post-drop KVM
        // probe, the concrete group/permission cause replaces the generic guess.
        let msg = describe_start_error_with_probe(
            -22,
            Some("Cannot access /dev/kvm (permission denied). Add your user to the 'kvm' group"),
        );
        assert!(msg.contains("krun_start_enter returned: -22"));
        assert!(msg.contains("KVM inaccessible to the VM process after privilege drop"));
        assert!(msg.contains("kvm' group"));
        // A non-hypervisor errno ignores the probe result entirely.
        let eio = describe_start_error_with_probe(-5, Some("should be ignored"));
        assert!(eio.contains("EIO"));
        assert!(!eio.contains("privilege drop"));
    }

    #[test]
    fn describe_krun_start_error_appends_library_detail() {
        let message = describe_krun_start_error_with_detail(
            -22,
            Some("build microVM: vCPU rejected checkpoint state"),
        );
        assert!(message.contains("krun_start_enter returned: -22"));
        assert!(message.contains("vCPU rejected checkpoint state"));
        assert_eq!(
            describe_krun_start_error_with_detail(-5, Some("  ")),
            describe_krun_start_error(-5)
        );
    }

    // cargo's test binaries are ad-hoc signed without entitlements, so a
    // hypervisor-access errno must name the missing entitlement instead of the
    // generic disk/overlay guess — while keeping the grep contract intact.
    #[cfg(target_os = "macos")]
    #[test]
    fn describe_krun_start_error_names_missing_hypervisor_entitlement() {
        let msg = describe_krun_start_error(-22);
        assert!(msg.contains("krun_start_enter returned: -22"), "{msg}");
        assert!(msg.contains("com.apple.security.hypervisor"), "{msg}");
        assert!(msg.contains("codesign"), "{msg}");
    }

    // codesign names the entitlement key even when a signature sets it to
    // false, so the value — not the key's presence — decides.
    #[cfg(target_os = "macos")]
    #[test]
    fn entitlement_is_granted_only_when_value_is_true() {
        assert!(entitlement_enabled(
            "[Key] com.apple.security.hypervisor\n[Value]\n[Bool] true"
        ));
        assert!(!entitlement_enabled(
            "[Key] com.apple.security.hypervisor\n[Value]\n[Bool] false"
        ));
        assert!(entitlement_enabled(
            "<key>com.apple.security.hypervisor</key><true/>"
        ));
        assert!(!entitlement_enabled(
            "<key>com.apple.security.hypervisor</key><false/>"
        ));
        // A later entitlement's `true` must not leak into the decision.
        assert!(!entitlement_enabled(
            "<key>com.apple.security.hypervisor</key><false/>\
             <key>com.apple.security.cs.allow-jit</key><true/>"
        ));
        // A dump without the key at all is not granted.
        assert!(!entitlement_enabled(
            "<key>com.apple.security.cs.allow-jit</key><true/>"
        ));
    }

    #[test]
    fn truncate_console_log_clears_prior_boot_output() {
        let dir = std::env::temp_dir().join(format!("smolvm-console-trunc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("agent-console.log");
        // A prior boot's console is present.
        std::fs::write(&log, b"PRIOR BOOT: agent init complete\n").unwrap();
        assert!(std::fs::metadata(&log).unwrap().len() > 0);

        truncate_console_log(&log);

        // The next boot starts from an empty file — no stale success lines.
        assert_eq!(std::fs::metadata(&log).unwrap().len(), 0);
        // A missing log is left untouched (no spurious file where capture is a no-op).
        let missing = dir.join("nope.log");
        truncate_console_log(&missing);
        assert!(!missing.exists());

        std::fs::remove_dir_all(&dir).ok();
    }
}
