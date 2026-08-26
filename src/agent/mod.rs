//! Agent VM management.
//!
//! This module manages the agent VM lifecycle and provides a client
//! for communicating with the smolvm-agent via vsock.

pub mod boot_config;
mod client;
pub mod display;
pub mod fork;
mod fsnotify_watch;
pub mod input;
mod krun;
mod launcher;
pub mod launcher_dynamic;
mod manager;
pub mod pod_net;
pub mod state_probe;
pub mod terminal;
pub mod vnc;
mod vsock_service;

pub use crate::data::network::PortMapping;
pub use crate::data::resources::VmResources;
pub use crate::data::storage::HostMount;
pub use client::{
    file_transfer_max_total, pack_export_max_total, AgentClient, ExecEvent, FileWriteMeta,
    InteractiveInput, InteractiveOutput, PullOptions, RunConfig,
};
pub use fsnotify_watch::FsNotifyWatcher;
pub use krun::KrunFunctions;
pub use launcher::{
    create_disk_overlays, find_lib_dir, launch_agent_vm, DiskOverlaySpec, LaunchConfig,
    LaunchFeatures, VmDisks,
};
pub(crate) use manager::{cleanup_dead_vm_runtime, cleanup_dead_vm_runtime_in_db};
pub use manager::{
    disk_used_mb, docker_config_dir, docker_config_mount, ensure_vm_dir, machine_layers_cache_dir,
    prune_orphaned_ready_markers, read_egress_denials, read_egress_telemetry,
    read_shared_pack_pointer, resolve_disk_image, shared_pack_cache_root, shared_pack_pointer_path,
    vm_cache_root, vm_data_dir, vm_dir_hash, vm_uid_registry_dir, AgentManager, AgentState,
    EgressDenial, SHARED_PACK_POINTER,
};

/// Agent VM name.
pub const AGENT_VM_NAME: &str = "smolvm-agent";

/// Parse a `WIDTHxHEIGHT` display size (e.g. `"1920x1080"`).
///
/// Returns `None` for absent/blank input so "no display" stays the default —
/// a scanout adds a KMS connector the guest can see, which existing GPU
/// workloads (CUDA, headless Vulkan) do not need.
///
/// Rejects zero and absurd dimensions rather than passing them to libkrun: the
/// virtio-gpu EDID generator will happily build a nonsense mode, and the guest
/// then fails far away from the cause.
pub fn parse_display_size(raw: Option<&str>) -> Option<(u32, u32)> {
    const MAX_DIM: u32 = 16384;
    let raw = raw?.trim();
    if raw.is_empty() {
        return None;
    }
    let (w, h) = raw.split_once(['x', 'X'])?;
    let w: u32 = w.trim().parse().ok()?;
    let h: u32 = h.trim().parse().ok()?;
    if w == 0 || h == 0 || w > MAX_DIM || h > MAX_DIM {
        return None;
    }
    Some((w, h))
}

/// Default `KRUN_GPU_BACKEND=2d` on macOS when a display is requested.
///
/// The virglrenderer bundled on macOS is Venus-only: it cannot create the
/// classic 2D resources a scanout serves, so every display path fails until
/// libkrun is switched to rutabaga's CPU 2D component. Users shouldn't need
/// to know that; an explicit KRUN_GPU_BACKEND still wins.
///
/// Shared by both launchers. Must run before the VM starts — libkrun reads
/// the variable when it builds the virtio-gpu device.
pub fn default_gpu_backend_for_display() {
    #[cfg(target_os = "macos")]
    if std::env::var_os("KRUN_GPU_BACKEND").is_none() {
        std::env::set_var("KRUN_GPU_BACKEND", "2d");
        tracing::info!("display requested on macOS: defaulting KRUN_GPU_BACKEND=2d");
    }
}

/// Compute the `virgl_flags` bitmask for `krun_set_gpu_options2`.
///
/// Shared by both the static (`launcher.rs`) and dynamic (`launcher_dynamic.rs`)
/// launchers so they can never silently diverge.
///
/// Flag values from `libkrun/include/libkrun.h` virglrenderer bindings:
///   bit 0  — VIRGLRENDERER_USE_EGL         (Linux): EGL context for GPU rendering
///   bit 3  — VIRGLRENDERER_USE_SURFACELESS  (Linux): no display server required
///   bit 6  — VIRGLRENDERER_VENUS           (both): Vulkan-over-virtio-gpu (Venus ICD)
///   bit 7  — VIRGLRENDERER_NO_VIRGL        (macOS): skip OpenGL (vrend) init — without
///             EGL, vrend_renderer_init crashes on null platform function pointers
///   bit 9  — VIRGLRENDERER_RENDER_SERVER   (Linux): REQUIRED for render-server mode.
///             Enables virglrenderer to call the get_server_fd callback and use an
///             external render server.  Without this bit, virglrenderer attempts
///             in-process Venus which fails (version stays 0).  With get_server_fd
///             provided in the callbacks struct, virglrenderer uses the externally
///             spawned virgl_render_server instead of fork/exec-ing its own process.
fn gpu_virgl_flags() -> u32 {
    #[cfg(target_os = "linux")]
    {
        (1 << 0) | (1 << 3) | (1 << 6) | (1 << 9)
    }
    #[cfg(not(target_os = "linux"))]
    {
        (1 << 6) | (1 << 7)
    }
}

/// Build the guest-network environment variables handed to the agent at boot.
///
/// Shared by both the static (`launcher.rs`) and dynamic (`launcher_dynamic.rs`)
/// launchers — like [`gpu_virgl_flags`] — so the two can never silently diverge.
/// They previously each open-coded this block, and the dynamic one drifted: it
/// omitted the TSI `--dns` override, silently dropping `--dns` on the default
/// backend (PR #466). With one source of truth, the guest's resolver is decided
/// in exactly one place and the agent remains the sole writer of resolv.conf.
///
/// `guest_network` is `Some` for virtio-net (the agent derives its resolver from
/// `dns_server`, the gateway address). For TSI it is `None`: there is no host
/// gateway to route a resolver through, so a `--dns` override must be passed
/// straight through for the agent to write into resolv.conf.
pub(crate) fn guest_network_env(
    guest_network: Option<smolvm_network::GuestNetworkConfig>,
    dns_override: Option<std::net::Ipv4Addr>,
) -> Vec<std::ffi::CString> {
    use smolvm_protocol::guest_env;
    let mut env: Vec<std::ffi::CString> = Vec::new();
    let mut push = |key: &str, val: String| {
        env.push(std::ffi::CString::new(format!("{key}={val}")).expect("env var contains NUL"));
    };
    if let Some(n) = guest_network {
        push(
            guest_env::BACKEND,
            guest_env::BACKEND_VIRTIO_NET.to_string(),
        );
        push(guest_env::GUEST_IP, n.guest_ip.to_string());
        push(guest_env::GATEWAY, n.gateway_ip.to_string());
        push(guest_env::PREFIX_LEN, n.prefix_len.to_string());
        push(guest_env::GUEST_MAC, format_mac(n.guest_mac));
        // Only hand the guest an IPv6 identity when the host can actually
        // route v6: a global-scope guest address makes dual-stack clients
        // sort AAAA answers first (RFC 6724), and on a v6-less host every
        // such connection is refused. Omitting the trio keeps the guest
        // v4-first; the agent treats the absent set as a valid contract.
        if smolvm_network::host_has_ipv6_route() {
            push(guest_env::GUEST_IP6, n.guest_ip6.to_string());
            push(guest_env::GATEWAY6, n.gateway_ip6.to_string());
            push(guest_env::PREFIX_LEN6, n.prefix_len6.to_string());
        }
        push(guest_env::DNS, n.dns_server.to_string());
    } else if let Some(dns) = dns_override {
        push(guest_env::DNS, dns.to_string());
    }
    env
}

fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

#[cfg(test)]
mod display_size_tests {
    use super::parse_display_size;

    #[test]
    fn parses_wxh() {
        assert_eq!(parse_display_size(Some("1920x1080")), Some((1920, 1080)));
        assert_eq!(parse_display_size(Some("1280X800")), Some((1280, 800)));
        assert_eq!(parse_display_size(Some("  1024x768 ")), Some((1024, 768)));
    }

    // Absent/blank must mean "no display", not a default one: adding a scanout
    // changes guest topology for every existing --gpu workload.
    #[test]
    fn absent_or_blank_means_no_display() {
        assert_eq!(parse_display_size(None), None);
        assert_eq!(parse_display_size(Some("")), None);
        assert_eq!(parse_display_size(Some("   ")), None);
    }

    #[test]
    fn rejects_malformed() {
        for bad in ["1920", "1920x", "x1080", "axb", "1920*1080", "1920x1080x60"] {
            assert_eq!(parse_display_size(Some(bad)), None, "should reject {bad}");
        }
    }

    // Zero would produce a degenerate EDID mode; huge values blow up the
    // framebuffer allocation. Fail here, where the error names the cause.
    #[test]
    fn rejects_zero_and_absurd() {
        assert_eq!(parse_display_size(Some("0x1080")), None);
        assert_eq!(parse_display_size(Some("1920x0")), None);
        assert_eq!(parse_display_size(Some("99999x1080")), None);
        assert_eq!(parse_display_size(Some("1920x99999")), None);
    }
}
