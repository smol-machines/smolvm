//! Agent VM management.
//!
//! This module manages the agent VM lifecycle and provides a client
//! for communicating with the smolvm-agent via vsock.

pub mod boot_config;
mod client;
pub mod fork;
mod krun;
mod launcher;
pub mod launcher_dynamic;
mod manager;
pub mod state_probe;
pub mod terminal;

pub use crate::data::network::PortMapping;
pub use crate::data::resources::VmResources;
pub use crate::data::storage::HostMount;
pub use client::{
    AgentClient, ExecEvent, InteractiveInput, InteractiveOutput, PullOptions, RunConfig,
};
pub use krun::KrunFunctions;
pub use launcher::{
    create_disk_overlays, find_lib_dir, launch_agent_vm, DiskOverlaySpec, LaunchConfig,
    LaunchFeatures, VmDisks,
};
pub use manager::{
    disk_used_mb, docker_config_dir, docker_config_mount, ensure_vm_dir, machine_layers_cache_dir,
    read_egress_telemetry, resolve_disk_image, vm_cache_root, vm_data_dir, vm_dir_hash,
    vm_uid_registry_dir, AgentManager, AgentState,
};

/// Agent VM name.
pub const AGENT_VM_NAME: &str = "smolvm-agent";

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
        push(guest_env::GUEST_IP6, n.guest_ip6.to_string());
        push(guest_env::GATEWAY6, n.gateway_ip6.to_string());
        push(guest_env::PREFIX_LEN6, n.prefix_len6.to_string());
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
