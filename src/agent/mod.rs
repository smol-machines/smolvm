//! Agent VM management.
//!
//! This module manages the agent VM lifecycle and provides a client
//! for communicating with the smolvm-agent via vsock.

pub mod boot_config;
mod client;
mod krun;
mod launcher;
pub mod launcher_dynamic;
mod manager;
pub mod state_probe;
pub mod terminal;

pub use crate::data::network::PortMapping;
pub use crate::data::resources::VmResources;
pub use crate::data::storage::HostMount;
pub use client::{AgentClient, ExecEvent, PullOptions, RunConfig};
pub use krun::KrunFunctions;
pub use launcher::{find_lib_dir, launch_agent_vm, LaunchConfig, LaunchFeatures, VmDisks};
pub use manager::{
    docker_config_dir, docker_config_mount, ensure_vm_dir, vm_cache_root, vm_data_dir, vm_dir_hash,
    AgentManager, AgentState,
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
