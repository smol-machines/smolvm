//! OCI bundle inspection + rootfs mounting.
//!
//! containerd hands the shim a bundle dir (config.json) and a list of rootfs
//! mounts (e.g. one overlay mount). The CRI plugin marks pod-sandbox vs
//! workload containers with annotations, and passes the pod netns path on the
//! sandbox's config.

use std::path::Path;

use log::warn;
use serde::Deserialize;

/// CRI annotation: "sandbox" (the pause container) or "container".
const ANN_CONTAINER_TYPE: &str = "io.kubernetes.cri.container-type";
/// CRI annotation on sandboxes: host path of the pod's network namespace.
const ANN_SANDBOX_NETNS: &str = "io.kubernetes.cri.sandbox-network-ns";

#[derive(Debug, Default)]
pub struct BundleInfo {
    pub is_sandbox: bool,
    pub netns: Option<String>,
}

#[derive(Deserialize)]
struct MinimalSpec {
    #[serde(default)]
    annotations: std::collections::HashMap<String, String>,
    #[serde(default)]
    linux: Option<MinimalLinux>,
}

#[derive(Deserialize)]
struct MinimalLinux {
    #[serde(default)]
    namespaces: Vec<MinimalNs>,
}

#[derive(Deserialize)]
struct MinimalNs {
    #[serde(rename = "type")]
    ns_type: String,
    #[serde(default)]
    path: Option<String>,
}

/// Read the bundle's config.json and classify it.
pub fn load(bundle: &str) -> Result<BundleInfo, String> {
    let cfg = Path::new(bundle).join("config.json");
    let raw = std::fs::read_to_string(&cfg).map_err(|e| format!("read {}: {e}", cfg.display()))?;
    let spec: MinimalSpec =
        serde_json::from_str(&raw).map_err(|e| format!("parse {}: {e}", cfg.display()))?;

    let is_sandbox = spec
        .annotations
        .get(ANN_CONTAINER_TYPE)
        .map(|v| v == "sandbox")
        // No CRI annotations (plain `ctr run`): treat the task as its own
        // sandbox so a bare container still gets a VM.
        .unwrap_or(true);

    // Netns: prefer the CRI annotation, else the OCI network namespace path.
    let netns = spec
        .annotations
        .get(ANN_SANDBOX_NETNS)
        .cloned()
        .or_else(|| {
            spec.linux.as_ref().and_then(|l| {
                l.namespaces
                    .iter()
                    .find(|n| n.ns_type == "network")
                    .and_then(|n| n.path.clone())
                    .filter(|p| !p.is_empty())
            })
        });

    Ok(BundleInfo { is_sandbox, netns })
}

/// Mount containerd's rootfs mounts at `<bundle>/rootfs`, returning that path.
/// No mounts (tests, pre-mounted rootfs) is fine — the directory is used as-is.
pub async fn mount_rootfs(
    bundle: &str,
    mounts: &[containerd_shim_protos::api::Mount],
) -> Result<String, String> {
    let target = Path::new(bundle).join("rootfs");
    tokio::fs::create_dir_all(&target)
        .await
        .map_err(|e| format!("mkdir {}: {e}", target.display()))?;
    for m in mounts {
        containerd_shim::mount::mount_rootfs(
            Some(m.type_.as_str()),
            Some(m.source.as_str()),
            &m.options.to_vec(),
            &target,
        )
        .map_err(|e| format!("mount rootfs ({}): {e}", m.type_))?;
    }
    Ok(target.to_string_lossy().into_owned())
}

/// Unmount `<bundle>/rootfs` (best-effort; may never have been mounted).
pub async fn unmount_rootfs(bundle: &str) {
    let target = Path::new(bundle).join("rootfs");
    if let Err(e) = containerd_shim::mount::umount_recursive(target.to_str(), 0) {
        warn!("umount {}: {e}", target.display());
    }
}
