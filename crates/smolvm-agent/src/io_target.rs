//! Which filesystem a file request acts on.
//!
//! A host that names a [`WorkloadTarget`] gets exactly that filesystem: the
//! VM's own root for a bare machine, or the container root of the named
//! persistent overlay, which this module mounts if needed. Only a request with
//! no target (from an older host) is resolved by inference, as before.

use std::path::PathBuf;

use smolvm_protocol::{error_codes, AgentResponse, WorkloadTarget};

use crate::{nsfile, storage};

/// The filesystem a file request resolved to.
pub(crate) enum IoRoot {
    /// No target given: infer it from the running containers and mounted
    /// overlays.
    Inferred,
    /// The VM's own root filesystem.
    Vm,
    /// A persistent overlay, mounted at `merged`.
    Overlay {
        workload_id: String,
        merged: PathBuf,
    },
}

impl IoRoot {
    /// Resolve a request's target, mounting its overlay when it names one.
    pub(crate) fn resolve(target: Option<&WorkloadTarget>) -> Result<Self, AgentResponse> {
        let Some(target) = target else {
            return Ok(Self::Inferred);
        };
        if let Err(reason) = target.validate() {
            return Err(AgentResponse::error(reason, error_codes::INVALID_REQUEST));
        }
        match target {
            WorkloadTarget::Vm => Ok(Self::Vm),
            WorkloadTarget::Container { image, overlay_id } => {
                let workload_id = format!("persistent-{overlay_id}");
                match storage::prepare_overlay(image, &workload_id) {
                    Ok(overlay) => Ok(Self::Overlay {
                        workload_id,
                        merged: PathBuf::from(overlay.rootfs_path),
                    }),
                    Err(e) => Err(storage_error_response(e, error_codes::OVERLAY_FAILED)),
                }
            }
        }
    }

    /// The mount namespace the request's paths live in.
    pub(crate) fn namespace(&self) -> nsfile::GuestNs {
        match self {
            Self::Inferred => nsfile::GuestNs::for_workload(),
            Self::Vm => nsfile::GuestNs::Root(nsfile::RootReason::VmTarget),
            Self::Overlay {
                workload_id,
                merged,
            } => nsfile::GuestNs::on_overlay(workload_id, merged),
        }
    }

    /// The overlay root that paths outside `/workspace` map into when written
    /// from the VM's namespace, or `None` for plain VM paths.
    pub(crate) fn overlay_merged_root(&self) -> Option<PathBuf> {
        match self {
            Self::Inferred => crate::active_persistent_overlay_merged_root(),
            Self::Vm => None,
            Self::Overlay { merged, .. } => Some(merged.clone()),
        }
    }
}

/// An agent response for a storage error, with the specific code a host can
/// act on where there is one.
pub(crate) fn storage_error_response(e: storage::StorageError, code: &str) -> AgentResponse {
    let code = match e {
        storage::StorageError::OverlayImageConflict { .. } => error_codes::OVERLAY_IMAGE_CONFLICT,
        _ => code,
    };
    AgentResponse::from_err(e, code)
}
