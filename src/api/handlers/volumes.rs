//! Volume provisioning endpoints — node-side storage for the control plane.
//!
//! smolfleet's `create_volume`/`delete_volume` call these to materialize a `local`
//! volume ON the worker (not on the control plane's own disk, which the worker
//! can't see): a directory under the smolvm data dir that the worker
//! virtiofs-shares into a guest at mount time.
//!
//! Persistent-disk (`pd`) volumes are NOT handled here — disk create/format/attach
//! run on the control plane (which has cloud credentials and no `serve` syscall
//! reaper), and the node-agent does the final mount out-of-band. See smolfleet
//! docs/d3-replicated-volumes.md.

use axum::{extract::Path, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

use crate::api::error::ApiError;

/// Request body for `POST /api/v1/volumes`.
#[derive(Deserialize)]
pub struct ProvisionVolumeRequest {
    /// Control-plane volume id (e.g. `vol-<hex>`); names the on-node directory.
    pub id: String,
    /// Requested size. Advisory for the `local` backend — a plain directory has no
    /// hard quota.
    #[serde(default)]
    pub size_gb: u64,
    /// Storage backend. Only `local` (a worker dir, the default) is handled on the
    /// node; `pd` volumes are driven from the control plane, not here.
    #[serde(default)]
    pub backend: Option<String>,
}

/// Response body for `POST /api/v1/volumes`.
#[derive(Serialize)]
pub struct ProvisionVolumeResponse {
    /// Host path the volume is mounted at on this node — becomes a workload mount
    /// `source`.
    pub node_path: String,
}

/// Base directory for node-local volumes: `<data_local_dir>/smolvm/volumes`.
fn volumes_base() -> std::path::PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("smolvm")
        .join("volumes")
}

/// Reject ids that could escape the volumes base (path traversal / separators).
/// The control plane generates `vol-<hex>`; this is defense in depth.
fn safe_volume_id(id: &str) -> Result<(), ApiError> {
    let ok = !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if ok {
        Ok(())
    } else {
        Err(ApiError::BadRequest(format!("invalid volume id: {id:?}")))
    }
}

/// `POST /api/v1/volumes` — create the backing storage and return its host path.
pub async fn provision_volume(
    Json(req): Json<ProvisionVolumeRequest>,
) -> Result<Json<ProvisionVolumeResponse>, ApiError> {
    safe_volume_id(&req.id)?;
    match req.backend.as_deref().unwrap_or("local") {
        "local" => {
            let path = volumes_base().join(&req.id);
            std::fs::create_dir_all(&path).map_err(ApiError::internal)?;
            // The node service runs as root, so the dir is created root:root 0755.
            // But a machine mounts it via virtiofs under per-VM uid isolation
            // (#456): the guest's uid 0 is a dropped host uid (e.g. 2000025), and
            // the virtiofs daemon writing on the guest's behalf runs as THAT uid —
            // which has no write access to a root-owned 0755 dir, so every write
            // into the mounted volume fails with EACCES (the volume is read-only in
            // practice). Make the volume root world-writable so whichever per-VM
            // uid mounts it can write; the dir is only ever virtiofs-exposed to the
            // single VM that has it attached (volumes are single-attach), and the
            // per-VM uid boundary — not these bits — is the isolation guarantee.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o777))
                    .map_err(ApiError::internal)?;
            }
            let node_path = path.to_string_lossy().to_string();
            tracing::info!(volume_id = %req.id, node_path = %node_path, size_gb = req.size_gb, "provisioned local volume");
            Ok(Json(ProvisionVolumeResponse { node_path }))
        }
        other => Err(ApiError::BadRequest(format!(
            "unsupported node volume backend: {other:?} (pd volumes are driven from the control plane)"
        ))),
    }
}

/// `DELETE /api/v1/volumes/{id}` — tear down the backing storage. Idempotent:
/// deleting an already-absent volume succeeds.
pub async fn deprovision_volume(Path(id): Path<String>) -> Result<StatusCode, ApiError> {
    safe_volume_id(&id)?;
    let path = volumes_base().join(&id);
    match std::fs::remove_dir_all(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {} // already gone
        Err(e) => return Err(ApiError::internal(e)),
    }
    tracing::info!(volume_id = %id, "deprovisioned local volume");
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_path_traversal_ids() {
        assert!(safe_volume_id("vol-abc123").is_ok());
        assert!(safe_volume_id("vol_1").is_ok());
        assert!(safe_volume_id("../etc").is_err());
        assert!(safe_volume_id("a/b").is_err());
        assert!(safe_volume_id("").is_err());
        assert!(safe_volume_id(&"x".repeat(200)).is_err());
    }

    #[test]
    fn volumes_base_is_under_smolvm() {
        let b = volumes_base();
        assert!(b.ends_with("smolvm/volumes"), "got {b:?}");
    }
}
