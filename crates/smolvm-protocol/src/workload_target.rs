//! Which filesystem a guest operation acts on.
//!
//! A machine's commands run either in the VM's own root filesystem (a bare
//! machine) or in a container whose root is a persistent overlay built from an
//! image (an image machine, or `run(image, ...)` on any machine). The host knows
//! which from the machine record, so it names the target on every request that
//! touches guest files instead of leaving the agent to infer it from what is
//! mounted. A file operation and an `exec` with the same target see the same
//! filesystem.

use serde::{Deserialize, Serialize};

/// The agent capability for [`WorkloadTarget`]: the agent resolves file
/// requests against the target they carry. An agent without it ignores the
/// field and infers the target, so the host must prepare the filesystem it
/// means before such an agent's file requests (see the host's client).
pub const WORKLOAD_TARGET_CAPABILITY: &str = "workload-target-v1";

/// The filesystem a guest operation acts on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WorkloadTarget {
    /// The VM's own root filesystem, where a bare machine's commands run.
    Vm,
    /// The container root of persistent overlay `overlay_id`, built from
    /// `image`. The agent mounts it if needed and refuses one that was built
    /// from a different image.
    Container {
        /// Image the overlay is built from.
        image: String,
        /// Persistent overlay id (the agent's overlay directory is
        /// `persistent-<overlay_id>`).
        overlay_id: String,
    },
}

impl WorkloadTarget {
    /// Check that the target is well formed: an overlay id is used as a path
    /// component in the guest, so it must be one.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Vm => Ok(()),
            Self::Container { image, overlay_id } => {
                if image.is_empty() {
                    return Err("container target has an empty image".into());
                }
                validate_overlay_id(overlay_id)
            }
        }
    }
}

/// Check that `id` is usable as a persistent overlay id: a single path
/// component of ASCII letters, digits, `.`, `_` and `-`, not `.` or `..`.
pub fn validate_overlay_id(id: &str) -> Result<(), String> {
    let valid = !id.is_empty()
        && id.len() <= 200
        && id != "."
        && id != ".."
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if valid {
        Ok(())
    } else {
        Err(format!("invalid overlay id {id:?}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_round_trip_as_tagged_json() {
        let vm = serde_json::to_string(&WorkloadTarget::Vm).unwrap();
        assert_eq!(vm, r#"{"kind":"vm"}"#);
        let container = WorkloadTarget::Container {
            image: "alpine:3.20".into(),
            overlay_id: "web".into(),
        };
        let json = serde_json::to_string(&container).unwrap();
        assert_eq!(
            json,
            r#"{"kind":"container","image":"alpine:3.20","overlay_id":"web"}"#
        );
        assert_eq!(
            serde_json::from_str::<WorkloadTarget>(&json).unwrap(),
            container
        );
    }

    #[test]
    fn overlay_ids_must_be_one_safe_path_component() {
        for ok in ["web", "my-vm.1", "a_b", "run-web-0123456789ab"] {
            assert!(validate_overlay_id(ok).is_ok(), "{ok}");
        }
        for bad in ["", ".", "..", "a/b", "../x", "a b", "x\0", &"a".repeat(201)] {
            assert!(validate_overlay_id(bad).is_err(), "{bad:?}");
        }
        assert!(WorkloadTarget::Container {
            image: String::new(),
            overlay_id: "web".into()
        }
        .validate()
        .is_err());
    }
}
