//! Guest-side trust for credential substitution.
//!
//! When the host mounts a machine's credential CA at
//! [`GUEST_CA_DIR`](smolvm_protocol::credentials::GUEST_CA_DIR), the workload
//! must trust it for the hosts the interceptor terminates while still trusting
//! public roots for everything spliced through. Several clients treat their CA
//! variable as a replacement for the system store (OpenSSL, curl, Python
//! `requests`, Git), so the agent assembles one bundle — the image's own roots
//! followed by the machine CA — and bind-mounts it where the host-provided
//! environment already points.

use crate::oci::OciSpec;
use smolvm_protocol::credentials::{GUEST_CA_BUNDLE, GUEST_CA_DIR, GUEST_CA_FILE};
use std::path::Path;

/// Agent-side location of the assembled bundle (tmpfs; rebuilt every boot).
const AGENT_BUNDLE: &str = "/run/smolvm-credentials/ca-bundle.pem";

/// Trust-root files commonly shipped by images, checked in order.
const SYSTEM_BUNDLES: &[&str] = &[
    "etc/ssl/certs/ca-certificates.crt",
    "etc/pki/tls/certs/ca-bundle.crt",
    "etc/ssl/ca-bundle.pem",
    "etc/pki/tls/cacert.pem",
    "etc/ssl/cert.pem",
];

/// If the machine's credential CA is among `mounts`, assemble the trust bundle
/// and bind it into the container at [`GUEST_CA_BUNDLE`].
pub fn inject_into_container(spec: &mut OciSpec, rootfs: &Path, mounts: &[(String, String, bool)]) {
    let Some((tag, _, _)) = mounts.iter().find(|(_, path, _)| path == GUEST_CA_DIR) else {
        return;
    };
    let ca_path = crate::storage::volume_bind_source(tag).join(GUEST_CA_FILE);
    let ca = match std::fs::read(&ca_path) {
        Ok(ca) => ca,
        Err(e) => {
            tracing::warn!(path = %ca_path.display(), error = %e, "credential CA not readable; workload will not trust the interceptor");
            return;
        }
    };
    let bundle = assemble_bundle(rootfs, &ca);
    if let Err(e) = write_bundle(&bundle) {
        tracing::warn!(error = %e, "could not write credential trust bundle");
        return;
    }
    if let Err(e) = crate::storage::ensure_file_mount_target_under_root(rootfs, GUEST_CA_BUNDLE) {
        tracing::warn!(error = %e, "could not prepare credential trust bundle mountpoint");
        return;
    }
    spec.add_bind_mount(AGENT_BUNDLE, GUEST_CA_BUNDLE, true);
}

/// The image's first available system bundle followed by the machine CA. An
/// image without system roots gets the machine CA alone, which is exactly the
/// trust it had before plus the interceptor.
fn assemble_bundle(rootfs: &Path, ca: &[u8]) -> Vec<u8> {
    let mut bundle = SYSTEM_BUNDLES
        .iter()
        .find_map(|candidate| std::fs::read(rootfs.join(candidate)).ok())
        .unwrap_or_default();
    if !bundle.is_empty() && !bundle.ends_with(b"\n") {
        bundle.push(b'\n');
    }
    bundle.extend_from_slice(ca);
    if !bundle.ends_with(b"\n") {
        bundle.push(b'\n');
    }
    bundle
}

fn write_bundle(bundle: &[u8]) -> std::io::Result<()> {
    let path = Path::new(AGENT_BUNDLE);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, bundle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_is_system_roots_then_machine_ca() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("etc/ssl/certs")).unwrap();
        std::fs::write(
            root.path().join("etc/ssl/certs/ca-certificates.crt"),
            b"-----BEGIN CERTIFICATE-----\nsystem\n-----END CERTIFICATE-----",
        )
        .unwrap();
        let ca = b"-----BEGIN CERTIFICATE-----\nmachine\n-----END CERTIFICATE-----\n";
        let bundle = assemble_bundle(root.path(), ca);
        let text = String::from_utf8(bundle).unwrap();
        assert!(text.starts_with("-----BEGIN CERTIFICATE-----\nsystem"));
        assert!(text.ends_with("machine\n-----END CERTIFICATE-----\n"));
        assert_eq!(text.matches("BEGIN CERTIFICATE").count(), 2);

        let empty = tempfile::tempdir().unwrap();
        assert_eq!(assemble_bundle(empty.path(), ca), ca.to_vec());
    }
}
