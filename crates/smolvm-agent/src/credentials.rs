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
    let bundle = assemble_bundle(rootfs, Path::new("/"), &ca);
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

/// For a machine without a container image, whose commands run in the agent's
/// own root: if the credential CA is among the boot `mounts`, assemble the
/// trust bundle from the agent's roots and the CA and write it at
/// [`GUEST_CA_BUNDLE`], where the workload's environment already points.
/// Without it, clients that honour `SSL_CERT_FILE` trust nothing at all.
pub fn install_for_agent_root(mounts: &[(String, String, bool)]) {
    install_bundle_at(mounts, Path::new("/"), Path::new(GUEST_CA_BUNDLE));
}

fn install_bundle_at(mounts: &[(String, String, bool)], root: &Path, bundle_path: &Path) {
    if !mounts.iter().any(|(_, path, _)| path == GUEST_CA_DIR) {
        return;
    }
    let ca_path = root
        .join(GUEST_CA_DIR.trim_start_matches('/'))
        .join(GUEST_CA_FILE);
    let ca = match std::fs::read(&ca_path) {
        Ok(ca) => ca,
        Err(e) => {
            tracing::warn!(path = %ca_path.display(), error = %e, "credential CA not readable; workload will not trust the interceptor");
            return;
        }
    };
    let bundle = assemble_bundle(root, root, &ca);
    let written = bundle_path
        .parent()
        .map_or(Ok(()), std::fs::create_dir_all)
        .and_then(|()| std::fs::write(bundle_path, bundle));
    if let Err(e) = written {
        tracing::warn!(path = %bundle_path.display(), error = %e, "could not write credential trust bundle");
    }
}

/// Prefer the image's own trust roots. Minimal images without roots still need
/// public HTTPS trust: use the agent's bundled public roots in that case, then
/// append the machine CA for intercepted hosts. Never use host-specific roots
/// here; a host-specific root would silently widen the machine's trust.
fn assemble_bundle(rootfs: &Path, agent_rootfs: &Path, ca: &[u8]) -> Vec<u8> {
    let read_roots = |root: &Path| {
        SYSTEM_BUNDLES.iter().find_map(|candidate| {
            std::fs::read(root.join(candidate)).ok().filter(|pem| {
                pem.windows(b"-----BEGIN CERTIFICATE-----".len())
                    .any(|window| window == b"-----BEGIN CERTIFICATE-----")
            })
        })
    };
    let mut bundle = read_roots(rootfs)
        .or_else(|| read_roots(agent_rootfs))
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
    fn a_machine_without_an_image_gets_the_bundle_its_environment_names() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("etc/ssl/certs")).unwrap();
        std::fs::write(
            root.path().join("etc/ssl/certs/ca-certificates.crt"),
            b"-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let ca_dir = root.path().join(GUEST_CA_DIR.trim_start_matches('/'));
        std::fs::create_dir_all(&ca_dir).unwrap();
        std::fs::write(
            ca_dir.join(GUEST_CA_FILE),
            b"-----BEGIN CERTIFICATE-----\nmachine\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let bundle = root.path().join("run/smolvm/ca-bundle.pem");

        // No credential CA mounted: nothing to trust, nothing written.
        install_bundle_at(&[], root.path(), &bundle);
        assert!(!bundle.exists());

        let mounts = [("smolvm0".to_string(), GUEST_CA_DIR.to_string(), true)];
        install_bundle_at(&mounts, root.path(), &bundle);
        let text = std::fs::read_to_string(&bundle).unwrap();
        assert!(text.starts_with("-----BEGIN CERTIFICATE-----\npublic"));
        assert!(text.ends_with("machine\n-----END CERTIFICATE-----\n"));
    }

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
        let agent = tempfile::tempdir().unwrap();
        let bundle = assemble_bundle(root.path(), agent.path(), ca);
        let text = String::from_utf8(bundle).unwrap();
        assert!(text.starts_with("-----BEGIN CERTIFICATE-----\nsystem"));
        assert!(text.ends_with("machine\n-----END CERTIFICATE-----\n"));
        assert_eq!(text.matches("BEGIN CERTIFICATE").count(), 2);

        let empty = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(agent.path().join("etc/ssl/certs")).unwrap();
        std::fs::write(
            agent.path().join("etc/ssl/certs/ca-certificates.crt"),
            b"-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let fallback = String::from_utf8(assemble_bundle(empty.path(), agent.path(), ca)).unwrap();
        assert!(fallback.starts_with("-----BEGIN CERTIFICATE-----\npublic"));
        assert!(fallback.ends_with("machine\n-----END CERTIFICATE-----\n"));
        assert_eq!(fallback.matches("BEGIN CERTIFICATE").count(), 2);

        let no_roots = tempfile::tempdir().unwrap();
        assert_eq!(
            assemble_bundle(empty.path(), no_roots.path(), ca),
            ca.to_vec()
        );
    }
}
