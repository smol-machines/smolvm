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
//!
//! Chrome and Chromium ignore those variables and the system store alike on
//! most distributions, so they get the CA through their `CACertificates`
//! policy: a file of its own in their managed-policy directories, which no
//! package writes. The image's system bundle and trust anchors are left
//! alone: a read-only file over a bundle makes the CA package's own update
//! fail, and an anchor would be baked into the image's bundle by the next
//! `update-ca-trust`.

use crate::oci::OciSpec;
use smolvm_protocol::credentials::{GUEST_CA_BUNDLE, GUEST_CA_DIR, GUEST_CA_FILE};
use std::path::{Path, PathBuf};

/// Every bundle this boot assembled: (the machine CA file it read, the root whose trust roots it started from, where
/// it was written), so [`refresh`] rebuilds each in place when the host adds a CA.
static BUILT: std::sync::Mutex<Vec<(PathBuf, PathBuf, PathBuf)>> =
    std::sync::Mutex::new(Vec::new());

/// The machine's credential CA bundle as the host last pushed it ([`push_ca`]). The host rewrites the CA file in
/// place when it adds a CA, and the guest's file cache can serve the old contents for a while after, so a pushed copy
/// is preferred to the file. The host only ever appends CAs, so the pushed copy is never older than the file.
static PUSHED: std::sync::Mutex<Option<Vec<u8>>> = std::sync::Mutex::new(None);

/// Use `ca` as the machine's credential CA bundle from now on, in place of its file.
pub fn push_ca(ca: Vec<u8>) {
    *PUSHED.lock().unwrap_or_else(|e| e.into_inner()) = Some(ca);
}

/// The machine's credential CA bundle: the pushed copy, else the file at `ca_path`.
fn read_ca(ca_path: &Path) -> std::io::Result<Vec<u8>> {
    match PUSHED.lock().unwrap_or_else(|e| e.into_inner()).clone() {
        Some(ca) => Ok(ca),
        None => std::fs::read(ca_path),
    }
}

fn remember(ca_path: &Path, roots: &Path, bundle: &Path) {
    let mut built = BUILT.lock().unwrap_or_else(|e| e.into_inner());
    built.retain(|(_, _, b)| b != bundle);
    built.push((
        ca_path.to_path_buf(),
        roots.to_path_buf(),
        bundle.to_path_buf(),
    ));
}

/// Rebuild every bundle this boot assembled from the CA file as it is now. Written in place, so a bundle bind-mounted
/// into a running container shows the new roots to its next connection. Returns how many it rebuilt.
pub fn refresh() -> std::io::Result<usize> {
    let mut built = BUILT.lock().unwrap_or_else(|e| e.into_inner());
    // a bundle whose CA file or root is gone (its container exited) has nothing left to trust: dropped, not an error
    built.retain(|(ca_path, roots, bundle)| {
        ca_path.exists() && roots.exists() && bundle.parent().is_some_and(Path::exists)
    });
    // one bundle that cannot be rewritten does not keep the others on the old roots
    let mut rebuilt = 0;
    for (ca_path, roots, bundle) in built.iter() {
        let written = read_ca(ca_path)
            .and_then(|ca| std::fs::write(bundle, assemble_bundle(roots, Path::new("/"), &ca)));
        match written {
            Ok(()) => rebuilt += 1,
            Err(e) => {
                tracing::warn!(bundle = %bundle.display(), error = %e, "could not rebuild credential trust bundle")
            }
        }
        // the browser policy is bound beside the container's bundle
        if bundle == Path::new(AGENT_BUNDLE) {
            if let Err(e) = read_ca(ca_path).and_then(|ca| write_browser_policy(&ca)) {
                tracing::warn!(error = %e, "could not rewrite the credential CA browser policy")
            }
        }
    }
    Ok(rebuilt)
}

/// Agent-side location of the assembled bundle (tmpfs; rebuilt every boot).
const AGENT_BUNDLE: &str = "/run/smolvm-credentials/ca-bundle.pem";
/// Agent-side Chrome/Chromium policy trusting the machine CA.
const AGENT_BROWSER_POLICY: &str = "/run/smolvm-credentials/browser-policy.json";

/// Managed-policy directories of Chromium and of Google Chrome. Created when
/// missing, since a browser installed after the container starts still reads
/// them.
const BROWSER_POLICY_DIRS: &[&str] = &[
    "/etc/chromium/policies/managed",
    "/etc/opt/chrome/policies/managed",
];
const BROWSER_POLICY_FILE: &str = "smolvm-credentials.json";

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
    let ca = match read_ca(&ca_path) {
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
    remember(&ca_path, rootfs, Path::new(AGENT_BUNDLE));
    if let Err(e) = crate::storage::ensure_file_mount_target_under_root(rootfs, GUEST_CA_BUNDLE) {
        tracing::warn!(error = %e, "could not prepare credential trust bundle mountpoint");
        return;
    }
    spec.add_bind_mount(AGENT_BUNDLE, GUEST_CA_BUNDLE, true);
    if let Err(e) = write_browser_policy(&ca) {
        tracing::warn!(error = %e, "could not write the credential CA browser policy");
        return;
    }
    for dir in BROWSER_POLICY_DIRS {
        bind_file(
            spec,
            rootfs,
            AGENT_BROWSER_POLICY,
            &format!("{dir}/{BROWSER_POLICY_FILE}"),
        );
    }
}

/// Bind the agent's `source` read-only at `target` in the container, creating
/// an empty file there first when the image has none.
fn bind_file(spec: &mut OciSpec, rootfs: &Path, source: &str, target: &str) {
    match crate::storage::ensure_file_mount_target_under_root(rootfs, target) {
        Ok(_) => spec.add_bind_mount(source, target, true),
        Err(e) => {
            tracing::warn!(target, error = %e, "could not prepare a credential trust mountpoint")
        }
    }
}

/// Chrome's and Chromium's `CACertificates` policy for every certificate in
/// `ca`: each certificate's DER, base64-encoded, which is its PEM body.
fn browser_policy(ca: &[u8]) -> Vec<u8> {
    let mut certificates: Vec<String> = Vec::new();
    let mut current: Option<String> = None;
    for line in String::from_utf8_lossy(ca).lines().map(str::trim) {
        match line {
            "-----BEGIN CERTIFICATE-----" => current = Some(String::new()),
            "-----END CERTIFICATE-----" => certificates.extend(current.take()),
            body => {
                if let Some(cert) = current.as_mut() {
                    cert.push_str(body);
                }
            }
        }
    }
    serde_json::to_vec(&serde_json::json!({ "CACertificates": certificates })).unwrap_or_default()
}

/// Write the browser policy beside the assembled bundle, in place, so its
/// bind shows a CA added later.
fn write_browser_policy(ca: &[u8]) -> std::io::Result<()> {
    std::fs::create_dir_all(
        Path::new(AGENT_BROWSER_POLICY)
            .parent()
            .unwrap_or(Path::new("/")),
    )?;
    std::fs::write(AGENT_BROWSER_POLICY, browser_policy(ca))
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
    let ca = match read_ca(&ca_path) {
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
    match written {
        Ok(()) => remember(&ca_path, root, bundle_path),
        Err(e) => {
            tracing::warn!(path = %bundle_path.display(), error = %e, "could not write credential trust bundle")
        }
    }
}

/// Prefer the image's own trust roots. Minimal images without roots still need
/// public HTTPS trust: use the agent's bundled public roots in that case, then
/// append the machine CA for intercepted hosts. Never use host-specific roots
/// here; a host-specific root would silently widen the machine's trust.
fn assemble_bundle(rootfs: &Path, agent_rootfs: &Path, ca: &[u8]) -> Vec<u8> {
    let read_roots = |root: &Path| {
        SYSTEM_BUNDLES.iter().find_map(|candidate| {
            // through the image's own links: Fedora's bundle is an absolute
            // link, which read from here would land in the agent's root
            #[cfg(target_os = "linux")]
            let path = crate::container::resolve_in_root(root, candidate)?;
            #[cfg(not(target_os = "linux"))]
            let path = root.join(candidate);
            std::fs::read(path).ok().filter(|pem| {
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

    /// Chrome takes each CA as its base64 DER: the PEM body, joined.
    #[test]
    fn the_browser_policy_lists_every_certificate_in_the_bundle() {
        let ca = b"-----BEGIN CERTIFICATE-----\nQUJD\nREVG\n-----END CERTIFICATE-----\n\
                   -----BEGIN CERTIFICATE-----\nR0hJ\n-----END CERTIFICATE-----\n";
        let policy: serde_json::Value = serde_json::from_slice(&browser_policy(ca)).unwrap();
        assert_eq!(
            policy,
            serde_json::json!({ "CACertificates": ["QUJDREVG", "R0hJ"] })
        );
    }

    /// Fedora's bundle is an absolute link into `ca-trust/extracted`: the
    /// image's roots are read through it inside the image, not from the
    /// agent's own root.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_images_roots_are_read_through_its_own_links() {
        let root = tempfile::tempdir().unwrap();
        let extracted = root.path().join("etc/pki/ca-trust/extracted/pem");
        std::fs::create_dir_all(&extracted).unwrap();
        const ROOTS: &[u8] = b"-----BEGIN CERTIFICATE-----\nroots\n-----END CERTIFICATE-----\n";
        std::fs::write(extracted.join("tls-ca-bundle.pem"), ROOTS).unwrap();
        std::fs::create_dir_all(root.path().join("etc/ssl/certs")).unwrap();
        std::os::unix::fs::symlink(
            "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
            root.path().join("etc/ssl/certs/ca-certificates.crt"),
        )
        .unwrap();
        let bundle = assemble_bundle(root.path(), Path::new("/nonexistent"), b"ca\n");
        assert_eq!(
            bundle,
            [ROOTS, b"ca\n"].concat(),
            "the image's roots, read through its link"
        );
    }

    /// A CA the host adds while the machine runs reaches the bundle it built at boot, rewritten in place.
    #[test]
    fn refresh_rebuilds_the_boot_bundle_from_the_ca_file_as_it_is_now() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("etc/ssl/certs")).unwrap();
        std::fs::write(
            root.path().join("etc/ssl/certs/ca-certificates.crt"),
            b"-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let ca_dir = root.path().join(GUEST_CA_DIR.trim_start_matches('/'));
        std::fs::create_dir_all(&ca_dir).unwrap();
        let ca_file = ca_dir.join(GUEST_CA_FILE);
        std::fs::write(
            &ca_file,
            b"-----BEGIN CERTIFICATE-----\nmachine\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let bundle = root.path().join("bundle.pem");
        let mounts = vec![("tag".to_string(), GUEST_CA_DIR.to_string(), true)];
        install_bundle_at(&mounts, root.path(), &bundle);
        let inode = |p: &Path| std::os::unix::fs::MetadataExt::ino(&std::fs::metadata(p).unwrap());
        let before = inode(&bundle);
        assert!(!String::from_utf8_lossy(&std::fs::read(&bundle).unwrap()).contains("added"));
        std::fs::write(
            &ca_file,
            b"-----BEGIN CERTIFICATE-----\nmachine\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nadded\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        assert!(refresh().unwrap() >= 1);
        let after = String::from_utf8_lossy(&std::fs::read(&bundle).unwrap()).into_owned();
        assert!(
            after.contains("public") && after.contains("machine") && after.contains("added"),
            "{after}"
        );
        assert_eq!(
            inode(&bundle),
            before,
            "rewritten in place, so a bind mount of it sees the new roots"
        );
    }

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
