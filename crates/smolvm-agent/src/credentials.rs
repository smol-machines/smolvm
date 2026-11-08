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
//! A machine that booted with credential bindings gets the CA as a read-only
//! mount. One that gains its first binding while it runs, or whose CA is
//! widened to cover a new host, gets the certificate from the host instead
//! ([`install_live`]): the agent writes it, rebuilds every bundle, and gives
//! containers created later the same files.

use crate::oci::OciSpec;
use smolvm_protocol::credentials::{GUEST_CA_BUNDLE, GUEST_CA_DIR, GUEST_CA_FILE};
use std::path::Path;
use std::sync::Mutex;

/// Agent-side directory of the assembled bundles, one per container (tmpfs;
/// rebuilt every boot). Each container trusts its own image's roots, so no
/// container's bundle is another's.
const AGENT_BUNDLES: &str = "/run/smolvm-credentials/bundles";
/// Agent-side copy of a CA the host sent while the machine runs, bound into
/// containers that have no CA mount of their own.
const AGENT_CA: &str = "/run/smolvm-credentials/ca.pem";

/// The CA the host sent while the machine runs, newest first in force. Lives
/// in guest memory, so a checkpoint, a branch and a resume keep it.
static LIVE_CA: Mutex<Option<Vec<u8>>> = Mutex::new(None);

/// Containers given a bundle at creation: the agent-side bundle each one
/// binds, and the container's root filesystem it was assembled from.
static BUNDLES: Mutex<Vec<(std::path::PathBuf, std::path::PathBuf)>> = Mutex::new(Vec::new());

/// The agent-side bundle for the container whose root filesystem is `rootfs`.
fn bundle_path_for(rootfs: &Path) -> std::path::PathBuf {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    rootfs.hash(&mut hasher);
    Path::new(AGENT_BUNDLES).join(format!("{:016x}.pem", hasher.finish()))
}

fn live_ca() -> Option<Vec<u8>> {
    LIVE_CA.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

fn guest_ca_path() -> String {
    format!("{GUEST_CA_DIR}/{GUEST_CA_FILE}")
}

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
    let ca_mount = mounts.iter().find(|(_, path, _)| path == GUEST_CA_DIR);
    // A CA the host sent while the machine runs is the newest certificate,
    // even beside a CA mount: it may have been widened since boot.
    let ca = match (live_ca(), ca_mount) {
        (Some(ca), _) => ca,
        (None, Some((tag, _, _))) => {
            let ca_path = crate::storage::volume_bind_source(tag).join(GUEST_CA_FILE);
            match std::fs::read(&ca_path) {
                Ok(ca) => ca,
                Err(e) => {
                    tracing::warn!(path = %ca_path.display(), error = %e, "credential CA not readable; workload will not trust the interceptor");
                    return;
                }
            }
        }
        (None, None) => return,
    };
    let bundle = assemble_bundle(rootfs, Path::new("/"), &ca);
    let bundle_path = bundle_path_for(rootfs);
    if let Err(e) = write_file(&bundle_path, &bundle) {
        tracing::warn!(error = %e, "could not write credential trust bundle");
        return;
    }
    if let Err(e) = crate::storage::ensure_file_mount_target_under_root(rootfs, GUEST_CA_BUNDLE) {
        tracing::warn!(error = %e, "could not prepare credential trust bundle mountpoint");
        return;
    }
    spec.add_bind_mount(&bundle_path.to_string_lossy(), GUEST_CA_BUNDLE, true);
    let mut bound = BUNDLES.lock().unwrap_or_else(|e| e.into_inner());
    bound.retain(|(path, _)| *path != bundle_path);
    bound.push((bundle_path, rootfs.to_path_buf()));
    drop(bound);
    // Without a CA mount, the CA file itself comes from the agent's copy.
    if ca_mount.is_none() {
        let target = guest_ca_path();
        if let Err(e) = crate::storage::ensure_file_mount_target_under_root(rootfs, &target) {
            tracing::warn!(error = %e, "could not prepare credential CA mountpoint");
            return;
        }
        spec.add_bind_mount(AGENT_CA, &target, true);
    }
}

/// Trust `ca_pem` from now on, in the machine root and every running
/// workload container, and remember it for containers created later.
///
/// Where the CA is the machine's own read-only mount (it booted with
/// bindings), the host has already replaced the file under it; only the
/// bundles, which hold a copy, are rebuilt. Everywhere else the agent writes
/// the CA file too.
pub fn install_live(ca_pem: &str) -> Result<(), String> {
    if !ca_pem.contains("-----BEGIN CERTIFICATE-----") {
        return Err("credential CA is not a PEM certificate".to_string());
    }
    let mut ca = ca_pem.as_bytes().to_vec();
    if !ca.ends_with(b"\n") {
        ca.push(b'\n');
    }
    write_file(Path::new(AGENT_CA), &ca).map_err(|e| format!("write {AGENT_CA}: {e}"))?;
    *LIVE_CA.lock().unwrap_or_else(|e| e.into_inner()) = Some(ca.clone());

    // The machine root, where a machine without an image runs its commands.
    write_unless_read_only(Path::new(&guest_ca_path()), &ca)?;
    let root_bundle = assemble_bundle(Path::new("/"), Path::new("/"), &ca);
    write_file(Path::new(GUEST_CA_BUNDLE), &root_bundle)
        .map_err(|e| format!("write {GUEST_CA_BUNDLE}: {e}"))?;
    // Containers given a bundle when they were created bind their own file;
    // rewriting it in place updates that container, from its own roots.
    let bound = BUNDLES.lock().unwrap_or_else(|e| e.into_inner()).clone();
    for (bundle_path, rootfs) in bound {
        if rootfs.is_dir() {
            write_file(&bundle_path, &assemble_bundle(&rootfs, Path::new("/"), &ca))
                .map_err(|e| format!("write {}: {e}", bundle_path.display()))?;
        }
    }

    let mut failures = Vec::new();
    for pid in crate::nsfile::container_namespace_pids() {
        if let Err(e) = install_in_container(pid, &ca) {
            failures.push(format!("container {pid}: {e}"));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

/// Write the CA and a bundle of the container's own roots into container
/// `pid`. A bundle that is the container's bind of its agent-side file is
/// read-only there, and was rewritten through that file already.
fn install_in_container(pid: u32, ca: &[u8]) -> Result<(), String> {
    use crate::nsfile::{write_in_container, ContainerWriteError};
    // The container's root as the agent sees it; paths below it are resolved
    // as the container would resolve them (see `read_in_root`).
    let rootfs = std::path::PathBuf::from(format!("/proc/{pid}/root"));
    let bundle = assemble_bundle(&rootfs, Path::new("/"), ca);
    match write_in_container(pid, GUEST_CA_BUNDLE, &bundle) {
        Ok(()) | Err(ContainerWriteError::ReadOnly) => {}
        Err(ContainerWriteError::Failed(e)) => return Err(format!("{GUEST_CA_BUNDLE}: {e}")),
    }
    match write_in_container(pid, &guest_ca_path(), ca) {
        // The CA's own mount, already replaced by the host.
        Ok(()) | Err(ContainerWriteError::ReadOnly) => Ok(()),
        Err(ContainerWriteError::Failed(e)) => Err(format!("{}: {e}", guest_ca_path())),
    }
}

/// Overwrite `path` in place, creating it and its directory when missing.
fn write_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, bytes)
}

/// [`write_file`], leaving a file on a read-only mount alone.
fn write_unless_read_only(path: &Path, bytes: &[u8]) -> Result<(), String> {
    match write_file(path, bytes) {
        Ok(()) => Ok(()),
        #[cfg(target_os = "linux")]
        Err(e) if e.raw_os_error() == Some(libc::EROFS) => Ok(()),
        Err(e) => Err(format!("write {}: {e}", path.display())),
    }
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
            read_in_root(root, candidate).filter(|pem| {
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

/// Read `path` as a process whose root directory is `root` would: a link,
/// absolute or relative, is followed inside `root`, and `..` never climbs
/// above it. A container image's roots are commonly links (`/etc/ssl/cert.pem
/// -> /etc/pki/...`), which read from outside would resolve against the
/// machine's own root instead of the container's.
fn read_in_root(root: &Path, path: &str) -> Option<Vec<u8>> {
    use std::collections::VecDeque;
    use std::ffi::OsString;
    use std::path::Component;
    fn parts(path: &Path) -> VecDeque<OsString> {
        path.components()
            .filter_map(|c| match c {
                Component::Normal(name) => Some(name.to_os_string()),
                Component::ParentDir => Some(OsString::from("..")),
                _ => None,
            })
            .collect()
    }
    let mut pending = parts(Path::new(path));
    let mut resolved: Vec<OsString> = Vec::new();
    let mut links = 0;
    while let Some(part) = pending.pop_front() {
        if part == ".." {
            resolved.pop();
            continue;
        }
        let mut candidate = root.to_path_buf();
        candidate.extend(&resolved);
        candidate.push(&part);
        let meta = std::fs::symlink_metadata(&candidate).ok()?;
        if meta.file_type().is_symlink() {
            links += 1;
            if links > 40 {
                return None;
            }
            let target = std::fs::read_link(&candidate).ok()?;
            if target.is_absolute() {
                resolved.clear();
            }
            let mut next = parts(&target);
            next.extend(pending);
            pending = next;
        } else {
            resolved.push(part);
        }
    }
    let mut file = root.to_path_buf();
    file.extend(&resolved);
    std::fs::read(file).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An image's roots reached through links resolve inside its own root:
    /// an absolute link restarts at the container root, not the machine's,
    /// and `..` cannot climb out of it.
    #[cfg(unix)]
    #[test]
    fn roots_behind_links_are_read_inside_the_containers_root() {
        let root = tempfile::tempdir().unwrap();
        let r = root.path();
        std::fs::create_dir_all(r.join("etc/pki/tls/certs")).unwrap();
        std::fs::create_dir_all(r.join("etc/ssl/certs")).unwrap();
        std::fs::write(
            r.join("etc/pki/tls/certs/ca-bundle.crt"),
            b"-----BEGIN CERTIFICATE-----\ncontainer\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(
            "/etc/pki/tls/certs/ca-bundle.crt",
            r.join("etc/ssl/certs/ca-certificates.crt"),
        )
        .unwrap();
        let read = read_in_root(r, "etc/ssl/certs/ca-certificates.crt").unwrap();
        assert!(String::from_utf8(read).unwrap().contains("container"));

        // A relative link climbing above the root stays inside it.
        std::os::unix::fs::symlink(
            "../../../../../../etc/pki/tls/certs/ca-bundle.crt",
            r.join("etc/ssl/cert.pem"),
        )
        .unwrap();
        assert!(read_in_root(r, "etc/ssl/cert.pem").is_some());
        // A loop ends instead of spinning.
        std::os::unix::fs::symlink("loop-b", r.join("etc/loop-a")).unwrap();
        std::os::unix::fs::symlink("loop-a", r.join("etc/loop-b")).unwrap();
        assert!(read_in_root(r, "etc/loop-a").is_none());
        // The whole bundle comes from the container's roots.
        let bundle = assemble_bundle(
            r,
            Path::new("/nonexistent"),
            b"-----BEGIN CERTIFICATE-----\nmachine\n-----END CERTIFICATE-----\n",
        );
        let text = String::from_utf8(bundle).unwrap();
        assert!(
            text.starts_with("-----BEGIN CERTIFICATE-----\ncontainer"),
            "{text}"
        );
    }

    /// Each container's bundle has a file of its own, so one container's
    /// roots never end up in another's trust.
    #[test]
    fn every_container_gets_its_own_bundle_file() {
        let a = bundle_path_for(Path::new("/storage/overlays/a/merged"));
        let b = bundle_path_for(Path::new("/storage/overlays/b/merged"));
        assert_ne!(a, b);
        assert_eq!(a, bundle_path_for(Path::new("/storage/overlays/a/merged")));
        assert!(a.starts_with(AGENT_BUNDLES));
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
