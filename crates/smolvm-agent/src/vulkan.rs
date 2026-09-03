//! Guest-side Vulkan (Venus) driver injection for the workload container.
//!
//! A `--gpu` VM exposes `/dev/dri` into every container
//! (`oci::add_gpu_devices_if_available`), but the container can only use
//! Vulkan if its image ships a Mesa with the virtio ICD — which stock images
//! don't, and on macOS hosts even a stock Mesa fails Venus blob negotiation
//! (16 KiB pages; needs the mesa-krunkit patch). The agent rootfs bundles the
//! patched driver, its shared-library closure, and the Vulkan loader
//! (`scripts/fetch-vulkan-guest-driver.sh`); this module bind-mounts the
//! bundle into the container and points the Vulkan loader at it, mirroring
//! [`crate::cuda`]'s shim staging.
//!
//! Every gate degrades to a silent no-op, so behavior without the bundle (or
//! on non-GPU VMs) is exactly today's.

/// Where the bundle ships inside the VM rootfs (from the agent rootfs).
const GUEST_BUNDLE_DIR: &str = "/usr/local/lib/smolvm-vulkan";
/// Where the bundle is bind-mounted inside the workload container. The ICD
/// manifest's `library_path` points here, so the two must stay in sync with
/// `scripts/fetch-vulkan-guest-driver.sh`.
const CONTAINER_BUNDLE_DIR: &str = "/opt/smolvm-vulkan";
/// The Venus driver inside the bundle — its presence is the "bundled" gate.
const DRIVER: &str = "libvulkan_virtio.so";
/// The ICD manifest inside the bundle.
const ICD_JSON: &str = "virtio_icd.json";
/// The bundle keeps the Vulkan loader in its own subdirectory so an image that
/// ships none can be pointed at the loader alone. Nothing else in the bundle
/// may ever land on `LD_LIBRARY_PATH`: its libzstd, libexpat, libz and libdrm
/// are older than any current distro's and would shadow them for every
/// process in the container. The driver and its closure carry
/// `RUNPATH=$ORIGIN` instead (scripts/fetch-vulkan-guest-driver.sh), so they
/// resolve each other only when the driver itself is loaded.
const LOADER_SUBDIR: &str = "loader";
/// The loader's soname; its presence is what "the image has a loader" means.
const LOADER: &str = "libvulkan.so.1";
/// Request-level opt-out (set via `--env`).
const OPT_OUT_ENV: &str = "SMOLVM_NO_VULKAN_INJECT";

/// Stage the bundled Venus driver into the workload container spec so an
/// unmodified image gets working Vulkan on a `--gpu` VM with no setup: the
/// bundle rides a read-only bind mount, `VK_DRIVER_FILES` pins the loader to
/// our ICD (unless the user chose a driver themselves), and `LD_LIBRARY_PATH`
/// resolves the loader for images that ship none. No-op unless the VM has a
/// GPU, the bundle is present, and the image's libc can load it (glibc).
pub fn inject_into_container(spec: &mut crate::oci::OciSpec, rootfs: &std::path::Path) {
    inject_into_container_if(
        spec,
        rootfs,
        std::path::Path::new("/dev/dri").exists(),
        std::path::Path::new(GUEST_BUNDLE_DIR),
    );
}

/// Testable core of [`inject_into_container`].
fn inject_into_container_if(
    spec: &mut crate::oci::OciSpec,
    rootfs: &std::path::Path,
    gpu_present: bool,
    bundle_dir: &std::path::Path,
) {
    if !gpu_present {
        return; // not a --gpu VM
    }
    if !bundle_dir.join(DRIVER).is_file() || !bundle_dir.join(ICD_JSON).is_file() {
        return; // bundle not shipped in this rootfs — manual setup still works
    }
    if env_set(&spec.process.env, OPT_OUT_ENV) {
        return; // user opted out for this workload
    }
    if is_musl_image(rootfs) {
        // The bundled driver is glibc; a musl image can't load it. Skip until
        // a musl bundle ships rather than surface a confusing dlopen error.
        return;
    }

    spec.add_bind_mount(&bundle_dir.to_string_lossy(), CONTAINER_BUNDLE_DIR, true);

    // Pin the loader to our ICD unless the image or request already chose a
    // driver — an explicit user choice always wins. Pinning one ICD also
    // sidesteps multi-ICD probe failures (unrelated ICDs crashing the probe,
    // or a swapchain-less device being picked over Venus).
    if !env_set(&spec.process.env, "VK_DRIVER_FILES")
        && !env_set(&spec.process.env, "VK_ICD_FILENAMES")
    {
        spec.add_env(
            "VK_DRIVER_FILES",
            &format!("{}/{}", CONTAINER_BUNDLE_DIR, ICD_JSON),
        );
    }

    // Loader fallback for images without libvulkan.so.1: only the loader's own
    // directory, appended so an image-provided one earlier on the path still
    // wins. The driver never needs the path -- the manifest names it by
    // absolute path and its closure resolves via RUNPATH -- and exposing the
    // whole bundle shadowed the image's libzstd, libexpat, libz and libdrm for
    // every process (tar --zstd, pacman hooks and python's expat all broke,
    // and eglInitialize failed so GL fell back to software).
    if !image_has_vulkan_loader(rootfs) && bundle_has_loader(bundle_dir) {
        append_ld_library_path(&mut spec.process.env, &container_loader_dir());
    }
}
/// `CONTAINER_BUNDLE_DIR/loader` -- where the bundle's loader is inside the
/// container.
fn container_loader_dir() -> String {
    format!("{CONTAINER_BUNDLE_DIR}/{LOADER_SUBDIR}")
}
/// Does the bundle (seen from the agent or from inside the container) carry
/// the loader in its own directory? Older bundles kept it flat; those are
/// never exposed, since the flat layout is exactly what shadowed the image.
fn bundle_has_loader(bundle_dir: &std::path::Path) -> bool {
    bundle_dir.join(LOADER_SUBDIR).join(LOADER).is_file()
}

/// Append the Vulkan loader pin (and the bundle's loader path) to an explicit
/// exec env. Used on the `crun exec` path (joining a persistent machine's
/// keep-alive container), where the workload env is passed via `--env` rather
/// than inherited from the container spec, so the spec injection above doesn't
/// reach it. A user-provided driver choice in the exec env still wins.
///
/// The gate is the bundle's ACTUAL presence inside the target container, read
/// through the container's own mount namespace — not a re-derivation of the
/// inject path's policy. Pointing `VK_DRIVER_FILES` at a bundle the container
/// never received is worse than leaving Vulkan alone: the loader fails with
/// `Found no drivers!` naming a smolvm path, which reads as a broken install
/// rather than an unsupported image, and sends people hunting for a missing
/// mount (#1050). Asking the container covers every reason the mount can be
/// absent — a musl image, the opt-out, or a creation path that never injects —
/// without duplicating a check that then has to be kept in sync.
pub fn augment_exec_env(env: Vec<(String, String)>, container_id: &str) -> Vec<(String, String)> {
    let container_root =
        crate::crun_container_pid(container_id).map(|pid| format!("/proc/{pid}/root"));
    augment_exec_env_in(env, container_root.as_deref().map(std::path::Path::new))
}

/// Testable core of [`augment_exec_env`]. `container_root` is the agent's view
/// of the container's filesystem (`/proc/<pid>/root`), or `None` when the
/// container's PID could not be resolved.
fn augment_exec_env_in(
    mut env: Vec<(String, String)>,
    container_root: Option<&std::path::Path>,
) -> Vec<(String, String)> {
    // Fail closed. An unconfirmed bundle leaves the workload on whatever driver
    // its image ships — the behavior from before the bundle existed, and the
    // silent no-op every other gate in this module degrades to.
    let Some(root) = container_root else {
        return env;
    };
    // `CONTAINER_BUNDLE_DIR` is absolute, which `Path::join` would treat as a
    // replacement rather than a descent; strip the root so it stays relative to
    // the container's view.
    if !root
        .join(CONTAINER_BUNDLE_DIR.trim_start_matches('/'))
        .join(ICD_JSON)
        .is_file()
    {
        return env;
    }
    if !env
        .iter()
        .any(|(k, v)| (k == "VK_DRIVER_FILES" || k == "VK_ICD_FILENAMES") && !v.is_empty())
    {
        env.push((
            "VK_DRIVER_FILES".to_string(),
            format!("{}/{}", CONTAINER_BUNDLE_DIR, ICD_JSON),
        ));
    }
    // Same rule as the inject path, judged against the container as it is
    // now rather than the image it was created from: once the workload has
    // installed a loader of its own, execs stop pointing at ours.
    let mounted_bundle = root.join(CONTAINER_BUNDLE_DIR.trim_start_matches('/'));
    if !image_has_vulkan_loader(root) && bundle_has_loader(&mounted_bundle) {
        let loader_dir = container_loader_dir();
        match env.iter_mut().find(|(k, _)| k == "LD_LIBRARY_PATH") {
            Some((_, v)) => {
                if !v.split(':').any(|p| p == loader_dir) {
                    *v = format!("{v}:{loader_dir}");
                }
            }
            None => env.push(("LD_LIBRARY_PATH".to_string(), loader_dir)),
        }
    }
    env
}

/// Whether `name` is set (to anything non-empty) in the container env.
fn env_set(env: &[String], name: &str) -> bool {
    let prefix = format!("{}=", name);
    env.iter()
        .any(|e| e.strip_prefix(&prefix).is_some_and(|v| !v.is_empty()))
}

/// A musl-libc image can't load the bundled glibc driver. Musl distros ship
/// their dynamic loader as /lib/ld-musl-<arch>.so.1.
fn is_musl_image(rootfs: &std::path::Path) -> bool {
    std::fs::read_dir(rootfs.join("lib"))
        .map(|entries| {
            entries
                .flatten()
                .any(|e| e.file_name().to_string_lossy().starts_with("ld-musl-"))
        })
        .unwrap_or(false)
}

/// Does the image ship its own Vulkan loader?
///
/// The bundle carries one for images that have none, but putting it on the
/// library path is only safe when nothing else would be shadowed by it.
fn image_has_vulkan_loader(rootfs: &std::path::Path) -> bool {
    [
        "usr/lib",
        "usr/lib64",
        "lib",
        "usr/lib/x86_64-linux-gnu",
        "usr/lib/aarch64-linux-gnu",
    ]
    .iter()
    .any(|dir| rootfs.join(dir).join(LOADER).exists())
}

/// Append `dir` to the spec's `LD_LIBRARY_PATH`, preserving an image-provided
/// value; creates the variable if absent, skips if already present.
fn append_ld_library_path(env: &mut Vec<String>, dir: &str) {
    for e in env.iter_mut() {
        if let Some(v) = e.strip_prefix("LD_LIBRARY_PATH=") {
            if v.split(':').any(|p| p == dir) {
                return;
            }
            *e = format!("LD_LIBRARY_PATH={v}:{dir}");
            return;
        }
    }
    env.push(format!("LD_LIBRARY_PATH={dir}"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci::{OciSpec, ProcessIdentity};

    fn spec() -> OciSpec {
        OciSpec::new(
            &["true".to_string()],
            &[],
            "/",
            false,
            &ProcessIdentity::root(),
            false,
        )
    }

    fn bundle_mounted(s: &OciSpec) -> bool {
        s.mounts
            .iter()
            .any(|m| m.destination == CONTAINER_BUNDLE_DIR)
    }

    fn bundle_fixture() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(DRIVER), b"").unwrap();
        std::fs::write(dir.path().join(ICD_JSON), b"{}").unwrap();
        std::fs::create_dir(dir.path().join(LOADER_SUBDIR)).unwrap();
        std::fs::write(dir.path().join(LOADER_SUBDIR).join(LOADER), b"").unwrap();
        dir
    }
    fn ld_library_path(s: &OciSpec) -> Option<String> {
        s.process
            .env
            .iter()
            .find_map(|e| e.strip_prefix("LD_LIBRARY_PATH=").map(str::to_string))
    }

    fn glibc_rootfs() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("lib")).unwrap();
        dir
    }

    #[test]
    fn injects_when_gpu_and_bundle_present() {
        let bundle = bundle_fixture();
        let rootfs = glibc_rootfs();
        let mut s = spec();
        inject_into_container_if(&mut s, rootfs.path(), true, bundle.path());
        assert!(s
            .mounts
            .iter()
            .any(|m| m.destination == CONTAINER_BUNDLE_DIR));
        assert!(s
            .process
            .env
            .iter()
            .any(|e| e == "VK_DRIVER_FILES=/opt/smolvm-vulkan/virtio_icd.json"));
        // An image without a loader gets the loader's directory and nothing
        // else: the bundle root on the path shadowed the image's own libraries.
        assert_eq!(
            ld_library_path(&s).as_deref(),
            Some("/opt/smolvm-vulkan/loader")
        );
    }
    #[test]
    fn image_with_its_own_loader_gets_no_library_path() {
        let bundle = bundle_fixture();
        let rootfs = glibc_rootfs();
        std::fs::create_dir_all(rootfs.path().join("usr/lib")).unwrap();
        std::fs::write(rootfs.path().join("usr/lib").join(LOADER), b"").unwrap();
        let mut s = spec();
        inject_into_container_if(&mut s, rootfs.path(), true, bundle.path());
        assert!(bundle_mounted(&s));
        assert_eq!(ld_library_path(&s), None);
    }
    #[test]
    fn flat_bundle_without_loader_dir_is_never_put_on_the_path() {
        let bundle = tempfile::tempdir().unwrap();
        std::fs::write(bundle.path().join(DRIVER), b"").unwrap();
        std::fs::write(bundle.path().join(ICD_JSON), b"{}").unwrap();
        let rootfs = glibc_rootfs();
        let mut s = spec();
        inject_into_container_if(&mut s, rootfs.path(), true, bundle.path());
        assert!(bundle_mounted(&s));
        assert_eq!(ld_library_path(&s), None);
    }

    #[test]
    fn noop_without_gpu() {
        let bundle = bundle_fixture();
        let rootfs = glibc_rootfs();
        let mut s = spec();
        inject_into_container_if(&mut s, rootfs.path(), false, bundle.path());
        assert!(!bundle_mounted(&s));
        assert!(!s
            .process
            .env
            .iter()
            .any(|e| e.starts_with("VK_DRIVER_FILES=")));
    }

    #[test]
    fn noop_without_bundle() {
        let empty = tempfile::tempdir().unwrap();
        let rootfs = glibc_rootfs();
        let mut s = spec();
        inject_into_container_if(&mut s, rootfs.path(), true, empty.path());
        assert!(!bundle_mounted(&s));
    }

    #[test]
    fn user_driver_choice_wins() {
        let bundle = bundle_fixture();
        let rootfs = glibc_rootfs();
        let mut s = spec();
        s.add_env("VK_ICD_FILENAMES", "/usr/share/vulkan/icd.d/mine.json");
        inject_into_container_if(&mut s, rootfs.path(), true, bundle.path());
        assert!(!s
            .process
            .env
            .iter()
            .any(|e| e.starts_with("VK_DRIVER_FILES=")));
        // The bundle is still mounted — only the loader pin defers to the user.
        assert!(s
            .mounts
            .iter()
            .any(|m| m.destination == CONTAINER_BUNDLE_DIR));
    }

    #[test]
    fn opt_out_env_skips_entirely() {
        let bundle = bundle_fixture();
        let rootfs = glibc_rootfs();
        let mut s = spec();
        s.add_env(OPT_OUT_ENV, "1");
        inject_into_container_if(&mut s, rootfs.path(), true, bundle.path());
        assert!(!bundle_mounted(&s));
    }

    #[test]
    fn musl_image_skips() {
        let bundle = bundle_fixture();
        let rootfs = tempfile::tempdir().unwrap();
        std::fs::create_dir(rootfs.path().join("lib")).unwrap();
        std::fs::write(rootfs.path().join("lib/ld-musl-aarch64.so.1"), b"").unwrap();
        let mut s = spec();
        inject_into_container_if(&mut s, rootfs.path(), true, bundle.path());
        assert!(!bundle_mounted(&s));
    }

    /// A container root as the agent sees it (`/proc/<pid>/root`) with the
    /// bundle bind-mounted at `CONTAINER_BUNDLE_DIR`.
    fn container_root_with_bundle() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let mounted = dir
            .path()
            .join(CONTAINER_BUNDLE_DIR.trim_start_matches('/'));
        std::fs::create_dir_all(&mounted).unwrap();
        std::fs::write(mounted.join(ICD_JSON), b"{}").unwrap();
        std::fs::write(mounted.join(DRIVER), b"").unwrap();
        std::fs::create_dir(mounted.join(LOADER_SUBDIR)).unwrap();
        std::fs::write(mounted.join(LOADER_SUBDIR).join(LOADER), b"").unwrap();
        dir
    }

    fn value<'a>(env: &'a [(String, String)], key: &str) -> Option<&'a str> {
        env.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    #[test]
    fn exec_env_pins_driver_when_the_container_has_the_bundle() {
        let root = container_root_with_bundle();
        let env = augment_exec_env_in(vec![], Some(root.path()));
        assert_eq!(
            value(&env, "VK_DRIVER_FILES"),
            Some("/opt/smolvm-vulkan/virtio_icd.json")
        );
        assert_eq!(
            value(&env, "LD_LIBRARY_PATH"),
            Some("/opt/smolvm-vulkan/loader")
        );
    }
    /// A workload that installed its own loader after creation must not be
    /// pointed at ours any more; the exec path judges the container as it is.
    #[test]
    fn exec_env_drops_the_loader_path_once_the_container_has_a_loader() {
        let root = container_root_with_bundle();
        std::fs::create_dir_all(root.path().join("usr/lib")).unwrap();
        std::fs::write(root.path().join("usr/lib").join(LOADER), b"").unwrap();
        let env = augment_exec_env_in(vec![], Some(root.path()));
        assert_eq!(
            value(&env, "VK_DRIVER_FILES"),
            Some("/opt/smolvm-vulkan/virtio_icd.json")
        );
        assert_eq!(value(&env, "LD_LIBRARY_PATH"), None);
    }
    #[test]
    fn exec_env_never_exposes_the_bundle_root() {
        let root = container_root_with_bundle();
        let env = augment_exec_env_in(
            vec![("LD_LIBRARY_PATH".to_string(), "/app/lib".to_string())],
            Some(root.path()),
        );
        assert_eq!(
            value(&env, "LD_LIBRARY_PATH"),
            Some("/app/lib:/opt/smolvm-vulkan/loader")
        );
    }

    /// #1050: a musl image skips the mount on the inject path, so the exec path
    /// must not hand it env pointing at the bundle that was never mounted.
    #[test]
    fn exec_env_untouched_when_the_container_lacks_the_bundle() {
        let root = tempfile::tempdir().unwrap();
        let env = augment_exec_env_in(vec![], Some(root.path()));
        assert!(env.is_empty(), "expected no Vulkan env, got {env:?}");
    }

    /// The mount point can exist without the bundle behind it; only a readable
    /// ICD proves the container actually received a driver.
    #[test]
    fn exec_env_untouched_when_the_mount_point_is_empty() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(
            root.path()
                .join(CONTAINER_BUNDLE_DIR.trim_start_matches('/')),
        )
        .unwrap();
        let env = augment_exec_env_in(vec![], Some(root.path()));
        assert!(env.is_empty(), "expected no Vulkan env, got {env:?}");
    }

    #[test]
    fn exec_env_untouched_when_the_container_pid_is_unresolvable() {
        let env = augment_exec_env_in(vec![], None);
        assert!(env.is_empty(), "expected no Vulkan env, got {env:?}");
    }

    #[test]
    fn exec_env_defers_to_a_user_driver_choice() {
        let root = container_root_with_bundle();
        let chosen = vec![(
            "VK_ICD_FILENAMES".to_string(),
            "/usr/share/vulkan/icd.d/mine.json".to_string(),
        )];
        let env = augment_exec_env_in(chosen, Some(root.path()));
        assert!(value(&env, "VK_DRIVER_FILES").is_none());
        // The loader path is still added — only the driver pin defers.
        assert_eq!(
            value(&env, "LD_LIBRARY_PATH"),
            Some("/opt/smolvm-vulkan/loader")
        );
    }

    #[test]
    fn exec_env_appends_to_an_existing_ld_library_path_once() {
        let root = container_root_with_bundle();
        let env = augment_exec_env_in(
            vec![("LD_LIBRARY_PATH".to_string(), "/usr/lib".to_string())],
            Some(root.path()),
        );
        assert_eq!(
            value(&env, "LD_LIBRARY_PATH"),
            Some("/usr/lib:/opt/smolvm-vulkan/loader")
        );
        let twice = augment_exec_env_in(env, Some(root.path()));
        assert_eq!(
            value(&twice, "LD_LIBRARY_PATH"),
            Some("/usr/lib:/opt/smolvm-vulkan/loader")
        );
    }

    #[test]
    fn ld_library_path_appends_and_dedupes() {
        let mut env = vec!["LD_LIBRARY_PATH=/usr/lib".to_string()];
        append_ld_library_path(&mut env, CONTAINER_BUNDLE_DIR);
        assert_eq!(
            env[0],
            format!("LD_LIBRARY_PATH=/usr/lib:{CONTAINER_BUNDLE_DIR}")
        );
        append_ld_library_path(&mut env, CONTAINER_BUNDLE_DIR);
        assert_eq!(env.len(), 1);
        assert_eq!(env[0].matches(CONTAINER_BUNDLE_DIR).count(), 1);
    }
}
