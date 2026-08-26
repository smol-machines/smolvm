//! Guest-side CUDA forwarding wiring for the workload container.
//!
//! When a VM is launched with `--cuda`, the launcher sets `SMOLVM_CUDA_ZEROCOPY`
//! in the agent's (PID 1) environment. The workload container gets its env from
//! the image plus the request — not from the agent's own env — so the zero-copy
//! opt-in has to be forwarded into the container spec explicitly, the same way
//! [`crate::ssh_agent`] forwards `SSH_AUTH_SOCK`.
//!
//! With the flag set, the guest CUDA shim (`libcudart.so`) backs
//! `cudaHostAlloc`/`cudaMallocHost` with page-locked guest RAM whose
//! guest-physical frames it reads from `/proc/self/pagemap`, so a memcpy ships
//! only a guest-physical descriptor and the host DMAs straight from guest RAM.
//! It degrades to byte-shipping wherever that path is unavailable (no
//! `CAP_SYS_ADMIN`, older libkrun), so forwarding it is always safe.

/// The env var the launcher sets on the agent, and that the guest shim reads.
const ZEROCOPY_ENV: &str = smolvm_protocol::guest_env::CUDA_ZEROCOPY;
const FORK_POOL_SIZE_ENV: &str = smolvm_protocol::guest_env::CUDA_FORK_POOL_SIZE;
const EXPANDABLE_SEGMENTS_ENV: &str = smolvm_protocol::guest_env::CUDA_EXPANDABLE_SEGMENTS;
const PYTORCH_ALLOC_CONF: &str = "PYTORCH_ALLOC_CONF";
const PYTORCH_CUDA_ALLOC_CONF: &str = "PYTORCH_CUDA_ALLOC_CONF";
const EXPANDABLE_SEGMENTS: &str = "expandable_segments:True";
const NCCL_SHM_DISABLE: &str = "NCCL_SHM_DISABLE";

/// Whether CUDA guest-RAM zero-copy was requested for this VM.
pub fn zerocopy_enabled() -> bool {
    std::env::var(ZEROCOPY_ENV).as_deref() == Ok("1")
}

fn fork_pool_enabled() -> bool {
    std::env::var(FORK_POOL_SIZE_ENV)
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .is_some_and(|size| size > 0)
}

fn disabled(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "0" | "false" | "off" | "no"
    )
}

fn has_expandable_segments(value: &str) -> bool {
    value.split(',').any(|option| {
        option
            .split_once(':')
            .is_some_and(|(key, _)| key.trim().eq_ignore_ascii_case("expandable_segments"))
    })
}

fn append_expandable_segments(value: &mut String) {
    if !value.trim().is_empty() {
        value.push(',');
    }
    value.push_str(EXPANDABLE_SEGMENTS);
}

fn inject_expandable_segments_specs(env: &mut Vec<String>, enabled: bool) {
    if !enabled
        || env.iter().any(|entry| {
            entry
                .split_once('=')
                .is_some_and(|(key, value)| key == EXPANDABLE_SEGMENTS_ENV && disabled(value))
        })
    {
        return;
    }
    let allocator_indexes: Vec<usize> = env
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| {
            let (key, _) = entry.split_once('=')?;
            matches!(key, PYTORCH_ALLOC_CONF | PYTORCH_CUDA_ALLOC_CONF).then_some(index)
        })
        .collect();
    if allocator_indexes.iter().any(|&index| {
        env[index]
            .split_once('=')
            .is_some_and(|(_, value)| has_expandable_segments(value))
    }) {
        return;
    }
    if let Some(&index) = allocator_indexes.first() {
        let (key, value) = env[index].split_once('=').unwrap();
        let mut value = value.to_string();
        append_expandable_segments(&mut value);
        env[index] = format!("{key}={value}");
    } else {
        env.push(format!("{PYTORCH_CUDA_ALLOC_CONF}={EXPANDABLE_SEGMENTS}"));
    }
}

fn inject_expandable_segments_pairs(env: &mut Vec<(String, String)>, enabled: bool) {
    if !enabled
        || env
            .iter()
            .any(|(key, value)| key == EXPANDABLE_SEGMENTS_ENV && disabled(value))
    {
        return;
    }
    if env.iter().any(|(key, value)| {
        matches!(key.as_str(), PYTORCH_ALLOC_CONF | PYTORCH_CUDA_ALLOC_CONF)
            && has_expandable_segments(value)
    }) {
        return;
    }
    if let Some((_, value)) = env
        .iter_mut()
        .find(|(key, _)| matches!(key.as_str(), PYTORCH_ALLOC_CONF | PYTORCH_CUDA_ALLOC_CONF))
    {
        append_expandable_segments(value);
    } else {
        env.push((
            PYTORCH_CUDA_ALLOC_CONF.to_string(),
            EXPANDABLE_SEGMENTS.to_string(),
        ));
    }
}

/// NCCL's host-SHM transport registers an arbitrary `/dev/shm` mapping with
/// CUDA. That mapping exists only inside the guest, so it cannot be registered
/// in the host process that owns the remoted CUDA context. Keep NCCL's faster
/// P2P/IPC transport enabled and make it fall back to NET when P2P is
/// unavailable. An explicit workload setting remains authoritative.
fn inject_nccl_shm_disable_specs(env: &mut Vec<String>) {
    if !env.iter().any(|entry| {
        entry
            .split_once('=')
            .is_some_and(|(key, _)| key == NCCL_SHM_DISABLE)
    }) {
        env.push(format!("{NCCL_SHM_DISABLE}=1"));
    }
}

fn inject_nccl_shm_disable_pairs(env: &mut Vec<(String, String)>) {
    if !env.iter().any(|(key, _)| key == NCCL_SHM_DISABLE) {
        env.push((NCCL_SHM_DISABLE.to_string(), "1".to_string()));
    }
}

/// Where the guest CUDA shims ship inside the VM rootfs (from the agent
/// rootfs). Absent on builds without CUDA shim bundling — every staging step
/// degrades to a no-op so `--cuda` still works in the manual-setup mode.
const GUEST_SHIM_DIR: &str = "/usr/local/lib/smolvm-cuda";
/// Where the shim dir is bind-mounted inside the workload container, and put
/// on `LD_LIBRARY_PATH` so the loader finds `libcuda.so.1` there.
const CONTAINER_SHIM_DIR: &str = "/opt/smolvm-cuda";
/// The runtime shim file inside [`GUEST_SHIM_DIR`] (one cdylib exports the
/// whole cudart/cuBLAS/cuBLASLt/cuDNN surface; it is staged under each soname).
const RUNTIME_SHIM: &str = "libcudart-shim.so";
/// The driver shim (`libcuda.so.1`) inside [`GUEST_SHIM_DIR`].
const DRIVER_SHIM: &str = "libcuda.so.1";

/// The pip-bundled NVIDIA sonames PyTorch's `libtorch_cuda.so` resolves via
/// DT_RPATH. RPATH is searched *before* `LD_LIBRARY_PATH`, so the only way to
/// interpose is to place the shim at these exact paths (a read-only bind mount
/// over each file). CUDA 12 and 11 wheel layouts.
const RPATH_PINNED_SONAMES: &[&str] = &[
    "libcudart.so.13",
    "libcublas.so.13",
    "libcublasLt.so.13",
    "libcudart.so.12",
    "libcublas.so.12",
    "libcublasLt.so.12",
    "libcudnn.so.9",
    "libcudart.so.11.0",
    "libcublas.so.11",
    "libcublasLt.so.11",
    "libcudnn.so.8",
];

/// Forward the CUDA opt-in into the workload container spec and, when the
/// guest shims are bundled, stage them so an unmodified PyTorch works with no
/// user setup: the shim dir rides `LD_LIBRARY_PATH` (covers `libcuda.so.1`,
/// which nothing RPATH-pins) and the runtime shim is bind-mounted over each
/// pip-bundled NVIDIA library found in the image rootfs (RPATH-pinned, so env
/// vars can't reach them). Used on the fresh-container path (`crun run`/
/// `create`). No-op unless CUDA was requested.
pub fn inject_into_container(spec: &mut crate::oci::OciSpec, rootfs: &std::path::Path) {
    inject_into_container_if(spec, rootfs, zerocopy_enabled(), fork_pool_enabled());
}

/// Testable core of [`inject_into_container`].
fn inject_into_container_if(
    spec: &mut crate::oci::OciSpec,
    rootfs: &std::path::Path,
    enabled: bool,
    fork_pool: bool,
) {
    if !enabled {
        return;
    }
    spec.add_env(ZEROCOPY_ENV, "1");
    inject_nccl_shm_disable_specs(&mut spec.process.env);
    inject_expandable_segments_specs(&mut spec.process.env, fork_pool);
    stage_shims(spec, rootfs, std::path::Path::new(GUEST_SHIM_DIR));
}

/// Bind-mount the bundled shims into the container. Split from the gate so
/// tests can point `shim_dir` at a fixture.
fn stage_shims(
    spec: &mut crate::oci::OciSpec,
    rootfs: &std::path::Path,
    shim_dir: &std::path::Path,
) {
    let runtime = shim_dir.join(RUNTIME_SHIM);
    let driver = shim_dir.join(DRIVER_SHIM);
    if !runtime.is_file() || !driver.is_file() {
        return; // shims not bundled — manual staging still works
    }

    // Driver shim: the whole shim dir at a stable path + LD_LIBRARY_PATH.
    // `libcuda.so.1` is resolved through the normal loader search (no RPATH in
    // the way), and this also lets users link the runtime shim directly.
    spec.add_bind_mount(&shim_dir.to_string_lossy(), CONTAINER_SHIM_DIR, true);
    append_ld_library_path(&mut spec.process.env, CONTAINER_SHIM_DIR);

    // Runtime shim over each RPATH-pinned pip-bundled NVIDIA library.
    let runtime_src = runtime.to_string_lossy();
    for hit in find_rpath_pinned_libs(rootfs) {
        let dest = format!(
            "/{}",
            hit.strip_prefix(rootfs).unwrap_or(&hit).to_string_lossy()
        );
        spec.add_bind_mount(&runtime_src, &dest, true);
    }
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

/// Find pip-bundled NVIDIA libraries in the image rootfs: files named like the
/// RPATH-pinned sonames under a `site-packages`/`dist-packages` → `nvidia`
/// wheel layout. Bounded walk: skips pseudo-filesystems and never follows
/// symlinks (wheel layouts don't use them and cycles would hang the boot).
fn find_rpath_pinned_libs(rootfs: &std::path::Path) -> Vec<std::path::PathBuf> {
    const SKIP_TOP: &[&str] = &["proc", "sys", "dev", "run", "tmp", "boot"];
    const MAX_DEPTH: usize = 16;
    let mut hits = Vec::new();
    let mut stack: Vec<(std::path::PathBuf, usize)> = vec![(rootfs.to_path_buf(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        if depth >= MAX_DEPTH {
            continue;
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let ft = match entry.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if ft.is_dir() && !ft.is_symlink() {
                if depth == 0 && SKIP_TOP.contains(&name.as_ref()) {
                    continue;
                }
                stack.push((entry.path(), depth + 1));
            } else if ft.is_file() && RPATH_PINNED_SONAMES.contains(&name.as_ref()) {
                let p = entry.path();
                let s = p.to_string_lossy();
                if s.contains("/nvidia/")
                    && (s.contains("/site-packages/") || s.contains("/dist-packages/"))
                {
                    hits.push(p);
                }
            }
        }
    }
    hits.sort();
    hits
}

/// Append the CUDA opt-in (and the shim dir's loader path) to an explicit exec
/// env when enabled. Used on the `crun exec` path (joining a persistent
/// machine's keep-alive container), where the workload env is passed via
/// `--env` rather than inherited from the container spec, so the spec injection
/// above doesn't reach it. The bind mounts themselves were established when the
/// keep-alive container was created. No-op when disabled or already present.
pub fn augment_exec_env(mut env: Vec<(String, String)>) -> Vec<(String, String)> {
    if !zerocopy_enabled() {
        return env;
    }
    if !env.iter().any(|(k, _)| k == ZEROCOPY_ENV) {
        env.push((ZEROCOPY_ENV.to_string(), "1".to_string()));
    }
    match env.iter_mut().find(|(k, _)| k == "LD_LIBRARY_PATH") {
        Some((_, v)) => {
            if !v.split(':').any(|p| p == CONTAINER_SHIM_DIR) {
                *v = format!("{v}:{CONTAINER_SHIM_DIR}");
            }
        }
        None => env.push((
            "LD_LIBRARY_PATH".to_string(),
            CONTAINER_SHIM_DIR.to_string(),
        )),
    }
    inject_nccl_shm_disable_pairs(&mut env);
    inject_expandable_segments_pairs(&mut env, fork_pool_enabled());
    env
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

    #[test]
    fn injects_when_enabled() {
        let mut s = spec();
        inject_into_container_if(&mut s, std::path::Path::new("/nonexistent"), true, false);
        assert!(s.process.env.iter().any(|e| e == "SMOLVM_CUDA_ZEROCOPY=1"));
        assert!(s.process.env.iter().any(|e| e == "NCCL_SHM_DISABLE=1"));
    }

    #[test]
    fn noop_when_disabled() {
        let mut s = spec();
        inject_into_container_if(&mut s, std::path::Path::new("/nonexistent"), false, false);
        assert!(!s
            .process
            .env
            .iter()
            .any(|e| e.starts_with("SMOLVM_CUDA_ZEROCOPY")));
        assert!(!s
            .process
            .env
            .iter()
            .any(|e| e.starts_with("NCCL_SHM_DISABLE")));
    }

    #[test]
    fn preserves_explicit_nccl_shm_choice() {
        let mut specs = vec!["NCCL_SHM_DISABLE=0".to_string()];
        inject_nccl_shm_disable_specs(&mut specs);
        assert_eq!(specs, ["NCCL_SHM_DISABLE=0"]);

        let mut pairs = vec![("NCCL_SHM_DISABLE".to_string(), "0".to_string())];
        inject_nccl_shm_disable_pairs(&mut pairs);
        assert_eq!(pairs, [("NCCL_SHM_DISABLE".to_string(), "0".to_string())]);
    }

    #[test]
    fn augment_exec_env_is_idempotent() {
        let base = vec![("SMOLVM_CUDA_ZEROCOPY".to_string(), "1".to_string())];
        // Gate off in tests (env var unset) → unchanged.
        assert_eq!(augment_exec_env(base.clone()), base);
    }

    #[test]
    fn ld_library_path_append_preserves_existing() {
        let mut env = vec!["LD_LIBRARY_PATH=/usr/local/nvidia/lib".to_string()];
        append_ld_library_path(&mut env, CONTAINER_SHIM_DIR);
        assert_eq!(
            env[0],
            format!("LD_LIBRARY_PATH=/usr/local/nvidia/lib:{CONTAINER_SHIM_DIR}")
        );
        // Idempotent.
        append_ld_library_path(&mut env, CONTAINER_SHIM_DIR);
        assert_eq!(env.len(), 1);
        assert_eq!(env[0].matches(CONTAINER_SHIM_DIR).count(), 1);
    }

    #[test]
    fn ld_library_path_created_when_absent() {
        let mut env = vec!["PATH=/usr/bin".to_string()];
        append_ld_library_path(&mut env, CONTAINER_SHIM_DIR);
        assert!(env.contains(&format!("LD_LIBRARY_PATH={CONTAINER_SHIM_DIR}")));
    }

    #[test]
    fn fork_pool_injects_expandable_segments() {
        let mut s = spec();
        inject_into_container_if(&mut s, std::path::Path::new("/nonexistent"), true, true);
        assert!(s
            .process
            .env
            .iter()
            .any(|entry| entry == "PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True"));
    }

    #[test]
    fn fork_pool_appends_to_existing_allocator_config() {
        let mut s = spec();
        s.process
            .env
            .push("PYTORCH_ALLOC_CONF=max_split_size_mb:128".to_string());
        inject_into_container_if(&mut s, std::path::Path::new("/nonexistent"), true, true);
        assert!(s.process.env.iter().any(|entry| {
            entry == "PYTORCH_ALLOC_CONF=max_split_size_mb:128,expandable_segments:True"
        }));
    }

    #[test]
    fn fork_pool_preserves_explicit_allocator_choice() {
        let mut s = spec();
        s.process
            .env
            .push("PYTORCH_CUDA_ALLOC_CONF=expandable_segments:False".to_string());
        inject_into_container_if(&mut s, std::path::Path::new("/nonexistent"), true, true);
        assert!(s
            .process
            .env
            .iter()
            .any(|entry| entry == "PYTORCH_CUDA_ALLOC_CONF=expandable_segments:False"));
    }

    #[test]
    fn workload_can_disable_automatic_expandable_segments() {
        let mut s = spec();
        s.process
            .env
            .push("SMOLVM_CUDA_EXPANDABLE_SEGMENTS=off".to_string());
        inject_into_container_if(&mut s, std::path::Path::new("/nonexistent"), true, true);
        assert!(!s.process.env.iter().any(|entry| {
            entry.starts_with("PYTORCH_CUDA_ALLOC_CONF=")
                || entry.starts_with("PYTORCH_ALLOC_CONF=")
        }));
    }

    #[test]
    fn exec_env_injects_expandable_segments() {
        let mut env = vec![(
            PYTORCH_CUDA_ALLOC_CONF.to_string(),
            "max_split_size_mb:128".to_string(),
        )];
        inject_expandable_segments_pairs(&mut env, true);
        assert!(env.iter().any(|(key, value)| {
            key == PYTORCH_CUDA_ALLOC_CONF
                && value == "max_split_size_mb:128,expandable_segments:True"
        }));
    }

    #[test]
    fn exec_env_respects_expandable_segments_opt_out() {
        let mut env = vec![(EXPANDABLE_SEGMENTS_ENV.to_string(), "false".to_string())];
        inject_expandable_segments_pairs(&mut env, true);
        assert!(!env.iter().any(|(key, _)| {
            matches!(key.as_str(), PYTORCH_ALLOC_CONF | PYTORCH_CUDA_ALLOC_CONF)
        }));
    }

    #[test]
    fn finds_and_overmounts_wheel_libs() {
        let tmp = std::env::temp_dir().join(format!("cuda-stage-test-{}", std::process::id()));
        let rootfs = tmp.join("rootfs");
        let wheel = rootfs.join("usr/lib/python3.11/site-packages/nvidia/cublas/lib");
        std::fs::create_dir_all(&wheel).unwrap();
        std::fs::write(wheel.join("libcublas.so.12"), b"real").unwrap();
        std::fs::write(wheel.join("libnvblas.so.12"), b"other").unwrap(); // not pinned
                                                                          // A same-named file outside a wheel layout must NOT match.
        let stray = rootfs.join("opt/other");
        std::fs::create_dir_all(&stray).unwrap();
        std::fs::write(stray.join("libcublas.so.12"), b"stray").unwrap();

        let hits = find_rpath_pinned_libs(&rootfs);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].ends_with("nvidia/cublas/lib/libcublas.so.12"));

        // With a shim fixture present, staging adds the dir mount + overmount.
        let shim_dir = tmp.join("shims");
        std::fs::create_dir_all(&shim_dir).unwrap();
        std::fs::write(shim_dir.join(RUNTIME_SHIM), b"shim").unwrap();
        std::fs::write(shim_dir.join(DRIVER_SHIM), b"shim").unwrap();
        let mut s = spec();
        stage_shims(&mut s, &rootfs, &shim_dir);
        assert!(s.mounts.iter().any(|m| m.destination == CONTAINER_SHIM_DIR));
        assert!(s.mounts.iter().any(|m| m
            .destination
            .ends_with("nvidia/cublas/lib/libcublas.so.12")
            && m.source.ends_with(RUNTIME_SHIM)));
        assert!(s
            .process
            .env
            .iter()
            .any(|e| e.starts_with("LD_LIBRARY_PATH=") && e.contains(CONTAINER_SHIM_DIR)));

        std::fs::remove_dir_all(&tmp).ok();
    }
}
