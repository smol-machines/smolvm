//! Shared container-overlay transfer over a short-lived helper VM.
//!
//! Capturing a stopped image-machine's container overlay is the common atom
//! behind three features: packaging a machine into a `.smolmachine` (`pack
//! create --from-vm`), the cloud snapshot endpoint, and — in reverse — seeding
//! an overlay from a snapshot tar (restore/fork). All of them boot a helper VM
//! with the machine's `storage.raw` attached as `/dev/vdc` and `tar` the overlay
//! `upper` dir; this module is the single place that knows how.

use std::path::Path;

use crate::agent::{vm_data_dir, AgentClient, AgentManager, LaunchFeatures, VmResources};
use crate::data::disk::DiskFormat;
use crate::error::{Error, Result};

/// A captured container overlay.
pub struct OverlayTar {
    /// The overlay `upper` dir as a tar archive. Always a valid archive — an
    /// empty-dir tar when the machine has no overlay yet — so callers can treat
    /// the bytes uniformly.
    pub tar: Vec<u8>,
    /// Whether the overlay actually held any files. Callers that package the
    /// tar as an image layer (pack) skip empty overlays; the snapshot endpoint
    /// keeps the (valid, empty) archive regardless.
    pub had_content: bool,
}

/// Tar the container overlay `upper` dir for `vm_name` inside a helper VM that
/// already has the source storage mounted at `mount_point`. Always produces a
/// valid archive (an empty dir when there's no overlay) and reports whether the
/// overlay held content.
pub fn tar_overlay_upper(
    client: &mut AgentClient,
    mount_point: &str,
    vm_name: &str,
) -> Result<OverlayTar> {
    let upper = format!("{}/overlays/persistent-{}/upper", mount_point, vm_name);
    // Always emit a valid tar: the overlay's contents when present, else an
    // empty dir. Echo a marker so the host can tell the two apart. The `tar cf
    // -C <upper> .` invocation is byte-identical to the legacy pack path, so an
    // exported layer's digest is unchanged.
    let script = format!(
        "mkdir -p /tmp/empty && \
         if [ -d '{u}' ] && [ -n \"$(ls -A '{u}' 2>/dev/null)\" ]; then \
             tar cf /tmp/overlay.tar -C '{u}' . && echo HAS_CONTENT; \
         else \
             tar cf /tmp/overlay.tar -C /tmp/empty . && echo EMPTY; \
         fi",
        u = upper
    );
    let (code, stdout, stderr) = client.vm_exec(
        vec!["sh".into(), "-c".into(), script],
        vec![],
        None,
        None,
        None,
    )?;
    if code != 0 {
        return Err(Error::agent(
            "tar container overlay",
            format!(
                "tar failed (exit {}): {}",
                code,
                String::from_utf8_lossy(&stderr)
            ),
        ));
    }
    let had_content = String::from_utf8_lossy(&stdout).contains("HAS_CONTENT");
    let tar = client.read_file("/tmp/overlay.tar")?;
    Ok(OverlayTar { tar, had_content })
}

/// Boot a short-lived helper VM with `storage_path` attached as `/dev/vdc`,
/// mount it, and hand a connected client to `f`. The helper VM is always
/// stopped and its data dir removed, even if `f` errors.
fn with_overlay_helper_vm<T>(
    storage_path: &Path,
    storage_fmt: DiskFormat,
    read_only: bool,
    f: impl FnOnce(&mut AgentClient) -> Result<T>,
) -> Result<T> {
    // Unique helper-VM name (pid + nanos); first char alphanumeric, matching the
    // VM-name constraint the pack-from-vm path documents.
    let helper_name = format!(
        "overlay-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let helper_data = vm_data_dir(&helper_name);

    let manager = AgentManager::for_vm(&helper_name)?;
    let features = LaunchFeatures {
        extra_disks: vec![(storage_path.to_path_buf(), read_only, storage_fmt)],
        ..Default::default()
    };
    // Lean fixed sizing: mounting a disk and (un)taring one directory needs no
    // network and little memory. This intentionally under-provisions relative to
    // a workload VM.
    manager.start_with_full_config(
        Vec::new(),
        Vec::new(),
        VmResources {
            cpus: 2,
            memory_mib: 2048,
            network: false,
            network_backend: None,
            gpu: false,
            gpu_vram_mib: None,
            cuda: false,
            rosetta: false,
            storage_gib: None,
            overlay_gib: None,
            allowed_cidrs: None,
            dns: None,
        },
        features,
    )?;

    let mount_flag = if read_only { "-o ro " } else { "" };
    let result: Result<T> = (|| {
        let mut client = manager.connect()?;
        let (code, _, stderr) = client.vm_exec(
            vec![
                "sh".into(),
                "-c".into(),
                format!("mkdir -p /mnt/src && mount {}/dev/vdc /mnt/src", mount_flag),
            ],
            vec![],
            None,
            None,
            None,
        )?;
        if code != 0 {
            return Err(Error::agent(
                "mount source storage in helper VM",
                format!(
                    "mount failed (exit {}): {}",
                    code,
                    String::from_utf8_lossy(&stderr)
                ),
            ));
        }
        f(&mut client)
    })();

    if let Err(e) = manager.stop() {
        tracing::warn!(helper = %helper_name, error = %e, "failed to stop overlay helper VM");
    }
    let _ = std::fs::remove_dir_all(&helper_data);
    result
}

/// Boot a read-only helper VM and capture the machine's container overlay as a
/// tar. Used by both `pack create --from-vm` and the cloud snapshot endpoint.
pub fn capture_overlay_tar(
    vm_name: &str,
    storage_path: &Path,
    storage_fmt: DiskFormat,
) -> Result<OverlayTar> {
    with_overlay_helper_vm(storage_path, storage_fmt, true, |client| {
        tar_overlay_upper(client, "/mnt/src", vm_name)
    })
}

/// Boot a read-write helper VM and seed the machine's container overlay from a
/// snapshot tar, replacing any prior overlay state. Syncs and unmounts inside
/// the guest so the write reaches the host disk image before teardown. On the
/// machine's next start, the agent's overlay setup finds the existing `upper`
/// and remounts it (preserving the restored state) instead of creating a blank
/// one. The inverse of [`capture_overlay_tar`].
pub fn seed_overlay_tar(
    vm_name: &str,
    storage_path: &Path,
    storage_fmt: DiskFormat,
    tar: &[u8],
) -> Result<()> {
    let vm_name = vm_name.to_string();
    with_overlay_helper_vm(storage_path, storage_fmt, false, move |client| {
        // Push the snapshot tar into the helper VM (auto-chunked over vsock).
        client.write_file("/tmp/restore.tar", tar, None)?;

        // Replace the persistent overlay's upper dir with the snapshot contents.
        // Removing the whole overlay root first guarantees the agent takes the
        // "existing upper → remount preserving it" path (not a stale merged-mount
        // reuse) on the next start; `work`/`merged` are recreated at mount time.
        // sync + umount so the write lands on the host disk before teardown.
        let overlay_root = format!("/mnt/src/overlays/persistent-{}", vm_name);
        let script = format!(
            "set -e; \
             rm -rf '{root}'; \
             mkdir -p '{root}/upper'; \
             tar xf /tmp/restore.tar -C '{root}/upper'; \
             sync; umount /mnt/src",
            root = overlay_root
        );
        let (code, _, stderr) = client.vm_exec(
            vec!["sh".into(), "-c".into(), script],
            vec![],
            None,
            None,
            None,
        )?;
        if code != 0 {
            return Err(Error::agent(
                "seed container overlay",
                format!(
                    "apply overlay failed (exit {}): {}",
                    code,
                    String::from_utf8_lossy(&stderr)
                ),
            ));
        }
        Ok(())
    })
}
