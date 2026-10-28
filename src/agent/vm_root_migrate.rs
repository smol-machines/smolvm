//! One-time move of machine state out of the user cache.
//!
//! Machines used to live under `<cache_dir>/smolvm/vms`. The cache is
//! expendable to the OS and to cleanup tools, so a purge deleted every
//! machine's disks while the database still listed them (#373). The machine
//! root now lives in the data directory, and this module carries the old
//! layout over on first use.
//!
//! Two things make this more than a rename. A clone's disk names the fork
//! base's disk by absolute path in its qcow2 header, so moved machines need
//! those paths rewritten or every clone family dangles. And a seeded
//! machine's storage overlay names a seed file that stays in the cache, so
//! the move is also the moment to hard link that seed next to the overlay
//! and point the header at the link, after which evicting the cache cannot
//! break the machine. Rewrites only ever shrink the stored string (absolute
//! to relative), so they fit in place and no other header structure moves.
//!
//! The work is two phases so a crash at any point heals on the next run.
//! The move phase renames directories (staging name plus rename when a copy
//! is needed, so a partial copy never claims a machine's name). The fixup
//! phase then runs over EVERY directory in the new root, not only the ones
//! moved this run: fixups are cheap and idempotent, and that is what
//! recovers a kill between the two phases.

use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::disk_utils::{qcow2_backing_entry, rewrite_qcow2_backing};

/// Subdirectories of the legacy root that are re-creatable scratch, not
/// machines. They are left behind and die with the legacy root.
const SCRATCH_DIRS: &[&str] = &["_restore-base", "_cow-bases", "checkpoint-unpack"];

/// Move every stopped machine from `legacy` to `root` and make its disk
/// chain location-independent. Best effort throughout: a machine that cannot
/// be moved (running, or a copy failed) is left in place for
/// [`ensure_machine_migrated`] to pick up when it is next touched, and a
/// backing path that cannot be rewritten is left pointing at its old
/// absolute target, which still resolves until the legacy root is deleted.
pub(crate) fn migrate_legacy_vm_root(legacy: &Path, root: &Path, seed_root: &Path) {
    // On Windows the cache and local data dirs are the same place, so there
    // is nothing to move and nothing below runs.
    if legacy == root {
        return;
    }
    if fs::create_dir_all(root).is_err() {
        return;
    }
    let Some(_lock) = MigrateLock::acquire(root) else {
        return;
    };

    // A staging dir can only be left behind by a crash; nothing owns one.
    if let Ok(entries) = fs::read_dir(root) {
        for entry in entries.flatten() {
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with(".migrating-")
            {
                let _ = fs::remove_dir_all(entry.path());
            }
        }
    }

    if legacy.is_dir() {
        let mut moved = 0usize;
        if let Ok(entries) = fs::read_dir(legacy) {
            for entry in entries.flatten() {
                if move_one(&entry.path(), root) {
                    moved += 1;
                }
            }
        }
        if moved > 0 {
            tracing::info!(
                count = moved,
                from = %legacy.display(),
                to = %root.display(),
                "migrated machines out of the cache directory"
            );
        }
        // Stale per-machine lock dotfiles keep the legacy dir from going
        // away; anything nobody holds is dead weight.
        sweep_free_lock_files(legacy);
        for scratch in SCRATCH_DIRS {
            let _ = fs::remove_dir_all(legacy.join(scratch));
        }
        let _ = fs::remove_dir(legacy);
    }

    // Fixups for everything in the new root, whenever it got here.
    if let Ok(entries) = fs::read_dir(root) {
        for entry in entries.flatten() {
            let dir = entry.path();
            if !dir.is_dir() {
                continue;
            }
            fix_backing_paths(&dir, legacy, root, seed_root);
            fix_shared_pack_pointer(&dir, legacy, root);
        }
    }
}

/// Migrate a single machine directory if it is still sitting in the legacy
/// root. Called whenever a machine's directory is about to be used, so a
/// machine the bulk migration skipped (it was running) moves over the first
/// time it is touched while stopped. While it is still running it is left in
/// place; `vm_data_dir` keeps resolving to the legacy copy until then.
/// Best effort, like the bulk pass.
pub(crate) fn ensure_machine_migrated(
    legacy: &Path,
    root: &Path,
    seed_root: &Path,
    dir_name: &str,
) {
    if legacy == root || root.join(dir_name).exists() {
        return;
    }
    let old_dir = legacy.join(dir_name);
    if !old_dir.is_dir() || machine_is_running(&old_dir) {
        return;
    }
    if fs::create_dir_all(root).is_err() {
        return;
    }
    let Some(_lock) = MigrateLock::acquire(root) else {
        return;
    };
    if root.join(dir_name).exists() {
        return;
    }
    if move_one(&old_dir, root) {
        let new_dir = root.join(dir_name);
        fix_backing_paths(&new_dir, legacy, root, seed_root);
        fix_shared_pack_pointer(&new_dir, legacy, root);
        let _ = fs::remove_dir(legacy);
    }
}

/// Exclusive advisory lock serializing migration across processes.
struct MigrateLock(#[allow(dead_code)] fs::File);

impl MigrateLock {
    fn acquire(root: &Path) -> Option<Self> {
        let file = fs::File::create(root.join(".migrate.lock")).ok()?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // SAFETY: a blocking flock on an fd this struct owns.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
                return None;
            }
        }
        Some(Self(file))
    }
}

/// Move one legacy entry into `root`. Returns true when a directory moved.
fn move_one(old_dir: &Path, root: &Path) -> bool {
    if !old_dir.is_dir() {
        return false;
    }
    let Some(name) = old_dir.file_name() else {
        return false;
    };
    let name_str = name.to_string_lossy().into_owned();
    if SCRATCH_DIRS.iter().any(|s| name_str == *s) {
        return false;
    }
    let new_dir = root.join(name);
    if new_dir.exists() {
        return false;
    }
    if machine_is_running(old_dir) {
        tracing::info!(machine_dir = %old_dir.display(), "machine is running; migrating it when it is next touched");
        return false;
    }
    if fs::rename(old_dir, &new_dir).is_err() {
        // Different filesystems (a tmpfs cache, say): copy to a staging name
        // and rename, so a crash mid-copy can never leave a partial machine
        // dir claiming the final name while the complete original sits
        // stranded in the cache.
        let staging = root.join(format!(".migrating-{name_str}"));
        let _ = fs::remove_dir_all(&staging);
        if let Err(error) = copy_dir_recursive(old_dir, &staging) {
            tracing::warn!(machine_dir = %old_dir.display(), %error, "could not migrate machine out of the cache");
            let _ = fs::remove_dir_all(&staging);
            return false;
        }
        if fs::rename(&staging, &new_dir).is_err() {
            let _ = fs::remove_dir_all(&staging);
            return false;
        }
        let _ = fs::remove_dir_all(old_dir);
    }
    true
}

/// A running machine's VM process holds an exclusive flock on `vm.lock`.
fn machine_is_running(dir: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let Ok(file) = fs::File::open(dir.join("vm.lock")) else {
            return false;
        };
        // SAFETY: probing an advisory lock on an open fd.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return true;
        }
        // SAFETY: releasing the probe lock taken above.
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
    }
    // Windows never reaches a migration: its cache and local data dirs are
    // the same folder, so both entry points return before any probe.
    #[cfg(not(unix))]
    let _ = dir;
    false
}

/// Remove `*.lock` dotfiles nobody holds, so an otherwise-empty legacy root
/// can actually be deleted.
fn sweep_free_lock_files(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() || path.extension().is_none_or(|e| e != "lock") {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let Ok(file) = fs::File::open(&path) else {
                continue;
            };
            // SAFETY: probing then releasing an advisory lock.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                continue;
            }
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
        }
        let _ = fs::remove_file(&path);
    }
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> crate::Result<()> {
    fs::create_dir_all(dst).map_err(|e| crate::Error::storage("migrate machine", e.to_string()))?;
    for entry in
        fs::read_dir(src).map_err(|e| crate::Error::storage("migrate machine", e.to_string()))?
    {
        let entry = entry.map_err(|e| crate::Error::storage("migrate machine", e.to_string()))?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let kind = entry
            .file_type()
            .map_err(|e| crate::Error::storage("migrate machine", e.to_string()))?;
        if kind.is_dir() {
            copy_dir_recursive(&from, &to)?;
        } else if kind.is_file() {
            crate::disk_utils::clone_or_copy_file(&from, &to)?;
        }
        // Sockets and other runtime specials are per-boot state; skip them.
    }
    Ok(())
}

/// Rewrite every absolute qcow2 backing path inside `machine_dir` so the
/// machine stops depending on where other directories live. Idempotent:
/// relative backings are left alone, so running this over an already-fixed
/// directory reads one header per disk and writes nothing.
fn fix_backing_paths(machine_dir: &Path, legacy: &Path, root: &Path, seed_root: &Path) {
    let legacy_resolved = resolved(legacy);
    let seed_root_resolved = resolved(seed_root);
    let mut stack = vec![machine_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|e| e != "qcow2") {
                continue;
            }
            let Some((backing, _, _)) = qcow2_backing_entry(&path) else {
                continue;
            };
            if backing.is_relative() {
                continue;
            }
            let overlay_dir = path.parent().unwrap_or(machine_dir);
            if let Some(rest) = strip_either(&backing, legacy, &legacy_resolved) {
                // A machine disk, this one's own or a fork base's. The
                // target dir moved with this migration, so point at its new
                // home by a path relative to the overlay.
                let target = root.join(rest);
                if let Some(rel) = relative_between(overlay_dir, &target, root) {
                    if let Err(error) = rewrite_qcow2_backing(&path, &rel) {
                        tracing::warn!(disk = %path.display(), %error, "could not rewrite backing path");
                    }
                }
            } else if strip_either(&backing, seed_root, &seed_root_resolved).is_some() {
                // A cache seed. Hard link it beside the overlay (copy across
                // filesystems) and use the link, so evicting the seed cache
                // can no longer break this machine.
                let link_name = match (path.file_stem(), backing.extension()) {
                    (Some(stem), Some(ext)) => {
                        format!("{}.base.{}", stem.to_string_lossy(), ext.to_string_lossy())
                    }
                    _ => continue,
                };
                let link = overlay_dir.join(&link_name);
                if !link.exists() {
                    if !backing.exists() {
                        tracing::warn!(disk = %path.display(), backing = %backing.display(), "backing seed is already gone");
                        continue;
                    }
                    if fs::hard_link(&backing, &link).is_err() {
                        if let Err(error) = crate::disk_utils::clone_or_copy_file(&backing, &link) {
                            tracing::warn!(disk = %path.display(), %error, "could not pin backing seed");
                            continue;
                        }
                    }
                }
                if let Err(error) = rewrite_qcow2_backing(&path, &link_name) {
                    tracing::warn!(disk = %path.display(), %error, "could not rewrite backing path");
                }
            }
            // Any other absolute backing (a storage template in the install
            // dir, a user-supplied path) is not ours to move.
        }
    }
}

/// A shared-pack machine's `.pack-shared` pointer holds the shared copy's
/// absolute path. The shared tree (`_shared`) moves with the root, so a
/// pointer into the legacy root is rewritten to the new one; otherwise the
/// pointer reads as stale and the machine boots with empty packed layers.
fn fix_shared_pack_pointer(machine_dir: &Path, legacy: &Path, root: &Path) {
    let pointer = machine_dir.join(super::SHARED_PACK_POINTER);
    let Ok(raw) = fs::read_to_string(&pointer) else {
        return;
    };
    let old = PathBuf::from(raw.trim());
    let Some(rest) = strip_either(&old, legacy, &resolved(legacy)) else {
        return;
    };
    let new = root.join(rest);
    if let Err(error) = fs::write(&pointer, new.to_string_lossy().as_bytes()) {
        tracing::warn!(pointer = %pointer.display(), %error, "could not rewrite shared pack pointer");
    }
}

/// The path with symlinks resolved, even once it no longer exists: the
/// deepest existing ancestor is canonicalized and the rest appended. Disk
/// headers written by older versions hold canonicalized paths, so a HOME
/// behind a symlink makes them differ from the roots as `dirs` reports them.
fn resolved(path: &Path) -> PathBuf {
    let mut existing = path;
    let mut rest = Vec::new();
    loop {
        if let Ok(real) = existing.canonicalize() {
            let mut out = real;
            for part in rest.iter().rev() {
                out.push(part);
            }
            return out;
        }
        match (existing.parent(), existing.file_name()) {
            (Some(parent), Some(name)) => {
                rest.push(name.to_os_string());
                existing = parent;
            }
            _ => return path.to_path_buf(),
        }
    }
}

/// `rest` of `path` below whichever spelling of `base` it starts with.
fn strip_either<'a>(path: &'a Path, base: &Path, base_resolved: &Path) -> Option<&'a Path> {
    path.strip_prefix(base)
        .or_else(|_| path.strip_prefix(base_resolved))
        .ok()
}

/// `target` expressed relative to `from_dir`, both under `root`.
/// `None` when either escapes `root` or the paths are not plain components.
fn relative_between(from_dir: &Path, target: &Path, root: &Path) -> Option<String> {
    let from = from_dir.strip_prefix(root).ok()?;
    let to = target.strip_prefix(root).ok()?;
    let ups = from
        .components()
        .filter(|c| matches!(c, Component::Normal(_)))
        .count();
    let mut rel = PathBuf::new();
    for _ in 0..ups {
        rel.push("..");
    }
    rel.push(to);
    rel.to_str().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn qcow2_with_backing(path: &Path, backing: &str) {
        let backing = backing.as_bytes();
        let mut image = vec![0u8; 512];
        image[..4].copy_from_slice(b"QFI\xfb");
        image[8..16].copy_from_slice(&256u64.to_be_bytes());
        image[16..20].copy_from_slice(&(backing.len() as u32).to_be_bytes());
        image[256..256 + backing.len()].copy_from_slice(backing);
        fs::write(path, &image).unwrap();
    }

    fn backing_of(path: &Path) -> PathBuf {
        qcow2_backing_entry(path).unwrap().0
    }

    #[test]
    fn moves_machines_and_rewrites_clone_backing() {
        let tmp = tempfile::tempdir().unwrap();
        let legacy = tmp.path().join("cache/vms");
        let root = tmp.path().join("data/vms");
        let seeds = tmp.path().join("cache/image-seeds");
        let golden = legacy.join("aaaa");
        let clone = legacy.join("bbbb");
        // A generation disk below a subdirectory keeps its depth.
        fs::create_dir_all(golden.join("d/3")).unwrap();
        fs::create_dir_all(&clone).unwrap();
        fs::write(golden.join("d/3/storage.base.qcow2"), b"base").unwrap();
        qcow2_with_backing(
            &clone.join("storage.qcow2"),
            golden.join("d/3/storage.base.qcow2").to_str().unwrap(),
        );

        migrate_legacy_vm_root(&legacy, &root, &seeds);

        assert!(root.join("aaaa/d/3/storage.base.qcow2").exists());
        assert_eq!(
            backing_of(&root.join("bbbb/storage.qcow2")),
            PathBuf::from("../aaaa/d/3/storage.base.qcow2")
        );
        assert!(!legacy.exists());
    }

    #[test]
    fn rewrites_backing_written_through_a_resolved_symlink() {
        // tempdir lives under /var on macOS, a symlink to /private/var, so a
        // canonicalized backing path differs from the legacy root as given.
        // The old fork code wrote clone backings with canonicalize().
        let tmp = tempfile::tempdir().unwrap();
        let legacy = tmp.path().join("cache/vms");
        let root = tmp.path().join("data/vms");
        let seeds = tmp.path().join("cache/image-seeds");
        let golden = legacy.join("aaaa");
        let clone = legacy.join("bbbb");
        fs::create_dir_all(&golden).unwrap();
        fs::create_dir_all(&clone).unwrap();
        fs::write(golden.join("storage.raw"), b"base").unwrap();
        let resolved = golden.join("storage.raw").canonicalize().unwrap();
        qcow2_with_backing(&clone.join("storage.qcow2"), resolved.to_str().unwrap());

        migrate_legacy_vm_root(&legacy, &root, &seeds);

        assert_eq!(
            backing_of(&root.join("bbbb/storage.qcow2")),
            PathBuf::from("../aaaa/storage.raw")
        );
    }

    #[test]
    fn pins_seed_backing_with_a_local_link() {
        let tmp = tempfile::tempdir().unwrap();
        let legacy = tmp.path().join("cache/vms");
        let root = tmp.path().join("data/vms");
        let seeds = tmp.path().join("cache/image-seeds");
        let key_dir = seeds.join("k1");
        fs::create_dir_all(&key_dir).unwrap();
        fs::write(key_dir.join("storage.qcow2"), b"seed-bytes").unwrap();
        let machine = legacy.join("cccc");
        fs::create_dir_all(&machine).unwrap();
        qcow2_with_backing(
            &machine.join("storage.qcow2"),
            key_dir.join("storage.qcow2").to_str().unwrap(),
        );

        migrate_legacy_vm_root(&legacy, &root, &seeds);

        let moved = root.join("cccc/storage.qcow2");
        assert_eq!(backing_of(&moved), PathBuf::from("storage.base.qcow2"));
        // The link carries the seed bytes even after the cache is purged.
        fs::remove_dir_all(&seeds).unwrap();
        assert_eq!(
            fs::read(root.join("cccc/storage.base.qcow2")).unwrap(),
            b"seed-bytes"
        );
    }

    #[test]
    fn fixups_also_heal_dirs_moved_by_an_interrupted_run() {
        let tmp = tempfile::tempdir().unwrap();
        let legacy = tmp.path().join("cache/vms");
        let root = tmp.path().join("data/vms");
        let seeds = tmp.path().join("cache/image-seeds");
        // Simulate a kill between the move and fixup phases: the machine is
        // already in the new root, its backing still absolute into the
        // legacy root, and the legacy root is already gone.
        fs::create_dir_all(root.join("aaaa")).unwrap();
        fs::create_dir_all(root.join("bbbb")).unwrap();
        fs::write(root.join("aaaa/storage.raw"), b"base").unwrap();
        qcow2_with_backing(
            &root.join("bbbb/storage.qcow2"),
            legacy.join("aaaa/storage.raw").to_str().unwrap(),
        );

        migrate_legacy_vm_root(&legacy, &root, &seeds);

        assert_eq!(
            backing_of(&root.join("bbbb/storage.qcow2")),
            PathBuf::from("../aaaa/storage.raw")
        );
    }

    #[test]
    fn shared_pack_pointer_is_rewritten() {
        let tmp = tempfile::tempdir().unwrap();
        let legacy = tmp.path().join("cache/vms");
        let root = tmp.path().join("data/vms");
        let seeds = tmp.path().join("seeds");
        fs::create_dir_all(legacy.join("_shared/pack1")).unwrap();
        let machine = legacy.join("dddd");
        fs::create_dir_all(&machine).unwrap();
        fs::write(
            machine.join(crate::agent::SHARED_PACK_POINTER),
            legacy.join("_shared/pack1").to_string_lossy().as_bytes(),
        )
        .unwrap();

        migrate_legacy_vm_root(&legacy, &root, &seeds);

        let raw =
            fs::read_to_string(root.join("dddd").join(crate::agent::SHARED_PACK_POINTER)).unwrap();
        assert_eq!(
            PathBuf::from(raw.trim()),
            root.join("_shared/pack1"),
            "pointer follows the shared tree into the new root"
        );
        assert!(root.join("_shared/pack1").is_dir());
    }

    #[test]
    fn single_machine_catchup_migrates_and_fixes() {
        let tmp = tempfile::tempdir().unwrap();
        let legacy = tmp.path().join("cache/vms");
        let root = tmp.path().join("data/vms");
        let seeds = tmp.path().join("seeds");
        fs::create_dir_all(legacy.join("eeee")).unwrap();
        fs::write(legacy.join("eeee/overlay.raw"), b"x").unwrap();

        ensure_machine_migrated(&legacy, &root, &seeds, "eeee");

        assert!(root.join("eeee/overlay.raw").exists());
        assert!(!legacy.exists());
        // Idempotent for a machine already in place.
        ensure_machine_migrated(&legacy, &root, &seeds, "eeee");
        assert!(root.join("eeee/overlay.raw").exists());
    }

    #[cfg(unix)]
    #[test]
    fn running_machine_stays_put_until_it_stops() {
        use std::os::fd::AsRawFd;
        let tmp = tempfile::tempdir().unwrap();
        let legacy = tmp.path().join("cache/vms");
        let root = tmp.path().join("data/vms");
        let seeds = tmp.path().join("seeds");
        fs::create_dir_all(legacy.join("hhhh")).unwrap();
        fs::write(legacy.join("hhhh/storage.raw"), b"live").unwrap();
        // The VM process holds vm.lock for as long as it runs.
        let lock = fs::File::create(legacy.join("hhhh/vm.lock")).unwrap();
        assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);

        migrate_legacy_vm_root(&legacy, &root, &seeds);
        ensure_machine_migrated(&legacy, &root, &seeds, "hhhh");
        assert!(legacy.join("hhhh/storage.raw").exists());
        assert!(
            !root.join("hhhh").exists(),
            "no empty dir may shadow a machine that is still running"
        );

        drop(lock);
        ensure_machine_migrated(&legacy, &root, &seeds, "hhhh");
        assert_eq!(fs::read(root.join("hhhh/storage.raw")).unwrap(), b"live");
        assert!(!legacy.join("hhhh").exists());
    }

    #[test]
    fn second_run_is_a_noop_and_scratch_dirs_die() {
        let tmp = tempfile::tempdir().unwrap();
        let legacy = tmp.path().join("cache/vms");
        let root = tmp.path().join("data/vms");
        let seeds = tmp.path().join("seeds");
        fs::create_dir_all(legacy.join("_restore-base")).unwrap();
        fs::create_dir_all(legacy.join("ffff")).unwrap();
        fs::write(legacy.join("ffff/overlay.raw"), b"x").unwrap();
        fs::write(legacy.join(".ffff.fork-operation.lock"), b"").unwrap();

        migrate_legacy_vm_root(&legacy, &root, &seeds);
        migrate_legacy_vm_root(&legacy, &root, &seeds);

        assert!(root.join("ffff/overlay.raw").exists());
        assert!(!root.join("_restore-base").exists());
        assert!(!legacy.exists(), "free lock dotfiles are swept too");
    }

    #[test]
    fn same_old_and_new_root_is_untouched() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("vms");
        fs::create_dir_all(root.join("gggg")).unwrap();
        migrate_legacy_vm_root(&root, &root, &tmp.path().join("seeds"));
        assert!(root.join("gggg").exists());
    }
}
