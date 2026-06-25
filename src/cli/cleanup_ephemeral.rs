//! Detached cleanup helper for ephemeral `machine run` VMs.
//!
//! Invoked as `smolvm _cleanup-ephemeral <vm-name> <pid> <start-time> <ephemeral-name>`
//! after the parent CLI has flushed output and is about to exit. Running out of
//! process lets the parent return the guest's exit code immediately while disk
//! removal and process teardown happen asynchronously.
//!
//! Safety guarantees:
//! - SIGKILL is sent only after strict PID+start_time verification (no fallback).
//! - Directory removal only happens after the VM process is confirmed dead.
//! - DB deregistration runs only after the directory is confirmed gone.
//! - All three steps are gated: a failure at any step leaves state for orphan sweep.

use crate::cli::vm_common::deregister_ephemeral_vm;
use smolvm::agent::{vm_cache_root, vm_data_dir};
use std::path::Path;

/// Entry point for the `_cleanup-ephemeral` subcommand.
pub fn run(vm_name: &str, pid: i32, start_time: u64, ephemeral_name: &str) {
    let data_dir = vm_data_dir(vm_name);
    let cache_root = vm_cache_root();
    let ephemeral_name = ephemeral_name.to_owned();
    run_inner(
        pid,
        start_time,
        smolvm::process::kill_verified,
        smolvm::process::is_alive,
        move || {
            // Validate the path is inside the smolvm cache root — never delete
            // /, home, empty paths, or symlink-rooted paths.
            if !is_safe_cache_path(&data_dir, &cache_root) {
                return false;
            }
            if data_dir.is_dir() {
                // Release this VM's per-VM uid before its `.vm-uid` record goes
                // with the dir. `machine run` is the highest-churn path, so
                // freeing it here keeps the uid registry small (the allocator
                // self-heals stale entries too, but proactively freeing avoids
                // buildup).
                smolvm::process::free_vm_uid(&smolvm::agent::vm_uid_registry_dir(), &data_dir);
                std::fs::remove_dir_all(&data_dir).is_ok()
            } else {
                !data_dir.exists()
            }
        },
        move || deregister_ephemeral_vm(&ephemeral_name),
    );
}

/// Returns `true` only when `data_dir` is a safe path to delete:
/// non-empty, strictly inside `cache_root`, not equal to `cache_root`,
/// and not a symlink (prevents escaping via redirected root).
fn is_safe_cache_path(data_dir: &Path, cache_root: &Path) -> bool {
    !data_dir.as_os_str().is_empty()
        && data_dir.starts_with(cache_root)
        && data_dir != cache_root
        && !data_dir.is_symlink()
}

/// Core cleanup logic with injectable side-effect functions.
///
/// Separated from `run` to enable unit testing of the failure-ordering invariants
/// without needing a real process, filesystem, or database.
///
/// - `remove_dir`: called when the process is confirmed dead; returns `true` on
///   success. The caller is responsible for path-safety checks inside this closure.
/// - `deregister`: called only after `remove_dir` succeeds; the caller binds the
///   ephemeral record name in the closure.
fn run_inner<FKill, FAlive, FRemove, FDeregister>(
    pid: i32,
    start_time: u64,
    kill_verified: FKill,
    is_alive: FAlive,
    remove_dir: FRemove,
    deregister: FDeregister,
) where
    FKill: Fn(i32, Option<u64>) -> bool,
    FAlive: Fn(i32) -> bool,
    FRemove: Fn() -> bool,
    FDeregister: Fn(),
{
    let start_time_opt = if start_time > 0 {
        Some(start_time)
    } else {
        None
    };

    // Send SIGKILL using strict verification: refuses to signal if start_time
    // is missing or the PID has been reused by an unrelated process.
    let kill_sent = kill_verified(pid, start_time_opt);

    let vm_confirmed_dead = if kill_sent {
        // Poll until the process is gone. The VM is reparented to launchd/init
        // after our parent exited, so try_wait returns ECHILD — use is_alive.
        let mut dead = false;
        for _ in 0..500 {
            if !is_alive(pid) {
                dead = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        dead
    } else {
        // kill_verified refused — either start_time was absent/mismatched (PID
        // reuse) or the process is already dead. Safe to proceed only if dead.
        !is_alive(pid)
    };

    if !vm_confirmed_dead {
        // VM is still alive (SIGKILL timed out) or a different process now holds
        // the PID. Leave the data directory and DB record intact so the orphan
        // sweep can retry.
        return;
    }

    // Remove the data directory. The caller's closure handles path-safety
    // validation. Failure here leaves the DB record for the orphan sweep.
    if !remove_dir() {
        return;
    }

    // Deregister the ephemeral DB record. Done last so cleanup_orphaned_ephemeral_vms()
    // can find and recover this record if the helper is killed before reaching here.
    deregister();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::path::PathBuf;

    /// Build a safe (cache_root, data_dir) pair inside a real temp directory.
    fn fake_dirs() -> (tempfile::TempDir, PathBuf) {
        let cache_root = tempfile::TempDir::new().unwrap();
        let data_dir = cache_root.path().join("vm-abc123");
        (cache_root, data_dir)
    }

    /// start_time = 0 → kill is skipped; proceeds if the process is already dead.
    #[test]
    fn missing_start_time_skips_kill_and_cleans_up_dead_process() {
        let (_cache_tmp, data_dir) = fake_dirs();
        std::fs::create_dir(&data_dir).unwrap();
        let kill_called = Cell::new(false);
        let deregistered = Cell::new(false);

        run_inner(
            9999,
            0, // start_time = 0  →  start_time_opt = None
            |_pid, st| {
                assert_eq!(st, None, "no start_time → kill_verified must receive None");
                kill_called.set(true);
                false
            },
            |_pid| false, // process already dead
            || std::fs::remove_dir_all(&data_dir).is_ok(),
            || deregistered.set(true),
        );

        assert!(kill_called.get(), "kill_verified should still be called");
        assert!(!data_dir.exists(), "data dir should be removed");
        assert!(
            deregistered.get(),
            "ephemeral record should be deregistered"
        );
    }

    /// PID reuse: start_time present but mismatched — kill refused, process alive → abort.
    ///
    /// Invariant: when a different process now holds the PID, neither the data
    /// directory nor the DB record should be touched.
    #[test]
    fn reused_pid_refuses_all_cleanup_when_process_alive() {
        let (_cache_tmp, data_dir) = fake_dirs();
        std::fs::create_dir(&data_dir).unwrap();
        let remove_called = Cell::new(false);
        let deregistered = Cell::new(false);

        run_inner(
            9999,
            12345,
            |_pid, _st| false, // kill_verified refuses (start_time mismatch / PID reused)
            |_pid| true,       // is_alive: a different process holds this PID
            || {
                remove_called.set(true);
                false
            },
            || deregistered.set(true),
        );

        assert!(data_dir.exists(), "data dir must be preserved on PID reuse");
        assert!(!remove_called.get(), "remove must not be called");
        assert!(!deregistered.get(), "DB record must be preserved");
    }

    /// Failed directory removal must prevent DB deregistration.
    ///
    /// This is the critical ordering invariant: the orphan sweep relies on the
    /// DB record surviving so it can retry cleanup on the next startup.
    #[test]
    fn failed_dir_removal_preserves_db_record() {
        let deregistered = Cell::new(false);

        run_inner(
            9999,
            12345,
            |_pid, _st| true, // kill_verified succeeds
            |_pid| false,     // process confirmed dead after kill
            || false,         // remove_dir fails (e.g. permission error, busy mount)
            || deregistered.set(true),
        );

        assert!(
            !deregistered.get(),
            "DB record must NOT be removed when directory deletion fails"
        );
    }

    /// Already-dead PID: kill refused because process is gone; cleanup proceeds normally.
    #[test]
    fn already_dead_pid_proceeds_to_full_cleanup() {
        let (_cache_tmp, data_dir) = fake_dirs();
        std::fs::create_dir(&data_dir).unwrap();
        let deregistered = Cell::new(false);

        run_inner(
            9999,
            12345,
            |_pid, _st| false, // kill_verified: process already dead, refuses to signal
            |_pid| false,      // is_alive: confirmed dead
            || std::fs::remove_dir_all(&data_dir).is_ok(),
            || deregistered.set(true),
        );

        assert!(!data_dir.exists(), "data dir should be removed");
        assert!(
            deregistered.get(),
            "ephemeral record should be deregistered"
        );
    }

    /// Path safety check: only paths strictly inside cache_root are safe.
    #[test]
    fn safe_cache_path_checks() {
        let cache = tempfile::TempDir::new().unwrap();
        let data_dir = cache.path().join("vm-abc123");
        assert!(
            is_safe_cache_path(&data_dir, cache.path()),
            "child of cache root is safe"
        );
        assert!(
            !is_safe_cache_path(cache.path(), cache.path()),
            "cache root itself is not safe"
        );
        assert!(
            !is_safe_cache_path(Path::new(""), cache.path()),
            "empty path is not safe"
        );

        let other = tempfile::TempDir::new().unwrap();
        let outside = other.path().join("vm-abc123");
        assert!(
            !is_safe_cache_path(&outside, cache.path()),
            "path outside cache root is not safe"
        );
    }
}
