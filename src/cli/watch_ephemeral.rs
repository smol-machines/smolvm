//! Background watcher for ephemeral detached `machine run -d` VMs.
//!
//! Invoked as `smolvm _watch-ephemeral <vm-name> <pid> <start-time>`
//! after the parent CLI detaches. Polls until the VM process exits naturally
//! (the agent calls libc::exit when the workload finishes, shutting down
//! the guest kernel and the krun process), then deletes the machine record
//! and data directory via the normal `delete_vm` path.
//!
//! If the user manually stops and deletes the machine first, `delete_vm`
//! returns vm_not_found, which the watcher silently ignores.
//!
//! Safety ordering (same as _cleanup-ephemeral but without the SIGKILL step):
//! - Process death confirmed before any cleanup.
//! - Config record removed before data directory deletion.

/// Entry point for the `_watch-ephemeral` subcommand.
pub fn run(vm_name: &str, pid: i32, start_time: u64) {
    let start_time_opt = if start_time > 0 {
        Some(start_time)
    } else {
        None
    };

    // Poll until the VM process exits naturally or PID is reused.
    loop {
        let still_ours = match start_time_opt {
            // With a start time, detect PID reuse: breaks when PID is dead
            // or a different process has taken over the slot.
            Some(st) => smolvm::process::is_our_process(pid, Some(st)),
            // Without a start time, fall back to liveness check only.
            None => smolvm::process::is_alive(pid),
        };

        if !still_ours {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    // VM has exited. Remove the named machine record and data directory.
    // Ignore errors: if the user already ran `machine delete`, this is a no-op.
    let _ = super::vm_common::delete_vm(
        vm_name,
        true, // force — no interactive prompt in background helper
        super::vm_common::DeleteVmOptions {
            stop_if_running: false, // VM already exited naturally
        },
    );
}
