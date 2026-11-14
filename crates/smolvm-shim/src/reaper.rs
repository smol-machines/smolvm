//! Child ownership for the shim's embedded engine.

use containerd_shim::Config;
use std::time::Duration;
use tokio::task::JoinHandle;

pub fn configuration() -> Config {
    // The embedded engine owns native VM children and synchronous helpers.
    // containerd's waitpid(-1) loop can steal cp/tar/busctl exit statuses from
    // their Child handles. Keep the engine's per-PID VM reaper instead.
    // Do not adopt arbitrary grandchildren that this scoped reaper does not
    // own; their supervising ancestor (ultimately init) remains responsible.
    Config {
        no_reaper: true,
        no_sub_reaper: true,
        ..Config::default()
    }
}

/// Keep detached VM children drained even when no client asks for VM state.
/// Foreground helpers remain owned by their ordinary `Child` handles.
pub struct VmReaper(JoinHandle<()>);

impl VmReaper {
    pub fn start() -> Self {
        Self(tokio::spawn(async {
            let mut timer = tokio::time::interval(Duration::from_secs(1));
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                timer.tick().await;
                if let Err(error) =
                    tokio::task::spawn_blocking(smolvm::process::reap_vm_children).await
                {
                    log::error!("VM child reaper failed: {error}");
                    break;
                }
            }
        }))
    }
}

impl Drop for VmReaper {
    fn drop(&mut self) {
        self.0.abort();
    }
}
