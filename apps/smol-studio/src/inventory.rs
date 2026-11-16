//! One bounded, read-only inventory request independent of user commands.
use crate::{
    model::{Machine, Operation},
    runtime::{Payload, Runtime, Worker},
};

pub struct Inventory {
    worker: Worker,
    epoch: u64,
    observed: Option<u64>,
    pending: Option<u64>,
    requested: bool,
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        os::unix::fs::PermissionsExt,
        path::Path,
        thread,
        time::{Duration, Instant},
    };

    fn fixture() -> (tempfile::TempDir, Runtime) {
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("test cli");
        std::fs::write(
            &executable,
            r#"#!/bin/sh
if [ "$2" = ls ]; then
    code=0
    if [ -e "$SMOLVM_DATA_DIR/failure" ]; then code=7; printf stale-failure >&2; fi
    cat "$SMOLVM_DATA_DIR/snapshot"
    if [ -e "$SMOLVM_DATA_DIR/hold" ]; then
        touch "$SMOLVM_DATA_DIR/started"
        while [ -e "$SMOLVM_DATA_DIR/hold" ]; do sleep 0.01; done
    fi
    exit "$code"
fi
printf action-complete
"#,
        )
        .unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
        snapshot(dir.path(), "initial");
        let runtime = Runtime {
            executable,
            state_dir: Some(dir.path().to_path_buf()),
        };
        (dir, runtime)
    }

    fn snapshot(root: &Path, name: &str) {
        std::fs::write(
            root.join("snapshot"),
            format!(r#"[{{"name":"{name}","state":"stopped","cpus":1,"memory_mib":512}}]"#),
        )
        .unwrap();
    }

    fn until(mut check: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !check() {
            assert!(
                Instant::now() < deadline,
                "observer did not reach expected state"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn result(inventory: &mut Inventory) -> Result<Vec<Machine>, String> {
        let mut output = None;
        until(|| {
            output = inventory.poll();
            output.is_some()
        });
        output.unwrap()
    }

    #[test]
    fn delayed_inventory_does_not_block_actions_or_publish_pre_action_snapshot() {
        let (dir, runtime) = fixture();
        let mut inventory = Inventory::new(|| {});
        inventory.start(&runtime).unwrap();
        assert_eq!(result(&mut inventory).unwrap()[0].name, "initial");
        assert!(inventory.current());

        std::fs::write(dir.path().join("hold"), "").unwrap();
        snapshot(dir.path(), "before-action");
        inventory.request();
        inventory.start(&runtime).unwrap();
        until(|| dir.path().join("started").exists());
        assert!(
            inventory.current(),
            "ordinary refresh must leave controls usable"
        );
        for _ in 0..100 {
            inventory.request();
            inventory.start(&runtime).unwrap();
        }
        assert!(!inventory.requested, "duplicate refreshes must coalesce");

        inventory.invalidate();
        let actions = Worker::new(|| {});
        actions
            .submit(
                runtime.clone(),
                Operation::Exec {
                    name: "fixture".into(),
                    command: "true".into(),
                },
            )
            .unwrap();
        let done = actions
            .responses
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        assert!(
            matches!(done.result, Ok(Payload::Output { text, .. }) if text.contains("action-complete"))
        );
        assert!(!inventory.current());
        assert!(
            dir.path().join("hold").exists(),
            "command completed before refresh was released"
        );

        // A connection change during the same request also rejects the old source.
        inventory.invalidate();
        snapshot(dir.path(), "after-action");
        std::fs::remove_file(dir.path().join("hold")).unwrap();
        until(|| {
            assert!(inventory.poll().is_none());
            inventory.pending.is_none()
        });
        inventory.start(&runtime).unwrap();
        assert_eq!(result(&mut inventory).unwrap()[0].name, "after-action");
        assert!(inventory.current());
        assert!(!inventory.busy());
    }

    #[test]
    fn obsolete_connection_failure_is_discarded_but_current_failure_is_reported() {
        let (dir, runtime) = fixture();
        let mut inventory = Inventory::new(|| {});
        std::fs::write(dir.path().join("failure"), "").unwrap();
        std::fs::write(dir.path().join("hold"), "").unwrap();
        inventory.start(&runtime).unwrap();
        until(|| dir.path().join("started").exists());
        inventory.invalidate();
        std::fs::remove_file(dir.path().join("hold")).unwrap();
        until(|| {
            assert!(inventory.poll().is_none());
            inventory.pending.is_none()
        });
        inventory.start(&runtime).unwrap();
        assert!(
            result(&mut inventory)
                .unwrap_err()
                .contains("stale-failure")
        );
        assert!(!inventory.current());
        std::fs::remove_file(dir.path().join("failure")).unwrap();
        inventory.request();
        inventory.start(&runtime).unwrap();
        assert!(result(&mut inventory).is_ok());
        assert!(inventory.current());
    }
}

impl Inventory {
    pub fn new(wake: impl Fn() + Send + Sync + 'static) -> Self {
        Self {
            worker: Worker::new(wake),
            epoch: 0,
            observed: None,
            pending: None,
            requested: true,
        }
    }

    pub fn current(&self) -> bool {
        self.observed == Some(self.epoch)
    }

    pub fn busy(&self) -> bool {
        self.pending.is_some() || self.requested
    }

    /// Coalesce refresh clicks with an existing request for this epoch.
    pub fn request(&mut self) {
        if self.pending != Some(self.epoch) {
            self.requested = true;
        }
    }

    /// A command or connection change makes any earlier snapshot obsolete.
    pub fn invalidate(&mut self) {
        self.epoch = self.epoch.wrapping_add(1);
        self.requested = true;
    }

    /// The caller defers starting reads during actions and ordinary dialogs.
    pub fn start(&mut self, runtime: &Runtime) -> Result<(), String> {
        if self.requested && self.pending.is_none() {
            self.worker.submit(runtime.clone(), Operation::Refresh)?;
            self.pending = Some(self.epoch);
            self.requested = false;
        }
        Ok(())
    }

    /// The caller may defer polling while a dialog owns the current selection.
    pub fn poll(&mut self) -> Option<Result<Vec<Machine>, String>> {
        let done = self.worker.responses.try_recv().ok()?;
        if self.pending.take() != Some(self.epoch) {
            return None;
        }
        let result = match done.result {
            Ok(Payload::Machines(machines)) => Ok(machines),
            Ok(_) => Err("The runtime returned an unexpected machine inventory.".into()),
            Err(error) => Err(error),
        };
        self.observed = result.as_ref().ok().map(|_| self.epoch);
        Some(result)
    }
}
