//! Bounded recovery of live resource changes after a server restart.

use super::state::ApiState;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

/// Reconcile one machine at a time without delaying the health supervisor.
/// Shutdown waits for an already-started blocking operation: dropping its
/// future would not stop the operation and must not release lifecycle ownership.
pub async fn run(state: Arc<ApiState>, mut shutdown: watch::Receiver<bool>) {
    loop {
        if *shutdown.borrow() {
            return;
        }
        let db = state.db().clone();
        let names = match tokio::task::spawn_blocking(move || db.pending_resize_names()).await {
            Ok(Ok(names)) => names,
            result => {
                tracing::warn!(?result, "could not list unfinished machine resizes");
                Vec::new()
            }
        };
        for name in names {
            if *shutdown.borrow() {
                return;
            }
            let Ok(guard) = state.lifecycle_lock(&name).try_lock_owned() else {
                continue;
            };
            let db = state.db().clone();
            let machine = name.clone();
            let result = tokio::task::spawn_blocking(move || {
                let _guard = guard;
                crate::agent::live_resize::reconcile_pending(&db, &machine)
            })
            .await;
            match result {
                Ok(Ok(Some(_))) => {
                    tracing::info!(machine = %name, "recovered unfinished machine resize")
                }
                Ok(Ok(None)) => {}
                Ok(Err(error)) => {
                    tracing::warn!(machine = %name, %error, "machine resize remains unfinished")
                }
                Err(error) => {
                    tracing::error!(machine = %name, %error, "machine resize recovery task failed")
                }
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(10)) => {},
            _ = shutdown.changed() => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::VmRecord;
    use crate::db::{ResizeTarget, SmolvmDb};

    #[tokio::test]
    async fn shutdown_does_not_wait_for_a_busy_machine_or_clear_its_intent() {
        let temp = tempfile::tempdir().unwrap();
        let db = SmolvmDb::open_at(&temp.path().join("state.db")).unwrap();
        db.insert_vm(
            "busy",
            &VmRecord::new("busy".into(), 2, 1024, vec![], vec![], false),
        )
        .unwrap();
        let intent = db
            .begin_resize("busy", 123, 45, ResizeTarget::Cpus(4))
            .unwrap();
        let state = Arc::new(ApiState::with_db(db.clone()));
        let _guard = state.lifecycle_lock("busy").lock_owned().await;
        let (tx, rx) = watch::channel(false);
        let task = tokio::spawn(run(state, rx));
        tokio::time::sleep(Duration::from_millis(50)).await;
        tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(db.pending_resize("busy").unwrap(), Some(intent));
    }

    #[tokio::test]
    async fn already_stopped_controller_does_no_work() {
        let temp = tempfile::tempdir().unwrap();
        let db = SmolvmDb::open_at(&temp.path().join("state.db")).unwrap();
        let (_tx, rx) = watch::channel(true);
        tokio::time::timeout(
            Duration::from_secs(1),
            run(Arc::new(ApiState::with_db(db)), rx),
        )
        .await
        .unwrap();
    }
}
