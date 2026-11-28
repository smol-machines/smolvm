//! Bounded recovery of live resource changes after a server restart.

use super::state::ApiState;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

/// Reconcile one machine at a time without delaying the health supervisor.
/// Shutdown waits for an already-started blocking operation: dropping its
/// future would not stop the operation and must not release lifecycle ownership.
pub async fn run(state: Arc<ApiState>, mut shutdown: watch::Receiver<bool>) {
    // The last failure warned about for each machine, so a retry that fails the
    // same way every 10 s is not logged again.
    let mut warned: HashMap<String, String> = HashMap::new();
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
        warned.retain(|name, _| names.contains(name));
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
                    warned.remove(&name);
                    tracing::info!(machine = %name, "recovered unfinished machine resize")
                }
                Ok(Ok(None)) => {
                    warned.remove(&name);
                }
                Ok(Err(error)) => {
                    // The error can carry text from the guest, up to a full agent frame.
                    let error = bounded(&error.to_string());
                    if warned.get(&name) != Some(&error) {
                        tracing::warn!(machine = %name, %error, "machine resize remains unfinished");
                        warned.insert(name, error);
                    } else {
                        tracing::debug!(machine = %name, "machine resize still unfinished");
                    }
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

/// The most of an error's text a log line keeps.
const MAX_LOGGED_ERROR: usize = 1024;

fn bounded(text: &str) -> String {
    if text.len() <= MAX_LOGGED_ERROR {
        return text.to_string();
    }
    let mut end = MAX_LOGGED_ERROR;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}… ({} bytes not shown)", &text[..end], text.len() - end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_long_error_is_cut_at_a_character_boundary() {
        let text = format!(
            "{}é{}",
            "a".repeat(MAX_LOGGED_ERROR - 1),
            "b".repeat(32 << 20)
        );
        let shown = bounded(&text);
        assert!(shown.len() < MAX_LOGGED_ERROR + 64, "{} bytes", shown.len());
        assert!(shown.starts_with(&"a".repeat(MAX_LOGGED_ERROR - 1)));
        assert!(shown.ends_with(&format!(
            "({} bytes not shown)",
            text.len() - (MAX_LOGGED_ERROR - 1)
        )));
        assert_eq!(bounded("short"), "short");
    }
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
