use super::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum ResizeTarget {
    Cpus(u8),
    Memory(u32),
    Disks {
        storage: Option<u64>,
        overlay: Option<u64>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ResizeIntent {
    pub token: String,
    pub pid: i32,
    pub started: u64,
    pub target: ResizeTarget,
}

impl SmolvmDb {
    pub(crate) fn pending_resize(&self, name: &str) -> Result<Option<ResizeIntent>> {
        self.with_read_conn(|conn| {
            let bytes: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT data FROM vm_resize_intents WHERE name = ?1",
                    params![name],
                    |row| row.get(0),
                )
                .optional()
                .db_err("read pending resize")?;
            bytes
                .map(|bytes| serde_json::from_slice(&bytes).db_err("decode pending resize"))
                .transpose()
        })
    }

    pub(crate) fn pending_resize_names(&self) -> Result<Vec<String>> {
        self.with_read_conn(|conn| {
            let mut statement = conn
                .prepare("SELECT name FROM vm_resize_intents ORDER BY name")
                .db_err("list pending resizes")?;
            let rows = statement
                .query_map([], |row| row.get(0))
                .db_err("query pending resizes")?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .db_err("read pending resize names")
        })
    }
    /// Branch/capture callers hold the source lock before this check, so an
    /// unfinished operation cannot leak partially applied geometry into a
    /// published checkpoint or descendant.
    pub(crate) fn require_completed_resize(&self, name: &str) -> Result<()> {
        self.with_read_conn(|conn| {
            let pending: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM vm_resize_intents WHERE name = ?1)",
                params![name], |row| row.get(0)).db_err("check pending resize")?;
            if pending {
                return Err(Error::agent_conflict("live resize",
                    "machine has an unfinished resize; retry its original target before branching or checkpointing"));
            }
            Ok(())
        })
    }
    /// Persist intent before an irreversible runtime operation. Callers hold
    /// the machine's cross-process source lock; SQLite also rejects competing
    /// targets if another caller fails to follow that protocol.
    pub(crate) fn begin_resize(
        &self,
        name: &str,
        pid: i32,
        started: u64,
        target: ResizeTarget,
    ) -> Result<ResizeIntent> {
        if pid <= 0 {
            return Err(Error::agent("live resize", "invalid VMM process identity"));
        }
        self.with_durable_resize_write(|conn| {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)
                .db_err("begin resize intent")?;
            let exists: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM vms WHERE name = ?1)",
                params![name], |row| row.get(0)).db_err("check resize machine")?;
            if !exists {
                return Err(Error::vm_not_found(name));
            }
            let bytes: Option<Vec<u8>> = tx.query_row(
                "SELECT data FROM vm_resize_intents WHERE name = ?1", params![name], |row| row.get(0))
                .optional().db_err("read resize intent")?;
            let intent = if let Some(bytes) = bytes {
                let intent: ResizeIntent = serde_json::from_slice(&bytes).db_err("decode resize intent")?;
                if intent.pid != pid || intent.started != started || intent.target != target {
                    return Err(Error::agent_conflict("live resize",
                        "an unfinished resize belongs to a different target or VM incarnation; reconcile it before another resize"));
                }
                intent
            } else {
                let intent = ResizeIntent { token: Self::create_reservation_token(), pid, started, target };
                tx.execute("INSERT INTO vm_resize_intents (name, data) VALUES (?1, ?2)",
                    params![name, serde_json::to_vec(&intent).db_err("encode resize intent")?])
                    .db_err("save resize intent")?;
                intent
            };
            tx.commit().db_err("commit resize intent")?;
            Ok(intent)
        })
    }

    /// Clear only the operation we verified. A stale completion must never
    /// erase a newer operation, even if the machine name has been reused.
    pub(crate) fn finish_resize(&self, name: &str, expected: &ResizeIntent) -> Result<()> {
        self.with_durable_resize_write(|conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .db_err("begin resize completion")?;
            let bytes: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT data FROM vm_resize_intents WHERE name = ?1",
                    params![name],
                    |row| row.get(0),
                )
                .optional()
                .db_err("read resize completion")?;
            let actual: ResizeIntent = serde_json::from_slice(&bytes.ok_or_else(|| {
                Error::agent_conflict("live resize", "resize intent disappeared before completion")
            })?)
            .db_err("decode resize completion")?;
            if actual != *expected {
                return Err(Error::agent_conflict(
                    "live resize",
                    "resize ownership changed before completion",
                ));
            }
            tx.execute(
                "DELETE FROM vm_resize_intents WHERE name = ?1",
                params![name],
            )
            .db_err("finish resize intent")?;
            tx.commit().db_err("commit resize completion")?;
            Ok(())
        })
    }

    // NORMAL WAL commits survive process crashes but need not survive a power
    // loss. The intent and completion boundaries require FULL durability.
    // The writer mutex prevents another operation sharing this connection
    // while its synchronous policy is changed.
    fn with_durable_resize_write<T>(
        &self,
        operation: impl FnOnce(&mut Connection) -> Result<T>,
    ) -> Result<T> {
        self.with_conn(|conn| {
            conn.pragma_update(None, "synchronous", "FULL")
                .db_err("enable durable resize commit")?;
            let result = operation(conn);
            let reset = conn
                .pragma_update(None, "synchronous", "NORMAL")
                .db_err("restore database sync policy");
            match result {
                Err(error) => Err(error),
                Ok(value) => {
                    reset?;
                    Ok(value)
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (tempfile::TempDir, SmolvmDb) {
        let dir = tempfile::tempdir().unwrap();
        let db = SmolvmDb::open_at(&dir.path().join("state.db")).unwrap();
        db.insert_vm(
            "vm",
            &VmRecord::new("vm".into(), 2, 1024, vec![], vec![], false),
        )
        .unwrap();
        (dir, db)
    }

    #[test]
    fn intent_survives_reopen_and_only_identical_retry_can_resume() {
        let (dir, db) = setup();
        let intent = db
            .begin_resize("vm", 123, 45, ResizeTarget::Memory(1280))
            .unwrap();
        assert_eq!(db.pending_resize_names().unwrap(), vec!["vm"]);
        assert_eq!(db.pending_resize("vm").unwrap(), Some(intent.clone()));
        assert!(db.require_completed_resize("vm").is_err());
        drop(db);
        let db = SmolvmDb::open_at(&dir.path().join("state.db")).unwrap();
        assert_eq!(
            db.begin_resize("vm", 123, 45, ResizeTarget::Memory(1280))
                .unwrap(),
            intent
        );
        for (pid, started, target) in [
            (124, 45, ResizeTarget::Memory(1280)),
            (123, 46, ResizeTarget::Memory(1280)),
            (123, 45, ResizeTarget::Memory(1536)),
            (123, 45, ResizeTarget::Cpus(4)),
        ] {
            assert!(db.begin_resize("vm", pid, started, target).is_err());
        }
        let mut wrong = intent.clone();
        wrong.token.push('x');
        assert!(db.finish_resize("vm", &wrong).is_err());
        db.finish_resize("vm", &intent).unwrap();
        assert!(db.pending_resize_names().unwrap().is_empty());
        assert!(db.pending_resize("vm").unwrap().is_none());
        db.require_completed_resize("vm").unwrap();
        let next = db
            .begin_resize("vm", 123, 45, ResizeTarget::Cpus(4))
            .unwrap();
        assert!(db.finish_resize("vm", &intent).is_err());
        db.finish_resize("vm", &next).unwrap();
    }

    #[test]
    fn concurrent_connections_share_one_intent() {
        let (dir, _db) = setup();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let threads: Vec<_> = (0..2)
            .map(|_| {
                let path = dir.path().join("state.db");
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let db = SmolvmDb::open_at(&path).unwrap();
                    barrier.wait();
                    db.begin_resize("vm", 123, 45, ResizeTarget::Cpus(4))
                        .unwrap()
                })
            })
            .collect();
        let results: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        assert_eq!(results[0], results[1]);
    }

    #[test]
    fn removal_clears_intent_without_allowing_stale_completion() {
        let (_dir, db) = setup();
        let intent = db
            .begin_resize("vm", 123, 45, ResizeTarget::Cpus(4))
            .unwrap();
        db.remove_vm("vm").unwrap();
        assert!(db
            .begin_resize("vm", 123, 45, ResizeTarget::Cpus(4))
            .is_err());
        db.insert_vm(
            "vm",
            &VmRecord::new("vm".into(), 2, 1024, vec![], vec![], false),
        )
        .unwrap();
        let replacement = db
            .begin_resize("vm", 124, 46, ResizeTarget::Cpus(4))
            .unwrap();
        assert!(db.finish_resize("vm", &intent).is_err());
        db.finish_resize("vm", &replacement).unwrap();
    }

    #[test]
    fn journal_uses_full_durability_and_restores_policy_on_error() {
        let (_dir, db) = setup();
        let result: Result<()> = db.with_durable_resize_write(|conn| {
            let mode: i64 = conn
                .pragma_query_value(None, "synchronous", |row| row.get(0))
                .unwrap();
            assert_eq!(mode, 2);
            Err(Error::agent("test", "injected failure"))
        });
        assert!(result.is_err());
        db.with_conn(|conn| {
            let mode: i64 = conn
                .pragma_query_value(None, "synchronous", |row| row.get(0))
                .unwrap();
            assert_eq!(mode, 1);
            Ok(())
        })
        .unwrap();
    }
}
