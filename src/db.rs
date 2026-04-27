//! Database module for persistent state storage.
//!
//! Provides ACID-compliant storage using SQLite for VM state persistence
//! with atomic transactions and concurrent access safety.
//!
//! The connection handle is cached for the lifetime of the `SmolvmDb`
//! instance, amortising connection open cost across all operations.
//!
//! SQLite is configured in WAL mode with a 5s busy_timeout, so concurrent
//! CLI invocations share the database file without manual retry logic.

use crate::config::VmRecord;
use crate::error::{Error, Result};
use parking_lot::Mutex;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// SQLite busy_timeout: how long a blocked writer waits for the write lock
/// before returning SQLITE_BUSY. Replaces the per-process retry/backoff used
/// with redb's exclusive file lock.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Extension trait to convert errors into `Error::database`.
trait DbResultExt<T> {
    fn db_err(self, operation: impl Into<String>) -> Result<T>;
}

impl<T, E: std::fmt::Display> DbResultExt<T> for std::result::Result<T, E> {
    fn db_err(self, operation: impl Into<String>) -> Result<T> {
        self.map_err(|e| Error::database(operation, e.to_string()))
    }
}

/// Thread-safe database handle for smolvm state persistence.
///
/// The SQLite `Connection` is opened lazily on first use and cached for the
/// lifetime of the `SmolvmDb` instance. The Mutex serialises access within
/// the process; cross-process concurrency is handled by SQLite's WAL mode
/// and busy_timeout.
#[derive(Clone)]
pub struct SmolvmDb {
    path: PathBuf,
    handle: Arc<Mutex<Option<Connection>>>,
}

impl std::fmt::Debug for SmolvmDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmolvmDb")
            .field("path", &self.path)
            .field("open", &self.handle.lock().is_some())
            .finish()
    }
}

impl SmolvmDb {
    /// Run a closure with the cached connection, opening it on first use.
    fn with_conn<T, F>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&mut Connection) -> Result<T>,
    {
        let mut guard = self.handle.lock();
        if guard.is_none() {
            *guard = Some(Self::open_connection(&self.path)?);
        }
        f(guard.as_mut().unwrap())
    }

    /// Open the SQLite connection, configure pragmas, and ensure tables exist.
    fn open_connection(path: &Path) -> Result<Connection> {
        let conn = Connection::open(path)
            .map_err(|e| Error::database_unavailable(format!("open database: {}", e)))?;

        // WAL lets readers and writers overlap across processes; synchronous=NORMAL
        // is safe under WAL and significantly faster than the default FULL.
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
            .db_err("configure pragmas")?;
        conn.busy_timeout(BUSY_TIMEOUT).db_err("set busy_timeout")?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS vms (
                 name TEXT PRIMARY KEY NOT NULL,
                 data BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS config (
                 key TEXT PRIMARY KEY NOT NULL,
                 value TEXT NOT NULL
             );",
        )
        .db_err("create tables")?;

        Ok(conn)
    }

    /// Open the database at the default location.
    ///
    /// Default path: `~/Library/Application Support/smolvm/server/smolvm.db` (macOS)
    /// or `~/.local/share/smolvm/server/smolvm.db` (Linux)
    ///
    /// If the database doesn't exist, it will be created.
    pub fn open() -> Result<Self> {
        let path = Self::default_path()?;
        Self::open_at(&path)
    }

    /// Open the database at a specific path. Parent directories are created
    /// if missing; the connection itself is opened lazily on first use.
    pub fn open_at(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).db_err("create directory")?;
        }

        Ok(Self {
            path: path.to_path_buf(),
            handle: Arc::new(Mutex::new(None)),
        })
    }

    /// Get the default database path.
    pub fn default_path() -> Result<PathBuf> {
        let data_dir = dirs::data_local_dir().ok_or_else(|| {
            Error::database_unavailable("could not determine local data directory")
        })?;
        Ok(data_dir.join("smolvm").join("server").join("smolvm.db"))
    }

    /// Initialize database tables.
    ///
    /// Tables are created automatically when the connection opens, so this
    /// just forces the connection open. Retained for API compatibility.
    pub fn init_tables(&self) -> Result<()> {
        self.with_conn(|_| Ok(()))
    }

    // ========================================================================
    // VM Operations
    // ========================================================================

    /// Insert or update a VM record.
    pub fn insert_vm(&self, name: &str, record: &VmRecord) -> Result<()> {
        let json = serde_json::to_vec(record).db_err("serialize vm record")?;
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO vms (name, data) VALUES (?1, ?2)
                 ON CONFLICT(name) DO UPDATE SET data = excluded.data",
                params![name, json],
            )
            .db_err(format!("insert vm '{}'", name))?;
            Ok(())
        })
    }

    /// Insert a VM record only if it doesn't already exist.
    ///
    /// Returns `Ok(true)` if inserted, `Ok(false)` if the name already exists.
    /// Atomicity is provided by SQLite's `INSERT OR IGNORE`.
    pub fn insert_vm_if_not_exists(&self, name: &str, record: &VmRecord) -> Result<bool> {
        let json = serde_json::to_vec(record).db_err("serialize vm record")?;
        self.with_conn(|conn| {
            let changed = conn
                .execute(
                    "INSERT OR IGNORE INTO vms (name, data) VALUES (?1, ?2)",
                    params![name, json],
                )
                .db_err(format!("insert vm '{}'", name))?;
            Ok(changed == 1)
        })
    }

    /// Get a VM record by name.
    pub fn get_vm(&self, name: &str) -> Result<Option<VmRecord>> {
        self.with_conn(|conn| {
            let data: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT data FROM vms WHERE name = ?1",
                    params![name],
                    |row| row.get(0),
                )
                .optional()
                .db_err(format!("get vm '{}'", name))?;

            match data {
                Some(bytes) => {
                    let record: VmRecord = serde_json::from_slice(&bytes)
                        .db_err(format!("deserialize vm record '{}'", name))?;
                    Ok(Some(record))
                }
                None => Ok(None),
            }
        })
    }

    /// Remove a VM record by name, returning the removed record if it existed.
    ///
    /// Read + delete happen in a single transaction to prevent TOCTOU races.
    pub fn remove_vm(&self, name: &str) -> Result<Option<VmRecord>> {
        self.with_conn(|conn| {
            let tx = conn.transaction().db_err("begin transaction")?;

            let data: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT data FROM vms WHERE name = ?1",
                    params![name],
                    |row| row.get(0),
                )
                .optional()
                .db_err(format!("get vm '{}'", name))?;

            let record = match data {
                Some(bytes) => {
                    let r: VmRecord = serde_json::from_slice(&bytes)
                        .db_err(format!("deserialize vm record '{}'", name))?;
                    tx.execute("DELETE FROM vms WHERE name = ?1", params![name])
                        .db_err(format!("remove vm '{}'", name))?;
                    Some(r)
                }
                None => None,
            };

            tx.commit().db_err("commit vm removal")?;
            Ok(record)
        })
    }

    /// List all VM records.
    pub fn list_vms(&self) -> Result<Vec<(String, VmRecord)>> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare_cached("SELECT name, data FROM vms")
                .db_err("prepare list_vms")?;
            let rows = stmt
                .query_map([], |row| {
                    let name: String = row.get(0)?;
                    let data: Vec<u8> = row.get(1)?;
                    Ok((name, data))
                })
                .db_err("query vms")?;

            let mut vms = Vec::new();
            for row in rows {
                let (name, data) = row.db_err("read vms row")?;
                let record: VmRecord = serde_json::from_slice(&data)
                    .db_err(format!("deserialize vm record '{}'", name))?;
                vms.push((name, record));
            }
            Ok(vms)
        })
    }

    /// Update a VM record in place using a closure.
    ///
    /// Returns the updated record if found, `None` if not found. Read +
    /// write happen in a single transaction to prevent lost updates.
    pub fn update_vm<F>(&self, name: &str, f: F) -> Result<Option<VmRecord>>
    where
        F: FnOnce(&mut VmRecord),
    {
        self.with_conn(|conn| {
            let tx = conn.transaction().db_err("begin transaction")?;

            let data: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT data FROM vms WHERE name = ?1",
                    params![name],
                    |row| row.get(0),
                )
                .optional()
                .db_err(format!("get vm '{}'", name))?;

            let updated = match data {
                Some(bytes) => {
                    let mut record: VmRecord = serde_json::from_slice(&bytes)
                        .db_err(format!("deserialize vm record '{}'", name))?;
                    f(&mut record);
                    let new_data = serde_json::to_vec(&record).db_err("serialize vm record")?;
                    tx.execute(
                        "UPDATE vms SET data = ?2 WHERE name = ?1",
                        params![name, new_data],
                    )
                    .db_err(format!("update vm '{}'", name))?;
                    Some(record)
                }
                None => None,
            };

            tx.commit().db_err("commit vm update")?;
            Ok(updated)
        })
    }

    // ========================================================================
    // Global Config Operations
    // ========================================================================

    /// Get a global configuration value.
    pub fn get_config(&self, key: &str) -> Result<Option<String>> {
        self.with_conn(|conn| {
            conn.query_row(
                "SELECT value FROM config WHERE key = ?1",
                params![key],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .db_err(format!("get config '{}'", key))
        })
    }

    /// Set a global configuration value.
    pub fn set_config(&self, key: &str, value: &str) -> Result<()> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO config (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, value],
            )
            .db_err(format!("set config '{}'", key))?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RecordState;
    use tempfile::TempDir;

    fn temp_db() -> (TempDir, SmolvmDb) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.db");
        let db = SmolvmDb::open_at(&path).unwrap();
        (dir, db)
    }

    #[test]
    fn test_db_crud_operations() {
        let (_dir, db) = temp_db();

        let record = VmRecord::new(
            "test-vm".to_string(),
            2,
            1024,
            vec![("/host".to_string(), "/guest".to_string(), false)],
            vec![(8080, 80)],
            false,
        );

        db.insert_vm("test-vm", &record).unwrap();

        let retrieved = db.get_vm("test-vm").unwrap().unwrap();
        assert_eq!(retrieved.name, "test-vm");
        assert_eq!(retrieved.cpus, 2);
        assert_eq!(retrieved.mem, 1024);

        let updated = db
            .update_vm("test-vm", |r| {
                r.state = RecordState::Running;
                r.pid = Some(12345);
            })
            .unwrap()
            .unwrap();
        assert_eq!(updated.state, RecordState::Running);
        assert_eq!(updated.pid, Some(12345));

        let vms = db.list_vms().unwrap();
        assert_eq!(vms.len(), 1);
        assert_eq!(vms[0].0, "test-vm");

        let removed = db.remove_vm("test-vm").unwrap().unwrap();
        assert_eq!(removed.name, "test-vm");

        assert!(db.get_vm("test-vm").unwrap().is_none());
    }

    #[test]
    fn test_db_concurrent_access() {
        let (_dir, db) = temp_db();

        let handles: Vec<_> = (0..10)
            .map(|i| {
                let db = db.clone();
                std::thread::spawn(move || {
                    let name = format!("vm-{}", i);
                    let record = VmRecord::new(name.clone(), 1, 512, vec![], vec![], false);
                    db.insert_vm(&name, &record).unwrap();
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        let vms = db.list_vms().unwrap();
        assert_eq!(vms.len(), 10);
    }

    #[test]
    fn test_config_settings() {
        let (_dir, db) = temp_db();

        db.set_config("test_key", "test_value").unwrap();

        let value = db.get_config("test_key").unwrap().unwrap();
        assert_eq!(value, "test_value");

        assert!(db.get_config("nonexistent").unwrap().is_none());
    }

    #[test]
    fn test_update_nonexistent_vm() {
        let (_dir, db) = temp_db();

        let result = db.update_vm("nonexistent", |_| {}).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_remove_nonexistent_vm() {
        let (_dir, db) = temp_db();

        let result = db.remove_vm("nonexistent").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_insert_vm_if_not_exists() {
        let (_dir, db) = temp_db();

        let record = VmRecord::new("test-vm".to_string(), 1, 512, vec![], vec![], false);

        let inserted = db.insert_vm_if_not_exists("test-vm", &record).unwrap();
        assert!(inserted, "first insert should succeed");

        let inserted = db.insert_vm_if_not_exists("test-vm", &record).unwrap();
        assert!(!inserted, "second insert should fail (already exists)");

        let vms = db.list_vms().unwrap();
        assert_eq!(vms.len(), 1);

        let record2 = VmRecord::new("test-vm2".to_string(), 2, 1024, vec![], vec![], false);
        let inserted = db.insert_vm_if_not_exists("test-vm2", &record2).unwrap();
        assert!(inserted, "different name should succeed");

        let vms = db.list_vms().unwrap();
        assert_eq!(vms.len(), 2);
    }

    #[test]
    fn test_insert_vm_if_not_exists_concurrent() {
        let (_dir, db) = temp_db();

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let db = db.clone();
                std::thread::spawn(move || {
                    let record =
                        VmRecord::new("contested-name".to_string(), 1, 512, vec![], vec![], false);
                    db.insert_vm_if_not_exists("contested-name", &record)
                        .unwrap()
                })
            })
            .collect();

        let results: Vec<bool> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        let success_count = results.iter().filter(|&&r| r).count();
        assert_eq!(success_count, 1, "exactly one insert should succeed");

        let vms = db.list_vms().unwrap();
        assert_eq!(vms.len(), 1);
    }
}
