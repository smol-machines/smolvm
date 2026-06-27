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
use parking_lot::{Condvar, Mutex};
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// SQLite busy_timeout: how long a blocked writer waits for the write lock
/// before returning SQLITE_BUSY. Set high enough to survive burst contention
/// from concurrent CLI processes (e.g., 10-20 VMs starting simultaneously).
const BUSY_TIMEOUT: Duration = Duration::from_secs(15);

/// Long enough for a legitimate slow create/extract, short enough that a
/// crashed creator does not reserve a name forever.
const CREATE_RESERVATION_TTL_SECS: u64 = 60 * 60;

/// Max SQLite connections held open by the pool. WAL allows these to read
/// concurrently (writes still serialize at the SQLite layer, gated by
/// `busy_timeout`), so a slow write can no longer block reads — the prior
/// single-`Mutex<Connection>` design serialized EVERY db call, which let a
/// stalled write park the async reactor and wedge the liveness probes
/// (see `tests/reactor_wedge.rs`). Sized to comfortably cover the API server's
/// concurrent handlers without holding a large fan of file descriptors.
const POOL_MAX_CONNS: usize = 8;

/// A small fixed-capacity pool of SQLite connections to the same database file.
///
/// Each connection is opened with the WAL pragmas + `busy_timeout`, so multiple
/// readers proceed in parallel and a writer only blocks other *writers*. A
/// connection is checked out for the duration of one `with_conn` closure and
/// returned on drop (discarded if the closure panicked, so a half-applied
/// statement can't be handed to the next caller). Checkout blocks only when all
/// `POOL_MAX_CONNS` are in use — never behind an unrelated read.
struct ConnPool {
    path: PathBuf,
    inner: Mutex<PoolInner>,
    available: Condvar,
}

struct PoolInner {
    /// Connections opened and not currently checked out.
    idle: Vec<Connection>,
    /// Total connections in existence (idle + checked out).
    open: usize,
}

impl ConnPool {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            inner: Mutex::new(PoolInner {
                idle: Vec::new(),
                open: 0,
            }),
            available: Condvar::new(),
        }
    }

    /// Take a connection, opening a new one (up to `POOL_MAX_CONNS`) or waiting
    /// for one to be returned. Opening happens outside the lock so a slow open
    /// never blocks other checkouts/checkins.
    fn checkout(&self) -> Result<Connection> {
        let mut inner = self.inner.lock();
        loop {
            if let Some(conn) = inner.idle.pop() {
                return Ok(conn);
            }
            if inner.open < POOL_MAX_CONNS {
                inner.open += 1;
                drop(inner);
                match SmolvmDb::open_connection(&self.path) {
                    Ok(conn) => return Ok(conn),
                    Err(e) => {
                        // Roll back the reservation and let a waiter retry.
                        self.inner.lock().open -= 1;
                        self.available.notify_one();
                        return Err(e);
                    }
                }
            }
            // Pool saturated: wait for a checkin.
            self.available.wait(&mut inner);
        }
    }

    fn checkin(&self, conn: Connection) {
        self.inner.lock().idle.push(conn);
        self.available.notify_one();
    }

    /// Drop a connection without returning it (used when its closure panicked,
    /// so its possibly-dirty state is not reused). Frees a slot for a new open.
    fn discard(&self) {
        self.inner.lock().open -= 1;
        self.available.notify_one();
    }
}

/// RAII guard returning a checked-out connection to the pool on drop.
struct PooledConn<'a> {
    pool: &'a ConnPool,
    conn: Option<Connection>,
}

impl Drop for PooledConn<'_> {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            if std::thread::panicking() {
                self.pool.discard();
            } else {
                self.pool.checkin(conn);
            }
        }
    }
}

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
/// Uses the standard WAL split: a single dedicated WRITER connection (behind a
/// mutex) serializes all mutations in-process — so they never contend at the
/// SQLite write-lock layer (no `SQLITE_BUSY` spinning) — while READS go through a
/// small pool of separate connections that run concurrently under WAL. A reader
/// therefore never waits on the writer, so a stalled write can no longer park the
/// async reactor that serves the liveness probes (the single-`Mutex<Connection>`
/// failure mode; see `tests/reactor_wedge.rs`). Connections open lazily.
/// Cross-process concurrency is still handled by WAL + busy_timeout.
#[derive(Clone)]
pub struct SmolvmDb {
    path: PathBuf,
    /// Single connection serializing writes (and the rare read that must observe
    /// its own just-committed write on the same connection). Opened on first use.
    writer: Arc<Mutex<Option<Connection>>>,
    /// Pool of connections for concurrent reads. Never used for writes.
    readers: Arc<ConnPool>,
}

impl std::fmt::Debug for SmolvmDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmolvmDb")
            .field("path", &self.path)
            .field("writer_open", &self.writer.lock().is_some())
            .field("reader_conns", &self.readers.inner.lock().open)
            .finish()
    }
}

impl SmolvmDb {
    /// Run a closure with the single writer connection, opening it on first use.
    /// Serializes all writers in-process so they never collide at the SQLite
    /// write lock. Use for every mutation (and any read that must see a write it
    /// just made on this connection).
    fn with_conn<T, F>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&mut Connection) -> Result<T>,
    {
        let mut guard = self.writer.lock();
        if guard.is_none() {
            *guard = Some(Self::open_connection(&self.path)?);
        }
        f(guard.as_mut().expect("writer connection present"))
    }

    /// Run a closure with a pooled READ connection. Concurrent reads use
    /// different connections (up to `POOL_MAX_CONNS`) and, under WAL, never block
    /// on the writer — so a stalled write can't serialize or wedge reads. MUST
    /// NOT be used for writes (that would reintroduce SQLite write contention).
    fn with_read_conn<T, F>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&mut Connection) -> Result<T>,
    {
        let conn = self.readers.checkout()?;
        let mut guard = PooledConn {
            pool: &self.readers,
            conn: Some(conn),
        };
        f(guard.conn.as_mut().expect("reader connection present"))
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
             CREATE TABLE IF NOT EXISTS vm_create_reservations (
                 name TEXT PRIMARY KEY NOT NULL,
                 owner_token TEXT NOT NULL,
                 owner_pid INTEGER NOT NULL,
                 created_at INTEGER NOT NULL
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
            writer: Arc::new(Mutex::new(None)),
            readers: Arc::new(ConnPool::new(path.to_path_buf())),
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
    /// Atomicity is provided by SQLite's `INSERT OR IGNORE`. A name with an
    /// active create reservation is treated as already taken so older callers
    /// that have not been threaded through the reservation API cannot clobber a
    /// machine whose per-machine data directory is being prepared.
    pub fn insert_vm_if_not_exists(&self, name: &str, record: &VmRecord) -> Result<bool> {
        let json = serde_json::to_vec(record).db_err("serialize vm record")?;
        self.with_conn(|conn| {
            let changed = conn
                .execute(
                    "INSERT OR IGNORE INTO vms (name, data)
                     SELECT ?1, ?2
                     WHERE NOT EXISTS (
                         SELECT 1 FROM vm_create_reservations WHERE name = ?1
                     )",
                    params![name, json],
                )
                .db_err(format!("insert vm '{}'", name))?;
            Ok(changed == 1)
        })
    }

    /// Generate an opaque token identifying this process's create reservation.
    pub fn create_reservation_token() -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        format!(
            "{}-{}-{}",
            std::process::id(),
            crate::util::current_timestamp(),
            nanos
        )
    }

    /// Reserve a VM name across processes before touching its data directory.
    ///
    /// Returns `Ok(false)` when the VM already exists or another live creator
    /// owns the reservation. Dead/stale reservations are reaped before the
    /// insert attempt so a crashed creator does not permanently wedge a name.
    pub fn reserve_vm_create(&self, name: &str, owner_token: &str) -> Result<bool> {
        let owner_pid = i64::from(std::process::id());
        let now = crate::util::current_timestamp();
        let stale_before = now.saturating_sub(CREATE_RESERVATION_TTL_SECS);

        self.with_conn(|conn| {
            let tx = conn.transaction().db_err("begin create reservation")?;

            if let Some((existing_pid, created_at)) = tx
                .query_row(
                    "SELECT owner_pid, created_at
                     FROM vm_create_reservations
                     WHERE name = ?1",
                    params![name],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, u64>(1)?)),
                )
                .optional()
                .db_err(format!("read create reservation '{}'", name))?
            {
                let pid_alive =
                    existing_pid > 0 && crate::process::is_alive(existing_pid as libc::pid_t);
                if !pid_alive || created_at <= stale_before {
                    tx.execute(
                        "DELETE FROM vm_create_reservations WHERE name = ?1",
                        params![name],
                    )
                    .db_err(format!("remove stale create reservation '{}'", name))?;
                }
            }

            let exists: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM vms WHERE name = ?1)",
                    params![name],
                    |row| row.get(0),
                )
                .db_err(format!("check vm '{}'", name))?;
            if exists {
                tx.commit().db_err("commit create reservation check")?;
                return Ok(false);
            }

            let changed = tx
                .execute(
                    "INSERT OR IGNORE INTO vm_create_reservations
                     (name, owner_token, owner_pid, created_at)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![name, owner_token, owner_pid, now],
                )
                .db_err(format!("reserve vm '{}'", name))?;

            tx.commit().db_err("commit create reservation")?;
            Ok(changed == 1)
        })
    }

    /// Persist a VM record and release the matching create reservation atomically.
    ///
    /// Returns `Ok(false)` if the caller does not own the reservation or if the
    /// VM row already exists.
    pub fn commit_reserved_vm(
        &self,
        name: &str,
        owner_token: &str,
        record: &VmRecord,
    ) -> Result<bool> {
        let json = serde_json::to_vec(record).db_err("serialize vm record")?;
        self.with_conn(|conn| {
            let tx = conn.transaction().db_err("begin reserved vm commit")?;

            let owns_reservation: bool = tx
                .query_row(
                    "SELECT EXISTS(
                         SELECT 1 FROM vm_create_reservations
                         WHERE name = ?1 AND owner_token = ?2
                     )",
                    params![name, owner_token],
                    |row| row.get(0),
                )
                .db_err(format!("check create reservation '{}'", name))?;
            if !owns_reservation {
                tx.commit().db_err("commit reservation ownership check")?;
                return Ok(false);
            }

            let changed = tx
                .execute(
                    "INSERT OR IGNORE INTO vms (name, data) VALUES (?1, ?2)",
                    params![name, json],
                )
                .db_err(format!("insert reserved vm '{}'", name))?;

            tx.execute(
                "DELETE FROM vm_create_reservations
                 WHERE name = ?1 AND owner_token = ?2",
                params![name, owner_token],
            )
            .db_err(format!("release create reservation '{}'", name))?;

            tx.commit().db_err("commit reserved vm")?;
            Ok(changed == 1)
        })
    }

    /// Release a create reservation if it is still owned by `owner_token`.
    pub fn release_vm_create_reservation(&self, name: &str, owner_token: &str) -> Result<()> {
        self.with_conn(|conn| {
            conn.execute(
                "DELETE FROM vm_create_reservations
                 WHERE name = ?1 AND owner_token = ?2",
                params![name, owner_token],
            )
            .db_err(format!("release create reservation '{}'", name))?;
            Ok(())
        })
    }

    /// Get a VM record by name.
    pub fn get_vm(&self, name: &str) -> Result<Option<VmRecord>> {
        self.with_read_conn(|conn| {
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
        self.with_read_conn(|conn| {
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

    /// Names of VMs forked from `golden`. Their block disks are copy-on-write
    /// overlays backed by the golden's disks, so the golden must outlive them
    /// and must not be re-run with writable disks while they exist.
    pub fn dependent_clones(&self, golden: &str) -> Result<Vec<String>> {
        Ok(self
            .list_vms()?
            .into_iter()
            .filter(|(_, r)| r.golden.as_deref() == Some(golden))
            .map(|(name, _)| name)
            .collect())
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

    /// Load all VMs into an in-memory HashMap (for compatibility layer).
    pub fn load_all_vms(&self) -> Result<HashMap<String, VmRecord>> {
        let vms = self.list_vms()?;
        Ok(vms.into_iter().collect())
    }

    /// Load all config settings and VM records in a single transaction.
    pub fn load_all(&self) -> Result<(HashMap<String, String>, HashMap<String, VmRecord>)> {
        self.with_conn(|conn| {
            let tx = conn.transaction().db_err("begin read transaction")?;

            let mut config = HashMap::new();
            {
                let mut stmt = tx
                    .prepare_cached("SELECT key, value FROM config")
                    .db_err("prepare list config")?;
                let rows = stmt
                    .query_map([], |row| {
                        let k: String = row.get(0)?;
                        let v: String = row.get(1)?;
                        Ok((k, v))
                    })
                    .db_err("query config")?;
                for row in rows {
                    let (k, v) = row.db_err("read config row")?;
                    config.insert(k, v);
                }
            }

            let mut vms = HashMap::new();
            {
                let mut stmt = tx
                    .prepare_cached("SELECT name, data FROM vms")
                    .db_err("prepare list vms")?;
                let rows = stmt
                    .query_map([], |row| {
                        let name: String = row.get(0)?;
                        let data: Vec<u8> = row.get(1)?;
                        Ok((name, data))
                    })
                    .db_err("query vms")?;
                for row in rows {
                    let (name, data) = row.db_err("read vms row")?;
                    let record: VmRecord = serde_json::from_slice(&data)
                        .db_err(format!("deserialize vm record '{}'", name))?;
                    vms.insert(name, record);
                }
            }

            tx.commit().db_err("commit read transaction")?;
            Ok((config, vms))
        })
    }

    /// Save multiple config key-value pairs in a single transaction.
    pub fn save_config(&self, settings: &[(&str, &str)]) -> Result<()> {
        self.with_conn(|conn| {
            let tx = conn.transaction().db_err("begin transaction")?;
            {
                let mut stmt = tx
                    .prepare_cached(
                        "INSERT INTO config (key, value) VALUES (?1, ?2)
                         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    )
                    .db_err("prepare set config")?;
                for (k, v) in settings {
                    stmt.execute(params![k, v])
                        .db_err(format!("set config '{}'", k))?;
                }
            }
            tx.commit().db_err("commit config save")?;
            Ok(())
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

    /// A read must not block behind a stalled write. Before the connection pool,
    /// every db call shared one `Mutex<Connection>`, so a write stalled on
    /// SQLite's `busy_timeout` held that mutex and serialized ALL reads behind
    /// it — the serialization that let a stalled write park the async reactor and
    /// wedge the liveness probes in production (see `tests/reactor_wedge.rs`).
    /// With the pool the read uses a different WAL connection and returns at once.
    /// Pre-pool this asserts in ~15s (busy_timeout) and fails; post-pool ~ms.
    #[test]
    fn read_does_not_block_behind_a_stalled_write() {
        let (dir, db) = temp_db();
        let path = dir.path().join("test.db");
        db.insert_vm(
            "m0",
            &VmRecord::new("m0".to_string(), 1, 256, vec![], vec![], false),
        )
        .unwrap();

        // Warm the pool to 2 idle connections so the read below reuses one rather
        // than opening a fresh connection while the external write lock is held.
        std::thread::scope(|s| {
            for _ in 0..2 {
                s.spawn(|| {
                    let _ = db.get_vm("m0");
                    std::thread::sleep(Duration::from_millis(60));
                });
            }
        });

        // A second connection to the same file holds the SQLite write lock —
        // exactly what concurrent cross-process create-reservations do under churn.
        let blocker = Connection::open(&path).unwrap();
        blocker.busy_timeout(Duration::from_secs(30)).unwrap();
        blocker.execute_batch("BEGIN IMMEDIATE").unwrap();

        // A SmolvmDb write now stalls on busy_timeout, holding one pooled connection.
        let db_w = db.clone();
        let writer = std::thread::spawn(move || {
            let _ = db_w.insert_vm(
                "m1",
                &VmRecord::new("m1".to_string(), 1, 256, vec![], vec![], false),
            );
        });
        std::thread::sleep(Duration::from_millis(300)); // let the write grab a conn + stall

        // Concurrent read on a DIFFERENT pooled connection (WAL): must be immediate.
        let start = std::time::Instant::now();
        let got = db.get_vm("m0").unwrap();
        let elapsed = start.elapsed();
        assert!(got.is_some(), "read returned no record");
        assert!(
            elapsed < Duration::from_secs(2),
            "read blocked {elapsed:?} behind a stalled write — the pool is not isolating reads from writes"
        );

        blocker.execute_batch("COMMIT").ok();
        let _ = writer.join();
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
    fn test_create_reservation_blocks_unreserved_insert() {
        let (_dir, db) = temp_db();
        let token = SmolvmDb::create_reservation_token();
        let record = VmRecord::new("reserved-vm".to_string(), 1, 512, vec![], vec![], false);

        assert!(db.reserve_vm_create("reserved-vm", &token).unwrap());
        assert!(
            !db.insert_vm_if_not_exists("reserved-vm", &record).unwrap(),
            "legacy unreserved insert must not publish a reserved name"
        );
        assert!(
            db.get_vm("reserved-vm").unwrap().is_none(),
            "reservation must not create a visible VM row"
        );

        assert!(db
            .commit_reserved_vm("reserved-vm", &token, &record)
            .unwrap());
        assert!(db.get_vm("reserved-vm").unwrap().is_some());
    }

    #[test]
    fn test_create_reservation_is_exclusive_and_releasable() {
        let (_dir, db) = temp_db();
        let first = SmolvmDb::create_reservation_token();
        let second = SmolvmDb::create_reservation_token();

        assert!(db.reserve_vm_create("contested", &first).unwrap());
        assert!(
            !db.reserve_vm_create("contested", &second).unwrap(),
            "second live creator must not reserve the same name"
        );

        db.release_vm_create_reservation("contested", &first)
            .unwrap();
        assert!(
            db.reserve_vm_create("contested", &second).unwrap(),
            "released reservation should make the name available"
        );
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
