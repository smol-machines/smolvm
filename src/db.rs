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
use crate::pool::{
    ClaimForkPoolSlot, ForkLeaseRecord, ForkLeaseState, ForkPoolAdmissionLimit, ForkPoolRecord,
    ForkPoolSlotRecord, ForkPoolSlotState,
};
use parking_lot::{Condvar, Mutex};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::collections::{HashMap, HashSet};
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

/// Inputs committed together when one ready fork-pool worker is claimed.
pub struct ForkPoolSlotClaim<'a> {
    /// Pool that owns the ready worker.
    pub pool_name: &'a str,
    /// New opaque lease identifier.
    pub lease_id: &'a str,
    /// Caller-provided retry key, unique within the pool.
    pub idempotency_key: &'a str,
    /// Environment installed before the held workload is released.
    pub assignment: &'a [(String, String)],
    /// Canonical digest of any files staged before release.
    pub payload_sha256: Option<&'a str>,
    /// Reject workers whose `/workspace` is backed by an external mount.
    pub require_private_workspace: bool,
    /// Runtime-calibrated active-lease ceiling, applied with the durable limit.
    pub admission_limit: Option<ForkPoolAdmissionLimit>,
    /// Lease lifetime renewed by each heartbeat.
    pub ttl_secs: u64,
    /// Timestamp used for every record in this transaction.
    pub now: u64,
}

fn targets_workspace_tree(target: &str) -> bool {
    let mut components = Vec::new();
    for component in target.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            value => components.push(value),
        }
    }
    components.first() == Some(&"workspace")
}

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
/// Each connection is opened read-only at the SQL layer with `busy_timeout`, so
/// multiple readers proceed in parallel and a writer only blocks other *writers*. A
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
                match SmolvmDb::open_reader_connection(&self.path) {
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
/// failure mode; see `tests/reactor_wedge.rs`). The writer opens eagerly so WAL
/// and schema initialization finish before read connections can fan out.
/// Cross-process concurrency is still handled by WAL + busy_timeout.
#[derive(Clone)]
pub struct SmolvmDb {
    path: PathBuf,
    /// Single connection serializing writes (and the rare read that must observe
    /// its own just-committed write on the same connection). Opened eagerly so
    /// WAL and schema initialization precede concurrent reads.
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
    /// Run a closure with the single writer connection, reopening it if needed.
    /// Serializes all writers in-process so they never collide at the SQLite
    /// write lock. Use for every mutation (and any read that must see a write it
    /// just made on this connection).
    fn with_conn<T, F>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&mut Connection) -> Result<T>,
    {
        let mut guard = self.writer.lock();
        if guard.is_none() {
            *guard = Some(Self::open_writer_connection(&self.path)?);
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

    /// Open the serialized writer, configure WAL, and ensure tables exist.
    fn open_writer_connection(path: &Path) -> Result<Connection> {
        let conn = Connection::open(path)
            .map_err(|e| Error::database_unavailable(format!("open database: {}", e)))?;

        // Install the busy handler before any pragma or schema statement that
        // may need SQLite's write lock. Reader connections open lazily and can
        // arrive as a burst, so setting this after `journal_mode=WAL` allowed
        // first-use concurrency to fail immediately with SQLITE_BUSY.
        conn.busy_timeout(BUSY_TIMEOUT).db_err("set busy_timeout")?;
        // WAL lets readers and writers overlap across processes; synchronous=NORMAL
        // is safe under WAL and significantly faster than the default FULL.
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
            .db_err("configure pragmas")?;

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
             );
             CREATE TABLE IF NOT EXISTS fork_pools (
                 name TEXT PRIMARY KEY NOT NULL,
                 data BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS fork_pool_snapshots (
                 golden TEXT PRIMARY KEY NOT NULL,
                 data BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS fork_pool_slots (
                 machine_name TEXT PRIMARY KEY NOT NULL,
                 pool_name TEXT NOT NULL,
                 state TEXT NOT NULL,
                 data BLOB NOT NULL
             );
             CREATE INDEX IF NOT EXISTS fork_pool_slots_pool_state
                 ON fork_pool_slots(pool_name, state);
             CREATE TABLE IF NOT EXISTS fork_leases (
                 id TEXT PRIMARY KEY NOT NULL,
                 pool_name TEXT NOT NULL,
                 idempotency_key TEXT NOT NULL,
                 state TEXT NOT NULL,
                 data BLOB NOT NULL,
                 UNIQUE(pool_name, idempotency_key)
             );
             CREATE INDEX IF NOT EXISTS fork_leases_pool_state
                 ON fork_leases(pool_name, state);",
        )
        .db_err("create tables")?;

        Ok(conn)
    }

    /// Open one pooled reader after the eager writer initialized WAL and schema.
    fn open_reader_connection(path: &Path) -> Result<Connection> {
        let conn = Connection::open(path)
            .map_err(|e| Error::database_unavailable(format!("open database reader: {e}")))?;
        conn.busy_timeout(BUSY_TIMEOUT)
            .db_err("set reader busy_timeout")?;
        // Reader setup must not repeat journal-mode or schema writes. Bursts of
        // first-use reads otherwise race each other before the pool has idle
        // connections to reuse. query_only also enforces the pool contract.
        conn.execute_batch("PRAGMA query_only=ON; PRAGMA synchronous=NORMAL;")
            .db_err("configure reader pragmas")?;
        Ok(conn)
    }

    /// Open the database at the default location.
    ///
    /// Default path: `~/Library/Application Support/smolvm/server/smolvm.db` (macOS)
    /// or `~/.local/share/smolvm/server/smolvm.db` (Linux)
    ///
    /// If the database doesn't exist, it will be created and initialized.
    pub fn open() -> Result<Self> {
        let path = Self::default_path()?;
        Self::open_at(&path)
    }

    /// Open the database at a specific path. Parent directories are created if
    /// missing; WAL and tables are initialized before this returns.
    pub fn open_at(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).db_err("create directory")?;
        }

        let writer = Self::open_writer_connection(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            writer: Arc::new(Mutex::new(Some(writer))),
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
    /// Tables are initialized eagerly by `open_at`; retained for API compatibility.
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
                let pid_alive = existing_pid > 0
                    && crate::process::is_alive(existing_pid as crate::process::Pid);
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
            // Reserve the writer before reading. A deferred transaction can
            // observe a record, lose a cross-process writer race, and fail its
            // DELETE upgrade with SQLITE_BUSY_SNAPSHOT — which surfaced when
            // NeMo Gym closed 100 fork leaves concurrently. `busy_timeout`
            // cannot repair a stale snapshot; IMMEDIATE prevents one.
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .db_err("begin vm removal")?;

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
                    // A retained checkpoint only means anything while its golden
                    // process is alive, so it dies with the record rather than
                    // waiting for a sweep that only the pool controller runs.
                    tx.execute(
                        "DELETE FROM fork_pool_snapshots WHERE golden = ?1",
                        params![name],
                    )
                    .db_err(format!("remove retained fork snapshot for '{}'", name))?;
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

    /// All descendants of `source`, ordered deepest-first so each machine can
    /// be deleted before the disk backing it depends on. Rejects a corrupted
    /// cyclic lineage instead of recursing forever or deleting an ancestor
    /// before its child.
    pub fn dependent_descendants_postorder(&self, source: &str) -> Result<Vec<String>> {
        let mut children: HashMap<String, Vec<String>> = HashMap::new();
        for (name, record) in self.list_vms()? {
            if let Some(parent) = record.golden {
                children.entry(parent).or_default().push(name);
            }
        }
        for names in children.values_mut() {
            names.sort();
        }

        fn visit(
            parent: &str,
            children: &HashMap<String, Vec<String>>,
            visiting: &mut HashSet<String>,
            visited: &mut HashSet<String>,
            ordered: &mut Vec<String>,
        ) -> Result<()> {
            if !visiting.insert(parent.to_string()) {
                return Err(Error::database(
                    "resolve fork lineage",
                    format!("cycle detected at machine '{parent}'"),
                ));
            }
            if let Some(direct) = children.get(parent) {
                for child in direct {
                    if !visited.contains(child) {
                        visit(child, children, visiting, visited, ordered)?;
                        visited.insert(child.clone());
                        ordered.push(child.clone());
                    }
                }
            }
            visiting.remove(parent);
            Ok(())
        }

        let mut ordered = Vec::new();
        visit(
            source,
            &children,
            &mut HashSet::new(),
            &mut HashSet::new(),
            &mut ordered,
        )?;
        Ok(ordered)
    }

    /// Number of fork edges from a root machine to `name`.
    pub fn fork_lineage_depth(&self, name: &str) -> Result<usize> {
        let records: HashMap<String, VmRecord> = self.list_vms()?.into_iter().collect();
        let mut current = name;
        let mut seen = HashSet::new();
        let mut depth = 0;
        while let Some(parent) = records
            .get(current)
            .and_then(|record| record.golden.as_ref())
        {
            if !seen.insert(current.to_string()) {
                return Err(Error::database(
                    "resolve fork lineage",
                    format!("cycle detected at machine '{current}'"),
                ));
            }
            if !records.contains_key(parent) {
                return Err(Error::database(
                    "resolve fork lineage",
                    format!("machine '{current}' references missing parent '{parent}'"),
                ));
            }
            depth += 1;
            current = parent;
        }
        Ok(depth)
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
            // Reserve the writer before reading. A deferred transaction can
            // fail with SQLITE_BUSY_SNAPSHOT when it upgrades to a write.
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .db_err("begin transaction")?;

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
    // Automatic fork-pool operations
    // ========================================================================

    /// Create a fork pool if its name is unused.
    pub fn insert_fork_pool_if_not_exists(&self, pool: &ForkPoolRecord) -> Result<bool> {
        let data = serde_json::to_vec(pool).db_err("serialize fork pool")?;
        self.with_conn(|conn| {
            let changed = conn
                .execute(
                    "INSERT OR IGNORE INTO fork_pools (name, data) VALUES (?1, ?2)",
                    params![pool.name, data],
                )
                .db_err(format!("insert fork pool '{}'", pool.name))?;
            Ok(changed == 1)
        })
    }

    /// Read one fork pool.
    pub fn get_fork_pool(&self, name: &str) -> Result<Option<ForkPoolRecord>> {
        self.with_read_conn(|conn| {
            let data: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT data FROM fork_pools WHERE name = ?1",
                    params![name],
                    |row| row.get(0),
                )
                .optional()
                .db_err(format!("get fork pool '{name}'"))?;
            data.map(|bytes| serde_json::from_slice(&bytes).db_err("deserialize fork pool"))
                .transpose()
        })
    }

    /// List all fork pools.
    pub fn list_fork_pools(&self) -> Result<Vec<ForkPoolRecord>> {
        self.with_read_conn(|conn| {
            let mut stmt = conn
                .prepare_cached("SELECT data FROM fork_pools ORDER BY name")
                .db_err("prepare list fork pools")?;
            let rows = stmt
                .query_map([], |row| row.get::<_, Vec<u8>>(0))
                .db_err("query fork pools")?;
            let mut pools = Vec::new();
            for row in rows {
                let bytes = row.db_err("read fork pool row")?;
                pools.push(serde_json::from_slice(&bytes).db_err("deserialize fork pool")?);
            }
            Ok(pools)
        })
    }

    /// Durably publish the RAM checkpoint every later fork of this golden reuses.
    ///
    /// The `fork_pool_snapshots` table predates plain forks using this and keeps
    /// its name so no migration is needed; it is not pool-specific.
    pub(crate) fn set_retained_fork_snapshot(
        &self,
        golden: &str,
        snapshot: &crate::agent::fork::RetainedForkSnapshot,
    ) -> Result<()> {
        let data = serde_json::to_vec(snapshot).db_err("serialize retained fork snapshot")?;
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO fork_pool_snapshots (golden, data) VALUES (?1, ?2)
                 ON CONFLICT(golden) DO UPDATE SET data = excluded.data",
                params![golden, data],
            )
            .db_err(format!("set retained fork snapshot for '{golden}'"))?;
            Ok(())
        })
    }

    /// Read one golden's retained checkpoint, if it still has one.
    pub(crate) fn retained_fork_snapshot(
        &self,
        golden: &str,
    ) -> Result<Option<crate::agent::fork::RetainedForkSnapshot>> {
        self.with_read_conn(|conn| {
            let data: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT data FROM fork_pool_snapshots WHERE golden = ?1",
                    params![golden],
                    |row| row.get(0),
                )
                .optional()
                .db_err(format!("get retained fork snapshot for '{golden}'"))?;
            match data {
                Some(bytes) => Ok(Some(
                    serde_json::from_slice(&bytes)
                        .db_err(format!("deserialize retained fork snapshot for '{golden}'"))?,
                )),
                None => Ok(None),
            }
        })
    }

    /// Load every retained checkpoint after a controller restart.
    pub(crate) fn list_retained_fork_snapshots(
        &self,
    ) -> Result<Vec<(String, crate::agent::fork::RetainedForkSnapshot)>> {
        self.with_read_conn(|conn| {
            let mut stmt = conn
                .prepare_cached("SELECT golden, data FROM fork_pool_snapshots ORDER BY golden")
                .db_err("prepare list retained fork snapshots")?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
                })
                .db_err("query retained fork snapshots")?;
            let mut snapshots = Vec::new();
            for row in rows {
                let (golden, data) = row.db_err("read retained fork snapshot row")?;
                let snapshot = serde_json::from_slice(&data)
                    .db_err(format!("deserialize retained fork snapshot for '{golden}'"))?;
                snapshots.push((golden, snapshot));
            }
            Ok(snapshots)
        })
    }

    /// Forget a checkpoint only after its golden is resumed or no clone can use it.
    pub(crate) fn remove_retained_fork_snapshot(&self, golden: &str) -> Result<bool> {
        self.with_conn(|conn| {
            let changed = conn
                .execute(
                    "DELETE FROM fork_pool_snapshots WHERE golden = ?1",
                    params![golden],
                )
                .db_err(format!("remove retained fork snapshot for '{golden}'"))?;
            Ok(changed == 1)
        })
    }

    /// Change a pool's ready target and retire surplus unclaimed workers.
    pub fn resize_fork_pool(
        &self,
        name: &str,
        desired_ready: u32,
        now: u64,
    ) -> Result<Option<ForkPoolRecord>> {
        self.with_conn(|conn| {
            let tx = conn.transaction().db_err("begin fork pool resize")?;
            let data: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT data FROM fork_pools WHERE name = ?1",
                    params![name],
                    |row| row.get(0),
                )
                .optional()
                .db_err(format!("get fork pool '{name}'"))?;
            let Some(data) = data else {
                tx.commit().db_err("commit missing fork pool resize")?;
                return Ok(None);
            };
            let mut pool: ForkPoolRecord =
                serde_json::from_slice(&data).db_err("deserialize fork pool")?;
            if pool.deleting {
                tx.commit().db_err("commit deleting fork pool resize")?;
                return Ok(Some(pool));
            }
            pool.desired_ready = desired_ready;
            let updated = serde_json::to_vec(&pool).db_err("serialize fork pool")?;
            tx.execute(
                "UPDATE fork_pools SET data = ?2 WHERE name = ?1",
                params![name, updated],
            )
            .db_err("update fork pool size")?;

            let available_rows: Vec<Vec<u8>> = {
                let mut stmt = tx
                    .prepare_cached(
                        "SELECT data FROM fork_pool_slots
                         WHERE pool_name = ?1 AND state IN ('provisioning', 'ready')
                         ORDER BY CASE state WHEN 'provisioning' THEN 0 ELSE 1 END, machine_name",
                    )
                    .db_err("prepare surplus fork slots")?;
                let rows = stmt
                    .query_map(params![name], |row| row.get(0))
                    .db_err("query surplus fork slots")?;
                let mut collected = Vec::new();
                for row in rows {
                    collected.push(row.db_err("read surplus fork slot")?);
                }
                collected
            };
            let surplus = available_rows.len().saturating_sub(desired_ready as usize);
            for slot_data in available_rows.into_iter().take(surplus) {
                let mut slot: ForkPoolSlotRecord =
                    serde_json::from_slice(&slot_data).db_err("deserialize surplus fork slot")?;
                slot.state = ForkPoolSlotState::Retiring;
                slot.updated_at = now;
                let slot_updated =
                    serde_json::to_vec(&slot).db_err("serialize surplus fork slot")?;
                tx.execute(
                    "UPDATE fork_pool_slots SET state = 'retiring', data = ?2
                     WHERE machine_name = ?1",
                    params![slot.machine_name, slot_updated],
                )
                .db_err("retire surplus fork slot")?;
            }
            tx.commit().db_err("commit fork pool resize")?;
            Ok(Some(pool))
        })
    }

    /// List every slot owned by a pool.
    pub fn list_fork_pool_slots(&self, pool_name: &str) -> Result<Vec<ForkPoolSlotRecord>> {
        self.with_read_conn(|conn| {
            let mut stmt = conn
                .prepare_cached(
                    "SELECT data FROM fork_pool_slots WHERE pool_name = ?1 ORDER BY machine_name",
                )
                .db_err("prepare list fork pool slots")?;
            let rows = stmt
                .query_map(params![pool_name], |row| row.get::<_, Vec<u8>>(0))
                .db_err(format!("query slots for fork pool '{pool_name}'"))?;
            let mut slots = Vec::new();
            for row in rows {
                let bytes = row.db_err("read fork pool slot row")?;
                slots.push(serde_json::from_slice(&bytes).db_err("deserialize fork pool slot")?);
            }
            Ok(slots)
        })
    }

    /// Read pool ownership for one machine, if it is controller-managed.
    pub fn get_fork_pool_slot(&self, machine_name: &str) -> Result<Option<ForkPoolSlotRecord>> {
        self.with_read_conn(|conn| {
            let data: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT data FROM fork_pool_slots WHERE machine_name = ?1",
                    params![machine_name],
                    |row| row.get(0),
                )
                .optional()
                .db_err(format!("get fork pool slot '{machine_name}'"))?;
            data.map(|bytes| serde_json::from_slice(&bytes).db_err("deserialize fork pool slot"))
                .transpose()
        })
    }

    /// Number of additional provisioning/ready slots needed for a pool target.
    pub fn fork_pool_ready_deficit(&self, pool_name: &str) -> Result<u32> {
        self.with_read_conn(|conn| {
            let data: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT data FROM fork_pools WHERE name = ?1",
                    params![pool_name],
                    |row| row.get(0),
                )
                .optional()
                .db_err(format!("get fork pool '{pool_name}'"))?;
            let Some(data) = data else {
                return Ok(0);
            };
            let pool: ForkPoolRecord =
                serde_json::from_slice(&data).db_err("deserialize fork pool")?;
            if pool.deleting {
                return Ok(0);
            }
            let activating: u32 = conn
                .query_row(
                    "SELECT COUNT(*) FROM fork_pool_slots
                     WHERE pool_name = ?1 AND state = 'activating'",
                    params![pool_name],
                    |row| row.get(0),
                )
                .db_err("count activating fork pool slots")?;
            if activating > 0 {
                return Ok(0);
            }
            let available: u32 = conn
                .query_row(
                    "SELECT COUNT(*) FROM fork_pool_slots
                     WHERE pool_name = ?1 AND state IN ('provisioning', 'ready')",
                    params![pool_name],
                    |row| row.get(0),
                )
                .db_err("count available fork pool slots")?;
            Ok(pool.desired_ready.saturating_sub(available))
        })
    }

    /// Return the active/activating lease count and cumulative successful
    /// completions used by the runtime-only admission controller.
    pub fn fork_pool_admission_counts(&self, pool_name: &str) -> Result<(u32, u64)> {
        self.with_read_conn(|conn| {
            let active = conn
                .query_row(
                    "SELECT COUNT(*) FROM fork_leases
                     WHERE pool_name = ?1 AND state IN ('activating', 'active')",
                    params![pool_name],
                    |row| row.get(0),
                )
                .db_err("count active fork leases for admission")?;
            let completed = conn
                .query_row(
                    "SELECT COUNT(*) FROM fork_leases
                     WHERE pool_name = ?1 AND state = 'completed'",
                    params![pool_name],
                    |row| row.get(0),
                )
                .db_err("count completed fork leases for admission")?;
            Ok((active, completed))
        })
    }

    /// Reserve a provisioning slot only while the pool still has a ready deficit.
    ///
    /// The deficit check and insert share a transaction, so repeated controller
    /// ticks or a future second controller cannot overfill a pool.
    pub fn reserve_fork_pool_slot(
        &self,
        pool_name: &str,
        machine_name: &str,
        now: u64,
    ) -> Result<bool> {
        self.with_conn(|conn| {
            let tx = conn.transaction().db_err("begin fork slot reservation")?;
            let pool_data: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT data FROM fork_pools WHERE name = ?1",
                    params![pool_name],
                    |row| row.get(0),
                )
                .optional()
                .db_err(format!("get fork pool '{pool_name}'"))?;
            let Some(pool_data) = pool_data else {
                tx.commit().db_err("commit missing fork pool reservation")?;
                return Ok(false);
            };
            let pool: ForkPoolRecord =
                serde_json::from_slice(&pool_data).db_err("deserialize fork pool")?;
            if pool.deleting {
                tx.commit()
                    .db_err("commit deleting fork pool reservation")?;
                return Ok(false);
            }
            let activating: u32 = tx
                .query_row(
                    "SELECT COUNT(*) FROM fork_pool_slots
                     WHERE pool_name = ?1 AND state = 'activating'",
                    params![pool_name],
                    |row| row.get(0),
                )
                .db_err("count activating fork pool slots")?;
            if activating > 0 {
                tx.commit()
                    .db_err("commit deferred fork pool reservation")?;
                return Ok(false);
            }
            let available: u32 = tx
                .query_row(
                    "SELECT COUNT(*) FROM fork_pool_slots
                     WHERE pool_name = ?1 AND state IN ('provisioning', 'ready')",
                    params![pool_name],
                    |row| row.get(0),
                )
                .db_err("count available fork pool slots")?;
            if available >= pool.desired_ready {
                tx.commit().db_err("commit full fork pool reservation")?;
                return Ok(false);
            }
            let slot = ForkPoolSlotRecord {
                pool_name: pool_name.to_string(),
                machine_name: machine_name.to_string(),
                state: ForkPoolSlotState::Provisioning,
                lease_id: None,
                created_at: now,
                updated_at: now,
                last_error: None,
            };
            let data = serde_json::to_vec(&slot).db_err("serialize fork pool slot")?;
            let changed = tx
                .execute(
                    "INSERT OR IGNORE INTO fork_pool_slots
                     (machine_name, pool_name, state, data) VALUES (?1, ?2, ?3, ?4)",
                    params![
                        machine_name,
                        pool_name,
                        ForkPoolSlotState::Provisioning.as_str(),
                        data
                    ],
                )
                .db_err(format!("reserve fork pool slot '{machine_name}'"))?;
            tx.commit().db_err("commit fork slot reservation")?;
            Ok(changed == 1)
        })
    }

    /// Mark a successfully booted held worker ready for acquisition.
    pub fn mark_fork_pool_slot_ready(&self, machine_name: &str, now: u64) -> Result<bool> {
        self.update_fork_pool_slot_state(
            machine_name,
            ForkPoolSlotState::Provisioning,
            ForkPoolSlotState::Ready,
            now,
            None,
        )
    }

    /// Retire a worker after provisioning, activation, expiry, or cancellation.
    pub fn mark_fork_pool_slot_retiring(
        &self,
        machine_name: &str,
        now: u64,
        error: Option<String>,
    ) -> Result<bool> {
        self.with_conn(|conn| {
            let tx = conn.transaction().db_err("begin retire fork pool slot")?;
            let data: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT data FROM fork_pool_slots WHERE machine_name = ?1",
                    params![machine_name],
                    |row| row.get(0),
                )
                .optional()
                .db_err(format!("get fork pool slot '{machine_name}'"))?;
            let Some(data) = data else {
                tx.commit().db_err("commit missing fork slot retirement")?;
                return Ok(false);
            };
            let mut slot: ForkPoolSlotRecord =
                serde_json::from_slice(&data).db_err("deserialize fork pool slot")?;
            slot.state = ForkPoolSlotState::Retiring;
            slot.updated_at = now;
            slot.last_error = error;
            let updated = serde_json::to_vec(&slot).db_err("serialize fork pool slot")?;
            tx.execute(
                "UPDATE fork_pool_slots SET state = ?2, data = ?3 WHERE machine_name = ?1",
                params![machine_name, ForkPoolSlotState::Retiring.as_str(), updated],
            )
            .db_err(format!("retire fork pool slot '{machine_name}'"))?;
            tx.commit().db_err("commit fork slot retirement")?;
            Ok(true)
        })
    }

    fn update_fork_pool_slot_state(
        &self,
        machine_name: &str,
        expected: ForkPoolSlotState,
        next: ForkPoolSlotState,
        now: u64,
        error: Option<String>,
    ) -> Result<bool> {
        self.with_conn(|conn| {
            let tx = conn.transaction().db_err("begin fork pool slot update")?;
            let data: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT data FROM fork_pool_slots WHERE machine_name = ?1 AND state = ?2",
                    params![machine_name, expected.as_str()],
                    |row| row.get(0),
                )
                .optional()
                .db_err(format!("get fork pool slot '{machine_name}'"))?;
            let Some(data) = data else {
                tx.commit().db_err("commit unchanged fork slot")?;
                return Ok(false);
            };
            let mut slot: ForkPoolSlotRecord =
                serde_json::from_slice(&data).db_err("deserialize fork pool slot")?;
            slot.state = next;
            slot.updated_at = now;
            slot.last_error = error;
            let updated = serde_json::to_vec(&slot).db_err("serialize fork pool slot")?;
            tx.execute(
                "UPDATE fork_pool_slots SET state = ?2, data = ?3 WHERE machine_name = ?1",
                params![machine_name, next.as_str(), updated],
            )
            .db_err(format!("update fork pool slot '{machine_name}'"))?;
            tx.commit().db_err("commit fork slot update")?;
            Ok(true)
        })
    }

    /// Atomically consume one held worker and create its idempotent lease.
    ///
    /// The VM's `forkpoint_held` bit is cleared in the same transaction as the
    /// slot claim. A crash after commit can waste this worker, but can never
    /// make a released workload appear ready for a second caller.
    pub fn claim_fork_pool_slot(&self, claim: ForkPoolSlotClaim<'_>) -> Result<ClaimForkPoolSlot> {
        let ForkPoolSlotClaim {
            pool_name,
            lease_id,
            idempotency_key,
            assignment,
            payload_sha256,
            require_private_workspace,
            admission_limit,
            ttl_secs,
            now,
        } = claim;
        self.with_conn(|conn| {
            // Take the SQLite writer reservation before reading any capacity
            // counters. Concurrent claims on different pools can otherwise
            // both observe the same device headroom before either inserts.
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .db_err("begin fork pool claim")?;
            if let Some(bytes) = tx
                .query_row(
                    "SELECT data FROM fork_leases
                     WHERE pool_name = ?1 AND idempotency_key = ?2",
                    params![pool_name, idempotency_key],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()
                .db_err("look up idempotent fork lease")?
            {
                let lease = serde_json::from_slice(&bytes).db_err("deserialize fork lease")?;
                tx.commit().db_err("commit idempotent fork claim")?;
                return Ok(ClaimForkPoolSlot::Existing(lease));
            }

            let pool_data: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT data FROM fork_pools WHERE name = ?1",
                    params![pool_name],
                    |row| row.get(0),
                )
                .optional()
                .db_err(format!("get fork pool '{pool_name}'"))?;
            let Some(pool_data) = pool_data else {
                tx.commit().db_err("commit missing fork pool claim")?;
                return Ok(ClaimForkPoolSlot::PoolNotFound);
            };
            let pool: ForkPoolRecord =
                serde_json::from_slice(&pool_data).db_err("deserialize fork pool")?;
            if pool.deleting {
                tx.commit().db_err("commit deleting fork pool claim")?;
                return Ok(ClaimForkPoolSlot::PoolDeleting);
            }
            let adaptive_pool_limit = admission_limit.map(|limit| limit.pool);
            let max_active = match (pool.max_active, adaptive_pool_limit) {
                (Some(configured), Some(adaptive)) => Some(configured.min(adaptive)),
                (Some(configured), None) => Some(configured),
                (None, adaptive) => adaptive,
            };
            if let Some(max_active) = max_active {
                let active: u32 = tx
                    .query_row(
                        "SELECT COUNT(*) FROM fork_leases
                         WHERE pool_name = ?1 AND state IN ('activating', 'active')",
                        params![pool_name],
                        |row| row.get(0),
                    )
                    .db_err("count active fork leases")?;
                if active >= max_active {
                    tx.commit().db_err("commit fork pool capacity check")?;
                    return Ok(ClaimForkPoolSlot::AtCapacity);
                }
            }
            if let (Some(limit), Some(device_ordinal)) =
                (admission_limit, pool.admission_device_ordinal())
            {
                let active_on_device = {
                    let mut stmt = tx
                        .prepare_cached(
                            "SELECT pool_name, COUNT(*) FROM fork_leases
                             WHERE state IN ('activating', 'active')
                             GROUP BY pool_name",
                        )
                        .db_err("prepare active device lease count")?;
                    let rows = stmt
                        .query_map([], |row| {
                            Ok((row.get::<_, String>(0)?, row.get::<_, u32>(1)?))
                        })
                        .db_err("query active device lease count")?;
                    let mut active = 0_u32;
                    for row in rows {
                        let (active_pool_name, count) =
                            row.db_err("read active device lease count")?;
                        let active_pool = if active_pool_name == pool_name {
                            Some(pool.clone())
                        } else {
                            tx.query_row(
                                "SELECT data FROM fork_pools WHERE name = ?1",
                                params![active_pool_name],
                                |row| row.get::<_, Vec<u8>>(0),
                            )
                            .optional()
                            .db_err("read active lease pool for device admission")?
                            .map(|bytes| {
                                serde_json::from_slice::<ForkPoolRecord>(&bytes)
                                    .db_err("deserialize active lease pool")
                            })
                            .transpose()?
                        };
                        if active_pool
                            .as_ref()
                            .and_then(ForkPoolRecord::admission_device_ordinal)
                            == Some(device_ordinal)
                        {
                            active = active.saturating_add(count);
                        }
                    }
                    active
                };
                if active_on_device >= limit.device {
                    tx.commit().db_err("commit CUDA device capacity check")?;
                    return Ok(ClaimForkPoolSlot::AtCapacity);
                }
            }

            let ready_rows: Vec<(String, Vec<u8>)> = {
                let mut stmt = tx
                    .prepare_cached(
                        "SELECT machine_name, data FROM fork_pool_slots
                         WHERE pool_name = ?1 AND state = 'ready'
                         ORDER BY machine_name",
                    )
                    .db_err("prepare ready fork slot query")?;
                let rows = stmt
                    .query_map(params![pool_name], |row| Ok((row.get(0)?, row.get(1)?)))
                    .db_err("query ready fork slots")?;
                let mut collected = Vec::new();
                for row in rows {
                    collected.push(row.db_err("read ready fork slot")?);
                }
                collected
            };

            let mut selected = None;
            for (machine_name, slot_data) in ready_rows {
                let mut slot: ForkPoolSlotRecord = serde_json::from_slice(&slot_data)
                    .db_err("deserialize ready fork pool slot")?;
                let vm_data: Option<Vec<u8>> = tx
                    .query_row(
                        "SELECT data FROM vms WHERE name = ?1",
                        params![machine_name],
                        |row| row.get(0),
                    )
                    .optional()
                    .db_err(format!("get pool worker '{machine_name}'"))?;
                let valid = vm_data
                    .as_deref()
                    .map(|bytes| {
                        serde_json::from_slice::<VmRecord>(bytes)
                            .map(|vm| {
                                vm.forkpoint_held
                                    && vm.golden.as_deref() == Some(pool.golden.as_str())
                            })
                            .unwrap_or(false)
                    })
                    .unwrap_or(false);
                if valid {
                    selected = Some((machine_name, slot, vm_data.expect("valid VM data")));
                    break;
                }
                slot.state = ForkPoolSlotState::Retiring;
                slot.updated_at = now;
                slot.last_error = Some("ready slot no longer has a matching held VM".into());
                let updated =
                    serde_json::to_vec(&slot).db_err("serialize invalid fork pool slot")?;
                tx.execute(
                    "UPDATE fork_pool_slots SET state = 'retiring', data = ?2
                     WHERE machine_name = ?1",
                    params![machine_name, updated],
                )
                .db_err("retire invalid ready fork slot")?;
            }

            let Some((machine_name, mut slot, vm_data)) = selected else {
                tx.commit().db_err("commit no-ready fork claim")?;
                return Ok(ClaimForkPoolSlot::NoReadySlot);
            };
            let mut vm: VmRecord =
                serde_json::from_slice(&vm_data).db_err("deserialize pool worker")?;
            if require_private_workspace
                && vm
                    .mounts
                    .iter()
                    .any(|(_, target, _)| targets_workspace_tree(target))
            {
                tx.commit()
                    .db_err("commit external-workspace fork claim rejection")?;
                return Ok(ClaimForkPoolSlot::WorkspaceExternallyMounted);
            }
            let merged = crate::agent::fork::merge_fork_env(&vm.fork_env, assignment);
            crate::agent::fork::record_fork_activation(&mut vm, assignment, merged);
            let vm_updated = serde_json::to_vec(&vm).db_err("serialize claimed pool worker")?;
            tx.execute(
                "UPDATE vms SET data = ?2 WHERE name = ?1",
                params![machine_name, vm_updated],
            )
            .db_err("consume held pool worker")?;

            slot.state = ForkPoolSlotState::Activating;
            slot.lease_id = Some(lease_id.to_string());
            slot.updated_at = now;
            let slot_updated =
                serde_json::to_vec(&slot).db_err("serialize claimed fork pool slot")?;
            tx.execute(
                "UPDATE fork_pool_slots SET state = 'activating', data = ?2
                 WHERE machine_name = ?1",
                params![machine_name, slot_updated],
            )
            .db_err("claim fork pool slot")?;

            let lease = ForkLeaseRecord {
                id: lease_id.to_string(),
                pool_name: pool_name.to_string(),
                machine_name,
                idempotency_key: idempotency_key.to_string(),
                state: ForkLeaseState::Activating,
                assignment: assignment.to_vec(),
                payload_sha256: payload_sha256.map(str::to_owned),
                created_at: now,
                updated_at: now,
                expires_at: now.saturating_add(crate::pool::FORK_LEASE_ACTIVATION_GRACE_SECS),
                ttl_secs,
                last_error: None,
            };
            let lease_data = serde_json::to_vec(&lease).db_err("serialize fork lease")?;
            tx.execute(
                "INSERT INTO fork_leases (id, pool_name, idempotency_key, state, data)
                 VALUES (?1, ?2, ?3, 'activating', ?4)",
                params![lease.id, pool_name, idempotency_key, lease_data],
            )
            .db_err("insert fork lease")?;
            tx.commit().db_err("commit fork pool claim")?;
            Ok(ClaimForkPoolSlot::Claimed(lease))
        })
    }

    /// Read one lease by ID, scoped to its pool.
    pub fn get_fork_lease(
        &self,
        pool_name: &str,
        lease_id: &str,
    ) -> Result<Option<ForkLeaseRecord>> {
        self.with_read_conn(|conn| {
            let data: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT data FROM fork_leases WHERE pool_name = ?1 AND id = ?2",
                    params![pool_name, lease_id],
                    |row| row.get(0),
                )
                .optional()
                .db_err(format!("get fork lease '{lease_id}'"))?;
            data.map(|bytes| serde_json::from_slice(&bytes).db_err("deserialize fork lease"))
                .transpose()
        })
    }

    /// Read one lease by its globally unique opaque ID.
    pub fn get_fork_lease_by_id(&self, lease_id: &str) -> Result<Option<ForkLeaseRecord>> {
        self.with_read_conn(|conn| {
            let data: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT data FROM fork_leases WHERE id = ?1",
                    params![lease_id],
                    |row| row.get(0),
                )
                .optional()
                .db_err(format!("get fork lease '{lease_id}'"))?;
            data.map(|bytes| serde_json::from_slice(&bytes).db_err("deserialize fork lease"))
                .transpose()
        })
    }

    /// Mark a claimed worker active after its guest release succeeds.
    pub fn mark_fork_lease_active(
        &self,
        lease_id: &str,
        now: u64,
    ) -> Result<Option<ForkLeaseRecord>> {
        self.transition_fork_lease(
            lease_id,
            ForkLeaseState::Activating,
            ForkLeaseState::Active,
            ForkPoolSlotState::Leased,
            now,
            None,
        )
    }

    /// Fail a lease and retire its consumed worker after activation fails.
    pub fn fail_fork_lease(
        &self,
        lease_id: &str,
        now: u64,
        error: String,
    ) -> Result<Option<ForkLeaseRecord>> {
        self.transition_fork_lease(
            lease_id,
            ForkLeaseState::Activating,
            ForkLeaseState::Failed,
            ForkPoolSlotState::Retiring,
            now,
            Some(error),
        )
    }

    /// Fail an active lease whose worker process exited unexpectedly.
    pub fn fail_active_fork_lease(
        &self,
        lease_id: &str,
        now: u64,
        error: String,
    ) -> Result<Option<ForkLeaseRecord>> {
        self.transition_fork_lease(
            lease_id,
            ForkLeaseState::Active,
            ForkLeaseState::Failed,
            ForkPoolSlotState::Retiring,
            now,
            Some(error),
        )
    }

    fn transition_fork_lease(
        &self,
        lease_id: &str,
        expected: ForkLeaseState,
        next: ForkLeaseState,
        slot_next: ForkPoolSlotState,
        now: u64,
        error: Option<String>,
    ) -> Result<Option<ForkLeaseRecord>> {
        self.with_conn(|conn| {
            let tx = conn.transaction().db_err("begin fork lease transition")?;
            let data: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT data FROM fork_leases WHERE id = ?1",
                    params![lease_id],
                    |row| row.get(0),
                )
                .optional()
                .db_err(format!("get fork lease '{lease_id}'"))?;
            let Some(data) = data else {
                tx.commit().db_err("commit missing fork lease transition")?;
                return Ok(None);
            };
            let mut lease: ForkLeaseRecord =
                serde_json::from_slice(&data).db_err("deserialize fork lease")?;
            if lease.state != expected {
                tx.commit().db_err("commit unchanged fork lease")?;
                return Ok(Some(lease));
            }
            lease.state = next;
            lease.updated_at = now;
            if expected == ForkLeaseState::Activating && next == ForkLeaseState::Active {
                // The configured TTL is runtime ownership time. Payload staging
                // and guest release can be delayed by host contention, so start
                // its countdown only after activation commits.
                lease.expires_at = now.saturating_add(lease.ttl_secs);
            }
            lease.last_error = error.clone();
            let updated = serde_json::to_vec(&lease).db_err("serialize fork lease")?;
            tx.execute(
                "UPDATE fork_leases SET state = ?2, data = ?3 WHERE id = ?1",
                params![lease_id, next.as_str(), updated],
            )
            .db_err(format!("transition fork lease '{lease_id}'"))?;

            let slot_data: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT data FROM fork_pool_slots WHERE machine_name = ?1",
                    params![lease.machine_name],
                    |row| row.get(0),
                )
                .optional()
                .db_err("get leased fork pool slot")?;
            if let Some(slot_data) = slot_data {
                let mut slot: ForkPoolSlotRecord = serde_json::from_slice(&slot_data)
                    .db_err("deserialize leased fork pool slot")?;
                slot.state = slot_next;
                slot.updated_at = now;
                slot.last_error = error;
                let slot_updated =
                    serde_json::to_vec(&slot).db_err("serialize leased fork pool slot")?;
                tx.execute(
                    "UPDATE fork_pool_slots SET state = ?2, data = ?3 WHERE machine_name = ?1",
                    params![lease.machine_name, slot_next.as_str(), slot_updated],
                )
                .db_err("transition leased fork pool slot")?;
            }
            tx.commit().db_err("commit fork lease transition")?;
            Ok(Some(lease))
        })
    }

    /// Extend one active lease using its configured TTL.
    pub fn heartbeat_fork_lease(
        &self,
        pool_name: &str,
        lease_id: &str,
        now: u64,
    ) -> Result<Option<ForkLeaseRecord>> {
        self.with_conn(|conn| {
            let tx = conn.transaction().db_err("begin fork lease heartbeat")?;
            let data: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT data FROM fork_leases WHERE pool_name = ?1 AND id = ?2",
                    params![pool_name, lease_id],
                    |row| row.get(0),
                )
                .optional()
                .db_err(format!("get fork lease '{lease_id}'"))?;
            let Some(data) = data else {
                tx.commit().db_err("commit missing fork lease heartbeat")?;
                return Ok(None);
            };
            let mut lease: ForkLeaseRecord =
                serde_json::from_slice(&data).db_err("deserialize fork lease")?;
            if lease.state == ForkLeaseState::Active && lease.expires_at > now {
                lease.updated_at = now;
                lease.expires_at = now.saturating_add(lease.ttl_secs);
                let updated = serde_json::to_vec(&lease).db_err("serialize fork lease")?;
                tx.execute(
                    "UPDATE fork_leases SET data = ?2 WHERE id = ?1",
                    params![lease_id, updated],
                )
                .db_err(format!("heartbeat fork lease '{lease_id}'"))?;
            }
            tx.commit().db_err("commit fork lease heartbeat")?;
            Ok(Some(lease))
        })
    }

    /// Complete one active lease and retire its one-shot worker.
    pub fn complete_fork_lease(
        &self,
        pool_name: &str,
        lease_id: &str,
        now: u64,
    ) -> Result<Option<ForkLeaseRecord>> {
        let lease = self.get_fork_lease(pool_name, lease_id)?;
        let Some(lease) = lease else {
            return Ok(None);
        };
        if lease.state != ForkLeaseState::Active {
            return Ok(Some(lease));
        }
        self.transition_fork_lease(
            lease_id,
            ForkLeaseState::Active,
            ForkLeaseState::Completed,
            ForkPoolSlotState::Retiring,
            now,
            None,
        )
    }

    /// Expire overdue active or ambiguous-activation leases and retire workers.
    pub fn expire_fork_leases(&self, now: u64) -> Result<Vec<ForkLeaseRecord>> {
        self.with_conn(|conn| {
            let tx = conn.transaction().db_err("begin fork lease expiry")?;
            let rows: Vec<Vec<u8>> = {
                let mut stmt = tx
                    .prepare_cached(
                        "SELECT data FROM fork_leases
                         WHERE state IN ('activating', 'active')",
                    )
                    .db_err("prepare expiring fork leases")?;
                let rows = stmt
                    .query_map([], |row| row.get(0))
                    .db_err("query expiring fork leases")?;
                let mut collected = Vec::new();
                for row in rows {
                    collected.push(row.db_err("read expiring fork lease")?);
                }
                collected
            };
            let mut expired = Vec::new();
            for data in rows {
                let mut lease: ForkLeaseRecord =
                    serde_json::from_slice(&data).db_err("deserialize fork lease")?;
                if lease.expires_at > now {
                    continue;
                }
                lease.state = ForkLeaseState::Expired;
                lease.updated_at = now;
                let updated = serde_json::to_vec(&lease).db_err("serialize expired fork lease")?;
                tx.execute(
                    "UPDATE fork_leases SET state = 'expired', data = ?2 WHERE id = ?1",
                    params![lease.id, updated],
                )
                .db_err("expire fork lease")?;
                if let Some(slot_data) = tx
                    .query_row(
                        "SELECT data FROM fork_pool_slots WHERE machine_name = ?1",
                        params![lease.machine_name],
                        |row| row.get::<_, Vec<u8>>(0),
                    )
                    .optional()
                    .db_err("get expired lease slot")?
                {
                    let mut slot: ForkPoolSlotRecord = serde_json::from_slice(&slot_data)
                        .db_err("deserialize expired lease slot")?;
                    slot.state = ForkPoolSlotState::Retiring;
                    slot.updated_at = now;
                    let slot_updated =
                        serde_json::to_vec(&slot).db_err("serialize expired lease slot")?;
                    tx.execute(
                        "UPDATE fork_pool_slots SET state = 'retiring', data = ?2
                         WHERE machine_name = ?1",
                        params![lease.machine_name, slot_updated],
                    )
                    .db_err("retire expired lease slot")?;
                }
                expired.push(lease);
            }
            tx.commit().db_err("commit fork lease expiry")?;
            Ok(expired)
        })
    }

    /// List active leases for worker-liveness reconciliation.
    pub fn list_active_fork_leases(&self) -> Result<Vec<ForkLeaseRecord>> {
        self.with_read_conn(|conn| {
            let mut stmt = conn
                .prepare_cached("SELECT data FROM fork_leases WHERE state = 'active'")
                .db_err("prepare active fork leases")?;
            let rows = stmt
                .query_map([], |row| row.get::<_, Vec<u8>>(0))
                .db_err("query active fork leases")?;
            let mut leases = Vec::new();
            for row in rows {
                leases.push(
                    serde_json::from_slice(&row.db_err("read active fork lease")?)
                        .db_err("deserialize active fork lease")?,
                );
            }
            Ok(leases)
        })
    }

    /// List workers waiting for controller cleanup.
    pub fn list_retiring_fork_pool_slots(&self) -> Result<Vec<ForkPoolSlotRecord>> {
        self.with_read_conn(|conn| {
            let mut stmt = conn
                .prepare_cached("SELECT data FROM fork_pool_slots WHERE state = 'retiring'")
                .db_err("prepare retiring fork slots")?;
            let rows = stmt
                .query_map([], |row| row.get::<_, Vec<u8>>(0))
                .db_err("query retiring fork slots")?;
            let mut slots = Vec::new();
            for row in rows {
                slots.push(
                    serde_json::from_slice(&row.db_err("read retiring fork slot")?)
                        .db_err("deserialize retiring fork slot")?,
                );
            }
            Ok(slots)
        })
    }

    /// Forget a slot after its machine and data directory are gone.
    pub fn remove_fork_pool_slot(&self, machine_name: &str) -> Result<bool> {
        self.with_conn(|conn| {
            Ok(conn
                .execute(
                    "DELETE FROM fork_pool_slots WHERE machine_name = ?1",
                    params![machine_name],
                )
                .db_err(format!("remove fork pool slot '{machine_name}'"))?
                == 1)
        })
    }

    /// Begin pool deletion and retire its workers atomically.
    pub fn begin_delete_fork_pool(
        &self,
        name: &str,
        force: bool,
        now: u64,
    ) -> Result<Option<bool>> {
        self.with_conn(|conn| {
            let tx = conn.transaction().db_err("begin fork pool deletion")?;
            let data: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT data FROM fork_pools WHERE name = ?1",
                    params![name],
                    |row| row.get(0),
                )
                .optional()
                .db_err(format!("get fork pool '{name}'"))?;
            let Some(data) = data else {
                tx.commit().db_err("commit missing fork pool deletion")?;
                return Ok(None);
            };
            let active: u32 = tx
                .query_row(
                    "SELECT COUNT(*) FROM fork_leases
                     WHERE pool_name = ?1 AND state IN ('activating', 'active')",
                    params![name],
                    |row| row.get(0),
                )
                .db_err("count active fork leases")?;
            if active > 0 && !force {
                tx.commit().db_err("commit refused fork pool deletion")?;
                return Ok(Some(false));
            }
            let mut pool: ForkPoolRecord =
                serde_json::from_slice(&data).db_err("deserialize fork pool")?;
            pool.deleting = true;
            let updated = serde_json::to_vec(&pool).db_err("serialize fork pool")?;
            tx.execute(
                "UPDATE fork_pools SET data = ?2 WHERE name = ?1",
                params![name, updated],
            )
            .db_err("mark fork pool deleting")?;

            let slot_rows: Vec<Vec<u8>> = {
                let mut stmt = tx
                    .prepare_cached("SELECT data FROM fork_pool_slots WHERE pool_name = ?1")
                    .db_err("prepare deleting fork pool slots")?;
                let rows = stmt
                    .query_map(params![name], |row| row.get(0))
                    .db_err("query deleting fork pool slots")?;
                let mut collected = Vec::new();
                for row in rows {
                    collected.push(row.db_err("read deleting fork pool slot")?);
                }
                collected
            };
            for slot_data in slot_rows {
                let mut slot: ForkPoolSlotRecord = serde_json::from_slice(&slot_data)
                    .db_err("deserialize deleting fork pool slot")?;
                slot.state = ForkPoolSlotState::Retiring;
                slot.updated_at = now;
                let slot_updated =
                    serde_json::to_vec(&slot).db_err("serialize deleting fork pool slot")?;
                tx.execute(
                    "UPDATE fork_pool_slots SET state = 'retiring', data = ?2
                     WHERE machine_name = ?1",
                    params![slot.machine_name, slot_updated],
                )
                .db_err("retire deleting fork pool slot")?;
            }
            if force {
                let lease_rows: Vec<Vec<u8>> = {
                    let mut stmt = tx
                        .prepare_cached(
                            "SELECT data FROM fork_leases
                             WHERE pool_name = ?1 AND state IN ('activating', 'active')",
                        )
                        .db_err("prepare cancelled fork leases")?;
                    let rows = stmt
                        .query_map(params![name], |row| row.get(0))
                        .db_err("query cancelled fork leases")?;
                    let mut collected = Vec::new();
                    for row in rows {
                        collected.push(row.db_err("read cancelled fork lease")?);
                    }
                    collected
                };
                for lease_data in lease_rows {
                    let mut lease: ForkLeaseRecord = serde_json::from_slice(&lease_data)
                        .db_err("deserialize cancelled fork lease")?;
                    lease.state = ForkLeaseState::Cancelled;
                    lease.updated_at = now;
                    let lease_updated =
                        serde_json::to_vec(&lease).db_err("serialize cancelled fork lease")?;
                    tx.execute(
                        "UPDATE fork_leases SET state = 'cancelled', data = ?2 WHERE id = ?1",
                        params![lease.id, lease_updated],
                    )
                    .db_err("cancel fork lease")?;
                }
            }
            tx.commit().db_err("commit fork pool deletion")?;
            Ok(Some(true))
        })
    }

    /// Remove fully drained deleting pools and their completed lease history.
    pub fn finalize_deleted_fork_pools(&self) -> Result<Vec<String>> {
        self.with_conn(|conn| {
            let tx = conn.transaction().db_err("begin finalize fork pools")?;
            let pool_rows: Vec<(String, Vec<u8>)> = {
                let mut stmt = tx
                    .prepare_cached("SELECT name, data FROM fork_pools")
                    .db_err("prepare finalizing fork pools")?;
                let rows = stmt
                    .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                    .db_err("query finalizing fork pools")?;
                let mut collected = Vec::new();
                for row in rows {
                    collected.push(row.db_err("read finalizing fork pool")?);
                }
                collected
            };
            let mut removed = Vec::new();
            for (name, data) in pool_rows {
                let pool: ForkPoolRecord =
                    serde_json::from_slice(&data).db_err("deserialize fork pool")?;
                if !pool.deleting {
                    continue;
                }
                let slots: u32 = tx
                    .query_row(
                        "SELECT COUNT(*) FROM fork_pool_slots WHERE pool_name = ?1",
                        params![name],
                        |row| row.get(0),
                    )
                    .db_err("count draining fork pool slots")?;
                if slots == 0 {
                    tx.execute(
                        "DELETE FROM fork_leases WHERE pool_name = ?1",
                        params![name],
                    )
                    .db_err("remove deleted fork pool leases")?;
                    tx.execute("DELETE FROM fork_pools WHERE name = ?1", params![name])
                        .db_err("remove deleted fork pool")?;
                    removed.push(name);
                }
            }
            tx.commit().db_err("commit finalize fork pools")?;
            Ok(removed)
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

    #[test]
    fn fork_descendants_are_returned_deepest_first() {
        let (_dir, db) = temp_db();
        for (name, parent) in [
            ("root", None),
            ("child-b", Some("root")),
            ("child-a", Some("root")),
            ("grandchild", Some("child-a")),
            ("great-grandchild", Some("grandchild")),
        ] {
            let mut record = VmRecord::new(name.to_string(), 1, 128, vec![], vec![], false);
            record.golden = parent.map(str::to_string);
            db.insert_vm(name, &record).unwrap();
        }

        assert_eq!(
            db.dependent_descendants_postorder("root").unwrap(),
            vec!["great-grandchild", "grandchild", "child-a", "child-b"]
        );
        assert_eq!(db.fork_lineage_depth("root").unwrap(), 0);
        assert_eq!(db.fork_lineage_depth("great-grandchild").unwrap(), 3);
    }

    #[test]
    fn fork_lineage_rejects_cycles_and_missing_parents() {
        let (_dir, db) = temp_db();
        for (name, parent) in [("a", "b"), ("b", "a")] {
            let mut record = VmRecord::new(name.to_string(), 1, 128, vec![], vec![], false);
            record.golden = Some(parent.to_string());
            db.insert_vm(name, &record).unwrap();
        }
        assert!(db.dependent_descendants_postorder("a").is_err());
        assert!(db.fork_lineage_depth("a").is_err());

        let mut orphan = VmRecord::new("orphan".to_string(), 1, 128, vec![], vec![], false);
        orphan.golden = Some("missing".to_string());
        db.insert_vm("orphan", &orphan).unwrap();
        assert!(db.fork_lineage_depth("orphan").is_err());
    }

    #[test]
    fn concurrent_vm_updates_wait_instead_of_failing_busy_snapshot() {
        let (_dir, db) = temp_db();
        for name in ["slot-0", "slot-1"] {
            db.insert_vm(
                name,
                &VmRecord::new(name.to_string(), 1, 256, vec![], vec![], false),
            )
            .unwrap();
        }

        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let first_db = db.clone();
        let first = std::thread::spawn(move || {
            first_db.update_vm("slot-0", |record| {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                record.forkpoint_held = false;
            })
        });
        entered_rx.recv().unwrap();

        let (second_started_tx, second_started_rx) = std::sync::mpsc::channel();
        let (second_entered_tx, second_entered_rx) = std::sync::mpsc::channel();
        let second_db = db.clone();
        let second = std::thread::spawn(move || {
            second_started_tx.send(()).unwrap();
            second_db.update_vm("slot-1", |record| {
                second_entered_tx.send(()).unwrap();
                record.forkpoint_held = false;
            })
        });
        second_started_rx.recv().unwrap();
        let entered_while_first_active = second_entered_rx
            .recv_timeout(Duration::from_millis(50))
            .is_ok();
        release_tx.send(()).unwrap();

        first.join().unwrap().unwrap();
        second.join().unwrap().unwrap();
        assert!(!entered_while_first_active);
        assert!(!db.get_vm("slot-0").unwrap().unwrap().forkpoint_held);
        assert!(!db.get_vm("slot-1").unwrap().unwrap().forkpoint_held);
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
    fn fresh_reader_burst_does_not_race_database_initialization() {
        let (_dir, db) = temp_db();
        let start = Arc::new(std::sync::Barrier::new(POOL_MAX_CONNS));
        let readers = (0..POOL_MAX_CONNS)
            .map(|_| {
                let db = db.clone();
                let start = start.clone();
                std::thread::spawn(move || {
                    start.wait();
                    db.with_read_conn(|conn| {
                        let missing: Option<Vec<u8>> = conn
                            .query_row(
                                "SELECT data FROM vms WHERE name = 'not-present'",
                                [],
                                |row| row.get(0),
                            )
                            .optional()
                            .db_err("read absent VM during connection burst")?;
                        assert!(missing.is_none());
                        std::thread::sleep(Duration::from_millis(50));
                        Ok(())
                    })
                })
            })
            .collect::<Vec<_>>();

        for reader in readers {
            reader.join().unwrap().unwrap();
        }
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
    fn fork_pool_snapshot_survives_database_reopen_and_can_be_removed() {
        let (dir, db) = temp_db();
        let snapshot = crate::agent::fork::RetainedForkSnapshot {
            path: PathBuf::from("/golden/s/12345678"),
            golden_pid: 123,
            golden_pid_start_time: 456,
        };
        db.set_retained_fork_snapshot("golden", &snapshot).unwrap();
        drop(db);

        let reopened = SmolvmDb::open_at(&dir.path().join("test.db")).unwrap();
        assert_eq!(
            reopened.list_retained_fork_snapshots().unwrap(),
            vec![("golden".to_string(), snapshot.clone())]
        );
        assert_eq!(
            reopened.retained_fork_snapshot("golden").unwrap().as_ref(),
            Some(&snapshot)
        );
        assert!(reopened.retained_fork_snapshot("other").unwrap().is_none());
        assert!(reopened.remove_retained_fork_snapshot("golden").unwrap());
        assert!(reopened.list_retained_fork_snapshots().unwrap().is_empty());
        assert!(!reopened.remove_retained_fork_snapshot("golden").unwrap());
    }

    /// A retained checkpoint restores RAM from one specific golden process, so it
    /// must not outlive that golden's record — otherwise a later machine reusing
    /// the name would inherit a checkpoint that belongs to a dead VM.
    #[test]
    fn removing_a_golden_also_drops_its_retained_fork_snapshot() {
        let (_dir, db) = temp_db();
        db.insert_vm(
            "golden",
            &VmRecord::new("golden".to_string(), 1, 256, vec![], vec![], true),
        )
        .unwrap();
        db.set_retained_fork_snapshot(
            "golden",
            &crate::agent::fork::RetainedForkSnapshot {
                path: PathBuf::from("/golden/s/12345678"),
                golden_pid: 123,
                golden_pid_start_time: 456,
            },
        )
        .unwrap();

        assert!(db.remove_vm("golden").unwrap().is_some());
        assert!(db.retained_fork_snapshot("golden").unwrap().is_none());
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

    fn test_pool(name: &str, desired_ready: u32) -> ForkPoolRecord {
        ForkPoolRecord {
            name: name.into(),
            golden: "golden".into(),
            desired_ready,
            max_active: None,
            auto_admission: false,
            cuda_device_ordinal: Some(0),
            share_weights: true,
            ready_timeout_secs: 30,
            lease_ttl_secs: 60,
            created_at: 100,
            deleting: false,
        }
    }

    fn insert_ready_pool_slot(db: &SmolvmDb, pool: &str, machine: &str) {
        let mut vm = VmRecord::new(machine.into(), 2, 1024, vec![], vec![], false);
        vm.golden = Some("golden".into());
        vm.forkpoint_held = true;
        vm.fork_env = vec![("BASE".into(), "1".into())];
        db.insert_vm(machine, &vm).unwrap();
        assert!(db.reserve_fork_pool_slot(pool, machine, 101).unwrap());
        assert!(db.mark_fork_pool_slot_ready(machine, 102).unwrap());
    }

    #[test]
    fn fork_pool_reservation_honors_desired_ready() {
        let (_dir, db) = temp_db();
        assert!(db
            .insert_fork_pool_if_not_exists(&test_pool("rollouts", 2))
            .unwrap());
        assert!(!db
            .insert_fork_pool_if_not_exists(&test_pool("rollouts", 2))
            .unwrap());
        assert!(db.reserve_fork_pool_slot("rollouts", "slot-1", 1).unwrap());
        assert!(db.reserve_fork_pool_slot("rollouts", "slot-2", 1).unwrap());
        assert!(!db.reserve_fork_pool_slot("rollouts", "slot-3", 1).unwrap());
        assert_eq!(db.list_fork_pool_slots("rollouts").unwrap().len(), 2);
    }

    #[test]
    fn shrinking_fork_pool_retires_surplus_ready_workers() {
        let (_dir, db) = temp_db();
        db.insert_fork_pool_if_not_exists(&test_pool("rollouts", 3))
            .unwrap();
        for machine in ["slot-1", "slot-2", "slot-3"] {
            insert_ready_pool_slot(&db, "rollouts", machine);
        }
        let resized = db.resize_fork_pool("rollouts", 1, 200).unwrap().unwrap();
        assert_eq!(resized.desired_ready, 1);
        let slots = db.list_fork_pool_slots("rollouts").unwrap();
        assert_eq!(
            slots
                .iter()
                .filter(|slot| slot.state == ForkPoolSlotState::Ready)
                .count(),
            1
        );
        assert_eq!(
            slots
                .iter()
                .filter(|slot| slot.state == ForkPoolSlotState::Retiring)
                .count(),
            2
        );
    }

    #[test]
    fn fork_pool_claim_is_idempotent_and_consumes_vm_atomically() {
        let (_dir, db) = temp_db();
        db.insert_fork_pool_if_not_exists(&test_pool("rollouts", 1))
            .unwrap();
        insert_ready_pool_slot(&db, "rollouts", "slot-1");
        let assignment = vec![("EPISODE".into(), "42".into())];
        let payload_sha256 = "payload-digest";

        let first = db
            .claim_fork_pool_slot(ForkPoolSlotClaim {
                pool_name: "rollouts",
                lease_id: "lease-a",
                idempotency_key: "request-a",
                assignment: &assignment,
                payload_sha256: Some(payload_sha256),
                require_private_workspace: true,
                admission_limit: None,
                ttl_secs: 60,
                now: 200,
            })
            .unwrap();
        let lease = match first {
            ClaimForkPoolSlot::Claimed(lease) => lease,
            other => panic!("unexpected claim result: {other:?}"),
        };
        assert_eq!(lease.machine_name, "slot-1");
        assert_eq!(lease.payload_sha256.as_deref(), Some(payload_sha256));
        let vm = db.get_vm("slot-1").unwrap().unwrap();
        assert!(!vm.forkpoint_held);
        assert!(vm
            .fork_env
            .iter()
            .any(|(key, value)| key == "EPISODE" && value == "42"));

        let retry = db
            .claim_fork_pool_slot(ForkPoolSlotClaim {
                pool_name: "rollouts",
                lease_id: "unused-new-id",
                idempotency_key: "request-a",
                assignment: &assignment,
                payload_sha256: Some(payload_sha256),
                require_private_workspace: true,
                admission_limit: None,
                ttl_secs: 60,
                now: 201,
            })
            .unwrap();
        assert!(matches!(
            retry,
            ClaimForkPoolSlot::Existing(ref existing)
                if existing.id == "lease-a"
                    && existing.payload_sha256.as_deref() == Some(payload_sha256)
        ));
        let second_request = db
            .claim_fork_pool_slot(ForkPoolSlotClaim {
                pool_name: "rollouts",
                lease_id: "lease-b",
                idempotency_key: "request-b",
                assignment: &assignment,
                payload_sha256: None,
                require_private_workspace: false,
                admission_limit: None,
                ttl_secs: 60,
                now: 201,
            })
            .unwrap();
        assert_eq!(second_request, ClaimForkPoolSlot::NoReadySlot);
    }

    #[test]
    fn fork_pool_refill_waits_for_guest_activation() {
        let (_dir, db) = temp_db();
        db.insert_fork_pool_if_not_exists(&test_pool("rollouts", 2))
            .unwrap();
        insert_ready_pool_slot(&db, "rollouts", "slot-1");
        insert_ready_pool_slot(&db, "rollouts", "slot-2");

        let claim = db
            .claim_fork_pool_slot(ForkPoolSlotClaim {
                pool_name: "rollouts",
                lease_id: "lease-a",
                idempotency_key: "request-a",
                assignment: &[],
                payload_sha256: None,
                require_private_workspace: false,
                admission_limit: None,
                ttl_secs: 60,
                now: 200,
            })
            .unwrap();
        assert!(matches!(claim, ClaimForkPoolSlot::Claimed(_)));
        assert_eq!(db.fork_pool_ready_deficit("rollouts").unwrap(), 0);
        assert!(!db
            .reserve_fork_pool_slot("rollouts", "replacement", 201)
            .unwrap());

        db.mark_fork_lease_active("lease-a", 202).unwrap();
        assert_eq!(db.fork_pool_ready_deficit("rollouts").unwrap(), 1);
        assert!(db
            .reserve_fork_pool_slot("rollouts", "replacement", 203)
            .unwrap());
    }

    #[test]
    fn payload_claim_rejects_external_workspace_without_consuming_slot() {
        let (_dir, db) = temp_db();
        db.insert_fork_pool_if_not_exists(&test_pool("rollouts", 1))
            .unwrap();
        insert_ready_pool_slot(&db, "rollouts", "slot-1");
        db.update_vm("slot-1", |vm| {
            vm.mounts
                .push(("/host/jobs".into(), "/workspace/jobs".into(), false));
        })
        .unwrap();

        let rejected = db
            .claim_fork_pool_slot(ForkPoolSlotClaim {
                pool_name: "rollouts",
                lease_id: "lease-a",
                idempotency_key: "request-a",
                assignment: &[],
                payload_sha256: Some("payload-digest"),
                require_private_workspace: true,
                admission_limit: None,
                ttl_secs: 60,
                now: 200,
            })
            .unwrap();
        assert_eq!(rejected, ClaimForkPoolSlot::WorkspaceExternallyMounted);
        assert_eq!(
            db.get_fork_pool_slot("slot-1").unwrap().unwrap().state,
            ForkPoolSlotState::Ready
        );
        assert!(db.get_vm("slot-1").unwrap().unwrap().forkpoint_held);

        let env_only = db
            .claim_fork_pool_slot(ForkPoolSlotClaim {
                pool_name: "rollouts",
                lease_id: "lease-b",
                idempotency_key: "request-b",
                assignment: &[],
                payload_sha256: None,
                require_private_workspace: false,
                admission_limit: None,
                ttl_secs: 60,
                now: 201,
            })
            .unwrap();
        assert!(matches!(env_only, ClaimForkPoolSlot::Claimed(_)));
    }

    #[test]
    fn workspace_mount_targets_are_normalized_component_wise() {
        for target in [
            "/workspace",
            "/workspace/",
            "/workspace/jobs",
            "/workspace/./jobs",
            "/tmp/../workspace/jobs",
            "workspace/jobs",
        ] {
            assert!(targets_workspace_tree(target), "{target}");
        }
        for target in ["/data", "/workspace2", "/tmp/workspace", "/workspace/.."] {
            assert!(!targets_workspace_tree(target), "{target}");
        }
    }

    #[test]
    fn concurrent_idempotent_claims_return_one_lease() {
        let (_dir, db) = temp_db();
        db.insert_fork_pool_if_not_exists(&test_pool("rollouts", 1))
            .unwrap();
        insert_ready_pool_slot(&db, "rollouts", "slot-1");
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let handles: Vec<_> = ["lease-a", "lease-b"]
            .into_iter()
            .map(|lease_id| {
                let db = db.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    db.claim_fork_pool_slot(ForkPoolSlotClaim {
                        pool_name: "rollouts",
                        lease_id,
                        idempotency_key: "same-request",
                        assignment: &[("EPISODE".into(), "42".into())],
                        payload_sha256: None,
                        require_private_workspace: false,
                        admission_limit: None,
                        ttl_secs: 60,
                        now: 200,
                    })
                    .unwrap()
                })
            })
            .collect();
        barrier.wait();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, ClaimForkPoolSlot::Claimed(_)))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, ClaimForkPoolSlot::Existing(_)))
                .count(),
            1
        );
        let ids: Vec<_> = results
            .iter()
            .map(|result| match result {
                ClaimForkPoolSlot::Claimed(lease) | ClaimForkPoolSlot::Existing(lease) => {
                    lease.id.as_str()
                }
                other => panic!("unexpected result: {other:?}"),
            })
            .collect();
        assert_eq!(ids[0], ids[1]);
    }

    #[test]
    fn fork_pool_max_active_preserves_ready_capacity() {
        let (_dir, db) = temp_db();
        let mut pool = test_pool("rollouts", 2);
        pool.max_active = Some(1);
        db.insert_fork_pool_if_not_exists(&pool).unwrap();
        insert_ready_pool_slot(&db, "rollouts", "slot-1");
        insert_ready_pool_slot(&db, "rollouts", "slot-2");
        db.claim_fork_pool_slot(ForkPoolSlotClaim {
            pool_name: "rollouts",
            lease_id: "lease-1",
            idempotency_key: "request-1",
            assignment: &[],
            payload_sha256: None,
            require_private_workspace: false,
            admission_limit: None,
            ttl_secs: 60,
            now: 200,
        })
        .unwrap();
        db.mark_fork_lease_active("lease-1", 201).unwrap();

        assert_eq!(
            db.claim_fork_pool_slot(ForkPoolSlotClaim {
                pool_name: "rollouts",
                lease_id: "lease-2",
                idempotency_key: "request-2",
                assignment: &[],
                payload_sha256: None,
                require_private_workspace: false,
                admission_limit: None,
                ttl_secs: 60,
                now: 202,
            })
            .unwrap(),
            ClaimForkPoolSlot::AtCapacity
        );
        assert_eq!(
            db.list_fork_pool_slots("rollouts")
                .unwrap()
                .into_iter()
                .filter(|slot| slot.state == ForkPoolSlotState::Ready)
                .count(),
            1,
            "capacity rejection must not consume a clean worker"
        );
        assert!(matches!(
            db.claim_fork_pool_slot(ForkPoolSlotClaim {
                pool_name: "rollouts",
                lease_id: "ignored",
                idempotency_key: "request-1",
                assignment: &[],
                payload_sha256: None,
                require_private_workspace: false,
                admission_limit: None,
                ttl_secs: 60,
                now: 203,
            })
                .unwrap(),
            ClaimForkPoolSlot::Existing(lease) if lease.id == "lease-1"
        ));
    }

    #[test]
    fn adaptive_limit_is_atomic_and_never_loosens_static_limit() {
        let (_dir, db) = temp_db();
        let mut pool = test_pool("rollouts", 3);
        pool.max_active = Some(2);
        db.insert_fork_pool_if_not_exists(&pool).unwrap();
        for machine in ["slot-1", "slot-2", "slot-3"] {
            insert_ready_pool_slot(&db, "rollouts", machine);
        }

        let claim = |lease_id: &str, request: &str, admission_limit: Option<u32>| {
            db.claim_fork_pool_slot(ForkPoolSlotClaim {
                pool_name: "rollouts",
                lease_id,
                idempotency_key: request,
                assignment: &[],
                payload_sha256: None,
                require_private_workspace: false,
                admission_limit: admission_limit
                    .map(|pool| ForkPoolAdmissionLimit { pool, device: 3 }),
                ttl_secs: 60,
                now: 200,
            })
            .unwrap()
        };

        assert!(matches!(
            claim("lease-1", "request-1", Some(1)),
            ClaimForkPoolSlot::Claimed(_)
        ));
        assert_eq!(
            claim("lease-2", "request-2", Some(1)),
            ClaimForkPoolSlot::AtCapacity
        );
        assert!(matches!(
            claim("lease-2", "request-2", Some(3)),
            ClaimForkPoolSlot::Claimed(_)
        ));
        assert_eq!(
            claim("lease-3", "request-3", Some(3)),
            ClaimForkPoolSlot::AtCapacity,
            "dynamic admission may not exceed maxActive"
        );
    }

    #[test]
    fn device_limit_is_shared_across_pools_but_not_across_devices() {
        let (_dir, db) = temp_db();
        let mut first = test_pool("first", 1);
        first.auto_admission = true;
        let mut second = test_pool("second", 1);
        second.auto_admission = true;
        db.insert_fork_pool_if_not_exists(&first).unwrap();
        db.insert_fork_pool_if_not_exists(&second).unwrap();
        insert_ready_pool_slot(&db, "first", "first-slot");
        insert_ready_pool_slot(&db, "second", "second-slot");
        let limit = Some(ForkPoolAdmissionLimit { pool: 1, device: 1 });

        assert!(matches!(
            db.claim_fork_pool_slot(ForkPoolSlotClaim {
                pool_name: "first",
                lease_id: "first-lease",
                idempotency_key: "first-request",
                assignment: &[],
                payload_sha256: None,
                require_private_workspace: false,
                admission_limit: limit,
                ttl_secs: 60,
                now: 200,
            })
            .unwrap(),
            ClaimForkPoolSlot::Claimed(_)
        ));
        assert_eq!(
            db.claim_fork_pool_slot(ForkPoolSlotClaim {
                pool_name: "second",
                lease_id: "second-lease",
                idempotency_key: "second-request",
                assignment: &[],
                payload_sha256: None,
                require_private_workspace: false,
                admission_limit: limit,
                ttl_secs: 60,
                now: 201,
            })
            .unwrap(),
            ClaimForkPoolSlot::AtCapacity
        );

        let (_other_dir, other_db) = temp_db();
        second.cuda_device_ordinal = Some(1);
        other_db.insert_fork_pool_if_not_exists(&first).unwrap();
        other_db.insert_fork_pool_if_not_exists(&second).unwrap();
        insert_ready_pool_slot(&other_db, "first", "other-first-slot");
        insert_ready_pool_slot(&other_db, "second", "other-second-slot");
        for (pool, machine, lease) in [
            ("first", "other-first-slot", "other-first-lease"),
            ("second", "other-second-slot", "other-second-lease"),
        ] {
            assert!(matches!(
                other_db
                    .claim_fork_pool_slot(ForkPoolSlotClaim {
                        pool_name: pool,
                        lease_id: lease,
                        idempotency_key: lease,
                        assignment: &[],
                        payload_sha256: None,
                        require_private_workspace: false,
                        admission_limit: limit,
                        ttl_secs: 60,
                        now: 202,
                    })
                    .unwrap(),
                ClaimForkPoolSlot::Claimed(_)
            ));
            assert_eq!(
                other_db
                    .get_fork_pool_slot(machine)
                    .unwrap()
                    .unwrap()
                    .lease_id,
                Some(lease.into())
            );
        }
    }

    #[test]
    fn concurrent_cross_pool_claims_cannot_cross_device_limit() {
        let (dir, db) = temp_db();
        let mut first = test_pool("first", 1);
        first.auto_admission = true;
        let mut second = test_pool("second", 1);
        second.auto_admission = true;
        db.insert_fork_pool_if_not_exists(&first).unwrap();
        db.insert_fork_pool_if_not_exists(&second).unwrap();
        insert_ready_pool_slot(&db, "first", "first-slot");
        insert_ready_pool_slot(&db, "second", "second-slot");
        drop(db);

        let path = dir.path().join("test.db");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let mut threads = Vec::new();
        for (pool, slot) in [("first", "first-slot"), ("second", "second-slot")] {
            let db = SmolvmDb::open_at(&path).unwrap();
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                db.claim_fork_pool_slot(ForkPoolSlotClaim {
                    pool_name: pool,
                    lease_id: slot,
                    idempotency_key: slot,
                    assignment: &[],
                    payload_sha256: None,
                    require_private_workspace: false,
                    admission_limit: Some(ForkPoolAdmissionLimit { pool: 1, device: 1 }),
                    ttl_secs: 60,
                    now: 200,
                })
                .unwrap()
            }));
        }
        let outcomes = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, ClaimForkPoolSlot::Claimed(_)))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, ClaimForkPoolSlot::AtCapacity))
                .count(),
            1
        );
    }

    #[test]
    fn fork_lease_heartbeat_completion_and_expiry_retire_workers() {
        let (_dir, db) = temp_db();
        db.insert_fork_pool_if_not_exists(&test_pool("rollouts", 2))
            .unwrap();
        insert_ready_pool_slot(&db, "rollouts", "slot-complete");
        insert_ready_pool_slot(&db, "rollouts", "slot-expire");

        for (machine, lease, request) in [
            ("slot-complete", "lease-complete", "req-complete"),
            ("slot-expire", "lease-expire", "req-expire"),
        ] {
            let claimed = db
                .claim_fork_pool_slot(ForkPoolSlotClaim {
                    pool_name: "rollouts",
                    lease_id: lease,
                    idempotency_key: request,
                    assignment: &[],
                    payload_sha256: None,
                    require_private_workspace: false,
                    admission_limit: None,
                    ttl_secs: 10,
                    now: 200,
                })
                .unwrap();
            assert!(
                matches!(claimed, ClaimForkPoolSlot::Claimed(ref l) if l.machine_name == machine)
            );
            let active = db.mark_fork_lease_active(lease, 201).unwrap().unwrap();
            assert_eq!(active.state, ForkLeaseState::Active);
        }

        let heartbeat = db
            .heartbeat_fork_lease("rollouts", "lease-complete", 205)
            .unwrap()
            .unwrap();
        assert_eq!(heartbeat.expires_at, 215);
        let completed = db
            .complete_fork_lease("rollouts", "lease-complete", 206)
            .unwrap()
            .unwrap();
        assert_eq!(completed.state, ForkLeaseState::Completed);

        let expired = db.expire_fork_leases(211).unwrap();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].id, "lease-expire");
        assert_eq!(expired[0].state, ForkLeaseState::Expired);
        let retiring = db.list_retiring_fork_pool_slots().unwrap();
        assert_eq!(retiring.len(), 2);
    }

    #[test]
    fn fork_lease_ttl_starts_after_activation_completes() {
        let (_dir, db) = temp_db();
        db.insert_fork_pool_if_not_exists(&test_pool("rollouts", 1))
            .unwrap();
        insert_ready_pool_slot(&db, "rollouts", "slot-delayed");
        let claimed = db
            .claim_fork_pool_slot(ForkPoolSlotClaim {
                pool_name: "rollouts",
                lease_id: "lease-delayed",
                idempotency_key: "req-delayed",
                assignment: &[],
                payload_sha256: None,
                require_private_workspace: false,
                admission_limit: None,
                ttl_secs: 30,
                now: 200,
            })
            .unwrap();
        let ClaimForkPoolSlot::Claimed(claimed) = claimed else {
            panic!("expected claimed lease");
        };
        assert_eq!(claimed.expires_at, 500);

        let active = db
            .mark_fork_lease_active("lease-delayed", 231)
            .unwrap()
            .unwrap();
        assert_eq!(active.expires_at, 261);
        assert!(db.expire_fork_leases(260).unwrap().is_empty());
        assert_eq!(db.expire_fork_leases(261).unwrap().len(), 1);
    }

    #[test]
    fn fork_pool_state_survives_database_reopen() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("pool.db");
        let db = SmolvmDb::open_at(&path).unwrap();
        db.insert_fork_pool_if_not_exists(&test_pool("durable", 1))
            .unwrap();
        insert_ready_pool_slot(&db, "durable", "slot-durable");
        drop(db);

        let reopened = SmolvmDb::open_at(&path).unwrap();
        let pool = reopened.get_fork_pool("durable").unwrap().unwrap();
        assert_eq!(pool.desired_ready, 1);
        let slots = reopened.list_fork_pool_slots("durable").unwrap();
        assert_eq!(slots[0].state, ForkPoolSlotState::Ready);
    }

    #[test]
    fn fork_pool_delete_refuses_active_lease_without_force() {
        let (_dir, db) = temp_db();
        db.insert_fork_pool_if_not_exists(&test_pool("rollouts", 1))
            .unwrap();
        insert_ready_pool_slot(&db, "rollouts", "slot-1");
        db.claim_fork_pool_slot(ForkPoolSlotClaim {
            pool_name: "rollouts",
            lease_id: "lease-1",
            idempotency_key: "request-1",
            assignment: &[],
            payload_sha256: None,
            require_private_workspace: false,
            admission_limit: None,
            ttl_secs: 60,
            now: 200,
        })
        .unwrap();
        db.mark_fork_lease_active("lease-1", 201).unwrap();

        assert_eq!(
            db.begin_delete_fork_pool("rollouts", false, 202).unwrap(),
            Some(false)
        );
        assert_eq!(
            db.begin_delete_fork_pool("rollouts", true, 203).unwrap(),
            Some(true)
        );
        let lease = db.get_fork_lease("rollouts", "lease-1").unwrap().unwrap();
        assert_eq!(lease.state, ForkLeaseState::Cancelled);
        assert_eq!(
            db.list_fork_pool_slots("rollouts").unwrap()[0].state,
            ForkPoolSlotState::Retiring
        );
    }

    #[test]
    fn dead_active_worker_failure_is_terminal_and_retired() {
        let (_dir, db) = temp_db();
        db.insert_fork_pool_if_not_exists(&test_pool("rollouts", 1))
            .unwrap();
        insert_ready_pool_slot(&db, "rollouts", "slot-1");
        db.claim_fork_pool_slot(ForkPoolSlotClaim {
            pool_name: "rollouts",
            lease_id: "lease-1",
            idempotency_key: "request-1",
            assignment: &[],
            payload_sha256: None,
            require_private_workspace: false,
            admission_limit: None,
            ttl_secs: 60,
            now: 200,
        })
        .unwrap();
        db.mark_fork_lease_active("lease-1", 201).unwrap();

        let failed = db
            .fail_active_fork_lease("lease-1", 202, "worker exited".into())
            .unwrap()
            .unwrap();
        assert_eq!(failed.state, ForkLeaseState::Failed);
        assert_eq!(failed.last_error.as_deref(), Some("worker exited"));
        assert!(db.list_active_fork_leases().unwrap().is_empty());
        assert_eq!(
            db.get_fork_pool_slot("slot-1").unwrap().unwrap().state,
            ForkPoolSlotState::Retiring
        );
    }
}
