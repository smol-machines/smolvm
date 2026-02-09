//! Database module for persistent state storage.
//!
//! This module provides ACID-compliant storage using redb for
//! VM state persistence with atomic transactions and concurrent access safety.

use crate::config::VmRecord;
use crate::error::{Error, Result};
use parking_lot::RwLock;
use redb::{Database, ReadableTable, TableDefinition};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Table for storing VM records (name -> JSON-serialized VmRecord).
const VMS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("vms");

/// Table for storing global configuration settings.
const CONFIG_TABLE: TableDefinition<&str, &str> = TableDefinition::new("config");

/// Thread-safe database handle for smolvm state persistence.
///
/// Supports close/reopen to release file locks before forking child processes.
#[derive(Clone)]
pub struct SmolvmDb {
    db: Arc<RwLock<Option<Database>>>,
}

impl std::fmt::Debug for SmolvmDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmolvmDb").finish_non_exhaustive()
    }
}

impl SmolvmDb {
    /// Open the database at the default location.
    ///
    /// Default path: `~/Library/Application Support/smolvm/server/smolvm.redb` (macOS)
    /// or `~/.local/share/smolvm/server/smolvm.redb` (Linux)
    ///
    /// If the database doesn't exist, it will be created.
    pub fn open() -> Result<Self> {
        let path = Self::default_path()?;
        Self::open_at(&path)
    }

    /// Open the database at a specific path.
    ///
    /// Creates parent directories if they don't exist.
    pub fn open_at(path: &Path) -> Result<Self> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::database("create directory", e.to_string()))?;
        }

        let db = Database::create(path).map_err(|e| Error::database("open", e.to_string()))?;

        let instance = Self {
            db: Arc::new(RwLock::new(Some(db))),
        };

        // Initialize tables
        instance.init_tables()?;

        Ok(instance)
    }

    /// Get the default database path.
    fn default_path() -> Result<PathBuf> {
        let data_dir = dirs::data_local_dir().ok_or_else(|| {
            Error::database_unavailable("could not determine local data directory")
        })?;
        Ok(data_dir.join("smolvm").join("server").join("smolvm.redb"))
    }

    /// Initialize database tables.
    fn init_tables(&self) -> Result<()> {
        let db_guard = self.db.read();
        let db = db_guard
            .as_ref()
            .ok_or_else(|| Error::database_unavailable("database is closed"))?;

        let write_txn = db
            .begin_write()
            .map_err(|e| Error::database("begin write transaction", e.to_string()))?;

        // Create tables if they don't exist
        write_txn
            .open_table(VMS_TABLE)
            .map_err(|e| Error::database("create vms table", e.to_string()))?;
        write_txn
            .open_table(CONFIG_TABLE)
            .map_err(|e| Error::database("create config table", e.to_string()))?;

        write_txn
            .commit()
            .map_err(|e| Error::database("commit table creation", e.to_string()))?;

        Ok(())
    }

    // ========================================================================
    // VM Operations
    // ========================================================================

    /// Insert or update a VM record.
    pub fn insert_vm(&self, name: &str, record: &VmRecord) -> Result<()> {
        let json = serde_json::to_vec(record)
            .map_err(|e| Error::database("serialize vm record", e.to_string()))?;

        let db_guard = self.db.read();
        let db = db_guard
            .as_ref()
            .ok_or_else(|| Error::database_unavailable("database is closed"))?;

        let write_txn = db
            .begin_write()
            .map_err(|e| Error::database("begin write transaction", e.to_string()))?;

        {
            let mut table = write_txn
                .open_table(VMS_TABLE)
                .map_err(|e| Error::database("open vms table", e.to_string()))?;
            table
                .insert(name, json.as_slice())
                .map_err(|e| Error::database(format!("insert vm '{}'", name), e.to_string()))?;
        }

        write_txn
            .commit()
            .map_err(|e| Error::database("commit vm insert", e.to_string()))?;

        Ok(())
    }

    /// Insert a VM record only if it doesn't already exist.
    ///
    /// Returns `Ok(true)` if inserted, `Ok(false)` if already exists.
    /// This provides atomic conflict detection at the database level.
    pub fn insert_vm_if_not_exists(&self, name: &str, record: &VmRecord) -> Result<bool> {
        let json = serde_json::to_vec(record)
            .map_err(|e| Error::database("serialize vm record", e.to_string()))?;

        let db_guard = self.db.read();
        let db = db_guard
            .as_ref()
            .ok_or_else(|| Error::database_unavailable("database is closed"))?;

        let write_txn = db
            .begin_write()
            .map_err(|e| Error::database("begin write transaction", e.to_string()))?;

        let inserted = {
            let mut table = write_txn
                .open_table(VMS_TABLE)
                .map_err(|e| Error::database("open vms table", e.to_string()))?;

            // Check if key already exists
            let exists = table
                .get(name)
                .map_err(|e| Error::database(format!("check vm '{}'", name), e.to_string()))?
                .is_some();

            if exists {
                false
            } else {
                table
                    .insert(name, json.as_slice())
                    .map_err(|e| Error::database(format!("insert vm '{}'", name), e.to_string()))?;
                true
            }
        };

        write_txn
            .commit()
            .map_err(|e| Error::database("commit vm insert", e.to_string()))?;

        Ok(inserted)
    }

    /// Get a VM record by name.
    pub fn get_vm(&self, name: &str) -> Result<Option<VmRecord>> {
        let db_guard = self.db.read();
        let db = db_guard
            .as_ref()
            .ok_or_else(|| Error::database_unavailable("database is closed"))?;

        let read_txn = db
            .begin_read()
            .map_err(|e| Error::database("begin read transaction", e.to_string()))?;

        let table = read_txn
            .open_table(VMS_TABLE)
            .map_err(|e| Error::database("open vms table", e.to_string()))?;

        match table.get(name) {
            Ok(Some(guard)) => {
                let record: VmRecord = serde_json::from_slice(guard.value()).map_err(|e| {
                    Error::database(format!("deserialize vm record '{}'", name), e.to_string())
                })?;
                Ok(Some(record))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(Error::database(format!("get vm '{}'", name), e.to_string())),
        }
    }

    /// Remove a VM record by name, returning the removed record if it existed.
    ///
    /// Uses a single write transaction to atomically read and delete the record,
    /// preventing TOCTOU races with concurrent writers.
    pub fn remove_vm(&self, name: &str) -> Result<Option<VmRecord>> {
        let db_guard = self.db.read();
        let db = db_guard
            .as_ref()
            .ok_or_else(|| Error::database_unavailable("database is closed"))?;

        let write_txn = db
            .begin_write()
            .map_err(|e| Error::database("begin write transaction", e.to_string()))?;

        let existing = {
            let mut table = write_txn
                .open_table(VMS_TABLE)
                .map_err(|e| Error::database("open vms table", e.to_string()))?;

            // Read and deserialize first, releasing the AccessGuard before mutation
            let record = {
                let get_result = table
                    .get(name)
                    .map_err(|e| Error::database(format!("get vm '{}'", name), e.to_string()))?;
                match get_result {
                    Some(guard) => {
                        let r: VmRecord = serde_json::from_slice(guard.value()).map_err(|e| {
                            Error::database(
                                format!("deserialize vm record '{}'", name),
                                e.to_string(),
                            )
                        })?;
                        Some(r)
                    }
                    None => None,
                }
            };

            // Now safe to mutate — AccessGuard is dropped
            if record.is_some() {
                table
                    .remove(name)
                    .map_err(|e| Error::database(format!("remove vm '{}'", name), e.to_string()))?;
            }
            record
        };

        write_txn
            .commit()
            .map_err(|e| Error::database("commit vm removal", e.to_string()))?;

        Ok(existing)
    }

    /// List all VM records.
    pub fn list_vms(&self) -> Result<Vec<(String, VmRecord)>> {
        let db_guard = self.db.read();
        let db = db_guard
            .as_ref()
            .ok_or_else(|| Error::database_unavailable("database is closed"))?;

        let read_txn = db
            .begin_read()
            .map_err(|e| Error::database("begin read transaction", e.to_string()))?;

        let table = read_txn
            .open_table(VMS_TABLE)
            .map_err(|e| Error::database("open vms table", e.to_string()))?;

        let mut vms = Vec::new();
        for entry in table
            .iter()
            .map_err(|e| Error::database("iterate vms table", e.to_string()))?
        {
            let (key, value) =
                entry.map_err(|e| Error::database("read vms entry", e.to_string()))?;
            let name = key.value().to_string();
            let record: VmRecord = serde_json::from_slice(value.value()).map_err(|e| {
                Error::database(format!("deserialize vm record '{}'", name), e.to_string())
            })?;
            vms.push((name, record));
        }

        Ok(vms)
    }

    /// Update a VM record in place using a closure.
    ///
    /// Returns `Some(())` if the VM was found and updated, `None` if not found.
    ///
    /// Uses a single write transaction to atomically read, mutate, and write back,
    /// preventing lost updates from concurrent writers.
    pub fn update_vm<F>(&self, name: &str, f: F) -> Result<Option<()>>
    where
        F: FnOnce(&mut VmRecord),
    {
        let db_guard = self.db.read();
        let db = db_guard
            .as_ref()
            .ok_or_else(|| Error::database_unavailable("database is closed"))?;

        let write_txn = db
            .begin_write()
            .map_err(|e| Error::database("begin write transaction", e.to_string()))?;

        let updated = {
            let mut table = write_txn
                .open_table(VMS_TABLE)
                .map_err(|e| Error::database("open vms table", e.to_string()))?;

            // Read and deserialize first, releasing the AccessGuard before mutation
            let record = {
                let get_result = table
                    .get(name)
                    .map_err(|e| Error::database(format!("get vm '{}'", name), e.to_string()))?;
                match get_result {
                    Some(guard) => {
                        let r: VmRecord = serde_json::from_slice(guard.value()).map_err(|e| {
                            Error::database(
                                format!("deserialize vm record '{}'", name),
                                e.to_string(),
                            )
                        })?;
                        Some(r)
                    }
                    None => None,
                }
            };

            // Now safe to mutate — AccessGuard is dropped
            match record {
                Some(mut record) => {
                    f(&mut record);
                    let json = serde_json::to_vec(&record)
                        .map_err(|e| Error::database("serialize vm record", e.to_string()))?;
                    table.insert(name, json.as_slice()).map_err(|e| {
                        Error::database(format!("update vm '{}'", name), e.to_string())
                    })?;
                    true
                }
                None => false,
            }
        };

        write_txn
            .commit()
            .map_err(|e| Error::database("commit vm update", e.to_string()))?;

        Ok(if updated { Some(()) } else { None })
    }

    /// Load all VMs into an in-memory HashMap (for compatibility layer).
    pub fn load_all_vms(&self) -> Result<HashMap<String, VmRecord>> {
        let vms = self.list_vms()?;
        Ok(vms.into_iter().collect())
    }

    // ========================================================================
    // Global Config Operations
    // ========================================================================

    /// Get a global configuration value.
    pub fn get_config(&self, key: &str) -> Result<Option<String>> {
        let db_guard = self.db.read();
        let db = db_guard
            .as_ref()
            .ok_or_else(|| Error::database_unavailable("database is closed"))?;

        let read_txn = db
            .begin_read()
            .map_err(|e| Error::database("begin read transaction", e.to_string()))?;

        let table = read_txn
            .open_table(CONFIG_TABLE)
            .map_err(|e| Error::database("open config table", e.to_string()))?;

        match table.get(key) {
            Ok(Some(guard)) => Ok(Some(guard.value().to_string())),
            Ok(None) => Ok(None),
            Err(e) => Err(Error::database(
                format!("get config '{}'", key),
                e.to_string(),
            )),
        }
    }

    /// Set a global configuration value.
    pub fn set_config(&self, key: &str, value: &str) -> Result<()> {
        let db_guard = self.db.read();
        let db = db_guard
            .as_ref()
            .ok_or_else(|| Error::database_unavailable("database is closed"))?;

        let write_txn = db
            .begin_write()
            .map_err(|e| Error::database("begin write transaction", e.to_string()))?;

        {
            let mut table = write_txn
                .open_table(CONFIG_TABLE)
                .map_err(|e| Error::database("open config table", e.to_string()))?;
            table
                .insert(key, value)
                .map_err(|e| Error::database(format!("set config '{}'", key), e.to_string()))?;
        }

        write_txn
            .commit()
            .map_err(|e| Error::database("commit config set", e.to_string()))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RecordState;
    use tempfile::TempDir;

    fn temp_db() -> (TempDir, SmolvmDb) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.redb");
        let db = SmolvmDb::open_at(&path).unwrap();
        (dir, db)
    }

    #[test]
    fn test_db_crud_operations() {
        let (_dir, db) = temp_db();

        // Create a VM record
        let record = VmRecord::new(
            "test-vm".to_string(),
            2,
            1024,
            vec![("/host".to_string(), "/guest".to_string(), false)],
            vec![(8080, 80)],
            false,
        );

        // Insert
        db.insert_vm("test-vm", &record).unwrap();

        // Get
        let retrieved = db.get_vm("test-vm").unwrap().unwrap();
        assert_eq!(retrieved.name, "test-vm");
        assert_eq!(retrieved.cpus, 2);
        assert_eq!(retrieved.mem, 1024);

        // Update
        db.update_vm("test-vm", |r| {
            r.state = RecordState::Running;
            r.pid = Some(12345);
        })
        .unwrap();

        let updated = db.get_vm("test-vm").unwrap().unwrap();
        assert_eq!(updated.state, RecordState::Running);
        assert_eq!(updated.pid, Some(12345));

        // List
        let vms = db.list_vms().unwrap();
        assert_eq!(vms.len(), 1);
        assert_eq!(vms[0].0, "test-vm");

        // Remove
        let removed = db.remove_vm("test-vm").unwrap().unwrap();
        assert_eq!(removed.name, "test-vm");

        // Verify removed
        assert!(db.get_vm("test-vm").unwrap().is_none());
    }

    #[test]
    fn test_db_concurrent_access() {
        let (_dir, db) = temp_db();

        // Create multiple VMs from different threads
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

        // Verify all VMs were created
        let vms = db.list_vms().unwrap();
        assert_eq!(vms.len(), 10);
    }

    #[test]
    fn test_config_settings() {
        let (_dir, db) = temp_db();

        // Set config
        db.set_config("test_key", "test_value").unwrap();

        // Get config
        let value = db.get_config("test_key").unwrap().unwrap();
        assert_eq!(value, "test_value");

        // Get non-existent config
        assert!(db.get_config("nonexistent").unwrap().is_none());
    }

    #[test]
    fn test_update_nonexistent_vm() {
        let (_dir, db) = temp_db();

        // Update should return None for non-existent VM
        let result = db.update_vm("nonexistent", |_| {}).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_remove_nonexistent_vm() {
        let (_dir, db) = temp_db();

        // Remove should return None for non-existent VM
        let result = db.remove_vm("nonexistent").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_insert_vm_if_not_exists() {
        let (_dir, db) = temp_db();

        let record = VmRecord::new("test-vm".to_string(), 1, 512, vec![], vec![], false);

        // First insert should succeed
        let inserted = db.insert_vm_if_not_exists("test-vm", &record).unwrap();
        assert!(inserted, "first insert should succeed");

        // Second insert with same name should return false
        let inserted = db.insert_vm_if_not_exists("test-vm", &record).unwrap();
        assert!(!inserted, "second insert should fail (already exists)");

        // Verify only one VM exists
        let vms = db.list_vms().unwrap();
        assert_eq!(vms.len(), 1);

        // Different name should succeed
        let record2 = VmRecord::new("test-vm2".to_string(), 2, 1024, vec![], vec![], false);
        let inserted = db.insert_vm_if_not_exists("test-vm2", &record2).unwrap();
        assert!(inserted, "different name should succeed");

        let vms = db.list_vms().unwrap();
        assert_eq!(vms.len(), 2);
    }

    #[test]
    fn test_insert_vm_if_not_exists_concurrent() {
        let (_dir, db) = temp_db();

        // Try to insert the same name from multiple threads
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

        // Exactly one should have succeeded
        let success_count = results.iter().filter(|&&r| r).count();
        assert_eq!(success_count, 1, "exactly one insert should succeed");

        // Verify only one VM exists
        let vms = db.list_vms().unwrap();
        assert_eq!(vms.len(), 1);
    }
}
