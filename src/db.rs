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
    path: PathBuf,
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
            std::fs::create_dir_all(parent).map_err(|e| {
                Error::Database(format!("failed to create database directory: {}", e))
            })?;
        }

        let db = Database::create(path)
            .map_err(|e| Error::Database(format!("failed to open database: {}", e)))?;

        let instance = Self {
            db: Arc::new(RwLock::new(Some(db))),
            path: path.to_path_buf(),
        };

        // Initialize tables
        instance.init_tables()?;

        Ok(instance)
    }

    /// Temporarily close the database to release file locks.
    ///
    /// This is used before forking child processes to prevent them from
    /// inheriting the database file descriptor and holding the lock.
    ///
    /// Call `reopen()` after the fork to restore database access.
    pub fn close_temporarily(&self) {
        let mut db = self.db.write();
        *db = None;
        tracing::debug!("database closed temporarily");
    }

    /// Reopen the database after a temporary close.
    ///
    /// Call this after forking to restore database access.
    pub fn reopen(&self) -> Result<()> {
        let mut db = self.db.write();
        if db.is_none() {
            let new_db = Database::create(&self.path)
                .map_err(|e| Error::Database(format!("failed to reopen database: {}", e)))?;
            *db = Some(new_db);
            tracing::debug!("database reopened");
        }
        Ok(())
    }

    /// Check if the database is currently open.
    pub fn is_open(&self) -> bool {
        self.db.read().is_some()
    }

    /// Get the default database path.
    fn default_path() -> Result<PathBuf> {
        let data_dir = dirs::data_local_dir().ok_or_else(|| {
            Error::Database("could not determine local data directory".to_string())
        })?;
        Ok(data_dir.join("smolvm").join("server").join("smolvm.redb"))
    }

    /// Initialize database tables.
    fn init_tables(&self) -> Result<()> {
        let db_guard = self.db.read();
        let db = db_guard
            .as_ref()
            .ok_or_else(|| Error::Database("database is closed".to_string()))?;

        let write_txn = db
            .begin_write()
            .map_err(|e| Error::Database(format!("failed to begin write transaction: {}", e)))?;

        // Create tables if they don't exist
        write_txn
            .open_table(VMS_TABLE)
            .map_err(|e| Error::Database(format!("failed to create vms table: {}", e)))?;
        write_txn
            .open_table(CONFIG_TABLE)
            .map_err(|e| Error::Database(format!("failed to create config table: {}", e)))?;

        write_txn
            .commit()
            .map_err(|e| Error::Database(format!("failed to commit table creation: {}", e)))?;

        Ok(())
    }

    // ========================================================================
    // VM Operations
    // ========================================================================

    /// Insert or update a VM record.
    pub fn insert_vm(&self, name: &str, record: &VmRecord) -> Result<()> {
        let json = serde_json::to_vec(record)
            .map_err(|e| Error::Database(format!("failed to serialize VmRecord: {}", e)))?;

        let db_guard = self.db.read();
        let db = db_guard
            .as_ref()
            .ok_or_else(|| Error::Database("database is closed".to_string()))?;

        let write_txn = db
            .begin_write()
            .map_err(|e| Error::Database(format!("failed to begin write transaction: {}", e)))?;

        {
            let mut table = write_txn
                .open_table(VMS_TABLE)
                .map_err(|e| Error::Database(format!("failed to open vms table: {}", e)))?;
            table
                .insert(name, json.as_slice())
                .map_err(|e| Error::Database(format!("failed to insert VM '{}': {}", name, e)))?;
        }

        write_txn
            .commit()
            .map_err(|e| Error::Database(format!("failed to commit VM insert: {}", e)))?;

        Ok(())
    }

    /// Insert a VM record only if it doesn't already exist.
    ///
    /// Returns `Ok(true)` if inserted, `Ok(false)` if already exists.
    /// This provides atomic conflict detection at the database level.
    pub fn insert_vm_if_not_exists(&self, name: &str, record: &VmRecord) -> Result<bool> {
        let json = serde_json::to_vec(record)
            .map_err(|e| Error::Database(format!("failed to serialize VmRecord: {}", e)))?;

        let db_guard = self.db.read();
        let db = db_guard
            .as_ref()
            .ok_or_else(|| Error::Database("database is closed".to_string()))?;

        let write_txn = db
            .begin_write()
            .map_err(|e| Error::Database(format!("failed to begin write transaction: {}", e)))?;

        let inserted = {
            let mut table = write_txn
                .open_table(VMS_TABLE)
                .map_err(|e| Error::Database(format!("failed to open vms table: {}", e)))?;

            // Check if key already exists
            let exists = table
                .get(name)
                .map_err(|e| Error::Database(format!("failed to check VM '{}': {}", name, e)))?
                .is_some();

            if exists {
                false
            } else {
                table.insert(name, json.as_slice()).map_err(|e| {
                    Error::Database(format!("failed to insert VM '{}': {}", name, e))
                })?;
                true
            }
        };

        write_txn
            .commit()
            .map_err(|e| Error::Database(format!("failed to commit VM insert: {}", e)))?;

        Ok(inserted)
    }

    /// Get a VM record by name.
    pub fn get_vm(&self, name: &str) -> Result<Option<VmRecord>> {
        let db_guard = self.db.read();
        let db = db_guard
            .as_ref()
            .ok_or_else(|| Error::Database("database is closed".to_string()))?;

        let read_txn = db
            .begin_read()
            .map_err(|e| Error::Database(format!("failed to begin read transaction: {}", e)))?;

        let table = read_txn
            .open_table(VMS_TABLE)
            .map_err(|e| Error::Database(format!("failed to open vms table: {}", e)))?;

        match table.get(name) {
            Ok(Some(guard)) => {
                let record: VmRecord = serde_json::from_slice(guard.value()).map_err(|e| {
                    Error::Database(format!("failed to deserialize VmRecord '{}': {}", name, e))
                })?;
                Ok(Some(record))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(Error::Database(format!(
                "failed to get VM '{}': {}",
                name, e
            ))),
        }
    }

    /// Remove a VM record by name, returning the removed record if it existed.
    pub fn remove_vm(&self, name: &str) -> Result<Option<VmRecord>> {
        // First get the existing record
        let existing = self.get_vm(name)?;

        if existing.is_none() {
            return Ok(None);
        }

        let db_guard = self.db.read();
        let db = db_guard
            .as_ref()
            .ok_or_else(|| Error::Database("database is closed".to_string()))?;

        let write_txn = db
            .begin_write()
            .map_err(|e| Error::Database(format!("failed to begin write transaction: {}", e)))?;

        {
            let mut table = write_txn
                .open_table(VMS_TABLE)
                .map_err(|e| Error::Database(format!("failed to open vms table: {}", e)))?;
            table
                .remove(name)
                .map_err(|e| Error::Database(format!("failed to remove VM '{}': {}", name, e)))?;
        }

        write_txn
            .commit()
            .map_err(|e| Error::Database(format!("failed to commit VM removal: {}", e)))?;

        Ok(existing)
    }

    /// List all VM records.
    pub fn list_vms(&self) -> Result<Vec<(String, VmRecord)>> {
        let db_guard = self.db.read();
        let db = db_guard
            .as_ref()
            .ok_or_else(|| Error::Database("database is closed".to_string()))?;

        let read_txn = db
            .begin_read()
            .map_err(|e| Error::Database(format!("failed to begin read transaction: {}", e)))?;

        let table = read_txn
            .open_table(VMS_TABLE)
            .map_err(|e| Error::Database(format!("failed to open vms table: {}", e)))?;

        let mut vms = Vec::new();
        for entry in table
            .iter()
            .map_err(|e| Error::Database(format!("failed to iterate vms table: {}", e)))?
        {
            let (key, value) =
                entry.map_err(|e| Error::Database(format!("failed to read vms entry: {}", e)))?;
            let name = key.value().to_string();
            let record: VmRecord = serde_json::from_slice(value.value()).map_err(|e| {
                Error::Database(format!("failed to deserialize VmRecord '{}': {}", name, e))
            })?;
            vms.push((name, record));
        }

        Ok(vms)
    }

    /// Update a VM record in place using a closure.
    ///
    /// Returns `Some(())` if the VM was found and updated, `None` if not found.
    pub fn update_vm<F>(&self, name: &str, f: F) -> Result<Option<()>>
    where
        F: FnOnce(&mut VmRecord),
    {
        // Get existing record
        let mut record = match self.get_vm(name)? {
            Some(r) => r,
            None => return Ok(None),
        };

        // Apply the update
        f(&mut record);

        // Write back
        self.insert_vm(name, &record)?;

        Ok(Some(()))
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
            .ok_or_else(|| Error::Database("database is closed".to_string()))?;

        let read_txn = db
            .begin_read()
            .map_err(|e| Error::Database(format!("failed to begin read transaction: {}", e)))?;

        let table = read_txn
            .open_table(CONFIG_TABLE)
            .map_err(|e| Error::Database(format!("failed to open config table: {}", e)))?;

        match table.get(key) {
            Ok(Some(guard)) => Ok(Some(guard.value().to_string())),
            Ok(None) => Ok(None),
            Err(e) => Err(Error::Database(format!(
                "failed to get config '{}': {}",
                key, e
            ))),
        }
    }

    /// Set a global configuration value.
    pub fn set_config(&self, key: &str, value: &str) -> Result<()> {
        let db_guard = self.db.read();
        let db = db_guard
            .as_ref()
            .ok_or_else(|| Error::Database("database is closed".to_string()))?;

        let write_txn = db
            .begin_write()
            .map_err(|e| Error::Database(format!("failed to begin write transaction: {}", e)))?;

        {
            let mut table = write_txn
                .open_table(CONFIG_TABLE)
                .map_err(|e| Error::Database(format!("failed to open config table: {}", e)))?;
            table
                .insert(key, value)
                .map_err(|e| Error::Database(format!("failed to set config '{}': {}", key, e)))?;
        }

        write_txn
            .commit()
            .map_err(|e| Error::Database(format!("failed to commit config set: {}", e)))?;

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
    fn test_close_and_reopen() {
        let (_dir, db) = temp_db();

        // Insert a VM before closing
        let record = VmRecord::new("test-vm".to_string(), 1, 512, vec![], vec![], false);
        db.insert_vm("test-vm", &record).unwrap();

        // Verify database is open
        assert!(db.is_open());

        // Close temporarily
        db.close_temporarily();
        assert!(!db.is_open());

        // Operations should fail while closed
        assert!(db.get_vm("test-vm").is_err());
        assert!(db.list_vms().is_err());

        // Reopen
        db.reopen().unwrap();
        assert!(db.is_open());

        // Data should still be there after reopen
        let retrieved = db.get_vm("test-vm").unwrap().unwrap();
        assert_eq!(retrieved.name, "test-vm");

        // New operations should work
        let record2 = VmRecord::new("test-vm2".to_string(), 2, 1024, vec![], vec![], false);
        db.insert_vm("test-vm2", &record2).unwrap();

        let vms = db.list_vms().unwrap();
        assert_eq!(vms.len(), 2);
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
