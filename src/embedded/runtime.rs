//! Process-local runtime registry for embedded machines.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, RwLock};
use std::time::Duration;

use crate::agent::ExecEvent;
use crate::config::RecordState;
use crate::db::SmolvmDb;
use crate::embedded::control::{self, MachineSpec};
use crate::embedded::handle::VmHandle;
use crate::{Error, Result};
use smolvm_protocol::ImageInfo;

type SharedHandle = Arc<Mutex<VmHandle>>;

/// Stateful runtime shared by all embedded machine objects in this process.
pub struct EmbeddedRuntime {
    db: SmolvmDb,
    registry: RwLock<HashMap<String, SharedHandle>>,
    name_locks: RwLock<HashMap<String, Arc<Mutex<()>>>>,
}

impl EmbeddedRuntime {
    /// Create a runtime backed by the default smolvm database.
    pub fn new() -> Result<Self> {
        Ok(Self::with_db(SmolvmDb::open()?))
    }

    /// Create a runtime backed by an explicit database handle.
    pub fn with_db(db: SmolvmDb) -> Self {
        Self {
            db,
            registry: RwLock::new(HashMap::new()),
            name_locks: RwLock::new(HashMap::new()),
        }
    }

    /// Create a persisted machine record.
    pub fn create_machine(&self, spec: MachineSpec) -> Result<()> {
        self.with_name_lock(&spec.name, || control::create_vm(&self.db, &spec))
    }

    /// Start or reconnect to a persisted machine and cache its handle.
    pub fn start_machine(&self, name: &str) -> Result<()> {
        self.with_name_lock(name, || {
            if let Some(handle) = self.cached_handle(name)? {
                let alive = lock_handle(&handle)?.is_process_alive();
                if alive {
                    return Ok(());
                }
                self.remove_cached_handle(name)?;
            }

            let handle = control::start_vm(&self.db, name)?;
            self.insert_handle(name, handle)?;
            Ok(())
        })
    }

    /// Connect to an already-running machine and cache its handle.
    pub fn connect_machine(&self, name: &str) -> Result<()> {
        self.with_name_lock(name, || {
            if let Some(handle) = self.cached_handle(name)? {
                if lock_handle(&handle)?.is_process_alive() {
                    return Ok(());
                }
                self.remove_cached_handle(name)?;
            }

            let handle = control::connect_vm(&self.db, name)?;
            self.insert_handle(name, handle)?;
            Ok(())
        })
    }

    /// Stop a machine and persist stopped state.
    pub fn stop_machine(&self, name: &str) -> Result<()> {
        self.with_name_lock(name, || {
            if let Some(handle) = self.remove_cached_handle(name)? {
                lock_handle(&handle)?.stop()?;
                control::mark_stopped(&self.db, name)?;
                return Ok(());
            }

            control::stop_vm(&self.db, name)
        })
    }

    /// Stop best-effort, remove from the registry and DB, and delete storage.
    pub fn delete_machine(&self, name: &str) -> Result<()> {
        self.with_name_lock(name, || {
            if let Some(handle) = self.remove_cached_handle(name)? {
                let _ = lock_handle(&handle)?.stop();
            } else {
                let _ = control::stop_vm(&self.db, name);
            }

            control::delete_vm(&self.db, name)?;
            self.remove_name_lock(name)?;
            Ok(())
        })
    }

    /// Execute a command directly in the VM.
    pub fn exec(
        &self,
        name: &str,
        command: Vec<String>,
        env: Vec<(String, String)>,
        workdir: Option<String>,
        timeout: Option<Duration>,
    ) -> Result<(i32, Vec<u8>, Vec<u8>)> {
        let handle = self.started_handle(name)?;
        let mut handle = lock_handle(&handle)?;
        handle.exec(command, env, workdir, timeout)
    }

    /// Pull an OCI image and run a command inside it.
    pub fn run(
        &self,
        name: &str,
        image: &str,
        command: Vec<String>,
        env: Vec<(String, String)>,
        workdir: Option<String>,
        timeout: Option<Duration>,
    ) -> Result<(i32, Vec<u8>, Vec<u8>)> {
        let handle = self.started_handle(name)?;
        let mut handle = lock_handle(&handle)?;
        handle.run(image, command, env, workdir, timeout)
    }

    /// Pull an OCI image into the machine's storage.
    pub fn pull_image(&self, name: &str, image: &str) -> Result<ImageInfo> {
        let handle = self.started_handle(name)?;
        let mut handle = lock_handle(&handle)?;
        handle.pull_image(image)
    }

    /// List cached OCI images in the machine's storage.
    pub fn list_images(&self, name: &str) -> Result<Vec<ImageInfo>> {
        let handle = self.started_handle(name)?;
        let mut handle = lock_handle(&handle)?;
        handle.list_images()
    }

    /// Write a file into the machine.
    pub fn write_file(
        &self,
        name: &str,
        path: &str,
        data: Vec<u8>,
        mode: Option<u32>,
    ) -> Result<()> {
        let handle = self.started_handle(name)?;
        let mut handle = lock_handle(&handle)?;
        handle.write_file(path, &data, mode)
    }

    /// Read a file from the machine.
    pub fn read_file(&self, name: &str, path: &str) -> Result<Vec<u8>> {
        let handle = self.started_handle(name)?;
        let mut handle = lock_handle(&handle)?;
        handle.read_file(path)
    }

    /// Execute a command and collect streaming output events.
    pub fn exec_streaming(
        &self,
        name: &str,
        command: Vec<String>,
        env: Vec<(String, String)>,
        workdir: Option<String>,
        timeout: Option<Duration>,
    ) -> Result<Vec<ExecEvent>> {
        let handle = self.started_handle(name)?;
        let mut handle = lock_handle(&handle)?;
        handle.exec_streaming(command, env, workdir, timeout)
    }

    /// Get the child PID if the machine is running.
    pub fn pid(&self, name: &str) -> Option<i32> {
        if let Ok(Some(handle)) = self.cached_handle(name) {
            if let Ok(handle) = handle.lock() {
                if let Some(pid) = handle.child_pid() {
                    return Some(pid);
                }
            }
        }

        self.db
            .get_vm(name)
            .ok()
            .flatten()
            .and_then(|record| record.pid)
    }

    /// Return whether the machine process is currently running.
    pub fn is_running(&self, name: &str) -> bool {
        if let Ok(Some(handle)) = self.cached_handle(name) {
            if let Ok(handle) = handle.lock() {
                return handle.is_process_alive();
            }
        }

        self.db
            .get_vm(name)
            .ok()
            .flatten()
            .is_some_and(|record| record.actual_state() == RecordState::Running)
    }

    /// Get the current machine state as a string.
    pub fn state(&self, name: &str) -> String {
        if let Ok(Some(handle)) = self.cached_handle(name) {
            if let Ok(handle) = handle.lock() {
                return handle.state();
            }
        }

        match self.db.get_vm(name).ok().flatten() {
            Some(record) if record.actual_state() == RecordState::Running => "running".into(),
            Some(record) if record.actual_state() == RecordState::Failed => "failed".into(),
            _ => "stopped".into(),
        }
    }

    fn started_handle(&self, name: &str) -> Result<SharedHandle> {
        self.cached_handle(name)?
            .ok_or_else(|| Error::InvalidState {
                expected: "started".into(),
                actual: "not started".into(),
            })
    }

    fn cached_handle(&self, name: &str) -> Result<Option<SharedHandle>> {
        let registry = self
            .registry
            .read()
            .map_err(|e| Error::agent("runtime registry", e.to_string()))?;
        Ok(registry.get(name).cloned())
    }

    fn insert_handle(&self, name: &str, handle: VmHandle) -> Result<()> {
        let mut registry = self
            .registry
            .write()
            .map_err(|e| Error::agent("runtime registry", e.to_string()))?;
        registry.insert(name.to_string(), Arc::new(Mutex::new(handle)));
        Ok(())
    }

    fn remove_cached_handle(&self, name: &str) -> Result<Option<SharedHandle>> {
        let mut registry = self
            .registry
            .write()
            .map_err(|e| Error::agent("runtime registry", e.to_string()))?;
        Ok(registry.remove(name))
    }

    fn with_name_lock<T, F>(&self, name: &str, op: F) -> Result<T>
    where
        F: FnOnce() -> Result<T>,
    {
        let lock = self.lock_for_name(name)?;
        let _guard = lock_name(&lock)?;
        op()
    }

    fn lock_for_name(&self, name: &str) -> Result<Arc<Mutex<()>>> {
        if let Some(lock) = self
            .name_locks
            .read()
            .map_err(|e| Error::agent("runtime name locks", e.to_string()))?
            .get(name)
            .cloned()
        {
            return Ok(lock);
        }

        let mut locks = self
            .name_locks
            .write()
            .map_err(|e| Error::agent("runtime name locks", e.to_string()))?;
        Ok(locks
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone())
    }

    fn remove_name_lock(&self, name: &str) -> Result<()> {
        let mut locks = self
            .name_locks
            .write()
            .map_err(|e| Error::agent("runtime name locks", e.to_string()))?;
        locks.remove(name);
        Ok(())
    }
}

fn lock_name(lock: &Arc<Mutex<()>>) -> Result<MutexGuard<'_, ()>> {
    lock.lock()
        .map_err(|e| Error::agent("runtime name lock", e.to_string()))
}

fn lock_handle(handle: &SharedHandle) -> Result<MutexGuard<'_, VmHandle>> {
    handle
        .lock()
        .map_err(|e| Error::agent("runtime handle", e.to_string()))
}

/// Return the process-local embedded runtime singleton.
pub fn runtime() -> Result<Arc<EmbeddedRuntime>> {
    static RUNTIME: OnceLock<Arc<EmbeddedRuntime>> = OnceLock::new();

    if let Some(runtime) = RUNTIME.get() {
        return Ok(runtime.clone());
    }

    let runtime = Arc::new(EmbeddedRuntime::new()?);
    match RUNTIME.set(runtime.clone()) {
        Ok(()) => Ok(runtime),
        Err(_) => Ok(RUNTIME
            .get()
            .expect("runtime initialized by competing thread")
            .clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> SmolvmDb {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "smolvm-embedded-runtime-{}-{}.redb",
            std::process::id(),
            unique
        ));
        SmolvmDb::open_at(&path).unwrap()
    }

    fn test_spec(name: &str, persistent: bool) -> MachineSpec {
        MachineSpec {
            name: name.to_string(),
            mounts: Vec::new(),
            ports: Vec::new(),
            resources: crate::agent::VmResources::default(),
            persistent,
        }
    }

    #[test]
    fn remove_name_lock_removes_entry() {
        let runtime = EmbeddedRuntime::with_db(test_db());
        runtime.lock_for_name("runtime-remove-lock").unwrap();

        runtime.remove_name_lock("runtime-remove-lock").unwrap();

        assert!(runtime
            .name_locks
            .read()
            .expect("name locks should not be poisoned")
            .is_empty());
    }

    #[test]
    fn remove_name_lock_ignores_missing_entry() {
        let runtime = EmbeddedRuntime::with_db(test_db());
        runtime.remove_name_lock("runtime-missing-lock").unwrap();

        assert!(runtime
            .name_locks
            .read()
            .expect("name locks should not be poisoned")
            .is_empty());
    }

    #[test]
    fn runtime_rejects_duplicate_create() {
        let runtime = EmbeddedRuntime::with_db(test_db());
        runtime
            .create_machine(test_spec("runtime-duplicate", false))
            .unwrap();

        let err = runtime
            .create_machine(test_spec("runtime-duplicate", false))
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Agent {
                kind: crate::error::AgentErrorKind::Conflict,
                ..
            }
        ));
    }

    #[test]
    fn runtime_state_defaults_to_stopped_for_created_record() {
        let runtime = EmbeddedRuntime::with_db(test_db());
        runtime
            .create_machine(test_spec("runtime-state", true))
            .unwrap();

        assert_eq!(runtime.state("runtime-state"), "stopped");
        assert!(!runtime.is_running("runtime-state"));
        assert_eq!(runtime.pid("runtime-state"), None);
    }

    #[test]
    fn delete_machine_removes_name_lock_entry() {
        let runtime = EmbeddedRuntime::with_db(test_db());
        runtime
            .create_machine(test_spec("runtime-delete-lock", true))
            .unwrap();

        assert!(runtime
            .name_locks
            .read()
            .expect("name locks should not be poisoned")
            .contains_key("runtime-delete-lock"));

        runtime.delete_machine("runtime-delete-lock").unwrap();

        assert!(!runtime
            .name_locks
            .read()
            .expect("name locks should not be poisoned")
            .contains_key("runtime-delete-lock"));
    }
}
