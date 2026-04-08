//! Process-local runtime registry for NAPI machines.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, RwLock};
use std::time::Duration;

use smolvm::agent::ExecEvent;
use smolvm::config::RecordState;
use smolvm::db::SmolvmDb;
use smolvm::{Error, Result};
use smolvm_protocol::ImageInfo;

use crate::control::{self, MachineSpec};
use crate::handle::VmHandle;

type SharedHandle = Arc<Mutex<VmHandle>>;

/// Stateful runtime shared by all NAPI machine objects in this process.
pub(crate) struct NapiRuntime {
    db: SmolvmDb,
    registry: RwLock<HashMap<String, SharedHandle>>,
    name_locks: RwLock<HashMap<String, Arc<Mutex<()>>>>,
}

impl NapiRuntime {
    pub(crate) fn new() -> Result<Self> {
        Ok(Self::with_db(SmolvmDb::open()?))
    }

    pub(crate) fn with_db(db: SmolvmDb) -> Self {
        Self {
            db,
            registry: RwLock::new(HashMap::new()),
            name_locks: RwLock::new(HashMap::new()),
        }
    }

    /// Create a persisted machine record.
    pub(crate) fn create_machine(&self, spec: MachineSpec) -> Result<()> {
        self.with_name_lock(&spec.name, || control::create_vm(&self.db, &spec))
    }

    /// Start or reconnect to a persisted machine and cache its handle.
    pub(crate) fn start_machine(&self, name: &str) -> Result<()> {
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
    pub(crate) fn connect_machine(&self, name: &str) -> Result<()> {
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
    pub(crate) fn stop_machine(&self, name: &str) -> Result<()> {
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
    pub(crate) fn delete_machine(&self, name: &str) -> Result<()> {
        self.with_name_lock(name, || {
            if let Some(handle) = self.remove_cached_handle(name)? {
                let _ = lock_handle(&handle)?.stop();
            } else {
                let _ = control::stop_vm(&self.db, name);
            }

            control::delete_vm(&self.db, name)
        })
    }

    pub(crate) fn exec(
        &self,
        name: &str,
        command: Vec<String>,
        env: Vec<(String, String)>,
        workdir: Option<String>,
        timeout: Option<Duration>,
    ) -> Result<(i32, String, String)> {
        let handle = self.started_handle(name)?;
        let mut handle = lock_handle(&handle)?;
        handle.exec(command, env, workdir, timeout)
    }

    pub(crate) fn run(
        &self,
        name: &str,
        image: &str,
        command: Vec<String>,
        env: Vec<(String, String)>,
        workdir: Option<String>,
        timeout: Option<Duration>,
    ) -> Result<(i32, String, String)> {
        let handle = self.started_handle(name)?;
        let mut handle = lock_handle(&handle)?;
        handle.run(image, command, env, workdir, timeout)
    }

    pub(crate) fn pull_image(&self, name: &str, image: &str) -> Result<ImageInfo> {
        let handle = self.started_handle(name)?;
        let mut handle = lock_handle(&handle)?;
        handle.pull_image(image)
    }

    pub(crate) fn list_images(&self, name: &str) -> Result<Vec<ImageInfo>> {
        let handle = self.started_handle(name)?;
        let mut handle = lock_handle(&handle)?;
        handle.list_images()
    }

    pub(crate) fn write_file(
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

    pub(crate) fn read_file(&self, name: &str, path: &str) -> Result<Vec<u8>> {
        let handle = self.started_handle(name)?;
        let mut handle = lock_handle(&handle)?;
        handle.read_file(path)
    }

    pub(crate) fn exec_streaming(
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

    pub(crate) fn pid(&self, name: &str) -> Option<i32> {
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

    pub(crate) fn is_running(&self, name: &str) -> bool {
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

    pub(crate) fn state(&self, name: &str) -> String {
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
        let result = {
            let _guard = lock_name(&lock)?;
            op()
        };
        let cleanup = self.cleanup_name_lock(name, &lock);

        match (result, cleanup) {
            (Err(err), _) => Err(err),
            (Ok(value), Ok(())) => Ok(value),
            (Ok(_), Err(err)) => Err(err),
        }
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

    fn cleanup_name_lock(&self, name: &str, lock: &Arc<Mutex<()>>) -> Result<()> {
        let mut locks = self
            .name_locks
            .write()
            .map_err(|e| Error::agent("runtime name locks", e.to_string()))?;

        let should_remove = locks
            .get(name)
            .is_some_and(|entry| Arc::ptr_eq(entry, lock) && Arc::strong_count(entry) == 2);

        if should_remove {
            locks.remove(name);
        }

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

pub(crate) fn runtime() -> Result<Arc<NapiRuntime>> {
    static RUNTIME: OnceLock<Arc<NapiRuntime>> = OnceLock::new();

    if let Some(runtime) = RUNTIME.get() {
        return Ok(runtime.clone());
    }

    let runtime = Arc::new(NapiRuntime::new()?);
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
            "smolvm-napi-runtime-{}-{}.redb",
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
            resources: smolvm::agent::VmResources::default(),
            persistent,
        }
    }

    #[test]
    fn cleanup_name_lock_removes_unused_entry() {
        let runtime = NapiRuntime::with_db(test_db());
        let lock = runtime.lock_for_name("runtime-cleanup-unused").unwrap();

        runtime
            .cleanup_name_lock("runtime-cleanup-unused", &lock)
            .unwrap();

        assert!(runtime
            .name_locks
            .read()
            .expect("name locks should not be poisoned")
            .is_empty());
    }

    #[test]
    fn cleanup_name_lock_keeps_entry_while_other_clones_exist() {
        let runtime = NapiRuntime::with_db(test_db());
        let lock = runtime.lock_for_name("runtime-cleanup-retained").unwrap();
        let extra = lock.clone();

        runtime
            .cleanup_name_lock("runtime-cleanup-retained", &lock)
            .unwrap();

        assert!(runtime
            .name_locks
            .read()
            .expect("name locks should not be poisoned")
            .contains_key("runtime-cleanup-retained"));

        drop(extra);

        runtime
            .cleanup_name_lock("runtime-cleanup-retained", &lock)
            .unwrap();

        assert!(runtime
            .name_locks
            .read()
            .expect("name locks should not be poisoned")
            .is_empty());
    }

    #[test]
    fn runtime_rejects_duplicate_create() {
        let runtime = NapiRuntime::with_db(test_db());
        runtime
            .create_machine(test_spec("runtime-duplicate", false))
            .unwrap();

        assert!(runtime
            .name_locks
            .read()
            .expect("name locks should not be poisoned")
            .is_empty());

        let err = runtime
            .create_machine(test_spec("runtime-duplicate", false))
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Agent {
                kind: smolvm::error::AgentErrorKind::Conflict,
                ..
            }
        ));
        assert!(runtime
            .name_locks
            .read()
            .expect("name locks should not be poisoned")
            .is_empty());
    }

    #[test]
    fn runtime_state_defaults_to_stopped_for_created_record() {
        let runtime = NapiRuntime::with_db(test_db());
        runtime
            .create_machine(test_spec("runtime-state", true))
            .unwrap();

        assert!(runtime
            .name_locks
            .read()
            .expect("name locks should not be poisoned")
            .is_empty());

        assert_eq!(runtime.state("runtime-state"), "stopped");
        assert!(!runtime.is_running("runtime-state"));
        assert_eq!(runtime.pid("runtime-state"), None);
    }
}
