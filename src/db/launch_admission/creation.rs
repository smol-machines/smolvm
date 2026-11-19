//! Creation ownership spans preparation, publication, and failure cleanup.

use super::*;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

/// A creation and its blocking workers share one lifetime. The last worker
/// cleans up before releasing the name; publication requires all workers done.
#[derive(Clone)]
pub struct VmCreationLease(Arc<CreationOwner>);

struct CreationOwner {
    db: SmolvmDb,
    name: String,
    token: String,
    owner: ProcessIdentity,
    data_dir: PathBuf,
    committed: AtomicBool,
}

impl VmCreationLease {
    /// Reserve a new machine before preparing any name-derived state.
    pub fn reserve(db: SmolvmDb, name: &str) -> Result<Self> {
        let token = SmolvmDb::create_reservation_token();
        if !db.reserve_vm_create(name, &token)? {
            return Err(conflict("machine already exists or is being created"));
        }
        Self::from_reserved(db, name, token)
    }

    pub(crate) fn from_reserved(db: SmolvmDb, name: &str, token: String) -> Result<Self> {
        let data_dir = db.creation_data_dir(name, &token)?;
        let lease = Self(Arc::new(CreationOwner {
            db,
            name: name.to_owned(),
            token,
            owner: ProcessIdentity::current()?,
            data_dir,
            committed: AtomicBool::new(false),
        }));
        // An exited creator can leave partial disks or extraction output. A new
        // creation starts clean while it exclusively owns the unpublished name.
        lease.0.cleanup_files()?;
        crate::agent::ensure_vm_dir_at(&lease.0.data_dir, name)?;
        Ok(lease)
    }

    /// The name whose preparation this capability owns.
    pub fn name(&self) -> &str {
        &self.0.name
    }

    pub(crate) fn token(&self) -> &str {
        &self.0.token
    }
    pub(crate) fn db(&self) -> &SmolvmDb {
        &self.0.db
    }

    pub(crate) fn ensure_exclusive(&self) -> Result<()> {
        if Arc::strong_count(&self.0) != 1 {
            return Err(conflict("machine preparation workers are still active"));
        }
        self.db().check_creation_owner(self.name(), self.token())
    }

    pub(crate) fn disarm(&self) {
        self.0.committed.store(true, Ordering::Release);
    }

    /// Publish only after every preparation worker has relinquished its clone.
    pub fn commit(&self, record: &VmRecord) -> Result<()> {
        self.ensure_exclusive()?;
        if !self
            .db()
            .commit_reserved_vm(self.name(), self.token(), record)?
        {
            return Err(conflict("machine creation is no longer owned"));
        }
        self.disarm();
        Ok(())
    }

    pub(crate) fn admit_preparation(
        &self,
        paths: &[PathBuf],
    ) -> Result<super::super::transfer_admission::MutationGuard> {
        if resource_path(&crate::agent::vm_data_dir(self.name()))? != self.0.data_dir {
            return Err(conflict(
                "creation state directory changed during preparation",
            ));
        }
        let gate = self.db().admit_startup_mutation(Some(self.name()), paths)?;
        let paths = paths
            .iter()
            .map(|path| resource_path(path))
            .collect::<std::io::Result<Vec<_>>>()?;
        self.db().with_durable_conn(|conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .db_err("begin creation preparation")?;
            let mut launch = owned_creation(&tx, self.name(), self.token())?;
            refuse_other_owners(&tx, Some(self.name()), &paths, Some(self.token()))?;
            for path in paths {
                if path != launch.storage && !launch.exclusive_paths.contains(&path) {
                    launch.exclusive_paths.push(path);
                }
            }
            tx.execute(
                "UPDATE vm_launch_admission SET data = ?2 WHERE token = ?1",
                params![
                    self.token(),
                    serde_json::to_vec(&launch).db_err("encode creation preparation")?
                ],
            )
            .db_err("extend creation preparation")?;
            tx.commit().db_err("commit creation preparation")
        })?;
        Ok(gate)
    }
}

impl Drop for CreationOwner {
    fn drop(&mut self) {
        if self.owner.pid != std::process::id() as i32 || self.committed.load(Ordering::Acquire) {
            return;
        }
        // A stale capability must never remove a replacement's files. New
        // creators cannot acquire this name until cleanup and release finish.
        if let Err(error) = self.db.check_creation_owner(&self.name, &self.token) {
            tracing::warn!(name = %self.name, %error, "preserving files after loss of creation ownership");
            return;
        }
        if let Err(error) = self.cleanup_files() {
            tracing::warn!(name = %self.name, %error, "could not clean unfinished creation data");
        }
        if let Err(error) = self
            .db
            .release_vm_create_reservation(&self.name, &self.token)
        {
            tracing::warn!(name = %self.name, %error, "could not release creation ownership");
        }
    }
}

impl CreationOwner {
    fn cleanup_files(&self) -> Result<()> {
        self.db.check_creation_owner(&self.name, &self.token)?;
        if !self.db.dependent_clones(&self.name)?.is_empty() {
            return Err(conflict("unpublished machine still has dependent clones"));
        }
        let dir = &self.data_dir;
        let metadata = match dir.symlink_metadata() {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(conflict("creation directory is not an owned directory"));
        }
        match std::fs::read_to_string(dir.join("name")) {
            Ok(name) if name == self.name => {}
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && std::fs::read_dir(dir)?.next().is_none() => {}
            _ => return Err(conflict("creation directory has no matching name binding")),
        }
        smolvm_pack::extract::force_detach_layers_volume(&dir.join("pack"));
        match std::fs::remove_dir_all(dir) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

fn saved_creation(tx: &Transaction<'_>, name: &str, token: &str) -> Result<Option<Launch>> {
    let data: Option<Vec<u8>> = tx
        .query_row(
            "SELECT data FROM vm_launch_admission WHERE token = ?1",
            [token],
            |row| row.get(0),
        )
        .optional()
        .db_err("read creation ownership")?;
    let Some(data) = data else {
        return Ok(None);
    };
    let launch = decode(&data)?;
    if !matches!(&launch.purpose, Purpose::Create { name: owned } if owned == name) {
        return Err(conflict(
            "creation ownership does not match its reservation",
        ));
    }
    Ok(Some(launch))
}

fn owned_creation(tx: &Transaction<'_>, name: &str, token: &str) -> Result<Launch> {
    let reserved: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM vm_create_reservations WHERE name = ?1 AND owner_token = ?2)", params![name, token], |row| row.get(0)).db_err("check creation reservation")?;
    let launch = saved_creation(tx, name, token)?
        .ok_or_else(|| conflict("creation ownership is missing"))?;
    if !reserved || launch.owner != ProcessIdentity::current()? {
        return Err(conflict("creation belongs to another owner"));
    }
    let exists: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM vms WHERE name = ?1)",
            [name],
            |row| row.get(0),
        )
        .db_err("check unpublished creation")?;
    if exists {
        return Err(conflict("creation already has a published machine"));
    }
    Ok(launch)
}

impl SmolvmDb {
    /// Generate an opaque capability, unrelated to clocks or process IDs.
    pub fn create_reservation_token() -> String {
        rand::random::<[u8; 24]>()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    /// Reserve a name and its directory until its exact creating process exits
    /// or explicitly publishes/releases it. A live import never expires by age.
    pub fn reserve_vm_create(&self, name: &str, token: &str) -> Result<bool> {
        crate::data::validate_vm_name(name, "create machine").map_err(|error| conflict(&error))?;
        if token.is_empty()
            || token.len() > 128
            || !token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(conflict("invalid creation capability"));
        }
        let dir = crate::agent::vm_data_dir(name);
        match dir.symlink_metadata() {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(conflict("creation directory cannot be a symlink"))
            }
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
            _ => {}
        }
        let mut paths = vec![resource_path(&dir)?];
        for filename in [
            crate::storage::STORAGE_DISK_FILENAME,
            crate::storage::OVERLAY_DISK_FILENAME,
        ] {
            paths.push(resource_path(
                &crate::agent::resolve_disk_image(&dir, filename).0,
            )?);
        }
        let _gate = self.admit_startup_mutation(Some(name), &paths)?;
        let owner = ProcessIdentity::current()?;
        self.with_durable_conn(|conn| {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate).db_err("begin creation ownership")?;
            let prior: Option<(String, i64)> = tx.query_row("SELECT owner_token, owner_pid FROM vm_create_reservations WHERE name = ?1", [name], |row| Ok((row.get(0)?, row.get(1)?))).optional().db_err("read prior creation")?;
            if let Some((prior_token, pid)) = prior {
                let alive = match saved_creation(&tx, name, &prior_token)? {
                    Some(launch) => launch.owner.may_be_alive(),
                    // Legacy reservations have no process start identity: only
                    // definite absence permits recovery, never elapsed time.
                    None => pid > 0 && (pid > i64::from(i32::MAX) || crate::process::is_alive(pid as i32)),
                };
                if alive { return Ok(false); }
                tx.execute("DELETE FROM vm_create_reservations WHERE name = ?1", [name]).db_err("retire dead creation")?;
                remove(&tx, &prior_token)?;
            }
            let exists: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM vms WHERE name = ?1)", [name], |row| row.get(0)).db_err("check creation name")?;
            if exists { return Ok(false); }
            refuse_other_owners(&tx, Some(name), &paths, None)?;
            let launch = Launch { version: 1, owner: owner.clone(), member: None, storage: paths[0].clone(), roots: vec![], child: None, purpose: Purpose::Create { name: name.to_owned() }, exclusive_paths: paths[1..].to_vec() };
            tx.execute("INSERT INTO vm_launch_admission(token, data) VALUES (?1, ?2)", params![token, serde_json::to_vec(&launch).db_err("encode creation owner")?]).db_err("reserve creation owner")?;
            tx.execute("INSERT INTO vm_create_reservations(name, owner_token, owner_pid, created_at) VALUES (?1, ?2, ?3, ?4)", params![name, token, owner.pid, crate::util::current_timestamp()]).db_err("reserve creation name")?;
            tx.commit().db_err("commit creation ownership")?;
            Ok(true)
        })
    }

    fn creation_data_dir(&self, name: &str, token: &str) -> Result<PathBuf> {
        self.with_conn(|conn| {
            let tx = conn.transaction().db_err("inspect creation owner")?;
            Ok(owned_creation(&tx, name, token)?.storage)
        })
    }

    fn check_creation_owner(&self, name: &str, token: &str) -> Result<()> {
        self.creation_data_dir(name, token).map(|_| ())
    }

    /// Publish the record and release ownership in one durable transaction.
    pub fn commit_reserved_vm(&self, name: &str, token: &str, record: &VmRecord) -> Result<bool> {
        if record.name != name {
            return Err(conflict("creation record names another machine"));
        }
        self.with_durable_conn(|conn| {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate).db_err("begin creation publication")?;
            let reserved: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM vm_create_reservations WHERE name = ?1 AND owner_token = ?2)", params![name, token], |row| row.get(0)).db_err("check creation token")?;
            if !reserved { return Ok(false); }
            owned_creation(&tx, name, token)?;
            tx.execute("INSERT INTO vms(name, data) VALUES (?1, ?2)", params![name, serde_json::to_vec(record).db_err("encode created machine")?]).db_err("publish created machine")?;
            tx.execute("DELETE FROM vm_create_reservations WHERE name = ?1 AND owner_token = ?2", params![name, token]).db_err("release published creation")?;
            remove(&tx, token)?;
            tx.commit().db_err("commit creation publication")?;
            Ok(true)
        }).inspect(|inserted| { if *inserted { self.journal_insert(name, record); } })
    }

    /// Release an uncommitted reservation after its filesystem work is done.
    pub fn release_vm_create_reservation(&self, name: &str, token: &str) -> Result<()> {
        self.with_durable_conn(|conn| {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate).db_err("begin creation release")?;
            let reserved: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM vm_create_reservations WHERE name = ?1 AND owner_token = ?2)", params![name, token], |row| row.get(0)).db_err("check creation release")?;
            if !reserved { return Ok(()); }
            owned_creation(&tx, name, token)?;
            tx.execute("DELETE FROM vm_create_reservations WHERE name = ?1 AND owner_token = ?2", params![name, token]).db_err("release creation reservation")?;
            remove(&tx, token)?;
            tx.commit().db_err("commit creation release")
        })
    }
}

#[cfg(test)]
mod tests;
