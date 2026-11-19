//! Durable ownership between spawning a boot helper and publishing its PID.
//!
//! A helper must claim its ticket before opening VM disks. Revoking a pending
//! ticket prevents even a delayed helper from executing. An admitted helper is
//! never forgotten merely because its controller died. This is admission, not
//! a guest/device freeze barrier, and does not cover legacy boot entry points.

use super::transfer_admission::Member;
use super::{params, DbResultExt, OptionalExtension, SmolvmDb, TransactionBehavior};
use crate::config::{RecordState, VmRecord};
use crate::{Error, Result};
use rusqlite::Transaction;

pub(super) mod review;
pub(crate) use review::{LaunchReview, RecordIdentity};

mod creation;
pub use creation::VmCreationLease;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProcessIdentity {
    pub(super) pid: i32,
    pub(super) start: u64,
}

impl ProcessIdentity {
    pub(super) fn current() -> Result<Self> {
        let pid = std::process::id() as i32;
        let start = crate::process::process_start_time(pid)
            .ok_or_else(|| conflict("cannot identify the startup process"))?;
        Ok(Self { pid, start })
    }

    pub(super) fn may_be_alive(&self) -> bool {
        // Linux can positively identify an exited, unreaped thread group.
        #[cfg(target_os = "linux")]
        if !crate::process::is_alive(self.pid) {
            return false;
        }
        #[cfg(windows)]
        {
            use windows_sys::Win32::Foundation::{
                CloseHandle, GetLastError, ERROR_INVALID_PARAMETER, WAIT_OBJECT_0,
            };
            use windows_sys::Win32::System::Threading::{
                OpenProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE,
            };
            // SAFETY: request only a wait handle for the recorded, positive PID.
            let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, self.pid as u32) };
            if handle.is_null() {
                return unsafe { GetLastError() } != ERROR_INVALID_PARAMETER;
            }
            let alive = unsafe { WaitForSingleObject(handle, 0) } != WAIT_OBJECT_0;
            unsafe { CloseHandle(handle) };
            if !alive {
                return false;
            }
        }
        if let Some(actual) = crate::process::process_start_time(self.pid) {
            return actual == self.start;
        }
        // Failure to read identity is not evidence of exit (e.g. a VMM that
        // dropped privileges). Only definite absence permits reclamation.
        #[cfg(unix)]
        {
            (unsafe { libc::kill(self.pid, 0) }) == 0
                || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
        }
        #[cfg(not(unix))]
        {
            // Unknown identity stays fenced on platforms without an absence
            // probe. It is safe to recover after observing a reused PID.
            true
        }
    }
}

/// Host-only capability carried by the mandatory owned-boot entry point.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootTicket {
    /// Canonical database whose controller reserved this launch.
    pub database: PathBuf,
    /// Must also be passed separately on argv to reject a replaced config file.
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Launch {
    version: u32,
    owner: ProcessIdentity,
    member: Option<Member>,
    storage: PathBuf,
    roots: Vec<PathBuf>,
    child: Option<ProcessIdentity>,
    #[serde(default, skip_serializing_if = "Purpose::is_boot")]
    purpose: Purpose,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    exclusive_paths: Vec<PathBuf>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum Purpose {
    #[default]
    Boot,
    Prepare {
        name: Option<String>,
    },
    Create {
        name: String,
    },
}

impl Purpose {
    fn is_boot(&self) -> bool {
        matches!(self, Self::Boot)
    }
}

impl Launch {
    fn name(&self) -> Option<&str> {
        match &self.purpose {
            Purpose::Boot => self.member.as_ref().map(|member| member.name.as_str()),
            Purpose::Prepare { name } => name.as_deref(),
            Purpose::Create { name } => Some(name),
        }
    }

    fn paths(&self) -> impl Iterator<Item = &PathBuf> {
        std::iter::once(&self.storage).chain(self.exclusive_paths.iter())
    }

    fn alive(&self) -> bool {
        self.child.as_ref().unwrap_or(&self.owner).may_be_alive()
    }
}

/// Resolve the existing prefix before creating a disk or runtime file. A
/// dangling symlink is not a prospective regular path and must not be guessed.
pub(super) fn resource_path(path: &Path) -> std::io::Result<PathBuf> {
    let mut prefix = std::path::absolute(path)?;
    let mut tail = Vec::new();
    loop {
        match prefix.canonicalize() {
            Ok(mut path) => {
                for part in tail.into_iter().rev() {
                    path.push(part);
                }
                return Ok(path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match prefix.symlink_metadata() {
                    Ok(meta) if meta.file_type().is_symlink() => return Err(error),
                    Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                        return Err(error)
                    }
                    _ => {}
                }
                let part = prefix.file_name().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "unresolved workload path",
                    )
                })?;
                tail.push(part.to_owned());
                prefix.pop();
            }
            Err(error) => return Err(error),
        }
    }
}

/// Canonical spelling catches symlinks; file identity also catches hard links.
/// Metadata-only checks on Unix work for disks and sockets without opening them.
pub(super) fn same_resource(a: &Path, b: &Path) -> std::io::Result<bool> {
    if a == b {
        return Ok(true);
    }
    let metadata = |path: &Path| match path.metadata() {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    };
    let (Some(a_meta), Some(b_meta)) = (metadata(a)?, metadata(b)?) else {
        return Ok(false);
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(a_meta.dev() == b_meta.dev() && a_meta.ino() == b_meta.ino())
    }
    #[cfg(not(unix))]
    {
        let _ = (a_meta, b_meta);
        same_file::is_same_file(a, b)
    }
}

fn refuse_other_owners(
    tx: &Transaction<'_>,
    name: Option<&str>,
    paths: &[PathBuf],
    except: Option<&str>,
) -> Result<()> {
    super::recovery::refuse_conflicts(tx, name, paths)?;
    for (token, launch) in rows(tx)? {
        if except == Some(token.as_str()) {
            continue;
        }
        if !launch.alive() {
            remove(tx, &token)?;
            continue;
        }
        if name.is_some() && name == launch.name() {
            return Err(conflict("another launch still owns this machine"));
        }
        for owned in launch.paths() {
            for requested in paths {
                if overlaps(owned, requested) || same_resource(owned, requested)? {
                    return Err(conflict(
                        "another launch still owns this disk or runtime path",
                    ));
                }
            }
        }
    }
    if let Some(name) = name {
        let data: Option<Vec<u8>> = tx
            .query_row("SELECT data FROM vms WHERE name = ?1", [name], |row| {
                row.get(0)
            })
            .optional()
            .db_err("read preparation member")?;
        if let Some(data) = data {
            let record: VmRecord =
                serde_json::from_slice(&data).db_err("decode preparation member")?;
            if record.pid.is_some_and(|pid| {
                record.pid_start_time.map_or_else(
                    || crate::process::is_alive(pid),
                    |start| ProcessIdentity { pid, start }.may_be_alive(),
                )
            }) {
                return Err(conflict("the recorded machine process is still present"));
            }
        }
    }
    Ok(())
}

/// Cancels an unclaimed launch on every normal failure path. Once admitted,
/// the helper remains durably tracked until its exact process has exited.
pub(crate) struct LaunchReservation {
    db: SmolvmDb,
    pub(crate) ticket: BootTicket,
    owner: ProcessIdentity,
}

impl LaunchReservation {
    pub(crate) fn review(&self) -> Result<LaunchReview> {
        self.db.with_read_conn(|conn| {
            let data: Vec<u8> = conn
                .query_row(
                    "SELECT data FROM vm_launch_admission WHERE token = ?1",
                    [&self.ticket.token],
                    |row| row.get(0),
                )
                .db_err("read reserved startup identity")?;
            let launch = decode(&data)?;
            LaunchReview::from_member(&self.db, launch.member.as_ref())
        })
    }
}

impl Drop for LaunchReservation {
    fn drop(&mut self) {
        if self.owner.pid != std::process::id() as i32 {
            return;
        }
        if let Err(error) = self.db.cancel_pending_launch(&self.ticket.token) {
            tracing::warn!(%error, "startup ticket requires recovery");
        }
    }
}

fn conflict(message: &str) -> Error {
    Error::agent_conflict("admit VM startup", message)
}

fn decode(data: &[u8]) -> Result<Launch> {
    let launch: Launch = serde_json::from_slice(data)
        .map_err(|_| conflict("cannot read saved startup ownership"))?;
    if !matches!(launch.version, 1 | 2)
        || launch.owner.pid <= 0
        || launch.child.as_ref().is_some_and(|child| child.pid <= 0)
        || !launch.storage.is_absolute()
        || launch.roots.iter().any(|root| !root.is_absolute())
        || launch
            .exclusive_paths
            .iter()
            .any(|path| !path.is_absolute())
        || (!launch.purpose.is_boot() && (launch.member.is_some() || launch.child.is_some()))
        || launch
            .name()
            .is_some_and(|name| crate::data::validate_vm_name(name, "startup member").is_err())
        || launch.member.as_ref().is_some_and(|member| {
            crate::data::validate_vm_name(&member.name, "startup member").is_err()
                || !member.identity_valid(launch.version >= 2)
        })
    {
        return Err(conflict("unsupported saved startup ownership"));
    }
    Ok(launch)
}

fn rows(tx: &Transaction<'_>) -> Result<Vec<(String, Launch)>> {
    let mut statement = tx
        .prepare("SELECT token, data FROM vm_launch_admission")
        .db_err("read startup ownership")?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .db_err("query startup ownership")?;
    rows.map(|row| {
        let (token, data) = row.db_err("read startup ticket")?;
        Ok((token, decode(&data)?))
    })
    .collect()
}

fn remove(tx: &Transaction<'_>, token: &str) -> Result<()> {
    let data: Option<Vec<u8>> = tx
        .query_row(
            "SELECT data FROM vm_launch_admission WHERE token = ?1",
            [token],
            |row| row.get(0),
        )
        .optional()
        .db_err("read revoked ownership")?;
    if let Some(data) = data {
        if let Purpose::Create { name } = decode(&data)?.purpose {
            tx.execute(
                "DELETE FROM vm_create_reservations WHERE name = ?1 AND owner_token = ?2",
                params![name, token],
            )
            .db_err("retire creation name with ownership")?;
        }
    }
    tx.execute("DELETE FROM vm_launch_admission WHERE token = ?1", [token])
        .db_err("revoke startup ticket")?;
    Ok(())
}

fn overlaps(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}

impl SmolvmDb {
    /// The commit must reach stable storage before any helper may execute.
    pub(super) fn with_durable_conn<T>(
        &self,
        f: impl FnOnce(&mut rusqlite::Connection) -> Result<T>,
    ) -> Result<T> {
        self.with_conn(|conn| {
            conn.execute_batch("PRAGMA synchronous=FULL;")
                .db_err("enable durable startup")?;
            let result = f(conn);
            let restore = conn
                .execute_batch("PRAGMA synchronous=NORMAL;")
                .db_err("restore database synchronous mode");
            match result {
                Ok(value) => restore.map(|()| value),
                Err(error) => Err(error),
            }
        })
    }

    #[cfg(test)]
    pub(crate) fn reserve_vm_launch(
        &self,
        provisional: Option<VmRecord>,
        storage: &Path,
        roots: &[PathBuf],
        exclusive_paths: &[PathBuf],
    ) -> Result<LaunchReservation> {
        let review = LaunchReview::capture(self, provisional.as_ref().map(|r| r.name.as_str()))?;
        self.reserve_reviewed_vm_launch(&review, provisional, storage, roots, exclusive_paths)
    }

    pub(crate) fn reserve_reviewed_vm_launch(
        &self,
        review: &LaunchReview,
        provisional: Option<VmRecord>,
        storage: &Path,
        roots: &[PathBuf],
        exclusive_paths: &[PathBuf],
    ) -> Result<LaunchReservation> {
        let name = provisional.as_ref().map(|record| record.name.as_str());
        review.check_name(name)?;
        let paths = std::iter::once(storage.to_path_buf())
            .chain(exclusive_paths.iter().cloned())
            .collect::<Vec<_>>();
        let _gate = self.admit_startup_mutation(name, &paths)?;
        let _shares = self.admit_workload_mutation(name, roots)?;
        if let Some(name) = name {
            crate::data::validate_vm_name(name, "startup member")
                .map_err(|_| conflict("invalid startup member"))?;
        }
        let storage = storage.canonicalize()?;
        let exclusive_paths = exclusive_paths
            .iter()
            .map(|path| resource_path(path))
            .collect::<std::io::Result<Vec<_>>>()?;
        let roots = roots
            .iter()
            .map(|root| root.canonicalize())
            .collect::<std::io::Result<Vec<_>>>()?;
        let owner = ProcessIdentity::current()?;
        let token = rand::random::<[u8; 24]>()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let reservation = LaunchReservation {
            db: self.clone(),
            ticket: BootTicket {
                database: self.path.canonicalize()?,
                token,
            },
            owner: owner.clone(),
        };
        let inserted = self.with_durable_conn(|conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .db_err("begin startup reservation")?;
            review.validate_conn(self, &tx)?;
            let mut inserted = false;
            refuse_other_owners(
                &tx,
                name,
                &std::iter::once(storage.clone())
                    .chain(exclusive_paths.iter().cloned())
                    .collect::<Vec<_>>(),
                None,
            )?;
            let member = if let Some(provisional) = &provisional {
                let data: Option<Vec<u8>> = tx
                    .query_row(
                        "SELECT data FROM vms WHERE name = ?1",
                        [&provisional.name],
                        |row| row.get(0),
                    )
                    .optional()
                    .db_err("read startup member")?;
                let record = if let Some(data) = data {
                    serde_json::from_slice::<VmRecord>(&data).db_err("decode startup member")?
                } else {
                    let reserved: bool = tx
                        .query_row(
                            "SELECT EXISTS(SELECT 1 FROM vm_create_reservations WHERE name = ?1)",
                            [&provisional.name],
                            |row| row.get(0),
                        )
                        .db_err("check create reservation")?;
                    if reserved {
                        return Err(conflict("machine creation is still in progress"));
                    }
                    tx.execute(
                        "INSERT INTO vms(name, data) VALUES (?1, ?2)",
                        params![
                            provisional.name,
                            serde_json::to_vec(provisional).db_err("encode startup member")?
                        ],
                    )
                    .db_err("record provisional startup member")?;
                    inserted = true;
                    provisional.clone()
                };
                if record.pid.is_some_and(|pid| {
                    record.pid_start_time.map_or_else(
                        || crate::process::is_alive(pid),
                        |start| ProcessIdentity { pid, start }.may_be_alive(),
                    )
                }) {
                    return Err(conflict("the recorded machine process is still present"));
                }
                Some(Member::read(&tx, &provisional.name)?.0)
            } else {
                None
            };
            let launch = Launch {
                version: 2,
                owner,
                member,
                storage,
                roots,
                child: None,
                purpose: Purpose::Boot,
                exclusive_paths,
            };
            tx.execute(
                "INSERT INTO vm_launch_admission(token, data) VALUES (?1, ?2)",
                params![
                    reservation.ticket.token,
                    serde_json::to_vec(&launch).db_err("encode startup ticket")?
                ],
            )
            .db_err("reserve startup ticket")?;
            tx.commit().db_err("commit startup reservation")?;
            Ok(inserted)
        })?;
        if inserted {
            if let Some(record) = &provisional {
                self.journal_insert(&record.name, record);
            }
        }
        Ok(reservation)
    }

    /// Own creation/growth before touching disks, without inventing a VM record
    /// or holding a database write lock during filesystem work. Boot and other
    /// preparation reservations use the same atomic conflict check.
    #[cfg(test)]
    pub(crate) fn reserve_vm_preparation(
        &self,
        name: Option<&str>,
        storage: &Path,
        exclusive_paths: &[PathBuf],
    ) -> Result<LaunchReservation> {
        let review = LaunchReview::capture(self, name)?;
        self.reserve_reviewed_vm_preparation(&review, name, storage, exclusive_paths)
    }

    pub(crate) fn reserve_reviewed_vm_preparation(
        &self,
        review: &LaunchReview,
        name: Option<&str>,
        storage: &Path,
        exclusive_paths: &[PathBuf],
    ) -> Result<LaunchReservation> {
        review.check_name(name)?;
        if let Some(name) = name {
            crate::data::validate_vm_name(name, "preparation member")
                .map_err(|_| conflict("invalid preparation member"))?;
        }
        let paths = std::iter::once(storage.to_path_buf())
            .chain(exclusive_paths.iter().cloned())
            .map(|path| resource_path(&path))
            .collect::<std::io::Result<Vec<_>>>()?;
        let _gate = self.admit_startup_mutation(name, &paths)?;
        let owner = ProcessIdentity::current()?;
        let token = rand::random::<[u8; 24]>()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let reservation = LaunchReservation {
            db: self.clone(),
            owner: owner.clone(),
            ticket: BootTicket {
                database: self.path.canonicalize()?,
                token,
            },
        };
        self.with_durable_conn(|conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .db_err("begin disk preparation")?;
            review.validate_conn(self, &tx)?;
            refuse_other_owners(&tx, name, &paths, None)?;
            let launch = Launch {
                version: 2,
                owner,
                member: None,
                storage: paths[0].clone(),
                exclusive_paths: paths[1..].to_vec(),
                roots: Vec::new(),
                child: None,
                purpose: Purpose::Prepare {
                    name: name.map(str::to_owned),
                },
            };
            tx.execute(
                "INSERT INTO vm_launch_admission(token, data) VALUES (?1, ?2)",
                params![
                    reservation.ticket.token,
                    serde_json::to_vec(&launch).db_err("encode disk preparation")?
                ],
            )
            .db_err("reserve disk preparation")?;
            tx.commit().db_err("commit disk preparation")
        })?;
        Ok(reservation)
    }

    fn cancel_pending_launch(&self, token: &str) -> Result<()> {
        // Serializes against child admission; no OS gate is required to remove
        // authority. Never removes an admitted process, even after an error.
        self.with_durable_conn(|conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .db_err("begin startup cancellation")?;
            let data: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT data FROM vm_launch_admission WHERE token = ?1",
                    [token],
                    |row| row.get(0),
                )
                .optional()
                .db_err("read startup cancellation")?;
            if let Some(data) = data {
                if decode(&data)?.child.is_none() {
                    remove(&tx, token)?;
                }
            }
            tx.commit().db_err("commit startup cancellation")
        })
    }

    /// Called only by the mandatory owned-boot entry point, before VM setup.
    pub(crate) fn admit_vm_boot(&self, token: &str) -> Result<()> {
        // A transfer's exclusive gate and this transaction establish one order
        // for revoking pending tickets versus registering an executing helper.
        let _gate = self.transfer_gate(false)?;
        let child = ProcessIdentity::current()?;
        let transition = self.with_durable_conn(|conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .db_err("begin boot admission")?;
            let data: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT data FROM vm_launch_admission WHERE token = ?1",
                    [token],
                    |row| row.get(0),
                )
                .optional()
                .db_err("read boot admission")?;
            let mut launch =
                decode(&data.ok_or_else(|| conflict("startup was cancelled or recovered"))?)?;
            if !launch.purpose.is_boot() {
                return Err(conflict("disk preparation does not authorize VM execution"));
            }
            if launch.child.is_some() {
                return Err(conflict("startup ticket was already consumed"));
            }
            if !launch.owner.may_be_alive() {
                return Err(conflict("startup controller exited before boot admission"));
            }
            let transition = if let Some(member) = &launch.member {
                let (current, mut record) = Member::read(&tx, &member.name)?;
                if current != *member {
                    return Err(conflict("startup member changed before admission"));
                }
                let before = record.clone();
                record.pid = Some(child.pid);
                record.pid_start_time = Some(child.start);
                // Register the process without consuming saved execution. A
                // failed restore must still be retryable from its checkpoint.
                if !matches!(record.state, RecordState::Paused | RecordState::Pausing) {
                    record.state = RecordState::Running;
                }
                record.engine_build = Some(crate::ENGINE_BUILD.to_owned());
                tx.execute(
                    "UPDATE vms SET data = ?2 WHERE name = ?1",
                    params![
                        member.name,
                        serde_json::to_vec(&record).db_err("encode boot member")?
                    ],
                )
                .db_err("publish boot process identity")?;
                Some((member.name.clone(), before, record))
            } else {
                None
            };
            launch.child = Some(child);
            tx.execute(
                "UPDATE vm_launch_admission SET data = ?2 WHERE token = ?1",
                params![
                    token,
                    serde_json::to_vec(&launch).db_err("encode boot admission")?
                ],
            )
            .db_err("record boot admission")?;
            tx.commit().db_err("commit boot admission")?;
            Ok(transition)
        })?;
        if let Some((name, before, after)) = transition {
            crate::usage::on_update(&name, &before, &after);
        }
        Ok(())
    }
}

/// Keep the admitted execution's disk/runtime paths fenced through recovery.
pub(super) fn recovery_paths(
    tx: &Transaction<'_>,
    member: &Member,
    runtime: &Path,
) -> Result<Vec<PathBuf>> {
    let mut paths = std::collections::BTreeSet::from([runtime.to_path_buf()]);
    for (_, launch) in rows(tx)? {
        if launch.name() == Some(member.name.as_str()) {
            paths.extend(launch.paths().cloned());
        }
    }
    Ok(paths.into_iter().collect())
}

/// Called in the same durable transaction that claims transfer authority.
pub(super) fn reconcile_transfer(
    tx: &Transaction<'_>,
    members: &[Member],
    roots: &[PathBuf],
) -> Result<()> {
    for (token, launch) in rows(tx)? {
        let reviewed = members
            .iter()
            .find(|reviewed| Some(reviewed.name.as_str()) == launch.name());
        let mut relevant = reviewed.is_some();
        for path in launch.paths().chain(launch.roots.iter()) {
            for root in roots {
                relevant |= overlaps(path, root) || same_resource(path, root)?;
            }
        }
        if !relevant {
            continue;
        }
        if let Some(child) = &launch.child {
            if child.may_be_alive() {
                if !reviewed.is_some_and(|reviewed| {
                    launch
                        .member
                        .as_ref()
                        .is_some_and(|member| reviewed.same_incarnation(member))
                        && reviewed.pid == Some(child.pid)
                        && reviewed.pid_start_time == Some(child.start)
                }) {
                    return Err(conflict(
                        "an executing startup was not included in the environment review",
                    ));
                }
                // The reviewed child remains tracked while the coordinator
                // establishes the separate whole-group freeze/I/O barrier.
                continue;
            }
        } else if launch.owner.may_be_alive() {
            return Err(conflict("an environment startup is still pending"));
        }
        remove(tx, &token)?;
    }
    Ok(())
}

/// Deletion must wait for a live controller's preparation or an admitted child
/// to finish, then revoke delayed children atomically with name removal.
pub(super) fn revoke_removed_member(tx: &Transaction<'_>, name: &str) -> Result<()> {
    for (token, launch) in rows(tx)? {
        if launch.name() != Some(name) {
            continue;
        }
        if launch.child.is_none() && launch.owner.may_be_alive() {
            return Err(conflict("disk preparation is still in progress"));
        }
        if launch
            .child
            .as_ref()
            .is_some_and(ProcessIdentity::may_be_alive)
        {
            return Err(conflict(
                "stop the admitted startup process before removing its machine",
            ));
        }
        remove(tx, &token)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
