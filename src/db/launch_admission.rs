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
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessIdentity {
    pid: i32,
    start: u64,
}

impl ProcessIdentity {
    fn current() -> Result<Self> {
        let pid = std::process::id() as i32;
        let start = crate::process::process_start_time(pid)
            .ok_or_else(|| conflict("cannot identify the startup process"))?;
        Ok(Self { pid, start })
    }

    fn may_be_alive(&self) -> bool {
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
}

/// Cancels an unclaimed launch on every normal failure path. Once admitted,
/// the helper remains durably tracked until its exact process has exited.
pub(crate) struct LaunchReservation {
    db: SmolvmDb,
    pub(crate) ticket: BootTicket,
    owner: ProcessIdentity,
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
    if launch.version != 1
        || launch.owner.pid <= 0
        || launch.child.as_ref().is_some_and(|child| child.pid <= 0)
        || !launch.storage.is_absolute()
        || launch.roots.iter().any(|root| !root.is_absolute())
        || launch.member.as_ref().is_some_and(|member| {
            crate::data::validate_vm_name(&member.name, "startup member").is_err()
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

    pub(crate) fn reserve_vm_launch(
        &self,
        provisional: Option<VmRecord>,
        storage: &Path,
        roots: &[PathBuf],
    ) -> Result<LaunchReservation> {
        let name = provisional.as_ref().map(|record| record.name.as_str());
        let _gate = self.admit_workload_mutation(name, roots)?;
        if let Some(name) = name {
            crate::data::validate_vm_name(name, "startup member")
                .map_err(|_| conflict("invalid startup member"))?;
        }
        let storage = storage.canonicalize()?;
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
            let mut inserted = false;
            for (token, launch) in rows(&tx)? {
                if launch.storage != storage
                    && !launch
                        .member
                        .as_ref()
                        .is_some_and(|member| Some(member.name.as_str()) == name)
                {
                    continue;
                }
                if launch.child.as_ref().map_or_else(
                    || launch.owner.may_be_alive(),
                    ProcessIdentity::may_be_alive,
                ) {
                    return Err(conflict("another launch still owns this machine"));
                }
                remove(&tx, &token)?;
            }
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
                Some(Member::from_record(&provisional.name, &record))
            } else {
                None
            };
            let launch = Launch {
                version: 1,
                owner,
                member,
                storage,
                roots,
                child: None,
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
            if launch.child.is_some() {
                return Err(conflict("startup ticket was already consumed"));
            }
            if !launch.owner.may_be_alive() {
                return Err(conflict("startup controller exited before boot admission"));
            }
            let transition = if let Some(member) = &launch.member {
                let data: Option<Vec<u8>> = tx
                    .query_row(
                        "SELECT data FROM vms WHERE name = ?1",
                        [&member.name],
                        |row| row.get(0),
                    )
                    .optional()
                    .db_err("read boot member")?;
                let mut record: VmRecord = serde_json::from_slice(
                    &data.ok_or_else(|| conflict("startup member was removed"))?,
                )
                .db_err("decode boot member")?;
                if Member::from_record(&member.name, &record) != *member {
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

/// Called in the same durable transaction that claims transfer authority.
pub(super) fn reconcile_transfer(
    tx: &Transaction<'_>,
    members: &[Member],
    roots: &[PathBuf],
) -> Result<()> {
    for (token, launch) in rows(tx)? {
        let reviewed = launch
            .member
            .as_ref()
            .and_then(|member| members.iter().find(|reviewed| reviewed.name == member.name));
        if reviewed.is_none()
            && !launch
                .roots
                .iter()
                .any(|root| roots.iter().any(|other| overlaps(root, other)))
        {
            continue;
        }
        if let Some(child) = &launch.child {
            if child.may_be_alive() {
                if !reviewed.is_some_and(|reviewed| {
                    Some(reviewed.created_at)
                        == launch.member.as_ref().map(|member| member.created_at)
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

/// Deletion must revoke delayed children atomically with name removal. A live
/// admitted child must be stopped first, even if another writer lost its PID.
pub(super) fn revoke_removed_member(tx: &Transaction<'_>, name: &str) -> Result<()> {
    for (token, launch) in rows(tx)? {
        if !launch
            .member
            .as_ref()
            .is_some_and(|member| member.name == name)
        {
            continue;
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
