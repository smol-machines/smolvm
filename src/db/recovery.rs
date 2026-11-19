//! Pin the reviewed machine row while recovery performs external side effects.
//!
//! SQLite triggers fence even legacy row writers. No write transaction remains
//! open during process waits or filesystem cleanup. This is not a freeze barrier
//! for guest I/O, nor authority over arbitrary host filesystem changes.

use super::launch_admission::{resource_path, LaunchReview, ProcessIdentity};
use super::transfer_admission::{Member, MutationGuard};
use super::{params, Connection, DbResultExt, OptionalExtension, SmolvmDb, TransactionBehavior};
use crate::{config::VmRecord, Error, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Recovery {
    version: u32,
    owner: ProcessIdentity,
    member: Member,
    paths: Vec<PathBuf>,
}

fn conflict(message: &str) -> Error {
    Error::agent_conflict("recover machine", message)
}

fn installed(conn: &Connection) -> Result<bool> {
    conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='vm_recovery_owners')", [], |r| r.get(0)).db_err("inspect recovery ownership schema")
}

pub(super) fn install(conn: &mut Connection) -> Result<()> {
    if installed(conn)? {
        return Ok(());
    }
    conn.execute_batch("PRAGMA synchronous=FULL;")
        .db_err("enable durable recovery ownership")?;
    let result = (|| {
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .db_err("begin recovery ownership migration")?;
        if !installed(&tx)? {
            tx.execute_batch("CREATE TABLE vm_recovery_owners (name TEXT PRIMARY KEY NOT NULL, token TEXT NOT NULL, data BLOB NOT NULL);").db_err("create recovery ownership")?;
            for table in ["vms", "vm_incarnations"] {
                for (action, names) in [
                    ("INSERT", "NEW.name"),
                    ("UPDATE", "OLD.name, NEW.name"),
                    ("DELETE", "OLD.name"),
                ] {
                    tx.execute_batch(&format!(
                        "CREATE TRIGGER vm_recovery_{table}_{action} BEFORE {action} ON {table}
                         WHEN EXISTS(SELECT 1 FROM vm_recovery_owners WHERE name IN ({names})) BEGIN
                         SELECT RAISE(ABORT, 'machine execution is owned by recovery'); END;"
                    ))
                    .db_err("install recovery ownership fence")?;
                }
            }
        }
        tx.commit().db_err("commit recovery ownership migration")
    })();
    let restored = conn
        .execute_batch("PRAGMA synchronous=NORMAL;")
        .db_err("restore database durability policy");
    result.and(restored)
}

fn rows(conn: &Connection) -> Result<Vec<(String, String, Recovery)>> {
    let mut statement = conn
        .prepare("SELECT name, token, data FROM vm_recovery_owners")
        .db_err("read recovery owners")?;
    let rows = statement
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Vec<u8>>(2)?,
            ))
        })
        .db_err("query recovery owners")?;
    rows.map(|row| {
        let (name, token, bytes) = row.db_err("read recovery owner")?;
        let saved: Recovery = serde_json::from_slice(&bytes)
            .map_err(|_| conflict("saved recovery ownership is corrupt"))?;
        if saved.version != 1
            || saved.member.name != name
            || !saved.member.identity_valid(true)
            || saved.owner.pid <= 0
            || saved.owner.start == 0
            || saved.paths.is_empty()
            || saved.paths.len() > 1024
            || saved.paths.iter().any(|p| !p.is_absolute())
            || token.len() != 48
            || !token.bytes().all(|v| v.is_ascii_hexdigit())
        {
            return Err(conflict("saved recovery ownership is unsupported"));
        }
        Ok((name, token, saved))
    })
    .collect()
}

fn overlaps_recovery(
    saved: &Recovery,
    name: &str,
    machine: Option<&str>,
    paths: &[PathBuf],
) -> Result<bool> {
    if machine == Some(name) {
        return Ok(true);
    }
    for owned in &saved.paths {
        for path in paths {
            if owned.starts_with(path)
                || path.starts_with(owned)
                || super::launch_admission::same_resource(owned, path)?
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Called inside the caller's write transaction, before preparing a launch.
/// A definitely dead owner can no longer perform side effects; unknown identity
/// stays fenced. Removing its row never resumes or signals the guest.
pub(super) fn refuse_conflicts(
    conn: &Connection,
    machine: Option<&str>,
    paths: &[PathBuf],
) -> Result<()> {
    for (name, token, saved) in rows(conn)? {
        if !saved.owner.may_be_alive() {
            conn.execute(
                "DELETE FROM vm_recovery_owners WHERE name=?1 AND token=?2",
                params![name, token],
            )
            .db_err("retire exited recovery owner")?;
            continue;
        }
        if overlaps_recovery(&saved, &name, machine, paths)? {
            return Err(conflict(
                "this machine is being recovered; retry after recovery finishes",
            ));
        }
    }
    Ok(())
}

pub(crate) struct VmRecoveryGuard {
    db: SmolvmDb,
    record: VmRecord,
    token: String,
    owner: ProcessIdentity,
    runtime: PathBuf,
    active: bool,
    _admission: MutationGuard,
}

impl SmolvmDb {
    pub(crate) fn check_recovery_admission(
        &self,
        machine: Option<&str>,
        paths: &[PathBuf],
    ) -> Result<()> {
        let owners = self.with_read_conn(|conn| rows(conn))?;
        if owners.is_empty() {
            return Ok(());
        }
        let paths = paths
            .iter()
            .map(|p| resource_path(p))
            .collect::<std::io::Result<Vec<_>>>()?;
        let mut reclaim = false;
        for (name, _, saved) in owners {
            if !overlaps_recovery(&saved, &name, machine, &paths)? {
                continue;
            }
            if saved.owner.may_be_alive() {
                return Err(conflict(
                    "this machine is being recovered; retry after recovery finishes",
                ));
            }
            reclaim = true;
        }
        // Nested metadata updates may already own a SQLite writer. Unrelated
        // live or abandoned recoveries must never make them acquire another.
        if !reclaim {
            return Ok(());
        }
        self.with_durable_conn(|conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .db_err("begin recovery admission")?;
            refuse_conflicts(&tx, machine, &paths)?;
            tx.commit().db_err("commit recovery admission")
        })
    }

    pub(crate) fn reserve_vm_recovery(&self, record: &VmRecord) -> Result<VmRecoveryGuard> {
        let admission = self.admit_machine_mutation(&record.name)?;
        let review = LaunchReview::from_record(record)?;
        let runtime = resource_path(&crate::agent::vm_data_dir(&record.name))?;
        let owner = ProcessIdentity::current()?;
        let token: String = rand::random::<[u8; 24]>()
            .iter()
            .map(|v| format!("{v:02x}"))
            .collect();
        self.with_durable_conn(|conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .db_err("begin recovery ownership")?;
            refuse_conflicts(&tx, Some(&record.name), std::slice::from_ref(&runtime))?;
            review.validate_conn(self, &tx)?;
            let (member, current) = Member::read(&tx, &record.name)?;
            if (current.pid, current.pid_start_time) != (record.pid, record.pid_start_time) {
                return Err(conflict("machine execution changed before recovery"));
            }
            super::launch_admission::reconcile_transfer(
                &tx,
                std::slice::from_ref(&member),
                std::slice::from_ref(&runtime),
            )?;
            let paths = super::launch_admission::recovery_paths(&tx, &member, &runtime)?;
            super::launch_admission::reconcile_transfer(
                &tx,
                std::slice::from_ref(&member),
                &paths,
            )?;
            refuse_conflicts(&tx, Some(&record.name), &paths)?;
            let saved = Recovery {
                version: 1,
                owner: owner.clone(),
                member,
                paths,
            };
            tx.execute(
                "INSERT INTO vm_recovery_owners(name,token,data) VALUES (?1,?2,?3)",
                params![
                    record.name,
                    token,
                    serde_json::to_vec(&saved).db_err("encode recovery ownership")?
                ],
            )
            .db_err("reserve recovery ownership")?;
            tx.commit().db_err("commit recovery ownership")
        })?;
        Ok(VmRecoveryGuard {
            db: self.clone(),
            record: record.clone(),
            token,
            owner,
            runtime,
            active: true,
            _admission: admission,
        })
    }
}

impl VmRecoveryGuard {
    pub(crate) fn runtime_dir(&self) -> &Path {
        &self.runtime
    }

    /// Release ownership and publish stopped state as one durable transition.
    pub(crate) fn mark_stopped(mut self) -> Result<()> {
        if self.owner != ProcessIdentity::current()? {
            return Err(conflict("recovery belongs to another process"));
        }
        let (before, after) = self.db.with_durable_conn(|conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .db_err("begin recovery completion")?;
            let token: Option<String> = tx
                .query_row(
                    "SELECT token FROM vm_recovery_owners WHERE name=?1",
                    [&self.record.name],
                    |r| r.get(0),
                )
                .optional()
                .db_err("read recovery completion owner")?;
            if token.as_deref() != Some(&self.token) {
                return Err(conflict("recovery ownership changed"));
            }
            LaunchReview::from_record(&self.record)?.validate_conn(&self.db, &tx)?;
            let (_, before) = Member::read(&tx, &self.record.name)?;
            if (before.pid, before.pid_start_time) != (self.record.pid, self.record.pid_start_time)
            {
                return Err(conflict("machine execution changed during recovery"));
            }
            let mut after = before.clone();
            after.mark_process_stopped();
            tx.execute(
                "DELETE FROM vm_recovery_owners WHERE name=?1 AND token=?2",
                params![self.record.name, self.token],
            )
            .db_err("release recovery ownership")?;
            tx.execute(
                "UPDATE vms SET data=?2 WHERE name=?1",
                params![
                    self.record.name,
                    serde_json::to_vec(&after).db_err("encode recovered machine")?
                ],
            )
            .db_err("publish recovered machine")?;
            tx.commit().db_err("commit recovery completion")?;
            Ok((before, after))
        })?;
        self.active = false;
        crate::usage::on_update(&self.record.name, &before, &after);
        Ok(())
    }
}

impl Drop for VmRecoveryGuard {
    fn drop(&mut self) {
        if !self.active || self.owner.pid != std::process::id() as i32 {
            return;
        }
        let result = self.db.with_durable_conn(|conn| {
            conn.execute(
                "DELETE FROM vm_recovery_owners WHERE name=?1 AND token=?2",
                params![self.record.name, self.token],
            )
            .db_err("release failed recovery ownership")?;
            Ok(())
        });
        if let Err(error) = result {
            tracing::warn!(%error, "recovery ownership needs reconciliation");
        }
    }
}

#[cfg(test)]
mod tests;
