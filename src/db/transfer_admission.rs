//! Durable admission for a workload transfer within one engine state root.
//!
//! This is cooperative admission for guarded mutations, not proof of quiescence. The
//! coordinator must still inventory existing users, freeze every member, drain
//! I/O, revalidate metadata, and capture the complete workload. In particular,
//! this cannot fence another engine state root or arbitrary host processes.
//! A process crash never releases an admission; only explicit recovery does.
//! Older runtime binaries that do not participate in admission are not fenced.
//! The capture coordinator must cover every writer and recover interrupted
//! launches before using this primitive to authorize a remote handoff.

use super::{params, OptionalExtension, SmolvmDb, TransactionBehavior};
use crate::config::VmRecord;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};

/// Execution identity reviewed before a coordinator claims its whole group.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Member {
    /// Named machine within this database's engine state root.
    pub name: String,
    /// Creation identity observed during dependency review.
    pub created_at: u64,
    /// VMM process observed during dependency review, if it is running.
    pub pid: Option<i32>,
    /// Host process start time, distinguishing a reused PID.
    pub pid_start_time: Option<u64>,
}

impl Member {
    /// Bind a reviewed machine record to its current execution generation.
    pub fn from_record(name: &str, record: &VmRecord) -> Self {
        Self {
            name: name.to_owned(),
            created_at: record.created_at,
            pid: record.pid,
            pid_start_time: record.pid_start_time,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Claim {
    version: u32,
    members: Vec<Member>,
    roots: Vec<PathBuf>,
}

/// Keep this guard until the admitted mutation, including process registration,
/// has finished. Claim creation cannot pass a live guard from another process.
pub struct MutationGuard {
    _gate: File,
}

fn conflict(message: &str) -> Error {
    Error::agent_conflict("move environment", message)
}

fn overlaps(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}

fn operation_valid(operation: &str) -> bool {
    !operation.is_empty()
        && operation.len() <= 128
        && operation
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
}

fn decode(data: &[u8]) -> Result<Claim> {
    let claim: Claim = serde_json::from_slice(data).map_err(|_| {
        conflict("the saved transfer admission cannot be read; recover the transfer first")
    })?;
    let mut names = BTreeSet::new();
    if claim.version != 1
        || claim.members.is_empty()
        || claim.members.len() > 1024
        || claim.roots.len() > 1024
        || claim.roots.iter().any(|path| !path.is_absolute())
        || claim.members.iter().any(|member| {
            crate::data::validate_vm_name(&member.name, "transfer member").is_err()
                || !names.insert(&member.name)
        })
    {
        return Err(conflict("the saved transfer admission is unsupported"));
    }
    Ok(claim)
}

#[cfg(all(test, unix))]
mod live_tests;
#[cfg(test)]
mod tests;

impl SmolvmDb {
    fn transfer_gate(&self, exclusive: bool) -> Result<File> {
        // Resolve symlink spellings of the database to the same gate. The gate
        // is outside removable VM directories and is never unlinked on release.
        let path = self
            .path
            .canonicalize()?
            .with_extension("transfer-admission.lock");
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path)?;
        let result = if exclusive {
            file.try_lock()
        } else {
            file.try_lock_shared()
        };
        match result {
            Ok(()) => Ok(file),
            Err(TryLockError::WouldBlock) => Err(conflict(
                "another machine operation is still being admitted; retry the move",
            )),
            Err(TryLockError::Error(error)) => Err(error.into()),
        }
    }

    /// Admit an ordinary start, resume, or share mutation. Readers of a volume
    /// are fenced too: after a move they must not retain an obsolete local copy.
    /// Observation does not acquire this guard and never resumes a machine.
    pub fn admit_workload_mutation(
        &self,
        machine: Option<&str>,
        sources: &[PathBuf],
    ) -> Result<MutationGuard> {
        let gate = self.transfer_gate(false)?;
        let claims = self.with_read_conn(|conn| {
            let mut statement = conn
                .prepare("SELECT data FROM workload_transfer_admission WHERE retired = 0")
                .map_err(|e| Error::database_unavailable(e.to_string()))?;
            let data = statement
                .query_map([], |row| row.get::<_, Vec<u8>>(0))
                .map_err(|e| Error::database_unavailable(e.to_string()))?;
            data.map(|bytes| {
                decode(&bytes.map_err(|e| Error::database_unavailable(e.to_string()))?)
            })
            .collect::<Result<Vec<_>>>()
        })?;
        // Preserve ordinary startup's existing path validation when no transfer
        // is active; this fast path does no filesystem traversal of mounts.
        if !claims.is_empty() {
            if claims.iter().any(|claim| {
                claim
                    .members
                    .iter()
                    .any(|member| Some(member.name.as_str()) == machine)
            }) {
                return Err(conflict(
                    "this environment is moving; finish or cancel its transfer before changing it",
                ));
            }
            for source in sources {
                let source = source.canonicalize().map_err(|_| {
                    conflict("a shared directory cannot be resolved while a transfer is active")
                })?;
                if claims
                    .iter()
                    .any(|claim| claim.roots.iter().any(|root| overlaps(&source, root)))
                {
                    return Err(conflict(
                        "this shared data belongs to an active environment transfer",
                    ));
                }
            }
        }
        Ok(MutationGuard { _gate: gate })
    }

    /// Claim all members and shared roots atomically, after dependency review.
    /// Reusing the same operation is idempotent only for the exact same claim.
    /// A retired operation can never fence a later execution or reused name.
    /// This does not pause guests, authorize cloud execution, or copy data.
    pub fn claim_workload_transfer(
        &self,
        operation: &str,
        mut members: Vec<Member>,
        roots: &[PathBuf],
    ) -> Result<()> {
        if !operation_valid(operation)
            || members.is_empty()
            || members.len() > 1024
            || roots.len() > 1024
        {
            return Err(conflict("invalid transfer admission"));
        }
        let mut names = BTreeSet::new();
        for member in &members {
            crate::data::validate_vm_name(&member.name, "transfer member")
                .map_err(|_| conflict("invalid transfer member"))?;
            if !names.insert(member.name.clone()) {
                return Err(conflict("duplicate transfer member"));
            }
        }
        members.sort_by(|a, b| a.name.cmp(&b.name));
        let _gate = self.transfer_gate(true)?;
        let mut canonical_roots = BTreeSet::new();
        for root in roots {
            let root = root.canonicalize()?;
            if !root.is_dir() {
                return Err(conflict("transfer shared data must be a directory"));
            }
            canonical_roots.insert(root);
        }
        let claim = Claim {
            version: 1,
            members,
            roots: canonical_roots.into_iter().collect(),
        };
        self.with_conn(|conn| {
            conn.execute_batch("PRAGMA synchronous=FULL;")
                .map_err(|e| Error::database_unavailable(e.to_string()))?;
            let result = (|| -> Result<()> {
                let tx = conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(|e| Error::database_unavailable(e.to_string()))?;
                let existing: Option<(bool, Vec<u8>)> = tx.query_row(
                    "SELECT retired, data FROM workload_transfer_admission WHERE operation = ?1",
                    [operation], |row| Ok((row.get(0)?, row.get(1)?)),
                ).optional().map_err(|e| Error::database_unavailable(e.to_string()))?;
                if let Some((retired, data)) = existing {
                    if retired || decode(&data)? != claim {
                        return Err(conflict(
                            "this transfer operation was completed or has different members",
                        ));
                    }
                    return Ok(());
                }
                {
                    let mut statement = tx
                        .prepare("SELECT data FROM workload_transfer_admission WHERE retired = 0")
                        .map_err(|e| Error::database_unavailable(e.to_string()))?;
                    let rows = statement
                        .query_map([], |row| row.get::<_, Vec<u8>>(0))
                        .map_err(|e| Error::database_unavailable(e.to_string()))?;
                    for bytes in rows {
                        let other = decode(
                            &bytes.map_err(|e| Error::database_unavailable(e.to_string()))?,
                        )?;
                        if other.members.iter().any(|m| names.contains(&m.name))
                            || other
                                .roots
                                .iter()
                                .any(|a| claim.roots.iter().any(|b| overlaps(a, b)))
                        {
                            return Err(conflict(
                                "another transfer already owns part of this environment",
                            ));
                        }
                    }
                }
                for member in &claim.members {
                    let data: Option<Vec<u8>> = tx
                        .query_row(
                            "SELECT data FROM vms WHERE name = ?1",
                            [&member.name],
                            |row| row.get(0),
                        )
                        .optional()
                        .map_err(|e| Error::database_unavailable(e.to_string()))?;
                    let data = data.ok_or_else(|| Error::vm_not_found(&member.name))?;
                    let record: VmRecord = serde_json::from_slice(&data)
                        .map_err(|e| Error::database_unavailable(e.to_string()))?;
                    if Member::from_record(&member.name, &record) != *member {
                        return Err(conflict("an environment member changed after review"));
                    }
                }
                let data = serde_json::to_vec(&claim)
                    .map_err(|e| Error::database_unavailable(e.to_string()))?;
                tx.execute(
                    "INSERT INTO workload_transfer_admission(operation, data) VALUES (?1, ?2)",
                    params![operation, data],
                )
                .map_err(|e| Error::database_unavailable(e.to_string()))?;
                tx.commit()
                    .map_err(|e| Error::database_unavailable(e.to_string()))
            })();
            let restore = conn
                .execute_batch("PRAGMA synchronous=NORMAL;")
                .map_err(|e| Error::database_unavailable(e.to_string()));
            result.and(restore)
        })
    }

    /// Explicitly return mutation authority to the local environment. A cloud
    /// coordinator must first prove that the remote copy cannot execute. No
    /// timeout, process exit, or Drop implementation retires an admission.
    pub fn retire_workload_transfer(&self, operation: &str) -> Result<()> {
        if !operation_valid(operation) {
            return Err(conflict("invalid transfer operation"));
        }
        let _gate = self.transfer_gate(true)?;
        self.with_conn(|conn| {
            conn.execute_batch("PRAGMA synchronous=FULL;")
                .map_err(|e| Error::database_unavailable(e.to_string()))?;
            let result = conn
                .execute(
                    "UPDATE workload_transfer_admission SET retired = 1 WHERE operation = ?1",
                    [operation],
                )
                .map_err(|e| Error::database_unavailable(e.to_string()))
                .and_then(|changed| {
                    if changed == 1 {
                        Ok(())
                    } else {
                        Err(conflict("unknown transfer operation"))
                    }
                });
            let restore = conn
                .execute_batch("PRAGMA synchronous=NORMAL;")
                .map_err(|e| Error::database_unavailable(e.to_string()));
            result.and(restore)
        })
    }
}
