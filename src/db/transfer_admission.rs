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

use super::{params, Connection, DbResultExt, OptionalExtension, SmolvmDb, TransactionBehavior};
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
    /// Opaque database-row identity, changed whenever the machine is recreated.
    /// Absent only on legacy saved claims, which can fence mutations but cannot
    /// authorize a new transfer or boot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<String>,
    /// Creation timestamp observed during dependency review.
    pub created_at: u64,
    /// VMM process observed during dependency review, if it is running.
    pub pid: Option<i32>,
    /// Host process start time, distinguishing a reused PID.
    pub pid_start_time: Option<u64>,
}

impl Member {
    /// Read the row identity and execution state in one SQLite snapshot.
    pub(super) fn read(conn: &Connection, name: &str) -> Result<(Self, VmRecord)> {
        let row: Option<(Vec<u8>, Option<String>, Option<String>)> = conn
            .query_row(
                "SELECT v.data, g.generation, e.generation FROM vms v
                 LEFT JOIN vm_incarnations g ON g.name = v.name
                 LEFT JOIN vm_execution_epochs e ON e.name = v.name WHERE v.name = ?1",
                [name],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .db_err("read reviewed machine identity")?;
        let (data, generation, execution) = row.ok_or_else(|| Error::vm_not_found(name))?;
        let generation = generation
            .filter(|value| super::incarnation::valid(value))
            .ok_or_else(|| {
                conflict("machine identity is missing or corrupt; recover it before moving")
            })?;
        let mut record: VmRecord =
            serde_json::from_slice(&data).db_err("decode reviewed machine")?;
        record.execution_identity = execution.filter(|value| super::incarnation::valid(value));
        Ok((
            Self {
                name: name.to_owned(),
                generation: Some(generation),
                created_at: record.created_at,
                pid: record.pid,
                pid_start_time: record.pid_start_time,
            },
            record,
        ))
    }

    pub(super) fn identity_valid(&self, require: bool) -> bool {
        self.generation
            .as_deref()
            .map_or(!require, super::incarnation::valid)
    }

    pub(super) fn same_incarnation(&self, other: &Self) -> bool {
        self.name == other.name
            && self.generation.is_some()
            && self.generation == other.generation
            && self.created_at == other.created_at
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
    _gate: AdmissionGate,
    #[cfg(unix)]
    active_transfers: bool,
}

#[cfg(unix)]
impl MutationGuard {
    /// The gate prevents a new transfer from appearing before this guard ends.
    pub(crate) fn has_active_transfers(&self) -> bool {
        self.active_transfers
    }
}

pub(super) struct AdmissionGate {
    file: File,
    owner_pid: u32,
}

impl Drop for AdmissionGate {
    fn drop(&mut self) {
        // An unrelated fork inherits the open-file description, even with
        // CLOEXEC, until it execs or exits. Closing our descriptor alone can
        // therefore retain admission for that child's entire lifetime.
        // Only the process that acquired this gate may unlock it: dropping
        // an inherited Rust guard in a child must not release its parent.
        if std::process::id() != self.owner_pid {
            return;
        }
        if let Err(error) = self.file.unlock() {
            tracing::warn!(%error, "could not explicitly release transfer admission gate");
        }
    }
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
    if !matches!(claim.version, 1 | 2)
        || claim.members.is_empty()
        || claim.members.len() > 1024
        || claim.roots.len() > 1024
        || claim.roots.iter().any(|path| !path.is_absolute())
        || claim.members.iter().any(|member| {
            crate::data::validate_vm_name(&member.name, "transfer member").is_err()
                || !member.identity_valid(claim.version >= 2)
                || !names.insert(&member.name)
        })
    {
        return Err(conflict("the saved transfer admission is unsupported"));
    }
    Ok(claim)
}

#[cfg(all(test, unix))]
mod live_tests;
pub(crate) mod preparation;
#[cfg(test)]
mod tests;

impl SmolvmDb {
    /// Review a machine for transfer from one consistent database snapshot.
    /// Re-read after a changed machine is reported; never synthesize a review
    /// from a name, timestamp, or a previously serialized VM configuration.
    pub fn review_workload_member(&self, name: &str) -> Result<Member> {
        self.with_read_conn(|conn| Member::read(conn, name).map(|(member, _)| member))
    }

    pub(super) fn transfer_gate(&self, exclusive: bool) -> Result<AdmissionGate> {
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
            Ok(()) => Ok(AdmissionGate {
                file,
                owner_pid: std::process::id(),
            }),
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
        self.admit_workload_paths(machine, sources, |path| path.canonicalize(), false)
    }

    pub(super) fn admit_startup_mutation(
        &self,
        machine: Option<&str>,
        sources: &[PathBuf],
    ) -> Result<MutationGuard> {
        self.admit_workload_paths(
            machine,
            sources,
            super::launch_admission::resource_path,
            false,
        )
    }

    /// Hold admission across changes to engine-owned storage and metadata.
    /// New paths are resolved through their existing ancestors, so unrelated
    /// volume creation remains possible while a transfer owns another tree.
    #[cfg(unix)]
    pub(crate) fn admit_storage_mutation(&self, paths: &[PathBuf]) -> Result<MutationGuard> {
        self.admit_startup_mutation(None, paths)
    }

    fn admit_workload_paths(
        &self,
        machine: Option<&str>,
        sources: &[PathBuf],
        resolve: impl Fn(&Path) -> std::io::Result<PathBuf>,
        allow_deletion: bool,
    ) -> Result<MutationGuard> {
        let gate = self.transfer_gate(false)?;
        self.check_recovery_admission(machine, sources)?;
        self.check_deletion_admission(machine, sources, allow_deletion)?;
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
                let source = resolve(source).map_err(|_| {
                    conflict("a workload path cannot be resolved while a transfer is active")
                })?;
                for root in claims.iter().flat_map(|claim| &claim.roots) {
                    if overlaps(&source, root)
                        || super::launch_admission::same_resource(&source, root)?
                    {
                        return Err(conflict(
                            "this shared data belongs to an active environment transfer",
                        ));
                    }
                }
            }
        }
        Ok(MutationGuard {
            _gate: gate,
            #[cfg(unix)]
            active_transfers: !claims.is_empty(),
        })
    }

    /// Admit mutation of a named machine and its persisted host shares.
    /// Keep the gate held while reading the record and checking the share roots,
    /// so a transfer cannot claim a newly discovered dependency in between.
    pub fn admit_machine_mutation(&self, name: &str) -> Result<MutationGuard> {
        let admission = self.admit_workload_mutation(Some(name), &[])?;
        if let Some(record) = self.get_vm(name)? {
            let roots = record
                .host_mounts()
                .into_iter()
                .map(|mount| mount.source)
                .collect::<Vec<_>>();
            let checked = self.admit_workload_mutation(Some(name), &roots)?;
            drop(admission);
            Ok(checked)
        } else {
            Ok(admission)
        }
    }

    /// Admit only retrying deletion of this member; its durable intent continues
    /// to refuse startup, transfer and mutation by other callers.
    pub fn admit_machine_deletion(&self, name: &str) -> Result<MutationGuard> {
        let admission = self.admit_workload_paths(
            Some(name),
            &[],
            super::launch_admission::resource_path,
            true,
        )?;
        if let Some(record) = self.get_vm(name)? {
            let roots = record
                .host_mounts()
                .into_iter()
                .map(|mount| mount.source)
                .collect::<Vec<_>>();
            let checked = self.admit_workload_paths(
                Some(name),
                &roots,
                super::launch_admission::resource_path,
                true,
            )?;
            drop(admission);
            Ok(checked)
        } else {
            Ok(admission)
        }
    }

    /// Claim all members and shared roots atomically, after dependency review.
    /// Reusing the same operation is idempotent only for the exact same claim.
    /// A retired operation can never fence a later execution or reused name.
    /// This does not pause guests, authorize cloud execution, or copy data.
    pub fn claim_workload_transfer(
        &self,
        operation: &str,
        members: Vec<Member>,
        roots: &[PathBuf],
    ) -> Result<()> {
        self.claim_workload_transfer_with_preparation(operation, members, roots, None, None)
    }

    fn claim_workload_transfer_with_preparation(
        &self,
        operation: &str,
        mut members: Vec<Member>,
        roots: &[PathBuf],
        preparation: Option<&[u8]>,
        recovery: Option<&[u8]>,
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
            if !member.identity_valid(true) {
                return Err(conflict("transfer review has no valid machine identity"));
            }
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
            version: 2,
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
                for member in &claim.members {
                    super::deletion_intent::refuse_conflicts(
                        &tx,
                        Some(&member.name),
                        &claim.roots,
                        false,
                    )?;
                }
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
                    preparation::match_existing(&tx, operation, preparation)?;
                    let saved_recovery: Option<Vec<u8>> = tx.query_row(
                        "SELECT data FROM workload_preparation_recovery WHERE operation = ?1",
                        [operation], |row| row.get(0),
                    ).optional().db_err("read preparation recovery")?;
                    if saved_recovery.as_deref() != recovery {
                        return Err(conflict("preparation recovery ownership changed"));
                    }
                    // A retry must not authorize a replacement created by a
                    // writer that did not participate in transfer admission.
                    for member in &claim.members {
                        if Member::read(&tx, &member.name)?.0 != *member {
                            return Err(conflict("an environment member changed after review"));
                        }
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
                super::launch_admission::reconcile_transfer(&tx, &claim.members, &claim.roots)?;
                for member in &claim.members {
                    if Member::read(&tx, &member.name)?.0 != *member {
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
                if let Some(data) = preparation {
                    tx.execute(
                        "INSERT INTO workload_transfer_preparations(operation, data) VALUES (?1, ?2)",
                        params![operation, data],
                    )
                    .db_err("persist workload preparation")?;
                }
                if let Some(data) = recovery {
                    if preparation.is_none() || data.is_empty() || data.len() > 16 * 1024 * 1024 {
                        return Err(conflict("invalid preparation recovery record"));
                    }
                    tx.execute(
                        "INSERT INTO workload_preparation_recovery(operation, data) VALUES (?1, ?2)",
                        params![operation, data],
                    ).db_err("persist preparation recovery")?;
                }
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
            if conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM workload_transfer_preparations WHERE operation = ?1)",
                [operation], |row| row.get::<_, bool>(0),
            ).db_err("inspect workload preparation ownership")? {
                return Err(conflict("cancel this workload through its transfer coordinator"));
            }
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
