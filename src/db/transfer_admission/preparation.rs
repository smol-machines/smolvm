//! Durable, recoverable preparation of a reviewed workload.
//!
//! Reservation and the inventory it protects commit in the same transaction.
//! Neither Reserved nor Prepared authorizes freezing or remote execution.

use super::{conflict, operation_valid};
use crate::db::{Connection, DbResultExt, OptionalExtension};
use crate::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Phase {
    Reserved,
    Prepared,
    Cancelled,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Preparation {
    pub version: u32,
    pub operation: String,
    pub phase: Phase,
    pub fingerprint: String,
    /// Private reviewed metadata, including configuration and secret references.
    /// Never serialize this record as an HTTP response or log its contents.
    pub inventory: serde_json::Value,
}

fn decode(operation: &str, data: &[u8]) -> Result<Preparation> {
    let record: Preparation = serde_json::from_slice(data)
        .map_err(|_| conflict("workload preparation is unreadable; recover it before moving"))?;
    let bytes = serde_json::to_vec(&record.inventory)
        .map_err(|_| conflict("workload preparation inventory is invalid"))?;
    if record.version != 1
        || record.operation != operation
        || !operation_valid(operation)
        || !record.inventory.is_object()
        || record.fingerprint != format!("sha256:{:x}", Sha256::digest(bytes))
    {
        return Err(conflict("workload preparation identity is invalid"));
    }
    Ok(record)
}

fn same_review(a: &Preparation, b: &Preparation) -> bool {
    a.version == b.version
        && a.operation == b.operation
        && a.fingerprint == b.fingerprint
        && a.inventory == b.inventory
}

pub(super) fn match_existing(
    conn: &Connection,
    operation: &str,
    requested: Option<&[u8]>,
) -> Result<()> {
    let existing: Option<Vec<u8>> = conn
        .query_row(
            "SELECT data FROM workload_transfer_preparations WHERE operation = ?1",
            [operation],
            |row| row.get(0),
        )
        .optional()
        .db_err("read existing workload preparation")?;
    match (existing, requested) {
        (None, None) => Ok(()),
        (Some(existing), Some(requested)) => {
            let existing = decode(operation, &existing)?;
            let requested = decode(operation, requested)?;
            if same_review(&existing, &requested) && existing.phase != Phase::Cancelled {
                Ok(())
            } else {
                Err(conflict(
                    "this operation belongs to a different workload review",
                ))
            }
        }
        _ => Err(conflict(
            "this operation has different preparation ownership",
        )),
    }
}

#[cfg(unix)]
fn read(conn: &Connection, operation: &str) -> Result<Option<Preparation>> {
    let row: Option<(Vec<u8>, Option<bool>)> = conn
        .query_row(
            "SELECT p.data, a.retired FROM workload_transfer_preparations p
             LEFT JOIN workload_transfer_admission a ON a.operation = p.operation
             WHERE p.operation = ?1",
            [operation],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .db_err("read workload preparation")?;
    row.map(|(bytes, retired)| {
        let record = decode(operation, &bytes)?;
        if retired != Some(record.phase == Phase::Cancelled) {
            return Err(conflict("workload preparation ownership is inconsistent"));
        }
        Ok(record)
    })
    .transpose()
}

#[cfg(unix)]
impl crate::db::SmolvmDb {
    pub(crate) fn reserve_workload_preparation(
        &self,
        record: Preparation,
        members: Vec<super::Member>,
        roots: &[std::path::PathBuf],
    ) -> Result<Preparation> {
        if record.phase != Phase::Reserved {
            return Err(conflict(
                "a workload preparation must begin with a reservation",
            ));
        }
        let bytes = serde_json::to_vec(&record).db_err("encode workload preparation")?;
        decode(&record.operation, &bytes)?;
        self.claim_workload_transfer_with_preparation(
            &record.operation,
            members,
            roots,
            Some(&bytes),
        )?;
        self.workload_preparation(&record.operation)?
            .ok_or_else(|| conflict("workload preparation disappeared after reservation"))
    }

    pub(crate) fn workload_preparation(&self, operation: &str) -> Result<Option<Preparation>> {
        if !operation_valid(operation) {
            return Err(conflict("invalid transfer operation"));
        }
        self.with_read_conn(|conn| read(conn, operation))
    }

    pub(crate) fn confirm_workload_preparation(
        &self,
        reviewed: &Preparation,
    ) -> Result<Preparation> {
        self.transition_workload_preparation(&reviewed.operation, Some(reviewed))
    }

    /// Safe only before capture: neither supported active phase changes source
    /// execution or creates a destination. Future capture phases must provide
    /// their own recovery, and must never be admitted by this transition.
    pub(crate) fn cancel_workload_preparation(&self, operation: &str) -> Result<Preparation> {
        self.transition_workload_preparation(operation, None)
    }

    fn transition_workload_preparation(
        &self,
        operation: &str,
        reviewed: Option<&Preparation>,
    ) -> Result<Preparation> {
        if !operation_valid(operation) {
            return Err(conflict("invalid transfer operation"));
        }
        let _gate = self.transfer_gate(true)?;
        self.with_conn(|conn| {
            conn.execute_batch("PRAGMA synchronous=FULL;")
                .db_err("enable durable preparation transition")?;
            let result = (|| {
                let tx = conn
                    .transaction_with_behavior(crate::db::TransactionBehavior::Immediate)
                    .db_err("begin workload preparation transition")?;
                let mut current = read(&tx, operation)?
                    .ok_or_else(|| conflict("unknown workload preparation"))?;
                match reviewed {
                    Some(reviewed) => {
                        if !same_review(&current, reviewed)
                            || !matches!(current.phase, Phase::Reserved | Phase::Prepared)
                        {
                            return Err(conflict("workload preparation changed during review"));
                        }
                        current.phase = Phase::Prepared;
                    }
                    None => {
                        match current.phase {
                            Phase::Reserved | Phase::Prepared => {}
                            Phase::Cancelled => return Ok(current),
                        }
                        current.phase = Phase::Cancelled;
                        tx.execute(
                            "UPDATE workload_transfer_admission SET retired = 1 WHERE operation = ?1",
                            [operation],
                        )
                        .db_err("retire cancelled workload preparation")?;
                    }
                }
                let bytes = serde_json::to_vec(&current).db_err("encode preparation transition")?;
                tx.execute(
                    "UPDATE workload_transfer_preparations SET data = ?2 WHERE operation = ?1",
                    crate::db::params![operation, bytes],
                )
                .db_err("persist preparation transition")?;
                tx.commit().db_err("commit preparation transition")?;
                Ok(current)
            })();
            let restored = conn
                .execute_batch("PRAGMA synchronous=NORMAL;")
                .db_err("restore preparation durability policy");
            match (result, restored) {
                (Ok(record), Ok(())) => Ok(record),
                (Err(error), _) | (_, Err(error)) => Err(error),
            }
        })
    }
}
