//! Keep the reviewed database row through disk preparation and boot admission.

use super::{conflict, DbResultExt, OptionalExtension, SmolvmDb};
use crate::{config::VmRecord, Result};
use rusqlite::Connection;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RecordIdentity {
    database: PathBuf,
    name: String,
    generation: String,
}

/// An absent row is an explicit expectation too: a delayed new launch must
/// never adopt a machine another caller created in the meantime.
#[derive(Clone, Debug)]
pub(crate) struct LaunchReview {
    database: PathBuf,
    name: Option<String>,
    identity: Option<RecordIdentity>,
    execution: Option<(Option<i32>, Option<u64>)>,
}

impl LaunchReview {
    pub(crate) fn identity(&self) -> Option<RecordIdentity> {
        self.identity.clone()
    }

    /// Compare the published incarnation, independently of a later stop/start.
    pub(crate) fn matches_record(&self, record: &VmRecord) -> bool {
        self.identity.is_some()
            && self.identity == record.database_identity
            && self.name.as_deref() == Some(record.name.as_str())
    }

    pub(crate) fn capture(db: &SmolvmDb, name: Option<&str>) -> Result<Self> {
        let record = name.map(|name| db.get_vm(name)).transpose()?.flatten();
        Ok(Self {
            database: db.path.canonicalize()?,
            name: name.map(str::to_owned),
            execution: record
                .as_ref()
                .map(|record| (record.pid, record.pid_start_time)),
            identity: record
                .map(|record| {
                    record.database_identity.ok_or_else(|| {
                        conflict(
                            "machine identity is missing or corrupt; recover it before starting",
                        )
                    })
                })
                .transpose()?,
        })
    }

    pub(crate) fn from_record(record: &VmRecord) -> Result<Self> {
        let identity = record.database_identity.clone().ok_or_else(|| {
            conflict("machine settings have no database identity; read them again before starting")
        })?;
        if identity.name != record.name {
            return Err(conflict("machine settings were renamed after review"));
        }
        Ok(Self {
            database: identity.database.clone(),
            name: Some(record.name.clone()),
            identity: Some(identity),
            execution: Some((record.pid, record.pid_start_time)),
        })
    }

    pub(super) fn from_member(db: &SmolvmDb, member: Option<&super::Member>) -> Result<Self> {
        let database = db.path.canonicalize()?;
        let identity = member
            .map(|member| {
                Ok::<_, crate::Error>(RecordIdentity {
                    database: database.clone(),
                    name: member.name.clone(),
                    generation: member
                        .generation
                        .clone()
                        .filter(|value| crate::db::incarnation::valid(value))
                        .ok_or_else(|| {
                            conflict("startup ticket has no reviewed machine identity")
                        })?,
                })
            })
            .transpose()?;
        Ok(Self {
            database,
            name: member.map(|member| member.name.clone()),
            identity,
            execution: member.map(|member| (member.pid, member.pid_start_time)),
        })
    }

    pub(crate) fn check_name(&self, name: Option<&str>) -> Result<()> {
        if self.name.as_deref() != name {
            return Err(conflict("startup review belongs to another machine"));
        }
        Ok(())
    }

    pub(crate) fn validate(&self, db: &SmolvmDb) -> Result<()> {
        db.with_read_conn(|conn| self.validate_conn(db, conn))
    }

    pub(crate) fn validate_conn(&self, db: &SmolvmDb, conn: &Connection) -> Result<()> {
        self.reviewed_record(db, conn).map(|_| ())
    }

    /// A known record with no PID is distinct from an anonymous process whose
    /// identity can only be recovered from its private runtime files.
    pub(crate) fn observed_execution(&self) -> Option<(Option<i32>, Option<u64>)> {
        self.execution
    }

    pub(crate) fn validate_execution(
        &self,
        db: &SmolvmDb,
        child: Option<(i32, Option<u64>)>,
    ) -> Result<()> {
        self.review_execution_record(db, child).map(|_| ())
    }

    /// Read the original execution for a subsequent durable control reservation.
    /// The reservation must revalidate this record in its write transaction.
    pub(crate) fn review_execution_record(
        &self,
        db: &SmolvmDb,
        child: Option<(i32, Option<u64>)>,
    ) -> Result<Option<VmRecord>> {
        db.with_read_conn(|conn| {
            let record = self.reviewed_record(db, conn)?;
            if let Some(record) = &record {
                let expected = child
                    .map(|(pid, start)| (Some(pid), start))
                    .or(self.execution);
                if expected != Some((record.pid, record.pid_start_time)) {
                    return Err(conflict(
                        "machine execution changed since this handle was acquired",
                    ));
                }
            }
            Ok(record)
        })
    }

    fn reviewed_record(&self, db: &SmolvmDb, conn: &Connection) -> Result<Option<VmRecord>> {
        if self.database != db.path.canonicalize()? {
            return Err(conflict("startup review belongs to another database"));
        }
        if let Some(name) = &self.name {
            let record = read_record(conn, &self.database, name)?;
            let current = record
                .as_ref()
                .map(|record| {
                    record.database_identity.clone().ok_or_else(|| {
                        conflict(
                            "machine identity is missing or corrupt; recover it before starting",
                        )
                    })
                })
                .transpose()?;
            if current != self.identity {
                return Err(conflict(
                    "machine changed since its settings were reviewed; retry with current settings",
                ));
            }
            return Ok(record);
        }
        Ok(None)
    }
}

pub(in crate::db) fn read_record(
    conn: &Connection,
    database: &Path,
    name: &str,
) -> Result<Option<VmRecord>> {
    let row: Option<(Vec<u8>, Option<String>)> = conn.query_row(
        "SELECT v.data, i.generation FROM vms v LEFT JOIN vm_incarnations i ON i.name = v.name WHERE v.name = ?1",
        [name], |row| Ok((row.get(0)?, row.get(1)?)),
    ).optional().db_err("read machine settings and identity")?;
    row.map(|(data, generation)| decode_record(database, name, &data, generation))
        .transpose()
}

pub(in crate::db) fn decode_record(
    database: &Path,
    name: &str,
    data: &[u8],
    generation: Option<String>,
) -> Result<VmRecord> {
    let mut record: VmRecord =
        serde_json::from_slice(data).db_err("decode reviewed machine settings")?;
    // Observation remains possible for diagnosis; launching a record without
    // a valid identity fails closed in capture/from_record/validate_conn.
    record.database_identity = generation
        .filter(|value| crate::db::incarnation::valid(value))
        .map(|generation| RecordIdentity {
            database: database.to_path_buf(),
            name: name.to_owned(),
            generation,
        });
    Ok(record)
}

#[cfg(test)]
mod tests;
