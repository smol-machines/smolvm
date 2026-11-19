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
}

impl LaunchReview {
    pub(crate) fn capture(db: &SmolvmDb, name: Option<&str>) -> Result<Self> {
        Ok(Self {
            database: db.path.canonicalize()?,
            name: name.map(str::to_owned),
            identity: name
                .map(|name| db.get_vm(name))
                .transpose()?
                .flatten()
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
        if self.database != db.path.canonicalize()? {
            return Err(conflict("startup review belongs to another database"));
        }
        if let Some(name) = &self.name {
            let current = read_record(conn, &self.database, name)?
                .map(|record| {
                    record.database_identity.ok_or_else(|| {
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
        }
        Ok(())
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
