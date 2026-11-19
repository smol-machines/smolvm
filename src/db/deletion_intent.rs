//! Durable refusal of execution over storage whose deletion has begun.
use super::launch_admission::{resource_path, same_resource};
use super::transfer_admission::Member;
use super::{params, Connection, DbResultExt, SmolvmDb, TransactionBehavior};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    version: u32,
    member: Member,
    runtime: PathBuf,
    paths: Vec<PathBuf>,
}

fn conflict() -> Error {
    Error::agent_conflict(
        "use machine",
        "machine deletion is incomplete; retry deletion before reusing this name or its storage",
    )
}

fn installed(conn: &Connection) -> Result<bool> {
    conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='vm_deletion_intents')", [], |r| r.get(0)).db_err("inspect deletion intent schema")
}

pub(super) fn install(conn: &mut Connection) -> Result<()> {
    if installed(conn)? {
        return Ok(());
    }
    conn.execute_batch("PRAGMA synchronous=FULL;")
        .db_err("enable durable deletion migration")?;
    let result = (|| {
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .db_err("begin deletion intent migration")?;
        if !installed(&tx)? {
            tx.execute_batch("CREATE TABLE vm_deletion_intents (name TEXT PRIMARY KEY NOT NULL, data BLOB NOT NULL);").db_err("create deletion intents")?;
            for table in ["vms", "vm_incarnations"] {
                for (action, names) in [
                    ("INSERT", "NEW.name"),
                    ("UPDATE", "OLD.name, NEW.name"),
                    ("DELETE", "OLD.name"),
                ] {
                    tx.execute_batch(&format!(
                        "CREATE TRIGGER vm_deletion_{table}_{action} BEFORE {action} ON {table}
                         WHEN EXISTS(SELECT 1 FROM vm_deletion_intents WHERE name IN ({names})) BEGIN
                         SELECT RAISE(ABORT, 'machine deletion is incomplete; retry deletion'); END;"
                    )).db_err("install deletion row fence")?;
                }
            }
            // Older controllers must not reserve new named disk preparation or
            // boot tickets while they do not yet understand deletion intents.
            for (action, references) in [("INSERT", vec!["NEW"]), ("UPDATE", vec!["OLD", "NEW"])] {
                let names = references
                    .iter()
                    .flat_map(|row| {
                        [
                            "$.member.name",
                            "$.purpose.Prepare.name",
                            "$.purpose.Create.name",
                        ]
                        .map(|path| format!("json_extract(CAST({row}.data AS TEXT), '{path}')"))
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                tx.execute_batch(&format!(
                    "CREATE TRIGGER vm_deletion_launch_{action} BEFORE {action} ON vm_launch_admission
                     WHEN CASE WHEN EXISTS(SELECT 1 FROM vm_deletion_intents) THEN
                     EXISTS(SELECT 1 FROM vm_deletion_intents WHERE name IN ({names})) ELSE 0 END BEGIN
                     SELECT RAISE(ABORT, 'machine deletion is incomplete; retry deletion'); END;"
                )).db_err("install deletion launch fence")?;
            }
        }
        tx.commit().db_err("commit deletion intent migration")
    })();
    let restored = conn
        .execute_batch("PRAGMA synchronous=NORMAL;")
        .db_err("restore deletion migration durability");
    result.and(restored)
}

fn rows(conn: &Connection) -> Result<Vec<Intent>> {
    let mut statement = conn
        .prepare("SELECT name,data FROM vm_deletion_intents")
        .db_err("read deletion intents")?;
    let raw = statement
        .query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
        })
        .db_err("query deletion intents")?
        .collect::<rusqlite::Result<Vec<_>>>()
        .db_err("decode deletion intent rows")?;
    raw.into_iter()
        .map(|(name, bytes)| {
            let intent: Intent = serde_json::from_slice(&bytes).map_err(|_| conflict())?;
            if intent.version != 1
                || intent.member.name != name
                || !intent.member.identity_valid(true)
                || !intent.runtime.is_absolute()
                || intent.paths.is_empty()
                || intent.paths.len() > 1024
                || intent.paths.iter().any(|p| !p.is_absolute())
                || !intent.paths.contains(&intent.runtime)
                || Member::read(conn, &name)?.0 != intent.member
            {
                return Err(conflict());
            }
            Ok(intent)
        })
        .collect()
}

/// General mutation admits only an explicit deletion retry for its own member;
/// other machines and anonymous users cannot take its captured paths.
pub(super) fn refuse_conflicts(
    conn: &Connection,
    machine: Option<&str>,
    paths: &[PathBuf],
    allow_deletion: bool,
) -> Result<()> {
    let intents = rows(conn)?;
    if intents.is_empty() {
        return Ok(());
    }
    let paths = paths
        .iter()
        .map(|p| resource_path(p))
        .collect::<std::io::Result<Vec<_>>>()?;
    for intent in intents {
        if machine == Some(intent.member.name.as_str()) {
            if allow_deletion {
                continue;
            }
            return Err(conflict());
        }
        for owned in &intent.paths {
            for path in &paths {
                if owned.starts_with(path) || path.starts_with(owned) || same_resource(owned, path)?
                {
                    return Err(conflict());
                }
            }
        }
    }
    Ok(())
}

/// A retry may only remove the original runtime and keeps all captured paths
/// fenced, even when an earlier attempt already removed some of those files.
pub(super) fn retry_paths(
    conn: &Connection,
    member: &Member,
    runtime: &Path,
) -> Result<Vec<PathBuf>> {
    for intent in rows(conn)? {
        if intent.member.name == member.name {
            if intent.member != *member || intent.runtime != runtime {
                return Err(conflict());
            }
            return Ok(intent.paths);
        }
    }
    Ok(Vec::new())
}

pub(super) fn persist(
    conn: &Connection,
    member: Member,
    runtime: &Path,
    paths: Vec<PathBuf>,
) -> Result<()> {
    let name = member.name.clone();
    let intent = Intent {
        version: 1,
        member,
        runtime: runtime.to_path_buf(),
        paths,
    };
    conn.execute(
        "INSERT INTO vm_deletion_intents(name,data) VALUES(?1,?2)",
        params![
            name,
            serde_json::to_vec(&intent).db_err("encode deletion intent")?
        ],
    )
    .db_err("persist deletion intent")?;
    Ok(())
}

/// Called only under the original recovery owner, in the same write transaction
/// as its stopped publication or final row removal; never an external unlock.
pub(super) fn retire_owned(conn: &Connection, name: &str) -> Result<()> {
    conn.execute("DELETE FROM vm_deletion_intents WHERE name=?1", [name])
        .db_err("retire owned deletion intent")?;
    Ok(())
}

impl SmolvmDb {
    pub(crate) fn check_deletion_admission(
        &self,
        machine: Option<&str>,
        paths: &[PathBuf],
        allow_deletion: bool,
    ) -> Result<()> {
        self.with_read_conn(|conn| refuse_conflicts(conn, machine, paths, allow_deletion))
    }
}
