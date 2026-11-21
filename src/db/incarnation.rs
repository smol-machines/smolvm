//! Durable identity of a VM row, independent of timestamps and process IDs.

use super::{Connection, DbResultExt, Result, TransactionBehavior};

fn installed(conn: &Connection) -> Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'vm_incarnations')",
        [],
        |row| row.get(0),
    )
    .db_err("inspect machine incarnation schema")
}

/// Install and backfill atomically. Readers never generate identities, and an
/// ordinary database open does not rewrite every machine. Triggers also cover
/// provisional startup inserts and writers using the previous row format.
pub(super) fn install(conn: &mut Connection) -> Result<()> {
    if installed(conn)? {
        return Ok(());
    }
    conn.execute_batch("PRAGMA synchronous=FULL;")
        .db_err("enable durable machine identities")?;
    let result = (|| {
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .db_err("begin machine identity migration")?;
        // Another opener may have completed the migration while we waited.
        if !installed(&tx)? {
            tx.execute_batch(
                "CREATE TABLE vm_incarnations (
                     name TEXT PRIMARY KEY NOT NULL,
                     generation TEXT NOT NULL CHECK (
                         length(generation) = 48 AND generation NOT GLOB '*[^0-9a-f]*'
                     )
                 );
                 CREATE TRIGGER vm_incarnation_insert AFTER INSERT ON vms BEGIN
                     INSERT OR REPLACE INTO vm_incarnations(name, generation)
                         VALUES (NEW.name, lower(hex(randomblob(24))));
                 END;
                 CREATE TRIGGER vm_incarnation_delete AFTER DELETE ON vms BEGIN
                     DELETE FROM vm_incarnations WHERE name = OLD.name;
                 END;
                 CREATE TRIGGER vm_incarnation_rename AFTER UPDATE OF name ON vms
                     WHEN OLD.name != NEW.name BEGIN
                     DELETE FROM vm_incarnations WHERE name = OLD.name;
                     INSERT OR REPLACE INTO vm_incarnations(name, generation)
                         VALUES (NEW.name, lower(hex(randomblob(24))));
                 END;
                 INSERT INTO vm_incarnations(name, generation)
                     SELECT name, lower(hex(randomblob(24))) FROM vms;",
            )
            .db_err("install machine incarnation schema")?;
        }
        tx.commit().db_err("commit machine identity migration")
    })();
    let restored = conn
        .execute_batch("PRAGMA synchronous=NORMAL;")
        .db_err("restore database durability policy");
    result.and(restored)
}

pub(super) fn valid(generation: &str) -> bool {
    generation.len() == 48
        && generation
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests;
