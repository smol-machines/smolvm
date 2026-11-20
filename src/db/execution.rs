//! Host execution identity that survives a stop and cannot be lost by an old writer.

use super::{Connection, DbResultExt, Result, TransactionBehavior};

fn installed(conn: &Connection) -> Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'vm_execution_epochs')",
        [],
        |row| row.get(0),
    )
    .db_err("inspect machine execution schema")
}

pub(super) fn install(conn: &mut Connection) -> Result<()> {
    if installed(conn)? {
        return Ok(());
    }
    conn.execute_batch("PRAGMA synchronous=FULL;")
        .db_err("enable durable execution identities")?;
    let result = (|| {
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .db_err("begin execution identity migration")?;
        if !installed(&tx)? {
            // Keep the identity outside serialized VmRecord fields: an older
            // engine can overwrite the row without forgetting execution history.
            // Clear PID on stop without clearing this identity. A replacement,
            // new process or repair of invalid metadata invalidates old reviews.
            tx.execute_batch(
                "CREATE TABLE vm_execution_epochs (
                     name TEXT PRIMARY KEY NOT NULL,
                     generation TEXT NOT NULL CHECK (
                         length(generation) = 48 AND generation NOT GLOB '*[^0-9a-f]*'
                     )
                 );
                 CREATE TRIGGER vm_execution_insert AFTER INSERT ON vms BEGIN
                     INSERT OR REPLACE INTO vm_execution_epochs(name, generation)
                         VALUES (NEW.name, lower(hex(randomblob(24))));
                 END;
                 CREATE TRIGGER vm_execution_delete AFTER DELETE ON vms BEGIN
                     DELETE FROM vm_execution_epochs WHERE name = OLD.name;
                 END;
                 CREATE TRIGGER vm_execution_rename AFTER UPDATE OF name ON vms
                     WHEN OLD.name != NEW.name BEGIN
                     DELETE FROM vm_execution_epochs WHERE name = OLD.name;
                     INSERT OR REPLACE INTO vm_execution_epochs(name, generation)
                         VALUES (NEW.name, lower(hex(randomblob(24))));
                 END;
                 CREATE TRIGGER vm_execution_update AFTER UPDATE OF data ON vms
                     WHEN CASE
                         WHEN NOT json_valid(CAST(NEW.data AS TEXT))
                           OR NOT json_valid(CAST(OLD.data AS TEXT)) THEN 1
                         ELSE json_extract(CAST(NEW.data AS TEXT), '$.pid') IS NOT NULL
                           AND (
                             json_extract(CAST(NEW.data AS TEXT), '$.pid')
                               IS NOT json_extract(CAST(OLD.data AS TEXT), '$.pid')
                             OR json_extract(CAST(NEW.data AS TEXT), '$.pid_start_time')
                               IS NOT json_extract(CAST(OLD.data AS TEXT), '$.pid_start_time')
                           )
                         END
                     BEGIN
                         UPDATE vm_execution_epochs SET generation = lower(hex(randomblob(24)))
                             WHERE name = NEW.name;
                     END;
                 INSERT INTO vm_execution_epochs(name, generation)
                     SELECT name, lower(hex(randomblob(24))) FROM vms;",
            )
            .db_err("install machine execution schema")?;
        }
        tx.commit().db_err("commit execution identity migration")
    })();
    let restored = conn
        .execute_batch("PRAGMA synchronous=NORMAL;")
        .db_err("restore database durability policy");
    result.and(restored)
}

#[cfg(test)]
mod tests;
