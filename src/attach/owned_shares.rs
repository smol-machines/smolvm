//! Live exports pinned to the original database incarnation and VMM execution.

use super::*;
use crate::{config::VmRecord, db::SmolvmDb};

pub(crate) struct OwnedShares {
    record: VmRecord,
    ownership: crate::db::VmRecoveryGuard,
}

impl OwnedShares {
    pub(crate) fn new(db: &SmolvmDb, record: &VmRecord) -> Result<Self> {
        Self::reserve(db, record, &crate::agent::vm_data_dir(&record.name))
    }

    fn reserve(db: &SmolvmDb, record: &VmRecord, runtime: &Path) -> Result<Self> {
        let ownership = db.reserve_vm_control(record, runtime, &[])?;
        ownership.validate_staged_record(record)?;
        Ok(Self {
            record: record.clone(),
            ownership,
        })
    }

    pub(crate) fn source(&self, share: &str, read_only: bool) -> Result<Option<PathBuf>> {
        self.ownership.validate_staged_record(&self.record)?;
        // A dead execution has no remaining exports. Ownership still prevents
        // another start while its retained image references are released.
        if !self.record.is_process_alive() {
            return Ok(None);
        }
        let reply = control_socket_cmd(
            &self.ownership.runtime_dir().join("control.sock"),
            &format!("SHARE_LIST {}", tag(read_only)),
        )?;
        Ok(parse_shared_directories(&reply)?
            .into_iter()
            .find(|(name, _)| name == share)
            .map(|(_, path)| path))
    }

    pub(crate) fn remove(&self, share: &str, expected: &Path, read_only: bool) -> Result<()> {
        let Some(source) = self.source(share, read_only)? else {
            return Ok(());
        };
        if source != expected {
            return Err(Error::agent_conflict(
                "release container share",
                "live export source changed since the container started",
            ));
        }
        control_reply(control_socket_cmd(
            &self.ownership.runtime_dir().join("control.sock"),
            &format!("SHARE_REMOVE {} {share}", tag(read_only)),
        )?)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
