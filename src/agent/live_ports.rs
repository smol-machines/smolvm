//! Replace a machine's published ports, live when it runs.
//!
//! One implementation for every caller that changes ports: the embedded SDK
//! runtime and the HTTP API. The caller holds its own per-machine lock and
//! says whether the machine is running.

use crate::config::VmRecord;
use crate::data::network::{PortMapping, PortProtocol, MAX_PORT_MAPPINGS};
use crate::db::SmolvmDb;
use crate::{Error, Result};

/// Make `ports` machine `name`'s published ports, the whole set, and return
/// the saved record.
///
/// A stopped machine gets them at its next start. A running one changes its
/// TCP ports now: new host ports start accepting, removed ones stop
/// (connections they already accepted carry on). Its UDP ports are bound for
/// the life of the VM, so a running machine refuses a UDP change. A machine on
/// virtio-net changes its own listeners; any other runs them in the port
/// forwarder. A host port already taken fails the call and changes nothing.
pub fn set_published_ports(
    db: &SmolvmDb,
    record: &VmRecord,
    running: bool,
    ports: &[PortMapping],
) -> Result<VmRecord> {
    let name = record.name.as_str();
    if ports.len() > MAX_PORT_MAPPINGS {
        return Err(Error::config(
            "published ports",
            format!(
                "{} mappings; the maximum per machine is {MAX_PORT_MAPPINGS}",
                ports.len()
            ),
        ));
    }
    PortMapping::check_duplicates(ports).map_err(|e| Error::config("published ports", e))?;
    let tcp = split(ports, PortProtocol::Tcp);
    let udp = split(ports, PortProtocol::Udp);
    if running {
        if udp != split(&record.port_mappings(), PortProtocol::Udp) {
            return Err(Error::agent_conflict(
                "published ports",
                "published UDP ports cannot change on a running machine; stop it first",
            ));
        }
        crate::agent::apply_live_published_ports(name, &tcp)?;
    }
    let saved = db.update_vm(name, |r| {
        r.ports = tcp.clone();
        r.udp_ports = udp.clone();
    });
    match saved {
        Ok(Some(saved)) => Ok(saved),
        other => {
            if running {
                // The record keeps the old set, so the machine must too.
                let _ = crate::agent::apply_live_published_ports(name, &record.ports);
            }
            other?;
            Err(Error::vm_not_found(name))
        }
    }
}

/// The `(host, guest)` pairs of one protocol, sorted so two sets compare equal
/// regardless of order.
fn split(ports: &[PortMapping], protocol: PortProtocol) -> Vec<(u16, u16)> {
    let mut set: Vec<(u16, u16)> = ports
        .iter()
        .filter(|p| p.protocol == protocol)
        .map(PortMapping::to_tuple)
        .collect();
    set.sort_unstable();
    set
}
