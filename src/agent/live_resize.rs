//! Live disk growth shared by engine entry points.
//!
//! The caller holds its API/CLI lifecycle guard. This layer additionally
//! serializes the operation with cross-process checkpoint and branch capture.

use super::{fork, AgentClient, AgentManager};
use crate::config::{RecordState, VmRecord};
use crate::db::SmolvmDb;
use crate::storage::{DEFAULT_OVERLAY_SIZE_GIB, DEFAULT_STORAGE_SIZE_GIB};
use crate::{Error, Result};
use smolvm_protocol::{ManagedDisk, ONLINE_FILESYSTEM_GROWTH_CAPABILITY};
use std::time::Duration;

#[derive(Debug, PartialEq, Eq)]
#[cfg(any(target_os = "linux", test))]
pub(crate) struct MemoryGrowthInfo {
    boot_mib: u32,
    base: u64,
    mapped: u64,
    plugged: u64,
    capacity: u64,
}

#[cfg(any(target_os = "linux", test))]
impl MemoryGrowthInfo {
    pub(crate) fn parse(reply: &str) -> Result<Self> {
        let invalid = || Error::agent("RAM resize", "runtime reported invalid RAM growth geometry");
        let words: Vec<_> = reply.split_whitespace().collect();
        let ["OK", "boot_mib", boot, "base", base, "mapped", mapped, "plugged", plugged, "capacity", capacity] =
            words.as_slice()
        else {
            return Err(invalid());
        };
        let info = Self {
            boot_mib: boot.parse().map_err(|_| invalid())?,
            base: base.parse().map_err(|_| invalid())?,
            mapped: mapped.parse().map_err(|_| invalid())?,
            plugged: plugged.parse().map_err(|_| invalid())?,
            capacity: capacity.parse().map_err(|_| invalid())?,
        };
        if info.boot_mib == 0
            || info.capacity == 0
            || info.mapped > info.capacity
            || info.plugged > info.mapped
            || !info.base.is_multiple_of(128 << 20)
            || !info.mapped.is_multiple_of(128 << 20)
            || !info.capacity.is_multiple_of(128 << 20)
            || !info.plugged.is_multiple_of(2 << 20)
            || info.base.checked_add(info.capacity).is_none()
            || u64::from(info.boot_mib)
                .checked_add(info.capacity >> 20)
                .is_none_or(|total| total > u64::from(u32::MAX))
        {
            return Err(invalid());
        }
        Ok(info)
    }

    pub(crate) fn target_added_mib(&self, total_mib: u32) -> Result<u64> {
        let target = total_mib
            .checked_sub(self.boot_mib)
            .map(u64::from)
            .ok_or_else(|| Error::config("RAM resize", "RAM cannot shrink below boot memory"))?;
        let bytes = target << 20;
        if bytes < self.mapped || bytes > self.capacity || !target.is_multiple_of(128) {
            return Err(Error::config(
                "RAM resize",
                "RAM must grow in 128 MiB steps within the runtime capacity",
            ));
        }
        Ok(target)
    }
}

/// Experimental live RAM growth. Host budget changes precede guest exposure;
/// the runtime reports its boot layout so retries need not trust stale metadata.
/// This prototype still needs persistent operation recovery before release.
#[cfg(target_os = "linux")]
pub fn grow_memory(db: &SmolvmDb, name: &str, target_mib: u32) -> Result<VmRecord> {
    let _source_guard = fork::lock_fork_source(name)?;
    let record = db.get_vm(name)?.ok_or_else(|| Error::vm_not_found(name))?;
    if record.actual_state() != RecordState::Running {
        return Err(Error::agent_conflict(
            "RAM resize",
            "machine must be running",
        ));
    }
    if target_mib < record.mem {
        return Err(Error::config("RAM resize", "RAM cannot shrink"));
    }
    let manager = AgentManager::for_vm(name)?;
    let mut client = AgentClient::connect(manager.vsock_socket())?;
    if !client.supports_capability(smolvm_protocol::ONLINE_MEMORY_GROWTH_CAPABILITY)? {
        return Err(Error::agent(
            "RAM resize",
            "running guest lacks RAM growth support; no RAM changed",
        ));
    }
    let socket = fork::control_socket_path(name);
    let info =
        MemoryGrowthInfo::parse(&fork::control_socket_cmd(&socket, "PROTOTYPE_MEMORY_INFO")?)?;
    let added_mib = info.target_added_mib(target_mib)?;
    let target_bytes = added_mib << 20;
    let extra_bytes = target_bytes - info.mapped;
    if extra_bytes > 0 {
        let available = crate::process::host_memory_stats().ok_or_else(|| {
            Error::agent("RAM resize", "host memory headroom could not be verified")
        })?;
        let reserve = (available.total_bytes / 20).clamp(512 << 20, 4096 << 20);
        if available.available_bytes < extra_bytes.saturating_add(reserve) {
            return Err(Error::agent_conflict(
                "RAM resize",
                "insufficient host memory headroom for requested growth",
            ));
        }
    }
    let (pid, started) = manager
        .pid_and_start_time()
        .ok_or_else(|| Error::agent("RAM resize", "VMM process identity is unavailable"))?;
    let budget = fork::live_resize_memory_budget(db, name, &record, target_mib)?;
    if !crate::process::raise_managed_vmm_memory_budget(name, pid, started, budget)? {
        // Do not silently resize a guest beyond an external/shared cgroup's
        // allowance. External capacity negotiation is a separate integration.
        return Err(Error::agent_conflict("RAM resize", "live RAM growth currently requires a runtime-managed VM memory scope; external limits were not changed"));
    }
    let reply = fork::control_socket_cmd(&socket, &format!("PROTOTYPE_GROW_MEMORY {added_mib}"))?;
    if reply.trim() != "OK RAM registered; guest onlining pending" {
        return Err(Error::agent("RAM resize", format!("RAM growth not confirmed: {reply}; limits may be raised, reconcile before retrying")));
    }
    let actual =
        MemoryGrowthInfo::parse(&fork::control_socket_cmd(&socket, "PROTOTYPE_MEMORY_INFO")?)?;
    if actual.boot_mib != info.boot_mib || actual.base != info.base || actual.mapped != target_bytes
    {
        return Err(Error::agent(
            "RAM resize",
            "runtime did not verify the requested RAM geometry",
        ));
    }
    db.update_vm(name, |record| record.mem = target_mib)?
        .ok_or_else(|| {
            Error::agent(
                "RAM resize",
                "RAM registered but machine record disappeared",
            )
        })?;
    if target_bytes != 0 {
        client
            .online_memory(actual.base, target_bytes)
            .map_err(|error| {
                Error::agent(
                    "RAM resize",
                    format!(
                        "RAM registered; guest onlining incomplete: {error}; retry the same target"
                    ),
                )
            })?;
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let ready =
            MemoryGrowthInfo::parse(&fork::control_socket_cmd(&socket, "PROTOTYPE_MEMORY_INFO")?)?;
        if ready
            == (MemoryGrowthInfo {
                plugged: target_bytes,
                ..actual
            })
        {
            break;
        }
        if std::time::Instant::now() >= deadline {
            return Err(Error::agent(
                "RAM resize",
                "RAM registered but guest did not finish plugging it; retry the same target",
            ));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    db.get_vm(name)?.ok_or_else(|| Error::vm_not_found(name))
}

#[cfg(not(target_os = "linux"))]
pub fn grow_memory(_db: &SmolvmDb, _name: &str, _target_mib: u32) -> Result<VmRecord> {
    Err(Error::agent(
        "RAM resize",
        "live RAM growth is not yet supported on this host platform",
    ))
}

fn validate_growth(current: u64, requested: u64) -> Result<u64> {
    if requested == 0 || requested < current {
        return Err(Error::config(
            "live resize",
            "disk capacity cannot shrink or be zero",
        ));
    }
    requested
        .checked_mul(1 << 30)
        .ok_or_else(|| Error::config("live resize", "disk capacity overflows bytes"))
}

fn cpu_status(reply: &str) -> Result<(u8, u8)> {
    let words: Vec<_> = reply.split_whitespace().collect();
    if let ["OK", "created", created, "capacity", capacity] = words.as_slice() {
        if let (Ok(created), Ok(capacity)) = (created.parse::<u8>(), capacity.parse::<u8>()) {
            if created > 0 && created <= capacity {
                return Ok((created, capacity));
            }
        }
    }
    Err(Error::agent(
        "CPU resize",
        format!("runtime cannot report usable CPU growth state: {reply}"),
    ))
}

/// Experimental CPU resize; runtime must have explicitly enabled CPU growth.
/// Preserve created CPU count even if subsequent guest onlining fails.
pub fn grow_cpus(db: &SmolvmDb, name: &str, target: u8) -> Result<VmRecord> {
    let _source_guard = fork::lock_fork_source(name)?;
    let record = db
        .get_vm(name)?
        .ok_or_else(|| Error::VmNotFound { name: name.into() })?;
    if record.actual_state() != RecordState::Running {
        return Err(Error::agent_conflict(
            "CPU resize",
            "machine must be running",
        ));
    }
    if target == 0 || target < record.cpus {
        return Err(Error::config(
            "CPU resize",
            "CPU count cannot shrink or be zero",
        ));
    }
    let manager = AgentManager::for_vm(name)?;
    let mut client = AgentClient::connect(manager.vsock_socket())?;
    if !client.supports_capability(smolvm_protocol::ONLINE_CPU_GROWTH_CAPABILITY)? {
        return Err(Error::agent(
            "CPU resize",
            "running guest lacks CPU growth support; no CPUs changed",
        ));
    }
    let socket = fork::control_socket_path(name);
    let (created, capacity) =
        cpu_status(&fork::control_socket_cmd(&socket, "PROTOTYPE_CPU_STATUS")?)?;
    if target < created || target > capacity {
        return Err(Error::config(
            "CPU resize",
            format!(
                "target must be between {created} created CPUs and platform capacity {capacity}"
            ),
        ));
    }
    let (pid, started) = manager
        .pid_and_start_time()
        .ok_or_else(|| Error::agent("CPU resize", "VMM process identity is unavailable"))?;
    crate::process::set_managed_vmm_cpu_count(name, pid, started, target)?;
    let reply = fork::control_socket_cmd(&socket, &format!("PROTOTYPE_GROW_CPUS {target}"))?;
    if reply.trim() != format!("OK created {target} vCPUs; guest online required") {
        return Err(Error::agent("CPU resize", format!("CPU creation incomplete: {reply}; quota may already be raised, reconcile before retrying")));
    }
    let (actual, _) = cpu_status(&fork::control_socket_cmd(&socket, "PROTOTYPE_CPU_STATUS")?)?;
    if actual != target {
        return Err(Error::agent(
            "CPU resize",
            "runtime did not verify the requested CPU count",
        ));
    }
    db.update_vm(name, |record| record.cpus = actual)?
        .ok_or_else(|| Error::agent("CPU resize", "CPUs created but machine record disappeared"))?;
    client.online_cpus(actual).map_err(|error| {
        Error::agent(
            "CPU resize",
            format!(
                "{actual} CPUs created; guest onlining incomplete: {error}; retry the same target"
            ),
        )
    })?;
    db.get_vm(name)?
        .ok_or_else(|| Error::VmNotFound { name: name.into() })
}

/// Grow running disks and their mounted filesystems without restarting the VM.
/// After the runtime confirms growth, record the new disk limit even if the
/// subsequent filesystem operation fails. Retrying the same limit then finishes
/// the filesystem operation instead of attempting to undo disk growth.
pub fn grow_disks(
    db: &SmolvmDb,
    name: &str,
    storage_gb: Option<u64>,
    overlay_gb: Option<u64>,
) -> Result<VmRecord> {
    let _source_guard = fork::lock_fork_source(name)?;
    let record = db
        .get_vm(name)?
        .ok_or_else(|| Error::VmNotFound { name: name.into() })?;
    if record.actual_state() != RecordState::Running {
        return Err(Error::agent_conflict(
            "live resize",
            "machine must be running",
        ));
    }
    if storage_gb.is_none() && overlay_gb.is_none() {
        return Err(Error::config(
            "live resize",
            "specify storage or overlay capacity",
        ));
    }
    if !db.dependent_clones(name)?.is_empty() {
        return Err(Error::agent_conflict(
            "live resize",
            "cannot modify a disk with dependent branches",
        ));
    }
    let mut requested = Vec::new();
    for (disk, id, current, target) in [
        (
            ManagedDisk::Storage,
            "storage",
            record.storage_gb.unwrap_or(DEFAULT_STORAGE_SIZE_GIB),
            storage_gb,
        ),
        (
            ManagedDisk::Overlay,
            "overlay",
            record.overlay_gb.unwrap_or(DEFAULT_OVERLAY_SIZE_GIB),
            overlay_gb,
        ),
    ] {
        if let Some(target) = target {
            requested.push((disk, id, target, validate_growth(current, target)?));
        }
    }
    let manager = AgentManager::for_vm(name)?;
    let mut client = AgentClient::connect(manager.vsock_socket())?;
    if !client.supports_capability(ONLINE_FILESYSTEM_GROWTH_CAPABILITY)? {
        return Err(Error::agent(
            "live resize",
            "running guest agent lacks online growth support; no disks changed",
        ));
    }
    let socket = fork::control_socket_path(name);
    let capabilities = fork::control_socket_cmd(&socket, "GROW_DISK_CAPABILITIES")?;
    if capabilities.trim() != "OK grow-disk-v1" {
        return Err(Error::agent(
            "live resize",
            "running runtime lacks online disk growth support; no disks changed",
        ));
    }
    for (disk, id, target, bytes) in requested {
        let reply = fork::control_socket_cmd_with_timeout(
            &socket, &format!("GROW_DISK {id} {bytes}"), Duration::from_secs(120),
        ).map_err(|error| Error::agent("live resize", format!(
            "{id} growth outcome is unknown: {error}; reconcile or retry the same target, never shrink to roll back"
        )))?;
        if reply.trim() != format!("OK disk {id} capacity {bytes}") {
            return Err(Error::agent(
                "live resize",
                format!("{id} growth not confirmed: {reply}"),
            ));
        }
        db.update_vm(name, |record| match disk {
            ManagedDisk::Storage => record.storage_gb = Some(target),
            ManagedDisk::Overlay => record.overlay_gb = Some(target),
        })?
        .ok_or_else(|| Error::agent("live resize", "disk grew but machine record disappeared"))?;
        client.grow_filesystem(disk, bytes).map_err(|error| Error::agent(
            "live resize", format!("{id} disk is now {target} GiB; filesystem growth incomplete: {error}; retry the same target"),
        ))?;
    }
    db.get_vm(name)?
        .ok_or_else(|| Error::config("live resize", "machine record disappeared"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_growth_targets_use_runtime_boot_layout_not_a_stale_record() {
        let info = MemoryGrowthInfo::parse("OK boot_mib 1024 base 4831838208 mapped 268435456 plugged 134217728 capacity 68719476736\n").unwrap();
        assert_eq!(info.target_added_mib(1280).unwrap(), 256);
        assert_eq!(info.target_added_mib(1536).unwrap(), 512);
        for invalid in [0, 1023, 1024, 1152, 1281, 100000] {
            assert!(info.target_added_mib(invalid).is_err(), "{invalid}");
        }
        for invalid in [
            "OK mapped 0 plugged 0",
            "OK boot_mib 0 base 0 mapped 0 plugged 0 capacity 134217728",
            "OK boot_mib 1024 base 1 mapped 0 plugged 0 capacity 134217728",
            "OK boot_mib 1024 base 0 mapped 134217728 plugged 268435456 capacity 134217728",
            "OK boot_mib 1024 base 0 mapped 268435456 plugged 0 capacity 134217728",
            "OK boot_mib 1024 base 0 mapped 0 plugged 0 capacity 18446744073709551615",
        ] {
            assert!(MemoryGrowthInfo::parse(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn cpu_status_requires_valid_created_and_capacity_counts() {
        assert_eq!(cpu_status("OK created 4 capacity 16\n").unwrap(), (4, 16));
        for reply in [
            "OK created 0 capacity 16",
            "OK created 17 capacity 16",
            "OK created 4 capacity 256",
            "OK created 4 capacity 16 extra",
            "ERR EIO partial",
        ] {
            assert!(cpu_status(reply).is_err(), "{reply}");
        }
    }

    #[test]
    fn live_disk_targets_never_shrink_or_overflow() {
        assert!(validate_growth(2, 1).is_err());
        assert!(validate_growth(0, 0).is_err());
        assert!(validate_growth(1, u64::MAX).is_err());
        assert_eq!(validate_growth(2, 2).unwrap(), 2 << 30);
        assert_eq!(validate_growth(2, 4).unwrap(), 4 << 30);
    }
}
