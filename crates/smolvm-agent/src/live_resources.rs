//! Verified guest-side resource changes; never shrink mounted filesystems.

use smolvm_protocol::{error_codes, AgentResponse, ManagedDisk};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{self, Seek, SeekFrom};
use std::os::unix::fs::{FileExt, FileTypeExt, MetadataExt};
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
use std::os::unix::io::RawFd;
use std::sync::Mutex;
use std::time::{Duration, Instant};

static RESIZE: Mutex<()> = Mutex::new(());
static CPU_RESIZE: Mutex<()> = Mutex::new(());
static MEMORY_RESIZE: Mutex<()> = Mutex::new(());

fn memory_blocks(start: u64, length: u64, block_size: u64) -> io::Result<std::ops::Range<u64>> {
    if block_size == 0
        || !block_size.is_power_of_two()
        || length == 0
        || !start.is_multiple_of(block_size)
        || !length.is_multiple_of(block_size)
        || length / block_size > 8192
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "RAM range must cover 1–8192 complete guest memory blocks",
        ));
    }
    let end = start
        .checked_add(length)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "RAM range overflows"))?;
    Ok(start / block_size..end / block_size)
}

fn memory_online_plan(
    blocks: std::ops::Range<u64>,
    mut read_state: impl FnMut(u64) -> io::Result<String>,
) -> io::Result<Vec<u64>> {
    let mut plan = Vec::new();
    // Complete validation precedes any write. A missing or transitioning block
    // is not success, and a retry never offlines already usable memory.
    for block in blocks {
        match read_state(block)?.trim() {
            "online" => {}
            "offline" => plan.push(block),
            state => {
                return Err(io::Error::other(format!(
                    "memory{block} has unsettled state {state}"
                )))
            }
        }
    }
    Ok(plan)
}

fn wait_memory_online_plan(
    blocks: std::ops::Range<u64>,
    timeout: Duration,
    mut read_state: impl FnMut(u64) -> io::Result<String>,
    mut cancelled: impl FnMut() -> bool,
) -> io::Result<Vec<u64>> {
    let deadline = Instant::now() + timeout;
    loop {
        if cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "RAM caller disconnected before onlining",
            ));
        }
        match memory_online_plan(blocks.clone(), &mut read_state) {
            // Only publication lag is retryable. Permission failures or an
            // unexpected existing state must not turn into blind retries.
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            result => return result,
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "guest did not publish the requested RAM blocks",
            ));
        }
        std::thread::sleep(remaining.min(Duration::from_millis(20)));
    }
}

pub(crate) fn online_memory(start: u64, length: u64, client_fd: Option<RawFd>) -> AgentResponse {
    let Ok(_guard) = MEMORY_RESIZE.try_lock() else {
        return AgentResponse::error(
            "another RAM resize is in progress",
            error_codes::INVALID_REQUEST,
        );
    };
    let started = Instant::now();
    let read_state = |block: u64| {
        std::fs::read_to_string(format!("/sys/devices/system/memory/memory{block}/state"))
    };
    let preflight = (|| -> io::Result<_> {
        let size = std::fs::read_to_string("/sys/devices/system/memory/block_size_bytes")?;
        let size = u64::from_str_radix(size.trim().trim_start_matches("0x"), 16)
            .map_err(|_| io::Error::other("invalid guest memory block size"))?;
        let blocks = memory_blocks(start, length, size)?;
        let plan =
            wait_memory_online_plan(blocks.clone(), Duration::from_secs(30), read_state, || {
                client_fd.is_some_and(crate::process::is_peer_closed)
            })?;
        Ok((blocks, plan))
    })();
    let (blocks, plan) = match preflight {
        Ok(value) => value,
        Err(error) => {
            return AgentResponse::error(
                format!(
                    "cannot online RAM: {error}; wait for memory blocks and retry the same range"
                ),
                error_codes::INVALID_REQUEST,
            )
        }
    };
    if !plan.is_empty() {
        // Only validated numeric block IDs reach the shell. The existing exec
        // supervisor bounds a slow kernel write and handles client disconnect.
        let script = plan
            .iter()
            .map(|block| format!("printf online > /sys/devices/system/memory/memory{block}/state"))
            .collect::<Vec<_>>()
            .join("; ");
        let response = crate::handle_vm_exec(
            &["/bin/sh".into(), "-ec".into(), script],
            &[],
            None,
            Some(120_000u64.saturating_sub(started.elapsed().as_millis() as u64)),
            client_fd,
            None,
        );
        if !matches!(response, AgentResponse::Completed { exit_code: 0, .. }) {
            return AgentResponse::error("RAM onlining incomplete; some blocks may be online, retry the same range without shrinking", error_codes::INTERNAL_ERROR);
        }
    }
    match memory_online_plan(blocks, read_state) {
        Ok(remaining) if remaining.is_empty() => AgentResponse::Ok {
            data: Some(serde_json::json!({"start_address": start, "online_bytes": length})),
        },
        _ => AgentResponse::error(
            "RAM online state could not be verified; retry the same range",
            error_codes::INTERNAL_ERROR,
        ),
    }
}

fn parse_cpu_list(value: &str) -> io::Result<BTreeSet<u32>> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid kernel CPU list");
    let mut cpus = BTreeSet::new();
    for part in value.trim().split(',') {
        let (first, last) = part.split_once('-').unwrap_or((part, part));
        let first: u32 = first.parse().map_err(|_| invalid())?;
        let last: u32 = last.parse().map_err(|_| invalid())?;
        // Bound parsing independently of the requested count. This is not
        // the VMM's capacity; larger kernel topologies fail explicitly.
        if first > last || last >= 8192 {
            return Err(invalid());
        }
        cpus.extend(first..=last);
    }
    Ok(cpus)
}

fn cpu_online_plan(
    present: &BTreeSet<u32>,
    online: &BTreeSet<u32>,
    count: u8,
) -> io::Result<Vec<u32>> {
    let target: BTreeSet<_> = (0..u32::from(count)).collect();
    if count == 0 || !online.is_subset(&target) || !target.is_subset(present) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "CPU target must include every online CPU and be present in the guest topology",
        ));
    }
    Ok(target.difference(online).copied().collect())
}

pub(crate) fn online_cpus(count: u8, client_fd: Option<RawFd>) -> AgentResponse {
    let Ok(_guard) = CPU_RESIZE.try_lock() else {
        return AgentResponse::error(
            "another CPU resize is in progress",
            error_codes::INVALID_REQUEST,
        );
    };
    let read_list = |name: &str| -> io::Result<BTreeSet<u32>> {
        parse_cpu_list(&std::fs::read_to_string(format!(
            "/sys/devices/system/cpu/{name}"
        ))?)
    };
    let plan = read_list("present").and_then(|present| {
        read_list("online").and_then(|online| cpu_online_plan(&present, &online, count))
    });
    let plan = match plan {
        Ok(plan) => plan,
        Err(error) => {
            return AgentResponse::error(
                format!("cannot online CPUs: {error}"),
                error_codes::INVALID_REQUEST,
            )
        }
    };
    if !plan.is_empty() {
        // Only validated numeric IDs enter this script. The exec supervisor
        // bounds slow kernel CPU startup and reaps the writer on disconnect.
        // Never offline CPUs to roll back a partial success.
        let script = plan
            .iter()
            .map(|cpu| format!("printf 1 > /sys/devices/system/cpu/cpu{cpu}/online"))
            .collect::<Vec<_>>()
            .join("; ");
        let response = crate::handle_vm_exec(
            &["/bin/sh".into(), "-ec".into(), script],
            &[],
            None,
            Some(120_000),
            client_fd,
            None,
        );
        if !matches!(response, AgentResponse::Completed { exit_code: 0, .. }) {
            return AgentResponse::error(
                "CPU onlining did not complete; some CPUs may already be online, reconcile before retrying",
                error_codes::INTERNAL_ERROR,
            );
        }
    }
    match read_list("online") {
        Ok(online) if online == (0..u32::from(count)).collect() => AgentResponse::Ok {
            data: Some(serde_json::json!({"online_cpus": count})),
        },
        _ => AgentResponse::error(
            "CPU online count could not be verified; reconcile before retrying",
            error_codes::INTERNAL_ERROR,
        ),
    }
}

fn cpu_offline_plan(
    present: &BTreeSet<u32>,
    online: &BTreeSet<u32>,
    count: u8,
) -> io::Result<Vec<u32>> {
    let target: BTreeSet<_> = (0..u32::from(count)).collect();
    if count == 0 || !online.is_subset(present) || !target.is_subset(online) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "CPU shrink must retain CPU0 and all requested CPUs already online",
        ));
    }
    Ok(online.difference(&target).rev().copied().collect())
}

pub(crate) fn offline_cpus(count: u8, client_fd: Option<RawFd>) -> AgentResponse {
    let Ok(_guard) = CPU_RESIZE.try_lock() else {
        return AgentResponse::error(
            "another CPU resize is in progress",
            error_codes::INVALID_REQUEST,
        );
    };
    let read = |name| {
        parse_cpu_list(&std::fs::read_to_string(format!(
            "/sys/devices/system/cpu/{name}"
        ))?)
    };
    let plan = read("present").and_then(|present| {
        read("online").and_then(|online| cpu_offline_plan(&present, &online, count))
    });
    let plan = match plan {
        Ok(plan) => plan,
        Err(error) => {
            return AgentResponse::error(
                format!("cannot offline CPUs: {error}"),
                error_codes::INVALID_REQUEST,
            )
        }
    };
    if !plan.is_empty() {
        // Let the kernel migrate tasks and veto unsafe CPU removal. A partial
        // operation is reported as such; never lower host quota on this error.
        let script = plan
            .iter()
            .map(|cpu| format!("printf 0 > /sys/devices/system/cpu/cpu{cpu}/online"))
            .collect::<Vec<_>>()
            .join("; ");
        let result = crate::handle_vm_exec(
            &["/bin/sh".into(), "-ec".into(), script],
            &[],
            None,
            Some(120_000),
            client_fd,
            None,
        );
        if !matches!(result, AgentResponse::Completed { exit_code: 0, .. }) {
            return AgentResponse::error("CPU offlining incomplete; host limits must remain unchanged; retry the same target to reconcile any CPUs already offlined", error_codes::INTERNAL_ERROR);
        }
    }
    match read("online") {
        Ok(online) if online == (0..u32::from(count)).collect() => AgentResponse::Ok {
            data: Some(serde_json::json!({"online_cpus": count})),
        },
        _ => AgentResponse::error(
            "CPU offline count could not be verified; host limits must remain unchanged",
            error_codes::INTERNAL_ERROR,
        ),
    }
}

fn device_path(disk: ManagedDisk) -> &'static str {
    match disk {
        ManagedDisk::Storage => "/dev/vda",
        ManagedDisk::Overlay => "/dev/vdb",
    }
}

fn validate_capacity(actual: u64, expected: u64) -> io::Result<()> {
    if expected == 0 || !expected.is_multiple_of(512) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected capacity must be nonzero and sector aligned",
        ));
    }
    if actual != expected {
        return Err(io::Error::other(format!(
            "guest disk capacity is {actual} bytes, expected {expected}; wait for the device capacity update before growing the filesystem"
        )));
    }
    Ok(())
}

fn filesystem_bytes(superblock: &[u8; 1024]) -> io::Result<(u64, u64)> {
    let u32_at = |offset| u32::from_le_bytes(superblock[offset..offset + 4].try_into().unwrap());
    if u16::from_le_bytes([superblock[56], superblock[57]]) != 0xef53 {
        return Err(io::Error::other("managed disk has no ext4 superblock"));
    }
    let shift = u32_at(24);
    if shift > 6 {
        return Err(io::Error::other("invalid ext4 block size"));
    }
    let block_size = 1024u64 << shift;
    let mut blocks = u64::from(u32_at(4));
    if u32_at(96) & 0x80 != 0 {
        blocks |= u64::from(u32_at(0x150)) << 32;
    }
    let bytes = blocks
        .checked_mul(block_size)
        .ok_or_else(|| io::Error::other("ext4 capacity overflow"))?;
    Ok((bytes, block_size))
}

fn verify_filesystem_capacity(bytes: u64, block_size: u64, expected: u64) -> io::Result<()> {
    if bytes == 0 || bytes > expected || expected - bytes >= block_size {
        return Err(io::Error::other(format!(
            "disk grew to {expected} bytes but filesystem covers {bytes}; filesystem growth is incomplete"
        )));
    }
    Ok(())
}

fn unescape_mount_path(value: &str) -> String {
    // These are the four escapes emitted by procfs for mount paths. Decode
    // backslash last so a literal backslash plus digits is not decoded twice.
    value
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

pub(crate) fn grow_filesystem(
    disk: ManagedDisk,
    expected: u64,
    client_fd: Option<RawFd>,
) -> AgentResponse {
    let Ok(_guard) = RESIZE.try_lock() else {
        return AgentResponse::error(
            "another filesystem resize is in progress",
            error_codes::INVALID_REQUEST,
        );
    };
    let device = device_path(disk);
    let mount = match filesystem_mount(disk, expected) {
        Ok(mount) => mount,
        Err(error) => {
            return AgentResponse::error(
                format!("cannot grow filesystem: {error}"),
                error_codes::INVALID_REQUEST,
            )
        }
    };
    // Run the kernel resize in a supervised subprocess. resize2fs opens the
    // mounted block device writable, which hardened guest kernels prohibit.
    // EXT4_IOC_RESIZE_FS instead authorizes growth on the mounted filesystem.
    // A timeout never implies rollback; the existing journal reconciles it.
    let disk_name = match disk {
        ManagedDisk::Storage => "storage",
        ManagedDisk::Overlay => "overlay",
    };
    let response = crate::handle_vm_exec(
        &[
            "/proc/self/exe".into(),
            FILESYSTEM_HELPER.into(),
            disk_name.into(),
            expected.to_string(),
        ],
        &[],
        None,
        Some(120_000),
        client_fd,
        None,
    );
    if !matches!(response, AgentResponse::Completed { exit_code: 0, .. }) {
        return response;
    }
    let verified = (|| -> io::Result<u64> {
        let _mounted = File::open(mount)?;
        #[cfg(target_os = "linux")]
        if unsafe { libc::syncfs(_mounted.as_raw_fd()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let file = File::open(device)?;
        let mut sb = [0; 1024];
        file.read_exact_at(&mut sb, 1024)?;
        let (bytes, block_size) = filesystem_bytes(&sb)?;
        verify_filesystem_capacity(bytes, block_size, expected)?;
        Ok(bytes)
    })();
    match verified {
        Ok(bytes) => AgentResponse::Ok {
            data: Some(serde_json::json!({"device_bytes": expected, "filesystem_bytes": bytes})),
        },
        Err(error) => AgentResponse::error(
            format!("disk capacity changed, but filesystem growth could not be verified: {error}; reconcile before retrying"),
            error_codes::INTERNAL_ERROR,
        ),
    }
}

fn filesystem_mount(disk: ManagedDisk, expected: u64) -> io::Result<String> {
    let device = device_path(disk);
    let mut file = File::open(device)?;
    if !file.metadata()?.file_type().is_block_device() {
        return Err(io::Error::other("managed disk is not a block device"));
    }
    validate_capacity(file.seek(SeekFrom::End(0))?, expected)?;
    let mounts = std::fs::read_to_string("/proc/mounts")?;
    let mount = mounts
        .lines()
        .find_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            (fields.len() >= 4
                && fields[0] == device
                && fields[2] == "ext4"
                && fields[3].split(',').any(|option| option == "rw"))
            .then(|| unescape_mount_path(fields[1]))
        })
        .ok_or_else(|| {
            io::Error::other("managed disk must already be mounted read-write as ext4")
        })?;
    if File::open(&mount)?.metadata()?.dev() != file.metadata()?.rdev() {
        return Err(io::Error::other("managed filesystem mount changed"));
    }
    Ok(mount)
}

const FILESYSTEM_HELPER: &str = "--smolvm-grow-filesystem";

pub(crate) fn filesystem_helper_requested() -> bool {
    std::env::args().nth(1).as_deref() == Some(FILESYSTEM_HELPER)
}

fn filesystem_helper_args(args: &[String]) -> io::Result<(ManagedDisk, u64)> {
    let [disk, capacity] = args else {
        return Err(io::Error::other("expected managed disk and capacity"));
    };
    let disk = match disk.as_str() {
        "storage" => ManagedDisk::Storage,
        "overlay" => ManagedDisk::Overlay,
        _ => return Err(io::Error::other("unknown managed disk")),
    };
    let capacity = capacity.parse::<u64>().map_err(io::Error::other)?;
    validate_capacity(capacity, capacity)?;
    Ok((disk, capacity))
}

pub(crate) fn run_filesystem_helper() -> i32 {
    let result = filesystem_helper_args(&std::env::args().skip(2).collect::<Vec<_>>())
        .and_then(|(disk, expected)| online_resize(disk, expected));
    match result {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("online filesystem growth failed: {error}");
            1
        }
    }
}

fn online_resize(disk: ManagedDisk, expected: u64) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let mount = File::open(filesystem_mount(disk, expected)?)?;
        let file = File::open(device_path(disk))?;
        if mount.metadata()?.dev() != file.metadata()?.rdev() {
            return Err(io::Error::other("managed filesystem mount changed"));
        }
        let mut sb = [0; 1024];
        file.read_exact_at(&mut sb, 1024)?;
        let (bytes, block_size) = filesystem_bytes(&sb)?;
        if bytes > expected {
            return Err(io::Error::other("filesystem shrink is not supported"));
        }
        let blocks = expected / block_size;
        // Linux ext4 UAPI: _IOW('f', 16, __u64), on a pinned mount descriptor.
        let request = libc::_IOW::<u64>(b'f' as u32, 16);
        if bytes / block_size != blocks
            && unsafe { libc::ioctl(mount.as_raw_fd(), request, &blocks) } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::syncfs(mount.as_raw_fd()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (disk, expected);
        Err(io::Error::other("online filesystem growth requires Linux"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filesystem_helper_accepts_only_managed_disks_and_valid_capacities() {
        for disk in ["storage", "overlay"] {
            let (parsed, bytes) =
                filesystem_helper_args(&[disk.into(), "2147483648".into()]).unwrap();
            assert_eq!(
                device_path(parsed),
                if disk == "storage" {
                    "/dev/vda"
                } else {
                    "/dev/vdb"
                }
            );
            assert_eq!(bytes, 2 << 30);
        }
        for args in [
            vec![],
            vec!["storage"],
            vec!["/dev/vda", "512"],
            vec!["storage", "0"],
            vec!["storage", "513"],
            vec!["storage", "-512"],
            vec!["storage", "18446744073709551616"],
            vec!["storage", "512", "extra"],
        ] {
            assert!(filesystem_helper_args(
                &args.into_iter().map(String::from).collect::<Vec<_>>()
            )
            .is_err());
        }
    }

    #[test]
    fn memory_range_rejects_partial_blocks_overflow_and_unbounded_work() {
        assert_eq!(memory_blocks(1024, 512, 128).unwrap(), 8..12);
        for (start, length, block) in [
            (0, 0, 128),
            (1, 128, 128),
            (0, 129, 128),
            (0, 128, 0),
            (0, 128, 3),
            (u64::MAX - 127, 128, 128),
            (0, 8193 * 128, 128),
        ] {
            assert!(memory_blocks(start, length, block).is_err());
        }
    }

    #[test]
    fn memory_online_retries_only_offline_blocks_and_rejects_missing_or_unsettled_blocks() {
        assert_eq!(
            memory_online_plan(8..11, |id| Ok(if id == 9 {
                "online\n"
            } else {
                "offline\n"
            }
            .into()))
            .unwrap(),
            vec![8, 10]
        );
        assert!(memory_online_plan(8..11, |_| Ok("online\n".into()))
            .unwrap()
            .is_empty());
        assert!(
            memory_online_plan(8..11, |_| Err(io::Error::from(io::ErrorKind::NotFound))).is_err()
        );
        for state in ["going-offline", "", "unknown"] {
            assert!(memory_online_plan(8..11, |_| Ok(state.into())).is_err());
        }
    }

    #[test]
    fn memory_onlining_waits_for_publication_but_not_other_errors() {
        let mut attempts = 0;
        let plan = wait_memory_online_plan(
            8..9,
            Duration::from_secs(1),
            |_| {
                attempts += 1;
                if attempts < 3 {
                    Err(io::ErrorKind::NotFound.into())
                } else {
                    Ok("offline".into())
                }
            },
            || false,
        )
        .unwrap();
        assert_eq!(plan, vec![8]);
        assert_eq!(attempts, 3);
        assert_eq!(
            wait_memory_online_plan(
                8..9,
                Duration::ZERO,
                |_| Err(io::ErrorKind::NotFound.into()),
                || false
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            wait_memory_online_plan(
                8..9,
                Duration::from_secs(1),
                |_| Err(io::ErrorKind::PermissionDenied.into()),
                || false
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            wait_memory_online_plan(
                8..9,
                Duration::from_secs(1),
                |_| panic!("cancelled request must not inspect memory"),
                || true
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::Interrupted
        );
    }

    #[test]
    fn cpu_lists_are_bounded_and_validate_ranges() {
        assert_eq!(
            parse_cpu_list("0-2,5\n").unwrap(),
            BTreeSet::from([0, 1, 2, 5])
        );
        for invalid in ["", "3-1", "0-4294967295", "1-2-3", "-1", "0,"] {
            assert!(parse_cpu_list(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn cpu_growth_retries_only_missing_cpus_and_never_offlines() {
        let present = parse_cpu_list("0-15").unwrap();
        let online = parse_cpu_list("0-1").unwrap();
        assert_eq!(cpu_online_plan(&present, &online, 4).unwrap(), vec![2, 3]);
        assert!(cpu_online_plan(&present, &online, 2).unwrap().is_empty());
        assert!(cpu_online_plan(&present, &online, 0).is_err());
        assert!(cpu_online_plan(&present, &online, 1).is_err());
        assert!(cpu_online_plan(&present, &online, 17).is_err());
        assert_eq!(
            cpu_online_plan(&present, &parse_cpu_list("0-2").unwrap(), 4).unwrap(),
            vec![3]
        );
        assert!(cpu_online_plan(&parse_cpu_list("0,2-3").unwrap(), &online, 4).is_err());
    }

    #[test]
    fn cpu_shrink_preserves_boot_cpu_and_reconciles_partial_progress() {
        let present = parse_cpu_list("0-7").unwrap();
        assert_eq!(
            cpu_offline_plan(&present, &parse_cpu_list("0-5").unwrap(), 2).unwrap(),
            vec![5, 4, 3, 2]
        );
        assert_eq!(
            cpu_offline_plan(&present, &parse_cpu_list("0-1,4").unwrap(), 2).unwrap(),
            vec![4]
        );
        assert!(
            cpu_offline_plan(&present, &parse_cpu_list("0-1").unwrap(), 2)
                .unwrap()
                .is_empty()
        );
        for (online, target) in [("0-3", 0), ("1-3", 2), ("0,2-3", 2), ("0-1", 3), ("0-8", 2)] {
            assert!(cpu_offline_plan(&present, &parse_cpu_list(online).unwrap(), target).is_err());
        }
    }

    #[test]
    fn growth_waits_for_exact_guest_capacity() {
        assert!(validate_capacity(1024, 2048).is_err());
        assert!(validate_capacity(4096, 2048).is_err());
        assert!(validate_capacity(0, 0).is_err());
        assert!(validate_capacity(513, 513).is_err());
        assert!(validate_capacity(2048, 2048).is_ok());
    }

    #[test]
    fn filesystem_postcondition_rejects_partial_or_excessive_growth() {
        assert!(verify_filesystem_capacity(1024, 4096, 8192).is_err());
        assert!(verify_filesystem_capacity(12288, 4096, 8192).is_err());
        assert!(verify_filesystem_capacity(0, 4096, 0).is_err());
        assert!(verify_filesystem_capacity(8192, 4096, 8192).is_ok());
        assert!(verify_filesystem_capacity(8192, 4096, 8193).is_ok());
    }

    #[test]
    fn ext4_capacity_honors_64_bit_feature_and_rejects_overflow() {
        let mut sb = [0; 1024];
        sb[56..58].copy_from_slice(&0xef53u16.to_le_bytes());
        sb[24..28].copy_from_slice(&2u32.to_le_bytes());
        sb[4..8].copy_from_slice(&7u32.to_le_bytes());
        sb[0x150..0x154].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(filesystem_bytes(&sb).unwrap(), (7 * 4096, 4096));
        sb[96..100].copy_from_slice(&0x80u32.to_le_bytes());
        assert_eq!(filesystem_bytes(&sb).unwrap().0, ((1u64 << 32) + 7) * 4096);
        sb[0x150..0x154].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(filesystem_bytes(&sb).is_err());
    }
}
