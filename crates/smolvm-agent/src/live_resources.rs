//! Verified guest-side resource growth; never shrink or repair offline.

use smolvm_protocol::{error_codes, AgentResponse, ManagedDisk};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{self, Seek, SeekFrom};
use std::os::unix::fs::{FileExt, FileTypeExt};
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
use std::os::unix::io::RawFd;
use std::sync::Mutex;

static RESIZE: Mutex<()> = Mutex::new(());
static CPU_RESIZE: Mutex<()> = Mutex::new(());

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
    let preflight = (|| -> io::Result<String> {
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
        Ok(mount)
    })();
    let mount = match preflight {
        Ok(mount) => mount,
        Err(error) => {
            return AgentResponse::error(
                format!("cannot grow filesystem: {error}"),
                error_codes::INVALID_REQUEST,
            )
        }
    };
    // The existing exec supervisor bounds runtime and reaps the child on
    // disconnect. A timeout does not imply rollback: callers must reconcile
    // the actual filesystem size before retrying. Never invoke e2fsck here.
    let response = crate::handle_vm_exec(
        &["resize2fs".into(), device.into()],
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
        // Flush the actual mounted filesystem, not /dev's devtmpfs, before
        // reading its on-disk superblock for the postcondition.
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

#[cfg(test)]
mod tests {
    use super::*;

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
