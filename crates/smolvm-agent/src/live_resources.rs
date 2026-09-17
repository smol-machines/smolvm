//! Online filesystem growth for managed disks; no offline repair fallback.

use smolvm_protocol::{error_codes, AgentResponse, ManagedDisk};
use std::fs::File;
use std::io::{self, Seek, SeekFrom};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::io::RawFd;
use std::sync::Mutex;

static RESIZE: Mutex<()> = Mutex::new(());

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
    let preflight = (|| -> io::Result<()> {
        let mut file = File::open(device)?;
        if !file.metadata()?.file_type().is_block_device() {
            return Err(io::Error::other("managed disk is not a block device"));
        }
        validate_capacity(file.seek(SeekFrom::End(0))?, expected)?;
        let mounts = std::fs::read_to_string("/proc/mounts")?;
        if !mounts.lines().any(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            fields.len() >= 4
                && fields[0] == device
                && fields[2] == "ext4"
                && fields[3].split(',').any(|option| option == "rw")
        }) {
            return Err(io::Error::other(
                "managed disk must already be mounted read-write as ext4",
            ));
        }
        Ok(())
    })();
    if let Err(error) = preflight {
        return AgentResponse::error(
            format!("cannot grow filesystem: {error}"),
            error_codes::INVALID_REQUEST,
        );
    }
    // The existing exec supervisor bounds runtime and reaps the child on
    // disconnect. A timeout does not imply rollback: callers must reconcile
    // the actual filesystem size before retrying. Never invoke e2fsck here.
    crate::handle_vm_exec(
        &["resize2fs".into(), device.into()],
        &[],
        None,
        Some(120_000),
        client_fd,
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn growth_waits_for_exact_guest_capacity() {
        assert!(validate_capacity(1024, 2048).is_err());
        assert!(validate_capacity(4096, 2048).is_err());
        assert!(validate_capacity(0, 0).is_err());
        assert!(validate_capacity(513, 513).is_err());
        assert!(validate_capacity(2048, 2048).is_ok());
    }
}
