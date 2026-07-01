//! Guest wall-clock sync from the host over a vsock DGRAM (port 123).
//!
//! On hypervisors without a guest-readable paravirt clock (macOS/HVF and
//! Windows/WHP), libkrun's host-side `TimesyncThread` pushes the host's
//! `CLOCK_REALTIME` to the guest — at boot, every 60s, and (critically) as soon
//! as it detects the host was suspended (lid closed / sleep). During host sleep
//! the VM is frozen, so the guest clock stops; without a receiver it falls
//! behind by the accumulated sleep and eventually breaks TLS / signed package
//! indexes inside the guest (issue #521). The agent runs as PID-1 with
//! `CAP_SYS_TIME`, so — unlike the unprivileged container — it can apply the fix.
//!
//! Each host datagram is an 8-byte little-endian u64: host `CLOCK_REALTIME` in
//! nanoseconds (see libkrun `vsock/timesync.rs::write_time_sync`). Mirrors
//! libkrun's own guest reader (`init/src/timesync.rs`), but as a thread since
//! the agent is long-lived (it never `exec`s away, so it needs no `fork`).

use std::mem;

const AF_VSOCK: libc::c_int = 40;
const VMADDR_CID_ANY: u32 = u32::MAX;
const TSYNC_PORT: u32 = 123;
const NANOS_IN_SECOND: u64 = 1_000_000_000;
/// Ignore sub-100ms drift — matches libkrun's guest reader.
const DELTA_SYNC_NS: u64 = 100_000_000;

#[repr(C)]
struct sockaddr_vm {
    svm_family: libc::sa_family_t,
    svm_reserved1: u16,
    svm_port: u32,
    svm_cid: u32,
    svm_zero: [u8; 4],
}

/// Spawn the host→guest clock-sync receiver as a background thread. Best-effort:
/// on any setup error the thread exits and the boot-seeded clock stands.
pub fn spawn() {
    let _ = std::thread::Builder::new()
        .name("timesync".into())
        .spawn(run);
}

fn run() {
    // AF_VSOCK DGRAM bound to port 123 — the port libkrun's TimesyncThread sends
    // to. VMADDR_CID_ANY: accept from the host CID.
    let fd = unsafe { libc::socket(AF_VSOCK, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return;
    }
    let addr = sockaddr_vm {
        svm_family: AF_VSOCK as libc::sa_family_t,
        svm_reserved1: 0,
        svm_port: TSYNC_PORT,
        svm_cid: VMADDR_CID_ANY,
        svm_zero: [0; 4],
    };
    let rc = unsafe {
        libc::bind(
            fd,
            &addr as *const sockaddr_vm as *const libc::sockaddr,
            mem::size_of::<sockaddr_vm>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        unsafe { libc::close(fd) };
        return;
    }

    let mut buf = [0u8; 8];
    loop {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n < 0 {
            break; // socket error — give up (the boot clock stands)
        }
        if n != 8 {
            continue; // malformed datagram — ignore
        }

        let host_ns = u64::from_le_bytes(buf);
        if host_ns.abs_diff(current_realtime_ns()) > DELTA_SYNC_NS {
            let ts = libc::timespec {
                tv_sec: (host_ns / NANOS_IN_SECOND) as libc::time_t,
                tv_nsec: (host_ns % NANOS_IN_SECOND) as libc::c_long,
            };
            // SAFETY: ts is a valid timespec; the agent is PID-1 with CAP_SYS_TIME.
            unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &ts) };
        }
    }
    unsafe { libc::close(fd) };
}

fn current_realtime_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is a valid, writable timespec.
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    ts.tv_sec as u64 * NANOS_IN_SECOND + ts.tv_nsec as u64
}
