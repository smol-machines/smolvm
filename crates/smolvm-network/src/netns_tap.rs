//! CNI netns ↔ virtio-net L2 bridge for the Kubernetes runtime.
//!
//! Kubernetes semantics require the pod to live *in* its CNI-allocated network
//! namespace with the CNI-assigned IP, reachable at L2 from other pods — which
//! the smoltcp NAT gateway ([`crate::frame_stream`]) deliberately does not
//! provide. This module gives the alternative "netns-tap" datapath the
//! containerd shim uses (see docs/kubernetes-runtime.md):
//!
//! ```text
//!  CNI netns                         host (shim)                 guest
//!  ┌─────────┐   ethernet frames   ┌──────────────┐  unixstream ┌────────┐
//!  │  tapX    │◀───────────────────▶│ netns_tap    │◀───────────▶│ libkrun │
//!  │ (vethed  │   raw, no framing   │ frame pump   │  4B-len +   │virtio-  │
//!  │  by CNI) │                     │              │   frame     │  net    │
//!  └─────────┘                     └──────────────┘             └────────┘
//! ```
//!
//! The shim opens a tap **inside the pod netns**, plugs it into the CNI bridge
//! the same way a container veth would be, and pumps raw Ethernet frames
//! between the tap fd and libkrun's unixstream (which uses the
//! `[4-byte BE length][frame]` protocol from [`crate::frame_stream`]). No IP
//! logic lives here — the guest configures the CNI address/routes/MTU
//! statically from boot config; this is a pure L2 wire.

use std::io;
use std::net::Shutdown;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use crate::frame_stream::{read_frame, write_frame};

/// Largest Ethernet frame we relay (jumbo-safe MTU + header + VLAN slack).
const TAP_READ_BUF: usize = 65_536;

/// A running netns-tap bridge. Dropping it signals both pump threads to stop
/// and joins them; the tap fd closes with the bridge.
pub struct NetnsTapBridge {
    stop: Arc<AtomicBool>,
    stream: Arc<UnixStream>,
    wake_sockets: Vec<UnixStream>,
    threads: Vec<JoinHandle<()>>,
}

impl NetnsTapBridge {
    /// Stop the pumps and join. Idempotent; also called on drop.
    pub fn shutdown(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Closing a duplicated TAP fd does not reliably interrupt a read that
        // is already blocked in another thread. The TAP workers therefore poll
        // dedicated wake sockets, while shutting down the shared Unix stream
        // interrupts any framed read or write already in progress.
        let _ = self.stream.shutdown(Shutdown::Both);
        for wake in &self.wake_sockets {
            let _ = wake.shutdown(Shutdown::Both);
        }
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

impl Drop for NetnsTapBridge {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Pump raw Ethernet frames between a tap fd and libkrun's unixstream.
///
/// `tap` is a TAP device fd opened with `IFF_NO_PI` (no 4-byte packet-info
/// prefix — payloads are bare Ethernet frames). `stream` is the AF_UNIX stream
/// libkrun is given for its virtio-net backend. Two threads run until either
/// side closes or [`NetnsTapBridge::shutdown`] is called:
/// - **tap → stream**: `read()` a frame from the tap, `write_frame` it (adds the
///   4-byte length prefix libkrun expects).
/// - **stream → tap**: `read_frame` (strips the prefix), `write()` the raw frame
///   to the tap.
pub fn start_netns_tap_bridge(stream: UnixStream, tap: OwnedFd) -> io::Result<NetnsTapBridge> {
    // TAP writes can otherwise block behind a full device queue after shutdown
    // begins. Both duplicated fds share this file status flag.
    set_nonblocking(tap.as_raw_fd())?;
    let tap_rx = tap.try_clone()?;
    let tap_tx = tap;
    let stream = Arc::new(stream);
    let (tap_wake_worker, tap_wake_control) = UnixStream::pair()?;
    let (stream_wake_worker, stream_wake_control) = UnixStream::pair()?;

    let stop = Arc::new(AtomicBool::new(false));

    let stop_a = stop.clone();
    let stream_tx = stream.clone();
    let t_up = std::thread::Builder::new()
        .name("netns-tap-tx".into())
        .spawn(move || pump_tap_to_stream(tap_rx, stream_tx, tap_wake_worker, &stop_a))?;

    let stop_b = stop.clone();
    let stream_rx = stream.clone();
    let t_down = match std::thread::Builder::new()
        .name("netns-tap-rx".into())
        .spawn(move || pump_stream_to_tap(stream_rx, tap_tx, stream_wake_worker, &stop_b))
    {
        Ok(thread) => thread,
        Err(error) => {
            stop.store(true, Ordering::SeqCst);
            let _ = stream.shutdown(Shutdown::Both);
            let _ = tap_wake_control.shutdown(Shutdown::Both);
            let _ = stream_wake_control.shutdown(Shutdown::Both);
            let _ = t_up.join();
            return Err(error);
        }
    };

    Ok(NetnsTapBridge {
        stop,
        stream,
        wake_sockets: vec![tap_wake_control, stream_wake_control],
        threads: vec![t_up, t_down],
    })
}

fn pump_tap_to_stream(tap: OwnedFd, stream: Arc<UnixStream>, wake: UnixStream, stop: &AtomicBool) {
    let mut buf = vec![0u8; TAP_READ_BUF];
    let fd = tap.as_raw_fd();
    while !stop.load(Ordering::SeqCst) {
        match wait_for_fd(fd, libc::POLLIN, wake.as_raw_fd(), stop) {
            Ok(true) => {}
            Ok(false) => break,
            Err(e) => {
                if !stop.load(Ordering::SeqCst) {
                    tracing::debug!("netns-tap: tap poll ended: {e}");
                }
                break;
            }
        }
        match read_fd(fd, &mut buf) {
            Ok(0) => break, // tap closed
            Ok(n) => {
                let mut stream = stream.as_ref();
                if let Err(e) = write_frame(&mut stream, &buf[..n]) {
                    if !stop.load(Ordering::SeqCst) {
                        tracing::debug!("netns-tap: stream write ended: {e}");
                    }
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                if !stop.load(Ordering::SeqCst) {
                    tracing::debug!("netns-tap: tap read ended: {e}");
                }
                break;
            }
        }
    }
}

fn pump_stream_to_tap(stream: Arc<UnixStream>, tap: OwnedFd, wake: UnixStream, stop: &AtomicBool) {
    let fd = tap.as_raw_fd();
    while !stop.load(Ordering::SeqCst) {
        let mut stream = stream.as_ref();
        match read_frame(&mut stream) {
            Ok(frame) => match write_tap_frame(fd, &frame, wake.as_raw_fd(), stop) {
                Ok(true) => {}
                Ok(false) => break,
                Err(e) => {
                    if !stop.load(Ordering::SeqCst) {
                        tracing::debug!("netns-tap: tap write ended: {e}");
                    }
                    break;
                }
            },
            Err(e) => {
                if !stop.load(Ordering::SeqCst) {
                    tracing::debug!("netns-tap: stream read ended: {e}");
                }
                break;
            }
        }
    }
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if flags & libc::O_NONBLOCK == 0
        && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Wait for TAP readiness or an explicit bridge shutdown wakeup.
fn wait_for_fd(fd: RawFd, events: i16, wake_fd: RawFd, stop: &AtomicBool) -> io::Result<bool> {
    while !stop.load(Ordering::SeqCst) {
        let mut fds = [
            libc::pollfd {
                fd,
                events,
                revents: 0,
            },
            libc::pollfd {
                fd: wake_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let result = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, -1) };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if stop.load(Ordering::SeqCst)
            || fds[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0
        {
            return Ok(false);
        }
        if fds[0].revents & (events | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            return Ok(true);
        }
    }
    Ok(false)
}

// Raw fd read/write: the tap fd is a character device, not a std type. Using
// libc directly avoids wrapping it in a File (whose Drop would double-close a
// try_clone'd fd we already own).

fn read_fd(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

fn write_tap_frame(fd: RawFd, buf: &[u8], wake_fd: RawFd, stop: &AtomicBool) -> io::Result<bool> {
    loop {
        if !wait_for_fd(fd, libc::POLLOUT, wake_fd, stop)? {
            return Ok(false);
        }
        // One write() call per Ethernet frame (tap semantics are datagram-like).
        let n = unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
        if n < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock
                || error.kind() == io::ErrorKind::Interrupted
            {
                continue;
            }
            return Err(error);
        }
        if (n as usize) != buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short tap write truncated an ethernet frame",
            ));
        }
        return Ok(true);
    }
}

/// Open a TAP device inside the network namespace at `netns_path` and return
/// its fd. The tap is created with `IFF_TAP | IFF_NO_PI`, named `ifname`, and
/// brought up; the CNI plugin (already run by containerd) owns bridging it into
/// the pod network. The fd remains valid in the caller's process after we
/// switch back to the original netns — only the *device* lives in the pod's
/// netns.
///
/// Requires `CAP_SYS_ADMIN`. Isolated so the frame pump can be unit-tested
/// without root ([`start_netns_tap_bridge`] takes any `OwnedFd`).
#[cfg(target_os = "linux")]
pub fn open_tap_in_netns(netns_path: &str, ifname: &str) -> io::Result<OwnedFd> {
    use std::fs::File;
    use std::os::fd::AsFd;

    if ifname.len() >= libc::IFNAMSIZ {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name too long",
        ));
    }

    // Remember our current netns so we can return to it no matter what.
    let self_ns = File::open("/proc/self/ns/net")?;
    let target = File::open(netns_path)?;

    // setns(CLONE_NEWNET) affects only the calling thread, so do the whole
    // enter → create tap → restore on a dedicated scoped thread. That keeps the
    // caller's thread (and any tokio worker it belongs to) in the host netns.
    let ifname = ifname.to_string();
    std::thread::scope(|s| {
        s.spawn(|| -> io::Result<OwnedFd> {
            enter_netns(target.as_fd().as_raw_fd())?;
            let res = create_tap(&ifname);
            // Always attempt to restore, even on failure — a scoped worker left
            // in the pod netns would be a latent bug if the platform ever
            // pooled it (it does not today, but don't rely on that).
            let _ = enter_netns(self_ns.as_fd().as_raw_fd());
            res
        })
        .join()
        .map_err(|_| io::Error::other("tap-open thread panicked"))?
    })
}

/// Wire a tap (created by [`open_tap_in_netns`]) into the pod's CNI datapath via
/// `tc` mirred redirect: every frame arriving on the CNI interface (`cni_if` —
/// the veth the CNI plugin placed in the netns) is redirected to the tap's
/// egress (into the VM), and every frame the VM emits on the tap is redirected
/// back onto the CNI interface. The guest NIC, configured with the pod's CNI
/// IP+MAC, thus appears on the pod network at L2. This is Kata's "tcfilter" mode
/// and works with any CNI plugin (no assumptions about bridges/veth naming).
///
/// Runs `tc` inside `netns_path` via `nsenter`. Requires CAP_NET_ADMIN; call in
/// the boot subprocess's privileged window, before any uid drop. Both `tc` and
/// `nsenter` (iproute2 + util-linux) must be on PATH — they are on every k8s node.
#[cfg(target_os = "linux")]
pub fn setup_tc_redirect(netns_path: &str, cni_if: &str, tap_if: &str) -> io::Result<()> {
    // A clsact/ingress qdisc on each device gives us the ingress hook the mirred
    // redirect attaches to. `matchall` (kernel 4.9+) classifies every frame.
    tc(netns_path, &["qdisc", "add", "dev", cni_if, "ingress"])?;
    tc(netns_path, &["qdisc", "add", "dev", tap_if, "ingress"])?;
    tc(
        netns_path,
        &[
            "filter", "add", "dev", cni_if, "ingress", "protocol", "all", "matchall", "action",
            "mirred", "egress", "redirect", "dev", tap_if,
        ],
    )?;
    tc(
        netns_path,
        &[
            "filter", "add", "dev", tap_if, "ingress", "protocol", "all", "matchall", "action",
            "mirred", "egress", "redirect", "dev", cni_if,
        ],
    )?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn tc(netns_path: &str, args: &[&str]) -> io::Result<()> {
    let out = std::process::Command::new("nsenter")
        .arg(format!("--net={netns_path}"))
        .arg("tc")
        .args(args)
        .output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "nsenter --net={netns_path} tc {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn enter_netns(ns_fd: RawFd) -> io::Result<()> {
    let rc = unsafe { libc::setns(ns_fd, libc::CLONE_NEWNET) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn create_tap(ifname: &str) -> io::Result<OwnedFd> {
    use std::os::fd::FromRawFd;

    let tun = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR) };
    if tun < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: tun >= 0 is a fresh owned fd.
    let owned = unsafe { OwnedFd::from_raw_fd(tun) };

    #[repr(C)]
    struct Ifreq {
        name: [libc::c_char; libc::IFNAMSIZ],
        flags: libc::c_short,
        _pad: [u8; 22],
    }
    let mut req = Ifreq {
        name: [0; libc::IFNAMSIZ],
        flags: (libc::IFF_TAP | libc::IFF_NO_PI) as libc::c_short,
        _pad: [0; 22],
    };
    for (i, b) in ifname.bytes().enumerate() {
        req.name[i] = b as libc::c_char;
    }
    // TUNSETIFF = _IOW('T', 202, int)
    const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
    let rc = unsafe { libc::ioctl(owned.as_raw_fd(), TUNSETIFF as _, &mut req) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }

    bring_up(ifname)?;
    Ok(owned)
}

/// `ip link set <ifname> up` via a netlink-free SIOCSIFFLAGS ioctl (we are in
/// the target netns on this thread).
#[cfg(target_os = "linux")]
fn bring_up(ifname: &str) -> io::Result<()> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }
    let _guard = scopeguard_close(sock);

    #[repr(C)]
    struct IfreqFlags {
        name: [libc::c_char; libc::IFNAMSIZ],
        flags: libc::c_short,
        _pad: [u8; 22],
    }
    let mut req = IfreqFlags {
        name: [0; libc::IFNAMSIZ],
        flags: 0,
        _pad: [0; 22],
    };
    for (i, b) in ifname.bytes().enumerate() {
        req.name[i] = b as libc::c_char;
    }
    const SIOCGIFFLAGS: libc::c_ulong = 0x8913;
    const SIOCSIFFLAGS: libc::c_ulong = 0x8914;
    if unsafe { libc::ioctl(sock, SIOCGIFFLAGS as _, &mut req) } < 0 {
        return Err(io::Error::last_os_error());
    }
    req.flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
    if unsafe { libc::ioctl(sock, SIOCSIFFLAGS as _, &mut req) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn scopeguard_close(fd: RawFd) -> impl Drop {
    struct Closer(RawFd);
    impl Drop for Closer {
        fn drop(&mut self) {
            unsafe { libc::close(self.0) };
        }
    }
    Closer(fd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::fd::OwnedFd;

    /// A socketpair stands in for both the tap fd and the libkrun stream so the
    /// pump logic runs without root or a real tap.
    fn socketpair() -> (OwnedFd, OwnedFd) {
        let mut fds = [0i32; 2];
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        assert_eq!(rc, 0);
        use std::os::fd::FromRawFd;
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }

    #[test]
    fn frames_relay_both_directions() {
        // "tap" side = a socketpair; the pump reads raw bytes from tap_far and
        // length-frames them onto the stream, and vice versa.
        let (tap_near, tap_far) = socketpair();
        let (stream_near_raw, stream_far_raw) = socketpair();
        let stream_near = UnixStream::from(stream_near_raw);
        let mut stream_far = UnixStream::from(stream_far_raw);

        let bridge = start_netns_tap_bridge(stream_near, tap_near).unwrap();

        // tap → stream: write a raw frame into the tap side; expect it framed on
        // the stream side.
        let frame = b"\xde\xad\xbe\xef hello ethernet";
        let mut tap_far_w = UnixStream::from(tap_far);
        tap_far_w.write_all(frame).unwrap();
        let got = read_frame(&mut stream_far).unwrap();
        assert_eq!(&got, frame);

        // stream → tap: write a framed packet on the stream; expect raw bytes on
        // the tap side.
        let frame2 = b"reply frame \x00\x01\x02";
        write_frame(&mut stream_far, frame2).unwrap();
        let mut buf = vec![0u8; frame2.len()];
        tap_far_w.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, frame2);

        // Both peer sockets deliberately remain open. Shutdown must wake the
        // idle TAP and stream reads instead of waiting for peer teardown.
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            drop(bridge);
            let _ = done_tx.send(());
        });
        done_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("netns TAP bridge shutdown blocked on idle I/O");
    }
}
