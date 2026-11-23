//! Host side of `--serial`: a host serial device made reachable in the guest.
//!
//! The VMM drops to a per-VM uid and confines itself before the guest runs, so it
//! cannot open `/dev/ttyUSB0` or `/dev/cu.usbserial-*` itself. Instead, before that
//! drop, [`prestart`] starts one `_serial-bridge` helper per device. The helper
//! opens and configures the device as the invoking user, drops to the VM's uid,
//! and relays the device over a Unix socket in the VM's directory. libkrun dials
//! that socket when the guest agent connects to the device's vsock port, and the
//! agent hands guest programs a pty at the device's guest path.
//!
//! The helper exits when its VMM does, like the video encoder helper.

use crate::config::PublishedSocketConfig;
use smolvm_protocol::publish_socket::SocketDirection;
use std::path::Path;

/// Baud rate a device runs at when `--serial` names none.
pub const DEFAULT_BAUD: u32 = 115_200;

/// Guest path of the `index`th serial device.
pub fn guest_path(index: usize) -> String {
    format!("/dev/ttySMOL{index}")
}

/// Parse a `--serial DEVICE[:BAUD]` flag into the published-socket entry that
/// carries it. `index` numbers the machine's serial devices from 0.
pub fn parse_flag(spec: &str, index: usize) -> Result<PublishedSocketConfig, String> {
    let (device, baud) = match spec.rsplit_once(':') {
        Some((device, baud)) if !baud.is_empty() && baud.bytes().all(|b| b.is_ascii_digit()) => {
            let baud: u32 = baud
                .parse()
                .map_err(|_| format!("baud rate '{baud}' in '{spec}' is out of range"))?;
            (device, baud)
        }
        _ => (spec, DEFAULT_BAUD),
    };
    if !device.starts_with('/') {
        return Err(format!(
            "expected an absolute device path such as /dev/ttyUSB0 or /dev/cu.usbserial-0001, got '{spec}'"
        ));
    }
    if baud == 0 {
        return Err(format!("baud rate in '{spec}' must be greater than 0"));
    }
    Ok(PublishedSocketConfig {
        direction: SocketDirection::Serial,
        guest_path: guest_path(index),
        host_path: Some(device.to_string()),
        baud: Some(baud),
    })
}

/// Start a bridge helper for every serial entry in `sockets` and return the list
/// with each serial entry's host path pointing at its helper's socket, which is
/// what libkrun dials. Other entries pass through unchanged.
///
/// Runs in the boot process before it drops privileges, so each helper can open
/// its device with the invoking user's access. A device that cannot be opened
/// fails the boot: the caller asked for it by name.
pub fn prestart(
    sockets: &[PublishedSocketConfig],
    vm_dir: &Path,
    run_as: Option<(u32, u32)>,
) -> Result<Vec<PublishedSocketConfig>, String> {
    let mut out = Vec::with_capacity(sockets.len());
    let mut serial_index = 0usize;
    for spec in sockets {
        if spec.direction != SocketDirection::Serial {
            out.push(spec.clone());
            continue;
        }
        let device = spec
            .host_path
            .as_deref()
            .ok_or_else(|| format!("serial device for {} has no host path", spec.guest_path))?;
        let socket = vm_dir.join(format!("serial-{serial_index}.sock"));
        start_helper(
            Path::new(device),
            spec.baud.unwrap_or(DEFAULT_BAUD),
            &socket,
            run_as,
        )?;
        let mut bridged = spec.clone();
        bridged.host_path = Some(socket.to_string_lossy().into_owned());
        out.push(bridged);
        serial_index += 1;
    }
    Ok(out)
}

#[cfg(unix)]
fn start_helper(
    device: &Path,
    baud: u32,
    socket: &Path,
    run_as: Option<(u32, u32)>,
) -> Result<(), String> {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    // A missing device is the common mistake (unplugged, or a different name on
    // this host); say so here, where the caller sees it, rather than only in the
    // helper's log.
    std::fs::metadata(device).map_err(|e| format!("serial device {}: {e}", device.display()))?;
    let _ = std::fs::remove_file(socket);
    let exe = std::env::current_exe()
        .map_err(|e| format!("locate smolvm executable for the serial bridge: {e}"))?;
    let mut command = Command::new(exe);
    command
        .arg("_serial-bridge")
        .arg("--device")
        .arg(device)
        .arg("--baud")
        .arg(baud.to_string())
        .arg("--socket")
        .arg(socket)
        .arg("--owner-pid")
        .arg(std::process::id().to_string());
    if let Some((uid, gid)) = run_as {
        command
            .arg("--run-as-uid")
            .arg(uid.to_string())
            .arg("--run-as-gid")
            .arg(gid.to_string());
    }
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("start the serial bridge for {}: {e}", device.display()))?;
    let deadline = Instant::now() + Duration::from_secs(3);
    while !socket.exists() {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| format!("check the serial bridge for {}: {e}", device.display()))?
        {
            return Err(format!(
                "serial device {}: the bridge could not open it ({status}); check that your \
                 user may open it (on Linux, membership in the dialout or uucp group)",
                device.display()
            ));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            return Err(format!(
                "serial device {}: the bridge did not become ready within 3 seconds",
                device.display()
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    tracing::info!(device = %device.display(), baud, socket = %socket.display(), "serial bridge ready");
    Ok(())
}

#[cfg(not(unix))]
fn start_helper(
    device: &Path,
    _baud: u32,
    _socket: &Path,
    _run_as: Option<(u32, u32)>,
) -> Result<(), String> {
    Err(format!(
        "serial device {}: serial passthrough needs a Unix host",
        device.display()
    ))
}

/// Entry point for the hidden `_serial-bridge` subprocess.
#[cfg(unix)]
pub fn run_helper(
    device: &Path,
    baud: u32,
    socket: &Path,
    owner_pid: u32,
    run_as: Option<(u32, u32)>,
) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::time::Duration;

    if unsafe { libc::getppid() } as u32 != owner_pid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "serial bridge owner is not its parent",
        ));
    }
    // Open while still the invoking user, who has access to the device; the fd
    // stays usable after the drop below.
    let device_file = open_device(device, baud).map_err(|e| {
        eprintln!("[serial] cannot open {}: {e}", device.display());
        e
    })?;
    #[cfg(target_os = "linux")]
    if let Some((uid, gid)) = run_as {
        crate::process::drop_privileges(uid, gid).map_err(std::io::Error::other)?;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = run_as;

    let _ = std::fs::remove_file(socket);
    let listener = UnixListener::bind(socket)?;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;

    let watched_socket = socket.to_path_buf();
    std::thread::Builder::new()
        .name("smolvm-serial-owner-watch".into())
        .spawn(move || loop {
            std::thread::sleep(Duration::from_millis(500));
            if unsafe { libc::getppid() } as u32 != owner_pid {
                let _ = std::fs::remove_file(&watched_socket);
                std::process::exit(0);
            }
        })?;

    // One guest connection at a time: a serial line has one other end.
    for connection in listener.incoming() {
        match connection {
            Ok(stream) => match relay(&device_file, stream) {
                Ok(RelayEnd::GuestClosed) => continue,
                Ok(RelayEnd::DeviceClosed) => {
                    eprintln!("[serial] {} went away", device.display());
                    let _ = std::fs::remove_file(socket);
                    return Ok(());
                }
                Err(e) => tracing::debug!(error = %e, "serial relay ended"),
            },
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn run_helper(
    _device: &Path,
    _baud: u32,
    _socket: &Path,
    _owner_pid: u32,
    _run_as: Option<(u32, u32)>,
) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "serial passthrough needs a Unix host",
    ))
}

/// Open a serial device raw (no echo, no line editing, no translation) at `baud`.
#[cfg(unix)]
fn open_device(device: &Path, baud: u32) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;

    // O_NONBLOCK so the open does not wait for carrier detect on a modem-control
    // line; it is cleared again once the line is configured.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK)
        .open(device)?;
    let fd = file.as_raw_fd();
    let speed = speed_constant(baud).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unsupported baud rate {baud}"),
        )
    })?;
    unsafe {
        let mut tio: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut tio) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        libc::cfmakeraw(&mut tio);
        tio.c_cflag |= libc::CLOCAL | libc::CREAD;
        if libc::cfsetispeed(&mut tio, speed) != 0 || libc::cfsetospeed(&mut tio, speed) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::tcsetattr(fd, libc::TCSANOW, &tio) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 || libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(file)
}

/// The `speed_t` for a baud rate. BSD-derived systems (macOS) take the rate
/// itself; Linux takes one of the `B*` constants.
#[cfg(all(unix, not(target_os = "linux")))]
fn speed_constant(baud: u32) -> Option<libc::speed_t> {
    Some(baud as libc::speed_t)
}

#[cfg(target_os = "linux")]
fn speed_constant(baud: u32) -> Option<libc::speed_t> {
    Some(match baud {
        1200 => libc::B1200,
        2400 => libc::B2400,
        4800 => libc::B4800,
        9600 => libc::B9600,
        19200 => libc::B19200,
        38400 => libc::B38400,
        57600 => libc::B57600,
        115200 => libc::B115200,
        230400 => libc::B230400,
        460800 => libc::B460800,
        500000 => libc::B500000,
        921600 => libc::B921600,
        1000000 => libc::B1000000,
        1500000 => libc::B1500000,
        2000000 => libc::B2000000,
        3000000 => libc::B3000000,
        _ => return None,
    })
}

#[cfg(unix)]
#[derive(Debug, PartialEq, Eq)]
enum RelayEnd {
    GuestClosed,
    DeviceClosed,
}

/// Relay bytes between the device and one guest connection until either side
/// closes. The device stays open for the next connection when the guest closes.
#[cfg(unix)]
fn relay(
    device: &std::fs::File,
    mut guest: std::os::unix::net::UnixStream,
) -> std::io::Result<RelayEnd> {
    use std::io::{Read, Write};
    use std::os::unix::io::AsRawFd;

    let mut dev_read = device;
    let mut dev_write = device;
    let mut buf = [0u8; 16 * 1024];
    loop {
        let mut fds = [
            libc::pollfd {
                fd: device.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: guest.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        if unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) } < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if fds[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            match dev_read.read(&mut buf) {
                Ok(0) => return Ok(RelayEnd::DeviceClosed),
                Ok(n) => guest.write_all(&buf[..n])?,
                // EIO is how a tty reports a hangup, such as an unplugged adapter.
                Err(e) if e.raw_os_error() == Some(libc::EIO) => return Ok(RelayEnd::DeviceClosed),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        if fds[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            match guest.read(&mut buf) {
                Ok(0) => return Ok(RelayEnd::GuestClosed),
                Ok(n) => dev_write.write_all(&buf[..n])?,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }
}

/// The machine's serial device paths in the guest, for display.
pub fn guest_paths(sockets: &[PublishedSocketConfig]) -> Vec<(String, String)> {
    sockets
        .iter()
        .filter(|s| s.direction == SocketDirection::Serial)
        .map(|s| {
            (
                s.host_path.clone().unwrap_or_default(),
                s.guest_path.clone(),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_flag_names_the_device_and_an_optional_baud() {
        let entry = parse_flag("/dev/cu.usbserial-0001:9600", 0).unwrap();
        assert_eq!(entry.direction, SocketDirection::Serial);
        assert_eq!(entry.host_path.as_deref(), Some("/dev/cu.usbserial-0001"));
        assert_eq!(entry.baud, Some(9600));
        assert_eq!(entry.guest_path, "/dev/ttySMOL0");

        let entry = parse_flag("/dev/ttyACM0", 2).unwrap();
        assert_eq!(entry.baud, Some(DEFAULT_BAUD));
        assert_eq!(entry.guest_path, "/dev/ttySMOL2");
    }

    #[test]
    fn a_relative_path_or_a_zero_baud_is_refused() {
        assert!(parse_flag("ttyUSB0", 0).is_err());
        assert!(parse_flag("/dev/ttyUSB0:0", 0).is_err());
    }

    #[test]
    fn prestart_leaves_other_sockets_alone() {
        let mount = PublishedSocketConfig {
            direction: SocketDirection::Mount,
            guest_path: "/run/a.sock".into(),
            host_path: Some("/tmp/a.sock".into()),
            baud: None,
        };
        let out = prestart(std::slice::from_ref(&mount), Path::new("/tmp"), None).unwrap();
        assert_eq!(out, vec![mount]);
    }

    /// Bytes flow both ways between a real tty and a guest connection, using a
    /// pseudo-terminal as the device.
    #[cfg(unix)]
    #[test]
    fn the_relay_carries_bytes_both_ways_between_a_tty_and_the_guest() {
        use std::io::{Read, Write};
        use std::os::unix::io::FromRawFd;
        use std::os::unix::net::UnixStream;

        let (mut master, slave_path) = unsafe {
            let mut master: libc::c_int = -1;
            let mut slave: libc::c_int = -1;
            assert_eq!(
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut()
                ),
                0
            );
            let name = std::ffi::CStr::from_ptr(libc::ttyname(slave))
                .to_string_lossy()
                .into_owned();
            libc::close(slave);
            (std::fs::File::from_raw_fd(master), name)
        };
        let device = open_device(Path::new(&slave_path), 115_200).unwrap();
        let (host_end, mut guest_end) = UnixStream::pair().unwrap();
        let relay_thread = std::thread::spawn(move || relay(&device, host_end));

        master.write_all(b"from-device").unwrap();
        let mut got = [0u8; 11];
        guest_end.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"from-device");

        guest_end.write_all(b"to-device").unwrap();
        let mut got = [0u8; 9];
        master.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"to-device");

        drop(guest_end);
        assert_eq!(relay_thread.join().unwrap().unwrap(), RelayEnd::GuestClosed);
    }
}
