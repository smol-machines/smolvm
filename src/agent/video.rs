//! Low-latency H.264 streaming for the browser display client.
//!
//! The VMM is deliberately unable to `exec` after its Landlock/seccomp
//! sandbox is installed.  A tiny, unprivileged helper is therefore started
//! before that boundary when `SMOLVM_VIDEO` is enabled.  The helper owns
//! ffmpeg and talks to the VMM over a mode-0600 Unix socket; no codec library
//! is linked into smolvm and the VMM sandbox is not weakened.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::display::{self, DisplayFramebuffer, Frame};

const REQUEST_MAGIC: &[u8; 4] = b"SVH1";
const REQUEST_LEN: usize = 21;
const MAX_ENCODED_FRAME: usize = 16 << 20;
const MAX_RAW_FRAME: usize = 16384 * 16384 * 4;
const SOCKET_ENV: &str = "SMOLVM_VIDEO_SOCKET";

static VIDEO_SESSION_ACTIVE: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Encoder {
    Nvenc,
    VideoToolbox,
    Vaapi,
    X264,
}

impl Encoder {
    fn id(self) -> u8 {
        match self {
            Self::Nvenc => 1,
            Self::VideoToolbox => 2,
            Self::Vaapi => 3,
            Self::X264 => 4,
        }
    }

    fn from_id(id: u8) -> std::io::Result<Self> {
        match id {
            1 => Ok(Self::Nvenc),
            2 => Ok(Self::VideoToolbox),
            3 => Ok(Self::Vaapi),
            4 => Ok(Self::X264),
            _ => Err(invalid_data("unknown video encoder")),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct VideoConfig {
    encoder: Encoder,
    fps: u16,
    bitrate_kbps: u32,
    software_threads: u8,
}

impl VideoConfig {
    fn from_env() -> Result<Option<Self>, String> {
        // Unset means "use it when the host can": encoded video is on by
        // default wherever an ffmpeg is on the PATH, since a browser then
        // gets frames at a fraction of the raw cost and the raw path stays
        // the fallback. `SMOLVM_VIDEO=off` disables it outright.
        let raw = match std::env::var_os("SMOLVM_VIDEO") {
            Some(raw) => raw.to_string_lossy().trim().to_ascii_lowercase(),
            None if ffmpeg_on_path() => "auto".to_string(),
            None => return Ok(None),
        };
        if raw.is_empty() || matches!(raw.as_str(), "0" | "off" | "false" | "disabled") {
            return Ok(None);
        }

        let encoder = match raw.as_str() {
            "1" | "on" | "true" | "auto" => auto_encoder(),
            "nvenc" | "h264_nvenc" => Encoder::Nvenc,
            "videotoolbox" | "h264_videotoolbox" => Encoder::VideoToolbox,
            "vaapi" | "h264_vaapi" => Encoder::Vaapi,
            "software" | "x264" | "libx264" => Encoder::X264,
            _ => {
                return Err(format!(
                    "invalid SMOLVM_VIDEO={raw:?}; expected auto, nvenc, videotoolbox, vaapi, x264, or off"
                ));
            }
        };
        let fps = parse_bounded_env("SMOLVM_VIDEO_FPS", 60u16, 1, 240)?;
        let bitrate_mbps = parse_bounded_env("SMOLVM_VIDEO_BITRATE_MBIT", 20u32, 1, 200)?;
        let software_threads = parse_bounded_env("SMOLVM_VIDEO_THREADS", 2u8, 1, 32)?;
        Ok(Some(Self {
            encoder,
            fps,
            bitrate_kbps: bitrate_mbps * 1000,
            software_threads,
        }))
    }
}

fn parse_bounded_env<T>(name: &str, default: T, min: T, max: T) -> Result<T, String>
where
    T: Copy + Ord + std::str::FromStr + std::fmt::Display,
{
    let Some(raw) = std::env::var_os(name) else {
        return Ok(default);
    };
    let value: T = raw
        .to_string_lossy()
        .parse()
        .map_err(|_| format!("{name} must be an integer between {min} and {max}"))?;
    if value < min || value > max {
        return Err(format!("{name} must be between {min} and {max}"));
    }
    Ok(value)
}

/// Whether an `ffmpeg` binary can be found on the PATH.
fn ffmpeg_on_path() -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| {
        let candidate = dir.join(if cfg!(windows) {
            "ffmpeg.exe"
        } else {
            "ffmpeg"
        });
        candidate.is_file()
    })
}

fn auto_encoder() -> Encoder {
    #[cfg(target_os = "macos")]
    return Encoder::VideoToolbox;

    #[cfg(target_os = "linux")]
    {
        let nvidia = Path::new("/dev/nvidia0").exists() || Path::new("/dev/nvidiactl").exists();
        let vaapi = Path::new(
            &std::env::var("SMOLVM_VAAPI_DEVICE").unwrap_or_else(|_| "/dev/dri/renderD128".into()),
        )
        .exists();
        return linux_auto_encoder(nvidia, vaapi);
    }

    #[cfg(target_os = "windows")]
    return Encoder::Nvenc;

    #[allow(unreachable_code)]
    Encoder::X264
}

#[cfg(target_os = "linux")]
fn linux_auto_encoder(nvidia: bool, vaapi: bool) -> Encoder {
    if nvidia {
        Encoder::Nvenc
    } else if vaapi {
        Encoder::Vaapi
    } else {
        Encoder::X264
    }
}

/// Start the per-VM encoder broker before the VMM's filesystem/syscall
/// sandbox is installed. This is a no-op unless encoded video was requested.
/// A failure only removes the compressed viewer path; raw VNC stays usable.
pub fn prestart_helper() -> Result<(), String> {
    let Some(_) = VideoConfig::from_env()? else {
        return Ok(());
    };
    if std::env::var_os(SOCKET_ENV).is_some() {
        return Ok(());
    }

    #[cfg(not(unix))]
    return Err("the video encoder helper currently requires Unix sockets".into());

    #[cfg(unix)]
    {
        use std::process::{Command, Stdio};

        let socket = helper_socket_path();
        let _ = std::fs::remove_file(&socket);
        let exe = std::env::current_exe()
            .map_err(|e| format!("locate smolvm executable for video helper: {e}"))?;
        let mut command = Command::new(exe);
        command
            .arg("_video-encoder")
            .arg("--socket")
            .arg(&socket)
            .arg("--owner-pid")
            .arg(std::process::id().to_string());
        if let Some(uid) = std::env::var_os("SMOLVM_VM_UID") {
            let uid: u32 = uid
                .to_string_lossy()
                .parse()
                .map_err(|_| "SMOLVM_VM_UID is invalid for the video helper".to_string())?;
            let gid: u32 = std::env::var("SMOLVM_VM_GID")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(uid);
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
            .map_err(|e| format!("start video encoder helper: {e}"))?;

        let deadline = Instant::now() + Duration::from_secs(3);
        while !socket.exists() {
            if let Some(status) = child
                .try_wait()
                .map_err(|e| format!("check video encoder helper: {e}"))?
            {
                return Err(format!(
                    "video encoder helper exited during startup ({status})"
                ));
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                return Err("video encoder helper did not become ready within 3 seconds".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        // Single-threaded boot path: setting an inherited configuration value
        // here cannot race another environment reader/writer.
        std::env::set_var(SOCKET_ENV, &socket);
        tracing::info!(socket = %socket.display(), "video encoder helper ready");
        Ok(())
    }
}

fn helper_socket_path() -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    std::env::temp_dir().join(format!(
        "smolvm-video-{}-{nonce:08x}.sock",
        std::process::id()
    ))
}

/// Whether encoded video is configured for this VMM, explicitly or by
/// default because an ffmpeg is on the PATH.
pub fn is_configured() -> bool {
    VideoConfig::from_env().ok().flatten().is_some()
}

/// Whether this VMM has an enabled, pre-started encoder helper.
pub fn is_available() -> bool {
    VideoConfig::from_env().ok().flatten().is_some() && std::env::var_os(SOCKET_ENV).is_some()
}

/// Stream H.264 frames to one browser WebSocket.
///
/// Input continues over the ordinary RFB WebSocket.  This socket is video
/// only, which lets an encoder failure close and transparently fall back to
/// Raw RFB without losing the keyboard/pointer session.
#[cfg(unix)]
pub(crate) fn serve_browser<S: Read + Write>(
    mut ws: super::websocket::WsStream<S>,
    fb: Arc<DisplayFramebuffer>,
) -> std::io::Result<()> {
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;

    if VIDEO_SESSION_ACTIVE
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "an encoded-video viewer is already connected",
        ));
    }
    struct SessionGuard;
    impl Drop for SessionGuard {
        fn drop(&mut self) {
            VIDEO_SESSION_ACTIVE.store(false, Ordering::Release);
        }
    }
    let _guard = SessionGuard;

    let config = VideoConfig::from_env()
        .map_err(invalid_input)?
        .ok_or_else(|| invalid_input("encoded video is disabled"))?;
    let socket = std::env::var_os(SOCKET_ENV)
        .ok_or_else(|| invalid_input("video encoder helper is unavailable"))?;

    // The guest may still be booting when the browser connects.
    let first = fb
        .wait_for_frame(0, Duration::from_secs(10))
        .or_else(|| fb.latest())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::TimedOut, "no display frame"))?;
    let width = first.width;
    let height = first.height;

    let mut encoder = UnixStream::connect(PathBuf::from(socket))?;
    write_request(&mut encoder, config, width, height)?;

    let mut feeder = encoder.try_clone()?;
    let feeder_fb = Arc::clone(&fb);
    let feeder_thread = std::thread::Builder::new()
        .name("smolvm-video-feed".into())
        .spawn(move || {
            let result = feed_frames(&mut feeder, feeder_fb, first, config.fps);
            // `try_clone` duplicates one socket endpoint; merely dropping this
            // fd does not produce EOF while the reader fd remains open.  An
            // explicit half-close wakes the helper on resize or feed failure.
            let _ = feeder.shutdown(std::net::Shutdown::Write);
            result
        })?;

    // Do not advertise the decoder until the helper has emitted a real access
    // unit.  A missing ffmpeg or unsupported device then becomes a clean close
    // and the page falls back to Raw RFB instead of showing a black canvas.
    let mut first_packet = true;
    let result = loop {
        let mut len = [0u8; 4];
        if let Err(e) = encoder.read_exact(&mut len) {
            break Err(e);
        }
        let len = u32::from_be_bytes(len) as usize;
        if !(10..=MAX_ENCODED_FRAME).contains(&len) {
            break Err(invalid_data("invalid encoded video packet length"));
        }
        let mut packet = vec![0u8; len];
        if let Err(e) = encoder.read_exact(&mut packet) {
            break Err(e);
        }
        if first_packet {
            let mut hello = Vec::with_capacity(12);
            hello.push(0); // stream configuration
            hello.extend_from_slice(&width.to_be_bytes());
            hello.extend_from_slice(&height.to_be_bytes());
            hello.extend_from_slice(&config.fps.to_be_bytes());
            hello.push(0); // protocol flags, reserved
            if let Err(e) = ws.write_binary(&hello) {
                break Err(e);
            }
            first_packet = false;
        }
        if let Err(e) = ws.write_binary(&packet) {
            break Err(e);
        }
    };

    let _ = encoder.shutdown(Shutdown::Both);
    let _ = feeder_thread.join();
    result
}

#[cfg(not(unix))]
pub(crate) fn serve_browser<S: Read + Write>(
    _ws: super::websocket::WsStream<S>,
    _fb: Arc<DisplayFramebuffer>,
) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "encoded video currently requires Unix sockets",
    ))
}

#[cfg(unix)]
fn write_request<W: Write>(
    out: &mut W,
    config: VideoConfig,
    width: u32,
    height: u32,
) -> std::io::Result<()> {
    let mut request = Vec::with_capacity(REQUEST_LEN);
    request.extend_from_slice(REQUEST_MAGIC);
    request.push(1); // protocol version
    request.push(config.encoder.id());
    request.extend_from_slice(&config.fps.to_be_bytes());
    request.extend_from_slice(&width.to_be_bytes());
    request.extend_from_slice(&height.to_be_bytes());
    request.extend_from_slice(&config.bitrate_kbps.to_be_bytes());
    request.push(config.software_threads);
    debug_assert_eq!(request.len(), REQUEST_LEN);
    out.write_all(&request)
}

#[cfg(unix)]
fn read_request<R: Read>(input: &mut R) -> std::io::Result<(VideoConfig, u32, u32)> {
    let mut request = [0u8; REQUEST_LEN];
    input.read_exact(&mut request)?;
    if &request[..4] != REQUEST_MAGIC || request[4] != 1 {
        return Err(invalid_data("invalid video helper request"));
    }
    let config = VideoConfig {
        encoder: Encoder::from_id(request[5])?,
        fps: u16::from_be_bytes(request[6..8].try_into().unwrap()),
        bitrate_kbps: u32::from_be_bytes(request[16..20].try_into().unwrap()),
        software_threads: request[20],
    };
    let width = u32::from_be_bytes(request[8..12].try_into().unwrap());
    let height = u32::from_be_bytes(request[12..16].try_into().unwrap());
    if config.fps == 0
        || config.fps > 240
        || config.bitrate_kbps == 0
        || config.software_threads == 0
        || config.software_threads > 32
        || width == 0
        || height == 0
        || width > 16384
        || height > 16384
    {
        return Err(invalid_data("video helper request is out of range"));
    }
    Ok((config, width, height))
}

#[cfg(unix)]
fn feed_frames<W: Write>(
    out: &mut W,
    fb: Arc<DisplayFramebuffer>,
    mut frame: Frame,
    fps: u16,
) -> std::io::Result<()> {
    let interval = Duration::from_nanos(1_000_000_000 / u64::from(fps));
    let mut next = Instant::now();
    let mut generation = frame.generation;
    // The Annex-B parser uses the next AUD as the prior frame's boundary.
    // One duplicate after activity flushes the final changed frame; after
    // that an idle desktop sends no raw pixels at all.
    // Hardware encoders hold several frames before emitting one (VideoToolbox
    // emits its first access unit after the seventh input), so a lone change
    // such as a typed character would sit in the encoder until enough later
    // frames arrive. After every change the unchanged frame is repeated at
    // the full cadence for this many ticks, which pushes the change through
    // in a few tens of milliseconds for a few small delta frames.
    const FLUSH_TICKS: u32 = 8;
    let mut flush_ticks = FLUSH_TICKS;
    // Once quiet, the unchanged frame is still repeated slowly so a viewer
    // that connects to an idle desktop gets a picture at all.
    const IDLE_INTERVAL: Duration = Duration::from_secs(1);
    let mut last_written = Instant::now();
    write_raw_frame(out, &frame)?;
    loop {
        next += interval;
        let now = Instant::now();
        if next <= now {
            next = now + interval;
        }
        std::thread::sleep(next.saturating_duration_since(now));

        // Pull only the newest frame at the configured cadence, dropping
        // intermediate presents rather than building latency under load.
        let current_generation = fb.current_generation();
        if current_generation != generation {
            let Some(newer) = fb.latest() else { continue };
            if (newer.width, newer.height) != (frame.width, frame.height) {
                return Err(invalid_data(
                    "display size changed; reconnecting through Raw RFB",
                ));
            }
            generation = newer.generation;
            frame = newer;
            write_raw_frame(out, &frame)?;
            last_written = Instant::now();
            flush_ticks = FLUSH_TICKS;
        } else if flush_ticks > 0 || last_written.elapsed() >= IDLE_INTERVAL {
            write_raw_frame(out, &frame)?;
            last_written = Instant::now();
            flush_ticks = flush_ticks.saturating_sub(1);
        }
    }
}

#[cfg(unix)]
fn write_raw_frame<W: Write>(out: &mut W, frame: &Frame) -> std::io::Result<()> {
    let pixels = display::to_bgrx(frame);
    if pixels.len() > MAX_RAW_FRAME {
        return Err(invalid_data("raw video frame exceeds maximum size"));
    }
    out.write_all(&(pixels.len() as u32).to_be_bytes())?;
    out.write_all(&pixels)
}

/// Entry point for the hidden `_video-encoder` subprocess.
#[cfg(unix)]
pub fn run_helper(
    socket: &Path,
    owner_pid: u32,
    run_as: Option<(u32, u32)>,
) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    if unsafe { libc::getppid() } as u32 != owner_pid {
        return Err(invalid_input("video helper owner is not its parent"));
    }
    #[cfg(target_os = "linux")]
    if let Some((uid, gid)) = run_as {
        let needs_video_device = VideoConfig::from_env()
            .ok()
            .flatten()
            .is_none_or(|config| config.encoder != Encoder::X264);
        drop_encoder_privileges(uid, gid, needs_video_device).map_err(std::io::Error::other)?;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = run_as;
    let _ = std::fs::remove_file(socket);
    let listener = UnixListener::bind(socket)?;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;

    let watched_socket = socket.to_path_buf();
    std::thread::Builder::new()
        .name("smolvm-video-owner-watch".into())
        .spawn(move || loop {
            std::thread::sleep(Duration::from_millis(500));
            if unsafe { libc::getppid() } as u32 != owner_pid {
                let _ = std::fs::remove_file(&watched_socket);
                std::process::exit(0);
            }
        })?;

    for connection in listener.incoming() {
        match connection {
            Ok(mut stream) => {
                if let Err(e) = encode_session(&mut stream) {
                    if is_client_disconnect(&e) {
                        tracing::debug!(error = %e, "video encoder client disconnected");
                    } else {
                        tracing::warn!(error = %e, "video encoder session ended");
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn is_client_disconnect(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::UnexpectedEof
    )
}

#[cfg(not(unix))]
pub fn run_helper(
    _socket: &Path,
    _owner_pid: u32,
    _run_as: Option<(u32, u32)>,
) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "video encoder helper requires Unix sockets",
    ))
}

/// Drop a root-started encoder helper to its per-VM uid. Hardware encoders
/// retain only the standard groups that own Linux render nodes; software
/// encoding keeps no supplementary groups. The VMM itself never gets them.
#[cfg(target_os = "linux")]
fn drop_encoder_privileges(uid: u32, gid: u32, needs_video_device: bool) -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("cannot apply encoder uid isolation without root".into());
    }
    let mut groups = Vec::new();
    if needs_video_device {
        for name in [c"render", c"video"] {
            let group = unsafe { libc::getgrnam(name.as_ptr()) };
            if !group.is_null() {
                let group_gid = unsafe { (*group).gr_gid };
                if group_gid != 0 && !groups.contains(&group_gid) {
                    groups.push(group_gid);
                }
            }
        }
    }
    unsafe {
        if libc::setgroups(groups.len(), groups.as_ptr()) != 0 {
            return Err(format!(
                "set encoder supplementary groups: {}",
                std::io::Error::last_os_error()
            ));
        }
        if libc::setgid(gid as libc::gid_t) != 0 {
            return Err(format!(
                "set encoder gid {gid}: {}",
                std::io::Error::last_os_error()
            ));
        }
        if libc::setuid(uid as libc::uid_t) != 0 {
            return Err(format!(
                "set encoder uid {uid}: {}",
                std::io::Error::last_os_error()
            ));
        }
        if uid != 0 && libc::setuid(0) == 0 {
            return Err("encoder privilege drop was reversible".into());
        }
    }
    Ok(())
}

#[cfg(unix)]
fn encode_session(stream: &mut std::os::unix::net::UnixStream) -> std::io::Result<()> {
    use std::net::Shutdown;
    use std::process::Stdio;

    let (config, width, height) = read_request(stream)?;
    let mut command = ffmpeg_command(config, width, height);
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let mut ffmpeg_in = child
        .stdin
        .take()
        .ok_or_else(|| invalid_data("ffmpeg stdin"))?;
    let mut ffmpeg_out = child
        .stdout
        .take()
        .ok_or_else(|| invalid_data("ffmpeg stdout"))?;

    let mut raw_input = stream.try_clone()?;
    let expected_len = width as usize * height as usize * 4;
    let input_thread = std::thread::Builder::new()
        .name("smolvm-video-raw".into())
        .spawn(move || -> std::io::Result<()> {
            loop {
                let mut len = [0u8; 4];
                raw_input.read_exact(&mut len)?;
                let len = u32::from_be_bytes(len) as usize;
                if len != expected_len || len > MAX_RAW_FRAME {
                    return Err(invalid_data("raw video frame has the wrong size"));
                }
                let mut remaining = len;
                let mut chunk = [0u8; 64 << 10];
                while remaining != 0 {
                    let take = remaining.min(chunk.len());
                    raw_input.read_exact(&mut chunk[..take])?;
                    ffmpeg_in.write_all(&chunk[..take])?;
                    remaining -= take;
                }
            }
        })?;

    let started = Instant::now();
    let mut parser = AnnexBAccessUnits::default();
    let mut buf = [0u8; 64 << 10];
    // Keep teardown outside the fallible parsing loop: every error must close
    // the full-duplex socket, stop ffmpeg and wake the raw-input thread.
    let result = (|| -> std::io::Result<()> {
        'encode: loop {
            match ffmpeg_out.read(&mut buf) {
                Ok(0) => {
                    if let Some(access_unit) = parser.finish() {
                        send_access_unit(stream, &access_unit, started.elapsed())?;
                    }
                    break Ok(());
                }
                Ok(n) => {
                    let units = parser.push(&buf[..n])?;
                    for access_unit in units {
                        if let Err(e) = send_access_unit(stream, &access_unit, started.elapsed()) {
                            break 'encode Err(e);
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => break Err(e),
            }
        }
    })();

    let _ = stream.shutdown(Shutdown::Both);
    if result.is_err() {
        let _ = child.kill();
    }
    let status = child.wait();
    let _ = input_thread.join();
    result.and_then(|()| match status {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(std::io::Error::other(format!(
            "ffmpeg encoder exited with {status}"
        ))),
        Err(e) => Err(e),
    })
}

#[cfg(unix)]
fn ffmpeg_command(config: VideoConfig, width: u32, height: u32) -> std::process::Command {
    let executable = std::env::var_os("SMOLVM_FFMPEG").unwrap_or_else(|| "ffmpeg".into());
    let mut command = std::process::Command::new(executable);
    command.args([
        "-hide_banner",
        "-loglevel",
        "error",
        "-nostdin",
        "-f",
        "rawvideo",
        "-pix_fmt",
        "bgra",
        "-video_size",
        &format!("{width}x{height}"),
        "-framerate",
        &config.fps.to_string(),
        "-i",
        "pipe:0",
        "-an",
        "-sn",
        "-dn",
    ]);

    match config.encoder {
        Encoder::Nvenc => {
            command.args([
                "-c:v",
                "h264_nvenc",
                "-preset",
                "p1",
                "-tune",
                "ull",
                "-rc",
                "cbr",
                "-spatial_aq",
                "0",
                "-temporal_aq",
                "0",
                "-zerolatency",
                "1",
                "-pix_fmt",
                "yuv420p",
            ]);
        }
        Encoder::VideoToolbox => {
            // Baseline with no B-frames: VideoToolbox writes no VUI, so a
            // decoder cannot learn the reorder depth from the stream and
            // buffers frames before showing the first one; browsers treat
            // Baseline itself as reorder-free and display each frame as it
            // arrives.
            command.args([
                "-c:v",
                "h264_videotoolbox",
                "-realtime",
                "1",
                "-allow_sw",
                "0",
                "-pix_fmt",
                "yuv420p",
            ]);
        }
        Encoder::Vaapi => {
            let device = std::env::var("SMOLVM_VAAPI_DEVICE")
                .unwrap_or_else(|_| "/dev/dri/renderD128".into());
            command.args([
                "-vaapi_device",
                &device,
                "-vf",
                "format=nv12,hwupload",
                "-c:v",
                "h264_vaapi",
            ]);
        }
        Encoder::X264 => {
            command.args([
                "-c:v",
                "libx264",
                "-preset",
                "ultrafast",
                "-tune",
                "zerolatency",
                "-threads",
                &config.software_threads.to_string(),
                "-pix_fmt",
                "yuv420p",
            ]);
        }
    }

    let bitrate = format!("{}k", config.bitrate_kbps);
    let buffer = format!(
        "{}k",
        (config.bitrate_kbps / u32::from(config.fps)).max(1) * 2
    );
    let gop = config.fps.to_string();
    // VideoToolbox writes no VUI, so a decoder cannot learn the reorder depth
    // from the stream and buffers frames before showing the first; browsers
    // treat Baseline itself as reorder-free and show each frame on arrival.
    let profile = match config.encoder {
        Encoder::VideoToolbox => "baseline",
        _ => "main",
    };
    command.args([
        "-profile:v",
        profile,
        "-b:v",
        &bitrate,
        "-maxrate",
        &bitrate,
        "-bufsize",
        &buffer,
        "-g",
        &gop,
        "-keyint_min",
        &gop,
        "-bf",
        "0",
        "-bsf:v",
        "h264_metadata=aud=insert",
        "-flush_packets",
        "1",
        "-f",
        "h264",
        "pipe:1",
    ]);
    command
}

#[cfg(unix)]
fn send_access_unit<W: Write>(
    out: &mut W,
    access_unit: &[u8],
    timestamp: Duration,
) -> std::io::Result<()> {
    let packet_len = 1usize + 8 + access_unit.len();
    if packet_len > MAX_ENCODED_FRAME {
        return Err(invalid_data("encoded H.264 access unit is too large"));
    }
    out.write_all(&(packet_len as u32).to_be_bytes())?;
    out.write_all(&[if has_nal_type(access_unit, 5) { 1 } else { 2 }])?;
    out.write_all(&(timestamp.as_micros() as u64).to_be_bytes())?;
    out.write_all(access_unit)
}

#[derive(Default)]
struct AnnexBAccessUnits {
    pending: Vec<u8>,
}

impl AnnexBAccessUnits {
    fn push(&mut self, bytes: &[u8]) -> std::io::Result<Vec<Vec<u8>>> {
        self.pending.extend_from_slice(bytes);
        let mut complete = Vec::new();
        loop {
            let auds = nal_positions(&self.pending, 9);
            if auds.len() < 2 {
                break;
            }
            let boundary = auds[1];
            complete.push(self.pending.drain(..boundary).collect());
        }
        if self.pending.len() > MAX_ENCODED_FRAME {
            return Err(invalid_data("H.264 stream has no access-unit boundaries"));
        }
        Ok(complete)
    }

    fn finish(&mut self) -> Option<Vec<u8>> {
        (!self.pending.is_empty()).then(|| std::mem::take(&mut self.pending))
    }
}

fn nal_positions(data: &[u8], wanted_type: u8) -> Vec<usize> {
    let mut result = Vec::new();
    let mut i = 0;
    while i + 3 < data.len() {
        let (start, nal) = if data[i..].starts_with(&[0, 0, 1]) {
            (i, i + 3)
        } else if i + 4 < data.len() && data[i..].starts_with(&[0, 0, 0, 1]) {
            (i, i + 4)
        } else {
            i += 1;
            continue;
        };
        if nal < data.len() && data[nal] & 0x1f == wanted_type {
            result.push(start);
        }
        i = nal + 1;
    }
    result
}

fn has_nal_type(data: &[u8], wanted_type: u8) -> bool {
    !nal_positions(data, wanted_type).is_empty()
}

fn invalid_data(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into())
}

fn invalid_input(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message.into())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips() {
        let config = VideoConfig {
            encoder: Encoder::Nvenc,
            fps: 60,
            bitrate_kbps: 20_000,
            software_threads: 2,
        };
        let mut bytes = Vec::new();
        write_request(&mut bytes, config, 1920, 1080).unwrap();
        assert_eq!(bytes.len(), REQUEST_LEN);
        assert_eq!(read_request(&mut &bytes[..]).unwrap(), (config, 1920, 1080));
    }

    #[test]
    fn annex_b_is_split_on_aud_boundaries() {
        let mut parser = AnnexBAccessUnits::default();
        let first = [0, 0, 0, 1, 9, 0xf0, 0, 0, 1, 5, 1, 2];
        let second = [0, 0, 0, 1, 9, 0xf0, 0, 0, 1, 1, 3, 4];
        assert!(parser.push(&first).unwrap().is_empty());
        let units = parser.push(&second).unwrap();
        assert_eq!(units, vec![first.to_vec()]);
        assert_eq!(parser.finish().unwrap(), second);
    }

    #[test]
    fn split_start_code_across_reads_is_supported() {
        let mut parser = AnnexBAccessUnits::default();
        assert!(parser.push(&[0, 0]).unwrap().is_empty());
        assert!(parser.push(&[0, 1, 9, 0xf0, 0, 0]).unwrap().is_empty());
        let units = parser.push(&[1, 9, 0xf0]).unwrap();
        assert_eq!(units.len(), 1);
    }

    #[test]
    fn idr_detection_understands_three_and_four_byte_start_codes() {
        assert!(has_nal_type(&[0, 0, 1, 5, 0xaa], 5));
        assert!(has_nal_type(&[0, 0, 0, 1, 5, 0xaa], 5));
        assert!(!has_nal_type(&[0, 0, 1, 1, 0xaa], 5));
    }

    #[test]
    fn ffmpeg_nvenc_command_forbids_software_fallback() {
        let command = ffmpeg_command(
            VideoConfig {
                encoder: Encoder::Nvenc,
                fps: 60,
                bitrate_kbps: 20_000,
                software_threads: 2,
            },
            1920,
            1080,
        );
        let args: Vec<_> = command
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(args.windows(2).any(|a| a == ["-c:v", "h264_nvenc"]));
        assert!(!args.iter().any(|a| a == "libx264"));
        assert!(args.windows(2).any(|a| a == ["-tune", "ull"]));
    }

    #[test]
    fn non_nvidia_commands_are_hardware_only() {
        let args_for = |encoder| {
            ffmpeg_command(
                VideoConfig {
                    encoder,
                    fps: 60,
                    bitrate_kbps: 20_000,
                    software_threads: 2,
                },
                1920,
                1080,
            )
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
        };

        let vt = args_for(Encoder::VideoToolbox);
        assert!(vt.windows(2).any(|a| a == ["-c:v", "h264_videotoolbox"]));
        assert!(vt.windows(2).any(|a| a == ["-allow_sw", "0"]));

        let vaapi = args_for(Encoder::Vaapi);
        assert!(vaapi.windows(2).any(|a| a == ["-c:v", "h264_vaapi"]));
        assert!(vaapi
            .windows(2)
            .any(|a| a == ["-vf", "format=nv12,hwupload"]));
        assert!(!vt.iter().chain(&vaapi).any(|a| a == "libx264"));
    }

    #[test]
    fn software_command_is_low_latency_and_cpu_bounded() {
        let command = ffmpeg_command(
            VideoConfig {
                encoder: Encoder::X264,
                fps: 60,
                bitrate_kbps: 20_000,
                software_threads: 3,
            },
            1920,
            1080,
        );
        let args: Vec<_> = command
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(args.windows(2).any(|a| a == ["-c:v", "libx264"]));
        assert!(args.windows(2).any(|a| a == ["-preset", "ultrafast"]));
        assert!(args.windows(2).any(|a| a == ["-tune", "zerolatency"]));
        assert!(args.windows(2).any(|a| a == ["-threads", "3"]));
    }

    #[test]
    fn expected_client_disconnects_are_not_encoder_failures() {
        for kind in [
            std::io::ErrorKind::BrokenPipe,
            std::io::ErrorKind::ConnectionAborted,
            std::io::ErrorKind::ConnectionReset,
            std::io::ErrorKind::UnexpectedEof,
        ] {
            assert!(is_client_disconnect(&std::io::Error::from(kind)));
        }
        assert!(!is_client_disconnect(&std::io::Error::from(
            std::io::ErrorKind::NotFound,
        )));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cpu_only_linux_auto_selects_software() {
        assert_eq!(linux_auto_encoder(false, false), Encoder::X264);
        assert_eq!(linux_auto_encoder(false, true), Encoder::Vaapi);
        assert_eq!(linux_auto_encoder(true, false), Encoder::Nvenc);
    }
}
