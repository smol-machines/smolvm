//! A minimal RFB (VNC) server over the host-side framebuffer.
//!
//! Serving from the host rather than the guest is the point: the guest needs
//! no capture tool, no seat-visible VNC port and no compositor-specific
//! screencopy protocol. Anything that can drive a KMS display — Hyprland,
//! sway, GNOME, a plain framebuffer — is visible through this without knowing
//! it is being watched.
//!
//! Scope is deliberately small: RFB 3.8, no authentication, Raw encoding.
//! When the launcher attaches virtio-input devices, client key and pointer
//! events are injected into the guest; on a libkrun without the input
//! feature the session degrades to view-only and events are discarded.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use super::display::{self, DisplayFramebuffer, Frame};

const RFB_VERSION: &[u8; 12] = b"RFB 003.008\n";
const SECURITY_NONE: u8 = 1;

/// How long a client's incremental update request waits for a new frame
/// before we answer with the current one. Without a bound, a client would
/// hang for as long as the desktop is idle and look disconnected.
const UPDATE_WAIT: Duration = Duration::from_secs(2);

/// Pseudo-encoding letting us tell the client the desktop changed size, which
/// happens when the compositor sets a mode different from the initial one.
const ENCODING_DESKTOP_SIZE: i32 = -223;
const ENCODING_RAW: i32 = 0;

/// The pixel layout a client asked for. Defaults to what we natively hold, so
/// a client that never sends SetPixelFormat gets a zero-copy path.
#[derive(Clone, Copy, PartialEq, Eq)]
struct PixelFormat {
    bits_per_pixel: u8,
    depth: u8,
    big_endian: bool,
    true_colour: bool,
    red_max: u16,
    green_max: u16,
    blue_max: u16,
    red_shift: u8,
    green_shift: u8,
    blue_shift: u8,
}

impl PixelFormat {
    /// Little-endian 32-bit true colour with R=16/G=8/B=0, i.e. bytes B,G,R,X
    /// in memory — the layout `display::to_bgrx` produces.
    const fn bgrx() -> Self {
        Self {
            bits_per_pixel: 32,
            depth: 24,
            big_endian: false,
            true_colour: true,
            red_max: 255,
            green_max: 255,
            blue_max: 255,
            red_shift: 16,
            green_shift: 8,
            blue_shift: 0,
        }
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.push(self.bits_per_pixel);
        out.push(self.depth);
        out.push(self.big_endian as u8);
        out.push(self.true_colour as u8);
        out.extend_from_slice(&self.red_max.to_be_bytes());
        out.extend_from_slice(&self.green_max.to_be_bytes());
        out.extend_from_slice(&self.blue_max.to_be_bytes());
        out.push(self.red_shift);
        out.push(self.green_shift);
        out.push(self.blue_shift);
        out.extend_from_slice(&[0u8; 3]); // padding
    }

    fn parse(raw: &[u8; 16]) -> Self {
        Self {
            bits_per_pixel: raw[0],
            depth: raw[1],
            big_endian: raw[2] != 0,
            true_colour: raw[3] != 0,
            red_max: u16::from_be_bytes([raw[4], raw[5]]),
            green_max: u16::from_be_bytes([raw[6], raw[7]]),
            blue_max: u16::from_be_bytes([raw[8], raw[9]]),
            red_shift: raw[10],
            green_shift: raw[11],
            blue_shift: raw[12],
        }
    }

    /// Can we serve this layout by rewriting our BGRX bytes?
    fn is_supported(&self) -> bool {
        self.bits_per_pixel == 32 && self.true_colour
    }
}

/// Rewrite BGRX pixels into the client's requested 32-bit layout.
///
/// Borrows rather than copies when the client wants exactly what we already
/// hold — the common case, and a whole framebuffer per update otherwise.
fn encode_pixels<'a>(bgrx: &'a [u8], fmt: &PixelFormat) -> std::borrow::Cow<'a, [u8]> {
    if *fmt == PixelFormat::bgrx() {
        return std::borrow::Cow::Borrowed(bgrx);
    }
    let mut out = vec![0u8; bgrx.len()];
    let (src_px, _) = bgrx.as_chunks::<4>();
    let (dst_px, _) = out.as_chunks_mut::<4>();
    for (src, dst) in src_px.iter().zip(dst_px.iter_mut()) {
        // Our source is B,G,R,X in memory.
        let (b, g, r) = (src[0] as u32, src[1] as u32, src[2] as u32);
        let px = ((r * fmt.red_max as u32) / 255) << fmt.red_shift
            | ((g * fmt.green_max as u32) / 255) << fmt.green_shift
            | ((b * fmt.blue_max as u32) / 255) << fmt.blue_shift;
        let bytes = if fmt.big_endian {
            px.to_be_bytes()
        } else {
            px.to_le_bytes()
        };
        dst.copy_from_slice(&bytes);
    }
    std::borrow::Cow::Owned(out)
}

/// Start the RFB server. Returns the bound address so callers can log it.
/// With `input` present, client key and pointer events are injected into the
/// guest's virtio-input devices; without it the session is view-only.
pub fn serve(
    addr: &str,
    fb: Arc<DisplayFramebuffer>,
    input: Option<super::input::VncInput>,
) -> std::io::Result<std::net::SocketAddr> {
    let listener = TcpListener::bind(addr)?;
    let local = listener.local_addr()?;

    std::thread::Builder::new()
        .name("smolvm-vnc".into())
        .spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(s) => {
                        let fb = Arc::clone(&fb);
                        let input = input.clone();
                        let peer = s.peer_addr().ok();
                        if let Err(e) = std::thread::Builder::new()
                            .name("smolvm-vnc-client".into())
                            .spawn(move || {
                                if let Err(e) = handle_client(s, fb, input) {
                                    tracing::debug!(?peer, error = %e, "vnc client ended");
                                }
                            })
                        {
                            tracing::warn!(error = %e, "could not spawn vnc client thread");
                        }
                    }
                    // A per-connection failure must not retire the listener:
                    // treating every accept error as fatal means one transient
                    // ECONNABORTED/EMFILE silently ends VNC for the life of
                    // the VM, with the port simply gone and nothing logged
                    // after the fact.
                    Err(e) if is_transient_accept_error(&e) => {
                        tracing::debug!(error = %e, "vnc accept failed; continuing");
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "vnc listener stopped");
                        break;
                    }
                }
            }
        })?;

    Ok(local)
}

/// Accept errors that say something about one connection or a momentary
/// resource shortage, rather than about the listening socket itself.
fn is_transient_accept_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    matches!(
        e.kind(),
        ConnectionAborted | ConnectionReset | Interrupted | WouldBlock | TimedOut
    ) || e.raw_os_error() == Some(libc::EMFILE)
        || e.raw_os_error() == Some(libc::ENFILE)
        || e.raw_os_error() == Some(libc::ENOBUFS)
        || e.raw_os_error() == Some(libc::ENOMEM)
}

fn handle_client(
    mut s: TcpStream,
    fb: Arc<DisplayFramebuffer>,
    input: Option<super::input::VncInput>,
) -> std::io::Result<()> {
    s.set_nodelay(true).ok();

    // --- handshake -------------------------------------------------------
    s.write_all(RFB_VERSION)?;
    let mut version = [0u8; 12];
    s.read_exact(&mut version)?;

    // Offer only "None"; this port is expected to be bound to loopback or a
    // trusted interface by the caller.
    s.write_all(&[1, SECURITY_NONE])?;
    let mut chosen = [0u8; 1];
    s.read_exact(&mut chosen)?;
    if chosen[0] != SECURITY_NONE {
        // SecurityResult: failure, plus a reason string (3.8 requires one).
        let reason = b"only the None security type is offered";
        let mut msg = 1u32.to_be_bytes().to_vec();
        msg.extend_from_slice(&(reason.len() as u32).to_be_bytes());
        msg.extend_from_slice(reason);
        s.write_all(&msg)?;
        return Ok(());
    }
    s.write_all(&0u32.to_be_bytes())?; // SecurityResult: OK

    let mut shared = [0u8; 1];
    s.read_exact(&mut shared)?; // ClientInit

    // Geometry has to be committed at ServerInit, before the guest may have
    // presented anything. Fall back to the configured display size so a client
    // that connects during boot still gets a sane desktop rather than 0x0.
    let first = fb.latest();
    let (mut width, mut height) = first
        .as_ref()
        .map(|f| (f.width, f.height))
        .unwrap_or((1280, 800));

    let mut fmt = PixelFormat::bgrx();
    let name = b"smolvm";
    let mut init = Vec::with_capacity(32);
    init.extend_from_slice(&(width as u16).to_be_bytes());
    init.extend_from_slice(&(height as u16).to_be_bytes());
    fmt.write(&mut init);
    init.extend_from_slice(&(name.len() as u32).to_be_bytes());
    init.extend_from_slice(name);
    s.write_all(&init)?;

    tracing::info!(width, height, "vnc client connected");

    // --- message loop ----------------------------------------------------
    let mut last_generation = 0u64;
    // BGRX pixels of the last frame this client was sent, for damage diffing.
    let mut last_sent: Option<Vec<u8>> = None;
    let mut client_supports_resize = false;
    let mut last_button_mask = 0u8;

    loop {
        let mut kind = [0u8; 1];
        if s.read_exact(&mut kind).is_err() {
            return Ok(()); // client hung up
        }
        match kind[0] {
            0 => {
                // SetPixelFormat: 3 bytes padding + 16 byte PixelFormat
                let mut rest = [0u8; 19];
                s.read_exact(&mut rest)?;
                let mut pf = [0u8; 16];
                pf.copy_from_slice(&rest[3..19]);
                let requested = PixelFormat::parse(&pf);
                if requested.is_supported() {
                    fmt = requested;
                } else {
                    // Keep our format rather than emit pixels the client will
                    // misread; say so, because wrong colours are otherwise a
                    // baffling symptom.
                    tracing::warn!(
                        bpp = requested.bits_per_pixel,
                        true_colour = requested.true_colour,
                        "vnc client asked for an unsupported pixel format; \
                         continuing with 32-bit true colour"
                    );
                }
            }
            2 => {
                // SetEncodings: 1 byte padding + u16 count + count * i32
                let mut head = [0u8; 3];
                s.read_exact(&mut head)?;
                let count = u16::from_be_bytes([head[1], head[2]]) as usize;
                let mut encodings = vec![0u8; count * 4];
                s.read_exact(&mut encodings)?;
                let (encodings, _) = encodings.as_chunks::<4>();
                client_supports_resize = encodings
                    .iter()
                    .any(|c| i32::from_be_bytes(*c) == ENCODING_DESKTOP_SIZE);
            }
            3 => {
                // FramebufferUpdateRequest: incremental + x,y,w,h
                let mut req = [0u8; 9];
                s.read_exact(&mut req)?;
                let incremental = req[0] != 0;

                let frame = if incremental {
                    fb.wait_for_frame(last_generation, UPDATE_WAIT)
                        .or_else(|| fb.latest())
                } else {
                    fb.latest()
                };

                let Some(frame) = frame else {
                    // Nothing presented yet. Answer with an empty update so the
                    // client stays in its request loop instead of stalling.
                    s.write_all(&[0u8, 0, 0, 0])?;
                    continue;
                };

                if incremental && frame.generation == last_generation {
                    s.write_all(&[0u8, 0, 0, 0])?;
                    continue;
                }
                last_generation = frame.generation;

                if (frame.width, frame.height) != (width, height) {
                    width = frame.width;
                    height = frame.height;
                    if client_supports_resize {
                        send_resize(&mut s, width, height)?;
                    } else {
                        tracing::warn!(
                            width,
                            height,
                            "guest changed mode but the vnc client cannot resize; \
                             reconnect to pick up the new size"
                        );
                    }
                }

                let bgrx = display::to_bgrx(&frame);
                match last_sent.as_ref() {
                    Some(prev) if incremental && prev.len() == bgrx.len() => {
                        send_frame_diff(&mut s, &frame, &bgrx, prev, &fmt)?;
                    }
                    _ => send_frame(&mut s, &frame, &bgrx, &fmt)?,
                }
                last_sent = Some(bgrx.into_owned());
            }
            4 => {
                // KeyEvent: down-flag, 2 bytes padding, u32 keysym.
                let mut buf = [0u8; 7];
                s.read_exact(&mut buf)?;
                if let Some(ref input) = input {
                    let down = buf[0] != 0;
                    let keysym = u32::from_be_bytes([buf[3], buf[4], buf[5], buf[6]]);
                    match super::input::keysym_to_evdev(keysym) {
                        Some(code) => {
                            input
                                .keyboard
                                .push(&[(super::input::EV_KEY, code, down as u32)])
                        }
                        None => tracing::debug!(keysym, "vnc keysym with no evdev mapping"),
                    }
                }
            }
            5 => {
                // PointerEvent: button mask, u16 x, u16 y.
                let mut buf = [0u8; 5];
                s.read_exact(&mut buf)?;
                if let Some(ref input) = input {
                    let mask = buf[0];
                    let x = u16::from_be_bytes([buf[1], buf[2]]) as u32;
                    let y = u16::from_be_bytes([buf[3], buf[4]]) as u32;

                    // Absolute axes use a fixed virtual range; scale from the
                    // framebuffer size the client is looking at so a guest
                    // mode change never needs new absinfo.
                    let scale = |v: u32, span: u32| -> u32 {
                        let span = span.max(2);
                        (v.min(span - 1) * super::input::ABS_RANGE) / (span - 1)
                    };
                    let mut batch: Vec<(u16, u16, u32)> = vec![
                        (super::input::EV_ABS, 0, scale(x, width)),
                        (super::input::EV_ABS, 1, scale(y, height)),
                    ];

                    // RFB buttons: bit 0 = left, 1 = middle, 2 = right;
                    // bits 3/4 are wheel up/down, sent as press+release per
                    // notch, so only the rising edge scrolls.
                    let changed = mask ^ last_button_mask;
                    for (bit, code) in [
                        (0u8, super::input::BTN_LEFT),
                        (1, super::input::BTN_MIDDLE),
                        (2, super::input::BTN_RIGHT),
                    ] {
                        if changed & (1 << bit) != 0 {
                            let down = mask & (1 << bit) != 0;
                            batch.push((super::input::EV_KEY, code, down as u32));
                        }
                    }
                    if changed & mask & (1 << 3) != 0 {
                        batch.push((super::input::EV_REL, super::input::REL_WHEEL, 1));
                    }
                    if changed & mask & (1 << 4) != 0 {
                        batch.push((super::input::EV_REL, super::input::REL_WHEEL, -1i32 as u32));
                    }
                    last_button_mask = mask;

                    input.pointer.push(&batch);
                }
            }
            6 => {
                // ClientCutText: 3 padding + u32 length + text
                let mut head = [0u8; 7];
                s.read_exact(&mut head)?;
                let len = u32::from_be_bytes([head[3], head[4], head[5], head[6]]) as usize;
                // Bound it: a hostile length would otherwise allocate freely.
                if len > 1 << 20 {
                    return Ok(());
                }
                let mut text = vec![0u8; len];
                s.read_exact(&mut text)?;
            }
            other => {
                tracing::debug!(message_type = other, "unknown vnc client message; closing");
                return Ok(());
            }
        }
    }
}

fn send_resize(s: &mut TcpStream, width: u32, height: u32) -> std::io::Result<()> {
    let mut msg = vec![0u8, 0];
    msg.extend_from_slice(&1u16.to_be_bytes()); // one rectangle
    msg.extend_from_slice(&0u16.to_be_bytes()); // x
    msg.extend_from_slice(&0u16.to_be_bytes()); // y
    msg.extend_from_slice(&(width as u16).to_be_bytes());
    msg.extend_from_slice(&(height as u16).to_be_bytes());
    msg.extend_from_slice(&ENCODING_DESKTOP_SIZE.to_be_bytes());
    s.write_all(&msg)
}

fn send_frame(
    s: &mut TcpStream,
    frame: &Frame,
    bgrx: &[u8],
    fmt: &PixelFormat,
) -> std::io::Result<()> {
    let pixels = encode_pixels(bgrx, fmt);

    let mut header = vec![0u8, 0];
    header.extend_from_slice(&1u16.to_be_bytes()); // one rectangle
    header.extend_from_slice(&0u16.to_be_bytes()); // x
    header.extend_from_slice(&0u16.to_be_bytes()); // y
    header.extend_from_slice(&(frame.width as u16).to_be_bytes());
    header.extend_from_slice(&(frame.height as u16).to_be_bytes());
    header.extend_from_slice(&ENCODING_RAW.to_be_bytes());
    s.write_all(&header)?;
    s.write_all(&pixels)
}

/// Send only the row bands that changed since the frame this client last
/// received. Raw encoding ships every pixel of a rectangle, so cursor-sized
/// damage would otherwise cost a full-frame update (~5 MB at 1440x900) on
/// every pointer movement.
fn send_frame_diff(
    s: &mut TcpStream,
    frame: &Frame,
    bgrx: &[u8],
    prev: &[u8],
    fmt: &PixelFormat,
) -> std::io::Result<()> {
    const BAND_ROWS: usize = 16;
    let row = frame.width as usize * 4;
    let height = frame.height as usize;

    // Dirty 16-row bands, with adjacent bands merged into one rectangle.
    let mut rects: Vec<(usize, usize)> = Vec::new();
    let mut start = 0;
    while start < height {
        let rows = BAND_ROWS.min(height - start);
        if bgrx[start * row..(start + rows) * row] != prev[start * row..(start + rows) * row] {
            match rects.last_mut() {
                Some(last) if last.0 + last.1 == start => last.1 += rows,
                _ => rects.push((start, rows)),
            }
        }
        start += rows;
    }

    if rects.is_empty() {
        // The frame generation moved but the pixels did not.
        return s.write_all(&[0u8, 0, 0, 0]);
    }

    let mut header = vec![0u8, 0];
    header.extend_from_slice(&(rects.len() as u16).to_be_bytes());
    s.write_all(&header)?;
    for (band_start, band_rows) in rects {
        let mut rect = Vec::with_capacity(12);
        rect.extend_from_slice(&0u16.to_be_bytes());
        rect.extend_from_slice(&(band_start as u16).to_be_bytes());
        rect.extend_from_slice(&(frame.width as u16).to_be_bytes());
        rect.extend_from_slice(&(band_rows as u16).to_be_bytes());
        rect.extend_from_slice(&ENCODING_RAW.to_be_bytes());
        s.write_all(&rect)?;
        let band = &bgrx[band_start * row..(band_start + band_rows) * row];
        s.write_all(&encode_pixels(band, fmt))?;
    }
    Ok(())
}

/// Resolve `SMOLVM_VNC` into a bind address. Accepts a bare port ("5900"), a
/// host:port pair, or a bare host (defaulting to 5900).
pub fn parse_bind_addr(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if let Ok(port) = raw.parse::<u16>() {
        // Bare port stays on loopback: a desktop framebuffer is not something
        // to expose on every interface because a number was set.
        return Some(format!("127.0.0.1:{port}"));
    }
    if raw.contains(':') {
        return Some(raw.to_string());
    }
    Some(format!("{raw}:5900"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_port_binds_loopback_only() {
        assert_eq!(parse_bind_addr("5900").as_deref(), Some("127.0.0.1:5900"));
    }

    #[test]
    fn host_port_is_passed_through() {
        assert_eq!(
            parse_bind_addr("0.0.0.0:5901").as_deref(),
            Some("0.0.0.0:5901")
        );
    }

    #[test]
    fn bare_host_gets_the_default_port() {
        assert_eq!(parse_bind_addr("0.0.0.0").as_deref(), Some("0.0.0.0:5900"));
    }

    #[test]
    fn blank_means_disabled() {
        assert_eq!(parse_bind_addr(""), None);
        assert_eq!(parse_bind_addr("   "), None);
    }

    #[test]
    fn pixel_format_round_trips() {
        let fmt = PixelFormat::bgrx();
        let mut out = Vec::new();
        fmt.write(&mut out);
        assert_eq!(out.len(), 16);
        let mut raw = [0u8; 16];
        raw.copy_from_slice(&out);
        assert!(PixelFormat::parse(&raw) == fmt);
    }

    #[test]
    fn native_format_encodes_unchanged() {
        let src = vec![0x11, 0x22, 0x33, 0xff];
        let out = encode_pixels(&src, &PixelFormat::bgrx());
        assert_eq!(&*out, &src[..]);
    }

    #[test]
    fn rgbx_client_gets_channels_reordered() {
        // Client wants R at shift 0, B at shift 16 (the mirror of ours).
        let fmt = PixelFormat {
            red_shift: 0,
            blue_shift: 16,
            ..PixelFormat::bgrx()
        };
        // Source memory B,G,R,X = 0x11,0x22,0x33
        let out = encode_pixels(&[0x11, 0x22, 0x33, 0xff], &fmt);
        // px = R<<0 | G<<8 | B<<16 = 0x112233 -> little-endian bytes
        assert_eq!(&*out, &[0x33, 0x22, 0x11, 0x00]);
    }

    #[test]
    fn unsupported_format_is_rejected_so_we_keep_our_own() {
        let fmt = PixelFormat {
            bits_per_pixel: 8,
            true_colour: false,
            ..PixelFormat::bgrx()
        };
        assert!(!fmt.is_supported());
    }
}
