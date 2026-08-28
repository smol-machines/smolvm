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
//!
//! The same port also answers HTTP, serving a small browser client and
//! upgrading it to a WebSocket carrying that identical RFB stream. That is
//! what lets a plain browser open the desktop with nothing installed, and it
//! is also what lets the cloud reach it: an HTTP port traverses an ingress,
//! TLS terminator and authenticating proxy, where a raw RFB socket cannot.
//! Native viewers are unaffected — the protocol is chosen per connection.

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
///
/// This also bounds INPUT latency, which is why it is short. A session is one
/// loop: read a message, act on it, repeat. While it is parked in
/// `wait_for_frame` nothing is reading the socket, so a keystroke that arrives
/// mid-wait is not seen until the wait ends. With a two-second bound — the
/// value this started at — typing into a still screen stalled for up to two
/// seconds per keypress, because a still screen is exactly the case that runs
/// the wait to its full length. A frame arriving still wakes the wait
/// immediately via the condvar, so shortening it costs only an empty
/// four-byte reply per tick on an idle desktop.
const UPDATE_WAIT: Duration = Duration::from_millis(15);

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
                                if let Err(e) = handle_connection(s, fb, input) {
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

/// Route one accepted connection to whichever protocol the peer speaks.
fn handle_connection(
    s: TcpStream,
    fb: Arc<DisplayFramebuffer>,
    input: Option<super::input::VncInput>,
) -> std::io::Result<()> {
    s.set_nodelay(true).ok();
    if speaks_http(&s) {
        serve_http(s, fb, input)
    } else {
        handle_client(s, fb, input)
    }
}

/// Did the peer open with an HTTP request line?
///
/// This has to be a bounded wait rather than a blocking peek, because in RFB
/// the *server* speaks first: a native viewer connects and then stays silent
/// until it has been greeted, so blocking here would hang exactly the clients
/// that must keep working. A browser sends its request immediately. Waiting
/// briefly for bytes therefore tells the two apart, and only costs a native
/// viewer this much delay before its greeting.
fn speaks_http(s: &TcpStream) -> bool {
    const SNIFF_WAIT: Duration = Duration::from_millis(300);

    let restore = s.read_timeout().ok().flatten();
    if s.set_read_timeout(Some(SNIFF_WAIT)).is_err() {
        return false;
    }

    let deadline = std::time::Instant::now() + SNIFF_WAIT;
    let mut probe = [0u8; 4];
    let verdict = loop {
        // Peek leaves the bytes in the socket, so whichever handler runs next
        // sees an untouched stream and needs no hand-off buffer.
        match s.peek(&mut probe) {
            Ok(4) => break &probe == b"GET ",
            // A short read means the request line is still arriving. Only
            // wait on it while what did arrive is still a prefix of "GET ".
            Ok(n) if n > 0 && probe[..n] == b"GET "[..n] => {
                if std::time::Instant::now() >= deadline {
                    break false;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            _ => break false,
        }
    };

    let _ = s.set_read_timeout(restore);
    verdict
}

/// The browser client, served from the same port the RFB protocol uses.
const CLIENT_HTML: &str = include_str!("vnc_client.html");

struct HttpRequest {
    path: String,
    /// Present only on a well-formed upgrade request.
    websocket_key: Option<String>,
    wants_binary_subprotocol: bool,
}

fn serve_http(
    mut s: TcpStream,
    fb: Arc<DisplayFramebuffer>,
    input: Option<super::input::VncInput>,
) -> std::io::Result<()> {
    let Some(request) = read_request(&mut s)? else {
        return respond(
            &mut s,
            "400 Bad Request",
            "text/plain",
            b"malformed request",
        );
    };

    if let Some(key) = request.websocket_key.as_deref() {
        let route = request.path.as_str();
        if route != "/websockify" && route != "/video" {
            return respond(&mut s, "404 Not Found", "text/plain", b"not found");
        }
        if route == "/video" && !super::video::is_available() {
            return respond(
                &mut s,
                "503 Service Unavailable",
                "text/plain",
                b"encoded video unavailable",
            );
        }
        let mut reply = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {}\r\n",
            super::websocket::accept_key(key)
        );
        // A client that offered a subprotocol expects to be told which one was
        // taken; staying silent makes some of them close the connection.
        if request.wants_binary_subprotocol {
            reply.push_str("Sec-WebSocket-Protocol: binary\r\n");
        }
        reply.push_str("\r\n");
        s.write_all(reply.as_bytes())?;
        if route == "/video" {
            tracing::info!("encoded video browser client connected");
            return super::video::serve_browser(super::websocket::WsStream::new(s), fb);
        }
        tracing::info!("vnc browser client connected");
        return handle_client(super::websocket::WsStream::new(s), fb, input);
    }

    match request.path.as_str() {
        "/" | "/index.html" => respond(
            &mut s,
            "200 OK",
            "text/html; charset=utf-8",
            CLIENT_HTML.as_bytes(),
        ),
        _ => respond(&mut s, "404 Not Found", "text/plain", b"not found"),
    }
}

/// Read and parse the request head, or `None` if it is not one we serve.
///
/// Deliberately reads a byte at a time instead of wrapping the stream in a
/// `BufReader`: on an upgrade the very next bytes belong to the WebSocket, and
/// anything a buffered reader pulled past the blank line would be stranded in
/// a buffer the frame decoder never sees.
fn read_request<R: Read>(s: &mut R) -> std::io::Result<Option<HttpRequest>> {
    const MAX_HEAD: usize = 8 << 10;

    let mut head = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_HEAD || s.read(&mut byte)? == 0 {
            return Ok(None);
        }
        head.push(byte[0]);
    }

    let text = String::from_utf8_lossy(&head);
    let mut lines = text.split("\r\n");
    let mut request_line = lines.next().unwrap_or_default().split_whitespace();
    if request_line.next() != Some("GET") {
        return Ok(None);
    }
    let path = request_line.next().unwrap_or("/");

    let mut websocket_key = None;
    let mut upgrading = false;
    let mut wants_binary_subprotocol = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "upgrade" => upgrading = value.eq_ignore_ascii_case("websocket"),
            "sec-websocket-key" => websocket_key = Some(value.to_string()),
            "sec-websocket-protocol" => {
                wants_binary_subprotocol = value
                    .split(',')
                    .any(|p| p.trim().eq_ignore_ascii_case("binary"));
            }
            _ => {}
        }
    }

    Ok(Some(HttpRequest {
        path: path.split('?').next().unwrap_or("/").to_string(),
        websocket_key: upgrading.then_some(websocket_key).flatten(),
        wants_binary_subprotocol,
    }))
}

fn respond<W: Write>(
    s: &mut W,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    s.write_all(head.as_bytes())?;
    s.write_all(body)
}

/// Drive one RFB session. Generic over the transport so the very same
/// protocol code serves a native viewer on a raw socket and a browser over a
/// WebSocket — the two differ only in how bytes are framed beneath this.
fn handle_client<S: Read + Write>(
    mut s: S,
    fb: Arc<DisplayFramebuffer>,
    input: Option<super::input::VncInput>,
) -> std::io::Result<()> {
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

fn send_resize<S: Write>(s: &mut S, width: u32, height: u32) -> std::io::Result<()> {
    let mut msg = vec![0u8, 0];
    msg.extend_from_slice(&1u16.to_be_bytes()); // one rectangle
    msg.extend_from_slice(&0u16.to_be_bytes()); // x
    msg.extend_from_slice(&0u16.to_be_bytes()); // y
    msg.extend_from_slice(&(width as u16).to_be_bytes());
    msg.extend_from_slice(&(height as u16).to_be_bytes());
    msg.extend_from_slice(&ENCODING_DESKTOP_SIZE.to_be_bytes());
    s.write_all(&msg)
}

fn send_frame<S: Write>(
    s: &mut S,
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
fn send_frame_diff<S: Write>(
    s: &mut S,
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

/// The URL to open in a browser for a server bound to `addr`. A wildcard
/// bind is reported as loopback, because that is the address whoever reads
/// the log can actually open.
pub fn browser_url(addr: std::net::SocketAddr) -> String {
    let ip = addr.ip();
    let host = if ip.is_unspecified() {
        if addr.is_ipv6() {
            "[::1]".to_string()
        } else {
            "127.0.0.1".to_string()
        }
    } else if addr.is_ipv6() {
        format!("[{ip}]")
    } else {
        ip.to_string()
    };
    format!("http://{host}:{}/", addr.port())
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

    fn request_of(raw: &str) -> Option<HttpRequest> {
        read_request(&mut std::io::Cursor::new(raw.as_bytes().to_vec())).unwrap()
    }

    #[test]
    fn websocket_upgrade_is_recognised() {
        let r = request_of(
            "GET /websockify HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Protocol: binary\r\n\r\n",
        )
        .unwrap();
        assert_eq!(r.websocket_key.as_deref(), Some("dGhlIHNhbXBsZSBub25jZQ=="));
        assert!(r.wants_binary_subprotocol);
    }

    #[test]
    fn a_key_without_an_upgrade_is_not_a_websocket() {
        // Otherwise a plain GET carrying a stray header would be handed to
        // the frame decoder, which would then read HTML as frame bytes.
        let r = request_of("GET / HTTP/1.1\r\nSec-WebSocket-Key: abc\r\n\r\n").unwrap();
        assert!(r.websocket_key.is_none());
    }

    #[test]
    fn header_names_are_case_insensitive() {
        let r = request_of("GET / HTTP/1.1\r\nUPGRADE: WebSocket\r\nSEC-WEBSOCKET-KEY: k\r\n\r\n")
            .unwrap();
        assert_eq!(r.websocket_key.as_deref(), Some("k"));
    }

    #[test]
    fn query_strings_do_not_change_the_route() {
        assert_eq!(
            request_of("GET /?scale=1 HTTP/1.1\r\n\r\n").unwrap().path,
            "/"
        );
    }

    #[test]
    fn non_get_methods_are_refused() {
        assert!(request_of("POST / HTTP/1.1\r\n\r\n").is_none());
    }

    #[test]
    fn a_truncated_head_is_not_a_request() {
        assert!(request_of("GET / HTTP/1.1\r\nHost: x\r\n").is_none());
    }

    #[test]
    fn an_endless_head_is_bounded() {
        // A client that never sends the blank line must not grow the buffer
        // without limit.
        let mut raw = String::from("GET / HTTP/1.1\r\n");
        while raw.len() < 16 << 10 {
            raw.push_str("X-Pad: filler\r\n");
        }
        assert!(request_of(&raw).is_none());
    }

    #[test]
    fn responses_carry_a_length_and_close() {
        let mut out = Vec::new();
        respond(&mut out, "200 OK", "text/plain", b"hi").unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("Content-Length: 2\r\n"));
        assert!(text.ends_with("\r\n\r\nhi"));
    }

    #[test]
    fn wildcard_bind_is_advertised_as_loopback() {
        assert_eq!(
            browser_url("0.0.0.0:5900".parse().unwrap()),
            "http://127.0.0.1:5900/"
        );
    }

    #[test]
    fn a_concrete_address_is_kept() {
        assert_eq!(
            browser_url("192.168.1.5:5901".parse().unwrap()),
            "http://192.168.1.5:5901/"
        );
    }

    #[test]
    fn ipv6_hosts_are_bracketed() {
        assert_eq!(
            browser_url("[::]:5900".parse().unwrap()),
            "http://[::1]:5900/"
        );
    }

    #[test]
    fn the_embedded_client_is_a_whole_document() {
        // A truncated or mis-pathed asset would only show up as a blank page
        // in a browser, long after the build went green.
        assert!(CLIENT_HTML.starts_with("<!doctype html>"));
        assert!(CLIENT_HTML.contains("/websockify"));
        assert!(CLIENT_HTML.contains("/video"));
        assert!(CLIENT_HTML.contains("VideoDecoder"));
        assert!(CLIENT_HTML.trim_end().ends_with("</html>"));
    }

    // --- end to end over a real socket ----------------------------------
    //
    // These drive the listener the way a client does, so the sniffer, the
    // HTTP layer, the frame codec and the RFB code are exercised together
    // rather than each in isolation.

    const TEST_W: u32 = 64;
    const TEST_H: u32 = 32;

    fn serve_a_test_desktop() -> std::net::SocketAddr {
        let fb = Arc::new(display::DisplayFramebuffer::with_presented_frame(
            TEST_W,
            TEST_H,
            [9, 8, 7, 255],
        ));
        serve("127.0.0.1:0", fb, None).unwrap()
    }

    fn connect(addr: std::net::SocketAddr) -> TcpStream {
        let s = TcpStream::connect(addr).unwrap();
        // Never let a protocol bug turn into a hung test run.
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        s
    }

    /// Run a client-side RFB 3.8 session and pull one full-frame update.
    /// Returns the pixel bytes of the rectangle received.
    fn drive_rfb_session<S: Read + Write>(s: &mut S) -> Vec<u8> {
        let mut version = [0u8; 12];
        s.read_exact(&mut version).unwrap();
        assert_eq!(&version, RFB_VERSION);
        s.write_all(RFB_VERSION).unwrap();

        let mut offered = [0u8; 1];
        s.read_exact(&mut offered).unwrap();
        let mut types = vec![0u8; offered[0] as usize];
        s.read_exact(&mut types).unwrap();
        assert!(types.contains(&SECURITY_NONE));
        s.write_all(&[SECURITY_NONE]).unwrap();

        let mut result = [0u8; 4];
        s.read_exact(&mut result).unwrap();
        assert_eq!(u32::from_be_bytes(result), 0, "security handshake rejected");

        s.write_all(&[1]).unwrap(); // ClientInit: shared

        let mut init = [0u8; 24];
        s.read_exact(&mut init).unwrap();
        assert_eq!(u16::from_be_bytes([init[0], init[1]]) as u32, TEST_W);
        assert_eq!(u16::from_be_bytes([init[2], init[3]]) as u32, TEST_H);
        let name_len = u32::from_be_bytes(init[20..24].try_into().unwrap()) as usize;
        let mut name = vec![0u8; name_len];
        s.read_exact(&mut name).unwrap();

        // FramebufferUpdateRequest, non-incremental so we get pixels now.
        let mut req = vec![3u8, 0];
        req.extend_from_slice(&0u16.to_be_bytes());
        req.extend_from_slice(&0u16.to_be_bytes());
        req.extend_from_slice(&(TEST_W as u16).to_be_bytes());
        req.extend_from_slice(&(TEST_H as u16).to_be_bytes());
        s.write_all(&req).unwrap();

        let mut head = [0u8; 4];
        s.read_exact(&mut head).unwrap();
        assert_eq!(head[0], 0, "expected a FramebufferUpdate");
        assert_eq!(u16::from_be_bytes([head[2], head[3]]), 1, "one rectangle");

        let mut rect = [0u8; 12];
        s.read_exact(&mut rect).unwrap();
        let w = u16::from_be_bytes([rect[4], rect[5]]) as usize;
        let h = u16::from_be_bytes([rect[6], rect[7]]) as usize;
        assert_eq!(
            i32::from_be_bytes(rect[8..12].try_into().unwrap()),
            ENCODING_RAW
        );

        let mut pixels = vec![0u8; w * h * 4];
        s.read_exact(&mut pixels).unwrap();
        pixels
    }

    #[test]
    fn a_native_viewer_still_gets_a_plain_rfb_session() {
        // The back-compat guarantee: adding HTTP to this port must not
        // disturb a client that opens with silence and waits to be greeted.
        let mut s = connect(serve_a_test_desktop());
        let pixels = drive_rfb_session(&mut s);
        assert_eq!(pixels.len(), (TEST_W * TEST_H * 4) as usize);
        assert_eq!(&pixels[..4], &[9, 8, 7, 255]);
    }

    #[test]
    fn an_idle_incremental_request_returns_promptly_so_input_is_not_starved() {
        // A session is one loop: read a message, act on it, repeat. While it
        // is parked in `wait_for_frame` nothing is reading the socket, so a
        // keystroke arriving mid-wait is not seen until the wait ends — and a
        // still screen is exactly what runs the wait to its full length.
        // Bounding the wait is therefore what keeps typing responsive, so
        // assert the bound rather than the constant.
        let mut s = connect(serve_a_test_desktop());
        drive_rfb_session(&mut s); // consume the first, full-frame update

        // Nothing has changed since, so this request exercises the wait path.
        let mut req = vec![3u8, 1]; // incremental
        req.extend_from_slice(&0u16.to_be_bytes());
        req.extend_from_slice(&0u16.to_be_bytes());
        req.extend_from_slice(&(TEST_W as u16).to_be_bytes());
        req.extend_from_slice(&(TEST_H as u16).to_be_bytes());

        let started = std::time::Instant::now();
        s.write_all(&req).unwrap();
        let mut head = [0u8; 4];
        s.read_exact(&mut head).unwrap();
        let waited = started.elapsed();

        assert_eq!(head[0], 0, "expected a FramebufferUpdate");
        assert!(
            waited < Duration::from_millis(500),
            "an idle incremental request took {waited:?}; input would stall for \
             that long behind it"
        );
    }

    #[test]
    fn a_browser_is_served_the_embedded_client() {
        let mut s = connect(serve_a_test_desktop());
        s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        let mut page = Vec::new();
        s.read_to_end(&mut page).unwrap();
        let page = String::from_utf8_lossy(&page);
        assert!(page.starts_with("HTTP/1.1 200 OK"), "got: {page:.60}");
        assert!(page.contains("<!doctype html>"));
    }

    #[test]
    fn an_unknown_path_is_a_404() {
        let mut s = connect(serve_a_test_desktop());
        s.write_all(b"GET /nope HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        let mut reply = Vec::new();
        s.read_to_end(&mut reply).unwrap();
        assert!(String::from_utf8_lossy(&reply).starts_with("HTTP/1.1 404"));
    }

    #[test]
    fn video_upgrade_without_a_prestarted_helper_is_503() {
        // Encoded video is optional. A page receiving this response starts
        // Raw RFB on its already-established input/display connection.
        assert!(std::env::var_os("SMOLVM_VIDEO_SOCKET").is_none());
        let mut s = connect(serve_a_test_desktop());
        s.write_all(
            b"GET /video HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n\
              Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
        )
        .unwrap();
        let mut reply = Vec::new();
        s.read_to_end(&mut reply).unwrap();
        assert!(String::from_utf8_lossy(&reply).starts_with("HTTP/1.1 503"));
    }

    /// The client half of a WebSocket: masks what it writes, unmasks what it
    /// reads. Only as much of RFC 6455 as our server speaks.
    struct ClientWs(TcpStream, Vec<u8>, usize);

    impl Write for ClientWs {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let mask = [0x37u8, 0xfa, 0x21, 0x3d];
            let mut frame = vec![0x82]; // FIN + binary
            match buf.len() {
                n if n < 126 => frame.push(0x80 | n as u8),
                n => {
                    frame.push(0x80 | 126);
                    frame.extend_from_slice(&(n as u16).to_be_bytes());
                }
            }
            frame.extend_from_slice(&mask);
            frame.extend(buf.iter().enumerate().map(|(i, b)| b ^ mask[i & 3]));
            self.0.write_all(&frame)?;
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.0.flush()
        }
    }

    impl Read for ClientWs {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            while self.2 >= self.1.len() {
                let mut head = [0u8; 2];
                self.0.read_exact(&mut head)?;
                let len = match head[1] & 0x7f {
                    126 => {
                        let mut e = [0u8; 2];
                        self.0.read_exact(&mut e)?;
                        u16::from_be_bytes(e) as usize
                    }
                    127 => {
                        let mut e = [0u8; 8];
                        self.0.read_exact(&mut e)?;
                        u64::from_be_bytes(e) as usize
                    }
                    n => n as usize,
                };
                // Server frames are never masked, so the payload is literal.
                let mut payload = vec![0u8; len];
                self.0.read_exact(&mut payload)?;
                self.1 = payload;
                self.2 = 0;
            }
            let n = (self.1.len() - self.2).min(buf.len());
            buf[..n].copy_from_slice(&self.1[self.2..self.2 + n]);
            self.2 += n;
            Ok(n)
        }
    }

    #[test]
    fn a_browser_gets_the_same_rfb_session_over_a_websocket() {
        let mut s = connect(serve_a_test_desktop());
        s.write_all(
            b"GET /websockify HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n\
              Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
              Sec-WebSocket-Protocol: binary\r\n\r\n",
        )
        .unwrap();

        // Read exactly the response head, leaving frame bytes in the socket.
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            assert_eq!(s.read(&mut byte).unwrap(), 1, "connection closed early");
            head.push(byte[0]);
        }
        let head = String::from_utf8_lossy(&head);
        assert!(
            head.starts_with("HTTP/1.1 101 Switching Protocols"),
            "{head}"
        );
        assert!(head.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
        assert!(head.contains("Sec-WebSocket-Protocol: binary"));

        // The identical protocol now runs inside frames.
        let mut ws = ClientWs(s, Vec::new(), 0);
        let pixels = drive_rfb_session(&mut ws);
        assert_eq!(pixels.len(), (TEST_W * TEST_H * 4) as usize);
        assert_eq!(&pixels[..4], &[9, 8, 7, 255]);
    }
}
