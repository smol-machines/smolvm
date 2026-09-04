//! Host-side virtio-gpu display backend.
//!
//! `krun_add_display` describes a display: it makes the device report a
//! scanout, so the guest builds a connector with an EDID and a mode list and
//! `/dev/dri/card0` becomes a KMS device. That is necessary for a DRM
//! compositor to *start*, but it is not enough for one to *run*. Frames are
//! consumed by a display backend registered separately through
//! `krun_set_display_backend`, and when none is registered libkrun installs a
//! no-op whose `configure_scanout`/`alloc_frame`/`present_frame` all fail with
//! `InvalidScanoutId`. The guest's first page flip then never completes and
//! the compositor blocks forever on it — Hyprland reports
//! "Cannot commit when a page-flip is awaiting" and stops responding.
//!
//! This module is that missing consumer. It keeps the framebuffer on the host,
//! which is also what lets `vnc` serve the desktop without the guest running a
//! capture tool of its own.

use std::ffi::c_void;
use std::sync::{Arc, Condvar, Mutex};

use crate::error::{Error, Result};

/// `KRUN_DISPLAY_FEATURE_BASIC_FRAMEBUFFER`.
const FEATURE_BASIC_FRAMEBUFFER: u64 = 1;
const FEATURE_CURSOR: u64 = 2;

const ERR_INVALID_SCANOUT_ID: i32 = -3;
const ERR_INVALID_PARAM: i32 = -4;

/// virtio-gpu pixel formats, as re-exported by `libkrun_display.h`. The names
/// describe byte order in memory, so `B8G8R8A8` is B,G,R,A — the same order
/// RFB wants for a little-endian true-colour pixel with shifts R=16/G=8/B=0,
/// which is why those two need no conversion on the way out.
pub const FORMAT_B8G8R8A8: u32 = 1;
/// Bytes B,G,R,X in memory; the alpha byte is ignored.
pub const FORMAT_B8G8R8X8: u32 = 2;
/// Bytes A,R,G,B in memory — needs swizzling for RFB.
pub const FORMAT_A8R8G8B8: u32 = 3;
/// Bytes X,R,G,B in memory — needs swizzling for RFB.
pub const FORMAT_X8R8G8B8: u32 = 4;

const BYTES_PER_PIXEL: usize = 4;

/// Refuse absurd scanout geometry rather than allocating from it. libkrun is
/// trusted here, but this is guest-influenced state and the allocation is
/// `width * height * 4`.
const MAX_DIM: u32 = 16384;

// ---------------------------------------------------------------------------
// C ABI (see libkrun/src/display/libkrun_display.h)
// ---------------------------------------------------------------------------

/// `struct krun_rect` — a damage rectangle passed to `present_frame`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KrunRect {
    /// Left edge, in pixels.
    pub x: u32,
    /// Top edge, in pixels.
    pub y: u32,
    /// Width of the damaged area, in pixels.
    pub width: u32,
    /// Height of the damaged area, in pixels.
    pub height: u32,
}

#[repr(C)]
struct BasicFramebufferVtable {
    destroy: Option<unsafe extern "C" fn(*mut c_void) -> i32>,
    disable_scanout: Option<unsafe extern "C" fn(*mut c_void, u32) -> i32>,
    configure_scanout:
        Option<unsafe extern "C" fn(*mut c_void, u32, u32, u32, u32, u32, u32) -> i32>,
    alloc_frame: Option<unsafe extern "C" fn(*mut c_void, u32, *mut *mut u8, *mut usize) -> i32>,
    present_frame: Option<unsafe extern "C" fn(*mut c_void, u32, u32, *const KrunRect) -> i32>,
}

#[repr(C)]
struct CursorVtable {
    set_cursor:
        Option<unsafe extern "C" fn(*mut c_void, u32, u32, u32, u32, u32, *const u8, usize) -> i32>,
    move_cursor: Option<unsafe extern "C" fn(*mut c_void, u32, u32, u32) -> i32>,
}

#[repr(C)]
struct KrunDisplayBackend {
    features: u64,
    create_userdata: *const c_void,
    create: Option<unsafe extern "C" fn(*mut *mut c_void, *const c_void, *const c_void) -> i32>,
    vtable: BasicFramebufferVtable,
    cursor: CursorVtable,
}

// ---------------------------------------------------------------------------
// Shared framebuffer state
// ---------------------------------------------------------------------------

/// A fully presented frame, plus the geometry it was presented at.
#[derive(Clone)]
pub struct Frame {
    /// Raw pixels, `width * height * 4` bytes in `format`'s byte order.
    pub buf: Vec<u8>,
    /// Frame width in pixels.
    pub width: u32,
    /// Frame height in pixels.
    pub height: u32,
    /// One of the `FORMAT_*` constants.
    pub format: u32,
    /// Bumped on every present. Viewers compare against their last value to
    /// tell a new frame from a repeat without diffing pixels.
    pub generation: u64,
}

/// The guest's pointer as the VMM hands it over: the image the guest put on
/// its hardware cursor plane and where the hot spot is. With the pointer on
/// that plane the guest no longer draws it into frames, so viewers either
/// draw it themselves or composite it onto the frames they send.
#[derive(Clone, Default)]
pub struct Cursor {
    /// Image width in pixels; 0 when hidden.
    pub width: u32,
    /// Image height in pixels; 0 when hidden.
    pub height: u32,
    /// Hot spot x offset inside the image.
    pub hot_x: u32,
    /// Hot spot y offset inside the image.
    pub hot_y: u32,
    /// `width * height * 4` bytes, B,G,R,A with straight alpha; empty when
    /// the pointer is hidden.
    pub bgra: Vec<u8>,
    /// Hot spot x position on the scanout.
    pub x: u32,
    /// Hot spot y position on the scanout.
    pub y: u32,
    /// Bumped on every image change or move.
    pub generation: u64,
    /// Bumped only when the image changes, so a viewer that draws the pointer
    /// itself resends the image only when it has to.
    pub image_generation: u64,
    /// When the guest last hid the pointer while an image was still known.
    /// Compositors hide and re-show the pointer around every buffer flip,
    /// so a hide only counts once it has lasted a moment.
    pub hidden_since: Option<std::time::Instant>,
    /// When the guest last showed the pointer.
    pub shown_at: Option<std::time::Instant>,
}

/// How long a hide must last before viewers stop showing the pointer.
const HIDE_GRACE: std::time::Duration = std::time::Duration::from_millis(250);
/// A hide this soon after a show is the tail of a buffer flip, not a hide:
/// some compositors show the new pointer buffer and then hide the old one,
/// leaving the plane hidden until the next move. Those are dropped outright.
const FLIP_WINDOW: std::time::Duration = std::time::Duration::from_millis(150);

impl Cursor {
    /// Whether there is an image to show right now.
    pub fn is_visible(&self) -> bool {
        self.width > 0
            && self.height > 0
            && !self.bgra.is_empty()
            && self.hidden_since.is_none_or(|t| t.elapsed() < HIDE_GRACE)
    }
}

/// The buffer libkrun writes into. Deliberately *not* behind the mutex: the
/// contract in `libkrun_display.h` is that every backend method is called from
/// one and the same thread, so this is single-threaded state, and holding the
/// viewer lock across a whole guest frame render would stall the GPU device.
struct Staging {
    buf: Vec<u8>,
    width: u32,
    height: u32,
    format: u32,
    configured: bool,
}

/// The host-side framebuffer the guest presents into, shared between
/// libkrun's GPU thread and any viewers.
pub struct DisplayFramebuffer {
    /// # Safety
    /// Only ever touched from the libkrun GPU thread — see `Staging`.
    staging: std::cell::UnsafeCell<Staging>,
    front: Mutex<Frame>,
    presented: Condvar,
    cursor: Mutex<Cursor>,
    /// Mirrors `cursor.generation` so waiters can test it under `front`.
    cursor_generation: std::sync::atomic::AtomicU64,
    /// Optional call trace, enabled by `SMOLVM_DISPLAY_TRACE=<path>`.
    ///
    /// libkrun's own logging goes through `env_logger` in a process whose
    /// stdout and stderr are `/dev/null` unless `SMOLVM_BOOT_DEBUG` is set,
    /// and even with it set no libkrun line has ever reached us. Writing our
    /// own trace to a plain file is the only way to see whether the guest is
    /// actually presenting, which is the question that matters when a
    /// compositor renders once and then stalls.
    trace: Option<Mutex<std::fs::File>>,
    /// Monotonic counter so trace lines are ordered and countable.
    traced_calls: std::sync::atomic::AtomicU64,
}

// SAFETY: `staging` is only accessed from the single thread libkrun uses for
// every display-backend callback (documented in libkrun_display.h). `front`
// and `presented` are ordinary sync primitives.
unsafe impl Sync for DisplayFramebuffer {}
unsafe impl Send for DisplayFramebuffer {}

impl DisplayFramebuffer {
    fn new() -> Self {
        // Best effort: a missing or unwritable path just disables tracing
        // rather than failing the boot.
        let trace = std::env::var("SMOLVM_DISPLAY_TRACE").ok().and_then(|path| {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .ok()
                .map(Mutex::new)
        });
        Self {
            staging: std::cell::UnsafeCell::new(Staging {
                buf: Vec::new(),
                width: 0,
                height: 0,
                format: FORMAT_B8G8R8A8,
                configured: false,
            }),
            front: Mutex::new(Frame {
                buf: Vec::new(),
                width: 0,
                height: 0,
                format: FORMAT_B8G8R8A8,
                generation: 0,
            }),
            presented: Condvar::new(),
            cursor: Mutex::new(Cursor::default()),
            cursor_generation: std::sync::atomic::AtomicU64::new(0),
            trace,
            traced_calls: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Append a numbered line to the call trace, bounded so a long-running
    /// desktop cannot fill the disk. Sampling was a mistake the first time
    /// round: it could not distinguish "presents stopped" from "presents
    /// continued but missed the sampling window".
    fn trace_seq(&self, what: &str) {
        if self.trace.is_none() {
            return;
        }
        const MAX_TRACED_CALLS: u64 = 2000;
        let n = self
            .traced_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if n < MAX_TRACED_CALLS {
            self.trace(&format!("{n:05} {what}"));
        } else if n == MAX_TRACED_CALLS {
            self.trace("... trace limit reached, further calls not logged");
        }
    }

    /// Append one line to the call trace, if enabled.
    fn trace(&self, line: &str) {
        let Some(f) = self.trace.as_ref() else { return };
        use std::io::Write;
        let mut f = f.lock().unwrap_or_else(|e| e.into_inner());
        let _ = writeln!(f, "{line}");
        let _ = f.flush();
    }

    /// The most recently presented frame, or `None` before the guest has
    /// presented anything.
    pub fn latest(&self) -> Option<Frame> {
        let f = self.front.lock().unwrap_or_else(|e| e.into_inner());
        if f.generation == 0 {
            None
        } else {
            Some(f.clone())
        }
    }

    /// Generation of the most recently presented frame, or zero before the
    /// first present.  Video pacing uses this cheap check to avoid cloning a
    /// full framebuffer when an idle desktop has not changed.
    pub fn current_generation(&self) -> u64 {
        self.front
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .generation
    }

    /// A framebuffer already holding one presented frame, so viewer tests
    /// have something to serve without a guest behind them.
    #[cfg(test)]
    pub(crate) fn with_presented_frame(width: u32, height: u32, pixel: [u8; 4]) -> Self {
        let fb = Self::new();
        {
            let mut front = fb.front.lock().unwrap();
            front.buf = pixel.repeat((width * height) as usize);
            front.width = width;
            front.height = height;
            front.generation = 1;
        }
        fb
    }

    /// The pointer as last reported by the guest.
    pub fn cursor(&self) -> Cursor {
        self.cursor
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Block until a frame newer than `since_frame` is presented or the
    /// pointer changes past `since_cursor`, or `timeout` elapses. Returns
    /// whichever of the two is new.
    pub fn wait_for_change(
        &self,
        since_frame: u64,
        since_cursor: u64,
        timeout: std::time::Duration,
    ) -> (Option<Frame>, Option<Cursor>) {
        use std::sync::atomic::Ordering;
        let guard = self.front.lock().unwrap_or_else(|e| e.into_inner());
        let (guard, _) = self
            .presented
            .wait_timeout_while(guard, timeout, |f| {
                f.generation <= since_frame
                    && self.cursor_generation.load(Ordering::Acquire) <= since_cursor
            })
            .unwrap_or_else(|e| e.into_inner());
        let frame = (guard.generation > since_frame).then(|| guard.clone());
        drop(guard);
        let cursor = {
            let c = self.cursor.lock().unwrap_or_else(|e| e.into_inner());
            (c.generation > since_cursor).then(|| c.clone())
        };
        (frame, cursor)
    }

    /// Record a pointer change and wake viewers. Taken under `front` so a
    /// viewer between its generation check and its wait cannot miss it.
    fn cursor_changed(&self, apply: impl FnOnce(&mut Cursor)) {
        use std::sync::atomic::Ordering;
        let _front = self.front.lock().unwrap_or_else(|e| e.into_inner());
        {
            let mut c = self.cursor.lock().unwrap_or_else(|e| e.into_inner());
            apply(&mut c);
            c.generation = c.generation.wrapping_add(1);
            self.cursor_generation
                .store(c.generation, Ordering::Release);
        }
        self.presented.notify_all();
    }

    /// Block until a frame newer than `since` is presented, or `timeout`
    /// elapses. Returns the frame if one arrived.
    pub fn wait_for_frame(&self, since: u64, timeout: std::time::Duration) -> Option<Frame> {
        let guard = self.front.lock().unwrap_or_else(|e| e.into_inner());
        let (guard, _) = self
            .presented
            .wait_timeout_while(guard, timeout, |f| f.generation <= since)
            .unwrap_or_else(|e| e.into_inner());
        if guard.generation > since {
            Some(guard.clone())
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Backend callbacks
// ---------------------------------------------------------------------------

/// # Safety
/// `instance` must be the pointer handed back by `display_create`, i.e. a
/// borrowed `Arc<DisplayFramebuffer>` that outlives the VM.
unsafe fn fb<'a>(instance: *mut c_void) -> Option<&'a DisplayFramebuffer> {
    if instance.is_null() {
        None
    } else {
        Some(unsafe { &*(instance as *const DisplayFramebuffer) })
    }
}

unsafe extern "C" fn display_create(
    instance: *mut *mut c_void,
    userdata: *const c_void,
    _reserved: *const c_void,
) -> i32 {
    if instance.is_null() {
        return ERR_INVALID_PARAM;
    }
    // The state is created up front and leaked; `create` just hands it back as
    // the `self` pointer for subsequent calls.
    unsafe { *instance = userdata as *mut c_void };
    0
}

unsafe extern "C" fn display_destroy(_instance: *mut c_void) -> i32 {
    // The state is intentionally leaked for the process lifetime: viewer
    // threads hold `Arc`s and the VM teardown path is the process exiting.
    0
}

unsafe extern "C" fn display_configure_scanout(
    instance: *mut c_void,
    scanout_id: u32,
    _display_width: u32,
    _display_height: u32,
    width: u32,
    height: u32,
    format: u32,
) -> i32 {
    // Only scanout 0 exists: smolvm adds exactly one display.
    if scanout_id != 0 {
        return ERR_INVALID_SCANOUT_ID;
    }
    if width == 0 || height == 0 || width > MAX_DIM || height > MAX_DIM {
        return ERR_INVALID_PARAM;
    }
    let Some(fb) = (unsafe { fb(instance) }) else {
        return ERR_INVALID_PARAM;
    };

    let staging = unsafe { &mut *fb.staging.get() };
    let len = width as usize * height as usize * BYTES_PER_PIXEL;
    staging.buf.clear();
    staging.buf.resize(len, 0);
    staging.width = width;
    staging.height = height;
    staging.format = format;
    staging.configured = true;

    fb.trace(&format!(
        "configure_scanout scanout=0 {width}x{height} format={format} bytes={len}"
    ));
    tracing::info!(
        width,
        height,
        format,
        "virtio-gpu scanout configured (host framebuffer ready)"
    );
    0
}

unsafe extern "C" fn display_disable_scanout(instance: *mut c_void, scanout_id: u32) -> i32 {
    if scanout_id != 0 {
        return ERR_INVALID_SCANOUT_ID;
    }
    let Some(fb) = (unsafe { fb(instance) }) else {
        return ERR_INVALID_PARAM;
    };
    let staging = unsafe { &mut *fb.staging.get() };
    staging.configured = false;
    fb.trace("disable_scanout scanout=0");
    tracing::debug!("virtio-gpu scanout disabled");
    0
}

unsafe extern "C" fn display_alloc_frame(
    instance: *mut c_void,
    scanout_id: u32,
    buffer: *mut *mut u8,
    buffer_size: *mut usize,
) -> i32 {
    if scanout_id != 0 {
        return ERR_INVALID_SCANOUT_ID;
    }
    if buffer.is_null() || buffer_size.is_null() {
        return ERR_INVALID_PARAM;
    }
    let Some(fb) = (unsafe { fb(instance) }) else {
        return ERR_INVALID_PARAM;
    };

    let staging = unsafe { &mut *fb.staging.get() };
    if !staging.configured || staging.buf.is_empty() {
        fb.trace("alloc_frame REJECTED (scanout not configured)");
        return ERR_INVALID_SCANOUT_ID;
    }

    unsafe {
        *buffer = staging.buf.as_mut_ptr();
        *buffer_size = staging.buf.len();
    }
    fb.trace_seq("alloc_frame");
    // Single staging buffer, so there is only ever one live frame id.
    0
}

unsafe extern "C" fn display_present_frame(
    instance: *mut c_void,
    scanout_id: u32,
    _frame_id: u32,
    _damage: *const KrunRect,
) -> i32 {
    if scanout_id != 0 {
        return ERR_INVALID_SCANOUT_ID;
    }
    let Some(fb) = (unsafe { fb(instance) }) else {
        return ERR_INVALID_PARAM;
    };

    let staging = unsafe { &*fb.staging.get() };
    if !staging.configured {
        return ERR_INVALID_SCANOUT_ID;
    }

    {
        let mut front = fb.front.lock().unwrap_or_else(|e| e.into_inner());
        // Copy the whole frame rather than honouring the damage rect: the
        // front buffer may be a different generation than the damage was
        // computed against, and a viewer that joined mid-stream would inherit
        // stale pixels outside the damaged area.
        front.buf.clear();
        front.buf.extend_from_slice(&staging.buf);
        front.width = staging.width;
        front.height = staging.height;
        front.format = staging.format;
        front.generation = front.generation.wrapping_add(1);
    }
    fb.presented.notify_all();

    fb.trace_seq("present_frame");
    0
}

unsafe extern "C" fn display_set_cursor(
    instance: *mut c_void,
    scanout_id: u32,
    width: u32,
    height: u32,
    hot_x: u32,
    hot_y: u32,
    bgra: *const u8,
    bgra_size: usize,
) -> i32 {
    if scanout_id != 0 {
        return ERR_INVALID_SCANOUT_ID;
    }
    let Some(fb) = (unsafe { fb(instance) }) else {
        return ERR_INVALID_PARAM;
    };
    let hidden = width == 0 || height == 0;
    let needed = width as usize * height as usize * BYTES_PER_PIXEL;
    if !hidden && (bgra.is_null() || bgra_size < needed || width > 512 || height > 512) {
        return ERR_INVALID_PARAM;
    }
    let (width, height, hot_x, hot_y, pixels) = if hidden {
        (0, 0, hot_x, hot_y, Vec::new())
    } else {
        // Safe: libkrun promises `bgra_size` readable bytes for the call.
        let full = unsafe { std::slice::from_raw_parts(bgra, needed) };
        crop_cursor(full, width, height, hot_x, hot_y)
    };
    fb.cursor_changed(|c| {
        if hidden {
            if c.shown_at.is_some_and(|t| t.elapsed() < FLIP_WINDOW) {
                return;
            }
            // Keep the image; the hide takes effect only if it lasts.
            if c.hidden_since.is_none() {
                c.hidden_since = Some(std::time::Instant::now());
            }
            return;
        }
        c.hidden_since = None;
        c.shown_at = Some(std::time::Instant::now());
        // Compositors re-send the same image on every move; only a real
        // change should make viewers re-fetch it.
        let same = c.width == width
            && c.height == height
            && c.hot_x == hot_x
            && c.hot_y == hot_y
            && c.bgra == pixels;
        if same {
            return;
        }
        c.width = width;
        c.height = height;
        c.hot_x = hot_x;
        c.hot_y = hot_y;
        c.bgra = pixels;
        c.image_generation = c.image_generation.wrapping_add(1);
    });
    fb.trace_seq("set_cursor");
    0
}

/// Trim the transparent border off a pointer image and shift the hot spot to
/// match. Compositors hand over the same pointer drawn at different offsets
/// in a fixed 64x64 buffer; trimmed, those compare equal, so viewers are not
/// sent a "new" image on every move, and the image itself gets much smaller.
fn crop_cursor(
    bgra: &[u8],
    width: u32,
    height: u32,
    hot_x: u32,
    hot_y: u32,
) -> (u32, u32, u32, u32, Vec<u8>) {
    let (w, h) = (width as usize, height as usize);
    let (mut x0, mut y0, mut x1, mut y1) = (w, h, 0usize, 0usize);
    for y in 0..h {
        for x in 0..w {
            if bgra[(y * w + x) * 4 + 3] != 0 {
                x0 = x0.min(x);
                y0 = y0.min(y);
                x1 = x1.max(x + 1);
                y1 = y1.max(y + 1);
            }
        }
    }
    if x0 >= x1 || y0 >= y1 {
        return (0, 0, hot_x, hot_y, Vec::new());
    }
    // Keep the hot spot inside the trimmed image.
    let x0 = x0.min(hot_x as usize);
    let y0 = y0.min(hot_y as usize);
    let x1 = x1.max(hot_x as usize + 1).min(w);
    let y1 = y1.max(hot_y as usize + 1).min(h);
    let (cw, ch) = (x1 - x0, y1 - y0);
    let mut out = Vec::with_capacity(cw * ch * 4);
    for y in y0..y1 {
        out.extend_from_slice(&bgra[(y * w + x0) * 4..(y * w + x1) * 4]);
    }
    (
        cw as u32,
        ch as u32,
        hot_x - x0 as u32,
        hot_y - y0 as u32,
        out,
    )
}

unsafe extern "C" fn display_move_cursor(
    instance: *mut c_void,
    scanout_id: u32,
    x: u32,
    y: u32,
) -> i32 {
    if scanout_id != 0 {
        return ERR_INVALID_SCANOUT_ID;
    }
    let Some(fb) = (unsafe { fb(instance) }) else {
        return ERR_INVALID_PARAM;
    };
    fb.cursor_changed(|c| {
        c.x = x;
        c.y = y;
    });
    0
}

// ---------------------------------------------------------------------------
// Installation
// ---------------------------------------------------------------------------

/// Register a host framebuffer as the VM's display backend.
///
/// Must be called before boot and after `krun_add_display`, and the returned
/// handle is what viewers (e.g. the VNC server) read frames from.
pub fn install(
    set_display_backend: unsafe extern "C" fn(u32, *const c_void, usize) -> i32,
    ctx: u32,
) -> Result<Arc<DisplayFramebuffer>> {
    let state = Arc::new(DisplayFramebuffer::new());

    // libkrun keeps `create_userdata` and calls back into it for the life of
    // the VM, so this reference is deliberately leaked rather than tied to a
    // Rust lifetime the FFI boundary cannot express.
    let raw = Arc::into_raw(Arc::clone(&state));

    let backend = KrunDisplayBackend {
        features: FEATURE_BASIC_FRAMEBUFFER | FEATURE_CURSOR,
        create_userdata: raw as *const c_void,
        create: Some(display_create),
        vtable: BasicFramebufferVtable {
            destroy: Some(display_destroy),
            disable_scanout: Some(display_disable_scanout),
            configure_scanout: Some(display_configure_scanout),
            alloc_frame: Some(display_alloc_frame),
            present_frame: Some(display_present_frame),
        },
        cursor: CursorVtable {
            set_cursor: Some(display_set_cursor),
            move_cursor: Some(display_move_cursor),
        },
    };

    // libkrun copies the struct out (read_unaligned), so a stack pointer is
    // fine; only `create_userdata` has to outlive this call.
    let ret = unsafe {
        set_display_backend(
            ctx,
            &backend as *const KrunDisplayBackend as *const c_void,
            std::mem::size_of::<KrunDisplayBackend>(),
        )
    };
    if ret < 0 {
        // Reclaim the leak so a failed install does not also lose memory.
        unsafe { drop(Arc::from_raw(raw)) };
        return Err(Error::agent(
            "configure display",
            format!("krun_set_display_backend failed (ret={ret})"),
        ));
    }

    state.trace("display backend installed");
    Ok(state)
}

/// Convert a presented frame into RFB's little-endian 32-bit true-colour
/// layout (shifts R=16, G=8, B=0), which is byte order B,G,R,X in memory.
///
/// Returns `Cow::Borrowed` for the formats that already match, so the common
/// path copies nothing.
pub fn to_bgrx(frame: &Frame) -> std::borrow::Cow<'_, [u8]> {
    match frame.format {
        // Already B,G,R,{A,X} in memory.
        FORMAT_B8G8R8A8 | FORMAT_B8G8R8X8 => std::borrow::Cow::Borrowed(&frame.buf),
        // A,R,G,B in memory -> B,G,R,A.
        FORMAT_A8R8G8B8 | FORMAT_X8R8G8B8 => {
            let mut out = vec![0u8; frame.buf.len()];
            let (src_px, _) = frame.buf.as_chunks::<BYTES_PER_PIXEL>();
            let (dst_px, _) = out.as_chunks_mut::<BYTES_PER_PIXEL>();
            for (src, dst) in src_px.iter().zip(dst_px.iter_mut()) {
                dst[0] = src[3];
                dst[1] = src[2];
                dst[2] = src[1];
                dst[3] = src[0];
            }
            std::borrow::Cow::Owned(out)
        }
        // Unknown format: pass through rather than mangle. Colours may be
        // wrong but the geometry and liveness are still meaningful.
        _ => std::borrow::Cow::Borrowed(&frame.buf),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(format: u32, buf: Vec<u8>) -> Frame {
        Frame {
            buf,
            width: 1,
            height: 1,
            format,
            generation: 1,
        }
    }

    #[test]
    fn bgra_passes_through_without_copying() {
        let f = frame(FORMAT_B8G8R8A8, vec![1, 2, 3, 4]);
        assert!(matches!(to_bgrx(&f), std::borrow::Cow::Borrowed(_)));
        assert_eq!(&*to_bgrx(&f), &[1, 2, 3, 4]);
    }

    #[test]
    fn argb_is_swizzled_to_bgra() {
        // memory A,R,G,B = 0xAA,0xRR,0xGG,0xBB -> B,G,R,A
        let f = frame(FORMAT_A8R8G8B8, vec![0xAA, 0x11, 0x22, 0x33]);
        assert_eq!(&*to_bgrx(&f), &[0x33, 0x22, 0x11, 0xAA]);
    }

    #[test]
    fn unknown_format_is_passed_through_not_mangled() {
        let f = frame(9999, vec![9, 8, 7, 6]);
        assert_eq!(&*to_bgrx(&f), &[9, 8, 7, 6]);
    }

    #[test]
    fn latest_is_none_before_any_present() {
        let fb = DisplayFramebuffer::new();
        assert!(fb.latest().is_none());
    }

    #[test]
    fn present_publishes_a_frame_and_bumps_generation() {
        let fb = Arc::new(DisplayFramebuffer::new());
        let raw = Arc::as_ptr(&fb) as *mut c_void;
        unsafe {
            assert_eq!(
                display_configure_scanout(raw, 0, 2, 2, 2, 2, FORMAT_B8G8R8A8),
                0
            );
            let mut buf: *mut u8 = std::ptr::null_mut();
            let mut len: usize = 0;
            assert_eq!(display_alloc_frame(raw, 0, &mut buf, &mut len), 0);
            assert_eq!(len, 2 * 2 * 4);
            std::ptr::write_bytes(buf, 0x7f, len);
            assert_eq!(display_present_frame(raw, 0, 0, std::ptr::null()), 0);
        }
        let f = fb.latest().expect("a frame was presented");
        assert_eq!((f.width, f.height), (2, 2));
        assert_eq!(f.generation, 1);
        assert!(f.buf.iter().all(|&b| b == 0x7f));
    }

    #[test]
    fn alloc_before_configure_is_rejected() {
        let fb = Arc::new(DisplayFramebuffer::new());
        let raw = Arc::as_ptr(&fb) as *mut c_void;
        let mut buf: *mut u8 = std::ptr::null_mut();
        let mut len: usize = 0;
        // Without this guard alloc_frame would hand back a zero-length slice
        // and the guest would present into nothing.
        assert_eq!(
            unsafe { display_alloc_frame(raw, 0, &mut buf, &mut len) },
            ERR_INVALID_SCANOUT_ID
        );
    }

    #[test]
    fn non_zero_scanout_is_rejected() {
        let fb = Arc::new(DisplayFramebuffer::new());
        let raw = Arc::as_ptr(&fb) as *mut c_void;
        unsafe {
            assert_eq!(
                display_configure_scanout(raw, 1, 2, 2, 2, 2, FORMAT_B8G8R8A8),
                ERR_INVALID_SCANOUT_ID
            );
            assert_eq!(
                display_present_frame(raw, 1, 0, std::ptr::null()),
                ERR_INVALID_SCANOUT_ID
            );
        }
    }

    #[test]
    fn absurd_geometry_is_rejected_before_allocating() {
        let fb = Arc::new(DisplayFramebuffer::new());
        let raw = Arc::as_ptr(&fb) as *mut c_void;
        unsafe {
            assert_eq!(
                display_configure_scanout(raw, 0, 0, 0, 0, 100, FORMAT_B8G8R8A8),
                ERR_INVALID_PARAM
            );
            assert_eq!(
                display_configure_scanout(raw, 0, 0, 0, 99999, 100, FORMAT_B8G8R8A8),
                ERR_INVALID_PARAM
            );
        }
    }
}
