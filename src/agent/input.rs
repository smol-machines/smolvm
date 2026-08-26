//! Virtio-input devices fed by the VNC server, so a connected client can
//! type and point instead of only watching.
//!
//! libkrun's input device is backend-driven like the display: the embedder
//! hands `krun_add_input_device` a *config* vtable (device identity and
//! capability bitmaps, queried once by the guest driver) and an *event
//! provider* vtable (a ready fd plus a non-blocking `next_event` pop). Two
//! devices are registered — a keyboard and an absolute pointer — because a
//! single device advertising both keys and absolute axes classifies poorly
//! in libinput, while the split matches what QEMU exposes and every guest
//! stack already understands.

use std::collections::VecDeque;
use std::ffi::c_void;
use std::sync::{Arc, Mutex};

use crate::{Error, Result};

// ---------------------------------------------------------------------------
// C ABI mirrors of libkrun_input.h
// ---------------------------------------------------------------------------

/// Linux `EV_SYN` event type (frame terminator).
pub const EV_SYN: u16 = 0x00;
/// Linux `EV_KEY` event type (keys and buttons).
pub const EV_KEY: u16 = 0x01;
/// Linux `EV_REL` event type (relative axes; used for the scroll wheel).
pub const EV_REL: u16 = 0x02;
/// Linux `EV_ABS` event type (absolute axes; pointer position).
pub const EV_ABS: u16 = 0x03;
const SYN_REPORT: u16 = 0;

/// Linux `BTN_LEFT` keycode.
pub const BTN_LEFT: u16 = 0x110;
/// Linux `BTN_RIGHT` keycode.
pub const BTN_RIGHT: u16 = 0x111;
/// Linux `BTN_MIDDLE` keycode.
pub const BTN_MIDDLE: u16 = 0x112;
/// Linux `REL_WHEEL` axis code.
pub const REL_WHEEL: u16 = 8;
#[cfg(unix)]
const ABS_X: u16 = 0;
#[cfg(unix)]
const ABS_Y: u16 = 1;

/// Absolute axes are reported in a fixed virtual range and scaled from pixel
/// coordinates, so a guest mode change never invalidates the device's absinfo.
pub const ABS_RANGE: u32 = 32767;

#[cfg(unix)]
const ERR_INVALID_PARAM: i32 = -4;

#[cfg(unix)]
const FEATURE_QUERY: u64 = 1;
#[cfg(unix)]
const FEATURE_QUEUE: u64 = 1;

/// One input event in libkrun's wire layout, matching `struct
/// krun_input_event` and the virtio-input event the guest receives.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KrunInputEvent {
    /// Event type (`EV_KEY`, `EV_ABS`, ...).
    pub type_: u16,
    /// Event code within the type (keycode, axis, ...).
    pub code: u16,
    /// Event value (press state, axis position, wheel delta).
    pub value: u32,
}

#[cfg(unix)]
#[repr(C)]
struct KrunInputDeviceIds {
    bustype: u16,
    vendor: u16,
    product: u16,
    version: u16,
}

#[cfg(unix)]
#[repr(C)]
struct KrunInputAbsinfo {
    min: u32,
    max: u32,
    fuzz: u32,
    flat: u32,
    res: u32,
}

#[cfg(unix)]
type CreateFn = unsafe extern "C" fn(*mut *mut c_void, *const c_void, *const c_void) -> i32;

#[cfg(unix)]
#[repr(C)]
struct ConfigVtable {
    destroy: Option<unsafe extern "C" fn(*mut c_void) -> i32>,
    query_device_name: Option<unsafe extern "C" fn(*mut c_void, *mut u8, usize) -> i32>,
    query_serial_name: Option<unsafe extern "C" fn(*mut c_void, *mut u8, usize) -> i32>,
    query_device_ids: Option<unsafe extern "C" fn(*mut c_void, *mut KrunInputDeviceIds) -> i32>,
    query_event_capabilities: Option<unsafe extern "C" fn(*mut c_void, u8, *mut u8, usize) -> i32>,
    query_abs_info: Option<unsafe extern "C" fn(*mut c_void, u8, *mut KrunInputAbsinfo) -> i32>,
    query_properties: Option<unsafe extern "C" fn(*mut c_void, *mut u8, usize) -> i32>,
}

#[cfg(unix)]
#[repr(C)]
struct KrunInputConfig {
    features: u64,
    create_userdata: *const c_void,
    create: Option<CreateFn>,
    vtable: ConfigVtable,
}

#[cfg(unix)]
#[repr(C)]
struct ProviderVtable {
    destroy: Option<unsafe extern "C" fn(*mut c_void) -> i32>,
    get_ready_efd: Option<unsafe extern "C" fn(*mut c_void) -> i32>,
    next_event: Option<unsafe extern "C" fn(*mut c_void, *mut KrunInputEvent) -> i32>,
}

#[cfg(unix)]
#[repr(C)]
struct KrunInputEventProvider {
    features: u64,
    create_userdata: *const c_void,
    create: Option<CreateFn>,
    vtable: ProviderVtable,
}

// ---------------------------------------------------------------------------
// Event queue shared between the VNC server (producer) and libkrun's input
// worker (consumer)
// ---------------------------------------------------------------------------

/// A pipe is used for readiness instead of an eventfd so the same code builds
/// on macOS. The worker epolls the read end level-triggered and never reads
/// it, so `next_event` must drain the pipe when reporting empty — under the
/// queue lock, so a concurrent push (which writes the pipe *after* enqueuing)
/// can never be swallowed.
pub struct InputQueue {
    events: Mutex<VecDeque<KrunInputEvent>>,
    #[cfg(unix)]
    read_fd: i32,
    #[cfg(unix)]
    write_fd: i32,
}

// SAFETY: the fds are plain integers used with thread-safe syscalls, and the
// queue itself is behind a Mutex.
unsafe impl Send for InputQueue {}
unsafe impl Sync for InputQueue {}

impl InputQueue {
    #[cfg(unix)]
    fn new() -> Result<Self> {
        let mut fds = [0i32; 2];
        // SAFETY: fds is a valid out-array for pipe(2).
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err(Error::agent(
                "configure input",
                format!("pipe failed: {}", std::io::Error::last_os_error()),
            ));
        }
        for fd in fds {
            // SAFETY: fd was just returned by pipe(2).
            unsafe {
                let flags = libc::fcntl(fd, libc::F_GETFL);
                libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
        }
        Ok(Self {
            events: Mutex::new(VecDeque::new()),
            read_fd: fds[0],
            write_fd: fds[1],
        })
    }

    /// Queue a batch of events followed by a SYN_REPORT frame terminator,
    /// then signal the ready fd.
    pub fn push(&self, batch: &[(u16, u16, u32)]) {
        if batch.is_empty() {
            return;
        }
        {
            let mut q = self.events.lock().unwrap();
            for &(type_, code, value) in batch {
                q.push_back(KrunInputEvent { type_, code, value });
            }
            q.push_back(KrunInputEvent {
                type_: EV_SYN,
                code: SYN_REPORT,
                value: 0,
            });
        }
        // A full pipe is fine: it is still readable, which is all the worker
        // needs to wake up.
        // SAFETY: write_fd is a valid non-blocking pipe write end.
        #[cfg(unix)]
        unsafe {
            libc::write(self.write_fd, [1u8].as_ptr() as *const c_void, 1)
        };
    }

    #[cfg(unix)]
    fn pop(&self) -> Option<KrunInputEvent> {
        let mut q = self.events.lock().unwrap();
        match q.pop_front() {
            Some(ev) => Some(ev),
            None => {
                // Clear readiness while holding the lock; see type docs.
                #[cfg(unix)]
                {
                    let mut buf = [0u8; 64];
                    // SAFETY: read_fd is a valid non-blocking pipe read end.
                    while unsafe { libc::read(self.read_fd, buf.as_mut_ptr() as *mut c_void, 64) }
                        > 0
                    {}
                }
                None
            }
        }
    }
}

#[cfg(unix)]
impl Drop for InputQueue {
    fn drop(&mut self) {
        // SAFETY: both fds are owned by this queue.
        unsafe {
            libc::close(self.read_fd);
            libc::close(self.write_fd);
        }
    }
}

/// Handles the VNC server holds to feed the guest's input devices.
#[derive(Clone)]
pub struct VncInput {
    /// Event queue of the virtio keyboard device.
    pub keyboard: Arc<InputQueue>,
    /// Event queue of the virtio absolute-pointer device.
    pub pointer: Arc<InputQueue>,
}

// ---------------------------------------------------------------------------
// Config backends
// ---------------------------------------------------------------------------

#[cfg(unix)]
enum DeviceKind {
    Keyboard,
    Pointer,
}

#[cfg(unix)]
struct DeviceDesc {
    name: &'static str,
    kind: DeviceKind,
}

#[cfg(unix)]
unsafe extern "C" fn passthrough_create(
    instance: *mut *mut c_void,
    userdata: *const c_void,
    _reserved: *const c_void,
) -> i32 {
    // The userdata *is* the instance: config state is immutable and the
    // event queue is internally synchronized.
    unsafe { *instance = userdata as *mut c_void };
    0
}

#[cfg(unix)]
unsafe extern "C" fn config_query_device_name(
    instance: *mut c_void,
    buf: *mut u8,
    len: usize,
) -> i32 {
    let desc = unsafe { &*(instance as *const DeviceDesc) };
    let bytes = desc.name.as_bytes();
    if bytes.len() > len {
        return ERR_INVALID_PARAM;
    }
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, bytes.len()) };
    bytes.len() as i32
}

#[cfg(unix)]
unsafe extern "C" fn config_query_serial_name(
    _instance: *mut c_void,
    _buf: *mut u8,
    _len: usize,
) -> i32 {
    0
}

#[cfg(unix)]
unsafe extern "C" fn config_query_device_ids(
    instance: *mut c_void,
    ids: *mut KrunInputDeviceIds,
) -> i32 {
    let desc = unsafe { &*(instance as *const DeviceDesc) };
    let product = match desc.kind {
        DeviceKind::Keyboard => 1,
        DeviceKind::Pointer => 2,
    };
    unsafe {
        *ids = KrunInputDeviceIds {
            bustype: 0x06, // BUS_VIRTUAL
            vendor: 0x1af4,
            product,
            version: 1,
        };
    }
    0
}

/// Write a byte bitmap with the given bit positions set. Returns the number
/// of bytes the bitmap spans, which is what the caller forwards to the guest.
#[cfg(unix)]
fn write_bitmap(buf: *mut u8, len: usize, bits: &[u16]) -> i32 {
    let span = match bits.iter().max() {
        Some(&m) => (m as usize / 8) + 1,
        None => return 0,
    };
    if span > len {
        return ERR_INVALID_PARAM;
    }
    // SAFETY: caller guarantees buf points at len writable bytes.
    unsafe {
        std::ptr::write_bytes(buf, 0, span);
        for &bit in bits {
            *buf.add(bit as usize / 8) |= 1 << (bit % 8);
        }
    }
    span as i32
}

#[cfg(unix)]
unsafe extern "C" fn config_query_event_capabilities(
    instance: *mut c_void,
    event_type: u8,
    buf: *mut u8,
    len: usize,
) -> i32 {
    let desc = unsafe { &*(instance as *const DeviceDesc) };
    match (&desc.kind, event_type as u16) {
        (DeviceKind::Keyboard, EV_KEY) => {
            // All plain keyboard keycodes. 1..=248 covers everything the
            // keysym table below can produce, with room for layouts we may
            // map later.
            let keys: Vec<u16> = (1u16..=248).collect();
            write_bitmap(buf, len, &keys)
        }
        (DeviceKind::Pointer, EV_KEY) => write_bitmap(buf, len, &[BTN_LEFT, BTN_RIGHT, BTN_MIDDLE]),
        (DeviceKind::Pointer, EV_ABS) => write_bitmap(buf, len, &[ABS_X, ABS_Y]),
        (DeviceKind::Pointer, EV_REL) => write_bitmap(buf, len, &[REL_WHEEL]),
        _ => 0,
    }
}

#[cfg(unix)]
unsafe extern "C" fn config_query_abs_info(
    instance: *mut c_void,
    abs_axis: u8,
    abs_info: *mut KrunInputAbsinfo,
) -> i32 {
    let desc = unsafe { &*(instance as *const DeviceDesc) };
    match (&desc.kind, abs_axis as u16) {
        (DeviceKind::Pointer, ABS_X) | (DeviceKind::Pointer, ABS_Y) => {
            unsafe {
                *abs_info = KrunInputAbsinfo {
                    min: 0,
                    max: ABS_RANGE,
                    fuzz: 0,
                    flat: 0,
                    res: 0,
                };
            }
            0
        }
        _ => ERR_INVALID_PARAM,
    }
}

#[cfg(unix)]
unsafe extern "C" fn config_query_properties(
    _instance: *mut c_void,
    _buf: *mut u8,
    _len: usize,
) -> i32 {
    0
}

// ---------------------------------------------------------------------------
// Event provider backend
// ---------------------------------------------------------------------------

#[cfg(unix)]
unsafe extern "C" fn provider_get_ready_efd(instance: *mut c_void) -> i32 {
    let queue = unsafe { &*(instance as *const InputQueue) };
    queue.read_fd
}

#[cfg(unix)]
unsafe extern "C" fn provider_next_event(instance: *mut c_void, out: *mut KrunInputEvent) -> i32 {
    let queue = unsafe { &*(instance as *const InputQueue) };
    match queue.pop() {
        Some(ev) => {
            unsafe { *out = ev };
            1
        }
        None => 0,
    }
}

// ---------------------------------------------------------------------------
// Installation
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn add_device(
    add_input_device: unsafe extern "C" fn(u32, *const c_void, usize, *const c_void, usize) -> i32,
    ctx: u32,
    desc: DeviceDesc,
) -> Result<Arc<InputQueue>> {
    let queue = Arc::new(InputQueue::new()?);

    // libkrun keeps both userdata pointers and calls back into them for the
    // life of the VM; leak deliberately, exactly like the display backend.
    let desc_raw = Box::into_raw(Box::new(desc));
    let queue_raw = Arc::into_raw(Arc::clone(&queue));

    let config = KrunInputConfig {
        features: FEATURE_QUERY,
        create_userdata: desc_raw as *const c_void,
        create: Some(passthrough_create),
        vtable: ConfigVtable {
            destroy: None,
            query_device_name: Some(config_query_device_name),
            query_serial_name: Some(config_query_serial_name),
            query_device_ids: Some(config_query_device_ids),
            query_event_capabilities: Some(config_query_event_capabilities),
            query_abs_info: Some(config_query_abs_info),
            query_properties: Some(config_query_properties),
        },
    };
    let provider = KrunInputEventProvider {
        features: FEATURE_QUEUE,
        create_userdata: queue_raw as *const c_void,
        create: Some(passthrough_create),
        vtable: ProviderVtable {
            destroy: None,
            get_ready_efd: Some(provider_get_ready_efd),
            next_event: Some(provider_next_event),
        },
    };

    // libkrun copies both structs out; only the userdata must outlive this.
    let ret = unsafe {
        add_input_device(
            ctx,
            &config as *const KrunInputConfig as *const c_void,
            std::mem::size_of::<KrunInputConfig>(),
            &provider as *const KrunInputEventProvider as *const c_void,
            std::mem::size_of::<KrunInputEventProvider>(),
        )
    };
    if ret < 0 {
        // Reclaim the leaks so a failed install does not also lose memory.
        unsafe {
            drop(Box::from_raw(desc_raw));
            drop(Arc::from_raw(queue_raw));
        }
        return Err(Error::agent(
            "configure input",
            format!("krun_add_input_device failed (ret={ret})"),
        ));
    }
    Ok(queue)
}

/// Register the keyboard and pointer devices. Must be called before boot.
#[cfg(unix)]
pub fn install(
    add_input_device: unsafe extern "C" fn(u32, *const c_void, usize, *const c_void, usize) -> i32,
    ctx: u32,
) -> Result<VncInput> {
    let keyboard = add_device(
        add_input_device,
        ctx,
        DeviceDesc {
            name: "smolvm vnc keyboard",
            kind: DeviceKind::Keyboard,
        },
    )?;
    let pointer = add_device(
        add_input_device,
        ctx,
        DeviceDesc {
            name: "smolvm vnc pointer",
            kind: DeviceKind::Pointer,
        },
    )?;
    Ok(VncInput { keyboard, pointer })
}

// ---------------------------------------------------------------------------
// X11 keysym -> Linux evdev keycode
// ---------------------------------------------------------------------------

/// RFB carries X11 keysyms. Clients send the *shifted* symbol together with
/// real Shift key events, so shifted symbols map to the same physical key as
/// their unshifted partner (US layout) and the guest's own Shift state does
/// the rest. Returns None for keysyms with no mapping, which are dropped.
pub fn keysym_to_evdev(keysym: u32) -> Option<u16> {
    Some(match keysym {
        // Letters: keysyms mirror ASCII; upper and lower map to the same key.
        0x61..=0x7a | 0x41..=0x5a => {
            const LETTERS: [u16; 26] = [
                30, 48, 46, 32, 18, 33, 34, 35, 23, 36, 37, 38, 50, // a-m
                49, 24, 25, 16, 19, 31, 20, 22, 47, 17, 45, 21, 44, // n-z
            ];
            let idx = if keysym >= 0x61 {
                keysym - 0x61
            } else {
                keysym - 0x41
            };
            LETTERS[idx as usize]
        }
        // Digit row, with each key's shifted symbol.
        0x31 => 2,
        0x21 => 2, // 1 !
        0x32 => 3,
        0x40 => 3, // 2 @
        0x33 => 4,
        0x23 => 4, // 3 #
        0x34 => 5,
        0x24 => 5, // 4 $
        0x35 => 6,
        0x25 => 6, // 5 %
        0x36 => 7,
        0x5e => 7, // 6 ^
        0x37 => 8,
        0x26 => 8, // 7 &
        0x38 => 9,
        0x2a => 9, // 8 *
        0x39 => 10,
        0x28 => 10, // 9 (
        0x30 => 11,
        0x29 => 11, // 0 )
        // Punctuation row keys.
        0x2d => 12,
        0x5f => 12, // - _
        0x3d => 13,
        0x2b => 13, // = +
        0x5b => 26,
        0x7b => 26, // [ {
        0x5d => 27,
        0x7d => 27, // ] }
        0x3b => 39,
        0x3a => 39, // ; :
        0x27 => 40,
        0x22 => 40, // ' "
        0x60 => 41,
        0x7e => 41, // ` ~
        0x5c => 43,
        0x7c => 43, // \ |
        0x2c => 51,
        0x3c => 51, // , <
        0x2e => 52,
        0x3e => 52, // . >
        0x2f => 53,
        0x3f => 53, // / ?
        0x20 => 57, // space
        // Controls and navigation.
        0xff08 => 14,  // BackSpace
        0xff09 => 15,  // Tab
        0xfe20 => 15,  // ISO_Left_Tab (Shift+Tab)
        0xff0d => 28,  // Return
        0xff8d => 96,  // KP_Enter
        0xff1b => 1,   // Escape
        0xff63 => 110, // Insert
        0xffff => 111, // Delete
        0xff50 => 102, // Home
        0xff51 => 105, // Left
        0xff52 => 103, // Up
        0xff53 => 106, // Right
        0xff54 => 108, // Down
        0xff55 => 104, // PageUp
        0xff56 => 109, // PageDown
        0xff57 => 107, // End
        0xff67 => 127, // Menu
        // Function keys.
        0xffbe => 59,
        0xffbf => 60,
        0xffc0 => 61,
        0xffc1 => 62, // F1-F4
        0xffc2 => 63,
        0xffc3 => 64,
        0xffc4 => 65,
        0xffc5 => 66, // F5-F8
        0xffc6 => 67,
        0xffc7 => 68,
        0xffc8 => 87,
        0xffc9 => 88, // F9-F12
        // Modifiers.
        0xffe1 => 42,  // Shift_L
        0xffe2 => 54,  // Shift_R
        0xffe3 => 29,  // Control_L
        0xffe4 => 97,  // Control_R
        0xffe5 => 58,  // Caps_Lock
        0xffe9 => 56,  // Alt_L
        0xffea => 100, // Alt_R
        0xffeb => 125, // Super_L
        0xffec => 126, // Super_R
        _ => return None,
    })
}

/// Windows builds have no POSIX pipe for the event provider (and the krun
/// dll ships without the input feature), so the session stays view-only.
#[cfg(not(unix))]
pub fn install(
    _add_input_device: unsafe extern "C" fn(u32, *const c_void, usize, *const c_void, usize) -> i32,
    _ctx: u32,
) -> Result<VncInput> {
    Err(Error::agent(
        "configure input",
        "virtio-input requires a unix host",
    ))
}
