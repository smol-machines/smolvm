//! Drop-in `libcuda.so.1` for smolvm guests: the CUDA Driver API C ABI,
//! implemented by marshaling every call over smolvm's CUDA RPC to the host.
//!
//! Install this library at `/usr/lib/libcuda.so.1` inside a guest (or point
//! `LD_LIBRARY_PATH` at it) and unmodified Driver-API programs — including the
//! CUDA runtime's dlopen of the driver — run their GPU work on the host GPU
//! with no code changes.
//!
//! Transport is chosen by `SMOLVM_CUDA_RPC`:
//!   * unset / `vsock` — AF_VSOCK to host CID 2, port 7000 (production, in-guest)
//!   * `tcp:HOST:PORT` — TCP (host-side testing against a loopback server)
//!   * `unix:/path`    — AF_UNIX (host-side testing against the real cuda.sock)
//!
//! Semantics notes:
//!   * Handles returned to the app (contexts, modules, functions, streams,
//!     events) are the server's opaque ids cast to pointers — never host
//!     addresses.
//!   * Everything executes synchronously on the host; the `*Async` entry points
//!     complete before returning, which the CUDA API permits (an implementation
//!     may be more synchronous than requested). Stream/event query entry points
//!     therefore always report "complete".
//!   * The context-current APIs are process-global, not per-thread. Programs
//!     that juggle distinct contexts on different threads concurrently are out
//!     of scope for this shim.
//!   * `cuLaunchKernel` serializes `kernelParams` using per-parameter sizes the
//!     host extracts from the loaded module (`cuFuncGetParamInfo`, CUDA 12.4+).

// These are C ABI entry points: the caller is C code holding the CUDA Driver
// API contract (valid pointers or NULL, checked where the API allows NULL).
// Marking them `unsafe fn` would not change what C callers can do.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use smolvm_cuda::client::{Client, CudaRpcError};
mod driver_stubs;
mod integrity;
use std::collections::HashMap;
use std::ffi::{c_char, c_int, c_uint, c_void, CStr, CString};
use std::io::{Read, Write};
use std::sync::Mutex;

// ---- CUresult codes the shim produces locally -------------------------------

const CUDA_SUCCESS: c_int = 0;
const CUDA_ERROR_INVALID_VALUE: c_int = 1;
const CUDA_ERROR_OUT_OF_MEMORY: c_int = 2;
const CUDA_ERROR_NOT_INITIALIZED: c_int = 3;
const CUDA_ERROR_NO_DEVICE: c_int = 100;
const CUDA_ERROR_INVALID_IMAGE: c_int = 200;
const CUDA_ERROR_INVALID_CONTEXT: c_int = 201;
const CUDA_ERROR_NOT_FOUND: c_int = 500;
const CUDA_ERROR_NOT_SUPPORTED: c_int = 801;
const CUDA_ERROR_UNKNOWN: c_int = 999;

#[repr(C)]
pub struct CUmemLocation {
    type_: c_int,
    id: c_int,
}

/// CUDA keeps this ABI at 88 bytes; newer toolkits consume fields that were
/// reserved in older versions without changing the public layout.
#[repr(C)]
pub struct CUmemPoolProps {
    alloc_type: c_int,
    handle_types: c_uint,
    location: CUmemLocation,
    win32_security_attributes: *mut c_void,
    max_size: usize,
    usage: u16,
    reserved: [u8; 54],
}

#[repr(C)]
pub struct CUmemAccessDesc {
    location: CUmemLocation,
    flags: c_int,
}

/// The CUDA version this shim reports for its own API surface.
/// CUDA version the driver shim ADVERTISES. Must not overpromise: a real cu12
/// cuBLASLt that hears "13020" requests 13.x entry points through
/// cuGetProcAddress that this shim only partially provides, and fails
/// CUBLAS_STATUS_NOT_INITIALIZED at its first matmul (broke every cu124-wheel
/// guest). Default to the fully-implemented 12.4 surface; a cu130-wheel guest
/// opts into the newer advertisement with SMOLVM_CUDA_ADVERTISE=13020.
fn shim_cuda_version() -> c_int {
    static V: std::sync::OnceLock<c_int> = std::sync::OnceLock::new();
    *V.get_or_init(|| {
        std::env::var("SMOLVM_CUDA_ADVERTISE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(12040)
    })
}

// ---- transport ---------------------------------------------------------------

/// One concrete byte stream to the host CUDA server. `Bridged` owns no
/// socket: the client routes through the runtime shim's connection instead
/// and never touches its stream.
enum Stream {
    #[cfg(target_os = "linux")]
    Vsock(vsock::VsockStream),
    Tcp(std::net::TcpStream),
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixStream),
    Bridged,
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            #[cfg(target_os = "linux")]
            Stream::Vsock(s) => s.read(buf),
            Stream::Tcp(s) => s.read(buf),
            #[cfg(unix)]
            Stream::Unix(s) => s.read(buf),
            Stream::Bridged => Err(std::io::Error::other("bridged client has no stream")),
        }
    }
}
impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            #[cfg(target_os = "linux")]
            Stream::Vsock(s) => s.write(buf),
            Stream::Tcp(s) => s.write(buf),
            #[cfg(unix)]
            Stream::Unix(s) => s.write(buf),
            Stream::Bridged => Err(std::io::Error::other("bridged client has no stream")),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            #[cfg(target_os = "linux")]
            Stream::Vsock(s) => s.flush(),
            Stream::Tcp(s) => s.flush(),
            #[cfg(unix)]
            Stream::Unix(s) => s.flush(),
            Stream::Bridged => Ok(()),
        }
    }
}

#[cfg(unix)]
impl Stream {
    /// Raw socket fd for the liveness peek; -1 when bridged (no own socket).
    fn raw_fd(&self) -> std::os::unix::io::RawFd {
        use std::os::unix::io::AsRawFd;
        match self {
            #[cfg(target_os = "linux")]
            Stream::Vsock(s) => s.as_raw_fd(),
            Stream::Tcp(s) => s.as_raw_fd(),
            Stream::Unix(s) => s.as_raw_fd(),
            Stream::Bridged => -1,
        }
    }
}

/// Non-blocking, non-consuming liveness peek on the host connection. A VM-fork
/// clone (same pid, so a pid check can't fire) inherits a socket whose host peer
/// is gone; the guest kernel resets it and the peek sees EOF, telling us to
/// reconnect. `true` = usable (data pending or none yet), `false` = closed/error.
#[cfg(unix)]
fn conn_alive(fd: std::os::unix::io::RawFd) -> bool {
    if fd < 0 {
        return true; // bridged: liveness is the runtime shim's concern
    }
    let mut b = [0u8; 1];
    let n = unsafe {
        libc::recv(
            fd,
            b.as_mut_ptr() as *mut libc::c_void,
            1,
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    if n > 0 {
        true
    } else if n == 0 {
        false
    } else {
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        e == libc::EAGAIN || e == libc::EWOULDBLOCK
    }
}

fn connect() -> Result<Stream, c_int> {
    let spec = std::env::var("SMOLVM_CUDA_RPC").unwrap_or_default();
    if let Some(addr) = spec.strip_prefix("tcp:") {
        return std::net::TcpStream::connect(addr)
            .map(|s| {
                let _ = s.set_nodelay(true); // low-latency request/response
                Stream::Tcp(s)
            })
            .map_err(|_| CUDA_ERROR_NO_DEVICE);
    }
    #[cfg(unix)]
    if let Some(path) = spec.strip_prefix("unix:") {
        return std::os::unix::net::UnixStream::connect(path)
            .map(Stream::Unix)
            .map_err(|_| CUDA_ERROR_NO_DEVICE);
    }
    #[cfg(target_os = "linux")]
    {
        // smolvm's reserved CUDA port on the host CID (smolvm_protocol::ports::CUDA).
        const HOST_CID: u32 = 2;
        const CUDA_PORT: u32 = 7000;
        vsock::VsockStream::connect_with_cid_port(HOST_CID, CUDA_PORT)
            .map(Stream::Vsock)
            .map_err(|_| CUDA_ERROR_NO_DEVICE)
    }
    #[cfg(not(target_os = "linux"))]
    Err(CUDA_ERROR_NO_DEVICE)
}

// ---- global state -------------------------------------------------------------

struct ShimState {
    client: Client<Stream>,
    /// Kernel-argument byte sizes per function handle, fetched once per function.
    param_sizes: HashMap<u64, Vec<u32>>,
    /// Primary-context handle per device (retain is refcounted host-side; the
    /// app-visible handle stays stable per device as the real driver's does).
    primary_ctx: HashMap<i32, u64>,
    /// Process-global "current context" stack (bottom = cuCtxSetCurrent slot).
    ctx_stack: Vec<u64>,
    /// Fork-reconnect bookkeeping for a standalone (non-bridged) connection:
    /// pid that opened it, its socket fd (liveness peek), and the host-assigned
    /// lineage token to resume. Bridged connections leave these inert (fd -1).
    conn_pid: i32,
    conn_fd: i32,
    conn_token: u64,
}

static STATE: Mutex<Option<ShimState>> = Mutex::new(None);

/// Establish the server connection + primary context if not already done.
/// Idempotent. Called from `cuInit` and lazily from any driver call — the real
/// driver treats `cuInit` as process-global, but this shim is a separate library
/// (and separate connection) from our `libcudart` shim, so a consumer that only
/// initialized CUDA through the runtime API never called *our* `cuInit`. Lazily
/// connecting on first use makes any driver entry point self-initializing.
fn ensure_connected(guard: &mut Option<ShimState>) -> Result<(), c_int> {
    if let Some(st) = guard.as_mut() {
        // A standalone connection can be severed under us by a VM-fork clone
        // (pid is preserved across the snapshot, so the peek is what catches
        // it). Bridged connections ride the runtime shim, which reconnects
        // itself. Rebuild in place, resuming the lineage token; the registries
        // (param sizes, primary-context + stack — all raw handles valid in the
        // shared primary context) survive.
        let bridged = BRIDGED.load(std::sync::atomic::Ordering::Relaxed);
        let pid = std::process::id() as i32;
        #[cfg(unix)]
        let severed = !bridged && !conn_alive(st.conn_fd);
        #[cfg(not(unix))]
        let severed = false;
        if !bridged && (st.conn_pid != pid || severed) {
            let (mut client, token, fd) = connect_standalone(st.conn_token)?;
            // Restore a current context on the fresh host session. The host binds
            // the primary context on retain (its `cuCtxSetCurrent` is local), so
            // without this a driver-API alloc/launch on the reconnected session
            // faults with INVALID_CONTEXT. The app's own handle stays valid in
            // the shared daemon context; we only need the host thread bound.
            if !st.primary_ctx.is_empty() {
                let _ = client.primary_ctx_retain(0);
            }
            st.client = client;
            st.conn_token = token;
            st.conn_fd = fd;
            st.conn_pid = pid;
        }
        return Ok(());
    }
    // Preferred: ride the runtime shim's connection (both shims loaded, one
    // program-ordered pipeline, full deferral). Fallback: own connection —
    // then this traffic shares one guest program-order stream with the
    // runtime shim's connection, and two independently flushed deferred
    // queues would let the host execute work out of order (recorded misorder
    // in a CUDA graph replays wrong), so run every op sync and fence the
    // runtime connection before each one (see fence_runtime).
    let (client, token, fd) = match resolve_bridge() {
        Some(bridge) => {
            let mut client = Client::new_bridged(Stream::Bridged, bridge);
            let token = client.init(0).map_err(init_err)?;
            (client, token, -1)
        }
        None => connect_standalone(0)?,
    };
    BRIDGED.store(client.is_bridged(), std::sync::atomic::Ordering::Relaxed);
    *guard = Some(ShimState {
        client,
        param_sizes: HashMap::new(),
        primary_ctx: HashMap::new(),
        ctx_stack: Vec::new(),
        conn_pid: std::process::id() as i32,
        conn_fd: fd,
        conn_token: token,
    });
    Ok(())
}

/// Open a standalone (non-bridged) connection to the host, run the handshake
/// resuming `resume_token`, and return the client, its assigned token, and its
/// socket fd. Deferral is off — a standalone driver connection must stay
/// program-ordered against the runtime shim's separate connection.
fn connect_standalone(resume_token: u64) -> Result<(Client<Stream>, u64, i32), c_int> {
    let stream = connect()?;
    #[cfg(unix)]
    let fd = stream.raw_fd();
    #[cfg(not(unix))]
    let fd = -1;
    let mut client = Client::new(stream);
    client.set_defer_enabled(false);
    let token = client.init(resume_token).map_err(init_err)?;
    // Per-machine GPU pin (see the runtime shim's bring_up_client).
    if let Some(d) = std::env::var("SMOLVM_CUDA_DEVICE")
        .ok()
        .and_then(|v| v.parse::<i32>().ok())
    {
        let _ = client.set_device_base(d);
    }
    Ok((client, token, fd))
}

fn init_err(e: CudaRpcError) -> c_int {
    match e {
        CudaRpcError::Cuda(code) => code as c_int,
        _ => CUDA_ERROR_NO_DEVICE,
    }
}

/// Set once at connect: this shim's client rides the runtime shim's
/// connection, so the per-op runtime fence is unnecessary.
static BRIDGED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The runtime shim's bridge exports, if it's loaded in this process.
/// All three must resolve or none are used. `SMOLVM_CUDA_BRIDGE=0` forces the
/// standalone fallback (kill-switch, mirrors `SMOLVM_CUDA_ASYNC=0`).
fn resolve_bridge() -> Option<smolvm_cuda::client::Bridge> {
    if std::env::var("SMOLVM_CUDA_BRIDGE").as_deref() == Ok("0") {
        return None;
    }
    extern "C" {
        fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    }
    // glibc: RTLD_DEFAULT == NULL (this shim is glibc-only).
    unsafe {
        let quiet = dlsym(std::ptr::null_mut(), c"smolvm_cudart_bridge_quiet".as_ptr());
        let call = dlsym(std::ptr::null_mut(), c"smolvm_cudart_bridge_call".as_ptr());
        let drain = dlsym(std::ptr::null_mut(), c"smolvm_cudart_bridge_drain".as_ptr());
        if quiet.is_null() || call.is_null() || drain.is_null() {
            return None;
        }
        Some(smolvm_cuda::client::Bridge {
            quiet: std::mem::transmute::<*mut c_void, unsafe extern "C" fn(*const u8, usize) -> i32>(
                quiet,
            ),
            call: std::mem::transmute::<
                *mut c_void,
                unsafe extern "C" fn(*const u8, usize, *mut u8, usize) -> isize,
            >(call),
            drain: std::mem::transmute::<*mut c_void, unsafe extern "C" fn() -> i32>(drain),
        })
    }
}

/// Run `f` against the connected client, translating errors to `CUresult`.
/// Auto-connects on first use (see [`ensure_connected`]).
/// Settle the runtime shim's deferred pipeline before running one of our ops,
/// so guest program order holds across the two connections. The hook is
/// exported by the runtime shim (`smolvm_cudart_fence` in libcudart); resolved
/// lazily because either shim can load first. dlsym cost is paid only until
/// the symbol appears (a process without the runtime shim keeps probing, but
/// such a process has no cross-connection ordering to preserve anyway).
fn fence_runtime() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    extern "C" {
        fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    }
    // glibc: RTLD_DEFAULT == NULL (this shim is glibc-only).
    static HOOK: AtomicUsize = AtomicUsize::new(0);
    let mut p = HOOK.load(Ordering::Relaxed);
    if p == 0 {
        p = unsafe { dlsym(std::ptr::null_mut(), c"smolvm_cudart_fence".as_ptr()) } as usize;
        if p != 0 {
            HOOK.store(p, Ordering::Relaxed);
        }
    }
    if p != 0 {
        let f: extern "C" fn() = unsafe { std::mem::transmute::<usize, extern "C" fn()>(p) };
        f();
    }
}

fn with_state<T>(f: impl FnOnce(&mut ShimState) -> Result<T, CudaRpcError>) -> Result<T, c_int> {
    // Bridged: program order is inherent (one pipeline), no fence needed.
    if !BRIDGED.load(std::sync::atomic::Ordering::Relaxed) {
        fence_runtime();
    }
    let mut guard = match STATE.lock() {
        Ok(g) => g,
        Err(_) => return Err(CUDA_ERROR_UNKNOWN),
    };
    ensure_connected(&mut guard)?;
    let state = guard.as_mut().expect("connected");
    f(state).map_err(|e| match e {
        CudaRpcError::Cuda(code) => code as c_int,
        CudaRpcError::Io(_) | CudaRpcError::Protocol(_) => CUDA_ERROR_UNKNOWN,
    })
}

/// Fold a `Result<CUresult-able>` into the C return convention.
fn ret(r: Result<(), c_int>) -> c_int {
    match r {
        Ok(()) => CUDA_SUCCESS,
        Err(code) => code,
    }
}

/// Write `v` through an out-pointer, guarding NULL.
unsafe fn out<T>(p: *mut T, v: T) -> Result<(), c_int> {
    if p.is_null() {
        return Err(CUDA_ERROR_INVALID_VALUE);
    }
    unsafe { p.write(v) };
    Ok(())
}

// ---- init / device ------------------------------------------------------------

#[no_mangle]
pub extern "C" fn cuInit(_flags: c_uint) -> c_int {
    let mut guard = match STATE.lock() {
        Ok(g) => g,
        Err(_) => return CUDA_ERROR_UNKNOWN,
    };
    ret(ensure_connected(&mut guard))
}

/// CUDA's statically linked runtime uses this process-local table to retain the
/// primary context and register embedded fatbins. Dynamic `libcudart` is
/// normally replaced by smolvm's runtime shim, but libraries that embed cudart
/// (collective runtimes are a common example) cannot be interposed that way.
/// Keep the private table deliberately small and implement its operations in
/// terms of the public driver entry points already forwarded by this shim.
const CUDART_INTERFACE_UUID: [u8; 16] = [
    0x6b, 0xd5, 0xfb, 0x6c, 0x5b, 0xf4, 0xe7, 0x4a, 0x89, 0x87, 0xd9, 0x39, 0x12, 0xfd, 0x9d, 0xf9,
];

// This probe UUID asks whether the driver can bypass normal cudart bootstrap.
// Success skips the CUDART_INTERFACE path, so an implementation that does not
// provide the bypass table must report NOT_FOUND rather than NOT_SUPPORTED.
const CUDART_SKIP_INIT_UUID: [u8; 16] = [
    0xf8, 0xcf, 0xf9, 0x51, 0x21, 0x46, 0x8b, 0x4e, 0xb9, 0xe2, 0xfb, 0x46, 0x9e, 0x7c, 0x0d, 0xd9,
];

const TOOLS_RUNTIME_CALLBACK_HOOKS_UUID: [u8; 16] = [
    0xa0, 0x94, 0x79, 0x8c, 0x2e, 0x74, 0x2e, 0x74, 0x93, 0xf2, 0x08, 0x00, 0x20, 0x0c, 0x0a, 0x66,
];

const TOOLS_TLS_UUID: [u8; 16] = [
    0x42, 0xd8, 0x5a, 0x81, 0x23, 0xf6, 0xcb, 0x47, 0x82, 0x98, 0xf6, 0xe7, 0x8a, 0x3a, 0xec, 0xdc,
];

const CONTEXT_LOCAL_STORAGE_UUID: [u8; 16] = [
    0xc6, 0x93, 0x33, 0x6e, 0x11, 0x21, 0xdf, 0x11, 0xa8, 0xc3, 0x68, 0xf3, 0x55, 0xd8, 0x95, 0x93,
];

const CONTEXT_CHECKS_UUID: [u8; 16] = [
    0x26, 0x3e, 0x88, 0x60, 0x7c, 0xd2, 0x61, 0x43, 0x92, 0xf6, 0xbb, 0xd5, 0x00, 0x6d, 0xfa, 0x7e,
];

const INTEGRITY_CHECK_UUID: [u8; 16] = [
    0xd4, 0x08, 0x20, 0x55, 0xbd, 0xe6, 0x70, 0x4b, 0x8d, 0x34, 0xba, 0x12, 0x3c, 0x66, 0xe1, 0xf2,
];

#[repr(C)]
struct FatbincWrapper {
    magic: c_uint,
    _version: c_uint,
    data: *const c_void,
    _filename_or_fatbins: *const c_void,
}

fn trace_private_call(name: &str, status: c_int) -> c_int {
    if std::env::var_os("SMOLVM_CUDA_SHIM_TRACE").is_some() {
        eprintln!("[shim] private driver call: {name} -> {status}");
    }
    status
}

extern "C" fn cudart_get_module_from_cubin(
    module: *mut *mut c_void,
    wrapper: *const FatbincWrapper,
) -> c_int {
    if module.is_null() || wrapper.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    let wrapper = unsafe { &*wrapper };
    if wrapper.magic != 0x4662_43b1 || wrapper.data.is_null() {
        return 200; // CUDA_ERROR_INVALID_IMAGE
    }
    trace_private_call(
        "CUDART_INTERFACE.get_module_from_cubin",
        cuModuleLoadData(module, wrapper.data),
    )
}

extern "C" fn cudart_primary_context(pctx: *mut *mut c_void, device: c_int) -> c_int {
    trace_private_call(
        "CUDART_INTERFACE.primary_context",
        cuDevicePrimaryCtxRetain(pctx, device),
    )
}

extern "C" fn cudart_get_module_from_cubin_ext1(
    module: *mut *mut c_void,
    wrapper: *const FatbincWrapper,
    _arg3: *mut c_void,
    _arg4: *mut c_void,
    _arg5: c_uint,
) -> c_int {
    cudart_get_module_from_cubin(module, wrapper)
}

extern "C" fn cudart_interface_fn7(_arg: usize) {}

extern "C" fn cudart_get_module_from_cubin_ext2(
    fatbin_header: *const c_void,
    module: *mut *mut c_void,
    _arg3: *mut c_void,
    _arg4: *mut c_void,
    _arg5: c_uint,
) -> c_int {
    if module.is_null() || fatbin_header.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    trace_private_call(
        "CUDART_INTERFACE.get_module_from_cubin_ext2",
        cuModuleLoadData(module, fatbin_header),
    )
}

extern "C" fn cudart_load_compilers() -> c_int {
    trace_private_call("CUDART_INTERFACE.load_compilers", CUDA_SUCCESS)
}

fn cudart_interface_table() -> &'static [usize; 13] {
    static TABLE: std::sync::OnceLock<[usize; 13]> = std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        [
            13 * std::mem::size_of::<usize>(),
            cudart_get_module_from_cubin as *const () as usize,
            cudart_primary_context as *const () as usize,
            0,
            0,
            0,
            cudart_get_module_from_cubin_ext1 as *const () as usize,
            cudart_interface_fn7 as *const () as usize,
            cudart_get_module_from_cubin_ext2 as *const () as usize,
            0,
            0,
            0,
            cudart_load_compilers as *const () as usize,
        ]
    })
}

fn tools_buffer<const N: usize>(slot: &'static std::sync::OnceLock<usize>) -> *mut c_void {
    *slot.get_or_init(|| Box::into_raw(Box::new([0u8; N])) as usize) as *mut c_void
}

extern "C" fn tools_get_buffer1(ptr: *mut *mut c_void, size: *mut usize) {
    static BUFFER: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    if !ptr.is_null() {
        unsafe { *ptr = tools_buffer::<1024>(&BUFFER) };
    }
    if !size.is_null() {
        unsafe { *size = 1024 };
    }
}

extern "C" fn tools_get_buffer2(ptr: *mut *mut c_void, size: *mut usize) {
    static BUFFER: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    if !ptr.is_null() {
        unsafe { *ptr = tools_buffer::<14>(&BUFFER) };
    }
    if !size.is_null() {
        unsafe { *size = 14 };
    }
}

fn tools_runtime_callback_hooks_table() -> &'static [usize; 7] {
    static TABLE: std::sync::OnceLock<[usize; 7]> = std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        [
            7 * std::mem::size_of::<usize>(),
            tools_runtime_callback_event as *const () as usize,
            tools_get_buffer1 as *const () as usize,
            0,
            tools_runtime_callback_span as *const () as usize,
            0,
            tools_get_buffer2 as *const () as usize,
        ]
    })
}

// The static runtime brackets driver lookups with these private tooling hooks.
// No profiler is registered in the guest, so preserving the callbacks as
// no-ops is the correct behavior. They must still be callable: CUDA 12.8 uses
// them on the ordinary "optional symbol not found" path.
extern "C" fn tools_runtime_callback_event(_event: c_uint, _data: *mut c_void) {}

extern "C" fn tools_runtime_callback_span(_context: *mut c_void, _data: *mut c_void) {}

extern "C" fn tools_tls_callback(_record: *mut c_void) {}

fn tools_tls_table() -> &'static [usize; 4] {
    static TABLE: std::sync::OnceLock<[usize; 4]> = std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        [
            4 * std::mem::size_of::<usize>(),
            0,
            tools_tls_callback as *const () as usize,
            0,
        ]
    })
}

fn context_local_storage() -> &'static Mutex<HashMap<(usize, usize), usize>> {
    static STORAGE: std::sync::OnceLock<Mutex<HashMap<(usize, usize), usize>>> =
        std::sync::OnceLock::new();
    STORAGE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn context_handle(context: *mut c_void) -> Result<usize, c_int> {
    if !context.is_null() {
        return Ok(context as usize);
    }
    let mut current = std::ptr::null_mut();
    let result = cuCtxGetCurrent(&mut current);
    if result != CUDA_SUCCESS {
        return Err(result);
    }
    if current.is_null() {
        Err(CUDA_ERROR_INVALID_CONTEXT)
    } else {
        Ok(current as usize)
    }
}

extern "C" fn context_local_storage_put(
    context: *mut c_void,
    key: *mut c_void,
    value: *mut c_void,
    _destructor: *mut c_void,
) -> c_int {
    let context = match context_handle(context) {
        Ok(context) => context,
        Err(error) => return error,
    };
    match context_local_storage().lock() {
        Ok(mut storage) => {
            storage.insert((context, key as usize), value as usize);
            CUDA_SUCCESS
        }
        Err(_) => CUDA_ERROR_UNKNOWN,
    }
}

extern "C" fn context_local_storage_delete(context: *mut c_void, key: *mut c_void) -> c_int {
    let context = match context_handle(context) {
        Ok(context) => context,
        Err(error) => return error,
    };
    match context_local_storage().lock() {
        Ok(mut storage) => {
            storage.remove(&(context, key as usize));
            CUDA_SUCCESS
        }
        Err(_) => CUDA_ERROR_UNKNOWN,
    }
}

extern "C" fn context_local_storage_get(
    value: *mut *mut c_void,
    context: *mut c_void,
    key: *mut c_void,
) -> c_int {
    if value.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    let context = match context_handle(context) {
        Ok(context) => context,
        Err(error) => return error,
    };
    match context_local_storage().lock() {
        Ok(storage) => match storage.get(&(context, key as usize)) {
            Some(&stored) => {
                unsafe { *value = stored as *mut c_void };
                CUDA_SUCCESS
            }
            None => {
                unsafe { *value = std::ptr::null_mut() };
                CUDA_ERROR_NOT_FOUND
            }
        },
        Err(_) => CUDA_ERROR_UNKNOWN,
    }
}

fn context_local_storage_table() -> &'static [usize; 4] {
    static TABLE: std::sync::OnceLock<[usize; 4]> = std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        [
            context_local_storage_put as *const () as usize,
            context_local_storage_delete as *const () as usize,
            context_local_storage_get as *const () as usize,
            0,
        ]
    })
}

extern "C" fn context_check(
    _context: *mut c_void,
    result: *mut c_uint,
    _detail: *mut *const c_void,
) -> c_int {
    if !result.is_null() {
        unsafe { *result = 0 };
    }
    CUDA_SUCCESS
}

extern "C" fn context_check_flags() -> c_uint {
    0
}

fn context_checks_table() -> &'static [usize; 4] {
    static TABLE: std::sync::OnceLock<[usize; 4]> = std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        [
            4 * std::mem::size_of::<usize>(),
            0,
            context_check as *const () as usize,
            context_check_flags as *const () as usize,
        ]
    })
}

extern "C" fn integrity_check(version: c_uint, unix_seconds: u64, result: *mut [u64; 2]) -> c_int {
    if result.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    let mut count = 0;
    let status = cuDeviceGetCount(&mut count);
    if status != CUDA_SUCCESS {
        return status;
    }
    let mut devices = Vec::with_capacity(count.max(0) as usize);
    for device in 0..count {
        let mut uuid = [0u8; 16];
        let status = cuDeviceGetUuid(uuid.as_mut_ptr(), device);
        if status != CUDA_SUCCESS {
            return status;
        }
        let attribute = |id| {
            let mut value = 0;
            let status = cuDeviceGetAttribute(&mut value, id, device);
            if status == CUDA_SUCCESS {
                Ok(value)
            } else {
                Err(status)
            }
        };
        let pci_domain = match attribute(50) {
            Ok(value) => value,
            Err(status) => return status,
        };
        let pci_bus = match attribute(33) {
            Ok(value) => value,
            Err(status) => return status,
        };
        let pci_device = match attribute(34) {
            Ok(value) => value,
            Err(status) => return status,
        };
        devices.push(integrity::DeviceHashInfo {
            uuid,
            pci_domain,
            pci_bus,
            pci_device,
        });
    }
    #[cfg(unix)]
    let thread = unsafe { libc::pthread_self() as usize as u32 };
    #[cfg(windows)]
    let thread = unsafe {
        unsafe extern "system" {
            fn GetCurrentThreadId() -> u32;
        }
        GetCurrentThreadId()
    };
    let response = integrity::compute(integrity::Inputs {
        version,
        unix_seconds,
        driver_version: shim_cuda_version() as u32,
        process: std::process::id(),
        thread,
        integrity_check_table: integrity_check_table().as_ptr() as usize,
        cudart_table: cudart_interface_table().as_ptr() as usize,
        function_address: integrity_check as *const () as usize,
        devices: &devices,
    });
    unsafe { *result = response };
    CUDA_SUCCESS
}

fn integrity_check_table() -> &'static [usize; 3] {
    static TABLE: std::sync::OnceLock<[usize; 3]> = std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        [
            3 * std::mem::size_of::<usize>(),
            integrity_check as *const () as usize,
            0,
        ]
    })
}

#[no_mangle]
pub extern "C" fn cuGetExportTable(table: *mut *const c_void, uuid: *const c_void) -> c_int {
    if table.is_null() || uuid.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    let b = unsafe { std::slice::from_raw_parts(uuid as *const u8, 16) };
    let (result, label) = if b == CUDART_INTERFACE_UUID {
        unsafe { *table = cudart_interface_table().as_ptr().cast() };
        (CUDA_SUCCESS, "CUDART_INTERFACE")
    } else if b == TOOLS_RUNTIME_CALLBACK_HOOKS_UUID {
        unsafe { *table = tools_runtime_callback_hooks_table().as_ptr().cast() };
        (CUDA_SUCCESS, "TOOLS_RUNTIME_CALLBACK_HOOKS")
    } else if b == TOOLS_TLS_UUID {
        unsafe { *table = tools_tls_table().as_ptr().cast() };
        (CUDA_SUCCESS, "TOOLS_TLS")
    } else if b == CONTEXT_LOCAL_STORAGE_UUID {
        unsafe { *table = context_local_storage_table().as_ptr().cast() };
        (CUDA_SUCCESS, "CONTEXT_LOCAL_STORAGE")
    } else if b == CONTEXT_CHECKS_UUID {
        unsafe { *table = context_checks_table().as_ptr().cast() };
        (CUDA_SUCCESS, "CONTEXT_CHECKS")
    } else if b == INTEGRITY_CHECK_UUID {
        unsafe { *table = integrity_check_table().as_ptr().cast() };
        (CUDA_SUCCESS, "INTEGRITY_CHECK")
    } else {
        unsafe { *table = std::ptr::null() };
        let label = if b == CUDART_SKIP_INIT_UUID {
            "SKIP_INIT_NOT_FOUND"
        } else {
            "NOT_FOUND"
        };
        (CUDA_ERROR_NOT_FOUND, label)
    };
    if std::env::var_os("SMOLVM_CUDA_SHIM_TRACE").is_some() {
        let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
        eprintln!("[shim] cuGetExportTable uuid={hex} -> {label}");
    }
    result
}

#[no_mangle]
pub extern "C" fn cuDriverGetVersion(version: *mut c_int) -> c_int {
    // ALWAYS the advertised surface, never the daemon's real driver version.
    // Forwarding post-connect leaked the host's version (e.g. 13000 on a
    // CUDA-13 box) to guest libraries that then negotiate cu13 entry points
    // this shim only partially provides — cuBLASLt degraded into loading
    // kernels the driver rejects (209 NO_BINARY_FOR_GPU on sm90).
    ret(unsafe { out(version, shim_cuda_version()) })
}

#[no_mangle]
pub extern "C" fn cuDeviceGetCount(count: *mut c_int) -> c_int {
    ret(with_state(|s| s.client.device_get_count()).and_then(|v| unsafe { out(count, v) }))
}

#[no_mangle]
pub extern "C" fn cuDeviceGet(device: *mut c_int, ordinal: c_int) -> c_int {
    // CUdevice is the ordinal itself in this ABI.
    match with_state(|s| s.client.device_get_count()) {
        Ok(n) if ordinal >= 0 && ordinal < n => ret(unsafe { out(device, ordinal) }),
        Ok(_) => CUDA_ERROR_INVALID_VALUE,
        Err(code) => code,
    }
}

#[no_mangle]
pub extern "C" fn cuDeviceGetName(name: *mut c_char, len: c_int, device: c_int) -> c_int {
    if name.is_null() || len <= 0 {
        return CUDA_ERROR_INVALID_VALUE;
    }
    match with_state(|s| s.client.device_get_name(device)) {
        Ok(n) => {
            let bytes = n.as_bytes();
            let copy = bytes.len().min(len as usize - 1);
            unsafe {
                // `.cast()` rather than `as *mut u8`: c_char is u8 on aarch64
                // Linux, where the `as` form is a no-op cast clippy rejects,
                // but i8 on x86_64 and macOS, where the conversion is real.
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), name.cast::<u8>(), copy);
                *name.add(copy) = 0;
            }
            CUDA_SUCCESS
        }
        Err(code) => code,
    }
}

#[no_mangle]
pub extern "C" fn cuDeviceTotalMem_v2(bytes: *mut usize, device: c_int) -> c_int {
    ret(with_state(|s| s.client.device_total_mem(device))
        .and_then(|v| unsafe { out(bytes, v as usize) }))
}

#[no_mangle]
pub extern "C" fn cuDeviceGetAttribute(pi: *mut c_int, attrib: c_int, device: c_int) -> c_int {
    // Immutable — memoize to spare a host round-trip per repeat.
    static DEV_ATTRS: Mutex<Option<HashMap<(c_int, c_int), c_int>>> = Mutex::new(None);
    if let Ok(mut g) = DEV_ATTRS.lock() {
        if let Some(&v) = g.get_or_insert_with(HashMap::new).get(&(device, attrib)) {
            return ret(unsafe { out(pi, v) });
        }
    }
    ret(
        with_state(|s| s.client.device_get_attribute(attrib, device)).and_then(|v| {
            if let Ok(mut g) = DEV_ATTRS.lock() {
                g.get_or_insert_with(HashMap::new)
                    .insert((device, attrib), v);
            }
            unsafe { out(pi, v) }
        }),
    )
}

/// Deprecated capability query PyTorch still calls at init. Forwards the two
/// compute-capability attributes (MAJOR=75, MINOR=76).
#[no_mangle]
pub extern "C" fn cuDeviceComputeCapability(
    major: *mut c_int,
    minor: *mut c_int,
    device: c_int,
) -> c_int {
    let r = with_state(|s| {
        let maj = s.client.device_get_attribute(75, device)?;
        let min = s.client.device_get_attribute(76, device)?;
        Ok((maj, min))
    });
    ret(r.and_then(|(maj, min)| unsafe {
        out(major, maj)?;
        out(minor, min)
    }))
}

#[no_mangle]
pub extern "C" fn cuDeviceGetUuid(uuid: *mut u8, device: c_int) -> c_int {
    if uuid.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    match with_state(|s| s.client.device_get_uuid(device)) {
        Ok(u) => {
            unsafe { std::ptr::copy_nonoverlapping(u.as_ptr(), uuid, 16) };
            CUDA_SUCCESS
        }
        Err(code) => code,
    }
}

#[no_mangle]
pub extern "C" fn cuDeviceGetUuid_v2(uuid: *mut u8, device: c_int) -> c_int {
    cuDeviceGetUuid(uuid, device)
}

#[no_mangle]
pub extern "C" fn cuDeviceGetPCIBusId(pci_bus_id: *mut c_char, len: c_int, device: c_int) -> c_int {
    if pci_bus_id.is_null() || len <= 0 {
        return CUDA_ERROR_INVALID_VALUE;
    }
    match with_state(|state| state.client.device_get_pci_bus_id(device)) {
        Ok(value) => {
            let bytes = value.as_bytes();
            if bytes.len() >= len as usize {
                return CUDA_ERROR_INVALID_VALUE;
            }
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), pci_bus_id.cast::<u8>(), bytes.len());
                *pci_bus_id.add(bytes.len()) = 0;
            }
            CUDA_SUCCESS
        }
        Err(status) => status,
    }
}

#[no_mangle]
pub extern "C" fn cuDeviceGetByPCIBusId(device: *mut c_int, pci_bus_id: *const c_char) -> c_int {
    if device.is_null() || pci_bus_id.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    let value = match unsafe { CStr::from_ptr(pci_bus_id) }.to_str() {
        Ok(value) => value,
        Err(_) => return CUDA_ERROR_INVALID_VALUE,
    };
    ret(
        with_state(|state| state.client.device_get_by_pci_bus_id(value))
            .and_then(|ordinal| unsafe { out(device, ordinal) }),
    )
}

// ---- contexts -------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn cuCtxCreate_v2(pctx: *mut *mut c_void, _flags: c_uint, device: c_int) -> c_int {
    match with_state(|s| s.client.ctx_create(device)) {
        Ok(h) => {
            let r = ret(unsafe { out(pctx, h as *mut c_void) });
            if r == CUDA_SUCCESS {
                if let Ok(mut g) = STATE.lock() {
                    if let Some(s) = g.as_mut() {
                        // cuCtxCreate makes the new context current (pushes it).
                        s.ctx_stack.push(h);
                    }
                }
            }
            r
        }
        Err(code) => code,
    }
}

#[no_mangle]
pub extern "C" fn cuCtxDestroy_v2(ctx: *mut c_void) -> c_int {
    let h = ctx as u64;
    let r = ret(with_state(|s| s.client.ctx_destroy(h)));
    if r == CUDA_SUCCESS {
        if let Ok(mut g) = STATE.lock() {
            if let Some(s) = g.as_mut() {
                s.ctx_stack.retain(|&c| c != h);
            }
        }
    }
    r
}

#[no_mangle]
pub extern "C" fn cuCtxSetCurrent(ctx: *mut c_void) -> c_int {
    let mut g = match STATE.lock() {
        Ok(g) => g,
        Err(_) => return CUDA_ERROR_UNKNOWN,
    };
    if let Err(e) = ensure_connected(&mut g) {
        return e;
    }
    let s = g.as_mut().expect("connected");
    s.ctx_stack.pop();
    if !ctx.is_null() {
        s.ctx_stack.push(ctx as u64);
    }
    CUDA_SUCCESS
}

#[no_mangle]
pub extern "C" fn cuCtxGetCurrent(pctx: *mut *mut c_void) -> c_int {
    let mut g = match STATE.lock() {
        Ok(g) => g,
        Err(_) => return CUDA_ERROR_UNKNOWN,
    };
    if let Err(e) = ensure_connected(&mut g) {
        return e;
    }
    let s = g.as_ref().expect("connected");
    // Report the explicitly-pushed context if there is one; otherwise fall back
    // to a retained primary context. Real `cudaSetDevice`/runtime init leaves the
    // device's primary context current, so torch/cuBLAS expect a non-null current
    // context here. Returning 0 makes torch lazily retain+bind the primary on
    // first cuBLAS use — harmless in eager (a warning that self-heals) but FATAL
    // during CUDA-graph capture, where context ops aren't allowed and cuBLAS then
    // fails `CUBLAS_STATUS_NOT_INITIALIZED`. Surfacing the primary avoids the lazy
    // bind entirely, which is what lets a graph-capturing engine (vLLM) work.
    let cur = s
        .ctx_stack
        .last()
        .copied()
        .or_else(|| s.primary_ctx.values().next().copied())
        .unwrap_or(0);
    ret(unsafe { out(pctx, cur as *mut c_void) })
}

#[no_mangle]
pub extern "C" fn cuCtxPushCurrent_v2(ctx: *mut c_void) -> c_int {
    if ctx.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    let mut g = match STATE.lock() {
        Ok(g) => g,
        Err(_) => return CUDA_ERROR_UNKNOWN,
    };
    if let Err(e) = ensure_connected(&mut g) {
        return e;
    }
    g.as_mut().expect("connected").ctx_stack.push(ctx as u64);
    CUDA_SUCCESS
}

#[no_mangle]
pub extern "C" fn cuCtxPopCurrent_v2(pctx: *mut *mut c_void) -> c_int {
    let mut g = match STATE.lock() {
        Ok(g) => g,
        Err(_) => return CUDA_ERROR_UNKNOWN,
    };
    if let Err(e) = ensure_connected(&mut g) {
        return e;
    }
    match g.as_mut().expect("connected").ctx_stack.pop() {
        Some(h) => {
            if !pctx.is_null() {
                unsafe { *pctx = h as *mut c_void };
            }
            CUDA_SUCCESS
        }
        None => CUDA_ERROR_INVALID_CONTEXT,
    }
}

#[no_mangle]
pub extern "C" fn cuCtxGetDevice(device: *mut c_int) -> c_int {
    // Single-device model: the current context always belongs to device 0.
    let mut g = match STATE.lock() {
        Ok(g) => g,
        Err(_) => return CUDA_ERROR_UNKNOWN,
    };
    if let Err(e) = ensure_connected(&mut g) {
        return e;
    }
    ret(unsafe { out(device, 0) })
}

#[no_mangle]
pub extern "C" fn cuCtxSynchronize() -> c_int {
    ret(with_state(|s| s.client.ctx_synchronize()))
}

#[no_mangle]
pub extern "C" fn cuDevicePrimaryCtxRetain(pctx: *mut *mut c_void, device: c_int) -> c_int {
    let r = with_state(|s| {
        if let Some(&h) = s.primary_ctx.get(&device) {
            return Ok(h);
        }
        let h = s.client.primary_ctx_retain(device)?;
        s.primary_ctx.insert(device, h);
        Ok(h)
    });
    match r {
        Ok(h) => {
            let rc = ret(unsafe { out(pctx, h as *mut c_void) });
            if rc == CUDA_SUCCESS {
                if let Ok(mut g) = STATE.lock() {
                    if let Some(s) = g.as_mut() {
                        // The host binds the retained primary context current on
                        // its serving thread; mirror that in the guest's
                        // process-global current-context view.
                        s.ctx_stack.push(h);
                    }
                }
            }
            rc
        }
        Err(code) => code,
    }
}

#[no_mangle]
pub extern "C" fn cuDevicePrimaryCtxRelease_v2(device: c_int) -> c_int {
    ret(with_state(|s| s.client.primary_ctx_release(device)))
}

#[no_mangle]
pub extern "C" fn cuDevicePrimaryCtxRelease(device: c_int) -> c_int {
    cuDevicePrimaryCtxRelease_v2(device)
}

#[no_mangle]
pub extern "C" fn cuDevicePrimaryCtxSetFlags_v2(_device: c_int, _flags: c_uint) -> c_int {
    CUDA_SUCCESS // flags are advisory; the host context uses defaults
}

#[no_mangle]
pub extern "C" fn cuDevicePrimaryCtxGetState(
    device: c_int,
    flags: *mut c_uint,
    active: *mut c_int,
) -> c_int {
    let mut g = match STATE.lock() {
        Ok(g) => g,
        Err(_) => return CUDA_ERROR_UNKNOWN,
    };
    if let Err(e) = ensure_connected(&mut g) {
        return e;
    }
    let is_active = g
        .as_ref()
        .expect("connected")
        .primary_ctx
        .contains_key(&device);
    if !flags.is_null() {
        unsafe { *flags = 0 };
    }
    if !active.is_null() {
        unsafe { *active = is_active as c_int };
    }
    CUDA_SUCCESS
}

// ---- modules --------------------------------------------------------------------

/// Byte length of a module image the app handed us as a bare pointer.
///
/// The Driver API infers the length from the image itself; the RPC needs it
/// explicit. PTX is NUL-terminated text; cubins are ELF; nvcc embeddings are
/// fatbin containers with a size field in the header.
unsafe fn module_image_len(image: *const c_void) -> Result<usize, c_int> {
    if image.is_null() {
        return Err(CUDA_ERROR_INVALID_VALUE);
    }
    let p = image as *const u8;
    let magic = unsafe { std::slice::from_raw_parts(p, 4) };
    // Fatbin container: u32 magic, u16 version, u16 headerSize, u64 fatSize.
    // nvcc/cuBLAS emit BACK-TO-BACK containers (per-arch/per-component) and
    // the driver walks them all — summing only the first truncates any SASS
    // living in a later container (observed: cuBLASLt sm90 kernels → the
    // shipped image loads fine on sm80/sm86 but fails 209 NO_BINARY_FOR_GPU
    // on H100). Walk every consecutive container.
    if magic == [0x50, 0xED, 0x55, 0xBA] {
        let chain = std::env::var_os("SMOLVM_CUDA_FATBIN_CHAIN").is_some();
        let mut total = 0usize;
        loop {
            let q = unsafe { p.add(total) };
            let m = unsafe { std::slice::from_raw_parts(q, 4) };
            if m != [0x50, 0xED, 0x55, 0xBA] {
                break;
            }
            let header_size = u16::from_le_bytes(unsafe { *(q.add(6) as *const [u8; 2]) }) as usize;
            let fat_size = u64::from_le_bytes(unsafe { *(q.add(8) as *const [u8; 8]) }) as usize;
            if header_size == 0 || fat_size == 0 {
                break;
            }
            total += header_size + fat_size;
            if !chain {
                break;
            }
            // Chains abutting in .rodata can run away (the walk cannot see
            // module boundaries); cap well above any real per-module chain.
            if total >= 128 * 1024 * 1024 {
                break;
            }
        }
        if total > 0 {
            return Ok(total);
        }
        return Err(CUDA_ERROR_INVALID_VALUE);
    }
    // ELF (cubin): the image ends at whichever header table comes LAST. The ELF
    // spec does not fix their order, and some toolchains (observed: Triton's RL
    // kernels) place the PROGRAM-header table AFTER the section-header table — so
    // the old "sections are last" assumption under-counted the length, the RPC
    // marshalled a truncated image, and cuModuleLoadData read past the short
    // host buffer and SIGSEGV'd. Take the max of both header-table ends.
    if magic == [0x7F, b'E', b'L', b'F'] {
        let e_phoff = u64::from_le_bytes(unsafe { *(p.add(0x20) as *const [u8; 8]) }) as usize;
        let e_phentsize = u16::from_le_bytes(unsafe { *(p.add(0x36) as *const [u8; 2]) }) as usize;
        let e_phnum = u16::from_le_bytes(unsafe { *(p.add(0x38) as *const [u8; 2]) }) as usize;
        let e_shoff = u64::from_le_bytes(unsafe { *(p.add(0x28) as *const [u8; 8]) }) as usize;
        let e_shentsize = u16::from_le_bytes(unsafe { *(p.add(0x3A) as *const [u8; 2]) }) as usize;
        let e_shnum = u16::from_le_bytes(unsafe { *(p.add(0x3C) as *const [u8; 2]) }) as usize;
        // An absent table has offset 0 and count 0, so its computed end is 0.
        let sh_end = e_shoff + e_shentsize * e_shnum;
        let ph_end = e_phoff + e_phentsize * e_phnum;
        return Ok(sh_end.max(ph_end));
    }
    // PTX text: NUL-terminated.
    Ok(unsafe { CStr::from_ptr(image as *const c_char) }
        .to_bytes()
        .len()
        + 1)
}

/// Resolve the private fatbin wrapper that statically linked libcudart passes
/// to the CUDA Library API into the actual module image behind it.
///
/// CUDA 12's static runtime uses `cuLibraryLoadData` with
/// `__fatBinC_Wrapper_t`, rather than passing its embedded fatbin directly.
/// Forwarding the wrapper bytes as PTX truncates them at the first zero byte
/// (six bytes for a version-1 wrapper) and the host driver reports
/// `CUDA_ERROR_INVALID_IMAGE`. Version 1 has one image pointer and is the form
/// emitted by the NCCL 2.27.5 binaries. Version 2 describes a list of images,
/// which cannot be represented by the shim's single module handle yet.
unsafe fn canonical_module_image(image: *const c_void) -> Result<*const c_void, c_int> {
    if image.is_null() {
        return Err(CUDA_ERROR_INVALID_VALUE);
    }
    let magic = unsafe { (image as *const u32).read_unaligned() };
    if magic != 0x4662_43b1 {
        return Ok(image);
    }
    let wrapper = unsafe { &*(image as *const FatbincWrapper) };
    match wrapper._version {
        1 if !wrapper.data.is_null() => Ok(wrapper.data),
        1 => Err(CUDA_ERROR_INVALID_VALUE),
        _ => Err(CUDA_ERROR_NOT_SUPPORTED),
    }
}

#[cfg(test)]
mod module_image_tests {
    use super::*;

    #[test]
    fn unwraps_version_one_fatbin_wrapper() {
        let image = [0x50_u8, 0xed, 0x55, 0xba];
        let wrapper = FatbincWrapper {
            magic: 0x4662_43b1,
            _version: 1,
            data: image.as_ptr().cast(),
            _filename_or_fatbins: std::ptr::null(),
        };

        let resolved =
            unsafe { canonical_module_image((&wrapper as *const FatbincWrapper).cast()) };
        assert_eq!(resolved, Ok(image.as_ptr().cast()));
    }

    #[test]
    fn leaves_direct_module_images_unchanged() {
        let image = [0x7f_u8, b'E', b'L', b'F'];
        let ptr = image.as_ptr().cast();
        assert_eq!(unsafe { canonical_module_image(ptr) }, Ok(ptr));
    }

    #[test]
    fn rejects_multi_image_fatbin_wrapper() {
        let wrapper = FatbincWrapper {
            magic: 0x4662_43b1,
            _version: 2,
            data: std::ptr::null(),
            _filename_or_fatbins: std::ptr::null(),
        };

        assert_eq!(
            unsafe { canonical_module_image((&wrapper as *const FatbincWrapper).cast()) },
            Err(CUDA_ERROR_NOT_SUPPORTED)
        );
    }

    #[test]
    fn parses_version_two_fatbin_list() {
        let first = [0x50_u8, 0xed, 0x55, 0xba];
        let second = [0x50_u8, 0xed, 0x55, 0xba];
        let list = [
            first.as_ptr().cast::<c_void>(),
            second.as_ptr().cast::<c_void>(),
            std::ptr::null(),
        ];
        let wrapper = FatbincWrapper {
            magic: 0x4662_43b1,
            _version: 2,
            data: std::ptr::null(),
            _filename_or_fatbins: list.as_ptr().cast(),
        };

        let images = unsafe { version_two_fatbins(&wrapper) }.unwrap();
        assert_eq!(images, list[..2]);
    }
}

// ---- VMM (torch expandable-segments allocator) --------------------------------
// Prop/desc structs are read at fixed offsets: CUmemAllocationProp.location.id
// sits at byte 12, CUmemAccessDesc.location.id at byte 4.

#[no_mangle]
pub extern "C" fn cuMemAddressReserve(
    ptr: *mut u64,
    size: usize,
    align: usize,
    _addr_hint: u64,
    _flags: u64,
) -> c_int {
    match with_state(|s| s.client.mem_address_reserve(size as u64, align as u64)) {
        Ok(va) => ret(unsafe { out(ptr, va) }),
        Err(code) => code,
    }
}

/// Allocation-burst bookkeeping: fire-and-forget `cuMemCreate` under a
/// guest-minted virtual handle, so allocation-heavy phases (model load: torch's
/// expandable segments create/map/setAccess per 2 MiB granule) pipeline instead
/// of paying a round trip per call. Bounded by a VRAM headroom check so a
/// plausible OOM still surfaces synchronously (torch's allocator frees its
/// cache and retries on cuMemCreate OOM — that contract needs a sync answer
/// when memory is actually tight). `SMOLVM_CUDA_ALLOC_BURST=0` disables.
mod vmm_burst {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    /// vh → size of burst-created allocations (for the headroom counter).
    static SIZES: Mutex<Option<std::collections::HashMap<u64, u64>>> = Mutex::new(None);
    static CREATED: AtomicU64 = AtomicU64::new(0);
    static TOTAL: AtomicU64 = AtomicU64::new(0);
    static NEXT_VH: AtomicU64 = AtomicU64::new(1 << 62); // distinct from lib vhandles

    pub fn enabled() -> bool {
        static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *ON.get_or_init(|| std::env::var("SMOLVM_CUDA_ALLOC_BURST").as_deref() != Ok("0"))
    }
    pub fn set_total(bytes: u64) {
        TOTAL.store(bytes, Ordering::Relaxed);
    }
    /// Quiet-create is allowed while there is comfortable headroom; near the
    /// device limit the caller must fall back to a synchronous create so OOM
    /// surfaces at the right call.
    pub fn headroom_ok(size: u64) -> bool {
        let total = TOTAL.load(Ordering::Relaxed);
        total > 0 && (CREATED.load(Ordering::Relaxed) + size) < total / 100 * 85
    }
    pub fn mint(size: u64) -> u64 {
        let vh = (1 << 63) | NEXT_VH.fetch_add(1, Ordering::Relaxed);
        CREATED.fetch_add(size, Ordering::Relaxed);
        SIZES
            .lock()
            .unwrap()
            .get_or_insert_with(Default::default)
            .insert(vh, size);
        vh
    }
    pub fn released(handle: u64) {
        if let Some(sz) = SIZES
            .lock()
            .unwrap()
            .get_or_insert_with(Default::default)
            .remove(&handle)
        {
            CREATED.fetch_sub(sz, Ordering::Relaxed);
        }
    }
}

#[no_mangle]
pub extern "C" fn cuMemCreate(
    handle: *mut u64,
    size: usize,
    prop: *const c_void,
    _flags: u64,
) -> c_int {
    let device = if prop.is_null() {
        0
    } else {
        unsafe { ((prop as *const u8).add(12) as *const c_int).read_unaligned() }
    };
    if vmm_burst::enabled() {
        // Lazily learn the device capacity for the headroom check.
        if !vmm_burst::headroom_ok(size as u64) {
            if let Ok(total) = with_state(|s| s.client.device_total_mem(device)) {
                vmm_burst::set_total(total);
            }
        }
        if vmm_burst::headroom_ok(size as u64) {
            let vh = vmm_burst::mint(size as u64);
            match with_state(|s| s.client.mem_create_vh(size as u64, device, vh)) {
                Ok(()) => return ret(unsafe { out(handle, vh) }),
                Err(code) => {
                    vmm_burst::released(vh);
                    return code;
                }
            }
        }
    }
    match with_state(|s| s.client.mem_create(size as u64, device)) {
        Ok(h) => ret(unsafe { out(handle, h) }),
        Err(code) => code,
    }
}

#[no_mangle]
pub extern "C" fn cuMemMap(
    ptr: u64,
    size: usize,
    offset: usize,
    handle: u64,
    _flags: u64,
) -> c_int {
    if vmm_burst::enabled() {
        return ret(with_state(|s| {
            s.client
                .mem_map_quiet(ptr, size as u64, offset as u64, handle)
        }));
    }
    ret(with_state(|s| {
        s.client.mem_map(ptr, size as u64, offset as u64, handle)
    }))
}

#[no_mangle]
pub extern "C" fn cuMemSetAccess(
    ptr: u64,
    size: usize,
    desc: *const c_void,
    _count: usize,
) -> c_int {
    let device = if desc.is_null() {
        0
    } else {
        unsafe { ((desc as *const u8).add(4) as *const c_int).read_unaligned() }
    };
    if vmm_burst::enabled() {
        return ret(with_state(|s| {
            s.client.mem_set_access_quiet(ptr, size as u64, device)
        }));
    }
    ret(with_state(|s| {
        s.client.mem_set_access(ptr, size as u64, device)
    }))
}

#[no_mangle]
pub extern "C" fn cuMemUnmap(ptr: u64, size: usize) -> c_int {
    ret(with_state(|s| s.client.mem_unmap(ptr, size as u64)))
}

#[no_mangle]
pub extern "C" fn cuMemRelease(handle: u64) -> c_int {
    vmm_burst::released(handle);
    if vmm_burst::enabled() {
        return ret(with_state(|s| s.client.mem_release_quiet(handle)));
    }
    ret(with_state(|s| s.client.mem_release(handle)))
}

#[no_mangle]
pub extern "C" fn cuMemAddressFree(ptr: u64, size: usize) -> c_int {
    ret(with_state(|s| s.client.mem_address_free(ptr, size as u64)))
}

#[no_mangle]
pub extern "C" fn cuMemGetAllocationGranularity(
    granularity: *mut usize,
    prop: *const c_void,
    flags: c_uint,
) -> c_int {
    let device = if prop.is_null() {
        0
    } else {
        unsafe { ((prop as *const u8).add(12) as *const c_int).read_unaligned() }
    };
    match with_state(|s| s.client.mem_get_allocation_granularity(device, flags)) {
        Ok(g) => ret(unsafe { out(granularity, g as usize) }),
        Err(code) => code,
    }
}

#[no_mangle]
pub extern "C" fn cuModuleLoadData(module: *mut *mut c_void, image: *const c_void) -> c_int {
    let image = match unsafe { canonical_module_image(image) } {
        Ok(image) => image,
        Err(code) => return code,
    };
    let len = match unsafe { module_image_len(image) } {
        Ok(l) => l,
        Err(code) => return code,
    };
    let bytes = unsafe { std::slice::from_raw_parts(image as *const u8, len) };
    match with_state(|s| s.client.module_load_data(bytes)) {
        Ok(h) => ret(unsafe { out(module, h as *mut c_void) }),
        Err(code) => code,
    }
}

#[no_mangle]
pub extern "C" fn cuModuleLoadDataEx(
    module: *mut *mut c_void,
    image: *const c_void,
    _num_options: c_uint,
    _options: *mut c_void,
    _option_values: *mut *mut c_void,
) -> c_int {
    // JIT options are tuning hints; the host driver applies its defaults.
    cuModuleLoadData(module, image)
}

#[no_mangle]
pub extern "C" fn cuModuleLoadFatBinary(module: *mut *mut c_void, fatbin: *const c_void) -> c_int {
    cuModuleLoadData(module, fatbin)
}

#[no_mangle]
pub extern "C" fn cuModuleLoad(module: *mut *mut c_void, fname: *const c_char) -> c_int {
    if fname.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    let path = match unsafe { CStr::from_ptr(fname) }.to_str() {
        Ok(p) => p,
        Err(_) => return CUDA_ERROR_INVALID_VALUE,
    };
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => return CUDA_ERROR_NOT_FOUND,
    };
    match with_state(|s| s.client.module_load_data(&bytes)) {
        Ok(h) => ret(unsafe { out(module, h as *mut c_void) }),
        Err(code) => code,
    }
}

/// Smolvm resolves and loads a module's full image before returning its handle,
/// so its observable loading mode is eager even when the guest requested lazy
/// kernel loading.
#[no_mangle]
pub extern "C" fn cuModuleGetLoadingMode(mode: *mut c_int) -> c_int {
    ret(unsafe { out(mode, 1) }) // CU_MODULE_EAGER_LOADING
}

const CUDA_LIBRARY_BEGIN: u16 = 3;
const CUDA_LIBRARY_ADD_IMAGE: u16 = 4;
const CUDA_LIBRARY_COMPLETE: u16 = 5;
const CUDA_LIBRARY_UNLOAD: u16 = 6;
const CUDA_LIBRARY_GET_KERNEL: u16 = 7;
const CUDA_KERNEL_GET_FUNCTION: u16 = 8;
const CUDA_LIBRARY_GET_MODULE: u16 = 9;
const CUDA_LIBRARY_CANCEL: u16 = 10;
const CUDA_MODULE_GET_GLOBAL: u16 = 11;
const CUDA_HOST_REGISTER_GPA: u16 = 12;
const CUDA_HOST_UNREGISTER_GPA: u16 = 13;

fn native_libraries() -> &'static Mutex<std::collections::HashSet<usize>> {
    static HANDLES: std::sync::OnceLock<Mutex<std::collections::HashSet<usize>>> =
        std::sync::OnceLock::new();
    HANDLES.get_or_init(|| Mutex::new(std::collections::HashSet::new()))
}

fn native_kernels() -> &'static Mutex<std::collections::HashSet<usize>> {
    static HANDLES: std::sync::OnceLock<Mutex<std::collections::HashSet<usize>>> =
        std::sync::OnceLock::new();
    HANDLES.get_or_init(|| Mutex::new(std::collections::HashSet::new()))
}

fn native_functions() -> &'static Mutex<std::collections::HashSet<usize>> {
    static HANDLES: std::sync::OnceLock<Mutex<std::collections::HashSet<usize>>> =
        std::sync::OnceLock::new();
    HANDLES.get_or_init(|| Mutex::new(std::collections::HashSet::new()))
}

/// Static libcudart occasionally applies attributes to optional CUDA host
/// stubs that were not resolved for the active architecture.  In a native
/// process the runtime consumes those addresses locally; forwarding one to a
/// different process makes the host driver dereference a foreign code pointer.
/// A genuine CUfunction returned by this shim is recorded in
/// [`native_functions`], while `dladdr` identifies an unresolved pointer into a
/// guest ELF image without parsing `/proc` or depending on address ranges.
#[cfg(unix)]
fn is_guest_elf_pointer(pointer: *mut c_void) -> bool {
    let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
    unsafe { libc::dladdr(pointer.cast_const(), &mut info) != 0 && !info.dli_fname.is_null() }
}

#[cfg(not(unix))]
fn is_guest_elf_pointer(_pointer: *mut c_void) -> bool {
    false
}

fn is_unresolved_guest_host_stub(function: *mut c_void) -> bool {
    !function.is_null()
        && !native_functions()
            .lock()
            .unwrap()
            .contains(&(function as usize))
        && is_guest_elf_pointer(function)
}

#[cfg(all(test, unix))]
mod guest_elf_pointer_tests {
    use super::*;

    #[test]
    fn distinguishes_loaded_code_from_an_unmapped_handle() {
        assert!(is_guest_elf_pointer(cuInit as *const () as *mut c_void));
        assert!(!is_guest_elf_pointer(std::ptr::dangling_mut::<c_void>()));
    }
}

fn cuda_driver_lib_call(func: u16, args: Vec<u8>) -> Result<Vec<u8>, c_int> {
    match with_state(|s| s.client.lib_call(6, func, args)) {
        Ok((CUDA_SUCCESS, out)) => Ok(out),
        Ok((status, _)) => Err(status),
        Err(status) => Err(status),
    }
}

#[cfg(target_os = "linux")]
mod mapped_host_memory {
    use super::*;
    use std::os::unix::fs::FileExt;

    const PAGE: usize = 4096;
    const HUGE_PAGE: usize = 2 * 1024 * 1024;
    const MAX_ALLOCATION: usize = 256 * 1024 * 1024;

    struct Allocation {
        base: usize,
        len: usize,
        device_pointer: u64,
        flags: c_uint,
    }

    static ALLOCATIONS: Mutex<Vec<Allocation>> = Mutex::new(Vec::new());

    fn allocation_len(bytes: usize) -> Option<usize> {
        bytes
            .checked_add(HUGE_PAGE - 1)
            .map(|n| n & !(HUGE_PAGE - 1))
    }

    fn contiguous_gpa(base: usize, pages: usize) -> Option<u64> {
        let file = std::fs::File::open("/proc/self/pagemap").ok()?;
        let mut entries = vec![0u8; pages.checked_mul(8)?];
        file.read_exact_at(&mut entries, (base / PAGE) as u64 * 8)
            .ok()?;
        let mut first = None;
        for (index, entry) in entries.chunks_exact(8).enumerate() {
            let entry = u64::from_le_bytes(entry.try_into().unwrap());
            if entry & (1 << 63) == 0 {
                return None;
            }
            let pfn = entry & ((1u64 << 55) - 1);
            if pfn == 0 {
                return None;
            }
            let gpa = pfn.checked_mul(PAGE as u64)?;
            match first {
                None => first = Some(gpa),
                Some(start) if gpa == start + index as u64 * PAGE as u64 => {}
                Some(_) => return None,
            }
        }
        first
    }

    fn page_len(bytes: usize) -> Option<usize> {
        bytes.checked_add(PAGE - 1).map(|n| n & !(PAGE - 1))
    }

    fn file_allocation(bytes: usize, flags: c_uint) -> Option<Result<Allocation, c_int>> {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::io::AsRawFd;
        use std::sync::atomic::{AtomicU64, Ordering};

        static NEXT: AtomicU64 = AtomicU64::new(1);
        let len = page_len(bytes)?;
        let name = format!(
            "hostmem-{}-{}.bin",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let path = std::path::Path::new("/opt/smolvm-ring").join(&name);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .ok()?;
        if file.set_len(len as u64).is_err() {
            let _ = std::fs::remove_file(&path);
            return None;
        }
        let pointer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };
        if pointer == libc::MAP_FAILED {
            let _ = std::fs::remove_file(&path);
            return None;
        }
        let mut args = Vec::with_capacity(8 + name.len());
        args.extend_from_slice(&(len as u64).to_le_bytes());
        args.extend_from_slice(name.as_bytes());
        let result = cuda_driver_lib_call(14, args).and_then(|bytes| returned_handle(&bytes));
        // The host has opened and mapped the file before acknowledging the
        // registration, so the directory entry is no longer needed.
        let _ = std::fs::remove_file(&path);
        match result {
            Ok(device_pointer) => Some(Ok(Allocation {
                base: pointer as usize,
                len,
                device_pointer: device_pointer as u64,
                flags,
            })),
            Err(status) => {
                unsafe { libc::munmap(pointer, len) };
                // A runtime without a tmpfs ring or the new host registration
                // path falls back to the physically-contiguous compatibility
                // allocation below.
                if matches!(
                    status,
                    CUDA_ERROR_INVALID_VALUE | CUDA_ERROR_OUT_OF_MEMORY | 801
                ) {
                    None
                } else {
                    Some(Err(status))
                }
            }
        }
    }

    unsafe fn aligned_mapping(len: usize) -> Option<*mut u8> {
        let reserve = len.checked_add(HUGE_PAGE)?;
        let raw = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                reserve,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if raw == libc::MAP_FAILED {
            return None;
        }
        let raw = raw as usize;
        let aligned = raw.checked_add(HUGE_PAGE - 1)? & !(HUGE_PAGE - 1);
        let prefix = aligned - raw;
        let suffix = reserve - prefix - len;
        if prefix != 0 {
            unsafe { libc::munmap(raw as *mut c_void, prefix) };
        }
        if suffix != 0 {
            unsafe { libc::munmap((aligned + len) as *mut c_void, suffix) };
        }
        let pointer = aligned as *mut u8;
        unsafe {
            libc::madvise(pointer.cast(), len, libc::MADV_HUGEPAGE);
            std::ptr::write_bytes(pointer, 0, len);
            // Linux 6.1+: synchronously collapse each aligned 2 MiB range.
            // Best-effort on older kernels; the physical-contiguity check
            // below remains authoritative.
            libc::madvise(pointer.cast(), len, 25); // MADV_COLLAPSE
        }
        if unsafe { libc::mlock(pointer.cast(), len) } != 0 {
            unsafe { libc::munmap(pointer.cast(), len) };
            return None;
        }
        Some(pointer)
    }

    pub fn allocate(out: *mut *mut c_void, bytes: usize, flags: c_uint) -> c_int {
        if out.is_null() || bytes == 0 || bytes > MAX_ALLOCATION {
            return CUDA_ERROR_INVALID_VALUE;
        }
        if let Some(result) = file_allocation(bytes, flags) {
            return match result {
                Ok(allocation) => {
                    let pointer = allocation.base as *mut c_void;
                    ALLOCATIONS.lock().unwrap().push(allocation);
                    unsafe { *out = pointer };
                    CUDA_SUCCESS
                }
                Err(status) => status,
            };
        }
        let Some(len) = allocation_len(bytes) else {
            return CUDA_ERROR_INVALID_VALUE;
        };
        for _ in 0..8 {
            let Some(pointer) = (unsafe { aligned_mapping(len) }) else {
                continue;
            };
            let Some(gpa) = contiguous_gpa(pointer as usize, len / PAGE) else {
                unsafe { libc::munmap(pointer.cast(), len) };
                continue;
            };
            let mut args = Vec::with_capacity(16);
            args.extend_from_slice(&gpa.to_le_bytes());
            args.extend_from_slice(&(len as u64).to_le_bytes());
            let device_pointer = match cuda_driver_lib_call(CUDA_HOST_REGISTER_GPA, args)
                .and_then(|bytes| returned_handle(&bytes))
            {
                Ok(pointer) => pointer as u64,
                Err(status) => {
                    unsafe { libc::munmap(pointer.cast(), len) };
                    return status;
                }
            };
            ALLOCATIONS.lock().unwrap().push(Allocation {
                base: pointer as usize,
                len,
                device_pointer,
                flags,
            });
            unsafe { *out = pointer.cast() };
            return CUDA_SUCCESS;
        }
        CUDA_ERROR_OUT_OF_MEMORY
    }

    pub fn device_pointer(out: *mut u64, pointer: *mut c_void) -> c_int {
        if out.is_null() || pointer.is_null() {
            return CUDA_ERROR_INVALID_VALUE;
        }
        let pointer = pointer as usize;
        match ALLOCATIONS.lock().unwrap().iter().find(|allocation| {
            pointer >= allocation.base && pointer < allocation.base + allocation.len
        }) {
            Some(allocation) => {
                unsafe { *out = allocation.device_pointer + (pointer - allocation.base) as u64 };
                CUDA_SUCCESS
            }
            None => CUDA_ERROR_INVALID_VALUE,
        }
    }

    pub fn flags(out: *mut c_uint, pointer: *mut c_void) -> c_int {
        if out.is_null() || pointer.is_null() {
            return CUDA_ERROR_INVALID_VALUE;
        }
        let pointer = pointer as usize;
        match ALLOCATIONS.lock().unwrap().iter().find(|allocation| {
            pointer >= allocation.base && pointer < allocation.base + allocation.len
        }) {
            Some(allocation) => {
                unsafe { *out = allocation.flags };
                CUDA_SUCCESS
            }
            None => CUDA_ERROR_INVALID_VALUE,
        }
    }

    pub fn free(pointer: *mut c_void) -> c_int {
        if pointer.is_null() {
            return CUDA_SUCCESS;
        }
        let allocation = {
            let mut allocations = ALLOCATIONS.lock().unwrap();
            let Some(index) = allocations
                .iter()
                .position(|allocation| allocation.base == pointer as usize)
            else {
                return CUDA_ERROR_INVALID_VALUE;
            };
            allocations.swap_remove(index)
        };
        let mut args = Vec::with_capacity(16);
        args.extend_from_slice(&allocation.device_pointer.to_le_bytes());
        args.extend_from_slice(&(allocation.len as u64).to_le_bytes());
        let status = match cuda_driver_lib_call(CUDA_HOST_UNREGISTER_GPA, args) {
            Ok(_) => CUDA_SUCCESS,
            Err(status) => status,
        };
        unsafe { libc::munmap(pointer, allocation.len) };
        status
    }

    #[cfg(test)]
    mod tests {
        use super::{allocation_len, page_len, HUGE_PAGE, PAGE};

        #[test]
        fn host_allocations_retain_full_hugepage_backing() {
            assert_eq!(allocation_len(1), Some(HUGE_PAGE));
            assert_eq!(allocation_len(HUGE_PAGE), Some(HUGE_PAGE));
            assert_eq!(allocation_len(HUGE_PAGE + 1), Some(HUGE_PAGE * 2));
            assert_eq!(allocation_len(usize::MAX), None);
        }

        #[test]
        fn file_allocations_are_page_rounded() {
            assert_eq!(page_len(1), Some(PAGE));
            assert_eq!(page_len(PAGE), Some(PAGE));
            assert_eq!(page_len(PAGE + 1), Some(PAGE * 2));
            assert_eq!(page_len(usize::MAX), None);
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod mapped_host_memory {
    use super::*;

    pub fn allocate(_: *mut *mut c_void, _: usize, _: c_uint) -> c_int {
        CUDA_ERROR_NOT_SUPPORTED
    }
    pub fn device_pointer(_: *mut u64, _: *mut c_void) -> c_int {
        CUDA_ERROR_NOT_SUPPORTED
    }
    pub fn flags(_: *mut c_uint, _: *mut c_void) -> c_int {
        CUDA_ERROR_NOT_SUPPORTED
    }
    pub fn free(_: *mut c_void) -> c_int {
        CUDA_ERROR_NOT_SUPPORTED
    }
}

fn returned_handle(bytes: &[u8]) -> Result<usize, c_int> {
    if bytes.len() != 8 {
        return Err(CUDA_ERROR_UNKNOWN);
    }
    Ok(u64::from_le_bytes(bytes.try_into().unwrap()) as usize)
}

unsafe fn image_bytes<'a>(image: *const c_void) -> Result<&'a [u8], c_int> {
    let len = unsafe { module_image_len(image) }?;
    Ok(unsafe { std::slice::from_raw_parts(image.cast::<u8>(), len) })
}

unsafe fn version_two_fatbins(wrapper: &FatbincWrapper) -> Result<Vec<*const c_void>, c_int> {
    if wrapper._filename_or_fatbins.is_null() {
        return Err(CUDA_ERROR_INVALID_VALUE);
    }
    let list = wrapper._filename_or_fatbins as *const *const c_void;
    let mut images = Vec::new();
    // Generated wrappers are short; the cap turns a missing terminator into a
    // clean error instead of walking arbitrary guest memory forever.
    for index in 0..4096 {
        let image = unsafe { list.add(index).read() };
        if image.is_null() {
            return if images.is_empty() {
                Err(CUDA_ERROR_INVALID_IMAGE)
            } else {
                Ok(images)
            };
        }
        images.push(image);
    }
    Err(CUDA_ERROR_INVALID_IMAGE)
}

/// CUDA's library API is a newer handle vocabulary over the same loaded-code
/// object used by the module API. Static libcudart also passes private v1/v2
/// fatbin wrappers here. Stream their pointed-to images to the daemon, which
/// reconstructs the wrapper and invokes the host driver's real Library API;
/// eagerly loading every image as an independent module both violates lazy
/// architecture selection and can exhaust/crash the driver on large NCCL
/// libraries.
#[no_mangle]
pub extern "C" fn cuLibraryLoadData(
    library: *mut *mut c_void,
    code: *const c_void,
    _jit_options: *mut c_int,
    _jit_option_values: *mut *mut c_void,
    _num_jit_options: c_uint,
    _library_options: *mut c_int,
    _library_option_values: *mut *mut c_void,
    _num_library_options: c_uint,
) -> c_int {
    let trace = std::env::var_os("SMOLVM_CUDA_SHIM_TRACE").is_some();
    if library.is_null() || code.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    let magic = unsafe { (code as *const u32).read_unaligned() };
    let wrapper_version =
        (magic == 0x4662_43b1).then(|| unsafe { (code as *const u32).add(1).read_unaligned() });
    let (kind, images) = match wrapper_version {
        Some(1) => {
            let wrapper = unsafe { &*(code as *const FatbincWrapper) };
            if wrapper.data.is_null() {
                return CUDA_ERROR_INVALID_VALUE;
            }
            (1_u32, vec![wrapper.data])
        }
        Some(2) => {
            let wrapper = unsafe { &*(code as *const FatbincWrapper) };
            if wrapper.data.is_null() {
                return CUDA_ERROR_INVALID_VALUE;
            }
            match unsafe { version_two_fatbins(wrapper) } {
                Ok(prelinked) => {
                    // v2 keeps the primary fatbin in `data`; the pointer list
                    // contains additional prelinked fatbins. Preserve that
                    // distinction so the host driver selects kernels from the
                    // primary image rather than treating the first dependency
                    // as the library itself.
                    let mut images = Vec::with_capacity(prelinked.len() + 1);
                    images.push(wrapper.data);
                    images.extend(prelinked);
                    (2_u32, images)
                }
                Err(status) => return status,
            }
        }
        _ => (0_u32, vec![code]),
    };
    if trace {
        eprintln!(
            "[shim] cuLibraryLoadData kind={kind} images={} code={code:p}",
            images.len()
        );
    }

    let build = match cuda_driver_lib_call(CUDA_LIBRARY_BEGIN, kind.to_le_bytes().to_vec())
        .and_then(|bytes| returned_handle(&bytes))
    {
        Ok(build) => build,
        Err(status) => return status,
    };
    let cancel = || {
        let _ = cuda_driver_lib_call(CUDA_LIBRARY_CANCEL, (build as u64).to_le_bytes().to_vec());
    };
    for (index, image) in images.into_iter().enumerate() {
        if trace {
            eprintln!("[shim] cuLibraryLoadData image={index} ptr={image:p} sizing");
        }
        let bytes = match unsafe { image_bytes(image) } {
            Ok(bytes) => bytes,
            Err(status) => {
                cancel();
                return status;
            }
        };
        if trace {
            eprintln!(
                "[shim] cuLibraryLoadData image={index} len={:#x} streaming",
                bytes.len()
            );
        }
        let mut args = Vec::with_capacity(8 + bytes.len());
        args.extend_from_slice(&(build as u64).to_le_bytes());
        args.extend_from_slice(bytes);
        if let Err(status) = cuda_driver_lib_call(CUDA_LIBRARY_ADD_IMAGE, args) {
            cancel();
            return status;
        }
    }
    let handle =
        match cuda_driver_lib_call(CUDA_LIBRARY_COMPLETE, (build as u64).to_le_bytes().to_vec())
            .and_then(|bytes| returned_handle(&bytes))
        {
            Ok(handle) => handle,
            Err(status) => {
                cancel();
                return status;
            }
        };
    if trace {
        eprintln!("[shim] cuLibraryLoadData complete handle={handle:#x}");
    }
    native_libraries().lock().unwrap().insert(handle);
    ret(unsafe { out(library, handle as *mut c_void) })
}

#[no_mangle]
pub extern "C" fn cuLibraryUnload(library: *mut c_void) -> c_int {
    let trace = std::env::var_os("SMOLVM_CUDA_SHIM_TRACE").is_some();
    if native_libraries()
        .lock()
        .unwrap()
        .remove(&(library as usize))
    {
        let status = match cuda_driver_lib_call(
            CUDA_LIBRARY_UNLOAD,
            (library as u64).to_le_bytes().to_vec(),
        ) {
            Ok(_) => CUDA_SUCCESS,
            Err(status) => status,
        };
        if trace {
            eprintln!("[shim] cuLibraryUnload library={library:p} status={status}");
        }
        return status;
    }
    cuModuleUnload(library)
}

#[no_mangle]
pub extern "C" fn cuLibraryGetKernel(
    kernel: *mut *mut c_void,
    library: *mut c_void,
    name: *const c_char,
) -> c_int {
    let trace = std::env::var_os("SMOLVM_CUDA_SHIM_TRACE").is_some();
    if native_libraries()
        .lock()
        .unwrap()
        .contains(&(library as usize))
    {
        if kernel.is_null() || name.is_null() {
            return CUDA_ERROR_INVALID_VALUE;
        }
        let name = unsafe { CStr::from_ptr(name) }.to_bytes();
        let mut args = Vec::with_capacity(8 + name.len());
        args.extend_from_slice(&(library as u64).to_le_bytes());
        args.extend_from_slice(name);
        let status = match cuda_driver_lib_call(CUDA_LIBRARY_GET_KERNEL, args)
            .and_then(|bytes| returned_handle(&bytes))
        {
            Ok(handle) => {
                native_kernels().lock().unwrap().insert(handle);
                if trace {
                    eprintln!(
                        "[shim] cuLibraryGetKernel library={library:p} name={} kernel={handle:#x}",
                        String::from_utf8_lossy(name)
                    );
                }
                ret(unsafe { out(kernel, handle as *mut c_void) })
            }
            Err(status) => {
                if trace {
                    eprintln!(
                        "[shim] cuLibraryGetKernel library={library:p} name={} status={status}",
                        String::from_utf8_lossy(name)
                    );
                }
                status
            }
        };
        return status;
    }
    cuModuleGetFunction(kernel, library, name)
}

#[no_mangle]
pub extern "C" fn cuLibraryGetModule(module: *mut *mut c_void, library: *mut c_void) -> c_int {
    let trace = std::env::var_os("SMOLVM_CUDA_SHIM_TRACE").is_some();
    if native_libraries()
        .lock()
        .unwrap()
        .contains(&(library as usize))
    {
        let status = match cuda_driver_lib_call(
            CUDA_LIBRARY_GET_MODULE,
            (library as u64).to_le_bytes().to_vec(),
        )
        .and_then(|bytes| returned_handle(&bytes))
        {
            Ok(handle) => {
                if trace {
                    eprintln!("[shim] cuLibraryGetModule library={library:p} module={handle:#x}");
                }
                ret(unsafe { out(module, handle as *mut c_void) })
            }
            Err(status) => status,
        };
        return status;
    }
    ret(unsafe { out(module, library) })
}

#[no_mangle]
pub extern "C" fn cuKernelGetFunction(function: *mut *mut c_void, kernel: *mut c_void) -> c_int {
    let trace = std::env::var_os("SMOLVM_CUDA_SHIM_TRACE").is_some();
    if native_kernels()
        .lock()
        .unwrap()
        .contains(&(kernel as usize))
    {
        let status = match cuda_driver_lib_call(
            CUDA_KERNEL_GET_FUNCTION,
            (kernel as u64).to_le_bytes().to_vec(),
        )
        .and_then(|bytes| returned_handle(&bytes))
        {
            Ok(handle) => {
                native_functions().lock().unwrap().insert(handle);
                if trace {
                    eprintln!("[shim] cuKernelGetFunction kernel={kernel:p} function={handle:#x}");
                }
                ret(unsafe { out(function, handle as *mut c_void) })
            }
            Err(status) => status,
        };
        return status;
    }
    ret(unsafe { out(function, kernel) })
}

#[no_mangle]
pub extern "C" fn cuModuleGetFunction(
    func: *mut *mut c_void,
    module: *mut c_void,
    name: *const c_char,
) -> c_int {
    let trace = std::env::var_os("SMOLVM_CUDA_SHIM_TRACE").is_some();
    if func.is_null() || name.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    // CUDA's statically linked runtime registers code through the Library API
    // but later resolves registered kernels through the legacy Module API.
    // CUlibrary and CUmodule are distinct host-driver handle types, so bridge
    // that compatibility lookup through CUkernel before returning CUfunction.
    let is_library = native_libraries()
        .lock()
        .map(|libraries| libraries.contains(&(module as usize)))
        .unwrap_or(false);
    if is_library {
        let mut kernel = std::ptr::null_mut();
        let status = cuLibraryGetKernel(&mut kernel, module, name);
        if status != CUDA_SUCCESS {
            return status;
        }
        return cuKernelGetFunction(func, kernel);
    }
    let fn_name = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(n) => n.to_string(),
        Err(_) => return CUDA_ERROR_INVALID_VALUE,
    };
    let status = match with_state(|s| s.client.module_get_function(module as u64, &fn_name)) {
        Ok(h) => {
            native_functions().lock().unwrap().insert(h as usize);
            ret(unsafe { out(func, h as *mut c_void) })
        }
        Err(code) => code,
    };
    if trace {
        eprintln!("[shim] cuModuleGetFunction module={module:p} name={fn_name} status={status}");
    }
    status
}

#[no_mangle]
pub extern "C" fn cuModuleGetGlobal(
    dptr: *mut u64,
    bytes: *mut usize,
    module: *mut c_void,
    name: *const c_char,
) -> c_int {
    if dptr.is_null() || name.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    let name = unsafe { CStr::from_ptr(name) }.to_bytes();
    let mut args = Vec::with_capacity(8 + name.len());
    args.extend_from_slice(&(module as u64).to_le_bytes());
    args.extend_from_slice(name);
    match cuda_driver_lib_call(CUDA_MODULE_GET_GLOBAL, args) {
        Ok(result) if result.len() == 16 => {
            let pointer = u64::from_le_bytes(result[..8].try_into().unwrap());
            let size = u64::from_le_bytes(result[8..].try_into().unwrap());
            unsafe {
                *dptr = pointer;
                if !bytes.is_null() {
                    *bytes = size as usize;
                }
            }
            CUDA_SUCCESS
        }
        Ok(_) => CUDA_ERROR_UNKNOWN,
        Err(status) => status,
    }
}

#[no_mangle]
pub extern "C" fn cuModuleGetGlobal_v2(
    dptr: *mut u64,
    bytes: *mut usize,
    module: *mut c_void,
    name: *const c_char,
) -> c_int {
    cuModuleGetGlobal(dptr, bytes, module, name)
}

#[no_mangle]
pub extern "C" fn cuModuleUnload(module: *mut c_void) -> c_int {
    ret(with_state(|s| s.client.module_unload(module as u64)))
}

// ---- memory ---------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn cuMemHostAlloc(pointer: *mut *mut c_void, bytes: usize, flags: c_uint) -> c_int {
    mapped_host_memory::allocate(pointer, bytes, flags)
}

#[no_mangle]
pub extern "C" fn cuMemHostGetDevicePointer_v2(
    device_pointer: *mut u64,
    host_pointer: *mut c_void,
    _flags: c_uint,
) -> c_int {
    mapped_host_memory::device_pointer(device_pointer, host_pointer)
}

#[no_mangle]
pub extern "C" fn cuMemHostGetDevicePointer(
    device_pointer: *mut u64,
    host_pointer: *mut c_void,
    flags: c_uint,
) -> c_int {
    cuMemHostGetDevicePointer_v2(device_pointer, host_pointer, flags)
}

#[no_mangle]
pub extern "C" fn cuMemHostGetFlags(flags: *mut c_uint, host_pointer: *mut c_void) -> c_int {
    mapped_host_memory::flags(flags, host_pointer)
}

#[no_mangle]
pub extern "C" fn cuMemFreeHost(host_pointer: *mut c_void) -> c_int {
    mapped_host_memory::free(host_pointer)
}

#[no_mangle]
pub extern "C" fn cuMemAlloc_v2(dptr: *mut u64, bytes: usize) -> c_int {
    match with_state(|s| s.client.mem_alloc(bytes as u64)) {
        Ok(d) => ret(unsafe { out(dptr, d) }),
        Err(code) => code,
    }
}

#[no_mangle]
pub extern "C" fn cuMemFree_v2(dptr: u64) -> c_int {
    ret(with_state(|s| s.client.mem_free(dptr)))
}

#[no_mangle]
pub extern "C" fn cuMemPoolCreate(pool: *mut *mut c_void, props: *const CUmemPoolProps) -> c_int {
    if pool.is_null() || props.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    let props = unsafe { &*props };
    match with_state(|s| {
        s.client.mem_pool_create(
            props.alloc_type,
            props.handle_types,
            props.location.type_,
            props.location.id,
            props.max_size as u64,
            props.usage,
        )
    }) {
        Ok(handle) => ret(unsafe { out(pool, handle as *mut c_void) }),
        Err(code) => code,
    }
}

#[no_mangle]
pub extern "C" fn cuMemPoolDestroy(pool: *mut c_void) -> c_int {
    if pool.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    ret(with_state(|s| s.client.mem_pool_destroy(pool as u64)))
}

fn mem_pool_attr_is_int(attr: c_int) -> bool {
    matches!(attr, 1..=3)
}

#[no_mangle]
pub extern "C" fn cuMemPoolSetAttribute(
    pool: *mut c_void,
    attr: c_int,
    value: *mut c_void,
) -> c_int {
    if pool.is_null() || value.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    let value = unsafe {
        if mem_pool_attr_is_int(attr) {
            *(value as *const c_int) as u32 as u64
        } else {
            *(value as *const u64)
        }
    };
    ret(with_state(|s| {
        s.client.mem_pool_set_attribute(pool as u64, attr, value)
    }))
}

#[no_mangle]
pub extern "C" fn cuMemPoolGetAttribute(
    pool: *mut c_void,
    attr: c_int,
    value: *mut c_void,
) -> c_int {
    if pool.is_null() || value.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    match with_state(|s| s.client.mem_pool_get_attribute(pool as u64, attr)) {
        Ok(v) => {
            unsafe {
                if mem_pool_attr_is_int(attr) {
                    *(value as *mut c_int) = v as c_int;
                } else {
                    *(value as *mut u64) = v;
                }
            }
            CUDA_SUCCESS
        }
        Err(code) => code,
    }
}

#[no_mangle]
pub extern "C" fn cuMemPoolSetAccess(
    pool: *mut c_void,
    map: *const CUmemAccessDesc,
    count: usize,
) -> c_int {
    if pool.is_null() || (map.is_null() && count != 0) {
        return CUDA_ERROR_INVALID_VALUE;
    }
    let descriptors = if count == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(map, count) }
            .iter()
            .map(|d| (d.location.type_, d.location.id, d.flags as u32 as u64))
            .collect()
    };
    ret(with_state(|s| {
        s.client.mem_pool_set_access(pool as u64, descriptors)
    }))
}

#[no_mangle]
pub extern "C" fn cuMemPoolGetAccess(
    flags: *mut c_int,
    pool: *mut c_void,
    location: *const CUmemLocation,
) -> c_int {
    if flags.is_null() || pool.is_null() || location.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    let location = unsafe { &*location };
    match with_state(|s| {
        s.client
            .mem_pool_get_access(pool as u64, location.type_, location.id)
    }) {
        Ok(v) => ret(unsafe { out(flags, v as c_int) }),
        Err(code) => code,
    }
}

#[no_mangle]
pub extern "C" fn cuMemPoolTrimTo(pool: *mut c_void, min_bytes: usize) -> c_int {
    if pool.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    ret(with_state(|s| {
        s.client.mem_pool_trim_to(pool as u64, min_bytes as u64)
    }))
}

#[no_mangle]
pub extern "C" fn cuMemAllocFromPoolAsync(
    dptr: *mut u64,
    bytes: usize,
    pool: *mut c_void,
    stream: *mut c_void,
) -> c_int {
    if dptr.is_null() || pool.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    match with_state(|s| {
        s.client
            .mem_alloc_from_pool_async(bytes as u64, pool as u64, stream as u64)
    }) {
        Ok(v) => ret(unsafe { out(dptr, v) }),
        Err(code) => code,
    }
}

#[no_mangle]
pub extern "C" fn cuMemAllocFromPoolAsync_ptsz(
    dptr: *mut u64,
    bytes: usize,
    pool: *mut c_void,
    stream: *mut c_void,
) -> c_int {
    cuMemAllocFromPoolAsync(dptr, bytes, pool, stream)
}

#[no_mangle]
pub extern "C" fn cuMemAllocAsync(dptr: *mut u64, bytes: usize, stream: *mut c_void) -> c_int {
    if dptr.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    match with_state(|s| s.client.mem_alloc_async(bytes as u64, stream as u64)) {
        Ok(v) => ret(unsafe { out(dptr, v) }),
        Err(code) => code,
    }
}

#[no_mangle]
pub extern "C" fn cuMemAllocAsync_ptsz(dptr: *mut u64, bytes: usize, stream: *mut c_void) -> c_int {
    cuMemAllocAsync(dptr, bytes, stream)
}

#[no_mangle]
pub extern "C" fn cuMemFreeAsync(dptr: u64, stream: *mut c_void) -> c_int {
    ret(with_state(|s| s.client.mem_free_async(dptr, stream as u64)))
}

#[no_mangle]
pub extern "C" fn cuMemFreeAsync_ptsz(dptr: u64, stream: *mut c_void) -> c_int {
    cuMemFreeAsync(dptr, stream)
}

fn device_mem_pool(device: c_int, default: bool, pool: *mut *mut c_void) -> c_int {
    if pool.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    let result = with_state(|s| {
        if default {
            s.client.device_get_default_mem_pool(device)
        } else {
            s.client.device_get_mem_pool(device)
        }
    });
    match result {
        Ok(handle) => ret(unsafe { out(pool, handle as *mut c_void) }),
        Err(code) => code,
    }
}

#[no_mangle]
pub extern "C" fn cuDeviceGetDefaultMemPool(pool: *mut *mut c_void, device: c_int) -> c_int {
    device_mem_pool(device, true, pool)
}

#[no_mangle]
pub extern "C" fn cuDeviceGetMemPool(pool: *mut *mut c_void, device: c_int) -> c_int {
    device_mem_pool(device, false, pool)
}

#[no_mangle]
pub extern "C" fn cuDeviceSetMemPool(device: c_int, pool: *mut c_void) -> c_int {
    if pool.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    ret(with_state(|s| {
        s.client.device_set_mem_pool(device, pool as u64)
    }))
}

#[no_mangle]
pub extern "C" fn cuMemcpyHtoD_v2(dptr: u64, src: *const c_void, bytes: usize) -> c_int {
    if src.is_null() && bytes > 0 {
        return CUDA_ERROR_INVALID_VALUE;
    }
    let data = unsafe { std::slice::from_raw_parts(src as *const u8, bytes) };
    ret(with_state(|s| s.client.memcpy_htod(dptr, data, 0)))
}

#[no_mangle]
pub extern "C" fn cuMemcpyDtoH_v2(dst: *mut c_void, dptr: u64, bytes: usize) -> c_int {
    if dst.is_null() && bytes > 0 {
        return CUDA_ERROR_INVALID_VALUE;
    }
    match with_state(|s| s.client.memcpy_dtoh(dptr, bytes as u64, 0)) {
        Ok(data) => {
            if data.len() != bytes {
                return CUDA_ERROR_UNKNOWN;
            }
            unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), dst as *mut u8, bytes) };
            CUDA_SUCCESS
        }
        Err(code) => code,
    }
}

#[no_mangle]
pub extern "C" fn cuMemcpyDtoD_v2(dst: u64, src: u64, bytes: usize) -> c_int {
    ret(with_state(|s| s.client.memcpy_dtod(dst, src, bytes as u64)))
}

fn pointer_is_device(pointer: u64) -> Result<bool, c_int> {
    let out = cuda_driver_lib_call(2, pointer.to_le_bytes().to_vec())?;
    Ok(out.first().copied() == Some(2))
}

fn memcpy_unified(dst: u64, src: u64, bytes: usize, stream: u64) -> c_int {
    if bytes == 0 {
        return CUDA_SUCCESS;
    }
    if dst == 0 || src == 0 {
        return CUDA_ERROR_INVALID_VALUE;
    }
    let dst_device = match pointer_is_device(dst) {
        Ok(value) => value,
        Err(code) => return code,
    };
    let src_device = match pointer_is_device(src) {
        Ok(value) => value,
        Err(code) => return code,
    };
    match (dst_device, src_device) {
        (true, true) => ret(with_state(|s| {
            s.client.memcpy_dtod_async(dst, src, bytes as u64, stream)
        })),
        (true, false) => {
            let data = unsafe { std::slice::from_raw_parts(src as *const u8, bytes) };
            ret(with_state(|s| s.client.memcpy_htod(dst, data, stream)))
        }
        (false, true) => match with_state(|s| s.client.memcpy_dtoh(src, bytes as u64, stream)) {
            Ok(data) if data.len() == bytes => {
                unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), dst as *mut u8, bytes) };
                CUDA_SUCCESS
            }
            Ok(_) => CUDA_ERROR_UNKNOWN,
            Err(code) => code,
        },
        (false, false) => {
            unsafe { std::ptr::copy(src as *const u8, dst as *mut u8, bytes) };
            CUDA_SUCCESS
        }
    }
}

#[no_mangle]
pub extern "C" fn cuMemcpy(dst: u64, src: u64, bytes: usize) -> c_int {
    memcpy_unified(dst, src, bytes, 0)
}

#[no_mangle]
pub extern "C" fn cuMemcpyAsync(dst: u64, src: u64, bytes: usize, stream: *mut c_void) -> c_int {
    memcpy_unified(dst, src, bytes, stream as u64)
}

#[no_mangle]
pub extern "C" fn cuMemcpyAsync_ptsz(
    dst: u64,
    src: u64,
    bytes: usize,
    stream: *mut c_void,
) -> c_int {
    cuMemcpyAsync(dst, src, bytes, stream)
}

#[no_mangle]
pub extern "C" fn cuMemsetD8_v2(dptr: u64, value: u8, n: usize) -> c_int {
    ret(with_state(|s| s.client.memset_d8(dptr, value, n as u64)))
}

#[no_mangle]
pub extern "C" fn cuMemsetD8Async(dptr: u64, value: u8, n: usize, stream: *mut c_void) -> c_int {
    ret(with_state(|s| {
        s.client
            .memset_d8_async(dptr, value, n as u64, stream as u64)
    }))
}

#[no_mangle]
pub extern "C" fn cuMemsetD8Async_ptsz(
    dptr: u64,
    value: u8,
    n: usize,
    stream: *mut c_void,
) -> c_int {
    cuMemsetD8Async(dptr, value, n, stream)
}

#[no_mangle]
pub extern "C" fn cuMemGetInfo_v2(free: *mut usize, total: *mut usize) -> c_int {
    match with_state(|s| s.client.mem_get_info()) {
        Ok((f, t)) => {
            if !free.is_null() {
                unsafe { *free = f as usize };
            }
            if !total.is_null() {
                unsafe { *total = t as usize };
            }
            CUDA_SUCCESS
        }
        Err(code) => code,
    }
}

// The *Async variants complete synchronously — permitted by the API contract
// (an implementation may be more synchronous than requested).

#[no_mangle]
pub extern "C" fn cuMemcpyHtoDAsync_v2(
    dptr: u64,
    src: *const c_void,
    bytes: usize,
    _stream: *mut c_void,
) -> c_int {
    cuMemcpyHtoD_v2(dptr, src, bytes)
}

#[no_mangle]
pub extern "C" fn cuMemcpyDtoHAsync_v2(
    dst: *mut c_void,
    dptr: u64,
    bytes: usize,
    _stream: *mut c_void,
) -> c_int {
    cuMemcpyDtoH_v2(dst, dptr, bytes)
}

#[no_mangle]
pub extern "C" fn cuMemcpyDtoDAsync_v2(
    dst: u64,
    src: u64,
    bytes: usize,
    _stream: *mut c_void,
) -> c_int {
    cuMemcpyDtoD_v2(dst, src, bytes)
}

// ---- kernel launch ----------------------------------------------------------------

/// `CUlaunchConfig` (CUDA 12): dims + shared bytes + stream + an attribute
/// array we don't forward (clusters/programmatic completion — not used by the
/// Triton kernels that launch through this entry point).
#[repr(C)]
struct CuLaunchConfig {
    grid_x: c_uint,
    grid_y: c_uint,
    grid_z: c_uint,
    block_x: c_uint,
    block_y: c_uint,
    block_z: c_uint,
    shared_bytes: c_uint,
    stream: *mut c_void,
    attrs: *mut c_void,
    num_attrs: c_uint,
}

/// Attribute-carrying launch (Triton/torch.compile's launcher). The attributes
/// are ignored; everything else lowers onto the plain launch path.
#[no_mangle]
pub extern "C" fn cuLaunchKernelEx(
    config: *const c_void,
    func: *mut c_void,
    kernel_params: *mut *mut c_void,
    extra: *mut *mut c_void,
) -> c_int {
    if config.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    // SAFETY: caller passes a valid CUlaunchConfig.
    let c = unsafe { &*(config as *const CuLaunchConfig) };
    if std::env::var_os("SMOLVM_CUDA_SHIM_TRACE").is_some() {
        eprintln!(
            "[shim] cuLaunchKernelEx grid={}x{}x{} block={}x{}x{} shared={} attrs={}",
            c.grid_x,
            c.grid_y,
            c.grid_z,
            c.block_x,
            c.block_y,
            c.block_z,
            c.shared_bytes,
            c.num_attrs
        );
    }
    cuLaunchKernel(
        func,
        c.grid_x,
        c.grid_y,
        c.grid_z,
        c.block_x,
        c.block_y,
        c.block_z,
        c.shared_bytes,
        c.stream,
        kernel_params,
        extra,
    )
}

#[no_mangle]
pub extern "C" fn cuLaunchKernelEx_ptsz(
    config: *const c_void,
    func: *mut c_void,
    kernel_params: *mut *mut c_void,
    extra: *mut *mut c_void,
) -> c_int {
    cuLaunchKernelEx(config, func, kernel_params, extra)
}

/// Pointer attributes. Every device pointer we hand out is the host's real
/// `CUdeviceptr`, so a pointer the guest holds is a device pointer: report
/// memory-type Device, device-pointer = the value itself, ordinal 0, not
/// managed. Range/host-pointer queries return the pointer / null respectively.
/// vLLM's allocator and Triton link these; a stub error broke import.
#[no_mangle]
pub extern "C" fn cuPointerGetAttribute(data: *mut c_void, attribute: c_int, ptr: u64) -> c_int {
    if data.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    // CUpointer_attribute: 1=CONTEXT, 2=MEMORY_TYPE, 3=DEVICE_POINTER,
    // 4=HOST_POINTER, 6=BUFFER_ID, 7=IS_MANAGED, 9=DEVICE_ORDINAL,
    // 11=RANGE_START_ADDR, 12=RANGE_SIZE, 13=MAPPED.
    unsafe {
        match attribute {
            2 => *(data as *mut c_uint) = 2, // CU_MEMORYTYPE_DEVICE
            3 | 11 => *(data as *mut u64) = ptr,
            12 => *(data as *mut usize) = 0,
            4 => *(data as *mut u64) = 0, // no host mapping
            7 => *(data as *mut c_int) = 0,
            9 => *(data as *mut c_int) = 0,
            13 => *(data as *mut c_int) = 1,
            _ => *(data as *mut u64) = 0,
        }
    }
    CUDA_SUCCESS
}

/// Batched pointer-attribute query: fill each requested attribute per the
/// single-attribute logic above.
#[no_mangle]
pub extern "C" fn cuPointerGetAttributes(
    num_attributes: c_uint,
    attributes: *const c_int,
    data: *const *mut c_void,
    ptr: u64,
) -> c_int {
    if attributes.is_null() || data.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    for i in 0..num_attributes as isize {
        let attr = unsafe { *attributes.offset(i) };
        let out = unsafe { *data.offset(i) };
        if !out.is_null() {
            cuPointerGetAttribute(out, attr, ptr);
        }
    }
    CUDA_SUCCESS
}

/// Cache-config is a scheduling hint the host driver applies at launch; a
/// no-op here is correct (work runs on the host's real function).
#[no_mangle]
pub extern "C" fn cuFuncSetCacheConfig(_func: *mut c_void, _config: c_int) -> c_int {
    CUDA_SUCCESS
}

/// Context limits (stack size, printf FIFO, malloc heap): report a generous
/// value on get, accept any set. Triton reads the stack-size limit during
/// launcher setup; a stub error there aborted the launch.
#[no_mangle]
pub extern "C" fn cuCtxGetLimit(pvalue: *mut usize, _limit: c_int) -> c_int {
    if pvalue.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    unsafe { *pvalue = 8 * 1024 * 1024 };
    CUDA_SUCCESS
}
#[no_mangle]
pub extern "C" fn cuCtxSetLimit(_limit: c_int, _value: usize) -> c_int {
    CUDA_SUCCESS
}

/// No cluster support (clusters are an sm_90+ feature we don't forward);
/// reporting 0 max clusters keeps Triton on the standard, non-cluster launch.
#[no_mangle]
pub extern "C" fn cuOccupancyMaxActiveClusters(
    num_clusters: *mut c_int,
    _func: *mut c_void,
    _config: *const c_void,
) -> c_int {
    if num_clusters.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    unsafe { *num_clusters = 0 };
    CUDA_SUCCESS
}

#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn cuLaunchKernel(
    func: *mut c_void,
    grid_x: c_uint,
    grid_y: c_uint,
    grid_z: c_uint,
    block_x: c_uint,
    block_y: c_uint,
    block_z: c_uint,
    shared_bytes: c_uint,
    stream: *mut c_void,
    kernel_params: *mut *mut c_void,
    extra: *mut *mut c_void,
) -> c_int {
    let fh = func as u64;
    // Argument sizes come from the host's view of the loaded module; fetch once
    // per function and cache.
    let sizes = match with_state(|s| {
        if let Some(sz) = s.param_sizes.get(&fh) {
            return Ok(sz.clone());
        }
        let sz = s.client.func_get_param_info(fh)?;
        s.param_sizes.insert(fh, sz.clone());
        Ok(sz)
    }) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let params: Vec<Vec<u8>> = if sizes.is_empty() {
        Vec::new()
    } else {
        if kernel_params.is_null() {
            // The `extra` buffer-pointer convention is not implemented.
            return if extra.is_null() {
                CUDA_ERROR_INVALID_VALUE
            } else {
                CUDA_ERROR_NOT_SUPPORTED
            };
        }
        let ptrs = unsafe { std::slice::from_raw_parts(kernel_params, sizes.len()) };
        sizes
            .iter()
            .zip(ptrs)
            .map(|(&sz, &p)| {
                unsafe { std::slice::from_raw_parts(p as *const u8, sz as usize) }.to_vec()
            })
            .collect()
    };
    ret(with_state(|s| {
        s.client.launch_kernel(
            fh,
            [grid_x, grid_y, grid_z],
            [block_x, block_y, block_z],
            shared_bytes,
            stream as u64,
            &params,
        )
    }))
}

// ---- streams / events ----------------------------------------------------------------

#[no_mangle]
pub extern "C" fn cuThreadExchangeStreamCaptureMode(mode: *mut c_int) -> c_int {
    if mode.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    let requested = unsafe { *mode };
    match with_state(|s| s.client.thread_exchange_capture_mode(requested)) {
        Ok(previous) => ret(unsafe { out(mode, previous) }),
        Err(status) => status,
    }
}

#[no_mangle]
pub extern "C" fn cuStreamCreate(stream: *mut *mut c_void, flags: c_uint) -> c_int {
    match with_state(|s| s.client.stream_create(flags)) {
        Ok(h) => ret(unsafe { out(stream, h as *mut c_void) }),
        Err(code) => code,
    }
}

// PyTorch's stream pool (used for CUDA-graph capture) creates streams here.
// Priority is advisory scheduling only; forward as a plain stream. A stub that
// left `stream` unwritten fed callers an uninitialized handle → a bad-pointer
// crash inside cuBLAS during graph capture.
#[no_mangle]
pub extern "C" fn cuStreamCreateWithPriority(
    stream: *mut *mut c_void,
    flags: c_uint,
    _priority: c_int,
) -> c_int {
    match with_state(|s| s.client.stream_create(flags)) {
        Ok(h) => ret(unsafe { out(stream, h as *mut c_void) }),
        Err(code) => code,
    }
}

#[no_mangle]
pub extern "C" fn cuStreamDestroy_v2(stream: *mut c_void) -> c_int {
    ret(with_state(|s| s.client.stream_destroy(stream as u64)))
}

#[no_mangle]
pub extern "C" fn cuStreamSynchronize(stream: *mut c_void) -> c_int {
    ret(with_state(|s| s.client.stream_synchronize(stream as u64)))
}

#[no_mangle]
pub extern "C" fn cuStreamQuery(stream: *mut c_void) -> c_int {
    // Honest completion status (0 or 600-NotReady) now that work runs on real
    // side streams.
    match with_state(|s| s.client.stream_query(stream as u64)) {
        Ok(code) => code,
        Err(e) => e,
    }
}

#[no_mangle]
pub extern "C" fn cuStreamWaitEvent(
    stream: *mut c_void,
    event: *mut c_void,
    flags: c_uint,
) -> c_int {
    // Real cross-stream ordering edge (a graph dependency during capture).
    ret(with_state(|s| {
        s.client
            .stream_wait_event(stream as u64, event as u64, flags)
    }))
}

#[no_mangle]
pub extern "C" fn cuEventCreate(event: *mut *mut c_void, flags: c_uint) -> c_int {
    match with_state(|s| s.client.event_create(flags)) {
        Ok(h) => ret(unsafe { out(event, h as *mut c_void) }),
        Err(code) => code,
    }
}

#[no_mangle]
pub extern "C" fn cuEventDestroy_v2(event: *mut c_void) -> c_int {
    ret(with_state(|s| s.client.event_destroy(event as u64)))
}

#[no_mangle]
pub extern "C" fn cuEventRecord(event: *mut c_void, stream: *mut c_void) -> c_int {
    ret(with_state(|s| {
        s.client.event_record(event as u64, stream as u64)
    }))
}

#[no_mangle]
pub extern "C" fn cuEventSynchronize(event: *mut c_void) -> c_int {
    ret(with_state(|s| s.client.event_synchronize(event as u64)))
}

#[no_mangle]
pub extern "C" fn cuEventQuery(_event: *mut c_void) -> c_int {
    CUDA_SUCCESS
}

#[no_mangle]
pub extern "C" fn cuEventElapsedTime(ms: *mut f32, start: *mut c_void, end: *mut c_void) -> c_int {
    match with_state(|s| s.client.event_elapsed_time(start as u64, end as u64)) {
        Ok(v) => ret(unsafe { out(ms, v) }),
        Err(code) => code,
    }
}

// ---- error strings -------------------------------------------------------------------

fn error_name(code: c_int) -> &'static CStr {
    match code {
        CUDA_SUCCESS => c"CUDA_SUCCESS",
        CUDA_ERROR_INVALID_VALUE => c"CUDA_ERROR_INVALID_VALUE",
        CUDA_ERROR_NOT_INITIALIZED => c"CUDA_ERROR_NOT_INITIALIZED",
        CUDA_ERROR_NO_DEVICE => c"CUDA_ERROR_NO_DEVICE",
        CUDA_ERROR_INVALID_CONTEXT => c"CUDA_ERROR_INVALID_CONTEXT",
        200 => c"CUDA_ERROR_INVALID_IMAGE",
        218 => c"CUDA_ERROR_INVALID_PTX",
        400 => c"CUDA_ERROR_INVALID_HANDLE",
        CUDA_ERROR_NOT_FOUND => c"CUDA_ERROR_NOT_FOUND",
        700 => c"CUDA_ERROR_ILLEGAL_ADDRESS",
        701 => c"CUDA_ERROR_LAUNCH_OUT_OF_RESOURCES",
        719 => c"CUDA_ERROR_LAUNCH_FAILED",
        CUDA_ERROR_NOT_SUPPORTED => c"CUDA_ERROR_NOT_SUPPORTED",
        _ => c"CUDA_ERROR_UNKNOWN",
    }
}

#[no_mangle]
pub extern "C" fn cuGetErrorName(code: c_int, pstr: *mut *const c_char) -> c_int {
    ret(unsafe { out(pstr, error_name(code).as_ptr()) })
}

#[no_mangle]
pub extern "C" fn cuGetErrorString(code: c_int, pstr: *mut *const c_char) -> c_int {
    // Name doubles as description; apps only ever print it.
    cuGetErrorName(code, pstr)
}

// ---- cuGetProcAddress ------------------------------------------------------------------

/// The modern CUDA runtime resolves nearly every driver entry point through
/// this table rather than dlsym, so it must cover everything we export.
fn proc_table(name: &str) -> Option<*mut c_void> {
    macro_rules! table {
        ($($sym:literal => $f:expr),+ $(,)?) => {
            match name {
                $($sym => Some($f as *mut c_void),)+
                _ => None,
            }
        };
    }
    table! {
        "cuInit" => cuInit,
        "cuDriverGetVersion" => cuDriverGetVersion,
        "cuDeviceGetCount" => cuDeviceGetCount,
        "cuDeviceGet" => cuDeviceGet,
        "cuDeviceGetName" => cuDeviceGetName,
        "cuDeviceTotalMem" => cuDeviceTotalMem_v2,
        "cuDeviceGetAttribute" => cuDeviceGetAttribute,
        "cuDeviceGetUuid" => cuDeviceGetUuid,
        "cuCtxCreate" => cuCtxCreate_v2,
        "cuCtxDestroy" => cuCtxDestroy_v2,
        "cuCtxSetCurrent" => cuCtxSetCurrent,
        "cuCtxGetCurrent" => cuCtxGetCurrent,
        "cuCtxPushCurrent" => cuCtxPushCurrent_v2,
        "cuCtxPopCurrent" => cuCtxPopCurrent_v2,
        "cuCtxGetDevice" => cuCtxGetDevice,
        "cuCtxSynchronize" => cuCtxSynchronize,
        "cuDevicePrimaryCtxRetain" => cuDevicePrimaryCtxRetain,
        "cuDevicePrimaryCtxRelease" => cuDevicePrimaryCtxRelease_v2,
        "cuDevicePrimaryCtxSetFlags" => cuDevicePrimaryCtxSetFlags_v2,
        "cuDevicePrimaryCtxGetState" => cuDevicePrimaryCtxGetState,
        "cuModuleLoad" => cuModuleLoad,
        "cuModuleLoadData" => cuModuleLoadData,
        "cuModuleLoadDataEx" => cuModuleLoadDataEx,
        "cuModuleLoadFatBinary" => cuModuleLoadFatBinary,
        "cuModuleGetFunction" => cuModuleGetFunction,
        "cuModuleGetGlobal" => cuModuleGetGlobal_v2,
        "cuModuleUnload" => cuModuleUnload,
        "cuModuleGetLoadingMode" => cuModuleGetLoadingMode,
        "cuLibraryLoadData" => cuLibraryLoadData,
        "cuLibraryUnload" => cuLibraryUnload,
        "cuLibraryGetKernel" => cuLibraryGetKernel,
        "cuLibraryGetModule" => cuLibraryGetModule,
        "cuKernelGetFunction" => cuKernelGetFunction,
        "cuMemAlloc" => cuMemAlloc_v2,
        "cuMemFree" => cuMemFree_v2,
        "cuMemPoolCreate" => cuMemPoolCreate,
        "cuMemPoolDestroy" => cuMemPoolDestroy,
        "cuMemPoolSetAttribute" => cuMemPoolSetAttribute,
        "cuMemPoolGetAttribute" => cuMemPoolGetAttribute,
        "cuMemPoolSetAccess" => cuMemPoolSetAccess,
        "cuMemPoolGetAccess" => cuMemPoolGetAccess,
        "cuMemPoolTrimTo" => cuMemPoolTrimTo,
        "cuMemAllocFromPoolAsync" => cuMemAllocFromPoolAsync,
        "cuMemAllocAsync" => cuMemAllocAsync,
        "cuMemFreeAsync" => cuMemFreeAsync,
        "cuDeviceGetDefaultMemPool" => cuDeviceGetDefaultMemPool,
        "cuDeviceGetMemPool" => cuDeviceGetMemPool,
        "cuDeviceSetMemPool" => cuDeviceSetMemPool,
        "cuMemHostAlloc" => cuMemHostAlloc,
        "cuMemHostGetDevicePointer" => cuMemHostGetDevicePointer_v2,
        "cuMemHostGetFlags" => cuMemHostGetFlags,
        "cuMemFreeHost" => cuMemFreeHost,
        "cuMemcpyHtoD" => cuMemcpyHtoD_v2,
        "cuMemcpy" => cuMemcpy,
        "cuMemcpyAsync" => cuMemcpyAsync,
        "cuMemcpyDtoH" => cuMemcpyDtoH_v2,
        "cuMemcpyDtoD" => cuMemcpyDtoD_v2,
        "cuMemcpyHtoDAsync" => cuMemcpyHtoDAsync_v2,
        "cuMemcpyDtoHAsync" => cuMemcpyDtoHAsync_v2,
        "cuMemcpyDtoDAsync" => cuMemcpyDtoDAsync_v2,
        "cuMemsetD8" => cuMemsetD8_v2,
        "cuMemsetD8Async" => cuMemsetD8Async,
        "cuMemGetInfo" => cuMemGetInfo_v2,
        "cuLaunchKernel" => cuLaunchKernel,
        "cuLaunchKernelEx" => cuLaunchKernelEx,
        "cuTensorMapEncodeTiled" => cuTensorMapEncodeTiled,
        "cuThreadExchangeStreamCaptureMode" => cuThreadExchangeStreamCaptureMode,
        "cuStreamCreate" => cuStreamCreate,
        "cuStreamCreateWithPriority" => cuStreamCreateWithPriority,
        "cuStreamDestroy" => cuStreamDestroy_v2,
        "cuStreamSynchronize" => cuStreamSynchronize,
        "cuStreamQuery" => cuStreamQuery,
        "cuStreamWaitEvent" => cuStreamWaitEvent,
        "cuEventCreate" => cuEventCreate,
        "cuEventDestroy" => cuEventDestroy_v2,
        "cuEventRecord" => cuEventRecord,
        "cuEventSynchronize" => cuEventSynchronize,
        "cuEventQuery" => cuEventQuery,
        "cuEventElapsedTime" => cuEventElapsedTime,
        "cuGetErrorName" => cuGetErrorName,
        "cuGetErrorString" => cuGetErrorString,
        "cuGetExportTable" => cuGetExportTable,
        // NB: cuGetProcAddress is resolved by `resolve_proc` (version-dependent
        // v1 vs v2 ABI), never through this table — see the note there.
    }
}

/// Resolve a driver symbol to a function pointer, honoring the caller's CUDA
/// version for entry points whose C ABI changed across revisions.
///
/// `cuGetProcAddress` is the load-bearing case: its own signature gained a
/// fifth `symbolStatus` parameter in CUDA 12.0 (the `_v2` form). A CUDA 11.x
/// runtime resolves "cuGetProcAddress" and then *calls the result with the
/// 4-argument v1 convention*. Handing back the v2 pointer there makes it read
/// an uninitialized fifth argument and write through it — a crash on the very
/// first bootstrap call. So serve v1 below 12000 and v2 at/above it.
fn resolve_proc(name: &str, cuda_version: c_int) -> Option<*mut c_void> {
    let base = name.trim_end_matches("_v3").trim_end_matches("_v2");
    if base == "cuGetProcAddress" {
        // An explicit "_v2" request always wants v2; a bare request follows the
        // caller's version.
        return Some(if name.ends_with("_v2") || cuda_version >= 12000 {
            cuGetProcAddress_v2 as *mut c_void
        } else {
            cuGetProcAddress as *mut c_void
        });
    }
    let resolved = proc_table(base);
    if resolved.is_some() || cuda_version > shim_cuda_version() {
        return resolved;
    }
    // Static libcudart builds eagerly resolve the complete Driver API surface
    // for the advertised compatibility version before performing even a
    // cudaFree(NULL). The generated exports preserve that ABI contract: APIs
    // outside smolvm's forwarded subset resolve and return NOT_SUPPORTED if an
    // application actually invokes them, instead of making the whole runtime
    // look like an older/incompatible driver during bootstrap.
    for candidate in [name, base] {
        let Ok(candidate) = CString::new(candidate) else {
            continue;
        };
        let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, candidate.as_ptr()) };
        if !address.is_null() {
            return Some(address);
        }
    }
    None
}

#[no_mangle]
pub extern "C" fn cuGetProcAddress_v2(
    symbol: *const c_char,
    pfn: *mut *mut c_void,
    cuda_version: c_int,
    _flags: u64,
    symbol_status: *mut c_int,
) -> c_int {
    if symbol.is_null() || pfn.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    let name = match unsafe { CStr::from_ptr(symbol) }.to_str() {
        Ok(n) => n,
        Err(_) => return CUDA_ERROR_INVALID_VALUE,
    };
    let resolved = resolve_proc(name, cuda_version);
    trace_proc(name, resolved.is_some());
    match resolved {
        Some(f) => {
            unsafe { *pfn = f };
            if !symbol_status.is_null() {
                unsafe { *symbol_status = 0 }; // CU_GET_PROC_ADDRESS_SUCCESS
            }
            CUDA_SUCCESS
        }
        None => {
            unsafe { *pfn = std::ptr::null_mut() };
            if !symbol_status.is_null() {
                unsafe { *symbol_status = 1 }; // CU_GET_PROC_ADDRESS_SYMBOL_NOT_FOUND
            }
            CUDA_ERROR_NOT_FOUND
        }
    }
}

/// When `SMOLVM_CUDA_SHIM_TRACE` is set, log each cuGetProcAddress lookup and
/// whether the shim served it — the fastest way to enumerate the surface a
/// given CUDA runtime needs. No-op otherwise.
fn trace_proc(name: &str, hit: bool) {
    use std::sync::atomic::{AtomicU8, Ordering};
    static ENABLED: AtomicU8 = AtomicU8::new(0); // 0=unknown, 1=on, 2=off
    let on = match ENABLED.load(Ordering::Relaxed) {
        1 => true,
        2 => false,
        _ => {
            let on = std::env::var_os("SMOLVM_CUDA_SHIM_TRACE").is_some();
            ENABLED.store(if on { 1 } else { 2 }, Ordering::Relaxed);
            on
        }
    };
    if on {
        eprintln!(
            "[shim] cuGetProcAddress {name} -> {}",
            if hit { "hit" } else { "MISS" }
        );
    }
}

#[no_mangle]
pub extern "C" fn cuGetProcAddress(
    symbol: *const c_char,
    pfn: *mut *mut c_void,
    cuda_version: c_int,
    flags: u64,
) -> c_int {
    cuGetProcAddress_v2(symbol, pfn, cuda_version, flags, std::ptr::null_mut())
}

// ---- driver symbols PyTorch's stack links (exported so the shim loads) -------
// None are called during basic CUDA init; JIT-link (cuLink*), cooperative
// launch, and Hopper TMA (cuTensorMapEncodeTiled) are unused on sm_86 forwarding.
const CU_ERROR_NOT_SUPPORTED: c_int = 801;

fn unsupported_driver_call(name: &str) -> c_int {
    if std::env::var_os("SMOLVM_CUDA_SHIM_TRACE").is_some() {
        eprintln!("[shim] unsupported driver call: {name}");
    }
    CU_ERROR_NOT_SUPPORTED
}

#[no_mangle]
pub extern "C" fn cuLinkCreate_v2() -> c_int {
    unsupported_driver_call("cuLinkCreate_v2")
}
#[no_mangle]
pub extern "C" fn cuLinkAddData_v2() -> c_int {
    unsupported_driver_call("cuLinkAddData_v2")
}
#[no_mangle]
pub extern "C" fn cuLinkComplete() -> c_int {
    unsupported_driver_call("cuLinkComplete")
}
#[no_mangle]
pub extern "C" fn cuFuncGetAttribute(pi: *mut c_int, attrib: c_int, func: *mut c_void) -> c_int {
    if pi.is_null() || func.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    if is_unresolved_guest_host_stub(func) {
        if std::env::var_os("SMOLVM_CUDA_SHIM_TRACE").is_some() {
            eprintln!(
                "[shim] cuFuncGetAttribute consumed unresolved guest host stub={func:p} \
                 attrib={attrib}"
            );
        }
        return ret(unsafe { out(pi, 0) });
    }
    match with_state(|state| state.client.func_get_attribute(func as u64, attrib)) {
        Ok(value) => ret(unsafe { out(pi, value) }),
        Err(status) => status,
    }
}
// Triton/vLLM kernels needing >48 KiB shared memory must raise
// CU_FUNC_ATTRIBUTE_MAX_DYNAMIC_SHARED_SIZE_BYTES here before launching, or the
// launch fails with INVALID_VALUE. Forward it so the host function's real limit
// is raised; Triton checks the return to decide whether the kernel can run.
#[no_mangle]
pub extern "C" fn cuFuncSetAttribute(func: *mut c_void, attrib: c_int, value: c_int) -> c_int {
    if func.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    if is_unresolved_guest_host_stub(func) {
        if std::env::var_os("SMOLVM_CUDA_SHIM_TRACE").is_some() {
            eprintln!(
                "[shim] cuFuncSetAttribute ignored unresolved guest host stub={func:p} \
                 attrib={attrib} value={value}"
            );
        }
        return CUDA_SUCCESS;
    }
    let status = ret(with_state(|s| {
        s.client.func_set_attribute(func as u64, attrib, value)
    }));
    if std::env::var_os("SMOLVM_CUDA_SHIM_TRACE").is_some() {
        eprintln!(
            "[shim] cuFuncSetAttribute function={func:p} attrib={attrib} value={value} status={status}"
        );
    }
    status
}
#[no_mangle]
pub extern "C" fn cuLaunchCooperativeKernel() -> c_int {
    unsupported_driver_call("cuLaunchCooperativeKernel")
}
#[no_mangle]
pub extern "C" fn cuOccupancyMaxActiveBlocksPerMultiprocessor(
    num_blocks: *mut c_int,
    _func: *mut c_void,
    block_size: c_int,
    _dynamic_smem: usize,
) -> c_int {
    let bs = block_size.max(1);
    if !num_blocks.is_null() {
        unsafe { *num_blocks = (2048 / bs).clamp(1, 32) };
    }
    CUDA_SUCCESS
}
/// Hopper TMA descriptor encode, forwarded to the daemon (generic LibCall,
/// lib 6 / func 0). sm90 cuBLASLt and FlashAttention kernels cannot
/// initialize without it — the old NOT_SUPPORTED stub surfaced as
/// "Failed to initialize the TMA descriptor 801" → CUBLAS_STATUS_NOT_INITIALIZED
/// in vLLM on H100. Blob: [u32 dtype][u32 rank][u64 gaddr][5xu64 gdim]
/// [5xu64 gstride][5xu32 boxdim][5xu32 estride][u32 il][u32 sw][u32 l2][u32 oob]
/// = 152 bytes; reply payload is the 128-byte CUtensorMap.
#[no_mangle]
pub extern "C" fn cuTensorMapEncodeTiled(
    tensor_map: *mut u8,
    data_type: c_int,
    rank: u32,
    global_address: u64,
    global_dim: *const u64,
    global_strides: *const u64,
    box_dim: *const u32,
    element_strides: *const u32,
    interleave: c_int,
    swizzle: c_int,
    l2_promotion: c_int,
    oob_fill: c_int,
) -> c_int {
    if tensor_map.is_null() || rank == 0 || rank > 5 || global_dim.is_null() || box_dim.is_null() {
        return CUDA_ERROR_INVALID_VALUE;
    }
    let r = rank as usize;
    let mut blob = Vec::with_capacity(152);
    blob.extend_from_slice(&(data_type as u32).to_le_bytes());
    blob.extend_from_slice(&rank.to_le_bytes());
    blob.extend_from_slice(&global_address.to_le_bytes());
    for i in 0..5 {
        let v = if i < r {
            unsafe { *global_dim.add(i) }
        } else {
            0
        };
        blob.extend_from_slice(&v.to_le_bytes());
    }
    for i in 0..5 {
        // The API takes rank-1 stride entries (innermost is implicit).
        let v = if i + 1 < r && !global_strides.is_null() {
            unsafe { *global_strides.add(i) }
        } else {
            0
        };
        blob.extend_from_slice(&v.to_le_bytes());
    }
    for i in 0..5 {
        let v = if i < r { unsafe { *box_dim.add(i) } } else { 0 };
        blob.extend_from_slice(&v.to_le_bytes());
    }
    for i in 0..5 {
        // NULL elementStrides means all-ones, per the driver contract.
        let v = if i < r && !element_strides.is_null() {
            unsafe { *element_strides.add(i) }
        } else {
            1
        };
        blob.extend_from_slice(&v.to_le_bytes());
    }
    for v in [interleave, swizzle, l2_promotion, oob_fill] {
        blob.extend_from_slice(&(v as u32).to_le_bytes());
    }
    match with_state(|s| s.client.lib_call(6, 0, blob)) {
        Ok((0, out)) if out.len() == 128 => {
            unsafe { std::ptr::copy_nonoverlapping(out.as_ptr(), tensor_map, 128) };
            CUDA_SUCCESS
        }
        Ok((st, _)) => {
            if st == 0 {
                CU_ERROR_NOT_SUPPORTED // 128-byte payload missing: daemon too old
            } else {
                st
            }
        }
        Err(e) => e,
    }
}

#[no_mangle]
pub extern "C" fn cuOccupancyMaxActiveBlocksPerMultiprocessorWithFlags(
    num_blocks: *mut c_int,
    _func: *mut c_void,
    block_size: c_int,
    _dyn_smem: usize,
    _flags: c_uint,
) -> c_int {
    let bs = block_size.max(1);
    if !num_blocks.is_null() {
        unsafe { *num_blocks = (2048 / bs).clamp(1, 32) }
    }
    CUDA_SUCCESS
}

#[cfg(test)]
mod mem_pool_abi_tests {
    use super::{CUmemAccessDesc, CUmemLocation, CUmemPoolProps};

    #[test]
    fn cuda_memory_pool_struct_layout_matches_cuda_h() {
        assert_eq!(std::mem::size_of::<CUmemLocation>(), 8);
        assert_eq!(std::mem::size_of::<CUmemAccessDesc>(), 12);
        assert_eq!(std::mem::size_of::<CUmemPoolProps>(), 88);
    }
}
